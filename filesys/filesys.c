#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/disk.h"
#include "filesys/page_cache.h"
#include "threads/thread.h"
#ifdef USERPROG
#include "userprog/syscall.h"
#include "threads/synch.h"
#endif
#ifdef EFILESYS
#include "filesys/fat.h"
#endif

/* The disk that contains the file system. */
struct disk *filesys_disk;

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	filesys_disk = disk_get (0, 1);
	if (filesys_disk == NULL)
		PANIC ("hd0:1 (hdb) not present, file system initialization failed");

	buffer_cache_init ();
	inode_init ();

#ifdef EFILESYS
	fat_init ();

	if (format)
		do_format ();
	else
		fat_open ();
#else
	/* Original FS */
	free_map_init ();

	if (format)
		do_format ();

	free_map_open ();
#endif
	buffer_cache_start ();
}

/* Shuts down the file system module, writing any unwritten data
 * to disk. */
void
filesys_done (void) {
#ifdef USERPROG
	/* Quiesce foreground filesystem operations before stopping cache workers. */
	bool acquired = !lock_held_by_current_thread (&filesys_lock);
	if (acquired)
		lock_acquire (&filesys_lock);
#endif
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
	buffer_cache_done ();
#ifdef USERPROG
	if (acquired)
		lock_release (&filesys_lock);
#endif
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	disk_sector_t inode_sector = 0;
	char leaf[NAME_MAX + 1];
	struct dir *dir = dir_resolve_parent (name, leaf);
	if (dir == NULL)
		return false;
	if (!strcmp (leaf, ".") || !strcmp (leaf, "..") || name[strlen (name) - 1] == '/') {
		dir_close (dir);
		return false;
	}
#ifdef EFILESYS
	cluster_t inode_cluster = dir != NULL ? fat_create_chain (0) : 0;
	bool created = false;
	if (inode_cluster != 0) {
		inode_sector = cluster_to_sector (inode_cluster);
		created = inode_create (inode_sector, initial_size);
	}
	bool success = created && dir_add (dir, leaf, inode_sector);
	if (!success && inode_cluster != 0) {
		if (created)
			inode_discard (inode_sector);
		else
			fat_remove_chain (inode_cluster, 0);
	}
#else
	bool success = (dir != NULL
			&& free_map_allocate (1, &inode_sector)
			&& inode_create (inode_sector, initial_size)
			&& dir_add (dir, leaf, inode_sector));
	if (!success && inode_sector != 0)
		free_map_release (inode_sector, 1);
#endif

	dir_close (dir);

	return success;
}

/* Opens the file with the given NAME.
 * Returns the new file if successful or a null pointer
 * otherwise.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name) {
	char leaf[NAME_MAX + 1];
	struct dir *dir = dir_resolve_parent (name, leaf);
	struct inode *inode = NULL;
	if (dir != NULL)
		dir_lookup (dir, leaf, &inode);
	dir_close (dir);
	if (inode != NULL && name[strlen (name) - 1] == '/' && !inode_is_directory (inode)) {
		inode_close (inode);
		inode = NULL;
	}
	return file_open (inode);
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	char leaf[NAME_MAX + 1];
	struct dir *dir = dir_resolve_parent (name, leaf);
	struct inode *inode = NULL;
	bool success = dir != NULL && strcmp (leaf, ".") && strcmp (leaf, "..") &&
	               dir_lookup (dir, leaf, &inode) &&
	               (name[strlen (name) - 1] != '/' || inode_is_directory (inode)) &&
	               dir_remove (dir, leaf);
	inode_close (inode);
	dir_close (dir);
	return success;
}

/* Publish a typed directory only after its inode and parent metadata have
   been initialized. Failed publication releases both metadata and data. */
bool
filesys_mkdir (const char *name) {
#ifdef EFILESYS
	char leaf[NAME_MAX + 1];
	struct dir *parent = dir_resolve_parent (name, leaf);
	if (parent == NULL)
		return false;
	struct inode *existing = NULL;
	if (!strcmp (leaf, ".") || !strcmp (leaf, "..") ||
	    dir_lookup (parent, leaf, &existing)) {
		inode_close (existing);
		dir_close (parent);
		return false;
	}
	cluster_t cluster = fat_create_chain (0);
	bool created = cluster != 0 &&
	               dir_create_at (cluster_to_sector (cluster), 16,
	                              inode_get_inumber (dir_get_inode (parent)));
	bool success = created && dir_add (parent, leaf, cluster_to_sector (cluster));
	if (!success && cluster != 0) {
		if (created)
			inode_discard (cluster_to_sector (cluster));
		else
			fat_remove_chain (cluster, 0);
	}
	dir_close (parent);
	return success;
#else
	return false;
#endif
}

/* Replace CWD only after the entire destination path has been resolved. */
bool
filesys_chdir (const char *name) {
#ifdef USERPROG
	char leaf[NAME_MAX + 1];
	struct dir *parent = dir_resolve_parent (name, leaf);
	struct inode *inode = NULL;
	if (parent != NULL)
		dir_lookup (parent, leaf, &inode);
	dir_close (parent);
	struct dir *next = dir_open (inode);
	if (next == NULL)
		return false;
	struct dir *previous = thread_current ()->cwd;
	thread_current ()->cwd = next;
	dir_close (previous);
	return true;
#else
	return false;
#endif
}

/* Formats the file system. */
static void
do_format (void) {
	printf ("Formatting file system...");

#ifdef EFILESYS
	/* Create FAT and save it to the disk. */
	fat_create ();
	if (!dir_create (cluster_to_sector (ROOT_DIR_CLUSTER), 16))
		PANIC ("FAT root directory creation failed");
	fat_close ();
#else
	free_map_create ();
	if (!dir_create (ROOT_DIR_SECTOR, 16))
		PANIC ("root directory creation failed");
	free_map_close ();
#endif

	printf ("done.\n");
}
