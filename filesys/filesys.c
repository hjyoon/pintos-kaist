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
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#ifdef EFILESYS
#include "filesys/fat.h"
#endif

/* The disk that contains the file system. */
struct disk *filesys_disk;

static struct semaphore operations_drained, shutdown_waiters;
static unsigned active_operations;
static bool stopping;

void
filesys_operation_begin (void) {
	struct thread *current = thread_current ();
	if (current->filesys_depth++ != 0)
		return;
	enum intr_level old = intr_disable ();
	while (stopping)
		sema_down (&shutdown_waiters);
	active_operations++;
	intr_set_level (old);
}

void
filesys_operation_end (int *scope UNUSED) {
	struct thread *current = thread_current ();
	ASSERT (current->filesys_depth > 0);
	if (--current->filesys_depth != 0)
		return;
	enum intr_level old = intr_disable ();
	ASSERT (active_operations > 0);
	if (--active_operations == 0 && stopping)
		sema_up (&operations_drained);
	intr_set_level (old);
}

static void do_format (void);

/* Initializes the file system module.
 * If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) {
	sema_init (&operations_drained, 0);
	sema_init (&shutdown_waiters, 0);
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
	ASSERT (thread_current ()->filesys_depth == 0);
	enum intr_level old = intr_disable ();
	stopping = true;
	while (active_operations != 0)
		sema_down (&operations_drained);
	intr_set_level (old);
	/* Shutdown itself may close metadata handles after the gate is drained. */
	thread_current ()->filesys_depth = 1;
#ifdef EFILESYS
	fat_close ();
#else
	free_map_close ();
#endif
	buffer_cache_done ();
	thread_current ()->filesys_depth = 0;
}

/* Creates a file named NAME with the given INITIAL_SIZE.
 * Returns true if successful, false otherwise.
 * Fails if a file named NAME already exists,
 * or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) {
	FILESYS_OPERATION;
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
	bool created = free_map_allocate (1, &inode_sector) &&
	               inode_create (inode_sector, initial_size);
	bool success = created && dir_add (dir, leaf, inode_sector);
	if (!success && inode_sector != 0) {
		if (created)
			inode_discard (inode_sector);
		else
			free_map_release (inode_sector, 1);
	}
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
	FILESYS_OPERATION;
	return file_open (dir_resolve_inode (name));
}

/* Deletes the file named NAME.
 * Returns true if successful, false on failure.
 * Fails if no file named NAME exists,
 * or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) {
	FILESYS_OPERATION;
	char leaf[NAME_MAX + 1];
	struct dir *dir = dir_resolve_parent (name, leaf);
	bool success = dir != NULL && strcmp (leaf, ".") && strcmp (leaf, "..") &&
	               dir_remove (dir, leaf, name[strlen (name) - 1] == '/');
	dir_close (dir);
	return success;
}

/* Publish a typed directory only after its inode and parent metadata have
   been initialized. Failed publication releases both metadata and data. */
bool
filesys_mkdir (const char *name) {
	FILESYS_OPERATION;
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
	FILESYS_OPERATION;
#ifdef USERPROG
	struct dir *next = dir_open (dir_resolve_inode (name));
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

/* Link contents are stored in the ordinary FAT data chain. The name becomes
   visible only once both its type and complete target have been written. */
int
filesys_symlink (const char *target, const char *linkpath) {
	FILESYS_OPERATION;
#ifdef EFILESYS
	if (target == NULL)
		return -1;
	size_t length = strnlen (target, PGSIZE);
	if (length == 0 || length == PGSIZE)
		return -1;
	char leaf[NAME_MAX + 1];
	struct dir *parent = dir_resolve_parent (linkpath, leaf);
	if (parent == NULL)
		return -1;
	struct inode *existing = NULL;
	if (!strcmp (leaf, ".") || !strcmp (leaf, "..") ||
	    linkpath[strlen (linkpath) - 1] == '/' || dir_lookup (parent, leaf, &existing)) {
		inode_close (existing);
		dir_close (parent);
		return -1;
	}
	cluster_t cluster = fat_create_chain (0);
	disk_sector_t sector = cluster != 0 ? cluster_to_sector (cluster) : 0;
	bool created = cluster != 0 && inode_create_symlink (sector, length);
	struct inode *inode = created ? inode_open (sector) : NULL;
	bool success = inode != NULL && inode_write_at (inode, target, length, 0) == (off_t) length;
	inode_close (inode);
	success = success && dir_add (parent, leaf, sector);
	if (!success && cluster != 0) {
		if (created)
			inode_discard (sector);
		else
			fat_remove_chain (cluster, 0);
	}
	dir_close (parent);
	return success ? 0 : -1;
#else
	return -1;
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
