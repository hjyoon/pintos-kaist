#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#ifdef EFILESYS
#include "filesys/fat.h"
#endif
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* A directory. */
struct dir {
	struct inode *inode;                /* Backing store. */
	off_t pos;                          /* Current position. */
};

/* A single directory entry. */
struct dir_entry {
	disk_sector_t inode_sector;         /* Sector number of header. */
	char name[NAME_MAX + 1];            /* Null terminated file name. */
	bool in_use;                        /* In use or free? */
};

/* Creates a directory with space for ENTRY_CNT entries in the
 * given SECTOR.  Returns true if successful, false on failure. */
bool
dir_create (disk_sector_t sector, size_t entry_cnt) {
	return dir_create_at (sector, entry_cnt, sector);
}

/* Parent identity is metadata, so . and .. need no visible directory slots. */
bool
dir_create_at (disk_sector_t sector, size_t entry_cnt, disk_sector_t parent) {
	return inode_create_directory (sector, entry_cnt * sizeof (struct dir_entry), parent);
}

/* Opens and returns the directory for the given INODE, of which
 * it takes ownership.  Returns a null pointer on failure. */
struct dir *
dir_open (struct inode *inode) {
	struct dir *dir = calloc (1, sizeof *dir);
	if (inode != NULL && inode_is_directory (inode) && dir != NULL) {
		dir->inode = inode;
		dir->pos = 0;
		return dir;
	} else {
		inode_close (inode);
		free (dir);
		return NULL;
	}
}

/* Opens the root directory and returns a directory for it.
 * Return true if successful, false on failure. */
struct dir *
dir_open_root (void) {
#ifdef EFILESYS
	return dir_open (inode_open (cluster_to_sector (ROOT_DIR_CLUSTER)));
#else
	return dir_open (inode_open (ROOT_DIR_SECTOR));
#endif
}

/* Opens and returns a new directory for the same inode as DIR.
 * Returns a null pointer on failure. */
struct dir *
dir_reopen (struct dir *dir) {
	return dir != NULL ? dir_open (inode_reopen (dir->inode)) : NULL;
}

/* Destroys DIR and frees associated resources. */
void
dir_close (struct dir *dir) {
	if (dir != NULL) {
		inode_close (dir->inode);
		free (dir);
	}
}

/* Returns the inode encapsulated by DIR. */
struct inode *
dir_get_inode (struct dir *dir) {
	return dir->inode;
}

/* Searches DIR for a file with the given NAME.
 * If successful, returns true, sets *EP to the directory entry
 * if EP is non-null, and sets *OFSP to the byte offset of the
 * directory entry if OFSP is non-null.
 * otherwise, returns false and ignores EP and OFSP. */
static bool
lookup (const struct dir *dir, const char *name,
		struct dir_entry *ep, off_t *ofsp) {
	struct dir_entry e;
	size_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (e.in_use && !strcmp (name, e.name)) {
			if (ep != NULL)
				*ep = e;
			if (ofsp != NULL)
				*ofsp = ofs;
			return true;
		}
	return false;
}

/* Searches DIR for a file with the given NAME
 * and returns true if one exists, false otherwise.
 * On success, sets *INODE to an inode for the file, otherwise to
 * a null pointer.  The caller must close *INODE. */
bool
dir_lookup (const struct dir *dir, const char *name,
		struct inode **inode) {
	struct dir_entry e;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	if (inode_is_removed (dir->inode)) {
		*inode = NULL;
		return false;
	}
	if (!strcmp (name, ".")) {
		*inode = inode_reopen (dir->inode);
		return *inode != NULL;
	}
	if (!strcmp (name, "..")) {
		disk_sector_t parent = inode_get_parent (dir->inode);
		*inode = parent != 0 ? inode_open (parent) : NULL;
		return *inode != NULL;
	}
	if (lookup (dir, name, &e, NULL))
		*inode = inode_open (e.inode_sector);
	else
		*inode = NULL;

	return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
 * file by that name.  The file's inode is in sector
 * INODE_SECTOR.
 * Returns true if successful, false on failure.
 * Fails if NAME is invalid (i.e. too long) or a disk or memory
 * error occurs. */
bool
dir_add (struct dir *dir, const char *name, disk_sector_t inode_sector) {
	struct dir_entry e;
	off_t ofs;
	bool success = false;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Check NAME for validity. */
	if (*name == '\0' || strlen (name) > NAME_MAX || strchr (name, '/') != NULL ||
	    !strcmp (name, ".") || !strcmp (name, "..") || inode_is_removed (dir->inode))
		return false;

	/* Check that NAME is not in use. */
	if (lookup (dir, name, NULL, NULL))
		goto done;

	/* Set OFS to offset of free slot.
	 * If there are no free slots, then it will be set to the
	 * current end-of-file.

	 * inode_read_at() will only return a short read at end of file.
	 * Otherwise, we'd need to verify that we didn't get a short
	 * read due to something intermittent such as low memory. */
	for (ofs = 0; inode_read_at (dir->inode, &e, sizeof e, ofs) == sizeof e;
			ofs += sizeof e)
		if (!e.in_use)
			break;

	/* Write slot. */
	e.in_use = true;
	strlcpy (e.name, name, sizeof e.name);
	e.inode_sector = inode_sector;
	success = inode_write_at (dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
	return success;
}

/* Removes any entry for NAME in DIR.
 * Returns true if successful, false on failure,
 * which occurs only if there is no file with the given NAME. */
bool
dir_remove (struct dir *dir, const char *name) {
	struct dir_entry e;
	struct inode *inode = NULL;
	bool success = false;
	off_t ofs;

	ASSERT (dir != NULL);
	ASSERT (name != NULL);

	/* Find directory entry. */
	if (inode_is_removed (dir->inode) || !strcmp (name, ".") ||
	    !strcmp (name, "..") || !lookup (dir, name, &e, &ofs))
		goto done;

	/* Open inode. */
	inode = inode_open (e.inode_sector);
	if (inode == NULL)
		goto done;

	if (inode_is_directory (inode)) {
		/* Open directories may be unlinked, but must first be empty. The
		   inode stays allocated until its last descriptor or CWD closes. */
		char child[NAME_MAX + 1];
		off_t position = 0;
		if (inode_get_inumber (inode) == inode_get_parent (inode) ||
		    dir_read_next (inode, &position, child))
			goto done;
	}

	/* Erase directory entry. */
	e.in_use = false;
	if (inode_write_at (dir->inode, &e, sizeof e, ofs) != sizeof e)
		goto done;

	/* Remove inode. */
	inode_remove (inode);
	success = true;

done:
	inode_close (inode);
	return success;
}

/* Reads the next directory entry in DIR and stores the name in
 * NAME.  Returns true if successful, false if the directory
 * contains no more entries. */
bool
dir_readdir (struct dir *dir, char name[NAME_MAX + 1]) {
	return dir_read_next (dir->inode, &dir->pos, name);
}

/* Descriptors keep their own cursor, shared by dup2 aliases and copied on
   fork. CWD handles never need to share a descriptor's enumeration state. */
bool
dir_read_next (struct inode *inode, off_t *position, char name[NAME_MAX + 1]) {
	struct dir_entry e;

	if (!inode_is_directory (inode) || inode_is_removed (inode))
		return false;
	while (inode_read_at (inode, &e, sizeof e, *position) == sizeof e) {
		*position += sizeof e;
		if (e.in_use && strcmp (e.name, ".") && strcmp (e.name, "..")) {
			strlcpy (name, e.name, NAME_MAX + 1);
			return true;
		}
	}
	return false;
}

/* Parse one bounded component without placing the whole path on the stack. */
static int
next_component (const char **path, char name[NAME_MAX + 1]) {
	const char *cursor = *path;
	while (*cursor == '/')
		cursor++;
	if (*cursor == '\0')
		return 0;
	size_t length = 0;
	while (*cursor != '\0' && *cursor != '/') {
		if (length == NAME_MAX)
			return -1;
		name[length++] = *cursor++;
	}
	name[length] = '\0';
	*path = cursor;
	return 1;
}

/* Return an owned parent handle and its final component. The caller holds
   filesys_lock, just as for other filesystem operations at this stage. */
struct dir *
dir_resolve_parent (const char *path, char name[NAME_MAX + 1]) {
	if (path == NULL || *path == '\0' || strnlen (path, PGSIZE) == PGSIZE)
		return NULL;
	struct dir *current = NULL;
#ifdef USERPROG
	if (*path != '/' && thread_current ()->cwd != NULL)
		current = dir_reopen (thread_current ()->cwd);
	else
#endif
		current = dir_open_root ();
	if (current == NULL)
		return NULL;
	if (inode_is_removed (dir_get_inode (current)))
		goto fail;
	for (;;) {
		int result = next_component (&path, name);
		if (result < 0)
			goto fail;
		if (result == 0) {
			strlcpy (name, ".", NAME_MAX + 1);
			return current;
		}
		while (*path == '/')
			path++;
		if (*path == '\0')
			return current;
		struct inode *inode = NULL;
		if (!dir_lookup (current, name, &inode))
			goto fail;
		struct dir *next = dir_open (inode);
		if (next == NULL)
			goto fail;
		dir_close (current);
		current = next;
	}
fail:
	dir_close (current);
	return NULL;
}
