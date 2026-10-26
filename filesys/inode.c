#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/page_cache.h"
#ifdef EFILESYS
#include "filesys/fat.h"
#endif

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

enum inode_type { INODE_FILE, INODE_DIRECTORY, INODE_SYMLINK };

/* On-disk inode.
 * Must be exactly DISK_SECTOR_SIZE bytes long. */
struct inode_disk {
	disk_sector_t start;                /* FAT cluster, or legacy data sector. */
	off_t length;                       /* File size in bytes. */
	unsigned magic;                     /* Magic number. */
	uint32_t type;
	disk_sector_t parent;
	uint32_t unused[123];               /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
 * bytes long. */
static inline size_t
bytes_to_sectors (off_t size) {
	return DIV_ROUND_UP ((size_t) size, DISK_SECTOR_SIZE);
}

/* Keep interpreted inode fields, rather than another cached sector image. */
struct inode_data {
	disk_sector_t start;
	off_t length;
	unsigned magic;
	uint32_t type;
	disk_sector_t parent;
};

/* In-memory inode. */
struct inode {
	struct list_elem elem;              /* Element in inode list. */
	disk_sector_t sector;               /* Sector number of disk location. */
	int open_cnt;                       /* Number of openers. */
	bool removed;                       /* True if deleted, false otherwise. */
	int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
	struct inode_data data;             /* Interpreted inode fields. */
	struct lock data_lock;             /* Chain changes and length publication. */
#ifdef EFILESYS
	cluster_t cached_cluster;          /* Sequential chain traversal hint. */
	size_t cached_index;
#endif
};

#ifdef EFILESYS
/* Resolve reserved chain entries too, before a growing write publishes EOF. */
static disk_sector_t
index_to_sector (struct inode *inode, size_t target) {
	cluster_t cluster = inode->data.start;
	size_t index = 0;
	if (inode->cached_cluster != 0 && inode->cached_index <= target) {
		cluster = inode->cached_cluster;
		index = inode->cached_index;
	}
	while (index < target) {
		cluster = fat_get (cluster);
		ASSERT (cluster != 0 && cluster != EOChain);
		index++;
	}
	inode->cached_cluster = cluster;
	inode->cached_index = target;
	return cluster_to_sector (cluster);
}

/* Reserve and zero the complete extension before changing existing data.
   Failure removes only the newly allocated suffix and preserves the old EOF. */
static bool
reserve_extension (struct inode *inode, off_t end) {
	size_t old_count = bytes_to_sectors (inode->data.length);
	size_t new_count = bytes_to_sectors (end);
	if (new_count <= old_count)
		return true;
	cluster_t old_tail = old_count == 0 ? 0 :
	                     sector_to_cluster (index_to_sector (inode, old_count - 1));
	cluster_t tail = old_tail, first = 0;
	static const uint8_t zeros[DISK_SECTOR_SIZE];
	for (size_t count = old_count; count < new_count; count++) {
		cluster_t next = fat_create_chain (tail);
		if (next == 0) {
			fat_remove_chain (first, old_tail);
			return false;
		}
		if (first == 0)
			first = next;
		tail = next;
		buffer_cache_write (cluster_to_sector (next), zeros, 0, DISK_SECTOR_SIZE);
	}
	if (old_count == 0)
		inode->data.start = first;
	return true;
}
#endif

/* Returns the sector containing POS, or -1 beyond the published file length. */
static disk_sector_t
byte_to_sector (struct inode *inode, off_t pos) {
	ASSERT (inode != NULL);
	if (pos < 0 || pos >= inode->data.length)
		return (disk_sector_t) -1;
#ifdef EFILESYS
	return index_to_sector (inode, pos / DISK_SECTOR_SIZE);
#else
	return inode->data.start + pos / DISK_SECTOR_SIZE;
#endif
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
static bool
create_inode (disk_sector_t sector, off_t length, enum inode_type type, disk_sector_t parent) {
	struct inode_disk *disk_inode = NULL;
	bool success = false;

	ASSERT (length >= 0);

	/* If this assertion fails, the inode structure is not exactly
	 * one sector in size, and you should fix that. */
	ASSERT (sizeof *disk_inode == DISK_SECTOR_SIZE);

	disk_inode = calloc (1, sizeof *disk_inode);
	if (disk_inode != NULL) {
		size_t sectors = bytes_to_sectors (length);
		disk_inode->length = length;
		disk_inode->magic = INODE_MAGIC;
		disk_inode->type = type;
		disk_inode->parent = parent;
#ifdef EFILESYS
		cluster_t tail = 0;
		static const char zeros[DISK_SECTOR_SIZE];
		size_t allocated = 0;
		for (; allocated < sectors; allocated++) {
			cluster_t next = fat_create_chain (tail);
			if (next == 0)
				break;
			if (disk_inode->start == 0)
				disk_inode->start = next;
			tail = next;
			buffer_cache_write (cluster_to_sector (next), zeros, 0, DISK_SECTOR_SIZE);
		}
		if (allocated == sectors) {
			buffer_cache_write (sector, disk_inode, 0, DISK_SECTOR_SIZE);
			success = true;
		} else
			fat_remove_chain (disk_inode->start, 0);
#else
		if (free_map_allocate (sectors, &disk_inode->start)) {
			buffer_cache_write (sector, disk_inode, 0, DISK_SECTOR_SIZE);
			if (sectors > 0) {
				static char zeros[DISK_SECTOR_SIZE];
				size_t i;

				for (i = 0; i < sectors; i++) 
					buffer_cache_write (disk_inode->start + i, zeros, 0, DISK_SECTOR_SIZE);
			}
			success = true; 
		} 
#endif
		free (disk_inode);
	}
	return success;
}

bool
inode_create (disk_sector_t sector, off_t length) {
	return create_inode (sector, length, INODE_FILE, 0);
}

bool
inode_create_directory (disk_sector_t sector, off_t length, disk_sector_t parent) {
	return create_inode (sector, length, INODE_DIRECTORY, parent);
}

bool
inode_create_symlink (disk_sector_t sector, off_t length) {
	return create_inode (sector, length, INODE_SYMLINK, 0);
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (disk_sector_t sector) {
	struct list_elem *e;
	struct inode *inode;

	/* Check whether this inode is already open. */
	for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
			e = list_next (e)) {
		inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode_reopen (inode);
			return inode; 
		}
	}

	/* Allocate memory. */
	inode = malloc (sizeof *inode);
	if (inode == NULL)
		return NULL;

	/* Initialize. */
	list_push_front (&open_inodes, &inode->elem);
	inode->sector = sector;
	inode->open_cnt = 1;
	inode->deny_write_cnt = 0;
	inode->removed = false;
	lock_init (&inode->data_lock);
	buffer_cache_read (inode->sector, &inode->data, 0, sizeof inode->data);
#ifdef EFILESYS
	if (inode->data.magic != INODE_MAGIC || inode->data.length < 0 ||
	    inode->data.type > INODE_SYMLINK ||
	    (inode->data.length > 0 && inode->data.start == 0)) {
		list_remove (&inode->elem);
		free (inode);
		return NULL;
	}
	inode->cached_cluster = inode->data.start;
	inode->cached_index = 0;
#endif
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	if (inode != NULL)
		inode->open_cnt++;
	return inode;
}

/* Returns INODE's inode number. */
disk_sector_t
inode_get_inumber (const struct inode *inode) {
	return inode->sector;
}

/* Closes INODE and writes it to disk.
 * If this was the last reference to INODE, frees its memory.
 * If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) {
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Release resources if this was the last opener. */
	if (--inode->open_cnt == 0) {
		/* Remove from inode list and release lock. */
		list_remove (&inode->elem);

		/* Deallocate blocks if removed. */
		if (inode->removed) {
#ifdef EFILESYS
			fat_remove_chain (inode->data.start, 0);
			fat_remove_chain (sector_to_cluster (inode->sector), 0);
#else
			free_map_release (inode->sector, 1);
			free_map_release (inode->data.start,
					bytes_to_sectors (inode->data.length));
#endif
		}

		free (inode); 
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	ASSERT (inode != NULL);
	inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {
	uint8_t *buffer = buffer_;
	if (offset < 0 || size <= 0)
		return 0;
	lock_acquire (&inode->data_lock);
	off_t bytes_read = 0;
	while (size > 0) {
		disk_sector_t sector = byte_to_sector (inode, offset);
		size_t within = offset % DISK_SECTOR_SIZE;
		off_t remaining = inode_length (inode) - offset;
		off_t bytes = DISK_SECTOR_SIZE - within;
		if (bytes > remaining)
			bytes = remaining;
		if (bytes > size)
			bytes = size;
		if (bytes <= 0)
			break;
		buffer_cache_read (sector, buffer + bytes_read, within, bytes);

		size -= bytes;
		offset += bytes;
		bytes_read += bytes;
	}

	lock_release (&inode->data_lock);
	return bytes_read;
}

/* Explicit data I/O sites request read-ahead. Executable headers and directory
   metadata do not speculatively read unrelated blocks into the data cache. */
void
inode_readahead (struct inode *inode, off_t offset) {
	lock_acquire (&inode->data_lock);
	if (offset < 0 || offset >= inode_length (inode))
		goto out;
	off_t next_offset = offset - offset % DISK_SECTOR_SIZE + DISK_SECTOR_SIZE;
	if (next_offset >= inode_length (inode))
		goto out;
	disk_sector_t sector = byte_to_sector (inode, offset);
#ifdef EFILESYS
	cluster_t next = fat_get (sector_to_cluster (sector));
	if (next != 0 && next != EOChain)
		buffer_cache_readahead (cluster_to_sector (next));
#else
	buffer_cache_readahead (sector + 1);
#endif
out:
	lock_release (&inode->data_lock);
}

/* Growing writes reserve all storage first and publish their new EOF only
   after zero-filling the gap and copying data. Readers share data_lock. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) {
	const uint8_t *buffer = buffer_;
	if (offset < 0 || size <= 0)
		return 0;
	lock_acquire (&inode->data_lock);
	off_t bytes_written = 0;
	if (inode->deny_write_cnt)
		goto out;
#ifdef EFILESYS
	if ((uint64_t) offset + (uint64_t) size > INT32_MAX)
		goto out;
	off_t end = offset + size;
	if (!reserve_extension (inode, end))
		goto out;
	/* Newly reserved sectors are already zero. Only the old partial sector
	   can contain a gap that still needs initialization. */
	if (offset > inode->data.length && inode->data.length % DISK_SECTOR_SIZE != 0) {
		size_t within = inode->data.length % DISK_SECTOR_SIZE;
		size_t gap = offset - inode->data.length;
		if (gap > DISK_SECTOR_SIZE - within)
			gap = DISK_SECTOR_SIZE - within;
		static const uint8_t zeros[DISK_SECTOR_SIZE];
		buffer_cache_write (index_to_sector (inode, inode->data.length / DISK_SECTOR_SIZE),
		                    zeros, within, gap);
	}
#endif
	while (size > 0) {
#ifdef EFILESYS
		disk_sector_t sector = index_to_sector (inode, offset / DISK_SECTOR_SIZE);
#else
		disk_sector_t sector = byte_to_sector (inode, offset);
#endif
		size_t within = offset % DISK_SECTOR_SIZE;
		off_t bytes = DISK_SECTOR_SIZE - within;
#ifndef EFILESYS
		off_t remaining = inode_length (inode) - offset;
		if (bytes > remaining)
			bytes = remaining;
#endif
		if (bytes > size)
			bytes = size;
		if (bytes <= 0)
			break;
		buffer_cache_write (sector, buffer + bytes_written, within, bytes);
		size -= bytes;
		offset += bytes;
		bytes_written += bytes;
	}
#ifdef EFILESYS
	if (end > inode->data.length) {
		inode->data.length = end;
		buffer_cache_write (inode->sector, &inode->data, 0, sizeof inode->data);
	}
#endif
out:
	lock_release (&inode->data_lock);
	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
	void
inode_deny_write (struct inode *inode) 
{
	lock_acquire (&inode->data_lock);
	inode->deny_write_cnt++;
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	lock_release (&inode->data_lock);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	lock_acquire (&inode->data_lock);
	ASSERT (inode->deny_write_cnt > 0);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	inode->deny_write_cnt--;
	lock_release (&inode->data_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	return inode->data.length;
}

#ifdef EFILESYS
/* Discard a newly created inode that could not be linked into a directory. */
void
inode_discard (disk_sector_t sector) {
	struct inode_data disk_inode;
	buffer_cache_read (sector, &disk_inode, 0, sizeof disk_inode);
	ASSERT (disk_inode.magic == INODE_MAGIC);
	fat_remove_chain (disk_inode.start, 0);
	fat_remove_chain (sector_to_cluster (sector), 0);
}
#endif

static disk_sector_t
root_inode_sector (void) {
#ifdef EFILESYS
	return cluster_to_sector (ROOT_DIR_CLUSTER);
#else
	return ROOT_DIR_SECTOR;
#endif
}

bool
inode_is_directory (const struct inode *inode) {
	/* The root is also recognized on FAT disks formatted before type fields. */
	return inode != NULL && (inode->data.type == INODE_DIRECTORY || inode->sector == root_inode_sector ());
}

bool
inode_is_symlink (const struct inode *inode) {
	return inode != NULL && inode->data.type == INODE_SYMLINK;
}

disk_sector_t
inode_get_parent (const struct inode *inode) {
	return inode->sector == root_inode_sector () ? inode->sector : inode->data.parent;
}

bool
inode_is_removed (const struct inode *inode) {
	return inode->removed;
}
