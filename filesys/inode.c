#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include <stddef.h>
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

/* Transient operation snapshots only. Open inodes retain no disk header:
   authoritative metadata always lives in the bounded sector cache. */
struct inode_metadata {
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
	struct rw_lock data_lock;          /* Stable I/O shared; growth exclusive. */
	struct lock directory_lock;        /* Namespace entries and unlink. */
	struct lock mapping_lock;          /* Short in-memory chain hint updates. */
	bool valid;                       /* Initialization has finished successfully. */
#ifdef EFILESYS
	cluster_t cached_cluster;          /* Sequential chain traversal hint. */
	size_t cached_index;
#endif
};

#ifdef EFILESYS
/* Resolve reserved chain entries too, before a growing write publishes EOF. */
static disk_sector_t
index_to_sector (struct inode *inode, const struct inode_metadata *data, size_t target) {
	lock_acquire (&inode->mapping_lock);
	cluster_t cluster = data->start;
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
	disk_sector_t sector = cluster_to_sector (cluster);
	lock_release (&inode->mapping_lock);
	return sector;
}

/* Reserve and zero the complete extension before changing existing data.
   Failure removes only the newly allocated suffix and preserves the old EOF. */
static bool
reserve_extension (struct inode *inode, struct inode_metadata *data, off_t end) {
	size_t old_count = bytes_to_sectors (data->length);
	size_t new_count = bytes_to_sectors (end);
	if (new_count <= old_count)
		return true;
	cluster_t old_tail = old_count == 0 ? 0 :
	                     sector_to_cluster (index_to_sector (inode, data, old_count - 1));
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
		data->start = first;
	return true;
}
#endif

/* Returns the sector containing POS, or -1 beyond the published file length. */
static disk_sector_t
byte_to_sector (struct inode *inode, const struct inode_metadata *data, off_t pos) {
	ASSERT (inode != NULL);
	if (pos < 0 || pos >= data->length)
		return (disk_sector_t) -1;
#ifdef EFILESYS
	return index_to_sector (inode, data, pos / DISK_SECTOR_SIZE);
#else
	return data->start + pos / DISK_SECTOR_SIZE;
#endif
}

/* List of open inodes, so that opening a single inode twice
 * returns the same `struct inode'. */
static struct list open_inodes;
static struct lock open_lock;

/* Initializes the inode module. */
void
inode_init (void) {
	list_init (&open_inodes);
	lock_init (&open_lock);
}

/* Initializes an inode with LENGTH bytes of data and
 * writes the new inode to sector SECTOR on the file system
 * disk.
 * Returns true if successful.
 * Returns false if memory or disk allocation fails. */
static bool
create_inode (disk_sector_t sector, off_t length, enum inode_type type, disk_sector_t parent) {
	ASSERT (length >= 0);
	_Static_assert (sizeof (struct inode_disk) == DISK_SECTOR_SIZE, "inode disk layout");
	_Static_assert (sizeof (struct inode_metadata) == offsetof (struct inode_disk, unused),
	                "metadata snapshots match the disk header");
	struct inode_metadata data = {.length = length, .magic = INODE_MAGIC,
	                             .type = type, .parent = parent};
	static const uint8_t zeros[DISK_SECTOR_SIZE];
	size_t sectors = bytes_to_sectors (length);
#ifdef EFILESYS
	cluster_t tail = 0;
	for (size_t allocated = 0; allocated < sectors; allocated++) {
		cluster_t next = fat_create_chain (tail);
		if (next == 0) {
			fat_remove_chain (data.start, 0);
			return false;
		}
		if (data.start == 0)
			data.start = next;
		tail = next;
		buffer_cache_write (cluster_to_sector (next), zeros, 0, DISK_SECTOR_SIZE);
	}
#else
	if (!free_map_allocate (sectors, &data.start))
		return false;
	for (size_t i = 0; i < sectors; i++)
		buffer_cache_write (data.start + i, zeros, 0, DISK_SECTOR_SIZE);
#endif
	buffer_cache_write (sector, zeros, 0, DISK_SECTOR_SIZE);
	buffer_cache_write (sector, &data, 0, sizeof data);
	return true;
}

bool
inode_create (disk_sector_t sector, off_t length) {
	FILESYS_OPERATION;
	return create_inode (sector, length, INODE_FILE, 0);
}

bool
inode_create_directory (disk_sector_t sector, off_t length, disk_sector_t parent) {
	FILESYS_OPERATION;
	return create_inode (sector, length, INODE_DIRECTORY, parent);
}

bool
inode_create_symlink (disk_sector_t sector, off_t length) {
	FILESYS_OPERATION;
	return create_inode (sector, length, INODE_SYMLINK, 0);
}

/* Reads an inode from SECTOR
 * and returns a `struct inode' that contains it.
 * Returns a null pointer if memory allocation fails. */
/* Publish a placeholder under the short registry lock. Its exclusive data
   lock protects initialization, so other opens wait only on this inode and
   keep it referenced. No disk I/O holds the registry lock. */
struct inode *
inode_open (disk_sector_t sector) {
	FILESYS_OPERATION;
	lock_acquire (&open_lock);
	for (struct list_elem *e = list_begin (&open_inodes);
	     e != list_end (&open_inodes); e = list_next (e)) {
		struct inode *inode = list_entry (e, struct inode, elem);
		if (inode->sector == sector) {
			inode->open_cnt++;
			lock_release (&open_lock);
			rw_lock_read (&inode->data_lock);
			bool valid = inode->valid;
			rw_unlock_read (&inode->data_lock);
			if (!valid) {
				inode_close (inode);
				return NULL;
			}
			return inode;
		}
	}
	struct inode *inode = calloc (1, sizeof *inode);
	if (inode == NULL) {
		lock_release (&open_lock);
		return NULL;
	}
	inode->sector = sector;
	inode->open_cnt = 1;
	rw_lock_init (&inode->data_lock);
	lock_init (&inode->directory_lock);
	lock_init (&inode->mapping_lock);
	rw_lock_write (&inode->data_lock);
	list_push_front (&open_inodes, &inode->elem);
	lock_release (&open_lock);
	struct inode_metadata data;
	buffer_cache_read (sector, &data, 0, sizeof data);
	inode->valid = data.magic == INODE_MAGIC && data.length >= 0 &&
	               data.type <= INODE_SYMLINK &&
	               (data.length == 0 || data.start != 0);
#ifdef EFILESYS
	inode->cached_cluster = data.start;
	inode->cached_index = 0;
#endif
	bool valid = inode->valid;
	rw_unlock_write (&inode->data_lock);
	if (!valid) {
		inode_close (inode);
		return NULL;
	}
	return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode) {
	FILESYS_OPERATION;
	if (inode != NULL) {
		lock_acquire (&open_lock);
		inode->open_cnt++;
		lock_release (&open_lock);
	}
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
	FILESYS_OPERATION;
	/* Ignore null pointer. */
	if (inode == NULL)
		return;

	/* Detach the last reference before doing any allocator/cache I/O. */
	lock_acquire (&open_lock);
	bool last = --inode->open_cnt == 0;
	if (last)
		list_remove (&inode->elem);
	lock_release (&open_lock);
	if (last) {

		/* Deallocate blocks if removed. */
		if (inode->removed) {
			struct inode_metadata data;
			buffer_cache_read (inode->sector, &data, 0, sizeof data);
#ifdef EFILESYS
			fat_remove_chain (data.start, 0);
			fat_remove_chain (sector_to_cluster (inode->sector), 0);
#else
			free_map_release (inode->sector, 1);
			free_map_release (data.start,
					bytes_to_sectors (data.length));
#endif
		}

		free (inode); 
	}
}

/* Marks INODE to be deleted when it is closed by the last caller who
 * has it open. */
void
inode_remove (struct inode *inode) {
	FILESYS_OPERATION;
	ASSERT (inode != NULL);
	lock_acquire (&open_lock);
	inode->removed = true;
	lock_release (&open_lock);
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
 * Returns the number of bytes actually read, which may be less
 * than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) {
	FILESYS_OPERATION;
	uint8_t *buffer = buffer_;
	if (offset < 0 || size <= 0)
		return 0;
	rw_lock_read (&inode->data_lock);
	struct inode_metadata data;
	buffer_cache_read (inode->sector, &data, 0, sizeof data);
	off_t bytes_read = 0;
	while (size > 0) {
		disk_sector_t sector = byte_to_sector (inode, &data, offset);
		size_t within = offset % DISK_SECTOR_SIZE;
		off_t remaining = data.length - offset;
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

	rw_unlock_read (&inode->data_lock);
	return bytes_read;
}

/* Explicit data I/O sites request read-ahead. Executable headers and directory
   metadata do not speculatively read unrelated blocks into the data cache. */
void
inode_readahead (struct inode *inode, off_t offset) {
	FILESYS_OPERATION;
	rw_lock_read (&inode->data_lock);
	struct inode_metadata data;
	buffer_cache_read (inode->sector, &data, 0, sizeof data);
	if (offset < 0 || offset >= data.length)
		goto out;
	off_t next_offset = offset - offset % DISK_SECTOR_SIZE + DISK_SECTOR_SIZE;
	if (next_offset >= data.length)
		goto out;
	disk_sector_t sector = byte_to_sector (inode, &data, offset);
#ifdef EFILESYS
	cluster_t next = fat_get (sector_to_cluster (sector));
	if (next != 0 && next != EOChain)
		buffer_cache_readahead (cluster_to_sector (next));
#else
	buffer_cache_readahead (sector + 1);
#endif
out:
	rw_unlock_read (&inode->data_lock);
}

/* Stable reads and nonextending writes share the inode lock. Growth excludes
   both until its gap/data and new EOF are fully initialized. Cache sector
   locks still serialize accesses to the same block. */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) {
	FILESYS_OPERATION;
	const uint8_t *buffer = buffer_;
	if (offset < 0 || size <= 0)
		return 0;
	rw_lock_read (&inode->data_lock);
	struct inode_metadata data;
	buffer_cache_read (inode->sector, &data, 0, sizeof data);
	bool exclusive = false;
#ifdef EFILESYS
	if ((uint64_t) offset + (uint64_t) size > INT32_MAX) {
		rw_unlock_read (&inode->data_lock);
		return 0;
	}
	off_t end = offset + size;
	if (end > data.length) {
		rw_unlock_read (&inode->data_lock);
		rw_lock_write (&inode->data_lock);
		buffer_cache_read (inode->sector, &data, 0, sizeof data);
		exclusive = true;
	}
#endif
	off_t bytes_written = 0;
	if (inode->deny_write_cnt)
		goto out;
#ifdef EFILESYS
	if (end > data.length && !reserve_extension (inode, &data, end))
		goto out;
	/* Newly reserved sectors are already zero. Only the old partial sector
	   can contain a gap that still needs initialization. */
	if (offset > data.length && data.length % DISK_SECTOR_SIZE != 0) {
		size_t within = data.length % DISK_SECTOR_SIZE;
		size_t gap = offset - data.length;
		if (gap > DISK_SECTOR_SIZE - within)
			gap = DISK_SECTOR_SIZE - within;
		static const uint8_t zeros[DISK_SECTOR_SIZE];
		buffer_cache_write (index_to_sector (inode, &data, data.length / DISK_SECTOR_SIZE),
		                    zeros, within, gap);
	}
#endif
	while (size > 0) {
#ifdef EFILESYS
		disk_sector_t sector = index_to_sector (inode, &data, offset / DISK_SECTOR_SIZE);
#else
		disk_sector_t sector = byte_to_sector (inode, &data, offset);
#endif
		size_t within = offset % DISK_SECTOR_SIZE;
		off_t bytes = DISK_SECTOR_SIZE - within;
#ifndef EFILESYS
		off_t remaining = data.length - offset;
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
	if (end > data.length) {
		data.length = end;
		buffer_cache_write (inode->sector, &data, 0, sizeof data);
	}
#endif
out:
	if (exclusive)
		rw_unlock_write (&inode->data_lock);
	else
		rw_unlock_read (&inode->data_lock);
	return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
	void
inode_deny_write (struct inode *inode) 
{
	FILESYS_OPERATION;
	rw_lock_write (&inode->data_lock);
	inode->deny_write_cnt++;
	lock_acquire (&open_lock);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	lock_release (&open_lock);
	rw_unlock_write (&inode->data_lock);
}

/* Re-enables writes to INODE.
 * Must be called once by each inode opener who has called
 * inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) {
	FILESYS_OPERATION;
	rw_lock_write (&inode->data_lock);
	ASSERT (inode->deny_write_cnt > 0);
	lock_acquire (&open_lock);
	ASSERT (inode->deny_write_cnt <= inode->open_cnt);
	lock_release (&open_lock);
	inode->deny_write_cnt--;
	rw_unlock_write (&inode->data_lock);
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode) {
	FILESYS_OPERATION;
	struct inode *mutable = (struct inode *) inode;
	rw_lock_read (&mutable->data_lock);
	off_t length;
	buffer_cache_read (inode->sector, &length, offsetof (struct inode_disk, length), sizeof length);
	rw_unlock_read (&mutable->data_lock);
	return length;
}

/* Discard a newly created inode that could not be linked into a directory. */
void
inode_discard (disk_sector_t sector) {
	FILESYS_OPERATION;
	struct inode_metadata disk_inode;
	buffer_cache_read (sector, &disk_inode, 0, sizeof disk_inode);
	ASSERT (disk_inode.magic == INODE_MAGIC);
#ifdef EFILESYS
	fat_remove_chain (disk_inode.start, 0);
	fat_remove_chain (sector_to_cluster (sector), 0);
#else
	free_map_release (disk_inode.start, bytes_to_sectors (disk_inode.length));
	free_map_release (sector, 1);
#endif
}

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
	FILESYS_OPERATION;
	if (inode == NULL)
		return false;
	/* Also recognize roots formatted before explicit type fields. */
	if (inode->sector == root_inode_sector ())
		return true;
	uint32_t type;
	buffer_cache_read (inode->sector, &type, offsetof (struct inode_disk, type), sizeof type);
	return type == INODE_DIRECTORY;
}

bool
inode_is_symlink (const struct inode *inode) {
	FILESYS_OPERATION;
	if (inode == NULL)
		return false;
	uint32_t type;
	buffer_cache_read (inode->sector, &type, offsetof (struct inode_disk, type), sizeof type);
	return type == INODE_SYMLINK;
}

disk_sector_t
inode_get_parent (const struct inode *inode) {
	FILESYS_OPERATION;
	if (inode->sector == root_inode_sector ())
		return inode->sector;
	disk_sector_t parent;
	buffer_cache_read (inode->sector, &parent, offsetof (struct inode_disk, parent), sizeof parent);
	return parent;
}

bool
inode_is_removed (const struct inode *inode) {
	FILESYS_OPERATION;
	lock_acquire (&open_lock);
	bool removed = inode->removed;
	lock_release (&open_lock);
	return removed;
}

/* Directory locking is distinct from file data locking: entry scans and
   updates may call inode I/O while their namespace transaction stays held. */
void
inode_lock_directory (struct inode *inode) {
	lock_acquire (&inode->directory_lock);
}

void
inode_unlock_directory (struct inode *inode) {
	lock_release (&inode->directory_lock);
}
