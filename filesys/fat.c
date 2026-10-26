#include "filesys/fat.h"
#include "devices/disk.h"
#include "filesys/filesys.h"
#include "filesys/page_cache.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include <stdio.h>
#include <string.h>

/* Should be less than DISK_SECTOR_SIZE */
struct fat_boot {
	unsigned int magic;
	unsigned int sectors_per_cluster; /* Fixed to 1 */
	unsigned int total_sectors;
	unsigned int fat_start;
	unsigned int fat_sectors; /* Size of FAT in sectors. */
	unsigned int root_dir_cluster;
};

/* FAT FS */
struct fat_fs {
	struct fat_boot bs;
	unsigned int *fat;
	unsigned int fat_length;
	disk_sector_t data_start;
	cluster_t last_clst;
	struct lock write_lock;
};

static struct fat_fs *fat_fs;

void fat_boot_create (void);
void fat_fs_init (void);

void
fat_init (void) {
	fat_fs = calloc (1, sizeof (struct fat_fs));
	if (fat_fs == NULL)
		PANIC ("FAT init failed");

	buffer_cache_read (FAT_BOOT_SECTOR, &fat_fs->bs, 0, sizeof fat_fs->bs);

	// Extract FAT info
	if (fat_fs->bs.magic != FAT_MAGIC)
		fat_boot_create ();
	fat_fs_init ();
}

void
fat_open (void) {
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT load failed");

	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	size_t bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; bytes > 0; i++) {
		size_t count = bytes < DISK_SECTOR_SIZE ? bytes : DISK_SECTOR_SIZE;
		buffer_cache_read (fat_fs->bs.fat_start + i, buffer, 0, count);
		buffer += count;
		bytes -= count;
	}
}

void
fat_close (void) {
	static const uint8_t zeros[DISK_SECTOR_SIZE];
	buffer_cache_write (FAT_BOOT_SECTOR, zeros, 0, DISK_SECTOR_SIZE);
	buffer_cache_write (FAT_BOOT_SECTOR, &fat_fs->bs, 0, sizeof fat_fs->bs);

	uint8_t *buffer = (uint8_t *) fat_fs->fat;
	size_t bytes = fat_fs->fat_length * sizeof (cluster_t);
	for (unsigned i = 0; i < fat_fs->bs.fat_sectors; i++) {
		size_t count = bytes < DISK_SECTOR_SIZE ? bytes : DISK_SECTOR_SIZE;
		if (count < DISK_SECTOR_SIZE)
			buffer_cache_write (fat_fs->bs.fat_start + i, zeros, 0, DISK_SECTOR_SIZE);
		if (count > 0)
			buffer_cache_write (fat_fs->bs.fat_start + i, buffer, 0, count);
		buffer += count;
		bytes -= count;
	}
}

void
fat_create (void) {
	// Create FAT boot
	fat_boot_create ();
	fat_fs_init ();

	// Create FAT table
	fat_fs->fat = calloc (fat_fs->fat_length, sizeof (cluster_t));
	if (fat_fs->fat == NULL)
		PANIC ("FAT creation failed");

	// Set up ROOT_DIR_CLST
	fat_put (ROOT_DIR_CLUSTER, EOChain);

	static const uint8_t zeros[DISK_SECTOR_SIZE];
	buffer_cache_write (cluster_to_sector (ROOT_DIR_CLUSTER), zeros, 0, DISK_SECTOR_SIZE);
}

void
fat_boot_create (void) {
	unsigned int fat_sectors =
	    (disk_size (filesys_disk) - 1)
	    / (DISK_SECTOR_SIZE / sizeof (cluster_t) * SECTORS_PER_CLUSTER + 1) + 1;
	fat_fs->bs = (struct fat_boot){
	    .magic = FAT_MAGIC,
	    .sectors_per_cluster = SECTORS_PER_CLUSTER,
	    .total_sectors = disk_size (filesys_disk),
	    .fat_start = 1,
	    .fat_sectors = fat_sectors,
	    .root_dir_cluster = ROOT_DIR_CLUSTER,
	};
}

void
fat_fs_init (void) {
	struct fat_boot *bs = &fat_fs->bs;
	uint64_t start = (uint64_t) bs->fat_start + bs->fat_sectors;
	if (bs->magic != FAT_MAGIC || bs->total_sectors != disk_size (filesys_disk) ||
	    bs->sectors_per_cluster != SECTORS_PER_CLUSTER || bs->fat_start != 1 ||
	    bs->fat_sectors == 0 || start >= bs->total_sectors ||
	    bs->root_dir_cluster != ROOT_DIR_CLUSTER)
		PANIC ("invalid FAT geometry");
	/* Entry zero is reserved. Cluster one begins at the first data sector. */
	fat_fs->data_start = start;
	fat_fs->fat_length = (bs->total_sectors - start) / SECTORS_PER_CLUSTER + 1;
	if ((uint64_t) fat_fs->fat_length * sizeof (cluster_t) >
	    (uint64_t) bs->fat_sectors * DISK_SECTOR_SIZE || fat_fs->fat_length <= 2)
		PANIC ("FAT does not cover the data region");
	fat_fs->last_clst = ROOT_DIR_CLUSTER;
	lock_init (&fat_fs->write_lock);
}

/*----------------------------------------------------------------------------*/
/* FAT handling                                                               */
/*----------------------------------------------------------------------------*/

/* Add a cluster to the chain.
 * If CLST is 0, start a new chain.
 * Returns 0 if fails to allocate a new cluster. */
cluster_t
fat_create_chain (cluster_t clst) {
	lock_acquire (&fat_fs->write_lock);
	if (clst != 0 && (clst >= fat_fs->fat_length ||
	                  fat_fs->fat[clst] != EOChain)) {
		lock_release (&fat_fs->write_lock);
		return 0;
	}
	cluster_t next = fat_fs->last_clst + 1;
	for (size_t checked = 0; checked < fat_fs->fat_length - 2; checked++, next++) {
		if (next >= fat_fs->fat_length || next < 2)
			next = 2;
		if (fat_fs->fat[next] == 0) {
			fat_fs->fat[next] = EOChain;
			if (clst != 0)
				fat_fs->fat[clst] = next;
			fat_fs->last_clst = next;
			lock_release (&fat_fs->write_lock);
			return next;
		}
	}
	lock_release (&fat_fs->write_lock);
	return 0;
}

/* Remove the chain of clusters starting from CLST.
 * If PCLST is 0, assume CLST as the start of the chain. */
void
fat_remove_chain (cluster_t clst, cluster_t pclst) {
	lock_acquire (&fat_fs->write_lock);
	if (clst == 0 || clst >= fat_fs->fat_length ||
	    (pclst != 0 && (pclst >= fat_fs->fat_length ||
	                    fat_fs->fat[pclst] != clst))) {
		lock_release (&fat_fs->write_lock);
		return;
	}
	if (pclst != 0)
		fat_fs->fat[pclst] = EOChain;
	/* Never index entry zero, and bound traversal even for a corrupt cycle. */
	for (size_t checked = 0; clst > 0 && clst < fat_fs->fat_length &&
	     checked < fat_fs->fat_length - 1; checked++) {
		cluster_t next = fat_fs->fat[clst];
		if (next == 0)
			break;
		fat_fs->fat[clst] = 0;
		if (next == EOChain)
			break;
		clst = next;
	}
	lock_release (&fat_fs->write_lock);
}

/* Update a value in the FAT table. */
void
fat_put (cluster_t clst, cluster_t val) {
	ASSERT (clst > 0 && clst < fat_fs->fat_length);
	ASSERT (val == 0 || val == EOChain || (val > 0 && val < fat_fs->fat_length));
	lock_acquire (&fat_fs->write_lock);
	fat_fs->fat[clst] = val;
	lock_release (&fat_fs->write_lock);
}

/* Fetch a value in the FAT table. */
cluster_t
fat_get (cluster_t clst) {
	ASSERT (clst > 0 && clst < fat_fs->fat_length);
	lock_acquire (&fat_fs->write_lock);
	cluster_t next = fat_fs->fat[clst];
	lock_release (&fat_fs->write_lock);
	return next;
}

/* Covert a cluster # to a sector number. */
disk_sector_t
cluster_to_sector (cluster_t clst) {
	ASSERT (clst > 0 && clst < fat_fs->fat_length);
	return fat_fs->data_start + (clst - 1) * SECTORS_PER_CLUSTER;
}

/* Inode metadata occupies one cluster too. Zero denotes an invalid sector. */
cluster_t
sector_to_cluster (disk_sector_t sector) {
	if (sector < fat_fs->data_start || sector >= fat_fs->bs.total_sectors ||
	    (sector - fat_fs->data_start) % SECTORS_PER_CLUSTER != 0)
		return 0;
	return (sector - fat_fs->data_start) / SECTORS_PER_CLUSTER + 1;
}
