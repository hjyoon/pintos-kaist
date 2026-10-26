#ifndef FILESYS_PAGE_CACHE_H
#define FILESYS_PAGE_CACHE_H

#include <stdbool.h>
#include <stddef.h>
#include "devices/disk.h"

/* VM keeps this union member for compatibility. Cache storage is shared by
   the filesystem and consists of exactly 64 sector-sized slots. */
struct page_cache {
	disk_sector_t sector;
};

void buffer_cache_init (void);
void buffer_cache_start (void);
void buffer_cache_tick (void);
void buffer_cache_flush (void);
void buffer_cache_done (void);
void buffer_cache_read (disk_sector_t sector, void *buffer, size_t offset, size_t size);
void buffer_cache_write (disk_sector_t sector, const void *buffer,
                         size_t offset, size_t size);
void buffer_cache_readahead (disk_sector_t sector);
/* Existing VM startup hook. */
void pagecache_init (void);

#endif
