/* A shared sector cache with bounded asynchronous read-ahead and write-behind. */

#include "filesys/page_cache.h"
#include <debug.h>
#include <string.h>
#include "devices/timer.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"

#define CACHE_SIZE 64
#define FLUSH_INTERVAL (5 * TIMER_FREQ)

struct cache_entry {
	disk_sector_t sector;
	disk_sector_t pending;
	bool valid;
	bool busy;                 /* Reserved while an old tag is being replaced. */
	bool dirty;                /* Protected by data_lock. */
	bool accessed;
	unsigned pins;
	struct lock data_lock;
	uint8_t data[DISK_SECTOR_SIZE];
};

static struct cache_entry entries[CACHE_SIZE];
static struct lock cache_lock;
static struct condition changed;
static size_t hand;
static bool initialized;
static bool started;
static bool stopping;
static tid_t reader_tid = TID_ERROR, writer_tid = TID_ERROR;
static struct semaphore reader_ready, writer_ready;
static struct semaphore reader_done, writer_done;
static disk_sector_t requests[CACHE_SIZE];
static size_t request_head, request_count;
/* Only touched with interrupts off, including from the timer interrupt. */
static unsigned flush_ticks;
static bool flush_pending;

static void read_worker (void *aux);
static void write_worker (void *aux);

void
buffer_cache_init (void) {
	ASSERT (!initialized);
	lock_init (&cache_lock);
	cond_init (&changed);
	sema_init (&reader_ready, 0);
	sema_init (&writer_ready, 0);
	sema_init (&reader_done, 0);
	sema_init (&writer_done, 0);
	for (size_t i = 0; i < CACHE_SIZE; i++)
		lock_init (&entries[i].data_lock);
	initialized = true;
}

void
buffer_cache_start (void) {
	ASSERT (initialized);
	if (started)
		return;
	started = true;
	reader_tid = thread_create ("cache-read", PRI_DEFAULT, read_worker, NULL);
	writer_tid = thread_create ("cache-flush", PRI_DEFAULT, write_worker, NULL);
}

void
pagecache_init (void) {
	buffer_cache_start ();
}

/* Wake a blocked daemon rather than sleeping in a loop or performing I/O
   from interrupt context. Shutdown wakes the same semaphore immediately. */
void
buffer_cache_tick (void) {
	if (!started || stopping || writer_tid == TID_ERROR)
		return;
	if (++flush_ticks >= FLUSH_INTERVAL) {
		flush_ticks = 0;
		if (!flush_pending) {
			flush_pending = true;
			sema_up (&writer_ready);
		}
	}
}

/* Return a pinned entry with its data lock held. cache_lock protects tags,
   reservations and pins; no disk I/O or data-lock wait holds cache_lock. */
static struct cache_entry *
cache_get (disk_sector_t sector, bool load, bool speculative) {
	ASSERT (initialized && sector < disk_size (filesys_disk));
	lock_acquire (&cache_lock);
	for (;;) {
		struct cache_entry *found = NULL;
		for (size_t i = 0; i < CACHE_SIZE; i++) {
			struct cache_entry *entry = &entries[i];
			/* Keep the old tag visible until dirty writeback has finished.
			   The pending tag coalesces misses for its replacement too. */
			if ((entry->valid && entry->sector == sector) ||
			    (entry->busy && entry->pending == sector)) {
				found = entry;
				break;
			}
		}
		if (found != NULL) {
			if (speculative) {
				lock_release (&cache_lock);
				return NULL;
			}
			if (found->busy) {
				cond_wait (&changed, &cache_lock);
				continue;
			}
			found->pins++;
			found->accessed = true;
			lock_release (&cache_lock);
			lock_acquire (&found->data_lock);
			return found;
		}

		struct cache_entry *victim = NULL;
		for (size_t scanned = 0; scanned < CACHE_SIZE * 2; scanned++) {
			struct cache_entry *entry = &entries[hand];
			hand = (hand + 1) % CACHE_SIZE;
			if (entry->busy || entry->pins != 0)
				continue;
			if (entry->valid && entry->accessed) {
				entry->accessed = false;
				continue;
			}
			victim = entry;
			break;
		}
		if (victim == NULL) {
			if (speculative) {
				lock_release (&cache_lock);
				return NULL;
			}
			cond_wait (&changed, &cache_lock);
			continue;
		}
		victim->busy = true;
		victim->pending = sector;
		victim->pins = 1;
		lock_release (&cache_lock);
		lock_acquire (&victim->data_lock);
		if (victim->valid && victim->dirty)
			disk_write (filesys_disk, victim->sector, victim->data);
		if (load)
			disk_read (filesys_disk, sector, victim->data);
		victim->dirty = false;
		lock_acquire (&cache_lock);
		victim->sector = sector;
		victim->valid = true;
		victim->accessed = !speculative;
		victim->busy = false;
		cond_broadcast (&changed, &cache_lock);
		lock_release (&cache_lock);
		return victim;
	}
}

static void
cache_put (struct cache_entry *entry) {
	lock_release (&entry->data_lock);
	lock_acquire (&cache_lock);
	ASSERT (entry->pins > 0);
	entry->pins--;
	cond_broadcast (&changed, &cache_lock);
	lock_release (&cache_lock);
}

void
buffer_cache_read (disk_sector_t sector, void *buffer, size_t offset, size_t size) {
	ASSERT (offset <= DISK_SECTOR_SIZE && size <= DISK_SECTOR_SIZE - offset);
	if (size == 0)
		return;
	struct cache_entry *entry = cache_get (sector, true, false);
	memcpy (buffer, entry->data + offset, size);
	cache_put (entry);
}

void
buffer_cache_write (disk_sector_t sector, const void *buffer,
                    size_t offset, size_t size) {
	ASSERT (offset <= DISK_SECTOR_SIZE && size <= DISK_SECTOR_SIZE - offset);
	if (size == 0)
		return;
	/* A complete overwrite supplies all bytes, so a miss needs no disk read. */
	struct cache_entry *entry = cache_get (sector, size != DISK_SECTOR_SIZE, false);
	memcpy (entry->data + offset, buffer, size);
	entry->dirty = true;
	cache_put (entry);
}

void
buffer_cache_readahead (disk_sector_t sector) {
	if (reader_tid == TID_ERROR || sector >= disk_size (filesys_disk))
		return;
	lock_acquire (&cache_lock);
	if (stopping || request_count == CACHE_SIZE)
		goto out;
	for (size_t i = 0; i < CACHE_SIZE; i++)
		if ((entries[i].valid && entries[i].sector == sector) ||
		    (entries[i].busy && entries[i].pending == sector))
			goto out;
	for (size_t i = 0; i < request_count; i++)
		if (requests[(request_head + i) % CACHE_SIZE] == sector)
			goto out;
	requests[(request_head + request_count) % CACHE_SIZE] = sector;
	request_count++;
	sema_up (&reader_ready);
out:
	lock_release (&cache_lock);
}

void
buffer_cache_flush (void) {
	for (size_t i = 0; i < CACHE_SIZE; i++) {
		struct cache_entry *entry = &entries[i];
		lock_acquire (&cache_lock);
		while (entry->busy)
			cond_wait (&changed, &cache_lock);
		if (!entry->valid) {
			lock_release (&cache_lock);
			continue;
		}
		entry->pins++;
		lock_release (&cache_lock);
		lock_acquire (&entry->data_lock);
		if (entry->dirty) {
			disk_write (filesys_disk, entry->sector, entry->data);
			entry->dirty = false;
		}
		cache_put (entry);
	}
}

void
buffer_cache_done (void) {
	enum intr_level old = intr_disable ();
	stopping = true;
	intr_set_level (old);
	if (reader_tid != TID_ERROR) {
		sema_up (&reader_ready);
		sema_down (&reader_done);
	}
	if (writer_tid != TID_ERROR) {
		sema_up (&writer_ready);
		sema_down (&writer_done);
	}
	buffer_cache_flush ();
}

static void
read_worker (void *aux UNUSED) {
	for (;;) {
		sema_down (&reader_ready);
		lock_acquire (&cache_lock);
		if (stopping) {
			lock_release (&cache_lock);
			break;
		}
		ASSERT (request_count > 0);
		disk_sector_t sector = requests[request_head];
		request_head = (request_head + 1) % CACHE_SIZE;
		request_count--;
		lock_release (&cache_lock);
		struct cache_entry *entry = cache_get (sector, true, true);
		if (entry != NULL)
			cache_put (entry);
	}
	/* Report cache quiescence before generic kernel-thread exit cleanup. */
	sema_up (&reader_done);
}

static void
write_worker (void *aux UNUSED) {
	for (;;) {
		sema_down (&writer_ready);
		enum intr_level old = intr_disable ();
		flush_pending = false;
		bool stop = stopping;
		intr_set_level (old);
		if (stop)
			break;
		buffer_cache_flush ();
	}
	sema_up (&writer_done);
}
