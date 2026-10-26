/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "lib/kernel/bitmap.h"

/* All backing state is serialized by the VM lock. */
struct anon_backing {
	size_t slot;
	unsigned references;
	struct frame *resident;
};
static struct bitmap *swap_slots;
#define SECTORS_PER_PAGE (PGSIZE / DISK_SECTOR_SIZE)

/* DO NOT MODIFY BELOW LINE */
static struct disk *swap_disk;
static bool anon_swap_in (struct page *page, void *kva);
static bool anon_swap_out (struct page *page);
static void anon_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations anon_ops = {
	.swap_in = anon_swap_in,
	.swap_out = anon_swap_out,
	.destroy = anon_destroy,
	.type = VM_ANON,
};

/* Initialize the data for anonymous pages */
void
vm_anon_init (void) {
	swap_disk = disk_get (1, 1);
	if (swap_disk != NULL)
		swap_slots = bitmap_create (disk_size (swap_disk) / SECTORS_PER_PAGE);
}

bool
anon_initializer (struct page *page, enum vm_type type UNUSED, void *kva UNUSED) {
	struct anon_backing *backing = malloc (sizeof *backing);
	if (backing == NULL)
		return false;
	backing->slot = BITMAP_ERROR;
	backing->references = 1;
	backing->resident = NULL;
	page->operations = &anon_ops;
	page->anon.backing = backing;
	return true;
}

static bool
anon_swap_in (struct page *page, void *kva) {
	struct anon_backing *backing = page->anon.backing;
	if (backing->slot == BITMAP_ERROR || swap_slots == NULL)
		return false;
	for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
		disk_read (swap_disk, backing->slot * SECTORS_PER_PAGE + i,
		           (uint8_t *) kva + i * DISK_SECTOR_SIZE);
	if (backing->references == 1) {
		bitmap_reset (swap_slots, backing->slot);
		backing->slot = BITMAP_ERROR;
	}
	return true;
}

static bool
anon_swap_out (struct page *page) {
	struct anon_backing *backing = page->anon.backing;
	if (swap_slots == NULL)
		return false;
	if (backing->slot == BITMAP_ERROR) {
		size_t slot = bitmap_scan_and_flip (swap_slots, 0, 1, false);
		if (slot == BITMAP_ERROR)
			return false;
		for (size_t i = 0; i < SECTORS_PER_PAGE; i++)
			disk_write (swap_disk, slot * SECTORS_PER_PAGE + i,
			            (uint8_t *) page->frame->kva + i * DISK_SECTOR_SIZE);
		backing->slot = slot;
	}
	return true;
}

static void
anon_destroy (struct page *page) {
	struct anon_backing *backing = page->anon.backing;
	if (--backing->references == 0) {
		if (backing->slot != BITMAP_ERROR)
			bitmap_reset (swap_slots, backing->slot);
		free (backing);
	}
}

/* Sharing an anonymous snapshot also shares its swap slot if nonresident. */
void
anon_share (struct page *copy, struct page *source) {
	copy->anon.backing = source->anon.backing;
	copy->anon.backing->references++;
}

/* Called before a protected page can be written. The old disk snapshot
   remains immutable while another process still refers to it. */
bool
anon_make_private (struct page *page) {
	struct anon_backing *backing = page->anon.backing;
	if (backing->references > 1) {
		struct anon_backing *private = malloc (sizeof *private);
		if (private == NULL)
			return false;
		private->slot = BITMAP_ERROR;
		private->references = 1;
		private->resident = NULL;
		if (list_size (&page->frame->pages) == 1)
			backing->resident = NULL;
		backing->references--;
		page->anon.backing = private;
	} else if (backing->slot != BITMAP_ERROR) {
		bitmap_reset (swap_slots, backing->slot);
		backing->slot = BITMAP_ERROR;
	}
	return true;
}

/* Reuse a resident snapshot when a sibling faults it back in first. */
struct frame *
anon_resident (struct page *page) {
	return page->anon.backing->resident;
}

void
anon_attach (struct page *page, struct frame *frame) {
	ASSERT (page->anon.backing->resident == NULL ||
	        page->anon.backing->resident == frame);
	page->anon.backing->resident = frame;
}

/* Called after removing PAGE's alias but before its backing is released. */
void
anon_detach (struct page *page) {
	struct anon_backing *backing = page->anon.backing;
	for (struct list_elem *elem = list_begin (&page->frame->pages);
	     elem != list_end (&page->frame->pages); elem = list_next (elem)) {
		struct page *alias = list_entry (elem, struct page, frame_elem);
		if (page_get_type (alias) == VM_ANON && alias->anon.backing == backing)
			return;
	}
	if (backing->resident == page->frame)
		backing->resident = NULL;
}
