/* anon.c: Implementation of page for non-disk image (a.k.a. anonymous page). */

#include "vm/vm.h"
#include "devices/disk.h"

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
	/* TODO: Set up the swap_disk. */
	swap_disk = NULL;
}

/* Initialize the file mapping */
bool
anon_initializer (struct page *page, enum vm_type type UNUSED, void *kva UNUSED) {
	page->operations = &anon_ops;
	return true;
}

/* Until swapping is implemented, initialized anonymous pages stay resident. */
static bool
anon_swap_in (struct page *page UNUSED, void *kva UNUSED) {
	return false;
}

static bool
anon_swap_out (struct page *page UNUSED) {
	return false;
}

/* The SPT releases the resident frame after the type-specific destructor. */
static void
anon_destroy (struct page *page UNUSED) {
}
