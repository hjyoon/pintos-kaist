/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "filesys/inode.h"
#include <string.h>
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

struct file_backing {
	struct frame *resident;
	unsigned references;
};

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Transfer the pending backing reference before overwriting the union. */
bool
file_backed_initializer (struct page *page, enum vm_type type UNUSED, void *kva) {
	struct lazy_load_info *info = page->uninit.aux;
	if (info == NULL || info->file == NULL)
		return false;
	struct file_backing *backing = calloc (1, sizeof *backing);
	if (backing == NULL)
		return false;
	backing->references = 1;
	struct file_page data = {
		.file = info->file, .offset = info->offset, .read_bytes = info->read_bytes,
		.backing = backing
	};
	info->file = NULL;
	page->operations = &file_ops;
	page->file = data;
	return file_backed_swap_in (page, kva);
}

static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file = &page->file;
	lock_acquire (&filesys_lock);
	bool success = file_read_at (file->file, kva, file->read_bytes, file->offset)
	               == (off_t) file->read_bytes;
	if (success && file->read_bytes > 0)
		inode_readahead (file_get_inode (file->file), file->offset + file->read_bytes - 1);
	lock_release (&filesys_lock);
	if (success)
		memset ((uint8_t *) kva + file->read_bytes, 0, PGSIZE - file->read_bytes);
	return success;
}

/* Write only real file bytes and only when this mapping was dirtied. */
static bool
write_back (struct page *page) {
	struct frame *frame = page->frame;
	if (frame == NULL || !pml4_is_dirty (page->pml4, page->va))
		return true;
	struct file_page *file = &page->file;
	lock_acquire (&filesys_lock);
	bool success = file_write_at (file->file, frame->kva, file->read_bytes,
	                             file->offset) == (off_t) file->read_bytes;
	lock_release (&filesys_lock);
	if (success)
		pml4_set_dirty (page->pml4, page->va, false);
	return success;
}

static bool
file_backed_swap_out (struct page *page) {
	if (page->frame == NULL || !write_back (page))
		return false;
	/* The eviction layer clears every alias only after all writebacks succeed. */
	return true;
}

static void
file_backed_destroy (struct page *page) {
	write_back (page);
	lock_acquire (&filesys_lock);
	file_close (page->file.file);
	lock_release (&filesys_lock);
	if (--page->file.backing->references == 0)
		free (page->file.backing);
}

/* Reserve every page before publishing the complete mapping.  On any
   failure remove the prefix, including its unopened lazy references. */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	uintptr_t start = (uintptr_t) addr;
	if (addr == NULL || !is_user_vaddr (addr) || pg_ofs (addr) != 0 ||
	    length == 0 || length > KERN_BASE - start ||
	    offset < 0 || offset % PGSIZE != 0 || file == NULL)
		return NULL;
	size_t count = (length - 1) / PGSIZE + 1;
	struct supplemental_page_table *spt = &thread_current ()->spt;
	for (size_t i = 0; i < count; i++) {
		void *va = (void *) (start + i * PGSIZE);
		if (spt_find_page (spt, va) != NULL ||
		    pml4_get_page (thread_current ()->pml4, va) != NULL)
			return NULL;
	}
	lock_acquire (&filesys_lock);
	off_t file_size = file_length (file);
	lock_release (&filesys_lock);
	if (file_size == 0)
		return NULL;

	size_t inserted = 0;
	for (; inserted < count; inserted++) {
		struct lazy_load_info *info = malloc (sizeof *info);
		if (info == NULL)
			break;
		size_t displacement = inserted * PGSIZE;
		uint64_t position = (uint64_t) offset + displacement;
		size_t bytes = position < (uint64_t) file_size ? file_size - position : 0;
		if (bytes > PGSIZE)
			bytes = PGSIZE;
		if (bytes > length - displacement)
			bytes = length - displacement;
		/* Pages beyond EOF contain zeros and have no bytes to write back. */
		info->offset = bytes != 0 ? (off_t) position : 0;
		info->read_bytes = bytes;
		lock_acquire (&filesys_lock);
		info->file = file_reopen (file);
		lock_release (&filesys_lock);
		void *va = (void *) (start + displacement);
		if (info->file == NULL ||
		    !vm_alloc_page_with_initializer (VM_FILE, va, writable != 0, NULL, info)) {
			lock_acquire (&filesys_lock);
			file_close (info->file);
			lock_release (&filesys_lock);
			free (info);
			break;
		}
		struct page *page = spt_find_page (spt, va);
		page->mapping_start = addr;
		page->mapping_pages = inserted == 0 ? count : 0;
	}
	if (inserted == count)
		return addr;
	for (size_t i = 0; i < inserted; i++)
		spt_remove_page (spt, spt_find_page (spt, (void *) (start + i * PGSIZE)));
	return NULL;
}

void
do_munmap (void *addr) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *first = spt_find_page (spt, addr);
	if (first == NULL || first->va != addr || first->mapping_start != addr ||
	    page_get_type (first) != VM_FILE)
		return;
	size_t count = first->mapping_pages;
	for (size_t i = 0; i < count; i++) {
		struct page *page = spt_find_page (spt, (uint8_t *) addr + i * PGSIZE);
		if (page != NULL && page->mapping_start == addr)
			spt_remove_page (spt, page);
	}
}

void
file_page_share (struct page *copy, struct page *source) {
	copy->file.backing = source->file.backing;
	copy->file.backing->references++;
}

bool
file_page_private (struct page *page) {
	struct file_backing *backing = page->file.backing;
	if (backing->references > 1) {
		struct file_backing *private = calloc (1, sizeof *private);
		if (private == NULL)
			return false;
		private->references = 1;
		if (list_size (&page->frame->pages) == 1)
			backing->resident = NULL;
		backing->references--;
		page->file.backing = private;
	}
	return true;
}

struct frame *
file_page_resident (struct page *page) {
	return page->file.backing->resident;
}

void
file_page_attach (struct page *page, struct frame *frame) {
	ASSERT (page->file.backing->resident == NULL || page->file.backing->resident == frame);
	page->file.backing->resident = frame;
}

void
file_page_detach (struct page *page) {
	struct file_backing *backing = page->file.backing;
	for (struct list_elem *elem = list_begin (&page->frame->pages);
	     elem != list_end (&page->frame->pages); elem = list_next (elem)) {
		struct page *alias = list_entry (elem, struct page, frame_elem);
		if (page_get_type (alias) == VM_FILE && alias->file.backing == backing)
			return;
	}
	if (backing->resident == page->frame)
		backing->resident = NULL;
}
