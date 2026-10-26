/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <string.h>
#include "userprog/syscall.h"
#include "intrinsic.h"

static struct list frames;
static struct lock vm_lock;

static uint64_t page_hash (const struct hash_elem *, void *);
static bool page_less (const struct hash_elem *, const struct hash_elem *, void *);
static void destroy_spt_page (struct hash_elem *, void *);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	list_init (&frames);
	lock_init (&vm_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	struct supplemental_page_table *spt = &thread_current ()->spt;
	if (upage == NULL || !is_user_vaddr (upage) || pg_ofs (upage) != 0 ||
	    !spt->initialized || spt_find_page (spt, upage) != NULL)
		return false;
	bool (*initializer) (struct page *, enum vm_type, void *);
	switch (VM_TYPE (type)) {
		case VM_ANON: initializer = anon_initializer; break;
		case VM_FILE: initializer = file_backed_initializer; break;
		default: return false;
	}
	struct page *page = malloc (sizeof *page);
	if (page == NULL)
		return false;
	uninit_new (page, upage, init, type, aux, initializer);
	page->writable = writable;
	page->pml4 = thread_current ()->pml4;
	if (!spt_insert_page (spt, page)) {
		/* On failure the caller still owns AUX. */
		free (page);
		return false;
	}
	return true;
}

/* Hash page-aligned addresses, so any byte in a page finds the same entry. */
static uint64_t
page_hash (const struct hash_elem *elem, void *aux UNUSED) {
	const struct page *page = hash_entry (elem, struct page, spt_elem);
	return hash_bytes (&page->va, sizeof page->va);
}

static bool
page_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED) {
	const struct page *left = hash_entry (a, struct page, spt_elem);
	const struct page *right = hash_entry (b, struct page, spt_elem);
	return (uintptr_t) left->va < (uintptr_t) right->va;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	if (spt == NULL || !spt->initialized || va == NULL || !is_user_vaddr (va))
		return NULL;
	struct page key = { .va = pg_round_down (va) };
	struct hash_elem *elem = hash_find (&spt->pages, &key.spt_elem);
	return elem != NULL ? hash_entry (elem, struct page, spt_elem) : NULL;
}

/* Ownership transfers to SPT only on a successful insertion. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
	if (spt == NULL || !spt->initialized || page == NULL ||
	    page->va == NULL || !is_user_vaddr (page->va) || pg_ofs (page->va) != 0)
		return false;
	return hash_insert (&spt->pages, &page->spt_elem) == NULL;
}

/* Page-table edits must invalidate the active translation, including when
   a writable mapping becomes a protected COW mapping. */
static void
refresh_translation (struct page *page) {
	if (rcr3 () == vtop (page->pml4))
		invlpg ((uint64_t) page->va);
}

static void
set_writable (struct page *page, bool writable) {
	uint64_t *pte = pml4e_walk (page->pml4, (uint64_t) page->va, false);
	ASSERT (pte != NULL && (*pte & PTE_P) != 0);
	if (writable)
		*pte |= PTE_W;
	else
		*pte &= ~PTE_W;
	refresh_translation (page);
}

static void
update_representative (struct frame *frame) {
	frame->page = list_empty (&frame->pages) ? NULL :
	              list_entry (list_front (&frame->pages), struct page, frame_elem);
	frame->pml4 = frame->page != NULL ? frame->page->pml4 : NULL;
}

static void
attach_frame (struct page *page, struct frame *frame) {
	page->frame = frame;
	list_push_back (&frame->pages, &page->frame_elem);
	if (page_get_type (page) == VM_ANON)
		anon_attach (page, frame);
	else
		file_page_attach (page, frame);
	update_representative (frame);
	if (!frame->listed) {
		list_push_back (&frames, &frame->elem);
		frame->listed = true;
	}
}

static void
discard_frame (struct frame *frame) {
	ASSERT (list_empty (&frame->pages));
	if (frame->listed)
		list_remove (&frame->elem);
	palloc_free_page (frame->kva);
	free (frame);
}

/* The type destructor retains access to its mapping during file writeback.
   Other processes' aliases outlive removal of this one SPT entry. */
static void
destroy_spt_page (struct hash_elem *elem, void *aux UNUSED) {
	struct page *page = hash_entry (elem, struct page, spt_elem);
	struct frame *frame = page->frame;
	void *va = page->va;
	uint64_t *pml4 = page->pml4;
	if (frame != NULL) {
		list_remove (&page->frame_elem);
		if (page_get_type (page) == VM_ANON)
			anon_detach (page);
		else
			file_page_detach (page);
		update_representative (frame);
	}
	vm_dealloc_page (page);
	if (frame != NULL) {
		if (pml4_get_page (pml4, va) == frame->kva)
			pml4_clear_page (pml4, va);
		if (list_empty (&frame->pages))
			discard_frame (frame);
	}
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	lock_acquire (&vm_lock);
	if (page != NULL && spt_find_page (spt, page->va) == page) {
		hash_delete (&spt->pages, &page->spt_elem);
		destroy_spt_page (&page->spt_elem, NULL);
	}
	lock_release (&vm_lock);
}

/* Second-chance clock, rotating the list instead of retaining stale cursors. */
static struct frame *
vm_get_victim (void) {
	size_t attempts = list_size (&frames) * 2;
	while (attempts-- > 0) {
		struct frame *frame = list_entry (list_pop_front (&frames), struct frame, elem);
		list_push_back (&frames, &frame->elem);
		if (frame->pins != 0)
			continue;
		bool accessed = false;
		for (struct list_elem *elem = list_begin (&frame->pages);
		     elem != list_end (&frame->pages); elem = list_next (elem)) {
			struct page *page = list_entry (elem, struct page, frame_elem);
			if (pml4_is_accessed (page->pml4, page->va)) {
				accessed = true;
				pml4_set_accessed (page->pml4, page->va, false);
			}
		}
		if (accessed)
			continue;
		return frame;
	}
	return NULL;
}

static struct frame *
vm_evict_frame (void) {
	/* If swap is full a file-backed victim may still be reclaimable. */
	size_t attempts = list_size (&frames);
	while (attempts-- > 0) {
		struct frame *victim = vm_get_victim ();
		if (victim == NULL)
			break;
		bool saved = true;
		for (struct list_elem *elem = list_begin (&victim->pages);
		     elem != list_end (&victim->pages); elem = list_next (elem)) {
			struct page *page = list_entry (elem, struct page, frame_elem);
			if (!swap_out (page)) {
				saved = false;
				break;
			}
		}
		if (!saved)
			continue;
		while (!list_empty (&victim->pages)) {
			struct page *page = list_entry (list_pop_front (&victim->pages),
			                               struct page, frame_elem);
			pml4_clear_page (page->pml4, page->va);
			if (page_get_type (page) == VM_ANON)
				anon_detach (page);
			else
				file_page_detach (page);
			page->frame = NULL;
		}
		update_representative (victim);
		return victim;
	}
	return NULL;
}

/* Called with vm_lock held; returned frames are not evictable until publish. */
static struct frame *
vm_get_frame (void) {
	struct frame *frame = calloc (1, sizeof *frame);
	if (frame == NULL)
		return NULL;
	list_init (&frame->pages);
	frame->kva = palloc_get_page (PAL_USER | PAL_ZERO);
	if (frame->kva == NULL) {
		free (frame);
		frame = vm_evict_frame ();
		if (frame != NULL)
			memset (frame->kva, 0, PGSIZE);
	}
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	struct thread *current = thread_current ();
	uintptr_t target = (uintptr_t) pg_round_down (addr);
	uintptr_t bottom = (uintptr_t) current->stack_bottom;
	if (bottom == 0)
		return;
	while (bottom > target) {
		void *next = (void *) (bottom - PGSIZE);
		if (!vm_alloc_page (VM_ANON | VM_MARKER_0, next, true))
			return;
		if (!vm_do_claim_page (spt_find_page (&current->spt, next))) {
			struct page *page = spt_find_page (&current->spt, next);
			hash_delete (&current->spt.pages, &page->spt_elem);
			destroy_spt_page (&page->spt_elem, NULL);
			return;
		}
		bottom -= PGSIZE;
		current->stack_bottom = (void *) bottom;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page) {
	if (page == NULL || !page->writable || !page->cow || page->frame == NULL)
		return false;
	struct frame *old = page->frame;
	if (list_size (&old->pages) == 1) {
		if (page_get_type (page) == VM_ANON) {
			if (!anon_make_private (page))
				return false;
			anon_attach (page, old);
		} else {
			if (!file_page_private (page))
				return false;
			file_page_attach (page, old);
		}
		page->cow = false;
		set_writable (page, true);
		return true;
	}

	old->pins++;
	struct frame *fresh = vm_get_frame ();
	if (fresh == NULL) {
		old->pins--;
		return false;
	}
	memcpy (fresh->kva, old->kva, PGSIZE);
	bool private = page_get_type (page) == VM_ANON ?
	               anon_make_private (page) : file_page_private (page);
	if (!private) {
		discard_frame (fresh);
		old->pins--;
		return false;
	}
	bool dirty = pml4_is_dirty (page->pml4, page->va);
	if (!pml4_set_page (page->pml4, page->va, fresh->kva, true)) {
		discard_frame (fresh);
		old->pins--;
		return false;
	}
	refresh_translation (page);
	list_remove (&page->frame_elem);
	update_representative (old);
	attach_frame (page, fresh);
	page->cow = false;
	pml4_set_dirty (page->pml4, page->va, dirty);
	old->pins--;
	return true;
}

/* Return true on success */
static bool
handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	struct thread *current = thread_current ();
	if (addr == NULL || !is_user_vaddr (addr))
		return false;
	struct page *page = spt_find_page (&current->spt, addr);
	if (!not_present)
		return write && page != NULL && page->writable && page->cow &&
		       vm_do_claim_page (page) && vm_handle_wp (page);
	if (page == NULL) {
		uintptr_t rsp = user && f != NULL ? f->rsp : (uintptr_t) current->user_rsp;
		uintptr_t address = (uintptr_t) addr;
		uintptr_t limit = USER_STACK - (1 << 20);
		if (rsp < limit || rsp > USER_STACK || address < limit ||
		    address >= USER_STACK || address + 8 < rsp)
			return false;
		vm_stack_growth (addr);
		page = spt_find_page (&current->spt, addr);
	}
	/* A stack heuristic never overrides an existing page's permissions. */
	if (page == NULL || (write && !page->writable) || !vm_do_claim_page (page))
		return false;
	return !write || !page->cow || vm_handle_wp (page);
}

bool
vm_try_handle_fault (struct intr_frame *f, void *addr, bool user,
                     bool write, bool not_present) {
	lock_acquire (&vm_lock);
	bool success = handle_fault (f, addr, user, write, not_present);
	lock_release (&vm_lock);
	return success;
}

/* Validate metadata without faulting the entire range into physical memory. */
bool
vm_user_buffer_valid (const void *buffer, size_t size, bool writable) {
	if (size == 0)
		return true;
	uintptr_t start = (uintptr_t) buffer;
	if (buffer == NULL || !is_user_vaddr (buffer) || size > KERN_BASE - start)
		return false;
	lock_acquire (&vm_lock);
	bool valid = true;
	uintptr_t last = (uintptr_t) pg_round_down (start + size - 1);
	for (uintptr_t va = (uintptr_t) pg_round_down (start);; va += PGSIZE) {
		struct page *page = spt_find_page (&thread_current ()->spt, (void *) va);
		if (page == NULL) {
			void *fault = (void *) (va < start ? start : va);
			if (handle_fault (NULL, fault, false, writable, true))
				page = spt_find_page (&thread_current ()->spt, (void *) va);
		}
		if (page == NULL || (writable && !page->writable)) {
			valid = false;
			break;
		}
		if (va == last)
			break;
	}
	lock_release (&vm_lock);
	return valid;
}

/* User I/O touches one resident page at a time, with no filesystem lock held.
   vm_lock prevents eviction while the kernel copies through the frame alias. */
bool
vm_copy_user (void *kernel, void *user, size_t size, bool to_user) {
	lock_acquire (&vm_lock);
	bool success = true;
	while (size > 0) {
		struct page *page = spt_find_page (&thread_current ()->spt, user);
		if (page == NULL || (to_user && !page->writable) || !vm_do_claim_page (page) ||
		    (to_user && page->cow && !vm_handle_wp (page))) {
			success = false;
			break;
		}
		size_t bytes = PGSIZE - pg_ofs (user);
		if (bytes > size)
			bytes = size;
		void *alias = (uint8_t *) page->frame->kva + pg_ofs (user);
		if (to_user) {
			memcpy (alias, kernel, bytes);
			pml4_set_dirty (page->pml4, page->va, true);
		} else
			memcpy (kernel, alias, bytes);
		pml4_set_accessed (page->pml4, page->va, true);
		user = (uint8_t *) user + bytes;
		kernel = (uint8_t *) kernel + bytes;
		size -= bytes;
	}
	lock_release (&vm_lock);
	return success;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim an existing SPT entry; an absent entry is never implicitly created. */
bool
vm_claim_page (void *va) {
	lock_acquire (&vm_lock);
	struct page *page = spt_find_page (&thread_current ()->spt, va);
	bool success = page != NULL && vm_do_claim_page (page);
	lock_release (&vm_lock);
	return success;
}

/* Claim PAGE and set up the MMU.  Only publish a resident frame after both
   mapping and initialization succeed.  Roll back every acquired resource. */
static bool
vm_do_claim_page (struct page *page) {
	uint64_t *pml4 = page != NULL ? page->pml4 : NULL;
	if (page == NULL || pml4 == NULL || page->operations == NULL ||
	    page->operations->swap_in == NULL)
		return false;
	if (page->frame != NULL)
		return pml4_get_page (pml4, page->va) == page->frame->kva;
	if (pml4_get_page (pml4, page->va) != NULL)
		return false;
	struct frame *resident = NULL;
	if (page->operations->type == VM_ANON)
		resident = anon_resident (page);
	else if (page->operations->type == VM_FILE)
		resident = file_page_resident (page);
	if (resident != NULL) {
		if (!pml4_set_page (pml4, page->va, resident->kva, page->writable && !page->cow))
			return false;
		attach_frame (page, resident);
		return true;
	}

	struct frame *frame = vm_get_frame ();
	if (frame == NULL)
		return false;
	frame->pml4 = pml4;
	frame->page = page;
	page->frame = frame;
	if (!pml4_set_page (pml4, page->va, frame->kva, page->writable && !page->cow))
		goto fail;
	if (!swap_in (page, frame->kva)) {
		pml4_clear_page (pml4, page->va);
		goto fail;
	}
	attach_frame (page, frame);
	return true;

fail:
	page->frame = NULL;
	frame->page = NULL;
	discard_frame (frame);
	return false;
}

/* The caller must kill an existing table before initializing it again. */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	spt->initialized = hash_init (&spt->pages, page_hash, page_less, NULL);
}

/* Pending initializers retain independent backing references. Resident pages
   share frames; swapped anonymous pages share immutable disk snapshots. */
static bool
copy_spt (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	if (!dst->initialized || !src->initialized || !hash_empty (&dst->pages))
		return false;
	struct hash_iterator iterator;
	hash_first (&iterator, &src->pages);
	while (hash_next (&iterator)) {
		struct page *source = hash_entry (hash_cur (&iterator), struct page, spt_elem);
		if (source->operations->type == VM_UNINIT) {
			struct lazy_load_info *info = NULL;
			if (source->uninit.aux != NULL) {
				info = malloc (sizeof *info);
				if (info == NULL)
					return false;
				*info = *(struct lazy_load_info *) source->uninit.aux;
				lock_acquire (&filesys_lock);
				info->file = file_reopen (info->file);
				lock_release (&filesys_lock);
				if (info->file == NULL) {
					free (info);
					return false;
				}
			}
			if (!vm_alloc_page_with_initializer (source->uninit.type, source->va,
			                                    source->writable, source->uninit.init, info)) {
				if (info != NULL) {
					lock_acquire (&filesys_lock);
					file_close (info->file);
					lock_release (&filesys_lock);
					free (info);
				}
				return false;
			}
		} else {
			struct page *copy = calloc (1, sizeof *copy);
			if (copy == NULL)
				return false;
			copy->operations = source->operations;
			copy->va = source->va;
			copy->pml4 = thread_current ()->pml4;
			copy->writable = source->writable;
			copy->cow = source->writable;
			if (page_get_type (source) == VM_ANON)
				anon_share (copy, source);
			else if (page_get_type (source) == VM_FILE) {
				copy->file = source->file;
				lock_acquire (&filesys_lock);
				copy->file.file = file_reopen (source->file.file);
				lock_release (&filesys_lock);
				if (copy->file.file == NULL) {
					free (copy);
					return false;
				}
				file_page_share (copy, source);
			} else {
				free (copy);
				return false;
			}
			if (!spt_insert_page (dst, copy)) {
				vm_dealloc_page (copy);
				return false;
			}
			if (source->frame != NULL) {
				if (!pml4_set_page (copy->pml4, copy->va, source->frame->kva, false))
					return false;
				attach_frame (copy, source->frame);
				set_writable (source, false);
				pml4_set_dirty (copy->pml4, copy->va,
				                pml4_is_dirty (source->pml4, source->va));
			}
			source->cow = source->writable;
		}
		struct page *copy = spt_find_page (dst, source->va);
		copy->mapping_start = source->mapping_start;
		copy->mapping_pages = source->mapping_pages;
	}
	return true;
}

bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
                             struct supplemental_page_table *src) {
	lock_acquire (&vm_lock);
	bool success = copy_spt (dst, src);
	lock_release (&vm_lock);
	return success;
}

/* Destroy mappings before process_cleanup destroys their owning PML4. */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	lock_acquire (&vm_lock);
	if (spt->initialized) {
		hash_destroy (&spt->pages, destroy_spt_page);
		spt->initialized = false;
	}
	lock_release (&vm_lock);
}
