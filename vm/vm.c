/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <string.h>
#include "userprog/syscall.h"

static struct list frames;
static struct lock frames_lock;

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
	lock_init (&frames_lock);
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
	/* File-backed pages are enabled in the mmap stage. */
	if (VM_TYPE (type) != VM_ANON)
		return false;
	struct page *page = malloc (sizeof *page);
	if (page == NULL)
		return false;
	uninit_new (page, upage, init, type, aux, anon_initializer);
	page->writable = writable;
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

/* Type-specific destruction runs while its mapping and frame are still
   available (e.g. for a later file-backed writeback).  The SPT owns the
   generic mapping and frame, and releases them after that callback. */
static void
destroy_spt_page (struct hash_elem *elem, void *aux UNUSED) {
	struct page *page = hash_entry (elem, struct page, spt_elem);
	struct frame *frame = page->frame;
	void *va = page->va;
	if (frame != NULL) {
		lock_acquire (&frames_lock);
		list_remove (&frame->elem);
		lock_release (&frames_lock);
	}
	vm_dealloc_page (page);
	if (frame != NULL) {
		if (pml4_get_page (frame->pml4, va) == frame->kva)
			pml4_clear_page (frame->pml4, va);
		palloc_free_page (frame->kva);
		free (frame);
	}
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	if (page != NULL && spt_find_page (spt, page->va) == page) {
		hash_delete (&spt->pages, &page->spt_elem);
		destroy_spt_page (&page->spt_elem, NULL);
	}
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* Allocate metadata and a zeroed user-pool frame.  Eviction is added in
   the swapping stage; exhaustion currently fails without leaking resources. */
static struct frame *
vm_get_frame (void) {
	struct frame *frame = calloc (1, sizeof *frame);
	if (frame == NULL)
		return NULL;
	frame->kva = palloc_get_page (PAL_USER | PAL_ZERO);
	if (frame->kva == NULL) {
		free (frame);
		return NULL;
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
		if (!vm_claim_page (next)) {
			spt_remove_page (&current->spt, spt_find_page (&current->spt, next));
			return;
		}
		bottom -= PGSIZE;
		current->stack_bottom = (void *) bottom;
	}
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	/* Copy-on-write is a later, optional stage. */
	return false;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	struct thread *current = thread_current ();
	if (!not_present || addr == NULL || !is_user_vaddr (addr))
		return false;
	struct page *page = spt_find_page (&current->spt, addr);
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
	if (!not_present || page == NULL || (write && !page->writable))
		return false;
	return vm_do_claim_page (page);
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
	struct page *page = spt_find_page (&thread_current ()->spt, va);
	return page != NULL && vm_do_claim_page (page);
}

/* Claim PAGE and set up the MMU.  Only publish a resident frame after both
   mapping and initialization succeed.  Roll back every acquired resource. */
static bool
vm_do_claim_page (struct page *page) {
	uint64_t *pml4 = thread_current ()->pml4;
	if (page == NULL || pml4 == NULL || page->operations == NULL ||
	    page->operations->swap_in == NULL)
		return false;
	if (page->frame != NULL)
		return page->frame->pml4 == pml4 &&
		       pml4_get_page (pml4, page->va) == page->frame->kva;
	if (pml4_get_page (pml4, page->va) != NULL)
		return false;

	struct frame *frame = vm_get_frame ();
	if (frame == NULL)
		return false;
	frame->pml4 = pml4;
	frame->page = page;
	page->frame = frame;
	if (!pml4_set_page (pml4, page->va, frame->kva, page->writable))
		goto fail;
	if (!swap_in (page, frame->kva)) {
		pml4_clear_page (pml4, page->va);
		goto fail;
	}
	lock_acquire (&frames_lock);
	list_push_back (&frames, &frame->elem);
	lock_release (&frames_lock);
	return true;

fail:
	page->frame = NULL;
	frame->page = NULL;
	palloc_free_page (frame->kva);
	free (frame);
	return false;
}

/* The caller must kill an existing table before initializing it again. */
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	spt->initialized = hash_init (&spt->pages, page_hash, page_less, NULL);
}

/* Preserve lazy backing references and copy resident contents independently. */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
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
			if (page_get_type (source) != VM_ANON || source->frame == NULL ||
			    !vm_alloc_page (VM_ANON, source->va, source->writable) ||
			    !vm_claim_page (source->va))
				return false;
			struct page *copy = spt_find_page (dst, source->va);
			memcpy (copy->frame->kva, source->frame->kva, PGSIZE);
		}
	}
	return true;
}

/* Destroy mappings before process_cleanup destroys their owning PML4. */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	if (spt->initialized) {
		hash_destroy (&spt->pages, destroy_spt_page);
		spt->initialized = false;
	}
}
