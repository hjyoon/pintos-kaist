/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/* NOTE: The beginning where custom code is added */
struct uninit_page_aux {
    struct file *file;
    off_t ofs;
    size_t read_bytes;
    size_t zero_bytes;
    bool writable;
};
/* NOTE: The end where custom code is added */

/* NOTE: The beginning where custom code is added */
bool
uninit_new (struct page **page, void *upage, vm_initializer *init, void *aux) {
    *page = malloc(sizeof(struct page));
    if (*page == NULL)
        return false;

    (*page)->va = upage;
    (*page)->status = VM_UNINIT;
    (*page)->uninit.init = init;
    (*page)->uninit.aux = aux;
    (*page)->uninit.type = VM_TYPE(aux); // 적절한 타입 설정

    // 기타 초기화 작업 (예: locks 초기화 등)

    return true;
}
/* NOTE: The end where custom code is added */

/* NOTE: The beginning where custom code is added */
/* 페이지의 가상 주소를 기반으로 해시 값을 계산 */
static unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}
/* 두 페이지의 가상 주소를 비교하여 순서를 결정 */
static bool
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);
    return a->va < b->va;
}
/* NOTE: The end where custom code is added */

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
	/* TODO: Your code goes here. */
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
// bool
// vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
// 		vm_initializer *init, void *aux) {

// 	ASSERT (VM_TYPE(type) != VM_UNINIT)

// 	struct supplemental_page_table *spt = &thread_current ()->spt;

// 	/* Check wheter the upage is already occupied or not. */
// 	if (spt_find_page (spt, upage) == NULL) {
// 		/* TODO: Create the page, fetch the initialier according to the VM type,
// 		 * TODO: and then create "uninit" page struct by calling uninit_new. You
// 		 * TODO: should modify the field after calling the uninit_new. */

// 		/* TODO: Insert the page into the spt. */
// 	}
// err:
// 	return false;
// }

bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
        vm_initializer *init, void *aux) {

    ASSERT (VM_TYPE(type) != VM_UNINIT);
    ASSERT (pg_ofs(upage) == 0); // 페이지 정렬 확인

    struct supplemental_page_table *spt = &thread_current ()->spt;

    /* Check whether the upage is already occupied or not. */
    if (spt_find_page (spt, upage) != NULL) {
        return false; // 이미 페이지가 존재함
    }

    struct page *page = NULL;

    switch (type) {
        case VM_FILE:
            /* aux는 uninit_page에 필요한 정보 */
            struct uninit_page_aux *aux_page = malloc(sizeof(struct uninit_page_aux));
            if (aux_page == NULL)
                return false;
            aux_page->file = (struct file *)aux;
            aux_page->ofs = (off_t)(long)aux; // 적절히 캐스팅 필요
            aux_page->read_bytes = /* 읽을 바이트 수 설정 */;
            aux_page->zero_bytes = PGSIZE - aux_page->read_bytes;
            aux_page->writable = writable;

            /* uninit_new 호출 */
            if (!uninit_new(&page, upage, init, aux_page)) {
                free(aux_page);
                return false;
            }
            break;

        case VM_ANON:
            /* VM_ANON 타입의 경우, aux는 필요 없을 수 있음 */
            if (!uninit_new(&page, upage, init, aux)) {
                return false;
            }
            break;

        default:
            /* 지원되지 않는 타입 */
            return false;
    }

    /* 보조 페이지 테이블에 페이지 추가 */
    if (!spt_insert_page(spt, page)) {
        /* 페이지 삽입 실패 시, 페이지와 aux 해제 */
        page->operations->destroy(page);
        return false;
    }

    return true;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */

	return page;
}

/* Insert PAGE into spt with validation. */
// bool
// spt_insert_page (struct supplemental_page_table *spt UNUSED,
// 		struct page *page UNUSED) {
// 	int succ = false;
// 	/* TODO: Fill this function. */

// 	return succ;
// }

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt, struct page *page) {
    struct hash_elem *existing;

    /* 페이지가 이미 존재하는지 확인 */
    existing = hash_find (&spt->hash, &page->hash_elem);
    if (existing != NULL) {
        /* 페이지가 이미 존재하므로 삽입 실패 */
        return false;
    }

    /* 새로운 페이지를 해시 테이블에 삽입 */
    if (hash_insert (&spt->hash, &page->hash_elem) == NULL) {
        /* 삽입 성공 */
        return true;
    }
    else {
        /* 삽입 실패 (예: 해시 충돌 등) */
        return false;
    }
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
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

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
}
