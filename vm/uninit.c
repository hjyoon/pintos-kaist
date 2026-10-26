/* uninit.c: Implementation of uninitialized page.
 *
 * All of the pages are born as uninit page. When the first page fault occurs,
 * the handler chain calls uninit_initialize (page->operations.swap_in).
 * The uninit_initialize function transmutes the page into the specific page
 * object (anon, file, page_cache), by initializing the page object,and calls
 * initialization callback that passed from vm_alloc_page_with_initializer
 * function.
 * */

#include "vm/vm.h"
#include "vm/uninit.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"

static bool uninit_initialize (struct page *page, void *kva);
static void uninit_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations uninit_ops = {
	.swap_in = uninit_initialize,
	.swap_out = NULL,
	.destroy = uninit_destroy,
	.type = VM_UNINIT,
};

/* DO NOT MODIFY this function */
void
uninit_new (struct page *page, void *va, vm_initializer *init,
		enum vm_type type, void *aux,
		bool (*initializer)(struct page *, enum vm_type, void *)) {
	ASSERT (page != NULL);

	*page = (struct page) {
		.operations = &uninit_ops,
		.va = va,
		.frame = NULL, /* no frame for now */
		.uninit = (struct uninit_page) {
			.init = init,
			.type = type,
			.aux = aux,
			.page_initializer = initializer,
		}
	};
}

/* Initalize the page on first fault */
static bool
uninit_initialize (struct page *page, void *kva) {
	struct uninit_page *uninit = &page->uninit;

	/* Fetch first, page_initialize may overwrite the values */
	vm_initializer *init = uninit->init;
	void *aux = uninit->aux;

	enum vm_type type = uninit->type;
	bool (*initializer) (struct page *, enum vm_type, void *) =
		uninit->page_initializer;
	bool initialized = initializer (page, type, kva);
	/* A failed type allocation must retain the lazy callback and its AUX. */
	if (!initialized && page->operations->type == VM_UNINIT)
		return false;
	bool success = initialized && (init == NULL || init (page, aux));
	if (aux != NULL) {
		struct lazy_load_info *info = aux;
		lock_acquire (&filesys_lock);
		file_close (info->file);
		lock_release (&filesys_lock);
		free (info);
	}
	if (page->operations->type == VM_UNINIT)
		page->uninit.aux = NULL;
	return success;
}

/* Free the resources hold by uninit_page. Although most of pages are transmuted
 * to other page objects, it is possible to have uninit pages when the process
 * exit, which are never referenced during the execution.
 * PAGE will be freed by the caller. */
static void
uninit_destroy (struct page *page) {
	struct lazy_load_info *info = page->uninit.aux;
	if (info != NULL) {
		lock_acquire (&filesys_lock);
		file_close (info->file);
		lock_release (&filesys_lock);
		free (info);
	}
}
