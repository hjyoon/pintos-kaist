#ifndef VM_ANON_H
#define VM_ANON_H
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_backing;
struct anon_page {
	struct anon_backing *backing;
};

void vm_anon_init (void);
void anon_share (struct page *copy, struct page *source);
bool anon_make_private (struct page *page);
struct frame *anon_resident (struct page *page);
void anon_attach (struct page *page, struct frame *frame);
void anon_detach (struct page *page);
bool anon_initializer (struct page *page, enum vm_type type, void *kva);

#endif
