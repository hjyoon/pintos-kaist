#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"

struct page;
enum vm_type;

struct file_backing;
struct file_page {
	struct file_backing *backing;
	struct file *file;     /* Owned independently of the descriptor. */
	off_t offset;
	size_t read_bytes;
};

void vm_file_init (void);
void file_page_share (struct page *copy, struct page *source);
bool file_page_private (struct page *page);
struct frame *file_page_resident (struct page *page);
void file_page_attach (struct page *page, struct frame *frame);
void file_page_detach (struct page *page);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap (void *va);
#endif
