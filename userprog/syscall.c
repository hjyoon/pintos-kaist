#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"

/* NOTE: The beginning where custom code is added */
#include "threads/palloc.h"
#include "threads/mmu.h"
#include "threads/pte.h"
#include <string.h>
/* NOTE: The end where custom code is added */

#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* Reject invalid user ranges before allocating resources or dereferencing
   user pointers.  A zero-length range does not access its pointer. */
bool
user_buffer_valid (const void *buffer, size_t size, bool writable) {
	if (size == 0)
		return true;

	uintptr_t start = (uintptr_t) buffer;
	if (buffer == NULL || !is_user_vaddr (buffer) || size > KERN_BASE - start)
		return false;

	uint64_t *pml4 = thread_current ()->pml4;
	if (pml4 == NULL)
		return false;
	uintptr_t last_page = (uintptr_t) pg_round_down (start + size - 1);
	for (uintptr_t page = (uintptr_t) pg_round_down (start);;
	     page += PGSIZE) {
		uint64_t *pte = pml4e_walk (pml4, page, 0);
		if (pte == NULL || (*pte & (PTE_P | PTE_U)) != (PTE_P | PTE_U) ||
		    (writable && (*pte & PTE_W) == 0))
			return false;
		if (page == last_page)
			return true;
	}
}

/* Both system calls and user exceptions use the same exit path. */
void
syscall_exit (int status) {
	thread_current ()->exit_status = status;
	thread_exit ();
}

static int
sys_write (int fd, const void *buffer, unsigned size) {
	if (!user_buffer_valid (buffer, size, false))
		syscall_exit (-1);
	if (fd != STDOUT_FILENO)
		return -1;
	if (size == 0)
		return 0;

	/* Reuse one page for arbitrarily sized, validated user buffers. */
	char *copy = palloc_get_page (0);
	if (copy == NULL)
		return -1;
	for (size_t offset = 0; offset < size;) {
		size_t chunk = size - offset;
		if (chunk > PGSIZE)
			chunk = PGSIZE;
		memcpy (copy, (const char *) buffer + offset, chunk);
		putbuf (copy, chunk);
		offset += chunk;
	}
	palloc_free_page (copy);
	return size;
}

void
syscall_handler (struct intr_frame *f) {
	switch (f->R.rax) {
		case SYS_EXIT:
			syscall_exit ((int) f->R.rdi);
		case SYS_WRITE:
			f->R.rax = sys_write ((int) f->R.rdi,
			                     (const void *) f->R.rsi,
			                     (unsigned) f->R.rdx);
			break;
		default:
			syscall_exit (-1);
	}
}
