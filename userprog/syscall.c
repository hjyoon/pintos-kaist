#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "userprog/process.h"

/* NOTE: The beginning where custom code is added */
#include "threads/palloc.h"
#include "threads/mmu.h"
#include "threads/pte.h"
#include <string.h>
/* NOTE: The end where custom code is added */

#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

struct lock filesys_lock;

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
	lock_init (&filesys_lock);
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

/* Copy strings a page at a time, stopping at NUL before checking any
   later page.  No filesystem lock is held on a validation failure. */
static char *
copy_user_string (const char *user) {
	if (!user_buffer_valid (user, 1, false))
		syscall_exit (-1);
	char *copy = palloc_get_page (0);
	if (copy == NULL)
		return NULL;
	for (size_t offset = 0; offset < PGSIZE;) {
		const char *part = user + offset;
		size_t chunk = PGSIZE - pg_ofs (part);
		if (chunk > PGSIZE - offset)
			chunk = PGSIZE - offset;
		if (!user_buffer_valid (part, chunk, false)) {
			palloc_free_page (copy);
			syscall_exit (-1);
		}
		const char *end = memchr (part, '\0', chunk);
		if (end != NULL) {
			memcpy (copy + offset, part, end - part + 1);
			return copy;
		}
		memcpy (copy + offset, part, chunk);
		offset += chunk;
	}
	palloc_free_page (copy);
	return NULL;
}

static struct file *
lookup_file (int fd) {
	struct file **table = thread_current ()->fd_table;
	return table != NULL && fd >= 2 && fd < FD_COUNT ? table[fd] : NULL;
}

static int
sys_open (const char *user) {
	char *name = copy_user_string (user);
	if (name == NULL)
		return -1;
	struct thread *current = thread_current ();
	int fd;
	for (fd = 2; fd < FD_COUNT; fd++)
		if (current->fd_table[fd] == NULL)
			break;
	if (fd == FD_COUNT) {
		palloc_free_page (name);
		return -1;
	}
	lock_acquire (&filesys_lock);
	struct file *file = filesys_open (name);
	lock_release (&filesys_lock);
	palloc_free_page (name);
	if (file == NULL)
		return -1;
	current->fd_table[fd] = file;
	return fd;
}

static bool
sys_create (const char *user, unsigned size) {
	char *name = copy_user_string (user);
	if (name == NULL)
		return false;
	lock_acquire (&filesys_lock);
	bool success = size <= INT32_MAX && filesys_create (name, size);
	lock_release (&filesys_lock);
	palloc_free_page (name);
	return success;
}

static bool
sys_remove (const char *user) {
	char *name = copy_user_string (user);
	if (name == NULL)
		return false;
	lock_acquire (&filesys_lock);
	bool success = filesys_remove (name);
	lock_release (&filesys_lock);
	palloc_free_page (name);
	return success;
}

static void
sys_close (int fd) {
	struct file *file = lookup_file (fd);
	if (file != NULL) {
		thread_current ()->fd_table[fd] = NULL;
		lock_acquire (&filesys_lock);
		file_close (file);
		lock_release (&filesys_lock);
	}
}

/* Validate the whole range before allocating a bounce page or taking a
   filesystem lock.  Transfers use bounded chunks rather than malloc(size). */
static int
sys_read (int fd, void *buffer, unsigned size) {
	if (!user_buffer_valid (buffer, size, true))
		syscall_exit (-1);
	struct file *file = lookup_file (fd);
	if (fd != STDIN_FILENO && file == NULL)
		return -1;
	if (size == 0)
		return 0;
	char *copy = palloc_get_page (0);
	if (copy == NULL)
		return -1;
	size_t total = 0;
	if (file != NULL)
		lock_acquire (&filesys_lock);
	while (total < size) {
		size_t chunk = size - total;
		if (chunk > PGSIZE)
			chunk = PGSIZE;
		int count;
		if (fd == STDIN_FILENO) {
			for (size_t i = 0; i < chunk; i++)
				copy[i] = input_getc ();
			count = chunk;
		} else
			count = file_read (file, copy, chunk);
		if (count <= 0)
			break;
		memcpy ((char *) buffer + total, copy, count);
		total += count;
		if ((size_t) count < chunk)
			break;
	}
	if (file != NULL)
		lock_release (&filesys_lock);
	palloc_free_page (copy);
	return total;
}

static int
sys_write (int fd, const void *buffer, unsigned size) {
	if (!user_buffer_valid (buffer, size, false))
		syscall_exit (-1);
	struct file *file = lookup_file (fd);
	if (fd != STDOUT_FILENO && file == NULL)
		return -1;
	if (size == 0)
		return 0;
	char *copy = palloc_get_page (0);
	if (copy == NULL)
		return -1;
	size_t total = 0;
	if (file != NULL)
		lock_acquire (&filesys_lock);
	while (total < size) {
		size_t chunk = size - total;
		if (chunk > PGSIZE)
			chunk = PGSIZE;
		memcpy (copy, (const char *) buffer + total, chunk);
		int count;
		if (fd == STDOUT_FILENO) {
			putbuf (copy, chunk);
			count = chunk;
		} else
			count = file_write (file, copy, chunk);
		if (count <= 0)
			break;
		total += count;
		if ((size_t) count < chunk)
			break;
	}
	if (file != NULL)
		lock_release (&filesys_lock);
	palloc_free_page (copy);
	return total;
}

void
syscall_handler (struct intr_frame *f) {
	switch (f->R.rax) {
		case SYS_HALT:
			power_off ();
		case SYS_EXIT:
			syscall_exit ((int) f->R.rdi);
		case SYS_FORK: {
			char *name = copy_user_string ((const char *) f->R.rdi);
			f->R.rax = name != NULL ? process_fork (name, f) : TID_ERROR;
			palloc_free_page (name);
			break;
		}
		case SYS_EXEC: {
			char *command = copy_user_string ((const char *) f->R.rdi);
			if (command == NULL || process_exec (command) < 0)
				syscall_exit (-1);
			NOT_REACHED ();
		}
		case SYS_WAIT:
			f->R.rax = process_wait ((tid_t) f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = sys_create ((const char *) f->R.rdi, (unsigned) f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = sys_remove ((const char *) f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open ((const char *) f->R.rdi);
			break;
		case SYS_CLOSE:
			sys_close ((int) f->R.rdi);
			break;
		case SYS_FILESIZE:
		case SYS_TELL:
		case SYS_SEEK: {
			struct file *file = lookup_file ((int) f->R.rdi);
			uint64_t call = f->R.rax;
			f->R.rax = -1;
			if (file != NULL) {
				lock_acquire (&filesys_lock);
				if (call == SYS_FILESIZE)
					f->R.rax = file_length (file);
				else if (call == SYS_TELL)
					f->R.rax = file_tell (file);
				else if ((unsigned) f->R.rsi <= INT32_MAX)
					file_seek (file, (unsigned) f->R.rsi);
				lock_release (&filesys_lock);
			}
			break;
		}
		case SYS_READ:
			f->R.rax = sys_read ((int) f->R.rdi, (void *) f->R.rsi,
			                    (unsigned) f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = sys_write ((int) f->R.rdi, (const void *) f->R.rsi,
			                     (unsigned) f->R.rdx);
			break;
		default:
			syscall_exit (-1);
	}
}
