#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "threads/init.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/input.h"
#include "userprog/process.h"

/* NOTE: The beginning where custom code is added */
#include "threads/palloc.h"
#include "threads/malloc.h"
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
#ifdef VM
	return vm_user_buffer_valid (buffer, size, writable);
#else
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
#endif
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
copy_user_string_cleanup (const char *user, void *on_fault) {
	if (!user_buffer_valid (user, 1, false)) {
		palloc_free_page (on_fault);
		syscall_exit (-1);
	}
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
			palloc_free_page (on_fault);
			syscall_exit (-1);
		}
#ifdef VM
		if (!vm_copy_user (copy + offset, (void *) part, chunk, false)) {
			palloc_free_page (copy);
			return NULL;
		}
#else
		memcpy (copy + offset, part, chunk);
#endif
		if (memchr (copy + offset, '\0', chunk) != NULL)
			return copy;
		offset += chunk;
	}
	palloc_free_page (copy);
	return NULL;
}

static char *
copy_user_string (const char *user) {
	return copy_user_string_cleanup (user, NULL);
}

static struct process_fd *
lookup_fd (int fd) {
	struct process_fd **table = thread_current ()->fd_table;
	return table != NULL && fd >= 0 && fd < FD_COUNT ? table[fd] : NULL;
}

static struct file *
lookup_file (int fd) {
	struct process_fd *entry = lookup_fd (fd);
	return entry != NULL && entry->file != NULL &&
	       !inode_is_directory (file_get_inode (entry->file)) ? entry->file : NULL;
}

static int
sys_open (const char *user) {
	char *name = copy_user_string (user);
	if (name == NULL)
		return -1;
	struct thread *current = thread_current ();
	int fd;
	for (fd = 0; fd < FD_COUNT; fd++)
		if (current->fd_table[fd] == NULL)
			break;
	if (fd == FD_COUNT) {
		palloc_free_page (name);
		return -1;
	}
	struct process_fd *entry = calloc (1, sizeof *entry);
	if (entry == NULL) {
		palloc_free_page (name);
		return -1;
	}
	struct file *file = filesys_open (name);
	palloc_free_page (name);
	if (file == NULL) {
		free (entry);
		return -1;
	}
	entry->file = file;
	entry->kind = FD_FILE;
	entry->references = 1;
	current->fd_table[fd] = entry;
	return fd;
}

static bool
sys_create (const char *user, unsigned size) {
	char *name = copy_user_string (user);
	if (name == NULL)
		return false;
	bool success = size <= INT32_MAX && filesys_create (name, size);
	palloc_free_page (name);
	return success;
}

static bool
sys_remove (const char *user) {
	char *name = copy_user_string (user);
	if (name == NULL)
		return false;
	bool success = filesys_remove (name);
	palloc_free_page (name);
	return success;
}

static void
sys_close (int fd) {
	struct process_fd *entry = lookup_fd (fd);
	if (entry != NULL) {
		thread_current ()->fd_table[fd] = NULL;
		process_fd_release (entry);
	}
}

static int
sys_dup2 (int oldfd, int newfd) {
	struct process_fd *entry = lookup_fd (oldfd);
	if (entry == NULL || newfd < 0 || newfd >= FD_COUNT)
		return -1;
	if (oldfd == newfd)
		return newfd;
	/* Retain first: newfd may already be an alias of oldfd. */
	entry->references++;
	process_fd_release (thread_current ()->fd_table[newfd]);
	thread_current ()->fd_table[newfd] = entry;
	return newfd;
}

#ifdef EFILESYS
static bool
sys_readdir (int fd, char *user_name) {
	if (!user_buffer_valid (user_name, NAME_MAX + 1, true))
		syscall_exit (-1);
	struct process_fd *entry = lookup_fd (fd);
	if (entry == NULL || entry->file == NULL)
		return false;
	char name[NAME_MAX + 1] = {0};
	off_t position = entry->position;
	bool success = dir_read_next (file_get_inode (entry->file), &position, name);
	entry->position = position;
	if (success) {
#ifdef VM
		if (!vm_copy_user (name, user_name, sizeof name, true))
			syscall_exit (-1);
#else
		memcpy (user_name, name, sizeof name);
#endif
	}
	return success;
}
#endif

/* Validate the whole range before allocating a bounce page or taking a
   filesystem lock.  Transfers use bounded chunks rather than malloc(size). */
static int
sys_read (int fd, void *buffer, unsigned size) {
	if (!user_buffer_valid (buffer, size, true))
		syscall_exit (-1);
	struct process_fd *entry = lookup_fd (fd);
	struct file *file = entry != NULL ? entry->file : NULL;
	if (entry == NULL || entry->kind == FD_OUTPUT ||
	    (file != NULL && inode_is_directory (file_get_inode (file))))
		return -1;
	if (size == 0)
		return 0;
	char *copy = palloc_get_page (0);
	if (copy == NULL)
		return -1;
	size_t total = 0;
	while (total < size) {
		size_t chunk = size - total;
		if (chunk > PGSIZE)
			chunk = PGSIZE;
		int count;
		if (entry->kind == FD_INPUT) {
			for (size_t i = 0; i < chunk; i++)
				copy[i] = input_getc ();
			count = chunk;
		} else {
			/* The base filesystem cannot grow beyond signed inode offsets.
			   An unsigned position past EOF must not be narrowed first. */
			if (entry->position > INT32_MAX)
				count = 0;
			else {
				count = file_read_at (file, copy, chunk, (off_t) entry->position);
				if (count > 0) {
					entry->position += count;
					inode_readahead (file_get_inode (file), entry->position - 1);
				}
			}
		}
		if (count <= 0)
			break;
#ifdef VM
		if (!vm_copy_user (copy, (char *) buffer + total, count, true)) {
			palloc_free_page (copy);
			syscall_exit (-1);
		}
#else
		memcpy ((char *) buffer + total, copy, count);
#endif
		total += count;
		if ((size_t) count < chunk)
			break;
	}
	palloc_free_page (copy);
	return total;
}

static int
sys_write (int fd, const void *buffer, unsigned size) {
	if (!user_buffer_valid (buffer, size, false))
		syscall_exit (-1);
	struct process_fd *entry = lookup_fd (fd);
	struct file *file = entry != NULL ? entry->file : NULL;
	if (entry == NULL || entry->kind == FD_INPUT ||
	    (file != NULL && inode_is_directory (file_get_inode (file))))
		return -1;
	if (size == 0)
		return 0;
	char *copy = palloc_get_page (0);
	if (copy == NULL)
		return -1;
	size_t total = 0;
	while (total < size) {
		size_t chunk = size - total;
		if (chunk > PGSIZE)
			chunk = PGSIZE;
#ifdef VM
		if (!vm_copy_user (copy, (char *) buffer + total, chunk, false)) {
			palloc_free_page (copy);
			syscall_exit (-1);
		}
#else
		memcpy (copy, (const char *) buffer + total, chunk);
#endif
		int count;
		if (entry->kind == FD_OUTPUT) {
			putbuf (copy, chunk);
			count = chunk;
		} else {
			/* Keep the unsigned descriptor position out of signed inode offsets. */
			bool valid_position = entry->position <= INT32_MAX;
#ifndef EFILESYS
			valid_position = valid_position && entry->position < (uint32_t) file_length (file);
#endif
			if (!valid_position)
				count = 0;
			else {
				count = file_write_at (file, copy, chunk, (off_t) entry->position);
				if (count > 0)
					entry->position += count;
			}
		}
		if (count <= 0)
			break;
		total += count;
		if ((size_t) count < chunk)
			break;
	}
	palloc_free_page (copy);
	return total;
}

void
syscall_handler (struct intr_frame *f) {
#ifdef VM
	thread_current ()->user_rsp = (void *) f->rsp;
#endif
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
#ifdef EFILESYS
		case SYS_SYMLINK: {
			char *target = copy_user_string ((const char *) f->R.rdi);
			/* A fault in the second string must release the first copy too. */
			char *linkpath = target != NULL ?
			                 copy_user_string_cleanup ((const char *) f->R.rsi, target) : NULL;
			f->R.rax = -1;
			if (target != NULL && linkpath != NULL) {
				f->R.rax = filesys_symlink (target, linkpath);
			}
			palloc_free_page (linkpath);
			palloc_free_page (target);
			break;
		}
		case SYS_CHDIR:
		case SYS_MKDIR: {
			bool make_directory = f->R.rax == SYS_MKDIR;
			char *path = copy_user_string ((const char *) f->R.rdi);
			f->R.rax = false;
			if (path != NULL) {
				f->R.rax = make_directory ? filesys_mkdir (path) : filesys_chdir (path);
				palloc_free_page (path);
			}
			break;
		}
		case SYS_READDIR:
			f->R.rax = sys_readdir ((int) f->R.rdi, (char *) f->R.rsi);
			break;
		case SYS_ISDIR:
		case SYS_INUMBER: {
			bool get_number = f->R.rax == SYS_INUMBER;
			struct process_fd *entry = lookup_fd ((int) f->R.rdi);
			f->R.rax = get_number ? -1 : 0;
			if (entry != NULL && entry->file != NULL) {
				struct inode *inode = file_get_inode (entry->file);
				f->R.rax = get_number ? inode_get_inumber (inode) : inode_is_directory (inode);
			}
			break;
		}
#endif
#ifdef VM
		case SYS_MMAP: {
			struct file *file = lookup_file ((int) f->R.r10);
			if (f->R.r8 > INT32_MAX)
				f->R.rax = 0;
			else
				f->R.rax = (uintptr_t) do_mmap ((void *) f->R.rdi, f->R.rsi,
				                              (int) f->R.rdx, file, (off_t) f->R.r8);
			break;
		}
		case SYS_MUNMAP:
			do_munmap ((void *) f->R.rdi);
			break;
#endif
		case SYS_DUP2:
			f->R.rax = sys_dup2 ((int) f->R.rdi, (int) f->R.rsi);
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
				if (call == SYS_FILESIZE)
					f->R.rax = file_length (file);
				else if (call == SYS_TELL)
					f->R.rax = thread_current ()->fd_table[(int) f->R.rdi]->position;
				else
					thread_current ()->fd_table[(int) f->R.rdi]->position =
						(unsigned) f->R.rsi;
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
