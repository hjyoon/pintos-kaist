#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef VM
#include "vm/vm.h"
#endif

/* Includes the program name.  Reject larger argument vectors. */
#define MAX_ARGC 128

/* Build the initial user stack only after checking its complete size. */
static bool
setup_arguments (int argc, char **argv, void **rsp) {
	if (argc <= 0 || argc > MAX_ARGC)
		return false;

	size_t string_bytes = 0;
	for (int i = 0; i < argc; i++) {
		size_t length = strlen (argv[i]) + 1;
		if (length > PGSIZE - string_bytes)
			return false;
		string_bytes += length;
	}
	size_t stack_bytes = ROUND_UP (string_bytes, sizeof (void *)) +
	                     (argc + 2) * sizeof (void *);
	if (stack_bytes > PGSIZE)
		return false;

	uintptr_t sp = (uintptr_t) *rsp;
	for (int i = argc - 1; i >= 0; i--) {
		size_t length = strlen (argv[i]) + 1;
		sp -= length;
		memcpy ((void *) sp, argv[i], length);
		/* Reuse the kernel argument vector for the user addresses. */
		argv[i] = (char *) sp;
	}

	uintptr_t aligned_sp = sp & ~(uintptr_t) (sizeof (void *) - 1);
	memset ((void *) aligned_sp, 0, sp - aligned_sp);
	sp = aligned_sp;
	sp -= sizeof (char *);
	*(char **) sp = NULL;
	for (int i = argc - 1; i >= 0; i--) {
		sp -= sizeof (char *);
		*(char **) sp = argv[i];
	}
	sp -= sizeof (void *);
	*(uintptr_t *) sp = 0;
	*rsp = (void *) sp;
	return true;
}

static void process_cleanup (void);
static bool load (const char *file_name, struct intr_frame *if_);
static void initd (void *f_name);
static void __do_fork (void *);

/* Exit records outlive either thread.  The parent and child each own one
   reference; wait consumes the parent's reference exactly once. */
struct child_status {
	tid_t tid;
	int exit_status;
	int references;
	bool fork_success;
	struct semaphore exited;
	struct semaphore fork_done;
	struct list_elem elem;
};

struct launch_aux {
	char *command;
	char *name;
	struct child_status *status;
};

struct fork_aux {
	struct thread *parent;
	char *name;
	struct child_status *status;
	struct intr_frame frame;
};

static struct child_status *
new_status (void) {
	struct child_status *s = malloc (sizeof *s);
	if (s != NULL) {
		s->tid = TID_ERROR;
		s->exit_status = -1;
		s->references = 2;
		s->fork_success = false;
		sema_init (&s->exited, 0);
		sema_init (&s->fork_done, 0);
	}
	return s;
}

static void
status_put (struct child_status *s) {
	enum intr_level old = intr_disable ();
	bool last = --s->references == 0;
	intr_set_level (old);
	if (last)
		free (s);
}

/* Keep the complete process name separately from thread.name, whose
   small debugging buffer is intentionally allowed to truncate. */
static char *
copy_process_name (const char *name, size_t length) {
	char *copy = malloc (length + 1);
	if (copy != NULL) {
		memcpy (copy, name, length);
		copy[length] = '\0';
	}
	return copy;
}

static bool
process_init (void) {
	struct thread *current = thread_current ();
	current->is_user_process = true;
	_Static_assert (FD_COUNT * sizeof (struct process_fd) <= PGSIZE,
	                "file descriptors must fit in their allocated page");
	current->fd_table = palloc_get_page (PAL_ZERO);
	return current->fd_table != NULL;
}

tid_t
process_create_initd (const char *command) {
	if (strnlen (command, PGSIZE) == PGSIZE)
		return TID_ERROR;
	const char *name = command + strspn (command, " ");
	size_t length = strcspn (name, " ");
	char *full_name = copy_process_name (name, length);
	char *copy = palloc_get_page (0);
	struct child_status *status = new_status ();
	struct launch_aux *aux = malloc (sizeof *aux);
	if (full_name == NULL || copy == NULL || status == NULL || aux == NULL) {
		free (full_name);
		palloc_free_page (copy);
		free (status);
		free (aux);
		return TID_ERROR;
	}
	strlcpy (copy, command, PGSIZE);
	char thread_name[16];
	if (length >= sizeof thread_name)
		length = sizeof thread_name - 1;
	memcpy (thread_name, name, length);
	thread_name[length] = '\0';
	aux->command = copy;
	aux->name = full_name;
	aux->status = status;
	tid_t tid = thread_create (thread_name, PRI_DEFAULT, initd, aux);
	if (tid == TID_ERROR) {
		free (full_name);
		palloc_free_page (copy);
		free (status);
		free (aux);
		return TID_ERROR;
	}
	status->tid = tid;
	list_push_back (&thread_current ()->children, &status->elem);
	return tid;
}

static void
initd (void *aux_) {
	struct launch_aux *aux = aux_;
	char *command = aux->command;
	thread_current ()->process_name = aux->name;
	thread_current ()->as_child = aux->status;
	free (aux);
#ifdef VM
	supplemental_page_table_init (&thread_current ()->spt);
#endif
	if (!process_init ()) {
		palloc_free_page (command);
		syscall_exit (-1);
	}
	if (process_exec (command) < 0)
		syscall_exit (-1);
	NOT_REACHED ();
}

tid_t
process_fork (const char *name, struct intr_frame *frame) {
	char *full_name = copy_process_name (name, strlen (name));
	struct fork_aux *aux = malloc (sizeof *aux);
	struct child_status *status = new_status ();
	if (full_name == NULL || aux == NULL || status == NULL) {
		free (full_name);
		free (aux);
		free (status);
		return TID_ERROR;
	}
	aux->parent = thread_current ();
	aux->name = full_name;
	aux->status = status;
	memcpy (&aux->frame, frame, sizeof *frame);
	tid_t tid = thread_create (name, thread_current ()->priority, __do_fork, aux);
	if (tid == TID_ERROR) {
		free (full_name);
		free (aux);
		free (status);
		return TID_ERROR;
	}
	status->tid = tid;
	list_push_back (&thread_current ()->children, &status->elem);
	/* The parent cannot change its image or descriptors while cloning. */
	sema_down (&status->fork_done);
	if (!status->fork_success) {
		process_wait (tid);
		return TID_ERROR;
	}
	return tid;
}

#ifndef VM
static bool
duplicate_pte (uint64_t *pte, void *va, void *aux) {
	if (!is_user_vaddr (va))
		return true;
	struct thread *parent = aux;
	void *source = pml4_get_page (parent->pml4, va);
	void *copy = palloc_get_page (PAL_USER);
	if (copy == NULL)
		return false;
	memcpy (copy, source, PGSIZE);
	if (!pml4_set_page (thread_current ()->pml4, va, copy, is_writable (pte))) {
		palloc_free_page (copy);
		return false;
	}
	return true;
}
#endif

static void
__do_fork (void *aux_) {
	struct fork_aux *aux = aux_;
	struct thread *parent = aux->parent;
	struct child_status *status = aux->status;
	struct intr_frame frame;
	memcpy (&frame, &aux->frame, sizeof frame);
	struct thread *current = thread_current ();
	current->process_name = aux->name;
	free (aux);
	current->as_child = status;
#ifdef VM
	supplemental_page_table_init (&current->spt);
#endif
	bool success = process_init ();
	if (success) {
		current->pml4 = pml4_create ();
		success = current->pml4 != NULL;
	}
	if (success) {
		process_activate (current);
#ifdef VM
		success = supplemental_page_table_copy (&current->spt, &parent->spt);
#else
		success = pml4_for_each (parent->pml4, duplicate_pte, parent);
#endif
	}
	if (success) {
		lock_acquire (&filesys_lock);
		for (int fd = 2; fd < FD_COUNT; fd++) {
			if (parent->fd_table[fd].file != NULL) {
				current->fd_table[fd].file = file_duplicate (parent->fd_table[fd].file);
				current->fd_table[fd].position = parent->fd_table[fd].position;
				if (current->fd_table[fd].file == NULL) {
					success = false;
					break;
				}
			}
		}
		if (success && parent->executable != NULL) {
			current->executable = file_duplicate (parent->executable);
			success = current->executable != NULL;
		}
		lock_release (&filesys_lock);
	}
	status->fork_success = success;
	sema_up (&status->fork_done);
	if (!success)
		syscall_exit (-1);
	frame.R.rax = 0;
	do_iret (&frame);
	NOT_REACHED ();
}

/* Switch to the executable described by the owned command-line page.
   Consumes F_NAME on success and failure.  Returns -1 on failure. */
int
process_exec (void *f_name) {
	char *file_name = f_name;
	char *argv[MAX_ARGC];
	char *save_ptr;
	int argc = 0;

	if (file_name == NULL)
		return -1;
	if (strnlen (file_name, PGSIZE) == PGSIZE)
		goto error;

	/* Tokenize the owned page directly, avoiding a second allocation. */
	for (char *token = strtok_r (file_name, " ", &save_ptr);
	     token != NULL; token = strtok_r (NULL, " ", &save_ptr)) {
		if (argc == MAX_ARGC)
			goto error;
		argv[argc++] = token;
	}
	if (argc == 0)
		goto error;

	/* Use a separate frame because scheduling overwrites thread.tf. */
	struct intr_frame _if;
	memset (&_if, 0, sizeof _if);
	_if.ds = _if.es = _if.ss = SEL_UDSEG;
	_if.cs = SEL_UCSEG;
	_if.eflags = FLAG_IF | FLAG_MBS;

	process_cleanup ();
	/* exec preserves descriptors and the original process name. */
	lock_acquire (&filesys_lock);
	file_close (thread_current ()->executable);
	thread_current ()->executable = NULL;
	bool loaded = load (argv[0], &_if);
	lock_release (&filesys_lock);
	/* Avoid passing the address of a packed integer field as void **. */
	void *stack_pointer = (void *) _if.rsp;
	if (!loaded || !setup_arguments (argc, argv, &stack_pointer)) {
		process_cleanup ();
		goto error;
	}
	_if.rsp = (uintptr_t) stack_pointer;

	_if.R.rdi = argc;
	_if.R.rsi = (uintptr_t) _if.rsp + sizeof (void *);
	palloc_free_page (file_name);
	do_iret (&_if);
	NOT_REACHED ();

error:
	palloc_free_page (file_name);
	return -1;
}


/* Wait for a direct child, including one that has already exited. */
int
process_wait (tid_t tid) {
	struct list *children = &thread_current ()->children;
	for (struct list_elem *e = list_begin (children);
	     e != list_end (children); e = list_next (e)) {
		struct child_status *status = list_entry (e, struct child_status, elem);
		if (status->tid == tid) {
			list_remove (e);
			sema_down (&status->exited);
			int result = status->exit_status;
			status_put (status);
			return result;
		}
	}
	return -1;
}

void
process_exit (void) {
	struct thread *current = thread_current ();
	if (current->is_user_process) {
		const char *name = current->process_name != NULL ?
		                   current->process_name : current->name;
		printf ("%s: exit(%d)\n", name, current->exit_status);
	}
	free (current->process_name);
	current->process_name = NULL;
	if (current->fd_table != NULL || current->executable != NULL) {
		lock_acquire (&filesys_lock);
		if (current->fd_table != NULL)
			for (int fd = 2; fd < FD_COUNT; fd++)
				file_close (current->fd_table[fd].file);
		file_close (current->executable);
		current->executable = NULL;
		lock_release (&filesys_lock);
		palloc_free_page (current->fd_table);
		current->fd_table = NULL;
	}
	process_cleanup ();
	while (!list_empty (&current->children)) {
		struct child_status *status = list_entry (list_pop_front (&current->children),
		                                         struct child_status, elem);
		status_put (status);
	}
	if (current->as_child != NULL) {
		struct child_status *status = current->as_child;
		status->exit_status = current->exit_status;
		sema_up (&status->exited);
		status_put (status);
		current->as_child = NULL;
	}
}

/* Free the current process's resources. */
static void
process_cleanup (void) {
	struct thread *curr = thread_current ();

#ifdef VM
	supplemental_page_table_kill (&curr->spt);
#endif

	uint64_t *pml4;
	/* Destroy the current process's page directory and switch back
	 * to the kernel-only page directory. */
	pml4 = curr->pml4;
	if (pml4 != NULL) {
		/* Correct ordering here is crucial.  We must set
		 * cur->pagedir to NULL before switching page directories,
		 * so that a timer interrupt can't switch back to the
		 * process page directory.  We must activate the base page
		 * directory before destroying the process's page
		 * directory, or our active page directory will be one
		 * that's been freed (and cleared). */
		curr->pml4 = NULL;
		pml4_activate (NULL);
		pml4_destroy (pml4);
	}
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void
process_activate (struct thread *next) {
	/* Activate thread's page tables. */
	pml4_activate (next->pml4);

	/* Set thread's kernel stack for use in processing interrupts. */
	tss_update (next);
}

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
	unsigned char e_ident[EI_NIDENT];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct ELF64_PHDR {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

static bool setup_stack (struct intr_frame *if_);
static bool validate_segment (const struct Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes,
		bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
 * Stores the executable's entry point into *RIP
 * and its initial stack pointer into *RSP.
 * Returns true if successful, false otherwise. */
static bool
load (const char *file_name, struct intr_frame *if_) {
	struct thread *t = thread_current ();
	struct ELF ehdr;
	struct file *file = NULL;
	off_t file_ofs;
	bool success = false;
	int i;

	/* Allocate and activate page directory. */
	t->pml4 = pml4_create ();
	if (t->pml4 == NULL)
		goto done;
	process_activate (thread_current ());

	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		goto done;
	}

	/* Read and verify executable header. */
	if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
			|| memcmp (ehdr.e_ident, "\177ELF\2\1\1", 7)
			|| ehdr.e_type != 2
			|| ehdr.e_machine != 0x3E // amd64
			|| ehdr.e_version != 1
			|| ehdr.e_phentsize != sizeof (struct Phdr)
			|| ehdr.e_phnum > 1024) {
		printf ("load: %s: error loading executable\n", file_name);
		goto done;
	}

	/* Read program headers. */
	file_ofs = ehdr.e_phoff;
	for (i = 0; i < ehdr.e_phnum; i++) {
		struct Phdr phdr;

		if (file_ofs < 0 || file_ofs > file_length (file))
			goto done;
		file_seek (file, file_ofs);

		if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
			goto done;
		file_ofs += sizeof phdr;
		switch (phdr.p_type) {
			case PT_NULL:
			case PT_NOTE:
			case PT_PHDR:
			case PT_STACK:
			default:
				/* Ignore this segment. */
				break;
			case PT_DYNAMIC:
			case PT_INTERP:
			case PT_SHLIB:
				goto done;
			case PT_LOAD:
				if (validate_segment (&phdr, file)) {
					bool writable = (phdr.p_flags & PF_W) != 0;
					uint64_t file_page = phdr.p_offset & ~PGMASK;
					uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
					uint64_t page_offset = phdr.p_vaddr & PGMASK;
					uint32_t read_bytes, zero_bytes;
					if (phdr.p_filesz > 0) {
						/* Normal segment.
						 * Read initial part from disk and zero the rest. */
						read_bytes = page_offset + phdr.p_filesz;
						zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
								- read_bytes);
					} else {
						/* Entirely zero.
						 * Don't read anything from disk. */
						read_bytes = 0;
						zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
					}
					if (!load_segment (file, file_page, (void *) mem_page,
								read_bytes, zero_bytes, writable))
						goto done;
				}
				else
					goto done;
				break;
		}
	}

	/* Set up stack. */
	if (!setup_stack (if_))
		goto done;

	/* Start address. */
	if_->rip = ehdr.e_entry;

	/* TODO: Your code goes here.
	 * TODO: Implement argument passing (see project2/argument_passing.html). */

	success = true;

done:
	if (success) {
		file_deny_write (file);
		t->executable = file;
		file = NULL;
	}
	/* Failed loads relinquish their file immediately. */
	file_close (file);
	return success;
}


/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Phdr *phdr, struct file *file) {
	/* p_offset and p_vaddr must have the same page offset. */
	if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
		return false;

	/* p_offset must point within FILE. */
	if (phdr->p_offset > (uint64_t) file_length (file))
		return false;

	/* p_memsz must be at least as big as p_filesz. */
	if (phdr->p_memsz < phdr->p_filesz)
		return false;

	/* The segment must not be empty. */
	if (phdr->p_memsz == 0)
		return false;

	/* The virtual memory region must both start and end within the
	   user address space range. */
	if (!is_user_vaddr ((void *) phdr->p_vaddr))
		return false;
	if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
		return false;

	/* The region cannot "wrap around" across the kernel virtual
	   address space. */
	if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
		return false;

	/* Disallow mapping page 0.
	   Not only is it a bad idea to map page 0, but if we allowed
	   it then user code that passed a null pointer to system calls
	   could quite likely panic the kernel by way of null pointer
	   assertions in memcpy(), etc. */
	if (phdr->p_vaddr < PGSIZE)
		return false;

	/* It's okay. */
	return true;
}

#ifndef VM
/* Codes of this block will be ONLY USED DURING project 2.
 * If you want to implement the function for whole project 2, implement it
 * outside of #ifndef macro. */

/* load() helpers. */
static bool install_page (void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	file_seek (file, ofs);
	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* Get a page of memory. */
		uint8_t *kpage = palloc_get_page (PAL_USER);
		if (kpage == NULL)
			return false;

		/* Load this page. */
		if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
			palloc_free_page (kpage);
			return false;
		}
		memset (kpage + page_read_bytes, 0, page_zero_bytes);

		/* Add the page to the process's address space. */
		if (!install_page (upage, kpage, writable)) {
			printf("fail\n");
			palloc_free_page (kpage);
			return false;
		}

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool
setup_stack (struct intr_frame *if_) {
	uint8_t *kpage;
	bool success = false;

	kpage = palloc_get_page (PAL_USER | PAL_ZERO);
	if (kpage != NULL) {
		success = install_page (((uint8_t *) USER_STACK) - PGSIZE, kpage, true);
		if (success)
			if_->rsp = USER_STACK;
		else
			palloc_free_page (kpage);
	}
	return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable) {
	struct thread *t = thread_current ();

	/* Verify that there's not already a page at that virtual
	 * address, then map our page there. */
	return (pml4_get_page (t->pml4, upage) == NULL
			&& pml4_set_page (t->pml4, upage, kpage, writable));
}
#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
		uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (upage) == 0);
	ASSERT (ofs % PGSIZE == 0);

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		void *aux = NULL;
		if (!vm_alloc_page_with_initializer (VM_ANON, upage,
					writable, lazy_load_segment, aux))
			return false;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		upage += PGSIZE;
	}
	return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool
setup_stack (struct intr_frame *if_) {
	bool success = false;
	void *stack_bottom = (void *) (((uint8_t *) USER_STACK) - PGSIZE);

	/* TODO: Map the stack on stack_bottom and claim the page immediately.
	 * TODO: If success, set the rsp accordingly.
	 * TODO: You should mark the page is stack. */
	/* TODO: Your code goes here */

	return success;
}
#endif /* VM */
