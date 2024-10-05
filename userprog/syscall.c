#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"

/* NOTE: The beginning where custom code is added */
#include "threads/palloc.h"
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

/* The main system call interface */
// void
// syscall_handler (struct intr_frame *f UNUSED) {
// 	// TODO: Your implementation goes here.
// 	printf ("system call!\n");
// 	thread_exit ();
// }

const char* syscall_name(int syscall_number) {
    switch (syscall_number) {
        case SYS_HALT:
            return "halt";
        case SYS_EXIT:
            return "exit";
        case SYS_EXEC:
            return "exec";
        case SYS_WAIT:
            return "wait";
        case SYS_CREATE:
            return "create";
        case SYS_REMOVE:
            return "remove";
        case SYS_OPEN:
            return "open";
        case SYS_FILESIZE:
            return "filesize";
        case SYS_READ:
            return "read";
        case SYS_WRITE:
            return "write";
        case SYS_SEEK:
            return "seek";
        case SYS_TELL:
            return "tell";
        case SYS_CLOSE:
            return "close";
        default:
            return "unknown";
    }
}

/* verify_user_buffer: function to validate user buffer */
bool verify_user_buffer(const void *buffer, unsigned size) {
	if (buffer == NULL) {
		return false;
	}

	/* Check within the user address space */
	if (!is_user_vaddr(buffer)) {
		return false;
	}

	/* Check if each byte is mapped */
	for (unsigned i = 0; i < size; i++) {
		void *addr = (void *) ((uintptr_t) buffer + i);
		if (!is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL) {
			return false;
		}
	}

	return true;
}

/* copy_user_buffer: function to safely copy user buffer to kernel buffer */
bool copy_user_buffer(const void *user_buffer, void *kernel_buffer, unsigned size) {
	/* In actual implementation, exception handling is required to prevent page faults */
	memcpy(kernel_buffer, user_buffer, size);
	return true;
}

int sys_write(int fd, const void *buffer, unsigned size) {
	if (fd != STDOUT_FILENO) {
		return -1;
	}

	if (!verify_user_buffer(buffer, size)) {
		return -1;
	}

	/* Allocate kernel buffer */
	char *kernel_buffer = palloc_get_page(PAL_ZERO);
	if (kernel_buffer == NULL) {
		return -1; // Memory allocation failed
	}

	/* Copy user buffer to kernel buffer */
	if (!copy_user_buffer(buffer, kernel_buffer, size)) {
		palloc_free_page(kernel_buffer);
		return -1; // Copy failed
	}

	/* Output data to console */
	putbuf(kernel_buffer, size);

	/* Free kernel buffer */
	palloc_free_page(kernel_buffer);

	/* Return the number of bytes actually written */
	return size;
}

void syscall_handler(struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

    /* Extract system call number */
    int syscall_number = f->R.rax;

    /* Extract system call name */
    const char* name = syscall_name(syscall_number);

    /* Extract caller's RIP (program counter) */
    uintptr_t caller_rip = f->rip;

    /* Print system call information */
    // printf("System Call Invoked: %s (%d) from RIP: 0x%016lx\n", name, syscall_number, caller_rip);

    /* Processing according to system call number */
    switch (syscall_number) {
        case SYS_EXIT:
            {
                /* In exit(status), status is passed to rdi */
                thread_current()->exit_status = (int) f->R.rdi;
                // printf("Process %s exiting with status %d\n", thread_current()->name, status);
				// printf("%s: exit(%d)\n", thread_current()->name, status);
                thread_exit();
            }
            break;

		case SYS_WRITE:
            {
                int fd = (int) f->R.rdi; // file descriptor
                const void *buffer = (const void *) f->R.rsi; // data buffer
                unsigned size = (unsigned) f->R.rdx;  // data size

                int bytes_written = sys_write(fd, buffer, size);

                /* Set return value */
                f->R.rax = bytes_written;
            }
            break;

        /* Handling other system calls */

        default:
            // printf("Unknown system call: %d\n", syscall_number);
            thread_exit();
    }
}
