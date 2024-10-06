#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"

/* NOTE: The beginning where custom code is added */
#include "threads/init.h"
#include "threads/palloc.h"
#include <string.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"
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

/* NOTE: The beginning where custom code is added */
#define NAME_MAX 512

/* Structure to represent a file descriptor */
struct file_descriptor {
    int fd;                     /* File descriptor number */
    struct file *file;          /* Pointer to the open file */
    struct list_elem elem;      /* List element */
};

struct file *find_file_descriptor(int fd);
/* NOTE: The end where custom code is added */

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

void sys_halt(void) {
    power_off();
}

void sys_exit(int status) {
    thread_current()->exit_status = status;
    thread_exit();
}

/* The main system call interface */
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

bool is_valid_user_pointer(const void *ptr) {
    /* Check if the pointer is not NULL and lies within user address space */
    if (ptr == NULL || !is_user_vaddr(ptr)) {
        return false;
    }

    /* Check if the pointer is mapped in the page table */
    if (pml4_get_page(thread_current()->pml4, ptr) == NULL) {
        return false;
    }

    return true;
}

bool is_valid_user_buffer(const void *buffer, size_t size) {
    const uint8_t *ptr = (const uint8_t *) buffer;
    size_t i;

    for (i = 0; i < size; i++) {
        if (!is_valid_user_pointer(ptr + i)) {
            return false;
        }
    }
    return true;
}

bool copy_from_user(void *kernel_dst, const void *user_src, size_t size) {
    size_t i;
    uint8_t *k_dst = (uint8_t *) kernel_dst;
    const uint8_t *u_src = (const uint8_t *) user_src;

    for (i = 0; i < size; i++) {
        if (!is_valid_user_pointer(u_src + i)) {
            return false;
        }
        k_dst[i] = u_src[i];
    }
    return true;
}

bool copy_to_user(void *user_dst, const void *kernel_src, size_t size) {
    size_t i;
    uint8_t *u_dst = (uint8_t *)user_dst;
    const uint8_t *k_src = (const uint8_t *)kernel_src;

    for (i = 0; i < size; i++) {
        if (!is_valid_user_pointer(u_dst + i)) {
            return false;
        }
        u_dst[i] = k_src[i];
    }
    return true;
}

bool get_user_string(const char *user_src, char *kernel_dst, size_t max_length) {
    size_t i;
    for (i = 0; i < max_length; i++) {
        if (!is_valid_user_pointer(user_src + i)) {
            return false;
        }
        kernel_dst[i] = user_src[i];
        if (kernel_dst[i] == '\0') {
            return true;
        }
    }
    /* String exceeds maximum length */
    return false;
}

int sys_write(int fd, const void *buffer, unsigned size) {
    /* If size is zero, return zero without accessing buffer */
    if (size == 0) {
        return 0;
    }

    /* Validate the user buffer */
    if (!is_valid_user_buffer(buffer, size)) {
        sys_exit(-1); // Invalid user buffer
    }

    if (fd == STDOUT_FILENO) {
        /* Write directly from user buffer */
        putbuf((const char *) buffer, size);
        return size;
    } else {
        /* Writing to a file descriptor other than standard output */
        struct file *f = find_file_descriptor(fd);
        if (f == NULL) {
            return -1; // Invalid file descriptor
        }

        /* Allocate a kernel buffer */
        void *kernel_buffer = malloc(size);
        if (kernel_buffer == NULL) {
            return -1; // Memory allocation failed
        }

        /* Copy data from user to kernel space */
        if (!copy_from_user(kernel_buffer, buffer, size)) {
            free(kernel_buffer);
            sys_exit(-1); // Invalid user memory access
        }

        /* Write to the file */
        int bytes_written = file_write(f, kernel_buffer, size);

        /* Free the kernel buffer */
        free(kernel_buffer);

        return bytes_written;
    }
}

/* Returns the next available file descriptor starting from 2 */
static int get_next_fd(void) {
    struct thread *t = thread_current();
    int fd = 2; /* Start from 2 as 0 and 1 are reserved */

    lock_acquire(&t->file_list_lock);
    while (1) {
        bool found = false;
        struct list_elem *e;

        for (e = list_begin(&t->file_list); e != list_end(&t->file_list); e = list_next(e)) {
            struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
            if (fd_struct->fd == fd) {
                found = true;
                break;
            }
        }

        if (!found) {
            lock_release(&t->file_list_lock);
            return fd;
        }
        fd++;
    }
    /* Not reached */
}

/* Define find_file_descriptor first */
struct file *find_file_descriptor(int fd) {
    struct thread *t = thread_current();
    struct list_elem *e;

    lock_acquire(&t->file_list_lock);
    for (e = list_begin(&t->file_list); e != list_end(&t->file_list); e = list_next(e)) {
        struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
        if (fd_struct->fd == fd) {
            lock_release(&t->file_list_lock);
            return fd_struct->file;
        }
    }
    lock_release(&t->file_list_lock);
    return NULL; /* Not found */
}

int sys_open(const char *file) {
    /* If file is NULL, terminate the process */
    if (file == NULL) {
        sys_exit(-1);
    }

    /* Validate the user pointer */
    if (!is_valid_user_pointer(file)) {
        sys_exit(-1); // Invalid user pointer
    }

    char filename[NAME_MAX + 1]; // +1 for null terminator
    if (!get_user_string(file, filename, sizeof(filename))) {
        sys_exit(-1); // Invalid user memory access or filename too long
    }

    /* Check if filename is empty */
    if (filename[0] == '\0') {
        return -1; // Cannot open a file with an empty name
    }

    /* Open the file using the file system */
    struct file *f = filesys_open(filename);
    if (f == NULL) {
        return -1; /* File could not be opened */
    }

    /* Assign a new file descriptor */
    int fd = get_next_fd();
    if (fd == -1) {
        file_close(f);
        return -1; // Could not get a valid file descriptor
    }

    /* Allocate and initialize a new file_descriptor structure */
    struct file_descriptor *fd_struct = malloc(sizeof(struct file_descriptor));
    if (fd_struct == NULL) {
        file_close(f);
        return -1; /* Memory allocation failed */
    }
    fd_struct->fd = fd;
    fd_struct->file = f;

    /* Add the new file descriptor to the thread's file list */
    struct thread *t = thread_current();
    lock_acquire(&t->file_list_lock);
    list_push_back(&t->file_list, &fd_struct->elem);
    lock_release(&t->file_list_lock);

    /* Return the file descriptor */
    return fd;
}

/* Example implementation for sys_close */
int sys_close(int fd) {
    if (fd == STDIN_FILENO || fd == STDOUT_FILENO) {
        return -1;
    }

    struct file *f = find_file_descriptor(fd);
    if (f == NULL) {
        return -1;
    }

    file_close(f);

    struct thread *t = thread_current();
    lock_acquire(&t->file_list_lock);
    struct list_elem *e;
    for (e = list_begin(&t->file_list); e != list_end(&t->file_list); e = list_next(e)) {
        struct file_descriptor *fd_struct = list_entry(e, struct file_descriptor, elem);
        if (fd_struct->fd == fd) {
            list_remove(e);
            free(fd_struct);
            break;
        }
    }
    lock_release(&t->file_list_lock);

    return 0;
}

bool sys_create(const char *file, unsigned initial_size) {
    /* If file is NULL, terminate the process */
    if (file == NULL) {
        sys_exit(-1);
    }

    /* Validate the user pointer */
    if (!is_valid_user_pointer(file)) {
        sys_exit(-1); // Invalid user pointer
    }

    char filename[NAME_MAX + 1]; // +1 for null terminator
    if (!get_user_string(file, filename, sizeof(filename))) {
        sys_exit(-1); // Invalid user memory access or filename too long
    }

    /* Check if filename is empty */
    if (filename[0] == '\0') {
        return false; // Cannot create a file with an empty name
    }

    /* Create the file */
    bool success = filesys_create(filename, initial_size);
    return success;
}

int sys_read(int fd, void *buffer, unsigned size) {
    /* If size is zero, return zero without accessing buffer */
    if (size == 0) {
        return 0;
    }

    /* Validate the user buffer */
    if (!is_valid_user_buffer(buffer, size)) {
        sys_exit(-1); // Invalid user buffer
    }

    if (fd == STDIN_FILENO) {
        /* Read from the console (standard input) */
        uint8_t *buf = (uint8_t *)buffer;
        for (unsigned i = 0; i < size; i++) {
            char c = input_getc();
            if (c == '\r') {
                c = '\n';
            }
            buf[i] = c;
            if (c == '\n') {
                return i + 1;
            }
        }
        return size;
    } else {
        /* Reading from a file descriptor other than standard input */
        struct file *f = find_file_descriptor(fd);
        if (f == NULL) {
            return -1; // Invalid file descriptor
        }

        /* Allocate a kernel buffer */
        void *kernel_buffer = malloc(size);
        if (kernel_buffer == NULL) {
            return -1; // Memory allocation failed
        }

        /* Read from the file */
        int bytes_read = file_read(f, kernel_buffer, size);

        if (bytes_read < 0) {
            free(kernel_buffer);
            return -1; // Read error
        }

        /* Copy data from kernel to user space */
        if (!copy_to_user(buffer, kernel_buffer, bytes_read)) {
            free(kernel_buffer);
            sys_exit(-1); // Invalid user memory access
        }

        /* Free the kernel buffer */
        free(kernel_buffer);

        return bytes_read;
    }
}

int sys_filesize(int fd) {
    struct file *f = find_file_descriptor(fd);
    if (f == NULL) {
        return -1; // 유효하지 않은 파일 디스크립터
    }
    off_t size = file_length(f);
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
        case SYS_HALT:
            sys_halt();
            break;

        case SYS_EXIT:
            {
                /* In exit(status), status is passed to rdi */
                int status = (int) f->R.rdi;
                sys_exit(status);
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

        case SYS_OPEN:
            {
                /* sys_open(const char *file) */
                const char *file = (const char *) f->R.rdi;
                int fd = sys_open(file);
                f->R.rax = fd;
            }
            break;

        case SYS_CLOSE:
            {
                int fd = (int) f->R.rdi;
                int result = sys_close(fd);
                f->R.rax = result;
            }
            break;

        case SYS_CREATE:
            {
                const char *file = (const char *) f->R.rdi;
                unsigned initial_size = (unsigned) f->R.rsi;
                bool success = sys_create(file, initial_size);
                f->R.rax = success;
            }
            break;

        case SYS_READ:
            {
                int fd = (int)f->R.rdi;          // File descriptor
                void *buffer = (void *)f->R.rsi; // Buffer to read into
                unsigned size = (unsigned)f->R.rdx; // Number of bytes to read

                int bytes_read = sys_read(fd, buffer, size);

                /* Set return value */
                f->R.rax = bytes_read;
            }
            break;

        case SYS_FILESIZE:
            {
                int fd = (int) f->R.rdi;
                int size = sys_filesize(fd);
                f->R.rax = size;
            }
            break;

        /* Handling other system calls */

        default:
            // printf("Unknown system call: %d\n", syscall_number);
            sys_exit(-1);
    }
}
