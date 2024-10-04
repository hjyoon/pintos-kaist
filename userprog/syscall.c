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
        /* 필요한 만큼 추가 */
        default:
            return "unknown";
    }
}

/* verify_user_buffer: 사용자 버퍼의 유효성을 검증하는 함수 */
bool
verify_user_buffer(const void *buffer, unsigned size) 
{
	if (buffer == NULL) {
		return false;
	}

	/* 사용자 주소 공간 내에 있는지 확인 */
	if (!is_user_vaddr(buffer)) {
		return false;
	}

	/* 각 바이트가 매핑되어 있는지 확인 */
	for (unsigned i = 0; i < size; i++) {
		void *addr = (void *) ((uintptr_t) buffer + i);
		if (!is_user_vaddr(addr) || pml4_get_page(thread_current()->pml4, addr) == NULL) {
			return false;
		}
	}

	return true;
}

/* copy_user_buffer: 사용자 버퍼를 커널 버퍼로 안전하게 복사하는 함수 */
bool
copy_user_buffer(const void *user_buffer, void *kernel_buffer, unsigned size) 
{
	/* 실제 구현에서는 페이지 폴트 방지를 위한 예외 처리 필요 */
	memcpy(kernel_buffer, user_buffer, size);
	return true; /* 예외 처리 후 반환 */
}

/* 
 * sys_write: 지정된 파일 디스크립터로 데이터를 쓰는 함수.
 * - fd: 파일 디스크립터
 * - buffer: 데이터 버퍼
 * - size: 데이터 크기
 * - 반환값: 실제로 쓰인 바이트 수, 오류 시 -1
 */
int
sys_write(int fd, const void *buffer, unsigned size) 
{
	/* 파일 디스크립터가 표준 출력인지 확인 */
	if (fd != STDOUT_FILENO) {
		/* 현재는 표준 출력만 지원 */
		return -1;
	}

	/* 버퍼 검증 */
	if (!verify_user_buffer(buffer, size)) {
		return -1;
	}

	/* 커널 버퍼 할당 */
	char *kernel_buffer = palloc_get_page(PAL_ZERO);
	if (kernel_buffer == NULL) {
		return -1; /* 메모리 할당 실패 */
	}

	/* 사용자 버퍼를 커널 버퍼로 복사 */
	if (!copy_user_buffer(buffer, kernel_buffer, size)) {
		palloc_free_page(kernel_buffer);
		return -1; /* 복사 실패 */
	}

	/* 콘솔에 데이터 출력 */
	putbuf(kernel_buffer, size);

	/* 커널 버퍼 해제 */
	palloc_free_page(kernel_buffer);

	/* 실제로 쓴 바이트 수 반환 */
	return size;
}

/* syscall_handler 함수 수정 */
void syscall_handler(struct intr_frame *f) {
	// TODO: Your implementation goes here.
	// printf ("system call!\n");

    /* 시스템 콜 번호 추출 */
    int syscall_number = f->R.rax;

    /* 시스템 콜 이름 추출 */
    const char* name = syscall_name(syscall_number);

    /* 호출자의 RIP (프로그램 카운터) 추출 */
    uintptr_t caller_rip = f->rip;

    /* 시스템 콜 정보 출력 */
    // printf("System Call Invoked: %s (%d) from RIP: 0x%016lx\n", name, syscall_number, caller_rip);

    /* 시스템 콜 번호에 따른 처리 */
    switch (syscall_number) {
        case SYS_EXIT:
            {
                /* exit(status)에서 status는 rdi에 전달됨 */
                int status = (int) f->R.rdi;
                // printf("Process %s exiting with status %d\n", thread_current()->name, status);
				printf("%s: exit(%d)\n", thread_current()->name, status);
                thread_exit();
            }
            break;

		case SYS_WRITE:
            {
                /* SYS_WRITE 시스템 콜 처리 */
                int fd = (int) f->R.rdi;               /* 파일 디스크립터 */
                const void *buffer = (const void *) f->R.rsi; /* 데이터 버퍼 */
                unsigned size = (unsigned) f->R.rdx;  /* 데이터 크기 */

                /* SYS_WRITE 함수 호출 */
                int bytes_written = sys_write(fd, buffer, size);

                /* 반환 값 설정 */
                f->R.rax = bytes_written;
            }
            break;

        /* 다른 시스템 콜 처리 */

        default:
            printf("Unknown system call: %d\n", syscall_number);
            thread_exit();
    }
}
