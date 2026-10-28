> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/introduction.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="project2-user-programs"></a>

# Project 2: User Programs

Pintos의 기반 구조와 thread 기능에 익숙해졌다면 이제 user program을 실행하는 부분을 다룰 차례입니다. 기본 코드는 user program의 loading과 실행은 지원하지만 I/O나 상호작용은 지원하지 않습니다. 이번 프로젝트에서는 system call로 프로그램이 OS와 상호작용하게 만듭니다. 주로 `userprog`에서 작업하지만 Pintos의 거의 모든 부분과 연결되며, 관련 코드를 아래에서 설명합니다.

**Project 2는 Project 1 제출물을 기반으로 구현해야 합니다.** Project 1 코드가 Project 2 구현에 직접 영향을 주지 않더라도 누적형 프로젝트이므로 Project 1 테스트를 계속 통과해야 합니다.

Project 2부터는 extra 과제도 있습니다. **선택 사항이며 필수 구현은 아닙니다.** extra에는 test case만 제공하고 skeleton은 제공하지 않으므로 설계는 직접 해야 합니다. **Extra를 테스트하고 제출하려면 `userprog/Make.vars`를 수정해야 합니다.**

`TODO` 표시가 없는 코드도 수정이 필요할 수 있습니다. Project 2에서는 테스트 코드를 제외한 소스를 자유롭게 수정할 수 있습니다.

<a id="background"></a>

## 배경

지금까지 Pintos에서 실행한 코드는 모두 kernel의 일부였습니다. 예를 들어 이전 과제의 테스트도 kernel 안에서 실행되어 privileged resource에 전부 접근할 수 있었습니다. user program을 실행하기 시작하면 더 이상 이런 가정이 성립하지 않습니다. 이 프로젝트에서는 그에 따른 문제를 다룹니다.

여러 process가 함께 실행될 수 있습니다. 각 process는 thread 하나만 가지며 multithreaded process는 지원하지 않습니다. user program은 자신이 컴퓨터 전체를 독점한다고 가정하고 작성됩니다. 여러 process를 실행해도 이 가정이 유지되도록 memory, scheduling, 기타 상태를 올바르게 관리해야 합니다.

이전 프로젝트에서는 테스트 코드를 kernel에 직접 컴파일했기 때문에 특정 내부 함수 interface를 요구했습니다. 이제부터는 user program으로 운영체제를 테스트하므로 구현의 자유도가 높아집니다. 명시된 user program interface만 지키면 kernel 내부 구조를 바꾸거나 다시 작성해도 됩니다. Project 2에 필요한 코드를 `#ifdef VM`로 둘러싼 구간 안에만 넣어서는 안 됩니다. 이 구간은 Project 3에서 VM을 활성화해야 포함되기 때문입니다. 반대로 `#ifndef VM`로 둘러싼 코드는 VM을 켜면 제외됩니다.

**시작 전에 [Synchronization](../appendix/synchronization.md)과 [Virtual Address](../appendix/virtual_address.md)를 읽는 것을 강하게 권장합니다.**

<a id="source-files"></a>

### 소스 파일

수정할 부분을 하나씩 살펴보면 작업의 전체 흐름을 파악하기 쉽습니다. `userprog`의 파일 수는 적지만 대부분의 작업은 이곳에서 이루어집니다.

- `process.c`, `process.h`

  ELF binary를 load하고 process를 시작합니다.

- `syscall.c`, `syscall.h`

  user process가 kernel 기능을 요청할 때 system call을 호출합니다. 이 파일에는 handler의 skeleton이 있으며, 현재는 메시지를 출력한 뒤 process를 종료할 뿐입니다. system call 구현 단계에서 필요한 기능을 추가합니다.

- `syscall-entry.S`

  system call handler에 진입하는 짧은 assembly 코드입니다. 자세히 이해할 필요는 없습니다.

- `exception.c`, `exception.h`

  user process가 privileged operation이나 금지된 작업을 수행하면 `exception` 또는 `fault` 등의 exception으로 kernel에 진입합니다. 이 파일들이 exception을 처리하며, 기본적으로 메시지를 출력한 뒤 process를 종료합니다. 구현 방식에 따라 이 파일의 `page_fault()`를 수정해야 할 수 있습니다.

<!-- -->

- `gdt.c`, `gdt.h`

  x86-64는 segmentation을 지원하는 architecture입니다. Global Descriptor Table(GDT)은 사용하는 segment를 기술하는 table이며, 이 파일들이 GDT를 설정합니다. 어느 프로젝트에서도 수정할 필요는 없습니다. 동작 원리가 궁금하면 읽어 보십시오.

- `tss.c`, `tss.h`

  Task-State Segment(TSS)는 x86에서 hardware task switching에 사용되었습니다. x86-64에서는 그 방식의 task switching을 사용하지 않지만, privilege level인 ring이 바뀔 때 stack pointer를 찾는 용도로 TSS가 여전히 필요합니다.

  즉, user process에서 interrupt handler로 진입할 때 hardware는 TSS에서 kernel stack pointer를 찾습니다. 이 파일들도 프로젝트에서 수정할 필요는 없습니다. TSS에 관심이 있다면 읽어 보십시오.

<a id="using-the-file-system"></a>

### File System 사용

user program을 file system에서 load하고, 구현할 여러 system call도 파일을 다루므로 file system 코드와 연동해야 합니다. 다만 이번 과제의 핵심은 file system이 아니므로 `filesys`에 단순하지만 필요한 기능을 갖춘 구현을 제공합니다. `filesys.h`와 `file.h` interface를 읽어 사용 방법과 제한을 파악하십시오.

**이번 프로젝트에서 file system 코드를 수정할 필요는 없으며, 수정하지 않는 것을 권장합니다.** 여기에 시간을 쓰면 과제의 핵심에서 벗어나기 쉽습니다.

**지금 file system 함수를 올바르게 사용하면 Project 4에서 구현을 개선할 때 훨씬 수월합니다.** 그전까지는 다음 제약을 받아들여야 합니다.

- 내부 synchronization이 없습니다. 동시에 접근하면 서로 간섭하므로, 한 번에 하나의 process만 file system 코드에 진입하도록 보호해야 합니다.
- 파일 크기는 생성 시 고정됩니다. root directory도 파일이므로 생성할 수 있는 파일 수도 제한됩니다.
- 파일 하나의 데이터는 연속한 disk sectors, 즉 단일 extent에 저장됩니다. 오래 사용하면 external fragmentation이 심해질 수 있습니다.
- subdirectory를 지원하지 않습니다.
- 파일 이름은 최대 14자입니다.
- 작업 도중 시스템이 비정상 종료되면 자동 복구할 수 없는 disk 손상이 생길 수 있습니다. file system 복구 도구도 제공하지 않습니다.

**다음의 중요한 기능은 이미 구현되어 있습니다.**

`filesys_remove()`에는 Unix와 같은 동작이 구현되어 있습니다. 열린 파일을 삭제해도 마지막 opener가 닫기 전까지 block을 해제하지 않으며, 기존에 열어 둔 thread는 계속 접근할 수 있습니다. [열린 파일의 삭제](FAQ.md)를 참조하십시오.

------------------------------------------------------------------------

Project 1과 달리 user space에서 실행하는 테스트 프로그램은 kernel image에 포함되지 않습니다. 직접 Pintos VM 안에 넣어야 합니다. 보통은 `make check` 등의 테스트 스크립트가 자동으로 처리하므로 세부사항을 몰라도 되지만, 개별 테스트를 실행할 때는 알아 두면 유용합니다.

파일을 VM에 넣으려면 먼저 file system partition이 있는 simulated disk를 만들어야 합니다. `pintos-mkdisk`가 이 기능을 제공합니다. `userprog/build`에서 `pintos-mkdisk filesys.dsk 2`을 실행하면 2 MB Pintos file system partition이 든 `filesys.dsk`가 생성됩니다. disk 지정 옵션 `--fs-disk filesys.dsk`은 `pintos` 뒤, `--` 앞에 둡니다. 전체 형식은 `pintos --fs-disk filesys.disk -- KERNEL_COMMANDS...`입니다. `--fs-disk`는 simulated kernel이 아니라 pintos 스크립트의 옵션이므로 구분자 `--`가 필요합니다. 다음으로 kernel command line에 `-f -q`를 전달해 format합니다. 전체 명령은 `pintos SCRIPT_COMMANDS -- -f -q`입니다. `-f`는 format을, `-q`는 format 후 즉시 종료를 지시합니다.

pintos의 `-p`(put)과 `-g`(get) 옵션으로 simulated file system 안팎에 파일을 복사합니다. 'file'을 넣으려면 `pintos -p file -- -q`를 사용합니다. `newname`라는 이름으로 넣으려면 원래 파일 이름 뒤에 `:newname`을 붙여 `pintos -p file:newname -- -q`처럼 실행합니다. VM에서 꺼낼 때도 비슷하지만 `-p` 대신 `-g`를 사용합니다.

이 기능은 kernel command line에 extract·append 등의 특수 명령을 전달하고, 별도의 simulated scratch partition을 통해 파일을 복사하는 방식으로 동작합니다. 자세한 구현은 pintos 스크립트와 `filesys/fsutil.c`를 살펴보십시오.

아래는 disk 생성, format, 이 프로젝트의 두 번째 테스트인 *args-single* 복사, 'onearg'를 argument로 전달한 실행까지의 예입니다. argument passing을 구현하기 전에는 argument 전달이 동작하지 않습니다. 테스트 프로그램을 이미 빌드했고 현재 directory가 `userprog/build`라고 가정합니다.

```
pintos-mkdisk filesys.dsk 10
pintos --fs-disk filesys.dsk -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'
```

disk를 나중에 보관하거나 조사할 필요가 없으면 네 단계를 한 명령으로 합칠 수도 있습니다. `--filesys-size=n`는 pintos 실행 동안만 사용하는 약 n MB 크기의 임시 file system partition을 만듭니다. 자동 테스트에서도 이 형식을 많이 사용합니다.

```
pintos --fs-disk=10 -p tests/userprog/args-single:args-single -- -q -f run 'args-single onearg'
```

<a id="how-user-programs-work"></a>

### User Program의 동작

memory에 들어가고 구현된 system call만 사용하는 일반 C 프로그램을 실행할 수 있습니다. 다만 이번 과제의 system call에는 memory allocation 기능이 없으므로 `malloc()`은 구현할 수 없습니다. context switch 때 floating-point unit의 상태를 저장·복원하지 않으므로 floating-point 연산을 사용하는 프로그램도 지원하지 않습니다.

`userprog/process.c`에 제공된 loader는 ELF executable을 load합니다. ELF는 Linux, Solaris 등 여러 OS에서 object file, shared library, executable에 사용하는 형식입니다.

x86-64 ELF executable을 출력하는 compiler와 linker라면 어떤 것을 사용해도 됩니다. 제공된 도구를 사용해도 충분합니다. 테스트 프로그램을 simulated file system에 복사하기 전에는 Pintos로 할 수 있는 일이 거의 없습니다. 여러 프로그램을 넣어 실행해 보십시오. debugging 중 `filesys.dsk`를 사용할 수 없을 정도로 손상시킬 수도 있으므로, 깨끗한 기준 disk image를 만들어 두고 필요할 때 복원하면 편리합니다.

<a id="virtual-memory-layout"></a>

### Virtual Memory Layout

Pintos의 virtual memory는 user virtual memory와 kernel virtual memory로 나뉩니다. user 영역은 virtual address `0`부터 `include/threads/vaddr.h`에 정의된 `KERN_BASE` 전까지이며, 경계의 기본값은 `0x8004000000`입니다. 나머지 virtual address space는 kernel 영역입니다.

user virtual memory는 process마다 독립적입니다. process를 전환할 때 processor의 page directory base register를 바꾸어 user address space도 전환합니다. `thread/mmu.c`의 `pml4_activate()`를 참조하십시오. struct thread에는 process의 page table pointer가 있습니다.

kernel virtual memory는 시스템 전체에서 공유하며, 실행 중인 user process나 kernel thread가 바뀌어도 같은 mapping이 유지됩니다. Pintos에서는 `KERN_BASE`부터 physical memory와 일대일로 대응합니다. 예를 들어 virtual address `KERN_BASE`는 physical address `0`를, `KERN_BASE + 0x1234`는 `0x1234`를 가리키며, 이 대응은 실제 physical memory 크기까지 이어집니다.

user program은 자신의 user virtual memory에만 접근할 수 있습니다. kernel virtual memory에 접근하면 page fault가 발생해 `userprog/exception.c`의 `page_fault()`가 처리하며 process가 종료됩니다. kernel thread는 kernel 영역과 현재 실행 중인 user process의 user 영역에 접근할 수 있습니다. 그러나 kernel에서도 mapping이 없는 user virtual address에 접근하면 page fault가 발생합니다.

<a id="typical-memory-layout"></a>

### 일반적인 Memory Layout

개념적으로 process는 자신의 user virtual memory를 원하는 대로 배치할 수 있습니다. 보통은 다음과 같은 구성을 사용합니다.

    USER_STACK +----------------------------------+
               |             user stack           |
               |                 |                |
               |                 |                |
               |                 V                |
               |           grows downward         |
               |                                  |
               |                                  |
               |                                  |
               |                                  |
               |           grows upward           |
               |                 ^                |
               |                 |                |
               |                 |                |
               +----------------------------------+
               | uninitialized data segment (BSS) |
               +----------------------------------+
               |     initialized data segment     |
               +----------------------------------+
               |            code segment          |
     0x400000  +----------------------------------+
               |                                  |
               |                                  |
               |                                  |
               |                                  |
               |                                  |
           0   +----------------------------------+

이번 프로젝트의 user stack 크기는 고정이지만 Project 3에서는 확장할 수 있게 됩니다. 전통적으로 uninitialized data segment의 크기는 system call로 조절하지만, 이 기능은 구현하지 않아도 됩니다.

Pintos의 code segment는 user virtual address 0x400000에서 시작합니다. 이 값은 Ubuntu에서 흔히 사용하던 값이며 특별한 의미는 없습니다.

> **원문 주의:** 원문은 0x400000을 약 128 MB라고 설명하지만, 실제로는 4 MiB입니다. 주소 값 자체는 그대로 보존했습니다.

linker는 linker script가 지정한 segment 이름과 위치에 따라 user program의 memory layout을 결정합니다. `info ld`로 볼 수 있는 linker 매뉴얼의 Scripts 장에서 자세히 설명합니다.

특정 executable의 배치를 보려면 objdump에 `-p` 옵션을 지정하십시오.

<a id="accessing-user-memory"></a>

### User Memory 접근

system call을 처리하는 kernel은 user program이 넘긴 pointer로 memory에 접근해야 하는 경우가 많습니다. user는 null pointer, mapping이 없는 virtual memory의 pointer, 또는 `KERN_BASE` 이상의 kernel 영역을 가리키는 pointer를 전달할 수 있으므로 주의해야 합니다. invalid pointer를 발견하면 해당 process를 종료하고 자원을 해제하되, kernel이나 다른 process에 피해를 주어서는 안 됩니다.

안전하게 처리하는 대표적인 방법은 두 가지입니다. 첫 번째는 pointer의 유효성을 먼저 확인한 뒤 dereference하는 것입니다. `thread/mmu.c`와 `include/threads/vaddr.h`의 함수를 살펴보십시오. user memory 접근을 처리하는 가장 단순한 방식입니다.

두 번째는 pointer가 `KERN_BASE` 아래에 있는지만 확인한 뒤 dereference하는 것입니다. invalid pointer라면 page fault가 발생하므로 `userprog/exception.c`의 `page_fault()`를 수정해 처리합니다. processor의 MMU를 활용하므로 보통 더 빠르며 Linux 등 실제 kernel에서도 사용하는 접근입니다.

어느 방법이든 resource leak을 막아야 합니다. system call이 이미 lock을 획득했거나 `malloc()`으로 memory를 할당한 뒤 invalid pointer를 발견했다면 lock을 해제하거나 page를 반환해야 합니다. 사전 검증 방식에서는 비교적 간단하지만, page fault를 이용하면 memory access 자체에서 오류 코드를 반환할 수 없으므로 더 어렵습니다. 후자의 방식을 시도하는 경우를 위해 다음 보조 코드를 제공합니다.

```
/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
```

각 함수는 user address가 `KERN_BASE` 아래임을 이미 확인했다고 가정합니다. 또한 kernel에서 page fault가 발생하면 rax를 -1로 바꾸고, 바꾸기 전 rax 값을 `%rip`에 복사하도록 `page_fault()`를 수정했다고 가정합니다.
