> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project1/introduction.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="project1-threads"></a>

# Project 1: Threads

이 과제에서는 최소한의 기능만 갖춘 thread system을 제공합니다. synchronization 문제를 더 잘 이해할 수 있도록 이 시스템의 기능을 확장하는 것이 목표입니다. 주로 `threads`에서 작업하고, 일부 코드는 `devices`에서 수정합니다. 컴파일은 `threads` directory에서 수행하십시오. 과제 설명을 읽기 전에 [Synchronization](../appendix/synchronization.md)을 적어도 한 번 훑어보십시오.

<a id="background"></a>

## 배경

<a id="understanding-threads"></a>

### Thread 이해하기

먼저 초기 thread system 코드를 읽고 이해하십시오. Pintos는 이미 thread의 생성과 종료, thread 사이를 전환하는 간단한 scheduler, 그리고 semaphore·lock·condition variable·optimization barrier 등의 synchronization primitive를 제공합니다.

처음에는 일부 코드가 이해하기 어려울 수 있습니다. [시작하기](../introduction/getting_started.md)에 따라 기본 시스템을 빌드하고 실행하지 않았다면 지금 해 보십시오. 소스를 따라가며 동작을 살펴보고, 필요하면 여러 위치에 `printf()`를 추가한 뒤 다시 컴파일·실행해 실행 순서를 확인할 수 있습니다. debugger에서 kernel을 실행하며 breakpoint를 걸거나, 코드를 한 단계씩 실행하고 데이터를 조사해도 됩니다.

thread 생성은 scheduler가 실행할 새로운 context를 만드는 일입니다. thread_create()의 argument로 이 context에서 실행할 함수를 전달합니다. thread가 처음 scheduling되어 실행될 때 그 함수의 첫 부분부터 시작하며, 함수가 반환되면 thread가 종료됩니다. 따라서 각 thread는 Pintos 안에서 실행되는 작은 프로그램과 비슷하고, `thread_create()`에 전달한 함수는 그 프로그램의 `main()` 역할을 합니다.

어느 순간이든 실행되는 thread는 정확히 하나이고, 나머지는 실행되지 않는 상태입니다. 다음 thread는 scheduler가 선택합니다. 실행 가능한 thread가 하나도 없으면 `idle()`에 구현된 특별한 *idle* thread가 실행됩니다. 한 thread가 다른 thread의 작업을 기다려야 할 때 synchronization primitive가 context switch를 일으킬 수 있습니다.

context switch의 세부 동작은 `threads/thread.c`의 `thread_launch()`에 구현되어 있습니다. 이 코드를 자세히 이해할 필요는 없습니다. 현재 thread의 상태를 저장하고 다음 thread의 상태를 복원하는 코드입니다.

[GDB](../appendix/debugging_tools.md#gdb)로 context switch를 천천히 따라가 보십시오. `schedule()`에 breakpoint를 건 뒤 single-step으로 진행하면 됩니다. 각 thread의 주소와 상태, call stack에 있는 함수들을 추적하십시오. 한 thread가 `do_iret()`에서 `iret`를 실행하면 다른 thread가 실행되기 시작하는 모습을 볼 수 있습니다.

**주의:** Pintos는 thread마다 4 kB보다 약간 작은 고정 크기의 execution stack을 할당합니다. kernel이 stack overflow를 탐지하려고 하지만 완벽하지는 않습니다. `int buf[1000];`처럼 큰 자료구조를 non-static local variable로 선언하면 원인을 알기 어려운 kernel panic 등이 발생할 수 있습니다. stack 대신 page allocator나 block allocator를 사용할 수 있습니다. [Memory Allocation](../appendix/memory_allocation.md)을 참조하십시오.

<a id="source-files"></a>

### 소스 파일

다음은 `threads`와 `include/threads` directory의 파일들을 간단히 정리한 것입니다. 대부분을 수정할 필요는 없지만, 어떤 코드를 살펴봐야 하는지 판단하는 데 도움이 됩니다.

<a id="threads-codes"></a>

#### `threads` 코드

- `loader.S`, `loader.h`

  kernel loader입니다. PC BIOS가 memory에 적재하는 512 bytes의 code와 data로 assemble됩니다. loader는 disk의 kernel을 찾아 memory로 읽은 뒤 `start.S`의 `bootstrap()`으로 이동합니다. 보통 이 코드를 살펴보거나 수정할 필요는 없습니다. `start.S`는 memory protection에 필요한 초기 설정을 하고 64-bit long mode로 전환합니다. loader와 달리 이 코드는 kernel 자체에 포함됩니다.

- `kernel.lds.S`

  kernel을 link할 때 사용하는 linker script입니다. kernel의 load address를 정하고 `start.S`를 kernel image의 앞부분에 배치합니다. 보통 수정할 필요는 없지만 궁금하면 살펴보십시오.

- `init.c`, `init.h`

  kernel 초기화 코드입니다. kernel의 `main program.`인 `main()`도 포함합니다. 적어도 `main()`을 읽어 무엇이 초기화되는지 확인하십시오. 자신의 초기화 코드를 추가할 수도 있습니다.

- `thread.c`, `thread.h`

  기본 thread 기능을 제공합니다. 많은 작업을 이 파일들에서 수행하게 됩니다. `thread.h`에는 네 프로젝트에 걸쳐 수정하게 될 struct thread가 정의되어 있습니다. 자세한 내용은 [Threads](../appendix/threads.md)를 참조하십시오.

- `palloc.c`, `palloc.h`

  system memory를 4 kB page의 배수 단위로 할당하는 page allocator입니다. [Page Allocator](../appendix/memory_allocation.md#page-allocator)를 참조하십시오.

- `malloc.c`, `malloc.h`

  kernel용 `malloc()`과 `free()`의 간단한 구현입니다. [Block Allocator](../appendix/memory_allocation.md#block-allocator)를 참조하십시오.

- `interrupt.c`, `interrupt.h`

  기본 interrupt 처리와 interrupt를 켜고 끄는 함수들입니다.

- `intr-stubs.S`, `intr-stubs.h`

  low-level interrupt 처리를 위한 assembly 코드입니다.

- `synch.c`, `synch.h`

  semaphore, lock, condition variable, optimization barrier 등 기본 synchronization primitive입니다. 네 프로젝트 모두에서 synchronization을 위해 사용합니다. [Synchronization](../appendix/synchronization.md)을 참조하십시오.

- `mmu.c`, `mmu.h`

  x86-64 page table을 조작하는 함수들입니다. Project 1 이후 자세히 살펴보게 됩니다.

- `io.h`

  I/O port에 접근하는 함수들입니다. 주로 직접 수정할 필요가 없는 `devices`의 코드에서 사용합니다.

- `vaddr.h`, `pte.h`

  virtual address와 page table entry를 다루는 함수·macro입니다. Project 3에서 중요해지므로 지금은 넘어가도 됩니다.

- `flags.h`

  x86-64 `flags` register의 일부 bit를 정의하는 macro입니다. 보통 자세히 살펴볼 필요는 없습니다.

<a id="devices-codes"></a>

#### `devices` 코드

기본 threaded kernel에는 `devices`의 다음 파일들도 포함됩니다.

- `timer.c`, `timer.h`

  기본적으로 초당 100번 tick하는 system timer입니다. 이번 프로젝트에서 수정합니다.

- `vga.c`, `vga.h`

  화면에 text를 출력하는 VGA display driver입니다. `printf()`가 대신 호출하므로 보통 직접 살펴보거나 호출할 필요가 없습니다.

- `serial.c`, `serial.h`

  serial port driver입니다. 이것도 `printf()`가 대신 호출하므로 직접 사용할 필요는 없습니다. serial 입력은 아래의 input layer로 전달합니다.

- `block.c`, `block.h`

  block device의 abstraction layer입니다. block device는 크기가 일정한 block의 배열로 구성된, disk처럼 random access가 가능한 장치입니다. 기본 Pintos는 IDE disk와 partition 두 종류를 지원합니다. 실제 block device 사용은 Project 2부터 시작합니다.

- `ide.c`, `ide.h`

  최대 4개의 IDE disk에서 sector를 읽고 쓰는 기능을 제공합니다.

- `partition.c`, `partition.h`

  disk의 partition 구조를 해석해 하나의 disk를 독립적으로 사용할 여러 영역, 즉 partition으로 나눌 수 있게 합니다.

- `kbd.c`, `kbd.h`

  keyboard driver입니다. key 입력을 아래의 input layer로 전달합니다.

- `input.c`, `input.h`

  keyboard나 serial driver가 전달한 입력 문자를 queue에 보관하는 input layer입니다.

- `intq.c`, `intq.h`

  kernel thread와 interrupt handler가 함께 접근하는 circular queue를 관리하는 interrupt queue입니다. keyboard와 serial driver에서 사용합니다.

- `rtc.c`, `rtc.h`

  kernel이 현재 날짜와 시간을 알 수 있게 하는 real-time clock driver입니다. 기본적으로는 `thread/init.c`가 random number generator의 초기 seed를 정할 때만 사용합니다.

- `speaker.c`, `speaker.h`

  PC speaker에서 음을 내는 driver입니다.

- `pit.c`, `pit.h`

  8254 Programmable Interrupt Timer를 설정합니다. `devices/timer.c`와 `devices/speaker.c`가 각각 PIT의 output channel 하나를 사용하므로 이 코드를 함께 이용합니다.

<a id="lib-codes"></a>

#### `lib` 코드

마지막으로 `lib`와 `lib/kernel`에는 유용한 library 함수들이 있습니다. `lib/user`는 Project 2부터 user program에서 사용하며 kernel에는 포함되지 않습니다. 주요 구성은 다음과 같습니다.

- `ctype.h`, `inttypes.h`, `limits.h`, `stdarg.h`, `stdbool.h`, `stddef.h`, `stdint.h`, `stdio.c`, `stdio.h`, `stdlib.c`, `stdlib.h`, `string.c`, `string.h`

  표준 C library의 일부입니다.

- `debug.c`, `debug.h`

  debugging을 돕는 함수·macro입니다. [Debugging Tools](../appendix/debugging_tools.md)를 참조하십시오.

- `random.c`, `random.h`

  pseudo-random number generator입니다. 기본적으로 생성하는 값의 순서는 Pintos를 다시 실행해도 달라지지 않습니다.

- `round.h`

  rounding에 사용하는 macro입니다.

- `syscall-nr.h`

  system call 번호를 정의합니다. Project 2부터 사용합니다.

- `kernel/list.c`, `kernel/list.h`

  doubly linked list 구현입니다. Pintos 전반에서 사용하며 Project 1에서도 여러 곳에 활용할 수 있습니다. **시작 전에 이 코드, 특히 header의 주석을 훑어보는 것을 권장합니다.**

- `kernel/bitmap.c`, `kernel/bitmap.h`

  bitmap 구현입니다. 필요하면 사용해도 되지만 Project 1에서는 보통 필요하지 않습니다.

- `kernel/hash.c`, `kernel/hash.h`

  hash table 구현입니다. Project 3에서 유용하게 사용할 수 있습니다.

- `kernel/console.c`, `kernel/console.h`, `kernel/stdio.h`

  `printf()`와 몇 가지 다른 함수를 구현합니다.

<a id="synchronization"></a>

### Synchronization

올바른 synchronization은 이 과제의 중요한 부분입니다. interrupt를 끄면 동시 실행이 일어나지 않아 race condition을 쉽게 피할 수 있지만, 모든 문제를 이 방식으로 해결해서는 안 됩니다. 대부분의 synchronization에는 semaphore, lock, condition variable을 사용하십시오. 어떤 상황에 어떤 primitive를 사용할 수 있는지 불분명하다면 [Synchronization](../appendix/synchronization.md)이나 `threads/synch.c`의 주석을 읽어 보십시오.

Pintos에서 interrupt를 끄는 방법이 적합한 대표적인 경우는 kernel thread와 interrupt handler가 공유하는 데이터를 보호할 때입니다. interrupt handler는 sleep할 수 없어 lock을 획득할 수 없습니다. 따라서 kernel thread가 handler와 공유하는 데이터에 접근할 때는 interrupt를 꺼서 보호해야 합니다.

이번 프로젝트에서 interrupt handler가 접근해야 하는 thread 상태는 많지 않습니다. alarm clock에서는 timer interrupt가 sleeping thread를 깨워야 합니다. advanced scheduler에서는 timer interrupt가 일부 전역 변수와 thread별 변수에 접근합니다. kernel thread에서 이 변수들을 다룰 때는 timer interrupt가 중간에 개입하지 않도록 interrupt를 꺼야 합니다.

interrupt를 끄는 코드 구간은 최대한 짧게 유지하십시오. 그렇지 않으면 timer tick이나 입력 event를 놓칠 수 있습니다. interrupt 처리 지연도 길어지므로, 지나치면 시스템이 느리게 반응합니다.

`synch.c`의 synchronization primitive 자체도 interrupt를 꺼서 구현합니다. 이 파일에서 interrupt가 꺼진 구간을 늘려야 할 수 있지만, 그래도 가능한 한 짧게 유지하십시오.

특정 코드 구간이 interrupt에 의해 중단되지 않게 하려는 debugging 용도로도 interrupt 비활성화를 사용할 수 있습니다. 제출 전에는 이런 debugging 코드를 제거하십시오. 읽기 어려운 코드를 남기지 않도록 주석 처리만 하지 말고 삭제하십시오.

제출물에는 busy waiting이 없어야 합니다. `thread_yield()`를 반복 호출하는 짧은 loop도 busy waiting의 한 형태입니다.

<a id="development-suggestions"></a>

### 개발 제안

예전에는 과제를 나누어 각자 작업하다가 마감 직전에 코드를 합쳐 제출하는 팀이 많았습니다. 이 방식은 권장하지 않습니다. 마지막에 변경 사항이 충돌해 debugging에 많은 시간을 쓰기 쉽고, 테스트는커녕 컴파일이나 부팅도 되지 않는 코드를 제출한 사례도 있었습니다.

대신 <a href="https://git-scm.com/docs/gittutorial" target="_blank">git</a> 같은 version control system으로 변경 사항을 일찍부터 자주 통합하십시오. 완성된 뒤에야 코드를 보는 것이 아니라 작업 중에도 서로의 코드를 볼 수 있어 예상하지 못한 문제를 줄일 수 있습니다. 변경 이력을 검토하고 버그를 도입한 변경을 이전의 정상 버전으로 되돌리는 데도 도움이 됩니다.

이번 프로젝트와 이후 프로젝트에서 원인을 이해하기 어려운 버그를 만나게 될 것입니다. 그럴 때는 [Debugging Tools](../appendix/debugging_tools.md)를 다시 읽어 보십시오. 유용한 debugging 방법이 많습니다. 특히 [Backtraces](../appendix/debugging_tools.md#backtraces) 절을 읽으면 kernel panic이나 assertion failure에서 더 많은 정보를 얻을 수 있습니다.
