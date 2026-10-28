> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/FAQ.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="faq"></a>

# FAQ

<a id="how-much-code-will-i-need-to-write"></a>

### 코드를 얼마나 작성해야 하나요?

다음은 `git diff --stat`로 집계한 reference solution의 변경량입니다. 마지막 행은 추가·삭제한 줄의 합계이며, 수정한 한 줄은 추가와 삭제에 각각 한 줄씩 포함됩니다. reference solution은 가능한 구현 중 하나일 뿐입니다. 전혀 다른 좋은 구현도 가능하며, 같은 파일을 모두 수정하거나 같은 파일만 수정할 필요는 없습니다. 이 집계에는 extra 요구사항의 구현도 포함되어 있고, 약 150줄이 extra와 관련됩니다.

    src/include/threads/thread.h   |  23 ++
    src/include/userprog/syscall.h |   3 +
    src/threads/thread.c           |   5 +
    src/userprog/exception.c       |   4 +
    src/userprog/process.c         | 355 +++++++++++++++++++++++++++++++++++++++++-
    src/userprog/syscall.c         | 429 ++++++++++++++++++++++++++++++++++++++++++-
    6 files changed, 782 insertions(+), 37 deletions(-)

<a id="the-kernel-always-panics-when-i-run-pintos--p-file-----q"></a>

### `pintos -p file -- -q`를 실행하면 항상 kernel panic이 발생합니다.

`pintos -f` 옵션으로 file system을 format했는지 확인하십시오.

파일 이름이 너무 긴지 확인하십시오. 기본 file system은 이름을 14자로 제한합니다.

`pintos -p ../../examples/echo -- -q` 같은 명령은 이 제한을 넘습니다.

대신 `pintos -p ../../examples/echo:echo -- -q`를 사용해 `echo`라는 이름으로 복사하십시오.

file system이 가득 차지 않았는지 확인하십시오.

이미 파일이 16개 있는지도 확인하십시오. 기본 Pintos file system에는 16개 제한이 있습니다.

fragmentation 때문에 파일을 저장할 연속 공간이 부족할 수도 있습니다.

<a id="when-i-run-pintos--p-file----file-isnt-copied"></a>

### `pintos -p ../file --`를 실행해도 'file'이 복사되지 않습니다.

기본적으로 파일은 명령에 지정한 이름 그대로 저장되므로, 이 경우 복사한 파일의 이름은 '../file'이 됩니다. 의도한 명령은 아마 `pintos -p ../file:file --`일 것입니다.

<a id="all-my-user-programs-die-with-page-faults"></a>

### 모든 user program이 page fault로 종료됩니다.

argument passing을 구현하지 않았거나 잘못 구현했을 때 발생합니다. user program용 C library는 stack에서 argv를 읽으려 하므로, stack이나 register를 올바르게 설정하지 않으면 page fault가 발생합니다.

<a id="all-my-user-programs-die-with-system-call"></a>

### 모든 user program이 `system call!` 메시지와 함께 종료됩니다.

다른 동작을 보려면 system call을 구현해야 합니다. 정상적인 프로그램은 최소한 `exit()`을 호출하며, 대부분 그보다 많은 system call을 사용합니다. 특히 `printf()`는 write system call을 호출합니다. 기본 handler는 `system call!`를 출력하고 프로그램을 종료할 뿐입니다. 그전까지는 `hex_dump()`로 argument passing이 올바른지 확인할 수 있습니다.

<a id="how-can-i-disassemble-user-programs"></a>

### User program은 어떻게 disassemble하나요?

objdump -d file로 user program 전체나 object file을 disassemble할 수 있습니다. 함수 하나만 확인하려면 GDB의 disassemble 명령을 사용하십시오.

<a id="why-do-many-c-include-files-not-work-in-pintos-programs"></a>

### Pintos 프로그램에서 여러 C header를 사용할 수 없는 이유는 무엇인가요?

<a id="can-i-use-libfoo-in-my-pintos-programs"></a>

### Pintos 프로그램에서 libfoo를 사용할 수 있나요?

제공되는 C library는 기능이 제한적이며, 일반 운영체제의 C library에 있는 많은 기능이 없습니다. I/O와 memory allocation을 위해 해당 OS의 system call을 사용해야 하므로, C library는 OS와 architecture에 맞춰 빌드해야 합니다. 모든 함수가 system call을 쓰는 것은 아니지만 보통 library를 하나의 단위로 빌드합니다.

사용하려는 library가 Pintos에 없는 C library 기능에 의존할 가능성이 높습니다. Pintos에서 동작하게 하려면 어느 정도 porting이 필요할 것입니다. 특히 Pintos의 user program용 C library에는 `malloc()`이 없습니다.

<a id="how-do-i-compile-new-user-programs"></a>

### 새 user program은 어떻게 컴파일하나요?

`src/examples/Makefile`를 수정한 뒤 `make`를 실행하십시오.

<a id="can-i-run-user-programs-under-a-debugger"></a>

### Debugger에서 user program을 실행할 수 있나요?

일부 제약은 있지만 가능합니다. [GDB](../appendix/debugging_tools.md#gdb)를 참조하십시오.

<a id="whats-the-difference-between-tidt-and-pidt"></a>

### tid_t와 pid_t의 차이는 무엇인가요?

tid_t는 kernel thread를 식별하며 kernel 안에서만 사용하는 type입니다. `process_fork()`로 만든 thread는 user process를 실행할 수 있고, `thread_create()`로 만든 thread는 그렇지 않을 수도 있습니다. pid_t는 user process를 식별하며 exec와 wait system call에서 kernel과 user process 양쪽이 사용합니다. 두 type은 적절한 것을 선택하면 되고, 기본값은 둘 다 int입니다. 같은 값이 같은 process를 가리키도록 일대일로 대응시켜도 되고, 더 복잡한 관계를 사용해도 됩니다.

<a id="can-i-just-cast-a-struct-file--to-get-a-file-descriptor"></a>

### `struct file *`를 cast해서 file descriptor로 사용해도 되나요?

<a id="can-i-just-cast-a-struct-thread--to-a-pidt"></a>

### `struct thread *`를 `pid_t`로 cast해도 되나요?

아니요. `pid_t`와 `file descriptor`는 pointer보다 작으므로, 단순한 cast로 pointer 값을 온전히 보존할 수 없습니다.

> **원문 주의:** 원문의 두 번째 문장은 “can”이라고 쓰여 있지만 앞의 “No”와 모순됩니다. 여기서는 type 크기 차이로 값이 잘릴 수 있다는 문맥에 맞춰 옮겼습니다.

<a id="can-i-set-a-maximum-number-of-open-files-per-process"></a>

### Process당 열린 파일 수의 상한을 정해도 되나요?

임의의 제한은 두지 않는 것이 좋습니다. 필요하면 process당 128개로 제한해도 됩니다. 다만 extra 요구사항을 구현한다면 이런 제한이 없어야 합니다.

<a id="what-happens-when-an-open-file-is-removed"></a>

### 열린 파일을 삭제하면 어떻게 되나요?

Unix와 같은 동작을 구현해야 합니다. 파일을 삭제해도 그 파일의 file descriptor를 가진 process는 계속 읽고 쓸 수 있습니다. 이름은 사라져 다른 process가 새로 열 수는 없지만, 이를 가리키는 모든 file descriptor가 닫히거나 시스템이 종료될 때까지 파일 자체는 유지됩니다.

<a id="how-can-i-run-user-programs-that-need-more-than-4-kb-stack-space"></a>

### 4 kB보다 큰 stack이 필요한 user program은 어떻게 실행하나요?

stack 초기화 코드를 수정해 process마다 여러 page를 할당해도 됩니다. 다음 프로젝트에서 더 나은 방법을 구현하게 됩니다.
