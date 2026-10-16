> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/FAQ.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="faq"></a>

# 자주 묻는 질문

<a id="how-much-code-will-i-need-to-write"></a>

### 코드를 얼마나 작성해야 하나요?

다음은 `git diff --stat`에 의해 생산된 우리의 참조 솔루션의 요약입니다. 마지막 줄은 삽입 및 삭제된 전체 라인을 나타냅니다. 변경된 라인은 삽입과 삭제 모두로 간주됩니다. 참고 솔루션은 하나의 가능한 솔루션입니다. 또한 다른 많은 솔루션이 가능하며 그 중 많은 것이 참조 솔루션과 크게 다릅니다. 일부 우수한 솔루션은 참조 솔루션으로 수정된 모든 파일을 수정하지 않을 수도 있고, 일부에서는 참조 솔루션으로 수정되지 않은 파일을 수정할 수도 있습니다. 또한, 추가 요구사항을 시행하는 것도 포함된다. FYI, ~ 150 줄은 추가와 관련이 있습니다.

    src/include/threads/thread.h   |  23 ++
    src/include/userprog/syscall.h |   3 +
    src/threads/thread.c           |   5 +
    src/userprog/exception.c       |   4 +
    src/userprog/process.c         | 355 +++++++++++++++++++++++++++++++++++++++++-
    src/userprog/syscall.c         | 429 ++++++++++++++++++++++++++++++++++++++++++-
    6 files changed, 782 insertions(+), 37 deletions(-)

<a id="the-kernel-always-panics-when-i-run-pintos--p-file-----q"></a>

### `pintos -p file -- -q`를 실행하면 항상 커널 패닉이 발생합니다.

파일 시스템 (`pintos -f`) 을 포맷하셨나요?

파일 이름은 너무 길어? 파일 시스템은 파일 이름을 14개의 문자로 제한합니다.

`pintos -p ../../examples/echo -- -q` 같은 명령은 제한을 초과합니다.

대신 `pintos -p ../../examples/echo:echo -- -q`을 사용하여 파일을 `echo`로 부릅니다.

파일 시스템이 가득한가요?

파일 시스템은 이미 16개의 파일을 포함하고 있나요? 기본 Pintos 파일 시스템에는 16 파일 제한이 있습니다.

파일 시스템은 너무 파편화되어서 파일에는 충분한 공간이 없을 수도 있습니다.

<a id="when-i-run-pintos--p-file----file-isnt-copied"></a>

### `pintos -p ../file --`를 실행해도 'file'이 복사되지 않습니다.

파일은 기본적으로 당신이 참조하는 이름으로 작성됩니다. 따라서 이 경우 복사된 파일은 '../file'라는 이름이 붙습니다. 당신은 아마도 대신 `pintos -p ../file:file --`를 실행하기를 원할 것입니다.

<a id="all-my-user-programs-die-with-page-faults"></a>

### 모든 유저 프로그램이 페이지 폴트로 종료됩니다.

만약 당신이 논증 통과를 구현하지 않았다면 (또는 올바르게 수행하지 않았다면) 이 발생합니다. 사용자 프로그램에 대한 기본적인 C 라이브러리는 stack에서 argv를 읽는 것을 시도합니다. 스택이나 레지스터가 제대로 설정되지 않으면 페이지 폴트가 발생합니다.

<a id="all-my-user-programs-die-with-system-call"></a>

### 모든 유저 프로그램이 `system call!`로 종료됩니다.

다른 것을 보기 전에 시스템 호출을 실행해야 합니다. 모든 합리적인 프로그램은 적어도 하나의 시스템 호출 (`exit()`) 을 시도합니다. 대부분의 프로그램은 그 이상을 만듭니다. 특히, `printf()`는 쓰기 시스템 호출을 호출합니다. 기본 시스템 호출 핸들러는 `system call!`를 프린트해서 프로그램을 종료합니다. 그 때까지, 당신은 `hex_dump()`을 사용하여 논증 통과가 올바르게 구현되었다는 것을 자신있게 할 수 있습니다.

<a id="how-can-i-disassemble-user-programs"></a>

### 유저 프로그램은 어떻게 역어셈블하나요?

Objdump 유틸리티는 전체 사용자 프로그램이나 객체 파일을 해체 할 수 있습니다. 오브 덤프 파일로 부릅니다. GDB의 분해 명령어를 사용하여 개별 함수를 분해할 수 있습니다.

<a id="why-do-many-c-include-files-not-work-in-pintos-programs"></a>

### 많은 C 헤더 파일이 Pintos 프로그램에서 동작하지 않는 이유는 무엇인가요?

<a id="can-i-use-libfoo-in-my-pintos-programs"></a>

### Pintos 프로그램에서 libfoo를 사용해도 되나요?

우리가 제공하는 C 라이브러리는 매우 제한적입니다. 실제 운영 체제의 C 라이브러리에서 기대되는 많은 함수를 포함하지 않습니다. C 라이브러리는 운영 체제 (그리고 아키텍처) 를 위해 특별히 구축되어야 하며, 이는 I/O 및 메모리 할당을 위한 시스템 호출을 해야 하기 때문이다. (물론 모든 함수이 작동하지는 않지만 일반적으로 라이브러리는 단위로 컴파일됩니다.)

당신이 원하는 라이브러리는 Pintos가 구현하지 않는 C 라이브러리의 일부를 사용하는 가능성이 높습니다. 피노스 밑에서 작동하기 위해서는 적어도 약간의 포팅 노력이 필요할 것입니다. 특히 Pintos 사용자 프로그램 C 라이브러리는 `malloc()` 구현이 없습니다.

<a id="how-do-i-compile-new-user-programs"></a>

### 새 유저 프로그램은 어떻게 컴파일하나요?

`src/examples/Makefile`을 수정하고 `make`을 실행하세요.

<a id="can-i-run-user-programs-under-a-debugger"></a>

### 디버거로 유저 프로그램을 실행할 수 있나요?

예, 몇 가지 한계를 가지고 있습니다. [GDB](FAQ.md) 참조

<a id="whats-the-difference-between-tidt-and-pidt"></a>

### tid_t와 pid_t의 차이는 무엇인가요?

tid_t는 커널 스레드를 식별합니다. 이 스레드에는 사용자 프로세스가 실행될 수 있습니다 (`process_fork()`을 사용하여 생성된 경우) 또는 그렇지 않습니다 (`thread_create()`을 사용하여 생성된 경우). 이것은 커널에서만 사용되는 데이터 타입입니다. pid_t는 사용자 프로세스를 식별합니다. 그것은 exec 및 대기 시스템 호출에서 사용자 프로세스와 커널에서 사용됩니다. TID_T 및 PID_T에 대해 원하는 적절한 유형을 선택할 수 있습니다. 기본적으로 둘 다 int입니다. 둘 다 같은 값으로 동일한 프로세스를 식별할 수 있도록 한 대 한 매핑를 만들 수도 있고, 더 복잡한 매핑를 사용할 수도 있습니다. 그건 네 몫이야

<a id="can-i-just-cast-a-struct-file--to-get-a-file-descriptor"></a>

### `struct file *`을 형변환해 파일 디스크립터로 사용해도 되나요?

<a id="can-i-just-cast-a-struct-thread--to-a-pidt"></a>

### `struct thread *`를 `pid_t`로 형변환해도 되나요?

아뇨 `pid_t`과 `file descriptor`은 포인터 타입보다 작기 때문에 직접 cast을 할 수 있습니다.

<a id="can-i-set-a-maximum-number-of-open-files-per-process"></a>

### 프로세스당 열린 파일 수에 상한을 두어도 되나요?

임의의 한계를 설정하지 않는 것이 좋습니다. 필요하다면 프로세스당 128개의 오픈 파일의 한계를 설정할 수 있습니다. 하지만 추가적인 요구사항을 적용하고 싶다면 제한이 없어야 합니다.

<a id="what-happens-when-an-open-file-is-removed"></a>

### 열려 있는 파일을 삭제하면 어떻게 되나요?

파일의 표준 유닉스 의미론을 구현해야 합니다. 즉, 파일이 삭제되면 해당 파일에 대한 파일 디스크립터를 가진 모든 프로세스는 해당 설명서를 계속 사용할 수 있습니다. 이것은 그들이 파일에서 읽고 쓸 수 있다는 것을 의미합니다. 파일에는 이름이 없으며 다른 프로세스가 열 수 없지만 파일에 관한 모든 파일 디스크립터가 닫히거나 기계가 닫을 때까지 계속 존재할 것입니다.

<a id="how-can-i-run-user-programs-that-need-more-than-4-kb-stack-space"></a>

### 스택 공간이 4 kB보다 많이 필요한 유저 프로그램은 어떻게 실행하나요?

각 프로세스에 대해 1 페이지 이상의 스택 공간을 할당하도록 스택 설정 코드를 수정할 수 있습니다. 다음 프로젝트에서는 더 나은 해결책을 구현할 것입니다.
