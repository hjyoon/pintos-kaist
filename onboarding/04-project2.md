# Project 2: User Program이 kernel을 사용하게 만들기

[온보딩 목차](README.md) · 이전: [Project 1](03-project1.md) · 다음: [Project 3](05-project3.md)

## Project 1과 무엇이 달라지나?

Project 1의 테스트는 kernel 내부 함수였다. Project 2부터는 별도의 user program이 실행된다. user program은 kernel의 내부 상태를 마음대로 바꿀 수 없고, 파일 읽기·출력·종료 등의 작업을 **system call로 요청**한다.

```text
user program의 printf()
  → user library의 write wrapper
  → syscall instruction
  → userprog/syscall-entry.S
  → syscall_handler()
  → kernel이 출력 처리
  → 반환값을 user program에 전달
```

Pintos용 user program은 host Linux의 일반 실행 파일과 다르다. 제공된 C library와 빌드 규칙으로 만든 프로그램을 Pintos의 file system에 넣어 실행한다.

## baseline에서 제공된 부분과 남은 부분

| 위치 | 제공된 기반 | 구현할 동작 |
| --- | --- | --- |
| [userprog/process.c](../userprog/process.c) | ELF 검사·segment loading, 최소 stack, user mode 진입 | argument 배치, fork, wait, exec 전후 자원 관리, 종료 처리 |
| [userprog/syscall-entry.S](../userprog/syscall-entry.S) | system call 진입·복귀를 위한 assembly 경로 | 처음에는 경로와 전달되는 context를 이해 |
| [userprog/syscall.c](../userprog/syscall.c) | CPU의 system call 진입점 설정 | 호출 번호 판별, argument 검증, 각 요청 수행, 반환값 설정 |
| [userprog/exception.c](../userprog/exception.c) | exception 등록과 기본 종료 처리 | 잘못된 user 접근을 안전하게 처리하고 종료 경로 연결 |
| [threads/mmu.c](../threads/mmu.c) | hardware page table 생성·조회·변경 | Project 2의 mapping 검사와 fork 복사에 활용 |
| [filesys/file.c](../filesys/file.c) | file read/write, offset, deny-write 등의 함수 | process별 file descriptor와 lifetime 연결 |
| [lib/user/syscall.c](../lib/user/syscall.c) | user program이 호출하는 wrapper | 보통 wrapper보다 kernel 쪽 handler가 주 작업 대상 |

## 먼저 구분할 네 단어

| 용어 | 이 프로젝트에서의 의미 |
| --- | --- |
| `thread` | CPU가 실행하는 kernel의 실행 단위 |
| `process` | user program의 주소 공간·파일·종료 상태 등을 가진 실행 환경. 이 Pintos에서는 user process당 thread 하나 |
| `fork` | 현재 process를 복제해 child를 만든다 |
| `exec` | 현재 process의 실행 내용을 다른 executable로 바꾼다. 성공하면 이전 실행 흐름으로 돌아오지 않는다 |

`exec`가 새 child를 만든다고 생각하면 wait와 자원 정리 설계가 꼬인다. child 생성과 실행 내용 교체를 나눠 이해한다.

## 시작 순서

### 1. Argument Passing: 프로그램이 자기 argument를 읽게 한다

`process_exec()` → `load()` → `setup_stack()`의 흐름을 읽는다. 첫 단어는 실행할 파일 이름이고, 나머지는 프로그램의 argument다.

예를 들어 `echo hello`라면 다음 상태를 만들어야 한다.

```text
argc = 2
argv[0] → "echo"
argv[1] → "hello"
argv[2] = NULL
```

문자열, pointer 배열, alignment, register 값을 함께 준비한다. 실제 배치는 [Argument Passing](../docs/project2/argument_passing.md)의 표를 보면서 확인한다.

`process.c`의 `setup_stack()`는 baseline에서 stack page만 준비한다. argument가 자동으로 들어가는 것은 아니다. kernel에서 `hex_dump()`로 준비한 memory를 확인하면 user program이 출력할 수 없는 단계에도 조사할 수 있다.

### 2. User Memory: 넘겨받은 pointer를 바로 믿지 않는다

`write(fd, buffer, size)`가 요청되면 buffer는 user program이 정한 값이다. NULL, mapping이 없는 주소, kernel 주소, page 경계를 가로지르는 범위, 쓰기 권한이 없는 주소 등이 들어올 수 있다.

첫 주소 하나만 검사해서 끝내지 말고 **요청된 범위와 접근 방향**을 확인한다. read는 user buffer에 쓰는 작업이고, write는 user buffer에서 읽는 작업이다. 문자열은 끝의 null을 찾는 동안에도 잘못된 주소를 만날 수 있다.

오류가 나면 해당 process를 종료하거나 요구사항에 맞는 실패값을 반환한다. 이미 얻은 lock, 할당한 memory, 열린 파일의 정리 경로도 함께 설계해야 한다. kernel이 panic하면 다른 정상 process까지 영향을 받는다.

### 3. 최소 system call과 종료·대기 기반을 연결한다

system call 번호는 `include/lib/syscall-nr.h`, user용 원형은 `include/lib/user/syscall.h`에 있다. x86-64에서는 번호가 `rax`, argument가 `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`로 전달된다. handler는 받은 `struct intr_frame`에서 읽고 반환값도 그 context에 기록한다.

처음에는 console `write`, `exit`, 최초 process의 종료를 기다릴 수 있는 기반을 연결하면 실행 결과를 관찰하기 쉬워진다. 이후 file 관련 호출과 fork/exec/wait의 전체 의미를 완성한다.

**argument 테스트도 argument 배치만으로 PASS하지 않을 수 있다.** 테스트가 결과를 출력하고 종료하려면 write와 exit가 필요하고, kernel이 너무 일찍 끝나지 않도록 process 대기도 연결되어야 한다. 초기 FAIL을 곧바로 argument 배치 오류라고 단정하지 않는다.

### 4. File Descriptor: 정수 번호에 process의 열린 자원을 연결한다

```text
user program의 fd 번호
  → 해당 process의 descriptor 관리 구조
  → 열린 file object
  → inode와 실제 파일 데이터
```

같은 파일을 두 번 open한 경우와, extra의 dup2로 descriptor를 복제한 경우를 구분한다. 전자는 독립된 file offset을 가져야 하고 후자는 같은 open file description의 offset을 공유해야 한다.

기본 요구사항을 먼저 완성한 뒤 [dup2 extra](../docs/project2/dup.md)를 진행한다. extra에서는 stdin·stdout의 close와 재사용도 다룬다.

### 5. Process Lifetime: 누가 자원을 언제 해제하는가?

fork는 memory뿐 아니라 file descriptor 등의 상태도 복제한다. parent는 child의 복제 성공 여부를 확인한 뒤 반환해야 한다. wait는 직접적인 child에 대해 한 번만 성공해야 하며, child가 먼저 종료한 경우도 처리해야 한다.

다음 경우를 표로 써 보면 필요한 상태가 보인다.

| 먼저 일어난 일 | 나중에 필요한 정보 |
| --- | --- |
| child 종료 | parent의 wait가 읽을 exit status |
| parent 종료 | 남은 child가 접근하면 안 되는 parent의 해제된 상태 |
| fork 중간 실패 | 이미 복사한 자원의 정리와 parent에게 전할 실패 결과 |
| exec 성공 | 유지할 file descriptor와 새 주소 공간 |
| process 종료 | 파일·주소 공간·공유 상태의 마지막 참조 정리 |

Process Termination Message와 Deny Write on Executables도 함께 챙긴다. 실행 중인 executable은 쓰기로 내용이 바뀌지 않도록 보호해야 하며, 보호를 해제할 시점은 단순히 load 함수가 끝나는 순간이 아니다.

## 테스트와 실행

구현이 준비된 작업 directory의 루트에서 실행한다.

```bash
source ./activate
make -C userprog -j2
make -C userprog/build TIMEOUT=60 tests/userprog/args-single.result
```

`master`에서는 위 대표 테스트를 확인했다. 더 살펴볼 테스트는 `bad-read`, `read-boundary`, `wait-simple`, `fork-once`, `rox-simple` 등이다. test 이름과 `.c`·`.ck`를 함께 읽는다.

직접 실행할 때는 user program을 guest의 file system으로 복사해야 한다. 위 make target 실행 후 `userprog/build`에서 다음 예를 사용할 수 있다.

```bash
pintos -T 60 -m 20 --fs-disk=10 \
  -p tests/userprog/args-single:args-single \
  -- -q -f run 'args-single hello'
```

`-p` 앞쪽 파일은 host의 빌드 결과이고, colon 뒤는 guest에 넣을 이름이다. `--fs-disk=10`은 실행 도구가 임시 disk를 준비하게 하며, `-f`는 guest file system을 format한다. 이 명령은 기존 영구 disk 대신 임시 disk를 사용한다.

Project 2 전체 검증은 `userprog/build`에서 `make check`다. dup2 extra 테스트는 기본 설정에 포함되지 않는다. [작업 방법](07-workflow-and-debugging.md)의 extra 설정도 확인한다.
