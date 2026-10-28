# 브랜치·테스트·debugging 작업 방법

[온보딩 목차](README.md) · 이전: [Project 4](06-project4.md)

## 지금 어떤 코드를 보고 있는지 먼저 확인한다

저장소 루트에서 다음 명령을 사용한다.

```bash
git status --short --branch
git log -1 --oneline
git branch --show-current
```

최상위 directory 이름은 같아도 브랜치에 따라 구현과 `Make.vars`가 다르다. 별도의 worktree를 사용하는 경우에는 각 directory에서 현재 브랜치와 PATH를 확인한다.

```bash
source ./activate
command -v pintos
```

## 이 저장소의 단계별 브랜치

기준일은 2026-10-28이다. 다음 목록은 이미 작업한 구현을 찾아보기 위한 지도다. 직접 구현할 학습 브랜치는 `study/...`처럼 별도의 이름으로 만들면 기존 결과와 구분하기 쉽다.

| 단계 | 기존 브랜치 |
| --- | --- |
| 최초 baseline | `skeleton` |
| Alarm Clock | `project1/alarm_clock` |
| 기본 priority 순서 | `project1/alarm_clock_priority` |
| preemption | `project1/priority_check_preemption` |
| semaphore waiter | `project1/priority_sema` |
| condition variable waiter | `project1/priority_condvar` |
| priority donation | `project1/priority_donate` |
| MLFQS | `project1/mlfqs` |
| argument passing | `project2/argument_passing` |
| user memory 검증 | `project2/user_memory_access` |
| system calls | `project2/system_calls` |
| termination message 보완 | `project2/process_termination` |
| dup2 extra | `project2/dup` |
| VM 관리 기반 | `project3/mmemory_management` |
| stack growth | `project3/stack_growth` |
| swapping | `project3/swapping` |
| memory-mapped files | `project3/memory_mapped_files` |
| anonymous page·lazy loading 보완 | `project3/anonymous_page` |
| COW extra | `project3/copy_on_write` |
| FAT | `project4/fat` |
| buffer cache | `project4/buffer_cache` |
| file growth | `project4/file_growth` |
| path resolution | `project4/path_resolution` |
| subdirectories | `project4/subdirectories` |
| symbolic links | `project4/symbolic_links` |
| synchronization·통합 | `project4/synchronization` |
| 통합한 결과 | `master` |

VM 관리 브랜치의 실제 이름은 오타를 포함한 **`mmemory_management`**다. `memory_management`로 입력하면 기존 브랜치를 찾을 수 없다.

기존 브랜치는 구현 시점의 checkpoint이며 이름에 적힌 기능만 포함하는 것은 아니다. 예를 들어 VM의 기능들은 초기화·fault·fork·cleanup을 공유한다. 앞 단계에 기반 코드가 들어가고 뒤 단계에서 보완되기도 한다. 이 목록은 구현 차이를 찾아보기 위한 지도이며, 학습할 때 반드시 똑같이 나눠야 하는 규칙은 아니다.

## 작은 변경부터 비교한다

Alarm Clock의 차이는 다음처럼 볼 수 있다.

```bash
git diff skeleton..project1/alarm_clock -- \
  devices/timer.c threads/thread.c include/threads/thread.h
```

이는 두 브랜치의 끝 commit에 있는 내용을 비교하는 명령이다. 다음 단계의 변경을 읽을 때는 먼저 변화량을 확인한다.

```bash
git diff --stat project1/alarm_clock..project1/alarm_clock_priority
git log --oneline --max-count=8 project1/alarm_clock_priority
```

최종 `master`와 baseline을 비교하면 변경량이 많다. 처음에는 관심 있는 파일이나 가까운 단계로 범위를 좁힌다.

자신의 구현에서는 동작하는 단계를 commit한 뒤 다음 브랜치를 만들면 비교하기 쉽다.

```bash
git switch -c study/priority
```

이 명령은 **현재 commit에서** 브랜치를 만든다. commit하지 않은 변경이 자동으로 이력에 기록되는 것은 아니므로, 앞 단계를 먼저 commit한다.

## 빌드와 테스트를 나누어 확인한다

| 단계 | 확인하는 것 |
| --- | --- |
| `make` | compiler·linker가 kernel image를 만들 수 있는가? |
| `pintos ...` | kernel이 부팅하고 지정한 작업을 실행하는가? |
| `make ...result` | 출력이 해당 테스트의 판정 규칙을 만족하는가? |
| `make check` | 해당 구성의 테스트들을 모아 실행·판정한 결과는 무엇인가? |
| `make grade` | 지정된 grading file에 따라 집계한 점수는 얼마인가? |

`make`가 성공해도 미구현 system call이나 fault 처리가 올바르게 동작하는 것은 아니다. 가장 먼저 실패한 단계부터 원인을 좁힌다.

### 최신 상태라고 표시되면서 테스트가 다시 실행되지 않을 때

make는 timestamp를 이용해 필요한 작업을 판단한다. 같은 `.result`가 이미 있으면 실행을 생략할 수 있다.

Project 1의 예로, 저장된 결과를 테스트 하나만 다시 만들려면 `threads/build`에서 실행한다.

```bash
rm -f tests/threads/alarm-single.output \
      tests/threads/alarm-single.errors \
      tests/threads/alarm-single.result
make TIMEOUT=60 tests/threads/alarm-single.result
```

여기서 지우는 것은 생성된 로그와 판정 결과다. 소스 파일을 지우는 명령이 아니다.

브랜치, 빌드 옵션, 공통 구조체를 크게 바꿨다면 보관할 로그를 먼저 옮기고 저장소 루트에서 다시 빌드한다.

```bash
make -C threads clean
make -C threads -j2
```

이 `clean`은 `threads/build`를 삭제한다. Project 2~4에서는 대상을 `userprog`·`vm`·`filesys`로 바꾼다. target 이름은 **`clean`**이며 `clear`가 아니다.

### 전체 테스트

구현 단계에 맞는 `build` directory에서 실행한다.

```bash
make check
make grade
```

먼저 테스트 하나의 출력을 확인하고 이후 범위를 넓힌다. file system 테스트에는 임시 disk 이름을 공유하는 recipe가 있으므로 여기에는 `-j`를 붙이지 않는다. kernel의 병렬 빌드와 구분한다.

## extra 테스트는 설정을 확인한다

`userprog/Make.vars`에서 dup2 extra는 초기 상태에 비활성화되어 있다. dup2를 테스트할 학습 worktree에서 아래 세 줄의 주석을 해제한다.

```make
TDEFINE := -DEXTRA2
TEST_SUBDIRS += tests/userprog/dup2
GRADING_FILE = $(SRCDIR)/tests/userprog/Grading.extra
```

변경 후 저장소 루트에서 clean·build한 뒤 실행한다.

```bash
make -C userprog clean
make -C userprog -j2
make -C userprog/build TIMEOUT=60 tests/userprog/dup2/dup2-complex.result
```

이 변경은 테스트 대상도 바꾼다. 아직 일반 Project 2를 진행하는 단계라면 extra의 실패를 분리해서 판단한다.

`vm/Make.vars`는 COW 테스트를 포함한다. 현재 `master`의 `filesys/Make.vars`는 VM과 buffer-cache 테스트도 활성화한다. `make check`의 범위는 **그 브랜치의 Make.vars**에서 확인한다.

## 오류를 구분해서 읽는다

| 증상 | 먼저 확인할 것 |
| --- | --- |
| `pintos: command not found` | 올바른 저장소에서 source했는가? `command -v pintos`는 어디를 가리키는가? |
| `qemu-system-x86_64`를 찾지 못함 | host의 QEMU 설치와 PATH |
| `os.dsk cannot be temporal.` | kernel을 빌드했는가? 현재 위치가 해당 `build`인가? |
| compiler error / undefined reference | 첫 오류, header 선언, 함수 정의, 빌드 대상 |
| `Kernel PANIC` / assertion failure | `.output`의 첫 panic, 파일·줄 번호, call stack |
| page fault | fault address, user/kernel, read/write, mapping과 권한 |
| `TIMEOUT` | sleep 후 wake-up 누락, wait, lock 순서, 무한 loop. 필요하면 제한 시간도 확인 |
| `.result`가 FAIL | `.output`·`.errors`, 해당 `.c`·`.ck`, 아직 구현하지 않은 의존 기능 |

`.result`를 만드는 make가 끝났다는 것만으로 PASS라고 판단하지 않는다. 파일 안의 `PASS` / `FAIL`을 읽는다.

## printf와 GDB를 사용하는 시점

처음에는 적은 수의 `printf()`로 어디까지 실행했는지 확인해도 좋다. 다만 scheduler나 interrupt 안에서 대량 출력하면 timing이 바뀌어 원래 문제가 잘 보이지 않을 수 있다. 출력 자체가 lock을 사용하는 점도 주의한다.

멈춰서 상태를 보려면 terminal 두 개를 사용한다. 두 terminal 모두 같은 학습 worktree의 `threads/build`로 이동한다.

terminal A:

```bash
pintos --gdb -- -q run alarm-single
```

`pintos`를 찾지 못하면 해당 terminal에서도 먼저 저장소 루트의 activate를 source한다.

terminal B:

```bash
gdb kernel.o
```

GDB 안에서 실행한다.

```gdb
target remote localhost:1234
break timer_sleep
continue
next
bt
info args
```

이 실행 도구에서 QEMU의 GDB port는 1234다. 먼저 자신의 kernel의 `timer_sleep()`에서 멈추는지 확인한다. 함수 시작에서 멈춘 직후에는 argument가 아직 local 위치에 저장되지 않았을 수 있으므로 `next`로 본문에 들어간 뒤 값을 확인한다. 이후 `next`, `step`, `print` 등으로 상태를 살펴본다. 멈춰 조사하는 시간은 일반 실행보다 길어지므로 이 예에는 실행 제한 시간을 붙이지 않았다.

## commit 전에 확인한다

저장소 루트에서 차이를 확인한다.

```bash
git diff --check
git diff --stat
git status --short
```

학습 구현에서는 바꾼 `.c`·`.h` 등 필요한 소스를 명시해 stage한다. 이 저장소는 추가 테스트나 script를 구현 commit에 넣지 않고, 생성물인 `build/`도 넣지 않는 방침으로 진행해 왔다.

Alarm Clock에서 실제로 해당 세 파일을 바꿨을 때의 예다.

```bash
git add devices/timer.c threads/thread.c include/threads/thread.h
git diff --cached
git commit -m "Implement blocking alarm sleep"
```

실패한 테스트 이름, 원인, 바꾼 상태, 다시 확인한 결과를 짧게 기록하면 다음 단계에서 문제가 생겼을 때 찾아보기 쉽다.
