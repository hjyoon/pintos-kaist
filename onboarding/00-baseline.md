# 기본 제공 코드는 어디까지인가

[온보딩 목차](README.md) · 다음: [첫 빌드와 실행](01-first-run.md)

## Pintos에서 만드는 것은 무엇인가?

Pintos는 x86-64 환경에서 실행하는 교육용 OS다. 이 프로젝트에서는 Linux 위에서 돌아가는 일반 application을 만드는 것이 아니라, **QEMU 안에서 부팅하는 kernel의 동작을 확장**한다.

처음부터 OS 전체를 작성하지는 않는다. 부팅 코드, C 코드 실행 환경, 기본 thread, interrupt, memory allocator, disk 접근 등의 기반을 받는다. 그 위에 scheduling 정책, user program 지원, virtual memory, file system 기능을 순서대로 붙인다.

## 먼저 익숙해질 용어

| 용어 | 처음에는 이렇게 이해하면 된다 |
| --- | --- |
| kernel | CPU·memory·disk 같은 자원을 관리하고 프로그램의 요청을 처리하는 OS의 핵심 코드 |
| thread | 함수 호출을 이어 가며 실행되는 하나의 흐름. 기다리거나 다른 thread에 실행 순서를 넘길 수 있다 |
| scheduler | 실행 가능한 thread 중 다음에 CPU를 사용할 대상을 고르는 코드 |
| interrupt | timer나 장치의 사건 때문에 CPU가 하던 일을 잠시 멈추고 handler로 이동하는 경로 |
| synchronization | 공유 데이터에 접근하는 실행 흐름들이 서로의 상태를 깨뜨리지 않도록 조정하는 것 |
| system call | user program이 kernel에 작업을 요청하는 정해진 interface |

C의 함수 호출, pointer, `struct`와 member 접근, 동적 memory 할당을 읽을 수 있으면 시작하기 좋다. C 문법이 막히면 해당 함수에서 사용하는 문법부터 확인한다. OS의 모든 구조를 미리 아는 것보다 작은 실행 경로 하나를 따라가 보는 것이 첫 작업에 도움이 된다.

## 기본 코드도 이미 부팅하고 thread를 바꿀 수 있다

이 문서에서 baseline은 `skeleton`의 `49a7ed3`이다.

| 분야 | baseline에 실제로 있는 것 | 아직 구현해야 하는 것 |
| --- | --- | --- |
| 부팅 | `loader.S`, 초기 CPU 설정, `threads/init.c`의 `main()` | 보통 부팅 자체를 새로 작성하지 않는다 |
| 기본 thread | 생성·종료, ready list, block/unblock, context switch, time slice | 잠든 thread 관리, priority에 따른 선택·preemption |
| synchronization | semaphore, lock, condition variable의 기본 동작 | priority에 맞는 waiter 선택과 lock의 priority donation |
| timer | timer interrupt, tick 증가, `timer_ticks()` | busy waiting을 없앤 `timer_sleep()` |
| memory 기반 | page allocator, `malloc()`, hardware page table 조작 함수 | Project 3의 supplemental page table, frame 관리, swap 등 |
| user program 기반 | ELF를 읽는 loader, 최소 stack page, user mode 진입 코드 | argument 전달, 유효한 user memory 접근, process 자원·상태 관리 |
| system call 기반 | user용 wrapper, assembly 진입 코드, handler를 연결하는 초기 설정 | 번호별 실제 처리. 기본 handler는 메시지를 출력한 뒤 thread를 종료한다 |
| 기본 file system | Project 2에서 사용할 단순한 파일 읽기·쓰기·생성·삭제 | FAT 기반 확장, file growth, path와 subdirectory, cache, synchronization |
| 테스트 도구 | 테스트 소스, 실행 recipe, 판정용 `.ck` 파일 | 테스트가 요구하는 kernel 동작 |

"함수가 있다"와 "과제 요구사항을 만족한다"는 서로 다른 단계다. 다음 예제를 보면 차이가 분명해진다.

## 예 1: `timer_sleep()`는 있지만, 해야 할 일이 남아 있다

[devices/timer.c](../devices/timer.c)의 baseline 구현은 다음과 같다.

```c
void
timer_sleep (int64_t ticks) {
    int64_t start = timer_ticks ();

    ASSERT (intr_get_level () == INTR_ON);
    while (timer_elapsed (start) < ticks)
        thread_yield ();
}
```

시간은 기다리지만, 기다리는 thread가 계속 ready 상태로 돌아와 시간을 다시 확인한다. 이런 반복을 busy waiting이라고 한다. CPU를 잠깐 다른 thread에 양보해도 반복해서 실행 가능 상태가 되므로, Project 1의 Alarm Clock 요구사항은 충족하지 못한다.

직접 구현할 동작은 다음과 같다.

```text
sleep 요청 → 깨어날 tick 기록 → thread를 blocked로 전환
          → timer interrupt가 시각을 확인 → 시간이 된 thread를 ready로 전환
```

**baseline에서 `alarm-single`이 PASS해도 Alarm Clock 구현을 끝냈다는 뜻은 아니다.** 테스트의 결과와 별도로 busy waiting이 제거됐는지 코드로 확인해야 한다.

## 예 2: priority 값을 저장한다고 priority scheduling은 아니다

[threads/thread.c](../threads/thread.c)의 `thread_set_priority()`는 baseline에서 현재 thread의 숫자만 바꾼다. `next_thread_to_run()`은 ready list의 앞 원소를 고른다.

따라서 "priority를 바꿨으니 다음 실행 대상도 바뀌겠지"라고 가정하면 안 된다. ready thread의 선택, 높은 priority의 thread가 준비됐을 때의 preemption, waiters를 깨우는 순서를 함께 구현해야 한다.

## 예 3: user mode로 들어가는 경로는 있어도 application 지원은 미완성이다

[userprog/process.c](../userprog/process.c)에는 ELF header를 검사하고 segment를 읽는 코드가 있다. 하지만 argument를 stack과 register에 배치하는 부분, fork 자원 복제, wait, 종료 시 자원 관리 등은 남아 있다.

[userprog/syscall.c](../userprog/syscall.c)의 기본 handler는 다음처럼 동작한다.

```c
printf ("system call!\n");
thread_exit ();
```

따라서 C 프로그램에 있는 `printf()`나 `exit()`가 실제로 동작하려면 해당 system call도 구현해야 한다. ELF를 읽는 기능만으로 프로그램의 입출력과 종료까지 완성되지는 않는다.

## 예 4: 기본 file system과 Project 4의 file system은 단계가 다르다

Project 2는 제공된 단순한 file system을 이용한다. 이때 파일 크기는 고정되어 있고 데이터는 연속 영역에 배치되며, 이름 탐색도 root directory 중심이다.

Project 4에서는 같은 interface를 확장하면서 FAT chain, 파일 확장, path 탐색, subdirectory, symbolic link, cache 등을 구현한다. `filesys/fat.c`나 `filesys/page_cache.c`라는 파일이 baseline에 존재해도 그 기능이 완성된 것은 아니다.

## `TODO`만 찾아서 채우면 되나?

`TODO` 검색은 위치를 찾는 출발점으로는 좋다. 하지만 완료 여부를 판단하는 기준으로는 부족하다.

- `timer_sleep()`처럼 이미 동작하는 형태의 함수를 교체해야 하는 곳도 있다.
- priority scheduling처럼 여러 함수와 자료구조를 함께 바꿔야 하는 기능도 있다.
- 현재 `master`의 `process.c`에는 예전 argument passing `TODO` 주석이 남아 있지만, 실제 argument 설정은 `setup_arguments()`와 `process_exec()` 쪽에 구현되어 있다.

각 함수가 **입력으로 무엇을 받고, 어떤 상태를 바꾸며, 누구에게 제어를 넘기는지** 확인한다. 테스트와 실제 호출 흐름을 함께 읽어야 한다.

## baseline에 앞서 들어간 호환성 commit

| commit | 의미 |
| --- | --- |
| `463f7de` | Ubuntu 22.04 / GCC 11에서 사용할 수 있도록 호환성 조정 |
| `1d7d37a` | compiler 옵션에서 `-fcommon` 제거 |
| `49a7ed3` | 위 변경을 합친 merge. 이 저장소의 `skeleton` 기준 |

이 변경들이 있다고 해서 Alarm Clock이나 system call 등의 과제 구현이 완료된 것은 아니다. 빌드 환경을 맞춘 작업과 OS 기능 구현을 구분하면 시작점을 찾기 쉽다.

## 이제 어디서 시작하나?

첫 프로젝트는 [Project 1 안내](03-project1.md)의 Alarm Clock 순서로 시작한다. 아직 빌드·실행을 안 해 봤다면 먼저 [첫 빌드와 실행](01-first-run.md)을 따라간다. `loader.S`나 CPU의 모든 세부 동작을 이해한 뒤 시작할 필요는 없다.
