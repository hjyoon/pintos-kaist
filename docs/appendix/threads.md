> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/threads.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="threads"></a>

# Threads

<a id="struct-thread"></a>

## `struct thread`

Pintos에서 thread를 나타내는 주요 자료구조는 `threads/thread.h`의 `struct thread`입니다.

------------------------------------------------------------------------

```
struct thread;
```

thread 또는 user process를 나타냅니다. 프로젝트를 진행하면서 `struct thread`에 member를 추가해야 하며, 기존 member를 변경하거나 삭제해도 됩니다. 각 `struct thread`는 자신에게 할당된 memory page의 시작 부분을 차지합니다. 나머지는 page 끝에서 낮은 주소 방향으로 자라는 thread stack에 사용합니다.

                          4 kB +---------------------------------+
                               |         kernel stack            |
                               |               |                 |
                               |               |                 |
                               |               V                 |
                               |        grows downward           |
                               |                                 |
                               |                                 |
                               |                                 |
                               |                                 |
                               |                                 |
                               |                                 |
                               |                                 |
                               |                                 |
        sizeof (struct thread) +---------------------------------+
                               |             magic               |
                               |          intr_frame             |
                               |               :                 |
                               |               :                 |
                               |             status              |
                               |              tid                |
                          0 kB +---------------------------------+

따라서 두 가지를 주의해야 합니다. 첫째, `struct thread`가 너무 커지면 kernel stack 공간이 부족해집니다. 기본 `struct thread`는 작으며, 확장하더라도 1 kB보다 충분히 작게 유지하는 것이 좋습니다. 둘째, kernel stack도 너무 커져서는 안 됩니다. overflow하면 thread 상태를 덮어씁니다. 큰 구조체나 배열을 non-static local variable로 할당하지 말고 `malloc()`나 `palloc_get_page()`를 이용하십시오. [Memory Allocation](memory_allocation.md)을 참조하십시오.

------------------------------------------------------------------------

```
tid_t tid;
```

> thread identifier, 즉 tid입니다. kernel의 전체 실행 기간 동안 고유해야 합니다. 기본 `tid_t`는 `int`의 `typedef`이며, 최초 process의 1부터 새 thread마다 순서대로 증가합니다. type이나 번호 배정 방식을 바꿔도 됩니다.

------------------------------------------------------------------------

```
enum thread_status status;
```

> thread의 상태로, 다음 중 하나입니다.
>
> - `THREAD_RUNNING`
>
>   현재 실행 중입니다. 한 순간에 실행 중인 thread는 정확히 하나이며, `thread_current()`가 그 thread를 반환합니다.
>
> - `THREAD_READY`
>
>   실행할 준비는 되었지만 지금 실행 중은 아닙니다. 다음 scheduling에서 선택될 수 있습니다. ready thread는 `ready_list`라는 doubly linked list에 보관합니다.
>
> - `THREAD_BLOCKED`
>
>   lock이나 interrupt 등 어떤 사건을 기다립니다. `thread_unblock()`로 `THREAD_READY` 상태가 되기 전까지는 scheduling되지 않습니다. 보통 직접 다루기보다 thread를 자동으로 block·unblock하는 [Synchronization](synchronization.md) primitive를 사용하는 편이 좋습니다. 상태값만으로 무엇을 기다리는지 알 수는 없지만 [Backtraces](debugging_tools.md#backtraces)가 도움이 됩니다.
>
> - `THREAD_DYING`
>
>   다음 thread로 전환한 뒤 scheduler가 이 thread를 정리합니다.

------------------------------------------------------------------------

```
char name[16];
```

> thread 이름의 문자열입니다. 이름이 길면 앞부분만 보관할 수도 있습니다.

------------------------------------------------------------------------

```
struct intr_frame tf;
```

> register와 stack pointer 등 context switch에 필요한 정보를 저장합니다.

------------------------------------------------------------------------

```
int priority;
```

> priority는 `PRI_MIN`(0)부터 `PRI_MAX`(63)까지입니다. 숫자가 작을수록 낮아 0이 최저, 63이 최고입니다. 기본 Pintos는 priority를 무시하지만 Project 1에서 [Priority Scheduling](../project1/priority_scheduling.md)을 구현합니다.

------------------------------------------------------------------------

```
struct list_elem elem;
```

> thread를 doubly linked list에 넣기 위한 list element입니다. `ready_list` ready list 또는 `sema_down()`의 semaphore waiters list에 사용합니다. semaphore를 기다리는 thread는 ready가 아니고 그 반대도 마찬가지이므로 하나의 member를 두 용도로 쓸 수 있습니다.

------------------------------------------------------------------------

```
uint64_t *pml4;
```

> Project 2 이후에만 있습니다. [Page Tables](page_table.md)를 참조하십시오.

------------------------------------------------------------------------

```
unsigned magic
```

> 항상 `threads/thread.c`에 정의된 임의의 상수 `THREAD_MAGIC`로 설정하며 stack overflow를 감지하는 데 사용합니다. `thread_current()`는 현재 thread의 `struct thread`에 있는 `magic` 값이 `THREAD_MAGIC`인지 확인합니다. overflow가 이 값을 덮어쓰면 assertion이 실패합니다. `struct thread`에 member를 추가할 때도 `magic`를 맨 끝에 두면 효과적입니다.

<a id="thread-functions"></a>

## Thread 함수

`threads/thread.c`는 thread 관련 public 함수를 제공합니다. 주요 함수는 다음과 같습니다.

------------------------------------------------------------------------

```
void thread_init (void);
```

> `main()`이 호출해 thread system을 초기화합니다. 주된 목적은 최초 thread의 `struct thread`를 만드는 것입니다. loader가 최초 stack을 다른 thread와 마찬가지로 page의 높은 주소 쪽에 두기 때문에 가능합니다.
>
> `thread_init()` 전에는 현재 thread의 `magic` 값이 올바르지 않아 `thread_current()`가 실패합니다. lock을 획득하는 `lock_acquire()` 등 여러 함수가 직접·간접적으로 `thread_current()`를 호출하므로 `thread_init()`는 초기화 초기에 실행합니다.

------------------------------------------------------------------------

```
void thread_start (void);
```

> `main()`이 호출해 scheduler를 시작합니다. 실행 가능한 다른 thread가 없을 때 사용할 idle thread를 만들고 interrupt를 켭니다. timer interrupt 반환 경로의 `intr_yield_on_return()`에서 scheduling이 이루어지므로 interrupt 활성화는 scheduler도 동작시키는 효과가 있습니다.

------------------------------------------------------------------------

```
void thread_tick (void);
```

> 매 timer tick마다 interrupt handler가 호출합니다. thread 통계를 갱신하고 time slice가 끝나면 scheduling을 요청합니다.

------------------------------------------------------------------------

```
void thread_print_stats (void);
```

> Pintos 종료 시 thread 통계를 출력합니다.

------------------------------------------------------------------------

```
tid_t thread_create (const char *name, int priority, thread func *func, void *aux);
```

> name이라는 이름과 주어진 priority의 thread를 생성·시작하고 tid를 반환합니다. 새 thread는 단일 argument aux로 func를 실행합니다.
>
> `thread_create()`는 `struct thread`와 stack용 page를 할당하고 member를 초기화한 뒤, 최초 실행을 위한 가짜 stack frame들을 준비합니다. thread는 처음에는 blocked 상태이며 반환 직전에 unblock하여 scheduling 가능하게 합니다.

------------------------------------------------------------------------

```
void thread_func (void *aux);
```

> `thread_create()`에 전달할 함수의 type입니다. aux가 이 함수의 argument로 전달됩니다.

------------------------------------------------------------------------

```
void thread_block (void);
```

> 현재 thread를 running에서 blocked로 바꿉니다. 이후 누군가 `thread_unblock()`를 호출해야 다시 실행되므로, 깨우는 경로를 반드시 마련해야 합니다. `thread_block()`는 low-level 함수이므로 보통 [Synchronization](synchronization.md) primitive를 사용하는 것이 좋습니다.

------------------------------------------------------------------------

```
void thread_unblock (struct thread *thread);
```

> blocked 상태인 thread를 ready로 바꿔 다시 실행될 수 있게 합니다. 기다리던 lock이 풀리는 등 필요한 event가 발생했을 때 호출합니다.

------------------------------------------------------------------------

```
struct thread *thread_current (void);
```

> 현재 실행 중인 thread를 반환합니다.

------------------------------------------------------------------------

```
tid_t thread_tid (void);
```

> 현재 thread의 tid를 반환합니다. `thread_current ()->tid`와 같습니다.

------------------------------------------------------------------------

```
const char *thread_name (void);
```

> 현재 thread의 이름을 반환합니다. `thread_current ()->name`와 같습니다.

------------------------------------------------------------------------

```
void thread_exit (void) NO_RETURN;
```

> 현재 thread를 종료합니다. 반환하지 않습니다.

------------------------------------------------------------------------

```
void thread_yield (void);
```

> CPU를 scheduler에 양보해 실행할 thread를 다시 고르게 합니다. 현재 thread가 다시 선택될 수도 있으므로, 이 함수를 호출했다고 일정 시간 실행되지 않는다고 가정해서는 안 됩니다.

------------------------------------------------------------------------

```
int thread_get_priority (void);
void thread_set_priority (int new_priority);
```

> priority를 설정·조회하는 stub입니다. [Priority Scheduling](../project1/priority_scheduling.md)을 참조하십시오.

------------------------------------------------------------------------

```
int thread_get_nice (void);
void thread_set_nice (int new_nice);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);
```

> advanced scheduler용 stub입니다.
