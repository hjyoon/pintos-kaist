> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/synchronization.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="synchronization"></a>

# Synchronization

thread 사이의 자원 공유를 신중하게 제어하지 않으면 심각한 문제가 생깁니다. 특히 kernel에서는 잘못된 공유가 시스템 전체를 중단시킬 수 있습니다. Pintos는 이를 돕는 synchronization primitive들을 제공합니다.

<a id="disabling-interrupts"></a>

## Interrupt 비활성화

가장 단순한 synchronization 방법은 CPU가 interrupt에 응답하지 않도록 잠시 끄는 것입니다. 단일 CPU인 Pintos에서는 timer interrupt가 preemption을 일으키므로, interrupt를 끄면 다른 thread가 현재 thread를 preempt하지 못합니다. 평소처럼 켜져 있으면 C statement 사이뿐 아니라 하나의 statement를 실행하는 도중에도 preempt될 수 있습니다.

따라서 Pintos는 kernel thread도 언제든 preempt될 수 있는 preemptible kernel입니다. 전통적인 Unix의 nonpreemptible kernel은 kernel thread가 명시적으로 scheduler를 호출한 위치에서만 다른 thread로 전환했습니다. 두 방식 모두 user program은 언제든 preempt될 수 있습니다. preemptible kernel에서는 더 명시적인 synchronization이 필요합니다.

interrupt 상태를 직접 바꿔야 하는 경우는 많지 않습니다. 보통은 아래 primitive를 사용하십시오. 직접 끄는 주된 이유는 kernel thread와 external interrupt handler가 공유하는 데이터를 보호하기 위해서입니다. handler는 sleep할 수 없어 대부분의 다른 synchronization 방법을 사용할 수 없습니다.

interrupt를 꺼도 지연시킬 수 없는 external interrupt도 있습니다. **Non-maskable interrupt(NMI)**라고 하며, 심각한 hardware 이상 같은 긴급 상황에 사용합니다. 원문은 컴퓨터에 불이 난 경우를 예로 듭니다. Pintos는 NMI를 처리하지 않습니다.

관련 type과 함수는 `include/threads/interrupt.h`에 있습니다.

------------------------------------------------------------------------

```
enum intr_level;
```

> INTR_OFF 또는 INTR_ON으로, 각각 interrupt 비활성·활성 상태를 나타냅니다.

------------------------------------------------------------------------

```
enum intr_level intr_get_level (void)
```

> 현재 interrupt 상태를 반환합니다.

------------------------------------------------------------------------

```
enum intr_level intr_set_level (enum intr_level level);
```

> level에 따라 interrupt를 켜거나 끄고 이전 상태를 반환합니다.

------------------------------------------------------------------------

```
enum intr_level intr_enable (void);
```

> interrupt를 켜고 이전 상태를 반환합니다.

------------------------------------------------------------------------

```
enum intr_level intr_disable (void);
```

> interrupt를 끄고 이전 상태를 반환합니다.

<a id="semaphores"></a>

## Semaphore

semaphore는 음이 아닌 정수 값과 이를 atomic하게 조작하는 두 operation으로 구성됩니다.

- Down 또는 P: 값이 양수가 될 때까지 기다린 뒤 1 감소시킵니다.
- Up 또는 V: 값을 1 증가시키고, 기다리는 thread가 있으면 하나를 깨웁니다.

0으로 초기화한 semaphore는 한 번 발생할 event를 기다리는 데 사용할 수 있습니다. A가 B를 시작하고 특정 작업의 완료를 기다리려면, 0인 semaphore를 B에 전달하고 down합니다. B는 작업이 끝나면 up합니다. A의 down과 B의 up 중 어느 쪽이 먼저 실행되어도 올바르게 동작합니다.

예를 들면 다음과 같습니다.

```
struct semaphore sema;

/* Thread A */
void threadA (void) {
    sema_down (&sema);
}

/* Thread B */
void threadB (void) {
    sema_up (&sema);
}

/* main function */
void main (void) {
    sema_init (&sema, 0);
    thread_create ("threadA", PRI_MIN, threadA, NULL);
    thread_create ("threadB", PRI_MIN, threadB, NULL);
}
```

이 예제에서 threadA는 threadB가 `sema_up ()`를 호출할 때까지 `sema_down ()`에서 기다립니다.

1로 초기화한 semaphore는 보통 자원 접근을 제어하는 데 사용합니다. 사용 전에 down하고 끝나면 up합니다. 이런 용도에는 아래의 lock이 더 적절할 수 있습니다.

1보다 큰 값으로 초기화할 수도 있지만 자주 쓰이지는 않습니다. semaphore는 Edsger Dijkstra가 고안해 THE 운영체제에서 처음 사용했습니다. Pintos의 type과 operation은 `include/threads/synch.h`에 선언되어 있습니다.

------------------------------------------------------------------------

```
struct semaphore;
```

> semaphore를 나타냅니다.

------------------------------------------------------------------------

```
void sema_init (struct semaphore *sema, unsigned value);
```

> sema를 주어진 초기값의 semaphore로 초기화합니다.

------------------------------------------------------------------------

```
void sema_down (struct semaphore *sema);
```

sema에 down 또는 P operation을 수행합니다. 값이 양수가 될 때까지 기다린 뒤 1 감소시킵니다.

------------------------------------------------------------------------

```
bool sema_try_down (struct semaphore *sema);
```

> 기다리지 않고 down을 시도합니다. 값을 줄였으면 true, 이미 0이어서 줄이지 못했으면 false를 반환합니다. 짧은 loop에서 반복 호출하면 CPU 시간을 낭비하므로 `sema_down()`나 다른 방법을 사용하십시오.

------------------------------------------------------------------------

```
void sema_up (struct semaphore *sema);
```

> up 또는 V operation으로 값을 1 증가시킵니다. 기다리는 thread가 있으면 하나를 깨웁니다. 대부분의 다른 primitive와 달리 `sema_up()`는 external interrupt handler에서도 호출할 수 있습니다.

semaphore 내부는 [Interrupt 비활성화](synchronization.md#disabling-interrupts)와 thread의 block·unblock, 즉 `thread_block()`와 `thread_unblock()`로 구현됩니다. 각 semaphore는 `lib/kernel/list.c`의 linked list로 waiters를 관리합니다.

<a id="locks"></a>

## Lock

lock은 초기값이 1인 [Semaphore](synchronization.md#semaphores)와 비슷합니다. down에 해당하는 작업을 acquire, up에 해당하는 작업을 release라고 부릅니다.

추가 제약은 lock을 획득한 owner thread만 해제할 수 있다는 것입니다. 다른 thread가 해제해야 한다면 lock보다 semaphore가 적합하다는 신호입니다.

Pintos의 lock은 recursive하지 않습니다. 이미 보유한 lock을 같은 thread가 다시 acquire하면 오류입니다. type과 함수는 `include/threads/synch.h`에 있습니다.

------------------------------------------------------------------------

```
struct lock;
```

> lock을 나타냅니다.

------------------------------------------------------------------------

```
void lock_init (struct lock *lock);
```

> lock을 초기화합니다. 처음에는 어떤 thread도 보유하지 않습니다.

------------------------------------------------------------------------

```
void lock_acquire (struct lock *lock);
```

> 현재 thread를 위해 lock을 획득합니다. 다른 owner가 있으면 해제할 때까지 기다립니다.

------------------------------------------------------------------------

```
bool lock_try_acquire (struct lock *lock);
```

> 기다리지 않고 acquire를 시도합니다. 성공하면 true, 이미 보유 중이면 false를 반환합니다. 반복 호출로 CPU를 낭비하지 말고 `lock_acquire()`를 사용하십시오.

------------------------------------------------------------------------

```
void lock_release (struct lock *lock);
```

> 현재 thread가 보유한 lock을 해제합니다.

------------------------------------------------------------------------

```
bool lock_held_by_current_thread (const struct lock *lock):
```

> 현재 thread가 owner이면 true, 아니면 false를 반환합니다. 임의의 다른 thread가 owner인지 검사하는 함수는 없습니다. 검사 직후 상태가 바뀔 수 있어 그 결과만으로 안전하게 행동할 수 없기 때문입니다.

<a id="monitors"></a>

## Monitor

monitor는 semaphore나 lock보다 상위 수준의 synchronization 방식입니다. 보호할 데이터, monitor lock 하나, 하나 이상의 condition variable로 구성됩니다. thread는 데이터에 접근하기 전에 lock을 획득해 monitor에 진입합니다. 그 안에서는 보호된 데이터를 조회·수정할 수 있고 작업을 마치면 lock을 해제합니다.

condition variable은 monitor 안에서 특정 조건이 참이 될 때까지 기다리게 합니다. 예를 들어 처리할 데이터가 도착했다거나 마지막 key 입력 후 10초가 지났다는 조건입니다. wait하면 monitor lock을 놓고 signal을 기다립니다. 조건을 참으로 만든 쪽은 signal로 waiter 하나를 깨우거나 broadcast로 모두 깨웁니다.

monitor의 이론은 C. A. R. Hoare가 정리했고, 실용적인 사용법은 Mesa 운영체제 논문에서 발전했습니다. condition variable type과 함수는 `include/threads/synch.h`에 선언되어 있습니다.

------------------------------------------------------------------------

```
struct condition;
```

> condition variable을 나타냅니다.

------------------------------------------------------------------------

```
void cond_init (struct condition *cond);
```

> cond를 초기화합니다.

------------------------------------------------------------------------

```
void cond_wait (struct condition *cond, struct lock *lock);
```

> monitor lock을 atomic하게 해제하고 cond의 signal을 기다립니다. 깨어나면 lock을 다시 획득한 뒤 반환합니다. 호출 전에는 반드시 lock을 보유해야 합니다. signal을 보내는 것과 waiter가 실제로 실행되는 것은 하나의 atomic operation이 아니므로, 보통 `cond_wait()`의 호출자는 반환 후 조건을 다시 검사하고 필요하면 다시 기다려야 합니다. 다음 예제를 참조하십시오.

------------------------------------------------------------------------

```
void cond_signal (struct condition *cond, struct lock *lock);
```

> monitor lock으로 보호되는 cond에 waiter가 있으면 하나를 깨웁니다. 없으면 아무 작업도 하지 않습니다. 호출 전에는 lock을 보유해야 합니다.

------------------------------------------------------------------------

```
void cond_broadcast (struct condition *cond, struct lock *lock);
```

> cond의 모든 waiter를 깨웁니다. 호출 전에는 monitor lock을 보유해야 합니다.

<a id="monitor-example"></a>

### Monitor 예제

고전적인 예는 하나 이상의 producer thread가 문자를 쓰고 consumer thread가 읽는 buffer입니다. monitor lock 외에 `not_full`와 `not_empty`라는 두 condition variable이 필요합니다.

```
    char buf[BUF_SIZE];     /* Buffer. */
    size_t n = 0;         /* 0 <= n <= BUF SIZE: # of characters in buffer. */
    size_t head = 0;        /* buf index of next char to write (mod BUF SIZE). */
    size_t tail = 0;         /* buf index of next char to read (mod BUF SIZE). */
    struct lock lock;         /* Monitor lock. */
    struct condition not_empty; /* Signaled when the buffer is not empty. */
    struct condition not_full;     /* Signaled when the buffer is not full. */

    ...initialize the locks and condition variables...

    void put (char ch) {
      lock_acquire (&lock);
      while (n == BUF_SIZE)    /* Can't add to buf as long as it's full. */
        cond_wait (&not_full, &lock);
      buf[head++ % BUF_SIZE] = ch;    /* Add ch to buf. */
      n++;
      cond_signal (&not_empty, &lock);    /* buf can't be empty anymore. */
      lock_release (&lock);
    }

    char get (void) {
      char ch;
      lock_acquire (&lock);
      while (n == 0)        /* Can't read buf as long as it's empty. */
        cond_wait (&not_empty, &lock);
      ch = buf[tail++ % BUF_SIZE];    /* Get ch from buf. */
      n--;
      cond_signal (&not_full, &lock);    /* buf can't be full anymore. */
      lock_release (&lock);
    }
```

이 코드가 완전히 올바르려면 `BUF_SIZE`가 `SIZE_MAX + 1`의 약수여야 합니다. 그렇지 않으면 `head`가 처음 0으로 wraparound할 때 문제가 생깁니다. 보통 `BUF_SIZE`를 2의 거듭제곱으로 둡니다.

<a id="optimization-barriers"></a>

## Optimization Barrier

optimization barrier는 compiler가 barrier 전후의 memory 상태에 관한 가정을 바탕으로 최적화하지 못하게 하는 장치입니다. 변수의 읽기·쓰기를 barrier 너머로 재배치하거나, 값이 바뀌지 않았다고 가정하는 것을 막습니다. 다만 주소를 외부로 전달한 적 없는 local variable은 예외입니다. Pintos는 `include/threads/synch.h`의 `barrier()` macro로 제공합니다.

> **용어 주의:** 여기서 barrier는 compiler optimization barrier입니다. CPU memory fence나 thread 간 mutual exclusion을 대신한다는 뜻은 아닙니다.

다른 thread나 interrupt handler가 compiler 모르게 데이터를 비동기로 바꿀 수 있을 때 유용합니다. 예를 들어 `devices/timer.c`의 `too_many_loops()`는 다음 timer tick이 올 때까지 busy waiting하는 loop로 시작합니다.

```
    /* Wait for a timer tick. */
    int64_t start = ticks;
    while (ticks == start)
        barrier();
```

barrier가 없으면 compiler는 `start`와 `ticks`가 처음에 같고 loop 안에서 바뀌지 않으므로 끝나지 않는 loop라고 판단할 수 있습니다. 실제로 interrupt가 값을 바꿀 수 있다는 사실을 모른 채 무한 loop로 최적화하는 것을 막아야 합니다.

다른 최적화를 막는 데도 사용합니다. 같은 `devices/timer.c`에 있는 `busy_wait()`의 loop가 예입니다.

```
    while (loops-- > 0)
      barrier ();
```

이 loop는 처음 값부터 0까지 세며 busy waiting하려는 코드입니다. barrier가 없으면 출력이나 side effect가 없다고 판단해 loop 자체를 지울 수 있습니다. barrier는 compiler가 loop 본문에 중요한 효과가 있다고 간주하게 합니다.

memory 접근 순서를 유지하는 데도 사용합니다. timer interrupt가 올 때 전역 Boolean `timer_do_put`가 true이면 전역 문자 `timer_put_char`를 출력하는 기능을 추가한다고 합시다. `x`를 출력하도록 설정하려면 다음과 같이 barrier를 둘 수 있습니다.

```
    timer_put_char = 'x';
    barrier ();
    timer_do_put = true;
```

barrier가 없으면 compiler가 두 대입의 순서를 바꿀 수 있어 버그가 됩니다. compiler는 순서가 중요하다는 사실을 모르므로 서로 바꿔도 된다고 판단할 수 있습니다. 실제로 바꿀지는 알 수 없고, compiler 버전이나 최적화 옵션이 달라지면 결과도 달라질 수 있습니다.

다른 방법은 두 대입 동안 interrupt를 끄는 것입니다. 재배치 자체를 막지는 않지만 중간에 handler가 실행되는 것은 막습니다. 대신 interrupt를 끄고 다시 켜는 실행 비용이 듭니다.

```
    enum intr_level old_level = intr_disable ();
    timer_put_char = 'x';
    timer_do_put = true;
    intr_set_level (old_level);
```

`timer_put_char`와 `timer_do_put`를 `volatile`로 선언하는 방법도 생각할 수 있습니다. compiler에 외부에서 관찰되는 값임을 알리고 일부 최적화를 제한합니다. 하지만 `volatile`는 일반적인 synchronization 해법이 아니며 필요한 순서·동시성 보장을 대신하지 않습니다. 기본 Pintos는 `volatile`를 사용하지 않습니다.

다음처럼 lock만 사용하는 것은 해결책이 아닙니다. lock은 interrupt를 끄지 않고, lock을 보유한 구간 안에서 compiler가 대입 순서를 바꾸는 것도 막지 않기 때문입니다.

```
    lock_acquire (&timer_lock);        /* INCORRECT CODE */
    timer_put_char = 'x';
    timer_do_put = true;
    lock_release (&timer_lock);
```

다른 소스 파일에 정의된 외부 함수를 호출하면 compiler는 제한적인 optimization barrier처럼 취급합니다. 그 함수가 static·dynamic data와 주소를 전달한 local variable에 접근할 수 있다고 가정하기 때문입니다. 그래서 명시적 barrier가 생략될 수 있고 Pintos에 barrier가 많지 않은 이유이기도 합니다.

> **적용 범위:** 이 설명은 외부 함수의 내부를 compiler가 분석하지 않는 빌드 상황을 전제로 합니다. LTO 등으로 함수 내부를 볼 수 있는 경우까지 일반화해서는 안 됩니다.

같은 소스나 포함한 header에 정의된 함수는 optimization barrier라고 믿어서는 안 됩니다. 정의보다 앞에서 호출하더라도 compiler는 소스 전체를 읽고 최적화할 수 있으므로 마찬가지입니다.
