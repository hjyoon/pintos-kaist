> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project1/FAQ.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="faq"></a>

# FAQ

<a id="how-much-code-will-i-need-to-write"></a>

### 코드를 얼마나 작성해야 하나요?

다음은 `git diff --stat`로 집계한 reference solution의 변경량입니다. 마지막 행은 추가·삭제한 줄의 합계이며, 수정한 한 줄은 추가와 삭제에 각각 한 줄씩 포함됩니다. reference solution은 가능한 구현 중 하나일 뿐입니다. 이와 상당히 다른 구현도 가능하며, 같은 파일을 모두 수정하지 않거나 다른 파일을 수정하는 좋은 해법도 있습니다.

    devices/timer.c               |  29 +++++++++++++++++++++++++++++
    include/threads/fixed-point.h |  10 ++++++++++
    include/threads/synch.h       |   4 ++++
    include/threads/thread.h      |  21 +++++++++++++++++++++
    threads/synch.c               | 143 +++++++++++++++++++++++++++++++++++++++++++-
    threads/thread.c              | 135 ++++++++++++++++++++++++++++++++++++++++----
    6 files changed, 330 insertions(+), 12 deletions(-)

`fixed-point.h`는 reference solution에서 새로 추가한 파일입니다.

<a id="how-do-i-update-the-makefiles-when-i-add-a-new-source-file"></a>

### 새 소스를 추가하면 `Makefile`는 어떻게 수정하나요?

`.c` 파일을 추가하려면 해당 하위 directory의 `targets.mk`를 수정해 새 파일을 `dir_SRC` 변수에 추가하십시오. dir는 `targets.mk`가 있는 directory입니다. 그다음 make를 실행합니다. 새 파일이 컴파일되지 않으면 `make clean`을 실행한 뒤 다시 시도하십시오. `.h` 파일만 추가할 때는 `Makefile`를 수정할 필요가 없습니다.

<a id="what-does-warning-no-previous-prototype-for-func-mean"></a>

### warning: no previous prototype for `func`는 무슨 뜻인가요?

prototype 없이 non-static 함수를 정의했다는 뜻입니다. 다른 `.c` 파일에서도 사용하는 함수라면 정의 전에 포함하는 header에 prototype을 선언해야 안전합니다. 사용하는 header에 prototype을 추가하거나, 다른 `.c` 파일에서는 사용하지 않는 함수라면 static으로 선언하십시오.

<a id="what-is-the-interval-between-timer-interrupts"></a>

### Timer interrupt는 얼마나 자주 발생하나요?

timer interrupt는 초당 TIMER_FREQ번 발생합니다. `devices/timer.h`에서 값을 바꿀 수 있으며 기본값은 100 Hz입니다. 값을 변경하면 여러 테스트가 실패할 수 있으므로 변경하지 않는 것을 권장합니다.

<a id="how-long-is-a-time-slice"></a>

### Time slice는 얼마나 긴가요?

하나의 time slice는 `TIME_SLICE` ticks입니다. 이 macro는 `threads/thread.c`에 선언되어 있으며 기본값은 4 ticks입니다. 값을 변경하면 여러 테스트가 실패할 수 있으므로 변경하지 않는 것을 권장합니다.

<a id="how-do-i-run-the-tests"></a>

### 테스트는 어떻게 실행하나요?

[테스트](../introduction/grading.md#testing) 절을 참조하십시오.

<a id="why-do-i-get-a-test-failure-in-pass"></a>

### 왜 pass()에서 테스트가 실패하나요?

다음과 비슷한 backtrace를 보고 있을 수 있습니다.

    0x8004208810: debug_panic (lib/kernel/debug.c:32)
    0x800420a99f: pass (tests/threads/tests.c:93)
    0x800420bdd3: test_mlfqs_load_1 (...threads/mlfqs-load-1.c:33)
    0x800420a8cf: run_test (tests/threads/tests.c:51)
    0x8004200452: run_task (threads/init.c:283)
    0x8004200536: run_actions (threads/init.c:333)
    0x80042000bb: main (threads/init.c:137)

이는 backtrace 프로그램의 출력이 혼동을 주는 경우입니다. 실제로 `pass()`가 `debug_panic()`를 호출했다는 뜻은 아닙니다. 실제 호출은 `fail()`에서 `PANIC()` macro를 통해 `debug_panic()`로 이어집니다. `debug_panic()`는 `NO_RETURN`로 선언되어 반환하지 않는다는 것을 GCC가 알기 때문에, `fail()`에는 `debug_panic()`가 반환된 뒤 실행할 코드가 생성되지 않습니다. 그 결과 stack의 return address가 memory상 `fail()` 다음에 우연히 배치된 `pass()`의 시작을 가리키는 것처럼 보입니다. [Backtraces](../appendix/debugging_tools.md#backtraces)를 참조하십시오.

<a id="how-do-interrupts-get-re-enabled-in-the-new-thread-following-schedule"></a>

### schedule() 이후 새 thread에서는 interrupt가 어떻게 다시 켜지나요?

schedule()로 들어오는 모든 경로는 interrupt를 끕니다. interrupt는 다음에 scheduling된 thread가 다시 켭니다. 일반적으로 새로 실행되는 thread는 schedule()이 호출한 switch_thread() 안에서 이어서 실행됩니다. schedule()을 호출하는 경로는 다음과 같습니다. 단, 최초 실행은 아래의 예외를 보십시오.

- `thread_exit()`: 종료한 thread로 다시 전환하지 않으므로 고려할 필요가 없습니다.
- `thread_yield()`: schedule()에서 돌아오자마자 이전 interrupt level을 복원합니다.
- `thread_block()`: 다음 여러 위치에서 호출합니다.
  - `sema_down()`: schedule()에서 돌아오자마자 이전 interrupt level을 복원합니다.
  - `idle()`: assembly의 STI 명령으로 interrupt를 켭니다.
  - `devices/intq.c`의 `wait()`: 호출자가 interrupt를 다시 켤 책임이 있습니다.

새 thread가 처음 실행될 때는 예외입니다. 최초 thread를 제외한 모든 kernel thread의 call stack 맨 아래에는 `kernel_thread()`가 있고, 이 함수가 가장 먼저 `intr_enable()`를 호출합니다.

<a id="do-i-need-to-account-for-timer-values-overflowing"></a>

### Timer 값의 overflow를 처리해야 하나요?

timer 값은 signed 64-bit 정수입니다. 초당 100 ticks 기준으로 약 2,924,712,087년 동안 사용할 수 있으므로 overflow는 걱정하지 않아도 됩니다.

<a id="doesnt-priority-scheduling-lead-to-starvation"></a>

### Priority scheduling은 starvation을 일으키지 않나요?

그렇습니다. strict priority scheduling에서는 더 높은 priority의 runnable thread가 하나라도 있으면 낮은 thread가 실행되지 못해 starvation이 생길 수 있습니다. advanced scheduler는 priority를 동적으로 조절하는 방법을 도입합니다. strict priority scheduling은 어떤 작업에 CPU 시간을 줄지 프로그래머가 더 직접 제어할 수 있어 real-time system에 유용합니다. 높은 priority는 보통 시간 제약이 중요한 작업에 사용합니다. 공정한 방식은 아니지만 범용 운영체제와는 다른 요구를 충족합니다.

<a id="what-thread-should-run-after-a-lock-has-been-released"></a>

### Lock을 해제한 뒤에는 어떤 thread를 실행해야 하나요?

그 lock을 기다리는 thread 중 priority가 가장 높은 thread를 unblock하고 ready list에 넣어야 합니다. 그 뒤 scheduler는 ready list 전체에서 priority가 가장 높은 thread를 실행합니다.

<a id="if-the-highest-priority-thread-yields-does-it-continue-running"></a>

### 최고 priority thread가 yield하면 계속 실행되나요?

그렇습니다. 최고 priority thread가 하나뿐이면 `thread_yield()`를 호출해도 block되거나 종료될 때까지 계속 실행합니다. 같은 최고 priority의 thread가 여러 개라면 `thread_yield()`가 round-robin 순서로 전환해야 합니다.

<a id="what-happens-to-the-priority-of-a-donating-thread"></a>

### Donation하는 thread 자신의 priority는 어떻게 되나요?

priority donation은 받는 쪽의 priority만 변경합니다. 주는 쪽의 priority는 바뀌지 않습니다. donation은 덧셈도 아닙니다. priority 5인 A가 priority 3인 B에 donate하면 B의 새 priority는 8이 아니라 5입니다.

<a id="can-a-threads-priority-change-while-it-is-on-the-ready-queue"></a>

### Ready queue에 있는 thread의 priority도 바뀔 수 있나요?

그렇습니다. lock을 보유한 낮은 priority의 L이 ready 상태라고 합시다. 높은 priority의 H가 그 lock을 획득하려다 block되면 ready 상태의 L에 priority를 donate합니다.

<a id="can-a-threads-priority-change-while-it-is-blocked"></a>

### Blocked thread의 priority도 바뀔 수 있나요?

그렇습니다. lock L을 보유한 thread가 어떤 이유로 block된 상태라도, 더 높은 priority의 thread가 L을 획득하려 하면 donation으로 priority가 올라갈 수 있습니다. priority-donate-sema 테스트가 이 경우를 검사합니다.

<a id="can-a-thread-added-to-the-ready-list-preempt-the-processor"></a>

### Ready list에 추가된 thread가 현재 thread를 preempt할 수 있나요?

그렇습니다. 새 thread의 priority가 실행 중인 thread보다 높으면 즉시 CPU를 양보해야 합니다. 다음 timer interrupt까지 기다리는 것은 허용되지 않습니다. 최고 priority thread는 runnable이 되는 즉시 현재 thread를 preempt하고 실행되어야 합니다.

<a id="how-does-threadsetpriority-affect-a-thread-receiving-donations"></a>

### `thread_set_priority()`는 donation을 받는 thread에 어떤 영향을 주나요?

thread의 base priority를 설정합니다. effective priority는 새 base priority와 donate받은 priority 중 가장 높은 값이 됩니다. donation이 모두 해제되면 함수 호출로 설정한 base priority를 사용합니다. priority-donate-lower 테스트가 이 동작을 검사합니다.

<a id="doubled-test-names-in-output-make-them-fail"></a>

### 출력에 테스트 이름이 중복되어 테스트가 실패합니다.

다음처럼 테스트 이름이 겹쳐 보일 수 있습니다.

    (alarm-priority) begin
    (alarm-priority) (alarm-priority) Thread priority 30 woke up.
    Thread priority 29 woke up.
    (alarm-priority) Thread priority 28 woke up.

두 thread의 출력이 interleave된 것입니다. 한 thread가 `(alarm-priority) Thread priority 29 woke up.\n`를 출력하는 중에 다른 thread에 preempt되어, 다른 thread의 `(alarm-priority) Thread priority 30 woke up.\n` 출력이 끼어든 것입니다. 이는 priority scheduler의 버그를 뜻합니다. priority 30인 thread에 할 일이 있는데 priority 29인 thread가 실행되어서는 안 되기 때문입니다. kernel의 `printf()`는 보통 호출 동안 console lock을 보유해 이런 출력 섞임을 방지합니다. 그러나 `(alarm-priority)` 같은 테스트 이름과 그 뒤의 메시지는 두 번의 printf 호출로 출력하므로 console lock도 두 번 획득·해제됩니다.

<a id="how-does-priority-donation-interact-with-the-advanced-scheduler"></a>

### Priority donation과 advanced scheduler는 어떻게 함께 동작하나요?

함께 동작하도록 구현할 필요가 없습니다. 둘을 동시에 테스트하지 않습니다.

<a id="can-i-use-one-queue-instead-of-64-queues"></a>

### Queue 64개 대신 하나만 사용해도 되나요?

그렇습니다. 전반적으로 구현 방식이 설명과 달라도 관찰되는 동작이 같으면 됩니다.

<a id="some-scheduler-tests-fail-and-i-dont-understand-why-help"></a>

### 이유를 알 수 없는 scheduler 테스트 실패가 발생합니다.

advanced scheduler 테스트가 예상과 다르게 실패하면 다음을 확인하십시오.

- 실패한 테스트의 소스를 읽고 의도와 동작을 이해했는지 확인하십시오. 각 파일 맨 위의 주석에 목적과 예상 결과가 설명되어 있습니다.
- fixed-point arithmetic 함수와 scheduler 안에서의 사용 방법을 다시 확인하십시오.
- timer interrupt handler에서 수행하는 작업량을 살펴보십시오. handler가 너무 오래 실행되면 preempt된 thread는 한 timer tick의 대부분을 빼앗깁니다. 돌아온 뒤 조금 일하다가 다시 interrupt를 맞게 되므로 실제 사용한 시간보다 많은 CPU 시간을 사용한 것으로 집계될 수 있습니다. 그 결과 recent_cpu가 증가하고 priority가 낮아져 scheduling 결정이 달라지며, load average도 올라갑니다.
