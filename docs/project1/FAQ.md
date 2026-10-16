> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project1/FAQ.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="faq"></a>

# 자주 묻는 질문

<a id="how-much-code-will-i-need-to-write"></a>

### 코드를 얼마나 작성해야 하나요?

다음은 `git diff --stat`에 의해 생산된 우리의 참조 솔루션의 요약입니다. 마지막 줄은 삽입 및 삭제된 전체 라인을 나타냅니다. 변경된 라인은 삽입과 삭제 모두로 간주됩니다. 참고 솔루션은 하나의 가능한 솔루션입니다. 또한 다른 많은 솔루션이 가능하며 그 중 많은 것이 참조 솔루션과 크게 다릅니다. 일부 우수한 솔루션은 참조 솔루션으로 수정된 모든 파일을 수정하지 않을 수도 있고, 일부에서는 참조 솔루션으로 수정되지 않은 파일을 수정할 수도 있습니다.

    devices/timer.c               |  29 +++++++++++++++++++++++++++++
    include/threads/fixed-point.h |  10 ++++++++++
    include/threads/synch.h       |   4 ++++
    include/threads/thread.h      |  21 +++++++++++++++++++++
    threads/synch.c               | 143 +++++++++++++++++++++++++++++++++++++++++++-
    threads/thread.c              | 135 ++++++++++++++++++++++++++++++++++++++++----
    6 files changed, 330 insertions(+), 12 deletions(-)

`fixed-point.h`는 참조 솔루션으로 추가된 새로운 파일입니다.

<a id="how-do-i-update-the-makefiles-when-i-add-a-new-source-file"></a>

### 새 소스 파일을 추가할 때 `Makefile`은 어떻게 수정하나요?

`.c` 파일을 추가하려면 각 하위 디렉터리에서 `targets.mk` 파일을 편집하십시오. 새로운 파일을 변수 `dir_SRC`에 추가하여 `targets.mk`이 있는 디렉터리입니다. 그럼 뛸 수 있어. 새 파일이 컴파일되지 않으면 `make clean`을 실행하고 다시 시도하십시오. 새로운 `.h` 파일이 `Makefile`s를 편집할 필요가 없습니다.

<a id="what-does-warning-no-previous-prototype-for-func-mean"></a>

### warning: no previous prototype for `func` 경고는 무슨 뜻인가요?

즉, 당신은 프로토타입으로 선행하지 않고 비정형 함수를 정의했습니다. 비정형 함수는 다른 `.c` 파일에서 사용하도록 되어 있기 때문에 안전성 때문에 그 함수는 정의 전에 포함된 헤더 파일에서 프로토타입되어야 합니다. 문제를 해결하기 위해 포함된 헤더 파일에 프로토타입을 추가하거나, 함수가 실제로 다른 `.c` 파일에 사용되지 않으면, 정적하도록하십시오.

<a id="what-is-the-interval-between-timer-interrupts"></a>

### 타이머 인터럽트의 발생 간격은 얼마인가요?

타이머 인터럽트는 1초에 TIMER_FREQ로 발생합니다. `devices/timer.h`를 편집하여 이 값을 조정할 수 있습니다. 기본은 100Hz입니다. 우리는 이 값을 변경하는 것을 권장하지 않습니다. 왜냐하면 어떤 변화는 많은 테스트가 실패할 가능성이 있기 때문입니다.

<a id="how-long-is-a-time-slice"></a>

### 타임 슬라이스는 얼마나 긴가요?

시간 단위로 `TIME_SLICE` 틱이 있습니다. 이 매크로는 `threads/thread.c`로 선언됩니다. 기본값은 4 틱입니다. 우리는 이 값을 변경하는 것을 권장하지 않습니다. 왜냐하면 어떤 변화는 많은 테스트가 실패할 가능성이 있기 때문입니다.

<a id="how-do-i-run-the-tests"></a>

### 테스트는 어떻게 실행하나요?

[시험](../introduction/grading.md#testing) 참조

<a id="why-do-i-get-a-test-failure-in-pass"></a>

### pass()에서 테스트가 실패하는 이유는 무엇인가요?

여러분들은 아마도 아래와 같은 백트랙을 보고 있을 것입니다.

    0x8004208810: debug_panic (lib/kernel/debug.c:32)
    0x800420a99f: pass (tests/threads/tests.c:93)
    0x800420bdd3: test_mlfqs_load_1 (...threads/mlfqs-load-1.c:33)
    0x800420a8cf: run_test (tests/threads/tests.c:51)
    0x8004200452: run_task (threads/init.c:283)
    0x8004200536: run_actions (threads/init.c:333)
    0x80042000bb: main (threads/init.c:137)

이것은 단지 배트트레이스 프로그램에서 혼란스러운 출력입니다. 이것은 실제로 `pass()`가 `debug_panic()`라고 불리는 것을 의미하지는 않습니다. 사실, `fail()`은 `debug_panic()` (`PANIC()` 매크로) 라고 불립니다. GCC는 `debug_panic()`이 반환되지 않는다는 것을 알고 있습니다. 왜냐하면 그것은 `NO_RETURN`로 선언되었기 때문에 `fail()`에 `debug_panic()`이 반환될 때 통제권을 취하기 위해 코드가 포함되어 있지 않습니다. 즉, 스택에 있는 반환 주소는 기억에서 `fail()`을 따르는 함수의 시작에 있는 것처럼 보입니다. 이 경우 `pass()`입니다. 자세한 내용은 [후퇴](FAQ.md) 문서를 참조하십시오.

<a id="how-do-interrupts-get-re-enabled-in-the-new-thread-following-schedule"></a>

### schedule() 뒤 새 스레드에서 인터럽트는 어떻게 다시 활성화되나요?

시간표의 모든 경로는 장애가 중단됩니다. 그들은 결국 다음 로드에서 재활성화됩니다 가능성에 대해 생각해보십시오: 새로운 스레드는 switch_thread() 로 실행됩니다 (하지만 아래를 참조하십시오), 이는 스케줄에 의해 호출됩니다(), 몇 가지 가능한 함수 중 하나에 의해 호출됩니다:

- `thread_exit()` 하지만 우리는 결코 그런 스레드에 다시 전환하지 않을 것입니다, 그래서 그것은 흥미롭지 않습니다.
- `thread_yield()`는 일정에서 돌아와 즉시 중단 수준을 회복합니다.
- 여러 곳에서 호출되는 `thread_block()`:
  - `sema_down()`는 일정에서 돌아와 즉시 중단 수준을 회복합니다.
  - `idle()`는 명시적인 집합 STI 명령으로 인터럽트를 가능하게 합니다.
  - `wait()`는 `devices/intq.c`에 있으며, 그 호출자가 중단을 재활성화하는 책임이 있습니다.

새로 만들어진 스레드가 처음으로 실행되는 특별한 경우도 있습니다. 이러한 스레드는 `intr_enable()`을 `kernel_thread()`의 첫 번째 동작으로 호출 스택의 하단에 있는 모든 커널 스레드, 첫 번째를 제외하고 호출 스택에 호출합니다.

<a id="do-i-need-to-account-for-timer-values-overflowing"></a>

### 타이머 값의 오버플로를 처리해야 하나요?

타이머 값이 넘어가기 때문에 걱정하지 마세요. 타이머 값은 서명된 64비트 숫자로 표현되며, 이 값은 초당 100점으로 거의 2,924,712,087년 동안 유효합니다.

<a id="doesnt-priority-scheduling-lead-to-starvation"></a>

### 우선순위 스케줄링은 기아를 유발하지 않나요?

예, 엄격한 우선순위 스케줄링은 굶주림으로 이어질 수 있습니다. 왜냐하면 더 높은 우선순위가 있는 스레드가 실행될 수 있다면 스레드가 실행되지 않을 것이기 때문입니다. 고급 스케줄러는 역동적으로 변화하는 스레드 우선순위를 위한 메커니즘을 도입합니다. 엄격한 우선순위 스케줄링은 실시간 시스템에서 유용합니다. 이는 프로그래머에게 어떤 작업이 처리 시간을 얻는지에 대한 더 많은 통제력을 제공합니다. 높은 우선순위는 일반적으로 시간적으로 중요한 작업에 대한 것입니다. 그것은 "공평하지 않습니다". 하지만 일반용 운영체제에 적용되지 않는 다른 문제들을 해결합니다.

<a id="what-thread-should-run-after-a-lock-has-been-released"></a>

### 락을 해제한 뒤에는 어떤 스레드가 실행돼야 하나요?

잠금을 풀면 잠금을 기다리는 최우선 우선순위 스레드가 잠금을 풀고 준비된 스레드 목록에 넣어야 합니다. 스케줄러는 준비 목록에서 가장 높은 우선순위를 가진 스레드를 실행해야 합니다.

<a id="if-the-highest-priority-thread-yields-does-it-continue-running"></a>

### 우선순위가 가장 높은 스레드가 양보하면 계속 실행되나요?

\- 그래요 가장 높은 우선순위가 있는 하나의 스레드가 있는 경우 `thread_yield()`을 호출하더라도 막거나 종료될 때까지 계속 실행됩니다. 여러 개의 스레드가 동일한 최상위 우선순위를 가지고 있다면, `thread_yield()`은 "라운드 로빈" 순서로 그들 사이에 전환해야 합니다.

<a id="what-happens-to-the-priority-of-a-donating-thread"></a>

### 우선순위를 기부하는 스레드 자신의 우선순위는 어떻게 되나요?

우선순위 기부은 단지 Donee 스레드의 우선순위를 변화시킵니다. 기부자의 우선순위는 변하지 않습니다. 우선순위 기부은 덧셈이 아닙니다. 만약 스레드 A ( 우선순위 5) 는 스레드 B ( 우선순위 3) 에 기부한다면, B의 새로운 우선순위는 5이므로 8이 아닙니다.

<a id="can-a-threads-priority-change-while-it-is-on-the-ready-queue"></a>

### 준비 큐에 있는 스레드의 우선순위도 바뀔 수 있나요?

\- 그래요 준비된, 우선순위가 낮은 L 스레드를 고려해 보세요. 높은 우선순위 스레드 H는 잠금 및 블록을 획득하려고 시도하고, 따라서 준비 스레드 L에 우선순위를 기부합니다.

<a id="can-a-threads-priority-change-while-it-is-blocked"></a>

### 블록 상태인 스레드의 우선순위도 바뀔 수 있나요?

\- 그래요 로크 L를 획득한 스레드는 어떤 이유로든 차단되지만, 우선순위가 높은 스레드가 L를 획득하려는 경우 우선순위 기부으로 우선순위가 증가할 수 있습니다. 이 사례는 우선순위 기부-세마 테스트로 확인됩니다.

<a id="can-a-thread-added-to-the-ready-list-preempt-the-processor"></a>

### 준비 리스트에 추가된 스레드가 현재 실행을 선점할 수 있나요?

\- 그래요 준비 목록에 추가된 스레드가 실행 스레드보다 더 높은 우선순위를 가지고 있다면, 올바른 행동은 즉시 프로세서를 생성하는 것입니다. 다음 타이머 인터럽트를 기다리는 것은 허용되지 않습니다. 가장 우선순위가 높은 스레드가 실행 가능한 즉시 실행되어야 하며, 현재 실행 중인 스레드가 우선되어야 합니다.

<a id="how-does-threadsetpriority-affect-a-thread-receiving-donations"></a>

### `thread_set_priority()`는 우선순위를 기부받는 스레드에 어떤 영향을 주나요?

스레드의 기본 우선순위를 설정합니다. 스레드의 효과적인 우선순위는 새로 설정된 우선순위 중 가장 높거나 가장 높은 기부된 우선순위가 됩니다. 기부금이 공개되면 함수 호출을 통해 열의 우선순위가 설정됩니다. 이 행동은 우선순위 기부-저기 테스트에 의해 검증됩니다.

<a id="doubled-test-names-in-output-make-them-fail"></a>

### 출력에서 테스트 이름이 중복돼 테스트가 실패합니다.

몇 가지 테스트 이름이 두 배로 표시되는 출력을 보인다고 가정해보세요.

    (alarm-priority) begin
    (alarm-priority) (alarm-priority) Thread priority 30 woke up.
    Thread priority 29 woke up.
    (alarm-priority) Thread priority 28 woke up.

두 개의 스레드에서 나오는 출력은 서로 얽혀 있습니다. 즉, 하나의 스레드는 `(alarm-priority) Thread priority 29 woke up.\n`을 인쇄하고 다른 스레드는 `(alarm-priority) Thread priority 30 woke up.\n`을 인쇄하고 있지만 첫 번째 스레드는 출력 중간에 두 번째 스레드가 앞장서고 있습니다. 이 문제는 우선순위 스케줄러의 오류를 나타냅니다. 결국, 우선순위 29의 스레드는 실행할 수 없어야 하지만 우선순위 30의 스레드는 작업해야 합니다. 일반적으로, Pintos 커널에서 `printf()` 함수를 구현하면 프린트프 호출 기간 동안 콘솔 로크를 획득하고 그 후 풀어서 이러한 간접 출력을 방지하려고 시도합니다. 그러나 테스트 이름 (예를 들어, `(alarm-priority)`) 의 출력과 그 다음의 메시지는 printf에 두 번의 호출을 사용하여 출력되며, 콘솔 잠금을 획득하고 두 번 풀 수 있습니다.

<a id="how-does-priority-donation-interact-with-the-advanced-scheduler"></a>

### 우선순위 기부는 고급 스케줄러와 어떻게 상호작용하나요?

그럴 필요는 없어요 우선순위 기부과 고급 스케줄러를 동시에 테스트하지 않을 겁니다.

<a id="can-i-use-one-queue-instead-of-64-queues"></a>

### 큐 64개 대신 하나만 사용해도 되나요?

\- 그래요 일반적으로, 당신의 구현은 설명과 다를 수 있습니다.

<a id="some-scheduler-tests-fail-and-i-dont-understand-why-help"></a>

### 일부 스케줄러 테스트가 실패하는 이유를 모르겠습니다.

만약 여러분의 구현이 일부 고급 스케줄러 테스트에서 미스터리하게 실패한다면 다음을 시도하세요:

- 실패한 테스트의 소스 파일을 읽고 무슨 일이 일어나고 있는지 이해하는지 확인하세요. 그 각각의 목적과 기대되는 결과를 설명하는 해설이 상단에 있습니다.
- 고정소수점 수학적 루틴과 스케줄러 루틴에서 사용하는 것을 두 번 확인하세요.
- 타이머 인터럽트에서 구현이 얼마나 많은 작업을 수행하는지 생각해보십시오. 타이머 인터럽트 핸들링이 너무 오래 걸린다면, 타이머 인터럽트가 선행한 스레드에서 대부분의 타이머 틱을 제거합니다. 이 스레드에 컨트롤을 반환하면 다음 타이머 인터럽트가 도착하기 전에 많은 작업을 할 수 없습니다. 따라서 그 스레드는 실제로 사용할 수있는 것보다 훨씬 더 많은 CPU 시간으로 비난받을 것입니다. 이것은 중단된 스레드의 최근 CPU 수를 높이고, 따라서 우선순위를 낮추는 것입니다. 일정에 대한 결정이 변경될 수 있습니다. 그것은 또한 평균 부하를 증가시킵니다.
