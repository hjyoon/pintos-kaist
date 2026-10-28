> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project1/advanced_scheduler.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="advanced-scheduler"></a>

# Advanced Scheduler

**실행 작업의 평균 response time을 줄이도록 [4.4BSD scheduler](advanced_scheduler.md#44bsd-scheduler)와 유사한 multilevel feedback queue scheduler를 구현하십시오.**

priority scheduler와 마찬가지로 advanced scheduler도 priority에 따라 실행할 thread를 선택합니다. 다만 priority donation은 하지 않습니다. 따라서 advanced scheduler 작업에 들어가기 전에, donation 부분은 아직 완성하지 않았더라도 기본 priority scheduler는 동작하도록 해 두는 것을 권장합니다.

Pintos 시작 시 scheduling policy를 선택할 수 있어야 합니다. 기본값은 priority scheduler이며, `-mlfqs` kernel 옵션을 주면 4.4BSD scheduler를 선택할 수 있어야 합니다. 이 옵션을 지정하면 `main()` 초기에 호출되는 `parse_options()`가 옵션을 해석하면서, `threads/thread.h`에 선언된 `thread_mlfqs`를 true로 설정합니다.

4.4BSD scheduler가 활성화되면 thread는 자신의 priority를 직접 제어하지 않습니다. `thread_create()`의 priority argument와 `thread_set_priority()` 호출은 무시해야 합니다. `thread_get_priority()`는 scheduler가 계산한 현재 thread의 priority를 반환해야 합니다. 이후 프로젝트에서는 advanced scheduler를 사용하지 않습니다.

<a id="44bsd-scheduler"></a>

# 4.4BSD Scheduler

범용 scheduler의 목표는 thread마다 다른 scheduling 요구를 균형 있게 충족하는 것입니다. I/O가 많은 thread는 입출력 장치를 계속 활용할 수 있도록 빠른 response time이 필요하지만 CPU 시간은 많이 필요하지 않습니다. 반면 CPU-bound thread는 작업을 끝내려면 CPU 시간이 많이 필요하지만 빠른 응답이 필수는 아닙니다. I/O와 계산을 번갈아 수행해 시간에 따라 요구가 달라지는 thread도 있습니다. 잘 설계된 scheduler는 이런 서로 다른 요구를 동시에 만족시킬 수 있습니다.

Project 1에서는 이 절에서 설명하는 scheduler를 구현합니다. 이 scheduler는 \[McKusick\]에 설명된 것과 유사하며, multilevel feedback queue scheduler의 한 예입니다. 서로 다른 priority의 ready thread를 여러 queue에 나누어 보관하고, 비어 있지 않은 queue 중 priority가 가장 높은 queue에서 다음 thread를 선택합니다. 그 queue에 thread가 여러 개 있으면 round-robin 순서로 실행합니다.

scheduler의 여러 값은 정해진 수의 timer tick이 지날 때마다 갱신해야 합니다. 이 갱신은 항상 일반 kernel thread가 다시 실행되기 전에 끝나야 합니다. 어떤 thread도 새로 증가한 `timer_ticks()` 값과 아직 갱신되지 않은 scheduler 값을 함께 관찰해서는 안 됩니다.

4.4BSD scheduler에는 priority donation이 없습니다.

<a id="niceness"></a>

## Nice 값

priority는 아래 식에 따라 scheduler가 동적으로 결정합니다. 별도로 각 thread에는 다른 thread에 CPU를 얼마나 양보할지 나타내는 정수 nice 값이 있습니다. nice가 0이면 priority에 영향을 주지 않습니다. 양수 nice는 최대 20까지이며 priority를 낮춰 원래 받을 CPU 시간의 일부를 양보하게 합니다. 음수 nice는 최소 -20까지이며 다른 thread의 CPU 시간을 더 가져오는 방향으로 작용합니다.

최초 thread의 nice 값은 0입니다. 이후 생성하는 thread는 parent의 nice 값을 상속합니다. 테스트에서 사용할 다음 함수들을 구현하십시오. skeleton은 `threads/thread.c`에 있습니다.

```
int thread_get_nice (void);
```

> 현재 thread의 nice 값을 반환합니다.

```
int thread_set_nice (int nice);
```

> 현재 thread의 nice 값을 새 값으로 설정하고 그에 따라 priority를 다시 계산합니다. [Priority 계산](advanced_scheduler.md#calculating-priority)을 참조하십시오. 현재 thread가 더 이상 최고 priority가 아니면 CPU를 양보합니다.
>
> **원문 주의:** 위 prototype의 반환 type은 원문 표기입니다. 이 저장소의 include/threads/thread.h에서는 thread_set_nice의 반환 type이 void이므로 실제 선언에 맞춰 구현하십시오.

<a id="calculating-priority"></a>

## Priority 계산

priority는 0 `(PRI_MIN)`부터 `63 (PRI_MAX)`까지 64개이며, 각각에 대응하는 ready queue도 64개입니다. 숫자가 작을수록 priority가 낮아 0이 최저, 63이 최고입니다. thread 초기화 시 priority를 계산하고, 이후 모든 thread에 대해 timer tick 4회마다 다시 계산합니다. 두 경우 모두 다음 식을 사용합니다.

> priority = PRI_MAX - (recent_cpu / 4) - (nice \* 2),

recent_cpu는 thread가 최근 사용한 CPU 시간의 추정치이고, nice는 해당 thread의 nice 값입니다. 계산 결과의 소수 부분은 절삭합니다. recent_cpu의 계수 1/4과 nice의 계수 2는 실용적으로 잘 동작하는 값이지만 특별한 이론적 의미가 있는 것은 아닙니다. 계산한 priority는 항상 `PRI_MIN`부터 `PRI_MAX`까지의 유효 범위 안으로 제한합니다.

이 식은 최근 CPU를 사용한 thread의 priority를 낮춰 다음 scheduling에서 CPU를 다시 배정받기 어렵게 합니다. 이는 starvation 방지의 핵심입니다. 최근 CPU 시간을 전혀 받지 못한 thread는 recent_cpu가 0이므로, nice 값이 높지 않다면 곧 CPU를 배정받을 수 있습니다.

<a id="calculating-recentcpu"></a>

## `recent_cpu` 계산

recent_cpu는 각 process가 최근에 받은 CPU 시간을 나타내야 합니다. 더 최근에 사용한 CPU 시간일수록 더 높은 가중치를 주는 것이 좋습니다. 최근 n초 각각의 CPU 시간을 n개짜리 배열에 기록하는 방법도 있지만, thread당 O(n)의 공간과 새 가중 평균을 계산할 때마다 O(n)의 시간이 필요합니다.

대신 다음 형태의 exponentially weighted moving average를 사용합니다.

> x(0) = f(0),
>
> x(t) = ax(t − 1) + (1 − a)f(t),
>
> a = k/(k + 1),

여기서 `x(t)`는 정수 시점 `t ≥ 0`에서의 moving average이고, `f(t)`는 평균을 구할 함수이며, `k > 0`는 과거 값의 가중치가 감소하는 속도를 조절합니다. 몇 단계 전개한 식은 다음과 같습니다.

> x(1) = f(1),
>
> x(2) = af(1) + f(2),
>
> ...
>
> x(5) = a^4 \* f(1) + a^3 \* f(2) + a^2 \* f(3) + a \* f(4) + f(5).

> **원문 주의:** 위 전개식은 원문 그대로입니다. 앞의 점화식에 있는 (1 − a) 계수 및 초기값 표기와 일치하지 않으므로, scheduler 구현에는 아래의 recent_cpu·load_avg 요구식을 사용하십시오.

`f(t)`의 가중치는 시점 `t`에서 1, `t + 1`에서 `a`, `t + 2`에서 `a^2`로 줄어듭니다. `x(t)`와 `k`의 관계로도 설명할 수 있습니다. `f(t)`의 가중치는 시점 `t + k`에서 약 `1/e`, `t + 2k`에서 약 `1/(e^2)`가 됩니다. 반대로 말하면 `f(t)`의 가중치가 `w`까지 감소하는 시점은 `t + log_a(w)`입니다.

최초 thread의 `recent_cpu` 초기값은 0이며, 이후 thread는 parent의 값을 상속합니다. timer interrupt가 발생할 때마다 idle thread를 제외한 현재 실행 중인 thread의 `recent_cpu`를 1씩 증가시킵니다. 이와 별도로 매초 모든 thread의 recent_cpu를 다시 계산합니다. running, ready, blocked 상태를 모두 포함하며 식은 다음과 같습니다.

> recent_cpu = (2 \* load_avg)/(2 \* load_avg + 1) \* recent_cpu + nice

`load_avg`는 실행 가능한 thread 수의 moving average입니다. `load_avg`가 1이면 평균적으로 thread 하나가 CPU를 사용하려 경쟁한다는 뜻이며, 현재 recent_cpu 값의 가중치가 `.1`으로 감소하는 데 약 `log_(2/3) .1 ≈ 6`초가 걸립니다. load_avg가 2이면 가중치가 `.1`으로 감소하는 데 약 `log_(3/4) .1 ≈ 8`초가 걸립니다. 따라서 recent_cpu는 최근 CPU 사용량을 추정하며, CPU를 두고 경쟁하는 thread 수가 많을수록 과거 값의 가중치가 더 천천히 줄어듭니다.

> **원문 주의:** load_avg가 2인 두 번째 예의 수치도 원문 그대로입니다. 위 recent_cpu 갱신식에 2를 대입하면 감소 계수는 4/5이며, 가중치가 0.1이 되는 시간은 약 10.3초입니다. 구현 기준은 예의 수치가 아니라 갱신식입니다.

일부 테스트는 recent_cpu가 정확한 시점에 갱신된다고 가정합니다. system tick counter가 1초의 배수가 되는 순간, 즉 `timer_ticks () % TIMER_FREQ == 0`일 때만 다시 계산해야 하며 다른 시점에 갱신해서는 안 됩니다.

nice가 음수인 thread에서는 `recent_cpu`도 음수가 될 수 있습니다. 음수 `recent_cpu`를 0으로 제한해서는 안 됩니다.

계산 순서도 중요합니다. 먼저 recent_cpu에 곱할 계수를 계산한 다음 곱하는 방법을 권장합니다. `load_avg`에 `recent_cpu`를 바로 곱하면 overflow가 발생할 수 있습니다.

`threads/thread.c`에 skeleton이 있는 `thread_get_recent_cpu()`를 구현하십시오.

```
int thread_get_recent_cpu (void);
```

> 현재 thread의 recent_cpu 값에 100을 곱한 뒤 가장 가까운 정수로 반올림해 반환합니다.

<a id="calculating-loadavg"></a>

## `load_avg` 계산

system load average라고도 부르는 load_avg는 지난 1분 동안 실행 가능한 thread 수의 평균을 추정합니다. `recent_cpu`와 마찬가지로 exponentially weighted moving average를 사용합니다. priority나 `recent_cpu`와 달리 `load_avg`는 thread별 값이 아니라 시스템 전체의 값입니다. 부팅 시 0으로 초기화하고, 이후 매초 다음 식으로 갱신합니다.

> load_avg = (59/60) \* load_avg + (1/60) \* ready_threads,

ready_threads는 갱신 시점에 running 또는 ready 상태인 thread 수이며 idle thread는 제외합니다.

일부 테스트의 가정을 만족하려면 `load_avg`를 system tick counter가 1초의 배수가 되는 순간, 즉 `timer_ticks () % TIMER_FREQ == 0`일 때만 갱신해야 합니다. `threads/thread.c`에 skeleton이 있는 `thread_get_load_avg()`도 구현하십시오.

```
int thread_get_load_avg (void)
```

> 현재 system load average에 100을 곱한 뒤 가장 가까운 정수로 반올림해 반환합니다.

<a id="summary"></a>

## 계산 요구사항 요약

아래 식은 scheduler 구현에 필요한 계산을 요약한 것입니다. scheduler의 모든 요구사항을 대신하는 설명은 아닙니다.

각 thread는 -20부터 20까지의 nice 값을 직접 제어합니다. priority는 0(`PRI_MIN`)부터 63(`PRI_MAX`)까지이며, timer tick 4회마다 다음 식으로 다시 계산합니다.

> priority = PRI_MAX - (recent_cpu / 4) - (nice \* 2)

`recent_cpu`는 thread가 최근 받은 CPU 시간을 나타냅니다. 매 timer tick마다 실행 중인 thread의 recent_cpu를 1 증가시키고, 매초 모든 thread에 대해 다음 식으로 갱신합니다.

> recent_cpu = (2 \* load_avg) / (2 \* load_avg + 1) \* recent_cpu + nice

`load_avg`는 지난 1분 동안 실행 가능한 thread 수의 평균을 추정합니다. 부팅 시 0으로 초기화한 뒤 매초 다음 식으로 다시 계산합니다.

> load_avg = (59/60) \* load_avg + (1/60) \* ready_threads

`ready_threads`는 갱신 시점에 running 또는 ready 상태인 thread 수이며, idle thread는 제외합니다.

<a id="fixed-point-real-arithmetic"></a>

## Fixed-Point Arithmetic

위 식에서 `priority`, `nice`, `ready_threads`는 정수이지만 `recent_cpu`와 `load_avg`는 실수입니다. Pintos는 kernel 구현이 복잡해지고 느려지는 것을 피하기 위해 kernel에서 floating-point arithmetic을 지원하지 않습니다. 실제 kernel도 같은 이유로 이 제한을 두는 경우가 많습니다. 따라서 정수 연산으로 실수 계산을 모사해야 합니다. 어렵지는 않지만 익숙하지 않을 수 있으므로 여기에서 기본 원리를 설명합니다.

핵심은 정수의 하위 bits를 소수 부분으로 해석하는 것입니다. 예를 들어 signed 32-bit 정수의 하위 14 bits를 소수 부분으로 사용하면 정수 x는 실수 `x/(2^14)`를 나타냅니다. 정수 부분 17 bits, 소수 부분 14 bits, sign bit 하나를 사용하므로 이를 17.14 fixed-point 표현이라고 합니다. 이 형식에서 표현할 수 있는 최댓값은 `(2^31 − 1)/(2^14) ≈ 131,071.999`입니다.

`p.q` fixed-point 형식을 사용하고 `f = 2^q`라고 합시다. 정수나 실수를 `p.q` 형식으로 바꾸려면 `f`를 곱합니다. 예를 들어 위의 `load_avg` 계산에 사용한 `59/60`는 17.14 형식에서 `(59/60)2^14 = 16,110`입니다. fixed-point 값을 정수로 되돌리려면 `f`로 나눕니다. C의 일반적인 `/` 연산자는 0 방향으로 절삭합니다. 즉, 양수는 아래쪽 정수로, 음수는 위쪽 정수로 갑니다. 가장 가까운 정수로 반올림하려면 나누기 전에 양수에는 `f / 2`를 더하고 음수에서는 같은 값을 빼십시오.

기본 연산은 간단합니다. `x`와 `y`가 fixed-point 값이고 `n`이 정수라고 합시다. `x`와 `y`의 합은 `x + y`, 차는 `x - y`입니다. `x`와 `n`의 합은 `x + n * f`, 차는 `x - n * f`, 곱은 `x * n`, 몫은 `x / n`입니다.

두 fixed-point 값을 곱할 때는 두 가지 문제가 있습니다. 첫째, 결과의 소수점이 올바른 위치보다 q bits 왼쪽에 놓입니다. 예를 들어 `(59/60)(59/60)`는 `1`보다 약간 작아야 하지만, 정수 표현 그대로 계산한 `16,111 × 16,111 = 259,564,321`는 `2^14 = 16,384`보다 훨씬 큽니다. 이를 오른쪽으로 `q` bits 이동하면 `259,564,321/2^14 = 15,842`, 즉 약 `0.97`이라는 올바른 답이 나옵니다. 둘째, 결과를 표현할 수 있어도 중간 곱셈에서 overflow가 발생할 수 있습니다. 17.14 형식의 `64`는 `64 × 2^14 = 1,048,576`이고 제곱인 `64^2 = 4,096`도 표현 범위 안에 있지만, 중간 계산 `1,048,576^2 = 2^40`는 signed 32-bit 정수의 최댓값 `2^31 − 1`를 넘습니다. 곱셈을 64-bit로 수행하면 해결할 수 있습니다. 따라서 x와 y의 곱은 `((int64_t) x) * y / f`로 계산합니다.

나눗셈에서는 반대 문제가 생깁니다. 소수점이 너무 오른쪽에 놓이므로, 나누기 전에 dividend를 q bits 왼쪽으로 이동해 보정합니다. 다만 왼쪽 shift는 상위 q bits를 버릴 수 있으므로 나눗셈도 64-bit로 수행해야 합니다. 따라서 x를 y로 나눈 몫은 `((int64_t) x) * f / y`입니다.

이 절에서 q-bit shift 대신 `f`를 곱하거나 나누는 표현을 쓴 데에는 두 가지 이유가 있습니다. 곱셈·나눗셈은 C shift operator의 혼동하기 쉬운 operator precedence 문제를 피할 수 있고, 음수 operand에 대해서도 동작이 명확히 정의되기 때문입니다. C의 shift operator는 음수에 대해 같은 보장을 하지 않으므로 구현할 때 주의하십시오.

다음 표는 fixed-point arithmetic을 C로 구현하는 방법을 요약합니다. `x`와 `y`는 fixed-point 값, `n`은 정수이며, signed `p.q` 형식에서 `p + q = 31`입니다. `f`는 `1 << q`입니다.

| 연산 | C |
|----|----|
| `n`을 fixed-point로 변환 | `n * f` |
| `x`를 정수로 변환: 0 방향 절삭 | `x / f` |
| `x`를 정수로 변환: 가장 가까운 정수로 반올림 | `x >= 0`이면 `(x + f / 2) / f` |
|  | `x <= 0`이면 `(x - f / 2) / f` |
| `x`와 `y`를 더함 | `x + y` |
| `x`에서 `y`를 뺌 | `x - y` |
| `x`와 `n`을 더함 | `x + n * f` |
| `x`에서 `n`을 뺌 | `x - n * f` |
| `x`에 `y`를 곱함 | `((int64_t) x) * y / f` |
| `x`에 `n`을 곱함 | `x * n` |
| `x`를 `y`로 나눔 | `((int64_t) x) * f / y` |
| `x`를 `n`으로 나눔 | `x / n` |
