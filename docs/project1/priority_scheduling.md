> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project1/priority_scheduling.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="priority-scheduling"></a>

# Priority Scheduling

**Pintos에 priority scheduling과 priority donation을 구현하십시오.**

현재 실행 중인 thread보다 priority가 높은 thread가 ready list에 추가되면, 현재 thread는 즉시 CPU를 그 thread에 양보해야 합니다. 마찬가지로 lock, semaphore, condition variable을 기다리는 thread 중에서는 priority가 가장 높은 thread를 먼저 깨워야 합니다. thread는 자신의 priority를 언제든 높이거나 낮출 수 있습니다. priority를 낮춘 결과 더 이상 최고 priority가 아니게 되면 즉시 CPU를 양보해야 합니다.

thread의 priority 범위는 `PRI_MIN (0)`부터 `PRI_MAX (63)`까지입니다. 숫자가 작을수록 priority가 낮아 0이 최저, 63이 최고입니다. 초기 priority는 `thread_create()`의 argument로 전달합니다. 다른 값을 선택할 이유가 없다면 `PRI_DEFAULT (31)`를 사용하십시오. `PRI_` macro는 `threads/thread.h`에 정의되어 있으며 값을 변경해서는 안 됩니다.

priority scheduling에는 priority inversion 문제가 있습니다. priority가 높은 thread *H*, 중간인 *M*, 낮은 *L*을 생각해 봅시다. *H*가 *L*이 보유한 lock 등을 기다리고 있고 *M*이 ready list에 있다면, *L*은 CPU 시간을 받지 못하고 그 결과 *H*도 실행되지 못합니다. 이를 부분적으로 해결하는 방법은 *L*이 lock을 보유하는 동안 *H*가 자신의 priority를 *L*에 donate하는 것입니다. *L*이 lock을 해제하고 *H*가 그 lock을 획득하면 donation을 철회합니다.

priority donation이 필요한 여러 상황을 모두 고려해 구현하십시오. 하나의 thread가 여러 priority를 donate받는 multiple donation을 처리해야 합니다. nested donation도 필요합니다. 예를 들어 *H*가 *M*의 lock을 기다리고 *M*이 *L*의 lock을 기다린다면, *M*과 *L* 모두 *H*의 priority까지 높아져야 합니다. 필요하면 nested donation의 최대 깊이를 8단계와 같은 합리적인 수준으로 제한해도 됩니다.

lock에는 priority donation을 반드시 구현해야 합니다. 다른 Pintos synchronization primitive에 donation을 구현할 필요는 없지만, **priority scheduling은 모든 경우에 적용해야 합니다.**

thread가 자신의 priority를 조회하고 변경할 수 있도록 다음 함수도 구현하십시오. skeleton은 `threads/thread.c`에 있습니다.

------------------------------------------------------------------------

```
void thread_set_priority (int new_priority);
```

> 현재 thread의 priority를 새 값으로 설정합니다. 그 결과 더 이상 최고 priority가 아니면 CPU를 양보합니다.

------------------------------------------------------------------------

```
int thread_get_priority (void);
```

> 현재 thread의 priority를 반환합니다. priority donation을 받고 있다면 더 높은, 즉 donate받은 priority를 반환합니다.

다른 thread의 priority를 직접 변경할 수 있는 interface는 제공하지 않아도 됩니다.

이후 프로젝트에서는 priority scheduler를 사용하지 않습니다.
