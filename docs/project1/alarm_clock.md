> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project1/alarm_clock.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="alarm-clock"></a>

# Alarm Clock

**`devices/timer.c`에 정의된 `timer_sleep()`를 다시 구현하십시오.**

동작하는 구현이 제공되지만 **busy waiting**을 사용합니다. 충분한 시간이 지날 때까지 반복해서 현재 시간을 확인하고 `thread_yield()`를 호출하는 방식입니다. busy waiting을 하지 않도록 다시 구현하십시오.

------------------------------------------------------------------------

```
void timer_sleep (int64_t ticks);
```

> 호출한 thread의 실행을 최소 x timer ticks가 지날 때까지 중단합니다. 다른 작업이 전혀 없는 상황이 아니라면 정확히 x ticks 뒤에 깨울 필요는 없습니다. 필요한 시간이 지난 뒤 ready queue에 넣으면 됩니다.

`timer_sleep()`는 1초마다 cursor를 깜박이는 것처럼 실시간으로 동작하는 thread에 유용합니다. `timer_sleep()`의 argument 단위는 milliseconds 등이 아니라 timer tick입니다. 1초에는 `TIMER_FREQ`개의 timer tick이 있으며, `TIMER_FREQ`는 `devices/timer.h`에 정의된 macro입니다. 기본값은 `100`입니다. 이 값을 바꾸면 여러 테스트가 실패할 수 있으므로 변경하지 않는 것을 권장합니다.

milliseconds, microseconds, nanoseconds 단위로 기다리는 함수인 `timer_msleep()`, `timer_usleep()`, `timer_nsleep()`도 있습니다. 필요한 경우 이 함수들이 자동으로 `timer_sleep()`를 호출하므로 수정하지 않아도 됩니다. 이후 프로젝트에서 alarm clock 구현이 필수는 아니지만, Project 4에서는 유용하게 활용할 수 있습니다.
