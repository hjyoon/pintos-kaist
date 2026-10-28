> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/process_termination.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="process-termination-message"></a>

# Process 종료 메시지

**Process 종료 메시지를 출력하십시오.**

user process가 `exit`을 호출하거나 다른 이유로 종료될 때마다 **process 이름과 exit code를 출력**해야 합니다. 출력 형식은 다음 호출과 같아야 합니다.

```
printf ("%s: exit(%d)\n", ...);
```

이름은 `fork()`에 전달한 전체 이름을 사용합니다. user process가 아닌 kernel thread가 종료되거나 halt system call을 호출할 때는 이 메시지를 출력하지 마십시오. process loading에 실패한 경우에는 출력 여부를 선택할 수 있습니다.

이 메시지를 제외하고 제공된 Pintos가 원래 출력하지 않던 메시지를 추가로 출력해서는 안 됩니다. debugging에는 도움이 될 수 있지만 채점 스크립트를 혼동시켜 감점으로 이어질 수 있습니다.
