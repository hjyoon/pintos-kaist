> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/stack_growth.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="stack-growth"></a>

# Stack Growth

Project 2의 stack은 `USER_STACK`에서 시작하는 한 page로 고정되어 프로그램 실행도 그 크기에 제한되었습니다. 이제 현재 크기를 넘어 확장되면 필요한 page를 추가로 할당합니다.

모든 잘못된 접근에 page를 추가해서는 안 됩니다. stack 접근으로 보이는 경우에만 확장하도록, 다른 memory 접근과 구분할 heuristic을 설계하십시오.

일반적인 실제 OS는 언제든 signal을 전달하면서 stack 내용을 수정할 수 있으므로, 프로그램이 stack pointer 아래에 임의로 쓰는 것은 잘못된 동작입니다. 다만 x86-64의 PUSH 명령은 stack pointer를 조정하기 전에 접근 권한을 검사하므로, 현재 stack pointer보다 8 bytes 아래에서 page fault가 발생할 수 있습니다.

현재 user stack pointer를 얻을 수 있어야 합니다. system call에서는 `syscall_handler()`에, user program의 page fault에서는 `page_fault()`에 전달된 `struct intr_frame`의 `rsp` member를 읽으면 됩니다. invalid access 판별에 page fault를 활용한다면 kernel 안에서 발생하는 fault도 고려해야 합니다. processor는 exception이 user mode에서 kernel mode로 전환시킬 때만 user stack pointer를 저장하므로, kernel fault에서 `page_fault()`에 전달된 `struct intr_frame`의 `rsp`를 읽어도 user stack pointer를 얻을 수 없습니다. user→kernel 진입 시 rsp를 `struct thread`에 저장하는 등 별도 방법을 마련하십시오.

**Stack growth를 구현하십시오.** 먼저 `vm/vm.c`의 `vm_try_handle_fault`가 stack 확장이 필요한 경우를 판별하도록 수정합니다. 확장으로 처리할 수 있으면 `vm/vm.c`의 `vm_stack_growth`를 호출합니다. `vm_stack_growth`를 구현하십시오.

------------------------------------------------------------------------

```
bool vm_try_handle_fault (struct intr_frame *f, void *addr,
    bool user, bool write, bool not_present);
```

> `userprog/exception.c`의 `page_fault`가 page fault를 처리하는 동안 호출하는 경로입니다. stack growth로 처리할 수 있는 유효한 fault인지 확인한 뒤 해당하면 fault address를 `vm_stack_growth`에 전달하십시오.

------------------------------------------------------------------------

```
void vm_stack_growth (void *addr);
```

> 하나 이상의 anonymous page를 할당해 `addr`에 더 이상 fault가 발생하지 않도록 stack을 확장합니다. 할당할 때 `addr`를 PGSIZE 경계로 내림 정렬해야 합니다.

대부분의 OS는 stack 크기에 상한을 둡니다. 여러 Unix의 `ulimit`처럼 사용자가 조절할 수 있는 경우도 있습니다. GNU/Linux에서는 기본값이 8 MB인 경우가 많지만, **이 프로젝트의 최대 stack 크기는 1 MB**로 제한해야 합니다.

이제 모든 stack-growth 테스트가 통과해야 합니다.
