> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/system_call.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="system-calls"></a>

# System Calls

**System call 기반 구조를 구현하십시오.**

`userprog/syscall.c`에 system call handler를 구현합니다. 제공된 skeleton은 호출한 process를 종료하는 것만으로 system call을 처리합니다. system call 번호와 argument를 가져와 각 요청에 맞는 동작을 수행하도록 확장해야 합니다.

<a id="system-call-details"></a>

## System Call의 세부 동작

Project 1에서는 timer와 I/O device가 발생시키는 interrupt를 통해 OS가 제어를 되찾는 방법을 다뤘습니다. CPU 바깥의 장치에서 발생하므로 external interrupt라고 부릅니다.

OS는 프로그램 실행 중 발생하는 software exception도 처리합니다. page fault나 0으로 나누기 같은 오류가 그 예입니다. exception은 user program이 OS에 서비스를 요청하는 system call의 수단으로도 사용됩니다.

기존 x86에서는 system call도 다른 software exception과 같은 방식으로 처리했습니다. x86-64에는 handler를 빠르게 호출하기 위한 전용 명령인 `syscall`이 도입되었습니다.

현재 x86-64에서 system call을 호출하는 가장 일반적인 방법은 `syscall` 명령입니다. Pintos의 user program도 `syscall`을 사용합니다. `syscall`을 실행하기 전에 번호와 argument를 register에 넣어야 합니다. 일반 calling convention과 비교하면 다음 두 가지가 다릅니다.

- `%rax`에는 system call 번호를 넣습니다.
- 네 번째 argument는 `%rcx`가 아니라 `%r10`로 전달합니다.

따라서 `syscall_handler()`로 제어가 넘어오면 rax에 system call 번호가 있고, argument는 %rdi, %rsi, %rdx, %r10, %r8, %r9 순서로 전달됩니다.

호출자의 register는 handler에 전달된 `struct intr_frame`을 통해 접근할 수 있습니다. `struct intr_frame`은 kernel stack에 있습니다.

x86-64는 함수 반환값을 RAX에 넣습니다. 값을 반환하는 system call도 `struct intr_frame`의 `rax` member를 수정해 결과를 전달할 수 있습니다.

<a id="implement-the-following-system-calls"></a>

## 구현할 System Call

아래 원형은 `include/lib/user/syscall.h`를 포함한 user program에서 보이는 선언입니다. 이 header와 `include/lib/user`의 나머지 header는 user program 전용입니다. system call 번호는 `include/lib/syscall-nr.h`에 정의되어 있습니다.

------------------------------------------------------------------------

```
void halt (void);
```

> `src/include/threads/init.h`에 선언된 `power_off()`를 호출해 Pintos를 종료합니다. deadlock 등의 문제를 조사할 정보가 사라지므로 드물게 사용해야 합니다.

------------------------------------------------------------------------

```
void exit (int status);
```

> 현재 user program을 종료하고 kernel에 `status`를 전달합니다. parent가 해당 process에 대해 `wait`를 호출하면 이 상태값을 받습니다. 관례상 `status`가 `0`이면 성공, 그 외 값이면 오류를 뜻합니다.

------------------------------------------------------------------------

```
pid_t fork (const char *thread_name);
```

> 현재 process를 복제해 THREAD_NAME이라는 새 process를 만듭니다. callee-saved register인 `%RBX`, `%RSP`, `%RBP`, `%R12`부터 `%R15`까지를 제외한 나머지 register 값은 반드시 복제할 필요는 없습니다. parent에는 child의 pid를 반환하고, 실패 시에는 유효한 pid가 아닌 값을 반환해야 합니다. child에서의 반환값은 `0`입니다. file descriptor와 virtual address space를 포함한 자원을 **복제**해야 합니다. parent는 child의 복제 성공 여부를 알기 전까지 fork에서 반환해서는 안 됩니다. child가 자원 복제에 실패하면 parent의 fork()도 TID_ERROR를 반환해야 합니다.
>
> template은 `threads/mmu.c`의 `pml4_for_each()`로 page table 구조를 포함한 user memory 전체를 복사합니다. 여기에 전달하는 `pte_for_each_func`의 미완성 부분은 직접 구현해야 합니다. [Virtual Address](../appendix/virtual_address.md)를 참조하십시오.

------------------------------------------------------------------------

```
int exec (const char *cmd_line);
```

> 현재 process의 실행 내용을 `cmd_line`가 지정하는 executable로 바꾸고 주어진 argument를 전달합니다. 성공하면 반환하지 않습니다. loading이나 실행이 어떤 이유로든 실패하면 exit status `-1`로 process를 *종료*합니다. `exec`를 호출한 thread의 이름은 바뀌지 않습니다. 열린 file descriptor는 `exec` 이후에도 유지됩니다.

------------------------------------------------------------------------

```
int wait (pid_t pid);
```

> child process `pid`를 기다리고 exit status를 받습니다. `pid`가 아직 실행 중이면 종료될 때까지 기다린 뒤 `pid`가 exit에 넘긴 값을 반환합니다. `pid`가 `exit()`를 호출하지 않고 exception 등으로 kernel에 의해 종료됐다면 `wait(pid)`는 `-1`을 반환해야 합니다. parent가 wait를 호출하기 전에 child가 이미 종료된 경우도 정상입니다. 이때도 child의 exit status 또는 kernel이 종료시켰다는 사실을 알아낼 수 있어야 합니다.
>
> 다음 중 하나라도 해당하면 `wait`는 즉시 `-1`을 반환하며 실패해야 합니다.
>
> - `pid`가 호출한 process의 직접적인 child가 아닙니다. `pid`가 직접적인 child이려면 그 process가 성공한 `fork`에서 반환값으로 `pid`를 받은 경우여야 합니다. child 관계는 상속되지 않습니다. A가 B를 만들고 B가 C를 만들었다면 B가 종료되어도 A는 C를 기다릴 수 없으며, A의 `wait(C)`는 실패해야 합니다. parent가 먼저 종료되어 orphan이 된 process에 새 parent를 배정하지도 않습니다.
> - 호출한 process가 `pid`에 대해 이미 `wait`를 호출했습니다. 즉, `wait`를 호출하는 process는 특정 child에 대해 최대 한 번만 `wait`할 수 있습니다.

process는 여러 child를 만들고 어떤 순서로든 `wait`할 수 있으며, 일부 또는 모든 child를 기다리지 않고 종료해도 됩니다. 모든 경우를 고려하십시오. parent가 기다리는지, parent와 child 중 누가 먼저 종료되는지와 상관없이 `struct thread`를 포함한 process의 모든 자원은 해제해야 합니다.

**최초 process가 종료되기 전에는 Pintos가 종료되지 않도록 해야 합니다.** 제공된 코드는 `threads/init.c`의 `main()`에서 `userprog/process.c`의 `process_wait()`를 호출해 이를 처리하려고 합니다. `process_wait()`를 함수 위의 주석에 맞춰 구현한 뒤, wait system call에서 `process_wait()`를 활용하는 방식을 권장합니다.

이 system call은 나머지에 비해 구현할 작업량이 상당히 많습니다.

------------------------------------------------------------------------

```
bool create (const char *file, unsigned initial_size);
```

> 이름이 `file`이고 초기 크기가 `initial_size` bytes인 새 파일을 만듭니다. 성공하면 true, 실패하면 false를 반환합니다. 생성은 열기와 별개의 작업입니다. 새 파일을 열려면 `open` system call이 따로 필요합니다.

------------------------------------------------------------------------

```
bool remove (const char *file);
```

> 이름이 `file`인 파일을 삭제합니다. 성공하면 true, 실패하면 false를 반환합니다. 열려 있는 파일도 삭제할 수 있으며, 삭제한다고 기존 descriptor가 닫히지는 않습니다. [FAQ의 열린 파일 삭제](FAQ.md)를 참조하십시오.

------------------------------------------------------------------------

```
int open (const char *file);
```

> 이름이 `file`인 파일을 엽니다. 성공하면 file descriptor(fd)라는 음이 아닌 정수 handle을, 실패하면 `-1`을 반환합니다. 기본 요구사항에서 fd 0(`STDIN_FILENO`)은 standard input, fd 1(`STDOUT_FILENO`)은 standard output으로 예약되어 있습니다. 기본 `open`는 이 번호를 반환하지 않으며, 아래에서 명시한 경우에만 system call argument로 사용할 수 있습니다. descriptor 집합은 process별로 독립적이며 child는 parent의 descriptor를 상속합니다. 같은 파일을 여러 번 열면 호출마다 새 descriptor를 반환합니다. 각 open의 descriptor는 독립적으로 close하며 file position도 공유하지 않습니다. **Extra를 구현할 때는 Linux처럼 0부터 사용 가능한 descriptor 번호를 배정해야 합니다.**

------------------------------------------------------------------------

```
int filesize (int fd);
```

> `fd`로 열린 파일의 크기를 bytes 단위로 반환합니다.

------------------------------------------------------------------------

```
int read (int fd, void *buffer, unsigned size);
```

> `fd`로 열린 파일에서 `size` bytes를 읽어 `buffer`에 저장합니다. 실제 읽은 byte 수를 반환하며 EOF에서는 `0`을 반환합니다. EOF 이외의 문제로 읽지 못하면 `-1`을 반환합니다. `fd` 0은 `input_getc()`로 keyboard 입력을 읽습니다.

------------------------------------------------------------------------

```
int write (int fd, const void *buffer, unsigned size);
```

> `buffer`에서 `size` bytes를 가져와 열린 파일 `fd`에 씁니다. 실제 기록한 byte 수를 반환하며 전부 쓸 수 없으면 `size`보다 작을 수 있습니다. 일반적인 file system은 EOF 너머의 쓰기로 파일을 확장하지만, 기본 Pintos file system은 file growth를 지원하지 않습니다. 따라서 EOF까지 가능한 만큼 쓰고 그 수를 반환하며, 전혀 쓰지 못하면 `0`을 반환해야 합니다. `fd` 1은 console 출력입니다. 적어도 수백 bytes 이하의 buffer는 `putbuf()` 호출 한 번으로 전부 출력하십시오. 더 큰 buffer를 나누는 것은 괜찮습니다. 그렇지 않으면 여러 process의 출력이 섞여 사람이 읽기 어렵고 채점 스크립트도 혼동할 수 있습니다.

------------------------------------------------------------------------

```
void seek (int fd, unsigned position);
```

> 열린 파일 `fd`에서 다음에 읽거나 쓸 위치를 파일 시작부터 `position` bytes 떨어진 곳으로 바꿉니다. 따라서 `position`가 `0`이면 파일의 시작입니다. EOF 너머로 seek하는 것은 오류가 아닙니다. 이후 `read`는 EOF를 뜻하는 0 bytes를 반환합니다. 파일 확장을 지원하면 `write`가 파일을 늘리고 빈 간격을 0으로 채웁니다. 다만 Project 4 전에는 파일 크기가 고정되어 EOF 너머의 `write`는 확장할 수 없으며, 반환값은 앞의 write 요구사항을 따라야 합니다. 이 동작은 file system에 구현되어 있으므로 system call에서 따로 구현할 필요는 없습니다.

------------------------------------------------------------------------

```
unsigned tell (int fd);
```

> 열린 파일 `fd`에서 다음에 읽거나 쓸 위치를 파일 시작부터의 byte offset으로 반환합니다.

------------------------------------------------------------------------

```
void close (int fd);
```

> file descriptor `fd`를 닫습니다. process가 종료되면 이 함수를 각 descriptor에 호출한 것처럼 열린 descriptor를 모두 닫아야 합니다.

파일에는 다른 system call도 정의되어 있습니다. 일부는 Project 3, 나머지는 Project 4에서 구현하므로 지금은 넘어가되 확장 가능성을 고려해 설계하십시오.

여러 user process가 동시에 system call을 호출해도 안전하도록 synchronization해야 합니다. 특히 `filesys`에 제공된 file system 코드는 여러 thread가 동시에 호출하면 안전하지 않습니다. 이 코드 전체를 critical section으로 다뤄야 합니다. `process_exec()`도 파일에 접근한다는 점을 잊지 마십시오. 지금은 `filesys`의 코드를 수정하지 않는 것을 권장합니다.

각 system call의 user-level 함수는 `lib/user/syscall.c`에 제공됩니다. C 프로그램에서 호출하면 짧은 inline assembly로 system call을 요청하고, 반환값이 있으면 그 결과를 돌려줍니다.

이 부분을 구현한 뒤부터는 user program의 어떤 동작도 OS를 crash시키거나 panic, assertion failure, 기타 오동작을 일으켜서는 안 됩니다. 테스트는 매우 다양한 방법으로 system call을 공격하므로 모든 corner case를 고려해야 합니다. user program이 OS를 종료할 수 있는 유일한 방법은 halt system call이어야 합니다.

invalid argument를 받았을 때는 값을 반환하는 호출에서 오류값을 반환하거나, 정의되지 않은 값을 반환하거나, 해당 process를 종료하는 방법을 사용할 수 있습니다.
