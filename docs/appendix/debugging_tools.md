> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/debugging_tools.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="debugging-tools"></a>

# Debugging 도구

Pintos를 debugging할 때 사용할 수 있는 여러 도구 중 일부를 소개합니다.

<a id="printf"></a>

## `printf()`

`printf()`의 가치를 과소평가하지 마십시오. Pintos의 `printf()`는 kernel thread나 interrupt handler를 포함해 kernel의 거의 어디에서든 사용할 수 있으며 보유한 lock에도 대체로 제약을 받지 않습니다. `printf()`는 값 확인뿐 아니라, 유용한 메시지 없이 crash나 panic이 발생한 위치를 찾는 데도 도움이 됩니다. 의심 구간마다 “\<1\>”, “\<2\>”처럼 서로 다른 문자열을 출력하는 `printf()`를 넣어 보십시오. \<1\>도 안 나오면 그 이전, \<1\>만 나오고 \<2\>가 안 나오면 두 지점 사이가 문제입니다. 범위를 좁힐 때마다 `printf()`를 더 넣으면 한 statement까지 원인을 좁힐 수 있습니다. 비슷한 기법은 [Triple Faults](debugging_tools.md#triple-faults)에도 설명합니다.

<a id="assert"></a>

## ASSERT

assertion은 문제가 더 커지기 전에 조기에 발견하는 데 유용합니다. 함수 시작에서 argument를 검사하고, 잘못될 가능성이 있는 지점이나 loop invariant 검사에도 사용하십시오. 단, local variable의 initializer는 assertion보다 먼저 평가되므로 initializer에서 이미 argument가 유효하다고 가정해서는 안 됩니다.

`<debug.h>`에 정의된 `ASSERT` macro로 assertion을 검사할 수 있습니다.

```
#define ASSERT(expression) { /* Omit details */ }
```

expression이 0, 즉 false이면 kernel panic을 발생시킵니다. 실패한 expression, 파일·줄 번호, backtrace를 출력하므로 원인 파악에 도움이 됩니다. [Backtraces](debugging_tools.md#backtraces)를 참조하십시오.

<a id="function-and-parameter-attributes"></a>

## Function·Parameter Attribute

`<debug.h>`의 다음 macro는 함수나 parameter의 특성을 compiler에 알립니다. GCC 전용 확장으로 구현되어 있습니다.

------------------------------------------------------------------------

```
#define UNUSED { /* Omit details */ }
```

> parameter 뒤에 붙여 함수 안에서 사용하지 않을 수도 있음을 알립니다. unused parameter 경고를 막습니다.

------------------------------------------------------------------------

```
#define NO_RETURN { /* Omit details */ }
```

> 함수 원형 뒤에 붙여 반환하지 않는 함수임을 알립니다. compiler가 경고와 코드 생성을 더 정확하게 처리할 수 있습니다.

------------------------------------------------------------------------

```
#define NO_INLINE { /* Omit details */ }
```

> 함수 원형 뒤에 붙여 inline으로 생성하지 못하게 합니다. backtrace를 읽기 좋게 만드는 데 유용할 때가 있습니다.

------------------------------------------------------------------------

```
#define PRINTF_FORMAT(format, first) { /* Omit details */ }
```

> 함수 원형 뒤에 붙입니다. 1부터 세었을 때 format번째 argument가 `printf()` 같은 format string이고, 대응하는 값들은 first번째 argument부터라는 뜻입니다. compiler가 argument type 불일치를 검사할 수 있습니다.

<a id="backtraces"></a>

## Backtrace

kernel panic이 발생하면 실행 경로를 함수 주소 목록으로 요약한 backtrace를 출력합니다. 코드 중간에서도 `<debug.h>`에 선언된 `debug_backtrace()`를 호출해 볼 수 있습니다. 같은 `<debug.h>`의 `debug_backtrace_all()`는 모든 thread의 backtrace를 출력합니다.

raw hexadecimal address만으로는 해석하기 어려우므로 `backtrace` 도구를 제공합니다. 첫 argument로 `kernel.o` 파일을, 나머지로 `0x` prefix를 포함한 backtrace 주소들을 전달하면 함수 이름과 소스의 줄 번호로 변환합니다.

해석 결과가 깨져 보이거나, B가 A를 호출하지 않는데도 A가 B의 호출 경로 위에 나타나는 등 말이 안 된다면 kernel thread의 stack이 손상되었을 수 있습니다. backtrace를 stack에서 추출하기 때문입니다. 또는 도구에 넘긴 `kernel.o`가 실제 실행한 kernel과 다른 버전일 수도 있습니다.

손상 없이도 compiler 최적화 때문에 혼동할 수 있습니다. 마지막 동작으로 다른 함수를 호출하는 tail call에서는 caller가 backtrace에서 빠질 수 있습니다. A가 반환하지 않는 B를 호출할 때는 A 대신 memory상 바로 다음에 놓인 무관한 C가 나타나기도 합니다. thread 과제의 테스트 실패에서 흔히 볼 수 있습니다.

<a id="example"></a>

### 예제

다음은 실제 file system 과제 제출물에서 나온 call stack의 예입니다.

```
Call stack: 0x800426eff 0x8004202fb 0x80042dc22 0x80042cf67 0x800422319
0x80042325a 0x40012c 0x400a96 0x400ac8.
```

`kernel.o`가 현재 directory에 있다고 가정하고 아래와 같이 `backtrace`에 주소를 복사해 넣습니다. 문서의 폭 때문에 길게 보이지만 shell에서는 한 줄로 입력해야 합니다.

```
backtrace 0x800426eff 0x8004202fb 0x80042dc22 0x80042cf67 0x800422319
0x80042325a 0x400012c 0x400a96 0x4000ac8
```

변환 결과는 다음과 비슷합니다.

```
0x0000000800426eff: debug_panic (lib/debug.c:86)
0x00000008004202fb: file_seek (filesys/file.c:405)
0x000000080042dc22: seek (userprog/syscall.c:744)
0x000000080042cf67: syscall_handler (userprog/syscall.c:444)
0x0000000800422319: intr_handler (threads/interrupt.c:334)
0x000000080042325a: intr_entry (threads/intr-stubs.S:38)
0x000000000040012c: (unknown)
0x0000000000400a96: (unknown)
0x0000000000400ac8: (unknown)
```

자신의 kernel로 실행하면 소스와 compiler가 달라 주소가 정확히 같지는 않을 것입니다. 첫 줄의 `debug_panic()`는 kernel panic 구현 함수입니다. panic에서 얻은 backtrace라면 `debug_panic()`가 맨 위에 있는 경우가 많습니다. 두 번째 줄은 `file_seek()`에서 assertion failure로 panic했음을 보여 줍니다. 이 예제의 `filesys/file.c` 405번째 줄에는 다음 assertion이 있었습니다.

    ASSERT (file_ofs >= 0);

이 줄 번호는 assertion 메시지에도 표시됩니다. 따라서 `file_seek()`에는 음수 file offset을 전달한 것이 문제입니다. 세 번째 줄에서는 `seek()`가 offset을 검증하지 않은 채 `file_seek()`를 호출했음을 알 수 있습니다. 이 제출물에서는 `seek()`가 seek system call을 구현합니다. 네 번째 줄의 handler `syscall_handler()`는 `seek()`를 호출했습니다. 다섯·여섯 번째 줄은 interrupt handler의 진입 경로입니다. 나머지는 `KERN_BASE`보다 낮은 주소이므로 kernel이 아니라 user program의 주소입니다.

<a id="gdb"></a>

## GDB

먼저 Pintos를 `--gdb` 옵션으로 시작하십시오. 예를 들면 `pintos --gdb -- run mytest`과 같습니다. 같은 컴퓨터의 다른 terminal에서 다음과 같이 kernel.o를 대상으로 GDB를 실행합니다.

    gdb kernel.o

이어서 다음 GDB 명령을 입력합니다.

    target remote localhost:1234

이제 GDB가 로컬 network를 통해 simulator에 연결됩니다. 일반 GDB 명령을 사용할 수 있습니다. c를 입력하면 simulated BIOS가 제어를 받아 kernel을 load하고 Pintos를 실행합니다. Ctrl+C로 언제든 실행을 중단할 수 있습니다.

<a id="using-gdb"></a>

### GDB 사용법

terminal에서 `info gdb`로 GDB 매뉴얼을 읽을 수 있습니다. 자주 쓰는 명령은 다음과 같습니다.

- c \[GDB 명령\]

> Ctrl+C를 누르거나 다음 breakpoint에 도달할 때까지 실행합니다.

- break *function* \[GDB 명령\]

- break *file:line* \[GDB 명령\]

- break *address* \[GDB 명령\]

> function, file의 line, 또는 address에 breakpoint를 설정합니다. hexadecimal address에는 0x를 붙입니다. break main으로 Pintos 실행이 시작되는 지점에 멈출 수 있습니다.

- p *expression* \[GDB 명령\]

> expression을 평가하고 값을 출력합니다. 함수 호출이 포함되어 있으면 그 함수가 실제로 실행됩니다.

- l *address* \[GDB 명령\]

> address 주변의 소스 몇 줄을 표시합니다. hexadecimal address에는 0x를 붙입니다.

- bt \[GDB 명령\]

> 앞의 backtrace 도구와 비슷한 stack backtrace를 출력합니다.

- p/a *address* \[GDB 명령\]

> address에 위치한 함수나 변수 이름을 출력합니다. hexadecimal address에는 0x를 붙입니다.

- disassemble *function* \[GDB 명령\]

> function을 disassemble합니다.
>
> **원문 주의:** 원문의 명령 이름은 diassemble로 잘못 적혀 있습니다. 실제 GDB 명령은 disassemble입니다.

추가로 <a href="https://github.com/pwndbg/pwndbg" target="_blank">pwndbg</a> 같은 GDB script를 설치하면 debugging이 편리해집니다.

<a id="faq"></a>

### FAQ

- Emacs 안에서 GDB를 사용할 수 있나요?

> 가능합니다. Emacs는 GDB를 subprocess로 실행하는 기능을 제공합니다. M-x gdb를 실행하고 prompt에 pintos-gdb 명령을 입력하십시오. Emacs 매뉴얼의 Debuggers 절에서 자세한 사용법을 볼 수 있습니다.

- GDB가 이상하게 동작합니다.

> 수정한 Pintos의 버그, Bochs와 GDB 사이의 interface 또는 GDB 자체의 버그, 원래 Pintos 코드의 버그 중 하나일 수 있습니다. 첫 번째와 두 번째 가능성을 모두 진지하게 검토하십시오. 세 번째도 가능하지만 상대적으로 드물기를 바랍니다.

<a id="triple-faults"></a>

## Triple Fault

page fault handler 같은 exception handler가 없거나 잘못되어 호출할 수 없으면 CPU는 double-fault handler를 호출하려 합니다. 그 handler도 없거나 잘못되어 처리할 수 없으면 triple fault가 발생하며, CPU가 즉시 reset됩니다.

계속 재부팅한다면 triple fault일 가능성이 높습니다. `printf()`에 필요한 초기화가 끝나기도 전에 재부팅할 수 있어 `printf()`로 debugging하지 못할 수도 있습니다.

다음 방법으로 발생 지점을 찾을 수 있습니다.

의심 구간에 무한 loop `for (;;);`를 넣고 다시 컴파일해 실행합니다. 두 가지 결과가 가능합니다.

- 재부팅 없이 멈추면 무한 loop에 도달한 것입니다. 원인은 그 뒤에 있으므로 loop를 더 뒤로 옮깁니다.

- 계속 재부팅하면 loop에 도달하기 전에 문제가 발생한 것입니다. loop를 더 앞에 넣습니다.

  binary search처럼 범위를 절반씩 좁히면 문제가 발생한 정확한 위치를 보통 몇 분 안에 찾을 수 있습니다.

<a id="tips"></a>

## Debugging 팁

`threads/palloc.c`의 page allocator와 `threads/malloc.c`의 block allocator는 해제한 memory를 0xcc로 채웁니다. 따라서 `0xcccccccc` 같은 pointer를 dereference하거나 `0xcc`가 나타나면 이미 free한 page를 다시 사용하는 것일 수 있습니다. 0xcc는 CPU에서 interrupt 3을 호출하는 opcode이므로, `Interrupt 0x03 (#BP Breakpoint Exception)` 같은 오류는 해제한 page나 block의 내용을 코드로 실행하려 했다는 신호일 수 있습니다. `sec_no < d->capacity`의 assertion failure는 닫고 해제한 inode를 사용했다는 뜻일 수 있습니다. inode를 free하면 시작 sector 번호가 `0xcccccccc`로 덮이며, 약 1.6 TB보다 작은 disk에서는 유효하지 않은 sector 번호입니다.
