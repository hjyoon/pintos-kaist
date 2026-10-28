> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/argument_passing.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="argument-passing"></a>

# Argument Passing

**`process_exec()`에서 user program의 argument를 설정하십시오.**

<a id="x86-64-calling-convention"></a>

## x86-64 Calling Convention

이 절은 Unix의 64-bit x86-64 환경에서 일반적인 함수 호출에 사용하는 calling convention의 핵심을 요약합니다. 간결하게 설명하기 위해 일부 세부사항은 생략합니다. 자세한 내용은 <a href="https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI" target="_blank">System V AMD64 ABI</a>를 참조하십시오.

호출 절차는 다음과 같습니다.

1. user application은 integer argument를 순서대로 `%rdi`, `%rsi`, `%rdx`, `%rcx`, `%r8`, `%r9` register로 전달합니다.
2. caller는 다음 instruction의 주소인 return address를 stack에 push하고 callee의 첫 instruction으로 이동합니다. x86-64의 `CALL` 명령 하나가 두 작업을 수행합니다.
3. callee가 실행됩니다.
4. 반환값이 있으면 callee는 이를 RAX register에 저장합니다.
5. callee는 `RET` 명령으로 stack의 return address를 pop하고 그 주소로 이동해 반환합니다.

int argument 세 개를 받는 함수 `f()`를 생각해 봅시다. 아래 그림은 `f()`를 `f(1, 2, 3)`으로 호출했을 때, 위 3단계가 시작되는 시점에 callee가 보는 stack frame과 register 상태입니다. stack의 시작 주소는 임의로 정한 것입니다.

                                 +----------------+
    stack pointer --> 0x4747fe70 | return address |
                                 +----------------+
    RDI: 0x0000000000000001 | RSI: 0x0000000000000002 | RDX: 0x0000000000000003

<a id="program-startup-details"></a>

## Program 시작 과정

Pintos의 user program용 C library는 `lib/user/entry.c`에 있는 `_start()`를 entry point로 사용합니다. 이 함수는 `main()`을 감싸는 wrapper이며, `main()`이 반환되면 `exit()`을 호출합니다.

```
void
_start (int argc, char *argv[]) {
    exit (main (argc, argv));
}
```

kernel은 user program 실행을 허용하기 전에 초기 함수의 argument를 register에 넣어야 합니다. 전달 방식은 일반 calling convention과 같습니다.

예제 명령 `/bin/ls -l foo bar`의 argument를 어떻게 준비하는지 살펴봅시다.

1. 명령을 `/bin/ls`, `-l`, `foo`, `bar`의 단어로 나눕니다.

2. 문자열들을 stack의 높은 주소 쪽에 배치합니다. pointer로 참조하므로 문자열 자체의 배치 순서는 상관없습니다.

3. 각 문자열의 주소와 마지막 null pointer sentinel을 오른쪽부터 왼쪽 순서로 stack에 push합니다. 이들이 argv의 원소가 됩니다. sentinel은 C 표준에 따라 `argv[argc]`가 null pointer임을 보장하고, 역순 push는 `argv[0]`가 가장 낮은 virtual address에 놓이게 합니다. 정렬된 memory 접근이 더 빠르므로 첫 push 전에 stack pointer를 8의 배수 주소로 내림 정렬하십시오.

4. `%rsi`가 `argv[0]`의 주소인 `argv`를 가리키게 하고, `%rdi`에는 `argc`를 설정합니다.

5. 마지막으로 가짜 return address를 push합니다. entry 함수는 실제로 반환하지 않지만, stack frame의 구조는 일반 함수와 같아야 합니다.

다음 표는 user program이 실행되기 직전의 stack과 관련 register 상태입니다. stack은 낮은 주소 방향으로 자랍니다.

| Address    | Name             | Data        | Type         |
|------------|------------------|-------------|--------------|
| 0x4747fffc | argv\[3\]\[...\] | 'bar\0'     | char\[4\]    |
| 0x4747fff8 | argv\[2\]\[...\] | 'foo\0'     | char\[4\]    |
| 0x4747fff5 | argv\[1\]\[...\] | '-l\0'      | char\[3\]    |
| 0x4747ffed | argv\[0\]\[...\] | '/bin/ls\0' | char\[8\]    |
| 0x4747ffe8 | word-align       | 0           | uint8_t\[\]  |
| 0x4747ffe0 | argv\[4\]        | 0           | char \*      |
| 0x4747ffd8 | argv\[3\]        | 0x4747fffc  | char \*      |
| 0x4747ffd0 | argv\[2\]        | 0x4747fff8  | char \*      |
| 0x4747ffc8 | argv\[1\]        | 0x4747fff5  | char \*      |
| 0x4747ffc0 | argv\[0\]        | 0x4747ffed  | char \*      |
| 0x4747ffb8 | return address   | 0           | void (\*) () |

> RDI: 4 \| RSI: 0x4747ffc0

이 예제에서는 stack pointer를 `0x4747ffb8`로 초기화합니다. 위와 같이 stack의 시작점은 `include/threads/vaddr.h`에 정의된 `USER_STACK`로 설정해야 합니다.

argument passing 코드를 debugging할 때 `<stdio.h>`에 선언된 비표준 함수 `hex_dump()`을 활용할 수 있습니다.

<a id="implement-the-argument-passing"></a>

## Argument Passing 구현

현재 `process_exec()`는 새 process에 argument를 전달하지 못합니다. `process_exec()`가 입력을 단순한 실행 파일 이름으로만 처리하지 않고 공백 기준으로 나누도록 확장하십시오. 첫 단어는 프로그램 이름이고 두 번째 단어부터 argument입니다. 예를 들어 `process_exec("grep foo bar")`는 grep을 실행하면서 foo와 bar를 argument로 전달해야 합니다.

연속한 여러 공백은 하나의 공백과 같습니다. 따라서 `process_exec("grep foo bar")`도 원래 예제와 같은 의미입니다. argument 문자열 길이에는 합리적인 제한을 둘 수 있습니다. 예를 들어 한 page인 4 kB 안에 들어가도록 제한해도 됩니다. 이와 별도로 pintos 실행 도구가 kernel에 전달하는 command-line argument에는 128-byte 제한이 있습니다.

argument를 나누는 방식은 자유롭게 선택할 수 있습니다. 막막하다면 `include/lib/string.h`에 선언되고 `lib/string.c`에 자세한 주석과 함께 구현된 `strtok_r()`를 살펴보십시오. shell에서 `man strtok_r`을 실행해 man page를 읽어도 됩니다.
