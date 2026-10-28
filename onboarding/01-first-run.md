# 첫 빌드와 실행

[온보딩 목차](README.md) · 이전: [기본 제공 코드](00-baseline.md) · 다음: [코드에서 길 찾기](02-code-tour.md)

## 1. 작업할 코드부터 고른다

아래 명령은 Bash 기준이다. SSH 접속 후 `bash`를 실행하면 shell 차이를 줄일 수 있다.

서버와 경로는 이 프로젝트를 진행한 환경 기준이다. 다른 계정이나 장비에서는 자신의 저장소 위치에 맞춘다.

```bash
ssh hjyoon-900x3n
bash
cd /home/hjyoon/git/pintos-kaist
git status --short --branch
```

직접 구현을 시작한다면, 기존 directory를 그대로 둔 채 별도의 worktree를 만든다.

```bash
git worktree add -b study/project1 ../pintos-study skeleton
cd ../pintos-study
```

`pintos-study`에는 baseline 소스가 들어가고, 새로 만든 `study/project1`에 변경을 기록하게 된다. 원래 directory의 브랜치나 build 파일을 바꾸지 않고 실습할 수 있다. 브랜치·directory 이름이 이미 있다면 다른 이름을 사용한다.

완성된 구현을 실행하며 공부하려면 **위 두 명령 대신** 다음 경로를 선택한다.

```bash
git worktree add -b study/reference ../pintos-reference master
cd ../pintos-reference
```

이후 "저장소 루트"는 선택한 작업 directory를 뜻한다. 문서 브랜치에만 있는 `onboarding/`은 새 worktree에 없을 수 있으므로, 이 안내는 원래 문서 화면에서 보면서 따라가면 된다.

## 2. 필요한 실행 도구를 확인한다

저장소 루트에서 확인한다.

```bash
command -v gcc make ld objcopy python3 perl qemu-system-x86_64
gcc --version
```

| 도구 | 하는 일 |
| --- | --- |
| GCC, GNU Make, binutils의 `ld`·`objcopy` | C·assembly를 컴파일하고 kernel image를 만든다 |
| Python 3 | 저장소의 `utils/pintos` 실행 도구를 구동한다 |
| Perl | 테스트의 `.ck` 판정 스크립트를 실행한다 |
| `qemu-system-x86_64` | Pintos가 실행할 가상 컴퓨터를 제공한다 |
| GDB | 선택 사항. kernel을 멈추고 변수와 call stack을 조사한다 |

이 서버에는 작성 시 위 필수 도구가 설치되어 있었다. 새로운 Ubuntu 환경에 설치해야 할 때의 예는 다음과 같다.

```bash
sudo apt update
sudo apt install build-essential binutils python3 perl qemu-system-x86 gdb
```

설치 명령은 Ubuntu/Debian 계열을 위한 예다. 이 저장소의 baseline은 Ubuntu 22.04 / GCC 11 호환성 변경을 포함한다. 다른 환경에서는 첫 compiler 오류부터 확인한다.

## 3. `activate`를 현재 shell에 적용한다

저장소 루트에서 실행한다.

```bash
source ./activate
command -v pintos
pintos --help
```

`command -v pintos`의 결과는 선택한 저장소의 `utils/pintos`여야 한다. 직접 구현 경로를 골랐다면 `/home/hjyoon/git/pintos-study/utils/pintos`가 된다.

실행 원리는 간단하다. [activate](../activate)가 이 저장소의 `utils/`를 `PATH` 앞에 넣는다. shell은 `pintos`라는 명령을 받으면 그 directory에서 [utils/pintos](../utils/pintos)를 찾고, script 첫 줄의 Python 3로 실행한다.

따라서 현재 directory에 `pintos` 파일이 없어도 명령을 사용할 수 있다. 또한 `./activate`를 별도 process로 실행하면 변경한 환경이 부모 shell에 남지 않으므로, **`source ./activate`로 실행해야 한다.**

일반적인 shell에서는 `PATH`가 이미 export된 변수여서 추가 `export`는 필요 없다. 새 SSH session이나 새 terminal을 열었을 때는 다시 source한다. 서로 다른 worktree를 오갈 때도 그 worktree의 activate를 다시 source하면 된다. 자동 실행을 설정할 경우 shell 초기화 파일에는 activate의 절대 경로를 쓴다.

## 4. Project 1을 빌드하고 부팅한다

저장소 루트에서 시작한다.

```bash
cd threads
make -j2
cd build
pintos -T 60 -- -q
```

다음 흐름을 확인한다.

```text
compiler가 kernel을 빌드
→ threads/build/os.dsk 생성
→ pintos 도구가 QEMU 실행
→ Pintos 부팅
→ Boot complete. 출력
→ -q에 따라 종료
```

`-q`는 Pintos가 작업을 마치면 종료하게 한다. `-T 60`은 host의 실행 도구에 제한 시간을 준다. `--` 앞은 실행 도구의 옵션이고, 뒤는 Pintos kernel에 전달할 옵션과 action이다.

**최상위 directory에서 `make`만 실행하면 kernel이 빌드되지 않는다.** 최상위 Makefile은 `threads`, `userprog`, `vm`, `filesys` 중 하나에서 빌드하라고 안내한다.

## 5. 테스트를 실행하고 판정한다

지금 위치는 `threads/build`다.

직접 실행해 출력을 보려면 다음을 사용한다.

```bash
pintos -T 60 -- -q run alarm-single
```

판정 스크립트까지 실행하려면 다음을 사용한다.

```bash
make TIMEOUT=60 tests/threads/alarm-single.result
cat tests/threads/alarm-single.result
```

둘은 역할이 다르다. `pintos ... run ...`은 kernel의 실행 출력을 보여 준다. `make ...result`는 실행 출력에 대해 `.ck` 스크립트의 판정도 수행한다.

| 파일 | 용도 |
| --- | --- |
| `tests/threads/alarm-single.output` | kernel의 stdout, 테스트 진행 내용 |
| `tests/threads/alarm-single.errors` | 실행 도구와 QEMU의 stderr |
| `tests/threads/alarm-single.result` | 판정 결과인 `PASS` 또는 `FAIL` |

baseline에서도 이 테스트는 PASS할 수 있다. [기본 제공 코드 설명](00-baseline.md)의 busy waiting 예를 함께 읽는다.

다음 문서로 넘어가기 전에 저장소 루트로 돌아온다.

```bash
cd ../..
```

## 다른 프로젝트는 어느 directory에서 실행하나?

네 directory는 서로 다른 kernel 구성을 빌드한다. 프로젝트 번호만 바꿔서 같은 kernel image를 실행하는 방식이 아니다.

| 프로젝트 | 빌드할 directory | 실행·테스트할 directory | 대표 테스트 |
| --- | --- | --- | --- |
| Project 1 | `threads` | `threads/build` | `tests/threads/alarm-single.result` |
| Project 2 | `userprog` | `userprog/build` | `tests/userprog/args-single.result` |
| Project 3 | `vm` | `vm/build` | `tests/vm/pt-grow-stack.result` |
| Project 4 | `filesys` | `filesys/build` | `tests/filesys/extended/grow-file-size.result` |

예를 들어 **`master` 기반 작업 directory의 루트**에서는 다음처럼 실행한다.

```bash
source ./activate
make -C userprog -j2
make -C userprog/build TIMEOUT=60 tests/userprog/args-single.result
```

Project 3은 `vm`, Project 4는 `filesys`로 directory와 target을 맞춘다. 세부 명령은 각 프로젝트 문서에 있다. `skeleton`에서 Project 2~4의 테스트 실패는 해당 기능의 미구현 때문일 수 있다. 빌드 도구 설치 문제와 구분해야 한다.

## 실행 검증 기록

작성일: 2026-10-28. 별도 worktree에서 GCC 11.4 / Ubuntu 22.04의 도구를 사용했다.

다음은 이 문서를 작성하면서 실제로 확인한 결과다.

| 코드 | 확인 항목 | 결과 |
| --- | --- | --- |
| `skeleton` `49a7ed3` | `threads` 빌드, `pintos --help`, 빈 action으로 부팅 | 성공, `Boot complete.` 확인 |
| `skeleton` `49a7ed3` | `alarm-single` | PASS. busy waiting 제거를 증명하는 결과는 아님 |
| `skeleton` `49a7ed3` | `priority-preempt` | FAIL. baseline에 priority preemption이 없는 것과 일치 |
| `master` `81db683` | `threads`, `userprog`, `vm`, `filesys` 빌드 | 네 구성 모두 성공 |
| `master` `81db683` | `priority-preempt`, `args-single`, `pt-grow-stack`, `grow-file-size` | 네 대표 테스트 모두 PASS |
| `master` `81db683` | Project 2 안내의 `args-single hello` 직접 실행 | argument 출력 후 `exit(0)`으로 종료 |
| `master` `81db683` | `grow-file-size-persistence`, `mmap-read` | PASS |
| `master` `81db683` | 안내한 세 줄로 extra 활성화 후 `dup2-complex` | PASS |
| `master` `81db683` | GDB 연결, `timer_sleep()` breakpoint, 본문 진입 후 argument·backtrace 조회 | 성공. 예제 호출의 `ticks = 250` 확인 |

전체 테스트의 실행 방법과 기존 결과 때문에 재실행이 생략되는 경우는 [작업 방법](07-workflow-and-debugging.md)에서 설명한다.
