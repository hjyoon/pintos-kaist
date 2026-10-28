# Pintos를 처음 시작하는 사람을 위한 안내

이 문서는 **이 저장소의 코드를 처음 읽고 직접 수정해 보려는 사람**을 위한 온보딩이다. 무엇이 이미 제공되어 있고, 무엇을 구현해야 하며, 첫 파일을 어디서 열어야 하는지 설명한다. 설명은 이 저장소의 실제 코드에서 출발해 직접 작성했다.

공식 과제의 세부 규칙은 [공식 매뉴얼의 한국어 번역](../docs/README.md)에서 확인할 수 있다. 여기서는 먼저 작업의 전체 모습을 이해하고 작은 기능 하나를 완성하는 데 집중한다. thread, kernel, page fault 같은 핵심 용어는 코드와 연결해 찾기 쉽도록 English로 쓴다.

## 먼저 알아야 할 저장소 상태

**처음부터 구현하려면 `skeleton`을 기준으로 시작한다. 현재 `master`는 Project 1~4의 구현을 합친 결과다.** 같은 함수라도 어느 브랜치에서 보느냐에 따라 내용이 크게 다르다.

| 코드 기준 | 이 문서에서의 의미 | 확인한 commit |
| --- | --- | --- |
| `skeleton` | 과제 시작 시 제공된 baseline | [49a7ed3](https://github.com/hjyoon/pintos-kaist/commit/49a7ed3b69504d04c305ed659af76fd92296436a) |
| `master` | 지금까지 진행한 구현을 통합한 코드 | [81db683](https://github.com/hjyoon/pintos-kaist/commit/81db6839ba920956b060575cfe4b10f04195225f) |
| `docs/korean-manual-2026-10-17` | 번역본과 이 온보딩을 관리하는 문서 브랜치. 소스 기반은 `skeleton` | 온보딩 작성 전 `0458ab4` |

기준일은 **2026-10-28**이다. 이후 브랜치가 이동하면 위 commit을 기준으로 설명과 코드를 대조할 수 있다. 단계별 브랜치 이름은 [작업 방법](07-workflow-and-debugging.md)에 정리했다.

문서 브랜치에서 기본 코드가 보인다고 해서 `master`의 구현이 사라진 것은 아니다. 반대로 `master`의 긴 함수를 읽고 그것이 전부 기본 제공 코드라고 생각해서도 안 된다.

## 무엇부터 읽으면 되나?

| 순서 | 문서 | 읽고 나면 알 수 있는 것 |
| --- | --- | --- |
| 1 | [기본 제공 코드는 어디까지인가](00-baseline.md) | 제공된 기반과 구현할 기능의 경계 |
| 2 | [첫 빌드와 실행](01-first-run.md) | 작업용 directory 준비, activate, 부팅, 테스트 한 개 실행 |
| 3 | [코드에서 길 찾기](02-code-tour.md) | 부팅 후 어떤 C 함수가 실행되는지, 파일을 읽는 순서 |
| 4 | [Project 1에서 첫 수정 시작하기](03-project1.md) | Alarm Clock부터 시작하는 이유와 첫 설계 질문 |
| 5 | [Project 2: User Programs](04-project2.md) | argument, user memory, system call, process 관리의 관계 |
| 6 | [Project 3: Virtual Memory](05-project3.md) | page와 frame, page fault, lazy loading, swap의 연결 |
| 7 | [Project 4: File System](06-project4.md) | FAT, file growth, path, directory, cache의 연결 |
| 필요할 때 | [브랜치·테스트·debugging](07-workflow-and-debugging.md) | 실패 결과 읽기, 재실행, 단계 비교, commit 준비 |

## 처음 직접 구현한다면

첫 세션의 목표는 다음 네 가지면 충분하다.

1. `skeleton`에서 별도의 학습 브랜치와 worktree를 만든다.
2. `threads`를 빌드하고 `alarm-single`을 실행한다.
3. `devices/timer.c`의 `timer_sleep()`가 왜 진짜 sleep이 아닌지 설명한다.
4. `threads/thread.c`의 `thread_block()`와 `thread_unblock()`를 읽고, 잠든 thread를 어디에 보관할지 생각한다.

바로 전체 scheduler나 VM을 구현할 필요는 없다. 구체적인 명령은 [첫 빌드와 실행](01-first-run.md), 첫 수정의 범위는 [Project 1 안내](03-project1.md)에 있다.

## 이미 구현된 코드를 공부한다면

`master`에서 동작을 확인하고, 관심 있는 기능의 이전·이후 브랜치를 비교한다. 예를 들어 Alarm Clock은 `skeleton`과 `project1/alarm_clock`의 차이부터 보는 것이 좋다. 최종 `master`에는 scheduling, process, VM, file system 변경이 함께 들어 있어 첫 학습 대상으로는 변화량이 크다.

각 프로젝트 문서의 표는 **baseline에서 제공된 부분**과 **그다음 구현할 부분**을 구분한다. 구현 브랜치는 작은 변화의 예제로 사용하고, 요구사항은 해당 과제 설명과 테스트에서 확인한다.

## 이 문서의 실행 검증

Ubuntu 22.04의 GCC 11.4, QEMU가 설치된 `hjyoon-900x3n`에서 별도 worktree로 예제 명령을 확인했다. 결과와 범위는 [실행 검증 기록](01-first-run.md#실행-검증-기록)에 있다. 이 확인은 문서에 등장하는 대표 실행 경로에 대한 것이며, 모든 테스트를 새로 실행한 기록은 아니다.
