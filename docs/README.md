# Pintos KAIST 한국어 매뉴얼

[공식 Pintos KAIST 매뉴얼](https://casys-kaist.github.io/pintos-kaist/)의 한국어 번역이다. 2026-10-17에 사이트 내부 링크를 재귀적으로 탐색하고 공개 브랜치의 문서 목록과 대조해 **HTML 문서 39개와 직접 게시된 Markdown 문서 2개, 총 41개**를 수집했다. 외부 참고 자료와 GitBook의 검색·글꼴·테마 파일은 번역 범위에 포함하지 않는다.

2026-10-28에 **41개 원문 전체를 다시 대조하고 한국어 설명을 직접 다시 작성했다.** 이번 교정에는 로컬 번역 모델을 사용하지 않았다. 중요한 OS 개념과 자주 쓰이는 기술 용어는 English로 유지하고, 설명과 문장 구조를 자연스러운 한국어로 다듬었다.

원문의 장·절, 목록, 표, 코드, API 원형과 수식을 유지했다. 내부 문서 링크는 이 디렉터리의 상대 경로로 바꾸고 원문의 절별 앵커를 보존했다. 각 문서 상단에서 해당 원문으로 이동할 수 있다. 원문 주소와 SHA-256은 [수집 기록](_meta/sources.json)에 있다. 재확인한 원문 41개는 최초 수집본과 SHA-256이 모두 같았다.

## 도입부

1. [소개](index.md)
2. [시작하기](introduction/getting_started.md)
3. [채점](introduction/grading.md)
4. [법적·윤리적 문제](introduction/legal_and_ethical_issues.md)

## Project 1: Threads

1. [프로젝트 소개](project1/introduction.md)
2. [Alarm Clock](project1/alarm_clock.md)
3. [Priority Scheduling](project1/priority_scheduling.md)
4. [Advanced Scheduler와 Fixed-Point Arithmetic](project1/advanced_scheduler.md)
5. [자주 묻는 질문](project1/FAQ.md)

## Project 2: User Programs

1. [프로젝트 소개](project2/introduction.md)
2. [Argument Passing](project2/argument_passing.md)
3. [User Memory Access](project2/user_memory.md)
4. [System Calls](project2/system_call.md)
5. [Process Termination Message](project2/process_termination.md)
6. [Deny Write on Executables](project2/deny_write.md)
7. [File Descriptor 확장 — 추가 과제](project2/dup.md)
8. [자주 묻는 질문](project2/FAQ.md)

## Project 3: Virtual Memory

1. [프로젝트 소개](project3/introduction.md)
2. [Memory Management](project3/vm_management.md)
3. [Anonymous Page](project3/anon.md)
4. [Stack Growth](project3/stack_growth.md)
5. [Memory-Mapped Files](project3/memory_mapped_files.md)
6. [Swap In/Out](project3/swapping.md)
7. [Copy-on-Write — 추가 과제](project3/cow.md)
8. [Accessing User Memory — Markdown 원문](project3/accessing_user_memory.md)
9. [Paging — Markdown 원문](project3/paging.md)
10. [자주 묻는 질문](project3/FAQ.md)

## Project 4: File System

1. [프로젝트 소개](project4/introduction.md)
2. [Indexed and Extensible Files](project4/indexed_and_extensible_files.md)
3. [Subdirectories와 Symbolic Links](project4/subdirectories.md)
4. [Synchronization](project4/synchronization.md)
5. [Buffer Cache — 추가 점수](project4/buffer_cache.md)
6. [자주 묻는 질문](project4/FAQ.md)

## 부록

1. [Threads](appendix/threads.md)
2. [Synchronization](appendix/synchronization.md)
3. [Memory Allocation](appendix/memory_allocation.md)
4. [Virtual Address](appendix/virtual_address.md)
5. [Page Table](appendix/page_table.md)
6. [Hash Table](appendix/hash_table.md)
7. [디버깅 도구](appendix/debugging_tools.md)
8. [개발 도구](appendix/development_tools.md)

## 번역과 원문 보존

설명은 한국어로 직접 번역하되, 아래와 같은 핵심 용어는 제목과 본문 모두 English로 쓴다. API 이름, type 이름, register 이름, 명령어와 수식의 식별자도 원형을 유지한다. 코드 블록과 인라인 코드는 번역하지 않는다. 문서 변환·서식 정리·검사에는 도구를 사용했지만 번역 모델을 호출하지 않았다.

| 유지하는 용어 | 본문에서 가리키는 개념 |
| --- | --- |
| thread / process / kernel | 실행 단위와 OS의 핵심 실행 영역 |
| scheduler / priority / preemption | 다음 실행 대상을 정하는 정책과 실행권 전환 |
| priority donation / priority inversion | lock 의존 관계에서 priority를 전달하거나 실행 순서가 뒤집히는 현상 |
| semaphore / lock / condition variable / monitor | 공유 자원 접근과 대기를 조정하는 synchronization 수단 |
| interrupt / interrupt handler / context switch | 비동기 사건의 처리와 실행 문맥 전환 |
| system call / file descriptor / open file description | user program의 kernel 요청과 열린 파일 상태를 참조하는 구조 |
| virtual address / physical address / address space | program에서 쓰는 주소, 실제 memory 주소, process의 주소 범위 |
| page / frame / page fault / eviction | virtual memory의 관리 단위, physical memory의 저장 단위, 접근 예외와 회수 |
| page table / supplemental page table / frame table | 주소 변환과 page·frame 상태를 관리하는 자료구조 |
| accessed bit / dirty bit / alias | page의 접근·수정 이력과 같은 frame을 가리키는 여러 주소 |
| anonymous page / file-backed page | 파일을 backing storage로 사용하는지에 따른 page 구분 |
| lazy loading / demand paging / copy-on-write | 필요한 시점까지 page 내용의 적재나 복사를 미루는 기법 |
| swap / swap slot / swap table | 회수한 page 내용을 저장하는 영역과 관리 정보 |
| buffer cache / write-behind / read-ahead | disk I/O를 줄이는 memory 저장 영역과 입출력 정책 |
| inode / FAT / sector / directory / symbolic link | 파일 배치와 이름 탐색을 구성하는 file system 개념 |
| stack / heap / pointer / register | 실행 중 데이터의 저장 위치와 참조 수단 |
| hash table / key / bucket | key를 기준으로 원소를 저장·검색하는 자료구조 |
| fixed-point arithmetic / load_avg / recent_cpu / nice | Advanced Scheduler의 수치 표현과 계산에 쓰는 값 |

원문의 오류나 오래된 설명은 해당 위치에 **원문 주의** 또는 버전 설명으로 구분했다. 예를 들어 `0x400000`의 크기 설명, 정수와 pointer 사이의 cast 설명, Memory-Mapped Files의 길이 표현, page fault의 유효성 구분을 바로잡았다. Advanced Scheduler의 점화식 전개·감소 계수 예제와 실제 skeleton의 함수 선언이 다른 부분에도 주석을 달았다. 원문 코드나 API prototype 자체는 보존했으므로, skeleton과 선언이 다른 경우에는 해당 버전의 선언도 확인해야 한다. 과제 요구 사항을 판단할 때는 연결된 공식 원문과 이 주석을 함께 확인한다.

Project 3의 직접 게시된 Markdown 두 문서는 HTML 매뉴얼과 함께 수집된 별도 원문이다. 중복되는 설명과 버전 차이가 있을 수 있어 목차에 원문 형식을 표시했다.

원문에서 발견한 내부 경로 오타와 잘못된 연결 대상을 수정했다. 원문의 href가 비어 있어 현재 문서로 되돌아가던 GDB·Backtraces·Debugging Tips 링크도 실제 절로 연결했다. 전체 수정 목록은 [링크 교정 기록](_meta/link-repairs.json)에 있으며, 대표적인 수정은 다음과 같다.

| 원문의 잘못된 대상 경로 | 번역본 연결 대상 |
| --- | --- |
| `appendix/appendix/debugging_tools.md` | `appendix/debugging_tools.md` |
| `appendix/debuuging_tools.md` | `appendix/debugging_tools.md` |
| `appendix/memoryAllocation.md` | `appendix/memory_allocation.md` |
| `project1/priority_scheduling` | `project1/priority_scheduling.md` |
| `project2/introduction` | `project2/introduction.md` |
| `introduction/grading#Testing` | `introduction/grading.md#testing` |
| `introduction` | `introduction/getting_started.md` |
| 비어 있는 GDB·Backtraces·Debugging Tips 링크 | `appendix/debugging_tools.md`의 해당 절 |
| Page Tables라는 이름으로 `appendix/virtual_address.html`에 연결한 링크 | `appendix/page_table.md` |

원문의 저작권·라이선스 고지는 [LICENSE.upstream](_meta/LICENSE.upstream)에 보존했다. 특히 KAIST 수정분에는 원문이 명시하는 RECEX SHARED SOURCE LICENSE가 적용된다. 번역본도 원문의 이용 조건을 따른다.

문서를 수정한 뒤에는 저장소 루트에서 다음 명령으로 문서 누락·내부 파일 링크·절 앵커를 검사할 수 있다. Python 3 표준 라이브러리만 사용한다. 이번 전수 교정에서 수행한 원문 SHA-256·코드 보존·절 구조·링크 대상 대조 결과는 [검증 기록](_meta/validation.json)에 있다.

```bash
python3 docs/_meta/check_links.py
```

## 현재 저장소에서 실행하기

번역 본문은 원문의 버전과 명령을 보존한다. 원문의 Ubuntu 16.04·GCC 7 관련 설명이나 일부 예전 `pintos` 옵션은 2026-10-17에 확인한 `skeleton`의 Python 실행 도구와 차이가 있다. 아래 명령은 당시 확인한 실행 예제다. 이 문서 교정에서는 kernel 구현이나 빌드를 변경하지 않았다.

```bash
source ./activate
cd threads
make clean && make
cd build
pintos -T 60 -- -q
pintos -T 60 -- -q run alarm-single
make TIMEOUT=60 tests/threads/alarm-single.result
```

실행 도구의 옵션은 `pintos --help`, kernel의 옵션은 `pintos -- -h`로 확인한다. 위 예제의 빌드·부팅·`alarm-single` PASS는 2026-10-17의 확인 기록이며, 이번 교정에서 다시 실행한 결과나 다른 브랜치의 전체 테스트 결과를 뜻하지 않는다.
