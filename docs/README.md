# Pintos KAIST 한국어 매뉴얼

[공식 Pintos KAIST 매뉴얼](https://casys-kaist.github.io/pintos-kaist/)의 한국어 번역이다. 2026-10-17에 사이트 내부 링크를 재귀적으로 탐색하고 공개 브랜치의 문서 목록과 대조해 **HTML 문서 39개와 직접 게시된 Markdown 문서 2개, 총 41개**를 수집했다. 외부 참고 자료와 GitBook의 검색·글꼴·테마 파일은 번역 범위에 포함하지 않는다.

원문의 장·절, 목록, 표, 코드, API 원형과 수식을 유지했다. 내부 문서 링크는 이 디렉터리의 상대 경로로 바꾸고 원문의 절별 앵커를 보존했다. 각 문서 상단에서 해당 원문으로 이동할 수 있다. 원문 주소와 SHA-256은 [수집 기록](_meta/sources.json)에 있다.

## 도입부

1. [소개](index.md)
2. [시작하기](introduction/getting_started.md)
3. [채점](introduction/grading.md)
4. [법적·윤리적 문제](introduction/legal_and_ethical_issues.md)

## 프로젝트 1: 스레드

1. [프로젝트 소개](project1/introduction.md)
2. [알람 시계](project1/alarm_clock.md)
3. [우선순위 스케줄링](project1/priority_scheduling.md)
4. [고급 스케줄러와 고정소수점 연산](project1/advanced_scheduler.md)
5. [자주 묻는 질문](project1/FAQ.md)

## 프로젝트 2: 유저 프로그램

1. [프로젝트 소개](project2/introduction.md)
2. [인자 전달](project2/argument_passing.md)
3. [유저 메모리 접근](project2/user_memory.md)
4. [시스템 콜](project2/system_call.md)
5. [프로세스 종료 메시지](project2/process_termination.md)
6. [실행 파일 쓰기 금지](project2/deny_write.md)
7. [파일 디스크립터 확장 — 추가 과제](project2/dup.md)
8. [자주 묻는 질문](project2/FAQ.md)

## 프로젝트 3: 가상 메모리

1. [프로젝트 소개](project3/introduction.md)
2. [메모리 관리](project3/vm_management.md)
3. [익명 페이지](project3/anon.md)
4. [스택 확장](project3/stack_growth.md)
5. [메모리 매핑 파일](project3/memory_mapped_files.md)
6. [스왑 인/아웃](project3/swapping.md)
7. [쓰기 시 복사 — 추가 과제](project3/cow.md)
8. [유저 메모리 접근 — Markdown 원문](project3/accessing_user_memory.md)
9. [페이징 — Markdown 원문](project3/paging.md)
10. [자주 묻는 질문](project3/FAQ.md)

## 프로젝트 4: 파일 시스템

1. [프로젝트 소개](project4/introduction.md)
2. [인덱스 및 확장 가능한 파일](project4/indexed_and_extensible_files.md)
3. [하위 디렉터리와 심볼릭 링크](project4/subdirectories.md)
4. [동기화](project4/synchronization.md)
5. [버퍼 캐시 — 추가 점수](project4/buffer_cache.md)
6. [자주 묻는 질문](project4/FAQ.md)

## 부록

1. [스레드](appendix/threads.md)
2. [동기화](appendix/synchronization.md)
3. [메모리 할당](appendix/memory_allocation.md)
4. [가상 주소](appendix/virtual_address.md)
5. [페이지 테이블](appendix/page_table.md)
6. [해시 테이블](appendix/hash_table.md)
7. [디버깅 도구](appendix/debugging_tools.md)
8. [개발 도구](appendix/development_tools.md)

## 번역과 원문 보존

한국어 초안은 로컬에서 실행한 NLLB 번역 모델을 이용해 작성하고, 제목·주요 요구 사항·운영체제 용어를 원문과 대조해 교정했다. 코드 블록, 인라인 코드, 함수 원형, 레지스터 이름, 수식의 식별자는 원형을 유지한다. 과제 요구 사항의 최종 기준은 공식 원문이다.

| 원어 | 번역 용어 |
| --- | --- |
| thread / scheduler | 스레드 / 스케줄러 |
| priority donation / priority inversion | 우선순위 기부 / 우선순위 역전 |
| semaphore / condition variable | 세마포어 / 조건 변수 |
| page fault / page eviction | 페이지 폴트 / 페이지 퇴거 |
| supplemental page table / frame table | 보조 페이지 테이블 / 프레임 테이블 |
| accessed bit / dirty bit | 접근 비트 / 더티 비트 |
| anonymous page / file-backed page | 익명 페이지 / 파일 기반 페이지 |
| lazy loading / copy-on-write | 지연 로딩 / 쓰기 시 복사 |
| fixed-point arithmetic | 고정소수점 연산 |

원문에서 발견한 아래 내부 경로 오타는 번역본의 실제 문서로 연결했다.

| 원문의 잘못된 대상 경로 | 번역본 연결 대상 |
| --- | --- |
| `appendix/appendix/debugging_tools.md` | `appendix/debugging_tools.md` |
| `appendix/debuuging_tools.md` | `appendix/debugging_tools.md` |
| `appendix/memoryAllocation.md` | `appendix/memory_allocation.md` |
| `project1/priority_scheduling` | `project1/priority_scheduling.md` |
| `project2/introduction` | `project2/introduction.md` |
| `introduction/grading#Testing` | `introduction/grading.md#testing` |
| `introduction` | `introduction/getting_started.md` |

원문의 저작권·라이선스 고지는 [LICENSE.upstream](_meta/LICENSE.upstream)에 보존했다. 특히 KAIST 수정분에는 원문이 명시하는 RECEX SHARED SOURCE LICENSE가 적용된다. 번역본도 원문의 이용 조건을 따른다.

문서를 수정한 뒤에는 저장소 루트에서 다음 명령으로 문서 누락·내부 파일 링크·절 앵커를 검사할 수 있다. Python 3 표준 라이브러리만 사용한다.

```bash
python3 docs/_meta/check_links.py
```

## 현재 저장소에서 실행하기

번역 본문은 원문의 버전과 명령을 보존한다. 원문의 Ubuntu 16.04·GCC 7 관련 설명이나 일부 예전 `pintos` 옵션은 현재 `skeleton`의 Python 실행 도구와 차이가 있다. 이번 저장소에서 확인한 기본 명령은 다음과 같다.

```bash
source ./activate
cd threads
make clean && make
cd build
pintos -T 60 -- -q
pintos -T 60 -- -q run alarm-single
make TIMEOUT=60 tests/threads/alarm-single.result
```

실행 도구의 옵션은 `pintos --help`, 커널의 옵션은 `pintos -- -h`로 확인한다. 위 예제의 빌드·부팅·`alarm-single` PASS는 이 번역 작업 이전에 확인한 결과다. 전체 테스트 통과를 의미하지 않는다.
