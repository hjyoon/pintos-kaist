# Project 3: 필요할 때 memory를 준비하기

[온보딩 목차](README.md) · 이전: [Project 2](04-project2.md) · 다음: [Project 4](06-project4.md)

## 해결할 문제가 무엇인가?

Project 2에서는 executable의 내용을 시작할 때 memory에 읽어 넣었다. stack도 처음 준비한 범위 안에서 사용했다. Project 3에서는 **virtual address는 존재하지만 실제 내용이 아직 RAM에 없을 수 있는 구조**를 만든다.

필요할 때 파일에서 읽고, stack을 늘리고, RAM이 부족하면 일부 내용을 swap disk로 옮긴다. 준비되지 않은 주소에 접근했을 때의 page fault가 이 동작들을 연결하는 출발점이다.

**동작하는 Project 2를 기반으로 진행한다.** user memory 처리, fork, 종료 시 정리가 불안정하면 VM 오류와 구분하기 어렵다.

## 먼저 네 가지를 구분한다

| 이름 | 역할 | 비유 없이 확인할 질문 |
| --- | --- | --- |
| page | process의 virtual memory를 관리하는 단위 | 어떤 virtual address에 어떤 내용이 있어야 하나? |
| frame | page 내용을 담는 physical memory 단위 | 지금 RAM의 어느 공간을 사용하는가? |
| hardware page table, `pml4` | CPU가 virtual address를 실제 memory로 변환할 때 사용 | 현재 접근 가능한 mapping과 권한은 무엇인가? |
| supplemental page table, SPT | kernel이 page의 추가 정보를 보관하는 자료구조 | 내용이 RAM에 없으면 어디서 복구해야 하나? |

Pintos의 page 크기는 4 KiB다. page와 frame을 같은 뜻으로 생각하면 lazy loading과 eviction을 이해하기 어렵다. page 정보는 남아 있지만 그 내용을 담은 frame은 없을 수 있다.

SPT는 hardware page table을 대체하지 않는다. CPU는 hardware page table로 주소를 변환하고, kernel은 SPT를 이용해 fault와 자원 관리를 처리한다.

## baseline에서 제공되는 틀

| 파일 | 이미 있는 기반 | 구현할 부분 |
| --- | --- | --- |
| [include/vm/vm.h](../include/vm/vm.h) | `struct page`, `struct frame`, page operation interface | 상태와 관리 자료구조 확장 |
| [vm/vm.c](../vm/vm.c) | allocation·claim·fault·SPT 함수의 틀 | SPT, frame 관리, fault 판별, eviction, fork 복사·정리 |
| [vm/uninit.c](../vm/uninit.c) | uninit page 생성과 최초 초기화 연결 | 설계에 맞는 초기화 정보·미사용 page 정리 |
| [vm/anon.c](../vm/anon.c) | anonymous page operation 등록 틀 | 초기화, swap in/out, destroy |
| [vm/file.c](../vm/file.c) | file-backed operation과 mmap 함수 틀 | mapping 관리, 파일 읽기·write-back·정리 |
| [userprog/process.c](../userprog/process.c)의 `#ifdef VM` 구간 | VM용 loader 분기 | lazy executable loading, stack 준비, process lifetime 연결 |
| [userprog/exception.c](../userprog/exception.c) | page fault 진입 경로 | 처리 가능한 fault를 VM에 넘기고 결과 반영 |

baseline의 `vm_stack_growth()`처럼 본문이 비어 있는 함수도 있다. 코드가 컴파일되는지와 VM 기능이 동작하는지는 따로 확인한다.

## 이해하기 쉬운 구현 순서

기존 브랜치 이름과 정확히 한 기능씩 일치하는 순서가 아니라, 개념의 의존 관계를 기준으로 한 학습 순서다. 실제 단계별 브랜치는 [브랜치 목록](07-workflow-and-debugging.md)에 있다.

### 1. Memory Management: page를 찾고 frame을 연결한다

먼저 SPT의 초기화·검색·삽입을 구현한다. 같은 virtual page에 중복 entry를 만들지 않아야 한다. process가 종료할 때 SPT도 정리할 수 있어야 한다.

다음으로 frame을 할당하고 page와 연결하며 hardware page table에 mapping을 추가한다. 이 과정을 claim이라고 부른다. user page에 사용할 frame은 `PAL_USER`로 할당한다.

이 단계에서는 "SPT에 등록"과 "RAM 확보·mapping"을 구분해 설명할 수 있어야 한다.

### 2. Anonymous Page와 Lazy Loading: 내용 준비를 늦춘다

anonymous page는 원본 파일의 특정 영역을 backing으로 삼지 않는 page다. stack, 실행 중 변경되는 데이터 등에 사용한다. 나중에 swap disk에 보관될 수 있다는 점과 원본 파일이 없다는 점을 혼동하지 않는다.

executable을 lazy loading하려면 아직 읽지 않은 내용의 출처와 길이 등의 정보를 보관한다. fault가 발생하면 그 정보를 이용해 실제 frame에 내용을 채운다.

```text
실행 전: virtual page 정보와 initializer 등록
최초 접근: CPU에서 page fault
  → vm_try_handle_fault()
  → SPT에서 page 검색
  → frame 확보와 mapping 준비
  → swap_in operation
  → uninit page면 type 초기화와 lazy loading callback 실행
  → 원래 instruction을 다시 실행
```

`anon_initializer()`처럼 page type의 상태를 준비하는 함수와, `lazy_load_segment()`처럼 파일 내용을 읽는 callback의 역할을 나누어 읽으면 좋다. fault가 발생하기 전에 process가 종료되면 아직 사용하지 않은 초기화 정보도 정리해야 한다.

### 3. Stack Growth: 정해진 범위에서 stack을 늘린다

기존 mapping이 없다는 이유만으로 모든 주소에 stack page를 만들어서는 안 된다. stack pointer와의 관계, 접근한 주소, 최대 크기 등의 조건을 확인한다.

system call 처리 중 user stack에 접근하다 fault가 발생할 수도 있다. 그때 kernel stack pointer를 user stack pointer로 오해하지 않도록, 올바른 user context를 관리해야 한다.

### 4. Swapping: RAM이 부족해도 진행한다

빈 frame이 없으면 eviction 대상을 고르고 내용을 보존한 뒤 frame을 재사용한다. anonymous page라면 swap slot에 저장한 내용을 나중에 복구한다.

여기서 필요한 것은 단순한 disk write 호출만이 아니다.

- victim이 속한 process의 hardware mapping도 함께 관리한다.
- swap slot의 사용 상태와 해제 시점을 기록한다.
- 다른 실행 경로가 사용 중인 frame을 잘못 회수하지 않는다.
- accessed/dirty bit와 kernel alias를 고려한다.
- process 종료 시 RAM과 swap에 남은 자원을 모두 정리한다.

### 5. Memory-Mapped Files: 파일을 주소 공간에 연결한다

mmap은 파일의 특정 범위를 virtual address에 연결한다. open descriptor의 lifetime과 mapping의 lifetime은 다르다. descriptor를 close해도 mapping을 유지할 독립적인 파일 참조가 필요하다.

파일 끝을 넘는 마지막 page 일부는 0으로 제공하고, 파일에 write-back할 때는 그 부분을 기록하지 않는다. dirty page만 필요한 범위에 반영한다. unmap과 process 종료 모두에서 정리가 필요하다.

### 6. Copy-on-Write: fork 복사를 실제 write 시점으로 미룬다

이 단계는 extra다. fork 직후에는 parent와 child가 frame을 공유하고, 쓰기 시 필요한 쪽에 별도 frame을 만든다.

read-only page에 발생한 fault라고 모두 복사할 수 있는 것은 아니다. 원래 쓰기가 허용된 COW page인지 구분해야 한다. 참조 수, 마지막 owner의 해제, swap과의 관계도 함께 다룬다.

## Project 2 코드도 다시 살펴봐야 한다

user buffer가 virtual address로는 유효하지만 아직 RAM에 없을 수 있다. 한 번 확인한 뒤 I/O 중 frame이 회수되는 문제도 고려해야 한다. kernel이 user buffer를 다루는 방식, frame 보호, 파일 I/O의 lock 순서를 함께 설계한다.

fork는 SPT와 초기화 정보, mapping, 공유 관계를 복제해야 하고 exec·exit는 이전 VM 상태를 정리해야 한다. VM directory만 수정하고 process·system call 코드가 그대로라고 가정하지 않는다.

## 테스트 시작점

구현이 준비된 저장소 루트에서 실행한다.

```bash
source ./activate
make -C vm -j2
make -C vm/build TIMEOUT=60 tests/vm/pt-grow-stack.result
```

`master`에서 위 대표 테스트를 확인했다. 다른 출발점으로는 `tests/vm/mmap-read.result`, `tests/vm/page-linear.result`가 있다. 각 테스트가 어느 기능까지 요구하는지 소스를 읽고 고른다.

전체 VM 검증은 `vm/build`의 `make check`다. 이 저장소의 `vm/Make.vars`에는 COW 테스트도 포함되어 있으므로, COW 이전 단계에서는 그 실패를 별도로 해석해야 한다. VM을 추가한 후에는 Project 2의 user program 동작도 다시 확인한다.

세부 요구사항: [Memory Management](../docs/project3/vm_management.md), [Anonymous Page](../docs/project3/anon.md), [Swapping](../docs/project3/swapping.md), [Memory-Mapped Files](../docs/project3/memory_mapped_files.md).
