> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/introduction.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="project3-virtual-memory"></a>

# Project 3: Virtual Memory

이제 Pintos의 내부 동작에 어느 정도 익숙해졌을 것입니다. 적절한 synchronization으로 여러 thread를 다루고 여러 user program을 함께 load할 수 있지만, 실행 가능한 프로그램 수와 크기는 main memory 크기에 제한됩니다. 이번 과제에서는 virtual memory를 구현해 프로그램이 실제보다 훨씬 큰 memory를 사용할 수 있게 합니다.

Project 3는 이전 과제 위에 구현합니다. Project 2의 테스트도 계속 동작해야 합니다. 이전 버그가 같은 문제를 일으킬 수 있으므로 시작 전에 Project 2 제출물의 버그부터 고치십시오.

이해를 돕기 위해 Project 3에서는 단계별 구현 지침을 제공합니다.

<a id="background"></a>

## 배경

<a id="source-files"></a>

### 소스 파일

이번 프로젝트의 작업 directory는 `vm`입니다. `Makefile`는 `-DVM` 설정을 켜도록 구성되어 있습니다. 많은 template 코드를 제공하며, ***반드시 이 template을 기반으로 구현해야 합니다. 다른 기반의 코드를 제출하면 0점입니다.*** 또한 DO NOT CHANGE라고 표시한 부분은 수정해서는 안 됩니다. 주요 template 파일은 다음과 같습니다.

- `include/vm/vm.h`, `vm/vm.c`

  VM 공통 interface를 제공합니다. header에는 VM_UNINIT, VM_ANON, VM_FILE, VM_PAGE_CACHE의 정의와 설명이 있습니다. VM_PAGE_CACHE는 Project 4용이므로 지금은 무시해도 됩니다. supplemental page table도 여기에서 구현합니다.

- `include/vm/uninit.h`, `vm/uninit.c`

  uninitialized page, 즉 vm_type이 `VM_UNINIT`인 page의 operation을 제공합니다. 현재 설계에서는 page를 uninitialized 상태로 만든 뒤 anonymous page나 file-backed page로 전환합니다.

- `include/vm/anon.h`, `vm/anon.c`

  vm_type이 `VM_ANON`인 anonymous page의 operation입니다.

- `include/vm/file.h`, `vm/file.c`

  vm_type이 `VM_FILE`인 file-backed page의 operation입니다.

- `include/vm/inspect.h`, `vm/inspect.c`

  채점용 memory inspection 코드입니다. 수정하지 마십시오.

대부분의 작업은 `vm`와 이전 프로젝트에서 사용한 파일들에서 진행합니다. 다음 파일은 새로 접하게 될 수 있습니다.

- `include/devices/block.h`, `devices/block.c`

  block device를 sector 단위로 읽고 쓰는 interface입니다. swap partition 접근에 사용합니다.

<a id="memory-terminology"></a>

### Memory 용어

memory와 storage의 주요 용어부터 살펴보겠습니다. 일부는 Project 2의 [Virtual Memory Layout](../project2/introduction.md)에서 보았지만 새 용어도 많습니다.

<a id="pages"></a>

#### Page

page 또는 virtual page는 virtual memory의 연속한 4,096-byte 영역입니다. 이 크기를 ***page size***라고 합니다. 시작 주소는 page size로 나누어떨어지는 ***page-aligned*** 주소여야 합니다. 따라서 64-bit virtual address의 하위 12 bits가 ***page offset***이며, 나머지 상위 bits는 page table의 index로 사용합니다. 64-bit 환경에서는 4-level page table을 사용하므로 주소 구조는 다음과 같습니다.

    63          48 47            39 38            30 29            21 20         12 11         0
    +-------------+----------------+----------------+----------------+-------------+------------+
    | Sign Extend |    Page-Map    | Page-Directory | Page-directory |  Page-Table |    Page    |
    |             | Level-4 Offset |    Pointer     |     Offset     |   Offset    |   Offset   |
    +-------------+----------------+----------------+----------------+-------------+------------+
                  |                |                |                |             |            |
                  +------- 9 ------+------- 9 ------+------- 9 ------+----- 9 -----+---- 12 ----+
                                              Virtual Address

각 process는 `KERN_BASE`(0x8004000000) 아래에 독립적인 user virtual page 집합을 가집니다. 반면 ***kernel virtual page***는 시스템 전체에서 공유하며 어떤 thread나 process가 실행되어도 같은 위치에 있습니다. kernel은 user·kernel page 양쪽에 접근할 수 있지만 user process는 자신의 user page에만 접근할 수 있습니다. [Virtual Memory Layout](../project2/introduction.md)을 참조하십시오.

virtual address를 다루는 보조 함수는 [Virtual Addresses](../appendix/virtual_address.md)에 설명되어 있습니다.

<a id="frames"></a>

#### Frame

***frame***은 physical frame 또는 page frame이라고도 하며, physical memory의 연속 영역입니다. page와 마찬가지로 page size 크기이고 page-aligned여야 합니다. 따라서 physical address는 ***frame number***와 ***frame offset***으로 나눌 수 있습니다.

                              12 11         0
        +-----------------------+-----------+
        |      Frame Number     |   Offset  |
        +-----------------------+-----------+
                  Physical Address

x86-64에서는 일반적인 memory 접근에 physical address를 직접 사용할 수 없습니다. Pintos는 kernel virtual memory의 첫 page를 physical memory의 첫 frame에, 둘째 page를 둘째 frame에 대응시키는 방식으로 해결합니다. 따라서 frame에는 kernel virtual address를 통해 접근할 수 있습니다.

physical address와 kernel virtual address 사이의 변환 함수는 [Virtual Addresses](../appendix/virtual_address.md)를 참조하십시오.

<a id="page-tables"></a>

#### Page Table

***page table***은 CPU가 virtual address를 physical address로, 즉 page를 frame으로 변환할 때 사용하는 자료구조입니다. 형식은 x86-64 architecture가 정하며, Pintos는 `threads/mmu.c`에 관리 코드를 제공합니다.

다음 그림은 page와 frame의 관계입니다. 왼쪽 virtual address는 page number와 offset으로 구성됩니다. page table로 page number를 frame number로 변환한 뒤, 바뀌지 않은 offset을 붙여 오른쪽 physical address를 얻습니다.

                              +----------+
             .--------------->|Page Table|-----------.
            /                 +----------+            |
            |   12 11 0                               V  12 11 0
        +---------+----+                         +---------+----+
        | Page Nr | Ofs|                         |Frame Nr | Ofs|
        +---------+----+                         +---------+----+
         Virt Addr   |                            Phys Addr    ^
                      \_______________________________________/

<a id="swap-slots"></a>

#### Swap Slot

***swap slot***은 swap partition에 있는 page-size disk 영역입니다. frame보다 배치 제약은 느슨하지만, page-aligned로 두어도 불이익이 없으므로 같은 경계를 사용하십시오.

<a id="resource-management-overview"></a>

### Resource Management 개요

다음 자료구조를 설계하고 구현해야 합니다.

***Supplemental page table***

> page별 추가 정보를 저장해 page fault 처리를 지원합니다. 아래의 Supplemental page table 관리 절을 참조하십시오.

***Frame table***

> physical frame의 eviction policy를 효율적으로 구현할 수 있게 합니다. 아래의 Frame table 관리 절을 참조하십시오.

***Swap table***

> swap slot의 사용 상태를 추적합니다. 아래의 Swap table 관리 절을 참조하십시오.

세 자료구조를 완전히 분리할 필요는 없습니다. 관련 자원들을 일부 또는 전부 통합해서 관리하면 편리할 수도 있습니다.

각 entry에 필요한 정보를 정하고, process별 local 구조인지 시스템 전체의 global 구조인지, 그 범위 안에서 instance가 몇 개 필요한지도 결정하십시오.

설계를 단순하게 하려면 `calloc`나 `malloc`로 할당한 non-pageable memory에 이 자료구조들을 두어도 됩니다. 그러면 이들 사이의 pointer가 eviction 때문에 무효화되지 않습니다.

<a id="choices-of-implementation-performance-perspective"></a>

#### 성능 관점에서 본 자료구조 선택

array, list, bitmap, hash table 등을 사용할 수 있습니다. array는 단순하지만 대부분 비어 있으면 memory를 낭비합니다. list도 간단하지만 특정 entry를 찾으려고 긴 list를 순회하면 시간이 걸립니다. 둘 다 크기를 조절할 수 있으나 중간 삽입·삭제는 보통 list가 더 효율적입니다.

Pintos의 bitmap 구현은 `lib/kernel/bitmap.c`와 `include/lib/kernel/bitmap.h`에 있습니다. bitmap은 각 bit가 true 또는 false인 배열로, 같은 종류 자원의 사용 여부를 추적할 때 주로 사용합니다. 자원 n이 사용 중이면 ***n***번째 bit를 true로 설정합니다. 제공되는 bitmap의 크기는 고정이지만 필요하면 resize 기능을 추가할 수 있습니다.

[Hash Table](../appendix/hash_table.md)도 제공합니다. Pintos의 hash table은 다양한 크기에서 삽입·삭제를 효율적으로 지원합니다.

더 복잡한 자료구조가 성능상 이점이 있더라도 구현을 불필요하게 어렵게 할 수 있습니다. balanced binary tree 같은 고급 자료구조를 직접 구현하는 것은 권장하지 않습니다.

<a id="managing-the-supplemental-page-table"></a>

### Supplemental Page Table 관리

***supplemental page table***은 hardware page table에 담을 수 없는 page별 정보를 보완합니다. 이 구조도 흔히 page table이라고 부르지만, 여기서는 혼동을 줄이려고 supplemental을 붙입니다.

최소 두 가지 용도가 있습니다. page fault 시 해당 virtual page에 어떤 데이터를 채워야 하는지 찾고, process 종료 시 어떤 자원을 해제해야 하는지 판단합니다.

<a id="organization-of-supplemental-page-table"></a>

#### Supplemental Page Table의 구성

구성 방식은 자유롭게 선택할 수 있습니다. 기본적으로 segment 단위 또는 page 단위로 관리할 수 있습니다. 여기서 segment는 executable이나 memory-mapped file을 담는 연속한 page들의 집합입니다.

선택적으로 hardware page table 자체를 확장해 supplemental 정보의 entry를 추적할 수도 있습니다. 이 방식은 `threads/mmu.c`의 page table 구현을 수정해야 하므로 숙련된 학생에게만 권장합니다.

<a id="handling-page-fault"></a>

#### Page Fault 처리

supplemental page table의 가장 중요한 사용처는 page fault handler입니다. Project 2에서는 page fault가 kernel이나 user program의 버그를 의미했지만, 이제는 file이나 swap에서 page를 가져오면 되는 경우도 있습니다. 이를 처리하려면 더 정교한 handler가 필요합니다. `userprog/exception.c`의 `page_fault()`가 `vm/vm.c`의 `vm_try_handle_fault()`를 호출하며, 구현할 handler의 대략적인 작업은 다음과 같습니다.

1. supplemental page table에서 fault가 발생한 page를 찾습니다. 유효한 접근이라면 entry를 보고 원본 데이터를 찾습니다. file system이나 swap slot에 있거나 모두 0으로 채울 page일 수 있습니다. copy-on-write 등의 공유를 구현하면 frame에는 이미 데이터가 있지만 이 process의 page table에 연결되지 않았을 수도 있습니다. 반대로 그 주소에 데이터가 없어야 하거나, kernel 영역에 접근하거나, 원래 read-only인 page에 쓰려는 경우는 invalid access입니다. 해당 process를 종료하고 모든 자원을 해제해야 합니다. COW를 구현할 때는 원래 쓰기가 허용된 page에 임시로 건 write protection과 실제 read-only 권한을 구분하십시오.

2. page를 담을 frame을 확보합니다. 공유를 구현했다면 필요한 데이터가 이미 있는 frame을 찾을 수 있어야 합니다.

3. file system이나 swap에서 읽거나 0으로 채워 frame을 초기화합니다. 이미 공유 frame에 내용이 있으면 이 단계는 필요하지 않습니다.

4. fault가 발생한 virtual address의 page table entry가 해당 physical page를 가리키도록 설정합니다. `threads/mmu.c`의 함수를 사용할 수 있습니다.

<a id="managing-the-frame-table"></a>

### Frame Table 관리

frame table은 frame마다 하나의 entry를 가집니다. 각 entry에는 현재 frame을 사용하는 page의 pointer와 필요한 다른 정보를 저장합니다. 빈 frame이 없을 때 evict할 page를 고르는 데 사용합니다.

user page용 frame은 `palloc_get_page(PAL_USER)`로 user pool에서 할당해야 합니다. `PAL_USER`를 빠뜨려 kernel pool을 사용하면 테스트가 예상치 못하게 실패할 수 있습니다. frame 관리 때문에 `palloc.c`를 수정하더라도 두 pool의 구분은 유지해야 합니다.

가장 중요한 작업은 비어 있는 frame을 얻는 것입니다. 빈 frame이 있으면 간단하지만, 없으면 기존 page를 evict해 공간을 만들어야 합니다.

page를 evict하려면 swap slot이 필요한데 swap도 가득 차 있다면 kernel panic을 발생시키십시오. 실제 OS는 여러 회복·예방 정책을 쓰지만 이번 프로젝트의 범위를 벗어납니다.

대략적인 eviction 절차는 다음과 같습니다.

1. page replacement algorithm으로 frame을 선택합니다. 아래에서 설명하는 accessed bit와 dirty bit를 활용할 수 있습니다.

2. 그 frame을 참조하는 모든 page table에서 mapping을 제거합니다. 공유를 구현하지 않았다면 한 순간에 하나의 page만 frame을 참조해야 합니다.

3. 필요하면 내용을 원본 파일이나 swap에 기록합니다. 이제 frame을 다른 page에 재사용할 수 있습니다.

<a id="accessed-and-dirty-bits"></a>

#### Accessed Bit와 Dirty Bit

x86-64는 각 page table entry(PTE)의 두 bit로 replacement algorithm을 지원합니다. page를 읽거나 쓰면 accessed bit를 1로, 쓰면 ***dirty bit***를 1로 설정합니다. CPU가 이 bit를 0으로 되돌리지는 않으며 OS가 해제할 수 있습니다.

`aliases`, 즉 같은 frame을 가리키는 둘 이상의 page에 주의하십시오. alias를 통해 접근하면 실제 사용한 page의 PTE에만 accessed·dirty bit가 갱신되고 다른 alias의 PTE는 바뀌지 않습니다.

Pintos의 모든 user virtual page에는 같은 frame을 가리키는 kernel virtual page alias가 있습니다. 두 주소의 accessed·dirty bit를 함께 검사하고 갱신하거나, kernel이 user 데이터에 접근할 때 항상 user virtual address만 쓰는 등의 방법으로 처리해야 합니다.

그 외 alias는 공유를 구현했거나 코드에 버그가 있는 경우에만 생겨야 합니다.

관련 함수는 [Page Table의 Accessed·Dirty Bit](../appendix/page_table.md)를 참조하십시오.

<a id="managing-the-swap-table"></a>

### Swap Table 관리

swap table은 사용 중인 slot과 빈 slot을 추적합니다. eviction 시 빈 slot을 선택할 수 있어야 하며, page를 다시 읽어 왔거나 해당 process가 종료되면 slot을 해제할 수 있어야 합니다.

`vm/build`에서 `pintos-mkdisk swap.dsk --swap-size=n`을 실행하면 n MB swap partition이 든 `swap.dsk`가 생성됩니다. 이후 pintos를 실행하면 `swap.dsk`가 추가 disk로 자동 연결됩니다. 한 번의 실행에 임시 n MB swap disk를 쓰려면 `--swap-size=n`를 사용해도 됩니다.

swap slot은 eviction 때문에 실제로 필요해질 때만 lazy하게 할당해야 합니다. process 시작 때 executable page를 읽자마자 swap에 써 두는 것은 lazy allocation이 아닙니다. 특정 page를 위한 slot을 미리 예약하지도 마십시오.

swap의 내용을 frame으로 다시 읽어 왔으면 해당 slot을 해제합니다.

<a id="managing-memory-mapped-files"></a>

### Memory-Mapped File 관리

보통 file system에는 `read`와 `write`로 접근하지만, `mmap`로 파일을 virtual page에 map할 수도 있습니다. 그 뒤 프로그램은 일반 memory instruction으로 파일 데이터에 직접 접근합니다. `foo`의 크기가 `0x1000` bytes, 즉 4 kB라고 합시다. 이를 `0x5000`부터 map하면 `0x5000. . .0x5fff`의 memory 접근은 `foo`의 해당 byte에 대응합니다. 즉 그 범위는 `foo`의 데이터입니다.

다음 프로그램은 `mmap`로 파일을 console에 출력합니다. command line으로 받은 파일을 열고 virtual address `0x10000000`에 map한 뒤, 연결된 데이터를 fd 1로 출력하고 unmap합니다.

```
#include <stdio.h>
#include <syscall.h>
int main (int argc UNUSED, char *argv[])
{
  void *data = (void *) 0x10000000;                 /* Address at which to map. */
  int fd = open (argv[1]);                          /* Open file. */
  void *map = mmap (data, filesize (fd), 0, fd, 0); /* Map file. */
  write (1, data, filesize (fd));                   /* Write file to console. */
  munmap (map);                                     /* Unmap file (optional). */
  return 0;
}
```

구현은 memory-mapped file이 사용하는 virtual memory 영역을 추적해야 합니다. 해당 영역의 page fault를 처리하고 같은 process의 다른 segment와 mapping이 겹치지 않게 하려면 필요합니다.
