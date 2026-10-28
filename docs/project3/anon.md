> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/anon.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="anonymous-page"></a>

# Anonymous Page

이번 단계에서는 disk의 원본 파일에 기반하지 않는 *anonymous page*를 구현합니다.

anonymous mapping에는 backing file이나 device가 없습니다. file-backed page와 달리 이름을 가진 원본 파일이 없어서 anonymous라고 부릅니다. 프로그램 실행 중 stack이나 heap 등에 사용합니다.

anonymous page를 설명하는 구조체는 `include/vm/anon.h`의 `anon_page`입니다. 현재는 비어 있지만 필요한 정보와 상태를 저장할 member를 추가할 수 있습니다. `include/vm/page.h`의 `struct page`에는 page 공통 정보가 있습니다. anonymous page의 page 구조체에는 `struct anon_page anon`가 포함됩니다.

> **원문 주의:** page 공통 구조체의 파일 경로가 잘못 적혀 있습니다. 이 저장소에서는 include/vm/page.h가 아니라 include/vm/vm.h에 struct page가 정의되어 있습니다.

<a id="page-initialization-with-lazy-loading"></a>

## Lazy Loading을 통한 Page 초기화

lazy loading은 실제로 필요할 때까지 데이터 적재를 미루는 설계입니다. page를 할당했다는 것은 해당 page 구조체가 있다는 뜻이며, 아직 physical frame이나 실제 내용은 없을 수 있습니다. 프로그램이 접근해 page fault가 발생하면 그때 내용을 읽어 옵니다.

page type이 세 가지이므로 초기화 과정도 type마다 다릅니다. 전체 흐름을 먼저 살펴보면, 새 page 요청이 들어올 때 `vm_alloc_page_with_initializer`가 호출됩니다. 이 함수는 page 구조체를 할당하고 type에 맞는 initializer를 지정한 뒤 user program으로 돌아갑니다. 이후 프로그램이 아직 내용이 없는 page에 접근하면 page fault가 발생합니다. 처리 과정에서 `uninit_initialize`가 앞서 지정한 initializer를 호출합니다. anonymous page에는 `anon_initializer`, file-backed page에는 `file_backed_initializer`를 사용합니다.

page의 생명주기는 초기화 → (page fault → lazy loading → swap in → swap out → …) → destroy로 볼 수 있습니다. 각 단계의 작업은 page type, 즉 `VM_TYPE`에 따라 달라집니다. 앞의 설명은 초기화 단계의 예이며, 이번 프로젝트에서는 type별 전환 과정을 구현합니다.

<a id="lazy-loading-for-executable"></a>

## Executable의 Lazy Loading

lazy loading에서는 process를 시작할 때 당장 필요한 부분만 main memory에 적재합니다. binary image 전체를 한 번에 적재하는 eager loading보다 시작 시 부담을 줄일 수 있습니다.

이를 위해 `include/vm/vm.h`에 `VM_UNINIT` type을 도입합니다. 모든 page는 처음에 `VM_UNINIT` 상태로 생성됩니다. uninitialized page용 구조체는 `include/vm/uninit.h`의 `struct uninit_page`이며, 생성·초기화·destroy 함수는 `include/vm/uninit.c`에 있습니다. 뒤에서 이 함수들의 미완성 부분을 구현합니다.

> **원문 주의:** 위 include/vm/uninit.c는 원문의 경로 오타입니다. 구현 파일의 실제 경로는 vm/uninit.c입니다.

page fault가 발생하면 `userprog/exception.c`의 handler `page_fault`가 `vm/vm.c`의 `vm_try_handle_fault`로 제어를 넘깁니다. 먼저 잘못된 memory 접근인지, lazy loading처럼 VM이 복구할 수 있는 fault인지 판별해야 합니다. 복구 가능한 fault라면 필요한 내용을 준비한 뒤 user program으로 돌아갑니다.

> **원문 주의:** 이 문단은 “valid”와 “bogus”의 의미를 뒤바꾸어 설명하고 있습니다. 번역에서는 잘못된 접근과 복구 가능한 page fault를 구분해 옮겼습니다. 모든 page fault를 invalid access로 처리한다는 뜻이 아닙니다.

VM이 복구할 수 있는 대표적인 경우는 lazy-loaded page, swapped-out page, write-protected page입니다. 마지막 경우는 [Copy-on-Write — Extra](cow.md)를 참조하십시오. 지금은 lazy loading만 고려합니다. kernel은 앞서 `vm_alloc_page_with_initializer`에 설정한 initializer를 호출해 segment를 load합니다. `userprog/process.c`의 `lazy_load_segment`를 구현해야 합니다.

**`vm_alloc_page_with_initializer()`를 구현하십시오.** 전달받은 vm_type에 맞는 initializer를 선택해 `uninit_new`에 넘겨야 합니다.

------------------------------------------------------------------------

```
bool vm_alloc_page_with_initializer (enum vm_type type, void *va,
        bool writable, vm_initializer *init, void *aux);
```

> 주어진 type의 uninitialized page를 만듭니다. uninit page의 swap_in handler는 type에 맞게 page를 초기화하고, 지정한 AUX로 INIT을 호출합니다. page 구조체를 만든 뒤 process의 supplemental page table에 삽입하십시오. `vm.h`에 정의된 `VM_TYPE` macro를 활용할 수 있습니다.

page fault handler의 호출 경로에서 swap_in을 호출하면 최종적으로 `uninit_intialize`에 도달합니다. 이 함수는 완성된 구현이 제공되지만, 설계에 따라 `uninit_initialize`를 수정해야 할 수 있습니다.

------------------------------------------------------------------------

```
static bool uninit_initialize (struct page *page, void *kva);
```

> 최초 fault에서 page를 초기화합니다. template은 먼저 `vm_initializer`와 `aux`를 가져오고 function pointer를 통해 해당 page_initializer를 호출합니다. 설계에 맞게 수정해도 됩니다.

필요에 따라 `vm/anon.c`의 `vm_anon_init`와 `anon_initializer`를 수정할 수 있습니다.

------------------------------------------------------------------------

```
void vm_anon_init (void);
```

> anonymous page subsystem을 초기화합니다. 관련 초기 설정을 이 함수에서 수행하십시오.

------------------------------------------------------------------------

```
bool anon_initializer (struct page *page,enum vm_type type, void *kva);
```

> 먼저 `page->operations`에 anonymous page용 handler들을 설정합니다. 현재 비어 있는 `anon_page`에 필요한 정보를 추가할 수 있습니다. 이 함수는 `VM_ANON`, 즉 anonymous page의 initializer로 사용됩니다.

**`userprog/process.c`의 `load_segment`와 `lazy_load_segment`를 구현하십시오.** executable의 segment를 load하되, 해당 page의 fault가 발생할 때만 실제 내용을 읽는 lazy loading이어야 합니다.

수정할 핵심은 `userprog/process.c`에 있는 `load_segment`의 loop입니다. 반복할 때마다 `vm_alloc_page_with_initializer`로 아직 적재되지 않은 page 객체를 만들고, 실제 file loading은 page fault 시 수행합니다.

------------------------------------------------------------------------

```
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
        uint32_t read_bytes, uint32_t zero_bytes, bool writable);
```

> 현재 loop는 파일에서 읽을 byte 수와 0으로 채울 byte 수를 계산한 뒤 `vm_alloc_page_with_initializer`로 pending page를 만듭니다. `vm_alloc_page_with_initializer`에 전달할 `aux` argument에 필요한 정보를 준비하십시오. binary loading에 필요한 정보를 모은 구조체를 만들면 편리합니다.

------------------------------------------------------------------------

```
static bool lazy_load_segment (struct page *page, void *aux);
```

> `load_segment`의 `vm_alloc_page_with_initializer` 호출에서 네 번째 argument로 `lazy_load_segment`를 전달합니다. 이 함수는 executable page의 initializer로, page fault 시 page 구조체와 `aux`를 받습니다. `aux`는 앞서 `load_segment`에서 준비한 정보입니다. 이를 이용해 원본 파일과 위치를 찾아 해당 segment의 내용을 memory로 읽어야 합니다.

**`userprog/process.c`의 `setup_stack`도 새 memory management 구조에 맞게 수정하십시오.** 첫 stack page는 lazy loading일 필요가 없습니다. fault를 기다리지 않고 load 시점에 할당해 command-line argument로 초기화해도 됩니다. stack임을 구분할 방법이 필요할 수 있으며, `vm/vm.h`의 `vm_type`에 있는 `VM_MARKER_0` 같은 보조 marker를 사용할 수 있습니다.

마지막으로 `vm_try_handle_fault`가 `spt_find_page`로 supplemental page table을 조회하여 fault address에 대응하는 page 구조체를 찾도록 수정하십시오.

여기까지 구현하면 fork를 제외한 Project 2 테스트가 통과해야 합니다.

<a id="supplemental-page-table---revisit"></a>

## Supplemental Page Table 다시 살펴보기

process 생성, 특히 child 생성과 process 종료에 필요한 복사·정리 작업을 supplemental page table interface에 추가합니다. 지금 다시 다루는 이유는 앞에서 구현한 초기화 함수들을 활용할 수 있기 때문입니다.

**`vm/vm.c`의 `supplemental_page_table_copy`와 `supplemental_page_table_kill`를 구현하십시오.**

------------------------------------------------------------------------

```
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
    struct supplemental_page_table *src);
```

> src의 supplemental page table을 dst로 복사합니다. child가 `fork()` 등을 통해 parent의 execution context를 상속할 때 사용합니다. src의 각 page를 순회해 dst에 대응하는 entry를 정확히 복제하십시오. 기본 구현 방식에서는 uninit page를 할당한 뒤 즉시 claim해야 합니다.

------------------------------------------------------------------------

```
void supplemental_page_table_kill (struct supplemental_page_table *spt);
```

> supplemental page table이 보유한 모든 자원을 해제합니다. process 종료 시 `userprog/process.c`의 `process_exit()`에서 호출됩니다. entry를 순회하며 각 page에 `destroy(page)`를 호출해야 합니다. 실제 page table인 pml4와 palloc으로 할당한 physical memory의 정리는 이 함수의 책임이 아닙니다. supplemental page table을 정리한 뒤 호출자가 처리합니다.

<a id="page-cleanup"></a>

## Page 정리

**`vm/uninit.c`의 `uninit_destroy`와 `vm/anon.c`의 `anon_destroy`를 구현하십시오.** uninitialized page의 `destroy` handler입니다. 보통은 다른 type으로 전환되지만, 한 번도 접근되지 않아 process 종료 때까지 uninit 상태인 page도 있을 수 있습니다.

------------------------------------------------------------------------

```
static void uninit_destroy (struct page *page);
```

> page 구조체가 보유한 자원을 해제합니다. VM type을 확인해 그에 맞게 처리할 수 있습니다.

지금은 anonymous page만 처리하면 됩니다. 나중에 file-backed page 정리도 추가합니다.

------------------------------------------------------------------------

```
static void anon_destroy (struct page *page);
```

> anonymous page가 보유한 자원을 해제합니다. page 구조체 자체는 호출자가 해제하므로 여기에서 직접 free하지 않아도 됩니다.

이제 Project 2의 모든 테스트가 통과해야 합니다.
