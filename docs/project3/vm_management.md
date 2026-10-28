> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/vm_management.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="memory-management"></a>

# Memory Management

VM을 지원하려면 virtual page와 physical frame을 효율적으로 관리해야 합니다. 어떤 virtual·physical memory 영역이 누구에 의해 어떤 목적으로 사용 중인지 추적해야 한다는 뜻입니다. 먼저 supplemental page table을 다룬 뒤 physical frame을 관리합니다. 이 문서에서는 혼동을 피하려고 virtual page를 page, physical page를 frame이라고 부릅니다.

<a id="page-structure-and-operations"></a>

## Page 구조와 Operation

<a id="struct-page"></a>

### struct page

`include/vm/vm.h`의 `page`는 virtual memory의 page를 나타내며, 그 page에 대해 필요한 정보를 저장합니다. template의 구조는 다음과 같습니다.

```
struct page {
  const struct page_operations *operations;
  void *va;              /* Address in terms of user space */
  struct frame *frame;   /* Back reference for frame */

  union {
    struct uninit_page uninit;
    struct anon_page anon;
    struct file_page file;
#ifdef EFILESYS
    struct page_cache page_cache;
#endif
  };
};
```

page operation, virtual address, physical frame 외에 union도 있습니다. union은 같은 memory 영역에 여러 type 중 하나의 데이터를 저장하는 C type입니다. member는 여러 개지만 한 시점에 유효한 내용은 하나입니다. 따라서 page는 uninit_page, anon_page, file_page, page_cache 중 하나의 형태를 가집니다. 예를 들어 [Anonymous Page](anon.md)라면 `struct anon_page anon`가 사용되고, `anon_page`에 anonymous page 관리에 필요한 정보가 들어갑니다.

<a id="page-operations"></a>

### Page Operations

`include/vm/vm.h`에 정의된 page type은 `VM_UNINIT`, `VM_ANON`, `VM_FILE` 등입니다. 각 page에는 swap in, swap out, destroy 등의 작업이 필요하며, 구체적인 절차는 type마다 다릅니다. 예를 들어 `VM_ANON`와 `VM_FILE`에는 다른 `destroy` 함수가 필요합니다. 각 함수에서 switch-case로 분기할 수도 있지만, 여기서는 OOP의 class inheritance와 유사한 방식을 사용합니다. C에는 class나 inheritance가 없으므로 <a href="https://www.geeksforgeeks.org/function-pointer-in-c/" target="_blank">function pointer</a>로 구현합니다. Linux 같은 실제 OS 코드에서도 비슷한 방식을 사용합니다.

function pointer는 memory 안의 함수, 즉 실행할 코드를 가리킵니다. 실행 시 설정된 pointer를 통해 호출할 함수를 선택할 수 있어 type마다 조건 분기를 반복할 필요가 없습니다. 코드에서는 `destroy (page)`만 호출하면 되고, 실제로는 해당 page type에 등록된 `destroy` 함수가 간접 호출됩니다.

> **원문 주의:** 원문은 compiler가 page type을 보고 호출 대상을 고르는 것처럼 설명하지만, 여기서 설명하는 동작은 실행 시 function pointer를 통한 간접 호출입니다.

`include/vm/vm.h`에 정의된 `struct page_operations`는 세 개의 function pointer를 담은 function table로 볼 수 있습니다.

```
struct page_operations {
  bool (*swap_in) (struct page *, void *);
  bool (*swap_out) (struct page *);
  void (*destroy) (struct page *);
  enum vm_type type;
};
```

`include/vm/vm.h`의 `struct page`를 보면 `operations`라는 field가 있습니다. `vm/file.c`에는 함수 원형 앞에 `file_ops`라는 page_operations 구조체가 정의되어 있습니다. file-backed page의 function table이며, `.destroy` field는 같은 파일에 정의된 page 정리 함수 `file_backed_destroy`를 가리킵니다.

function pointer로 `file_backed_destroy`를 호출하는 흐름을 살펴봅시다. `vm/vm.c`의 `vm_dealloc_page (page)`에 `VM_FILE`, 즉 file-backed page가 전달되면 내부에서 `destroy (page)`를 호출합니다. `destroy (page)`는 `include/vm/vm.h`에 다음과 같은 macro로 정의됩니다.

```
#define destroy(page) if ((page)->operations->destroy) (page)->operations->destroy (page)
```

따라서 `destroy`를 호출하면 page 구조체의 `destroy` function pointer를 통해 실제로 `(page)->operations->destroy (page)`가 호출됩니다. 이 page는 `VM_FILE`이므로 `.destroy`가 `file_backed_destory`를 가리켜 file-backed page의 destroy routine이 실행됩니다.

> **원문 주의:** 위 file_backed_destory는 원문의 오타입니다. 실제 함수명은 file_backed_destroy입니다.

<a id="implement-supplemental-page-table"></a>

## Supplemental Page Table 구현

현재 Pintos는 `pml4` page table로 virtual-to-physical mapping을 관리합니다. 그러나 page fault와 자원 관리를 위해서는 page별 추가 정보를 담을 supplemental page table이 필요합니다. Project 3의 첫 작업으로 그 기본 기능부터 구현하는 것을 권장합니다.

**`vm/vm.c`의 supplemental page table 관리 함수를 구현하십시오.**

자료구조를 먼저 설계한 뒤, 그 설계에 맞게 다음 세 함수를 구현합니다.

------------------------------------------------------------------------

```
void supplemental_page_table_init (struct supplemental_page_table *spt);
```

> supplemental page table을 초기화합니다. 사용할 자료구조는 자유롭게 선택할 수 있습니다. 새 process 시작 시에는 `userprog/process.c`의 `initd`에서, fork 시에는 `userprog/process.c`의 `__do_fork`에서 호출됩니다.

------------------------------------------------------------------------

```
struct page *spt_find_page (struct supplemental_page_table *spt, void *va);
```

> 주어진 supplemental page table에서 va에 해당하는 `struct page`를 찾습니다. 없으면 NULL을 반환합니다.

------------------------------------------------------------------------

```
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);
```

> `struct page`를 주어진 supplemental page table에 삽입합니다. 같은 virtual address의 entry가 이미 없는지 확인해야 합니다.

<a id="frame-management"></a>

## Frame Management

이제 page 생성 시에는 metadata만 만들고 physical memory는 나중에 연결할 수 있으므로, physical memory를 별도로 관리할 구조가 필요합니다. `include/vm/vm.h`의 `struct frame`은 physical frame을 나타내며 template은 다음과 같습니다.

```
/* The representation of "frame" */
struct frame {
  void *kva;
  struct page *page;
};
```

현재 field는 kernel virtual address인 `kva`와 연결된 page 구조체인 `page` 두 개입니다. frame 관리에 필요한 member를 추가할 수 있습니다.

**`vm/vm.c`의 `vm_get_frame`, `vm_claim_page`, `vm_do_claim_page`를 구현하십시오.**

------------------------------------------------------------------------

```
static struct frame *vm_get_frame (void);
```

> `palloc_get_page`로 user pool에서 새 physical page를 가져옵니다. 성공하면 frame 구조체도 할당하고 member를 초기화한 뒤 반환합니다. `vm_get_frame` 구현 이후 모든 user-space page는 이 함수를 통해 할당해야 합니다. 원문의 PALLOC_USER는 이 저장소에서 PAL_USER라고 부르는 user-pool 할당 flag를 뜻합니다. 지금은 할당 실패 시 swap out까지 구현하지 않아도 되며, 해당 경로를 `PANIC ("todo")`로 표시해 두십시오.

------------------------------------------------------------------------

```
bool vm_do_claim_page (struct page *page);
```

> page를 claim한다는 것은 physical frame을 확보해 연결한다는 뜻입니다. 먼저 template처럼 `vm_get_frame`로 frame을 얻은 뒤, page table에 virtual-to-physical mapping을 추가해 MMU가 사용할 수 있게 합니다. 성공 여부를 반환해야 합니다.

------------------------------------------------------------------------

```
bool vm_claim_page (void *va);
```

> `va`에 해당하는 page를 claim합니다. 먼저 page 구조체를 찾고, 그 page로 vm_do_claim_page를 호출해야 합니다.
