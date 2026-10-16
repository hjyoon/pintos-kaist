> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/vm_management.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="memory-management"></a>

# 메모리 관리

가상 메모리 시스템을 지원하기 위해서는 가상 페이지와 물리적 프레임을 효과적으로 관리해야 합니다. 이것은 어떤 (虛擬 또는 물리적) 메모리 영역이 사용되고 있는지, 어떤 목적으로 사용되고 있는지, 누구에 의해 사용되고 있는지 등을 추적해야한다는 것을 의미합니다. 먼저 보조 페이지 테이블, 그리고 물리적 프레임에 대해 이야기 할 것입니다. 참고로, 여러분의 이해를 위해, 우리는 가상 페이지에 대해 "페이지"라는 용어를 사용하고, 물리적 페이지에 대해 "프레임"라는 용어를 사용합니다.

<a id="page-structure-and-operations"></a>

## 페이지 구조와 연산

<a id="struct-page"></a>

### struct page

`page`에서 정의된 `include/vm/vm.h`은 가상 메모리의 페이지를 나타내는 구조입니다. 페이지에 대한 필요한 모든 데이터를 저장합니다. 현재, 구조는 템플릿에서 다음과 같습니다:

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

페이지 운영 (이하에서 읽으십시오), 가상 주소 및 물리적 프레임이 있습니다. 또한 노동조합이 있습니다. 유니온은 메모리 영역에 다양한 유형의 데이터를 저장할 수 있는 특별한 데이터 유형입니다. 조합에는 여러 명의 구성원이 있지만 한 번에 하나의 구성원이만 값을 포함할 수 있습니다. 이것은 우리 시스템의 페이지가 uninit_page, anon_page, file_page, 또는 page_cache가 될 수 있음을 의미합니다. 예를 들어, 페이지가 익명 페이지인 경우 ([익명 페이지](anon.md) 참조), then the page struct will have the field `struct anon_page anon` as one of its members. `anon_page`은 익명 페이지에 필요한 모든 정보를 포함합니다.

<a id="page-operations"></a>

### 페이지 연산

위에서 설명하고 `include/vm/vm.h`에서 정의된 바와 같이, 페이지에서 `VM_UNINIT`, `VM_ANON` 또는 `VM_FILE`이 될 수 있습니다. 페이지에 대해 몇 가지 조치를 취해야 합니다. 예를 들어, 페이지를 교체하고, 교체하고, 파괴하는 것 같은 것들이 있습니다. 각 페이지 유형에 따라 이러한 작업에 필요한 단계와 작업은 다릅니다. 즉, 다른 `destroy` 함수는 `VM_ANON` 페이지와 `VM_FILE` 페이지에 호출되어야 합니다. 한 가지 방법은 각 함수에서 각 경우를 처리하기 위해 스위치 케이스 문법을 사용하는 것입니다. 우리는 이를 해결하기 위해 객체 지향 프로그래밍의 " 클래스 상속" 개념을 도입합니다. 실제로, C 프로그래밍 언어에는 "클래스" 또는 "유산"이 없습니다. 우리는 리눅스와 같은 실제 운영 체제 코드에서 동일한 방식으로 개념을 구현하기 위해 [함수 포인터](https://www.geeksforgeeks.org/function-pointer-in-c/)을 사용합니다.

함수 포인터는, 지금까지 배운 모든 다른 포인터와 마찬가지로, 함수, 또는 메모리의 실행 가능한 코드를 가리키는 포인터입니다. 함수 포인터는 실행 시간 값에 근거하여 특정 함수를 실행하도록 호출하는 간단한 방법을 제공하므로 유용합니다. 우리의 경우, `destroy (page)`을 호출하는 것만으로도 코드 수준에서 충분하며 컴파일러는 올바른 함수 포인터를 호출하여 페이지 유형에 따라 적절한 `destroy` 루틴을 선택합니다.

페이지 연산 구조체 `struct page_operations`은 `include/vm/vm.h`에 정의돼 있습니다. 이 구조체는 함수 포인터 3개를 담은 함수 테이블로 생각하면 됩니다.

```
struct page_operations {
  bool (*swap_in) (struct page *, void *);
  bool (*swap_out) (struct page *);
  void (*destroy) (struct page *);
  enum vm_type type;
};
```

page_operation 구조체를 어디서 찾을 수 있는지 봅시다. `include/vm/vm.h`의 페이지 구조체 `struct page`에는 `operations`이라는 필드가 있습니다. `vm/file.c`을 보면 함수 원형 앞에 page_operations 구조체 `file_ops`가 선언돼 있습니다. 이는 파일 기반 페이지의 함수 포인터 테이블입니다. `.destroy` 필드의 값은 `file_backed_destroy`이며, 같은 파일에 정의된 페이지 해제 함수입니다.

함수 포인터 인터페이스로 `file_backed_destroy`이 어떻게 호출되는지 이해하려고 하자. `vm_dealloc_page (page)` (`vm/vm.c`) 로 호출된 경우, 이 페이지는 파일 백업 페이지 (`VM_FILE`) 로 나타납니다. 함수 내부에서 `destroy (page)`을 호출합니다. `destroy (page)`는 `include/vm/vm.h`에서 다음과 같은 매크로로 정의됩니다:

```
#define destroy(page) if ((page)->operations->destroy) (page)->operations->destroy (page)
```

이것은 우리에게 `destroy` 함수를 호출하면 실제로 페이지 구조에서 검색된 `destroy` 함수인 `(page)->operations->destroy (page)`을 호출한다는 것을 알려줍니다. 페이지가 `VM_FILE` 페이지이기 때문에, 그 `.destroy` 필드는 `file_backed_destory`로 표시됩니다. 결과적으로 파일 백업 페이지의 파괴 루틴이 수행됩니다.

<a id="implement-supplemental-page-table"></a>

## 보조 페이지 테이블 구현

이 시점에서, Pintos는 메모리 가상 및 물리적 매핑을 관리하기 위해 페이지 테이블 (`pml4`) 을 가지고 있습니다. 하지만 이것만으로는 충분하지 않습니다. 이전 섹션의 논의와 마찬가지로 페이지 폴트 및 리소스 관리를 처리하기 위해 각 페이지에 대한 추가 정보를 보관하기 위해 보조 페이지 테이블이 필요합니다. 따라서 우리는 3 프로젝트의 첫 번째 과제로 보조 페이지 테이블에 대한 몇 가지 기본적인 기능을 구현하는 것을 제안합니다.

**`vm/vm.c`에서 보조 페이지 테이블 관리 함수를 구현합니다.**

먼저 Pintos의 보조 페이지 테이블을 어떻게 디자인할지 결정해야 합니다. 자신의 보조 페이지 테이블을 설계한 후, 아래와 같은 세 가지 함수를 설계에 적용합니다.

------------------------------------------------------------------------

```
void supplemental_page_table_init (struct supplemental_page_table *spt);
```

> 보조 페이지 테이블을 초기화합니다. 보조 페이지 테이블에 사용하고자 하는 데이터 구조를 선택할 수 있습니다. 이 함수는 새로운 프로세스가 시작될 때 호출된다 (`initd`의 `userprog/process.c`) 그리고 프로세스가 포크되고 있을 때 (`__do_fork`의 `userprog/process.c`).

------------------------------------------------------------------------

```
struct page *spt_find_page (struct supplemental_page_table *spt, void *va);
```

> 주어진 보조 페이지 테이블에서 va에 해당하는 `struct page`를 찾습니다. 실패하면 NULL을 반환합니다.

------------------------------------------------------------------------

```
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);
```

> 주어진 추가 페이지 테이블에 `struct page`을 삽입한다. 이 함수는 주어진 보조 페이지 테이블에서 가상 주소가 존재하지 않는다는 것을 확인해야 합니다.

<a id="frame-management"></a>

## 프레임 관리

이제부터 모든 페이지들은 단지 메타데이터를 저장하는 것이 아닙니다. 따라서 물리 메모리을 관리하기 위해 다른 시스템이 필요합니다. `include/vm/vm.h`에는 물리적 메모리를 나타내는 `struct frame`가 있습니다. 현재 구조는 다음과 같습니다.

```
/* The representation of "frame" */
struct frame {
  void *kva;
  struct page *page;
};
```

그것은 단지 두 개의 필드를 가지고 있습니다 - 커널 가상 주소인 `kva` 및 페이지 구조인 `page`. 프레임 관리 인터페이스를 구현함에 따라 더 많은 멤버를 추가할 수 있습니다.

**`vm_get_frame`, `vm_claim_page` 및 `vm_do_claim_page`을 `vm/vm.c`에 구현한다.**

------------------------------------------------------------------------

```
static struct frame *vm_get_frame (void);
```

> `palloc_get_page`를 호출해 유저 풀에서 새 물리 페이지를 얻습니다. 성공하면 frame도 할당하고 멤버를 초기화해 반환합니다. `vm_get_frame`를 구현한 뒤에는 모든 유저 공간 페이지(PALLOC_USER)를 이 함수를 통해 할당해야 합니다. 지금은 할당 실패 시 스왑 아웃까지 처리할 필요가 없습니다. 해당 경우를 `PANIC ("todo")`로 표시해 두세요.

------------------------------------------------------------------------

```
bool vm_do_claim_page (struct page *page);
```

> 페이지에 물리 프레임을 할당하는 claim 연산입니다. 먼저 `vm_get_frame`를 호출해 프레임을 얻습니다. 이 부분은 템플릿에 구현돼 있습니다. 그다음 MMU를 설정해야 합니다. 즉 페이지 테이블에 가상 주소에서 물리 주소로의 매핑을 추가합니다. 반환값으로 성공 여부를 나타내야 합니다.

------------------------------------------------------------------------

```
bool vm_claim_page (void *va);
```

> `va`을 할당하기 위해 페이지를 요구합니다. 먼저 페이지를 가져다가 페이지와 함께 vm_do_claim_page를 호출해야 합니다.
