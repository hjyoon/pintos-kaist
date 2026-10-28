> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/page_table.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="page-table"></a>

# Page Table

`threads/mmu.c`는 x86-64 hardware page table을 추상화한 interface입니다. Intel 문서에서는 4-level page table의 최상위를 Page-Map-Level-4, 즉 `pml4`라고 부릅니다. Pintos interface는 내부 구조에 접근하기 편하도록 page table을 `uint64_t *`로 표현합니다. 아래에서 interface와 내부 동작을 설명합니다.

> **원문 주의:** 아래 pml4_activate의 uint64 t와 pgdir_destory 등은 원문의 type·함수명 오타입니다. 실제 type은 uint64_t이며, 관련 선언과 구현은 include/threads/mmu.h 및 threads/mmu.c에서 확인하십시오.

<a id="creation-destruction-and-activation"></a>

## 생성·해제·활성화

다음 함수는 page table을 만들고 해제하고 활성화합니다. 기본 코드가 필요한 위치에서 이미 호출하므로 보통 직접 호출할 필요는 없습니다.

------------------------------------------------------------------------

```
uint64_t * pml4_create (void);
```

> 새 page table을 만들어 반환합니다. 기본 kernel virtual mapping은 포함하지만 user virtual mapping은 없습니다. memory를 얻지 못하면 null pointer를 반환합니다.

------------------------------------------------------------------------

```
void pml4_destroy (uint64_t *pml4);
```

> pml4 자체와 연결된 frame 등 그 page table이 보유한 자원을 해제합니다. `pdpe_destroy`, `pgdir_destory`, `pt_destroy`를 *재귀적으로* 호출해 모든 level을 정리합니다.

------------------------------------------------------------------------

```
void pml4_activate (uint64 t *pml4)
```

> pml4를 활성화합니다. CPU는 활성 page table로 memory address를 변환합니다.

<a id="inspection-and-updates"></a>

## 조회와 갱신

다음 함수는 page-to-frame mapping을 조회하거나 변경합니다. 활성·비활성 page table, 즉 실행 중인 process와 실행을 멈춘 process의 table 양쪽에 사용할 수 있으며 필요하면 TLB를 flush합니다.

------------------------------------------------------------------------

```
bool pml4_set_page (uint64_t *pml4, void *upage, void *kpage, bool rw);
```

> user page upage에서 kernel virtual address kpage가 가리키는 frame으로의 mapping을 pml4에 추가합니다. rw가 true이면 read/write, false이면 read-only입니다. upage에는 기존 mapping이 없어야 합니다. kpage는 `palloc_get_page(PAL_USER)`로 user pool에서 얻은 frame의 kernel virtual address여야 합니다. 성공하면 true, page table에 필요한 추가 memory를 얻지 못하는 등 실패하면 false를 반환합니다.

------------------------------------------------------------------------

```
void * pml4_get_page (uint64_t *pml4, const void *uaddr);
```

> pml4에서 uaddr에 연결된 frame을 찾습니다. mapping이 있으면 그 frame의 kernel virtual address를, 없으면 null pointer를 반환합니다.

------------------------------------------------------------------------

```
void pml4_clear_page (uint64_t *pml4, void *upage);
```

> pml4에서 page를 not-present로 표시해 이후 접근 시 fault가 발생하게 합니다. accessed bit와 dirty bit 등을 나중에 확인할 수 있도록 다른 PTE bits는 보존합니다. mapping이 없으면 아무 효과가 없습니다.

<a id="accessed-and-dirty-bits"></a>

## Accessed Bit와 Dirty Bit

x86-64는 각 page table entry(PTE)의 두 bit로 page replacement를 지원합니다. page를 읽거나 쓰면 accessed bit를 1로, 쓰면 dirty bit를 1로 설정합니다. CPU는 이 값을 0으로 되돌리지 않으며 OS가 해제할 수 있습니다. 해석할 때는 같은 frame을 가리키는 여러 page, 즉 *alias*를 고려해야 합니다. 접근에 실제 사용한 page의 PTE만 갱신되며 다른 alias의 accessed·dirty bit는 바뀌지 않습니다.

------------------------------------------------------------------------

```
bool pml4_is_dirty (uint64_t *pml4, const void *vpage);
bool pml4_is_accessed (uint64_t *pml4, const void *vpage);
```

> pml4에 vpage의 PTE가 있고 dirty 또는 accessed로 표시되어 있으면 true, 아니면 false를 반환합니다.

------------------------------------------------------------------------

```
void pml4_set_dirty (uint64_t *pml4, const void *vpage, bool dirty);
void pml4_set_accessed (uint64_t *pml4, const void *vpage, bool accessed);
```

> pml4에 page의 PTE가 있으면 dirty 또는 accessed bit를 주어진 값으로 설정합니다.
