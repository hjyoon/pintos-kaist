> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/virtual_address.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="virtual-addresses"></a>

# Virtual Addresses

64-bit virtual address의 구조는 다음과 같습니다.

    63          48 47            39 38            30 29            21 20         12 11         0
    +-------------+----------------+----------------+----------------+-------------+------------+
    | Sign Extend |    Page-Map    | Page-Directory | Page-directory |  Page-Table |  Physical  |
    |             | Level-4 Offset |    Pointer     |     Offset     |   Offset    |   Offset   |
    +-------------+----------------+----------------+----------------+-------------+------------+
                  |                |                |                |             |            |
                  +------- 9 ------+------- 9 ------+------- 9 ------+----- 9 -----+---- 12 ----+
                                              Virtual Address

`include/threads/vaddr.h`와 `include/threads/mmu.h` header는 virtual address를 다루는 다음 함수·macro를 정의합니다.

------------------------------------------------------------------------

```
#define PGSHIFT { /* Omit details */ }
#define PGBITS { /* Omit details */ }
```

> virtual address에서 offset 부분의 시작 bit index인 0과 bit 수인 12를 각각 나타냅니다.

------------------------------------------------------------------------

```
#define PGMASK { /* Omit details */ }
```

> page offset에 해당하는 bits만 1이고 나머지는 0인 bit mask, 즉 0xfff입니다.

------------------------------------------------------------------------

```
#define PGSIZE { /* Omit details */ }
```

> byte 단위 page size로, 4,096입니다.

------------------------------------------------------------------------

```
#define pg_ofs(va) { /* Omit details */ }
```

> virtual address va에서 page offset을 추출해 반환합니다.

------------------------------------------------------------------------

```
#define pg_no(va) { /* Omit details */ }
```

> virtual address va에서 page number를 추출해 반환합니다.

------------------------------------------------------------------------

```
#define pg_round_down(va) { /* Omit details */ }
```

> va가 속한 virtual page의 시작 주소를 반환합니다. page offset을 0으로 만든 값입니다.

------------------------------------------------------------------------

```
#define pg_round_up(va) { /* Omit details */ }
```

> va를 다음 page boundary로 올림한 주소를 반환합니다.

Pintos의 virtual memory는 user 영역과 kernel 영역으로 나뉩니다. [Virtual Memory Layout](../project2/introduction.md)을 참조하십시오.

두 영역의 경계는 `KERN_BASE`입니다.

------------------------------------------------------------------------

```
#define KERN_BASE { /* Omit details */ }
```

> kernel virtual memory의 시작 주소이며 기본값은 0x8004000000입니다. user 영역은 0부터 `KERN_BASE` 전까지이고, 나머지가 kernel 영역입니다.

------------------------------------------------------------------------

```
#define is_user_vaddr(vaddr) { /* Omit details */ }
#define is_kernel_vaddr(vaddr) { /* Omit details */ }
```

> va가 각각 user 또는 kernel virtual address이면 true, 아니면 false를 반환합니다.

------------------------------------------------------------------------

x86-64의 일반적인 memory 접근은 physical address를 직접 사용하지 않습니다. Pintos는 kernel 영역과 physical memory를 일대일로 대응시킵니다. virtual address `KERN_BASE`는 physical address 0에, `KERN_BASE + 0x1234`는 physical address 0x1234에 대응하며, 실제 physical memory 크기만큼 이어집니다. 따라서 physical address에 `KERN_BASE`를 더하면 대응하는 kernel virtual address가 되고, kernel virtual address에서 `KERN_BASE`를 빼면 physical address가 됩니다.

`include/threads/vaddr.h`에는 이 변환을 위한 두 함수가 있습니다.

------------------------------------------------------------------------

```
#define ptov(paddr) { /* Omit details */ }
```

> physical address pa에 대응하는 kernel virtual address를 반환합니다. pa는 실제 physical memory 범위 안에 있어야 합니다.

------------------------------------------------------------------------

```
#define vtop(vaddr) { /* Omit details */ }
```

> kernel virtual address va에 대응하는 physical address를 반환합니다.

`include/threads/mmu.h`에는 page table을 다루는 operation이 있습니다.

------------------------------------------------------------------------

```
#define is_user_pte(pte) { /* Omit details */ }
#define is_kern_pte(pte) { /* Omit details */ }
```

> PTE가 각각 user용인지 kernel용인지 판별합니다.

------------------------------------------------------------------------

```
#define is_writable(pte) { /* Omit details */ }
```

> PTE가 가리키는 virtual address에 쓰기가 허용되는지 판별합니다.

------------------------------------------------------------------------

```
typedef bool pte_for_each_func (uint64_t *pte, void *va, void *aux);
bool pml4_for_each (uint64_t *pml4, pte_for_each_func *func, void *aux);
```

> PML4 아래의 유효한 각 entry에 보조 값 AUX와 함께 FUNC를 적용합니다. VA는 그 entry의 virtual address입니다. pte_for_each_func가 false를 반환하면 순회를 중단하고 false를 반환합니다.

다음은 `pml4_for_each`에 전달할 수 있는 `func`의 예입니다.

```
static bool
stat_page (uint64_t *pte, void *va,  void *aux) {
        if (is_user_vaddr (va))
                printf ("user page: %llx\n", va);
        if (is_writable (va))
                printf ("writable page: %llx\n", va);
        return true;
}
```
