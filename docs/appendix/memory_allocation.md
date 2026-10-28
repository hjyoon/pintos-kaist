> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/memory_allocation.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="memory-allocation"></a>

# Memory Allocation

Pintos에는 page 단위로 할당하는 allocator와 임의 크기의 block을 할당하는 allocator가 있습니다.

<a id="page-allocator"></a>

## Page Allocator

`include/threads/palloc.h`에 선언된 page allocator는 page 단위로 memory를 할당합니다. 보통 한 page씩 사용하지만 여러 개의 연속 page를 한 번에 요청할 수도 있습니다.

할당할 memory는 kernel pool과 user pool로 나뉩니다. 기본적으로 1 MB 이상의 system memory를 절반씩 나누며, **ul** kernel 옵션으로 비율을 바꿀 수 있습니다. 각 요청은 한 pool에서 할당하므로 한쪽이 비어도 다른 쪽에는 여유가 있을 수 있습니다. user process용 memory는 user pool, 나머지는 kernel pool을 사용합니다. 원문은 이 구분이 Project 3부터 중요해지고 그전에는 kernel pool을 사용한다고 설명합니다.

> **버전 주의:** 실제 skeleton의 user page 할당에는 Project 2에서도 PAL_USER를 사용하는 코드가 있습니다. 위 문장은 원문의 프로젝트 진행 설명이며, user page를 kernel pool로 바꾸라는 지시로 해석하지 마십시오.

각 pool은 page마다 bit 하나를 쓰는 bitmap으로 사용 상태를 추적합니다. n개 page 요청이 들어오면 false인 연속 bit n개를 찾아 true로 바꿉니다. 이를 first-fit allocation이라고 합니다.

이 allocator도 fragmentation의 영향을 받습니다. 빈 page가 n개 이상이어도 사용 중인 page 사이에 흩어져 있으면 연속 n개를 할당할 수 없습니다. 심하면 절반이 비어도 연속한 두 page를 할당하지 못합니다. 한 page 요청은 fragmentation 때문에 실패하지 않으므로 여러 연속 page 요청은 가능한 한 줄이십시오.

interrupt context에서는 page를 할당할 수 없지만 해제할 수는 있습니다.

page를 해제하면 debugging을 돕기 위해 모든 byte를 **0xcc**로 채웁니다. [Debugging Tips](debugging_tools.md#tips)를 참조하십시오.

주요 type과 함수는 다음과 같습니다.

------------------------------------------------------------------------

```
void *palloc_get_page (enum palloc_flags flags)
void *palloc_get_multiple (enum palloc_flags flags, size_t page_cnt)
```

> 각각 한 page 또는 연속한 *page_cnt*개 page를 할당해 반환합니다. 할당할 수 없으면 null pointer를 반환합니다.
>
> *flags*에는 다음 flag를 조합할 수 있습니다.
>
> - `PAL_ASSERT`
>
>   할당 실패 시 kernel panic을 발생시킵니다. kernel 초기화 단계에만 적절합니다. user process 때문에 kernel이 panic해서는 안 됩니다.
>
> - `PAL_ZERO`
>
>   반환하기 전에 모든 byte를 0으로 채웁니다. 지정하지 않으면 새 page의 초기 내용은 보장되지 않습니다.
>
> - `PAL_USER`
>
>   user pool에서 할당합니다. 지정하지 않으면 kernel pool을 사용합니다.

------------------------------------------------------------------------

```
void palloc_free_page (void *page)
void palloc_free_multiple (void *pages, size_t page_cnt)
```

> *pages*부터 한 page 또는 연속한 page_cnt개 page를 해제합니다. 모두 `palloc_get_page()`나 `palloc_get_multiple()`로 할당한 page여야 합니다.

<a id="block-allocator"></a>

## Block Allocator

`threads/malloc.h`의 block allocator는 임의 크기의 block을 할당합니다. page allocator 위에 구현되어 있으며, 반환하는 block의 memory는 kernel pool에서 가져옵니다.

크기에 따라 두 방식을 사용합니다. 1 kB 이하, 즉 page size의 1/4 이하인 요청은 16 bytes 이상인 가장 가까운 2의 거듭제곱 크기로 올림합니다. 그런 뒤 해당 크기 block만 저장하는 page에서 할당합니다.

1 kB보다 큰 요청은 작은 관리 비용을 더한 크기를 page 단위로 올림한 뒤, page allocator에 필요한 수의 연속 page를 요청합니다.

요청 크기와 실제 block 크기의 차이는 사용하지 못하는 공간입니다. 실제 OS는 이 낭비를 줄이도록 allocator를 조정하지만 교육용 Pintos에서는 크게 중요하지 않습니다.

작은 요청은 필요한 page를 얻을 수 있으면 성공하며, 대부분 이미 할당된 page의 일부를 재사용하므로 새 page도 필요하지 않습니다. 반면 큰 요청은 항상 page allocator를 호출합니다. 여러 연속 page가 필요하면 fragmentation 때문에 실패할 수 있으므로 큰 할당, 특히 약 4 kB를 넘는 요청은 줄이십시오.

block을 해제하면 debugging을 돕기 위해 모든 byte를 **0xcc**로 채웁니다. [Debugging Tips](debugging_tools.md#tips)를 참조하십시오.

interrupt context에서는 block allocator를 호출할 수 없습니다.

다음 함수의 interface는 같은 이름의 표준 C library 함수와 같습니다.

------------------------------------------------------------------------

```
void *malloc (size_t size)
```

> kernel pool에서 최소 *size* bytes의 block을 할당해 반환합니다. size가 0이거나 공간이 부족하면 null pointer를 반환합니다.

------------------------------------------------------------------------

```
void *calloc (size_t a, size_t b)
```

> kernel pool에서 최소 a \* b bytes의 block을 할당해 0으로 채운 뒤 반환합니다. a나 b가 0이거나 공간이 부족하면 null pointer를 반환합니다.

------------------------------------------------------------------------

```
void *realloc (void *block, size_t new_size)
```

> *block*의 크기를 *new_size* bytes로 바꿉니다. 위치가 이동할 수 있습니다. 성공하면 새 block을 반환하고 이전 block에는 더 이상 접근해서는 안 됩니다. 실패하면 null pointer를 반환하며 이전 block은 계속 유효합니다. block이 null이면 `malloc()`과 같고, new_size가 0이면 `free()`와 같습니다.

------------------------------------------------------------------------

```
void free (void *block)
```

> `malloc()`, `calloc()`, `realloc()` 중 하나로 반환받고 아직 해제하지 않은 *block*을 해제합니다.
