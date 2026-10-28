> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/hash_table.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="hash-table"></a>

# Hash Table

Pintos는 `lib/kernel/hash.c`에 hash table을 제공합니다. 사용하려면 `#include <hash.h>`로 header `lib/kernel/hash.h`를 포함하십시오. 기본 코드에서는 이 hash table을 사용하지 않으므로 그대로 활용하거나, 목적에 맞게 수정하거나, 사용하지 않아도 됩니다.

> **원문 주의:** 아래 일부 API prototype에는 struct hash elem, hash action func, size t처럼 underscore가 빠진 type 이름이나 잘못된 parameter 표기가 있습니다. 원문 표기는 보존했으며, 실제 선언은 이 저장소의 include/lib/kernel/hash.h를 확인하십시오.

virtual memory 프로젝트에서는 page와 frame의 대응을 관리할 때 hash table을 많이 사용합니다. 다른 용도로 활용해도 됩니다.

<a id="data-types"></a>

## Data Type

hash table은 struct hash로 표현합니다.

------------------------------------------------------------------------

```
struct hash;
```

> hash table 전체를 나타냅니다. `struct hash`의 member는 opaque이므로 내부에 직접 접근하지 말고, 그럴 필요도 없습니다. `struct hash`를 직접 다루는 대신 제공된 함수와 macro를 사용하십시오.

hash table은 `struct hash_elem` type의 element를 다룹니다.

------------------------------------------------------------------------

```
struct hash_elem;
```

> hash table에 넣을 구조체 안에 `struct hash_elem` member를 포함하십시오. `struct hash`와 마찬가지로 `struct hash_elem`도 opaque입니다. hash 함수를 비롯한 element 관련 함수는 실제 사용자 구조체가 아니라 `struct hash_elem`의 pointer를 주고받습니다.

실제 element에서 `struct hash_elem`를 얻거나 반대로 돌아가야 할 일이 많습니다. 실제 구조체에서 `&` 연산자로 `struct hash_elem`의 주소를 얻고, 반대 방향에는 `hash_entry()`를 사용하십시오.

------------------------------------------------------------------------

```
#define hash_entry (elem, type, member) { /* Omit details */ }
```

> `struct hash_elem` pointer인 elem을 member로 포함한 구조체의 pointer를 반환합니다. type은 그 구조체 type이고, member는 elem이 가리키는 member의 이름입니다.
>
> 예를 들어 `h`가 `struct hash_elem *` type이고 struct thread의 `h_elem`라는 `struct hash_elem` member를 가리킨다고 합시다. 그러면 `hash_entry`(`h, struct thread, h_elem`)는 `h`를 포함한 `struct thread`의 주소를 반환합니다.

각 element는 다른 element와 구별하는 고유 key를 가져야 합니다. key가 아닌 데이터는 중복되어도 됩니다. table에 들어 있는 동안 key를 바꿔서는 안 됩니다. 변경하려면 먼저 element를 제거하고 key를 바꾼 뒤 다시 삽입하십시오.

각 hash table에는 key를 다루는 hash function과 comparison function을 작성해야 합니다. 다음 원형을 따릅니다.

------------------------------------------------------------------------

```
typedef unsigned hash_hash_func (const struct hash_elem *e, void *aux);
```

> element의 key를 기반으로 unsigned int 범위의 hash 값을 반환합니다. key가 아닌 member나 key 외의 변하는 값에 의존해서는 안 됩니다. Pintos는 hash function을 만드는 데 사용할 다음 함수들을 제공합니다.
>
> `unsigned hash_bytes (const void *buf, size t *size)`
>
> > buf부터 size bytes의 hash를 구합니다. 구현은 32-bit word용 범용 Fowler–Noll–Vo hash(`http://en.wikipedia.org/wiki/Fowler_Noll_Vo_hash`)입니다.
>
> `unsigned hash_string (const char *s)`
>
> > null-terminated 문자열 s의 hash를 반환합니다.
>
> `unsigned hash_int (int i)`
>
> > 정수 i의 hash를 반환합니다.
>
> key가 적절한 단일 값이면 이 함수 중 하나의 결과를 바로 반환해도 됩니다. 여러 값으로 구성된 key라면 여러 호출 결과를 '^', 즉 XOR 등으로 조합할 수 있습니다. 직접 hash function을 작성해도 되지만, 이 과제의 목적은 hash function 설계가 아니라 kernel 구현임을 기억하십시오. aux는 아래 Auxiliary Data 절에서 설명합니다.
>
> `bool hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux)`
>
> > a와 b의 key를 비교합니다. a가 b보다 작으면 true, 크거나 같으면 false를 반환합니다. 같은 key로 판정되는 두 element는 같은 hash 값을 가져야 합니다.
>
> aux는 Auxiliary Data 절을, 함수 예제는 Hash Table Example 절을 참조하십시오. 일부 함수는 다음 type의 callback도 받습니다.
>
> `void hash_action_func (struct hash_elem *element, void *aux)`
>
> > element에 대해 호출자가 정한 작업을 수행합니다. aux의 의미는 Auxiliary Data 절을 참조하십시오.

<a id="basic-functions"></a>

## 기본 함수

다음 함수는 hash table을 초기화하고 해제하거나 상태를 조회합니다.

------------------------------------------------------------------------

```
bool hash_init (struct hash *hash, hash_hash_func *hash_func,
                    hash_less_func *less_func, void *aux)
```

> hash를 초기화합니다. hash_func는 hash function, less_func는 comparison function, aux는 보조 데이터입니다. 성공하면 true, `hash_init()` 내부에서 `malloc()`에 필요한 memory를 얻지 못하는 등 실패하면 false를 반환합니다. aux는 보통 null pointer이며 아래에서 자세히 설명합니다.

------------------------------------------------------------------------

```
void hash_clear (struct hash *hash, hash_action_func *action)
```

> `hash_init()`로 초기화한 hash의 모든 element를 제거합니다. action이 null이 아니면 element마다 한 번 호출하므로, 여기서 element의 memory 등 자원을 해제할 수 있습니다. 예를 들어 `malloc()`으로 동적 할당했다면 action에서 `free()`할 수 있습니다. `hash_clear()`는 action 이후 해당 element의 memory에 다시 접근하지 않으므로 안전합니다. 단, action 안에서 `hash_insert()`나 `hash_delete()` 등 table을 바꾸는 함수를 호출해서는 안 됩니다.

------------------------------------------------------------------------

```
void hash_destroy (struct hash *hash, hash_action_func *action);
```

> action이 null이 아니면 `hash_clear()`와 같은 방식으로 모든 element에 호출합니다. 그 뒤 table 자체가 보유한 memory를 해제합니다. 다시 hash_init()하기 전에는 어떤 hash table 함수에도 이 hash를 전달해서는 안 됩니다.

------------------------------------------------------------------------

```
size_t hash_size (struct hash *hash);
```

> hash에 저장된 element 수를 반환합니다.

------------------------------------------------------------------------

```
bool hash_empty (struct hash *hash);
```

> hash가 비어 있으면 true, element가 하나 이상 있으면 false를 반환합니다.

<a id="search-functions"></a>

## 검색 함수

주어진 element와 key가 같은 항목을 찾고, 결과에 따라 새 항목을 삽입하거나 검색 결과를 반환합니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_insert (struct hash *hash, struct hash elem *element);
```

> element와 같은 key의 항목을 찾습니다. 없으면 element를 삽입하고 null pointer를 반환합니다. 이미 있으면 table을 바꾸지 않고 기존 element를 반환합니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_replace (struct hash *hash, struct hash elem *element);
```

> element를 삽입하고, 같은 key의 기존 element가 있으면 제거해 반환합니다. 없으면 null pointer를 반환합니다.
>
> 반환된 element의 자원 정리는 호출자의 책임입니다. 예를 들어 `malloc()`으로 할당했다면 더 이상 필요하지 않을 때 `free()`해야 합니다.

아래 함수에 전달하는 element는 hash 계산과 key 비교에만 쓰이며 table에 실제로 삽입되지 않습니다. 따라서 key만 초기화하면 됩니다. 작은 구조체라면 local variable로 만들고 key를 설정한 뒤 `struct hash_elem`의 주소를 `hash_find()`나 `hash_delete()`에 전달하면 편리합니다. 아래 예제를 참조하십시오. 큰 구조체는 stack에 두지 마십시오. [struct thread](threads.md)를 참조하십시오.

------------------------------------------------------------------------

```
struct hash_elem *hash_find (struct hash *hash, struct hash elem *element);
```

> element와 같은 key의 항목을 찾아 반환합니다. 없으면 null pointer를 반환합니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_delete (struct hash *hash, struct hash elem *element);
```

> element와 같은 key의 항목을 찾아 table에서 제거하고 반환합니다. 없으면 table을 바꾸지 않고 null pointer를 반환합니다.
>
> 반환된 element의 자원 정리는 호출자의 책임입니다. 예를 들어 `malloc()`으로 할당했다면 더 이상 필요하지 않을 때 `free()`해야 합니다.

<a id="iteration-functions"></a>

## 순회 함수

table의 모든 element를 순회하는 두 interface가 있습니다. 첫 번째는 각 element에 적용할 hash_action_func를 전달하는 방식입니다.

------------------------------------------------------------------------

```
void hash_apply (struct hash *hash, hash action func *action);
```

> 순서는 정해져 있지 않지만 hash의 각 element에 action을 한 번씩 호출합니다. action 안에서 `hash_insert()`나 `hash_delete()` 등 table을 변경하는 함수를 호출하면 안 됩니다. element의 key도 변경할 수 없지만 나머지 데이터는 수정해도 됩니다.

두 번째 방식은 iterator를 사용합니다. 일반적인 사용 예는 다음과 같습니다.

------------------------------------------------------------------------

```
struct hash_iterator i;
hash_first (&i, h);
while (hash_next (&i)) {
    struct foo *f = hash_entry (hash_cur (&i), struct foo, elem);
    . . . do something with f . . .
}
```

------------------------------------------------------------------------

```
struct hash_iterator;
```

> hash table의 순회 위치를 나타냅니다. `hash_insert()`나 `hash_delete()` 등 table을 변경할 수 있는 함수를 호출하면 그 table의 모든 iterator가 무효가 됩니다. 다른 hash 관련 type과 마찬가지로 iterator도 opaque입니다.
>
> **원문 주의:** 원문의 마지막 문장은 struct hash_elem을 반복해 적지만, 여기서 설명하는 대상은 struct hash_iterator입니다.

------------------------------------------------------------------------

```
void hash_first (struct hash iterator *iterator, struct hash *hash);
```

> iterator를 hash의 첫 element 바로 앞 위치로 초기화합니다.

```
struct hash_elem *hash_next (struct hash iterator *iterator);
```

> 다음 element로 이동하고 그 element를 반환합니다. 남은 element가 없으면 null pointer를 반환합니다. `hash_next()`가 null을 반환한 iterator에 다시 호출하면 동작이 정의되지 않습니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_cur (struct hash iterator *iterator);
```

> iterator에서 가장 최근 `hash_next()`가 반환한 값을 반환합니다. `hash_first()`로 초기화한 뒤 처음 `hash_next()`를 호출하기 전에는 동작이 정의되지 않습니다.

<a id="hash-table-example"></a>

## Hash Table 예제

`struct page`라는 구조체를 hash table에 넣는다고 합시다. 먼저 `struct page` 안에 `struct hash_elem` member를 추가합니다.

```
struct page {
    struct hash_elem hash_elem; /* Hash table element. */
    void *addr; /* Virtual address. */
    /* . . . other members. . . */
};
```

addr를 key로 사용하는 hash function과 comparison function을 작성합니다. pointer는 자신의 byte 표현으로 hash를 구할 수 있고, 이 예제에서는 `<` 연산자로 비교합니다.

```
/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->addr, sizeof p->addr);
}
```

```
/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->addr < b->addr;
}
```

함수 원형의 `UNUSED`는 aux를 사용하지 않는다는 경고를 막습니다. `UNUSED`는 Function and Parameter Attributes 절을, aux는 Auxiliary Data 절을 참조하십시오.

이제 다음과 같이 hash table을 만들 수 있습니다.

```
struct hash pages;
hash_init (&pages, page_hash, page_less, NULL);
```

`p`가 `struct page` pointer라면 다음과 같이 삽입할 수 있습니다.

```
hash_insert (&pages, &p->hash_elem);
```

같은 addr의 page가 이미 있을 수 있다면 `hash_insert()'`의 반환값을 확인해야 합니다.

검색에는 `hash_find()`를 사용합니다. `hash_find()`는 비교용 element를 받으므로 약간의 준비가 필요합니다. 다음 예제는 pages가 file scope에 있다고 가정하고, virtual address로 page를 찾아 반환합니다.

```
/* Returns the page containing the given virtual address, or a null pointer if no such page exists. */
struct page *
page_lookup (const void *address) {
  struct page p;
  struct hash_elem *e;

  p.addr = address;
  e = hash_find (&pages, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}
```

여기서는 구조체가 작다고 가정해 `struct page`를 local variable로 사용합니다. 큰 구조체를 이렇게 할당해서는 안 됩니다.

비슷한 방식으로 `hash_delete()`를 이용해 주소에 해당하는 page를 삭제할 수 있습니다.

<a id="auxiliary-data"></a>

## Auxiliary Data

앞의 간단한 예제에는 aux가 필요하지 않습니다. 이때는 `hash_init()`의 aux에 null pointer를 전달하고 hash·comparison 함수가 받은 값을 무시하면 됩니다. 사용하지 않는 parameter 경고는 예제처럼 `UNUSED`로 끄거나 그대로 두어도 됩니다.

***aux***는 hash 계산이나 비교에 필요한 불변 속성이 element 자체에는 저장되어 있지 않을 때 유용합니다. 예를 들어 element가 고정 길이 문자열인데 그 길이를 스스로 표시하지 않는다면, 길이를 aux로 전달할 수 있습니다.

<a id="synchronization"></a>

## Synchronization

hash table 내부에는 synchronization이 없습니다. 호출자가 함수 호출을 보호해야 합니다. `hash_find()`나 `hash_next()`처럼 조회만 하는 작업끼리는 동시에 실행해도 됩니다. 그러나 `hash_insert()`나 `hash_delete()`처럼 table을 변경하는 작업과는 동시에 실행할 수 없고, 변경 작업 여러 개도 동시에 실행할 수 없습니다.

element에 저장한 데이터의 접근도 호출자가 synchronize해야 합니다. 구체적인 방식은 다른 자료구조와 마찬가지로 데이터의 설계와 구성에 따라 달라집니다.
