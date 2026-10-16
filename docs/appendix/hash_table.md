> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/hash_table.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="hash-table"></a>

# 해시 테이블

Pintos는 `lib/kernel/hash.c`에서 해시 테이블 데이터 구조를 제공합니다. 이를 사용하기 위해서는 '`lib/kernel/hash.h`'라는 헤더 파일을 '`#include <hash.h>`'와 함께 포함해야 합니다. Pintos에 제공된 코드는 해시 테이블을 사용하지 않습니다. 즉, 당신이 원하는 대로 해시 테이블을 사용할 수 있고, 자신의 목적을 위해 구현을 수정하거나 무시할 수 있습니다.

가상 메모리 프로젝트의 대부분의 구현은 페이지를 프레임으로 번역하기 위해 해시 테이블을 사용합니다. 해시 테이블의 다른 사용도 찾을 수 있습니다.

<a id="data-types"></a>

## 자료형

해시 테이블은 구조 해시로 표현됩니다.

------------------------------------------------------------------------

```
struct hash;
```

> 전체 해시 테이블을 나타냅니다. `struct hash`의 실제 멤버들은 "오파크"입니다. 즉 해시 테이블을 사용하는 코드는 `struct hash` 멤버들을 직접 접근해서는 안 되며, 그럴 필요도 없습니다. 대신 해시 테이블 함수와 매크로를 사용하십시오.

해시 테이블은 `struct hash_elem` 타입의 요소에 동작한다.

------------------------------------------------------------------------

```
struct hash_elem;
```

> 해시 테이블에 넣을 구조체 안에 `struct hash_elem` 멤버를 포함하세요. `struct hash`처럼 `struct hash_elem`도 내부 구현을 직접 다루지 않는 불투명한 타입입니다. 해시 요소를 처리하는 함수는 실제 요소 타입의 포인터 대신 `struct hash_elem` 포인터를 받고 반환합니다.

종종 해시 테이블의 실제 요소와 반대로 `struct hash_elem`을 얻어야 합니다. 해시 테이블의 실제 요소를 고려하면 `&` 운영자를 사용하여 `struct hash_elem`에 대한 포인터를 얻을 수 있습니다. 다른 방향으로 이동하기 위해 `hash_entry()` 매크로를 사용하십시오.

------------------------------------------------------------------------

```
#define hash_entry (elem, type, member) { /* Omit details */ }
```

> `struct hash_elem` 포인터인 elem이 멤버로 포함된 구조체의 포인터를 반환합니다. elem을 포함하는 구조체 이름 type과, 그 구조체 안에서 elem이 가리키는 멤버 이름 member를 지정해야 합니다.
>
> 예를 들어 `h`가 `struct hash_elem *` 타입의 변수이며, struct thread 안에서 이름이 `h_elem`이고 타입이 `struct hash_elem`인 멤버를 가리킨다고 합시다. 이때 `hash_entry`(`h, struct thread, h_elem`)는 `h`이 그 내부를 가리키고 있는 `struct thread`의 주소를 반환합니다.

해시 테이블의 각 요소는 해시 테이블의 요소들 중 독특해야 할 요소들을 식별하고 구별하는 키, 즉 데이터를 포함해야 합니다. (element) 는 해시 테이블에 있는 동안, 그 키 데이터를 변경할 수 없습니다. 대신 필요한 경우 해시 테이블에서 요소를 제거하고 키를 수정하고 다시 요소를 삽입하십시오.

각 해시 테이블에 대해 키에 작용하는 두 개의 함수를 작성해야 합니다: 해시 함수와 비교 함수. 이 함수은 다음과 같은 프로토타입과 일치해야 합니다.

------------------------------------------------------------------------

```
typedef unsigned hash_hash_func (const struct hash_elem *e, void *aux);
```

> 요소 데이터의 해시를 unsigned int 범위의 값으로 반환합니다. 해시는 요소의 키에 대한 의사 난수 함수여야 합니다. 키 이외의 데이터나 키 외부의 변경 가능한 데이터에 의존해서는 안 됩니다. Pintos는 해시 함수의 기반으로 사용할 수 있는 다음 함수들을 제공합니다.
>
> `unsigned hash_bytes (const void *buf, size t *size)`
>
> > buf에서 시작하는 size바이트의 해시를 반환합니다. 구현은 32비트 워드용 범용 Fowler–Noll–Vo 해시(`http://en.wikipedia.org/wiki/Fowler_Noll_Vo_hash`)입니다.
>
> `unsigned hash_string (const char *s)`
>
> > 널 문자로 끝나는 문자열 s의 해시를 반환합니다.
>
> `unsigned hash_int (int i)`
>
> > 정수 i의 해시를 반환합니다.
>
> 만약 당신의 키가 적절한 타입의 단일 데이터라면, 해시 함수는 이러한 함수 중 하나의 출력을 직접 반환하는 것이 합리적일 것이다. 여러 데이터의 경우, 예를 들어, '^' (특유 또는) 오퍼터를 사용하여 하나 이상의 호출의 출력을 결합하고 싶을 수 있습니다. 마지막으로, 이러한 함수를 완전히 무시하고 처음부터 자신의 해시 함수를 작성할 수도 있지만, 당신의 목표는 운영 체제 커널을 구축하는 것이지 해시 함수를 설계하는 것이 아니라는 것을 기억하십시오. \[Hash 보조 데이터\] 섹션에 대한 설명을 참조하십시오.
>
> `bool hash_less_func (const struct hash_elem *a, const struct hash_elem *b, void *aux)`
>
> > 요소 a와 b의 키를 비교합니다. a가 b보다 작으면 true, 크거나 같으면 false를 반환합니다. 두 요소가 같다고 비교되면 해시값도 같아야 합니다.
>
> \[Hash 보조 데이터\] 섹션에 대한 설명을 참조하십시오. 해시 함수와 비교 함수의 예를 위해 \[해시 테이블 예제\] 섹션을 참조하십시오. 몇 가지 함수는 논증으로 세 번째 유형의 함수에 대한 포인터를 받아들인다:
>
> `void hash_action_func (struct hash_elem *element, void *aux)`
>
> > 호출자가 선택한 어떤 종류의 행동을 요소에 수행합니다. \[Hash 보조 데이터\] 섹션에 대한 설명을 참조하십시오.

<a id="basic-functions"></a>

## 기본 함수

이 함수은 해시 테이블을 만들고 파괴하고 검사합니다.

------------------------------------------------------------------------

```
bool hash_init (struct hash *hash, hash_hash_func *hash_func,
                    hash_less_func *less_func, void *aux)
```

> hash를 해시 테이블로 초기화합니다. hash func는 해시 함수, less func는 비교 함수, aux는 보조 데이터입니다. 성공하면 true, 실패하면 false를 반환합니다. `hash_init()`는 `malloc()`을 호출하며 메모리를 할당할 수 없으면 실패합니다. aux는 대개 널 포인터이며 자세한 설명은 해시의 보조 데이터 절을 참고하세요.

------------------------------------------------------------------------

```
void hash_clear (struct hash *hash, hash_action_func *action)
```

> `hash_init()`로 초기화한 hash에서 모든 요소를 제거합니다. action이 널이 아니면 각 요소에 한 번씩 호출해 요소가 사용한 메모리나 자원을 해제할 기회를 줍니다. 예를 들어 요소를 `malloc()`으로 동적 할당했다면 action에서 `free()`할 수 있습니다. `hash_clear()`는 action 호출 뒤 그 요소의 메모리에 접근하지 않으므로 안전합니다. 다만 action에서 `hash_insert()`나 `hash_delete()`처럼 해시 테이블을 변경하는 함수를 호출해서는 안 됩니다.

------------------------------------------------------------------------

```
void hash_destroy (struct hash *hash, hash_action_func *action);
```

> action이 널이 아니면 `hash_clear()`와 같은 방식으로 hash의 각 요소에 호출합니다. 이후 hash가 보유한 메모리를 해제합니다. 다시 hash_init()을 호출하기 전에는 hash를 어떤 해시 테이블 함수에도 전달하면 안 됩니다.

------------------------------------------------------------------------

```
size_t hash_size (struct hash *hash);
```

> 현재 hash에 저장된 요소 수를 반환합니다.

------------------------------------------------------------------------

```
bool hash_empty (struct hash *hash);
```

> hash가 비어 있으면 true, 요소가 하나라도 있으면 false를 반환합니다.

<a id="search-functions"></a>

## 검색 함수

이 함수들 각각은 제공된 함수와 동등한 요소를 비교하는 해시 테이블을 검색합니다. 검색의 성공에 따라 그들은 새로운 요소를 해시 테이블에 삽입하거나 단순히 검색 결과를 반환하는 것과 같은 작업을 수행합니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_insert (struct hash *hash, struct hash elem *element);
```

> hash에서 element와 같은 요소를 찾습니다. 없으면 element를 삽입하고 널 포인터를 반환합니다. 이미 있으면 hash를 바꾸지 않고 기존 요소를 반환합니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_replace (struct hash *hash, struct hash elem *element);
```

> element를 hash에 삽입합니다. 같은 요소가 이미 있다면 제거합니다. 제거한 요소를 반환하고, 같은 요소가 없었다면 널 포인터를 반환합니다.
>
> 반환된 요소와 관련된 자원은 호출자가 적절히 해제해야 합니다. 예를 들어 해시 테이블 요소를 `malloc()`으로 동적 할당했다면 더 이상 필요하지 않을 때 호출자가 그 요소를 `free()`해야 합니다.

다음 함수에 전달된 요소는 해시 및 비교 목적으로만 사용됩니다. 그것은 실제로 해시 테이블에 삽입되지 않습니다. 따라서, 요소의 핵심 데이터만 초기화되어야 하며, 요소의 다른 데이터는 사용되지 않습니다. 종종 요소 타입의 인스턴스를 로컬 변수로 선언하고 키 데이터를 초기화하고 그 `struct hash_elem`의 주소를 `hash_find()` 또는 `hash_delete()`로 전달하는 것이 의미가 있습니다. 예를 들어 해시 테이블 예시를 참조하십시오. (큰 구조를 지역 변수로 할당해서는 안 됩니다. 자세한 내용은 [구조 스레드](threads.md) 참조.)

------------------------------------------------------------------------

```
struct hash_elem *hash_find (struct hash *hash, struct hash elem *element);
```

> hash에서 element와 같은 요소를 찾아 반환합니다. 없으면 널 포인터를 반환합니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_delete (struct hash *hash, struct hash elem *element);
```

> hash에서 element와 같은 요소를 찾습니다. 있으면 제거한 뒤 반환합니다. 없으면 hash를 바꾸지 않고 널 포인터를 반환합니다.
>
> 반환된 요소와 관련된 자원은 호출자가 적절히 해제해야 합니다. 예를 들어 해시 테이블 요소를 `malloc()`로 동적 할당했다면 더 이상 필요하지 않을 때 호출자가 그 요소를 `free()`해야 합니다.

<a id="iteration-functions"></a>

## 순회 함수

이 함수는 해시 테이블의 요소들을 반복하는 것을 허용합니다. 두 개의 인터페이스가 제공됩니다. 첫 번째는 각 요소에 작용하기 위해 hash_action_func를 작성하고 공급하는 것을 요구합니다.

------------------------------------------------------------------------

```
void hash_apply (struct hash *hash, hash action func *action);
```

> hash의 각 요소마다 임의 순서로 action을 한 번씩 호출합니다. action은 `hash_insert()`나 `hash_delete()`처럼 해시 테이블을 변경할 수 있는 함수를 호출해서는 안 됩니다. 요소의 다른 데이터는 변경해도 되지만 키 데이터는 바꿔서는 안 됩니다.

두 번째 인터페이스는 "이터레이터" 데이터 타입을 기반으로 합니다. 어휘적으로, 반복자는 다음과 같이 사용됩니다.

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

> 해시 테이블 안에 있는 위치를 나타냅니다. `hash_insert()` 또는 `hash_delete()`와 같은 해시 테이블을 수정할 수 있는 함수를 호출하면 해당 해시 테이블 내 모든 반복자를 무효화합니다.
>
> 구조 해시 및 구조 해시_elem와 마찬가지로 구조 해시_elem는 불투명합니다.

------------------------------------------------------------------------

```
void hash_first (struct hash iterator *iterator, struct hash *hash);
```

> 해시의 첫 번째 요소 직전에 반복자를 초기화합니다.

```
struct hash_elem *hash_next (struct hash iterator *iterator);
```

> iterator를 hash의 다음 요소로 이동하고 그 요소를 반환합니다. 남은 요소가 없으면 널 포인터를 반환합니다. `hash_next()`가 iterator에 대해 널을 반환한 뒤 다시 호출하면 동작은 정의되지 않습니다.

------------------------------------------------------------------------

```
struct hash_elem *hash_cur (struct hash iterator *iterator);
```

> iterator에 대해 `hash_next()`가 가장 최근 반환한 값을 반환합니다. `hash_first()`를 호출한 뒤 `hash_next()`를 처음 호출하기 전에는 동작이 정의되지 않습니다.

<a id="hash-table-example"></a>

## 해시 테이블 예제

해시 테이블에 넣고 싶은 `struct page`라는 구조가 있다고 가정해보자. 먼저, `struct page`을 정의하여 `struct hash_elem` 멤버를 포함합니다.

```
struct page {
    struct hash_elem hash_elem; /* Hash table element. */
    void *addr; /* Virtual address. */
    /* . . . other members. . . */
};
```

우리는 addr를 키로 사용하여 해시 함수와 비교 함수를 작성합니다 포인터를 바이트에 따라 해시할 수 있으며, `<` 오퍼레이터는 포인터를 비교하기 위해 잘 작동합니다.

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

(이 함수의 프로토타입에서 `UNUSED`의 사용은 aux가 사용되지 않는다는 경고를 억제합니다. `UNUSED`에 대한 자세한 내용은 함수 및 파라미터 속성을 참조하십시오. 해시 보조 자료를 참조하여 aux에 대한 설명을 참조하십시오.)

그러면 아래와 같은 해시 테이블을 만들 수 있습니다.

```
struct hash pages;
hash_init (&pages, page_hash, page_less, NULL);
```

이제 우리가 만든 해시 테이블을 조작할 수 있습니다. 만약 `p`가 `struct page`에 대한 포인터라면, 우리는 다음으로 해시 테이블에 삽입할 수 있습니다.

```
hash_insert (&pages, &p->hash_elem);
```

만약 페이지가 이미 같은 주소를 가진 페이지를 포함할 가능성이 있다면, 우리는 `hash_insert()'`s 반환 값을 확인해야 합니다.

해시 테이블에서 요소를 검색하려면 `hash_find()`을 사용합니다. 이것은 약간의 설정이 필요하죠. 왜냐하면 `hash_find()`는 비교할 수 있는 요소가 필요하기 때문입니다. 다음은 가상 주소를 기반으로 페이지를 찾아 반환하는 함수입니다. 페이지는 파일 범위에서 정의된 것으로 가정합니다.

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

여기서 `struct page`은 상당히 작다는 가정에서 로컬 변수로 할당된다. 큰 구조를 지역 변수로 할당해서는 안 됩니다.

비슷한 함수는 `hash_delete()`을 사용하여 주소로 페이지를 삭제할 수 있습니다.

<a id="auxiliary-data"></a>

## 보조 데이터

위의 예와 같은 간단한 경우, aux 매개 변수가 필요하지 않습니다. 이러한 경우, aux에 대해 `hash_init()`에 null 포인터를 전달하고 해시 함수와 비교 함수에 전달된 값을 무시합니다. (Aux 매개 변수를 사용하지 않으면 컴파일러 경고를 받게 되지만, 예를 들어 `UNUSED` 매크로로 끄거나 그냥 무시할 수 있습니다.)

***AUX***은 해시 테이블의 데이터의 일부 속성이 일정하고 해시 또는 비교에 필요한 경우 유용하지만 데이터 항목 자체에 저장되지 않습니다. 예를 들어, 해시 테이블의 항목이 고정된 길이의 문자열이지만 항목 자체는 고정된 길이가 무엇인지 표시하지 않으면, 길이를 aux 매개 변수로 통과시킬 수 있습니다.

<a id="synchronization"></a>

## 동기화

해시 테이블은 내부 동기화를 수행하지 않습니다. 해시 테이블 함수에 대한 호출을 동기화하는 것은 호출자의 책임입니다. 일반적으로, `hash_find()` 또는 `hash_next()`와 같은 해시 테이블을 조사하지만 수정하지 않는 모든 함수는 동시에 실행될 수 있습니다. 그러나 이러한 함수는 주어진 해시 테이블을 수정할 수 있는 함수, 예를 들어 `hash_insert()` 또는 `hash_delete()`와 같은 함수와 동시에 안전하게 실행될 수 없으며, 주어진 해시 테이블을 수정할 수 있는 하나 이상의 함수는 동시에 안전하게 실행될 수 없습니다.

또한 해시 테이블 요소에 있는 데이터에 대한 접근을 동기화하는 것은 호출자의 책임입니다. 이러한 데이터에 대한 접근을 동기화하는 방법은 다른 데이터 구조와 마찬가지로 어떻게 설계되고 조직되는지에 달려 있습니다.
