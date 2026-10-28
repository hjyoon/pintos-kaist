> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/swapping.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="swap-inout"></a>

# Swap In/Out

memory swapping은 physical memory를 효율적으로 쓰기 위한 memory reclamation 기법입니다. main memory의 frame을 모두 할당하면 user program의 추가 요청을 처리할 수 없습니다. 현재 사용하지 않는 frame의 내용을 disk로 swap out하면 그 memory를 다른 프로그램에 제공할 수 있습니다.

swapping은 OS가 수행합니다. memory가 부족한데 할당 요청이 들어오면 page 하나를 골라 swap disk로 evict하고, frame 내용을 그대로 복사합니다. process가 나중에 그 page에 접근하면 disk의 내용을 memory로 다시 가져와 복원합니다.

eviction 대상은 anonymous page일 수도, file-backed page일 수도 있습니다. 이 절에서 두 경우를 다룹니다.

swapping 함수들은 직접 이름으로 호출하기보다 `struct page_operations file_ops`의 function pointer를 통해 호출합니다. 각 page initializer가 해당 operation을 등록합니다.

<a id="anonymous-page"></a>

## Anonymous Page

**`vm/anon.c`의 `vm_anon_init`와 `anon_initializer`를 수정하십시오.** anonymous page에는 원래 backing store가 없으므로, swapping을 위해 임시 backing store인 swap disk를 제공합니다. 이를 이용해 anonymous page의 swap을 구현합니다.

------------------------------------------------------------------------

```
void vm_anon_init (void);
```

> swap disk를 초기화합니다. 사용 중인 영역과 빈 영역을 관리할 자료구조도 필요합니다. swap 공간은 PGSIZE, 즉 4096-byte 단위로 관리합니다.

------------------------------------------------------------------------

```
bool anon_initializer (struct page *page, enum vm_type type, void *kva);
```

> anonymous page의 initializer입니다. swapping에 필요한 정보를 `anon_page`에 추가해야 합니다.

`vm/anon.c`의 `anon_swap_in`와 `anon_swap_out`를 구현하십시오. swap in하려면 먼저 swap out된 page가 있어야 하므로 `anon_swap_in`보다 `anon_swap_out`를 먼저 구현하면 편리합니다. 데이터를 swap disk로 옮기고 안전하게 memory로 복원해야 합니다.

------------------------------------------------------------------------

```
static bool anon_swap_in (struct page *page, void *kva);
```

> swap disk의 데이터를 memory로 읽어 anonymous page를 swap in합니다. disk상의 위치는 swap out할 때 page 구조체에 저장해 두어야 합니다. [Swap table 관리](introduction.md)에 따라 swap table도 갱신하십시오.

------------------------------------------------------------------------

```
static bool anon_swap_out (struct page *page);
```

> memory의 내용을 swap disk에 복사해 anonymous page를 swap out합니다. swap table에서 빈 swap slot을 찾고 page 내용을 복사한 뒤, 그 위치를 page 구조체에 저장합니다. 빈 slot이 없으면 kernel panic을 발생시켜도 됩니다.

<a id="file-mapped-page"></a>

## File-Backed Page

file-backed page의 내용은 파일에서 왔으므로 mmap으로 연결한 파일 자체를 backing store로 사용해야 합니다. 즉, eviction 시 원래 파일로 write-back합니다. `vm/file.c`의 `file_backed_swap_in`와 `file_backed_swap_out`를 구현하십시오. 설계에 따라 `file_backed_init`와 `file_initializer`도 수정할 수 있습니다.

------------------------------------------------------------------------

```
static bool file_backed_swap_in (struct page *page, void *kva);
```

> 파일 내용을 읽어 `kva`에 page를 swap in합니다. file system과의 synchronization이 필요합니다.

------------------------------------------------------------------------

```
static bool file_backed_swap_out (struct page *page);
```

> page 내용을 파일에 write-back해 swap out합니다. 먼저 dirty 여부를 확인하고, dirty가 아니면 파일을 수정할 필요가 없습니다. swap out한 뒤에는 해당 page의 dirty bit를 해제하십시오.
