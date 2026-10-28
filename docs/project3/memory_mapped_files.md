> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/memory_mapped_files.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="memory-mapped-files"></a>

# Memory-Mapped Files

이 절에서는 memory-mapped page를 구현합니다. anonymous page와 달리 file-backed mapping이며, page의 내용은 기존 파일의 데이터에 대응합니다. page fault가 발생하면 physical frame을 할당하고 파일 내용을 memory로 읽어 옵니다. unmap하거나 swap out할 때는 변경 내용을 파일에 반영합니다.

<a id="mmap-and-munmap-system-call"></a>

## `mmap`과 `munmap` System Call

**Memory-mapped file용 system call `mmap`과 `munmap`을 구현하십시오.** mmap 영역은 lazy loading이어야 하며 map한 파일 자체를 backing store로 사용해야 합니다. 두 system call을 위해 `vm/file.c`의 `do_mmap`와 `do_munmap`를 구현하고 사용하십시오.

------------------------------------------------------------------------

```
void *mmap (void *addr, size_t length, int writable, int fd, off_t offset);
```

> `fd`로 열린 파일의 `offset` byte 위치부터 `length` bytes를 process의 virtual address `addr`에 map합니다. mapping은 `addr`부터 연속된 virtual page들로 구성합니다. 파일 크기가 PGSIZE의 배수가 아니면 마지막 page의 일부가 EOF 밖으로 나갈 수 있습니다. 그 부분은 fault 시 0으로 채우고, disk에 write-back할 때는 버려야 합니다. 성공하면 mapping의 virtual address를, 실패하면 유효한 mapping 주소가 아닌 NULL을 반환합니다.

> **원문 주의:** 원문에는 이어서 “entire file”이라는 표현이 있지만, 범위는 이 함수의 length·offset argument와 첫 문장의 설명을 함께 읽어 판단해야 합니다.

`mmap`은 fd로 열린 파일의 길이가 0이면 실패할 수 있습니다. addr가 page-aligned가 아니거나, mapping 범위가 stack·executable page 등 기존 page와 겹치면 반드시 실패해야 합니다. Linux에서는 `addr`가 NULL이면 적당한 주소를 찾아 주지만, 이 과제에서는 주어진 `addr`만 사용하면 됩니다. Pintos 일부 코드가 virtual page 0을 비워 둔다고 가정하므로 `addr`가 0이면 실패해야 합니다. `length`이 0인 경우에도 실패해야 하며, console input·output의 file descriptor는 map할 수 없습니다.

memory-mapped page도 anonymous page처럼 lazy하게 할당해야 합니다. page 객체를 만들 때 `vm_alloc_page_with_initializer`나 `vm_alloc_page`를 사용할 수 있습니다.

------------------------------------------------------------------------

```
void munmap (void *addr);
```

> `addr`에서 시작하는 mapping을 해제합니다. 이 주소는 같은 process의 이전 mmap이 반환한 주소여야 하며, 아직 unmap하지 않은 mapping이어야 합니다.

`exit` 호출이나 다른 이유로 process가 종료되면 모든 mapping을 암묵적으로 해제합니다. 명시적·암묵적 unmap 모두에서 process가 수정한 page만 파일에 write-back해야 합니다. 수정하지 않은 page는 기록하면 안 됩니다. 그 뒤 process의 virtual page 목록에서 page를 제거합니다.

파일을 close하거나 remove해도 mapping은 사라지지 않습니다. Unix와 마찬가지로 한 번 만든 mapping은 `munmap`을 호출하거나 process가 종료될 때까지 유효합니다. [열린 파일의 삭제](../project2/FAQ.md)를 참조하십시오. 각 mapping마다 파일을 독립적으로 참조하도록 `file_reopen`을 사용해야 합니다.

여러 process가 같은 파일을 map했을 때 서로 일관된 데이터를 보게 할 필요는 없습니다. Unix는 같은 physical page를 공유해 이를 처리하며, mmap argument로 shared mapping인지 private mapping, 즉 copy-on-write인지도 지정할 수 있습니다.

필요에 따라 `vm/vm.c`의 `vm_file_init`와 `vm_file_initializer`를 수정할 수 있습니다.

> **원문 주의:** 위 설명의 파일 경로와 initializer 이름은 원문 표기입니다. 이 저장소에서는 vm/file.c의 vm_file_init와 file_backed_initializer를 확인하십시오.

------------------------------------------------------------------------

```
void vm_file_init (void);
```

> file-backed page subsystem을 초기화합니다. 관련 초기 설정을 이 함수에서 수행하십시오.

------------------------------------------------------------------------

```
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
```

> file-backed page를 초기화합니다. 먼저 `page->operations`에 handler들을 설정합니다. backing file 등 필요한 정보를 page 구조체에 추가할 수 있습니다.

------------------------------------------------------------------------

```
static void file_backed_destroy (struct page *page);
```

> 연결된 파일을 닫아 file-backed page를 정리합니다. 내용이 dirty라면 변경 사항을 먼저 파일에 기록해야 합니다. page 구조체 자체는 `file_backed_destroy`의 호출자가 해제하므로 여기에서 free하지 않아도 됩니다.
