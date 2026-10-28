> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/FAQ.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="faq"></a>

# FAQ

<a id="do-we-need-a-working-project-2-to-implement-project-3"></a>

### Project 3를 구현하려면 동작하는 Project 2가 필요한가요?

그렇습니다.

<a id="how-do-we-resume-a-process-after-we-have-handled-a-page-fault"></a>

### Page fault 처리 후 process는 어떻게 재개하나요?

`page_fault()`에서 반환하면 현재 user process가 재개되고 instruction pointer가 가리키는 명령을 다시 실행합니다.

원문에는 이어서 “왜 user process가 stack pointer보다 높은 주소에서 fault를 일으키기도 하나요?”라는 질문도 있습니다. stack growth 테스트에서 이런 접근을 볼 수 있다는 설명은 있지만, 이 FAQ에는 별도의 답변이 제시되어 있지 않습니다.

<a id="does-the-virtual-memory-system-need-to-support-data-segment-growth"></a>

### Data segment의 확장도 지원해야 하나요?

아니요. data segment 크기는 linker가 결정합니다. Pintos의 user program에는 아직 dynamic allocation이 없지만 memory-mapped file로 비슷하게 흉내 낼 수는 있습니다. 잘 설계한 시스템이라면 data segment 확장을 추가하는 데 큰 구조 변경은 필요하지 않을 것입니다.

<a id="why-should-i-use-paluser-for-allocating-page-frames"></a>

### Page frame을 할당할 때 왜 `PAL_USER`를 사용해야 하나요?

`palloc_get_page()`에 `PAL_USER`를 주면 kernel pool 대신 user pool에서 할당합니다. user pool이 부족하면 paging으로 처리할 수 있지만, kernel pool이 부족하면 memory가 필요한 여러 kernel 함수가 실패합니다. `palloc_get_page()` 위에 다른 allocator를 구성해도 되지만, 기반 할당은 이 함수로 수행해야 합니다. `-ul` kernel 옵션으로 user pool 크기를 제한하면 여러 memory 크기에서 VM을 테스트하기 쉽습니다.
