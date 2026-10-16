> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/FAQ.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="faq"></a>

# 자주 묻는 질문

<a id="do-we-need-a-working-project-2-to-implement-project-3"></a>

### 프로젝트 3을 구현하려면 프로젝트 2가 정상 동작해야 하나요?

네.

<a id="how-do-we-resume-a-process-after-we-have-handled-a-page-fault"></a>

### 페이지 폴트를 처리한 뒤 프로세스를 어떻게 재개하나요?

`page_fault()`에서 반환하면 현재 유저 프로세스의 실행이 재개됩니다. 그러면 명령어 포인터가 가리키는 명령을 다시 시도합니다. 유저 프로세스가 스택 포인터보다 높은 주소에서 폴트를 일으키는 이유도 생각해 보세요. 스택 확장 테스트에서는 현재 유저 스택 포인터보다 높은 주소에서 폴트가 발생하는 것을 볼 수 있습니다.

<a id="does-the-virtual-memory-system-need-to-support-data-segment-growth"></a>

### 가상 메모리 시스템에서 데이터 세그먼트 확장을 지원해야 하나요?

아니요. 데이터 세그먼트의 크기는 링커가 결정합니다. Pintos에는 아직 동적 메모리 할당이 없습니다. 다만 메모리 매핑 파일을 이용해 유저 수준에서 비슷한 동작을 만들 수는 있습니다. 잘 설계된 시스템이라면 데이터 세그먼트 확장을 지원해도 복잡성이 크게 늘어나지는 않습니다.

<a id="why-should-i-use-paluser-for-allocating-page-frames"></a>

### 페이지 프레임 할당에 `PAL_USER`를 사용해야 하는 이유는 무엇인가요?

`palloc_get_page()`에 `PAL_USER`을 전달하면 기본 커널 풀 대신 유저 풀에서 메모리를 할당합니다. 유저 풀의 페이지가 부족하면 유저 프로그램에 페이징이 발생하지만, 커널 풀이 고갈되면 메모리를 할당해야 하는 많은 커널 함수가 실패합니다. 원한다면 `palloc_get_page()` 위에 다른 할당자를 구현해도 되지만 기본 할당 방식으로는 이 함수를 사용해야 합니다. `-ul` 커널 명령행 옵션으로 유저 풀 크기를 제한하면 여러 유저 메모리 크기에서 VM 구현을 쉽게 테스트할 수 있습니다.
