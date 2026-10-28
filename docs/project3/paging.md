> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/paging.md) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="paging"></a>

# Paging

executable에서 load하는 segment에 paging을 구현하십시오. page는 모두 lazy loading으로, 해당 page의 fault가 발생할 때만 실제 내용을 적재해야 합니다. eviction 시 loading 이후 변경된 page는 dirty bit 등을 확인하여 swap에 기록해야 합니다. read-only page를 포함해 수정하지 않은 page는 executable에서 다시 읽을 수 있으므로 swap에 기록해서는 안 됩니다.

LRU에 근접하는 global page replacement algorithm을 구현하십시오. 최소한 단순한 second-chance 또는 clock 알고리즘만큼의 성능을 내야 합니다.

설계는 parallelism을 허용해야 합니다. 한 page fault가 I/O를 기다리는 동안에도 fault가 없는 process는 계속 실행되고, I/O가 필요 없는 다른 page fault는 처리될 수 있어야 합니다. 이를 위한 synchronization이 필요합니다.

program loader의 핵심인 `userprog/process.c`의 `load_segment()` loop를 수정해야 합니다. 각 반복에서 `page_read_bytes`는 executable에서 읽을 byte 수이고, `page_zero_bytes`는 그 뒤를 0으로 채울 byte 수입니다. 합은 항상 `PGSIZE`, 즉 4,096입니다. 값에 따라 다음처럼 처리합니다.

- `page_read_bytes`가 `PGSIZE`이면 최초 접근 시 원본 파일에서 demand paging합니다.
- `page_zero_bytes`가 `PGSIZE`이면 내용이 전부 0이므로 disk를 읽지 않습니다. 최초 fault에서 0으로 채운 새 page를 만드십시오.
- `page_read_bytes`와 `page_zero_bytes` 어느 쪽도 `PGSIZE`가 아니면 page의 앞부분은 파일에서 읽고 나머지는 0으로 채웁니다.
