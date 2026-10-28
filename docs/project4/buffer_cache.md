> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project4/buffer_cache.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="buffer-cache-extra-credit"></a>

# Buffer Cache — 추가 점수

file system이 file block을 cache하도록 수정하십시오. block 읽기·쓰기 요청이 들어오면 먼저 cache에 있는지 확인하고, 있다면 disk에 접근하지 않고 cache 데이터를 사용합니다. 없다면 disk에서 block을 읽어 오며, 필요하면 기존 entry를 evict합니다. **cache 크기는 최대 64 sectors입니다.**

적어도 clock 알고리즘만큼 성능이 좋은 cache replacement algorithm을 구현해야 합니다. 보통 data보다 metadata의 가치가 높다는 점도 고려해 보십시오. accessed 정보, dirty 정보 등을 어떻게 조합해야 disk 접근 횟수를 가장 줄일 수 있는지 실험하십시오.

free map의 복사본을 memory에 상주시켜도 됩니다. 이는 cache 크기에 포함하지 않아도 됩니다.

제공된 inode 코드는 sector 단위의 disk interface를 byte 단위의 system call interface로 변환하기 위해 `malloc()`으로 할당한 bounce buffer를 사용합니다. 이 bounce buffer를 제거하고, **buffer cache의 sector에 데이터를 직접 복사해 넣거나 sector에서 직접 복사해 오십시오.**

cache는 write-behind 방식이어야 합니다. 변경된 데이터를 곧바로 disk에 쓰지 않고 dirty block으로 cache에 보관했다가, evict할 때 disk에 기록합니다. write-behind는 비정상 종료 시 데이터 손실 위험을 높이므로, cache에 있는 모든 dirty block을 주기적으로 disk에 기록하는 기능도 필요합니다. Pintos가 종료될 때도 cache를 flush할 수 있도록 `filesys_done()`에서 남은 데이터를 기록해야 합니다.

첫 프로젝트의 `timer_sleep()`가 동작한다면 write-behind에 활용하기 좋습니다. 그렇지 않으면 더 단순한 전용 기능을 구현해도 되지만, busy waiting을 사용해서는 안 됩니다.

read-ahead도 구현해야 합니다. 파일의 한 block을 읽으면 다음에 읽힐 가능성이 있는 block을 자동으로 cache에 가져오는 기능입니다. read-ahead는 비동기로 처리해야 실질적인 효과가 있습니다. 예를 들어 process가 파일의 disk block 1을 요청하면 block 1을 읽을 때까지는 기다리되, 읽기가 끝나는 즉시 process로 제어를 돌려주어야 합니다. block 2의 read-ahead는 background에서 비동기로 처리합니다. 이를 위해 I/O 전용 thread를 만들고, disk I/O가 필요할 때 그 thread로 요청을 넘기는 방법을 사용할 수 있습니다.

<a id="hint-for-implementation"></a>

## 구현 힌트

Linux처럼 virtual memory subsystem을 통해 이 기능을 구현할 수도 있습니다. 예를 들어 pagecache라는 새 VM type을 도입하고 `swap_in`, `swap_out`, `destroy` interface로 buffer cache를 관리하는 방식입니다. 이 설계를 선택하면 SECTOR_SIZE 대신 PAGE_SIZE 단위로 cache를 관리할 수 있습니다. file-backed page의 synchronization에는 mmap으로 map한 영역을 cache로 활용하는 방법도 고려할 수 있습니다.

**설계 초기부터 cache를 통합하는 것을 권장합니다.** 과거에는 구현을 거의 마친 뒤 cache를 덧붙이려는 팀이 많았습니다. 이렇게 작업하면 매우 어렵고, 테스트 대부분이나 전부를 통과하지 못한 사례도 많았습니다.
