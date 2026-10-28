> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/cow.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="copy-on-write-extra"></a>

# Copy-on-Write — Extra

**Pintos에 copy-on-write를 구현하십시오.**

copy-on-write는 같은 physical page를 공유해 자원 복제를 빠르게 하는 기법입니다. 여러 process가 같은 자원을 사용할 때는 보통 서로 간섭하지 않도록 각자의 복사본이 필요합니다. 하지만 읽기만 하고 수정하지 않는 동안에는 physical memory에 여러 복사본을 둘 이유가 없습니다.

예를 들어 `fork`로 process를 만들면 child는 parent의 자원을 자신의 virtual address space로 복제해야 합니다. 일반적으로 physical page를 할당하고, frame에 데이터를 복사한 뒤, page table에 virtual-to-physical mapping을 추가합니다. 이 작업은 시간이 많이 들 수 있습니다.

copy-on-write에서는 내용이 이미 physical memory에 있으므로 새 physical page를 할당하지 않습니다. child의 page table에 같은 frame을 가리키는 mapping만 추가합니다. parent와 child는 서로 다른 virtual address space를 사용하지만 같은 physical page의 데이터를 공유하며, 이 사실은 OS만 관리합니다. 둘 중 하나가 공유 데이터를 수정하려 할 때 그 process를 위한 새 physical page를 만들고 복사합니다. 즉, 실제 복사는 최초 쓰기 시점까지 미룹니다.

OS는 copy-on-write page에 대한 쓰기 시도를 감지해야 합니다. 이를 위해 write protection을 사용합니다. page를 writable이 아니도록 표시하여 쓰기 접근 시 page fault가 발생하게 하면 됩니다.

**`fork`에 대해서만 copy-on-write를 구현하면 됩니다.** child가 parent의 자원을 상속할 때 바로 복사하지 않고 같은 physical data를 참조하다가 수정 시 분리할 수 있습니다. **Write-protected page도 모두 eviction 대상에 포함해야 합니다.**

copy-on-write에는 기본 test case만 제공합니다. 가능한 모든 상황을 직접 고려해야 합니다. 힌트를 하나 들면 file-backed page의 공유도 구현해야 합니다. 이 extra는 hidden test로도 채점합니다.
