> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project3/accessing_user_memory.md) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="accessing-user-memory"></a>

# User Memory 접근

system call을 처리하는 코드도 VM 환경에 맞춰 수정해야 합니다. [User memory 접근](../project2/introduction.md)을 참조하십시오. user process가 file이나 swap에 있는 non-resident page에 접근할 수 있듯이, system call에도 이런 page의 주소를 넘길 수 있습니다. 별도 보호가 없다면 kernel이 접근하는 도중에도 page가 frame에서 evict될 수 있습니다. kernel이 non-resident user page를 접근하면 page fault가 발생합니다.

kernel은 이런 page fault를 처리할 수 있어야 하거나, 접근 중 fault가 발생하지 않도록 막아야 합니다. 특히 fault 처리에 필요한 자원을 이미 보유한 동안에는 fault를 예방해야 합니다. 예를 들어 file system이나 swap device driver의 lock이 해당합니다. driver가 `file_read`에 전달된 user buffer에 접근하는 중 fault가 발생하면, 그 fault를 처리하려고 같은 driver를 다시 호출할 수 없으므로 이런 상황을 허용해서는 안 됩니다.

예방하려면 user memory 접근 코드와 page eviction 코드가 협력해야 합니다. frame table에 특정 frame의 page를 evict해서는 안 된다는 상태를 기록하는 방법이 있습니다. 이를 page를 frame에 pinning 또는 locking한다고 부릅니다. pinning은 replacement algorithm의 선택지를 줄이므로 꼭 필요한 경우에만, 필요한 시간 동안만 유지하십시오.
