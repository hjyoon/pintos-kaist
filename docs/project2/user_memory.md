> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/user_memory.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="user-memory-access"></a>

# User Memory 접근

**User memory에 접근하는 기능을 구현하십시오.**

system call을 구현하려면 user virtual address space의 데이터를 읽고 쓰는 방법이 필요합니다. register에서 argument 자체를 얻을 때는 이 기능이 필요하지 않습니다. 그러나 system call argument로 받은 pointer가 가리키는 데이터를 읽을 때는 반드시 이 접근 기능을 거쳐야 합니다. user가 invalid pointer, kernel memory를 가리키는 pointer, 또는 유효하지 않은 영역과 일부가 겹친 memory 범위를 전달할 수 있습니다. 이런 경우 user process를 종료해야 합니다.
