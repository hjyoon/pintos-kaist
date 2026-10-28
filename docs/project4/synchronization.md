> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project4/synchronization.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="synchronization"></a>

# Synchronization

제공된 file system은 외부에서 synchronization을 보장해야 합니다. 즉, 호출자가 file system 코드에 한 번에 하나의 thread만 들어가도록 해야 합니다. 제출할 구현은 **외부 synchronization에 의존하지 않는 finer-grained synchronization**을 사용해야 합니다. 독립적인 대상에 대한 작업은 가능한 한 서로 기다리지 않고 진행할 수 있어야 합니다.

서로 다른 cache block에 대한 작업은 독립적이어야 합니다. 특히 한 block에서 I/O를 기다리는 동안에도 I/O가 필요 없는 다른 block의 작업은 그 I/O가 끝날 때까지 기다리지 않고 진행할 수 있어야 합니다.

여러 process가 같은 파일에 동시에 접근할 수 있어야 합니다. 같은 파일에 대한 여러 읽기는 서로를 기다리지 않고 완료할 수 있어야 합니다. 파일 크기를 늘리지 않는 쓰기라면 같은 파일에 대한 여러 쓰기도 동시에 진행할 수 있어야 합니다. 다른 process가 쓰는 도중 파일을 읽으면, 그 쓰기가 전혀 반영되지 않았거나 일부 또는 전부 반영된 결과를 읽어도 됩니다. 다만 `write` system call이 반환된 뒤 시작하는 읽기는 변경된 내용을 볼 수 있어야 합니다. 두 process가 같은 영역에 동시에 쓸 때는 양쪽 데이터가 섞여도 됩니다.

반면 파일 확장과 확장 영역에 대한 데이터 기록은 atomic해야 합니다. process A와 B가 같은 파일을 열고 둘 다 EOF에 위치했다고 가정합시다. A가 읽는 동시에 B가 쓰면 A는 B가 쓴 데이터의 전부·일부를 읽거나 아무것도 읽지 않아도 됩니다. 그러나 B가 쓰지 않은 데이터는 읽어서는 안 됩니다. 예를 들어 B가 쓴 모든 byte가 0이 아니라면 A가 그 영역에서 0을 읽는 것은 허용되지 않습니다.

서로 다른 directory에 대한 작업은 동시에 진행할 수 있어야 합니다. 같은 directory에 대한 작업끼리는 서로 기다려도 됩니다.

synchronization이 필요한 것은 여러 thread가 공유하는 데이터뿐입니다. 기본 file system의 `struct file`과 `struct dir`는 하나의 thread에서만 접근한다는 점을 기억하십시오.
