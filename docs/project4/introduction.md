> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project4/introduction.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="project-4-file-systems"></a>

# Project 4: File Systems

이전 두 과제에서는 내부 구현을 깊이 다루지 않은 채 file system을 많이 사용했습니다. 마지막 과제에서는 file system 구현 자체를 개선합니다. 주로 `filesys` directory에서 작업합니다.

Project 4는 Project 2 또는 Project 3 위에 구현할 수 있습니다. 어느 쪽이든 Project 2의 모든 필수 기능이 동작해야 합니다. Project 3를 기반으로 삼는다면 Project 3의 모든 기능도 동작해야 하며, `filesys/Make.vars`를 수정해 VM 기능을 활성화해야 합니다. **VM을 비활성화하면 10%를 감점합니다.** 추가 점수 항목인 page cache에도 VM 기능이 필요합니다.

<a id="background"></a>

## 배경

<a id="new-code"></a>

### 새 코드

다음은 처음 접할 수 있는 파일들입니다. 별도 표시가 없으면 `filesys` directory에 있습니다.

- `filesys/fsutil.c`

  > kernel command line에서 사용할 수 있는 간단한 file system 유틸리티입니다.

- `include/filesys/filesys.h`, `filesys/filesys.c`

  > file system의 최상위 interface입니다. 소개는 [File system 사용](../project2/introduction.md)을 참조하십시오.

- `include/filesys/directory.h`, `filesys/directory.c`

  > 파일 이름을 inode로 변환합니다. directory 자료구조도 파일로 저장됩니다.

- `include/filesys/inode.h`, `filesys/inode.c`

  > disk에 저장되는 파일 데이터의 배치를 나타내는 자료구조를 관리합니다.

- `include/filesys/fat.h`, `filesys/fat.c`

  > FAT file system을 관리합니다.

- `include/filesys/file.h`, `filesys/file.c`

  > 파일 읽기·쓰기를 disk sector 읽기·쓰기로 변환합니다.

- `include/filesys/page_cache.h`, `filesys/page_cache.c`

  > VM 기능을 활용한 page cache 구현용 template입니다. 이 template의 사용을 강하게 권장하지만, 직접 코드를 작성해도 됩니다. VM flag를 끄면 이 template을 사용할 수 없습니다.

- `include/lib/kernel/bitmap.h`, `lib/kernel/bitmap.c`

  > bitmap 자료구조와 bitmap을 disk file에서 읽거나 파일에 쓰는 함수를 제공합니다.

file system은 Unix와 비슷한 interface를 제공하므로, `creat, open, close, read, write, lseek`와 `unlink`의 Unix man page를 참고해도 좋습니다. Pintos의 system call은 이들과 비슷하지만 완전히 같지는 않습니다. file system은 이런 호출을 disk 작업으로 변환합니다.

앞선 두 프로젝트에서 보았듯이 기본 기능은 이미 구현되어 있어 처음부터 file system을 사용할 수 있습니다. 다만 심각한 제약이 있으며, 이번 과제에서 이를 없애야 합니다.

대부분의 작업은 `filesys`에서 진행하지만, 이전 프로젝트의 코드와 상호작용할 수 있다는 점도 고려하십시오.

<a id="testing-file-system-persistence"></a>

#### File System Persistence 테스트

지금까지 각 테스트는 Pintos를 한 번만 실행했습니다. 그러나 file system의 중요한 목적은 재부팅 후에도 데이터를 사용할 수 있게 하는 것입니다. 따라서 file system 테스트는 Pintos를 한 번 더 실행합니다. 두 번째 실행에서는 file system의 모든 파일과 directory를 하나의 파일로 묶은 뒤 host Unix file system으로 복사합니다.

채점 스크립트는 두 번째 실행에서 추출한 파일의 내용을 검사해 file system이 올바른지 판단합니다. 따라서 추출용 user program인 `tar`를 지원할 정도로 구현하기 전에는 extended file system 테스트를 통과할 수 없습니다. `tar`는 file growth와 subdirectory를 모두 요구하므로 지원하는 데 상당한 작업이 필요합니다. 그전까지는 `make check`가 출력하는 추출 file system 관련 오류를 무시해도 됩니다.

추출 파일은 표준 Unix tar 형식입니다. Unix의 tar 프로그램으로 내용을 살펴볼 수 있습니다. 테스트 t의 tar 파일 이름은 `t.tar`입니다.
