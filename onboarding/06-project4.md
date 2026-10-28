# Project 4: 파일을 저장하고 이름으로 찾기

[온보딩 목차](README.md) · 이전: [Project 3](05-project3.md) · 다음: [브랜치·테스트·debugging](07-workflow-and-debugging.md)

## 이번에는 무엇을 바꾸나?

Project 2에서는 제공된 단순한 file system을 사용했다. Project 4에서는 그 내부를 확장한다. 크게 보면 **데이터를 disk 어디에 저장할지**, **이름으로 어떤 파일을 찾을지**, **동시에 접근해도 어떻게 일관성을 지킬지**를 해결한다.

예를 들어 `/home/note.txt`를 열어 파일 끝에 내용을 추가하는 동작에는 path 탐색, directory 조회, inode 접근, 공간 할당, 데이터 기록과 synchronization이 함께 필요하다.

## 파일 관련 자료구조를 구분한다

| 이름 | 역할 |
| --- | --- |
| file descriptor | process가 system call에서 사용하는 정수 번호 |
| file object | 열린 파일의 offset 등 한 번의 open에 관련된 상태 |
| inode | 파일의 종류·길이·저장 위치 등 파일 자체의 정보 |
| directory | 이름을 inode에 연결하는 entry들의 집합 |
| sector | disk가 읽고 쓰는 기본 단위. 이 Pintos에서는 512 bytes |
| FAT | cluster가 다음 어느 cluster로 이어지는지 기록하는 table |
| buffer cache | disk sector의 내용을 RAM에 보관해 반복 I/O를 줄이는 구조 |

같은 inode를 여러 file object가 참조할 수 있다. 하나를 close했다고 inode와 데이터를 바로 없애면 다른 open이나 mapping이 깨질 수 있다.

## baseline에 있는 코드

| 파일 | baseline에서의 역할 | 확장할 방향 |
| --- | --- | --- |
| [filesys/filesys.c](../filesys/filesys.c) | root directory에서 파일 생성·open·삭제 | path, mkdir, chdir, symbolic link 등과 연결 |
| [filesys/inode.c](../filesys/inode.c) | 연속한 sector에 고정 길이 데이터 저장 | FAT chain, 파일 확장, inode 종류, 안전한 동시 접근 |
| [filesys/directory.c](../filesys/directory.c) | directory entry의 기본 읽기·추가·삭제 | 하위 directory, `.`·`..`, 삭제 조건 |
| [filesys/file.c](../filesys/file.c) | file offset과 read/write interface | 변경된 inode 구현을 활용하고 lifetime 유지 |
| [filesys/fat.c](../filesys/fat.c) | FAT 초기화와 API의 일부 틀 | chain 할당·연결·해제, cluster와 sector 변환 |
| [filesys/page_cache.c](../filesys/page_cache.c) | cache 관련 함수의 틀 | bounded cache, write-behind, read-ahead |
| [devices/disk.c](../devices/disk.c) | 실제 가상 disk의 sector read/write | 보통 이 위에 file system 정책을 구현 |

`EFILESYS`가 켜진 Project 4에서는 FAT 경로를 사용한다. Project 2에서 단순 file system이 동작했다고 해서 Project 4의 FAT 구현도 동작한다고 가정하면 안 된다.

## 이 저장소에서 따라갈 단계

### 1. FAT: 흩어진 저장 공간을 chain으로 연결한다

기본 inode는 데이터가 연속되어 있다고 가정한다. FAT를 사용하면 파일 데이터가 떨어진 cluster에 있어도 연결 관계를 따라갈 수 있다. 이 skeleton은 cluster당 sector 수를 1로 단순화했다.

시작은 `fat_fs_init()`, `fat_create_chain()`, `fat_remove_chain()`, `fat_get()`, `fat_put()`, `cluster_to_sector()`다. FAT를 만든 뒤에는 inode가 그 chain을 이용하도록 연결해야 한다.

새 cluster를 얻는 경우뿐 아니라 공간 부족, 중간 실패, chain 해제도 생각한다. 실패하면서 이미 할당한 공간을 잃어버리면 다음 요청에서도 공간이 계속 줄어든다.

### 2. Buffer Cache: disk I/O를 공통 경로로 모은다

이 부분은 공식 과제의 extra지만, 이 저장소에서는 FAT 다음 단계로 구현했다. 뒤의 file growth와 directory 작업이 같은 cache 경로를 사용하게 하기 좋다.

원문에는 VM 기반 page cache를 활용하는 설계도 나온다. **현재 `master`의 구현은 `filesys/page_cache.c`에 있는 64-entry sector cache**를 중심으로 읽으면 된다. 원문 예시의 함수 이름과 구현의 helper 이름이 다를 수 있다.

확인할 것은 hit/miss만이 아니다. dirty 데이터를 언제 기록하는지, eviction 중 같은 sector의 요청을 어떻게 처리하는지, read-ahead와 종료 시 flush가 어떻게 동작하는지도 본다. inode metadata를 cache 밖에 통째로 보관해 64-sector 제한을 우회하지 않아야 한다.

### 3. File Growth: EOF 너머 쓰기로 파일을 늘린다

파일 끝을 넘는 위치에 write하면 필요한 cluster를 추가한다. 기존 EOF와 새 데이터 사이의 간격은 0으로 읽혀야 한다. seek만 했을 때는 파일을 늘리지 않는다.

큰 파일뿐 아니라 root directory의 확장도 필요하다. 쓰기 중 공간 부족이 발생했을 때, 파일 길이와 chain이 서로 다른 상태로 남지 않도록 실패 경로를 설계한다.

### 4. Path Resolution: 이름을 한 component씩 찾는다

```text
절대 path /a/b.txt → root에서 시작 → a 조회 → b.txt 조회
상대 path a/b.txt → 현재 working directory에서 시작 → 같은 방식으로 조회
```

여러 함수가 path를 제각각 해석하면 open은 되는데 remove는 실패하는 식의 차이가 생긴다. path 탐색 규칙을 공통 코드로 모으면 이후 단계에서 도움이 된다.

`/`, `.`, `..`, 연속한 slash, 중간 component가 일반 파일인 경우를 먼저 정리한다. process의 current working directory와 fork 때의 상속·종료 시 정리도 함께 다룬다.

### 5. Subdirectories: directory도 수명이 있는 자원이다

mkdir, chdir, readdir, isdir, inumber를 system call과 연결한다. `.`와 `..`를 만들고, 비어 있지 않은 directory 삭제나 root 삭제 같은 경우의 규칙을 확인한다.

directory를 open 중이거나 working directory로 참조 중일 수 있다. 삭제 시 파일 이름, 열린 참조, 실제 inode의 lifetime을 구분해야 한다.

### 6. Symbolic Links: 다른 path로 탐색을 이어 간다

symbolic link에는 target path가 저장된다. 일반 파일의 데이터를 복사하는 기능이 아니다.

특히 **상대 target은 symbolic link가 놓인 directory를 기준으로** 해석한다. 절대 target, dangling link, link가 다른 link를 가리키는 경우와 순환도 고려한다. 무한 탐색을 막을 한도가 필요하다.

### 7. Synchronization: 공유 상태별로 보호 범위를 정한다

Project 2에서 file system 진입 전체를 하나의 lock으로 막았더라도, Project 4에서는 서로 다른 파일에 대한 작업이 불필요하게 모두 직렬화되지 않도록 개선한다.

cache entry, FAT 변경, inode의 길이와 데이터 배치, directory entry 등의 보호 범위를 나누어 생각한다. 여러 lock을 동시에 잡는다면 획득 순서를 기록한다. rename 같은 과제 밖 기능을 새로 만들기보다 요구된 동작의 동시 접근과 오류 경로부터 완성한다.

## VM과 함께 빌드되는지 확인한다

| 기준 | `filesys/Make.vars`의 기본 설정 |
| --- | --- |
| `skeleton` | `USERPROG`, `FILESYS`, `EFILESYS`; VM 추가 설정은 주석 |
| 현재 `master` | 위 세 가지에 `VM`도 포함. VM·COW·buffer-cache 테스트를 함께 구성 |

Project 4는 file system 코드만 읽어서는 끝나지 않는다. file-backed page의 I/O, mmap 참조, fork/exec/exit의 파일 상태도 연결되어 있다. 실제 빌드 옵션은 [filesys/Make.vars](../filesys/Make.vars)에서 확인하고, 현재 보고 있는 브랜치가 baseline인지 구현본인지 구분한다.

## 첫 테스트와 persistence

구현이 준비된 저장소 루트에서 실행한다.

```bash
source ./activate
make -C filesys -j2
make -C filesys/build TIMEOUT=60 tests/filesys/extended/grow-file-size.result
make -C filesys/build TIMEOUT=60 tests/filesys/extended/grow-file-size-persistence.result
```

첫 target은 파일 확장 동작, 두 번째는 저장된 내용의 persistence 판정을 확인한다. extended 테스트의 recipe는 disk를 유지해 다시 부팅하고 tar로 내용을 꺼내는 과정도 포함한다. 따라서 출력 파일이 하나보다 많을 수 있다.

다음으로 `dir-mkdir`, `symlink-file`, `syn-rw`, `tests/filesys/buffer-cache/bc-easy` 등을 기능별로 확인한다. 전체 테스트와 채점은 `filesys/build`에서 `make check`, `make grade`다.

**file system 테스트를 처음부터 `make -j check`로 병렬 실행하지 않는다.** 일부 recipe가 `tmp.dsk` 같은 이름을 공유한다. kernel 빌드의 `make -j2`와 테스트 실행의 병렬화는 별개다.

세부 요구사항: [FAT와 File Growth](../docs/project4/indexed_and_extensible_files.md), [Subdirectories와 Symbolic Links](../docs/project4/subdirectories.md), [Synchronization](../docs/project4/synchronization.md).
