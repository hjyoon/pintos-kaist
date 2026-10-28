> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project4/indexed_and_extensible_files.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="indexed-and-extensible-files"></a>

# Indexed and Extensible Files

기본 file system은 파일을 하나의 연속 영역인 extent에 할당하므로 external fragmentation에 취약합니다. 즉, 빈 block이 *n*개 있어도 서로 흩어져 있으면 *n*-block 파일을 할당하지 못할 수 있습니다. on-disk inode 구조를 변경해 이 문제를 해결하십시오.

일반적으로는 direct block, indirect block, doubly indirect block을 사용하는 index 구조를 생각할 수 있습니다. 이전 학기에는 강의에서 배운 *Berkeley UNIX FFS*와 같은 multi-level indexing을 채택한 학생이 많았습니다. 하지만 이 과제에서는 구현 부담을 줄이기 위해 FAT를 사용합니다. **제공된 skeleton 코드로 FAT를 구현해야 합니다.** multi-level indexing, 즉 강의의 FFS 방식 코드를 포함해서는 안 됩니다. 위반하면 file growth 부분은 0점입니다.

file system partition은 8 MB를 넘지 않는다고 가정해도 됩니다. metadata 공간을 제외한 partition 전체 크기까지 파일을 저장할 수 있어야 합니다. inode 하나는 disk sector 하나에 저장되므로, 그 안에 넣을 수 있는 block pointer 수는 제한됩니다.

<a id="indexing-large-files-with-fat-file-allocation-table"></a>

## FAT(File Allocation Table)를 이용한 큰 파일의 indexing

> 이 문서는 강의에서 다룬 일반적인 file system과 FAT의 기본 원리를 알고 있다고 가정합니다. 아직 익숙하지 않다면 먼저 강의 자료를 다시 확인하십시오.

이전 프로젝트에서 사용한 기본 file system은 여러 disk sectors에 걸친 하나의 연속 영역에 파일을 저장했습니다. 하나 이상의 연속한 sector로 이루어진 이런 영역을 *cluster*라고 부르겠습니다. 이 관점에서 기본 file system의 cluster 크기는 그 cluster에 저장한 파일 크기와 같았습니다.

external fragmentation을 줄이려면 cluster 크기를 줄일 수 있습니다. virtual memory의 page 크기를 떠올려 보십시오. skeleton에서는 단순화를 위해 cluster당 sector 수를 `1`로 고정했습니다. 이처럼 작은 cluster 하나로는 파일 전체를 담지 못할 수 있으므로 여러 cluster가 필요하며, inode에서 이들을 찾아갈 자료구조가 필요합니다. 간단한 방법은 linked list, 즉 *chain*입니다. inode가 첫 block의 sector 번호를 보관하고, 각 block이 다음 block의 번호를 보관하도록 구성할 수 있습니다. 하지만 마지막 block만 필요해도 앞의 모든 block을 읽어야 하므로 이 방식은 느립니다. FAT는 block 자체 대신 크기가 정해진 File Allocation Table에 연결 관계를 저장합니다. 실제 파일 데이터 없이 연결 정보만 담으므로 DRAM에 cache할 만큼 작으며, 원하는 table entry를 바로 조회할 수 있습니다.

`filesys/fat.c`의 skeleton을 이용해 inode indexing을 구현합니다. 아래에서는 `fat.c`에 이미 구현된 함수와 직접 구현할 함수를 설명합니다.

`fat.c`의 `fat_init()`, `fat_open()`, `fat_close()`, `fat_create()`, `fat_boot_create()`는 부팅 시 disk를 초기화하고 format하는 함수이므로 직접 수정할 필요는 없습니다. 이 함수들의 역할을 간단히 이해한 뒤 `fat_fs_init()`를 구현하십시오.

> **원문 주의:** 원문은 위 함수를 “6개”라고 부르지만 실제로 나열한 함수는 5개입니다. 아래 fat_fs_init의 반환 type도 원문 그대로 보존했습니다. 이 저장소의 filesys/fat.c에서는 반환 type이 void이므로 실제 선언에 맞춰 구현하십시오.

------------------------------------------------------------------------

```
cluster_t fat_fs_init (void);
```

> FAT file system을 초기화합니다. `fat_fs`의 `fat_length`와 `data_start` field를 초기화해야 합니다. `fat_length`는 file system의 cluster 수를, `data_start`는 파일 저장을 시작할 수 있는 sector 위치를 나타냅니다. `fat_fs->bs`의 값을 활용할 수 있습니다. 필요한 다른 데이터도 이 함수에서 초기화할 수 있습니다.

------------------------------------------------------------------------

```
cluster_t fat_create_chain (cluster_t clst);
```

> cluster 번호 `clst`가 가리키는 cluster 뒤에 새 cluster를 붙여 chain을 확장합니다. `clst`이 0이면 새 chain을 만듭니다. 새로 할당한 cluster의 번호를 반환합니다.

------------------------------------------------------------------------

```
void fat_remove_chain (cluster_t clst, cluster_t pclst);
```

> `clst`부터 시작하는 chain을 제거합니다. `pclst`는 제거할 chain 바로 앞의 cluster여야 하며, 작업이 끝나면 `pclst`가 남은 chain의 마지막 cluster가 됩니다. `clst`가 chain의 첫 cluster라면 `pclst`는 0이어야 합니다.

------------------------------------------------------------------------

```
void fat_put (cluster_t clst, cluster_t val);
```

> cluster 번호 `clst`에 해당하는 FAT entry를 `val`로 변경합니다. 각 entry는 다음 cluster를 가리키며, 다음 cluster가 없으면 `EOChain`를 저장하므로 이 함수로 chain의 연결 관계를 갱신할 수 있습니다.

------------------------------------------------------------------------

```
cluster_t fat_get (cluster_t clst);
```

> cluster 번호 `clst`에 해당하는 FAT entry의 값, 즉 다음 cluster를 가리키는 값을 반환합니다.

------------------------------------------------------------------------

```
disk_sector_t cluster_to_sector (cluster_t clst);
```

> cluster 번호 `clst`를 대응하는 sector 번호로 변환해 반환합니다.

------------------------------------------------------------------------

이 함수들을 `filesys.c`와 `inode.c`에서 활용해 기본 file system을 확장할 수 있습니다.

<a id="file-growth"></a>

## File Growth

**확장 가능한 파일을 구현하십시오.** 기본 file system은 생성할 때 파일 크기를 지정합니다. 반면 대부분의 현대적인 file system에서는 크기 0으로 파일을 생성한 뒤 EOF를 넘어 쓰기를 할 때마다 파일을 확장합니다. 구현할 file system도 이 동작을 지원해야 합니다.

metadata 공간을 제외한 file system 크기를 넘을 수 없다는 점 외에는 파일 크기의 한도를 미리 정해서는 안 됩니다. root directory에도 같은 요구사항이 적용됩니다. root directory는 초기 제한인 파일 16개를 넘어 확장될 수 있어야 합니다.

user program은 현재 EOF를 넘는 위치로 seek할 수 있습니다. seek 자체는 파일을 확장하지 않습니다. EOF 너머에 데이터를 쓰면 쓰기 위치까지 파일을 확장하며, 이전 EOF와 새 데이터 사이의 간격은 0으로 채워야 합니다. EOF 너머에서 시작한 읽기는 0 bytes를 반환합니다.

EOF에서 멀리 떨어진 위치에 쓰면 내용 전체가 0인 block이 많이 생길 수 있습니다. 일부 file system은 이런 block에도 실제 공간을 할당해 0을 기록합니다. 다른 방식은 실제 데이터가 쓰이기 전까지 이 block들을 할당하지 않는 것입니다. 후자를 sparse file 지원이라고 합니다. 두 방식 중 어느 쪽을 선택해도 됩니다.
