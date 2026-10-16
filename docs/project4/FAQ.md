> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project4/FAQ.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="faq"></a>

# 자주 묻는 질문

<a id="can-blocksectorsize-change"></a>

### BLOCK_SECTOR_SIZE 값이 바뀔 수 있나요?

아니, BLOCK_SECTOR_SIZE는 512에 고정되어 있습니다. IDE 디스크의 경우, 이 값은 하드웨어의 고정된 속성입니다. 다른 디스크는 반드시 512 바이트 섹터를 가지고 있지 않지만, 단순하기 위해 Pintos는 단지 그렇게 하는 것을 지원합니다.

<a id="indexed-files-faq"></a>

### 인덱스 파일 FAQ

<a id="what-is-the-largest-file-size-that-we-are-supposed-to-support"></a>

#### 지원해야 할 최대 파일 크기는 얼마인가요?

우리가 만든 파일 시스템 파티션은 8 MB 또는 더 작습니다. 그러나 개별 파일은 메타데이터를 수용하기 위해 파티션보다 작아야 합니다. 아이노드 조직을 결정할 때 이것을 고려해야 합니다.

<a id="subdirectories-faq"></a>

### 하위 디렉터리 FAQ

<a id="how-should-a-file-name-like-ab-be-interpreted"></a>

#### `a//b` 같은 파일 이름은 어떻게 해석하나요?

여러 연속 슬래시는 하나의 슬래시와 동등하므로 이 파일 이름은 `a/b`와 동일합니다.

<a id="how-about-a-file-name-like-x"></a>

#### `/../x` 같은 파일 이름은 어떻게 해석하나요?

루트 디렉토리는 자신의 모자이기 때문에 `/x`에 해당한다.

<a id="how-should-a-file-name-that-ends-in--be-treated"></a>

#### `/`로 끝나는 파일 이름은 어떻게 처리하나요?

대부분의 유닉스 시스템은 디렉토리의 이름 끝에 슬래시를 허용하고, 슬래스로 끝나는 다른 이름을 거부합니다. 우리는 이러한 행동을 허용하고, 단순히 슬래스로 끝나는 이름을 거부할 것입니다.

<a id="buffer-cache-faq"></a>

### 버퍼 캐시 FAQ

<a id="can-we-keep-a-struct-inodedisk-inside-struct-inode"></a>

#### `struct inode_disk` 안에 `struct inode`를 보관해도 되나요?

64블록 제한의 목적은 캐시된 파일 시스템 데이터의 총량을 제한하는 것입니다. 파일 데이터든 메타데이터든 디스크 데이터 블록을 커널 메모리 어디에 보관하더라도 이 제한에 포함해야 합니다. 같은 규칙은 디스크 블록과 유사한 것에도 적용됩니다. 예를 들어 `length`나 `sector_cnt` 멤버를 제거한 `struct inode_disk`도 해당합니다.

즉, 아이노드 구현이 해당 디스크 아이노드에 접근하는 방식을 변경해야 합니다. 현재 `struct inode_disk`을 `struct inode`에 삽입하고 해당 섹터를 디스크에서 읽습니다. 아이노드의 추가 복사본을 보관하면 64 블록의 제한을 제거할 수 있습니다.

`struct inode`에서 아이노드 데이터에 대한 포인터를 저장할 수 있지만, 그렇게 한다면 OS를 64개의 동시에 열리는 파일로 제한하지 않도록 주의해야 합니다. 아이노드를 필요할 때 찾을 수 있는 다른 정보도 저장할 수 있습니다. 마찬가지로 64개의 캐시 항목에 따라 메타데이터를 저장할 수도 있습니다.

원하는 경우 무료 매핑의 캐시된 복사본을 영구적으로 메모리에 보관할 수 있습니다. 캐시 크기에 비해서 계산할 필요는 없습니다.

`byte_to_sector()`은 `filesys/inode.c`에서 `struct inode_disk`을 직접적으로 사용하며 저장 계층에 해당하는 분야를 처음 읽지 않고 있습니다. 더 이상 작동하지 않을 겁니다. 사용 전에 캐시에서 `struct inode_disk`을 얻기 위해 `inode_byte_to_sector()`을 변경해야 합니다.
