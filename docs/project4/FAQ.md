> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project4/FAQ.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="faq"></a>

# FAQ

<a id="can-blocksectorsize-change"></a>

### BLOCK_SECTOR_SIZE는 바뀔 수 있나요?

아니요. BLOCK_SECTOR_SIZE는 512로 고정됩니다. IDE disk에서는 hardware가 정하는 값입니다. 다른 종류의 disk는 sector가 512 bytes가 아닐 수도 있지만, Pintos는 단순화를 위해 512-byte sector만 지원합니다.

<a id="indexed-files-faq"></a>

### Indexed Files FAQ

<a id="what-is-the-largest-file-size-that-we-are-supposed-to-support"></a>

#### 지원해야 하는 최대 파일 크기는 얼마인가요?

테스트에서 사용하는 file system partition은 8 MB 이하입니다. 다만 metadata를 위한 공간이 필요하므로 개별 파일은 partition보다 작아야 합니다. inode 구조를 설계할 때 이를 고려하십시오.

<a id="subdirectories-faq"></a>

### Subdirectories FAQ

<a id="how-should-a-file-name-like-ab-be-interpreted"></a>

#### `a//b` 같은 파일 이름은 어떻게 해석하나요?

연속한 slash 여러 개는 slash 하나와 같습니다. 따라서 이 경로는 `a/b`와 동일합니다.

<a id="how-about-a-file-name-like-x"></a>

#### `/../x` 같은 이름은 어떤가요?

root directory는 자기 자신의 parent이므로 `/x`와 같습니다.

<a id="how-should-a-file-name-that-ends-in--be-treated"></a>

#### `/`로 끝나는 이름은 어떻게 처리하나요?

대부분의 Unix 시스템은 directory 이름 끝의 slash는 허용하고, 그 외 파일 이름 끝의 slash는 거부합니다. 이 방식을 사용해도 되고, slash로 끝나는 이름을 모두 거부해도 됩니다.

<a id="buffer-cache-faq"></a>

### Buffer Cache FAQ

<a id="can-we-keep-a-struct-inodedisk-inside-struct-inode"></a>

#### `struct inode` 안에 `struct inode_disk`를 보관해도 되나요?

64-block 제한의 목적은 cache에 보관하는 file system 데이터의 양을 제한하는 것입니다. 파일 데이터든 metadata든 disk block의 내용을 kernel memory 어딘가에 보관한다면 64-block 제한에 포함해야 합니다. `length`나 `sector_cnt` member를 뺀 `struct inode_disk`처럼, disk block과 실질적으로 유사한 복사본에도 같은 규칙이 적용됩니다.

현재 inode 구현은 `struct inode`에 `struct inode_disk`를 포함하고, inode를 생성할 때 해당 sector를 읽어 넣습니다. 따라서 disk에 있는 inode에 접근하는 방식을 변경해야 합니다. inode의 추가 복사본을 유지하면 cache에 적용한 64-block 제한을 우회하게 됩니다.

`struct inode`에 inode 데이터의 pointer를 저장할 수는 있습니다. 다만 그 때문에 동시에 열 수 있는 파일 수가 64개로 제한되지 않도록 주의하십시오. 필요할 때 inode를 찾는 데 도움이 되는 다른 정보를 저장해도 됩니다. 마찬가지로 64개 cache entry 각각에 일부 metadata를 둘 수도 있습니다.

free map의 복사본을 memory에 상주시켜도 됩니다. 이는 cache 크기에 포함하지 않아도 됩니다.

`filesys/inode.c`의 `byte_to_sector()`는 해당 sector를 storage hierarchy에서 읽어 오는 과정 없이 `struct inode_disk`를 직접 사용합니다. 이제 이 방식은 사용할 수 없습니다. `inode_byte_to_sector()`가 `struct inode_disk`를 cache에서 얻은 뒤 사용하도록 변경해야 합니다.
