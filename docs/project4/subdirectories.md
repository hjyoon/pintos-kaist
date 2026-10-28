> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project4/subdirectories.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="subdirectories"></a>

# Subdirectories

**계층적인 namespace를 구현하십시오.** 기본 file system은 모든 파일을 하나의 directory에 저장합니다. directory entry가 파일뿐 아니라 다른 directory도 가리킬 수 있도록 변경하십시오.

directory도 일반 파일처럼 초기 크기를 넘어 확장될 수 있어야 합니다.

기본 file system은 파일 이름을 14자로 제한합니다. 개별 path component의 이름 길이는 이 제한을 유지하거나 늘려도 됩니다. 다만 **전체 path는 14자보다 훨씬 길 수 있어야 합니다.**

**각 process마다 독립적인 current working directory를 유지하십시오.** 초기 process의 current working directory는 root로 설정합니다. process가 fork system call로 child process를 생성하면 child는 parent의 current working directory를 상속합니다. 그 뒤에는 양쪽이 독립적이므로 한쪽이 current working directory를 바꿔도 다른 쪽에는 영향을 주지 않습니다. Unix에서 cd가 외부 프로그램이 아니라 shell built-in인 이유도 이것입니다.

파일 이름을 받는 모든 기존 system call에서 absolute path와 relative path를 사용할 수 있도록 수정하십시오. path separator는 slash('/')입니다. Unix와 같은 의미의 특수 이름 '.'과 '..'도 지원해야 합니다.

`open` system call로 directory도 열 수 있도록 수정하십시오. 기존 system call 중 directory를 가리키는 file descriptor를 받아야 하는 것은 close뿐입니다.

`remove` system call은 일반 파일 외에 빈 directory도 삭제할 수 있어야 합니다. 단, root는 삭제할 수 없습니다. directory 안에 '.'과 '..'을 제외한 파일이나 subdirectory가 하나라도 있으면 삭제해서는 안 됩니다. 어떤 process가 열어 두었거나 current working directory로 사용 중인 directory를 삭제할 수 있게 할지는 선택할 수 있습니다. 삭제를 허용한다면, 삭제된 directory에서 파일을 열거나 새 파일을 만드는 시도는 모두 거부해야 합니다. 여기에는 '.'과 '..'을 여는 경우도 포함됩니다. 다음 system call을 구현하십시오.

------------------------------------------------------------------------

```
bool chdir (const char *dir);
```

> process의 current working directory를 dir로 변경합니다. dir는 absolute path나 relative path일 수 있습니다. 성공하면 true, 실패하면 false를 반환합니다.

------------------------------------------------------------------------

```
bool mkdir (const char *dir);
```

> dir라는 directory를 만듭니다. dir는 absolute path나 relative path일 수 있습니다. 성공하면 true, 실패하면 false를 반환합니다. dir가 이미 존재하거나 마지막 component를 제외한 중간 directory 중 하나라도 존재하지 않으면 실패합니다. 즉, `mkdir("/a/b/c")`는 `/a/b`가 이미 존재하고 `/a/b/c`는 존재하지 않을 때만 성공합니다.

------------------------------------------------------------------------

```
bool readdir (int fd, char *name);
```

> directory를 나타내는 file descriptor fd에서 다음 entry를 읽습니다. 성공하면 null-terminated 파일 이름을 name에 저장하고 true를 반환합니다. name에는 최소 `READDIR_MAX_LEN + 1` bytes를 저장할 공간이 있어야 합니다. 남은 entry가 없으면 false를 반환합니다.
>
> `readdir`는 '.'과 '..'을 반환해서는 안 됩니다. directory가 열린 동안 내용이 변경되었다면 일부 entry를 건너뛰거나 여러 번 읽어도 됩니다. 내용이 바뀌지 않았다면 순서에 관계없이 각 entry를 정확히 한 번씩 읽어야 합니다.
>
> `READDIR_MAX_LEN`는 `lib/user/syscall.h`에 정의되어 있습니다. 기본값인 14자보다 긴 파일 이름을 지원한다면 이 값도 늘려야 합니다.

------------------------------------------------------------------------

```
bool isdir (int fd);
```

> fd가 directory를 나타내면 true, 일반 파일을 나타내면 false를 반환합니다.

------------------------------------------------------------------------

```
int inumber (int fd);
```

> fd와 연결된 inode의 번호를 반환합니다. fd는 일반 파일이나 directory를 가리킬 수 있습니다.
>
> inode number는 파일이나 directory를 존재하는 동안 지속적으로 식별하는 고유 번호입니다. Pintos에서는 inode의 sector 번호를 inode number로 사용할 수 있습니다.

<a id="soft-link"></a>

# Symbolic Link

**Pintos에 symbolic link를 구현하십시오.** soft link라고도 부르는 symbolic link는 다른 파일이나 directory를 참조하는 특수한 파일 객체입니다. 이 파일에는 대상의 absolute path 또는 relative path가 저장됩니다. 다음 구성을 가정해 봅시다.

    /
    ├── a
    │   ├── link1 -> /file
    │   │
    │   └── link2 -> ../file
    └── file

`/a`의 symbolic link `link1`는 absolute path `/file`을 가리킵니다. `/a`의 `link2`는 relative path `../file`을 가리킵니다. `link1`나 `link2`를 통해 파일을 읽는 것은 `/file`을 읽는 것과 같습니다.

------------------------------------------------------------------------

```
int symlink (const char *target, const char *linkpath);
```

> 문자열 target을 내용으로 저장하는 symbolic link linkpath를 생성합니다. 성공하면 0, 실패하면 -1을 반환합니다.
