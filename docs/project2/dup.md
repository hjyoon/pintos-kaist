> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/dup.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="extend-file-descriptor-extra"></a>

# File Descriptor 확장 — Extra

**Linux처럼 stdin·stdout을 닫는 기능과 dup2 system call을 지원하십시오.**

기본 Pintos 구현은 `stdin`과 `stdout`의 file descriptor를 닫지 못하게 합니다. 이 extra에서는 Linux처럼 `stdin`과 `stdout`도 닫을 수 있어야 합니다. `stdin`을 닫은 뒤에는 그 입력 경로로 읽을 수 없어야 하고, `stdout`을 닫은 뒤에는 그 출력 경로로 출력할 수 없어야 합니다.

다음으로 `dup2` system call을 구현하십시오.

------------------------------------------------------------------------

```
int dup2(int oldfd, int newfd);
```

> `dup2()`는 `oldfd`를 `newfd` 번호의 file descriptor로 복제합니다. 성공하면 `newfd`를 반환합니다. `newfd`가 이미 열려 있으면 재사용하기 전에 별도 오류 출력 없이 닫습니다.
>
> 다음 두 경우에 주의하십시오.
>
> - `oldfd`가 유효한 file descriptor가 아니면 `-1`를 반환하며 실패합니다. 이때 `newfd`는 닫지 않습니다.
> - `oldfd`가 유효하고 `newfd`가 `oldfd`와 같으면 `dup2()`는 아무 작업도 하지 않고 `newfd`를 반환합니다.
>
> 성공한 뒤에는 두 descriptor를 같은 파일 접근에 사용할 수 있습니다. **서로 다른 file descriptor지만 같은 open file description을 가리키므로**, *file offset*과 *status flags*를 공유합니다. 예를 들어 한쪽에서 `seek`로 offset을 변경하면 다른 쪽의 offset도 함께 바뀝니다.

`dup`로 복제한 descriptor들의 공유 관계와 의미는 fork 이후에도 유지되어야 합니다.

**Extra의 모든 test case를 통과해야 추가 점수를 받습니다. 부분 점수는 없습니다.**
