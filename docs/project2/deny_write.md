> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/project2/deny_write.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="deny-write-on-executables"></a>

# 실행 중인 Executable의 쓰기 금지

**Executable로 사용 중인 파일에 대한 쓰기를 금지하십시오.**

많은 OS는 실행 중인 코드가 disk에서 동시에 변경되면 결과를 예측할 수 없으므로 executable에 대한 쓰기를 막습니다. Project 3에서 virtual memory를 구현한 뒤에는 특히 중요해지지만, 지금 구현해도 필요합니다.

`file_deny_write()`로 열린 파일에 대한 쓰기를 막고, `file_allow_write()`로 다시 허용할 수 있습니다. 단, 다른 opener가 쓰기를 금지한 상태라면 계속 금지됩니다. 파일을 닫아도 그 opener가 건 쓰기 금지는 해제됩니다. 따라서 process가 실행되는 동안에는 executable 파일을 계속 열어 두어야 합니다.
