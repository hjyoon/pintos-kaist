> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/introduction/grading.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="grading"></a>

# 채점

과제는 테스트 결과를 기준으로 채점합니다.

<a id="testing"></a>

## 테스트

각 프로젝트에는 이름이 `tests`로 시작하는 여러 테스트가 있습니다. 제출물을 전체적으로 검사하려면 해당 프로젝트의 `build` directory에서 make check를 실행하십시오. 각 테스트를 빌드하고 실행한 뒤 `pass` 또는 `fail`를 출력합니다. 실패하면 원인에 관한 설명도 표시하며, 모든 테스트가 끝나면 결과를 요약합니다.

테스트를 하나씩 실행할 수도 있습니다. 테스트 `t`의 출력은 `t.output`에 저장되고, 채점 스크립트가 이를 `pass` 또는 `fail`로 판정해 `t.result`에 기록합니다. 단일 테스트를 실행하고 채점하려면 `build` directory에서 `.result` 파일을 명시적으로 make하십시오. 예를 들면 `make tests/threads/alarm-multiple.result`과 같습니다. make가 결과를 최신 상태라고 판단해 실행하지 않을 때 강제로 다시 실행하려면 make clean을 사용하거나 `.output` 파일을 직접 삭제하십시오. 기본적으로는 테스트가 끝나야 결과를 볼 수 있습니다. 실행 과정을 함께 보려면 make command line에 `VERBOSE=1`을 지정하십시오. 예를 들어 make check `VERBOSE=1`를 실행합니다.

테스트와 관련 파일은 모두 `pintos/src/tests`에 있습니다. 올바른 테스트로 채점하기 위해 제출물 검사 전 이 directory를 수정되지 않은 원본으로 교체합니다. 따라서 debugging을 위해 테스트를 수정해도 되지만, 실제 채점에는 원본이 사용됩니다. 테스트에도 버그가 있을 수 있습니다. 자신의 코드가 아니라 테스트의 문제라고 판단하면 알려 주십시오. 확인 후 필요하면 수정하겠습니다.

테스트를 공개했다는 점을 악용해서는 안 됩니다. 제공된 test case만이 아니라 일반적인 상황에서도 코드가 올바르게 동작해야 합니다. 예를 들어 실행 중인 테스트 이름에 따라 kernel의 동작을 바꾸는 것은 허용되지 않습니다. 이런 식으로 테스트를 우회하면 점수를 받을 수 없습니다. 자신의 방법이 허용되는지 불분명하면 문의하십시오.

<a id="submission"></a>

## 제출

archive를 만드는 명령을 제공합니다. `threads`, `userprog`, `vm`, `filesys` directory가 있는 Pintos 최상위 directory에서 `TEAM=YOUR_TEAM_NUMBER make archive`를 실행하십시오. 예를 들면 `TEAM=5 make archive`과 같습니다. 같은 directory에 `team5.tar.gz`가 생성되면 그 archive를 제출합니다. **중복 제출하지 마십시오.** 팀당 한 번 제출하면 됩니다.
