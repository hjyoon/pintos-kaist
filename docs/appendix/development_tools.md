> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/development_tools.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="development-tools"></a>

# 개발 도구

코드를 개발할 때 유용하게 사용할 수 있는 몇 가지 도구가 있습니다.

<a id="tags"></a>

## 태그

태그는 프로그램에 선언된 함수와 전역 변수의 색인입니다. Emacs와 vi를 비롯한 여러 편집기가 이를 사용할 수 있습니다. `pintos/`의 `Makefile`는 make `TAGS` 명령으로 Emacs용 태그를 만들고 make tags로 vi용 태그를 만듭니다.

Emacs에서 `M-`을 사용하여 현재 창의 태그, `C-x 4` .를 새로운 창에서 또는 `C-x 5` .를 새로운 프레임에서 추적합니다. 만약 당신의 커서가 그 명령어 중 어느 하나에 대한 상징 이름에 있다면, 그것은 기본 목표가 됩니다. 태그 이름에는 여러 가지 정의가 있는 경우, `M-0 M-`. 다음으로 이동합니다. 마지막 태그를 따라가기 전에 있던 곳으로 돌아가려면 `M-*`을 사용하세요.

<a id="cscope"></a>

## cscope

`cscope` 프로그램은 또한 프로그램에서 선언된 함수 및 변수에 대한 인덱스를 제공합니다. 태그 시설이 부족한 몇 가지 특징이 있습니다. 특히, 주어진 함수를 호출하는 프로그램에서 모든 포인트를 찾을 수 있습니다.

`pintos/`의 `Makefile`는 make `cscope`로 실행하면 `cscope` 색인을 생성합니다. 색인이 만들어지면 셸 명령행에서 `cscope`를 실행하세요. 보통 명령행 인자는 필요하지 않습니다. 화살표 키로 터미널 아래쪽의 검색 기준을 선택하고 식별자를 입력한 뒤 `Enter`를 누르세요. `cscope`가 터미널 위쪽에 일치하는 항목을 표시합니다. 화살표 키로 항목을 선택하고 `Enter`를 누르면 `cscope`가 기본 시스템 편집기 <sup><a href="development_tools.md#fn_1" id="reffn_1">1</a></sup>를 실행해 해당 위치에 커서를 놓습니다. 새 검색은 `Tab`, `cscope` 종료는 `Ctrl-d`을 입력하면 됩니다.

Emacs 및 vi의 일부 버전은 `cscope`에 대한 자체 인터페이스를 가지고 있습니다. 이 인터페이스를 사용하는 방법에 대한 정보는 `cscope` 홈페이지 (<http://cscope.sourceforge.net>) 를 참조하십시오.

<a id="fn_1"></a>

> <sup>1</sup>. 이것은 일반적으로 `vi`입니다. `vi`을 종료하려면 `:q` `Enter`.[↩](development_tools.md#reffn_1 "Jump back to footnote [1] in the text.")를 입력합니다
