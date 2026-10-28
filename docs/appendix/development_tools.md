> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/appendix/development_tools.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="development-tools"></a>

# 개발 도구

코드를 개발할 때 유용한 도구를 소개합니다.

<a id="tags"></a>

## Tags

tags는 프로그램에 선언된 함수와 전역 변수의 index입니다. Emacs, vi 등 여러 editor에서 사용할 수 있습니다. `pintos/`의 `Makefile`는 make `TAGS`로 Emacs용 tags를, make tags로 vi용 tags를 생성합니다.

Emacs에서는 `M-`.로 현재 window에서, `C-x 4` .로 새 window에서, `C-x 5` .로 새 frame에서 tag를 따라갈 수 있습니다. cursor가 symbol 이름 위에 있으면 그 이름이 기본 검색 대상이 됩니다. 정의가 여러 개면 `M-0 M-`.로 다음 정의로 이동합니다. 이전 위치로 돌아가려면 `M-*`를 사용하십시오.

<a id="cscope"></a>

## cscope

`cscope`도 함수와 변수의 index를 제공합니다. tags에는 없는 기능도 있으며, 특히 주어진 함수를 호출하는 모든 위치를 찾을 수 있습니다.

`pintos/`의 `Makefile`에서 make `cscope`를 실행하면 `cscope` index를 생성합니다. 이후 shell에서 `cscope`를 실행하면 되며 보통 argument는 필요 없습니다. 화면 아래의 검색 조건을 방향키로 고르고 identifier를 입력한 뒤 `Enter`를 누르십시오. `cscope`가 화면 위쪽에 결과를 표시합니다. 원하는 항목을 고르고 `Enter`를 누르면 `cscope`가 기본 editor를 열어<sup><a id="reffn_1"></a>[1](development_tools.md#fn_1)</sup> 해당 위치로 이동합니다. 새 검색은 `Tab`, 종료는 `Ctrl-d`이며 종료 대상은 `cscope`입니다.

Emacs와 일부 vi는 `cscope` 연동 interface도 제공합니다. 사용 방법은 `cscope` <a href="http://cscope.sourceforge.net" target="_blank">홈페이지</a>를 참조하십시오.

<a id="fn_1"></a>

> <sup>1</sup>. 기본 editor는 보통 `vi`입니다. `vi`에서 나가려면 `:q` `Enter`를 입력하십시오. [↩](development_tools.md#reffn_1 "Jump back to footnote [1] in the text.")
