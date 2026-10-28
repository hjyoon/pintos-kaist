> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/index.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](README.md)

<a id="introduction"></a>

# 소개

KAIST CS330의 Pintos 프로젝트에 오신 것을 환영합니다. 이 수업에서는 KAIST CS330에 맞게 수정한 Pintos를 사용합니다.

원래 Pintos와 요구사항이 일부 다르므로 **이 매뉴얼의 지침을 우선 따라야 합니다.** **본인이 작성한** 이전 Pintos 프로젝트를 참고할 수는 있지만, **변경된 요구사항에 맞춰 일부 기능을 다시 구현해야 합니다.**

코드를 수정하면서 매뉴얼도 함께 갱신했습니다. 매뉴얼과 수정된 구현을 일치시키려고 노력했지만, 아직 맞지 않는 부분이 있을 수 있습니다. 발견하면 담당 강사에게 알려 주십시오.

**[법적·윤리적 사항](introduction/legal_and_ethical_issues.md)을 반드시 읽으십시오.**

pintos-kaist는 x86-64 architecture를 위한 간단한 운영체제 framework로, Stanford University의 Pintos 프로젝트에서 fork한 것입니다. 이하에서는 pintos-kaist를 Pintos라고 부릅니다. Pintos는 kernel thread, user program의 loading과 실행, file system을 지원하지만, 모두 매우 단순한 형태로 구현되어 있습니다. 프로젝트를 진행하면서 이 세 영역의 기능을 보강하고 virtual memory도 추가합니다.

이론적으로 Pintos는 일반 x86-64 PC에서도 실행할 수 있습니다. 그러나 모든 수강생에게 전용 PC를 제공하기는 어려우므로 system simulator에서 실행합니다. system simulator는 x86-64 CPU와 주변 장치를 충분히 정확하게 모사하여, 수정하지 않은 운영체제와 소프트웨어를 실행할 수 있게 하는 프로그램입니다. 수업에서는 **QEMU**를 사용합니다.

프로젝트는 어렵고 많은 시간이 필요합니다. CS330이 시간이 많이 드는 수업으로 알려진 데에는 이유가 있습니다. 참고 자료 제공 등을 통해 부담을 줄이겠지만 상당한 노력이 필요합니다. 불필요한 과제 수행 비용을 줄이고 핵심 문제에 집중하는 데 도움이 되는 의견이 있으면 알려 주십시오. 이 장은 Pintos를 시작하는 방법을 설명합니다. 어떤 프로젝트든 작업에 들어가기 전에 장 전체를 읽으십시오.
