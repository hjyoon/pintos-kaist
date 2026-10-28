> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/introduction/getting_started.html) · 수집일: 2026-10-17 · 대조·교정: 2026-10-28 · [목차](../README.md)

<a id="getting-started"></a>

# 시작하기

먼저 Pintos를 빌드할 수 있는 컴퓨터에 로그인해야 합니다. 강사가 제공하는 Linux 장비나 본인의 Solaris·Linux 장비를 사용할 수 있습니다. 다만 채점은 제공된 장비에서 진행하며, 이 문서도 그 환경을 전제로 합니다. 개인 장비에서의 설치와 실행은 지원하지 않습니다. 각 학생에게는 아래 사양의 서버 환경이 제공됩니다.

다음 명령을 실행하면 Pintos 소스를 'pintos'라는 directory로 내려받을 수 있습니다.

```
git clone https://github.com/casys-kaist/pintos-kaist
```

소스는 **프로젝트 기간이 시작되기 전까지** 변경될 수 있으므로 저장소를 <a href="https://help.github.com/en/github/creating-cloning-and-archiving-repositories/duplicating-a-repository" target="_blank">복제</a>하는 방법을 권장합니다. template이 변경되면 자신의 코드를 <a href="https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork" target="_blank">동기화</a>할 수 있습니다. **public fork는 만들지 마십시오.** 프로젝트 기간 중에는 template에 심각한 버그가 있는 경우를 제외하고 소스를 변경하지 않습니다.

참고로, 제공된 Linux 장비와 동일한 `Ubuntu 16.04.6 LTS` 환경에서 gcc `gcc (Ubuntu 7.4.0-1ubuntu1~16.04~ppa1) 7.4.0`와 qemu-system-x86_64 `QEMU emulator version 2.5.0 (Debian 1:2.5+dfsg-5ubuntu10.43)`를 사용해 Pintos 코드와 정답 구현을 테스트했습니다.

소스를 받은 뒤 Pintos의 최상위 directory에서 다음 명령으로 환경을 설정할 수 있습니다.

```
$ source ./activate
```

이 줄을 home directory의 '.bashrc'에 추가해 두면 편리합니다. 추가하지 않으면 로그인할 때마다 직접 실행해야 합니다.

> **환경 설정 참고:** .bashrc에서 자동 실행하려면 현재 directory에 의존하지 않도록 activate의 절대 경로를 지정하십시오. source는 현재 shell에 환경을 적용합니다.

<a id="source-tree-overview"></a>

## 소스 트리 구성

`pintos/` 안에서 다음과 같은 directory 구성을 확인할 수 있습니다.

- `threads/`: 기본 kernel 소스입니다. Project 1부터 수정합니다.
- `userprog/`: user program loader 소스입니다. Project 2부터 수정합니다.
- `vm/`: 거의 비어 있는 directory입니다. Project 3에서 virtual memory를 구현합니다.
- `filesys/`: 기본 file system 소스입니다. Project 2부터 사용하지만 Project 4 전까지는 수정하지 않습니다.
- `devices/`: keyboard, timer, disk 등 I/O device와 연결되는 코드입니다. Project 1에서 timer를 수정하며, 그 외 코드는 보통 수정할 필요가 없습니다.
- `lib/`: 표준 C library의 일부를 구현합니다. 이 코드는 Pintos kernel과, Project 2부터 그 위에서 실행할 user program 양쪽에 포함됩니다. 수정할 일은 거의 없습니다.
- `include/lib/kernel/`: kernel에만 포함되는 C library 코드입니다. kernel에서 사용할 수 있는 bitmap, doubly linked list, hash table 등의 구현도 있습니다. 이 directory의 header는 kernel 코드에서 `#include <...>` 형식으로 포함할 수 있습니다.
- `include/lib/user/`: user program에만 포함되는 C library 코드입니다. user program에서는 이 directory의 header를 `#include <...>` 형식으로 포함할 수 있습니다.
- `tests/`: 각 프로젝트의 테스트입니다. 구현을 검증하는 데 도움이 된다면 수정해도 되지만, 채점 전에는 원본 테스트로 교체됩니다.
- `examples/`: Project 2부터 사용하는 user program 예제입니다.
- `include/`: header file(`*.h`)을 모아 둔 directory입니다.

<a id="building-pintos"></a>

## Pintos 빌드

이제 첫 프로젝트에 제공된 소스를 빌드합니다. 먼저 `cd` 명령으로 `threads` directory에 들어간 뒤 `make`를 실행하십시오. 그러면 `threads` 아래에 `build` directory를 만들고, 그 안에 `Makefile`과 몇 개의 하위 directory를 준비한 다음 kernel을 빌드합니다.

빌드가 끝나면 `build` directory에서 다음 파일들을 확인할 수 있습니다.

- `Makefile`: `pintos/src/Makefile.build`의 복사본으로, kernel의 빌드 방법을 정의합니다.
- `kernel.o`: kernel 전체의 object file입니다. 각 kernel 소스에서 컴파일한 object file들을 하나로 link한 결과이며, debug information도 포함합니다. 따라서 [GDB](../appendix/debugging_tools.md#gdb)나 [backtrace](../appendix/debugging_tools.md#backtraces) 도구로 분석할 수 있습니다.
- `kernel.bin`: Pintos kernel을 실행할 때 memory에 적재하는 정확한 byte sequence, 즉 kernel memory image입니다. `kernel.o`에서 debug information을 제거한 것으로, 크기가 크게 줄어듭니다. 이는 kernel loader의 설계상 512 kB 크기 제한을 넘지 않게 하는 데 도움이 됩니다.
- `loader.bin`: assembly로 작성된 작은 kernel loader의 memory image입니다. loader는 disk에서 kernel을 memory로 읽어 실행을 시작합니다. PC BIOS의 제약에 따라 크기는 정확히 512 bytes입니다. `build`의 하위 directory에는 compiler가 생성한 object file(`.o`)과 dependency file(`.d`)이 있습니다. dependency file은 다른 소스나 header가 변경됐을 때 어떤 소스를 다시 컴파일해야 하는지 make에 알려 줍니다.

<a id="running-pintos"></a>

## Pintos 실행

simulator에서 Pintos를 편리하게 실행할 수 있도록 pintos라는 프로그램을 제공합니다. 가장 단순한 사용 형태는 pintos argument...이며, 각 argument는 Pintos kernel에 전달됩니다. 새로 만든 `build` directory로 이동한 뒤 pintos run alarm-multiple을 실행해 보십시오. kernel에는 run alarm-multiple이라는 argument가 전달됩니다. 여기서 run은 테스트 실행을 지시하며, alarm-multiple은 실행할 테스트 이름입니다. Pintos가 부팅되고 alarm-multiple 테스트가 여러 화면 분량의 출력을 표시합니다.

command line에서 출력을 redirect하면 serial 출력을 파일에 기록할 수 있습니다. 예를 들면 `pintos -- run alarm-multiple > logfile`과 같습니다. pintos는 QEMU와 virtual hardware를 설정하는 여러 옵션을 제공합니다. 옵션은 kernel에 전달할 명령보다 앞에 두고 `--`로 구분해야 하므로 전체 명령은 `pintos option... -- argument....` 형태가 됩니다. pintos를 argument 없이 실행하면 사용할 수 있는 옵션 목록을 볼 수 있습니다. 화면 출력 방식도 설정할 수 있습니다. `-v`는 VGA display를 끄고, `-s`는 stdin을 통한 serial 입력과 stdout으로의 serial 출력을 끕니다. kernel에는 run 외의 명령과 옵션도 있습니다. 아직 자세히 알 필요는 없지만, `-h`를 사용하면 목록을 확인할 수 있습니다. 예를 들어 `pintos -h`을 실행합니다.
