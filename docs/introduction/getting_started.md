> 원문: [공식 매뉴얼](https://casys-kaist.github.io/pintos-kaist/introduction/getting_started.html) · 수집일: 2026-10-17 · [한국어 목차](../README.md)

<a id="getting-started"></a>

# 시작하기

먼저 Pintos를 빌드할 수 있는 컴퓨터에 로그인해야 합니다. 담당 교원이 제공한 Linux 컴퓨터나 자신의 Solaris·Linux 컴퓨터를 사용할 수 있습니다. 다만 코드는 제공된 컴퓨터에서 테스트하며, 이 문서의 지시도 그 환경을 가정합니다. 개인 컴퓨터에서 Pintos를 설치하고 사용하는 작업은 지원하지 않습니다. 각 학생에게는 아래에 설명된 서버 환경을 제공합니다.

이제 다음 명령으로 Pintos 소스 코드를 'pintos'라는 디렉터리에 받을 수 있습니다.

```
git clone https://github.com/casys-kaist/pintos-kaist
```

소스 코드가 **프로젝트 기간이 시작되기 전**에 바뀔 수 있으므로 [저장소 복제](https://help.github.com/en/github/creating-cloning-and-archiving-repositories/duplicating-a-repository)를 권장합니다. 템플릿이 바뀌면 여러분의 코드를 템플릿과 [쉽게 동기화](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/syncing-a-fork)할 수 있습니다. **공개 포크를 만들지 마세요**. 템플릿의 치명적인 버그를 제외하면 프로젝트 기간 중에는 소스 코드를 변경하지 않습니다.

참고로 Pintos 코드와 해답 코드는 제공된 Linux 컴퓨터와 같은 `Ubuntu 16.04.6 LTS` 환경에서 gcc(`gcc (Ubuntu 7.4.0-1ubuntu1~16.04~ppa1) 7.4.0`)와 qemu-system-x86_64(`QEMU emulator version 2.5.0 (Debian 1:2.5+dfsg-5ubuntu10.43)`)로 테스트했습니다.

소스 코드를 받은 뒤 Pintos 루트 디렉터리에서 다음 명령으로 환경을 설정할 수 있습니다.

```
$ source ./activate
```

이 명령을 홈 디렉터리의 '.bashrc'에 추가해 두는 것이 좋습니다. 그렇지 않으면 로그인할 때마다 다시 입력해야 합니다.

<a id="source-tree-overview"></a>

## 소스 트리 개요

먼저 소스 트리 내부를 살펴봅시다. `pintos/`에서 볼 수 있는 디렉터리 구조는 다음과 같습니다.

- `threads/`: 기본 커널 소스 코드입니다. 프로젝트 1부터 수정합니다.
- `userprog/`: 유저 프로그램 로더의 소스 코드입니다. 프로젝트 2부터 수정합니다.
- `vm/`: 거의 비어 있는 디렉터리입니다. 프로젝트 3에서 여기에 가상 메모리를 구현합니다.
- `filesys/`: 기본 파일 시스템의 소스 코드입니다. 프로젝트 2부터 사용하지만 프로젝트 4 전까지 수정하지 않습니다.
- `devices/`: 키보드, 타이머, 디스크 등 입출력 장치와 연결하는 코드입니다. 프로젝트 1에서 타이머 구현을 수정합니다. 그 밖의 코드는 대체로 수정할 필요가 없습니다.
- `lib/`: 표준 C 라이브러리 일부를 구현합니다. 이 코드는 Pintos 커널과 프로젝트 2부터 그 위에서 실행하는 유저 프로그램 양쪽에 컴파일됩니다. 거의 수정할 필요가 없습니다.
- `include/lib/kernel/`: Pintos 커널에만 포함되는 C 라이브러리 부분입니다. 비트맵, 이중 연결 리스트, 해시 테이블처럼 커널에서 사용할 수 있는 자료형 구현도 있습니다. 커널에서는 `#include <...>` 표기법으로 이 디렉터리의 헤더를 포함할 수 있습니다.
- `include/lib/user/`: Pintos 유저 프로그램에만 포함되는 C 라이브러리 부분입니다. 유저 프로그램에서는 `#include <...>` 표기법으로 이 디렉터리의 헤더를 포함할 수 있습니다.
- `tests/`: 각 프로젝트의 테스트입니다. 제출 코드를 시험하는 데 도움이 된다면 수정할 수 있지만, 실제 채점 전에는 원본으로 교체합니다.
- `examples/`: 프로젝트 2부터 사용하는 유저 프로그램 예제입니다.
- `include/`: 헤더 파일(`*.h`)의 소스 코드입니다.

<a id="building-pintos"></a>

## Pintos 빌드

다음으로 첫 번째 프로젝트용 소스를 빌드합니다. 먼저 `threads` 디렉터리로 `cd`한 뒤 `make`를 실행하세요. `threads` 아래에 `build` 디렉터리를 만들고 `Makefile`과 하위 디렉터리들을 준비한 다음 그 안에서 커널을 빌드합니다.

빌드가 끝나면 `build` 디렉터리에서 다음 파일들을 살펴볼 수 있습니다.

- `Makefile`: `pintos/src/Makefile.build`의 복사본입니다. 커널 빌드 방법을 기술합니다.
- `kernel.o`: 커널 전체의 오브젝트 파일입니다. 각 커널 소스 파일을 컴파일한 오브젝트 파일들을 하나로 링크한 결과이며 디버그 정보를 담고 있습니다. 따라서 GDB([GDB](../appendix/debugging_tools.md#gdb) 참고)나 백트레이스([백트레이스](../appendix/debugging_tools.md#backtraces))를 사용할 수 있습니다.
- `kernel.bin`: 커널의 메모리 이미지, 즉 Pintos 커널을 실행하기 위해 메모리에 적재하는 실제 바이트입니다. `kernel.o`에서 디버그 정보를 제거한 것으로, 공간을 크게 줄여 커널 로더 설계가 부과하는 512 kB 제한을 넘지 않게 합니다.
- `loader.bin`: 디스크에서 커널을 읽어 메모리에 적재하고 실행하는 작은 어셈블리 코드인 커널 로더의 메모리 이미지입니다. PC BIOS가 정한 크기인 정확히 512바이트입니다. `build`의 하위 디렉터리에는 컴파일러가 만든 오브젝트 파일(`.o`)과 의존성 파일(`.d`)이 있습니다. 의존성 파일은 다른 소스나 헤더가 바뀌었을 때 어떤 소스를 다시 컴파일할지 make에 알려 줍니다.

<a id="running-pintos"></a>

## Pintos 실행

시뮬레이터에서 Pintos를 쉽게 실행하는 pintos 프로그램을 제공합니다. 가장 단순한 사용법은 pintos argument...이며 각 인자는 Pintos 커널에 전달돼 처리됩니다. 새로 만든 `build` 디렉터리로 이동해 pintos run alarm-multiple을 실행해 보세요. run alarm-multiple 인자를 커널에 전달하며, run은 테스트 실행을 지시하고 alarm-multiple은 실행할 테스트의 이름입니다. Pintos가 부팅해 alarm-multiple 테스트를 실행하고 화면 몇 장 분량의 텍스트를 출력합니다.

명령행 리다이렉션을 이용해 직렬 출력을 파일로 저장할 수 있습니다. 예를 들면 `pintos -- run alarm-multiple > logfile`입니다. pintos는 QEMU와 가상 하드웨어를 설정하는 여러 옵션을 제공합니다. 옵션은 커널에 전달할 명령보다 앞에 두고 `--`로 구분해, 전체 명령이 `pintos option... -- argument....` 형태가 되게 해야 합니다. 인자 없이 pintos를 실행하면 사용 가능한 옵션 목록을 볼 수 있습니다. 출력 방법도 선택할 수 있습니다. `-v`는 VGA 화면을 끄고 `-s`는 stdin을 통한 직렬 입력과 stdout으로의 직렬 출력을 억제합니다. 커널에는 run 외에도 명령과 옵션이 있습니다. 지금은 중요하지 않지만 `-h`로 목록을 볼 수 있습니다. 예를 들면 `pintos -h`입니다.
