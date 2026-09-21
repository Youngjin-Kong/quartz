# Sorcerer → _PLAYBOOK 이관 제안

작성자: pg-note-forge (Sorcerer 개작 세션). `_PLAYBOOK.md`는 직접 쓰지 않음 — 관리자가 회수 후 일괄 반영.

원본 백업: `03. PG\_backup\Sorcerer.md.bak` (개작 전 1111행 전문)

---

## 제안 1 — 신규 (A. 증상별)

**①어느 절**: 신규 (제목 후보: "강제 명령(command=)이 자기 자신을 보호하는 파일까지는 못 막는다")

**②병합/신규**: 신규. `_PLAYBOOK` 에 `command=`/forced-command 자기파괴 사고를 다루는 항목 없음(grep 확인 — `authorized_keys` 관련 기존 항목은 A-2-10⑤Redis 쓰기 차단·A-37 rbash scp 차단·B-3-11 MOTD·B-3304 Fractal 키 심기뿐, 전부 "제한된 채널로 authorized_keys 에 «접근»" 이지 "그 채널 자체가 제한을 정의하는 파일을 덮어쓸 수 있다"는 이 프레임과 다름).

**③넣을 본문**:

```text
증상 — SSH 인증(키)은 성공하는데 `command=` 강제 명령 때문에 임의 명령이 안 먹는다. 그 강제
명령이 `scp`처럼 "파일 쓰기"가 가능한 원시이고, 쓸 수 있는 대상에 `authorized_keys` 자신이
포함된다.

메커니즘 — `authorized_keys` 옵션 필드(`command=`·`no-pty`·`no-port-forwarding` 등)는
그 줄의 키로 인증했을 때만 적용되는 서버측 제약이다. `command=`는 클라이언트가 요청한 명령을
버리고 지정된 프로그램만 실행하며, 버려진 원래 명령은 `SSH_ORIGINAL_COMMAND` 환경변수로
전달된다. 그런데 이 파일 자체가 세션 사용자 소유이면, "허용된 그 프로그램"이 임의 경로 쓰기가
가능한 한(`scp`가 전형) **제한을 정의하는 파일 자체를 덮어쓸 수 있다** — 옵션 필드만 제거한
새 `authorized_keys`를 같은 경로에 얹으면 다음 접속부터 제한이 사라진다.

일반화 — "제한된 원시(primitive)"를 만나면 그 원시로 제한 자체를 건드릴 수 있는지 먼저 볼 것:
- 쓰기만 되는 원시 → `~/.ssh/authorized_keys`(내 키 추가) · `~/.bashrc`(다음 로그인 시 실행) ·
  `/etc/passwd`(해시 삽입) · cron 파일
- 읽기만 되는 원시(LFI) → `/proc/self/environ` · 로그 포이즈닝 · 설정 파일의 DB 자격증명
- 명령 하나만 되는 sudo 항목 → GTFOBins에서 그 바이너리의 탈출 구문
질문은 항상 같다 — "내가 건드릴 수 있는 것 중에 나를 가두는 규칙이 들어 있는가?"

덮어쓸 때 지킬 것 둘:
1. 키 본문은 그대로 둔다. 우리가 가진 개인키에 대응해야 하는 공개키라 지울 것은 앞의
   옵션 필드뿐
2. 퍼미션 — sshd는 `StrictModes yes`(기본값)에서 `~/.ssh`가 그룹/타인 쓰기 가능하면 키를
   거부한다. scp는 원본 파일의 모드를 보존하므로 로컬에서 `chmod 600 authorized_keys`를
   유지한 채 올릴 것

"인증 성공 + 제한"과 "인증 실패"를 구분하는 진단표:
| 증상 | 의미 | 다음 수 |
|---|---|---|
| `Permission denied (publickey)` | 인증 실패. 키가 안 맞거나 계정이 없다 | 키/사용자명 재확인 |
| 접속은 되는데 프롬프트 대신 메시지/즉시 종료 | 인증 성공 + 제한. `command=`·`no-pty`·제한 셸(rbash) | `authorized_keys`를 손에 넣었다면 옵션 필드를 읽을 것 |
| `PTY allocation request failed` | `no-pty` | `ssh -T`로 비대화형 명령만 시도 |

`authorized_keys`를 미리 못 읽는 실전 상황의 탐침 3종:
```bash
ssh -i id_rsa max@target 'id'                       # 강제 명령 여부 확인
ssh -i id_rsa max@target -T 'bash -i'               # PTY 없이 셸 시도
ssh -i id_rsa max@target -o RemoteCommand=none -N   # 세션만 유지
```

출처 — [[Sorcerer]] (`command="/home/max/scp_wrapper.sh"`, scp로 authorized_keys 자체 덮어쓰기)
```

**④지우기 전 원문** (Sorcerer.md.bak 2-3, 3장 note, 6장②):

> `command=`는 어떤 프로그램이 실행되는지를 통제한다. 그런데 이 설계에는 구멍이 있다:
> **허용된 그 프로그램이 `authorized_keys` 자체를 덮어쓸 수 있다면, 제한은 자기 자신을 지키지 못한다.**
> `scp`는 임의 경로에 파일을 쓴다. `max`는 `/home/max/.ssh/authorized_keys`의 소유자다. 따라서:
> ```bash
> scp 전용 채널  →  /home/max/.ssh/authorized_keys 덮어쓰기  →  옵션 필드 제거  →  다음 접속은 완전한 셸
> ```
> [!danger] 일반화 — "제한된 원시(primitive)"를 만나면 **그 원시로 제한 자체를 건드릴 수 있는지** 먼저 본다
> 같은 사고가 반복해서 나온다:
> - **쓰기만 되는 원시** → `~/.ssh/authorized_keys`(내 키 추가) · `~/.bashrc`(다음 로그인 시 실행) · `/etc/passwd`(해시 삽입) · cron 파일
> - **읽기만 되는 원시(LFI)** → `/proc/self/environ` · 로그 포이즈닝 · 설정 파일의 DB 자격증명
> - **명령 하나만 되는 sudo 항목** → GTFOBins에서 그 바이너리의 탈출 구문
> 질문은 항상 같다: **"내가 건드릴 수 있는 것 중에 나를 가두는 규칙이 들어 있는가?"**
> [!warning] `authorized_keys`를 덮어쓸 때 두 가지를 지켜라
> 1. **키 본문을 바꾸지 마라.** 우리가 가진 `id_rsa`에 대응하는 공개키여야 한다. 지울 것은 **앞의 옵션 필드뿐**이다
> 2. **퍼미션.** sshd는 `StrictModes yes`(기본값)에서 `~/.ssh`가 그룹/타인 쓰기 가능하면 키를 **거부**한다. scp는 원본 파일의 모드를 보존하므로 로컬에서 `chmod 600 authorized_keys`를 유지한 채 올린다
> ### ② SSH가 붙는데 셸이 안 뜬다 — "인증 실패"와 "제한"을 구분하라
> **구분 기준:**
> | 증상 | 의미 | 다음 수 |
> |---|---|---|
> | `Permission denied (publickey)` | **인증 실패.** 키가 안 맞거나 계정이 없다 | 키/사용자명 재확인 |
> | 접속은 되는데 프롬프트 대신 메시지/즉시 종료 | **인증 성공 + 제한.** `command=`·`no-pty`·제한 셸(rbash) | **`authorized_keys`를 손에 넣었다면 옵션 필드를 읽어라** |
> | `PTY allocation request failed` | `no-pty` | `ssh -T`로 비대화형 명령만 시도 |
> ```bash
> ssh -i id_rsa max@target 'id'                 # 강제 명령 여부 확인
> ssh -i id_rsa max@target -T 'bash -i'         # PTY 없이 셸 시도
> ssh -i id_rsa max@target -o RemoteCommand=none -N   # 세션만 유지
> ```

---

## 제안 2 — 병합 (A-37. rbash 대상에 `scp` 가 조용히 끊긴다)

**①어느 절**: `A-37. rbash 대상에 \`scp\` 가 조용히 끊긴다`

**②병합/신규**: 병합. 같은 `-O` 메커니즘(OpenSSH 9+ scp 기본 SFTP 전환)이 **다른 증상**(rbash 의 `/` 거부가 아니라, 강제 명령 래퍼의 `case 'scp'*` 문자열 매칭 실패)에서도 발생함을 보여주는 두 번째 사례.

**③넣을 본문**:

```text
**같은 메커니즘의 다른 증상 — 강제 명령(`command=`) 래퍼.** [[Sorcerer]] 는 rbash 가 아니라
`command="scp_wrapper.sh"` 강제 명령 환경이었다. 래퍼는 `$SSH_ORIGINAL_COMMAND` 가 문자열
`scp` 로 시작하는지만 검사한다. 최신 scp 클라이언트가 기본으로 SFTP 서브시스템을 요청하면
서버가 받는 `SSH_ORIGINAL_COMMAND` 는 `scp -t ...` 가 아니라 `sftp` 가 되어 매칭이 실패,
`ACCESS DENIED.` 로 떨어진다. `-O` 로 레거시 `scp -t/-f` 프로토콜을 강제하면 문자열이
다시 `scp` 로 시작해 통과한다.

⚠️ **`sshd(8)` 원문**: *"Note that this option applies to shell, command or subsystem
execution."* — `command=` 는 scp(레거시, command 실행)든 sftp(subsystem 실행)든 **둘 다**
가로채고, 둘 다 원래 요청을 `SSH_ORIGINAL_COMMAND` 로 노출한다. 래퍼가 그 값을 인용 없이
셸에 넘기면 명령 주입 공격면도 별도로 열린다.

→ **강제 명령/제한 셸 환경에서 `scp` 가 실패하면(연결이 끊기든, 서버 스크립트가 거부하든)
가장 먼저 `-O` 를 붙여볼 것.** rbash 의 "슬래시 없는 명령 이름" 우회와 강제 명령 래퍼의
"문자열이 `scp` 로 시작" 우회는 근본 원인(OpenSSH 9+ 의 SFTP 기본 전환)이 같다.
```

**④지우기 전 원문** (Sorcerer.md.bak 2-4):

> 전통적으로 `scp`는 **원격에서 `scp -t`(수신 모드)/`scp -f`(송신 모드)를 실행**해 그 표준입출력으로 파일을 흘려보내는 방식이었다(레거시 SCP/rcp 프로토콜). 그래서 `scp_wrapper.sh`의 `case 'scp'*` 검사가 통과된다 — 서버가 받는 `SSH_ORIGINAL_COMMAND`가 실제로 `scp -t ...` 로 시작하기 때문이다.
> **OpenSSH 9.0부터 `scp`는 기본적으로 SFTP 프로토콜을 쓴다.** 릴리스 노트 원문:
> > This release switches scp(1) from using the legacy scp/rcp protocol to using the SFTP protocol by default. … the scp(1) client may be instructed to use the legacy scp/rcp using the `-O` flag.
> (정확히는 **8.7**에서 `-s` 플래그로 SFTP를 실험적으로 넣었고, **9.0**에서 기본값을 뒤집으며 `-s`를 없애고 `-O`를 탈출구로 남겼다.)
> 그러면 서버가 받는 요청은 `scp -t ...` 명령이 아니라 **`sftp` 서브시스템 요청**이 되고, 이 래퍼의 `case` 분기는 `*`(기본)로 떨어져 **`ACCESS DENIED.`** 를 뱉는다.
> [!note] 강제 명령은 scp에도 sftp에도 **똑같이** 걸린다
> `sshd(8)`의 `command=` 설명에 한 문장이 박혀 있다: *"Note that this option applies to shell, command or subsystem execution."*
> - `scp` 레거시 모드 → **command 실행** (`scp -t /path`) → `SSH_ORIGINAL_COMMAND`에 그 문자열이 들어온다
> - `sftp` → **subsystem 실행** → `SSH_ORIGINAL_COMMAND`가 `sftp` 가 된다
> 둘 다 강제 명령으로 대체되고, **둘 다 원래 요청이 `SSH_ORIGINAL_COMMAND`에 노출된다.**
> [!danger] 강제 명령/제한 셸 환경에서 `scp`가 실패하면 **가장 먼저 `-O`를 붙여본다**
> 증상이 헷갈린다 — 인증은 되는데 전송만 안 되거나, 서버 스크립트의 거부 메시지가 나온다. "키가 틀렸나?"로 새면 시간을 크게 잃는다.

---

## 제안 3 — 신규 (A. 증상별)

**①어느 절**: 신규 (제목 후보: "커널 익스플로잋 소스를 컴파일 전에 읽지 않으면 헛수고가 된다")

**②병합/신규**: 신규. B-24(커널 익스플로잋은 "한 발") 는 **발사 후 재시도 금지**가 골자라 이 항목의 **발사 «전» 소스 검증** 과 스코프가 다름. `A-1` 부근 nmap OS 지문 신뢰 금지(line 69)와도 다른 카드 — 이쪽은 "오탐을 실제로 믿고 익스플로잋을 골라 컴파일까지 갔다"는 구체적 실패 사례.

**③넣을 본문**:

```text
증상 — nmap OS 지문(`OS details: Linux 5.0 - 5.14`)을 근거로 그 범위의 커널 익스플로잋을
찾아 컴파일까지 했으나, 실제 커널은 배포판 버전(예: Debian 10 buster = 4.19 계열)이었다.

[[Sorcerer]] 실측 — `OpenSSH 7.9p1 Debian 10+deb10u2` 배너로 OS는 Debian 10 확정인데,
nmap 의 TCP/IP 스택 추정은 `Linux 5.0 - 5.14` 를 냈다(오탐 — [[Pelican]] 에서 같은 배너의
박스를 덤프해 `uname -a` 로 `4.19.0-10-amd64` 확인). 이 오탐을 근거로 CVE-2021-22555
(`theflow@` 의 netfilter `xt_compat_target_from_user`) 를 골라 `gcc -m32 -static` 로
컴파일까지 했다(14:54~14:56, 782,560바이트). 15분 뒤 SUID `start-stop-daemon` 으로
root 를 잡아 실제로는 쓰지 않았다.

**컴파일 전에 소스 자체가 답을 갖고 있었다:**
```c
/* Exploit tested on Ubuntu 5.8.0-48-generic and COS 5.4.89+. */
#define KERNEL_UBUNTU_5_8_0_48 1
```
하드코딩된 ROP 가젯 오프셋이 **두 특정 커널 빌드 전용**이라, Debian 10 의 4.19 커널에서는
성공이 아니라 **커널 패닉**이 정상 결과다. 추가로 `ip_tables` 모듈 로드 여부·유저 네임스페이스
생성 권한도 전제조건이었다.

**손절 규칙**:
1. 커널 익스플로잋은 열거를 전부 끝낸 뒤 마지막에 본다 — `sudo -l`·SUID·cron·capabilities·
   쓰기 가능 서비스 파일·프로세스 목록을 먼저 다 훑을 것
2. `uname -a` 로 커널을 확정한 뒤에 고른다 — nmap 의 OS 추측은 근거가 못 됨
3. 익스플로잋 소스의 `#define` 과 "Tested on" 주석을 컴파일 «전에» 읽을 것. 오프셋이
   하드코딩돼 있으면 그 빌드 외에는 패닉
4. 박스가 죽으면 리버트해야 하고, 리버트는 20분 — 24시간 시험에서 크다
5. 정 써야 하면 로컬에 동일 커널 VM 을 먼저 세워 시험 — 시험 중엔 그럴 시간이 없으므로
   결국 "쓰지 마라"는 뜻

→ **컴파일에 쓴 시간이 `find / -perm -4000` 한 줄보다 100배 길었던 사례**([[Sorcerer]]).
```

**④지우기 전 원문**: 위 §"kernel 949-1001" 블록 전체(본 파일 상단 조사 과정에서 이미 그대로 인용) — `### ⑤ 버린 경로 (2) — 커널 익스플로잋 CVE-2021-22555를 컴파일까지 해놓고 안 썼다` 절 전문. (분량상 재인용 생략 — `03. PG\_backup\Sorcerer.md.bak` 949~1001행 원문 그대로가 원본이며, 위 ③ 본문이 그 손실 없는 재구성임. 원 표현 중 "이 박스의 정답은 `find / -perm -4000` 한 줄이었다. 커널 익스플로잋을 컴파일하는 데 쓴 시간이 그 한 줄보다 100배 길다." 문장은 위 인용에 그대로 보존함)

---

## 제안 4 — 병합 (B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash))

**①어느 절**: `B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)`

**②병합/신규**: 병합. 기존 카드는 `sh x.sh`/PATH 하이재킹 스크립트 경유 사례([[GLPI]]·[[PlanetExpress]])뿐 — `start-stop-daemon -x` 처럼 **셸을 직접 spawn** 하는 GTFOBins 벡터가 아직 없음. 같은 dash euid 드롭 메커니즘의 세 번째 실측.

**③넣을 본문**:

```text
**GTFOBins `start-stop-daemon` 도 같은 메커니즘.** [[Sorcerer]] — 비표준 SUID
`/usr/sbin/start-stop-daemon` 발견 후 `start-stop-daemon -S -x /bin/sh -- -p` 로 root.
`-x`(`--exec`)가 지정한 프로그램을 실행하는 게 본질이라 SUID가 붙으면 "임의 프로그램을
root로 실행"과 동일해진다. `--` 는 옵션 종료 구분자 — 없으면 뒤의 `-p` 를
`start-stop-daemon` 자신의 `--pidfile` 옵션으로 오인해 실패한다.
GTFOBins 는 SUID 탭에서만 `-p` 를 요구하고(Shell/Sudo 탭은 `-p` 없음) —
"기본 셸이 SUID 특권을 버리지 않는 배포판에서는 `-p` 를 빼라"는 주석이 붙어 있음. 데비안의
`/bin/sh` 는 dash 라 이 카드의 dash euid 드롭 메커니즘이 그대로 적용되어 `-p` 필수.
```

**④지우기 전 원문** (Sorcerer.md.bak 4-4 note + 2-5 danger):

> [!note] 이 명령은 GTFOBins의 SUID 항목과 **글자 그대로 동일**하다
> GTFOBins `start-stop-daemon` 페이지는 셋을 싣고 있다:
> - Shell(일반) / Sudo — `start-stop-daemon -S -x /bin/sh`
> - **SUID — `start-stop-daemon -S -x /bin/sh -- -p`**
> GTFOBins의 단서: **기본 셸이 SUID 특권을 버리지 않는 배포판에서는 `-p`를 빼라.** 데비안의 `/bin/sh`는 dash고 dash는 버리므로 **여기서는 `-p`가 필수**다.
> [!danger] `sh -p`의 `-p`가 없으면 SUID 셸은 무용지물이다
> 데비안의 `/bin/sh`는 **dash**다. `dash(1)`의 `-p` 정의를 그대로 읽자:
> > "Do not attempt to reset effective uid if it does not match uid. This is not set by default to help avoid incorrect usage by setuid root programs via `system(3)` or `popen(3)`."
> 즉 dash는 **기본적으로 `euid != uid`면 euid를 uid로 되돌린다.** SUID로 얻은 root를 스스로 버리는 것이다. `-p`가 그 초기화를 막는다.

---

## 제안 5 — 신규 (A. 증상별)

**①어느 절**: 신규 (제목 후보: "웹루트에 노출된 백업 아카이브 — 디렉터리 열거 확장자에 zip/bak/tar.gz 를 넣지 않으면 못 본다")

**②병합/신규**: 신규. 기존 `A-1-20`(php 확장자 누락 계열, [[Zipper]] 등)·`A-15`(302 여도 본문) 와는 다른 구체 사례 — "아카이브·백업 확장자 자체를 후보에서 빠뜨림" + "디렉터리 리스팅을 스캐너 요약에서 놓칠 뻔함" 두 교훈을 한 카드로 묶음.

**③넣을 본문**:

```text
증상 — `-x html,txt` 같은 일반 확장자로만 디렉터리 열거를 돌려서 `.zip`/`.bak`/`.tar.gz`
백업 파일 자체는 못 찾고, 그 파일이 들어 있는 **디렉터리**만 워드리스트 운으로 맞음.

[[Sorcerer]] — `feroxbuster -x html,txt` 로는 `zipfiles` 디렉터리(301)만 걸렸고, 그 안의
`francis.zip`·`max.zip` 등은 **디렉터리 리스팅** 이 켜져 있어서 보였을 뿐, 워드리스트에
파일 이름(`francis`·`max`·`miriam`·`sofia`, 사람 이름 사전)이 우연히 있었기에 재귀 워드리스트
매칭으로 잡힌 것. feroxbuster 는 `--scan-dir-listings` 없이는 리스팅을 재귀로 훑지 않고,
마지막 줄에 그 사실을 스스로 알려준다:
`=> Directory listing (add --scan-dir-listings to scan)`
이 요약 줄을 안 읽었으면 파일 이름이 흔치 않은 경우 `zipfiles/` 존재만 알고 내용물은
놓쳤을 것.

→ 다음부터:
```bash
feroxbuster -u http://TARGET:PORT/ \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x zip,tar,tar.gz,bak,old,sql,txt,conf,php,html -t 50
```
→ **디렉터리 리스팅이 켜진 경로를 스캐너가 알려주면 무조건 브라우저로 직접 연다** — 워드리스트
운에 맡기지 말 것. 스캐너의 마지막 요약·경고 줄을 읽는 습관 자체가 별도로 값어치가 있다.

→ 홈 디렉터리 백업(`.zip` 등)이 잡히면 SSH 키·`.bash_history`·`.netrc`·`*.bak` 앱 설정까지
한 번에 노출되는 경우가 많다([[Sorcerer]] 는 `id_rsa` + `authorized_keys` + `tomcat-users.xml.bak`
셋을 동시에 얻음) — `unzip -l` 로 숨은 파일(`.` 로 시작) 포함 목록부터 확인할 것.

→ 로그인 폼을 먼저 보면 자격증명부터 찔러보고 싶어지지만, **커스텀 폼은 "기본 자격증명"
개념 자체가 없는 경우가 많다.** 순서: 열거 → 소스/주석/robots.txt → 그다음이 자격증명.
`PasswordField` 존재가 곧 공격면이라는 뜻은 아니다.
```

**④지우기 전 원문**: 위 §"218-232"·"879-885"·"1014-1018" 블록(본 파일 상단 조사에서 이미 원문 그대로 인용). 요지 보존 확인 문장: "정답 파일은 `.zip`이었다. `-x html,txt`로는 `zipfiles` **디렉터리**를 우연히 맞춰야만 발견된다." / "`http://192.168.120.100:7742/zipfiles/ => Directory listing (add --scan-dir-listings to scan)`" / "**폼은 마지막에 공략한다.** 열거 → 소스/주석 → robots.txt → 그 다음이 자격증명이다."

---

## 제안 6 — 신규 (A. 증상별, 짧은 카드)

**①어느 절**: 신규 (제목 후보: "NFS 포트가 열려 있는데 mountd 열거를 안 하고 넘어갔다")

**②병합/신규**: 신규. `_PLAYBOOK` 에 `showmount` 키워드 매칭 0건.

**③넣을 본문**:

```text
증상 — `2049/tcp nfs` + `rpcinfo` 에 mountd 가 여러 개 뜨는데 정찰 산출물에 `showmount`
실행 기록이 없다.

[[Sorcerer]] — mountd 셋이 열려 있었으나 익스포트를 열거한 기록이 없어 "확인 안 함" 으로
남김. `/home` 이 익스포트돼 있었다면 zip 유출 없이 `.ssh` 를 바로 읽었을 것이고,
`no_root_squash` 였다면 SUID 바이너리를 직접 심어 권한상승까지 한 번에 갔을 가능성
[가정] — 확인하지 않았으므로 단정하지 않음.

→ NFS 포트가 보이면 반사적으로 두 줄:
```bash
showmount -e <타겟>                                    # 익스포트 목록
mount -t nfs <타겟>:/EXPORT /mnt/nfs -o vers=3,nolock
```
```

**④지우기 전 원문** (Sorcerer.md.bak 1-6):

> `2049/tcp nfs`가 열려 있고 mountd가 셋이나 떠 있는데, **이 박스의 산출물에는 `showmount` 결과가 남아 있지 않다.** 실제로 익스포트를 열거했는지 확인할 수 없으므로 결과를 지어내지 않는다.
> #### NFS는 이 박스에서 훨씬 짧은 길이였을 수 있다 [가정]
> `/home`이 익스포트돼 있었다면 zip을 거치지 않고 `max`의 `.ssh`를 바로 읽었을 것이고, `no_root_squash`였다면 SUID 바이너리를 직접 심어 권한상승까지 한 번에 갔을 것이다.
> **확인하지 않았으므로 단정하지 않는다.** 다만 "열린 NFS를 보고 열거하지 않았다"는 것 자체가 정찰 누락이다.

---

## 제안 7 — 신규 (B. 기법 카드, 분량 큼 — 버린 경로지만 시험 단골 유형)

**①어느 절**: 신규 (제목 후보: "Tomcat CVE-2017-12617 — PUT 트레일링 슬래시로 확장자 매퍼 우회 (JSP 업로드 RCE)")

**②병합/신규**: 신규. `_PLAYBOOK` 에 CVE-2017-12617/12615 매칭 0건.

**③넣을 본문**: 아래 ④ 원문 전체를 **그대로** 이관(요약 금지 대상 — 코드블록·표·1차 사료 인용이 대부분). 유일하게 덧붙일 문장: "[[Sorcerer]] 에서 8080 Tomcat 7.0.4 발견 후 후보로 검토했으나 최종 경로에는 쓰이지 않음(다른 경로가 더 빨랐음) — readonly 기본값(true) 때문에 전제조건 검증(`curl -i -X OPTIONS`)에서 걸렸을 가능성 [가정], 실행 로그 없음."

**④지우기 전 원문**: 본 파일 상단에서 이미 그대로 인용한 `### 2-6. 참고 — Tomcat 7.0.4와 CVE-2017-12617` 절 전문(원본 510~614행, 아파치 공지 원문·영향범위 표·매퍼 코드·패치 커밋 2개·수동 재현 curl 2단계·플래그 해설 표·시험 금지 경고 전부 포함). 재타이핑 손실 방지를 위해 이 파일 앞부분 도구 호출 결과에 이미 원문 그대로 캡처돼 있으며, 관리자 반영 시 `03. PG\_backup\Sorcerer.md.bak` 510~614행을 직접 잘라 붙일 것을 권장(가장 안전).

---

## 검산

이관 제안 7건(신규 5 · 병합 2). 원본에서 삭제된 절(구 장 번호 기준): 0(NFS 미탐), 2-3·2-4(authorized_keys 자기파괴·scp -O), 2-6(Tomcat CVE 전문), 6장 전체(①~⑧ 시행착오), 7장 전체(시험 관점), 8장 방어표는 각 finding 의 Vulnerability Fix 로 분산 흡수(별도 이관 아님). 삭제 절 수와 위 제안(①~⑦, 제안 3·5는 각각 절 2개씩 흡수) 건수가 일치함 — 별도 카운트 없이 원본 각 절이 정확히 하나의 제안 안에 인용돼 있는지 위에서 재확인함.
