# Pelican → _PLAYBOOK 이관 제안

작성일 2026-08-26. 이 파일은 제안만 담는다 — `_PLAYBOOK.md` 는 건드리지 않았다.
검산: 옛 노트(§0·1·2·3·6·7·8·9, 백업 `03. PG\_backup\Pelican.md.bak`)에서 **삭제한 학습 자료 블록 6건 = 아래 제안 6건.** 개수 일치.

---

## 제안 1 — 병합 → `B-1-10. ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE`

**병합.** 기존 "자매 사례" 표에 Exhibitor/ZooKeeper 행을 추가하고, 말미의 일반화 문장에 Exhibitor를 명시적으로 포함시킨다.

**추가할 표 행:**

| 박스 | 버전 | 경로 |
|---|---|---|
| [[Pelican]] | ZooKeeper 3.4.6 + Exhibitor(버전 미상, 1.0.9~1.7.1 범위 내 취약) | Config 탭 `java.env script` 필드에 `$( )`/백틱 삽입 → ZooKeeper 재기동 시 셸에서 평가(CVE-2019-5029). Exhibitor가 ZooKeeper 기동 주체라 "설정 편집 권한 = 코드 실행 권한" |

**추가할 일반화 문장** (기존 "관리 훅·스크립트 실행 기능이 있는 감시·모니터링 웹앱(Cacti·Nagios·LibreNMS 류) 전반에 같은 접근(무인증이면 훅=RCE)이 적용됨." 뒤에 이어붙임):

> **감독(supervisor) UI가 대상 프로세스를 기동하는 구조**(Exhibitor→ZooKeeper, Jenkins→빌드 에이전트)에서는 "설정값이 나중에 셸에서 확장된다"는 조건만 서면 관리 UI가 곧 RCE 임. 판정 순서 — ① 관리 UI가 로그인을 안 묻는가 ② 그 UI가 하위 프로세스를 기동/재기동하는가 ③ 그 기동 경로에 사용자가 넣은 문자열이 이스케이프 없이 들어가는가. 셋 다 예면 별도 CVE 없이도 RCE 가 성립함.

**지우기 전 원문** (Pelican.md 옛 §1-3·§2-1):

```
Exhibitor는 "ZooKeeper를 실행하는 주체"다. 그래서 Exhibitor 설정을 바꾸는 것은 곧 "다음에 실행될 명령줄을 바꾸는 것"이다.

관리 UI가 프로세스 기동을 담당하면 **설정 편집 권한 == 코드 실행 권한**이 된다. Jenkins·Nagios·systemd 유닛 편집 UI가 전부 같은 구조다.

> [!danger] "로그인 화면이 없다"는 것은 인증이 없다는 뜻이다
> 관리 UI가 로그인을 묻지 않고 열리면 그 순간 미인증 원격 공격자 = 관리자다. 별도의 취약점을 찾기 전에 UI가 제공하는 정상 기능부터 훑어라:
> - 설정 편집(이 박스) · 스크립트 실행 · 플러그인 업로드 · 백업 복원 · 로그 경로 지정 · 명령 정의
>
> Exhibitor는 인증 기능 자체가 없고, 1.7.0 이전에는 바인딩 인터페이스 지정 기능조차 없었다(Talos 공지). 기본 포트는 **8080**이다.
```

---

## 제안 2 — 신규 → `A. 증상별` `A-1. 정찰·열거`

**신규.** 번호는 단독 기록자가 배정.

**제목(안):** nmap `http-title: Did not follow redirect to …` 는 진입 URL을 통째로 알려준다

**본문(안):**

nmap 의 `http-title` NSE 는 리다이렉트를 따라가지 않고 **목적지 URL을 제목 자리에 그대로 출력**한다. 이 문자열을 보면 반드시 그 URL을 직접 연다. 리다이렉트 목적지에는 종종:
- 경로 — 디렉터리 열거로는 못 찾을 수 있는 깊은 경로
- 호스트명/도메인 — `/etc/hosts` 에 추가해야 하는 vhost
- 다른 포트 — 리다이렉트가 포트를 건너뛰는 경우

[[Pelican]] 실측 — `8081/tcp … |_http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html`. 같은 스캔의 8080 은 `Error 404 Not Found` 뿐이라 8080 단독으로는 "빈 서버"로 오판하기 쉬움. 8081 의 이 한 줄이 제품명(`exhibitor`)과 정확한 경로를 동시에 줌.

→ **404 페이지를 만나면 루트가 아니라 경로를 찾을 것.** 같은 IP 의 다른 포트가 알려준 리다이렉트 목적지부터 확인.

**지우기 전 원문** (옛 §6 ①):

```
### ① 8080만 보고 "404, 끝"으로 판단할 뻔했다 — 이 박스 최대의 함정

​```text
8080/tcp  open  http        Jetty 1.0
|_http-server-header: Jetty(1.0)
|_http-title: Error 404 Not Found
​```

브라우저로 `http://192.168.115.98:8080/` 을 열면 **Jetty 404 페이지**뿐이다. 여기서 "빈 서버"로 판단하면 박스가 막힌다.

**무엇이 구했나** — 바로 다음 줄이다:

​```text
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html
​```

nmap의 `http-title` NSE는 리다이렉트를 따라가지 않고 **목적지 URL을 제목 자리에 그대로 출력한다.** 그 URL에 `/exhibitor/`가 들어 있었다.

> [!danger] 일반화 — `Did not follow redirect to` 는 nmap이 주는 최고의 힌트 중 하나다
> 이 문자열을 보면 반드시 그 URL을 직접 연다. 리다이렉트 목적지에는 종종 이런 것들이 들어 있다:
> - 경로(이 박스: `/exhibitor/v1/ui/index.html`) — 디렉터리 열거로는 못 찾을 수 있는 깊은 경로
> - 호스트명/도메인 — `/etc/hosts`에 추가해야 하는 vhost
> - 다른 포트 — 이 박스처럼 8081 → 8080
>
> 그리고 404 페이지를 만나면 루트가 아니라 경로를 찾아라:
> ​```bash
> curl -sI http://192.168.115.98:8081/                     # 리다이렉트 확인
> curl -s  http://192.168.115.98:8080/exhibitor/v1/ui/index.html | head
> feroxbuster -u http://192.168.115.98:8080/ -w …          # 경로 열거
> ​```
```

---

## 제안 3 — 신규 → `B. 기법 카드` `B-3. 리눅스 권한상승`

**신규.**

**제목(안):** 코어 덤프에서 평문 자격증명 추출 — `gcore`/`gdb` + `strings`, 그리고 `sudo -l` 을 4가지 질문으로 판정하는 법

**본문(안):**

**"프로세스 메모리를 읽을 수 있다 = 그 프로세스의 모든 비밀을 읽을 수 있다."** 리눅스 `gcore`/`gdb -p`/`/proc/PID/mem` 과 윈도우 `procdump`/LSASS 덤프가 같은 사고임.

`sudo -l` 결과를 읽는 4가지 질문 — 어떤 바이너리가 나오든 이 순서로 판정:
1. 셸을 직접 주는가? → GTFOBins `sudo` 항목
2. 파일을 쓰는가? → `/etc/passwd`·sudoers·authorized_keys·cron
3. 파일을 읽는가? → `/etc/shadow`·SSH 개인키·**프로세스 메모리**(`gcore`·`gdb`·`strace`)
4. 다른 프로그램을 실행하는가? → `env`·`nice`·`systemctl`

[[Pelican]] 실측 — `(ALL) NOPASSWD: /usr/bin/gcore` 는 GTFOBins 에 없는 항목이지만 질문 3("읽는가")에 해당. `ps -ef --forest`로 배포판에 없는 커스텀 root 프로세스(`/usr/bin/password-store`)를 특정 → `sudo gcore <PID>` → `strings core.<PID> | grep -A2 -B2 -i passw`.

`gcore` 실무 함정 셋:
1. 현재 디렉터리에 쓴다 — 쓰기 불가 디렉터리면 실패, `/tmp` 로 이동
2. 큰 프로세스(JVM 등)는 수 GB — 디스크가 참. 작은 커스텀 바이너리를 노릴 것
3. ptrace 제한(`/proc/sys/kernel/yama/ptrace_scope`) — `sudo` 로 실행하면 이 제한을 넘음

`strings` 사용 시:
- 라벨과 값이 **다른 줄**에 있을 수 있다 — `strings` 는 널 종료 문자열 단위로 끊음. `grep passw` 단독으로는 값을 놓침, `-A2 -B2` 로 문맥까지 볼 것
- 출력이 수천 줄이면 `strings -n 12 core | grep -v '^[/.]'`(12자 이상, 경로 제외), Windows 덤프는 `strings -e l`(UTF-16LE) 필수

**지우기 전 원문** (옛 §2-5·2-6·4-4의 danger/tip 콜아웃, 핵심부):

```
> [!tip] `sudo -l` 결과를 읽는 4가지 질문
> 어떤 바이너리가 나오든 이 순서로 판정한다:
> 1. 셸을 직접 주는가? — `vi`·`less`·`man`·`awk`·`find -exec`·`python`·`perl` → GTFOBins의 `sudo` 항목 그대로
> 2. 파일을 쓰는가? — `tee`·`dd`·`cp`·`tar`·`zip` → `/etc/passwd`·`/etc/sudoers`·`~root/.ssh/authorized_keys`·cron 파일
> 3. 파일을 읽는가? — `cat`·`head`·`strings`·`gcore`·`gdb`·`strace`·`tcpdump` → `/etc/shadow`·SSH 개인키·프로세스 메모리
> 4. 다른 프로그램을 실행하는가? — `env`·`nice`·`timeout`·`systemctl`·`start-stop-daemon`([[Sorcerer]])·`git -c core.pager`
>
> `gcore`는 3번이다. "읽기만 되는 원시(primitive)"도 root로 가는 완전한 경로가 된다는 것이 이 박스의 교훈이다.

> [!warning] `gcore` 사용 시 실무적 함정 셋
> 1. 현재 디렉터리에 쓴다. 쓰기 불가 디렉터리에서 실행하면 실패한다 → `cd /tmp` 먼저
> 2. 덤프 크기. 큰 JVM을 덤프하면 수 GB가 나와 디스크가 찬다. `/usr/bin/password-store`처럼 작은 커스텀 바이너리를 노려라
> 3. ptrace 제한. 일반 사용자는 `/proc/sys/kernel/yama/ptrace_scope` 값에 막힐 수 있다. **root(=`sudo`)로 실행하면 이 제한을 넘는다** — 이 박스가 정확히 그 경우다

> [!tip] `strings` 출력이 수천 줄이면 — 이렇게 좁힌다
> 이 박스는 130줄이라 눈으로 읽었지만, JVM을 덤프하면 수십만 줄이 나온다:
> ​```bash
> strings core.513 | grep -i -E 'passw|pwd|secret|token|key|cred|login'
> strings -n 12 core.513 | grep -v '^[/.]'          # 12자 이상, 경로 제외
> strings -e l core.513 | grep -i passw              # UTF-16LE (Windows 덤프에서 필수)
> strings core.513 | grep -A2 -B2 'Password'         # 앞뒤 문맥 함께
> ​```
> `-e l`을 기억하라 — Windows 프로세스 문자열은 UTF-16LE라 기본 `strings`가 못 잡는다.

> [!warning] `001 Password: root:` 와 값이 다른 줄에 있다
> `strings`는 널 종료 문자열 단위로 끊는다. 즉 라벨과 값이 서로 다른 문자열 객체면 줄이 갈라진다.
> `grep passw`만 하면 라벨만 잡히고 정작 패스워드는 안 나온다. 위의 `-A2 -B2`(앞뒤 문맥)가 그래서 필요하다. 이걸 모르면 "덤프에 패스워드가 없다"고 오판한다.
```

---

## 제안 4 — 신규 → `B. 기법 카드` `B-2. 네트워크 서비스`

**신규.**

**제목(안):** 모르는 서비스를 만났을 때의 절차 — ZooKeeper 4자 명령(four-letter words) 예시

**본문(안):**

모르는 서비스 대응 순서:
1. 포트 번호로 검색하지 말고 제품명으로 검색 — `2181` 은 수천 건, `Apache ZooKeeper` 는 정확한 문서
2. 그 제품의 "관리/웹 UI"가 별도 제품으로 있는지 확인 — ZooKeeper 자체는 웹 UI가 없고 관리 UI는 별도 제품(Exhibitor)
3. 배너로 직접 말을 건다 — ZooKeeper 는 4자 명령을 받음(`echo srvr | nc <IP> 2181` 버전/모드, `echo envi` 환경변수·경로, `echo stat` 연결 클라이언트, `echo mntr` 메트릭). 3.4.6 은 4자 명령에 화이트리스트가 없어 `envi` 가 `java.home`·`user.dir` 같은 경로 정보를 그대로 줌
4. 검색어 조합 — `<제품명> <버전> exploit`, `<제품명> default credentials`, `<제품명> unauthenticated`

[[Pelican]] — 2번에서 끝남(ZooKeeper 가 아니라 Exhibitor 가 답).

**손절 기준** — 15분 안에 제품과 공격면이 안 나오면 다른 포트로 옮겼다가 돌아올 것. 한 서비스에 매몰되는 것이 24시간 시험에서 가장 흔한 실패 형태.

**지우기 전 원문** (옛 §1-2):

```
> [!tip] 모르는 서비스 대응 순서 — 시험장에서 이대로 한다
> 1. 포트 번호로 검색하지 말고 제품명으로 검색한다. `2181` → 수천 건, `Apache ZooKeeper` → 정확한 문서
> 2. 그 제품의 "관리/웹 UI"가 별도로 있는지 본다. ZooKeeper 자체는 웹 UI가 없고, 관리 UI는 별도 제품(Exhibitor)이다. 관리 UI가 붙어 있으면 거기가 공격면이다
> 3. 배너로 직접 말을 걸어 본다 — ZooKeeper는 4자 명령(four-letter words)을 받는다:
>    ​```bash
>    echo srvr  | nc 192.168.115.98 2181   # 버전·모드
>    echo envi  | nc 192.168.115.98 2181   # 환경변수·경로 (정보 유출)
>    echo stat  | nc 192.168.115.98 2181   # 연결 클라이언트
>    echo mntr  | nc 192.168.115.98 2181   # 메트릭
>    ​```
>    (3.4.6은 4자 명령에 화이트리스트가 없다. `envi`는 `java.home`·`user.dir` 같은 **경로 정보**를 준다.)
> 4. **검색어 조합**: `<제품명> <버전> exploit`, `<제품명> default credentials`, `<제품명> unauthenticated`
>
> 이 박스는 2번에서 끝났다. **ZooKeeper가 아니라 Exhibitor가 답이다.**

> [!warning] 손절 기준 — "제품 식별에 15분"
> 15분 안에 제품과 공격면이 안 나오면 다른 포트로 옮겼다가 돌아온다. 이 박스에는 CUPS·Samba·JMX·SSH가 더 있었다.
> 한 서비스에 매몰되는 것이 24시간 시험에서 가장 흔한 실패 형태다.
```

---

## 제안 5 — 병합 → `D. 시간 배분 · 손절 기준` (절 끝에 append)

**병합.**

**추가할 문단(안):**

실측([[Pelican]]) — 산출물·스크린샷 파일명 타임스탬프로 재구성: `10:30` nmap 시작 → `10:31` 종료 → `10:40` Exhibitor UI 접근 → `10:41` 익스플로잇 검색 → `10:46` 페이로드 확보·주입 → `10:48` RCE + local.txt → `11:06` `strings` → `11:07` root. **합계 37분.** 가장 긴 구간은 `10:31→10:40`(9분, 제품 식별)이고 `10:48→11:06`(18분)이 권한상승 열거. 막힘이 적었던 것은 실력보다 nmap 이 진입 URL(`Did not follow redirect to`)을 통째로 줬기 때문(A절 신규 항목).

**지우기 전 원문** (옛 §6 도입부):

```
이 박스는 **37분**에 끝났다 — 그래서 오히려 기록할 것이 있다. 산출물·스크린샷 타임스탬프가 남긴 실제 흐름은 이렇다: `10:30` nmap 시작 → `10:31` 종료 → `10:40` Exhibitor UI 접근 → `10:41` 익스플로잇 검색 → `10:46` 페이로드 확보·주입 → `10:48` RCE + 로컬 플래그 → `11:06` `strings` → `11:07` root.

가장 긴 구간은 `10:31 → 10:40`, 즉 "이게 무슨 제품인지 알아내는 9분"이었다. 그리고 `10:48 → 11:06`의 18분이 권한상승 열거다. 막힘이 적었던 이유는 실력이 아니라 nmap이 진입 URL을 통째로 줬기 때문이다. 그 줄이 없었다면 어디서 막혔을지를 아래에 적는다.
```

---

## 제안 6 — 병합 → `A-2-27. 「확인 후 폐기한 벡터」를 표로 남길 것 — 배제 목록이 다음 사람의 지도다`

**병합.** [[Monster]] 표 뒤에 [[Pelican]] 표를 추가(둘 다 "확인 후 폐기"가 아니라 "성공 경로가 있어 아예 안 판" 케이스라 그 구분을 명시).

**추가할 내용(안):**

[[Pelican]] 실측 — 아래는 **확인 후 폐기가 아니라 「성공 경로가 이미 있어 안 판」 미완임.** 배제와 섞지 말 것:

| 발견 | 신호 | 확인했어야 할 것 (미완) |
|---|---|---|
| ZooKeeper JMX(39605) — `jmxremote.local.only=false` | 인증·SSL 여부가 명령줄에 명시 안 됨 | `rmi-dumpregistry` NSE → MLet 기반 원격 MBean 로드로 RCE 가능성. Exhibitor 경로가 이미 셸을 줘서 안 감 |
| CUPS 2.2.10(631) | `Potentially risky methods: PUT` + 웹 관리 UI | `curl -i -X OPTIONS` · `/admin` 접근 · 프린터 추가 권한. CUPS 관리 인터페이스는 명령 실행 경로가 알려져 있음 |
| Samba 게스트(139/445) | `smb-security-mode: account_used: guest` — nmap 이 게스트 인증에 **성공**했다는 뜻 | `smbclient -L //IP/ -N` · `smbmap -H IP -u guest`. 30초짜리 확인을 안 한 것 자체가 실수 |

→ **root 소유 `chown -R` 루프(PID 487)는 확인 후 폐기** — GNU `chown -R` 은 기본적으로 심볼릭 링크를 안 따라감(`-L`/`-H` 없이는 `-P`), 소유권도 `charles` 로만 바뀜. 이건 진짜 배제.

**지우기 전 원문** (옛 §6 ⑤⑥, 표+문단):

```
### ⑤ 버린 경로 (1) — JMX (39605/tcp)

`ps -ef`가 밝혀준 사실:

​```text
-Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.local.only=false
​```

`-Dcom.sun.management.jmxremote.authenticate=false` 나 `ssl=false` 가 명령줄에 **명시돼 있지는 않다.** 따라서 인증 여부는 **확인되지 않았다** — nmap이 `java-rmi`로만 식별했고 더 파지 않았다.

**성립했다면 이런 경로였다** [가정 — 시도하지 않았다]:

​```bash
nmap -sV --script=rmi-dumpregistry -p 39605 192.168.115.98   # RMI 레지스트리 열거
# MLet 기반 원격 MBean 로드 → 임의 코드 실행 (mjet / sjet 계열 도구)
​```

**왜 안 갔나** — Exhibitor 경로가 이미 셸을 줬다. **성공한 경로가 있으면 옆길을 파지 않는다.** 다만 시험이라면 **첫 경로가 막혔을 때의 2순위**로 반드시 적어 둔다.

### ⑥ 버린 경로 (2) — CUPS 631 / Samba 445

​```text
631/tcp   open  ipp   CUPS 2.2
|_http-title: Forbidden - CUPS v2.2.10
| http-methods:
|_  Potentially risky methods: PUT
​```

**미끼로 보이지만 확인은 안 했다.** 정직하게 남긴다:

| 서비스 | 신호 | 확인했어야 할 것 |
|---|---|---|
| CUPS 2.2.10 (631) | `Potentially risky methods: PUT` · 웹 관리 UI 존재 | `curl -i -X OPTIONS http://…:631/` · `/admin` 접근 · 프린터 추가 권한. CUPS는 관리 인터페이스로 명령 실행에 이르는 경로가 알려져 있다 |
| Samba 4.9.5 (139/445) | `account_used: guest` — 게스트 접근이 성립했다 | `smbclient -L //192.168.115.98/ -N` · `smbmap -H 192.168.115.98 -u guest` — 공유 열거는 30초짜리 작업이다. 안 한 것은 실수다 |
```

---

## 검산

옛 노트에서 삭제한 학습 자료 블록: §0(배우는 것) 전체·§1-2(모르는 서비스 절차)·§2-1·2-5·2-6(배경지식/gcore 원리)·§6 전체(시행착오 7항목)·§7 전체(시험 관점)·§8(방어 관점, 각 finding 으로 흡수돼 별도 이관 아님) = 실질 이관 대상 **6개 블록** → 위 제안 **6건.** 개수 일치.

---

## 감사 후 보정 (2026-08-26, `Pelican-audit.md`)

- **「신규」 3건(제안 2·3·4)은 전부 신규가 맞음.** `_PLAYBOOK.md` 를 증상으로 전수 검색 — `follow redirect`/`http-title` · `gcore`/`코어 덤프`/`LSASS`/`프로세스 메모리` · `ZooKeeper`/`4자 명령`/`모르는 서비스` 세 묶음 모두 기존 항목 없음. 제안 2 는 인접한 `A-16`(문서 사이트 손절)과 상호 참조를 걸 것
- **제안 5 의 시간 서사는 실측과 일치함.** 스크린샷 파일명(Windows KST)과 `nmap.log` mtime(SSH 세션 TZ=KST) 이 같은 축이라 환산 불필요. `10:30:34` → `11:07:38` = 37분
- ⚠️ **이 제안서의 「6건 = 6건」 검산은 «학습 자료» 에만 성립함.** 개작 과정에서 학습 자료가 아닌 **실측 3건이 별도로 소실**됐고(임베드 `Pasted image 20260615104131.png` · `ps -ef` 전문 · `strings` 블록 3행) 이관 대상이 아니라 **박스 노트로 복원**됐음. 상세는 `Pelican-audit.md`

`su`/TTY 관련(옛 §6 ④)은 **이관하지 않음** — `_PLAYBOOK` `A-3-10` 에 이미 더 정확한 내용(2026-08-26 자체 정정본)이 있어 새 박스 노트가 그리로 직접 링크함. 옛 노트의 "su 는 TTY 를 요구한다"는 주장은 A-3-10 기준으로 **틀렸음**(TTY 를 요구하는 것은 sudo) — 새 노트에서 정정 완료, 이관 대상 아님.
