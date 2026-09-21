# `~/PG/_lib/recon.sh` — 정찰 번들 스크립트 구축 기록

- 작성 2026-08-21
- 대상 파일 `kali:~/PG/_lib/recon.sh` (506행, 25406바이트, md5 `9f0c410230c6469124199a3b40d91bad`)
- 실행 권한 부여됨 (`-rwxr-xr-x`)

---

## 1. 왜 만들었나

`harvest.sh` 가 「셸 획득 후 권한상승 열거」를 한 번에 터는 것과 같은 해법을 **정찰 단계**에 적용한 것이다.
근거는 프로젝트 규율 원문 — 「명령을 하나씩 치지 마라. 명령 자체는 30초면 끝나는데 에이전트 왕복 때문에 5분이 된다.」

`harvest.sh` 와의 차이는 **실행 위치**다. 혼동하면 안 된다.

| | `harvest.sh` | `recon.sh` |
|---|---|---|
| 도는 곳 | **타겟** | **Kali** |
| 셸 | `sh` 전용 (낡은 박스 대응) | `bash` 사용 가능 |
| 시점 | 셸 획득 «직후» | 박스를 켠 «직후» |
| 산출 | `/tmp/.h/harvest.txt` 한 장 | `~/PG/<박스>/` 아래 파일 다수 + `_SUMMARY.txt` |

출력 관례(`=====` 구획 구분, 「도구 없으면 건너뛰고 그 사실을 남긴다」, 「판단하지 말고 다 남긴다」)는 `harvest.sh` 를 따랐다.

---

## 2. 핵심 설계 — 빠른 것 먼저, 느린 것은 던져놓는다

이 스크립트의 요점 전부가 여기 있다. 즉시 구간이 **25~31초**에 끝나고, 그 시점에 이미 침투를 시작할 수 있는 정보가 손에 있다.

```
[즉시 — 30초 안]
  0. 프리플라이트 (ping·tun0·시각. ping 은 참고용이고 어차피 -Pn 으로 간다)
  1. nmap top-1000 포트 스캔 (-oG 로 파싱)         ← 여기서 열린 포트 확정
     └ 비면 흔한 고포트 21종 재시도 (8080·8443·10000 …)
  2. 열린 포트«에만» -sCV 서비스 판별
  3. ── tmux 로 던진다 ──────────────────────  ⛔ 폴링 루프 없음
  4. 서비스 분류 (웹 / 비웹)
  5. 웹 포트마다: 스킴 확인 → 루트 · 리다이렉트추적 · OPTIONS · 흔한파일 25종
                  · whatweb · TLS 인증서 · chromium 스크린샷
  6. ── gobuster 를 tmux 로 던진다 ──────────
  7. 비웹 서비스 빠른 열거 (FTP·SSH·SMTP·DNS·NFS·SMB·SNMP·LDAP·DB·RDP)
  8. _SUMMARY.txt 한 장

[백그라운드 — 나중에 파일로 회수]
  tmux rc-<slug>-full : nmap -p- 전체 → 이어서 sudo nmap -sU top-100
  tmux rc-<slug>-gb   : gobuster (웹 포트를 «순차»로)
```

### 왜 tmux 세션을 둘로만 만들었나

요구는 「웹이면 gobuster 도 tmux 에 던진다」였다. 웹 포트가 4개면 세션이 4개가 되고, 「한 호출에 여러 tmux 세션을 만들면 레이스로 실패한다」는 전례에 정면으로 걸린다.

그래서 **gobuster 를 포트마다 세션으로 쪼개지 않고, 한 세션 안에서 순차로 돌게** 생성한 스크립트에 나열했다. 부수 효과로 타겟에 동시 부하가 안 걸린다. UDP 스캔도 별도 세션을 만들지 않고 전체 TCP 스캔 «뒤에» 이어 붙였다.

결과적으로 세션은 **박스당 최대 2개**다. 생성은 `spawn_tmux()` 하나를 거치고, 그 안에서 `sleep 1` 후 `tmux has-session` 으로 **생성 성공을 확인한 뒤** 다음으로 간다.

### tmux 안전 규율 (사고 이력 반영)

- **`pkill` 이 스크립트에 한 글자도 없다.** 과거 `sudo pkill -f 'nc -lvnp'` 한 줄이 tmux 서버 전체를 날린 사고 때문이다.
- 세션 이름은 `rc-<슬러그>-full` / `rc-<슬러그>-gb`. 접두사 `rc-` 로 다른 작업 세션과 네임스페이스를 가른다.
- 이름이 **이미 쓰이고 있으면 그 세션을 건드리지 않고** `x` 를 덧붙여 새 이름을 만든다 (`while tmux has-session … s="${s}x"`).
- 어디에도 `send-keys` 가 없다. 남의 페인에 키를 밀면 셸이 죽는다.
- `_SUMMARY.txt` 가 세션 이름·회수 경로·`kill-session` 명령을 찍고 「⛔ pkill 쓰지 마라」를 함께 적는다.

---

## 3. 재실행 안전성 — `sf()`

```bash
sf() {   # 이미 있으면 RUNID 를 끼운 새 이름을 준다
  [ ! -e "$p" ] && { echo "$p"; return; }
  # nmap-quick.txt → nmap-quick-20260821-084315.txt
  # web-8080       → web-8080-20260821-084315      (확장자 없으면 뒤에 붙인다)
}
```

모든 산출물 경로가 이걸 통과한다. 파일뿐 아니라 `web-<포트>/`·`svc/` 디렉터리도 마찬가지다.
같은 박스에 두 번 돌려도 **1차 산출물이 하나도 안 사라진다.** 스모크에서 3회 실행해 실측 확인했다.

「덮어쓰지 말라」를 「이미 있으면 건너뛴다」로 구현하지 않은 이유 — 건너뛰면 **재실행이 아무 일도 안 하게** 되고, 박스를 재부팅해 포트가 바뀐 경우를 못 잡는다. 둘 다 남기고 나중에 고르는 쪽이 이 프로젝트의 규율에 맞다.

---

## 4. 「자동 판정을 근거로 쓰지 마라」를 어떻게 구현했나

whatweb 도메인 오탐으로 90분을 날린 실측이 있다. 그래서 두 겹으로 막았다.

**(1) `_SUMMARY.txt` 최상단 경고.** 요약 바로 아래 세 줄이 「이 요약은 편의다. 판정 근거로 쓰지 마라. 원문 파일을 눈으로 다시 읽어라」이고, 모든 항목이 **원문 파일 경로를 함께** 찍는다.

**(2) 스킴 자동 정정.** nmap 배너로 http/https 를 추정한 뒤, **실제로 한 번 때려보고** `000`(연결 실패)이면 반대쪽 스킴으로 재시도한다. 뒤집히면 `_SUMMARY.txt` 에 전용 섹션이 뜬다:

```
===== ⚠️ 스킴 자동 정정 — nmap 배너가 틀렸던 곳 =====
  [8080] nmap 은 https 로 보였는데 실제 응답은 http 였다 (HTTP 200). 배너를 믿지 마라.
```

이건 **스모크에서 실제로 당해서** 넣은 것이다. 아래 6장 참조.

---

## 5. 0바이트 파일과 실패 로그

- 응답 파일을 **하나도 지우지 않는다.** `curl` 이 빈 응답을 받아도 그 파일이 남고, `probe-index.txt` 에 `000 0 /robots.txt` 로 기록된다. 「0바이트 파일은 빈 파일이 아니라 «빈 응답을 받았다는 기록»」이다.
- `_SUMMARY.txt` 의 산출물 목록이 바이트 수를 함께 찍고 그 헤더에 이 문장을 박아뒀다 — 다음 사람이 정리 충동으로 지우지 않도록.
- `chromium` 실패 시 `web-<포트>/chromium.log` 가 남고 요약에 「스크린샷 실패」가 뜬다. 실패도 산출물이다.
- 유일하게 지우는 것은 `mktemp -d` 로 만든 chromium 임시 프로필(`/tmp/rc-chrome-XXXXXX`)이다. 산출물이 아니라 실행 부산물이라 남길 이유가 없고, 안 지우면 `/tmp` 가 찬다.

---

## 6. 반증 — 요구받은 설계 중 실환경에서 «안 통했던» 것

스모크 테스트에서 셋이 깨졌다. 전부 고쳤고, 고친 내용을 스크립트 주석에 남겼다.

### (1) ⚠️ `*https*` glob 가 `SimpleHTTPServer` 를 매칭했다 — 가장 위험했던 버그

1차 구현은 nmap 출력 **줄 전체**에 glob 를 걸었다.

```bash
case "$low" in
  *ssl/http*|*https*) scheme=https ;;   # ← 여기
```

nmap 이 뱉은 줄은 이랬다:

```
8080/tcp open  http       SimpleHTTPServer 0.6 (Python 3.13.12)
```

소문자로 내리면 `simplehttpserver` 인데, 이 안에 부분문자열 **`https`** 가 들어 있다(`...p-l-e-h-t-t-p-s-e-r...`). 그래서 평문 HTTP 서버를 https 로 판정했고, 그 뒤가 전부 도미노로 무너졌다:

- `curl` 이 HTTP `000` 반환 → 루트 헤더·본문이 **0바이트**
- 흔한 파일 25종이 전부 `000`
- `whatweb` 이 `SSL_connect returned=1 errno=107` 로 죽음
- `chromium` 이 TLS 핸드셰이크 에러 페이지를 찍음 (19985바이트 PNG 가 **에러 화면**이었다)
- `gobuster` 결과 0바이트

**핵심은 이게 조용히 실패했다는 것이다.** 스크립트는 정상 종료했고 `_SUMMARY.txt` 도 멀쩡히 나왔다. 「웹 포트가 있는데 응답이 없네」로 읽고 넘어갔으면 진입점을 통째로 놓쳤다.

같은 함정에 걸릴 실제 배너들: `SimpleHTTPServer`·`BaseHTTPServer` 등 `HTTPServer` 를 포함하는 모든 것.

**수정**: 줄 전체가 아니라 nmap 의 **서비스 칼럼(3번째 필드)만** 보고, 접두/완전 일치로 판정한다. 그 위에 4장의 스킴 자동 정정을 얹어 판정이 틀려도 복구되게 했다.

### (2) `onesixtyone <host> public private community` 는 스캔이 아니라 usage 를 뱉는다

`onesixtyone` 0.3.3 은 커뮤니티 스트링을 **하나만** 인자로 받는다. 여러 개를 나열하면 usage 를 출력하고 끝난다. 그런데 출력이 835바이트라 **파일 크기만 보면 스캔한 것처럼 보인다.**

```
onesixtyone 0.3.3 [options] <host> <community>
  -c <communityfile> file with community names to try
```

**수정**: `svc/snmp-communities.txt` 에 커뮤니티 5종(`public private community manager admin`)을 써두고 `-c` 로 넘긴다. 고친 뒤 정상 출력 확인 — `Scanning 1 hosts, 5 communities`.

### (3) `gobuster -o` 는 `--no-color` 없이는 ANSI 이스케이프를 파일에 박는다

gobuster 3.8 에서 `-o` 로 쓴 파일이 이랬다:

```
/index.html          ^[[32m (Status: 200)^[[0m ^[[34m [Size: 119]
```

나중에 이 파일을 `grep`·`awk` 로 파싱하면 색코드 때문에 어긋난다. **수정**: `--no-color --no-progress` 추가. 고친 뒤 깨끗한 출력 확인.

### (4) 반증은 아니지만 — GLPI tmux 세션이 애초에 없었다

지시에 「그쪽 tmux 세션(`glpinmap`·`glpish`)을 건드리지 마라」가 있었는데, 작업 시작 시점에 Kali 는 `no server running on /tmp/tmux-1000/default` 였다. **tmux 서버 자체가 안 떠 있었다.** 어차피 건드리지 않았지만, 그 세션들이 살아 있다는 전제는 사실이 아니었다.

---

## 7. 스모크 테스트 방법 — GLPI 를 안 건드리고 전 경로를 돈 방법

지시상 진행 중인 GLPI(`192.168.248.242`)에는 `-p-` 도 gobuster 도 못 댄다. 그런데 그 둘이 이 스크립트의 **핵심 설계**라 안 돌려보면 검증이 안 된다.

그래서 **타겟을 아예 `127.0.0.1` 로 잡았다.** Kali 위에 임시 웹서버를 띄우면 전 경로를 부하 걱정 없이 돌 수 있다.

```
tmux new-session -d -s smokehttp 'cd ~/PG/_lib/_smoke/webroot && python3 -m http.server 8080 --bind 127.0.0.1; exec bash'
bash ~/PG/_lib/recon.sh 127.0.0.1 _lib/_smoke
```

포트를 8080 으로 고른 이유 — nmap top-1000 에 들어 있어 **1단계 포트 스캔부터** 태울 수 있다. webroot 에는 `index.html`(`<title>` 포함)·`robots.txt`·`CHANGELOG.md`·`admin/` 을 두어 흔한파일 프로빙과 gobuster 가 실제로 히트하게 했다.

**결과 — GLPI 를 향한 패킷은 한 개도 나가지 않았다.**

부수적으로 Kali 자신의 22(ssh)·5432(postgres)가 잡혀서 비웹 서비스 분기(`ssh-banner`·`pgsql-nmap`)까지 같이 검증됐다.

### 실행 3회 결과

| 회차 | 즉시구간 | 결과 |
|---|---|---|
| 1차 | 25s | 버그 (1) 발현 — 스킴 오판, 웹 프로빙 전멸. 버그 (2) 발현 |
| 2차 | 30s | (1)(2) 수정 후. HTTP 200 · title `Smoke Test Page` · Server 헤더 정상 포착. 1차 산출물 전부 보존 확인 |
| 3차 | 31s | (3) 수정 후. gobuster 파일 색코드 제거 확인 |

**검증한 것:**

- 즉시 구간 25~31초 — 폴링 없이 tmux 로 던지는 설계가 의도대로 작동
- `nmap-full.txt` 가 백그라운드에서 4563바이트까지 자라는 것을 확인 (tmux 경로 실동작)
- `gobuster` 가 `/index.html`·`/admin`·`/robots.txt` 를 찾아냄
- 스크린샷 `PNG image data, 1280 x 900, 8-bit/color RGB` — 실제 페이지가 찍힘
- 흔한파일 프로빙 — `probe-interesting.txt` 에 `200 /robots.txt`·`200 /CHANGELOG.md`·`200 /admin/`
- 재실행 안전성 — 1·2·3차 산출물이 RUNID 로 갈려 **전부 공존** (`_SUMMARY.txt` / `_SUMMARY-20260821-084315.txt` / …)
- `sudo -n nmap -sU` 가 프롬프트 없이 도는 것을 별도 확인 (NOPASSWD 유효)
- 산출물 132개 생성

### 정리

세션 3개를 **이름으로만** 종료(`tmux kill-session -t …`), 8080 해제 확인, `~/PG/_lib/_smoke` 삭제. `tmux ls` → `no server running`. **pkill 은 쓰지 않았다.**

---

## 8. 사용법

```sh
ssh kali@10.44.44.128 "bash ~/PG/_lib/recon.sh 192.168.x.y <박스명>"
```

박스명을 주면 `~/PG/<박스명>/`, 안 주면 `~/PG/recon-<IP>/` 에 떨어진다.
30초 뒤 `_SUMMARY.txt` 가 표준출력으로도 나오므로 **에이전트 왕복 1회에 정찰이 끝난다.**

나중에 회수할 것:

```sh
ssh kali@10.44.44.128 "tmux ls; cat ~/PG/<박스>/nmap-full.txt ~/PG/<박스>/gobuster-*.txt"
ssh kali@10.44.44.128 "tmux kill-session -t rc-<슬러그>-full; tmux kill-session -t rc-<슬러그>-gb"
```

### 산출물 배치

```
~/PG/<박스>/
  _SUMMARY.txt                 요약 한 장 (편의용. 근거는 원문에서)
  recon-preflight.txt          타겟·tun0·시각·ping
  nmap-quick-ports.txt/.gnmap  top-1000 포트 스캔
  nmap-quick.txt               열린 포트 -sCV
  nmap-full.txt                [백그라운드] -p- 전체
  nmap-udp-top100.txt          [백그라운드] UDP
  gobuster-<포트>.txt           [백그라운드]
  shot_<포트>_root.png          스크린샷 → 볼트 파일보관\PG-<박스>-<설명>.png 로 옮겨라
  web-<포트>/
    root.headers/.body         리다이렉트 «안» 따라간 것
    root-followed.*            따라간 것
    root.options               허용 메서드
    probe-index.txt            흔한파일 25종 전수 (000 포함 — 지우지 마라)
    probe-interesting.txt      200/401/403/301/302 만
    probe_<파일명>              응답 본문 각각
    whatweb.txt · tls-cert.txt · chromium.log
  svc/
    ftp-* ssh-banner smtp-* dns rpcinfo nfs-exports
    smb-* smbmap-null rpcclient-null nbtscan
    snmp-* ldap-base mysql-* mssql-* pgsql-* redis-info mongodb-* rdp-*
  .bg-fullscan.sh · .bg-gobuster.sh    tmux 가 실행한 «실제» 명령 (재현용)
```

`.bg-*.sh` 를 남긴 이유 — tmux 세션이 죽어도 **무슨 명령을 던졌는지**가 파일로 남는다. writeup 6장에서 「무엇을 시도했나」를 복원할 때 쓴다.

---

## 9. 안 넣은 것과 그 이유

| 안 넣음 | 이유 |
|---|---|
| `nikto` | 설치돼 있지만 느리다(수 분). 즉시 구간을 30초로 유지하는 것이 이 스크립트의 존재 이유고, 필요하면 손으로 던지면 된다 |
| `enum4linux-ng -A` | 같은 이유. `_SUMMARY.txt` 에 「안 돌렸다. 필요하면 직접」을 명시했다 — 「배제」와 「안 해봤다」를 섞지 않기 위해 |
| 온라인 브루트포스 (hydra 등) | 정찰이 아니다. 시끄럽고 느리다 |
| vhost 퍼징 | 도메인명을 모르는 상태에서는 헛돈다. 대신 리다이렉트 Location·본문·TLS SAN 에서 **호스트명 후보를 긁어** `_SUMMARY.txt` 의 「호스트명 힌트」로 올린다 |
| `sqlmap` | **OSCP 금지 도구**다 |
| 폴링 루프 | 지시가 금지했고, 기다리는 순간 「던져놓는다」의 이점이 사라진다 |

## 10. 도구 가용성 (2026-08-21 Kali 실측)

요구된 것 전부가 **이미 설치돼 있다.** 추가 설치 없음.

`nmap 7.98` · `curl` · `wget` · `gobuster 3.8` · `feroxbuster` · `chromium` · `cutycapt` · `whatweb` · `nikto` · `smbclient` · `smbmap` · `enum4linux(-ng)` · `nbtscan` · `rpcclient` · `snmpwalk` · `onesixtyone` · `showmount` · `dig` · `host` · `ldapsearch` · `mysql` · `psql` · `redis-cli` · `tmux 3.6` · `jq` · `nc` · `ncat` · `openssl` · `ftp` · `timeout`

없는 것: `xmlstarlet` (안 씀).

워드리스트는 `seclists/Discovery/Web-Content/raft-small-words.txt` 를 1순위로, 없으면 `dirb/common.txt` 로 폴백한다. 둘 다 실존 확인.

`have()` 헬퍼가 도구 부재를 누적해 `_SUMMARY.txt` 의 「도구 없음 / 건너뜀」 섹션에 찍는다 — **없으면 조용히 건너뛰지 않고 그 사실을 남긴다.**
