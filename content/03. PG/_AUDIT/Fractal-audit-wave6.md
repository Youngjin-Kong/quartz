---
type: audit
platform: pg
box: Fractal
manual_tags: true
manual_cves: true
---

# Fractal — 적대적 검증·정정 (wave 6)

대상 `03. PG\Fractal.md` (OSCP 제출 보고서 구조 개작본) · 원본 `03. PG\_backup\Fractal.md.bak`
확인 출처 — `~/PG/Fractal/` 산출물 전량 · 볼트 `파일보관\PG-Fractal-*.png` 2장 · `~/.zsh_history` · Kali 직접 실행 2건 · Ubuntu 보안 공지 USN-5252-1

> git 이력 없음 — `git log -- "03. PG/Fractal.md"` 무출력. 노트가 아직 커밋되지 않아 **git baseline 이 존재하지 않음.** 비교 기준은 `_backup\Fractal.md.bak` 단독.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `pkexec` 0.105-26ubuntu1.3 은 PwnKit(CVE-2021-4034) 대상 버전이지만 | **틀린 일반 지식.** Ubuntu 20.04 의 PwnKit 수정판이 `policykit-1 0.105-26ubuntu1.2`(USN-5252-1). 호스트의 `1.3` 은 그보다 **뒤** 버전이라 이미 패치됨. `.bak` 272행에서 상속된 오류 | 「PwnKit 대상이 **아님**」으로 반전. 수정판 버전·USN 번호·`dpkg -l` 행번호를 근거로 명시 |
| `getcap` 은 `ping`·`traceroute6`·`mtr-packet` **뿐** | **거짓 전수 주장.** `harvest_root.txt` CAPS 절(120–124행)에 `gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep` 와 `/snap/core20/1623/usr/bin/ping` 이 더 있음 | 5개 전량 나열 + 「권한상승으로 이어지는 것 없음」 판정 유지 |
| SUID 는 배포판 기본(snap 계열 + `/usr/bin/sudo`) | **요약이 원문과 어긋남.** 실제 `/usr/bin` SUID 는 13개(`pkexec`·`at`·`fusermount`·`dmcrypt-get-device` 등 포함) | 실제 집합을 나열하고 「비표준 SUID 없음」으로 판정 명시 |
| `sign_fragment.py` 파이썬 펜스 | **펜스가 원문이 아님.** 실제 파일은 `import sys, …`, `def sign(path_value, secret=SECRET, base=BASE):`, 인라인 주석 2줄, 본문에서 `secret`/`base` 사용. 노트 쪽은 시그니처·변수·공백이 재작성돼 있었음 | 파일 원문 그대로 교체(상단 주석·`__main__` 만 생략) + 캡션에 「발췌」 명시 |
| ```` ```bash / sudo -i    → root@fractal:~# ```` | **의사코드를 펜스로 감쌈.** `→` 표기는 작성자가 만든 것이고, 실제 출력은 15행 아래 `proof_root.txt` 블록에 이미 있음 | 펜스 삭제, 바로 위 `[가정]` 문단이 같은 내용을 이미 서술하므로 중복 제거 |
| `printf … openssl base64   → {md5}xKZnXxuuNbTj2DiMKnfv2A==` | 같은 유형. `{md5}` 접두사는 명령 출력이 아니라 ProFTPd 저장 형식 | 명령과 출력을 분리. **Kali 에서 직접 재실행해 `xKZnXxuuNbTj2DiMKnfv2A==` 재현 확인**, 접두사는 손으로 붙인 것이라고 명시 |
| `parameters.yml` 펜스 | **말없는 선별 발췌.** `database_port`·`mailer_*` 4행과 상단 주석을 지웠는데, **바로 아래 스크린샷이 그 12행을 다 보여줌** — 노트가 자기 증거에 반박당하는 형태 | 산출물 원문 12행 전량으로 복원 |
| `sql.conf` 펜스 | 주석·`SQLAuthenticate`·`SQLGroupInfo` 를 지운 발췌인데 캡션이 원문처럼 읽힘 | 캡션에 「발췌 — 값·순서는 원문 그대로」 명시. 펜스 내용은 그대로(원문과 바이트 일치, 행말 공백만 탈락) |
| `INSERT INTO ftpuser …` SQL 펜스 | 출처 캡션 없음. **이 문장 텍스트는 어느 파일에도 없음**(`rce.py` 인자로 넘겨 원문 미보존) | 삭제하지 않고 캡션 추가 — 「원문 파일 없음, 삽입된 값은 `db_insert.html` 결과 행으로 확정」 |
| 타겟 pty 블록 캡션 `출처: tmux fr-shell capture-pane` | tmux 세션은 `cleanup.txt` 대로 종료됨 → **그 캡처 파일이 존재하지 않음** | 프롬프트·출력은 **그대로 두고**(실측 표식), 「캡처 원문 파일 미보존」과 대체 근거(`harvest_root.txt` 프로세스 목록)를 아래에 명시 |
| `그 출력은 Privilege Escalation 절에 있음` | ⓒ 절충 자체는 타당하나 연결이 모호 — 해당 절에 하위 절이 둘 | `Privilege Escalation` → `www-data → benoit` 절 끝 `proof_user.txt` 블록으로 특정 |
| `/phpmyadmin` 301 → `/phpmyadmin/` | **「배제」와 「미시도」가 구분 안 됨.** `.bak` 6장의 해당 서술이 `_PLAYBOOK` 으로 이관되며 노트에서 사라져, 읽는 사람이 닫힌 문으로 오독할 자리 | 「배제한 것이 아니라 시도하지 않았음」과 그 이유(앱 DB ≠ `proftpd` DB) 한 문장 복원 |
| `## 관련` 절 | `_PLAYBOOK` 앵커 링크 **0개** | 6개 추가(A-12·A-21·A-31·A-33·B-17·B-21). 6개 전부 `_PLAYBOOK.md` 에 해당 제목으로 실재함을 grep 으로 확인(44·88·139·181·437·483행) |
| `local.txt` 는 `-r--r--r--` 라 | 값이 불완전 | `-r--r--r-- 1 benoit benoit 33` 로 원문 일치화 |
| `proof_root.txt` 블록 펜스 태그 ```` ```bash ```` | 명령이 아니라 세션 출력. `proof_user.txt` 블록은 ```` ```text ```` 라 불일치 | ```` ```text ```` 로 통일 |

**삭제한 것 — 1건.** 원문 전문:

```
```bash
sudo -i    → root@fractal:~#
```
```
근거: `→` 는 작성자 표기이고 실제 세션 출력(`$ sudo -i` / `root@fractal:~#`)은 같은 절 아래 `proof_root.txt` 블록에 원문으로 이미 실려 있음. 정보 손실 없음.

---

## 2. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

**ⓐ 새로 추가된 실측 블록 5개 — 5건 전부 원문 일치. 날조 0건.**

| 블록 | 대조 결과 |
|---|---|
| `probe_robots.txt` | 4행 **바이트 일치**(`cat -A` 로 행말 확인, 파일 끝 개행 없음) |
| `idtest.html` (id+uname) | 추출 결과 7–9행과 **완전 일치**(3행) |
| `db1.html` (기존 `ftpuser` 행) | 9–10행과 **완전 일치**. 탭 구분·`{md5}RDLDFEKYiwjDGYuwpgb7Cw==` 포함 |
| `db_insert.html` | 8–11행과 **완전 일치**(`INS_DONE` 마커 포함) |
| `harvest_root.txt` **434–438행** | `sed -n 428,442p` 로 역산 — 434=`sshd: benoit [priv]`, 435=`sshd: benoit@pts/3`, 436=`-sh`, 437=`sudo -i`, 438=`-bash`. **행번호까지 정확** |
| `cleanup.txt` DB before/after | 12행 **완전 일치** |

**ⓑ 작성자의 반증 3건 — 3건 전부 성립.**

1. `grep -c "SQLConnectInfo\|SQLUserInfo" harvest_root.txt` = **0**. `harvest_root.txt` 병기는 실제로 틀렸고 출처를 `frag/enum1.html` 단독으로 고친 것이 옳음
2. 홈 리스팅 출처가 `frag/enum1.html` (9–14행) — 맞음. 다만 「`db1.html` 에도 **같은** 리스팅이 있다」는 부정확 — `db1.html` 12–14행은 `/home/benoit` **내부** 리스팅이고 `enum1.html` 쪽은 `/home` 리스팅임. 노트는 `enum1.html` 만 인용하므로 **본문에는 영향 없음**
3. `/server-status` 403 — `gobuster-80.txt` 에 항목 없음, `web-80/probe-interesting.txt` 에 `403 280 /server-status -> probe_server-status` 로 존재. 출처 명시 전환이 옳음

**ⓓ 코드펜스 전수 — 「산출물 원문인 척한 산문」은 위 표의 4건(`sign_fragment.py`·`sudo -i`·`openssl`·`parameters.yml`)뿐.** 나머지 펜스는 원문 대조 통과. Wheels 유형(작성자 의사코드를 ```text 로 감쌈)은 **없었음.**

**ⓔ `INSERT INTO ftpuser` SQL — 값 전부 실측과 일치.** `hacker`/`1000`/`1000`/`/home/benoit`/`/bin/bash` 는 `db_insert.html` 11행이 그대로 확인. 해시는 Kali 재실행으로 재현. **원문 오타 `protfpd_with_MYSQL_password` 도 `enum1.html` 38행과 바이트 일치 — 고치지 않았음.**

**ⓕ 이관 손실 — 없음.**
- `[가정]` **3건 전부 생존**: ①53 도착·443 미도착·443 차단 여부 ②benoit `sudo -l` 원문 미보존 ③`app_dev.php` 가드만 빠졌다는 판단
- 「관측 없음」류 유보 **5건 전부 생존**: `set ftp:ssl-allow no` 필수 여부 · 트래버설 미시도 · FTP 세션 로그 미보존 · tcpdump/리스너 화면 미보존 · `sudo -l` 스크롤백
- 특히 지목된 **「Kali 쪽 tcpdump·리스너 화면을 파일로 안 남겨서 『53 도 나간다 / 443 은 막혔다』가 `[가정]` 으로 남았다」는 유보가 그대로 유지됨**
- **타겟 pty 프롬프트 3종 전부 생존**: `www-data@fractal:/var/www/html/web$` · benoit dash `$` · `root@fractal:~#`. **하나도 지우지 않았음**
- Kali 프롬프트(`┌──(kali㉿kali)`) 0개 — 새 노트라 애초에 없음

**ⓖ 남긴 흔적 — `cleanup.txt` 항목 6종과 1:1 대응, 누락 없음.** DB `hacker` 행 · `/home/benoit/.ssh/authorized_keys` · 웹루트 `h.txt`/`h2.txt` · `/tmp/.h*` · Kali 리스너·tmux · 마운트 없음. `.ssh` 가 「원래 없던 디렉터리」라는 서술도 `--sshbefore` 리스팅의 `.` mtime `Aug 21 01:14`(공격 시각)로 뒷받침됨.

**그 밖에 대조해 통과한 것:**
- 스크린샷 2장을 **직접 열어** 확인 — `PG-Fractal-index.png` 에 푸터 없음(뷰포트 잘림) ✅, `root.body` 의 `<img` 개수 **3** 으로 「전폭 이미지 3장」 ✅. `PG-Fractal-profiler-parameters.png` 는 `secret` 포함 12행 표시 ✅
- `sym/` 응답 바이트 수 7개(43503·97468·82451·13958·6922·471·471) **전부 `ls` 와 일치**
- `root.body` **46–50행** 푸터 — 행번호까지 일치
- `nmap-full.txt` `Not shown: 64513 closed …, 1019 filtered …` 원문 일치 · UDP top-100 전량 `open|filtered` 일치 · `svc/ftp-nmap.txt` 스크립트 무출력 일치
- `sym/config.php.html` = `This script is only accessible from localhost.` 46바이트 ✅ · `sym/_profiler.html` 404 본문 문구 ✅
- `proof_user.txt`·`proof_root.txt`·`ftp_upload.sh` **바이트 일치**
- `proof_*.txt` mtime 서사 — root 10:16:16 / user 10:18:18(KST), 본문 `date` UTC 01:15:21 → 01:16:13. **타임존 환산 후 노트 설명대로 모순 없음**
- `Ubuntu 20.04.5 LTS` · 커널 `5.4.0-126` · `proftpd-basic 1.3.6c-2ubuntu0.1` 전부 산출물 확인
- Symfony 3.4 `FragmentListener`(서명 외 방어 없음)·`ProfilerController::openAction` 정규식 가드·`UriSigner` 해시식 — 3.4 동작과 일치
- 프론트매터 `tech/*` 6종 전부 실제 사용 기법. `manual_cves: true` + `cves` 필드 없음 → 본문에 언급만 된 CVE-2021-4034 가 색인에 안 들어감. **PwnKit 판정을 「대상 아님」으로 뒤집었으므로 이 설정이 오히려 정확**
- `~/.zsh_history` — Fractal 관련 항목 0건(에이전트가 비대화형으로 작업). **부재를 근거로 한 판정 없음**

---

## 3. 총괄에 올릴 것

- **색인 갱신 필요** — 본문 문장이 바뀌었으므로 `refresh.ps1` 대상. 감사자는 실행하지 않음(공유 인프라).
- **`_STATUS.md` 판정: Fractal = 완료 2/2**(user `f62124f1ae5f1ab510a1a4a5de5bf0d5` · root `3fccb8b2b4eb6870d248850dbd7994ea`, 둘 다 같은 대화형 SSH pty 세션 회수). 감사자는 직접 기록하지 않음.
- **파급 없음(확인함)** — PwnKit 오판정이 다른 노트에 상속됐는지 `grep "0.105-"` 로 확인. [[Exghost]] 465–468행이 **독립적으로 같은 수정판 `0.105-26ubuntu1.2` 를 기준으로 삼아 `1.1` 을 취약 판정**하고 있어, 정정 방향이 볼트 내 다른 노트와도 일치함. Fractal 국소 오류였음.
- **문체 이관 0건** — `pg-doc-reviewer` 로 넘길 건 없음.
