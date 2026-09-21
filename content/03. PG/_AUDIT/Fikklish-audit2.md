---
tags:
  - type/audit
  - platform/pg
---
# Fikklish — 2차 적대적 검증 (2026-08-26)

대상: `03. PG\Fikklish.md` (개작 직후 490행 → 감사 후 509행). 대조 원본: `03. PG\_backup\Fikklish.md.bak`(645행) · `git show HEAD:"03. PG/Fikklish.md"`(663행, 1차 감사 정정이력 콜아웃 포함본).
증거원: `~/PG/Fikklish/` 49개 파일 전수 · 볼트 `파일보관\` 스크린샷 3장(**직접 열어 봄**) · `03. PG\_AUDIT\Fikklish-audit.md`(1차) · `Fikklish-playbook.md` · 1차 사료 NVD 2건 · **Kali 직접 재실행 1건**.
`refresh.ps1`·`extract.py` 미실행. `_STATUS.md`·`_PLAYBOOK.md`·`_WRITEUP-STANDARD.md` 미수정. 타겟 미접속(정지됨).

---

## ⓐ pty 프롬프트 — **작성자의 제거는 오판. 복원함**

작성자는 `grep` 0건(부재)을 근거로 두 블록의 타겟 프롬프트를 지우고 「재구성」 산문으로 대체함. **이 박스는 1차 감사에서 정확히 같은 사고(타겟 pty 프롬프트를 「위반」으로 오판해 제거)가 났던 곳이고, 이번이 그 반복임.**

부재는 등급 상한이 `근거부족`이지 `날조`가 아님. 그리고 실측임을 지지하는 **양성 증거가 넷** 있음:

| # | 근거 |
|---|---|
| 1 | 지워진 프롬프트 `<lib/python3.10/site-packages/data/vcs/poc/rev443b$` 가 `shell443.log` 3행의 `</lib/python3.10/site-packages/data/vcs/poc/rev443$ ` 와 **선행 `<` 아티팩트까지 포함해 같은 잘림 형태**임. 지어내는 쪽은 `tom@fikklish:…$` 를 썼을 것 |
| 2 | 그 블록의 `date -u` 는 `Thu Aug 20 10:25:44 UTC 2026` 으로 **`AM` 이 없음**. 같은 호스트의 `proof_user.txt`·`harvest_tom.txt` 는 `10:26:46 AM UTC 2026`. glibc 2.35 에서 C/POSIX 로캘(서비스에서 태어난 리버스셸)과 `LANG` 을 물려받은 SSH 세션의 차이와 정확히 일치 — `proof_user.txt` 를 베꼈다면 `AM` 이 따라왔을 것 |
| 3 | 소스 포트 `57430` 이 `reg_smtp.pcap` 에 `19:25:26.171960 … Flags [S]` 로 실재. 블록의 `10:25:44 UTC`(=KST 19:25:44)가 그 18초 뒤 |
| 4 | `tom@fikklish:~$` 는 `ssh -tt -i fik_key tom@…` 대화형 세션의 기본 PS1 그대로이고(HOME=/home/tom, `~/.bashrc` 존재), `traces_confirmed.log` wtmp 에 `tom pts/0`·`root pts/0` 두 pty 세션이 실재 |

화면을 담은 파일이 없는 것은 CLAUDE.md §2 가 명시한 구조적 공백(`tmux capture-pane` 출력은 에이전트 전사에만 남고 파일로 안 떨어짐)이므로, 「화면 자체는 근거부족」이라고 **표시**하고 블록은 **복원**했다.

⛔ `┌──(kali㉿kali)`·`└─$` 는 노트·산출물 양쪽에서 **여전히 0건**. 새로 붙이지 않음.

---

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| 「실제로 명령을 친 것은 두 번째 셸…재구성이다」 | 실측 pty 프롬프트 4행을 부재 근거로 제거 | 원 블록 복원 + 근거부족 표시 + 로캘 교차근거 명시 | 위 ⓐ |
| 「gem 버전은 대화형 셸에서 `gem list git` → …」 | 같은 이유로 `tom@fikklish:~$ gem list git` 제거 | 코드펜스로 복원 + 출처 표기 | 위 ⓐ |
| 1장 gobuster 코드펜스 | **산출물 원문이 아님.** `.htaccess/.htpasswd/.hta` 를 한 줄로 합치고 `[Size:]`·리다이렉트 칼럼을 지운 합성 블록 | `gobuster_80.txt` 전문으로 교체, medium 실행의 증분(`/README.txt`·`/sass`)은 캡션에 산문으로 | `gobuster_80.txt`·`gobuster_80_big.txt` |
| 「실패한 SSH 시도 **10건**」 | `traces.sh` 가 `lastb -n 10 \| head -12` 라 **10은 표시 상한**. btmp 시작이 10:04:25 로 hydra 구간을 포함하므로 실제 건수는 훨씬 많음 | 「표시 상한이지 총 건수 아님」+ 전수는 관측 없음 | `traces.sh:8`, `traces_confirmed.log` BTMP |
| 「`/root/.ssh/authorized_keys` … 원래 키 한 줄뿐이었음을 `cat` 으로 확인」 | 그 한 줄은 **우리가 심은 키**(`ssh-ed25519 …GYGt7 kali@kali` = `fik_key.pub` 과 동일) | 「원래 등록된 키 없음」으로 재서술 | `traces_confirmed.log` ROOT AUTHORIZED_KEYS ↔ `fik_key.pub` |
| 「Weblate 프로젝트 `poc` + **컴포넌트 5개**」 | ORM 열거가 `before: ['poc'] []` — **컴포넌트 레코드 0개** | 「컴포넌트 0개(생성이 매번 실패)」로 정정, `after: [] []` 명시 | `traces_confirmed.log`, `cleanup.sh` |
| `![[PG-Fikklish-port80-hint.png]]` | 파일명과 배치가 「Editors Note 힌트 화면」을 함의하나 **이미지에는 그 문단이 없음**(헤드리스 1280×900 첫 화면만) | 캡션으로 명시, 본문 근거를 `index80.html` 로 | 스크린샷 직접 열람 |
| 「셸을 잡자마자 `harvest.sh` 를 tom 권한으로 실행」 | **시간 서사 오류.** harvest 는 19:29, **root 획득(19:28:48) 이후** 실행 | 「19:27 손으로 열거 / harvest 는 19:29 사후 채증」으로 재서술 | `harvest_tom.txt` mtime 19:29:13, `traces_confirmed.log` `10:29:04 … COMMAND=list` |
| Steps 2 「**최신 값**이 tom 시스템 비번」 | 통한 것은 히스토리상 **첫 번째(더 오래된)** `RapidlyLockstepDrenched103` | 「최신 값이 아니라 첫 번째 값」+ 전부 시험하라 | `trysudo.sh`, `HARVEST_PW=…103`, `/root/projects/RapidlyLockstepDrenched103` |
| 「ruby-git … 두 값 모두 검증하지 않음」 | NVD 는 `remote` 만 지목 | 어드바이저리 문구와 실측(`ref` 자리도 흐름)을 갈라 서술 | NVD CVE-2022-25648 |
| git 인자주입 재현 블록 | `$` 프롬프트 + `-rw-r--r-- 1 ... 0 ...` 같은 **생략 기호가 든 합성 transcript** | **Kali 에서 재실행**해 실호출 형태 + 원문 출력으로 교체(git 2.51.0, exit=128, 파일 생성) | 직접 실행 |
| 「`last` 에 남은 세션은 정확히 두 건」 | `last -n 15` 상한 미고지 | 「출력 7행 = 상한 미달 = 전량」 근거 명시 | `traces.sh:6` |
| proof 캡션 「비대화형 1회 호출」 | 같은 노트가 「`ssh -tt` 로 pty 를 강제해 대화형 셸에서 `cat`」이라 적어 **내부 모순** | 「`-tt` 가 pty 강제 → wtmp 에 `pts/0` 기록」으로 통일 | `traces_confirmed.log` LAST/WTMP |
| Editors Note·Multinational 인용 | 생략 표시 없는 부분 인용 | `…` 표시 + 전문 출처 명시 | `index80.html` |
| 「tmux 세션 `fik_*` **8개** 종료」 | 개수 근거 없음 | 「전량(개수 기록 없음)」 | 산출물 부재 |
| `/root/traces.sh`·`/root/cleanup.sh` | 존재 확인 산출물 없음(확인된 것은 `/root/h.sh` 뿐) | 그 사실을 표 안에 명시 | `traces_confirmed.log` FILES WE CREATED |

**강등(근거부족·관측 없음 표시 추가) 7건** — `rev443b` 화면 · `gem list git` 화면 · `/tmp/one.sh` 출력 · `ls -la /home/tom` 블록 · ruby 예외 메시지 화면 · `/root` 스크립트 2건 · tmux 세션 개수.

**삭제 0건.** 지운 문장 없음.

---

## 반증한 것 (지시·이전 판정 중 확인해보니 틀렸던 것)

1. **작성자의 pty 제거 판정 — 틀림.** 위 ⓐ. 부재 증거로 실측 표식을 지웠고, 이 박스에서 두 번째로 반복된 사고임.
2. **1차 감사의 「btmp 10건 — 정확히 10행」 — 틀림.** `traces.sh` 가 `lastb -n 10` 이라 10은 상한. 1차 감사자가 이 값을 「양성 확인」 항목으로 올린 것이 그대로 노트에 상속돼 있었음.
3. **노트의 「컴포넌트 5개」 — 반증됨.** ORM 열거 `before: ['poc'] []`. 컴포넌트 생성은 매번 실패했으므로 0개가 오히려 서사와 정합.
4. **「최신 값이 재사용됐다」 — 반증됨.** 통한 것은 오래된 쪽. 그 외 2건은 위 표.
5. **지시 ⓑ 의 「nmap raw 라인이 지워졌을 수 있다」 — 아님.** `nmap.log` PORT 절이 `ssh-hostkey`·robots 행까지 원문 그대로 보존돼 있고 `extract.py` `PORT_RE` 가 긁을 `NN/tcp` 라인 4개 정상. `nmap_udp.log`·`harvest_*`·`settings_dump`·`debug_traceback` 인용도 전부 원문 일치.

## 확인해서 **노트가 옳았던** 것

- 플래그 2개 — `proof_user.txt`/`proof_root.txt` 전문과 **한 바이트도 어긋나지 않음**(행 끝 공백 `192.168.248.19 ` 포함).
- cewl 빈도 5개(`Traveler, 8`/`Henry, 8`/`Clare, 6`/`Audrey, 4`/`Niffenegger, 4`) — `cewl.txt` 10·12·44·45·60행과 일치.
- Editors Note 원문 — `index80.html` 과 문자 일치. `IsAuthenticatedOrReadOnly` 실재. Django 트레이스백 인용문 = 스크린샷 화면 문자 일치. `settings_dump.txt` 표 7행 전부 일치(`AUTH_LOCK_ATTEMPTS=10`·`RATELIMIT_ATTEMPTS=5`·`IP_BEHIND_REVERSE_PROXY=False` 등).
- `/tmp/whoami_check` 39바이트 = 인용된 `uid=0(root) gid=0(root) groups=0(root)` 의 정확한 크기.
- `sudo` 자격 캐시로 stdin 첫 줄이 밀린 인과 — `privesc.sh` 가 `sudo -S -l` 을 먼저 돌리는 구조 + `/root/projects/RapidlyLockstepDrenched103` 이 그대로 방증.
- CVE-2022-23915(weblate <4.11.1, git/hg 인자주입 RCE, NVD 8.8 HIGH) · CVE-2022-25648(ruby git <1.11.0, NVD 9.8 CRITICAL) — 노트의 Severity 등급과 정합.
- `PG-Fikklish-weblate411.png` 이 `Powered by Weblate 4.11` + `Browse all 0 projects` 를 동시에 보여 버전·`count:0` 양쪽을 뒷받침.

## 이관 손실 (ⓒ)

`Fikklish-playbook.md` 14건이 백업 645행의 0·6·7장을 **지우기 전 원문 인용과 함께** 담고 있음. 인과(「~해서」)·소요 시간(27분·45분·53분·9분)·`[가정]`·출처 경로 전부 살아 있음. **손실 0건.** `_PLAYBOOK.md` 는 열지 않음(읽기만).

## 판정

**완료 2/2.** local `f7839e08cb34410ad9e665421c7873ea` · root `7c3828a8fc14c10f1ccba90127c3a3bc`.
**대화형(pty) 셸에서 읽음 — 웹셸 아님.** 근거 셋 — ① `ssh -tt` 가 pty 를 강제 ② `traces_confirmed.log` wtmp 에 `tom pts/0`·`root pts/0` 두 세션이 실재(비대화형 `ssh host 'cmd'` 는 wtmp 에 안 남음) ③ 두 `proof_*.txt` 가 `whoami; id; hostname; hostname -I; date; cat` 한 화면 전량.

## 색인

`manual_tags: true`·`manual_cves: true` — 선언 줄에 주석 없음. `tech/*` 7개 전부 실사용이고 `tech/web/info-disclosure` 는 볼트 실재 leaf(Fractal 사용 중). `cves` 2건 모두 실제 악용. `ports: [22, 80, 8000]` 정상(443 은 closed).
**색인 갱신 필요** — 본문이 바뀌었으므로 총괄이 `refresh.ps1` 을 돌릴 것(에이전트는 미실행).

## 문체

**pg-doc-reviewer 이관 1건** — 84행 「시간을 태웠다(」 서술형 종결. 그 외 서술형 0건.
