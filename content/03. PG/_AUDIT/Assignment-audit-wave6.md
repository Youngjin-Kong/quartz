---
type: audit
target: "[[Assignment]]"
wave: 6
date: 2026-08-25
manual_tags: true
manual_cves: true
---

# Assignment 감사 (wave 6)

대상: `03. PG\Assignment.md` (개작 초고 421행 → 감사 후 461행)
기준선: `03. PG\_backup\Assignment.md.bak` (496행). **git 이력 없음** — `git log -- "03. PG/Assignment.md"` 가 빈 출력이라 이 노트는 한 번도 커밋된 적이 없음. baseline 은 `.bak` 하나뿐임.

---

## 0. 타겟 pty 프롬프트 판정 — **전부 실측. 한 글자도 안 건드림**

지목 ⓐ 는 **Wheels 와 정반대 결론**임.

| 근거 | 내용 |
|---|---|
| `~/PG/Assignment/proof_user.txt` | `jane@assignment:~$` 프롬프트 + **명령이 두 번 찍힌 로컬 에코**. 에코 이중화는 pty 에서만 발생함 |
| `~/PG/Assignment/proof_root.txt` | `bash-5.0#` · `root@assignment:/tmp#` 프롬프트 + 동일한 이중 에코 |
| `harvest_jane.txt` PROCS 374·379행 | `git-receive-pack /home/jane/gogs-repositories/jane/pgtest.git` → 자손 `python3 -c import pty;pty.spawn("/bin/bash")`. **pty 가 실제로 떴다는 프로세스 증거** |
| `~/.zsh_history` | Assignment 관련 항목 0건 — 즉 타겟 접근이 비대화형 `ssh target "cmd"` 였다는 반대 증거도 없음. Kali 쪽은 전부 비대화형이었고 노트에 Kali 프롬프트도 0개 |

**판정: 실측 확정.** 웹셸이 아니라 대화형 셸에서 플래그를 읽었다는 증거가 파일로 남아 있음. Wheels 와 달리 이 박스는 `sshpass ... ssh user@host "cmd"` 형태의 비대화형 접근이 **아니었음**.

부수 정정 — 초고가 pty 로컬 에코 중복 행을 **지우고** 실었기에 원문대로 복원함. 그 중복이 곧 pty 표식이라 지우면 판정 근거가 약해짐.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `Gogs 는 [security] ENABLE_GIT_HOOKS = false 를 올바른 섹션에 두고` | **틀린 일반 지식.** Gogs 0.12.9 에 그런 설정 키가 **존재하지 않음** — 어느 섹션에 둬도 무효 | 실제 게이트(`CanEditGitHook() = u.IsAdmin \|\| u.AllowGitHook`)로 대체. 완화책을 「관리자 최소화 + `allow_git_hook` 회수」로 정정 |
| `RUN_USER = jane` (2곳) | `app.ini` 를 읽은 적 없음. 미관측 설정 키를 실측처럼 단정 | 관측된 프로세스 소유자(`jane 850 gogs web` → `jane 2975 gogs hook ... post-receive`)로 근거 교체 |
| `# ~/PG/Assignment/manual/reg.sh 발췌` 블록 | **「발췌」인데 원문에 없는 `-d "user[role]=owner"` 줄이 있었음.** 원문은 `"${ARGS[@]}"` 이고 role 은 호출부 인자 | 스크립트 원문 그대로 + 호출부 3줄 분리. 호출부는 산출물 파일명 역산이라 `[가정]` 표시 |
| `/var/www/rails-app` 은 `www-data:www-data drwxrwxr-x` | 그 소유자·모드를 찍은 산출물이 없음 | 실제 관측(`harvest_jane.txt` WRITABLE 목록에 `/var/www` 계열 부재)으로 교체. 모드는 「관측 없음」 명시 |
| `applicants_controller.rb` · `notes_controller.rb` ruby 블록 2개 | **`~/PG/Assignment/` 어디에도 이 소스가 없음.** `grep -rn 'user_params\|permit(\|current_user.role\|Insufficient rights'` 전부 0건 | 삭제하지 않고 **「출처 미보존 `[가정]`」 강등.** 결론 자체는 실측(role 대조표 + `note_1.html` 열람 성공)으로 별도 지지됨을 병기 |
| role 대조표 3행 | 2·3행(`admin`·`member` 결과)을 뒷받침할 캡처가 없음. 남은 role 캡처는 `/users/1` 하나뿐 | 표는 유지하고 아래에 `근거부족` `[가정]` 주석 추가. 1행은 결과로 확증됨을 명시 |
| `root@assignment:/tmp# crontab -l` | 실제로 친 명령은 `crontab -l; echo ---; cat /root/clean-tmp.sh; ls -la ...` 였음. 초고가 명령을 잘라 재구성 | `root_crontab.txt` 원문 그대로 복원(`/root/clean-tmp.sh` 사본 존재까지 드러남) |
| `jane@assignment:/tmp$ /bin/bash -p` | `proof_root.txt` 첫 줄은 **프롬프트 없는 `/bin/bash -p`** 임. 초고가 프롬프트를 창작해 붙임 | 파일 원문대로 복원 + 「그 앞 프롬프트는 캡처 범위 밖」 캡션 |
| `— 출처: proof_user.txt` (pty 승격 블록) | 블록 선두 2행(리스너 프롬프트·pty spawn 명령)이 그 파일에 **없음.** 캡션 오귀속 | 블록 분리. 리스너 프롬프트는 「tmux 페인에만 있었음」 + `harvest_jane.txt` 프로세스 계보 교차근거로 재캡션 |
| `find / -xdev ...` · `ls -la /usr/bin/clean-tmp.sh` 블록 | 리버스셸 «안»에서 친 것이라 로그 미보존인데 출처 표기 없었음 | 「출처 미보존」 명시 + 값이 `root_crontab.txt` 와 바이트 일치함을 병기 |
| nmap 코드펜스 | `80/tcp` 다음에 `|_http-title: notes.pg` 가 빠져 8000 의 `Gogs` 타이틀이 80 에 붙어 보임 | 원문대로 `fingerprint-strings` 요약 2행 + `notes.pg` 타이틀 복원. **raw 포트 3행은 그대로 보존**(`PORT_RE` 색인) |
| `/tmp` 업로드물 목록 | `.h/`·`.clean.sh` 는 `cleanup.txt` 에 없고, 실제 있던 `.hj.txt`·`.pspy*.log`·`.seenpids`·`.wb.log` 는 빠져 있었음 | `cleanup.txt` 3절 원문과 일치시킴 |
| `PwnKit 은 시도하지 않음` | 「배제」와 「못 해봄」이 붙어 있어 닫힌 문으로 읽힘(지목 ⓔ) | DirtyPipe = **커널 버전으로 배제됨**, PwnKit = **시도하지 않음**으로 분리. `pkexec` SUID 존재(양성 증거) 명시, 패치 여부는 「관측 없음」 |
| `## 관련` 의 `[[_PLAYBOOK]]` 한 줄 | 앵커 링크 0개 | 지시받은 앵커 7개 연결. 제목 문자열은 `_PLAYBOOK.md` 실물과 대조해 확인(`####` 레벨이지만 Obsidian 앵커는 레벨 무관) |
| Gogs 로그인 curl 블록 | 출처 표기 없음 | `manual/gogs.sh` 원문 대비 차이(`-o`/`-w` 제거, 변수 전개) 명시 + `gogs_login.html` 0바이트·`gogs_home.html` 의 `/admin` 링크를 근거로 추가 |

## 2. 삭제한 것

**없음.** 전부 정정 또는 `[가정]` 강등으로 처리함.

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **「`manual/register.html` 이 실재하지 않는다」 → 틀림.** 파일이 실재함(`-rw-rw-r-- 1 kali kali 5608 2026-08-21 09:20:44 register.html`). 노트의 `<input>` 4행과 **정확히 일치**함(초고는 CSRF 토큰 값만 `...` 로 생략 — 적절한 처리). 캡션 수정 불필요. 지시 ⓑ-1 은 파일 목록 오독이었음.

2. **`forged_owner` / id 번호 서술 → 전부 실측.** 초고의 「id 11 에 URL 인코딩 문자열, id 13 이 `forged_owner`, 내가 만든 계정은 id 14 부터」가 `manual/page_users.html`·`u2.html` 의 `href="/users/N"` 와 완전 일치함:
   `1 jane · 2 tom · 3 jim · 4 judie · 5 james · 6 bob · 7 simon · 10 deezy · 11 authenticity_token=... · 12 deezy · 13 forged_owner · 14 probe1 · 15 mass_owner · 16 mass_admin · 17 mass_admtrue`
   ⚠️ 스크린샷의 **화면 순서(9번째·11번째)와 id 가 다름**(8·9 결번) — 순서로 세면 오탐이 남. `[가정]` 표기도 적정.

3. **「세 후보를 한 번에 쏜 뒤 대조」 → 실측 지지.** `resp_reg_*.html` mtime 이 09:23:51 · 09:24:04 · 09:24:17 로 **평가(로그인 09:24:32~) 이전에 3건이 연속 발사**됨. 순차 평가가 아니었음.

4. **Gogs 0.12.9 / 빌드시각 → 실측.** `manual/gogs_admin.html` 에 `Application version` `0.12.9` 와 `2022-06-07 05:03:46 UTC` 가 그대로 있음. 「버전 근거 2개」 원칙 서술도 사실.

5. **`harvest_jane.txt`, 1300행 → 정확.** `wc -l` = 1300.

6. **puma root 구동 · 커널/OS · SUID/getcap 스톡 · cleanup 증적(`/bin/bash` md5 `23c415748ff840b296d0b93f98649dec`, `/dev/shm` 페이로드, `authorized_keys`) → 전부 산출물과 일치.**

7. **`^---$` 4개 중 2개가 코드펜스 안이라는 관리자 판정 → 옳음.** 건드리지 않았음. 정정 과정에서 crontab 블록을 원문 복원하며 **펜스 안 `---` 이 하나 늘어 3개**가 됨(전부 `echo ---` 실측 출력).

## 4. 근거 출처

- Kali 산출물: `~/PG/Assignment/` — `proof_user.txt` · `proof_root.txt` · `root_crontab.txt` · `cleanup.txt` · `harvest_jane.txt`(1300행) · `harvest_root.txt`(1366행) · `nmap-quick.txt` · `gobuster-80.txt` · `_SUMMARY.txt` · `manual/` 70개 파일
- 볼트 `파일보관\` — `PG-Assignment-*.png` **8장 전부 실재**하며 노트의 `![[...]]` 8개와 1:1 대응. `PG-Assignment-members-owner.png` 는 직접 열어 회원 목록을 대조함
- `~/.zsh_history` — Assignment 항목 0건(비대화형 접근이었다는 증거이자, 타겟 셸 내부 명령이 안 남는다는 §2 규율의 실례)
- git: `git log -- "03. PG/Assignment.md"` 빈 출력 → **커밋 이력 없음**
- 1차 사료 — Gogs `v0.12.9` 태그 소스 직접 조회:
  - `conf/app.ini` (19650바이트) — 전 섹션 목록에 `ENABLE_GIT_HOOKS` **부재**
  - `internal/cmd/web.go:448-452` — 훅 라우트가 `context.GitHookService()` 하나로만 게이트됨
  - `internal/context/repo.go:455-462` — `if !c.User.CanEditGitHook() { c.NotFound() }`
  - `internal/db/user.go:174-177` — `CanEditGitHook() { return u.IsAdmin || u.AllowGitHook }` — **설정 키 참조 0**

## 5. 이관 손실 점검 (지목 ⓓ)

`.bak` 의 시행착오 7건 중 **6건이 `_PLAYBOOK.md` 에 인과·수치와 함께 생존**함:

| `.bak` 항목 | `_PLAYBOOK` 위치 | 인과·수치 보존 |
|---|---|---|
| `head -20` 절단 | A-45 (243행~) | ✅ 「약 10분 손실」 유지 |
| pspy GLIBC 실패 | A-45 (251행~) | ✅ `GLIBC_2.34 not found` 원문 |
| `ENABLE_GIT_HOOKS` 함정 | A-45 (269행~) / B-22 (510행) | ✅ `[가정]` 포함 |
| `pkill -f` 자기살해 | A-33 (187행~) | ✅ 「cmdline 전체 매칭이라 자기 셸이 죽음」 |
| Gogs 200 조용한 실패 | A-12 (50~54행) | ✅ `uid` vs `user_id` · 27KB vs 0바이트 대조까지 |
| SSH 비번 재사용 실패 | A-24 (129행) | ✅ |
| 소요 시간 | 744행 | ✅ 「전체 약 30분 · 정찰 1분 · 매스어사인먼트~자격증명 6분 · 훅 RCE 3분 · **root 크론 특정 14분**」 |

⚠️ **누락 1건 — 「포털 브리핑이 포트 80 을 통째로 빠뜨렸다」.** `_PLAYBOOK.md` 에 `브리핑` 문자열이 **0건**임. `.bak` 366~376행의 항목 전체가 이관되지 않았음. 내용:

> 브리핑이 제시한 경로는 「8000 Gogs → 계정 열거 + 파라미터 변조로 admin 승격 → git hooks RCE → jane → root 크론 clean-tmp.sh」. 실제와 두 군데가 어긋남 — ① 계정 열거와 파라미터 변조는 Gogs 가 아니라 **80 의 Rails 앱**에서 일어남(브리핑은 80 을 아예 언급 안 함) ② **Gogs 에서 승격할 일이 없음**(jane 이 처음부터 admin). 교훈: **공식 힌트를 우선순위로는 쓰되 열거 범위를 좁히는 데 쓰지 말 것.**

`_PLAYBOOK.md` 는 감사자 편집 금지 대상이라 손대지 않음. **총괄 판단 필요.**

`[가정]` 은 초고 1건 → 정정 후 7건, 「관측 없음」 은 2건 → 3건. 어느 것도 지우지 않았음.

## 6. 총괄에 올릴 것

1. **`_PLAYBOOK.md` A-45·B-22 의 `ENABLE_GIT_HOOKS` 서술이 이 노트와 같은 오류를 상속함.** 「값이 `false` 였는데 그대로 동작했음」이라는 **관측은 옳고** 「믿지 말 것」이라는 **결론도 옳으나**, 붙어 있는 원인 추정(`[가정]` 섹션 배치 어긋남)이 **1차 사료로 반증됨** — Gogs 에는 그 키가 아예 없고 훅 편집은 `u.IsAdmin || u.AllowGitHook` 로만 갈림. 비슷한 이름의 `[security] DISABLE_GIT_HOOKS` 는 **Gitea** 설정임. 여러 노트에 파급되는 사안이라 감사자가 고치지 않음.
2. **「포털 브리핑 공백」 시행착오 1건이 `_PLAYBOOK` 으로 이관되지 않음**(위 5절 전문 인용).
3. **색인 갱신 필요** — 본문 CVE 언급이 늘었으나 `manual_cves: true` + `cves:` 필드 부재라 색인에는 안 잡히는 것이 의도된 결과임. `tech_count: 8` 은 실제 `tech/*` 태그 8개와 일치함(검산 통과). `refresh.ps1` 은 감사자가 돌리지 않음.
4. **구조 순서 — 손대지 않았으나 보고함.** `### Initial Access`(finding 4항목) 가 `### Service Enumeration` **앞**에 옴. OSCP 제출 보고서 순서로는 열거가 먼저지만, 관리자가 이미 구조를 검산·승인했으므로 재배치하지 않았음.
