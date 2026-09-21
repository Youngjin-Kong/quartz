---
type: audit
box: GLPI
wave: 6
date: 2026-08-25
manual_tags: true
manual_cves: true
---

# GLPI 적대적 검증 — wave 6

대상: `03. PG\GLPI.md` (개작 초고 496행 → 508행)
증거원: `~/PG/GLPI/` 52개 산출물 · 볼트 `파일보관\`·`_backup\` PNG 4장 · `~/.zsh_history` · Kali 직접 재실행 · 벤더 공지 / NVD

**날조 확정 0건.** 정정 11 · 강등 3(`[가정]` 신설) · 삭제 0 · 반증 6.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `**Local.txt value:**` | `Privilege Escalation` 절 안에 있어 같은 웨이브 `Fractal.md`(값=`Initial Access` 말미 + 회수 시점 한 줄 명시)와 형식이 어긋남 | `Initial Access` 상세 절 말미로 이동. `-r--r----- betty betty` 라 www-data 로 못 읽었고 betty 승격 뒤 회수했음을 그 자리에서 한 줄로 명시. PrivEsc 쪽은 「값은 `Initial Access` 절 말미에 표기」로 교차참조 |
| `=== root proof ===` 펜스 | 「`proof_root.txt` 전문 그대로」라고 적고서 **`/root/proof.txt` 한 줄을 누락** | 원문대로 복원. 더해 ⓐ 그 줄은 `cat` 이 낼 수 없어 `ls` 류가 하나 더 있었음 `[가정]` ⓑ `id` 가 `euid=0` 인 것으로 보아 `;` 로 끊긴 betty 셸이 아니라 이미 열린 `rootbash -p` 세션 안에서 실행됨을 명시 |
| `mysqldump -uglpi ... grep -aoiE ".{120}...{160}"` | 명령 원문 미보존인데 실측처럼 제시. 이 정규식이면 출력 창이 **최소 283자**여야 하는데 `db_grep.txt` 실측은 **220~290자**로 흩어짐 → 실제 호출은 이것과 다름 | 명령은 남기되 `[가정]` 강등 + 길이 불일치를 근거로 명시. 「접근(DB 전량 덤프 후 일괄 grep)은 확정, 폭 값은 재현용으로 쓰지 말 것」 |
| `sshpass -p ... ssh betty@...` | 산출물·`~/.zsh_history` 어디에도 없는 재구성 명령 | `[가정]` 강등. 「`~/.zsh_history` 에 이 박스 명령이 한 줄도 없음(비대화형 `ssh kali "..."` + 원격 셸 내부 명령은 미기록)」을 근거로 붙임. 확정되는 것은 `proof_user.txt` 가 betty 계정으로 찍혔다는 것뿐 |
| 실패 응답 10종 목록 | **`m_id.html` 누락**(원본 `.bak` §6 에는 있었음). 이관 손실 | `m_id.html => ''` 추가(11종). 재추출로 11개 전부 `''` 확인 |
| `rce_a~d.html·page1.html·p.html 은 42134바이트로 ... 동일` | 「동일」이 바이트 동일을 함의하나 **md5 는 6개가 전부 다름** | 「크기가 42134바이트로 같음」으로 정정 + 요청마다 새 `sid`·CSRF 토큰이 박혀 md5 가 다름을 명시 |
| nmap 펜스 캡션 `— 출처: nmap.log` | `ssh-hostkey` 3줄·OS 추정·TRACEROUTE 를 말없이 잘라냄 | `(발췌 — …생략)` 명시 |
| `클래스패스 중간과 시스템 프로퍼티 뒷부분은 ... 로 줄임` | 클래스패스는 **원문 그대로**였음(잘못된 자기신고) | 「클래스패스는 원문 그대로, 뒤쪽 시스템 프로퍼티와 `etc/*.xml` 인자만 생략」 |
| `root  3356  0.0 ... \_ /tmp/rootbash` 펜스 | 공백이 압축돼 `ps` 출력이 손질됨(문체 명목의 실측 훼손) | `harvest_betty.txt` 367행 원문 공백 그대로 복원 + 행번호 출처 추가 |
| `===SSH===` 펜스 | `cat: /home/betty/.ssh/id_rsa: No such file` 한 줄 누락, 발췌 표기 없음 | 원문 줄 복원 + `(발췌)` 표기. `local.txt` 퍼미션이 여기서 확정된다는 연결 추가 |
| `LDAP·메일수집기 테이블도 비어 있음` | 해당 테이블을 **직접 덤프한 산출물이 없음**(`tables_cred.txt` 는 테이블 «이름» 목록뿐) | `proxy_passwd`·`smtp_passwd` 는 `db_grep.txt` 2행으로 직접 확정, LDAP·메일수집기는 `[관측 없음]` + ⓐDB 전량 grep 무히트 ⓑ`/status.php` 두 근거로 부재 판단임을 분리 표기 |
| `Vulnerability Fix` — 「데모·테스트 스크립트 제거」 | 벤더 공지는 **`htmLawedTest.php` 만** 지우고 `htmLawed.php` 는 «건드리지 말라»고 명시 — 통째 삭제는 앱을 깨뜨림 | 벤더 문구대로 파일 단위로 특정 |
| `dash 는 … euid 를 ruid 로 되돌림` | 맞지만 불완전 — 독자가 「`sh` 를 `bash` 로 바꾸면 된다」로 오독할 수 있음 | Kali 재현 결과(`bash -c` 도 강등, `bash -p -c` 만 유지)를 한 줄로 추가 |
| `[[_PLAYBOOK]]` 3곳 bare 링크 | 앵커 없음 → 시험장에서 증상 카드로 못 감 | 실재 확인된 7개 앵커(A-22·A-41·B-13·B-18·B-33·B-34·B-62)로 교체. `_PLAYBOOK.md` 104·197·371·456·537·558·663행에서 제목 문자열 일치 확인 |

## 2. 삭제한 것

**없음.** 반증된 서술은 전부 정정 또는 `[가정]`·`[관측 없음]` 강등으로 처리.

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **「11분 / 전체 16분」이 틀렸다는 작성자 반증 → 작성자가 옳음.** mtime 재현(전부 KST=UTC+9): `rce_a.html` 07:52:00.654 KST(=22:52:00 UTC) → `am_id.html` 08:01:41.05 KST(=23:01:41 UTC) = **9분 41초**. nmap 헤더 `Fri Aug 21 07:51:09 2026`(Kali 로컬=KST) → `proof_root.txt` 08:18:24 KST = **27분 15초**. `head_80.txt` 의 `Date: Thu, 20 Aug 2026 22:51:12 GMT` 가 KST↔UTC 대응을 고정해 줌. ⚠️ **틀린 쪽은 노트가 아니라 `CLAUDE.md` §2 「11분 / 전체 16분」** — 총괄 판단 필요.
2. **dash euid 소실 재현 → 작성자가 옳음.** Kali **홈 디렉터리**에서 SUID root bash 를 만들어 실행:
   `-p -c 'id'` → `euid=0(root)` / `-p -c 'sh -c id'` → 소실 / `-p -c 'bash -c id'` → 소실 / `-p -c 'bash -p -c id'` → `euid=0` 유지 / `-p -c 'dash -c id'` → 소실. `/bin/sh -> dash` 확인.
   `/tmp` 가 `tmpfs rw,**nosuid**,…` 라 거기서 재현하면 SUID 자체가 무시돼 헛짚는다는 지적도 사실. (테스트 파일은 즉시 삭제.)
3. **CVE-2022-35914 수정 버전 10.0.3 · 9.5.9 → 맞음.** 벤더 공지 원문 확인. NVD 문구도 `"GLPI through 10.0.2"`, CVSS 3.1 = **9.8** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` 로 노트와 일치.
4. **`disable_functions.txt` 가 root 획득 뒤 메모 → 맞음.** mtime 08:20:57 KST > `proof_root.txt` 08:18:24 KST. 0바이트 `nothing` 파일도 **같은 초**(08:20:57)라 정리 시점에 같이 생긴 것으로 보강됨. 산출물 전체에서 `disable_functions` 등장 파일이 이것 하나라는 것도 확인.
5. **실패 응답의 `</form>` 뒤 구간이 전부 빈 문자열 → 맞음.** `rce.sh` 와 같은 정규식으로 재추출: 11개 전부 `''`, `am_id.html`·`rce_success_id.html` 만 `uid=33(www-data)…`.
6. **`[관측 없음]` 8→8 이관 무손실 → 맞고, 정정 후 9.** `.bak` 8건 · 개작본 8건(7 유지 + 「UDP 미시도」 신규, 1건 `_PLAYBOOK` 이관). 이번 감사에서 LDAP·메일수집기 건이 추가돼 **9**.
7. **`_PLAYBOOK` 이관 무손실 → 확인됨.** 인과(「~해서」)·수치(9분41초·27분15초·실패 산출물 18개)·`[관측 없음]`(bcrypt 대기 시간 미기록)·출처 경로(`ssh_reuse.txt`·`glpicrypt.key`)가 A-22 112·114행, A-41 212행, B-13 384행, B-18 460·465행, B-33 541행, B-34 562·566행, B-62 667행, D절 739·749행에 살아 있음. 실패 산출물 18개 = 프로빙 응답 17 + 0바이트 `htmLawed_src.php` 로 검산 일치.
8. **웹셸 플래그 경고 → 노트가 옳음.** `proof_user.txt`·`proof_root.txt` 모두 betty 계정 pty 에서 찍혔고(`uid=1000(betty)`, root 쪽은 `euid=0`), 노트에 `> [!warning] 여기는 대화형 셸이 아니다` 콜아웃으로 웹 RCE 단계와 분리돼 있음. `local.txt` 가 `-r--r----- betty betty` 라 www-data 로는 애초에 읽을 수 없었다는 것이 물리적 보강.
9. **코드펜스 안 산문 위장(ⓒ) → 해당 없음.** 56개 펜스 전수 대조. 유일하게 의심 대상이던 `harvest` SUDO 절의 한국어 줄 `(sudo -n 실패 — 비밀번호 필요)` 는 `harvest_betty.txt` **29행에 실제로 있는 스크립트 출력**이라 창작이 아님. 나머지 산출물 인용은 `nmap.log`·`head_80.txt`·`resp_CHANGELOG.md` 6행·`resp_status.php`·`config_db.txt`·`glpi_users.txt`·`ticket_dump.txt`·`root.xml`·`rce.sh`·`harvest_betty.txt` 145~152·382·1273행과 **바이트 일치**. `**http**` 펜스 2개는 `<cmd>`·`<CMD>` 자리표시자를 쓴 요청 «형태»이고 본문이 「통상 형태는 이것」으로 명시함 — 출력 위장 아님.
10. **스크린샷 임베드 → 깨지지 않음.** `파일보관\PG-GLPI-login.png`(32209B)·`PG-GLPI-htmlawed-testpage.png`(62837B) 실재. `_backup\` 의 `PG-GLPI-glpi-login.png`·`PG-GLPI-htmlawed-rce.png` 는 각각 같은 크기의 사본으로 노트 서술과 일치. Kali `shot_htmlawed.png` == `shot_rce_success.png`(md5 `5b8b79b333d505816c05b501ef6f563c`) 도 확인.
11. **산출물 52개 → 맞음.** `ls -1 | wc -l` = 52.

## 4. 손대지 않은 것 — 관할 밖

- **문체 이관 0건.** 개조식·번역투 위반이 눈에 띄지 않았음. (`pg-doc-reviewer` 로 넘길 건 없음)
- **타겟 pty 프롬프트** — 이 노트에는 애초에 없음(플래그 증거가 리다이렉트 파일이라 프롬프트가 안 남음). 지운 것 없음.
- **Kali 프롬프트 0개** — 창작 없음.
- `_PLAYBOOK.md`·`_STATUS.md`·`_WRITEUP-STANDARD.md`·`CLAUDE.md` 미편집. `refresh.ps1`·`extract.py` 미실행.

## 5. 근거 출처

- Kali 산출물: `~/PG/GLPI/` 전량(mtime `--time-style=full-iso`, md5sum, `</form>` 재추출 스크립트, 줄길이 `awk length()`)
- `~/.zsh_history` — GLPI 관련 명령 **0건**(`betty` 히트 2건은 무관한 `a.betty` 계정 목록)
- 볼트: `03. PG\_backup\GLPI.md.bak`(326행 원본) · `파일보관\PG-GLPI-*.png` · `03. PG\Fractal.md` 220~233행(형식 기준) · `03. PG\_PLAYBOOK.md`(앵커 실재 확인, 읽기만)
- Kali 직접 실행: 홈 디렉터리 SUID bash 로 dash/bash euid 강등 5종 재현, `findmnt` 로 `/tmp` `nosuid` 확인
- 1차 사료: <https://www.glpi-project.org/en/security-update-10-0-3-and-9-5-9/> · <https://nvd.nist.gov/vuln/detail/CVE-2022-35914>

## 6. 총괄 판단이 필요한 것

1. **`CLAUDE.md` §2 「GLPI 는 … 약 20회 돌아 11분을 태웠다 — 전체 16분」이 실측과 불일치.** 실측은 **9분 41초 / 27분 15초**(위 반증 1). `_PLAYBOOK` D절 739행은 이미 실측값으로 갱신돼 있어 **`CLAUDE.md` 만 스테일**. 공유 인프라라 감사자가 고치지 않음.
2. **색인 갱신 필요** — 노트 본문·링크가 바뀌었으므로 다음 `refresh.ps1` 사이클에 포함할 것(감사자는 실행하지 않음).
3. **`_STATUS.md` 판정 제안: GLPI = 완료 2/2**(user·root 플래그 모두 `proof_*.txt` 로 확정). 기록은 `pg-line-manager` 몫.
