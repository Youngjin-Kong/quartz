---
type: audit
box: Twiggy
wave: 18
date: 2026-08-26
role: writeup-auditor
---

# Twiggy — 적대적 검증 · 정정 기록 (웨이브 18)

대상: `03. PG\Twiggy.md` (pg-note-forge 개작본 441행 ← 1365행)
백업: `03. PG\_backup\Twiggy.md.post-forge.bak` (정정 전 437행 시점 원본 = 개작 직후 상태)

## 근거 출처 — 실제로 연 것만

| 출처 | 확인 내용 |
|---|---|
| `~/PG/Twiggy/nmap.log` (2087B / 37행) | 노트 raw 블록과 **바이트 동일** 확인(정정 후) |
| `~/PG/Twiggy/CVE-2020-11651-poc/exploit.py` (10242B) | argparse·`pwn_upload_file`·`pwn_read_file`·`pwn_exec` 전문 대조 |
| `~/PG/Twiggy/CVE-2020-11651-poc/passwd` (1054B, md5 `04c2979e…`) | 노트 블록과 내용 동일. **원본 22줄 + `qq` 1줄 = 23줄** |
| `~/PG/Twiggy/CVE-2020-11651-poc/.git` HEAD | `eca6ba2d0845…` / `Fri Jul 10 11:30:09 2020 +0200` / `Rework version / vulnerability detection` — 노트 인용과 일치 |
| 볼트 `파일보관\` 스크린샷 8장 직접 열람 | 아래 ⓔⓕ |
| `~/.zsh_history` | `twiggy`·`189.62` 히트 1건 — **1024행 `ssh qq@192.168.189.62`**. 노트의 「1024행」 표기 정확 |
| git `15671e5` / `607fbc5` / `aba5a29` | 아래 ⓘ |
| kali pip salt 3008.0 소스 (`master.py`·`wheel/file_roots.py`·`channel/client.py`) | 아래 소스 검증 |
| NVD CVE-2020-11651 / -11652 · VMSA-2020-0009(Broadcom 이관 URL) | CVSS 확인 |
| `_AUDIT\portal-진행도-실측-20260820.md` 35행 | `Twiggy | 완료 1/1 | 0/1 | 미제출` |

## 고친 것 (13건)

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `— 출처: ~/PG/Twiggy/CVE-2020-11651-poc/ 실행 로그(세션 캡처)` ×3 | **그 경로에 실행 로그 파일이 없다.** 디렉터리 내용은 `exploit.py`·`.git`·`passwd`·`README.md` 뿐. `.bak` 에는 0건, 개작본에 3건 — **개작 중 새로 붙은 허위 출처 표기** | 실제 출처로 교체 — 2건은 스크린샷 파일명(`…125348.png`·`…125525.png`), 업로드 블록은 「최초 노트(2026-06-11) 전사 원문 — 스크린샷 없음」 |
| `ED25519 key fingerprint is SHA256:uYMZ…` | **실측 개변.** 스크린샷 `…134941.png` 확대 판독과 최초판(`15671e5`) 모두 `is:` — 콜론이 있다. `aba5a29` 에서 1바이트 소실 | `is:` 로 복원 |
| `조립한 passwd 파일(원본 21줄 + 추가 1줄)` | 산출물 `passwd`·스크린샷 `…130140.png` 모두 **원본 22줄**. 개작 중 새로 붙은 오산 | `원본 22줄 + 추가 1줄` |
| `if cmd.startswith('__'):  # 유일한 방어 — 거부 목록` | 인용한 salt 소스에 없는 **한국어 주석을 코드펜스 안에 주입**. 소스 원문 개변 | 주석 제거 |
| `key = self.key  # 마스터의 키 딕셔너리 전체` | 동상. salt 3008.0 `master.py:4012` 원문은 주석 없음 | 주석 제거 |
| `_package_load` 펜스의 `# 'clear' 또는 'aes'`·`# 실제 요청 본문` | 동상. `channel/client.py:497` 원문에 주석 없음 | 주석 제거 + 같은 설명을 펜스 **밖** 산문으로 |
| ` ```bash pip3 install salt  # kali: …site-packages/salt (3008.0)``` ` | 실제로 친 적 없는 주석을 명령줄에 덧붙임 | 명령만 남기고 경로·버전은 산문으로 |
| `\| ssh-hostkey:` (nmap raw) | 원문의 **행말 공백 1바이트**가 탈락 | 복원 → 블록이 `nmap.log` 와 바이트 동일(2087=2087) |
| `**Local.txt value:** … 다만 위 /etc/passwd 읽기가 …있었다면 같은 방식으로 읽혔을 것.` | 플래그 슬롯 안에서 **「위」 상대 참조** + 근거 없는 추측을 무표시 단정 | 상대 참조를 `wheel file_roots.read` 로 치환, 「**관측 없음**」 유지, 추측에 `[가정]` 부착. 「요약 참조」도 제거 |
| `Not shown: 65529 filtered … 이것이 후속 리버스셸 실패와 관련된다` | **인과 비약.** 인바운드 `filtered` 는 아웃바운드 차단의 근거가 아니다. `--exec` 실패 원인은 이관 제안 1 자신이 「전부 확정 못함」으로 적고 있다 | 「**인바운드** 앞단 방화벽」으로 한정 + `[가정]` 로 아웃바운드 개연성 강등, 원인 미확정 명시 |
| `크론·--exec RCE 는 … 아웃바운드가 막혀 있어 배제` | 미확정 원인을 단정 + 「배제」와 「못 해봤다」 혼동 | 「connect-back 이 리스너까지 오지 않아 포기 — **실패 원인은 확정하지 못했음**」 |
| `- Kali 리스너 없음(SSH 경로라 리버스셸을 쓰지 않았음 …)` | 스크린샷 `…125416.png` 에 4444 리스너를 겨눈 `--exec` 가 실측으로 남아 있어 「리스너 없음」이 오독을 부름 | 「리스너 **잔존** 없음 — 시도 때 4444 를 띄웠으나 정리했고 최종 경로는 SSH」 |
| `salt-master 는 배포 패키지 유닛에 User= 지시자가 없어 …` | 타겟 유닛 파일을 본 적이 없다(pip 패키지에도 `salt-master.service` 없음 — 실측). 검증 불가 단정 | 「이 박스의 salt-master 는 root 로 구동 — 증거는 `/etc/passwd` 쓰기 성공」을 앞세우고 유닛 추정은 `[가정]` 으로 분리 |

### 깊이 기준(소스 고고학) 정리 2건
- `salt/master.py:1080` · `salt/master.py:2153` — 파일:행번호 제거, 함수명만 유지. `_prep_auth_info` 쪽은 「kali 의 salt 3008.0 소스에서 확인」으로 검증 근거를 대체 명시
- `<탈취한 root key>` → `<root key>` — 코드펜스 안 한국어 제거(플레이스홀더)

### 표준 관할 이동 1건
- `> [!warning] 시험 증거 형식 — … ip a 가 빠져 감점 대상이다` 콜아웃 **삭제**. `_WRITEUP-STANDARD` 「시험 관점은 박스 노트에 쓰지 않는다」 위반이고, **같은 내용이 `Twiggy-playbook.md` 제안 7 에 이미 원문 보존**돼 있어 손실 없음.
  삭제 원문(복원용):
  ```
  > [!warning] 시험 증거 형식 — 이 화면(SSH 세션 캡처)은 `ip a` 가 빠져 감점 대상이다
  > OSCP 는 플래그를 `whoami`·`hostname`·`ip a` 와 한 화면에 요구한다. 습관으로 굳힐 한 줄: `whoami; hostname; ip a | grep 'inet '; cat /root/proof.txt`.
  ```

## 반증한 것 — 지적으로 올렸다가 «노트가 옳았던» 것 (8건)

1. **ⓐ 절 순서가 틀렸다** → **철회.** `Initial Access`(4항목) → `Service Enumeration` → `Initial Access`(재현) → `Privilege Escalation` → `Post-Exploitation` 은 `_WRITEUP-STANDARD` 「단일 호스트(템플릿 4장)」 템플릿과 **글자 그대로 일치**하고, 실물 기준 `Robust.md` 도 동일 배열(32/55/85/210/275행). 첫 `Initial Access` 절에 4항목 외의 것 **섞이지 않음**. 두 `Initial Access` 제목도 서로 다름
2. **ⓓ nmap raw 절단·압축** → **철회.** 37행 전량 보존. 행말 공백 1바이트만 어긋나 있었고(위에서 복원) 그것이 유일한 차이. `PORT_RE` 대상 라인 6개 전부 생존 → `ports` 색인 정상
3. **ⓔ 프롬프트 실측 주장이 허위** → **철회.** 스크린샷 5장을 **직접 열어** 확인: `…125348`(exploit 실행) · `…125525`(passwd 읽기) · `…125947`(openssl passwd) · `…130140`(cat passwd) · `…134941`(ssh) 전부 `┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]` 형태의 **대화형 터미널 캡처**. 작성자 신고대로 5장이 실재하며, `[root@twiggy ~]#` 타겟 pty 프롬프트도 스크린샷과 일치 — **하나도 지우지 않았다**
4. **ⓔ 업로드 블록에 스크린샷이 없으니 근거부족** → **부분 철회.** 스크린샷은 실제로 없으나(11장 전수 확인: `…125416`·`…125419` 는 `--exec` 시도, `…134858` 은 ssh 초기 캡처), 그 블록은 **최초판 `15671e5` 와 바이트 동일(818B)** — 사람이 2026-06-11 당일 전사한 원문이다. 등급은 「출처 표기 정정」에 그쳤고 삭제·강등하지 않음
5. **ⓕ 스크린샷 재배치가 틀렸다** → **철회.** `Pasted image 20260611125243.png` 를 열어보니 **구글 검색 「CVE-2020-11651 github」 결과 화면**(1위 jasperla/CVE-2020-11651-poc). 작성자 반증이 맞고 새 배치·캡션도 정확
6. **ⓖ CVE 오염** → **철회.** 본문 CVE 토큰은 `CVE-2020-11651`·`CVE-2020-11652`·`CVE-2014-9721` 3종이고 `CVE-2014-9721` 은 「이 박스와 무관」 명시 상태. `manual_cves: true` + `cves:` 줄에 주석 없음이라 색인 오염 없음. 역할 구분도 정확 — 11651=`ClearFuncs` 인증우회(NVD **9.8 CRITICAL** 확인), 11652=`file_roots` 트래버설(NVD **6.5 MEDIUM · CWE-22** 확인). VMSA-2020-0009 의 11651 최대 **10.0** 도 원문 확인
7. **ⓒ 이관 손실** → **대체로 철회.** 구 노트 6장 ①~⑧ 전량이 `Twiggy-playbook.md` 9건 제안의 「④ 지우기 전 원문」에 **전문 인용**으로 보존. 개작본이 떨어뜨린 유일한 이미지 링크 `![[Pasted image 20260611125419.png]]` 도 제안 1 원문 인용 안에 살아 있음. 최초판(`15671e5`)에만 있고 현행·이관본 **양쪽에 없는 실측은 발견하지 못함**
8. **ⓘ 「aba5a29 소실 없음」** → **확인(작성자 옳음), 단 1건 예외.** `15671e5`(204행) → `aba5a29`(1365행) 은 순수 확장이 맞다. 다만 SSH 블록에서 3바이트가 손질됐고 그중 `is:` → `is` **1건은 실손실**(나머지 `can''t`→`can't`, `''s`→`'s` 는 최초판의 전사 오타를 스크린샷대로 바로잡은 것이라 정정이 옳다). 나머지 블록(`--upload-src` 818B · `cat passwd` 1125B · `-r /etc/passwd` 1681B)은 **바이트 동일**

## 1차 사료로 «맞다»고 확인한 노트 주장

- `_prep_auth_info` 본문 — salt 3008.0 `master.py:3998-4014` 와 구조 일치(따옴표 스타일만 다름). 「패치 이후에도 함수 본문은 그대로」 **참**
- 패치 = `ClearFuncs.expose_methods` 허용 목록 6개 — `master.py:3622` 에 `ping/publish/get_token/mk_token/wheel/runner` **정확히 6개**. `get_method()`(`2106`)가 `_handle_clear`(`1988`)의 디스패치를 대체 **참**
- `find()` 에 `isabs` 없음 / `write()` 에 `isabs` 있음 / `os.makedirs()` 자동 생성 / 반환 문자열 `Wrote data to file {dest}` — `wheel/file_roots.py` 전문 대조 **전부 참**. 노트 출력의 `[ ] Wrote data to file /srv/salt/../../../../../etc/passwd` 와 정합
- PoC 동작 — `--master` 기본값 `127.0.0.1`, `[-] Destination path must be relative; aborting` 은 `os.path.isabs(args.upload_dest)` 의 **클라이언트측** 거부, `print('[ ] {}')` 라 성공 판정 없음, `if rets: print('YES')` — 전부 `exploit.py` 원문 **일치**
- `wheel file_roots.read` 요청 딕셔너리 — `pwn_read_file()` 의 `msg` 와 키·순서 **일치**
- 타임존 정합 — `--exec` 스크린샷의 jid `20260611035400329542`(UTC 03:54:00) ↔ 파일 mtime `12:54:16 +0900`. **모순 없음**
- 플래그 `3fd4954f15b0824c66637cf374e5afd0` · 해시 `$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0` · root key · 공격자 IP `192.168.45.173` — 스크린샷과 **한 글자도 다르지 않음**

## 문체 — `pg-doc-reviewer` 관할로 이관

서술형 종결(`~한다`·`~이다`)이 산문 전반에 남아 있음. `_WRITEUP-STANDARD` 「문체」(명사 종결형 개조식) 미적용 구간 다수 — **이관 N건: 약 25개 문단**. 사실 검증 관할이 아니므로 손대지 않았음.

## 색인

`manual_tags: true` · `manual_cves: true` 유지. `tech/*` 4종(`svc/salt`·`web/auth-bypass`·`lin/passwd-write`·`cred/crack`) 전부 실제 사용 기법. `ports`·`cves` 변경 없음.
**노트 본문이 바뀌었으므로 색인 갱신이 필요함** — `refresh.ps1` 은 총괄/관리자 몫이라 실행하지 않았음.

## 진행 판정

**완료 1/1** — proof 플래그 1개(포털 슬롯도 1개), `local.txt` 슬롯 없음. 근거: `_AUDIT\portal-진행도-실측-20260820.md` 35행(`완료 1/1`) + 스크린샷 `…134941.png` 의 `[root@twiggy ~]# cat proof.txt`. 포털 제출은 **0/1 미제출** 상태.
