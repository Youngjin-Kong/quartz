# Monster.md 적대적 검증 — 감사 기록

작업일 2026-08-20 · 백업 `03. PG\_backup\Monster.md.bak-audit-20260820`
행수 890 → 993 (LF 기준. 지시서의 "797행"은 다른 계수기 값으로 보인다)
⚠️ 감사 중 **동시 편집이 있었다.** 러너의 후속 세션이 §4 XAMPP 절·§6-7·§6-8·「남긴 흔적」을 추가했고, 그 추가분에 반증 대상이 섞여 있었다(아래 A-6).

---

## A. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| A-1 §6-7 `best64.rule` | **"틀린 파일명을 줘도 hashcat 이 에러를 안 낸다 / 조용히 0줄을 출력하고 종료한다"** — Kali 에서 직접 실행해 반증. hashcat 은 `/usr/share/hashcat/rules/best64.rule: No such file or directory` 를 **stderr 로 찍고 exit 255** 를 낸다 | 진짜 함정으로 다시 씀 — (1) 에러가 stderr 라 `> words_b64.txt` 리다이렉트를 안 타고, (2) 파이프라인 exit code 가 `sort` 의 0 이라 `&&`·`set -e` 가 안 걸리고, (3) `sort` 가 빈 입력을 정상 처리해 0바이트 파일을 성공적으로 만든다. 실행 원문을 블록으로 넣음 |
| A-2 §4 세션 0 `notepad.exe` 블록 | 출처로 `try_privesc_full_scrollback.log` + `tasklist /v /fi "imagename eq notepad.exe"` 를 적었는데 그 파일에 **`tasklist` 가 한 번도 나오지 않는다**(`grep -n tasklist` 무매치). 노트에 실린 `Services`·`0`·`324 K`·`364 K`·`Unknown`·`0:00:00`·`N/A` 컬럼은 **어느 산출물에도 없는 값**이다 | 실제 산출물(`Get-WmiObject Win32_Process ... GetOwner()` 필터 출력, 901~1005행)로 교체. `notepad.exe` 정확히 **23개**. 확정되는 것은 「Owner 열이 비어 있다 = 소유자 접근 거부」까지이고, **「세션 0」 판독은 `[가정]` 으로 강등** |
| A-3 §4 `nxc smb` 블록 | 비대화형 `ssh kali "..."` 결과에 `┌──(kali㉿kali)-[~/PG/Monster]` / `└─$` 두 줄을 붙였다. `try2_spray_admin.log` 는 `SMB ...` 5줄로 시작한다 | Kali 프롬프트 2줄 제거, 명령을 별도 블록으로 분리. **SMB 출력 5줄은 한 글자도 안 건드림** |
| A-4 §6-8 `ping` 블록 | 같은 형태의 Kali 프롬프트 4줄 | 프롬프트 제거, 명령+출력 유지 |
| A-5 §6-7 `ls /usr/share/hashcat/rules/` 블록 | 같은 형태의 Kali 프롬프트 2줄 | 프롬프트 제거 |
| A-6 **상단 요약 · §6-6 · §6-8** | 셋 다 **「XAMPP 가 서비스다」라는 반증된 전제** 위에 서 있었다. 요약: *"쓰기 가능한 **서비스 바이너리**(`httpd.exe`·`mysqld.exe`)까지 도달"*, §6-6: *"`StartName` 을 빼먹은 게 실수. XAMPP 계열에서 제일 먼저 볼 것"*, §6-8: *"여기서는 그게 XAMPP 서비스 계정(`StartName`)이었고, 그걸 빼먹은 대가를 인스턴스 수명으로 치렀다"* | 세 곳 정정. **놓친 XAMPP 서비스라는 것이 존재하지 않는다** — `Get-CimInstance Win32_Service \| ? PathName -like '*xampp*'` 빈 결과, `sc.exe qc mysql` → 1060. §6-6 에 "`StartName` 을 초반에 봤어도 이 박스는 안 풀렸을 것"을 `[가정]` 으로 명시. `StartName` 습관 자체는 좋은 교훈이라 살림 |
| A-7 §4 MySQL 축 | 「XAMPP 니까 MySQL」 추론의 반증이 표 6번의 *"MySQL 도 안 뜸"* 한 조각으로만 있었다 | §4-2-b 신설. ①서비스 없음 ②프로세스·소켓 없음 ③**Monstra 3.0.4 는 플랫파일 CMS 라 DB 자체가 없다** 를 소스 근거와 함께. 일반화 `[!tip]` 추가 |
| A-8 §4-2 배제 표 | 14줄 전부가 동등한 실측인 것처럼 보였다 | **출처 열 추가** + 17줄로 확장. 파일로 되짚히는 줄과 「페인만」(스크롤백 저장 이후, 미보존) 4줄을 구분 |
| A-9 §4-1 `DefaultDomainName` | 관측(두 문자열이 다름)은 사실인데 **"컴퓨터 이름을 바꿨다는 뜻이다"** 라는 해석을 단정으로 적었다 | `[가정]` 강등 + §4-3 미해결 단서 (나) 로 승격 |
| A-10 §5 플래그 블록 · §4 `whoami /all` 블록 | 출처 표기 없음 | `~/PG/Monster/proof_user.txt` 로 명시하고 **그 파일의 내력**을 적음 — 러너가 저장 전 하네스 차단을 받아, `tmux capture-pane -pt mon_lsnr443 -S -3000` 으로 **사후 회수한 66행 스크롤백 덤프**다. mtime(20:50 KST)은 실행 시각이 아니다 |
| A-11 노트 앞부분 | "미해결"임이 요약 콜아웃 안쪽 문장에만 있었다 | 프론트매터 직후에 `[!danger] 이 박스는 root 를 못 잡았다 — 손절한 노트다` 배너 + `[!warning] 적대적 검증 정정 이력` 표 |
| A-12 「남긴 흔적」 44,000건 | 규모는 적혀 있었으나 **그 규모의 의미**가 없었다 | "한 시간 안에 한 IP 에서 같은 엔드포인트로 4만 건의 실패 POST 는 어떤 로그 상관분석에도 걸린다"를 추가. **지우지 않은 것이 규율대로**임을 명시. Windows 이벤트 로그도 목록에 포함 |
| A-13 §0 · §7 · §8 | 이 박스의 실제 교훈이 학습 항목에 반영 안 됨 | §0 에 2줄, §7 에 3항목(실행 주체 확인 / 번들 스택 유추 금지 / 긴 명령은 파일로), §8 에 2줄(`C:\` 루트 설치, 자동 로그온) 추가 |

## B. 삭제한 것

**터미널 출력은 한 줄도 삭제하지 않았다.** 삭제는 아래 둘뿐이고 둘 다 중복 제거다.

**B-1. §4 「XAMPP 자체를 다시 봤다 — 여기가 이 박스의 정답에 가장 가깝다」 절 (동시 편집으로 추가된 것).**
신설한 §4-2-b/§4-2-c 와 같은 내용이었다. **그 절의 터미널 블록 4개(`Get-CimInstance`/`sc.exe qc mysql`, `netstat 3306`/`tasklist`, `icacls mysqld.exe`/`httpd.exe`, `Win32_Process PID 5268 Owner: Mike`)는 전부 §4-2-b·§4-2-c 로 옮겨 살렸다.** 산문 중 아래 한 문장만 `[가정]` 을 달아 옮겼다(원문 인용, 복원 가능):

> **그래서 이 경로의 완성형은 「바이너리 교체 + SYSTEM 컨텍스트의 재시작 유발」이다.** 라이브 박스라면 리부트를 걸거나(autologon 이 mike 라 그래도 mike 지만), PG 박스가 종종 도는 관리자 시뮬레이션/서비스 재시작이 SYSTEM 으로 그 바이너리를 건드리기를 기다리는 식이다.

「PG 박스가 종종 도는 관리자 시뮬레이션」은 이 박스에서 관측된 바 없어 `[가정]` 으로 강등해 옮겼다.

**B-2. §6-4 의 `best64.rule` 장문 서술.**
§6-7 과 중복이라 §6-4 는 한 줄 포인터로 축약. 내용은 §6-7 에 정본으로 남아 있다(오히려 확장됐다).

## C. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

검증 절차 자체의 정확도를 판단할 수 있도록 전부 적는다.

1. **§4 `icacls` 블록** (SAM/vssadmin/vmtoolsd/xampp ACL) — `try5_sam_acl_shadow.log` 와 **바이트 단위 일치.** 명령 줄바꿈 위치까지 같다.
2. **§4 `whoami /all` 블록** — `proof_user.txt` 와 완전 일치. 컬럼 정렬·빈 줄 개수까지 같다.
3. **§5 플래그 증거 블록** — `proof_user.txt` 와 완전 일치. `Thu 08/20/2026` / `04:40 AM` / `192.168.248.180` / `mike-pc\mike` / `Mike-PC` 가 한 화면. **대화형 PowerShell 리버스셸이고 웹셸이 아니다.** 프롬프트 `PS C:\xampp\htdocs\blog\public\themes\default>` 도 실측이라 유지.
4. **§3 hydra 출력 블록** — `hydra_cewl_run.txt` 와 일치(`29158 login tries (l:2/p:14579)`, STATUS 3줄, 히트 줄). 노트가 출처를 `capture-pane` 으로 적었는데 파일도 있어 **출처만 보강**했다.
5. **§2 사전 숫자** — `words.txt` 253줄, `words_b66.txt` 14,579줄, `words_b64.txt` **0줄**. 전부 정확.
6. **§2 "정답 `wazowski` 가 사이트 사전에 있었다"** — `cewl.txt:22 Wazowski`, `cewl.txt:38 wazowski`, `cewl_blog.txt:97`. 사실.
7. **§2 "10k 사전 20,000 시도"** — `10k-most-common.txt` 가 정확히 10,000줄, 사용자 2명. 사실.
8. **§4 표 1·2·3·4·6·7·8·9·10·12** — `try3`·`try4`·`try6`·스크롤백과 대조해 전부 확인.
9. **「남긴 흔적」 삭제 전후 `dir` 블록** — `traces_confirmed.log` 와 일치.
10. **스크린샷 3장** — 볼트 `파일보관\` 의 파일 크기가 Kali `shot_*.png` 와 정확히 일치(21594 / 112507 / 524680). `PG-Monster-80-blog.png` 를 직접 열어 푸터 `Powered by Monstra 3.0.4` 와 `Users`·`Registration` 메뉴를 확인 — 본문 주장과 일치.
11. **프론트매터** — `tech/enum/dirbust`·`tech/enum/searchsploit`·`tech/cred/crack`·`tech/payload/revshell` 4개 전부 볼트 실재 leaf(각각 15·13·11·40개 노트에서 사용 중). `os/windows` 있음, `status: partial` + `manual_status: true` 로 부분 완료 표시 정확, `manual_tags`/`manual_cves` 선언 뒤 주석 없음. `cves:` 키 부재는 의도대로 — `extract.py:356` 은 선언된 `cves` 가 없으면 키를 안 만든다. 실제 악용한 CVE 가 없으니 맞다.
12. **`admin`/`proof` 플래그 날조 없음** — 32자 hex 는 `db85d2fa7033db43da92bb07dde4da5b` 하나뿐이고 user 플래그다. proof 는 세 곳 모두 「미확보」.
13. **49152↑ 고포트 색인 제외** — 정상 동작. 버그 아님.

## D. 근거 출처

**Kali 산출물** (`ssh kali@10.44.44.128`, `~/PG/Monster/`)
`nmap.log` · `gobuster80.log` · `cewl.txt` · `cewl_blog.txt` · `words.txt` · `words_b64.txt`(0바이트) · `words_b66.txt` · `users.txt` · `hydra_10k.log` · `hydra_cewl.log` · `hydra_cewl_run.txt` · `writeup_notes.txt` · `traces_confirmed.log` · `proof_user.txt` · `try1_winlogon.log` · `try1b_winlogon_filtered.log` · `try2_spray_admin.log` · `try3_services_tasks.log` · `try4_alwaysinstallelevated_xampppw.log` · `try5_sam_acl_shadow.log` · `try6_autostart.log` · `try_privesc_full_scrollback.log` · `send.sh` · `cmd.txt` · `hosts.before_revert`

**1차 사료** — 클론된 Monstra 3.0.4 소스 `~/PG/Monster/monstra-src/`
- `engine/boot/defines.php:91` — `//define('MONSTRA_DB_DSN', 'mysql:dbname=monstra;host=localhost;port=3306');` **주석 상태로 출하**
- `engine/Monstra.php:181` — `if (defined('MONSTRA_DB_DSN'))` 로 Idiorm 초기화가 게이팅됨. 주석이면 블록에 들어가지 않는다
- `engine/Monstra.php:34` — `const VERSION = '3.0.4'`
- `storage/database/` — `users.table.xml`·`pages.table.xml`·`options.table.xml`·`plugins.table.xml`·`menu.table.xml` (XML 플랫파일)
- `README.md` System Requirements — PHP 5.3.2+ / SimpleXML / mbstring. **데이터베이스 항목 없음**

**직접 실행한 명령 (Kali)**
```
hashcat --version                                   → v7.1.2
ls /usr/share/hashcat/rules/ | grep -i best         → best66.rule (best64.rule 부재)
hashcat --stdout -r .../best64.rule w1.txt > o 2> e → exit 255, stdout 0줄,
                                                       stderr "best64.rule: No such file or directory"
wc -l /usr/share/seclists/.../10k-most-common.txt   → 10000
grep -c "notepad.exe" try_privesc_full_scrollback.log → 23
grep -n "tasklist" try_privesc_full_scrollback.log  → 무매치
grep -i monster ~/.zsh_history                      → 무매치 (전 작업이 비대화형 ssh / 리버스셸 안)
```

**볼트** — `파일보관\PG-Monster-80-{index,blog,admin-login}.png` (blog 는 직접 열어 확인)

## E. 관측 없음 / 근거부족으로 남긴 것

- §4-2 표 5·11·13·14 번의 출력, MySQL 반증 ①②의 출력, `mysqld.exe` 바이트 수, `icacls C:\xampp\...\httpd.exe`·PID 5268 Owner, `w.tmp` 사후 확인 — **전부 `try_privesc_full_scrollback.log` 저장(21:00 KST) 이후에 페인에서 나온 것**이고 페인은 손절 때 종료됐다. 스크롤백 자체가 `===CREDFILES===`/`===HOTFIX===` 명령이 발사된 지점에서 정확히 끊긴다(파일 마지막 3줄). **부재 증거이므로 날조로 판정하지 않았고**, 노트에 「페인만」으로 표기해 남겼다.
- 「세션 0」 판독 — 위와 같은 이유. `[가정]`.
- `DefaultDomainName` 의 개명 해석 — 검증할 산출물 없음. `[가정]`.

## F. 하지 않은 것

- `refresh.ps1` **미실행**(지시대로). `_STATUS.md`·포털·브라우저·박스·tmux·`harvest.sh` 미접촉.
- `~/PG` 전수 스캔·홈 grep·`find /` **미실시**. 고정 출처 목록 안에서만 확인했다.
- Kali 에서 파일을 쓰거나 지우지 않았다(`/tmp` 테스트 파일 3개는 즉시 삭제).

---

# 2차 패스 — 라인 관리자 정정 반영 (같은 날)

백업 `03. PG\_backup\Monster.md.bak-audit2-20260820` · 993 → 1020행

## G. 내가 틀렸던 것 — 사실과 결론을 붙여 버렸다

1차 패스에서 나는 `C:\xampp` ACL 을 **배제 표 17번**에 "트리거 없음"으로 올렸다. 근거였던 사실은 지금도 옳다 —
`Get-CimInstance Win32_Service | ? PathName -like '*xampp*'` 빈 결과, `sc.exe qc mysql` → `OpenService FAILED 1060`,
Apache PID 5268 소유자 `Mike`, Startup `xampp-control - Shortcut.lnk`.

**틀린 것은 거기서 끌어낸 결론이다.** 「XAMPP 가 서비스가 아니다」에서 「그러므로 쓰기 권한이 **무의미하다**」로 한 걸음 더 갔는데,
`httpd.exe`·`mysqld.exe` 가 `Authenticated Users:(M)` 인 이상 **mike 는 실제로 그것을 덮어쓸 수 있다.**
빠진 것은 권한이 아니라 **트리거 한 조각**이고, 그건 「배제」가 아니라 「미완」이다.
Fundamental 난이도에서 이만큼 눈에 띄는 오설정이라면 오히려 **의도된 취약점 쪽**으로 읽는 것이 맞다.

교훈으로 적어둔다: **관측을 반증하는 것과 결론을 반증하는 것은 다른 작업이다.** 관측이 맞다고 결론이 따라오지 않는다.

## H. 2차 패스에서 고친 것

| 위치 | 무엇을 | 어떻게 |
|---|---|---|
| H-1 §4-2 배제 표 | XAMPP 바이너리 쓰기 줄(17번) 제거 | **17줄 → 16줄.** 표 바로 아래에 `[!danger]` 로 "이건 배제가 아니라 미완, §4-4 로 옮겼다"를 남겨 **다음 사람이 표를 완결로 오독하지 않게** 함 |
| H-2 **§4-4 신설** — 「미완 — 가장 유력한 리드 (다시 붙는다면 여기부터)」 | 없던 절 | ① `icacls` 실측 **원문 2블록 그대로**(`httpd.exe`·`mysqld.exe`, `Authenticated Users:(I)(M)`) ② PID 5268 Owner `Mike` 블록 + `AutoAdminLogon=1`·`AutoLogonSID -1002`·`INTERACTIVE`/`CONSOLE LOGON`·Startup `.lnk` 수렴 ③ **남은 질문 한 줄**로 격리: 「무엇이 이 바이너리를 SYSTEM 으로 재실행할 수 있는가」 ④ 미확인 후보 4개(Session 0 notepad 23개 / Administrator 주기 로그온 / `RunOnce`·`Userinit`·`Shell` / `xampp-control.exe` UAC 매니페스트) ⑤ 절차 주의 — `httpd.exe` 를 덮으면 **자기 발판(`.chunk.php` RCE)이 죽는다**, `mysqld.exe` 는 아무도 실행하지 않으니 교체해도 무의미 → **트리거를 먼저 찾고 대상을 고르는 순서** |
| H-3 Session 0 연결 | 1차에서 `[가정]` 강등해 둔 것과 모순되지 않게 | §4-4 안에서 **연결 자체를 `[가정]`** 으로 명시하고, 확정된 것은 「`GetOwner()` 거부 = mike 소유 아님」까지임을 다시 못박음. 세션 번호·기동 주체·주기성 **전부 미확인**으로 표기 |
| H-4 §4-3 제목·도입 | "여기가 다음 시도의 출발점이다" — 이제 출발점은 §4-4 다 | 「설명이 안 된 관측 둘」로 변경. §4-4 의 빠진 조각이 여기 있을 수 있다는 연결만 남김 |
| H-5 §4-2-d → §4-2-c | ACL 절이 빠지며 생긴 번호 구멍 | 재번호. 본문 상호참조 4곳 동기화 |
| H-6 §6-8 제목·도입 | "박스가 열거 도중 내려갔다 — 인스턴스 수명" 이 **「시도해서 실패」로 읽혔다** | 「**실패가 아니라 중단이다**」로. **경위 명시** — 다른 박스(Flimsy) 기동에 따른 **포털 동시 1대 슬롯 규칙**으로 인스턴스 정지·리버트. **기술적 실패도 조작 실수도 아니고 운영 결정이다.** `pkill` 미사용도 명시. "「시도해서 실패했다」와 「시도 중에 끊겼다」는 다음 사람에게 전혀 다른 정보"를 본문에 박음 |
| H-7 `harvest.ps1` | 언급 없음 | §6-8 에 추가 — `~/PG/_lib/harvest.ps1`(4,082바이트), `StartName` 포함이 이번 교훈 반영. **전송·MD5 일치·실행 개시까지만 확인, 완주와 출력 회수는 미검증**임을 명시 |
| H-8 상단 배너 · 요약 · §6-6 | "17종 전부 빈손"·"쓰기 권한은 성립하지 않는다" | 「16종 배제 + 1건 미완」 구조로 통일. 배너에서 **§4-4 부터 시작하라**고 지시. 스테일 참조 4곳(17종/17줄/§4-2-d) 전부 제거 |
| H-9 §4 도입 | — | "「아니었다」와 「못 갔다」를 섞지 않는 것이 이 절의 규율" + **"§4-4 를 배제로 읽고 건너뛰면 정답을 지나친다"** 추가 |
| H-10 정정 이력 콜아웃 | — | **감사자 본인의 오분류**를 항목으로 추가. 라인 관리자 지시가 틀렸다가 총괄이 정정한 경위도 이력에 남도록 사실 관계로 기술 |

## I. 2차 패스에서 지키 것

- **터미널 실측 블록 무삭제.** `icacls` 출력 2블록과 PID 5268 `GetOwner()` 블록은 §4-2-c 에서 §4-4 로 **한 글자도 안 바꾸고 이동**했다.
- **타겟 프롬프트(`PS C:\...>`) 전량 유지.** Kali 프롬프트는 1차에서 처리한 8줄이 전부이고 2차에서 추가 제거 없음.
- `_STATUS.md`·`refresh.ps1`·포털·박스·tmux 미접촉. 다른 노트(특히 `Flimsy`) 미개봉.

## J. 남은 판단 — 관리자용

§4-4 의 미확인 후보 4개는 **전부 이 노트의 추론이고 실측이 아니다.** 박스가 리버트됐으므로 검증하려면 재기동이 필요하다.
노트에는 「미확인」으로 표기해 뒀으니 **다음에 이 박스를 켤 때 그 4개를 순서대로 때리는 것이 가장 짧은 경로**로 보인다.
