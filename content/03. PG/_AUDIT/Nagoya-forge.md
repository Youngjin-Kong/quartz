# Nagoya — 개작 감사 기록

작업일 2026-08-20 · 대상 `03. PG\Nagoya.md` (728행 44.8KB → 950행) · 백업 `Nagoya.md.bak`

## 1. 판정: `_STATUS.md` 의 "미착수 0/2" 는 **오류**

정확한 판정은 **완료 1/2 (proof.txt 확보, local.txt 무기록)**.

| 증거 | 내용 |
|---|---|
| `파일보관/Pasted image 20260707105621.png` | `C:\Users\Administrator\Desktop>type proof.txt` → `be83df05d75cfee867192bdf8dcd2fdb` |
| `파일보관/Pasted image 20260707105454.png` | 같은 셸의 `whoami` = `nagoya-ind\nagoya$`, `nc -lnvp 9001` 대화형 셸 (웹셸 아님 → 시험 기준 유효) |
| `~/PG/Nagoya/Administrator.ccache` (07-07 10:39:08) | `klist` 로 검증: principal `Administrator@NAGOYA-INDUSTRIES.COM`, service `MSSQL/nagoya.nagoya-industries.com`, 만료 2036-07-04 → **위조 실버티켓** |

`local.txt` — `~/PG/Nagoya/` 산출물, `~/.zsh_history`, 볼트 스크린샷 28장 전수 확인. **어디에도 없다.** 스크린샷의 `dir` 도 Administrator 데스크톱만 보여준다. christopher.lewis WinRM 셸이 있었으므로 손이 닿는 거리였으나 실제로 읽은 기록이 없어 노트에 "기록에 없다 + `[가정]` 표준 위치"로 명시.

## 2. 복원한 경로 (전체)

웹 `/Team` 실명 28 → username-anarchy 405 → kerbrute 26 → 푸터 `© 2023` 근거 계절 스프레이 → `craig.carr:Spring2023` (+ `fiona.clark:Summer2023`) → BloodHound → ACL 2홉 → `christopher.lewis` WinRM → Kerberoast `svc_mssql:Service1` → **1433 방화벽 차단** → ligolo-ng 터널 → 실버티켓 위조 → mssqlclient `-k` → `xp_cmdshell`(= svc_mssql) → `SeImpersonate` → PrintSpoofer → `nagoya$` → proof.txt

### BloodHound JSON 에서 새로 복원한 것 (원본 노트에 없던 부분)

원본은 "bloodhound 확인 후 christopher.lewis 획득으로 전환" 한 줄이었다. `20260706153247_{users,groups}.json` 을 파싱해 실제 사슬을 확정:

| 홉 | 주체 | 권한 | 대상 |
|---|---|---|---|
| 1 | `craig.carr` ∈ EMPLOYEES | GenericAll | `iain.white` |
| 2 | `iain.white` ∈ HELPDESK | GenericAll | `christopher.lewis` |
| 3 | `christopher.lewis` ∈ DEVELOPERS | — | DEVELOPERS 가 **Remote Management Users 의 유일 멤버** |

**왜 christopher.lewis 였는가**가 이걸로 설명된다 — DEVELOPERS 멤버 5명 중 EMPLOYEES/HELPDESK 가 통제 가능한 계정이 그 하나뿐이다. 원본 노트에는 이 이유가 없었다.

부수 확인: `Domain Controllers` 그룹이 도메인 객체에 `GetChangesAll` 보유 → `nagoya$` = DCSync 가능 = DA 등가. 4-5절 콜아웃의 근거.

## 3. 반증한 것

### 3-1. 기존 기록이 틀렸던 것

1. **`_STATUS.md` 의 `Nagoya 0/2 미착수`** — 위 1절. 실제로는 proof.txt 확보 완료.
2. **frontmatter 의 `status: unsolved`** → `solved` 로 정정.
3. **frontmatter 태그 6개가 오탐** — `tech/ad/asreproast`(GetNPUsers 는 돌렸으나 전멸, 성공 경로 아님) · `tech/ad/dcsync`(secretsdump 실행 기록 없음) · `tech/web/lfi-rfi`(**전혀 무관**) · `tech/svc/smb`(nxc 열거만) · `tech/pivot/ssh-tunnel`(`ssh -L 13389` 시도 후 중단) · `tech/cred/spray` 는 누락돼 있었다. `manual_tags: true` 선언 자체가 없어 자동 판정이 돌고 있었다. 실제 사용 13개로 재큐레이션 + 선언 추가.
4. **원본의 "3389를 시도했지만 로그인 불가"** — 같은 노트에 붙여둔 `nxc-sweep` 출력이 `RDP 192.168.120.21 3389 NAGOYA [+] nagoya-industries.com\svc_mssql:Service1` 로 **자격증명 유효**를 말한다. 내부 모순이다. xfreerdp 출력은 산출물·히스토리·스크린샷 어디에도 없으므로 실패 원인을 단정할 수 없다 → "원인은 기록에 없다"로 강등해 6-5절에 기록.

### 3-2. 내 초고가 틀렸던 것

1. **초고에 "PrintSpoofer 로 SYSTEM 획득"이라고 썼다.** 스크린샷을 열어보니 `whoami` 가 `nt authority\system` 이 아니라 **`nagoya-ind\nagoya$`** 였다. 메커니즘을 그럴듯하게 설명하려다 멈추고, 관측만 적고 원인은 `[가정]` 으로 강등했다. 대신 BloodHound 로 확인 가능한 사실(`Domain Controllers` → `GetChangesAll`)로 "그래서 충분했다"를 지지했다.
2. **초고에 "kerbrute 로 26개를 확정한 뒤 곧바로 스프레이"라고 시간순으로 썼다.** mtime 을 보니 `season_pass.txt`(14:55:04)가 웹 푸터 스크린샷(14:56:21)보다 **먼저** 만들어졌다. 붙여넣기 시각 ≠ 캡처 시각이라는 유보를 3-3절 콜아웃에 명시했다.
3. **초고에 "ferox 3회 = 약 10분 낭비"를 단정.** state 파일을 파싱해 보니 앞의 두 개는 응답 12개에서 중단, 세 번째만 913개 완주였다. "세 번 다 돌렸다"가 아니라 "두 번 중단하고 세 번째만 완주"가 맞다. 그리고 완주분에서도 신규 경로는 0 — 이쪽이 더 나은 교훈이라 그대로 6-1절에 썼다.
4. **초고에 "히스토리 순서상 ccache 생성 전에 `-k` 를 쳤다"고 단정하려 했다.** `~/.zshrc` 를 확인하니 `hist_ignore_dups` 가 켜져 있고 `EXTENDED_HISTORY` 는 없어 타임스탬프가 없다. 세션 종료 시 append 라 순서를 단정할 수 없다 → "이 줄을 두 번 쳤다"는 사실만 남기고 순서 단정을 뺐다(6-7절).
5. **07-06 오전 스크린샷 4장(09:16 · 10:48 · 10:49 · 10:50)을 Nagoya 것으로 셀 뻔했다.** 열어보니 `impacket-rbcd -delegate-from '4Leaf$' -delegate-to 'RESOURCEDC$' … 192.168.120.175 resourced.local` — **Resourced 박스**다. 제외했다. 총괄이 준 "07-06 9장" 중 실제 Nagoya 는 5장.

## 4. 실행해서 확인한 단정

노트에 새로 써넣은 단정 중 실측으로 뒷받침한 것:

- `python3 -c 'hashlib.new("md4","Service1".encode("utf-16le"))'` → `e3a0168bc21cfb88b95c954a5b18f57c` — 노트에 적힌 값과 일치(Kali 에서 직접 실행).
- `KRB5CCNAME=./Administrator.ccache klist` — 티켓 principal/SPN/만료 직접 확인.
- hashcat potfile(`~/.local/share/hashcat/hashcat.potfile`)에 `…$svc_mssql$NAGOYA-INDUSTRIES.COM$…:Service1` 존재 확인. `svc_helpdesk` 는 **없다** → "1/2 크랙"이 사실.
- ferox state JSON 파싱 → 200 응답 경로 12종 전수. `/Nagoya.styles.css`(ASP.NET Core CSS isolation) + 확장자 없는 라우트 = 프레임워크 판정 근거 2개.
- `/etc/hosts` 에 `240.0.0.1 nagoya.nagoya-industries.com` 실재 확인 → "SPN 호스트명으로 붙어야 한다" 서술의 근거.
- `agent.exe` = ligolo-ng 에이전트 (PE32+, `github.com/nicocha30/ligolo-ng` 문자열, 스크린샷상 v0.8.2).

확인하지 못해 **쓰지 않은 것**: xfreerdp 실패 원인, PrintSpoofer 가 SYSTEM 대신 머신 계정을 준 이유, `local.txt` 위치.

## 5. 총괄 판단이 필요한 것

- **`_STATUS.md`** — `- [ ] Nagoya 0/2 ← 노트O` (317행) 을 완료 1/2 로. 이 에이전트는 지시대로 건드리지 않았다.
- **태그 taxonomy** — 실버티켓/골든티켓은 `extract.py:63` 의 `tech/ad/ticket-forge` 로 커버되어 그것을 썼다. 다만 `tech/ad/userenum`(kerbrute 류 계정 열거)에 해당하는 태그가 taxonomy 에 없다. 공유 인프라라 손대지 않고 보고만 한다.
