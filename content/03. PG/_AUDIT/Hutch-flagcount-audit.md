# Hutch — 플래그 개수 판정 재검증 (2026-08-20, 2차 감사)

**최종 판정: 부분 완료 · `1/2`** — `proof.txt` 만 확보. `local.txt` 미확보.

---

## 1. 판정 근거

### 1-1. 확보한 플래그 (실측)

| 플래그 | 값 | 근거 |
|---|---|---|
| `proof.txt` | `14fb84ee9468eda117d59d5c6d378774` | `파일보관\Pasted image 20260515145246.png` — evil-winrm 대화형 PowerShell 에서 `type proof.txt` → 값, 이어서 `ipconfig` → `192.168.216.122`. **노트 1109~1131행 인용과 한 글자도 다르지 않다.** OSCP 증거 형식(대화형 셸 + 값 + IP 한 화면) 충족 |

### 1-2. `local.txt` — 미확보로 확정 (부재 증거를 소진했다)

`local.txt` 값이 존재한 흔적을 아래 전부에서 찾지 못했다:

1. `~/PG/Hutch/` **전체** — 11개 파일뿐. nmap.log · users.txt · kerbrute_linux_386 · BloodHound JSON 7종. 플래그 파일 없음
2. **홈 디렉터리 mtime 스윕** — `find /home/kali -maxdepth 6 -newermt '2026-05-14 00:00' ! -newermt '2026-05-16 00:00'`.
   Hutch 관련 산출물은 위 11개가 전부. 나머지는 VPN 파일·브라우저 캐시·BloodHound 설치 흔적
3. **볼트 `파일보관\` 2026-05-14~15 스크린샷 6장 전부 직접 열람** (05-14 자 스크린샷은 **0장**). `local.txt` 를 보여주는 장면 없음. **6장 모두 §6-6 표에 이미 등재돼 있다 — 노트가 누락한 장면은 없었다**
4. `~/.zsh_history` (2552행) — `hutch|pyLAPS|216.122|178.122|fmcsorley|CrabShark` **전부 0건**. 노트의 "히스토리에서 밀려났다"는 서술이 사실로 확인됨
5. `~/.bash_history` — 0건
6. **Kali 측 Claude 세션 기록** `~/.claude/projects/-home-kali/f97513be-….jsonl` (2026-05-15 13:42~15:26, 1.0MB) — 공격 종반 시간대를 포함하는데도 `proof.txt` **0건**, `14fb84…` **0건**, `local.txt` 는 evil-winrm 치트시트 템플릿 2건뿐(실제 시도 아님). **이 세션은 BloodHound 설치·툴체인 정비용이었고 익스플로잇은 여기서 돌지 않았다**

7. **양성 대조군(positive control) — 이번 감사에서 가장 강한 증거**
   ```
   grep -rln 'local\.txt' /home/kali/PG      # 188M, 47개 박스
   ```
   → **14개 파일에서 hit.** ClamAV `shell_session.log` · Cockpit `ferox.txt` · **Flu `flag_evidence.txt`·`writeup_notes.txt`·`privesc_session.log`** · Hawat `probe.py` · Pebbles `pebbles_pwn.sh` · Algernon `shell_session.log` · Bratarina `verify_shell.log` · **Wombo `flags.txt`·`writeup_notes.txt`** 등.
   **`/home/kali/PG/Hutch/` 에서는 0건.**

   즉 이 작업자는 **다른 박스에서는 `local.txt` 값을 Kali 산출물(`flags.txt`·`flag_evidence.txt`·`writeup_notes.txt`·세션 로그)에 습관적으로 남겼다.** Hutch 에는 그런 파일이 **아예 하나도 없다** — `writeup_notes.txt` 도, `flags.txt` 도, 세션 로그도 없다. `proof.txt` 를 얻은 직후 박스를 놓았다는 서사와 정확히 일치한다.

> [!warning] 이 대조군을 과대해석하지 않기 위해 함께 적는다
> **같은 grep 에서 `proof.txt` 값 `14fb84…` 도 `~/PG` 전체에 0건이었다.** 그런데 `proof.txt` 는 **확실히 확보한 플래그**다(스크린샷). 즉 **"플래그 값이 `~/PG` 에 없다"는 그 자체로는 미확보의 증거가 되지 못한다** — Hutch 의 종반부는 처음부터 스크린샷에만 남았다.
> 대조군이 말해주는 것은 «값의 부재»가 아니라 **«산출물 파일 자체의 부재»** 다. 그리고 최종 판정을 떠받치는 것은 어디까지나 **포털 `0/2` 라는 양성 증거**이지 부재 증거가 아니다.

> 부재 증거만이라면 등급 상한이 `근거부족`이다. 그러나 **포털 실측 `0/2`(총괄, 2026-08-20)** 라는 양성 증거가 별도로 있고, 노트 본문이 스스로 `C:\Users\Administrator\Desktop` 목록에 `proof.txt` 하나뿐임을 기록하고 있다. 둘을 합치면 **`1/2` 로 확정**된다.

---

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| 상단 요약 `**플래그 1개**(§5의 [가정] 참조)` | 포털 `0/2` 로 반증 | `**플래그 2개 중 1개 확보** — proof.txt 만 얻었고 local.txt 는 놓쳤다 (§5 · §6-9)` |
| §5 `[!warning] local.txt 는 확보하지 못했다 — 이 박스가 단일 플래그인가?` 콜아웃 | `[가정]` 1플래그 판정이 반증됨 | `[!danger] local.txt 를 놓쳤다 — 이 박스는 2플래그다` 로 교체. 포털 실측 명시, 재도전 명령 2줄 제시. **위치 추정은 `[가정]` 으로 유지** |
| §5 재도전 지침 `nxc winrm <IP> -u fmcsorley …로 그 계정의 WinRM 가능 여부부터 본다` | **잘못된 조언.** fmcsorley 는 WinRM·RDP 불가 | 새 `[!warning]` 콜아웃 추가 — BloodHound `computers.json` 의 `PSRemoteUsers`/`RemoteDesktopUsers` 가 `Collected:true` 에 **멤버 0**, `groups.json` 의 `REMOTE MANAGEMENT USERS` 도 **0**. 올바른 조치는 **이미 가진 Administrator 세션에서 남의 프로필을 읽는 것** |
| §6-9 제목 `fmcsorley 로는 셸을 시도조차 하지 않았다 — local.txt 미확보와 직결된다` | **잘못된 인과.** 그 셸은 시도해도 열리지 않았다 | `local.txt 를 놓친 진짜 원인 — C:\Users 를 나열하지 않았다` 로 교체. 틀린 진단/맞는 진단을 나란히 제시하고, "플래그 개수를 내가 본 디렉터리로 추론하지 마라" 일반화 추가 |
| §6-9 표 1행 `Remote Management Users 멤버면 그 자리에서 대화형 셸이다` | 이 도메인에서는 성립하지 않음 | "결과적으로 실패했을 시도지만 5초에 배제되는 것이 값이다" 로 강등. Resourced 대조는 유지 |
| §6-9 `[!danger] 이 누락이 §5의 local.txt 불확실성을 만들었다` | 전제가 바뀜 | `그렇다면 의도된 저권한 셸은 어디였나` 로 교체 — 80/tcp WebDAV 를 남은 유일 후보로 `[가정]` 표기. 웹셸 플래그 0점 경고 병기 |
| §6-4 `[!note] 결과적으로는 옳은 판단이었지만` | 평가가 뒤집힘 | 앞에 `[!danger] 2026-08-20 재검증으로 이 절의 평가가 뒤집혔다` 추가. 80번 미탐색이 «플래그 하나를 잃은 지점일 수 있다» — `[가정]` 명시 |
| 상단 규약 콜아웃 `원본 노트에만 있는 출력(대조 원본 없음): … pyLAPS · secretsdump · evil-winrm 세션` | **내부 모순.** 그 셋은 전부 스크린샷으로 실증된다 (노트가 그 스크린샷을 §4·§5에 임베드해 놓고도 «대조 원본 없음» 이라 적었다) | 「볼트 스크린샷으로 실증됨」 항목을 신설해 이관. 남은 미대조는 `kerbrute`·`GetNPUsers`·`nxc` 스프레이·`smbmap`·§5 의 `dir` 목록(스크린샷은 `type` 부터 시작) |
| §6-7 재현 최소 경로 | 플래그 한 개만 회수 | `# 5) 플래그 «둘 다»` 블록 추가 (`Get-ChildItem C:\Users` → `local.txt` → `proof.txt`). **주석 처리해 실행 기록으로 오인되지 않게 했다** |
| §7-3 시간 배분 표 | `local.txt` 구간 없음 | `local.txt 회수 / 하지 않음 — 박스를 여기서 놓았다 / +3분` 행 추가 |
| 노트 상단 | 정정 이력 부재 | `[!warning] 적대적 검증 정정 이력 — 2026-08-20 (2차)` 콜아웃 신설. 반증된 원문 4건을 **전문 인용**해 되살릴 수 있게 남김 |

## 3. 삭제한 것

**없다.** 반증된 서술은 전부 정정 이력 콜아웃에 원문 인용으로 보존했다. 특히 반증된 `[가정]` 원문:

> "**[가정]** PG의 단일 DC 박스는 **사용자 프로필이 실질적으로 Administrator 하나뿐**이라 `proof.txt` 만 두는 경우가 있으므로, 이 박스를 **1플래그 박스로 판단**한다."

## 4. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **"local.txt 를 실제로 읽은 흔적이 어딘가 있어 2/2 일 수 있다"** (총괄이 먼저 배제하라고 지시한 가능성) → **없었다.** 위 1-2 의 6개 경로를 전부 소진. 노트가 "확보하지 못했다"고 적은 것이 정확했다
2. **"§6 스크린샷 표에 등재되지 않은 그날 스크린샷이 있을 수 있다"** → **없었다.** 2026-05-14~15 자 스크린샷은 정확히 6장이고 **6장 모두 §6-6 표에 등재**돼 있다. 05-14 자는 0장
3. **노트의 "`~/.zsh_history` 에 Hutch 구간이 남아 있지 않다"** → **사실 확인.** 6개 키워드 전부 0건
4. **`proof.txt` 값·LAPS 평문·타겟 IP·secretsdump 해시** → 스크린샷과 **전부 일치.** 개작 1차 감사의 "원본의 관측은 훼손되지 않았다"는 결론이 재확인됨

## 5. 새로 얻은 실측 (BloodHound 덤프 재분석, 2026-08-20)

```
computers.json  HUTCHDC.HUTCH.OFFSEC
  LocalAdmins         Collected=True  n=3  (RID 500 / 519 Enterprise Admins / 512 Domain Admins)
  PSRemoteUsers       Collected=True  n=0
  RemoteDesktopUsers  Collected=True  n=0
  DcomUsers           Collected=True  n=0
  haslaps             True
groups.json     REMOTE MANAGEMENT USERS@HUTCH.OFFSEC  멤버 0
users.json      ADMINISTRATOR  pwdlastset 2026-05-15   ← LAPS 가 회전시킨 흔적. §2-4 의 해시 대조와 정합
                FMCSORLEY      lastlogon  2026-05-15   ← 우리 자신의 인증. 프로필 존재의 증거는 아니다
```

`fmcsorley` 가 WinRM·RDP·DCOM 어디에도 없다는 것이 이번 감사의 핵심 신규 사실이다.

## 6. 근거 출처

- **Kali 산출물**: `~/PG/Hutch/` 전체 · `~/.zsh_history` · `~/.bash_history` · `~/.claude/projects/-home-kali/f97513be-1957-4b16-836f-08d50132ade7.jsonl`
- **볼트**: `파일보관\Pasted image 2026051510525 0/142817/143503/144914/145041/145246.png` 6장 전부 직접 열람
- **git**: `03. PG/Hutch.md` 커밋 3개(`15671e5` 원본 → `607fbc5` 프론트매터 → `aba5a29` 개작). 개작 커밋에서 신규 생성된 노트가 아니므로 baseline 존재
- **포털 실측**: 총괄, 2026-08-20 전수 조회 — Hutch `0/2`
- **직접 실행**: `find … -newermt` mtime 스윕, `jq`/`python3` BloodHound JSON 파싱, `grep` 히스토리 검색

## 7. 총괄에 올릴 사항

- **프론트매터 `status: solved` / `status/solved` 를 바꾸지 않았다** (지시대로). 실제 상태는 **부분 완료 `1/2`** 다. taxonomy 에 부분 완료를 표현할 값(`status/partial` 등)이 없다 — **283개 노트에 걸린 공유 인프라라 단독 변경하지 않았다.**
- **`_STATUS.md` 를 건드리지 않았다.** 현재 완료 `1/1` 로 기록돼 있고 **`부분 1/2` 로 옮겨야 한다.** 라인 관리자 소관
- **`refresh.ps1` 을 돌리지 않았다.** 이번 수정은 `tech/*`·CVE·포트·서비스·IP 를 하나도 바꾸지 않았고(`manual_tags: true`·`manual_cves: true` 둘 다 이미 선언돼 있다), 색인 갱신은 335개 노트의 프론트매터를 일괄 재작성하므로 **동시 편집 중일 수 있는 시점에 단독 실행하지 않는 쪽을 택했다.**
