---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# Vault — 적대적 검증 + 정정

대상 `03. PG\Vault.md` · 개작 직후 1093행 → 감사 후 **1089행**
비교 기준 — 개작 직전판 `git show HEAD:"03. PG/Vault.md"`(1229행) · 최초판 `git show 15671e5:…`(516행) · 백업 `03. PG\_backup\Vault.md.bak`(1229행)

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `┌──(kali㉿kali)` 8블록 — `python3 - <<'EOF'` · `hashcat -hh \| grep …` · `grep -i '^ANIRUDH' …potfile` · `jq` 5개 | **개작 중 에이전트가 붙인 창작 프롬프트.** 최초판(15671e5)에 없고 `~/.zsh_history` 에도 없음. 비대화형 `ssh kali "…"` 로 돌린 명령에 대화형 세션 겉모습을 입힌 것 (CLAUDE.md §3) | **프롬프트 두 줄만 제거.** 명령·출력은 한 바이트도 안 건드림. `└─$ ` 접두만 벗김 |
| 위 8블록 중 4곳 | 출처 캡션 없음 | `— 출처: ~/PG/Vault/20260708124927_groups.json` · `…_gpos.json` · `— 출처: ~/.local/share/hashcat/hashcat.potfile` · `— 입력: ~/PG/Vault/hash.txt · 위 디코드는 노트 작성 시점의 재분석임` 추가 |
| `⚠️ 실제로 통과한 문자열은 --AddlocalAdmin … 확인하지 않았음(관측 없음)` | 유보가 과했음. 1차 사료로 확인 가능한 사실이었음 | 상류 README(`~/git/SharpGPOAbuse/SharpGPOAbuse-master/README.md:29,60`)가 `--AddLocalAdmin` 로 표기하는데 `--AddlocalAdmin` 으로 실행이 성공했으므로 **이 인자에 한해 파서가 대소문자 차이를 허용함**으로 격상. 「문서상 정식 표기는 `--AddLocalAdmin`」 명시 |
| 규약 콜아웃 `⚠️ 이전 판이 「SeRestore 경로도 미실행」이라고 적었던 것은 반증됨 …` | **정정 이력이 노트 본문에 남아 있었음**(CLAUDE.md §4 위반 — 공개 발행물의 첫 화면이 「무엇이 틀렸었나」가 되면 안 됨) | 「이전 판」 참조를 걷고 **양성 서술**로 바꿈 — `**완주 확인** — SeRestorePrivilege → utilman 치환 → RDP 경로(경로 B)는 끝까지 실행됨. 근거는 …134045.png` |
| jq 연속행 들여쓰기 11칸 | 프롬프트 제거로 정렬이 어긋남 | 7칸으로 축소(따옴표 안 jq 프로그램의 공백이라 동작 무관) |
| `_AUDIT\Vault-playbook.md` 의 `(1229행 → 1084행)` · `1229 → 1084 로 145행만` | 실제 행수와 불일치(작성자 스냅샷 1093, 감사 후 1089) | `1089` · `140행` 으로 정정 |

## 2. 삭제한 것

**본문 삭제 0행.** 제거한 것은 창작 프롬프트 16줄(8블록 × 2줄)뿐이고, 원문은 아래에 전량 인용함 — 되살릴 수 있음.

```text
┌──(kali㉿kali)-[~/PG/Vault]
└─$ python3 - <<'EOF'

┌──(kali㉿kali)-[~]
└─$ hashcat -hh | grep -E "^\s+(5600|13100|18200)\s"

┌──(kali㉿kali)-[~]
└─$ grep -i '^ANIRUDH' ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev

┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[].Properties | [.samaccountname,.enabled,.dontreqpreauth] | @tsv' 20260708124927_users.json

┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | select((.Members//[])[].ObjectIdentifier=="S-1-5-21-537427935-490066102-1511301751-1103")

┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | .Properties.name as $n | (.Aces//[])[]

┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | .Properties.name as $n | (.Aces//[])[]

┌──(kali㉿kali)-[~/PG/Vault]
└─$ jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
```

**왜 이것이 「실측 프롬프트 삭제」가 아닌가** — 세 근거가 겹침.
1. **git 최초판(15671e5)에 없음.** 최초판의 Kali 프롬프트는 14개이고 그 목록에 이 8개가 전부 없음. 즉 개작 웨이브가 만든 것임
2. **`~/.zsh_history` 에 `jq` 가 0건, `hashcat -hh` 0건, `hashcat.potfile` 0건.** 사람이 대화형으로 친 적이 없음
3. **노트 자신이 재분석이라고 말함** — 「hashcat 모드는 Kali 에서 **직접 확인함**」 · 「BloodHound JSON 은 `jq` 로 **직접 열어 대조함**」. 박스 풀이 시점이 아니라 노트 작성 시점의 행위임

**보존한 것 — 손대지 않음:**
- 최초판 유래 Kali 프롬프트 12개 + `sudo nmap -sU …`(`~/.zsh_history` 1608행에 실재) + 변형 2 = **15개 전량 보존**
- **타겟 pty 프롬프트 전량 보존** — `*Evil-WinRM* PS …`, `C:\Windows\system32>`, `smb: \>`. 개작 직전판 대비 오히려 4개 늘었음(최초판에서 복원된 분)

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

| 내가 의심한 것 | 확인 결과 |
|---|---|
| `Initial Access` 절이 **두 번** 나오고 `Service Enumeration` 이 그 사이에 끼어 구조가 깨졌다 | **노트가 옳음.** `_WRITEUP-STANDARD.md:166` 이 「앞은 4항목 요약, 뒤는 상세 재현. 순서는 요약 → Service Enumeration → 상세」로 못박음. 제목도 긴 형/짧은 형으로 다름(:168 요구) |
| `tech/ad/ntlm-relay` 태그가 붙었는데 본문은 「릴레이가 아니라 크랙」이라고 함 — 내부 모순 | **노트가 옳음.** `extract.py:64` 의 해당 태그 패턴이 `[ntlmrelayx, ntlm[- ]?relay, **responder**]` 라 Responder 강제 인증이 이 버킷임. 자매 박스 [[Heist]] 도 동일 태그. **다만 태그 «이름»이 기법과 어긋나는 taxonomy 문제는 남음 → 총괄 판단 사항** |
| frontmatter 에 `difficulty`·`flags` 필드가 없다 | **노트가 옳음.** [[Hutch]]·[[Heist]] 도 없음 — 볼트 관례임 |
| 작성자 신고 「git 최초판에서 2개 복원」(`ls`/`pwd`)이 근거 없는 창작 아닌가 | **작성자가 옳음.** 15671e5:495–499 에 `└─$ ls` / `SeBackupPrivilegeCmdLets.dll  SeBackupPrivilegeUtils.dll` / `└─$ pwd` 가 그대로 있음 |
| `ntlm_theft` 출력 마지막 5줄(`zoom-attack-instructions.txt` ~ `steal.theme (THEME TO INSTALL`)이 스크린샷에 없으니 창작 아닌가 | **작성자가 옳음.** 15671e5:172–176 에 동일 5줄이 있고, `~/git/ntlm_theft/steal/`(mtime 10:22:16, 파일 24개)이 파일명을 전부 증언함 |
| 「스크린샷 17장」이 실제 18장과 불일치 | **노트가 옳음.** 임베드 17개 · 18번째(`…103351.png`)는 `…103353.png` 과 **28759바이트 동일 중복**이라 본문에서 그 사실을 밝히고 미임베드. 실측으로 크기 일치 확인 |
| 작성자 신고 ⑥ 시간표가 UTC/로컬 미환산일 것 | **환산 문제 없음.** `nmap.log` 헤더 시각(`Wed Jul 8 09:15:26`)은 로컬, 본문 `server time: 2026-07-08 00:15:59Z` 는 UTC — 09:15 KST = 00:15 UTC 로 정합. 모든 mtime 이 `+0900` 렌더이고 표의 값과 일치 |

## 4. 검산 결과

**ⓑ 코드블록 바이트 대조 — 3/3 일치, 불일치 0건**

| 블록 | 산출물 | 결과 |
|---|---|---|
| nmap TCP raw | `~/PG/Vault/nmap.log` 3052B | MD5 `453adb216437b015b01e3b773fc5e1c3` **동일** (65행) |
| nmap UDP raw | `~/PG/Vault/udp.txt` 422B | MD5 `08f4b1c94b13d02d4f66d41e3f132ecc` **동일** (10행) |
| NetNTLMv2 해시 | `~/PG/Vault/hash.txt` 706B | `diff` 무출력 — **바이트 동일** |

감사 정정 후 재검산에서도 셋 다 동일. 절단 없음.

**ⓒ 「삭제 334줄」 검산 — 정확함, 이관 손실 0**

`_AUDIT\Vault-playbook.md` 부록의 5개 인용 블록을 백업(`Vault.md.bak`)의 해당 행범위와 MD5 대조:

| 원본 장 | 행범위 | 줄수 | MD5 |
|---|---|---:|---|
| §0 이 박스에서 배우는 것 | 38–59 | 22 | `5d5bce…` **일치** |
| §2-8 강제 인증 신호 판독 | 458–486 | 29 | `b9038d…` **일치** |
| §6 막혔던 지점/시행착오 | 911–1136 | 226 | `328d90…` **일치** |
| §7 OSCP 시험 관점 | 1139–1181 | 43 | `95e4c7…` **일치** |
| §8 방어 관점 | 1184–1197 | 14 | `47814d…` **일치** |
| 합계 | | **334** | **5/5 바이트 동일** |

행수 산술도 맞음 — 1229 − 334(삭제) + 약 198(nmap/UDP/`Created:`/`putting file` 전문 복원 · SharpGPOAbuse 실패 2회 · 시각 복원표 · 플래그 불일치 서술) = 1093. 「1229→1093 은 136줄뿐인데 334 신고」라는 총괄 우려는 **재배치·복원분으로 정확히 해소됨.**

**ⓔ 프롬프트 27개 가름 — 재판정**

작성자 신고(23 보존 / 4 이동 / 전환 0 / 삭제 0 / 최초판 2 복원)를 개작 직전판 27개와 대조한 결과:

| 실제로 일어난 일 | 건수 |
|---|---|
| 개작에서 제거(→ `_PLAYBOOK` 제안 파일로) — `enum4linux-ng ×2` · `impacket-GetNPUsers -h` · jq 사용자 질의 2개(1개로 병합) · `hashcat -m 5600`(프롬프트만 벗김) | 6 |
| 최초판에서 복원 — `ls` · `pwd` | 2 |
| 개작 후 잔존 | 23 |
| **이번 감사에서 창작으로 판정해 제거** | **8** |
| **최종** | **15** |

⚠️ **작성자의 「전환 0」은 부정확함** — `hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt` 는 프롬프트만 벗고 명령은 남았으므로 전환 1건임. 명령이 보존됐으므로 실질 손실은 없음.

**ⓖ 스크린샷 대조 — 11장 직접 열람, 불일치 0건**

| 파일 | 확인한 것 |
|---|---|
| `…103353.png` | 해시 blob — `hash.txt` 와 바이트 동일 |
| `…103424.png` | Responder 배너 Poisoners `LLMNR/NBT-NS/MDNS/DNS [ON]`, `DHCP [OFF]` · 프롬프트 `~/PG/Vault` |
| `…103537.png` | `mput` 24행 중 앞 16행 순서까지 노트와 동일 · 프롬프트 `~/git/ntlm_theft/steal` |
| `…103551.png` | `Created:` 목록이 `steal.pdf` 까지 · 그 아래 5줄은 15671e5 에서 복원된 것으로 확인 |
| `…103721.png` | `smbclient -L` 공유 목록 + SMB1 오류 3줄 전량 일치 |
| `…103849.png` | `put test.txt` · 블록수 `712639`→`712624` 일치 · **공유가 비어 있었음 확정** |
| `…104729.png` | nxc-sweep — `C$ READ,WRITE` · `ADMIN$ READ` · `nla:False` · `(Pwn3d!)` 일치 |
| `…104942.png` | `local.txt = 5a3377f8afb97ee39a988c201052df14` **한 글자씩 대조** |
| `…125002.png` | bloodhound-python 출력 전량 일치(`Done in 00M 18S`) |
| `…131411.png` | 그래프 — `GenericWrite`/`WriteOwner`/`WriteDacl` 세 엣지 확인 |
| `…132007.png` | SharpGPOAbuse — `--GPO`/`-- UserAccount` 실패 2회 + `--GPOName` 성공, SID·GUID 전량 일치. **`--AddlocalAdmin` 소문자 l 확정** |
| `…132134.png` | `net localgroup administrators` — `Administrator`/`anirudh` 일치 |
| `…132320.png` | `proof.txt = 714b4d1566a4bc88b9a0f45c33b36f0b` **한 글자씩 대조** |
| `…132526.png` | `whoami /priv` 9개 특권 전량 일치 |
| `…134045.png` | `nt authority\system` + `proof.txt = 74a1ddd00c6d187cf4f787c14d5cbde1` **한 글자씩 대조** · 창 제목 `C:\Windows\system32\utilman.exe - .\Utilman.exe` |

(15장 열람. 미열람 3장 — `…103351.png`(중복) · `…131710.png`(git clone) · `…132047.png`(gpupdate) — 값이 걸리지 않는 화면)

**독립 재실행으로 확인한 것**

| 명령 | 결과 |
|---|---|
| `jq -r '.data[].Properties \| [.samaccountname,.enabled,.dontreqpreauth] \| @tsv'` | 노트 출력과 **바이트 동일**(선행 `\t\t` 행 포함) |
| blob 디코드 `python3` | `MsvAvTargetName = cifs/192.168.45.175` · `T3QX` · `WIN-XX6CZIRM2X8` · `WIN-XX6CZIRM2X8.T3QX.LOCAL` — **전부 일치** |
| `grep -i '^ANIRUDH' ~/.local/share/hashcat/hashcat.potfile` | 항목 존재 · `hash.txt` 와 동일 blob · `:SecureHM` — 노트의 「이 박스에서도 실행됐음은 확정」 **입증됨** |
| `responder -h` / `Responder.py:31` | `-I, --interface … metavar="eth0"` — 노트의 「`-I` 는 인터페이스 이름」 **맞음** |
| `ls ~/git/ntlm_theft/steal/` | 파일 **24개** · mtime **10:22:16** · `steal.url` 은 없고 `steal-(url).url`·`steal-(icon).url` 임 → 작성자 반증 ④ **맞음** |
| `ls ~/git/SeBackupPrivilege/…/bin/Debug/` | DLL 2개 mtime **2026-07-08 13:49:45** — 노트 시각표와 일치, 「RDP SYSTEM(13:40) 뒤에 클론 = 준비만 하고 멈춤」 **성립** |
| `grep -i addlocaladmin ~/git/SharpGPOAbuse/` | README:29,60 이 `--AddLocalAdmin` 표기 |

**ⓐ 구조 · ⓓ 형식 — 결손 없음**

- `Initial Access`(요약, 긴 제목) 4항목 ✅ / `Privilege Escalation – GPO GenericWrite 악용 (SharpGPOAbuse)` 4항목 ✅
- `Port Scan Results` 표 존재 ✅ · **nmap raw 포트행 보존** ✅(`extract.py` `PORT_RE` 가 긁을 수 있음)
- 두 `Initial Access` 제목 상이 ✅ · 4항목 안에 「아래/위」 상대 참조 0건 ✅
- `Local.txt value:` = `Initial Access` 상세 절 끝 ✅ · `Proof.txt value:` = `Post-Exploitation` ✅
- TCP/UDP raw 2종이 캡션으로 구분됨 ✅ · 코드펜스 짝 80개(짝수) ✅ · 펜스 안 한국어 주석 **0건** ✅
- `## 관련` 의 `_PLAYBOOK` 앵커 5개 전부 실재 ✅

**ⓘ 남긴 흔적** — 미끼 24개(파일명 전량) · GPO Restricted Groups · 로컬 Administrators · `utilman.exe` 치환(+`cmd.exe` 가 원래 자리에 없음) · `SharpGPOAbuse.exe` · `test.txt` · Kali 잔존물. **전부 있음** ✅

**ⓕ 작성자 반증 반영 — 6/6 반영 확인**

① 태그 3종 제거(`tech/win/sebackup`·`tech/ad/dcsync`·`tech/ad/pth`) — frontmatter 확인, `tech_count: 9` 와 실제 개수 일치 ✅ ② `--GPO`→`--GPOName` 실패 2회 복원 ✅ ③ `--AddlocalAdmin` 소문자 복원 ✅(감사에서 유보를 사료로 격상) ④ `steal.url` 부재 ✅ ⑤ 10:38 공유 공백 관측 + `[가정]` ✅ ⑥ 시간표 재실측 ✅(타임존 정합)

## 5. 총괄 판단 사항

1. **`tech/ad/coerced-auth` taxonomy 신설** — 작성자 제안. 현재 Responder 강제 인증이 `tech/ad/ntlm-relay` 로 들어가는데, 이 박스는 본문에서 「릴레이가 아니라 크랙」이라고 명시적으로 배제함. 색인에서 두 기법이 구분되지 않음. **`extract.py:64` 수정이 필요하므로 공유 인프라 = 총괄 몫**
2. **색인 갱신 필요** — 노트 본문이 바뀜(행수 1093→1089). `refresh.ps1` 은 감사자가 돌리지 않음
3. **`_STATUS.md` 판정** — Vault = **완료 2/2**. 근거: `local.txt` `5a3377f8afb97ee39a988c201052df14`(evil-winrm PS 프롬프트) · `proof.txt` `714b4d1566a4bc88b9a0f45c33b36f0b`(evil-winrm) 및 `74a1ddd00c6d187cf4f787c14d5cbde1`(RDP SYSTEM cmd). 둘 다 **대화형 셸** — 웹셸 0점 규정 저촉 없음

## 6. 근거 출처

- Kali — `~/PG/Vault/`(nmap.log 3052B · udp.txt 422B · hash.txt 706B · test.txt 5B · BloodHound JSON 7종) · `~/git/ntlm_theft/steal/`(24개, mtime 10:22:16) · `~/git/SharpGPOAbuse/SharpGPOAbuse-master/README.md` · `~/git/SeBackupPrivilege/…/bin/Debug/`(mtime 13:49:45) · `~/.local/share/hashcat/hashcat.potfile` · `~/.zsh_history`(1608·1613·1616–1617·1691–1697 등) · `/usr/share/responder/Responder.py:31`
- git — `15671e5`(최초판 516행) · `HEAD`=`aba5a29`(1229행) · 백업 `03. PG\_backup\Vault.md.bak`
- 볼트 — `파일보관\Pasted image 2026070810/12/13*.png` 15장 직접 열람
- 기준 — `03. PG\_WRITEUP-STANDARD.md:71–230` · `_INDEX\_tools\extract.py:57–71` · `CLAUDE.md` §3·§4
