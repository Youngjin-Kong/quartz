---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# Jacko — 노트 개작 기록 (`pg-note-forge`, 2026-08-26)

대상 `03. PG\Jacko.md` · **851행 → 770행** · 백업 `03. PG\_backup\Jacko.md.bak2`
이관 제안 `03. PG\_AUDIT\Jacko-playbook.md`(10건)

## 1. 무엇을 했나

옛 0~9장 구조 → OSCP 제출 보고서 형식(`## Target #1` 래퍼 + `###` 절, `Initial Access` 2회).
학습 자료(§0 배우는 것 · §6 시행착오 · §7 시험 관점)를 잘라내 `_AUDIT\Jacko-playbook.md` 로 이관 제안, §8 방어 관점은 `Vulnerability Fix:` 로 분산.
플래그는 **1/2** — `Proof.txt value: 없음` + 근거 3개 명시.

## 2. 구조 대응

| 옛 | 새 |
|---|---|
| 머리말 3줄 | `> [!info] 요약`(+ 「시행착오·교훈 → [[_PLAYBOOK]]」) |
| §0 배우는 것 | → 제안 8(`B-2` 신규 H2 카드) · 제안 9(`C-1`) |
| §1 정찰 | `### Service Enumeration` + **Port Scan Results 표**(nmap raw 는 그대로 보존) |
| §2 취약점 분석 | `Vulnerability Explanation:` + `### Initial Access – H2 Console → JNI 코드 실행` 산문 |
| §3 Foothold | `Initial Access` 두 절(요약 4항목 / 상세 재현) |
| §4 권한상승 미완 | `### Privilege Escalation – 없음 (열거 미실행 · 취약점 미특정)` + 4항목 |
| §5 플래그 | `**Local.txt value:**` / `**Proof.txt value:**` |
| §6 시행착오 | → 제안 1·2·3·4·5·6 |
| §7 시험 관점 | → 제안 9(`C-1`) · 제안 10(`D`). 4번(시험 규정 점검)만 `Post-Exploitation` 에 잔류 |
| §8 방어 관점 | → `Vulnerability Fix:` 5줄 |
| §9 참고 · 남긴 흔적 | `## 관련` · `Post-Exploitation` |

두 `Initial Access` 제목을 다르게 지음 — 앞은 긴 서술형(「무인증 노출된 H2 Database Console 이 CSVWRITE 파일쓰기와 CREATE ALIAS 네이티브 로드로 이어져 원격 코드 실행」), 뒤는 짧은 형(「H2 Console → JNI 코드 실행」). 4항목 안에 「아래」·「위」 상대 참조 0건.

## 3. 반증한 것

### 3-1. 작업 지시가 틀렸던 것 — 스크린샷 범위

지시문의 확정 사실: *「Kali 산출물 mtime(15:41~17:01)과 겹치는 구간은 `150805`~`170741` 이다」*

**반증됨.** `150805`·`150807`·`150817`·`150903`·`151033`·`151116`·`151215` 7장은 **리눅스 박스**이고 Jacko(Windows)와 무관함.

- `Pasted image 20260710150805.png` — linpeas 의 「Files with Interesting Permissions / SUID」 화면. `/usr/sbin/mount.nfs`·`/usr/bin/passwd`·`/usr/bin/su` 등 **리눅스 SUID 목록**
- `Pasted image 20260710151215.png` — `# cd /home/` → `dennis francis max miriam sofia`, `# cat local.txt` → `c91395bd06b23a3455e9a6bf711184f3`. Jacko 의 `local.txt` 값(`dc9bb9f7d40681ebf2db1589d6ca40f0`)과 **다름**

**Jacko 스크린샷은 `161043` 부터 10장**(161043·161044·161232·161258·161324·162803·162836·162931·170436·170741). 노트는 그중 9장을 임베드하고 `161043`(161044 와 동일 크기 14694B 의 중복 붙여넣기)만 뺌. 임베드 9건 전부 파일 실재 확인 — 깨진 링크 0.

### 3-2. 기존 노트가 자기 코드블록에 반박당한 곳

「`xxd` 로 뜨면 차이가 **두 군데**뿐이다」 → 바로 아래 diff 가 **세 hunk**(`19c19`·`40c40`·`431c431`). 2026-08-26 Kali 재실행으로 세 hunk 확인. **「세 군데」로 정정.**

### 3-3. 자기 초고에서 잘라낸 것

「파일은 **23행짜리 텍스트**인데 … **15행 한 줄이 124,111자**」 — 최장 행 길이 **124111** 은 `awk '{print length}' … | sort -rn | head -1` 로 재확인됐으나, **행 번호 15 는 근거가 없음.** 행 번호를 뺌.
(`wc -l` = 22 — 마지막 줄에 개행이 없어 「23행」과 정합. 크기 125,140B 로 정정, 종전 「125KB」는 반올림.)

### 3-4. 출처 시각의 두 층

「출처: `파일보관/Pasted image 20260710161044.png`」 — 파일 mtime 은 **16:10:44**(붙여넣기 시각)이고 화면 안 `http.server` 로그는 **16:10:29**. 둘을 구분해 캡션에 병기함. 서사의 기준은 화면 안 시각 쪽.

## 4. 프롬프트 판정 — **양쪽 다 실측. 하나도 지우지 않음**

| 종류 | 블록 수 | 판정 근거 |
|---|---|---|
| `┌──(kali㉿kali)` Kali 대화형 | **12블록 / 14줄** | ① `~/.zsh_history` 1792~1810행에 이 박스 작업 명령 실재(`mkdir Jacko`·`nnmap 192.168.120.66`·`whatweb`·`feroxbuster`·`msfvenom`·`rlwrap nc`·`searchsploit`) — **zsh 는 대화형 세션에서만 히스토리를 씀** ② `Pasted image 20260710161044.png` 가 **그 프롬프트를 화면으로 찍은 것**(`┌──(kali㉿kali)-[~/PG/Jacko]` + `└─$ python -m http.server 80`). 창작이 아니라 캡처임 |
| 타겟 셸 프롬프트 | **2블록 / 4줄** | `C:\Program Files (x86)\H2\service>whoami`(레거시 원본 `Jacko.md.bak` 에 그대로 있음) · `c:\Users>` `c:\Users\tony>` `c:\Users\tony\Desktop>`(스크린샷 `170741` 원본과 일치). **플래그를 대화형 셸에서 읽었다는 증거** — 명령 에코 중복(`cd tony` / `cd tony`)이 `shell_reverse_tcp` pty-less 파이프 셸의 지문 |

새로 붙인 Kali 프롬프트 없음 — 노트에 있는 12블록은 전부 원본에 있던 것이거나(10) 원본 §6 에서 위치만 옮긴 것(2: `python3 -c "print(0x03a200)"` · `msfvenom … mtr.exe`).

## 5. Kali 재실측(2026-08-26)으로 값을 확인한 것

| 노트의 단정 | 확인 |
|---|---|
| `net.ipv4.ip_unprivileged_port_start = 0` | 일치 |
| 최장 행 124111 | 일치 |
| `searchsploit` 이 `cp -i`(mtime 미보존) | `/usr/bin/searchsploit:958` 일치 |
| 원본 `49384.txt` mtime 2025-12-17 09:16:42 | 일치 |
| `xxd` diff 3 hunk · sockaddr `0087`=135 / `1f92`=8082 / `c0a82dd7` | 일치 |
| `~/.zshrc` `#setopt share_history`(57행) · `nnmap` 별칭(247행) | 일치 |
| `~/PG/Jacko/` 5파일 크기·mtime | 일치(`nmap.log` 6154B 15:41:50 · `whatweb.txt` 390B 15:44:46 · `49384.txt` 125140B 15:50:27 · `rev.exe` 7680B 16:46:50 · `reverse.exe` 7680B 17:01:44) |
| 히스토리 「1792~1810행」 | 일치(`nnmap 192.168.120.66` = 1796행) |

## 6. 판정

**Jacko · Intermediate · 1/2 (부분)** — 변경 없음.

근거: `local.txt` = `dc9bb9f7d40681ebf2db1589d6ca40f0` 확보(스크린샷 `170741`, 타겟 대화형 셸에서 `type`). `proof.txt` 는 값·시도 기록 모두 없음 — 셸 획득 17:04:36 이후 스크린샷이 17:07:41 한 장이고 그 뒤 0장, `~/PG/Jacko/` 에 셸 이후 산출물 0건.

## 7. 검산

- 노트 행수 **851 → 770**
- 코드펜스 **25쌍 50줄** — 여는 펜스 25개 전부 언어 태그(`bash` 15 · `sql` 4 · `text` 6). **무태그 0**
- nmap raw 원문 보존(`PORT_RE` 대상 라인 손대지 않음) · Port Scan Results 표는 **추가**
- 스크린샷 임베드 9건 전부 `파일보관\` 실재
- 이관 손실 **0** — 노트에서 지운 5블록(md5sum · searchsploit `cp -i` grep · 원본 mtime `ls` · 히스토리 순서 text · §0/§7 산문)의 원문을 `Jacko-playbook.md` 「지우기 전 원문」에 전량 인용. **삭제 5블록 → append 제안 10건**(원문 하나가 둘로 갈린 것 2건 포함)
- 플래그·IP·해시·자격증명·명령 원문·`[가정]`(9건)·「관측 없음」 전부 유지
- frontmatter — `tech_count: 5 → 6`, `tech/web/rce` 추가(H2 콘솔을 통한 원격 코드 실행). `manual_tags`·`manual_cves`·`manual_status` 유지, 값 든 줄에 주석 0
- `_PLAYBOOK` 앵커 7종 전부 **기존 절** — 재배정 영향 없음. 신규 항목 앵커는 걸지 않음

## 8. 총괄 판단이 필요한 것

- **태그 taxonomy** — `tech/db/h2` 신설이 자연스러우나 taxonomy 는 총괄 몫이라 **만들지 않음.** 기존 `tech/web/rce` 로 대체함. `tech/db/*` 는 현재 `mysql`·`mssql`·`sqlite` 3종
- `refresh.ps1`·`extract.py` 미실행(지시대로). 노트 개작 + `_AUDIT` 2파일 신규 생성이 색인에 반영되려면 총괄이 돌려야 함
- `03. PG\_backup\` 의 Jacko 백업이 이제 3개(`.bak` 레거시 원본 · `.pre-readability2-20260821.bak` · `.bak2` 이번 개작 전). 정리 여부는 총괄 판단
