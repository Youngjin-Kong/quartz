# Graph — 구조 전환 개작 (pg-note-forge, 2026-08-26)

대상: `03. PG\Graph.md` (478행 → 540행)
백업: `03. PG\_backup\Graph.md.bak` (기존 `Graph.md.pre-docreview-20260821.bak` 은 보존)
이관 제안: `03. PG\_AUDIT\Graph-playbook.md` (A 7건 · B 3건 · C 2건 = 12항목)
선행 감사: `Graph-audit.md`(writeup-auditor) · `Graph-docreview.md`(pg-doc-reviewer) — 두 결과 위에서 작업함

증거원: Kali `~/PG/Graph/` 전량(직접 열람) · 볼트 `파일보관\PG-Graph-*.png` 2장(직접 열람) · `~/.zsh_history` · `/usr/share/wordlists/rockyou.txt`(직접 대조). 박스 정지 상태, 재접속 없음. `find /`·홈 전수 스캔 없음.

---

## 1. 구조 전환

옛 0~9장 → OSCP 제출 보고서 형식(템플릿 4장).

| 옛 장 | 어디로 |
|---|---|
| `[!info]` 요약 | 유지 + 「시행착오·교훈 → [[_PLAYBOOK]]」 |
| 0. 배우는 것 | `_PLAYBOOK` B 제안 3건 |
| 1. 정찰 | `### Service Enumeration` + Port Scan Results 표 |
| 2. 취약점 분석 | `Initial Access` 4항목 `Vulnerability Explanation:` + 상세 절 재현 산문 |
| 3. Foothold | `### Initial Access` 두 절 |
| 4. 권한상승 | `### Privilege Escalation – …` 한 절 |
| 5. 플래그 | `**Local.txt value:**` / `**Proof.txt value:**` 로 분산 |
| 6. 시행착오 | `_PLAYBOOK` A 제안 5건 |
| 7. 시험 관점 | `_PLAYBOOK` A·B·C 흡수(6건) + C 독립 2건 |
| 8. 방어 관점 | 6항목 전부 두 finding 의 `Vulnerability Fix:` 로 분산(이관 아님, 노트에 남음) |
| 9. 참고 · 남긴 흔적 | `## 관련` · `### Post-Exploitation` |

최종 골격:

```
> [!info] 요약
## Target #1 – 192.168.248.201
### Initial Access – GraphQL introspection 이 드러낸 users(searchTerm) 인자 주입으로 전 계정 해시를 덤프하고 크랙해 SSH 진입   ← 4항목만
### Service Enumeration
### Initial Access – GraphQL 인자 주입 → jane SSH                                                                        ← 재현 + Local.txt value
### Privilege Escalation – sudo pass-gen 인자 개행 주입으로 /etc/shadow 에 josh 행 선삽입                                  ← 4항목 + 재현(#### 4개)
### Post-Exploitation                                                                                                    ← Proof.txt value + 남긴 흔적
## 관련
```

### `Privilege Escalation` 을 한 절로 둔 근거

이 박스는 jane → josh → root 의 2단 상승이나 **기법은 하나**임 — `sudo pass-gen` 인자 개행 주입. josh → root 구간은 별개 익스플로잇이 아니라 ① josh 가 `/etc/shadow` 를 읽어 root 해시를 회수하고 ② rockyou 로 크랙해 ③ `su - root` 한 것이라 「자격증명 크랙」이지 새 취약점이 아님. 게다가 **josh 가 shadow 를 읽을 수 있었던 근거 자체가 관측 없음**(harvest 가 `/etc/group` 을 안 뜸)이라 독립 finding 의 `Vulnerability Explanation:` 을 채울 재료가 없음. 따라서 한 절 안에서 `#### josh → root` 단계로 씀.

---

## 2. 반증한 것

### 2-1. `john.out` 에 `Session completed` 가 «있다» — 원본 노트가 틀림

원본 §3:

> 다만 이 출력에는 `Session completed` 가 없음 — 워드리스트를 끝까지 돈 것인지, jane 이 나온 시점에 끊고 넘어간 것인지는 산출물로 구분되지 않음(해시 정리 14:53:20 → 이 출력 14:53:30, 10초). 즉 **admin·josh 가 "안 깨진다"가 아니라 "이 실행에서는 안 나왔다"** 가 정확함

현재 파일 실측:

```text
oakland          (jane)     
1g 0:02:31:54 DONE (2026-08-21 17:25) 0.000109g/s 1573p/s 3148c/s 3148C/s  naptown410..^D*^C7M-BM-!Vamos!^C
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

**파일 mtime 이 17:25:20 인 것이 이유임** — 총괄 프롬프트가 「두 시간 뒤라 확인하라」고 짚은 그 지점이 정확히 이것이었음. 노트를 쓸 당시 john 은 **아직 돌고 있었고** 부분 기록만 읽힌 것임. `17:25:20 − 2:31:54 = 14:53:26` 이 `hashes.txt`(14:53:20) 6초 뒤라 시작 시각도 맞음. 후속 작업이 아니라 **같은 job 의 완주**임.

→ 노트를 「rockyou 전량 완주 후에도 admin·josh 미크랙」으로 승격함.

### 2-2. 1차 john 의 워드리스트는 rockyou 임 — `[가정]` 이 아니라 확정

원본 §3: 「워드리스트는 산출물에 명시돼 있지 않으나 … **[가정]** 여기서도 rockyou 였을 가능성이 높음」

세 근거가 일치함(전부 Kali 에서 직접 대조):

| 근거 | 값 |
|---|---|
| 상태줄 마지막 후보 `^D*^C7M-BM-!Vamos!^C` | `tail -3 /usr/share/wordlists/rockyou.txt` 의 **마지막 줄**과 동일 |
| 직전 후보 `naptown410` | 같은 파일 **14,344,167행** |
| 1573 p/s × 9,114초 ≈ 14,336,000 | 파일 전체 **14,344,392행** |

→ `[가정]` 제거, 확정 서술로.

부수 확인 — `oakland` = rockyou 4,451행(시작 몇 초 만에 크랙, 원본의 「10초 안」 mtime 관측과 일치), `espartaco` = 70,985행 ÷ 1949 p/s = 36.4초(`graphroot.log` 의 `0:00:00:36` 과 일치).

### 2-3. john.rec 락을 쥔 job 이 «누구인지» 관측 없음 — 반증됨

원본 §4·§6-3: 「다른 PG 박스 작업에서 쓰던 세션 파일이 아직 잠겨 있었던 것으로 보임(**[가정]** — 정확히 어떤 이전 job 이 이 락을 쥐고 있었는지는 관측 없음)」

2-1 이 이것을 푼다 — 1차 john(14:53:26~17:25:20)이 15:06:02 시점에 **살아 있었음.** 다른 박스가 아니라 **같은 박스의 자기 job** 이 락을 쥐고 있었던 것임. `[가정]` 제거.

### 2-4. root 해시를 읽은 세션이 「관측 없음」 — 부분 반증

원본 §4: 「⚠️ **[가정] 이 파일을 어떤 세션에서 만들었는지는 관측 없음.** … 그 전에 이미 josh 로 갈아탄 세션이 따로 있었고 그것이 종료돼 `ps` 에 남지 않은 것으로 보는 편이 자연스러움」

`harvest_root.txt` 「TMP」절의 `/tmp` 목록이 그 세션의 물증을 갖고 있었음 — 이전 감사가 「USERS」·「PROCS」만 보고 「TMP」를 안 본 것임:

```text
-rw-rw-r--  1 jane jane  575 Aug 21 02:00 .p.sh                          ← Kali exploit_passgen.sh(575B)와 같은 크기 = 손상 사본
-rw-rw-r--  1 jane jane  415 Aug 21 02:01 .p.out                         ← 1차 실행 로그(회수 안 됨) → bogus 행의 출처
-rw-rw-r--  1 jane jane  443 Aug 21 02:04 .p2.sh                         ← 2차(성공) 스크립트(회수 안 됨)
-rw-r-----  1 josh josh 1688 Aug 21 02:05 .shadow_snapshot_afterinject   ← josh 소유, 조작 후 shadow 와 같은 크기
```

`.shadow_snapshot_afterinject` 가 **josh 소유**이고 크기 1688 이 조작 후 `/etc/shadow` 와 정확히 같음. `root_hash.txt` 생성 시각(Kali 15:05:47 = 타겟 02:05:47, KST = EDT + 13h)과 맞물림.

→ **「josh 세션이 02:05 에 존재했고 shadow 를 읽었다」는 확정.** 남는 `[가정]` 은 「무슨 권한으로 읽었는가」뿐임(shadow 그룹 vs `sudo` — 파일 소유자가 josh 인 것은 `sudo cat … > /tmp/x` 로도 성립하므로 판별 불가).

부수 — 「성공한 페이로드는 저장되지 않았음」도 `.p2.sh`(443B) 존재로 **「타겟에 있었으나 회수 안 함」**으로 좁혀짐.

### 2-5. 성공한 페이로드는 결과에서 역산됨 — 원본이 「복원 불가」로 남겨둔 것

원본 §4: 「성공한 실행에서 쓴 온전한 페이로드는 따로 저장되지 않음」

관측된 두 행을 이으면 인자가 그대로 떨어짐:

```
jane:<새해시>:19831:0: + [99999:7:::\njosh:$6$Gr4phSlt$PGF3…Z1:19000:0:99999] + :7:::
```

를 조립하면 `harvest_root.txt` 의 jane 행 + josh 행과 **바이트가 맞음.** 「요청 원문이 아니라 결과에서 되짚은 재구성」 캡션과 함께 노트에 실음. 이로써 `pass-gen` 의 동작(인자를 `max` 필드에 그대로 꽂음)이 추정이 아니라 산술로 확인됨.

### 2-6. jane 의 비밀번호가 익스플로잇으로 «바뀌었음» — 원본에 없던 관측

복원본 `jane:$6$41234567$UopO…:19831:0:1337:7:::` ↔ 조작 후 `jane:$6$32320834$CYv6…:19831:0:99999:7:::`. 해시가 재생성돼 크랙한 `oakland` 이 더는 jane 의 비밀번호가 아님. 원본은 `max` 필드 변경만 지적하고 해시 재생성의 «의미»(재로그인 불가)를 안 적었음. 노트에 한 줄 추가 + `_PLAYBOOK` A-7 신규 제안.

### 2-7. 원본의 gobuster 인용이 바이트 부정확 — 정정

원본 §1 이 `gobuster-raft.txt` 를 이렇게 인용:

```text
/static              [Status: 301] [Size: 179] [--> /static/]
```

실제 파일은 ANSI 이스케이프가 살아 있고 **괄호**임:

```text
/static              ^[[36m (Status: 301)^[[0m [Size: 179]^[[34m [--> /static/]^[[0m
```

→ `cat -v` 표기로 교체하고 「제어문자를 `^[` 로 렌더한 것 외에 원문 그대로」 캡션을 붙임. 별도로 `gobuster-80.txt` 원문(`(Status: 301)`)도 추가해 두 실행을 나란히 볼 수 있게 함.

### 2-8. 내 초고가 틀렸던 것 — `bogus` 행을 「사본을 그대로 돌린 것」으로 단정하려 했음

초고에서 「Kali 사본 = 타겟 `.p.sh` = bogus 행의 원인」으로 삼단 연결하려 했으나 **산술이 안 맞음.** 사본의 `PAY=$99999:7:::…` 는 bash 에서 `$9`(빈 위치 파라미터) + `9999` 로 전개돼 `9999` 가 되어야 하는데, 관측된 bogus 행의 해당 자리는 `99999` 임. 또 `bogus` 라는 계정명은 사본의 인자 어디에도 없음.

→ 단정을 접고 **지문 3개(리터럴 `njosh` · 접두 없는 해시 · 후행 `$`)의 일치**까지만 확정으로 쓰고, `bogus` 계정명의 출처와 `pass-gen` 의 인자 규약은 「관측 없음」으로 명시함. 바이너리를 회수하지 않아 더 파는 것은 소스 고고학이라 하지 않음.

### 2-9. tmux 잔여 세션 서술이 stale — 정정

원본 「남긴 흔적」: 「Kali 쪽 — tmux 세션 `graph-josh`·`graphjosh` 가 이 노트 작성 시점까지 남아 있음 … 관리자가 처리할 몫이라 직접 종료하지 않음」

2026-08-26 실측: `tmux ls` → `no server running on /tmp/tmux-1000/default`. 이미 정리됨. 노트를 「재확인 시점에 tmux 서버 자체가 없음」으로 갱신함(과거 서술을 지우지 않고 상태 변화로 적음).

---

## 3. 프롬프트 판정 — 타겟 pty 프롬프트

**판정: 실측. 전부 보존함(5개).**

| 검사 | 결과 |
|---|---|
| 비대화형 `ssh "cmd"` 산출물만 있는가 | 아님 |
| pty 캡처·로컬 에코 흔적 | **있음** |
| Kali 프롬프트(`┌──(kali㉿kali)`) | **0건** — 만들어 붙이지 않았고 원래도 없음 |
| `~/.zsh_history` 의 Graph 관련 명령 | **0건**(Kali 쪽은 전부 비대화형 — 정상) |

근거 셋:

1. `proof_user.txt` 에 **Ubuntu MOTD 전문 + `Last login: Thu Apr 18 14:10:19 2024 from 192.168.118.13`** 이 있음. 비대화형 `ssh host "cmd"` 는 MOTD 를 출력하지 않음 = tty 로그인의 표시
2. `proof_root.txt` 에서 명령행이 `…; c` / `at /root/proof.txt` 로 **토큰 중간에서 줄바꿈**됨 = 터미널 폭 래핑, pty 아니면 나올 수 없음
3. 프롬프트 문자열이 `jane@graph:~$`·`root@graph:~#` 로 타겟 호스트명·사용자와 일치하고, `harvest_root.txt` 의 `ps auxf` 가 같은 시각의 `pts/1` 세션을 독립적으로 보여줌

→ **두 플래그 모두 대화형 셸에서 원위치 `cat`.** 웹셸 경유 아님, 시험 기준 0점 대상 아님.

---

## 4. 여전히 「관측 없음」으로 남는 것 (8건)

1. GraphQL 주입 payload 문자열(요청 본문) — 헤드리스 캡처에도 URL 바 없음. **영구 손실**
2. 심어 놓은 josh 해시의 **평문**, 그 해시를 생성한 명령
3. `root_hash.txt` 를 읽어낸 **명령**(세션의 존재는 2-4 로 확정, 명령은 미확인)
4. josh 가 shadow 를 읽을 수 있었던 **권한 근거** — harvest 가 `/etc/group` 을 안 뜸
5. `sudo -l` 원문(허용 조건 — NOPASSWD 여부·인자 제한)
6. `pass-gen` 바이너리 자체(`ls -la`·`file`·`strings` 없음)와 `bogus` 계정명의 출처
7. 수동 gobuster 의 명령행(워드리스트가 raft 계열이라는 것 외)
8. 이 취약점에 해당하는 공개 CVE 번호(커스텀 Node.js 앱)

---

## 5. 검산

| 항목 | 값 |
|---|---|
| 행수 | 478 → 540 |
| 코드펜스 | 35쌍(70줄), **무태그 여는 펜스 0** — `bash` 9 · `text` 21 · `json` 5 |
| nmap raw 라인 | `22/tcp open  ssh` · `80/tcp open  http` 보존(`PORT_RE` 매칭 확인). Port Scan Results 표는 **추가** |
| UDP `closed` 블록 추가의 색인 영향 | 없음 — `PORT_RE = ^\s*(\d{1,5})/(tcp\|udp)\s+open\s+(\S+)` 이 `open` 만 매칭 |
| `[가정]` | 6곳(요약 1 · 엔드포인트 · UNION · 캡처방식 · ANSI-C · josh shadow 권한) |
| 「관측 없음」 | 8곳 |
| 출처 캡션 | 29 |
| 스크린샷 `![[…]]` | 2 (둘 다 직접 열람해 본문과 대조 — 반박 없음) |
| 플래그 | user `754551935abdc3b2bdde424a9b5ccb66` · root `3e823452d93d1c9c8ef9bcf9d34612eb` |
| 자격증명 | `oakland` · `espartaco` 보존 |
| `[[_PLAYBOOK#…]]` 앵커 | **0** — 신규 항목 앵커를 걸지 않음. 본문 링크 `[[_PLAYBOOK]]` 1건뿐 |
| 이관 제안 | `Graph-playbook.md` — A 7 · B 3 · C 2 = 12항목, 전부 「지우기 전 원문」 인용 동봉 |
| 프론트매터 | 무변경. `manual_tags: true` 의 `tech/*` 5종 전부 실제 사용 기법 |

### 스크린샷 대조

- `PG-Graph-web80-landing.png` — Bootstrap 템플릿, 「Welcome to Graph」 + 「Coming soon」, 상단 내비 Tour/Product/Features/Enterprise/Support/Pricing/Cart. 본문 서술과 일치
- `PG-Graph-graphql-sqli-hashdump.png` — **브라우저 JSON 뷰어**(`Pretty-print` 체크박스, 해제 상태)에 `dump_users.json` 과 동일한 6원소 배열. 새 관측: 같은 덤프가 **GET URL 로 재현 가능**했다는 뜻임(mtime 15:06:34 = root 획득 후 문서화용 재실행). URL 바가 없어 payload 는 여전히 복원 불가

---

## 6. 관리자에게 넘기는 판정

- **완료 2/2** — user `754551935abdc3b2bdde424a9b5ccb66`(jane pty) · root `3e823452d93d1c9c8ef9bcf9d34612eb`(josh → `su - root` pty). 둘 다 대화형 셸 원위치 `cat`. `_STATUS.md` 는 **건드리지 않음**
- **색인 갱신 필요** — 본문 대폭 수정. `refresh.ps1` 은 **돌리지 않음**(공유 인프라)
- **`_PLAYBOOK` 반영 필요** — `Graph-playbook.md` 12항목. 번호 배정 후 노트에 앵커를 걸지 판단할 것(현재 노트는 번호 앵커 0건이라 재배정으로 깨질 링크가 없음)
- **적대적 검증 필요** — 구조 전환 + 반증 9건이라 `writeup-auditor` 재투입 대상임
- Kali tmux 잔여 세션 없음(`no server running`). 처리할 것 없음
