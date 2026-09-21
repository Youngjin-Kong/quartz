---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# Graph — 적대적 검증 2차 (writeup-auditor, 2026-08-26)

대상: `03. PG\Graph.md`(개작본 540행) · 백업 `03. PG\_backup\Graph.md.bak`(478행)
선행: `Graph-forge.md`(작성자 리포트) · `Graph-playbook.md`(이관 제안 12건) · `Graph-audit.md`(1차, 덮지 않음)

증거원 — Kali `~/PG/Graph/` 전량(직접 열람·`cat -A` 대조) · 볼트 `파일보관\PG-Graph-*.png` 2장(직접 열람) · `~/.zsh_history` · `/usr/share/wordlists/rockyou.txt`(직접 대조) · `~/PG/_lib/recon.sh` · `_INDEX/_tools/extract.py`. 박스 정지, 재접속 없음. `find /`·홈 전수 스캔 없음.

---

## 1. 고친 것 — 7건

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `whatweb` 도 `Bootstrap, HTML5, Script, X-Powered-By[Express]` 외에는 없음 | 실제 `whatweb.txt` 에는 `Title[Welcome at Graph!]`·`IP[…]`·`Country[RESERVED][ZZ]` 도 있음. 「외에는 없음」이 부정확 | 실제 출력 항목을 그대로 적고 「nmap 배너 이상을 주지 않음」으로 판정만 유지 |
| `Service Enumeration` 끝 | **이관 손실** — 백업 §2 의 「앱 소스 배치 시도 전부 404」와 §1 의 「Express 배너 → PHP 계열은 헛수고」 인과가 노트에서 사라졌고 `Graph-playbook.md` 어느 항목에도 없음 | 두 문단 복원. 7경로·`gql/s_*.txt`·14:53:40 시각·「취약 코드 자체는 끝까지 관측되지 않음」 명시 |
| `나머지는 전부 내장 메타 타입임` | `String`·`Boolean` 은 메타 타입이 아니라 **내장 스칼라** | 「내장 스칼라 2종(`String`·`Boolean`)과 introspection 메타 타입 8종(`__*`)」 |
| 스크린샷 캡션 `같은 덤프가 GET URL 로도 재현됨을 보여줌` | **근거 없는 단정.** 크롬 JSON 뷰어(`Pretty-print` 체크박스)는 `file:///…/dump_users.json` 을 열어도 동일하게 렌더됨. URL 바가 잘려 있고 `web-80/chromium.log` 에는 랜딩 캡처 기록만 있음 | 「라이브 GET 인지 `file://` 인지 구분되지 않음」으로 강등 |
| `② 직전 후보 naptown410 이 그 파일 14,344,167번째 줄` | 「직전 후보」가 부정확 — 전체 14,344,392행이라 225행 뒤가 끝. john 은 **256개 청크** 단위로 후보를 버퍼링하므로 이것은 마지막 청크의 «시작»임 | 청크 산술(392−167=225 < 256)을 명시. `[가정]`→확정 승격의 근거가 오히려 강해짐 |
| `부작용으로 jane 의 비밀번호가 oakland 이 아니게 됨 — 재로그인이 불가함` | **표기 누락.** salt 가 `41234567`→`32320834` 로 바뀌어 «해시 재생성」은 확정이나, **평문이 바뀌었다는 근거는 없음**(같은 평문을 새 salt 로 재해시해도 같은 관측). 재로그인 시도 자체가 없었음 | `[가정]` 강등 + 「관측 없음」 명기. `ps auxf` 의 jane `pts/0`(01:54)가 그대로 살아 있다는 양성 증거 추가 |
| `proof_root.txt … 같은 명령의 첫 실행(02:08:13)` | **「같은 명령」이 아님.** 파일 앞부분 블록에는 `ls -la /root/proof.txt` 출력이 없음 = `cat` 까지만 친 실행이고, 프롬프트 줄도 스크롤백에서 잘림 | 「그쪽은 `ls -la` 없이 `cat` 까지만이고 프롬프트 줄이 잘려 출력만 남음」으로 정정 |

**삭제 0건. 강등 1건**(jane 비밀번호). 실측 블록·명령·해시·플래그·자격증명은 한 바이트도 건드리지 않음.

---

## 2. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

### 2-1. 작성자의 자기반증 3건은 «전부 진짜 반증»이었음 (총괄 지시 검증 항목)

**① `john.out` 의 `Session completed` — 확정.** 타임존 함정 없음. `john.out` mtime `2026-08-21 17:25:20 +0900`, 로그 본문 `DONE (2026-08-21 17:25)` — **둘 다 Kali 로컬 시계**라 환산 대상이 아님. `17:25:20 − 2:31:54 = 14:53:26`, `hashes.txt` mtime 14:53:20 의 6초 뒤로 시작 시각까지 맞음. 파생인 「`john.rec` 락을 쥔 job」 반증도 성립 — 실패 로그 `john_root.out` mtime 15:06:02 가 `14:53:26 ~ 17:25:20` 구간 «안»에 있음. **같은 박스의 1차 john 이 락 보유자.**

**② 1차 워드리스트 = rockyou — 승격 정당.** `[가정]`→확정 방향이라 직접 검산함(Kali 실행):

| 근거 | 실측 |
|---|---|
| john 상태줄 마지막 후보 `^D*^C7M-BM-!Vamos!^C` | `tail -1 rockyou.txt \| cat -A` 와 **바이트 동일**(제어문자 포함) |
| ` naptown410`(선행 공백) | 14,344,167행. 총 14,344,392행 − 167 = **225 < 청크 256** |
| `oakland` | 4,451행 ✔ / `espartaco` 70,985행 ✔ (70985 ÷ 1949 p/s = 36.4초 = `0:00:00:36`) |
| 1573 p/s × 9,114초 = 14,336,322 | 총행수 14,344,392 대비 0.06% 오차 |

제어문자가 섞인 마지막 줄이 우연히 일치할 확률은 없음. **확정 승격 유지.**

**③ `harvest_root.txt` 「TMP」절 — 확정.** `/tmp` 목록에 `.p.sh`(575B, 02:00, jane) · `.p.out`(415B, 02:01) · `.p2.sh`(443B, 02:04) · `.shadow_snapshot_afterinject`(**1688B, josh 소유**, 02:05) 실재. Kali `exploit_passgen.sh` 도 575B 로 일치. 1688 은 조작 후 `/etc/shadow` 크기(`cleanup_evidence_box.txt` 의 `1688 /etc/shadow`)와 정확히 같음. 타임존도 맞음 — `root_hash.txt` Kali 15:05:47 = 타겟 02:05:47(EDT, −13h). **「josh 세션이 02:05 에 존재했고 shadow 를 읽었다」 확정 유지.**

### 2-2. pty 판정 — 실측. 프롬프트 4개 전부 보존 (지우지 않음)

Fikklish 사고(감사자가 타겟 pty 프롬프트를 「위반」으로 제거)를 피하려 방향부터 가림.

- `proof_user.txt` — Ubuntu MOTD 전문 + `You have mail.` + `Last login: Thu Apr 18 14:10:19 2024 from 192.168.118.13` 뒤에 `jane@graph:~$ whoami; id; …` 가 **한 줄로 에코**됨. 비대화형 `ssh host "cmd"` 로는 프롬프트+명령 에코가 나오지 않음
- `proof_root.txt` — `…; c` / `at /root/proof.txt` 로 **토큰 중간 폭 래핑**. pty 아니면 불가
- `harvest_root.txt` 「PROCS」— `sshd: josh@pts/1`(02:07) → `-bash` → `su - root` → `-su`(02:08) 로 독립 교차확인
- `~/.zsh_history` 의 Graph/248.201 관련 명령 **0건**, 노트의 Kali 프롬프트(`┌──(kali㉿kali)`) **0건** — 창작 없음

⚠️ sshd_config 는 `PrintMotd no` 이나 MOTD 는 `pam_motd` 가 내며, sshd 는 tty 없는 세션의 PAM 메시지를 표시하지 않음. MOTD 근거는 유효함. 어차피 **에코·폭래핑 둘만으로도 pty 확정**임.

→ **완료 2/2 · 둘 다 대화형 pty 원위치 `cat` · 웹셸 아님 · 시험 0점 대상 아님.**

### 2-3. 코드펜스 35쌍 전수 대조 — 날조 0건

`nmap-quick.txt`·`nmap-udp-top100.txt`·`snmp-onesixtyone.txt`·`probe-index.txt`·`probe_admin_`·`.bg-gobuster.sh`·`gobuster-80.txt`·`gobuster-raft.txt`(`cat -v`)·`GET_graphql.txt`·`introspect_short.json`·`query_fields.json`·`dump_users.json`·`hashes.txt`·`john.out`(`cat -A`)·`john_root.out`·`john_root2.out`·`graphroot.log`·`root_hash.txt`·`proof_user.txt`·`proof_root.txt`·`exploit_passgen.sh`·`josh_hash.txt`·`cleanup_evidence_box.txt`·`harvest_jane_full.txt`(SUDO·shadow)·`harvest_root.txt`(USERS·PROCS·TMP·SSH) — **전부 바이트 일치.** 압축·생략은 캡션에 명시된 것뿐. **한국어 주석 삽입 0건** — `exploit_passgen.sh` 의 한국어 주석 2줄은 **원본 파일에 실재**(`cat -A` 로 UTF-8 바이트 확인), 노트가 넣은 것이 아님.

### 2-4. 그 밖에 확인 결과 노트가 옳았던 것

- `probe-interesting.txt` 0바이트의 원인 — `~/PG/_lib/recon.sh:275` 가 정확히 `grep -E '^(200|401|403|301|302) '` 임 ✔
- `/usr/bin/node = cap_net_bind_service+ep` 가 node 의 80 바인딩 근거 — `harvest_jane_full` 「PROCS」에서 `node index.js` 가 **user `node`** 로 돌고 「LISTEN」이 `0.0.0.0:80` 임을 확인. 노트 서술보다 오히려 근거가 강함 ✔
- 161/udp 는 `closed` 10개 목록에 없고 `Not shown: 90 open|filtered` 쪽 — 원문 확인 ✔
- 성공 페이로드 역산 — `jane:<해시>:19831:0:` + `99999:7:::`⏎`josh:$6$Gr4phSlt$…:19000:0:99999` + `:7:::` 조립 시 관측된 두 행과 **바이트가 맞음** ✔
- josh 원본 3행이 백업 `/tmp/s.restore` 에 있음 = 박스 원래 것 ✔ · 1688→1433B(255B 차) ✔ · `/tmp/cleanup_evidence.txt` 926B root 잔존 ✔
- tmux `no server running` ✔ (2026-08-26 재확인)
- 18개 후보 경로 / 53바이트 응답 4개 / 26경로 전부 `404 32` — 파일 수까지 일치 ✔
- gobuster 12분(14:52:01 → 15:04:53) ✔ · `gobuster-raft.txt` 의 ANSI + `DONE` ✔
- GraphQL 경로 프로빙은 `recon.sh` 에 **없음** → 「명령행은 재구성」 캡션이 옳음 ✔
- 시험 규정 판정 없음(자동 도구 미사용, 전 구간 `curl`/`john`) — 과잉 금지 판정 0건 ✔

---

## 3. 구조·색인 검사

| 항목 | 결과 |
|---|---|
| finding 4항목 | `Initial Access`(요약) · `Privilege Escalation` **각각 4항목 완비.** 첫 `Initial Access` 는 4항목«만» ✔ |
| 두 `Initial Access` 제목 | 상이(긴 서술형 / 짧은 형) ✔ |
| 헤딩 레벨 | `## Target #1` → `###` 5개 → `####` 4개(Priv Esc 하위) ✔ |
| `Port Scan Results` 표 | 있음 ✔ |
| nmap raw | `22/tcp open  ssh …` · `80/tcp open  http …` 보존. `extract.py:148 PORT_RE` 로 직접 대조 — 2건 매칭, `ports: [22, 80]` 유지 ✔ |
| 코드펜스 | 35쌍 70줄, **무태그 여는 펜스 0** |
| `[가정]` 7곳 · 「관측 없음」 9곳 | 강등 1건 추가로 각 +1 |
| 프론트매터 | `manual_tags: true`, `tech/*` 5종 전부 실사용 기법. 값 줄 주석 0. 본문에 `CVE-` 문자열 없어 `manual_cves` 불요 |
| 깊이 초과 | 소스 고고학 없음(바이너리 미회수를 「더 파지 않음」으로 명시한 것이 옳음) |

---

## 4. 이관 손실 검산

`Graph-playbook.md` 제안 12건이 백업 §0(7항목)·§6(도입+5)·§7(8항목)을 전부 「지우기 전 원문」으로 인용함 — 대응표 확인, **누락 0**.
§8 방어 6항목은 두 finding 의 `Vulnerability Fix:` 로 전부 살아 있음(introspection 차단 / 파라미터 바인딩 / 비밀번호 정책 / 커스텀 바이너리 입력 검증 / shadow 행 무결성 / `PermitRootLogin no`) ✔

**단 손실 1건 발견 — 노트에도 playbook 에도 없던 것:**

> (백업 §2 말미) 앱 소스 자체를 노리는 배치 시도(`s_app.js.txt`·`s_server.js.txt`·`s_package.json.txt`·`s_.git_HEAD.txt`·`s_static_*.txt`)도 같은 시각(14:53)에 돌렸으나 **전부 404** — Express 정적 서빙 경로 밖이라 소스는 못 봄.

> (백업 §1) `Node.js Express framework` 배너가 곧 스택 힌트임 — PHP/WordPress 계열 점검(`.env`·`wp-login.php`·`phpinfo.php` 등)은 애초에 헛수고일 가능성이 높다는 뜻이고, 실제로 아래 probe 배치가 전부 그렇게 나왔음.

→ **노트 `Service Enumeration` 에 복원함**(관측+인과라 박스 노트 소재가 맞음). 일반화 쪽을 `_PLAYBOOK` `B-1` 에 한 줄 덧붙일지는 단독 기록자 판단.

**참고 — playbook 쪽에 넘길 정정 1건:** `Graph-playbook.md` `A-7` 이 「크랙한 `oakland` 이 **더는 jane 의 비밀번호가 아님**」을 단정하고 있음. 위 §1 대로 **평문 변경은 관측 없음**이므로 append 시 `[가정]` 을 붙여야 함.

---

## 5. 총괄 판정

- **완료 2/2** — user `754551935abdc3b2bdde424a9b5ccb66` · root `3e823452d93d1c9c8ef9bcf9d34612eb`. 둘 다 대화형 pty 원위치 `cat` 확정. `_STATUS.md` 미편집
- **색인 갱신 필요** — 본문 수정. `refresh.ps1` 미실행(공유 인프라)
- **`_PLAYBOOK` 반영 필요** — `Graph-playbook.md` 12건 + 위 §4 정정 1건. 노트는 번호 앵커 0건이라 재배정으로 깨질 링크 없음
- **문체 이관 0건** — 서술형 종결·번역투·공개 부적합 표현 발견 없음(`pg-doc-reviewer` 선행 처리분)
