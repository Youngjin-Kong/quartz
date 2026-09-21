---
type: audit
target: "[[Crane]]"
wave: 14
date: 2026-08-26
manual_tags: true
manual_cves: true
manual_ports: true
ports: []
---
# Crane — 적대적 검증 · 정정 기록 (웨이브 14)

**대상**: `03. PG\Crane.md` (개작 직후 579행 → 감사 후 593행)
**원본**: `03. PG\_backup\Crane.md.bak2` (1049행)
**이관 제안**: `03. PG\_AUDIT\Crane-playbook.md` (20건)

**근거 출처**
- Kali `~/PG/Crane/` — `nmap.log`(1662B) · `nmap_full.txt`(730B) · `ferox.log`(94047B · 1085행) · `resp.txt`(2687B) · `c.txt`(275B) · `install.log`(51295B · 687행) · `CVE-2022-23940/`(`exploit.py`·`README.md`·git 메타)
- Kali 직접 실행 — `grep -c -iE 'crane|248\.146' ~/.zsh_history` → **0** (히스토리 mtime 2026-08-25 16:07, 생존) · `grep -n 'nnmap' ~/.zshrc` → 247행 · `sed -n '128,145p' /usr/sbin/service` · `git log`/`git status --porcelain` (PoC 클론본)
- 볼트 — `_backup\Crane.md.bak2` · `_PLAYBOOK.md` 앵커 전수 grep
- 스크린샷: 이 박스는 임베드 0개. **부재를 근거로 삼지 않았음.**

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `하나는 \`nnmap\` 별칭(...)` | `nmap.log` 가 스스로 기록한 명령줄은 `-oN /home/kali/PG/Crane/nmap.log`(**절대경로**)인데 `~/.zshrc:247` 의 별칭은 `-oN nmap.log`(상대). 「별칭 그대로」는 성립하지 않음 | 「플래그 조합이 `nnmap` 별칭과 동일. 단 기록된 명령줄의 `-oN` 은 절대경로라 별칭 그대로는 아님」 |
| `— 출처: \`~/PG/Crane/resp.txt\`` | `resp.txt` 는 2687B 이고 헤더 뒤에 2216B 응답 본문이 이어짐. 노트는 헤더까지만 싣고 **생략 표기가 없었음** | 캡션에 「헤더까지. 뒤따르는 응답 본문 2216B 는 생략」 추가 |
| `**searchsploit**` 절 | 결과 4행은 남았으나 **명령 `searchsploit suitecrm` 이 소실**(Kali 프롬프트 블록을 걷어내며 함께 사라짐). 재현 불가 | `\`\`\`bash searchsploit suitecrm\`\`\`` 펜스를 결과 블록 앞에 복원(`.bak2` 204행 기준) |
| `**\`name\`·\`status\`·\`schedule_type\`·\`Referer\` 를 빼면 레코드 생성이 실패함.**` | **미검증 단정.** 확정된 사실은 「`exploit.py`·README 가 그 6필드 + 두 헤더를 보낸다」까지. 하나씩 빼서 실패를 확인한 적 없음(타겟 정지). 표준 「단정형 일반 지식은 때려보고 넣는다」 위반 | 단정을 제거하고 `[가정]` 문단으로 강등 — 「필수인지는 미검증. 수동 재현 시에는 전부 넣고 시작할 것」 |
| `— 출처: Kali \`/usr/sbin/service\` 49행 ... 132~140행` | 행번호는 **실측과 일치**(49 `SERVICEDIR` · 132 `run_via_sysvinit` · 137 `unrecognized service` · 140 `}`). 다만 표준이 「소스 `파일:행번호` 인용」을 깊이 초과로 명시 | 행번호를 걷어내고 `(\`init-system-helpers\` 패키지)` 로 대체. **틀려서가 아니라 과잉이라 걷음** |

## 2. 되살린 것 — 이관 손실

`.bak2` 를 하위 단위로 훑어 `Crane-playbook.md` 의 ④ 인용과 대조한 결과, 제안서가 **「이관 아님 — 노트로 흡수」로 자기 신고한 항목에서 실제 손실 5건**이 나왔다.

### (a) 8장 「방어 관점」 9행 중 4행이 어디에도 없음

제안서 검산표는 `| 8장 방어 관점 9행 | 이관 아님 — 노트의 두 Vulnerability Fix: 로 분산 흡수 |` 로 적었으나, 대조 결과 흡수된 것은 5행뿐이었다(is_array 우회 · unserialize sink · 7.12.3 미패치 · admin:admin · PHPSESSID HttpOnly). **나머지 4행은 노트에도 제안서 ④ 에도 없었다.**

지워진 원문:

> | `/install.log`(51KB) 웹루트 노출 | 설치 완료 후 인스톨러 산출물(`install.log`·`install/` 등)을 삭제하거나 웹루트 밖으로 옮긴다. 설치 로그에는 경로·버전·구성요소 목록이 남고, 제품·설정에 따라 자격증명이 섞이는 경우도 있다. 웹서버 레벨에서 `.log` 확장자를 거부 규칙으로 차단 |
> | MySQL `root` / 빈 패스워드 | 애플리케이션 전용 계정을 별도 생성하고 필요한 DB에만 최소 권한. root 비밀번호 설정 및 `FILE` 권한 회수 |
> | DB 자격증명 평문 저장(`config.php`) | 파일 권한을 웹서버 사용자 읽기 전용으로 제한. 환경변수/시크릿 관리자 사용 |
> | 심층 방어 | 아웃바운드 egress 필터링 — 서버가 임의 포트로 나가지 못하면 리버스셸이 붙지 않는다. RCE가 나도 피해가 줄어든다 |

복원 위치 — 앞의 둘 중 `install.log` 와 egress 는 `Initial Access` 의 `Vulnerability Fix:` 에, MySQL·`config.php` 는 자격증명이 실제로 등장하는 `Post-Exploitation` 자격증명 문단 아래에(그 finding 의 취약점이 아니므로 4항목에 끼워넣지 않음).

### (b) nmap 해설 「httponly flag not set」 행

지워진 원문:

> | `httponly flag not set` | 세션 탈취 XSS 가능성 신호. 이 박스에서는 쓰이지 않았다 |

`Vulnerability Fix:` 의 `session.cookie_httponly` 불릿에 관측 근거로 합쳐 복원(「nmap NSE 가 `httponly flag not set` 을 잡아냈음」).

### (c) 정찰 결론 「공격면은 80 하나」

지워진 원문:

> 공격면은 사실상 **80번 하나**다. 3306은 원격 접속 허용 목록에 없어 `MySQL (unauthorized)`로 튕기고, SMB/NFS/RPC는 전수 스캔에서 전부 closed였다.

`Service Enumeration` 3306 문단 뒤에 한 줄로 복원. 두 raw 가 스스로 뒷받침함(열린 포트 22·80·3306·33060 넷뿐).

### (d) 제안서 자체의 절차 결함 — 보고 대상, 파일은 손대지 않음

원본 **0장(「이 박스에서 배우는 것」 5불릿 · 「시험 출제 가능성」)** 은 검산표에서 제안 10·11·12·2 로 매핑됐으나 **④ 「지우기 전 원문」 인용이 한 곳도 없다.** 표준의 「지우기 전 원문을 같은 파일에 인용해 둔다 — 이관 손실 검산의 유일한 근거」 위반. 다만 `.bak2`(24~44행)와 git 이력이 원문을 보존하고 있어 **복구 불능은 아니다.**
그중 「변형 예상」 목록(Laravel `Ignition`·Drupal·Magento·Zabbix·Cacti·phpMyAdmin)은 제안 ③ 본문 어디에도 실리지 않았다 — 반영자가 `B-1-37`·`B-1-29` 에 넣을지 판단할 것.

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

**이 절이 검증 절차 자체의 정확도 근거다. 다섯 건 전부 내 지적이 뒤집힌 것이다.**

| 내가 세운 지적 | 반증 근거 | 결론 |
|---|---|---|
| **Kali 프롬프트 10곳 제거로 실측이 파괴됐다** | ① `~/.zsh_history` 에 `crane`·`248.146` **0건**(히스토리는 8/25 까지 생존) ② 그보다 강한 **양성 증거** — `nmap.log` 가 스스로 기록한 명령줄이 `-oN /home/kali/PG/Crane/nmap.log`(절대경로)인데 `.bak2` 의 프롬프트 블록은 `~/PG/Crane` 에서 `-oN nmap.log`(상대)로 친 것처럼 그려져 있었음. **대화형 세션이었다면 나올 수 없는 불일치** ③ 제거된 10블록의 명령·출력을 전수 대조한 결과 소실은 `searchsploit suitecrm` **한 줄뿐**(§1 에서 복원) | **제거가 옳았음.** 부재 증거만이 아니라 양성 증거가 있었음 |
| **README 인용 PHP 블록의 경로 주석을 개변했다** — `.bak2` 는 `// modules/AOR_Scheduled_Reports/...` 인데 노트는 `// SuiteCRM-Core/public/legacy/modules/...` | `~/PG/Crane/CVE-2022-23940/README.md` 원문이 **긴 쪽**임. `.bak2` 가 축약한 것이고 노트가 1차 사료로 되돌린 것 | **노트가 옳음.** 충실도가 올라간 정정 |
| **`gmt_time` 캡션이 자기모순** — 응답 시각이 산출물 mtime 보다 이르다 | 로그 본문은 **UTC**, `ls` mtime 은 **로컬(KST)**. 07:53:08 UTC = 16:53:08 KST 이고 마지막 산출물 mtime 은 16:52:49 KST → **19초 뒤**. 캡션의 「직후」가 정확함 | **노트가 옳음.** 내 미환산 오류 |
| **`_PLAYBOOK` 앵커 8건 중 댕글링이 있다** | `_PLAYBOOK.md` 전수 grep — `A-12`(95행) `A-14`(193) `A-1-11`(328) `A-31`(1174) `A-38`(1485) `B-1-29`(2990) `B-1-37`(3220) `B-81`(4479). **8/8 실재.** 신규 제안 앵커는 노트에 하나도 걸려 있지 않음(정상) | **노트가 옳음** |
| **「`password` 44행이 전부 한 문구」가 과장** — grep 에 `ERROR::` 와 `.....` 두 형태가 보임 | `grep -i password install.log \| sed -E 's/^[0-9-]+ [0-9:]+//' \| sort -u` → 결과 **2행**, 차이는 로그 레벨 접두(`...ERROR::` / `.....`)뿐이고 메시지 본문은 동일. `grep -c` = **44** 도 일치. 인용한 151행도 바이트 일치 | **노트가 옳음.** 「값은 없음」 판정 유효 |

## 4. 대조 결과 — 이상 없음으로 확인한 것

- **nmap raw 2종 무손실** — `nmap.log` 39행 · `nmap_full.txt` 12행이 선두 `# Nmap ... initiated` 명령줄과 말미 `# Nmap done` 까지 **전량 그대로**. `PORT_RE` 가 긁을 `22/tcp open ssh …` 형태 보존. `.bak2` 는 `nmap_full.txt` 를 **아예 누락**했고 `nmap.log` 도 선두·말미를 잘랐으므로, 개작이 raw 보존을 개선한 것
- **판정 갈림·`[가정]` 서술 존재** — 80 이 `Apache httpd 2.4.38` vs `tcpwrapped`, 동시 프로빙 추정에 `[가정]` + 「실제 원인은 확인하지 않음」 명시 ✅
- **`ferox.log` 인용 18행 전량 바이트 일치**(285·286·287·291·648·649·650·653·715·906·933… 라인 대조). 상태코드·응답 길이 컬럼까지 원문 그대로
- **`exploit.py` 인용 3상수 바이트 일치.** 「INFO 직후 Save POST → 응답 오면 `Succesfully created …`」 로그 순서 서술이 소스와 일치. `git status --porcelain` 공백 · `git log` 에 `bd51e74 FIX: added auto trigger rev sh` 존재 → 노트 서술 확인
- **PoC README 인용**(PHP 코드 · HTTP 요청 원문 · 7.12.5/8.0.4 패치 버전 · *"any user with permission to create Scheduled Reports…"*) 전부 원문 일치
- **`install.log` 151행 인용** 바이트 일치
- **타겟 pty 프롬프트 13곳 전량 보존**(`.bak2` 13 → 노트 13). 노트 15회는 `Post-Exploitation` 산문에서 「대화형 셸이었다는 유일한 증거」로 2회 더 언급한 것. **한 곳도 제거되지 않았음**
- **구조** — `## Target #1 – 192.168.248.146` 래퍼, 하위 전부 `###`. 두 `Initial Access` 제목 상이(긴 서술형 / 짧은 형). `Port Scan Results` 표 존재. `Initial Access`·`Privilege Escalation` **각각** 4항목 완비. 4항목 안에 「아래」·「위」 상대 참조 **0건**
- **코드펜스 27개 전부 언어 태그**(감사 후 기준. `text`·`bash`·`python`·`http`·`php`·`sh`). 펜스 안 한국어 주석·해설 **0건**
- **플래그 2개 값 무손실** — `dd091466af4faca653da308c6d836aa1` · `f92c362a87099978dbf8f3f108147934`. 「한 화면 증거 미수집」 유보와 pty 프롬프트가 유일 증거라는 서술 유지 ✅
- **프론트매터** — `manual_tags: true`·`manual_cves: true` 선언 존재, 값 줄에 주석 없음. `tech/*` 6개 전부 실사용(deserialization·default-creds·sudo-abuse·dirbust·searchsploit·revshell). `cves: [CVE-2022-23940]` 단독 — 반증용 CVE 혼입 없음. `ports` 는 두 raw 모두 4포트뿐이라 `manual_ports` 불요
- **시험 규정** — phpggc·공개 PoC 허용 판정. 표준 원문과 일치, 과잉 금지 없음
- **`tmux`/`nc` 내부 모순 해소** — `.bak2` 는 `tmux new-session -d -s crane 'rlwrap nc -lvnp 4444'` 로 detached 기동해놓고 뒤에서 다시 `└─$ rlwrap nc -lvnp 4444` 를 전경 실행한 것처럼 그렸음. 노트는 뒤 명령줄을 걷고 출력만 남긴 뒤 「출처: tmux 세션 `crane` 의 리스너 출력」 캡션을 붙임 ✅
- **「응답이 성공을 뜻하지 않는다」 인과 보존** — 「Save POST 가 반환되지 않았다 → 역직렬화가 요청 처리 도중 인라인 발화 → 리버스셸이 요청 스레드를 붙잡음」 3단 인과가 살아 있음. 상호링크 5건 유지

## 5. 넘긴 것

- **문체 이관 1건** → `pg-doc-reviewer`. 서술형 종결 1곳(`… 를 찍는다.` — 「스크립트가 굳고 결국 타임아웃됨」 문단). 나머지 산문은 명사 종결형

## 6. 판정

**완료 2/2** — `local.txt` `dd091466af4faca653da308c6d836aa1`(`/var/www/local.txt`) · `proof.txt` `f92c362a87099978dbf8f3f108147934`(`/root/proof.txt`). 두 값 모두 노트 본문에 보존돼 있고 대화형 pty 프롬프트가 획득 맥락을 뒷받침한다.

**색인 갱신 필요** — 본문 편집으로 행수·본문이 바뀌었다. `refresh.ps1` 은 총괄 몫이라 실행하지 않았다.
