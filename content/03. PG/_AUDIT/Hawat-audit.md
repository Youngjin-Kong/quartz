---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# Hawat — 적대적 검증 (웨이브 9)

대상: `03. PG\Hawat.md` (개작 직후 537행 → 정정 후 554행)
대조: `03. PG\_backup\Hawat.md.bak`(496행) · `03. PG\_AUDIT\Hawat-playbook.md` · `03. PG\_WRITEUP-STANDARD.md` · 실물 기준 `03. PG\Wombo.md`·`03. PG\Robust.md`
증거원: Kali `~/PG/Hawat/` 전량 · 볼트 `파일보관\PG-Hawat-*.png` 4장 · `~/.zsh_history` · `03. PG\_AUDIT\portal-진행도-실측-20260820.md` · 회수 소스 트리 재실행

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `### Privilege Escalation – 없음 (...)` | **구조 결손.** finding 4항목(`Vulnerability Explanation`·`Vulnerability Fix`·`Severity`·`Steps to reproduce the attack`)이 통째로 없음. STANDARD 172행 「`Initial Access` 와 `Privilege Escalation` **각각**에 붙인다. 하나라도 빠지면 심사관 채점 항목이 비는 것이다」 위반. 「권한상승 없음」 박스의 실물 선례가 [[Wombo]] 에 이미 있고 거기서는 4항목을 전부 달고 값만 「해당 없음 — …」으로 채움 | Wombo 형식으로 4항목 추가. `Explanation` 은 `user root;` 인과, `Fix`·`Severity`·`Steps` 는 「해당 없음 — Initial Access 에 계상」 |
| `근거 둘 — … 포털 진행도 슬롯이 `0/1` 이었음` | **원본에서 상속된 오류.** `portal-진행도-실측-20260820.md` 실측은 Hawat **`1/1`**(n==m 22개 목록 및 §3 개수 검증 양쪽에 등재). `0/1` 은 반증됨. 논증이 실제로 기대는 것은 분자가 아니라 **분모(플래그 슬롯 1개)** 임 | 「포털 진행도의 **플래그 슬롯 자체가 1개**임(`_AUDIT\portal-진행도-실측-20260820.md` 전수 조회에서 Hawat `1/1`)」로 정정 |
| `> ```text` / `> mysql    mariadbd` (root RCE 원인 콜아웃) | **실측 표식 파괴.** `.bak` 에 있던 타겟 pty 프롬프트 + 명령 `[root@hawat http]# ps -o user=,comm= -C mysqld -C mariadbd` 가 개작에서 사라지고 출력 한 줄만 남음. CLAUDE.md §3 — 타겟 pty 프롬프트는 「대화형 셸에서 얻었는가」의 판정 근거라 **반드시 남길 것**. Fikklish 사고와 같은 방향 | 프롬프트+명령 줄 복원 |
| 같은 콜아웃, `nginx 와 php-fpm7 이 둘 다 root 로 구동되므로…` | **이관 손실.** `.bak` §3-3 의 `root nginx` / `root php-fpm7` 2행 ps 출력이 노트에서 삭제됐는데 `Hawat-playbook.md` 제안 8 은 「병합 시에도 그 2행을 실측 블록처럼 싣지 말 것」이라 **_PLAYBOOK 에도 안 들어감** → 어디에도 없음. 이 박스 전체의 중심 인과(왜 웹셸이 root 인가)를 직접 뒷받침하는 증거. CLAUDE.md §8 「근거가 없을 뿐인 서술은 `[가정]` 강등이지 삭제가 아니다」 | 2행 복원 + 「⚠️ 위 `ps` 두 블록은 **원 노트 기록**임 — 리버스셸 안에서 친 명령이라 `~/PG/Hawat/` 에도 `~/.zsh_history` 에도 남지 않음」 명시 |
| 포트 판정 표 `30455 … `phpinfo.php` 노출` | **이관 손실(소).** `.bak` 의 판정 근거는 phpinfo 의 **`Server API = FPM/FastCGI`** 였음. 「FPM 인지 mod_php 인지」가 root 구동 판정으로 이어지는 고리인데 개작이 「노출」로 뭉갬. 제안 12 는 일반론으로만 가져감 | 근거 문자열 복원 + `(원 노트 기록 — 본문 산출물 미보존)` 표기 |
| `` `application.properties` 의 JDBC URL 에 `allowMultiQueries` 파라미터가 없고 `` | **근거를 엉뚱한 곳에 걺.** 주입이 도는 커넥션은 `IssueController` 가 직접 여는 `DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker", connectionProps)` 이지 Spring 데이터소스가 아님. 결론(스택 쿼리 불가)은 옳으나 근거가 어긋남 — 실측으로 **양쪽 모두** 파라미터 없음 확인 | 컨트롤러 URL 과 `application.properties` URL(`...?serverTimeZone=UTC`) 양쪽을 명시 |
| `![[PG-Hawat-17445_register.png]]` | 4장 중 이 한 장만 캡션 없음 | 스크린샷 실물 확인 후 캡션 1줄 추가(가시 입력은 Username·Password 둘뿐, `userId` 는 hidden — `user_form.html` 35행과 일치) |
| `Initial Access` 재현 절 서두 | 출처 캡션이 붙은 블록과 안 붙은 블록의 지위 차이가 독자에게 안 보임 | 「출처 캡션이 붙은 블록만 산출물로 보존. 캡션 없는 출력 블록은 셸 안에서 친 명령이라 **원 노트 기록**」 1줄 추가(인식론적 표시 — 작업 과정 기록 아님) |
| `_AUDIT\Hawat-playbook.md` 검산 569행 `(신규 8 · 기존 병합 5)` | **자기 모순.** 바로 아래 열거는 신규 7(제안 1·2·3·6·7·11·12) · 병합 6(제안 4·5·8·9·10·13). 합계 13 은 같으나 분해가 틀림 | `(신규 7 · 기존 병합 6)` 으로 정정 |

## 2. 삭제한 것

**없음.** 이번 사이클의 정정은 전부 추가·복원·문자열 교체다. 강등도 새로 만들지 않았다(개작자가 이미 2건을 강등해 뒀고 둘 다 타당했다 — §3 참조).

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

1. **「Kali 프롬프트를 지운 것이 레거시 실측 파괴 아닌가」 — 반증됨.** `~/.zsh_history` 에 `hawat`·`192.168.248.147`·`17445`·`30455`·`50080` 히트가 **0건**. zsh 는 대화형 세션에서만 히스토리를 쓰므로, 이 박스는 비대화형 `ssh kali "..."` 로 풀렸고 `.bak` 의 `┌──(kali㉿kali)` 프롬프트는 창작이었다. **제거가 옳다.** 반대로 `[root@hawat http]#` 는 타겟 pty 라 보존이 옳다 — 개작자의 양방향 판정이 정확했다.
2. **「nmap 코드펜스가 압축·생략된 날조 아닌가」 — 반증됨.** `~/PG/Hawat/nmap.log` 와 바이트 대조: 헤더부터 TRACEROUTE 까지 **완전 일치**. 잘린 것은 말미 2줄(`OS and Service detection performed…` / `# Nmap done at …`)뿐이고 내용 변조·한국어 주석 삽입 없음.
3. **「gob_50080 블록이 재배열된 발췌 아닌가」 — 반증됨.** 원본 26행 중 7행 선별인데 **상대 순서가 원본 그대로**이고 노트가 「발췌 — 403 만 뱉는 `.ht*`·`~user` 계열 다수 생략」이라고 명시함.
4. **총괄 지시 ⓖ 「작성자 보고 행수 538 vs 실제 537」의 파급 우려 — 반증됨.** 다른 수치를 표본 대조했으나 **전부 산출물과 일치**: `allports.nmap` 44.42초/09:15:39~09:16:23 · `nmap.log` 50.80초/09:15:12~09:16:03 · `services.nmap` 17.91초 · `issuetracker.zip` 164010B · md5 `cd816a09d8608c3b24b4e8c5c212640c`(재계산) · `/phpinfo.php` 200/68610B · `cj.txt` 09:18:24 `JSESSIONID B34662FE…` · `cj2.txt` 09:25:42 `208A8537…` · `oracle.sh` 09:18:41 · `probe.py` 09:21:21 · `blind.py` 09:22:38 · `shell.py` 09:23:20. **행수 1 차이는 보고서의 오기이지 노트의 결함이 아님.**
5. **「소스 인용의 행번호가 깊이 초과(소스 고고학) 아닌가」 — 자기 반증.** STANDARD 가 금하는 것은 **패치 diff·바이트 대조** 부류이고, 여기 행번호는 심사관이 취약 지점을 찾아가는 한 줄짜리 인용 표기임. 게다가 전부 실측과 일치 — `@GetMapping` 60행 · `createStatement()` 72행 · `executeQuery` 73행 · `printStackTrace()` 77행 · `GetAll()` 81행 · 메서드 종료 85행 · `WebSecurityConfig` 27~30행 · `Users.userId` 25행 · `user_form.html` 35행. **손대지 않음.**
6. **「grep 블록이 재구성된 날조 아닌가」 — 반증됨.** 회수 소스 트리에서 동일 grep 을 직접 재실행해 **3행이 문자 단위로 일치**함을 확인:
   ```
   ./src/main/java/com/issue/tracker/issues/IssueController.java:6:import java.sql.Statement;
   ./src/main/java/com/issue/tracker/issues/IssueController.java:72:		    Statement stmt = conn.createStatement();
   ./src/main/java/com/issue/tracker/issues/IssueController.java:73:		    stmt.executeQuery(query);
   ```
7. **「스크린샷 서술이 실물과 다르지 않은가」 — 반증됨.** `PG-Hawat-17445_issuetracker.png` 를 직접 열어 확인: Priority 열 값이 `Unbreak`·`Normal`·`Normal`, 우상단에 Register/Sign In(비로그인 상태) — 노트 서술과 일치. `PG-Hawat-30455_root.png` 도 W3.CSS 템플릿으로 nmap `http-title: W3.CSS` 와 일치.
8. **총괄 지시 ⓖ 「플래그 값이 `~/PG/` 에 없다」 — 노트는 이미 이 한계를 정확히 적고 있었다.** `Post-Exploitation` 의 「⚠️ 증거 형식의 한계」 문단이 `proof_user.txt`·`proof_root.txt` 부재와 tmux 스크롤백 미보존을 명시하고, 「대화형 셸에서 읽었다」의 근거가 pty 프롬프트뿐임을 밝힘. **본문 어디에도 「산출물에 있다」는 취지의 서술이 없음.** 부재 증거의 등급 상한은 `근거부족` 이고 노트가 그 등급대로 쓰여 있음 — 지적 불성립.
9. **개작자의 강등 2건은 둘 다 타당.** ①`userId=0` 을 빼면 400 → `[가정]` 강등: `Users.java` 25행이 `private int userId;` 원시형임은 소스로 확인되나, **필드를 아예 생략한** 요청의 응답은 산출물에 없음. 강등이 정확함. ②「아웃바운드 443만 허용 / 4444 는 안 붙는다」 → 성공 회선만 확정으로 강등: nmap `443/tcp closed` 는 **인바운드** 결과라 egress 근거가 될 수 없음. 정확함.
10. **`src/`(09:16:59)가 `issuetracker.zip`(09:17:14)보다 «이른» 시각인 점** — 시간 서사 모순으로 올릴 뻔했으나 노트는 이 둘의 선후를 주장하지 않고 구간 양끝으로만 씀(`src/issuetracker` 는 09:17:14 로 zip 과 동일). 지적 불성립. 타임존 문제도 없음 — nmap 로그 본문과 `ls` mtime 이 **둘 다 로컬(+0900)** 이라 환산 대상 아님.

## 4. 근거 출처

- Kali 산출물: `~/PG/Hawat/{nmap.log,allports.nmap,services.nmap,gob_30455.txt,gob_50080.txt,cj.txt,cj2.txt,oracle.sh,exploit.py,probe.py,blind.py,shell.py,issuetracker.zip,src/}` — 전량 열람, 코드펜스 바이트 대조
- 회수 소스: `~/PG/Hawat/src/issuetracker/` 의 `IssueController.java`·`WebSecurityConfig.java`·`Users.java`·`user_form.html`·`application.properties`·`pom.xml`
- 직접 실행: `md5sum issuetracker.zip` · `grep -rn -iE 'createQuery|…' --include='*.java' .` · `sed -n` 행번호 대조 · `grep -c hawat ~/.zsh_history`
- 볼트: `파일보관\PG-Hawat-{17445_issuetracker,17445_register,30455_root,50080_cloud_login}.png` 4장 직접 열람 · `03. PG\_AUDIT\portal-진행도-실측-20260820.md`
- 기준: `03. PG\_WRITEUP-STANDARD.md` 100~215행 · 실물 선례 `03. PG\Wombo.md` 364~372행

## 5. 항목별 통과 여부

| 항 | 판정 |
|---|---|
| ⓐ finding 4항목 | ❌ → ✅ **정정.** `Privilege Escalation` 4항목 결손을 Wombo 형식으로 보충. 첫 `Initial Access` 는 4항목만 있었음(통과) |
| ⓑ 코드펜스 원문성 | ✅ 통과. nmap·gobuster·cj.txt·oracle.sh·probe.py·blind.py·shell.py·소스·grep 전부 바이트 일치. 날조·한국어 주석 삽입 없음 |
| ⓒ 이관 손실 0 | ❌ → ✅ **2건 복원**(ps 2행 · `Server API = FPM/FastCGI`). 나머지는 `.bak` 전 절 대조 결과 노트 또는 playbook 에 보존됨. 삭제=append 건수는 13=13 (분해 표기 오류 1건 정정) |
| ⓓ nmap raw · 헤딩 · 두 제목 상이 | ✅ 통과. `22/tcp   open  ssh …` 원문 보존(PORT_RE 정상) · `## Target #1` / `###` · 긴 서술형 / 짧은 기법명으로 상이 |
| ⓔ pty 판정 양방향 | ❌ → ✅ **정정.** Kali 프롬프트 제거는 옳음(zsh_history 0건). 타겟 pty 보존도 옳음. 단 `ps` 블록의 pty 프롬프트가 문체 정리로 잘려나가 복원 |
| ⓕ 상속 오류 | ❌ → ✅ **1건 정정**(포털 `0/1` → 플래그 슬롯 1개, 실측 `1/1`) |
| ⓖ 플래그 출처 · 수치 | ✅ 통과. 노트가 증거 한계를 명시. 표본 13개 수치 전부 산출물과 일치 |
| 깊이 초과 | ✅ 통과. 소스 고고학 부류(패치 diff·바이트 대조) 없음. 행번호 인용은 유지 판단 |
| 재접속 전제 서술 | ✅ 없음 |
| 색인 | ✅ `manual_tags: true` · `tech_count: 5` — sqli·webdav·default-creds·mysql·revshell 전부 실제 사용. `manual_cves` 불요(본문에 CVE 번호 없음) |

## 6. 총괄에 넘길 판정

- **`_STATUS.md`: Hawat = 완료 `1/1`** — 포털 실측 `1/1`(제출 완료), 플래그는 `proof.txt` 단일. 노트 상태 정상. **직접 편집하지 않음**(CLAUDE.md §6)
- **색인 갱신 필요** — 노트 537→554행, 본문 변경 있음. `refresh.ps1` 은 총괄 몫이라 실행하지 않음
- `Hawat-playbook.md` 13건은 아직 `_PLAYBOOK` 에 반영 전 상태로 확인됨(제안 파일이 「`_PLAYBOOK` 파일은 열지 않았음」이라고 밝힘). **단독 기록자가 번호를 배정해 append 해야 이관이 실제로 닫힘**
