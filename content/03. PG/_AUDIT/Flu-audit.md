---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# Flu — 적대적 검증 + 정정 (웨이브 17)

대상: `03. PG\Flu.md` (개작 직후 1034행 → 감사 후 1105행)
대조본: `git show 15671e5:"03. PG/Flu.md"`(292행 최초 스냅샷) · `git show 3171152:...`(1269행 개작 직전)
증거원: `~/PG/Flu/`(nmap.log · nmap_new.log · nmap_stdout.txt · privesc_session.log · flag_evidence.txt · writeup_notes.txt · through_the_wire/) · 볼트 `파일보관\` 스크린샷 6장 · `~/.zsh_history` · Kali 직접 실행 8건

---

## 총평

**날조는 없었음.** 셸 이후 구간의 터미널 블록은 **전부** `privesc_session.log`(604행) 또는 `flag_evidence.txt` 에서 대조됨. 「관측 없음」으로 비워 둔 구간도 그대로 유지돼 있었음.

다만 **「실측을 옮기며 조용히 손본」 곳이 9군데** 있었음 — 명령줄 절단, 출력 줄 무표시 삭제, 명령/출력 불일치 1건. 방향은 날조가 아니라 **정리 충동**이지만 코드펜스 안이므로 정직성 규율 위반임. 전부 원본에서 복원함.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `urllib.parse.quote()` 콜아웃 | 🔴 **명령과 출력이 서로 맞지 않음.** 명령은 `p='${...eval(...)}'` 인데 출력은 `%24%7BClass.forName%28%22x%22%29.eval%28...` — 그 명령에서 나올 수 없는 문자열임. Kali 실행 결과는 `%24%7B...eval%28...` | 실제로 Kali 에서 돌려 얻은 스크립트 3줄 + 실제 출력으로 교체. 출처 캡션을 「타겟 아님」으로 명시 |
| `┌──(kali㉿kali)-[~] grep ... nmap-services` | 에이전트가 비대화형 `ssh kali "..."` 로 돌린 것에 대화형 프롬프트를 붙임(`~/.zsh_history` 0건) | 출력은 Kali 재실행으로 **바이트 동일 확인**. 프롬프트만 `ssh kali@10.44.44.128 "..."` 실호출 형태로 교체 |
| `┌──(kali㉿kali)-[/tmp] python3 argtest.py` | 동상. `/tmp/argtest.py` mtime 2026-08-20 12:23 = 에이전트 세션 | 동상. 출력 재실행으로 동일 확인 |
| `┌──(kali㉿kali)-[~] for s in jammy lunar; curl ...` | 동상 | 동상. Launchpad 응답 재실행으로 동일 확인 |
| `#### 반사 명령 — 5개를 한 줄로` 블록 | 🔴 명령줄이 `; getcap -r / 2>/dev/null` 에서 **절단**됨. 실제로는 `; cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.hourly/ 2>&1; crontab -l 2>&1` 이 이어짐. 그 출력이 노트 뒷부분(「크론 열거가 아무것도 없음이었는데」)의 근거인데 증거가 잘려 있었음 | 명령줄 전문 복원 + `...` + `no crontab for confluence` 복원. 절 제목을 「반사 열거 — 표준 5종을 한 줄로 묶어 한 번에」로, 후보 표에 크론 행 추가(셋 → 넷) |
| SUID 블록 | 펜스 **안**에 한국어 주석 `(이하 /snap/core22/607/... 은 위 목록의 스냅 사본이라 생략하지 않고 원문에 그대로 있다)` — 규율 위반이고 문장 자체가 자기모순(「생략하지 않고」인데 실제로는 생략함) | 펜스 안은 `...` 로, 설명은 펜스 밖 산문으로. SGID 나열에 누락돼 있던 `pam_extrausers_chkpwd` 추가 |
| `ss -lntup` 블록 | 실측 **4줄이 무표시 삭제**됨 — `udp 0.0.0.0:46761`·`udp 127.0.0.54:53`·`udp 127.0.0.53%lo:53`·`tcp LISTEN 127.0.0.54:53`·`tcp LISTEN 127.0.0.53%lo:53` | 전량 복원 + `— 출처:` 캡션 추가 |
| `ps -eo user,pid,args \| grep -v "\["` | 명령줄에서 `\| tail -40` 이 빠짐 | 복원 |
| `find / -writable` 블록 | 뒤쪽 13줄(`/snap/core22/607/...`)이 **무표시 삭제**. 산문의 「남는 줄이 20개 안쪽임」도 실제 29줄과 어긋남. 같은 명령에 이어진 `cat /etc/group \| tail -25` 도 통째로 누락 | `...` 표시 + 실제 29줄 명시. `/etc/group` 의 `lxd:x:105:`(멤버 공란)를 한 줄로 반영 |
| `/usr/lib/systemd/system/*.service` 마스킹 설명 | 「전부 `/dev/null` 로 심볼릭 링크된 마스킹된 유닛」이 **타겟에서 관측된 적 없음**(`ls -la` 미실행) | 기제는 Kali(데비안 계열)에서 실행해 확인해 근거 블록으로 넣고, **타겟 쪽은 `[가정]` + 「관측 없음」으로 강등** |
| `#### root 확인` 블록 2개 | 🔴 실제 명령이 `export TERM=xterm; id; whoami; hostname; hostname -I; echo ---; ls -la /root; echo ---; cat /root/proof.txt` 인데 노트에는 **`id` 한 줄로 다시 쓰여** 있었음. 두 번째 블록도 동일 | 실제 명령줄 전문 복원 + `ls -la /root` 출력 전량 복원(`/root` 가 `drwx------` 인데 `proof.txt` 는 `0644` 라는 뒷절 콜아웃의 직접 근거임) |
| 「`uid` 는 여전히 1001 이라 프롬프트도 `rootbash-5.2#` 로 뜸」 | **인과가 틀림.** `rootbash-5.2` 는 bash 기본 `PS1=\s-\v\$`(셸 이름 + 버전) 때문이고 uid 와 무관함. `#` 만이 `euid=0` 을 뜻함 | Kali 실행(`PS1_DEFAULT=\s-\v\$`)으로 근거를 붙여 정정 |
| 페이로드 주입 블록 | `tail -3` 앞의 빈 줄 2개가 삭제돼 「tail -3 인데 1줄만 나왔다」로 읽힘. 출처 캡션도 없었음 | 빈 줄 복원 + 캡션 + 「원본이 빈 줄로 끝나서」·「개행이 없어 `date` 가 같은 줄에 이어 붙음」 설명 추가 |
| 「남긴 흔적」 4번째 항목 | `tmux kill-session -t flunmap 으로 종료 확인` — **어느 산출물에도 없음.** 바로 아래 캡션은 「위 세 줄」이라 적어 4번째 항목이 근거 없이 떠 있었음 | 목록에서 분리해 **「관측 없음」으로 명시**. 「위 세 줄」과 항목 수를 일치시킴 |
| 개작 선언 콜아웃 | 「줄바꿈을 되붙이고 중복 에코 줄만 걷어냈음」이라 적었으나 실제로는 `echo ===MARKER` 구분자 제거와 출력 생략도 했음 | 변형 3종(하드랩 되붙이기 · 중복 에코 제거 · `echo ===MARKER` 제거)과 「자른 곳은 `...` 로 표시」를 정확히 선언 |

## 2. 삭제한 것

**없음.** 강등 1건(마스킹 유닛 → `[가정]`), 나머지는 전부 복원·정정임.

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

| 의심 | 확인 결과 |
|---|---|
| 🔴 **nmap raw 중간 절단**(웨이브 15 재발 의심) | **반증됨.** `15671e5` 최초판 · `3171152` 개작 직전 · 현재 노트의 nmap raw 블록 md5 가 **셋 다 `46bd5eab2b3f5ad9a9139d6571780233`**(105행 / 5,302B LF). 절단 없음 |
| nmap 블록이 `nmap.log` 와 다르다(헤더·푸터 형식, 후행 공백 8줄) | **반증됨.** 노트 쪽은 **stdout 형식**이고, 같은 명령의 stdout 실물(`nmap_stdout.txt`, 2차 세션)이 정확히 그 형식임(`Starting Nmap 7.98 (...) at ...` / `Nmap done: ...`). `-oN` 파일과 stdout 은 원래 다름 |
| 두 개의 `### Initial Access` 헤딩 · 두 번째에 4항목 없음 = 구조 결손 | **반증됨.** `_WRITEUP-STANDARD.md` 「단일 호스트(템플릿 4장)」 골격이 **그 자체로** `Initial Access`(4항목) → `Service Enumeration` → `Initial Access`(짧은 제목, 재현) 순서임. 노트가 템플릿과 1:1 일치 |
| 1차 세션 Kali 프롬프트 5블록이 창작 | **부분 반증.** ① 실제 창작은 **4블록**이지 5블록이 아님(작성자가 센 `head -8 51904.py` 블록은 이미 `_PLAYBOOK` 으로 이관돼 **현재 노트에 없음**) ② nmap·searchsploit·git clone·read-file·revshell 5블록은 **진짜 실측** — `~/.zsh_history` 1840~1859행에 `nnmap 192.168.103.41`·`git clone https://github.com/jbaines-r7/...`·`python through_the_wire.py ...` 가 남아 있고, 스크린샷 `141054`·`141236` 이 `┌──(kali㉿kali)-[~/PG/Flu]` 프롬프트를 그대로 찍고 있음. **손대지 않았음** |
| 「`searchsploit jamlink` 는 0건이었음」이 미검증 | **반증됨.** `~/.zsh_history:1824` 에 명령이 있고, Kali 재실행 결과 `Exploits: No Results` |
| `manual_ports: true`·`manual_services: true` 가 파서에 없는 필드일 수 있음 | **반증됨.** `extract.py:173,175` 에 `MANUAL_SVC_RE`·`MANUAL_PORT_RE` 존재, `inject.py:79-86` 이 보존함. nmap raw 의 `jamlink` 도 그대로 살아 있어 `PORT_RE` 색인에 영향 없음 |
| 작성자 자기 반증 ③(`tail -3` 근거 없음 → md5 로 교체) | **작성자가 옳았음.** `privesc_session.log` 는 04:54:36 `===DONE9` 에서 끝나 04:56 정리 구간을 담지 않음. 노트에 md5 `8364444e3d54916cc38b8bea50ebc5e2` 로 실제 반영돼 있었음 |
| 작성자 자기 반증 ②(`141017` 스크린샷 근거로 「jamlink 검색이 결과적으로 맞았다」) | **작성자가 옳았음.** 스크린샷은 Google 검색어 `8091/tcp open jamlink` 와 최상위 결과 `Atlassian, CVE-2022-26134.md` 를 그대로 보여줌. 원본 노트의 「8090」 오기도 「8091」로 정정돼 있었음 |
| 작성자 자기 반증 ①(searchsploit 제목 정정을 `A-13` 앵커로 처리) | **반영 확인.** 노트 451행 + `[[_PLAYBOOK#A-13. ...]]`, 앵커 실재 확인 |
| 검산표의 「nmap raw 109행 / 5,377바이트」 | **수치가 부정확.** 실측 105행 / 5,302B(LF). 109·5,377 은 펜스와 프롬프트 2줄을 포함해 센 값으로 보임. **동일성 주장 자체는 참** |
| 이관 손실(§0 · §6 · §7 · §8 = 333행) | **손실 없음.** §6 ①~⑫ · §7-11/12/17 · §3-1 tip · §3-3 콜아웃이 `_AUDIT\Flu-playbook.md`(861행)에 **「지우기 전 원문」 인용으로 전량 보존**. §8 15행은 두 `Vulnerability Fix:` 로 이관돼 대조표(§Z)까지 있음. §0 은 각 절 산문으로 흡수 확인 |

## 4. 검증했으나 문제 없던 것

- 플래그 3종 · DB 자격증명 · PKCS5S2 해시 — `flag_evidence.txt` 와 **바이트 동일**, 출현 횟수 4/3/3/4/1 로 전량 보존
- 스크린샷 6장 전량 직접 확인 — `140908`(푸터 `7.13.6` + URL `192.168.103.41:8090/login.action`) · `141017`(검색어 `8091/tcp open jamlink`) · `141054`(searchsploit 출력 전문) · `141213`(취약 버전 목록 7구간) · `141236`(git clone) · `142017`(`local.txt` = `2d0c7239ce98c1add6986385f076c26e`). **본문과 한 글자도 어긋나지 않음**
- 두 IP 분리(1차 `192.168.103.41` 16회 · 2차 `192.168.248.41` 3회)가 인용문 안에서 실행 시점대로 유지됨
- PoC 헤더 CVE 오타 — `through_the_wire.py:9` = `# CVE : CVE-2022-26123` 실물 확인. 노트가 「헤더 쪽이 오타」로 올바르게 판정. 프론트매터 `cves` 는 `CVE-2022-26134` 단독 + `manual_cves: true`
- argparse 기본값 5줄 — `through_the_wire.py:48-54` 와 대조해 전부 일치
- `Vulnerability Explanation / Fix / Severity / Steps` 4항목이 `Initial Access`·`Privilege Escalation` **양쪽에** 완비. `Port Scan Results` 표 존재. nmap raw 의 `22/tcp   open  ssh ...` 라인 보존
- 타겟 pty 프롬프트(`confluence@flu:...$` · `rootbash-5.2#` · `root@flu:...#`) 전량 보존 — **하나도 지우지 않았음**
- 막다른 길 기록 보존 — SUID·SGID·리스닝 포트 공백 절, DB 자격증명 절 모두 살아 있고 「`HoldingOn12` 재사용은 **배제한 것이 아니라 안 해본 것임**」 유보도 유지됨
- 펜스 균형(70개, 짝수) · 무태그 여는 펜스 0 · 크론 스크립트의 영문 원본 주석(`# Create a backup of log files`·`# Cleanup old backups`) 유지
- `_PLAYBOOK` 앵커 5종 전부 실재 확인
- 「시간 서사」 — `04:52:17` → `04:53:05`(48초) · `04:54:36` 이 `privesc_session.log`·`flag_evidence.txt` 와 일치. 산출물 mtime(2026-08-20 13:50~14:04 KST = 04:50~05:04 UTC)과도 정합

## 5. 근거 출처

- Kali 산출물: `~/PG/Flu/nmap.log` · `nmap_stdout.txt` · `privesc_session.log`(604행) · `flag_evidence.txt` · `writeup_notes.txt` · `through_the_wire/through_the_wire.py`
- git: `15671e5` · `3171152`
- 스크린샷: `파일보관\Pasted image 2026071414{0908,1017,1054,1213,1236,2017}.png`
- `~/.zsh_history:1824`(`searchsploit jamlink`) · `1840~1859`(Flu 1차 세션 명령 20건)
- Kali 직접 실행 8건 — `grep nmap-services` · `urllib.parse.quote` · `python3 argtest.py` · Launchpad API × 2 · `ls -la /usr/lib/systemd/system/*.service` · `bash --norc -i -c 'echo $PS1'` · `searchsploit jamlink`
- 볼트 도구: `_INDEX/_tools/extract.py:167-177,376,390` · `inject.py:79-86`

## 6. 총괄에 올리는 것

- **색인 갱신 필요** — 노트 본문이 바뀌었으므로 `refresh.ps1` 대상. 감사자는 돌리지 않았음
- `_STATUS.md` 판정: **완료 (2/2)** — `local.txt` `52791694c2a6ccde2db0f566f81d084f` · `proof.txt` `2caa37b3c096709c688b69556c3c6cf7`, 둘 다 `flag_evidence.txt` 의 대화형 root 셸 한 화면에 있음. 감사자는 `_STATUS.md` 를 건드리지 않았음
- `_AUDIT\Flu-playbook.md`(17건 제안)는 **총괄이 반영 중**이라 손대지 않았음. 그 파일의 검산표 중 「nmap raw 109행 / 5,377바이트」와 「코드블록 1개 변경」 두 수치는 실측과 어긋남(위 §3 참조) — 반영자가 그 표를 근거로 쓰지 말 것
