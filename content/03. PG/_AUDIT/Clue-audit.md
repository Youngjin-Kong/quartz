---
title: Clue 적대적 검증 감사 기록
type: audit
box: Clue
date: 2026-08-26
wave: 18
---

# Clue — 적대적 검증·정정 기록 (웨이브 18)

대상: `03. PG\Clue.md`(pg-note-forge 개작본 1434→806행) · `03. PG\_AUDIT\Clue-playbook.md`(이관 제안 402행)
정정 전 백업: `03. PG\_backup\Clue.md.post-forge.bak`

## 근거 출처

- git `15671e5`(사람이 쓴 최초 원본) · `607fbc5` · `aba5a29` · `_backup\Clue.md.bak2`(개작 직전)
- Kali `~/PG/Clue/` 전량 — `nmap.log`(2876B) · `47799.py` · `49362.py` · `id_rsa`(1823B, md5 `21199258ea2ab9d87443a5426f57ca1b`) · `freeswitch/`(245파일) · `cassandra/` · `CVE-2021-44142/`
- `~/.zsh_history` 해당 구간 106줄(박스 작업 전량)
- 볼트 `파일보관\` 스크린샷 11장 중 5장을 직접 열어 대조
- Kali 직접 실행 — `readlink -f /usr/bin/nc` · `sed -n '30,35p' /usr/share/exploitdb/.../47799.txt` · `ls --time-style=full-iso` · 설정본 `grep`

## 고친 것 — 노트

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `searchsploit freeswitch` 블록 | 🔴 스크린샷 `20260616164511.png` 에 **searchsploit 표 전문 + `-m` 출력 전량**이 찍혀 있는데 노트는 명령 2줄만 남기고 출력을 통째로 버림. 게다가 프롬프트를 `┌──(kali㉿kali)`/`└─$` 로 바꿔 달았는데 **스크린샷의 실제 프롬프트는 `kali@kali:~/PG/Clue$`** | 스크린샷 원문 그대로 복원(프롬프트 포함). 복원으로 `47698.rb`(Metasploit 모듈) 적중이 드러나 OSCP Metasploit 1대 제한 서술 한 줄 추가 |
| `ssh cassie@192.168.115.240` 블록 | 스크린샷 `20260616144300.png` 에 있는 `** WARNING: ... post-quantum ...` 3줄을 잘라냄 | 3줄 복원 |
| `netstat -tulpn` 블록 | 🔴 `tcp 0 0 127.0.0.1:7000 ... LISTEN -` 한 줄이 빠져 있음. **git `15671e5` 원본에는 있음**(bak2 단계에서 이미 유실, forge 소행 아님) | 원본 위치(3000 과 1337 사이)에 복원. 원본과 바이트 일치 재확인 |
| 위 블록 해설 「내부에서 본 포트 …(11개)」 | 7000 유실로 개수가 어긋남 | 12개로 정정 + 7000 을 루프백 목록에 추가 |
| 위 블록 해설 | 7000·9042·7199 의 정체가 미근거 | 약탈 설정본으로 확정 — `cassandra.yaml` `storage_port: 7000`/`native_transport_port: 9042`, `cassandra-env.sh` `JMX_PORT="7199"`+`LOCAL_JMX=yes`. 출처 명기 |
| `curl 0.0.0.0:9999` HTML 출력 | 실측 출력의 **빈 줄 3개**를 지워 「다듬음」 | 원본과 바이트 일치하도록 복원 |
| `— 출처: ~/PG/Clue/ (터미널 캡처)` ×9 | 🔴 **거짓 출처 표기.** `~/PG/Clue/` 에는 터미널 캡처 파일이 하나도 없음(nmap.log·py 2개·id_rsa·디렉터리 2개가 전부). 재구성한 텍스트에 「회수한 산출물」의 겉모습을 입힌 것 | 진짜 출처로 전량 교체 — 스크린샷 4건은 `파일보관\Pasted image ....png`, 나머지 5건은 「원본 writeup 기록 보존」 |
| `— 출처: ~/PG/Clue/49362.py 실행 결과` ×3, `~/PG/Clue/47799.py 실행 결과` ×1, `~/PG/Clue/49362.py` ×1 | 같은 계열 — 출력은 그 파일에 저장돼 있지 않음 | 스크린샷 파일명 / 「원본 writeup 기록 보존」으로 교체 |
| `— 출처: ~/PG/Clue/id_rsa` | 블록은 원본 노트의 `curl` 캡처이지 그 파일이 아님 | 「원본 writeup 기록 보존 + 회수 사본과 바이트 일치 확인」으로 교체(실제로 1823B 파일과 diff 무차이 확인) |
| `┌──(kali㉿kali)-[~]` + `readlink -f /usr/bin/nc` | 에이전트가 비대화형 `ssh kali "..."` 로 돌린 것에 붙인 **창작 프롬프트**(`~/.zsh_history` 부재) | 프롬프트 제거, 출력만 남기고 「사후 검증」 캡션. 값 자체는 Kali 재실행으로 참임을 확인 |
| `┌──(kali㉿kali)-[/tmp]` + `curl ... 18099` ×2 | 같은 유형의 창작 프롬프트 | `$ ` 로 축약, 「사후 검증」 캡션 |
| 「Connection to 192.168.239.240 closed 없이 …」 | 존재한 적 없는 문자열의 **부재**를 pty 근거로 삼는 뒤집힌 논증 | 실제 근거로 교체 — 배너 뒤 `root@clue:~#` 프롬프트 위에서 `cat`·`ls` 가 연속 실행된 것, 그리고 그 한 화면이 `Pasted image 20260622131520.png` 라는 것 |

## 고친 것 — 이관 제안(`Clue-playbook.md`)

작성자 자가신고 「코드펜스 27건 불일치, 전수 확인 결과 **실손실 0건**」은 **반증됨.** bak2 펜스 47개를 note+playbook 결합본과 재대조한 결과 미일치 17건 중 **5건이 실제 내용 손실**이었다.

| 제안 | 손실 | 조치 |
|---|---|---|
| 3 | `~/.zsh_history` pip 시도 **6줄 → 3줄**(문법 오류 3줄 삭제, 주석도 개변) | 6줄 원문 복원 + 실패 5회의 내역 명시 |
| 3 | `EXTERNALLY-MANAGED` 원문 **4줄 누락**(venv 안내 부분) | 복원 |
| 6 | 49362 인자 시도 **4줄 → 1줄** | 4줄 원문 복원 |
| 6 | argparse `usage` 출력 블록 **전량 삭제**(산문 요약으로 대체) | 복원. 단 이 출력은 bak2 본문이 밝힌 대로 **박스 정지 후 Kali 재현본**이므로 그 사실을 캡션에 명기 |
| 6 | `ssh cassie:SecondBiteTheApple330@192.168.115.240` → `ssh cassie:PASSWORD@host` 로 **값 개변** | 원문 복원 |
| 8 | IP 오타 2줄(`1921.168.115.240`)을 「일반화 가치 낮음」으로 선언 후 제외 | 선언은 정직했으나 원문 보존이 우선 — 4줄 전량 복원 |
| 검산 절 | 「실손실 0건」 | 위 표로 교체, 반증 사실 명기 |

## 삭제한 것

없음. 이번 감사에서 노트·제안 파일 어느 쪽도 내용을 삭제하지 않았다. 전부 복원·정정·출처 교체다.

## 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **`** WARNING: connection is not using a post-quantum key exchange algorithm.` 3줄이 날조 아닌가** — CLAUDE.md §3 이 「실행된 적 없는 SSH 경고 블록」을 대표적 날조 사례로 들고 있어 최우선 의심 대상이었다. **git `15671e5`(사람이 쓴 최초 원본)에 그대로 있고**, 스크린샷 `20260616144300.png`·`20260622131520.png` 두 장에도 육안으로 찍혀 있다. 진짜다. 오히려 노트 쪽이 이 3줄을 **잘라내고 있어서 복원했다.**
2. **`Starting Nmap 7.98 ... at 2026-06-15 15:42 +0900` 이 `nmap.log` 헤더(`scan initiated Mon Jun 15 15:43:00`)와 1분 어긋나므로 재구성 아닌가** — `nmap.log` 에 없는 줄이라 합성이 의심됐다. **git `15671e5` 원본에 그대로 있다.** 사람이 터미널 stdout 을 붙여넣은 것이므로 실측이고 손대지 않았다. (15:42 vs 15:43:00 의 1분 차는 미해결로 남긴다 — 원본 캡처가 우선이다.)
3. **`┌──(kali㉿kali)` 프롬프트 전반이 에이전트 창작 아닌가** — 스크린샷 `20260616140217.png` 를 열어보니 `searchsploit cassandra` 화면이 **정확히 그 프롬프트 형태**였다. 사람이 두 가지 터미널 프로파일(`kali@kali:~/PG/Clue$` 와 `┌──(kali㉿kali)`)을 섞어 썼을 뿐이며, `~/.zsh_history` 에 있는 명령(`searchsploit cassandra`·`searchsploit -m 49362`·`searchsploit freeswitch`·`searchsploit -m 47799`·`grep -ri 'passw'`·`grep -ri 'Strong*'`·`ssh-keygen -l -f id_rsa`·`ssh -i ./id_rsa root@192.168.239.240`)의 프롬프트는 전부 실측이다. **지우지 않았다.**
4. **타겟 pty 프롬프트(`root@clue:~#`) 제거 여부** — 제거되지 않았고 그대로 살아 있다. Fikklish 형 사고 재발 없음. 스크린샷 `20260622131520.png` 한 장에 `ssh` → `cat proof.txt` → `ls` → `cat proof_youtriedharder.txt` 가 연속으로 찍혀 있어 대화형 셸 판정 근거가 온전하다.
5. **`__pycache__` mtime 3분 39초 주장** — 작성자 신고가 맞다. `ls --time-style=full-iso` 재실행 결과 clone `2026-06-16 10:27:46.747984048 +0900`, `__pycache__` `2026-06-16 10:31:25.699503068 +0900` = **3분 38.95초**. 양쪽 모두 로컬(+0900) 표기라 타임존 환산 문제 없음.
6. **두 번째 `### Initial Access` 에 4항목이 없다** — 구조 결손이 아니다. 실물 기준 `03. PG\Robust.md` 도 동일하다(요약 절에만 4항목, 재현 절에는 없음). 두 `Initial Access` 제목이 서로 다른 것도 Robust 와 같은 관례다.
7. **`manual_cves: true` 인데 `cves:` 선언이 없다** — 옳다. CVE-2021-44142 는 이 박스에서 **막다른 길**이며 노트 「관련」 절이 그렇게 명시하고 있다. 되돌리지 않았다.
8. **`127.0.0.1:7000` 을 「Kali 산출물에 뒷받침이 없어 확정 불가」로 유보한 판단** — 유보할 필요가 없었다. `netstat` 출력 자체가 실측이고(사람이 쓴 원본), 정체는 약탈해 온 `cassandra.yaml` 의 `storage_port: 7000` 으로 확정된다. **부재 추론 대신 양성 증거가 있었다.**

## 스크린샷 대조 결과 (직접 열어 확인한 5장)

| 파일 | 대조 대상 | 결과 |
|---|---|---|
| `Pasted image 20260616171517.png` | `sudo -l` 블록 | 전 줄 일치. `(ALL) NOPASSWD: /usr/local/bin/cassandra-web` 확인 |
| `Pasted image 20260616144300.png` | ssh 거부 블록 | 노트가 PQ 경고 3줄을 누락 → 복원 |
| `Pasted image 20260616164511.png` | searchsploit freeswitch | 노트가 출력 전량 누락 + 프롬프트 개변 → 복원 |
| `Pasted image 20260616164751.png` | 47799.py 수정본 33행 | `PASSWORD='StrongClueConEight021' # default password for FreeSWITCH` 일치 |
| `Pasted image 20260622131520.png` | root 로그인 + 플래그 2개 | `1a6357e9c8ef5c6611ff47866ad97541` 한 글자 일치. pty 세션 확인 |

## 그 밖에 확인만 하고 손대지 않은 것

- `~/PG/Clue/freeswitch/etc/freeswitch/autoload_configs/event_socket.conf.xml` 원문 10줄 ↔ 노트 블록: **바이트 일치**
- `~/PG/Clue/id_rsa`(1823B) ↔ 노트 키 블록: **바이트 일치**
- `~/PG/Clue/nmap.log` 포트 6줄 ↔ 노트 raw 출력: 일치. `8021` 등 고포트 제외 없음(리눅스 노트)
- 47799 EDB 원본 33행 = `PASSWORD='ClueCon' # default password for FreeSWITCH` — 노트 표의 행번호·값 모두 정확
- 플래그 2개 값 노트 내 각 2회 등장, 오탈자 없음
- 원 명제 둘 다 생존 — 「한 서비스의 거부가 자격증명의 오류를 뜻하지 않음」·「주석은 키를 만든 사람이 붙인 라벨일 뿐 서버 인증에 쓰이지 않음」
- IP 3개 보존 — `192.168.115.240`(본문 다수) · `.178.240`·`.239.240`(요약 줄에 축약형, `.239.240` 은 본문에도 2회)

## 미해결 / 총괄 판단 대상

- **`~/.zsh_history` 에 있으나 노트·제안 어느 쪽에도 없는 시행착오 6종** — `smbclient -L`·`nxc smb --shares` 계열 널세션 열거 6줄, `python 47799.py 192.168.178.240 'ls -al /home/anthony/.ssh/'`, `ssh cassie@192.168.178.240:id_rsa`, 리스너 포트 `3001` 시도 2줄, `ssh-keygen -F <해시>` 오입력 1줄. **개작으로 잃은 것이 아니라 원래부터 노트에 없던 것**이라 이번 정정 범위 밖으로 두었다. 이관 웨이브에서 주울지는 관리자 판단.
- 색인 갱신 필요 — 본문 변경으로 `ports`·본문 스캔 재추출 대상. `refresh.ps1` 은 돌리지 않았다(공유 인프라, 총괄 몫).
