# BossPlayersCTF — 적대적 검증 + 정정 기록

- 대상: `03. PG\BossPlayersCTF.md` (감사 전 286행 → 감사 후 344행)
- 감사일: 2026-08-21
- **git baseline 없음** — 노트가 이번 웨이브에서 신규 생성돼 커밋 이력이 0건임(`git log --oneline -- "03. PG/BossPlayersCTF.md"` 무출력, `git status` = `??`). 개작 전후 대조는 불가하고, 검증은 전량 Kali 산출물·1차 사료 대조로 수행함.

## 근거 출처

| 종류 | 경로 / 대상 |
|---|---|
| Kali 산출물 | `~/PG/BossPlayersCTF/` 전량 (nmap 5종, `index_raw.txt`, `decode_chain.txt`, `robots.txt`, `param_*.html` 8종 + `wip_noparam.html`, `shell443.log`, `session_bpc-shell.txt`, `proof_user.txt`, `proof_root.txt`, `harvest_www-data.txt`, `logs.php.html`, `recon-driver.log`, `_SUMMARY.txt`, `writeup_notes.txt`, `web-80/*`, `svc/*`) |
| 스크린샷 | 볼트 `파일보관\PG-BossPlayersCTF-{index,robots,workinginprogress,rce-cmd-id}.png` 4장 — **직접 열어 본문과 대조함** |
| 셸 히스토리 | `~/.zsh_history` — BossPlayers 관련 항목 **0건** |
| 스크립트 원본 | `~/PG/_lib/harvest.sh` (SUDO 절 로직 확인) |
| 1차 사료 | GTFOBins `find` 페이지(Kali 에서 `curl -sL https://gtfobins.github.io/gtfobins/find/`), `man bash` INVOCATION 절 |
| 직접 실행 | Kali 에서 `test -u` 로 SUID 기본값 14경로 대조, `dash -p -c` 실행, `ls -l /bin/sh` |

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| §1 `top-100 UDP 는 전부 closed` / §6 `UDP top-100 이 전부 closed` | **판독 오류.** `nmap-udp-top100.txt` 원문은 `Not shown: 90 open\|filtered udp ports (no-response)` + closed 10개. 90개는 «무응답»이라 열림/필터링 미구분이지 closed 가 아님. `--max-retries 1` 이라 신뢰도도 낮음 | 두 곳 모두 "10개 closed / 90개 `open\|filtered`(무응답) → UDP 는 판정 보류"로 정정. UDP 부재 단정을 제거 |
| §0 · §9 `GTFOBins 정석 find . -exec /bin/bash -p \; -quit` | **1차 사료와 불일치.** GTFOBins 원문은 `/bin/sh` 임(직접 fetch 확인) | "원문은 `/bin/sh`, 여기서는 bash 로 바꿔 씀"으로 정정. §9 에 URL 명시 |
| §1 `(recon-driver.log: "recon.sh 기동 + 수동 nmap 병행")` | **출처 오귀속.** 그 문자열은 `recon-driver.log` 에 없고 `writeup_notes.txt` 3행에 있음 | 출처를 `writeup_notes.txt`(작업 기록)로 교체, 인용도 원문 그대로로 교체 |
| §2 `(recon-driver.log: "파라미터 배치 퍼징 8개")` | **출처 오귀속.** `writeup_notes.txt` 11행 | 동일 |
| §3 `(recon-driver.log: "bash -c 'bash -i >& …'", "443 으로 즉시 connect-back 성공")` | **출처 오귀속.** `writeup_notes.txt` 13~14행 | 동일. 아울러 "작업 기록에만 남아 있음"을 명시해 캡처가 아님을 드러냄 |
| §5 `플래그 증거 한 화면(proof_user.txt)` / `proof_root.txt:` | **출처 오귀속.** 인용된 블록은 프롬프트(`www-data@bossplayers:…$`, `bash-5.0#`)가 붙은 형태인데 `proof_*.txt` 는 `script` 캡처라 프롬프트가 없음. 실제 출처는 `shell443.log` 11~17행 / 64~70행 (말미 공백 `192.168.248.20 ` 까지 일치) | 출처를 `shell443.log` 로 교체하고 행번호 명시, `proof_*.txt` 에도 같은 캡처가 있음을 병기 |
| §1 `probe-index.txt 의 24개 개별 프로브 … 전부 404, /server-status 만 403` | **내부 모순 + 수치 오류.** 실제 26행: 404×24, 200×1(`/robots.txt`), 403×1(`/server-status`) | "26종 중 24종 404, `/robots.txt` 200, `/server-status` 403" |
| §3 shell443.log 인용 블록 | **실측 블록의 무표시 생략.** 원문 5행(`<r(110)+chr(47)+…` — pty 승격 명령의 잘린 에코)을 말없이 빼고 1~4행 + 6~10행을 연속인 것처럼 제시 | 5행 복원. 캡션을 "1~10행 전량"으로 명시 |
| §4 curl 실패 블록 | 원문 `wc: /tmp/harvest_www.txt: No such file or directory` 행과 프롬프트 접두를 생략 | `shell443.log` 18~28행 전량으로 복원 |
| §5 `/root/root.txt` 미끼 블록 | 명령줄과 `---` 사이의 실제 출력 2행(`수집 완료: …`, `833 …`)을 생략 | 복원 + 왜 그 두 줄이 거기 있는지 캡션 |
| §4 SUID 목록 | `harvest_www-data.txt` 의 14행 중 뒤 3행(`dbus-daemon-launch-helper`·`ssh-keysign`·`dmcrypt-get-device`)을 잘라내고 "SUID 목록"이라 제시 | 전량 복원 + "전량" 명시 |
| §4 `sudo -l 이 아니라 명령이 없어 "no such command" 류` | **미검증 추측.** `harvest.sh:30` 이 `command -v sudo` 로 분기하는 구조임을 확인 | "`command -v sudo` 로 존재를 먼저 확인하고 없으면 `sudo -l` 을 실행하지 않는 구조"로 사실화 |
| §2 스크린샷 캡션 `?cmd=id` 결과 … 스크린샷: [[…rce-cmd-id.png]] | **스크린샷이 본문에 반박.** 이미지를 직접 열어보니 마지막 줄이 `uid=33(…) Linux bossplayers 4.19.0-6-amd64 …` 로 `id` + `uname -a` 출력임. `param_cmd.html`(=`?cmd=id`)과 다른 요청 | "명령 두 개를 이어 붙인 별도 요청"으로 정정. 연결자(`;`·`&&`·`\|`)는 요청 원문이 없어 확정 불가로 유보 |
| §1 index 주석 + 스크린샷 배치 | 주석 코드블록 바로 뒤에 스크린샷을 붙여 «주석이 화면에 보인다»는 오독을 유발. 실제 이미지는 렌더된 페이지라 주석 없음 | "아래 스크린샷이 렌더된 화면이고 주석은 여기 나타나지 않음"을 명시. 아울러 `</html>` 뒤 **빈 줄 118개**(실측 카운트) 뒤에 주석이 숨어 있다는 실제 은닉 방식을 보강 |
| §7 `이 박스는 사용 가능한 도구가 curl(반복 요청)뿐이었지만` | **근거 없는 단정.** 도구 가용성 기록 없음 | 삭제하고, 재현 명령은 "**재현용 템플릿**이지 이 박스에서 캡처된 명령이 아님"으로 명시 |
| §7 `약 5분(15:58~16:03)` | 부정확 | `nmap-quick-ports.txt` 헤더(15:58:59) → `proof_root.txt` mtime(16:03:20) = **약 4분 20초**, KST 기준임을 명시 |
| §0 `미니멀 Debian 이미지에는 wget/python 만 있는 경우가 흔함` | **미검증 일반화** | 이 박스 실측(`wget`·`python`·`python3` 있음, `curl` 없음)으로 교체 |
| §4 `bash -p 의 -p 옵션이 …` | 서술은 옳으나 근거 없음 | `man bash` INVOCATION 원문 인용을 §4·§9 에 추가(Kali 에서 직접 확인) |
| 프론트매터 | `ports`·`ip`·`services`·`difficulty`·`flags` **전부 누락** | `ip: 192.168.248.20` / `ports: [22, 80]` / `services: [ssh, http]` / `difficulty: Fundamental` / `flags: 2` 추가. 값이 든 줄에는 주석을 붙이지 않음 |
| 태그 | 리버스셸을 실제로 썼는데 태그 없음 | `tech/payload/revshell` 추가. `tech/web/rce`·`tech/priv/suid` 는 실사용 확인돼 유지 |
| 「남긴 흔적」 | `(GLPI 쪽 노트는 이번 작업 범위 밖이라 역방향 링크는 추가하지 않음)` — **작업 과정 기록**이라 공개 본문에서 나가야 함 | 삭제. 심은 파일 목록에 `/tmp/harvest_www.txt`·`/tmp/harvest_root_out.txt` 보강 |

## 2. 보강한 것 (틀린 것은 아니나 근거가 얇았던 곳)

- **파라미터 무반응 판정** — "271바이트 동일"만으로는 크기만 같고 내용이 다를 가능성이 남음. `md5sum` 실측(7종 + 대조군 전부 `e90a614e7e94ce1f9eb40e4b43fef152`)을 본문에 넣어 바이트 동일을 확정.
- **SUID 목록 읽는 법** — Kali 에서 같은 14경로를 `test -u` 로 대조. `mount`·`umount`·`gpasswd`·`su`·`chsh`·`chfn`·`passwd`·`fusermount`·`newgrp`·`dbus-daemon-launch-helper`·`ssh-keysign` 11개는 Kali 도 SUID, `dmcrypt-get-device` 는 Kali 미설치(미확인), **`find`·`grep` 은 설치돼 있으나 SUID 아님**. 즉 "비정상은 정확히 그 둘"이 실측으로 뒷받침됨.
- **페이로드 조각 해설** — `.`·`-maxdepth 0`·`-exec … \;`·`-p`·`-quit` 각 조각의 역할 표를 추가(STANDARD §2 "페이로드를 조각내어 각 부분의 역할" 요구).
- **`python3` vs `python` 외견상 모순** — 3장은 `python3`, 4장 `which` 결과는 `python` 만. `which` 질의 목록에 `python3` 를 넣지 않은 것이 원인임을 본문에 명시해 독자가 모순으로 오독하지 않게 함.
- **타임존** — 타겟 AEST(UTC+10) vs Kali KST(UTC+9) 1시간 차. `harvest_www-data.txt` DATE 절에 `07:01:47 UTC` / `17:01:47 AEST` 가 나란히 있어 환산 확정. 7장 시각이 KST 임을 명시.
- **`/root/root.txt` 미끼 판정** — 값을 열기 전에도 크기(32B vs 진짜 플래그 33B)로 구분됨을 `ls -la /root` 실측으로 보강.
- **`dash -p`** — Kali 에서 `dash -p -c 'echo ok'` 실행 확인, `/bin/sh -> dash` 확인.

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 **노트가 옳았던 것**

1. **「3중 base64 는 과장이다」 — 반증됨. 노트가 옳다.**
   지시는 `decode_chain.txt` 의 `[1]` 이 HTML 주석 원문일 가능성을 의심하라고 했음. `index_raw.txt` 를 열어 확인하니 주석 원문은 `WkRJNWVXRXliSFZhTW14MVkwaEtkbG96U214ak0wMTFZMGRvZDBOblBUMEsK` 이고 `[1]`(`ZDI5eWEy…`)은 **그것을 한 번 디코드한 결과**임. 즉 주석 → [1] → [2] → [3](평문) = **디코드 3회**로 노트의 「3중」이 정확함. `[4]`~`[6]` 은 평문을 더 푼 잔여물이라 층수에 세지 않은 노트의 처리도 맞음.

2. **「`python3` 이 아니라 `python` 일 것이다」 — 반증됨. 노트가 옳다.**
   `session_bpc-shell.txt` 5~6행에 `python3 -c "import pty;pty.spawn([chr(47)+…])"` 가 **문자 그대로** 남아 있음. `which wget curl python` 이 `python3` 를 안 보여준 것은 질의 목록에 없었기 때문이지 부재가 아님(pty 승격이 성공했으므로 존재 확정). 노트의 「python 버전 단정 회피」 판단이 옳았고, 본문도 그 판단과 일관됨.

3. **「`export TERM=xterm; stty rows 50 cols 200` 이 세션 로그에 없을 것이다」 — 반증됨.**
   `shell443.log` 6행에 프롬프트까지 포함해 그대로 존재함.

4. **「파라미터 배치 사격의 실제 URL 형태가 어딘가 남아 있을 것이다」 — 반증 실패. 노트의 「관측 없음」이 옳다.**
   `~/.zsh_history` 에 BossPlayers 관련 항목 0건, `recon-driver.log`·`_SUMMARY.txt` 에도 요청 원문 없음. 응답 파일만 남음. 부재 확인은 고정 출처 목록 안에서만 수행했고, 등급은 **근거부족**이 아니라 **관측 없음 확정**(요청을 저장하지 않는 절차였음이 산출물 구성으로 드러남).

5. **「타임라인에 자기모순이 있을 것이다」 — 반증됨.**
   AEST↔KST 미환산으로 모순처럼 보이지만 환산하면 완전히 일치함. `harvest_www-data.txt` DATE(`17:01:47 AEST` = `07:01:47 UTC` = `16:01:47 KST`) ↔ 파일 mtime `16:02:42 KST`. `proof_root.txt` 내용 `17:03:17 AEST` ↔ mtime `16:03:20 KST`. **모순 없음.**

6. **「타겟 pty 프롬프트가 창작일 것이다」 — 반증됨. 전량 실측이다.**
   본문의 `www-data@bossplayers:/var/www/html$`·`www-data@bossplayers:/tmp$`·`bash-5.0#` 은 전부 `shell443.log` 에 실재함. **하나도 지우지 않았고, 오히려 원문에 있는데 노트가 빠뜨린 프롬프트를 복원함**(§4 curl 블록, §4 find 블록). `┌──(kali㉿kali)`·`└─$` 창작 프롬프트는 감사 후에도 0건.

## 4. 삭제한 것 (원문 인용 — 되살릴 수 있어야 함)

삭제는 **두 건뿐**이며 둘 다 반증 또는 규율 근거가 있음.

1. §7 — 반증된 단정:
   > 이 박스는 사용 가능한 도구가 `curl`(반복 요청)뿐이었지만 시험장에서는 `ffuf`/`wfuzz` 로 같은 일을 자동화할 수 있다

   도구 가용성에 대한 기록이 어느 산출물에도 없음. 뒷부분(`ffuf`/`wfuzz` 허용)은 살려서 재작성함.

2. 「남긴 흔적」 — CLAUDE.md §4 「본문에서 나가는 것」:
   > (GLPI 쪽 노트는 이번 작업 범위 밖이라 역방향 링크는 추가하지 않음)

   작업 과정 기록이라 공개 본문에서 제외.

그 외에는 **삭제 없이 정정·강등·보강**으로 처리함. `[가정]` 강등 2건 — ⓐ index.html 설명문 "avoid the rabit holes" 가 `robots.txt` 미끼를 가리킨다는 해석, ⓑ `nmap-manual-quick` 에서 443·8080 을 굳이 지정한 의도.

## 5. 문체 이관 — `pg-doc-reviewer` 관할

서술형 종결이 남은 곳 **4건**: §0 「…골라냈다」, §7 「…삼는다」·「…한다」·「…보인다」. 감사 범위 밖이라 손대지 않음.

별도 판단 필요 1건 — §4 SUID 코드펜스 안의 harvest 스크립트 출력 `(sudo 바이너리 없음 — PwnLab 류. 이 반사는 접어라)` 는 **실측 출력이라 한 바이트도 못 고침**. 다만 공개 발행 시 내부 도구 어조가 노출되므로 캡션으로 감쌀지 여부는 문체 검토 쪽 판단.

## 6. 색인 / 상태

- **색인 갱신 필요** — 프론트매터에 `ip`·`ports`·`services`·`difficulty`·`flags` 를 새로 넣었고 태그를 1개 추가함. `refresh.ps1` 은 총괄 몫이라 **돌리지 않음**.
- `manual_cves` 는 **넣지 않음** — 본문에 `CVE-` 문자열이 0건이라 자동 스캔이 빈 결과를 내므로 선언이 불필요하고, `cves` 필드 없이 `manual_cves: true` 만 두는 조합은 파서에 대해 미검증이라 위험을 만들지 않음.
- **`_STATUS.md` 판정(직접 편집하지 않음)**: BossPlayersCTF = **완료 2/2**. 근거 — `/home/local.txt` `70d307a8623905cf272ddd4e5b9931ab`, `/root/proof.txt` `202c3b297263da9f4550d47f62ee3736` 둘 다 `shell443.log` 의 대화형 pty 세션(`www-data@bossplayers:…$` / `bash-5.0#`)에서 `cat` 으로 읽힌 것이 캡처로 확인됨. 웹셸 경유 아님.
- 스크린샷 4장 링크 전부 유효(볼트 파일 존재, 바이트 크기가 Kali 원본과 일치). 재이관 불필요.
