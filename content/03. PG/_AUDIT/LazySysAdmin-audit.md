# LazySysAdmin — 적대적 검증 감사 (2026-08-20)

대상: `03. PG\LazySysAdmin.md` (499행 → 634행)
감사자: writeup-auditor / 작성자와 분리
소요: 약 22분 (고정 출처만 확인, 전수 훑기 없음)

## 확인한 출처 (고정 목록 안)

| 출처 | 실제로 읽은 것 |
|---|---|
| `kali:~/PG/LazySysAdmin/` | 산출물 31개 전부. `nmap.log`·`quick.log`·`smb_shares.txt`·`smb_share_ls.txt`·`smb_conf_share.txt`·`deets.txt`·`todolist.txt`·`robots.txt`·`info.php`·`wp-config.php`·`web_index.html`·`wp_home.html`·`proof_user.txt`·`proof_root.txt`·`try_sudo_l.log`·`try1`~`try9`·`harvest_togie.txt`·`harvest_root.txt`·`traces_confirmed.log`·`writeup_notes.txt`. mtime 은 `--time-style=full-iso` |
| 볼트 `파일보관\` | `PG-LazySysAdmin-index.png`(39412B)·`PG-LazySysAdmin-wordpress.png`(56990B) — **이미지를 직접 열어** 본문과 대조 |
| `~/.zsh_history` | `rpcclient`·`smbclient`·`sftp`·`scp`·`grep -o` 로 검색. **192.168.248.36 관련 항목 0건** — 이 박스는 전부 비대화형 SSH 로 몰았으므로 zsh 이력에 안 남는다. 부재를 근거로 아무것도 판정하지 않았다 |
| 1차 사료 (Kali 직접 실행) | `sort -k3 -rn /usr/share/nmap/nmap-services` 로 6667/tcp 개방빈도 순위 산출 |
| `_AUDIT\portal-진행도-실측-20260820.md` | 참조 대상 없음(이 박스는 완료 확정) |

**박스에는 접속하지 않았다.** 러너가 흔적 확인 중이라는 지시를 지켰다.

---

## A. 고친 것

`위치 | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거`

### A1. 1장 — "6667 은 top-1000 밖" (틀린 일반 지식)

원문: `` `6667 InspIRCd` 는 top-1000 밖이라 `-p-` 가 아니면 못 본다. ``

Kali 에서 직접 실행:
```
grep -E '/tcp' /usr/share/nmap/nmap-services | sort -k3 -rn | grep -n '\s6667/tcp\s'
316:irc	6667/tcp	0.000652
```
tcp 만 세면 **316위**, 서비스 전체에서도 300위권이다. nmap 기본 `--top-ports 1000` 안에 넉넉히 들어온다. 못 본 진짜 이유는 예열 스캔이 `--top-ports 200` 이었기 때문(`quick.log` 1행: `--top-ports 200`, 결과 22/80/139/445/3306).

→ 문장을 정정하고 `[!warning]` 콜아웃으로 오귀인 자체를 교훈화. 총괄 지시 (c) 와 일치.

### A2. 1장 nmap 블록 — 무표시 절단

원문 블록은 22/tcp 다음에 곧바로 80/tcp 가 오고 6667 에서 끝난다. `nmap.log` 원문에는 그 사이에 `ssh-hostkey` 4행이 있고, 6667 뒤에 `irc-info`·OS 탐지·`Host script results`(`smb-security-mode`·`clock-skew`·`smb-os-discovery`)가 이어진다. 절단 표시가 없어 연속 출력으로 읽힌다.

→ `nmap.log` 원문으로 복원. 부수 효과로 `smb-os-discovery` 의 `System time: 2026-08-20T17:43:55+10:00` 이 5장 타임존 서술의 **독립 근거 세 번째**가 됐고, `account_used: guest` 가 `map to guest = bad user` 서술을 뒷받침한다.

### A3. 1장 robots.txt — "앞의 셋은 빈 디렉터리"

`smb_share_ls.txt` 의 디렉터리 헤더는 `\wordpress`(15) `\Backnode_files`(40) `\wp`(59) `\apache`(63) `\test`(67) `\old`(71) `\wordpress\wp-admin`(75). `\test`·`\old` 는 `.`/`..` 만 = 빈 디렉터리가 맞다. 그러나 **`TR2` 는 웹루트에 아예 없다** — "빈 디렉터리"가 아니라 부재다.

→ old/test 는 빈 디렉터리, TR2 는 공유 목록에 없음, Backnode_files 는 랜딩 페이지 자산으로 정정.

### A4. 1장 rpcclient — 과잉 일반화

원문: "1000 만 이름으로 해석됐다 = 실제 계정은 `togie` 하나."
물어본 것은 1000·1001·1002 뿐이다. → "때려본 범위 안에서는" 으로 한정하고, `harvest_root.txt` 의 `===== USERS =====` (uid 1000 이상 일반 계정은 `togie:x:1000:1000:togie,,,:/home/togie:/bin/rbash` 단 하나, `/home` 에도 `togie` 만) 로 결론을 **뒷받침해** 다시 썼다. 결론 자체는 유지.

### A5. 4장 — 시간 서사 역전 (이번 감사에서 제일 큰 건)

원문: "셸을 잡자마자 `harvest.sh` 를 돌렸다" → SUDO 섹션이 빈손 → "여기서 멈추면 안 된다" → `sudo -S -l` 재시도.

산출물 시각이 반대다:

| 시각(KST) | 근거 | |
|---|---|---|
| 16:44:27 | `try1_ssh_togie_12345.log` mtime | 첫 SSH, `id` 에 `27(sudo)` |
| 16:45:40 | `try_sudo_l.log` mtime | `sudo -S -l` → `(ALL : ALL) ALL` |
| 16:45:50 | `proof_root.txt` mtime | root |
| 16:46:02 | `harvest_root.txt` 본문 `===== DATE =====` `07:46:02 UTC` | 열거(root) |
| 16:48:23 | `harvest_togie.txt` 본문 `07:48:23 UTC` | 열거(togie) |

`harvest_togie.txt` 의 mtime 은 17:22 이지만 이는 러너의 `HARVEST_PW` 마스킹 인플레이스 편집 시각이다(`writeup_notes.txt` 17:22 항목: "값만 가림, 행은 지우지 않았다"). 본문 DATE 섹션이 실행 시각의 진짜 출처다. **UTC↔AEST↔KST 를 모두 환산해 대조했다.**

또 3장이 보여주듯 16:44 시점의 harvest 실행 시도는 rbash 에 막혀 실패했으므로, root 이전에 성공한 togie harvest 산출물은 존재하지 않는다.

→ 4장 서두를 산출물 시각표로 바꾸고, "권한상승의 단서는 열거 스크립트가 아니라 첫 `id` 한 줄"로 인과를 바로잡음. 6장 ③ 도 같은 방향으로 재작성.

### A6. 4장 SUDO 블록 — 섹션을 중간에서 끊어 인용

원문 인용:
```
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요하거나 sudo 없음)
```
`harvest_togie.txt` 실제 24~34행은 그 **바로 다음 줄부터** `-- sudo -S -l (HARVEST_PW) --` 와 `(ALL : ALL) ALL` 을 담고 있다. 끊어 인용하면 "스크립트가 놓쳤다"는 서사가 성립하는 것처럼 보인다.

→ 섹션 전문으로 복원. `HARVEST_PW` 절반이 사후 추가분이라는 점은 명시하되 **추가 시각을 기록해두지 않았으므로 `[가정]`** 으로 표기.

### A7. 4장 `sudo -S -l` 터미널 블록 — 경고·배너 절단

원문은 `#   Welcome to Web_TR1   #` 부터 시작한다. `try_sudo_l.log` 는 post-quantum 경고 3행 + `####...####` 로 시작한다. 총괄이 지목한 "깔끔하게 만든" 패턴 그대로다.
→ `try_sudo_l.log` 원문 복원.

### A8. 4장 root 블록 — 명령 축약 + 출력 접합 (`...` 이 불일치를 가림)

원문:
```
└─$ ... "bash -c 'echo 12345 | sudo -S -i bash -c \"whoami; id\"'"
...
[sudo] password for togie: stdin: is not a tty
root
uid=0(root) gid=0(root) groups=0(root)
```
`whoami; id` 만 도는 실행의 산출물은 존재하지 않는다. 타겟 `auth.log`(= `traces_confirmed.log` 의 `===SUDO_LINES===`)에 남은 실제 명령은

```
Aug 20 17:45:50 LazySysAdmin sudo:    togie : TTY=pts/0 ; PWD=/home/togie ; USER=root ;
  COMMAND=/bin/bash -c bash -c whoami;\ id;\ hostname;\ hostname\ -I;\ date;\ ls\ -la\ /root;\ cat\ /root/proof.txt
```

이며 그 출력이 `proof_root.txt` 다. 즉 **명령을 줄여 적고 그 뒤에 다른 실행의 출력 앞부분을 `...` 로 이어 붙인 것.** 총괄이 경고한 "성공 응답을 엉뚱한 명령에 갖다 붙이기" 패턴이다.

→ 실제 명령 전문으로 되돌리고, 출력은 5장 `proof_root.txt` 블록을 가리키게 함(중복 인용 회피). `sudo -i` 가 `COMMAND=` 에 로그인 셸을 먼저 찍는 이유도 함께 서술.

### A9. 4장 `stdin: is not a tty` 설명 — 근거 좁힘

"`/etc/profile` 계열 스크립트가 뱉는 잡음" → `/root/.profile` 의 `mesg n` 으로 좁히고 `[가정]` 표기. 확인한 것은 `proof_root.txt` 의 `-rw-r--r-- 1 root root 140 Feb 20 2014 .profile` 이 14.04 기본 크기라는 것까지다. 파일 내용은 읽지 않았다.

### A10. 5장 플래그 블록 — 배너·경고·종료행 절단

`proof_user.txt`·`proof_root.txt` 둘 다 post-quantum 경고 3행 + 배너 5행으로 시작하고 `Connection to 192.168.248.36 closed.` 로 끝난다. 노트는 둘 다 잘라냈다.
→ **전문 복원.** 플래그 값·`uid=` 줄·`date` 줄은 원래도 정확했고 한 바이트도 안 바꿨다.
→ `[sudo] password for togie: stdin: is not a tty` 가 남아 있는 것이 오히려 실측의 표식이며 SSH 세션이므로 OSCP 규정상 문제없다는 서술을 추가.

### A11. 6장 ③ — 틀린 일반 지식

원문: "`sudo -n` 은 **NOPASSWD 항목만** 보여준다."
`-n`(non-interactive)은 프롬프트를 띄우지 말라는 플래그다. 인증이 필요한 상태면 목록을 **거르는 게 아니라** `sudo: a password is required` 로 종료한다 — 산출물 자체가 그 증거다(`harvest_togie.txt` SUDO 섹션 1행이 정확히 그 문자열).
→ "항목이 없다가 아니라 못 물어봤다"로 정정.

### A12. 3장 rbash 제약 블록 — 배너 2행 절단

`try8_rbash_limits.log` 의 앞 2행(배너 잔여분)을 복원. 로그 자체가 부분 캡처라 완전 복원은 불가하며, 로그에 있는 만큼은 전부 실었다.

### A13. 「남긴 흔적」 — 「미확인 `[가정]`」이 실제로는 확인됨

원문은 `auth.log`·`wtmp`·`.bash_history` 를 "확인하지 않았다 `[가정]`" 으로 남겼다. `traces_confirmed.log`(17:22 생성)에 전부 실측이 있다:
- `auth.log` 192.168.45.207 관련 **68행**, `sudo:` 항목 **14행** (`COMMAND=` 에 명령 전문 포함)
- `wtmp`: `togie pts/0` **2건**, 둘 다 17:45 AEST — `ssh -tt` 로 플래그 읽은 두 번뿐
- `btmp`: 실패 로그인 **1건** 17:47 AEST = try5(`togie:TogieMYSQL12345^^`, Kali mtime 16:47:14 KST 와 정확히 일치)
- `.bash_history`: **0바이트, mtime 2020-03-05** — 확인 완료

→ 표로 확정 서술. `[가정]` 해제. 덤으로 "`sudo` 는 `COMMAND=` 에 인자까지 통째로 남긴다"는 시험용 교훈 추가.

**A13-보강 (라인 관리자 지시, 2차 패스).** 요약 표를 걷어내고 `traces_confirmed.log` **47행 전문**을 코드펜스에 그대로 넣었다(`diff` 로 아티팩트와 대조 — ssh stderr 의 CR 3행을 뺀 나머지 **바이트 동일**). 덧붙인 것:
- **관측자 효과 자기참조** — 흔적 확인 실행 자체가 `auth.log` 에 `sudo` 2행을 얹었다(`===AUTHLOG_TAIL===` 18:22:33). 따라서 `68`·`14` 는 **이 확인 실행분을 포함한 숫자**다. 러너 지시는 "2행을 더 얹었다"였고, 내가 로그를 다시 읽어 **카운트 자체가 자기포함이라는 점까지** 확인해 함께 적었다(`grep -c` 가 같은 SSH 세션 안에서 돌았으므로 그 세션의 `Accepted password ... from 192.168.45.207` 이 이미 파일에 있었다).
- **로그 미삭제의 근거를 한 줄로** — 「남긴 흔적」은 지우는 절이 아니라 아는 절이고, 삭제는 흔적을 줄이는 게 아니라 늘리며 되돌릴 수 없다.
- **`wtmp` 2건 vs `auth.log` 68행 대비** — 비대화형 `ssh <cmd>` 는 pty 를 안 여니 `last` 가 조용하다. "어느 로그를 보느냐로 결론이 갈린다"로 교훈화.
- **미확인 목록 신설** — Apache 액세스 로그, Samba 로그, MySQL 1130 거부 기록. 러너가 안 본 것이므로 "보지 않았다"로 명시. 확인/미확인을 절 안에서 분리했다.

### A14. 6장 서두 소요시간

"약 3분" → 16:43:25(`nmap.log` 개시)~16:45:50(`proof_root.txt` mtime) = **2분 25초**로 정정.

### A15. 상단 `[!warning] 적대적 검증 정정 이력` 콜아웃 신설

위 항목을 표로 요약. 반증되어 그대로 둔 것도 함께 명시.

---

## B. 삭제한 것

**없다.** 전부 정정·복원·강등으로 처리했다. A8 에서 잘못된 명령/출력 접합을 교체했으나 원문은 위 A8 에 전문 인용돼 있어 되살릴 수 있다. 터미널 실측 블록은 하나도 줄이지 않았고, 오히려 4곳에서 원문 복원으로 늘었다.

---

## C. 내가 다시 반증한 것 (지적으로 올렸다가 철회)

1. **"1장 rpcclient 블록에 산출물이 없다 → 날조 의심"** — 철회. `~/PG/LazySysAdmin/` 에 `rpc*` 파일이 없고 `~/.zsh_history` 에도 이 박스 명령이 0건이지만, **이 박스는 전부 비대화형 SSH 로 몰았으므로 zsh 이력에 남을 수가 없다.** 게다가 `writeup_notes.txt` 16:45 항목이 "rpcclient lookupsids S-1-22-1-1000 -> togie. enum4linux -U 는 빈 결과"로 독립 기록하고, `try4_enum4linux_users.log` 가 그 빈 결과를 실물로 갖고 있다. 출력 형식(`S-1-22-1-1000 Unix User\togie (1)`)도 rpcclient 표준형. **부재 증거의 등급 상한 `근거부족` 규율 적용 — 지적 취소.** 대신 A4 의 논리 한정만 반영.

2. **"3장 rbash 블록 3개(`sh /tmp/.h.sh`, `echo SHELL=$SHELL...`, `bash -c 'echo esc...'`)에 산출물이 없다"** — 철회. `harvest_root.txt` 의 `===== TMP =====` 가 세 블록을 전부 교차 검증해준다: `-rwxrwxr-x 1 togie togie 2711 Aug 20 17:44 /tmp/.h.sh`(노트 본문 크기·시각과 바이트 단위 일치), `drwxrwxr-x togie togie /tmp/.h`, `-rw-rw-r-- 1 togie togie 4 Aug 20 17:45 /tmp/zz`(= `esc\n` 4바이트, 탈출 테스트 파일과 정확히 일치). 노트가 옳다.

3. **"6장 ① `scp -O` 인과가 추론"** — 철회, 뒷받침됨. `try9_sftp_rbash.log` 가 `sftp` 직접 접속의 `Connection closed.` 를 실물로 갖고 있고, `harvest_togie.txt` 의 `===== SSH =====` 가 `Subsystem sftp /usr/lib/openssh/sftp-server` 를 원문으로 보여준다. `try8_rbash_limits.log` 의 ``rbash: /bin/ls: restricted: cannot specify `/' in command names`` 가 규칙의 실측이다. 세 조각이 인과를 완성한다 — 이 노트에서 제일 값나가는 대목이 맞다. 그대로 뒀다.

4. **"6장 ④ 56건 주장"** — 확인됨. `grep -c -i togie wp_home.html` = **56**, `web_index.html` = **0**. 스크린샷 `PG-LazySysAdmin-wordpress.png` 를 직접 열어 `My name is togie.` 반복과 "Please dont make me setup wp again" 을 눈으로 확인했다. 교훈("부재 판정은 문맥 없는 `grep -c` 로")도 노트에 있다. 그대로 뒀다.
   - 참고로 `writeup_notes.txt` 첫 블록에 "index.html author togie" 라는 기록이 있는데 이건 **러너의 초기 오기**다(`web_index.html` 의 togie 는 0건). 노트 본문은 이 오기를 상속하지 않았다 — 노트가 옳다.

5. **"5장 타임존 서술이 자기모순"** — 철회. `proof_user.txt` 본문 `Thu Aug 20 17:45:25 AEST` ↔ 파일 mtime `2026-08-20 16:45:26 +0900`. 1초 차는 `cat` 과 파일 flush 사이다. 정확하다.

6. **"pkexec/커널을 실측인 척 적었다"** — 해당 없음. 둘 다 "시도하지 않았다 / `[가정]`" 으로 이미 표기돼 있다. 안 해본 것을 안 해봤다고 적은 것이므로 옳다. 손대지 않았다.

---

## D. 프론트매터 점검

- `tags` 8개. `tech/svc/smb`·`tech/cred/reuse`·`tech/lin/sudo-abuse` 는 `_INDEX\01. 기법별 색인.md` 에 실재하는 leaf. `tech/lin/rbash-escape` 는 총괄 승인 신규 — 그대로 뒀다.
- **설명만 하고 안 쓴 기법 태그 없음.** 넷 다 실제 경로에 쓰였다(SMB 널 세션 / 12345 재사용 / rbash 탈출 / `(ALL:ALL) ALL`).
- `manual_tags: true`·`manual_cves: true` — **뒤에 주석 없음** 확인.
- `cves: []` — 본문에 CVE-2021-4034 가 "미시도 대체 경로"로만 언급되므로 비워두는 것이 맞다.
- `Nmap scan report for 192.168.248.36` — nmap 블록 2행에 **존재함**. 색인 `ip` 필드 잡힌다.
- `![[PG-LazySysAdmin-index.png]]`·`![[PG-LazySysAdmin-wordpress.png]]` 링크 2개, 볼트 `파일보관\` 파일명과 일치. 이미지를 열어 본문 서술(Silex 랜딩 / wordpress 첫 포스트 반복)과 일치함을 확인.

## E. 손대지 않은 것 (경계 준수)

- `_STATUS.md` — 미변경
- `refresh.ps1` / `extract.py` / `harvest.sh` / 포털 / 브라우저 / 타겟 박스 — 미접촉
- `harvest_togie.txt` 921행 `HARVEST_PW` 마스킹 — 러너 작업 중이므로 미접촉
- 다른 노트 — 열지 않음
