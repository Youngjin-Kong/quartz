# LazySysAdmin → _PLAYBOOK 이관 제안

작성: pg-note-forge (2026-08-26). `_PLAYBOOK.md` 직접 편집 안 함 — 총괄/`pg-line-manager` 가 반영.
번호는 전부 비움("신규") — 배정은 총괄 몫.

---

## 제안 1 — 신규, `A-1. 정찰·열거` 하위

**넣을 본문:**
예열 스캔(`--top-ports 200`)이 놓친 포트를 "top-1000 밖이라 못 본다"로 오귀인하지 말 것. `nmap-services` 개방빈도 순위와 실제 예열 스캔 범위를 구분해 확인할 것 — [[LazySysAdmin]] 사례에서 6667/tcp(InspIRCd)는 tcp 300위권으로 기본 `--top-ports 1000` 안에 들어오는 포트였고, 놓친 이유는 예열 스캔을 top-200 으로 좁혀 돌렸기 때문임. `-p-` 전체 스캔이 뒤늦게 잡아줌.

**지우기 전 원문(구 노트 §1):**
> `6667 InspIRCd` 는 먼저 돌린 빠른 스캔(`--top-ports 200`, `quick.log`)에 안 잡혔다. `-p-` 가 뒤늦게 잡아준 포트다. 이 박스에서는 결국 안 썼지만, 못 봤으면 후보 하나를 통째로 잃는 것이다.
>
> > [!warning] "top-1000 밖이라 못 본다"는 틀린 설명이다
> > 6667/tcp 는 `/usr/share/nmap/nmap-services` 의 개방빈도 순으로 **tcp 300위권**이라 nmap 기본 `--top-ports 1000` 안에 넉넉히 들어온다. 여기서 놓친 이유는 내가 **top-200 으로 예열 스캔을 돌렸기 때문**이지 포트가 희귀해서가 아니다. 예열 스캔의 범위를 기억해두지 않으면 이런 오귀인이 그대로 굳는다.

---

## 제안 2 — 신규, `A-1. 정찰·열거` 또는 `B-2. 네트워크 서비스` 하위

**넣을 본문:**
Samba 공유가 익명(널 세션, `-N`)으로 열리면 그 공유의 `path` 가 웹 서버 문서 루트와 같은지부터 확인할 것 — 같으면 `wp-config.php`/`configuration.php`/`.env` 같은 설정파일이 그대로 자격증명 덤프가 됨. `robots.txt` 의 disallow 항목과 공유 디렉터리 목록이 1:1 대응하면 그 공유가 웹루트라는 결정적 증거. [[LazySysAdmin]] 사례: `smbclient -L //T -N` → `share$`(guest ok=yes) → `recurse ON; ls` → `index.html`·`robots.txt`·`wordpress/` 가 그대로 노출, `wp-config.php` 에서 DB 자격증명 회수.

**지우기 전 원문(구 노트 §1):**
> `index.html`·`robots.txt`·`wordpress/` — **웹루트다.** `robots.txt` 의 항목들이 여기 디렉터리와 1:1로 맞는 것이 결정적 대조다. `-N` 으로 읽히는 공유가 웹루트면 `wp-config.php` 를 그냥 가져갈 수 있다.

---

## 제안 3 — 신규, `A-1. 정찰·열거` 하위 (Samba 사용자 열거)

**넣을 본문:**
`enum4linux -U` 가 Perl 경고만 뱉고 빈 결과일 때, 포기하지 말고 `rpcclient -U '' -N <타겟> -c "lookupsids S-1-22-1-<uid>"` 로 Unix 계정 SID 역조회할 것. Samba 는 Unix 계정을 SAM RID(`S-1-5-21-...`)가 아니라 `S-1-22-1-<uid>`(사용자)/`S-1-22-2-<gid>`(그룹) 네임스페이스에 둠 — `S-1-5-21-...-1000` 대역만 뒤지면 로컬 유닉스 계정은 영영 안 나옴. [[LazySysAdmin]]: `S-1-22-1-1000` → `Unix User\togie`.

**지우기 전 원문(구 노트 §1):**
> `enum4linux -U` 는 사용자 목록을 못 뽑았다(6장). Unix 계정은 SAM RID 가 아니라 **`S-1-22-1-<uid>`** 네임스페이스에 있고, `rpcclient` 로 SID→이름 역조회를 하면 나온다.
>
> > [!tip] Samba 가 뜬 리눅스 박스에서 사용자명을 얻는 순서
> > `enum4linux -U` → 빈 결과면 포기하지 말고 `rpcclient -U '' -N <타겟> -c "lookupsids S-1-22-1-1000"`.
> > `S-1-22-1-*` = Unix 사용자, `S-1-22-2-*` = Unix 그룹. `S-1-5-21-...-1000` 대역만 뒤지면 로컬 유닉스 계정은 영영 안 나온다.

---

## 제안 4 — 신규, `A-3. 셸` 하위 (rbash 탈출)

**넣을 본문:**
rbash 는 자기 프로세스의 동작만 제한하고 자식 프로세스는 제한하지 않음 — `bash -c '...'` 를 SSH 명령 인자로 직접 던지면 자식 `bash` 는 `-r` 없이 시작해 그대로 평범한 셸이 됨. rbash 가 실제로 막는 것은 `cd`·명령 이름의 `/`·리다이렉션(`>`/`>>`)·`PATH`/`SHELL`/`ENV`/`BASH_ENV` 대입·`hash -p`·`enable`/`command` 우회·`-r` 해제뿐이고, **PATH 에 이미 있는 실행파일을 이름만으로 부르는 것은 막지 않음.** 따라서 판정 기준은 "PATH 가 화이트리스트 디렉터리로 좁혀졌는가" — 평범한 기본 PATH 그대로면 감옥이 아니라 문패일 뿐. 대상이 SSH 라면 GTFOBins 를 뒤지기 전에 **명령 인자로 `bash -c` 를 던지는 것**이 제일 빠름.

**지우기 전 원문(구 노트 §3):**
> ```bash
> ┌──(kali㉿kali)-[~/PG/LazySysAdmin]
> └─$ sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@192.168.248.36 'cd /tmp; /bin/ls /home; PATH=/tmp; export -f x'
> ...
> rbash: line 0: cd: restricted
> rbash: /bin/ls: restricted: cannot specify `/' in command names
> rbash: PATH: readonly variable
> ```
>
> > [!note] rbash 가 실제로 막는 것
> > `cd` · 명령 이름에 `/` 포함 · `>`/`>>` 리다이렉션 · `PATH`·`SHELL`·`ENV`·`BASH_ENV` 대입 · `hash -p` · `enable`/`command` 로 빌트인 우회 · `-r` 해제.
> > **막지 않는 것: PATH 에 이미 있는 실행파일을 이름만으로 부르는 것.** 그래서 탈출은 "무엇이 PATH 에 남아 있는가" 문제로 환원된다.
>
> 여기 PATH 는 `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games` — **평범한 기본 PATH 를 그대로 두었다.** 제대로 된 rbash 감옥은 PATH 를 `~/bin` 같은 화이트리스트 디렉터리 하나로 좁히고 거기에 심볼릭 링크를 몇 개만 둔다. 그게 없으니 `/bin/bash` 가 `bash` 라는 이름만으로 그대로 손에 잡힌다.
>
> > [!tip] 제한 셸을 만나면 순서대로 때린다
> > 1. `echo $PATH` · `ls $(echo $PATH | tr : ' ')` — 뭐가 남아 있는지가 전부다
> > 2. `bash` / `sh` / `python3 -c 'import os;os.system("/bin/bash")'`
> > 3. `vi` → `:set shell=/bin/bash` → `:shell`, `awk 'BEGIN{system("/bin/bash")}'`, `find . -exec /bin/bash \;`
> > 4. 원격이면 셸을 아예 안 거치는 방법 — `ssh user@host -t "bash --noprofile"`, 또는 `ssh user@host` 대신 `ssh -o RemoteCommand=bash`
> >
> > 대상이 SSH 라면 3번까지 갈 것도 없이 **명령 인자로 `bash -c` 를 던지는 것**이 제일 빠르다.

---

## 제안 5 — 신규, `A-3. 셸` 하위 (scp/sftp가 rbash에서 조용히 끊김)

**넣을 본문:**
제한 셸(rbash) 대상에 `scp` 로 파일이 안 올라가고 `scp: Connection closed`만 나오면 방화벽·권한이 아니라 **로그인 셸을 의심할 것.** 최신 OpenSSH `scp` 는 기본으로 SFTP 서브시스템을 쓰는데, sshd 는 그 서브시스템(`/usr/lib/openssh/sftp-server`)을 사용자의 로그인 셸에 `-c` 로 넘겨 실행함 — 셸이 rbash 면 경로에 `/` 가 있다는 이유로 거부되어 연결이 끊김(`sftp` 직접 접속으로도 재현됨). `scp -O`(대문자 O, legacy SCP 프로토콜 강제)로 우회 가능 — legacy 모드는 원격에서 `scp -t <경로>` 를 실행하고 **명령 이름 `scp` 자체에는 `/` 가 없기** 때문. rbash 는 인자의 슬래시가 아니라 명령 이름의 슬래시만 봄.

**지우기 전 원문(구 노트 §6 ①):**
> **① `scp` 가 조용히 끊겼다** — `harvest.sh` 를 올리려는데 `scp: Connection closed`. 방화벽이나 권한 문제로 읽히기 쉬운데 아니다. `scp -O` (대문자 O, legacy SCP 프로토콜 강제)로 즉시 해결됐다.
>
> 원인은 이때는 몰랐고 rbash 정체를 파악한 뒤에 맞춰졌다. 최신 OpenSSH 의 `scp` 는 기본으로 **SFTP 서브시스템**을 쓴다. `sshd_config` 에는 `Subsystem sftp /usr/lib/openssh/sftp-server` 가 정상 등재돼 있었는데, sshd 는 외부 서브시스템을 **사용자의 로그인 셸에 `-c` 로 넘겨** 실행한다. 그 셸이 rbash 라 `/usr/lib/openssh/sftp-server` 에 `/` 가 들어 있다는 이유로 거부하고 연결이 끊긴다. `sftp` 를 직접 붙여보면 같은 증상이 재현된다.
>
> ```bash
> ┌──(kali㉿kali)-[~/PG/LazySysAdmin]
> └─$ sshpass -p '12345' sftp -o StrictHostKeyChecking=no togie@192.168.248.36 <<< 'ls'
> ##################################################################################################
>
> Connection closed.  
> Connection closed
> ```
>
> `-O` 가 통한 이유도 같은 규칙으로 설명된다 — legacy 모드는 원격에서 `scp -t <경로>` 를 실행하고, **명령 이름 `scp` 에는 `/` 가 없다.** rbash 는 인자의 슬래시가 아니라 명령 이름의 슬래시만 본다.
>
> **구형 리눅스 박스에 파일이 안 올라가면 `-O` 를 먼저 때려보고, 그래도 안 되면 로그인 셸을 의심하라.** 나머지 대안 `cat file | ssh user@host 'cat > /tmp/x'` 는 여기서 rbash 가 `>` 를 막아 어차피 실패했을 것이다.

---

## 제안 6 — 신규, `A-2. 진입 (foothold)` 또는 `B-2. 네트워크 서비스` 하위

**넣을 본문:**
MySQL 원격 접속 실패 시 에러 번호로 원인을 구분할 것 — **1130** 은 호스트 기반 거부(`Host '...' is not allowed to connect`, 자격증명은 맞을 수 있음 → 피벗해서 로컬에서 접속하면 됨), **1045** 는 자격증명 자체가 틀림(비밀번호를 더 찾아야 함). `wp-config.php` 등에서 `DB_HOST=localhost` 로 박혀 있으면 애초에 외부 접속이 설계상 막혀 있다는 신호.

**지우기 전 원문(구 노트 §6 ⑦):**
> **⑦ MySQL 원격 접속** — `Admin:TogieMYSQL12345^^` 를 3306 에 직접 던졌다.
>
> ```bash
> ┌──(kali㉿kali)-[~/PG/LazySysAdmin]
> └─$ mysql -h 192.168.248.36 -u Admin -p'TogieMYSQL12345^^' -e 'select 1'
> ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.207' is not allowed to connect to this MySQL server
> ```
>
> 에러 1130 = **호스트 기반 거부**. 비번이 틀린 게 아니다(1045 였으면 자격증명 문제). `wp-config.php` 의 `DB_HOST` 가 `localhost` 인 것과 일치한다. nmap 이 `MySQL (unauthorized)` 로 적은 것도 같은 현상을 본 것이다. **1130 과 1045 를 구분하라** — 전자는 피벗해서 다시 오면 되고, 후자는 비번을 더 찾아야 한다.

---

## 제안 7 — 신규, `B-1. 웹` 하위 (WordPress 로그인 판정)

**넣을 본문:**
WordPress `wp-login.php` 성공/실패 판정은 상태 코드로 할 것 — 성공은 `302 Found` + `Location: .../wp-admin/`, 실패는 `200 OK`(로그인 폼 재출력). 본문 길이나 "Error" 문자열을 찾을 필요 없이 sqlmap 등 자동 도구 없이 수동으로 즉시 판정 가능. [[LazySysAdmin]]: `Admin:TogieMYSQL12345^^` → 302(성공), `togie:12345` → 200(실패, SSH 비밀번호와 WP 비밀번호가 계정별로 달랐음을 보여줌).

**지우기 전 원문(구 노트 §6 ⑧):**
> | 조합 | 결과 |
> |---|---|
> | `ssh togie:12345` | **성공** |
> | `ssh togie:TogieMYSQL12345^^` | `Permission denied (publickey,password).` |
> | `POST wp-login.php log=Admin&pwd=TogieMYSQL12345^^` | `HTTP/1.1 302 Found` → `Location: .../wp-admin/` — **성공** |
> | `POST wp-login.php log=togie&pwd=12345` | `HTTP/1.1 200 OK` (로그인 폼 재출력 = 실패) |
>
> WordPress 로그인 판정은 **상태 코드로 한다.** 성공은 `302` + `Location: wp-admin/`, 실패는 `200` 으로 폼을 다시 그린다. 본문 길이나 "Error" 문자열을 찾을 필요가 없다.

---

## 제안 8 — 기존 `A-41. 셸은 잡았는데 권한상승 실마리가 없다` 에 병합 (사례 추가)

기존 항목이 이미 `sudo -n` 재확인 원칙을 [[Graph]]·[[Fikklish]] 사례로 다루고 있음(`_PLAYBOOK.md:451`). [[LazySysAdmin]] 을 세 번째 사례로 추가 제안.

**추가할 본문(기존 문단 뒤에 이어 붙임):**
[[LazySysAdmin]]: 첫 SSH 의 `id` 출력에서 `groups=...,27(sudo),...` 를 먼저 보고 `echo '<pw>' | sudo -S -l` 로 곧장 재확인해 `(ALL : ALL) ALL` 을 확인함 — `harvest.sh` 의 `sudo -n -l` 결과(`sudo: a password is required`)만 봤다면 "sudo 경로 없음"으로 오판했을 것. `id` 의 보조 그룹을 sudo 재확인의 트리거로 쓸 것.

**지우기 전 원문(구 노트 §6 ③):**
> **③ `sudo -n -l` 이 빈손이었다** — 열거 스크립트의 SUDO 섹션이 `sudo: a password is required` 한 줄로 끝난다. 이 출력만 보면 "sudo 경로 없음"으로 읽히는데, 실제 답은 `(ALL : ALL) ALL` 이었다.
>
> 여기서 나를 구한 건 첫 SSH 의 `id` 였다. `27(sudo)` 를 보고 곧장 `echo 12345 | sudo -S -l` 로 다시 쳤고, 그래서 `harvest.sh` 의 빈손 출력을 볼 일 자체가 없었다(4장 시각표 — 스크립트는 root 를 잡은 뒤에야 돌았다). 순서가 반대였다면 그대로 막혔을 것이다.
>
> **`sudo -n` 의 의미를 정확히 읽어라.** `-n` 은 "비밀번호 프롬프트를 절대 띄우지 말라"는 뜻이다. 인증이 필요한 상태면 목록을 걸러서 보여주는 게 아니라 **아예 물어보지 못하고 `a password is required` 로 죽는다.** "항목이 없다"가 아니라 "못 물어봤다"이다. 비번을 이미 아는 상황이면 반드시 `echo '<pw>' | sudo -S -l` 로 다시 쳐라. (이 때문에 `~/PG/_lib/harvest.sh` 에 `HARVEST_PW` 환경변수를 넣어 `sudo -S -l` 을 추가로 돌리도록 고쳤다.)

---

## 제안 9 — 신규, `A-1. 정찰·열거` 하위 (grep 컨텍스트 패턴의 행경계 탈락)

⚠️ **총괄 프롬프트가 이 사례를 "grep -c 행경계 탈락"으로 지칭했으나 실측과 다름 — 아래 보고 3번 참고. 실제로는 `grep -o` 컨텍스트 패턴 문제이고 `grep -c` 는 오히려 정답이었음.**

**넣을 본문:**
문자열 부재를 확인할 때 `grep -o -E '.{N}패턴.{N}'` 같은 **컨텍스트 포함 패턴을 먼저 쓰지 말 것.** 매치가 행 시작·끝 근처에 있으면 앞뒤 `.{N}` 요구를 못 채워 전체가 탈락 — "0건"이 "존재하지 않음"이 아니라 "컨텍스트 조건을 못 채움"일 수 있음. 부재 판정은 컨텍스트 없는 단순 카운트(`grep -c 패턴`)로 먼저 세고, 컨텍스트가 필요하면 나중에 존재가 확인된 자리에서만 쓸 것. [[LazySysAdmin]] 사례: `grep -o -E '.{60}togie.{60}' wp_home.html` → 0건(오판), 실제로는 `grep -c togie wp_home.html` → 56건. Kali 재실행으로 검증됨(2026-08-26).

**지우기 전 원문(구 노트 §6 ④):**
> **④ 웹에 적힌 사용자명을 못 보고 SMB 로 돌아갔다** — `curl` 로 받은 `wp_home.html` 에 `grep -o -E '.{60}togie.{60}'` 을 돌렸더니 **0건**이 나왔다. "웹에는 togie 언급이 없다"고 결론냈는데 틀렸다. 실제로는 56건 있었다. `grep -o` 의 `.{60}` 앞뒤 문맥 요구가 **행 시작/끝에 걸린 매치를 전부 탈락**시킨 것이다. 스크린샷을 눈으로 보고서야 `My name is togie.` 를 발견했다. **부재를 확인할 때는 문맥 없는 단순 패턴(`grep -c -i togie`)으로 먼저 세라.** 문맥 패턴은 확인용이지 존재 판정용이 아니다.

---

## 제안 10 — 신규, `C` 계열(harvest.sh 공유 인프라) — 총괄 판단 필요

`~/PG/_lib/harvest.sh` 는 이미 수정됨(env leak fix, `~/PG/_lib/harvest.sh.bak-envleak` 백업 존재) — 공유 인프라 변경 사항이라 문서화 여부를 총괄이 판단할 것.

**넣을 본문(안):**
`harvest.sh` 의 `ENV` 섹션이 `env` 명령을 그대로 실행하면 호출자가 넘긴 환경변수(예: `HARVEST_PW`)가 값 그대로 출력 파일에 찍힘 — 비밀값을 환경변수로 넘겨 스크립트를 실행하면 그 값이 수집 로그에 평문으로 남음. `env 2>/dev/null | grep -v '^HARVEST_PW='` 로 해당 변수만 걸러내도록 수정됨.

**지우기 전 원문(구 노트 §4·writeup_notes.txt, 산출물 근거):**
> 17:22 [사후처리] harvest_togie.txt 921행 'HARVEST_PW=12345' -> 'HARVEST_PW=<redacted>' 로 값만 가림.
>        원인: harvest.sh ENV 섹션의 'env' 가 내가 넘긴 환경변수를 통째로 뱉었다. 행은 지우지 않았다.
>        이 값(12345)은 침투 경로의 자격증명으로 노트 본문에 정당하게 실려 있다 — 가린 건 환경변수 유출이라는 위생 문제다.
>        harvest.sh 수정: env 2>/dev/null | grep -v '^HARVEST_PW=' . 백업 ~/PG/_lib/harvest.sh.bak-envleak.
>        재실행 검증 산출물: harvest_envleak_verify.txt (grep -c '12345' = 0, ENV/PATH·SUDO 섹션 정상).
— 출처: `~/PG/LazySysAdmin/writeup_notes.txt`
