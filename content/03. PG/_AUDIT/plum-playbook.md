---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# plum — `_PLAYBOOK` 이관 제안

> 반영자는 `pg-line-manager` 단독. 이 파일은 제안서이고 `_PLAYBOOK.md` 를 직접 고치지 않았음.
> 각 제안에 ①어느 절 ②병합/신규 ③넣을 본문 ④지우기 전 원문 을 적음.
> 「신규」로 올리기 전 `_PLAYBOOK` 을 **증상으로** 역검색했고, 결과를 각 항목의 「역검색」 줄에 적음.

---

## P1. A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다 — **병합**

**역검색** — `_PLAYBOOK:191` 에 이미 `| [[plum]] | SUID exim4 를 보고 CVE-2019-10149(4.87–4.91)를 확보했으나 타겟은 **4.94.2** 로 애초에 취약하지 않았음 |` 행이 있고 `:196` 에 CVE 표기 정정 줄이 있음. **신규 아님.** 아래는 그 항목에 «빠져 있는» 배제 근거와 확인 명령.

**넣을 본문**

> **버전 번호 자체가 「이미 패치됨」을 말해주는 경우가 있음.** [[plum]] 의 `4.94.2` 는 2021-05-04 공개된 **21Nails 묶음**(CVE-2020-28007~28026 + CVE-2021-27216, 21건)의 수정 릴리스임. 그러므로 이 숫자를 보면 CVE-2019-10149 도 21Nails 도 **둘 다** 배제해야 함 — 「최근에 패치된 버전」이라는 신호임.
> ⚠️ **번호가 그럴듯하게 들어맞는다고 아무 문서나 출처로 붙이지 말 것.** 21Nails 어드바이저리(`21nails.txt`)는 `4.94.2` 를 **단 한 번도 언급하지 않음**(`grep -c "4\.94\.2" 21nails.txt` → 0). 어드바이저리가 정하는 것은 CRD 2021-05-04 까지이고 어떤 릴리스 번호로 나갔는지는 별도 사료가 필요함 — ftp.exim.org 의 `exim-4.94.2.tar.xz  04-May-2021 13:35`(CRD 와 같은 날)과 4.94.2 태그 `doc/doc-txt/ChangeLog` 의 `Exim version 4.94.2` 절이 그것임. **검증자는 `grep` 한 번으로 확인함.**
> **10초짜리 확인이 5분과 오판을 없앰:**
> ```bash
> <바이너리> --version | head -1
> dpkg -l | grep <패키지>          # Debian/Ubuntu
> rpm -qa | grep <패키지>          # RHEL 계열
> ```
> **버전 정보는 예상 밖의 곳에 있음** — 메일 헤더(`Received: from root by localhost with local (Exim 4.94.2)`)·HTTP 응답 헤더·에러 페이지·`--version`·패키지 DB·`/usr/share/doc/<pkg>/changelog.Debian.gz`. [[plum]] 은 메일함을 열었을 때 **자격증명과 exim 버전이 같은 파일에** 있었음.
> **[가정]** 4.94.2 에 남아 있는 공개 로컬 권한상승 경로는 2026-07 공개된 CVE-2026-66140/66141(`< 4.99.5`)뿐이고, 이 박스 스냅샷 시점에 공개 PoC 가 가용했는지는 미확인임.

**④ 지우기 전 원문**(plum.md 초판 6-① · 4-2 · 6-⑥ 발췌)

```text
왜 실패했는지는 확정 근거가 둘 있다. 첫째, 타겟 Exim은 4.94.2다 — 4-2의 메일 헤더가 증거다(`Received: from root by localhost with local (Exim 4.94.2)`). 둘째, CVE-2019-10149는 4.92에서 이미 수정됐다. Qualys 원 어드바이저리 원문은 이렇다:

> "we discovered an RCE vulnerability in versions **4.87 to 4.91 (inclusive)**"
> "this vulnerability was **fixed in version 4.92** (released on February 10, 2019)"

**4.94.2 > 4.92 이므로 취약 범위 밖이고, 이 익스플로잇은 처음부터 성공할 수 없었다**.

한 걸음 더 들어가면 4.94.2 자체가 보안 수정 릴리스다. 2021-05-04 공개된 21Nails 취약점 묶음(CVE-2020-28007 ~ 28026 + CVE-2021-27216, 합 21건)의 수정본이고, Debian 11의 exim4 패키지가 `4.94.2-7+deb11u*` 계열인 것도 그 때문이다.

이 사실의 출처는 `21nails.txt` 가 아니다. 그 문서는 `4.94.2` 를 단 한 번도 언급하지 않는다(`grep -c "4\.94\.2" 21nails.txt` → 0). 어드바이저리가 정하는 것은 Coordinated Release Date 2021-05-04 까지이고, 어떤 릴리스 번호로 나갔는지는 별도 사료가 필요하다. 올바른 근거는 둘이다 — ftp.exim.org 배포 디렉터리의 `exim-4.94.2.tar.xz  04-May-2021 13:35`(CRD와 같은 날), 그리고 4.94.2 태그의 `doc/doc-txt/ChangeLog` 에서 `Exim version 4.94.2` 절이 `CVE-2020-28016` 을 비롯한 21Nails 항목들을 나열하는 것. 번호가 그럴듯하게 들어맞는다고 아무 문서나 출처로 붙이지 마라. 검증자는 `grep` 한 번으로 확인한다.

그러니까 `4.94.2` 라는 숫자를 보면 CVE-2019-10149도 21Nails도 둘 다 배제해야 한다. 오히려 최근에 패치된 버전이라는 신호다. **[가정]** 4.94.2에 남아 있는 공개 로컬 권한상승 경로는 2026-07 공개된 CVE-2026-66140/66141(`< 4.99.5`)뿐이고, 이 박스 스냅샷 시점에 공개 PoC가 가용했는지는 미확인이다.
```

```text
버전 정보는 예상 밖의 곳에 있다. 메일 헤더·HTTP 응답 헤더·에러 페이지·`--version`·패키지 DB(`dpkg -l | grep exim`)·`/usr/share/doc/<pkg>/changelog.Debian.gz`. **익스플로잇을 던지기 전에 버전을 확인하는 것이 항상 더 싸다.**.
```

```text
그래도 유효한 교훈 하나는 남는다 — 버전 확인 없이 익스플로잇을 확보했다는 것:

# 이 한 줄이면 46996을 받을 이유가 없었다
dpkg -l | grep exim
/usr/sbin/exim4 --version | head -1
```

```text
손절 기준은 이렇게 고정한다. 권한상승 익스플로잇을 고려하는 순간 먼저 버전을 확인하고 취약 범위와 대조한다.

<바이너리> --version | head -1
dpkg -l | grep <패키지>          # Debian/Ubuntu
rpm -qa | grep <패키지>          # RHEL 계열
```

---

## P2. A-12. 응답이 성공을 뜻하지 않는다 — **병합**

**역검색** — `_PLAYBOOK:120` 에 이미 `**권한상승 판** — 실패한 익스플로잇도 셸 프롬프트를 띄움. 돌린 직후 **`id` 로 판정**할 것. ([[plum]] — exim 익스플로잇이 실패했는데 셸이 떠서 성공처럼 보였음)` 이 있음. **신규 아님.** 아래는 그 한 줄이 «어떻게» 판정됐는지의 재현 근거.

**넣을 본문**

> **판정 근거 둘** — ⑴ `id` 의 `uid=0` ⑵ 스크립트가 뱉는 `ls -l /tmp/pwned` 가 `-rwsr-xr-x`(**s**)인가. `-rwxr-xr-x` 면 실패임.
> **실패의 물증은 에러 문구의 «접두사»가 알려줌.** [[plum]] 의 리버스셸 전사에 `cd www-data` / `/tmp/pwned: 8: cd: can't cd to www-data` 라는 설명되지 않는 줄이 있었고, 접두사 `/tmp/pwned:`(= `$0`)가 **`/tmp/pwned` 자체가 셸**임을 말해줌 — 즉 `raptor_exim_wiz` 의 `cp /bin/sh /tmp/pwned` 폴백 가지가 돌았다는 뜻임(= 컴파일 실패, B-86). Kali 재현:
> ```bash
> cp /bin/dash /tmp/pwned_test
> printf 'echo a\necho b\necho c\necho d\necho e\necho f\necho g\ncd www-data\n' | /tmp/pwned_test
> ```
> ```text
> /tmp/pwned_test: 8: cd: can't cd to www-data      ← 원문과 완전히 같은 형식
> ```
> `bash` 는 형식이 다름(`bash: line 1: cd: www-data: No such file or directory`) — **에러 형식만으로 dash/bash 를 가름.**

**④ 지우기 전 원문**(plum.md 초판 6-②)

```text
### ② `/tmp/pwned` — 실패의 물증을 역추적하다

기존 노트의 터미널 기록 한가운데에 설명되지 않은 줄이 있다:

cd www-data
/tmp/pwned: 8: cd: can't cd to www-data

`/tmp/pwned` 은 raptor_exim_wiz가 만드는 파일이다. 스크립트를 보면 이렇게 동작한다:

	echo "Preparing setuid shell helper..."
	echo "main(){setuid(0);setgid(0);system(\"/bin/sh\");}" >/tmp/pwned.c
	gcc -o /tmp/pwned /tmp/pwned.c 2>/dev/null
	if [ $? -ne 0 ]; then
		echo "Problems compiling setuid shell helper, check your gcc."
		echo "Falling back to the /bin/sh method."
		cp /bin/sh /tmp/pwned
	fi

그 다음 페이로드를 보내 `/tmp/pwned` 를 root 소유 + setuid(4755)로 만들려 시도하고, 5초 뒤 실행한다.

저 한 줄에서 두 가지를 확정할 수 있다. 실제로 재현해서 확인했다.

┌──(kali㉿kali)-[~]
└─$ cp /bin/dash /tmp/pwned_test
└─$ printf 'echo a\necho b\necho c\necho d\necho e\necho f\necho g\ncd www-data\n' | /tmp/pwned_test
a
b
c
d
e
f
g
/tmp/pwned_test: 8: cd: can't cd to www-data      ← 원문과 완전히 같은 형식

└─$ printf 'cd www-data\n' | bash
bash: line 1: cd: www-data: No such file or directory   ← bash는 형식이 다르다

| 관측 | 결론 |
|---|---|
| 에러 접두사가 `/tmp/pwned:` (= `$0`) | `/tmp/pwned` 자체가 셸이다. 즉 `cp /bin/sh /tmp/pwned` 폴백이 실행됐다 → **[가정] 타겟에 `gcc` 가 없다.** 폴백은 `gcc` 의 종료 코드가 0이 아닐 때 실행되므로 `gcc` 부재가 가장 유력하지만, `PATH` 에 없거나(웹서버 자식 프로세스의 빈약한 `PATH` — 3-4 참조) 컴파일 자체가 실패한 경우도 같은 결과를 낸다. `which gcc` 를 안 쳤으므로 확정할 수 없다 |
| 에러 형식이 `NN: cd: can't cd to X` | dash 형식이다. Debian의 `/bin/sh` = dash와 일치 (bash는 `bash: line N: cd: X: No such file or directory`) |
| 그 뒤 `whoami` → `www-data` | setuid가 걸리지 않았다. 익스플로잇이 실패했고 그냥 평범한 셸이 하나 더 떴을 뿐이다 |

> [!danger] "셸이 떴다"와 "권한이 올라갔다"는 다르다
> raptor_exim_wiz는 실패해도 셸 프롬프트를 띄운다. `/tmp/pwned` 를 실행하는 마지막 단계가 취약 여부와 무관하게 그냥 실행되기 때문이다. 화면만 보면 뭔가 된 것처럼 보이는데 실제로는 같은 계정의 셸이 하나 더 열린 것뿐이다.
> 권한상승 익스플로잇을 돌린 직후에는 반드시 `id` 를 친다:
> id          # uid=0(root) 인가?
> whoami
> 스크립트가 뱉는 `ls -l /tmp/pwned` 출력도 봐야 한다 — `-rwsr-xr-x`(s가 있음)여야 성공이고, `-rwxr-xr-x` 면 실패다.
> 누적 패턴 "응답이 성공을 뜻하지 않는다"([[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]]·[[pyLoader]])의 권한상승 판이다.
```

---

## P3. B-86. 타겟에 컴파일러가 없다 — C PoC 를 못 빌드한다 — **병합**

**역검색** — B-86 이 이미 존재함. **신규 아님.**

**넣을 본문**

> **[[plum]]** — `raptor_exim_wiz` 는 `gcc` 가 실패하면 `cp /bin/sh /tmp/pwned` 로 조용히 폴백함. 즉 **컴파일러 부재를 스크립트가 말해주지 않고 「setuid 가 안 걸린 평범한 셸」로 나타남**(A-12). 반사 확인:
> ```bash
> which gcc cc make python3 perl
> ```
> 없으면 Kali 에서 정적 링크로 빌드해 전송(`gcc -static -o exp exp.c`, 타겟 아키텍처 일치 필요).
> ⚠️ **[가정]** — 폴백은 `gcc` 의 종료 코드가 0이 아닐 때 실행되므로 `gcc` 부재가 가장 유력하지만, `PATH` 에 없거나(웹서버 자식 프로세스의 빈약한 `PATH`) 컴파일 자체가 실패한 경우도 같은 결과를 냄. [[plum]] 에서 `which gcc` 를 안 쳤으므로 확정 불가임.

**④ 지우기 전 원문**(plum.md 초판 6-②)

```text
`gcc` 가 없는 것 자체도 정보다 — 다만 이 박스에서는 **[가정]** 이다. 타겟에 컴파일러가 없으면 소스 형태의 커널 익스플로잇·SUID 헬퍼가 전부 막힌다. 확인 습관은 이것이다.

which gcc cc make python3 perl

없으면 칼리에서 정적 링크로 컴파일해 전송한다.

gcc -static -o exp exp.c        # 타겟 아키텍처가 같아야 한다

이 박스는 그럴 필요가 없었다 — 애초에 취약하지 않았으니까.
```

---

## P4. A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명 — **병합**

**역검색** — A-64 가 이미 존재함. **신규 아님.** [[plum]] 언급은 아직 없음.

**넣을 본문**

> **[[plum]] 실측 — 「무엇을 했나」가 아니라 「무엇을 «안» 남겼나」가 드러남.**
> 복원 재료 셋: `~/PG/plum/` 파일 mtime · 볼트 스크린샷 파일명(`Pasted image 20260629HHMMSS.png`) · **타겟 메일함에 남은 `sudo` 실패 로그**.
> ```text
> 12:41:58  nmap 완료            nmap.log mtime
> 12:56:42  익스플로잇 클론       pluxml-rce/pluxml.py mtime
> 12:56:51  vi (읽기, 수정 없음)  디렉터리 mtime만 갱신 · git status 클린
> 12:59:32  익스플로잇 출력       스크린샷 125932·125939
> 13:00:31  www-data 셸 확인      스크린샷 130031
> 13:57:06  sudo -l 시도 #1 실패  메일 로그 Jun 29 04:57:06 (UTC)
> 14:08:58  local.txt 획득        스크린샷 140858
> 14:12:46  sudo -l 시도 #2 실패  메일 로그 Jun 29 05:12:46 (UTC)
> 14:21:05  find / -perm -u=s     스크린샷 142105
> 14:23:56  exploit-db 46996 확보  ~/PG/plum/46996 mtime
> 14:28:34  netstat -tulpn        스크린샷 142834
> 14:28:56  메일함 → root 자격증명 스크린샷 142856
> 14:29:47  root 획득             스크린샷 142947
> ```
> **⚠️ 타임존을 먼저 정규화할 것.** 타겟은 EDT(UTC−4), Kali 는 KST(UTC+9)라 메일 로그가 9시간 어긋나 보임. 메일 헤더 `Mon, 29 Jun 2026 00:57:06 -0400` 과 본문 로그 `Jun 29 04:57:06`(UTC)은 **같은 순간**이고 KST 로는 13:57:06 임. 미환산이면 정합한 데이터를 「자기모순」으로 오독함 — 실제로 [[plum]] 에서 「mtime `Jun 29 01:12` 인 파일이 `05:12:46` 줄을 담고 있다」가 모순처럼 보였으나 `05:12:46 UTC = 01:12:46 EDT` 로 **완전 일치**였음.
> **통념이 반증되는 지점** — 「SUID exim4 를 보고 삽질하느라 오래 걸렸다」는 서사가 타임스탬프로 무너짐. `46996` 확보(14:23:56)는 root 획득(14:29:47) **6분 전**이고 메일함 발견 뒤 root 까지는 **51초**였음. **진짜 손실은 13:00:31→13:57:06 의 57분**이고 그 구간에는 산출물이 **하나도 없음**(원인 미상, `[가정]` 조차 못 붙임).
> → **열거를 하면서 파일로 남길 것.** 그러면 사후 복원이 추측이 아니라 실측이 됨:
> ```bash
> { id; sudo -l; ls -la /var/spool/mail/ /var/mail/; ss -lntup; \
>   find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; \
>   cat /etc/crontab; } 2>&1 | tee /tmp/enum.txt
> ```
> **파일 하나의 메타데이터가 도구 사용 이력을 말해줌.** [[plum]] 의 `~/PG/plum/46996` 은 `searchsploit -m` 산출물이 **아님** — Kali 재현으로 반증됨:
>
> | | `searchsploit -m` 산출물 | `~/PG/plum/46996`(실제) |
> |---|---|---|
> | 파일명 | `46996.sh` | `46996`(확장자 없음) |
> | 권한 | `-rwxr-xr-x` | `-rw-rw-r--` |
> | 크기 | 3552 바이트 | 3557 바이트 |
> | 내용 | — | `diff` 상 행말 공백 4곳 + 최종 개행이 더 있음 |
>
> 셋 다 브라우저/`curl` 다운로드의 특징임(`curl -o 46996 https://www.exploit-db.com/download/46996`). 대조군 — [[pyLoader]] 의 `51532.py` 는 `-rwxr-xr-x` 이고 `/usr/share/exploitdb/...` 원본과 바이트 단위 동일하며 스크린샷에 `Copied to: …` 줄까지 찍혀 있음(그쪽이 진짜 `searchsploit`). **보고서에 「이 도구를 썼다」고 적기 전에 산출물을 대조할 것.**

**④ 지우기 전 원문**(plum.md 초판 6-① 콜아웃 · 6-③ 후반 · 6-④ 전문)

```text
> [!warning] 이건 `searchsploit` 산출물이 **아니다.** exploit-db 웹에서 직접 받은 것이다
> 한 번 실행해보면 반증된다:
> ┌──(kali㉿kali)-[/tmp/vtest46996]
> └─$ searchsploit -m 46996
>   Exploit: Exim 4.87 - 4.91 - Local Privilege Escalation
>     Codes: CVE-2019-10149
> Copied to: /tmp/vtest46996/46996.sh          ← ★ 확장자 .sh 가 보존된다
>
> └─$ ls -l
> -rwxr-xr-x 1 kali kali 3552 …  46996.sh      ← ★ 실행 권한이 붙는다
> 로컬 산출물과 세 군데가 다르다.
> | | `searchsploit -m` 산출물 | `~/PG/plum/46996` (실제) |
> |---|---|---|
> | 파일명 | `46996.sh` | `46996` (확장자 없음) |
> | 권한 | `-rwxr-xr-x` | `-rw-rw-r--` |
> | 크기 | 3552 바이트 | 3557 바이트 |
> | 내용 | — | `diff` 상 행말 공백 4곳 + 최종 개행 이 더 있다 |
> 이 세 가지는 전부 브라우저/`curl` 다운로드의 특징이다 — `curl -o 46996 https://www.exploit-db.com/download/46996` 은 정확히 이 결과를 낸다(exploit-db의 `/download/` 는 원본 텍스트를 그대로 내려주고, 그쪽 사본에는 행말 공백이 남아 있다).
> 대조군이 같은 노트 밖에 있다 — [[pyLoader]]의 `51532.py` 는 `-rwxr-xr-x` 이고 로컬 사본이 `/usr/share/exploitdb/...` 원본과 바이트 단위로 동일하며 스크린샷에 `Copied to: …` 줄까지 찍혀 있다. 그쪽은 진짜 `searchsploit` 이다.
> **파일 하나의 메타데이터가 도구 사용 이력을 말해준다.** `ls -l` 의 권한 비트·확장자 유무·바이트 크기 셋만 봐도 어떻게 받았는가가 대개 갈린다. 보고서에 "이 도구를 썼다"고 적기 전에 산출물을 대조하라.
```

```text
메일함 mtime `Jun 29 01:12` 은 모순이 아니다. 4-2의 `ls -al` 은 `-rw-rw---- 1 www-data mail 4528 Jun 29 01:12 www-data` 를 보여주고 본문 로그의 마지막 줄은 `Jun 29 05:12:46` 이다. "01:12 인 파일이 05:12 에 쓰인 줄을 담을 수 있는가?" — 담을 수 있다.

로그 본문 05:12:46 (UTC)  →  타겟 로컬 01:12:46 (EDT, UTC−4)  →  KST 14:12:46
ls -al 의 mtime 은 타겟 로컬 시각으로 렌더된다  →  01:12 (EDT)

완전 일치한다. mtime `01:12` 은 두 번째 `sudo` 실패가 만든 메일이 배달된 순간이고, 첫 번째(04:57:06 UTC = 00:57 EDT)가 아니다. 디렉터리 `.` 의 mtime도 같은 `Jun 29 01:12` 인데, 이는 exim/procmail이 배달 시 락 파일을 만들었다 지우면서 디렉터리 mtime을 건드린 흔적으로 설명된다(**[가정]**).

이 절이 6-④의 타임존 규칙이 왜 필요한지 보여주는 실례다. 정규화하지 않으면 정합한 데이터를 모순으로 오독하게 된다.
```

```text
### ④ 실제 타임라인 — 산출물 타임스탬프로 복원

기억이나 서술 순서가 아니라 파일 mtime · 스크린샷 파일명 · 메일 로그로 재구성한 것이다. 전부 실측이다.

| 시각(KST) | 사건 | 근거 |
|---|---|---|
| 12:41:58 | nmap 완료 | `~/PG/plum/nmap.log` mtime |
| 12:56:42 | 익스플로잇 클론 | `pluxml-rce/pluxml.py` mtime |
| 12:56:51 | `vi pluxml.py` (읽기, 수정 없음) | 디렉터리 mtime만 갱신 · `git status` 클린 |
| ~12:57 | 익스플로잇 실행 | — |
| 12:59:32 | 익스플로잇 출력 `[+] Check your listener...` | 스크린샷 `20260629125932`·`125939` |
| 13:00:31 | `www-data` 셸 확인 (`whoami` → `www-data`) | 스크린샷 `20260629130031` |
| 13:57:06 | `sudo -l` 시도 #1 → 실패 | 메일 로그 `Jun 29 04:57:06 ... COMMAND=list` (UTC) |
| 14:08:58 | `local.txt` 획득 | 스크린샷 `20260629140858` |
| 14:12:46 | `sudo -l` 시도 #2 → 실패 | 메일 로그 `Jun 29 05:12:46 ...` (UTC) |
| 14:23:56 | exploit-db `46996` 내려받음 — exim 익스플로잇 확보 (`searchsploit` 아니다 — 6-① 정정) | `~/PG/plum/46996` mtime |
| 14:28:34 | `netstat -tulpn` | 스크린샷 `20260629142834` |
| 14:28:56 | 메일함 발견 → root 자격증명 | 스크린샷 `20260629142856` |
| 14:29:47 | root 획득 | 스크린샷 `20260629142947` |

타겟은 EDT(UTC−4), 칼리는 KST(UTC+9)라 메일 로그가 9시간 어긋나 보인다. 메일 헤더의 `Mon, 29 Jun 2026 00:57:06 -0400` 과 본문 로그의 `Jun 29 04:57:06`(UTC)은 같은 순간이고 KST로는 13:57:06이다. 여러 호스트의 로그를 대조할 때는 타임존부터 정규화해야 "먼저 일어난 일"과 "나중에 일어난 일"을 뒤집어 읽지 않는다.

이 타임라인이 통념과 다른 것을 두 가지 말해준다. 하나는 exim 익스플로잇이 시간을 별로 안 잡아먹었다는 것이다 — 확보(14:23:56)부터 메일함 발견(14:28:56)까지 약 5분이고, 익스플로잇을 손에 넣은 시점이 root 획득 6분 전이라 "SUID를 보고 삽질하다 한참을 날렸다"는 서사가 들어설 창 자체가 없다. 다른 하나는 진짜 공백이 13:00 → 13:57 사이 약 57분이라는 것이다. 이 구간에 무슨 열거를 했는지 산출물에 아무 기록이 없다. 4-1의 `find / -perm -u=s` 도 이 구간 어딘가로 추정되지만 **[가정]** 이고, 그 외에 무엇을 했는지는 미확인이다.

셸을 잡고(13:00:31) 첫 플래그(14:08:58)까지 68분이 걸렸는데 그 사이 산출물이 하나도 없다. 교훈은 "exim을 던지지 말았어야 했다"가 아니라 무엇을 했는지 남기지 않았다는 쪽이다. 기록이 없으면 다음에 같은 실수를 반복해도 알 수 없다. 실전 습관으로 셸을 잡으면 열거 출력을 파일로 남긴다.

{ id; sudo -l; ls -la /var/spool/mail/ /var/mail/; ss -lntup; \
  find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; \
  cat /etc/crontab; } 2>&1 | tee /tmp/enum.txt

그리고 칼리로 회수한다. 시험 리포트의 증거이자 나중에 노트를 쓸 때의 1차 사료가 된다.
```

> ⚠️ **반영자 주의 — 원문 타임라인의 `find / -perm -u=s` 행을 그대로 옮기지 말 것.**
> 초판은 그것을 「57분 공백 어딘가로 추정 `[가정]`」이라고 적었으나 **반증됨** — 볼트에 `Pasted image 20260629142105.png` 가 있고 그 화면이 정확히 `find / -perm -u=s 2>/dev/null` 출력임. 실행 시각은 **14:21:05 KST 로 확정**이고, 57분 공백에는 여전히 **아무 산출물도 없음.** 위 「넣을 본문」의 타임라인이 정정본임.

---

## P5. A-41. 셸은 잡았는데 권한상승 실마리가 없다 — **병합** (자격증명 사냥 체크리스트)

**역검색** — A-41 존재. `_PLAYBOOK:6266`(C-2)이 이미 「[[plum]] 은 메일함」이라고 이름만 언급함. **자격증명 사냥 목록에 메일함 경로가 없음** — 그 목록을 보강하는 제안임. B-2-13 은 **네트워크 POP3/IMAP** 카드라 「셸에서 로컬 메일함을 연다」와 진입점이 다름.

**넣을 본문**

> **`www-data` 같은 서비스 계정으로 떨어졌으면 SUID·크론보다 «자격증명 사냥»이 먼저임** — 싸고 안정적이고 흔적이 적음. 체크리스트:
> ```bash
> cat ~/.bash_history                      # HOME 미설정이면 /home/*/.bash_history
> ls -la /var/www/html/                    # config.php · .env · wp-config.php
> grep -rn "password\|passwd\|secret" /var/www/ 2>/dev/null | head
> ls -la /var/spool/mail/ /var/mail/       # ★ 로컬 메일함 — 자주 잊힘
> ls -la ~/mbox ~/Maildir/                 # ★
> ls -la /opt /srv /backup
> find / -name "*.bak" -o -name "*.old" 2>/dev/null | head
> ```
> ★ 두 줄이 [[plum]] 의 정답이었음 — `/var/spool/mail/www-data` 는 **소유자가 `www-data`** 라 셸 계정이 그대로 읽었고, 본문에 `root:6s8kaZZNaZZYBMfh2YEW` 가 평문으로 있었음. 셸 획득(13:00:31)부터 확인(14:28:56)까지 **88분**이 걸림.
> **메일함을 볼 신호는 정찰에서 이미 나옴** — ⑴ 앱 진단 페이지의 `Mail sending function available` ⑵ `netstat`/`ss` 의 `127.0.0.1:25`(루프백 MTA, 외부 nmap 에 안 잡힘). 둘 중 하나라도 보이면 메일함이 존재함.
> **리눅스 권한상승 열거 순서 — ②가 ⑥보다 앞임:**
> ```text
> ① id · sudo -l                    ← 가장 싸고 가장 자주 정답
> ② 자격증명 사냥                    ← 설정파일 · 히스토리 · 백업 · ★메일함
> ③ netstat/ss -lntup               ← 루프백 서비스 (외부 스캔에 안 잡힘)
> ④ find / -perm -4000 · getcap -r /
> ⑤ crontab · /etc/cron.*
> ⑥ 커널/서비스 CVE                  ← ★ 반드시 버전 확인 후에 (A-13)
> ```
> **`sudo -l` 은 한 번 실패하면 접을 것.** 비밀번호를 모르면 정보를 못 주고(`NOPASSWD` 항목이 없으면 목록조차 안 나옴) 실패 로그만 남음. [[plum]] 은 15분 간격으로 **두 번** 시도해 둘 다 실패했고 그 로그가 메일함에 쌓였음.
> ⛔ **「`sudo` 실패는 기본적으로 root 에게 메일을 보낸다」는 틀림.** `sudoers(5)` 실측:
> ```text
> mail_badpass    Send mail to the mailto user if the user running sudo
>                 does not enter the correct password.  …  This flag is off
>                 by default.
>
> mail_no_user    If set, mail will be sent to the mailto user if the
>                 invoking user is not in the sudoers file.  This flag
>                 is on by default.
> ```
> 기본 ON 은 `mail_no_user` 뿐이고 **`mail_badpass` 는 기본 OFF** 임. [[plum]] 에서 관측된 문구는 정확히 `1 incorrect password attempt` = `mail_badpass` 템플릿이므로 **그 박스가 특별히 켜둔 것**임. → **「메일이 안 왔으니 안 들켰다」로 읽지 말 것** — 같은 man 페이지가 *"By default, all attempts to run sudo (successful or not) are logged, regardless of whether or not mail is sent."* 라고 못 박음.

**④ 지우기 전 원문**(plum.md 초판 6-③ 전문 · 6-④ 후반 · 4-2 발췌)

```text
### ③ `sudo -l` 을 두 번 시도했고 두 번 실패했다 — 메일함이 그것을 기록했다

메일함 뒷부분에 우리가 만든 로그가 들어 있다:

localhost : Jun 29 04:57:06 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list
...
localhost : Jun 29 05:12:46 : www-data : 1 incorrect password attempt ; PWD=/tmp ; USER=root ; COMMAND=list

> [!warning] 근거 등급 — 이 발췌도 **[가정]** 이다
> 4-2의 스크린샷은 메일 **첫 통의 본문까지만** 보여주고 끊긴다. 위 두 줄은 **초판의 터미널 기록에서 옮긴 것**이며 산출물로 재검증되지 않았다.
> 다만 **완전한 날조는 아니라고 볼 근거**가 있다 — 두 시각을 KST로 환산하면 **13:57:06 · 14:12:46** 이고, 이는 6-④의 스크린샷 타임라인(12:59:32 실행 → 14:08:58 `local.txt` → 14:23:56 `46996`)과 **모순 없이 끼워진다.** 지어낸 시각이 이렇게 맞아떨어지기는 어렵다.

`COMMAND=list` 는 `sudo -l` 이다. 15분 간격으로 두 번, `PWD=/tmp` 에서 시도했고 비밀번호를 몰라 둘 다 실패했다.

**[가정]** 그 실패가 root 앞 보안 경고 메일을 발생시켰고, root 앞 메일이 로컬 별칭으로 배달되지 못해 반송본이 `www-data` 메일함에 쌓인 것으로 본다. `sudo` 로그 줄이 `/var/spool/mail/www-data` 안에 들어 있다는 관측 자체는 확실하지만, `Unrouteable address` 라는 특정 에러나 `debian@localhost` 라는 특정 별칭은 어떤 산출물에도 없다.

> [!warning] "`sudo` 실패는 기본적으로 root에게 메일을 보낸다"는 틀렸다
> `sudoers(5)` 실측:
> mail_badpass    Send mail to the mailto user if the user running sudo
>                 does not enter the correct password.  …  This flag is off
>                 by default.
>
> mail_no_user    If set, mail will be sent to the mailto user if the
>                 invoking user is not in the sudoers file.  This flag
>                 is on by default.
> 기본 ON 인 것은 `mail_no_user`(sudoers에 없는 사용자)뿐이고, `mail_badpass`(비밀번호 오류)는 기본 OFF다. 그런데 관측된 문구는 정확히 `1 incorrect password attempt` — `mail_badpass` 템플릿이다. 즉 이 박스가 `mail_badpass` 를 특별히 켜둔 것이고, 그 덕분에 메일함이 갱신되어 결과적으로 들여다볼 이유를 하나 더 만들었다.
> 이것이 [[_WRITEUP-STANDARD]]가 "특히 위험한 형태"로 지목한 승격의 전형이다 — *"이 박스가 이랬으니 일반적으로 이렇다."* 이 박스에서 메일이 왔다는 관측을 확인 없이 sudo의 기본 동작으로 일반화했다. 일반화의 근거는 관측이 아니라 별도 확인이어야 한다. `man 5 sudoers` 한 번이면 끝났다.
> 실전 함의도 뒤집힌다. 기본 구성에서는 비밀번호를 틀려도 메일이 가지 않는다. 다만 로그는 항상 남는다(`auth.log`/`journald`) — 같은 man 페이지가 *"By default, all attempts to run sudo (successful or not) are logged, regardless of whether or not mail is sent."* 라고 못 박는다. "메일이 안 왔으니 안 들켰다"고 읽지 마라.

`sudo -l` 은 비밀번호를 모르면 정보를 못 준다. `NOPASSWD` 항목이 있으면 비밀번호 없이도 목록이 나오지만, 없으면 그냥 실패 로그만 남는다. **두 번 시도할 가치는 없다**.
```

```text
리눅스 권한상승 열거는 순서를 이렇게 고정한다.

① id · sudo -l                    ← 가장 싸고 가장 자주 정답
② 자격증명 사냥                    ← 설정파일 · 히스토리 · 백업 · ★메일함
③ netstat/ss -lntup               ← 루프백 서비스 (외부 스캔에 안 잡힘)
④ find / -perm -4000 · getcap -r /
⑤ crontab · /etc/cron.*
⑥ 커널/서비스 CVE                  ← ★ 반드시 버전 확인 후에

**②가 ⑥보다 앞이다**. 자격증명은 익스플로잇보다 싸고 안정적이며 흔적이 적다. 이 박스는 정답이 ②(메일함)에 있었는데 셸 획득 후 88분이 지나서야 확인했다(13:00:31 → 14:28:56). ②의 체크리스트에서 이 박스에 잊혔던 항목에 ★를 붙이면 이렇다.

cat ~/.bash_history                      # HOME 미설정이면 /home/*/.bash_history
ls -la /var/www/html/                    # config.php · .env · wp-config.php
grep -rn "password\|passwd\|secret" /var/www/ 2>/dev/null | head
★ ls -la /var/spool/mail/ /var/mail/     # 메일함 ← 이 박스의 정답
ls -la /opt /srv /backup
find / -name "*.bak" -o -name "*.old" 2>/dev/null | head
```

```text
메일함 뒷부분에는 우리 자신의 실패 기록도 남아 있다 — 6장 ③에서 다룬다.
```

---

## P6. A-44. 셸을 잡으면 `netstat -tulpn` 도 친다 — **병합**

**역검색** — A-44 존재. **신규 아님.** 아래 둘이 빠져 있음 — ⑴ 「도구가 없는 게 아니라 PATH 가 없다」의 **리눅스판**(A-3-11 은 Windows 판임) ⑵ 루프백 MTA 를 자격증명 경로로 연결하는 신호 해석.

**넣을 본문**

> **웹 계정 셸을 잡으면 `HOME`·`PATH`·`TERM` 부터 세울 것.** Apache 가 띄운 자식 프로세스는 환경을 거의 물려받지 않음 — [[plum]] 은 인자 없는 `cd` 가 `bash: cd: HOME not set` 으로 실패했음.
> ```bash
> export HOME=/tmp; export TERM=xterm; export PATH=$PATH:/usr/sbin:/sbin
> ```
> ⚠️ **`/usr/sbin:/sbin` 을 빼면 `netstat`·`ss`·`iptables` 가 「command not found」로 보임** — 도구가 없는 게 아니라 경로가 없는 것임(Windows 판은 A-3-11).
> **루프백 전용 서비스는 외부 스캔에 원리적으로 안 잡힘.** [[plum]] 은 외부 nmap 이 22/80 만 봤는데 셸 안에서는 `127.0.0.1:25` 가 있었음:
> ```text
> tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
> ```
> 25 가 보이면 ⑴ 로컬 MTA 가동 ⑵ **메일함이 존재**함이 함께 확정됨 → `/var/spool/mail/` 로 직행(A-41). [[plum]] 은 그것이 정답이었음.

**④ 지우기 전 원문**(plum.md 초판 3-4 · 4-1 · 7-11·12 발췌 — 3-4 의 `export` 블록과 셸 획득 서술은 **노트에 그대로 남겨 두었음**)

```text
11. 웹 계정 셸을 잡으면 `HOME`·`PATH`·`TERM` 부터 세운다. `export PATH=$PATH:/usr/sbin:/sbin` 없이는 `netstat`·`ss` 가 "command not found"로 보인다 — 도구가 없는 게 아니라 경로가 없는 것이다.
12. 셸을 잡으면 `netstat -tulpn`/`ss -lntup` 을 반드시 다시 돌린다. 루프백 전용 서비스(여기서는 `127.0.0.1:25`)는 외부 nmap에 원리적으로 안 잡히고, 이게 권한상승 경로를 알려주는 경우가 많다.
13. ★ **메일함을 열거 목록에 넣어라**. `/var/spool/mail/` · `/var/mail/` · `~/mbox` · `~/Maildir/`. 이 박스의 정답이었다. `Mail sending function available` 같은 신호가 있으면 더더욱.
14. **자격증명 사냥이 익스플로잇보다 먼저다**. 설정파일·히스토리·백업·메일함 — 싸고 안정적이고 흔적이 적다.
```

---

## P7. A-2-14. 웹셸을 심을 웹루트를 «틀린 곳»에 골랐다 — **병합** (인접 증상)

**역검색** — 증상 「저장은 됐는데 웹셸이 실행 안 됨 / 지정한 파일이 안 생겼다」로 역검색함. 후보 셋 — A-2-14(웹셸 심을 곳을 틀림) · A-2-21(올렸는데 실행이 401) · A-2-26(업로드가 죽어 있다). **가장 가까운 것이 A-2-14** 라 그 아래 병합을 제안함. 반영자가 별도 항목이 낫다고 보면 신규로 승격해도 됨(번호는 반영자가 배정).

**넣을 본문**

> **「지정한 파일명이 안 생겼다」가 「아무 일도 안 일어났다」가 아닐 수 있음 — 다른 파일이 대신 덮였을 수 있음.**
> [[plum]] 의 PluXml 템플릿 편집기는 `realpath()` 로 경로를 확정하는데 **`realpath()` 는 존재하지 않는 경로에 `false` 를 반환**함:
> ```bash
> php -r 'var_dump(realpath("/tmp/definitely_does_not_exist_12345.php")); var_dump(realpath("/etc/hostname"));'
> ```
> ```text
> bool(false)
> string(13) "/etc/hostname"
> ```
> 그 `false` 가 문자열 문맥에서 `""` 로 캐스팅 → 접두사 정규식 검사 실패 → **`$tpl` 이 조용히 `home.php` 로 폴백**되고 재계산됨. 결과는 「쓰기 실패」가 아니라 **사이트 첫 화면이 웹셸로 덮이는 것**임.
> → **파일 쓰기가 「신규 생성」인지 「덮어쓰기」인지부터 확정할 것.** 신규 생성이 막힌 앱에서는 **테마에 실재하는 파일**을 명시적으로 골라 덮어써야 함.
> → **「반응이 없다」고 접기 전에 `/` 를 열어 첫 화면을 확인할 것** — 이미 심겨 있을 수 있음.
> → 어느 파일을 고를 것인가: `home.php`(첫 화면, 접근 쉽고 가장 눈에 띔) · `static.php`(정적 페이지에서만 렌더, 덜 띄고 경로 명확) · `footer.php`/`sidebar.php`(모든 페이지에 include 돼 어디서든 트리거되지만 티가 남).
> ⚠️ **드롭다운에 있는 값만 고를 수 있다」는 클라이언트 측 제약임.** PluXml 의 유일한 확장자 화이트리스트는 **편집기 드롭다운 목록을 만드는 용도**이고 거기에도 `.php` 가 들어 있으며, 쓰기 경로(`plxUtils::write`)에는 확장자 검사가 **아예 없음**. **선택지가 제한된 폼을 보면 값을 직접 바꿔 POST 해 볼 것.**

**④ 지우기 전 원문**(plum.md 초판 6-⑤ 표 · 7-5 — 2-3 의 소스·재현 블록은 **노트에 그대로 남겨 두었음**)

```text
### ⑤ 이 유형에서 흔히 막히는 지점 (이 박스에서는 겪지 않았다 — 구분해서 적는다)

| 증상 | 원인 후보 | 확인 / 대응 |
|---|---|---|
| 템플릿 저장이 `Security error : invalid or expired token` | 토큰 재사용. 세션의 토큰이 전부 삭제된 상태 | 재로그인부터. 매 POST 전에 토큰을 새로 긁는다(2-4) |
| 저장은 되는데 웹셸이 실행 안 됨 | 잘못된 템플릿 파일을 골랐다 (그 페이지가 렌더되지 않음) | `footer.php`·`header.php` 처럼 모든 페이지에 include되는 것으로 바꾼다 |
| 저장 자체가 실패 | `themes/` 쓰기 권한 없음 | Information 페이지의 초록 체크를 먼저 확인(1-3) |
| ★ 새 파일명을 지정했더니 `home.php` 가 웹셸로 덮였다 (또는 "지정한 파일이 안 생겼다") | `realpath()` 가 `false` → 정규식 검사 통과 실패 → `$tpl='home.php'` 폴백 후 재계산. 신규 생성은 불가하고 대상이 첫 화면으로 바뀐다 | 기존 파일을 명시적으로 덮어써라(2-3). 반응이 없어 보이면 `/` 를 열어 `home.php` 를 확인 — 이미 심겼을 수 있다 |
| `system()` 이 빈 값 | `disable_functions` 에 등록됨 | `phpinfo()` 확인 → `passthru`·`shell_exec`·`popen`·`proc_open` 중 살아 있는 것으로 교체 |
| 리버스셸이 안 붙음 | 아웃바운드 차단 / LHOST 오기 | 443·80·53 시도. `ip -br a` 로 `tun0` 재확인 |
| `su` 가 비밀번호를 안 받는 것처럼 보임 | TTY 부재가 원인이 아니다(4-3 정정) — util-linux `su` 는 stdin에서 읽는다. 대개는 비밀번호 자체가 틀렸거나 `su` 가 별도 PAM 정책에 막힌 것 | `su: Authentication failure` 문구를 그대로 읽어라. 그래도 TTY를 올리면 조작이 편하다: `python3 -c 'import pty; pty.spawn("/bin/bash")'` |

5. 파일 쓰기가 신규 생성인지 덮어쓰기인지 확인한다. PluXml은 `realpath()` 때문에 기존 파일만 덮어쓸 수 있다. 그리고 실패가 조용하지 않다 — 없는 파일명을 넣으면 대상이 `home.php` 로 강제 폴백되어 첫 화면이 웹셸로 덮인다(2-3). "반응이 없다"고 포기하기 전에 `/` 를 열어봐라.
```

---

## P8. B-1-14. CSRF 벽은 토큰을 실시간 파싱해 넘는다 — **병합**

**역검색** — B-1-14 존재. **신규 아님.**

**넣을 본문**

> **1회용 토큰은 실패의 대가가 큼.** [[plum]] 의 PluXml 은 토큰을 **소비 즉시 폐기**하고, 없는 토큰이 오면 `unset($_SESSION['formtoken'])` 로 **그 세션의 토큰을 전부 날린 뒤** `die()` 함 — 한 번 실수하면 그 세션의 모든 폼이 죽어 **로그인부터 다시** 해야 함.
> ⚠️ 게다가 `die('Security error : invalid or expired token')` 는 **200 응답**으로 옴 — 상태 코드만 보면 성공처럼 보임(A-12). **자동화가 이상하면 응답 본문을 파일로 통째로 저장해 눈으로 볼 것.**
> **웹앱 자동화에서 걸리는 함정은 대개 셋임** — ⑴ CSRF 토큰이 1회용이거나 매 요청 갱신됨([[plum]] · [[Squid]] phpMyAdmin) ⑵ 세션 쿠키 미유지(`requests.Session()` 필수) ⑶ 환경변수 프록시 개입(`trust_env=False`, [[Squid]]). **셋 다 HTTP 에러가 아니라 「엉뚱한 페이지」로 나타나서 원인 찾기가 오래 걸림.**
> **패턴 — 「저장」 전에 「불러오기」를 한 번 더 치는 2단계 POST.** 첫 요청의 목적은 파일을 여는 것이 아니라 **새 토큰을 받는 것**임.

**④ 지우기 전 원문**(plum.md 2-4 산문 — 소스 블록과 2단계 POST 블록은 **노트에 그대로 남겨 두었음**)

```text
웹앱 자동화에서 걸리는 함정은 대개 셋이다 — CSRF 토큰이 1회용이거나 매 요청 갱신되는 것(이 박스, 그리고 [[Squid]]의 phpMyAdmin), 세션 쿠키 미유지(`requests.Session()` 필수, 익스플로잇도 `s = requests.Session()` 을 쓴다), 환경변수 프록시 개입(`trust_env=False`, [[Squid]]). 셋 다 HTTP 에러가 아니라 "엉뚱한 페이지"로 나타나서 원인 찾기가 오래 걸린다. 여기서는 더 나쁘다 — `die('Security error : invalid or expired token')` 라는 **200 응답**이 오므로 상태 코드만 보면 성공처럼 보인다. 자동화가 이상하면 응답 본문을 파일로 통째로 저장해서 눈으로 봐라. 누적 패턴 "응답이 성공을 뜻하지 않는다"([[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]])의 또 다른 얼굴이다.
```

---

## P9. B-1-36. 인증 후 파일 업로드 → RCE — **병합** (「테마·템플릿 편집기」 행 보강)

**역검색** — B-1-36 의 표에 이미 `| 테마·템플릿 편집기 | 템플릿에 PHP 코드 삽입 후 페이지 렌더 |` 행이 있음. **신규 아님.**

**넣을 본문**

> **테마·템플릿 편집기는 「취약점」이 아니라 «설계된» 코드 실행임 — 그래서 업그레이드로 안 막힘.**
> [[plum]](PluXml 5.8.7, CVE-2024-48138) 실측 — `core/admin/parametres_edittpl.php` 의 저장 로직이 **v5.8.7(2021) · v5.8.16 · v5.8.23(2026) 이 사실상 동일**함(세 태그 diff 는 `include` 경로 표기 3곳뿐). 벤더도 발견자도 「관리자는 PHP 템플릿을 편집할 수 있다」를 정상 기능으로 봄(*"can always execute arbitrary code"*). master 가 `$tpl` 화이트리스트를 넣어 임의 파일명은 막았으나 **화이트리스트에 `.php` 가 남아 있어 「관리자 = 코드 실행」은 그대로**임.
> → **관리자 세션을 얻었으면 CVE 를 찾지 말고 관리자 기능 목록부터 셀 것.** 테마·템플릿 편집기 · 플러그인 업로드 · 백업/복원 · 파일 관리자 · 크론/작업 스케줄러 — 하나라도 있으면 이미 RCE 임.
> **`eval()` 이 필요 없음** — 테마 템플릿은 데이터가 아니라 `include` 되는 PHP 소스라 **파일 내용이 곧 코드**임.
> **DB 가 없는 CMS 는 공격면이 「파일 시스템」으로 옮겨간 것뿐임.** PluXml 은 XML 파일 저장이라 SQLi 면이 아예 없고, 대신 웹서버 계정이 웹 루트에 쓰기 권한을 가져야 앱이 돎 — **「임의 파일 쓰기」가 정상 기능**이고 그것이 그대로 공격면임. 저장 방식별로: RDBMS → SQLi `INTO OUTFILE`/`DUMPFILE` · 역직렬화 저장 → insecure deserialization · 플랫파일/XML → 파일 쓰기 권한 · XXE · 트래버설.
> **앱의 진단 페이지가 공격 전제조건을 대신 확인해줌** — PluXml 의 Information 화면이 `themes/ has write access` 를 **초록 체크**로 알려줬음. 찾을 이름: `Information` · `System Status` · `Site Health`(WordPress) · `phpinfo.php` · `info.php` · `server-status` · `/actuator/env`. **디렉터리 브루트 30분보다 이 페이지 30초가 나음**([[Squid]] 의 `phpsysinfo`·`testmysql.php` 가 같은 역할).

**④ 지우기 전 원문**(plum.md 초판 0장 · 7-2·3·4 발췌 — 2-1·2-2 의 소스 인용은 **노트에 남겨 두었음**)

```text
- 테마·템플릿 편집기가 있는 CMS에서 관리자 자격증명은 이미 셸이다. 별도 취약점을 찾을 필요가 없다
- 애플리케이션의 진단 페이지가 공격 전제조건을 대신 확인해준다 — PluXml의 Information 화면이 `themes/ has write access` 를 초록 체크로 알려줬다

시험 출제 가능성으로 보면, **CMS 기본 자격증명 → 관리자 기능으로 RCE** 가 제일 높다. WordPress 테마 편집기, Joomla 템플릿, Drupal PHP 필터, Grav, PluXml이 전부 같은 구조이고 OSCP 웹 foothold의 대표 유형이다.

변형은 이런 모습이다 — PluXml 대신 WordPress `theme-editor.php`, 메일함 대신 `~/.bash_history`·`config.php`·백업 파일. 원리는 같다.

2. 로그인에 성공하면 곧바로 "관리자가 할 수 있는 일"을 목록화한다. 테마·템플릿 편집기, 플러그인 업로드, 백업/복원, 파일 관리자, 크론/작업 스케줄러. 이 중 하나라도 있으면 이미 RCE이고 CVE를 찾을 필요가 없다.
3. Information / System Status / Site Health 페이지를 먼저 찾는다. 버전·PHP 버전·쓰기 가능 디렉터리·활성 모듈을 한 번에 준다. 디렉터리 브루트포싱보다 효율이 훨씬 높다.
4. "쓰기 가능"을 앱이 확인해줬다면 그것이 곧 전제조건 충족이다. `themes/ has write access` 초록 체크가 익스플로잇 성공을 사실상 보증했다.
```

---

## P10. B-1-37. 로그인 폼을 만나면 기본 자격증명이 1순위 — **병합** (제품별 기본값 표에 1행)

**역검색** — B-1-37 존재. **신규 아님.**

**넣을 본문**

> 표에 1행 추가 — `| PluXml | admin / admin | /core/admin/ | [[plum]] 실측 |`
> 그리고 순서 규율 한 줄: **기본 자격증명 → 다른 서비스에서 주운 자격증명 재사용 → 브루트포스.** 기본값 3~5개는 **1분**이면 끝나고 통하면 몇 시간을 아낌. `hydra`·`wfuzz` 는 시험에서 쓸 수 있지만 시간을 잡아먹으므로 뒤임.

**④ 지우기 전 원문**(plum.md 1-2 · 7-1)

```text
CMS를 보면 기본 자격증명이 1순위다. `admin/admin` · `admin/password` · `admin/<제품명>` · `root/root` 를 3~5개만 손으로 시도한다. 통하면 몇 시간을 아끼고 안 통해도 1분밖에 안 든다. [[Codo]]·[[Astronaut]]·[[Levram]]·[[Crane]]에서 반복된 패턴이다. 브루트포스(`hydra`·`wfuzz`)는 시험에서 쓸 수 있지만 시간을 잡아먹으니 순서를 기본 자격증명 → 다른 서비스에서 주운 자격증명 재사용 → 브루트포스로 둔다.

1. CMS 이름이 보이면 기본 자격증명이 1순위다. `admin/admin` · `admin/password` · `admin/<제품명>` 을 3~5개, 1분 안에. 브루트포스는 그 다음의 다음이다.
```

---

## P11. B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다 — **병합**

**역검색** — B-6-12 존재. **신규 아님.**

**넣을 본문**

> **재사용 시험 순서 — `su -` 가 SSH 보다 먼저임:**
> ```text
> ① su -                     ← root부터. 성공하면 나머지가 필요 없다
> ② su <각 로컬 계정>         ← /etc/passwd 에서 UID>=1000 목록
> ③ ssh <계정>@localhost      ← 로컬 셸이 있으면 su가 우선이지만, 안정된 TTY가 필요하면 ssh
> ④ 다른 웹 패널 / DB / 서비스
> ```
> SSH 는 `PermitRootLogin`·`AllowUsers` 에 막힐 수 있고 **그 거부를 「비밀번호 틀림」으로 오독하기 쉬움**(A-24). [[plum]] 은 `su -` 한 번에 root — 메일함 발견부터 root 까지 **51초**였음. 누적: [[Codo]] · [[Scarlet]] · [[Zipper]] · [[plum]].
> ⚠️ **`su` 가 아니라 `su -` 를 쓸 것.** `su root` 는 환경을 물려받아 `PATH` 가 www-data 것이고, `su -` 는 로그인 셸이라 `/root` 로 이동하고 `PATH`·`HOME`·프로필이 root 것으로 새로 섬 — 웹 계정 셸의 `HOME not set` 문제가 한 번에 정리됨.

**④ 지우기 전 원문**(plum.md 4-3 후반 · 7-19·20 — `su`/TTY 판정 서술과 `su -` 실측 블록은 **노트에 남겨 두었음**)

```text
19. 평문 비밀번호를 주우면 `su -` 로 root부터 시험한다. 성공하면 나머지가 필요 없다. **`su` 는 TTY 없이도 동작한다** — util-linux `su` 는 stdin에서 비밀번호를 읽으므로 PTY를 못 올렸다고 `su` 를 포기하지 마라(4-3). 이 박스가 정확히 TTY 없는 리버스셸에서 `su -` 로 root를 잡았고, 비밀번호가 화면에 에코된 것이 그 증거다. ([[Codo]]·[[Scarlet]]·[[Zipper]])
20. `su -` 를 쓴다(`su` 가 아니라). `HOME`·`PATH` 가 root 것으로 새로 서고, 웹 계정 셸의 `HOME not set` 문제가 한 번에 정리된다.
```

> ⚠️ **반영자 주의 — 위 19번의 「비밀번호가 화면에 에코된 것이 그 증거다」를 옮기지 말 것.**
> `_PLAYBOOK` A-3-10 이 이미 반증해 둠 — `Password:` 뒤 평문은 **리스너 쪽 로컬 터미널의 타이핑 에코**로 설명되므로 **타겟 TTY 부재의 증거가 아님.** [[plum]] 의 PTY 부재 근거는 셸 획득 시점의 `bash: cannot set terminal process group` · `bash: no job control in this shell` 와 PTY 승격 기록 부재임. 노트 본문은 이미 정정해 두었음.

---

## P12. C-3. 플래그·증거 — **병합**

**역검색** — C-3 존재. `dir C:\` 사례([[Squid]])가 이미 있음. **리눅스판 탐색 순서가 없음.**

**넣을 본문**

> **리눅스 — 플래그가 표준 위치에 없을 수 있음.** 일반 사용자 계정이 없는 박스에서는 `local.txt` 가 서비스 계정이 읽을 수 있는 곳에 놓임. [[plum]] 은 `/var/www/local.txt` 였음(셸 계정이 `www-data` 라 홈 디렉터리가 없음).
> ```bash
> ls -la /home/*/ 2>/dev/null            # ① 표준 위치
> ls -la /var/www/ /var/www/html/        # ② 웹 계정으로 잡았다면 여기
> ls -la /tmp /opt /srv                  # ③ 흔한 대안
> find / -name "local.txt" -o -name "proof.txt" 2>/dev/null   # ④ 최후
> ```
> ④는 느리니 ①~③을 먼저 침. **표준 위치 가정은 자주 깨짐** — [[Squid]] 는 `C:\local.txt` 였음.

**④ 지우기 전 원문**(plum.md 5장)

```text
`local.txt` 가 `/home/*/` 에 없는 것은 일반 사용자 계정이 없기 때문이다. (…노트에 남김…)

플래그를 못 찾을 때의 탐색 순서:

ls -la /home/*/ 2>/dev/null            # ① 표준 위치
ls -la /var/www/ /var/www/html/        # ② 웹 계정으로 잡았다면 여기
ls -la /tmp /opt /srv                  # ③ 흔한 대안
find / -name "local.txt" -o -name "proof.txt" 2>/dev/null   # ④ 최후

④는 느리니 ①~③을 먼저 친다. [[Squid]]에서도 플래그가 `C:\local.txt` 에 있었다 — **표준 위치 가정은 자주 깨진다**.

시험 증거 형식은 한 화면에 담아야 인정되고, 플래그가 2개면 각각 찍는다.

whoami; hostname; ip a; cat /var/www/local.txt
whoami; hostname; ip a; cat /root/proof.txt
```

---

## P13. D. 시간 배분 · 손절 기준 — **병합**

**역검색** — D 절 존재. [[plum]] 항목 없음.

**넣을 본문**

> **[[plum]](Intermediate, 총 1시간 48분)** — 전부 산출물 mtime · 스크린샷 파일명 · 메일 로그(타임존 환산)로 뒷받침됨.
>
> | 단계 | 실측 | 권장 예산 | 초과 시 판단 |
> |---|---|---|---|
> | nmap + 웹 열거 + 기본 자격증명 | 15분 (12:41:58→12:56:42) | 20분 | 진단/Information 페이지를 먼저 찾을 것 |
> | 익스플로잇 확보 → 셸 | 4분 (12:56:42→13:00:31) | 15분 | 안 통하면 브루트포스 전에 공개 익스플로잇 탐색 |
> | **권한상승 전체** | **89분** (13:00:31→14:29:47) | 30분 | ★ 여기서 샘 |
> | └ 기록 없는 구간 | 57분 (13:00:31→13:57:06) | — | ★★ 가장 큰 손실이자 **원인 미상** |
> | └ `sudo -l` ×2 → `local.txt` → SUID 열거 → `46996` 확보 | 27분 (13:57:06→14:23:56) | 10분 | `sudo -l` 은 한 번 실패하면 접을 것 |
> | └ exim 익스플로잇 확보~폐기 | 5분 (14:23:56→14:28:56) | 0분 | 버전을 먼저 봤다면 확보조차 안 했음(A-13) |
> | └ 메일함 → root | 51초 (14:28:56→14:29:47) | 5분 | 정답을 찾은 뒤에는 60초 |
>
> **시간을 잡아먹은 것은 exim 익스플로잇이 아님.** 「SUID `exim4` 를 보고 삽질하느라 오래 걸렸다」는 서사를 타임스탬프가 반증함 — `46996` 확보(14:23:56)는 root 획득(14:29:47) **6분 전**임. **실제 손실은 13:00~13:57 의 57분, 무엇을 했는지 산출물에 남지 않은 구간임.**
> → 손절 교훈이 두 겹임. ⑴ **버전 확인은 익스플로잇 확보보다 먼저**(10초짜리 `dpkg -l | grep exim` 이 5분과 오판을 없앰) ⑵ **열거는 파일로 남기면서 할 것** — 57분을 어디에 썼는지 모르면 개선할 수 없음(A-64).
> ⚠️ 하위 항목의 합(57+27+5+1)이 상위 89분과 맞는지 확인하고 적을 것 — **소계가 안 맞는 시간표는 그 자체로 서술이 틀렸다는 신호임.**

**④ 지우기 전 원문**(plum.md 6-⑥ 전문)

```text
### ⑥ 시간 배분

nmap 12:41:58 → www-data 셸 13:00:31 → local.txt 14:08:58 → root 14:29:47. 총 1시간 48분이고 그중 권한상승이 89분이다. 전부 산출물 mtime · 스크린샷 파일명 · 메일 로그(타임존 환산)로 뒷받침되는 값이다. 하위 항목의 합(57+27+5+1)이 상위 89분과 맞는지 확인하고 적었다 — 소계가 안 맞는 시간표는 그 자체로 서술이 틀렸다는 신호다.

| 단계 | 실측 | 권장 예산 | 초과 시 판단 |
|---|---|---|---|
| nmap + 웹 열거 + 기본 자격증명 | 15분 (12:41:58→12:56:42) | 20분 | Information 페이지를 먼저 찾아라 |
| 익스플로잇 확보 → 셸 | 4분 (12:56:42→13:00:31) | 15분 | 안 통하면 브루트포스 전에 공개 익스플로잇 탐색 |
| **권한상승 전체** | **89분** (13:00:31→14:29:47) | 30분 | ★ 여기서 샜다 |
| └ 기록 없는 구간 | 57분 (13:00:31→13:57:06) | — | ★★ 가장 큰 손실이자 원인 미상(④) |
| └ `sudo -l` ×2 → `local.txt` → `46996` 확보 | 27분 (13:57:06→14:23:56) | 10분 | `sudo -l` 은 한 번 실패하면 접는다 |
| └ exim 익스플로잇 확보~폐기 | 5분 (14:23:56→14:28:56) | 0분 | 버전을 먼저 봤다면 확보조차 안 했다 |
| └ 메일함 → root | 51초 (14:28:56→14:29:47) | 5분 | 정답을 찾은 뒤에는 60초 |

**시간을 잡아먹은 것은 exim 익스플로잇이 아니다.**. "SUID `exim4` 를 보고 삽질하느라 오래 걸렸다"고 서술하기 쉽지만 타임스탬프가 반증한다 — `46996` 을 손에 넣은 시각(14:23:56)은 root 획득(14:29:47) 6분 전이고, 메일함을 발견한 뒤 root까지는 51초였다. 실제 손실은 13:00~13:57의 57분, 무엇을 했는지 산출물에 남지 않은 구간이다.

그래서 손절 교훈이 두 겹이다. 버전 확인은 익스플로잇 확보보다 먼저다 — 10초짜리 확인(`dpkg -l | grep exim`)이 5분과 오판을 없앤다. 그리고 열거는 파일로 남기면서 한다 — 57분을 어디에 썼는지 모르면 개선할 수 없다(④의 `tee /tmp/enum.txt`).

그리고 익스플로잇을 돌렸으면 `id` 로 결과를 판정한다. **프롬프트가 떴다고 성공이 아니다**(②).
```

> ⚠️ **반영자 주의** — 원문의 27분 행은 「`sudo -l` ×2 → `local.txt` → `46996` 확보」였으나 그 구간에 **SUID 열거(14:21:05, 스크린샷 `142105`)가 들어감**이 새로 확정됐으므로 위 「넣을 본문」처럼 고쳐 넣을 것.

---

## P14. E. OSCP 시험 규정 — **병합**

**역검색** — E 절 존재. **신규 아님.** 아래는 「이 셋을 한 묶음으로 적는 흔한 오해」의 실물 사례.

**넣을 본문**

> **`searchsploit` · AutoRecon · 특정 CVE 겨냥 공개 PoC — 셋 다 금지도 제한도 아님.** `searchsploit` 은 검색 도구, AutoRecon 은 열거 전용(익스플로잇 단계 없음), 공개 PoC 는 스스로 취약점을 발견하지 않음. **이 셋을 sqlmap·Metasploit 과 한 묶음으로 적는 오해가 흔함.**
> **판정 예시 — [[plum]]** — `sqlmap` 불필요(애초에 DB 가 없는 XML CMS), Metasploit 미사용, `pluxml.py` 는 **HTTP 요청 3개짜리 스크립트**라 브라우저로 100% 대체 가능. **자동 익스플로잇 프레임워크와 「요청 몇 개를 순서대로 보내는 스크립트」를 같은 것으로 세지 말 것.**
> → **수동 대안을 반드시 병기할 것**(표준 원칙 5). 스크립트가 깨질 때의 생명줄이기도 함.

**④ 지우기 전 원문**(plum.md 3-3 도입 · 7-7)

```text
시험 관점에서 이 박스는 자동 도구가 전혀 필요 없다. `sqlmap`(명시적 금지)도 Metasploit(1대 한정)도 쓰지 않았다. `pluxml.py` 는 자동 익스플로잇 프레임워크가 아니라 HTTP 요청 3개를 순서대로 보내는 스크립트이고, 그 3개는 브라우저로 손수 할 수 있다.

⚠️ [[_WRITEUP-STANDARD]]가 이미 정정한 대로 **AutoRecon은 금지도 제한도 아니다**(열거 전용이라 규정에 언급이 없다). [[pyLoader]] 3-1은 이것을 올바르게 적었다.

7. ⚠️ 자동 도구 관점에서 이 박스는 완전히 안전하다. sqlmap(애초에 DB가 없다)·Metasploit 미사용이고, `pluxml.py` 는 요청 3개짜리 스크립트라 3-3의 브라우저 절차로 100% 대체 가능하다. `searchsploit` 은 검색 도구라 제한 대상이 아니고, **AutoRecon도 금지·제한 대상이 아니다**(열거 전용) — 이 셋을 한 묶음으로 적는 흔한 오해에 주의하라.
```

---

## P15. A-14. 공개 PoC는 실행 전에 소스를 읽는다 — **병합**

**역검색** — A-14 존재. **신규 아님.**

**넣을 본문**

> **⚠️ 저자의 경고가 «README 가 아니라 코드 주석»에만 있을 수 있음.** [[plum]] 의 `pluxml.py` 76행:
> ```python
>     # change reverse shell type and/or bash path as appropriate
> ```
> `README.md` 는 228바이트 4줄이고 리버스셸을 **한 번도 언급하지 않음.** 「저자가 문서에 명시했다」와 「코드를 읽어야만 보인다」는 **실전 함의가 정반대**임 — 경고가 주석에만 있으면 **스크립트를 실행만 하는 사람은 영영 못 봄.**
> **읽을 때 확인할 것 셋** — ⑴ 어디로 요청을 보내는가(엔드포인트·메서드) ⑵ **성공을 어떻게 판정하는가**(판정이 없으면 던지기만 하는 도구임) ⑶ 내 쪽 설정이 필요한가(리스너·아웃바운드·경로).
> **같은 스크립트 안에서도 줄마다 신뢰도가 다름** — `pluxml.py` 의 `[+] Successfully logged in as: admin` 은 응답 본문에서 `Incorrect login or password` 를 검사한 **실제 판정**이지만, 마지막 줄 `[+] Check your listener...` 는 **아무것도 판정하지 않음**(요청을 보냈다는 사실만). 판정 근거는 리스너 쪽임.
> **「고쳤을 것」이라고 추정하지 말고 확인할 것** — [[plum]] 은 `~/.zsh_history` 에 `vi pluxml.py` 가 있어 리버스셸 줄을 손봤을 것으로 보였으나 `git status --porcelain`·`git diff --stat` 이 **둘 다 빈 출력**이었고, `pluxml.py` mtime 은 클론 시각 그대로이며 **디렉터리 mtime 만 9초 뒤로** 갱신돼 있었음(= `vi` 스왑 파일 생성·삭제 흔적, `.gitignore` 의 `*.swp` 와 정합). **읽고 나서 「고칠 필요 없다」고 판단한 것**임.

**④ 지우기 전 원문**(plum.md 2-6 후반 · 3-1 · 3-2 후반 — 코드 블록과 `git status` 블록은 **노트에 남겨 두었음**)

```text
익스플로잇 저자도 이 취약함을 알고 경고를 달아뒀다 — *"change reverse shell type and/or bash path as appropriate"*. 그 문장은 README가 아니라 `pluxml.py` 76행의 코드 주석이다. (…노트에 남김…)

남의 익스플로잇은 실행 전에 읽는다. 최소한 어디로 요청을 보내는가(엔드포인트·메서드), 성공을 어떻게 판정하는가(판정이 없으면 그건 던지기만 하는 도구다), 내 쪽 설정이 필요한가(리스너·아웃바운드·경로) 세 가지는 확인한다. (…노트에 남김…)
```

---

## P16. B-8x. 페이로드·전송 — **병합** (`mkfifo` 원라이너 근거 보강)

**역검색** — `_PLAYBOOK:1712` 의 A-31 리버스셸 사다리에 이미 `# 2순위 — mkfifo (nc가 -e 없이 빌드됐어도 동작)` 가 있음. **신규 아님.** 빠진 것은 **왜 `/dev/tcp` 가 아닌가**의 두 근거.

**넣을 본문**

> **PHP 웹셸에서 `/dev/tcp` 를 쓰지 말 것 — 두 이유가 겹침.** ⑴ `system()` 은 `/bin/sh` 로 실행되는데 Debian 의 `/bin/sh` 는 **dash** 이고 dash 에는 `/dev/tcp` 가상 파일이 없음 ⑵ Debian 기본 `netcat-openbsd` 에는 **`-e` 가 컴파일돼 있지 않음**(백도어 방지). 그래서 `mkfifo` 형이 가장 범용적이고, bash 를 쓸 때는 **절대 경로로 명시 호출**해야 함.
> ⚠️ **`rm /tmp/f` 를 빠뜨리지 말 것** — 재시도 시 FIFO 가 이미 있으면 `mkfifo` 가 `File exists` 로 실패함.
> ⚠️ **`/usr/bin/bash` 냐 `/bin/bash` 냐** — Debian 11 은 usr-merge 라 `/bin` 이 `/usr/bin` 심볼릭 링크이므로 둘 다 있음. **[가정]** usr-merge 이전 시스템(Debian 9 이하 등)이면 `/usr/bin/bash` 가 없어 **조용히 실패**함.

**④ 지우기 전 원문**(plum.md 2-6 — 페이로드 블록과 조각 표는 **노트에 남겨 두었음**)

```text
`/dev/tcp` 대신 `mkfifo` 를 쓴 이유는 둘이다. `system()` 이 `/bin/sh` 로 실행되는데 Debian의 `/bin/sh` 는 dash이고 dash에는 `/dev/tcp` 가상 파일이 없다. 그리고 Debian 기본 `netcat-openbsd` 에는 `-e` 옵션이 컴파일되어 있지 않다(백도어 방지 목적). `mkfifo` 방식은 `-e` 없는 nc에서도 동작해서 리눅스에서 가장 범용적이고, 외워둘 값어치가 있는 원라이너다.

10. `system()` 은 `/bin/sh`(dash)로 돈다. `/dev/tcp` 가 없고 Debian `nc` 에는 `-e` 가 없으니 `mkfifo` 원라이너가 가장 범용적이다.
```

---

## 이관 계정 — 검산

| | 값 |
|---|---|
| 노트 행수 | 1266 → 878 (**−388**) |
| 노트에서 삭제된 원본 행 | **439**행 (초판 22–48 의 0장 27행 + 827–1249 의 5장 잔여·6·7·8·9장 423행 + 1255–1266 의 관련 노트 12행 중 재작성분 제외) |
| `_PLAYBOOK` 이관 제안 | **16건** — 병합 16 / 신규 0 |
| 이관 제안에 «원문 그대로» 실은 블록 | 16건 전량(각 제안의 ④) |
| 삭제했으나 이관하지 않은 것 | 없음. 6·7·8장 전량이 P1~P16 중 하나에 대응하거나, 노트의 `Vulnerability Fix:`·재현 산문으로 **본문에 남음** |

**8장(방어 관점) 전량은 `_PLAYBOOK` 이 아니라 노트의 `Vulnerability Fix:` 두 곳으로 갔음** — Initial Access(기본 자격증명·템플릿 편집기·웹루트 쓰기권한)와 Privilege Escalation(평문 비밀번호·메일함·`su`·nologin·아웃바운드·탐지).
