---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---

# Pebbles — 적대적 검증 (웨이브 9)

대상: `03. PG\Pebbles.md` (개작 후 460행) · 개작 전 `03. PG\_backup\Pebbles.md.bak` (620행)
이관 제안: `03. PG\_AUDIT\Pebbles-playbook.md`
검증 시각 기준 산출물: Kali `~/PG/Pebbles/` · 볼트 `파일보관\` · `~/.zsh_history` · `03. PG\_STATUS.md`

---

## 1. 근거 출처 — 실제로 확인한 것

| 출처 | 확인 내용 |
|---|---|
| `~/PG/Pebbles/` 전량 | **파일 22개**(노트가 「23개」로 적었음 — 오류). mtime 전량 `--time-style=full-iso` 로 회수 |
| `nmap.log` 헤더 argv | `/usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Pebbles/nmap.log 192.168.248.52` — **절대경로** |
| `nmap_lowrate_allports.log` 헤더 argv | `-sS -p- -Pn --min-rate 500 --max-retries 3 -oN /home/kali/PG/Pebbles/nmap_lowrate_allports.log` — **절대경로** |
| `~/.zsh_history` | `pebbles`·`248.52` 매칭 **0건** |
| 볼트 `파일보관\` | `PG-Pebbles-*` **0장** · `Pasted image 20260820*` **0장** |
| `03. PG\_STATUS.md:64` | `\| Pebbles \| Fundamental \| 1/1 \| [[Pebbles]] \|` |
| `03. PG\Cobbles.md` (읽기만) | 1.34.23 · Filter `AutoExecuteCmd` → `zmfilter.pl` `qx()` · PHP7 느슨비교 숫자접두 우회 |
| Kali 직접 실행 — `hashlib` | MySQL `PASSWORD()` 후보 해시 재계산 |
| Kali 직접 실행 — `/usr/share/nmap/nmap-services` | `odette-ftp 3305/tcp` · `http-proxy 8080/tcp` |

---

## 2. ⓑ 코드펜스 바이트 대조 — 작성자 주장 검증

작성자 주장: 「아티팩트 유래 16블록 전부 바이트 일치」.
**표본 3건이 아니라 16블록 전부를 기계 대조함**(노트에서 펜스를 추출해 산출물 원문의 부분문자열인지 판정).

| 노트 펜스(시작행) | 산출물 | 결과 |
|---|---|---|
| 64 · 101 | `nmap.log` · `nmap_lowrate_allports.log` | 정확 일치 |
| 125 · 134 · 141 · 157 | `gob_80` · `gob_3305` · `gob_8080` · `gob_zm` | 정확 일치 |
| 236 | `blind.py` | 정확 일치(27행 전문. 25행 말미 **후행 공백 1칸**까지 보존) |
| 283 · 293 · 299 | `dbs.out` · `zmusers.out` · `mysqluser.out` | 정확 일치 |
| 321 · 330 | `dbphp.out`(탭 포함) · `proof.out` | 정확 일치 |
| 351 · 356 · 364 | `crontab.out` · `crontail.out`(탭 포함) · `tables.out` | 정확 일치 |
| 399 | `pebbles_pwn.sh` | 정확 일치(16행 전문) |

**작성자 주장은 사실임.** 한국어 주석 삽입·값 개조·행 압축 **0건**.

산출물 유래가 «아닌» 펜스 2개는 둘 다 정직하게 표시돼 있음:
- 198행 PHP 「개념도」 — 펜스 안 첫 줄이 `// 개념도 — 실제 소스는 … 원문을 확보하지 못함 [가정]`
- 221행 페이로드 템플릿 `1;SELECT IF((<조건>),SLEEP(0.6),0)#` — `blind.py` 문자열의 조각화 표기

**단 하나의 결함** — 299행 `mysqluser.out` 펜스는 파일의 **앞부분만** 싣고 마지막 `[+] RESULT:` 행을 생략했는데 생략 표시가 없었음. 같은 파일의 완주 여부를 아래 표에서 `[+] RESULT:` 유무로 판정하는 노트라 표시 부재가 자기모순을 만듦. → 캡션에 생략 명시로 정정.

---

## 3. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `**Severity:** Critical — …` (Initial Access) | 「`INTO DUMPFILE` UDF RCE **경로가 열려 있었음**」을 단정. `FILE` 권한은 `LOAD_FILE` 성공으로 확정되나 **`plugin_dir` 쓰기 가능 여부는 관측된 적이 없음** | 「확장될 여지가 있으나 `plugin_dir` 쓰기 가능 여부를 확인한 적이 없어 미검증 `[가정]`」으로 강등 |
| `— 출처: ~/PG/Pebbles/mysqluser.out (mysql.user)` | 파일 말미 `[+] RESULT:` 행을 무표시 생략. 노트가 바로 아래에서 그 마커로 완주/중단을 가르므로 내부 모순 | 캡션에 「마지막 `[+] RESULT:` 행은 생략함」 명시 |
| `crontab.out 은 4~5분을 태우고 … 문자당 약 10초` | mtime 실측과 불일치. 직전 산출물 `mysqluser.out` 10:30:34 → `crontab.out` 10:35:55 = **5분 21초**, 30바이트면 **10.7초/문자** | 「5분 21초」·「약 10.7초」로 정정, 기준점(직전 산출물)도 명시 |
| `~/PG/Pebbles/ 전량 23개 파일` (Local.txt 근거) | 실제 **22개**. `ls` 실측: blind.py·crontab.out·crontail.out·dbphp.out·dbs.out·gob_3305·gob_8080·gob_80·gob_zm·mysqlroot.hash·mysqluser.out·nmap.log·nmap_lowrate_allports.log·nmap_services.txt·pebbles_pwn.sh·peb_key·peb_key.pub·proof.out·tables.out·zmhash_only.txt·zmhash.txt·zmusers.out | 22개로 정정 |
| `산출물 ~/PG/Pebbles/ 23개 보존` (남긴 흔적) | 위와 같음 | 22개로 정정 |
| `**읽기만 수행** — INTO OUTFILE·INTO DUMPFILE·UDF·계정 생성 없음` | **내부 모순.** 같은 목록의 바로 다음 항목이 「`peb_key.pub` 를 심었는지 확인 불가 `[가정]`」인데, 심었다면 그 수단이 곧 `INTO OUTFILE`/`DUMPFILE` 임. 게다가 `blind.py` 는 argv 를 기록하지 않아 「쓰기를 안 했다」는 **부재로 증명할 수 없음** | 「산출물에 남은 페이로드는 전부 읽기 … 실행한 **기록은** 없음」으로 강등 + 「argv 미기록이라 쓰기 부재를 증명할 수 없음 `[가정]`」 추가 |
| `## 관련` | 개작에서 원 노트 `9. 참고 자료` 7행 중 **2행이 노트·제안 파일 어디에도 없이 소실**(OWASP blind SQLi · `lib_mysqludf_sys` UDF) | 두 줄 복원. UDF 쪽은 「이 박스에서는 미시도」를 붙여 실측과 구분 |
| `## 관련` | 원 노트 `관련 노트` 의 **[[Hub]] 링크 소실**. Pebbles 의 미시도 lead 인 「mysqld 구동 계정 확인」과 직결되는 링크라 색인 손실 | [[Hub]] 복원 + 연결 근거 한 줄 |

**행수: 460 → 463행** (강등·복원으로 순증 3행).

---

## 4. 삭제한 것 — 원문 인용(되살릴 수 있어야 함)

이번 감사에서 **본문 삭제는 하지 않았음.** 전부 정정 또는 강등임.

다만 **개작 단계에서 사라졌는데 `Pebbles-playbook.md` 에도 인용이 없는 원문 3건**을 여기 보존함. 셋 다 새 깊이 기준(「지우면 심사관이 재현하지 못하거나 납득하지 못하는가」)으로 판정하면 **복원 불필요**이므로 노트에는 되돌리지 않고 인용만 남김.

**① 원 노트 `4-2. 셸을 잡았다면 쳤을 명령 5개` 의 명령 블록** (백업 435–441행)

```bash
id
sudo -l
find / -perm -4000 -type f 2>/dev/null
getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*
```

판정 — 이 박스에서 **실행된 적이 없는** 일반 반사 명령이고, `CLAUDE.md` §2 의 `harvest.sh` 가 같은 목록을 이미 담당함. 심사관 재현에 불필요. 복원 안 함.

**② 원 노트 `9. 참고 자료` 중 2행** (백업 600–601행)

```text
- MySQL UDF RCE(`lib_mysqludf_sys`): sqlmap `udf/` 및 `sys_exec` 문서
- Time-based blind SQLi 개념: OWASP "Blind SQL Injection"
```

판정 — **복원함**(위 3절). 색인·참조 가치가 있고 비용이 2행임.

**③ 원 노트 `관련 노트` 중 1행** (백업 619행)

```text
- [[Hub]] — 서비스가 root로 구동되는 권한상승 패턴
```

판정 — **복원함**(위 3절).

---

## 5. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

**총 7건.** 이 중 3건은 **총괄/작성자가 준 지시 자체가 틀렸던 것**임.

### ⓒ 「`8. 방어 관점` 8행 중 두 행만 흡수, 나머지는 노트에서 빠짐」 — **틀림**

작성자가 보고에서 자백했고 `Pebbles-playbook.md` 「이관 검산」도 「미끼 8080 / 오픈 프록시 배너」·「디렉터리 리스팅 활성」·「구버전 스택」 **3행이 노트에서 빠졌음**이라고 적었음. 총괄 지시도 이를 그대로 옮겨 「빠진 행을 복원하거나 인용을 추가하라」고 했음.

**실제로는 8행 전부가 노트에 살아 있음.** 대조:

| 원 노트 `8. 방어 관점` 행 | 현 노트 위치 |
|---|---|
| `limit` SQLi → `intval()`/정수 화이트리스트 | Initial Access `Vulnerability Fix:` 1항 |
| 스택 쿼리 허용 → `mysqli_multi_query` 금지 | 같은 절 4항 |
| ZM 인증 비활성 → `ZM_OPT_USE_AUTH=1` | 같은 절 2항 |
| DB 계정 `FILE` 권한 → 회수 + `secure_file_priv` | 같은 절 3항 |
| MySQL 이 root 로 구동 → 비특권 계정 | **Privilege Escalation** `Vulnerability Fix:` |
| **디렉터리 리스팅 활성 → `Options -Indexes`** | 같은 절 5항 — 「`/zm/includes/` 디렉터리 리스팅 비활성(`Options -Indexes`)」 |
| **미끼 8080 / 오픈 프록시 배너** | 같은 절 6항 — 「불필요한 vhost(3305·8080)와 프록시 메서드도 비활성」 |
| **구버전 스택(Ubuntu 16.04, ZM 1.29.0)** | 같은 절 6항 — 「Ubuntu 16.04 와 ZoneMinder 1.29.0 둘 다 EOL」 |

이관 손실 **0건**. 작성자가 자기 산출물을 과소 보고한 것이고, 그 자백이 그대로 총괄 지시로 승격됐음. **복원 조치 불필요.**
(다만 원 노트 「강한 관리자 비밀번호(`password` 금지)」의 `password` 부분은 아래 ⓕ 반증으로 근거가 사라진 서술이라 흡수 안 된 것이 옳음.)

### ⓐ 「첫 `Initial Access` 절은 4항목만」 — 구조는 기준에 맞음

`_WRITEUP-STANDARD.md:164` — 「앞은 **4항목 요약**, 뒤는 **상세 재현**. 순서는 `요약 → Service Enumeration → 상세`」. 현 노트가 정확히 그 순서임. `_WRITEUP-STANDARD.md:166` 의 「두 제목을 다르게」도 충족(요약=긴 서술형, 상세=짧은 형). `Local.txt value:` 가 상세 절 끝에 있는 것도 `:201` 대로임. **지적 취소.**

### ⓔ Kali 프롬프트 16줄 삭제 — **삭제가 옳았음**

`nmap.log` 헤더의 실제 argv 를 직접 확인함:

```text
# Nmap 7.98 scan initiated Thu Aug 20 09:54:19 2026 as: /usr/lib/nmap/nmap -sCV -p- -Pn -A --min-rate 5000 -oN /home/kali/PG/Pebbles/nmap.log 192.168.248.52
```

원 노트는 `┌──(kali㉿kali)-[~/PG/Pebbles]` / `└─$ sudo nmap … -oN nmap.log` 로 적었음 — **`cd` 한 대화형 세션에서 상대경로로 친 것처럼** 보이나 실제 argv 는 절대경로임. `nmap_lowrate_allports.log` 도 동일. 여기에 `~/.zsh_history` 의 Pebbles 매칭 **0건**(zsh 는 대화형 세션에서만 히스토리를 씀)이 겹침.

→ **2026-08-20 에이전트가 비대화형 `ssh kali "…"` 로 푼 박스가 맞고, Kali 프롬프트는 창작이었음. 삭제 판정 유지.**
⚠️ 이 박스에는 **타겟 pty 프롬프트가 애초에 존재하지 않음**(셸 미획득). Fikklish 형 사고(타겟 프롬프트를 위반으로 오판해 제거)의 위험 자체가 없음.
삭제 원문은 `03. PG\_backup\Pebbles.md.bak` 의 50–51 · 84–85 · 102–103 · 127–128 · 152–153 · 251–252 · 258 · 347 · 365 · 372 · 390 · 473 · 475 · 483 · 500 · 514 행에 전량 보존돼 있음(백업 파일이 곧 인용임).

### ⓕ-① 「`*4ACFE…9441` 은 `password` 가 아니라 `admin`」 — **작성자가 옳음. 재계산으로 확정**

Kali 에서 직접 계산(`'*' + SHA1(SHA1_binary(pw)).hex().upper()`):

| 평문 | MySQL `PASSWORD()` |
|---|---|
| `admin` | `*4ACFE3202A5FF5CF467898FC58AAB1D615029441` ← **zmusers.out 과 일치** |
| `password` | `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19` |
| `zmpass` | `*C1D2D6FC5C596AFB19FFC4331DF6DAA287749A3E` ← **mysqluser.out `zmuser` 와 일치** |

원 노트의 「잘 알려진 `password` 의 해시」는 **반증됨**. 현 노트의 해시 표(`admin`/`zmpass`/미크랙 2건)는 전부 정확함.

### ⓕ-② 「세 웹 포트가 같은 문서 루트」 — **작성자가 옳음. 산출물이 반박함**

`gob_80.txt`(`/index.php` 1134B + `/images`·`/css`) · `gob_3305.txt`(`/index.html` **11321B**) · `gob_8080.txt`(`/index.php` **11074B** + `/hello.php`) — 세 루트가 서로 다름. 원 노트의 md5 대조 블록은 산출물에 없고, 그 결론(「나머지 두 포트 열거는 버리는 시간」)은 `/hello.php` 가 8080 열거에만 나온 것으로 직접 반박됨. 현 노트의 정정(공유되는 것은 `/zm/`·`/javascript/` 두 Alias 뿐)이 맞음.

### ⓖ-부수 「SSH 셸을 잡았을 가능성이 높다」 — **틀림. 작성자의 반증이 옳음**

- `pebbles_pwn.sh` 첫 줄: `# One-shot re-exploit for Pebbles once the box is back up.` — 작성 시점(11:09:43)에 박스가 이미 정지 상태였음
- `peb_key`(10:57:42) · `peb_key.pub`(10:57:42) 는 **Kali 생성 기록뿐**. 타겟 기입 산출물·SSH 세션 로그 없음
- `~/.zsh_history` Pebbles 매칭 0건
- 플래그 유일 출처 `proof.out`(94B)은 `blind.py` 출력 형식(`[*] len... ` + `[+] RESULT: …`)임 — 대화형 `cat` 화면이 아님

→ **셸 미획득 확정. `### Privilege Escalation – 없음 (셸 미획득)` 판정 정확. OSCP 0점 danger 콜아웃도 정확.**
노트 전수 grep 결과 「셸을 잡았다」 취지의 잔존 서술 **0건**(유일한 히트가 「셸을 잡은 적이 없으므로」 부정문). `peb_key.pub` 도 「심었다」 단정 없이 `[가정]`·확인 불가로 적혀 있음.

### 기타 — 단정형 일반 지식 3건 재확인, 전부 노트가 옳음

| 노트 서술 | 확인 방법 | 결과 |
|---|---|---|
| 저레이트 스캔의 `odette-ftp`·`http-proxy` 는 「식별 결과가 아니라 `nmap-services` 사전 항목」 | Kali `/usr/share/nmap/nmap-services` 직접 조회 | `odette-ftp 3305/tcp` · `http-proxy 8080/tcp` — **정확** |
| `OpenSSH 7.2p2` 가 CVE-2016-6210(사용자명 열거) 영향 범위 | 영향 범위 `< 7.3` | **정확**. 「배제가 아니라 미시도」 표기도 정확 |
| 난이도 `Fundamental` | `03. PG\_STATUS.md:64` | **정확**(백업의 「Intermediate」가 오류였음) |
| 스크린샷 0장 · `~/.zsh_history` 0건 | `파일보관\` 목록 · `grep -c` | **정확** |
| [[Cobbles]] 상호 링크의 버전·경로 | `03. PG\Cobbles.md` 대조 | 1.34.23 · Filter `AutoExecuteCmd` · `zmfilter.pl` `qx()` · PHP7 타입저글링 — **정확** |

---

## 6. ⓒ 160행 감소의 행별 귀속

백업 620행 → 개작 460행. 원 노트의 장 단위로 전량 귀속됨:

| 원 노트 장(백업 행) | 행수 | 어디로 |
|---|---|---|
| `0. 배우는 것` (30–43) | 14 | playbook §6 — 원문 인용 있음 |
| 1장 Kali 프롬프트 펜스 4개 | ~20 | **삭제**(ⓔ 창작 판정). 서술은 노트에 산문으로 남고 `[가정]` 부착 |
| 2장 배경·표 (139–238) | ~60 | 노트 `Initial Access` 상세로 압축 + playbook §6·§8 |
| 3-1 탐지 curl 펜스 (247–264) | 18 | **삭제**(프롬프트 창작). 측정값은 노트에 `[가정]` 부착 산문으로 보존 |
| 3-5 요청 수 표 (318–339) | 22 | 노트 1행 + playbook §6 |
| 3-7 sqlmap 사다리 표 (400–412) | 13 | playbook §6 표 |
| `4-2` 반사 명령 5개 (433–443) | 11 | **어디에도 없음** → 위 4절 ①에 원문 인용(복원 불필요 판정) |
| `5. 플래그` 표 (447–454) | 8 | `Local.txt value:` · `Proof.txt value:` · danger 콜아웃 |
| `6. 막혔던 지점` 6-1~6-7 (458–559) | 102 | playbook §1·§2·§3·§4·§5·§6·§10 — **7항목 전부 원문 인용 있음** |
| `7. OSCP 시험 관점` (563–577) | 15 | playbook §6·§8·§9·§10 |
| `8. 방어 관점` (581–592) | 12 | **8행 전부** 두 finding 의 `Vulnerability Fix:` 로 흡수(위 5절 ⓒ 반증) |
| `9. 참고 자료` (596–602) | 7 | 5행 → `## 관련`, **2행 소실** → 복원함 |
| `남긴 흔적`·`관련 노트` (604–620) | 17 | 확장 이관, **[[Hub]] 1행 소실** → 복원함 |

**귀속 불가 = 실질 손실: 3행**(참고자료 2 + [[Hub]] 1) — **전부 복원함.**
**판정 유보 후 복원 안 함: 11행**(4-2 반사 명령 블록) — 원문을 위 4절에 인용해 되살릴 수 있게 함.
인과(「~해서」)·소요 시간(2분 33초 · 5분 28초 · 5분 21초)·`[가정]`·「관측 없음」·출처 경로는 이관본·노트 양쪽에 보존돼 있음을 확인함.

---

## 7. ⓐ~ⓖ 통과 여부

| | 항목 | 판정 |
|---|---|---|
| ⓐ | 4항목 × 2 finding · 두 `Initial Access` 제목 상이 · 순서 | **통과** |
| ⓑ | 코드펜스 바이트 일치 | **통과**(16/16). 단 `mysqluser.out` 생략 무표시 1건 → 정정 |
| ⓒ | 이관 손실 0 | **통과**(실질 손실 3행, 전부 복원). 지시받은 「8. 방어 관점 손실」은 반증 |
| ⓓ | nmap raw 보존 · 헤딩 · [[Cobbles]] 상호링크 | **통과**(`PORT_RE` 매칭 라인 10개 생존) |
| ⓔ | Kali 프롬프트 삭제 판정 | **삭제가 옳았음**(argv 절대경로 + zsh 0건) |
| ⓕ | 자기 산출물 반박 | **통과**. 두 반증 모두 재확인됨. 추가 상속 오류 발견 없음 |
| ⓖ | 플래그 경로 0점 판정 · 잔존 셸 서술 | **통과**. 잔존 0건. SSH 셸 반증도 확인됨 |

## 8. 총괄 판단이 필요한 것

- **색인 갱신 필요.** 프론트매터가 `cves: [CVE-2016-6210]` → `cves: []` + `manual_cves: true` 로 바뀌었음. `refresh.ps1` 은 이 감사에서 돌리지 않았음(공유 인프라).
- **문체는 이 감사의 관할이 아님.** 이관 대상 없음 — 개작본이 이미 명사 종결형 개조식임. `pg-doc-reviewer` 로 넘길 건 0건.
- `03. PG\_STATUS.md:64` 는 현 상태(`Fundamental` · `1/1`)가 정확해 **변경 불필요**.
