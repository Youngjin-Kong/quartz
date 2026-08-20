---
tags:
  - type/audit
  - platform/pg
---
# PlanetExpress — 적대적 검증 + 정정 기록

**대상** `03. PG/PlanetExpress.md` (초고 919행 → 정정본 1016행)
**검증일** 2026-08-20
**박스 상태** 정지·반납됨. 재접속 검증 불가. 모든 판정은 Kali 산출물 대조 / 1차 사료 / Kali 재실행으로만.

---

## 0. 근거 출처

| 종류 | 실제로 본 것 |
|---|---|
| **git 원본** | 없음. `git status` = `?? "03. PG/PlanetExpress.md"` — **신규 생성 노트라 baseline 이 존재하지 않는다.** 개작 전후 diff 검증은 불가능했고, 대신 Kali 산출물 전량 대조로 대체했다 |
| **Kali 산출물** | `~/PG/PlanetExpress/` 62개 전부 열람. 특히 `writeup_notes.txt`(시간순 1차 사료), `try1`~`try14`, `enum_*.log`, `root_enum_fw.log`, `cleanup_target.log`, `proof_*.txt`, `picotest_out.html`, `config.yml`, `installed.json`, `payload_*.php`, `fcgi.py`, `relayd.bin`/`relayd.main.asm`/`relayd.strings.txt` |
| **Kali 직접 실행** | ① setuid 래퍼 dash/bash/python/`-p` 재현 실험 전량 ② `tcpdump -d` 로 노트의 필터 파싱 검증 ③ `nm relayd.bin` 심볼·정규식 검증 ④ `readelf -lW` + 파이썬으로 relayd 문자열 상수 vaddr→오프셋 환산 ⑤ `installed.json` 파싱 |
| **스크린샷** | 볼트 `파일보관\PG-PlanetExpress-pico-landing.png`(54335B) · `-picotest-phpinfo.png`(188647B) **둘 다 직접 열어봄.** 본문 서술과 일치 |
| **`~/.zsh_history`** | 훑음(2552행). `tcpdump`·`dashtest` 흔적 없음 — 단 이 작업은 전부 tmux/리버스셸 안이라 히스토리에 안 남는다. **부재를 근거로 쓰지 않았다** |
| **볼트 색인** | `tech/*` leaf 6개 실재 확인, `extract.py`의 `declared_cves()` 동작 확인(읽기만) |

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| 1장 `phpinfo 에서 뽑은 것` | **최대 결함.** phpinfo 의 `disable_functions=no value`·`allow_url_include=On`·`open_basedir=/` 를 **박스 설정으로 읽었다.** 실제로는 `fcgi.py` 가 주입한 값이 되비친 것 | 오염 사실을 명시, 신뢰 가능한 줄만 남김, 6장 (4) 신설 | `picotest_out.html` + `fcgi.py:83-84` + `root_enum_fw.log` |
| 1장 `disable_functions ... 6장에 적는다` | **6장에 그 설명이 없었다** (댕글링 참조) | 6장 (4) 를 실제로 신설하고 링크 | 본문 대조 |
| 1장 `Not shown: 65532 filtered` | "리버스셸이 안 붙을 것을 예고" — inbound filtered 는 **INPUT 체인** 정보다. OUTPUT 을 추론할 근거가 아니다 | 휴리스틱으로 강등, 실제 확인은 root 의 `iptables -S` 였음을 명시 | `root_enum_fw.log` |
| 1장 `9000 이 php-fpm 이라는 첫 번째 독립 근거` | Apache 404 본문은 "PHP=fpm" 까지만 증명한다. **"그 fpm 이 9000"은 아니다**(유닉스 소켓일 수도) | 2단계 논증으로 분리 | 논리 |
| 1장 `2.1.4 는 최신에 가깝고` | 2026 기준 currency 단정, 미검증 | 삭제하고 "버전보다 그 파일이 뭘 흘리는지" 로 대체 | — |
| 2장 `기본값은 listen = /run/php/php7.3-fpm.sock` | 배포판 스코프 없이 "기본값" 단정. PHP 업스트림 `www.conf.default` 는 다르다 | "Debian 의 php7.3-fpm 패키지는 …로 출하한다" 로 한정. `listen.group` 줄도 복원 | `root_enum_fw.log` |
| 2장 `그 요청에만 적용되는 php.ini 지시자` | 이 박스에서 **다음 요청까지 남았다** | 한정 + 6장 (4) 링크 | `picotest_out.html` |
| 2장 `phpinfo 가 이미 …보여줬으니 두 개는 보험이다` | 오염된 값을 근거로 삼은 문장 | 정정 — 원 설정을 모를 때는 셋 다 얹는 게 맞다 | 위와 동일 |
| 2장 `PHP_VALUE 구분자 … 조용히 무시된다` | 미검증 단정(Kali 에 php-fpm 없음) | `[가정]` 강등 + "분리 실험 안 했다" 명시 | — |
| 3장 `60줄이면 된다` / 7장 `60줄 파이썬` | 실제 `fcgi.py` 는 **87줄** | 87줄 / "100줄 안쪽" 으로 정정 | `wc -l fcgi.py` |
| 3장 try5 블록 | 로그의 **한 줄**을 두 줄로 쪼개고 `Content-type:` 헤더를 뺐다 | 로그 원문 그대로 복원 + `payload_funcs.php` 원문 추가 | `try5_funcs.log` |
| 3장 try6 블록 | `passwd` 출력에서 `sync:` 줄이 **표시 없이 삭제**됨, 명령도 `ls -la /home ...` 로 축약 | 명령 원문 복원, `sync:` 복원, 생략은 `[… 생략 …]` 로 표시 | `try6_enum.log`, `payload_enum.php` |
| 3장 `php.ini 가 이유를 설명한다` | 실제 php.ini 줄을 인용하지 않았다 | `root_enum_fw.log` 의 `php.ini:310` 원문 인용 추가 | 위 |
| 3장 `리버스셸 — 포트를 바꿔야 붙는다` | **교란변수.** 443→80 과 동시에 `proc_open` 핸들(`pipe`→`/dev/null` 파일)과 서브셸 괄호도 바꿨다. "포트 때문"이라고 단정 | 제목을 "443 으로는 못 나간다" 로 바꾸고 세 변수 명시, SIGPIPE 설명은 `[가정]` 강등 | `payload_rev.php` vs `payload_rev80.php` |
| 4장 `셸을 잡자마자 치는 다섯 개` + `capabilities 도 없었다` | **`getcap` 은 한 번도 실행되지 않았다.** 산출물 전체 grep 에 `getcap`/`cap_` 0건 | "넷을 돌렸다" 로 정정, 다섯 번째를 건너뛴 것을 경고로 남김 | `grep -rn getcap ~/PG/PlanetExpress` → 0 |
| 4장 `nm relayd.bin \| grep " t main\."` | **소문자 `t` 로는 한 줄도 안 나온다.** 실제 심볼은 `T`. 목록에서 `main.parseOptions.func1` 누락, "함수 13개" 도 오류(14) | 명령·목록·개수 전부 정정 | `nm relayd.bin` 재실행 |
| 4장 `grep -E "os/exec\.[A-Za-z]+$"` | 그 정규식은 **9줄**을 뱉는다(`dedupEnvCase`·`ErrNotFound`·`findExecutable`·`init`·`interfaceEqual`·`skipStdinCopyError`·`type..eq.os/exec.Error` 포함). 노트는 2줄만 실었다 | 출력과 일치하는 `grep -E " T os/exec\.(Command\|LookPath)$"` 로 정정 | `nm` 재실행 |
| 4장 디스어셈 블록 | 레지스터 단위 `lea`/`mov` 나열 = 소스 고고학 과잉 | 산문 1문단 + 문자열 3줄로 압축. `runMain` 인자가 `-L` 인 것도 명시(실측) | 표준 원칙 1 / `readelf`+오프셋 환산 |
| 4장 `PATH=/tmp/.x:$PATH /usr/sbin/relayd -b up` | `timeout 30 … 2>&1 \| head -20` 이 잘렸다 | 원문 복원 | `payload_pathhijack.php` |
| 4장 python 페이로드 | `try/except` 래퍼가 통째로 삭제됨(로그는 그 형태로 출력함) | 복원 + `st2.txt` 를 setreuid 앞에 쓴 설계 의도 설명 | `payload_py.php`, `try12_python_hijack.log` |
| 4장 dash 실험 블록 | (오류 아님) | **Kali 에서 전량 재현**하고 그 사실 + `/tmp` nosuid 함정을 추가 | 아래 §3 참조 |
| 4장 `/tmp/.x/rootbash -p -c "id"` | 실제 호출은 `payload_root1.php` 의 긴 `-c` 였다 | 실제 형태로 정정 | `payload_root1.php` |
| 4장 SSH 블록 | `ssh` 후 출력이 `uid…` → `root` 순으로 **재배열**됨(실측은 `whoami; id; …` 순) | 중복 블록 제거하고 5장 원문으로 넘김. `try13` 근거 추가 | `proof_root.txt`, `proof_session_raw.txt` |
| 6장 (1) `try1_fcgi_index.log 에서 … 12개 경로` | **날조된 형식의 블록.** `-> unknown=1` 형태 출력은 **어느 산출물에도 없다**(전체 grep 0건). `try1_fcgi_index.log` 는 135바이트, 단일 응답만 담고 있다 | 로그 원문으로 교체, 12개라는 숫자는 `writeup_notes.txt` 회상임을 `[가정]` 으로 명시 (삭제 원문은 아래 §2) | `grep -rl 'unknown=1' .` → 0건 |
| 6장 (2) tcpdump 서사 | "필터를 고쳐 다시 잡으니 한 패킷도 안 잡혔다" — 유일한 tcpdump 산출물은 **파싱 에러 한 줄**이다 | 실측대로 정정. 결론은 맞았으나 근거는 `iptables -S` + 80 재시도였음을 명시. "gobuster SYN-ACK" 부분은 `[가정]` | `tcpdump_connectback.log` (53바이트) |
| 6장 `-C /etc/shadow` 출력 | 앞의 `config.cpp:1539`·`config.cpp:1213` 두 줄과 `rc=0` 이 표시 없이 잘림 | 복원 + 실제 명령 형태(`timeout 10 … \| head -20`) | `enum_relayd2.log`, `payload_relayd2.php` |
| 6장 `-P` 디스어셈 | 주소 3줄 나열 = 과잉 | 산문 1문단으로 압축(문자열 내용은 `readelf` 오프셋 환산으로 검증 완료) | 0x563a2b 실측 |
| 7장 6·7·9·10·11·12 | 항목 6 "13개", 항목 7 `grep main.`, 항목 10 "정찰 3분째" | 14개 / `" T main\."` / "정찰 시작 2분 만에" 로 정정. **9(자기 오염)·10(캡처 도구) 두 항목 신설** | 위 |
| 8장 `security.limit_extensions …` | `PHP_ADMIN_VALUE` 로 덮이는 여지 운운 — 이 박스 관측과 어긋난다(엔진 기동 시 제거라 안 덮였다) | 관측된 사실로 다시 씀 | `try3`·`try4`·`try5` |
| 남긴 흔적 표 | "디버그 txt 5개" — 실제로는 txt 4개(`st`·`st2`·`st3`·`whoami`) + `t.sh` | 파일명 전부 명시 | `cleanup_target.log` |
| 3장 `which` 해설(신규) | — | `ncat`·`socat`·`curl` 부재를 정보로 추가 | `try6_enum.log` |

---

## 2. 삭제한 것 — 원문 전문

되살릴 수 있도록 삭제된 블록을 그대로 남긴다.

### (a) 6장 (1) 의 `-> unknown=1` 블록 — **유일한 전면 삭제**

````
`try1_fcgi_index.log` 에서 `/var/www/html/index.php` 를 시작으로 12개 경로를 브루트했다. 전부 `Primary script unknown`.

```
/var/www/html/index.php -> unknown=1
/var/www/index.php -> unknown=1
/var/www/html/pico/index.php -> unknown=1
/var/www/pico/index.php -> unknown=1
...
/var/www/html/vendor/autoload.php -> unknown=1
```
````

**삭제 근거** — `grep -rl 'unknown=1' ~/PG/PlanetExpress` 가 **0건**. `try1_fcgi_index.log` 는 135바이트이고 내용은 단일 FastCGI 응답(`Status: 404` + `Primary script unknown`)뿐이다. 즉 이 형식의 출력은 존재한 적이 없다.
**주의** — "브루트를 시도했다"는 사실 자체는 `writeup_notes.txt` 의 "docroot 후보 12개를 브루트했지만 전부 실패(try1 로그)" 로 뒷받침된다. 그래서 **행위는 남기고 형식만 지웠다.** 등급: 형식은 `날조`, 시도 사실은 `사실`.

### (b) 4장 디스어셈 register 나열 (분량 과잉으로 압축)

```
5180fd:  lea    0x402d7(%rip),%rcx   # 5583db     ← 인자 슬라이스 원소
518112:  lea    0x4145f(%rip),%rax   # 559578     ← 실행 파일 이름
518119:  mov    $0x8,%ebx                         ← 이름 길이 8
51812b:  call   4d4180 <os/exec.Command>
```

**근거** — 이 네 줄은 전부 정확하다(`relayd.main.asm` 557·561·562·566행과 일치). 지운 이유는 오류가 아니라 표준의 "소스 고고학은 과잉" 조항이다. 결론(`exec.Command("iptables","-S")` 가 상대경로)과 문자열 3줄은 남겼다.

### (c) 4장 `-P` 디스어셈 3줄 (분량 과잉으로 압축)

```
517fb5:  call   4a6500 <os.Stat>
517fbd:  je     517fd2
517fbf:  lea    0x4ba65(%rip),%rax   # → "relayd.cpp:1601 [UpnpUpdate] Open file [/var/run/relayd_upnp_update.pid] failed."
```

**근거** — 정확하다. `0x563a2b` 를 파일 오프셋으로 환산해 읽으면 `relayd.cpp:1601 [UpnpUpdate] Open file [/var/run/relayd_upnp_update.pid] failed.` 가 나온다(직접 확인). 압축만 했다.

### (d) 4장 SSH 세션 블록 (중복 + 순서 재배열)

```
ssh -i pe_key root@192.168.248.205
uid=0(root) gid=0(root) groups=0(root)
root
planetexpress
```

**근거** — 실측(`proof_root.txt`)의 순서는 `root` → `uid=…` → `planetexpress` 다(`whoami; id; hostname` 순). 노트가 뒤바꿔 실었고, 같은 내용이 5장에 원문으로 있다. 5장으로 일원화.

---

## 3. 반증한 것 — 지적으로 올렸다가 확인 결과 노트가 옳았던 것

**검증 절차 자체의 정확도를 판단할 수 있게 전부 적는다.**

1. **`php.ini` 원문을 회수 못 했을 것이다 (총괄 지시 ③(b))** → **반증됨.** 총괄은 "러너가 재진입 못 해 `php.ini` 원문을 회수하지 못했을 가능성이 높다, 없으면 `[가정]` 강등 대상" 이라고 지시했다. 실제로는 `root_enum_fw.log` 의 `---PHPFPM---` 절에 있다:
   `/etc/php/7.3/fpm/php.ini:310:disable_functions = system,exec,shell_exec,pcntl_alarm,…,pcntl_async_signals,`
   → 노트의 "실제 php.ini 에는 목록이 있다" 는 **정확했다.** 강등하지 않고 오히려 원문을 인용해 강화했다.

2. **"동시에 돌던 gobuster" 는 시간상 불가능하다** → **자기 반증.** 처음에 `gobuster.log` mtime 16:06:32 < tcpdump 16:10:46 을 보고 "겹치지 않는다"고 판정하려 했다. 그런데 mtime 은 **마지막 히트 시각**이지 종료 시각이 아니고, `directory-list-2.3-medium` × 5확장 = 100만 요청 규모라 26초에 끝날 수 없다. `writeup_notes.txt` 도 "16:06 gobuster 시작 … 결과는 끝까지 8줄" 이라 16:10 에도 돌고 있었을 가능성이 높다. → 이 근거로는 반증 못 한다고 판단해 `[가정]` 강등에서 멈췄다(전면 삭제하지 않음).

3. **노트의 tcpdump 필터가 파싱 에러의 원인이다** → **반증됨.** `sudo tcpdump -d 'src host … and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'` 를 Kali 에서 돌려보니 **정상 파싱된다**(BPF 출력 확인). 따라서 `tcpdump_connectback.log` 의 에러는 **다른** 필터에서 났다. 노트에 실린 필터 자체는 옳으므로 그대로 두고, "파싱 확인함" 을 덧붙였다.

4. **dash/bash/python setuid 실험 전체** → **반증 실패(노트가 옳음).** `~/dashtest` 가 이미 삭제돼 있어 "부재"였지만, 규율대로 부재를 근거로 삼지 않고 **Kali 에서 처음부터 재현**했다. 결과가 노트와 전부 일치 — dash script/`bash -c id` = euid 없음, python = `1000 0`, `bash -p -c id` = `euid=0(root)`. 노트가 "둘 다 확인" 이라고만 적었던 `#!/bin/sh -p`·`#!/bin/bash -p` 도 실제로 euid 를 유지한다. `dash 0.5.12-12`, `/bin/sh → /usr/bin/dash`.
   부수 발견: 처음 `/tmp` 에서 래퍼를 만들었더니 **python 까지 `1000 1000`** 이 나왔다. Kali `/tmp` 가 `tmpfs … nosuid` 이기 때문이다. 하마터면 "python 도 euid 를 못 받는다"는 오판을 노트에 실을 뻔했다 — 이 함정을 노트에 추가했다.

5. **relayd 문자열 상수 `0x559578`/`0x5583db`/`0x5583d9`** → **노트가 옳음.** `readelf -lW` 로 LOAD 세그먼트를 얻어 vaddr→파일 오프셋 환산 후 읽으니 각각 `b'iptables'`(8) · `b'-S'`(2) · `b'-L'`(2). 노트가 적은 그대로다. `relayd.main.asm` 의 행번호(557·561·562·566·1023)도 실제 파일과 일치.

6. **`installed.json` 컴포넌트 9줄** → **노트가 옳음.** JSON 파싱 결과와 순서·버전 전부 일치.

7. **플래그·`proof_*` 블록** → **노트가 옳음.** `proof_user.txt`·`proof_root.txt`·`proof_session_raw.txt` 3파일과 노트 5장이 **줄바꿈 위치(`/root/proof.t`↵`xt`)까지** 일치. 손댄 흔적 없음.

8. **`config.yml` 인용** → **노트가 옳음.** 실제 파일과 일치.

9. **스크린샷 2장** → **노트가 옳음.** 직접 열어봤다. 랜딩은 "We Are Coming Very Soon!" + 이메일 폼, phpinfo 는 `PHP Version 7.3.31-1~deb10u1` / `Linux planetexpress 4.19.0-18-amd64` / `FPM/FastCGI` / `Loaded Configuration File /etc/php/7.3/fpm/php.ini` — 본문 서술과 일치.

10. **정리(`남긴 흔적`) 표 전 항목** → **노트가 옳음.** `cleanup_target.log` 가 `/tmp/.x`·`/tmp/.pf` 삭제, `assets/` 에 `.gitignore` 만 남음, `---PS---`/`---NONE---`, `/root/.ssh` 부재, 재접속 `Permission denied (publickey,password)` 를 전부 담고 있다. `~/dashtest`·`/tmp/dashtest` 부재도 확인.

11. **1장 수동 디렉터리 훑기 블록(`403 280 …`)** → **날조로 올렸다가 철회.** 이 형식의 출력은 산출물에 없다(grep 0건). 그러나 같은 블록의 크기 값이 **디스크의 실제 파일 크기와 정확히 일치**한다 — `installed.json` 23215B, `config.yml` 812B, `PicoTest.php` 66763B(= `picotest_out.html` 크기), `index.php` 5176B(= gobuster 보고값), `/config/config.php` 404 본문 16B(= `File not found.\n`). 우연으로 맞출 수 없는 값들이라 **실제로 돌린 루프의 출력**으로 판단, 그대로 두었다. (부재 증거 상한 = `근거부족`)

12. **`disable_functions` 는 엔진 기동 시 함수 테이블에서 제거된다** → **노트가 옳음.** `try3`(system 막힘) + `try4`(`ini_get` 은 빈 값) + `try5`(`function_exists` = N) 세 관측이 서로를 뒷받침한다. 별도 반증 불필요.

13. **`_STATUS.md`** → 지시대로 **건드리지 않았다.**

---

## 4. 「관측 없음 — 박스 정지로 재수집 불가」로 표시한 것

노트 6장 끝에 전용 표를 신설해 넣었다. 「안 해본 것」(선택)과 「관측 없음」(불가)을 **분리**한 것이 요점이다.

1. `/plugins/PicoTest.php` **원본 소스** — 회수 못 함. 렌더된 HTML 만 있음. "phpinfo() 였다" 는 출력으로부터의 추론
2. **phpinfo 값 오염의 지속 메커니즘** — 요청 단위여야 할 `PHP_ADMIN_VALUE` 가 왜 다음 요청까지 살아남았는지 미검증
3. **relayd 의 `/proc/<pid>/stat` 조상 체인** — 안 봄. `ps -o …euser -p $PPID` + `/proc/self/status` Uid 4쌍으로만 확인. 결론에는 영향 없음
4. **침투 전 `/tmp` 스냅샷** — 못 찍음 (기존 신고 항목, 유지)
5. **리버스셸 `proc_open` 핸들·서브셸의 개별 기여** — 분리 실험 안 함

추가로 「남긴 흔적 > 미확인」 맨 위에 **"이 박스는 정지·반납됐다. 재접속으로 확인할 수 없다"** 를 명시했다.
**재접속을 전제한 서술은 없었다** — 유일하게 "재접속 시도 → `Permission denied`" 가 있으나 이는 정리 검증의 과거형 기록이라 그대로 뒀다.

---

## 5. 프론트매터 판정

| 항목 | 판정 |
|---|---|
| `tech/svc/php-fpm` | 유지 (신규 leaf, 총괄 승인). 볼트 내 실재 확인 |
| **`tech/enum/dirbust`** | **유지.** 근거: gobuster 는 기여 못 했지만 **손으로 돌린 디렉터리 열거가 결정적이었다** — `/config/config.yml`(200, 진입점 유출)과 `/config/config.php`(404 본문 16B, php-fpm 식별)이 그 sweep 에서 나왔다. 두 개 다 경로상 필수다. "안 통한 기법" 이 아니라 "**도구는 실패하고 수동은 성공한** 기법" 이므로 색인 오염이 아니다. 다만 노트가 gobuster 실패를 6장에 명시하고 있어 검색해 들어온 사람이 오해할 여지는 없다 |
| `tech/lin/suid` · `tech/lin/path-hijack` · `tech/payload/revshell` · `tech/exec/ssh-key` | 유지. 4개 다 실제 사용 + 볼트 내 실재 leaf 확인 |
| `manual_tags: true` / `manual_cves: true` | **뒤에 주석 없음 확인.** 정상 |
| `cves:` 키 부재 | **정상.** `extract.py:declared_cves()` 는 `manual_cves: true` + `cves:` 줄 없음 = "이 노트에 CVE 없음" 으로 처리한다(소스 확인). 본문의 CVE-2019-11043 반증 서술은 색인되지 않는다 |
| `tech_count: 6` | tech 태그 6개와 일치 |
| `ports: [22, 80, 9000]` | `nmap.log` 와 일치 |
| `Nmap scan report for 192.168.248.205` | 본문 2곳(quick/full)에 존재 — 총괄 확인 완료분 |

**`refresh.ps1` 은 돌리지 않았다**(지시).

---

## 6. 수치

| | |
|---|---|
| 행수 | 919 → 1016 (+97) |
| 정정 | 30개소 |
| `[가정]` 강등 | 5건 (PHP_VALUE 구분자 / 리버스셸 SIGPIPE / try1 브루트 개수 / gobuster SYN-ACK 회상 / phpinfo 오염 메커니즘) |
| 전면 삭제 | 1건 (§2(a)) — 원문 보존됨 |
| 분량 압축 | 3건 (§2(b)(c)(d)) — 원문 보존됨 |
| 원문 복원 | 6건 (try5 · try6 · try10 명령 · try12 try/except · `-C` 출력 · php.ini:310) |
| 신설 | 6장 (4) 절 · 6장 「관측 없음」 표 · 7장 항목 2개 · 상단 정정 이력 콜아웃 |
| 반증(노트가 옳았음) | 13건 |
| 플래그 | 재검증 불필요 처리(총괄 확인분). 노트 5장이 `proof_*.txt` 와 바이트 일치함만 확인 |

---

## 7. 총괄 판단이 필요한 것

**없음.** 공유 인프라·다른 노트·`_STATUS.md`·`refresh.ps1`·포털 전부 손대지 않았다.

참고로 **Kali 의 죽은 NFS 마운트 징후는 없었다** — 모든 명령이 즉시 반환됐다.
