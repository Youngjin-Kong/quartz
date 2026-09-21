# PlanetExpress → _PLAYBOOK 이관 제안

작성: pg-note-forge (2026-08-26). `_PLAYBOOK.md` 는 직접 쓰지 않음 — 관리자가 이 파일을 보고 반영.
각 항목: ①어느 절 ②병합/신규 ③넣을 본문 ④지우기 전 원문 인용.

---

## 제안 1 — 신규 (A, 정찰 카테고리 · A-1x 부근)

**제목(가안):** 정찰 페이지가 방금 보낸 내 페이로드 값을 되비친다 — 순서를 지켜라

**본문:**

php-fpm·CGI·`LD_PRELOAD`·환경변수 주입처럼 런타임 설정을 바꾸는 공격을 이미 던진 상태라면, 그 뒤에 읽은 `phpinfo()`·`/server-status`·`env` 출력에는 내 값이 섞여 있을 수 있음.

[[PlanetExpress]] — FastCGI(9000)로 `PHP_VALUE`/`PHP_ADMIN_VALUE` 주입 요청을 먼저 보낸 뒤(16:04~16:05), 같은 fpm 워커에 Apache 경유로 도달한 phpinfo() 페이지(16:06~16:07)가 그 값들(`allow_url_include=On`, `open_basedir=/`, `extension_dir=/tmp`, `disable_functions=no value`)을 Local/Master 양쪽으로 그대로 보여줌. 세 값은 배포판 기본값이 아니고, `disable_functions` 는 root 로 읽은 `php.ini:310` 의 긴 블랙리스트와 정면으로 어긋남 — 판별법은 "그 값이 내가 보낸 값과 글자까지 같은가". `[가정]` 정확한 지속 조건(왜 요청 단위여야 할 값이 다음 요청까지 살아남았는가)은 **관측 없음 — 박스 정지로 재수집 불가**.

증상은 조용함 — `system()` 은 계속 막혀 있었으니 `disable_functions=no value` 만 믿었으면 "왜 막혔지"로 헤맸을 것(실제로 잠깐 그랬음). 살려준 건 phpinfo 재확인이 아니라 `function_exists` 전수조사였음.

→ 일반화: 순서를 지킬 것 — 정찰 페이지는 아무것도 주입하기 전에 먼저 저장해 두고, 이후 판본은 diff 로만 믿을 것.

**출처:** [[PlanetExpress]] (`~/PG/PlanetExpress/try1_fcgi_index.log`, `picotest_out.html`, `root_enum_fw.log` 의 `php.ini:310`)

**지우기 전 원문(노트에서 제거한 6장 (4) 전문):**

> 이건 나중에 산출물을 다시 대조하다 알아챈 함정이라 시간을 태운 건 아니지만, **다음에 반드시 걸릴** 종류다.
>
> 순서가 문제였다. `fcgi.py` 로 9000 을 두드린 게 **먼저**(`try1_fcgi_index.log`, 16:05)고, 브라우저/`curl` 로 `/plugins/PicoTest.php` 를 읽은 게 **나중**(16:06~16:07)이다. 그런데 `fcgi.py` 는 매 요청에 이걸 싣는다.
>
> ```python
> 'PHP_VALUE'      : 'allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input',
> 'PHP_ADMIN_VALUE': 'extension_dir = /tmp\ndisable_functions = ',
> ```
>
> 그리고 나중에 **Apache 를 거쳐** 읽은 phpinfo 가 `allow_url_include=On` · `open_basedir=/` · `extension_dir=/tmp` · `disable_functions=no value` 를 Local/Master 양쪽으로 보여줬다. 그 페이지의 `SERVER_SOFTWARE` 는 `Apache/2.4.38 (Debian)` 이라 내 클라이언트가 만든 응답이 아니다(`fcgi.py` 는 `php/fcgiclient` 로 보낸다).
>
> 세 값은 배포판 기본값도 아니고, `disable_functions` 는 root 로 읽은 `php.ini:310` 의 긴 블랙리스트와 정면으로 어긋난다. **내가 방금 주입한 지시자가 그 fpm 워커에 남아 다음 요청 응답까지 물들인 것**으로 본다. `[가정]` — 정확한 지속 조건은 **관측 없음 — 박스 정지로 재수집 불가**.
>
> 증상은 조용하다. `system()` 은 계속 막혀 있었으니 phpinfo 의 `disable_functions=no value` 만 믿었으면 "왜 막혔지" 로 한참 헤맸을 것이다(실제로 3장에서 잠깐 그랬다). 살려준 건 phpinfo 가 아니라 `function_exists` **전수 조사**였다.
>
> > [!danger] 익스플로잇을 먼저 쏜 뒤에 읽는 정찰 페이지는 1차 사료가 아니다
> > php-fpm·CGI·`LD_PRELOAD`·환경변수 주입처럼 **런타임 설정을 바꾸는 공격**을 이미 던져놓은 상태라면, 그 뒤에 읽은 `phpinfo()`·`/server-status`·`env` 출력에는 내 값이 섞여 있을 수 있다.
> > 순서를 지켜라 — **정찰 페이지는 아무것도 주입하기 전에 먼저 저장**해 두고, 나중 판본과 diff 한다.
> > 그게 안 됐으면 판별법은 하나다. **그 값이 내가 보낸 값과 글자까지 같은가.** 같으면 내 것이다.

---

## 제안 2 — 신규 (A, foothold 카테고리 · A-2x 부근)

**제목(가안):** php-fpm RCE 는 페이로드가 아니라 docroot 를 아는가의 문제

**본문:**

php-fpm(9000) FastCGI 직타에서 `SCRIPT_FILENAME` 이 가리키는 파일이 실제로 존재해야 요청이 처리됨 — 없으면 `Primary script unknown` 만 뱉고 `auto_prepend_file` 도 안 돎.

[[PlanetExpress]] — docroot 후보 12개를 브루트했으나 전부 실패(`try1_fcgi_index.log`, 첫 한 건만 보존되고 나머지는 tmux 스크롤백과 함께 소멸, `[가정]` 몇 개였는지는 `writeup_notes.txt` 의 "후보 12개"라는 회상만 남고 개별 출력은 없음). `/var/www/html/planetexpress` 는 추측 목록에 들어갈 이름이 아니었음 — 정보 유출(`phpinfo()` 의 `DOCUMENT_ROOT`)로 얻어야 하는 값이었음.

→ 일반화: 브루트에 시간을 쓰기 전에 경로 유출 통로(phpinfo, 스택트레이스, `debug=true`, `.git`, 백업 파일)를 먼저 뒤질 것.

**출처:** [[PlanetExpress]] (`try1_fcgi_index.log`, `writeup_notes.txt`) — 소요 약 3분(16:04~16:05→16:06 phpinfo 확보로 해소)

**지우기 전 원문(노트 6장 (1) 전문):**

> `/var/www/html/index.php` 를 시작으로 뻔한 docroot 후보들을 브루트했다. 전부 같은 응답이었다 — 남아 있는 `try1_fcgi_index.log` 는 그중 **첫 한 건만** 담고 있고(135바이트), 나머지는 tmux 스크롤백과 함께 사라졌다.
>
> ```text
> --- STDOUT ---
> Status: 404 Not Found
> Content-type: text/html; charset=UTF-8
>
> File not found.
>
> --- STDERR ---
> Primary script unknown
> ```
>
> `[가정]` `writeup_notes.txt` 는 "후보 12개" 라고만 적어놨고, **그 시도들의 출력은 어느 산출물에도 없다.** 여러 개를 던진 것은 사실이나 몇 개였는지·어떤 형식이었는지는 기록으로 남지 않았다.
>
> **브루트로는 못 맞혔다.** `/var/www/html/planetexpress` 는 추측 목록에 들어갈 이름이 아니다. 정보 유출로 얻어야 하는 값이었고, 실제로 phpinfo 가 줬다.
>
> 교훈 — **php-fpm RCE 는 "경로를 아는가" 문제로 환원된다.** 브루트에 시간을 쓰기 전에 경로 유출 통로(phpinfo, 스택트레이스, `debug=true`, `.git`, 백업 파일)를 먼저 뒤져라. 여기선 `debug: true` 도 켜져 있었으니 Twig 예외를 유도하는 길도 있었을 것이다.

---

## 제안 3 — 병합 (A-31. 리버스셸이 안 붙는다)

**본문 추가:**

**stdout/stderr 버퍼링이 진단 로그의 줄 순서를 뒤섞으면 "refused"를 "차단"으로 오독한다.**

[[PlanetExpress]] — `passthru` 로 돌린 다중 포트 아웃바운드 테스트 루프에서 stdout(블록 버퍼링)·stderr(비버퍼링)의 줄 순서가 뒤섞여 `RESULT 443 FAIL` 바로 뒤에 `Connection refused` 가 붙어 보임. 443 이 refuse 된 것으로 오독 → "80 도 refuse 되니 아웃바운드가 전부 막혔다"는 결론으로 8분 소모. 실제로는 443/4444 는 5초 타임아웃(타겟 OUTPUT `DROP`), 80/53 은 즉시 refused(타겟 OUTPUT 은 **ACCEPT** — 단지 그 시점 Kali 쪽에 리스너가 없어 RST 를 받은 것).

| 포트 | 실제로 일어난 일 | 타겟 방화벽 |
|---|---|---|
| 443 | 5초 타임아웃, 에러 메시지 없음 | OUTPUT DROP |
| 80 | 즉시 `Connection refused` | ACCEPT (Kali 쪽에 리스너 없어 RST) |
| 53 | 즉시 `Connection refused` | ACCEPT (위와 같음) |
| 4444 | 5초 타임아웃 | OUTPUT DROP |

→ **`Connection refused` 는 나쁜 소식이 아니라 좋은 소식** — 패킷이 목적지까지 갔다는 뜻이고 RST 를 보낸 건 리스너가 없는 내 Kali. 차단은 refused 가 아니라 **무응답 타임아웃**으로 나타남.

**tcpdump 필터 문법 오류로 캡처가 즉시 죽었는데 백그라운드로 띄워 그 한 줄을 놓쳤다.** `tcpdump_connectback.log` 전문이 `tcpdump: can't parse filter expression: syntax error` 한 줄 — "아무 패킷도 안 잡혔다"로 읽었으나 실제로는 tcpdump 가 뜨지도 않은 것. `[가정]` "처음 필터가 gobuster 트래픽의 SYN-ACK 를 잔뜩 잡아서 헷갈렸다"는 회상이 남아 있으나 뒷받침하는 캡처 산출물은 없음(tmux 스크롤백 소멸).

→ 일반화: **캡처 도구가 조용하면 "트래픽이 없다"가 아니라 "도구가 살아 있나"를 먼저 의심할 것.** 띄운 직후 자기 자신에게 `ping -c1` 한 방으로 캡처가 도는지 확인하는 습관.

`src host` 로 좁힐 때 SYN-ACK 를 빼는 형태(Kali 에서 파싱 확인함):
```bash
sudo tcpdump -i tun0 -n 'src host <타겟> and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```

막판에 80 리스너로 재시도해서 실측으로 닫음(`try14_revshell80.log` + `shell80.log`). **"막혔다"는 판정은 반대 실험으로 확인하기 전까지 가설.**

**출처:** [[PlanetExpress]] (`try9_outbound2.log`, `tcpdump_connectback.log`, `try14_revshell80.log`)

**지우기 전 원문(노트 6장 (2) 전문):** 원본 781~832행. 요지는 위 요약과 동일 — 원문 표·코드블록 전체는 `03. PG\_backup\PlanetExpress.md.bak` 의 781~832행 참조(축약 없이 그대로 보존됨).

---

## 제안 4 — 병합 (A-16. 워드리스트 열거가 전부 공전한다)

**본문 추가:**

[[PlanetExpress]] — `gobuster dir -w directory-list-2.3-medium.txt -x php,txt,md,html -t 40` 8줄 전량 이미 알던 경로(`/index.md`·`/index.php`·`/content`·`/themes`·`/assets`·`/plugins`·`/vendor`·`/config`). 진짜 진입점 `/plugins/PicoTest.php` 는 워드리스트에 없는 이름 — `/config/config.yml` 의 **주석 처리된 블록**(`## Self developed plugin for PlanetExpress` / `#PicoTest:` / `#  enabled: true`)에서 사람이 읽어야 나옴.

→ 스캐너가 끝났다고 열거가 끝난 게 아님. 읽히는 설정 파일은 끝까지 읽을 것.

**출처:** [[PlanetExpress]] (`~/PG/PlanetExpress/gobuster.log`, `config.yml`)

**지우기 전 원문(노트 6장 「헛다리 — gobuster」 전문):**

> ```bash
> gobuster dir -u http://192.168.248.205/ -w directory-list-2.3-medium.txt -x php,txt,md,html -t 40
> ```
>
> 결과 8줄. 전부 이미 알던 것이다.
>
> ```text
> /index.md   (Status: 200) [Size: 80]
> /index.php  (Status: 200) [Size: 5176]
> /content    (Status: 301)
> /themes     (Status: 301)
> /assets     (Status: 301)
> /plugins    (Status: 301)
> /vendor     (Status: 301)
> /config     (Status: 301)
> ```
>
> `PicoTest` 는 워드리스트에 없다. 이 박스의 진입점은 **읽히는 설정 파일을 사람이 읽어서** 나왔다. 스캐너를 돌려놓는 건 좋지만 그것이 끝났다고 열거가 끝난 게 아니다.

---

## 제안 5 — 병합 (B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash))

**본문 추가(확증 소스 + 새 진단 팁):**

[[PlanetExpress]] 도 같은 함정 — SUID Go 바이너리(`relayd`)의 PATH 하이재킹 스크립트를 `#!/bin/sh` 로 심자 스크립트는 분명히 실행되고 `chmod 4755` 도 먹었으나 `rootbash` 소유자가 www-data 라 무의미했음(`id` 에도 `euid=0` 없음). 부모(`relayd`, `ps` 의 `EUSER=root`)와 자식(`/proc/self/status` 의 `Uid: 33 33 33 33`)을 대비해 "실행은 됐는데 권한이 안 넘어옴"을 확정.

**진단 팁 — 하이재킹 페이로드에 반드시 `id` 를 심을 것.** 파일이 생겼는지가 아니라 어떤 권한으로 생겼는지를 봐야 함 — 파일 생성 자체는 성공/실패와 무관하게 일어날 수 있음.

`#!/usr/bin/python3` + `os.setreuid(0,0)` 로 교체하니 `(33, 0)`(setreuid 호출 **전** 상태를 먼저 파일에 기록하는 설계 — 실패해도 "euid 가 넘어오긴 했는가"는 남음) → `os.setreuid(0,0)` 으로 real uid 까지 0 으로 올린 뒤 `cp`/`chmod` → root 소유 SUID `rootbash` 획득 성공.

Kali 로컬 재현(이 박스가 아니라 Kali 로컬 실측)으로 dash·bash(`-p` 없음)는 euid 소실, python 은 `(1000, 0)` 유지, `bash -p`·`#!/bin/sh -p`·`#!/bin/bash -p` 는 euid 유지 — 4가지 케이스 전부 확인.

**출처:** [[PlanetExpress]] (`try10_pathhijack.log`, `try11_suid_debug.log`, `try12_python_hijack.log`)

**지우기 전 원문:** 노트 6장 (3) 「`#!/bin/sh` 하이재킹이 조용히 실패한 것」 전문 — 원본 834~849행, `03. PG\_backup\PlanetExpress.md.bak` 참조(그대로 보존됨). 핵심 인용:

> 살려준 건 스크립트에 넣어둔 `id > /tmp/.x/whoami.txt` 였다. `euid=0` 이 없어서 이상하다고 느꼈고, 다음 시도에서 `/proc/self/status` 와 `ps -o euser -p $PPID` 를 같이 찍어 **부모는 root, 자식은 33** 이라는 대비를 잡았다. 여기서 인터프리터를 의심하게 됐다.
>
> 교훈 두 개.
> - **하이재킹 페이로드에는 반드시 `id` 를 심어라.** 파일이 생겼는지가 아니라 어떤 권한으로 생겼는지를 봐야 한다.
> - **"실행됐다" 와 "권한이 넘어왔다" 는 다른 사건이다.** 셸 스크립트는 이 둘을 갈라놓는 대표적인 지점이다.

---

## 제안 6 — 신규 (B, 리눅스 권한상승 카테고리 · B-3x 부근)

**제목(가안):** Go 정적 SUID 바이너리가 외부 명령을 상대경로로 부르면 심볼로 찾는다

**본문:**

커스텀 SUID 바이너리를 만나면 `-h`/도움말을 믿지 말고 `nm`/`objdump` 로 확인할 것.

1. `nm <bin> | grep " T main\."` 로 심볼 나열 — Go 는 정적 링크라 `strings` 는 잡음이 많지만 심볼은 깨끗함. **Go 심볼은 대문자 `T`** — 소문자 `t` 로 grep 하면 빈손
2. `nm <bin> | grep -E " T os/exec\.(Command|LookPath)$"` 로 외부 명령 실행 여부 확인
3. `objdump -d --start-address=<addr> --stop-address=<addr> <bin>` 으로 호출 지점 디스어셈, 직전 `lea`/`mov` 로 인자 문자열 주소 특정. **Go 문자열은 (포인터, 길이) 쌍으로 인코딩** — 그 오프셋을 파일 오프셋으로 환산해 읽으면 실제 실행 명령이 그대로 나옴
4. 이름에 `/` 가 없으면(`exec.Command("iptables", ...)`) `LookPath` 로 `$PATH` 를 뒤짐 → PATH 하이재킹

**도움말의 옵션이 그럴듯해도 실제 동작은 디스어셈으로 확인할 것.** [[PlanetExpress]] `relayd` 의 `-C [file]`(config 읽기)·`-P [file]`(pid 파일)은 임의 파일 읽기/쓰기처럼 보였으나 둘 다 미끼 — `-C` 는 JSON 파서 실패 사유만 찍고 내용은 안 보여줌, `-P` 는 `os.Stat` 한 번 부르고 로그만 찍을 뿐 파일을 만들지 않음. `config.cpp:1539` 같은 C++ 파일:행 표기가 박혀 있지만 실제로는 Go 로 빌드됨(`/usr/lib/go-1.17/src/...` 경로가 문자열에 남음) — **가짜 로그 문구로 위장한 미끼**. `github.com/docker/docker/pkg/namesgenerator`·`github.com/google/uuid` 로 Synology DSM 흉내(`vigorous_haibt` alias, `-s` 의 serverID)를 냄.

심볼 목록 → `os/exec` 호출 지점 → 인자 문자열 순서로 15분이면 끝남.

**출처:** [[PlanetExpress]] (`relayd.bin`, `relayd.main.asm`, `enum_relayd.log`, `enum_relayd2.log`)

**지우기 전 원문:** 노트 4장 「바이너리를 Kali 로 빼기」~「헛다리 — relayd 의 `-C` 와 `-P`」 전문(원본 483~527, 873~899행). 핵심 인용 이미 위 본문에 반영. 코드블록(nm/objdump 출력) 원문은 `03. PG\_backup\PlanetExpress.md.bak` 그대로 보존.

---

## 검산

- 노트에서 제거한 6장(시행착오) 하위 절: (1) docroot 3분, (2) 아웃바운드 오독 8분, (3) `#!/bin/sh` 조용한 실패, (4) phpinfo 자기오염, 헛다리 `-C`/`-P`, 헛다리 gobuster = **6개 단위**
- 위 제안 1~6 = **6건** — 1:1 대응, 손실 없음
- 「관측 없음」 표·「안 해본 것」 목록·「남긴 흔적」은 노트 본문에 **그대로 유지**(§ 지시대로 이관 대상 아님)
- 7장(OSCP 시험 관점) 12개 항목 중 1~11번은 4항목 재현·Service Enumeration·Privilege Escalation 본문에 이미 녹아 있는 반사이므로 별도 이관 없음(내용 손실 아님, 재배치). 12번(시간 배분 반사, "20분 안에 foothold 안 보이면 재열거")은 이미 `_PLAYBOOK` D절(시간 배분·손절 기준)의 일반 원칙과 중복이라 판단해 이관 제안에서 제외 — 관리자가 필요시 D절에 [[PlanetExpress]] 확증 사례로 한 줄 추가 검토 가능
