# PlanetExpress — 실행 기록 (2026-08-20)

타겟 `192.168.248.205` · Debian 10 `planetexpress` · Fundamental · 플래그 2/2 확보.
작업 시간 16:03~16:22 KST (약 19분). Kali 산출물 `~/PG/PlanetExpress/` (파일 60여 개).
노트: `03. PG\PlanetExpress.md` (920행).

## 경로

1. **정찰** — `-p-` 전수: 22 / 80 / 9000 만 open, 나머지 65532 filtered.
   80 = Apache 2.4.38 + Pico CMS. 9000 = `cslistener?` 미식별, raw HTTP 무응답.
2. **9000 = php-fpm 판정 (독립 근거 2개)**
   ① `/config/config.php` 의 404 본문이 `File not found.` + chunked → Apache 404(277B)가 아니라 fpm 것
   ② 자작 FastCGI 클라이언트로 실제 레코드가 오감
3. **`/config/config.yml` 이 그냥 읽힘.** picocms/pico 2.1.4, `debug: true`, 그리고 맨 아래
   주석 블록 `## Self developed plugin for PlanetExpress / #PicoTest:` → 플러그인 이름 유출.
4. **`/plugins/PicoTest.php` = `phpinfo()`** (200, 66763B). `DOCUMENT_ROOT=/var/www/html/planetexpress` 확보.
   gobuster(directory-list-2.3-medium + php,txt,md,html)는 8줄만 뱉었고 `PicoTest` 는 못 찾았다.
5. **FastCGI 직타 RCE** — `SCRIPT_FILENAME=/var/www/html/planetexpress/vendor/autoload.php`
   + `PHP_VALUE: auto_prepend_file=php://input`. `system/exec/shell_exec/pcntl_*` 는 disable 이지만
   `passthru`·`popen`·`proc_open` 생존. → `www-data`
6. **권한상승** — SUID `/usr/sbin/relayd` (4705, root, dpkg 미등록, 정적 Go).
   `nm` → `main.*` 13개 → `os/exec.Command` 호출 2곳 → Go 문자열 상수 해석 결과
   **`exec.Command("iptables","-S")`** (절대경로 아님). PATH 하이재킹.
7. **대화형 셸** — `PermitRootLogin yes`. 일회용 ed25519 키 설치 후 `ssh root@` → `su - astro`.

## 플래그 (2026-08-20 인스턴스)

| | 경로 | 값 | 획득 셸 |
|---|---|---|---|
| user | `/home/astro/local.txt` | `484f662f955b828510887c65d2565a7f` | SSH root → `su - astro` (대화형) |
| root | `/root/proof.txt` | `4dca621ae70cad152924516c7789381c` | SSH root (대화형) |

증거: `~/PG/PlanetExpress/proof_user.txt` · `proof_root.txt` · `proof_session_raw.txt`(tmux 원문).
`local.txt` 는 `-rw-r--r--` 라 www-data 도 읽을 수 있었지만 **웹 경유 획득은 OSCP 0점**이라 SSH 로 재취득했다.

## 시행착오 (6장 재료, 실패 로그 14개)

| # | 로그 | 내용 |
|---|---|---|
| 1 | `try1_fcgi_index.log` | docroot 후보 12개 브루트 전멸. `/var/www/html/planetexpress` 는 추측으로 못 맞힌다 — phpinfo 가 필요했다 |
| 2 | `try2_fcgi_realpath.log` | 대상을 `index.php` 로 잡아 페이로드 출력이 Pico HTML 5.7KB 에 파묻힘. 출력 없는 `autoload.php` 로 교체 |
| 3 | `try4_disable_functions.log` | `PHP_ADMIN_VALUE` 로 `disable_functions` 를 비워도 `system()` 은 안 살아난다(엔진 기동 시 함수 테이블에서 제거됨). `ini_get` 은 빈 값을 보고해서 헷갈린다 |
| 4 | `try7/8/9_outbound*.log` | **443 리버스셸 실패를 "아웃바운드 전면 차단" 으로 오독.** 실제 OUTPUT 체인은 dport 53/80/9000 만 ACCEPT. 80/53 의 `Connection refused` 는 **Kali 쪽에 리스너가 없어서** 난 것이고 차단(443/4444)은 타임아웃으로 나타났다. `passthru` 루프의 stdout 버퍼링 때문에 에러줄 순서가 뒤엉킨 게 오독 원인 |
| 5 | `tcpdump_connectback.log` | 첫 필터가 `tcp-syn != 0` 이라 **동시에 돌던 gobuster 에 대한 SYN-ACK** 를 연결 시도로 오인. `and tcp[tcpflags] & tcp-ack == 0` 을 붙여야 한다 |
| 6 | `try10_pathhijack.log` | **가장 값비싼 함정.** `#!/bin/sh` 페이로드가 실행되고 파일도 생겼지만 소유자가 `www-data`. dash 가 `uid != euid` 면 스스로 euid 를 버린다. `ps -o euser -p $PPID` = root vs `/proc/self/status` Uid: 33 33 33 33 로 확정 |
| 7 | `try12_python_hijack.log` | `#!/usr/bin/python3` 으로 교체 → `(uid,euid)=(33,0)`. `os.setreuid(0,0)` 후 root SUID bash 확보 |
| 8 | `enum_relayd2.log` | `-C [file]` 은 JSON 파서 에러만 뱉고 내용 미노출, `-P [file]` 은 `os.Stat` 후 로그만(디스어셈 확인). 둘 다 막다른 길 |

**Kali 로컬 재현 실측** (이 박스가 아님, 일반 지식 검증용): setuid 래퍼로 dash 스크립트/python 스크립트/`bash -c`/`bash -p -c`/`#!/bin/bash -p`/`#!/bin/sh -p` 를 각각 실행해 euid 유지 여부를 확인했다. dash·bash(무옵션)만 버린다. 검증 후 `~/dashtest`·`/tmp/dashtest` 삭제 확인.

## 스크린샷 2장

- `파일보관\PG-PlanetExpress-pico-landing.png` — 진입점(Pico "Coming Soon")
- `파일보관\PG-PlanetExpress-picotest-phpinfo.png` — 버전·DOCUMENT_ROOT 가 드러난 화면

`chromium --headless --no-sandbox --disable-gpu --hide-scrollbars --screenshot=... --window-size=1280,900` 로 촬영. 터미널 출력은 표준대로 캡처하지 않았다.

## 정리 — 전부 직접 확인

| 흔적 | 처리 | 확인 |
|---|---|---|
| `/var/www/html/planetexpress/assets/relayd.bin` | 삭제 | `ls -la assets/` → `.gitignore` 만 |
| `/tmp/.x/` (가짜 iptables, rootbash, k.pub, txt 5개) | 재귀 삭제 | `ls -la /tmp/` |
| `/tmp/.pf` FIFO | 삭제 | 동상 |
| 리버스셸 프로세스 | `pkill -f` (타겟에서만) | `ps -ef \| grep` → 0줄 |
| `/root/.ssh/` + authorized_keys (우리가 생성) | 재귀 삭제 | 재접속 → `Permission denied (publickey,password)` |
| Kali tmux 6개 · 리스너 443/80 | 세션 이름으로 종료 | `tmux ls` → `no server running`, `ss -lntp` |

원본 파일은 **하나도 수정하지 않았다**(추가만 하고 지웠다). 되돌리지 않은 것 없음.
**미확인**: 침투 전 `/tmp` 스냅샷이 없어 `systemd-private-*`·`vmware-root_*` 는 대조 불가(mtime `Aug 3 2024` 라 우리 것 아님이 거의 확실). php-fpm/Apache 액세스 로그는 의도적으로 보존.

## 태그 판정

기존 leaf 재사용: `tech/lin/suid` · `tech/lin/path-hijack` · `tech/payload/revshell` · `tech/exec/ssh-key` · `tech/enum/dirbust`.
**신규 1개: `tech/svc/php-fpm`** — 볼트 전체 grep 결과 php-fpm 계열 leaf 가 없었다. `tech/svc/redis`·`tech/svc/salt`·`tech/svc/smtp` 와 같은 서비스명 패턴을 따랐다. taxonomy 파일은 건드리지 않았다.
`manual_tags: true` · `manual_cves: true` 둘 다 설정(본문에서 CVE-2019-11043 을 **반증용**으로 언급하므로 스캔 차단 필요). `cves: []`.

## 안 한 것

- rockyou 로 root/astro sha512 크랙 미성공(john 중단). 룰·다른 사전 미시도
- relayd 의 `-a`/`-r`/`-i`/`-U` 액션 미조사
- Pico 2.1.4 자체 취약점, `PicoOutput` 플러그인, `debug: true` + Twig 1.44.6 SSTI 경로 미조사
- `_STATUS.md` 미수정(라인 관리자 단독 기록), `refresh.ps1` 미실행
