---
tags:
  - type/audit
  - platform/pg
---
# PwnLab — 적대적 검증 + 정정 (2026-08-20)

감사 범위: `03. PG\PwnLab.md` (761행 → 896행).
증거원: Kali `~/PG/PwnLab/` 32개 파일 · 볼트 `파일보관\PG-PwnLab-*.png` 3장 · `~/.zsh_history` · Kali 재실행 3건.
**git baseline 없음** — 이 노트는 신규 생성이라 개작 전 커밋이 존재하지 않는다(`git log -- "03. PG/PwnLab.md"` 빈손). 대조는 전량 Kali 산출물로 했다.

## 총평

**값은 전부 정확했다.** 플래그 2개, 비밀번호 3개, base64 원문, md5 업로드 경로, sh.gif 52바이트, PHPSESSID, nmap 전문, SUID 목록 2종, exim4 버전 — 산출물과 **한 바이트도 다르지 않았다.**

틀린 것은 전부 한 종류다 — **어떤 명령이 어느 프롬프트에서 실행됐는가.** 초고는 pty 캡처를 읽기 좋게 정리하면서 명령을 자르고, 붙이고, 프롬프트를 다시 그렸다. 그 과정에서 한 곳은 노트 자신의 주장과 모순됐고(4-3), 한 곳은 진단 단서를 통째로 지웠다(6장 (4)).

---

## 1. 고친 것

| 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| 3장 리버스셸 블록 | `$ python -c "import pty;pty.spawn(...)"` 가 캡처에 찍힌 것처럼 적힘 | 캡처 원문(`$ www-data@pwnlab:/var/www/html$ cd /tmp && wget ...` + harvest 실행 결과)으로 복원. pty 명령은 코드펜스 밖 산문으로 | `shell_www-data.log:1-9` |
| 3장 `curl -F` 검증 블록 | 필터링된 2줄을 원문처럼 제시 | "nc 가 받은 요청에서 Content-Type 두 줄만 뽑은 것"이라고 명시 | 감사자 재실행(아래 4절) |
| 4-2 su kent | `Password: (JWzXuBJJNy)` — 캡처에 없는 값을 출력 줄에 삽입 | `Password: ` (원문 그대로)로 복원, 비번은 산문으로 | `shell_www-data.log:37-38` |
| 4-2 su kent | `kent@pwnlab:/tmp$ id` — 실제는 `id; ls -la ~` | 명령·출력 전문 복원(kent 홈 dotfile 4개). "홈이 비었다"의 근거가 이 목록이다 | 동 `:39-46` |
| 4-2 su kane | `... /home/john` — `2>&1` 이 잘림 | `2>&1` 복원 + 플래그 해설 추가(빠지면 `Permission denied` 가 사라져 "mike 홈이 비었다"로 오독) | 동 `:49` / `proof_user.txt` |
| 4-3 msgmike | `kane@pwnlab:/tmp$ /home/kane/msgmike` — 그런 단독 실행은 없음. 두 실행의 출력을 역순으로 접합 | 원문 명령 `strings ...; echo ===; ./ /home/kane/msgmike 2>/dev/null; /home/kane/msgmike` 와 뒤이은 `strings \| grep -i cat` 순서대로 복원 | `shell_www-data.log:69-146` / `try1_msgmike_histexpand.log` |
| **4-3 하이재킹 성공** | **`kane@pwnlab:/tmp$ id`** → uid=1002. 성공했으면 프롬프트가 `mike@` 여야 한다 — **노트 자신의 주장과 모순** | `mike@pwnlab:/tmp$ id; ls -la /home/mike` + 출력 전문으로 복원. 프롬프트 전환이 곧 성공 신호라는 해설 추가 | `shell_www-data.log:161-172` |
| 4-4 `ls -la /home/mike` | 별도 실행인 것처럼 블록 분리 — 실제로는 위 `id; ls -la /home/mike` 의 뒷부분 | 4-3으로 통합, 4-4에서 삭제(내용은 유실 없음) | 동 |
| 4-4 `strings msg2root` | `...` 로 3줄만 남겨 `fgets`·`asprintf`·`system` 을 가림 | `head -30` 출력의 읽을 부분 복원 + 세 심볼이 데이터 흐름을 어떻게 만드는지 해설 | `shell_www-data.log:173-190` |
| 4-4 root 획득 | `root@pwnlab:/tmp# id` → uid=0. `id` 단독 실행은 없었다 | 실제 명령 `whoami; id; hostname; hostname -I; date; ls -la /root; cat /root/proof.txt` 와 출력 전문 복원. **`ls -la /root` 가 flag.txt(000)·messages.txt→/dev/null 을 한 번에 보여준다** | `shell_www-data.log:196-215` / `try4` |
| 4-3 nosuid 콜아웃 | "마운트가 `/dev/sda1` 하나뿐" — 가상 fs 마운트가 20개 넘게 있다 | "실 디스크 마운트가 하나이고 **`/tmp` 항목이 없어** `/` 옵션을 물려받는다"로 정밀화 | `harvest_root.txt:881-905` (MOUNTS) |
| **6장 (4)** | 명령에서 `; echo ---; cat /root/flag.txt` 를 잘라냄 | 원문 복원. **`---` 조차 안 찍힌 것이 진짜 단서**였고, 원인은 `exec` 가 줄의 나머지를 들고 있던 셸을 통째로 갈아치운 것 — 이 메커니즘을 추가 | `try4_fakecat_shadowed_PATH.log` |
| 6장 (4) | `echo "PATH=$PATH"` 와 PATH 복원을 두 블록으로 분리 | 원문대로 한 블록. 쪼개면 "보고 나서 고쳤다"는 없던 서사가 생긴다 | 동 |
| 6장 (3) | `...` 로 줄인 명령 2개 | 전문 복원 | `shell_www-data.log:147-160` |

## 2. 추가한 것 (산출물에 있었는데 초고가 빠뜨림)

- **6장 (3) 중간 실패 한 번** — `printf '%s\n' '#''!/bin/bash' ...` 따옴표 분리 우회. **우회 자체는 통했는데**(`event not found` 가 안 남) `/tmp/.pth` 가 없어서 다른 에러 셋이 났다. 에러 문구가 바뀌면 원인도 바뀐 것이라는 교훈. (`shell_www-data.log:151-155`)
- **6장 (5) SUID 열거 함정** — `diff <(sed -n '/===== SUID/,/^===== SGID/p' harvest_www-data.txt) <(... harvest_root.txt)` → `/home/mike/msg2root`, `/home/kane/msgmike` 두 줄. 재현 가능한 형태로 6장에 넣었다(4-1의 `[!danger]` 는 그대로 둠).
- **`; echo ---` 카나리아** — PATH 오염 진단법으로 `[!tip]` 에 추가.
- **`last` vs `auth.log`** — wtmp 만 보고 "흔적 없음"으로 결론 내면 틀린다는 한 줄. (`traces_confirmed.log`)
- **access.log 58건** — `grep -c 192.168.45.207` 실측값.

## 3. 삭제한 것

**없다.** 전부 정정·복원이고, 유일하게 사라진 블록(4-4의 `mike@pwnlab:/tmp$ ls -la /home/mike`)은 같은 출력이 4-3에 원문 형태로 들어갔다. 원문 인용:

```
mike@pwnlab:/tmp$ ls -la /home/mike
total 28
... (이하 msg2root 포함 7행 — 4-3 블록에 그대로 존재)
```

## 4. 내가 다시 반증한 것 — 지적으로 올렸다가 철회

1. **`try3_mysql_ssl.log` 에 `ERROR 2026 (HY000): TLS/SSL error: SSL is required...` 가 없다 → 날조 의심.**
   철회. MariaDB 클라이언트 바이너리에 문자열이 실재한다 —
   `strings $(readlink -f $(which mysql)) | grep -i "SSL is required"` → `SSL is required, but the server does not support it`, 그리고 `TLS/SSL error: %s`.
   `writeup_notes.txt` 17:38 이 같은 문구를 관측 기록으로 남겨두었다. `ERROR 2026` 은 클라이언트 SSL 에러 코드(CR_SSL_CONNECTION_ERROR)의 표준 렌더링. **노트가 옳다. 그대로 뒀다.**

2. **`~/suidtest/` 와 `9099` 리스너 테스트가 `~/.zsh_history` 에 없다 → 미실행 의심.**
   철회 — 이중으로 틀렸다. (a) 이 명령들은 비대화형 `ssh kali "..."` 로 돌아 히스토리에 안 남는다. (b) **감사자가 직접 재현했고 값이 일치한다:**
   - `curl -s -F "file=@probe.gif" http://127.0.0.1:9098/` → `Content-Type: image/gif` (`;type=` 없이)
   - SUID root `execl("/bin/bash","bash",...)` → `1000 / 1000 / EUID=1000 UID=1000`
   - 같은 코드 + `-p` → `0 / 1000 / EUID=0 UID=1000`
   초고가 적은 숫자와 **완전히 같다.** (테스트 디렉터리는 `sudo rm -rf` 로 정리 확인)

## 5. 확인했으나 손대지 않은 것 (근거 확인 완료)

| 주장 | 판정 | 근거 |
|---|---|---|
| ③(a) www-data SUID 열거에 커스텀 SUID 미출현 | ✅ 확인 | `harvest_www-data.txt` 15개(배포판 기본) vs `harvest_root.txt` 17개 — 차이가 정확히 `msgmike`·`msg2root` |
| ③(b) `sudo` 미설치 | ✅ 확인 | `harvest_www-data.txt` SUDO 섹션 `sudo: not found`; `which sudo` 가 빈 출력(`shell_www-data.log` 의 `--- / ---` 사이) |
| ③(c) exim4 4.84.2-1 → `[가정]` 강등 | ✅ 옳은 처리 | `shell_www-data.log` 말미 `dpkg -l` 원문 일치. 익스플로잇 미시도를 미시도라고 적었다 |
| 플래그 2개 · 대화형 pty 원위치 `cat` | ✅ 통과 | `proof_user.txt` / `proof_root.txt` 와 블록이 바이트 일치. `<d; hostname;` 잘림·2회 에코가 **원문 그대로** 실려 있다 |
| `/root/flag.txt` 미끼 표기 | ✅ 있음 | 5장 + 6장 (4). mode 000 · `Your flag is in another file...` |
| nmap 블록 출처 | ✅ 일치 | `nmap.log` 전문. `nnmap` 별칭 실패 후 **전개해서 재실행한 17:47 판**이 맞고, `try2` 가 그 전환을 보여준다 |
| `Nmap scan report for 192.168.248.29` 존재 | ✅ | 색인 `ip: 192.168.248.29` 정상 추출됨 |
| sh.gif 52바이트 / xxd | ✅ | `xxd sh.gif` 와 노트 블록이 오프셋까지 일치 |
| `/etc/exports` 비어 있음 | ✅ | `harvest_root.txt:919` `-- exports --` 다음 줄이 공백 |
| 시간 서사 (17:37→17:45, 13시간 차) | ✅ | 타겟 `date` EDT 04:45:30 = KST 17:45:30, Kali mtime 과 정합 |
| 스크린샷 3장 | ✅ | 볼트 파일 크기가 Kali `shot_80_*` 와 동일(27375/26241/24994). 직접 열어 `You must be log in.`·로그인 폼 확인 |
| 프론트매터 태그 8개 | ✅ 신규 0건 | 전부 `03. PG` 내 다른 노트에 이미 존재(최소 2건~최대 50건). 설명만 하고 안 쓴 기법 없음 |
| `manual_tags: true` 뒤 주석 | ✅ 없음 | `refresh.ps1` 후에도 보존, `tech_count: 8` |
| `manual_cves` | 불필요 | 본문에 CVE 번호가 0개 |
| 로그 삭제 서술 | ✅ 없음 | 「지우지 않은 것」으로 분리돼 있고 규율대로다 |
| 미확인 2건(MySQL 쿼리 로그·syslog) | ✅ 명시됨 | 「확인하지 않은 것」 절 존재 |

## 6. 관리자 판단 필요 — 노트 밖 사안

**(A) 터미널 블록의 Kali 프롬프트 관례 — 노트 전체에 파급되는 사안이라 손대지 않았다.**
이 노트(그리고 정황상 다른 노트들)는 Kali 쪽 명령을 `┌──(kali㉿kali)-[~/PG/PwnLab]` / `└─$` 로 감싼다. 그런데 이 명령들은 실제로는 **비대화형 `ssh kali "..."`** 로 실행됐고, 그 출력에는 zsh 프롬프트가 **존재한 적이 없다.** 값과 명령은 전부 산출물과 일치하므로 날조는 아니지만, `CLAUDE.md` §3 이 "코드펜스와 셸 프롬프트는 서식이 아니라 **실측의 표식**"이라고 못박은 것과 정면으로 어긋난다.
셋 중 하나로 정해야 한다 — (i) 프롬프트 장식을 허용 관례로 표준에 명문화, (ii) Kali 쪽 블록은 프롬프트 없이 명령만, (iii) 실제로 대화형 pane 에서 친 것만 프롬프트 유지.
**타겟 쪽 pty 블록은 이 문제가 없다** — 그건 진짜 캡처다.

**(B) `harvest.sh` 잔버그** — 지시대로 손대지 않았다. `sudo` 없는 호스트에서 `sudo -S -l` 분기가 `sh: echo: I/O error` 를 낸다. 이 박스에서는 `SUDO` 섹션에 `sudo: not found` 가 정상적으로 남아 동작에 지장 없었다.

## 7. 감사가 하지 않은 것

- 박스·tmux `pwnlab_shell` 접속 안 함(지시대로). 타겟 측 재검증은 산출물 대조로만.
- `_STATUS.md` 미수정(이미 반영됨).
- 홈 전체 스캔·`find /` 안 함(규율). 고정 출처 목록 안에서만 확인.
- Kali 재실행 3건은 전부 **localhost 및 임시 디렉터리** 한정, 종료 후 `sudo rm -rf` 로 정리 확인.
