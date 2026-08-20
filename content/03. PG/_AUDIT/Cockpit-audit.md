---
tags:
  - type/audit
  - platform/pg
---
# Cockpit — 적대적 검증 감사 (2026-08-20)

대상: `03. PG\Cockpit.md` (148행 `.bak` → 655행 개작본 → **687행** 정정본)
검증자 = 정정자 동일. 타겟에 패킷을 보내지 않았다 — 문서·산출물·스크린샷 대조 전용.

## 0. 최종 판정

**완료 2/2.**

근거는 노트가 아니라 스크린샷이다.
- `local.txt` = `e4461b92c770db29bb95ae433e3f73ac` — `파일보관/Pasted image 20260626111320.png`
- `proof.txt` = `fc0dcc22a87ad79ebf61dcece9b4ce0c` — `파일보관/Pasted image 20260626135233.png`

2026-06-26 에 두 플래그를 읽은 화면이 실재하므로 그 시점에 이미 푼 박스다. `_STATUS.md` 의 "미착수"는 **볼트 기록이 뒤처졌던 것**이지 안 푼 것이 아니다.

**단, OSCP 시험 채점 기준으로는 두 플래그 다 0점이다** (아래 2절).

## 1. 관리자 지시 확인 — `flag2.txt` 실측 블록 변조

관리자 지적이 **맞다.** 독립 확인했다.

- 노트 코드펜스: `RWFzdGdVVyRWdn` (14자)
- 스크린샷 실제 값: **`RWFzdGVyRWdn`** (12자) — `Pasted image 20260626135233.png` 의 해당 줄을 5배 LANCZOS 확대해 판독
- `echo -n 'RWFzdGVyRWdn' | base64 -d` → **`EasterEgg`** (Kali 에서 실행)
- 대조군: `echo -n 'RWFzdGdVVyRWdn' | base64 -d` → `EastgUW$V` 뒤 `base64: invalid input`, exit 1

즉 노트가 "디코딩되지 않는다 · 무엇인지 확인하지 않았다"고 결론 낸 것은 **자기가 만든 오타를 관찰한 것**이었다.

**삭제한 원문 (되살릴 수 있게 인용해 둔다):**

> `/root/flag2.txt` 의 `RWFzdGdVVyRWdn` 는 제출 대상이 아닌 별도 파일이다. base64 로는 온전히 디코딩되지 않는다(14자, 패딩 불일치). 이게 무엇인지는 확인하지 않았다.

교체한 것: 값 정정 + `base64 -d` 실행 블록 + 이스터에그 확정 + "32자 hex 가 아니면 대개 플래그가 아니다" 한 줄.

### 같은 유형이 다른 코드펜스에도 있는가 — 전수 대조

노트의 터미널 블록 **19개 전부**를 원본과 맞춰봤다. **flag2 한 건 외에 변조 없음.**

| 블록 | 대조 대상 | 결과 |
|---|---|---|
| `nmap.log` 전문 | `~/PG/Cockpit/nmap.log` | **바이트 일치**(`ssh-hostkey:` 줄 끝 공백 1개만 트림) |
| `searchsploit Cockpit` | Kali 재실행 | 5건·순서·잘린 위치까지 일치 |
| `searchsploit -p 49390` | Kali 재실행 | `Codes: N/A`·`Verified: False`·`File Type: ASCII text` 전부 일치 |
| 49390 페이로드 `{"auth":{"user":"test'.phpinfo().'",…}}` | `/usr/share/exploitdb/.../49390.txt` | 일치 |
| feroxbuster 2일차 배너+결과 7줄 | 2일차 `.state`(`resources_discovered: 7`, scans 목록) | URL 7개 정확히 일치 |
| `base64 -d 'Y2Fud…'` | `~/.zsh_history` 1193행 + Kali 재실행 | 명령·출력 일치 |
| MySQL 에러 텍스트 | `…105549.png` | 일치(끝의 `'%%"` 는 노트가 이미 모호성을 명시) |
| 사용자 표 (2계정 base64) | `…105320.png` | 일치 |
| `sudo -l` 출력 | `…130129.png` | 일치 |
| `sudo tar` 권한상승 전문 | `.bak` 원본 | 일치(개작이 손대지 않음) |
| 권한상승 1차 폐기 페이로드 | `…133613.png` | 일치 |
| `wc -l ferox.txt` → 6997 | Kali 재실행 | 일치 |
| `grep -c '^200'` → 6833 | Kali 재실행 | 일치 |
| 크기분포 awk 6줄 | Kali 재실행 | 6줄 전부 숫자까지 일치 |
| `grep '^200' \| head -5` | Kali 재실행 | 5줄 일치 |
| 디렉터리 분포 sed/uniq 4줄 | Kali 재실행 | 일치 |
| `ferox_80.txt` 결과 8줄 | Kali 재실행 | 일치 |
| history 8줄 (searchsploit 구간) | `~/.zsh_history` 1170–1177 | 일치 |
| Kali sudoers `ztest` 재현 실험 | journald | 2절 참조 — **실행 확인됨** |

## 2. 두 번째 초점 — `proof.txt` 는 웹 터미널인가

**웹 터미널이다. 두 플래그 모두 시험 기준 0점.** `[가정]` 아님 — 픽셀 증거가 있다.

방법: 각 스크린샷에서 초록색 프롬프트 `james@blaze` 구간을 잘라 비교했다.

- `…111320.png` (Cockpit UI 크롬이 그대로 찍힌 확정 웹터미널) 의 `james@blaze` = **87×14px**
- `…135233.png` (proof.txt, 크롬 없음) 의 같은 구간 = **87×14px**
- 두 크롭의 RGB 배열 **`np.array_equal` → True (완전 동일, mean abs diff 0.0)**
- `…130129.png`(sudo -l), `…133613.png`(권한상승 1차)도 동일하게 **diff 0.0**

같은 렌더러·같은 폰트·같은 크기·같은 서브픽셀 안티앨리어싱이라는 뜻이다. 다른 터미널 에뮬레이터(Windows Terminal·PuTTY·xterm)에서 우연히 바이트 단위로 일치할 확률은 사실상 0이다.

방증:
- `~/.zsh_history` 에 **`ssh james@` 0건** (`grep -c` = 0)
- `~/PG/Cockpit/` 에 리스너·리버스셸·페이로드 산출물 **없음**
- 6월 25–26 구간 history 에 `nc -l` 계열 **없음**
- `…111116.png` 주소창이 `https://192.168.161.10:9090/system` — 세션은 브라우저 안에서 시작됐다

노트 반영: §3 `[!danger]` 에 "이후 전 과정이 같은 창"을 추가, §5 에 판정 근거를 담은 `[!warning]` 을 신설, §0·상단 요약·§7-4 를 "둘 다"로 정정, §5 플래그 표에 "어디서 읽었나" 열 추가.

## 3. 세 번째 초점 — 작성자 주장 재판정

### 3-1. "Kali 에서 직접 실행 검증했다" — **사실이다. 날조 아님.**

`/etc/sudoers.d/` 에 `ztest` 잔재 없음, `/tmp/ztest`·`/tmp/backup.tar.gz` 없음, `~/.zsh_history` 에도 흔적 없음. 여기서 멈췄으면 "부재 → 날조" 오판이 나올 자리였다.

이 Kali 에는 **`/var/log/auth.log` 자체가 없다**(journald 전용). `journalctl` 을 보니 전부 남아 있었다:

```
Aug 20 13:40:00 kali sudo[350103]: kali : COMMAND=/usr/sbin/visudo -c -f /tmp/ztest
Aug 20 13:40:00 kali sudo[350106]: kali : COMMAND=/usr/bin/install -m 440 -o root -g root /tmp/ztest /etc/sudoers.d/ztest
Aug 20 13:40:00 kali sudo[350114]: kali : USER=nobody ; COMMAND=/usr/bin/sudo -n -l /usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=id
Aug 20 13:40:00 kali sudo[350119]: kali : USER=nobody ; COMMAND=/usr/bin/sudo -n -l /usr/bin/tar -czvf /tmp/other.tar.gz x      ← 노트가 말한 대조군
Aug 20 13:40:24 kali sudo[350134]: kali : USER=nobody ; COMMAND=/usr/bin/sudo -n /usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=id /etc/hostname
Aug 20 13:40:24 kali sudo[350137]: nobody : USER=root ; COMMAND=/usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint=1 --checkpoint-action=exec=id /etc/hostname
Aug 20 13:40:24 kali sudo[350132]: kali : COMMAND=/usr/bin/rm -f /etc/sudoers.d/ztest /tmp/ztest /tmp/backup.tar.gz
```

마지막에서 두 번째 줄이 결정적이다 — **`nobody` 가 `sudo` 를 통해 root 로 `tar` 를 실행한 기록**이라, sudoers 의 `*` 가 그 인자를 실제로 매칭했음을 journald 가 독립적으로 증명한다. 노트가 보여준 출력이 사실이라는 뜻이고, **흔적 제거 주장도 사실**이다.

같은 실험을 다시 돌리지는 않았다 — `/etc/sudoers.d/` 에 파일을 쓰는 것은 시스템 보안 설정 변경이고, journald 증거가 재실행보다 강하다.

다른 단정형 주장도 Kali 에서 직접 때려봤고 **전부 노트가 맞았다**:

| 노트의 단정 | 실행 결과 |
|---|---|
| `touch --` 를 빼면 `unrecognized option` 으로 죽는다 | `touch: unrecognized option '--checkpoint=1'` ✔ |
| `--checkpoint` 만 주면 체크포인트 줄이 찍히고, `--checkpoint-action=exec=` 를 주면 사라진다 | `tar: Write checkpoint 1` 나옴 → action 주니 사라짐 ✔ (GNU tar 1.35) |
| `sudoers(5)`: `*` 는 "zero or more characters (including white space)" | man 5 sudoers 975–992행 ✔ |
| 인자 자리에서는 슬래시도 매칭된다 | man 5 sudoers 1010–1013행 *"a slash does get matched … arbitrary strings and not just path names"* ✔ |
| `"Wildcards in command line arguments should be used with care"` | man 5 sudoers 1015행 ✔ |
| base64 두 개 → `canttouchhhthiss@455152` / `thisscanttbetouchedd@455152` | ✔ |
| `49397.txt` 는 `.txt` 인데 python3 스크립트 | `file` → `Python script, ASCII text executable` ✔ |
| `login` 이 두 워드리스트 모두 53(행)째 | 두 파일 다 `grep -n -x login` → 53 ✔ |
| `@localhost` 는 워드리스트에 없다 | `grep -c -x '@localhost'` → 0 ✔ |
| 링크 추출이 기본 켜짐 | ✔ (배너 `Extract Links │ true`) — **단 플래그명은 틀렸다.** `--extract-links` 는 `--help` 에 없고 `--dont-extract-links` 만 있다. 대조군 `--zzznotaflag` 는 rc=2 `unexpected argument` 인데 `--extract-links` 는 rc=0 이라 구 별칭으로 파싱만 되는 상태 |

### 3-2. 총괄 지시 둘 — **작성자의 반증이 옳다. 지시가 틀렸다.**

**① "2일차 `.state` 8.6KB = 작업 중단"** → 인과가 반대다.
2일차 `.state`(mtime `2026-06-26 10:51:35 +0900`)를 파싱하니 `resources_discovered: 7` 에 **`login.php` 가 이미 들어 있고**, 루트 스캔만 `Running` 인 채로 저장됐다. 즉 `login.php` 를 발견하고 **Ctrl-C 로 끊은 것**이다. 90초 뒤인 `10:53:12` 에 로그인 페이지 스크린샷이 찍혔다. "지쳐서 중단"이 아니라 "찾아서 중단"이다.

**타임존 확인함** — 이 Kali 는 systemd 상 UTC 지만 SSH 세션 환경에 `TZ=Asia/Seoul` 이 걸려 있어 `ls --time-style=full-iso` 가 `+0900` 으로 렌더한다. `nmap.log` 본문의 `Nmap done at Thu Jun 25 10:23:32 2026` 과 그 파일 mtime `10:23:32 +0900` 이 정확히 일치해 교차 확인했다. **환산 오류로 인한 자기모순 지적은 없다.**

**② "9090 이 침투 경로"** → 아니다. 9090 스캔(`ferox.txt`, 200 응답 6,833건)에서 건진 것은 0이고, 실제 경로는 tcp/80 `login.php` → base64 자격증명 → 그 자격증명으로 9090 로그인이다. 9090 은 **셸을 얻는 창구**였지 취약점이 아니었다. 1일차는 통째로 헛수고가 맞다.

### 3-3. "원본 노트도 이미 두 플래그를 담고 있었다" — **거짓.**

라인 관리자 대조와 같은 결론. `.bak` 148행에 `e4461b92…`·`fc0dcc22…` **0건**. 값은 스크린샷 링크 뒤에만 있었다. 복원 자체는 정당하지만 출처 진술이 틀렸으므로, 노트 상단 정정 이력에 **증가분 출처를 "스크린샷 10장 + `~/PG/Cockpit/` 산출물 6개 + `~/.zsh_history` 1170–1197행 + Kali 직접 실행"** 으로 명시했다.

"스크린샷 10장" 주장은 **사실이다.** Cockpit 관련 스크린샷을 세면 정확히 10장(`105312`·`105320`·`105549`·`110746`·`110833`·`111116`·`111320`·`130129`·`133613`·`135233`). 같은 날짜대의 `20260625135833`(boroCTF 수료증)·`20260626142047`(Gerapy 로그인, Levram 건)은 다른 건이라 제외한 것이 맞다. 노트가 본문에 링크한 것은 9장이고, `110746`(Burp Decoder 1차)은 §6 시간표에서만 근거로 쓰였다.

## 4. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `bash-5.0# cat flag2.txt` 다음 줄 | `RWFzdGdVVyRWdn` — 실측 블록 전사 변조 | `RWFzdGVyRWdn` |
| `base64 로는 온전히 디코딩되지 않는다` | 위 오타에서 파생된 틀린 결론 | `base64 -d` 실행 블록 + `EasterEgg` 확정으로 교체 |
| `> [!warning] 증거 스크린샷 형식` | 웹셸 문제를 언급하지 않음 | `> [!warning] 이 화면은 시험 증거로 두 번 실격이다` 로 확장, 픽셀 대조 근거 수록 |
| `\| 위치 \| 값 \|` (§5 표) | 어디서 읽었는지 없음 · flag2 누락 | "어디서 읽었나" 열 + flag2 행 추가 |
| `→ 콘솔 내장 터미널로 local.txt → … → root` (상단 요약) | root 획득만 적고 proof 출처 누락 | `→ 같은 터미널에서 proof.txt` |
| `이 박스의 원본 기록이 정확히 그 실수를 했다` (§0) | 한 플래그만 해당하는 것처럼 읽힘 | "둘 다 0점" 명시 |
| `> [!danger] 이 화면으로 받은 플래그는…` (§3) | 이후 구간이 같은 창임을 안 밝힘 | 한 문단 추가 |
| `### 열거 — feroxbuster 3회` | history 상 실제 9회 | `9회` + 회차 내역 |
| `두 번 돌렸고, 두 번째 결과가 ferox.txt 다` (§6②) | 9090 은 4회 | 4회 + 워드리스트 구분 |
| `결과가 7줄이었다` / `건진 7건을 보면` (§6③) | 200 응답은 6건 | 6건 (+`MSG` 2줄) |
| `\| 06-25 15:32 \| 80 ferox — 결과 7줄` (시간표) | 위와 같음 | `200 응답 6건` |
| `\| 06-25 11:12 \| 9090 ferox 1차 중단` · `2차 종료` | 4회를 2회로 압축 | "이 시점의 상태만 `.state` 로 남았다" / "마지막 회차" |
| `\| 06-26 10:51 \| … 재시도, 중단` | 인과 미기재 | `login.php 발견 후 Ctrl-C` + 근거 명시 |
| `벤더 홈페이지 필드(Vendor Homepage:)` (§1 tip) | `49390.txt` 에는 그 필드가 없다 (`# Product:`) | 두 형식 병기 + "필드명 grep 하지 말고 머리말을 훑어라" |
| `첫 20줄에서 확인할 것은 셋이다 — ① 제품명(Vendor Homepage:)` (§6①) | 위와 같음 | `제품 식별 줄` + 파일별 실제 필드명 |
| `파일 첫 20줄에 Vendor Homepage: 와` (§7-1) | 위와 같음 | `제품 식별 줄(Vendor Homepage: 또는 Product:)` |
| `맞춤법 밑줄이 그어진 한 글자` (§2) | 확대해도 밑줄 없음 (서브픽셀 색번짐을 오독) | 밑줄 서술 삭제, 글리프 형태 판독으로 대체 |
| `login 은 두 워드리스트 모두에서 53번째 단어` (§1) | "단어"는 부정확(주석 15줄 포함 시 53**행**) · 워드리스트명 미기재 | 파일명 명시 + `53행째` |
| `워드리스트 220,560 단어에 -x…` (§6②) | 220,560×6 = 1,323,360 ≠ 상태파일의 1,323,276 | `22만 단어` + 파일 행수/단어수 구분 |
| `text 는 워드리스트 341번째 … 단어` | 341/550/1688 은 행 번호 | `행` 으로 통일 |
| `login.php 는 common.txt 에도 있다` (§7-3) | `common.txt` 에 있는 건 `login`(2347행) | `-x php` 와 함께면 요청된다로 정정 |
| `다음 날 … 같은 스캔이 곧바로` (§6③) | 워드리스트가 달랐다 | `같은 성격의 스캔` + `.state` 근거 |
| `링크 추출(--extract-links, 기본 켜짐)` (§6②) | 2.13.1 `--help` 에 `--extract-links` 는 없다. 문서화된 것은 끄는 쪽 `--dont-extract-links` 뿐 | 끄는 플래그명으로 정정 + "워드리스트에 없는 경로가 나오면 이걸 의심" 한 줄 |
| `sudoers 인자 매칭을 검증하려고 … 삭제 확인` (남긴 흔적) | 주장만 있고 교차 근거 없음 | journald 타임스탬프로 교차 확인 결과 병기 |
| (신설) 노트 상단 | 정정 이력 없음 | `> [!warning] 적대적 검증 정정 이력` 표 + "노트가 옳았던 것" 목록 |

## 5. 삭제한 것

**한 건뿐이다** (1절에 원문 인용). 나머지는 전부 정정·보강이며, `[가정]` 강등은 새로 만든 것이 없다 — 기존 `[가정]` 표기 다섯(`a` 판독 · 대시보드 별도 조회 · SSH 추론 · IP 차단 추정 · 1차 페이로드 미실행) 은 근거를 재확인한 뒤 **그대로 유지**했다. 특히 SSH 추론 `[가정]`(§3)은 `grep -c 'ssh james' ~/.zsh_history` = 0 으로 노트의 자기 진술이 정확함을 확인했다.

## 6. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

이 절이 검증 절차 자체의 정확도 기록이다.

1. **"Kali sudoers 실험은 날조다"** — `/etc/sudoers.d/`·`/tmp`·`~/.zsh_history` 어디에도 흔적이 없어 첫 판정은 "날조 유력"이었다. `/var/log/auth.log` 를 봤더니 **그 파일 자체가 없었다.** journald 를 뒤져서야 전 과정이 나왔다. **부재 증거로 판정했으면 정확한 절을 삭제할 뻔했다.**
2. **"타임존 미환산으로 시간 서사가 깨져 있다"** — 깨지지 않았다. `nmap.log` 본문 시각과 파일 mtime 이 같은 프레임(KST)이고 스크린샷 파일명도 KST다. §6 시간표는 정합적이다.
3. **"`ferox.txt` 통계는 재현 불가한 창작이다"** — 6개 명령 전부 그대로 재현했고 숫자 하나까지 일치했다.
4. **"2일차 feroxbuster 블록은 출력 파일이 없으니 검증 불가"** — `-o` 가 없어 파일은 없지만 `.state` 의 `resources_discovered: 7` 과 `scans` 목록이 URL 7개를 정확히 뒷받침한다.
5. **"`searchsploit` 블록은 지어낸 것"** — Kali 재실행 결과 5건·순서·잘린 위치까지 일치했다.
6. **총괄 지시 ①②** — 둘 다 지시 쪽이 틀렸다(3-2절).
7. **"스크린샷 10장은 부풀린 숫자"** — 정확히 10장이다.

## 7. 근거 출처

- Kali 산출물: `~/PG/Cockpit/{nmap.log, 49390.py, ferox.txt, ferox_80.txt, ferox-http_192_168_150_10_9090_-1782353548.state, ferox-http_192_168_161_10_-1782438695.state}`
- `~/.zsh_history` 1170–1197행 (`~/.bash_history` 는 존재하지 않음)
- journald: `journalctl --since '2026-08-20 00:00' _COMM=sudo`
- 볼트 스크린샷 10장 (`파일보관\Pasted image 20260626*.png`), PIL 로 크롭·확대·픽셀 비교
- 1차 사료: `man 5 sudoers`(sudo 1.9.x, Kali), GNU tar 1.35, `/usr/share/exploitdb/exploits/{php/webapps/49390.txt, multiple/webapps/49397.txt}`
- 직접 실행: `base64 -d` ×3, `touch '--checkpoint=1'`, `tar --checkpoint` 유무 대조, `searchsploit Cockpit`, `searchsploit -p 49390`, `file`, 워드리스트 `grep -n -x`, `wc -l`
- git: `03. PG/Cockpit.md` 는 `607fbc5`·`15671e5` 두 커밋에만 등장한다(개작본은 미커밋). baseline 대조는 워킹트리의 `Cockpit.md.bak` 으로 했다.

## 8. 정리한 흔적 (Kali)

이 감사 중 만든 것은 전부 제거했다 — `/tmp/--checkpoint=1`, `/tmp/t1.tar.gz`, `/tmp/t2.tar.gz`, `mktemp -d` 임시 디렉터리. `sudo` 는 읽기(`ls`/`journalctl`)에만 썼다. `/etc/sudoers.d/` 는 배포 기본 4개 그대로.
