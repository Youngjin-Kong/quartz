---
type: audit
box: PlanetExpress
wave: 13
auditor: writeup-auditor
date: 2026-08-26
manual_tags: true
manual_cves: true
---

# PlanetExpress 적대적 감사 (wave 13)

대상: `03. PG\PlanetExpress.md` (개작 직후 765행 → 정정 후 803행)
대조 출처: `~/PG/PlanetExpress/` 62개 산출물 · 볼트 `파일보관\` 스크린샷 2장 · `~/.zsh_history` · `03. PG\_backup\PlanetExpress.md.bak`(1003행) · `03. PG\_AUDIT\PlanetExpress-playbook.md`

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `RST 무응답은 INPUT 체인 DROP 을 뜻함` | **자기 산출물에 반박당함.** 같은 노트가 인용하는 `root_enum_fw.log` 의 `iptables -L -v -n` 에서 INPUT 의 `DROP` 카운터가 `0 packets`이고, 그 앞 `-m conntrack --ctstate NEW,RELATED,ESTABLISHED -j ACCEPT` 가 새 연결까지 받아 DROP 규칙에 닿지 않음. 즉 nmap 이 본 `filtered` 65532개는 이 호스트가 만든 것이 아님 | 인과를 정정. 상류(랩 네트워크) 필터링으로 판정하고, 카운터 근거를 Privilege Escalation 부록에 4행 발췌로 추가 |
| 부록 `iptables -S` 만 게재 | `-L -v -n` 카운터가 빠져 위 판정의 근거가 노트 안에 없었음 | `root_enum_fw.log` 의 `-L -v -n` 에서 INPUT ctstate/DROP · OUTPUT dpt:80/DROP 4행 발췌 추가. OUTPUT DROP `131K`(실제로 물었음) vs INPUT DROP `0`(안 물었음) 대비 서술 |
| `아웃바운드가 막혀 있으니 인바운드 80 을 역이용` (2곳: PrivEsc Steps 2, 본문) | **내부 모순.** 같은 노트가 tcp/80 아웃바운드로 리버스셸이 붙었다고 적음. `iptables -S` 도 `--dport 80 ... ACCEPT` | 「아웃바운드가 dport 53/80/9000 로만 열려 있고 타겟에 `curl` 도 없음」으로 한정. Steps 는 「아웃바운드가 제한돼 있어」로 |
| relayd `-h` 블록 `— 출처: enum_relayd.log (전문 축약)` | **출처 오기.** `enum_relayd.log` 는 `ls`/`file`/`md5`/`stat`/`dpkg` 만 담음. Usage 블록은 `enum_ps.log` 의 `--- relayd usage ---` 절 | 출처를 `enum_ps.log` 로 정정. 아울러 축약돼 있던 액션 7개(`-v -k -s -U -r -i -R`)·옵션 3개(`-d -g -n`)를 전문으로 복원 |
| `nm relayd.bin` 6행 + `심볼 14개짜리` | **표·서술 불일치.** 펜스에는 6행뿐인데 산문은 14개라 함. 출처도 `relayd.main.asm 관련 nm 출력` 으로 objdump 파일에 오귀속 | 회수본 `relayd.bin` 에 `nm` 재실행해 14행 전량 복원. 출처를 `relayd.bin` 으로 정정. 도움말 액션과의 1:1 대응 명시 |
| `— 출처: payload_pathhijack.php 경유로 심음` (python 하이재킹) | **파일 오기.** mtime 대조 — `payload_pathhijack.php`(16:14:31)→`try10`(`#!/bin/sh` 판), `payload_py.php`(16:15:20)→`try12`(python 판) | `payload_py.php` 로 정정하고 `payload_pathhijack.php` 가 첫 시도 판임을 병기 |
| `ls -la /usr/sbin/relayd` 펜스 (출처 없음) | 캡션 누락 | `enum_relayd.log` 캡션 + BuildID·stat 생략 표시 추가 |
| `#!/bin/sh` 하이재킹 셸 블록 (출처 없음) | 캡션 누락 | `payload_pathhijack.php` 캡션 + 「passthru 한 줄을 셸 명령 단위로 끊어 옮김」 명시 |
| Go 문자열 오프셋 표 (출처 없음) | 캡션 누락 | `relayd.bin` 직접 읽기 + `relayd.main.asm` 의 `lea`/`mov` 대응 명시 |
| phpinfo 자기오염 ⚠️ 「이 **네** 값은」 | **누락.** `picotest_out.html` 에는 `auto_prepend_file=php://input` 도 Local/Master 양쪽에 찍혀 있음 — `fcgi.py` 의 `PHP_VALUE` 세 지시자 중 가장 결정적인 것 | 「다섯 값」으로 정정, `auto_prepend_file=php://input` 추가, 「다섯 개가 그 두 지시자 문자열의 전부」 명시 |
| nmap `-p-` 펜스 | OS 추정·TRACEROUTE 블록이 **표시 없이** 잘려 있었음 | `Warning: OSScan results may be unreliable ...` 1행 복원(닫힌 포트 부재의 보강 근거) + 「OS 추정·TRACEROUTE 블록 생략」 캡션 |
| `try6_enum.log` 펜스 | `/home` 의 `total`·`.`·`..` 3행과 `/var/www/html/planetexpress` 목록 전체가 **표시 없이** 생략 | 생략 표시 삽입 |
| `payload_rev80.php` 펜스 | 원본 2행을 3행으로 재줄바꿈, `echo "fired\n";` 누락 | 원본 전문 그대로 복원 |
| `proof_session_raw.txt (tmux 캡처, ...)` | **근거 없는 단정.** 파일에 tmux 표식 없음(첫 줄이 SSH 배너·post-quantum 경고·Debian MOTD). Kali 프롬프트도 없음 | 「전문(앞의 SSH 배너·MOTD 생략)」 + 타겟 pty 프롬프트가 대화형 셸 근거임을 명시. **프롬프트·플래그·명령은 한 바이트도 안 건드림** |
| 「남긴 흔적」 표 8행 전체를 `cleanup_target.log` 에 귀속 | **과잉 귀속.** 그 로그는 **타겟 쪽만** 담음(끝이 `Permission denied (publickey,password)`). Kali 쪽 3행(tmux 6세션·리스너·`~/dashtest`)은 어느 산출물에도 확인 출력이 없음 | 표를 타겟 5행으로 줄이고, Kali 쪽은 별도 목록 + `[가정]` 강등(「했다는 기록만 있고 확인 출력이 없음」). **삭제 아님 — 서술 보존** |
| `되돌리지 않은 것: 없음 — 타겟 원본 파일은 하나도 수정하지 않음` | 파일은 맞으나 디렉터리 mtime 변화가 남음 | 「원본 **파일**은」으로 한정하고 `/tmp`·`/root` mtime 변화 병기 |
| 「관측 없음」 표 | `.bak` §6 「안 해본 것」 3항목이 노트·`_PLAYBOOK` 제안 어느 쪽에도 안 들어감(아래 3절) | 3행 추가 — relayd `-a/-r/-i/-U` 미확인 · Pico 2.1.4 자체 벡터(`debug:true`+Twig 1.44.6 SSTI, `PicoOutput`) 미확인 · shadow 룰/다른 사전 미시도 |

**삭제한 것: 없음.** 모든 정정이 문구 교체·한정·강등·복원이며, 실측 블록에서 제거한 줄은 한 줄도 없음.

---

## 2. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

1. **🔴 지목 1 「443 차단」 등급 — 노트가 옳다. `[가정]` 강등하지 않았다.**
   지시는 「tun0 캡처는 성공한 회선만 보여준다 → `[가정]` 으로 강등」이었으나, **이 노트는 캡처 추론에 기대지 않는다.** root 로 읽은 `root_enum_fw.log` 의 `iptables -S` 에 OUTPUT 이 `dport 53/80/9000`·`sport 22/80/9000`·lo·icmp 만 ACCEPT 하고 마지막이 `-j DROP` 이며, `-L -v -n` 카운터가 그 DROP 에 `131K packets`. 443 은 그 DROP 에 걸릴 수밖에 없음 — **양성 증거이므로 단정형이 정확한 등급**이다. 오히려 `tcpdump_connectback.log` 는 전문이 `tcpdump: can't parse filter expression: syntax error` 한 줄이라 캡처 자체가 존재하지 않는다(그 사실은 이미 `_PLAYBOOK` 제안 3에 이관됨). 계층 분리도 확인 — Kali 쪽 `address already in use` 흔적 없음(`shell443.log` 는 `listening on [any] 443 ...` 로 정상 LISTEN).
2. **🔴 지목 2 「남긴 흔적」 타겟 절대경로 개변 — 없다.**
   `cleanup_target.log` 트레이스에 `rm -rf /tmp/.x /tmp/.pf`, `rm -f /var/www/html/planetexpress/assets/relayd.bin`, `pkill -f 'nc 192.168.45.207 80'` 이 **타겟 절대경로 그대로** 남아 있고 노트 표와 문자열 단위로 일치. SSH 키 경로도 `payload_key.php` 의 `cp /tmp/.x/k.pub /root/.ssh/authorized_keys` 와 일치하며, `/root/.ssh` 가 **우리가 만든 것**이라는 주장도 뒷받침됨 — `try13` 시점 `/root` 링크수 4, 정리 후 3. 가짜 `iptables` 위치도 `/tmp/.x/iptables` 로 일관. **경로 개변 0건.**
3. **🔴 지목 3 pty 프롬프트 — 노트가 원문과 바이트 일치.**
   `proof_session_raw.txt` 를 `cat -A` 로 대조. `root@planetexpress:~#`, 줄바꿈이 `/root/proof.t` + `xt` 로 끊긴 것까지 그대로, `su - astro` 뒤 `$` 프롬프트도 보존. 플래그 두 개 한 글자씩 대조 — `4dca621ae70cad152924516c7789381c`(root) / `484f662f955b828510887c65d2565a7f`(astro) **완전 일치**. 지목이 예고한 `Connection to <host> closed.` 는 **원문에 없다**(파일이 astro 프롬프트에서 끝남) — 노트가 그 줄을 지운 것이 아니라 애초에 없던 것.
4. **지목 4 Kali 프롬프트 제거 — 정당했다. 복원 대상 없음.**
   직접 재확인: `grep -al 'kali㉿kali' ~/PG/PlanetExpress/*` → **0건**, `grep -ac planet ~/.zsh_history` → **0**(전체 3165행). PwnLab 식 `tmux capture-pane` 예외에 해당하는 산출물이 이 박스에는 **없음.**
5. **지목 12 「노트가 자기 산출물에 반박당하는 곳」 — 대부분 반박당하지 않았다.**
   `installed.json` 9개 패키지 버전이 노트 목록과 순서·값 전부 일치. `picotest_out.html` 의 `PHP Version 7.3.31-1~deb10u1`·`System`·`FPM/FastCGI`·`Loaded Configuration File`·`$_SERVER['SCRIPT_FILENAME']`·`$_SERVER['DOCUMENT_ROOT']=/var/www/html/planetexpress` 전부 일치. 스크린샷 `PG-PlanetExpress-picotest-phpinfo.png` 를 직접 열어 대조 — 모순 없음. `exec.Command` 상대경로 서술도 실측으로 재확인(아래 6). **반박당한 것은 위 1절 첫 두 행뿐.**
6. **디스어셈 주장 — 재실행으로 전부 확인.** `relayd.main.asm` 566행 `51812b: call 4d4180 <os/exec.Command>`(broadcast), 1023행 `518883`(runMain) 일치. 각 직전 `lea ... # 5583db` / `# 5583d9` 와 `lea ... # 559578` + `mov $0x8,%ebx` 확인. `relayd.bin` 에서 해당 가상주소를 직접 읽어 `b'iptables'`(8) / `b'-S'` / `b'-L'` 확인. `md5sum relayd.bin` = `63f7be5bc3bddda4783e84f7db1fedd0` — 노트의 타겟측 md5 와 일치(회수 무손상 주장 확증).
7. **`config.yml` 펜스 — 원본과 완전 일치.** 812바이트 전문을 `cat -A` 로 대조. 주석 블록(`##`·`# Basic`·`## `(뒤 공백)·`#PicoTest:`)과 `pages_order_by_meta: planetexpress `(뒤 공백)까지 보존. **작성자가 덧붙인 한국어 해설은 전부 펜스 밖.** 개변 0.
8. **`enum_www-data.log` 계열 인용 — SUID 14행·`sudo: a password is required`·`/etc/crontab` run-parts 4줄·`/etc/cron.d` 2항목 전부 일치.** `getcap` 미실행 자인도 사실(`payload_enum2.php` 에 없음).
9. **타임존 — 노트가 옳다.** 타겟 EDT(UTC−4) vs Kali KST(UTC+9) = 13시간. 노트의 `03:17:03 AM EDT` ↔ 산출물 mtime `16:17:30 +0900` 정합.

---

## 3. 이관 손실 — `_PLAYBOOK` 제안 1건 누락 (관리자 판단 필요)

`_AUDIT\PlanetExpress-playbook.md` 「검산」이 **「§6 하위 6개 단위 = 제안 6건, 1:1, 손실 없음」** 이라 적었으나, `.bak` §6 하위 절은 실제로 **7개**다.

```
760 ### (1) docroot 를 모른 채 FastCGI 를 두드린 3분      → 제안 2
781 ### (2) 아웃바운드 진단 오독 — 8분                     → 제안 3
834 ### (3) `#!/bin/sh` 하이재킹이 조용히 실패한 것        → 제안 5
851 ### (4) phpinfo 가 내 값을 되비쳤다                    → 제안 1
873 ### 헛다리 — relayd 의 `-C` 와 `-P`                    → 제안 6
901 ### 헛다리 — gobuster                                  → 제안 4
922 ### 안 해본 것                                          → 대응 제안 «없음»  ← 누락
```

누락된 「안 해본 것」 3항목 원문(`03. PG\_backup\PlanetExpress.md.bak` 922~927행):

> - `/etc/shadow` 의 sha512 두 개는 rockyou 로 안 깨졌다(`john.log` — 로드까지만 남고 크랙 줄 없음). 룰 적용이나 다른 사전은 안 돌렸다.
> - relayd 의 `-a`/`-r`/`-i`/`-U` 액션은 열어보지 않았다. `-b up` 으로 목적을 달성해서 멈췄다.
> - Pico CMS 2.1.4 자체 취약점, `PicoOutput` 플러그인의 `formats: [content, raw, json]` 도 건드리지 않았다. `debug: true` + Twig 1.44.6 조합으로 SSTI 나 스택트레이스 유출을 노리는 경로가 있었을 수 있지만 확인 안 했다. `[가정]`

**처리:** CLAUDE.md §4 「본문에 남는 것 — 「관측 없음」 서술·유보」에 해당하므로 **`_PLAYBOOK` 이관이 아니라 노트 「관측 없음」 표에 3행으로 복원**했다. `_PLAYBOOK` 쪽 추가 조치는 불필요하다고 판단 — 시행착오가 아니라 미시도 목록이기 때문. 다만 **`PlanetExpress-playbook.md` 의 「검산」 절이 「1:1, 손실 없음」이라 적은 것은 사실이 아니므로** 관리자가 그 파일을 신뢰 근거로 쓰지 않도록 여기 남긴다.

그 외 6건은 전수 대조 결과 ④지우기 전 원문 인용·인과(「~해서」)·소요 시간(3분/8분)·`[가정]`·출처 경로가 모두 살아 있음. 제안 3의 원문은 `.bak` 781~832행 참조로 대체돼 있으나 `.bak` 이 보존돼 있으므로 복원 가능.

---

## 4. 구조·색인 검사

- **4항목 완비** — `Initial Access`(35행)·`Privilege Escalation`(415행) 각각 `Vulnerability Explanation:`·`Vulnerability Fix:`·`Severity:`·`Steps to reproduce the attack:` 넷 다 있음 ✅
- **두 `### Initial Access` 제목 상이** ✅ (「설정 파일 주석 유출로 docroot 확보 후 무인증 php-fpm 에 FastCGI 직타 RCE」 / 「FastCGI 직타」)
- **`Port Scan Results` 표** ✅ · **nmap raw PORT 행 보존** ✅ (`22/tcp   open  ssh` 형식 그대로 — `extract.py` `PORT_RE` 정상 매칭)
- **`ports: [22, 80, 9000]`** ✅ 9000 보존(리눅스이므로 고포트 제외 규칙 무관)
- **4항목 안 상대 참조** — 없음. 「Privilege Escalation 절」·「Service Enumeration 절」 등 **절 이름**으로만 참조 ✅
- **코드펜스** — 총 86개(짝수, 무태그 여는 펜스 **0**) ✅
- **`tech/*` 6개** — php-fpm·dirbust·suid·path-hijack·revshell·ssh-key. 전부 실사용. `tech_count: 6` 일치 ✅
- **`manual_cves: true` + `cves` 필드 없음** ✅ — CVE-2019-11043 은 「이 박스와 무관」 반증으로만 언급되므로 색인 제외가 맞음
- **색인 갱신 필요** — 행수 765→803, 본문 변경 있음. `refresh.ps1` 은 총괄 몫이므로 **실행하지 않음**
- **`_STATUS.md` 판정(참고)** — 완료 2/2(local.txt + proof.txt, 대화형 SSH 세션 원위치 `cat` 증거 있음). **직접 수정 안 함**

---

## 5. 근거 출처

- Kali 산출물 — `~/PG/PlanetExpress/` 전 62파일 중 대조에 쓴 것: `quick.log` `nmap.log` `svc.log` `gobuster.log` `config.yml` `installed.json` `picotest_out.html` `fcgi.py` `try1`~`try14` 로그 14종 `enum_www-data.log` `enum_relayd.log` `enum_relayd2.log` `enum_ps.log` `enum_root_shadow.log` `root_enum_fw.log` `hashes.txt` `john.log` `shell443.log` `shell80.log` `tcpdump_connectback.log` `payload_*.php` 16종 `cleanup_target.log` `proof_session_raw.txt` `proof_user.txt` `proof_root.txt` `writeup_notes.txt` `relayd.bin` `relayd.main.asm` `relayd.strings.txt`
- 볼트 — `파일보관\PG-PlanetExpress-pico-landing.png` · `PG-PlanetExpress-picotest-phpinfo.png`(직접 열어 대조)
- 볼트 — `03. PG\_backup\PlanetExpress.md.bak`(1003행) · `03. PG\_AUDIT\PlanetExpress-playbook.md`
- `~/.zsh_history` (3165행, `planet` 0건)
- 직접 실행한 명령
  - `ssh kali "grep -al 'kali㉿kali' ~/PG/PlanetExpress/*"` → 0건
  - `ssh kali "grep -ac planet ~/.zsh_history"` → 0
  - `nm relayd.bin | grep ' T main\.'` → 14행
  - `nm relayd.bin | grep -E ' T os/exec\.(Command|LookPath)$'` → 2행
  - `md5sum relayd.bin` → `63f7be5bc3bddda4783e84f7db1fedd0`
  - pyelftools 로 `relayd.bin` 의 `0x559578`/`0x5583db`/`0x5583d9` 직접 읽기 → `b'iptables'`/`b'-S'`/`b'-L'`
  - `cat -A proof_session_raw.txt` · `cat -A config.yml`
  - `python3` 로 `picotest_out.html` 태그 제거 후 지시자 값 추출
