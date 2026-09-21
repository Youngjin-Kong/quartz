---
tags:
  - type/audit
  - platform/pg
---
# Muddy — 적대적 검증 감사 (2026-08-26)

대상: `03. PG\Muddy.md` (895행 `.bak` → 345행 개작본 → **364행** 정정본)
검증자 = 정정자 동일. 타겟은 정지 상태 — 문서·Kali 산출물·스크린샷·포털 실측 대조 전용.
정정 전 백업: `03. PG\_backup\Muddy.md.bak2`(345행 개작본 원형)

## 0. 최종 판정

| 항목 | 판정 |
|---|---|
| **박스 진행도** | **완료 2/2** — 포털 전수 실측(`portal-진행도-실측-20260820.md` §1)에서 `n == m` 22개 목록에 Muddy 포함. 볼트·포털 일치 |
| **날조** | **0건.** 셸 이후 서술 전량의 출처가 «개작 전 노트 본문»으로 확인됨. 산출물 근거로 오귀속한 곳도 없었음 |
| **오귀속** | **1건** — `~/.zsh_history` 부재를 「대화형 셸로 작업해 안 남은 것」으로 [가정]. 인과가 뒤집혀 있었음(아래 §3) |
| **실측 파괴** | **0건.** 타겟 pty 프롬프트(`www-data@muddy:` · `root@muddy:~#`) 7줄 전량 보존 |
| **창작 프롬프트** | **5블록** — `┌──(kali㉿kali)-[~/PG/Muddy]` / `└─$`. 제거함(명령·출력은 한 바이트도 안 바꿈) |
| **이관 손실** | **5건** — `_AUDIT\Muddy-playbook.md` 에 C-1~C-5 로 복구. ④항목 누락 3건도 보완 |
| **구조** | 4항목 완비 · `Port Scan Results` 표 존재 · nmap raw 라인 보존(`PORT_RE` 정상) · 무태그 여는 펜스 0 |

---

## 1. 🔴 최우선 지목 — 셸 이후 서술 세 건의 출처 판정

Kali 산출물은 정찰 6개(2026-08-20 09:03~09:14)뿐이고 **셸 획득 이후 산출물 0건**이다. 지목된 셋을 각각 추적했다.

| 대상 | 판정 | 근거 |
|---|---|---|
| `Local.txt value:` `3f568bb1...` + `find / -name local.txt` 서술 | **개작 전 노트 §5 에서 이관.** 산출물·스크린샷 아님 → `근거부족` | `_backup\Muddy.md.bak` §5 「플래그 — user 플래그가 표준 위치에 없다」에 같은 값·같은 경로·같은 표가 존재 |
| `Proof.txt value:` `669fbcc1...` + `root@muddy:~#` 코드블록 | **개작 전 노트 §4-5 + §5 에서 이관**(두 블록을 하나로 이어붙임) → `근거부족` | `.bak` §4-5 가 `id; hostname` + `cat /root/proof.txt`, §5 가 `find` + `cat /var/www/local.txt`. 순서·바이트 그대로 |
| `Privilege Escalation – 크론 PATH 선두 /dev/shm 하이재킹` 전체 | **개작 전 노트 §4-2·§4-4 에서 이관** → `근거부족` | `.bak` §4-2 crontab 블록, §4-4 `cat netstat`·`chmod 777 netstat` 블록과 동일 |

**따라서 삭제 대상이 아니다.** 셋 다 원본 노트가 출처이고, 부재 증거의 등급 상한은 `근거부족`이다. 노트에는 등급 표기를 명시하는 방향으로만 정정했다.

**작성자의 귀속 표기는 정확했다.** 인용한 산출물 경로(`nmap.log`·`nmap_full.txt`·`gobuster_80.txt`·`ferox_80.txt`·`gobuster_8888.txt`)는 **전부 실재**하고 내용도 일치한다. 「노트 본문 값을 산출물 근거로 오귀속」한 사례는 이 노트에 없다.

### 1-1. 결말은 오히려 «양성 증거»가 있다 — 노트에 반영함

포털 전수 조회 실측에서 Muddy 는 `n == m` 인 **2/2 완료** 박스다. `proof.txt` 는 `/root/` 안이라 root 가 아니면 못 읽는다. 즉 **root 획득과 두 플래그 회수는 실제로 일어났다.** 재현 절차의 «각 줄»이 근거부족일 뿐 결말이 미확인인 것이 아니다. 이 구분을 본문에 넣었다.

⚠️ 단 플래그 값은 인스턴스마다 재생성되므로 재제출 불가 — 본문에 경고를 붙였다.

---

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `┌──(kali㉿kali)-[~/PG/Muddy]` 5블록 (hosts 등록 · XXE curl · john · WebDAV PUT/실행 · 리버스셸) | 이 박스는 비대화형 `ssh kali "..."` 작업이라 그 프롬프트가 화면에 뜬 적이 없음 — **창작**(CLAUDE.md §3) | 프롬프트 장식만 제거. 명령·출력은 한 바이트도 안 바꿈. 명령/출력 펜스를 분리해 「출력만 싣고 출처를 캡션으로」 형식에 맞춤 |
| `parser = make_parser()          # setFeature(feature_external_ges, False) 없음` | 「PyPI 원본」이라고 캡션 붙인 펜스 «안»에 한국어 주석 혼입 — 원문이 아님 | 주석 제거, 같은 내용을 펜스 «밖» 산문으로 |
| `/etc/apache2/passwd.dav              ← 같은 내용의 별개 사본` | `text` 펜스 안에 한국어 해설 혼입 | `←` 주석 제거, 펜스 앞 산문으로 이동 |
| `Python 2.7 expat 백엔드 기본값이 활성(True)` | 단정형 일반 지식인데 근거 없음 | **Kali 의 `python2` 로 직접 실행해 확인**(`getFeature(feature_external_ges)` → `1`, `file:///etc/hostname` 엔티티 실제 확장). 재현 명령과 출력을 본문에 추가 |
| `WordPress 5.7 + shapely 테마 + kali-forms 2.3.0` | 셋을 동급 실측처럼 단정. 실제로는 이름만 산출물에 있음 | `ferox_80.txt` 의 `themes/shapely/style.css`·`plugins/kali-forms/...` 히트 라인을 인용해 **이름은 실측으로 승격**, **세부 버전은 `근거부족`** 으로 분리 |
| `curl` 로도 443·808·908 은 빈 응답이라 오탐으로 처리 | curl 응답 저장 파일 없음 | `근거부족` 명시 + 「오탐 판정 자체는 두 스캔 불일치만으로 성립」으로 논리를 분리. `nmap_sv.txt`(5포트 한정 재스캔) 인용 추가 |
| `Ladon 이 WSGI 디스패처 기반이라 ... 불필요했던 것으로 판단` | 관측(0바이트)→결론 비약. 0바이트는 「히트 0건」과 「도중 중단」을 구분 못 함 | `[가정]` 강등 + 두 해석을 모두 적음. mtime 이 산출물 중 가장 늦다는 사실 추가 |
| `PyPI sdist 11종의 세 파일 ... 바이트 동일` | 새 깊이 기준의 **소스 고고학 과잉**. 대조 산출물도 없음 | 결론(0.9.30–0.9.40)만 남기고 축약, `근거부족` 표기 |
| `soap.py:645`(`soap11.py:541` 동일) | 행 번호 = 소스 고고학 | 행 번호 제거, 파일명만 |
| `일반 사용자 계정이 없어 플래그가 ... 있었음` | 이 박스의 `/etc/passwd` 내용은 저장된 것이 없음 — 관측 아님 | `[가정]` 강등 |
| `~/.zsh_history 에도 muddy 관련 명령이 0건(대화형 셸/직접 curl 로 작업해 파일로 안 남은 것으로 추정 — [가정])` | **인과가 뒤집혀 있음**(§3) | 「비대화형 SSH 명령은 zsh 히스토리에 안 남으므로 부재가 정보가 되지 못함」으로 정정 |
| Post-Exploitation 말미 `부재 증거로 실측을 지우지 않는다는 원칙에 따름` 등 | 노트 본문의 **작업 과정·감사 규율 서술**(CLAUDE.md §4 「나간다」) | 제거. `근거부족` 등급 표기(「남는다」)는 유지 |
| Post-Exploitation | 결말의 독립 근거가 누락 | 포털 2/2 실측 + `proof.txt` 위치 논거 추가(§1-1) |

**행수**: 345 → 364행.

---

## 3. 반증한 것 — 지적으로 올랐다가 확인 결과 «노트가 옳았거나 지적이 틀린» 것

1. **「두 `Initial Access` 제목이 다르다」는 결손이 아니다.** 실물 기준 `03. PG\Robust.md` 도 동일하다 — 32행에 긴 제목의 4항목 절, 85행에 짧은 제목의 워크스루 절. **집안 관례이므로 통일하지 않았다.** 지목 ⓕ 중 이 항목은 반증됨.

2. **작성자 보고 「기존 노트의 Kali 프롬프트를 그대로 보존함」은 판정이 틀렸다.** CLAUDE.md §3 의 「지우지 마라」는 **사람이 대화형 Kali 터미널에서 푼 레거시 노트**에만 적용된다. Muddy 의 `.bak` 은 레거시가 아니라 **2026-08-20 에이전트 산출물**이며(git 상 최초 등장이 개작 커밋 `efe8cef`, 그 이전 판 없음), 비대화형 `ssh` 에는 그 프롬프트가 존재할 수 없다. 작성자는 nmap 블록 1건만 교체하고 나머지 5블록을 「레거시 실측」으로 오분류했다.

3. **`~/.zsh_history` 0건은 「대화형으로 작업했다」의 근거가 아니라 정반대다.** zsh 는 **대화형 세션에서만** 히스토리를 쓴다. 노트의 [가정]은 인과가 뒤집혀 있었다. 보강 근거 — 히스토리에는 같은 시기 `192.168.248.215`·`.222`(다른 박스) 명령이 **14건** 남아 있어 히스토리 기능 자체는 정상 동작했다. 그럼에도 `muddy`·`192.168.248.161` 이 0건인 것은 **비대화형 작업의 예상 결과**다.

4. **초안 playbook 검산의 「§7(1~15) 전문 이관」·「2-5 등급표는 본문 잔류」는 둘 다 사실이 아니었다.** §7 은 11개만 흡수됐고 §7-4·§7-6·§7-13 이 어느 제안에도 없었으며, §2-5 등급표는 개작된 박스 노트 어디에도 남아 있지 않다.

5. **`gobuster_8888.txt`(0B)는 살아 있었다.** 지목 ⓔ 는 기우 — 노트 172행이 이미 「빈 파일이 아니라 기록」으로 인용 중이었다. 해석만 `[가정]` 으로 강등했다.

6. **작성자의 산출물 인용 경로는 전부 실재했다.** 「직전 웨이브의 오귀속 사례」가 여기서 반복됐다는 가설은 반증됐다.

7. **`ferox_80.txt` 는 노트를 반박하지 않고 오히려 보강했다.** `wp-json` 401·`/webdav` 401·shapely·kali-forms 전부 일치. `wp-login.php` 는 gobuster·ferox 양쪽에서 **302 → `/404`** 이고, `.bak` §6-② 가 「404면 그 순간 접는다」로 적었던 부정확을 개작본이 이미 302 로 고쳐놨다.

8. **스크린샷 2장은 본문과 일치한다.** 직접 열어 확인 — `PG-Muddy-ladon_8888.png` 의 서비스명 `muddy`, 인터페이스 6종, `checkout ( string uid )`, "Powered by Ladon for Python" 이 노트 표와 정확히 일치. `PG-Muddy-wordpress_80.png` 는 정상 렌더 화면(`Muddy | Found some mud? Call us!`)이며 오류 페이지가 아니다.

---

## 4. 삭제한 것 — 원문 전문 인용(되살릴 수 있게)

### 4-1. Kali 프롬프트 장식 5블록

명령·출력은 전부 남았고 **아래 장식 줄만** 제거했다.

```
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ echo '192.168.248.161 muddy.ugc muddy' | sudo tee -a /etc/hosts
```
```
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -s -X POST http://192.168.248.161:8888/muddy/soap11 \
```
```
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ john --format=md5crypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
```
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ printf '%s\n' '<?php system($_REQUEST["c"]); ?>' > /tmp/sh.php
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -T /tmp/sh.php --user administrant:sleepless http://192.168.248.161/webdav/sh.php
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -s --user administrant:sleepless 'http://192.168.248.161/webdav/sh.php?c=id'
```
```
┌──(kali㉿kali)-[~/PG/Muddy]
└─$ curl -sG --user administrant:sleepless \
```

### 4-2. 코드펜스 안 한국어 혼입 2건

```python
    parser = make_parser()          # setFeature(feature_external_ges, False) 없음
```
```text
/etc/apache2/passwd.dav              ← 같은 내용의 별개 사본
```

### 4-3. 소스 고고학 축약 — 삭제 전 원문

> PyPI sdist 11종의 세 파일(`wsgi_application.py`·`base.py`·`xmlrpc.py`)의 해당 행과 대조 — 0.9.30–0.9.40 구간에서만 세 파일 모두 일치. 세부 버전은 이 구간 안에서 바이트 동일이라 더 좁힐 수 없음(익스플로잇에 영향 없어 추가 조사 안 함).

### 4-4. 작업 과정 서술 — 삭제 전 원문

> 값·명령 자체를 반증할 근거는 없고 기존 노트의 Kali 프롬프트(`┌──(kali㉿kali)`)를 그대로 보존함 — 삭제하지 않되 등급은 **근거부족**.

> 근거부족(`Privilege Escalation` 절과 동일 사유) — 이 캡처를 뒷받침하는 `~/PG/Muddy/` 파일이 없음. 기존 노트의 타겟 pty 프롬프트를 그대로 보존함(부재 증거로 실측을 지우지 않는다는 원칙에 따름).

> `~/.zsh_history` 에도 muddy 관련 명령이 0건(대화형 셸/직접 curl 로 작업해 파일로 안 남은 것으로 추정 — [가정]).

**남긴 것**: 타겟 pty 프롬프트 7줄, 플래그 2개, 자격증명, 모든 명령·출력, `[가정]`·「관측 없음」·`근거부족` 표기.

---

## 5. 이관 손실 — `_AUDIT\Muddy-playbook.md` 정정

초안 9건이 895행에서 잘라낸 내용을 **11개 항목만** 흡수했다. 다음 5건을 C 절로 추가했다.

| 신규 | 복구한 원문 |
|---|---|
| C-1 | §7-4 — 금지 도구 ↔ 수동 대안 표(XXE 스캐너·`wpscan`·`davtest`·`linpeas`) |
| C-2 | §1 tip + §6-⑦ + §7-6 — **traceback 을 버전 지문으로 쓰는 기법**. 옛 노트가 「가장 재사용 가치 높은 기법」으로 지목한 것인데 초안에 없었음 |
| C-3 | §5 tip + §7-13 — `local.txt` 가 홈에 없을 때 `getent passwd \| grep -v nologin` 으로 판정 |
| C-4 | §3-3 warning — PUT 은 되는데 PHP 실행이 안 되는 3가지 원인 |
| C-5 | §2-5 — 엔드포인트 «파서별» 등급표(초안 검산이 「본문 잔류」라 했으나 실제로는 소실) |

**④「지우기 전 원문 인용」 누락 3건**(B-XXE·B-HASH·B-31)에 필드를 추가했다. A-1~A-6·D 는 절 지시자 형태이나 원문 전량이 `_backup\Muddy.md.bak`(895행)에 보존돼 복원 가능하므로 **손실 아님**으로 판정했다.

**A-6 전제에 경고를 붙였다** — 「헤드리스 캡처 4장이 전부 오류 페이지」의 실물이 `~/PG/Muddy/` 에 없고(`.png` 0개), 볼트에 남은 2장은 정상 렌더다. 기법 자체는 유효하나 사례는 `근거부족`으로 반영할 것.

---

## 6. 총괄 판단이 필요한 것 — 색인 파이프라인 (다른 노트에 파급)

**프론트매터가 본문과 모순된다.**

```
ports: [22, 25, 80, 111, 443, 808, 908, 8888]
services: [ccproxy-http, http, https, rpcbind, smtp, ssh, sun-answerbook]
```

본문은 443·808·908 을 **오탐**으로 판정하고 `Port Scan Results` 표에 5개만 적는다. 그런데 `extract.py` 의 `PORT_RE` 가 **raw nmap 블록에서 포트를 긁으므로** 오탐 포트까지 색인된다.

- CLAUDE.md §4·§8 은 **raw nmap 라인 보존을 요구**한다(지우면 `ports` 색인이 통째로 빈다). 즉 「raw 보존」과 「오탐 미색인」이 현재 도구로는 양립 불가다.
- `extract.py` 에 `manual_tags`·`manual_cves`·`manual_domain`·`manual_status` 는 있으나 **`manual_ports` 가 없다.**
- 프론트매터를 손으로 고쳐도 다음 `refresh.ps1` 이 되돌린다 — 그래서 **건드리지 않았다.**
- 파급 범위: 오탐 포트를 raw 로 인용한 모든 노트. 시험장 진입 질문이 「포트 N 에 뭐가 있었나」이므로 **색인 오염이 실제 비용**이다.

제안: `extract.py` 에 `manual_ports: true` 도입(다른 manual_* 와 동형). **공유 인프라라 총괄 몫이다 — 감사자가 손대지 않았다.**

---

## 7. 근거 출처

- **Kali 산출물**: `~/PG/Muddy/` 6개 전량 — `nmap.log`(2170B) · `nmap_full.txt`(498B) · `nmap_sv.txt`(1581B) · `gobuster_80.txt`(668B) · `gobuster_8888.txt`(**0B**) · `ferox_80.txt`(10140B). mtime 2026-08-20 09:03:22~09:14:59
- **git**: `git log --oneline -- "03. PG/Muddy.md"` → `efe8cef`, `076525b` 2건뿐. `git show efe8cef^:...` 는 `exists on disk, but not in efe8cef^` — **개작 커밋 이전 baseline 이 git 에 없음**. `.bak` 은 `076525b` 판의 굵게 제거본(diff 확인)
- **셸 히스토리**: `~/.zsh_history` — `muddy` 0건, `192.168.248.161` 0건, `192.168.248.215/.222`(타 박스) 14건
- **스크린샷**: 볼트 `파일보관\PG-Muddy-ladon_8888.png`(37423B) · `PG-Muddy-wordpress_80.png`(11961B), 둘 다 2026-08-20 09:11 — **직접 열어 본문과 대조함**
- **포털 실측**: `03. PG\_AUDIT\portal-진행도-실측-20260820.md` §1 — `n == m` 22개 목록에 Muddy 포함 = **2/2 완료**
- **직접 실행(Kali, 2026-08-26)**:
  - `python2 -c "...getFeature(feature_external_ges)"` → `1`
  - `xml.sax` 파서로 `<!ENTITY xxe SYSTEM "file:///etc/hostname">` 파싱 → `u'kali'` 확장 확인
- **비교 기준 노트**: `03. PG\Robust.md`(두 `Initial Access` 절 구조 확인), `03. PG\_backup\Muddy.md.bak`(895행)
- **도구 소스**: `_INDEX\_tools\extract.py` — `PORT_RE`(148행), `MANUAL_*_RE`(167~173행)
