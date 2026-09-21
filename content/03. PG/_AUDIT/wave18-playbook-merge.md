---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# 웨이브 18 — `_PLAYBOOK.md` 단독 반영 기록

- 일자: 2026-08-26 · 반영자: `writeup-auditor`(단독 기록자)
- 입력: `Twiggy-playbook.md`(9) · `Levram-playbook.md`(6) · `Osaka-playbook.md`(10 + 감사자 추가 3 + 정정 1) · `Clue-playbook.md`(11, 감사 보완 6건은 제안 본문에 이미 반영돼 있었음) = **제안 40건**
- 백업: `03. PG\_backup\_PLAYBOOK.md.bak14`
- 결과: **9176행 → 9806행(+630)** · 항목 **239 → 260(신규 21)** · 병합 **17곳** · 기각 **2건**

---

## 1. 신규 항목 21개

| 번호 | 제목 | 출처 제안 |
|---|---|---|
| A-1-31 | `Microsoft-HTTPAPI` 배너가 뜨는 포트에 디렉터리 브루트는 헛수고다 | Osaka 7 |
| A-1-32 | Apache 루트 403 을 「막혔다」로 읽지 않는다 | Clue 11ⓐ |
| A-1-33 | Kali `pip install` 이 거부된다 — PEP 668 | Clue 3 |
| A-2-33 | 원격 명령 실행에는 항상 절대경로 — CWD 는 «대상 프로세스»의 것이다 | Clue 8 |
| A-3-17 | Windows 셸인데 Linux 반사로 치고 있다 | Osaka 11 |
| A-4-18 | sudo NOPASSWD 대상이 GTFOBins 에 없다 — 「이 프로그램이 뭘 하는가」로 사고한다 | Clue 2 |
| A-6-14 | 내가 찾아본 곳에 없다 ≠ 존재하지 않는다 — 부재 증거를 존재 부정으로 승격시키지 않는다 | Levram 2 |
| B-1-52 | 문자열로 함수를 고르는 디스패처는 「막는 목록」인지 「통과시키는 목록」인지 본다 | Twiggy 4 |
| B-2-18 | nmap `SERVICE` 열은 «전송 계층» 이름일 수 있다 — 첫 검색어는 포트 번호 | Twiggy 3 |
| B-2-19 | 루프백에 열린 무인증 JMX 는 그 자체로 권한상승 후보다 | Clue 11ⓑ |
| B-3-16 | getcap 결과에서 노이즈와 후보를 가른다 — GTFOBins 원문이 정확히 그 최대치다 | Levram 3 |
| B-3-17 | `/etc/passwd` 에 심을 crypt 해시 만들기 — `openssl passwd` 가 가장 안전한 선택 | Twiggy 5 |
| B-48 | `SeDebugPrivilege` 는 그 자체로 SYSTEM 상승 경로다 | Osaka 5 |
| B-8-11 | FTP 는 `binary` 모드 — 크기 불일치는 CRLF 형과 truncation 형을 갈라서 진단한다 | Osaka 6 + 감사자 정정 |
| B-95 | nmap 이 못 알아보는 서비스 = 커스텀 바이너리 = 메모리 손상 후보 | Osaka 1 |
| B-96 | 포맷 스트링 릭으로 ASLR 우회 — 64KB 할당 단위로 베이스를 검산한다 | Osaka 2 |
| B-97 | `VirtualAlloc` ROP — `PUSHAD` 한 번으로 호출 프레임을 조립한다 | Osaka 3 |
| B-98 | 셸코드는 붙이기 전에 눈으로 검증한다 — badchar 통과는 파서 구조의 증거다 | Osaka 4 |
| B-99 | 셸코드 아키텍처를 확정하지 않고 만들면 즉사한다 | Osaka 12 |
| B-9-10 | 원샷 익스플로잇 — 던지기 직전 5항목 | Osaka 13 |
| B-9-11 | pwntools `recvuntil` 뒤 잔여 개행 — 인덱스가 하나씩 밀린다 | Osaka 9 |

**번호 배정 규칙** — 각 카테고리의 현재 최대 번호 다음. B-9 는 기존 4개(B-91~94)에 7개가 붙어 **B-99 다음이 B-9-10** 이 됨(9개 초과 시 하이픈 한 번 더, 플레이북 머리말 규칙).
**기존 항목의 제목·번호는 한 글자도 바꾸지 않았음** — 전부 append.

## 2. 병합 17곳 (전부 append, 기존 서술 삭제 0)

| 병합처 | 넣은 것 | 출처 |
|---|---|---|
| A-11 | 제품이 자기 화면에 찍는 버전 문자열은 위조 비용 0(Gerapy 푸터 26533B vs 26541B) | Levram 6 |
| A-12 | 비동기 작업 API 의 「예약됨 ≠ 실행됨」(`jid`) | Twiggy 1 |
| A-13 | CVE-2021-44142 설정 게이트 대조표 | Clue 1 |
| A-14 | ①Twiggy PoC 함정 4종 ②Levram 「예외의 발생 위치가 진단」 표 ③Clue `-h` argparse + `user:pass@host` | Twiggy 2 · Levram 1 · Clue 6 |
| A-31 | 목적지 IP 를 타겟 자신으로 적는 실수(증상이 egress 차단과 동일) | Clue 4 |
| A-65 | 타겟 IP 와 LHOST 가 «둘 다» 낡는 3-IP 전이 | Clue 5 |
| B-14 | 트래버설 `../` 넉넉히 넣기가 HTTP 밖(salt wheel)에서도 성립 | Twiggy 6 |
| B-1-27 | 플래그 파일도 읽기 후보이되 그렇게 읽으면 시험 0점 | Twiggy 7ⓐ |
| B-1-48 | 덮어쓰기 원시는 반드시 먼저 읽을 것(`/etc/passwd` 파괴) | Twiggy 7ⓑ |
| B-61 | 개인키 진단 순서 5단계 + Clue 의 틀린 가설 둘 | Clue 7 |
| B-82 | `certutil -urlcache -split` 은 404 여도 본문을 파일로 씀 | Osaka 8 |
| C-2 | Clue 극단 사례(`sudo -l` 이 즉시 보였는데 root 는 6일 뒤) | Clue 9 |
| C-3 | ①Clue `proof.txt` 미끼 2번째 사례 ②Twiggy 증거에 `ip a` 누락 ③Levram `email3.txt` `[가정]` | Clue 10 · Twiggy 7ⓓ · Levram 5 |
| D | Twiggy 시간 복기 + Levram 8분 복기 + Osaka 바이너리 익스플로잇 손절표 | Twiggy 8 · Levram 4 · Osaka 10 |
| E | `--exec-all` 스코프 경고(`tgt: '*'`) | Twiggy 9 |

## 3. 기각 2건

| 제안 | 사유 |
|---|---|
| Twiggy 7ⓒ 「셸 잡자마자 칠 5개(`id`·`sudo -l`·SUID·`getcap`·크론)」 | **완전 중복.** C-2 「리눅스 5줄 반사 — 각 줄이 «무엇을 묻는가»까지 외울 것」이 같은 5개를 주석과 함께 이미 싣고 있음(플레이북 8363행 부근) |
| Twiggy 7ⓐⓑ 를 「C 절 신규 항목」으로 두자는 배치안 | 배치만 기각. **내용은 B-1-27·B-1-48 로 병합** — 두 항목이 정확히 「임의 읽기/쓰기를 얻었을 때 무엇을」을 다루는 기존 카드임 |

Levram 제안 파일의 「검토 후 병합 없음」 4건(A-3-10 · B-6-12 · A-11 구체기법 · DRF 헤더)은 판단을 그대로 존중해 손대지 않았음.

## 4. 반증한 것 — 「신규」였으나 실제로는 기존이었던 것 3건

1. **Levram 제안 3 의 전반부는 기존.** 「capability 목록에서 노이즈를 거른다」의 원리는 **A-41 에 이미 있음** — 「SUID·capability 는 «목록»이 아니라 «배포판 기본과 다른 것»을 보는 것임」([[Fowsniff]] 사례, `getcap` 결과 셋이 전부 배포판 기본값). 제안은 「B-3 절에 capability 카드가 없다」만 확인하고 A-41 을 역검색하지 않았음.
   → **조치**: B-3-16 은 만들되 첫 줄을 「A-41 의 capability 판 실측」으로 명시해 원리 중복을 없애고, **genuinely new 한 부분**(6행 캡처 실측 · `cap_net_*` 규칙 · **GTFOBins 최소성**)에 무게를 실었음.
2. **Levram 제안 2 의 원리는 A-64 에 이미 한 줄 있음** — 「부재를 미실행의 근거로 쓰지 말 것 … `CLAUDE.md` §3 의 「부재 증거의 등급 상한은 `근거부족`」과 같은 선」. 제안은 A-61~A-6-11 을 훑었다고 적었으나 A-64 본문 안쪽은 못 봤음.
   → **조치**: 사건 서사와 「확인할 고정 출처 목록」이 A-64 에 없는 실질 증분이므로 **A-6-14 로 신규 유지**, A-63·A-64 상호 참조를 붙였음.
3. **Clue 제안 11ⓑ(JMX)의 절반은 기존** — A-44 가 이미 「[[Clue]] — 밖에서 6개, 안에서 11개. 필터링된 `0.0.0.0:1337` 과 **루프백 JMX** 가 거기 있었음」으로 인용 중이고, 포트포워딩으로 꺼내는 절차는 B-71 임.
   → **조치**: B-2-19 는 **「JMX = 무인증 관리 평면」이라는 «제품 지식»**에만 초점을 맞추고, 발견(A-44)과 포워딩(B-71)은 링크로 넘겼음.

## 5. 반증한 것 — 제안 본문의 사실 오류 3건

1. **Twiggy 제안 5: 「`mkpasswd`(`whois` 패키지, kali 에 없을 수 있음)」 — 이 Kali 에는 있음.**
   ```text
   $ dpkg -S /usr/bin/mkpasswd
   whois: /usr/bin/mkpasswd
   $ mkpasswd -m sha-512 testpw
   $6$81CinWVUVtOUlMo2$4jg7JEUYLk/DZXt3HhPMQSSM.U5a8J8B4Oz0zbx1Ed50j1Cf/hB9/ob1gA70vGaMQUGVtctJRE1h9tddzS.7Z1
   ```
   → B-3-17 본문에 **「whois 패키지. 이 Kali 에는 설치돼 있음」**으로 정정. 같은 절의 다른 두 주장은 실측으로 **확증**됨 — `openssl passwd` 기본값이 `$1$`(`$1$abcdefgh$D55xP04zxsKH/ekCiYAd4.`), Python 3.13.12 에서 `import crypt` → `ModuleNotFoundError`.
2. **Clue 제안 4 의 「순차 개선」 서사가 히스토리 순서와 어긋남.** 제안은 5줄을 「목적지 오타 → … → 성공한 형태」 순으로 배열했으나 `~/.zsh_history` 실제 행번호는 1064 · 1077 · **1117(올바른 형태)** · 1119 · 1120 임 — **올바른 형태가 틀린 형태보다 먼저** 나옴.
   → A-31 병합본에 **행번호를 그대로 달고** 「한 번 맞히고 다시 틀린 것이라 «점점 고쳐 나갔다»는 서사가 성립하지 않음」을 명시. 교훈이 오히려 강해짐(손이 기억하는 형태로 되돌아감).
3. **Twiggy 제안 9 의 「`_send_pub` 은 root key 조차 불필요」는 이 PoC 경로에서 확인되지 않음.** `pwn_exec_all(channel, root_key, cmd, master_ip, jid)` 이 `msg['key'] = root_key` 를 그대로 실음(서버측 `_send_pub` 의 인증 부재 여부는 별개 명제이고 소스를 확인하지 않았음).
   → E 절 병합본에서 그 주장을 **빼고**, 실측으로 확인된 것(`'tgt': '*'`, `'tgt_type': 'glob'`, `[!] Lester, is this what you want?` 경고)만 실었음.

## 6. 지시 중 반증한 것 1건

**「Osaka 의 FTP 확보 경로를 `[가정]` 으로 강등하는 것은 과잉이니 되돌려라」 — 되돌릴 대상이 없었음.**
`Osaka-playbook.md` 10건 + 감사자 추가 4건을 전수 확인한 결과 **FTP 확보 경로를 `[가정]` 으로 강등한 제안이 하나도 없음.** 제안 7 말미의 「성공/실패 여부 확정 불가」는 `smbclient -L`(공유 «목록» 나열, 전송 아님)에 붙은 것이고 이는 `~/.zsh_history` 2201·2643행에 명령만 있고 출력 산출물이 없다는 **정확한 서술**임 — 그대로 반영했음.

## 7. 출처 캡션 검증 — 가짜 적발 0건, 다만 3건을 강화

지시 ⑤에 따라 Clue 제안의 캡션을 하나씩 대조했음. `~/PG/Clue/` 에는 터미널 캡처가 **하나도 없음**(파일 9개 = `47799.py`·`49362.py`·`id_rsa`·`nmap.log` + 디렉터리 3개).

**가짜 캡션 0건.** 이 웨이브의 Clue 제안은 자기 한계를 정확히 적고 있었음 —
- 제안 1: 「이 시도는 `check_vulnerable.py` 1회 실행뿐이고 그 출력은 남아 있지 않음 … 이 박스에서 관측된 출력이 아님」 ✅
- 제안 6: 「박스 정지 후 Kali 에서 재현한 것 — 당시 캡처 아님」 ✅
- 제안 8: 「그 출력 자체는 기록에 없음(관측 없음, 재구성)」 ✅

**강화한 것 3건** — 반영본에서 검증 가능한 형태로 바꿈:
- `~/.zsh_history` 인용에 **행번호를 전부 부여**(Clue 1051~1056 · 1059 · 1072~1076 · 1096~1099 · 1106~1131 · 1135~1137 — 2026-08-26 전수 대조 완료)
- 제안 3 의 `/usr/lib/python3.12/EXTERNALLY-MANAGED` → **현재 Kali 는 3.13** 이므로 「파이썬 마이너 버전이 오르면 경로도 함께 바뀜」을 붙이고 재확인 일자를 명기
- 제안 1 의 `__pycache__` mtime 을 **clone 시각과 나란히** 실어 「3분 39초 뒤, 그 이후 활동 없음」까지 남김

## 8. 실측으로 확증한 것 (반영본에 실린 단정형 주장)

| 주장 | 확인 방법 | 결과 |
|---|---|---|
| `openssl passwd` 기본값 = `$1$` MD5-crypt | Kali 직접 실행 | ✅ |
| Python 3.13 에서 `crypt` 모듈 제거 | Kali 직접 실행 | ✅ `ModuleNotFoundError` |
| Osaka `ftp.exe` = `MS-DOS executable, MZ for MS-DOS` | `file` | ✅ 감사자 정정이 옳음 |
| `PE\0\0` 가 `e_lfanew`(`0x100`) 아닌 `0xff` 에 있음 | `xxd -s 0x3c` / `xxd -s 0xf8` | ✅ `e_lfanew=0x00000100`, `PE` 시그니처 `0xff` |
| Osaka 취약 서비스가 x86 | PE machine 필드 | ✅ `0x014c` = I386 |
| `ftp.exe` 55,971B | `ls -la` | ✅ |
| Twiggy PoC `--force` 가 죽은 옵션 | `exploit.py:294` | ✅ `default=False, action='store_false'` |
| Twiggy PoC `--run-checks` 가 방어자용 + 3군데 깨짐 | `exploit.py:325~337` | ✅ 주석 `# Assuming this check runs on the master itself` · `salt.utils.fopen` · 맨이름 `debug` · `pp()` (import 없음) |
| Twiggy PoC 성공 판정 `if rets.get('jid')` | `exploit.py:259` | ✅ |
| Twiggy `git log` 의 `eca6ba2 Rework version / vulnerability detection` | `git log` | ✅ |
| `--exec-all` 의 `tgt: '*'` · `tgt_type: 'glob'` | `exploit.py:262~285` | ✅ |
| Levram getcap 6행 | `파일보관\Pasted image 20260629102405.png` **직접 열람** | ✅ 제안의 표와 6행 전량 일치(헤더는 `Files with capabilities (limited to 50)`) |
| Osaka 47001 이 `Microsoft-HTTPAPI/2.0` | `~/PG/Osaka/nmap.log` 26~30행 | ✅ 5985 도 동일 |
| Osaka feroxbuster 시도 | `~/.zsh_history` 2148·2149 | ✅ **추가 발견** — 2744행에 «다른 박스»(`192.168.104.111:47001`)에 같은 반사를 또 씀. 굳어진 반사라는 근거가 하나 더 늘어 카드에 반영 |
| Clue pip 6줄 · ssh 자격증명 원문 · 49362 인자 4줄 · 절대경로 4줄 · id_rsa 10줄 · 3-IP 3줄 | `~/.zsh_history` | ✅ 전부 일치. **`ssh cassie:SecondBiteTheApple330@…` 는 1059행에 원문 그대로 존재** — 감사자의 「자격증명 값 개변」 지적이 옳았고 복원본이 정확함 |

## 9. 정책 충돌 해소 1건

**Levram 제안 2 의 「훑을 곳」 목록이 현행 `CLAUDE.md` §3 과 충돌.**
제안은 `~/.cache/pip`·`~/.npm`·`~/.gem`·`~/.cargo`·`/var/cache/apt`·브라우저/`curl` 캐시·`~/.bash_history`·tmux 스크롤백·mtime 을 「전부 훑으라」고 적었으나, 현행 규율은 **⛔ 파일시스템 헤매기 금지 + 고정 출처 목록**임(실측 근거: 그렇게 훑은 감사 3건이 판정을 하나도 못 바꿨음).

→ **A-6-14 반영본은 현행 정책으로 재작성**했음. ⓐ 「부재 증거의 등급 상한은 `근거부족`」은 그대로 살리고 ⓑ 「훑을 곳」을 **고정 출처 목록**(`~/PG/<박스>/` · `파일보관\` · `~/.zsh_history` · 포털 진행도 실측 · 레거시 한정 패키지 캐시)으로 교체하고 ⓒ **「목록 밖으로 나가지 말 것 · 없으면 「관측 없음」」**을 명시. Levram 을 구한 `~/.cache/pip` 는 목록 안에 있으므로 사건의 교훈은 손실 없이 보존됨.

## 10. 전수 검증 결과

```text
헤딩          299 → 320 · 손실 0
항목(#### N.) 239 → 260 · 신규 21 · 번호 중복 0 · 제목 중복 0
헤딩 제목의 | # [ ]    0건
코드펜스 ```  900개 · 짝 맞음
_PLAYBOOK 앵커 링크  볼트 전체 638건
  깨진 것 31건 — 전부 «작업 전에도» 깨져 있던 것(`_AUDIT\*` · `_WRITEUP-STANDARD.md` 의 `…`/`...` 자리표시자)
  이번 작업으로 «새로» 깨진 것  0건
박스 노트 앵커  Twiggy 3 · Levram 15 · Osaka 11 · Clue 5 — 전부 정상, 깨짐 0
행수          9176 → 9806 (+630)
```

**`## 관련` 앵커 추가** — Twiggy 3 · Levram 2 · Osaka 11(1줄에 B-9 계열 7개 묶음 포함) · Clue 5 = 링크 **21개**. 박스 노트는 `## 관련` 이외 어디도 건드리지 않았고 `<박스>-playbook.md` 경로는 남기지 않았음.

## 11. 총괄에 올릴 것

1. **색인 갱신 필요** — `_PLAYBOOK.md` 가 630행 늘고 박스 노트 4개의 `## 관련` 이 바뀜. `refresh.ps1` 은 공유 인프라라 실행하지 않았음(`CLAUDE.md` §5·§8).
2. **`_PLAYBOOK.md` 의 CVE 색인 오염 — 판단 요청.** B-2-18 에 **`CVE-2014-9721`(zmtp 검색 오탐, 「무관」 명시)**을 실었음. `_PLAYBOOK.md` 에는 `manual_cves` 선언이 없어 `extract.py` 가 이 번호를 긁어감. 다만 **선례가 이미 있고**(A-13 의 `CVE-2021-43326` = 「전혀 다른 제품」), `manual_cves: true` 를 걸면 플레이북의 CVE 색인이 통째로 비므로 **혼자 결정하지 않고 올림.**
3. **`_STATUS.md` 는 손대지 않았음**(§6 — `pg-line-manager` 단독 기록). 이 웨이브는 노트 상태를 바꾸지 않는 플레이북 반영 작업이므로 갱신 대상 없음.
