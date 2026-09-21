---
tags:
  - type/audit
  - platform/pen200
type: audit
platform: pen200
---

# PEN-200 AD 인증·패스워드공격·지속성 독해감사 (G2)

담당 16개 절 — 22.3.5 · 22.4 · 22.4.1 · 22.4.2 · 22.5 · 23 · 23.1 · 23.1.1 · 23.1.2 · 23.1.3 · 23.2 · 23.2.1 · 24.2 · 24.2.1 · 24.2.2 · 24.3

방법 — 절마다 원문 `src\<번호> <영문제목>.md` 전문과 노트 전문을 나란히 읽고 산문 단락을 대조. 코드펜스는 게이트 검증 완료분이라 대조·수정 대상에서 제외.

## 결함

| 절 | 유형 | 원문 근거 | 고친 내용 |
|---|---|---|---|
| 22.3.5 | 창작 | Listing 834 의 FILES04.corp.com 행 8개 — `ADMIN$`·`C`·`C$`·`docshare`·`IPC$`·`Tools`·`Users`·`Windows`. `C` 와 `Windows` 는 Remark 가 비고 Type 0 으로, 노트가 이미 비기본으로 분류한 `docshare`·`Tools`·`Users` 와 «같은 서명». 원문은 기본/비기본을 열거하지 않음 — 이 목록 자체가 노트 창작이고 그 안에서 두 개가 누락됨 | 비기본 공유 목록에 `C`·`Windows` 추가. `(backup·docshare·Tools·Users·sharing)` → `(backup·C·docshare·Tools·Users·Windows·sharing)` |

## 무결 판정

22.4 · 22.4.1 · 22.4.2 · 22.5 · 23 · 23.1 · 23.1.1 · 23.1.2 · 23.1.3 · 23.2 · 23.2.1 · 24.2 · 24.2.1 · 24.2.2 · 24.3

## 중점 대조 항목의 실측 결과

관리자가 「순서와 주체가 뒤집히기 쉬운 구간」으로 지목한 항목의 대조 결과임.

**23.1.1 NTLM 단계 수 — 원문 `seven steps`, 노트 「일곱 단계」. 일치함.**
원문 1행 `The NTLM authentication protocol consists of seven steps`. 노트 17행 「프로토콜은 일곱 단계로 구성됨」. 관리자가 우려한 「6단계」 오염은 노트에 없음. 각 단계의 주체도 원문과 1:1 일치 — ①클라이언트가 해시 계산 ②클라이언트→서버 사용자명 ③서버→클라이언트 nonce ④클라이언트→서버 response ⑤서버→DC 전달(response+사용자명+nonce) ⑥DC 가 자기 해시로 nonce 를 암호화해 비교 ⑦일치 시 성공.

**23.1.2 Kerberos** — AS-REQ→AS-REP→TGS-REQ→TGS-REP→AP-REQ 순서 일치. 암호화 주체 갈림 정확 — 세션 키는 사용자 패스워드 해시로, TGT 는 `krbtgt` NTLM 해시로, TGS-REP 의 서비스명·세션 키는 TGT 생성 때의 원래 세션 키로, 서비스 티켓은 서비스 계정 패스워드 해시로. 「NTLM 은 클라이언트가 애플리케이션 서버와 시작 / Kerberos 는 KDC 역할의 DC 와 먼저 시작」이라는 원문의 핵심 대비가 노트 17행에 살아 있음. TGT 유효기간 10시간, KDC 3중 검사(타임스탬프·사용자명·클라이언트 IP) 일치.

**23.1.3 캐시 자격증명** — LSASS 메모리 저장, SYSTEM/로컬관리자 권한 요구, `sekurlsa::logonpasswords`(로그온 사용자 자격증명) 대 `sekurlsa::tickets`(TGT·서비스 티켓) 구분, WDigest 활성 시 평문 노출, 기능 수준별 NTLM/SHA-1 가용성 — 전부 원문과 일치.

**23.2.1 패스워드 공격** — `net accounts` 출력의 Lockout threshold 5 → 안전 시도 4회, observation window 30분, 24시간 192회 산정 모두 원문 그대로. 스프레이 3종(LDAP/ADSI · SMB/crackmapexec · TGT/kerbrute) 순서·특징 일치. `kinit` 계열의 「AS-REQ 만 보내고 응답을 봐 UDP 프레임 두 개로 판정」 정확.

**24.2.1 Golden Ticket** — 필요한 것은 `krbtgt` 계정의 NTLM 해시 + 도메인 SID. Silver(TGS 위조 → 특정 서비스) 대 Golden(TGT 위조 → 도메인 전체) 대비 정확. `mimikatz` 인자 의미 뒤바뀜 없음 — `/sid` 도메인 SID, `/krbtgt` (`/rc4` 아님) krbtgt 해시, `/user` 실재 계정, `/ptt` 현재 세션 주입. 기본값 User Id 500 · Groups Id 최상위 그룹군 서술 정확. 2022년 7월 이후 실재 계정 요구, IP 지정 시 NTLM 강제되어 실패하는 함정도 원문대로.

**24.2.2 섀도 복사본** — `vshadow -nw -p` → device name 기록 → `copy` 로 `ntds.dit` 회수 → `reg save hklm\system` → `secretsdump -ntds -system LOCAL` 순서 일치. `⚠️ 교재 오류`(해시 줄 끝 `</div>`) 표시는 관리자 확인분이라 재검증하지 않음.

**22.4.1/22.4.2 SharpHound/BloodHound** — 「수집=SharpHound, 분석·정리·표현=BloodHound」 역할 구분 원문대로. 실행 함수가 `Invoke-BloodHound` 라 직관에 어긋난다는 원문 지적 보존. `-CollectionMethod All` = 로컬 그룹 정책 제외 전 방식 수행, JSON→zip 자동 묶음, 결과가 실행 계정(stephanie) 관점 스냅숏이라는 전제 모두 일치.

## 반증한 것 — 지적했다가 원문 재확인으로 철회

착수 시 결함 후보로 잡았다가 원문을 되짚어 «정당»으로 판정한 것들임. 고치지 않았다.

1. **23.2.1·22.4.1 의 「⚠️ 아래 블록은 PDF 추출 과정에서 줄이 접혀 있음」 주석 3건** — 원문에 없는 문장이라 창작으로 볼 뻔했으나, 지목한 접힘이 «전부 실재»함. 23.2.1 의 `$domainObj =` / `[System.DirectoryServices...]` 분리, `--` / `continue-on-success` 분리, `kerberos::golden` 의 패스워드 인자 분리, 22.4.1 의 `-` / `OutputDirectory` 분리를 원문 블록에서 직접 확인함. 시험장에서 그대로 복붙하면 깨지는 지점을 짚은 검증 가능한 사실이라 SPEC §3-A 의 정정 표시와 같은 성격임.
2. **24.2.2 17행 「AD DS 가 파일을 잠근다」** — 원문에 없는 배경 지식이라 창작 후보였으나, 노트가 이미 `[가정]` 을 달고 **「이 절의 원문에 없는 배경 지식임」을 본문에 명시**하고 있음. 규율이 요구하는 강등이 이미 적용된 상태라 손댈 것이 없음.
3. **24.2.1 70행 「`/ptt` 는 만든 즉시 현재 세션에 주입하라는 뜻」** — 원문 산문에 `/ptt` 설명이 없어 창작으로 볼 뻔했으나, 같은 절 Listing 918 출력에 `-> Ticket : ** Pass The Ticket **` 와 `successfully submitted for current session` 이 «그대로» 찍혀 있음. 노트에 실린 블록에서 직접 읽히는 것이라 창작 아님.
4. **24.2 의 「이 단위가 다루는 것」 목록** — 원문 말미가 `In the next Learning Unit, we are going to explore how golden ticket and shadow copy techniques...` 라 「다음 단위」로 적어야 하는지 검토했으나, **원문 자체가 모순**임 — 같은 문서 서두의 Learning Objectives 가 golden ticket·shadow copy 를 «이» 단위 목표로 열거하고, 실제 절 번호도 24.2.1·24.2.2 로 24.2 하위임. 노트가 Objectives 쪽을 따른 것이 옳음.

## 관측 사항 — 수정하지 않음

**「자격 증명」과 「자격증명」의 띄어쓰기가 절마다 갈림.** 23.1.3·23.2.1·23 은 띄고, 22.3.5·22.4.2·24.2 는 붙임. 다만 ①한국어 표기 흔들림이지 «다른 한국어 용어»를 쓴 것이 아니고 ②23.1.3 은 H1 제목(`titles_ko.json` 확정분)이 「캐시된 AD 자격 증명」이라 절별 강제가 있으며 ③담당 16개 절 밖으로 파급되는 사안임. 이번 감사 범위인 「뜻이 틀렸는가」에 해당하지 않아 손대지 않고 관리자에 보고함.

## 게이트 재실행 (챕터 22~24)

산문 1행만 고쳤으므로 코드블록 계열 게이트는 회귀 없음이 예상됐고 실측도 그러함.

```
strictcheck.py 22 24 → 노트 코드블록 159개 검사 · 줄 단위 비정렬 0개
audit2.py      22 24 → 합성 0 · 소실 0 · 거짓 「추출 손상」 서술 0
covercheck.py  22 24 → 판정 근거 줄 53개 검사 · 소실 0
verify.py      22 24 → 완료 42 / 전체 42 · 미생성 0 · 결함 0
```
