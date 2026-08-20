---
tags:
  - type/index
  - platform/pg
---
# PG Practice 전수 writeup — 진행현황

> [!abstract] 목표
> **OffSec Proving Grounds Practice의 283개 랩 전부를 풀고 writeup을 남긴다.**
> 포털: https://portal.offsec.com/labs/practice-2
> writeup 저장 위치: `03. PG/<박스명>.md`

## 현황 (2026-08-20 기준)

| 상태 | 개수 | 비율 |
|---|---:|---:|
| ✅ 완료 (플래그 전부) | 45 | 15.9% |
| 🟡 부분 완료 | 5 | 1.8% |
| ⬜ 미착수 | 233 | 82.3% |
| **합계** | **283** | |

난이도 분포: **Fundamental** 43개 · **Intermediate** 209개 · **Advanced** 31개

## ✅ 완료 (45)

| 박스 | 난이도 | 플래그 | writeup |
|---|---|---|---|
| Algernon | Fundamental | 1/1 | [[Algernon]] |
| Astronaut | Fundamental | 1/1 | [[Astronaut]] |
| Bratarina | Fundamental | 1/1 | [[Bratarina]] |
| Breakout | Intermediate | 2/2 | [[Breakout]] |
| Butch | Intermediate | 2/2 | [[Butch]] |
| ClamAV | Fundamental | 1/1 | [[ClamAV]] |
| Clue | Advanced | 2/2 | [[Clue]] |
| Cockpit | Intermediate | 2/2 | [[Cockpit]] |
| Codo | Fundamental | 1/1 | [[Codo]] |
| Crane | Intermediate | 2/2 | [[Crane]] |
| Exfiltrated | Fundamental | 2/2 | [[Exfiltrated]] |
| Exghost | Fundamental | 2/2 | [[Exghost]] |
| Fanatastic | Fundamental | 2/2 | [[Fanatastic]] |
| Fikklish | Fundamental | 2/2 | [[Fikklish]] |
| Flimsy | Fundamental | 2/2 | [[Flimsy]] |
| Flu | Intermediate | 2/2 | [[Flu]] |
| Fowsniff | Fundamental | 2/2 | [[Fowsniff]] |
| Hawat | Fundamental | 1/1 | [[Hawat]] |
| Heist | Advanced | 2/2 | [[Heist]] |
| Hub | Fundamental | 1/1 | [[Hub]] |
| Internal | Fundamental | 1/1 | [[Internal]] |
| Kevin | Fundamental | 1/1 | [[Kevin]] |
| LazySysAdmin | Fundamental | 2/2 | [[LazySysAdmin]] |
| Levram | Fundamental | 2/2 | [[Levram]] |
| Mice | Fundamental | 2/2 | [[Mice]] |
| MiddlewareBypass | Intermediate | 1/1 | [[MiddlewareBypass]] |
| Muddy | Fundamental | 2/2 | [[Muddy]] |
| Osaka | Advanced | 2/2 | [[Osaka]] |
| Outdated | Fundamental | 2/2 | [[Outdated]] |
| Pebbles | Fundamental | 1/1 | [[Pebbles]] |
| Pelican | Intermediate | 2/2 | [[Pelican]] |
| PlanetExpress | Fundamental | 2/2 | [[PlanetExpress]] |
| plum | Intermediate | 2/2 | [[plum]] |
| PwnLab | Fundamental | 2/2 | [[PwnLab]] |
| pyLoader | Intermediate | 1/1 | [[pyLoader]] |
| Resourced | Intermediate | 2/2 | [[Resourced]] |
| RubyDome | Fundamental | 2/2 | [[RubyDome]] |
| Scarlet | Intermediate | 2/2 | [[Scarlet]] |
| Sorcerer | Intermediate | 2/2 | [[Sorcerer]] |
| Squid | Fundamental | 2/2 | [[Squid]] |
| Twiggy | Fundamental | 1/1 | [[Twiggy]] |
| Vault | Advanced | 2/2 | [[Vault]] |
| Wheels | Fundamental | 2/2 | [[Wheels]] |
| Wombo | Fundamental | 1/1 | [[Wombo]] |
| Zipper | Advanced | 2/2 | [[Zipper]] |

## 🟡 부분 완료 (5) — 우선 처리 대상

| 박스 | 난이도 | 플래그 | writeup |
|---|---|---|---|
| Hutch | Intermediate | 1/2 | [[Hutch]] |
| Cobbles | Fundamental | 1/2 | [[Cobbles]] |
| Jacko | Intermediate | 1/2 | [[Jacko]] |
| Monster | Fundamental | 1/2 | [[Monster]] |
| Nagoya | Advanced | 1/2 | [[Nagoya]] |

## ⬜ 미착수 (233)

체크박스를 채우며 진행한다. `노트O` = 볼트에 기존 노트가 이미 있음(참고 자료로 활용 가능).

### Fundamental (13)

- [ ] Assignment `0/2`
- [ ] BossPlayersCTF `0/2`
- [ ] Compromised `0/2`
- [ ] Covfefe `0/2`
- [ ] CVE-2023-46818 `0/1`
- [ ] Detection `0/1`
- [ ] Fractal `0/2`
- [ ] GLPI `0/2`
- [ ] Graph `0/2`
- [ ] Interface `0/1`
- [ ] JISCTF `0/2`
- [ ] Robust `0/2`
- [ ] SunsetTwilight `0/2`

### Intermediate (195)

- [ ] Access `0/2`  ← 노트O
- [ ] AdminPanel `0/1`
- [ ] Air `0/2`
- [ ] Apex `0/2`
- [ ] Arin `0/2`
- [ ] AuthBy `0/2`
- [ ] BackupBuddy `0/2`
- [ ] Banzai `0/2`
- [ ] Billyboss `0/2`
- [ ] Bitest `0/2`
- [ ] BitForge `0/2`
- [ ] Boolean `0/2`
- [ ] Born2Root `0/2`
- [ ] Bossline `0/2`
- [ ] Bottleneck `0/2`
- [ ] Bottleup `0/2`
- [ ] BrokenGallery `0/2`
- [ ] bullyBox `0/1`
- [ ] cacti `0/2`
- [ ] carryover `0/2`
- [ ] Cassios `0/2`
- [ ] Catto `0/2`
- [ ] Charlotte `0/2`
- [ ] ChatRoom `0/2`
- [ ] Chatty `0/2`
- [ ] Clipper `0/2`
- [ ] Clone `0/1`
- [ ] Cobweb `0/2`
- [ ] Confusion `0/2`
- [ ] Convertex `0/2`
- [ ] Craft `0/2`
- [ ] Cryptkeeper `0/2`
- [ ] CVE-2023-33831 `0/1`
- [ ] CVE-2023-40582 `0/1`
- [ ] CVE-2023-6019 `0/1`
- [ ] CVE-2024-12029 `0/1`
- [ ] CVE-2024-25180 `0/1`
- [ ] CVE-2024-27292 `0/1`
- [ ] CVE-2024-32880 `0/1`
- [ ] CVE-2024-35374 `0/1`
- [ ] CVE-2024-36401_Attack `0/1`
- [ ] CVE-2024-3673 `0/2`
- [ ] CVE-2024-39914 `0/1`
- [ ] CVE-2024-40453 `0/1`
- [ ] CVE-2024-46507_Attack `0/1`
- [ ] CVE-2024-46986_Attack `0/1`
- [ ] CVE-2024-48061 `0/1`
- [ ] CVE-2024-48573 `0/1`
- [ ] CVE-2024-48914_Attack `0/1`
- [ ] CVE-2024-51482 `0/1`
- [ ] CVE-2024-5334 `0/1`
- [ ] CVE-2024-55415 `0/1`
- [ ] CVE-2024-55963 `0/1`
- [ ] CVE-2024-56145 `0/1`
- [ ] CVE-2025-10952 `0/1`  ← 노트O
- [ ] CVE-2025-21624 `0/1`
- [ ] CVE-2025-27136 `0/1`
- [ ] CVE-2025-27520 `0/1`
- [ ] CVE-2025-27636 `0/1`
- [ ] CVE-2025-2945_attack `0/1`
- [ ] CVE-2025-30208 `0/1`
- [ ] CVE-2025-31131 `0/1`
- [ ] CVE-2025-32101_Attack `0/1`
- [ ] CVE-2025-32375 `0/1`
- [ ] CVE-2025-50817 `0/2`
- [ ] CVE-2025-50946 `0/1`
- [ ] CVE-2025-5880_Attack `0/1`
- [ ] Dawn2 `0/2`
- [ ] Dawn3 `0/2`
- [ ] DC5 `0/2`
- [ ] Deception `0/2`
- [ ] Depreciated `0/2`
- [ ] DepthB2R `0/2`
- [ ] dev_working `0/2`
- [ ] DevArmor `0/2`
- [ ] Devnal `0/2`
- [ ] Dibble `0/2`
- [ ] DocsGPT `0/1`
- [ ] DVR4 `0/2`
- [ ] Educated `0/2`
- [ ] ERP `0/2`
- [ ] Extplorer `0/2`
- [ ] Fail `0/2`
- [ ] filebrowser `0/2`
- [ ] Fired `0/2`
- [ ] Fish `0/2`
- [ ] Five86.2 `0/2`
- [ ] Flasky `0/2`
- [ ] flink `0/2`
- [ ] flow `0/2`
- [ ] Forward `0/2`
- [ ] Fuxa `0/1`
- [ ] G00g `0/2`
- [ ] GourmetDelight `0/2`
- [ ] Groove `0/1`
- [ ] GRPC `0/2`
- [ ] Hallucination `0/2`
- [ ] Hasura `0/2`
- [ ] HAWordy `0/2`
- [ ] Hepet `0/2`
- [ ] Hetemit `0/2`
- [ ] Hunit `0/2`
- [ ] Illusion `0/2`
- [ ] image `0/2`
- [ ] Infilo `0/1`
- [ ] InvokeAI_RCE `0/1`
- [ ] Jordak `0/2`
- [ ] Keights `0/2`
- [ ] KeyVault `0/2`
- [ ] Kyoto `0/2`
- [ ] LaVita `0/2`
- [ ] law `0/2`
- [ ] Leaked `0/1`
- [ ] Leyla `0/2`
- [ ] Lunar `0/2`
- [ ] Mailserver_phase2 `-`  🔒
- [ ] Malbec `0/2`
- [ ] Mantis `0/2`
- [ ] Maria `0/2`
- [ ] Markers `0/2`
- [ ] Marketing `0/2`
- [ ] Marshalled `0/2`
- [ ] Matrimony `0/2`
- [ ] Matt `0/2`
- [ ] MediTrack `0/2`
- [ ] Medjed `0/2`
- [ ] midnight `0/2`
- [ ] Muon_phase2 `-`  🔒
- [ ] MyForum `0/2`
- [ ] MZEEAV `0/2`
- [ ] Nappa `0/2`
- [ ] nara `0/2`
- [ ] Needle `0/1`
- [ ] Nibbles `0/2`
- [ ] Nickel `0/2`
- [ ] Nukem `0/2`
- [ ] NullByte `0/2`
- [ ] Ochima `0/2`
- [ ] Orbiton_phase2 `-`  🔒
- [ ] Panic `0/2`
- [ ] Passport `0/2`
- [ ] Pathway `0/2`
- [ ] PayDay `0/2`
- [ ] pc `0/1`
- [ ] Pier `0/1`
- [ ] Pipe `0/1`
- [ ] Postfish `0/2`
- [ ] Precision `0/1`
- [ ] press `0/1`
- [ ] ProStore `0/2`
- [ ] Quackerjack `0/2`
- [ ] Rayeih `0/2`
- [ ] Readys `0/2`
- [ ] Reconstruction `0/2`
- [ ] Rookie Mistake `0/2`
- [ ] Roquefort `0/2`
- [ ] RPC1 `0/2`
- [ ] RussianDolls `0/2`
- [ ] Scarecrow1.1 `0/2`
- [ ] Scrutiny `0/2`
- [ ] Sea `0/2`
- [ ] Serialrunning `0/2`
- [ ] Shenzi `0/2`
- [ ] Shiftdel `0/2`
- [ ] Silicon `0/2`
- [ ] SkillForge `0/2`
- [ ] Slort `0/2`  ← 노트O
- [ ] Snookums `0/2`
- [ ] Sona `0/2`
- [ ] Source `0/2`
- [ ] Spaghetti `0/2`
- [ ] SpiderSociety `0/2`
- [ ] Splodge `0/2`
- [ ] SpringAuth_attack `0/2`
- [ ] SPX `0/2`
- [ ] sshcontrol `0/2`
- [ ] SugarVale `0/2`
- [ ] Surf `0/2`
- [ ] Sybaris `0/2`
- [ ] Symbolic `0/2`
- [ ] Tux `0/2`
- [ ] UC404 `0/2`
- [ ] USV2017 `0/2`
- [ ] Validator `0/2`
- [ ] Vanity `0/2`
- [ ] vmdak `0/2`
- [ ] VoIP `0/2`
- [ ] Walla `0/2`
- [ ] WallpaperHub `0/2`
- [ ] workaholic `0/2`
- [ ] XposedAPI `0/2`
- [ ] Y0usef `0/2`
- [ ] Zab `0/2`
- [ ] ZenPhoto `0/2`
- [ ] Zino `0/2`

### Advanced (25)

- [ ] BadCorp `0/2`
- [ ] BlackGate `0/2`
- [ ] Bunyip `0/2`
- [ ] CookieCutter `0/2`
- [ ] Craft2 `0/2`
- [ ] Deployer `0/2`
- [ ] Develop `0/2`
- [ ] Emporium `0/2`
- [ ] Escape `0/2`
- [ ] Flower `0/2`
- [ ] Glider `0/2`
- [ ] Gradle `0/2`
- [ ] Injecto `0/2`
- [ ] Megavolt `0/2`
- [ ] Peppo `0/2`
- [ ] Phobos `0/2`
- [ ] Powergrid `0/2`
- [ ] Shifty `0/2`
- [ ] Sirol `0/2`
- [ ] Synapse `0/2`
- [ ] Ted `0/2`
- [ ] Thor `0/2`
- [ ] Tico `0/2`
- [ ] Upsploit `0/2`
- [ ] Vector `0/2`

## 작업 파이프라인

박스마다 동일하게 반복한다:

1. **기동** — 포털에서 Start (이전 머신은 Accept로 자동 정지)
2. **브리핑 확인** — `View Briefing`은 점수에 영향 없음. `Show Walkthrough`는 누르지 않는다
3. **팀 투입** — 정찰(읽기전용) + 침투(풀체인) 병렬. pcap·바이너리 등이 끼면 전문 담당 추가
4. **교차 검증** — 하위 에이전트 보고를 그대로 믿지 않는다. 살아 있는 셸에서 플래그를 직접 `cat`으로 재확인
5. **제출** — 검증된 값만 포털에 입력
6. **writeup 작성** — `03. PG/<박스명>.md`
7. **트래커 갱신** — 이 파일의 체크박스와 현황표

## writeup 형식

```
> [!info] 상단 요약 — 타겟/OS/난이도/플래그 수 + 경로 한 줄
### Nmap                 터미널 원문 그대로
### 열거 / 버전 판정      근거와 출처 명시
### Foothold             명령 전문 + 원문 출력
### Privesc              경로가 둘이면 둘 다
### 플래그               표
## OSCP 관점 정리        함정·교훈 번호 목록  ← 가장 중요
## 남긴 흔적             랩 정리용
## 관련 노트             [[박스명]] 상호 링크
```

## 누적된 교훈 (박스 간 공통 패턴)

1. **응답이 성공을 뜻하지 않는다** — 타임아웃·`HTTP=000`·`200`+로그인페이지·무응답 전부 성공 사례였다. **리스너와 부작용을 봐라.** ([[Crane]] [[RubyDome]] [[Astronaut]] [[Exghost]]) · **권한상승 판**: 실패한 익스플로잇도 셸 프롬프트를 띄운다. 돌린 직후 **`id`로 판정**하라 ([[plum]] — exim 익스플로잇이 실패했는데 셸이 떠서 성공처럼 보였다)
2. **버전은 출처가 다른 근거 2개 이상 교차로 확정** — 근거 3개가 같은 파일에서 나왔으면 그건 근거 1개다. ([[Hub]]에서 실패 → [[Levram]] [[RubyDome]] [[Astronaut]]에서 교정)
3. **워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다** — 30만 건 완주하고 0건. 다른 채널(백업·캡처·로그)에서 얻어야 한다. ([[Exghost]])
4. **`sudo -l`이 좁아도 대상 파일 권한을 확인** — 내가 쓸 수 있으면 사실상 `NOPASSWD: ALL`이다. ([[RubyDome]])
5. **특권은 "없는" 게 아니라 "박탈된" 것일 수 있다** — `LOCAL SERVICE`는 FullPowers로 되찾는다. ([[Squid]])
6. **페이로드는 base64로 감싼다** — 다중 인용 계층을 한 번에 통과한다.
7. **파일 전송 후 `ls`/`md5sum`으로 확인** — 유명 도구는 파일명만으로 삭제된다. ([[Squid]] [[Exghost]])
8. **익스플로잇을 던지기 전에 버전을 확인하고 취약 범위와 대조한다** — 10초짜리 확인(`--version`·`dpkg -l`·배너)이 수십 분을 아낀다. 버전 정보는 **메일 헤더·HTTP 헤더·에러 페이지** 같은 예상 밖의 곳에 있다. ([[plum]] — SUID `exim4`를 보고 CVE-2019-10149(4.87–4.91)를 확보했으나 타겟은 **4.94.2**로 애초에 취약하지 않았다) · **searchsploit 제목의 범위를 믿지 말고 파일 헤더를 열어라** ([[Flu]] — 제목 `Confluence < 8.5.3`이 실제로는 **8.0 이상 전용**이었다. `head -10` 이면 반증된다) · **버전이 맞아도 설정 게이트가 있다** ([[Clue]] — Samba 4.9.5는 CVE-2021-44142 범위 안이었으나 `vfs_fruit`+`fruit:metadata=netatalk`+실재 공유가 전부 필요했다)
9. **공개 익스플로잇의 CVE 표기를 검증하라** — 저자가 붙인 참조일 뿐 벤더·NVD 판정이 아니다. **"어느 파일 / 어느 기능 / 어느 권한"** 이 내가 한 것과 일치하는지 NVD 원문과 대조한다. ([[plum]] — README는 CVE-2022-25018을 인용하지만 실제 악용 경로는 CVE-2024-48138이었다 · [[Flu]] — `through_the_wire.py` 헤더는 `CVE-2022-26123`, 배너는 `CVE-2022-26134`로 **파일 안에서 모순**)
10. **⚠️ 플래그는 반드시 «대화형 셸»에서 읽는다 — 웹셸 취득은 OSCP 시험에서 0점이다.** 규정 원문: *"this includes any type of web-based shell"* ([Exam Guide, "Exam Proofs"](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide)). 스크린샷에는 **플래그 내용 + 타겟 IP(`ipconfig`/`ip addr`)** 가 함께 있어야 한다. **웹셸은 대화형 셸을 얻는 데 쓰고, 읽기는 그 셸에서.** ([[Butch]] — 적대적 검증에서 노트가 정반대로 적혀 있던 것을 정정)
11. **공개 PoC는 실행 전에 소스를 읽는다** — 주석·`--help`·예시가 공짜 정찰 정보다. 그리고 **고쳐 쓰면 주석까지 고쳐라.** ([[Clue]] — 자격증명 채굴 아이디어가 저자 주석에 적혀 있었다 / 하드코딩 비밀번호를 고쳤더니 `# default password for FreeSWITCH` 주석이 **거짓말로 남았다**) · **README 예시의 인자를 그대로 복사하지 마라** ([[Clue]] — 공유 이름 `TimeMachineBackup`은 저자 장비의 것이었다)
12. **한 서비스의 거부는 자격증명의 오류가 아니다** — 얻은 자격증명은 **열린 포트 전부에** 시도한다. ([[Clue]] — `cassie`는 **SSH 거부 / SMB 통과 / 로컬 `su` 통과**였다. 여기서 포기했다면 박스가 막혔다)
13. **개인키의 주석은 소유자가 아니다** — `user@host` 는 만든 사람이 붙인 라벨이고, 인증을 정하는 것은 **대상 계정의 `authorized_keys`** 다. 키를 주우면 **사용자 이름을 전부 돌린다**(`-o BatchMode=yes`). ([[Clue]] — `anthony@clue` 키로 로그인된 계정은 **root**였다)
14. **셸을 잡으면 `netstat -tulpn` 도 친다** — 내부에서 보이는 포트가 외부 nmap보다 넓다. `127.0.0.1:*` 줄은 전부 "아직 안 본 공격면"이다. ([[Clue]] — 밖에서 6개, 안에서 11개. 필터링된 `0.0.0.0:1337`과 루프백 JMX가 거기 있었다) · ([[Squid]] — 프록시 경유 내부 포트 열거가 같은 계열)
15. **traversal을 손으로 칠 때 `--path-as-is`** — curl은 기본적으로 `../` 를 **보내기 전에 접는다**(실측 확인). 브라우저 주소창도 같다. ([[Clue]] — 이것이 `49362.py` 없이 같은 결과를 얻는 수동 대안이다)
16. **AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다** — ① 시계(`KRB_AP_ERR_SKEW` → `sudo rdate -n <DC>`; **현행 Kali에 `ntpdate` 는 패키지조차 없다**) ② 이름 해석(`getent hosts <FQDN>`; SPN은 IP가 아니라 FQDN이다) ③ `KRB5CCNAME`(**절대 경로**로 export 후 `klist` 확인; impacket `-k` 는 *"based on target parameters"* 로 SPN을 조립한다) ④ 박스 IP 변경(리버트). ([[Resourced]] · [[Hutch]] — 두 박스 모두 세션이 바뀌며 IP가 재배정됐고 노트 안에 두 IP가 공존한다)
17. **«사용자 설명 필드»는 AD의 자격증명 저장소다** — `description`·`info`·`comment` 를 **가장 먼저** 전수 조회한다. 익명으로 읽히는 도메인이 실제로 있다. ([[Resourced]] — SMB 널 세션, `Pre-Windows 2000 Compatible Access` 에 `ANONYMOUS LOGON` 포함 / [[Hutch]] — 익명 LDAP 서브트리 조회). **`ldapsearch` 는 `-o ldif_wrap=no` 없이 쓰면 긴 값이 잘려 비밀번호를 통째로 놓친다**
18. **`[-]` 가 실패를 뜻하지 않는다 — NTLM 상태 코드를 읽어라** — `STATUS_PASSWORD_EXPIRED`·`MUST_CHANGE`·`ACCOUNT_RESTRICTION` 은 **«자격증명이 맞다»는 증거**다. ([[Resourced]] — 만료되지 않은 두 계정만 통과했고, 그 둘이 `pwdneverexpires=true` 임이 BloodHound 덤프로 확인됐다). 그리고 **`-u 파일 -p/-H 파일` 은 기본이 «전조합 스프레이»** 다 — `--no-bruteforce` 를 빼면 계정을 잠근다 ([[Hutch]] — 196회를 뿌렸고 잠금 정책이 없어서 살았다)
19. **유효한 도메인 자격증명 «하나»를 얻는 즉시 BloodHound를 돌리고, «내 계정의 아웃바운드 엣지»를 직접 봐라** — Shortest Path 쿼리는 정답 엣지를 놓친다. ([[Resourced]] — 돌릴 수 있게 된 시점보다 **3시간 50분** 늦게 돌렸다 / [[Hutch]] — 데이터는 13:23에 있었는데 `ReadLAPSPassword` 엣지는 **65분 뒤** 14:28에 봤고, 본 뒤에는 24분 만에 끝났다)
20. **DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다** — `GenericAll`/`GenericWrite`/`WriteDacl`/`WriteOwner` 는 **한 방향으로 승격되므로 사실상 같은 것**이고, 컴퓨터 객체에서는 **RBCD**(ADCS 불필요) 또는 **Shadow Credentials**(ADCS 필요)로 무기화한다. `ReadLAPSPassword` 는 **속성 하나를 읽으면 끝**이다. **`inherited=false` 인 ACE가 오설정**이다 ([[Resourced]] `GenericAll` → RBCD → S4U / [[Hutch]] `ReadLAPSPassword` → LAPS 평문 → DCSync)

## 환경

- 공격 머신: `ssh kali@10.44.44.128` (키 인증, sudo NOPASSWD). Windows에서 `kali` 명령
- VPN: Kali의 `tun0` — 세션마다 IP가 바뀌므로 `ip -br a`로 확인
- 박스별 작업 디렉터리: `~/PG/<박스명>`
- **리버스셸은 반드시 tmux 세션으로** — 비대화식 SSH라 그냥 띄우면 끊긴다

