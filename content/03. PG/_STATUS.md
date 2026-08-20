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
| ✅ 완료 (플래그 전부) | 18 | 6.4% |
| 🟡 부분 완료 | 1 | 0.4% |
| ⬜ 미착수 | 264 | 93.3% |
| **합계** | **283** | |

난이도 분포: **Fundamental** 43개 · **Intermediate** 209개 · **Advanced** 31개

## ✅ 완료 (18)

| 박스 | 난이도 | 플래그 | writeup |
|---|---|---|---|
| Astronaut | Fundamental | 1/1 | [[Astronaut]] |
| Breakout | Intermediate | 2/2 | [[Breakout]] |
| Butch | Intermediate | 2/2 | [[Butch]] |
| Codo | Fundamental | 1/1 | [[Codo]] |
| Crane | Intermediate | 2/2 | [[Crane]] |
| Exfiltrated | Fundamental | 2/2 | [[Exfiltrated]] |
| Exghost | Fundamental | 2/2 | [[Exghost]] |
| Fanatastic | Fundamental | 2/2 | [[Fanatastic]] |
| Hawat | Fundamental | 1/1 | [[Hawat]] |
| Hub | Fundamental | 1/1 | [[Hub]] |
| Levram | Fundamental | 2/2 | [[Levram]] |
| MiddlewareBypass | Intermediate | 1/1 | [[MiddlewareBypass]] |
| Muddy | Fundamental | 2/2 | [[Muddy]] |
| Osaka | Advanced | 2/2 | [[Osaka]] |
| RubyDome | Fundamental | 2/2 | [[RubyDome]] |
| Scarlet | Intermediate | 2/2 | [[Scarlet]] |
| Squid | Fundamental | 2/2 | [[Squid]] |
| Zipper | Advanced | 2/2 | [[Zipper]] |

## 🟡 부분 완료 (1) — 우선 처리 대상

| 박스 | 난이도 | 플래그 | writeup |
|---|---|---|---|
| Flu | Intermediate | 1/2 | [[Flu]] |

## ⬜ 미착수 (264)

체크박스를 채우며 진행한다. `노트O` = 볼트에 기존 노트가 이미 있음(참고 자료로 활용 가능).

### Fundamental (32)

- [ ] Algernon `0/1`
- [ ] Assignment `0/2`
- [ ] BossPlayersCTF `0/2`
- [ ] Bratarina `0/1`
- [ ] ClamAV `0/1`
- [ ] Cobbles `0/2`
- [ ] Compromised `0/2`
- [ ] Covfefe `0/2`
- [ ] CVE-2023-46818 `0/1`
- [ ] Detection `0/1`
- [ ] Fikklish `0/2`
- [ ] Flimsy `0/2`
- [ ] Fowsniff `0/2`
- [ ] Fractal `0/2`
- [ ] GLPI `0/2`
- [ ] Graph `0/2`
- [ ] Interface `0/1`
- [ ] Internal `0/1`  ← 노트O
- [ ] JISCTF `0/2`
- [ ] Kevin `0/1`  ← 노트O
- [ ] LazySysAdmin `0/2`
- [ ] Mice `0/2`
- [ ] Monster `0/2`
- [ ] Outdated `0/2`
- [ ] Pebbles `0/1`
- [ ] PlanetExpress `0/2`
- [ ] PwnLab `0/2`
- [ ] Robust `0/2`
- [ ] SunsetTwilight `0/2`
- [ ] Twiggy `0/1`  ← 노트O
- [ ] Wheels `0/2`
- [ ] Wombo `0/1`

### Intermediate (203)

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
- [ ] Cockpit `0/2`  ← 노트O
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
- [ ] Hutch `0/2`  ← 노트O
- [ ] Illusion `0/2`
- [ ] image `0/2`
- [ ] Infilo `0/1`
- [ ] InvokeAI_RCE `0/1`
- [ ] Jacko `0/2`  ← 노트O
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
- [ ] Pelican `0/2`  ← 노트O
- [ ] Pier `0/1`
- [ ] Pipe `0/1`
- [ ] plum `0/2`  ← 노트O
- [ ] Postfish `0/2`
- [ ] Precision `0/1`
- [ ] press `0/1`
- [ ] ProStore `0/2`
- [ ] pyLoader `0/1`  ← 노트O
- [ ] Quackerjack `0/2`
- [ ] Rayeih `0/2`
- [ ] Readys `0/2`
- [ ] Reconstruction `0/2`
- [ ] Resourced `0/2`  ← 노트O
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
- [ ] Sorcerer `0/2`  ← 노트O
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

### Advanced (29)

- [ ] BadCorp `0/2`
- [ ] BlackGate `0/2`
- [ ] Bunyip `0/2`
- [ ] Clue `0/2`  ← 노트O
- [ ] CookieCutter `0/2`
- [ ] Craft2 `0/2`
- [ ] Deployer `0/2`
- [ ] Develop `0/2`
- [ ] Emporium `0/2`
- [ ] Escape `0/2`
- [ ] Flower `0/2`
- [ ] Glider `0/2`
- [ ] Gradle `0/2`
- [ ] Heist `0/2`  ← 노트O
- [ ] Injecto `0/2`
- [ ] Megavolt `0/2`
- [ ] Nagoya `0/2`  ← 노트O
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
- [ ] Vault `0/2`  ← 노트O
- [ ] Vector `0/2`

## 작업 파이프라인

박스마다 동일하게 반복한다:

1. **기동** — 포털에서 Start (이전 머신은 Accept로 자동 정지)
2. **브리핑 확인** — `View Briefing`은 점수에 영향 없음. `Show Walkthrough`는 누르지 않는다
3. **팀 투입** — 정찰(읽기전용) + 침투(풀체인) 병렬. pcap·바이너리 등이 끼면 전문 담당 추가
4. **교차 검증** — 하위 에이전트 보고를 그대로 믿지 않는다. 살아 있는 셸에서 플래그를 직접 `cat`으로 재확인
5. **제출** — 검증된 값만 포털에 입력
6. **writeup 작성** — `03. PG/<박스명>.md` ([[_WRITEUP-STANDARD]] 준수)
   - frontmatter에 **`manual_tags: true`** + **실제로 쓴 기법만** 태그
   - `refresh.ps1` 실행해 색인 갱신
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

1. **응답이 성공을 뜻하지 않는다** — 타임아웃·`HTTP=000`·`200`+로그인페이지·무응답 전부 성공 사례였다. **리스너와 부작용을 봐라.** ([[Crane]] [[RubyDome]] [[Astronaut]] [[Exghost]])
2. **버전은 출처가 다른 근거 2개 이상 교차로 확정** — 근거 3개가 같은 파일에서 나왔으면 그건 근거 1개다. ([[Hub]]에서 실패 → [[Levram]] [[RubyDome]] [[Astronaut]]에서 교정)
3. **워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다** — 30만 건 완주하고 0건. 다른 채널(백업·캡처·로그)에서 얻어야 한다. ([[Exghost]])
4. **`sudo -l`이 좁아도 대상 파일 권한을 확인** — 내가 쓸 수 있으면 사실상 `NOPASSWD: ALL`이다. ([[RubyDome]])
5. **특권은 "없는" 게 아니라 "박탈된" 것일 수 있다** — `LOCAL SERVICE`는 FullPowers로 되찾는다. ([[Squid]])
6. **페이로드는 base64로 감싼다** — 다중 인용 계층을 한 번에 통과한다.
7. **파일 전송 후 `ls`/`md5sum`으로 확인** — 유명 도구는 파일명만으로 삭제된다. ([[Squid]] [[Exghost]])

## 환경

- 공격 머신: `ssh kali@10.44.44.128` (키 인증, sudo NOPASSWD). Windows에서 `kali` 명령
- VPN: Kali의 `tun0` — 세션마다 IP가 바뀌므로 `ip -br a`로 확인
- 박스별 작업 디렉터리: `~/PG/<박스명>`
- **리버스셸은 반드시 tmux 세션으로** — 비대화식 SSH라 그냥 띄우면 끊긴다

