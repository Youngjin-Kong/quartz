---
tags:
  - type/index
  - platform/pg
---
# Nagoya — 적대적 검증 감사 기록 (2026-08-20)

소급 감사. 박스를 켜지 않고 문서·산출물만 대조했다.
대상: `03. PG/Nagoya.md` (728행 → 950행 개작본 → 정정 후 984행)

## 증거원

| 종류 | 실제로 본 것 |
|---|---|
| 개작 전 원본 | `03. PG/Nagoya.md.bak` (728행, 손기록. git 에는 이 노트의 개작 전 상태가 `607fbc5` 프론트매터 주입본으로만 있고 본문 baseline 은 `.bak` 이 유일) |
| Kali 산출물 | `~/PG/Nagoya/` 전량 — `nmap.log`, `whatweb.log`, `names.txt`, `users.txt`, `valid_users.txt`, `season_pass.txt`, `hash.txt`, `agent.exe`, `Administrator.ccache`, ferox `.state` 3개, BloodHound JSON 7종 |
| 히스토리 | `~/.zsh_history` (`~/.bash_history` 는 존재하지 않음) |
| 스크린샷 | 볼트 `파일보관\` 의 `Pasted image 202607{06,07}*.png` **28장 중 Nagoya 구간 24장을 전부 열어봄** (07-06 09:16·10:48·10:49·10:50 넷은 nmap 시작 13:08 이전이라 다른 박스) |
| 1차 사료 | impacket `ticketer.py` 소스(Kali), Microsoft KB5020805, Microsoft SQL Server 2008 R2 보안 변경 문서, Windows Server 2019 빌드 이력 |
| 직접 실행 | `python3` 로 BloodHound JSON 의 그룹 멤버십·ACE 집계, ferox `.state` JSON 파싱, `awk '{print length}' hash.txt`, `grep /etc/hosts` |
| 부재 확인 | `/tmp` 163개 항목(이름 스캔, nagoya/local/proof 0건), `~/.cache/pip`(존재. `~/.gem`·`~/.npm`·`~/.cargo` 는 없음, nagoya 0건), `~/.bash_history` 없음 |

> [!warning] `/tmp` 스캔이 처음에 실패했던 이유 — 감사 절차상 기록해 둔다
> `ls -la /tmp` 와 `find /tmp` 가 매번 멈춘다. 원인은 Nagoya 와 무관하다 — Kali 에 **`/tmp/nfs` 로 `192.168.248.222:/mnt/share` 가 `hard` 옵션으로 마운트된 채 죽어 있다**(`stat /tmp/nfs` 가 타임아웃). `hard` 마운트라 stat 를 하는 순회는 전부 거기서 영구 대기한다.
> 우회법: `ls -f /tmp`(stat 안 함)로 이름만 훑으면 즉시 끝난다. 그렇게 확인한 결과 `/tmp` 최상위 163개에 `local.txt`·nagoya 흔적은 **0건**이다.
> `/tmp/nfs` 안쪽만은 끝내 볼 수 없었으나, 그건 **다른 박스(192.168.248.x)의 공유**이고 Nagoya(192.168.120.21) 이후 세션의 것이라 이 판정에 영향을 주지 않는다.

## 판정

**부분 — 1/2.**
- `proof.txt` = `be83df05d75cfee867192bdf8dcd2fdb`. `파일보관/Pasted image 20260707105621.png` 에 `C:\Users\Administrator\Desktop` 에서 `type proof.txt` 한 화면이 그대로 찍혀 있다(대화형 raw 셸, 명령 에코 포함). 웹셸 아님 → 시험 기준으로도 유효.
- `local.txt` — **없다.** `~/PG/Nagoya/` 산출물, `~/.zsh_history`(문자열 `local.txt` 0건), `~/.bash_history`(파일 자체가 없음), `/tmp` 최상위, `~/.cache/pip`, 스크린샷 24장 전량 확인. 유일한 `dir` 출력도 Administrator 데스크톱만 보여준다. 셸(christopher.lewis WinRM + 머신 계정 리버스셸)은 있었으니 못 딴 게 아니라 안 딴 것이다.
  표준의 「부재 증거 상한」 체크리스트를 전부 소진했으므로 이 건은 `근거부족` 이 아니라 **무기록으로 확정**한다.

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| 6장 시간표 전체 | 스크린샷 파일명(붙여넣기 시각)을 사건 시각으로 단정. 노트가 3장에서 스스로 단 유보를 6장에서 어겼다 | 표에 `등급` 열을 붙여 실측(mtime·도구 타임스탬프)/역산/상한(붙여넣기 시각)을 분리. ligolo 구간은 `agent.exe` 로그와 `INFO[0171]`/`INFO[0191]` 로 역산 |
| "정찰 시작부터 플래그까지 실작업 약 3시간 40분" | 자기가 적은 구간(3시간 47분 + 21분)을 더해도 안 나오는 산수 | 약 4시간 15분 (13:08→16:55 = 3시간 47분, 10:28→10:56 = 28분) |
| "약 17시간 40분 공백" | 종점 시각 오류에서 파생 | 약 17시간 30분 (16:55:54 → ~10:27:51) |
| 7장 "ligolo 세팅부터 플래그까지 21분(10:35→10:56)" | 위와 같음 | 약 28분 (10:28→10:56) |
| 2-3장 "HELPDESK 가 일반 사용자 **20명** 전원에 GenericAll" | 실제 21명 | 21명으로 정정 + "EMPLOYEES 멤버 21명과 정확히 같은 집합"이라는 관측을 추가 |
| 4-3장 "**MSSQL 이 `BUILTIN\Administrators` 를 sysadmin 으로 매핑하는 기본 설정** 때문에 이게 곧 sysadmin 이 된다" | **틀린 일반 지식.** SQL Server 2008 이후 기본 설치는 `BUILTIN\Administrators` 를 sysadmin 에 자동 추가하지 않는다. 이 인스턴스는 `ACK: Microsoft SQL Server (160 …)` = 2022 | 매핑 경로를 `[가정]` 으로 강등하고, 관측된 사실(`dbo@master` 프롬프트 + `sp_configure` 성공 = sysadmin 이었다)만 단정. ticketer 기본 그룹은 소스로 확인해 오히려 강화 |
| 8장 "`PacRequestorEnforcement` 를 강제하면 위조 PAC 이 거부된다" | **틀린 일반 지식.** PacRequestorEnforcement(KB5008380/CVE-2021-42287)는 KDC 가 **발급한** 티켓의 PAC_REQUESTOR 를 검사한다. 실버티켓은 KDC 를 아예 안 거치므로 무관 | KB5020805(CVE-2022-37967)의 full PAC signature(`KrbtgtFullPacSignature`)로 교체. 2023-07-11 부터 enforcement 기본이고 이 DC 빌드 `17763.4252` 는 KB5025229(2023-04-11)라 그 이전임을 명시 |
| 2-4장 "(2) PAC 검증이 켜져 있으면 막힌다(기본은 꺼져 있다)" | 근거 없는 기본값 단정 | 위와 같은 근거로 구체화(서버 체크섬은 위조 가능, krbtgt 서명은 불가) |
| 4-5장·7장 "`Domain Controllers` 그룹이 `GetChangesAll`(= DCSync)" | DCSync 는 `GetChanges` + `GetChangesAll` 둘 다 필요. `domains.json` 실측상 `Domain Controllers` 는 `GetChangesAll` 만, `GetChanges` 는 `Enterprise Domain Controllers`(S-1-5-9)가 갖는다 | 두 권한의 출처를 나눠 서술. 결론(머신 계정이면 DCSync 됨)은 유지 |
| 3-2장 "큰따옴표를 닫지 않은 채 `-S 192.168.120.21\` 로 끝나는 시도가 **네 번**" | 히스토리 실측과 불일치 | 실패 4줄 중 인용부호 미종결 3줄, 줄 끝 `\` 3줄, 둘 다인 것 2줄로 정정 |
| 6장-6 "같은 형태가 네 번 반복된다" | 같은 형태는 3줄 | 3줄 + 앞선 `iain.white` 실패 1줄 = 합 4줄로 정정 |
| 6장-1 / 1장 경고 "세 번째만 913개까지 **완주**했다" | `.state` 실측: 913 = 200 열두 개 + **503 901개**. 200 응답은 세 실행 모두 동일한 12개. 세 state 전부 scan status `Running` = 완주한 실행 없음 | 숫자·완주 여부 정정. 확장자 조합 세 개를 실제 명령대로 명시 |
| 1장 경고 "세 번째는 `-x asp,aspx` 로" | 실제 `-x html,txt,asp,aspx` | 정정 |
| 5장 `proof.txt` 블록 | 스크린샷에 없는 `C:\Windows\system32>cd …` / `…Desktop>dir` 두 줄이 재구성돼 코드펜스 안에 들어갔다. 게다가 이 셸은 명령을 에코하는데(노트 자신이 그 아래에서 설명) 재구성된 두 줄에는 에코가 없어 자기모순 | 스크린샷에 찍힌 범위만 남기고(`2 Dir(s) … bytes free` 포함) 앞 절차는 코드펜스 밖 산문으로 |
| 5장 "볼트 스크린샷 **28장**" | 28장은 그날 붙여넣은 전량이고 그중 4장은 오전 다른 박스 | Nagoya 구간 24장으로 정정 + "전부 열어 확인했다"로 명시 |
| 5장 proof.txt 타임스탬프 해석 | "프로비저닝됐다"고 단정 | `[가정]` 강등 + 근거 보강(07-06 에 바꾼 비밀번호가 07-07 에도 통했으니 리버트가 아니라 재기동) |
| 6장 서두 "산출물 mtime 과 `~/.zsh_history`, 스크린샷 파일명으로 복원" | `ssh -L 13389:…` 는 히스토리에 없다(원본 손기록에만) | 출처를 정확히 표기 |
| 1장 `curl … \| paste - -   > names.txt` | 히스토리(1507행)에는 리다이렉트가 없다 | 명령은 히스토리대로 두고 "같은 출력을 `names.txt` 로 받았다"를 산문으로 |
| 3-3장 `nxc-sweep` 출력 블록 | 원본에 있던 SMB/WINRM 배너 2줄과 꼬리 3줄(`Port 21` / `All active services checked.`)이 표시 없이 잘려 있었다 | 원본 그대로 복원 |
| 2-2장 "기본 잠금 임계값(보통 5~10회)" | AD 기본 도메인 정책의 임계값은 관례적으로 0(비활성)이고 5~10 은 조직 하드닝 값이다. "기본값"이라는 단어가 틀린 단정 | "조직에서 흔히 쓰는 임계값"으로 바꾸고 `--pass-pol` 로 실제 정책을 읽는 법을 병기. 이 박스에서는 안 읽었다고 명시 |
| 4-3장 "유효기간이 10년" | 사실은 맞지만 근거가 없어 "타깃 특성"처럼 읽혔다 | impacket `ticketer.py` 의 `-duration` 기본값 87600시간(24×365×10)이라는 도구 산물임을 명시 |
| 프론트매터 | 8장 정정으로 CVE-2022-37967 이 본문에 새로 들어가 자동 색인에 잡히게 됐다 | `manual_cves: true` 추가(목록 없음 = "이 박스 CVE 없음"). `04. CVE 색인.md` 에 Nagoya 미등재 확인 |
| 노트 상단 | 정정 이력 없음 | `[!warning] 적대적 검증 정정 이력` 콜아웃 신설 |
| 9장 | 새 단정의 출처 없음 | KB5020805, SQL Server 2008 R2 보안 변경 문서 링크 추가 |

## 삭제한 것

**본문에서 완전히 지운 서술은 없다.** 전부 정정 또는 `[가정]` 강등이다. 다만 아래 두 문장은 문장 형태가 남지 않았으므로 원문을 여기 인용해 둔다 — 되살릴 수 있어야 한다.

1. 4-3장 (삭제 원문)
   > `-user-id 500` 이 사칭 대상. RID 500 은 빌트인 Administrator 고, ticketer 는 여기에 표준 그룹(513/512/520/518/519)을 함께 박아 넣는다. **MSSQL 이 `BUILTIN\Administrators` 를 sysadmin 으로 매핑하는 기본 설정** 때문에 이게 곧 sysadmin 이 된다.

   → 굵게 표시된 인과가 반증됐다. 앞부분(513/512/520/518/519)은 impacket 소스로 확인돼 유지·확장했다.

2. 8장 (삭제 원문)
   > **실버티켓 탐지** — 유효기간 10년짜리 티켓, KDC 로그(4768/4769) 없이 서비스 로그온(4624)만 있는 이벤트, 존재하지 않는 사용자 이름의 서비스 접근. `PacRequestorEnforcement` 를 강제하면 위조 PAC 이 거부된다.

   → 앞의 탐지 지표 셋은 유지했고 마지막 문장만 교체했다.

3. 5장 (삭제 원문 — 코드펜스 안 두 줄)
   ```
   C:\Windows\system32>cd C:\Users\Administrator\Desktop
   C:\Users\Administrator\Desktop>dir
   ```
   → 스크린샷에 없다. 절차 자체는 사실이므로 산문으로 옮겼다.

## 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

이 절이 이 감사에서 제일 중요하다. **초기 지적 6건 중 5건이 재검토에서 깨졌다.**

1. **`nxc-sweep` 의 SMB 공유 열거 8줄이 개작에서 창작됐다 (❌ 오판)**
   `.bak` 을 `grep -v '^SMB  '` 로 걸러 읽는 바람에 원본에 그 블록이 없다고 판단했다. 필터를 빼고 다시 읽으니 `.bak` 에 `ADMIN$`/`C$`/`IPC$ READ`/`NETLOGON READ`/`SYSVOL READ` 가 그대로 있다. **개작본은 오히려 배너 2줄을 지웠을 뿐이고, 지운 쪽이 문제였다.** — 부재 판정을 서두르면 이렇게 된다.

2. **`whoami` 가 `nagoya-ind\nagoya$` 라는 서술이 과잉 강등이다 (❌ 오판)**
   `Pasted image 20260707105454.png` 를 직접 열었다. 화면에 `nagoya-ind\nagoya$` 가 그대로 찍혀 있다. 다른 어떤 스크린샷에도 `nt authority\system` 은 없다. **작성자의 자기 반증이 옳았고 `[가정]` 강등도 타당하다.** 5장의 Administrator 데스크톱 접근과도 모순 없다 — DC 머신 계정은 그 권한을 갖는다(4-5장에 근거를 보강해 뒀다).

3. **`klist` 출력이 서술뿐이고 실행되지 않았다 (❌ 오판)**
   `Pasted image 20260707104041.png`(및 동일 내용의 `104049.png`)에 `export KRB5CCNAME` → `klist` → `impacket-mssqlclient -k` 가 한 화면에 있다. `Valid starting 07/07/2026 10:39:08`, `Expires 07/04/2036 10:39:08`, SPN `MSSQL/nagoya.nagoya-industries.com@NAGOYA-INDUSTRIES.COM` — 노트와 한 글자도 다르지 않다. `Administrator.ccache` 의 mtime(`10:39:08.037`)까지 일치한다.

4. **`ip route`/`nc -zv` 출력과 ligolo 콘솔 출력이 `.bak` 에 없으니 창작이다 (❌ 오판)**
   `.bak` 에는 없는 게 맞지만 `103642.png`·`103631.png`·`103620.png` 에 전부 찍혀 있다. `nagoya.nagoya-industries.com [240.0.0.1] 1433 (ms-sql-s) open`, `INFO[0171] Agent joined … remote="192.168.120.21:49860"`, `Connection established addr="192.168.45.175:11601"` 모두 화면 그대로다. **개작이 스크린샷에서 복원한 것이지 지어낸 것이 아니다.**

5. **`impacket-lookupsid` 출력 14줄이 창작이다 (❌ 오판)**
   `111134.png` 에 498/500/501/502/512/513/514 가 그대로 있다.

6. **`ligolo-ng v0.8.2` 가 근거 없다 (❌ 오판)**
   `103550.png`·`103631.png` 배너에 `Version: 0.8.2`, Kali `~/git/ligolo/` 에 `ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz`.

추가로 **프롬프트에서 지시받은 내용 중 반증된 것**:
- 프롬프트는 "노트가 28장이라고 적고 있다"를 그대로 전제했다. 실제로 그날 붙여넣은 이미지는 28장이 맞지만 **Nagoya 구간은 24장**이다(나머지 4장은 같은 날 오전 다른 박스). 노트의 "28장"은 그래서 부정확했고 정정했다.
- 프롬프트는 "PrintSpoofer 로 SYSTEM 획득"이 `[가정]` 으로 강등된 건을 "최우선 재판정 항목"으로 지목했다. 확인 결과 **강등이 옳았고 재판정할 것이 없다.** 대신 그 옆 문장의 `GetChangesAll = DCSync` 등식이 틀렸다.

## 그 외 대조했지만 정확했던 것

- `names.txt` 28행 — 노트 인용(`Matthew Harrison` … `Joanne Lewis`)과 파일 내용 일치
- `users.txt` 405행 / `valid_users.txt` 26행 — 노트 숫자와 일치
- `hash.txt` 두 줄의 길이 2389·2383자 — 노트가 괄호 안에 적은 값과 정확히 일치
- feroxbuster 결과 목록(3530/6896/3128/1123) — `.state` 의 `content_length` 와 일치
- BloodHound: `EMPLOYEES → GenericAll → {iain.white, joanna.wood, bethan.webster, svc_helpdesk}` 4개, `Remote Management Users` 의 유일 멤버가 `DEVELOPERS`, 나머지 DEVELOPERS 멤버 4명은 `ACCOUNT OPERATORS` 만 통제 — 전부 JSON 실측과 일치
- 스프레이 순서(비밀번호 바깥 루프) — `.bak` 의 nxc 원문이 그대로 증명
- 6장의 시행착오 목록(username-anarchy 경로 오타, kerbrute `_386`/`usernames.txt`, `-p 'FoundPass!'`, `smbclient -L … -N`, `KRB5CCNAME` 줄 끝 백슬래시 2회) — `~/.zsh_history` 1503~1607행과 전부 일치
- `xfreerdp` 실패 원인이 "기록에 없다"는 서술 — 맞다. 히스토리에 명령만 있고 출력이 없다
- `/etc/hosts` 의 `240.0.0.1 nagoya.nagoya-industries.com` 이 아직 남아 있다는 「남긴 흔적」 — 지금도 6행에 그대로 있다
- 태그 13개 — 전부 실제 사용 기법. `tech_count: 13` 과 실제 개수 일치. `manual_tags: true` 뒤 주석 없음

## 남은 판단 (총괄 참고)

- `tech/ad/asreproast` 를 지운 것은 경계선이다. AS-REP 로스팅은 **실제로 실행됐고**(6장-4) 26계정 전멸이라는 결과까지 남았다. 표준의 판단 기준("뚫는 데 실제로 사용했는가")에 따르면 제외가 맞아 그대로 뒀다. 다른 노트와 일관성이 문제가 되면 총괄이 정할 일이다.
- `tech/svc/smb` 제거도 같은 성격이다 — `nxc smb` 는 스프레이 수단으로 썼고 그건 `tech/cred/spray` 가 덮는다.
- 노트에 안 쓰인 스크린샷 4장: `20260707104049.png`(`104041` 과 동일 내용), `20260707105240.png`·`105242.png`(6장 시각 논증의 근거로 인용만 함), `20260707111345.png`(svc_mssql 자격증명으로 GetUserSPNs 재실행). 본문에 넣을 만한 새 정보는 없다.

## 관련

- [[Nagoya]]
- [[_WRITEUP-STANDARD]]
