
```
## tags: [oscp, ad, 인증, phase-cross-cutting] group: 1 related: ["02 AD 구조", "05 공격 기법"]

# 그룹 1 — Windows 인증 모델

> **이 노트의 핵심 관점** 모든 개념을 "내가 X를 가졌다 → Y라는 동작을 하면 → Z를 얻는다" 형태의 변환 사슬로 본다. AS-REP, TGS-REP 같은 이름은 외울 게 아니라 **이 사슬의 어느 단계에서 KDC가 돌려주는 결과물**인지 위치를 잡으면 자동으로 이해된다.
```
---

## 0. 전체 변환 사슬 (이것만 외워도 절반)

```
[손에 쥔 것]            [동사]                  [새로 얻는 것]
─────────────────────────────────────────────────────────────
Cleartext password  ──→ AS-REQ 보내기      ──→ TGT (= AS-REP의 결과)
NTLM hash           ──→ Pass-the-Hash      ──→ 호스트 shell
NTLM hash           ──→ Overpass-the-Hash  ──→ TGT
TGT                 ──→ TGS-REQ 보내기     ──→ TGS (= TGS-REP의 결과)
TGS                 ──→ AP-REQ (서비스 제시) ──→ 서비스 접근
도메인 cred + SPN   ──→ Kerberoasting      ──→ 서비스 cred (TGS crack)
대상 사용자명       ──→ AS-REP Roasting    ──→ user cred (AS-REP crack)
krbtgt hash         ──→ Golden Ticket      ──→ 아무 사용자 TGT (도메인 지배)
```

**읽는 법**: 한 줄의 [새로 얻는 것]은 다음 줄의 [손에 쥔 것]이 될 수 있다. 시험장에서 어디가 막혀도 이 표만 보면 "지금 내가 뭐 가졌고, 그걸로 뭘 할 수 있나"가 한눈에 보인다.

---

## 1. 두 개의 인증 세계 — NTLM과 Kerberos

Windows에는 인증 방식이 두 개 공존한다. 같은 password로 만들어진 두 가지 표현형이 있다고 생각하면 된다.

```
                     [같은 password]
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
       NTLM hash                  Kerberos key
       (= 비번의 MD4)              (= 비번의 다른 해시)
            │                           │
            ▼                           ▼
     NTLM 인증 세계             Kerberos 인증 세계
     - challenge-response       - 티켓 기반
     - 서버가 매번 DC에 검증     - 한 번 TGT 받고 재사용
     - 폐기 예정                - 현대 기본
```

> **핵심 통찰**: NTLM hash와 Kerberos key는 **같은 password에서 다른 방식으로 유도된 두 형태**다. NTLM hash가 있으면 Kerberos 세계로도 넘어갈 수 있다 (= Overpass-the-Hash).

---

## 2. NTLM 인증 세계

### 2-1. 흐름 (사슬로 보기)

```
[1] Client → Server: "나는 user다"
[2] Server → Client: random challenge (16 bytes)
[3] Client → Server: NTLMv2 response
                     (= challenge를 NTLM hash로 암호화한 결과)
[4] Server → DC: "이 response 검증해줘"
[5] DC → Server: OK / NO
```

### 2-2. 손에 쥘 수 있는 자료 — 두 가지를 절대 헷갈리지 말 것

|자료|어떻게 생겼냐|어디서 얻냐|뭘 할 수 있냐|
|---|---|---|---|
|**NTLM hash**|`31d6cfe0d16ae931b73c59d7e0c089c0` (32 hex)|SAM/NTDS.dit/LSASS 덤프|**PtH 가능** (인증에 직접 사용)|
|**NTLMv2 response**|`user::DOMAIN:challenge:response:blob` (긴 한 줄)|Responder, ntlmrelayx|**crack만 가능** (PtH 불가)|

> **왜 NTLMv2 response는 PtH가 안 되나?** Response는 "특정 challenge를 hash로 암호화한 결과"다. 다른 server에 제출하면 그 server는 **다른 challenge**를 던지므로 response가 안 맞는다. 반면 NTLM hash는 challenge에 의존하지 않는 정적 값이라 어디서나 재사용 가능.

### 2-3. 도구 매핑

```bash
# NTLM hash로 직접 인증 (Pass-the-Hash)
nxc smb <TARGET> -u <USER> -H <NT_HASH>
evil-winrm -i <TARGET> -u <USER> -H <NT_HASH>
impacket-psexec <USER>@<TARGET> -hashes :<NT_HASH>
impacket-wmiexec <USER>@<TARGET> -hashes :<NT_HASH>

# NTLM hash 덤프
reg save hklm\sam sam ; reg save hklm\system system
impacket-secretsdump -sam sam -system system LOCAL

# NTLMv2 response 캡처 → crack
sudo responder -I tun0
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

---

## 3. Kerberos 인증 세계

### 3-1. 메시지 이름의 정체 — AS-REP/TGS-REP가 뭔가

> **이게 본인이 안 잡혀 있던 부분.** AS-REP, TGS-REP는 **별개의 개념이 아니다**. 그냥 **요청에 대한 응답 메시지의 이름**이다.

```
AS-REQ  = Authentication Service - REQuest   (Client → KDC, "나 인증해줘")
AS-REP  = Authentication Service - REPly     (KDC → Client, "TGT 줄게")
TGS-REQ = Ticket Granting Service - REQuest  (Client → KDC, "이 서비스 표 줘")
TGS-REP = Ticket Granting Service - REPly    (KDC → Client, "TGS 줄게")
AP-REQ  = Application - REQuest              (Client → Service, "표 받아라")
```

즉:

- **AS-REP의 내용물 = TGT**
- **TGS-REP의 내용물 = TGS**

"AS-REP을 받았다"는 말은 "TGT를 받았다"와 같은 뜻. "TGS-REP을 받았다"는 말은 "TGS를 받았다"와 같은 뜻.

### 3-2. 전체 흐름 (반드시 한 번 직접 손으로 따라가볼 것)

```
                      ┌─────────────────────────┐
                      │  KDC (Domain Controller) │
                      │  ┌─────┐    ┌─────┐     │
                      │  │ AS  │    │ TGS │     │
                      │  └─────┘    └─────┘     │
                      └────▲────┬────▲────┬─────┘
                           │    │    │    │
                  AS-REQ ──┘ TGT │ TGS-│  TGS
                  ([1])         │ REQ │  ([4])
                          AS-REP│ ([3])│
                           ([2])│      │TGS-REP
                                ▼      ▼
                      ┌─────────────────────────┐
                      │      Client (공격자)      │
                      └─────────────┬────────────┘
                                    │
                              AP-REQ│ (TGS 제시)
                              ([5]) ▼
                          ┌──────────────────┐
                          │ Service (대상호스트) │
                          └──────────────────┘
```

### 3-3. 각 단계에서 무엇이 어떤 키로 암호화되는가 (공격의 모든 토대)

```
[2] AS-REP의 내용물:
    ├─ TGT       ← krbtgt 계정의 key로 암호화 ★★★
    └─ session key ← user key (= password 유도) 로 암호화 ★★

[4] TGS-REP의 내용물:
    ├─ TGS       ← 대상 서비스 계정의 key로 암호화 ★★★
    └─ session key ← 위의 session key로 암호화
```

이 표가 **모든 Kerberos 공격의 토대**다. 보이는 패턴:

```
[2]의 ★★ → 약한 user password면 AS-REP crack 가능 → AS-REP Roasting
[2]의 ★★★ → krbtgt hash 있으면 임의 TGT 위조 → Golden Ticket
[4]의 ★★★ → 약한 서비스 계정 password면 TGS crack 가능 → Kerberoasting
[4]의 ★★★ → 서비스 hash 있으면 임의 TGS 위조 → Silver Ticket
```

### 3-4. 도구 매핑

```bash
# TGT 받기 (= AS-REP 받기)
impacket-getTGT <DOMAIN>/<USER>:<PASS>
# → <USER>.ccache 파일 생성

# TGT 사용 (Linux에서)
export KRB5CCNAME=$(pwd)/<USER>.ccache
impacket-psexec -k -no-pass <USER>@<TARGET_FQDN>

# Kerberoasting (= 모든 SPN 계정의 TGS-REP 끌어오기)
impacket-GetUserSPNs <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt

# AS-REP Roasting (= pre-auth 없는 계정의 AS-REP 끌어오기)
impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC_IP> -no-pass
hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
```

---

## 4. 각 자료의 정체 — "이게 있으면 뭘 할 수 있나"

### 4-1. NTLM hash

```
[입력] password
[처리] MD4(password.encode('utf-16-le'))
[출력] 16 bytes → 32 hex string

[어디 있나]
- 로컬 SAM (로컬 계정)
- NTDS.dit (도메인 계정 전부 — DC에 있음)
- LSASS 메모리 (현재 로그온한 사용자)

[이게 있으면 할 수 있는 것]
- Pass-the-Hash → 다른 호스트에 NTLM 인증
- Overpass-the-Hash → Kerberos TGT 획득
- offline crack → cleartext 복원
```

### 4-2. TGT (= AS-REP의 알맹이)

```
[정체] "이 사용자가 KDC에 인증을 마쳤다"는 증표
[암호화 키] krbtgt 계정의 key (= krbtgt password의 hash)
[유효 기간] 기본 10시간
[안에 든 정보] 사용자 SID, 그룹 SID들, session key

[이게 있으면 할 수 있는 것]
- TGS-REQ 보내서 임의 서비스의 TGS 받기 (Pass-the-Ticket)
- 새로 인증할 필요 없이 모든 도메인 리소스 접근

[손에 쥐는 방법]
1. cleartext password로 정상 발급 (getTGT.py)
2. NTLM hash로 발급 (Overpass-the-Hash)
3. 메모리에서 추출 (mimikatz, Rubeus dump)
4. krbtgt hash로 위조 (Golden Ticket)
```

### 4-3. TGS (= TGS-REP의 알맹이)

```
[정체] "이 사용자가 이 서비스에 접근할 권한이 있다"는 증표
[암호화 키] 대상 서비스 계정의 key
[유효 기간] 기본 10시간
[안에 든 정보] 사용자 SID, 대상 서비스 SPN, session key

[이게 있으면 할 수 있는 것]
- 해당 서비스 한 개만 접근 (다른 서비스는 별도 TGS 필요)
- offline crack → 서비스 계정 password (Kerberoasting)

[손에 쥐는 방법]
1. TGT로 정상 발급 (GetUserSPNs.py)
2. 메모리에서 추출
3. 서비스 hash로 위조 (Silver Ticket)
```

### 4-4. NTLMv2 response

```
[정체] "이 챌린지를 내 hash로 암호화했다"는 응답
[형식] user::DOMAIN:challenge:response:blob (긴 한 줄)
[어디서 잡냐] Responder의 LLMNR/NBT-NS poisoning

[이게 있으면 할 수 있는 것]
- offline crack → cleartext password
- ntlmrelayx로 즉시 다른 호스트에 relay (SMB signing 안 켜진 경우)

[이게 있어도 못 하는 것]
- Pass-the-Hash 불가 ★ (PtH는 NTLM hash가 있을 때만)
- TGT 발급 불가
```

---

## 5. 시험장 트러블슈팅 — 1차 시험에서 막혔던 그 함정

### 5-1. realm은 대문자

```bash
kinit b.martin@oscp.exam   # ❌ "Cannot find KDC for realm"
kinit b.martin@OSCP.EXAM   # ✅
```

### 5-2. /etc/krb5.conf 표준 템플릿

```ini
[libdefaults]
    default_realm = OSCP.EXAM
    dns_lookup_kdc = false
    dns_lookup_realm = false

[realms]
    OSCP.EXAM = {
        kdc = dc20.oscp.exam
        admin_server = dc20.oscp.exam
        default_domain = oscp.exam
    }

[domain_realm]
    .oscp.exam = OSCP.EXAM
    oscp.exam = OSCP.EXAM
```

### 5-3. NetExec로 자동 생성

```bash
nxc smb <DC> -u <USER> -p <PASS> -k --generate-krb5-file krb5.conf
sudo cp krb5.conf /etc/krb5.conf
```

### 5-4. 그 외 자주 막히는 지점

|증상|원인|해결|
|---|---|---|
|`Cannot find KDC for realm`|realm 소문자, 또는 krb5.conf 없음|5-2 템플릿 적용|
|`Clock skew too great`|Kali와 DC 시간 차이 5분 초과|`sudo ntpdate <DC>` 또는 `sudo rdate -n <DC>`|
|`KRB_AP_ERR_SKEW`|위와 동일|위와 동일|
|`Server not found in Kerberos database`|FQDN 안 쓰고 IP 사용|hosts에 FQDN 등록 후 FQDN으로 접속|
|`KDC_ERR_PREAUTH_FAILED`|password 틀림|재확인|
|인증 되는데 ldap/smb 안 됨|KRB5CCNAME 환경변수 안 export됨|`export KRB5CCNAME=$(pwd)/file.ccache`|

---

## 6. 시험장 5초 판단 플로우차트

```
"내가 지금 손에 뭘 쥐었지?"
│
├─ Cleartext password ──→ 모든 것 가능. 일단 nxc로 권한 매핑부터.
│
├─ NTLM hash         ──→ 1순위: PtH로 다른 호스트 시도 (nxc -H)
│                       2순위: Overpass로 TGT 받기 (getTGT -hashes)
│                       3순위: 시간 남으면 offline crack
│
├─ NTLMv2 response   ──→ PtH 절대 시도 금지. crack 또는 relay만.
│                       (hashcat -m 5600 또는 ntlmrelayx)
│
├─ TGT (.ccache)     ──→ KRB5CCNAME export 후 -k -no-pass로 사용
│                       모든 SPN에 TGS 요청 가능
│
├─ TGS (.ccache)     ──→ 해당 서비스만 사용 가능
│                       crack 시도 (Kerberoasting의 결과면)
│
├─ krbtgt hash       ──→ Golden Ticket. 사실상 시험 끝.
│
└─ 사용자명 리스트만 ──→ AS-REP Roasting 시도
                        password spray 시도
                        Anonymous SMB enum
```

---

## 7. 다음 그룹과의 연결

- `Domain Controller`, `Domain`, `Forest`, `SID` → [[02 AD 구조]]
- `SeImpersonate`, `Service account`, `GMSA`, `Domain Admin` → [[03 계정과 권한]]
- `Pass-the-Hash`, `Kerberoasting`, `Golden Ticket` 등 각 공격의 세부 → [[05 공격 기법]]
- `BloodHound`, `Impacket`, `Rubeus`, `Certipy` 도구별 정리 → [[07 도구 매핑]]

---

## 8. 자기 점검 — 다음으로 넘어가기 전 확인할 것

다음 질문에 막힘없이 답할 수 있어야 한다. 막히면 위 섹션 다시.

1. AS-REP과 TGT의 관계는? (한 줄로)
2. TGS-REP과 TGS의 관계는? (한 줄로)
3. NTLM hash와 NTLMv2 response의 결정적 차이는?
4. Kerberoasting이 가능한 이유를 TGS 암호화 키의 관점에서 설명하라.
5. AS-REP Roasting이 가능한 이유를 AS-REP 암호화 키의 관점에서 설명하라.
6. Golden Ticket이 왜 도메인 지배인지, krbtgt key 관점에서 설명하라.
7. NTLM hash가 있는데 어떤 호스트가 NTLM을 막아놨다. 무엇을 시도하나? (답: Overpass-the-Hash로 TGT 받고 Kerberos로 우회)