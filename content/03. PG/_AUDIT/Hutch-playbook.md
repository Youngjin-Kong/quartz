---
tags:
  - type/audit
  - platform/pg
---

# Hutch → `_PLAYBOOK` 이관 제안

작성: `pg-note-forge` (2026-08-26) · 대상 노트 `03. PG\Hutch.md` (1606행 → 808행) · 백업 `03. PG\_backup\Hutch.md.bak`

⚠️ **워커는 `_PLAYBOOK.md` 를 열지 않았음.** 아래는 제안이고 반영은 단독 기록자 몫임. 신규 항목은 **번호를 비워** 두었음.

⚠️ **역검색 결과 — 이 박스의 교훈 상당수는 이미 이관돼 있음.** `_PLAYBOOK` 에서 `[[Hutch]]` 를 인용하는 기존 항목이 여섯임(A-51 · A-65 · B-51 · B-52 · B-53 · B-54). 아래 제안은 **그 여섯이 아직 담지 못한 것만** 골랐고, 담긴 것은 「이미 반영됨」으로 표시했음.

---

## 이미 반영돼 있어 제안하지 않는 것 (검산용)

| 원본 노트의 내용 | 이미 있는 절 |
|---|---|
| AD 에서 막히면 시계·이름해석·`KRB5CCNAME`·IP 재배정 넷부터 (§7-3) | `A-51` |
| 리버트로 IP 가 바뀌어 노트에 두 IP 가 공존 (§6-1) | `A-51` · `A-65` (둘 다 [[Hutch]] 를 명시 인용) |
| `description` 은 AD 의 자격증명 저장소 · `-o ldif_wrap=no` (§2-2) | `B-51` |
| `-u 파일 -p 파일` 은 전조합 스프레이 · 196회 (§3-1) | `B-52` |
| BloodHound 아웃바운드 엣지를 직접 볼 것 · 13:23→14:28 의 65분 (§6-6) | `B-53` |
| DC 컴퓨터 객체의 저권한 ACE · `ReadLAPSPassword` (§2-3) | `B-54` |
| AS-REP 빈손을 「내가 틀렸다」로 읽지 말 것 (§2-1) | `B-55 ⑸` |
| 플래그가 하나뿐인 박스 · `Local.txt value:` 를 비우지 말 것 (§5-2) | `C-3` |
| kerbrute 는 에러 코드 구분이라 계정을 안 잠금 (§1-4) | `B-55 ⑴` |
| 웹셸로 읽은 플래그는 0점 (§5-2) | `E` |

---

## 제안 1 — `C-3. 플래그·증거` **병합**

**넣을 본문**

> **⛔ 플래그 개수를 «내가 본 디렉터리»로 추론하지 말 것.** 개수는 포털이 `N/M` 으로 알려줌.
> [[Hutch]] 실측 — 14:52 에 도메인 관리자 대화형 셸을 쥐고 `cd Desktop` → `dir` → `type proof.txt` 로 곧장 갔고, **그 디렉터리에 `proof.txt` 하나뿐인 것을 보고 「이 박스는 플래그가 하나」로 결론지었음.** 관리자 프로필에 `local.txt` 가 없는 것은 정상인데 그것을 개수의 근거로 삼은 것임. 포털은 `0/2` 였고 플래그 하나를 그대로 잃었음.
> **Windows 판 3초 반사** — 셸을 잡으면 디렉터리 하나를 보고 끝내지 말고 항상:
> ```powershell
> Get-ChildItem C:\Users -Force | Select-Object Name
> ```
> 리눅스면 `ls -la /home` · `ls -la /root`. **비용 3초, [[Hutch]] 에서는 그 3초가 플래그 하나였음.**

**지우기 전 원문**

```text
### 6-8. `local.txt` 를 놓친 진짜 원인 — `C:\Users` 를 나열하지 않았다

이 박스에서 잃은 것은 플래그 하나다. 원인을 정확히 짚어야 다음 박스에서 안 반복한다.

**틀린 진단**: "`fmcsorley` 로 셸을 안 열어봐서 놓쳤다." — §5에서 보였듯 `PSRemoteUsers`·`RemoteDesktopUsers` 가 둘 다 0명이라 그 셸은 애초에 열리지 않는다.

**맞는 진단**: **14:52 에 도메인 관리자 대화형 셸을 손에 쥐고 있었는데 `C:\Users` 를 한 번도 나열하지 않았다.** `cd Desktop` → `dir` → `type proof.txt` 로 곧장 갔고, 그 디렉터리에 `proof.txt` 하나뿐인 것을 보고 "이 박스는 플래그가 하나" 라고 결론지었다. 관리자 프로필에 `local.txt` 가 없는 것은 정상인데 그것을 플래그 개수의 근거로 삼았다.

> [!tip] 일반화 — 플래그 개수를 «내가 본 디렉터리»로 추론하지 마라
> 개수는 포털이 `N/M` 으로 알려준다. 셸을 잡았으면 **디렉터리 하나를 보고 끝내지 말고** 항상:
> ```powershell
> Get-ChildItem C:\Users -Force | Select-Object Name
> ```
> 리눅스면 `ls -la /home` · `ls -la /root`. **비용 3초**, 이 박스에서는 그 3초가 플래그 하나였다.
```

⚠️ **「틀린 진단」 부분은 노트에 남겼음** — 그 박스의 `local.txt` 미확보 사유이자 BloodHound 근거가 붙은 판정이라 박스 고유임(`Post-Exploitation` 절).

---

## 제안 2 — `B-52. 실패 표시가 실패를 뜻하지 않는다 — NTLM 상태 코드를 읽는다` **병합**

기존 항목이 「196회를 뿌렸고 잠금 정책이 없어서 살았음」까지만 담고 있음. **올바른 순서**가 빠져 있음.

**넣을 본문**

> **스프레이 순서는 셋으로 고정임** — [[Hutch]] 는 ①을 건너뛰고 ③ 대신 전조합을 돌렸음:
> ```bash
> # ① 잠금 정책 확인 (자격증명 하나가 필요. 익명이 되면 enum4linux-ng -P)
> nxc smb <IP> -u <user> -p <pass> --pass-pol
> # ② 사용자 목록 정제 (계정을 잠그지 않음)
> kerbrute userenum --dc <IP> -d <domain> users.txt
> # ③ 비밀번호 «하나» × 사용자 전원. 잠금 관찰 창(보통 30분)마다 한 번
> nxc smb <IP> -u users.txt -p '<password>' --continue-on-success
> ```
> **사용자당 시도 횟수를 1로 유지하는 것이 핵심임.** `--no-bruteforce` 는 행 단위 짝짓기(`user1 => password1`)이지 스프레이가 아님.
> ⚠️ `--ignore-pw-decoding` 은 *"Ignore non UTF-8 characters when decoding the password file"* 라 **`-p` 가 파일일 때만** 의미가 있음(실측). 리터럴 문자열이면 아무 일도 하지 않음.
> ⚠️ **결과적으로 무사했다고 옳은 순서였던 것이 아님** — [[Hutch]] 는 잠금 정책이 «없어서» 살았고, 임계값이 5나 10 이었으면 도메인 전 계정이 잠겨 리버트 말고는 복구가 없었음.

**지우기 전 원문**

```text
> **반사 셋**:
> 1. **스프레이 전에 잠금 정책을 확인한다** — `nxc smb <IP> -u <user> -p <pass> --pass-pol` (자격증명 하나는 필요하다). 익명이 되면 `enum4linux-ng -P <IP>`
> 2. **행 단위 짝짓기를 원하면 `--no-bruteforce`** — `--help` 원문: *"No spray when using file for username and password (user1 => password1, user2 => password2)"*
> 3. **진짜 스프레이는 «비밀번호 하나 × 사용자 전원»** 으로, 잠금 관찰 창(보통 30분)마다 한 번씩 돌린다. 사용자당 시도 횟수를 1로 유지하는 것이 핵심이다
>
> `--ignore-pw-decoding` 은 *"Ignore non UTF-8 characters when decoding the password file"* 다(실측). **`-p` 가 파일일 때만 의미가 있고**, §3-2처럼 리터럴 문자열이면 아무 일도 하지 않는다.

### 6-3. 스프레이 순서가 위험했다 — 잠금 정책을 확인하지 않았다

§3-1의 196회 전조합이다. **`--pass-pol` 을 먼저 돌리지 않았고, `--no-bruteforce` 도 쓰지 않았다.**
결과적으로 잠금 정책이 없어서 무사했지만, **이건 «성공한 절차»가 아니라 «운이 좋았던 절차»** 다. 노트는 그것을 그대로 적어 둔다 — 성공했다고 옳은 순서였던 것은 아니다.

올바른 순서:
    # ① 잠금 정책 확인 (자격증명 하나가 필요. 익명이 되면 enum4linux-ng -P)
    nxc smb <IP> -u <user> -p <pass> --pass-pol
    # ② 사용자 목록 정제 (계정을 잠그지 않는다)
    ./kerbrute_linux_386 userenum --dc <IP> -d <domain> users.txt
    # ③ 비밀번호 «하나» × 사용자 전원
    nxc smb <IP> -u users.txt -p '<password>' --continue-on-success
```

---

## 제안 3 — `B-51. «사용자 설명 필드»는 AD 의 자격증명 저장소다` **병합**

기존 항목의 `-o ldif_wrap=no` 경고에 **사후 복구법과 base64 표기**가 빠져 있음.

**넣을 본문**

> **이미 접힌 출력을 사후에 펴는 법** — `sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D'`.
> ⚠️ 옵션은 **하이픈이 아니라 밑줄**(`ldif_wrap`)이고 `-o` 로 준다(실측, `ldapsearch -h`: *"any libldap ldap.conf options, plus ldif_wrap=<width> (in columns, or "no" for no wrapping)"*).
> ⚠️ 값이 `description::` 처럼 **콜론 두 개**로 나오면 base64 임(비-ASCII 가 섞였다는 뜻) — `base64 -d` 해야 읽힘.
> ⚠️ **`grep description:` 만 하면 어느 개체의 속성인지 알 수 없음** — LDIF 의 `dn:` 줄이 따로 떨어져 있고 grep 이 그것을 버림. 그래서 [[Hutch]] 는 정보 부족 상태에서 **전원 스프레이**를 했고 그것이 정답이었음. 처음부터 짝지어 뽑으려면:
> ```bash
> ldapsearch -x -H ldap://<IP> -b '<baseDN>' '(objectClass=user)' sAMAccountName description \
>   | sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D' \
>   | grep -A1 -i 'sAMAccountName'
> ```
> [[Hutch]] 는 **비밀번호가 값의 앞쪽에 있어서 살았음** — `grep` 결과가 `Please c` 에서 끊겼고, 뒤쪽에 있었으면 잘려 나간 채 「설명 필드에는 아무것도 없다」로 결론냈을 것임.

**지우기 전 원문**

```text
> **이 박스는 운 좋게 비밀번호가 앞쪽에 있어서 살았다.** 뒤쪽에 있었으면 비밀번호가 잘려 나갔을 것이고, 그걸 알아채지 못한 채 "설명 필드에는 아무것도 없다"고 결론냈을 것이다.
> **접힘을 «애초에 끄는» 법** — OpenLDAP `ldapsearch` 의 `-o` 옵션이다(실측, `ldapsearch -h`):
> -o <opt>[=<optparam>] any libldap ldap.conf options, plus
>            ldif_wrap=<width> (in columns, or "no" for no wrapping)
> **하이픈이 아니라 밑줄(`ldif_wrap`)이다.** 이미 접힌 출력을 사후에 펴려면 `sed -e ':a' -e '$!N;s/\n //;ta' -e 'P;D'`.
> 또한 값이 `description::` 처럼 콜론 두 개로 나오면 **base64**다(비-ASCII가 섞였다는 뜻) — `base64 -d` 해야 읽힌다.

### 왜 «비밀번호가 적힌 그 사람» 말고 전원에게 뿌렸는가 — 옳은 판단이다

`description`은 `fmcsorley`의 것이었지만, 그 사실은 BloodHound를 돌린 «뒤에» 확정됐다. `grep description:` 만으로는 **어느 개체의 속성인지 알 수 없다**(LDIF에서 `dn:` 줄이 따로 떨어져 있고 grep이 그것을 버렸다).
그래서 **전원 스프레이가 정보 부족 상태에서의 정답**이다. 비용은 사용자당 1회 — 잠금 정책이 정상이라면 안전한 수준이다.
```

⚠️ 노트에도 접힘 경고와 짝짓기 명령은 **재현에 필요해 남겼음**(중복이 아니라 재현 자료임).

---

## 제안 4 — `B-54. DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다` **병합**

**넣을 본문**

> **LAPS 평문을 얻으면 도메인 인증과 로컬 인증을 «둘 다» 시도할 것.** 어느 쪽이 통하는지는 대상이 DC 냐 멤버 서버냐에 달렸음 — NTLM 의 `NTOWFv2 = HMAC-MD5(NT해시, UPPER(user)+domain)` 계산에 **도메인 문자열이 키의 일부로** 들어가므로 같은 비밀번호라도 응답값이 다름. `-d <domain>` 은 NTDS 에서, `--local-auth` 는 로컬 SAM 에서 검증함.
> [[Hutch]] 실측 — DC 라 **도메인 인증**이 통했고(`(Pwn3d!)`), `--local-auth` 였으면 DSRM 계정을 대상으로 삼아 실패했을 것임. 근거는 해시 대조임:
> ```text
> 도메인 Administrator (DRSUAPI 구간, RID 500) : d1722dc7b059af8df626c88ee2d279e4  ← LAPS 평문의 MD4(UTF-16LE) 와 일치
> 로컬 SAM Administrator (SAM 구간, RID 500)   : bab179eba40e413086aa37742476c646  ← 불일치(DSRM 계정)
> ```
> **DC 로 승격되면 로컬 SAM 은 사실상 폐기되고 `Administrator` 는 도메인 계정이 됨.** SAM 에 남는 RID 500 은 DSRM(Directory Services Restore Mode) 계정이라 평상시 로그온에 쓰이지 않음 — 둘의 해시가 다른 것이 정상임.
> **어느 쪽인지 모를 때의 판정 한 줄** — `python3 -c "import hashlib;print(hashlib.new('md4','<평문>'.encode('utf-16le')).hexdigest())"` 로 계산해 덤프와 대조.
> ⚠️ **LAPS 평문은 만료됨**(`ms-Mcs-AdmPwdExpirationTime`). 평문을 얻으면 **해시를 먼저 확보**해 둘 것 — 그리고 `[`·`-`·`.` 이 섞인 LAPS 비밀번호는 셸 인용 사고를 부르므로 PtH 가 실무적으로 더 안전함.
> ⚠️ **`ms-Mcs-AdmPwd` 가 0건이면 「없는 것」이 아니라 「이름이 다른 것」일 수 있음** — Windows LAPS(2023+)는 `msLAPS-Password`/`msLAPS-EncryptedPassword` 임. pyLAPS 의 필터가 `(ms-MCS-AdmPwd=*)` 라 **권한이 없으면 에러 없이 조용히 0건**이 되는 것도 같은 함정임.

**지우기 전 원문**

```text
실전 교훈: LAPS 값을 얻으면 **로컬 인증(`--local-auth`)과 도메인 인증을 «둘 다» 시도하라.** 어느 쪽이 통할지는 대상이 DC인지 멤버 서버인지에 달렸다.

이 박스는 왜 **`--local-auth` 가 아니라 `-d hutch.offsec`** 이었나

NTLM의 ③에서 `NTOWFv2` 계산에 도메인 문자열이 «키의 일부»로 들어간다(`HMAC-MD5(NT해시, UPPER(user) + domain)`). 즉 **같은 비밀번호라도 도메인이 다르면 응답값이 다르다.**
- `-d hutch.offsec` → 도메인 계정 데이터베이스(NTDS)에서 검증
- `--local-auth` → **로컬 SAM**에서 검증. 도메인 부분에 컴퓨터 이름이 들어간다
DC에서 이 둘은 완전히 다른 계정을 가리킨다(§2-4의 해시 대조가 그것을 증명한다 — `d1722dc7…` vs `bab179eb…`).
**LAPS 평문을 얻으면 둘 다 시도하라.** 멤버 서버라면 `--local-auth` 가, DC라면 도메인 인증이 통한다.

### C. LAPS 평문을 얻었을 때 (`+CS0-.gm5l4o-[`)
1. **도메인 인증과 로컬 인증을 «둘 다» 시도한다** — `-d <domain>` / `--local-auth`. 어느 쪽인지는 대상이 DC냐 멤버 서버냐에 달렸다(§2-4)
2. **`(Pwn3d!)` 를 확인했으면 곧바로 `secretsdump`** — 가능하면 `-just-dc-ntlm`(조용하다)
3. **`ms-Mcs-AdmPwdExpirationTime` 을 확인하라** — 만료가 임박했으면 평문이 곧 무효가 된다. 해시를 먼저 확보해 두는 것이 안전하다
4. **다른 컴퓨터의 LAPS도 읽히는지** 확인 — `pyLAPS --action get` 은 읽을 수 있는 전부를 나열한다. 도메인에 서버가 여럿이면 여기서 횡적 이동이 시작된다
```

---

## 제안 5 — `B-5. Active Directory` **신규**

역검색: `_PLAYBOOK` 전문에 `AdminSDHolder` 0건, `adminCount` 0건. 증상(「관리자 계정이 안 보인다」)으로도 해당 항목 없음.

**제목(안)** — `B-5-?. 익명·저권한 열거에서 관리자 계정이 «안 보이는» 것은 정상이다`

**넣을 본문**

> **증상** — 익명 LDAP·SMB 열거로 사용자 목록은 나오는데 `Administrator`·`krbtgt`·도메인 관리자 계정이 하나도 없음. 「열거가 막혔다」로 오판해 방향을 틀기 쉬움.
> **원인은 AdminSDHolder / SDProp 임.** AD 는 특권 그룹(Domain Admins·Enterprise Admins·Administrators·Account Operators 등)의 멤버에게 `adminCount=1` 을 찍고, 60분마다 `SDProp` 프로세스가 그 개체들의 DACL 을 `CN=AdminSDHolder` 템플릿으로 덮어쓰며 **상속을 끊음.** 도메인 상위에 붙은 관대한 읽기 ACE 가 이 계정들에는 도달하지 않음.
> [[Hutch]] 실측 — 익명 조회 14개 vs 인증 수집 18개. **18 − 3(`adminCount=true`: Administrator·krbtgt·domainadmin) − 1(BloodHound 가 만드는 가상 개체 `NT AUTHORITY`) = 14.** 어긋남이 없음.
> → **`adminCount=1` 계정은 원래 마지막에 보임.** 자격증명을 하나 얻으면 즉시 다시 볼 것 — `nxc ldap <IP> -u U -p P --users --admin-count` 가 5초임.
> → 부수 효과: **덤프에 「숨어 있던 관리자 계정」이 있음.** [[Hutch]] 의 `domainadmin`(RID 1116)이 그것으로, 익명 열거에서는 안 보이지만 Domain Admins 멤버였음.

**지우기 전 원문**

```text
> [!danger] 익명 조회 결과에서 `Administrator`·`krbtgt`·`domainadmin` 이 «빠져 있다» — 이유를 알면 오판을 피한다
> 위 목록에 도메인 관리자 계정이 하나도 없다. **열거가 실패한 것이 아니다.**
> **18개(BloodHound) − 3개(`adminCount=true`) − 1개(가상 개체) = 14개(익명 조회).** 어긋남이 없다.
> **메커니즘 — AdminSDHolder / SDProp.** AD는 특권 그룹(Domain Admins·Enterprise Admins·Administrators·Account Operators 등)의 멤버에게 `adminCount=1`을 찍고, 60분마다 `SDProp` 프로세스가 그 개체들의 DACL을 `CN=AdminSDHolder` 의 템플릿으로 덮어쓴다. 덮어쓴 DACL은 상속을 끊는다. 그래서 도메인 상위에 붙은 관대한 읽기 ACE가 이 계정들에는 도달하지 않는다.
> 반사로 만들 것: 익명/저권한 열거에서 **관리자 계정이 안 보이는 것은 정상**이다. "열거가 막혔다"고 판단해 방향을 틀지 마라. `adminCount=1` 계정은 원래 마지막에 보인다.

- **`domainadmin`(RID 1116) 계정** — Domain Admins 멤버이고 해시(`8730fa0d1014eb78c61e3957aa7b93d7`)도 확보했다. 익명 열거에서는 안 보였던 계정이므로(§1-3), "숨어 있던 관리자 계정"의 좋은 사례다
```

⚠️ 노트에도 이 산술은 **남겼음** — 「익명 조회가 14개인데 BloodHound 는 18개」라는 관측이 그 절의 재현 근거이기 때문임.

---

## 제안 6 — `B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다` **병합**

**넣을 본문**

> **덤프를 받으면 반드시 돌릴 한 줄 — 중복 해시 탐지:**
> ```bash
> cut -d: -f4 dump.txt | sort | uniq -c | sort -rn | head
> ```
> [[Hutch]] 실측 — RID 1103~1114(`rplacidi`…`agitthouse`) **12명이 전원 `c11f1141ab4c1e825a11f15836e6978f`** 로 같음. 대량 계정 생성 시 초기 비밀번호를 동일하게 준 패턴임.
> - **하나만 크랙하면 12명분 평문**이고, **크랙조차 필요 없음** — 해시 그대로 12명 전원에게 PtH 가 됨
> - `fmcsorley`(1115)만 다른 이유는 `description` 이 적은 그대로임(「사용자 요청으로 재설정」) — **설명 필드가 사실이었음이 해시로 교차 검증됨**
> - **[가정]** 만약 사용자명 스프레이 대신 흔한 비밀번호를 뿌렸다면 `description` 을 찾기 «전에» foothold 를 잡았을 가능성이 있음 — 그 비밀번호가 무엇이었는지는 크랙하지 않아 모름. **잠금 정책 확인 후 rockyou 상위 몇 개로 한 번 돌려보는 것은 값싼 도박임**
> - 참고 상수 — `31d6cfe0d16ae931b73c59d7e0c089c0` 은 **빈 비밀번호의 NT 해시**임
> **다른 박스·다른 도메인으로 재사용될 값**이므로 시험 AD 세트에서는 특히 중요함.

**지우기 전 원문**

```text
> [!danger] 사용자 12명의 NT 해시가 전부 같다 — §4-4 덤프가 보여주는 «네 번째» 결함
> RID 1103~1114(`rplacidi`…`agitthouse`)가 전원 `c11f1141ab4c1e825a11f15836e6978f` 다. 즉 **12명이 같은 비밀번호를 쓴다.**
> `fmcsorley`(1115)만 다른 이유는 §2-2의 `description` 그대로다 — "사용자 요청으로 비밀번호를 재설정했다". **설명 필드가 사실이었음이 해시로 교차 검증된다.**
> **공격자 관점에서 이것이 뜻하는 것**:
> - **하나만 크랙하면 12명분 평문**을 얻는다
> - **크랙조차 필요 없다** — 해시 그대로 12명 전원에게 PtH가 된다
> - **만약 §3-1의 사용자명 스프레이 대신 흔한 비밀번호를 뿌렸다면**, `description`을 찾기 «전에» foothold를 잡았을 가능성이 있다. **[가정]** — 그 비밀번호가 무엇이었는지는 크랙하지 않아 모른다
> **덤프를 받으면 반드시 돌릴 한 줄**:
>     cut -d: -f4 dump.txt | sort | uniq -c | sort -rn | head
> 같은 해시가 뭉쳐 있으면 대량 계정 생성 시 초기 비밀번호를 동일하게 준 것이고, 그 조직 전체의 패턴이다. **다른 박스·다른 도메인으로 재사용될 값**이므로 시험 AD 세트에서는 특히 중요하다.
> 참고로 `31d6cfe0d16ae931b73c59d7e0c089c0` 이 보이면 그건 **빈 비밀번호의 NT 해시**다 — 이 덤프에서는 `Guest`·`DefaultAccount`가 그렇다. 외워 둘 상수다.

- **공통 해시 `c11f1141ab4c1e825a11f15836e6978f` 크랙** — 12명이 공유하는 비밀번호다. `hashcat -m 1000` 로 깼다면 평문 하나가 12명분이 된다. 다른 박스로 재사용될 수 있는 자산이므로 실전이라면 반드시 시도할 값이다
```

⚠️ 노트에는 **「12명이 같다」는 관측과 덤프 원문**만 남겼음(덤프 해석의 일부라 박스 고유임). 일반화·`uniq -c` 한 줄·[가정]은 이관 대상임.

---

## 제안 7 — `A-12. 응답이 성공을 뜻하지 않는다` **병합**

**넣을 본문**

> **nmap 의 `Allowed Methods`·`Potentially risky methods` 는 «허용의 증거»가 아님.** `http-methods`·`http-webdav-scan` NSE 는 `OPTIONS` 응답의 `Allow`/`Public` 헤더를 그대로 옮길 뿐 **실제로 던져 보지 않음.** 그 목록은 「서버가 그 모듈을 로드했다」이지 「인증 없이 허용된다」가 아님.
> [[Hutch]] 실측 — IIS 10.0 이 `PUT`·`DELETE`·`MOVE`·`MKCOL`·`COPY` 를 보고했으나 **실제로 던져본 기록이 하나도 없음.** 그리고 그 미시도가 플래그 하나(`local.txt`)를 잃은 지점일 수 있음 `[가정]`.
> **30초 검증 두 줄:**
> ```bash
> curl -sS -X PUT http://<IP>/t.txt --data 'x' -o /dev/null -w '%{http_code}\n'   # 201/204 면 진짜 쓰기
> davtest -url http://<IP>/                                                        # 업로드 가능 확장자 자동 판별
> ```
> ⚠️ **배제했으면 「배제했다」를 기록할 것.** 「안 봤는데 마침 없었다」는 재현 가능한 전략이 아니고, 막혔을 때 되돌아올 지점이 남지 않음. `IIS Windows Server` 같은 기본 시작 페이지 제목은 「아무것도 배포돼 있지 않다」의 **약한** 신호일 뿐임.

**지우기 전 원문**

```text
> [!warning] `http-webdav-scan` 이 «위험 메서드»를 잔뜩 뱉었지만 이 박스의 경로가 아니다
> **그러나 이 목록은 «IIS가 WebDAV 모듈을 로드했다»는 사실만 말한다. 그 메서드가 «인증 없이 허용된다»는 뜻이 아니다.** `http-methods` NSE는 `OPTIONS` 응답의 `Allow`/`Public` 헤더를 그대로 옮길 뿐, 실제로 시도해 보지 않는다.
> 일반화: `PUT`이 `Allow`에 보이면 **반드시 실제로 던져 확인하라.** 30초다:
> curl -sS -X PUT http://<IP>/test.txt --data 'x' -o /dev/null -w '%{http_code}\n'   # 201 이면 진짜
> davtest -url http://<IP>/                                                          # 업로드 가능 확장자 자동 판별
> **응답 코드를 보지 않고 헤더만 믿는 것**이 [[Crane]]·[[Squid]]에서 반복된 "응답이 성공을 뜻하지 않는다" 패턴이다.

### 정답 경로를 아꼈다는 점은 맞지만, 근거가 있어서 옳았던 것은 아니다
결과적으로 LDAP 쪽으로 `proof.txt` 까지 갔다. 하지만 **"안 봤는데 마침 없었다"** 는 재현 가능한 전략이 아니다.
**실제로는 이렇게 «값싸게» 배제했어야 한다** — 합쳐서 3분:
    curl -sSI http://<IP>/
    curl -sS -X PUT http://<IP>/t.txt --data x -o /dev/null -w '%{http_code}\n'
    feroxbuster -u http://<IP>/ -x aspx,asp,txt,config -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
`IIS Windows Server` 라는 기본 시작 페이지 제목은 "아무것도 배포돼 있지 않다"는 «약한» 신호다. 약한 신호로 배제하되, **배제했다는 사실을 기록하라.** 그래야 막혔을 때 되돌아올 지점이 남는다.
```

---

## 제안 8 — `A-6. 판단·검증 (메타)` **신규**

역검색: 증상 「노트에 적힌 명령을 그대로 쳤는데 출력이 다르다」로 해당 항목 없음. `A-63`(무엇을 보냈는지 기록이 없다)·`A-6-11`(박스 이름이 증거 사슬을 대신함)과 **다른 증상**임.

**제목(안)** — `A-6-?. 기록된 명령으로 기록된 출력이 재현되지 않는다 — 덮지 말고 차이를 명시하라`

**넣을 본문**

> **증상** — 노트의 명령을 그대로 쳤는데 화면이 다름. 둘 중 하나가 틀린 것이고, 덮으면 다음 사람이 재현에 실패함.
> [[Hutch]] 실측 — 기록된 명령은 `ldapsearch -H ldap://<IP> -x -s base` 인데 출력에 `Enter LDAP Password:` 가 있음. 2026-08-20 에 같은 Kali(OpenLDAP `ldapsearch 2.6.10`)로 때려 확인:
> ```bash
> ldapsearch -x -H ldap://127.0.0.1:389 -s base
> ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)      ← 프롬프트가 «없다»
>
> ldapsearch -x -W -H ldap://127.0.0.1:389 -s base < /dev/null
> Enter LDAP Password:                                        ← -W 가 프롬프트를 만든다
> ```
> **`-x` 단독은 절대 비밀번호를 묻지 않음.** 실제로 친 명령에는 `-W` 가 함께 있었거나 전사에서 누락된 것임.
> **결과에는 영향이 없었음** — `-D`(바인드 DN)가 없으므로 무엇을 넣든 익명 바인드이고 `result: 0 Success` 가 그것을 확인함.
> → **정정하지 말고 «차이를 명시»할 것.** 어느 쪽이 원본인지 모르는 상태에서 명령을 고치면 실측을 손으로 다시 쓰는 것이 됨. 「이 명령으로는 이 출력이 안 나온다」를 적어 두는 것이 정직하고 재현에도 도움이 됨.
> → **개작·감사의 핵심 작업이 이 대조임** — 「기록된 명령을 그대로 쳤을 때 기록된 출력이 나오는가」.

**지우기 전 원문**

```text
### 6-2. 기록된 `ldapsearch` 명령으로는 기록된 출력이 안 나온다

§1-2의 `Enter LDAP Password:` 문제다. **실측으로 `-x` 단독은 프롬프트를 내지 않음을 확인**했고, `-W`가 필요하다는 것도 확인했다.
결과에는 영향이 없지만(익명 바인드는 동일), **"노트대로 쳤는데 화면이 다르다"는 상황은 재현자를 반드시 혼란시킨다.** 그래서 정정하지 않고 차이를 명시했다.

> 2026-08-20에 같은 Kali(OpenLDAP `ldapsearch 2.6.10`)에서 때려 본 결과:
> ┌──(kali㉿kali)-[~]
> └─$ ldapsearch -x -H ldap://127.0.0.1:389 -s base
> ldap_sasl_bind(SIMPLE): Can't contact LDAP server (-1)      ← 프롬프트가 «없다»
>
> ┌──(kali㉿kali)-[~]
> └─$ ldapsearch -x -W -H ldap://127.0.0.1:389 -s base < /dev/null
> Enter LDAP Password:                                        ← -W 가 프롬프트를 만든다
> 이 노트가 이걸 굳이 적는 이유: "기록된 명령을 그대로 쳤을 때 기록된 출력이 나오는가"를 검증하는 것이 개작의 핵심 작업이기 때문이다. 안 나오면 둘 중 하나가 틀린 것이고, 그걸 덮으면 다음 사람이 재현에 실패한다.
```

⚠️ 노트에는 **경고 한 덩어리로 압축해 남겼음** — 그 블록의 재현자에게 직접 필요한 정보라 박스 고유이기도 함.

---

## 제안 9 — `A-63. 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다` **병합**

**넣을 본문**

> **박스를 «시작할 때» 세션 자체를 파일로 남길 것 — 비용 5초, 회수는 「노트를 다시 쓸 수 있는가」 전체임.**
> ```bash
> mkdir -p ~/PG/<박스>/ && cd ~/PG/<박스>
> script -f -a session.log            # 모든 입출력을 파일로. -f 는 즉시 flush
> tmux pipe-pane -o 'cat >> ~/PG/<박스>/pane.log'   # tmux 안이면 이쪽
> history -100 > ~/PG/<박스>/history.txt            # 최소한 박스를 끝낼 때마다
> ```
> [[Hutch]] 실측 — 작업이 2026-05-14~15 인데 `~/.zsh_history`(2552행)에 **그 구간이 남아 있지 않음.** 버퍼가 밀려 나갔고 같은 파일에 [[Resourced]](7월 3~6일) 구간은 100행 넘게 살아 있음. 그래서 [[Resourced]] 는 실패 12건을 **명령 단위**로 적을 수 있었고 [[Hutch]] 는 못 했음.
> **무엇이 복원됐고 무엇이 영구 손실인지 갈라 둘 것:**
>
> | 복원된 것 | 출처 | 복원 못 한 것 |
> |---|---|---|
> | 명령·출력·플래그·해시·IP | 원본 노트 본문 | 실패한 시도의 횟수와 순서 |
> | ACE·그룹·`adminCount`·`haslaps` | BloodHound JSON 7개 | 어떤 BloodHound 쿼리를 돌렸는가 |
> | 진행 시각(분 단위) | 스크린샷 파일명 + 파일 mtime | 각 단계 사이에 무엇을 시도했는가 |
> | LAPS 속성명·필터 | `~/git/pyLAPS/pyLAPS.py` 소스 | pyLAPS 를 왜 골랐는가(`nxc -M laps` 대신) |
>
> ⚠️ **히스토리 부재는 「미실행의 증거」가 아님**(A-64 의 유보와 같은 선). [[Hutch]] 는 그 구간 히스토리가 0건인데 **스크린샷 6장에 `┌──(kali㉿kali)-[~/PG/Hutch]` 프롬프트가 그대로 찍혀 있음** — 대화형 터미널이 실재했다는 양성 증거임. 등급 상한은 `근거부족` 임.

**지우기 전 원문**

```text
### 6-9. 셸 히스토리를 잃었다 — 무엇이 복원됐고 무엇이 영원히 사라졌는가

이 박스의 작업은 2026-05-14~15인데, `~/.zsh_history`(2552행)에는 **그 구간이 남아 있지 않다.** 버퍼가 밀려 나갔다. 같은 파일에 [[Resourced]](7월 3~6일) 구간은 100행 넘게 살아 있다.
| 복원할 수 있었던 것 | 출처 | 복원 못 한 것 |
| 명령·출력·플래그·해시·IP | 원본 노트 본문 | 실패한 시도의 횟수와 순서 |
| ACE·그룹·`adminCount`·`haslaps` | BloodHound JSON 7개 | 어떤 BloodHound 쿼리를 돌렸는가 |
| 진행 시각(분 단위) | 스크린샷 파일명 + 파일 mtime | 각 단계 사이에 무엇을 시도했는가 |
| LAPS 속성명·필터 | `~/git/pyLAPS/pyLAPS.py` 소스 | pyLAPS를 왜 골랐는가(`nxc -M laps` 대신) |
| 도구 플래그 동작 | Kali에서 재실행 | — |

> **그래서 실무 규율은 이것이다 — 박스를 시작할 때 세션을 기록으로 남겨라.**
> mkdir -p ~/PG/<박스>/ && cd ~/PG/<박스>
> script -f -a session.log            # 모든 입출력을 파일로. -f 는 즉시 flush
> # (또는) tmux 안에서
> tmux pipe-pane -o 'cat >> ~/PG/<박스>/pane.log'
> **비용 5초, 회수는 «노트를 다시 쓸 수 있는가» 전체다.**
> history -100 > ~/PG/<박스>/history.txt      # 박스를 끝낼 때마다
```

---

## 제안 10 — `C-5. 남긴 흔적` **병합**

**넣을 본문**

> **`impacket-secretsdump` 는 «흔적을 만드는» 도구임 — 옵션 하나로 안 만들 수 있음.**
> 기본 실행은 SAM/LSA 를 원격 레지스트리로 읽으려고 **`RemoteRegistry` 서비스를 시작시킴.** 끝나고 되돌리다 실패하는 경우가 있음:
> ```text
> [*] Service RemoteRegistry is in stopped state
> [*] Starting service RemoteRegistry
> ...
> [*] Stopping service RemoteRegistry
> [-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING
> ```
> [[Hutch]] 실측 — 다른 서비스가 의존 중이라 **시작된 채로 방치됨.** 실전이라면 `sc.exe \\<호스트> stop RemoteRegistry`(원래 disabled 였다면 `config … start= disabled` 까지).
> → **`-just-dc-ntlm` 은 DRSUAPI 만 쓰므로 `RemoteRegistry` 를 건드리지 않음.** 조용하고 빠름:
> ```bash
> impacket-secretsdump '<도메인>/administrator:<pass>@<IP>' -just-dc-ntlm
> impacket-secretsdump '<도메인>/administrator:<pass>@<IP>' -just-dc-user krbtgt   # 한 계정만
> ```
> ⚠️ **DCSync 는 이벤트 4662 에 복제 GUID 가 그대로 찍힘** — 성숙한 SOC 의 표준 탐지 규칙임. 출력 끝의 `KeyError: 'Cryptodome.Cipher.AES'` 트레이스백은 **덤프가 나온 뒤** 파이썬 종료 중 발생하는 것이라 실패가 아님. 이것을 보고 재실행하면 4662 만 두 배가 됨.

**지우기 전 원문**

```text
### 6-5. `RemoteRegistry` 를 켜 놓고 끄지 못했다 — 흔적이 남았다

`secretsdump`는 SAM/LSA를 원격 레지스트리로 읽기 위해 `RemoteRegistry` 서비스를 «시작»했고(출력 첫 줄 `Service RemoteRegistry is in stopped state` → `Starting service RemoteRegistry`), 끝나고 **되돌리는 데 실패**했다. 다른 서비스가 의존 중이었기 때문이다.

### 실전 침투테스트라면 직접 정리해야 하는 흔적이다
# 남은 것: RemoteRegistry 서비스가 «시작된 상태»로 방치됨
sc.exe \\HUTCHDC stop RemoteRegistry
sc.exe \\HUTCHDC config RemoteRegistry start= disabled     # 원래 disabled 였다면
**이 흔적을 피하려면 애초에 SAM/LSA를 뜨지 않으면 된다**:
impacket-secretsdump 'hutch.offsec/administrator:<pass>@<IP>' -just-dc-ntlm
`-just-dc*` 계열은 **DRSUAPI만 쓰므로 `RemoteRegistry`를 건드리지 않는다.** 조용하고 빠르다.

DCSync는 «시끄럽다» — 흔적을 알고 써라
- **이벤트 4662**(개체에 대한 오퍼레이션)에 위 GUID가 그대로 찍힌다. 성숙한 SOC의 표준 탐지 규칙이다
- `secretsdump`가 원격 레지스트리로 SAM/LSA를 먼저 뜨기 때문에 `RemoteRegistry` 서비스를 시작시킨다 — §6-5의 흔적
- **`-just-dc-ntlm` 을 쓰면** SAM/LSA 단계를 건너뛰고 NTDS만 받아 훨씬 조용하다:
  impacket-secretsdump 'hutch.offsec/administrator:<pass>@<IP>' -just-dc-ntlm
  impacket-secretsdump 'hutch.offsec/administrator:<pass>@<IP>' -just-dc-user krbtgt   # 한 계정만
```

⚠️ 노트의 「남긴 흔적」 표에는 **이 박스에서 실제로 남은 것**만 남겼음(`RemoteRegistry` 방치 · 4625 · 4662 · 4768/4771 · Kali 측 덤프 보관).

---

## 제안 11 — `B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다` **병합**

**넣을 본문**

> **자격증명 하나를 얻으면 «5초짜리 배제»를 배치로 쏠 것.** 실패해도 그 자체가 정보이고, 나중에 「해봤나」를 되짚는 비용이 사라짐:
> ```bash
> nxc winrm <IP> -u <user> -p <pass>                    # 5초 — Remote Management Users 인가
> nxc ldap  <IP> -u <user> -p <pass> --users --admin-count   # 5초 — 익명에 안 보이던 관리자 계정
> nxc smb   <IP> -u <user> -p <pass> --pass-pol          # 5초 — 스프레이 위험도 사후 확인
> impacket-GetUserSPNs -request -dc-ip <IP> <dom>/<user>:<pass>   # 10초 — Kerberoast
> nxc smb   <IP> -u <user> -p <pass> -M gpp_password -M gpp_autologin   # SYSVOL
> ```
> [[Hutch]] 실측 — 위 다섯을 **하나도 돌리지 않았고** 산출물에 흔적이 없음. Kerberoast 는 사후에 BloodHound 덤프로 확인하면 SPN 이 걸린 일반 계정이 없어 **결과적으로 소득이 없었을 것** `[가정]`. `--pass-pol` 은 196회 전조합이 얼마나 위험했는지를 사후에라도 알려줬을 값임.
> ⚠️ **「결과적으로 실패했을 시도」도 5초에 배제되는 것이 값임.** [[Resourced]] 의 `L.Livingstone` 은 같은 `nxc winrm` 이 통한 경우임 — **되는지 여부는 도메인마다 다르므로 매번 침.**

**지우기 전 원문**

```text
그 밖에 `fmcsorley` 자격증명을 얻은 직후 했어야 할 것들 — 셸은 안 됐겠지만 **열거는 됐다**:

| 시도했어야 할 것 | 왜 | 비용 |
| `nxc winrm <IP> -u fmcsorley -p 'CrabSharkJellyfish192'` | **결과적으로 실패했을 시도지만 «5초에 배제»되는 것이 값이다.** [[Resourced]]의 `L.Livingstone` 은 같은 시도가 통한 경우다 — 되는지 여부는 도메인마다 다르니 매번 친다 | 5초 |
| `nxc ldap <IP> -u .. -p .. --users --admin-count` | 익명으로 안 보이던 `Administrator`·`domainadmin` 이 인증하면 보인다(§1-3) | 5초 |
| `impacket-GetUserSPNs -request` | Kerberoast. 이 도메인엔 대상이 없었지만 확인은 했어야 한다 | 10초 |
| `nxc smb <IP> -u .. -p .. --pass-pol` | §3-1의 196회 스프레이가 얼마나 위험했는지 사후에라도 알 수 있었다 | 5초 |

- **Kerberoasting** — `impacket-GetUserSPNs -request` 를 돌린 기록이 없다. `fmcsorley` 자격증명을 얻은 직후가 적기였다. BloodHound 덤프로 사후 확인하면 일반 사용자에 SPN이 걸린 계정은 보이지 않았다 — 결과적으로 소득이 없었을 것이다. **[가정]**
```

---

## 제안 12 — `D. 시간 배분 · 손절 기준` **신규 실측 항목**

**넣을 본문**

> 실측([[Hutch]], AD Intermediate · **부분 1/2**) — 이틀에 걸침. 5/14 16:14 nmap → 5/15 10:52 익명 LDAP 열거(하루 공백) → 11:14 kerbrute → 13:23 BloodHound 수집 → **14:28 `ReadLAPSPassword` 엣지** → 14:35 LAPS 평문 → 14:49 도메인 관리자 확인 → 14:50 DCSync → 14:52 `proof.txt`.
> **태운 곳은 둘임:**
> - **13:23 → 14:28 의 65분** — 데이터를 손에 쥐고 «해석»에만 쓴 시간. 엣지를 본 뒤에는 **24분 만에** 박스가 끝났음(B-53)
> - **11:14 → 14:28 의 약 3시간** — AS-REP roast 와 사용자명 전조합 스프레이를 먼저 하고 `description` 전수 조회를 가장 늦게 했음. **LDAP 이 익명으로 읽히면 `description`·`info`·`comment` 전수 조회가 첫 수임** — 비용 10초, 회수는 박스 전체임(B-51)
> - **`local.txt` 회수는 «하지 않음»** — 3초짜리 `Get-ChildItem C:\Users -Force` 를 안 쳐서 플래그 하나를 잃었음(C-3)
> **구간별 손절 기준** — LDAP RootDSE 가 되면 곧바로 `-b <baseDN>` 서브트리, 안 되면 즉시 SMB/kerbrute 로 전환(10분) · AS-REP 0건이면 미련 없이 접을 것(다시 해도 같음) · `ReadLAPSPassword` 엣지를 보면 1분 안에 `pyLAPS`/`nxc ldap -M laps`.
> ⚠️ **시각 근거는 산출물 mtime + 스크린샷 파일명임**(A-64). `~/PG/Hutch/` 의 `users.txt`(10:55)·BloodHound JSON(13:23)·`~/git/pyLAPS` clone(14:30)과 스크린샷 6장이 축임. 붙여넣기 시각 ≠ 촬영 시각이라는 유보는 그대로 적용됨.

**지우기 전 원문**

```text
### 7-3. 시간 배분 — 어디서 손절했어야 하는가

| 구간 | 실제 | 적정 | 손절 기준 |
| nmap `-p-` | ~2분 | 2분 | — |
| LDAP RootDSE → 사용자 열거 | 5/14 16:17 → 5/15 10:52 (하루 걸침) | 10분 | `ldapsearch -x -s base` 가 되면 곧바로 `-b <baseDN>` 서브트리. 안 되면 즉시 SMB/kerbrute로 전환 |
| kerbrute → AS-REP roast | ~20분 | 10분 | AS-REP 0건이면 미련 없이 접어라. 다시 시도해도 결과는 같다 |
| `description` 발견 → 스프레이 | ~3시간(11:14→14:28, 다른 작업 포함) | 20분 | `description` 전수 조회는 AS-REP 직후 곧바로 했어야 한다. 이 박스에서 가장 늦게 도착한 조사다 |
| BloodHound → LAPS | ~7분(14:28→14:35) | 10분 | `ReadLAPSPassword` 엣지를 보면 1분 안에 pyLAPS/`-M laps` |
| LAPS → DCSync → `proof.txt` | ~11분(14:35→14:52) | 15분 | — |
| `local.txt` 회수 | **하지 않음 — 박스를 여기서 놓았다** | +3분 | 셸을 잡았으면 `Get-ChildItem C:\Users -Force` 를 먼저 친다. 한 디렉터리만 보고 "플래그는 하나"라고 결론짓지 마라 (§6-8) |

### 6-6. BloodHound 데이터는 13:23에 있었는데 정답 엣지는 14:28에 봤다 — 65분
| 시각 | 사건 | 근거 |
| 5/14 16:14 | nmap (구 IP `192.168.178.122`) | `nmap.log` 헤더 |
| 5/15 10:52 | 익명 LDAP 사용자 열거 | `Pasted image 20260515105250.png` |
| 5/15 10:55 | `users.txt` 저장 | `users.txt` mtime |
| 5/15 11:14 | kerbrute userenum | kerbrute 출력의 자체 타임스탬프 |
| 5/15 13:23 | BloodHound 수집 완료 | JSON 파일명 `20260515132325_*` |
| 5/15 14:28 | `ReadLAPSPassword` 엣지 확인 | `Pasted image 20260515142817.png` |
| 5/15 14:35 | pyLAPS → LAPS 평문 | `Pasted image 20260515143503.png` |
| 5/15 14:49 | 도메인 Administrator 확인 | `Pasted image 20260515144914.png` |
| 5/15 14:50 | DCSync | `Pasted image 20260515145041.png` |
| 5/15 14:52 | proof.txt | `Pasted image 20260515145246.png` |

> [!danger] 이 박스의 교훈 — `description` 전수 조회를 «맨 앞»으로 옮겨라
> 실제로는 AS-REP roast와 사용자명 스프레이에 시간을 쓴 뒤에야 `description`을 봤다. **순서가 뒤집혀 있었다.**
> **LDAP이 익명으로 읽히는 순간, 가장 먼저 할 일은 `description`·`info` 전수 조회다.** 비용 10초, 회수는 이 박스 전체다.
```

**보강 실측(이 개작에서 새로 확인)** — `~/git/pyLAPS/` 의 clone mtime 이 **2026-05-15 14:30** 임. 엣지 확인(14:28) 직후 도구를 받아 14:35 에 실행한 것이라 **「엣지를 본 뒤 24분」 서사가 도구 clone 시각으로도 뒷받침됨.**

---

## 제안 13 — `B-55. 웹 정찰이 곧 스프레이 재료다` ⑸ **병합** (AS-REP 0건 사례 추가)

**넣을 본문**

> [[Hutch]] 실측 — `impacket-GetNPUsers hutch.offsec/ -usersfile users.txt -format hashcat` 이 **13명 전원 `doesn't have UF_DONT_REQUIRE_PREAUTH set`** 로 0건. 이 0건이 확정해 주는 것 셋:
> ① 도메인에 사전인증 미요구 계정 없음 → AS-REP roast 경로 **완전 배제** ② `doesn't have ... set` 은 **계정이 존재해야 나오는 메시지**라 13명의 존재·활성이 재확인됨 ③ 사용자명 없이 뜬 `KDC_ERR_CLIENT_REVOKED` 는 `users.txt` 첫 행 `Guest` 이고 비활성이라 스프레이 대상에서 뺄 수 있음(BloodHound 의 `enabled=false` 로 확인).
> **30초에 후보 하나를 지운 것이라 실패가 아님.** LDAP 으로 미리 확인하려면(자격증명이 있을 때):
> ```bash
> ldapsearch -x -H ldap://<IP> -b '<baseDN>' \
>   '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName
> ```
> `1.2.840.113556.1.4.803` = **LDAP_MATCHING_RULE_BIT_AND**. UAC 비트 필터를 손으로 쓰려면 이 OID 가 필요함. `UF_DONT_REQUIRE_PREAUTH` = `0x400000`(십진 4194304). nxc 로도 됨 — `nxc ldap <IP> -u U -p P --asreproast out.txt`.

**지우기 전 원문**

```text
> [!tip] 0건은 «실패»가 아니라 «확정»이다 — 30초에 후보 하나를 지웠다
> 이 결과가 알려주는 것:
> 1. **이 도메인에 사전인증 미요구 계정은 없다** → AS-REP roast 경로 완전 배제
> 2. 사용자 13명이 «존재하고 활성»임이 재확인됐다 (`doesn't have ... set` 은 계정이 존재해야 나오는 메시지다)
> 3. `Guest`는 비활성이므로 스프레이 대상에서 빼도 된다
> LDAP으로 미리 확인하는 법(자격증명이 있을 때):
> ldapsearch -x -H ldap://<IP> -b '<baseDN>' \
>   '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' sAMAccountName
> `1.2.840.113556.1.4.803` = **LDAP_MATCHING_RULE_BIT_AND**. UAC 비트 필터를 손으로 쓰려면 이 OID가 필요하다.
> nxc로도 된다: `nxc ldap <IP> -u U -p P --asreproast out.txt`
```

⚠️ 노트에는 **①②③의 요지만** 두 줄로 남겼음(그 절의 판정 근거라 박스 고유임). OID·`nxc` 대안은 이관 대상임.

---

## 이관하지 않고 «삭제»한 것 (일반론·중복·배경 강의)

아래는 어느 절에도 제안하지 않았음 — `_PLAYBOOK` 에 이미 같은 내용이 있거나, 심사관 재현에 불필요한 배경 강의이거나, 노트 내 중복이었음.

| 원본 위치 | 무엇 | 사유 |
|---|---|---|
| §0 전체 | 「이 박스에서 배우는 것」 6항목 · 시험 출제 가능성 표 · [[Resourced]] 대조표 | 대조표는 노트 `## 관련` 의 [[Resourced]] 항목으로 압축해 **남김**. 나머지는 B-51·B-53·B-54 가 이미 담고 있음 |
| §1-4 후반 | `kerbrute` KDC 응답 4종 표 · 「탐지되지 않는다가 아니라 계정을 잠그지 않는다」 | `B-55 ⑴` 이 이미 `KDC_ERR_C_PRINCIPAL_UNKNOWN` vs `KDC_ERR_PREAUTH_REQUIRED` 구분을 담고 있음. 노트에는 요지 두 줄만 남김 |
| §1-4 경고 | `kerbrute` 는 시계에 민감 · `rdate` · 현행 Kali 에 `ntpdate` 없음 | `A-51` 에 **이미 그대로 있음** |
| §2-1 배경 | AS-REP 교환 흐름 ①② · Kerberoast 와의 차이 | 배경 강의. 심사관 재현에 불필요 |
| §2-2 표 | 평문이 자주 발견되는 속성 7종 표 · `nxc ldap -L` 모듈 목록 | `B-51` 이 `description`·`info`·`comment` 를 이미 담고, 모듈 목록은 `-L` 로 언제든 확인 가능 |
| §2-5 | DCSync 확장 권한 GUID 표 · 「BloodHound 에 DCSync 엣지가 보이면 이미 도메인 소유」 | GUID 두 개는 노트 산문에 **압축해 남김**. 나머지는 `B-53`·`B-54` 범위 |
| §2-6 | NTLM 3단 챌린지-응답 ASCII 다이어그램 · `STATUS_*` 8종 사전 | `B-52` 가 이미 담음. 다이어그램은 배경 강의 |
| §2-7 | 자격증명 없는 열거 채널 셋 표 + 배치 명령 | `A-1-30`(익명 SMB 표기 넷) · `F-1`(포트→첫 수) 이 이미 담음 |
| §2-8 | 결함 셋이 겹쳤다는 표 | 두 finding 의 `Vulnerability Explanation` 으로 **흡수**됨 |
| §5-2 | 시험 증거 형식 · 웹셸 0점 | `C-3` · `E` 가 이미 담음. 노트에는 한 줄만 남김 |
| §6-7 | 「재현 최소 경로 9줄」 블록 | **관측되지 않은 순서의 재구성**이라 원본도 그렇게 명시했음. 노트의 `Steps to reproduce the attack:` 두 벌이 같은 역할을 하고 그쪽은 실측 순서임 |
| §6-10 | Kerberoast·공통해시 크랙·`domainadmin`·골든티켓·WebDAV 미시도 목록 | 제안 5·6·7·11 로 **분산 이관**. 골든티켓(`krbtgt` 해시 보유·불필요)은 노트의 덤프 원문이 그대로 담고 있어 별도 서술 불요 |
| §7-1 | 도구별 시험 적법성 표 11행 | `E` 가 이미 「열거 전용은 허용」 원칙과 금지 목록을 담음. pyLAPS 는 「LDAP 속성을 읽는 스크립트」라 그 원칙에 그대로 포섭됨 |
| §7-2 | 피벗 체크리스트 A·B·D | A 는 `F-1`·`B-55`, B 는 `B-53`+제안 11, D 는 `B-6-12`+제안 6 이 담음 |
| §7-4 | 자동 도구 없이 같은 결과를 얻는 법 표 6행 | 수동 대안은 **각 finding 재현 산문에 남기는 것이 표준**이라 pyLAPS→`ldapsearch`, kerbrute→`GetNPUsers` 를 노트 본문에 남김. 나머지는 `E` 범위 |
| §6-8 후반 | 「Windows 셸을 잡자마자 칠 명령」 표 · 「리버스셸이 안 붙으면」 대비표 | `C-2` 가 Windows 5개 열거를 이미 담고, 대비표는 `A-51` 의 요약임 |
| §1-1 | [[Resourced]] 와 포트 구성 비교표 | 노트 `## 관련` 의 [[Resourced]] 항목으로 압축 |

---

## 검산

| 항목 | 값 |
|---|---|
| 노트 행수 | 1606 → 808 |
| 이관 제안 | 13건 (병합 10 · 신규 3) |
| 신규 제안 위치 | `B-5`(AdminSDHolder) · `A-6`(명령/출력 불일치) · `D`(Hutch 실측) |
| 이미 반영돼 제안하지 않은 것 | 10건 (위 표) |
| 이관한 원문 | **497행** — 원본 §0(40~73행, 34) · §2-6·2-7(633~735행, 103) · §6(1195~1456행, 262) · §7(1459~1556행, 98) |
| 삭제한 원문 | **약 300행** — 「삭제한 것」 표의 배경 강의·중복. 나머지 감소분은 삭제가 아니라 **압축·재배치**(§8 방어 13행 → 두 finding 의 `Vulnerability Fix:`, §9 참고 → `## 관련`, §5 플래그 → `Local.txt`/`Proof.txt` 블록) |
| 잃은 것 | 플래그 값 0 · IP 0(둘 다 유지) · 해시 0 · 자격증명 0 · 스크린샷 embed 0(6장 전부 유지) |
| `[가정]` 추적 | 원본 10개 → **노트 잔류 6** · **제안 본문에 그대로 실림 3**(제안 6·7·11) · **중복 1**(WebDAV 가정이 §6-4·§6-8 에 두 번 적혀 있어 하나로 합침). 손실 0 |
| 「왜 65분이 걸렸는가」 `[가정]` | 별도 이관 불요 — `B-53` 이 이미 「Shortest Path 쿼리는 정답 엣지를 놓침」으로 담고 있음 |
