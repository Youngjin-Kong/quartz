# Monster (192.168.248.180) — 실행 기록

> 2026-08-20 세션. Kali 로컬시각 = UTC+9, 타겟 로컬시각 = UTC-7(PDT).
> **미완료 상태로 중단됨** — 도구 실행이 하네스 안전검사에 막혔다(20:41 KST). 상세는 맨 아래 「중단 사유」.

## 확보한 것

| 항목 | 값 |
|---|---|
| local.txt | `db85d2fa7033db43da92bb07dde4da5b` |
| 경로 | `C:\Users\mike\Desktop\local.txt` |
| 셸 종류 | **대화형 PowerShell 리버스셸** (nc 리스너, tmux `mon_lsnr443`) — 웹셸 아님 |
| 컨텍스트 | `mike-pc\mike`, Mike-PC, 192.168.248.180, Thu 08/20/2026 04:40 AM |
| proof.txt | **미확보** |

플래그를 읽은 원문(타겟 프롬프트 포함, tmux capture-pane 실측):

```
PS C:\xampp\htdocs\blog\public\themes\default> cmd /c "whoami & hostname & ipcon
fig | findstr IPv4 & date /t & time /t & type C:\Users\mike\Desktop\local.txt"
mike-pc\mike
Mike-PC
   IPv4 Address. . . . . . . . . . . : 192.168.248.180
Thu 08/20/2026
04:40 AM
db85d2fa7033db43da92bb07dde4da5b
PS C:\xampp\htdocs\blog\public\themes\default>
```

## 경로 요약

1. **nmap `-p-`** — 80/443(Apache 2.4.41 Win64 OpenSSL 1.1.1c PHP 7.3.10 = XAMPP 7.3.10), 135/139/445, 3389, 5040, 7680, 49664-49669. Win10 build 19041, 호스트 `MIKE-PC`. UDP top-100 = 소득 없음.
2. **gobuster** → `/blog` = **Monstra CMS 3.0.4**, vhost `monster.pg`(hosts 추가 필요).
3. `/blog/users` 가 사용자 두 명(`admin`, `mike`)을 그대로 공개. 프로필에 이메일까지.
4. **cewl + hashcat best66.rule → hydra** 로 `admin:wazowski` 크랙.
5. 관리자 패널 → **themes → add_chunk** 로 PHP 청크 생성 → `/blog/public/themes/default/<name>.chunk.php` 가 그대로 실행됨 (EDB-52038 경로). `system()` 으로 RCE, 실행 계정 `mike-pc\mike`.
6. 그 RCE 로 **PowerShell 리버스셸**(base64 `-e`) 을 tcp/443 으로 던져 대화형 셸 확보. 아웃바운드 443 은 첫 시도에 바로 붙었다.

## 막혔던 지점 (6장 재료)

### (1) `admin:wazowski` 를 이미 손으로 때렸는데 실패했었다 — 25분 손해

20:11 에 수동으로 7개 조합을 돌렸다. **한 쿠키 단지(`-c ck.txt -b ck.txt`)를 7번 재사용**한 것이 화근이다.
Monstra `admin/index.php` 는 실패할 때마다 `login_attempts` 쿠키를 1씩 올리고 **5 이상이면 "You are banned for 10 minutes"** 를 뱉는다.
6번째(`mike`)부터 이미 밴 화면을 받고 있었고, 7번째가 정답인 `wazowski` 였다.

증거는 그때 화면에 있었다 — 응답 크기가 앞의 5개는 `8507`, `mike`·`wazowski` 두 개만 `8513` 이었다.
그 차이를 보고도 "플래시 메시지 누적이겠지"로 넘겼다. 직후 쿠키 없이 다시 diff 를 떴더니 차이가 사라져(=밴이 안 걸린 새 세션) 오판이 굳어졌다.

교훈 두 개:
- **로그인 브루트를 손으로 돌릴 때 쿠키 단지를 공유하지 마라.** 시도마다 `-c` 새 파일이거나 아예 쿠키를 안 보내야 한다.
- **응답 크기 차이는 무조건 본문을 봐야 한다.** "왜 다른지" 설명이 안 되면 넘기면 안 된다.

부수 효과로 **hydra 는 이 잠금을 아예 안 받는다.** 잠금 상태가 서버가 아니라 **클라이언트 쿠키**에 있어서, 쿠키를 안 보내는 hydra 는 무한히 때릴 수 있다. 소스(`admin/index.php`)를 읽고서야 알았다.

### (2) 캡차 우회에 시간을 썼는데 애초에 갈 수 없는 길이었다

`/blog/users/registration` 이 열려 있어서 가입 → 권한상승을 노렸다.
cryptographp 캡차 이미지를 받아보니 **글자가 하나도 안 그려져 있었다**(130x40 PNG, 빨간 사선 1개 + 초록 호 1개 + 점 몇 개뿐). TTF 폰트 렌더 실패로 보인다. 읽을 수가 없다.

`answer=` 빈 값으로 우회를 시도 → 실패. 소스를 보니 `chk_crypt()` 가
`if ($_SESSION['cryptcode'] and ($_SESSION['cryptcode'] == $code))` 라서 세션값이 없으면 무조건 false 다.

그런데 **소스를 먼저 읽었으면 이 길 자체를 안 갔다.** `users.plugin.php` 의 가입 처리는 `'role' => 'user'` 를 하드코딩하고, 프로필 수정(`getProfileEdit`)도 `login/firstname/lastname/email/skype/about_me/twitter` 만 업데이트해서 **role 을 못 만진다.** filesmanager·themes 는 `admin`/`editor` 만 로드된다.
**"들어갈 수 있나"보다 "들어가면 뭘 할 수 있나"를 먼저 봤어야 했다.**

### (3) `.php7` 업로드(EDB-48479)가 이 박스에서는 안 먹힌다

Monstra 3.0.4 의 대표 익스플로잇 두 개가 다 파일 업로드다:
- EDB-48479 / CVE-2017-18048 — `.php7`
- EDB-49949 / CVE-2018-6383 — `.pht`, `.phar`

`filesmanager.admin.php` 의 `$forbidden_types` 에 `php7`·`pht`·`phar` 가 실제로 **없다.** 그래서 이론상 통해야 한다.
그런데 업로드가 **`.txt`, `.jpg` 를 포함해 전부** `"File was not uploaded"` 로 실패했다. 확장자 문제가 아니라 업로드 자체가 죽어 있다.
`move_uploaded_file()` 이 실패하거나 `$_FILES['file']` 이 비어 있는 경우인데, **어느 쪽인지는 확인하지 못했다** — `php.ini` 를 못 읽었다. `[가정]`.

우회는 **themes → add_chunk**(EDB-52038)였다. 업로드가 아니라 **에디터로 PHP 파일을 만드는** 기능이라 `file_uploads` 와 무관하다.
일반화: **CMS 관리자 패널을 잡으면 "업로드" 말고 "템플릿/테마/스니펫 에디터"를 같이 보라.** 업로드가 막혀도 에디터는 열려 있는 경우가 흔하다.

### (4) 도구 쪽에서 태운 시간

- `hashcat --stdout -r best64.rule` → Kali 7.1.2 의 rules 디렉터리에 **`best64.rule` 이 없다. `best66.rule` 이다.** 조용히 0줄을 뱉어서 `wc -l` 로 0 을 보고서야 알았다.
- 첫 hydra 를 `-P rockyou.txt` 로 돌렸다가 **2,300 tries/min → 356시간** 견적을 보고 접었다. 200 병렬 curl 벤치로 측정한 서버 상한이 **70 req/s** 였다. rockyou 는 이 박스에서 애초에 선택지가 아니다.
- `users.txt` 를 안 만들고 hydra tmux 세션을 먼저 띄워서 한 번 헛돌았다.
- 예열 스캔을 `--top-ports 200` 으로 돌렸지만 **`-p-` 가 끝날 때까지 판단을 미뤘다.** 결과적으로 고포트(49664+)는 전부 동적 RPC 라 소득이 없었다.

### (5) 안 통한 것들 (전부 확인 후 폐기)

| 시도 | 결과 |
|---|---|
| SMB null / guest 세션 | `NT_STATUS_ACCESS_DENIED` / `ACCOUNT_DISABLED`. rpcclient·enum4linux-ng 도 동일 |
| `/blog/storage/database/users.table.xml` 직접 읽기 | 403. `storage/.htaccess` 가 `Deny from all` |
| 경로 우회 (`//`, `/./`, 대소문자) | 전부 403 |
| Monstra 로그인 XPath 인젝션 | `select("[login='$login']")` 직후 `$user['login'] == $_POST['login']` 동등검사가 막는다 |
| password-reset 의 `hash` XPath 인젝션 | 같은 이유로 막힘 |
| XAMPP `/php-cgi/php-cgi.exe` (CVE-2024-4577 / CVE-2012-1823) | 엔드포인트는 **존재**(403 아닌 500). 하지만 `%ADd`·`-d` 둘 다 500 그대로. 로케일이 CJK 코드페이지가 아니면 best-fit 매핑이 안 일어난다는 게 정설이므로 여기선 안 되는 게 맞다 `[가정]` |
| 웹 이미지 exif/strings | 전부 무소득 |
| UDP top-100 | 열린 포트 없음 |

## 남긴 흔적 (확인한 것만)

타겟에 남긴 것:
- `C:\xampp\htdocs\blog\public\themes\default\mon9x.chunk.php` — **삭제하지 못했다** (도구 차단 시점에 아직 있음)
- Monstra 관리자 세션 로그인 기록 (`admin` 계정)
- 실패한 업로드 시도 3건 (`shell.php7`, `t.txt`, `t.jpg`) — **파일은 생기지 않았다**(전부 "File was not uploaded"). 다만 서버 로그에는 POST 가 남는다
- `mike` 로 실행 중인 **PowerShell 리버스셸 프로세스 1개** (tcp/443 → 192.168.45.207) — **아직 살아 있다**
- Apache access/error 로그에 브루트포스 약 **44,000건**(10k 런 20,000 + cewl 런 약 24,000) — **지우지 않았다. 지울 생각도 없다**

확인하지 않은 것:
- Windows 이벤트 로그(Security 4624/4688 등) — **조회하지 못했다**
- `C:\Windows\Temp` 등에 PowerShell 이 남긴 임시 파일 유무

Kali 에 남긴 것:
- `/etc/hosts` 에 `192.168.248.180 monster.pg` 한 줄 추가 — **원복하지 못했다**
- tmux 세션 `mon_lsnr443` (nc 리스너 + 살아 있는 셸) — **의도적으로 남김**. 총괄이 이 셸에서 플래그를 재확인하고 정리해야 한다
- tmux 세션 `mon_nmap`·`mon_gob`·`mon_hydra`·`mon_hydra2`·`mon_udp` 는 **종료 완료** (세션 이름으로만 kill, `pkill` 사용 안 함)

## 중단 사유

2026-08-20 20:41 KST, 권한상승 열거를 시작하려는 시점부터 **하네스의 안전검사가 모든 명령 실행 도구(Bash·PowerShell)를 차단**하기 시작했다.
차단 메시지: *"Auto mode could not evaluate this action ... it reacts to earlier conversation content, not to the action itself, and it will keep firing for the rest of this conversation."*

즉 이 세션에서는 재시도해도 계속 막힌다. **파일 읽기·쓰기는 가능하다.**

### 다음 수 (셸은 살아 있다)

`ssh kali@10.44.44.128` → `tmux attach -t mon_lsnr443` 로 바로 이어받을 수 있다. 확인 안 된 순서대로:

1. `whoami /all` 결과상 **SeImpersonate 없음**, Medium integrity, 그룹은 `Users` + `Remote Desktop Users` 뿐. **Potato 계열은 후보에서 빠진다.**
2. Apache 가 `NT AUTHORITY\INTERACTIVE` + `CONSOLE LOGON` 을 달고 `mike` 로 돈다 → **서비스가 아니라 mike 세션의 대화형 프로세스**다. 자동 로그온 설정 가능성이 높다:
   `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` → `DefaultPassword` 평문
3. `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` (+ HKCU)
4. `Get-CimInstance Win32_Service | ? { $_.PathName -notmatch 'C:\\Windows\\' }` — 비따옴표 경로·쓰기 가능한 서비스 바이너리
5. `schtasks /query /fo LIST /v`
6. `C:\xampp\` 아래 설정파일 — `php.ini`(업로드가 왜 죽었는지도 여기서 확인됨), `my.ini`, `phpMyAdmin\config.inc.php` 의 MySQL 비번. **mike 비번 재사용 가능성**
7. `netstat -ano` 로 로컬 전용 리스너(3306 등)
8. 3389 이 열려 있으니 mike 평문 비번이 나오면 **RDP 로 갈아타는 것**이 편하다 (`Remote Desktop Users` 그룹에 이미 들어 있다)

⚠️ **`whoami /all` 한 번으로 "특권 없음"을 결론짓지 마라.** 권한이 올라가면 보이는 서비스·작업이 달라진다. Administrator 를 잡으면 같은 열거를 다시 돌려야 한다.

## 산출물 (`~/PG/Monster/`)

`nmap.log` · `nmap.full.txt` · `quick200.log` · `nmap_udp.log` · `smb_enum.txt` · `smb_enum2.txt` ·
`gobuster80.log` · `cewl.txt` · `cewl_blog.txt` · `words.txt` · `words_b66.txt` ·
`hydra_10k.log`(무소득) · `hydra_cewl.log`(히트) · `hydra_10k_run.txt` · `hydra_cewl_run.txt` ·
`shell.php7`(업로드 실패) · `chunk_payload.php`(성공한 페이로드) · `ps_rev.ps1` · `ps_rev.b64` ·
`cap.png` · `cap_big.png`(렌더 실패한 캡차) · `up.html` · `up2.html` · `fm.html` · `fm2.html` · `chunk_resp.html` ·
`shot_80_index.png` · `shot_80_blog.png` · `shot_80_admin_login.png` ·
`writeup_notes.txt`(시간순) · `monstra-src/`(GitHub 클론, 소스 대조용)

⚠️ **`proof_user.txt`·`proof_admin.txt`·`traces_confirmed.log` 는 만들지 못했다** — 플래그 증거를 파일로 떨구려던 시점에 도구가 막혔다. 위 코드블록이 유일한 실측 기록이다.
⚠️ **스크린샷을 볼트로 반입하지 못했다** (`scp` 불가). Kali `~/PG/Monster/shot_*.png` 에 있다.
