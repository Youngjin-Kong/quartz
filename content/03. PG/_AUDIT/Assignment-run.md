# Assignment — 실행 기록 (pg-box-runner, 2026-08-21)

타겟 192.168.248.224 / Kali tun0 192.168.45.207 / 산출물 `~/PG/Assignment/`

## 타임라인 (KST, Kali 파일 mtime 기준)

| 시각 | 사건 |
|---|---|
| 09:18:37 | `recon.sh 192.168.248.224 Assignment` 시작 |
| 09:19:40 | 즉시 구간 종료 — **63초**. 22/80/8000 확인, 스크린샷 2장 |
| 09:21 | 80 = Rails `notes.pg`, 8000 = Gogs. `/register` 폼 파라미터 확보 |
| 09:23 | 회원 목록 `/users` 에서 jane(id 1) role=`owner` 확인 |
| 09:24 | `user[role]=owner` 매스어사인먼트 성공 (id 15) |
| 09:25 | `/notes/1` 에서 Gogs 자격증명 회수 |
| 09:26 | Gogs 로그인 성공, jane 이 이미 Gogs admin |
| 09:27 | Gogs 0.12.9 확인 (`/admin`) |
| 09:28 | tmux `asg-rev443` 리스너 기동 |
| 09:29 | repo `jane/pgtest` 생성 → `post-receive` 훅 주입 → 웹 커밋으로 트리거 |
| 09:29 | **jane 리버스셸** (`jane@assignment:~/gogs-repositories/jane/pgtest.git$`) |
| 09:30 | pty 승격 → `proof_user.txt` |
| 09:31~33 | `harvest.sh` 실행·회수 (1300행) |
| 09:33 | jane `~/.ssh/authorized_keys` 에 Kali 공개키 설치 → 안정 SSH 확보 |
| 09:34~ | root 크론 `clean-tmp.sh` 추적 — pspy 실패, 자체 프로세스 감시기로 전환 |
| 09:41 | 스크린샷 8장 볼트 이관 (md5 중복 0) |

## recon.sh 첫 실전 투입 결과

- **즉시 구간 63초** (설계 목표 25~31초보다 길다. 열린 포트가 3개고 웹이 2개라 프로빙이 2배)
- 산출 파일 **약 80개** — `_SUMMARY.txt` · `nmap-quick*.txt` · `web-80/` · `web-8000/`(각 `root.body`/`root.headers`/`probe_*` 27개) · `svc/` · 스크린샷 2장
- tmux 2개 자동 기동: `rc-Assignment-full`(-p- + UDP), `rc-Assignment-gb`(gobuster 80·8000)
- **정상 동작.** 깨진 곳 없음. 스킴 자동 정정도 발동하지 않았고(둘 다 평문 http 로 정확히 판정) `SimpleHTTPServer` 오탐 방지 로직도 문제 없었음
- 호스트명 힌트 `assignment.pg` 를 Gogs `EXTERNAL_URL` 에서 정확히 추출

## 공략 경로 (실측)

1. **80/tcp Rails `notes.pg`** — `/register` 의 `ApplicantsController#user_params` 가 `:role` 을 permit
   ```ruby
   params.require(:user).permit(:username, :password, :password_confirmation, :role)
   ```
   → `user[role]=owner` 를 얹어 가입하면 owner 로 생성됨
2. `NotesController#show` 가 `current_user.role == "owner"` 면 남의 노트도 보여줌
   → `/notes/1` (jane 작성, 제목 "API creds") = `jane:svc-dev2022@@@!;P;4SSw0Rd`
3. **8000/tcp Gogs 0.12.9** — 그 자격증명으로 로그인. jane 은 이미 Gogs **admin**
4. repo 생성 → Settings → Git Hooks → `post-receive` 에 bash 리버스셸 → 웹 에디터 커밋으로 트리거 → **jane 셸**
5. root — 진행 중

## 브리핑과 실제의 차이

포털 Lab Briefing 은 5단계를 이렇게 적었다.
> 8000 Gogs → 계정 열거 + 파라미터 변조로 admin 승격 → Git hooks RCE → jane → root 크론 `clean-tmp.sh` 의 find 오용

실제로는:
- **계정 열거·파라미터 변조는 8000(Gogs)이 아니라 80(Rails notes.pg)에서 일어난다.** 브리핑은 80 을 아예 언급하지 않았다
- Gogs 쪽에서는 admin 으로 「승격」할 일이 없다 — jane 계정이 처음부터 Gogs admin이다
- Git hooks RCE 는 브리핑대로 성립

즉 브리핑만 따라 8000 만 팠으면 자격증명 출처를 못 찾는다. 전체 포트 스캔이 그 공백을 메웠다.

## 실패·함정 기록

- **`nmap` 배너에 Gogs 버전이 안 뜬다** — `Golang net/http server` 까지만. 버전은 `/admin` 페이지(admin 로그인 후)에서 `0.12.9` 로 확인. 독립 근거 2번째는 `~/gogs/gogs` 바이너리 빌드시각 `2022-06-07 05:03:46 UTC`
- **Gogs `repo/create` 의 소유자 필드는 `uid` 가 아니라 `user_id`** (0.12.9). `uid` 로 보내면 HTTP 200 으로 폼이 되돌아오고 에러 문구도 안 나온다 — 302 가 아니면 실패다
- **`app.ini` 에 `ENABLE_GIT_HOOKS = false` 가 `[service]` 섹션 아래 적혀 있는데 훅은 그대로 동작했다.** 값만 보고 「훅 막혔다」고 판단했으면 벡터를 통째로 버렸을 것
- **pspy 가 안 돌았다** — Kali `/usr/share/pspy/pspy64` 도 `pspy64s` 도 타겟(Ubuntu 20.04, glibc 2.31)에서 `GLIBC_2.34 not found`. Kali 패키지가 최신 glibc 로 빌드돼 있다. 자체 `/proc` 폴러로 대체
- ⚠️ **`pkill -f "sh /tmp/.w.sh"` 가 자기 자신을 죽였다.** SSH 원격 명령 문자열 안에 그 패턴이 들어 있어 `pkill -f` 가 **자기 셸의 cmdline** 에 매칭됐다. 명령 전체가 exit 1 로 끊기고 뒤따르던 `touch` 도 실행되지 않았다. → **PID 로 죽여라**
- SSH 비밀번호 인증은 Gogs 비밀번호로 안 된다(`Permission denied`). 시스템 비밀번호와 Gogs 비밀번호가 다르다

## 남긴 흔적 (원복 대상)

타겟:
- Rails 계정 5개 — `probe1`(id14) `mass_owner`(15) `mass_admin`(16) `mass_admtrue`(17), 그리고 최초 실패분 없음
- Gogs repo `jane/pgtest` + `post-receive` 훅
- `/home/jane/.ssh/authorized_keys` (원래 없었음 — `.ssh` 디렉터리는 비어 있었다)
- `/tmp/.h.sh` `/tmp/.h/` `/tmp/.hj.txt` `/tmp/.p` `/tmp/.ps` `/tmp/.w.sh` `/tmp/.w*.log` `/tmp/.w2.sh` `/tmp/.wb.log` `/tmp/.seenpids` `/tmp/marker_a` `/var/tmp/marker_a`

Kali:
- tmux `asg-rev443`(리스너) `asg-http`(:8080) `rc-Assignment-full` `rc-Assignment-gb`
