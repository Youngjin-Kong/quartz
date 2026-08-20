# Crane — 적대적 검증 기록

## 본문에서 이관한 정정 이력

(2026-08-20 이관 — 원래 `Crane.md` 상단에 있던 블록. 원문 그대로.)

> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> 이 노트는 [[_WRITEUP-STANDARD#적대적 검증 — 노트를 쓴 다음 반드시 거친다|적대적 검증]]을 거쳐 12건을 정정했다. 실측 터미널 블록은 훼손되지 않았고, 틀린 것은 전부 나중에 덧붙인 설명 문장이었다. 다시 읽을 때 같은 오해를 반복하지 않도록 요약해둔다.
>
> | 무엇이 틀렸었나 | 무엇이 사실인가 | 반증 근거 |
> |---|---|---|
> | "`rest_data`를 빼면 SuiteCRM이 오류를 낸다" | 필수는 `method` 하나. `rest_data`는 없으면 빈 문자열로 조용히 폴백 | v7.12.3 `SugarRestJSON.php` |
> | "dash에서 `/dev/tcp: No such file or directory`가 난다" | 실제는 `Syntax error: Bad fd number`. `/dev/tcp`에 도달조차 못 한다 | Kali 실행 |
> | "`save()`가 base64 디코드 후 `unserialize()`한다" | `save()`는 인코드한다. 진짜 버그는 `is_array()` 타입 검사 우회 → 조회 경로 `get_email_recipients()`의 `unserialize()` | PoC README의 벤더 코드 |
> | 가젯 체인 최상위 = `BufferHandler` | 최상위는 `SyslogUdpHandler`, `BufferHandler`는 그 `$socket` | `exploit.py:12` 하드코딩 페이로드 |
> | `/install/` 리스팅·`status.json`·내부 IP `172.16.201.78` | 산출물에 근거 없음. `ferox.log` 1085행에 해당 히트 0건, `install.log`에 `172.16.*` 0건 | `~/PG/Crane/ferox.log`·`install.log` |
> | "`AOR_Scheduled_Reports`는 관리자만" | 예약 보고서 생성 권한이 있는 임의 계정 | PoC README |
> | "RST = 방화벽이 없다" | RST는 묵살형(DROP) 차단이 없다까지만 말한다. REJECT 규칙도 RST를 준다 | — |
> | "공개 PoC는 OSCP 회색지대" | 허용된다. 금지 정의는 "스스로 발견하고 익스플로잇하는" 도구 | OffSec 공식 정의 |
> | MySQL "`root`가 `localhost`에서만 붙는다" | `mysql.user`를 조회한 적이 없다 → `[가정]`으로 강등 | — |
>
> 원칙: 이 노트에서 `[가정]` 딱지가 없는 단정은 실측이거나 1차 사료로 확인한 것이다. 딱지가 붙은 것은 확인하지 못했다는 뜻이다.

## 본문 1장에서 이관한 「반증됨」 블록

(2026-08-20 이관 — 원래 `Crane.md` 1장(정찰) 「노출된 파일」 표 아래에 있던 블록. 원문 그대로.)

> [!warning] 반증됨 — 여기 원래 세 줄이 더 있었다 (2026-08-20 적대적 검증)
> 이 노트는 원래 아래 세 항목을 실측인 것처럼 적고 있었다. 산출물이 전부 반박한다.
>
> | 원래 서술 | 반증 |
> |---|---|
> | `/install/` 200, 디렉터리 리스팅 활성 (인스톨러 전체 노출) | `ferox.log` 1085행 전량에 `/install` 히트 0건. 워드리스트 `raft-medium-directories.txt`에는 `install`이 51행에 실재하므로 200이었다면 반드시 찍혔다. 게다가 feroxbuster의 `detected directory listing` 휴리스틱은 같은 스캔에서 `/themes`·`/cache`에 실제로 발화했다 — `/install`에는 발화하지 않았다 |
> | `/install/status.json` → 내부 IP `172.16.201.78` 누출 | `install.log` 전수 grep에 `172.16.*` 0건. 이 IP는 산출물 어디에도 없다 |
> | `/upload/` 200, 리스팅 없음 | `ferox.log`에 `/upload` 히트 0건 (워드리스트 88행에 `upload` 실재) |
>
> 왜 남겨두는가: 지우면 "왜 뒤집혔는지"가 사라져 같은 실수를 반복한다. 그리고 이것 자체가 교훈이다 —
> 디렉터리 브루트포스 결과를 서술할 때는 로그를 다시 열어라. "인스톨러가 노출돼 있었던 것 같다"는 기억은 CMS 정찰에서 너무 그럴듯해서 검증 없이 통과한다.
>
> 아래 6장 ③·7장 12번·8장 방어 표에서 이 전제 위에 서 있던 서술도 함께 정정했다.

## 본문 6장 ③에서 이관한 「정정」 블록

(2026-08-20 이관 — 원래 `Crane.md` 6장 ③ 끝에 있던 블록. 원문 그대로.)

> [!warning] 정정 — 원래 여기 "디렉터리 리스팅"과 "내부 IP"가 적혀 있었다
> 원문: *"디렉터리 리스팅이 켜진 `/install/`, 내부 IP가 박힌 `status.json`"* / *"`/install/status.json` | 내부 IP `172.16.201.78` 하나. 접근 불가, 활용처 없음"*
> 둘 다 산출물이 반박한다 — `ferox.log`에 `/install` 히트 0건, `install.log` 전수 grep에 `172.16.*` 0건. (1장 열거 절의 "반증됨" 표 참조)
> 이 항목이 시행착오 장에 있었다는 것이 특히 위험했다. **"실제 겪음"이라고 라벨링된 서술은 검증 없이 통과하기 쉽다.** 라벨이 사실을 만들지 않는다.

## 본문 7장 12번에서 이관한 하위 항목

(2026-08-20 이관 — 원래 `Crane.md` 7장 12번의 하위 불릿. 원문 그대로.)

    - 이 항목은 원래 *"`/install/` 디렉터리 리스팅과 내부 IP 누출(`172.16.201.78`)"* 로 적혀 있었으나 **산출물이 반박했다**(`ferox.log`·`install.log` 전수 확인). 1장의 "반증됨" 표 참조. 정찰 산출물을 다시 열지 않고 기억으로 쓴 서술이 어떻게 굳는지의 사례로 남겨둔다.

## 본문 각 절에서 이관한 「원래 이렇게 적혀 있었다」 문장

(2026-08-20 이관 — 본문에 산문으로 섞여 있던 작업 과정 서술. 정정 **결과**는 본문에 그대로 남겼고, 초고가 무엇이었는지를 말하는 문장만 여기로 옮겼다. 아래는 이관 직전 `Crane.md`(커밋 `5d2ceca`)의 **해당 행 전문**이다 — 본문에 남긴 부분까지 포함해 붙여둔다. 마크업까지 바이트 그대로다.)

### 2-1 (원 324행)

```
같은 기준으로 3-2의 `exploit.py`도 허용된다 — 특정 CVE 하나를 겨냥한 PoC는 취약점을 스스로 발견하지 않는다. (이 노트는 원래 `exploit.py`를 "회색지대"로 적어놨었다. 과잉 해석이라 정정했다 — 3-2 참조.)
```

문장 끝 괄호 `(이 노트는 원래 … 3-2 참조.)` 를 들어냈다.

### 2-3 (원 431행)

```
**최상위는 `BufferHandler`가 아니라 `SyslogUdpHandler`다.** 이 노트는 원래 `BufferHandler::__destruct()`를 진입점으로 그려놨었는데 그건 `Monolog/RCE1` 계열의 모양이다. phpggc의 `gadgetchains/Monolog/RCE/2/chain.php`는 `$vector = '__destruct'` 로 두고 `SyslogUdpHandler`를 최상위에 놓은 뒤 그 `$socket` 프로퍼티에 `BufferHandler`를 담는다. 디스크의 `exploit.py` 페이로드가 정확히 그 모양이다(`O:32:"...SyslogUdpHandler":1:{s:6:"socket";O:29:"...BufferHandler"…`).
```

두 번째 문장 `이 노트는 원래 BufferHandler::__destruct()를 진입점으로 그려놨었는데 그건 Monolog/RCE1 계열의 모양이다.` 를 들어냈다. **아래 「되살리면 안 되는 문장」 절을 먼저 읽어라.**

### 2-3 콜아웃 안 (원 495행)

```
> 이 노트는 원래 `/dev/tcp: No such file or directory` 라고 적어놨었다. 그 문자열은 어느 경우에도 나오지 않는다. 그럴듯하지만 실행해본 적 없는 문구였고, 인과도 뒤집혀 있었다(파싱에서 먼저 죽는데 장치 부재를 원인으로 적었다).
```

행 전체를 들어냈다. 이 콜아웃의 Kali 실측 블록(`Syntax error: Bad fd number` · `Directory nonexistent`)과 2층 분리 표는 본문에 그대로 있다.

### 3-2 (원 596행)

```
**공개 PoC 스크립트는 시험에서 허용된다.** 이 노트는 원래 `exploit.py`를 "OSCP 자동 익스플로잇 도구 금지에 걸릴 소지"로 적어놨었는데 과잉 해석이었다. OffSec의 금지 정의는 이렇다:
```

두 번째 문장 `이 노트는 원래 exploit.py를 "OSCP 자동 익스플로잇 도구 금지에 걸릴 소지"로 적어놨었는데 과잉 해석이었다.` 를 들어냈다.

### 3-2 (원 633행)

```
**`name`·`status`·`schedule_type`을 빼면 레코드 생성이 실패한다.** 이 노트는 원래 `module`·`action`·`email_recipients` 3개만 적어놨었고, 그대로 따라 하면 재현이 안 된다. `exploit.py`가 실제로 보내는 것은 6개 필드에 `Referer` 헤더까지다. `Referer`는 SuiteCRM의 요청 출처 검사를 통과하기 위한 것이다.
```

두 번째 문장 `이 노트는 원래 module·action·email_recipients 3개만 적어놨었고, 그대로 따라 하면 재현이 안 된다.` 를 들어냈다.

### 3-2 (원 634행)

```
원래 있던 "폼 필드명은 실제 저장 폼을 브라우저로 열어 확인해야 한다"는 문장도 삭제했다 — PoC 소스에 이미 다 있다. 브라우저를 켜기 전에 `exploit.py`를 연다.
```

첫 문장 `원래 있던 "폼 필드명은 …"는 문장도 삭제했다 — PoC 소스에 이미 다 있다.` 를 들어내고 `브라우저를 켜기 전에 exploit.py를 연다.` 만 남겼다.

### 7장 5번 (원 1019행)

```
   - **`name`·`status`·`schedule_type`·`Referer`를 빼면 레코드 생성이 실패한다.** 3-2의 수동 절차가 원래 3개 필드만 적어놨던 것을 정정했다.
```

두 번째 문장 `3-2의 수동 절차가 원래 3개 필드만 적어놨던 것을 정정했다.` 를 들어냈다.

## 이관 감사 (2026-08-20) — 되살리면 안 되는 문장

위 「2-3 (원 431행)」 인용 안의 **`그건 Monolog/RCE1 계열의 모양이다` 는 틀렸다.** 이관 감사에서 Kali `/tmp/phpggc` 를 직접 열어 확인했다:

```
$ cat /tmp/phpggc/gadgetchains/Monolog/RCE/1/chain.php
    public static $version = '1.4.1 <= 1.6.0 1.17.2 <= 2.7.0+';
    public static $vector = '__destruct';
        return new \Monolog\Handler\SyslogUdpHandler(
            new \Monolog\Handler\BufferHandler(
```

RCE1 의 `generate()` 본체는 RCE2 와 **동일하다.** 최상위는 RCE1 에서도 `SyslogUdpHandler` 이고 `BufferHandler` 는 그 인자다. 둘의 실제 차이는 대상 버전 범위와 `gadgets.php` 의 `SyslogUdpHandler::$socket` 가시성 선언(`protected` vs `public`)뿐이다. 즉 **`BufferHandler` 최상위 형태는 phpggc 의 어느 Monolog 체인에도 없다.** 본문에서 이 문장이 빠진 것은 결과적으로 옳다 — **되살리지 마라.**

본문 400행에 남은 서술(`최상위는 BufferHandler가 아니라 SyslogUdpHandler다` + RCE/2 체인 설명)은 위 실측과 일치한다.

## 이관 감사 (2026-08-20) — 이관이 놓쳤던 잔여 과정 서술

원 751행(현 751행) 끝 괄호에 과정 서술이 남아 있었다. 감사에서 뒤 문장만 잘라냈다.

```
(1장 nmap 해설표는 이 구분을 지켜 "내 IP가 `mysql.user` 호스트 목록에 없다"로 써놨다. 여기서 "`localhost`에서만 붙는다"로 단정했던 것을 되돌린 것이다.)
```

남긴 것: `(1장 nmap 해설표는 이 구분을 지켜 "내 IP가 mysql.user 호스트 목록에 없다"로 써놨다.)` — 1장과의 표현 대조는 내용이라 유지했고, `단정했던 것을 되돌린 것이다` 만 들어냈다. `[가정]` 강등 자체는 751행 본문에 그대로 있다.
