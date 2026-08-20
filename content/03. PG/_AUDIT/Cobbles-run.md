# Cobbles — run log (192.168.248.214, 2026-08-21 인스턴스)

판정: **미완 · 0/2 flags · 초기 침투 실패(foothold 미확보).**

## 표면
- `nmap -p-` 2회(fast min-rate5000 + careful min-rate800/retries3): **22/tcp OpenSSH 8.4p1 Debian, 80/tcp Apache 2.4.53 (Debian)만** open. 나머지 filtered.
- UDP top-100: 전부 open|filtered(무응답). SNMP(onesixtyone 120 communities + snmpwalk public/private/community/manager/cobbles): 무응답.
- 80: 로그인 페이지 `index.php`(title Cobbles). 응답 헤더 `x-backend-server: primary`. Set-Cookie 없음.
- `/server-status` **노출**(mod_status). 백엔드 VHost `127.0.0.1:8080` 노출 → 포트80 = 리버스 프록시 → 백엔드 8080.
- server-status 스코어보드에 **내부 디렉터리 스캐너**(raft-large-files류 워드리스트)가 8080을 훑는 게 보임. **간헐적/버스트(cron성)**. = 로그·스코어보드 채우는 미끼 소음.
- feroxbuster(common, directory-list-2.3-medium ~220k×php/txt/html/bak, raft-large-directories): `index.php`, `style.css`, `favicon.png`, `server-status`, `/javascript`(403 = Debian javascript-common alias 미끼) 외 **아무것도 없음**.

## 로그인 (index.php) — 유일한 실질 표면
- 유저 열거: `Invalid username!` vs `Invalid password!`. xato 10만 이름 중 **유효 유저는 `sam` 하나뿐**.
- SQLi 없음(username은 리터럴 매치 — `sam' -- -` → Invalid username!). password SQLi(`' OR '1'='1`) → Invalid password!, 우회 안 됨.
- LDAP 인젝션 없음(`*`/`sam*`/`*)(uid=*` → Invalid username!, 와일드카드 확장 안 함).
- NoSQL/배열/타입저글링 없음(`username[]`/`password[]` → 그대로 Invalid; md5 매직해시 240610708 등 → Invalid).
- password=username(sam/sam + 대소문자 + Summer/Welcome/Cobbles 변형): 안 됨.
- **브루트(확정 부정)**: hydra + ffuf(100스레드) rockyou → **2.13M/14.3M 시도, 히트 0**. sam의 웹 비번은 rockyou 앞 2.1M에 없음 → 브루트형 박스 아님.
- SSH 브루트 sam rockyou: ~65/min 스로틀, ~700 시도, 히트 없음.

## `x-backend-server: primary` (핵심 미해결 아티팩트)
- **완전 정적**: 300+ 요청 전부 primary. 아래 어떤 것으로도 안 바뀜 —
  요청 헤더(X-Backend-Server/X-Backend/X-Route/X-Forwarded-*), 메서드(GET/POST/PUT/HEAD/OPTIONS/DELETE/TRACE/PATCH), HTTP/1.0, Host(localhost/primary/secondary/backend/cobbles/…), 쿠키(backend=/server=/SERVERID=), GET 파라미터(server=/backend=/route=/lb= =secondary), 경로 접두(/secondary//backup//admin/…), 동시성 버스트.
- 포워드 프록시 아님(`curl -x` → 절대 URI 무시하고 자기 사이트만 서빙; 127.0.0.1:22로 프록시해도 Cobbles HTML 반환).
- **CVE-2023-25690**(Apache 2.4.53 mod_proxy req smuggling): 경로 CRLF 스머글 테스트 → 백엔드가 리터럴 경로로 404, 단일 응답, 분리 없음 → 순수 ProxyPass(RewriteRule 재주입 아님). **취약 아님**.
- CVE-2021-41773/42013 경로 traversal(cgi-bin/icons `.%2e` 인코딩): 전부 404. 패치됨.
- `/balancer-manager`, `/server-info`: 404.

## 이미지 / 소스
- `cobbles.jpg`(배경): 진짜 Canon EOS 750D 사진, 덧붙은 데이터 없음(ffd9 정상 종료), steghide 없음(빈/cobbles/sam), exif·strings에 크레덴셜 없음. favicon.png: Adobe XMP 메타뿐.
- 소스 노출: `index.php.bak/~/.phps/.php%20/.php./Index.php/.swp` 등 전부 404/403. LFI 없음(`page/file/p/view/include/…` 파라미터 무시, 응답 정확히 1263바이트 고정).

## 크레덴셜 누출 가설(server-status 경유) — 미확인
- 여러 분 동안 버스트를 가로질러 server-status의 POST/쿼리스트링/크레덴셜 요청 관찰. 관측된 POST는 **전부 내 hydra/ffuf**(브루트 죽이면 POST 0으로 검증됨). 내부 스캐너는 GET 워드리스트 소음뿐. URL에 크레덴셜을 담은 cron/admin 요청은 **한 번도 관측 안 됨**.

## 결론 / 다음 후보
- sam 비번을 얻을 경로를 못 찾음(브루트 불가, 인젝션 없음, 소스/LFI 누출 없음, 크레덴셜 누출 없음, 스테고 없음).
- 미해결 아티팩트: `x-backend-server: primary` + 간헐적 8080 스캐너. 둘 다 미끼로 보이나 확증 못함.
- **총괄 판단 요망**: (a) web-exploit 전문 에이전트로 신선한 재검토, (b) 포털 힌트/공식 문서 확인, (c) 손절. 박스는 살아 있고 내 흔적은 정리됨(업로드·계정·설정 변경 없음, 리스너/tmux 없음). 남은 흔적은 타겟 로그의 브루트 소음뿐(셸 없어 정리 불가).

## 남긴 흔적 (확인한 것만)
- Kali `~/PG/Cobbles/` 산출물 42개 보존(nmap 원문, ferox/raft, hydra/ffuf 로그, smuggle_test.py, writeup_notes.txt, 스크린샷 login.png/serverstatus.png). `hydra.restore`(154MB) 잔존 — 삭제 안 함.
- Kali tmux 세션 전부 종료(이름으로), 리스너 없음(`ss -lntp` 확인), tmux 서버 미기동.
- 타겟: 파일 업로드/계정 생성/설정 변경 **없음**. access.log에 웹 브루트 ~2.1M 요청, auth.log에 sam SSH 실패 ~700건 — 셸 없어 정리 불가.
- 볼트: `파일보관\PG-Cobbles-login.png`, `PG-Cobbles-serverstatus.png` 반입 확인.
