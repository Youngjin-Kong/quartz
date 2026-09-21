---
tags:
  - type/audit
  - platform/pg
manual_tags: true
manual_cves: true
---
# Wombo — 적대적 검증 + 정정 (writeup-auditor)

대상 `03. PG\Wombo.md` · 백업 `03. PG\_backup\Wombo.md.bak`(485행) · 이관 제안 `03. PG\_AUDIT\Wombo-playbook.md`(12건)
근거 출처 — `~/PG/Wombo/` 전량 · `~/PG/Wombo/rrs/` · `~/.zsh_history` · 볼트 `파일보관\PG-Wombo-*.png` 2장 · git `076525b` · Kali 직접 실행 4건
행수 **422 → 434** (개작 전 485 · 개작 -63 · 감사 +12)

---

## 0. -63행 diff 분류 — 손실 0건

`.bak` 485행을 정규화해 「새 노트에도 `_playbook` 제안에도 없는 줄」을 기계 추출(153행) 후 의미 단위로 재분류함.

| 분류 | 건수 | 판정 |
|---|---|---|
| ① `_playbook` 제안으로 이관 | 12블록 | 제안 파일의 「지우기 전 원문」과 1:1 대응. 인과·수치·`[가정]`·출처 경로 보존 확인 |
| ② 반증되어 정정·삭제 | 5블록 | 아래 §1 |
| ③ OSCP 4·5장 형식으로 압축(내용 존속) | 대부분 | §2 취약점 분석 4개 절 → `Vulnerability Explanation` + `Initial Access` 재현 절. §8 방어 관점 → `Vulnerability Fix` |
| ④ **설명 없이 소실** | **2줄** | §8 방어 관점의 「egress 필터링은 완전하지 않다」·「평문 자격증명 방치 금지」 — **복원함** |

**복원 2건** — `Vulnerability Fix:` 에 아래 두 불릿을 되살림.

```
- **egress 필터링은 방어가 되지만 완전하지 않다.** :80만 열어도 그 포트로 C2/리버스셸이 나간다. 아웃바운드 최소화 + 프록시 강제가 더 낫다.
- **MongoDB·NodeBB 자격증명을 평문 config에 두고 root 가독으로 방치하지 마라** — 침해 후 횡적 이동의 재료가 된다.
```
(원문 `.bak` 460~461행. 개조식으로 종결만 바꿔 복원)

**정당한 삭제로 판정한 것** — 프론트매터 `tech/payload/revshell` · `tech_count: 2`. 리버스셸을 **실제로 잡은 기록이 산출물에 0건**이므로 「실제로 사용한 기법만」 기준에 맞음.

---

## 1. 작성자가 보고한 자기 반증 3건 — 되짚은 결과

| # | 작성자 주장 | 감사 판정 |
|---|---|---|
| 1 | 원본 코드펜스의 `$ redis-cli …` 프롬프트가 창작 · `8080/tcp open http-proxy   (NodeBB, Node.js)` 괄호 주석이 `nmap.log` 에 없음 | **전면 확정** |
| 2 | 「RDB를 웹루트에 써서 HTTP로 받아 실제 바이트를 눈으로 확인했다」를 산출물이 반박 | **확정** |
| 3 | 「익스플로잇 5분」이 mtime 과 불일치(35분) | **부분 확정 — 등급은 `반증`이 아니라 `근거부족`** |

**1번 근거** — `~/PG/Wombo/` 전체에 `^\$ redis-cli` · `kali㉿kali` · `└─$` · `root@wombo` 문자열 **0건**(`grep -rn`). `~/.zsh_history` 에 `wombo|248.69|redis` **0건**. 산출물의 선두 `#` 는 스크립트가 붙인 명령 주석(`id_output.txt`·`module_list.txt`). `nmap.log` 19행은 `8080/tcp  open   http-proxy` 로 끝나고 괄호 주석 없음 — 코드펜스 안에 작성자가 손으로 넣은 해설이었음.

**2번 근거** — `plant_cron2.sh` 원문:
```sh
} > /tmp/out.txt 2>&1; cp /tmp/out.txt /var/www/html/out.txt 2>/dev/null; cp /tmp/out.txt /usr/share/nginx/html/out.txt 2>/dev/null; … chmod 644 /var/www/html/out.txt …
```
웹루트로 복사한 것은 **크론 실행 결과 `/tmp/out.txt`** 이지 RDB 가 아님. 웹루트는 egress 가 죽은 상태의 **인바운드 회신 채널**. 「Debian 9 cron 이 파일 전체를 버렸다 — 실측」의 `[가정]` 강등도 타당 — 크론 거부 로그·`ps` 출력 산출물 0건이고 `writeup_notes.txt` 자기 보고뿐.

**3번 — 총괄이 준 검증 지적을 여기서 되짚음.** 타임존은 **문제없음**: Kali 는 시스템 TZ 가 UTC 이나 `date` 는 KST 로 렌더되고, `nmap.log` 본문 헤더(`Thu Aug 20 11:25:28 2026`)와 `ls` mtime(11:26:23 +0900)이 **같은 축**임(같은 파일 안 HTTP `Date:` 헤더는 `02:26:02 GMT` = +9 일치). 따라서 `exploit_run.log` 11:27:28 → `flags.txt` 12:02:31 = **35분 3초**는 확정.
다만 원문의 「익스플로잇 5분」은 *익스플로잇 단계 자체의 소요*를 뜻할 수 있고, 35분은 *첫 시도부터 플래그까지의 벽시계 시간*이라 **같은 것을 재고 있지 않음.** 5분을 반증한 산출물은 없으므로 등급은 `근거부족`. 노트 본문에는 이미 「5분」이 남아 있지 않아 정정 대상 없음 — `_playbook.md` 12번의 「반증한 것」 표현만 과합.

---

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| 요약 `glibc 2.24, 호스트명 wombo` | 본문은 glibc 2.24 를 「일반 지식 · 관측 없음」으로 강등했는데 요약은 단정 — 내부 모순 | 요약에서 `glibc 2.24,` 제거. 본문의 유보된 서술만 남김 |
| 규약 콜아웃 `~/PG/Wombo/ 원문만 실음` | `objdump` 블록은 2026-08-26 재조회분이라 blanket 주장과 충돌 | 「예외는 `objdump` 블록 하나로 … 캡션으로 표기함」 삽입 |
| `Vulnerability Fix:` | `.bak` 방어 항목 2건 소실 | 복원(§0) |
| egress `[가정]` 불릿 | 같은 불릿이 「`writeup_notes.txt` 에 443·8080·21000 시도 기록」이라 적고 바로 뒤에 「시도조차 안 했다와 구분 불가」라고 씀 — 자기 모순 | 구분 불가 대상을 **「SYN 부재의 원인 계층」**으로 정정. `[가정]` 은 유지 |
| `443 시도가 실재함 …` | 보존된 `exploit_run2.log`(11:28:40, 배너 2줄에서 잘림)가 노트에 없음 | 「한 번 더 돌렸다는 기록이지 결과의 기록은 아님」으로 한 줄 추가 |
| `### Privilege Escalation – 없음` | **4항목 전부 누락** — 구조 결손 | [[Bratarina]] 선례대로 `Vulnerability Explanation`/`Fix`/`Severity`/`Steps` 를 「해당 없음 + 어디에 계상했는가」로 추가. 기존 근거 불릿은 그대로 |
| `redis-server 가 uid 0(process_id:550)` | **잘못된 인과** — `process_id` 는 pid 일 뿐 구동 계정의 근거가 아님 | 근거를 `system.exec 'id'` 출력으로 재지정하고, pid 가 근거가 아님을 명시 |
| `OSCP 는 이 형태를 웹셸과 같은 지위로 봄` | 규정 원문은 *"any type of web-based shell"* 로 **웹셸**을 지정. Redis 모듈 커맨드로의 확장은 해석 | 규정 원문 인용 + 확장을 `[가정]` 으로 강등. 「한 화면 증거 부재는 확정」은 유지 |
| `system.rev … 이 박스에서는 실행하지 않았음` | `writeup_notes.txt` 가 443·8080·21000 리버스셸 시도를 기록 — 단정과 충돌 | 「세션 캡처 0건 · 그 시도가 `system.rev` 였는지는 산출물로 확정되지 않음(관측 없음)」으로 정정 |
| `[[Butch]]` 관련 항목 | 위 강등과 불일치 | 같은 취지로 맞춤 |

**삭제한 것 — 없음.** 정정·강등·복원만 수행함.

---

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **코드펜스 원문성** — 여는 펜스 18개를 전부 산출물과 바이트 대조. `nmap.log` 1~19행(캡션의 행 범위 정확) · 91행(`27017/tcp` 가 실제로 91행) · `nmap_lowrate.log` 전문 · `redis_recon.txt` 전문(CRLF 포함 내용 일치) · `module_list.txt` · `id_output.txt` · `mongo_nmap.txt` · `exploit_run.log` · `verify_run.log`(gb18030 바이트열 한 글자까지) · `manual_procedure.txt` §0·§1·§2 · `exp.c` `RedisModule_OnLoad`(탭 들여쓰기까지) · `popen` 20행 · `flags.txt`. **압축·생략·한국어 주석 삽입 0건.** 개작 전 있던 창작 주석(`<-- 소스 컴파일`·`(NodeBB, Node.js)` 등)은 전부 제거된 상태.
2. **pty 판정** — 작성자 보고가 정확. 타겟 pty 프롬프트가 **원래 0개**였고 새 노트도 0개. 지워진 것은 `$ redis-cli` 형태의 **Kali 측 창작 프롬프트**뿐. 2026-08-20 Fikklish 형 사고(실측 표식 제거) **해당 없음.**
3. **objdump 수치** — Kali 에서 직접 재실행: 재빌드 `exp.so` = `GLIBC_2.2.5`, `exp.so.prebuilt.bak` = `GLIBC_2.2.5`·`GLIBC_2.4`. 노트의 「둘 다 2.24 이하라 재빌드가 성공의 원인이었다는 증거는 없음」 **정확**.
4. **노트가 자기 산출물에 반박당하는 곳 0건** — 스크린샷 2장을 직접 열어 대조. `PG-Wombo-nodebb-8080.png` 에 Announcements/General Discussion/Comments & Feedback/Blogs **4개 카테고리 전부 `0 TOPICS` `0 POSTS`** — 노트의 「4개 카테고리 전부 0 topics / 0 posts」와 일치. `PG-Wombo-nginx-80.png` 은 nginx 기본 페이지 — 「콘텐츠 없음」과 일치. 스크린샷 mtime 12:11 로 플래그 회수(12:02) 이후이자 박스 생존 중.
5. **`local.txt` 「없음 + 근거 3개」** — 셋 다 산출물로 뒷받침됨. `flags.txt` 본문 · `writeup_notes.txt` `[FLAGS]`(find 무결과·`/home` 비어 있음·`/home/nodebb` 미생성) · **0바이트 `flags_raw.txt`(12:00:46)**. 노트가 이를 「빈 파일이 아니라 빈 응답을 받았다는 기록」으로 적은 것도 정확.
6. **「남긴 흔적」 전수** — cron 항목(`/etc/cron.d/pwnjob`, `plant_cron*.log` 두 번 다 `OK`) · `/exp.so` · `exp.so` 모듈 · **SSH 공개키는 심긴 적 없음**(`wombo_key.pub` 는 `plant_cron*.sh` 의 크론 문자열 안에만 존재하고 그 크론이 미실행, `config set dir /root/.ssh` 는 `ssh_dir_check.txt` 에서 실패) — 전부 산출물과 일치. `/etc/cron.d/zz`·`/var/spool/cron/crontabs/root` 의 생성 스크립트가 산출물에 없다는 「관측 없음」도 정확(두 `plant_cron` 스크립트는 `pwnjob` 만 씀).
7. **`Privilege Escalation – 없음` 판정 자체** — 타당. `system.exec` 첫 명령이 `uid=0`. 구조(4항목)만 결손이었고 판정은 옳았음.
8. **완료 1/1 · 증거 형식 미달** — 작성자 판정 그대로 성립하고, 노트가 그 한계를 `Post-Exploitation` 에 명시하고 있음.
9. **문체** — 코드펜스 밖 산문에서 서술형 종결(`했다`·`이다`·`된다`·`한다`·`있다`·`없다`) **0건**. `pg-doc-reviewer` 이관 대상 0건.
10. **색인** — `manual_tags: true` + `tech/svc/redis` 1개 + `tech_count: 1` 정합. nmap raw 포트 라인 12개 보존 → `PORT_RE` 정상. 여는 펜스 18개 전부 언어 태그 있음. `## Target #1` 래퍼 · 두 `Initial Access` 제목 상이 · 헤딩 레벨 전부 정상.

---

## 4. 총괄에 올릴 것

- **색인 갱신 필요** — 본문 수정으로 `refresh.ps1` 재실행 대상. 감사자는 실행하지 않음(공유 인프라).
- **`services` 중복(`mongod`/`mongodb`)** — `nmap_lowrate.log` 가 `mongod`, `nmap.log` 가 `mongodb` 로 찍혀 `extract.py` 가 둘 다 잡을 소지. 현재 프론트매터는 `mongodb` 하나뿐이라 노트 쪽 문제 아님. 공유 인프라라 손대지 않음.
- **`_STATUS.md` 판정(기록은 `pg-line-manager` 몫)** — Wombo **완료 1/1**. 근거: `proof.txt` = `d3441ce13f1b497ccb0575effb70ba65`(`flags.txt`), `local.txt` 는 이 호스트에 부재. 단 **증거 형식은 미달**(`proof_root.txt` 한 화면 없음, 전부 비대화형 `system.exec`).
- **`_playbook.md` 12번의 「반증」 표현** — 「익스플로잇 5분」은 반증이 아니라 `근거부족`(§1-3). append 시 문구 조정 권고.
