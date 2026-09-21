# Robust 개작 기록 (2026-08-25)

## 작업 내용
- `03. PG\Robust.md` 329행 → 284행. 백업 `03. PG\_backup\Robust.md.bak`.
- 옛 0/6/7/8장 → OSCP 보고서 형식(Service Enumeration / Initial Access / Privilege Escalation / Post-Exploitation / 관련)으로 전환.
- H1(`# Robust`) 제거 — STANDARD 템플릿·[[Detection]] 예시 모두 H1 없음. frontmatter `ip` 필드가 이미 타겟을 특정하므로 파일 자체가 타겟이라는 원칙 적용.
- `_PLAYBOOK.md` 471행 → 552행(+81). 신규 항목 4개(A-15·A-25·B-15·B-43) + 기존 항목 append 3건(A-24·A-41·B-12 — B-12 는 플레이스홀더 "이관 웨이브에서 채울 것"을 실제 내용으로 채움) + C-2·D 절 보강 2건.
- nmap raw 라인(`22/tcp open ssh...`·`80/tcp open http...`) 보존 확인. 코드펜스 언어 태그 전량 확인(`text`/`bash`/`sql`, 누락 0).
- 스크린샷 4개(403·login·home·sqli) 전량 재배치, 파일보관 실재 확인.
- 타겟 pty 프롬프트(jeff·administrator) 원문 그대로 보존. Kali 프롬프트는 원래도 없었음(신규 생성 안 함).

## 이관 매핑
| 원 절 | 이관 위치 |
|---|---|
| 0-a 헤더우회 | B-15(신규) |
| 0-b/0-c 수동UNION·엔진오판 | B-12(플레이스홀더 채움) |
| 0-d Sticky Notes | B-43(신규) |
| 0-e 시험출제가능성 | B-12·B-15 말미에 흡수 |
| 6-a DB엔진오판 상세 | B-12 |
| 6-b home.php 302 함정 | A-15(신규) |
| 6-c gobuster blacklist | A-15(신규, 같은 항목에 병합) |
| 6-d 앱로그인폼 미끼 | A-25(신규) |
| 6-e 자격증명≠앱로그인 | A-24(append) |
| 6-f 권한상승경로소거 | A-41(append) |
| 7 전체(체크리스트·헤더배치·SQLi절차·엔진치트·시간배분) | B-15/B-12/C-2/D 에 분산 흡수 |
| 8 방어관점 | 각 finding Vulnerability Fix 로 흡수 |
