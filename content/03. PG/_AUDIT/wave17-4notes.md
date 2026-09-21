---
type: audit
platform: pg
manual_tags: true
manual_cves: true
---
# 웨이브 17 — 소급 개작 4건 (plum · Flu · Algernon · Heist)

작성 `pg-note-forge` ×4 → 적대적 검증 `writeup-auditor` ×4 → 관리자 교차검증. 2026-08-26.

## 1. 노트별 결과

| 노트 | 원본 → 작성 → 감사 | 판정 | 감사 정정 | 손실 발견 |
|---|---|---|---|---|
| `plum` | 1266 → 878 → **936** | 완료 2/2 | 19건 | **118줄**(작성자 이전 소실) |
| `Flu` | 1269 → 1034 → **1105** | 완료 2/2 | 14건 | 0줄 |
| `Algernon` | 1270 → 686 → **712** | 완료 1/1 | 8건 | 4줄(재현 무관, 원문 보존) |
| `Heist` | 1352 → 860 → **858** | 완료 2/2 | 6건 | 0줄 |

**감사 단계에서 4건 모두 행수가 늘었다** — 실측 복원분이다. 작성자 4명 전원이 「손실 0/경미」로 보고했으나 감사에서 실질 손실이 나왔다(웨이브 15 와 같은 패턴).

## 2. 구조 검산 (관리자 직접 확인)

| 항목 | plum | Flu | Algernon | Heist |
|---|---|---|---|---|
| 무태그 여는 펜스 | 0 | 0 | 0 | 0 |
| 펜스 균형(짝수) | 84 ✓ | 58 ✓ | 64 ✓ | 60 ✓ |
| 골격 헤딩 7종 | ✓ | ✓ | ✓ | ✓ |
| 두 `Initial Access` 제목 상이 | ✓ | ✓ | ✓ | ✓ |
| `_AUDIT` 경로 노출 | 0 | 0 | 0 | 0 |
| 스크린샷 embed | 13 | 6 | 1 | 14 |

`Algernon` 만 `### Privilege Escalation – 없음 (MailService 가 LocalSystem 으로 구동)` 으로 4항목 생략 — 정본이다. `local.txt` 는 「없음 + 근거」.

## 3. 관리자 교차검증 — 표본 대조 실측

세 건을 직접 되짚었다.

**① plum 354행 헤딩 — 내 지시가 틀렸다.**
관리자가 「골격 밖 h3 가 끼었다」고 지목했으나, 펜스 인식 파서로 확인하니 372행 `### PluXml 5.8.7 RCE` 는 ` ```text ` 펜스 **안**의 README 인용이다(`fence_inside=1`). 단순 `grep '^### '` 이 펜스 안팎을 구분하지 못해 생긴 오탐. 감사자 반증이 정확했다.

**② plum 메일함 실측 복원 — 감사자 주장 확인됨.**
`git show 15671e5` 초판 162~285행에 `/var/spool/mail/www-data` 전사(`Unrouteable address`·`debian@localhost`·`drwxrwsr-x`)가 있었고 `aba5a29` 에서 소실됐다. 현재본 799~813행에 복원돼 있다. **두 번의 개작과 감사가 이 손실을 못 잡았다** — 작성자가 최초판을 열지 않고 직전 개작본만 봤기 때문이다.

**③ Heist rockyou 598행 — 감사자 정정 확인됨.**
Kali 에서 `grep -n -x california /usr/share/wordlists/rockyou.txt` → `598:california`. 원본의 「4,096번째 후보」는 `Progress: 4096` 을 정답 순번으로 오독한 것이었다(그 값은 배치 경계까지 올림된 처리 후보 수). 노트 50행에 「rockyou **598행**」으로 반영됨.

## 4. 감사자가 반증한 것 — 지시서 수치 오류

관리자가 워커 프롬프트에 박은 확정 사실 중 셋이 실측과 달랐다.

- **plum 스크린샷 「12개」** — 실제로는 미참조본이 둘 더 있었다(`142105` SUID 화면 · `130002`). 작성자가 `142105` 를 발굴해 `[가정]`→실측 승격, 감사자가 한 장 더 걸어 **13장**.
- **Heist 스크린샷 「12장」** — 실제 embed 는 **14장**(`155102`·`155109` 누락). 14장 전부 유지됨.
- **Heist nmap raw 「54바이트 차이」** — 실제는 3243B vs 3124B = **119B** 이고 헤더 83B + 푸터 32B + 후행공백 4B 로 전액 설명된다. **절단 없음.**
- **plum·Flu 「무태그 코드펜스 0개」** — plum 초판 1045행 `sudoers(5)` 블록이 무태그였다(이관분이라 제안 파일에서 `text` 태그로 처리).

## 5. 작성자 보고 중 깨진 것 (교차검증에서 확인)

| 노트 | 작성자 주장 | 실제 |
|---|---|---|
| plum | 「코드블록 43개 중 42개 md5 동일」 | **불일치 4건** — nmap 합성 · `drwxrwsr-x`→`drwxrwxr-x` 개변 · 리버스셸 공백 1자 · README 1줄 절단 |
| plum | 「삭제 457줄 = 이관 16건」 | 성립 안 함. 실측 손실 118줄 별도 존재 |
| Flu | 「Kali 프롬프트 5블록이 창작 의심」 | **4블록**. `head -8 51904.py` 는 이미 이관돼 노트에 없었다 |
| Flu | 「nmap raw 109행 5,377B」 | 실측 **105행 5,302B**(md5 `46bd5eab…`, 세 판 전부 동일) |
| Algernon | 「전역 재귀 검색 미실시 = 관측 없음」 | **했다.** `shell_session.log` 8~9행에 `dir C:\ /s /b` 실행 기록. `2>/dev/null` 이 Windows 리다이렉션이 아니라 판정 불가였을 뿐 → 「배제」가 아니라 **「미완」** |
| Algernon | 신설한 시험증거 명령 `whoami & hostname & …` | **이 박스 셸에서 안 돈다.** PS 5.1 파싱 거절, PS7 은 백그라운드 잡으로 출력 소실. 원본의 `;` 형태가 옳았고 작성자가 깨뜨렸다 |
| Algernon | 「Kali 프롬프트 12→0, 출력 보존」 | curl 2줄(`stProductBuild`·`login-v-`)을 통째로 잃어 버전판정 재현이 끊겼다. git 원본에서 복원 |
| Heist | jq 블록 손 축약 정정 | 사실. 다만 **크랙 블록의 축약 2건**(`0101000000000000…`)은 작성자가 못 봤고 감사자가 673자 전문 복원 |

## 6. 감사자가 스스로 반증한 것 (건전한 자기교정)

- **Heist** — Kali 프롬프트 9블록을 창작으로 걷어내려다 철회. `~/.zsh_history` 부재만으로는 **등급 상한이 `근거부족`**이고(HISTSIZE 트리밍이 이미 문서화됨), 노트 L37 이 이미 `[가정]` 강등 표기를 하고 있었다.
- **Algernon** — 지시받은 의심점 중 **9건이 반증**됐다(노트가 옳았음). md5 불일치 0 · 두 `Initial Access` 는 STANDARD:97·114 템플릿 그대로 · `manual_*` 은 `extract.py:173·175` 에 실재 · nmap raw 훼손 0 · CVE 오염 0 · 타겟 pty 프롬프트 6개 전량 보존.
- **Flu** — 지목된 nmap 절단 위험이 완전 반증(세 판 md5 동일). 1차 세션 프롬프트 5블록은 `zsh_history:1840~1859` + 스크린샷 2장으로 **실측 확증**돼 손대지 않았다.

## 7. `_PLAYBOOK` 이관 제안 (총괄 반영 대기)

| 파일 | 건수 |
|---|---|
| `_AUDIT\plum-playbook.md` | 16건 (병합 16 · 신규 0) |
| `_AUDIT\Flu-playbook.md` | 17건 (병합 16 · 신규 1) |
| `_AUDIT\Algernon-playbook.md` | 20건 (병합 17 · 신규 3) |
| `_AUDIT\Heist-playbook.md` | 14건 (병합 10 · 신규 4) + §6-10 원문 부록 |

**합계 67건 — 병합 59 / 신규 8.**

### 🔴 반영 전 반드시 볼 것

- **`_AUDIT\plum-playbook.md:348` 이 틀린 채로 대기 중이다.** 「`Unrouteable address`·`debian@localhost` 는 어떤 산출물에도 없다」고 적었으나 **git 초판 전사에 축자로 있다.** 같은 파일 `:344`(sudo 시각 2건 정황 방어)는 불필요하고, `:198`(「57분 원인 미상」)도 절반 설명된다 — 13:57:06·14:12:46 에 `sudo -l` 실패 2회.
- **`_AUDIT\plum-playbook.md` 제안 P4·P11 에 「반영자 주의」가 붙어 있다.** 원문 타임라인의 `find / -perm -u=s` 행과 「비밀번호 에코 = TTY 없음」 문구를 **그대로 옮기면 안 된다.**
- **`_AUDIT\Flu-playbook.md` 검산표의 「nmap raw 109행 / 5,377바이트」·「코드블록 1개 변경」 두 수치가 실측과 어긋난다.** 이관 내용 자체는 손실 0으로 확인됐으나 **그 표를 근거로 쓰지 말 것.**
- **`_AUDIT\Algernon-playbook.md`** — `# alg80: 1 windows (created Thu Aug 20 11:01:19 2026)` 1줄이 이관 파일에도 없다.
- **신규 8건은 번호 미배정.** 배정 후 각 노트 `## 관련` 에 앵커 추가 필요(Algernon 3 · Heist 4 · Flu 1).

## 8. 프론트매터 변경 — 색인 갱신 필요

`refresh.ps1` 은 규율대로 **미실행**(총괄 몫).

| 노트 | 변경 |
|---|---|
| plum | `tech/web/code-injection` 추가, `tech_count: 4` |
| Flu | `manual_ports: true` · `manual_services: true` 추가(8091 `jamlink` 오탐 색인 차단, raw 는 보존) |
| Algernon | `manual_ports`·`manual_services` 신규 선언, `services` 에서 오탐 `distinct32` 제거, `tech/svc/ftp`→`tech/enum/searchsploit` |
| Heist | `tech/exec/rdp` 추가(경로 A 가 xfreerdp3), `tech_count` 10→11 |

## 9. 총괄에 올리는 것

**태그 taxonomy 신설 요청 — 공유 인프라라 관리자가 못 고친다.**
볼트 전체에 `tech/ad/gmsa`·`tech/ad/coerced-auth` 가 없다. Heist 의 실제 기법 둘이 태그로 표현 불가라 현재는 `tech/ad/ntlm-relay`(릴레이는 **실패한** 경로다)를 Responder 버킷으로 대용 중. `extract.py:64` 수정이 필요하다.
⚠️ **`_AUDIT\Vault-audit.md:168` 에서 이미 올라간 건과 동일 사안** — 중복 제기다.

## 10. `_STATUS.md`

**판정 변경 없음.** 네 박스 모두 이미 완료 목록에 정확한 플래그 수로 등재돼 있다(Algernon 1/1 · Flu 2/2 · Heist 2/2 · plum 2/2). 소급 개작이므로 편집 불필요.

검산: 완료 53 + 부분 5 + 미착수 225 = **283 ✓**

## 11. 플래그 값 (감사자가 스크린샷·산출물과 한 글자씩 대조)

| 박스 | local.txt | proof.txt |
|---|---|---|
| plum | `26780c227fb20c4d1eb303a7536de3bd` | `b0d62860a794cb90eb6ac02cee93c579` |
| Flu | `52791694c2a6ccde2db0f566f81d084f` | `2caa37b3c096709c688b69556c3c6cf7` |
| Algernon | 없음(미배치, 근거 기재) | `6126cdddc1ed43d92e8a34f71ecda278` |
| Heist | `a1909577c8fb09bed9a1ff474af80620` | `b041c78918d81a4a4a15732053a1e416` |

Flu 1차 세션 `local.txt` = `2d0c7239ce98c1add6986385f076c26e` — 제출됐으나 리버트로 무효.
전부 대화형 셸에서 원위치 `cat`/`type` — **웹셸 경유 아님**(시험 규정상 유효).
