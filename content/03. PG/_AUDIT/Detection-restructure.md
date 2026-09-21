# Detection — 구조 전환분 적대적 검증 + 정정 (2026-08-24)

- 대상: `03. PG\Detection.md` (162행 → **181행**) · `03. PG\_PLAYBOOK.md` (258행 → **277행**)
- 대조 기준: `03. PG\_backup\Detection.md.bak` (220행, 구 9장 구조)
- 판정: **날조 0건.** 손실은 전부 「이관하며 실측 블록을 떨어뜨린 것」. 새로 잡은 사실 오류 1건(SUID 개수).
- 박스 정지 상태 — 재접속 전제 서술 없음. 모든 확인은 `~/PG/Detection/` · 볼트 `파일보관\` · `.bak` 안에서만 수행.

## 근거 출처

- Kali `~/PG/Detection/` — `pty_shell_evidence.log` · `listener/{shell443.log,nc443.log,http80.log}` · `proof_root.txt` · `harvest_root.txt`(1336행) · `writeup_notes.txt` · `nmap-udp-top100.txt` · `ssti/{settings.html,pwn.sh,p*.j2}` · 디렉터리 mtime(`--time-style=full-iso`)
- 볼트 `파일보관\PG-Detection-notification-ssti-payload.png` — **직접 열어 판독**
- `03. PG\_AUDIT\Detection-audit.md`(2026-08-21 선행 감사) · `03. PG\_WRITEUP-STANDARD.md` 71행~ 「노트 구조」
- `_INDEX/_tools/extract.py:142` `PORT_RE` 원문 확인(실행 안 함 — 공유 인프라)

---

## A. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `_PLAYBOOK` A-6 「원인 — 블로킹 페이로드」 | **타겟 pty 프롬프트 소실.** `.bak` 163행의 `pty_shell_evidence.log` → `root@detection:/#` 인용이 노트·`_PLAYBOOK` 어느 쪽에도 없었음. 「1차에 실제로 root 셸을 잡았고 재발사가 죽였다」는 인과 자체가 사라져 「블로킹이라 못 잡았다」로 오독됨 | 리스너 실측 2행(`connect to … 37522` + `root@detection:/#`)을 코드펜스로 복원 + 출처 표기. 「재발사가 죽였다」 인과 명시 |
| `_PLAYBOOK` B-1 「트리거가 저장인지 테스트 발송인지」 | **가장 강한 근거 ⓑ 의 실측 원문 소실.** `.bak` 99~102행의 apprise POST JSON 이 통째로 빠지고 서술만 남음. 출처 경로도 없었음 | ⓐ시각 / ⓑ내용 두 근거로 복원, `nc443.log` 원문 JSON 블록 + 출처 경로 복원, ⓑ가 더 강한 이유 명시 |
| `_PLAYBOOK` B-1 따옴표 중첩 항목 | **stderr 원문 2줄 + 인과 서사 + 증거등급 유보 소실.** `.bak` 183~186행이 문자열 한 조각(`Servname not supported…`)으로 축약됨 | stderr 2줄 코드펜스 복원 + 「`http80.log` 에 없고 `writeup_notes.txt` base64 원문뿐」 유보 복원 + `.j2` 4개 실제 따옴표 형태 복원 |
| `Detection.md` 2장 스크린샷 | `![[PG-Detection-notification-ssti-payload.png]]`(`.bak` 77행)이 소실. **파일은 `파일보관\` 에 실재**(145,295 B, 2026-08-21 14:10) | Initial Access `Steps to reproduce` 뒤로 복원 + 무엇이 찍힌 화면인지 캡션·Kali 원본 경로 표기 |
| `Detection.md` 「SUID 섹션은 40개」 | **사실 오류.** `harvest_root.txt` 36~74행 = **39개**, 75행은 빈 줄. 선행 감사(`Detection-audit.md` A절)가 40으로 세어 `.bak` 이 그대로 상속함 | **39개**로 정정. 아울러 `/usr/lib` 하위 실제 경로(`dbus-1.0/`·`openssh/`·`eject/`·`snapd/`)와 snap 리비전 4개(`core20/{2015,2318}`·`snapd/{21759,20290}`)로 정정 — `.bak` 은 `core20/2015` 하나만 적었음 |
| `Detection.md` `Vulnerability Fix:` | **방어 관점 3건 소실.** `.bak` 8장의 「비-root 계정 구동」·「`/backup`·`/settings` 인증 강제」·「5000 직접 노출 금지」가 이관되지 않음. STANDARD 는 방어를 별도 장이 아니라 finding 의 `Vulnerability Fix` 에 두라고 규정 | 세 항목을 `Vulnerability Fix` 에 압축 복원 |
| `Detection.md` Initial Access 재현 산문 | **수동 대안 소실.** `.bak` 138행이 「6장·7장 참조」로 넘겼는데 6·7장이 사라지며 노트에서 통째로 빠짐. STANDARD 68행 「수동 대안을 항상 병기, 자리는 해당 finding 절의 재현 산문」 위반 | `setsid nohup` 리버스셸 형태 + **「이 박스에서 쓰지 않았고 검증되지 않음 [가정]」** 유보를 함께 복원, B-1 앵커 링크 병기 |
| `Detection.md` `Vulnerability Explanation:` | 토큰 렌더 주장의 출처 표기 소실(`.bak` 75행 「설정 화면 하단 토큰 표에 명시」) | 스크린샷 판독으로 확인한 화면 문구(`You can use Jinja2 templating in the notification title, body and URL`)와 토큰 표를 근거로 복원 |
| `Detection.md` Post-Exploitation `Proof.txt value:` | 「`proof_root.txt` 의 프롬프트 + 한 화면」이라고 **서술만** 하고 실측 한 화면이 없었음(`.bak` 도 동일). STANDARD 126행은 한 화면 출력 자체를 요구 | `proof_root.txt` 원문 한 화면을 코드펜스로 복원(줄바꿈까지 원문 그대로) — 타겟 pty 프롬프트 2개 추가 확보. UTC 05:08 = KST 14:08 환산 명시 |

## B. 삭제한 것

**없음 (0건).** 정정·복원·강등만 수행함.

## C. 반증한 것 — 지적으로 올랐거나 복원 후보였으나 확인 결과 그대로 두는 것이 옳았던 것

1. **「stderr 를 base64 콜백으로 빼는 것이 blind SSTI 의 유일한 피드백 채널」이 소실됐는가 → 반증.** 관리자 지적 3번의 후단이 이것을 확인 요청했는데, **이미 살아 있었음** — `_PLAYBOOK` B-1 「출력이 안 돌아오는 sink 의 디버깅」 항목 + A-1 4번(진단 페이로드 원형)에 인과까지 보존돼 있음. 소실된 것은 **stderr 원문 2줄과 그 실패 서사**뿐이고 교훈 자체는 이관 성공. 중복 복원하지 않고 새 항목에서 「바로 위 항목」으로 참조만 걸었음.
2. **`.bak` 163행 「tcpdump 상 SYN 9회 전부 무응답」 → 복원하지 않음. 근거부족.** 고정 출처 목록 안에 pcap 파일이 없고(`~/PG/Detection/` 에 `.pcap` 부재), `writeup_notes.txt`·`cleanup.txt` 어디에도 SYN **횟수**가 없음(`cleanup.txt:35` = 「SYN 무응답(nmap: filtered)」, `writeup_notes.txt:46` = 「SYN drop」). 현행 A-6 의 일반화된 표현(「SYN 전부 무응답」)이 오히려 증거에 맞는 형태라 그대로 둠. 검증 안 된 수치를 이관 규율을 이유로 되살리는 것은 개악임.
3. **`.bak`·현 노트의 「UDP top-100 = 10 closed / 90 open|filtered, 배제가 아니라 미확정」 → 노트가 옳음.** `writeup_notes.txt` 는 「UDP 전부 closed」로 적었으나 `nmap-udp-top100.txt` 원문이 `Not shown: 90 open|filtered udp ports (no-response)` + closed 10개 열거. **산출물 원문이 작업 메모를 이김** — 노트 무수정.
4. **nmap raw 출력 라인 → 보존 확인.** `22/tcp   open  ssh …` · `5000/tcp open  http …` 가 코드펜스 안 원문 형식 그대로 있고, `extract.py:142` `PORT_RE = ^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)` 에 정규식으로 대조해 **둘 다 매칭**. `ports: [22, 5000]` 색인 안전. 표는 대체가 아니라 추가로 병존함.
5. **finding 4항목 온전성 → 이상 없음.** `Initial Access` 에 `Vulnerability Explanation:`·`Vulnerability Fix:`·`Severity:`·`Steps to reproduce the attack:` 4개 모두 존재. `Severity: Critical` 은 「무인증 원격 RCE + 프로세스 root 구동」이라는 근거와 일치(등급 판정 그대로 유지). `Privilege Escalation` 은 「없음(초기 접근이 곧 root)」이며 **4항목 생략 사실과 그 이유가 본문에 명시**돼 있고, 근거로 `harvest_root.txt` PROCS 의 pid 844 root 구동 + SUDO 원문 2행이 붙어 있음 — 재확인 결과 `harvest_root.txt:165`(LISTEN, pid=844)·`:372`(PROCS, root 844) 그대로임.
6. **타임존 자기모순 없음.** `proof_root.txt` 의 `Fri 21 Aug 2026 05:08:05 AM UTC` = KST 14:08 이고 `writeup_notes.txt` 14:08 항목·`backup.zip`(14:08:23)·`harvest_root.txt`(14:09:06) mtime 과 정합. `http80.log` 본문 시각(13:41:54 등)은 KST 로 찍히는 Python `http.server` 로그라 mtime 과 같은 축임.
7. **`pty_shell_evidence.log` mtime(13:58:32)이 서사(13:45 셸 획득)보다 늦은 것 → 모순 아님.** 내용·크기(239 B)가 `listener/shell443.log`(mtime 13:45:06)와 동일한 **사본**이고, 13:58 은 `ssti/pwn.sh`(13:58:32)와 같은 시각 = 증적 정리 시점. 시간 서사 반증 실패.
8. **Kali 프롬프트 창작 0건.** `┌──(kali㉿kali)`·`└─$` 가 두 파일 어디에도 없음. 반대로 타겟 pty 프롬프트는 **제거하지 않고 3개 늘렸음**(Fikklish 사고 재발 방지).

## D. 최종 상태 검산

- `Detection.md` 162 → **181행** · `_PLAYBOOK.md` 258 → **277행**
- 타겟 pty 프롬프트: `Detection.md` 코드펜스 안 **3개**(`root@detection:~#` ×3) + 산문 참조 1 / `_PLAYBOOK.md` **1개**(`root@detection:/#`) = 총 4
- 복원한 실측 코드블록 **4개** — pty 프롬프트 · apprise POST JSON · stderr 2행 · proof 한 화면
- 복원한 스크린샷 임베드 **1개**(파일 실재 확인 후 링크)
- 플래그 값 `05a2b432fb4eb4091fb7ed500bb7a9bd` 2회 보존 · IP · 명령 원문 · `[가정]` 5곳 · 「관측 없음」 서술 전부 보존
- 「적대적 검증 정정 이력」 콜아웃 노트 본문 유입 **0건**
- `_PLAYBOOK` 절 제목 **무변경**(앵커 무손상) — append·복원만 수행

## E. 총괄에 올릴 것

1. **색인 갱신 필요** — 노트 본문이 바뀌었으므로 `refresh.ps1` 재실행 대상. 공유 인프라라 돌리지 않았음.
2. **`_STATUS.md` 판정: 완료 (1/1)** — `proof_root.txt` 대화형 pty · harvest FLAGS 전수 탐색 `/root/proof.txt` 단일. 직접 편집하지 않았음.
3. **선행 감사(`Detection-audit.md`)의 SUID 「40개」가 오류였음** — 그 파일은 이력이라 수정하지 않았고 이 파일에 기록함. 같은 오류가 다른 노트에 상속됐는지는 미확인.
4. **문체 이관 0건** — 구조 전환분에서 서술형 종결·번역투가 새로 유입된 곳을 찾지 못함. `pg-doc-reviewer` 로 넘길 항목 없음.
5. **태그 검토(선행 감사에서 이월)** — `tech/payload/revshell` 은 1차 시도의 python3 pty 리버스셸이 **실제로 성공**했으므로(`pty_shell_evidence.log`) 유지가 옳음. 단 그 서사가 이제 노트가 아니라 `_PLAYBOOK` A-6 에만 있어 노트 본문만 보면 근거가 안 보임 — taxonomy 는 공유 인프라라 손대지 않았고 판단만 올림.
