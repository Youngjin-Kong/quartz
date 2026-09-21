---
type: audit
box: Fanatastic
manual_tags: true
manual_cves: true
---

# Fanatastic 적대적 검증 + 정정

대상: `03. PG\Fanatastic.md`(개작본 418행) · 원본 `03. PG\_backup\Fanatastic.md.bak`(886행) · 정정 전 백업 `03. PG\_backup\Fanatastic.md.bak2`
판정: **2/2 완료**(local `de1e53adbb59aa276d386e13838cb680` · proof `a0e3b952a1332b4b36bfb009b2747ded`) — 값 출처는 노트 원본 기록뿐, `proof_*.txt` 없음

---

## 근거 출처

| 종류 | 실제로 본 것 |
|---|---|
| Kali 산출물 | `~/PG/Fanatastic/` 전량 — `nmap.log` `nmap.stdout` `etc_passwd.txt` `gobuster_3000.txt` `gobuster_9090.txt` `grafana.ini` `grafana.db` `decrypt.py` `root_id_rsa` `screenshots/`(5장) |
| mtime | `ls -la --time-style=full-iso ~/PG/Fanatastic/` — 08:37:46 ~ 08:40:15 (2026-08-20, KST) |
| 볼트 스크린샷 | `파일보관\PG-Fanatastic-grafana-login.png` · `-prometheus-graph.png` · `-prometheus-targets.png` (직접 열어 판독) |
| Kali 스크린샷 | `screenshots/pg_grafana_api_health.png` · `pg_prometheus_buildinfo.png` (scp 회수 후 직접 판독) |
| `~/.zsh_history` | 3165행. `Fanatastic`·`248.181`·`grafana`·`debugfs`·`path-as-is` **매치 0건** |
| git | `03. PG/Fanatastic.md` 는 `efe8cef` 에서 **신규 생성** — 개작 전 baseline 없음 |
| 직접 실행 | `decrypt.py` 재실행 · `file grafana.db` · `sqlite3` 2회 · `ssh-keygen -y -f root_id_rsa` · curl 정규화 실험 · pycryptodome/hazmat CFB 비교 |

### 직접 실행으로 확정한 일반 지식

```
# curl 기본 vs --path-as-is (nc 리스너로 실제 요청 라인 캡처, curl 8.17.0)
기본:        GET /etc/passwd HTTP/1.1
--path-as-is: GET /public/plugins/alertlist/../../../../etc/passwd HTTP/1.1
```
```
pycryptodome AES.MODE_CFB 기본 == segment_size=128 ?  False
cryptography hazmat modes.CFB.__init__ 시그니처: (self, initialization_vector: 'bytes')
hazmat 에 별도 CFB8 클래스 존재: True
```
```
# decrypt.py 재실행 — 노트 코드펜스와 바이트 단위 일치
salt= b'jpgyaMCl'
iv  = fe2031a1cf76bbc316aa8e29ae825497
PLAINTEXT: b'SuperSecureP@ssw0rd'
```

---

## 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `907행의 빈 값은 별개 섹션(엔벨로프 암호화 키 프로바이더)이라 무관` | **노트가 자기 산출물에 반박당함.** `grafana.ini` 900~910행은 `[external_image_storage.s3]` — S3 액세스 시크릿이지 엔벨로프 키 프로바이더가 아님 | 실제 섹션명으로 정정. 223행이 `[security]`(바로 위 주석 `# used for signing`), 225행은 `encryption_provider` 설명 주석이 grep 에 걸린 것임을 함께 명시 |
| `debugfs -R "cat /root/.ssh/id_rsa" /dev/sda2 > root_id_rsa` | **실측 명령 개변.** 원본은 `> /tmp/root_id_rsa`(타겟). 리다이렉트 대상이 Kali 인 것처럼 바뀜 | 원본 명령 복원 + 타겟 실행/타겟 리다이렉트임을 산문으로 명시. Kali 사본으로의 전송 명령은 「관측 없음」 |
| 남긴 흔적 표 `타겟에는 심지 않음 … 타겟 파일시스템 변경 없음` / `타겟 파일시스템 변경 \| 없음` | 위 개변에서 파생된 **내부 모순**. 실제로는 타겟 `/tmp/root_id_rsa` 를 남김 | 두 행 정정 — 「타겟 `/tmp/root_id_rsa` 남김, 정리하지 않음」. `debugfs -w` 미사용은 유지 |
| `df -h /` · `debugfs -R "ls -l /root/.ssh"` 블록 | **타겟 pty 프롬프트 `sysadmin@fanatastic:~$` 가 제거됨.** 같은 노트의 ssh/id 블록에는 남아 있어 표기도 불일치 | 원본대로 프롬프트 복원, `text` 단일 펜스로 통일 |
| `gobuster_9090` 블록 | 열 정렬이 원문과 다름(`/classic` 이하 8줄에 공백 1~3개 추가) | `~/PG/Fanatastic/gobuster_9090.txt` 원문으로 교체 |
| `grafana.db: SQLite 3.x database, ... database pages 187, ... UTF-8` | 실측 출력을 `...` 로 두 곳 생략 | `file grafana.db` 재실행 전문으로 교체 + 출처 캡션 |
| `{"status":"success",...,"revision":"41f1…",...}}` | 실측 출력을 `...` 로 생략 | `pg_prometheus_buildinfo.png` 판독 전문으로 교체 + 출처 캡션 |
| `web.enable-admin-api`·`web.enable-lifecycle` 둘 다 `false` — 관리 API 경유 공격은 막혀 있음 | **관측→결론 비약.** 근거인 `/debug/pprof/cmdline` 출력 자체가 `...` 로 잘려 있고 저장 산출물 없음. 「확인했다」로 단정 | `[가정]` 강등. Prometheus 2.x 에서 둘 다 opt-in(기본 `false`)이고 관측 구간에 없다는 근거를 밝히되 단정하지 않음. 「스크랩 타겟 자기 자신뿐」은 Targets 캡처로 확인되므로 단정 유지하고 근거를 캡처로 명시 |
| `/api/health` · `/metrics` · `/debug/pprof/cmdline` 블록 | 출처 캡션 없음 — 다른 블록은 전부 붙어 있어 대비됨 | 앞 둘 중 `/api/health` 는 Kali 스크린샷 경로를 출처로 명시. `/metrics` grep 과 `cmdline` 은 「원본 기록, 산출물 관측 없음」으로 표시 |
| `ssh-keygen -y -f` 출력 | 출처 없이 `...` 로 절단 | `root_id_rsa` 재실행 일치 확인을 캡션으로 추가(전문은 인용하지 않음 — 675자 공개키) |
| `같은 시각(08:38:19, 2026-08-20)에 생성된` | **시간 서사 오류.** `grafana.ini` 08:37:55 · `grafana.db` 08:37:58 · `decrypt.py` 08:38:19 — 같은 시각이 아님 | 「`grafana.db` 회수 21초 뒤」로 정정 |
| `기법 카드는 [[_PLAYBOOK]] 로 이관됨(작업 시점 기준 관리자 반영 대기, 상세는 03. PG\_AUDIT\Fanatastic-playbook.md)` 외 2곳 | **작업 과정 기록이 노트 본문에 남음**(`CLAUDE.md` §4). 공개 발행 시 내부 감사 경로가 노출됨 | 3곳 모두 순수 `[[_PLAYBOOK]]` 링크로 축약 |
| 플래그 출처 캡션 2곳 | 「원문의 `┌──(kali㉿kali)` 프롬프트는 지우지 않되」 — **사실이 아님.** 개작본에서 그 프롬프트는 전부 제거됨 | 허위 문장 제거. 대신 양성 증거로 교체 — `~/.zsh_history` 에 다른 PG 박스 9개는 남고 Fanatastic 만 0건이므로 비대화형 작업으로 `[가정]` 판단. `proof_*.txt` 부재를 명시 |
| `segment_size` 문단의 `(2026-08-26 Kali 에서 … 실측 확인)` | 감사 날짜가 본문에 박힘(§4 「나가는 것」) | 날짜 제거, 사실만 남김. 두 라이브러리 차이를 두 문장으로 분리 |
| frontmatter | `tech_count: 3` 인데 태그 3개가 실제 경로를 덜 반영. `manual_cves` 미선언 | `tech/cred/reuse`(데이터소스 비번 → OS 계정 재사용, 이 박스의 핵심)·`tech/enum/dirbust`(gobuster 2회, 산출물 존재) 추가. `manual_cves: true` 선언(실제 악용 CVE 는 CVE-2021-43798 하나). `tech_count: 5` |
| 서술형 종결 4곳 | `~확정한다` · `~도달시키지 않는다` · `~복원된다` 등 | 명사 종결형으로 교체. 펜스 안·`[가정]`·「관측 없음」은 손대지 않음 |

**삭제한 것: 없음.** 모든 지적이 정정 또는 `[가정]` 강등으로 처리됨.

---

## 반증한 것 — 지적으로 올랐다가 확인 결과 노트/작성자가 옳았거나, 지시가 틀렸던 것

1. **`tech/payload/revshell` 제거는 타당함.** 본문 전체에 `nc`·리스너·리버스셸 페이로드가 없음. 침투는 SSH 비밀번호, 권한상승은 SSH 키. 원본 frontmatter 에만 있던 잔여 태그.
2. **`decrypt.py` 교체는 옳은 판정이었음.** 원본의 스크립트는 `[가정]` 콜아웃 안의 **재구성 참고 구현**이었고, 실제 `~/PG/Fanatastic/decrypt.py` 가 존재하며 재실행 결과가 노트 출력과 바이트 일치. 교체가 정확도를 올림.
3. ⚠️ **다만 작성자 보고의 「원본이 pycryptodome `segment_size` 함정을 “이 박스 최대 함정”으로 서술했다」는 과장임.** 원본에서 「이 박스 최대의 함정」이라는 표현이 붙은 곳은 **§2-6 `secret_key` 주석 처리**와 **§6-① `--path-as-is`(“실제로 겪은 최대 함정”)** 이고, `segment_size` 서술은 `[가정]` 표시가 붙은 재구성 콜아웃 안에서 「**`segment_size=128`이 함정이다**」로만 나옴 — 박스 귀속 실측으로 주장된 적이 없음. 원본은 스스로 「원본 스크립트 전문이 **노트에** 남아 있지 않아 재작성했다」고 정확히 적었고, 이는 문자 그대로 참(노트에 없었던 것은 사실). 정정 방향은 옳았으나 **원본의 과오 수준이 보고서에서 부풀려짐.**
4. **`--path-as-is` 서술은 참.** Kali 에서 nc 리스너로 실제 요청 라인을 캡처해 확인(위 「직접 실행」). 「curl 이 클라이언트 측에서 정규화한다」는 단정형 일반 지식이 실측으로 성립.
5. **hazmat `modes.CFB` 에 `segment_size` 가 없다는 서술도 참.** `inspect.signature` 로 인자가 `initialization_vector` 하나뿐임을 확인. pycryptodome 기본 CFB 와 `segment_size=128` 출력이 실제로 다름도 확인.
6. **버전 판정 3중 교차는 전부 실측으로 뒷받침됨.** 로그인 푸터 `v8.3.0 (914fcedb72)` 는 볼트 스크린샷에서 육안 판독, `/api/health` 는 Kali 스크린샷에서 JSON 전문 판독. 두 근거의 커밋 해시가 일치.
7. **nmap raw 출력은 압축·생략 없이 `nmap.log` 와 완전 일치.** `PORT_RE` 가 긁을 `22/tcp   open  ssh …` 3줄 온전. `Port Scan Results` 표 존재.
8. **구조는 `_WRITEUP-STANDARD.md` 및 실물 기준 `Robust.md` 와 절 단위로 동일.** 두 finding 각각 4항목 완비, 첫 `Initial Access` 는 4항목만, 두 `Initial Access` 제목이 서로 다름, 헤딩 레벨 정합. **구조 결손 0.**
9. **무태그 코드펜스 0건**(여는 펜스 34개 전부 언어 태그). 펜스 안에 한국어 주석·해설 혼입 없음 — `decrypt.py` 안의 영문 주석은 원본 파일 그대로.

---

## 이관 손실 점검 (`03. PG\_AUDIT\Fanatastic-playbook.md`)

요구 4항목 = ①어느 절 ②병합/신규 ③넣을 본문 ④지우기 전 원문.

| 제안 | ④ 상태 |
|---|---|
| A-신규-1 ~ A-신규-6 (6건) | ✅ 「지우기 전 원문: 위 인용과 동일(구 노트 6-⑤ 전문)」. 원본 §6 과 대조해 내용·인과 보존 확인 |
| B-신규-f (1건) | ⚠️ **부분 손실** — 콜아웃 골격은 인용됐으나 20행짜리 pycryptodome 스크립트 본문이 `> [python: pycryptodome 기반, segment_size=128 명시]` 한 줄로 대체됨 |
| B-신규-a·b·c·d·e·g·h·i (8건) | ❌ **④ 필드 자체가 없음** |
| C/D/E (3건) | ⚠️ 「구 노트 7장 1~17번 전문(git 이력에 보존됨)」 — 포인터만, 인용 아님 |

**④ 누락/부분 합계 12건**(전무 8 · 부분 1 · 포인터 3). 다만 `03. PG\_backup\Fanatastic.md.bak`(886행) + `_backup\Fanatastic.md.pre-readability2-20260821.bak` + git `efe8cef` 로 **원문 전량이 실제로 복구 가능**하므로 되살릴 수 없는 손실은 아님. 아래에 B-신규-f 의 누락분만 인용해 보전함.

### B-신규-f 누락분 — 원본 §2-8 콜아웃 전문 (`_backup\Fanatastic.md.bak` 476~498행)

````markdown
> [!tip] `decrypt.py` 재구성 — 포맷만 알면 20줄이다 [가정]
> 아래는 위 출력과 동일한 결과를 내도록 **포맷 정의로부터 재구성한 참고 구현**이다(원본 스크립트 전문이 노트에 남아 있지 않아 재작성했다). 시험장에서 같은 상황을 만나면 이 골격을 기억하면 된다.
> ```python
> import sys, base64, hashlib
> from Crypto.Cipher import AES          # pip install pycryptodome
>
> secret_key = sys.argv[1].encode()
> blob = base64.b64decode(sys.argv[2])
>
> salt, iv, ct = blob[:8], blob[8:24], blob[24:]
> key = hashlib.pbkdf2_hmac('sha256', secret_key, salt, 10000, 32)
> pt = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128).decrypt(ct)
>
> print('salt=', salt)
> print('iv  =', iv.hex())
> print('PLAINTEXT:', pt)
> ```
> **`segment_size=128`이 함정이다.** pycryptodome의 CFB 기본 세그먼트는 8비트(CFB8)인데 Go의 `cipher.NewCFBDecrypter`는 전체 블록(128비트) CFB다. 이걸 빼면 첫 바이트만 맞고 나머지가 쓰레기로 나온다 — "키가 틀렸나" 하고 엉뚱한 곳을 뒤지게 되는 전형적인 함정이다.
>
> 검증법: 평문이 출력 가능한 ASCII로 끝까지 나오면 성공. 앞 한두 글자만 말이 되면 **모드 파라미터를 의심**하라.
````

---

## 정정하지 않고 남긴 것 (근거부족 · 총괄 판단용)

- **인증 필요 API 401 목록** — 원본은 `/api/datasources` 만 상태코드를 실측했고 나머지(`/api/org`·`/api/user`·`/api/search`·`/api/admin/settings`)는 산문 주장. 개작본은 원본에 있던 `/api/frontend/settings` 를 빼고 `/api/datasources` 를 넣음. 저장 산출물 없음 = `근거부족`. 서술이 무해하고 원본 계승분이라 손대지 않음
- **`/dev/sda1` 시행착오** — 원본 §6-③ 은 「다른 writeup 을 베끼면 실패」를 일반론으로 적었을 뿐, 이 박스에서 실제로 `sda1` 을 쳐본 로그는 없음. `_PLAYBOOK` A-신규-3 도 같은 성격
- **`disk` 그룹 권한상승 태그 부재** — taxonomy 에 `tech/lin/*` 중 대응 항목 없음(`suid`·`sudo-abuse`·`capabilities`·`cron`·`path-hijack`·`wildcard`·`kernel-exploit`·`passwd-write` 뿐). 신설은 **공유 인프라**라 총괄 판단
- **Kali 스크린샷 2장 미이관** — `pg_grafana_api_health.png`·`pg_prometheus_buildinfo.png` 가 볼트 `파일보관\` 에 없음. 본문은 경로만 인용 중. 이관하면 노트가 자기완결됨
- **색인 갱신 필요** — frontmatter `tags`·`tech_count`·`manual_cves` 변경됨. `refresh.ps1` 은 총괄 몫(§5)
