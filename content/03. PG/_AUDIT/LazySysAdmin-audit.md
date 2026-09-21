---
type: audit
target: "[[LazySysAdmin]]"
date: 2026-08-26
role: writeup-auditor
---

# LazySysAdmin — 적대적 검증·정정 기록

대상: `03. PG\LazySysAdmin.md`(개작판 547행) · 대조 백업 `03. PG\_backup\LazySysAdmin.md.bak`(676행)
감사 직전 스냅샷: `03. PG\_backup\LazySysAdmin.md.preaudit.bak`
결과: **정정 19건 · 강등(`[가정]`·「보존 안 됨」 표기) 2건 · 삭제 1건 · 547 → 588행**

확인 출처(고정 목록 안): `~/PG/LazySysAdmin/`(33개 전량) · 볼트 `파일보관\` · `~/.zsh_history` · Kali 직접 실행.
`find /`·홈 전체 grep 미사용.

---

## 1. 지시받은 「반증」 두 건의 재검증

### ⓐ-1 「`grep -c` 행경계 탈락이 아니라 `grep -o` 컨텍스트 패턴이었다」 → **작성자가 옳음. 유지**

Kali 재실행(2026-08-26):

```
grep -c togie wp_home.html                        → 56
grep -o -E '.{60}togie.{60}' wp_home.html | wc -l → 0
grep -o togie wp_home.html | wc -l                → 56
grep -o -E '[^<>]*togie[^<>]*' | sort | uniq -c   → 56  My name is togie.
```

`grep -c` 는 정답을 냈고 0건을 낸 것은 앞뒤 `.{60}` 을 요구한 `grep -o` 패턴임. 총괄 프롬프트의 전제(「`grep -c` 행경계 탈락」)가 **틀렸고** 작성자의 반증이 맞음. `_AUDIT\LazySysAdmin-playbook.md` 제안 9 의 서술도 정확함.
부수 확인 — 노트의 「`My name is togie.` 를 56회 반복」은 문자열까지 정확(`grep -o 'My name is togie' → 56`).

### ⓐ-2 「Kali 프롬프트는 창작이었다 → 전량 제거」 → **작성자가 옳음. 되살리지 않음**

`~/.zsh_history`(3165행)를 여러 키로 직접 검색:

| 키 | 건수 |
|---|---|
| `192.168.248.36` | 0 |
| `togie`(대소문자 무시) | 0 |
| `lazy`(대소문자 무시) | 0 |
| `12345` | 0 |
| `lsa_` · `PG/Lazy` · `deets` · `Backnode` · `6667` | 0 |

같은 VPN 대역의 **다른** 박스(`192.168.248.215`·`.222`)는 히스토리에 남아 있음 — 즉 이 파일이 그 시기를 못 담은 것이 아니라 이 박스만 0건임. `writeup_notes.txt` 도 에이전트 워크플로(비대화형 `ssh`)를 기록. **대화형 Kali 세션은 없었고 백업의 `┌──(kali㉿kali)-[~/PG/LazySysAdmin]` 프롬프트 16개는 창작이 맞음.** 제거 유지.

---

## 2. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `## Post-Exploitation` | 다른 절이 전부 `###` 인데 혼자 `##` | `### Post-Exploitation` |
| nmap 블록 캡션 `— 출처: nmap.full.txt` | 블록 첫 줄이 `# Nmap 7.98 scan initiated ... -oN nmap.log` 로 **`nmap.log` 의 헤더**임. `nmap.full.txt` 는 `Starting Nmap 7.98 (...)` 로 시작 | 출처를 `nmap.log` 로 정정. 잘려 있던 `TRACEROUTE` 4행 + `OS and Service detection ...` + `# Nmap done at ...` 복원 |
| 「`/etc/os-release` 가 `14.04.5 LTS, Trusty Tahr` 로 세 번째 근거를 줌(권한상승 절 참고)」 | 개작에서 OS 블록이 통째로 빠져 **참조가 허공을 가리킴** | `harvest_root.txt` `===== OS =====` 블록 복원(출처 캡션 포함) |
| 버전 근거 문단 | 배너만 있고 설치 버전 대조 없음(CLAUDE.md §2 「둘 다 남겨라」 미충족) | `PKGS` 섹션 `dpkg -l` 3종 추가 — `openssh-server 1:6.6p1-2ubuntu2.8` · `apache2 2.4.7-1ubuntu4.17` · `samba 2:4.3.11+dfsg-0ubuntu0.14.04.10`. **셋 다 배너와 일치, 불일치 없음** |
| `  ...(css·js·이미지 다수, 생략 없이 원본은 smb_share_ls.txt 참조)` | **코드펜스 «안»의 한국어 주석** — 실측 블록 오염 | 펜스 밖 캡션으로 이동. 원본이 8192바이트에서 끊겨 마지막 행이 미완인 사실도 명기 |
| `ssh togie@192.168.248.36 'sh /tmp/.h.sh ...'` 외 3건 | 백업 원문은 `sshpass -p '12345' ssh -o StrictHostKeyChecking=no togie@...`. 개작이 `sshpass`·옵션을 **잘라내 재현 불가능한 명령**으로 만듦 | 백업(272·282·296·313행)대로 원문 복원 |
| `ssh togie@... "bash -c 'echo 12345 \| sudo -S -l'"` | 동일(백업 391행) | `sshpass ...` 복원 |
| `ssh -tt togie@... "bash -c 'echo 12345 \| sudo -S -i ...'"` | 동일(백업 416행). `-tt` 는 원문에 있었음 | `sshpass -p '12345' ssh -tt -o StrictHostKeyChecking=no ...` 복원 |
| `— 출처: harvest_root.txt`(SUDO 블록) | 그 블록은 **`harvest_togie.txt`** 것. `harvest_root.txt` 의 같은 섹션은 root 로 돌아 `Matching Defaults entries for root` / `User root may run ...` 로 찍힘 | 출처를 `harvest_togie.txt` 로 정정 + 두 회차 차이 명기 |
| proof_user / proof_root 블록 캡션 「전문. SSH 배너·경고를 포함해 자르지 않음」 | **거짓** — 두 블록 모두 post-quantum 경고 3행 + `Welcome to Web_TR1` 배너 5행 + 공백행이 잘려 있었음 | 두 파일 원문 전량 복원(base64 로 바이트 회수 후 CRLF→LF 만 정규화) |
| 「이 출력은 ... **비대화형** `ssh 대상 "명령"` 으로 실행됨」 | 타겟 세션에는 `-tt` 로 pty 가 붙었고 `wtmp` 에 `togie pts/0` 가 남음 — 같은 노트의 Post-Exploitation 절 「대화형 셸」 서술과 **자기모순** | Kali 쪽 프롬프트 부재 근거와 타겟 pty 사실을 분리 서술. `stdin: is not a tty` 가 pty 부재를 뜻하지 않는 이유도 명기 |
| 「두 플래그 모두 **SSH 대화형 셸에서** 원위치 `cat`」 | 판정 자체는 옳으나 근거가 없었고 「대화형」이 과장 | `ssh -tt` pty 세션으로 정정 + 근거 3종(`Connection to ... closed.` · `wtmp` pts/0 2건 · `auth.log` `TTY=pts/0`) 명시 |
| 「실제로 막히는 항목을 하나씩 확인:」 | `try8_rbash_limits.log` mtime 은 16:49:10 KST = root 획득(17:45:50 AEST) **이후**. 서사가 탈출 이전인 것처럼 읽힘 | 「산출물 mtime 기준 이 정리 자체는 root 획득 뒤인 16:49 KST 에 돌린 것」 괄호 추가 |
| `smb_conf_share.txt` 캡션 | 원본은 앞에 SSH 배너 + `[sudo] password for togie:` 가 붙어 있는데 노트는 깨끗한 `[share$]` 만 인용 | 발췌임을 캡션에 명시 |

## 3. 강등한 것(지우지 않음)

- **`rpcclient lookupsids` 블록** — 대응 산출물 파일이 없음. `writeup_notes.txt` 16:45 항목이 `S-1-22-1-1000 → togie` 와 `enum4linux -U` 빈 결과만 기록. 블록은 유지하고 「명령 출력 원문은 산출물로 보존되지 않음 `[가정]`」 캡션 부착. **부재를 근거로 날조 판정하지 않음**(CLAUDE.md §3).
- **local.txt 플래그 명령** — 개작이 `ssh togie@... "bash -c 'whoami; ...'"` 를 새로 써 넣었으나 백업에도 산출물에도 명령 원문이 없음. 게다가 출력 끝의 `Connection to ... closed.` 는 pty(=`-tt`)를 요구해 그 형태와 모순. root 플래그 명령과 같은 형태로 재구성하고 **`[가정]` 명시** — 페이로드는 출력이 직접 증명하고 `-tt` 는 `wtmp` 가 뒷받침한다는 근거를 함께 적음.

## 4. 삭제한 것 — 원문 인용

```markdown
```bash
ssh -tt togie@192.168.248.36 "bash -c 'echo 12345 | sudo -S -l'"
```
전체 출력은 Privilege Escalation 절 참고. 로컬 플래그 확인:
```

삭제 근거 둘.
1. **`-tt` 가 반증됨.** 타겟 `auth.log` 의 해당 행이 `Aug 20 17:45:40 ... togie : TTY=unknown ; ... COMMAND=list` — pty 가 없었음. 백업 391행의 원문도 `-tt` 없음(`sshpass -p '12345' ssh -o StrictHostKeyChecking=no ...`). 같은 명령이 Privilege Escalation 절에 **`-tt` 없이** 다시 나와 노트 안에서도 모순.
2. **시간 순서도 뒤집힘.** `proof_user.txt` 의 `date` 는 17:45:25, `sudo -n -l` 은 17:45:34, `sudo -S -l` 은 17:45:40 — 로컬 플래그가 먼저임. 티저가 그 반대로 배치돼 있었음.

동일 명령과 전체 출력이 Privilege Escalation 절에 그대로 남아 있어 정보 손실 없음. 대체 문장으로 시각(17:45:34~40)을 명기해 순서를 보존.

## 5. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

1. **총괄 전제 「`grep -c` 행경계 탈락」** — 틀림. 위 1절.
2. **「`## Post-Exploitation` 외에 구조 결손이 있을 것」** — 없었음. `Initial Access`·`Privilege Escalation` 각각에 4항목 전부 존재, `Port Scan Results` 표 존재, nmap raw `22/tcp   open  ssh ...` 라인 전량 보존(`extract.py` `PORT_RE` 정상 동작). 두 `Initial Access` 제목이 다른 것은 `_WRITEUP-STANDARD.md` 템플릿(첫째 긴 서술형, 둘째 짧은 제목)과 `Robust.md` 실물이 **똑같이** 하는 것으로 오류 아님. `## 관련` 이 `##` 인 것도 `Robust.md` 와 동일.
3. **「펜스에 언어 태그 누락이 있을 것」** — 없었음. 개작판 34개 개시 펜스 전부 `bash`/`text`/`ini` 태그 보유. 정정 후 34쌍 유지.
4. **「배너 버전과 설치 버전이 어긋날 것」(ⓕ 지목)** — 어긋나지 않음. `dpkg -l` 3종이 nmap 배너와 전부 일치. ClamAV 류 사례는 이 박스에 없음. (그래도 대조 결과 자체를 노트에 실었음 — 「확인했다」가 기록으로 남아야 하므로.)
5. **`sudo (ALL : ALL) ALL` 서술** — 정확함. `try_sudo_l.log`·`harvest_togie.txt`·`proof_root.txt`(`uid=0`) 3중 일치.
6. **rbash 제약 목록** — 정확함. bash 매뉴얼의 restricted shell 항목(`cd` / 명령 이름의 `/` / 리다이렉션 / `PATH`·`SHELL`·`ENV`·`BASH_ENV` 대입 / `hash -p` / `enable`·`command` / `set +r`)과 일치하고 `try8_rbash_limits.log` 3행이 실측으로 뒷받침.
7. **「6667 은 tcp 300위권」** — 정확함. Kali `/usr/share/nmap/nmap-services` 를 빈도 내림차순 정렬하면 6667/tcp 가 **314번째**(`0.000652`).
8. **「`old/`·`test/` 는 빈 디렉터리, `TR2/` 는 웹루트에 없음」** — 정확함. `smb_share_ls.txt` 63~74행에서 `\test`·`\old` 는 `.`·`..` 뿐, `TR2` 는 파일 전체에 0건.
9. **플래그 값** — `proof_user.txt`/`proof_root.txt` 원문과 **바이트 단위 일치**. `3170c6b1e7bac5a3dc430b899115d3b4` / `09675eaefc242e881bcf18f83c340e90`.

## 6. 이관 손실 점검(ⓒ)

`_AUDIT\LazySysAdmin-playbook.md`(177행, 제안 10건)에 백업 §0·§6·§7 의 시행착오가 **「지우기 전 원문」 인용과 함께** 전부 옮겨져 있음. 대조 결과:

| 산출물 | 시행착오 | 이관처 |
|---|---|---|
| `quick.log` | top-200 예열이 6667 누락 | 제안 1 |
| `smb_share_ls.txt` | 널 세션 공유 = 웹루트 판정법 | 제안 2 |
| `try4_enum4linux_users.log` | `enum4linux -U` 빈손 → `rpcclient` SID | 제안 3 |
| `try8_rbash_limits.log` | rbash 탈출 판정 기준 | 제안 4 |
| `try9_sftp_rbash.log` | `scp: Connection closed` = 로그인 셸 원인, `scp -O` 우회 | 제안 5 |
| `try3_mysql_remote.log` | MySQL 1130 vs 1045 구분 | 제안 6 |
| `try6/try7_wplogin_*.log` | WP 로그인 302/200 판정 | 제안 7 |
| `harvest_togie.txt` | `sudo -n` 이 「항목 없음」이 아님 | 제안 8 |
| `wp_home.html` | `grep -o` 컨텍스트 패턴 오판 | 제안 9 |
| `writeup_notes.txt` 17:22 | `harvest.sh` env leak | 제안 10 |

인과(「~여서 막혔다」)·소요 시각·`[가정]`·출처 경로 모두 살아 있음. **누락 0건.** `try2_smb_write.log`(SMB 쓰기 `NT_STATUS_ACCESS_DENIED`)만 playbook 이 아니라 노트 「남긴 흔적」에 남았는데, 흔적 판정에 쓰인 것이므로 자리로는 맞음.
⛔ `_PLAYBOOK.md` 는 읽지 않았고 쓰지도 않음.

## 7. 색인·상태 판정(총괄/라인 관리자 몫)

- **판정: 완료 2/2.** local `3170c6b1e7bac5a3dc430b899115d3b4`(`proof_user.txt`) · root `09675eaefc242e881bcf18f83c340e90`(`proof_root.txt`). 둘 다 `ssh -tt` pty 세션에서 타겟 파일시스템 원위치 `cat`. 웹셸 미사용 — 근거는 `wtmp` `togie pts/0` 2건, `auth.log` 17:45:50 `TTY=pts/0`, 출력 말미 `Connection to ... closed.`.
- **프론트매터 변경 없음.** `manual_tags: true` / `manual_cves: true` 유지. `tech/*` 4개는 전부 실사용 기법(smb 널세션·자격증명 재사용·rbash 탈출·sudo 남용)이라 그대로 둠. 본문에 CVE-2021-4034(PwnKit)가 「시도하지 않음」으로만 나오는데 `manual_cves: true` + `cves:` 필드 부재라 색인에 안 들어감 — 의도대로임. `Robust.md` 도 같은 형태.
- **색인 갱신 필요** — 본문 행수·블록이 바뀌었으므로 `refresh.ps1` 재실행이 필요함. 감사자는 돌리지 않았음(공유 인프라).
- **문체 이관 0건** — 서술형 종결·번역투 스캔 결과 `pg-doc-reviewer` 로 넘길 항목 없음. 개작판이 이미 명사 종결형 개조식임.
