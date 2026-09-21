---
type: audit
box: Sorcerer
manual_tags: true
manual_cves: true
---

# Sorcerer 적대적 감사 (writeup-auditor)

대상: `03. PG\Sorcerer.md` (개작본 372행 → 정정 후 414행)
대조: `03. PG\_backup\Sorcerer.md.bak`(1111행) · `~/PG/Sorcerer/` · `~/.zsh_history` · `파일보관\` 스크린샷 13장 · exploit.c 원문 · GTFOBins 캡처

---

## 1. 고친 것

| 위치(문자열) | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `whatweb ... \| tee whatweb.log` | 실제 명령은 `> whatweb.log`(`~/.zsh_history` 1593·1595). `tee` 는 창작 | `>` 로 정정. 포트 80 결과가 같은 파일명에 덮어써진 사실 추가 |
| `wget ...{francis,miriam,max,sofia}.zip` · `for f in *.zip; do ... unzip` (Kali 프롬프트 포함) | **날조.** `~/.zsh_history` 에 wget·unzip 기록 없음. 스크린샷 `20260710132554.png` 는 **Windows 탐색기**의 `…\max\home\max\.ssh` 경로를 보여줌 — 내려받기·해제는 Windows 쪽 | 펜스 삭제, 산문으로 대체(원문은 아래 §2 에 인용) |
| `ls -la max/ max/.ssh/` 펜스 | 날짜 컬럼 삭제·`.`/`..` 삭제·`authorized_keys.bak` 누락. 게다가 Kali 의 `.ssh/` 는 손으로 만든 것(`mkdir .ssh; mv * ./.ssh`)이라 "zip 풀면 이렇게 나온다"가 **틀린 인과** | 실제 `ls -la` 원문으로 교체(`.bak` 836B = 원본, 738B = 덮어쓰기용, 차이 98B = 옵션 필드) + 인과 정정 |
| `— 출처: .../authorized_keys` (옵션 필드 있는 cat 블록) | 현재 그 파일에는 옵션 필드가 **없다**(덮어쓰기용). 원본은 `authorized_keys.bak` | 출처를 `authorized_keys.bak` 로 정정 |
| `ssh-rsa AAAA... max@sorcerer` | 생략 표기가 모호 | `AAAAB3NzaC1yc2EAAAADAQAB…(생략)…` 로 생략 범위 명시 |
| feroxbuster 펜스 | 스크린샷의 404 auto-filter 줄·`/index.html`·`/default/index.html`·진행 3줄(`19m`)을 **삭제**한 압축본 | 스크린샷 원문 그대로 복원(배너·설정표만 생략 명시) |
| `![[Pasted image 20260710151033.png]]` 가 "디렉터리 리스팅 직접 확인" 자리에 | **151033 은 GTFOBins 페이지다.** 리스팅 화면은 `20260710132345.png` | 이미지 교체 |
| `max.zip만 13,898바이트, 나머지 셋은 4.7KB대` | 그 숫자는 feroxbuster 의 `c` 값. 인용한 리스팅 스크린샷에는 **8,274 / 2,834 / 2,826 / 2,818** 로 찍혀 있음 — 자기 증거와 모순 | 리스팅 실측치로 교체. feroxbuster 값이 약 1.68배 부푼 사실을 `[가정]` 으로 병기 |
| `showmount -e 실행 기록이 산출물에 없다 — 관측 없음` | **반증됨.** `~/.zsh_history` 1597 에 `showmount -e 192.168.120.100` 이 있음 | "실행했으나 출력 미보존 → 결과 관측 없음" 으로 정정 |
| `CVE-2017-12617 ... 후보로 확인했으나` | **반증됨.** PoC 두 종을 클론해 6회 이상 실행(history 1673~1683) | "실제로 돌렸으나 출력 미보존" 으로 정정. `Post-Exploitation` 에 「버린 경로」 절 신설 |
| `⚠️ **정정**: 이전 기록은 …였으나` (Post-Exploitation) | 노트 본문의 **감사 이력**. `CLAUDE.md` §4 위반(공개 발행 대상) | 정정 서술 제거, 사실만 남김(`exploit`·`1.txt` 존재 + 업로드 명령 관측 없음 `[가정]`) |
| SUID 펜스 | 스크린샷에 있는 `gpasswd`·`chsh` 두 줄 누락, `passwd`/`mount` 화살표 문자열을 `...` 로 절단 | 두 줄 복원, 화살표 전문 복원, `strings/strace Not Found` 복원. 산문의 정상 SUID 목록에도 두 개 추가 |
| linpeas 펜스 | 스크린샷의 `ls` + 결과 한 쌍 누락 | 복원 |
| `# cd ../dennis` | 실제로는 `# tree`(→ `tree: not found`) · `# cd ..` · `# cd dennis` | 스크린샷 원문대로 복원 |
| `ssh tomcat@` · `scp -O` 펜스 | 명령은 history 로 확인되나 **출력 원문 미보존** — 근거 표시가 없었음 | 출처 캡션 + `[가정]` 부착(삭제 아님) |
| `— 출처: ~/PG/.../authorized_keys(덮어쓴 버전)…` (max 셸 획득 블록) | 그 블록의 실제 출처는 스크린샷 `20260710140254.png` | 출처 교체 |
| nmap 펜스 | `Not shown: 65525 closed tcp ports (reset)` · `Network Distance` · `Service Info` 누락 | 복원 + 생략 범위 캡션 명시 |
| `아래 Post-Exploitation` · `위 root 셸` · `위 authorized_keys` | 상대 참조 | 절 이름 지정으로 교체 |
| `Steps to reproduce` 2·3 | 실제로는 `-x html,txt` 로 돌렸고 리스팅은 브라우저로 확인. zip 내부 경로도 `home/max/.ssh/` | 실제 절차대로 정정 |
| GTFOBins 문단 | Remarks 원문·`--` 구분자 설명 없음, Unprivileged 탭 캡처(`150903`) 미사용 | 원문 인용 + 캡처 추가 |
| `man scp -O` 캡처(`20260710135852.png`) | **미사용.** `-O` 를 알아낸 실제 근거인데 노트에 없었음 | `-O` 설명 옆에 추가 |
| 7742 앱 화면(`131947`) · 로그인 실패(`132020`) | 미사용 | `Service Enumeration` 에 추가(실패 경로) |

## 2. 삭제한 것 — 원문 인용

```bash
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ wget http://192.168.120.100:7742/zipfiles/{francis,miriam,max,sofia}.zip
┌──(kali㉿kali)-[~/PG/Sorcerer]
└─$ for f in *.zip; do echo "== $f"; unzip -o -q "$f"; done
```

근거: ①`~/.zsh_history` 에 Sorcerer 구간 wget/unzip 0건(`zipfiles`·`max.zip`·`unzip` 전수 grep) ②`Pasted image 20260710132554.png` 가 Windows 탐색기 `다운로드 > 새 폴더 (2) > max > home > max > .ssh` 를 보여줌 ③Kali `~/PG/Sorcerer/max/` 는 13:44:58 에 통째로 생성됐고 `.ssh` 는 14:01 — history 의 `mkdir .ssh; mv * ./.ssh` 와 일치. **이 펜스는 `.bak`(1111행판)에서 이미 존재하던 것으로, 개작자가 만든 것이 아니라 상속한 것이다.**

```text
max/.ssh/:
-rw------- 1 kali kali  738 authorized_keys
-rw------- 1 kali kali 3381 id_rsa
-rw------- 1 kali kali  738 id_rsa.pub
```
근거: 날짜 컬럼이 `ls -la` 출력에 없을 수 없음 + `authorized_keys.bak` 누락. 실제 원문으로 교체함.

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

- **두 `Initial Access` 제목이 다르다**(지목 ⓘ) → **지적 철회.** 기준 골격인 `Robust.md` 도 32행(긴 제목)/85행(축약)으로 **같은 패턴**이다. 하우스 관례이지 결손이 아니다.
- **`┌──(kali㉿kali)` 프롬프트**(지목 ⓕ) → **작성자 주장이 옳다.** `Pasted image 20260710133159.png` 에 `┌──(kali㉿kali)-[~/PG/Sorcerer]` 가 실제로 캡처돼 있고, `140254`·`143311` 도 같다. 이 노트는 사람이 대화형 터미널에서 푼 레거시다 — **지우지 않았다.**
- **타겟 pty 프롬프트**(`max@sorcerer:~$`·`max@sorcerer:/run/systemd$`·root `#`) → 전부 `140254`·`143311`·`151116`·`151215` 로 실측 확인. 그대로 보존.
- **`local.txt` = `c91395bd06b23a3455e9a6bf711184f3`, 위치 `/home/dennis/`**(지목 ⓓ-1) → **작성자 주장이 옳다.** `151215.png` 한 글자씩 대조: `c9-1-3-9-5-b-d-0-6-b-2-3-a-3-4-5-5-e-9-a-6-b-f-7-1-1-1-8-4-f-3` = 32자 일치. 화면에도 `# cd dennis` → `local.txt` → `cat` 순서가 그대로 있다.
- **`/home/max/` 에 `exploit`·`1.txt` 실존**(ⓓ-2) → **옳다.** 같은 캡처에 있고, 14:33 캡처(`143311`)에는 없으므로 14:56 컴파일 이후 업로드된 것과 정합. 다만 업로드 명령 자체는 관측 없음 → `[가정]` 유지.
- **`proof.txt` = `621b7558ae3578abef3e8f4c73485357`**(ⓓ-3) → `151116.png` 한 글자씩 대조 일치(32자).
- **07-08 33장 · 07-10 15:12 이후 6장이 Sorcerer 무관**(ⓔ) → **작성자 판정이 옳다.** ①07-08 스크린샷은 전부 ≤15:51 인데 Sorcerer nmap 은 17:43 시작 ②표본 `20260708155147.png` = `svc_apache$` Evil-WinRM(Windows) ③표본 `20260710161043.png` = `~/PG/Jacko` HTTP 서버.
- **exploit.c 커널 한정 주장** → 원문 확인. 55행 `Exploit tested on Ubuntu 5.8.0-48-generic and COS 5.4.89+.`, 96행 `#define KERNEL_UBUNTU_5_8_0_48 1`. 옳다.
- **Tomcat 자격증명 `tomcat`/`VTUD2XxJjf5LPmu6` · 롤 `manager-gui` 단독** → `~/PG/Sorcerer/max/tomcat-users.xml.bak` 38~39행 확인. 옳다.
- **`ports` 프론트매터 10개** → nmap.log 와 완전 일치.

## 4. 이관 손실 — `.bak` 에서 사라졌는데 `Sorcerer-playbook.md` 제안 7건에도 없는 것

관리자 반영 대상. **노트에 되돌릴 것이 아니라 `_PLAYBOOK` 에 가야 하는 재료다.**

1. **`find -perm -4000` 의 선행 `-` 의미** — "정확히 4000"이 아니라 "4000 비트 포함". 빼면 거의 아무것도 안 나옴 (`.bak` 4-2)
2. **`start-stop-daemon -S` 는 같은 `-x` 인스턴스가 이미 떠 있으면 조용히 exit 1** — 셸이 안 뜨는데 에러도 없을 때의 진단. 회피: `cp /bin/sh /tmp/x && start-stop-daemon -S -x /tmp/x -- -p`. `-x` 는 절대경로 필수 (`.bak` 4-4)
3. **`Permission denied (publickey)` vs `(publickey,password)`** — 괄호 안은 서버가 허용하는 인증 방식 목록. 전자면 패스워드 공략은 무의미 (`.bak` 3-1) ※노트에 한 줄 요약만 남김
4. **scp 전송 후 되읽어 `diff` 로 확인하는 관례** (`.bak` 3-3)
5. **파일 전송 3종 폴백** — `wget` → `curl` → bash 내장 `/dev/tcp`, 그리고 SSH 가 있으면 `scp` 가 최선, 디스크에 안 남기려면 `curl … | sh` (`.bak` 4-2)
6. **SSH 로 잡은 셸은 이미 완전한 TTY** — pty spawn·`stty raw -echo` 단계를 건너뜀 (`.bak` 3-4)
7. **feroxbuster 수동 대안 curl 루프**(시험 대비) (`.bak` 3-4)
8. **권한상승 후보 경로 비교표** — SUID / NFS `no_root_squash` / 커널 / Tomcat manager 의 우열과 판정 (`.bak` 4-4)
9. **`~/.zsh_history` 에만 있는 시행착오 전량**(제안서 어디에도 없음):
   - `ssh -i ./id_rsa root@192.168.120.100` — root 로 먼저 시도
   - `rm authorized_keys; cat >> authorized_keys; cat id_rsa.pub >> authorized_keys` — 원본을 지우고 공개키만으로 재구성했다가 `cp authorized_keys.bak authorized_keys` 로 되돌림
   - **`ssh -O -i ./id_rsa authorized_keys max@… ` 3회** — `scp` 자리에 `ssh` 를 쓴 오용
   - `scp` 무플래그 실패 → `scp -h` · `scp -H` · `scp -help` · `man scp` → `-O` 발견 (`Pasted image 20260710135852.png` 가 그 화면)
   - `chmod 600 id_rsa / id_rsa.pub / authorized_keys`

## 5. 제안서(`Sorcerer-playbook.md`) 신규/병합 재판정

`_PLAYBOOK.md` 를 증상으로 검색한 결과.

| 제안 | 작성자 신고 | 감사 판정 | 근거 |
|---|---|---|---|
| 1 `command=` 자기파괴 | 신규 | **신규 유지** | `forced`·`command=` 강제명령 항목 0건 |
| 2 A-37 병합 (`scp -O`) | 병합 | **병합 유지** | — |
| 3 커널 익스플로잇 소스 선독 | 신규 | **B-24 병합 권고** `[가정]` | B-24(3841행) 「커널 익스플로잇은 한 발」 + 4048행에 이미 「익스플로잇 헤더도 `Tested on: … H2 1.4.199`」 선례. 별 카드로 세울 만큼 떨어져 있지 않음 |
| 4 B-33 병합 (dash `-p`) | 병합 | **병합 유지.** GTFOBins Shell 탭에 `-p` 없음은 `Pasted image 20260710150903.png` 로 확인됨 | — |
| 5 백업 아카이브 확장자 | 신규 | **부분 기존 → 병합으로 낮출 것** | 682행에 이미 `-x php,txt,bak,old,zip 을 기본값으로 할 것`, 686행에 `…zip,rar,7z,log` 목록 존재. **진짜 신규는 `--scan-dir-listings` 요약줄 교훈 하나**(grep 0건) |
| 6 NFS `showmount` 미열거 | 신규 | **전제가 반증됨 — 철회 또는 F-5600 병합** | ①`showmount -e` 는 실제로 실행됐다(history 1597) → 「열거를 안 하고 넘어갔다」가 성립 안 함 ②F 절 5600행에 이미 `111 · 2049 → 익스포트 목록 → no_root_squash 확인` 이 있음 |
| 7 Tomcat CVE-2017-12617 | 신규 | **신규 유지.** 단 「실행 로그 없음」은 **반증됨** — PoC 두 종을 6회 이상 실행함(history 1673~1683). 본문의 그 문장을 「출력 미보존 → 결과 관측 없음」으로 고칠 것 | grep `12617`·`12615` 0건 |

## 6. 태그 확인 (총괄 판단 필요 — 감사자가 정하지 않음)

`tech/ssh/forced-command-bypass` 는 **볼트 전체에서 Sorcerer.md 한 곳에서만 쓰인다.** `tech/ssh/*` 네임스페이스 자체가 이 노트에서 처음 생겼다(`03. PG` 전 노트 grep). 인접 기존 태그: `tech/cred/ssh-key` · `tech/exec/ssh-key` · `tech/lin/rbash-escape`. taxonomy 는 공유 인프라이므로 유지/개명/폐기는 총괄 결정 사항.

나머지 4개(`tech/enum/dirbust`·`tech/exec/ssh-key`·`tech/enum/peas`·`tech/lin/suid`)는 전부 실사용 확인. `manual_cves: true` + `cves` 필드 없음 — CVE-2017-12617·CVE-2021-22555 둘 다 **악용되지 않았으므로** 올바르다.

**색인 갱신 필요**(`refresh.ps1` 은 감사자가 돌리지 않음).

## 7. 근거 출처

- Kali: `~/PG/Sorcerer/{nmap.log,whatweb.log,whatweb_8080.log,exploit.c,exploit,CVE-2017-12617/}` · `~/PG/Sorcerer/max/{scp_wrapper.sh,tomcat-users.xml.bak,.ssh/*}` · `ls -la --time-style=full-iso`
- `~/.zsh_history` 1592~1597 · 1669~1683 · 1739~1780
- 스크린샷 13장: `131947 132020 132345 132554 133159 135852 140254 143311 150807 150903 151033 151116 151215`(전부 07-10) + 표본 `20260708155147` · `20260710161043`
- git: `03. PG/Sorcerer.md` 는 `aba5a29` 이후 커밋 이력 없음 — 이번 개작은 아직 미커밋 상태이고 baseline 은 `_backup\Sorcerer.md.bak`
