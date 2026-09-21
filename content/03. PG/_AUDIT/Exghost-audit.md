---
tags:
  - type/audit
  - platform/pg
---
# Exghost 적대적 검증 — 2026-08-26

대상: `03. PG\Exghost.md`(개작 직후 276행) · 백업 `03. PG\_backup\Exghost.md.bak`(693행)
출처: `~/PG/Exghost/` 전량 · `~/.zsh_history` · 볼트 `파일보관\` · `03. PG\_AUDIT\portal-진행도-실측-20260820.md` · `pwnkit/.git`
결과: **276 → 355행**. 정정 9 · 강등 6 · 삭제 1(프론트매터 1필드) · 복원 7.

---

## 1. 최대 오류 — 작성자의 「반증 #3」이 반증처럼 보이는 새 창작이었다

작성자는 「PwnKit PoC 저장소는 `joeammond` 가 아니라 `berdav/CVE-2021-4034`」라고 보고하고 노트 3곳을 `berdav` 로 고쳤다. **거꾸로다.**

```
$ cat ~/PG/Exghost/pwnkit/.git/config
[remote "origin"]
	url = https://github.com/joeammond/CVE-2021-4034
$ git -C ~/PG/Exghost/pwnkit log --oneline -3
318add3 Merge pull request #1 from cclauss/patch-1
c017236 Fix typos
951329c Added links to the Qualys report
```

내부 정합성도 `joeammond` 쪽이다 — 노트가 「타겟에 컴파일러가 없어 C PoC 대신 **ELF 내장 파이썬 PoC**」라고 쓰는데, `berdav` 저장소가 C 구현이고 `joeammond` 가 파이썬 구현이다. `~/PG/Exghost/pwnkit/CVE-2021-4034.py`(3262B, 파이썬)가 실재하는 것도 같은 방향.

**원본 노트가 옳았고 개작이 오류를 넣었다.** 노트 3곳 + `_AUDIT\Exghost-playbook.md` 제안4 의 「정정 지시」까지 되돌렸다.

---

## 2. 작성자 반증 3건의 재판정

| 작성자 주장 | 감사 판정 | 근거 |
|---|---|---|
| ① Kali 프롬프트 14개는 창작 — `~/.zsh_history` 에 이 박스 명령 0건 | ✅ **옳다. 제거 유지** | `exghost`·`192.168.248.183`·`exiftest`·`djvu*`·`bzz`·`tshark`·`export-objects`·`myFile`·`HasselbladExif` 전수 grep 0건. 노트는 `git log --diff-filter=A` 기준 2026-08-20 **신규 생성**이고 박스는 2026-08-19 20:35~21:05 에 에이전트가 풀었다(`nmap.log` 가 절대경로 `-oN /home/kali/PG/Exghost/nmap.log`, root 소유 — `nnmap` 별칭이 아님). 레거시 사람 풀이가 아니다 |
| ② `~/.zsh_history:1208` 의 clone 은 Exghost 가 아니라 Levram 문맥 | ✅ **옳다 — 다만 근거가 더 세다** | 1209행이 `cd Levram`, 앞뒤가 pyLoad·pluxml·CVE-2021-3490. **결정적인 것은 저장소가 다르다는 점** — 1208행은 `berdav`, 로컬 클론은 `joeammond`. `pwnkit/` mtime 20:40:45 는 작업 구간 안이지만 그것만으로는 1208행과 이을 수 없다 |
| ③ 저장소는 `berdav` | ❌ **반증됨** | §1 |

**추가로 자기반증한 것**: `~/.zsh_history:2242` 에 `sudo apt-get install -y djvulibre-bin` 이 있어 한때 「Exghost 흔적 아니냐」를 검토했으나, 앞뒤 문맥이 전부 GitLab CVE-2021-22205 = **Breakout** 이고 Breakout 도 ExifTool DjVu 체인을 쓴다(`03. PG\Breakout.md:340-447`). Exghost 근거로 쓸 수 없다 — 작성자 주장 ① 유지.

---

## 3. 판정 근거 — 완료 2/2 는 «양성 증거»로 확인된다

`proof_user.txt`/`proof_root.txt` 부재를 근거로 삼지 않았다. 고정 출처 목록의 양성 증거를 먼저 봤다:

`03. PG\_AUDIT\portal-진행도-실측-20260820.md` §1 의 **`n == m` 22개 목록에 Exghost 가 포함**돼 있다(총괄이 포털 6페이지 전수 조회한 실측). 즉 **포털 기준 2/2 제출·인정**.

- **완료 2/2 판정 — 유지가 맞다.** 「미착수」·「부분」으로 볼 근거 없음
- **플래그 «값»** 은 여전히 `근거부족`(포털은 값을 보여주지 않음). 값 보존 처리는 그대로 유지 — 지우지도 지어내지도 않았다
- **웹셸 판정** — `판정 불가 · 근거부족`. 노트 원문의 타겟 pty 프롬프트(`www-data@exghost:/var/www/html$`)와 `pty.spawn` 기록이 대화형 셸을 가리키나 캡처 파일이 없다. 웹셸이었다는 반대 증거도 없다
- 볼트 `파일보관\` 에 이 박스 스크린샷 0장. 2026-08-19 자는 `Pasted image 20260819111158.png` 1장뿐이고 촬영 시각 11:11 이 작업 구간(20:35~21:05)과 어긋나 이 박스 것이 아니다

---

## 4. 이관 손실 — 백업 693행 대조

`_AUDIT\Exghost-playbook.md` 제안 8건은 §0·§6①~⑤·§2-2·2-3·2-4 를 덮는다. 그 밖에 **어느 쪽에도 안 간 손실 7건**을 복원했다.

| # | 잃은 것 | 백업 위치 | 조치 |
|---|---|---|---|
| 1 | `www-data@exghost:/tmp$ wget ... md5sum` 블록 + **md5 해시 `53f43d1a285c15491ad792a100b65bb5`** | §4-2 | 복원. **해시 유실은 「한 바이트도 잃지 마라」 위반** |
| 2 | `connect to [192.168.45.207] from (UNKNOWN) [192.168.248.183] 39420` | §3-1 | 복원 |
| 3 | `www-data@exghost:...$ python3 -c 'import pty;pty.spawn(...)'` — 산문으로 치환됨 | §3-1 | pty 프롬프트째 복원 |
| 4 | `ls -la /home/hassan/local.txt` + `-rw-r--r-- 1 hassan hassan 33` + `cat` — 산문으로 치환됨 | §5 | 복원. **웹셸 판정의 유일한 근거라 산문화는 실측 표식 파괴** |
| 5 | `# cat /root/proof.txt` + 값(root 프롬프트 안) | §4-3 | 복원 |
| 6 | `tmux new-session -d -s exg 'rlwrap nc -lvnp 9001'` 리스너 명령 | §3-1 | 복원(Kali 프롬프트는 붙이지 않음) |
| 7 | 「pcap에서 나오지 않은 것」 음성 결과 5항목 | §1 | 압축 복원. `근거부족` 명시 |

3·4·5 는 **문체 명목의 개조식화가 타겟 pty 프롬프트를 산문으로 바꿔버린 것**이다. Fikklish 사고와 같은 계열 — 날조 방향은 아니나 실측 표식을 지웠다.

추가로 백업에 있었으나 **복원하지 않은 것**(playbook 제안이 이미 덮음): §6⑥「다음 후보 경로 미리 세우기」·§6⑦「리버스셸 미접속 의심 순서」·§7 시험 관점·§8 방어 관점·명령 플래그 해설 표 4개. 원문은 `03. PG\_backup\Exghost.md.bak` 에 그대로 있다.

---

## 5. 코드펜스 대조 — 산출물 원문과 어긋난 곳

| 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| `exp.py` 블록 | 캡션이 「**원문 그대로**」인데 `print()` 5개·`os.makedirs`/`os.chdir`·결과 출력이 삭제되고 `configfile` 히어독의 `0xc51b => { ... }` 가 4행→1행으로 압축됨 | 1314B 원문 전량으로 복원 |
| `nmap_quick.txt` 블록 | `Not shown: 2 filtered` 행을 **PORT 표 아래로 옮김**(원문은 위). `Some closed ports may be reported as filtered due to --defeat-rst-ratelimit` 행 누락. 캡션의 「22·443 필터링 확정」은 `--open` 때문에 행이 안 찍힌 것을 필터링으로 단정한 것 | 원문 순서 복원 + 캡션을 「필터링으로 «보고»된 것」으로 정정 |
| `nmap.log` 블록 | `Aggressive OS guesses`·`No exact OS matches`·`Network Distance` 3행을 표시 없이 생략, `Not shown` 행 누락 | 복원(OS 후보 10개 중 3개만 옮겼음을 캡션에 명시) |
| `exiftest(1).php` 블록 | 실제 첫 행은 `File uploaded successfully :)<pre>ExifTool ...` 인데 `<pre>` 를 지우고 개행 삽입. 이후 15행을 표시 없이 절단 | `<pre>` 복원 + `...` 생략 표시 + 말미 `</pre>` 까지 |
| `%2f` 블록 | 원문 들여쓰기(form 4·input 8)를 4/4 로 재정렬, 주석 2행 제거 | 원문 그대로 복원 |
| 「빌드 산출물 확인」 `text` 펜스 | **`ls` 출력이 아니라 한국어 해설이 든 손수 만든 의사 리스팅** — 펜스=실측 표식 규율 위반. `payload` 내용도 `echo ...` 로 생략 | 펜스 밖 표로 변환 + `file` 판정 실측 추가 + `payload` 109B 전문을 별도 펜스로 |

펜스 언어 태그: 19개 전부 지정됨. 펜스 안 한국어 0건(최종 확인).

---

## 6. 그 밖의 정정·강등

| 위치 | 판정 | 조치 |
|---|---|---|
| `domain: exghost.local`(프론트매터) | 산출물 어디에도 없고, 백업 §1 에 `exghost`·`exghost.local`·`exghost.pg` **전부 기본 vhost 403** 이라고 적혀 있다 — 시도했다 실패한 추측이 색인 필드로 굳었다 | **필드 삭제.** 원문은 `domain: exghost.local`. 근거는 본문에 남김 |
| `shell_exec('/var/www/html/exiftool ' . $newFilepath . ' > ...')` PHP 소스 인용 | 산출물에 PHP 소스 없음. 「읽을 수 있었던 것은 정확히, 실행했어야 하는 것은 지어낸다」의 회색지대 | 소스 전문으로 복원하되 **`근거부족` 명시** + 간접 뒷받침(pcap 응답의 `Directory : /var/www/html/uploads`, `Content-Type: image/jpeg`)을 붙임 |
| ffuf 표 「`raft-medium-files.txt` 루트 파일 스캔 — 완주」 | `ffuf_files.txt` 에 진행률 행이 없다. **다만 `-s`(silent) 플래그 때문**이고 미완주 근거가 아니다(`ffuf -h`: `-s Do not print additional information`) | 「완주」를 `근거부족` 으로 강등. **미완주로 단정하지 않았다** |
| ffuf 표 「gobuster — 응답 자체를 못 받음」 | 0바이트는 「빈 결과의 기록」이지 원인 판정이 아니다 | 「원인 미기록 — `[가정]`」 으로 강등 |
| ffuf 디렉터리 결과 「`uploads`(301)·`server-status`(403)」 | 실제 `ffuf_dirs.json` 결과는 17건이고 그중 15건이 **워드리스트의 `#` 주석 줄이 그대로 요청된 403** | 17건 내역 명시 |
| feroxbuster 2회 실행 | `ferox.txt`·`ferox2.txt`·`ferox.stdout`·`ferox2.stdout` 4개가 실재하는데 **노트에 한 줄도 없었다** | 표에 행 추가(`/`·`/.php`·`/.html` 403 · `/uploads` 301 — ffuf 와 동일 결론) |
| `nmap_allports.txt` | 인용 없음 | 교차 확인 결과로 한 줄 추가 |
| 「20바이트 최소 JPEG면 충분」 | 요청·응답 로그 미보존. 남은 것은 pcap 에서 카빙한 `uploaded_testme.jpg`(14582B) 뿐 — 노트에 언급 자체가 없었다 | `근거부족` 강등 + 산출물 존재를 `[가정]` 해석과 함께 기재 |
| 「⚠️ 아래 재현도 위 증거 경고와 동일하게」 | 상대 참조(「아래」·「위」) | 자기완결 문장으로 교체 |

---

## 7. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

- **`ffuf_files` 미완주 의심** → `-s` 플래그가 진행률을 죽인 것. `ffuf -h` 로 직접 확인. 미완주로 단정하지 않고 `근거부족` 에서 멈췄다
- **`~/.zsh_history:2242 djvulibre-bin` = Exghost 흔적 의심** → 앞뒤가 전부 Breakout GitLab 작업이고 Breakout 도 ExifTool DjVu 를 쓴다. 기각
- **`pwnkit/` mtime 이 작업 구간 안이므로 1208행이 이 박스 clone** 의심 → 저장소 URL 이 달라 성립하지 않는다. mtime 만으로 히스토리 행을 묶을 수 없다
- **플래그 부재 = 미착수 의심** → 포털 실측이 2/2 인정. 부재 추론 자체가 불필요했다
- 220,560줄·85,645건 완주 주장 → `wc -l` 과 `Progress: [220560/220560]`·`[85645/85645]` 로 **정확 확인**. `grep -ic 'exiftest'` 0건도 재확인
- 구조(헤딩 레벨·두 `Initial Access` 제목 상이·4항목·`Port Scan Results`·nmap raw PORT 행) → `Robust.md` 골격과 일치. 지적 없음
- 타겟 IP `192.168.248.183` → 모든 산출물과 일치

---

## 8. 총괄에 올릴 것

- **색인 갱신 필요** — 프론트매터에서 `domain` 을 삭제했다. `refresh.ps1` 은 돌리지 않았다(공유 인프라)
- **`_STATUS.md` 미수정** — 판정은 **완료 2/2**(포털 실측 근거). 라인 관리자가 기록
- **문체 이관 3건** — ① 요약·관련 절의 `03. PG\_AUDIT\Exghost-playbook.md` 내부 경로 노출(공개 발행 적합성) ② 증거 캐비어트 콜아웃의 서술형 종결 잔존 ③ `Vulnerability Explanation` 불릿의 서술형. 전부 `pg-doc-reviewer` 관할이라 손대지 않았다
