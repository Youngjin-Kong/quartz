# Graph — 적대적 검증 + 정정 (writeup-auditor)

대상: `03. PG\Graph.md` (423행 → 466행)
증거원: Kali `~/PG/Graph/` 전량 · 볼트 `파일보관\PG-Graph-*.png` 2장(직접 열람) · tmux `graph-josh`/`graphjosh` capture-pane · `~/.zsh_history`(grep — Graph 관련 0건, 비대화형 실행이라 정상)
박스 정지 상태. 재접속 없음. `find /`·홈 전수 스캔 없음.

## 결론 한 줄

**작성자가 「관측 없음」으로 강등해 놓은 4장의 핵심 구간이, 실제로는 `harvest_root.txt`(47KB) 안에 전부 들어 있었다.** 강등이 과했고, 동시에 **강등되지 않은 채 남아 있던 root 로그인 서술은 날조에 가까웠다.**

---

## 1. 고친 것 — 실측으로 반증돼 정정

| 위치 | 무엇이 틀렸나 | 어떻게 고쳤나 |
|---|---|---|
| §4 root 획득 · §5 · §8 | **`ssh -tt root@192.168.248.201  # 비밀번호: espartaco`** 로 root 를 직접 SSH 로그인한 것처럼 서술. `PermitRootLogin yes` 를 "그래서 바로 직접 로그인이 가능했던 이유" 로 인과 연결 | `harvest_root.txt` 「PROCS」의 `ps auxf` 가 **`sshd: josh` → `-bash`(pts/1) → `su - root` → `-su` → `sh /tmp/.h.sh`** 트리를 보여준다. `sshd: root` 세션은 **없다.** root 는 josh 세션의 `su - root` 로 잡혔다. 명령 블록을 프로세스 트리 인용으로 교체하고, `PermitRootLogin yes` 는 「관측은 사실이나 실제로 쓰이지 않은 우회로」로 분리 |
| §4 「[가정] pass-gen 을 이용한 shadow 조작」 전체 | 「pass-gen 이 정확히 무엇을 했는지 관측 없음」·「실제로 josh 로 로그인했는지 산출물에 없다」·「josh 행 셋의 정체는 확정 불가(두 갈래 [가정])」 | **전부 반증됨.** `harvest_root.txt` 「USERS」절이 복원 «전» shadow 전문을 담고 있다 → ①jane 행 `max` 1337→99999 + 해시 재생성(pass-gen 이 인자를 필드에 꽂는다는 실측) ②그 다음 줄에 `josh:$6$Gr4phSlt$…`(**주입 성공**, 원본 josh 3행보다 앞) ③`bogus:!:0:0:99999:7:::njosh:…$:…`(개행이 안 먹은 **실패 잔재**). 절 제목을 「실행 결과 — 타겟 shadow 에 그대로 남았다」로 바꾸고 확정 서술로 승격 |
| §4 cleanup 인용 | 복원 후 josh 3행의 정체를 「①원본 vs ②시도 잔재」 두 갈래로 열어 둠 | 백업 `/tmp/s.restore` 에 `Gr4phSlt`·`bogus` 가 **둘 다 없으므로 조작 이전 상태** → 거기 있는 josh 3행은 **박스 원본**. ② 폐기. 인용에서 빠져 있던 **복원 전 1688바이트/md5 `c0ba3f99…`** 를 되살려 255바이트 증가를 근거로 제시 |
| §4 `sudo -l` | 「pass-gen 을 sudo 로 실행할 수 있다는 것을 보여주는 원문이 관측 없음」에서 멈춤 | 원문 부재는 사실(`harvest_jane_full.txt`·`harvest_root.txt` 어디에도 `pass-gen` 문자열 없음 — grep 확인). 다만 **호출 결과가 shadow 에 남았으므로 「실행할 수 있었다」 자체는 확정**. 못 남긴 것은 허용 «조건»(NOPASSWD·인자 제한)이라고 범위를 좁힘 |
| §4 exploit_passgen.sh | 「이스케이프가 깨진 «것처럼 보이는» 줄」로만 언급 — 독자가 그대로 따라 치면 동작하지 않는다는 경고 없음 | 코드펜스는 **한 바이트도 안 건드림**(`cat -A` 로 바이트 대조 완료). 펜스 «밖»에 손상 목록 추가: `\n`→리터럴 `n`, `H=` 에서 `$6$Gr4phSlt$PGF3` 접두 소실, `printf %sn`. 원본이 ANSI-C 인용(`$'…\n…'`)이었을 것이라는 [가정] 추가. **손상이 추정이 아님을 `bogus` 행으로 입증** |
| §1 SNMP | 「UDP top-100 에도 161 이 열려 있다는 표시가 없다」 | 161 은 `closed` 10개 목록에 **없고** `Not shown: 90 open|filtered udp ports (no-response)` 쪽이다. 「닫힘 확인」이 아니라 「열림 근거 없음」으로 정정 |
| §1 404 설명 | 「**Express 의 기본** `{"message":"404 page not found"}` JSON」 | Express/finalhandler 의 기본 404 는 `Cannot GET /경로` HTML 이고 이 JSON 은 앱이 정의한 것. Kali 에 express 가 없어 실행 검증 불가 → **다른 단정으로 바꾸지 않고 「앱이 미매칭 경로에 돌려주는 32바이트 JSON」으로 서술만 남김** |
| §1 gobuster 명령 블록 | 인용문이 `.bg-gobuster.sh` 원문과 다름(`:80` 누락, 따옴표·절대경로 제거) | 원문 그대로 교체 |
| §1 probe-index 블록 | 26줄 중 4줄을 **골라서 순서를 바꿔** 인용(정렬·간격도 다름) | 실제 파일 앞 5줄 그대로 교체 + 「앞 5줄」 캡션 |
| §2 엔드포인트 | 「응답한 넷 중 어느 것을 썼는지 확정 불가」, `get_bare.txt` 옆에 근거 없는 `(/query?)` 라벨을 **코드펜스 안에** 기입 | 라벨 제거. `${p//\//_}` 파일명 규칙상 `GET_graphql_v1`/`GET_graphql_console` 은 `/graphql/v1`·`/graphql/console` 에서 왔을 수 있고, `v1/graphql`·`api/graphql` 은 404 인데 이 둘만 응답한 것은 `app.use('/graphql')` 프리픽스 마운트로 설명된다 → **[가정] 단일 엔드포인트 `/graphql`** 로 좁힘 |
| §2·§3 명령 블록 | 산출물에 없는 `curl`·`john`·`ssh -tt jane@…` 호출을 실측처럼 제시 | 전부 「응답에서 역산한 재구성」·「호출 형태는 기록 없음」 캡션을 붙이거나 서술로 강등. `ssh -tt jane@…`·`ssh kali "john …"` 블록은 삭제(원문은 아래 3절) |
| §3 john.out | 「admin·josh 는 크랙되지 않았다」 | 출력에 `Session completed` 가 없다 → 완주인지 중단인지 구분 불가. 「이 실행에서는 안 나왔다」로 정정 |
| §0 | 「jane·root **둘 다 36초 내**」 | 36초는 root 만의 기록(`graphroot.log`). jane 은 실행 시간 미기록 → mtime 근거(14:53:20→14:53:30)로 대체 |
| §6-3 | 「이 **5초짜리** 실패」 | 5초의 근거 없음. mtime 15:05:47→15:06:02→15:07:33 → 「1분 30초 안에 회복」으로 교체 |
| §6-4 | 「이 노트에서 가장 근거가 얇은 구간」 | 대부분 복원됐으므로 제목·내용을 「실행 로그 없이 돌렸는데 타겟 스냅샷이 대신 기록해 줬다」로 재구성. 남은 공백(심은 해시의 평문, root 해시를 읽은 명령)만 명시 |
| §6-5 | 「위 **5-1** 의 5분 공백」 | 존재하지 않는 절 번호 → 6-4 |
| 「남긴 흔적」 | 「공격자가 남긴 것으로 특정할 파일은 보이지 않는다」 | cleanup 의 `/tmp` 목록에 **`cleanup_evidence.txt`(926바이트, root 소유)** 가 그대로 찍혀 있다. 심은 것 3종(Gr4phSlt 행·bogus 행·jane 행 변조)과 함께 명시 |
| 요약 콜아웃·§0·§5·§7·§8 | 위 정정의 파급 | 체인을 「pass-gen 개행 주입 → josh 선주입 → josh 로그인 → root 해시 → `su - root`」로 갱신. §0 에 `getspnam` 첫 일치 항목 추가. §7 에 「익스플로잇 직후 스냅샷」 항목 추가(번호 재정렬 6→7, 7→8) |

## 2. 삭제한 것 — 원문 보존

되살릴 수 있도록 삭제 원문을 그대로 인용한다.

1. `ssh -tt root@192.168.248.201   # 비밀번호: espartaco` — **반증됨**(ps 트리에 root sshd 세션 없음, `su - root` 가 실측)
2. `ssh -tt jane@192.168.248.201   # 비밀번호: oakland` — 호출 형태 미기록. 서술로 강등(로그인 사실 자체는 `proof_user.txt` 로 확정)
3. `ssh kali@10.44.44.128 "john --format=sha512crypt hashes.txt"` / `ssh kali@10.44.44.128 "john --format=sha512crypt root_hash.txt"` / `ssh kali@10.44.44.128 "john --session=graphroot …"` — 앞 둘은 명령행 미기록이라 삭제, 셋째는 `graphroot.log` 의 `Command line:` 원문 인용으로 교체
4. `gql/get_bare.txt (/query?)` 의 `(/query?)` — 근거 없는 경로 추정(같은 이름의 `GET_query.txt` 는 32바이트 404)
5. 「복원 후 상태에 josh 행이 셋이지만 … ② 세 번의 서로 다른 시도가 남긴 잔재다. 어느 쪽인지 이 산출물만으로는 확정할 수 없다.」 — ②가 반증됨

## 3. 반증한 것 — 지적으로 올랐다가 노트가 옳았던 것

총괄 프롬프트가 지목한 의심 중 **확인해보니 노트가 이미 맞았던 것들**:

- **「§4 의 `[가정]` 강등이 과한가」 → 절반만 맞다.** `sudo -l` 에 `/usr/local/bin/pass-gen` 이 있는지 확인하라는 지시에 대해: **없다.** `harvest_jane_full.txt`·`harvest_root.txt` 어디에도 `pass-gen` 문자열이 없다(grep). 노트의 「`sudo -l` 원문 관측 없음」은 **정확했다.** 과했던 것은 그 옆의 「pass-gen 이 무엇을 했는지 관측 없음」쪽이다.
- **「`josh_hash.txt` 가 덤프의 josh 해시와 다르다 — 이 사실이 노트에 반영돼 있는가」 → 반영돼 있었다.** 노트는 이미 `Gr4phSlt` 가 사람이 고른 salt 임을 근거로 「원격에서 새어 나온 해시가 아니라 직접 만든 해시」라고 적었다. 감사에서는 덤프 해시(`$6$g744Ii0AvY$`)를 명시적으로 병기해 근거를 한 단계 더 굳혔을 뿐이다.
- **「exploit_passgen.sh 인용의 무결성」 → 코드펜스는 이미 바이트 정확했다.** `cat -A` 대조 결과 개행 위치까지 일치. 노트는 손상 사실도 코드펜스 «밖»에 이미 적어 두었다(다만 「깨진 것처럼 보인다」로 약했고, 따라 쳐도 안 된다는 경고가 없어 그 부분만 보강).
- **「`root_hash.txt` 를 읽었다면 이미 root 상당 권한 — 인과가 바뀐다」 → 바뀌지 않는다.** root_hash.txt 는 Kali 15:05:47(타겟 02:05:44) 생성으로 ps 에 보이는 josh SSH 세션(02:07)보다 **앞선다.** 즉 「이미 root 였다」가 아니라 「ps 에 안 남은 더 이른 josh 세션이 있었다」로 읽는 편이 자연스럽고, 어느 쪽도 확정 근거가 없어 **[가정] 유지가 정답**이다.
- **「§6-1 gobuster 2회」 → 노트가 맞다.** `gobuster-raft.txt` 에 ANSI 컬러 + `DONE` 이 살아 있고 `.bg-gobuster.sh` 는 `--no-color` → 별도 수동 실행이 맞다. 결과도 `/static`·`/Static`·`/STATIC` 로 `gobuster-80.txt` 와 동일.
- **「§6-3 john 세션 충돌」 → 노트가 맞다.** `john_root.out` 에 `Crash recovery file is locked: /home/kali/.john/john.rec` 가 실제로 있고, `graphroot.log` 의 `Command line:` 에 `--session=graphroot` 가 있다. 다만 「다른 «박스»의 실행과 충돌」은 미확인이라 [가정] 표시를 붙였다.
- **타겟 pty 프롬프트 5개(`jane@graph:~$`·`root@graph:~#`)** — 전부 실측. **하나도 건드리지 않았다.** Kali 프롬프트 창작은 0건(재확인).
- **스크린샷 2장** — 직접 열어 본문과 대조. `PG-Graph-web80-landing.png` 는 「Welcome to Graph」+「Coming soon」, `PG-Graph-graphql-sqli-hashdump.png` 는 Pretty-print 체크 해제 상태의 동일 JSON. **노트 서술과 일치**(반박 없음). 다만 헤드리스 캡처라 URL 바가 없어 주입 payload 는 여기서도 복원되지 않는다.
- **tmux `graph-josh`(16:04 생성)·`graphjosh`(16:05)** — capture-pane 결과 둘 다 내용 없음(빈 kali 프롬프트 1줄). 박스 정지 이후 생성이라 4장 공백의 증거가 아니다. **종료하지 않았다.**

## 4. 여전히 「관측 없음」으로 남는 것

- GraphQL 주입 payload 문자열(요청 본문). 헤드리스 캡처에도 없음
- 심어 놓은 josh 해시의 **평문**, 그 해시를 생성한 명령
- `root_hash.txt` 를 **읽어낸 명령·세션**
- josh 가 shadow 를 읽을 수 있었던 근거 — harvest 가 `/etc/group` 을 뜨지 않음
- 1차 john 의 워드리스트(`graphroot.log` 로부터 rockyou 였을 [가정])
- `pass-gen` 바이너리 자체(`ls -la`·`file`·`strings` 없음), `bogus` 계정이 어떻게 생겼는지

## 5. 근거 출처

- `~/PG/Graph/harvest_root.txt` — 「USERS」(shadow 전문, 복원 전) · 「PROCS」(`ps auxf`) · 「SUDO」 · 「SSH」 · 「FLAGS」. **이번 감사의 결정적 증거 전부가 이 파일에 있다**
- `~/PG/Graph/cleanup_evidence_box.txt` — 복원 전후 md5/크기, `/tmp` 목록
- `~/PG/Graph/exploit_passgen.sh` — `cat -A` 바이트 대조
- `~/PG/Graph/{josh_hash.txt,root_hash.txt,root.pot,graphroot.log,john*.out,hashes.txt,proof_*.txt}`
- `~/PG/Graph/{nmap-*.txt,gobuster-*.txt,.bg-gobuster.sh,web-80/*,gql/*}`
- 볼트 `파일보관\PG-Graph-web80-landing.png`·`PG-Graph-graphql-sqli-hashdump.png` (Read 로 직접 열람)
- 타임존 환산: `proof_user.txt` 본문 01:54:07 EDT ↔ mtime 14:54:10 KST → **KST = EDT + 13h**. 이 환산으로 「root_hash 가 josh 세션보다 앞선다」를 판정
- 직접 실행: `node -e "require('express')"` → **express 미설치**로 Express 기본 404 검증 실패 → 해당 단정을 노트에서 제거(다른 단정으로 대체하지 않음)

## 6. 관리자에게 넘기는 판정

- **완료 2/2** — user `754551935abdc3b2bdde424a9b5ccb66`(jane pty), root `3e823452d93d1c9c8ef9bcf9d34612eb`(josh→`su - root` pty). **둘 다 대화형 셸 원위치 `cat`, 웹셸 아님** — `proof_user.txt`/`proof_root.txt` 의 타겟 프롬프트가 근거
- **색인 갱신 필요**(본문 대폭 수정). `refresh.ps1` 은 돌리지 않았다 — 공유 인프라
- 프론트매터 무변경. `manual_tags: true` 의 `tech/*` 5종은 전부 실제 사용 기법으로 확인(dirbust·graphql·sqli·cred-crack·sudo-abuse). CVE 없음
- 문체 이관 0건 — 개조식 미적용 산문이 남아 있으나 이 노트는 본문 대부분이 서술형으로 통일돼 있어 부분 개작이 오히려 혼재를 만든다. 필요하면 `pg-doc-reviewer` 로 통째로 넘길 것
- tmux `graph-josh`·`graphjosh` 정리 필요(둘 다 빈 세션). **세션 이름 지정으로만** 종료할 것
