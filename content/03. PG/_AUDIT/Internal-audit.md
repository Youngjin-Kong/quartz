# Internal.md — 적대적 검증/정정 감사 (2026-08-21)

감사자: writeup-auditor. 소요 ~35분. 백업: `03. PG\_backup\Internal.md.pre-audit-20260821`.
출처: `~/PG/Internal/`(Kali) · `try2.pcap`/`try9.pcap` 실측 · 40280.py/수정본 소스 · `~/.zsh_history` · git baseline 607fbc5. 볼트 `파일보관\` 에 Internal 스크린샷 없음(노트도 "스크린샷 대상 없음"으로 일치).

## 통과(반증 시도했으나 노트가 옳았던 것)
- **플래그 블록**: `flag_evidence.txt`/`shell_auto.txt`/`listener_443.log` 원문과 노트 인용이 정확히 일치. 대화형 `C:\Windows\system32>` cmd, `type` 원위치, `whoami=nt authority\system`, `hostname=internal`, IPv4 192.168.248.40, `Thu 08/20/2026 10:03 AM`. 웹셸 아님. 타임존 환산 일치(타겟 08/20 10:03 UTC-7 = KST 08/21 02:03, shell_auto.txt mtime 과 일치).
- **TCP timestamp 반증(6장 point1)**: try17_uptime_probe.log 로 확인. 6113@00:56:05 → 284901@01:42:33, Δ278788/2788s = 정확히 100.0 Hz, 리셋 없음 → revert 미반영. 산술까지 재검산 일치.
- **min vs max protocol 자기반증(point3)**: try11(testparm `client min protocol = LANMAN1`, NT1 강제해도 timeout) / try12(`smbclient max=NT1` → `NT_STATUS_LOGON_FAILURE`) 원문과 일치.
- **rpcclient IO_TIMEOUT 무익스(point6)**: try10 `=== T+0 rpcclient (no exploit) === … NT_STATUS_IO_TIMEOUT` 일치.
- **자동재부팅 사이클(point4)**: try20(IO_TIMEOUT)→try21(445 filtered)→try22(LOGON_FAILURE 복귀), attempt_loop.sh 주석("self-reboots in ~90s"), traces_confirmed.log, try24/25/30 모두 attempt1 콜백. systeminfo `System Boot Time 8/20/2026 10:17:35 AM`(플래그 회수 이후 재부팅) 이 사이클을 추가 뒷받침. 노트 6장에 재현 가능하게 담김.
- **셸 불안정 반복발사(point5)**: attempt_loop.sh + listener_auto.sh(stdin pre-feed) 실재. 노트 3장/6장 반영.
- **프론트매터**: ip 192.168.248.40 ✓, cves [CVE-2009-3103](=MS09-050, nmap_smbvuln.log 이 975497 로 확증; CVE-2012-1182 Samba 무관 삭제 정당) ✓, `manual_cves`/`manual_tags` 뒤 주석 없음 ✓. 태그 4개 전부 볼트 실재 leaf(smb 21·searchsploit 24·msfvenom 11·revshell 64 노트). `tech/payload/metasploit` 삭제 정당 — 수정본은 msfvenom+수동 PoC+nc, msfconsole/meterpreter 미사용(소스 확인). `os/windows` ✓. ports/services 이번 실측 일치, 49152↑ 정상 제외.
- **Kali 프롬프트**: `┌──(kali㉿kali)`/`???(kali?kali)` 잔존 0건(baseline 의 깨진 블록 전량 제거 확인). 타겟 프롬프트 `C:\Windows\system32>` 보존.

## 정정한 것
| 위치(문자열) | 무엇이 틀렸나 | 근거 파일 / 조치 |
|---|---|---|
| §1 nmap 블록 `49152-158/tcp open msrpc Microsoft Windows RPC` | 이번 스캔은 이 포트들을 `open unknown` 으로만 잡았다. `msrpc Microsoft Windows RPC` 는 **옛 인스턴스(baseline 607fbc5)의 서비스 라벨을 신규 스캔 블록에 잘못 옮긴 것**(날조성 컬럼). | nmap.log → `open unknown` 으로 정정, 실제로 있던 `53173/tcp filtered unknown` 줄 복원 |
| §1 "53173 … 재스캔에서 사라졌다" | 그 포트를 겨눈 재스캔 산출물 없음(부재 주장) | nmap.log(retransmission cap 경고) → "단발 blip, 재스캔 안 함"으로 정직화 |
| §2 "pysmb 가 있어 통과했다" | **거짓.** 이 Kali python2 엔 pysmb 없음(`ImportError`), 수정본은 그 import 줄을 **삭제**해 회피 | `python2 -c import` 실측 + 수정본 소스(`import sys, subprocess`) → "삭제했다"로 정정 |
| §6 try2 pcap "`dst port 443` 인바운드가 0" | try2.pcap 은 tcpdump 를 안 꺼 **try3 성공 콜백(00:57:33, 49159→443)까지 포함**. 파일 전체론 443 트래픽 5패킷 존재 → 문자 그대로면 반증됨 | `sudo tcpdump -r try2.pcap` 실측 → "try2 발사 직후 구간엔 콜백 없음, 같은 pcap 이 try3 콜백 담음(900→930)"으로 정밀화(오히려 증거 강화) |
| §6 "총 ~21분(150s·240s·280s·480s 대기)" | try4~try8 mtime 과 불일치(실 간격 44s/96s/~10분/~15분, 전 구간 ~27분) | try4-8 로그 mtime → 실측 간격으로 교체 |
| §3 "타겟 시간대 PST" | 8월은 PDT(UTC-7). smb-os-discovery `-07:00` | UTC-7/PDT 로 정정 |

## 보강한 것
- §2 길이제약: pcap 실측 900B(본문 896, 30B 부족)→930B(본문 926=0x39e) 대조를 추가해 "왜 패딩이 통했나"를 바이트로 뒷받침.
- §6 point2(복구 신호 오독): SMBv1 응답≠복구, SMBv2 생사는 `smb2-capabilities`(`SMB 2+ not supported` ↔ `2.0.2: Distributed File System`)로 갈린다는 계층 구분을 근거 파일과 함께 추가. 기존 노트에 이 스레드가 얇았음.
- §4 PRIVILEGES 블록: 재정렬·2열 압축이라 "(~30행 중 발췌)" 표기 추가(값은 전부 실측 Enabled로 정확).

## 삭제한 것
없음(정정·보강만).

## 관리자 판단 필요
없음. (색인 refresh 는 총괄 소관 — CVE/태그 수동 선언 정상.)
