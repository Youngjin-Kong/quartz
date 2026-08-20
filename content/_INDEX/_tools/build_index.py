# -*- coding: utf-8 -*-
"""색인 노트 생성 — 기존 노트는 읽기만 한다."""
# Windows 콘솔은 기본 코드페이지가 cp949 라 em-dash 같은 문자에서 UnicodeEncodeError 로 죽는다.
# 파일은 이미 다 쓴 뒤 출력 단계에서 죽어서 '갱신이 실패했다'로 보인다 — stdout 을 UTF-8 로 고정한다.
import sys
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, ValueError):
    pass

import os, io, json
from collections import defaultdict, Counter

VAULT = r"C:\Users\QQ\Documents\Obsidian Vault"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(VAULT, "_INDEX")

# 기법 태그 → 한국어 명칭 + 한 줄 요약
TECH_INFO = {
    "tech/ad/kerberoast":       ("Kerberoasting", "SPN 계정의 TGS 해시를 뽑아 오프라인 크랙"),
    "tech/ad/asreproast":       ("AS-REP Roasting", "선인증 비활성 계정의 AS-REP을 크랙"),
    "tech/ad/dcsync":           ("DCSync / secretsdump", "복제 권한으로 NTDS 전체 해시 덤프"),
    "tech/ad/adcs":             ("ADCS 악용 (ESC1~8)", "인증서 템플릿 오설정으로 DA 인증서 발급"),
    "tech/ad/rbcd":             ("RBCD", "쓰기 권한으로 위임 설정 후 S4U2Self/Proxy"),
    "tech/ad/acl-abuse":        ("AD ACL 악용", "GenericAll/WriteDACL 등으로 객체 장악"),
    "tech/ad/shadow-cred":      ("Shadow Credentials", "KeyCredentialLink에 인증서 심어 PKINIT"),
    "tech/ad/ntlm-relay":       ("NTLM 릴레이 / Responder", "인증 강제 후 릴레이로 세션 획득"),
    "tech/ad/pth":              ("Pass-the-Hash", "평문 없이 NT 해시로 인증"),
    "tech/ad/bloodhound":       ("BloodHound 열거", "그래프로 최단 권한상승 경로 탐색"),
    "tech/ad/userenum":         ("도메인 계정 열거", "kerbrute·lookupsid로 유효 사용자명 확보"),
    "tech/ad/gpo-abuse":        ("GPO 악용", "쓰기 가능한 GPO로 전역 명령 실행"),
    "tech/ad/dnsadmins":        ("DnsAdmins", "DLL 플러그인 로드로 SYSTEM 실행"),
    "tech/ad/ticket-forge":     ("Golden/Silver Ticket", "krbtgt/서비스 키로 티켓 위조"),
    "tech/ad/delegation":       ("위임 악용", "제약/비제약 위임으로 권한 승계"),
    "tech/win/potato":          ("Potato 계열", "SeImpersonate 보유 시 SYSTEM 승격"),
    "tech/win/seimpersonate":   ("SeImpersonate 권한", "토큰 가장 권한 — Potato의 전제조건"),
    "tech/win/sebackup":        ("SeBackup / Backup Operators", "SAM·SYSTEM 하이브 복사로 해시 추출"),
    "tech/win/serestore":       ("SeRestore 권한", "utilman 치환·서비스 레지스트리 하이재킹으로 SYSTEM"),
    "tech/win/service-abuse":   ("서비스 오설정", "비인용 경로·바이너리 쓰기권한 악용"),
    "tech/win/alwaysinstall":   ("AlwaysInstallElevated", "MSI를 SYSTEM으로 설치"),
    "tech/win/autologon":       ("자동 로그온 자격증명", "레지스트리 평문 비밀번호"),
    "tech/win/uac-bypass":      ("UAC 우회", "fodhelper 등으로 승격 프롬프트 회피"),
    "tech/win/dll-hijack":      ("DLL 하이재킹", "탐색 경로에 악성 DLL 배치"),
    "tech/win/scheduled-task":  ("예약 작업 악용", "쓰기 가능한 작업 스크립트 교체"),
    "tech/lin/suid":            ("SUID 바이너리", "GTFOBins로 SUID 실행파일 탈출"),
    "tech/lin/sudo-abuse":      ("sudo 오설정", "NOPASSWD 항목을 GTFOBins로 탈출"),
    "tech/lin/capabilities":    ("Capabilities", "cap_setuid 등 보유 바이너리 악용"),
    "tech/lin/cron":            ("cron / 스케줄", "쓰기 가능한 주기 실행 스크립트 (pspy로 탐지)"),
    "tech/lin/nfs":             ("NFS no_root_squash", "원격에서 SUID 바이너리 심기"),
    "tech/lin/container-escape": ("컨테이너 탈출", "docker 그룹·lxd·docker.sock 악용"),
    "tech/lin/ld-preload":      ("LD_PRELOAD", "sudo env_keep 경유 라이브러리 주입"),
    "tech/lin/path-hijack":     ("PATH 하이재킹", "상대 경로 호출 가로채기"),
    "tech/lin/kernel-exploit":  ("커널 익스플로잇", "DirtyCow/DirtyPipe/PwnKit 등"),
    "tech/lin/wildcard":        ("와일드카드 인젝션", "tar --checkpoint-action 등"),
    "tech/lin/passwd-write":    ("passwd/shadow 접근", "쓰기 가능하거나 읽어서 크랙"),
    "tech/web/sqli":            ("SQL 인젝션", "UNION·오류기반·blind → RCE 또는 자격증명"),
    "tech/web/lfi-rfi":         ("LFI / RFI / 경로탐색", "파일 읽기 → 로그 포이즈닝 → RCE"),
    "tech/web/file-upload":     ("파일 업로드", "웹셸 업로드로 최초 실행"),
    "tech/web/webdav":          ("WebDAV", "PUT 허용 시 aspx/php 업로드"),
    "tech/web/ssti":            ("SSTI", "템플릿 표현식 주입으로 RCE"),
    "tech/web/deserialization": ("역직렬화", "ysoserial/phpggc 가젯체인"),
    "tech/web/xss":             ("XSS", "세션 탈취·관리자 강제 조작"),
    "tech/web/ssrf":            ("SSRF", "내부망·메타데이터 접근"),
    "tech/web/cmd-injection":   ("명령어 인젝션", "쉘 메타문자로 직접 실행"),
    "tech/web/default-creds":   ("기본 자격증명", "admin:admin 계열 — 항상 먼저 시도"),
    "tech/web/info-disclosure": ("정보 노출", "DEBUG 페이지·phpinfo·.git 노출로 경로·비밀·버전 획득"),
    "tech/web/xpathi":          ("XPath 인젝션", "XML 저장소를 XPath 조작으로 조회 — SQLi와 별개, 평문 저장 흔함"),
    "tech/cred/config-file":    ("설정파일 자격증명", "FileZilla·wp-config·unattend 등 설정에 박힌 평문/복호가능 암호"),
    "tech/exec/rdp":            ("RDP 접속", "확보한 자격증명으로 GUI 세션 진입 — GUI 전용 벡터가 열린다"),
    "tech/win/gui-lpe":         ("GUI 권한상승", "SYSTEM 권한 GUI의 파일 대화상자에서 셸 실행"),
    "tech/db/mssql":            ("MSSQL 악용", "xp_cmdshell·링크드서버 경유 실행"),
    "tech/db/mysql":            ("MySQL/MariaDB", "into outfile로 웹셸 작성"),
    "tech/db/h2":               ("H2 Database", "웹 콘솔의 RUNSCRIPT·별칭 정의로 코드 실행"),
    "tech/svc/smb":             ("SMB 열거", "smbclient·smbmap·nxc로 공유·정책 확인"),
    "tech/svc/ftp":             ("FTP", "익명 로그인·업로드 가능 여부"),
    "tech/svc/snmp":            ("SNMP", "커뮤니티 스트링으로 정보 유출"),
    "tech/svc/redis":           ("Redis", "인증 없는 인스턴스로 키 작성"),
    "tech/exec/winrm":          ("WinRM (5985)", "evil-winrm으로 셸 — 자격증명 확보 후 1순위"),
    "tech/exec/psexec":         ("PsExec 계열", "SMB 경유 서비스 생성 실행"),
    "tech/exec/wmi":            ("WMI 실행", "wmiexec로 반쌍방향 셸"),
    "tech/exec/ssh-key":        ("SSH 키", "id_rsa 탈취·authorized_keys 주입"),
    "tech/cred/crack":          ("해시 크랙", "hashcat/john + rockyou"),
    "tech/cred/spray":          ("패스워드 스프레이", "확보한 비밀번호를 전 계정에 재시도"),
    "tech/cred/mimikatz":       ("Mimikatz / LSASS", "메모리에서 평문·해시 추출"),
    "tech/cred/keepass":        ("KeePass", ".kdbx 마스터키 크랙"),
    "tech/cred/dpapi":          ("DPAPI", "마스터키로 저장된 자격증명 복호화"),
    "tech/pivot/chisel":        ("chisel", "HTTP 터널로 포트 포워딩"),
    "tech/pivot/ligolo":        ("ligolo-ng", "TUN 인터페이스 기반 피벗 — 가장 편함"),
    "tech/pivot/ssh-tunnel":    ("SSH 터널 / proxychains", "-L/-R/-D 포워딩"),
    "tech/pivot/socat":         ("socat", "포트 릴레이"),
    "tech/enum/dirbust":        ("디렉터리 브루트포스", "gobuster/feroxbuster/ffuf"),
    "tech/enum/peas":           ("linPEAS / winPEAS", "권한상승 자동 열거"),
    "tech/enum/searchsploit":   ("searchsploit", "버전 확정 후 공개 익스플로잇 검색"),
    "tech/payload/msfvenom":    ("msfvenom", "페이로드 생성"),
    "tech/payload/revshell":    ("리버스 셸", "nc -lvnp + rlwrap"),
    "tech/payload/av-evasion":  ("AV 회피", "AMSI 우회·난독화"),
    "tech/payload/metasploit":  ("Metasploit", "시험 중 1대만 허용 — 아껴 쓸 것"),
}

CAT_ORDER = [
    ("ad", "🏛 Active Directory"), ("win", "🪟 Windows 권한상승"),
    ("lin", "🐧 Linux 권한상승"), ("web", "🌐 웹"),
    ("db", "🗄 데이터베이스"), ("svc", "🔌 서비스 열거"),
    ("exec", "▶ 원격 실행"), ("cred", "🔑 자격증명"),
    ("pivot", "🔀 피벗·터널링"), ("enum", "🔍 열거"),
    ("payload", "💣 페이로드"),
]

# 포트 → (서비스, 이 포트를 보면 할 일)
PORT_PLAY = {
    21:   ("FTP", "익명 로그인 → `ftp anonymous@`. 업로드 가능하면 웹루트와 겹치는지 확인. 버전 → searchsploit."),
    22:   ("SSH", "버전만 기록. 자격증명 확보 후 재방문. 사용자명 열거는 시간낭비."),
    23:   ("Telnet", "평문 — 기본 자격증명 시도."),
    25:   ("SMTP", "`VRFY`로 사용자 열거. 오픈 릴레이 확인."),
    53:   ("DNS", "AD면 도메인명 확보. `dig axfr @타겟 도메인`으로 존 트랜스퍼 시도."),
    80:   ("HTTP", "whatweb → 디렉터리 브루트포스 → 버전 확정 → searchsploit. 소스보기·robots.txt 필수."),
    88:   ("Kerberos", "**AD 확정.** 도메인명 확보 후 AS-REP Roasting(`GetNPUsers`)부터 — 인증 불필요."),
    110:  ("POP3", "자격증명 확보 후 메일함에서 재사용 비밀번호 탐색."),
    135:  ("MSRPC", "`rpcclient -U '' -N`으로 널 세션 열거 시도."),
    139:  ("NetBIOS", "`enum4linux -a`."),
    143:  ("IMAP", "메일함 = 자격증명 창고."),
    389:  ("LDAP", "익명 바인드 → `ldapsearch -x -H ldap://타겟 -b 'DC=..'`. description 필드에 비밀번호 자주 있음."),
    443:  ("HTTPS", "인증서의 CN/SAN에서 호스트명·도메인 확보 → /etc/hosts 등록."),
    445:  ("SMB", "`nxc smb 타겟 -u '' -p ''` → 공유 목록 → 읽기 가능 공유 전수 탐색. 비밀번호 정책도 확인."),
    464:  ("kpasswd", "AD 부가 신호."),
    593:  ("RPC over HTTP", "AD 부가 신호."),
    636:  ("LDAPS", "389과 동일하게 접근."),
    873:  ("rsync", "`rsync --list-only 타겟::`로 모듈 열거 — 인증 없는 경우 많음."),
    1433: ("MSSQL", "`mssqlclient.py -windows-auth` → `enable_xp_cmdshell` → RCE. 링크드 서버도 확인."),
    2049: ("NFS", "`showmount -e 타겟` → 마운트 → no_root_squash면 SUID 심기."),
    3268: ("Global Catalog", "AD 포레스트 — LDAP 열거를 여기로."),
    3306: ("MySQL", "기본 자격증명 → `into outfile`로 웹셸."),
    3389: ("RDP", "자격증명 확보 후 `xfreerdp`. GUI가 필요한 privesc에 유용."),
    5432: ("PostgreSQL", "기본 자격증명 → `COPY FROM PROGRAM`으로 RCE."),
    5985: ("WinRM", "**자격증명 있으면 최우선.** `evil-winrm -i 타겟 -u u -p p`. Remote Management Users 소속 확인."),
    5986: ("WinRM/TLS", "5985과 동일."),
    6379: ("Redis", "인증 없으면 `redis-cli` → SSH 키 작성 또는 웹셸."),
    8080: ("HTTP-alt", "80과 동일 절차. Tomcat/Jenkins/Jetty 가능성 — 관리자 콘솔 기본 자격증명."),
    8443: ("HTTPS-alt", "관리 콘솔 자주 — 인증서 정보 확인."),
    9389: ("AD Web Services", "AD 확정 신호."),
    11211: ("Memcached", "`stats items`로 캐시 덤프."),
    27017: ("MongoDB", "인증 없는 인스턴스 — `mongo` 접속."),
}


def link(m):
    """모호성 없는 위키링크."""
    return "[[%s|%s]]" % (m["rel"][:-3], m["name"])


def write(fn, body):
    with io.open(os.path.join(OUT, fn), "w", encoding="utf-8", newline="\n") as f:
        f.write(body)
    return fn


def main():
    os.makedirs(OUT, exist_ok=True)
    rows = json.load(io.open(os.path.join(HERE, "meta.json"), encoding="utf-8"))
    machines = [r for r in rows if r["kind"] == "머신" and r["size"] > 0]
    refs = [r for r in rows if r["kind"] == "참조"]
    theory = [r for r in rows if r["kind"] == "이론"]
    made = []

    # ============ 01. 기법별 색인 ============
    by_tech = defaultdict(list)
    for r in rows:
        for t in r["techniques"]:
            by_tech[t].append(r)

    L = ["---", "tags: [index]", "type: index", "---",
         "# 기법별 색인",
         "", "> 상황 → 기법 역방향 조회용. 기법 이름을 누르면 그 기법을 실제로 쓴 머신 노트로 바로 간다.",
         "> 태그 창에서 `tech/` 를 펼쳐도 같은 결과를 얻는다.", ""]
    for cat, title in CAT_ORDER:
        tags = sorted([t for t in by_tech if t.startswith("tech/%s/" % cat)],
                      key=lambda t: -len(by_tech[t]))
        if not tags:
            continue
        L.append("## %s" % title)
        L.append("")
        for t in tags:
            name, desc = TECH_INFO.get(t, (t.split("/")[-1], ""))
            ms = [r for r in by_tech[t] if r["kind"] == "머신"]
            rf = [r for r in by_tech[t] if r["kind"] == "참조"]
            L.append("### %s  `#%s`" % (name, t))
            L.append("%s" % desc)
            L.append("")
            if ms:
                L.append("**실전 사례 %d건** — %s" % (len(ms), ", ".join(link(x) for x in ms)))
            else:
                L.append("**실전 사례 없음** — 아직 이 기법으로 뚫은 머신이 없다.")
            if rf:
                L.append("")
                L.append("문법 참조 — %s" % ", ".join(link(x) for x in rf))
            L.append("")
    made.append(write("01. 기법별 색인.md", "\n".join(L)))

    # ============ 02. 서비스·포트별 색인 ============
    by_port = defaultdict(list)
    for r in machines:
        for p in r.get("ports", []):
            by_port[p].append(r)

    L = ["---", "tags: [index]", "type: index", "---",
         "# 서비스·포트별 색인",
         "", "> nmap 결과를 보고 \"이 포트가 열려 있으면 뭘 하나\"를 찾는 표.",
         "> **할 일** 칸이 시험 당일 행동 지침이고, **사례** 칸이 실제로 그 포트가 열려 있던 내 머신 노트다.", ""]
    known = sorted([p for p in by_port if p in PORT_PLAY])
    unknown = sorted([p for p in by_port if p not in PORT_PLAY])
    for p in known:
        svc, play = PORT_PLAY[p]
        ms = by_port[p]
        L.append("## %d — %s  <small>(사례 %d건)</small>" % (p, svc, len(ms)))
        L.append("")
        L.append("**할 일:** %s" % play)
        L.append("")
        L.append("**사례:** %s" % ", ".join(link(x) for x in ms[:25]))
        if len(ms) > 25:
            L.append(" …외 %d건" % (len(ms) - 25))
        L.append("")
    if unknown:
        L.append("## 그 외 관측된 포트")
        L.append("")
        for p in unknown:
            L.append("- **%d** — %s" % (p, ", ".join(link(x) for x in by_port[p][:12])))
        L.append("")
    made.append(write("02. 서비스·포트별 색인.md", "\n".join(L)))

    # ============ 03. 머신 전체 목록 ============
    L = ["---", "tags: [index]", "type: index", "---",
         "# 머신 전체 목록",
         "", "> 복기용. 기법 수가 많은 노트가 곧 배울 게 많았던 머신이다.", ""]
    for plat, label in [("pg", "Proving Grounds"), ("htb", "Hack The Box"),
                        ("pwk-challenge", "PWK 챌린지 랩"), ("exam", "시험 기록"), ("ctf", "CTF")]:
        ms = sorted([r for r in machines if r["platform"] == plat], key=lambda r: r["name"].lower())
        if not ms:
            continue
        L.append("## %s <small>(%d)</small>" % (label, len(ms)))
        L.append("")
        L.append("| 머신 | OS | IP | 도메인 | 상태 | 기법 | 주요 기법 |")
        L.append("|---|---|---|---|---|---|---|")
        for r in ms:
            top = [TECH_INFO.get(t, (t.split("/")[-1], ""))[0] for t in r["techniques"]
                   if not t.startswith(("tech/enum/", "tech/payload/", "tech/svc/"))][:3]
            L.append("| %s | %s | %s | %s | %s | %d | %s |" % (
                link(r), r.get("os", "—"), r.get("ip", "—"), r.get("domain", "—"),
                {"완료": "✅", "부분": "🟡"}.get(r.get("status"), "⬜"),
                len(r["techniques"]), ", ".join(top) if top else "—"))
        L.append("")
    made.append(write("03. 머신 전체 목록.md", "\n".join(L)))

    # ============ 04. CVE 색인 ============
    by_cve = defaultdict(list)
    for r in rows:
        for c in r.get("cves", []):
            by_cve[c].append(r)
    L = ["---", "tags: [index]", "type: index", "---",
         "# CVE 색인",
         "", "> 노트 본문에서 자동 수집한 CVE %d종. 연도 역순." % len(by_cve), ""]
    for c in sorted(by_cve, key=lambda x: (-int(x.split("-")[1]), x)):
        L.append("- **%s** — %s" % (c, ", ".join(link(x) for x in by_cve[c])))
    made.append(write("04. CVE 색인.md", "\n".join(L)))

    # ============ 05. 치트시트 라우터 ============
    L = ["---", "tags: [index]", "type: index", "---",
         "# 치트시트 라우터",
         "", "> 치트시트가 %d개로 흩어져 내용이 겹친다. 어느 파일에 무엇이 있는지의 지도." % len(refs),
         "> 커버 기법 수가 많은 것이 사실상의 메인이다.", ""]
    L.append("| 치트시트 | 커버 기법 | 강한 영역 |")
    L.append("|---|---|---|")
    for r in sorted(refs, key=lambda r: -len(r["techniques"])):
        cats = Counter(t.split("/")[1] for t in r["techniques"])
        strong = ", ".join("%s(%d)" % (dict(CAT_ORDER).get(c, c).split(" ", 1)[-1], n)
                           for c, n in cats.most_common(3))
        L.append("| %s | %d | %s |" % (link(r), len(r["techniques"]), strong or "—"))
    L.append("")
    made.append(write("05. 치트시트 라우터.md", "\n".join(L)))

    # ============ 06. PEN-200 이론 목차 ============
    L = ["---", "tags: [index]", "type: index", "---",
         "# PEN-200 이론 목차",
         "", "> ⬜ 는 **본문이 비어 있는 노트**다. 제목만 만들어두고 내용을 채우지 않은 상태.", ""]
    filled = [r for r in theory if r["size"] > 0]
    empty = [r for r in theory if r["size"] == 0]
    L.append("**채워짐 %d개 / 비어 있음 %d개**" % (len(filled), len(empty)))
    L.append("")
    def keyf(r):
        m = r["name"].split(".")[0].strip()
        try:
            return (0, float(m))
        except ValueError:
            return (1, 0)
    L.append("## 비어 있는 노트 (%d개)" % len(empty))
    L.append("")
    for r in sorted(empty, key=keyf):
        L.append("- ⬜ %s" % link(r))
    L.append("")
    L.append("## 내용이 있는 노트 (%d개)" % len(filled))
    L.append("")
    for r in sorted(filled, key=keyf):
        L.append("- ✅ %s  <small>%.1fKB</small>" % (link(r), r["size"] / 1024.0))
    made.append(write("06. PEN-200 이론 목차.md", "\n".join(L)))

    # ============ 00. 허브 ============
    tc = Counter(t for r in rows for t in r["techniques"])
    L = ["---", "tags: [index, hub]", "type: index", "---",
         "# 🎯 OSCP 허브",
         "", "볼트 진입점. 검색이 아니라 **여기서 시작**한다.", "",
         "> [!warning] 이 노트는 자동 생성물이다",
         "> `_tools/refresh.ps1` 을 돌리면 덮어써진다. 내용을 바꾸려면 `_tools/build_index.py` 를 고칠 것.",
         "> `_INDEX/` 안의 00~06 노트가 모두 그렇다. 99번만 손으로 관리한다.", "",
         "## 용도별 진입", "",
         "| 상황 | 여기로 |",
         "|---|---|",
         "| nmap 결과를 보고 뭘 시도할지 모른다 | [[02. 서비스·포트별 색인]] |",
         "| 특정 기법을 쓴 사례를 찾는다 | [[01. 기법별 색인]] |",
         "| 명령어 문법이 기억 안 난다 | [[05. 치트시트 라우터]] |",
         "| 머신 하나를 복기한다 | [[03. 머신 전체 목록]] |",
         "| 버전을 찾았고 CVE를 확인한다 | [[04. CVE 색인]] |",
         "| 개념·이론을 확인한다 | [[06. PEN-200 이론 목차]] |",
         "| 머신을 추가했고 색인을 갱신한다 | [[99. 색인 운영 안내]] |",
         "",
         "## 볼트 현황", "",
         "- 머신 노트 **%d개** (완료 %d / 부분 %d / 미완 %d)" % (
             len(machines), sum(1 for r in machines if r.get("status") == "완료"),
             sum(1 for r in machines if r.get("status") == "부분"),
             sum(1 for r in machines if r.get("status") == "미완")),
         "- 기법 태그 **%d종**, 총 %d개 부착" % (len(tc), sum(tc.values())),
         "- CVE **%d종** 색인" % len(set(c for r in rows for c in r.get("cves", []))),
         "- 이론 노트 %d개 중 **%d개가 빈 껍데기**" % (len(theory), sum(1 for r in theory if r["size"] == 0)),
         "",
         "## 검색 문법 (Obsidian)", "",
         "```",
         "tag:#tech/ad/kerberoast          기법으로 찾기",
         "tag:#os/windows tag:#tech/win/potato   윈도우 + Potato 사례",
         "[\"ports\":445]                    445가 열려 있던 머신",
         "[\"domain\":\"hutch.offsec\"]        도메인으로",
         "[\"status\":\"unsolved\"]            아직 못 뚫은 것",
         "path:\"03. PG\" tag:#tech/lin/suid  PG 중 SUID 사례",
         "```",
         "",
         "> 태그 창(좌측 사이드바)에서 `tech/` 를 펼치면 기법 트리를 클릭으로 훑을 수 있다.",
         "> 이게 전문검색보다 빠르다.",
         "",
         "## 가장 많이 쓴 기법 상위 15", "",
    ]
    for t, n in tc.most_common(15):
        name = TECH_INFO.get(t, (t.split("/")[-1], ""))[0]
        L.append("- **%s** (%d) `#%s`" % (name, n, t))
    made.append(write("00. OSCP 허브.md", "\n".join(L)))

    print("생성 완료 — %s" % OUT)
    for f in made:
        p = os.path.join(OUT, f)
        print("  %-28s %6.1f KB" % (f, os.path.getsize(p) / 1024.0))


if __name__ == "__main__":
    main()
