# -*- coding: utf-8 -*-
"""OSCP 볼트 메타데이터 추출기 — 본문 무수정, 프론트매터 후보만 생성."""
# Windows 콘솔은 기본 코드페이지가 cp949 라 em-dash 같은 문자에서 UnicodeEncodeError 로 죽는다.
# 파일은 이미 다 쓴 뒤 출력 단계에서 죽어서 '갱신이 실패했다'로 보인다 — stdout 을 UTF-8 로 고정한다.
import sys
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, ValueError):
    pass

import os, re, json, io

VAULT = r"C:\Users\QQ\Documents\Obsidian Vault"


def classify(rel):
    p = rel.replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    # 강의 모듈/코스 노트는 머신이 아니다 (예: "02. Pentest Essentials")
    if re.match(r"^\d+\.\s", base) and "Pentest" in base:
        return "pg-course", "참조"
    if p.startswith("03. PG"):
        return "pg", "머신"
    if p.startswith("02. HTB"):
        return "htb", "머신"
    if p.startswith("01. OSCP/02. OSCP Challenge"):
        return "pwk-challenge", "머신"
    if p.startswith("01. OSCP/01. OSCP CheatSheet"):
        return "cheatsheet", "참조"
    if p.startswith("01. OSCP/03. OSCP-exam") or p.startswith("01. OSCP/04. OSCP-EXAM"):
        return "exam", "머신"
    if p.startswith("01. OSCP/99. etc"):
        return "oscp-etc", "참조"
    if p.startswith("OSCP-OS-"):
        return "pen200", "이론"
    if p.startswith("97. CTF"):
        return "ctf", "머신"
    if p.startswith("00. Portfolio"):
        return "report", "보고서"
    if p.startswith("98. CPPG"):
        return "cppg", "이론"
    if p.startswith("04. SW"):
        return "swsec", "이론"
    return "misc", "기타"


# (태그, [정규식 패턴...]) — 대소문자 무시
TECH_RAW = [
    # ---- Active Directory ----
    ("tech/ad/kerberoast",       [r"GetUserSPNs", r"kerberoast"]),
    ("tech/ad/asreproast",       [r"GetNPUsers", r"asrep", r"DONT_REQUIRE_PREAUTH"]),
    ("tech/ad/dcsync",           [r"secretsdump", r"dcsync", r"drsuapi"]),
    ("tech/ad/adcs",             [r"certipy", r"\bESC[1-9]\b", r"Certify\.exe", r"\bADCS\b"]),
    ("tech/ad/rbcd",             [r"\bRBCD\b", r"getST\.py", r"AllowedToActOnBehalf", r"resource[- ]based constrained"]),
    ("tech/ad/acl-abuse",        [r"GenericAll", r"GenericWrite", r"WriteDACL", r"WriteOwner", r"ForceChangePassword"]),
    ("tech/ad/shadow-cred",      [r"shadow[- ]?cred", r"KeyCredentialLink", r"whisker"]),
    ("tech/ad/ntlm-relay",       [r"ntlmrelayx", r"ntlm[- ]?relay", r"responder"]),
    ("tech/ad/pth",              [r"pass[- ]the[- ]hash", r"-hashes\s+:", r"\bPtH\b"]),
    ("tech/ad/bloodhound",       [r"bloodhound", r"sharphound", r"neo4j"]),
    ("tech/ad/gpo-abuse",        [r"SharpGPOAbuse", r"gpo.?abuse"]),
    ("tech/ad/dnsadmins",        [r"DnsAdmin", r"serverlevelplugindll"]),
    ("tech/ad/ticket-forge",     [r"golden ticket", r"silver ticket", r"ticketer\.py"]),
    ("tech/ad/delegation",       [r"unconstrained deleg", r"constrained deleg", r"TRUSTED_FOR_DELEGATION"]),
    # ---- Windows privesc ----
    ("tech/win/potato",          [r"PrintSpoofer", r"GodPotato", r"JuicyPotato", r"RoguePotato", r"SweetPotato"]),
    ("tech/win/seimpersonate",   [r"SeImpersonate", r"SeAssignPrimaryToken"]),
    ("tech/win/sebackup",        [r"SeBackup", r"backup operator", r"reg save hklm"]),
    ("tech/win/serestore",       [r"SeRestore", r"SeRestoreAbuse"]),
    ("tech/win/service-abuse",   [r"unquoted", r"sc\s+qc\b", r"binPath="]),
    ("tech/win/alwaysinstall",   [r"AlwaysInstallElevated"]),
    ("tech/win/autologon",       [r"auto[Ll]ogon", r"DefaultPassword"]),
    ("tech/win/uac-bypass",      [r"uac.?bypass", r"fodhelper"]),
    ("tech/win/dll-hijack",      [r"dll.?hijack", r"procmon"]),
    ("tech/win/scheduled-task",  [r"schtasks", r"scheduled task"]),
    # ---- Linux privesc ----
    ("tech/lin/suid",            [r"\bSUID\b", r"perm -4000", r"perm -u=s"]),
    ("tech/lin/sudo-abuse",      [r"sudo\s+-l", r"NOPASSWD", r"gtfobins"]),
    ("tech/lin/capabilities",    [r"getcap", r"cap_setuid", r"cap_dac_read"]),
    ("tech/lin/cron",            [r"crontab", r"/etc/cron", r"\bpspy\b"]),
    ("tech/lin/nfs",             [r"no_root_squash", r"showmount"]),
    ("tech/lin/container-escape", [r"docker\s+group", r"\blxd\b", r"lxc\s+init", r"docker\.sock"]),
    ("tech/lin/ld-preload",      [r"LD_PRELOAD", r"LD_LIBRARY_PATH"]),
    ("tech/lin/path-hijack",     [r"path.?hijack", r"상대\s*경로"]),
    ("tech/lin/kernel-exploit",  [r"dirty\s?cow", r"dirty\s?pipe", r"kernel exploit", r"pwnkit", r"polkit"]),
    ("tech/lin/wildcard",        [r"checkpoint-action", r"tar.{0,20}wildcard"]),
    ("tech/lin/passwd-write",    [r"/etc/passwd", r"/etc/shadow"]),
    # ---- Web ----
    ("tech/web/sqli",            [r"sqlmap", r"UNION\s+SELECT", r"or 1=1", r"sql.?inject"]),
    ("tech/web/lfi-rfi",         [r"\.\./\.\./", r"\bLFI\b", r"\bRFI\b", r"php://filter", r"travers"]),
    ("tech/web/file-upload",     [r"webshell", r"shell\.(php|aspx|jsp|asp)", r"upload.{0,15}\.php"]),
    ("tech/web/webdav",          [r"davtest", r"cadaver", r"WebDAV", r"PROPFIND"]),
    ("tech/web/ssti",            [r"\bSSTI\b", r"\{\{7\*7\}\}", r"template inject"]),
    ("tech/web/deserialization", [r"deserializ", r"역직렬화", r"ysoserial", r"phpggc", r"__wakeup"]),
    ("tech/web/xss",             [r"\bXSS\b", r"script>alert"]),
    ("tech/web/ssrf",            [r"\bSSRF\b", r"169\.254\.169\.254"]),
    ("tech/web/cmd-injection",   [r"command inject", r"명령어?\s*삽입", r"명령어?\s*주입"]),
    ("tech/web/default-creds",   [r"default cred", r"admin:admin", r"기본 자격증명", r"admin:password"]),
    # ---- DB / 서비스 ----
    ("tech/db/mssql",            [r"xp_cmdshell", r"mssqlclient", r"OPENQUERY"]),
    ("tech/db/mysql",            [r"mysql\s+-u", r"MariaDB", r"into outfile"]),
    ("tech/svc/smb",             [r"smbclient", r"smbmap", r"enum4linux", r"crackmapexec", r"\bnxc\b", r"netexec"]),
    ("tech/svc/ftp",             [r"anonymous.{0,20}ftp", r"FileZilla", r"ftp>"]),
    ("tech/svc/snmp",            [r"snmpwalk", r"onesixtyone"]),
    ("tech/svc/redis",           [r"redis-cli"]),
    # ---- 접근 / 실행 ----
    ("tech/exec/winrm",          [r"evil-winrm", r"\bwinrs\b"]),
    ("tech/exec/psexec",         [r"psexec", r"smbexec", r"atexec", r"dcomexec"]),
    ("tech/exec/wmi",            [r"wmiexec"]),
    ("tech/exec/ssh-key",        [r"id_rsa", r"authorized_keys", r"id_ed25519"]),
    # ---- 자격증명 ----
    ("tech/cred/crack",          [r"hashcat", r"rockyou", r"john\s+--"]),
    ("tech/cred/spray",          [r"password spray", r"\bhydra\b", r"패스워드 스프레이"]),
    ("tech/cred/mimikatz",       [r"mimikatz", r"sekurlsa", r"\blsass\b"]),
    ("tech/cred/keepass",        [r"keepass", r"\.kdbx"]),
    ("tech/cred/dpapi",          [r"\bDPAPI\b", r"masterkey"]),
    # ---- 피벗 ----
    ("tech/pivot/chisel",        [r"chisel"]),
    ("tech/pivot/ligolo",        [r"ligolo"]),
    ("tech/pivot/ssh-tunnel",    [r"ssh\s+-[LRD]\s", r"sshuttle", r"proxychains"]),
    ("tech/pivot/socat",         [r"socat"]),
    # ---- 열거 ----
    ("tech/enum/dirbust",        [r"gobuster", r"feroxbuster", r"dirsearch", r"\bffuf\b", r"\bdirb\b"]),
    ("tech/enum/peas",           [r"linpeas", r"winpeas"]),
    ("tech/enum/searchsploit",   [r"searchsploit", r"exploit-?db"]),
    # ---- 페이로드 ----
    ("tech/payload/msfvenom",    [r"msfvenom"]),
    ("tech/payload/revshell",    [r"reverse shell", r"역방향 셸", r"리버스\s?셸", r"nc\s+-lvnp", r"rlwrap"]),
    ("tech/payload/av-evasion",  [r"av.?evasion", r"\bamsi\b", r"obfuscat", r"난독화"]),
    ("tech/payload/metasploit",  [r"msfconsole", r"meterpreter", r"multi/handler"]),
]
TECH = [(t, [re.compile(p, re.I) for p in pats]) for t, pats in TECH_RAW]

PORT_RE = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)", re.M)
IP_RE = re.compile(r"Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})")
DOM_RE = re.compile(r"Domain:\s*([A-Za-z0-9][A-Za-z0-9.\-]*\.[A-Za-z]{2,})")
# (?!\.[a-z0-9]) — 뒤에 레이블이 더 있으면 FQDN 의 끝이 아니므로 도메인이 아니다.
# 없으면 `com.sun.management.jmxremote.local.only=false` 의 `jmxremote.local` 을 도메인으로 오인한다.
# 부수 효과로 `dc01.corp.local` 이 `dc01.corp` 가 아니라 `corp.local` 로 올바르게 잡힌다.
DOM2_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]{1,30}\.(?:htb|offsec|local|lab|corp))\b(?!\.[a-z0-9])", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SOLVED_RE = re.compile(r"root\.txt|proof\.txt|local\.txt|nt authority\\system|uid=0\(root\)", re.I)


MANUAL_RE = re.compile(r"^manual_tags:\s*true\s*(?:#.*)?$", re.M | re.I)
DECL_TAG_RE = re.compile(r"^  - (tech/\S+)\s*$", re.M)
MANUAL_CVE_RE = re.compile(r"^manual_cves:\s*true\s*(?:#.*)?$", re.M | re.I)
DECL_CVE_RE = re.compile(r"^cves:\s*\[([^\]]*)\]\s*$", re.M | re.I)


def declared_tags(text):
    """노트가 `manual_tags: true` 를 선언했으면 프론트매터의 tech/* 태그를 그대로 쓴다.

    학습용으로 깊게 쓴 writeup은 배경 지식·대안 경로·GTFOBins 비교표에서 실제로 쓰지
    않은 기법을 대량으로 언급한다. 본문 키워드 매칭은 그것까지 잡아내 과잉 태깅이 된다.
    그런 노트는 사람이 태그를 관리하고, 자동 추출은 그 선언을 존중한다.
    선언이 없으면 종전대로 본문에서 자동 판정한다.
    """
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fm = text[:end]
    if not MANUAL_RE.search(fm):
        return None
    return DECL_TAG_RE.findall(fm)


def frontmatter(text):
    """프론트매터 블록만 떼어 돌려준다. 없으면 None."""
    if not text.startswith("---"):
        return None
    end = text.find('\n---', 3)
    return None if end < 0 else text[:end]


def declared_cves(text):
    """노트가 `manual_cves: true` 를 선언했으면 프론트매터의 cves 를 그대로 쓴다.

    CVE_RE 는 본문 전체를 무조건 긁는다. 그래서 **"이 CVE 는 이 박스가 아니다"라고
    반증하려고 적은 번호까지 색인된다** — 실측 사례: Kevin 에 CVE-2009-2685·2009-4000,
    Twiggy 에 CVE-2014-9721, Algernon 에 CVE-2019-18935 가 그렇게 붙었다.
    비교·반증 서술은 학습용 노트에서 오히려 값진 부분이라 본문에서 지울 수 없다.
    그러니 색인 쪽이 사람의 선언을 존중한다. manual_tags 와 독립이다.
    """
    fm = frontmatter(text)
    if fm is None or not MANUAL_CVE_RE.search(fm):
        return None
    m = DECL_CVE_RE.search(fm)
    if not m:
        return []          # 선언만 하고 목록이 없으면 "이 노트에 CVE 없음"
    return [c.strip().upper() for c in m.group(1).split(",") if c.strip()]


def read_text(path):
    raw = open(path, "rb").read()
    for enc in ("utf-8", "cp949"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "replace"), "broken"


def extract(path, rel):
    plat, kind = classify(rel)
    size = os.path.getsize(path)
    meta = {"platform": plat, "kind": kind, "size": size, "techniques": []}
    if size == 0:
        meta["status"] = "빈-스텁"
        return meta

    text, enc = read_text(path)
    meta["encoding"] = enc

    # 본문 스캔에서 프론트매터를 뺀다 — 안 빼면 **피드백 루프**가 생긴다.
    # 이 도구가 써 넣은 `domain: hub.local` / `cves: [...]` 가 다음 회차 스캔에
    # 다시 잡혀 자기 값을 강화한다. 그러면 한 번 들어간 오탐이 영구히 못 빠진다.
    # 선언(manual_tags / manual_cves) 판정은 프론트매터가 필요하므로 원문 text 를 그대로 넘긴다.
    fm_blk = frontmatter(text)
    body = text[len(fm_blk) + 4:] if fm_blk is not None else text

    low = body.lower()

    win = len(re.findall(r"cpe:/o:microsoft|running:\s*microsoft windows|os:\s*windows|microsoft windows rpc", low))
    lin = len(re.findall(r"cpe:/o:linux|running:\s*linux|openssh.{0,40}(ubuntu|debian)|uid=\d+\(", low))
    if win or lin:
        meta["os"] = "windows" if win >= lin else "linux"

    ports, svcs = set(), set()
    for p, _proto, svc in PORT_RE.findall(body):
        n = int(p)
        if n >= 49152 or n in (5040, 7680):
            continue
        ports.add(n)
        s = svc.rstrip("?").lower()
        if s not in ("unknown", "tcpwrapped"):
            svcs.add(s)
    if ports:
        meta["ports"] = sorted(ports)
    if svcs:
        meta["services"] = sorted(svcs)

    ips = IP_RE.findall(body)
    if ips:
        meta["ip"] = ips[0]

    # 도메인처럼 생겼지만 아닌 것 — 자바 시스템 프로퍼티·설정 키 조각이 대표적이다.
    # 예: `-Dcom.sun.management.jmxremote.local.only=false` 의 `jmxremote.local`
    NOT_DOMAIN = {"jmxremote.local", "management.local", "rmi.local",
                  "sun.local", "java.local", "localhost.local"}
    doms = [d.lower() for d in DOM_RE.findall(body)] + [d.lower() for d in DOM2_RE.findall(body)]
    doms = [d for d in doms if d not in NOT_DOMAIN]
    doms = [d for d in doms if not d.startswith("www.")]
    if doms:
        meta["domain"] = max(set(doms), key=doms.count)

    decl_cves = declared_cves(text)
    if decl_cves is not None:
        if decl_cves:
            meta["cves"] = decl_cves
        meta["manual_cves"] = True
    else:
        cves = sorted(set(c.upper() for c in CVE_RE.findall(body)))
        if cves:
            meta["cves"] = cves
            if len(cves) > 12:
                meta["cve_bulk"] = True   # 취약점 스캐너 출력 덤프로 추정

    manual = declared_tags(text)
    if manual is not None:
        meta["techniques"] = manual
        meta["manual_tags"] = True
    else:
        techs = []
        for tag, pats in TECH:
            for pr in pats:
                if pr.search(body):
                    techs.append(tag)
                    break
        meta["techniques"] = techs

    if kind == "머신":
        meta["status"] = "완료" if SOLVED_RE.search(body) else "미완"
    return meta


def main():
    rows = []
    for root, dirs, files in os.walk(VAULT):
        dirs[:] = [d for d in dirs if d not in (".obsidian", ".git", ".trash", "파일보관", "storage", "_INDEX")]
        for fn in files:
            if not fn.endswith(".md"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, VAULT)
            m = extract(path, rel)
            m["rel"] = rel.replace("\\", "/")
            m["name"] = fn[:-3]
            rows.append(m)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meta.json")
    with io.open(out, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=1)

    # ---- 요약 리포트 ----
    print("추출 완료: %d개 노트" % len(rows))
    from collections import Counter
    print("\n[분류별]")
    for k, v in Counter((r["platform"], r["kind"]) for r in rows).most_common():
        print("  %-16s %-6s %d" % (k[0], k[1], v))
    print("\n[OS 판정]")
    for k, v in Counter(r.get("os", "-미판정-") for r in rows).most_common():
        print("  %-12s %d" % (k, v))
    print("\n[기법 태그 상위 25]")
    tc = Counter(t for r in rows for t in r["techniques"])
    for k, v in tc.most_common(25):
        print("  %-28s %d" % (k, v))
    print("\n총 기법 태그 종류: %d, 태그 부착 총량: %d" % (len(tc), sum(tc.values())))
    print("\n[노트당 기법 태그 수 — 과잉 태깅 점검]")
    top = sorted(rows, key=lambda r: -len(r["techniques"]))[:10]
    for r in top:
        print("  %3d개  %s" % (len(r["techniques"]), r["rel"]))
    print("\n[인코딩]")
    for k, v in Counter(r.get("encoding", "-") for r in rows).most_common():
        print("  %-10s %d" % (k, v))
    print("\n[CVE 발견]")
    cv = Counter(c for r in rows for c in r.get("cves", []))
    print("  종류 %d개: %s" % (len(cv), ", ".join(k for k, _ in cv.most_common(15))))
    print("\n→ meta.json 저장: %s" % out)


if __name__ == "__main__":
    main()
