# -*- coding: utf-8 -*-
"""OSCP 볼트 메타데이터 추출기 — 본문 무수정, 프론트매터 후보만 생성."""
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
DOM2_RE = re.compile(r"\b([a-z0-9][a-z0-9\-]{1,30}\.(?:htb|offsec|local|lab|corp))\b", re.I)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SOLVED_RE = re.compile(r"root\.txt|proof\.txt|local\.txt|nt authority\\system|uid=0\(root\)", re.I)


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
    low = text.lower()

    win = len(re.findall(r"cpe:/o:microsoft|running:\s*microsoft windows|os:\s*windows|microsoft windows rpc", low))
    lin = len(re.findall(r"cpe:/o:linux|running:\s*linux|openssh.{0,40}(ubuntu|debian)|uid=\d+\(", low))
    if win or lin:
        meta["os"] = "windows" if win >= lin else "linux"

    ports, svcs = set(), set()
    for p, _proto, svc in PORT_RE.findall(text):
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

    ips = IP_RE.findall(text)
    if ips:
        meta["ip"] = ips[0]

    doms = [d.lower() for d in DOM_RE.findall(text)] + [d.lower() for d in DOM2_RE.findall(text)]
    doms = [d for d in doms if not d.startswith("www.")]
    if doms:
        meta["domain"] = max(set(doms), key=doms.count)

    cves = sorted(set(c.upper() for c in CVE_RE.findall(text)))
    if cves:
        meta["cves"] = cves
        if len(cves) > 12:
            meta["cve_bulk"] = True   # 취약점 스캐너 출력 덤프로 추정

    techs = []
    for tag, pats in TECH:
        for pr in pats:
            if pr.search(text):
                techs.append(tag)
                break
    meta["techniques"] = techs

    if kind == "머신":
        meta["status"] = "완료" if SOLVED_RE.search(text) else "미완"
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
