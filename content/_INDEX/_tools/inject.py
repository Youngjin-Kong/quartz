# -*- coding: utf-8 -*-
"""meta.json 기준으로 프론트매터를 주입한다. 본문은 한 바이트도 건드리지 않는다.
--dry 로 먼저 검증, --apply 로 실제 기록."""
# Windows 콘솔은 기본 코드페이지가 cp949 라 em-dash 같은 문자에서 UnicodeEncodeError 로 죽는다.
# 파일은 이미 다 쓴 뒤 출력 단계에서 죽어서 '갱신이 실패했다'로 보인다 — stdout 을 UTF-8 로 고정한다.
import sys
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except (AttributeError, ValueError):
    pass

import os, io, json, sys, re
from collections import defaultdict, Counter

VAULT = r"C:\Users\QQ\Documents\Obsidian Vault"
HERE = os.path.dirname(os.path.abspath(__file__))

PLAT_LABEL = {
    "pg": "Proving Grounds", "htb": "Hack The Box", "pwk-challenge": "PWK 챌린지 랩",
    "exam": "시험 기록", "cheatsheet": "치트시트", "oscp-etc": "OSCP 기타",
    "pen200": "PEN-200 이론", "ctf": "CTF", "report": "보고서",
    "cppg": "CPPG", "swsec": "SW보안약점", "misc": "기타",
}
KIND_TAG = {"머신": "machine", "참조": "reference", "이론": "theory",
            "보고서": "report", "기타": "misc"}
STATUS_TAG = {"완료": "solved", "미완": "unsolved", "빈-스텁": "empty"}


def yaml_list(vals):
    return "\n".join("  - %s" % v for v in vals)


def build_fm(m):
    tags = ["type/%s" % KIND_TAG.get(m["kind"], "misc"), "platform/%s" % m["platform"]]
    if m.get("os"):
        tags.append("os/%s" % m["os"])
    if m.get("status") in STATUS_TAG:
        tags.append("status/%s" % STATUS_TAG[m["status"]])
    tags += m["techniques"]

    lines = ["---", "tags:"]
    lines.append(yaml_list(tags))
    lines.append("type: %s" % KIND_TAG.get(m["kind"], "misc"))
    lines.append("platform: %s" % m["platform"])
    if m.get("os"):
        lines.append("os: %s" % m["os"])
    if m.get("ip"):
        lines.append("ip: %s" % m["ip"])
    if m.get("domain"):
        lines.append("domain: %s" % m["domain"])
    if m.get("ports"):
        lines.append("ports: [%s]" % ", ".join(str(p) for p in m["ports"]))
    if m.get("services"):
        lines.append("services: [%s]" % ", ".join(m["services"]))
    if m.get("cves"):
        lines.append("cves: [%s]" % ", ".join(m["cves"]))
    if m.get("status"):
        lines.append("status: %s" % STATUS_TAG.get(m["status"], m["status"]))
    if m.get("manual_tags"):
        # 태그는 사람이 관리한다 — extract.py 가 이 선언을 보고 자동 판정을 건너뛴다.
        lines.append("manual_tags: true")
    if m.get("manual_cves"):
        # CVE 도 사람이 관리한다. 반증·비교로 언급한 번호가 색인되는 것을 막는다.
        lines.append("manual_cves: true")
    lines.append("tech_count: %d" % len(m["techniques"]))
    lines.append("---")
    return "\n".join(lines) + "\n"


def main():
    apply = "--apply" in sys.argv
    refresh = "--refresh" in sys.argv
    rows = json.load(io.open(os.path.join(HERE, "meta.json"), encoding="utf-8"))

    injected = skipped = replaced = 0
    skip_reasons = Counter()
    samples = []

    for m in rows:
        path = os.path.join(VAULT, m["rel"].replace("/", os.sep))
        raw = open(path, "rb").read()

        # BOM 처리
        bom = b""
        if raw.startswith(b"\xef\xbb\xbf"):
            bom, raw = raw[:3], raw[3:]

        # 프론트매터 판정
        head = raw[:8].decode("utf-8", "replace")
        if head.startswith("---\n") or head.startswith("---\r\n"):
            end = raw.find(b"\n---", 3)
            fm_blob = raw[:end] if end > 0 else b""
            # tech_count 또는 manual_tags 가 있으면 이 도구가 관리하는 블록이다.
            # manual_tags 노트도 갱신 대상에 포함해야 ip/ports/services/cves 가 최신으로 유지된다.
            # (태그 자체는 extract.py 가 선언값을 그대로 넘겨주므로 덮이지 않는다)
            ours = ((b"tech_count:" in fm_blob) or (b"manual_tags:" in fm_blob)
                    or (b"manual_cves:" in fm_blob))
            if refresh and ours:
                nl = raw.find(b"\n", end + 1)
                raw = raw[nl + 1:]                 # 기존 블록 제거
                replaced += 1
            else:
                skipped += 1
                skip_reasons["수동 프론트매터 보존" if not ours
                             else "기존 유지 (--refresh 미지정)"] += 1
                continue

        fm = build_fm(m).encode("utf-8")
        new = fm + raw          # BOM 제거: 프론트매터가 1행이어야 Obsidian이 인식
        if apply:
            with open(path, "wb") as f:
                f.write(new)
        injected += 1
        if len(samples) < 3 and m["kind"] == "머신" and m.get("techniques"):
            samples.append((m["rel"], build_fm(m)))

    print("=" * 60)
    print("모드: %s" % ("실제 적용" if apply else "DRY RUN (기록 안 함)"))
    print("신규 주입: %d / 갱신: %d / 건너뜀: %d / 총 %d" % (injected - replaced, replaced, skipped, len(rows)))
    for k, v in skip_reasons.items():
        print("  건너뜀 사유 — %s: %d" % (k, v))
    print("=" * 60)
    for rel, fm in samples:
        print("\n### %s" % rel)
        print(fm)


if __name__ == "__main__":
    main()
