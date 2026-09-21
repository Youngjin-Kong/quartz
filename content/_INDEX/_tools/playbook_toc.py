# -*- coding: utf-8 -*-
"""`03. PG\\_PLAYBOOK.md` 의 목차 블록을 자기 헤딩에서 «생성»한다.

왜 손으로 안 쓰는가 — 이 파일은 웨이브마다 항목이 늘어난다. 손으로 적은 목록은
반드시 스테일해진다(실측: 노트 요약 줄의 절 번호 나열이 한 웨이브 만에 6건 어긋났고,
`D` 절의 「위 넷 중 셋이」가 표 17행이 될 때까지 남아 있었다).

`<!-- TOC -->` ~ `<!-- /TOC -->` 사이만 갈아끼우므로 본문·앵커는 건드리지 않는다.
목차 항목은 «링크가 아니라 텍스트»다 — 260개 앵커를 새로 만들면 제목이 바뀔 때마다
같이 깨지는 표면이 하나 더 생긴다. 시험장에서는 Ctrl+F 로 번호를 치는 것이 빠르다.
"""
import io
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except (AttributeError, ValueError):
    pass

PB = r"C:\Users\QQ\Documents\Obsidian Vault\03. PG\_PLAYBOOK.md"
BEGIN, END = "<!-- TOC -->", "<!-- /TOC -->"


def headings(lines):
    """펜스 «밖»의 헤딩만 돌려준다.

    ⚠️ `grep '^#'` 로 세면 안 된다 — 코드펜스 안의 YAML·셸 주석(`# enabled: true`)이
    헤딩으로 잡힌다. 실측으로 그 오탐이 실제로 났다.
    """
    inf = False
    for ln in lines:
        if re.match(r"^\s*```", ln):
            inf = not inf
            continue
        if inf:
            continue
        m = re.match(r"^(#{2,4})\s+(.+?)\s*$", ln)
        if m:
            yield len(m.group(1)), m.group(2).strip()


def build(lines):
    out = ["", "> [!abstract] 목차 — 자동 생성", "> 이 블록은 `_INDEX/_tools/playbook_toc.py` 가 헤딩에서 만든다. **손으로 고치지 마라.**",
           "> 항목은 링크가 아니라 텍스트다 — 번호를 Ctrl+F 하는 것이 빠르고, 앵커를 260개 더 만들면 제목이 바뀔 때 같이 깨진다.", ""]
    sec = cat = None
    bucket = []

    def flush():
        if cat and bucket:
            out.append("- **%s** — %s" % (cat, " · ".join(bucket)))
        del bucket[:]

    for lv, ti in headings(lines):
        if lv == 2:
            flush()
            cat = None
            sec = ti
            out.append("")
            out.append("**%s**" % sec)
        elif lv == 3:
            flush()
            cat = ti
        elif lv == 4:
            m = re.match(r"^([AB]-[\d-]+)\.\s*(.+)$", ti)
            bucket.append("`%s` %s" % (m.group(1), m.group(2)) if m else ti)
    flush()
    out.append("")
    return "\n".join(out)


def main():
    src = io.open(PB, encoding="utf-8").read()
    lines = src.split("\n")
    toc = build(lines)

    if BEGIN in src and END in src:
        head, rest = src.split(BEGIN, 1)
        _, tail = rest.split(END, 1)
        new = head + BEGIN + toc + END + tail
    else:
        # 최초 삽입 — 머리말(`---` 구분선) 바로 뒤, 첫 `## ` 앞
        m = re.search(r"^---\s*$", src, re.M)
        anchor = re.search(r"^## ", src, re.M)
        if not anchor:
            sys.stdout.write("삽입 위치를 못 찾았다 — 중단\n")
            return
        i = anchor.start()
        new = src[:i] + BEGIN + toc + END + "\n\n" + src[i:]

    io.open(PB, "w", encoding="utf-8", newline="").write(new)
    n = toc.count("`")
    sys.stdout.write("목차 갱신 — 항목 %d개 / 목차 %d행\n" % (n // 2, toc.count("\n")))


if __name__ == "__main__":
    main()
