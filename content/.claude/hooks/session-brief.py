#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""SessionStart 훅 — PG 라인 조직 규율과 현재 진행도를 세션 시작 시 주입한다.

`_STATUS.md` 를 읽어 집계를 뽑고, 중간 관리자(pg-line-manager)를 세우라는
상시 규율을 함께 붙인다. CLAUDE.md §0 과 같은 내용을 런타임에서도 강제한다.
"""
import io
import json
import os
import re
import sys

ORG = u"""[PG 라인 조직 — CLAUDE.md §0]
이 프로젝트는 중간 관리자를 거쳐 돈다. 총괄이 실무 에이전트를 직접 파견하는
평면 구조는 금지다.

  총괄 → pg-line-manager → pg-box-runner / pg-note-forge / writeup-auditor

총괄이 쥐는 것: 랩 슬롯(포털은 동시 1대만), 플래그 제출, 공유 인프라,
스코프·인가·다운로드 승인. 나머지는 관리자에게 넘긴다.

작업이 웨이브로 성립하면(박스/노트 2건 이상) pg-line-manager 를 먼저 세워라.
단발 1건이면 실무자를 직접 불러도 된다."""


def find_root():
    root = os.environ.get("CLAUDE_PROJECT_DIR")
    if root and os.path.isdir(root):
        return root
    # 훅 스크립트는 <root>/.claude/hooks/ 에 있다
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def read_status(root):
    path = os.path.join(root, "03. PG", "_STATUS.md")
    if not os.path.exists(path):
        return None, u"`03. PG\\_STATUS.md` 를 찾지 못했다 (경로: %s)" % path
    try:
        text = io.open(path, encoding="utf-8").read()
    except Exception as exc:                      # 인코딩 사고까지 세션을 죽이지 않는다
        return None, u"`_STATUS.md` 를 읽지 못했다: %s" % exc

    rows = []
    for label in (u"완료", u"부분 완료", u"미착수", u"합계"):
        m = re.search(u"\\|[^|\\n]*%s[^|\\n]*\\|\\s*\\**(\\d+)\\**" % re.escape(label), text)
        if m:
            rows.append((label, int(m.group(1))))

    checkboxes = len(re.findall(u"^- \\[ \\] ", text, re.M))
    return {"rows": rows, "checkboxes": checkboxes}, None


def main():
    try:
        sys.stdin.read()                          # 훅 입력은 쓰지 않지만 파이프는 비운다
    except Exception:
        pass

    root = find_root()
    status, err = read_status(root)

    lines = [ORG, u""]
    if err:
        lines.append(u"[진행도] " + err)
    else:
        parts = [u"%s %d" % (label, n) for label, n in status["rows"]]
        lines.append(u"[진행도] " + (u" · ".join(parts) if parts else u"집계표를 파싱하지 못했다"))
        lines.append(u"미착수 체크박스 실측: %d개" % status["checkboxes"])
        lines.append(
            u"주의: 집계표 숫자와 체크박스 실측이 어긋나면 표가 스테일한 것이다. "
            u"_STATUS.md 는 pg-line-manager 가 단독으로 기록한다(§6)."
        )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": u"\n".join(lines),
        },
        "suppressOutput": True,
    }
    # Windows 콘솔 stdout 은 cp949 로 잡힌다. ensure_ascii 로 \uXXXX 이스케이프해
    # 순수 ASCII 만 내보내면 코드페이지와 무관하게 안전하다.
    payload = json.dumps(out, ensure_ascii=True)
    try:
        sys.stdout.buffer.write(payload.encode("ascii"))
    except AttributeError:                        # py2 폴백
        sys.stdout.write(payload)


if __name__ == "__main__":
    main()
