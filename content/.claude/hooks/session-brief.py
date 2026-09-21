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

PG 박스 풀이·노트 작업은 예외 없이 pg-line-manager 를 먼저 세운다.
웨이브 성립 여부는 「박스 수」가 아니라 「실무 에이전트 파견 건수」로 센다 —
박스가 1개여도 작성(러너) + 적대적 검증(감사자)으로 파견이 2건이라 웨이브다.
총괄이 실무자를 직접 부르는 경우는 관리자 자체를 못 쓸 때뿐이다.

총괄은 사용자 지시를 기다리지 않고 라인을 스스로 굴린다. _STATUS.md 미착수에서
박스를 골라 켜고, 끝나면 묻지 말고 다음 박스로 넘어간다 —
「다음 박스 진행할까요?」를 묻는 것 자체가 규율 위반이다(사용자 상시 지시).
슬롯·플래그 제출·공유 인프라·손절 판단은 그대로 총괄이 쥐고,
진행 상황은 묻지 말고 보고한다.

웨이브는 슬롯 경계에서 자른다 — 박스 웨이브(러너)와 노트 웨이브(note-forge
+auditor)는 별개다. 러너는 증적을 다 걷은 지점에서 반환하고 관리자도 즉시
반환한다. 그 반환이 곧 슬롯 반납 신호이며, 에이전트 완료는 자동 통지되므로
별도 채널이 필요 없다. 신호를 받으면 ①정지+다음 박스 기동 → ②노트·감사 웨이브
파견 → ③사용자 보고 순서로 움직인다. 다음 박스를 켤 때 Accept 로 딸려
정리되는 것에 의존하지 마라 — 그건 정지가 아니라 부수 효과다.

러너 반환 전 ~/PG/<박스>/writeup_notes.txt 가 필수다. 반환하면 러너 기억이
사라지고 시행착오가 통째로 빈다(실측: 70박스 중 17개만 보유)."""


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
