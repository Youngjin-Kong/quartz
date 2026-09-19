---
tags:
  - type/theory
  - platform/pen200
type: theory
platform: pen200
source: pen-200.pdf
section: "17"
---

# 17 Windows 권한 상승

> **Windows Privilege Escalation** · PEN-200 §17

침투 테스트에서 Windows 시스템의 최초 발판은 대개 비권한 사용자로 잡힘. 다른 사용자의 홈 디렉터리에서 민감 정보를 찾거나, 시스템 설정 파일을 살피거나, Mimikatz 로 패스워드 해시를 추출하려면 관리자 권한이 필요함. 비권한 상태의 권한과 접근을 권한 있는 상태로 끌어올리는 이 과정이 권한 상승(privilege escalation) 임.

이 모듈은 Windows 를, 다음 모듈은 Linux 를 다룸. 둘을 마치면 두 운영체제의 보안 모델과 공격 표면이 어떻게 다른지, 각각에서 어떤 상승 벡터를 활용할 수 있는지를 함께 이해하게 됨.

다루는 학습 단위 셋 — Windows 열거, Windows 서비스 이용, 그 밖의 Windows 구성 요소 악용.

진행 순서 — Windows 의 권한과 접근 제어 메커니즘 소개 → 정보 수집으로 대상 시스템의 상황 파악 → 수집한 정보를 바탕으로 한 권한 상승 공격(사용자와 OS 가 남긴 민감 정보 탐색 → Windows 서비스 악용) → 예약 작업(scheduled tasks) 을 통한 상승 → 익스플로잇 활용.
