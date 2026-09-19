---
tags:
  - type/theory
  - platform/pen200
type: theory
platform: pen200
source: pen-200.pdf
section: "18"
---

# 18 Linux 권한 상승

> **Linux Privilege Escalation** · PEN-200 §18

권한 상승(privilege escalation)도 다른 기법과 마찬가지로 **대상에 대한 지식 수집이 선행 조건**임. 오설정이나 소프트웨어 취약점을 열거(enumeration)로 찾아내야 악용 지점이 생김.

MITRE ATT&CK 기준으로 권한 상승은 단일 기법이 아니라 **여러 기법을 묶은 전술(tactic)** — 주어진 권한을 지렛대로 원래 못 닿는 자원에 접근하는 것이 공통 목표임.

다루는 학습 단위 넷:

- Linux 열거
- 기밀 정보 노출
- 취약한 파일 권한
- 시스템 구성 요소 악용
