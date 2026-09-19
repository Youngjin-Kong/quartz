---
tags:
  - type/theory
  - platform/pen200
type: theory
platform: pen200
source: pen-200.pdf
section: "22"
---

# 22 Active Directory 소개와 열거

> **Active Directory Introduction and Enumeration** · PEN-200 §22

세 단원 — Active Directory 소개, 수동 도구 열거, 자동화 도구 열거.

Active Directory Domain Services(줄여서 AD)는 운영체제·애플리케이션·사용자·데이터 접근 권한을 대규모로 관리하는 서비스임. 설치는 표준 설정으로 되지만, 관리자가 조직 사정에 맞춰 손보는 것이 보통이라 **환경마다 구성이 다름.**

침투 테스터에게 AD 가 값나가는 이유는 담긴 정보량임 — 도메인 안의 특정 객체만 장악해도 조직 인프라 전체를 통제할 수 있음. 이 모듈은 그중 열거(enumeration)만 다루고, 여기서 걷은 정보가 이후 AD 인증 공격·측면 이동(lateral movement) 모듈의 입력이 됨.
