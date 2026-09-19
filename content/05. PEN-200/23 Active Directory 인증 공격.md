---
tags:
  - type/theory
  - platform/pen200
type: theory
platform: pen200
source: pen-200.pdf
section: "23"
---

# 23 Active Directory 인증 공격

> **Attacking Active Directory Authentication** · PEN-200 §23

- 학습 단위 둘 — Active Directory 인증의 이해, Active Directory 인증에 대한 공격 수행
- 앞 모듈에서 사용자 계정·그룹 소속·등록된 SPN 을 열거했음. 이 모듈은 그 열거 결과를 실제 침해로 전환하는 단계임
- 먼저 AD 의 인증 메커니즘을 보고, Windows 가 패스워드 해시·티켓 같은 인증 객체를 «어디에» 캐시하는지 확인함
- 이어서 그 인증 메커니즘을 노리는 공격 기법을 다룸. 침투 테스트의 여러 국면에서 자격 증명과 시스템·서비스 접근을 얻는 데 쓰임
- 대상 도메인은 앞 모듈과 같은 `corp.com`
