---
tags:
  - type/theory
  - platform/pen200
type: theory
platform: pen200
source: pen-200.pdf
section: "24"
---

# 24 Active Directory 측면 이동

> **Lateral Movement in Active Directory** · PEN-200 §24

앞 모듈에서 고가치 계정과 그 계정이 로그인한 호스트를 특정하고, 비밀번호 해시와 Kerberos 티켓을 확보했음. 이 모듈은 그 자산으로 **해당 머신을 장악하는 단계**임.

해시를 크래킹해 평문으로 인증하는 것이 자연스러운 다음 수 같지만, 크래킹은 오래 걸리고 실패할 수 있음. 게다가 Kerberos·NTLM 은 평문을 직접 쓰지 않고 Microsoft 기본 도구는 해시 인증을 지원하지 않음.

그래서 여기서 다루는 것은 **평문 없이 해시나 티켓만으로 인증하고 코드 실행까지 얻는** 기법들임. 학습 단위는 측면 이동(lateral movement) 기법과 지속성(persistence) 확보 둘임.
