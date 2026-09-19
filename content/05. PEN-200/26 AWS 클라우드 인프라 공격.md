---
tags:
  - type/theory
  - platform/pen200
type: theory
platform: pen200
source: pen-200.pdf
section: "26"
---

# 26 AWS 클라우드 인프라 공격

> **Attacking AWS Cloud Infrastructure** · PEN-200 §26

CI/CD 는 배포를 자동화·반복 가능·검증 가능하게 만드는 현대 클라우드 환경의 핵심임. 다만 그러려면 파이프라인이 소스 코드·시크릿·AWS 서비스와 배포 환경에 **접근 권한을 쥐어야** 하고, 그 점이 공격면을 넓힘. 취약한 CI/CD 하나를 장악하면 인프라 안쪽으로 권한 상승(privilege escalation)이 이어지므로 1순위 표적임.

OWASP 가 정리한 CI/CD 상위 10대 위험:

| | 위험 |
|---|---|
| CICD-SEC-1 | Insufficient Flow Control Mechanisms |
| CICD-SEC-2 | Inadequate Identity and Access Management |
| CICD-SEC-3 | Dependency Chain Abuse |
| CICD-SEC-4 | Poisoned Pipeline Execution (PPE) |
| CICD-SEC-5 | Insufficient PBAC (Pipeline-Based Access Controls) |
| CICD-SEC-6 | Insufficient Credential Hygiene |
| CICD-SEC-7 | Insecure System Configuration |
| CICD-SEC-8 | Ungoverned Usage of 3rd Party Services |
| CICD-SEC-9 | Improper Artifact Integrity Validation |
| CICD-SEC-10 | Insufficient Logging and Visibility |

모듈은 두 부분 — 전반부 「유출된 시크릿에서 파이프라인 오염까지」, 후반부 「의존성 체인 악용」. SEC-8 은 서드파티 서비스가 있어야 재현돼 일관된 랩을 못 만들므로 제외, SEC-10 은 가시성 확보에 수동 개입이 필요해 범위 밖임.

**전반부 — SEC-4·5·6.**
- Poisoned Pipeline Execution(PPE) — 빌드·배포 스크립트를 공격자가 장악하는 것. 리버스셸이나 시크릿 탈취로 이어짐
- Insufficient PBAC — 파이프라인이 시크릿·민감 자산을 제대로 보호하지 못함
- Insufficient Credential Hygiene — 시크릿·토큰 통제가 허술해 유출·상승에 노출됨

전반부 흐름 — S3 버킷 오설정으로 Git 자격 증명 획득 → 파이프라인 수정 → 페이로드 주입으로 시크릿 탈취 → 환경 장악.

**후반부 — SEC-3·5·7·9.**
- Dependency Chain Abuse — 공식 의존성을 가로채거나 유사 이름 패키지를 올려 빌드 시스템이 악성 코드를 내려받게 만듦
- Insufficient PBAC — 파이프라인 권한이 과도해 장악 시 피해가 커짐
- Insecure System Configuration — 파이프라인 애플리케이션의 오설정·취약 코드
- Improper Artifact Integrity Validation — 검증이 없어 악성 코드 주입이 안 걸러짐

후반부 흐름 — 공개 저장소에 없는 의존성을 공개 정보에서 발견 → 악성 패키지 게시 → 빌더가 내려받아 프로덕션에서 코드 실행 → 네트워크 스캔 → 자동화 서버로 터널링 → 계정 생성 후 플러그인 취약점으로 AWS 키 획득 → Terraform 상태 파일이 든 S3 버킷에서 관리자 키 확보.

이 위험들이 서로 겹치는 것은 정상임 — 배타적 분류가 아니라 파이프라인 취약점을 훑는 일반 지침이라서 그러함.

두 부분 모두 Lab Design · Information Gathering · Dependency Chain Attack · Compromising the Environment 순으로 진행됨.
