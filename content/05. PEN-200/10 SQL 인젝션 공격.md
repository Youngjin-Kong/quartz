---
tags:
  - type/theory
  - platform/pen200
type: theory
platform: pen200
source: pen-200.pdf
section: "10"
---

# 10 SQL 인젝션 공격

> **SQL Injection Attacks** · PEN-200 §10

SQL 인젝션(SQL injection, SQLi) — 웹 애플리케이션과 데이터베이스가 주고받는 SQL 질의에 공격자가 끼어드는 취약점 부류. OWASP Top 10 3위(`A03:2021-Injection`).

핵심은 **원래 질의의 확장**임 — 정상 경로로는 손댈 수 없는 테이블·컬럼까지 질의 범위에 끌어들이는 것.

이 모듈이 다루는 것 — SQL 이론과 DB 유형별 문법 차이, 수동 익스플로잇(오류 기반·UNION·블라인드), 코드 실행과 자동화.
