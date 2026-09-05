---
description: /security-check가 git URL에서 받아 둔 클론을 정리한다 (보고서는 남김)
argument-hint: [슬러그 | all]
allowed-tools: Bash, AskUserQuestion
---

# 클론 정리

`/security-check` 가 git URL 로부터 받아 `.secscan/repos/` 에 넣어 둔 클론을 지운다.

## 사전 조건

`.venv/bin/secscan` 이 없으면 **`/secscan-setup` 을 먼저 실행하라고 안내하고 멈춘다.**
(급하면 `python3 -m secscan` 으로도 동작하지만, 스캐너가 갖춰졌는지는 확인되지 않은 상태다.)

## 1단계 — 목록 확인

```bash
.venv/bin/secscan clean --list
```

클론이 없으면 그대로 알리고 끝낸다.

## 2단계 — 대상 확정

- `$ARGUMENTS` 가 `all` 이면 전체 삭제
- `$ARGUMENTS` 가 슬러그면 그것만 삭제
- 비어 있으면 **목록을 보여주고 AskUserQuestion 으로 묻는다** (전체 / 특정 하나 / 취소)

용량을 함께 보여준다 — 사용자가 지울 가치가 있는지 판단할 근거다.

## 3단계 — 삭제

```bash
.venv/bin/secscan clean                 # 전체
.venv/bin/secscan clean --slug <슬러그>  # 하나만
```

`rm -rf` 를 직접 실행하지 말 것. 삭제 범위 검증(`.secscan/repos/` 밖으로 못 나감,
심볼릭 링크 탈출 차단)은 secscan 안에 있다. 경로를 직접 계산하면 그 보호를 우회하게 된다.

## 마무리

**보고서(`out/<슬러그>/`)는 지우지 않는다.** 소스는 사라져도 과거 점검 결과는 남는다.
사용자가 보고서까지 지우길 원하면 그때 별도로 확인받고 지운다.

같은 repo 를 다시 점검하려면 `/security-check <같은 URL>` 로 다시 받으면 된다.
