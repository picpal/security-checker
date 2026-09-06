# V7 실행 노트 (2026-09-06)

- `SCRATCH=/private/tmp/secscan-verify` (플랜 1 과 동일 루트, `-v7` 아님 — Ruling L). `prepare_snapshot` 이
  `<scratch>/<sha>/repo` 를 매 스냅샷마다 새로 clone 하므로 격리는 유지된다. `a483b3b1/gradle-home` 과
  depscan 슬라이스 캐시(`a483b3b1/reach/9b78b0a3cb422e72/java-usages.slices.json`, 플랜 1에서 콜드
  depscan 이 엔진 예산 내 실패해 수동으로 미리 생성해 둔 것)는 재사용한다.
- trivy DB 상태(실행 직전 확인, `trivy --version`): Vulnerability DB `NextUpdate: 2026-09-06 01:12:13 UTC`,
  Java DB `NextUpdate: 2026-09-08 01:05:40 UTC`. 실행 시각(`date -u`) `2026-09-05 15:16:06 UTC` — 둘 다
  아직 유효(NextUpdate 미도래). `trivy image --download-db-only` 재실행 불필요.
- 최종 실스캔(`tools.verify.run_snapshot`, a483b3b1/standard)은 재사용된 `scratch/a483b3b1/repo`
  체크아웃(HEAD 일치 검증 통과, Ruling L)에 대해 1회에 성공(`elapsed_s=156.9`, `partial=[]`,
  `findings=73`). `raw/bom.cdx.json`은 `write_evidence`가 자동으로 쓰지 않는다(플랜 1
  `e97009a` 와 동일한 수동 보존 단계가 여전히 필요) — `secscan.sbom.ensure_bom`의 코드 해시 캐시
  (`$TMPDIR/secscan-bom/<hash>/bom.json`, 대상 경로 `scratch/a483b3b1/repo`의 resolve() 해시)에서
  찾아 `raw/bom.cdx.json`으로 복사했다. 이 캐시 항목은 같은 체크아웃 재사용으로 이전(2026-09-05
  04:10 KST)에 생성된 것이 그대로 재사용되었다 — 같은 커밋 sha·같은 소스이므로 cdxgen BOM 내용은
  동일하며, trivy sbom 은 이번 실행에서 그 BOM 에 대해 새로 실행되었다(`raw/trivy.json` 은
  2026-09-06 신규 산출).
