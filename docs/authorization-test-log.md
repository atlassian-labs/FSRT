# Authorization scanner: test log

Method for every committed iteration: `cargo test -p fsrt -p forge_analyzer`,
`cargo fmt --all -- --check`, `cargo clippy --workspace`, then
`cargo install --path crates/fsrt --locked` and the corpus scan
(`scan_fsrt.py <rsm-zipped/assets> --timeout 60 --jobs 8`, outputs written under the
task data directory because `--baseline-csv/--baseline-json` are output paths).

Reference corpus run (frozen, binary `993294e`): auth-header 93/74, authentication
92/44, authorization 1507/295, permission 36/36, runtime-version 539/539,
secret 56/29, secret-logging 76/16, 205 failed scans, max app runtime 34.97s,
p90 0.093s.

`FP removed` / `TP removed` are computed by joining the run's authorization
findings with the triage verdicts on (app, finding id), per group; the range is
the lower and upper bound when a group is partly suppressed.

| # | commit | authorization | auth-header | authentication | permission | runtime-version | secret | secret-logging | failed | max s | p90 s | FP removed | TP removed |
|---|--------|---------------|-------------|----------------|------------|-----------------|--------|----------------|--------|-------|-------|------------|------------|
| 0 | base `999d3d1` (captain's branch) | 1550/295 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 32.625 | 0.085 | - | - |
| 1 | boolean-argument branch pruning (captain's WIP) | 1507/295 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 32.544 | 0.086 | 0 triaged (43 untriaged findings) | 0 |
| 2 | request facts + candidate/audit pipeline | 1507/295 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 32.703 | 0.088 | 0 | 0 |

## Iteration tails

### 0 base 999d3d1
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 1550 findings in 295 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 32.625s, p90 0.085s
Baseline scans: 205 failed, 0 not completed
```

### 1 boolean-argument branch pruning
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 1507 findings in 295 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 32.544s, p90 0.086s
Baseline scans: 205 failed, 0 not completed
```

### 2 request facts + candidate/audit pipeline
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 1507 findings in 295 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 32.703s, p90 0.088s
Baseline scans: 205 failed, 0 not completed
```
