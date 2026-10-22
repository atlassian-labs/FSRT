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
| 3 | instance-metadata GET route table | 1185/283 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 32.735 | 0.085 | 303 rows (ordinal join) | 19 rows, 18 in groups that still report the TP sink; 1 group lost (see D3) |
| 4 | assets-import hooks and compass admin pages are privileged bindings | 1171/279 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 32.744 | 0.087 | 14 rows (13 ADMIN-ONLY, 1 NO-RESULT) | 0 (no TP group lost) |
| 5 | flow analysis: context-bound reads and unexposed read responses | 1092/263 | 93/74 | 92/44 | 36/36 | 539/539 | 56/29 | 76/16 | 205 | 34.075 | 0.086 | 75 rows (64 context-bound, 11 unexposed); 1 uncertain | 6 rows (5 in groups that keep another operation; 1 group lost: performancesavvy queue consumer) |
| 6 | second tranche of metadata routes; a read's options are not exposure | 1064/257 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 34.331 | 0.085 | 28 rows (all FP) | 0 (no TP row or TP group) |
| 7 | one finding per entry (operations listed in the proof) | 667/257 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 34.174 | 0.084 | 0 operations dropped; 397 findings merged into their entry's finding | 0 (385 TP-bearing entries, 12 uncertain, 268 all-FP, 2 untriaged) |
| 8 | actions no Rovo agent lists are privileged bindings | 659/250 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 34.063 | 0.085 | 8 findings (entries), all FP | 0 |
| 9 | module context content users edit is caller data | 659/250 | 93/74 | 92/44 | 36/36 | 538/538 | 56/29 | 76/16 | 205 | 34.025 | 0.085 | 0 | 0 (guards the TP initiativepicker/field value resolver) |

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

### 3 instance-metadata GET route table
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 1185 findings in 283 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 32.735s, p90 0.085s
Baseline scans: 205 failed, 0 not completed
```

### 4 assets-import hooks and compass admin pages are privileged bindings
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 1171 findings in 279 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 32.744s, p90 0.087s
Baseline scans: 205 failed, 0 not completed
```

### 5 flow analysis: context-bound reads and unexposed read responses
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 1092 findings in 263 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 539 findings in 539 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 34.075s, p90 0.086s
Baseline scans: 205 failed, 0 not completed
```

### 6 second tranche of metadata routes; a read's options are not exposure
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 1064 findings in 257 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 34.331s, p90 0.085s
Baseline scans: 205 failed, 0 not completed
```

### 7 one finding per entry (operations listed in the proof)
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 667 findings in 257 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 34.174s, p90 0.084s
Baseline scans: 205 failed, 0 not completed
```

### 8 actions no Rovo agent lists are privileged bindings
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 659 findings in 250 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 34.063s, p90 0.085s
Baseline scans: 205 failed, 0 not completed
```

### 9 module context content users edit is caller data
```
Unfiltered finding baseline:
  auth-header: 93 findings in 74 app(s)
  authentication: 92 findings in 44 app(s)
  authorization: 659 findings in 250 app(s)
  permission: 36 findings in 36 app(s)
  runtime-version: 538 findings in 538 app(s)
  secret: 56 findings in 29 app(s)
  secret-logging: 76 findings in 16 app(s)
Combined runtime per app: max 34.025s, p90 0.085s
Baseline scans: 205 failed, 0 not completed
```
