# CI Integration Guide

## GitHub Actions

```yaml
# .github/workflows/security.yml
name: Cairo Security Analysis

on: [push, pull_request]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install shadowhare
        run: cargo install shadowhare --locked

      - name: Build Starknet contracts
        run: scarb build

      - name: Run shadowhare (SARIF output)
        run: |
          shadowhare detect target/dev/ --format sarif > analyzer.sarif
        continue-on-error: true

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: analyzer.sarif
```

## Baseline workflow

```bash
# First time: create a baseline
shadowhare detect target/dev/ --format json > /dev/null
shadowhare update-baseline target/dev/ --baseline .shadowhare-baseline.json
git add .shadowhare-baseline.json
git commit -m "chore: add shadowhare baseline"

# CI: fail only on new findings
shadowhare detect target/dev/ \
  --baseline .shadowhare-baseline.json \
  --fail-on-new-only
```

## Diff workflow (PR vs baseline artifact set)

```bash
# Compare two artifact trees and fail only on new high+ issues
shadowhare detect-diff \
  --left artifacts/mainline \
  --right artifacts/pr \
  --fail-on-new-severity high
```

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No actionable findings |
| 1 | Findings at/above severity threshold |
| 2 | Runtime/config error |

## Scarb.toml configuration

```toml
[tool.shadowhare]
detectors = ["all"]
exclude = ["dead_code"]
severity_threshold = "medium"
baseline = ".shadowhare-baseline.json"
strict = false

[[tool.shadowhare.suppress]]
id = "reentrancy"
location_hash = "a1b2c3d4"  # from --format json output fingerprint
```

## Suppression

To suppress a specific finding, copy its `fingerprint` from the JSON output
into `Scarb.toml`:

```toml
[[tool.shadowhare.suppress]]
id = "felt252_overflow"
location_hash = "ff00aa11"
```

To suppress all findings from a detector:

```toml
[[tool.shadowhare.suppress]]
id = "dead_code"
```
