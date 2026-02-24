# CI Integration Guide

Shadowhare CI is split into:

1. SARIF security scanning (`.github/workflows/shadowhare.yml`)
2. Quality gates (`.github/workflows/qa-harness.yml`)

## Security Scanning (SARIF)

Current workflow (`shadowhare.yml`) runs the official GitHub Action:

```yaml
name: Shadowhare Scan
on: [push, pull_request]

jobs:
  shadowhare:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - name: Run Shadowhare
        uses: shadowhare/action@v1
        with:
          paths: target/dev
          format: sarif
          min_severity: medium
          output: shadowhare-results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: shadowhare-results.sarif
```

Equivalent local command:

```bash
shadowhare detect target/dev --format sarif --min-severity medium > shadowhare-results.sarif
```

## Quality Gates (QA Harness + Metadata Regression)

Current workflow (`qa-harness.yml`) enforces:

1. Detector docs quality lint:
   - `python3 scripts/docs_lint.py`
2. QA precision/recall gates:
   - `python3 scripts/qa_harness.py --enforce-gates --output-json corpus/qa_harness_report_ci.json`
3. Compatibility metadata regression:
   - `python3 scripts/compatibility_inventory.py --output-json corpus/metadata/compatibility_inventory_ci.json --baseline corpus/metadata/compatibility_inventory_baseline.json --enforce-no-regression`

This workflow uploads:

- `corpus/qa_harness_report_ci.json`
- `corpus/metadata/compatibility_inventory_ci.json`

## Baseline Workflow (Finding Diff)

```bash
# Create baseline
shadowhare update-baseline target/dev --baseline .shadowhare-baseline.json

# Fail only on findings that are new vs baseline
shadowhare detect target/dev \
  --baseline .shadowhare-baseline.json \
  --fail-on-new-only
```

## Artifact-to-Artifact Diff Workflow

```bash
shadowhare detect-diff \
  --left artifacts/mainline \
  --right artifacts/pr \
  --fail-on-new-severity high
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No actionable findings |
| 1 | Findings at/above threshold (or new findings in diff/baseline mode) |
| 2 | Runtime/config/usage error |

## Scarb.toml Configuration

```toml
[tool.shadowhare]
detectors = ["all"]
exclude = ["dead_code"]
severity_threshold = "medium"
baseline = ".shadowhare-baseline.json"
strict = false

[[tool.shadowhare.suppress]]
id = "reentrancy"
location_hash = "a1b2c3d4"  # finding fingerprint
```

## Suppression

Suppress one concrete finding:

```toml
[[tool.shadowhare.suppress]]
id = "felt252_overflow"
location_hash = "ff00aa11"
```

Suppress all findings for one detector:

```toml
[[tool.shadowhare.suppress]]
id = "dead_code"
```
