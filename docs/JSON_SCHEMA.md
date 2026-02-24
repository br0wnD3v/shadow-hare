# JSON Report Schema (`schema_version = 1.0.0`)

`shadowhare detect --format json` emits a stable, versioned report.
Breaking changes require a schema version bump.

## Top-Level Object

```json
{
  "schema_version": "1.0.0",
  "generated_at": "1708723200",
  "analyzer_version": "0.1.0",
  "sources": ["path/to/artifact.sierra.json"],
  "artifacts": [
    {
      "source": "path/to/artifact.sierra.json",
      "compatibility_tier": "tier3",
      "metadata_source": "unavailable",
      "degraded_reason": "No compiler/sierra version found in artifact..."
    }
  ],
  "findings": [],
  "warnings": [],
  "summary": {
    "total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  }
}
```

Notes:

- `generated_at` is a Unix timestamp string.
- `sources` is the analyzed artifact path list.
- `artifacts` contains per-source compatibility and version-metadata provenance.

## `artifacts[]` Object

```json
{
  "source": "target/dev/contract.sierra.json",
  "compatibility_tier": "tier1",
  "metadata_source": "compiler_version",
  "degraded_reason": null
}
```

Allowed values:

- `compatibility_tier`: `unsupported` | `parse_only` | `tier3` | `tier2` | `tier1`
- `metadata_source`: `compiler_version` | `sierra_version` | `contract_class_version` | `unavailable`

## `findings[]` Object

```json
{
  "detector_id": "u256_underflow",
  "severity": "high",
  "confidence": "medium",
  "title": "Unchecked integer underflow",
  "description": "Function 'withdraw': ...",
  "location": {
    "file": "target/dev/contract.sierra.json",
    "function": "my_contract::withdraw",
    "statement_idx": 42,
    "line": null,
    "col": null
  },
  "fingerprint": "a1b2c3d4e5f60708"
}
```

Field semantics:

- `location.statement_idx`, `location.line`, `location.col` can be `null`.
- `fingerprint` can be omitted for plugin-origin findings that do not provide one.

Allowed values:

- `severity`: `info` | `low` | `medium` | `high` | `critical`
- `confidence`: `low` | `medium` | `high`

## Fingerprint

When present, fingerprint is the first 8 bytes (16 hex chars) of SHA-256 over:

`detector_id:function_name:stmt_idx:file`

It is used for baseline deduplication and diffing.

## `warnings[]` Object

```json
{
  "kind": "IncompatibleVersion",
  "message": "No compiler/sierra version found in artifact — assuming Tier3 best-effort"
}
```

Warnings are non-fatal and become fatal only when strict mode escalates degraded analysis paths.
