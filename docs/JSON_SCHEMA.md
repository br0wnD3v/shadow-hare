# JSON Report Schema (v1.0.0)

The `--format json` output follows this stable schema. Breaking changes bump the major version.

## Top-level structure

```json
{
  "schema_version": "1.0.0",
  "generated_at": "<unix timestamp>",
  "analyzer_version": "0.1.0",
  "sources": ["path/to/artifact.sierra.json"],
  "findings": [...],
  "warnings": [...],
  "summary": {
    "total": 3,
    "critical": 0,
    "high": 2,
    "medium": 1,
    "low": 0,
    "info": 0
  }
}
```

## Finding object

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

## Severity values

`"info"` | `"low"` | `"medium"` | `"high"` | `"critical"`

## Confidence values

`"low"` | `"medium"` | `"high"`

## Fingerprint

8-byte (16 hex char) SHA-256 prefix of `"detector_id:function_name:stmt_idx:file"`.
Used for baseline deduplication. Stable across re-runs of the same artifact.

## Warnings object

```json
{
  "kind": "IncompatibleVersion",
  "message": "Cairo 2.13.0 is Tier3 — some detectors may skip"
}
```
