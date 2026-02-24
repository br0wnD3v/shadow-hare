# account_execute_missing_v0_block

- Detector ID: account_execute_missing_v0_block
- Source of truth: shadowhare/docs/RULES.md

## Purpose

Detect account `__execute__` paths that do not show an observable transaction
version guard against legacy invoke-v0 execution.

## Detection Logic

- Identify account execute entrypoints (`__execute__` naming patterns).
- Track `get_tx_info` / `get_execution_info` flow and guard-like comparisons.
- Fold helper-call behavior through `function_call` edges.
- Report execute paths with no observed v0-blocking guard signal.

## Severity and Confidence

Refer to `shadowhare list-detectors` for runtime metadata.

## False Positives / False Negatives

- Guard detection is heuristic; uncommon helper naming or custom guard idioms
  can lead to misses.
- Generic tx-info comparisons may be treated as a guard signal even if they are
  not strictly version checks.

## Recommended Remediation

- Add an explicit transaction version check in execute flow.
- Reject legacy invoke-v0 requests before executing external calls.
