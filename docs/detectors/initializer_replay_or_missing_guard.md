# initializer_replay_or_missing_guard

- Detector ID: initializer_replay_or_missing_guard
- Source of truth: shadowhare/docs/RULES.md

## Purpose

Detect initializer-like external functions that write storage without an
observable one-time initialization guard.

## Detection Logic

- Select external functions whose names look like initializer paths.
- Find the first storage write in the function.
- Before that write, look for storage-derived value flowing into a guard/check
  libfunc (`assert_eq`, `assert_ne`, `felt252_is_zero`, etc.).
- Flag when no such pre-write guard is observed.

## Severity and Confidence

Refer to `shadowhare list-detectors` for runtime metadata.

## False Positives / False Negatives

- False positives are possible when guard logic exists in helper functions not
  visible in local pre-write flow.
- False negatives are possible for custom guard idioms with uncommon libfuncs.

## Recommended Remediation

- Introduce explicit storage-backed one-time init guards.
- Ensure initialization-only entrypoints cannot be replayed after setup.

