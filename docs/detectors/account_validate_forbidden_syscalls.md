# account_validate_forbidden_syscalls

- Detector ID: account_validate_forbidden_syscalls
- Source of truth: shadowhare/docs/RULES.md

## Purpose

Detect side-effectful syscalls inside account validation entrypoints
(`__validate__`, `__validate_declare__`, `__validate_deploy__`).

## Detection Logic

- Identify validation entrypoints by canonical account naming patterns.
- Flag invocations of side-effectful libfunc families in those functions:
  cross-contract calls, deploy, replace-class, L2->L1 messaging, and storage
  writes.

## Severity and Confidence

Refer to `shadowhare list-detectors` for runtime metadata.

## False Positives / False Negatives

- Detection is name-pattern based for validation entrypoints and can miss
  non-standard naming schemes.
- Depending on Starknet version/runtime constraints, some side effects may be
  rejected at execution time; this detector treats them as security/robustness
  risk regardless.

## Recommended Remediation

- Keep validation entrypoints verification-only.
- Move side effects to execution paths guarded by authorization checks.

