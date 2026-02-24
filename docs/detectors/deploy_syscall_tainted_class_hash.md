# deploy_syscall_tainted_class_hash

- Detector ID: deploy_syscall_tainted_class_hash
- Source of truth: shadowhare/docs/RULES.md

## Purpose

Detect external deploy/factory paths where `deploy_syscall` receives a class hash
derived from user-controlled input.

## Detection Logic

- Seed taint from external function parameters.
- Track class-hash constants from `class_hash_const`.
- Flag `deploy`/`deploy_syscall` when class-hash argument is tainted and not
  recognized as a constant-derived value.

## Severity and Confidence

Refer to `shadowhare list-detectors` for runtime metadata.

## False Positives / False Negatives

- False positives are possible when class hash is user-supplied but validated
  through complex helper call chains not visible in local taint flow.
- False negatives are possible if deploy wrappers use uncommon libfunc naming.

## Recommended Remediation

- Restrict deployable class hashes via storage-backed allowlist or hardcoded
  trusted constants.
- Apply explicit authorization around class-hash selection.

