# account_interface_compliance

- Detector ID: account_interface_compliance
- Source of truth: shadowhare/docs/RULES.md

## Purpose

Detect account-like contracts that expose an incomplete SRC6-style account
interface surface.

## Detection Logic

- Identify account-like contracts from account entrypoint naming markers.
- Check presence of core account methods:
  `__execute__`, `__validate__`, `is_valid_signature`, `supports_interface`.
- Check protocol validation hooks:
  `__validate_declare__`, `__validate_deploy__`.
- Report when any required method/hook is missing.

## Severity and Confidence

Refer to `shadowhare list-detectors` for runtime metadata.

## False Positives / False Negatives

- Name-based detection can miss highly custom naming conventions.
- Non-account contracts with account-like naming may trigger if they expose
  enough account markers.

## Recommended Remediation

- Implement the full SRC6-style external account surface.
- Ensure deploy/declare validation hooks are present and wired.
