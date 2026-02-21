# Detector Reference

## u256_underflow

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects subtraction operations on u256 (and other integer types) where the
overflow/underflow flag is structurally not checked.

In Sierra, `u256_overflowing_sub` has two branches: the normal path and the
overflow path. If only one branch (Fallthrough) is present, the underflow case
is never handled.

**False positive rate:** Low. Two-branch subtractions (checked) are not flagged.

**Remediation:** Use `u256_checked_sub` or assert the result is non-overflowing.

---

## unchecked_l1_handler

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects L1 handler functions that do not validate the `from_address` parameter.

L1 handlers receive messages from Ethereum. The `from_address` is the Ethereum
address that sent the message. Without validation, any address can trigger the
handler.

**Remediation:** Check `from_address` against a stored allowed address:
```cairo
assert(from_address == allowed_l1_address, 'Unauthorized L1 sender');
```

---

## reentrancy

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only (conservative)

Detects the classic read-call-write reentrancy pattern:
1. Storage read (balance check)
2. External call (token transfer)
3. Storage write (balance update)

If the external contract calls back before the write, state is inconsistent.

**Remediation:** Use the Checks-Effects-Interactions pattern: write state before
making external calls.

**Suppression:** If the write is intentionally after the call and you have
reentrancy guards, suppress with a location hash in `Scarb.toml`.

---

## felt252_overflow

**Severity:** High
**Confidence:** Low
**Type:** Sierra-only

Arithmetic on `felt252` wraps silently modulo the field prime P. Code that
assumes overflow panics or produces a carry bit is incorrect.

This detector is conservative and may have false positives. Confidence is Low.

**Remediation:** Use typed integers (u256, u128, etc.) where overflow semantics
matter, or add explicit range checks.

---

## controlled_library_call

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects `library_call_syscall` where the class hash is derived from
user-controlled input. An attacker can pass a malicious class hash to execute
arbitrary code in the contract's storage context (equivalent to delegatecall
injection in Solidity).

**Remediation:** Only use hardcoded class hashes or validate against a stored
allowlist before library calls.

---

## tx_origin_auth

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only

Detects authentication using `get_tx_info` (transaction origin) instead of
`get_caller_address`. This is the Starknet equivalent of Ethereum's `tx.origin`
vulnerability.

**Remediation:** Use `get_caller_address()` for access control checks.

---

## unused_return

**Severity:** Low
**Confidence:** High
**Type:** Sierra-only

Return values of invocations that are never referenced in subsequent statements.
This can hide errors when functions return Result or Option types.

---

## dead_code

**Severity:** Info
**Confidence:** Medium
**Type:** Sierra-only (requires debug info for function names)

Functions that are not entry points and are never referenced. May indicate
unused code that can be removed.
