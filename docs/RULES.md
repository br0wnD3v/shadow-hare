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

## deploy_syscall_tainted_class_hash

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects deploy/factory paths where `deploy_syscall` receives a class hash that
is dataflow-derived from external input.

Without allowlisting, attackers can deploy arbitrary implementations through
your factory/deployer entrypoint.

**Remediation:** Gate class hash selection with authorization and a trusted
allowlist (storage-backed or constants).

---

## account_interface_compliance

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects account-like contracts that expose an incomplete SRC6-style interface
surface (missing core account methods or protocol validation hooks).

Core expectations include `__execute__`, `__validate__`,
`is_valid_signature`, and `supports_interface`, plus protocol validation hooks
for declare/deploy account flows.

**Remediation:** Implement full account interface coverage and ensure all
validation hooks are present and wired.

---

## account_validate_forbidden_syscalls

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects side-effectful syscalls in account validation entrypoints
(`__validate__`, `__validate_declare__`, `__validate_deploy__`), such as deploy,
replace-class, cross-contract calls, L2->L1 messaging, or storage writes.

Validation should remain verification-only.

**Remediation:** Move side effects to execution paths; keep validation pure.

---

## account_execute_missing_v0_block

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects account `__execute__` paths where no observable transaction-version
guard is present to reject legacy invoke-v0 execution.

The detector is inter-procedural over helper calls and treats tx-info flow
without guard-like compares/asserts as risky.

**Remediation:** Add an explicit transaction version guard in execute flow and
reject legacy invoke-v0 requests before executing calls.

---

## initializer_replay_or_missing_guard

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects initializer-like external functions that write storage without an
observable one-time storage-backed guard before the first write.

This often indicates a re-invocable initializer that can overwrite privileged
configuration after deployment.

**Remediation:** Read an initialization flag from storage and enforce a strict
single-use guard before writing state.

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

---

## unprotected_upgrade

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects `replace_class_syscall` reachable from an external surface without an
observable owner/admin authorization check.

Without an explicit access-control gate, any caller can upgrade the contract to
arbitrary code.

**Remediation:** Restrict upgrade entry points to privileged roles and validate
authorization before calling `replace_class_syscall`.

---

## unchecked_integer_overflow

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects integer arithmetic on fixed-width types (`u128/u64/u32/u16/u8`) where
only the success branch is handled and the overflow branch is discarded.

This can silently produce incorrect accounting/state transitions.

**Remediation:** Use checked arithmetic patterns and handle overflow branches
explicitly.

---

## integer_truncation

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects `u256_to_felt252`-style narrowing without a preceding fit/range check.
High bits are discarded when the source value exceeds the felt range.

**Remediation:** Validate upper limbs/range before narrowing, or keep values in
wide integer types where precision is required.

---

## unchecked_address_cast

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects fallible address/class-hash casts where only one branch is present.
Invalid-input handling is missing, so malformed user input can become zero or
garbage addresses.

**Remediation:** Handle the failure branch and reject invalid conversions.

---

## unchecked_array_access

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects array `pop/get`-style operations with no empty/out-of-bounds handling.
If attacker-controlled inputs can drive array size/index, this can panic or
cause undefined behavior.

**Remediation:** Enforce bounds/emptiness checks before access.

---

## oracle_price_manipulation

**Severity:** High
**Confidence:** Low
**Type:** Sierra-only (heuristic)

Detects flows where an external call result is written directly to storage
without sanity checks (bounds, freshness, source validation, medianization).

This can enable manipulated price/state writes and downstream accounting fraud.

**Remediation:** Validate oracle responses before storage writes and apply
domain-appropriate guards (bounds/deviation windows/staleness checks).

---

## missing_nonce_validation

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects account execution paths with no observable nonce storage update.
Without nonce consumption, equivalent transactions can be replayed.

**Remediation:** Read/validate and increment nonce in execution flow.

---

## signature_replay

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only (inter-procedural heuristic)

Detects signature/validation flows that appear to verify transaction data
without nonce-backed replay protection.

If signatures are accepted repeatedly, signed payloads can be replayed.

**Remediation:** Bind signatures to nonce/domain-separated message hashes and
consume nonce state on acceptance.

---

## arbitrary_token_transfer

**Severity:** High
**Confidence:** Low
**Type:** Sierra-only (heuristic)

Detects transfer-from style token movement where `from` appears user-controlled
and no caller/ownership guard is observed.

**Remediation:** Require explicit authorization for third-party transfer paths
and validate caller rights before token movement.

---

## write_without_caller_check

**Severity:** High
**Confidence:** Low
**Type:** Sierra-only (heuristic)

Detects external functions that write storage without an observable caller check
and without prior state-read guard patterns.

This can expose unrestricted state mutation.

**Remediation:** Add explicit access-control checks before privileged writes.

---

## l1_handler_unchecked_amount

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects L1-handler flows where payload-derived amount values are used in
arithmetic/external effects without a preceding bounds/state-backed check.

If the L1 side is compromised or misconfigured, this can enable unbounded mint
or accounting manipulation on L2.

**Remediation:** Validate payload amount against trusted state/config and apply
strict bounds checks before effectful operations.

---

## l1_handler_payload_to_storage

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects raw L1 payload values persisted directly into storage slots.

Writing unvalidated cross-domain payload data to storage can overwrite critical
state such as admin/config/rate variables.

**Remediation:** Parse and validate payload schema/semantics before storage
writes; isolate payload handling to constrained, typed update logic.

---

## l1_handler_unchecked_selector

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects selector injection in L1 handlers: payload data is used as dynamic
function selector in `call_contract_syscall`.

This allows attacker-controlled cross-domain messages to invoke arbitrary
target functions.

**Remediation:** Never derive call selectors directly from payload; enforce a
fixed selector set/dispatch table with explicit validation.

---

## l2_to_l1_tainted_destination

**Severity:** High
**Confidence:** High
**Type:** Sierra-only

Detects `send_message_to_l1_syscall` where destination address is derived from
user-controlled parameters.

Attackers can redirect bridge/oracle/governance messages to arbitrary L1
destinations.

**Remediation:** Use trusted destination configuration (constants/storage
allowlist), not untrusted runtime input.

---

## l2_to_l1_unverified_amount

**Severity:** High
**Confidence:** Medium
**Type:** Sierra-only

Detects L2->L1 message payload amounts sourced directly from parameters without
state-backed verification.

Unverified claimed amounts can enable fraudulent claims/withdrawals on L1.

**Remediation:** Derive bridged amounts from verified on-chain state and enforce
balance/accounting checks before emitting messages.

---

## divide_before_multiply

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only

Detects arithmetic order where integer division result is multiplied later.
Truncation loss from division is amplified by subsequent multiplication.

**Remediation:** Reorder as multiply-first-then-divide when safe, or use fixed
point/rational math with explicit precision handling.

---

## tainted_storage_key

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only

Detects user-controlled input flowing into
`storage_base_address_from_felt252`/related raw key construction.

This can expose arbitrary-slot read/write patterns and privileged state
tampering.

**Remediation:** Construct storage addresses from trusted base+offset mapping
patterns; avoid raw felt-derived storage keys from untrusted input.

---

## hardcoded_address

**Severity:** Medium
**Confidence:** High
**Type:** Sierra-only

Detects hardcoded contract addresses used as external call targets.

Hardcoded endpoints become brittle after upgrades/migrations and can pin logic
to deprecated infrastructure.

**Remediation:** Move target addresses into validated mutable config with secure
admin update paths.

---

## block_timestamp_dependence

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only

Detects security-critical comparisons/logic driven by block timestamp/number.

Sequencer control over timestamp bounds makes deadline/randomness/security
decisions manipulable.

**Remediation:** Avoid timestamp-based authorization/randomness; use stronger
stateful constraints and delay windows where timing checks are unavoidable.

---

## unchecked_transfer

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only

Detects token transfer-style calls whose return value is ignored.

Silent transfer failure can desynchronize accounting and business logic.

**Remediation:** Check transfer return status (or explicit success condition)
and abort on failure.

---

## multiple_external_calls

**Severity:** Medium
**Confidence:** Low
**Type:** Sierra-only (heuristic)

Detects external functions that perform many external calls and also write
storage, increasing reentrancy and failure-surface complexity.

**Remediation:** Minimize external call count per execution path, sequence
state updates safely, and use explicit reentrancy protections.

---

## view_state_modification

**Severity:** Medium
**Confidence:** High
**Type:** Sierra-only

Detects view-like/read-only surfaces that perform `storage_write_syscall`.

This violates read-only expectations and can create integration/audit blind
spots.

**Remediation:** Keep view/read APIs side-effect free; move writes to explicit
state-mutating entry points.

---

## rtlo

**Severity:** High
**Confidence:** High
**Type:** Sierra-only (symbol/debug-name scan)

Detects Unicode bidirectional control characters in function/libfunc symbol
names (Trojan-Source style visual spoofing risk).

These characters can reorder visible text and hide malicious intent during
review.

**Remediation:** Remove bidi control characters from symbols/build artifacts and
enforce ASCII-safe naming in CI.

---

## weak_prng

**Severity:** Medium
**Confidence:** Low
**Type:** Sierra-only (heuristic dataflow)

Detects env-derived values (`get_block_*`, `get_execution_info`) flowing into
randomness-like arithmetic or effectful sinks (`call_contract`,
`send_message_to_l1`, felt arithmetic).

Block/sequencer metadata is predictable and not secure entropy.

**Remediation:** Use robust randomness design (commit-reveal/VRF/beacon), and
avoid deriving security decisions from block metadata.

---

## pyth_unchecked_confidence

**Severity:** Medium
**Confidence:** Low
**Type:** Sierra-only (keyword-based heuristic)

Detects external flows that read Pyth prices but show no observable confidence
interval check before value use.

This can accept low-quality oracle updates and degrade price safety.

**Remediation:** Enforce explicit confidence bounds before using fetched prices.

---

## pyth_unchecked_publishtime

**Severity:** Medium
**Confidence:** Low
**Type:** Sierra-only (keyword-based heuristic)

Detects unbounded Pyth price reads (non-`no_older_than`) with no observable
freshness/publish-time validation.

Stale oracle values can be exploited for mispricing.

**Remediation:** Require freshness checks (`max_age`/publish-time validation) on
all consumed prices.

---

## pyth_deprecated_function

**Severity:** Medium
**Confidence:** High
**Type:** Sierra-only

Detects deprecated/unsafe Pyth API usage patterns (for example
`get_price_unsafe`, `get_ema_price_unsafe`, deprecated function markers).

These APIs bypass bounded freshness expectations and increase oracle misuse
risk.

**Remediation:** Migrate to bounded, freshness-aware Pyth access paths.

---

## tautological_compare

**Severity:** Medium
**Confidence:** High
**Type:** Sierra-only

Detects self-comparisons (same value on both sides) in equality/assert-like
operations.

This creates constant conditions (always true or always false) and often
indicates broken validation or dead logic.

**Remediation:** Compare against intended independent values; remove accidental
self-comparisons.

---

## tautology

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only (heuristic)

Detects condition-like operations driven by boolean constants, making branches
effectively always-taken or never-taken.

This can hide dead branches and invalid guard assumptions.

**Remediation:** Replace constant-driven control with real runtime predicates or
remove unreachable branches.

---

## unchecked_l1_message

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only

Detects external functions that send L2->L1 messages without observable caller
verification (`get_caller_address`/execution-info based checks).

Unrestricted callers can trigger arbitrary L1-side effects or spam bridge
message queues.

**Remediation:** Enforce explicit access control before `send_message_to_l1`.

---

## incorrect_erc20_interface

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only (best-effort symbol-set heuristic)

Detects token-like external symbol sets that appear to implement inconsistent or
incomplete ERC20/SNIP interface surfaces.

Current checks are name-based and require a minimum token-like method footprint
before validating core methods and return-shape expectations.

**Remediation:** Align exposed token ABI to the intended ERC20/SNIP interface,
including required core methods and return conventions.

---

## incorrect_erc721_interface

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only (best-effort symbol-set heuristic)

Detects NFT-like external symbol sets that appear to implement inconsistent or
incomplete ERC721 interface surfaces.

Current checks are name-based and validate core method presence plus basic
return-shape expectations.

**Remediation:** Align exposed NFT ABI to intended ERC721 behavior, including
core ownership/transfer methods.

---

## boolean_equality

**Severity:** Info
**Confidence:** High
**Type:** Sierra-only

Detects equality/assert-style comparisons where one operand is a tracked boolean
constant (`bool_const` / `bool_true` / `bool_false`) and the other operand is a
non-constant boolean value.

This is usually equivalent to direct condition usage and increases logic noise.

**Remediation:** Replace explicit `== true/false` comparisons with direct or
negated boolean expressions.

---

## cache_array_length

**Severity:** Info
**Confidence:** Medium
**Type:** Sierra-only (loop/back-edge + fallback heuristic)

Detects repeated `array_len`/`span_len` lookups inside loop ranges.

Primary signal is a loop back-edge enclosing 2+ length lookups. A fallback
heuristic flags functions with repeated length lookups plus loop-like
control-flow.

**Remediation:** Cache length before entering the loop and reuse the cached
value.

---

## calls_loop

**Severity:** Low
**Confidence:** Medium
**Type:** Sierra-only (loop/back-edge + fallback heuristic)

Detects external/library calls (`call_contract*` / `library_call*`) inside loop
bodies of external functions.

Repeated external calls inside loops amplify reentrancy and failure/gas surface.

**Remediation:** Avoid unbounded external calls in loops; batch work or cap loop
size and enforce safe call ordering.

---

## costly_loop

**Severity:** Info
**Confidence:** Medium
**Type:** Sierra-only (loop/back-edge + fallback heuristic)

Detects storage read/write operations inside loop ranges.

Primary signal is a back-edge enclosing storage access; fallback flags
loop-like control-flow with storage access in the same function.

**Remediation:** Hoist invariant reads, reduce per-iteration storage access, or
refactor state updates.

---

## l2_to_l1_double_send

**Severity:** Medium
**Confidence:** Medium
**Type:** Sierra-only

Detects external functions that call `send_message_to_l1*` two or more times in
one execution path.

This often indicates duplicate cross-domain effects (double processing or fee
waste), unless intentionally multi-message by design.

**Remediation:** Ensure one semantic action emits one message, or explicitly
document and guard intentional multi-message behavior.

---

## missing_event_emission

**Severity:** Low
**Confidence:** Medium
**Type:** Sierra-only

Detects external functions (excluding constructor-like names) that perform
storage writes but emit no event.

Missing events reduce observability for indexers, monitors, and off-chain
integrations.

**Remediation:** Emit explicit events for externally triggered state changes.

---

## missing_events_access_control

**Severity:** Low
**Confidence:** Medium
**Type:** Sierra-only (structural guard heuristic)

Detects external functions where:
1. A caller/storage-derived authorization guard appears before first write.
2. Storage mutation is present.
3. No `emit_event` is present.

This targets privileged-like state updates that become hard to audit off-chain.

**Remediation:** Emit an event when privileged configuration/state is changed.

---

## missing_events_arithmetic

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only (dataflow heuristic)

Detects arithmetic-derived values written to storage without event emission.

The detector tracks arithmetic-origin variables and flags writes using those
values when no event is emitted in the same external function.

**Remediation:** Emit domain-relevant events for arithmetic/accounting updates.

---

## missing_zero_address_check

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only (taint + guard heuristic)

Detects external `ContractAddress` parameters flowing into external call targets
without observable zero-address validation.

Signals include explicit zero-check libfuncs and guard-like branching before
sink; absent those signals, tainted target usage is flagged.

**Remediation:** Validate target addresses (including zero-address rejection)
before `call_contract*` usage.

---

## reentrancy_events

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only

Detects ordering pattern in external functions:
1. External/library call
2. Event emission
3. Storage write

If reentrancy occurs between call and write, emitted events may not match final
state transitions.

**Remediation:** Prefer committing state before external calls, or emit events
after safe state finalization.

---

## shadowing_builtin

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only (symbol-name heuristic)

Detects external function leaf names that exactly match known Cairo builtin
names (for example `pedersen`, `poseidon`, `range_check`, `system`).

This is a readability/auditability issue rather than direct runtime exploit.

**Remediation:** Rename entrypoints to domain-specific names that avoid builtin
name collisions.

---

## shadowing_local

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only (symbol-path heuristic)

Detects repeated adjacent segments in debug symbol paths (for example
`foo::foo::bar`), which suggests local naming shadowing.

This primarily increases review confusion and maintenance cost.

**Remediation:** Normalize module/function naming to avoid repeated adjacent
segments.

---

## shadowing_state

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only (symbol collision heuristic)

Detects function leaf names colliding with type/state-like symbol leaf names in
the same program.

Name collisions can obscure intent in reviews and increase misread risk.

**Remediation:** Rename functions or types to make state/API boundaries
unambiguous.

---

## unindexed_event

**Severity:** Info
**Confidence:** Medium
**Type:** Sierra-only (array-state heuristic)

Detects `emit_event` calls where the keys/index array appears empty.

The detector tracks empty-array constructors and append operations to infer
whether emitted keys were populated.

**Remediation:** Include meaningful indexed keys for event filtering and
monitoring.

---

## unused_state

**Severity:** Info
**Confidence:** High
**Type:** Sierra-only

Detects storage reads whose produced values are never consumed as inputs by
subsequent invocations in the same function.

This usually indicates redundant state loading or incomplete logic.

**Remediation:** Remove unused reads or wire loaded state into intended checks.

---

## write_after_write

**Severity:** Low
**Confidence:** Low
**Type:** Sierra-only

Detects consecutive storage writes in external functions with no intervening
storage read.

Later writes may unintentionally overwrite earlier transitions and hide logic
errors.

**Remediation:** Revisit write ordering and intermediate reads/assertions to
confirm intended final state.
