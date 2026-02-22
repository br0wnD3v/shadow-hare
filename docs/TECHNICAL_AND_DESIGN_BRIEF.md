# Technical Breakdown

## 1. Product Definition and Scope

`shadowhare` is a static analyzer for Starknet smart contracts that runs on **compiled Sierra artifacts** (`.sierra.json` and `.contract_class.json`), not Cairo source code.

Primary purpose:
- Detect exploit-prone patterns before deployment.
- Gate CI/CD with deterministic findings and baseline diffing.
- Export machine-consumable output for security automation (JSON, SARIF).

Core architecture claim (as implemented): load artifact -> normalize to internal IR -> run detector registry in parallel -> filter/suppress/baseline -> render output.

## 2. Runtime Architecture and Execution Flow

Entry points:
- CLI binaries: `shadowhare`, `shdr` (`src/main.rs`).
- Scarb wrappers: `scarb-shadowhare`, `scarb-shdr` (`src/scarb_main.rs`).
- Library API: `analyse_paths`, `render_output`, `update_baseline` (`src/lib.rs`).

Pipeline:
1. Resolve input artifact paths (`resolve_artifacts` for directories; recursive).
2. Load each artifact (`load_artifact`) and detect format:
   - Raw Sierra JSON.
   - Starknet contract class JSON.
3. Negotiate compatibility tier.
4. Convert loaded artifact to `ProgramIR`.
5. Run detector registry with rayon parallelism.
6. Apply suppressions and severity threshold.
7. Optionally compare with baseline fingerprints.
8. Render output as human, JSON, or SARIF.

Exit codes:
- `0`: no relevant findings.
- `1`: findings found (or new findings if `--fail-on-new-only`).
- `2`: runtime/config failures.

## 3. Artifact Loading and IR Normalization

Loader (`src/loader/sierra_loader.rs`) supports:
- Raw Sierra serde structures.
- Contract class decode via `cairo-lang-starknet-classes` (`extract_sierra_program(false)`), then conversion into local normalized types.

Normalized program model:
- Type declarations.
- Libfunc declarations.
- Statements (`Invocation` or `Return`).
- Functions (signature, params, entry point).
- Entry points (`external`, `l1_handler`, `constructor`).

Notable implementation details:
- `SierraId` supports numeric IDs, debug-name IDs, or both.
- Contract-class debug info is used to rehydrate function/libfunc/type names when available.
- File discovery for directories only accepts `*.sierra.json` and `*.contract_class.json`.

## 4. Compatibility Model

Compatibility tier model (`src/loader/version.rs`):
- `Tier1`: ~2.16
- `Tier2`: ~2.15
- `Tier3`: ~2.14
- `ParseOnly`: older 2.x
- `Unsupported`: non-2.x

Behavior:
- `Unsupported` throws an error.
- `ParseOnly` and lower: detector execution is skipped in `analyse_paths`.
- Tier warnings are surfaced in report warnings.

Important current behavior:
- Version negotiation reads `compiler_version` or `sierra_version`.
- `contract_class_version` is populated but currently not used in negotiation.
- Result: many contract-class artifacts can fall back to Tier3 warning mode unless other version fields are present.

## 5. ProgramIR and Function Classification

`ProgramIR` (`src/ir/program.rs`) provides:
- Source path.
- Compatibility tier and debug-info presence.
- Type/libfunc registries.
- Classified function metadata.
- Full statement vector and helper iterators/ranges.

Function kind classification (`src/ir/function.rs`):
- `External`, `L1Handler`, `Constructor`, `Internal`, `View`.
- Uses explicit entry-point metadata when available.
- Falls back to debug-name heuristics in raw Sierra mode.

## 6. Analysis Primitives

Reusable analysis modules:
- CFG builder (`analysis/cfg.rs`): leader-based basic-block construction and predecessor mapping.
- Forward dataflow engine (`analysis/dataflow.rs`): fixed-point block analysis.
- Taint propagation (`analysis/taint.rs`): variable taint sets across invocations.
- Storage/call scanners (`analysis/storage.rs`): find storage reads/writes and external calls.
- Reentrancy evidence extraction (`analysis/reentrancy.rs`): read -> external call -> write pattern.

Scope limitation:
- Analysis is mostly intra-function and heuristic.
- No full path-sensitive, interprocedural, or symbolic execution engine.

## 7. Detector Engine

Detector registry and finding model (`src/detectors/mod.rs`):
- Trait-based detectors with `id`, `severity`, `confidence`, `description`, `requirements`, `run`.
- Parallel execution using rayon.
- Deterministic final finding sort order: severity desc, detector ID, fingerprint.

Filtering and suppression:
- `--min-severity` threshold applied after detector run.
- Suppression supports detector-wide or detector+fingerprint targeting.

Finding fingerprint:
- 8-byte SHA-256 prefix (16 hex chars).
- Input string: `detector_id:function_name:statement_idx:file`.
- Stable for same artifact/path and statement mapping.

## 8. Full Implemented Detector Catalog (Registry Truth)

The current code registry contains 29 detectors:

| Detector ID | Severity | Confidence | Core Pattern |
|---|---|---|---|
| `u256_underflow` | High | Medium | Overflowing subtraction with only one branch (unchecked underflow path). |
| `unchecked_l1_handler` | High | High | L1 handler where inferred `from_address` is never validated. |
| `reentrancy` | High | Medium | Storage read -> external call -> storage write in entrypoint flow. |
| `felt252_overflow` | High | Low | Tainted felt252 arithmetic without observed range-check pattern. |
| `controlled_library_call` | High | Medium | Tainted/user-controlled class hash reaches `library_call*`. |
| `unprotected_upgrade` | High | Medium | `replace_class*` in external function without apparent owner/storage-backed check. |
| `unchecked_integer_overflow` | High | High | Bounded integer overflow ops with no overflow branch handling. |
| `integer_truncation` | High | High | `u256_to_felt252` lossy cast flagged as unsafe conversion site. |
| `unchecked_address_cast` | High | High | Fallible address/hash cast with single branch (failure path ignored). |
| `unchecked_array_access` | High | High | Fallible array pop/get with single branch (none/oob case ignored). |
| `oracle_price_manipulation` | High | Low | External call result stored directly without transformation/validation. |
| `missing_nonce_validation` | High | Medium | `__execute__` entrypoint without storage write (nonce increment missing). |
| `write_without_caller_check` | High | Low | External storage write without caller check and without storage read context. |
| `l2_to_l1_tainted_destination` | High | High | L2->L1 destination address tainted by user parameters. |
| `l1_handler_unchecked_amount` | High | Medium | L1 payload amount used in arithmetic/call/storage without bounds comparison. |
| `l1_handler_payload_to_storage` | High | Medium | Raw L1 payload taint reaches storage write value. |
| `l1_handler_unchecked_selector` | High | High | L1 payload taint controls `call_contract` selector argument. |
| `l2_to_l1_unverified_amount` | High | Medium | L2->L1 payload amount tainted by params with no storage-read evidence. |
| `tx_origin_auth` | Medium | Medium | `get_tx_info`/`get_execution_info` taint used in auth-like checks. |
| `divide_before_multiply` | Medium | Medium | Division result reused in multiplication (precision-loss pattern). |
| `tainted_storage_key` | Medium | Medium | User taint reaches storage key argument in storage read/write syscall. |
| `hardcoded_address` | Medium | High | Constant-derived call target in `call_contract*`. |
| `block_timestamp_dependence` | Medium | Medium | Block info taint reaches comparison/auth/deadline-like checks. |
| `multiple_external_calls` | Medium | Low | >=3 external calls plus storage write in one external function. |
| `unchecked_l1_message` | Medium | Medium | External function sends L1 message without caller verification signal. |
| `l2_to_l1_double_send` | Medium | Medium | Multiple `send_message_to_l1` invocations in one function. |
| `unused_return` | Low | High | Invocation result variables never consumed later. |
| `missing_event_emission` | Low | Medium | External state mutation without event emission. |
| `dead_code` | Info | Medium | Non-entrypoint function appears unreferenced (debug-name heuristic). |

## 9. Output and Integration Contracts

Human output:
- Per-finding blocks with detector, confidence, location, fingerprint, description.
- Summary by severity.
- Warning section.

JSON output (`schema_version = 1.0.0`):
- `schema_version`, `generated_at`, `analyzer_version`, `sources`, `findings`, `warnings`, `summary`.

SARIF output:
- Version `2.1.0`.
- Severity mapping: critical/high -> `error`, medium -> `warning`, low/info -> `note`.
- Includes rule metadata, logical location (function), optional region.

CI integration:
- Suitable for GitHub SARIF upload.
- Baseline workflow supports failing only on newly introduced findings.

## 10. Baseline and Suppression Mechanics

Baseline file (`.shadowhare-baseline.json` default):
- `schema_version`.
- Set of finding fingerprints.

Behavior:
- `update-baseline` overwrites fingerprint set with current findings.
- `--fail-on-new-only` compares current findings to baseline set.

Suppression model (Scarb):
- `id` only: suppress all findings for detector.
- `id` + `location_hash`: suppress specific fingerprint.

## 11. Configuration and CLI/Scarb Merge

Supported config tables:
- Preferred: `[tool.shadowhare]`.
- Backward-compatible fallback: `[tool.analyzer]`.

Merge precedence:
- Scarb config loads first.
- CLI flags overwrite config fields.

Supported knobs:
- Detector include/exclude selection.
- Severity threshold.
- Baseline path.
- Fail-on-new-only.
- Suppressions.
- Strict flag (present in config/CLI model).

Scarb wrapper behavior:
- Injects manifest from `SCARB_MANIFEST_PATH` when not supplied.
- Injects target artifacts path from `SCARB_TARGET_DIR/SCARB_PROFILE` when absent.

## 12. Test Coverage and Quality Signals

Test modules:
- `compatibility_matrix.rs`: tier and loose-version parsing behavior.
- `sarif_schema.rs`: SARIF structure, severity mapping, rule dedupe, locations.
- `detector_golden.rs`: golden checks for fixtures, fingerprint stability, output validity, contract-class decode non-emptiness.

Fixture strategy:
- Local fixtures for core scenarios (`fixtures/clean`, `fixtures/vulnerable`).
- Seeded fixtures under `../target_contracts/seeded` used for broad detector assertions.

## 13. Current Gaps and Product Truth Notes

Implementation-level observations that matter for roadmap and messaging:
- README and `list-detectors` command still describe only 8 detectors, while registry has 29.
- `strict` is wired in config/CLI but not used by detector/loader logic today.
- `DetectorRequirements.requires_debug_info` is defined but not enforced in registry filtering (only `source_aware` is checked).
- Warning constructors for `MissingDebugInfo`, `DetectorSkipped`, `UnknownType`, `UnknownLibfunc` exist but are rarely/never emitted in current execution paths.
- JSON field comment says ISO timestamp, but implementation emits UNIX timestamp string.
- Most findings have no source line/column today (artifact-level analysis, debug mapping limited).
- Detector logic is heuristic and can over/under-report on complex control/data flows.


# Design Agency Brief

## 1. Product Essence

Shadowhare should be positioned as:
- A **security intelligence layer for Starknet teams**.
- Focused on **pre-deploy risk detection** at compiled artifact level.
- Useful for both individual auditors and CI-enforced engineering teams.

Mental model for design:
- It is not just a linter.
- It is a contract-risk radar that explains exploit-shaped behavior.

## 2. Primary User Segments

1. Protocol engineering teams:
- Need fast, deterministic feedback in CI.
- Need to reduce exploit surface before audit/deploy.

2. Security auditors:
- Need a triage accelerator and machine-readable outputs.
- Need detector confidence/severity context quickly.

3. DevOps/Platform teams:
- Need SARIF/code-scanning integration and baseline governance.
- Need policy-style controls (`min-severity`, fail on new findings).

## 3. Key User Jobs to Reflect in UX

Jobs to be made obvious in product narrative and interface:
- “Scan my artifact set and tell me what is exploitable.”
- “Show only severe/new findings so CI can block regressions.”
- “Let me suppress intentionally accepted risk with explicit fingerprints.”
- “Export results to downstream security tooling.”

## 4. Product Behavior to Visualize Clearly

Core visual story (end-to-end):
1. Input artifacts discovered.
2. Compatibility tier determined.
3. Detector suite runs in parallel.
4. Findings are severity-ranked and fingerprinted.
5. Baseline and suppression filters applied.
6. Final outputs emitted (Human/JSON/SARIF).

This flow should be represented in both:
- Marketing narrative (what it does).
- Product UI/CLI docs visuals (how it decides).

## 5. Information Architecture for Product Website or Deck

Recommended page/section stack:
1. Hero: Starknet artifact analyzer for exploit patterns.
2. “How it works”: 6-step pipeline diagram.
3. Detector intelligence: grouped catalog (Arithmetic, Access Control, Messaging, State/Observability).
4. CI/automation: SARIF, baseline, fail-on-new-only workflow.
5. Trust section: deterministic fingerprints, open schemas, test strategy.
6. Roadmap/gaps: transparent heuristic boundaries and planned depth.

## 6. Tone and Messaging Constraints

Tone:
- Technical, calm, and explicit.
- No “magic AI” framing.
- Emphasize deterministic behavior and auditable outputs.

Copy principles:
- Say “heuristic detector” where appropriate.
- Distinguish “finding” from “confirmed exploit”.
- Explain confidence and severity as separate axes.

## 7. Detector Presentation Strategy for Designers

Design the detector catalog around:
- Risk domain grouping instead of alphabetical listing.
- Immediate chips for severity and confidence.
- “Trigger logic” and “Safe pattern” side-by-side.

Suggested grouping:
- Arithmetic and Precision: underflow/overflow/truncation/divide-before-multiply/felt wrap.
- Access Control and Auth: tx-origin auth, unchecked caller checks, unprotected upgrade.
- L1/L2 Messaging: selector injection, tainted destination, unverified amount, double send.
- Storage and State Integrity: tainted storage key, raw payload to storage, missing nonce/event.

## 8. Interaction Patterns to Capture Product Feel

If building a UI layer or interactive prototype:
- Start with severity-first queue (critical/high pinned).
- Allow toggles for “new only”, “with suppressions”, “by detector family”.
- Show fingerprint prominently with copy action.
- Keep artifact/function/statement location always visible.
- Provide one-click export preview for JSON and SARIF.

## 9. Visual Language Direction

Visual system should communicate:
- Precision.
- Security posture.
- Determinism and traceability.

Practical direction:
- Dense but readable data surfaces (tables, chips, callouts).
- Strong contrast for risk tiers.
- Minimal decorative noise; emphasize structured signal.
- Use directed-flow diagrams for analysis pipeline and CI integration.

## 10. Differentiators to Emphasize in Brand Narrative

Most important differentiators from this codebase:
- Sierra-level artifact analysis (works on compiled outputs).
- Broad Starknet-specific detector set (29 currently implemented).
- Baseline fingerprint workflow for regression gating.
- Native SARIF output for enterprise code-scanning pipelines.

## 11. Risks the Design Must Not Obscure

Design should explicitly communicate:
- Heuristic detections can include false positives.
- Detector coverage is wide but not formal verification.
- Some source-level precision (line/col mapping) may be absent depending on artifact/debug info.

This transparency increases trust with serious protocol teams.

## 12. Deliverables a Design Agency Should Produce

1. Positioning and messaging system:
- Tagline, value proposition, detector-family narratives, trust copy.

2. Product marketing site:
- Pipeline visualization, detector catalog UX, CI integration walkthrough.

3. Design system primitives:
- Severity/confidence tokens, finding cards, table states, warning components.

4. Prototype views:
- Scan summary.
- Finding drilldown.
- Baseline diff (“new vs existing”).
- Export/integration panel.

5. Documentation visuals:
- Architecture diagrams.
- Baseline/suppression workflow diagrams.
- SARIF/JSON schema quick-reference blocks.
