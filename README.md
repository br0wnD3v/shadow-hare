# shadowhare

Static analyzer for Cairo/Starknet contracts at the Sierra artifact layer.

`shadowhare` scans compiled artifacts (`.sierra.json` and
`.contract_class.json`), runs built-in detectors, and emits findings in human,
JSON, or SARIF format.

## What It Does

- Loads Sierra artifacts from files or directories (recursive walk).
- Normalizes artifacts into a single internal IR.
- Classifies functions (external, l1_handler, constructor, internal, view).
- Runs detector suite in parallel.
- Applies severity threshold and suppression rules.
- Supports baseline diffing (`--fail-on-new-only` + `--baseline`).
- Emits:
  - Human-readable report
  - Versioned JSON report
  - SARIF 2.1.0 for code-scanning pipelines

## Current Detector Set

The built-in registry currently runs 56 detectors in deterministic order.

- High: `u256_underflow`, `unchecked_l1_handler`, `reentrancy`, `controlled_library_call`, `unprotected_upgrade`, `unchecked_integer_overflow`, `integer_truncation`, `unchecked_address_cast`, `unchecked_array_access`, `oracle_price_manipulation`, `missing_nonce_validation`, `signature_replay`, `arbitrary_token_transfer`, `write_without_caller_check`, `rtlo`, `l2_to_l1_tainted_destination`, `l1_handler_unchecked_amount`, `l1_handler_payload_to_storage`, `l1_handler_unchecked_selector`, `l2_to_l1_unverified_amount`
- Medium: `felt252_overflow`, `tx_origin_auth`, `divide_before_multiply`, `tainted_storage_key`, `hardcoded_address`, `block_timestamp_dependence`, `unchecked_transfer`, `weak_prng`, `pyth_unchecked_confidence`, `pyth_unchecked_publishtime`, `pyth_deprecated_function`, `tautological_compare`, `tautology`, `multiple_external_calls`, `unchecked_l1_message`, `view_state_modification`, `l2_to_l1_double_send`
- Low: `incorrect_erc20_interface`, `incorrect_erc721_interface`, `calls_loop`, `write_after_write`, `reentrancy_events`, `unused_return`, `missing_event_emission`, `missing_events_access_control`, `missing_events_arithmetic`, `missing_zero_address_check`, `shadowing_builtin`, `shadowing_local`, `shadowing_state`
- Info: `boolean_equality`, `costly_loop`, `cache_array_length`, `unindexed_event`, `unused_state`, `dead_code`

Source of truth for detector behavior and rationale is `docs/RULES.md`.
Use `shadowhare list-detectors` for runtime metadata (severity/confidence/description).

## CLI

### Commands

```bash
shadowhare detect <PATH...> [options]
shadowhare update-baseline <PATH...> [--baseline <file>]
shadowhare list-detectors
```

Short CLI alias:

```bash
shdr detect <PATH...> [options]
```

### `detect` options

- `--format <human|json|sarif>` (default: `human`)
- `--min-severity <info|low|medium|high|critical>` (default: `low`)
- `--fail-on-new-only`
- `--baseline <path>`
- `--detectors <id1,id2,...>`
- `--exclude <id1,id2,...>`
- `--manifest <Scarb.toml path>`
- `--strict`
- `--plugin <executable>` (repeatable; external detector plugins)

### Exit codes

- `0`: no relevant findings
- `1`: findings exist
- `2`: runtime/config/error path

If `--fail-on-new-only` is set, exit code `1` is based only on findings not
present in baseline fingerprints.

## Input Artifacts

Accepted files:

- `*.sierra.json` (raw Sierra JSON)
- `*.contract_class.json` (Starknet contract class JSON)

Directory inputs are traversed recursively and filtered to the extensions above.

## Scarb Integration

This crate ships Scarb subcommand binaries: `scarb-shadowhare` and
`scarb-shdr`.

Expected usage:

```bash
scarb shadowhare detect
scarb shdr detect
```

Behavior:

- If `SCARB_MANIFEST_PATH` is set and `--manifest` is not passed, it injects
  `--manifest <SCARB_MANIFEST_PATH>`.
- If `SCARB_TARGET_DIR` is set and no explicit path is provided after
  `detect`/`update-baseline`, it injects `<SCARB_TARGET_DIR>/<SCARB_PROFILE>`
  (default profile fallback: `dev`).

## Configuration via `Scarb.toml`

Supported config source: `[tool.shadowhare]`.
Backward-compatible fallback: `[tool.analyzer]`.

```toml
[tool.shadowhare]
detectors = ["all"]                # or explicit ids
exclude = ["dead_code"]            # ignored if detectors is explicit non-"all"
severity_threshold = "medium"      # info|low|medium|high
baseline = ".shadowhare-baseline.json"
strict = false
plugins = ["./target/debug/my-shadowhare-plugin"] # optional external plugins

[[tool.shadowhare.suppress]]
id = "reentrancy"
location_hash = "a1b2c3d4"         # optional; omit to suppress all from detector
```

Merging rules:

- CLI flags override `Scarb.toml` values.
- `detectors` and `exclude` are mapped to include/exclude selection.
- Suppressions match by detector id + optional location fingerprint.

## Baseline File

Default baseline schema:

```json
{
  "schema_version": "1.0.0",
  "fingerprints": ["abcd1234", "ef567890"]
}
```

Workflow:

```bash
shadowhare update-baseline target/dev --baseline .shadowhare-baseline.json
shadowhare detect target/dev --baseline .shadowhare-baseline.json --fail-on-new-only
```

## Output Formats

### Human

- Per-finding section with detector id, confidence, location, fingerprint.
- Severity summary.
- Non-fatal warnings section.

### JSON (`schema_version = 1.0.0`)

Top-level fields:

- `schema_version`
- `generated_at` (Unix timestamp string)
- `analyzer_version`
- `sources`
- `findings`
- `warnings`
- `summary`

### SARIF

- SARIF version: `2.1.0`
- Schema: `https://json.schemastore.org/sarif-2.1.0.json`
- Severity mapping:
  - Critical/High -> `error`
  - Medium -> `warning`
  - Low/Info -> `note`

## Compatibility Model

Compatibility types exist in code (`Tier1`, `Tier2`, `Tier3`, `ParseOnly`,
`Unsupported`), with default matrix:

- Tier1: `~2.16`
- Tier2: `~2.15`
- Tier3: `~2.14`

Current loader behavior:

- If compiler/Sierra version metadata is unavailable, analyzer warns and uses
  Tier3 best-effort mode.
- Parse-only mode skips detector execution.

## Accuracy/Heuristic Notes

- Several detectors are intentionally heuristic (especially `felt252_overflow`
  and `dead_code`).
- Source `line`/`col` fields are optional and may be absent.
- Contract-class decoding uses `cairo-lang-starknet-classes` and enriches names
  from contract debug info when present.
- If coverage annotations are embedded (`cairo-annotations` namespace), findings
  are enriched with 1-based source `line`/`col`.

## External Plugins

`shadowhare detect` can execute external detector plugins via `--plugin`.

Plugin contract:

- Shadowhare invokes plugin as: `<plugin_executable> <artifact_path>`
- Plugin must print JSON to stdout:
  - either `[]` / `[Finding, ...]`
  - or `{ "findings": [Finding, ...] }`
- Non-zero plugin exit is treated as a warning; core analysis still completes.

## Build and Test

```bash
cargo build
cargo test
```

List detectors:

```bash
shadowhare list-detectors
```

## Library API (Internal Consumers)

Primary exported entry points:

- `analyse_paths(paths, config, registry) -> AnalysisResult`
- `render_output(result, format) -> String`
- `update_baseline(path, findings)`

Core modules:

- `loader`: artifact loading + normalization
- `ir`: program/function/type/libfunc registries
- `analysis`: CFG/dataflow/taint/storage helpers
- `detectors`: finding model + detector registry + built-ins
- `output`: human/json/sarif renderers
