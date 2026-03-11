# shadowhare

**Slither for Starknet** — a production-grade static security analyzer for Cairo smart contracts.

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](LICENSE-MIT)
[![Detectors](https://img.shields.io/badge/detectors-71-red)]()
[![Tests](https://img.shields.io/badge/tests-156%20passing-brightgreen)]()

---

## The Problem

Cairo smart contracts on Starknet manage real assets. A single vulnerability — an unprotected upgrade, a reentrancy path, a missing nonce check — can drain millions. Manual audits are slow, expensive, and don't scale.

**Starknet has no Slither.** Until now.

## What Shadowhare Does

Shadowhare scans **compiled Sierra artifacts** (`.sierra.json` / `.contract_class.json`) and runs **71 security detectors** using CFG analysis, taint tracking, and dataflow engines — the same techniques behind Slither, but purpose-built for Cairo's Sierra IR.

No source code needed. Point it at compiled artifacts and get results in seconds.

## Key Features

- **71 security detectors** across 4 severity tiers (21 High / 26 Medium / 16 Low / 8 Info)
- **Deep analysis** — CFG construction, dominator trees, taint propagation, call graph analysis
- **Zero source required** — works directly on compiled `.sierra.json` and `.contract_class.json`
- **CI/CD ready** — SARIF 2.1.0 output, baseline diffing, deterministic exit codes
- **Scarb integration** — `scarb shadowhare detect` just works
- **Upgrade safety** — `detect-diff` compares two contract versions and flags regressions
- **Parallel execution** — detectors run concurrently via Rayon
- **External plugins** — extend with custom detectors via a simple JSON protocol
- **Tested against production contracts** — 0 high-severity false positives on Argent, OpenZeppelin, AVNU, and 30+ real mainnet contracts

---

## Quick Start

### Install from crates.io

```bash
cargo install shadowhare
```

### Install from source

```bash
git clone https://github.com/br0wnD3v/shadowhare.git
cd shadowhare
cargo install --path .
```

### Run

```bash
# Scan a contract
shdr detect ./target/dev/my_contract.contract_class.json

# Scan an entire project directory
shdr detect ./target/dev/

# Include info-level findings
shdr detect ./target/dev/ --min-severity info

# Output SARIF for CI pipelines
shdr detect ./target/dev/ --format sarif

# List all 71 detectors
shdr list-detectors
```

### With Scarb

```bash
# Build your project first
scarb build

# Run shadowhare as a Scarb subcommand
scarb shadowhare detect
scarb shdr detect
```

---

## Example Output

### Scanning Satoru (DeFi protocol — 36 contracts)

```
$ shdr detect ./satoru/target/dev/ --min-severity medium

shadowhare — satoru_Bank.contract_class.json, satoru_Config.contract_class.json, ...

────────────────────────────────────────────────────────────

[HIGH]     Incomplete account interface surface
   Detector:   account_interface_compliance
   Confidence: high
   Function:   <program>
   File:       satoru_MockAccount.contract_class.json

   Account-like function set detected, but interface compliance check
   failed: missing core account methods: __execute__, __validate__,
   is_valid_signature, supports_interface.

   Fingerprint: f7bb2a7bdc27a760

[MEDIUM]   felt252 arithmetic without range check
   Detector:   felt252_overflow
   Confidence: low
   Function:   satoru::config::config::Config::constructor
   File:       satoru_Config.contract_class.json

   Function 'Config::constructor': felt252_add at stmt 1569 performs
   felt252 arithmetic on user-controlled input without a proven range
   check. felt252 wraps silently modulo the field prime.

   Fingerprint: 623285b52ec8368f

────────────────────────────────────────────────────────────
  Summary: 0 critical, 1 high, 3 medium, 0 low, 0 info
```

### Clean scan (Piltover — Starknet appchain)

```
$ shdr detect ./piltover/target/dev/ --min-severity medium

shadowhare — piltover.sierra.json, piltover_appchain.contract_class.json, ...

────────────────────────────────────────────────────────────
  No findings.
────────────────────────────────────────────────────────────
  Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info
```

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │         Sierra Artifacts         │
                    │  .sierra.json  .contract_class   │
                    └────────────────┬────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │           Loader              │
                    │  SierraLoader + VersionNeg.   │
                    │  Contract class enrichment    │
                    └───────────────┬───────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │        Internal IR            │
                    │  ProgramIR · TypeRegistry     │
                    │  FunctionClassifier · OZ      │
                    │  component detection          │
                    └───────────────┬───────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
  ┌─────────▼─────────┐  ┌─────────▼─────────┐  ┌─────────▼─────────┐
  │    CFG Engine      │  │   Taint Engine    │  │   Call Graph      │
  │  2-phase build     │  │  RPO worklist     │  │  Function         │
  │  dominator tree    │  │  source→sink      │  │  summaries        │
  │  natural loops     │  │  sanitizer-aware  │  │  reachability     │
  └─────────┬─────────┘  └─────────┬─────────┘  └─────────┬─────────┘
            │                       │                       │
            └───────────────────────┼───────────────────────┘
                                    │
                    ┌───────────────▼───────────────┐
                    │      71 Detectors (parallel)  │
                    │  21 High · 26 Med · 16 Low    │
                    │  8 Info · deterministic order  │
                    └───────────────┬───────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
    ┌─────────▼───────┐  ┌─────────▼───────┐  ┌─────────▼───────┐
    │     Human       │  │      JSON       │  │     SARIF       │
    │  terminal report│  │  versioned API  │  │  2.1.0 for CI   │
    └─────────────────┘  └─────────────────┘  └─────────────────┘
```

---

## Detector Overview

### High Severity (21)

| Detector | Description |
|----------|-------------|
| `reentrancy` | Storage read → external call → storage write pattern |
| `unprotected_upgrade` | `replace_class_syscall` without owner check |
| `unchecked_l1_handler` | L1 handler missing `from_address` validation |
| `controlled_library_call` | Library call with user-controlled class hash |
| `signature_replay` | Signature verification without nonce check |
| `arbitrary_token_transfer` | Token transfer with attacker-controlled parameters |
| `write_without_caller_check` | Storage write in external function without caller validation |
| `oracle_price_manipulation` | External call result stored without validation |
| `deploy_syscall_tainted_class_hash` | Deploy with user-controlled class hash |
| `initializer_replay_or_missing_guard` | Initializer without one-time guard |
| `missing_nonce_validation` | `__execute__` without nonce increment |
| `account_interface_compliance` | Incomplete SRC6 account interface |
| `account_validate_forbidden_syscalls` | Side-effectful syscalls in validation |
| `account_execute_missing_v0_block` | Missing tx-version guard in `__execute__` |
| `unchecked_ecrecover` | EC recovery without validation |
| `rtlo` | Right-to-left override character injection |
| `u256_underflow` | Unchecked u256 subtraction |
| `l1_handler_payload_to_storage` | L1 payload written to storage without sanitization |
| `l1_handler_unchecked_selector` | L1 handler without selector validation |
| `l2_to_l1_tainted_destination` | L2→L1 message with tainted destination |
| `l2_to_l1_unverified_amount` | L2→L1 message with unverified amount |

### Medium Severity (26)

| Detector | Description |
|----------|-------------|
| `felt252_overflow` | felt252 arithmetic without range check |
| `unchecked_integer_overflow` | Integer arithmetic with silent overflow discard |
| `integer_truncation` | u256→felt252 without high-word bounds check |
| `unchecked_address_cast` | Fallible address cast with unhandled failure |
| `unchecked_array_access` | Array access without bounds checking |
| `tx_origin_auth` | Authentication using transaction origin |
| `divide_before_multiply` | Division before multiplication (precision loss) |
| `weak_prng` | Weak pseudo-random number generation |
| `hardcoded_address` | Hardcoded contract/wallet addresses |
| `block_timestamp_dependence` | Block timestamp used for critical logic |
| `unchecked_transfer` | Token transfer without return value check |
| `tainted_storage_key` | User-controlled storage key |
| `gas_griefing` | Unbounded loop callable by external users |
| `view_state_modification` | View function modifying state |
| `uninitialized_storage_read` | Reading storage before initialization |
| `multiple_external_calls` | Multiple external calls in single function |
| `tautological_compare` | Always-true/false comparison |
| `tautology` | Tautological expression |
| `l1_handler_unchecked_amount` | L1 handler with unchecked amount |
| `l2_to_l1_double_send` | Duplicate L2→L1 messages |
| `pyth_*` (3) | Pyth oracle misuse patterns |
| `pragma_*` (3) | Pragma oracle misuse patterns |

### Low Severity (16)

Missing events, incorrect ERC interfaces, shadowing, write-after-write, calls in loops, and more.

### Info (8)

Dead code, magic numbers, costly loops, boolean equality, excessive complexity, and more.

Full detector documentation: [`docs/RULES.md`](docs/RULES.md)

---

## CLI Reference

```bash
# Core commands
shdr detect <PATH...> [options]        # Run security analysis
shdr detect-diff --left <V1> --right <V2>  # Compare two versions
shdr print <PRINTER> <PATH...>         # Structural analysis
shdr update-baseline <PATH...>         # Snapshot current findings
shdr list-detectors                    # Show all detectors
```

### `detect` options

| Flag | Description | Default |
|------|-------------|---------|
| `--format <human\|json\|sarif>` | Output format | `human` |
| `--min-severity <info\|low\|medium\|high>` | Severity threshold | `low` |
| `--detectors <id1,id2,...>` | Run only these detectors | all |
| `--exclude <id1,id2,...>` | Skip these detectors | none |
| `--baseline <path>` | Baseline file for diffing | none |
| `--fail-on-new-only` | Exit 1 only for new findings | off |
| `--strict` | Fail on degraded analysis | off |
| `--manifest <Scarb.toml>` | Read project config | auto-discover |
| `--plugin <exe>` | External detector plugin | none |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings (or no new findings with `--fail-on-new-only`) |
| `1` | Findings detected |
| `2` | Runtime error |

### Structural printers

```bash
shdr print summary <PATH>              # Function/statement overview
shdr print callgraph <PATH> --format dot   # Call graph (Graphviz)
shdr print attack-surface <PATH>       # Entrypoint→sink reachability
shdr print storage-layout <PATH>       # Storage slot analysis
shdr print data-dependence <PATH>      # Data dependency chains
shdr print function-signatures <PATH>  # Function signature listing
shdr print ir-dump <PATH>              # Raw IR dump
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Build Cairo contracts
  run: scarb build

- name: Security scan
  run: |
    cargo install shadowhare
    shdr detect ./target/dev/ --format sarif --min-severity medium \
      > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Baseline workflow (suppress known findings)

```bash
# Create baseline from current state
shdr update-baseline ./target/dev/ --baseline .shadowhare-baseline.json

# In CI: only fail on NEW findings
shdr detect ./target/dev/ --baseline .shadowhare-baseline.json --fail-on-new-only
```

### Upgrade safety check

```bash
# Compare v1 vs v2 — fail if new high-severity findings appear
shdr detect-diff --left ./v1/target/dev/ --right ./v2/target/dev/ \
  --fail-on-new-severity high
```

---

## Configuration via Scarb.toml

```toml
[tool.shadowhare]
detectors = ["all"]
exclude = ["dead_code"]
severity_threshold = "medium"
baseline = ".shadowhare-baseline.json"
strict = false
plugins = ["./target/debug/my-plugin"]

[[tool.shadowhare.suppress]]
id = "reentrancy"
location_hash = "a1b2c3d4"  # optional: omit to suppress all from this detector
```

CLI flags always override `Scarb.toml` values.

---

## Compatibility

| Cairo Compiler | Support Tier |
|---------------|--------------|
| `~2.16` | Tier 1 (full support) |
| `~2.15` | Tier 2 (supported) |
| `~2.14` | Tier 3 (best-effort) |

Artifacts without version metadata are analyzed in Tier 3 best-effort mode with a warning.

---

## Building from Source

**Prerequisites:** Rust 1.75+

```bash
git clone https://github.com/br0wnD3v/shadowhare.git
cd shadowhare
cargo build --release

# Run tests
cargo test

# Run clippy
cargo clippy --all-targets -- -D warnings

# Run benchmarks
cargo bench --bench analysis_bench
```

---

## License

Licensed under either of:

- [MIT license](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
