# Ecosystem Test Corpus Manifest

Generated: 2026-03-09

Test corpus for Shadowhare static analyzer. All repos cloned with `--depth 1`.

## Summary

| # | Directory | Source Repo | Cairo Files | Scarb.toml | Sierra Artifacts | Status |
|---|-----------|-------------|-------------|------------|------------------|--------|
| 1 | `openzeppelin/` | [OpenZeppelin/cairo-contracts](https://github.com/OpenZeppelin/cairo-contracts) | 307 | Yes (workspace, 16 packages) | None | Cloned |
| 2 | `crytic-secure-contracts/` | [crytic/building-secure-contracts](https://github.com/crytic/building-secure-contracts) | 0 | No | None | Cloned (EVM-focused, no Cairo) |
| 3 | `vuln-patterns/` | [0xEniotna/Starknet-contracts-vulnerabilities](https://github.com/0xEniotna/Starknet-contracts-vulnerabilities) | 0 | No | None | Cloned (README-only, no source) |
| 4 | `damn-vulnerable-defi/` | [credence0x/cairo-damn-vulnerable-defi](https://github.com/credence0x/cairo-damn-vulnerable-defi) | 34 | Yes | None | Cloned |
| 5 | `alexandria/` | [keep-starknet-strange/alexandria](https://github.com/keep-starknet-strange/alexandria) | 229 | Yes | None | Cloned |
| 6 | `unruggable-meme/` | [keep-starknet-strange/unruggable.meme](https://github.com/keep-starknet-strange/unruggable.meme) | 46 | Yes (nested: packages/contracts/) | None | Cloned |
| 7 | `jediswap-v2/` | [jediswaplabs/JediSwap-v2-core](https://github.com/jediswaplabs/JediSwap-v2-core) | 42 | Yes | None | Cloned |
| 8 | `satoru/` | [keep-starknet-strange/satoru](https://github.com/keep-starknet-strange/satoru) | 215 | Yes | None | Cloned |
| 9 | `snapshot-x/` | [snapshot-labs/sx-starknet](https://github.com/snapshot-labs/sx-starknet) | 75 | Yes (nested: starknet/) | None | Cloned |
| 10 | `starknet-by-example/` | [NethermindEth/StarknetByExample](https://github.com/NethermindEth/StarknetByExample) | 141 | Yes (30+ sub-projects) | None | Cloned |
| 11 | `avnu/` | [avnu-labs/avnu-contracts-v2](https://github.com/avnu-labs/avnu-contracts-v2) | 47 | Yes | None | Cloned |
| 12 | `piltover/` | [keep-starknet-strange/piltover](https://github.com/keep-starknet-strange/piltover) | 25 | Yes | None | Cloned |

**Total Cairo files: 1,161**

## Clone Results

All 12 repositories cloned successfully. No failures.

## Notes

- **crytic-secure-contracts**: This repo is EVM/Solidity-focused (Slither, Echidna, Manticore). Contains no Cairo source files. Retained for reference material on vulnerability patterns but not useful for direct Shadowhare testing.
- **vuln-patterns**: Contains only a README.md describing StarkNet vulnerability patterns. No actual Cairo code. Useful as a reference document only.
- **No pre-compiled Sierra artifacts** (`.contract_class.json` / `.sierra.json`) were found in any repo. All projects will need to be compiled with `scarb build` to generate Sierra IR for analysis.

## Build Readiness

Projects ready to build with `scarb build` (have root or nested Scarb.toml):

1. **openzeppelin** - Workspace with 16 packages (access, account, finance, governance, introspection, interfaces, macros, merkle_tree, presets, security, testing, test_common, token, upgrades, utils)
2. **alexandria** - Root Scarb.toml
3. **satoru** - Root Scarb.toml
4. **jediswap-v2** - Root Scarb.toml + scripts/Scarb.toml
5. **damn-vulnerable-defi** - Root Scarb.toml
6. **avnu** - Root Scarb.toml
7. **piltover** - Root Scarb.toml
8. **snapshot-x** - Nested at `starknet/Scarb.toml`
9. **unruggable-meme** - Nested at `packages/contracts/Scarb.toml`
10. **starknet-by-example** - Root Scarb.toml + 30+ individual listing sub-projects

Projects NOT buildable (no Cairo source):
- crytic-secure-contracts (EVM-only)
- vuln-patterns (documentation-only)

## Priority for Testing

### Tier 1 - High Priority (core libraries, real DeFi)
- `openzeppelin/` - Foundation of StarkNet contract ecosystem (307 files)
- `alexandria/` - Widely used utility library (229 files)
- `satoru/` - Complex DeFi protocol, GMX v2 fork (215 files)

### Tier 2 - Medium Priority (production DeFi, governance)
- `jediswap-v2/` - Major DEX (42 files)
- `snapshot-x/` - Governance protocol (75 files)
- `avnu/` - DEX aggregator, audited (47 files)
- `unruggable-meme/` - Real DeFi token patterns (46 files)
- `piltover/` - Core contract components (25 files)

### Tier 3 - Educational & Vulnerability Testing
- `starknet-by-example/` - Educational contracts, good baseline (141 files)
- `damn-vulnerable-defi/` - Intentionally vulnerable, detector validation (34 files)
