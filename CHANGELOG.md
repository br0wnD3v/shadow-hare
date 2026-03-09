# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- 5-layer architecture: loader, IR, analysis, detectors, output
- 30+ security detectors covering OWASP Smart Contract Top 10
- CFG-based taint analysis with configurable sanitizer lists
- Dominator-tree guard verification for access control patterns
- Inter-procedural analysis via CallGraph + FunctionSummaries
- OpenZeppelin component awareness (Ownable, AccessControl, Upgradeable, Pausable, ReentrancyGuard)
- Storage layout extraction from `storage_base_address_const` patterns
- Output formats: Human, JSON (versioned), SARIF 2.1.0
- Baseline diffing for CI integration
- External plugin support via JSON protocol
- Compatibility matrix for Sierra version negotiation
- Criterion benchmarks for loader, IR, CFG, detectors, and full pipeline
- Docker support via multi-stage Dockerfile
- GitHub Actions CI (stable + MSRV 1.75) and release workflows
- `scarb-shdr` / `scarb-shadowhare` Scarb plugin binaries

## [0.1.0] - TBD

Initial release.
