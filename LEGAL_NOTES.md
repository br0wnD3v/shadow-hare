# Legal Notes - Implementation Record

**Project:** shadowhare
**License:** MIT OR Apache-2.0
**Date Started:** 2026-02-21

---

## Independent Implementation Statement

This codebase is independently implemented.

No third-party source files, tests, or binaries were copied or ported into this
repository. External material was used only at the level of public concepts,
specifications, and high-level design patterns.

---

## Concept Lineage (Ideas Only)

| Concept | Reference Type | Implementation Location |
|---------|----------------|-------------------------|
| Multi-pass control-flow graph construction | Public architecture notes and specification docs | `src/analysis/cfg.rs` |
| Detector interface and registry model | Common static-analysis design patterns | `src/detectors/mod.rs` |
| Read-call-write reentrancy heuristic | Public security literature and ecosystem guidance | `src/detectors/reentrancy.rs` |
| Handler-origin validation checks | Public protocol/VM documentation | `src/detectors/l1_handler.rs` |
| Taint propagation and dataflow summaries | Academic and industry references | `src/analysis/taint.rs` |

---

## Licensing Posture

Current third-party dependencies are expected to be permissive-license
compatible with this repository's licensing model.

Verification source of truth:
- `Cargo.lock`
- package metadata from standard Rust tooling

If a non-permissive dependency is introduced, document it here immediately with
the rationale and impact.

---

## Process Controls

- Do not copy external implementation code into this repository.
- Re-implement behavior from specs and public concept descriptions.
- Keep detector logic and IR handling authored within this codebase.
- Record materially new external concept inputs in this file.

---

## Maintenance Note

This file is a lightweight implementation and compliance log.
Update it when external concept sources materially influence architecture or
detector behavior.
