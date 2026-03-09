# Contributing to Shadowhare

Thank you for your interest in contributing!

## Getting Started

```bash
git clone https://github.com/br0wnD3v/shadowhare.git
cd shadowhare
cargo build
cargo test
```

## Adding a Detector

1. Create `src/detectors/your_detector.rs` implementing the `Detector` trait
2. Add `pub mod your_detector;` to `src/detectors/mod.rs`
3. Register in `DetectorRegistry::all()` in the correct severity order
4. Add test fixtures in `fixtures/vulnerable/` and/or `fixtures/clean/`
5. Add golden tests in `tests/detector_golden.rs`

### Detector Requirements

- Set `min_tier` to the lowest `CompatibilityTier` your detector needs
- Set `requires_debug_info: true` if you rely on function/type debug names
- Use CFG-based taint analysis (`run_taint_analysis()`) over linear scans
- Use canonical sanitizer lists from `analysis::sanitizers`
- Keep false positive rate low — prefer `Confidence::Medium` or `Low` if unsure

## Running Tests

```bash
cargo test                    # All tests
cargo test --test detector_golden  # Detector golden tests only
cargo bench --bench analysis_bench -- --test  # Verify benchmarks compile
```

## Code Style

- `cargo fmt` before committing
- `cargo clippy --all-targets` with zero warnings
- Functions under 50 lines, files under 800 lines
- Immutable patterns — create new objects, never mutate

## Pull Requests

- One concern per PR
- Include test coverage for new detectors
- Reference any related issues
- CI must pass (fmt, clippy, test on stable + MSRV 1.75)
