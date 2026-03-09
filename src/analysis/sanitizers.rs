//! Canonical sanitizer and pass-through lists.
//!
//! Many detectors maintain their own inconsistent copies of these lists.
//! This module provides a single source of truth so that all detectors
//! agree on what breaks a taint chain, what is a constant producer, etc.

/// Hash-based sanitizers. These produce cryptographic commitments —
/// the output is not meaningfully controlled by the attacker even when
/// the input is tainted.
pub const HASH_SANITIZERS: &[&str] = &["pedersen", "poseidon", "hades_permutation", "keccak"];

/// Constant producers. Their output is compile-time or deploy-time fixed —
/// never attacker-controlled.
pub const CONST_PRODUCERS: &[&str] = &[
    "felt252_const",
    "u8_const",
    "u16_const",
    "u32_const",
    "u64_const",
    "u128_const",
    "u256_const",
    "i8_const",
    "i16_const",
    "i32_const",
    "i64_const",
    "i128_const",
    "bool_const",
    "contract_address_const",
    "class_hash_const",
    "storage_base_address_const",
];

/// Identity / environment producers. These produce values from the execution
/// context that are not derived from attacker-controlled inputs.
pub const IDENTITY_PRODUCERS: &[&str] = &[
    "get_caller_address",
    "get_contract_address",
    "get_execution_info",
    "get_block_timestamp",
    "get_block_number",
    "get_tx_info",
];

/// Pass-through libfuncs. These move/copy a value without transforming it.
/// For taint purposes, outputs carry the same taint as inputs. These should
/// NOT be treated as sanitizers — they propagate taint transparently.
pub const PASS_THROUGH: &[&str] = &["store_temp", "rename", "dup", "snapshot_take"];

/// Range-check libfuncs that convert or assert felt252 values into bounded
/// integer types. Their presence indicates intentional/guarded arithmetic.
pub const RANGE_CHECK_LIBFUNCS: &[&str] = &[
    "felt252_is_zero",
    "u128_from_felt252",
    "u256_from_felt252",
    "u8_from_felt252",
    "u16_from_felt252",
    "u32_from_felt252",
    "u64_from_felt252",
    "assert_le_felt252",
    "assert_lt_felt252",
];

/// Storage read syscall — produces a value from contract storage, not from
/// user input. Often used as a sanitizer in taint analysis.
pub const STORAGE_READ: &[&str] = &["storage_read_syscall"];

/// Storage write syscall.
pub const STORAGE_WRITE: &[&str] = &["storage_write_syscall"];

/// Comparison and assertion libfuncs. When a tainted value is used as input
/// to one of these, the branch taken is "validated" — downstream code in the
/// success branch can be considered range-checked.
pub const COMPARISON_SANITIZERS: &[&str] = &[
    "felt252_is_zero",
    "u128_is_zero",
    "u256_is_zero",
    "bool_not_impl",
    "enum_match",
    "felt252_lt",
    "felt252_le",
    "u128_lt",
    "u128_le",
    "u256_lt",
    "u256_le",
    "u64_lt",
    "u64_le",
    "u32_lt",
    "u32_le",
    "u16_lt",
    "u16_le",
    "u8_lt",
    "u8_le",
];

/// External call libfuncs — these represent calls to other contracts
/// which could be attacker-controlled.
pub const EXTERNAL_CALL_LIBFUNCS: &[&str] = &[
    "call_contract_syscall",
    "call_contract",
    "library_call_syscall",
    "library_call",
];

/// Check if a libfunc name represents an external call.
pub fn is_external_call(name: &str) -> bool {
    EXTERNAL_CALL_LIBFUNCS.iter().any(|p| name.contains(p))
}

/// Union of HASH_SANITIZERS + CONST_PRODUCERS + IDENTITY_PRODUCERS + STORAGE_READ.
///
/// This is the broadest sanitizer set — use when any trusted-value producer
/// should break the taint chain.
pub fn all_general_sanitizers() -> Vec<&'static str> {
    let mut v = Vec::with_capacity(
        HASH_SANITIZERS.len()
            + CONST_PRODUCERS.len()
            + IDENTITY_PRODUCERS.len()
            + STORAGE_READ.len(),
    );
    v.extend_from_slice(HASH_SANITIZERS);
    v.extend_from_slice(CONST_PRODUCERS);
    v.extend_from_slice(IDENTITY_PRODUCERS);
    v.extend_from_slice(STORAGE_READ);
    v
}

/// Hash-only sanitizer set — for detectors like `library_call` and
/// `deploy_tainted_class_hash` where only cryptographic hashing breaks
/// attacker control (constants and identity don't help because the attacker
/// controls the hash input).
pub fn hash_only_sanitizers() -> Vec<&'static str> {
    let mut v = Vec::with_capacity(HASH_SANITIZERS.len() + CONST_PRODUCERS.len());
    v.extend_from_slice(HASH_SANITIZERS);
    v.extend_from_slice(CONST_PRODUCERS);
    v
}

/// Sanitizer set for inter-procedural summary computation.
/// Matches the existing SUMMARY_SANITIZERS in callgraph.rs.
pub fn summary_sanitizers() -> Vec<&'static str> {
    let mut v = Vec::with_capacity(
        HASH_SANITIZERS.len() + CONST_PRODUCERS.len() + IDENTITY_PRODUCERS.len(),
    );
    v.extend_from_slice(HASH_SANITIZERS);
    // Only include the most common constant producers
    v.push("felt252_const");
    v.push("contract_address_const");
    v.push("storage_base_address_const");
    // Identity producers
    v.push("get_caller_address");
    v.push("get_contract_address");
    v
}

/// Check if a libfunc name matches any pattern in the given sanitizer list.
pub fn matches_any(name: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|p| name.contains(p))
}

/// Broadest sanitizer set including comparisons — for detectors where
/// any validation (hash, range, comparison) is sufficient.
pub fn all_sanitizers_with_comparisons() -> Vec<&'static str> {
    let mut v = all_general_sanitizers();
    v.extend_from_slice(COMPARISON_SANITIZERS);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_general_sanitizers_includes_all_categories() {
        let all = all_general_sanitizers();
        assert!(all.contains(&"pedersen"));
        assert!(all.contains(&"felt252_const"));
        assert!(all.contains(&"get_caller_address"));
        assert!(all.contains(&"storage_read_syscall"));
    }

    #[test]
    fn hash_only_excludes_identity() {
        let hash = hash_only_sanitizers();
        assert!(hash.contains(&"pedersen"));
        assert!(hash.contains(&"felt252_const"));
        assert!(!hash.contains(&"get_caller_address"));
        assert!(!hash.contains(&"storage_read_syscall"));
    }

    #[test]
    fn matches_any_works() {
        assert!(matches_any("felt252_const<42>", CONST_PRODUCERS));
        assert!(matches_any("pedersen", HASH_SANITIZERS));
        assert!(!matches_any("felt252_add", HASH_SANITIZERS));
    }

    #[test]
    fn pass_through_does_not_overlap_sanitizers() {
        let all = all_general_sanitizers();
        for pt in PASS_THROUGH {
            assert!(
                !all.contains(pt),
                "pass-through '{pt}' should not be in sanitizers"
            );
        }
    }

    #[test]
    fn hash_sanitizers_includes_keccak() {
        assert!(HASH_SANITIZERS.contains(&"keccak"));
    }

    #[test]
    fn comparison_sanitizers_not_in_general() {
        let general = all_general_sanitizers();
        // Comparisons are NOT in the general set — they're separate
        assert!(!general.contains(&"felt252_lt"));
    }

    #[test]
    fn external_call_detection() {
        assert!(is_external_call("call_contract_syscall"));
        assert!(is_external_call("library_call"));
        assert!(!is_external_call("felt252_add"));
    }
}
