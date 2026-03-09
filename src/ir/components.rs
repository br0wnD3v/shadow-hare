use std::collections::HashSet;

use crate::ir::program::ProgramIR;

/// Known OpenZeppelin component families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OzComponent {
    Ownable,
    AccessControl,
    Upgradeable,
    ReentrancyGuard,
    Pausable,
}

impl std::fmt::Display for OzComponent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ownable => write!(f, "Ownable"),
            Self::AccessControl => write!(f, "AccessControl"),
            Self::Upgradeable => write!(f, "Upgradeable"),
            Self::ReentrancyGuard => write!(f, "ReentrancyGuard"),
            Self::Pausable => write!(f, "Pausable"),
        }
    }
}

/// Patterns that indicate each OZ component is embedded.
/// We look for these in function debug names AND type debug names.
const OWNABLE_PATTERNS: &[&str] = &[
    "ownable_component",
    "OwnableComponent",
    "OwnableImpl",
    "OwnableMixinImpl",
    "InternalImpl::_transfer_ownership",
    "InternalImpl::assert_only_owner",
];

const ACCESS_CONTROL_PATTERNS: &[&str] = &[
    "access_control_component",
    "AccessControlComponent",
    "AccessControlImpl",
    "AccessControlMixinImpl",
    "InternalImpl::assert_only_role",
    "InternalImpl::_grant_role",
];

const UPGRADEABLE_PATTERNS: &[&str] = &[
    "upgradeable_component",
    "UpgradeableComponent",
    "UpgradeableImpl",
    "InternalImpl::_upgrade",
];

const REENTRANCY_GUARD_PATTERNS: &[&str] = &[
    "reentrancy_guard_component",
    "ReentrancyGuardComponent",
    "ReentrancyGuardImpl",
    "InternalImpl::start",
    "InternalImpl::end",
];

const PAUSABLE_PATTERNS: &[&str] = &[
    "pausable_component",
    "PausableComponent",
    "PausableImpl",
    "InternalImpl::assert_not_paused",
    "InternalImpl::_pause",
    "InternalImpl::_unpause",
];

/// Detected OZ components in a program.
#[derive(Debug, Clone)]
pub struct DetectedComponents {
    pub components: HashSet<OzComponent>,
}

impl DetectedComponents {
    /// Scan a ProgramIR for embedded OZ components.
    pub fn detect(program: &ProgramIR) -> Self {
        let mut components = HashSet::new();

        // Scan function debug names.
        for func in &program.functions {
            let name = &func.name;
            check_patterns(name, &mut components);
        }

        // Scan type debug names.
        for td in program.type_registry.all_debug_names() {
            check_patterns(td, &mut components);
        }

        // Scan libfunc debug names.
        for ld in program.libfunc_registry.all_debug_names() {
            check_patterns(ld, &mut components);
        }

        Self { components }
    }

    pub fn has(&self, component: OzComponent) -> bool {
        self.components.contains(&component)
    }

    /// Returns true if the program has some form of access control
    /// (either Ownable or AccessControl).
    pub fn has_access_control(&self) -> bool {
        self.has(OzComponent::Ownable) || self.has(OzComponent::AccessControl)
    }

    /// Returns true if the program has the Upgradeable component
    /// AND some form of access control guarding it.
    pub fn has_guarded_upgrade(&self) -> bool {
        self.has(OzComponent::Upgradeable) && self.has_access_control()
    }

    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
}

fn check_patterns(name: &str, components: &mut HashSet<OzComponent>) {
    let candidates: &[(&[&str], OzComponent)] = &[
        (OWNABLE_PATTERNS, OzComponent::Ownable),
        (ACCESS_CONTROL_PATTERNS, OzComponent::AccessControl),
        (UPGRADEABLE_PATTERNS, OzComponent::Upgradeable),
        (REENTRANCY_GUARD_PATTERNS, OzComponent::ReentrancyGuard),
        (PAUSABLE_PATTERNS, OzComponent::Pausable),
    ];

    for &(patterns, component) in candidates {
        if patterns.iter().any(|p| name.contains(p)) {
            components.insert(component);
        }
    }
}
