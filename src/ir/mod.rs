pub mod components;
pub mod function;
pub mod program;
pub mod type_registry;

pub use components::{DetectedComponents, OzComponent};
pub use function::{FunctionInfo, FunctionKind};
pub use program::ProgramIR;
pub use type_registry::{LibfuncRegistry, TypeRegistry};
