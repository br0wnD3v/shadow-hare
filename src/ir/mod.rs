pub mod function;
pub mod program;
pub mod type_registry;

pub use function::{FunctionInfo, FunctionKind};
pub use program::ProgramIR;
pub use type_registry::{LibfuncRegistry, TypeRegistry};
