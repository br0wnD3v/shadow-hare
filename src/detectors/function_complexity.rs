use crate::analysis::cfg::{Cfg, Terminator};
use crate::detectors::{Confidence, Detector, DetectorRequirements, Finding, Location, Severity};
use crate::error::AnalyzerWarning;
use crate::ir::program::ProgramIR;
use crate::loader::CompatibilityTier;

/// Detects functions with excessive cyclomatic complexity.
///
/// Cyclomatic complexity = number of CFG edges - number of CFG nodes + 2.
/// High complexity indicates code that is difficult to test, review, and
/// maintain — which increases the risk of security bugs.
pub struct ExcessiveFunctionComplexity;

/// Default threshold above which a function is flagged.
const COMPLEXITY_THRESHOLD: usize = 20;

impl Detector for ExcessiveFunctionComplexity {
    fn id(&self) -> &'static str {
        "excessive_function_complexity"
    }

    fn severity(&self) -> Severity {
        Severity::Info
    }

    fn confidence(&self) -> Confidence {
        Confidence::High
    }

    fn description(&self) -> &'static str {
        "Function has high cyclomatic complexity, making it difficult to \
         test and review. Consider refactoring into smaller functions."
    }

    fn requirements(&self) -> DetectorRequirements {
        DetectorRequirements {
            min_tier: CompatibilityTier::Tier3,
            requires_debug_info: false,
            source_aware: false,
        }
    }

    fn run(&self, program: &ProgramIR) -> (Vec<Finding>, Vec<AnalyzerWarning>) {
        let mut findings = Vec::new();
        let warnings = Vec::new();

        for func in program.external_functions() {
            let (start, end) = program.function_statement_range(func.idx);
            if start >= end {
                continue;
            }
            let end = end.min(program.statements.len());

            let cfg = Cfg::build(&program.statements, start, end);

            // Cyclomatic complexity: E - N + 2
            let num_nodes = cfg.blocks.len();
            let num_edges: usize = cfg
                .blocks
                .iter()
                .map(|b| match &b.terminator {
                    Terminator::Fallthrough(_) => 1,
                    Terminator::Branch(edges) => edges.len(),
                    Terminator::Return | Terminator::Diverge => 0,
                })
                .sum();

            let complexity = if num_edges + 2 >= num_nodes {
                (num_edges + 2) - num_nodes
            } else {
                1 // Degenerate case
            };

            if complexity > COMPLEXITY_THRESHOLD {
                findings.push(Finding::new(
                    self.id(),
                    self.severity(),
                    self.confidence(),
                    "Excessive function complexity",
                    format!(
                        "Function '{}': cyclomatic complexity is {} (threshold: {}). \
                         High complexity increases bug risk — consider refactoring.",
                        func.name, complexity, COMPLEXITY_THRESHOLD
                    ),
                    Location {
                        file: program.source.display().to_string(),
                        function: func.name.clone(),
                        statement_idx: Some(start),
                        line: None,
                        col: None,
                    },
                ));
            }
        }

        (findings, warnings)
    }
}
