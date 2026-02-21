use std::collections::HashMap;

use crate::analysis::cfg::{BlockIdx, Cfg};
use crate::loader::Statement;

/// Trait for forward dataflow analyses.
///
/// Implement this to run a fixed-point forward analysis over a CFG.
pub trait ForwardAnalysis {
    type Domain: Clone + Eq;

    /// Initial state at the function entry.
    fn bottom(&self) -> Self::Domain;

    /// Transfer function: given pre-state and a statement, compute post-state.
    fn transfer_stmt(&self, state: &Self::Domain, stmt: &Statement) -> Self::Domain;

    /// Join (merge) two states at a confluence point.
    fn join(&self, a: &Self::Domain, b: &Self::Domain) -> Self::Domain;
}

/// Run a forward dataflow analysis and return per-block exit states.
pub fn run_forward<A: ForwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    all_stmts: &[Statement],
) -> HashMap<BlockIdx, A::Domain> {
    let mut block_in: HashMap<BlockIdx, A::Domain> = HashMap::new();
    let mut block_out: HashMap<BlockIdx, A::Domain> = HashMap::new();

    // Initialise entry block
    block_in.insert(cfg.entry, analysis.bottom());

    let order = cfg.topological_order();

    // Worklist iteration — run until fixed point
    let mut changed = true;
    while changed {
        changed = false;

        for &block_id in &order {
            let block = &cfg.blocks[block_id];

            // Compute entry state: join all predecessor exit states
            let in_state = if block_id == cfg.entry {
                block_in.get(&block_id).cloned().unwrap_or_else(|| analysis.bottom())
            } else {
                let preds = cfg.predecessors.get(&block_id);
                let state = match preds {
                    None => analysis.bottom(),
                    Some(p) if p.is_empty() => analysis.bottom(),
                    Some(preds) => {
                        let mut it = preds.iter();
                        let first = it.next().unwrap();
                        let mut acc = block_out
                            .get(first)
                            .cloned()
                            .unwrap_or_else(|| analysis.bottom());
                        for pred in it {
                            let pred_out = block_out
                                .get(pred)
                                .cloned()
                                .unwrap_or_else(|| analysis.bottom());
                            acc = analysis.join(&acc, &pred_out);
                        }
                        acc
                    }
                };
                state
            };

            // Transfer through each statement in the block
            let mut state = in_state.clone();
            for &stmt_idx in &block.stmts {
                if let Some(stmt) = all_stmts.get(stmt_idx) {
                    state = analysis.transfer_stmt(&state, stmt);
                }
            }

            let old_out = block_out.get(&block_id).cloned();
            if old_out.as_ref() != Some(&state) {
                block_out.insert(block_id, state);
                changed = true;
            }
        }
    }

    block_out
}

/// Collect all statements that match a predicate in topological order.
pub fn collect_matching<'a, F>(
    cfg: &'a Cfg,
    all_stmts: &'a [Statement],
    predicate: F,
) -> Vec<(BlockIdx, usize, &'a Statement)>
where
    F: Fn(&Statement) -> bool,
{
    let mut results = Vec::new();
    for block_id in cfg.topological_order() {
        let block = &cfg.blocks[block_id];
        for &idx in &block.stmts {
            if let Some(stmt) = all_stmts.get(idx) {
                if predicate(stmt) {
                    results.push((block_id, idx, stmt));
                }
            }
        }
    }
    results
}
