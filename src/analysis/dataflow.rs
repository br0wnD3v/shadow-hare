use std::collections::{HashMap, VecDeque};

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
///
/// Uses RPO (reverse post-order) iteration with a worklist. For reducible CFGs
/// (which Sierra almost always produces), this converges in a single pass.
/// The worklist avoids re-processing blocks whose inputs haven't changed.
pub fn run_forward<A: ForwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    all_stmts: &[Statement],
) -> HashMap<BlockIdx, A::Domain> {
    let n = cfg.blocks.len();
    let mut block_out: HashMap<BlockIdx, A::Domain> = HashMap::with_capacity(n);

    // RPO is the optimal iteration order for forward analyses.
    let rpo = cfg.reverse_post_order();

    // RPO position for worklist ordering (process lower RPO numbers first).
    let mut rpo_pos = vec![0usize; n];
    for (pos, &block) in rpo.iter().enumerate() {
        rpo_pos[block] = pos;
    }

    // Seed the worklist with all blocks in RPO order.
    let mut in_worklist = vec![true; n];
    let mut worklist: VecDeque<BlockIdx> = rpo.iter().copied().collect();

    while let Some(block_id) = worklist.pop_front() {
        in_worklist[block_id] = false;
        let block = &cfg.blocks[block_id];

        // Compute entry state: join all predecessor exit states.
        let in_state = if block_id == cfg.entry {
            analysis.bottom()
        } else {
            join_predecessors(analysis, cfg, block_id, &block_out)
        };

        // Transfer through each statement in the block.
        let mut state = in_state;
        for &stmt_idx in &block.stmts {
            if let Some(stmt) = all_stmts.get(stmt_idx) {
                state = analysis.transfer_stmt(&state, stmt);
            }
        }

        // If the exit state changed, add successors to the worklist.
        let old_out = block_out.get(&block_id);
        if old_out != Some(&state) {
            block_out.insert(block_id, state);
            for succ in cfg.successors(block_id) {
                if !in_worklist[succ] {
                    in_worklist[succ] = true;
                    // Insert maintaining approximate RPO order for efficiency.
                    // For small worklists this is fine; for large ones a priority
                    // queue keyed on rpo_pos would be better.
                    worklist.push_back(succ);
                }
            }
        }
    }

    block_out
}

/// Join all predecessor exit states for a block.
fn join_predecessors<A: ForwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    block_id: BlockIdx,
    block_out: &HashMap<BlockIdx, A::Domain>,
) -> A::Domain {
    let Some(preds) = cfg.predecessors.get(&block_id) else {
        return analysis.bottom();
    };
    if preds.is_empty() {
        return analysis.bottom();
    }

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

/// Compute the entry state for a block by joining all predecessor exit states.
///
/// This is a common pattern used by detectors that run a manual forward pass
/// (e.g. `felt252_overflow`, `unchecked_write`, `storage_access`) where they
/// need the entry state of each block to check statements within it.
///
/// For the entry block, returns `analysis.bottom()`.
pub fn block_entry_state<A: ForwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    block_id: BlockIdx,
    block_out: &HashMap<BlockIdx, A::Domain>,
) -> A::Domain {
    if block_id == cfg.entry {
        return analysis.bottom();
    }

    let Some(preds) = cfg.predecessors.get(&block_id) else {
        return analysis.bottom();
    };
    if preds.is_empty() {
        return analysis.bottom();
    }

    let mut it = preds.iter();
    let first = it.next().expect("preds is non-empty");
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

/// Trait for backward dataflow analyses.
///
/// Implement this to run a fixed-point backward analysis over a CFG.
/// Backward analyses flow information from program exits toward the entry.
pub trait BackwardAnalysis {
    type Domain: Clone + Eq;

    /// Initial state at exit points (blocks with no successors).
    fn top(&self) -> Self::Domain;

    /// Backward transfer function: given post-state and a statement,
    /// compute the pre-state.
    fn transfer_stmt_backward(&self, state: &Self::Domain, stmt: &Statement) -> Self::Domain;

    /// Join (merge) two states at a confluence point.
    fn join(&self, a: &Self::Domain, b: &Self::Domain) -> Self::Domain;
}

/// Run a backward dataflow analysis and return per-block entry states.
///
/// Uses post-order iteration with a worklist. For reducible CFGs this
/// converges efficiently. Dual of run_forward.
pub fn run_backward<A: BackwardAnalysis>(
    analysis: &A,
    cfg: &Cfg,
    all_stmts: &[Statement],
) -> HashMap<BlockIdx, A::Domain> {
    let n = cfg.blocks.len();
    // block_in[block_id] = entry state for block (what we compute)
    let mut block_in: HashMap<BlockIdx, A::Domain> = HashMap::with_capacity(n);

    // Post-order is optimal for backward analyses.
    let po = cfg.topological_order();

    // Seed worklist with all blocks in reverse topological order (post-order).
    let mut in_worklist = vec![true; n];
    let mut worklist: VecDeque<BlockIdx> = po.into_iter().rev().collect();

    while let Some(block_id) = worklist.pop_front() {
        in_worklist[block_id] = false;
        let block = &cfg.blocks[block_id];

        // Compute exit state: join all successor entry states.
        let succs = cfg.successors(block_id);
        let out_state = if succs.is_empty() {
            analysis.top()
        } else {
            let mut it = succs.iter();
            let first = it.next().unwrap();
            let mut acc = block_in
                .get(first)
                .cloned()
                .unwrap_or_else(|| analysis.top());
            for succ in it {
                let succ_in = block_in
                    .get(succ)
                    .cloned()
                    .unwrap_or_else(|| analysis.top());
                acc = analysis.join(&acc, &succ_in);
            }
            acc
        };

        // Transfer backward through each statement in reverse order.
        let mut state = out_state;
        for &stmt_idx in block.stmts.iter().rev() {
            if let Some(stmt) = all_stmts.get(stmt_idx) {
                state = analysis.transfer_stmt_backward(&state, stmt);
            }
        }

        // If the entry state changed, add predecessors to the worklist.
        let old_in = block_in.get(&block_id);
        if old_in != Some(&state) {
            block_in.insert(block_id, state);
            if let Some(preds) = cfg.predecessors.get(&block_id) {
                for &pred in preds {
                    if !in_worklist[pred] {
                        in_worklist[pred] = true;
                        worklist.push_back(pred);
                    }
                }
            }
        }
    }

    block_in
}
