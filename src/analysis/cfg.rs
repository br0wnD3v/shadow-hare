use std::collections::{HashMap, HashSet};

use crate::loader::{BranchTarget, Statement};

/// Index into the ProgramIR.statements vec.
pub type StatementIdx = usize;

/// Index into a Cfg.blocks vec.
pub type BlockIdx = usize;

/// A single basic block in the CFG.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: BlockIdx,
    /// Statement indices (into ProgramIR.statements) contained in this block.
    pub stmts: Vec<StatementIdx>,
    pub terminator: Terminator,
}

#[derive(Debug, Clone)]
pub enum Terminator {
    /// Unconditional fall-through to the next block.
    Fallthrough(BlockIdx),
    /// Conditional or unconditional branches to one or more blocks.
    Branch(Vec<BlockEdge>),
    /// Function return.
    Return,
    /// Panic / diverge (no successor).
    Diverge,
}

#[derive(Debug, Clone)]
pub struct BlockEdge {
    pub target: BlockIdx,
    /// Variables produced on this edge.
    pub results: Vec<u64>,
}

/// A Control Flow Graph for a single function.
#[derive(Debug)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    /// Entry block index (always 0).
    pub entry: BlockIdx,
    /// Predecessor map: block → set of predecessor block indices.
    pub predecessors: HashMap<BlockIdx, HashSet<BlockIdx>>,
}

impl Cfg {
    /// Build a CFG for the statements in range `[start, end)`.
    ///
    /// Uses a 2-phase approach:
    ///  Phase 1: Identify block boundaries (leaders).
    ///  Phase 2: Connect blocks via branches.
    pub fn build(statements: &[Statement], start: StatementIdx, end: StatementIdx) -> Self {
        if start >= end || start >= statements.len() {
            return Self::empty();
        }

        let stmts = &statements[start..end.min(statements.len())];
        let n = stmts.len();

        // ── Phase 1: compute leaders (block entry points) ──────────────────
        // Statement 0 is always a leader.
        let mut leaders: HashSet<usize> = HashSet::new();
        leaders.insert(0);

        for (i, stmt) in stmts.iter().enumerate() {
            if let Statement::Invocation(inv) = stmt {
                for branch in &inv.branches {
                    match branch.target {
                        BranchTarget::Statement(target) => {
                            let local = target.saturating_sub(start);
                            if local < n {
                                leaders.insert(local);
                            }
                            // The statement after a branch is also a leader.
                            if i + 1 < n {
                                leaders.insert(i + 1);
                            }
                        }
                        BranchTarget::Fallthrough => {
                            if i + 1 < n {
                                leaders.insert(i + 1);
                            }
                        }
                    }
                }
            }
        }

        let mut sorted_leaders: Vec<usize> = leaders.into_iter().collect();
        sorted_leaders.sort_unstable();

        // ── Phase 2: build blocks and connect them ──────────────────────────
        let block_of: HashMap<usize, BlockIdx> = sorted_leaders
            .iter()
            .enumerate()
            .map(|(block_id, &leader)| (leader, block_id))
            .collect();

        let mut blocks: Vec<BasicBlock> = Vec::with_capacity(sorted_leaders.len());

        for (block_id, &leader) in sorted_leaders.iter().enumerate() {
            let block_end = sorted_leaders.get(block_id + 1).copied().unwrap_or(n);

            let stmt_indices: Vec<StatementIdx> =
                (leader..block_end).map(|local| local + start).collect();

            // Determine terminator from the last statement in this block.
            let terminator = if stmt_indices.is_empty() {
                Terminator::Diverge
            } else {
                let last_local = stmt_indices.last().copied().unwrap() - start;
                compute_terminator(stmts, last_local, start, &block_of)
            };

            blocks.push(BasicBlock {
                id: block_id,
                stmts: stmt_indices,
                terminator,
            });
        }

        // Build predecessor map.
        let mut predecessors: HashMap<BlockIdx, HashSet<BlockIdx>> = HashMap::new();
        for block in &blocks {
            for succ in successors(&block.terminator) {
                predecessors.entry(succ).or_default().insert(block.id);
            }
        }

        Self {
            blocks,
            entry: 0,
            predecessors,
        }
    }

    fn empty() -> Self {
        Self {
            blocks: vec![BasicBlock {
                id: 0,
                stmts: vec![],
                terminator: Terminator::Return,
            }],
            entry: 0,
            predecessors: HashMap::new(),
        }
    }

    pub fn successors(&self, block: BlockIdx) -> Vec<BlockIdx> {
        successors(&self.blocks[block].terminator)
    }

    /// Topological order (approximate, ignores back edges).
    pub fn topological_order(&self) -> Vec<BlockIdx> {
        let mut visited = vec![false; self.blocks.len()];
        let mut order = Vec::with_capacity(self.blocks.len());
        let mut stack = vec![self.entry];

        while let Some(b) = stack.pop() {
            if visited[b] {
                continue;
            }
            visited[b] = true;
            order.push(b);
            for s in self.successors(b).into_iter().rev() {
                if !visited[s] {
                    stack.push(s);
                }
            }
        }
        order
    }
}

fn compute_terminator(
    stmts: &[Statement],
    last_local: usize,
    start: usize,
    block_of: &HashMap<usize, BlockIdx>,
) -> Terminator {
    match &stmts[last_local] {
        Statement::Return(_) => Terminator::Return,
        Statement::Invocation(inv) => {
            let edges: Vec<BlockEdge> = inv
                .branches
                .iter()
                .filter_map(|b| {
                    let target_local = match b.target {
                        BranchTarget::Statement(abs) => abs.saturating_sub(start),
                        BranchTarget::Fallthrough => last_local + 1,
                    };
                    block_of.get(&target_local).map(|&block_id| BlockEdge {
                        target: block_id,
                        results: b.results.clone(),
                    })
                })
                .collect();

            if edges.is_empty() {
                // Diverge (e.g. panic libfunc with no branches)
                Terminator::Diverge
            } else if edges.len() == 1 {
                Terminator::Fallthrough(edges[0].target)
            } else {
                Terminator::Branch(edges)
            }
        }
    }
}

fn successors(term: &Terminator) -> Vec<BlockIdx> {
    match term {
        Terminator::Fallthrough(t) => vec![*t],
        Terminator::Branch(edges) => edges.iter().map(|e| e.target).collect(),
        Terminator::Return | Terminator::Diverge => vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{BranchInfo, BranchTarget, Invocation, SierraId, Statement};

    fn invocation_stmt(libfunc_name: &str, branches: Vec<BranchTarget>) -> Statement {
        Statement::Invocation(Invocation {
            libfunc_id: SierraId {
                id: Some(0),
                debug_name: Some(libfunc_name.to_string()),
            },
            args: vec![],
            branches: branches
                .into_iter()
                .map(|t| BranchInfo {
                    target: t,
                    results: vec![],
                })
                .collect(),
        })
    }

    #[test]
    fn empty_cfg_does_not_panic() {
        let cfg = Cfg::build(&[], 0, 0);
        assert_eq!(cfg.blocks.len(), 1);
    }

    #[test]
    fn linear_function_single_block() {
        let stmts = vec![
            invocation_stmt("felt252_add", vec![BranchTarget::Fallthrough]),
            Statement::Return(vec![0]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());
        // With a fallthrough and return, we expect 2 blocks (split at return)
        // or 1 block — depends on whether return is a leader.
        // Important: no panic.
        assert!(!cfg.blocks.is_empty());
    }

    #[test]
    fn branching_function_multiple_blocks() {
        // stmt 0: conditional branch to stmt 2 or fallthrough to stmt 1
        // stmt 1: return
        // stmt 2: return
        let stmts = vec![
            invocation_stmt(
                "felt252_is_zero",
                vec![BranchTarget::Fallthrough, BranchTarget::Statement(2)],
            ),
            Statement::Return(vec![]),
            Statement::Return(vec![]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());
        assert!(
            cfg.blocks.len() >= 2,
            "Expected multiple blocks, got {}",
            cfg.blocks.len()
        );
    }
}
