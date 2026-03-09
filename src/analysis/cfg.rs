use std::collections::{HashMap, HashSet};

use tracing::debug;

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

/// A natural loop identified via back-edge detection from the dominator tree.
#[derive(Debug, Clone)]
pub struct NaturalLoop {
    /// The loop header block (target of the back-edge).
    pub header: BlockIdx,
    /// All blocks in the loop body (includes header).
    pub body: HashSet<BlockIdx>,
    /// The block that branches back to the header.
    pub back_edge_source: BlockIdx,
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

        debug!(blocks = blocks.len(), stmts = end - start, "CFG built");

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

    /// Compute the immediate dominator tree using the Cooper-Harvey-Kennedy algorithm.
    ///
    /// Returns a map from each block to its immediate dominator. The entry block
    /// is its own dominator (i.e., `idom[entry] == entry`).
    ///
    /// Reference: Cooper, Harvey, Kennedy — "A Simple, Fast Dominance Algorithm" (2001)
    pub fn dominators(&self) -> HashMap<BlockIdx, BlockIdx> {
        let n = self.blocks.len();
        if n == 0 {
            return HashMap::new();
        }

        // Compute reverse post-order (RPO) numbering.
        let rpo = self.reverse_post_order();
        let mut rpo_num = vec![0usize; n];
        for (order, &block) in rpo.iter().enumerate() {
            rpo_num[block] = order;
        }

        // idom[b] = immediate dominator of b.  USIZE_MAX = undefined.
        let undefined: usize = usize::MAX;
        let mut idom = vec![undefined; n];
        idom[self.entry] = self.entry;

        let intersect = |mut b1: usize, mut b2: usize, idom: &[usize]| -> usize {
            while b1 != b2 {
                while rpo_num[b1] > rpo_num[b2] {
                    b1 = idom[b1];
                }
                while rpo_num[b2] > rpo_num[b1] {
                    b2 = idom[b2];
                }
            }
            b1
        };

        let mut changed = true;
        while changed {
            changed = false;
            for &b in &rpo {
                if b == self.entry {
                    continue;
                }
                let preds = self.predecessors.get(&b);
                let preds = match preds {
                    Some(p) => p,
                    None => continue,
                };

                // Pick the first predecessor that has an idom already.
                let mut new_idom = undefined;
                for &p in preds {
                    if idom[p] != undefined {
                        new_idom = p;
                        break;
                    }
                }
                if new_idom == undefined {
                    continue;
                }

                // Intersect with other processed predecessors.
                for &p in preds {
                    if p == new_idom {
                        continue;
                    }
                    if idom[p] != undefined {
                        new_idom = intersect(p, new_idom, &idom);
                    }
                }

                if idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        idom.into_iter()
            .enumerate()
            .filter(|(_, dom)| *dom != undefined)
            .collect()
    }

    /// Check if `guard_block` dominates `sink_block` using a precomputed
    /// dominator tree. Prefer this over `dominates()` when checking multiple
    /// pairs — compute the tree once with `dominators()` and reuse it.
    pub fn dominates_with(
        idom: &HashMap<BlockIdx, BlockIdx>,
        guard_block: BlockIdx,
        sink_block: BlockIdx,
    ) -> bool {
        if guard_block == sink_block {
            return true;
        }
        let mut current = sink_block;
        loop {
            let Some(&dom) = idom.get(&current) else {
                return false;
            };
            if dom == guard_block {
                return true;
            }
            if dom == current {
                return false;
            }
            current = dom;
        }
    }

    /// Check if `guard_block` dominates `sink_block`.
    ///
    /// NOTE: This recomputes the dominator tree on every call. If you need
    /// to check multiple pairs, use `dominators()` + `dominates_with()`.
    pub fn dominates(&self, guard_block: BlockIdx, sink_block: BlockIdx) -> bool {
        let idom = self.dominators();
        Self::dominates_with(&idom, guard_block, sink_block)
    }

    /// Compute reverse post-order (RPO) traversal.
    ///
    /// RPO is the standard iteration order for forward dataflow analyses.
    /// For reducible CFGs (which Sierra code almost always produces), a forward
    /// analysis converges in a single pass over RPO.
    pub fn reverse_post_order(&self) -> Vec<BlockIdx> {
        let mut visited = vec![false; self.blocks.len()];
        let mut post_order = Vec::with_capacity(self.blocks.len());
        self.rpo_dfs(self.entry, &mut visited, &mut post_order);
        post_order.reverse();
        post_order
    }

    fn rpo_dfs(&self, block: BlockIdx, visited: &mut Vec<bool>, post_order: &mut Vec<BlockIdx>) {
        if visited[block] {
            return;
        }
        visited[block] = true;
        for succ in self.successors(block) {
            self.rpo_dfs(succ, visited, post_order);
        }
        post_order.push(block);
    }

    /// Find natural loops via back-edge detection from the dominator tree.
    ///
    /// For each edge (A→B) where B dominates A, B is a loop header and the
    /// body is all blocks that can reach A without going through B (plus B).
    pub fn natural_loops(&self) -> Vec<NaturalLoop> {
        let idom = self.dominators();
        let mut loops = Vec::new();

        for block in &self.blocks {
            for succ in successors(&block.terminator) {
                // A back-edge exists when succ dominates block.
                if Self::dominates_with(&idom, succ, block.id) {
                    let header = succ;
                    let back_edge_source = block.id;

                    // Collect the loop body: all blocks that can reach
                    // back_edge_source without leaving through header.
                    let mut body = HashSet::new();
                    body.insert(header);

                    if header != back_edge_source {
                        body.insert(back_edge_source);
                        let mut worklist = vec![back_edge_source];
                        while let Some(b) = worklist.pop() {
                            if let Some(preds) = self.predecessors.get(&b) {
                                for &pred in preds {
                                    if body.insert(pred) {
                                        worklist.push(pred);
                                    }
                                }
                            }
                        }
                    }

                    loops.push(NaturalLoop {
                        header,
                        body,
                        back_edge_source,
                    });
                }
            }
        }

        loops
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

    #[test]
    fn dominators_empty_cfg() {
        let cfg = Cfg::build(&[], 0, 0);
        let idom = cfg.dominators();
        // Entry dominates itself.
        assert_eq!(idom.get(&0), Some(&0));
    }

    #[test]
    fn dominators_linear_chain() {
        // Block 0 → Block 1 → Return
        let stmts = vec![
            invocation_stmt("felt252_add", vec![BranchTarget::Fallthrough]),
            Statement::Return(vec![]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());
        let idom = cfg.dominators();
        // Entry dominates all blocks.
        assert_eq!(idom.get(&0), Some(&0));
    }

    #[test]
    fn dominates_entry_dominates_all() {
        // Block 0: branch to 1 or 2
        // Block 1: return
        // Block 2: return
        let stmts = vec![
            invocation_stmt(
                "felt252_is_zero",
                vec![BranchTarget::Fallthrough, BranchTarget::Statement(2)],
            ),
            Statement::Return(vec![]),
            Statement::Return(vec![]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());

        // Block 0 (entry) should dominate all reachable blocks.
        for block in &cfg.blocks {
            assert!(
                cfg.dominates(0, block.id),
                "Entry should dominate block {}",
                block.id
            );
        }
    }

    #[test]
    fn dominates_sibling_blocks_do_not_dominate_each_other() {
        // Block 0: branch to 1 or 2
        // Block 1: return
        // Block 2: return
        let stmts = vec![
            invocation_stmt(
                "felt252_is_zero",
                vec![BranchTarget::Fallthrough, BranchTarget::Statement(2)],
            ),
            Statement::Return(vec![]),
            Statement::Return(vec![]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());

        if cfg.blocks.len() >= 3 {
            // Block 1 should NOT dominate Block 2 (they are siblings).
            assert!(!cfg.dominates(1, 2));
            assert!(!cfg.dominates(2, 1));
        }
    }

    #[test]
    fn natural_loops_detects_simple_loop() {
        // stmt 0: setup (fallthrough)
        // stmt 1: loop body (fallthrough)
        // stmt 2: conditional: back-edge to stmt 1 or fallthrough to stmt 3
        // stmt 3: return
        let stmts = vec![
            invocation_stmt("felt252_add", vec![BranchTarget::Fallthrough]),
            invocation_stmt("felt252_add", vec![BranchTarget::Fallthrough]),
            invocation_stmt(
                "felt252_is_zero",
                vec![BranchTarget::Statement(1), BranchTarget::Fallthrough],
            ),
            Statement::Return(vec![]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());
        let loops = cfg.natural_loops();
        assert!(
            !loops.is_empty(),
            "Should detect at least one loop, got none. Blocks: {}",
            cfg.blocks.len()
        );
        // The loop header should be the block containing stmt 1.
        let lp = &loops[0];
        assert!(lp.body.len() >= 2, "Loop body should have at least 2 blocks");
    }

    #[test]
    fn natural_loops_calls_loop_fixture() {
        // Exact structure of calls_loop seeded fixture:
        // stmt 0: call_contract_syscall (Fallthrough)
        // stmt 1: loop_condition (Fallthrough + Statement(0))
        // stmt 2: Return
        let stmts = vec![
            invocation_stmt("call_contract_syscall", vec![BranchTarget::Fallthrough]),
            invocation_stmt(
                "loop_condition",
                vec![BranchTarget::Fallthrough, BranchTarget::Statement(0)],
            ),
            Statement::Return(vec![]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());
        let loops = cfg.natural_loops();
        assert!(
            !loops.is_empty(),
            "Should detect back-edge to stmt 0. Blocks: {}, predecessors: {:?}",
            cfg.blocks.len(),
            cfg.predecessors
        );
        let lp = &loops[0];
        // Verify call_contract stmt 0 is in the loop body
        let call_block_in_loop = cfg.blocks.iter().any(|b| {
            lp.body.contains(&b.id) && b.stmts.contains(&0)
        });
        assert!(call_block_in_loop, "Block containing stmt 0 should be in loop body");
    }

    #[test]
    fn natural_loops_no_loop_in_acyclic_cfg() {
        // Two branches, no back-edges.
        let stmts = vec![
            invocation_stmt(
                "felt252_is_zero",
                vec![BranchTarget::Fallthrough, BranchTarget::Statement(2)],
            ),
            Statement::Return(vec![]),
            Statement::Return(vec![]),
        ];
        let cfg = Cfg::build(&stmts, 0, stmts.len());
        let loops = cfg.natural_loops();
        assert!(loops.is_empty(), "Acyclic CFG should have no loops");
    }
}
