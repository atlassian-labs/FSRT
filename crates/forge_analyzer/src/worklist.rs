use std::{borrow::Borrow, collections::VecDeque, hash::Hash};

use forge_utils::FxHashSet;
use tracing::debug;

use crate::{
    definitions::{DefId, Environment},
    ir::BasicBlockId,
};

#[derive(Debug, Clone)]
pub struct WorkList<V, W> {
    pub worklist: VecDeque<(V, W)>,
    pub visited: FxHashSet<V>,
    pending: FxHashSet<(V, W)>,
}

impl<V, W> WorkList<V, W>
where
    V: Eq + Hash,
    W: Eq + Hash,
{
    #[inline]
    pub fn new() -> Self {
        Self {
            worklist: VecDeque::new(),
            visited: FxHashSet::default(),
            pending: FxHashSet::default(),
        }
    }

    #[inline]
    pub fn pop_front(&mut self) -> Option<(V, W)> {
        let work = self.worklist.pop_front()?;
        self.pending.remove(&work);
        Some(work)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.worklist.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.worklist.is_empty()
    }

    #[inline]
    pub fn reserve(&mut self, n: usize) {
        self.worklist.reserve(n);
        self.pending.reserve(n);
    }

    #[inline]
    pub fn visited<Q>(&self, key: &Q) -> bool
    where
        V: Borrow<Q>,
        Q: Eq + Hash + ?Sized,
    {
        self.visited.contains(key)
    }
}

impl<V, W> Default for WorkList<V, W>
where
    V: Eq + Hash,
    W: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<V, W> WorkList<V, W>
where
    V: Eq + Hash + Copy,
    W: Eq + Hash + Copy,
{
    #[inline]
    pub fn push_back(&mut self, v: V, w: W) {
        if self.visited.insert(v) && self.pending.insert((v, w)) {
            self.worklist.push_back((v, w));
        }
    }

    #[inline]
    pub fn push_back_force(&mut self, v: V, w: W) {
        if self.pending.insert((v, w)) {
            self.worklist.push_back((v, w));
        }
    }
}

impl WorkList<DefId, BasicBlockId> {
    #[inline]
    pub(crate) fn push_front_blocks(
        &mut self,
        env: &Environment,
        def: DefId,
        visit_all: bool,
    ) -> bool {
        if self.visited.insert(def) || visit_all {
            debug!("adding function: {}", env.def_name(def));
            let body = env.def_ref(def).expect_body();
            let blocks = body.iter_block_keys().map(|bb| (def, bb)).rev();
            self.worklist.reserve(blocks.len());
            for work in blocks {
                if self.pending.insert(work) {
                    debug!(?work, "push_front_blocks");
                    self.worklist.push_front(work);
                }
            }
            return true;
        }
        false
    }

    #[inline]
    pub(crate) fn push_back_blocks(
        &mut self,
        env: &Environment,
        def: DefId,
        visit_all: bool,
    ) -> bool {
        if self.visited.insert(def) || visit_all {
            debug!("adding function: {}", env.def_name(def));
            let body = env.def_ref(def).expect_body();
            self.worklist.reserve(body.iter_block_keys().len());
            for bb in body.iter_block_keys() {
                let work = (def, bb);
                if self.pending.insert(work) {
                    debug!(?work, "push_back_blocks");
                    self.worklist.push_back(work);
                }
            }
            return true;
        }
        false
    }
}

impl<V, W> Extend<(V, W)> for WorkList<V, W>
where
    V: Eq + Hash + Copy,
    W: Eq + Hash + Copy,
{
    #[inline]
    fn extend<T: IntoIterator<Item = (V, W)>>(&mut self, iter: T) {
        for (v, w) in iter {
            self.push_back_force(v, w);
        }
    }
}

#[cfg(test)]
mod tests;
