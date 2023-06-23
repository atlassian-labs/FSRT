use std::{borrow::Borrow, collections::VecDeque, hash::Hash};

use forge_utils::FxHashSet;
use tracing::debug;

use crate::{
    definitions::{DefId, Environment},
    ir::BasicBlockId,
};

#[derive(Debug, Clone)]
pub struct WorkList<V, W> {
    worklist: VecDeque<(V, W, Vec<V>)>,
    visited: FxHashSet<V>,
}

impl<V, W> WorkList<V, W>
where
    V: Eq + Hash,
{
    #[inline]
    pub fn new() -> Self {
        Self {
            worklist: VecDeque::new(),
            visited: FxHashSet::default(),
        }
    }

    #[inline]
    pub fn pop_front(&mut self) -> (Option<(V, W, Vec<V>)>) {
        self.worklist.pop_front()
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

impl<V, W> WorkList<V, W>
where
    V: Eq + Hash + Copy,
{
    #[inline]
    pub fn push_back(&mut self, v: V, w: W, args: Vec<V>) {
        if self.visited.insert(v) {
            self.worklist.push_back((v, w, args));
        }
    }

    #[inline]
    pub fn push_back_force(&mut self, v: V, w: W, args: Vec<V>) {
        self.worklist.push_back((v, w, args));
    }
}

impl WorkList<DefId, BasicBlockId> {
    #[inline]
    pub(crate) fn push_front_blocks(
        &mut self,
        env: &Environment,
        def: DefId,
        arguments: Vec<DefId>,
    ) -> bool {
        if self.visited.insert(def) {
            debug!("adding function: {}", env.def_name(def));
            let body = env.def_ref(def).expect_body();
            let blocks = body.iter_block_keys().map(|bb| (def, bb)).rev();
            self.worklist.reserve(blocks.len());
            for work in blocks {
                debug!(?work, "push_front_blocks");
                self.worklist
                    .push_front((work.0, work.1, arguments.clone()));
            }
            return true;
        }
        false
    }
}

impl<V, W> Extend<(V, W, Vec<V>)> for WorkList<V, W>
where
    V: Eq + Hash,
{
    #[inline]
    fn extend<T: IntoIterator<Item = (V, W, Vec<V>)>>(&mut self, iter: T) {
        self.worklist.extend(iter);
    }
}
