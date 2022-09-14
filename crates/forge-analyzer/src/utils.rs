// Copyright 2022 Joshua Wong.
// SPDX-License-Identifier: Apache-2.0

use std::hash::BuildHasherDefault;

use indexmap::{IndexMap, IndexSet};
use rustc_hash::FxHasher;

pub type FxIndexMap<K, V> = IndexMap<K, V, BuildHasherDefault<FxHasher>>;
pub type FxIndexSet<T> = IndexSet<T, BuildHasherDefault<FxHasher>>;

pub use rustc_hash::{FxHashMap, FxHashSet};
