// Copyright 2022 Joshua Wong.
// SPDX-License-Identifier: Apache-2.0

use std::hash::BuildHasherDefault;

use indexmap::{IndexMap, IndexSet};
use rustc_hash::FxHasher;

pub type FxIndexMap<K, V> = IndexMap<K, V, BuildHasherDefault<FxHasher>>;
pub type FxIndexSet<T> = IndexSet<T, BuildHasherDefault<FxHasher>>;

pub use rustc_hash::{FxHashMap, FxHashSet};

#[macro_export]
macro_rules! create_newtype {
    ($vis:vis struct $ident:ident ( $tyvis:vis $ty:ty );) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        $vis struct $ident($tyvis $ty);

        impl ::core::convert::From<usize> for $ident {
            fn from(n: usize) -> $ident {
                $ident(n as $ty)
            }
        }

        impl ::core::convert::From<$ident> for usize {
            fn from(id: $ident) -> usize {
                id.0 as usize
            }
        }
    };
}
