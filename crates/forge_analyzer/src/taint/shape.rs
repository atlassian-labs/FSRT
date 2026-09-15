//! A finite structural domain. Policies supply automata; the engine only follows
//! edges and preserves a guarantee when all alternatives agree.
use super::{Classification, FlowValue, OriginSite, PolicyFacts, SourceOrigin};
use crate::{definitions::DefId, interp::JoinSemiLattice, ir::Projection};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputRoot {
    pub function: DefId,
    pub argument: DefId,
    pub payload_source: &'static str,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputNode {
    pub classification: Classification,
    pub properties: &'static [(&'static str, usize)],
    pub other: usize,
    pub computed: usize,
    pub source: &'static str,
    /// Object views may be invalidated by mutations or escapes; scalar snapshots
    /// do not alias their former container.
    pub reference: bool,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InputSchema {
    pub name: &'static str,
    pub nodes: &'static [InputNode],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum InputShape {
    Bottom,
    /// No structural information (including provisional unresolved results).
    #[default]
    Absent,
    /// An authoritative input value whose schema guarantee has been lost.
    Unknown,
    Known {
        root: InputRoot,
        schema: &'static InputSchema,
        node: usize,
        invalid: Classification,
    },
}

impl InputShape {
    pub fn without_schema(self) -> Self {
        match self {
            Self::Known { .. } | Self::Unknown => Self::Unknown,
            _ => Self::Absent,
        }
    }
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::Known { .. } | Self::Unknown)
    }
}

impl JoinSemiLattice for InputShape {
    const BOTTOM: Self = Self::Bottom;
    fn join(&self, other: &Self) -> Self {
        if *self == Self::Bottom {
            return *other;
        }
        if *other == Self::Bottom || self == other {
            return *self;
        }
        if *self == Self::Absent || *other == Self::Absent {
            return Self::Absent;
        }
        if let (
            Self::Known {
                root,
                schema,
                node,
                invalid,
            },
            Self::Known {
                root: right_root,
                schema: right_schema,
                node: right_node,
                invalid: right_invalid,
            },
        ) = (*self, *other)
            && root == right_root
            && schema == right_schema
            && node == right_node
        {
            return Self::Known {
                root,
                schema,
                node,
                invalid: invalid.join(&right_invalid),
            };
        }
        // Different roots also lose the guarantee: keeping an arbitrary identity
        // here would make subsequent alias invalidation unsound.
        Self::Unknown
    }
    fn join_changed(&mut self, other: &Self) -> bool {
        let next = self.join(other);
        let changed = *self != next;
        *self = next;
        changed
    }
}

impl<F: PolicyFacts> FlowValue<F> {
    pub fn project(&self, path: &[Projection]) -> Self {
        let InputShape::Known {
            root,
            schema,
            mut node,
            invalid,
        } = self.shape
        else {
            let mut value = self.clone();
            if !path.is_empty() && value.shape == InputShape::Unknown {
                value.taint.classification =
                    value.taint.classification.join(&Classification::Unknown);
                value.facts = F::from_classification(value.taint.classification);
            }
            return value;
        };
        if path.is_empty() {
            return self.clone();
        }
        for property in path {
            let current = &schema.nodes[node];
            node = match property {
                Projection::Known(name) => current
                    .properties
                    .iter()
                    .find_map(|(key, target)| (*key == name.as_ref()).then_some(*target))
                    .unwrap_or(current.other),
                Projection::Computed(_) => current.computed,
            };
        }
        let selected = &schema.nodes[node];
        let source = if selected.source == "entry.payload" {
            root.payload_source
        } else {
            selected.source
        };
        let mut value = Self::source(
            selected.classification.join(&invalid),
            SourceOrigin {
                source,
                function: root.function,
                site: OriginSite::Argument(root.argument),
            },
        );
        for origin in self.taint.origins.iter() {
            // Re-label this root's selected category, preserving independent
            // evidence. An envelope is not payload evidence for a context leaf.
            if origin.function != root.function
                || origin.site != OriginSite::Argument(root.argument)
            {
                value.taint.origins.insert(*origin);
            }
        }
        if selected.reference {
            value.references = self.references.clone();
        }
        value.shape = InputShape::Known {
            root,
            schema,
            node,
            invalid,
        };
        value
    }
}
