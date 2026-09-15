use super::value::{Classification, OriginSite, SourceOrigin};
use crate::{
    definitions::{DefId, Environment},
    ir::{Base, Body, Inst, Intrinsic, Location, Operand, Rvalue, VarKind, Variable},
};

pub struct SourceContext<'a> {
    pub env: &'a Environment,
    pub body: &'a Body,
    pub function: DefId,
    pub location: Location,
    pub is_resolver: bool,
    pub argument: Option<(DefId, &'a Variable)>,
    pub intrinsic: Option<&'a Intrinsic>,
    pub call: Option<(&'a Operand, &'a [Operand])>,
}

/// One definition owns source recognition, default trust, and its evidence label.
/// Invocation entries provide labels; explicit root contracts seed their facts.
/// Predicates recognize result sources and unresolved argument evidence.
pub struct SourceDefinition {
    pub id: &'static str,
    pub label: &'static str,
    pub classification: Classification,
    pub matches: fn(&SourceContext<'_>) -> bool,
}
impl SourceDefinition {
    pub fn origin(&self, context: &SourceContext<'_>) -> SourceOrigin {
        SourceOrigin {
            source: self.id,
            function: context.function,
            site: context.argument.map_or(
                OriginSite::Instruction(context.location),
                |(arg, variable)| {
                    // Destructured parameters have an anonymous root in the IR.
                    // Attribute them to the declared binding and its span when one
                    // reads the matching parameter projection.
                    let named = context
                        .body
                        .iter_blocks_enumerated()
                        .flat_map(|(_, block)| block.iter())
                        .filter_map(|inst| {
                            let Inst::Assign(target, Rvalue::Read(Operand::Var(source))) = inst
                            else {
                                return None;
                            };
                            if source.base != variable.base
                                || source.projections.is_empty()
                                || !variable.projections.starts_with(&source.projections)
                            {
                                return None;
                            }
                            let Base::Var(target_var) = target.base else {
                                return None;
                            };
                            let Some(VarKind::Arg(binding) | VarKind::GlobalRef(binding)) =
                                context.body.vars.get(target_var)
                            else {
                                return None;
                            };
                            context
                                .body
                                .argument_span(*binding)
                                .map(|_| (source.projections.len(), *binding))
                        })
                        .max_by_key(|(length, _)| *length)
                        .map(|(_, binding)| binding);
                    OriginSite::Argument(named.unwrap_or(arg))
                },
            ),
        }
    }
}

pub static FORGE_SOURCES: &[SourceDefinition] = &[
    SourceDefinition {
        id: "forge.context.approved",
        label: "Forge invocation context",
        classification: Classification::Trusted,
        matches: |_| false,
    },
    SourceDefinition {
        id: "forge.context.unknown",
        label: "Forge invocation context",
        classification: Classification::Unknown,
        matches: |_| false,
    },
    SourceDefinition {
        id: "forge.resolver.payload",
        label: "resolver payload",
        classification: Classification::Untrusted,
        matches: |_| false,
    },
    SourceDefinition {
        id: "http.request",
        label: "HTTP request data",
        classification: Classification::Untrusted,
        matches: |_| false,
    },
    SourceDefinition {
        id: "forge.product.event",
        label: "product event payload",
        classification: Classification::Untrusted,
        matches: |_| false,
    },
    SourceDefinition {
        id: "entry.payload",
        label: "entrypoint input",
        classification: Classification::Untrusted,
        matches: |_| false,
    },
    SourceDefinition {
        id: "entry.unknown",
        label: "entrypoint or propagated input",
        classification: Classification::Unknown,
        matches: |ctx| ctx.argument.is_some(),
    },
    SourceDefinition {
        id: "network.response",
        label: "external network response",
        classification: Classification::Untrusted,
        matches: |ctx| matches!(ctx.intrinsic, Some(Intrinsic::Fetch)),
    },
    SourceDefinition {
        id: "forge.api.response",
        label: "Atlassian API response",
        classification: Classification::Untrusted,
        matches: |ctx| {
            matches!(
                ctx.intrinsic,
                Some(
                    Intrinsic::ApiCall(_)
                        | Intrinsic::SafeCall(_)
                        | Intrinsic::ApiCustomField
                        | Intrinsic::UserFieldAccess
                )
            )
        },
    },
    SourceDefinition {
        id: "forge.storage.read",
        label: "Forge storage read",
        classification: Classification::Untrusted,
        matches: |ctx| matches!(ctx.intrinsic, Some(Intrinsic::StorageRead)),
    },
];

use super::{FlowValue, InputNode, InputRoot, InputSchema, InputShape, PolicyFacts};
use crate::interp::InvocationContract;

/// Only invocation discovery may request a platform seed. Helpers receive their
/// callers' values, and unresolved invocations receive no schema guarantee.
pub(crate) fn root_argument<F: PolicyFacts>(
    contract: InvocationContract,
    position: usize,
    function: DefId,
    argument: DefId,
) -> FlowValue<F> {
    let (schema, node) = match (contract, position) {
        (InvocationContract::ForgeFunction, 0) => (&ORDINARY_INPUT, 2),
        (InvocationContract::ForgeFunction, 1) => (&ORDINARY_INPUT, 0),
        (InvocationContract::ResolverCallback, 0) => (&RESOLVER_INPUT, 6),
        _ => {
            let mut value = FlowValue::source(
                Classification::Unknown,
                SourceOrigin {
                    source: "entry.unknown",
                    function,
                    site: OriginSite::Argument(argument),
                },
            );
            value.shape = InputShape::Unknown;
            return value;
        }
    };
    let mut value = FlowValue::source(
        schema.nodes[node].classification,
        SourceOrigin {
            source: schema.nodes[node].source,
            function,
            site: OriginSite::Argument(argument),
        },
    );
    let root = InputRoot {
        function,
        argument,
        payload_source: schema.nodes[node].source,
    };
    value.references.insert(root);
    value.shape = InputShape::Known {
        root,
        schema,
        node,
        invalid: Classification::Trusted,
    };
    value
}

const APPROVED_SCALAR: InputNode = InputNode {
    classification: Classification::Trusted,
    properties: &[],
    other: 1,
    computed: 1,
    source: "forge.context.approved",
    reference: false,
};

static ORDINARY_INPUT: InputSchema = InputSchema {
    name: "ORDINARY_INPUT",
    nodes: &[
        InputNode {
            classification: Classification::Unknown,
            properties: &[
                ("installContext", 3),
                ("installation", 4),
                ("license", 7),
                ("principal", 8),
            ],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Untrusted,
            properties: &[],
            other: 2,
            computed: 2,
            source: "entry.payload",
            reference: true,
        },
        APPROVED_SCALAR,
        InputNode {
            classification: Classification::Unknown,
            properties: &[("ari", 5)],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[("installationId", 9)],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Untrusted,
            properties: &[("payload", 2), ("context", 0)],
            other: 1,
            computed: 2,
            source: "forge.resolver.payload",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[
                ("active", 11),
                ("billingPeriod", 12),
                ("ccpEntitlementId", 13),
                ("ccpEntitlementSlug", 14),
                ("isEvaluation", 15),
                ("subscriptionEndDate", 16),
                ("supportEntitlementNumber", 17),
                ("trialEndDate", 18),
                ("type", 19),
                ("isActive", 20),
                ("capabilitySet", 21),
            ],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[("accountId", 10)],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
    ],
};

static RESOLVER_INPUT: InputSchema = InputSchema {
    name: "RESOLVER_INPUT",
    nodes: &[
        InputNode {
            classification: Classification::Unknown,
            properties: &[
                ("installContext", 3),
                ("installation", 4),
                ("license", 7),
                ("accountId", 10),
            ],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Untrusted,
            properties: &[],
            other: 2,
            computed: 2,
            source: "forge.resolver.payload",
            reference: true,
        },
        APPROVED_SCALAR,
        InputNode {
            classification: Classification::Unknown,
            properties: &[("ari", 5)],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[("installationId", 9)],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Untrusted,
            properties: &[("payload", 2), ("context", 0)],
            other: 1,
            computed: 2,
            source: "forge.resolver.payload",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[
                ("active", 11),
                ("billingPeriod", 12),
                ("ccpEntitlementId", 13),
                ("ccpEntitlementSlug", 14),
                ("isEvaluation", 15),
                ("subscriptionEndDate", 16),
                ("supportEntitlementNumber", 17),
                ("trialEndDate", 18),
                ("type", 19),
            ],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        InputNode {
            classification: Classification::Unknown,
            properties: &[],
            other: 1,
            computed: 1,
            source: "forge.context.unknown",
            reference: true,
        },
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
        APPROVED_SCALAR,
    ],
};
