use super::value::{Classification, OriginSite, SourceOrigin};
use crate::{
    definitions::{DefId, Environment},
    ir::{Base, Body, Inst, Intrinsic, Location, Operand, Projection, Rvalue, VarKind, Variable},
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
/// Rules are ordered: specific platform properties precede broad input rules.
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

fn context_property<'a>(context: &SourceContext<'a>) -> Option<Option<&'a str>> {
    let (arg, variable) = context.argument?;
    // Preserve the existing supported context-projection behavior. This is a
    // platform source convention, not a property-name sanitizer.
    let names = variable
        .projections
        .iter()
        .filter_map(|p| match p {
            Projection::Known(name) => Some(name.as_ref()),
            Projection::Computed(_) => None,
        })
        .collect::<Vec<_>>();
    if context.env.def_name(arg) == "context" {
        Some(names.first().copied())
    } else if names.first() == Some(&"context") {
        Some(names.get(1).copied())
    } else {
        None
    }
}
fn is_payload(context: &SourceContext<'_>) -> bool {
    context.argument.is_some_and(|(arg, variable)| {
        context.env.def_name(arg) == "payload"
            || variable
                .projections
                .iter()
                .any(|p| matches!(p, Projection::Known(name) if name == "payload"))
    })
}

pub static FORGE_SOURCES: &[SourceDefinition] = &[
    SourceDefinition {
        id: "forge.context.approved",
        label: "resolver context",
        classification: Classification::Trusted,
        matches: |ctx| {
            matches!(
                context_property(ctx),
                Some(Some(
                    "installContext" | "accountId" | "license" | "jobId" | "installation"
                ))
            )
        },
    },
    SourceDefinition {
        id: "forge.context.unknown",
        label: "resolver context",
        classification: Classification::Unknown,
        matches: |ctx| context_property(ctx).is_some(),
    },
    SourceDefinition {
        id: "forge.resolver.payload",
        label: "resolver payload",
        classification: Classification::Untrusted,
        matches: |ctx| ctx.is_resolver && is_payload(ctx),
    },
    SourceDefinition {
        id: "http.request",
        label: "HTTP request data",
        classification: Classification::Untrusted,
        matches: |ctx| {
            ctx.argument
                .is_some_and(|(arg, _)| matches!(ctx.env.def_name(arg), "req" | "request"))
        },
    },
    SourceDefinition {
        id: "entry.payload",
        label: "entrypoint input",
        classification: Classification::Untrusted,
        matches: is_payload,
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
