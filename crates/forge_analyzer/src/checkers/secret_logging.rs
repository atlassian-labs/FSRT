use std::{
    cell::RefCell,
    collections::{BTreeSet, HashSet},
    fmt,
    hash::{Hash, Hasher},
    ops::ControlFlow,
    path::PathBuf,
    rc::Rc,
};

use smallvec::SmallVec;
use tracing::warn;

use crate::{
    definitions::DefId,
    interp::{Checker, Interp, JoinSemiLattice, Runner, WithCallStack},
    ir::{
        BasicBlockId, BinOp, ConsoleMethod, Inst, Intrinsic, Location, Operand, Projection, Rvalue,
    },
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{
        FlowFacts, FlowValue, Taint, TaintDataflow, TaintPolicy, TaintReader, UnresolvedCall,
        visit_taint_call,
    },
};

const SOURCES: &str = "@forge/kvs kvs.getSecret or @forge/api storage.getSecret";

/// Property-name suffixes that mark a secret.
pub const DEFAULT_SECRET_SUFFIXES: &[&str] = &[
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "privatekey",
];

/// The most characters of a secret a substring can show and still count as
/// partial masking, such as a key's last 4 characters or its public prefix.
const MAX_PARTIAL_MASK_CHARS: f64 = 12.0;

/// Suffixes that never mark a secret, such as pagination cursors.
pub const DEFAULT_EXCLUDED_SECRET_SUFFIXES: &[&str] = &["pagetoken"];

/// Names compare after lowercasing and removing `_` and `-`, so `api_key`,
/// `apiKey` and `API-KEY` are the same name.
fn normalize(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-'))
        .flat_map(char::to_lowercase)
        .collect()
}

/// Property-name suffixes that mark a secret. The longest matching suffix
/// decides, so an excluded `pagetoken` wins over `token` in `nextPageToken`.
#[derive(Clone, Debug)]
pub struct SecretSuffixes {
    /// Normalized suffixes, longest first, each marking a secret or not.
    suffixes: Vec<(String, bool)>,
}

impl SecretSuffixes {
    pub fn new(
        secret: impl IntoIterator<Item = impl AsRef<str>>,
        excluded: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        let mut suffixes: Vec<_> = excluded
            .into_iter()
            .map(|suffix| (normalize(suffix.as_ref()), false))
            .chain(
                secret
                    .into_iter()
                    .map(|suffix| (normalize(suffix.as_ref()), true)),
            )
            .filter(|(suffix, _)| !suffix.is_empty())
            .collect();
        // A stable sort keeps an exclusion ahead of the same secret suffix.
        suffixes.sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
        Self { suffixes }
    }

    pub fn matches(&self, name: &str) -> bool {
        let name = normalize(name);
        self.suffixes
            .iter()
            .find(|(suffix, _)| name.ends_with(suffix.as_str()))
            .is_some_and(|&(_, secret)| secret)
    }
}

impl Default for SecretSuffixes {
    fn default() -> Self {
        Self::new(DEFAULT_SECRET_SUFFIXES, DEFAULT_EXCLUDED_SECRET_SUFFIXES)
    }
}

/// How reading a property of a secret is treated.
#[derive(Clone, Debug, Default)]
pub enum PropertyReads {
    /// v0: property reads, indexes and destructured bindings are clean.
    #[default]
    Clean,
    /// v1: a written property keeps its own taint. Other properties read from a
    /// secret stay tracked, but only report when the last property name matches
    /// a secret suffix, as in `secret[account].password`.
    Named(SecretSuffixes),
}

/// Values returned by Forge secret storage reads are sources, and console
/// arguments are sinks.
#[derive(Clone, Debug, Default)]
pub struct SecretTaint {
    property_reads: PropertyReads,
    /// Partial masks already warned about, shared by every entrypoint's copy.
    masked: Rc<RefCell<BTreeSet<(DefId, Location)>>>,
}

/// Possible exposure classes, kept independently from source provenance.
/// A singleton Secret is a definite secret pattern; Public | Secret is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretFacts(u8);

impl SecretFacts {
    fn classes(self) -> impl Iterator<Item = Taint> {
        [Taint::No, Taint::Unknown, Taint::Yes]
            .into_iter()
            .filter(move |class| self.0 & (1 << *class as u8) != 0)
    }
    fn reports(self) -> bool {
        self.0 & 4 != 0
    }
    fn definite_secret(self) -> bool {
        self.0 == 4
    }
}

impl JoinSemiLattice for SecretFacts {
    const BOTTOM: Self = Self(0);
    fn join(&self, other: &Self) -> Self {
        Self(self.0 | other.0)
    }
    fn join_changed(&mut self, other: &Self) -> bool {
        let next = self.join(other);
        let changed = *self != next;
        *self = next;
        changed
    }
}

impl FlowFacts for SecretFacts {
    fn from_taint(taint: Taint) -> Self {
        Self(1 << taint as u8)
    }
    fn combine(&self, other: &Self) -> Self {
        self.classes()
            .flat_map(|left| other.classes().map(move |right| left.join(&right)))
            .fold(Self::BOTTOM, |facts, class| {
                facts.join(&Self::from_taint(class))
            })
    }
}

type SecretValue = FlowValue<SecretFacts>;

impl TaintPolicy for SecretTaint {
    type Facts = SecretFacts;

    fn intrinsic_value(&self, intrinsic: &Intrinsic) -> SecretValue {
        if matches!(intrinsic, Intrinsic::SecretRead) {
            FlowValue::from_taint(Taint::Yes)
        } else {
            FlowValue::default()
        }
    }

    fn is_violation(&self, inst: &Inst, values: &TaintReader<'_, Self>) -> bool {
        matches!(inst.rvalue(), Rvalue::Intrinsic(Intrinsic::ConsoleLog(_), args)
            if args.iter().any(|arg| values.operand(arg).facts.reports()))
    }

    fn tracks_fields(&self) -> bool {
        matches!(self.property_reads, PropertyReads::Named(_))
    }

    fn property_value(&self, base: SecretValue, name: Option<&str>) -> SecretValue {
        let facts = base
            .facts
            .classes()
            .map(|class| match &self.property_reads {
                PropertyReads::Clean => Taint::No,
                PropertyReads::Named(_) if class == Taint::No => Taint::No,
                PropertyReads::Named(suffixes)
                    if name.is_some_and(|name| suffixes.matches(name)) =>
                {
                    Taint::Yes
                }
                PropertyReads::Named(_) => Taint::Unknown,
            })
            .fold(SecretFacts::BOTTOM, |facts, class| {
                facts.join(&SecretFacts::from_taint(class))
            });
        base.with_facts(facts)
    }

    fn binary_value(&self, op: BinOp, left: SecretValue, right: SecretValue) -> SecretValue {
        // A falsy && operand discloses only absence, not its secret contents.
        if op == BinOp::And {
            let mut result = right;
            result.provenance = result.provenance.join(&left.provenance);
            result
        } else if matches!(op, BinOp::Or | BinOp::NullishCoalesce) {
            left.join(&right)
        } else if crate::taint::binary_taint(op, Taint::Yes, Taint::Yes) == Taint::No {
            left.combine(&right)
                .with_facts(SecretFacts::from_taint(Taint::No))
        } else {
            left.combine(&right)
        }
    }

    fn global_call_value(&self, name: &str, path: &[Projection]) -> Option<SecretValue> {
        match (name, path) {
            ("Boolean", []) => Some(FlowValue::default()),
            ("Object", [Projection::Known(method)]) if method == "keys" => {
                Some(FlowValue::default())
            }
            _ => None,
        }
    }

    fn method_value(&self, call: &UnresolvedCall<'_, SecretFacts>) -> Option<SecretValue> {
        // Partial masking, such as `${key.slice(0, 4)}...${key.slice(-4)}`, shows
        // a few characters of a secret. Treat it as redaction for now, but warn,
        // since it still discloses part of the secret.
        if let Some(len) = call
            .max_substring_len()
            .filter(|&len| len <= MAX_PARTIAL_MASK_CHARS)
        {
            if call.receiver.facts.reports() && self.masked.borrow_mut().insert(call.site()) {
                let (_, location) = call.site();
                warn!(
                    "{}: treating `{}` of a secret as partial masking (at most {len} characters) at {location:?}",
                    call.function(),
                    call.method,
                );
            }
            return Some(FlowValue::default());
        }
        let (method, receiver, args) = (call.method, &call.receiver, call.args);
        // Splitting on or replacing the secret itself redacts it from the
        // receiver: `text.split(secret).join('[REDACTED]')` or
        // `url.replace(key, '***')`. The pattern never reaches the result, and
        // the receiver is assumed to hold no other secret.
        let remaining = if args
            .first()
            .is_some_and(|value| value.facts.definite_secret())
        {
            receiver.with_facts(SecretFacts::from_taint(Taint::No))
        } else {
            receiver.clone()
        };
        match (method, args) {
            ("split", [_, ..]) => Some(remaining),
            ("replace" | "replaceAll", [_, replacement]) => Some(remaining.combine(replacement)),
            // An outbound call's return value is a response, never a verbatim
            // copy of the request that carried the secret: `fetch`/`forgeFetch`
            // (bare, imported, or `@forge/api`'s wrapper) and the `@forge/api`
            // request helpers all report their own result, not their inputs.
            (
                "fetch" | "forgeFetch" | "invokeRemote" | "requestJira" | "requestConfluence"
                | "requestBitbucket" | "requestGraph",
                _,
            ) => Some(FlowValue::default()),
            // A one-way digest/signature doesn't disclose its input.
            ("sign" | "digest", _) => Some(FlowValue::default()),
            _ => None,
        }
    }
}

#[derive(Default)]
pub struct SecretLoggingChecker {
    vulns: Vec<SecretLoggingVuln>,
    reported: HashSet<(DefId, Location)>,
    policy: SecretTaint,
}

impl SecretLoggingChecker {
    pub fn new(property_reads: PropertyReads) -> Self {
        Self {
            policy: SecretTaint {
                property_reads,
                ..SecretTaint::default()
            },
            ..Self::default()
        }
    }

    pub fn into_vulns(self) -> impl IntoIterator<Item = SecretLoggingVuln> {
        self.vulns
    }
}

pub struct SecretLoggingVuln {
    file: PathBuf,
    function: String,
    body: DefId,
    stack: String,
    location: Location,
    sink: ConsoleMethod,
}

impl fmt::Display for SecretLoggingVuln {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret logged to {}", self.sink)
    }
}

impl WithCallStack for SecretLoggingVuln {
    fn add_call_stack(&mut self, _stack: Vec<DefId>) {}
}

impl IntoVuln for SecretLoggingVuln {
    fn into_vuln(self, reporter: &Reporter) -> Vulnerability {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.file.hash(&mut hasher);
        self.function.hash(&mut hasher);
        self.body.hash(&mut hasher);
        self.location.hash(&mut hasher);
        Vulnerability {
            check_name: format!("Custom-Check-Secret-Logging-{}", hasher.finish()),
            description: format!(
                "A value returned by a Forge secret storage read is logged to {} in {} (entry file {:?}).",
                self.sink, self.function, self.file
            ),
            recommendation: "Remove secrets from console arguments. Log only non-sensitive metadata or an explicitly redacted value.",
            proof: format!(
                "Secret source: {SOURCES}; sink: {}; call path: {}; IR body: {:?} ({}); IR location: {:?}.",
                self.sink, self.stack, self.body, self.function, self.location
            ),
            severity: Severity::High,
            marketplace_security_requirement: "Requirement 5",
            app_key: reporter.app_key().to_owned(),
            app_name: reporter.app_name().to_owned(),
            date: reporter.current_date(),
        }
    }
}

impl<'cx> Runner<'cx> for SecretLoggingChecker {
    type State = Vec<Taint>;
    type Dataflow = TaintDataflow<SecretTaint>;
    const NAME: &'static str = "SecretLogging";
    const VISIT_GLOBALS: bool = true;

    fn dataflow(&self, _interp: &Interp<'cx, Self>) -> Self::Dataflow {
        TaintDataflow::new(self.policy.clone())
    }

    fn visit_intrinsic(
        &mut self,
        _interp: &Interp<'cx, Self>,
        _intrinsic: &'cx Intrinsic,
        _def: DefId,
        state: &Self::State,
        _operands: Option<SmallVec<[Operand; 4]>>,
    ) -> ControlFlow<(), Self::State> {
        ControlFlow::Continue(state.clone())
    }

    fn visit_call(
        &mut self,
        interp: &Interp<'cx, Self>,
        callee: &'cx Operand,
        _args: &'cx [Operand],
        block: BasicBlockId,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        visit_taint_call(self, interp, callee, block, state)
    }

    fn visit_inst(
        &mut self,
        interp: &Interp<'cx, Self>,
        def: DefId,
        loc: Location,
        inst: &'cx Inst,
        state: &Self::State,
    ) -> ControlFlow<(), Self::State> {
        if let Rvalue::Intrinsic(Intrinsic::ConsoleLog(sink), _) = inst.rvalue()
            && interp.instruction_has_finding(def, loc)
            && self.reported.insert((def, loc))
        {
            let entry = &interp.entry().kind;
            let mut path = vec![match entry {
                crate::interp::EntryKind::Function(name) => name.clone(),
                crate::interp::EntryKind::Resolver(name, method) => format!("{name}.{method}"),
                crate::interp::EntryKind::Empty => String::new(),
            }];
            path.extend(
                interp
                    .callstack()
                    .iter()
                    .map(|frame| interp.env().def_name(frame.calling_function).to_owned()),
            );
            self.vulns.push(SecretLoggingVuln {
                file: interp.entry().file.clone(),
                function: interp.env().def_name(def).to_owned(),
                body: def,
                stack: path.join(" -> "),
                location: loc,
                sink: *sink,
            });
        }
        self.visit_rvalue(interp, inst.rvalue(), def, loc.block, state)
    }
}

impl Checker<'_> for SecretLoggingChecker {
    type Vuln = SecretLoggingVuln;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposure_joins_preserve_alternatives_and_composition_is_distributive() {
        let public = SecretFacts::from_taint(Taint::No);
        let secret = SecretFacts::from_taint(Taint::Yes);
        assert!(public.join(&secret).reports());
        assert!(!public.join(&secret).definite_secret());
        assert!(public.combine(&secret).definite_secret());
        for a in (0..8).map(SecretFacts) {
            assert_eq!(a.join(&SecretFacts::BOTTOM), a);
            assert_eq!(a.join(&a), a);
            for b in (0..8).map(SecretFacts) {
                assert_eq!(a.join(&b), b.join(&a));
                for c in (0..8).map(SecretFacts) {
                    assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
                    assert_eq!(a.combine(&b.join(&c)), a.combine(&b).join(&a.combine(&c)));
                }
            }
        }
    }

    #[test]
    fn secret_suffixes_match_normalized_names_by_longest_suffix() {
        let suffixes = SecretSuffixes::default();
        for name in [
            "password",
            "dbPassword",
            "client_secret",
            "API-KEY",
            "accessToken",
            "privateKey",
        ] {
            assert!(suffixes.matches(name), "{name}");
        }
        for name in [
            "host",
            "tokenType",
            "nextPageToken",
            "page_token",
            "issueKey",
        ] {
            assert!(!suffixes.matches(name), "{name}");
        }

        // An exclusion wins a tie, and empty entries match nothing.
        let suffixes = SecretSuffixes::new(["token", ""], ["token"]);
        assert!(!suffixes.matches("token"));
        assert!(!suffixes.matches("host"));
    }
}
