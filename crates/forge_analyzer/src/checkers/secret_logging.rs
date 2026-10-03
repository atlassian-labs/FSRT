use std::{
    collections::HashSet,
    fmt,
    hash::{Hash, Hasher},
    ops::ControlFlow,
    path::PathBuf,
};

use smallvec::SmallVec;

use crate::{
    definitions::DefId,
    interp::{Checker, Interp, JoinSemiLattice, Runner, WithCallStack},
    ir::{BasicBlockId, ConsoleMethod, Inst, Intrinsic, Location, Operand, Rvalue},
    reporter::{IntoVuln, Reporter, Severity, Vulnerability},
    taint::{Taint, TaintDataflow, TaintPolicy, TaintReader, visit_taint_call},
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
}

impl TaintPolicy for SecretTaint {
    fn intrinsic_taint(&self, intrinsic: &Intrinsic) -> Taint {
        if matches!(intrinsic, Intrinsic::SecretRead) {
            Taint::Yes
        } else {
            Taint::No
        }
    }

    fn is_violation(&self, inst: &Inst, values: &TaintReader<'_, Self>) -> bool {
        matches!(inst.rvalue(), Rvalue::Intrinsic(Intrinsic::ConsoleLog(_), args)
            if args.iter().any(|arg| values.operand(arg) == Taint::Yes))
    }

    fn tracks_fields(&self) -> bool {
        matches!(self.property_reads, PropertyReads::Named(_))
    }

    fn property_taint(&self, base: Taint, name: Option<&str>) -> Taint {
        match &self.property_reads {
            // Without field tracking, a secret stored in one field would taint
            // every sibling ID, URL and count, so only whole values report.
            PropertyReads::Clean => Taint::No,
            PropertyReads::Named(_) if base == Taint::No => Taint::No,
            PropertyReads::Named(suffixes) if name.is_some_and(|name| suffixes.matches(name)) => {
                Taint::Yes
            }
            // Apps also keep ordinary settings in secret storage: keep tracking
            // the value, but only a secret-named property reports.
            PropertyReads::Named(_) => Taint::Unknown,
        }
    }

    fn method_taint(&self, method: &str, receiver: Taint, args: &[Taint]) -> Option<Taint> {
        // Splitting on or replacing the secret itself redacts it from the
        // receiver: `text.split(secret).join('[REDACTED]')` or
        // `url.replace(key, '***')`. The pattern never reaches the result, and
        // the receiver is assumed to hold no other secret.
        let remaining = if args.first() == Some(&Taint::Yes) {
            Taint::No
        } else {
            receiver
        };
        match (method, args) {
            ("split", [_, ..]) => Some(remaining),
            ("replace" | "replaceAll", [_, replacement]) => Some(remaining.join(replacement)),
            // An outbound call's return value is a response, never a verbatim
            // copy of the request that carried the secret: `fetch`/`forgeFetch`
            // (bare, imported, or `@forge/api`'s wrapper) and the `@forge/api`
            // request helpers all report their own result, not their inputs.
            (
                "fetch" | "forgeFetch" | "invokeRemote" | "requestJira" | "requestConfluence"
                | "requestBitbucket" | "requestGraph",
                _,
            ) => Some(Taint::No),
            // `Object.keys()` returns property names, never the values; a
            // one-way digest/signature doesn't disclose its input.
            ("keys" | "sign" | "digest", _) => Some(Taint::No),
            // `Boolean(secret)` and friends coerce to a flag, not the value.
            ("Boolean", _) => Some(Taint::No),
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
            policy: SecretTaint { property_reads },
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
