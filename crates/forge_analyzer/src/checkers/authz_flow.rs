//! Where does data go, for one resolver entry?
//!
//! A flow-insensitive, alias-unifying may-flow analysis over the IR reachable from
//! one resolver callback. It answers two questions about each privileged request
//! the walk reached:
//!
//! * origin: can a value the caller controls (`payload`), a value the platform
//!   supplies (`context`) or another external value (storage, an `asUser`
//!   response, `fetch`) reach the request's route or body?
//! * exposure: can the request's response reach the value the resolver returns,
//!   the body of another request, an outbound call or persistent state?
//!
//! Soundness is the point, precision a bonus. A conclusion drawn from the absence
//! of a flow is only as good as the analysis is complete, so every value that a
//! construct may copy, store or pass is *unified* with its source (aliases share
//! one class, so a mutation through any alias is seen by all) and only a short list
//! of operations that cannot carry data (comparisons, `typeof`, `length`) cut a
//! flow. Anything the lowering cannot express (see `definitions/authz_lossy.rs`),
//! a request object that escapes the resolver callback, or an exhausted budget
//! makes the whole analysis fail: callers must then keep their findings.

use std::collections::{BTreeSet, VecDeque};

use forge_utils::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use swc_core::ecma::atoms::Atom;

use crate::{
    definitions::{DefId, DefKind, Environment, IntrinsicName},
    ir::{
        Base, BinOp, Body, Inst, Intrinsic, Location, Operand, Projection, Rvalue, UnOp, VarId,
        VarKind, Variable,
    },
};

/// Where a value may come from.
pub(super) mod origin {
    /// The resolver request's `payload`, or anything else the caller controls.
    pub const PAYLOAD: u8 = 1;
    /// The platform's `context`, whose `extension` is the module context of the
    /// page the caller opened.
    pub const CONTEXT: u8 = 2;
    /// Storage, secrets, the environment, `fetch` and `asUser` responses.
    pub const EXTERNAL: u8 = 4;
}

/// Where a value may go.
mod exposure {
    /// The value the resolver returns to the caller.
    pub const RETURN: u8 = 1;
    /// The body of a request, or an argument of a call to a request client.
    pub const BODY: u8 = 2;
    /// An outbound or unknown call, or state that outlives the resolver call.
    pub const EGRESS: u8 = 4;
}

const MAX_FUNCTIONS: usize = 300;

/// A function whose body is part of the analysis: a definition, or a function
/// value passed to a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Func {
    Def(DefId),
    Closure(usize),
}

type Site = (Func, Location);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Node {
    Binding(DefId),
    Temp(Func, VarId),
    Ret(Func),
    Site(Func, Location),
    /// A value read through the request, at one operand of one instruction.
    Source(Func, Location, u8),
    /// Whatever the resolver throws; catch handlers read it.
    Thrown,
}

#[derive(Default)]
struct Meta {
    origin: u8,
    exposure: u8,
    sites: SmallVec<[Site; 1]>,
}

#[derive(Default)]
struct Classes {
    index: FxHashMap<Node, u32>,
    parent: Vec<u32>,
    meta: Vec<Meta>,
}

impl Classes {
    fn id(&mut self, node: Node) -> u32 {
        if let Some(&id) = self.index.get(&node) {
            return id;
        }
        let id = self.parent.len() as u32;
        self.parent.push(id);
        let mut meta = Meta::default();
        if let Node::Site(func, loc) = node {
            meta.sites.push((func, loc));
        }
        self.meta.push(meta);
        self.index.insert(node, id);
        id
    }

    fn find(&mut self, mut id: u32) -> u32 {
        while self.parent[id as usize] != id {
            let grand = self.parent[self.parent[id as usize] as usize];
            self.parent[id as usize] = grand;
            id = grand;
        }
        id
    }

    fn class(&mut self, node: Node) -> u32 {
        let id = self.id(node);
        self.find(id)
    }

    fn unify(&mut self, a: Node, b: Node) {
        let (a, b) = (self.class(a), self.class(b));
        if a == b {
            return;
        }
        let moved = std::mem::take(&mut self.meta[b as usize]);
        self.parent[b as usize] = a;
        let meta = &mut self.meta[a as usize];
        meta.origin |= moved.origin;
        meta.exposure |= moved.exposure;
        meta.sites.extend(moved.sites);
    }

    fn label(&mut self, node: Node, bits: u8) {
        let class = self.class(node);
        self.meta[class as usize].origin |= bits;
    }

    fn expose(&mut self, node: Node, bits: u8) {
        let class = self.class(node);
        self.meta[class as usize].exposure |= bits;
    }
}

/// How one request reads the data it was given.
#[derive(Default)]
struct Request {
    route: Option<Node>,
    rest: Vec<Node>,
}

/// The result of analysing one root.
pub(super) struct Flow {
    classes: Classes,
    requests: FxHashMap<Site, Request>,
}

fn site_of(site: (DefId, Location)) -> Site {
    (Func::Def(site.0), site.1)
}

impl Flow {
    /// The origins that may reach the request's route.
    pub(super) fn route_origin(&mut self, site: (DefId, Location)) -> Option<u8> {
        let node = self.requests.get(&site_of(site))?.route;
        Some(node.map_or(0, |node| self.origin_of(node)))
    }

    /// The origins that may reach anything but the route (the body, options).
    pub(super) fn body_origin(&mut self, site: (DefId, Location)) -> Option<u8> {
        let rest = self.requests.get(&site_of(site))?.rest.clone();
        Some(
            rest.into_iter()
                .fold(0, |bits, node| bits | self.origin_of(node)),
        )
    }

    /// Whether the response may reach the returned value, a request body, an
    /// outbound call or persistent state.
    pub(super) fn response_exposed(&mut self, site: (DefId, Location)) -> Option<bool> {
        let site = site_of(site);
        self.requests.contains_key(&site).then(|| {
            let class = self.classes.class(Node::Site(site.0, site.1));
            self.classes.meta[class as usize].exposure != 0
        })
    }

    fn origin_of(&mut self, node: Node) -> u8 {
        let class = self.classes.class(node);
        self.classes.meta[class as usize].origin
    }
}

/// Names that cannot carry data out of the resolver when called on, or with, data.
const PURE_METHODS: &[&str] = &[
    "json",
    "text",
    "map",
    "filter",
    "find",
    "findIndex",
    "findLast",
    "some",
    "every",
    "includes",
    "indexOf",
    "lastIndexOf",
    "join",
    "split",
    "slice",
    "splice",
    "concat",
    "flat",
    "flatMap",
    "reduce",
    "reduceRight",
    "sort",
    "toSorted",
    "reverse",
    "push",
    "unshift",
    "pop",
    "shift",
    "keys",
    "values",
    "entries",
    "fromEntries",
    "get",
    "has",
    "set",
    "add",
    "delete",
    "trim",
    "toLowerCase",
    "toUpperCase",
    "replace",
    "replaceAll",
    "startsWith",
    "endsWith",
    "substring",
    "substr",
    "toString",
    "at",
    "fill",
    "from",
    "of",
    "assign",
    "stringify",
    "parse",
    "isArray",
    "parseInt",
    "parseFloat",
    "Number",
    "String",
    "Boolean",
    "isNaN",
    "isFinite",
    "floor",
    "ceil",
    "round",
    "max",
    "min",
    "abs",
    "trunc",
    "now",
    "getTime",
    "toISOString",
    "padStart",
    "padEnd",
    "localeCompare",
    "asApp",
    "asUser",
    "route",
    "all",
    "allSettled",
    "resolve",
    "reject",
    "freeze",
    "isInteger",
    "random",
    "encodeURIComponent",
    "decodeURIComponent",
    "encodeURI",
    "decodeURI",
    "toFixed",
    "match",
    "test",
    "exec",
    "forEach",
    "blob",
    "arrayBuffer",
    "toLocaleString",
    "toLocaleDateString",
    "toJSON",
    "valueOf",
];

/// Reads of these properties give numbers or booleans, never the data they
/// summarize.
const SCALAR_PROPERTIES: &[&str] = &["length", "size", "ok", "statusText"];

/// Calls on these imports read state; they do not write what they are given.
const READ_METHODS: &[&str] = &[
    "get",
    "getSecret",
    "query",
    "list",
    "getMany",
    "where",
    "limit",
    "cursor",
    "getItems",
];

fn variable_def(kind: &VarKind) -> Option<DefId> {
    match kind {
        VarKind::Arg(def)
        | VarKind::GlobalRef(def)
        | VarKind::LocalDef(def)
        | VarKind::AnonClosure(def) => Some(*def),
        _ => None,
    }
}

fn node_of(body: &Body, func: Func, id: VarId) -> Node {
    match &body.vars[id] {
        VarKind::Temp { .. } => Node::Temp(func, id),
        VarKind::Ret => Node::Ret(func),
        kind => Node::Binding(variable_def(kind).unwrap()),
    }
}

struct Builder<'a> {
    env: &'a Environment,
    root: DefId,
    classes: Classes,
    requests: FxHashMap<Site, Request>,
    functions: BTreeSet<Func>,
    pending: VecDeque<Func>,
    /// The nodes that name the resolver request itself.
    request: FxHashSet<Node>,
    /// The instruction being read, and how many request reads it has had.
    cursor: (Location, u8),
    incomplete: Option<String>,
}

/// Analyse `root`, a resolver callback. An error means the analysis cannot vouch
/// for the absence of any flow, and says why.
pub(super) fn analyze(env: &Environment, root: DefId) -> Result<Flow, String> {
    let mut builder = Builder {
        env,
        root,
        classes: Classes::default(),
        requests: FxHashMap::default(),
        functions: BTreeSet::new(),
        pending: VecDeque::new(),
        request: FxHashSet::default(),
        cursor: (Location::new(crate::ir::BasicBlockId(0), 0), 0),
        incomplete: None,
    };
    builder.find_request();
    builder.add_function(Func::Def(root));
    // Module initializers hold the values of module-level bindings. They are not
    // checked for lossy lowering: they are not part of any request's flow.
    let globals: Vec<_> = env.global.iter().copied().collect();
    for global in globals {
        builder.process(Func::Def(global), false);
    }
    while let Some(func) = builder.pending.pop_front() {
        if let Some(reason) = builder.incomplete {
            return Err(reason);
        }
        builder.process(func, true);
    }
    if let Some(reason) = builder.incomplete {
        return Err(reason);
    }
    Ok(builder.finish())
}

impl<'a> Builder<'a> {
    fn body(&self, func: Func) -> Option<&'a Body> {
        let env: &'a Environment = self.env;
        match func {
            Func::Def(def) => env.def_ref(def).as_body().copied(),
            Func::Closure(index) => env.authz_closures.get(index),
        }
    }

    fn gap(&mut self, reason: &str) {
        if self.incomplete.is_none() {
            self.incomplete = Some(reason.to_owned());
        }
    }

    fn add_function(&mut self, func: Func) {
        if self.functions.insert(func) {
            if self.functions.len() > MAX_FUNCTIONS {
                self.gap("too many functions");
            }
            self.pending.push_back(func);
        }
    }

    /// The request: the first parameter of the root, the variables that only copy
    /// it (destructuring reads the whole request into a temporary first), and the
    /// parameters of functions it is passed to.
    fn find_request(&mut self) {
        let root = Func::Def(self.root);
        let Some(body) = self.body(root) else {
            return;
        };
        let Some(first) = body
            .vars
            .iter_enumerated()
            .find(|(_, kind)| matches!(kind, VarKind::Arg(_)))
            .map(|(id, _)| node_of(body, root, id))
        else {
            return;
        };
        let mut request: FxHashSet<Node> = FxHashSet::default();
        request.insert(first);
        let mut functions = vec![root];
        let mut seen: FxHashSet<Func> = FxHashSet::default();
        let mut grew = true;
        while grew {
            grew = false;
            seen.clear();
            let mut index = 0;
            while index < functions.len() {
                let func = functions[index];
                index += 1;
                if !seen.insert(func) {
                    continue;
                }
                let Some(body) = self.body(func) else {
                    continue;
                };
                for block in body.blocks.iter() {
                    for inst in block.iter() {
                        match inst {
                            Inst::Assign(lhs, Rvalue::Read(Operand::Var(source)))
                                if lhs.projections.is_empty() && source.projections.is_empty() =>
                            {
                                if let (Base::Var(lhs), Base::Var(source)) = (lhs.base, source.base)
                                    && request.contains(&node_of(body, func, source))
                                {
                                    grew |= request.insert(node_of(body, func, lhs));
                                }
                            }
                            Inst::Assign(_, Rvalue::Call(callee, args))
                            | Inst::Expr(Rvalue::Call(callee, args)) => {
                                let Some((target, target_body)) =
                                    body.resolve_call(self.env, callee)
                                else {
                                    continue;
                                };
                                let params: Vec<DefId> = target_body
                                    .vars
                                    .iter()
                                    .filter_map(|kind| match kind {
                                        VarKind::Arg(param) => Some(*param),
                                        _ => None,
                                    })
                                    .collect();
                                for (arg, param) in args.iter().zip(params) {
                                    if let Operand::Var(var) = arg
                                        && var.projections.is_empty()
                                        && let Base::Var(id) = var.base
                                        && request.contains(&node_of(body, func, id))
                                    {
                                        grew |= request.insert(Node::Binding(param));
                                    }
                                }
                                if !functions.contains(&Func::Def(target)) {
                                    functions.push(Func::Def(target));
                                    grew = true;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
        self.request = request;
    }

    fn node(&mut self, body: &Body, func: Func, var: &Variable) -> Option<Node> {
        match var.base {
            Base::Var(id) => Some(node_of(body, func, id)),
            // `this` and `super` flow through objects this analysis does not track.
            Base::This | Base::Super => {
                self.gap("this");
                None
            }
        }
    }

    /// The node an operand's value lives in. Reading a property of the request
    /// gives a fresh node labelled with where that property comes from; the
    /// request itself cannot be used whole, because `payload` and `context` could
    /// no longer be told apart; reading a number-valued property carries no data.
    fn operand(&mut self, body: &Body, func: Func, operand: &Operand) -> Option<Node> {
        self.operand_or_request(body, func, operand, false)
    }

    /// As `operand`; a function the analysis follows may be handed the request.
    fn operand_or_request(
        &mut self,
        body: &Body,
        func: Func,
        operand: &Operand,
        request_ok: bool,
    ) -> Option<Node> {
        let Operand::Var(var) = operand else {
            return None;
        };
        let node = self.node(body, func, var)?;
        let is_request = self.request.contains(&node);
        if var.projections.is_empty() {
            if is_request && !request_ok {
                self.gap("request escapes");
            }
            return Some(node);
        }
        if is_request {
            let source = Node::Source(func, self.cursor.0, self.cursor.1);
            self.cursor.1 += 1;
            self.classes
                .label(source, Self::request_read(&var.projections));
            return Some(source);
        }
        if let Some(Projection::Known(last)) = var.projections.last()
            && SCALAR_PROPERTIES.contains(&last.as_ref())
        {
            return None;
        }
        // The platform sets `context`, but a caller can name the job.
        if var
            .projections
            .iter()
            .any(|projection| matches!(projection, Projection::Known(name) if name == "jobId"))
        {
            let source = Node::Source(func, self.cursor.0, self.cursor.1);
            self.cursor.1 += 1;
            self.classes.label(source, origin::PAYLOAD);
            return Some(source);
        }
        for projection in &var.projections {
            if let Projection::Computed(Base::Var(key)) = projection {
                self.classes.unify(node, node_of(body, func, *key));
            }
        }
        Some(node)
    }

    fn unify(&mut self, a: Option<Node>, b: Option<Node>) {
        if let (Some(a), Some(b)) = (a, b) {
            self.classes.unify(a, b);
        }
    }

    /// The origin of a read through the request: `payload` is the caller's,
    /// `context` the platform's (but `context.jobId` is not), and every other
    /// property is treated as the caller's.
    fn request_read(projections: &[Projection]) -> u8 {
        match projections.first() {
            Some(Projection::Known(name)) if name == "context" => {
                if matches!(projections.get(1), Some(Projection::Known(job)) if job == "jobId") {
                    origin::PAYLOAD
                } else {
                    origin::CONTEXT
                }
            }
            _ => origin::PAYLOAD,
        }
    }

    fn read(&mut self, body: &Body, func: Func, lhs: Option<Node>, source: &Operand) {
        // Copying the request is not an escape; `find_request` followed the copies.
        if let Operand::Var(var) = source
            && var.projections.is_empty()
            && let Some(node) = self.node(body, func, var)
            && self.request.contains(&node)
        {
            return;
        }
        let value = self.operand(body, func, source);
        self.unify(lhs, value);
    }

    fn process(&mut self, func: Func, tracked: bool) {
        let Some(body) = self.body(func) else {
            return;
        };
        if tracked {
            if let Some(gap) = body.authz_flow_gap {
                self.gap(&format!("lossy lowering: {gap}"));
                return;
            }
            if body.authz_principal_opaque {
                self.gap("opaque function");
                return;
            }
        }
        if func == Func::Def(self.root) {
            self.classes.expose(Node::Ret(func), exposure::RETURN);
        }
        for &index in &body.authz_catches {
            // A catch handler returns from the function that contains it and
            // binds what was thrown.
            self.run(Func::Closure(index), Some(Node::Thrown), None);
            self.unify(Some(Node::Ret(Func::Closure(index))), Some(Node::Ret(func)));
        }
        for (from, to) in &body.authz_flow_links {
            let from = self.operand(body, func, from);
            let to = self.node(body, func, to);
            self.unify(from, to);
        }
        for (block_id, block) in body.iter_blocks_enumerated() {
            if matches!(block.term, crate::ir::Terminator::Throw)
                && let Some(Inst::Expr(Rvalue::Read(thrown))) = block.insts.last()
            {
                self.cursor = (Location::new(block_id, block.insts.len() as u32), 0);
                let thrown = self.operand(body, func, thrown);
                self.unify(thrown, Some(Node::Thrown));
            }
            for (index, inst) in block.iter().enumerate() {
                let loc = Location::new(block_id, index as u32);
                self.cursor = (loc, 0);
                let (lhs, rvalue) = match inst {
                    Inst::Assign(lhs, rvalue) => {
                        let node = self.node(body, func, lhs);
                        // A computed key names a property of what is written to.
                        for projection in &lhs.projections {
                            if let Projection::Computed(Base::Var(key)) = projection {
                                self.unify(node, Some(node_of(body, func, *key)));
                            }
                        }
                        (node, rvalue)
                    }
                    Inst::Expr(rvalue) => (None, rvalue),
                };
                self.rvalue(body, func, loc, lhs, rvalue);
            }
        }
    }

    fn rvalue(
        &mut self,
        body: &Body,
        func: Func,
        loc: Location,
        lhs: Option<Node>,
        rvalue: &Rvalue,
    ) {
        match rvalue {
            Rvalue::Read(source) => self.read(body, func, lhs, source),
            Rvalue::Unary(op, operand) => {
                if !matches!(op, UnOp::Not | UnOp::TypeOf | UnOp::Void | UnOp::Delete) {
                    let operand = self.operand(body, func, operand);
                    self.unify(lhs, operand);
                }
            }
            Rvalue::Bin(op, left, right) => {
                if !matches!(
                    op,
                    BinOp::Lt
                        | BinOp::Gt
                        | BinOp::EqEq
                        | BinOp::Neq
                        | BinOp::NeqEq
                        | BinOp::EqEqEq
                        | BinOp::Ge
                        | BinOp::Le
                        | BinOp::In
                        | BinOp::InstanceOf
                ) {
                    let (left, right) = (
                        self.operand(body, func, left),
                        self.operand(body, func, right),
                    );
                    self.unify(lhs, left);
                    self.unify(lhs, right);
                }
            }
            Rvalue::Phi(vars) => {
                for (var, _) in vars {
                    self.unify(lhs, Some(node_of(body, func, *var)));
                }
            }
            Rvalue::Template(template) => {
                for expr in &template.exprs {
                    let expr = self.operand(body, func, expr);
                    self.unify(lhs, expr);
                }
            }
            Rvalue::Intrinsic(intrinsic, operands) => {
                self.intrinsic(body, func, loc, lhs, intrinsic, operands);
            }
            Rvalue::Call(callee, args) => self.call(body, func, loc, lhs, callee, args),
        }
    }

    fn intrinsic(
        &mut self,
        body: &Body,
        func: Func,
        loc: Location,
        lhs: Option<Node>,
        intrinsic: &Intrinsic,
        operands: &[Operand],
    ) {
        let nodes: Vec<_> = operands
            .iter()
            .map(|operand| self.operand(body, func, operand))
            .collect();
        let site = Node::Site(func, loc);
        match intrinsic {
            Intrinsic::ApiCall(name) | Intrinsic::SafeCall(name) => {
                let is_app = matches!(intrinsic, Intrinsic::ApiCall(_));
                let rest_from = match name {
                    IntrinsicName::RequestJira
                    | IntrinsicName::RequestJiraAny
                    | IntrinsicName::RequestJiraSoftware
                    | IntrinsicName::RequestJiraServiceManagement
                    | IntrinsicName::RequestConfluence
                    | IntrinsicName::RequestBitbucket => 1,
                    // GraphQL and remote calls put data in every argument.
                    _ => 0,
                };
                let egress = matches!(name, IntrinsicName::InvokeRemote(_));
                for node in nodes.iter().skip(rest_from).flatten() {
                    self.classes.expose(
                        *node,
                        if egress {
                            exposure::EGRESS
                        } else {
                            exposure::BODY
                        },
                    );
                }
                if is_app {
                    self.classes.id(site);
                    self.unify(lhs, Some(site));
                    self.requests.insert(
                        (func, loc),
                        Request {
                            route: nodes.first().copied().flatten().filter(|_| rest_from == 1),
                            rest: nodes.iter().skip(rest_from).flatten().copied().collect(),
                        },
                    );
                } else if let Some(lhs) = lhs {
                    self.classes.label(lhs, origin::EXTERNAL);
                    // Data the caller put in the request shapes what comes back.
                    for node in nodes.iter().flatten() {
                        self.classes.unify(lhs, *node);
                    }
                }
            }
            Intrinsic::ApiCustomField => {
                // An asApp request to a `field` route: the route is the first operand.
                self.classes.id(site);
                self.unify(lhs, Some(site));
                for node in nodes.iter().skip(1).flatten() {
                    self.classes.expose(*node, exposure::BODY);
                }
                self.requests.insert(
                    (func, loc),
                    Request {
                        route: nodes.first().copied().flatten(),
                        rest: nodes.iter().skip(1).flatten().copied().collect(),
                    },
                );
            }
            Intrinsic::Fetch => {
                for node in nodes.iter().flatten() {
                    self.classes.expose(*node, exposure::EGRESS);
                }
                if let Some(lhs) = lhs {
                    self.classes.label(lhs, origin::EXTERNAL);
                    for node in nodes.iter().flatten() {
                        self.classes.unify(lhs, *node);
                    }
                }
            }
            Intrinsic::StorageRead | Intrinsic::SecretRead | Intrinsic::EnvRead => {
                if let Some(lhs) = lhs {
                    self.classes.label(lhs, origin::EXTERNAL);
                    for node in nodes.iter().flatten() {
                        self.classes.unify(lhs, *node);
                    }
                }
            }
            Intrinsic::UserFieldAccess => {
                if let Some(lhs) = lhs {
                    self.classes.label(lhs, origin::EXTERNAL);
                }
            }
            Intrinsic::SecretFunction(_) => {
                for node in nodes.iter().flatten() {
                    self.classes.expose(*node, exposure::EGRESS);
                }
            }
            Intrinsic::Authorize(_) | Intrinsic::ConsoleLog(_) => {}
        }
    }

    /// Join a function that a call may run to the call's data: its parameters
    /// take the data, and what it returns joins the call's result.
    fn run(&mut self, target: Func, data: Option<Node>, result: Option<Node>) {
        self.add_function(target);
        let Some(body) = self.body(target) else {
            return;
        };
        for kind in body.vars.iter() {
            if let VarKind::Arg(param) = kind {
                self.unify(Some(Node::Binding(*param)), data);
            }
        }
        self.unify(Some(Node::Ret(target)), result);
        self.unify(Some(Node::Ret(target)), data);
    }

    fn call(
        &mut self,
        body: &Body,
        func: Func,
        loc: Location,
        lhs: Option<Node>,
        callee: &Operand,
        args: &[Operand],
    ) {
        let followed = body.resolve_call(self.env, callee).is_some();
        let arg_nodes: Vec<_> = args
            .iter()
            .map(|arg| self.operand_or_request(body, func, arg, followed))
            .collect();
        if let Some((target, target_body)) = body.resolve_call(self.env, callee) {
            if target_body.authz_principal_opaque {
                self.gap("opaque function");
                return;
            }
            if body.authz_callbacks.contains_key(&loc) {
                self.gap("a function value passed to a function the analysis follows");
                return;
            }
            self.add_function(Func::Def(target));
            let params: Vec<_> = target_body
                .vars
                .iter()
                .filter_map(|kind| match kind {
                    VarKind::Arg(param) => Some(*param),
                    _ => None,
                })
                .collect();
            // The request itself is never joined to anything: its parameters are
            // already the request (see `find_request`).
            if body.authz_spread_calls.contains(&loc) {
                for node in arg_nodes.iter().flatten() {
                    for param in &params {
                        if !self.request.contains(node) {
                            self.classes.unify(*node, Node::Binding(*param));
                        }
                    }
                }
            } else {
                for (node, param) in arg_nodes.iter().zip(&params) {
                    if let Some(node) = node
                        && !self.request.contains(node)
                    {
                        self.classes.unify(*node, Node::Binding(*param));
                    }
                }
            }
            self.unify(lhs, Some(Node::Ret(Func::Def(target))));
            return;
        }
        let literal_callee = Variable::default();
        let callee_var = match callee {
            Operand::Var(var) => var,
            // A function the analysis cannot name: it may do anything with its arguments.
            Operand::Lit(_) => &literal_callee,
        };
        let callee_base = match callee_var.base {
            Base::Var(id) => Some(id),
            _ => None,
        };
        // A module object such as `console`, `JSON` or an imported client is not a
        // data holder: sharing it would unify every call made through it.
        let receiver = if callee_var.projections.is_empty() || !self.holds_data(body, callee_base) {
            None
        } else {
            callee_base.map(|id| node_of(body, func, id))
        };
        let method = match callee_var.projections.last() {
            Some(Projection::Known(name)) => Some(name.clone()),
            _ => None,
        };
        // Calling a variable runs a function this analysis cannot see.
        if callee_var.projections.is_empty() && self.holds_data(body, callee_base) {
            self.gap("call of a function value");
            return;
        }
        let kind = self.classify(
            body,
            callee_base,
            method.as_ref(),
            callee_var.projections.len(),
        );
        // Everything an unresolved call touches may end up in everything else.
        let mut all: Vec<Node> = args
            .iter()
            .zip(&arg_nodes)
            .filter_map(|(arg, node)| {
                let Operand::Var(var) = arg else {
                    return None;
                };
                match var.base {
                    Base::Var(id) if self.holds_data(body, Some(id)) => *node,
                    _ => None,
                }
            })
            .collect();
        all.extend(receiver);
        if let Some(first) = all.first().copied() {
            for node in &all {
                self.classes.unify(*node, first);
            }
            self.unify(lhs, Some(first));
        }
        // Function values among the arguments run with the call's data.
        let data = all.first().copied();
        if let Some(callbacks) = body.authz_callbacks.get(&loc) {
            for &index in callbacks {
                self.run(Func::Closure(index), data, lhs);
            }
        }
        for arg in args {
            if let Operand::Var(var) = arg
                && var.projections.is_empty()
                && let Base::Var(id) = var.base
                && let Some(def) = variable_def(&body.vars[id])
                && matches!(
                    self.env.def_ref(self.env.resolve_alias(def)),
                    DefKind::Function(_) | DefKind::Closure(_)
                )
            {
                self.run(Func::Def(self.env.resolve_alias(def)), data, lhs);
            }
        }
        match kind {
            Callee::Pure => {}
            Callee::Reads => {
                if let Some(lhs) = lhs {
                    self.classes.label(lhs, origin::EXTERNAL);
                }
            }
            Callee::Unknown => {
                for node in &all {
                    self.classes.expose(*node, exposure::EGRESS);
                }
                if let Some(lhs) = lhs {
                    self.classes.expose(lhs, exposure::EGRESS);
                }
            }
        }
    }

    /// Whether a variable can hold data, rather than name a module, a built-in or
    /// a function.
    fn holds_data(&self, body: &Body, id: Option<VarId>) -> bool {
        let Some(id) = id else {
            return false;
        };
        let Some(def) = variable_def(&body.vars[id]) else {
            return true;
        };
        let target = self.env.resolve_alias(def);
        !(self.env.is_undeclared_global(def)
            || self.env.foreign_import(target).is_some()
            || matches!(
                self.env.def_ref(target),
                DefKind::Function(_) | DefKind::Closure(_) | DefKind::Class(_)
            ))
    }

    fn classify(
        &self,
        body: &Body,
        base: Option<VarId>,
        method: Option<&Atom>,
        projections: usize,
    ) -> Callee {
        let Some(base) = base else {
            return Callee::Unknown;
        };
        let def = variable_def(&body.vars[base]);
        let name = method.map(|name| name.as_ref());
        let imported = def.and_then(|def| self.env.foreign_import(self.env.resolve_alias(def)));
        if let Some((module, _kind)) = imported {
            // Calls on `@forge/*` clients and everything else imported: reads give
            // external data, anything else may send what it is given somewhere.
            return match name {
                Some(name) if READ_METHODS.contains(&name) => Callee::Reads,
                Some("asApp" | "asUser" | "route") => Callee::Pure,
                _ if module == "lodash" || module == "lodash-es" => Callee::Pure,
                _ => Callee::Unknown,
            };
        }
        if def.is_some_and(|def| self.env.is_undeclared_global(def)) {
            // `JSON`, `Math`, `Object`, `console`... by name; bare `parseInt(...)`.
            let global = def.map(|def| self.env.def_name(def));
            return match (global, name) {
                (Some("console"), _) => Callee::Pure,
                (
                    Some(
                        "Promise" | "JSON" | "Math" | "Object" | "Array" | "Number" | "String"
                        | "Boolean" | "Date" | "Map" | "Set" | "URLSearchParams" | "URL" | "Buffer"
                        | "Symbol" | "BigInt" | "Intl" | "RegExp" | "Error",
                    ),
                    _,
                ) => Callee::Pure,
                (
                    Some(
                        "parseInt" | "parseFloat" | "isNaN" | "isFinite" | "encodeURIComponent"
                        | "decodeURIComponent" | "encodeURI" | "decodeURI" | "structuredClone"
                        | "setTimeout" | "clearTimeout" | "atob" | "btoa",
                    ),
                    None,
                ) => Callee::Pure,
                _ => Callee::Unknown,
            };
        }
        match name {
            Some(name) if projections > 0 && PURE_METHODS.contains(&name) => Callee::Pure,
            _ => Callee::Unknown,
        }
    }

    fn finish(mut self) -> Flow {
        // What the caller sent shapes what the app gets back. Join each request's
        // origins into its response without joining the classes themselves, which
        // would make everything sent also look returned.
        let mut changed = true;
        while changed {
            changed = false;
            let requests: Vec<(Site, Option<Node>, Vec<Node>)> = self
                .requests
                .iter()
                .map(|(site, request)| (*site, request.route, request.rest.clone()))
                .collect();
            for (site, route, rest) in requests {
                let sent = route.into_iter().chain(rest).fold(0, |bits, node| {
                    let class = self.classes.class(node);
                    bits | self.classes.meta[class as usize].origin
                });
                let class = self.classes.class(Node::Site(site.0, site.1));
                let meta = &mut self.classes.meta[class as usize];
                if meta.origin | sent != meta.origin {
                    meta.origin |= sent;
                    changed = true;
                }
            }
        }
        // Persistent module state outlives the call: anything stored in it is
        // reachable by a later request.
        let globals: Vec<Node> = self
            .classes
            .index
            .keys()
            .copied()
            .filter(|node| {
                matches!(node, Node::Binding(binding)
                    if self.env.binding_owner(*binding).is_some_and(|owner| self.env.global.contains(&owner)))
            })
            .collect();
        for node in globals {
            self.classes.expose(node, exposure::EGRESS);
        }
        Flow {
            classes: self.classes,
            requests: self.requests,
        }
    }
}

enum Callee {
    /// Cannot send what it is given anywhere; its result may contain it.
    Pure,
    /// Reads external state.
    Reads,
    /// May send its arguments, or its receiver's state, somewhere.
    Unknown,
}
