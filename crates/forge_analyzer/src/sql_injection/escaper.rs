//! Literal escapers: a helper that turns any value into one complete SQL string
//! literal, so what it returns cannot change the structure of the query it is
//! put into.
//!
//! A helper is trusted only after its body has been read, never by its name.
//! Every path that returns must give one of:
//! - a constant, or a number (`Number(v)`, or `String(v)` where `typeof v ===
//!   "number"` holds);
//! - `'` + E + `'`, with constant single-quote delimiters and nothing else
//!   concatenated, where E is `String(v)` put through global replacements that
//!   leave neither a lone `\` nor a lone `'`: every `\` is doubled before any
//!   step adds a backslash, every `'` is doubled (or becomes `\'` once
//!   backslashes are doubled), and every other step only deletes or swaps
//!   characters, or adds a `\c` pair, without touching the characters the
//!   earlier steps relied on.
//!
//! A path that returns the value itself, or anything this reading cannot show
//! to be one of those, fails the check, and the failed check is named in the
//! finding. A helper whose result is also put inside another quoted literal
//! anywhere in the program is rejected too, since the delimiters would no longer
//! line up.
use super::semantics::{
    method_receiver, unresolved_global_named, variable_definitions_with_aliases,
};
use crate::{
    definitions::{DefId, Environment},
    ir::{
        Base, BasicBlockId, BinOp, Body, Inst, Literal, Operand, Rvalue, Terminator, UnOp, VarId,
        VarKind, Variable,
    },
};
use std::{cell::Cell, collections::HashSet};

/// What reading a function says about whether it escapes its argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Nothing in the function looks like quoting or escaping.
    NotAnEscaper,
    /// The function escapes the value of this parameter.
    Verified(VarId),
    /// The function looks like an escaper and fails a check.
    Rejected(Check),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Check {
    /// A path returns the value itself.
    NoEscaping,
    /// A path returns escaped text without wrapping it in single quotes.
    MissingQuotes,
    /// A path returns something this reading cannot show to be one literal.
    Unproven,
    BackslashesNotDoubled,
    QuotesNotDoubled,
    NotGlobal,
    BackslashDoubledLate,
    UndoesEscaping,
    UnsupportedStep,
    SplicedInQuotes,
}

impl Check {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::NoEscaping => "a path returns the value without escaping it",
            Self::MissingQuotes => {
                "a path returns escaped text without wrapping it in single quotes"
            }
            Self::Unproven => "a path returns text that is not shown to be one escaped literal",
            Self::BackslashesNotDoubled => "the escape does not double backslashes",
            Self::QuotesNotDoubled => "the escape does not double single quotes",
            Self::NotGlobal => "a replacement does not apply to every occurrence",
            Self::BackslashDoubledLate => {
                "backslashes are doubled after a step that adds backslashes"
            }
            Self::UndoesEscaping => "a later step can change characters an earlier step relied on",
            Self::UnsupportedStep => "a step is not one this check can read",
            Self::SplicedInQuotes => {
                "a call puts the result inside another quoted literal, so the quotes do not line up"
            }
        }
    }
}

/// Read the function `def`.
pub(crate) fn judge(env: &Environment, def: DefId) -> Verdict {
    let def_ref = env.def_ref(def);
    let Some(body) = def_ref.as_body() else {
        return Verdict::NotAnEscaper;
    };
    let Some(parameter) = body
        .vars
        .iter_enumerated()
        .find_map(|(id, kind)| matches!(kind, VarKind::Arg(_)).then_some(id))
    else {
        return Verdict::NotAnEscaper;
    };
    if !looks_like_escaper(env, def, body) {
        return Verdict::NotAnEscaper;
    }
    let reader = Reader {
        env,
        body,
        parameter,
        escapes_parameter: Cell::new(false),
    };
    match reader.check() {
        // A function that returns only constants does not escape anything.
        Ok(()) if !reader.escapes_parameter.get() => Verdict::NotAnEscaper,
        Ok(()) => match calls_line_up(env, def) {
            Ok(()) => Verdict::Verified(parameter),
            Err(check) => Verdict::Rejected(check),
        },
        Err(check) => Verdict::Rejected(check),
    }
}

/// Whether the function wraps a value in single quotes, or replaces quotes or
/// backslashes, or is named for escaping. A name never makes a function
/// trusted; it only makes a function that fails a check worth saying so about,
/// so a query builder that merely contains quotes is left alone.
fn looks_like_escaper(env: &Environment, def: DefId, body: &Body) -> bool {
    let name = env.def_name(def).to_lowercase();
    if name.starts_with("esc")
        || ["escape", "quote", "sanitiz"]
            .iter()
            .any(|word| name.contains(word))
    {
        return true;
    }
    // The quote that opens a literal, on its own: a query builder also ends in
    // a quote, but it starts with other text.
    let opens_literal = |operand: &Operand| matches!(operand, Operand::Lit(Literal::Str(text)) if text.as_ref() == "'");
    // What a replacement writes in place of a quote or a backslash.
    let mentions_quote_or_backslash = |operand: &Operand| matches!(operand, Operand::Lit(Literal::Str(text)) if text.contains(['\'', '\\']));
    body.iter_blocks_enumerated()
        .flat_map(|(_, block)| block.iter())
        .any(|inst| match inst.rvalue() {
            Rvalue::Call(callee, operands) => {
                method_receiver(callee)
                    .is_some_and(|(_, method)| matches!(method, "replace" | "replaceAll"))
                    && operands.iter().any(mentions_quote_or_backslash)
            }
            Rvalue::Template(template) => template
                .quasis
                .first()
                .is_some_and(|text| text.as_ref() == "'"),
            Rvalue::Bin(BinOp::Add, left, _) => opens_literal(left),
            _ => false,
        })
}

/// What the parts of a text have been through, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Steps {
    /// Every backslash has been doubled.
    backslashes: bool,
    /// Every single quote has been doubled or escaped.
    quotes: bool,
    /// A step has added a backslash.
    added_backslash: bool,
    /// The second characters of the `\c` pairs steps have added.
    seconds: Vec<char>,
}

impl Steps {
    fn complete(&self) -> bool {
        self.backslashes && self.quotes
    }

    fn missing(&self) -> Check {
        if !self.backslashes {
            Check::BackslashesNotDoubled
        } else {
            Check::QuotesNotDoubled
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Shape {
    /// A literal, with its text when it is a string.
    Const(Option<String>),
    /// A number, or the text of one.
    Number,
    /// What `'` + text + `'` has been shown to be: one complete literal.
    Quoted,
    /// The parameter itself.
    Param,
    /// `String(parameter)` after replacement steps, or the first step that fails.
    Text(Result<Steps, Check>),
    /// Parts joined with `+` or in a template.
    Concat(Vec<Shape>),
    Unknown,
}

struct Reader<'a> {
    env: &'a Environment,
    body: &'a Body,
    parameter: VarId,
    /// Some return path was shown to make the parameter into a literal or a
    /// number, as opposed to returning only constants.
    escapes_parameter: Cell<bool>,
}

impl Reader<'_> {
    /// Every return gives a constant, a number or one escaped literal.
    fn check(&self) -> Result<(), Check> {
        if !self.parameter_is_never_reassigned() || !self.does_nothing_else() {
            return Err(Check::Unproven);
        }
        for (bb, block) in self.body.iter_blocks_enumerated() {
            let mut returned = None;
            for (stmt, inst) in block.iter().enumerate() {
                let Inst::Assign(target, rvalue) = inst else {
                    continue;
                };
                if !self.is_return_variable(target) {
                    continue;
                }
                if !matches!(block.term, Terminator::Ret) {
                    return Err(Check::Unproven);
                }
                returned = Some((stmt, rvalue));
            }
            let Some((_, rvalue)) = returned else {
                continue;
            };
            let shape = self.rvalue(rvalue, bb, &mut HashSet::new());
            self.returnable(shape)?;
        }
        Ok(())
    }

    /// The body only computes values: it calls nothing but `String`, `Number`,
    /// `parseInt`, `parseFloat`, `replace` and `replaceAll`, and writes no
    /// property. What the parameter holds is trusted only inside such a body.
    fn does_nothing_else(&self) -> bool {
        self.body
            .iter_blocks_enumerated()
            .flat_map(|(_, block)| block.iter())
            .all(|inst| {
                if let Inst::Assign(target, _) = inst
                    && !target.projections.is_empty()
                {
                    return false;
                }
                match inst.rvalue() {
                    Rvalue::Read(_) | Rvalue::Bin(..) | Rvalue::Phi(_) => true,
                    Rvalue::Unary(op, _) => !matches!(op, UnOp::Delete),
                    Rvalue::Template(template) => template.tag.is_none(),
                    Rvalue::Call(callee, _) => {
                        ["String", "Number", "parseInt", "parseFloat"]
                            .iter()
                            .any(|name| unresolved_global_named(self.env, self.body, callee, name))
                            || method_receiver(callee).is_some_and(|(_, method)| {
                                matches!(method, "replace" | "replaceAll")
                            })
                    }
                    _ => false,
                }
            })
    }

    fn is_return_variable(&self, target: &Variable) -> bool {
        target.projections.is_empty()
            && matches!(target.base, Base::Var(id) if matches!(self.body.vars[id], VarKind::Ret))
    }

    fn parameter_def(&self) -> Option<DefId> {
        match self.body.vars[self.parameter] {
            VarKind::Arg(def) => Some(def),
            _ => None,
        }
    }

    fn binds_parameter(&self, var: VarId) -> bool {
        self.parameter_def().is_some_and(|parameter| {
            matches!(self.body.vars[var],
                VarKind::Arg(def) | VarKind::LocalDef(def) | VarKind::GlobalRef(def) if def == parameter)
        })
    }

    /// The parameter is only ever copied, never given another value.
    fn parameter_is_never_reassigned(&self) -> bool {
        self.body
            .iter_blocks_enumerated()
            .flat_map(|(_, block)| block.iter())
            .all(|inst| {
                let Inst::Assign(target, rvalue) = inst else {
                    return true;
                };
                let Base::Var(id) = target.base else {
                    return true;
                };
                if !self.binds_parameter(id) {
                    return true;
                }
                target.projections.is_empty()
                    && matches!(rvalue, Rvalue::Read(Operand::Var(source))
                        if source.projections.is_empty()
                            && matches!(source.base, Base::Var(source) if self.binds_parameter(source)))
            })
    }

    fn returnable(&self, shape: Shape) -> Result<(), Check> {
        match shape {
            Shape::Const(_) | Shape::Number | Shape::Quoted => Ok(()),
            Shape::Concat(parts) => self.concat(parts).map(|_| ()),
            Shape::Text(Ok(steps)) if steps.complete() => Err(Check::MissingQuotes),
            Shape::Text(Ok(steps)) => Err(steps.missing()),
            Shape::Text(Err(check)) => Err(check),
            Shape::Param => Err(Check::NoEscaping),
            Shape::Unknown => Err(Check::Unproven),
        }
    }

    /// What parts joined together are: safe as they are, or one escaped literal.
    fn concat(&self, parts: Vec<Shape>) -> Result<Shape, Check> {
        let mut flat = Vec::new();
        for part in parts {
            match part {
                Shape::Concat(inner) => flat.extend(inner),
                Shape::Const(Some(text)) if text.is_empty() => {}
                part => flat.push(part),
            }
        }
        if flat
            .iter()
            .all(|part| matches!(part, Shape::Const(_) | Shape::Number | Shape::Quoted))
        {
            return Ok(Shape::Quoted);
        }
        let quote = |part: &Shape| matches!(part, Shape::Const(Some(text)) if text == "'");
        if let [open, middle, close] = flat.as_slice()
            && quote(open)
            && quote(close)
        {
            return match middle {
                Shape::Text(Ok(steps)) if steps.complete() => {
                    self.escapes_parameter.set(true);
                    Ok(Shape::Quoted)
                }
                Shape::Text(Ok(steps)) => Err(steps.missing()),
                Shape::Text(Err(check)) => Err(*check),
                Shape::Param => Err(Check::NoEscaping),
                Shape::Const(_) | Shape::Number | Shape::Quoted => Ok(Shape::Quoted),
                Shape::Concat(_) | Shape::Unknown => Err(Check::Unproven),
            };
        }
        Err(Check::Unproven)
    }

    fn joined(&self, parts: Vec<Shape>) -> Shape {
        // A failed join is not itself the verdict: the returns decide that. It
        // stays a concatenation so a later `+` can still complete the quotes.
        let mut flat = Vec::new();
        for part in parts {
            match part {
                Shape::Concat(inner) => flat.extend(inner),
                part => flat.push(part),
            }
        }
        Shape::Concat(flat)
    }

    fn operand(&self, operand: &Operand, at: BasicBlockId, visiting: &mut HashSet<VarId>) -> Shape {
        match operand {
            Operand::Lit(Literal::Str(text)) => Shape::Const(Some(text.to_string())),
            Operand::Lit(Literal::Number(_)) => Shape::Number,
            Operand::Lit(Literal::Bool(_) | Literal::Null | Literal::Undef) => Shape::Const(None),
            Operand::Lit(_) => Shape::Unknown,
            Operand::Var(variable) => self.variable(variable, at, visiting),
        }
    }

    fn variable(
        &self,
        variable: &Variable,
        at: BasicBlockId,
        visiting: &mut HashSet<VarId>,
    ) -> Shape {
        let Base::Var(id) = variable.base else {
            return Shape::Unknown;
        };
        if !variable.projections.is_empty() {
            return Shape::Unknown;
        }
        if self.binds_parameter(id) {
            return if self.number_guard(at) {
                self.escapes_parameter.set(true);
                Shape::Number
            } else {
                Shape::Param
            };
        }
        if !visiting.insert(id) {
            return Shape::Unknown;
        }
        let definitions = variable_definitions_with_aliases(self.body, variable);
        let mut shapes = definitions
            .into_iter()
            .map(|(location, rvalue)| self.rvalue(rvalue, location.block, visiting))
            .collect::<Vec<_>>();
        visiting.remove(&id);
        let Some(first) = shapes.pop() else {
            return Shape::Unknown;
        };
        if shapes.iter().all(|shape| *shape == first) {
            return first;
        }
        // Alternatives that are each safe as they stand are safe together.
        shapes.push(first);
        if shapes
            .iter()
            .all(|shape| matches!(shape, Shape::Const(_) | Shape::Number | Shape::Quoted))
        {
            return Shape::Quoted;
        }
        Shape::Unknown
    }

    fn rvalue(&self, rvalue: &Rvalue, at: BasicBlockId, visiting: &mut HashSet<VarId>) -> Shape {
        match rvalue {
            Rvalue::Read(operand) => self.operand(operand, at, visiting),
            Rvalue::Bin(BinOp::Add, left, right) => self.joined(vec![
                self.operand(left, at, visiting),
                self.operand(right, at, visiting),
            ]),
            Rvalue::Bin(BinOp::Sub | BinOp::Mul | BinOp::Div | BinOp::Mod | BinOp::Exp, _, _) => {
                Shape::Number
            }
            Rvalue::Template(template) if template.tag.is_none() => {
                let mut parts = Vec::new();
                for (index, text) in template.quasis.iter().enumerate() {
                    parts.push(Shape::Const(Some(text.to_string())));
                    if let Some(expr) = template.exprs.get(index) {
                        parts.push(self.operand(expr, at, visiting));
                    }
                }
                self.joined(parts)
            }
            Rvalue::Phi(values) => {
                let shapes = values
                    .iter()
                    .map(|(var, _)| self.variable(&Variable::new(*var), at, visiting))
                    .collect::<Vec<_>>();
                if shapes
                    .iter()
                    .all(|shape| matches!(shape, Shape::Const(_) | Shape::Number | Shape::Quoted))
                {
                    Shape::Quoted
                } else {
                    Shape::Unknown
                }
            }
            Rvalue::Call(callee, operands) => self.call(callee, operands, at, visiting),
            _ => Shape::Unknown,
        }
    }

    fn call(
        &self,
        callee: &Operand,
        operands: &[Operand],
        at: BasicBlockId,
        visiting: &mut HashSet<VarId>,
    ) -> Shape {
        let (env, body) = (self.env, self.body);
        if let [argument] = operands
            && unresolved_global_named(env, body, callee, "String")
        {
            return match self.operand(argument, at, visiting) {
                Shape::Param => Shape::Text(Ok(Steps::default())),
                text @ Shape::Text(_) => text,
                Shape::Number => Shape::Number,
                Shape::Const(_) => Shape::Const(None),
                Shape::Quoted => Shape::Quoted,
                _ => Shape::Unknown,
            };
        }
        if ["Number", "parseInt", "parseFloat"]
            .iter()
            .any(|name| unresolved_global_named(env, body, callee, name))
        {
            self.escapes_parameter.set(true);
            return Shape::Number;
        }
        let Some((receiver, method @ ("replace" | "replaceAll"))) = method_receiver(callee) else {
            return Shape::Unknown;
        };
        let Shape::Text(text) = self.variable(&receiver, at, visiting) else {
            return Shape::Unknown;
        };
        let Ok(steps) = text else {
            return Shape::Text(text);
        };
        let [pattern, Operand::Lit(Literal::Str(replacement))] = operands else {
            return Shape::Text(Err(Check::UnsupportedStep));
        };
        // `$&`, `$1` and the like expand to what matched.
        if replacement.contains('$') {
            return Shape::Text(Err(Check::UnsupportedStep));
        }
        let (pattern, global) = match pattern {
            Operand::Lit(Literal::RegExp(source, flags)) => {
                if flags.chars().any(|flag| !matches!(flag, 'g' | 'u')) {
                    return Shape::Text(Err(Check::UnsupportedStep));
                }
                (parse_pattern(source), flags.contains('g'))
            }
            Operand::Lit(Literal::Str(text)) => {
                let mut chars = text.chars();
                (
                    chars
                        .next()
                        .filter(|_| chars.next().is_none())
                        .map(CharSet::single),
                    method == "replaceAll",
                )
            }
            _ => (None, false),
        };
        let Some(pattern) = pattern else {
            return Shape::Text(Err(Check::UnsupportedStep));
        };
        Shape::Text(step(&steps, &pattern, global, replacement))
    }

    /// Whether every way to reach `block` has checked `typeof parameter ===
    /// "number"`, read from the conditions of the single-entry blocks above it.
    fn number_guard(&self, block: BasicBlockId) -> bool {
        let mut current = block;
        for _ in 0..16 {
            let &[predecessor] = self.body.predecessors(current) else {
                return false;
            };
            if let Terminator::If { cond, cons, alt } = &self.body.block(predecessor).term
                && cons != alt
                && self.is_number_check(cond, current == *cons)
            {
                return true;
            }
            current = predecessor;
        }
        false
    }

    fn is_number_check(&self, cond: &Operand, holds: bool) -> bool {
        let Operand::Var(variable) = cond else {
            return false;
        };
        let definitions = variable_definitions_with_aliases(self.body, variable);
        let [(_, Rvalue::Bin(op, left, right))] = definitions.as_slice() else {
            return false;
        };
        let equal = match op {
            BinOp::EqEq | BinOp::EqEqEq => true,
            BinOp::Neq | BinOp::NeqEq => false,
            _ => return false,
        };
        if equal != holds {
            return false;
        }
        let is_number = |operand: &Operand| matches!(operand, Operand::Lit(Literal::Str(text)) if text.as_ref() == "number");
        let is_typeof_parameter = |operand: &Operand| {
            let Operand::Var(variable) = operand else {
                return false;
            };
            variable_definitions_with_aliases(self.body, variable)
                .iter()
                .any(|(_, rvalue)| {
                    matches!(rvalue, Rvalue::Unary(UnOp::TypeOf, Operand::Var(argument))
                        if argument.projections.is_empty()
                            && matches!(argument.base, Base::Var(id) if self.binds_parameter(id)))
                })
        };
        (is_number(right) && is_typeof_parameter(left))
            || (is_number(left) && is_typeof_parameter(right))
    }
}

/// Put `text` through `replace(pattern, replacement)`.
fn step(text: &Steps, pattern: &CharSet, global: bool, replacement: &str) -> Result<Steps, Check> {
    if !global {
        return Err(Check::NotGlobal);
    }
    let mut next = text.clone();
    if pattern.is(&'\\') {
        if replacement != "\\\\" {
            return Err(Check::UnsupportedStep);
        }
        if text.added_backslash {
            return Err(Check::BackslashDoubledLate);
        }
        next.backslashes = true;
    } else if pattern.is(&'\'') {
        if text.quotes {
            return Err(Check::UndoesEscaping);
        }
        match replacement {
            "''" => next.quotes = true,
            "\\'" if text.backslashes => {
                next.quotes = true;
                next.added_backslash = true;
            }
            "\\'" => return Err(Check::BackslashesNotDoubled),
            _ => return Err(Check::UnsupportedStep),
        }
    } else if pattern.contains(&'\\') || pattern.contains(&'\'') {
        return Err(Check::UnsupportedStep);
    } else if text.seconds.iter().any(|second| pattern.contains(second)) {
        return Err(Check::UndoesEscaping);
    } else if let Some(second) = pair_second(replacement) {
        next.added_backslash = true;
        next.seconds.push(second);
    } else if replacement.contains(['\\', '\'']) {
        return Err(Check::UnsupportedStep);
    }
    Ok(next)
}

/// The character after the backslash of a replacement that is exactly `\c`,
/// for a `c` that is not itself special.
fn pair_second(replacement: &str) -> Option<char> {
    let mut chars = replacement.chars();
    let (Some('\\'), Some(second), None) = (chars.next(), chars.next(), chars.next()) else {
        return None;
    };
    (!matches!(second, '\\' | '\'') && !second.is_control()).then_some(second)
}

/// The characters a pattern can match, as inclusive ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CharSet(Vec<(char, char)>);

impl CharSet {
    fn single(c: char) -> Self {
        Self(vec![(c, c)])
    }

    fn is(&self, c: &char) -> bool {
        self.0 == [(*c, *c)]
    }

    fn contains(&self, c: &char) -> bool {
        self.0.iter().any(|(low, high)| low <= c && c <= high)
    }
}

/// The characters one regular expression atom, or one class of them, matches.
/// Anything else (a quantifier, a group, a negated class, a shorthand such as
/// `\d`) is not read.
fn parse_pattern(source: &str) -> Option<CharSet> {
    let chars = source.chars().collect::<Vec<_>>();
    if chars.first() != Some(&'[') {
        let (c, used) = atom(&chars, false)?;
        return (used == chars.len()).then(|| CharSet::single(c));
    }
    let inner = chars.strip_prefix(&['['])?.strip_suffix(&[']'])?;
    if inner.is_empty() || inner[0] == '^' {
        return None;
    }
    let mut members = Vec::new();
    let mut index = 0;
    while index < inner.len() {
        let (low, used) = atom(&inner[index..], true)?;
        index += used;
        if inner.get(index) == Some(&'-') && index + 1 < inner.len() {
            let (high, used) = atom(&inner[index + 1..], true)?;
            if high < low {
                return None;
            }
            members.push((low, high));
            index += 1 + used;
        } else {
            members.push((low, low));
        }
    }
    Some(CharSet(members))
}

/// One character, plain or escaped, and how many characters of `chars` it uses.
fn atom(chars: &[char], in_class: bool) -> Option<(char, usize)> {
    match *chars.first()? {
        '\\' => escape(&chars[1..]).map(|(c, used)| (c, used + 1)),
        '.' | '*' | '+' | '?' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']'
            if !in_class =>
        {
            None
        }
        c => Some((c, 1)),
    }
}

fn escape(chars: &[char]) -> Option<(char, usize)> {
    let hex = |digits: &[char]| {
        let text = digits.iter().collect::<String>();
        (digits.iter().all(char::is_ascii_hexdigit))
            .then(|| u32::from_str_radix(&text, 16).ok().and_then(char::from_u32))
            .flatten()
    };
    match *chars.first()? {
        'n' => Some(('\n', 1)),
        'r' => Some(('\r', 1)),
        't' => Some(('\t', 1)),
        'f' => Some(('\u{c}', 1)),
        'v' => Some(('\u{b}', 1)),
        '0' if !chars.get(1).is_some_and(char::is_ascii_digit) => Some(('\0', 1)),
        'x' => Some((hex(chars.get(1..3)?)?, 3)),
        'u' => Some((hex(chars.get(1..5)?)?, 5)),
        c @ ('\\' | '\'' | '"' | '/' | '.' | '-' | ']' | '[' | '^' | '$' | '*' | '+' | '?'
        | '(' | ')' | '|' | '{' | '}') => Some((c, 1)),
        _ => None,
    }
}

/// Every call of `escaper` in the program leaves its result outside any quoted
/// literal of the text it is put into.
fn calls_line_up(env: &Environment, escaper: DefId) -> Result<(), Check> {
    for body in env.bodies() {
        for (_, block) in body.iter_blocks_enumerated() {
            for inst in block.iter() {
                let Inst::Assign(target, Rvalue::Call(callee, _)) = inst else {
                    continue;
                };
                if !target.projections.is_empty()
                    || body.resolve_call(env, callee).map(|(def, _)| def) != Some(escaper)
                {
                    continue;
                }
                let Base::Var(result) = target.base else {
                    continue;
                };
                if result_is_inside_quotes(body, result) {
                    return Err(Check::SplicedInQuotes);
                }
            }
        }
    }
    Ok(())
}

/// Whether the variable, or a copy of it, is put into a template or a sum right
/// next to a quote, or after a quote that is still open.
fn result_is_inside_quotes(body: &Body, result: VarId) -> bool {
    let mut copies = HashSet::from([result]);
    loop {
        let before = copies.len();
        for (_, block) in body.iter_blocks_enumerated() {
            for inst in block.iter() {
                let Inst::Assign(target, Rvalue::Read(Operand::Var(source))) = inst else {
                    continue;
                };
                if source.projections.is_empty()
                    && matches!(source.base, Base::Var(id) if copies.contains(&id))
                    && target.projections.is_empty()
                    && let Base::Var(id) = target.base
                {
                    copies.insert(id);
                    if let Some(aliases) = body.binding_variables(&Variable::new(id)) {
                        copies.extend(aliases.iter().copied());
                    }
                }
            }
        }
        if copies.len() == before {
            break;
        }
    }
    let is_copy = |operand: &Operand| {
        matches!(operand, Operand::Var(variable)
            if variable.projections.is_empty()
                && matches!(variable.base, Base::Var(id) if copies.contains(&id)))
    };
    let quote = |c: char| matches!(c, '\'' | '"' | '`');
    body.iter_blocks_enumerated()
        .flat_map(|(_, block)| block.iter())
        .any(|inst| match inst.rvalue() {
            Rvalue::Template(template) => template.exprs.iter().enumerate().any(|(index, expr)| {
                if !is_copy(expr) {
                    return false;
                }
                let before = template.quasis[..=index]
                    .iter()
                    .flat_map(|text| text.chars())
                    .collect::<String>();
                let open = |q: char| before.chars().filter(|&c| c == q).count() % 2 == 1;
                before.ends_with(quote)
                    || template
                        .quasis
                        .get(index + 1)
                        .is_some_and(|after| after.starts_with(quote))
                    || open('\'')
                    || open('"')
            }),
            Rvalue::Bin(BinOp::Add, left, right) => {
                let text = |operand: &Operand| match operand {
                    Operand::Lit(Literal::Str(text)) => Some(text.to_string()),
                    _ => None,
                };
                (is_copy(right) && text(left).is_some_and(|text| text.ends_with(quote)))
                    || (is_copy(left) && text(right).is_some_and(|text| text.starts_with(quote)))
            }
            _ => false,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(source: &str) -> Option<Vec<(char, char)>> {
        parse_pattern(source).map(|set| set.0)
    }

    #[test]
    fn reads_single_characters_and_classes() {
        assert_eq!(pattern("\\\\"), Some(vec![('\\', '\\')]));
        assert_eq!(pattern("'"), Some(vec![('\'', '\'')]));
        assert_eq!(pattern("\\0"), Some(vec![('\0', '\0')]));
        assert_eq!(pattern("\\x1a"), Some(vec![('\u{1a}', '\u{1a}')]));
        assert_eq!(
            pattern("[\\x00-\\x1f\\x7f]"),
            Some(vec![('\0', '\u{1f}'), ('\u{7f}', '\u{7f}')])
        );
    }

    #[test]
    fn does_not_read_what_it_cannot_bound() {
        for source in ["[^0-9]", "\\d", "a+", "(a)", ".", "a|b", "[a-", "\\1", "ab"] {
            assert_eq!(pattern(source), None, "{source}");
        }
    }

    fn run(steps: &[(&str, bool, &str)]) -> Result<Steps, Check> {
        steps
            .iter()
            .try_fold(Steps::default(), |text, (source, global, replacement)| {
                step(&text, &parse_pattern(source).unwrap(), *global, replacement)
            })
    }

    #[test]
    fn accepts_the_order_that_keeps_every_backslash_and_quote_paired() {
        let text = run(&[
            ("\\\\", true, "\\\\"),
            ("\\0", true, "\\0"),
            ("'", true, "''"),
            ("\"", true, "\\\""),
            ("\\x1a", true, "\\Z"),
            ("[\\x00-\\x1f\\x7f]", true, ""),
        ])
        .unwrap();
        assert!(text.complete());
    }

    #[test]
    fn names_the_first_check_a_chain_fails() {
        assert_eq!(
            run(&[("'", true, "''")]).map(|text| text.missing()),
            Ok(Check::BackslashesNotDoubled)
        );
        assert_eq!(run(&[("'", false, "''")]), Err(Check::NotGlobal));
        assert_eq!(
            run(&[("\\\\", true, "\\\\")]).map(|text| text.missing()),
            Ok(Check::QuotesNotDoubled)
        );
        assert_eq!(
            run(&[("\\0", true, "\\0"), ("\\\\", true, "\\\\")]),
            Err(Check::BackslashDoubledLate)
        );
        assert_eq!(
            run(&[("\\\\", true, "\\\\"), ("'", true, "\\'")]).map(|text| text.complete()),
            Ok(true)
        );
        assert_eq!(
            run(&[
                ("\\\\", true, "\\\\"),
                ("'", true, "\\'"),
                ("'", true, "''")
            ]),
            Err(Check::UndoesEscaping)
        );
        assert_eq!(
            run(&[("'", true, "\\'")]),
            Err(Check::BackslashesNotDoubled)
        );
        assert_eq!(
            run(&[
                ("\\\\", true, "\\\\"),
                ("\\0", true, "\\0"),
                ("0", true, "")
            ]),
            Err(Check::UndoesEscaping)
        );
        assert_eq!(
            run(&[("\\\\", true, "\\\\"), ("x", true, "'")]),
            Err(Check::UnsupportedStep)
        );
    }
}
