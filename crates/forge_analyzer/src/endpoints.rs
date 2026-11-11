//! Extraction of network endpoints: domains and IP addresses, with any port
//! and pathname written next to them.
//!
//! Extraction favors sensitivity over precision. Nothing is resolved or
//! checked for reachability, and anything that looks like a host is kept.
//! The one filter is that a domain written without a scheme must end in a
//! delegated top-level domain, which keeps strings such as `index.handler`
//! out of the results.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    net::Ipv6Addr,
    path::Path,
    sync::LazyLock,
};

use regex::Regex;
use serde_json::Value;
use swc_core::{
    common::{FileName, SourceMap, comments::SingleThreadedComments, sync::Lrc},
    ecma::{
        ast::{BinExpr, BinaryOp, EsVersion, Expr, JSXText, Lit, Regex as RegexLit, Str, Tpl},
        parser::{EsSyntax, Syntax, TsSyntax, parse_file_as_program},
        visit::{Visit, VisitWith},
    },
};
use url::{Host, Url};

/// Stands in for an expression interpolated into a string. It ends a host,
/// so `${sub}.example.com` yields `example.com`, and it stays in a path, so
/// `/users/${id}` yields `/users/*`.
const HOLE: char = '*';

/// Top-level domains that IANA does not list but malware uses.
const EXTRA_TLDS: [&str; 1] = ["ONION"];

static TLDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    include_str!("../../../tlds-alpha-by-domain.txt")
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .chain(EXTRA_TLDS)
        .collect()
});

/// Builds the candidate pattern. `label` is the character class for one
/// domain label. Candidates are validated afterwards, so the pattern only
/// has to find every plausible host. Paths are read separately by
/// `path_at`, because base64 blobs in bundles form long slash-separated runs.
fn candidate_pattern(label: &str) -> Regex {
    let pattern = r##"(?x)
        (?:
            (?P<scheme> [A-Za-z][A-Za-z0-9+.\-]* ) ://
            (?: (?P<userinfo> [^\s/?\#@\[\]"'<>`]* ) @ )?
        )?
        (?P<host> \[ [0-9A-Fa-f:.]+ \] | LABEL+ (?: \. LABEL+ )* )
        (?: : (?P<port> [0-9]+ ) )?
    "##;
    Regex::new(&pattern.replace("LABEL", label)).expect("valid candidate pattern")
}

/// Accepts Unicode labels so internationalized domains, including homographs
/// of well-known names, are reported in their real form.
static CANDIDATE: LazyLock<Regex> = LazyLock::new(|| candidate_pattern(r"[\w\-]"));

/// Catches ASCII domains written directly against other letters, as in
/// `访问evil.com`, which the Unicode pattern reads as a single label.
static ASCII_CANDIDATE: LazyLock<Regex> = LazyLock::new(|| candidate_pattern(r"[A-Za-z0-9_\-]"));

/// IPv6 addresses written without brackets. Validated by `Ipv6Addr`.
static BARE_IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9A-Fa-f]{1,4})?")
        .expect("valid IPv6 pattern")
});

/// Punctuation that ends a sentence rather than a path.
const TRAILING_PUNCTUATION: [char; 7] = ['.', ',', ';', ':', '!', ')', ']'];

/// Longer paths are truncated. Real URLs rarely approach this, and it bounds
/// the work for each host found.
const MAX_PATH_CHARS: usize = 2048;

/// Reads the pathname at the start of `rest`, stopping at the query,
/// fragment, or anything that cannot appear unquoted in a URL in source code.
fn path_at(rest: &str) -> Option<&str> {
    if !rest.starts_with('/') {
        return None;
    }
    let is_path_char = |c: char| {
        !c.is_whitespace()
            && !matches!(
                c,
                '?' | '#' | '"' | '\'' | '<' | '>' | '`' | '\\' | '^' | '{' | '}' | '|' | '$'
            )
    };
    let end = rest
        .char_indices()
        .enumerate()
        .find(|&(count, (_, c))| count > MAX_PATH_CHARS || (count > 0 && !is_path_char(c)))
        .map_or(rest.len(), |(_, (index, _))| index);
    Some(rest[..end].trim_end_matches(TRAILING_PUNCTUATION))
}

/// A host with the port and pathname written alongside it.
#[derive(Debug, PartialEq, Eq)]
struct Endpoint {
    /// Lowercase domain with internationalized labels in punycode, IPv4 in
    /// dotted-quad form, or IPv6 in brackets.
    host: String,
    port: Option<u16>,
    /// Pathname without the query or fragment. `None` when empty or `/`.
    path: Option<String>,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.host)?;
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        if let Some(path) = &self.path {
            f.write_str(path)?;
        }
        Ok(())
    }
}

/// A deduplicated set of endpoints, rendered as `host[:port][/path]`.
///
/// Every host is also recorded on its own, so a host can be matched without
/// parsing the entries that carry a port or path.
#[derive(Debug, Default)]
pub struct Endpoints {
    found: BTreeSet<String>,
}

impl Endpoints {
    pub fn new() -> Self {
        Self::default()
    }

    /// The endpoints in byte order.
    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.found.iter().map(String::as_str)
    }

    /// Adds endpoints from a source file, choosing how to read it from the
    /// extension. JavaScript and TypeScript are parsed so string escapes,
    /// template literals, and concatenations are seen as they run. JSON is
    /// parsed so escapes such as `\n` do not merge into a neighboring
    /// domain. Anything else, and anything that fails to parse, is read as
    /// plain text.
    pub fn add_source(&mut self, path: &Path, text: &str) {
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase);
        let es = Syntax::Es(EsSyntax {
            jsx: true,
            decorators: true,
            ..Default::default()
        });
        let ts = |tsx| {
            Syntax::Typescript(TsSyntax {
                tsx,
                decorators: true,
                ..Default::default()
            })
        };
        let parsed = match extension.as_deref() {
            Some("js" | "jsx" | "mjs" | "cjs") => self.add_script(path, text, es),
            Some("ts" | "mts" | "cts") => self.add_script(path, text, ts(false)),
            Some("tsx") => self.add_script(path, text, ts(true)),
            Some("json" | "map") => match serde_json::from_str(text) {
                Ok(value) => {
                    self.add_json(&value);
                    true
                }
                Err(_) => false,
            },
            _ => false,
        };
        if !parsed {
            self.add_text(text);
        }
    }

    /// Adds endpoints from every key and string in a JSON value.
    pub fn add_json(&mut self, value: &Value) {
        match value {
            Value::String(text) => self.add_text(text),
            Value::Array(items) => items.iter().for_each(|item| self.add_json(item)),
            Value::Object(entries) => {
                for (key, value) in entries {
                    self.add_text(key);
                    self.add_json(value);
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Adds every endpoint that appears in `text`.
    pub fn add_text(&mut self, text: &str) {
        self.add_candidates(&CANDIDATE, text);
        if !text.is_ascii() {
            self.add_candidates(&ASCII_CANDIDATE, text);
        }
        self.add_bare_ipv6(text);
    }

    /// Parses a script and adds the endpoints in its literals and comments.
    /// Returns `false` when the script does not parse.
    fn add_script(&mut self, path: &Path, text: &str, syntax: Syntax) -> bool {
        let source_map = SourceMap::default();
        let file =
            source_map.new_source_file(Lrc::new(FileName::Real(path.to_owned())), text.to_owned());
        let comments = SingleThreadedComments::default();
        let program = parse_file_as_program(
            &file,
            syntax,
            EsVersion::latest(),
            Some(&comments),
            &mut Vec::new(),
        );
        let Ok(program) = program else {
            return false;
        };
        program.visit_with(&mut LiteralVisitor { endpoints: self });
        let (leading, trailing) = comments.borrow_all();
        for comment in leading.values().chain(trailing.values()).flatten() {
            self.add_text(&comment.text);
        }
        true
    }

    fn add_candidates(&mut self, pattern: &Regex, text: &str) {
        // Matches end at the host or port, so the scan resumes inside any
        // path and finds hosts there, as in a proxy or redirect URL.
        for captures in pattern.captures_iter(text) {
            // Hosts can hide in the userinfo: `https://evil.com@good.com`.
            if let Some(userinfo) = captures.name("userinfo") {
                self.add_candidates(pattern, userinfo.as_str());
            }
            let Some(host) = parse_host(captures.name("scheme").is_some(), &captures["host"])
            else {
                continue;
            };
            let end = captures.get(0).expect("whole match").end();
            self.insert(Endpoint {
                host,
                // Keep the port as written, even when it is the scheme's
                // default.
                port: captures
                    .name("port")
                    .and_then(|port| port.as_str().parse().ok()),
                path: path_at(&text[end..]).and_then(normalize_path),
            });
        }
    }

    fn add_bare_ipv6(&mut self, text: &str) {
        let is_word = |c: char| c.is_alphanumeric() || c == '_' || c == ':';
        for found in BARE_IPV6.find_iter(text) {
            let before = text[..found.start()].chars().next_back();
            let after = text[found.end()..].chars().next();
            if before.is_some_and(is_word) || after.is_some_and(is_word) {
                continue;
            }
            match found.as_str().parse::<Ipv6Addr>() {
                Ok(ip) if !ip.is_unspecified() => self.insert(Endpoint {
                    host: format!("[{ip}]"),
                    port: None,
                    path: None,
                }),
                _ => {}
            }
        }
    }

    fn insert(&mut self, endpoint: Endpoint) {
        if endpoint.port.is_some() || endpoint.path.is_some() {
            self.found.insert(endpoint.host.clone());
        }
        self.found.insert(endpoint.to_string());
    }
}

/// Validates and normalizes a candidate host with WHATWG URL parsing, as
/// Node's `fetch` would see it: domains are lowercased and converted to
/// punycode, and IPv4 written in other forms (`0x7f.1`) becomes dotted-quad.
fn parse_host(has_scheme: bool, host: &str) -> Option<String> {
    let host = host.trim_start_matches(['-', '_']);
    // Most candidates are single words; skip them before parsing.
    if !has_scheme && !host.contains(['.', '[']) {
        return None;
    }
    let url = Url::parse(&format!("http://{host}")).ok()?;
    let normalized = match url.host()? {
        Host::Domain(domain) => {
            let (_, tld) = domain.rsplit_once('.')?;
            if !has_scheme && !TLDS.contains(tld.to_ascii_uppercase().as_str()) {
                return None;
            }
            domain.to_owned()
        }
        // Without a scheme, only dotted quads are addresses; `1.2` and
        // `3.14` are numbers.
        Host::Ipv4(ip) if has_scheme || is_dotted_quad(host) => ip.to_string(),
        Host::Ipv4(_) => return None,
        Host::Ipv6(ip) => format!("[{ip}]"),
    };
    Some(normalized)
}

/// Resolves dot segments and percent-encodes as WHATWG URL parsing does.
/// `/` alone is no path.
fn normalize_path(path: &str) -> Option<String> {
    let url = Url::parse(&format!("http://host{path}")).ok()?;
    (url.path() != "/").then(|| url.path().to_owned())
}

fn is_dotted_quad(host: &str) -> bool {
    let octets = host.split('.').collect::<Vec<_>>();
    octets.len() == 4
        && octets.iter().all(|octet| {
            (1..=3).contains(&octet.len()) && octet.bytes().all(|b| b.is_ascii_digit())
        })
}

/// Finds text in a script's literals. String concatenations and template
/// literals are joined into one string, with `HOLE` in place of each
/// interpolated expression, so hosts and paths split across pieces are
/// found whole.
struct LiteralVisitor<'a> {
    endpoints: &'a mut Endpoints,
}

impl Visit for LiteralVisitor<'_> {
    fn visit_str(&mut self, str: &Str) {
        self.endpoints.add_text(&str.value);
    }

    fn visit_tpl(&mut self, tpl: &Tpl) {
        let mut text = String::new();
        render_tpl(tpl, &mut text);
        self.endpoints.add_text(&text);
        for expr in &tpl.exprs {
            expr.visit_with(self);
        }
    }

    fn visit_bin_expr(&mut self, bin: &BinExpr) {
        if bin.op != BinaryOp::Add {
            bin.visit_children_with(self);
            return;
        }
        let mut text = String::new();
        let mut holes = Vec::new();
        if render_concat(bin, &mut text, &mut holes) {
            self.endpoints.add_text(&text);
        }
        // Every operand that was not rendered is a hole, so this reaches each
        // node in the chain once, even when the chain is arithmetic.
        for hole in holes {
            hole.visit_with(self);
        }
    }

    fn visit_jsx_text(&mut self, text: &JSXText) {
        self.endpoints.add_text(&text.value);
    }

    fn visit_regex(&mut self, regex: &RegexLit) {
        // Dropping backslashes turns `evil\.com` back into `evil.com`.
        self.endpoints.add_text(&regex.exp.replace('\\', ""));
    }
}

fn render_tpl(tpl: &Tpl, text: &mut String) {
    for (index, quasi) in tpl.quasis.iter().enumerate() {
        if index > 0 {
            text.push(HOLE);
        }
        text.push_str(quasi.cooked.as_ref().unwrap_or(&quasi.raw));
    }
}

/// Renders the operands of a `+` chain into `text`, collecting operands that
/// are not literals into `holes`. Returns whether any operand is a string,
/// which makes the chain a concatenation rather than arithmetic.
fn render_concat<'a>(bin: &'a BinExpr, text: &mut String, holes: &mut Vec<&'a Expr>) -> bool {
    // `+` is left-associative, so walk the left spine in a loop: minified
    // code can chain thousands of operands.
    let mut rights = vec![&*bin.right];
    let mut leftmost = &*bin.left;
    while let Expr::Bin(inner) = leftmost
        && inner.op == BinaryOp::Add
    {
        rights.push(&inner.right);
        leftmost = &inner.left;
    }
    let mut is_concat = render_operand(leftmost, text, holes);
    for right in rights.into_iter().rev() {
        is_concat |= render_operand(right, text, holes);
    }
    is_concat
}

fn render_operand<'a>(expr: &'a Expr, text: &mut String, holes: &mut Vec<&'a Expr>) -> bool {
    match expr {
        Expr::Bin(bin) if bin.op == BinaryOp::Add => render_concat(bin, text, holes),
        Expr::Paren(paren) => render_operand(&paren.expr, text, holes),
        Expr::Lit(Lit::Str(str)) => {
            text.push_str(&str.value);
            true
        }
        Expr::Tpl(tpl) => {
            render_tpl(tpl, text);
            holes.extend(tpl.exprs.iter().map(|expr| &**expr));
            true
        }
        // A port is often appended as a number.
        Expr::Lit(Lit::Num(num)) => {
            match &num.raw {
                Some(raw) => text.push_str(raw),
                None => text.push_str(&num.value.to_string()),
            }
            false
        }
        _ => {
            text.push(HOLE);
            holes.push(expr);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_text(text: &str) -> Vec<String> {
        let mut endpoints = Endpoints::new();
        endpoints.add_text(text);
        endpoints.iter().map(str::to_owned).collect()
    }

    fn from_source(name: &str, source: &str) -> Vec<String> {
        let mut endpoints = Endpoints::new();
        endpoints.add_source(Path::new(name), source);
        endpoints.iter().map(str::to_owned).collect()
    }

    #[test]
    fn keeps_port_and_pathname_and_drops_query_and_fragment() {
        assert_eq!(
            from_text("see https://User:pw@API.Example.com:8443/v1/items?q=1#top."),
            ["api.example.com", "api.example.com:8443/v1/items"]
        );
    }

    #[test]
    fn treats_root_path_as_no_path() {
        assert_eq!(
            from_text("https://example.com/ and example.com"),
            ["example.com"]
        );
    }

    #[test]
    fn bare_domains_need_a_delegated_tld() {
        assert_eq!(
            from_text("index.handler resolver.define app.js cdn.evil.co.uk/lib.js x.onion"),
            ["cdn.evil.co.uk", "cdn.evil.co.uk/lib.js", "x.onion"]
        );
    }

    #[test]
    fn scheme_waives_tld_check_but_not_dot() {
        assert_eq!(
            from_text("https://svc.internal/x http://localhost:3000/"),
            ["svc.internal", "svc.internal/x"]
        );
    }

    #[test]
    fn normalizes_ipv4_and_rejects_version_numbers() {
        assert_eq!(
            from_text("10.0.0.1:22 v1.2.3 pi=3.14 http://0x7f.1/x 999.1.1.1"),
            ["10.0.0.1", "10.0.0.1:22", "127.0.0.1", "127.0.0.1/x"]
        );
    }

    #[test]
    fn finds_bracketed_and_bare_ipv6() {
        assert_eq!(
            from_text("http://[2001:DB8::1]:443/x fe80::1%eth0 a::before ::"),
            ["[2001:db8::1]", "[2001:db8::1]:443/x", "[fe80::1]"]
        );
    }

    #[test]
    fn converts_internationalized_domains_to_punycode() {
        assert_eq!(from_text("https://例え.jp/"), ["xn--r8jz45g.jp"]);
    }

    #[test]
    fn finds_ascii_domain_written_against_other_letters() {
        assert!(from_text("访问evil.com获取").contains(&"evil.com".to_owned()));
    }

    #[test]
    fn finds_hosts_nested_in_userinfo_and_path() {
        assert_eq!(
            from_text("https://evil.com@good.example/fetch/evil.org/x"),
            [
                "evil.com",
                "evil.org",
                "evil.org/x",
                "good.example",
                "good.example/fetch/evil.org/x"
            ]
        );
    }

    #[test]
    fn template_literal_holes_end_hosts_and_stay_in_paths() {
        assert_eq!(
            from_source(
                "index.js",
                "fetch(`https://${sub}.evil.com/api/${id}/items`)"
            ),
            ["evil.com", "evil.com/api/*/items"]
        );
    }

    #[test]
    fn joins_concatenations_and_reads_strings_in_operands() {
        assert_eq!(
            from_source(
                "index.ts",
                r#"const u = "https://" + host + ".evil.com:" + 8443 + "/x";
                   const v = "https://" + (prod ? "a.example.com" : "b.example.com") + `/${p}`;"#
            ),
            [
                "a.example.com",
                "b.example.com",
                "evil.com",
                "evil.com:8443/x"
            ]
        );
    }

    #[test]
    fn reads_escapes_comments_jsx_text_and_regexes() {
        assert_eq!(
            from_source(
                "App.jsx",
                r#"// mirror: mirror.evil.org
                   const a = "https:\/\/evil\x2ecom";
                   const re = /^https:\/\/evil\.io\//;
                   export const App = () => <p>Visit evil.net</p>;"#
            ),
            ["evil.com", "evil.io", "evil.net", "mirror.evil.org"]
        );
    }

    #[test]
    fn falls_back_to_text_when_parsing_fails() {
        assert_eq!(from_source("broken.js", "const = ; evil.com"), ["evil.com"]);
    }

    #[test]
    fn json_escapes_do_not_merge_into_domains() {
        assert_eq!(
            from_source("app.js.map", r#"{"sourcesContent": ["line\nevil.com"]}"#),
            ["evil.com"]
        );
    }

    #[test]
    fn long_slash_separated_runs_stay_linear() {
        // Base64 blobs in bundles look like one long path.
        let blob = format!("{}evil.com", "ab/".repeat(200_000));
        assert_eq!(from_text(&blob), ["evil.com"]);
    }

    #[test]
    fn long_concatenation_chains_are_joined() {
        let chain = vec![r#""a""#; 2_000].join(" + ");
        let source = format!(r#"const u = "https://evil." + "com/" + {chain};"#);
        let found = from_source("bundle.js", &source);
        assert_eq!(found[0], "evil.com");
        assert_eq!(found[1], format!("evil.com/{}", "a".repeat(2_000)));
    }

    #[test]
    fn output_is_deduplicated_and_byte_ordered() {
        assert_eq!(
            from_text("b.com a.com:80 a.com/x a.com b.com"),
            ["a.com", "a.com/x", "a.com:80", "b.com"]
        );
    }
}
