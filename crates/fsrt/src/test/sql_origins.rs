//! A SQL-injection finding's proof names what made the query attacker controlled.

use super::*;

/// The proof of each SQL-injection finding in `src/index.js`.
fn sql_proofs(source: &str) -> Vec<String> {
    let source = format!("// src/index.js\nimport sql from '@forge/sql';\n{source}");
    let report = scan_directory_test_with_args(
        MockForgeProject::files_from_string(&source),
        Args::parse_from(["fsrt", "--scanners", "sql-injection"]),
    );
    assert!(!report.has_errors(), "{source}\n{report:#?}");
    report
        .into_vulns()
        .iter()
        .filter(|vuln| vuln.check_name() == "forge-sql-injection")
        .map(|vuln| vuln.proof().to_owned())
        .collect()
}

/// The proof of the only finding.
fn sql_proof(source: &str) -> String {
    let mut proofs = sql_proofs(source);
    assert_eq!(proofs.len(), 1, "{source}\n{proofs:#?}");
    proofs.remove(0)
}

fn assert_origins(source: &str, origins: &str) {
    let proof = sql_proof(source);
    assert!(
        proof.starts_with(&format!("{origins} Propagation path: ")),
        "{source}\n{proof}"
    );
}

#[test]
fn sql_origin_of_a_module_payload() {
    assert_origins(
        "export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${payload.id}`);
        }",
        "Origin of the untrusted data: module payload.",
    );
}

#[test]
fn sql_origin_of_a_resolver_payload() {
    assert_origins(
        "import Resolver from '@forge/resolver';
        const resolver = new Resolver();
        resolver.define('find', async ({ payload }) => {
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${payload.id}`);
        });
        export const run = resolver.getDefinitions();",
        "Origin of the untrusted data: resolver payload.",
    );
}

#[test]
fn sql_origin_of_a_fetch_response() {
    assert_origins(
        "export async function run() {
            const response = await fetch('external-data');
            const body = await response.json();
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${body.id}`);
        }",
        "Origin of the untrusted data: fetch response.",
    );
}

#[test]
fn sql_origin_of_an_api_call_response() {
    assert_origins(
        "import api from '@forge/api';
        export async function run() {
            const response = await api.asUser().requestJira('/rest/api/3/issue/ABC-1');
            await sql.executeRaw(`SELECT * FROM issues WHERE summary = '${response.summary}'`);
        }",
        "Origin of the untrusted data: API call response.",
    );
}

#[test]
fn sql_origin_of_a_storage_read() {
    assert_origins(
        "import { kvs } from '@forge/kvs';
        export async function run() {
            const filter = await kvs.get('saved-filter');
            await sql.executeRaw(`SELECT * FROM users WHERE ${filter}`);
        }",
        "Origin of the untrusted data: storage read.",
    );
}

#[test]
fn sql_origin_of_a_secret_read() {
    assert_origins(
        "import { storage } from '@forge/api';
        export async function run() {
            const fragment = await storage.getSecret('fragment');
            await sql.executeRaw(`SELECT * FROM users ${fragment}`);
        }",
        "Origin of the untrusted data: secret read.",
    );
}

#[test]
fn sql_origin_of_rows_a_query_returned() {
    assert_origins(
        "export async function run() {
            const rows = await sql.prepare('SELECT name FROM users').execute();
            await sql.executeRaw(`SELECT * FROM audit WHERE actor = '${rows[0].name}'`);
        }",
        "Origin of the untrusted data: SQL result.",
    );
    // `executeRaw` returns rows too, and its own text is a literal here.
    assert_origins(
        "export async function run() {
            const rows = await sql.executeRaw('SELECT name FROM users');
            await sql.prepare(`SELECT * FROM audit WHERE actor = '${rows.rows[0].name}'`);
        }",
        "Origin of the untrusted data: SQL result.",
    );
}

#[test]
fn sql_origins_list_every_origin_that_reaches_the_query() {
    assert_origins(
        "import { kvs } from '@forge/kvs';
        export async function run(payload) {
            const saved = await kvs.get('saved-filter');
            const response = await fetch('external-data');
            const body = await response.json();
            await sql.executeRaw(`SELECT * FROM t WHERE a = ${payload.a} AND b = ${saved} AND c = ${body.c}`);
        }",
        "Origins of the untrusted data: module payload, fetch response, storage read.",
    );
}

#[test]
fn sql_origins_name_only_the_data_that_makes_the_text_unsafe() {
    // The payload is made a number, so only the fetched text can carry syntax.
    assert_origins(
        "export async function run(payload) {
            const response = await fetch('external-data');
            const body = await response.json();
            const limit = Number(payload.limit);
            await sql.executeRaw(`SELECT * FROM t WHERE n = ${body.name} LIMIT ${limit}`);
        }",
        "Origin of the untrusted data: fetch response.",
    );
    // An allowlist check makes the checked value safe, and keeps the rest.
    assert_origins(
        "export async function run(payload) {
            const response = await fetch('external-data');
            const body = await response.json();
            const columns = new Set(['name', 'created']);
            if (!columns.has(payload.sort)) { return; }
            await sql.executeRaw(`SELECT * FROM t WHERE n = ${body.name} ORDER BY ${payload.sort}`);
        }",
        "Origin of the untrusted data: fetch response.",
    );
}

#[test]
fn sql_origins_survive_a_join_with_a_constant() {
    assert_origins(
        "export async function run(payload) {
            const column = payload.sorted ? payload.column : 'created';
            await sql.executeRaw(`SELECT * FROM t ORDER BY ${column}`);
        }",
        "Origin of the untrusted data: module payload.",
    );
}

#[test]
fn sql_origins_follow_values_through_helpers_and_containers() {
    assert_origins(
        "function build(options) { return { text: `WHERE id = ${options.id}` }; }
        export async function run(payload) {
            const { text } = build({ id: payload.id });
            await sql.executeRaw(`SELECT * FROM t ${text}`);
        }",
        "Origin of the untrusted data: module payload.",
    );
}

#[test]
fn sql_origins_join_over_the_calls_of_one_helper() {
    assert_origins(
        "async function execute(text) { await sql.executeRaw(text); }
        export async function run(payload) {
            const response = await fetch('external-data');
            await execute(`SELECT * FROM a WHERE x = ${payload.x}`);
            await execute(`SELECT * FROM b WHERE y = ${await response.text()}`);
            await execute('SELECT 1');
        }",
        "Origins of the untrusted data: module payload, fetch response.",
    );
}

#[test]
fn sql_origins_of_a_sink_merge_over_resolver_callbacks() {
    assert_origins(
        "import Resolver from '@forge/resolver';
        import { kvs } from '@forge/kvs';
        const resolver = new Resolver();
        async function execute(query) { await sql.executeRaw(query); }
        resolver.define('first', async ({ payload }) => {
            await execute(`SELECT * FROM ${payload.table}`);
        });
        resolver.define('second', async () => {
            await execute(`SELECT * FROM ${await kvs.get('table')}`);
        });
        resolver.define('third', async ({ context }) => {
            await execute(`SELECT * FROM ${context.accountId}`);
        });
        export const run = resolver.getDefinitions();",
        "Origins of the untrusted data: resolver payload, storage read.",
    );
}

#[test]
fn sql_origins_are_kept_for_each_sink() {
    let proofs = sql_proofs(
        "import { kvs } from '@forge/kvs';
        export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM t WHERE a = ${payload.a}`);
            await sql.prepare(`SELECT * FROM t WHERE b = ${await kvs.get('b')}`);
        }",
    );
    assert_eq!(proofs.len(), 2, "{proofs:#?}");
    assert!(
        proofs.iter().any(|proof| proof
            .starts_with("Origin of the untrusted data: module payload. Propagation path: ")),
        "{proofs:#?}"
    );
    assert!(
        proofs.iter().any(|proof| proof
            .starts_with("Origin of the untrusted data: storage read. Propagation path: ")),
        "{proofs:#?}"
    );
}

#[test]
fn sql_proof_asks_the_reader_to_review_the_reported_origins() {
    let one = sql_proof(
        "export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${payload.id}`);
        }",
    );
    assert!(
        one.ends_with("review the reported origin and path in application context."),
        "{one}"
    );
    let many = sql_proof(
        "export async function run(payload) {
            const response = await fetch('external-data');
            await sql.executeRaw(`SELECT * FROM t WHERE a = ${payload.a} AND b = ${await response.text()}`);
        }",
    );
    assert!(
        many.ends_with("review the reported origins and path in application context."),
        "{many}"
    );
    for proof in [one, many] {
        assert!(!proof.contains("reported source"), "{proof}");
        assert!(proof.contains("Query argument at"), "{proof}");
        assert!(
            proof.contains("Binding: the value is part of SQL text"),
            "{proof}"
        );
    }
}

#[test]
fn sql_origins_never_make_an_unclassified_value_a_finding() {
    let proofs = sql_proofs(
        "export async function run(payload, context, event) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = '${event.userId}'`);
        }",
    );
    if forge_analyzer::sql_injection::UNKNOWN_IS_UNTRUSTED {
        assert_eq!(proofs.len(), 1, "{proofs:#?}");
        assert!(
            proofs[0].starts_with("Origin of the untrusted data: unclassified value. "),
            "{proofs:#?}"
        );
    } else {
        assert!(proofs.is_empty(), "{proofs:#?}");
    }
}
