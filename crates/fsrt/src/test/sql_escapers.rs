//! A helper that escapes a value into one SQL literal is trusted when its body
//! is shown to do so, and only then. The fixtures are the helpers of the triage
//! of `com.meewco.plugins.itassetmanager`: the sound ones must go silent, the
//! broken ones must stay High and say which check they fail.
use super::*;

/// The High findings and the proofs of a function module whose `run` puts
/// `query` into SQL text, with `helper` declared beside it.
fn scan(helper: &str, query: &str) -> Vec<String> {
    let source = format!(
        "import sql from '@forge/sql';\n{helper}\nexport async function run(payload) {{ await sql.executeRaw(`{query}`); }}"
    );
    // `files_from_string` drops every double quote, which these sources need.
    let mut project = MockForgeProject::files_from_string("// src/index.js\n");
    project.add_file("src/index.js", source.as_str());
    let report = scan_directory_test_with_args(
        project,
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

fn silent(helper: &str, query: &str) {
    let found = scan(helper, query);
    assert!(found.is_empty(), "{helper}\n{found:#?}");
}

fn stays_high(helper: &str, query: &str, failed_check: Option<&str>) {
    let found = scan(helper, query);
    assert_eq!(found.len(), 1, "{helper}\n{found:#?}");
    match failed_check {
        Some(check) => assert!(
            found[0].contains("Escaper check failed") && found[0].contains(check),
            "{helper}\n{}",
            found[0]
        ),
        None => assert!(!found[0].contains("Escaper check failed"), "{}", found[0]),
    }
}

const QUERY: &str = "DELETE FROM kit_items WHERE kit_id = ${esc(payload.id)}";

/// Guards, a number path, then backslashes and quotes doubled.
const ESC_DIRECT: &str = "function esc(v) {
    if (v === null || v === undefined) return 'NULL';
    if (typeof v === 'number') return String(v);
    const s = String(v).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, \"''\");
    return \"'\" + s + \"'\";
}";

#[test]
fn a_helper_that_doubles_backslashes_and_quotes_is_clean() {
    silent(ESC_DIRECT, QUERY);
    // Without the guards, which only handle other types.
    silent(
        "function esc(v) { return \"'\" + String(v).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, \"''\") + \"'\"; }",
        QUERY,
    );
    // The same escape read from a template literal, and with the quotes first.
    silent(
        "function esc(v) { return `'${String(v).replace(/'/g, \"''\").replace(/\\\\/g, '\\\\\\\\')}'`; }",
        QUERY,
    );
}

#[test]
fn the_itassetmanager_escaper_is_clean() {
    silent(
        r#"function esc(val) {
            if (val === null || val === undefined) return "NULL";
            if (typeof val === "number") return String(val);
            if (typeof val === "boolean") return val ? "1" : "0";
            const str = String(val)
                .replace(/\\/g, "\\\\")
                .replace(/\0/g, "\\0")
                .replace(/'/g, "''")
                .replace(/"/g, '\\"')
                .replace(/\x1a/g, "\\Z")
                .replace(/[\x00-\x1f\x7f]/g, "");
            return `'${str}'`;
        }"#,
        QUERY,
    );
}

#[test]
fn escaped_values_pushed_into_a_list_and_joined_are_clean() {
    silent(
        &format!(
            "{ESC_DIRECT}\nfunction build(payload) {{ const sets = []; sets.push('a = ' + esc(payload.a)); sets.push('b = ' + esc(payload.b)); return sets.join(', '); }}"
        ),
        "UPDATE t SET ${build(payload)} WHERE id = ${esc(payload.id)}",
    );
}

#[test]
fn a_helper_that_does_not_double_backslashes_stays_high_and_says_so() {
    for helper in [
        // Quotes are doubled and backslashes are not: `\'` ends the literal.
        "function esc(v) { return \"'\" + String(v).replace(/'/g, \"''\") + \"'\"; }",
        "function esc(v) {
            if (v === null || v === undefined) return 'NULL';
            if (typeof v === 'number') return String(v);
            return \"'\" + String(v).replace(/'/g, \"''\") + \"'\";
        }",
    ] {
        stays_high(helper, QUERY, Some("does not double backslashes"));
    }
}

#[test]
fn a_helper_that_escapes_nothing_stays_high_and_says_so() {
    stays_high(
        "function esc(v) { if (v === null || v === undefined) return 'NULL'; return \"'\" + v + \"'\"; }",
        QUERY,
        Some("returns the value without escaping it"),
    );
    stays_high(
        "function esc(v) { if (v === null || v === undefined) return 'NULL'; return v; }",
        QUERY,
        Some("returns the value without escaping it"),
    );
}

#[test]
fn a_replacement_that_is_not_global_stays_high_and_says_so() {
    stays_high(
        "function esc(v) { return \"'\" + String(v).replace(/\\\\/g, '\\\\\\\\').replace(/'/, \"''\") + \"'\"; }",
        QUERY,
        Some("does not apply to every occurrence"),
    );
    stays_high(
        "function esc(v) { return \"'\" + String(v).replace(/\\\\/g, '\\\\\\\\').replace(\"'\", \"''\") + \"'\"; }",
        QUERY,
        Some("does not apply to every occurrence"),
    );
}

#[test]
fn backslashes_doubled_after_a_step_that_adds_them_stay_high() {
    stays_high(
        "function esc(v) { return \"'\" + String(v).replace(/\\0/g, '\\\\0').replace(/\\\\/g, '\\\\\\\\').replace(/'/g, \"''\") + \"'\"; }",
        QUERY,
        Some("doubled after a step that adds backslashes"),
    );
}

#[test]
fn a_later_step_that_can_undo_an_earlier_one_stays_high() {
    stays_high(
        "function esc(v) { return \"'\" + String(v).replace(/\\\\/g, '\\\\\\\\').replace(/\\0/g, '\\\\0').replace(/0/g, '').replace(/'/g, \"''\") + \"'\"; }",
        QUERY,
        Some("can change characters an earlier step relied on"),
    );
}

#[test]
fn a_step_the_check_cannot_read_stays_high() {
    // Keeping only digits is sound, but needs another rule.
    stays_high(
        "function esc(v) { return \"'\" + String(v).replace(/[^0-9]/g, '') + \"'\"; }",
        QUERY,
        Some("not one this check can read"),
    );
}

#[test]
fn a_raw_value_next_to_escaped_ones_stays_high() {
    stays_high(
        ESC_DIRECT,
        "UPDATE t SET a = ${esc(payload.a)}, due = ${payload.due} WHERE id = ${esc(payload.id)}",
        None,
    );
    stays_high(ESC_DIRECT, "DELETE FROM t WHERE id = ${payload.id}", None);
}

#[test]
fn a_result_put_inside_another_quoted_literal_stays_high() {
    for query in [
        "DELETE FROM t WHERE id = '${esc(payload.id)}'",
        "DELETE FROM t WHERE id = \"${esc(payload.id)}\"",
        "DELETE FROM t WHERE name LIKE '%${esc(payload.id)}%'",
    ] {
        stays_high(ESC_DIRECT, query, Some("inside another quoted literal"));
    }
}

#[test]
fn one_call_inside_quotes_makes_every_call_of_the_helper_high() {
    let found = scan(
        ESC_DIRECT,
        "DELETE FROM t WHERE a = ${esc(payload.a)} AND b = '${esc(payload.b)}'",
    );
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(
        found[0].contains("inside another quoted literal"),
        "{found:#?}"
    );
}

#[test]
fn a_function_that_does_not_quote_or_replace_is_left_alone() {
    // Not an escaper: nothing is said about it, and its result stays attacker data.
    stays_high(
        "function tidy(v) { return v.trim(); }",
        "DELETE FROM kit_items WHERE kit_id = ${tidy(payload.id)}",
        None,
    );
}

#[test]
fn a_query_builder_that_contains_quotes_is_not_called_a_failed_escaper() {
    stays_high(
        "function where(v) { return `WHERE a = '${v}'`; }",
        "SELECT * FROM t ${where(payload.a)}",
        None,
    );
}

#[test]
fn only_the_verified_helper_is_trusted_among_two() {
    let helpers = format!(
        "{ESC_DIRECT}\nfunction loose(v) {{ return \"'\" + String(v).replace(/'/g, \"''\") + \"'\"; }}"
    );
    stays_high(
        &helpers,
        "DELETE FROM t WHERE a = ${esc(payload.a)} AND b = ${loose(payload.b)}",
        Some("`loose`"),
    );
}

#[test]
fn a_helper_imported_from_another_file_is_read_the_same() {
    for (helper, high) in [
        (
            "export function esc(v) { return \"'\" + String(v).replace(/\\\\/g, '\\\\\\\\').replace(/'/g, \"''\") + \"'\"; }",
            0,
        ),
        (
            "export function esc(v) { return \"'\" + String(v).replace(/'/g, \"''\") + \"'\"; }",
            1,
        ),
    ] {
        let mut project = MockForgeProject::files_from_string("// src/index.js\n");
        project.add_file("src/db.js", helper);
        project.add_file(
            "src/index.js",
            "import sql from '@forge/sql';
             import { esc } from './db';
             export async function run(payload) { await sql.executeRaw(`DELETE FROM t WHERE id = ${esc(payload.id)}`); }",
        );
        let report = scan_directory_test_with_args(
            project,
            Args::parse_from(["fsrt", "--scanners", "sql-injection"]),
        );
        assert!(
            report.contains_sql_vuln(Severity::High, high),
            "{helper}\n{report:#?}"
        );
    }
}
