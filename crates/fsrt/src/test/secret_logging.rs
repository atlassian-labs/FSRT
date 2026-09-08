use super::*;

fn project(source: &str) -> MockForgeProject<'_> {
    let mut project = MockForgeProject::files_from_string(source);
    project.manifest_file_content = Some("modules:\n  macro:\n    - key: test\n      function: main\n      title: Test\n  function:\n    - key: main\n      handler: index.run\napp:\n  id: test-app\npermissions:\n  scopes: []\n".to_owned());
    project
}

fn scan(source: &str) -> Report {
    let mut project = project("// src/index.js\n");
    project.add_file("src/index.js", source);
    scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "secret-logging"]),
    )
}

fn assert_findings(source: &str, count: usize) {
    let report = scan(source);
    assert!(!report.has_errors());
    assert_eq!(
        report.into_vulns().len(),
        count,
        "source: {source}\n{report:#?}"
    );
    assert!(report.into_vulns().iter().all(|vuln| {
        vuln.check_name()
            .starts_with("Custom-Check-Secret-Logging-")
    }));
}

#[test]
fn secret_logging_tracks_expressions_and_reassignment() {
    for (body, count) in [
        ("console.log(await kvs.getSecret('key'));", 1),
        (
            "const secret = await kvs.getSecret('key'); const copy = secret; console.log('label', copy);",
            1,
        ),
        (
            "const secret = await kvs.getSecret('key'); console.log(`secret: ${secret}`);",
            1,
        ),
        (
            "const secret = await kvs.getSecret('key'); console.log('prefix' + secret);",
            1,
        ),
        (
            "const secret = await kvs.getSecret('key'); console.log(secret.toString());",
            1,
        ),
        (
            "const secret = await kvs.getSecret('key'); console.log(JSON.stringify({secret}));",
            1,
        ),
        (
            "let value = await kvs.getSecret('key'); value = 'redacted'; console.log(value);",
            0,
        ),
        (
            "let value = 'public'; console.log(value); value = await kvs.getSecret('key');",
            0,
        ),
        (
            "const secret = await kvs.getSecret('key'); console.log(secret); console.log(secret);",
            2,
        ),
        ("console.log(await kvs.get('key'));", 0),
        ("kvs.getSecret('key'); console.log('public');", 0),
        ("console.warn(await kvs.getSecret('key'));", 0),
        ("console.log(request.payload);", 0),
        ("console.log(kvs.getSecret);", 0),
    ] {
        assert_findings(
            &format!(
                "import {{ kvs }} from '@forge/kvs'; export async function run(request) {{ {body} }}"
            ),
            count,
        );
    }
}

#[test]
fn secret_logging_respects_import_bindings() {
    for (source, count) in [
        (
            "import { kvs as store } from '@forge/kvs'; export async function run() { console.log(await store.getSecret('key')); }",
            1,
        ),
        (
            "import { kvs } from '@forge/kvs'; export async function run() { console['log'](await kvs['getSecret']('key')); }",
            1,
        ),
        (
            "import { kvs } from 'other-package'; export async function run() { console.log(await kvs.getSecret('key')); }",
            0,
        ),
        (
            "import { other as kvs } from '@forge/kvs'; export async function run() { console.log(await kvs.getSecret('key')); }",
            0,
        ),
        (
            "export async function run(kvs) { console.log(await kvs.getSecret('key')); }",
            0,
        ),
        (
            "import { kvs } from '@forge/kvs'; export async function run(kvs) { console.log(await kvs.getSecret('key')); }",
            0,
        ),
        (
            "import { kvs } from '@forge/kvs'; export async function run(console) { console.log(await kvs.getSecret('key')); }",
            0,
        ),
    ] {
        assert_findings(source, count);
    }
}

#[test]
fn secret_logging_joins_branches_and_loops() {
    for body in [
        "let value = 'public'; if (flag) { value = await kvs.getSecret('key'); } console.log(value);",
        "let value = 'public'; if (flag) { value = await kvs.getSecret('key'); } else { value = 'other'; } console.log(value);",
        "const value = flag ? await kvs.getSecret('key') : 'public'; console.log(value);",
        "let value = 'public'; while (flag) { console.log(value); value = await kvs.getSecret('key'); }",
        "let value = 'public'; while (flag) { value = await kvs.getSecret('key'); } console.log(value);",
    ] {
        assert_findings(
            &format!(
                "import {{ kvs }} from '@forge/kvs'; export async function run(flag) {{ {body} }}"
            ),
            1,
        );
    }

    assert_findings(
        "import { kvs } from '@forge/kvs'; export async function run(flag) { let value = await kvs.getSecret('key'); if (flag) { value = 'a'; } else { value = 'b'; } console.log(value); }",
        0,
    );
}

#[test]
fn secret_logging_tracks_helper_arguments_returns_and_captures() {
    for functions in [
        "function log(value) { console.log(value); } export async function run() { log(await kvs.getSecret('key')); }",
        "async function read() { return await kvs.getSecret('key'); } export async function run() { console.log(await read()); }",
        "function identity(value) { return value; } export async function run() { console.log(identity(await kvs.getSecret('key'))); }",
        "function log(a, b) { console.log(b); } export async function run() { log('public', await kvs.getSecret('key')); }",
        "function log(value) { console.log(value); } function pass(value) { log(value); } export async function run() { pass(await kvs.getSecret('key')); }",
        "export async function run() { const value = await kvs.getSecret('key'); function log() { console.log(value); } log(); }",
        "const value = kvs.getSecret('key'); export async function run() { console.log(await value); }",
        "function recurse(value, flag) { if (flag) { return recurse(value, false); } return value; } export async function run() { console.log(recurse(await kvs.getSecret('key'), true)); }",
    ] {
        assert_findings(
            &format!("import {{ kvs }} from '@forge/kvs'; {functions}"),
            1,
        );
    }

    for functions in [
        "function redact(value) { return '[redacted]'; } export async function run() { console.log(redact(await kvs.getSecret('key'))); }",
        "function log(value) { console.log(value); } export async function run() { const secret = await kvs.getSecret('key'); log('public'); }",
        "async function unused() { console.log(await kvs.getSecret('key')); } export function run() {}",
    ] {
        assert_findings(
            &format!("import {{ kvs }} from '@forge/kvs'; {functions}"),
            0,
        );
    }
}

#[test]
fn secret_logging_tracks_cross_module_helpers() {
    let project = project(
        "// src/index.js\nimport { read, log } from './helpers'; export async function run() { log(await read()); }\n// src/helpers.js\nimport { kvs } from '@forge/kvs'; export async function read() { return kvs.getSecret('key'); } export function log(value) { console.log(value); }",
    );
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "secret-logging"]),
    );
    assert_eq!(report.into_vulns().len(), 1, "{report:#?}");
    assert!(report.into_vulns()[0].description().contains("log"));
}

#[test]
fn secret_logging_is_enabled_by_default_and_can_be_excluded() {
    let project = project(
        "// src/index.js\nimport { kvs } from '@forge/kvs'; export async function run() { console.log(await kvs.getSecret('key')); }",
    );
    assert!(
        scan_directory_test(project.clone())
            .into_vulns()
            .iter()
            .any(|vuln| vuln
                .check_name()
                .starts_with("Custom-Check-Secret-Logging-"))
    );
    assert!(
        scan_directory_test_with_args(project, Args::parse_from(["fsrt", "--scanners", "secret"]))
            .has_no_vulns()
    );
}

#[test]
fn secret_logging_tracks_aggregates_and_module_initializers() {
    for functions in [
        "export async function run() { const secret = await kvs.getSecret('key'); console.log([secret]); }",
        "export async function run() { const secret = await kvs.getSecret('key'); const { value } = { value: secret }; console.log(value); }",
        "function log({ value }) { console.log(value); } export async function run() { log({ value: await kvs.getSecret('key') }); }",
        "console.log(kvs.getSecret('key')); export function run() {}",
    ] {
        assert_findings(
            &format!("import {{ kvs }} from '@forge/kvs'; {functions}"),
            1,
        );
    }
}

#[test]
fn secret_logging_excludes_local_console_variables() {
    for functions in [
        "export async function run() { let console; console.log(await kvs.getSecret('key')); }",
        "const console = logger; export async function run() { console.log(await kvs.getSecret('key')); }",
    ] {
        assert_findings(
            &format!("import {{ kvs }} from '@forge/kvs'; {functions}"),
            0,
        );
    }
}

#[test]
fn secret_logging_scans_resolvers_without_sharing_taint_between_entries() {
    let source = "// src/index.js
        import Resolver from '@forge/resolver';
        import { kvs } from '@forge/kvs';
        const resolver = new Resolver();
        function identity(value) { return value; }
        resolver.define('read', async () => { identity(await kvs.getSecret('key')); });
        resolver.define('safe', () => { console.log(identity('public')); });
        resolver.define('leak', async () => { console.log(await kvs.getSecret('key')); });
        export const run = resolver.getDefinitions();";
    let report = scan_directory_test_with_args(
        project(source),
        Args::parse_from(["fsrt", "--scanners", "secret-logging"]),
    );
    assert_eq!(report.into_vulns().len(), 1, "{report:#?}");
    assert!(report.into_vulns()[0].description().contains("leak"));
}

#[test]
fn secret_logging_tracks_promise_fulfillment() {
    for (body, count) in [
        ("kvs.getSecret('key').then(value => console.log(value));", 1),
        (
            "kvs.getSecret('key').then(function(value) { console.log(value); });",
            1,
        ),
        ("kvs.getSecret('key').then(console.log);", 1),
        (
            "kvs.getSecret('key').then(value => { return value; }).then(value => console.log(value));",
            1,
        ),
        (
            "kvs.getSecret('key').then(value => { return 'redacted'; }).then(value => console.log(value));",
            0,
        ),
        ("kvs.get('key').then(value => console.log(value));", 0),
    ] {
        assert_findings(
            &format!("import {{ kvs }} from '@forge/kvs'; export function run() {{ {body} }}"),
            count,
        );
    }
}

#[test]
fn secret_logging_uses_capture_values_at_calls() {
    for (functions, count) in [
        (
            "export async function run() { let value = await kvs.getSecret('key'); value = '[redacted]'; function log() { console.log(value); } log(); }",
            0,
        ),
        (
            "export async function run() { let value = 'public'; function log() { console.log(value); } log(); value = await kvs.getSecret('key'); }",
            0,
        ),
        (
            "export async function run() { let value = await kvs.getSecret('key'); function log() { console.log(value); } log(); value = '[redacted]'; }",
            1,
        ),
        (
            "export async function run() { let value = await kvs.getSecret('key'); function log() { console.log(value); value = '[redacted]'; } log(); }",
            1,
        ),
        (
            "export async function run() { let value = await kvs.getSecret('key'); function log() { value = '[redacted]'; console.log(value); } log(); }",
            0,
        ),
        (
            "export async function run() { const {value} = {value: await kvs.getSecret('key')}; function log() { console.log(value); } log(); }",
            1,
        ),
        (
            "export async function run() { let value = await kvs.getSecret('key'); function log() { console.log(value); } value = '[redacted]'; function pass() { log(); } pass(); }",
            0,
        ),
        (
            "export async function run() { const value = await kvs.getSecret('key'); function log() { console.log(value); } function pass() { log(); } pass(); }",
            1,
        ),
        (
            "export async function run() { let value = await kvs.getSecret('key'); value = '[redacted]'; Promise.resolve().then(() => console.log(value)); }",
            0,
        ),
        (
            "export async function run() { const value = await kvs.getSecret('key'); Promise.resolve().then(() => console.log(value)); }",
            1,
        ),
        (
            "let value = kvs.getSecret('key'); export async function run() { console.log(await value); value = 'redacted'; }",
            1,
        ),
        (
            "let value = kvs.getSecret('key'); export async function run() { value = 'redacted'; console.log(await value); }",
            0,
        ),
        (
            "let value = kvs.getSecret('key'); function log() { console.log(value); } export function run() { value = 'redacted'; log(); }",
            0,
        ),
        (
            "let value = kvs.getSecret('key'); value = 'redacted'; export function run() { console.log(value); }",
            0,
        ),
        (
            "let value = kvs.getSecret('key'); export function run() { let value = 'public'; console.log(value); }",
            0,
        ),
        (
            "let value = 'public'; export async function run() { console.log(value); value = await kvs.getSecret('key'); }",
            0,
        ),
        (
            "export async function run(flag) { let value = await kvs.getSecret('key'); if (flag) { value = 'redacted'; } else { value = 'public'; } function log() { console.log(value); } log(); }",
            0,
        ),
        (
            "export async function run(flag) { let value = 'public'; if (flag) { value = await kvs.getSecret('key'); } function log() { console.log(value); } log(); }",
            1,
        ),
    ] {
        assert_findings(
            &format!("import {{ kvs }} from '@forge/kvs'; {functions}"),
            count,
        );
    }
}

#[test]
fn secret_logging_distinguishes_values_from_operator_metadata() {
    for expression in [
        "void secret",
        "typeof secret",
        "!secret",
        "!!secret",
        "secret === undefined",
        "secret !== null",
        "secret == null",
        "secret != null",
        "secret < 1",
        "secret > 1",
        "secret <= 1",
        "secret >= 1",
        "'key' in secret",
        "secret instanceof Object",
        "delete secret.key",
    ] {
        assert_findings(
            &format!(
                "import {{ kvs }} from '@forge/kvs'; export async function run() {{ const secret = await kvs.getSecret('key'); console.log({expression}); }}"
            ),
            0,
        );
    }
    for expression in [
        "secret + 'suffix'",
        "secret || 'fallback'",
        "secret && 'fallback'",
        "secret ?? 'fallback'",
        "+secret",
        "-secret",
        "~secret",
        "secret - 1",
        "secret * 2",
        "secret / 2",
        "secret % 2",
        "secret ** 2",
        "secret | 1",
        "secret & 1",
        "secret ^ 1",
        "secret << 1",
        "secret >> 1",
        "secret >>> 1",
    ] {
        assert_findings(
            &format!(
                "import {{ kvs }} from '@forge/kvs'; export async function run() {{ const secret = await kvs.getSecret('key'); console.log({expression}); }}"
            ),
            1,
        );
    }
}
