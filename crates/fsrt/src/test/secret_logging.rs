use super::*;

fn project(source: &str) -> MockForgeProject<'_> {
    let mut project = MockForgeProject::files_from_string(source);
    project.manifest_file_content = Some("modules:\n  macro:\n    - key: test\n      function: main\n      title: Test\n  function:\n    - key: main\n      handler: index.run\napp:\n  id: test-app\npermissions:\n  scopes: []\n".to_owned());
    project
}

fn scan(source: &str) -> Report {
    scan_with(source, &[])
}

fn scan_with(source: &str, options: &[&str]) -> Report {
    let mut project = project("// src/index.js\n");
    project.add_file("src/index.js", source);
    let args = ["fsrt", "--scanners", "secret-logging"]
        .into_iter()
        .chain(options.iter().copied());
    scan_directory_test_with_args(project, Args::parse_from(args))
}

fn assert_findings(source: &str, count: usize) {
    assert_findings_with(source, &[], count);
}

fn assert_findings_with(source: &str, options: &[&str], count: usize) {
    let report = scan_with(source, options);
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
            "import kvs from '@forge/kvs'; export async function run() { console.log(await kvs.getSecret('key')); }",
            1,
        ),
        (
            "import store, { WhereConditions } from '@forge/kvs'; export async function run() { console.log(await store.getSecret('key')); }",
            1,
        ),
        (
            "import * as kvs from '@forge/kvs'; export async function run() { console.log(await kvs.getSecret('key')); }",
            0,
        ),
        (
            "import { storage } from '@forge/api'; export async function run() { console.log(await storage.getSecret('key')); }",
            1,
        ),
        (
            "import api, { storage as legacy } from '@forge/api'; export async function run() { console.log(await legacy.getSecret('key')); }",
            1,
        ),
        (
            "import { storage } from '@forge/api'; export async function run() { console.log(await storage.get('key')); }",
            0,
        ),
        (
            "import { storage } from 'other-package'; export async function run() { console.log(await storage.getSecret('key')); }",
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
fn secret_logging_is_disabled_by_default_and_runs_when_selected() {
    let project = project(
        "// src/index.js\nimport { kvs } from '@forge/kvs'; export async function run() { console.log(await kvs.getSecret('key')); }",
    );
    let findings = |report: &Report| {
        report
            .into_vulns()
            .iter()
            .filter(|vuln| {
                vuln.check_name()
                    .starts_with("Custom-Check-Secret-Logging-")
            })
            .count()
    };
    assert_eq!(findings(&scan_directory_test(project.clone())), 0);
    for (scanners, count) in [
        ("secret", 0),
        ("secret-logging", 1),
        ("secret,secret-logging", 1),
    ] {
        let report = scan_directory_test_with_args(
            project.clone(),
            Args::parse_from(["fsrt", "--scanners", scanners]),
        );
        assert_eq!(
            findings(&report),
            count,
            "--scanners {scanners}\n{report:#?}"
        );
    }
}

#[test]
fn secret_logging_tracks_aggregates_and_module_initializers() {
    for functions in [
        "export async function run() { const secret = await kvs.getSecret('key'); console.log([secret]); }",
        "export async function run() { const secret = await kvs.getSecret('key'); console.log({ value: secret }); }",
        "export async function run() { const config = { value: await kvs.getSecret('key') }; console.log(JSON.stringify(config)); }",
        "export async function run() { const config = {}; config.value = await kvs.getSecret('key'); console.log(config); }",
        "function log(value) { console.log(value); } export async function run() { log({ value: await kvs.getSecret('key') }); }",
        "export async function run() { console.log(await Promise.all([kvs.getSecret('key'), fetchPublic()])); }",
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
        "export async function run() { let console; console.warn(await kvs.getSecret('key')); }",
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
            "export async function run() { const value = {value: await kvs.getSecret('key')}; function log() { console.log(value); } log(); }",
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

#[test]
fn secret_logging_logical_presence_checks_do_not_disclose_values() {
    for (expression, count) in [
        ("secret && 'present'", 0),
        ("secret && true", 0),
        ("(secret && 'present') || 'missing'", 0),
        ("Boolean(secret) || false", 0),
        ("secret || 'fallback'", 1),
        ("flag && secret", 1),
        ("flag || secret", 1),
        ("secret ?? 'fallback'", 1),
        ("secret && secret", 1),
    ] {
        for options in [&[][..], &["--secret-logging-version", "v1"][..]] {
            assert_findings_with(
                &format!(
                    "import {{ kvs }} from '@forge/kvs'; export async function run(flag) {{ const secret = await kvs.getSecret('key'); console.log({expression}); }}"
                ),
                options,
                count,
            );
        }
    }
}

#[test]
fn secret_logging_reports_console_methods() {
    for (method, count) in [
        ("log", 1),
        ("info", 1),
        ("warn", 1),
        ("error", 1),
        ("debug", 1),
        ("table", 0),
        ("dir", 0),
    ] {
        let report = scan(&format!(
            "import {{ kvs }} from '@forge/kvs'; export async function run() {{ console.{method}(await kvs.getSecret('key')); }}"
        ));
        let vulns = report.into_vulns();
        assert_eq!(vulns.len(), count, "console.{method}\n{report:#?}");
        if let [vuln] = vulns {
            assert!(
                vuln.description()
                    .contains(&format!("logged to console.{method}")),
                "{vuln:#?}"
            );
        }
    }
}

#[test]
fn secret_logging_treats_property_reads_as_clean() {
    for (body, count) in [
        ("console.log(secret.length);", 0),
        ("console.log(secret.token);", 0),
        ("console.log(secret['token']);", 0),
        ("console.log(secret[0]);", 0),
        ("console.log(`token: ${secret.token}`);", 0),
        ("console.log(secret.token.trim());", 0),
        ("const { token } = secret; console.log(token);", 0),
        ("const [token] = secret; console.log(token);", 0),
        (
            "const config = { token: secret, id: 'public' }; console.log(config.id);",
            0,
        ),
        (
            "const [value, groups] = await Promise.all([secret, fetchGroups()]); console.log(groups.length);",
            0,
        ),
        (
            "function log({ value }) { console.log(value); } log({ value: secret });",
            0,
        ),
        ("console.log(secret);", 1),
        ("console.log(secret.trim());", 1),
        ("console.log(JSON.stringify(secret));", 1),
        (
            "const config = { token: secret, id: 'public' }; console.log(config);",
            1,
        ),
    ] {
        assert_findings(
            &format!(
                "import {{ kvs }} from '@forge/kvs'; function fetchGroups() {{}} export async function run() {{ const secret = await kvs.getSecret('key'); {body} }}"
            ),
            count,
        );
    }
}

#[test]
fn secret_logging_recognizes_exact_secret_redaction() {
    for (body, count) in [
        (
            "function redact(text, secret) { let out = String(text); if (secret) { out = out.split(secret).join('[REDACTED]'); } return out.replace(/Bearer\\s+\\S+/g, 'Bearer [REDACTED]'); } console.log(redact(body, secret));",
            0,
        ),
        ("console.log(body.replaceAll(secret, '***'));", 0),
        (
            "const url = `https://example.com/?key=${secret.trim()}`; console.log(url.replace(secret, '***'));",
            0,
        ),
        ("console.log(body.split(secret).join(secret));", 1),
        ("console.log(body.replace('placeholder', secret));", 1),
        ("console.log(secret.replace(body, '***'));", 1),
        ("console.log(secret.replace(/\\s/g, ''));", 1),
        ("console.log(secret.split(','));", 1),
        (
            "console.log(`${secret.substring(0, 12)}...${secret.substring(secret.length - 4)}`);",
            1,
        ),
    ] {
        assert_findings(
            &format!(
                "import {{ kvs }} from '@forge/kvs'; export async function run(body) {{ const secret = await kvs.getSecret('key'); {body} }}"
            ),
            count,
        );
    }
}

#[test]
fn secret_logging_drops_taint_for_known_non_propagating_calls() {
    for (body, count) in [
        // A bare call to a known global, not just a method call, is recognized.
        ("console.log(Object.keys(secret));", 0),
        ("console.log(Boolean(secret));", 0),
        (
            "const r = await fetch('https://example.com', { headers: { Authorization: secret } }); console.log(r);",
            0,
        ),
        // A method call on a locally declared (not global) receiver is still
        // recognized by name alone.
        (
            "const api = {}; const r = await api.invokeRemote('app', { headers: { Authorization: secret } }); console.log(r);",
            0,
        ),
        // The call's own arguments stay reportable; only its result is clean.
        ("console.log({ headers: { Authorization: secret } });", 1),
    ] {
        assert_findings(
            &format!(
                "import {{ kvs }} from '@forge/kvs'; export async function run() {{ const secret = await kvs.getSecret('key'); {body} }}"
            ),
            count,
        );
    }
}

#[test]
fn secret_logging_builtin_rules_respect_bindings_and_receiver() {
    for (setup, expression, count) in [
        ("", "Boolean(secret)", 0),
        ("", "Object.keys(secret)", 0),
        ("", "Object['keys'](secret)", 0),
        ("", "Object.values(secret)", 1),
        ("", "Object.entries(secret)", 1),
        ("", "String(secret)", 1),
        ("", "JSON.stringify(secret)", 1),
        ("", "unknownGlobal(secret)", 1),
        (
            "function Boolean(value) { return value; }",
            "Boolean(secret)",
            1,
        ),
        (
            "const Object = { keys(value) { return value; } };",
            "Object.keys(secret)",
            1,
        ),
        ("const other = {};", "other.keys(secret)", 1),
        ("const other = {};", "other.Boolean(secret)", 1),
        ("let Boolean;", "Boolean(secret)", 1),
        ("let Object;", "Object.keys(secret)", 1),
    ] {
        for options in [&[][..], &["--secret-logging-version", "v1"][..]] {
            assert_findings_with(
                &format!(
                    "import {{ kvs }} from '@forge/kvs'; {setup} export async function run() {{ const secret = await kvs.getSecret('key'); console.log({expression}); }}"
                ),
                options,
                count,
            );
        }
    }
}

const V1: &[&str] = &["--secret-logging-version", "v1"];

fn assert_v1_findings(body: &str, count: usize) {
    assert_findings_with(
        &format!(
            "import {{ kvs }} from '@forge/kvs'; function pick(value) {{ return value.creds; }} export async function run(key) {{ const secret = await kvs.getSecret('key'); {body} }}"
        ),
        V1,
        count,
    );
}

#[test]
fn secret_logging_v1_reports_property_reads_by_last_name() {
    for body in [
        "console.log(secret[key].password);",
        "const account = secret.accounts[key]; console.log(account.auth.password.trim());",
        "const { password } = secret.accounts[key]; console.log(password);",
        "console.log(`auth=${secret.config.apiToken}`);",
        "console.log(pick(secret).client_secret);",
        "const config = secret.config; function log() { console.log(config.password); } log();",
        "console.log(JSON.parse(secret.config).password);",
        "console.log({ password: secret.password });",
        "console.log(secret);",
    ] {
        assert_v1_findings(body, 1);
    }

    for body in [
        "console.log(secret[key]);",
        "console.log(secret.accounts[key].auth);",
        "console.log(JSON.stringify(secret[key]));",
        "console.log({ host: secret.host });",
        "console.log(secret.password.length);",
        "console.log(secret.password.value);",
        "console.log(secret.nextPageToken);",
        "const user = { password: key }; console.log(user.password);",
    ] {
        assert_v1_findings(body, 0);
    }
}

#[test]
fn secret_logging_v1_tracks_written_properties() {
    for body in [
        "const config = { host: secret.host, password: 'literal' }; console.log(config.password);",
        "const config = { auth: { user: secret.user, password: 'literal' } }; console.log(config.auth.password);",
        "function log(config) { console.log(config.password); } log({ host: secret.host, password: 'literal' });",
        "function make(value) { return { host: value.host, password: 'literal' }; } console.log(make(secret).password);",
        "const config = { host: secret.host, password: 'literal' }; function log() { console.log(config.password); } log();",
        "const config = {}; config.password = secret.password; config.password = 'literal'; console.log(config.password);",
        "const config = { host: secret.host, password: 'literal' }; const alias = config; console.log(alias.password);",
    ] {
        assert_v1_findings(body, 0);
    }

    for body in [
        "const config = { host: secret }; console.log(config.host);",
        "const config = { host: 'public' }; if (key) { config.host = secret; } console.log(config.host);",
        "const config = { host: 'public' }; config[key] = secret; console.log(config.host);",
        "function log({ value }) { console.log(value); } log({ value: secret });",
        "const config = { auth: { password: secret.password } }; console.log(config.auth);",
    ] {
        assert_v1_findings(body, 1);
    }
}

#[test]
fn secret_logging_v1_uses_configured_suffixes() {
    let source = |read: &str| {
        format!(
            "import {{ kvs }} from '@forge/kvs'; export async function run() {{ const secret = await kvs.getSecret('key'); console.log(secret.{read}); }}"
        )
    };
    let suffixes = [V1, &["--secret-logging-suffixes", "credential"]].concat();
    assert_findings_with(&source("dbCredential"), &suffixes, 1);
    assert_findings_with(&source("password"), &suffixes, 0);

    let excluded = [V1, &["--secret-logging-excluded-suffixes", "access_token"]].concat();
    assert_findings_with(&source("accessToken"), &excluded, 0);
    assert_findings_with(&source("refresh_token"), &excluded, 1);
    assert_findings_with(&source("nextPageToken"), &excluded, 1);
}
