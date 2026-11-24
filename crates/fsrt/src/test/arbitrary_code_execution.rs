//! Acceptance cases for the IR execution checker: sink recognition from IR
//! bindings, and suppression of text assembled only from constants. Run them
//! with `cargo nextest run -p fsrt -E 'test(arbitrary_code_execution)'`.

use super::*;

fn assert_execution_findings(project: &str, expected: usize) {
    let report = scan_directory_test_with_args(
        MockForgeProject::files_from_string(project),
        Args::parse_from(["fsrt", "--scanners", "arbitrary-code-execution"]),
    );
    assert!(!report.has_errors(), "{report:#?}");
    let findings: Vec<_> = report
        .into_vulns()
        .iter()
        .filter(|vuln| {
            vuln.check_name()
                .starts_with("Custom-Check-Arbitrary-Code-Execution-")
        })
        .collect();
    assert_eq!(findings.len(), expected, "{project}\n{report:#?}");
}

#[test]
fn arbitrary_code_execution_requires_explicit_selection() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        eval(fetch('/code'));
        export function run(input) { eval(input.source); }",
    );
    for (options, expected) in [
        (vec!["fsrt"], 0),
        (vec!["fsrt", "--scanners", "secret-logging"], 0),
        (vec!["fsrt", "--scanners", "arbitrary-code-execution"], 2),
        (
            vec![
                "fsrt",
                "--scanners",
                "secret-logging,arbitrary-code-execution",
            ],
            2,
        ),
    ] {
        let report = scan_directory_test_with_args(project.clone(), Args::parse_from(&options));
        assert!(!report.has_errors(), "{options:?}: {report:#?}");
        assert!(
            report.contains_arbitrary_code_execution_vuln(expected),
            "{options:?}: {report:#?}"
        );
        assert_eq!(
            report.into_vulns().len(),
            expected,
            "{options:?}: {report:#?}"
        );
    }
}

#[test]
fn mixed_static_and_user_branches_still_report() {
    for (left, right) in [("'1 + 1'", "input.source"), ("input.source", "'1 + 1'")] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            export function run(input) {{
                let source;
                if (input.useStatic) {{ source = {left}; }}
                else {{ source = {right}; }}
                eval(source);
            }}"#
            ),
            1,
        );
    }
}

#[test]
fn every_manifest_function_argument_is_a_source() {
    // Exercise each position independently: tainting only the first argument
    // must not accidentally satisfy a count for a sink using all arguments.
    for argument in ["event", "context", "extra"] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            export function onEvent(event, context, extra) {{ eval({argument}.source); }}
            export function consume(event, context, extra) {{ eval({argument}.source); }}
            export function scheduled(event, context, extra) {{ eval({argument}.source); }}
            export function unreferenced(event, context, extra) {{ eval({argument}.source); }}
            // manifest.yml
            modules:
              trigger:
                - key: issue-created
                  function: event-handler
                  events: [avi:jira:created:issue]
              consumer:
                - key: work-consumer
                  queue: work
                  function: consumer-handler
              scheduledTrigger:
                - key: periodic
                  function: scheduled-handler
                  interval: hour
              function:
                - key: event-handler
                  handler: index.onEvent
                - key: consumer-handler
                  handler: index.consume
                - key: scheduled-handler
                  handler: index.scheduled
                - key: unused-handler
                  handler: index.unreferenced
            app:
              id: test-app
            permissions:
              scopes: []
        "#
            ),
            4,
        );
    }
}

#[test]
fn resolver_request_and_context_are_sources() {
    for argument in ["request", "context"] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            import Resolver from '@forge/resolver';
            const resolver = new Resolver();
            resolver.define('execute', (request, context) => {{ eval({argument}.source); }});
            export const run = resolver.getDefinitions();
        "#
            ),
            1,
        );
    }
}

#[test]
fn fetch_response_remains_a_source_through_helpers() {
    for import in ["", "import { fetch } from '@forge/api';"] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            {import}
            function execute(source) {{ eval(source); }}
            export async function run() {{
                const response = await fetch('/code');
                const source = await response.text();
                execute(source);
            }}
        "#
            ),
            1,
        );
    }
}

#[test]
fn jira_responses_are_sources_even_for_as_app_and_trivial_routes() {
    for actor in ["asApp", "asUser"] {
        for route in ["/rest/api/3/issue/TEST-1", "/rest/api/3/myself"] {
            assert_execution_findings(
                &format!(
                    r#"// src/index.js
                import api, {{ route }} from '@forge/api';
                export async function run() {{
                    const response = await api.{actor}().requestJira(route`{route}`);
                    const issue = await response.json();
                    eval(issue.fields.description);
                }}
            "#
                ),
                1,
            );
        }
    }
}

#[test]
fn source_inside_array_join_still_reports() {
    assert_execution_findings(
        r#"// src/index.js
        export function run(input) {
            const lines = ['1 + 1', input.source];
            eval(lines.join('\n'));
        }
    "#,
        1,
    );
}

#[test]
fn child_process_checks_command_and_argv_but_not_callbacks_or_options() {
    assert_execution_findings(
        r#"// src/index.js
        import { exec, spawn } from 'node:child_process';
        export function run(input) {
            exec('printf ok', input.options, input.callback);
            spawn('printf', ['ok'], input.options);
            spawn('printf', input.args);
        }
    "#,
        1,
    );
}

#[test]
fn local_global_this_and_function_bindings_are_not_sinks() {
    assert_execution_findings(
        r#"// src/index.js
        const globalThis = { eval(value) { return value; } };
        class Function { constructor(value) { this.value = value; } }
        export function run(input) {
            globalThis.eval(input.source);
            new Function(input.source);
        }
    "#,
        0,
    );
}

#[test]
fn function_called_without_new() {
    assert_execution_findings(
        r#"// src/index.js
        export function run(input) { Function('value', input.source); }
    "#,
        1,
    );
}

#[test]
fn async_function_called_without_new() {
    assert_execution_findings(
        r#"// src/index.js
        const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
        export function run(input) { AsyncFunction(input.source); }
    "#,
        1,
    );
}

#[test]
fn generator_function_constructor() {
    assert_execution_findings(
        r#"// src/index.js
        const GeneratorFunction = Object.getPrototypeOf(function* () {}).constructor;
        export function run(input) { new GeneratorFunction(input.source); }
    "#,
        1,
    );
}

#[test]
fn async_generator_constructor_with_real_world_alias() {
    // AsyncGenerator is the app's name for AsyncGeneratorFunction, not a
    // global constructor supplied by JavaScript.
    assert_execution_findings(
        r#"// src/index.js
        const AsyncGenerator = Object.getPrototypeOf(async function* () {}).constructor;
        export function run(input) { new AsyncGenerator(input.source); }
    "#,
        1,
    );
}

#[test]
fn global_this_function_constructor() {
    assert_execution_findings(
        r#"// src/index.js
        export function run(input) { new globalThis.Function(input.source); }
    "#,
        1,
    );
}

#[test]
fn vm_run_in_new_context() {
    assert_execution_findings(
        r#"// src/index.js
        import { runInNewContext } from 'node:vm';
        export function run(input) { runInNewContext(input.source); }
    "#,
        1,
    );
}

#[test]
fn vm_script_constructor() {
    assert_execution_findings(
        r#"// src/index.js
        import { Script } from 'node:vm';
        export function run(input) { new Script(input.source); }
    "#,
        1,
    );
}

#[test]
fn static_array_join_is_not_user_input() {
    assert_execution_findings(
        r#"// src/index.js
        export function run() {
            const lines = ['const answer = 40;', 'answer + 2;'];
            eval(lines.join('\n'));
        }
    "#,
        0,
    );
}

#[test]
fn static_table_loop_is_not_user_input() {
    assert_execution_findings(
        r#"// src/index.js
        const TABLE = [{ type: 'const answer = 40;' }, { type: 'answer + 2;' }];
        export function run() {
            let lines = ['void 0;'];
            for (let i = 0; i < TABLE.length; ++i) {
                lines.push(TABLE[i].type);
            }
            eval(lines.join('\n'));
        }
    "#,
        0,
    );
}

#[test]
fn user_loop_bound_does_not_supply_executable_text() {
    // The user chooses how many fixed fragments are used, never their text.
    assert_execution_findings(
        r#"// src/index.js
        const TABLE = [{ type: 'void 0;' }, { type: '1 + 1;' }];
        export function run(input) {
            let lines = ['void 0;'];
            for (let i = 0; i < input.count && i < TABLE.length; ++i) {
                lines.push(TABLE[i].type);
            }
            eval(lines.join('\n'));
        }
    "#,
        0,
    );
}

#[test]
fn pure_helper_string_construction_is_not_user_input() {
    assert_execution_findings(
        r#"// src/index.js
        function buildSource() {
            const template = 'return VALUE;';
            return template.replace('VALUE', '42');
        }
        export function run() { eval(buildSource()); }
    "#,
        0,
    );
}

#[test]
fn app_module_helper_string_construction_is_not_user_input() {
    // A named import resolves to the app function, whose only return is a
    // constant. A destructured `require` of a relative path does not resolve,
    // so its result keeps the floor.
    for (import, expected) in [
        ("import { buildSource } from './build';", 0),
        ("const { buildSource } = require('./build');", 1),
    ] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            {import}
            export function run() {{ eval(buildSource()); }}
            // src/build.js
            export function buildSource() {{ return 'return 42;'; }}
        "#
            ),
            expected,
        );
    }
}

#[test]
fn a_package_namespace_is_not_executable_text_but_app_exports_are() {
    for (module, expected) in [("'node:path'", 0), ("'./code'", 1), ("name", 1)] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            const name = './code';
            export function run() {{ eval(require({module})); }}
            // src/code.js
            export default 'return 42;';
        "#
            ),
            expected,
        );
    }
}

#[test]
fn entity_store_read_is_a_source() {
    for (store, module) in [("storage", "@forge/api"), ("kvs", "@forge/kvs")] {
        for read in ["get", "getSecret", "query"] {
            assert_execution_findings(
                &format!(
                    r#"// src/index.js
            import {{ {store} }} from '{module}';
            export async function run() {{
                eval(await {store}.entity('rules').{read}('body'));
            }}
        "#
                ),
                1,
            );
        }
    }
}

#[test]
fn package_call_results_are_sources_whatever_their_arguments() {
    for (import, read) in [
        (
            "import { readFileSync } from 'fs';",
            "readFileSync('/tmp/code.js', 'utf8')",
        ),
        (
            "import * as fs from 'node:fs';",
            "fs.readFileSync('/tmp/code.js', 'utf8')",
        ),
        (
            "const fs = require('fs');",
            "fs.readFileSync('/tmp/code.js', 'utf8')",
        ),
        (
            "const { readFileSync } = require('fs');",
            "readFileSync('/tmp/code.js', 'utf8')",
        ),
        (
            "import axios from 'axios';",
            "(await axios.get('/code')).data",
        ),
        (
            "import axios from 'axios'; const client = axios.create({ baseURL: '/api' });",
            "(await client.get('/code')).data",
        ),
    ] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            {import}
            export async function run() {{ eval({read}); }}
        "#
            ),
            1,
        );
    }
}

#[test]
fn aliased_fetch_and_storage_reads_are_sources() {
    for (alias, read) in [
        ("const load = fetch;", "await (await load('/code')).text()"),
        (
            "import api from '@forge/api'; const load = api.fetch;",
            "await (await load('/code')).text()",
        ),
        (
            "import { storage } from '@forge/api'; const store = storage;",
            "await store.get('code')",
        ),
        (
            "import { storage } from '@forge/api'; const get = storage.get;",
            "await get('code')",
        ),
        (
            "import { kvs } from '@forge/kvs'; const { get } = kvs;",
            "await get('code')",
        ),
    ] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            {alias}
            export async function run() {{ eval({read}); }}
        "#
            ),
            1,
        );
    }
}

#[test]
fn pure_helper_results_follow_their_arguments() {
    for (source, expected) in [
        (
            "import _ from 'lodash'; export function run() { eval(_.join(['1', '1'], ' + ')); }",
            0,
        ),
        (
            "import { execSync } from 'child_process'; const path = require('node:path'); export function run() { execSync(path.join('/bin', 'ls')); }",
            0,
        ),
        (
            "import { join } from 'lodash-es'; export function run(input) { eval(join([input], ' + ')); }",
            1,
        ),
        (
            "import _ from 'lodash'; export function run(input) { eval(_.map(['a'], () => input)); }",
            1,
        ),
        // `map` returns what its callback returned, including when the
        // callback is an aliased import.
        (
            "import { readFileSync as read } from 'fs'; import _ from 'lodash'; const callback = read; export function run() { eval(_.map([0], callback).join('')); }",
            1,
        ),
        // A member that is not a known helper keeps the package floor.
        (
            "import _ from 'lodash'; export function run() { eval(_.sortBy(['1']).join(' + ')); }",
            1,
        ),
    ] {
        assert_execution_findings(&format!("// src/index.js\n{source}"), expected);
    }
}

#[test]
fn reflect_get_prototype_of_resolves_the_function_constructor() {
    for namespace in ["Object", "Reflect"] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            export function run(input) {{
                {namespace}.getPrototypeOf(function* () {{}}).constructor(input.source);
            }}
        "#
            ),
            1,
        );
    }
}

#[test]
fn prototype_of_a_package_import_is_the_function_constructor() {
    // An imported binding is opaque, so its prototype may be the one that
    // carries the `Function` constructor.
    for value in ["read", "readFileSync", "fs.readFileSync", "_"] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            import {{ readFileSync as read, readFileSync }} from 'fs';
            import _ from 'lodash';
            const fs = require('fs');
            export function run(input) {{
                Object.getPrototypeOf({value}).constructor(input.source);
            }}
        "#
            ),
            1,
        );
    }
}

#[test]
fn prototype_of_a_non_function_is_not_the_function_constructor() {
    // The constructor of a non-function prototype is Object, Array or String.
    for value in ["{}", "[]", "'text'", "input.value", "settings"] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            const settings = {{ mode: 'strict' }};
            export function run(input) {{
                Object.getPrototypeOf({value}).constructor(input.source);
            }}
        "#
            ),
            0,
        );
    }
}

#[test]
fn function_constructor_checks_every_argument() {
    // Each parameter name is compiled alongside the body, so a source in the
    // last position still reports.
    assert_execution_findings(
        r#"// src/index.js
        export function run(input) { new Function('a', 'b', input.source); }
    "#,
        1,
    );
}

#[test]
fn vm_api_is_recognized_with_and_without_the_node_prefix() {
    for module in ["vm", "node:vm"] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            import {{ runInNewContext }} from '{module}';
            export function run(input) {{ runInNewContext(input.source); }}
        "#
            ),
            1,
        );
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            export function run(input) {{
                require('{module}').runInNewContext(input.source);
            }}
        "#
            ),
            1,
        );
    }
}

#[test]
fn locally_declared_vm_api_name_is_not_a_sink() {
    assert_execution_findings(
        r#"// src/index.js
        function runInNewContext(source) { return source; }
        export function run(input) { runInNewContext(input.source); }
    "#,
        0,
    );
}

#[test]
fn coerced_boolean_is_not_executable_text() {
    for (expression, expected) in [("Boolean(input.flag)", 0), ("input.flag", 1)] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            export function run(input) {{ eval('answer = ' + {expression} + ' && true'); }}
        "#
            ),
            expected,
        );
    }
}

#[test]
fn constant_rule_names_split_from_a_literal_are_not_user_input() {
    assert_execution_findings(
        r#"// src/index.js
        const RULES = 'bold,italic';
        export function run(input) {
            const names = RULES.split(',');
            for (let i = 0; i < names.length; ++i) {
                eval('render_' + names[i] + '(content)');
            }
        }
    "#,
        0,
    );
}

#[test]
fn an_app_constructed_receiver_still_reports_its_method_result() {
    // The analysis does not resolve a method of an object a factory returned,
    // so the result keeps the floor even where the factory takes no input.
    assert_execution_findings(
        r#"// src/index.js
        function makeContext() {
            return { getActiveUniform: function (i) { return { size: 1 }; } };
        }
        const gl = makeContext();
        export function run(input) {
            const info = gl.getActiveUniform(0);
            return new Function('gl', 'location', 'value',
                'gl.uniform' + info.size + 'fv(location, value);');
        }
    "#,
        1,
    );
}

#[test]
fn a_sibling_field_does_not_taint_a_constant_field() {
    for (field, expected) in [("other", 0), ("source", 1)] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            export function run(input) {{
                const options = {{ source: 'answer = 42;' }};
                options.{field} = input.source;
                eval(options.source);
            }}
        "#
            ),
            expected,
        );
    }
}

#[test]
fn values_stored_through_a_method_call_still_report() {
    for project in [
        // The tainted twin of `static_table_loop_is_not_user_input`.
        r#"// src/index.js
        const TABLE = [{ type: 'void 0;' }];
        export function run(input) {
            let lines = ['void 0;'];
            for (let i = 0; i < TABLE.length; ++i) {
                lines.push(input.rows[i].type);
            }
            eval(lines.join('\n'));
        }"#,
        // A constant fragment joined to input before it is pushed.
        r#"// src/index.js
        const TABLE = [{ type: 'void 0;' }];
        export function run(input) {
            let lines = ['void 0;'];
            for (let i = 0; i < TABLE.length; ++i) {
                lines.push(TABLE[i].type + input.suffix);
            }
            eval(lines.join('\n'));
        }"#,
        // A fetched body.
        r#"// src/index.js
        export async function run() {
            const lines = ['void 0;'];
            const response = await fetch('/code');
            lines.push(await response.text());
            eval(lines.join('\n'));
        }"#,
        r#"// src/index.js
        export function run(input) {
            const parts = new Set();
            parts.add(input.source);
            eval([...parts].join(';'));
        }"#,
        r#"// src/index.js
        export function run(input) {
            const rules = new Map();
            rules.set('body', input.source);
            eval(rules.get('body'));
        }"#,
    ] {
        assert_execution_findings(project, 1);
    }
}

#[test]
fn results_of_calls_the_analysis_cannot_resolve_still_report() {
    for project in [
        // The tainted twin of the `require` half of
        // `app_module_helper_string_construction_is_not_user_input`.
        r#"// src/index.js
        const { load } = require('./load');
        export async function run() { eval(await load()); }
        // src/load.js
        export async function load() {
            const response = await fetch('/code');
            return response.text();
        }"#,
        // A method of a default-exported object.
        r#"// src/index.js
        import rules from './rules';
        export async function run() { eval(await rules.load()); }
        // src/rules.js
        export default {
            async load() {
                const response = await fetch('/code');
                return response.text();
            },
        };"#,
        // A method of an exported instance.
        r#"// src/index.js
        import { rules } from './rules';
        export async function run() { eval(await rules.load()); }
        // src/rules.js
        class Rules {
            async load() {
                const response = await fetch('/code');
                return response.text();
            }
        }
        export const rules = new Rules();"#,
        // A sibling method called through `this`.
        r#"// src/index.js
        const rules = {
            async load() {
                const response = await fetch('/code');
                return response.text();
            },
            async apply() { eval(await this.load()); },
        };
        export async function run() { await rules.apply(); }"#,
        // A function held in a local.
        r#"// src/index.js
        export function run(input) {
            const read = function () { return input.source; };
            const alias = read;
            eval(alias());
        }"#,
        // A promise resolved with input.
        r#"// src/index.js
        export async function run(input) {
            const source = await new Promise((resolve) => { resolve(input.source); });
            eval(source);
        }"#,
        // The tainted twin of
        // `an_app_constructed_receiver_still_reports_its_method_result`.
        r#"// src/index.js
        function makeContext(size) {
            return { getActiveUniform: function (i) { return { size: size }; } };
        }
        export function run(input) {
            const gl = makeContext(input.size);
            const info = gl.getActiveUniform(0);
            return new Function('gl', 'location', 'value',
                'gl.uniform' + info.size + 'fv(location, value);');
        }"#,
    ] {
        assert_execution_findings(project, 1);
    }
}

#[test]
fn constant_only_construction_stays_unreported() {
    for project in [
        // Input bounds the loop; every pushed fragment is a constant.
        r#"// src/index.js
        const CONST = [{ type: 'void 0;' }, { type: '1 + 1;' }];
        export function run(input) {
            let lines = ['static', 'strings'];
            for (let i = 0; i < input.count; ++i) {
                lines.push(CONST[i].type);
            }
            eval(lines.join('\n'));
        }"#,
        r#"// src/index.js
        const CONST = [{ type: 'void 0;' }, { type: '1 + 1;' }];
        export function run() {
            const lines = [];
            CONST.forEach(entry => { lines.push(entry.type); });
            for (const entry of CONST) { lines.push(entry.type); }
            eval(lines.join('\n'));
        }"#,
        // Built-in string and array methods on constants.
        r#"// src/index.js
        export function run() {
            eval('  a b  '.trim().toUpperCase().padEnd(6).repeat(2).split(' ')
                .reverse().concat(['c']).slice(0).filter(Boolean).join(';'));
        }"#,
        r#"// src/index.js
        const SETTINGS = { mode: 'strict' };
        export function run() { eval('(' + JSON.stringify(SETTINGS) + ')'); }"#,
    ] {
        assert_execution_findings(project, 0);
    }
}

#[test]
fn a_function_replacement_returns_what_it_returned() {
    for (replacement, expected) in [("'42'", 0), ("() => input.source", 1)] {
        assert_execution_findings(
            &format!(
                r#"// src/index.js
            export function run(input) {{
                const template = 'return VALUE;';
                eval(template.replace('VALUE', {replacement}));
            }}
        "#
            ),
            expected,
        );
    }
}
