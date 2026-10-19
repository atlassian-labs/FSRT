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
fn an_app_constructed_receiver_does_not_taint_its_method_result() {
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
        0,
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
