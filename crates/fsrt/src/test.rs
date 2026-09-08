use crate::{Args, Scanner, forge_project::ForgeProjectTrait, scan_directory};
use clap::{CommandFactory, Parser};
use forge_analyzer::reporter::{Report, Severity};
use forge_analyzer::{checkers::ForgeRuntimeVersionPolicyChecker, definitions::PackageData};
use forge_loader::manifest::{ForgeManifest, FunctionMod};
use std::fmt;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use swc_core::common::sync::Lrc;
use swc_core::common::{FileName, SourceFile, SourceMap};
use time::{Date, Month};

trait ReportExt {
    fn has_no_vulns(&self) -> bool;

    fn contains_secret_vuln(&self, expected_len: usize) -> bool;

    #[cfg(feature = "graphql_schema")]
    fn contains_perm_vuln(&self, expected_len: usize) -> bool;

    fn vuln_description_contains(&self, check_name: &str, description_snippet: &str) -> bool;

    fn contains_vulns(&self, expected_len: i32) -> bool;

    fn contains_authz_vuln(&self, expected_len: usize) -> bool;

    fn contains_api_token_vuln(&self, expected_len: usize) -> bool;

    fn contains_container_token_vuln(&self, expected_len: usize) -> bool;

    fn contains_sql_vuln(&self, severity: Severity, expected_len: usize) -> bool;
}

impl ReportExt for Report {
    #[inline]
    fn has_no_vulns(&self) -> bool {
        self.into_vulns().is_empty()
    }

    #[inline]
    fn contains_authz_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name().contains("Authorization"))
            .count()
            == expected_len
    }

    #[inline]
    fn contains_api_token_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name() == "ATLASSIAN_API_TOKEN")
            .count()
            == expected_len
    }

    #[inline]
    fn contains_container_token_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name() == "ATLASSIAN_CONTAINER_TOKEN")
            .count()
            == expected_len
    }

    #[inline]
    fn contains_secret_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| {
                vuln.check_name()
                    .starts_with("Custom-Check-Hardcoded-Secret-")
            })
            .count()
            == expected_len
    }

    #[cfg(feature = "graphql_schema")]
    #[inline]
    fn contains_perm_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name() == "Least-Privilege")
            .count()
            == expected_len
    }

    #[inline]
    fn vuln_description_contains(&self, check_name: &str, description_snippet: &str) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| {
                vuln.check_name() == check_name && vuln.description().contains(description_snippet)
            })
            .count()
            == 1
    }

    #[inline]
    fn contains_vulns(&self, expected_len: i32) -> bool {
        self.into_vulns().len() == expected_len as usize
    }

    fn contains_sql_vuln(&self, severity: Severity, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| {
                vuln.check_name() == "forge-sql-injection" && vuln.severity() == severity
            })
            .count()
            == expected_len
    }
}

#[derive(Clone)]
pub(crate) struct MockForgeProject<'a> {
    pub files_name_to_source: HashMap<PathBuf, Arc<SourceFile>>,
    pub test_manifest: ForgeManifest<'a>,
    pub manifest_file_content: Option<String>,
    pub cm: Lrc<SourceMap>,
}

impl fmt::Debug for MockForgeProject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mock Forge Project {:?}", self.files_name_to_source)
    }
}

#[allow(dead_code)]
impl<'a> MockForgeProject<'a> {
    pub fn files_from_string(string: &'a str) -> Self {
        let different_files = string.split("//").filter(|file| !file.is_empty());

        let manifest_file_content = different_files
            .clone()
            .find(|string| {
                string
                    .replace("//", "")
                    .trim_start()
                    .starts_with("manifest.yaml")
                    || string
                        .trim_start()
                        .replace("//", "")
                        .starts_with("manifest.yml")
            })
            .map(|manifest_string| manifest_string.split_once('\n').unwrap().1.to_string());

        let mut mock_forge_project = MockForgeProject {
            files_name_to_source: HashMap::new(),
            test_manifest: ForgeManifest::create_manifest_with_func_mod(FunctionMod {
                key: "main",
                handler: "index.run",
                providers: None,
            }),
            manifest_file_content,
            cm: Arc::default(),
        };

        for file in different_files {
            let (file_name, file_source) = file.split_once('\n').unwrap();
            if file_name.trim() == "manifest.yml" || file_name.trim() == "manifest.yaml" {
                continue;
            }
            mock_forge_project.add_file(
                file_name.replace("//", "").replace('"', "").trim(),
                file_source.replace('"', ""),
            );
        }
        mock_forge_project
    }

    pub fn add_file(&mut self, p: impl Into<PathBuf>, source: impl Into<String>) {
        let file_name = p.into();
        let source_file = self
            .cm
            .new_source_file(Arc::new(FileName::Real(file_name.clone())), source.into());

        self.files_name_to_source.insert(file_name, source_file);
    }
}

impl<'a> ForgeProjectTrait<'a> for MockForgeProject<'a> {
    fn load_file(
        &self,
        p: impl AsRef<Path>,
        _: Arc<SourceMap>,
    ) -> std::io::Result<Arc<SourceFile>> {
        self.files_name_to_source
            .get(p.as_ref())
            .cloned()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
    }

    fn get_paths(&self) -> HashSet<PathBuf> {
        self.files_name_to_source
            .keys()
            .map(|file| file.into())
            .collect::<HashSet<_>>()
    }

    #[allow(dead_code)]
    fn get_secret_packages(&self) -> Vec<PackageData> {
        vec![]
    }

    fn get_manifest(&self) -> Result<ForgeManifest<'_>, serde_yaml::Error> {
        if let Some(manifest_file_content) = &self.manifest_file_content {
            serde_yaml::from_str(manifest_file_content)
        } else {
            Ok(self.test_manifest.clone())
        }
    }
}

pub(crate) fn scan_directory_test_with_args(
    forge_test_proj: MockForgeProject<'_>,
    mut args: Args,
) -> forge_analyzer::reporter::Report {
    let secret_packages: Vec<PackageData> = std::fs::File::open("../../secretdata.yaml")
        .map(|f| serde_yaml::from_reader(f).expect("Failed to deserialize packages"))
        .unwrap_or_else(|_| vec![]);

    match scan_directory(PathBuf::new(), &mut args, forge_test_proj, &secret_packages) {
        Ok(report) => report,
        Err(err) => panic!("error while scanning {err:?}"),
    }
}

pub(crate) fn scan_directory_test(
    forge_test_proj: MockForgeProject<'_>,
) -> forge_analyzer::reporter::Report {
    // disallow parsing arguments meant for test harness (e.g., --nocapture, --exact) from std::env::args()
    let args = Args::parse_from([""]);
    scan_directory_test_with_args(forge_test_proj, args)
}

#[test]
fn default_export_class_with_private_method_does_not_panic() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.js
        export default class Service {
            run() {
                return this.#privateMethod();
            }

            #privateMethod() {
                return 'ok';
            }
        }

        export function run() {
            return new Service().run();
        }
        ",
    );

    let _ = scan_directory_test(test_forge_project);
}

#[test]
fn transpiled_async_detection_uses_helpers_not_strict_mode() {
    for source in [
        "\"use strict\";\nmodule.exports = function () {};",
        "'use strict';\nasync function run() { await work(); }",
    ] {
        assert!(!crate::contains_transpiled_async(source));
    }

    for source in [
        "return __awaiter(this, void 0, void 0, function* () {});",
        "return __generator(this, function (_a) {});",
        "const run = _asyncToGenerator(function* () {});",
        "regeneratorRuntime.mark(function run() {});",
    ] {
        assert!(crate::contains_transpiled_async(source));
    }
}

#[test]
fn scanners_parse_as_typed_list() {
    let args = Args::try_parse_from([
        "fsrt",
        "--scanners",
        "secret,auth-header",
        "--scanners",
        "authentication",
    ])
    .unwrap();

    assert_eq!(
        args.scanners,
        vec![
            Scanner::Secret,
            Scanner::AuthHeader,
            Scanner::Authentication,
        ]
    );
}

#[test]
fn scanners_help_lists_possible_values() {
    let help = Args::command().render_long_help().to_string();

    assert!(help.contains("possible values:"));
    for scanner in [
        "authentication",
        "authorization",
        "auth-header",
        "permission",
        "secret",
        "sql-injection",
    ] {
        assert!(help.contains(scanner), "help omitted scanner {scanner}");
    }
}

#[test]
fn scanners_only_run_selected_checks() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import { AES } from 'crypto-js';
        import ForgeUI, { render, Macro } from '@forge/ui';

        function App() {
            AES.encrypt('plaintext', 'hardcoded-key');
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let secret_args = Args::parse_from(["fsrt", "--scanners", "secret"]);
    let secret_report = scan_directory_test_with_args(test_forge_project.clone(), secret_args);
    assert!(secret_report.contains_secret_vuln(1));
    assert!(secret_report.contains_vulns(1));

    let authorization_args = Args::parse_from(["fsrt", "--scanners", "authorization"]);
    let authorization_report =
        scan_directory_test_with_args(test_forge_project, authorization_args);
    assert!(authorization_report.has_no_vulns());
}

#[test]
fn scanners_keep_findings_independent() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import { AES } from 'crypto-js';
        import api, { fetch, route } from '@forge/api';

        export function run() {
            AES.encrypt('plaintext', 'hardcoded-key');
            api.asApp().requestJira(route`/rest/api/3/issue`);
            fetch('api.atlassian.com/rest/api/3/issue', {
                headers: { Authorization: 'Basic ' + process.env.API_TOKEN }
            });
        }

        // manifest.yml
        modules:
          macro:
            - key: macro
              function: main
              title: Test
          webtrigger:
            - key: webhook
              function: hook
          function:
            - key: main
              handler: index.run
            - key: hook
              handler: index.run
        app:
          id: test-app
        permissions:
          scopes: []",
    );

    let check_names = |report: Report| {
        let mut names = report
            .into_vulns()
            .iter()
            .map(|vuln| vuln.check_name().to_owned())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let combined = check_names(scan_directory_test(project.clone()));
    let mut separate = Vec::new();
    for (scanner, expected_check) in [
        ("authentication", Some("Custom-Check-Authentication-")),
        ("authorization", Some("Custom-Check-Authorization-")),
        ("auth-header", Some("ATLASSIAN_API_TOKEN")),
        ("secret", Some("Custom-Check-Hardcoded-Secret-")),
        ("permission", None),
        ("runtime-version", None),
    ] {
        let args = Args::parse_from(["fsrt", "--scanners", scanner]);
        let names = check_names(scan_directory_test_with_args(project.clone(), args));
        if let Some(expected_check) = expected_check {
            assert!(
                !names.is_empty() && names.iter().all(|name| name.starts_with(expected_check)),
                "unexpected findings for {scanner}: {names:?}"
            );
        } else {
            assert!(
                names.is_empty(),
                "unexpected findings for {scanner}: {names:?}"
            );
        }
        separate.extend(names);
    }
    separate.sort();
    assert_eq!(combined, separate);
}

#[test]
fn auth_header_scans_uncalled_functions_only_when_requested() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import { fetch } from '@forge/api';

        export function run() {}

        function helper() {
            fetch('api.atlassian.com/rest/api/3/issue', {
                headers: { Authorization: 'Basic ' + process.env.API_TOKEN }
            });
        }",
    );

    for scan_functions in [false, true] {
        let mut args = Args::parse_from(["fsrt", "--scanners", "auth-header"]);
        args.scan_functions = scan_functions;
        let report = scan_directory_test_with_args(project.clone(), args);
        assert!(report.contains_api_token_vuln(usize::from(scan_functions)));
    }
}

#[test]
fn test_simple() {
    let forge_manifest = ForgeManifest::create_manifest_with_func_mod(FunctionMod {
        key: "main",
        handler: "index.run",
        providers: None,
    });

    let mut test_forge_project = MockForgeProject {
        test_manifest: forge_manifest,
        files_name_to_source: HashMap::new(),
        manifest_file_content: None,
        cm: Lrc::new(SourceMap::default()),
    };
    test_forge_project.add_file(
        "src/index.tsx",
        "import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
            function App() { console.log('test') } \n
            export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.has_no_vulns());
}

#[test]
fn forge_runtime_version_policy_flags_nodejs20() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.js
        export function run() {}

        // manifest.yml
        modules:
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/test-id
          runtime:
            name: nodejs20.x
        permissions:
          scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.vuln_description_contains(
        "Forge Runtime Version Policy Checker",
        "end-of-life Node.js runtime"
    ));
}

#[test]
fn forge_runtime_version_policy_allows_nodejs22() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.js
        export function run() {}

        // manifest.yml
        modules:
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/test-id
          runtime:
            name: nodejs22.x
        permissions:
          scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(!scan_result.vuln_description_contains(
        "Forge Runtime Version Policy Checker",
        "end-of-life Node.js runtime"
    ));
}

fn date(year: i32, month: Month, day: u8) -> Date {
    Date::from_calendar_date(year, month, day).unwrap()
}

#[test]
fn forge_runtime_version_policy_flags_runtime_after_support_ends() {
    let result =
        ForgeRuntimeVersionPolicyChecker::check_at(Some("nodejs20.x"), date(2026, Month::May, 1));

    assert!(result.is_some());
}

#[test]
fn forge_runtime_version_policy_allows_runtime_through_support_end_date() {
    let result = ForgeRuntimeVersionPolicyChecker::check_at(
        Some("nodejs20.x"),
        date(2026, Month::April, 30),
    );

    assert!(result.is_none());
}

#[test]
fn forge_runtime_version_policy_allows_runtime_with_future_support_end_date() {
    let result =
        ForgeRuntimeVersionPolicyChecker::check_at(Some("nodejs22.x"), date(2026, Month::May, 1));

    assert!(result.is_none());
}

#[test]
fn forge_runtime_version_policy_ignores_unrecognized_runtime_names() {
    assert!(
        ForgeRuntimeVersionPolicyChecker::check_at(Some("nodejs999.x"), date(2026, Month::May, 1),)
            .is_none()
    );
    assert!(
        ForgeRuntimeVersionPolicyChecker::check_at(Some("sandbox"), date(2026, Month::May, 1),)
            .is_none()
    );
}

#[test]
fn test_secret_vuln() {
    let forge_manifest = ForgeManifest::create_manifest_with_func_mod(FunctionMod {
        key: "main",
        handler: "index.run",
        providers: None,
    });

    let mut test_forge_project = MockForgeProject {
        test_manifest: forge_manifest,
        files_name_to_source: HashMap::new(),
        manifest_file_content: None,
        cm: Lrc::new(SourceMap::default()),
    };
    test_forge_project.add_file(
        "src/index.tsx",
        "import {AES} from 'crypto-js'
        import ForgeUI, { render, Macro } from '@forge/ui';
    
        function App() { 
            AES.encrypt(blah, 'blah');
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn with_multiple_files() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
        import test_function from 'test_function'; \n
        function App() { let test = 'textx'; console.log('test') } \n
        export const run = render(<Macro app={<App />} />); 
        // src/test_function.tsx
        export default function test() { let test1 = 'test_one'; console.log('test_function') }",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.has_no_vulns());
}

// secret checker integration tests
#[test]
fn secret_vuln_default_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import jwt from 'jsonwebtoken';

        function App() { 
            let a = 'shhhhh';
            let secret = jwt.sign({ foo: 'bar' }, a);
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_named_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import {AES} from 'crypto-js'
        import ForgeUI, { render, Macro } from '@forge/ui';

        function App() { 
            AES.encrypt(blah, 'nothing');
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_star_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 
            atlassian_jwt.encodeSymmetric(blah, 'blah');
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_global_import() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        let SECRET = 'secret';

        function App() { 
            atlassian_jwt.encodeSymmetric(blah, SECRET);
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_object() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 

            let dict = {};
            dict.secret = 'secret';

            atlassian_jwt.encodeSymmetric(dict.secret, dict.secret);
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_in_use_effect_hook() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro, useEffect } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 

            useEffect(() => {
                let dict = { secret: 'secret' };

                atlassian_jwt.encodeSymmetric({}, dict.secret);
            })

            return (
                <Fragment>
                    <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_object_unknown() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 

            let dict = { secret: 'secret' };

            atlassian_jwt.encodeSymmetric({}, dict.secret);

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[test]
// Disabling test due to SSA Form fix changes.
fn secret_vuln_object_reassignment() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 

            let dict = {};
            dict.secret = 'secret';

            let newDict = {};
            newDict.anotherSecret = dict.secret;

            atlassian_jwt.encodeSymmetric({}, newDict.anotherSecret);

            return (
                <Fragment>
                    <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn unauthz_vuln_function_called_in_object() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';

        const App = () => {

            let goodObject = {
                someFunction() {}
            }

            let badObject = {
                someFunction() {
                const res = api.asApp().requestConfluence(route`/rest/api/3/test`);
                return res;
                }
            }

            goodObject.someFunction()


            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yml 
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0))
}

#[test]
fn authz_function_called_in_object() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';

        const App = () => {

            let testObject = {
                someFunction() {
                const res = api.asApp().requestConfluence(route`/rest/api/3/test`);
                return res;
                }
            }

            testObject.someFunction()


            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yaml 
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(1))
}

// Tests that calls to /wiki/api/v2/app/properties are in TRIVIAL_API_PREFIXES and
// are not flagged by the AuthZ scanner even without a prior authorize() call.
#[test]
fn wiki_api_v2_app_properties_not_flagged_by_authz() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route } from '@forge/api';

        const App = async () => {
            const res = await api.asApp().requestConfluence(route`/wiki/api/v2/app/properties`);
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };

        export const run = render(<Macro app={<App />} />);

        // manifest.yml
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0))
}

// A non-allowlisted Confluence path without authorize() SHOULD be flagged,
// confirming wiki_api_v2_app_properties_not_flagged_by_authzis is actually exercising the allowlist.
#[test]
fn non_allowlisted_confluence_path_flagged_by_authz() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route } from '@forge/api';

        const App = async () => {
            const res = await api.asApp().requestConfluence(route`/wiki/api/v2/pages`);
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };

        export const run = render(<Macro app={<App />} />);

        // manifest.yml
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(1))
}

#[test]
fn secret_vuln_fetch_header() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import { fetch } from '@forge/api';

        function App() { 

            let h = { headers: { authorization: 'foo' } };
            h = h;
            fetch('url', h)
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

// Tests that API tokens on a fetch to a non-admin Atlassian URL are detected
// in both Basic and Bearer form across several common import patterns.
#[test]
fn api_token_fetch_detected_across_import_styles() {
    // (source, expected_api_token_vulns)
    let cases: &[(&str, usize)] = &[
        // named import { fetch }
        (
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            fetch('api.atlassian.com/rest/api/3/issue', { headers: { Authorization: 'Basic ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
        ),
        // default import api.fetch
        (
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            api.fetch('api.atlassian.com/rest/api/3/issue', { headers: { Authorization: 'Basic ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
        ),
        // chained .then()
        (
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            api.fetch('api.atlassian.com/rest/api/3/issue', { headers: { Authorization: 'Basic ' + token } }).then((res) => res.json());
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
        ),
        // template-literal header built before the call
        (
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';
        async function App() {
            let credentials = process.env.API_TOKEN;
            const basicAuthHeader = `Basic ${credentials}`;
            await fetch('api.atlassian.com/rest/api/3/issue', {
                method: 'GET',
                headers: { Accept: 'application/json', Authorization: basicAuthHeader },
            });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
        ),
        // Bearer form on a non-admin Atlassian API is still an API token.
        (
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            fetch('api.atlassian.com/rest/api/3/issue', { headers: { Authorization: 'Bearer ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
        ),
    ];

    for (src, expected) in cases {
        let result = scan_directory_test(MockForgeProject::files_from_string(src));
        assert!(
            result.contains_api_token_vuln(*expected),
            "expected {expected} basic-auth vuln(s) for snippet:\n{src}"
        );
        assert!(result.vuln_description_contains("ATLASSIAN_API_TOKEN", "vuln_type:{api_token}"));
        assert!(result.contains_secret_vuln(0));
        assert!(result.contains_vulns(*expected as i32));
    }
}

// Known gap: module-scope headers with Basic auth are not tracked into function-scoped fetch calls.
// The analyzer's value tracking is scoped to function bodies (DefId + VarId), so the Authorization
// field defined at module level is not visible when checking the fetch intrinsic's operands.
// When this limitation is fixed, update assertions to expect 1 basic_auth_vuln and 1 total vuln.
#[test]
fn fetch_http_basic_authorization_module_scope_headers() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';

        const token = process.env.API_TOKEN;
        const headers = {
            Authorization: 'Basic ' + token,
            Accept: 'application/json',
        };

        function App() {
            fetch('url', {
                method: 'GET',
                headers,
            });
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_api_token_vuln(0));
    assert!(scan_result.contains_secret_vuln(0));
    assert!(scan_result.contains_vulns(0));
}

// #[test]
// fn fetch_http_basic_authorization_re_export_resolver() {
//     let test_forge_project = MockForgeProject::files_from_string(
//         "// manifest.yml
// app:
//   id: test-app
// modules:
//   function:
//     - key: main
//       handler: index.handler
// permissions:
//   scopes: []
// // src/index.js
// export { handler } from './resolvers';
// // src/resolvers.ts
// import Resolver from '@forge/resolver';
// import { fetch } from '@forge/api';
// const resolver = new Resolver();
// resolver.define('fetchData', async () => {
//     const result = await fetch('api.atlassian.com/rest/api/3/issue', {
//         method: 'GET',
//         headers: { Authorization: 'Basic ' + process.env.TOKEN, Accept: 'application/json' }
//     });
//     return result;
// });
// export const handler = resolver.getDefinitions();",
//     );

//     let scan_result = scan_directory_test(test_forge_project);
//     assert!(scan_result.contains_api_token_vuln(1));
//     assert!(scan_result.contains_vulns(1));
// }

#[test]
fn container_token_fetch_detected_for_bearer_admin_request() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';

        function App() {
            const token = process.env.ADMIN_TOKEN;
            fetch('api.atlassian.com/admin/v1/orgs/123/users', {
                headers: {
                    Authorization: 'Bearer ' + token,
                    Accept: 'application/json'
                }
            });
            return <Fragment><Text>Hello</Text></Fragment>;
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_container_token_vuln(1));
    assert!(
        scan_result
            .vuln_description_contains("ATLASSIAN_CONTAINER_TOKEN", "vuln_type:{container_token}")
    );
    assert!(scan_result.contains_api_token_vuln(0));
    assert!(scan_result.contains_vulns(1));
}

// #[test]
// fn bearer_admin_api_fetch_template_url() {
//     let test_forge_project = MockForgeProject::files_from_string(
//         "// manifest.yml
// app:
//   id: test-app
// modules:
//   function:
//     - key: main
//       handler: index.handler
// permissions:
//   scopes: []
// // src/index.js
// export { handler } from './resolvers';
// // src/resolvers.ts
// import Resolver from '@forge/resolver';
// import { fetch } from '@forge/api';
// const resolver = new Resolver();
// resolver.define('getUsers', async () => {
//     const orgId = 'some-org';
//     const response = await fetch(`api.atlassian.com/admin/v2/orgs/${orgId}/users`, {
//         method: 'GET',
//         headers: { Authorization: `Bearer ${process.env.API_KEY}`, Accept: 'application/json' }
//     });
//     return response;
// });
// export const handler = resolver.getDefinitions();",
//     );

//     let scan_result = scan_directory_test(test_forge_project);
//     assert!(scan_result.contains_container_token_vuln(1));
//     assert!(scan_result.contains_api_token_vuln(0));
//     assert!(scan_result.contains_vulns(1));
// }

// Platform API shims (requestJira, requestConfluence, requestBitbucket) always
// target non-admin Atlassian endpoints, so both Basic and Bearer forms are
// reported as API tokens.
#[test]
fn api_tokens_on_platform_api_shims() {
    // (label, source, expected_api_token, expected_container_token)
    let cases: &[(&str, &str, usize, usize)] = &[
        (
            "requestJira concat",
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            api.asApp().requestJira(route`/rest/api/3/issue`, { method: 'GET', headers: { Authorization: 'Basic ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
            0,
        ),
        (
            "requestConfluence concat",
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            api.asApp().requestConfluence(route`/rest/api/content`, { method: 'GET', headers: { Authorization: 'Basic ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
            0,
        ),
        (
            "requestBitbucket concat",
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            api.asApp().requestBitbucket(route`/rest/api/3/test`, { method: 'GET', headers: { Authorization: 'Basic ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
            0,
        ),
        (
            "requestJira template literal",
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { requestJira, route } from '@forge/api';
        async function App() {
            let encodedCredentials = process.env.API_TOKEN;
            await requestJira(route`/rest/api/latest/group/user`, { method: 'DELETE', headers: { Authorization: `Basic ${encodedCredentials}` } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
            0,
        ),
        (
            "requestConfluence named import template literal",
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { requestConfluence, route } from '@forge/api';
        async function App() {
            let token = process.env.API_TOKEN;
            await requestConfluence(route`/wiki/rest/api/user/current`, { headers: { Accept: 'application/json', Authorization: `Basic ${token}` } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
            0,
        ),
        (
            "bearer on requestJira",
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';
        function App() {
            let token = process.env.API_TOKEN;
            api.asApp().requestJira(route`/rest/api/3/issue`, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            1,
            0,
        ),
    ];

    for (label, src, expected_api_token, expected_container_token) in cases {
        let result = scan_directory_test(MockForgeProject::files_from_string(src));
        assert!(
            result.contains_api_token_vuln(*expected_api_token),
            "[{label}] expected {expected_api_token} API-token vuln(s)"
        );
        assert!(
            result.contains_container_token_vuln(*expected_container_token),
            "[{label}] expected {expected_container_token} container-token vuln(s)"
        );
        assert!(
            result.contains_secret_vuln(0),
            "[{label}] expected no secret vulns"
        );
    }
}

#[test]
// Disabling test due to SSA Form fix changes.
fn secret_vuln_fetch_header_reassigned() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';

        function App() { 

            let h = { headers: { authorization: 'foo' } };
            
            let c = h;
            c.headers = {};
            fetch('url', h);
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0));
}

#[test]
fn basic_authz_vuln() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';


        function getText({ text }) {
        api.asApp().requestJira(route`/rest/api/3/issue`);
        return 'Hello, world!\n' + text;
        }

        function App() { 

            getText({ text: 'test' })
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yaml 
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_authz_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn api_route_authz_vuln() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.js
        import api, { route } from '@forge/api';

        export async function routeHandler() {
            await api.asApp().requestJira(route`/rest/api/3/issue`);
            return { statusCode: 200, body: '{}' };
        }

        // manifest.yml
        modules:
            apiRoute:
              - key: get-employee
                path: /employee
                operation: GET
                function: route-handler
                accept:
                  - application/json
                scopes:
                  - read:employee:custom
            function:
              - key: route-handler
                handler: index.routeHandler
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_authz_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn basic_authz_vuln_non_default() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { route, asApp } from '@forge/api';


        function getText({ text }) {
        asApp().requestJira(route`/rest/api/3/issue`);
        return 'Hello, world!\n' + text;
        }

        function App() { 

            getText({ text: 'test' })
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yaml 
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_authz_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn basic_authz_vuln_non_default_renamed() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { route, asApp as pineapple } from '@forge/api';


        function getText({ text }) {
        pineapple().requestJira(route`/rest/api/3/issue`);
        return 'Hello, world!\n' + text;
        }

        function App() { 

            getText({ text: 'test' })
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yaml 
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_authz_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn basic_authz_vuln_default_and_renamed_and() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, {route, asApp as pineapple } from '@forge/api';


        function getText({ text }) {
        api.asApp().requestJira(route`/rest/api/3/issue`);
        return 'Hello, world!\n' + text;
        }

        function App() { 

            getText({ text: 'test' })
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yaml 
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_authz_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn basic_false_authz_vuln_renamed() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { route, asApp as pineapple } from '@forge/api';


        function getText({ text }) {
        asApp().requestJira(route`/rest/api/3/issue`);
        return 'Hello, world!\n' + text;
        }

        function App() { 

            getText({ text: 'test' })
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yaml 
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0));
}

#[cfg(feature = "graphql_schema")]
#[test]
fn excess_scope() {
    let mut test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 
            
        } 

        export const run = render(<Macro app={<App />} />);
        ",
    );

    test_forge_project
        .test_manifest
        .permissions
        .scopes
        .push("read:component:compass".into());

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_perm_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[cfg(feature = "graphql_schema")]
#[test]
fn graphql_correct_scopes() {
    let mut test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 

        const query = `query compass_query($test:CompassSearchTeamsInput!) {
            compass {
                searchTeams(input: $test) {
                    ... on CompassSearchTeamsConnection{
                    nodes {
                    teamId
                    }
                }
                }
            }
            }`
            
            const result = await api
                .asApp()
                .requestGraph(
                query, {}, {}
                );
            const status = result.status;

        } 

        export const run = render(<Macro app={<App />} />);
        ",
    );

    test_forge_project
        .test_manifest
        .permissions
        .scopes
        .push("compass:atlassian-external".into());

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0))
}

#[cfg(feature = "graphql_schema")]
#[test]
fn graphql_excess_scope_with_fragments() {
    let mut test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 
            
        } 

        const check = `fragment componentParts on CompassCatalogQueryApi{ __typename } 
        
        query compass_query($test:CompassSearchTeamsInput!) { compass { ...componentParts } }`

        export const run = render(<Macro app={<App />} />);
        ",
    );

    test_forge_project
        .test_manifest
        .permissions
        .scopes
        .push("read:component:compass".into());

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_perm_vuln(1));
    assert!(scan_result.contains_vulns(1))
}

#[cfg(feature = "graphql_schema")]
#[test]
fn graphql_correct_scopes_with_fragment() {
    let mut test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Macro } from '@forge/ui';
        import * as atlassian_jwt from 'atlassian-jwt';

        function App() { 

        const check = `fragment componentParts on CompassCatalogQueryApi{ searchTeams(input: $test) 
            { ... on CompassSearchTeamsConnection{ nodes { teamId } } } } 
        
        query compass_query($test:CompassSearchTeamsInput!) { compass { ...componentParts } }`
        
        }

        export const run = render(<Macro app={<App />} />);
        ",
    );

    test_forge_project
        .test_manifest
        .permissions
        .scopes
        .push("compass:atlassian-external".into());

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0))
}

#[test]
fn rovo_function_basic_authz_vuln() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';

        function getText({ text }) {
        api.asApp().requestJira(route`/rest/api/3/issue`);
        return 'Hello, world!\n' + text;
        }

        function App() { 

            getText({ text: 'test' })
            
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        } 

        export const run = render(<Macro app={<App />} />);
        
        // manifest.yml 
        modules:
            rovo:agent:
              - key: data-discoverability
                name: Data Discoverability
                description: Test agent description
                prompt: Test prompt instructions
                conversationStarters:
                - starter1
                - starter2
                - starter3
                actions:
                - indexing-compass
            action:
              - key: indexing-compass
                function: main
                actionVerb: GET
                description: Test action description
                inputs:
                data:
                    title: Data
                    type: string
                    required: true
                    description: Test input description
            function:
              - key: main
                handler: index.run
        permissions:
            scopes:
              - 'read:component:compass'
            external:
                fetch:
                backend:
                  - test-backend.example.com
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_authz_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn authz_function_called_in_object_bitbucket() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        const App = () => {
            let testObject = {
                someFunction() {
                const res = api.asApp().requestBitbucket(route`/rest/api/3/test`);
                return res;
                }
            }
            testObject.someFunction()
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />);

        // manifest.yaml
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []", // No permission scopes added here so we expect an issue to be raised from the requestBitbucket()
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(1))
}

#[test]
#[ignore] // Tests manifest has an extra scope defined but not being used, we expect a permission vuln.
fn extra_scope_bitbucket() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        const App = () => {
            let testObject = {
                someFunction() {
                const res = api.asUser().requestBitbucket(route`/repositories/mockworkspace/mockreposlug/default-reviewers/jcg`, {
                    method: 'PUT',
                    body: {}
                });
                return res;
                }
            }
            testObject.someFunction()
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />);

        // manifest.yaml
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes:
              - 'admin:repository:bitbucket'
              - 'unused:permission:defined'"
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(1));
    assert!(scan_result.vuln_description_contains("Least-Privilege", "unused:permission:defined"));
}

#[test] // Tests manifest with no extra scopes, we expect no vulns.
fn no_extra_scope_bitbucket() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        const App = () => {
            let testObject = {
                someFunction() {
                const res = api.asUser().requestBitbucket(route`/repositories/mockworkspace/mockreposlug/default-reviewers/jcg`, {
                    method: 'PUT',
                    body: {}
                });
                return res;
                }
            }
            testObject.someFunction()
            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />);

        // manifest.yaml
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes:
              - 'admin:repository:bitbucket'"
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0));
}

#[test] // Tests manifest with no extra scopes, we expect no vulns.
fn graphql_compass() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import graphqlGateway from '@atlassian/forge-graphql';

        const App = () => {
            const {
                errors,
                data
            } = await graphqlGateway.compass.asApp().getComponent(1);

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />);

        // manifest.yaml
        modules:
            macro:
              - key: basic-hello-world
                function: main
                title: basic
                handler: nothing
                description: Inserts Hello world!
            function:
              - key: main
                handler: index.run
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes:
            ",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_authz_vuln(1));
    dbg!(scan_result.into_vulns()[0].description());
}

#[test]
fn global_webhook_secret() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        import graphqlGateway from '@atlassian/forge-graphql';

        const secret = 'test';

        const App = () => {
            let value = 'value'

            let h = { headers: { 'X-Automation-Webhook-Token': secret }, method: 'POST' }

            fetch('url', h)
            foo();

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />)
        // manifest.yaml
        modules:
          macro:
            - key: basic-hello-world
              function: main
              title: basic
              handler: nothing
              description: Inserts Hello world!
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes:
            - read:component:compass",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
}

#[test]
fn global_webhook_secret_no_post() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        import graphqlGateway from '@atlassian/forge-graphql';

        const secret = 'test';

        const App = () => {
            let value = 'value'

            let h = { headers: { 'X-Automation-Webhook-Token': secret } }

            fetch('url', h)
            foo();

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />)
        // manifest.yaml
        modules:
          macro:
            - key: basic-hello-world
              function: main
              title: basic
              handler: nothing
              description: Inserts Hello world!
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes:
            - read:component:compass",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn global_secret_vuln() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        import graphqlGateway from '@atlassian/forge-graphql';

        const secret = 'test';

        const App = () => {
            let value = 'value'

            let h = { headers: { authorization: secret } }

            fetch('url', h)
            foo();

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />)
        // manifest.yaml
        modules:
          macro:
            - key: basic-hello-world
              function: main
              title: basic
              handler: nothing
              description: Inserts Hello world!
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes:
            - read:component:compass",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn global_secret_no_vuln() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        import graphqlGateway from '@atlassian/forge-graphql';

        const secret = process.env.SECRET;

        const App = () => {
            let value = 'value'

            let h = { headers: { authorization: secret } }

            fetch('url', h)
            foo();

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />)
        // manifest.yaml
        modules:
          macro:
            - key: basic-hello-world
              function: main
              title: basic
              handler: nothing
              description: Inserts Hello world!
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes:
            - read:component:compass",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0));
}

#[test]
fn global_secret_vuln_reset() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        import graphqlGateway from '@atlassian/forge-graphql';

        const secret = 'test';

        const App = () => {
            let value = 'value'

            let h = { headers: { authorization: secret } }

            let secret = process.ENV.secret;

            fetch('url', h)
            foo();

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />)
        // manifest.yaml
        modules:
          macro:
            - key: basic-hello-world
              function: main
              title: basic
              handler: nothing
              description: Inserts Hello world!
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes:
            - read:component:compass",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0));
}

#[test]
fn global_secret_vuln_alternate_file() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/constants.ts
        export const secret = 'SECRET'
        // src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        import { secret } from './constants';
        import graphqlGateway from '@atlassian/forge-graphql';

        const App = () => {
            let value = 'value'

            let h = { headers: { authorization: secret } }

            fetch('url', h)
            foo();

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />)
        // manifest.yaml
        modules:
          macro:
            - key: basic-hello-world
              function: main
              title: basic
              handler: nothing
              description: Inserts Hello world!
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes:
            - read:component:compass",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn graphqlgateway_compass() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
        import api, { route, fetch } from '@forge/api';
        import graphqlGateway from '@atlassian/forge-graphql';

        const foo = async () => {
            const {
                errors,
                data
            } = await graphqlGateway.compass.asUser().getComponent({ id: '123' });
            return data;
        };
        const App = () => {
            let value = 'value'

            let h = { headers: { authorization: 'test' } }
            h.headers.authorization = process.env.SECRET
            h.headers.authorization = `test ${value}`

            fetch('url', h)
            foo();

            return (
                <Fragment>
                <Text>Hello world!</Text>
                </Fragment>
            );
        };
        export const run = render(<Macro app={<App />} />)
        // manifest.yaml
        modules:
          macro:
            - key: basic-hello-world
              function: main
              title: basic
              handler: nothing
              description: Inserts Hello world!
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes:
            - read:component:compass",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0));
}

#[test]
fn kvs_is_valid_authn() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.tsx
        import { kvs } from '@forge/kvs';
        import api from '@forge/api';


        export const src = () => {
            kvs.getSecret();
            api.asApp().requestJira('/rest/api/3/issue/40');
        };

        // manifest.yml
        modules:
            webtrigger:
              - key: basic-hello-world
                function: main
            function:
              - key: main
                handler: index.src
        app:
            id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
            scopes: []",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_vulns(0))
}

#[test]
fn secrets_hardcoded_in_manifest_query_params() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Text } from '@forge/ui';
        
        function App() { 
            return (
                <Text>Hello world!</Text>
            );
        }
        
        export const run = render(<Macro app={<App />} />);

        // manifest.yml
app:
    id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
modules:
    function:
      - key: main
        handler: index.run
permissions:
    scopes: []
providers:
    auth:
      - key: oauth-provider
        name: Oauth Provider
        actions:
            authorization:
                remote: oauth-apis
                path: /oauth2
                queryParameters:
                    client_id: '{{client_id}}'
                    client_secret: 'harcoded_secret'
                    grant_type: client_credentials
        ",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn secrets_hardcoded_in_manifest_exchange() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Text } from '@forge/ui';
        
        function App() { 
            return (
                <Text>Hello world!</Text>
            );
        }
        
        export const run = render(<Macro app={<App />} />);

        // manifest.yml
app:
    id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
modules:
    function:
      - key: main
        handler: index.run
permissions:
    scopes: []
providers:
    auth:
      - key: oauth-provider
        name: Oauth Provider
        actions:
            authorization:
                remote: oauth-apis
                path: /oauth2
            exchange:
                remote: linear-api
                path: oauth/token
                overrides:
                    headers:
                        content-type: application/x-www-form-urlencoded
                    body:
                        client_id: 'hardcoded_id'
                        client_secret: 'hardcoded_secret'
                        grant_type: client_credentials
                        token: '{{not_hardcoded_token}}'
        ",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn secrets_hardcoded_in_manifest_refresh() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Text } from '@forge/ui';
        
        function App() { 
            return (
                <Text>Hello world!</Text>
            );
        }
        
        export const run = render(<Macro app={<App />} />);

        // manifest.yml
app:
    id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
modules:
    function:
      - key: main
        handler: index.run
permissions:
    scopes: []
providers:
    auth:
      - key: oauth-provider
        name: Oauth Provider
        actions:
            authorization:
                remote: oauth-apis
                path: /oauth2
            exchange:
                remote: linear-api
                path: oauth/token
                overrides:
                    headers:
                        content-type: application/x-www-form-urlencoded
                    body:
                        client_id: 'hardcoded_id'
                        client_secret: '{{not_hardcoded_secret}}'
                        grant_type: client_credentials
                        token: '{{not_hardcoded_token}}'
            refresh:
                remote: linear-api
                path: oauth/refresh
                overrides:
                    headers:
                        content-type: application/x-www-form-urlencoded
                    body:
                        client_id: 'hardcoded_id'
                        client_secret: 'hardcoded_secret'
                        refresh_token: 'hardcoded_refresh_token'
        ",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_secret_vuln(2));
    assert!(scan_result.contains_vulns(2));
}

// -----------------------------------------------------------------------------
// Forge SQL injection checker integration tests.
// -----------------------------------------------------------------------------

#[test]
fn sql_injection_reports_direct_payload_interpolation() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = '${payload.id}'`);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_accepts_literals_and_bound_values() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            await sql.executeRaw('ALTER TABLE users ADD COLUMN active BOOLEAN');
            await sql.prepare('SELECT * FROM users WHERE id = ?')
                .bindParams(payload.id)
                .execute();
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_accepts_constant_query_variable_with_bound_parameter() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export const deleteStandupUpdate = async (id) => {
            try {
                const query = `DELETE FROM standup_update WHERE id = ?`;
                await sql.prepare(query).bindParams(id).execute();
            } catch (error) {
                console.error(error);
            }
        };
        export async function run(payload) {
            await deleteStandupUpdate(payload.id);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_accepts_numeric_result_interpolation() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            const requestedLimit = typeof payload.limit === 'number' ? payload.limit : 20;
            const requestedOffset = typeof payload.offset === 'number' ? payload.offset : 0;
            const limit = Math.min(Math.max(Math.floor(requestedLimit), 1), 100);
            const offset = Math.max(Math.floor(requestedOffset), 0);
            await sql.prepare(`SELECT * FROM users LIMIT ${limit} OFFSET ${offset}`).execute();
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_accepts_numeric_builtins_arithmetic_and_local_returns() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        function safeOffset(value) {
            return Number(value) * 10;
        }
        export async function run(payload) {
            const parsed = parseInt(payload.limit, 10);
            const floated = parseFloat(payload.ratio);
            const bounded = Math.min(Math.max(Math.floor(parsed), 1), 100);
            const offset = safeOffset(payload.page);
            await sql.prepare(
                'SELECT * FROM users LIMIT ' + bounded +
                ' OFFSET ' + offset +
                ' /* ratio ' + floated + ' */'
            ).execute();
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_does_not_trust_string_conversion_or_shadowed_numeric_builtins() {
    let string_conversion = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            const value = String(payload.value);
            await sql.prepare(`SELECT * FROM users WHERE name = '${value}'`).execute();
        }",
    );
    assert!(scan_directory_test(string_conversion).contains_sql_vuln(Severity::High, 1));

    let shadowed_number = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        function Number(value) {
            return value;
        }
        export async function run(payload) {
            const value = Number(payload.value);
            await sql.prepare(`SELECT * FROM users WHERE name = '${value}'`).execute();
        }",
    );
    assert!(scan_directory_test(shadowed_number).contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_reports_unresolved_dynamic_query_as_low() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run() {
            const query = unresolvedLibrary.buildQuery('value');
            await sql.executeRaw(query);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 1));
}

#[test]
fn sql_injection_tracks_local_function_arguments_and_returns() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        function makeQuery(id) {
            return `SELECT * FROM users WHERE id = '${id}'`;
        }
        async function executeQuery(id) {
            await sql.executeRaw(makeQuery(id));
        }
        export async function run(payload) {
            await executeQuery(payload.id);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
    assert!(report.into_vulns().iter().any(|finding| {
        finding.check_name() == "forge-sql-injection"
            && finding.proof().contains("call from")
            && finding.proof().contains("instruction")
    }));
}

#[test]
fn sql_injection_recovers_sources_from_projected_object_arguments() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import Resolver from '@forge/resolver';
        import sql from '@forge/sql';
        const resolver = new Resolver();
        function buildQuery({ projectId }) {
            return `UPDATE projects SET enabled = TRUE WHERE id = '${projectId}'`;
        }
        async function editProject(options) {
            await sql.prepare(buildQuery(options));
        }
        resolver.define('edit', async ({ payload }) => {
            await editProject({ projectId: payload.projectId });
        });
        export const run = resolver.getDefinitions();",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
    let proofs = report
        .into_vulns()
        .iter()
        .filter(|finding| finding.check_name() == "forge-sql-injection")
        .map(|finding| finding.proof())
        .collect::<Vec<_>>();
    assert!(
        proofs.iter().any(|proof| {
            proof.contains("resolver payload")
                && !proof.contains("Source: unresolved dynamic origin")
        }),
        "{proofs:#?}"
    );
}

#[test]
fn sql_injection_accepts_numeric_result_through_deep_options() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import Resolver from '@forge/resolver';
        import sql from '@forge/sql';
        const resolver = new Resolver();
        async function exec(query, params = []) {
            return await sql.prepare(query).bindParams(...params).execute();
        }
        async function list(accountId, options = {}) {
            const page = Math.max(1, options.page || 1);
            const offset = parseInt(page, 10);
            return await exec(`SELECT * FROM reminders WHERE account_id = ? LIMIT 10 OFFSET ${offset}`, [accountId]);
        }
        resolver.define('list', async ({ payload }) => list('account', { page: payload.page }));
        export const run = resolver.getDefinitions();",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_supports_transpiled_forge_sql_imports() {
    let safe = MockForgeProject::files_from_string(
        "// src/index.js
        const GET_ROWS = 'SELECT * FROM example';
        const sql_1 = tslib_1.__importStar(require('@forge/sql'));
        export async function run() {
            await sql_1.default.executeRaw(GET_ROWS);
        }",
    );
    let safe_report = scan_directory_test(safe);
    assert!(safe_report.contains_sql_vuln(Severity::High, 0));
    assert!(safe_report.contains_sql_vuln(Severity::Low, 0));

    let unsafe_project = MockForgeProject::files_from_string(
        "// src/index.js
        const sql_1 = tslib_1.__importStar(require('@forge/sql'));
        export async function run(payload) {
            await sql_1.default.executeRaw(`SELECT * FROM example WHERE id = '${payload.id}'`);
        }",
    );
    let unsafe_report = scan_directory_test(unsafe_project);
    assert!(unsafe_report.contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_supports_esm_import_aliases() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import forgeSql from '@forge/sql';
        import { migrationRunner as migrations } from '@forge/sql';
        export async function run(payload) {
            await forgeSql.executeRaw(`SELECT * FROM users WHERE id = ${payload.id}`);
            migrations.enqueue('create-index', `CREATE INDEX ${payload.name} ON users(id)`);
        }",
    );

    assert!(scan_directory_test(project).contains_sql_vuln(Severity::High, 2));
}

#[test]
fn sql_injection_only_flags_unbound_limit_and_offset_in_mixed_query() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            const conditions = ['project_key = ?'];
            const params = [payload.projectKey];
            if (payload.entityType) {
                conditions.push('entity_type = ?');
                params.push(payload.entityType);
            }
            if (payload.entityId !== undefined) {
                conditions.push('entity_id = ?');
                params.push(payload.entityId);
            }
            const where = conditions.join(' AND ');
            const limit = payload.limit ?? 50;
            const offset = payload.offset ?? 0;
            await sql.prepare(`SELECT COUNT(*) AS cnt FROM audit_log WHERE ${where}`)
                .bindParams(...params)
                .execute();
            await sql.prepare(`SELECT * FROM audit_log WHERE ${where} ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`)
                .bindParams(...params)
                .execute();
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_does_not_match_confirmed_other_sql_package() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from 'another-sql-library';
        export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = '${payload.id}'`);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_treats_unclassified_entry_argument_as_unknown() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(event) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = '${event.userId}'`);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 1));
}

#[test]
fn sql_injection_treats_api_and_storage_results_as_untrusted() {
    let api_project = MockForgeProject::files_from_string(
        "// src/index.js
        import api from '@forge/api';
        import sql from '@forge/sql';
        export async function run() {
            const response = await api.asUser().requestJira('/rest/api/3/issue/ABC-1');
            await sql.executeRaw(`SELECT * FROM issues WHERE summary = '${response.summary}'`);
        }",
    );
    let api_report = scan_directory_test(api_project);
    assert!(api_report.contains_sql_vuln(Severity::High, 1));

    let storage_project = MockForgeProject::files_from_string(
        "// src/index.js
        import { kvs } from '@forge/kvs';
        import sql from '@forge/sql';
        export async function run() {
            const filter = await kvs.get('saved-filter');
            await sql.executeRaw(`SELECT * FROM users WHERE ${filter}`);
        }",
    );
    let storage_report = scan_directory_test(storage_project);
    assert!(storage_report.contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_tracks_destructuring_and_containers() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            const { id } = payload;
            const container = { values: [id] };
            const [value] = container.values;
            await sql.executeRaw(`SELECT * FROM users WHERE id = '${value}'`);
        }",
    );

    assert!(scan_directory_test(project).contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_joins_trusted_and_untrusted_branches() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            let table = 'active_users';
            if (payload.includeArchived) {
                table = payload.table;
            }
            await sql.executeRaw(`SELECT * FROM ${table}`);
        }",
    );

    assert!(scan_directory_test(project).contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_reports_sources_and_dynamic_branch_alternatives() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import { storage } from '@forge/api';
        import sql from '@forge/sql';
        export async function run(payload) {
            const date = await storage.get('date');
            let whereClause = '';
            if (payload.filtered) {
                whereClause = ` WHERE due_date >= '${date}'`;
            }
            await sql.prepare(`SELECT * FROM issues${whereClause}`).execute();
        }",
    );

    let report = scan_directory_test(project);
    let finding = report
        .into_vulns()
        .iter()
        .find(|finding| finding.check_name() == "forge-sql-injection")
        .expect("expected SQL injection finding");
    assert_eq!(finding.severity(), Severity::High);
    assert!(finding.proof().contains("Forge storage read at"));
    assert!(finding.proof().contains("one of"));
    assert!(finding.proof().contains("due_date"));
}

#[test]
fn sql_injection_uses_strong_updates_for_definite_assignments() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            let query = payload.query;
            query = 'SELECT * FROM users';
            await sql.executeRaw(query);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.has_no_vulns(), "{:#?}", report.into_vulns());
}

#[test]
fn sql_injection_preserves_constant_structure_across_local_arguments() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        async function remove(table, column, value) {
            await sql.prepare(`DELETE FROM ${table} WHERE ${column} = ?`)
                .bindParams(value)
                .execute();
        }
        export async function run(payload) {
            await remove('users', 'id', payload.id);
        }",
    );

    assert!(scan_directory_test(project).has_no_vulns());
}

#[test]
fn sql_injection_resolves_cross_file_module_constants() {
    let project = MockForgeProject::files_from_string(
        "// src/constants.js
        export const DELETE_CHUNK_SIZE = 5000;
        // src/remove.js
        import sql from '@forge/sql';
        import { DELETE_CHUNK_SIZE } from './constants';
        export async function remove(table, column, value) {
            await sql.prepare(`DELETE FROM ${table} WHERE ${column} = ? LIMIT ${DELETE_CHUNK_SIZE}`)
                .bindParams(value)
                .execute();
        }
        // src/index.js
        import { remove } from './remove';
        export async function run(payload) {
            await remove('users', 'id', payload.id);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.has_no_vulns(), "{:#?}", report.into_vulns());
}

#[test]
fn sql_injection_tracks_transformed_payload_through_cross_file_helpers() {
    let project = MockForgeProject::files_from_string(
        "// src/db.js
        import sql from '@forge/sql';
        export function escapeValue(value) {
            return String(value).replace(/'/g, \"''\");
        }
        export async function queryRows(query) {
            return await sql.executeRaw(query);
        }
        // src/service.js
        import { escapeValue, queryRows } from './db.js';
        export async function save(payload) {
            return await queryRows(`SELECT * FROM users WHERE id = '${escapeValue(payload.id)}'`);
        }
        // src/index.js
        import Resolver from '@forge/resolver';
        import { save } from './service.js';
        const resolver = new Resolver();
        resolver.define('save', async ({ payload }) => save(payload));
        export const run = resolver.getDefinitions();",
    );

    let report = scan_directory_test(project);
    assert!(
        report.contains_sql_vuln(Severity::High, 1),
        "{:#?}",
        report.into_vulns()
    );
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_tracks_storage_read_variants() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import { storage } from '@forge/api';
        import { kvs } from '@forge/kvs';
        import sql from '@forge/sql';
        export async function run() {
            const first = await storage.getSecret('fragment');
            const second = await kvs.query().where('key', 'startsWith', 'filter').getMany();
            await sql.executeRaw(`SELECT * FROM users ${first}`);
            await sql.executeRaw(`SELECT * FROM groups ${second.results[0].value}`);
        }",
    );

    assert!(scan_directory_test(project).contains_sql_vuln(Severity::High, 2));
}

#[test]
fn sql_injection_checks_migration_runner_query_argument() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import { migrationRunner } from '@forge/sql';
        export async function run(payload) {
            migrationRunner.enqueue('migration-1', `CREATE INDEX ${payload.indexName} ON users(id)`);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_tracks_concatenation_aliases_and_string_transformations() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            const id = payload.id.trim().toLowerCase();
            const query = 'SELECT * FROM users WHERE id = ' + id;
            await sql.executeRaw(query);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_accepts_ir_proven_constant_alternatives() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            const table = payload.type === 'active' ? 'active_users' : 'archived_users';
            await sql.executeRaw(`SELECT * FROM ${table}`);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_reports_each_distinct_sink_location_once() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${payload.id}`);
            await sql.executeRaw(`SELECT * FROM projects WHERE id = ${payload.projectId}`);
        }",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 2));
}

#[test]
fn sql_injection_ignores_unsupported_execute_api() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            await sql.execute(`SELECT * FROM users WHERE id = ${payload.id}`);
        }",
    );

    assert!(scan_directory_test(project).has_no_vulns());
}

#[test]
fn sql_injection_scanner_respects_scanner_selection() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${payload.id}`);
        }",
    );

    let secret_args = Args::parse_from(["fsrt", "--scanners", "secret"]);
    assert!(scan_directory_test_with_args(project.clone(), secret_args).has_no_vulns());

    let sql_args = Args::parse_from(["fsrt", "--scanners", "sql-injection"]);
    assert!(scan_directory_test_with_args(project, sql_args).contains_sql_vuln(Severity::High, 1));
}

#[test]
fn sql_injection_report_contains_sink_source_query_and_cwe() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(payload) {
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${payload.id}`);
        }",
    );

    let report = scan_directory_test(project);
    let finding = report
        .into_vulns()
        .iter()
        .find(|finding| finding.check_name() == "forge-sql-injection")
        .unwrap();
    assert!(finding.description().contains("sql.executeRaw"));
    assert!(finding.description().contains("src/index.js"));
    assert!(finding.proof().contains("Query argument"));
    assert!(finding.proof().contains("payload"));
    assert!(finding.proof().contains("payload` at "));
    assert_eq!(finding.marketplace_security_requirement(), "CWE-89");
    let serialized = serde_json::to_value(finding).unwrap();
    assert!(serialized.get("confidence").is_none());
}

#[test]
fn sql_injection_resolver_context_is_property_sensitive() {
    let trusted = MockForgeProject::files_from_string(
        "// src/index.js
        import Resolver from '@forge/resolver';
        import sql from '@forge/sql';
        const resolver = new Resolver();
        resolver.define('safe', async ({ context }) => {
            await sql.executeRaw(`SELECT * FROM ${context.accountId}`);
        });
        export const run = resolver.getDefinitions();",
    );
    assert!(scan_directory_test(trusted).has_no_vulns());

    let unknown = MockForgeProject::files_from_string(
        "// src/index.js
        import Resolver from '@forge/resolver';
        import sql from '@forge/sql';
        const resolver = new Resolver();
        resolver.define('unknown', async ({ context }) => {
            await sql.executeRaw(`SELECT * FROM ${context.extension.foo}`);
        });
        export const run = resolver.getDefinitions();",
    );
    assert!(scan_directory_test(unknown).contains_sql_vuln(Severity::Low, 1));
}

#[test]
fn sql_injection_isolates_resolver_callbacks_and_merges_sink_origins() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import Resolver from '@forge/resolver';
        import sql from '@forge/sql';
        const resolver = new Resolver();
        async function execute(query) {
            await sql.executeRaw(query);
        }
        resolver.define('safe', async ({ context }) => {
            await execute(`SELECT * FROM ${context.accountId}`);
        });
        resolver.define('first', async ({ payload }) => {
            await execute(`SELECT * FROM ${payload.table}`);
        });
        resolver.define('second', async ({ payload }) => {
            await execute(`SELECT * FROM ${payload.otherTable}`);
        });
        export const run = resolver.getDefinitions();",
    );

    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
    assert!(report.into_vulns().iter().any(|finding| {
        finding.check_name() == "forge-sql-injection"
            && finding.proof().contains("run.first")
            && finding.proof().contains("run.second")
    }));
}

#[test]
fn sql_injection_tracks_request_and_external_response_reads() {
    let request = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(req) {
            const body = await req.json();
            await sql.prepare(`DELETE FROM users WHERE id = ${body.id}`);
        }",
    );
    assert!(scan_directory_test(request).contains_sql_vuln(Severity::High, 1));

    let network = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run() {
            const response = await fetch('external-data');
            const body = await response.json();
            await sql.executeRaw(`SELECT * FROM users WHERE id = ${body.id}`);
        }",
    );
    let report = scan_directory_test(network);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.into_vulns().iter().any(|finding| {
        finding.check_name() == "forge-sql-injection"
            && finding.proof().contains("external network response")
    }));
}

#[test]
fn sql_injection_tracks_api_sources_through_local_returns() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import api from '@forge/api';
        import sql from '@forge/sql';
        async function getSummary() {
            const issue = await api.asApp().requestJira('/rest/api/3/issue/ABC-1');
            return issue.fields.summary;
        }
        export async function run() {
            await sql.executeRaw(`SELECT * FROM issues WHERE summary = '${await getSummary()}'`);
        }",
    );
    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.contains_sql_vuln(Severity::Low, 0));
}

#[test]
fn sql_injection_tracks_prepared_statement_results() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run() {
            const rows = await sql.prepare('SELECT name FROM users').execute();
            await sql.executeRaw(`SELECT * FROM audit WHERE actor = '${rows[0].name}'`);
        }",
    );
    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 1));
    assert!(report.into_vulns().iter().any(|finding| {
        finding.check_name() == "forge-sql-injection"
            && finding.proof().contains("Forge SQL result")
    }));
}

#[test]
fn sql_injection_reports_unresolved_computed_properties_as_low() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import sql from '@forge/sql';
        export async function run(object, dynamicKey) {
            const fragment = object[dynamicKey];
            await sql.executeRaw(`SELECT * FROM users ${fragment}`);
        }",
    );
    let report = scan_directory_test(project);
    assert!(report.contains_sql_vuln(Severity::High, 0));
    assert!(report.contains_sql_vuln(Severity::Low, 1));
}

#[test]
fn sql_injection_does_not_match_proven_local_receiver() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        function customLibrary() {
            return { executeRaw() {} };
        }
        const sql = customLibrary();
        export async function run(payload) {
            await sql.executeRaw(`not SQL ${payload.id}`);
        }",
    );
    assert!(scan_directory_test(project).has_no_vulns());
}

#[test]
fn sql_injection_ignores_migration_id_argument() {
    let project = MockForgeProject::files_from_string(
        "// src/index.js
        import { migrationRunner } from '@forge/sql';
        export async function run(payload) {
            migrationRunner.enqueue(payload.id, 'CREATE TABLE users (id INT)');
        }",
    );
    assert!(scan_directory_test(project).has_no_vulns());
}

// -----------------------------------------------------------------------------
// Unit tests for `forge_analyzer::checkers::is_atlassian_url`.
//
// `is_atlassian_url` decides whether a fetch URL targets an Atlassian endpoint.
// Basic auth to an Atlassian URL is flagged; Basic auth to non-Atlassian URLs
// is not (so we don't flag third-party API calls).
// -----------------------------------------------------------------------------
#[cfg(test)]
mod is_atlassian_url_tests {
    use forge_analyzer::checkers::is_atlassian_url;

    #[test]
    fn atlassian_urls_are_classified() {
        let cases = [
            // Full URLs — known Atlassian hosts
            "https://api.atlassian.com",
            "https://api.atlassian.com/admin/v1/orgs",
            "https://api.atlassian.com/admin/v1/orgs/",
            "https://api.atlassian.com/admin/v1/orgs//directories",
            "https://api.atlassian.com/jsm/assets/v1/imports/info",
            "https://api.atlassian.com/jsm/csm/cloudid//api/v1/customer/details",
            "https://api.atlassian.com/jsm/ops/integration/v2/alerts",
            "https://api.atlassian.com/users//manage/api-tokens",
            "https://api.atlassian.com/ex/jira//rest/api/3/instance/license",
            "https://auth.atlassian.com/oauth/token",
            "https://community.atlassian.com/forums/s/api/2.0/search?q=",
            "https://marketplace.atlassian.com",
            "https://marketplace.atlassian.com/gateway/api/graphql",
            "https://marketplace.atlassian.com/rest/2/addons//versions/latest",
            "https://example.atlassian.net/rest/collectors/1.0/template/custom/aaaaaa",
            "https://example.atlassian.net/wiki/api/v2/pages//children",
            "https://example.atlassian.net/rest/api/3/attachment/content/11111",
            "https://example.atlassian.net/rest/api/3/search/jql",
            "https://api.bitbucket.org/2.0/repositories//",
            "https://api.bitbucket.org/2.0/snippets//",
            "https://api.statuspage.io/v1/pages",
            "https://api.statuspage.io/v1/pages//incidents/",
            // // Templated / redacted-subdomain URLs (host is empty or starts with ".")
            "https://.atlassian.net/rest/api/2/user",
            "https://.atlassian.net/rest/api/3/project",
            "https://.statuspage.io/api/v2/summary.json",
            "https:///rest/api/3/myself",
            "https:///rest/api/3/user/search?query=",
            "https:///wiki/rest/api/content//move//",
            // Relative paths — matched by Atlassian product path regex
            "/_edge/tenant_info",
            // `${baseUrl}` substituted to "" produces a doubled leading slash
            "//rest/api/3/issue",
            "//rest/api/3/issue//assignee",
            "//rest/api/3/project/search?action=create",
            // Case-insensitive host matching
            "HTTPS://API.ATLASSIAN.COM/admin/v1/orgs",
            "Https://Tenant.Atlassian.Net/rest/api/3/issue",
            // Full host-matched URL with a non-allowlisted path still matches by host
            "https://example.atlassian.net/rest/workflowDesigner/latest/workflows?name=foo",
        ];
        for url in &cases {
            assert!(
                is_atlassian_url(url),
                "expected Atlassian classification for: {url}"
            );
        }
    }

    #[test]
    fn non_atlassian_urls_are_not_classified() {
        let cases = [
            // Third-party / customer-controlled hosts
            "https://example.com/rest/api/3/issue",
            "https://attacker.com/rest/api/3/myself",
            "https://my.internal.corp/api/v1/whatever",
            "http://localhost:8080/foo",
            // Spoof attempts — suffix match must require a preceding dot
            "https://atlassian.net.attacker.com/rest/api/3/issue",
            "https://evil-atlassian.com/rest/api/3/issue",
            "https://fakeatlassian.com/rest/api/3/issue",
            // Third-party SaaS
            "https://api.openai.com/v1/chat/completions",
            "https://genai-playground.uksouth.cloudapp.azure.com/api/graphrag/transcribe-file",
            // Relative paths not in the Atlassian product allowlist
            "/rest/workflowDesigner/latest/workflows?name=foo&draft=false",
            "/api/v1/some-custom-path",
            "/foo/bar/baz",
            // Empty string
            "",
        ];
        for url in &cases {
            assert!(
                !is_atlassian_url(url),
                "expected NON-Atlassian classification for: {url}"
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Unit tests for `forge_analyzer::checkers::is_admin_path`.
//
// `is_admin_path` classifies URLs/paths that target Atlassian admin-scoped
// endpoints. Bearer auth on a matching path is reported as a container token.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod is_admin_path_tests {
    use forge_analyzer::checkers::is_admin_path;

    #[test]
    fn admin_paths_are_classified() {
        let cases = [
            // admin/v[12]/orgs/... — Org admin REST API
            "/admin/v1/orgs/",
            "/admin/v1/orgs/abc-123",
            "/admin/v1/orgs/abc-123/groups/search",
            "/admin/v1/orgs//directories",
            "https://api.atlassian.com/admin/v1/orgs",
            "https://api.atlassian.com/admin/v1/orgs/123",
            "//admin/v1/orgs/abc-123/users",
            "admin/v1/orgs/abc-123/policies",
            "/admin/v2/orgs/",
            "/admin/v2/orgs//workspaces",
            "/admin/v2/orgs/abc-123/workspaces",
            "https://api.atlassian.com/admin/v2/orgs/abc-123",
            // admin/control/v[12]/orgs — Org admin "control" API
            "/admin/control/v1/orgs",
            "/admin/control/v1/orgs/abc-123",
            "/admin/control/v2/orgs",
            "/admin/control/v2/orgs/abc-123/policies",
            "https://api.atlassian.com/admin/control/v1/orgs",
            "admin/control/v1/orgs",
            // admin/user-provisioning/v1/org — User provisioning
            "/admin/user-provisioning/v1/org/",
            "/admin/user-provisioning/v1/org/abc-123/users",
            "https://api.atlassian.com/admin/user-provisioning/v1/org/abc-123",
            // scim/directory — SCIM directory admin
            "/scim/directory/abc-123/ResourceTypes",
            "/scim/directory/abc-123/Schemas",
            "/scim/directory/abc-123/Groups",
            "/scim/directory/abc-123/Users",
            "/scim/directory/abc-123/Users/xyz-789",
            "https://api.atlassian.com/scim/directory/abc-123/Users",
            "//scim/directory/abc-123/Users",
            "scim/directory/abc-123/Users",
            // users/<id>/manage — Per-user admin endpoints
            "/users/abc-123/manage",
            "/users/abc-123/manage/api-tokens",
            "/users/abc-123/manage/profile",
            "https://api.atlassian.com/users/abc-123/manage/api-tokens",
            "users/abc-123/manage/api-tokens",
            // orgs/<id>/{api-tokens,service-accounts,...} — Per-org credential endpoints
            "/orgs/abc-123/classification-levels",
            "/orgs/abc-123/api-tokens",
            "/orgs/abc-123/api-tokens/xyz",
            "/orgs/abc-123/service-accounts",
            "/orgs/abc-123/api-keys",
            "https://api.atlassian.com/orgs/abc-123/api-tokens",
            "orgs/abc-123/api-tokens",
            // Case-insensitive matching
            "/Admin/V1/Orgs/abc-123",
            "/USERS/abc-123/MANAGE/api-tokens",
            "HTTPS://API.ATLASSIAN.COM/ADMIN/V2/ORGS/",
            "/Scim/Directory/abc/Users",
            "/Orgs/abc/Api-Tokens",
        ];
        for url in &cases {
            assert!(
                is_admin_path(url),
                "expected admin-path classification for: {url}"
            );
        }
    }

    #[test]
    fn non_admin_paths_are_not_classified() {
        let cases = [
            "",
            // Standard Atlassian non-admin endpoints
            "/rest/api/3/issue",
            "/rest/api/3/myself",
            "/wiki/api/v2/pages",
            "https://api.atlassian.com/jsm/assets/v1/imports/info",
            // Lookalikes — wrong version, wrong segment, or partial match
            "/admin/v3/orgs/",                  // wrong version (only v1/v2)
            "/admin/v1/users/abc-123",          // not /admin/v[12]/orgs/
            "/admin/control/v3/orgs",           // wrong version
            "/admin/control/v1/orgsfoo",        // segment must end at "orgs"
            "/admin/user-provisioning/v2/org/", // wrong version (only v1)
            "/users/manage/api-tokens",         // missing user-id segment
            "/users/abc-123/managefoo",         // segment must end at "manage"
            "/orgs/abc-123/api-tokensfoo",      // must match exactly
            "/orgs/abc-123/other-thing",        // not in the credential list
            "/scim/directory/abc-123/Other",    // not a known SCIM resource
            "https://example.com/rest/api/3/issue",
        ];
        for url in &cases {
            assert!(
                !is_admin_path(url),
                "expected NON-admin-path classification for: {url}"
            );
        }
    }
}
