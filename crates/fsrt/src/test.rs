use crate::{Args, forge_project::ForgeProjectTrait, scan_directory};
use clap::Parser;
use forge_analyzer::definitions::PackageData;
use forge_analyzer::reporter::Report;
use forge_loader::manifest::{ForgeManifest, FunctionMod};
use std::fmt;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use swc_core::common::sync::Lrc;
use swc_core::common::{FileName, SourceFile, SourceMap};

trait ReportExt {
    fn has_no_vulns(&self) -> bool;

    fn contains_secret_vuln(&self, expected_len: usize) -> bool;

    #[cfg(feature = "graphql_schema")]
    fn contains_perm_vuln(&self, expected_len: usize) -> bool;

    fn vuln_description_contains(&self, check_name: &str, description_snippet: &str) -> bool;

    fn contains_vulns(&self, expected_len: i32) -> bool;

    fn contains_authz_vuln(&self, expected_len: usize) -> bool;

    fn contains_basic_auth_vuln(&self, expected_len: usize) -> bool;

    fn contains_bearer_admin_vuln(&self, expected_len: usize) -> bool;
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
    fn contains_basic_auth_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name().starts_with("Custom-Check-Basic-Auth-"))
            .count()
            == expected_len
    }

    #[inline]
    fn contains_bearer_admin_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name().starts_with("Bearer-Admin"))
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
}

#[derive(Clone)]
pub(crate) struct MockForgeProject<'a> {
    pub files_name_to_source: HashMap<PathBuf, Arc<SourceFile>>,
    pub test_manifest: ForgeManifest<'a>,
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

        let manifest = if let Some(manifest_string) = different_files.clone().find(|string| {
            string
                .replace("//", "")
                .trim_start()
                .starts_with("manifest.yaml")
                || string
                    .trim_start()
                    .replace("//", "")
                    .starts_with("manifest.yml")
        }) {
            serde_yaml::from_str(manifest_string.split_once('\n').unwrap().1).unwrap_or_default()
        } else {
            ForgeManifest::create_manifest_with_func_mod(FunctionMod {
                key: "main",
                handler: "index.run",
                providers: None,
            })
        };

        let mut mock_forge_project = MockForgeProject {
            files_name_to_source: HashMap::new(),
            test_manifest: manifest.to_owned(),
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
    fn load_file(&self, p: impl AsRef<Path>, _: Arc<SourceMap>) -> Arc<SourceFile> {
        self.files_name_to_source.get(p.as_ref()).unwrap().clone()
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

    fn get_manifest(&self) -> ForgeManifest<'_> {
        self.test_manifest.clone()
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
fn test_simple() {
    let forge_manifest = ForgeManifest::create_manifest_with_func_mod(FunctionMod {
        key: "main",
        handler: "index.run",
        providers: None,
    });

    let mut test_forge_project = MockForgeProject {
        test_manifest: forge_manifest,
        files_name_to_source: HashMap::new(),
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
fn test_secret_vuln() {
    let forge_manifest = ForgeManifest::create_manifest_with_func_mod(FunctionMod {
        key: "main",
        handler: "index.run",
        providers: None,
    });

    let mut test_forge_project = MockForgeProject {
        test_manifest: forge_manifest,
        files_name_to_source: HashMap::new(),
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

// Tests that Basic auth on a fetch to an Atlassian URL is detected across
// several common import patterns: named import, default import (api.fetch),
// chained .then(), and a pre-built template-literal header variable.
#[test]
fn basic_auth_fetch_detected_across_import_styles() {
    // (source, expected_basic_auth_vulns)
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
    ];

    for (src, expected) in cases {
        let result = scan_directory_test(MockForgeProject::files_from_string(src));
        assert!(
            result.contains_basic_auth_vuln(*expected),
            "expected {expected} basic-auth vuln(s) for snippet:\n{src}"
        );
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
    assert!(scan_result.contains_basic_auth_vuln(0));
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
//     assert!(scan_result.contains_basic_auth_vuln(1));
//     assert!(scan_result.contains_vulns(1));
// }

#[test]
fn bearer_admin_api_fetch_static_url() {
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
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_bearer_admin_vuln(1));
    assert!(scan_result.contains_basic_auth_vuln(0));
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
//     assert!(scan_result.contains_bearer_admin_vuln(1));
//     assert!(scan_result.contains_basic_auth_vuln(0));
//     assert!(scan_result.contains_vulns(1));
// }

// Platform API shims (requestJira, requestConfluence, requestBitbucket) always
// target Atlassian endpoints, so Basic auth on any of them is flagged regardless
// of URL. Bearer auth on a shim is NOT flagged (only fetch is checked for BearerAdmin).
#[test]
fn basic_auth_on_platform_api_shims() {
    // (label, source, expected_basic_auth, expected_bearer_admin)
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
            // Bearer on a platform shim must NOT be flagged as BearerAdmin
            "bearer on requestJira not flagged",
            "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';
        function App() {
            let token = process.env.ADMIN_TOKEN;
            api.asApp().requestJira(route`/rest/api/3/issue`, { method: 'GET', headers: { Authorization: 'Bearer ' + token } });
            return <Fragment><Text>Hello</Text></Fragment>;
        }
        export const run = render(<Macro app={<App />} />);",
            0,
            0,
        ),
    ];

    for (label, src, expected_basic, expected_bearer) in cases {
        let result = scan_directory_test(MockForgeProject::files_from_string(src));
        assert!(
            result.contains_basic_auth_vuln(*expected_basic),
            "[{label}] expected {expected_basic} basic-auth vuln(s)"
        );
        assert!(
            result.contains_bearer_admin_vuln(*expected_bearer),
            "[{label}] expected {expected_bearer} bearer-admin vuln(s)"
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
// endpoints. Bearer auth on a matching path is flagged as BearerAdmin.
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
