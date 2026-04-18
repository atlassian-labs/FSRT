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
            .filter(|vuln| {
                vuln.check_name()
                    .starts_with("Custom-Check-Basic-Authorization-")
            })
            .count()
            == expected_len
    }

    #[inline]
    fn contains_bearer_admin_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| {
                vuln.check_name()
                    .starts_with("Custom-Check-Bearer-Admin-")
            })
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

#[test]
fn fetch_http_basic_authorization_concat_with_env() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';

        function App() {
            let token = process.env.API_TOKEN;
            let h = { headers: { Authorization: 'Basic ' + token } };
            fetch('api.atlassian.com/rest/api/3/issue', h);
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn fetch_http_basic_authorization_default_import_api_fetch() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api from '@forge/api';

        function App() {
            let token = process.env.API_TOKEN;
            let h = { headers: { Authorization: 'Basic ' + token } };
            api.fetch('api.atlassian.com/rest/api/3/issue', h);
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn fetch_http_basic_authorization_chained_api_fetch() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api from '@forge/api';

        function App() {
            let token = process.env.API_TOKEN;
            let h = { headers: { Authorization: 'Basic ' + token } };
            api.fetch('api.atlassian.com/rest/api/3/issue', h).then((res) => res.json());
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
    assert!(scan_result.contains_vulns(1));
}

#[test]
fn fetch_http_basic_authorization_separate_basic_auth_header_template() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { fetch } from '@forge/api';

        async function App() {
            let credentials = process.env.API_TOKEN;
            const basicAuthHeader = `Basic ${credentials}`;
            const response = await fetch('api.atlassian.com/rest/api/3/issue', {
                method: 'GET',
                headers: {
                    Accept: 'application/json',
                    'Content-Type': 'application/json',
                    Authorization: basicAuthHeader,
                },
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
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
    assert!(scan_result.contains_vulns(1));
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

#[test]
fn fetch_http_basic_authorization_re_export_resolver() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// manifest.yml
app:
  id: test-app
modules:
  function:
    - key: main
      handler: index.handler
permissions:
  scopes: []
// src/index.js
export { handler } from './resolvers';
// src/resolvers.ts
import Resolver from '@forge/resolver';
import { fetch } from '@forge/api';
const resolver = new Resolver();
resolver.define('fetchData', async () => {
    const result = await fetch('api.atlassian.com/rest/api/3/issue', {
        method: 'GET',
        headers: { Authorization: 'Basic ' + process.env.TOKEN, Accept: 'application/json' }
    });
    return result;
});
export const handler = resolver.getDefinitions();",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_vulns(1));
}

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

#[test]
fn bearer_admin_api_fetch_template_url() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// manifest.yml
app:
  id: test-app
modules:
  function:
    - key: main
      handler: index.handler
permissions:
  scopes: []
// src/index.js
export { handler } from './resolvers';
// src/resolvers.ts
import Resolver from '@forge/resolver';
import { fetch } from '@forge/api';
const resolver = new Resolver();
resolver.define('getUsers', async () => {
    const orgId = 'some-org';
    const response = await fetch(`api.atlassian.com/admin/v2/orgs/${orgId}/users`, {
        method: 'GET',
        headers: { Authorization: `Bearer ${process.env.API_KEY}`, Accept: 'application/json' }
    });
    return response;
});
export const handler = resolver.getDefinitions();",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_bearer_admin_vuln(1));
    assert!(scan_result.contains_basic_auth_vuln(0));
    assert!(scan_result.contains_vulns(1));
}

// #[test]
// fn fetch_http_basic_authorization_test_2() {
//     let test_forge_project = MockForgeProject::files_from_string(
//         "// src/index.jsx
//         import Resolver from '@forge/resolver';
//         import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
//         import { fetch } from '@forge/api';

//         const resolver = new Resolver();
//         resolver.define(
//             'deleteUser',
//             async ({ context, payload: { accountId, email, apiKey } }) => {
//                 const response = await fetch(
//                         context.siteUrl + `/rest/api/3/user?accountId=${accountId}`,
//                         {
//                             method: 'DELETE',
//                             headers: {
//                                 Authorization: 'Basic ' + base64StringFrom(email, apiKey),
//                                 Accept: 'application/json',
//                             },
//                         }
//                     );
//                 const data = await response.json();
//                 return data;
//             }
//         );

//         function App() {
//             return (
//                 <Fragment>
//                 <Text>Hello</Text>
//                 </Fragment>
//             );
//         }

//         export const run = render(<Macro app={<App />} />);",
//     );

//     let scan_result = scan_directory_test(test_forge_project);
//     assert!(scan_result.contains_basic_auth_vuln(1));
//     assert!(scan_result.contains_secret_vuln(0));
//     assert!(scan_result.contains_vulns(1));
// }

#[test]
fn basic_auth_request_jira_shim() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';

        function App() {
            let token = process.env.API_TOKEN;
            api.asApp().requestJira(route`/rest/api/3/issue`, {
                method: 'GET',
                headers: { Authorization: 'Basic ' + token }
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
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn basic_auth_request_confluence_shim() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';

        function App() {
            let token = process.env.API_TOKEN;
            api.asApp().requestConfluence(route`/rest/api/content`, {
                method: 'GET',
                headers: { Authorization: 'Basic ' + token }
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
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn basic_auth_forge_fetch_shim() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { forgeFetch } from '@forge/api';

        function App() {
            let token = process.env.API_TOKEN;
            let h = { headers: { Authorization: 'Basic ' + token } };
            forgeFetch('api.atlassian.com/rest/api/3/issue', h);
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn bearer_not_checked_for_request_jira_shim() {
    // BearerAdmin is only checked for fetch / api.fetch, not platform API shims.
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';

        function App() {
            let token = process.env.ADMIN_TOKEN;
            api.asApp().requestJira(route`/rest/api/3/issue`, {
                method: 'GET',
                headers: { Authorization: 'Bearer ' + token }
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
    assert!(scan_result.contains_bearer_admin_vuln(0));
    assert!(scan_result.contains_basic_auth_vuln(0));
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn basic_auth_request_bitbucket_shim() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';

        function App() {
            let token = process.env.API_TOKEN;
            api.asApp().requestBitbucket(route`/rest/api/3/test`, {
                method: 'GET',
                headers: { Authorization: 'Basic ' + token }
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
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn basic_auth_request_jira_template_literal() {
    // Mirrors real-world pattern: template literal Basic auth + api.requestJira
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import api, { route } from '@forge/api';
        import { requestJira } from '@forge/bridge';

        async function App() {
            let encodedCredentials = process.env.API_TOKEN;
            const response = await requestJira(route`/rest/api/latest/group/user`, {
                method: 'DELETE',
                headers: {
                    Authorization: `Basic ${encodedCredentials}`,
                },
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
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn basic_auth_request_confluence_named_import_forge_api() {
    // import { requestConfluence } from '@forge/api'; with template literal Basic auth
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { requestConfluence, route } from '@forge/api';

        async function App() {
            let token = process.env.API_TOKEN;
            const response = await requestConfluence(route`/wiki/rest/api/user/current`, {
                headers: {
                    Accept: 'application/json',
                    Authorization: `Basic ${token}`,
                },
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
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
}

#[test]
fn basic_auth_request_jira_class_method_unreachable_default_off() {
    // By default, unreachable class methods are not scanned. This issue should only
    // be reported when SCAN_FUNCTIONS=1 is enabled.
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { requestJira, route } from '@forge/api';

        export class BackupAdapter {
            async generateBackup(authKey) {
                const response = await requestJira(route`/rest/backup/1/export/runbackup`, {
                    method: 'POST',
                    headers: {
                        Authorization: `Basic ${authKey}`,
                        Accept: 'application/json',
                    },
                });
                return response;
            }
        }

        function App() {
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let args = Args::parse_from([""]);
    let scan_result = scan_directory_test_with_args(test_forge_project, args);
    assert!(scan_result.contains_basic_auth_vuln(0));
    assert!(scan_result.contains_secret_vuln(0));

    // also verify the explicit CLI flag enables the scan in tests deterministically.
}

#[test]
fn basic_auth_request_jira_class_method_with_scan_functions() {
    let test_forge_project = MockForgeProject::files_from_string(
        "// src/index.jsx
        import ForgeUI, { render, Macro, Fragment, Text } from '@forge/ui';
        import { requestJira, route } from '@forge/api';

        export class BackupAdapter {
            async generateBackup(authKey) {
                const response = await requestJira(route`/rest/backup/1/export/runbackup`, {
                    method: 'POST',
                    headers: {
                        Authorization: `Basic ${authKey}`,
                        Accept: 'application/json',
                    },
                });
                return response;
            }
        }

        function App() {
            return (
                <Fragment>
                <Text>Hello</Text>
                </Fragment>
            );
        }

        export const run = render(<Macro app={<App />} />);",
    );

    let args = Args::parse_from(["", "--scan-functions"]);
    let scan_result = scan_directory_test_with_args(test_forge_project, args);
    assert!(scan_result.contains_basic_auth_vuln(1));
    assert!(scan_result.contains_secret_vuln(0));
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
// `is_atlassian_url` is the URL classifier used by `AuthHeaderChecker` to decide
// whether sending an `Authorization: Basic ...` header is suspicious. These
// cases mirror the curated list in `basic-auth-urls-sorted.atlassian.txt` and
// the reference Python implementation in `split_atlassian_urls.py`. Every
// example below should agree with the Python classifier's verdict.
// -----------------------------------------------------------------------------
#[cfg(test)]
mod is_atlassian_url_tests {
    use forge_analyzer::checkers::is_atlassian_url;

    /// Atlassian-classified examples from `basic-auth-urls-sorted.atlassian.txt`.
    /// All of these MUST be classified as Atlassian.
    #[test]
    fn full_urls_with_atlassian_hosts() {
        let cases = [
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
            "https://deviniti.atlassian.net/rest/collectors/1.0/template/custom/d61ebf39",
            "https://osci.atlassian.net/wiki/api/v2/pages//children",
            "https://xdevpod.atlassian.net/rest/api/3/attachment/content/10117",
            "https://xdevpod.atlassian.net/rest/api/3/search/jql",
            "https://api.bitbucket.org/2.0/repositories//",
            "https://api.bitbucket.org/2.0/snippets//",
            "https://api.statuspage.io/v1/pages",
            "https://api.statuspage.io/v1/pages//incidents/",
        ];
        for url in &cases {
            assert!(
                is_atlassian_url(url),
                "expected Atlassian classification for: {url}"
            );
        }
    }

    /// Templated/redacted-subdomain URLs from the example file. The host is
    /// either `.atlassian.net` (subdomain placeholder collapsed to a leading
    /// dot) or completely empty (`https:///rest/...`).
    #[test]
    fn redacted_or_templated_subdomain_urls() {
        let cases = [
            "https://.atlassian.net/rest/api/2/user",
            "https://.atlassian.net/rest/api/3/project",
            "https://.statuspage.io/api/v2/summary.json",
            "https:///rest/api/3/myself",
            "https:///rest/api/3/user/search?query=",
            "https:///wiki/rest/api/content/",
            "https:///wiki/rest/api/content//move//",
            "https:///wiki/rest/api/content//pagehierarchy/copy",
            "https:///wiki/rest/api/content/search?cql=type=page+and+space=",
            "https:///wiki/rest/api/longtask/",
            "https:///wiki/rest/api/space",
            "https:///wiki/rest/api/space/",
            "https:///wiki/rest/api/space/?expand=homepage",
        ];
        for url in &cases {
            assert!(
                is_atlassian_url(url),
                "expected Atlassian classification for: {url}"
            );
        }
    }

    /// Relative paths and `${baseUrl}`-substituted-to-empty paths that show
    /// up in real Forge apps. These have no scheme/host and rely on the
    /// Atlassian-product-path regex.
    #[test]
    fn relative_atlassian_paths() {
        let cases = [
            "/_edge/tenant_info",
            "/admin/v1/orgs/",
            "/admin/v1/orgs//groups/search",
            "/admin/v2/orgs//workspaces",
            "/ex/confluence//wiki/api/v2/footer-comments",
            "/ex/confluence//wiki/api/v2/pages",
            "/gateway/api/graphql",
            "/gateway/api/jsm/assets/workspace//v1/object/aql?maxResults=&startAt=0",
            "/gateway/api/jsm/assets/workspace//v1/objectschema/create",
            "/gateway/api/public/teams/v1/org//teams/",
            "/jsm/assets/v1/imports/info",
            "/rest/api/2/filter/favourite?expand=jql",
            "/rest/api/2/search",
            "/rest/api/3/applicationrole",
            "/rest/api/3/issue",
            "/rest/api/3/myself",
            "/rest/api/3/myself?expand=groups",
            "/rest/api/latest/applicationrole/jira-software",
            "/rest/api/optics/auth?hostname=",
            "/rest/backup/1/export/getProgress?taskId=",
            "/rest/backup/1/export/lastTaskId",
            "/rest/backup/1/export/runbackup",
            "/rest/forge/1.0/license",
            "/rest/insight/1.0/object/navlist/aql",
            "/rest/insight/1.0/objectschema/list?maxResults=&startAt=",
            "/rest/servicedeskapi/assets/workspace",
            "/wiki/api/v2/pages",
            "/wiki/api/v2/spaces",
            "/wiki/rest/api/template/page",
            // `${baseUrl}` substituted to "" leaves a doubled leading slash.
            "//rest/api/3/issue",
            "//rest/api/3/issue/",
            "//rest/api/3/issue//assignee",
            "//rest/api/3/issue//comment",
            "//rest/api/3/issue//transitions",
            "//rest/api/3/project/search?action=create",
        ];
        for url in &cases {
            assert!(
                is_atlassian_url(url),
                "expected Atlassian classification for: {url}"
            );
        }
    }

    /// Non-Atlassian URLs MUST NOT be classified as Atlassian, so the
    /// `AuthHeaderChecker` still flags `Basic` auth sent to them.
    #[test]
    fn non_atlassian_urls_are_not_atlassian() {
        let cases = [
            // Customer-controlled or 3rd-party tenants.
            "https://example.com/rest/api/3/issue",
            "https://attacker.com/rest/api/3/myself",
            "https://my.internal.corp/api/v1/whatever",
            "http://localhost:8080/foo",
            // Spoofy host endings — must NOT match suffix-without-dot.
            "https://atlassian.net.attacker.com/rest/api/3/issue",
            "https://evil-atlassian.com/rest/api/3/issue",
            "https://fakeatlassian.com/rest/api/3/issue",
            // Plain path that doesn't match any known Atlassian product.
            "/api/v1/some-custom-path",
            "/foo/bar/baz",
            // Empty string must not be Atlassian.
            "",
        ];
        for url in &cases {
            assert!(
                !is_atlassian_url(url),
                "expected NON-Atlassian classification for: {url}"
            );
        }
    }

    /// Real customer URLs from the case studies that motivated this change:
    /// `${baseUrl}/rest/workflowDesigner/...` (a customer's own Jira tenant
    /// via `serverInfo.baseUrl`) is NOT a known Atlassian product path
    /// pattern, so the relative-path arm should NOT match. But a full
    /// `*.atlassian.net` URL with the same path SHOULD match by host.
    #[test]
    fn customer_baseurl_paths_via_workflowdesigner() {
        // `baseUrl` substituted to empty -> bare relative path that doesn't
        // match any known Atlassian product path pattern.
        assert!(
            !is_atlassian_url(
                "/rest/workflowDesigner/latest/workflows?name=foo&draft=false"
            ),
            "raw /rest/workflowDesigner/... is not in our Atlassian path allowlist",
        );

        // Same path on a real Atlassian tenant URL — host-matched.
        assert!(is_atlassian_url(
            "https://example.atlassian.net/rest/workflowDesigner/latest/workflows?name=foo&draft=false"
        ));
    }

    /// Mixed-case hosts and case-insensitive scheme.
    #[test]
    fn case_insensitive_classification() {
        assert!(is_atlassian_url("HTTPS://API.ATLASSIAN.COM/admin/v1/orgs"));
        assert!(is_atlassian_url(
            "Https://Tenant.Atlassian.Net/rest/api/3/issue"
        ));
    }

    /// Sanity: third-party SaaS endpoints (OpenAI, Azure cloudapp, etc.)
    /// must NEVER be classified as Atlassian. These are the exact URLs that
    /// surfaced during real-world CSV logging — they should be filtered out
    /// of the temporary `FSRT_AUTH_URL_CSV` output.
    #[test]
    fn third_party_saas_urls_are_not_atlassian() {
        let cases = [
            "https://api.openai.com/v1/chat/completions",
            "https://genai-playground.uksouth.cloudapp.azure.com/api/graphrag/transcribe-file",
        ];
        for url in &cases {
            assert!(
                !is_atlassian_url(url),
                "expected NON-Atlassian classification for: {url}"
            );
        }
    }
}
