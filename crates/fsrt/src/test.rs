use crate::{forge_project::ForgeProjectTrait, scan_directory, Args};
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

    fn contains_vulns(&self, expected_len: i32) -> bool;

    fn contains_authz_vuln(&self, expected_len: usize) -> bool;
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
            .filter(|vuln| vuln.check_name().contains("Authorizatio"))
            .count()
            == expected_len
    }

    #[inline]
    fn contains_secret_vuln(&self, expected_len: usize) -> bool {
        self.into_vulns()
            .iter()
            .filter(|vuln| vuln.check_name().starts_with("Hardcoded-Secret-"))
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
            .new_source_file(FileName::Real(file_name.clone()), source.into());

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

pub(crate) fn scan_directory_test(
    forge_test_proj: MockForgeProject<'_>,
) -> forge_analyzer::reporter::Report {
    let secret_packages: Vec<PackageData> = std::fs::File::open("../../secretdata.yaml")
        .map(|f| serde_yaml::from_reader(f).expect("Failed to deserialize packages"))
        .unwrap_or_else(|_| vec![]);

    let mut args = Args::parse();
    args.check_permissions = true;

    match scan_directory(PathBuf::new(), &mut args, forge_test_proj, &secret_packages) {
        Ok(report) => report,
        Err(err) => panic!("error while scanning {err:?}"),
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
#[ignore] // TODO: we've identified Rovo functions as user invokable but not yet if any vulnerabilities exist, remove this line when implemented
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
        
        // manifest.yaml 
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
