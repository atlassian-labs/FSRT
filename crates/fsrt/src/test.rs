use crate::forge_project::MockForgeProject;
use crate::scan_directory_test;
use forge_loader::manifest::{ForgeManifest, FunctionMod};
use std::collections::HashMap;

mod tests {
    use crate::{scan_directory_test, MockForgeProject};
    use forge_loader::manifest::{ForgeManifest, FunctionMod};
    use std::{collections::HashMap, path::PathBuf};

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
        };
        test_forge_project.files_name_to_source.insert(
            PathBuf::from("src/index.tsx"),
            "import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
            function App() { console.log('test') } \n
            export const run = render(<Macro app={<App />} />);"
                .to_string(),
        );

        let scan_result = scan_directory_test(test_forge_project);
        assert!(scan_result.is_some_and(|vec| vec.is_empty()));
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
        };
        test_forge_project.files_name_to_source.insert(
            PathBuf::from("src/index.tsx"),
            "import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui';
             import jwt from 'jsonwebtoken';
            function App() { console.log('test');
                jwt.sign({}, 'TEST');
             } \n
            export const run = render(<Macro app={<App />} />);"
                .to_string(),
        );

        let scan_result = scan_directory_test(test_forge_project);
        assert!(scan_result.is_some_and(|vec| vec.is_empty()));
    }

    #[test]
    fn with_multiple_files() {
        let mut test_forge_project = MockForgeProject::files_from_string(
            "// src/index.tsx
            import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
            import test_function from 'test_function'; \n
            function App() { let test = 'textx'; console.log('test') } \n
            export const run = render(<Macro app={<App />} />); 
            // src/test_function.tsx
            export default function test() { let test1 = 'test_one'; console.log('test_function') }"
                .to_string(),
        );

        let scan_result = scan_directory_test(test_forge_project);
        assert!(scan_result.is_some_and(|vec| vec.is_empty()));
    }
}
