mod tests {
    use crate::{scan_directory_test, MockForgeProject};
    use forge_loader::manifest::{ForgeManifest, FunctionMod};
    use std::collections::HashMap;

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
            "index.tsx".to_string(),
            "import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
            function App() { console.log('test') } \n
            export const run = render(<Macro app={<App />} />);"
                .to_string(),
        );

        let scan_result = scan_directory_test(test_forge_project);
        println!("printing from test");
        assert!(scan_result.is_some_and(|vec| vec.is_empty()));
    }
}
