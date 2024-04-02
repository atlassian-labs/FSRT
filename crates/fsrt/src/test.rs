mod tests {
    use crate::{scan_directory_test, MockForgeProject};

    #[test]
    fn test_simple() {
        let test_forge_project = MockForgeProject {
            name: "index.tsx".to_string(),
            source: "import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
            function App() { console.log('test') } \n
            export const run = render(<Macro app={<App />} />);"
                .to_string(),
        };
        let scan_result = scan_directory_test(vec![test_forge_project]);
        assert!(scan_result.is_some_and(|vec| vec.len() == 0));
    }
}
