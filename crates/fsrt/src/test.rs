use crate::{forge_project::ForgeProjectTrait, scan_directory, Args};
use clap::Parser;
use forge_analyzer::{definitions::PackageData, reporter::Vulnerability};
use forge_loader::manifest::{ForgeManifest, FunctionMod};
use std::fmt;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use swc_core::common::sync::Lrc;
use swc_core::{
    common::{FileName, SourceFile, SourceMap},
};

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
impl MockForgeProject<'_> {
    pub fn files_from_string(string: &str) -> Self {
        let forge_manifest = ForgeManifest::create_manifest_with_func_mod(FunctionMod {
            key: "main",
            handler: "index.run",
            providers: None,
        });

        let mut mock_forge_project = MockForgeProject {
            files_name_to_source: HashMap::new(),
            test_manifest: forge_manifest,
            cm: Arc::default(),
        };

        let different_files = string
            .split("//")
            .map(|f| f.replace("//", "").trim().to_string())
            .filter(|file| !file.is_empty());
        for file in different_files {
            let (file_name, file_source) = file.split_once('\n').unwrap();
            mock_forge_project.add_file(file_name.trim(), file_source.into());
        }

        mock_forge_project
    }

    fn add_file(&mut self, p: impl Into<PathBuf>, source: String) {
        let file_name = p.into();
        let source_file = self
            .cm
            .new_source_file(FileName::Real(file_name.clone()), source);

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

pub(crate) fn scan_directory_test(forge_test_proj: MockForgeProject<'_>) -> Vec<Vulnerability> {
    match scan_directory(PathBuf::new(), &Args::parse(), forge_test_proj) {
        Ok(report) => report.into_vulns().clone(),
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
        PathBuf::from("src/index.tsx"),
        "import ForgeUI, { render, Fragment, Macro, Text } from '@forge/ui'; \n
            function App() { console.log('test') } \n
            export const run = render(<Macro app={<App />} />);"
            .to_string(),
    );

    let scan_result = scan_directory_test(test_forge_project);
    assert!(scan_result.is_empty());
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
    assert!(scan_result.is_empty());
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
    println!("scan_result {scan_result:?}");
    assert!(scan_result.is_empty());
}
