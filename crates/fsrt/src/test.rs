use crate::{forge_project::ForgeProjectTrait, scan_directory, Args, Error};
use clap::Parser;
use forge_analyzer::{definitions::PackageData, reporter::Vulnerability};
use forge_loader::manifest::{ForgeManifest, FunctionMod};
use miette::Result;
use std::fmt;
use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};
use swc_core::common::source_map;
use swc_core::common::sync::Lrc;
use swc_core::{
    common::{FileName, SourceFile, SourceMap},
    ecma::visit::FoldWith,
};
use tracing::debug;

#[derive(Clone)]
pub(crate) struct MockForgeProject<'a> {
    pub files_name_to_source: HashMap<PathBuf, Arc<SourceFile>>,
    pub test_manifest: ForgeManifest<'a>,
    pub cm: Lrc<SourceMap>,
}

impl fmt::Debug for MockForgeProject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Mock Forge Project {:?}", self.files_name_to_source)
    }
}

#[allow(dead_code)]
impl MockForgeProject<'_> {
    pub fn files_from_string(string: String) -> Self {
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

    fn add_file(&mut self, p: impl AsRef<Path>, source: String) {
        let file_name = p.as_ref();

        let tx = self
            .cm
            .new_source_file(FileName::Real(file_name.into()), source);

        self.files_name_to_source
            .insert(file_name.to_path_buf(), tx);
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

    fn with_files_and_sourceroot<
        P: AsRef<Path>,
        I: IntoIterator<Item = PathBuf> + std::fmt::Debug,
    >(
        &self,
        src: P,
        iter: I,
        secret_packages: Vec<forge_analyzer::definitions::PackageData>,
    ) -> crate::forge_project::ForgeProject<'_> {
        let sm = std::sync::Arc::<swc_core::common::SourceMap>::default();
        let target = swc_core::ecma::ast::EsVersion::latest();
        let globals = swc_core::common::Globals::new();
        let ctx = forge_analyzer::ctx::AppCtx::new(src);
        let ctx = iter.into_iter().fold(ctx, |mut ctx, p| {
            let sourcemap = std::sync::Arc::clone(&sm);
            swc_core::common::GLOBALS.set(&globals, || {
                debug!(file = %p.display(), "parsing");
                let src = self.load_file(p.clone(), sourcemap);
                debug!("loaded sourcemap");
                let mut recovered_errors = vec![];
                let module = swc_core::ecma::parser::parse_file_as_module(
                    &src,
                    swc_core::ecma::parser::Syntax::Typescript(swc_core::ecma::parser::TsConfig {
                        tsx: true,
                        decorators: true,
                        ..Default::default()
                    }),
                    target,
                    None,
                    &mut recovered_errors,
                )
                .unwrap();
                debug!("finished parsing");
                let mut hygeine = swc_core::ecma::transforms::base::resolver(
                    swc_core::common::Mark::new(),
                    swc_core::common::Mark::new(),
                    true,
                );
                let module = module.fold_with(&mut hygeine);
                ctx.load_module(p, module);
                ctx
            })
        });
        let keys = ctx.module_ids().collect::<Vec<_>>();
        debug!(?keys);
        let env = forge_analyzer::definitions::run_resolver(
            ctx.modules(),
            ctx.file_resolver(),
            secret_packages,
        );
        crate::forge_project::ForgeProject {
            sm,
            ctx,
            env,
            funcs: vec![],
        }
    }
}

pub(crate) fn scan_directory_test(forge_test_proj: MockForgeProject<'_>) -> Vec<Vulnerability> {
    match scan_directory(PathBuf::new(), &Args::parse(), forge_test_proj) {
        Ok(report) => report.vulns,
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
        test_manifest: forge_manifest.clone(),
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
        test_manifest: forge_manifest.clone(),
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
            export default function test() { let test1 = 'test_one'; console.log('test_function') }"
                .to_string(),
        );

    let scan_result = scan_directory_test(test_forge_project);
    println!("scan_result {scan_result:?}");
    assert!(scan_result.is_empty());
}
