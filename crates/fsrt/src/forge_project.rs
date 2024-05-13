use crate::{collect_sourcefiles, ResolvedEntryPoint};
use forge_analyzer::ctx::AppCtx;
use forge_analyzer::definitions::{run_resolver, Environment, PackageData};
use forge_loader::manifest::{Entrypoint, ForgeManifest, FunctionMod, Resolved};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swc_core::common::sync::Lrc;
use swc_core::common::{FileName, Globals, Mark, SourceFile, SourceMap, GLOBALS};
use swc_core::ecma::ast::EsVersion;
use swc_core::ecma::parser::{parse_file_as_module, Syntax, TsConfig};
use swc_core::ecma::transforms::base::resolver;
use swc_core::ecma::visit::FoldWith;
use tracing::debug;

pub(crate) trait ForgeProjectTrait<'a> {
    fn load_file(&self, path: impl AsRef<Path>, _: Arc<SourceMap>) -> Arc<SourceFile>;
    #[inline]
    fn with_files_and_sourceroot<
        P: AsRef<Path>,
        I: IntoIterator<Item = PathBuf> + std::fmt::Debug,
    >(
        &self,
        src: P,
        iter: I,
        secret_packages: Vec<PackageData>,
    ) -> ForgeProject<'_> {
        let sm = Arc::<SourceMap>::default();
        let target = EsVersion::latest();
        let globals = Globals::new();
        let ctx = AppCtx::new(src);
        let ctx = iter.into_iter().fold(ctx, |mut ctx, p| {
            let sourcemap = Arc::clone(&sm);
            GLOBALS.set(&globals, || {
                debug!(file = %p.display(), "parsing");
                let src = self.load_file(p.clone(), sourcemap);
                debug!("loaded sourcemap");
                let mut recovered_errors = vec![];
                let module = parse_file_as_module(
                    &src,
                    Syntax::Typescript(TsConfig {
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
                let mut hygeine = resolver(Mark::new(), Mark::new(), true);
                let module = module.fold_with(&mut hygeine);
                ctx.load_module(p, module);
                ctx
            })
        });
        let keys = ctx.module_ids().collect::<Vec<_>>();
        debug!(?keys);
        let env = run_resolver(ctx.modules(), ctx.file_resolver(), secret_packages);
        ForgeProject {
            sm,
            ctx,
            env,
            funcs: vec![],
        }
    }

    fn get_paths(&self) -> HashSet<PathBuf>;

    fn get_secret_packages(&self) -> Vec<PackageData>;

    fn get_manifest(&self) -> ForgeManifest<'_>;
}
pub(crate) struct ForgeProject<'a> {
    #[allow(dead_code)]
    pub sm: Arc<SourceMap>,
    pub ctx: AppCtx,
    pub env: Environment,
    pub funcs: Vec<ResolvedEntryPoint<'a>>,
}

impl<'a> ForgeProject<'a> {
    #[inline]
    pub fn add_funcs<I: IntoIterator<Item = Entrypoint<'a, Resolved>>>(&mut self, iter: I) {
        self.funcs.extend(iter.into_iter().filter_map(|entrypoint| {
            let (func_name, path) = entrypoint.function.into_func_path();
            let module = self.ctx.modid_from_path(&path)?;
            let def_id = self.env.module_export(module, func_name)?;
            Some(ResolvedEntryPoint {
                func_name,
                path,
                module,
                def_id,
                invokable: entrypoint.invokable,
                webtrigger: entrypoint.web_trigger,
                admin: entrypoint.admin,
            })
        }));
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
        };

        let different_files = string
            .split("//")
            .map(|f| f.replace("//", "").trim().to_string())
            .filter(|file| !file.is_empty());
        for file in different_files {
            let (file_name, file_source) = file.split_once('\n').unwrap();
            mock_forge_project
                .files_name_to_source
                .insert(PathBuf::from(file_name.trim()), file_source.to_string());
        }

        mock_forge_project
    }
}

#[derive(Debug)]
pub(crate) struct ForgeProjectFromDir {
    #[allow(dead_code)]
    pub dir: PathBuf,
    pub manifest_file_content: String,
}

#[derive(Debug, Clone)]
pub(crate) struct MockForgeProject<'a> {
    pub files_name_to_source: HashMap<PathBuf, String>,
    pub test_manifest: ForgeManifest<'a>,
}

impl<'a> ForgeProjectTrait<'a> for ForgeProjectFromDir {
    fn load_file(&self, path: impl AsRef<Path>, sourcemap: Arc<SourceMap>) -> Arc<SourceFile> {
        sourcemap.load_file(path.as_ref()).unwrap()
    }

    fn get_paths(&self) -> HashSet<PathBuf> {
        collect_sourcefiles(self.dir.join("src/")).collect::<HashSet<_>>()
    }

    fn get_secret_packages(&self) -> Vec<PackageData> {
        if let Ok(f) = std::fs::File::open("secretdata.yaml") {
            let scrape_config: Vec<PackageData> =
                serde_yaml::from_reader(f).expect("Failed to deserialize package");
            scrape_config
        } else {
            vec![]
        }
    }

    fn get_manifest(&self) -> ForgeManifest<'_> {
        let out = serde_yaml::from_str(&self.manifest_file_content);
        out.unwrap_or_default()
    }
}

impl<'a> ForgeProjectTrait<'a> for MockForgeProject<'a> {
    fn load_file(&self, p: impl AsRef<Path>, _: Arc<SourceMap>) -> Arc<SourceFile> {
        let cm: Lrc<SourceMap> = Default::default();
        let file_name = p.as_ref();

        cm.new_source_file(
            FileName::Real(file_name.into()),
            self.files_name_to_source.get(file_name).unwrap().clone(),
        )
    }

    fn get_paths(&self) -> HashSet<PathBuf> {
        self.files_name_to_source
            .keys()
            .map(|file| file.into())
            .collect::<HashSet<_>>()
    }

    fn get_secret_packages(&self) -> Vec<PackageData> {
        vec![]
    }

    fn get_manifest(&self) -> ForgeManifest<'_> {
        self.test_manifest.clone()
    }
}
