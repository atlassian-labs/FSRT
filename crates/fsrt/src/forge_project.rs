use crate::imports::collect_imported_files_outside_src;
use crate::{ResolvedEntryPoint, collect_sourcefiles};
use forge_analyzer::ctx::AppCtx;
use forge_analyzer::definitions::{Environment, PackageData, run_resolver};
use forge_loader::manifest::{BindingKind, Entrypoint, ForgeManifest, Resolved};
use forge_permission_resolver::permissions_resolver::PermMap;
use serde_yaml::Error as YamlError;
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use swc_core::common::{GLOBALS, Globals, Mark, SourceFile, SourceMap};
use swc_core::ecma::ast::EsVersion;
use swc_core::ecma::parser::{Syntax, TsSyntax, parse_file_as_module};
use swc_core::ecma::transforms::base::resolver;
use swc_core::ecma::visit::VisitMutWith;
use tracing::{debug, warn};

pub(crate) fn find_manifest_path(app_dir: &Path) -> io::Result<PathBuf> {
    ["manifest.yaml", "manifest.yml"]
        .into_iter()
        .map(|name| app_dir.join(name))
        .find(|path| path.exists())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "Could not find manifest.yml or manifest.yaml in {}",
                    app_dir.display()
                ),
            )
        })
}

/// Names under `dependencies`, `devDependencies`, `peerDependencies` and `optionalDependencies`
/// of `<app_dir>/package.json`; `None` when there is no readable `package.json`.
fn declared_packages(app_dir: &Path) -> Option<HashSet<String>> {
    let package_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(app_dir.join("package.json")).ok()?).ok()?;
    Some(
        [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ]
        .into_iter()
        .filter_map(|section| package_json.get(section)?.as_object())
        .flat_map(|section| section.keys().cloned())
        .collect(),
    )
}

pub(crate) trait ForgeProjectTrait<'a> {
    fn load_file(&self, path: impl AsRef<Path>, _: Arc<SourceMap>) -> io::Result<Arc<SourceFile>>;

    #[inline]
    fn with_files_and_sourceroot<
        P: AsRef<Path>,
        I: IntoIterator<Item = PathBuf> + std::fmt::Debug,
    >(
        &self,
        src: P,
        iter: I,
        // Files for which a read or parse failure only skips the file instead of the scan.
        is_best_effort: impl Fn(&Path) -> bool,
        secret_packages: &[PackageData],
        perm_map: &mut PermMap,
        suspicious_remotes: &HashSet<String>,
    ) -> crate::Result<ForgeProject<'_>> {
        let sm = Arc::<SourceMap>::default();
        let target = EsVersion::latest();
        let globals = Globals::new();
        let mut ctx = AppCtx::new(src);
        if let Some(packages) = self.get_declared_packages() {
            ctx.set_declared_packages(packages);
        }
        let ctx = iter.into_iter().try_fold(ctx, |mut ctx, p| {
            let sourcemap = Arc::clone(&sm);
            GLOBALS.set(&globals, || -> crate::Result<_> {
                debug!(file = %p.display(), "parsing");
                let parsed = (|| -> io::Result<_> {
                    let src = self.load_file(p.clone(), sourcemap)?;
                    debug!("loaded sourcemap");
                    let mut recovered_errors = vec![];
                    let mut module = parse_file_as_module(
                        src.as_ref(),
                        Syntax::Typescript(TsSyntax {
                            tsx: p.extension().and_then(|extension| extension.to_str())
                                != Some("ts"),
                            decorators: true,
                            ..Default::default()
                        }),
                        target,
                        None,
                        &mut recovered_errors,
                    )
                    .map_err(|error| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Could not parse {}: {error:?}", p.display()),
                        )
                    })?;
                    debug!("finished parsing");
                    let mut hygeine = resolver(Mark::new(), Mark::new(), true);
                    module.visit_mut_with(&mut hygeine);
                    Ok(module)
                })();
                match parsed {
                    Ok(module) => {
                        ctx.load_module(p, module);
                    }
                    Err(error) if is_best_effort(&p) => {
                        warn!("skipping {}: {error}", p.display());
                    }
                    Err(error) => return Err(error.into()),
                }
                Ok(ctx)
            })
        })?;
        let keys = ctx.module_ids().collect::<Vec<_>>();
        debug!(?keys);
        let env = run_resolver(
            ctx.modules(),
            ctx.file_resolver(),
            secret_packages,
            perm_map,
            suspicious_remotes,
        );
        Ok(ForgeProject {
            sm,
            ctx,
            env,
            funcs: vec![],
        })
    }

    fn get_paths(&self) -> HashSet<PathBuf>;

    /// Packages the app declares in its `package.json`, or `None` when it has none.
    fn get_declared_packages(&self) -> Option<HashSet<String>> {
        None
    }

    #[allow(dead_code)]
    fn get_secret_packages(&self) -> Vec<PackageData>;

    fn get_manifest(&self) -> Result<ForgeManifest<'_>, YamlError>;
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
            let function_key = entrypoint.function.key();
            let (func_name, path) = entrypoint.function.into_func_path();
            let module = self.ctx.modid_from_path(&path)?;
            let def_id = self.env.module_export(module, func_name)?;
            // Resolve ExportAlias / ResolverHandler chains to the actual definition.
            let def_id = self.env.resolve_alias(def_id);
            Some(ResolvedEntryPoint {
                function_key,
                handler: entrypoint.handler,
                module_bindings: entrypoint.module_bindings,
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

#[derive(Debug)]
pub(crate) struct ForgeProjectFromDir {
    pub dir: PathBuf,
    pub manifest_file_content: String,
}

impl ForgeProjectTrait<'_> for ForgeProjectFromDir {
    fn load_file(
        &self,
        path: impl AsRef<Path>,
        sourcemap: Arc<SourceMap>,
    ) -> io::Result<Arc<SourceFile>> {
        sourcemap.load_file(path.as_ref())
    }

    fn get_paths(&self) -> HashSet<PathBuf> {
        // Entrypoints stay under `src/`. Code outside it is read only when something read imports it.
        let src_files = collect_sourcefiles(&self.dir, &self.dir.join("src/")).collect::<Vec<_>>();
        let imported = collect_imported_files_outside_src(
            &self.dir,
            &src_files,
            &declared_packages(&self.dir).unwrap_or_default(),
        );
        src_files.into_iter().chain(imported).collect()
    }

    fn get_declared_packages(&self) -> Option<HashSet<String>> {
        declared_packages(&self.dir)
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

    fn get_manifest(&self) -> Result<ForgeManifest<'_>, YamlError> {
        serde_yaml::from_str(&self.manifest_file_content)
    }
}

impl ResolvedEntryPoint<'_> {
    /// List only the registrations that selected this scanner.
    pub(crate) fn manifest_proof(&self, kind: BindingKind) -> String {
        let modules = self
            .module_bindings
            .iter()
            .filter(|binding| binding.kind == kind)
            .map(|binding| {
                // Keep accepting legacy declarations that omitted a key.
                let key = if binding.key.is_empty() {
                    "<missing key>"
                } else {
                    binding.key
                };
                format!("{}: {key} ({})", binding.module_type, binding.property)
            })
            .collect::<Vec<_>>()
            .join(", ");
        if modules.is_empty() {
            return String::new();
        }
        format!(
            "Modules: [{modules}]\nFunction: {}\nHandler: {}",
            self.function_key, self.handler
        )
    }
}
