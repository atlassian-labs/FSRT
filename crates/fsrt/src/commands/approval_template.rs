use std::{
    collections::BTreeSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use clap::{Args, Parser, ValueEnum, ValueHint};
use forge_analyzer::definitions::PackageData;
use forge_approval_template::{ApprovalTemplate, Checker, CodeAnalysis, ManifestFacts};

use crate::Result;
use crate::forge_project::{ForgeProjectFromDir, find_manifest_path};
use crate::scan_directory;

/// `approval-template` arguments.
#[derive(Args, Debug)]
pub(crate) struct ApprovalTemplateArgs {
    /// Forge app directory. Defaults to the current directory.
    #[arg(name = "APP_DIR", value_hint = ValueHint::DirPath, default_value = ".")]
    app_dir: PathBuf,

    /// Output format.
    #[arg(long, value_enum, default_value_t = Format::Markdown)]
    format: Format,

    /// Write to this file instead of standard output.
    #[arg(long, short, value_name = "PATH", value_hint = ValueHint::FilePath)]
    out: Option<PathBuf>,

    /// Exit non-zero when a check would block listing.
    ///
    /// Intended for CI, so a partner's pipeline fails before submission rather
    /// than after review.
    #[arg(long)]
    fail_on_blocking: bool,

    /// Also scan the app's source, and use the findings to answer the
    /// questionnaire questions the manifest cannot.
    ///
    /// Slower, and may need network access to build the permission maps.
    #[arg(long)]
    with_code_analysis: bool,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, ValueEnum)]
enum Format {
    /// Human-readable summary.
    Markdown,
    /// Canonical machine-readable form.
    Json,
    /// Machine-readable form, matching the manifest's own syntax.
    Yaml,
}

impl ApprovalTemplateArgs {
    pub(crate) fn diagnostic_logging_requested(&self) -> bool {
        false
    }
}

pub(crate) fn run(args: &ApprovalTemplateArgs) -> Result<()> {
    let manifest_path = find_manifest_path(&args.app_dir)?;
    let manifest = fs::read_to_string(&manifest_path)?;
    let facts = ManifestFacts::from_yaml(&manifest)?;

    let code = args
        .with_code_analysis
        .then(|| scan(&args.app_dir, &manifest, &facts))
        .transpose()?;

    let template = ApprovalTemplate::build(&facts, code, manifest_path.display().to_string());

    let rendered = match args.format {
        Format::Markdown => forge_approval_template::to_markdown(&template),
        Format::Json => serde_json::to_string_pretty(&template)?,
        Format::Yaml => serde_yaml::to_string(&template)?,
    };

    match &args.out {
        Some(path) => {
            fs::write(path, rendered)?;
            println!("Wrote {} to {}", args.format.describe(), path.display());
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(rendered.as_bytes())?;
            stdout.flush()?;
        }
    }

    let blocking = template.blocking_flags().count();
    if blocking > 0 {
        eprintln!("\n{blocking} check(s) would block listing. Resolve them before submitting.");
        if args.fail_on_blocking {
            return Err(format!("{blocking} blocking check(s) found").into());
        }
    }

    Ok(())
}

/// Scan the app's source and translate FSRT's findings into the shape the
/// approval template consumes.
///
/// # On `checkers_run`
///
/// A clean result only means something for a checker that actually ran, but
/// `scan_directory` does not report which ones did: `AuthZChecker` runs only over
/// invokable functions and `AuthenticateChecker` only over web triggers, both
/// resolved inside the scan. So the set below is inferred from the manifest, and
/// deliberately conservative:
///
/// - The secret and auth-header checkers run over every function, so they are
///   always included.
/// - The authentication checker is included only when the manifest declares a web
///   trigger, and the authorization checker only when the manifest declares a
///   module that can be invoked. Those are the same conditions under which the
///   corresponding questions are asked at all.
/// - The permission checker is never included. It is gated at runtime on a
///   GraphQL schema being available and on the app not using remote auth tokens,
///   neither of which is observable here. Its findings are still honoured, since
///   a finding proves the checker ran.
///
/// Removing this inference means teaching `scan_directory` to report the checkers
/// it ran, which is a change to a file another branch is currently editing. Worth
/// doing once that lands.
fn scan(app_dir: &Path, manifest: &str, facts: &ManifestFacts) -> Result<CodeAnalysis> {
    let secretdata = include_str!("../../../../secretdata.yaml");
    let secret_packages: Vec<PackageData> = serde_yaml::from_str(secretdata)?;

    // `scan_directory` takes the top-level CLI arguments. Build a default set for
    // this directory rather than plumbing the real ones through `Command::run`.
    let mut scan_args = crate::Args::parse_from(["fsrt", &app_dir.display().to_string()]);

    let project = ForgeProjectFromDir {
        dir: app_dir.to_path_buf(),
        manifest_file_content: manifest.to_owned(),
    };

    let report = scan_directory(
        app_dir.to_path_buf(),
        &mut scan_args,
        project,
        &secret_packages,
    )?;

    if report.has_errors() {
        return Err(format!("could not scan app source: {}", report.error_message()).into());
    }

    let mut checkers_run = BTreeSet::from([Checker::HardcodedSecret, Checker::AtlassianCredential]);
    if !facts.webtriggers.is_empty() {
        checkers_run.insert(Checker::Authentication);
    }
    if !facts.user_facing_module_types.is_empty() {
        checkers_run.insert(Checker::Authorization);
    }

    Ok(CodeAnalysis::from_findings(
        checkers_run,
        report
            .into_vulns()
            .iter()
            .map(|vuln| (vuln.check_name(), vuln.description())),
    ))
}

impl Format {
    fn describe(self) -> &'static str {
        match self {
            Self::Markdown => "Markdown summary",
            Self::Json => "JSON template",
            Self::Yaml => "YAML template",
        }
    }
}
