use std::{fs, path::PathBuf};

use clap::{Args, ValueHint};
use serde_json::Value as JsonValue;

use crate::{Result, forge_project::find_manifest_path};

use super::parse_ctx;

const REDACTED_FCT: &str = "<FCT selected at runtime>";

/// `invoke-extension` arguments.
#[derive(Args, Debug)]
pub(crate) struct InvokeExtensionArgs {
    /// Deployed module key containing the resolver.
    #[arg(name = "MODULE_KEY")]
    module_key: String,

    /// Resolver function key to invoke.
    #[arg(name = "FUNCTION")]
    function: String,

    /// Invocation payload as JSON.
    #[arg(name = "PAYLOAD")]
    payload: String,

    /// Replace the default invocation context with this JSON object.
    #[arg(long, value_name = "JSON", value_parser = parse_ctx)]
    ctx: Option<JsonValue>,

    /// Reuse this FCT instead of minting one.
    #[arg(long)]
    fct: Option<String>,

    /// Invoke asynchronously when supported.
    #[arg(long = "async", default_value_t = false)]
    invoke_async: bool,

    /// Forge app directory.
    #[arg(long, default_value = ".", value_hint = ValueHint::DirPath)]
    app_dir: PathBuf,

    /// Path to `fsrt-remote.toml`.
    #[arg(long, default_value = "./fsrt-remote.toml", value_hint = ValueHint::FilePath)]
    config: PathBuf,

    /// Resolve metadata and print redacted variables without invoking.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

impl InvokeExtensionArgs {
    pub(super) fn diagnostic_logging_requested(&self) -> bool {
        self.dry_run
    }
}

pub(super) fn run(args: &InvokeExtensionArgs) -> Result<()> {
    let module_key = require_non_empty("MODULE_KEY", &args.module_key)?;
    let function = require_non_empty("FUNCTION", &args.function)?;
    if args.fct.as_deref().is_some_and(|fct| fct.trim().is_empty()) {
        return Err(forge_pen_test::MintError::EmptySuppliedFct.into());
    }
    let payload: JsonValue = serde_json::from_str(&args.payload).map_err(|error| {
        forge_pen_test::MintError::InvocationFailed(format!("PAYLOAD is not valid JSON: {error}"))
    })?;

    let manifest_path = find_manifest_path(&args.app_dir)?;
    let manifest_text = fs::read_to_string(manifest_path)?;
    let manifest: forge_loader::manifest::ForgeManifest<'_> = serde_yaml::from_str(&manifest_text)?;

    let config = forge_pen_test::FsrtRemoteConfig::from_path(&args.config)?;
    let tester = forge_pen_test::ForgePenTester::new(&manifest, config)?;
    let ctx = match &args.ctx {
        Some(ctx) => ctx.clone(),
        None => tester.default_invoke_context(module_key)?,
    };

    if args.dry_run {
        let request = tester.invoke_extension_request(
            module_key,
            function,
            &payload,
            &ctx,
            REDACTED_FCT,
            args.invoke_async,
        )?;
        println!("{}", serde_json::to_string_pretty(&request.variables)?);
        return Ok(());
    }

    let outcome = tester.invoke_extension(
        module_key,
        function,
        &payload,
        &ctx,
        args.fct.as_deref(),
        args.invoke_async,
    )?;
    match outcome.response() {
        Some(response) => println!("{}", serde_json::to_string_pretty(response)?),
        None => println!("null"),
    }

    Ok(())
}

fn require_non_empty<'a>(name: &str, value: &'a str) -> Result<&'a str> {
    let value = value.trim();
    if value.is_empty() {
        Err(forge_pen_test::MintError::InvocationFailed(format!("{name} must not be empty")).into())
    } else {
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, error::ErrorKind};

    use super::*;
    use crate::{Args as RootArgs, commands::Command};

    fn args(module_key: &str, function: &str, payload: &str) -> InvokeExtensionArgs {
        InvokeExtensionArgs {
            module_key: module_key.to_string(),
            function: function.to_string(),
            payload: payload.to_string(),
            ctx: None,
            fct: None,
            invoke_async: false,
            app_dir: PathBuf::from("unused"),
            config: PathBuf::from("unused"),
            dry_run: false,
        }
    }

    #[test]
    fn parses_required_positionals_and_ctx() {
        let parsed = RootArgs::try_parse_from([
            "fsrt",
            "invoke-extension",
            "module-key",
            "resolver-fn",
            r#"{"probe":true}"#,
            "--ctx",
            r#"{"issueKey":"TEST-1"}"#,
            "--async",
            "--dry-run",
        ])
        .unwrap();

        let Some(Command::InvokeExtension(args)) = parsed.command else {
            panic!("invoke-extension command was not parsed")
        };
        assert_eq!(args.module_key, "module-key");
        assert_eq!(args.function, "resolver-fn");
        assert_eq!(args.payload, r#"{"probe":true}"#);
        assert_eq!(args.ctx, Some(serde_json::json!({ "issueKey": "TEST-1" })));
        assert!(args.invoke_async);
        assert!(args.diagnostic_logging_requested());
    }

    #[test]
    fn requires_all_positional_arguments() {
        for argv in [
            vec!["fsrt", "invoke-extension"],
            vec!["fsrt", "invoke-extension", "module-key"],
            vec!["fsrt", "invoke-extension", "module-key", "resolver-fn"],
        ] {
            assert_eq!(
                RootArgs::try_parse_from(argv).unwrap_err().kind(),
                ErrorKind::MissingRequiredArgument
            );
        }
    }

    #[test]
    fn ctx_must_be_a_json_object_and_context_is_not_an_alias() {
        for ctx in ["not-json", "[]", "null"] {
            assert_eq!(
                RootArgs::try_parse_from([
                    "fsrt",
                    "invoke-extension",
                    "module-key",
                    "resolver-fn",
                    "{}",
                    "--ctx",
                    ctx,
                ])
                .unwrap_err()
                .kind(),
                ErrorKind::ValueValidation
            );
        }

        assert_eq!(
            RootArgs::try_parse_from([
                "fsrt",
                "invoke-extension",
                "module-key",
                "resolver-fn",
                "{}",
                "--context",
                "{}",
            ])
            .unwrap_err()
            .kind(),
            ErrorKind::UnknownArgument
        );
    }

    #[test]
    fn rejects_empty_values_and_invalid_payload_before_file_access() {
        for (args, expected) in [
            (
                args(" ", "resolver-fn", "{}"),
                "MODULE_KEY must not be empty",
            ),
            (args("module-key", " ", "{}"), "FUNCTION must not be empty"),
            (
                args("module-key", "resolver-fn", "not-json"),
                "PAYLOAD is not valid JSON",
            ),
        ] {
            let error = run(&args).unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }

        let mut empty_fct = args("module-key", "resolver-fn", "{}");
        empty_fct.fct = Some(" ".to_string());
        assert!(
            run(&empty_fct)
                .unwrap_err()
                .to_string()
                .contains("supplied FCT must not be empty")
        );
    }

    #[test]
    fn help_documents_the_positional_interface_and_ctx() {
        let mut command = RootArgs::command();
        let help = command
            .find_subcommand_mut("invoke-extension")
            .expect("invoke-extension subcommand should exist")
            .render_long_help()
            .to_string();

        assert!(help.contains("<MODULE_KEY> <FUNCTION> <PAYLOAD>"));
        assert!(help.contains("--ctx <JSON>"));
        assert!(!help.contains("--context"));
    }
}
