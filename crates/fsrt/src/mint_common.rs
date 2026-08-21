//! Shared types and functions used by both `mint_fct` and `mint_fit`.
//!
//! This module contains:
//!   - Config structs (deserialised from the `fsrt-remote.toml` config file)
//!   - Auth header construction
//!   - GraphQL HTTP POST via `ureq`
//!   - Template rendering
//!   - The core `mint_fct_jwt()` function, which both subcommands call

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64_URL},
};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use forge_loader::manifest::ForgeManifest;
use tracing::{info, warn};

// The default FCT mutation for Confluence apps.
pub const DEFAULT_CONFLUENCE_MUTATION: &str = r#"mutation useGetContextTokenMutation($cloudId: ID!, $input: ConfluenceForgeContextTokenRequestInput!) {
  confluence_generateForgeContextToken(cloudId: $cloudId, input: $input) {
    success
    errors {
      message
      __typename
    }
    forgeContextToken {
      jwt
      expiresAt
      extensionId
      __typename
    }
    __typename
  }
}"#;

pub const CONFLUENCE_OPERATION_NAME: &str = "useGetContextTokenMutation";

// The default FCT mutation for global apps (Jira, Compass, Rovo, etc.).
// Calls globalApp_signForgeContextTokens on XIS (Xen Invocation Service).
// NOTE: Response returns a list of tokens (one per extensionContext entry).
pub const DEFAULT_GLOBAL_APP_MUTATION: &str = r#"mutation SignForgeContextToken($input: GlobalAppSignForgeContextTokensInput!) {
  globalApp_signForgeContextTokens(input: $input) {
    success
    errors {
      message
      __typename
    }
    tokens {
      jwt
      expiresAt
      extensionId
      __typename
    }
    __typename
  }
}"#;

pub const GLOBAL_APP_OPERATION_NAME: &str = "SignForgeContextToken";

// Error types
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("{0}")]
    Config(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("config error: {0}")]
    ConfigCrate(#[from] config::ConfigError),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    // Returned when the FCT mint succeeds at the HTTP level but the server
    // reports a logical failure (e.g. bad cloud_id, bad installation_id).
    #[error("FCT minting failed: {0}")]
    FctFailed(String),

    // Returned when the FIT mint reaches the server but no invocation token is
    // returned (GraphQL errors, or a missing token in the response).
    #[error("{0}")]
    FitFailed(String),

    // Returned when the configured session cookie's JWT `exp` is in the past.
    #[error("{0}")]
    CookieExpired(String),
}

// Convenience alias — write `Result<T>` instead of `Result<T, MintError>`.
pub type Result<T> = std::result::Result<T, MintError>;

// Config structs, deserialised from the `fsrt-remote.toml` config file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Product {
    Confluence,
    Global,
}

impl std::fmt::Display for Product {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Product::Confluence => write!(f, "confluence"),
            Product::Global => write!(f, "global"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MintFctConfig {
    // Required: which Atlassian product to mint the token for.
    pub product: Product,

    // The Atlassian GraphQL gateway URL.
    pub graphql_endpoint: String,

    // Optional: override the default FCT GraphQL mutation.
    pub mutation: Option<String>,

    // Auth credentials — how to authenticate the HTTP request.
    pub auth: AuthConfig,

    // Confluence-specific IDs (cloud_id, installation_id, environment_id, etc.)
    // Required when product: confluence.
    pub confluence: Option<ConfluenceConfig>,

    // Global app IDs (installation_id, environment_id, etc.)
    // Required when product: global.
    pub global: Option<GlobalAppConfig>,

    // The GraphQL variables template — an arbitrary object containing
    // `${...}` placeholders that get substituted at runtime.
    pub variables: Option<JsonValue>,
}

// `auth` section of the config, either session cookie or API token
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    // Config key is `type`, renamed
    #[serde(rename = "type", default = "default_auth_type")]
    pub auth_type: String,

    // The full Cookie header value, either inline or from a file.
    pub raw_cookie: Option<String>,
    pub raw_cookie_file: Option<String>,

    pub email: Option<String>,
    // API token is a secret — read from inline value or a file.
    pub api_token: Option<String>,
    pub api_token_file: Option<String>,
}

fn default_auth_type() -> String {
    "raw_cookie".to_string()
}

// The `confluence:` section of the config.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ConfluenceConfig {
    pub cloud_id: Option<String>,
    pub account_id: Option<String>,
    pub content_id: Option<String>,
    pub space_key: Option<String>,
    pub space_id: Option<String>,
    pub installation_id: Option<String>,
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    pub local_id: Option<String>,
    pub module_key: Option<String>,
    // Declared remote a FIT should target, defaults to first remote in manifest.
    pub remote_key: Option<String>,
    pub site_url: Option<String>,
    // Named Forge environment slot; used to look up environment_id when it
    // isn't supplied explicitly. Defaults to DEFAULT_ENVIRONMENT_KEY.
    pub environment_key: Option<String>,
}

// The `global:` section of the config.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GlobalAppConfig {
    pub cloud_id: Option<String>,
    pub installation_id: Option<String>,
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    pub module_key: Option<String>,
    // Declared remote a FIT should target, defaults to first remote in manifest.
    pub remote_key: Option<String>,
    // Named Forge environment slot; used to look up environment_id when it
    // isn't supplied explicitly. Defaults to DEFAULT_ENVIRONMENT_KEY.
    pub environment_key: Option<String>,
}

// Manifest context
#[derive(Debug, Clone)]
pub struct ManifestContext {
    // Full ARI: "ari:cloud:ecosystem::app/8bdd65d0-..."
    pub app_id: String,
    // Bare UUID after the last "/": "8bdd65d0-..."
    pub app_id_bare: String,
    pub app_name: Option<String>,
    pub module_key: Option<String>,
    pub module_type: Option<String>,
    // Resolved from the Forge platform via fetch_app_environment().
    pub environment_id: Option<String>,
    pub app_version: Option<String>,
}

// Reads a parsed ForgeManifest and returns a ManifestContext.
//
// `module_key` is an optional override from config; when absent, the first
// FCT-capable module in the manifest is auto-detected.
pub fn extract_manifest_context(
    manifest: &ForgeManifest<'_>,
    module_key: Option<&str>,
) -> ManifestContext {
    let app_id = manifest.app.id.to_string();

    // Strip the ARI prefix to get the bare UUID.
    let app_id_bare = app_id.rsplit('/').next().unwrap_or(&app_id).to_string();

    let app_name = manifest.app.name.map(|s| s.to_string());

    let (detected_key, detected_type) = match module_key {
        // Explicit override from config.
        Some(key) => (
            Some(key.to_string()),
            manifest
                .modules
                .fct_module_type_for_key(key)
                .map(|t| t.to_string()),
        ),
        // No override — auto-detect the first FCT-capable module.
        None => match manifest.modules.detect_fct_module() {
            Some((key, module_type)) => (Some(key.to_string()), Some(module_type.to_string())),
            None => (None, None),
        },
    };

    ManifestContext {
        app_id,
        app_id_bare,
        app_name,
        module_key: detected_key,
        module_type: detected_type,
        environment_id: None,
        app_version: None,
    }
}

// Walks the raw YAML manifest to find the `key` of the first declared remote.
pub fn detect_remote_key(
    manifest: &ForgeManifest<'_>,
    override_key: Option<&str>,
) -> Option<String> {
    // Config override takes priority.
    if let Some(key) = override_key
        && !key.is_empty()
    {
        return Some(key.to_string());
    }

    // Otherwise take the key of the first declared remote from the typed
    // manifest.
    manifest
        .remotes
        .as_ref()?
        .first()
        .map(|remote| remote.key.clone())
        .filter(|key| !key.is_empty())
}

// Reads a secret from inline value or file path (will be changed later)
pub fn load_secret_from_config(
    inline: Option<&str>,
    file_path: Option<&str>,
) -> Result<Option<String>> {
    // Inline value takes highest priority.
    if let Some(v) = inline
        && !v.is_empty()
    {
        return Ok(Some(v.to_string()));
    }

    // Read from a file.
    if let Some(path) = file_path
        && !path.is_empty()
    {
        let contents = fs::read_to_string(path).map_err(|e| {
            MintError::Config(format!("Could not read secret file '{}': {}", path, e))
        })?;
        return Ok(Some(contents.trim().to_string()));
    }

    Ok(None)
}

// Reads the `auth:` section of the config and returns the HTTP headers needed
// to authenticate the request. Returns a HashMap<header_name, header_value>.
pub fn build_auth_headers(auth: &AuthConfig) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();

    info!("building auth headers from config — this uses sensitive credentials");

    match auth.auth_type.as_str() {
        "raw_cookie" => {
            let raw = load_secret_from_config(
                auth.raw_cookie.as_deref(),
                auth.raw_cookie_file.as_deref(),
            )?
            .ok_or_else(|| {
                MintError::Config(
                    "auth.type=raw_cookie requires `raw_cookie` (inline) or `raw_cookie_file`"
                        .into(),
                )
            })?;

            info!(bytes = raw.len(), "loaded session cookie");

            // Check the session token's `exp` claim locally for expiry
            if let Some(secs_ago) = cookie_expired_secs_ago(&raw) {
                return Err(MintError::CookieExpired(format!(
                    "Session cookie EXPIRED {} ago. Renew it (e.g. re-copy the \
                     Cookie header from your browser/Burp into `raw_cookie` or \
                     the file referenced by `raw_cookie_file`), then retry.",
                    format_duration(secs_ago),
                )));
            }
            check_cookie_expiry(&raw);

            headers.insert("Cookie".to_string(), raw.trim().to_string());
        }

        // basic_api_token: Atlassian API token encoded as HTTP Basic auth.
        "basic_api_token" => {
            let email = auth
                .email
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    MintError::Config(
                        "auth.type=basic_api_token requires `email` in the config".into(),
                    )
                })?;

            let token =
                load_secret_from_config(auth.api_token.as_deref(), auth.api_token_file.as_deref())?
                    .ok_or_else(|| {
                        MintError::Config(
                    "auth.type=basic_api_token requires `api_token` (inline) or `api_token_file`"
                        .into(),
                )
                    })?;

            let credentials = format!("{}:{}", email.trim(), token.trim());
            let encoded = B64.encode(credentials.as_bytes());

            info!(email = %email.trim(), "using basic API token auth");
            headers.insert("Authorization".to_string(), format!("Basic {}", encoded));
        }

        other => {
            return Err(MintError::Config(format!(
                "Unsupported auth.type: '{}'. Valid types: raw_cookie, basic_api_token",
                other
            )));
        }
    }

    Ok(headers)
}

// Session-cookie expiry checking
const SESSION_COOKIE_NAME: &str = "tenant.session.token";

fn extract_session_token(raw_cookie: &str) -> Option<&str> {
    for pair in raw_cookie.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(value);
        }
    }
    let trimmed = raw_cookie.trim();
    if !trimmed.contains('=') && trimmed.split('.').count() == 3 {
        return Some(trimmed);
    }
    None
}

// Decode a JWT's `exp` (expiry) claim
fn decode_jwt_exp(token: &str) -> Option<i64> {
    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = B64_URL.decode(payload_b64).ok()?;
    let payload: JsonValue = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp")?.as_i64()
}

fn format_duration(seconds: i64) -> String {
    let seconds = seconds.abs();
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

// Definitive expiry check used to hard-fail before sending a stale cookie.
fn cookie_expired_secs_ago(raw_cookie: &str) -> Option<i64> {
    let token = extract_session_token(raw_cookie)?;
    let exp = decode_jwt_exp(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (exp <= now).then_some(now - exp)
}

// Inspect the raw cookie's session token and print its expiry status.
pub fn check_cookie_expiry(raw_cookie: &str) -> bool {
    let Some(token) = extract_session_token(raw_cookie) else {
        warn!(
            cookie_name = SESSION_COOKIE_NAME,
            "could not find session cookie — cannot check expiry"
        );
        return false;
    };

    let Some(exp) = decode_jwt_exp(token) else {
        warn!(
            cookie_name = SESSION_COOKIE_NAME,
            "could not read an `exp` claim (not a JWT?) — cannot check expiry"
        );
        return false;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if exp <= now {
        warn!(
            expired_ago = %format_duration(now - exp),
            exp,
            "session cookie EXPIRED — renew it before minting"
        );
        false
    } else {
        info!(
            expires_in = %format_duration(exp - now),
            exp,
            "session cookie valid"
        );
        true
    }
}

// Walks a JSON value tree and replaces every "${dotted.path}" placeholder
// with the value found at that path in the template context.
pub fn render_template(value: &JsonValue, context: &JsonValue) -> JsonValue {
    match value {
        JsonValue::Object(map) => {
            let rendered = map
                .iter()
                .map(|(k, v)| (k.clone(), render_template(v, context)))
                .collect();
            JsonValue::Object(rendered)
        }
        JsonValue::Array(arr) => {
            JsonValue::Array(arr.iter().map(|v| render_template(v, context)).collect())
        }
        JsonValue::String(s) => render_string(s, context),
        other => other.clone(),
    }
}

fn render_string(s: &str, context: &JsonValue) -> JsonValue {
    let re = Regex::new(r"\$\{([^}]+)\}").unwrap();

    // If the entire string is a single placeholder, return the resolved value
    // preserving its original type (number, boolean, etc.)
    if let Some(caps) = re.captures(s)
        && caps[0] == *s
    {
        let path = &caps[1];
        return get_path(context, path).cloned().unwrap_or(JsonValue::Null);
    }

    // Otherwise replace each placeholder with its string representation.
    let result = re.replace_all(s, |caps: &regex::Captures<'_>| {
        let path = &caps[1];
        match get_path(context, path) {
            Some(JsonValue::String(v)) => v.clone(),
            Some(JsonValue::Null) | None => String::new(),
            Some(v) => v.to_string(),
        }
    });

    JsonValue::String(result.into_owned())
}

// Walks a JsonValue by a dotted path string.
pub fn get_path<'a>(context: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut cur = context;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

// Sends a GraphQL POST request to the Atlassian gateway and returns
// (http_status_code, response_body_text) using ureq.
pub fn post_graphql(
    endpoint: &str,
    operation_name: &str,
    auth_headers: &HashMap<String, String>,
    query: &str,
    variables: &JsonValue,
) -> Result<(u16, String)> {
    // Extract origin from the endpoint URL for CSRF headers.
    let origin = endpoint.split('/').take(3).collect::<Vec<_>>().join("/");

    let url = format!("{}?q={}", endpoint, operation_name);

    let body = serde_json::json!({
        "operationName": operation_name,
        "query": query,
        "variables": variables,
    });

    // Build the ureq POST request.
    let mut request = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set("Accept", "application/json")
        .set("Origin", &origin)
        .set("Referer", &format!("{}/", origin))
        .set("X-Experimentalapi", "confluence-agg-beta")
        .set("X-Apollo-Operation-Name", operation_name)
        .set(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
             AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
        );

    for (name, value) in auth_headers {
        request = request.set(name, value);
    }

    match request.send_json(&body) {
        Ok(response) => {
            let status = response.status();
            let text = response
                .into_string()
                .map_err(|e| MintError::Http(e.to_string()))?;
            Ok((status, text))
        }
        Err(ureq::Error::Status(code, response)) => {
            let text = response
                .into_string()
                .unwrap_or_else(|_| "<unreadable response body>".to_string());
            Ok((code, text))
        }
        Err(e) => Err(MintError::Http(e.to_string())),
    }
}

// Loads and deserialises the `fsrt-remote.toml` config file into a
// `MintFctConfig` using the `config` crate (config-rs).
pub fn load_config(config_path: &std::path::Path) -> Result<MintFctConfig> {
    if !config_path.exists() {
        return Err(MintError::Config(format!(
            "Config file not found: {}",
            config_path.display()
        )));
    }

    let settings = config::Config::builder()
        .add_source(config::File::from(config_path))
        .build()?;

    let cfg: MintFctConfig = settings.try_deserialize()?;
    Ok(cfg)
}

// Resolve app's environmentId and versionId
pub const DEFAULT_ENVIRONMENT_KEY: &str = "default";

pub const APP_ENVIRONMENT_QUERY: &str = r#"query GetAppEnvironment($appId: ID!, $envKey: String!) {
  app(id: $appId) {
    id
    name
    environmentByKey(key: $envKey) {
      id
      key
      type
      versions {
        nodes { version isLatest }
      }
    }
  }
}"#;
pub const APP_ENVIRONMENT_OPERATION_NAME: &str = "GetAppEnvironment";

// Result of the environment lookup.
#[derive(Debug, Clone)]
pub struct AppEnvironment {
    pub environment_id: String,
    pub app_version: Option<String>,
}

// Performs the GraphQL query and parses out the environment id + version.
pub fn fetch_app_environment(
    endpoint: &str,
    auth_headers: &HashMap<String, String>,
    app_id: &str,
    env_key: &str,
) -> Result<AppEnvironment> {
    let variables = serde_json::json!({
        "appId": app_id,
        "envKey": env_key,
    });

    let (status, body) = post_graphql(
        endpoint,
        APP_ENVIRONMENT_OPERATION_NAME,
        auth_headers,
        APP_ENVIRONMENT_QUERY,
        &variables,
    )?;

    let parsed: JsonValue = serde_json::from_str(&body).map_err(MintError::Json)?;

    let env = parsed
        .get("data")
        .and_then(|d| d.get("app"))
        .and_then(|a| a.get("environmentByKey"));

    let environment_id = env
        .and_then(|e| e.get("id"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            MintError::Config(format!(
                "Could not resolve environment '{}' for app {} (HTTP {}). \
                 Check the environment key, or set environment_id explicitly in the config.\n\
                 Response body: {}",
                env_key, app_id, status, body
            ))
        })?
        .to_string();

    let app_version = env
        .and_then(|e| e.get("versions"))
        .and_then(|v| v.get("nodes"))
        .and_then(|n| n.as_array())
        .and_then(|nodes| {
            nodes
                .iter()
                .find(|node| {
                    node.get("isLatest")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                })
                .or_else(|| nodes.first())
        })
        .and_then(|node| node.get("version"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    Ok(AppEnvironment {
        environment_id,
        app_version,
    })
}

// High-level, opt-in resolver used by both subcommands.
pub fn resolve_environment(
    config: &MintFctConfig,
    manifest_ctx: &mut ManifestContext,
    auth_headers: &HashMap<String, String>,
) -> Result<()> {
    let (explicit_id, env_key) = match config.product {
        Product::Confluence => {
            let c = config.confluence.as_ref();
            (
                c.and_then(|c| c.environment_id.clone()),
                c.and_then(|c| c.environment_key.clone()),
            )
        }
        Product::Global => {
            let g = config.global.as_ref();
            (
                g.and_then(|g| g.environment_id.clone()),
                g.and_then(|g| g.environment_key.clone()),
            )
        }
    };

    if let Some(id) = explicit_id {
        manifest_ctx.environment_id = Some(id);
        return Ok(());
    }

    let env_key = env_key.unwrap_or_else(|| DEFAULT_ENVIRONMENT_KEY.to_string());

    let app_env = fetch_app_environment(
        &config.graphql_endpoint,
        auth_headers,
        &manifest_ctx.app_id,
        &env_key,
    )?;

    manifest_ctx.environment_id = Some(app_env.environment_id);
    manifest_ctx.app_version = app_env.app_version;

    Ok(())
}

// Shared manifest loading logic — reads the manifest.yml (or .yaml) from an app
// directory exactly once and returns its raw text.
pub fn load_manifest(app_dir: &Path) -> Result<String> {
    let mut manifest_path = app_dir.join("manifest.yaml");
    if !manifest_path.exists() {
        manifest_path = app_dir.join("manifest.yml");
    }
    if !manifest_path.exists() {
        return Err(MintError::Config(format!(
            "Could not find manifest.yml or manifest.yaml in {}",
            app_dir.display()
        )));
    }

    Ok(fs::read_to_string(&manifest_path)?)
}

// Builds the final FCT GraphQL variables by rendering the template from the
// config against the manifest + config context.
pub fn build_variables(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
) -> Result<JsonValue> {
    let config_value =
        serde_json::to_value(config).unwrap_or(JsonValue::Object(Default::default()));

    let context = serde_json::json!({
        "manifest": {
            "app_id":         manifest_ctx.app_id,
            "app_id_bare":    manifest_ctx.app_id_bare,
            "app_name":       manifest_ctx.app_name,
            "module_key":     manifest_ctx.module_key,
            "module_type":    manifest_ctx.module_type,
            "environment_id": manifest_ctx.environment_id,
            "app_version":    manifest_ctx.app_version,
        },
        "config": config_value,
    });

    let template: JsonValue = if let Some(vars) = &config.variables {
        vars.clone()
    } else {
        match config.product {
            Product::Confluence => serde_json::json!({
                "cloudId": "${config.confluence.cloud_id}",
                "input": {
                    "contextIds": ["ari:cloud:confluence::site/${config.confluence.cloud_id}"],
                    "extensionSpecificContexts": {
                        "appVersion": "${manifest.app_version}",
                        "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${manifest.environment_id}/static/${manifest.module_key}",
                        "extensionType": "xen:macro",
                        "installationId": "${config.confluence.installation_id}",
                        "context": {
                            "moduleKey": "${manifest.module_key}",
                            "type": "${manifest.module_type}",
                            "environmentId": "${manifest.environment_id}",
                            "extension": { "type": "${manifest.module_type}" }
                        }
                    }
                }
            }),
            Product::Global => serde_json::json!({
                "input": {
                    "contextIds": ["ari:cloud:jira::site/${config.global.cloud_id}"],
                    "unlicensed": false,
                    "extensionContexts": [{
                        "appVersion": "${manifest.app_version}",
                        "extensionId": "ari:cloud:ecosystem::extension/${manifest.app_id_bare}/${manifest.environment_id}/static/${manifest.module_key}",
                        "extensionType": "xen:${manifest.module_type}",
                        "installationId": "${config.global.installation_id}",
                        "context": {
                            "moduleKey": "${manifest.module_key}",
                            "cloudId": "${config.global.cloud_id}",
                            "environmentId": "${manifest.environment_id}",
                            "type": "${manifest.module_type}",
                            "extension": { "type": "${manifest.module_type}" }
                        }
                    }]
                }
            }),
        }
    };

    let rendered = render_template(&template, &context);

    if !rendered.is_object() {
        return Err(MintError::Config(
            "Rendered GraphQL variables must be a JSON object".into(),
        ));
    }

    Ok(rendered)
}

// Takes a fully-prepared config, manifest context, and auth headers, and
// returns the FCT JWT string on success.
pub fn mint_fct_jwt(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
    auth_headers: &HashMap<String, String>,
) -> Result<String> {
    mint_fct_jwt_opts(config, manifest_ctx, auth_headers, false)
}

// Same as `mint_fct_jwt`, but `quiet` suppresses variables/response diagnostics
pub fn mint_fct_jwt_opts(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
    auth_headers: &HashMap<String, String>,
    quiet: bool,
) -> Result<String> {
    let (default_mutation, operation_name, response_key) = match config.product {
        Product::Confluence => (
            DEFAULT_CONFLUENCE_MUTATION,
            CONFLUENCE_OPERATION_NAME,
            "confluence_generateForgeContextToken",
        ),
        Product::Global => (
            DEFAULT_GLOBAL_APP_MUTATION,
            GLOBAL_APP_OPERATION_NAME,
            "globalApp_signForgeContextTokens",
        ),
    };

    let query = config.mutation.as_deref().unwrap_or(default_mutation);

    let variables = build_variables(config, manifest_ctx)?;

    if !quiet {
        info!(
            variables = %serde_json::to_string_pretty(&variables)
                .unwrap_or_else(|_| "<serialisation error>".to_string()),
            "FCT GraphQL variables"
        );
    }

    let (status, body) = post_graphql(
        &config.graphql_endpoint,
        operation_name,
        auth_headers,
        query,
        &variables,
    )?;

    let parsed: JsonValue = serde_json::from_str(&body).map_err(|e| {
        warn!(response_body = %body, "FCT response was not valid JSON");
        MintError::Json(e)
    })?;
    if !quiet {
        info!(
            http_status = status,
            response = %serde_json::to_string_pretty(&parsed).unwrap_or_default(),
            "FCT GraphQL response"
        );
    }

    let fct_obj = parsed.get("data").and_then(|d| d.get(response_key));

    let success = fct_obj
        .and_then(|o| o.get("success"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !success {
        let errors: Vec<&str> = fct_obj
            .and_then(|o| o.get("errors"))
            .and_then(|e| e.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                    .collect()
            })
            .unwrap_or_default();

        return Err(MintError::FctFailed(if errors.is_empty() {
            "Server returned success=false with no error messages".to_string()
        } else {
            errors.join("; ")
        }));
    }

    // Extract the JWT string — path differs by product
    let jwt = match config.product {
        Product::Confluence => fct_obj
            .and_then(|o| o.get("forgeContextToken"))
            .and_then(|t| t.get("jwt"))
            .and_then(|j| j.as_str())
            .ok_or_else(|| {
                MintError::FctFailed("forgeContextToken.jwt missing from response".to_string())
            })?,
        Product::Global => fct_obj
            .and_then(|o| o.get("tokens"))
            .and_then(|t| t.as_array())
            .and_then(|arr| arr.first())
            .and_then(|t| t.get("jwt"))
            .and_then(|j| j.as_str())
            .ok_or_else(|| {
                MintError::FctFailed("tokens[0].jwt missing from response".to_string())
            })?,
    };

    Ok(jwt.to_string())
}

// Tests
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn get_path_walks_nested_objects() {
        let ctx = json!({
            "config": { "confluence": { "cloud_id": "abc-123" } }
        });
        assert_eq!(
            get_path(&ctx, "config.confluence.cloud_id"),
            Some(&json!("abc-123"))
        );
    }

    #[test]
    fn get_path_returns_none_for_missing_key() {
        let ctx = json!({ "config": { "confluence": {} } });
        assert_eq!(get_path(&ctx, "config.confluence.missing"), None);
        assert_eq!(get_path(&ctx, "nope.at.all"), None);
    }

    #[test]
    fn render_whole_string_placeholder_preserves_type() {
        let ctx = json!({ "count": 7 });
        let template = json!("${count}");
        assert_eq!(render_template(&template, &ctx), json!(7));
    }

    #[test]
    fn render_embedded_placeholder_produces_string() {
        let ctx = json!({ "name": "world" });
        let template = json!("hello ${name}!");
        assert_eq!(render_template(&template, &ctx), json!("hello world!"));
    }

    #[test]
    fn render_missing_placeholder_becomes_empty_or_null() {
        let ctx = json!({});
        assert_eq!(render_template(&json!("${gone}"), &ctx), json!(null));
        assert_eq!(render_template(&json!("a${gone}b"), &ctx), json!("ab"));
    }

    #[test]
    fn render_recurses_into_objects_and_arrays() {
        let ctx = json!({ "id": "X1", "n": 2 });
        let template = json!({
            "outer": { "inner": "${id}" },
            "list": ["${n}", "lit"]
        });
        let expected = json!({
            "outer": { "inner": "X1" },
            "list": [2, "lit"]
        });
        assert_eq!(render_template(&template, &ctx), expected);
    }

    #[test]
    fn product_display_matches_config_values() {
        assert_eq!(Product::Confluence.to_string(), "confluence");
        assert_eq!(Product::Global.to_string(), "global");
    }

    #[test]
    fn format_duration_buckets() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(3 * 60), "3m");
        assert_eq!(format_duration(2 * 3600 + 5 * 60), "2h 5m");
        assert_eq!(format_duration(3 * 86_400 + 4 * 3600), "3d 4h");
        assert_eq!(format_duration(-45), "45s");
    }

    fn manifest_with_remotes(keys: &[&str]) -> String {
        let remotes: Vec<String> = keys
            .iter()
            .map(|k| format!(r#"{{ "key": "{k}" }}"#))
            .collect();
        format!(
            r#"{{
                "app": {{ "name": "T", "id": "test-app" }},
                "modules": {{}},
                "remotes": [{}]
            }}"#,
            remotes.join(", ")
        )
    }

    #[test]
    fn detect_remote_key_override_wins() {
        let json = manifest_with_remotes(&["first-remote", "second-remote"]);
        let manifest: ForgeManifest<'_> = serde_json::from_str(&json).unwrap();
        // An explicit override is used verbatim, even when remotes exist.
        assert_eq!(
            detect_remote_key(&manifest, Some("chosen-remote")),
            Some("chosen-remote".to_string())
        );
    }

    #[test]
    fn detect_remote_key_empty_override_falls_back() {
        let json = manifest_with_remotes(&["first-remote", "second-remote"]);
        let manifest: ForgeManifest<'_> = serde_json::from_str(&json).unwrap();
        // An empty override is ignored; the first declared remote is used.
        assert_eq!(
            detect_remote_key(&manifest, Some("")),
            Some("first-remote".to_string())
        );
    }

    #[test]
    fn detect_remote_key_falls_back_to_first_remote() {
        let json = manifest_with_remotes(&["first-remote", "second-remote"]);
        let manifest: ForgeManifest<'_> = serde_json::from_str(&json).unwrap();
        assert_eq!(
            detect_remote_key(&manifest, None),
            Some("first-remote".to_string())
        );
    }

    #[test]
    fn detect_remote_key_none_when_no_remotes() {
        let json = manifest_with_remotes(&[]);
        let manifest: ForgeManifest<'_> = serde_json::from_str(&json).unwrap();
        // No remotes and no override → None (caller turns this into a clear error).
        assert_eq!(detect_remote_key(&manifest, None), None);
    }
}
