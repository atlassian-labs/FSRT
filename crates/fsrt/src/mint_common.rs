//! Shared types and functions used by both `mint_fct` and `mint_fit`.
//!
//! This module contains:
//!   - Config structs (deserialised from the YAML config files in `scripts/`)
//!   - Auth header construction
//!   - GraphQL HTTP POST via `ureq`
//!   - Template rendering
//!   - The core `mint_fct_jwt()` function, which both subcommands call

// ============================================================================
// Imports
// ============================================================================

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

// ============================================================================
// Constants
// ============================================================================

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

// ============================================================================
// Error type
// ============================================================================

// `MintError` is the shared error type for both mint_fct and mint_fit.
// `thiserror::Error` auto-generates the Display and Error trait impls from
// the `#[error("...")]` attributes — no boilerplate needed.
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

    // Returned when the configured session cookie's JWT `exp` is in the past.
    // We fail fast here instead of sending a stale cookie and getting a
    // confusing HTTP 401 downstream. The message tells the tester how to renew.
    #[error("{0}")]
    CookieExpired(String),
}

// Convenience alias — write `Result<T>` instead of `Result<T, MintError>`.
pub type Result<T> = std::result::Result<T, MintError>;

// ============================================================================
// Config structs
// ============================================================================
// These deserialise from the YAML config files in `scripts/`.
// Both `mint_fct` and `mint_fit` use the same YAML format.

// Which Atlassian product the FCT/FIT is being minted for.
// Controls which GraphQL mutation is used:
//   Confluence → confluence_generateForgeContextToken
//   GlobalApp  → globalApp_signForgeContextTokens
//
// Set via `product:` in the YAML config file:
//   product: confluence
//   product: global
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

// `#[derive(Debug, Deserialize, Serialize)]`:
//   Debug       → printable for logging (`println!("{:?}", ...)`)
//   Deserialize → can be built from YAML text (`serde_yaml::from_str`)
//   Serialize   → can be turned into JSON (`serde_json::to_value`)
//                 needed because we embed the whole config as the template context
#[derive(Debug, Deserialize, Serialize)]
pub struct MintFctConfig {
    // Which Atlassian product to mint the token for.
    // Required — must be "confluence" or "global" in the YAML config.
    pub product: Product,

    // The Atlassian GraphQL gateway URL.
    // e.g. "https://lhe2.atlassian.net/gateway/api/graphql"
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

    // The GraphQL variables template — an arbitrary JSON/YAML object containing
    // `${...}` placeholders that get substituted at runtime.
    pub variables: Option<JsonValue>,
}

// The `auth:` section of the config.
// Supports two types matching the YAML config files in `scripts/`:
//   "raw_cookie"      — full Cookie header pasted from Burp/DevTools
//   "basic_api_token" — Atlassian API token (email + token file)
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthConfig {
    // YAML key is `type` — a reserved word in Rust, so we rename it.
    #[serde(rename = "type", default = "default_auth_type")]
    pub auth_type: String,

    // --- raw_cookie ---
    // The full Cookie header value, either inline or from a file.
    pub raw_cookie: Option<String>,
    pub raw_cookie_file: Option<String>,

    // --- basic_api_token ---
    // Email is not a secret — it's inline in the config.
    // API token is a secret — read from inline value or a file.
    pub email: Option<String>,
    pub api_token: Option<String>,
    pub api_token_file: Option<String>,
}

fn default_auth_type() -> String {
    "raw_cookie".to_string()
}

// The `confluence:` section of the config.
// `#[derive(Clone)]` — needed because we clone it when building the template context.
// `Serialize` — needed so `serde_json::to_value(config)` includes this struct.
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
    pub site_url: Option<String>,
    // Named Forge environment slot; used to look up environment_id when it
    // isn't supplied explicitly. Defaults to "development".
    pub environment_key: Option<String>,
}

// The `global:` section of the config — used when product: global.
// Mirrors the fields needed to build a GlobalAppSignForgeContextTokensInput.
//
// `environment_id` is optional: if omitted, it is resolved automatically from
// the Forge platform via `fetch_app_environment()` (see below), using the app
// id (from the manifest) and `environment_key` (defaults to "development").
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct GlobalAppConfig {
    pub cloud_id: Option<String>,
    pub installation_id: Option<String>,
    pub environment_id: Option<String>,
    pub environment_type: Option<String>,
    pub module_key: Option<String>,
    // Named Forge environment slot ("development" | "staging" | "production").
    // Used to look up environment_id when it isn't supplied explicitly.
    pub environment_key: Option<String>,
}

// ============================================================================
// Manifest context
// ============================================================================
// What we extract from the Forge app's manifest.yml.
// Used to fill `${manifest.app_id_bare}`, `${manifest.module_key}`, etc.

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
    // environment_id: the UUID of the named environment slot.
    // app_version: the latest deployed version string (e.g. "43.0.0").
    // Both are None until the lookup runs; the default variable templates
    // reference them as ${manifest.environment_id} and ${manifest.app_version}.
    pub environment_id: Option<String>,
    pub app_version: Option<String>,
}

// ============================================================================
// extract_manifest_context()
// ============================================================================
// Reads a parsed ForgeManifest and returns a ManifestContext.
//
// Module/remote detection lives in forge_loader (see ForgeModules methods), so
// this works entirely off the typed manifest — the manifest is read from disk
// once and parsed once by the caller.
// Resolve the module that owns a `--function` value, tolerating both the bare
// "<function>" form and the "<resolver>.<function>" form. Tries the whole
// string first, then the segment after the last '.'.
fn detect_module_for_function<'a>(
    manifest: &ForgeManifest<'a>,
    function: &str,
) -> Option<(&'a str, &'static str)> {
    manifest
        .modules
        .detect_fct_module_for_function(function)
        .or_else(|| {
            function
                .rsplit_once('.')
                .and_then(|(_, tail)| manifest.modules.detect_fct_module_for_function(tail))
        })
}

pub fn extract_manifest_context(
    manifest: &ForgeManifest<'_>,
    module_key: Option<&str>,
) -> ManifestContext {
    // No invoked function is known in the mint-only paths, so module selection
    // uses first-module auto-detection (historical behaviour). With no
    // function supplied, the function-aware error path cannot trigger, so the
    // Result is always Ok here.
    extract_manifest_context_for_function(manifest, module_key, None)
        .expect("extract_manifest_context_for_function cannot fail without a function")
}

/// Like [`extract_manifest_context`], but aware of the backend resolver
/// `function` being invoked.
///
/// Module selection precedence:
///   1. An explicit `module_key` (from config) always wins. If it does not own
///      the invoked `function`, a warning is emitted — the mismatch is usually a
///      config mistake and would otherwise fail confusingly at the remote hop.
///   2. Otherwise, if a `function` is supplied, select the module whose
///      `resolver.function` matches it. This is the correct choice for apps
///      where several modules share one resolver, or where the first-declared
///      module is endpoint-backed (so blind first-module detection picks a
///      `moduleKey` that does not match the invoked resolver). If no module
///      declares that function, this is a hard error — we do NOT fall back to
///      an unrelated module, because sending a mismatched `moduleKey` fails
///      confusingly at the remote hop (e.g. a 404 text/html from the backend).
///   3. Otherwise (no function supplied), fall back to first-module
///      auto-detection.
pub fn extract_manifest_context_for_function(
    manifest: &ForgeManifest<'_>,
    module_key: Option<&str>,
    function: Option<&str>,
) -> Result<ManifestContext> {
    let app_id = manifest.app.id.to_string();

    // Strip the ARI prefix to get the bare UUID.
    // "ari:cloud:ecosystem::app/8bdd65d0-..." → "8bdd65d0-..."
    let app_id_bare = app_id.rsplit('/').next().unwrap_or(&app_id).to_string();

    let app_name = manifest.app.name.map(|s| s.to_string());

    let (detected_key, detected_type) = match module_key {
        // 1. Explicit override from config — inferring its type from the
        //    manifest. Warn if it doesn't own the invoked function.
        Some(key) => {
            if let Some(func) = function {
                let owns_func = detect_module_for_function(manifest, func)
                    .is_some_and(|(matched_key, _)| matched_key == key);
                if !owns_func {
                    eprintln!(
                        "warning: configured module_key '{key}' does not declare \
                         resolver function '{func}'; the invocation's moduleKey may \
                         not match the invoked resolver."
                    );
                }
            }
            (
                Some(key.to_string()),
                manifest
                    .modules
                    .fct_module_type_for_key(key)
                    .map(|t| t.to_string()),
            )
        }
        // 2. Select the module that owns the invoked function. No fallback: a
        //    mismatched moduleKey fails confusingly downstream, so error out.
        None => match function {
            Some(func) => match detect_module_for_function(manifest, func) {
                Some((key, module_type)) => (Some(key.to_string()), Some(module_type.to_string())),
                None => {
                    return Err(MintError::Config(format!(
                        "no module in the manifest declares resolver function '{func}'. \
                         Check the --function value, or set module_key in the config to \
                         the module that owns this resolver."
                    )));
                }
            },
            // 3. No function supplied — first-module auto-detection.
            None => match manifest.modules.detect_fct_module() {
                Some((key, module_type)) => (Some(key.to_string()), Some(module_type.to_string())),
                None => (None, None),
            },
        },
    };

    Ok(ManifestContext {
        app_id,
        app_id_bare,
        app_name,
        module_key: detected_key,
        module_type: detected_type,
        // Filled in later by resolve_environment() if a lookup runs.
        environment_id: None,
        app_version: None,
    })
}

// ============================================================================
// detect_remote_key()
// ============================================================================
// Walks the raw YAML manifest to find the `key` of the first declared remote.
//
// A remote in manifest.yml looks like:
//   remotes:
//     - key: my-remote-backend
//       baseUrl: https://my-backend.com
//       auth:
//         appUser: {}
//
// Returns None if no remotes are declared — the caller (run_mint_fit) will
// return a clear error in that case.
//
// An optional `override_key` (from the config) takes priority over
// auto-detection — needed for apps with multiple remotes.
pub fn detect_remote_key(
    manifest: &ForgeManifest<'_>,
    override_key: Option<&str>,
) -> Option<String> {
    // Config override takes priority over auto-detection.
    if let Some(key) = override_key
        && !key.is_empty()
    {
        return Some(key.to_string());
    }

    // Otherwise take the key of the first declared remote from the typed
    // manifest. Returns None if no remotes are declared or the first one has
    // no key.
    manifest
        .remotes
        .as_ref()?
        .first()
        .map(|remote| remote.key.clone())
        .filter(|key| !key.is_empty())
}

// ============================================================================
// load_secret_from_config()
// ============================================================================
// Reads a secret from one of two sources (in priority order):
//   1. Inline value in the config (e.g. `raw_cookie: "eyJ..."`)
//   2. A file path              (e.g. `raw_cookie_file: "./session-cookie.txt"`)
pub fn load_secret_from_config(
    inline: Option<&str>,
    file_path: Option<&str>,
) -> Result<Option<String>> {
    // 1. Inline value takes highest priority.
    if let Some(v) = inline
        && !v.is_empty()
    {
        return Ok(Some(v.to_string()));
    }

    // 2. Read from a file.
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

// ============================================================================
// build_auth_headers()
// ============================================================================
// Reads the `auth:` section of the config and returns the HTTP headers needed
// to authenticate the request. Returns a HashMap<header_name, header_value>.
pub fn build_auth_headers(auth: &AuthConfig) -> Result<HashMap<String, String>> {
    let mut headers = HashMap::new();

    println!("\n=== Auth material ===");
    println!("WARNING: Do not paste this output into public tickets, logs, or chat.");

    match auth.auth_type.as_str() {
        // ------------------------------------------------------------------
        // raw_cookie: the full Cookie header pasted from Burp/DevTools.
        // e.g. "tenant.session.token=eyJ...; atlassian.xsrf.token=5748..."
        // ------------------------------------------------------------------
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

            // Only print the first 80 chars — never log a full session token.
            println!("Cookie (first 80 chars): {}...", &raw[..raw.len().min(80)]);

            // Check the session token's `exp` claim locally (no network call).
            // If we can definitively tell it is expired, hard-fail here with
            // actionable advice — sending a stale cookie only yields a confusing
            // HTTP 401 later. If we cannot read an `exp` (non-standard cookie
            // format), we do NOT block: check_cookie_expiry() prints a warning
            // and we proceed, letting the server be the final authority.
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

        // ------------------------------------------------------------------
        // basic_api_token: Atlassian API token encoded as HTTP Basic auth.
        // The gateway accepts base64("email:api_token") in the Authorization header.
        // ------------------------------------------------------------------
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

            // HTTP Basic auth: base64-encode "email:token"
            let credentials = format!("{}:{}", email.trim(), token.trim());
            let encoded = B64.encode(credentials.as_bytes());

            println!("Basic auth email: {}", email.trim());
            println!(
                "Authorization: Basic {}... (truncated)",
                &encoded[..encoded.len().min(20)]
            );
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

// ============================================================================
// Session-cookie expiry checking
// ============================================================================
// The raw cookie contains `tenant.session.token`, which is a JWT. Its `exp`
// claim tells us exactly when the session dies — we can read it locally without
// any network round-trip. These helpers extract that claim and print a status
// message so an expired cookie is caught up front (rather than surfacing as an
// opaque HTTP 401 mid-request).

const SESSION_COOKIE_NAME: &str = "tenant.session.token";

// Pull the `tenant.session.token` value out of a full Cookie header string.
// The header looks like "name1=val1; tenant.session.token=eyJ...; name2=val2".
// Falls back to treating the whole trimmed string as the token if no explicit
// `name=` prefix is present (i.e. the file contains only the bare JWT).
fn extract_session_token(raw_cookie: &str) -> Option<&str> {
    for pair in raw_cookie.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix(&format!("{SESSION_COOKIE_NAME}=")) {
            return Some(value);
        }
    }
    // No "name=" pair matched. If the whole thing looks like a bare JWT
    // (three dot-separated segments and no '='), use it directly.
    let trimmed = raw_cookie.trim();
    if !trimmed.contains('=') && trimmed.split('.').count() == 3 {
        return Some(trimmed);
    }
    None
}

// Decode a JWT's `exp` (expiry) claim, in Unix seconds. Returns None if the
// token isn't a well-formed JWT or has no numeric `exp`.
fn decode_jwt_exp(token: &str) -> Option<i64> {
    // JWT = header.payload.signature — the middle segment is the JSON payload.
    let payload_b64 = token.split('.').nth(1)?;
    let payload_bytes = B64_URL.decode(payload_b64).ok()?;
    let payload: JsonValue = serde_json::from_slice(&payload_bytes).ok()?;
    payload.get("exp")?.as_i64()
}

// Format a duration in seconds as a short human string, e.g. "2h 5m", "3d 4h".
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
// Returns Some(seconds_since_expiry) ONLY when the session token is present,
// is a readable JWT, and its `exp` is in the past. Returns None when the
// cookie is still valid OR when we cannot read an `exp` (non-standard format) —
// i.e. "don't block unless we are sure it is expired".
fn cookie_expired_secs_ago(raw_cookie: &str) -> Option<i64> {
    let token = extract_session_token(raw_cookie)?;
    let exp = decode_jwt_exp(token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    (exp <= now).then_some(now - exp)
}

// Inspect the raw cookie's session token and print its expiry status. Returns
// true if the token is present and not yet expired, false otherwise. Purely
// informational — it does not block the request (the hard block lives in
// build_auth_headers via cookie_expired_secs_ago).
pub fn check_cookie_expiry(raw_cookie: &str) -> bool {
    let Some(token) = extract_session_token(raw_cookie) else {
        println!(
            "WARNING: could not find '{SESSION_COOKIE_NAME}' in the cookie — \
             cannot check expiry."
        );
        return false;
    };

    let Some(exp) = decode_jwt_exp(token) else {
        println!(
            "WARNING: could not read an `exp` claim from '{SESSION_COOKIE_NAME}' \
             (not a JWT?) — cannot check expiry."
        );
        return false;
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if exp <= now {
        println!(
            "WARNING: session cookie EXPIRED {} ago (exp={}). \
             Renew it (e.g. re-run the session-cookie harvester) before minting.",
            format_duration(now - exp),
            exp,
        );
        false
    } else {
        println!(
            "Session cookie valid — expires in {} (exp={}).",
            format_duration(exp - now),
            exp,
        );
        true
    }
}

// ============================================================================
// render_template() and helpers
// ============================================================================
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
// "config.confluence.cloud_id" → context["config"]["confluence"]["cloud_id"]
pub fn get_path<'a>(context: &'a JsonValue, path: &str) -> Option<&'a JsonValue> {
    let mut cur = context;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

// ============================================================================
// post_graphql()
// ============================================================================
// Sends a GraphQL POST request to the Atlassian gateway and returns
// (http_status_code, response_body_text).
// This is the ONLY place in the codebase that uses `ureq`.
pub fn post_graphql(
    endpoint: &str,
    operation_name: &str,
    auth_headers: &HashMap<String, String>,
    query: &str,
    variables: &JsonValue,
) -> Result<(u16, String)> {
    // Extract origin from the endpoint URL for CSRF headers.
    // "https://lhe2.atlassian.net/gateway/api/graphql" → "https://lhe2.atlassian.net"
    let origin = endpoint.split('/').take(3).collect::<Vec<_>>().join("/");

    // Append operation name as a query param — gateway uses this for routing.
    let url = format!("{}?q={}", endpoint, operation_name);

    let body = serde_json::json!({
        "operationName": operation_name,
        "query": query,
        "variables": variables,
    });

    // Build the ureq POST request.
    // `.set(name, value)` adds an HTTP header.
    // `ureq::post(&url)` returns a request builder.
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

    // Add auth headers (Cookie or Authorization).
    for (name, value) in auth_headers {
        request = request.set(name, value);
    }

    // `.send_json()` serialises the body and sends the request.
    match request.send_json(&body) {
        Ok(response) => {
            let status = response.status();
            let text = response
                .into_string()
                .map_err(|e| MintError::Http(e.to_string()))?;
            Ok((status, text))
        }
        Err(ureq::Error::Status(code, response)) => {
            // HTTP 4xx/5xx — still read the body for error details.
            let text = response
                .into_string()
                .unwrap_or_else(|_| "<unreadable response body>".to_string());
            Ok((code, text))
        }
        Err(e) => Err(MintError::Http(e.to_string())),
    }
}

// ============================================================================
// load_config()
// ============================================================================
// Loads and deserialises the `fsrt-remote.toml` config file into a
// `MintFctConfig` using the `config` crate (config-rs).
//
// The `config` crate is a layered configuration system: sources are added in
// priority order and merged, then the merged result is deserialised into a
// typed struct via serde. Right now we use a single source — the TOML file —
// but the builder pattern makes it trivial to add more layers later (e.g. an
// `Environment` source so secrets like the session cookie can be supplied via
// env vars instead of on disk):
//
//     Config::builder()
//         .add_source(File::from(path))                       // fsrt-remote.toml
//         .add_source(Environment::with_prefix("FSRT")        // FSRT_AUTH__RAW_COOKIE=...
//             .separator("__"))
//         .build()?
//
// `File::from(&Path)` auto-detects the format from the file extension, so a
// `.toml` file is parsed as TOML. `try_deserialize()` then pours the merged
// values into `MintFctConfig` — the exact same struct serde_yaml used to fill,
// so all the `#[serde(...)]` attributes and downstream code are unchanged.
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

// ============================================================================
// fetch_app_environment() / resolve_environment()
// ============================================================================
// Resolves the app's environment_id (and latest deployed version) from the
// Forge platform, so the pen tester doesn't have to paste a UUID or a version
// string into the config.
//
// The query is app-scoped: given the app id (already read from manifest.yml)
// and a named environment slot ("development" / "staging" / "production"), the
// platform returns the environment UUID and the latest deployed version.
//
//   app(id: $appId) {
//     environmentByKey(key: $envKey) { id }
//     ...latest version...
//   }

// Default named environment slot when the config doesn't specify one.
// The Forge platform's default development environment has the key "default"
// (its `type` is DEVELOPMENT). Override via `environment_key` in the config.
pub const DEFAULT_ENVIRONMENT_KEY: &str = "default";

// The read query that resolves environment_id + latest app version.
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
    // Latest deployed version, if the app has any deployed versions.
    pub app_version: Option<String>,
}

// Performs the GraphQL query and parses out the environment id + version.
// Reuses the shared post_graphql() helper — same endpoint, same auth headers.
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

    // Version is best-effort — an app may have no deployed versions yet.
    // Pick the node flagged isLatest, falling back to the first node.
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
//
// If the config already supplies `environment_id`, we trust it and skip the
// network round-trip (the config value acts as an override/cache). Otherwise we
// call fetch_app_environment() using the config's `environment_key` (defaulting
// to "development") and populate manifest_ctx.environment_id + app_version so
// build_variables() can reference them.
pub fn resolve_environment(
    config: &MintFctConfig,
    manifest_ctx: &mut ManifestContext,
    auth_headers: &HashMap<String, String>,
) -> Result<()> {
    // Read the config's explicit environment_id / environment_key for the
    // active product, if any.
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

    // Explicit environment_id in the config short-circuits the lookup.
    if let Some(id) = explicit_id {
        manifest_ctx.environment_id = Some(id);
        return Ok(());
    }

    let env_key = env_key.unwrap_or_else(|| DEFAULT_ENVIRONMENT_KEY.to_string());

    println!(
        "\n=== Resolving environment '{}' via Forge platform ===",
        env_key
    );
    let app_env = fetch_app_environment(
        &config.graphql_endpoint,
        auth_headers,
        &manifest_ctx.app_id,
        &env_key,
    )?;

    println!("  environment_id: {}", app_env.environment_id);
    println!("  app_version:    {:?}", app_env.app_version);

    manifest_ctx.environment_id = Some(app_env.environment_id);
    manifest_ctx.app_version = app_env.app_version;

    Ok(())
}

// ============================================================================
// load_manifest()
// ============================================================================
// Shared manifest loading logic — reads the manifest.yml (or .yaml) from an app
// directory exactly once and returns its raw text.
//
// The returned String must be kept alive by the caller because the typed
// `ForgeManifest` borrows from it. Callers parse it once via
// `serde_yaml::from_str` — module/remote details are then read through the
// typed accessors on `ForgeManifest`/`ForgeModules`, so the manifest is never
// parsed a second time.
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

// ============================================================================
// build_variables()
// ============================================================================
// Builds the final FCT GraphQL variables by rendering the template from the
// config against the manifest + config context.
// Branches on config.product to build the correct variable shape for each API.
pub fn build_variables(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
) -> Result<JsonValue> {
    // Build the template context:
    //   { "manifest": {...}, "config": <whole MintFctConfig as JSON> }
    //
    // This means ${config.confluence.cloud_id} and ${config.global.cloud_id}
    // resolve correctly because MintFctConfig has both "confluence" and "global"
    // fields that serde serialises by name.
    let config_value =
        serde_json::to_value(config).unwrap_or(JsonValue::Object(Default::default()));

    let context = serde_json::json!({
        "manifest": {
            "app_id":         manifest_ctx.app_id,
            "app_id_bare":    manifest_ctx.app_id_bare,
            "app_name":       manifest_ctx.app_name,
            "module_key":     manifest_ctx.module_key,
            "module_type":    manifest_ctx.module_type,
            // Resolved via resolve_environment() — used by the default templates
            // so the pen tester never has to supply these.
            "environment_id": manifest_ctx.environment_id,
            "app_version":    manifest_ctx.app_version,
        },
        "config": config_value,
    });

    // Use the variables template from the config if supplied — works for both
    // products. Otherwise fall back to a product-specific minimal default.
    let template: JsonValue = if let Some(vars) = &config.variables {
        vars.clone()
    } else {
        match config.product {
            // NOTE: environment_id and app_version come from the resolved
            // manifest context (${manifest.environment_id} / ${manifest.app_version}),
            // not from the config — so the pen tester never supplies them.
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
                            // moduleKey is what the platform bakes into the signed
                            // FCT and later surfaces as the resolver's
                            // `context.moduleKey`. Resolvers that branch on it
                            // (e.g. moduleKey.includes('node')) throw
                            // "Cannot read properties of undefined" without it.
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
                            // See the Confluence note above: moduleKey must be in
                            // the signed FCT so the resolver's context.moduleKey
                            // is populated.
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

// ============================================================================
// mint_fct_jwt()
// ============================================================================
// The core FCT minting function — called by both `mint_fct::run_mint_fct()`
// and `mint_fit::run_mint_fit()`.
//
// Takes a fully-prepared config, manifest context, and auth headers, and
// returns the FCT JWT string on success.
//
// This separation is why mint_common.rs exists — both subcommands need to
// mint an FCT, but only mint_fct prints the result as the final output.
// mint_fit uses the JWT as an input to the FIT minting step.
pub fn mint_fct_jwt(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
    auth_headers: &HashMap<String, String>,
) -> Result<String> {
    // Verbose by default — mint-fct / mint-fit want the full GraphQL trace.
    mint_fct_jwt_opts(config, manifest_ctx, auth_headers, false)
}

// Same as `mint_fct_jwt`, but `quiet` suppresses the FCT GraphQL
// variables/response diagnostics. `invoke-extension` uses quiet=true so its
// output stays focused on the invocation, not the intermediate token mint.
pub fn mint_fct_jwt_opts(
    config: &MintFctConfig,
    manifest_ctx: &ManifestContext,
    auth_headers: &HashMap<String, String>,
    quiet: bool,
) -> Result<String> {
    // Select mutation and operation name based on product.
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
        println!("\n=== FCT GraphQL variables ===");
        println!(
            "{}",
            serde_json::to_string_pretty(&variables)
                .unwrap_or_else(|_| "<serialisation error>".to_string())
        );
    }

    let (status, body) = post_graphql(
        &config.graphql_endpoint,
        operation_name,
        auth_headers,
        query,
        &variables,
    )?;

    // Parse and (unless quiet) pretty-print the response.
    let parsed: JsonValue = serde_json::from_str(&body).map_err(|e| {
        println!("{}", body); // print raw body if not valid JSON
        MintError::Json(e)
    })?;
    if !quiet {
        println!("\n=== FCT GraphQL response ===");
        println!("HTTP status: {}", status);
        println!("{}", serde_json::to_string_pretty(&parsed)?);
    }

    // Navigate to the FCT JWT in the response tree using the product-specific key.
    // Confluence: data.confluence_generateForgeContextToken.forgeContextToken.jwt
    // Global:     data.globalApp_signForgeContextTokens.tokens[0].jwt
    let fct_obj = parsed.get("data").and_then(|d| d.get(response_key));

    let success = fct_obj
        .and_then(|o| o.get("success"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !success {
        // Collect server-side error messages for a useful error.
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

    // Extract the JWT string — path differs by product:
    //   Confluence: .forgeContextToken.jwt  (single object)
    //   Global:     .tokens[0].jwt           (list, take first)
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

// ============================================================================
// Tests
// ============================================================================
// These cover the pure, network-free helpers shared by `mint_fct` and
// `mint_fit`: dotted-path lookup, `${...}` template rendering, `Product`
// display, and human-readable duration formatting. The GraphQL/HTTP paths are
// intentionally not exercised here — they require a live Atlassian gateway.
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
        // A string that is *only* a placeholder resolves to the underlying
        // JSON value, keeping its original type (here: a number).
        let ctx = json!({ "count": 7 });
        let template = json!("${count}");
        assert_eq!(render_template(&template, &ctx), json!(7));
    }

    #[test]
    fn render_embedded_placeholder_produces_string() {
        // A placeholder embedded in surrounding text is substituted as text.
        let ctx = json!({ "name": "world" });
        let template = json!("hello ${name}!");
        assert_eq!(render_template(&template, &ctx), json!("hello world!"));
    }

    #[test]
    fn render_missing_placeholder_becomes_empty_or_null() {
        let ctx = json!({});
        // Whole-string placeholder → Null.
        assert_eq!(render_template(&json!("${gone}"), &ctx), json!(null));
        // Embedded missing placeholder → empty replacement.
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
    fn product_display_matches_yaml_values() {
        assert_eq!(Product::Confluence.to_string(), "confluence");
        assert_eq!(Product::Global.to_string(), "global");
    }

    #[test]
    fn format_duration_buckets() {
        assert_eq!(format_duration(45), "45s");
        assert_eq!(format_duration(3 * 60), "3m");
        assert_eq!(format_duration(2 * 3600 + 5 * 60), "2h 5m");
        assert_eq!(format_duration(3 * 86_400 + 4 * 3600), "3d 4h");
        // Negative inputs are treated as their absolute value.
        assert_eq!(format_duration(-45), "45s");
    }
}
