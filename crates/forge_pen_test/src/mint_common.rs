//! Authentication, JWT, HTTP, and GraphQL support for FCT minting.

use std::{fs, path::PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tracing::{info, warn};
use ureq::{
    Body, SendBody,
    http::{
        Request, Response,
        header::{COOKIE, HeaderValue, InvalidHeaderValue, ORIGIN},
    },
    middleware::{Middleware, MiddlewareNext},
};
use url::Url;

const SESSION_COOKIE_NAME: &str = "tenant.session.token";
const GRAPHQL_ENDPOINT: &str = "https://www.atlassian.net/gateway/api/graphql";
const GRAPHQL_ORIGIN: &str = "https://www.atlassian.net";

/// A serialized GraphQL request shared by dry-run and live operations.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphqlRequest<V> {
    pub operation_name: String,
    pub query: String,
    pub variables: V,
}

/// An error object returned in a GraphQL response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct GraphqlErrorObject {
    /// The schema permits an absent or null message.
    pub message: Option<String>,
}

/// Errors produced while constructing or minting Forge tokens.
#[derive(Debug, thiserror::Error)]
pub enum MintError {
    #[error("could not read {kind} file '{path}'")]
    FileRead {
        kind: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not parse config file '{path}'")]
    ConfigParse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("tenant-info request to '{url}' failed")]
    TenantInfoRequest {
        url: Url,
        #[source]
        source: Box<ureq::Error>,
    },

    #[error("tenant-info response from '{url}' could not be read")]
    TenantInfoResponse {
        url: Url,
        #[source]
        source: Box<ureq::Error>,
    },

    #[error("tenant-info endpoint '{url}' returned HTTP {status}")]
    TenantInfoStatus { url: Url, status: u16, body: String },

    #[error("tenant-info endpoint '{url}' returned invalid JSON")]
    TenantInfoInvalidJson {
        url: Url,
        body: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("GraphQL operation '{operation_name}' could not be sent")]
    GraphqlRequest {
        operation_name: String,
        #[source]
        source: Box<ureq::Error>,
    },

    #[error("GraphQL operation '{operation_name}' returned an unreadable response body")]
    GraphqlResponse {
        operation_name: String,
        #[source]
        source: Box<ureq::Error>,
    },

    #[error("GraphQL operation '{operation_name}' returned HTTP {status}")]
    GraphqlHttpStatus {
        operation_name: String,
        status: u16,
        body: String,
    },

    #[error("GraphQL operation '{operation_name}' returned invalid JSON")]
    GraphqlInvalidJson {
        operation_name: String,
        body: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("GraphQL operation '{operation_name}' returned errors: {errors:?}")]
    GraphqlRejected {
        operation_name: String,
        errors: Vec<GraphqlErrorObject>,
    },

    #[error("invalid session cookie header")]
    InvalidCookieHeader {
        #[source]
        source: InvalidHeaderValue,
    },

    #[error("session cookie does not contain a 'tenant.session.token' JWT")]
    MissingSessionCookie,

    #[error("invalid session cookie JWT")]
    InvalidSessionCookie,

    #[error("session cookie expired {seconds_ago} seconds ago")]
    CookieExpired { seconds_ago: i64 },

    #[error("app '{app_id}' not installed in '{context_id}'")]
    AppNotInstalled { app_id: String, context_id: String },

    #[error("invalid app ID '{app_id}'")]
    InvalidAppId { app_id: String },

    #[error("app '{app_id}' has no installations in '{context_id}'")]
    NoInstallations { app_id: String, context_id: String },

    #[error("environment '{environment_key}' not found for app '{app_id}'")]
    EnvironmentNotFound {
        environment_key: String,
        app_id: String,
    },

    #[error("module '{module_key}' not found; available: {available:?}")]
    ModuleKeyNotFound {
        module_key: String,
        available: Vec<String>,
    },

    #[error("FIT minting failed: {source}; possible remotes: {available:?}")]
    FitMintFailed {
        #[source]
        source: Box<MintError>,
        available: Vec<String>,
    },

    #[error("FCT context must be a JSON object")]
    InvalidFctContext,

    #[error("supplied FCT must not be empty")]
    EmptySuppliedFct,

    #[error("FCT mutation was rejected (success: {success}): {errors:?}")]
    MintRejected {
        success: bool,
        errors: Vec<GraphqlErrorObject>,
    },

    #[error("FCT response has no token")]
    MissingFctToken,

    #[error("FIT response has no token")]
    MissingFitToken,
}

/// Structural and expiry status of a JWT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JwtValidity {
    /// The token is structurally valid and unexpired.
    Valid,
    /// The token is structurally valid but expired.
    Expired,
    /// The token is missing or structurally invalid.
    Invalid,
}

enum CookieExpiry {
    Expired(i64),
    Valid(i64),
}

#[derive(Deserialize)]
struct TenantInfo {
    #[serde(rename = "cloudId")]
    cloud_id: String,
}

#[derive(Deserialize)]
struct GraphqlData<T> {
    data: T,
}

pub(crate) struct GraphqlHeaders {
    cookie: HeaderValue,
}

impl GraphqlHeaders {
    pub(crate) fn new(cookie_header: String) -> Result<Self, MintError> {
        let cookie = HeaderValue::from_str(&cookie_header)
            .map_err(|source| MintError::InvalidCookieHeader { source })?;
        Ok(Self { cookie })
    }
}

impl Middleware for GraphqlHeaders {
    fn handle(
        &self,
        mut request: Request<SendBody<'_>>,
        next: MiddlewareNext<'_>,
    ) -> Result<Response<Body>, ureq::Error> {
        if request.uri() == GRAPHQL_ENDPOINT {
            request
                .headers_mut()
                .insert(ORIGIN, HeaderValue::from_static(GRAPHQL_ORIGIN));
            request.headers_mut().insert(COOKIE, self.cookie.clone());
        }
        next.handle(request)
    }
}

pub(crate) fn build_cookie_header(raw_cookie_file: &str) -> Result<String, MintError> {
    let raw = fs::read_to_string(raw_cookie_file).map_err(|source| MintError::FileRead {
        kind: "session cookie",
        path: PathBuf::from(raw_cookie_file),
        source,
    })?;
    let raw = raw.trim();

    match cookie_expiry(raw)? {
        CookieExpiry::Expired(seconds_ago) => {
            return Err(MintError::CookieExpired { seconds_ago });
        }
        CookieExpiry::Valid(seconds_remaining) => info!(
            expires_in = %format_duration(seconds_remaining),
            "session cookie valid"
        ),
    }

    Ok(if raw.contains('=') {
        raw.to_string()
    } else {
        format!("{SESSION_COOKIE_NAME}={raw}")
    })
}

pub(crate) fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let mut segments = token.split('.');
    let header_b64 = segments.next()?;
    let payload_b64 = segments.next()?;
    let signature_b64 = segments.next()?;
    if segments.next().is_some() {
        return None;
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).ok()?;
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).ok()?;
    if !header.is_object() {
        return None;
    }

    let signature = URL_SAFE_NO_PAD.decode(signature_b64).ok()?;
    if signature.is_empty() {
        return None;
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload.is_object().then_some(payload)
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

fn cookie_expiry(raw_cookie: &str) -> Result<CookieExpiry, MintError> {
    let token = raw_cookie
        .split(';')
        .find_map(|pair| {
            pair.trim()
                .strip_prefix(SESSION_COOKIE_NAME)?
                .strip_prefix('=')
        })
        .or_else(|| {
            let token = raw_cookie.trim();
            (!token.contains('=') && token.split('.').count() == 3).then_some(token)
        })
        .ok_or(MintError::MissingSessionCookie)?;
    let exp = decode_jwt_payload(token)
        .and_then(|payload| payload.get("exp")?.as_i64())
        .ok_or(MintError::InvalidSessionCookie)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0);
    if exp <= now {
        Ok(CookieExpiry::Expired(now - exp))
    } else {
        Ok(CookieExpiry::Valid(exp - now))
    }
}

pub(crate) fn fetch_cloud_id(agent: &ureq::Agent, site: &Url) -> Result<String, MintError> {
    let mut url = site.clone();
    url.set_path("/_edge/tenant_info");
    let mut response =
        agent
            .get(url.as_str())
            .call()
            .map_err(|source| MintError::TenantInfoRequest {
                url: url.clone(),
                source: Box::new(source),
            })?;
    let status = response.status().as_u16();
    let body =
        response
            .body_mut()
            .read_to_string()
            .map_err(|source| MintError::TenantInfoResponse {
                url: url.clone(),
                source: Box::new(source),
            })?;
    if status >= 400 {
        return Err(MintError::TenantInfoStatus { url, status, body });
    }

    let info: TenantInfo = serde_json::from_str(&body)
        .map_err(|source| MintError::TenantInfoInvalidJson { url, body, source })?;
    Ok(info.cloud_id)
}

pub(crate) fn post_graphql<V, T>(
    agent: &ureq::Agent,
    request: &GraphqlRequest<V>,
) -> Result<T, MintError>
where
    V: Serialize,
    T: DeserializeOwned,
{
    let operation_name = request.operation_name.clone();
    let mut response = agent
        .post(GRAPHQL_ENDPOINT)
        .send_json(request)
        .map_err(|source| MintError::GraphqlRequest {
            operation_name: operation_name.clone(),
            source: Box::new(source),
        })?;
    let status = response.status().as_u16();
    let body =
        response
            .body_mut()
            .read_to_string()
            .map_err(|source| MintError::GraphqlResponse {
                operation_name: operation_name.clone(),
                source: Box::new(source),
            })?;
    if status >= 400 {
        return Err(MintError::GraphqlHttpStatus {
            operation_name,
            status,
            body,
        });
    }

    let response: serde_json::Value = serde_json::from_str(&body).map_err(|source| {
        warn!(%operation_name, response_body = %body, "GraphQL response was not valid JSON");
        MintError::GraphqlInvalidJson {
            operation_name: operation_name.clone(),
            body: body.clone(),
            source,
        }
    })?;
    if let Some(errors) = response.get("errors").filter(|errors| !errors.is_null()) {
        let errors: Vec<GraphqlErrorObject> =
            serde_json::from_value(errors.clone()).map_err(|source| {
                MintError::GraphqlInvalidJson {
                    operation_name: operation_name.clone(),
                    body: body.clone(),
                    source,
                }
            })?;
        if !errors.is_empty() {
            return Err(MintError::GraphqlRejected {
                operation_name,
                errors,
            });
        }
    }

    let response: GraphqlData<T> =
        serde_json::from_value(response).map_err(|source| MintError::GraphqlInvalidJson {
            operation_name,
            body,
            source,
        })?;
    Ok(response.data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct HeaderAssertions;

    impl Middleware for HeaderAssertions {
        fn handle(
            &self,
            request: Request<SendBody<'_>>,
            _next: MiddlewareNext<'_>,
        ) -> Result<Response<Body>, ureq::Error> {
            let (response_body, has_graphql_headers) = if request.uri() == GRAPHQL_ENDPOINT {
                (r#"{"data":{"value":1}}"#, true)
            } else {
                assert_eq!(request.uri(), "https://foo.jira-dev.com/_edge/tenant_info");
                (r#"{"cloudId":"cloud-1"}"#, false)
            };
            let cookie = request
                .headers()
                .get(COOKIE)
                .and_then(|value| value.to_str().ok());
            let origin = request
                .headers()
                .get(ORIGIN)
                .and_then(|value| value.to_str().ok());
            if has_graphql_headers {
                assert_eq!(cookie, Some("tenant.session.token=test"));
                assert_eq!(origin, Some(GRAPHQL_ORIGIN));
            } else {
                assert_eq!(cookie, None);
                assert_eq!(origin, None);
            }

            Ok(Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(Body::builder().data(response_body))
                .unwrap())
        }
    }

    fn response_agent(status: u16, body: impl Into<String>) -> ureq::Agent {
        let body = body.into();
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .middleware(
                move |_request: Request<SendBody<'_>>, _next: MiddlewareNext<'_>| {
                    Ok(Response::builder()
                        .status(status)
                        .header("Content-Type", "application/json")
                        .body(Body::builder().data(body.clone()))
                        .unwrap())
                },
            )
            .build()
            .into()
    }

    fn request() -> GraphqlRequest<serde_json::Value> {
        GraphqlRequest {
            operation_name: "Test".into(),
            query: "query Test { value }".into(),
            variables: json!({}),
        }
    }

    #[test]
    fn graphql_headers_are_only_sent_to_the_https_graphql_endpoint() {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .middleware(GraphqlHeaders::new("tenant.session.token=test".into()).unwrap())
            .middleware(HeaderAssertions)
            .build()
            .into();

        assert_eq!(
            fetch_cloud_id(&agent, &Url::parse("https://foo.jira-dev.com").unwrap()).unwrap(),
            "cloud-1"
        );
        let data: serde_json::Value = post_graphql(&agent, &request()).unwrap();
        assert_eq!(data, json!({ "value": 1 }));
    }

    #[test]
    fn post_graphql_returns_generic_required_data() {
        #[derive(Deserialize)]
        struct Data {
            value: u8,
        }

        let data: Data = post_graphql(
            &response_agent(200, r#"{"data":{"value":7},"errors":null}"#),
            &request(),
        )
        .unwrap();
        assert_eq!(data.value, 7);
    }

    #[test]
    fn post_graphql_preserves_error_objects_with_nullable_messages() {
        let error = post_graphql::<_, serde_json::Value>(
            &response_agent(
                200,
                r#"{"errors":[{"message":"denied"},{"message":null},{}]}"#,
            ),
            &request(),
        )
        .unwrap_err();

        let MintError::GraphqlRejected { errors, .. } = error else {
            panic!("unexpected error variant")
        };
        assert_eq!(errors.len(), 3);
        assert_eq!(errors[0].message.as_deref(), Some("denied"));
        assert_eq!(errors[1].message, None);
        assert_eq!(errors[2].message, None);
    }

    #[test]
    fn graphql_error_display_uses_structured_fields() {
        let error = MintError::GraphqlRejected {
            operation_name: "MutationUnderTest".into(),
            errors: vec![GraphqlErrorObject {
                message: Some("denied".into()),
            }],
        };

        let display = error.to_string();
        assert!(display.contains("MutationUnderTest"));
        assert!(display.contains("denied"));
    }

    #[test]
    fn missing_required_graphql_fields_fail_deserialization() {
        #[derive(Deserialize)]
        struct Data {
            #[allow(dead_code)]
            value: u8,
        }

        for body in [r#"{"errors":[]}"#, r#"{"data":{}}"#, r#"{"data":null}"#] {
            assert!(matches!(
                post_graphql::<_, Data>(&response_agent(200, body), &request()),
                Err(MintError::GraphqlInvalidJson { .. })
            ));
        }
    }

    #[test]
    fn graphql_http_errors_retain_status() {
        let error =
            post_graphql::<_, serde_json::Value>(&response_agent(503, "unavailable"), &request())
                .unwrap_err();
        assert!(matches!(
            error,
            MintError::GraphqlHttpStatus {
                status: 503,
                body,
                ..
            } if body == "unavailable"
        ));
    }
}
