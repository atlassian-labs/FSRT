//! Direct Forge resolver invocation support.

use serde::Deserialize;
use serde_json::Value as JsonValue;

use crate::{ForgePenTester, GraphqlErrorObject, GraphqlRequest, MintError};

const INVOKE_MUTATION: &str = r#"mutation InvokeExtension($input: InvokeExtensionInput!) {
  invokeExtension(input: $input) {
    success
    errors {
      message
    }
    response {
      body
    }
  }
}"#;

const INVOKE_OPERATION_NAME: &str = "InvokeExtension";
const RESOLVER_ENTRY_POINT: &str = "resolver";
const REDACTED_FCT: &str = "<FCT selected at runtime>";

#[derive(Debug, Deserialize)]
struct InvokeData {
    #[serde(rename = "invokeExtension")]
    result: Option<InvokeResult>,
}

#[derive(Debug, Deserialize)]
struct InvokeResult {
    #[serde(default)]
    success: bool,
    #[serde(default, deserialize_with = "deserialize_null_vec")]
    errors: Vec<GraphqlErrorObject>,
    response: Option<JsonValue>,
}

fn deserialize_null_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Ok(Option::<Vec<T>>::deserialize(deserializer)?.unwrap_or_default())
}

/// Successful `invokeExtension` response.
#[derive(Debug, Clone, PartialEq)]
pub struct InvocationOutcome {
    response: Option<JsonValue>,
}

impl InvocationOutcome {
    /// Returns the backend response, when one was returned.
    pub fn response(&self) -> Option<&JsonValue> {
        self.response.as_ref()
    }
}

impl ForgePenTester<'_, '_> {
    /// Builds a default invocation context from the resolved deployment.
    pub fn default_invoke_context(&self, module_key: &str) -> Result<JsonValue, MintError> {
        let extension = self.config().extension_for_module_key(module_key)?;
        let cloud_id = self
            .config()
            .context_id()
            .split_once("::site/")
            .map(|(_, cloud_id)| cloud_id)
            .filter(|cloud_id| !cloud_id.is_empty())
            .ok_or_else(|| {
                MintError::InvocationFailed(format!(
                    "could not derive cloud ID from context '{}'",
                    self.config().context_id()
                ))
            })?;
        let environment_id = extension
            .extension_id()
            .strip_prefix("ari:cloud:ecosystem::extension/")
            .and_then(|value| value.split('/').nth(1))
            .filter(|environment_id| !environment_id.is_empty())
            .ok_or_else(|| {
                MintError::InvocationFailed(format!(
                    "could not derive environment ID from extension '{}'",
                    extension.extension_id()
                ))
            })?;

        Ok(serde_json::json!({
            "appVersion": self.config().app_version(),
            "cloudId": cloud_id,
            "environmentId": environment_id,
            "extension": { "type": extension.extension_type() },
            "moduleKey": extension.module_key(),
            "siteUrl": self.site().as_str(),
        }))
    }

    /// Constructs the exact GraphQL request used to invoke an extension.
    pub fn invoke_extension_request(
        &self,
        module_key: &str,
        function_key: &str,
        extension_payload: &JsonValue,
        ctx: &JsonValue,
        context_token: &str,
        invoke_async: bool,
    ) -> Result<GraphqlRequest<JsonValue>, MintError> {
        let extension = self.config().extension_for_module_key(module_key)?;
        let function_key = function_key.trim();
        if function_key.is_empty() {
            return Err(MintError::InvocationFailed(
                "resolver function key must not be empty".to_string(),
            ));
        }
        if !ctx.is_object() {
            return Err(MintError::InvalidFctContext);
        }
        if context_token.trim().is_empty() {
            return Err(MintError::EmptySuppliedFct);
        }

        Ok(GraphqlRequest {
            operation_name: INVOKE_OPERATION_NAME.to_string(),
            query: INVOKE_MUTATION.to_string(),
            variables: serde_json::json!({
                "input": {
                    "async": invoke_async,
                    "contextIds": [self.config().context_id()],
                    "entryPoint": RESOLVER_ENTRY_POINT,
                    "extensionId": extension.extension_id(),
                    "payload": {
                        "call": {
                            "functionKey": function_key,
                            "payload": extension_payload,
                        },
                        "context": ctx,
                        "contextToken": context_token,
                    }
                }
            }),
        })
    }

    /// Mints or reuses an FCT and invokes a resolver-backed extension.
    pub fn invoke_extension(
        &self,
        module_key: &str,
        function_key: &str,
        extension_payload: &JsonValue,
        ctx: &JsonValue,
        context_token: Option<&str>,
        invoke_async: bool,
    ) -> Result<InvocationOutcome, MintError> {
        let request = match context_token {
            Some(context_token) => self.invoke_extension_request(
                module_key,
                function_key,
                extension_payload,
                ctx,
                context_token,
                invoke_async,
            )?,
            None => {
                self.invoke_extension_request(
                    module_key,
                    function_key,
                    extension_payload,
                    ctx,
                    REDACTED_FCT,
                    invoke_async,
                )?;
                let context_token = self.mint_fct(module_key, ctx)?;
                self.invoke_extension_request(
                    module_key,
                    function_key,
                    extension_payload,
                    ctx,
                    &context_token,
                    invoke_async,
                )?
            }
        };
        let data: InvokeData = self.post_graphql_mutation(&request)?;
        let result = data.result.ok_or_else(|| {
            MintError::InvocationFailed("response missing data.invokeExtension".to_string())
        })?;
        if !result.success || !result.errors.is_empty() {
            let messages = result
                .errors
                .into_iter()
                .filter_map(|error| error.message)
                .collect::<Vec<_>>();
            return Err(MintError::InvocationFailed(if messages.is_empty() {
                "server returned an unsuccessful result without an error message".to_string()
            } else {
                messages.join("; ")
            }));
        }

        Ok(InvocationOutcome {
            response: result.response,
        })
    }
}
