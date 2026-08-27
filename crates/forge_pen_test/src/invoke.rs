//! Direct Forge resolver invocation support.

use serde::Deserialize;
use serde_json::Value as JsonValue;
use tracing::info;

use crate::{ForgePenTester, GraphqlErrorObject, GraphqlRequest, PenTestError};

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

#[derive(Debug, Deserialize)]
struct InvokeData {
    #[serde(rename = "invokeExtension")]
    result: Option<InvokeResult>,
}

#[derive(Debug, Deserialize)]
struct InvokeResult {
    #[serde(default)]
    success: bool,
    errors: Option<Vec<GraphqlErrorObject>>,
    response: Option<JsonValue>,
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
    /// Constructs the exact GraphQL request used to invoke a deployed module.
    pub fn invoke_extension_request(
        &self,
        module_key: &str,
        function_key: &str,
        extension_payload: Option<&JsonValue>,
        ctx: &JsonValue,
        context_token: &str,
    ) -> Result<GraphqlRequest<JsonValue>, PenTestError> {
        if context_token.trim().is_empty() {
            return Err(PenTestError::EmptySuppliedFct);
        }
        let extension = self.config().extension_for_module_key(module_key)?;
        let function_key = function_key
            .strip_prefix("resolver.")
            .unwrap_or(function_key);
        let mut call = serde_json::json!({ "functionKey": function_key });
        if let Some(extension_payload) = extension_payload {
            call.as_object_mut()
                .expect("resolver call must be a JSON object")
                .insert("payload".to_string(), extension_payload.clone());
        }

        Ok(GraphqlRequest {
            operation_name: INVOKE_OPERATION_NAME.to_string(),
            query: INVOKE_MUTATION.to_string(),
            variables: serde_json::json!({
                "input": {
                    "contextIds": [self.config().context_id()],
                    "entryPoint": RESOLVER_ENTRY_POINT,
                    "extensionId": extension.extension_id(),
                    "payload": {
                        "call": call,
                        "context": ctx,
                        "contextToken": context_token,
                    }
                }
            }),
        })
    }

    /// Invokes a resolver-backed extension with an existing FCT.
    pub fn invoke_extension(
        &self,
        module_key: &str,
        function_key: &str,
        extension_payload: Option<&JsonValue>,
        ctx: &JsonValue,
        context_token: &str,
    ) -> Result<InvocationOutcome, PenTestError> {
        let request = self.invoke_extension_request(
            module_key,
            function_key,
            extension_payload,
            ctx,
            context_token,
        )?;
        let variables = format!("{:#}", request.variables);
        info!(
            operation_name = INVOKE_OPERATION_NAME,
            variables = %variables,
            "InvokeExtension GraphQL variables"
        );
        let data: InvokeData = self.post_graphql_mutation(&request)?;
        let result = data.result.ok_or_else(|| {
            PenTestError::InvocationFailed("response missing data.invokeExtension".to_string())
        })?;
        let errors = result.errors.unwrap_or_default();
        if !result.success || !errors.is_empty() {
            let messages = errors
                .into_iter()
                .filter_map(|error| error.message)
                .collect::<Vec<_>>();
            return Err(PenTestError::InvocationFailed(if messages.is_empty() {
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
