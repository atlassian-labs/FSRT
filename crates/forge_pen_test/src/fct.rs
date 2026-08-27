//! Forge Context Token request construction and minting.

use serde::Deserialize;
use tracing::{debug, info};

use crate::{ForgePenTester, GraphqlErrorObject, GraphqlRequest, PenTestError};

const FCT_MUTATION: &str = r#"mutation SignForgeContextToken($input: GlobalAppSignForgeContextTokensInput!) {
  globalApp_signForgeContextTokens(input: $input) {
    success
    errors {
      message
    }
    tokens {
      jwt
    }
  }
}"#;

const FCT_OPERATION_NAME: &str = "SignForgeContextToken";

#[derive(Debug, Deserialize)]
struct FctData {
    #[serde(rename = "globalApp_signForgeContextTokens")]
    result: FctResult,
}

#[derive(Debug, Deserialize)]
struct FctResult {
    success: bool,
    errors: Vec<GraphqlErrorObject>,
    tokens: Vec<ForgeContextToken>,
}

#[derive(Debug, Deserialize)]
struct ForgeContextToken {
    jwt: String,
}

impl ForgePenTester<'_, '_> {
    /// Constructs the exact GraphQL request that `mint_fct` will send.
    pub fn mint_fct_request(
        &self,
        module_key: &str,
        ctx: &serde_json::Value,
    ) -> Result<GraphqlRequest<serde_json::Value>, PenTestError> {
        if !ctx.is_object() {
            return Err(PenTestError::InvalidFctContext);
        }
        let extension = self.config().extension_for_module_key(module_key)?;
        info!(
            module_key = ?module_key,
            deployment_id = ?extension.deployment_id(),
            extension_id = ?extension.extension_id(),
            extension_type = ?extension.extension_type(),
            "selected deployed extension"
        );
        Ok(GraphqlRequest {
            operation_name: FCT_OPERATION_NAME.to_string(),
            query: FCT_MUTATION.to_string(),
            variables: serde_json::json!({
                "input": {
                    "contextIds": [self.config().context_id()],
                    "extensionContexts": [{
                        "appVersion": self.config().app_version(),
                        "context": ctx,
                        "extensionId": extension.extension_id(),
                        "extensionType": extension.extension_type(),
                        "installationId": self.config().installation_id()
                    }]
                }
            }),
        })
    }

    /// Mints a new FCT and replaces the cache only on success.
    pub fn mint_fct(
        &self,
        module_key: &str,
        ctx: &serde_json::Value,
    ) -> Result<String, PenTestError> {
        let request = self.mint_fct_request(module_key, ctx)?;
        let variables = format!("{:#}", request.variables);
        info!(variables = %variables, "FCT GraphQL variables");
        let data: FctData = self.post_graphql_mutation(&request)?;
        let FctResult {
            success,
            errors,
            tokens,
        } = data.result;
        if !success || !errors.is_empty() {
            return Err(PenTestError::MintRejected { success, errors });
        }

        let jwt = tokens
            .into_iter()
            .next()
            .map(|token| token.jwt)
            .ok_or(PenTestError::MissingFctToken)?;
        self.replace_cached_fct_jwt(&jwt);
        debug!("successfully minted Forge Context Token");
        Ok(jwt)
    }
}
