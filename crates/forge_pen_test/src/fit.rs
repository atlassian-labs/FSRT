//! Forge Invocation Token request construction and minting.

use serde::Deserialize;
use tracing::{debug, info};

use crate::{ForgePenTester, GraphqlRequest, PenTestError};

const FIT_MUTATION: &str = r#"mutation SignInvocationTokenForUI($input: SignInvocationTokenForUIInput!) {
  signInvocationTokenForUI(input: $input) {
    forgeInvocationToken {
      jwt
    }
  }
}"#;

const FIT_OPERATION_NAME: &str = "SignInvocationTokenForUI";
const REDACTED_FCT: &str = "<FCT selected at runtime>";

#[derive(Debug, Deserialize)]
struct FitData {
    #[serde(rename = "signInvocationTokenForUI")]
    result: Option<FitResult>,
}

#[derive(Debug, Deserialize)]
struct FitResult {
    #[serde(rename = "forgeInvocationToken")]
    token: Option<ForgeInvocationToken>,
}

#[derive(Debug, Deserialize)]
struct ForgeInvocationToken {
    jwt: String,
}

impl ForgePenTester<'_, '_> {
    /// Constructs the exact GraphQL request used to mint a FIT.
    pub fn mint_fit_request(
        &self,
        fct: &str,
        remote_key: &str,
    ) -> Result<GraphqlRequest<serde_json::Value>, PenTestError> {
        if fct.trim().is_empty() {
            return Err(PenTestError::EmptySuppliedFct);
        }

        Ok(GraphqlRequest {
            operation_name: FIT_OPERATION_NAME.to_string(),
            query: FIT_MUTATION.to_string(),
            variables: serde_json::json!({
                "input": {
                    "forgeContextToken": fct,
                    "remoteKey": remote_key
                }
            }),
        })
    }

    /// Mints a FIT for a Forge remote using the supplied FCT.
    pub fn mint_fit(&self, remote_key: &str, fct: &str) -> Result<String, PenTestError> {
        let request = self.mint_fit_request(fct, remote_key)?;
        let mut variables = request.variables.clone();
        variables["input"]["forgeContextToken"] = REDACTED_FCT.into();
        let variables = format!("{variables:#}");
        info!(
            operation_name = FIT_OPERATION_NAME,
            variables = %variables,
            "FIT GraphQL variables"
        );
        let token = (|| {
            let data: FitData = self.post_graphql_mutation(&request)?;
            data.result
                .and_then(|result| result.token)
                .map(|token| token.jwt)
                .ok_or(PenTestError::MissingFitToken)
        })()
        .map_err(|source| PenTestError::FitMintFailed {
            source: Box::new(source),
            available: self.config().remote_keys(),
        })?;
        debug!("successfully minted Forge Invocation Token");
        Ok(token)
    }
}
