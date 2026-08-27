//! Finalized values for an FCT request.

use tracing::warn;

use crate::mint_common::PenTestError;

/// A deployed Forge extension available for FCT minting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionConfig {
    pub(crate) module_key: String,
    pub(crate) deployment_id: String,
    pub(crate) extension_id: String,
    pub(crate) extension_type: String,
}

impl ExtensionConfig {
    /// Returns the module key supplied by the deployment GraphQL response.
    pub fn module_key(&self) -> &str {
        &self.module_key
    }

    /// Returns the extension node ID supplied by the deployment GraphQL response.
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// Returns the deployed extension ID.
    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    /// Returns the deployed extension type.
    pub fn extension_type(&self) -> &str {
        &self.extension_type
    }
}

/// Values required to build FCT mutation variables.
#[derive(Debug)]
pub struct AppConfig {
    pub(crate) context_id: String,
    pub(crate) app_version: String,
    pub(crate) extensions: Vec<ExtensionConfig>,
    pub(crate) installation_id: String,
}

impl AppConfig {
    /// Returns the context ARI.
    pub fn context_id(&self) -> &str {
        &self.context_id
    }

    /// Returns the deployed app version.
    pub fn app_version(&self) -> &str {
        &self.app_version
    }

    /// Returns all deployed extensions captured during tester construction.
    pub fn extensions(&self) -> &[ExtensionConfig] {
        &self.extensions
    }

    /// Returns the unique keys of the deployed Forge remote extensions.
    pub fn remote_keys(&self) -> Vec<String> {
        let mut remote_keys = self
            .extensions
            .iter()
            .filter(|extension| extension.extension_type == "core:remote")
            .map(|extension| extension.module_key.clone())
            .collect::<Vec<_>>();
        remote_keys.sort(); // why need to sort and dedup?
        // make sure this only gets from the node you chose
        remote_keys.dedup();
        remote_keys
    }

    /// Returns the first deployed extension whose key exactly matches `module_key`.
    pub fn extension_for_module_key(
        &self,
        module_key: &str,
    ) -> Result<&ExtensionConfig, PenTestError> {
        let mut matches = self
            .extensions
            .iter()
            .filter(|extension| extension.module_key == module_key);
        let Some(first) = matches.next() else {
            return Err(PenTestError::ModuleKeyNotFound {
                module_key: module_key.to_string(),
                available: self
                    .extensions
                    .iter()
                    .map(|extension| extension.module_key.clone())
                    .collect(),
            });
        };

        let duplicates = matches
            .map(|extension| extension.deployment_id.as_str())
            .collect::<Vec<_>>();
        if !duplicates.is_empty() {
            warn!(
                module_key,
                selected_deployment_id = first.deployment_id,
                duplicate_deployment_ids = ?duplicates,
                "module key matched multiple deployed extensions; using the first"
            );
        }

        Ok(first)
    }

    /// Returns the Forge installation ID.
    pub fn installation_id(&self) -> &str {
        &self.installation_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(module_key: &str, extension_id: &str) -> ExtensionConfig {
        extension_with_type(module_key, extension_id, "jira:issuePanel")
    }

    fn extension_with_type(
        module_key: &str,
        extension_id: &str,
        extension_type: &str,
    ) -> ExtensionConfig {
        ExtensionConfig {
            module_key: module_key.into(),
            deployment_id: extension_id.into(),
            extension_id: extension_id.into(),
            extension_type: extension_type.into(),
        }
    }

    fn config(extensions: Vec<ExtensionConfig>) -> AppConfig {
        AppConfig {
            context_id: "ari:cloud:jira::site/cloud-1".into(),
            app_version: "1.0.0".into(),
            extensions,
            installation_id: "installation-1".into(),
        }
    }

    #[test]
    fn module_keys_are_matched_exactly_without_format_validation() {
        let key = "future:key.with@syntax/segment";
        let config = config(vec![extension(key, "extension-1")]);

        assert_eq!(
            config.extension_for_module_key(key).unwrap().extension_id(),
            "extension-1"
        );
        assert!(
            config
                .extension_for_module_key(&format!(" {key} "))
                .is_err()
        );
    }
    #[test]
    fn duplicate_module_keys_return_the_first_extension() {
        let config = config(vec![
            extension("duplicate", "extension-1"),
            extension("duplicate", "extension-2"),
        ]);

        assert_eq!(
            config
                .extension_for_module_key("duplicate")
                .unwrap()
                .extension_id(),
            "extension-1"
        );
    }

    #[test]
    fn remote_keys_include_unique_core_remote_extensions() {
        let config = config(vec![
            extension_with_type("remote-b", "extension-1", "core:remote"),
            extension_with_type("panel", "extension-2", "jira:issuePanel"),
            extension_with_type("remote-a", "extension-3", "core:remote"),
            extension_with_type("remote-b", "extension-4", "core:remote"),
            extension_with_type("", "extension-5", "core:remote"),
        ]);

        assert_eq!(
            config.remote_keys(),
            vec![
                "".to_string(),
                "remote-a".to_string(),
                "remote-b".to_string()
            ]
        );
    }
}
