use serde_yaml;
use std::collections::HashMap;
use tracing::warn;

#[derive(Debug)]
pub struct CompassPermissionResolver {
    api_scopes_map: HashMap<&'static str, Vec<&'static str>>,
}

impl CompassPermissionResolver {
    /// Factory method to create a new `CompassPermissionResolver`
    pub fn new() -> Self {
        let scopes = load_compass_api_scopes();
        CompassPermissionResolver {
            api_scopes_map: scopes,
        }
    }

    /// Retrieves permissions for a given key. Prints a warning if the key is missing.
    pub fn get(&self, key: &str) -> Option<&[&str]> {
        if let Some(scopes) = self.api_scopes_map.get(key) {
            Some(scopes)
        } else {
            warn!(
                "Warning: compass API '{}' not found in the api->scopes mapping.",
                key
            );
            None
        }
    }
}

impl Default for CompassPermissionResolver {
    fn default() -> Self {
        Self::new()
    }
}

// This is for handling https://developer.atlassian.com/cloud/compass/forge-graphql-toolkit/
fn load_compass_api_scopes() -> HashMap<&'static str, Vec<&'static str>> {
    let file = include_str!("../../../compass-scopes.yaml");
    serde_yaml::from_str(file)
        .expect("Error: Failed to parse compass-scopes YAML file. Ensure it is properly formatted.")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_load_compass_api_scopes() {
        let scopes = load_compass_api_scopes();

        // Verify that the scopes are loaded correctly
        assert!(scopes.contains_key("addEventSource"));
        assert_eq!(
            scopes.get("addEventSource").unwrap(),
            &vec![
                "write:component:compass".to_string(),
                "write:event:compass".to_string()
            ]
        );

        assert!(scopes.contains_key("addLabels"));
        assert_eq!(
            scopes.get("addLabels").unwrap(),
            &vec!["write:component:compass".to_string()]
        );
    }
}
