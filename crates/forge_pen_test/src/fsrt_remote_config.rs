//! Configuration loaded from `fsrt-remote.toml`.

use std::{fs, path::Path};

use serde::{Deserialize, Deserializer, de::Error as _};
use url::Url;

use crate::mint_common::MintError;

/// Untrusted configuration loaded from `fsrt-remote.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FsrtRemoteConfig {
    /// Full Atlassian site URL.
    #[serde(deserialize_with = "deserialize_https_origin")]
    pub site: Url,

    /// Session-cookie file configuration.
    pub auth: AuthConfig,

    /// Context ARI owner.
    pub product: String,

    /// Optional Forge environment preference used when multiple installations are found.
    pub environment_key: Option<String>,
}

/// Session-cookie file configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    /// File containing the Forge session cookie.
    pub raw_cookie_file: String,
}

impl FsrtRemoteConfig {
    /// Loads untrusted configuration from a TOML file.
    pub fn from_path(config_path: &Path) -> Result<Self, MintError> {
        let contents = fs::read_to_string(config_path).map_err(|source| MintError::FileRead {
            kind: "config",
            path: config_path.to_path_buf(),
            source,
        })?;
        toml::from_str(&contents).map_err(|source| MintError::ConfigParse {
            path: config_path.to_path_buf(),
            source,
        })
    }
}

fn deserialize_https_origin<'de, D>(deserializer: D) -> Result<Url, D::Error>
where
    D: Deserializer<'de>,
{
    let input = String::deserialize(deserializer)?;
    let site = Url::parse(&input).map_err(D::Error::custom)?;
    let valid = site.scheme() == "https"
        && site.host_str().is_some()
        && site.username().is_empty()
        && site.password().is_none()
        && site.path() == "/"
        && site.query().is_none()
        && site.fragment().is_none();
    if !valid {
        return Err(D::Error::custom(
            "site must be an HTTPS URL without credentials, a path, query, or fragment",
        ));
    }

    Ok(site)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(site: &str) -> Result<FsrtRemoteConfig, toml::de::Error> {
        toml::from_str(&format!(
            r#"site = "{site}"
product = "jira"
[auth]
raw_cookie_file = "./session-cookie.txt"
"#
        ))
    }

    #[test]
    fn site_accepts_any_https_host_and_an_explicit_port() {
        for site in [
            "https://foo.jira-dev.com",
            "https://example.atlassian.net/",
            "https://localhost:8443",
        ] {
            assert_eq!(parse(site).unwrap().site, Url::parse(site).unwrap());
        }
    }

    #[test]
    fn site_rejects_non_https_and_non_origin_urls() {
        for site in [
            "http://example.com",
            "example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com?query=value",
            "https://example.com#fragment",
        ] {
            assert!(parse(site).is_err(), "site unexpectedly accepted: {site}");
        }
    }
}
