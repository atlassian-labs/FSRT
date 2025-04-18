use crate::permissions_resolver::SwaggerResponse;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{env, io};
use tracing::{debug, warn};

const CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 7); // 1 week

fn default_cache_path() -> Option<PathBuf> {
    env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache/fsrt"))
}

/// Struct to hold cache-related settings
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheConfig {
    cache_path: Option<PathBuf>,
}

impl CacheConfig {
    pub fn new(use_cache: bool, cache_path: Option<PathBuf>) -> Self {
        CacheConfig {
            cache_path: if use_cache {
                cache_path.or_else(default_cache_path)
            } else {
                None
            },
        }
    }

    pub fn use_cache(&self) -> bool {
        self.cache_path.is_some()
    }

    pub fn cache_path(&self) -> Option<&Path> {
        self.cache_path.as_deref()
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            cache_path: default_cache_path(),
        }
    }
}


// ...existing code...

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    JiraSoftware,
    JiraServiceManagement,
    Jira,
    Confluence,
    Bitbucket,
}

impl Service {
    pub fn url(&self) -> &'static str {
        match self {
            Service::JiraSoftware => {
                "https://developer.atlassian.com/cloud/jira/software/swagger.v3.json"
            }
            Service::JiraServiceManagement => {
                "https://developer.atlassian.com/cloud/jira/service-desk/swagger.v3.json"
            }
            Service::Jira => {
                "https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json"
            }
            Service::Confluence => {
                "https://developer.atlassian.com/cloud/confluence/swagger.v3.json"
            }
            Service::Bitbucket => "https://api.bitbucket.org/swagger.json",
        }
    }
    pub fn filename(&self) -> &'static str {
        match self {
            Service::JiraSoftware => "jira_software.json",
            Service::JiraServiceManagement => "jira_service_management.json",
            Service::Jira => "jira.json",
            Service::Confluence => "confluence.json",
            Service::Bitbucket => "bitbucket.json",
        }
    }
}
#[derive(Default)]
pub struct PermissionsCache {
    config: CacheConfig,
}

impl PermissionsCache {
    pub fn new(config: CacheConfig) -> Self {
        PermissionsCache { config }
    }

    fn get_cache_path(&self, key: &str) -> Option<PathBuf> {
        self.config.cache_path().map(|path| {
            let mut full_path = path.to_path_buf();
            full_path.push(key);
            full_path
        })
    }

    fn is_cache_valid(&self, path: &PathBuf) -> bool {
        if let Ok(metadata) = fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.elapsed() {
                    if duration < CACHE_EXPIRATION {
                        return true;
                    } else {
                        eprintln!(
                            "Cache file expired: {:?}, duration {:?} is greater than ttl {:?}",
                            path, duration, CACHE_EXPIRATION
                        );
                    }
                } else {
                    eprintln!("Failed to get elapsed time for cache file: {:?}", path);
                }
            } else {
                eprintln!("Failed to get modified time for cache file: {:?}", path);
            }
        } else {
            eprintln!("Failed to get metadata for cache file: {:?}", path);
        }
        false
    }

    pub fn service_api(&self, service: Service) -> SwaggerResponse {
        let url = service.url();
        let filename = service.filename();
        if self.config.use_cache() {
            if let Some(cache_path) = self.get_cache_path(filename) {
                if self.is_cache_valid(&cache_path) {
                    if let Ok(file) = File::open(&cache_path) {
                        if let Ok(swagger_response) = serde_json::from_reader(BufReader::new(file))
                        {
                            return swagger_response;
                        }
                    }
                }
            }
        }
        let resp = ureq::get(url)
            .call()
            .unwrap_or_else(|err| panic!("Failed to fetch swagger url: {url}. error: {err}"));
        let raw = resp
            .into_string()
            .unwrap_or_else(|err| panic!("Failed to parse JSON response from {url}. error: {err}"));
        let swagger: SwaggerResponse = serde_json::from_str(&raw)
            .unwrap_or_else(|err| panic!("Failed to deserialize JSON response: {err}"));
        if self.config.use_cache() {
            if let Some(cache_path) = self.get_cache_path(filename) {
                let cache_dir = cache_path.parent().unwrap();
                if fs::create_dir_all(cache_dir).is_ok() {
                    if let Err(e) = fs::write(&cache_path, raw) {
                        warn!(
                            "Failed to write cache file: {:?}, error: {:?}",
                            cache_path, e
                        );
                    }
                }
            }
        }
        swagger
    }

    pub fn read(&self, key: &str) -> Option<String> {
        let cache_path = self.get_cache_path(key)?.with_extension("json");

        if !self.is_cache_valid(&cache_path) {
            return None;
        }
        debug!("cache_path: {:?}", cache_path);

        fs::read_to_string(&cache_path).ok()
    }

    pub fn set(&self, key: &str, response: &str) -> io::Result<()> {
        if !self.config.use_cache() {
            return Ok(()); // Ignore caching and return success
        }

        let cache_path = self
            .get_cache_path(key)
            .map(|path| path.with_extension("json"))
            .ok_or_else(|| io::Error::other("Invalid cache path"))?;

        let cache_dir = cache_path
            .parent()
            .ok_or_else(|| io::Error::other("Failed to get cache directory"))?;

        fs::create_dir_all(cache_dir)?;
        fs::write(&cache_path, response)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filetime;
    use tempfile::tempdir;

    #[test]
    fn test_cache_read_write() {
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().to_path_buf();
        let config = CacheConfig::new(true, Some(cache_path.clone()));
        let response = r#"{"paths":{}}"#.to_string();
        let cache = PermissionsCache::new(config.clone());

        // Test writing to cache
        assert!(cache.set("test_key", &response).is_ok());

        // Test reading from cache
        let read_response = cache.read("test_key").unwrap();

        assert_eq!(response, read_response);
    }

    #[test]
    fn test_cache_expiration() {
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().to_path_buf();
        let config = CacheConfig::new(true, Some(cache_path.clone()));
        let response = r#"{"paths":{}}"#.to_string();
        let cache = PermissionsCache::new(config.clone());

        // Test writing to cache
        assert!(cache.set("test_key", &response).is_ok());

        // Manually set the cache file's modified time to be expired
        let cache_file_path = cache
            .get_cache_path("test_key")
            .unwrap()
            .with_extension("json");
        let one_week_ago = std::time::SystemTime::now() - CACHE_EXPIRATION - Duration::from_secs(1);
        filetime::set_file_mtime(
            &cache_file_path,
            filetime::FileTime::from_system_time(one_week_ago),
        )
        .unwrap();

        // Test reading from cache should fail due to expiration
        assert!(cache.read("test_key").is_none());
    }

    #[test]
    fn test_cache_disabled() {
        let config = CacheConfig::new(false, None);
        let response = r#"{"paths":{}}"#.to_string();
        let cache = PermissionsCache::new(config);

        // Test writing to cache should return ok even the cache is disabled
        assert!(cache.set("test_key", &response).is_ok());
        // Test reading from cache should fail because cache is disabled
        assert!(cache.read("test_key").is_none());
    }
}
