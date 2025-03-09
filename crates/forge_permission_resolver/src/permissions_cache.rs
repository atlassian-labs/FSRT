use regex::Regex;
use std::collections::HashMap;
use std::env;
use std::path::PathBuf;
use std::time::Duration;

use crate::permissions_resolver::PermissionHashMap;
use crate::serde::{SerializablePermissionHashMap, ToStringMap};
use std::fs::{self, File};
use std::io::{Read, Write};
use tracing::debug;

const CACHE_EXPIRATION: Duration = Duration::from_secs(60 * 60 * 24 * 7); // 1 week

fn default_cache_path() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cache/fsrt")
}

/// Struct to hold cache-related settings
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct CacheConfig {
    use_cache: bool,
    cache_path: Option<PathBuf>,
    ttl: Duration,
}

impl CacheConfig {
    pub fn new(use_cache: bool, cache_path: Option<PathBuf>) -> Self {
        CacheConfig {
            use_cache,
            cache_path: Some(cache_path.unwrap_or_else(default_cache_path)),
            ttl: CACHE_EXPIRATION,
        }
    }

    pub fn use_cache(&self) -> bool {
        self.use_cache
    }

    pub fn cache_path(&self) -> &PathBuf {
        self.cache_path.as_ref().unwrap()
    }
}

pub struct PermissionsCache {
    config: CacheConfig,
}

impl PermissionsCache {
    pub fn new(config: CacheConfig) -> Self {
        PermissionsCache { config }
    }

    fn get_cache_path(&self, key: &str) -> PathBuf {
        let mut path = self.config.cache_path().clone();
        path.push(key);
        path
    }

    fn is_cache_valid(&self, path: &PathBuf) -> bool {
        if let Ok(metadata) = fs::metadata(path) {
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.elapsed() {
                    if duration < self.config.ttl {
                        return true;
                    } else {
                        println!(
                            "Cache file expired: {:?}, duration {:?} is greater than ttl {:?}",
                            path, duration, self.config.ttl
                        );
                    }
                } else {
                    println!("Failed to get elapsed time for cache file: {:?}", path);
                }
            } else {
                println!("Failed to get modified time for cache file: {:?}", path);
            }
        } else {
            println!("Failed to get metadata for cache file: {:?}", path);
        }
        false
    }

    pub fn read(
        &self,
        key: &str,
        permission_map: &mut PermissionHashMap,
        regex_map: &mut HashMap<String, Regex>,
    ) -> bool {
        if !self.config.use_cache() {
            return false;
        }

        let cache_path = self.get_cache_path(key).with_extension("json");

        if !self.is_cache_valid(&cache_path) {
            return false;
        }
        debug!("cache_path: {:?}", cache_path);

        let mut file = match File::open(&cache_path) {
            Ok(file) => file,
            Err(_) => return false,
        };

        let mut contents = String::new();
        if file.read_to_string(&mut contents).is_err() {
            return false;
        }

        match serde_json::from_str::<(SerializablePermissionHashMap, HashMap<String, String>)>(
            &contents,
        ) {
            Ok((perm_map, reg_map)) => {
                *permission_map = perm_map.into();
                *regex_map = HashMap::<String, Regex>::from_string_map(reg_map);
                true
            }
            Err(_) => false,
        }
    }

    pub fn set(
        &self,
        key: &str,
        permission_map: &PermissionHashMap,
        regex_map: &HashMap<String, Regex>,
    ) -> bool {
        if !self.config.use_cache() {
            return false;
        }

        let cache_path = self.get_cache_path(key).with_extension("json");

        let cache_dir = cache_path.parent().unwrap();
        if fs::create_dir_all(cache_dir).is_err() {
            return false;
        }

        let serializable_perm_map: SerializablePermissionHashMap = permission_map.into();
        let serializable_regex_map = regex_map.to_string_map();
        let data =
            serde_json::to_string_pretty(&(serializable_perm_map, serializable_regex_map)).unwrap();

        let mut file = match File::create(&cache_path) {
            Ok(file) => file,
            Err(_) => return false,
        };

        if file.write_all(data.as_bytes()).is_err() {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions_resolver::{PermissionHashMap, RequestType};
    use filetime;
    use tempfile::tempdir;

    #[test]
    fn test_cache_read_write() {
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().to_path_buf();
        let config = CacheConfig::new(true, Some(cache_path.clone()));

        let mut permission_map: PermissionHashMap = HashMap::new();
        permission_map.insert(
            ("/test/path".to_string(), RequestType::Get),
            vec!["read:test".to_string()],
        );

        let mut regex_map: HashMap<String, Regex> = HashMap::new();
        regex_map.insert("test".to_string(), Regex::new(r"^\d+$").unwrap());

        let cache = PermissionsCache::new(config.clone());

        // Test writing to cache
        assert!(cache.set("test_key", &permission_map, &regex_map));

        // Test reading from cache
        let mut read_permission_map: PermissionHashMap = HashMap::new();
        let mut read_regex_map: HashMap<String, Regex> = HashMap::new();
        assert!(cache.read("test_key", &mut read_permission_map, &mut read_regex_map));

        assert_eq!(permission_map, read_permission_map);
        assert_eq!(regex_map.len(), read_regex_map.len());
        for (key, regex) in regex_map {
            assert_eq!(regex.as_str(), read_regex_map.get(&key).unwrap().as_str());
        }
    }

    #[test]
    fn test_cache_expiration() {
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().to_path_buf();
        let config = CacheConfig::new(true, Some(cache_path.clone()));

        let mut permission_map: PermissionHashMap = HashMap::new();
        permission_map.insert(
            ("/test/path".to_string(), RequestType::Get),
            vec!["read:test".to_string()],
        );

        let mut regex_map: HashMap<String, Regex> = HashMap::new();
        regex_map.insert("test".to_string(), Regex::new(r"^\d+$").unwrap());

        let cache = PermissionsCache::new(config.clone());

        // Test writing to cache
        assert!(cache.set("test_key", &permission_map, &regex_map));

        // Manually set the cache file's modified time to be expired
        let cache_file_path = cache.get_cache_path("test_key").with_extension("json");
        let one_week_ago = std::time::SystemTime::now() - CACHE_EXPIRATION - Duration::from_secs(1);
        filetime::set_file_mtime(
            &cache_file_path,
            filetime::FileTime::from_system_time(one_week_ago),
        )
        .unwrap();

        // Test reading from cache should fail due to expiration
        let mut read_permission_map: PermissionHashMap = HashMap::new();
        let mut read_regex_map: HashMap<String, Regex> = HashMap::new();
        assert!(!cache.read("test_key", &mut read_permission_map, &mut read_regex_map));
    }

    #[test]
    fn test_cache_disabled() {
        let temp_dir = tempdir().unwrap();
        let cache_path = temp_dir.path().to_path_buf();
        let config = CacheConfig::new(false, Some(cache_path.clone()));

        let mut permission_map: PermissionHashMap = HashMap::new();
        permission_map.insert(
            ("/test/path".to_string(), RequestType::Get),
            vec!["read:test".to_string()],
        );

        let mut regex_map: HashMap<String, Regex> = HashMap::new();
        regex_map.insert("test".to_string(), Regex::new(r"^\d+$").unwrap());

        let cache = PermissionsCache::new(config.clone());

        // Test writing to cache should fail because cache is disabled
        assert!(!cache.set("test_key", &permission_map, &regex_map));

        // Test reading from cache should fail because cache is disabled
        let mut read_permission_map: PermissionHashMap = HashMap::new();
        let mut read_regex_map: HashMap<String, Regex> = HashMap::new();
        assert!(!cache.read("test_key", &mut read_permission_map, &mut read_regex_map));
    }
}
