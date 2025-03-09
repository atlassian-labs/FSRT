use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::permissions_resolver::{PermissionHashMap, RequestType};

/// PermissionsHashMap serialization
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializablePermissionHashMap {
    map: HashMap<String, Vec<String>>,
}

impl From<&PermissionHashMap> for SerializablePermissionHashMap {
    fn from(original: &PermissionHashMap) -> Self {
        let map = original
            .iter()
            .map(|((url, req), v)| (format!("{}::{:?}", url, req), v.clone()))
            .collect();
        Self { map }
    }
}

impl From<SerializablePermissionHashMap> for PermissionHashMap {
    fn from(serialized: SerializablePermissionHashMap) -> Self {
        let deserialized_map: PermissionHashMap = serialized
            .map
            .into_iter()
            .filter_map(|(key, v)| {
                let mut parts = key.split("::");
                let url = parts.next();
                let req = parts.next();
                if let (Some(url), Some(req)) = (url, req) {
                    match req.parse::<RequestType>() {
                        Ok(req_type) => Some(((url.to_string(), req_type), v)),
                        Err(_) => {
                            panic!("Failed to parse RequestType from: {}", req);
                        }
                    }
                } else {
                    panic!("Failed to split key: {}", key);
                }
            })
            .collect();
        deserialized_map
    }
}

/// Regex HashMap serialization
pub trait ToStringMap {
    fn to_string_map(&self) -> HashMap<String, String>;
    fn from_string_map(map: HashMap<String, String>) -> Self;
}

impl ToStringMap for HashMap<String, Regex> {
    fn to_string_map(&self) -> HashMap<String, String> {
        self.iter()
            .map(|(key, regex)| (key.clone(), regex.to_string())) // Convert Regex to String
            .collect()
    }

    fn from_string_map(map: HashMap<String, String>) -> Self {
        map.into_iter()
            .filter_map(|(key, value)| {
                Regex::new(&value).ok().map(|regex| (key, regex)) // Convert String to Regex
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::permissions_resolver::{PermissionHashMap, RequestType};
    use std::collections::HashMap;

    #[test]
    fn test_serializable_permission_hash_map() {
        let mut original_map: PermissionHashMap = HashMap::new();
        original_map.insert(
            (
                "/wiki/rest/api/content/{id}/property/{key}".to_string(),
                RequestType::Post,
            ),
            vec![
                "read:content.property:confluence".to_string(),
                "write:confluence-props".to_string(),
            ],
        );
        original_map.insert(
            (
                "/wiki/rest/api/space/{spaceKey}/settings".to_string(),
                RequestType::Put,
            ),
            vec!["write:confluence-space".to_string()],
        );
        let serializable: SerializablePermissionHashMap = (&original_map).into();
        let map_converted_back: PermissionHashMap = serializable.into();
        assert_eq!(original_map, map_converted_back);
    }

    #[test]
    fn test_to_string_map() {
        let mut original_map: HashMap<String, Regex> = HashMap::new();
        original_map.insert("key1".to_string(), Regex::new(r"^\d+$").unwrap());
        original_map.insert("key2".to_string(), Regex::new(r"^\w+$").unwrap());

        let string_map = original_map.to_string_map();
        let deserialized_map = HashMap::<String, Regex>::from_string_map(string_map);

        assert_eq!(original_map.len(), deserialized_map.len());
        for (key, regex) in original_map {
            assert_eq!(regex.as_str(), deserialized_map.get(&key).unwrap().as_str());
        }
    }
}
