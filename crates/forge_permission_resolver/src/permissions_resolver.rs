use regex::Regex;
use serde::Deserialize;
use serde_json;
use std::{cmp::Reverse, collections::HashMap, hash::Hash, vec};
use tracing::warn;
use ureq;

pub type PermissionHashMap = HashMap<(String, RequestType), Vec<String>>;

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct SwaggerReponse {
    #[serde(default)]
    paths: HashMap<String, Endpoint>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct Endpoint {
    #[serde(default)]
    get: Option<RequestDetails>,
    #[serde(default)]
    put: Option<RequestDetails>,
    #[serde(default)]
    patch: Option<RequestDetails>,
    #[serde(default)]
    post: Option<RequestDetails>,
    #[serde(default)]
    delete: Option<RequestDetails>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct RequestDetails {
    #[serde(
        rename(
            deserialize = "x-atlassian-oauth2-scopes",
            deserialize = "x-atlassian-oauth2-scopes"
        ),
        default
    )]
    permission: Vec<PermissionData>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct PermissionData {
    // TODO: Replace these with the ForgePermissionEnum once it is merged in
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Hash, PartialEq, Eq, Debug)]
pub enum RequestType {
    Get,
    Patch,
    Post,
    Put,
    Delete,
}

#[derive(Copy, Clone)]
pub enum PermissionType {
    Classic = 0,
    Granular = 1,
}

pub fn check_url_for_permissions(
    permission_map: &PermissionHashMap,
    endpoint_regex: &HashMap<String, Regex>,
    request: RequestType,
    url: &str,
) -> Vec<String> {
    println!("check_url_for_permissions {request:?} {url:?}");

    let mut length_of_regex = endpoint_regex
        .iter()
        .map(|(string, regex)| (regex.as_str().len(), &*string))
        .collect::<Vec<_>>();
    length_of_regex.sort_by_key(|k| Reverse(k.0));

    for (_, endpoint) in length_of_regex {
        let regex = endpoint_regex.get(endpoint).unwrap();
        if regex.is_match(&(url.to_owned() + "-")) {
            return permission_map
                .get(&(endpoint.to_owned(), request))
                .cloned()
                .unwrap_or_default();
        }
    }
    vec![]
}

pub fn get_permission_resolver_jira() -> (PermissionHashMap, HashMap<String, Regex>) {
    let jira_url = "https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json";
    return get_permission_resolver(jira_url);
}

pub fn get_permission_resolver_confluence() -> (PermissionHashMap, HashMap<String, Regex>) {
    let confluence_url = "https://developer.atlassian.com/cloud/confluence/swagger.v3.json";
    return get_permission_resolver(confluence_url);
}

pub fn get_permission_resolver(url: &str) -> (PermissionHashMap, HashMap<String, Regex>) {
    let mut endpoint_map: PermissionHashMap = HashMap::default();
    let mut endpoint_regex: HashMap<String, Regex> = HashMap::default();

    get_permisions_for(url, &mut endpoint_map, &mut endpoint_regex);

    return (endpoint_map, endpoint_regex);
}

pub fn get_permisions_for(
    url: &str,
    endpoint_map_classic: &mut PermissionHashMap,
    endpoint_regex: &mut HashMap<String, Regex>,
) {
    if let Result::Ok(response) = ureq::get(url).call() {
        let data: SwaggerReponse = response.into_json().unwrap();
        for (key, endpoint_data) in &data.paths {
            let endpoint_data = get_request_type(endpoint_data, key);
            endpoint_data
                .into_iter()
                .for_each(|(key, request, permissions)| {
                    let regex = Regex::new(&find_regex_for_endpoint(&key)).unwrap();

                    endpoint_regex.insert(key.clone(), regex);
                    endpoint_map_classic.insert((key, request), permissions);
                });
        }
    } else {
        warn!("Failed to retreive the permission json");
    }
}

pub fn find_regex_for_endpoint(key: &str) -> String {
    let mut regex_str = String::new();
    let mut prev_index = 0;
    for (i, char) in key.chars().enumerate() {
        if char == '{' {
            regex_str += &key[prev_index..i];
        } else if char == '}' {
            regex_str += ".*";
            prev_index = i + 1;
        } else if i == key.len() {
            regex_str += &key[prev_index..i]
        }
    }

    if prev_index < key.len() {
        regex_str += &key[prev_index..key.len()];
    }

    regex_str.push('-');
    regex_str
}

fn get_request_type(
    endpoint_data: &Endpoint,
    key: &str,
) -> Vec<(String, RequestType, Vec<String>)> {
    let mut all_methods = Vec::new();

    if let Some(endpoint_data) = &endpoint_data.delete {
        all_methods.push((
            key.to_string(),
            RequestType::Delete,
            get_scopes(endpoint_data),
        ));
    }
    if let Some(endpoint_data) = &endpoint_data.patch {
        all_methods.push((
            key.to_string(),
            RequestType::Patch,
            get_scopes(endpoint_data),
        ));
    }
    if let Some(endpoint_data) = &endpoint_data.post {
        all_methods.push((
            key.to_string(),
            RequestType::Post,
            get_scopes(endpoint_data),
        ));
    }
    if let Some(endpoint_data) = &endpoint_data.put {
        all_methods.push((key.to_string(), RequestType::Put, get_scopes(endpoint_data)));
    }
    if let Some(endpoint_data) = &endpoint_data.get {
        all_methods.push((key.to_string(), RequestType::Get, get_scopes(endpoint_data)));
    }

    return all_methods;
}

fn get_scopes(endpoint_data: &RequestDetails) -> Vec<String> {
    return endpoint_data
        .permission
        .clone()
        .into_iter()
        .map(|data| data.scopes)
        .flatten()
        .collect();
}
