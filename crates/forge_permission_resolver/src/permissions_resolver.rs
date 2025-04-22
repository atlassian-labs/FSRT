use crate::{
    permissions_cache::{CacheConfig, PermissionsCache, Service},
    permissions_resolver_compass::CompassPermissionResolver,
};

use regex::Regex;
use serde::Deserialize;
use std::{
    cmp::Reverse,
    collections::{HashMap, HashSet},
    hash::Hash,
    mem,
    str::FromStr,
};
use tracing::debug;

pub type PermissionHashMap = HashMap<(String, RequestType), Vec<String>>;

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SwaggerResponse {
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

    // For parsing Jira Software as that swagger doesn't follow "x-atlassian-oauth2-scopes" scope style
    #[serde(default)]
    security: Vec<SecurityData>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct PermissionData {
    // TODO: Replace these with the ForgePermissionEnum once it is merged in
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
struct SecurityData {
    #[serde(default, rename = "OAuth2")]
    oauth2: Vec<String>,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug, Deserialize)]
pub enum RequestType {
    Get,
    Patch,
    Post,
    Put,
    Delete,
}

// Implement `FromStr` for RequestType
impl FromStr for RequestType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "get" => Ok(RequestType::Get),
            "post" => Ok(RequestType::Post),
            "patch" => Ok(RequestType::Patch),
            "put" => Ok(RequestType::Put),
            "delete" => Ok(RequestType::Delete),
            _ => Err(()),
        }
    }
}

#[derive(Copy, Clone)]
pub enum PermissionType {
    Classic = 0,
    Granular = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct EndpointPerms {
    get: Vec<String>,
    put: Vec<String>,
    post: Vec<String>,
    delete: Vec<String>,
    patch: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct PermMap {
    // path id -> matcher, perms
    paths: Vec<(Regex, EndpointPerms)>,
    // scope -> possible matching urls
    possible_urls: HashMap<String, Vec<u32>>,
    declared_scopes: Vec<String>,
    unused_scopes: Vec<String>,
}

impl EndpointPerms {
    fn is_empty(&self) -> bool {
        self.get.is_empty()
            && self.put.is_empty()
            && self.post.is_empty()
            && self.delete.is_empty()
            && self.patch.is_empty()
    }

    fn perms(&self) -> impl Iterator<Item = &str> + '_ {
        self.get
            .iter()
            .chain(self.put.iter())
            .chain(self.post.iter())
            .chain(self.delete.iter())
            .chain(self.patch.iter())
            .map(String::as_str)
    }
}

impl RequestDetails {
    fn matching_paths(self, scopes: &HashSet<&str>) -> Vec<String> {
        let mut permissions = self
            .permission
            .into_iter()
            .flat_map(|p| p.scopes)
            .filter(|s| scopes.contains(&**s))
            .collect::<Vec<_>>();
        for perm in self.security.into_iter().flat_map(|s| s.oauth2) {
            if scopes.contains(&*perm) && !permissions.contains(&perm) {
                permissions.push(perm);
            }
        }
        permissions
    }
}

impl PermMap {
    pub fn new(scopes: &HashSet<&str>) -> Self {
        let permissions_cache = PermissionsCache::default();
        let jira_software = permissions_cache.service_api(Service::JiraSoftware);
        let jira_service_management = permissions_cache.service_api(Service::JiraServiceManagement);
        let jira = permissions_cache.service_api(Service::Jira);
        let confluence = permissions_cache.service_api(Service::Confluence);
        let bitbucket = permissions_cache.service_api(Service::Bitbucket);
        Self::with_iter(
            jira_software
                .paths
                .into_iter()
                .chain(jira_service_management.paths)
                .chain(jira.paths)
                .chain(confluence.paths)
                .chain(bitbucket.paths),
            scopes,
        )
    }

    #[inline]
    pub fn declared_scopes(&self) -> &[String] {
        &self.declared_scopes
    }

    #[inline]
    pub fn unused_scopes(&self) -> &[String] {
        &self.unused_scopes
    }

    #[inline]
    pub fn clear_scopes(&mut self) {
        self.unused_scopes.clear();
    }

    pub fn clear_readonly_scopes(&mut self) {
        self.unused_scopes.retain(|s| s.contains("write:"));
    }

    fn with_iter(
        resp: impl IntoIterator<Item = (String, Endpoint)>,
        scopes: &HashSet<&str>,
    ) -> Self {
        let declared_scopes = scopes.iter().map(|&s| s.to_owned()).collect::<Vec<_>>();
        let unused_scopes = declared_scopes.clone();
        let mut this = Self {
            paths: vec![],
            possible_urls: scopes
                .iter()
                .map(|&s| (s.to_owned(), Vec::<u32>::new()))
                .collect::<HashMap<_, Vec<_>>>(),
            declared_scopes,
            unused_scopes,
        };
        for (path, endpoint) in resp {
            let mut endpoint_perms = EndpointPerms::default();
            if let Some(get) = endpoint.get {
                endpoint_perms.get = get.matching_paths(scopes);
            }
            if let Some(put) = endpoint.put {
                endpoint_perms.put = put.matching_paths(scopes);
            }
            if let Some(post) = endpoint.post {
                endpoint_perms.post = post.matching_paths(scopes);
            }
            if let Some(delete) = endpoint.delete {
                endpoint_perms.delete = delete.matching_paths(scopes);
            }
            if let Some(patch) = endpoint.patch {
                endpoint_perms.patch = patch.matching_paths(scopes);
            }
            if endpoint_perms.is_empty() {
                continue;
            }
            let regex = Regex::new(&find_regex_for_endpoint(&path)).unwrap();
            this.paths.push((regex, endpoint_perms));
        }
        this.paths
            .sort_unstable_by_key(|(regex, _)| Reverse(regex.as_str().len()));
        for (idx, endpoint_perms) in this.paths.iter().map(|(_, perms)| perms).enumerate() {
            for scope in endpoint_perms.perms() {
                this.possible_urls.get_mut(scope).unwrap().push(idx as u32);
            }
        }
        this
    }

    pub fn use_scope(&mut self, url: String, request: RequestType) {
        let mut unused_scopes = mem::take(&mut self.unused_scopes);
        for scope in self.matching_scopes(url, request) {
            unused_scopes.retain(|s| s != scope);
        }
        self.unused_scopes = unused_scopes;
    }

    pub fn use_all_scopes(&mut self, url: String) {
        let mut unused_scopes = mem::take(&mut self.unused_scopes);
        for scope in self.all_scopes_for_url(url) {
            unused_scopes.retain(|s| s != scope);
        }
        self.unused_scopes = unused_scopes;
    }

    pub fn matching_scopes(
        &self,
        mut url: String,
        request_type: RequestType,
    ) -> impl Iterator<Item = &str> + '_ {
        if let Some(x) = url.find('?') {
            url.truncate(x)
        }
        url.push('-');
        self.paths
            .iter()
            .flat_map(move |(regex, endpoint_perms)| {
                if !regex.is_match(&url) {
                    return [].iter();
                }
                match request_type {
                    RequestType::Get => endpoint_perms.get.iter(),
                    RequestType::Put => endpoint_perms.put.iter(),
                    RequestType::Post => endpoint_perms.post.iter(),
                    RequestType::Delete => endpoint_perms.delete.iter(),
                    RequestType::Patch => endpoint_perms.patch.iter(),
                }
            })
            .map(String::as_str)
    }

    pub fn all_scopes_for_url(&self, mut url: String) -> impl Iterator<Item = &str> + '_ {
        static EMPTY: EndpointPerms = EndpointPerms {
            get: vec![],
            put: vec![],
            post: vec![],
            delete: vec![],
            patch: vec![],
        };
        if let Some(x) = url.find('?') {
            url.truncate(x);
        }
        url.push('-');
        self.paths.iter().flat_map(move |(regex, endpoint_perms)| {
            if !regex.is_match(&url) {
                return EMPTY.perms();
            }
            endpoint_perms.perms()
        })
    }

    pub fn possible_urls_for_scope(
        &self,
        scope: &str,
    ) -> impl Iterator<Item = &Regex> + use<'_> + '_ {
        self.possible_urls
            .get(scope)
            .into_iter()
            .flatten()
            .map(|&v| &self.paths[v as usize].0)
    }
}

pub fn check_url_for_permissions(
    permission_map: &PermissionHashMap,
    endpoint_regex: &HashMap<String, Regex>,
    request: RequestType,
    url: &str,
) -> Vec<String> {
    // sort by the length of regex
    let mut length_of_regex = endpoint_regex
        .iter()
        .map(|(string, regex)| (regex.as_str().len(), string))
        .collect::<Vec<_>>();
    length_of_regex.sort_by_key(|k| Reverse(k.0));
    let url_prefix = format!("{url}-");

    for (_, endpoint) in length_of_regex {
        let regex = endpoint_regex.get(endpoint).unwrap();
        if regex.is_match(&url_prefix) {
            return permission_map
                .get(&(endpoint.to_owned(), request))
                .cloned()
                .unwrap_or_default();
        }
    }
    vec![]
}

pub fn get_permission_resolver_jira_any(
    config: &CacheConfig,
) -> (PermissionHashMap, HashMap<String, Regex>) {
    // Combine all Jira variations to achieve a generic "any" Jira
    let (jira_map, jira_regex) = get_permission_resolver_jira(config);
    let (jsm_map, jsm_regex) = get_permission_resolver_jira_service_management(config);
    let (js_map, js_regex) = get_permission_resolver_jira_software(config);

    let mut combined_permission_map = PermissionHashMap::default();
    let mut combined_regex_map = HashMap::default();

    combined_permission_map.extend(jira_map);
    combined_permission_map.extend(jsm_map);
    combined_permission_map.extend(js_map);

    combined_regex_map.extend(jira_regex);
    combined_regex_map.extend(jsm_regex);
    combined_regex_map.extend(js_regex);

    (combined_permission_map, combined_regex_map)
}

pub fn get_permission_resolver_jira_software(
    config: &CacheConfig,
) -> (PermissionHashMap, HashMap<String, Regex>) {
    let jira_software_url = "https://developer.atlassian.com/cloud/jira/software/swagger.v3.json";
    get_permission_resolver(jira_software_url, "jira_software", config)
}

pub fn get_permission_resolver_jira_service_management(
    config: &CacheConfig,
) -> (PermissionHashMap, HashMap<String, Regex>) {
    let jira_service_management_url =
        "https://developer.atlassian.com/cloud/jira/service-desk/swagger.v3.json";
    get_permission_resolver(
        jira_service_management_url,
        "jira_service_management",
        config,
    )
}

pub fn get_permission_resolver_jira(
    config: &CacheConfig,
) -> (PermissionHashMap, HashMap<String, Regex>) {
    let jira_url = "https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json";
    get_permission_resolver(jira_url, "jira", config)
}

pub fn get_permission_resolver_confluence(
    config: &CacheConfig,
) -> (PermissionHashMap, HashMap<String, Regex>) {
    let confluence_url = "https://developer.atlassian.com/cloud/confluence/swagger.v3.json";
    get_permission_resolver(confluence_url, "confluence", config)
}

pub fn get_permission_resolver_bitbucket(
    config: &CacheConfig,
) -> (PermissionHashMap, HashMap<String, Regex>) {
    let bitbucket_url = "https://api.bitbucket.org/swagger.json";
    get_permission_resolver(bitbucket_url, "bitbucket", config)
}

pub fn get_permission_resolver_compass() -> CompassPermissionResolver {
    CompassPermissionResolver::new()
}

pub fn get_permission_resolver(
    url: &str,
    cache_key: &str,
    config: &CacheConfig,
) -> (PermissionHashMap, HashMap<String, Regex>) {
    let mut endpoint_map: PermissionHashMap = HashMap::default();
    let mut endpoint_regex: HashMap<String, Regex> = HashMap::default();

    get_permissions_for(
        url,
        cache_key,
        config,
        &mut endpoint_map,
        &mut endpoint_regex,
    );

    (endpoint_map, endpoint_regex)
}

pub fn get_permissions_for(
    url: &str,
    cache_key: &str,
    config: &CacheConfig,
    endpoint_map_classic: &mut PermissionHashMap,
    endpoint_regex: &mut HashMap<String, Regex>,
) {
    let cache = PermissionsCache::new(config.clone());

    if config.use_cache() {
        if let Some(raw_response) = cache.read(cache_key) {
            debug!("Cache hit for {}", cache_key);
            let data: SwaggerResponse = serde_json::from_str(&raw_response).unwrap();
            parse_swagger_response(data, endpoint_map_classic, endpoint_regex);
            return;
        }
    }

    ureq::get(url)
        .call()
        .map_err(|e| panic!("Failed to retrieve the permission json: {}", e)) // Handle fetch failure
        .and_then(|response| {
            let raw_response = response.into_string().unwrap();
            let data: SwaggerResponse = serde_json::from_str(&raw_response).unwrap();
            parse_swagger_response(data, endpoint_map_classic, endpoint_regex);
            cache
                .set(cache_key, &raw_response)
                .map_err(|e| panic!("Failed to write to cache: {}", e))
        })
        .unwrap();
}

fn parse_swagger_response(
    response: SwaggerResponse,
    endpoint_map_classic: &mut PermissionHashMap,
    endpoint_regex: &mut HashMap<String, Regex>,
) {
    for (key, endpoint_data) in response.paths {
        let endpoint_data = get_request_type(&endpoint_data, &key);
        endpoint_data
            .into_iter()
            .for_each(|(key, request, permissions)| {
                let regex = Regex::new(&find_regex_for_endpoint(&key)).unwrap();

                endpoint_regex.insert(key.clone(), regex);
                endpoint_map_classic.insert((key, request), permissions);
            });
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

    all_methods
}

fn get_scopes(endpoint_data: &RequestDetails) -> Vec<String> {
    let mut scopes = endpoint_data
        .permission
        .iter()
        .flat_map(|data| &*data.scopes)
        .cloned()
        .collect::<Vec<_>>();

    if scopes.is_empty() {
        // For Jira Software if the initial scopes are empty, try the scopes from the security field
        scopes.extend(
            endpoint_data
                .security
                .iter()
                .flat_map(|sec| &sec.oauth2)
                .cloned(),
        );
    }

    scopes
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_simple_url_with_end_var() {
        let result = find_regex_for_endpoint("/rest/api/3/version/{id}/mergeto/{moveIssuesTo}");
        assert_eq!(result, "/rest/api/3/version/.*/mergeto/.*-");
    }

    #[test]
    fn test_simple_url_with_middle_var() {
        let result = find_regex_for_endpoint("/rest/api/3/issue/{issueIdOrKey}/comment");
        assert_eq!(result, "/rest/api/3/issue/.*/comment-");
    }

    #[test]
    fn test_simple_url_with_no_var() {
        let result = find_regex_for_endpoint("/rest/api/3/fieldconfigurationscheme/project");
        assert_eq!(result, "/rest/api/3/fieldconfigurationscheme/project-");
    }

    #[test]
    fn test_resolving_permssion_basic() {
        let (permission_map, regex_map) = get_permission_resolver_jira(&CacheConfig::default());
        let url = "/rest/api/3/issue/27/attachments";
        let request_type = RequestType::Post;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        let expected_permission: Vec<String> = vec![
            String::from("write:jira-work"),
            String::from("read:user:jira"),
            String::from("write:attachment:jira"),
            String::from("read:attachment:jira"),
            String::from("read:avatar:jira"),
        ];

        assert_eq!(result, expected_permission);
    }

    #[test]
    fn test_resolving_permssion_end_var() {
        let (permission_map, regex_map) =
            get_permission_resolver_confluence(&CacheConfig::default());
        let url = "/wiki/rest/api/relation/1/from/1/2/to/3/4";
        let request_type = RequestType::Get;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        let expected_permission: Vec<String> = vec![
            String::from("read:confluence-content.summary"),
            String::from("read:relation:confluence"),
            String::from("read:content-details:confluence"),
        ];

        assert_eq!(result, expected_permission);
    }

    #[test]
    fn test_resolving_permssion_no_var() {
        let (permission_map, regex_map) = get_permission_resolver_jira(&CacheConfig::default());
        let url = "/rest/api/3/issue/archive";
        let request_type = RequestType::Post;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        let expected_permission: Vec<String> = vec![
            String::from("write:jira-work"),
            String::from("write:issue:jira"),
        ];

        assert_eq!(result, expected_permission);
    }

    #[test]
    fn test_get_organization() {
        let (permission_map, regex_map) =
            get_permission_resolver_jira_service_management(&CacheConfig::default());
        let url = "/rest/servicedeskapi/organization";
        let request_type = RequestType::Get;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        assert!(!result.is_empty(), "Should have parsed permissions");
        assert!(
            result.contains(&String::from("manage:servicedesk-customer")),
            "Should require manage:servicedesk-customer permission"
        );
    }

    #[test]
    fn test_resolving_default_reviewer_check_permissions() {
        let (permission_map, regex_map) =
            get_permission_resolver_bitbucket(&CacheConfig::default());
        let url = "/repositories/mockworkspace/mockreposlug/default-reviewers/jcg";
        let request_type = RequestType::Get;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        assert!(
            !result.is_empty(),
            "Should have parsed permissions for checking default reviewers endpoint"
        );
        assert!(
            result.contains(&String::from("read:pullrequest:bitbucket")),
            "Should require read:pullrequest:bitbucket permission"
        );
    }

    #[test]
    fn test_resolving_default_reviewer_add_permissions() {
        let (permission_map, regex_map) =
            get_permission_resolver_bitbucket(&CacheConfig::default());
        let url = "/repositories/mockworkspace/mockreposlug/default-reviewers/jcg";
        let request_type = RequestType::Put;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        assert!(
            !result.is_empty(),
            "Should have parsed permissions for adding default reviewers endpoint"
        );
        assert!(
            result.contains(&String::from("admin:repository:bitbucket")),
            "Should require admin:repository:bitbucket permission"
        );
    }

    #[test]
    fn test_resolving_repositories_workspace_permissions() {
        let (permission_map, regex_map) =
            get_permission_resolver_bitbucket(&CacheConfig::default());
        let url = "/repositories/asecurityteam";
        let request_type = RequestType::Get;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        assert!(
            !result.is_empty(),
            "Should have parsed permissions for workspace repositories endpoint"
        );
        assert!(
            result.contains(&String::from("read:repository:bitbucket")),
            "Should require read:repository:bitbucket permission"
        );
    }

    #[test]
    fn test_resolving_branch_restriction_permissions() {
        let (permission_map, regex_map) =
            get_permission_resolver_bitbucket(&CacheConfig::default());
        let url = "/repositories/asecurityteam/mock/branch-restrictions";
        let request_type = RequestType::Get;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        assert!(
            !result.is_empty(),
            "Should have parsed permissions for branch restrictions endpoint"
        );
        assert!(
            result.contains(&String::from("admin:repository:bitbucket")),
            "Should require admin:repository:bitbucket permission"
        );
    }

    #[test]
    fn test_get_issues_for_epic() {
        let (permission_map, regex_map) =
            get_permission_resolver_jira_software(&CacheConfig::default());
        let url = "/rest/agile/1.0/sprint/23";
        let request_type = RequestType::Get;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        assert!(!result.is_empty(), "Should have parsed permissions");
        assert!(
            result.contains(&String::from("read:sprint:jira-software")),
            "Should require read:sprint:jira-software permission"
        );
    }

    #[test]
    fn test_get_all_boards() {
        let (permission_map, regex_map) =
            get_permission_resolver_jira_software(&CacheConfig::default());
        let url = "/rest/agile/1.0/board";
        let request_type = RequestType::Get;
        let result = check_url_for_permissions(&permission_map, &regex_map, request_type, url);

        assert!(!result.is_empty(), "Should have parsed permissions");

        let expected_permission: Vec<String> = vec![
            String::from("read:board-scope:jira-software"),
            String::from("read:project:jira"),
        ];

        assert_eq!(result, expected_permission);
    }
}
