use crate::permissions_resolver_compass::CompassPermissionResolver;
use regex::Regex;
use serde::Deserialize;
use std::{cmp::Reverse, collections::HashMap, hash::Hash};
use tracing::warn;

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

#[derive(Clone, Copy, Hash, PartialEq, Eq, Debug)]
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

pub fn get_permission_resolver_jira_any() -> (PermissionHashMap, HashMap<String, Regex>) {
    // Combine all Jira variations to achieve a generic "any" Jira
    let (jira_map, jira_regex) = get_permission_resolver_jira();
    let (jsm_map, jsm_regex) = get_permission_resolver_jira_service_management();
    let (js_map, js_regex) = get_permission_resolver_jira_software();

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

pub fn get_permission_resolver_jira_software() -> (PermissionHashMap, HashMap<String, Regex>) {
    let jira_software_url = "https://developer.atlassian.com/cloud/jira/software/swagger.v3.json";
    get_permission_resolver(jira_software_url)
}

pub fn get_permission_resolver_jira_service_management(
) -> (PermissionHashMap, HashMap<String, Regex>) {
    let jira_service_management_url =
        "https://developer.atlassian.com/cloud/jira/service-desk/swagger.v3.json";
    get_permission_resolver(jira_service_management_url)
}

pub fn get_permission_resolver_jira() -> (PermissionHashMap, HashMap<String, Regex>) {
    let jira_url = "https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json";
    get_permission_resolver(jira_url)
}

pub fn get_permission_resolver_confluence() -> (PermissionHashMap, HashMap<String, Regex>) {
    let confluence_url = "https://developer.atlassian.com/cloud/confluence/swagger.v3.json";
    get_permission_resolver(confluence_url)
}

pub fn get_permission_resolver_bitbucket() -> (PermissionHashMap, HashMap<String, Regex>) {
    let bitbucket_url = "https://api.bitbucket.org/swagger.json";
    get_permission_resolver(bitbucket_url)
}

pub fn get_permission_resolver_compass() -> CompassPermissionResolver {
    CompassPermissionResolver::new()
}

pub fn get_permission_resolver(url: &str) -> (PermissionHashMap, HashMap<String, Regex>) {
    let mut endpoint_map: PermissionHashMap = HashMap::default();
    let mut endpoint_regex: HashMap<String, Regex> = HashMap::default();

    get_permisions_for(url, &mut endpoint_map, &mut endpoint_regex);

    (endpoint_map, endpoint_regex)
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
        let (permission_map, regex_map) = get_permission_resolver_jira();
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
        let (permission_map, regex_map) = get_permission_resolver_confluence();
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
        let (permission_map, regex_map) = get_permission_resolver_jira();
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
        let (permission_map, regex_map) = get_permission_resolver_jira_service_management();
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
        let (permission_map, regex_map) = get_permission_resolver_bitbucket();
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
        let (permission_map, regex_map) = get_permission_resolver_bitbucket();
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
        let (permission_map, regex_map) = get_permission_resolver_bitbucket();
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
        let (permission_map, regex_map) = get_permission_resolver_bitbucket();
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
        let (permission_map, regex_map) = get_permission_resolver_jira_software();
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
        let (permission_map, regex_map) = get_permission_resolver_jira_software();
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
