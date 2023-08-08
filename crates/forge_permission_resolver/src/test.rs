use crate::permissions_resolver::{
    check_url_for_permissions, find_regex_for_endpoint, get_permission_resolver, RequestType,
};

mod tests {
    use crate::permissions_resolver::{
        get_permission_resolver_confluence, get_permission_resolver_jira,
    };
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
}
