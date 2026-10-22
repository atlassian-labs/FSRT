//! Route classes the authorization policy knows by shape.
//!
//! A pattern is a path of `/`-separated segments. `:v` matches the REST version
//! segment (`2`, `3` or `latest`), `{}` matches exactly one segment, whether it
//! is a literal or computed, and any other segment is matched literally without
//! regard to case. Patterns are anchored: `/rest/api/:v/field` does not match
//! `/rest/api/3/field/search` or `/rest/api/3/fieldx`. A route whose matching
//! segment is computed (`/rest/api/3/${path}`) matches no literal segment.
//! The query string is ignored.

use crate::request::RouteText;

/// Instance configuration metadata: the same for every viewer, administered by
/// site admins and shown to every user in create/edit forms and pickers. None of
/// these routes names an issue, page, comment, attachment or user. Each is
/// matched only for GET requests.
///
/// Residual risk, accepted because the triage found no true positive that depends
/// on it: the project, board, service desk and space *lists* name containers the
/// caller may not be allowed to browse.
const INSTANCE_METADATA: &[&str] = &[
    // Fields, issue types and issue metadata.
    "/rest/api/:v/field",
    "/rest/api/:v/field/search",
    "/rest/api/:v/field/{}/context",
    "/rest/api/:v/field/{}/context/{}/option",
    "/rest/api/:v/issue/createmeta",
    "/rest/api/:v/issue/createmeta/{}/issuetypes",
    "/rest/api/:v/issue/createmeta/{}/issuetypes/{}",
    "/rest/api/:v/issuetype",
    "/rest/api/:v/issuetype/project",
    // Workflow vocabulary.
    "/rest/api/:v/status",
    "/rest/api/:v/statuscategory",
    "/rest/api/:v/priority",
    "/rest/api/:v/resolution",
    "/rest/api/:v/resolution/search",
    "/rest/api/:v/issueLinkType",
    "/rest/api/:v/label",
    "/rest/api/:v/role",
    "/rest/api/:v/workflows/search",
    "/rest/api/:v/workflowscheme/project",
    // Screens and schemes.
    "/rest/api/:v/screens",
    "/rest/api/:v/screens/{}/tabs",
    "/rest/api/:v/screens/{}/tabs/{}/fields",
    "/rest/api/:v/screenscheme",
    "/rest/api/:v/issuetypescreenscheme",
    "/rest/api/:v/issuetypescreenscheme/project",
    "/rest/api/:v/issuetypescreenscheme/mapping",
    // Site settings and query vocabulary.
    "/rest/api/:v/serverInfo",
    "/rest/api/:v/configuration",
    "/rest/api/:v/configuration/timetracking/options",
    "/rest/api/:v/jql/autocompletedata",
    "/rest/api/:v/field/{}/context/projectmapping",
    "/rest/api/:v/field/{}/context/issuetypemapping",
    "/rest/api/:v/fieldconfigurationscheme/project",
    "/rest/api/:v/fieldconfigurationscheme/mapping",
    "/rest/api/:v/config/fieldschemes",
    "/rest/api/:v/attachment/meta",
    "/rest/api/:v/project/{}/roledetails",
    "/rest/servicedeskapi/servicedesk/{}/requesttype",
    // Who the app is acting as: the app's own user, not a user of the caller's.
    "/rest/api/:v/myself",
    // Lists of containers.
    "/rest/api/:v/project",
    "/rest/api/:v/project/search",
    "/rest/api/:v/project/{}/statuses",
    "/rest/agile/1.0/board",
    "/rest/servicedeskapi/servicedesk",
    // One service desk by id: its name and project key, like the list.
    "/rest/servicedeskapi/servicedesk/{}",
    "/wiki/api/v2/spaces",
    "/wiki/rest/api/space",
    "/wiki/rest/api/settings/systemInfo",
];

/// POST endpoints that only read: the body selects what to read. They are treated
/// like GETs by the policies that depend on a request being a read.
const READ_ONLY_POSTS: &[&str] = &[
    "/rest/api/:v/search",
    "/rest/api/:v/search/jql",
    "/rest/api/:v/search/approximate-count",
    "/rest/api/:v/issue/bulkfetch",
    "/rest/api/:v/changelog/bulkfetch",
    "/rest/api/:v/worklog/list",
];

/// POST endpoints that analyse a query and return its structure; nothing in the
/// instance is read or changed.
const QUERY_ANALYSIS_POSTS: &[&str] = &["/rest/api/:v/jql/parse", "/rest/api/:v/jql/sanitize"];

fn matches(pattern: &str, route: &[Option<String>]) -> bool {
    let mut segments = pattern.split('/').filter(|segment| !segment.is_empty());
    for actual in route {
        let Some(expected) = segments.next() else {
            return false;
        };
        let ok = match (expected, actual) {
            ("{}", _) => true,
            (_, None) => false,
            (":v", Some(version)) => matches!(version.as_str(), "2" | "3" | "latest"),
            (expected, Some(actual)) => expected.eq_ignore_ascii_case(actual),
        };
        if !ok {
            return false;
        }
    }
    segments.next().is_none()
}

/// Whether a POST of `route` is a read whose body selects what to read.
pub(super) fn is_read_only_post(route: &RouteText) -> bool {
    let segments = route.path_segments();
    READ_ONLY_POSTS
        .iter()
        .any(|pattern| matches(pattern, &segments))
}

/// Whether a POST of `route` only analyses the query in its body.
pub(super) fn is_query_analysis_post(route: &RouteText) -> bool {
    let segments = route.path_segments();
    QUERY_ANALYSIS_POSTS
        .iter()
        .any(|pattern| matches(pattern, &segments))
}

/// Whether a GET of `route` reads instance configuration metadata.
pub(super) fn is_instance_metadata(route: &RouteText) -> bool {
    let segments = route.path_segments();
    INSTANCE_METADATA
        .iter()
        .any(|pattern| matches(pattern, &segments))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Piece;

    fn route(text: &str) -> RouteText {
        // Treat `$` as a hole so tests can write `/issue/$/comment`.
        let mut pieces = Vec::new();
        for (index, part) in text.split('$').enumerate() {
            if index > 0 {
                pieces.push(Piece::Hole);
            }
            pieces.push(Piece::Text(part.into()));
        }
        RouteText::new(pieces)
    }

    #[test]
    fn matches_anchored_literal_routes_and_versions() {
        for yes in [
            "/rest/api/3/field",
            "/rest/api/2/field/",
            "/rest/api/latest/field?query=$",
            "/REST/api/3/Field",
            "/rest/api/3/field/$/context",
            "/rest/api/3/field/customfield_10001/context/$/option",
            "/rest/api/3/project/$/statuses",
            "/wiki/api/v2/spaces?keys=$&limit=1",
        ] {
            assert!(is_instance_metadata(&route(yes)), "{yes}");
        }
    }

    #[test]
    fn rejects_longer_shorter_computed_and_unrelated_routes() {
        for no in [
            "/rest/api/3/field/search/extra",
            "/rest/api/3/fieldx",
            "/rest/api/4/field",
            "/rest/api/$/field",
            "/rest/api/3/$",
            "/rest/api/3/issue/$",
            "/rest/api/3/project/$",
            "/rest/api/3/project/$/role",
            "/rest/api/3/user/search",
            "/rest/api/3/issue/createmeta/$",
            "/wiki/api/v2/pages/$",
            "/wiki/api/v2/spaces/$",
            "/rest/api/3/field$",
            "/rest/agile/1.0/board/$/configuration",
        ] {
            assert!(!is_instance_metadata(&route(no)), "{no}");
        }
    }
}
