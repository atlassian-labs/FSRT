use crate::checkers::IntrinsicName;
use core::fmt;
use forge_loader::forgepermissions::ForgePermissions;

pub(crate) fn check_permission_used(
    function_name: IntrinsicName,
    first_arg: &String,
    second_arg: Option<&String>,
) -> Vec<ForgePermissions> {
    let mut used_permissions: Vec<ForgePermissions> = Vec::new();

    let post_call = second_arg.unwrap_or(&String::from("")).contains("POST");
    let delete_call = second_arg.unwrap_or(&String::from("")).contains("DELTE");
    let put_call = second_arg.unwrap_or(&String::from("")).contains("PUT");

    let contains_audit = first_arg.contains("audit");
    let contains_issue = first_arg.contains("issue");
    let contains_content = first_arg.contains("content");
    let contains_user = first_arg.contains("user");
    let contains_theme = first_arg.contains("theme");
    let contains_template = first_arg.contains("template");
    let contains_space = first_arg.contains("space");
    let contains_analytics = first_arg.contains("analytics");
    let contains_cql = first_arg.contains("cql");
    let contains_attachment = first_arg.contains("attachment");
    let contains_contentbody = first_arg.contains("contentbody");
    let contians_permissions = first_arg.contains("permissions");
    let contains_property = first_arg.contains("property");
    let contains_page_tree = first_arg.contains("pageTree");
    let contains_group = first_arg.contains("group");
    let contains_inlinetasks = first_arg.contains("inlinetasks");
    let contains_relation = first_arg.contains("relation");
    let contains_settings = first_arg.contains("settings");
    let contains_permission = first_arg.contains("permission");
    let contains_download = first_arg.contains("download");
    let contains_descendants = first_arg.contains("descendants");
    let contains_comment = first_arg.contains("comment");
    let contains_label = first_arg.contains("contains_label");
    let contains_search = first_arg.contains("contains_search");
    let contains_longtask = first_arg.contains("contains_longtask");
    let contains_notification = first_arg.contains("notification");
    let contains_watch = first_arg.contains("watch");
    let contains_version = first_arg.contains("version");
    let contains_state = first_arg.contains("contains_state");
    let contains_available = first_arg.contains("available");
    let contains_announcement_banner = first_arg.contains("announcementBanner");
    let contains_avatar = first_arg.contains("avatar");
    let contains_size = first_arg.contains("size");
    let contains_dashboard = first_arg.contains("dashboard");
    let contains_gadget = first_arg.contains("gadget");
    let contains_filter = first_arg.contains("filter");
    let contains_tracking = first_arg.contains("tracking");
    let contains_groupuserpicker = first_arg.contains("groupuserpicker");
    let contains_workflow = first_arg.contains("workflow");
    let contains_status = first_arg.contains("status");
    let contains_task = first_arg.contains("task");
    let contains_screen = first_arg.contains("screen");
    let non_get_call = post_call || delete_call || put_call;
    let contains_webhook = first_arg.contains("webhook");
    let contains_project = first_arg.contains("project");
    let contains_actor = first_arg.contains("actor");
    let contains_role = first_arg.contains("contains_role");
    let contains_project_validate = first_arg.contains("projectvalidate");
    let contains_email = first_arg.contains("email");
    let contains_notification_scheme = first_arg.contains("notificationscheme");
    let contains_priority = first_arg.contains("priority");
    let contains_properties = first_arg.contains("properties");
    let contains_remote_link = first_arg.contains("remotelink");
    let contains_resolution = first_arg.contains("resolution");
    let contains_security_level = first_arg.contains("securitylevel");
    let contains_issue_security_schemes = first_arg.contains("issuesecurityschemes");
    let contains_issue_type = first_arg.contains("issuetype");
    let contains_issue_type_schemes = first_arg.contains("issuetypescheme");
    let contains_votes = first_arg.contains("contains_votes");
    let contains_worklog = first_arg.contains("worklog");
    let contains_expression = first_arg.contains("expression");
    let contains_configuration = first_arg.contains("configuration");
    let contains_application_properties = first_arg.contains("application-properties");

    match function_name {
        IntrinsicName::RequestJira => {
            if (contains_dashboard && non_get_call)
                || (contains_user && non_get_call)
                || contains_task
            {
                used_permissions.push(ForgePermissions::WriteJiraWork);
                if contains_gadget {
                    used_permissions.push(ForgePermissions::ReadJiraWork)
                }
            } else if contains_expression {
                used_permissions.push(ForgePermissions::ReadJiraUser);
                used_permissions.push(ForgePermissions::ReadJiraUser)
            } else if (contains_avatar && contains_size)
                || contains_dashboard
                || contains_status
                || contains_groupuserpicker
            {
                used_permissions.push(ForgePermissions::ReadJiraWork)
            } else if (!non_get_call && contains_user) || contains_configuration {
                used_permissions.push(ForgePermissions::ReadJiraUser)
            } else if contains_webhook {
                used_permissions.push(ForgePermissions::ManageJiraWebhook);
                used_permissions.push(ForgePermissions::ReadJiraWork)
            } else if (contains_remote_link && non_get_call)
                || (contains_issue && contains_votes && non_get_call)
                || (contains_worklog && non_get_call)
            {
                used_permissions.push(ForgePermissions::WriteJiraWork)
            } else if (contains_issue_type && non_get_call)
                || (contains_issue_type && non_get_call)
                || (contains_project && non_get_call)
                || (contains_project && contains_actor)
                || (contains_project && contains_role)
                || (contains_project && contains_email)
                || (contains_priority && (non_get_call || contains_search))
                || (contains_properties && contains_issue && non_get_call)
                || (contains_resolution && non_get_call)
                || contains_audit
                || contains_avatar
                || contains_workflow
                || contains_tracking
                || contains_status
                || contains_screen
                || contains_notification_scheme
                || contains_security_level
                || contains_issue_security_schemes
                || contains_issue_type_schemes
                || contains_announcement_banner
                || contains_application_properties
            {
                used_permissions.push(ForgePermissions::ManageJiraConfiguration)
            } else if contains_filter {
                if non_get_call {
                    used_permissions.push(ForgePermissions::WriteJiraWork)
                } else {
                    used_permissions.push(ForgePermissions::ReadJiraWork)
                }
            } else if contains_project
                || contains_project_validate
                || contains_priority
                || contains_search
                || contains_issue_type
                || (contains_issue && contains_votes)
                || (contains_properties && contains_issue)
                || (contains_remote_link && !non_get_call)
                || (contains_resolution && !non_get_call)
                || contains_worklog
            {
                used_permissions.push(ForgePermissions::ReadJiraWork)
            } else if post_call {
                if contains_issue {
                    used_permissions.push(ForgePermissions::WriteJiraWork);
                } else {
                    used_permissions.push(ForgePermissions::Unknown);
                }
            } else {
                if contains_issue {
                    used_permissions.push(ForgePermissions::ReadJiraWork);
                } else {
                    used_permissions.push(ForgePermissions::Unknown);
                }
            }
        }
        IntrinsicName::RequestConfluence => {
            if non_get_call {
                if contains_content {
                    used_permissions.push(ForgePermissions::WriteConfluenceContent);
                } else if contains_audit {
                    used_permissions.push(ForgePermissions::WriteAuditLogsConfluence);
                    if post_call {
                        used_permissions.push(ForgePermissions::ReadAuditLogsConfluence);
                    }
                } else if contains_content && contains_attachment {
                    if put_call {
                        // review this more specifically
                        // /wiki/rest/api/content/{id}/child/attachment/{attachmentId}`,
                        used_permissions.push(ForgePermissions::WriteConfluenceFile);
                        used_permissions.push(ForgePermissions::WriteConfluenceProps)
                    } else {
                        used_permissions.push(ForgePermissions::WriteConfluenceFile)
                    }
                } else if contains_contentbody {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentAll)
                } else if contains_content && contians_permissions {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentPermission)
                } else if contains_property {
                    used_permissions.push(ForgePermissions::WriteConfluenceProps)
                } else if contains_content
                    || contains_page_tree
                    || contains_relation
                    || contains_template
                {
                    used_permissions.push(ForgePermissions::WriteConfluenceContent)
                } else if contains_group {
                    used_permissions.push(ForgePermissions::WriteConfluenceGroups)
                } else if contains_settings {
                    used_permissions.push(ForgePermissions::ManageConfluenceConfiguration)
                } else if contains_space && contains_permission {
                    if !delete_call {
                        used_permissions.push(ForgePermissions::ReadSpacePermissionConfluence);
                    }
                    used_permissions.push(ForgePermissions::WriteSpacePermissionsConfluence)
                } else if contains_space || contains_theme {
                    used_permissions.push(ForgePermissions::WriteConfluenceSpace);
                } else if contains_inlinetasks {
                    used_permissions.push(ForgePermissions::WriteInlineTaskConfluence)
                } else if contains_user && contains_property {
                    used_permissions.push(ForgePermissions::WriteUserPropertyConfluence);
                } else {
                    used_permissions.push(ForgePermissions::Unknown);
                }
            } else {
                if contains_issue {
                    used_permissions.push(ForgePermissions::ReadJiraWork);
                } else if contains_audit {
                    used_permissions.push(ForgePermissions::ReadAuditLogsConfluence)
                } else if contains_cql {
                    if contains_user {
                        used_permissions.push(ForgePermissions::ReadContentDetailsConfluence);
                    } else {
                        used_permissions.push(ForgePermissions::SearchConfluence);
                    }
                } else if contains_attachment && contains_download {
                    used_permissions.push(ForgePermissions::ReadOnlyContentAttachmentConfluence)
                } else if contains_longtask {
                    used_permissions.push(ForgePermissions::ReadContentMetadataConfluence);
                    used_permissions.push(ForgePermissions::ReadConfluenceSpaceSummary)
                } else if contains_content && contains_property {
                    used_permissions.push(ForgePermissions::ReadConfluenceProps);
                } else if contains_template
                    || contains_relation
                    || (contains_content
                        && (contains_comment || contains_descendants || contains_label))
                {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentSummary)
                } else if contains_space && contains_settings {
                    used_permissions.push(ForgePermissions::ReadConfluenceSpaceSummary)
                } else if contains_space && contains_theme {
                    used_permissions.push(ForgePermissions::ManageConfluenceConfiguration)
                } else if contains_space && contains_content && contains_state {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentAll)
                } else if contains_space && contains_content {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentSummary)
                } else if contains_state && contains_content && contains_available {
                    used_permissions.push(ForgePermissions::WriteConfluenceContent)
                } else if contains_content
                    && (contains_notification
                        || contains_watch
                        || contains_version
                        || contains_state)
                {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentSummary)
                } else if contains_space {
                    used_permissions.push(ForgePermissions::ReadConfluenceProps)
                } else if contains_content || contains_analytics {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentAll)
                } else if contains_user && contains_property {
                    used_permissions.push(ForgePermissions::WriteUserPropertyConfluence)
                } else if contains_settings {
                    used_permissions.push(ForgePermissions::ManageConfluenceConfiguration)
                } else if contains_search {
                    used_permissions.push(ForgePermissions::ReadContentDetailsConfluence)
                } else if contains_space {
                    used_permissions.push(ForgePermissions::ReadConfluenceSpaceSummary)
                } else if contains_user {
                    used_permissions.push(ForgePermissions::ReadConfluenceUser)
                } else if contains_label {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentSummary)
                } else if contains_inlinetasks {
                    used_permissions.push(ForgePermissions::ReadConfluenceContentAll);
                } else {
                    used_permissions.push(ForgePermissions::Unknown);
                }
            }
        }
        _ => {
            used_permissions.push(ForgePermissions::Unknown);
        }
    }
    used_permissions
}
