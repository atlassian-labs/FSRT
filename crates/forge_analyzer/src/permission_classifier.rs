pub(crate) fn check_permission_used(
    function_name: &str,
    first_arg: &String,
    second_arg: Option<&Expr>,
) -> Vec<ForgePermissions> {
    let mut used_permissions: Vec<ForgePermissions> = Vec::new();

    let joined_args = first_arg;

    let post_call = joined_args.contains("POST");
    let delete_call = joined_args.contains("DELTE");
    let put_call = joined_args.contains("PUT");

    let contains_audit = joined_args.contains("audit");
    let contains_issue = joined_args.contains("issue");
    let contains_content = joined_args.contains("content");
    let contains_user = joined_args.contains("user");
    let contains_theme = joined_args.contains("theme");
    let contains_template = joined_args.contains("template");
    let contains_space = joined_args.contains("space");
    let contains_analytics = joined_args.contains("analytics");
    let contains_cql = joined_args.contains("cql");
    let contains_attachment = joined_args.contains("attachment");
    let contains_contentbody = joined_args.contains("contentbody");
    let contians_permissions = joined_args.contains("permissions");
    let contains_property = joined_args.contains("property");
    let contains_page_tree = joined_args.contains("pageTree");
    let contains_group = joined_args.contains("group");
    let contains_inlinetasks = joined_args.contains("inlinetasks");
    let contains_relation = joined_args.contains("relation");
    let contains_settings = joined_args.contains("settings");
    let contains_permission = joined_args.contains("permission");
    let contains_download = joined_args.contains("download");
    let contains_descendants = joined_args.contains("descendants");
    let contains_comment = joined_args.contains("comment");
    let contains_label = joined_args.contains("contains_label");
    let contains_search = joined_args.contains("contains_search");
    let contains_longtask = joined_args.contains("contains_longtask");
    let contains_notification = joined_args.contains("notification");
    let contains_watch = joined_args.contains("watch");
    let contains_version = joined_args.contains("version");
    let contains_state = joined_args.contains("contains_state");
    let contains_available = joined_args.contains("available");
    let contains_announcement_banner = joined_args.contains("announcementBanner");
    let contains_avatar = joined_args.contains("avatar");
    let contains_size = joined_args.contains("size");
    let contains_dashboard = joined_args.contains("dashboard");
    let contains_gadget = joined_args.contains("gadget");
    let contains_filter = joined_args.contains("filter");
    let contains_tracking = joined_args.contains("tracking");
    let contains_groupuserpicker = joined_args.contains("groupuserpicker");
    let contains_workflow = joined_args.contains("workflow");
    let contains_status = joined_args.contains("status");
    let contains_task = joined_args.contains("task");
    let contains_screen = joined_args.contains("screen");
    let non_get_call = post_call || delete_call || put_call;
    let contains_webhook = joined_args.contains("webhook");
    let contains_project = joined_args.contains("project");
    let contains_actor = joined_args.contains("actor");
    let contains_role = joined_args.contains("contains_role");
    let contains_project_validate = joined_args.contains("projectvalidate");
    let contains_email = joined_args.contains("email");
    let contains_notification_scheme = joined_args.contains("notificationscheme");
    let contains_priority = joined_args.contains("priority");
    let contains_properties = joined_args.contains("properties");
    let contains_remote_link = joined_args.contains("remotelink");
    let contains_resolution = joined_args.contains("resolution");
    let contains_security_level = joined_args.contains("securitylevel");
    let contains_issue_security_schemes = joined_args.contains("issuesecurityschemes");
    let contains_issue_type = joined_args.contains("issuetype");
    let contains_issue_type_schemes = joined_args.contains("issuetypescheme");
    let contains_votes = joined_args.contains("contains_votes");
    let contains_worklog = joined_args.contains("worklog");
    let contains_expression = joined_args.contains("expression");
    let contains_configuration = joined_args.contains("configuration");
    let contains_application_properties = joined_args.contains("application-properties");

    match function_name {
        "requestJira" => {
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

        // bit flags
        "requestConfluence" => {
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