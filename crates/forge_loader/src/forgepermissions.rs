
use serde::{self, Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub enum ForgePermissions {
    #[serde(rename = "read:audit-log:confluence")]
    WriteAuditLogsConfluence,
    #[serde(rename = "write:audit-log:confluence")]
    ReadAuditLogsConfluence,
    #[serde(rename = "write:confluence-content")]
    WriteConfluenceContent,
    #[serde(rename = "read:confluence-space.summary")]
    ReadConfluenceSpaceSummary,
    #[serde(rename = "write:confluence-space")]
    WriteConfluenceSpace,
    #[serde(rename = "write:confluence-file")]
    WriteConfluenceFile,
    #[serde(rename = "read:confluence-props")]
    ReadConfluenceProps,
    #[serde(rename = "write:confluence-props")]
    WriteConfluenceProps,
    #[serde(rename = "read:confluence-content.all")]
    ReadConfluenceContentAll,
    #[serde(rename = "read:confluence-content.summary")]
    ReadConfluenceContentSummary,
    #[serde(rename = "read:inlinetask:confluence")]
    ReadInlineTaskConfluence,
    #[serde(rename = "search:confluence")]
    SearchConfluence,
    #[serde(rename = "read:confluence-content.permission")]
    ReadConfluenceContentPermission,
    #[serde(rename = "read:content-details:confluence")]
    ReadContentDetailsConfluence,
    #[serde(rename = "read:confluence-user")]
    ReadConfluenceUser,
    #[serde(rename = "read:user.property:confluence")]
    ReadUserPropertyConfluence,    
    #[serde(rename = "manage:confluence-configuration")]
    ManageConfluenceConfiguration,
    #[serde(rename = "read:content.metadata:confluence")]
    ReadContentMetadataConfluence,
    #[serde(rename = "read:confluence-content.permission")]
    ReadConfluenceGroups,
    #[serde(rename = "write:confluence-groups")]
    WriteConfluenceGroups,
    #[serde(rename = "write:user.property:confluence")]
    WriteUserPropertyConfluence,
    #[serde(rename = "read:space.permission:confluence")]
    ReadSpacePermissionConfluence,
    #[serde(rename = "write:space.permission:confluence")]
    WriteSpacePermissionsConfluence,
    #[serde(rename = "write:inlinetask:confluence")]
    WriteInlineTaskConfluence,    
    #[serde(rename = "readonly:content.attachment:confluence")]
    ReadOnlyContentAttachmentConfluence,
    #[serde(rename = "read:jira-user")]
    ReadJiraUser,
    #[serde(rename = "read:jira-work")]
    ReadJiraWork,
    #[serde(rename = "write:jira-work")]
    WriteJiraWork,
    #[serde(rename = "manage:jira-project")]
    ManageJiraProject,
    #[serde(rename = "manage:jira-configuration")]
    ManageJiraConfiguration,    
    #[serde(rename = "manage:jira-webhook")]
    ManageJiraWebhook,
    #[serde(other)]
    Unknown,
}