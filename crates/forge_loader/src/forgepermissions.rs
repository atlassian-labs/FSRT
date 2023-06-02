
use serde::{self, Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Hash)]
pub enum ForgePermissions {
    #[serde(rename = "read:audit-log:confluence")]
    WriteAuditLogsConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    ReadAuditLogsConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    WriteConfluenceContent,
    #[serde(rename = "read:audit-log:confluence")]
    ReadConfluenceSpaceSummary,
    #[serde(rename = "read:audit-log:confluence")]
    WriteConfluenceSpace,
    #[serde(rename = "read:audit-log:confluence")]
    WriteConfluenceFile,
    #[serde(rename = "read:audit-log:confluence")]
    ReadConfluenceProps,
    #[serde(rename = "read:audit-log:confluence")]
    WriteConfluenceProps,
    #[serde(rename = "read:audit-log:confluence")]
    ReadConfluenceContentAll,
    #[serde(rename = "read:audit-log:confluence")]
    ReadConfluenceContentSummary,
    #[serde(rename = "read:audit-log:confluence")]
    ReadInlineTaskConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    SearchConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    ReadConfluenceContentPermission,
    #[serde(rename = "read:audit-log:confluence")]
    ReadContentDetailsConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    ReadConfluenceUser,
    #[serde(rename = "read:audit-log:confluence")]
    ReadUserPropertyConfluence,    
    #[serde(rename = "read:audit-log:confluence")]
    ManageConfluenceConfiguration,
    #[serde(rename = "read:audit-log:confluence")]
    ReadContentMetadataConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    ReadConfluenceGroups,
    #[serde(rename = "read:audit-log:confluence")]
    WriteConfluenceGroups,
    #[serde(rename = "read:audit-log:confluence")]
    WriteUserPropertyConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    ReadSpacePermissionConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    WriteSpacePermissionsConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    WriteInlineTaskConfluence,    
    #[serde(rename = "read:audit-log:confluence")]
    ReadOnlyContentAttachmentConfluence,
    #[serde(rename = "read:audit-log:confluence")]
    ReadJiraUser,
    #[serde(rename = "read:audit-log:confluence")]
    ReadJiraWork,
    #[serde(rename = "read:audit-log:confluence")]
    WriteJiraWork,
    #[serde(rename = "read:audit-log:confluence")]
    ManageJiraProject,
    #[serde(rename = "read:audit-log:confluence")]
    ManageJiraConfiguration,    
    #[serde(rename = "read:audit-log:confluence")]
    ManageJiraWebhook,
    #[serde(other)]
    Unknown,
}