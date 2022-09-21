import { IssuePanel, IssuePanelAction, useProductContext } from '@forge/ui';
import { writeComment } from './utils';

export default IssuePanelApp = () => {
  const { platformContext } = useProductContext();
  if (platformContext == null || platformContext.type !== 'jira') {
    console.error('product context is not in JIRA');
    return null;
  }
  const { issueId } = platformContext;
  return (
    <IssuePanel
      actions={[
        <IssuePanelAction
          text="Issues"
          onClick={() => writeComment(issueId, 'Overwrite')}
        />,
      ]}
    >
      <Text>Overwrite vuln</Text>
    </IssuePanel>
  );
};
