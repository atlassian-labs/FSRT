import { IssuePanel, IssuePanelAction, useProductContext } from '@forge/ui';
import { writeComment } from './utils';

export const IssuePanelApp = () => {
  const { platformContext } = useProductContext();
  if (platformContext == null || platformContext.type !== 'jira') {
    console.error('product context is not in JIRA');
    return null;
  }
  const { issueId } = platformContext;


  const writeCommentFunction = () => {
    writeComment(issueId, 'Overwrite')
  }

  return (
    <IssuePanel
      actions={[
        <IssuePanelAction
          text="Issues"
          onClick={writeCommentFunction}
        />,
      ]}
    >
      <Text>Overwrite vuln</Text>
    </IssuePanel>
  );
};
