import api, { route } from '@forge/api';

export async function fetchIssueSummary(something, issueIdOrKey) {
  /* const api = await import('@forge/api'); */
  let issuevar = "overwriten";
  const sample = {test: "testvalue"};
  const {test: testa} = sample;


  if (something.length > 10) {
    issuevar = "issue";
  }
  const resp = await api
    .asApp()
    .requestJira(route`/rest/api/3/${`issue2 ${issuevar}`}/${issueIdOrKey}?fields=summary`, {
      headers: {
        Accept: 'application/json',
      },
    });
  const data = await resp.json();
  console.log(JSON.stringify(data));
  return data['fields']['summary'];
}

export async function writeComment(issueIdOrKey, comment) {
  /* const api = require('@forge/api'); */
  const resp = await api
    .asApp()
    .requestJira(route`/rest/api/3/issue/${issueIdOrKey}/comment`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: `{
        "body": {
          "type": "doc",
          "version": 1,
          "content": [
            {
              "type": "paragraph",
              "content": [
                "text": ${comment},
                "type": "text"
              ]
            }
          ]
        }
      }`,
    });
  console.log(`Response: ${resp.status} ${resp.statusText}`);
  console.log(await resp.json());
}
