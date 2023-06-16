import api, { route } from '@forge/api';

export async function fetchIssueSummary(issueIdOrKey) {

  let url = route`/rest/api/3/issue/${issueIdOrKey}?fields=summary`;

  if (10 > 5) {
    url = route`/rest/api/3/issue/${issueIdOrKey}?fields=summary`;
  }

  let test_string1 = "test_string1_value"

  test_function1(test_string1);

  let never_phi = "never_phi1";

  if (true) {
    never_phi = "not_never_phi";
  }

  /* const api = await import('@forge/api'); */
  const resp = await api
    .asApp()
    .requestJira(url, {
      headers: {
        Accept: 'application/json',
      },
    });
  const data = await resp.json();
  console.log(JSON.stringify(data));
  return data['fields']['summary'];
}

function test_function1(value) {

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
