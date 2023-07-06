import api, { route } from '@forge/api';

export async function fetchIssueSummary(issueIdOrKey, url) {

  let obj = {
    method: 'GET',
    headers: {
      Accept: 'application/json',
    },
  };

  let val = "grapefruit";

  val = "peach";

  let pre_url = "/rest/api/3/issue/" + val;

  let a_url = route`/rest/api/3/issue/${issueIdOrKey}?fields=summary`;

  const resp = await api
    .asApp()
<<<<<<< HEAD
    .requestJira( "/rest/api/3/issue/" + val, obj);
=======
    .requestJira(a_url, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
      },
    });
>>>>>>> 2fc49f1b4b00e3ae4e97b2340279f3aa3c7acdef
  const data = await resp.json();
  console.log(JSON.stringify(data));
  return data['fields']['summary'];
}

function get_route(url) {
  //return a_url = route`/rest/api/3/issue/${issueIdOrKey}?fields=summary`;
  return url;
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
