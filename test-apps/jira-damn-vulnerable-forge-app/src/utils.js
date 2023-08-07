import api, { route } from '@forge/api';
import { testFunctionFromTestFile } from './testfile';
import module_exports_func from './moduleex.js';
import { func_from_exports, diffunc } from './exportse.js';
import { another_export as foo, newExport } from './newexports.js';
import func_defult from './export_default';
import my_function from './export_default2.js';
import { classone } from './anewclass';
import * as c1 from './anewclass';

// Secret Scanner Default Imports
import * as bleep from 'jsonwebtoken';
import { sign } from 'jsonwebtoken';

import * as atlassian_jwt from 'atlassian-jwt';

// Secret Scanner Star Imports
import * as cryptoJS from 'crypto-js';
import * as jwtSimple from 'jwt-simple';

// Secret Scanner Named Imports
import { HmacSHA256 } from 'crypto-js';

let global = 'test';

export async function fetchIssueSummary(issueIdOrKey, test_value) {
  let obj = {
    method: 'DELETE',
    bananas: 'apple',
    headers: {
      //
      Accept: 'application/json',
    },
  };

  testFunctionFromTestFile();
  let val = 'grapefruit';

  val = 'peach';

  let pre_url = '/rest/api/3/issue/' + val;

  module_exports_func();
  func_from_exports();
  another_export();
  newExport();
  func_defult();
  my_function();
  let global = 'test';

  // Function calls from default imports
  // var token = bleep.sign({ foo: 'bar' }, 'peek a boo');
  var siggy = sign('Message', 'secret');
  // var token = atlassian_jwt.encodeSymmetric({ foo: 'bar' }, 'Atlassian jwt');

  // Function calls from star imports
  // var aes = cryptoJS.AES.encrypt('Secret message', 'secret password');
  // var simple_token = jwtSimple.encode({ foo: 'bar' }, 'Simple JWT');

  // Function calls from named imports
  // var hmac = HmacSHA256('Secret Message', 'HMAC PASSWORD');

  // calling edge case
  // console.log(sign());
  // console.log('End secret scanning test cases');

  // testFunctionFromTestFile();

  // diffunc();

  // different_function();
  let a_class = new ANewClass();
  a_class.function_a_new_class();

  let val = 'grapefruit';

  val = 'peach';

  let pre_url = '/rest/api/3/issue/' + val;

  let a_url = route`/rest/api/3/issue/${issueIdOrKey}?fields=summary/${val}`;

  const resp = await api.asApp().requestJira(global, obj);
  const data = await resp.json();
  console.log(JSON.stringify(data));
  return data['fields']['summary'];
}

// add Secret Scanner Edge cases here

// TODO: Calling function with same name as function from Secret Scanner
// function sign() {
//   console.log('this is a test function');
//   return 'test function';
// }

function get_random_string() {
  return 'test_string_from_get_random_string';
}

export async function writeComment(issueIdOrKey, comment) {
  /* const api = require('@forge/api'); */

  // ERROR, even if this is not assigned anything then it will assign the param to the issueIdOrKey var
  let issueIdOrKey = testFunctionFromTestFile('test_value_param');

  let my_class = new UselessClass();

  my_class.test_function();

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
