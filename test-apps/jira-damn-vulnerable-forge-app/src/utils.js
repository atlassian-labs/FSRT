import api, { route } from '@forge/api';
import jwt from 'jsonwebtoken';
import * as atlassian_jwt from 'atlassian-jwt';

import { testFunctionFromTestFile } from './testfile';
import module_exports_func from './moduleex.js';
import { func_from_exports, diffunc } from './exportse.js';
// foo = DefId(22)
import { another_export as foo, newExport } from './newexports.js';
import func_defult from './export_default';
import my_function from './export_default2.js';
import { classone } from './anewclass';
import * as c1 from './anewclass';
/*
import {default as something} from what;
import something from what;

packagename: jsonwebtoken
identifier: default
type: Object("sign")
position: 4

function require(input) {}
require('foo');

type: Enum {
  Function,
  Object(String), // <- method_name
}
*/

// import HmacMD5 from 'crypto-js';
// DefId(4)

// DEFINITIONS
// 0 -> name
// 0 -> Definition(enum)

// function chair() {
// DefId(22)
//as_foreign_import(DefId(22), 'newexports')) -> Some(ImportKind("another_export"))
// foo();
//
// [DefId(4), Static('blah'), Static('open')]
// atlassian_jwt['blah' + 'test']();
// atlassian_jwt.blah.open();
// atlassian_jwt['blah']();

// const blah = 'sign';
// atlassian_jwt[blah]();
// atlassian_jwt.sign();
// }

// var jwt = require('jwt-simple');
let global = 'test';
let CryptoJS = require('crypto-js');

export async function fetchIssueSummary(issueIdOrKey, test_value) {
  let obj = {
    method: 'POST',
    bananas: 'apple',
    headers: {
      //
      Accept: 'application/json',
    },
  };

  module_exports_func();
  func_from_exports();
  another_export();
  newExport();
  func_defult();
  my_function();
  let global = 'test';

  // testing all the libraries
  var token = jwt.sign({ foo: 'bar' }, 'peek a boo');
  // var hmac = HmacMD5('Secret Message', 'HMAC PASSWORD');
  var token = atlassian_jwt.encodeSymmetric({ foo: 'bar' }, 'Atlassian jwt');
  // var simple_token = jwt.encode({ foo: 'bar' }, 'Simple JWT');

  // testFunctionFromTestFile();

  diffunc();

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
