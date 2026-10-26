//! Authentication-check-present policy: a recognized verification call before a
//! privileged operation suppresses the Authentication finding. These tests pin
//! that the call is observed, not that its result is used.
use super::*;

const MANIFEST: &str = "// manifest.yml
        modules:
          webtrigger:
            - key: gateway
              function: main
          function:
            - key: main
              handler: index.run
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes: []";

fn authentication_findings(report: &Report) -> usize {
    report
        .into_vulns()
        .iter()
        .filter(|vuln| {
            vuln.check_name()
                .starts_with("Custom-Check-Authentication-")
        })
        .count()
}

/// Scan `src/index.js` (plus any extra `// path` sections in `files`) behind one
/// public web trigger and count Authentication findings.
fn authentication_findings_for(index: &str, files: &str) -> usize {
    authentication_findings(&report_for(index, files))
}

fn report_for(index: &str, files: &str) -> Report {
    let source = format!("// src/index.js\n{index}\n{files}\n{MANIFEST}");
    scan_directory_test(MockForgeProject::files_from_string(&source))
}

fn findings(index: &str) -> usize {
    authentication_findings_for(index, "")
}

const AS_APP: &str = "api.asApp().requestJira(route`/rest/api/3/myself`);";

fn handler(imports: &str, body: &str) -> String {
    format!(
        "import api, {{ route }} from '@forge/api';
        {imports}
        export const run = async (request) => {{
            {body}
        }};"
    )
}

#[test]
fn baseline_without_verification_is_reported() {
    assert_eq!(findings(&handler("", AS_APP)), 1);
}

#[test]
fn crypto_import_forms_before_privileged_operation_suppress() {
    let forms = [
        (
            "import crypto from 'node:crypto';",
            "crypto.verify(null, data, key, sig);",
        ),
        (
            "import crypto from 'crypto';",
            "crypto.verify(null, data, key, sig);",
        ),
        (
            "import * as crypto from 'node:crypto';",
            "crypto.verify(null, data, key, sig);",
        ),
        (
            "import * as c from 'crypto';",
            "c.verify(null, data, key, sig);",
        ),
        (
            "import { verify } from 'node:crypto';",
            "verify(null, data, key, sig);",
        ),
        (
            "import { verify as check } from 'crypto';",
            "check(null, data, key, sig);",
        ),
        (
            "import crypto, { verify as v } from 'crypto';",
            "v(null, data, key, sig);",
        ),
    ];
    for (import, call) in forms {
        let src = handler(import, &format!("{call} {AS_APP}"));
        assert_eq!(findings(&src), 0, "{import} {call}");
    }
}

#[test]
fn jsonwebtoken_verify_before_privileged_operation_suppresses() {
    for (import, call) in [
        ("import jwt from 'jsonwebtoken';", "jwt.verify(token, key);"),
        (
            "import * as jwt from 'jsonwebtoken';",
            "jwt.verify(token, key);",
        ),
        (
            "import { verify } from 'jsonwebtoken';",
            "verify(token, key);",
        ),
    ] {
        let src = handler(import, &format!("{call} {AS_APP}"));
        assert_eq!(findings(&src), 0, "{import}");
    }
}

#[test]
fn verification_reached_through_helpers_suppresses() {
    let src = "import api, { route } from '@forge/api';
        import crypto from 'node:crypto';
        function verifyToken(token, key) { return crypto.verify(null, token, key, token); }
        function authenticate(request) { return verifyToken(request.body, request.key); }
        export const run = async (request) => {
            authenticate(request);
            api.asApp().requestJira(route`/rest/api/3/myself`);
        };";
    assert_eq!(findings(src), 0);
}

#[test]
fn privileged_operation_in_callee_after_caller_verification_is_suppressed() {
    let src = "import api, { route } from '@forge/api';
        import crypto from 'node:crypto';
        function load() { return api.asApp().requestJira(route`/rest/api/3/myself`); }
        export const run = async (request) => {
            crypto.verify(null, request.body, request.key, request.sig);
            return load();
        };";
    assert_eq!(findings(src), 0);
}

#[test]
fn rmsis_gateway_structure_suppresses() {
    let index = "import api, { route } from '@forge/api';
        import { isAuthenticatedGatewayCall } from './auth.js';
        import { safeRequestJiraJson } from './jira-api.js';
        async function handleGetLoggedInUser(decoded) {
            return await safeRequestJiraJson('GET', route`/rest/api/3/myself`, null, 'me');
        }
        export async function run(request, context) {
            try {
                const body = JSON.parse(request.body);
                const decoded = { token: body.key, user: body.user };
                if (!isAuthenticatedGatewayCall(decoded, context)) {
                    return { statusCode: 401 };
                }
                switch (body.action) {
                    case 'getLoggedInUser':
                        return await handleGetLoggedInUser(decoded);
                    default:
                        return { statusCode: 400 };
                }
            } catch (error) {
                return { statusCode: 500 };
            }
        }";
    let files = "// src/auth.js
        import crypto from 'node:crypto';
        function verifyLoginToken(token, expected, key) {
            let signatureValid = false;
            try {
                signatureValid = crypto.verify(null, Buffer.from(token), crypto.createPublicKey(key), Buffer.from(token));
            } catch (error) {
                return { ok: false, reason: 'bad-signature' };
            }
            return { ok: signatureValid };
        }
        export function isAuthenticatedGatewayCall(decoded, context) {
            const result = verifyLoginToken(decoded.token, { accountId: decoded.user }, context.key);
            return result.ok;
        }
        // src/jira-api.js
        import api from '@forge/api';
        export async function requestJiraJson(method, routeObj, body) {
            const response = await api.asApp().requestJira(routeObj, { method });
            return await response.json();
        }
        export async function safeRequestJiraJson(method, routeObj, body, label) {
            try {
                return await requestJiraJson(method, routeObj, body);
            } catch (error) {
                return null;
            }
        }";
    assert_eq!(authentication_findings_for(index, files), 0);

    // The same app without the verification call is still reported.
    let unverified = files.replace(
        "signatureValid = crypto.verify(null, Buffer.from(token), crypto.createPublicKey(key), Buffer.from(token));",
        "signatureValid = true;",
    );
    assert_eq!(authentication_findings_for(index, &unverified), 1);
}

#[test]
fn ignored_result_still_suppresses() {
    let src = handler(
        "import crypto from 'node:crypto';",
        &format!("crypto.verify(null, data, key, sig); {AS_APP}"),
    );
    assert_eq!(findings(&src), 0);
}

#[test]
fn caught_failure_followed_by_operation_still_suppresses() {
    let src = handler(
        "import jwt from 'jsonwebtoken';",
        &format!(
            "try {{ jwt.verify(token, key); }} catch (error) {{ console.log('bad'); }} {AS_APP}"
        ),
    );
    assert_eq!(findings(&src), 0);
}

#[test]
fn verification_after_the_operation_does_not_suppress() {
    let src = handler(
        "import crypto from 'node:crypto';",
        &format!("{AS_APP} crypto.verify(null, data, key, sig);"),
    );
    assert_eq!(findings(&src), 1);
}

#[test]
fn unused_verification_helper_does_not_qualify() {
    let src = "import api, { route } from '@forge/api';
        import crypto from 'node:crypto';
        function unusedCheck(data, key, sig) { return crypto.verify(null, data, key, sig); }
        export const run = async (request) => {
            api.asApp().requestJira(route`/rest/api/3/myself`);
        };";
    assert_eq!(findings(src), 1);
}

#[test]
fn verification_in_another_entrypoint_grants_no_exemption() {
    let src = "// src/index.js
        import api, { route } from '@forge/api';
        import crypto from 'node:crypto';
        export const guarded = async (request) => {
            crypto.verify(null, request.body, request.key, request.sig);
            api.asApp().requestJira(route`/rest/api/3/myself`);
        };
        export const second = async (request) => {
            api.asApp().requestJira(route`/rest/api/3/priority`);
        };
        // manifest.yml
        modules:
          webtrigger:
            - key: guarded-trigger
              function: guarded
            - key: second-trigger
              function: second
          function:
            - key: guarded
              handler: index.guarded
            - key: second
              handler: index.second
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes: []";
    let project = MockForgeProject::files_from_string(src);
    let report = scan_directory_test(project);
    // Only the unguarded trigger is reported, whichever order they are scanned in.
    assert_eq!(authentication_findings(&report), 1);
    let reversed = src
        .replace("guarded", "tmp")
        .replace("second", "guarded")
        .replace("tmp", "second");
    let report = scan_directory_test(MockForgeProject::files_from_string(&reversed));
    assert_eq!(authentication_findings(&report), 1);
}

#[test]
fn foreign_or_shadowed_verify_does_not_qualify() {
    for (imports, call) in [
        ("import { verify } from 'other-lib';", "verify(data);"),
        ("import other from 'other-lib';", "other.verify(data);"),
        ("import { verify } from 'crypto-js';", "verify(data);"),
        (
            "import crypto from 'other-lib';",
            "crypto.verify(null, data, key, sig);",
        ),
        ("function verify(data) { return true; }", "verify(data);"),
        (
            "import { verify } from 'node:crypto'; function wrap() { const verify = (x) => x; verify(1); }",
            "wrap();",
        ),
        (
            "const checker = { verify(data) { return true; } };",
            "checker.verify(data);",
        ),
    ] {
        let src = handler(imports, &format!("{call} {AS_APP}"));
        assert_eq!(findings(&src), 1, "{imports} {call}");
    }
}

#[test]
fn signing_hashing_encryption_decoding_and_extraction_do_not_qualify() {
    for (imports, call) in [
        (
            "import crypto from 'node:crypto';",
            "crypto.sign(null, data, privateKey);",
        ),
        (
            "import crypto from 'node:crypto';",
            "crypto.createHash('sha256').update(data).digest('hex');",
        ),
        (
            "import crypto from 'node:crypto';",
            "crypto.createHmac('sha256', key);",
        ),
        (
            "import crypto from 'node:crypto';",
            "crypto.publicEncrypt(key, data);",
        ),
        (
            "import crypto from 'node:crypto';",
            "crypto.randomBytes(16);",
        ),
        ("import jwt from 'jsonwebtoken';", "jwt.sign(payload, key);"),
        ("import jwt from 'jsonwebtoken';", "jwt.decode(token);"),
        (
            "import bcrypt from 'bcrypt';",
            "bcrypt.compare(password, hash);",
        ),
        (
            "import bcryptjs from 'bcryptjs';",
            "bcryptjs.compareSync(password, hash);",
        ),
        (
            "import argon2 from 'argon2';",
            "argon2.verify(hash, password);",
        ),
        (
            "",
            "const token = request.headers.authorization.split(' ')[1];",
        ),
    ] {
        let src = handler(imports, &format!("{call} {AS_APP}"));
        assert_eq!(findings(&src), 1, "{imports} {call}");
    }
}

#[test]
fn verification_only_entries_do_not_classify_public_keys_as_secrets() {
    let src = handler(
        "import crypto from 'node:crypto'; import jwt from 'jsonwebtoken';",
        "crypto.verify(null, data, 'literal public key', sig);
         crypto.verify(null, data, key, sig);",
    );
    assert!(report_for(&src, "").contains_secret_vuln(0));
}

#[test]
fn existing_hardcoded_secret_checks_remain_stable() {
    // jsonwebtoken.verify keeps its secret position even though it is now also
    // an authentication check.
    let src = handler(
        "import jwt from 'jsonwebtoken';",
        &format!("jwt.verify(token, 'hardcoded'); {AS_APP}"),
    );
    let report = report_for(&src, "");
    assert!(report.contains_secret_vuln(1));
    assert_eq!(authentication_findings(&report), 0);

    let src = handler(
        "import crypto from 'crypto';",
        &format!("crypto.createHmac('sha256', 'hardcoded'); {AS_APP}"),
    );
    let report = report_for(&src, "");
    assert!(report.contains_secret_vuln(1));
    assert_eq!(authentication_findings(&report), 1);
}

#[test]
fn missing_or_zero_secret_position_cannot_underflow() {
    let packages: Vec<PackageData> = serde_yaml::from_str(
        "- package_name: some-lib
  identifier: check
  method:
- package_name: some-lib
  identifier: zero
  method:
  secret_position: 0
- package_name: some-lib
  identifier: far
  method:
  secret_position: 200
- package_name: some-lib
  identifier: checkAuth
  method:
  authentication_check: true",
    )
    .unwrap();
    assert_eq!(packages[0].secret_position, None);
    assert!(!packages[0].authentication_check);
    assert!(packages[3].authentication_check);

    let src = handler(
        "import lib from 'some-lib';",
        &format!("lib.check('x'); lib.zero('x'); lib.far('x'); {AS_APP}"),
    );
    let source = format!("// src/index.js\n{src}\n{MANIFEST}");
    let project = MockForgeProject::files_from_string(&source);
    let mut args = Args::parse_from([""]);
    let report = scan_directory(PathBuf::new(), &mut args, project, &packages)
        .unwrap_or_else(|err| panic!("error while scanning {err:?}"));
    assert!(report.contains_secret_vuln(0));

    let src = handler(
        "import lib from 'some-lib';",
        &format!("lib.checkAuth('x'); {AS_APP}"),
    );
    let source = format!("// src/index.js\n{src}\n{MANIFEST}");
    let project = MockForgeProject::files_from_string(&source);
    let report = scan_directory(PathBuf::new(), &mut args, project, &packages)
        .unwrap_or_else(|err| panic!("error while scanning {err:?}"));
    assert_eq!(authentication_findings(&report), 0);
}

#[test]
fn builtin_catalogs_keep_existing_entries_unmodified() {
    let packages = crate::builtin_packages();
    let secret_entries =
        serde_yaml::from_str::<Vec<PackageData>>(include_str!("../../../../secretdata.yaml"))
            .unwrap();
    assert_eq!(&packages[..secret_entries.len()], &secret_entries[..]);
    assert!(
        secret_entries
            .iter()
            .all(|entry| !entry.authentication_check)
    );
    assert!(
        secret_entries
            .iter()
            .all(|entry| entry.secret_position.is_some())
    );
}

#[test]
fn unsupported_import_forms_do_not_qualify() {
    // CommonJS require is not resolved to an import by the lowering (the same
    // holds for every secretdata.yaml entry), and neither are dynamic imports,
    // namespace member aliases or createVerify objects. They are not recognized.
    for (imports, call) in [
        (
            "const crypto = require('crypto');",
            "crypto.verify(null, data, key, sig);",
        ),
        (
            "const { verify } = require('node:crypto');",
            "verify(null, data, key, sig);",
        ),
        (
            "import crypto from 'node:crypto';",
            "crypto.createVerify('SHA256').verify(key, sig);",
        ),
        (
            "import { webcrypto } from 'node:crypto';",
            "webcrypto.subtle.verify('Ed25519', key, sig, data);",
        ),
    ] {
        let src = handler(imports, &format!("{call} {AS_APP}"));
        assert_eq!(findings(&src), 1, "{imports} {call}");
    }
}

#[test]
fn shared_verification_helper_suppresses_every_entrypoint() {
    // Only the first entry point walks the helper body; the second relies on the
    // summary computed by the dataflow pass.
    let src = "// src/index.js
        import api, { route } from '@forge/api';
        import crypto from 'node:crypto';
        function authenticate(request) {
            return crypto.verify(null, request.body, request.key, request.sig);
        }
        export const first = async (request) => {
            authenticate(request);
            api.asApp().requestJira(route`/rest/api/3/myself`);
        };
        export const second = async (request) => {
            authenticate(request);
            api.asApp().requestConfluence(route`/wiki/api/v2/pages`);
        };
        // manifest.yml
        modules:
          webtrigger:
            - key: first-trigger
              function: first
            - key: second-trigger
              function: second
          function:
            - key: first
              handler: index.first
            - key: second
              handler: index.second
        app:
          id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
        permissions:
          scopes: []";
    let report = scan_directory_test(MockForgeProject::files_from_string(src));
    assert_eq!(authentication_findings(&report), 0);
}
