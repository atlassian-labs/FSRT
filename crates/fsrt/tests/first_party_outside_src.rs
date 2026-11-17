//! End-to-end scans of apps whose first-party code sits beside `src/`, as the reverse
//! sourcemapper writes it (`lib/helper.js`, `common/util/request-util.ts`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MANIFEST: &str = "modules:
  jira:globalPage:
    - key: p
      resource: web
      resolver:
        function: resolver
      title: T
  function:
    - key: resolver
      handler: index.handler
resources:
  - key: web
    path: web
permissions:
  scopes:
    - read:jira-work
app:
  id: ari:cloud:ecosystem::app/00000000-0000-0000-0000-000000000000
";

const FETCH_ENTRY: &str = r#"import Resolver from "@forge/resolver";
import { fetchIssue } from "IMPORT";
const resolver = new Resolver();
resolver.define("get", async (req) => {
  return fetchIssue(req.payload.key);
});
export const handler = resolver.getDefinitions();
"#;

const FETCH_HELPER: &str = r#"import api, { route } from "@forge/api";
export async function fetchIssue(key) {
  const r = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
  return r.json();
}
"#;

const GUARDED_ENTRY: &str = r#"import Resolver from "@forge/resolver";
import api, { route } from "@forge/api";
import { requireAdmin } from "IMPORT";
const resolver = new Resolver();
resolver.define("get", async (req) => {
  await requireAdmin();
  const r = await api.asApp().requestJira(route`/rest/api/3/issue/${req.payload.key}`);
  return r.json();
});
export const handler = resolver.getDefinitions();
"#;

const GUARD: &str = r#"import { authorize } from "@forge/api";
export async function requireAdmin() {
  const p = await authorize().onJira([{ permissions: ["ADMINISTER"] }]);
  if (!p.every(x => x.permission === "ADMINISTER")) throw new Error("no");
}
"#;

struct App(PathBuf);

impl App {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("outside-src-{name}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let app = Self(dir);
        app.write("manifest.yml", MANIFEST);
        app
    }

    fn write(&self, path: &str, source: &str) -> &Self {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, source).unwrap();
        self
    }

    fn scan(&self) -> (bool, serde_json::Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_fsrt"))
            .args(["--scanners", "authorization", "--no-cache"])
            .arg(&self.0)
            .env_remove("FORGE_LOG")
            .output()
            .unwrap();
        let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "{error}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.success(), report)
    }

    fn findings(&self) -> usize {
        let (success, report) = self.scan();
        assert!(success && report["errors"] == false, "{report}");
        report["vulns"].as_array().unwrap().len()
    }
}

impl Drop for App {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn entry(template: &str, import: &str) -> String {
    template.replace("IMPORT", import)
}

#[test]
fn toy_a_helper_inside_src_is_reported() {
    let app = App::new("toy-a");
    app.write("src/index.js", &entry(FETCH_ENTRY, "./lib/helper"))
        .write("src/lib/helper.js", FETCH_HELPER);
    assert_eq!(app.findings(), 1);
}

#[test]
fn toy_b_helper_beside_src_is_reported() {
    let app = App::new("toy-b");
    app.write("src/index.js", &entry(FETCH_ENTRY, "../lib/helper"))
        .write("lib/helper.js", FETCH_HELPER);
    assert_eq!(app.findings(), 1);
}

#[test]
fn toy_c_guard_beside_src_clears_the_request() {
    let app = App::new("toy-c");
    app.write("src/index.js", &entry(GUARDED_ENTRY, "../lib/guard"))
        .write("lib/guard.js", GUARD);
    assert_eq!(app.findings(), 0);
}

#[test]
fn toy_d_guard_inside_src_clears_the_request() {
    let app = App::new("toy-d");
    app.write("src/index.js", &entry(GUARDED_ENTRY, "./lib/guard"))
        .write("src/lib/guard.js", GUARD);
    assert_eq!(app.findings(), 0);
}

#[test]
fn hosted_and_third_party_folders_are_not_scanned() {
    for folder in [
        "static",
        "node_modules",
        ".hidden",
        "lib/static",
        "webpack",
        "bundled",
    ] {
        let app = App::new("excluded");
        app.write(
            "src/index.js",
            &entry(FETCH_ENTRY, &format!("../{folder}/helper")),
        )
        .write(&format!("{folder}/helper.js"), FETCH_HELPER);
        assert_eq!(app.findings(), 0, "{folder}");
    }
}

#[test]
fn handler_beside_src_is_not_an_entrypoint() {
    let app = App::new("handler");
    app.write("lib/index.js", &entry(FETCH_ENTRY, "./helper"))
        .write("lib/helper.js", FETCH_HELPER);
    let (_, report) = app.scan();
    assert_eq!(report["vulns"], serde_json::json!([]), "{report}");
}

#[cfg(unix)]
#[test]
fn symlinked_folder_beside_src_is_not_followed() {
    let app = App::new("symlink");
    let elsewhere = App::new("symlink-target");
    elsewhere.write("lib/helper.js", FETCH_HELPER);
    std::os::unix::fs::symlink(elsewhere.0.join("lib"), app.0.join("lib")).unwrap();
    app.write("src/index.js", &entry(FETCH_ENTRY, "../lib/helper"));
    assert_eq!(app.findings(), 0);
}

#[test]
fn package_wrapper_named_like_the_package_it_imports_does_not_crash() {
    let app = App::new("self-import");
    app.write("src/index.js", &entry(FETCH_ENTRY, "../lib/axios"))
        .write(
            "lib/axios.js",
            &format!(
                "import axios from \"axios\";\nimport * as ns from \"axios\";\n{FETCH_HELPER}"
            ),
        );
    assert_eq!(app.findings(), 1);
}

#[test]
fn broken_or_transpiled_files_beside_src_do_not_fail_the_scan() {
    let app = App::new("best-effort");
    app.write("src/index.js", &entry(FETCH_ENTRY, "../lib/helper"))
        .write("lib/helper.js", FETCH_HELPER)
        .write("scripts/broken.js", "const = ;")
        .write("dist/bundle.js", "var _asyncToGenerator = function () {};");
    assert_eq!(app.findings(), 1);
}

#[test]
fn transpiled_async_in_src_still_fails_the_scan() {
    let app = App::new("transpiled-src");
    app.write("src/index.js", &entry(FETCH_ENTRY, "./helper"))
        .write("src/helper.js", "var _asyncToGenerator = function () {};");
    let (success, report) = app.scan();
    assert!(!success || report["errors"] == true, "{report}");
}

const SELF_IMPORT: &str = r#"import Resolver from "@forge/resolver";
import api, { route } from "@forge/api";
import * as self from "./index";
import { fetchIssue as again } from "./index";
const resolver = new Resolver();
resolver.define("get", async (req) => self.fetchIssue(req.payload.key));
resolver.define("again", async (req) => again(req.payload.key));
export async function fetchIssue(key) {
  const r = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
  return r.json();
}
export const handler = resolver.getDefinitions();
"#;

/// A module may import itself, and modules may import each other: the scan resolves these,
/// terminates and does not trip a debug assertion.
#[test]
fn a_module_that_imports_itself_is_resolved_and_scanned() {
    let app = App::new("self-import-module");
    app.write("src/index.js", SELF_IMPORT);
    assert_eq!(app.findings(), 1);
}

#[test]
fn a_helper_that_imports_itself_is_resolved_and_scanned() {
    let app = App::new("self-import-helper");
    app.write("src/index.js", &entry(FETCH_ENTRY, "./lib/helper"))
        .write(
            "src/lib/helper.js",
            &format!(
                "import * as me from \"./helper\";\nexport const again = (key) => me.fetchIssue(key);\n{FETCH_HELPER}"
            ),
        );
    assert_eq!(app.findings(), 1);
}

#[test]
fn circular_imports_between_modules_are_resolved_and_scanned() {
    let app = App::new("circular");
    app.write(
        "src/index.js",
        &entry(FETCH_ENTRY, "./a").replace("fetchIssue", "fromA"),
    )
    .write(
        "src/a.js",
        "import { fromB } from \"./b\";\nexport const fromA = (key) => fromB(key);\nexport const ping = (n) => (n > 0 ? fromB(n - 1) : 0);\n",
    )
    .write(
        "src/b.js",
        &format!(
            "import {{ ping }} from \"./a\";\nexport const fromB = (key) => {{ ping(0); return fetchIssue(key); }};\n{FETCH_HELPER}"
        ),
    );
    assert_eq!(app.findings(), 1);
}

/// `import x from "axios"` names the package: not a sibling file, and not `src/axios.js` when
/// the app declares `axios` in its `package.json`.
#[test]
fn bare_imports_of_declared_packages_are_foreign_not_first_party() {
    let package_json = r#"{"dependencies": {"axios": "^1.0.0", "fs-extra": "1"}}"#;
    for (name, importer) in [
        ("bare-src", "src/index.js"),
        ("bare-lib", "lib/axios.js"),
        ("bare-sibling", "lib/sibling.js"),
    ] {
        let app = App::new(name);
        app.write("package.json", package_json)
            .write("src/axios.js", FETCH_HELPER)
            .write("lib/axios.js", FETCH_HELPER);
        if importer == "src/index.js" {
            app.write(importer, &entry(FETCH_ENTRY, "axios"));
        } else {
            app.write("src/index.js", &entry(FETCH_ENTRY, &format!("../{}", importer.trim_end_matches(".js"))))
                .write(
                    importer,
                    &format!("import {{ fetchIssue as pkg }} from \"axios\";\nexport const fetchIssue = (key) => pkg(key);\n"),
                );
        }
        assert_eq!(app.findings(), 0, "{name}: the import is the axios package");
    }
}

/// Without a `package.json` that declares it, `axios` may be a `baseUrl`-style import of
/// `src/axios.js`; a relative `./axios` is always the file.
#[test]
fn undeclared_bare_imports_may_name_a_file_under_src_and_relative_ones_always_do() {
    let app = App::new("bare-undeclared");
    app.write("src/index.js", &entry(FETCH_ENTRY, "axios"))
        .write("src/axios.js", FETCH_HELPER);
    assert_eq!(app.findings(), 1);

    let app = App::new("relative-axios");
    app.write("package.json", r#"{"dependencies": {"axios": "1"}}"#)
        .write("src/index.js", &entry(FETCH_ENTRY, "./axios"))
        .write("src/axios.js", FETCH_HELPER);
    assert_eq!(app.findings(), 1);
}

#[test]
fn node_builtins_and_scoped_packages_stay_foreign_even_with_a_file_of_that_name() {
    for specifier in ["fs", "node:fs", "path", "@forge/api"] {
        let app = App::new("builtin");
        app.write("src/index.js", &entry(FETCH_ENTRY, specifier))
            .write("src/fs.js", FETCH_HELPER)
            .write("src/path.js", FETCH_HELPER)
            .write("src/@forge/api.js", FETCH_HELPER);
        assert_eq!(app.findings(), 0, "{specifier}");
    }
}

/// Self and cyclic `export *` / `export * as` re-exports do not make the scan loop or panic.
#[test]
fn self_and_cyclic_re_exports_terminate() {
    let app = App::new("re-export-cycle");
    app.write("src/index.js", r#"import Resolver from "@forge/resolver";
import api, { route } from "@forge/api";
import { fromA } from "./a";
export * from "./index";
export * as me from "./index";
import def from "./index";
const resolver = new Resolver();
resolver.define("get", async (req) => fromA(req.payload.key));
export default function d() { return def(); }
export const handler = resolver.getDefinitions();
"#)
        .write("src/a.js", r#"import api, { route } from "@forge/api";
export * from "./b";
export * from "./a";
import { fromB } from "./b";
export async function fromA(key) { await fromB(key); return api.asApp().requestJira(route`/rest/api/3/issue/${key}`); }
"#)
        .write("src/b.js", r#"export * from "./a";
import * as a from "./a";
export async function fromB(key) { return a.fromA ? 1 : 0; }
"#);
    assert_eq!(app.findings(), 1);
}
