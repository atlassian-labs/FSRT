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
    for folder in ["static", "node_modules", ".hidden", "lib/static"] {
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
