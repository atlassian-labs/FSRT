//! First-party code beside `src/` (`lib/helper.js`, `common/util/request-util.ts`) is loaded and
//! followed from entrypoints in `src/`.

use super::*;

const MANIFEST: &str = "// manifest.yaml
modules:
    macro:
      - key: resolver-macro
        function: main
        title: resolver
        handler: nothing
        description: Resolver backed macro
    function:
      - key: main
        handler: index.handler
app:
    id: ari:cloud:ecosystem::app/07b89c0f-949a-4905-9de9-6c9521035986
permissions:
    scopes: []";

const HELPER_REQUEST: &str = "import api, { route } from '@forge/api';
export async function fetchIssue(key) {
    const r = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
    return r.json();
}";

const GUARD: &str = "import { authorize } from '@forge/api';
export async function requireAdmin() {
    const p = await authorize().onJira([{ permissions: ['ADMINISTER'] }]);
    if (!p.every(x => x.permission === 'ADMINISTER')) throw new Error('no');
}";

const FETCH_ENTRY: &str = "import Resolver from '@forge/resolver';
import { fetchIssue } from '../lib/helper';
const resolver = new Resolver();
resolver.define('get', async (req) => fetchIssue(req.payload.key));
export const handler = resolver.getDefinitions();";

const GUARDED_ENTRY: &str = "import Resolver from '@forge/resolver';
import api, { route } from '@forge/api';
import { requireAdmin } from '../lib/guard';
const resolver = new Resolver();
resolver.define('get', async (req) => {
    await requireAdmin();
    const r = await api.asApp().requestJira(route`/rest/api/3/issue/${req.payload.key}`);
    return r.json();
});
export const handler = resolver.getDefinitions();";

fn authz_findings(files: &[(&str, &str)]) -> usize {
    let mut project = MockForgeProject::files_from_string(MANIFEST);
    for (path, source) in files {
        project.add_file(*path, *source);
    }
    scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    )
    .into_vulns()
    .iter()
    .filter(|vuln| vuln.check_name().contains("Authorization"))
    .count()
}

/// Toy A: helper under `src/`.
#[test]
fn privileged_call_in_helper_inside_src_is_reported() {
    let findings = authz_findings(&[
        ("src/index.js", &FETCH_ENTRY.replace("../lib/", "./lib/")),
        ("src/lib/helper.js", HELPER_REQUEST),
    ]);
    assert_eq!(findings, 1);
}

/// Toy B: the same helper in a root-level folder used to be skipped, so nothing was reported.
#[test]
fn privileged_call_in_helper_outside_src_is_reported() {
    let findings = authz_findings(&[
        ("src/index.js", FETCH_ENTRY),
        ("lib/helper.js", HELPER_REQUEST),
    ]);
    assert_eq!(findings, 1);
}

/// Toy C: an `authorize()` guard in a root-level folder used to be skipped, which left the
/// request after it flagged.
#[test]
fn authorize_guard_outside_src_clears_the_request_after_it() {
    let findings = authz_findings(&[("src/index.js", GUARDED_ENTRY), ("lib/guard.js", GUARD)]);
    assert_eq!(findings, 0);
}

/// Toy D: guard under `src/`.
#[test]
fn authorize_guard_inside_src_clears_the_request_after_it() {
    let findings = authz_findings(&[
        ("src/index.js", &GUARDED_ENTRY.replace("../lib/", "./lib/")),
        ("src/lib/guard.js", GUARD),
    ]);
    assert_eq!(findings, 0);
}

#[test]
fn nested_import_chain_through_folders_outside_src_is_followed() {
    let findings = authz_findings(&[
        (
            "src/index.js",
            &FETCH_ENTRY
                .replace("../lib/helper", "../common/util/request-util")
                .replace("fetchIssue", "load"),
        ),
        (
            "common/util/request-util.ts",
            "import { fetchIssue } from '../../shared/issues';
             export const load = (key: string) => fetchIssue(key);",
        ),
        ("shared/issues.js", HELPER_REQUEST),
    ]);
    assert_eq!(findings, 1);
}

/// `lib/axios.js` doing `import axios from 'axios'` resolved to itself, which tripped a debug
/// assertion once files beside `src/` were loaded.
#[test]
fn module_importing_a_package_named_like_itself_is_not_a_self_import() {
    let wrapper = "import api, { route } from '@forge/api';
        import axios from 'axios';
        import * as wrapper from 'axios';
        import { get } from 'axios';
        export async function fetchIssue(key) {
            const r = await api.asApp().requestJira(route`/rest/api/3/issue/${key}`);
            return axios.get(key) && wrapper && get && r.json();
        }";
    for wrapper_path in ["lib/axios.js", "src/lib/axios.js"] {
        let entry = if wrapper_path.starts_with("src") {
            FETCH_ENTRY.replace("../lib/helper", "./lib/axios")
        } else {
            FETCH_ENTRY.replace("../lib/helper", "../lib/axios")
        };
        let findings = authz_findings(&[("src/index.js", &entry), (wrapper_path, wrapper)]);
        assert_eq!(findings, 1, "{wrapper_path}");
    }
}

#[test]
fn unparseable_file_outside_src_is_skipped_but_one_in_src_still_fails() {
    let mut project = MockForgeProject::files_from_string(MANIFEST);
    project.add_file("src/index.js", FETCH_ENTRY);
    project.add_file("lib/helper.js", HELPER_REQUEST);
    project.add_file("scripts/broken.js", "const = ;");
    let report = scan_directory_test_with_args(
        project,
        Args::parse_from(["fsrt", "--scanners", "authorization"]),
    );
    assert!(report.contains_authz_vuln(1), "{report:#?}");

    let mut project = MockForgeProject::files_from_string(MANIFEST);
    project.add_file("src/index.js", FETCH_ENTRY);
    project.add_file("src/broken.js", "const = ;");
    let mut args = Args::parse_from(["fsrt", "--scanners", "authorization"]);
    assert!(
        scan_directory(PathBuf::new(), &mut args, project, &[]).is_err(),
        "a file in src/ that does not parse still fails the scan"
    );
}

struct TempApp(PathBuf);

impl TempApp {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("fsrt-outside-src-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn write(&self, path: &str, source: &str) {
        let path = self.0.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, source).unwrap();
    }

    /// Paths of the files found beside `src/`, relative to the app and sorted.
    fn outside_src(&self) -> Vec<String> {
        let mut found = crate::collect_sourcefiles_outside_src(&self.0)
            .iter()
            .map(|path| {
                path.strip_prefix(&self.0)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        found.sort();
        found
    }
}

impl Drop for TempApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn first_party_folders_beside_src_are_collected_without_hosted_or_third_party_code() {
    let app = TempApp::new("collect");
    app.write("src/index.js", "");
    app.write("lib/helper.js", "");
    app.write("lib/types.d.ts", "");
    app.write("lib/readme.md", "");
    app.write("common/util/request-util.ts", "");
    app.write("shared/config.jsx", "");
    app.write("static/hello/index.js", "");
    app.write("webpack/my-project/src/leftover.js", "");
    app.write("bundled/index.js", "");
    app.write("lib/webpack/config.js", "");
    app.write("node_modules/pkg/index.js", "");
    app.write(".storybook/main.js", "");
    app.write("lib/node_modules/pkg/index.js", "");
    app.write("client/static/bundle.js", "");
    app.write("lib/.cache/entry.js", "");
    app.write("root.js", "");

    assert_eq!(
        app.outside_src(),
        [
            "common/util/request-util.ts",
            "lib/helper.js",
            "lib/types.d.ts",
            "shared/config.jsx",
        ]
    );
}

#[test]
fn folders_beside_src_use_the_same_depth_cap_as_src() {
    let app = TempApp::new("depth");
    app.write("lib/a/b/c/d/within.js", "");
    app.write("lib/a/b/c/d/e/too-deep.js", "");

    assert_eq!(app.outside_src(), ["lib/a/b/c/d/within.js"]);
}

#[cfg(unix)]
#[test]
fn symlinks_beside_src_are_not_followed() {
    let app = TempApp::new("symlink");
    let elsewhere = TempApp::new("symlink-target");
    elsewhere.write("outside/secret.js", "");
    elsewhere.write("file.js", "");
    app.write("lib/helper.js", "");
    std::os::unix::fs::symlink(elsewhere.0.join("outside"), app.0.join("linked")).unwrap();
    std::os::unix::fs::symlink(elsewhere.0.join("outside"), app.0.join("lib/linked")).unwrap();
    std::os::unix::fs::symlink(elsewhere.0.join("file.js"), app.0.join("lib/file.js")).unwrap();

    assert_eq!(app.outside_src(), ["lib/helper.js"]);
}

#[cfg(unix)]
#[test]
fn symlinked_js_files_under_src_are_still_collected() {
    let app = TempApp::new("src-symlink");
    let elsewhere = TempApp::new("src-symlink-target");
    elsewhere.write("linked.js", "");
    app.write("src/index.js", "");
    std::os::unix::fs::symlink(elsewhere.0.join("linked.js"), app.0.join("src/linked.js")).unwrap();

    let mut found = crate::collect_sourcefiles(app.0.join("src"))
        .map(|path| path.strip_prefix(&app.0).unwrap().to_owned())
        .collect::<Vec<_>>();
    found.sort();
    assert_eq!(
        found,
        [
            PathBuf::from("src/index.js"),
            PathBuf::from("src/linked.js")
        ]
    );
}

#[test]
fn project_from_dir_scans_src_and_first_party_folders() {
    let app = TempApp::new("from-dir");
    app.write("src/index.js", "");
    app.write("lib/helper.js", "");
    app.write("static/ui.js", "");
    let project = crate::forge_project::ForgeProjectFromDir {
        dir: app.0.clone(),
        manifest_file_content: String::new(),
    };

    let mut paths = project
        .get_paths()
        .into_iter()
        .map(|path| path.strip_prefix(&app.0).unwrap().to_owned())
        .collect::<Vec<_>>();
    paths.sort();
    assert_eq!(
        paths,
        [
            PathBuf::from("lib/helper.js"),
            PathBuf::from("src/index.js")
        ]
    );
}

/// Older reverse-sourcemapped trees keep `webpack/<project>/` copies of the bundled sources
/// beside `src/` and inside other folders, and a `bundled/` folder beside `src/`.
#[test]
fn webpack_folders_are_not_read_at_any_depth_and_bundled_only_beside_src() {
    let app = TempApp::new("webpack");
    app.write("webpack/my-project/src/leftover.js", "");
    app.write("webpack/bootstrap/index.js", "");
    app.write("bundled/webpack/my-project/src/leftover.js", "");
    app.write("bundled/index.js", "");
    app.write("resolvers/webpack/my-project/src/store.ts", "");
    app.write("resolvers/index.ts", "");
    app.write("webpack.config.js", "");
    app.write("lib/webpack/config.js", "");
    app.write("lib/bundled/index.js", "");

    assert_eq!(
        app.outside_src(),
        ["lib/bundled/index.js", "resolvers/index.ts"]
    );
}
