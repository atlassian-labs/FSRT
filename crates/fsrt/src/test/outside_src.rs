//! First-party code outside `src/` (`lib/helper.js`, `common/util/request-util.ts`) is loaded when
//! a file that is read imports it, and followed from entrypoints in `src/`.

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

    /// Paths of the files a scan of the app reads, relative to the app and sorted.
    fn read(&self) -> Vec<String> {
        let project = crate::forge_project::ForgeProjectFromDir {
            dir: self.0.clone(),
            manifest_file_content: String::new(),
        };
        let mut found = project
            .get_paths()
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

    /// Like [`Self::read`], without the files in `src/`.
    fn read_outside_src(&self) -> Vec<String> {
        let mut found = self.read();
        found.retain(|path| !path.starts_with("src/"));
        found
    }
}

impl Drop for TempApp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn only_files_imported_from_src_are_read_outside_it() {
    let app = TempApp::new("imported");
    app.write(
        "src/index.js",
        "import { a } from '../lib/helper';
         import b from '../common/util/request-util.ts';
         import '../shared/side-effect';
         export { c } from '../shared/reexport';
         export * from '../shared/star';
         const d = require('../shared/required');
         const e = await import('../shared/lazy');
         import {
           multi,
           line,
         } from '../shared/multi-line';
         import f from '/shared/from-the-app-root';
         import type { T } from '../shared/types';",
    );
    for file in [
        "lib/helper.js",
        "common/util/request-util.ts",
        "shared/side-effect.js",
        "shared/reexport.js",
        "shared/star.js",
        "shared/required.js",
        "shared/lazy.js",
        "shared/multi-line.js",
        "shared/from-the-app-root.js",
        "shared/types.ts",
        "lib/not-imported.js",
        "shared/not-imported.js",
        "root.js",
    ] {
        app.write(file, "");
    }

    assert_eq!(
        app.read_outside_src(),
        [
            "common/util/request-util.ts",
            "lib/helper.js",
            "shared/from-the-app-root.js",
            "shared/lazy.js",
            "shared/multi-line.js",
            "shared/reexport.js",
            "shared/required.js",
            "shared/side-effect.js",
            "shared/star.js",
            "shared/types.ts",
        ]
    );
}

/// A file under `static/` that `src/` imports is backend code that older assets folded into
/// `src/`; the front-end next to it, which nothing imports, is not read. The same holds for the
/// `webpack/` and `bundled/` leftovers.
#[test]
fn static_webpack_and_bundled_files_are_read_only_when_imported() {
    let app = TempApp::new("hosted");
    app.write(
        "src/index.js",
        "import x from '../static/shared/x.ts';
         import y from '../webpack/my-project/src/y';
         import z from '../bundled/z';",
    );
    for file in [
        "static/shared/x.ts",
        "static/ui/App.jsx",
        "static/hello/index.js",
        "webpack/my-project/src/y.js",
        "webpack/my-project/src/leftover.js",
        "webpack/bootstrap/index.js",
        "bundled/z.js",
        "bundled/index.js",
        "bundled/webpack/my-project/src/leftover.js",
        "lib/webpack/config.js",
        "resolvers/webpack/my-project/src/store.ts",
    ] {
        app.write(file, "");
    }

    assert_eq!(
        app.read_outside_src(),
        [
            "bundled/z.js",
            "static/shared/x.ts",
            "webpack/my-project/src/y.js"
        ]
    );
}

#[test]
fn files_are_followed_through_several_hops_and_cycles_end() {
    let app = TempApp::new("hops");
    app.write("src/index.js", "import { a } from '../lib/a';");
    app.write(
        "lib/a.js",
        "import { b } from './b';\nimport { self } from './a';",
    );
    app.write(
        "lib/b.js",
        "import { c } from '../common/c';\nimport { a } from './a';",
    );
    app.write(
        "common/c.js",
        "import { b } from '../lib/b';\nimport d from '../static/d';",
    );
    app.write("static/d.js", "export const d = 1;");
    app.write("lib/unrelated.js", "import { a } from './a';");

    assert_eq!(
        app.read_outside_src(),
        ["common/c.js", "lib/a.js", "lib/b.js", "static/d.js"]
    );
}

#[test]
fn imports_are_resolved_with_the_resolvers_rules() {
    let app = TempApp::new("rules");
    app.write(
        "package.json",
        r#"{ "dependencies": { "lodash": "1", "@scope/pkg": "1" } }"#,
    );
    app.write(
        "src/index.js",
        "import a from 'lodash';
         import b from 'fs';
         import c from '@scope/pkg';
         import d from 'common/util';
         import e from 'helper';
         import f from './a.service';
         import g from '../../outside-the-app';
         import h from '../lib/is-a-folder';
         import i from '../lib/hidden';
         import j from '../node_modules/pkg/index';
         import k from '../.cache/entry';
         import l from '../lib/prefers-js';
         import m from 'src-relative/thing';
         const n = require(variable);
         const o = require(`../lib/template`);",
    );
    for file in [
        // package names are never files of the app
        "lodash.js",
        "fs.js",
        "lib/lodash.js",
        "common/util.js",
        "helper.js",
        "lib/a.service.ts",
        "lib/is-a-folder/index.js",
        "node_modules/pkg/index.js",
        ".cache/entry.js",
        "lib/template.js",
        "lib/prefers-js.ts",
        "lib/prefers-js.js",
        "lib/hidden.d.txt",
        // a bare name that is not a package is looked up under src/ only
        "src/src-relative/thing.js",
    ] {
        app.write(file, "");
    }
    std::fs::create_dir_all(app.0.join("lib/is-a-folder.js")).unwrap();

    assert_eq!(
        app.read_outside_src(),
        ["lib/prefers-js.js"],
        "only the first of a file's extensions the resolver would pick is read"
    );
}

#[test]
fn files_deeper_than_the_src_depth_cap_are_read_when_imported() {
    let app = TempApp::new("deep");
    app.write("src/index.js", "import '../lib/a/b/c/d/e/f/imported';");
    app.write("lib/a/b/c/d/e/f/imported.js", "");
    app.write("lib/a/b/c/d/e/f/not-imported.js", "");

    assert_eq!(app.read_outside_src(), ["lib/a/b/c/d/e/f/imported.js"]);
}

#[test]
fn files_in_src_are_read_as_before() {
    let app = TempApp::new("src-as-before");
    app.write("src/index.js", "import '../lib/a';");
    app.write("src/nested/static/helper.js", "");
    app.write("src/nested/webpack/proj/x.js", "");
    app.write("src/a/b/c/d/e/f/too-deep.js", "");
    app.write("src/node_modules/pkg/index.js", "");
    app.write("lib/a.js", "import '../src/a/b/c/d/e/f/too-deep';");

    assert_eq!(
        app.read(),
        [
            "lib/a.js",
            "src/index.js",
            "src/nested/static/helper.js",
            "src/nested/webpack/proj/x.js",
            "src/node_modules/pkg/index.js",
        ],
        "a file in src/ out of the depth cap stays unread even when imported"
    );
}

/// One rule for `src/` and the files imported from it: regular files, and links to files inside
/// the app, are read; directories named like a source file, links to folders, links to files
/// outside the app, broken links and link loops are not.
#[cfg(unix)]
#[test]
fn symlinked_files_are_read_only_when_they_stay_inside_the_app() {
    use std::os::unix::fs::symlink;

    let app = TempApp::new("symlinks");
    let elsewhere = TempApp::new("symlinks-target");
    elsewhere.write("file.js", "");
    elsewhere.write("folder/secret.js", "");
    app.write("real.js", "");
    app.write("src/real.js", "");
    app.write("lib/real.js", "");
    let mut imports = String::new();
    for dir in ["src", "lib"] {
        let path = app.0.join(dir);
        // link to a file inside the app: read, under the path of the link
        symlink(app.0.join("real.js"), path.join("link-in.js")).unwrap();
        // links the scan must not follow
        symlink(elsewhere.0.join("file.js"), path.join("link-out.js")).unwrap();
        symlink(elsewhere.0.join("folder"), path.join("folder-out")).unwrap();
        symlink(app.0.join("lib"), path.join("folder-in")).unwrap();
        symlink(app.0.join("lib"), path.join("folder-link.js")).unwrap();
        symlink(path.join("missing.js"), path.join("broken.js")).unwrap();
        symlink(path.join("loop.js"), path.join("loop.js")).unwrap();
        // a directory named like a source file is not a file
        std::fs::create_dir_all(path.join("dir.js")).unwrap();
        for name in [
            "link-in",
            "link-out",
            "folder-out/secret",
            "folder-in/real",
            "folder-link",
            "broken",
            "loop",
            "dir",
        ] {
            imports.push_str(&format!("import '../{dir}/{name}';\n"));
        }
    }
    symlink(elsewhere.0.join("folder"), app.0.join("linked")).unwrap();
    imports.push_str("import '../linked/secret';\nimport '../lib/real';\n");
    app.write("src/index.js", &imports);

    // `lib/folder-in` leads back into the app, so what is read through it is real
    assert_eq!(
        app.read(),
        [
            "lib/folder-in/real.js",
            "lib/link-in.js",
            "lib/real.js",
            "src/index.js",
            "src/link-in.js",
            "src/real.js",
        ]
    );
}

#[test]
fn an_app_that_imports_too_many_files_outside_src_is_read_up_to_a_cap() {
    let app = TempApp::new("cap");
    let total = crate::imports::MAX_FILES_OUTSIDE_SRC + 5;
    let mut index = String::new();
    for n in 0..total {
        index.push_str(&format!("import '../lib/f{n:05}';\n"));
        app.write(&format!("lib/f{n:05}.js"), "");
    }
    app.write("src/index.js", &index);

    let read = app.read_outside_src();
    assert_eq!(read.len(), crate::imports::MAX_FILES_OUTSIDE_SRC);
    assert_eq!(read.first().unwrap(), "lib/f00000.js");
    assert_eq!(
        read.last().unwrap(),
        &format!("lib/f{:05}.js", crate::imports::MAX_FILES_OUTSIDE_SRC - 1),
        "the files imported first are the ones kept"
    );
}

#[test]
fn project_from_dir_scans_src_and_the_files_it_imports() {
    let app = TempApp::new("from-dir");
    app.write("src/index.js", "import '../lib/helper';");
    app.write("lib/helper.js", "");
    app.write("static/ui.js", "");

    assert_eq!(app.read(), ["lib/helper.js", "src/index.js"]);
}
