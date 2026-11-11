use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn fsrt(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_fsrt"))
        .args(args)
        .output()
        .unwrap()
}

fn write_app(name: &str, files: &[(&str, &str)]) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&dir);
    for (path, contents) in files {
        let path = dir.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
    dir
}

const MANIFEST: &str = r#"
modules:
  jira:issuePanel:
    - key: panel
      resource: main
      title: Panel
  function:
    - key: resolver
      handler: index.run
resources:
  - key: main
    path: static/ui/build
remotes:
  - key: backend
    baseUrl: https://remote.example.com:8443/api
permissions:
  external:
    fetch:
      backend:
        - "*.egress.example.org"
        # - old.example.net
app:
  id: ari:cloud:ecosystem::app/00000000-0000-0000-0000-000000000000
"#;

#[test]
fn extracts_from_manifest_backend_and_custom_ui_sources() {
    let app = write_app(
        "extract-app",
        &[
            ("manifest.yml", MANIFEST),
            (
                "src/index.ts",
                "export const handler = () => fetch(`https://${region}.api.example.io/v1/${id}`);",
            ),
            ("src/hosts.json", r#"{"fallback": "198.51.100.7:9000"}"#),
            // The resource's build output is missing, so the Custom UI
            // package that produces it is read instead.
            ("static/ui/package.json", r#"{"homepage": "."}"#),
            (
                "static/ui/src/App.jsx",
                r#"export const App = () => <img src="//cdn.example.com/logo.png" />;"#,
            ),
            (
                "static/ui/public/index.html",
                r#"<script src="https://tracker.example.net/t.js"></script>"#,
            ),
            (
                "static/ui/package-lock.json",
                r#"{"resolved": "https://registry.npmjs.org/a.tgz"}"#,
            ),
            (
                "static/ui/node_modules/dep/index.js",
                "fetch('https://dep.example.com')",
            ),
            (
                "tests/fixture.js",
                "fetch('https://unreferenced.example.com')",
            ),
        ],
    );

    let output = fsrt(&["extract", app.to_str().unwrap()]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        [
            "198.51.100.7",
            "198.51.100.7:9000",
            "api.example.io",
            "api.example.io/v1/*",
            "cdn.example.com",
            "cdn.example.com/logo.png",
            "egress.example.org",
            "old.example.net",
            "remote.example.com",
            "remote.example.com:8443/api",
            "tracker.example.net",
            "tracker.example.net/t.js",
            "",
        ]
        .join("\n")
    );
}

#[test]
fn reads_built_custom_ui_resource() {
    let app = write_app(
        "extract-built-resource",
        &[
            (
                "manifest.yml",
                "resources:\n  - key: main\n    path: web\napp:\n  id: x\n",
            ),
            ("web/index.html", "<a href='https://built.example.com/x'>"),
            (
                "web/assets/app.js",
                "fetch('https://bundle.example.com/api')",
            ),
        ],
    );

    let out = app.join("endpoints.txt");
    let output = fsrt(&[
        "extract",
        app.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        fs::read_to_string(out).unwrap(),
        "built.example.com\nbuilt.example.com/x\nbundle.example.com\nbundle.example.com/api\n"
    );
}

#[test]
fn fails_without_manifest() {
    let app = write_app("extract-no-manifest", &[("src/index.js", "")]);

    let output = fsrt(&["extract", app.to_str().unwrap()]);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Could not find manifest.yml"));
}

#[test]
fn extract_is_hidden_from_help() {
    let output = fsrt(&["--help"]);

    assert!(output.status.success());
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("extract")
    );
}
