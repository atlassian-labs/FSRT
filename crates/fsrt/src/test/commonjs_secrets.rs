use super::*;

#[test]
fn commonjs_secret_packages_preserve_native_require_identity() {
    for (setup, parameter, body, expected) in [
        ("const jwt = require('jsonwebtoken');", "", "", 1),
        (
            "const other = require('unrelated'); const jwt = require('jsonwebtoken');",
            "",
            "",
            1,
        ),
        ("require++; const jwt = require('jsonwebtoken');", "", "", 0),
        (
            "[require] = loaders; const jwt = require('jsonwebtoken');",
            "",
            "",
            0,
        ),
        (
            "function custom(require) { require = customLoader; } const jwt = require('jsonwebtoken');",
            "",
            "",
            1,
        ),
        ("import jwt from 'jsonwebtoken';", "", "", 1),
        ("", "", "const jwt = require('jsonwebtoken');", 1),
        (
            "function require(name) { return {}; } const jwt = require('jsonwebtoken');",
            "",
            "",
            0,
        ),
        (
            "let require; const jwt = require('jsonwebtoken');",
            "",
            "",
            0,
        ),
        (
            "import require from 'custom-loader'; const jwt = require('jsonwebtoken');",
            "",
            "",
            0,
        ),
        ("", "require", "const jwt = require('jsonwebtoken');", 0),
        (
            "require = customLoader; const jwt = require('jsonwebtoken');",
            "",
            "",
            0,
        ),
        (
            "",
            "",
            "require = customLoader; const jwt = require('jsonwebtoken');",
            0,
        ),
        (
            "({ loader: require } = loaders); const jwt = require('jsonwebtoken');",
            "",
            "",
            0,
        ),
        (
            "function replaceLoader() { require = customLoader; } const jwt = require('jsonwebtoken');",
            "",
            "",
            0,
        ),
    ] {
        let source = format!(
            "{setup}
export function run({parameter}) {{
            {body}
            return jwt.sign({{ foo: 'bar' }}, 'hardcoded-signing-key');
        }}"
        );
        let mut project = MockForgeProject::files_from_string("// src/index.js\n");
        project.add_file("src/index.js", source.clone());
        let report = scan_directory_test_with_args(
            project,
            Args::parse_from(["fsrt", "--scanners", "secret"]),
        );
        assert!(
            report.contains_secret_vuln(expected),
            "{source}: {report:#?}"
        );
    }
}
