# Repository Guidelines

## Project Structure & Module Organization

FSRT (Forge Security Requirements Tester) is a Rust 2024 workspace for analyzing Atlassian Forge applications.

- `crates/fsrt/`: CLI, scan orchestration, and DAST command handlers.
- `crates/forge_analyzer/`: intermediate representation, analysis, checkers, and reporting.
- `crates/forge_loader/`, `forge_file_resolver/`, and `forge_permission_resolver/`: manifest loading, file resolution, and permission lookup.
- `crates/forge_pen_test/`: DAST support; `crates/forge_utils/`: shared utilities.
- `test-apps/`: JavaScript/TypeScript Forge fixtures for manual scans and reproductions.
- Root YAML, JSON, and endpoint files supply scanner rules and reference data.

## Build, Test, and Development Commands

Run commands from the repository root with a Rust toolchain supporting edition 2024:

- `cargo build --workspace`: build all workspace crates.
- `cargo run -p fsrt -- --help`: inspect CLI options.
- `cargo run -p fsrt -- --dump-ir=<function>`: inspect the IR of a function. Use `name` for `resolver.define("name", async () =>)`, This arbitrarily picks the first one in the event of colliding names.
- `cargo run -p fsrt -- ./test-apps/jira-damn-vulnerable-forge-app`: scan a sample app.
- `cargo nextest run --workspace`: run the suite used by CI.
- `cargo fmt --all -- --check`: check formatting; use `cargo fmt --all` to apply it.
- `cargo clippy --workspace`: run CI's lint checks.

## Coding Style & Naming Conventions

Follow existing Rust style and rustfmt output, using four-space indentation. Use `snake_case` for modules, functions, and variables; `PascalCase` for types; and `SCREAMING_SNAKE_CASE` for constants. Keep CLI handling in `fsrt` and reusable analysis logic in the supporting crates. Shared dependencies and lint settings live in the root `Cargo.toml`.

## Testing Guidelines

Use Rust's built-in `#[test]` framework. Unit tests live in inline test modules or `src/test.rs`; CLI integration tests live in `crates/fsrt/tests/`. Name tests after the behavior they verify, such as `parses_arguments_from_file_with_default_prefix`. Add regression tests for fixes and tests for new features. No numeric coverage threshold is configured. Run focused tests with `cargo test -p fsrt <test_name>`, then the workspace suite.

## Commit & Pull Request Guidelines

Recent history uses prefixes such as `feat(fsrt):`, `fix:`, `docs(fsrt):`, and `refactor(mint):`; follow that pattern with concise, imperative summaries. Keep unrelated changes in separate PRs. Describe the problem, resulting behavior, and validation; link relevant issues. Discuss larger changes in an issue first. Follow `CONTRIBUTING.md`, including the Atlassian CLA requirement.

## Configuration & Credentials

Use `fsrt-remote.toml.example` as the DAST configuration reference. Keep real tokens, passwords, and generated session-cookie files untracked and out of logs. Browser cookie harvesting requires the opt-in `mint_cookie` feature.
