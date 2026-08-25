# FSRT - Forge Security Requirements Tester

[![Apache license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE) [![MIT license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE-MIT) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

A static analysis tool for finding common [Forge][1] vulnerabilities.

[1]: https://developer.atlassian.com/platform/forge "Forge platform"

## Usage

```text
Usage: fsrt [OPTIONS] [DIRS]...
       fsrt [OPTIONS] <COMMAND>

Arguments:
  [DIRS]...  The directory to scan. Assumes there is a `manifest.yaml` file in the top level directory, and that the source code is located in `src/`

Commands:
  invoke-extension  Invoke a resolver-backed extension with a tester-controlled payload
  mint-fct          Mint an FCT for a deployed module
  mint-fit          Mint an FIT for a deployed module and Forge remote

  Options:
    -d, --debug
        --dump-ir <DUMP_IR>                 Dump the IR for the specified function
    -dt, --dump-dt <DUMP_DOM_TREE>          Dump the Dominator Tree for the specified app
    -f, --function <FUNCTION>               A specific function to scan, must be an entrypoint specified in `manifest.yml`
    -h, --help                              Print help information
    -V, --version                           Print version information
    --verbose                               Print diagnostics to stderr
    --check-permissions                     Runs the permission checker
    --cached-permissions                    Uses cached swagger permissions to avoid redownloading them
    --cached-permissions-path <LOCATION>    Uses the designated cache location, otherwise selects ~/.cache dir
    --graphql-schema-path <LOCATION>        Uses the graphql schema in location; othwerwise selects ~/.config dir
```

Run `fsrt --help` or `fsrt <COMMAND> --help` for current options.

## Installation

You will need to install [Rust] to compile `FSRT`. You can install `Rust` through [Rustup] or through your distro's package manager. You will also
need [Cargo], which comes by default with most `Rust toolchains`.[^1]
latest stable release, and adding the toolchain

[^1]: Cargo is technically not required if you want to download every dependency, invoke `rustc`, and link everything manually. However, I wouldn't recommend doing this unless you're extremely bored.

[Rust]: https://www.rust-lang.org/
[Rustup]: https://github.com/rust-lang/rustup "Rustup"
[Cargo]: https://github.com/rust-lang/cargo

Installing from source:

```sh
git clone https://github.com/atlassian-labs/FSRT.git
cd FSRT
cargo install --path crates/fsrt --locked
```

or alternatively:

```text
cargo install --git https://github.com/atlassian-labs/FSRT --locked
```

## Commands

```text
fsrt mint-fct <MODULE_KEY> [OPTIONS]
fsrt mint-fit <REMOTE_KEY> [--module <MODULE_KEY>] [OPTIONS]
fsrt invoke-extension <MODULE_KEY> <FUNCTION> <PAYLOAD> [OPTIONS]
```

All three commands use `--app-dir` and a TOML configuration file; see
[`fsrt-remote.toml.example`](fsrt-remote.toml.example). Keep that configuration and its
cookie file untracked.

`mint-fct` mints an FCT for a deployed module. Pass `--ctx '<JSON>'` to populate the
selected extension's `context` object.

`mint-fit` supports two mutually exclusive ways to provide its FCT:

| Mode | Required inputs | Behavior |
| --- | --- | --- |
| Use an existing FCT | `<REMOTE_KEY> --fct <FCT>` | Uses the supplied FCT when `--module` and `--ctx` are omitted. |
| Mint a new FCT | `<REMOTE_KEY> --module <MODULE_KEY>` | Mints an FCT with an empty context, then uses it to mint the FIT. Add `--ctx '<JSON>'` to set its context. |

`invoke-extension` invokes a resolver with tester-controlled JSON. Its positional arguments
select the deployed module, resolver function, and invocation payload. By default it derives
the invocation context from deployment metadata and mints an FCT in memory. Use
`--ctx '<JSON>'` to replace that context or `--fct <JWT>` to reuse a captured token.
`--async` requests an asynchronous invocation when supported.

By default, live mint commands print only the token, while `invoke-extension` prints the
backend response. `--dry-run` queries metadata without signing tokens or invoking the
extension and prints redacted request variables. `--verbose` prints live diagnostics to
stderr. Run `fsrt <COMMAND> --help` for all options.

## Tests

To run the test suite:

```sh
cargo test
```

There are also two sample vulnerable Forge apps for testing. In the future these will be added to the test-suite, but
until then you can test `fsrt` by manually invoking:

```sh
fsrt ./test-apps/jira-damn-vulnerable-forge-app
```

Testing with a GraphQl Schema:

```sh
cargo test --features graphql_schema
```

## Contributions

Contributions to FSRT are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Copyright (c) 2022 Atlassian and others.

FSRT is dual licensed under the MIT and Apache 2.0 licenses.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[![With â¤ï¸ from Atlassian](https://raw.githubusercontent.com/atlassian-internal/oss-assets/master/banner-cheers.png)](https://www.atlassian.com)
