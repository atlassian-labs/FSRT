# FSRT - Forge Security Requirements Tester

[![Apache license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE) [![MIT license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE-MIT) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

A static analysis tool for finding common [Forge][1] vulnerabilities.

[1]: https://developer.atlassian.com/platform/forge "Forge platform"

## Usage

```text
Usage: fsrt [OPTIONS] [DIRS]...

Arguments:
  [DIRS]...  The directory to scan. Assumes there is a `manifest.yaml` file in the top level directory, and that the source code is located in `src/`

  Options:
    -d, --debug
        --dump-ir <DUMP_IR>                 Dump the IR for the specified function
    -dt, --dump-dt <DUMP_DOM_TREE>          Dump the Dominator Tree for the specified app
    -f, --function <FUNCTION>               A specific function to scan, must be an entrypoint specified in `manifest.yml`
    -h, --help                              Print help information
    -V, --version                           Print version information
    --check-permissions                     Runs the permission checker
    --cached-permissions                    Uses cached swagger permissions to avoid redownloading them
    --cached-permissions-path <LOCATION>    Uses the designated cache location, otherwise selects ~/.cache dir 
    --graphql-schema-path <LOCATION>        Uses the graphql schema in location; othwerwise selects ~/.config dir  
```

## Minting Forge tokens

In addition to static scanning, FSRT can mint Forge tokens against a live
Atlassian site — useful for dynamic testing of a Forge app's backend.

- **`mint-fct`** — mint a **Forge Context Token (FCT)**.
- **`mint-fit`** — mint a **Forge Invocation Token (FIT)**. Internally mints an
  FCT first, then exchanges it for a FIT.

Both commands read a shared TOML config (default: `./fsrt-remote.toml`) and the
target app's `manifest.yml`. See [`fsrt-remote.toml`](fsrt-remote.toml) for a
fully commented example — copy it and replace the placeholder values with your
own. It selects the product (`confluence` or `global`), the GraphQL endpoint,
and how to authenticate (a raw session cookie or a Basic API token).

> **Warning:** these commands send and print auth material (cookies/tokens).
> Never commit real cookies, API tokens, tenant IDs, or account emails.

```sh
# Mint a Forge Context Token for the app in the current directory.
fsrt mint-fct --app-dir . --config ./fsrt-remote.toml

# Preview the exact GraphQL request without sending it.
fsrt mint-fct --config ./fsrt-remote.toml --dry-run

# Mint a Forge Invocation Token (mints an FCT under the hood first).
fsrt mint-fit --app-dir . --config ./fsrt-remote.toml
```

Both `--app-dir` (default `.`) and `--config` (default `./fsrt-remote.toml`)
are optional. Use `--dry-run` to render and inspect the request without calling
the GraphQL gateway.

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
