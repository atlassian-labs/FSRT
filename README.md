# FSRT - Forge Security Requirements Tester

[![Apache license](https://img.shields.io/badge/license-Apache%202.0-blue.svg?style=flat-square)](LICENSE-APACHE) [![MIT license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE-MIT) [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)

A static analysis tool for finding common [Forge][1] vulnerabilities.

[1]: https://developer.atlassian.com/platform/forge "Forge platform"

## Usage

```text
Usage: fsrt [OPTIONS] [DIRS]...

Arguments:
  [DIRS]...  The directory to scan. Assumes there is a `manifest.ya?ml` file in the top level directory, and that the source code is located in `src/`

  Options:
    -d, --debug
        --dump-ir <DUMP_IR> Dump the IR for the specified function.
    -f, --function <FUNCTION>  A specific function to scan. Must be an entrypoint specified in `manifest.yml`
    -h, --help                 Print help information
    -V, --version              Print version information
```

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
cargo install --path crates/fsrt
```

or alternatively:

```text
cargo install --git https://github.com/atlassian-labs/FSRT
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

## Contributions

Contributions to FSRT are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

Copyright (c) 2022 Atlassian and others.

FSRT is dual licensed under the MIT and Apache 2.0 licenses.

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT) for details.

[![With â¤ï¸ from Atlassian](https://raw.githubusercontent.com/atlassian-internal/oss-assets/master/banner-cheers.png)](https://www.atlassian.com)
