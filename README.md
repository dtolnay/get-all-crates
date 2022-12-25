get-all-crates
==============

[<img alt="github" src="https://img.shields.io/badge/github-dtolnay/get--all--crates-8da0cb?style=for-the-badge&labelColor=555555&logo=github" height="20">](https://github.com/dtolnay/get-all-crates)
[<img alt="crates.io" src="https://img.shields.io/crates/v/get-all-crates.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/get-all-crates)
[<img alt="build status" src="https://img.shields.io/github/actions/workflow/status/dtolnay/get-all-crates/ci.yml?branch=master&style=for-the-badge" height="20">](https://github.com/dtolnay/get-all-crates/actions?query=branch%3Amaster)

Download _.crate_ files of all versions of all crates from crates.io.

Useful for things like [noisy-clippy](https://github.com/dtolnay/noisy-clippy)
which need to analyze the source code of all crates.

I wrote this tool to saturate a 1000 Mbps connection. From scratch, it can
finish downloading in under 20 minutes. It can also check the checksums of a
directory of downloaded crates in 40 seconds on 64 cores. For a more fully
featured tool, which some of this code is based on, but which is much slower in
my experience, check out <https://git.shipyard.rs/jstrong/registry-backup>.

<br>

## Usage

```console
$ cargo install get-all-crates
$ git clone https://github.com/rust-lang/crates.io-index /path/to/index
$ get-all-crates --index /path/to/index --out /path/to/crates
```

Warning: as of 2022 this writes out more than 100 GB of crates.

The output directory structure is similar to how Cargo's registry index is
structured:

<pre>
/path/to/crates
 ├── <b>1</b>
 │  └── <b>m</b>
 │     └── <i>m-0.1.1.crate</i>
 ├── <b>2</b>
 │  └── <b>nu</b>
 │     └── <i>nu-0.73.0.crate</i>
 ├── <b>3</b>
 │  └── <b>s</b>
 │     └── <b>syn</b>
 │        └── <i>syn-1.0.107.crate</i>
 └── <b>se</b>
    └── <b>rd</b>
       ├── <b>serde</b>
       │  └── <i>serde-1.0.151.crate</i>
       └── <b>serde_json</b>
          └── <i>serde_json-1.0.91.crate</i>
</pre>

<br>

## License

<a href="LICENSE-MIT">MIT license</a>.
