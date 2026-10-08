# Windows Native Keyring Store

[![build](https://github.com/open-source-cooperative/windows-native-keyring-store/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/windows-native-keyring-store/actions) [![crates.io](https://img.shields.io/crates/v/windows-native-keyring-store.svg?style=flat-square)](https://crates.io/crates/windows-native-keyring-store) [![docs.rs](https://docs.rs/windows-native-keyring-store/badge.svg)](https://docs.rs/windows-native-keyring-store)

This library provides a credential store for use with the [keyring ecosystem](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring) that uses the Windows native credential store.

## Usage

To use this keychain-compatible credential store provider, you must take a dependency on the [keyring-core crate](https://crates.io/crates/keyring-core) and on [this crate](https://crates.io/crates/windows-native-keyring-store). Then you can instantiate a credential store and set it as your default credential store as shown in the [sample program](examples/example.rs) in this crate.

## Features

This crate has one feature, `search`, that is enabled by default. This feature requires the `regex` crate, which has a large footprint (typically over 1MB). If you care about library size and don't need to do credential searches, you can disable default features to shed the `regex` dependency. 

## Warning

Windows Credential Manager loses updates when credentials, even different ones, are written and deleted concurrently. A read can miss a credential just written, and a deleted credential can survive. This crate serializes its calls per user across threads and processes, which does not cover software calling Credential Manager directly. See [issue #20](https://github.com/open-source-cooperative/windows-native-keyring-store/issues/20).

## License

Licensed under either of the following at your discretion:

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.
