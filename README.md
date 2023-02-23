# Navajo

Navajo is a library for Rust that provides secure and easy to use cryptographic APIs.

Future

## Dependencies

### navajo

| Crate                                                                                                         | Usage                                                                                           | Optional |
| ------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | :------: |
| [base64](https://crates.io/crates/base64) [[repo]](https://github.com/marshallpierce/rust-base64)             | base64 encoding of keys                                                                         |    ❌    |
| [futures](https://crates.io/crates/futures) [[repo]](https://github.com/rust-lang/futures-rs)                 | Futures & streams traits                                                                        |    ❌    |
| [cfg-if](https://crates.io/crates/cfg-if) [[repo]](https://github.com/rust-lang/cfg-if)                       | conditional code based on cfg                                                                   |    ❌    |
| [hashbrown](https://crates.io/crates/hashbrown) [[repo]](https://github.com/rust-lang/hashbrown)              | Hashmaps for lookup tables                                                                      |    ❌    |
| [jsonptr](https://crates.io/crates/jsonptr) [[repo]](https://github.com/chanced/jsonptr)                      | optional public id retrieval from metadata for signature keys                                   |    ❌    |
| [pin-project](https://crates.io/crates/pin-project) [[repo]](https://github.com/taiki-e/pin-project)          | Pinnning futures / streams                                                                      |    ❌    |
| [rand](https://crates.io/crates/rand) [[repo]](https://github.com/rust-random/rand)                           | Random number generation                                                                        |    ❌    |
| [rayon](https://crates.io/crates/rayon) [[repo]](https://github.com/rayon-rs/rayon)                           | possible parallelism of certain operations (e.g. computing tags for numerous keys in a keyring) |    ✔️    |
| [serde](https://crates.io/crates/serde) [[repo]](https://github.com/serde-rs/serde)                           | Serialization / Deserialization                                                                 |    ❌    |
| [serde_json](https://crates.io/crates/serde_json) [[repo]](https://github.com/serde-rs/json)                  | JSON Serialization / Deserialization for keyrings                                               |    ❌    |
| [zeroize](https://crates.io/crates/zeroize) [[repo]](https://github.com/RustCrypto/utils/tree/master/zeroize) | Secure zeroization of sensitive keydata.                                                        |    ❌    |
| [ring](https://crates.io/crates/ring) [[repo]](https://github.com/briansmith/ring)                            | Crypotgraphic backend for all primitives for a subset of algorithms                             |    ✔️    |

## Credit

Navajo is inspired by and modeled after Google's [tink
project](https://github.com/google/tink). The two projects are not wire
compatible.

## License

MIT OR Apache 2.0 at your leisure
