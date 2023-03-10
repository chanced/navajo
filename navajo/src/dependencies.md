# navajo dependencies

As a measure of transparency and appreciation, each crate and their usage is
detailed below. A checkmark (✔️) indicates that the crate is optional while (❌)
indicates that it cannot be disabled.

| Crate                                                              | Usage                                                                                                                                          | Optional |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | :------: |
| [base64](https://github.com/marshallpierce/rust-base64)            | base64 encoding of keys                                                                                                                        |    ❌    |
| [bytes](https://github.com/tokio-rs/bytes)                         | Optionally provides an `impl` for the `Buffer` trait.                                                                                          |    ✔️    |
| [futures](https://github.com/rust-lang/futures-rs)                 | Futures & streams traits                                                                                                                       |    ❌    |
| [cfg-if](https://github.com/rust-lang/cfg-if)                      | conditional code based on cfg                                                                                                                  |    ❌    |
| [hashbrown](https://github.com/rust-lang/hashbrown)                | Hashmaps for lookup tables                                                                                                                     |    ❌    |
| [pin-project](https://github.com/taiki-e/pin-project)              | Pinnning futures / streams                                                                                                                     |    ❌    |
| [rand](https://github.com/rust-random/rand)                        | Random number generation                                                                                                                       |    ❌    |
| [rayon](https://github.com/rayon-rs/rayon)                         | possible parallelism of certain operations (e.g. computing tags for numerous keys in a keyring)                                                |    ✔️    |
| [serde](https://github.com/serde-rs/serde)                         | Serialization / Deserialization                                                                                                                |    ❌    |
| [serde_json](https://github.com/serde-rs/json)                     | JSON Serialization / Deserialization for keyrings                                                                                              |    ❌    |
| [quote](https://github.com/dtolnay/quote)                          | Type name concatenation in `macro_use!` blocks.                                                                                                |    ❌    |
| [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) | Secure zeroization of sensitive keydata.                                                                                                       |    ❌    |
| [ring](https://github.com/briansmith/ring)                         | Crypotgraphic backend for all primitives for a subset of algorithms                                                                            |    ✔️    |
| [typenum](https://github.com/paholg/typenum)                       | Type-level numbers, used for compatability with the Rust Crypto suite                                                                          |    ❌    |
| [generic-array](https://github.com/fizyk20/generic-array)          | Generic arrays, used for compatability with the Rust Crypto suite                                                                              |    ❌    |
| [aes-siv](https://github.com/RustCrypto/AEADs)                     | AES-SIV algorithm for the DAEAD primitive                                                                                                      |    ✔️    |
| [chachapoly1305](https://github.com/RustCrypto/AEADs)              | ChaCha20Poly1305 when _ring_ is not available and XChaCha20Poly1305 for the AEAD primitive. Not optional due to being used to encrypt keyrings |    ❌    |
| [aes](https://github.com/RustCrypto/block-ciphers)                 | AES block cipher for CMAC-AES primitive                                                                                                        |    ✔️    |
| [aes-gcm](https://github.com/RustCrypto/AEADs)                     | AES-GCM algorithms for the AEAD primitive. Not optional due to being used to encrypt keyrings                                                  |    ❌    |
| [hmac](https://github.com/RustCrypto/MACs)                         | HMAC support for the Rust Crypto suite                                                                                                         |    ✔️    |
| [cmac](https://github.com/RustCrypto/MACs)                         | CMAC support for the Rust Crypto suite                                                                                                         |    ✔️    |
| [sha2](https://github.com/RustCrypto/hashes)                       | SHA2 family of algorithms for HMAC, HKDF                                                                                                       |    ✔️    |
| [sha3](https://github.com/RustCrypto/hashes)                       | SHA3 family of algorithms for HMAC, HKDF                                                                                                       |    ✔️    |
| [blake3](https://github.com/BLAKE3-team/BLAKE3)                    | BLAKE3 hashing algorithm for HMAC                                                                                                              |    ✔️    |
| [pkcs8](https://github.com/RustCrypto/formats/tree/master/pkcs8)   | Public-Key Crypography Standards #8 for signature keys                                                                                         |    ❌    |
| [subtle](https://github.com/dalek-cryptography/subtle)             | Constant time equals when _ring_ is not available                                                                                              |    ❌    |
| [digest](https://github.com/RustCrypto/traits)                     | Traits for hash functions, used for Rust Crypto suite                                                                                          |    ❌    |
| [hkdf](https://github.com/RustCrypto/KDFs/)                        | Hash Key Derivation Functions from the Rust Crypto suite. Used when _ring_ is not available                                                    |    ❌    |
| [hkdf](https://github.com/RustCrypto/KDFs/)                        | Hash Key Derivation Functions from the Rust Crypto suite. Used when _ring_ is not available                                                    |    ❌    |

In addition to the table above, two crates are required as under development
dependencies for testing purposes. Those include
[tokio](https://github.com/tokio-rs/tokio) for async tests (streams, futures)
and [hex](https://github.com/KokaKiwi/rust-hex) for quality of life when dealing
with binary.
