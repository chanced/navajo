# navajo

Navajo is Rust library that provides secure and easy to use cryptographic APIs.

## Content

-   [Usage overview](#usage-overview)
    -   [Keyring Management / Envelope Encryption](#keying-management--envelope-encryption)
    -   [Authenticated Encryption with Associated Data (AEAD)](#authenticated-encryption-with-associated-data-aead)
    -   [Deterministic Authenticated Encryption with Associated Data (DAEAD)](#deterministic-authenticated-encryption-with-associated-data-daead)
    -   [Signature](#digital-signature)
    -   [Message Authentication Code (MAC)](#message-authentication-code-mac)
-   [Dependencies](#dependencies)
-   [Re-exports](#reexports) [docs]
-   [Modules](#modules) [docs]
-   [Structs](#structs) [docs]
-   [Enums](#enums) [docs]
-   [Traits](#traits) [docs]

## Usage overview

### Keying Management / Envelope Encryption

### Authenticated Encryption with Associated Data (AEAD)

### Deterministic Authenticated Encryption with Associated Data (DAEAD)

### Digital Signature

### Message Authentication Code (MAC)

```rust
use navajo::mac::{Mac, Algorithm};
// create a Mac keyring with a single, generated primary key:
let mac = Mac::new(Algorithm::Sha256, None);
// compute a tag:
let tag = mac.compute(b"an example");
// tags are prepended with a 4 byte key-id for optimization.
// to remove it from output:
let tag = tag.omit_header().unwrap();
// which can fail if you have previously set a truncation length.

// to set a truncation length:
let tag = tag.truncate_to(16).unwrap();
// which is fallible because tags must be at least 10 bytes long
// with the header omitted or 14 bytes with.

// Once you have a Tag, you can validate other tags, in either Tag
// or byte slice with a equal (==) to get constant-time comparison.

// To use the Mac instance to compute and verify:
mac.verify(&tag, b"an example").unwrap();
```

## Dependencies

As a measure of transparency and appreciation, each crate and their usage is
detailed below. A checkmark (✔️) indicates that the crate is optional while (❌)
indicates that it cannot be disabled.

In addition to the table below, two crates are required as under development
dependencies for testing purposes. Those include
[tokio](https://github.com/tokio-rs/tokio) for async tests (streams, futures)
and [hex](https://github.com/KokaKiwi/rust-hex) for quality of life when dealing
with binary.

| Crate                                                              | Usage                                                                                                                                          | Optional |
| ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- | :------: |
| [base64](https://github.com/marshallpierce/rust-base64)            | base64 encoding of keys                                                                                                                        |    ❌    |
| [bytes](https://github.com/tokio-rs/bytes)                         | Optionally provides an `impl` for the `Buffer` trait.                                                                                          |    ✔️    |
| [futures](https://github.com/rust-lang/futures-rs)                 | Futures & streams traits                                                                                                                       |    ❌    |
| [cfg-if](https://github.com/rust-lang/cfg-if)                      | conditional code based on cfg                                                                                                                  |    ❌    |
| [hashbrown](https://github.com/rust-lang/hashbrown)                | Hashmaps for lookup tables                                                                                                                     |    ❌    |
| [jsonptr](https://github.com/chanced/jsonptr)                      | optional public id retrieval from metadata for signature keys                                                                                  |    ❌    |
| [pin-project](https://github.com/taiki-e/pin-project)              | Pinnning futures / streams                                                                                                                     |    ❌    |
| [rand](https://github.com/rust-random/rand)                        | Random number generation                                                                                                                       |    ❌    |
| [rayon](https://github.com/rayon-rs/rayon)                         | possible parallelism of certain operations (e.g. computing tags for numerous keys in a keyring)                                                |    ✔️    |
| [serde](https://github.com/serde-rs/serde)                         | Serialization / Deserialization                                                                                                                |    ❌    |
| [serde_json](https://github.com/serde-rs/json)                     | JSON Serialization / Deserialization for keyrings                                                                                              |    ❌    |
| [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) | Secure zeroization of sensitive keydata.                                                                                                       |    ❌    |
| [ring](https://github.com/briansmith/ring)                         | Crypotgraphic backend for all primitives for a subset of algorithms                                                                            |    ✔️    |
| [typenum](https://github.com/paholg/typenum)                       | Type-level numbers, used for compatability with the Rust Crypto suite                                                                          |    ❌    |
| [generic-array](https://github.com/fizyk20/generic-array)          | Generic arrays, used for compatability with the Rust Crypto suite                                                                              |    ❌    |
| [aes-siv](https://github.com/RustCrypto/AEADs)                     | AES-SIV algorithm for the DAEAD primitive                                                                                                      |    ✔️    |
| [chachapoly1305](https://github.com/RustCrypto/AEADs)              | ChaCha20Poly1305 when _ring_ is not available and XChaCha20Poly1305 for the AEAD primitive. Not optional due to being used to encrypt keyrings |    ❌    |
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
