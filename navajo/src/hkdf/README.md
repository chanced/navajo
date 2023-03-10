# HMAC-based Extract-and-Expand Key Derivation Function - [HKDF](https://www.rfc-editor.org/rfc/rfc5869)

## Usage

```rust
use navajo::hkdf::{Salt, Algorithm};
use navajo::rand;
use hex::{encode, decode};

// generate a salt
let salt = Salt::generate(Algorithm::Sha256);

// secret key material
let ikm = decode("c78bc83f190589c1f28772f9bb11b5773c2274de342933e9aa8521a5e09c7829")
	.unwrap();
// extract
let prk = salt.extract(&ikm);

// expand into output key material
let mut okm = [0u8; 32];

let aad = b"associated info".to_vec();

prk.expand(&[&aad[..]], &mut okm).unwrap();

println!("{}", encode(okm));
```

## Algorithm Support

Navajo currently provides HDKF in Sha2 & Sha3 with either
[ring](https://docs.rs/ring/0.16.20/ring/index.html) or [Rust
Crypto](https://docs.rs/hkdf/0.12.3/hkdf/) backend.

| Hashing Algorithm | Crates                                                                                                                 | Feature  | Enabled by default |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------- | -------- | :----------------: |
| **Sha256**        | [_ring_](https://crates.io/crates/hma) OR [hmac](https://crates.io/crates/hmac), [sha2](https://crates.io/crates/sha2) |          |         ✔️         |
| **Sha384**        | [_ring_](https://crates.io/crates/hma) OR [hmac](https://crates.io/crates/hmac), [sha2](https://crates.io/crates/sha2) |          |         ✔️         |
| **Sha512**        | [_ring_](https://crates.io/crates/hma) OR [hmac](https://crates.io/crates/hmac), [sha2](https://crates.io/crates/sha2) |          |         ✔️         |
| **Sha3 256**      | [hmac](https://crates.io/crates/hmac), [sha3](https://crates.io/crates/sha3)                                           | `"sha3"` |         ️          |
| **Sha3 224**      | [hmac](https://crates.io/crates/hmac), [sha3](https://crates.io/crates/sha3)                                           | `"sha3"` |         ️          |
| **Sha3 384**      | [hmac](https://crates.io/crates/hmac), [sha3](https://crates.io/crates/sha3)                                           | `"sha3"` |         ️          |
| **Sha3 512**      | [hmac](https://crates.io/crates/hmac), [sha3](https://crates.io/crates/sha3)                                           | `"sha3"` |         ️          |
