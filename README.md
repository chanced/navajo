# navajo

navajo is a library that provides cryptographic and key management APIs built
upon the outstanding crates [_ring_](https://github.com/briansmith/ring),
[RustCrypto](https://github.com/RustCrypto), and
[jsonwebtoken](https://github.com/Keats/jsonwebtoken).

## Credit

navajo is inspired and based loosely on the amazing work of Google's [tink
project](https://github.com/google/tink).

## ⚠️ This crate is not ready for use

It has been published to cargo for name reservation.

## TODO

### navajo

-   Primitives
    -   [ ] _AEAD_ AES-128-GCM ([#1](https://github.com/chanced/navajo/issues/1), [#2](https://github.com/chanced/navajo/issues/2))
    -   [ ] _AEAD_ AES-256-GCM ([#1](https://github.com/chanced/navajo/issues/1), [#2](https://github.com/chanced/navajo/issues/2))
    -   [ ] _AEAD_ ChaCha20-Poly1305 ([#1](https://github.com/chanced/navajo/issues/1), [#2](https://github.com/chanced/navajo/issues/2))
    -   [ ] _DAEAD_ AES-SIV ([#3](https://github.com/chanced/navajo/issues/3))
    -   [ ] _Signature_ ECDSA-P256 ([#4](https://github.com/chanced/navajo/issues/4))
    -   [ ] _Signature_ ECDSA-P384 ([#5](https://github.com/chanced/navajo/issues/5))
    -   [ ] _Signature_ ECDSA-P521 ([#6](https://github.com/chanced/navajo/issues/6))
    -   [ ] _Signature_ Ed25519 ([#8](https://github.com/chanced/navajo/issues/8))
    -   [ ] _Signature_ RSA-SSA-PKCS1 ([#9](https://github.com/chanced/navajo/issues/9))
    -   [ ] _Hybrid_ ECIS+AEAD+HKDF ([#7](https://github.com/chanced/navajo/issues/7))
    -   [ ] _Agreement_ ECDH-P256 ([#10](https://github.com/chanced/navajo/issues/10))
    -   [ ] _Agreement_ ECDH-P384 ([#11](https://github.com/chanced/navajo/issues/11))
    -   [ ] _Agreement_ X25519 ([#20](https://github.com/chanced/navajo/issues/20))
    -   [ ] _MAC_ HMAC-2 ([#12](https://github.com/chanced/navajo/issues/12))
    -   [ ] _MAC_ AES-CMAC ([#13](https://github.com/chanced/navajo/issues/13))
-   [ ] Make _ring_ optional ([17](https://github.com/chanced/navajo/issues/17))
-   [ ] `nostd` support ([#18](https://github.com/chanced/navajo/issues/18))
-   [ ] WASM ([#19](https://github.com/chanced/navajo/issues/19), [#21](https://github.com/chanced/navajo/issues/21), [#22](https://github.com/chanced/navajo/issues/13))

### navajo-cli

-   [ ] GCP Integeration ([#14](https://github.com/chanced/navajo/issues/14))
-   [ ] AWS Integeration ([#15](https://github.com/chanced/navajo/issues/15))
-   [ ] Vault Integeration ([#16](https://github.com/chanced/navajo/issues/16))

## License

MIT OR Apache 2.0 at your leisure
