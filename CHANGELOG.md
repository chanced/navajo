# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] 2023-04-23

### Added

-   `KeyInfo` for Daead
-   `navajo::KeyringInfo` and corresponding methods on each primitive to return their respective `KeyringInfo` (#53)
-   Adds base64, base64url, and hex encoding and decoding to CLI input and output (#55)

### Changed

-   Added
-   Removed CLI alias `"e"` for enable-key and `"d"` for disable-key
-   Renames DSA keyring `"key_pair"` to `"value"` (#52)
-   Removes async from `navajo-cli`, making it sync for easier testing & resolving (#46)
-   Each primitive's `KeyInfo` were renmaed from {Primitive}KeyInfo to `KeyInfo` (#53)
-   Rename `Status::Secondary` to `Status::Active`

## Removed

-   `navajo::KeyInfo<T>` was removed, deferring to primitive `KeyInfo`

## [0.0.2] - 2023-04-13

### Added

-   Adds missing seal/unseal to `Aead`, `Daead`, `Signer` (#47)

### Fixed

-   Fixes issue where `aead::DecryptReader` would error if input `Read` length was less than `Segment` size (#39)

## [0.0.1] - 2023-04-12

### Added

-   CLI for `navajo` available in the crate `navajo-cli`
-   Initial draft of AEAD with algorithms `ChaCha20Poly1305`, `XChaCha20Poly1305`, `AES-128-GCM`, `AES-256-GCM`
-   Initial draft of DAEAD with algorithms `AES-256-SIV`
-   Initial draft of MAC with algorithms `BLAKE3`, `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`, `SHA3-224`, `SHA3-384`, `SHA3-512`, `AES-192`,`AES-256`
-   Initial draft of HKDF with algorithms `SHA-256`, `SHA-384`, `SHA-512`, `SHA3-256`, `SHA3-224`, `SHA3-384`, `SHA3-512`
-   Initial draft of DSA (digitial signatures) with algorithms `Ed25519`, `ES-256` (`ECDSA` using `P-256` with `SHA-256`), `ES-384` (`ECDSA` using `P-384` and `Sha-384`)
-   GCP integration, available with the crate `navajo-gcp`
