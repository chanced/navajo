# navajo

Navajo is Rust library that provides secure and easy to use cryptographic APIs.

The project is still in active, pre-release development. The short-term plans
are to provide adequate coverage for AEAD, DAEAD, MAC, HKDF, Signatures, and
HPKE with integrations for AWS, Azure, GCP, and Hashicrop Vault.

The first alpha release will lack HPKE. Fuzzing will be setup as soon as the API
is complete, hopefully before the end of Q1 2024.

The long-term plan is to extend to other languages via WASI after fuzzing is finished.

## Security Note

This crate has **not** undergone any sort of audit.

Please review the code and use at your own risk.

## Credit

Navajo is inspired by and modeled after Google's [tink
project](https://github.com/google/tink). The two projects are not wire
compatible.

## License

MIT OR Apache 2.0 at your leisure
