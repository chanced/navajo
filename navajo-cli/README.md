# navajo-cli

navajo-cli is [`navajo`](github.com/chanced/navajo)'s command line utility for
managing keys and CLI for a subset of cryptographic operations, such as
encryption/decryption. The `navajo` supports envelope encyrption/decryption for
keyrings stored in a KMS. Currently this is limited to GCP but AWS, Azure, and
Hashicorp's Vault are planned.

## Install

```bash
cargo install navajo-cli
```

## Usage

```bash
navajo <COMMAND>
```

## Commands

| Command            | Description                                                                                                                                              |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `new`              | Creates a new keyring, initialized with a single key of the specified algorithm.                                                                         |
| `inspect`          | Displays information about keys within the keyring                                                                                                       |
| `add-key`          | Adds a new key to a keyring.                                                                                                                             |
| `promote-key`      | Promotes a key to primary in a keyring                                                                                                                   |
| `disable-key`      | Disables the key with the supplied id from a keyring. Disabling a key effectively removes the key from the keyring, but leaves it in a recoverable state |
| `delete-key`       | Deletes the key with the supplied id from a keyring. The key can not be recovered.                                                                       |
| `set-key-metadata` | Sets metadata of a key in a keyring                                                                                                                      |
| `migrate`          | Migrates a keyring to a new envelope, changes the envelope's AAD, or both.                                                                               |
| `create-public`    | Creates a public JWKS for an asymetric keyring                                                                                                           |
| `help`             | Prints the help the `navajo` command or the given subcommand(s)                                                                                          |
