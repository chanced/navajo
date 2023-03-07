# Deterministic Authenticated Encryption with Associated Data DAEAD

Deterministic AEAD provides both confidentiality and integrity protection for
messages, along with the ability to authenticate associated data. Encrypting
the same plaintext with a given key will always result in the same ciphertext.

This determnistic nature is useful in key wraps and in situations where indexing
and querying encrypted data is desired. On the other hand, it means that an
attacker will be able to recognize when the same message is repeated or the
encrypted data is utilized elsewhere.
