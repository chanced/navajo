use kms_aead::*;

pub struct GcpKms {
    key: KmsAeadRingEnvelopeEncryption<kms_aead::providers::GcpKmsProvider>,
}
