#[derive(Clone, Copy, Debug)]
pub struct Size {
    pub nonce: usize,
    pub key: usize,
    pub tag: usize,
}
pub(super) const CHACHA20_POLY1305: Size = Size {
    nonce: 12,
    key: 32,
    tag: 16,
};

pub(super) const XCHACHA20_POLY1305: Size = Size {
    nonce: 24,
    key: 32,
    tag: 16,
};

pub(super) const AES_128_GCM: Size = Size {
    nonce: 12,
    key: 16,
    tag: 16,
};
pub(super) const AES_256_GCM: Size = Size {
    nonce: 12,
    key: 32,
    tag: 16,
};
