pub trait Keyset {
    type Key: Key + Send + Sync + Sized;
    fn primary_key(&self) -> Option<Self::Key>;
    fn add_key(&self) -> Result<(), String>;
}

pub trait Key {
    type PublicKey: AsRef<[u8]> + Send + Sync + Sized;
    fn public_key(&self) -> Self::PublicKey;
    fn key_id(&self) -> Option<&str>;
}
