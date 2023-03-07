use core::ops::Deref;

/// Additional Authenticated Data (AAD)
///
/// **There are no secrecy or validity guarantees for associated data.**
pub struct Aad<A>(pub A)
where
    A: AsRef<[u8]>;

impl Aad<[u8; 0]> {
    pub fn empty() -> Self {
        Self([0u8; 0])
    }
}
impl<A> Aad<A>
where
    A: AsRef<[u8]>,
{
    pub fn new(aad: A) -> Self {
        Self(aad)
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.as_ref().to_vec()
    }
}
impl<A> From<A> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn from(aad: A) -> Self {
        Self(aad)
    }
}

impl<A> AsRef<[u8]> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
impl<A> Clone for Aad<A>
where
    A: AsRef<[u8]> + Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<A> Deref for Aad<A>
where
    A: AsRef<[u8]>,
{
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<A> Copy for Aad<A> where A: AsRef<[u8]> + Copy {}
