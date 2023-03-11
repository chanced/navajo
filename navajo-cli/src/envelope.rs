use url::Url;

pub enum Envelope {
    Cleartext(navajo::CleartextJson),
    Gcp(navajo_gcp::Kms),
}
impl Envelope {
    pub async fn open(uri: Option<String>, data: tokio::io::AsyncRead)
}