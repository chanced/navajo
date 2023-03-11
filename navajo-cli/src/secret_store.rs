use std::{error::Error, pin::Pin};

use navajo::{secret_store::SecretStore as _, sensitive};

pub enum SecretStore {
    Gcp(navajo_gcp::SecretManager),
}
impl SecretStore {
    pub async fn get<N: ToString>(&self, name: &str) -> Result<sensitive::Bytes, Box<dyn Error>> {
        match self {
            SecretStore::Gcp(gcp) => gcp.get(name).await.map_err(|err| err.into()),
        }
    }
}
