use crate::boltz::Error;

#[derive(uniffi::Object)]
pub struct Preimage(pub(crate) boltz_client::util::secrets::Preimage);

#[uniffi::export]
impl Preimage {
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self(boltz_client::util::secrets::Preimage::new())
    }

    #[uniffi::constructor]
    pub fn from_bytes(vec: Vec<u8>) -> Result<Self, Error> {
        Ok(Self(boltz_client::util::secrets::Preimage::from_vec(vec)?))
    }

    #[uniffi::method]
    pub fn bytes(&self) -> Option<Vec<u8>> {
        self.0.bytes.map(|b| b.to_vec())
    }

    #[uniffi::method]
    pub fn to_string(&self) -> Option<String> {
        self.0.to_string()
    }

    #[uniffi::method]
    pub fn sha256(&self) -> String {
        self.0.sha256.to_string()
    }

    #[uniffi::method]
    pub fn hash160(&self) -> String {
        self.0.hash160.to_string()
    }
}

impl Default for Preimage {
    fn default() -> Self {
        Self::new()
    }
}
