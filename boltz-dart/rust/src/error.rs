use boltz_client::util::error::S5Error;
pub struct BoltzError {
    pub kind: String,
    pub message: String,
}

impl BoltzError {
    pub fn new(kind: String, message: String) -> Self {
        BoltzError {
            kind: kind.to_string(),
            message: message,
        }
    }
}

impl From<S5Error> for BoltzError {
    fn from(value: S5Error) -> Self {
        BoltzError {
            kind: value.kind.to_string(),
            message: value.message,
        }
    }
}
