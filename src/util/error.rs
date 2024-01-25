use bitcoin::secp256k1;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fmt::Formatter;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum ErrorKind {
    Key,
    BoltzApi,
    Network,
    Input,
    Script,
    Transaction,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ErrorKind::Input => write!(f, "Input"),
            ErrorKind::BoltzApi => write!(f, "BoltzApi"),
            ErrorKind::Key => write!(f, "Key"),
            ErrorKind::Network => write!(f, "Network"),
            ErrorKind::Script => write!(f, "Script"),
            ErrorKind::Transaction => write!(f, "Transaction"),
        }
    }
}

/// FFI Output
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct S5Error {
    pub kind: ErrorKind,
    pub message: String,
}

impl S5Error {
    pub fn new(kind: ErrorKind, message: &str) -> Self {
        S5Error {
            kind: kind,
            message: message.to_string(),
        }
    }
}

impl From<secp256k1::Error> for S5Error {
    fn from(error: secp256k1::Error) -> Self {
        S5Error {
            kind: ErrorKind::Key,
            message: error.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Error {
    Key(String),
    BoltzApi(String),
    Network(String),
    Input(String),
    Script(String),
    Transaction(String),
}
impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            Error::Input(s) => write!(f, "Input: {s}"),
            Error::BoltzApi(s) => write!(f, "BoltzApi: {s}"),
            Error::Key(s) => write!(f, "Key: {s}"),
            Error::Network(s) => write!(f, "Network: {s}"),
            Error::Script(s) => write!(f, "Script: {s}"),
            Error::Transaction(s) => write!(f, "Transaction: {s}"),
        }
    }
}
// Error::BoltzApi(e.to_string())
