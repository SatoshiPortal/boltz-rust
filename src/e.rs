// Implement bitcoin and bdk error type.
use std::ffi::CString;
use std::fmt::Display;
use std::fmt::Formatter;
use std::os::raw::c_char;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub enum ErrorKind {
    Key,
    Wallet,
    Network,
    Input,
    Internal,
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            ErrorKind::Input => write!(f, "Input"),
            ErrorKind::Internal => write!(f, "OpError"),
            ErrorKind::Key => write!(f, "KeyError"),
            ErrorKind::Wallet => write!(f, "WalletError"),
            ErrorKind::Network => write!(f, "NetworkError"),
        }
    }
}

/// FFI Output
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct S5Error {
    pub kind: String,
    pub message: String,
}

impl S5Error {
    pub fn new(kind: ErrorKind, message: &str) -> Self {
        S5Error {
            kind: kind.to_string(),
            message: message.to_string(),
        }
    }
    pub fn c_stringify(&self) -> *mut c_char {
        let stringified = match serde_json::to_string(self) {
            Ok(result) => result,
            Err(_) => {
                return CString::new("Error:JSON Stringify Failed. BAD NEWS! Contact Support.")
                    .unwrap()
                    .into_raw()
            }
        };

        CString::new(stringified).unwrap().into_raw()
    }
}
