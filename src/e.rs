use std::ffi::CString;
use std::fmt::Display;
use std::fmt::Formatter;
use std::os::raw::c_char;

use serde::{Deserialize, Serialize};

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
