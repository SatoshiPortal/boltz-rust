use crate::e::{ErrorKind, S5Error};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::secp256k1::{KeyPair, PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fmt::Display;
use std::fmt::Formatter;
use std::os::raw::c_char;
use std::str::FromStr;

/// FFI Output
#[derive(Serialize, Deserialize, Debug)]
pub struct ChildKeys {
    pub fingerprint: String,
    pub hardened_path: String,
    pub xprv: String,
    pub xpub: String,
}
impl ChildKeys {
    pub fn from_hardened_account(
        master_xprv: &str,
        purpose: DerivationPurpose,
        account: u64,
    ) -> Result<ChildKeys, S5Error> {
        let secp = Secp256k1::new();
        let root = match ExtendedPrivKey::from_str(master_xprv) {
            Ok(xprv) => xprv,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "Invalid Master Key.")),
        };
    
        let fingerprint = root.fingerprint(&secp);
        let network = root.network;
    
        let coin = match network {
            Network::Bitcoin => "0",
            Network::Testnet => "1",
            _ => "1",
        };
    
        let hardened_path = format!(
            "m/{}h/{}h/{}h",
            purpose.to_string(),
            coin,
            account.to_string()
        );
        let path = match DerivationPath::from_str(&hardened_path) {
            Ok(hdpath) => hdpath,
            Err(_) => {
                return Err(S5Error::new(
                    ErrorKind::Key,
                    "Invalid purpose or account in derivation path.",
                ))
            }
        };
        let child_xprv = match root.derive_priv(&secp, &path) {
            Ok(xprv) => xprv,
            Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
        };
    
        let child_xpub = ExtendedPubKey::from_priv(&secp, &child_xprv);
    
        Ok(ChildKeys {
            fingerprint: fingerprint.to_string(),
            hardened_path,
            xprv: child_xprv.to_string(),
            xpub: child_xpub.to_string(),
        })
    }
    pub fn from_path_str(master_xprv: &str, derivation_path: &str) -> Result<ChildKeys, S5Error> {
        let secp = Secp256k1::new();
        let root = match ExtendedPrivKey::from_str(master_xprv) {
            Ok(xprv) => xprv,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "Invalid Master Key.")),
        };
        let fingerprint = root.fingerprint(&secp);
        let path = match DerivationPath::from_str(&derivation_path) {
            Ok(path) => path,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "Invalid Derivation Path.")),
        };
        let child_xprv = match root.derive_priv(&secp, &path) {
            Ok(xprv) => xprv,
            Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
        };
        let child_xpub = ExtendedPubKey::from_priv(&secp, &child_xprv);
    
        Ok(ChildKeys {
            fingerprint: fingerprint.to_string(),
            hardened_path: derivation_path.to_string(),
            xprv: child_xprv.to_string(),
            xpub: child_xpub.to_string(),
        })
    }
    
}
#[derive(Clone)]
pub enum DerivationPurpose {
    Legacy,
    Compatible,
    Native,
    Taproot,
    _Encryption,
}
impl Display for DerivationPurpose {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            DerivationPurpose::Legacy => write!(f, "44"),
            DerivationPurpose::Compatible => write!(f, "49"),
            DerivationPurpose::Native => write!(f, "84"),
            DerivationPurpose::Taproot => write!(f, "86"),
            DerivationPurpose::_Encryption => write!(f, "392"),
        }
    }
}

pub fn check_xpub(xpub: &str) -> bool {
    ExtendedPubKey::from_str(xpub).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation() {
        let fingerprint = "eb79e0ff";
        let master_xprv: &str = "tprv8ZgxMBicQKsPduTkddZgfGyk4ZJjtEEZQjofpyJg74LizJ469DzoF8nmU1YcvBFskXVKdoYmLoRuZZR1wuTeuAf8rNYR2zb1RvFns2Vs8hY";
        let purpose = DerivationPurpose::Native; //Native-native
        let account = 0; // 0
        let hardened_path = "m/84h/1h/0h";
        let account_xprv = "tprv8gqqcZU4CTQ9bFmmtVCfzeSU9ch3SfgpmHUPzFP5ktqYpnjAKL9wQK5vx89n7tgkz6Am42rFZLS9Qs4DmFvZmgukRE2b5CTwiCWrJsFUoxz";
        let account_xpub = "tpubDDXskyWJLq5pUioZn8sGQ46aieCybzsjLb5BGmRPBAdwfGyvwiyXaoho8EYJcgJa5QGHGYpDjLQ8gWzczWbxadeRkCuExW32Boh696yuQ9m";
        let child_keys = ChildKeys {
            fingerprint: fingerprint.to_string(),
            hardened_path: hardened_path.to_string(),
            xprv: account_xprv.to_string(),
            xpub: account_xpub.to_string(),
        };
        let derived = ChildKeys::from_hardened_account(master_xprv, purpose, account).unwrap();
        assert_eq!(derived.xprv, child_keys.xprv);
    }

    #[test]
    fn test_check_xpub() {
        assert!(check_xpub("tpubDDXskyWJLq5pUioZn8sGQ46aieCybzsjLb5BGmRPBAdwfGyvwiyXaoho8EYJcgJa5QGHGYpDjLQ8gWzczWbxadeRkCuExW32Boh696yuQ9m"));
        assert_eq!(check_xpub("tpubTRICKSkyWJLq5pUioZn8sGQ46aieCybzsjLb5BGmRPBAdwfGyvwiyXaoho8EYJcgJa5QGHGYpDjLQ8gWzczWbxadeRkCuExW32Boh696yuQ9m"),false);
    }
}