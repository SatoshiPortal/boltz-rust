use crate::util::error::{ErrorKind, S5Error};
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{KeyPair, Secp256k1};

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

const SUBMARINE_SWAP_ACCOUNT: &str = "21";
const REVERSE_SWAP_ACCOUNT: &str = "42";

#[derive(Serialize, Deserialize, Debug)]
pub struct ChildKeys {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub keypair: KeyPair,
}
impl ChildKeys {
    pub fn from_submarine_account(mnemonic: &str, index: u64) -> Result<ChildKeys, S5Error> {
        let secp = Secp256k1::new();
        let mnemonic_struct = Mnemonic::from_str(&mnemonic).unwrap();
        let seed = mnemonic_struct.to_seed("");
        let root = match ExtendedPrivKey::new_master(bitcoin::Network::Testnet, &seed) {
            Ok(xprv) => xprv,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "Invalid Master Key.")),
        };
        let fingerprint = root.fingerprint(&secp);
        let network = root.network;
        let purpose = DerivationPurpose::Compatible;
        let coin = match network {
            Network::Bitcoin => "0",
            Network::Testnet => "1",
            _ => "1",
        };

        // 6777837e/purpose'/network'/account'/change|depost/index
        // m/0' => XKeypair
        // m/0'/1'/89718/29839823 => XKeypair
        // BIP32
        // m/
        let derivation_path = format!(
            "m/{}h/{}h/{}h/0/{}",
            purpose.to_string(),
            coin,
            SUBMARINE_SWAP_ACCOUNT,
            index
        );
        let path = match DerivationPath::from_str(&derivation_path) {
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

        let key_pair = match KeyPair::from_seckey_str(
            &secp,
            &hex::encode(child_xprv.private_key.secret_bytes()),
        ) {
            Ok(kp) => kp,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
        };

        Ok(ChildKeys {
            fingerprint: fingerprint,
            path: path,
            keypair: key_pair,
        })
    }
    pub fn from_reverse_account(mnemonic: &str, index: u64) -> Result<ChildKeys, S5Error> {
        let secp = Secp256k1::new();
        let mnemonic_struct = Mnemonic::from_str(&mnemonic).unwrap();
        let seed = mnemonic_struct.to_seed("");
        let root = match ExtendedPrivKey::new_master(bitcoin::Network::Testnet, &seed) {
            Ok(xprv) => xprv,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "Invalid Master Key.")),
        };
        let fingerprint = root.fingerprint(&secp);
        let network = root.network;
        let purpose = DerivationPurpose::Native;
        let coin = match network {
            Network::Bitcoin => "0",
            Network::Testnet => "1",
            _ => "1",
        };
        // m/84h/1h/42h/<0;1>/*  - child key for segwit wallet - xprv
        let derivation_path = format!(
            "m/{}h/{}h/{}h/0/{}",
            purpose.to_string(),
            coin,
            REVERSE_SWAP_ACCOUNT,
            index
        );
        let path = match DerivationPath::from_str(&derivation_path) {
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

        let key_pair = match KeyPair::from_seckey_str(
            &secp,
            &hex::encode(child_xprv.private_key.secret_bytes()),
        ) {
            Ok(kp) => kp,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
        };

        Ok(ChildKeys {
            fingerprint: fingerprint,
            path: path,
            keypair: key_pair,
        })
    }
}
#[derive(Clone)]
pub enum DerivationPurpose {
    Legacy,
    Compatible,
    Native,
    Taproot,
}
impl Display for DerivationPurpose {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            DerivationPurpose::Legacy => write!(f, "44"),
            DerivationPurpose::Compatible => write!(f, "49"),
            DerivationPurpose::Native => write!(f, "84"),
            DerivationPurpose::Taproot => write!(f, "86"),
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
        let mnemonic: &str = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let index = 0 as u64; // 0
        let derived = ChildKeys::from_submarine_account(mnemonic, index);
        assert!(derived.is_ok());
    }

    #[test]
    fn test_check_xpub() {
        assert!(check_xpub("tpubDDXskyWJLq5pUioZn8sGQ46aieCybzsjLb5BGmRPBAdwfGyvwiyXaoho8EYJcgJa5QGHGYpDjLQ8gWzczWbxadeRkCuExW32Boh696yuQ9m"));
        assert_eq!(check_xpub("tpubTRICKSkyWJLq5pUioZn8sGQ46aieCybzsjLb5BGmRPBAdwfGyvwiyXaoho8EYJcgJa5QGHGYpDjLQ8gWzczWbxadeRkCuExW32Boh696yuQ9m"),false);
    }
}
