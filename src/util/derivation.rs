use crate::network::Chain;
use crate::util::error::{ErrorKind, S5Error};
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, ExtendedPrivKey, Fingerprint};
use bitcoin::secp256k1::{KeyPair, Secp256k1};

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

const SUBMARINE_SWAP_ACCOUNT: u32 = 21;
const REVERSE_SWAP_ACCOUNT: u32 = 42;

const BITCOIN_NETWORK_PATH: u32 = 0;
const LIQUID_NETWORK_PATH: u32 = 1776;
const TESTNET_NETWORK_PATH: u32 = 1;

/// Derived KeyPair for use in a script.
#[derive(Serialize, Deserialize, Debug)]
pub struct ChildKeys {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub keypair: KeyPair,
}
impl ChildKeys {
    /// Derives keys for a submarine swap at standardized path
    /// m/49'/<0;1777;1>/21'/0/*
    pub fn from_submarine_account(
        mnemonic: &str,
        passphrase: &str,
        network: Chain,
        index: u64,
    ) -> Result<ChildKeys, S5Error> {
        let secp = Secp256k1::new();
        let mnemonic_struct = Mnemonic::from_str(&mnemonic).unwrap();
        let seed = mnemonic_struct.to_seed(passphrase);
        let root = match ExtendedPrivKey::new_master(bitcoin::Network::Testnet, &seed) {
            Ok(xprv) => xprv,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "Invalid Master Key.")),
        };
        let fingerprint = root.fingerprint(&secp);
        let purpose = DerivationPurpose::Compatible;
        let network_path = match network {
            Chain::Bitcoin => BITCOIN_NETWORK_PATH,
            Chain::Liquid => LIQUID_NETWORK_PATH,
            _ => TESTNET_NETWORK_PATH,
        };
        let derivation_path = format!(
            "m/{}h/{}h/{}h/0/{}",
            purpose.to_string(),
            network_path,
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
    /// Derives keys for a submarine swap at standardized path
    /// m/49'/<0;1777;1>/42'/0/*
    pub fn from_reverse_account(
        mnemonic: &str,
        passphrase: &str,
        network: Chain,
        index: u64,
    ) -> Result<ChildKeys, S5Error> {
        let secp = Secp256k1::new();
        let mnemonic_struct = Mnemonic::from_str(&mnemonic).unwrap();
        let seed = mnemonic_struct.to_seed(passphrase);
        let root = match ExtendedPrivKey::new_master(bitcoin::Network::Testnet, &seed) {
            Ok(xprv) => xprv,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "Invalid Master Key.")),
        };
        let fingerprint = root.fingerprint(&secp);
        let purpose = DerivationPurpose::Native;
        let network_path = match network {
            Chain::Bitcoin => BITCOIN_NETWORK_PATH,
            Chain::Liquid => LIQUID_NETWORK_PATH,
            _ => TESTNET_NETWORK_PATH,
        };
        // m/84h/1h/42h/<0;1>/*  - child key for segwit wallet - xprv
        let derivation_path = format!(
            "m/{}h/{}h/{}h/0/{}",
            purpose.to_string(),
            network_path,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivation() {
        let mnemonic: &str = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let index = 0 as u64; // 0
        let derived = ChildKeys::from_submarine_account(mnemonic, "", Chain::Bitcoin, index);
        // println!("{:?}", derived.unwrap().keypair.display_secret());
        assert!(derived.is_ok());
        assert_eq!(
            &derived.as_ref().unwrap().fingerprint.to_string(),
            "9a6a2580"
        );
        assert_eq!(
            &derived
                .as_ref()
                .unwrap()
                .keypair
                .display_secret()
                .to_string(),
            "d8d26ab9ba4e2c44f1a1fb9e10dc9d78707aaaaf38b5d42cf5c8bf00306acd85"
        );
    }
}
