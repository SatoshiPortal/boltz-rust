use crate::network::Chain;
use crate::swaps::bitcoin::BtcSwapScript;
use crate::swaps::liquid::LBtcSwapScript;
use crate::util::error::{ErrorKind, S5Error};
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use elements::secp256k1_zkp::{Keypair as ZKKeyPair, Secp256k1 as ZKSecp256k1};

use bitcoin::secp256k1::hashes::{hash160, ripemd160, sha256, Hash};
use lightning_invoice::Bolt11Invoice;

use bitcoin::secp256k1::rand::rngs::OsRng;
use rand_core::RngCore;

use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

const SUBMARINE_SWAP_ACCOUNT: u32 = 21;
const REVERSE_SWAP_ACCOUNT: u32 = 42;

const BITCOIN_NETWORK_PATH: u32 = 0;
const LIQUID_NETWORK_PATH: u32 = 1776;
const TESTNET_NETWORK_PATH: u32 = 1;

/// Derived Keypair for use in a script.
/// Can be used directly with Bitcoin structures
/// Can be converted .into() LiquidSwapKey
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SwapKey {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub keypair: Keypair,
}
impl SwapKey {
    /// Derives keys for a submarine swap at standardized path
    /// m/49'/<0;1777;1>/21'/0/*
    pub fn from_submarine_account(
        mnemonic: &str,
        passphrase: &str,
        network: Chain,
        index: u64,
    ) -> Result<SwapKey, S5Error> {
        let secp = Secp256k1::new();
        let mnemonic_struct = Mnemonic::from_str(&mnemonic).unwrap();
        let seed = mnemonic_struct.to_seed(passphrase);
        let root = match Xpriv::new_master(bitcoin::Network::Testnet, &seed) {
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

        let key_pair = match Keypair::from_seckey_str(
            &secp,
            &hex::encode(child_xprv.private_key.secret_bytes()),
        ) {
            Ok(kp) => kp,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
        };

        Ok(SwapKey {
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
    ) -> Result<SwapKey, S5Error> {
        let secp = Secp256k1::new();
        let mnemonic_struct = Mnemonic::from_str(mnemonic).unwrap();
        let seed = mnemonic_struct.to_seed(passphrase);
        let root = match Xpriv::new_master(bitcoin::Network::Testnet, &seed) {
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
            purpose, network_path, REVERSE_SWAP_ACCOUNT, index
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

        let key_pair = match Keypair::from_seckey_str(
            &secp,
            &hex::encode(child_xprv.private_key.secret_bytes()),
        ) {
            Ok(kp) => kp,
            Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
        };

        Ok(SwapKey {
            fingerprint: fingerprint,
            path: path,
            keypair: key_pair,
        })
    }
}
#[derive(Clone)]

/// For Liquid keys, first create a SwapKey and then call .into() to get the equaivalent ZKKeypair
/// let sk = SwapKey::from_reverse_account(&mnemonic.to_string(), "", Chain::LiquidTestnet, 1).unwrap()
/// let lsk: LiquidSwapKey = swap_key.into();
/// let zkkp = lsk.keypair;
#[derive(Serialize, Deserialize, Debug)]
pub struct LiquidSwapKey {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub keypair: ZKKeyPair,
}
impl From<SwapKey> for LiquidSwapKey {
    fn from(swapkey: SwapKey) -> Self {
        let secp = ZKSecp256k1::new();
        let liquid_keypair =
            ZKKeyPair::from_seckey_str(&secp, &swapkey.keypair.display_secret().to_string())
                .unwrap();

        LiquidSwapKey {
            fingerprint: swapkey.fingerprint,
            path: swapkey.path,
            keypair: liquid_keypair,
        }
    }
}
enum DerivationPurpose {
    _Legacy,
    Compatible,
    Native,
    _Taproot,
}
impl Display for DerivationPurpose {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            DerivationPurpose::_Legacy => write!(f, "44"),
            DerivationPurpose::Compatible => write!(f, "49"),
            DerivationPurpose::Native => write!(f, "84"),
            DerivationPurpose::_Taproot => write!(f, "86"),
        }
    }
}

/// Internally used rng to generate secure 32 byte preimages
fn rng_32b() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Helper to work with Preimage & Hashes required for swap scripts.
#[derive(Debug, Clone)]
pub struct Preimage {
    pub bytes: Option<[u8; 32]>,
    pub sha256: sha256::Hash,
    pub hash160: hash160::Hash,
}

impl Preimage {
    /// Creates a new random preimage
    pub fn new() -> Preimage {
        let preimage = rng_32b();
        let sha256 = sha256::Hash::hash(&preimage);
        let hash160 = hash160::Hash::hash(&preimage);

        Preimage {
            bytes: Some(preimage),
            sha256: sha256,
            hash160: hash160,
        }
    }

    /// Creates a struct from a preimage string.
    pub fn from_str(preimage: &str) -> Result<Preimage, S5Error> {
        let decoded = match hex::decode(preimage) {
            Ok(decoded) => decoded,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        // Ensure the decoded bytes are exactly 32 bytes long
        let preimage_bytes: [u8; 32] = match decoded.try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(S5Error::new(
                    ErrorKind::Input,
                    "Decoded Preimage input is not 32 bytes",
                ))
            }
        };
        let sha256 = sha256::Hash::hash(&preimage_bytes);
        let hash160 = hash160::Hash::hash(&preimage_bytes);
        Ok(Preimage {
            bytes: Some(preimage_bytes),
            sha256: sha256,
            hash160: hash160,
        })
    }

    /// Creates a Preimage struct without a value and only a hash
    /// Used only in submarine swaps where we do not know the preimage, only the hash
    pub fn from_sha256_str(preimage_sha256: &str) -> Result<Preimage, S5Error> {
        let sha256 = match sha256::Hash::from_str(preimage_sha256) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        let hash160 = hash160::Hash::from_slice(
            ripemd160::Hash::hash(sha256.as_byte_array()).as_byte_array(),
        )
        .unwrap();
        // will never fail as long as sha256 is a valid sha256::Hash
        Ok(Preimage {
            bytes: None,
            sha256: sha256,
            hash160: hash160,
        })
    }

    /// Extracts the preimage sha256 hash from a lightning invoice
    /// Creates a Preimage struct without a value and only a hash
    pub fn from_invoice_str(invoice_str: &str) -> Result<Preimage, S5Error> {
        let invoice = match Bolt11Invoice::from_str(&invoice_str) {
            Ok(invoice) => invoice,
            Err(e) => {
                println!("{:?}", e);
                return Err(S5Error::new(
                    ErrorKind::Input,
                    "Could not parse invoice string.",
                ));
            }
        };
        Ok(Preimage::from_sha256_str(
            &invoice.payment_hash().to_string(),
        )?)
    }

    /// Converts the preimage value bytes to String
    pub fn to_string(&self) -> Option<String> {
        match self.bytes {
            Some(result) => Some(hex::encode(result)),
            None => None,
        }
    }
}
use serde_json;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Boltz standard JSON refund swap file. Can be used to create a file that can be uploaded to boltz.exchange
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RefundSwapFile {
    pub id: String,
    pub currency: String,
    pub redeem_script: String,
    pub private_key: String,
    pub timeout_block_height: u64,
}
impl RefundSwapFile {
    pub fn file_name(&self) -> String {
        format!("boltz-{}.json", self.id)
    }
    pub fn write_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), S5Error> {
        let mut full_path = PathBuf::from(path.as_ref());
        full_path.push(self.file_name());
        let mut file = match File::create(&full_path) {
            Ok(f) => f,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        let json = match serde_json::to_string_pretty(self) {
            Ok(j) => j,
            Err(e) => return Err(S5Error::new(ErrorKind::Script, &e.to_string())),
        };
        if let Err(e) = writeln!(file, "{}", json) {
            return Err(S5Error::new(ErrorKind::Input, &e.to_string()));
        }
        Ok(())
    }
    pub fn read_from_file<P: AsRef<Path>>(path: P) -> Result<Self, S5Error> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        let mut contents = String::new();
        if let Err(e) = file.read_to_string(&mut contents) {
            return Err(S5Error::new(ErrorKind::Input, &e.to_string()));
        }
        match serde_json::from_str(&contents) {
            Ok(refund_swap_file) => Ok(refund_swap_file),
            Err(e) => Err(S5Error::new(ErrorKind::Script, &e.to_string())),
        }
    }
}

/// Recovery items for storage
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcSubmarineRecovery {
    pub id: String,
    pub refund_key: String,
    pub redeem_script: String,
}
impl BtcSubmarineRecovery {
    pub fn new(id: &str, refund_key: &Keypair, redeem_script: &str) -> Self {
        BtcSubmarineRecovery {
            id: id.to_string(),
            refund_key: refund_key.display_secret().to_string(),
            redeem_script: redeem_script.to_string(),
        }
    }
}
impl Into<RefundSwapFile> for BtcSubmarineRecovery {
    fn into(self) -> RefundSwapFile {
        let script = BtcSwapScript::submarine_from_str(&self.redeem_script).unwrap();
        RefundSwapFile {
            id: self.id,
            currency: "BTC".to_string(),
            redeem_script: self.redeem_script,
            private_key: self.refund_key,
            timeout_block_height: script.timelock as u64,
        }
    }
}

impl TryInto<BtcSwapScript> for &BtcSubmarineRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<BtcSwapScript, Self::Error> {
        Ok(BtcSwapScript::submarine_from_str(&self.redeem_script).unwrap())
    }
}

impl TryInto<Keypair> for &BtcSubmarineRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<Keypair, Self::Error> {
        let secp = Secp256k1::new();
        Ok(Keypair::from_seckey_str(&secp, &self.refund_key).unwrap())
    }
}

/// Recovery items for storage
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BtcReverseRecovery {
    pub id: String,
    pub preimage: String,
    pub claim_key: String,
    pub redeem_script: String,
}
impl BtcReverseRecovery {
    pub fn new(id: &str, preimage: &Preimage, claim_key: &Keypair, redeem_script: &str) -> Self {
        BtcReverseRecovery {
            id: id.to_string(),
            claim_key: claim_key.display_secret().to_string(),
            preimage: preimage.to_string().unwrap(),
            redeem_script: redeem_script.to_string(),
        }
    }
}
impl TryInto<BtcSwapScript> for &BtcReverseRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<BtcSwapScript, Self::Error> {
        Ok(BtcSwapScript::reverse_from_str(&self.redeem_script)?)
    }
}

impl TryInto<Keypair> for &BtcReverseRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<Keypair, Self::Error> {
        let secp = Secp256k1::new();
        Ok(Keypair::from_seckey_str(&secp, &self.claim_key)?)
    }
}
impl TryInto<Preimage> for &BtcReverseRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<Preimage, Self::Error> {
        Ok(Preimage::from_str(&self.preimage)?)
    }
}

/// Recovery items for storage
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LBtcSubmarineRecovery {
    pub id: String,
    pub refund_key: String,
    pub blinding_key: String,
    pub redeem_script: String,
}
impl LBtcSubmarineRecovery {
    pub fn new(
        id: &str,
        refund_key: &Keypair,
        blinding_key: &ZKKeyPair,
        redeem_script: &str,
    ) -> Self {
        LBtcSubmarineRecovery {
            id: id.to_string(),
            refund_key: refund_key.display_secret().to_string(),
            redeem_script: redeem_script.to_string(),
            blinding_key: blinding_key.display_secret().to_string(),
        }
    }
}
impl Into<RefundSwapFile> for LBtcSubmarineRecovery {
    fn into(self) -> RefundSwapFile {
        let script =
            LBtcSwapScript::submarine_from_str(&self.redeem_script, &self.blinding_key).unwrap();
        RefundSwapFile {
            id: self.id,
            currency: "L-BTC".to_string(),
            redeem_script: self.redeem_script,
            private_key: self.refund_key,
            timeout_block_height: script.timelock as u64,
        }
    }
}
/// Recovery items for storage
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LBtcReverseRecovery {
    pub id: String,
    pub preimage: String,
    pub claim_key: String,
    pub blinding_key: String,
    pub redeem_script: String,
}
impl LBtcReverseRecovery {
    pub fn new(
        id: &str,
        preimage: &Preimage,
        claim_key: &Keypair,
        blinding_key: &ZKKeyPair,
        redeem_script: &str,
    ) -> Self {
        LBtcReverseRecovery {
            id: id.to_string(),
            claim_key: claim_key.display_secret().to_string(),
            blinding_key: blinding_key.display_secret().to_string(),
            preimage: preimage.to_string().unwrap(),
            redeem_script: redeem_script.to_string(),
        }
    }
}
impl TryInto<LBtcSwapScript> for &LBtcReverseRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<LBtcSwapScript, Self::Error> {
        Ok(LBtcSwapScript::reverse_from_str(&self.redeem_script, &self.blinding_key).unwrap())
    }
}

impl TryInto<Keypair> for &LBtcReverseRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<Keypair, Self::Error> {
        let secp = Secp256k1::new();
        Ok(Keypair::from_seckey_str(&secp, &self.claim_key).unwrap())
    }
}
impl TryInto<Preimage> for &LBtcReverseRecovery {
    type Error = S5Error;
    fn try_into(self) -> Result<Preimage, Self::Error> {
        Ok(Preimage::from_str(&self.preimage).unwrap())
    }
}
#[cfg(test)]
mod tests {
    use std::{cell::Ref, path};

    use super::*;

    #[test]
    fn test_derivation() {
        let mnemonic: &str = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let index = 0 as u64; // 0
        let sk = SwapKey::from_submarine_account(mnemonic, "", Chain::Bitcoin, index).unwrap();
        let lks: LiquidSwapKey = sk.clone().into();
        assert!(sk.fingerprint == lks.fingerprint);
        // println!("{:?}", derived.unwrap().Keypair.display_secret());
        assert_eq!(&sk.fingerprint.to_string().clone(), "9a6a2580");
        assert_eq!(
            &sk.keypair.display_secret().to_string(),
            "d8d26ab9ba4e2c44f1a1fb9e10dc9d78707aaaaf38b5d42cf5c8bf00306acd85"
        );
    }

    #[test]
    #[ignore]
    fn test_recover() {
        let recovery = BtcSubmarineRecovery {
            id: "y8uGeA".to_string(),
            refund_key: "5416f1e024c191605502017d066786e294f841e711d3d437d13e9d27e40e066e".to_string(),
            redeem_script: "a914046fabc17989627f6ca9c1846af8e470263e712d87632102c929edb654bc1da91001ec27d74d42b5d6a8cf8aef2fab7c55f2eb728eed0d1f6703634d27b1752102c530b4583640ab3df5c75c5ce381c4b747af6bdd6c618db7e5248cb0adcf3a1868ac".to_string(),
        };
        let file: RefundSwapFile = recovery.into();
        let base_path = "/tmp/boltz-rust";
        file.write_to_file(base_path);
        let file_path = base_path.to_owned() + "/" + &file.file_name();
        let file_struct = RefundSwapFile::read_from_file(file_path);
        println!("Refund File: {:?}", file_struct);
    }
}
