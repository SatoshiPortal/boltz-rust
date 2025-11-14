//! # Usage Instructions
//!
//! ## Creating SwapMasterKey
//! Use `SwapMasterKey::new` with your wallet mnemonic and passphrase to create a SwapMasterKey.
//! The method will internally derive the BIP85 swap mnemonic from your wallet mnemonic.
//! The SwapMasterKey should then be stored (it can be serialized to JSON) to use for each swap with the `derive_swapkey` method.
//!
//! ## Example
//! ```no_run
//! use boltz_client::util::secrets::SwapMasterKey;
//! use boltz_client::network::Network;
//!
//! // Create SwapMasterKey from wallet mnemonic (BIP85 derivation happens internally)
//! let wallet_mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
//! let swap_master_key = SwapMasterKey::new(wallet_mnemonic, None, Network::Mainnet)?;
//!
//! // Store swap_master_key (can be serialized to JSON)
//! // Later, derive keys for each swap
//! let swap_key = swap_master_key.derive_swapkey(0)?;
//! # Ok::<(), boltz_client::error::Error>(())
//! ```

use std::str::FromStr;

use bip39::Mnemonic;
use bip85_extended;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::key::rand::{rngs::OsRng, RngCore};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use elements::secp256k1_zkp::{Keypair as ZKKeyPair, Secp256k1 as ZKSecp256k1};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::network::Network;

const MNEMONIC_BIP85_INDEX: u32 = 26589;
const SWAP_KEY_DERIVATION_PATH: &str = "m/26589'/0'/0'";

/// Swap master key to derive swap keys for all swaps.
///
/// This struct holds the BIP85-derived swap mnemonic and the master private key derived from it.
/// It can be stored (serialized to JSON) and reused to derive individual swap keys without
/// needing to pass the mnemonic and passphrase repeatedly.
///
/// The mnemonic field contains the BIP85-derived swap mnemonic, which can be used for recovery
/// on: https://boltz.exchange/rescue/external?mode=rescue-key
///
/// Can also be used to get the root xpubs that can be used with the swap/restore API.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct SwapMasterKey {
    /// The BIP85-derived swap mnemonic
    pub mnemonic: Mnemonic,
    /// The child xprv derived from the swap mnemonic at the standard derivation path
    pub xprv: Xpriv,
    /// The fingerprint of the root key
    pub fingerprint: Fingerprint,
    /// The network this key is for
    pub network: Network,
}

impl SwapMasterKey {
    /// Creates SwapMasterKey from a wallet mnemonic.
    ///
    /// This method internally derives the BIP85 swap mnemonic from the wallet mnemonic
    /// using BIP85 index `26589`, then creates the SwapMasterKey
    /// from that derived mnemonic.
    ///
    /// The swap mnemonic stored in the returned struct can be used for recovery on:
    /// https://boltz.exchange/rescue/external?mode=rescue-key
    ///
    /// # Arguments
    /// * `wallet_mnemonic` - The wallet mnemonic to derive the swap mnemonic from
    /// * `wallet_passphrase` - Optional passphrase for the wallet mnemonic
    /// * `network` - The network (Mainnet, Testnet, or Regtest)
    pub fn new(
        wallet_mnemonic: &str,
        wallet_passphrase: Option<&str>,
        network: Network,
    ) -> Result<SwapMasterKey, Error> {
        let secp = Secp256k1::new();
        let root = Self::derive_root_xpriv(wallet_mnemonic, wallet_passphrase, network)?;
        let swap_mnemonic =
            bip85_extended::mnemonic::to_mnemonic(&secp, &root, 12, MNEMONIC_BIP85_INDEX)?;
        Self::from_mnemonic(&swap_mnemonic.to_string(), None, network)
    }

    /// Creates SwapMasterKey directly from a mnemonic.
    ///
    /// Use this method if you already have the swap mnemonic (e.g., from a previous
    /// SwapMasterKey that was serialized, or if you're restoring from the rescue key).
    ///
    /// The mnemonic will be used to derive the master key at the standard derivation path
    /// `m/26589'/0'/0'`.
    ///
    /// # Arguments
    /// * `mnemonic` - The swap mnemonic (12-word BIP39 mnemonic)
    /// * `passphrase` - Optional passphrase for the mnemonic
    /// * `network` - The network (Mainnet, Testnet, or Regtest)
    pub fn from_mnemonic(
        mnemonic: &str,
        passphrase: Option<&str>,
        network: Network,
    ) -> Result<SwapMasterKey, Error> {
        let secp = Secp256k1::new();
        let root = Self::derive_root_xpriv(mnemonic, passphrase, network)?;
        let fingerprint = root.fingerprint(&secp);

        let master_path = DerivationPath::from_str(SWAP_KEY_DERIVATION_PATH)?;
        let xprv = root.derive_priv(&secp, &master_path)?;

        let mnemonic_struct = Mnemonic::from_str(mnemonic)?;

        Ok(SwapMasterKey {
            mnemonic: mnemonic_struct,
            xprv,
            fingerprint,
            network,
        })
    }
    /// Derives a KeyPair for a specific swap index.
    ///
    /// Use this method for each swap. The client must handle incrementing the index
    /// themselves to ensure each swap uses a unique key.
    ///
    /// # Arguments
    /// * `index` - The swap index (0, 1, 2, etc.)
    ///
    /// # Returns
    /// A `KeyPair` derived at path `m/26589'/0'/0'/{index}`
    pub fn derive_swapkey(&self, index: u64) -> Result<Keypair, Error> {
        let secp = Secp256k1::new();
        let child_path = DerivationPath::from_str(&format!("m/0/{index}"))?;
        let child_xprv = self.xprv.derive_priv(&secp, &child_path)?;
        let key_pair = Keypair::from_secret_key(&secp, &child_xprv.private_key);
        Ok(key_pair)
    }

    /// Derives a ZKKeyPair for Liquid swaps at a specific swap index.
    ///
    /// Use this method for each Liquid swap. The client must handle incrementing the index
    /// themselves to ensure each swap uses a unique key.
    ///
    /// # Arguments
    /// * `index` - The swap index (0, 1, 2, etc.)
    ///
    /// # Returns
    /// A `ZKKeyPair` derived at path `m/26589'/0'/0'/{index}`
    pub fn derive_liquid_swapkey(&self, index: u64) -> Result<ZKKeyPair, Error> {
        let keypair = self.derive_swapkey(index)?;
        let secp = ZKSecp256k1::new();
        let zk_keypair = ZKKeyPair::from_seckey_str(&secp, &keypair.display_secret().to_string())?;
        Ok(zk_keypair)
    }

    /// Gets the master extended public key (xpub) derived from the master private key.
    ///
    /// This xpub can be used with the swap/restore API to enable key recovery.
    ///
    /// # Returns
    /// The master extended public key
    pub fn get_master_xpub(&self) -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &self.xprv)
    }

    fn derive_root_xpriv(
        mnemonic: &str,
        passphrase: Option<&str>,
        network: Network,
    ) -> Result<Xpriv, Error> {
        let mnemonic_struct = Mnemonic::from_str(mnemonic)?;
        let seed = mnemonic_struct.to_seed(passphrase.unwrap_or(""));
        let root = Xpriv::new_master(bitcoin::Network::from(network), &seed)?;
        Ok(root)
    }
}

/// For Liquid keys, first create a KeyPair from SwapMasterKey and then convert it to ZKKeyPair
/// let swap_master_key = SwapMasterKey::new(wallet_mnemonic, None, Network::Mainnet)?;
/// let keypair = swap_master_key.derive_swapkey(1)?;
/// let zk_keypair = ZKKeyPair::from_seckey_str(&ZKSecp256k1::new(), &keypair.display_secret().to_string())?;
/// Internally used rng to generate secure 32 byte preimages
pub(crate) fn rng_32b() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Helper to work with Preimage & Hashes required for swap scripts.
#[derive(Serialize, Deserialize, Clone, Eq, PartialEq, Debug)]
pub struct Preimage {
    pub bytes: Option<[u8; 32]>,
    pub sha256: sha256::Hash,
    pub hash160: hash160::Hash,
}

impl FromStr for Preimage {
    type Err = Error;

    /// Creates a struct from a preimage string.
    fn from_str(preimage: &str) -> Result<Self, Self::Err> {
        Self::from_vec(Vec::from_hex(preimage)?)
    }
}

impl Default for Preimage {
    fn default() -> Self {
        Preimage::random()
    }
}

impl Preimage {
    /// Creates a new random preimage
    /// RECOMMENDED NOT TO USE THIS FUNCTION
    /// USE FROM_SWAP_KEY INSTEAD
    pub fn random() -> Preimage {
        let preimage = rng_32b();
        let sha256 = sha256::Hash::hash(&preimage);
        let hash160 = hash160::Hash::hash(&preimage);

        Preimage {
            sha256,
            hash160,
            bytes: Some(preimage),
        }
    }

    /// Creates a struct from a preimage vector.
    pub fn from_vec(preimage: Vec<u8>) -> Result<Preimage, Error> {
        // Ensure the decoded bytes are exactly 32 bytes long
        let preimage: [u8; 32] = preimage
            .try_into()
            .map_err(|_| Error::Protocol("Decoded Preimage input is not 32 bytes".to_string()))?;
        let sha256 = sha256::Hash::hash(&preimage);
        let hash160 = hash160::Hash::hash(&preimage);
        Ok(Preimage {
            sha256,
            hash160,
            bytes: Some(preimage),
        })
    }

    /// Creates a Preimage struct without a value and only a hash
    /// Used only in submarine swaps where we do not know the preimage, only the hash
    pub fn from_sha256_str(preimage_sha256: &str) -> Result<Preimage, Error> {
        Self::from_sha256_vec(Vec::from_hex(preimage_sha256)?)
    }

    /// Creates a Preimage struct without a value and only a hash
    /// Used only in submarine swaps where we do not know the preimage, only the hash
    pub fn from_sha256_vec(preimage_sha256: Vec<u8>) -> Result<Preimage, Error> {
        let sha256 = sha256::Hash::from_slice(preimage_sha256.as_slice())?;
        let hash160 = hash160::Hash::from_slice(
            ripemd160::Hash::hash(sha256.as_byte_array()).as_byte_array(),
        )?;
        // will never fail as long as sha256 is a valid sha256::Hash
        Ok(Preimage {
            sha256,
            hash160,
            bytes: None,
        })
    }

    /// Extracts the preimage sha256 hash from a lightning invoice
    /// Creates a Preimage struct without a value and only a hash
    pub fn from_invoice_str(invoice_str: &str) -> Result<Preimage, Error> {
        let invoice = Bolt11Invoice::from_str(invoice_str)?;
        Preimage::from_sha256_str(&invoice.payment_hash().to_string())
    }

    /// Converts the preimage value bytes to String
    pub fn to_string(&self) -> Option<String> {
        self.bytes.map(|res| res.to_lower_hex_string())
    }

    /// Creates a Preimage from a KeyPair's private key hash
    /// sha256(privateKey(index))
    /// RECOMMENDED TO ENSURE SWAPS CAN BE RESTORED MORE EASILY
    pub fn from_swap_key(keypair: &Keypair) -> Preimage {
        let private_key_bytes = keypair.secret_key().secret_bytes();
        let preimage = sha256::Hash::hash(&private_key_bytes);
        let preimage_bytes: [u8; 32] = *preimage.as_byte_array();
        let sha256 = sha256::Hash::hash(&preimage_bytes);
        let hash160 = hash160::Hash::hash(&preimage_bytes);

        Preimage {
            bytes: Some(preimage_bytes),
            sha256,
            hash160,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::pset::serialize::Serialize;

    #[macros::test_all]
    fn test_derivation() {
        let mnemonic: &str = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let index = 0_u64; // 0
        let swap_master_key =
            SwapMasterKey::from_mnemonic(mnemonic, None, Network::Mainnet).unwrap();
        let keypair = swap_master_key.derive_swapkey(index).unwrap();
        let secp = ZKSecp256k1::new();
        let zk_keypair =
            ZKKeyPair::from_seckey_str(&secp, &keypair.display_secret().to_string()).unwrap();
        assert_eq!(keypair.public_key(), zk_keypair.public_key());
    }

    #[macros::test_all]
    fn test_preimage_from_str() {
        let preimage = Preimage::random();
        assert_eq!(
            Preimage::from_str(&hex::encode(preimage.bytes.unwrap()).to_string()).unwrap(),
            preimage
        );
    }

    #[macros::test_all]
    fn test_preimage_from_vec() {
        let preimage = Preimage::random();
        assert_eq!(
            Preimage::from_vec(Vec::from(preimage.bytes.unwrap())).unwrap(),
            preimage
        );
    }

    #[macros::test_all]
    fn test_preimage_from_vec_invalid_length() {
        let mut bytes = [0u8; 33];
        OsRng.fill_bytes(&mut bytes);
        assert_eq!(
            Preimage::from_vec(Vec::from(bytes))
                .err()
                .unwrap()
                .message(),
            "Decoded Preimage input is not 32 bytes".to_string()
        );
    }

    #[macros::test_all]
    fn test_preimage_from_sha256_str() {
        let preimage = Preimage::random();
        let compare = Preimage::from_sha256_str(preimage.sha256.to_string().as_str()).unwrap();

        assert_eq!(compare.bytes, None);
        assert_eq!(compare.sha256, preimage.sha256);
        assert_eq!(compare.hash160, preimage.hash160);
    }

    #[macros::test_all]
    fn test_preimage_from_sha256_vec() {
        let preimage = Preimage::random();
        let compare = Preimage::from_sha256_vec(preimage.sha256.serialize()).unwrap();

        assert_eq!(compare.bytes, None);
        assert_eq!(compare.sha256, preimage.sha256);
        assert_eq!(compare.hash160, preimage.hash160);
    }

    #[macros::test_all]
    fn test_swap_master_key() -> Result<(), Error> {
        let wallet_mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let wallet_passphrase = None;
        let network = Network::Mainnet;

        let swap_master_key = SwapMasterKey::new(wallet_mnemonic, wallet_passphrase, network)?;

        assert_eq!(
            swap_master_key.mnemonic.to_string(),
            "velvet engage shaft effort clarify annual protect client only surround sock gain"
                .to_string(),
            "BIP85 extended method should produce the same mnemonic as raw derivation"
        );

        assert_eq!(
            swap_master_key.xprv.to_string(),
            "xprv9z1rybmkZ6Bx45RJ4wGsXWuMtrrKpvyMgny9ZPcoWWgXs2XWotuaqYaiLJuM8DEtj62DZ2wHpo4t2HsRtKfBf3mGf2LwK5xZix5LuvKNU7x",
            "xpriv should match expected value"
        );

        let master_xpub = swap_master_key.get_master_xpub();
        assert_eq!(
            master_xpub.to_string(),
            "xpub6D1DP7JePTkFGZVmAxoster6StgpEPhD41tkMn2R4rDWjprfMSDqPLuCBb4JjF9XCAhtosDaxBqxUnbx49796i4fqsARfWFqMuHffxyuQRT",
            "xpub should match expected value"
        );

        let swap_key_at_index_0 = swap_master_key.derive_swapkey(0)?;

        let xprv_str = "xprvA1o5FLJ3sGydPdLFruGAx4HdgftKNZAjNCrzinqfXavcSBToLsgmNYjyXG8hbygMQSnKMsVt7kqHoZ4DZRXgpCxUN2JZLGU67FRgXXJWhNK";
        let swap_xprv = Xpriv::from_str(xprv_str)?;
        let secp = Secp256k1::new();

        let keypair_from_xprv = Keypair::from_secret_key(&secp, &swap_xprv.private_key);

        assert_eq!(
            swap_key_at_index_0.public_key(),
            keypair_from_xprv.public_key(),
            "Swap key at index 0 should match KeyPair derived from xprv"
        );
        assert_eq!(
            swap_key_at_index_0.secret_key(),
            keypair_from_xprv.secret_key(),
            "Swap key secret at index 0 should match KeyPair secret derived from xprv"
        );
        println!(
            "Private key: {}",
            swap_key_at_index_0.secret_key().display_secret()
        );
        let preimage = Preimage::from_swap_key(&swap_key_at_index_0);
        assert_eq!(
            preimage.bytes.unwrap().to_lower_hex_string(),
            "92cde8be384328b97307492898383470dc4a967398bf45326b38e507752f844d".to_string(),
        );

        Ok(())
    }
}
