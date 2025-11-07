use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv, Xpub};
use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::key::rand::{rngs::OsRng, RngCore};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use elements::secp256k1_zkp::{Keypair as ZKKeyPair, Secp256k1 as ZKSecp256k1};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::network::{BitcoinChain, Chain, LiquidChain};

const SUBMARINE_SWAP_ACCOUNT: u32 = 21;
const REVERSE_SWAP_ACCOUNT: u32 = 42;
const CHAIN_SWAP_ACCOUNT: u32 = 84;

fn chain_to_bitcoin_network(chain: Chain) -> bitcoin::Network {
    match chain {
        Chain::Bitcoin(bitcoin_chain) => bitcoin_chain.into(),
        Chain::Liquid(liquid_chain) => match liquid_chain {
            LiquidChain::Liquid => bitcoin::Network::Bitcoin,
            LiquidChain::LiquidTestnet => bitcoin::Network::Testnet,
            LiquidChain::LiquidRegtest => bitcoin::Network::Regtest,
        },
    }
}

fn get_network_path(network: Chain) -> u32 {
    match network {
        Chain::Bitcoin(BitcoinChain::Bitcoin) | Chain::Liquid(LiquidChain::Liquid) => 0,
        _ => 1,
    }
}

fn derive_root_xpriv(
    mnemonic: &str,
    passphrase: &str,
    network: Chain,
) -> Result<(Secp256k1<bitcoin::secp256k1::All>, Xpriv), Error> {
    let secp = Secp256k1::new();
    let mnemonic_struct = Mnemonic::from_str(mnemonic)?;
    let seed = mnemonic_struct.to_seed(passphrase);
    let root = Xpriv::new_master(chain_to_bitcoin_network(network), &seed)?;
    Ok((secp, root))
}

fn build_base_path(purpose: DerivationPurpose, network_path: u32, account: u32) -> String {
    format!("m/{purpose}h/{network_path}h/{account}h/0")
}

/// Swap key xpriv for reverse, submarine, and chain swaps
/// Can be stored and used more easily to get SwapKeys for each swap rather than constantly passing the mnemonic and passphrase
/// Can also be used to get the root xpubs that can be used with the swap/restore api
#[derive(Clone)]
pub struct SwapXKeys {
    pub reverse: Xpriv,
    pub submarine: Xpriv,
    pub chain: Xpriv,
    pub fingerprint: Fingerprint,
    pub network: Chain,
}

impl SwapXKeys {
    pub fn derive(mnemonic: &str, passphrase: &str, network: Chain) -> Result<SwapXKeys, Error> {
        let (secp, root) = derive_root_xpriv(mnemonic, passphrase, network)?;
        let fingerprint = root.fingerprint(&secp);
        let network_path = get_network_path(network);

        let submarine_path = build_base_path(
            DerivationPurpose::Compatible,
            network_path,
            SUBMARINE_SWAP_ACCOUNT,
        );
        let submarine_xpriv =
            root.derive_priv(&secp, &DerivationPath::from_str(&submarine_path)?)?;

        let reverse_path = build_base_path(
            DerivationPurpose::Native,
            network_path,
            REVERSE_SWAP_ACCOUNT,
        );
        let reverse_xpriv = root.derive_priv(&secp, &DerivationPath::from_str(&reverse_path)?)?;

        let chain_path =
            build_base_path(DerivationPurpose::Taproot, network_path, CHAIN_SWAP_ACCOUNT);
        let chain_xpriv = root.derive_priv(&secp, &DerivationPath::from_str(&chain_path)?)?;

        Ok(SwapXKeys {
            reverse: reverse_xpriv,
            submarine: submarine_xpriv,
            chain: chain_xpriv,
            fingerprint,
            network,
        })
    }

    pub fn derive_submarine_key(&self, index: u64) -> Result<SwapKey, Error> {
        let network_path = get_network_path(self.network);
        let base_path = build_base_path(
            DerivationPurpose::Compatible,
            network_path,
            SUBMARINE_SWAP_ACCOUNT,
        );
        let full_path = DerivationPath::from_str(&format!("{base_path}/{index}"))?;
        let mut swap_key = SwapKey::from_priv_key(
            &self.submarine,
            DerivationPath::from_str(&format!("m/{index}"))?,
        )?;
        swap_key.path = full_path;
        swap_key.fingerprint = self.fingerprint;
        Ok(swap_key)
    }

    pub fn derive_reverse_key(&self, index: u64) -> Result<SwapKey, Error> {
        let network_path = get_network_path(self.network);
        let base_path = build_base_path(
            DerivationPurpose::Native,
            network_path,
            REVERSE_SWAP_ACCOUNT,
        );
        let full_path = DerivationPath::from_str(&format!("{base_path}/{index}"))?;
        let mut swap_key = SwapKey::from_priv_key(
            &self.reverse,
            DerivationPath::from_str(&format!("m/{index}"))?,
        )?;
        swap_key.path = full_path;
        swap_key.fingerprint = self.fingerprint;
        Ok(swap_key)
    }

    pub fn derive_chain_key(&self, index: u64) -> Result<SwapKey, Error> {
        let network_path = get_network_path(self.network);
        let base_path =
            build_base_path(DerivationPurpose::Taproot, network_path, CHAIN_SWAP_ACCOUNT);
        let full_path = DerivationPath::from_str(&format!("{base_path}/{index}"))?;
        let mut swap_key = SwapKey::from_priv_key(
            &self.chain,
            DerivationPath::from_str(&format!("m/{index}"))?,
        )?;
        swap_key.path = full_path;
        swap_key.fingerprint = self.fingerprint;
        Ok(swap_key)
    }

    pub fn get_reverse_xpub(&self) -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &self.reverse)
    }

    pub fn get_submarine_xpub(&self) -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &self.submarine)
    }

    pub fn get_chain_xpub(&self) -> Xpub {
        let secp = Secp256k1::new();
        Xpub::from_priv(&secp, &self.chain)
    }
}

/// Derived Keypair for use in a script.
/// Can be used directly with Bitcoin structures
/// Can be converted .into() LiquidSwapKey
/// Recommended to use SwapXKeys to derive SwapKeys for each swap rather than this struct and its methods directly
#[derive(Serialize, Deserialize, Clone)]
pub struct SwapKey {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub keypair: Keypair,
}
impl SwapKey {
    pub fn from_priv_key(root_xpriv: &Xpriv, path: DerivationPath) -> Result<SwapKey, Error> {
        let secp = Secp256k1::new();
        let fingerprint = root_xpriv.fingerprint(&secp);
        let child_xprv = root_xpriv.derive_priv(&secp, &path)?;
        let key_pair = Keypair::from_secret_key(&secp, &child_xprv.private_key);

        Ok(SwapKey {
            path,
            fingerprint,
            keypair: key_pair,
        })
    }

    fn from_mnemonic(
        mnemonic: &str,
        passphrase: &str,
        network: Chain,
        path: DerivationPath,
    ) -> Result<SwapKey, Error> {
        let (secp, root) = derive_root_xpriv(mnemonic, passphrase, network)?;
        let fingerprint = root.fingerprint(&secp);
        let child_xprv = root.derive_priv(&secp, &path)?;
        let key_pair = Keypair::from_secret_key(&secp, &child_xprv.private_key);

        Ok(SwapKey {
            path,
            fingerprint,
            keypair: key_pair,
        })
    }

    /// Derives keys for a submarine swap at standardized path
    /// m/49'/<0;1>'/21'/0/*
    pub fn from_submarine_account(
        mnemonic: &str,
        passphrase: &str,
        network: Chain,
        index: u64,
    ) -> Result<SwapKey, Error> {
        Self::from_mnemonic(
            mnemonic,
            passphrase,
            network,
            DerivationPath::from_str(&format!(
                "{}/{index}",
                build_base_path(
                    DerivationPurpose::Compatible,
                    get_network_path(network.clone()),
                    SUBMARINE_SWAP_ACCOUNT,
                )
            ))?,
        )
    }
    /// Derives keys for a reverse swap at standardized path
    /// m/84'/<0;1>'/42'/0/*
    pub fn from_reverse_account(
        mnemonic: &str,
        passphrase: &str,
        network: Chain,
        index: u64,
    ) -> Result<SwapKey, Error> {
        Self::from_mnemonic(
            mnemonic,
            passphrase,
            network,
            DerivationPath::from_str(&format!(
                "{}/{index}",
                build_base_path(
                    DerivationPurpose::Native,
                    get_network_path(network.clone()),
                    REVERSE_SWAP_ACCOUNT,
                )
            ))?,
        )
    }
    /// Derives keys for a chain swap at standardized path
    /// m/86'/<0;1>'/84'/0/*
    pub fn from_chain_account(
        mnemonic: &str,
        passphrase: &str,
        network: Chain,
        index: u64,
    ) -> Result<SwapKey, Error> {
        Self::from_mnemonic(
            mnemonic,
            passphrase,
            network,
            DerivationPath::from_str(&format!(
                "{}/{index}",
                build_base_path(
                    DerivationPurpose::Taproot,
                    get_network_path(network.clone()),
                    CHAIN_SWAP_ACCOUNT,
                )
            ))?,
        )
    }
}
#[derive(Clone)]

/// For Liquid keys, first create a SwapKey and then call .into() to get the equivalent ZKKeypair
/// let sk = SwapKey::from_reverse_account(&mnemonic.to_string(), "", Chain::LiquidTestnet, 1)?
/// let lsk: LiquidSwapKey = swap_key.try_into()?;
/// let zkkp = lsk.keypair;
#[derive(Serialize, Deserialize, Debug)]
pub struct LiquidSwapKey {
    pub fingerprint: Fingerprint,
    pub path: DerivationPath,
    pub keypair: ZKKeyPair,
}
impl TryFrom<SwapKey> for LiquidSwapKey {
    type Error = Error;
    fn try_from(swapkey: SwapKey) -> Result<Self, Self::Error> {
        let secp = ZKSecp256k1::new();
        let liquid_keypair =
            ZKKeyPair::from_seckey_str(&secp, &swapkey.keypair.display_secret().to_string())?;

        Ok(LiquidSwapKey {
            fingerprint: swapkey.fingerprint,
            path: swapkey.path,
            keypair: liquid_keypair,
        })
    }
}
enum DerivationPurpose {
    Compatible,
    Native,
    Taproot,
}
impl Display for DerivationPurpose {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            DerivationPurpose::Compatible => write!(f, "49"),
            DerivationPurpose::Native => write!(f, "84"),
            DerivationPurpose::Taproot => write!(f, "86"),
        }
    }
}

/// Internally used rng to generate secure 32 byte preimages
pub(crate) fn rng_32b() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Helper to work with Preimage & Hashes required for swap scripts.
#[derive(Debug, Clone, PartialEq)]
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
        Preimage::new()
    }
}

impl Preimage {
    /// Creates a new random preimage
    /// RECOMMENDED NOT TO USE THIS FUNCTION
    /// USE FROM_SWAP_KEY INSTEAD
    pub fn new() -> Preimage {
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

    /// Creates a Preimage from a SwapKey's private key hash
    /// sha256(privateKey(index))
    /// RECOMMENDED TO ENSURE SWAPS CAN BE RESTORED MORE EASILY
    pub fn from_swap_key(swap_key: &SwapKey) -> Preimage {
        let private_key_bytes = swap_key.keypair.secret_key().secret_bytes();
        let preimage_bytes = sha256::Hash::hash(&private_key_bytes);
        let preimage_array: [u8; 32] = *preimage_bytes.as_byte_array();
        let hash160 = hash160::Hash::hash(&preimage_array);

        Preimage {
            bytes: Some(preimage_array),
            sha256: preimage_bytes,
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
        let sk = SwapKey::from_submarine_account(
            mnemonic,
            "",
            Chain::Bitcoin(BitcoinChain::Bitcoin),
            index,
        )
        .unwrap();
        let lsk: LiquidSwapKey = match LiquidSwapKey::try_from(sk.clone()) {
            Ok(t) => t,
            Err(e) => {
                // Conversion failed, handle the error
                return println!("Error converting to LiquidSwapKey: {e:?}");
            }
        };
        assert_eq!(sk.fingerprint, lsk.fingerprint);
        // println!("{:?}", derived.unwrap().Keypair.display_secret());
        assert_eq!(&sk.fingerprint.to_string().clone(), "9a6a2580");
        assert_eq!(
            &sk.keypair.display_secret().to_string(),
            "d8d26ab9ba4e2c44f1a1fb9e10dc9d78707aaaaf38b5d42cf5c8bf00306acd85"
        );
    }

    #[macros::test_all]
    fn test_preimage_from_str() {
        let preimage = Preimage::new();
        assert_eq!(
            Preimage::from_str(&hex::encode(preimage.bytes.unwrap()).to_string()).unwrap(),
            preimage
        );
    }

    #[macros::test_all]
    fn test_preimage_from_vec() {
        let preimage = Preimage::new();
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
        let preimage = Preimage::new();
        let compare = Preimage::from_sha256_str(preimage.sha256.to_string().as_str()).unwrap();

        assert_eq!(compare.bytes, None);
        assert_eq!(compare.sha256, preimage.sha256);
        assert_eq!(compare.hash160, preimage.hash160);
    }

    #[macros::test_all]
    fn test_preimage_from_sha256_vec() {
        let preimage = Preimage::new();
        let compare = Preimage::from_sha256_vec(preimage.sha256.serialize()).unwrap();

        assert_eq!(compare.bytes, None);
        assert_eq!(compare.sha256, preimage.sha256);
        assert_eq!(compare.hash160, preimage.hash160);
    }

    #[macros::test_all]
    fn test_derive_swap_key_from_xpub() -> Result<(), Error> {
        let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let network = Chain::Bitcoin(BitcoinChain::Bitcoin);
        let index = 1;

        let chain_swap_key = SwapKey::from_chain_account(mnemonic, "", network, index)?;
        let reverse_swap_key = SwapKey::from_reverse_account(mnemonic, "", network, index)?;
        let submarine_swap_key = SwapKey::from_submarine_account(mnemonic, "", network, index)?;

        let root_xprivs = SwapXKeys::derive(mnemonic, "", network)?;

        let secp = Secp256k1::new();
        let child_path = DerivationPath::from_str("m/1")?;

        let chain_xpub = root_xprivs.get_chain_xpub();
        let chain_derived_xpub = chain_xpub.derive_pub(&secp, &child_path)?;
        assert_eq!(
            chain_swap_key.keypair.public_key(),
            chain_derived_xpub.public_key
        );

        let reverse_xpub = root_xprivs.get_reverse_xpub();
        let reverse_derived_xpub = reverse_xpub.derive_pub(&secp, &child_path)?;
        assert_eq!(
            reverse_swap_key.keypair.public_key(),
            reverse_derived_xpub.public_key
        );

        let submarine_xpub = root_xprivs.get_submarine_xpub();
        let submarine_derived_xpub = submarine_xpub.derive_pub(&secp, &child_path)?;
        assert_eq!(
            submarine_swap_key.keypair.public_key(),
            submarine_derived_xpub.public_key
        );

        Ok(())
    }

    #[macros::test_all]
    fn test_swap_xkeys_backward_compatibility() -> Result<(), Error> {
        let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let passphrase = "";
        let network = Chain::Bitcoin(BitcoinChain::Bitcoin);
        let indices = vec![0, 1, 5, 10, 100];

        let swap_xkeys = SwapXKeys::derive(mnemonic, passphrase, network)?;

        for index in indices {
            let chain_key_old = SwapKey::from_chain_account(mnemonic, passphrase, network, index)?;
            let chain_key_new = swap_xkeys.derive_chain_key(index)?;
            assert_eq!(chain_key_old.path, chain_key_new.path);
            assert_eq!(chain_key_old.fingerprint, chain_key_new.fingerprint);
            assert_eq!(
                chain_key_old.keypair.public_key(),
                chain_key_new.keypair.public_key()
            );
            assert_eq!(
                chain_key_old.keypair.secret_key(),
                chain_key_new.keypair.secret_key()
            );

            let reverse_key_old =
                SwapKey::from_reverse_account(mnemonic, passphrase, network, index)?;
            let reverse_key_new = swap_xkeys.derive_reverse_key(index)?;
            assert_eq!(reverse_key_old.path, reverse_key_new.path);
            assert_eq!(reverse_key_old.fingerprint, reverse_key_new.fingerprint);
            assert_eq!(
                reverse_key_old.keypair.public_key(),
                reverse_key_new.keypair.public_key()
            );
            assert_eq!(
                reverse_key_old.keypair.secret_key(),
                reverse_key_new.keypair.secret_key()
            );

            let submarine_key_old =
                SwapKey::from_submarine_account(mnemonic, passphrase, network, index)?;
            let submarine_key_new = swap_xkeys.derive_submarine_key(index)?;
            assert_eq!(submarine_key_old.path, submarine_key_new.path);
            assert_eq!(submarine_key_old.fingerprint, submarine_key_new.fingerprint);
            assert_eq!(
                submarine_key_old.keypair.public_key(),
                submarine_key_new.keypair.public_key()
            );
            assert_eq!(
                submarine_key_old.keypair.secret_key(),
                submarine_key_new.keypair.secret_key()
            );
        }

        Ok(())
    }
}
