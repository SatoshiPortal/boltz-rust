use crate::boltz::Error;
use crate::boltz::{BoltzApiClientV2, CreateSubmarineRequest};
use crate::network::Client;
use bitcoin::hex::DisplayHex;
use bitcoin::key::{rand, Keypair, PublicKey};
use bitcoin::secp256k1::SecretKey;
use bitcoin::{Address, OutPoint, TxOut};
use boltz_client::boltz::{CreateSubmarineResponse, SwapTxKind};
use boltz_client::fees::Fee;
use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::{self as swaps_bitcoin, TransactionOptions};
use boltz_client::util::secrets::Preimage;
use elements::secp256k1_zkp::{MusigPartialSignature, MusigPubNonce};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, uniffi::Object)]
pub struct SwapScript(swaps_bitcoin::SwapScript);

#[uniffi::export]
impl SwapScript {
    #[uniffi::constructor]
    pub fn submarine_from_swap_resp(
        chain: Chain,
        create_swap_response: &CreateSubmarineResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let script = swaps_bitcoin::SwapScript::submarine_from_swap_resp(
            chain,
            create_swap_response,
            our_pubkey,
        )?;
        Ok(Self(script))
    }
}

#[derive(uniffi::Object)]
pub struct SwapTx(swaps_bitcoin::SwapTx);

#[derive(uniffi::Object)]
pub struct Cooperative {
    boltz_api: Arc<BoltzApiClientV2>,
    swap_id: String,
    /// The pub_nonce is needed to post the claim tx details of the Chain swap
    pub_nonce: Option<MusigPubNonce>,
    /// The partial_sig is needed to post the claim tx details of the Chain swap
    partial_sig: Option<MusigPartialSignature>,
}

#[uniffi::remote(Record)]
pub struct TransactionOptions {
    /// Whether to use discount confidential transactions for Liquid swaps
    pub is_discount_ct: bool,
}

#[uniffi::remote(Enum)]
pub enum Fee {
    // In sat/vByte
    Relative(f64),
    // In satoshis
    Absolute(u64),
}

#[uniffi::export(async_runtime = "tokio")]
impl SwapTx {
    #[uniffi::constructor]
    pub async fn new_claim(
        swap_script: &SwapScript,
        output_address: String,
        client: &Client,
        boltz_client: &BoltzApiClientV2,
        swap_id: String,
    ) -> Result<Self, Error> {
        let tx = swaps_bitcoin::SwapTx::new_claim(
            swap_script.0.clone(),
            output_address,
            &client.0,
            &boltz_client.inner,
            swap_id,
        )
        .await?;
        Ok(Self(tx))
    }

    #[uniffi::method]
    pub async fn sign_claim(
        &self,
        keys: &KeyPair,
        preimage: &Preimage,
        fee: Fee,
        coop: Option<Arc<Cooperative>>,
        options: Option<TransactionOptions>,
    ) -> Result<BtcLikeTransaction, Error> {
        if let Some(coop) = coop {
            let c = Some(swaps_bitcoin::boltz::Cooperative {
                boltz_api: &coop.boltz_api.inner,
                swap_id: coop.swap_id.clone(),
                pub_nonce: coop.pub_nonce,
                partial_sig: coop.partial_sig,
            });
            let tx = self
                .0
                .sign_claim(&keys.inner, preimage, fee, c, options)
                .await?;
            return Ok(BtcLikeTransaction(tx));
        } else {
            let tx = self
                .0
                .sign_claim(&keys.inner, preimage, fee, None, options)
                .await?;
            return Ok(BtcLikeTransaction(tx));
        }
    }
}

#[derive(uniffi::Object)]
pub struct BtcLikeTransaction(pub(crate) swaps_bitcoin::BtcLikeTransaction);

/// A structure representing either a Claim or a Refund Tx.
/// This Tx spends from the HTLC.
/*
#[derive(Debug, Clone)]
pub struct BtcSwapTx {
    pub kind: SwapTxKind, // These fields needs to be public to do manual creation in IT.
    pub swap_script: boltz_client::BtcSwapScript,
    pub output_address: Address,
    /// All utxos for the script_pubkey of this swap, at this point in time:
    /// - the initial lockup utxo, if not yet spent (claimed or refunded)
    /// - any further utxos, if not yet spent
    pub utxos: Vec<(OutPoint, TxOut)>,
}

impl BtcSwapTx {
    /// Craft a new ClaimTx. Only works for Reverse and Chain Swaps.
    /// Returns None, if the HTLC utxo doesn't exist for the swap.
    pub async fn new_claim<BC: BitcoinClient>(
        swap_script: boltz_client::BtcSwapScript,
        claim_address: String,
        bitcoin_client: &BC,
        boltz_url: String,
        swap_id: String,
    ) -> Result<boltz_client::BtcSwapTx, Error> {
    }
}
*/

#[derive(uniffi::Object)]
pub struct KeyPair {
    inner: Keypair,
}

#[uniffi::export]
impl KeyPair {
    #[uniffi::constructor]
    pub fn new() -> Self {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let key = Keypair::new(&secp, &mut rand::thread_rng());
        KeyPair { inner: key }
    }

    #[uniffi::constructor]
    pub fn from_secret_key(secret: SecretKey) -> Self {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        KeyPair {
            inner: Keypair::from_secret_key(&secp, &secret),
        }
    }

    #[uniffi::method]
    pub fn secret(&self) -> SecretKey {
        self.inner.secret_key()
    }

    #[uniffi::method]
    pub fn public(&self) -> PublicKey {
        self.inner.public_key().into()
    }
}

uniffi::custom_type!(PublicKey, String, {
    remote,
    try_lift: |val| match PublicKey::from_str(val.as_str()) {
        Ok(key) => Ok(key),
        Err(e) => Err(e.into())
    },
    lower: |val| val.to_string(),
});
uniffi::custom_type!(SecretKey, String, {
    remote,
    try_lift: |val| match SecretKey::from_str(val.as_str()) {
        Ok(key) => Ok(key),
        Err(e) => Err(e.into())
    },
    lower: |val| val.secret_bytes().to_upper_hex_string(),
});

uniffi::custom_type!(Preimage, String, {
    remote,
    try_lift: |val| match Preimage::from_str(val.as_str()) {
        Ok(key) => Ok(key),
        Err(e) => Err(uniffi::deps::anyhow::Error::msg(e.message()))
    },
    lower: |val| val.to_string().unwrap_or_default(),
});
