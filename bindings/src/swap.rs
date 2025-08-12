use crate::boltz::BoltzApiClientV2;
use crate::boltz::Error;
use crate::network::ChainClient;
use crate::util::Preimage;
use bitcoin::hex::DisplayHex;
use bitcoin::key::{rand, Keypair, PublicKey};
use bitcoin::secp256k1::SecretKey;
use boltz_client::boltz::ChainSwapDetails;
use boltz_client::boltz::{CreateReverseResponse, CreateSubmarineResponse, Side};
use boltz_client::fees::Fee;
use boltz_client::network::Chain;
use boltz_client::swaps::{self as swaps_bitcoin};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, uniffi::Object)]
pub struct SwapScript(swaps_bitcoin::SwapScript);

#[derive(uniffi::Record)]
pub struct SwapTransactionParams {
    pub output_address: String,
    pub fee: Fee,
    pub swap_id: String,
    pub keys: Arc<KeyPair>,
    pub chain_client: Arc<ChainClient>,
    pub boltz_client: Arc<BoltzApiClientV2>,
    #[uniffi(default = None)]
    pub options: Option<TransactionOptions>,
}

impl<'a> From<&'a SwapTransactionParams> for swaps_bitcoin::SwapTransactionParams<'a> {
    fn from(params: &'a SwapTransactionParams) -> Self {
        swaps_bitcoin::SwapTransactionParams {
            keys: params.keys.inner,
            output_address: params.output_address.clone(),
            fee: params.fee,
            swap_id: params.swap_id.clone(),
            options: params.options.clone().map(|o| {
                let mut options =
                    swaps_bitcoin::TransactionOptions::default().with_cooperative(o.cooperative);
                if let Some(chain_claim) = o.chain_claim {
                    options = options.with_chain_claim(
                        chain_claim.keys.inner,
                        chain_claim.lockup_script.0.clone(),
                    );
                }
                options
            }),
            chain_client: &params.chain_client.0,
            boltz_client: &params.boltz_client.inner,
        }
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl SwapScript {
    #[uniffi::constructor]
    pub fn from_submarine(
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

    #[uniffi::constructor]
    pub fn from_reverse(
        chain: Chain,
        reverse_response: &CreateReverseResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let script =
            swaps_bitcoin::SwapScript::reverse_from_swap_resp(chain, reverse_response, our_pubkey)?;
        Ok(Self(script))
    }

    #[uniffi::constructor]
    pub fn from_chain(
        chain: Chain,
        side: Side,
        chain_swap_details: ChainSwapDetails,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let script = swaps_bitcoin::SwapScript::chain_from_swap_resp(
            chain,
            side,
            chain_swap_details,
            our_pubkey,
        )?;
        Ok(Self(script))
    }

    #[uniffi::method]
    pub async fn construct_claim(
        &self,
        preimage: &Preimage,
        params: &SwapTransactionParams,
    ) -> Result<BtcLikeTransaction, Error> {
        let tx = self.0.construct_claim(&preimage.0, params.into()).await?;
        Ok(BtcLikeTransaction(tx))
    }

    #[uniffi::method]
    pub async fn construct_refund(
        &self,
        params: &SwapTransactionParams,
    ) -> Result<BtcLikeTransaction, Error> {
        let tx = self.0.construct_refund(params.into()).await?;
        Ok(BtcLikeTransaction(tx))
    }

    #[uniffi::method]
    pub async fn submarine_cooperative_claim(
        &self,
        swap_id: &String,
        keys: &KeyPair,
        invoice: &str,
        boltz_api: &BoltzApiClientV2,
    ) -> Result<(), Error> {
        self.0
            .submarine_cooperative_claim(swap_id, &keys.inner, invoice, &boltz_api.inner)
            .await?;
        Ok(())
    }
}
#[derive(uniffi::Record, Clone)]
pub struct ChainClaim {
    pub keys: Arc<KeyPair>,
    pub lockup_script: Arc<SwapScript>,
}

#[derive(uniffi::Record, Clone)]
pub struct TransactionOptions {
    #[uniffi(default = true)]
    pub cooperative: bool,
    #[uniffi(default = None)]
    pub chain_claim: Option<ChainClaim>,
}

#[uniffi::remote(Enum)]
pub enum Fee {
    // In sat/vByte
    Relative(f64),
    // In satoshis
    Absolute(u64),
}

#[derive(uniffi::Object)]
pub struct BtcLikeTransaction(pub(crate) swaps_bitcoin::BtcLikeTransaction);

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

impl Default for KeyPair {
    fn default() -> Self {
        Self::new()
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
