use bitcoin::hashes::sha256;
use bitcoin::key::PublicKey;
use boltz_client::boltz::{
    self, BoltzWsConfig, ChainSwapDetails, CreateChainResponse, CreateReverseResponse, Side,
};
use boltz_client::boltz::{
    ChannelInfo, FailureReasonIncorrectAmounts, SubSwapStates, SwapStatus, TransactionInfo,
};
use boltz_client::error::Error as CoreError;
use boltz_client::network::{Chain, Network};
use boltz_client::swaps::boltz::*;
use boltz_client::util::secrets::Preimage;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::broadcast::Receiver;
use tokio::sync::Mutex;
use uniffi::Record;

#[derive(Debug, Error, uniffi::Enum)]
pub enum Error {
    #[error("HTTP error: {0}")]
    Http(String),

    #[error("{0}")]
    Generic(String),
}

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        match err {
            CoreError::HTTP(s) => Error::Http(s),
            _ => Error::Generic(err.message()),
        }
    }
}

#[derive(Debug, uniffi::Object)]
pub struct BoltzApiClientV2 {
    pub(crate) inner: boltz::BoltzApiClientV2,
}

#[uniffi::remote(Record)]
pub struct BoltzWsConfig {
    pub keep_alive_interval: Duration,
    pub reconnect_delay: Duration,
    pub subscription_timeout: Duration,
    pub protocols: Option<Vec<String>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl BoltzApiClientV2 {
    #[uniffi::constructor]
    pub fn new(base_url: &str, timeout: Option<u64>) -> Self {
        Self {
            inner: boltz::BoltzApiClientV2::new(
                base_url.to_string(),
                timeout.map(Duration::from_secs),
            ),
        }
    }

    #[uniffi::constructor]
    pub fn default(network: Network) -> Self {
        Self {
            inner: boltz::BoltzApiClientV2::default(network),
        }
    }

    #[uniffi::method]
    pub async fn create_swap(
        &self,
        swap_request: CreateSubmarineRequest,
    ) -> Result<CreateSubmarineResponse, Error> {
        let response = self
            .inner
            .post_swap_req(&boltz::CreateSubmarineRequest {
                from: swap_request.from.to_string(),
                to: swap_request.to.to_string(),
                invoice: swap_request.invoice.clone(),
                refund_public_key: swap_request.refund_public_key,
                pair_hash: swap_request.pair_hash.clone(),
                referral_id: swap_request.referral_id.clone(),
                webhook: None,
            })
            .await?;
        response.validate(
            &swap_request.invoice,
            &swap_request.refund_public_key,
            swap_request.from,
        )?;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn create_reverse_swap(
        &self,
        swap_request: CreateReverseRequest,
    ) -> Result<CreateReverseResponse, Error> {
        let response = self
            .inner
            .post_reverse_req(boltz::CreateReverseRequest {
                invoice_amount: Some(swap_request.invoice_amount),
                invoice: None,
                from: swap_request.from.to_string(),
                to: swap_request.to.to_string(),
                preimage_hash: Some(
                    swap_request
                        .preimage_hash
                        .parse::<sha256::Hash>()
                        .map_err(|e| Error::Generic(e.to_string()))?,
                ),
                claim_public_key: swap_request.claim_public_key,
                description: swap_request.description,
                description_hash: swap_request.description_hash,
                address: swap_request.address,
                address_signature: swap_request.address_signature,
                referral_id: swap_request.referral_id,
                webhook: None,
            })
            .await?;
        response.validate(
            &Preimage::from_sha256_str(&swap_request.preimage_hash)?,
            &swap_request.claim_public_key,
            swap_request.to,
        )?;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn create_chain_swap(
        &self,
        swap_request: CreateChainRequest,
    ) -> Result<CreateChainResponse, Error> {
        let response = self
            .inner
            .post_chain_req(boltz::CreateChainRequest {
                from: swap_request.from.to_string(),
                to: swap_request.to.to_string(),
                preimage_hash: swap_request
                    .preimage_hash
                    .parse::<sha256::Hash>()
                    .map_err(|e| Error::Generic(e.to_string()))?,
                claim_public_key: Some(swap_request.claim_public_key),
                refund_public_key: Some(swap_request.refund_public_key),
                user_lock_amount: swap_request.user_lock_amount,
                server_lock_amount: swap_request.server_lock_amount,
                pair_hash: swap_request.pair_hash,
                referral_id: swap_request.referral_id,
                webhook: None,
            })
            .await?;
        response.validate(
            &swap_request.claim_public_key,
            &swap_request.refund_public_key,
            swap_request.from,
            swap_request.to,
        )?;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn get_submarine_pairs(&self) -> Result<GetSubmarinePairsResponse, Error> {
        let response = self.inner.get_submarine_pairs().await?;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn get_reverse_pairs(&self) -> Result<GetReversePairsResponse, Error> {
        let response = self.inner.get_reverse_pairs().await?;
        Ok(response)
    }

    #[uniffi::method]
    pub async fn get_chain_pairs(&self) -> Result<GetChainPairsResponse, Error> {
        let response = self.inner.get_chain_pairs().await?;
        Ok(response)
    }

    #[uniffi::method]
    pub fn ws(&self) -> BoltzWsApi {
        BoltzWsApi(Arc::new(self.inner.ws(BoltzWsConfig::default())))
    }
}

#[uniffi::remote(Record)]
pub struct TransactionInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta: Option<u64>,
}

#[uniffi::remote(Record)]
pub struct FailureReasonIncorrectAmounts {
    pub expected: u64,
    pub actual: u64,
}

#[uniffi::remote(Record)]
pub struct ChannelInfo {
    #[serde(rename = "fundingTransactionId")]
    pub funding_transaction_id: String,
    #[serde(rename = "fundingTransactionVout")]
    pub funding_transaction_vout: u64,
}

#[uniffi::remote(Record)]
pub struct SwapStatus {
    pub id: String,
    pub status: String,
    pub zero_conf_rejected: Option<bool>,
    pub transaction: Option<boltz_client::boltz::TransactionInfo>,
    pub failure_reason: Option<String>,
    pub failure_details: Option<boltz_client::boltz::FailureReasonIncorrectAmounts>,
    pub channel_info: Option<ChannelInfo>,
}

#[derive(Debug, uniffi::Object)]
pub struct BoltzWsUpdates(Mutex<Receiver<SwapStatus>>);

#[uniffi::export(async_runtime = "tokio")]
impl BoltzWsUpdates {
    #[uniffi::method]
    pub async fn next(self: Arc<Self>) -> Result<SwapStatus, Error> {
        let mut receiver = self.0.lock().await;
        receiver
            .recv()
            .await
            .map_err(|e| Error::Generic(e.to_string()))
    }
}

#[derive(uniffi::Object)]
pub struct BoltzWsApi(Arc<boltz::BoltzWsApi>);

#[uniffi::export(async_runtime = "tokio")]
impl BoltzWsApi {
    #[uniffi::constructor]
    pub fn new(ws_url: String) -> Self {
        Self(Arc::new(boltz::BoltzWsApi::new(
            ws_url,
            BoltzWsConfig::default(),
        )))
    }

    #[uniffi::method]
    pub async fn run_ws_loop(&self) {
        self.0.clone().run_ws_loop().await;
    }

    #[uniffi::method]
    pub fn updates(&self) -> BoltzWsUpdates {
        BoltzWsUpdates(Mutex::new(self.0.updates()))
    }

    #[uniffi::method]
    pub async fn subscribe_swap(&self, swap_id: &str) -> Result<(), Error> {
        self.0.subscribe_swap(swap_id).await.map_err(|e| e.into())
    }
}

#[uniffi::remote(Enum)]
pub enum Side {
    Lockup,
    Claim,
}

#[uniffi::remote(Record)]
pub struct ChainSwapDetails {
    pub swap_tree: SwapTree,
    pub lockup_address: String,
    pub server_public_key: PublicKey,
    pub timeout_block_height: u32,
    pub amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blinding_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bip21: Option<String>,
}

#[uniffi::remote(Enum)]
pub enum SubSwapStates {
    Created,
    TransactionMempool,
    TransactionConfirmed,
    InvoiceSet,
    InvoicePaid,
    InvoicePending,
    InvoiceFailedToPay,
    TransactionClaimed,
    TransactionClaimPending,
    TransactionLockupFailed,
    SwapExpired,
}

#[derive(Debug, Record)]
pub struct CreateSubmarineRequest {
    pub from: Chain,
    pub to: Chain,
    pub invoice: String,
    pub refund_public_key: PublicKey,
    #[uniffi(default = None)]
    pub pair_hash: Option<String>,
    #[uniffi(default = None)]
    pub referral_id: Option<String>,
}

#[derive(Debug, Record)]
pub struct CreateReverseRequest {
    pub from: Chain,
    pub to: Chain,
    pub preimage_hash: String,
    pub claim_public_key: PublicKey,
    pub invoice_amount: u64,
    #[uniffi(default = None)]
    pub description: Option<String>,
    #[uniffi(default = None)]
    pub description_hash: Option<String>,
    #[uniffi(default = None)]
    pub address: Option<String>,
    #[uniffi(default = None)]
    pub address_signature: Option<String>,
    #[uniffi(default = None)]
    pub referral_id: Option<String>,
}

#[uniffi::remote(Record)]
pub struct Leaf {
    pub output: String,
    pub version: u8,
}

#[uniffi::remote(Record)]
pub struct SwapTree {
    pub claim_leaf: Leaf,
    pub refund_leaf: Leaf,
}

#[uniffi::remote(Record)]
pub struct CreateSubmarineResponse {
    pub accept_zero_conf: bool,
    pub address: String,
    pub bip21: String,
    pub claim_public_key: PublicKey,
    pub expected_amount: u64,
    pub id: String,
    pub referral_id: Option<String>,
    pub swap_tree: SwapTree,
    pub timeout_block_height: u64,
    pub blinding_key: Option<String>,
}

#[uniffi::remote(Record)]
pub struct CreateReverseResponse {
    pub id: String,
    pub invoice: Option<String>,
    pub swap_tree: SwapTree,
    pub lockup_address: String,
    pub refund_public_key: PublicKey,
    pub timeout_block_height: u32,
    pub onchain_amount: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blinding_key: Option<String>,
}

#[derive(Debug, Record)]
pub struct CreateChainRequest {
    pub from: Chain,
    pub to: Chain,
    pub preimage_hash: String,
    pub claim_public_key: PublicKey,
    pub refund_public_key: PublicKey,
    #[uniffi(default = None)]
    pub user_lock_amount: Option<u64>,
    #[uniffi(default = None)]
    pub server_lock_amount: Option<u64>,
    #[uniffi(default = None)]
    pub pair_hash: Option<String>,
    #[uniffi(default = None)]
    pub referral_id: Option<String>,
}

#[uniffi::remote(Record)]
pub struct CreateChainResponse {
    pub id: String,
    pub claim_details: ChainSwapDetails,
    pub lockup_details: ChainSwapDetails,
}

/// Various limits of swap parameters
#[uniffi::remote(Record)]
pub struct PairLimits {
    /// Maximum swap amount
    pub maximal: u64,
    /// Minimum swap amount
    pub minimal: u64,
    /// Maximum amount allowed for zero-conf
    pub maximal_zero_conf: u64,
}

#[uniffi::remote(Record)]
pub struct SubmarinePairLimits {
    /// Maximum swap amount
    pub maximal: u64,
    /// Minimum swap amount
    pub minimal: u64,
    /// Maximum amount allowed for zero-conf
    pub maximal_zero_conf: u64,
    /// Minimum batch swap amount
    pub minimal_batched: Option<u64>,
}

#[uniffi::remote(Record)]
pub struct ReverseLimits {
    /// Maximum swap amount
    pub maximal: u64,
    /// Minimum swap amount
    pub minimal: u64,
}

#[uniffi::remote(Record)]
pub struct PairMinerFees {
    pub lockup: u64,
    pub claim: u64,
}

#[uniffi::remote(Record)]
pub struct ChainMinerFees {
    pub server: u64,
    pub user: PairMinerFees,
}

#[uniffi::remote(Record)]
pub struct ChainFees {
    pub percentage: f64,
    pub miner_fees: ChainMinerFees,
}

#[uniffi::remote(Record)]
pub struct ReverseFees {
    pub percentage: f64,
    pub miner_fees: PairMinerFees,
}

#[uniffi::remote(Record)]
pub struct SubmarineFees {
    /// The percentage of the "send amount" that is charged by Boltz as "Boltz Fee".
    pub percentage: f64,
    /// The network fees charged for locking up and claiming funds onchain. These values are absolute, denominated in 10 ** -8 of the quote asset.
    pub miner_fees: u64,
}

#[uniffi::remote(Record)]
pub struct ChainPair {
    /// Pair hash, representing an id for an asset-pair swap
    pub hash: String,
    /// The exchange rate of the pair
    pub rate: f64,
    /// The swap limits
    pub limits: PairLimits,
    /// Total fees required for the swap
    pub fees: ChainFees,
}

#[uniffi::remote(Record)]
pub struct ReversePair {
    /// Pair hash, representing an id for an asset-pair swap
    pub hash: String,
    /// The exchange rate of the pair
    pub rate: f64,
    /// The swap limits
    pub limits: ReverseLimits,
    /// Total fees required for the swap
    pub fees: ReverseFees,
}

#[uniffi::remote(Record)]
pub struct SubmarinePair {
    /// Pair hash, representing an id for an asset-pair swap
    pub hash: String,
    /// The exchange rate of the pair
    pub rate: f64,
    /// The swap limits
    pub limits: SubmarinePairLimits,
    /// Total fees required for the swap
    pub fees: SubmarineFees,
}

#[uniffi::remote(Record)]
pub struct GetSubmarinePairsResponse {
    pub btc: HashMap<String, SubmarinePair>,
    pub lbtc: HashMap<String, SubmarinePair>,
}

#[uniffi::remote(Record)]
pub struct GetReversePairsResponse {
    pub btc: HashMap<String, ReversePair>,
}

#[uniffi::remote(Record)]
pub struct GetChainPairsResponse {
    pub btc: HashMap<String, ChainPair>,
    pub lbtc: HashMap<String, ChainPair>,
}
