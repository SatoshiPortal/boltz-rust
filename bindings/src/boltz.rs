use bitcoin::hashes::serde::{Deserialize, Serialize};
use bitcoin::key::PublicKey;
use boltz_client::boltz::{self, BoltzWsConfig};
use boltz_client::boltz::{
    ChannelInfo, FailureReasonIncorrectAmounts, SubSwapStates, SwapStatus, TransactionInfo,
};
use boltz_client::error::Error as CoreError;
use boltz_client::swaps::boltz::{CreateSubmarineResponse, Leaf, SwapTree};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use uniffi;
use uniffi::{custom_type, FfiConverter, MetadataBuffer, Record};

#[derive(Debug, Error, uniffi::Enum)]
pub enum Error {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("API error: {0}")]
    ApiError(String),

    #[error("{0}")]
    Generic(String),
}

impl From<CoreError> for Error {
    fn from(err: CoreError) -> Self {
        Error::Generic(err.message())
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

    #[uniffi::method]
    pub async fn post_swap_req(
        &self,
        swap_request: CreateSubmarineRequest,
    ) -> Result<CreateSubmarineResponse, Error> {
        self.inner
            .post_swap_req(&swap_request.into())
            .await
            .map_err(|e| e.into())
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
    pub funding_transaction_id: String,
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
}

#[derive(Debug, uniffi::Object)]
pub struct BoltzWsUpdates(tokio::sync::Mutex<tokio::sync::broadcast::Receiver<SwapStatus>>);

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
        Self(Arc::new(boltz::BoltzWsApi::new(ws_url, BoltzWsConfig::default())))
    }

    #[uniffi::method]
    pub async fn run_ws_loop(&self) {
        self.0.clone().run_ws_loop().await;
    }

    #[uniffi::method]
    pub fn updates(&self) -> BoltzWsUpdates {
        BoltzWsUpdates(tokio::sync::Mutex::new(self.0.updates()))
    }

    #[uniffi::method]
    pub async fn subscribe(&self, swap_id: &str) -> Result<(), Error> {
        self.0.subscribe(swap_id).await.map_err(|e| e.into())
    }
}

pub const BOLTZ_TESTNET_URL_V2: &str = "https://api.testnet.boltz.exchange/v2";

pub const BOLTZ_MAINNET_URL_V2: &str = "https://api.boltz.exchange/v2";

pub const BOLTZ_REGTEST: &str = "http://localhost:9001/v2";

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
    pub from: String,
    pub to: String,
    pub invoice: String,
    pub refund_public_key: PublicKey,
    pub pair_hash: Option<String>,
    pub referral_id: Option<String>,
}

impl From<CreateSubmarineRequest> for boltz::CreateSubmarineRequest {
    fn from(val: CreateSubmarineRequest) -> boltz::CreateSubmarineRequest {
        boltz::CreateSubmarineRequest {
            from: val.from.clone(),
            to: val.to.clone(),
            invoice: val.invoice.clone(),
            refund_public_key: val.refund_public_key,
            pair_hash: val.pair_hash.clone(),
            referral_id: val.referral_id.clone(),
            webhook: None,
        }
    }
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
