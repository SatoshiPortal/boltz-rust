//!
//! ## Estimate fees
//!
//! ### Example
//! ```
//! let client = BoltzApiClient::new(BOLTZ_MAINNET_URL);
//! let pairs = client.get_pairs().unwrap();
//! let btc_pair = pairs.get_btc_pair();
//! let output_amount = 75_000;
//! let base_fees = btc_pair.fees.reverse_base(output_amount).unwrap();
//! let claim_fee = btc_pair.fees.reverse_claim_estimate();
//! println!("CALCULATED FEES: {}", base_fees);
//! println!("ONCHAIN LOCKUP: {}", output_amount - base_fees);
//! println!(
//!     "ONCHAIN RECIEVABLE: {}",
//!     output_amount - base_fees - claim_fee
//! );
//! let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
//! let claim_key_pair = SwapKey::from_reverse_account(mnemonic, "", Chain::Bitcoin, 0)
//!     .unwrap()
//!     .keypair;

//! let preimage = Preimage::new();
//! let request = CreateSwapRequest::new_btc_reverse_invoice_amt(
//!     btc_pair.hash,
//!     preimage.sha256.clone().to_string(),
//!     claim_key_pair.public_key().to_string(),
//!     output_amount,
//! );
//! let response = client.create_swap(request).unwrap();
//! assert!(response.validate_reverse(preimage, claim_key_pair, Chain::Bitcoin));
//! println!("Onchain Amount: {}", response.onchain_amount.unwrap());
//! assert!((output_amount - base_fees) == response.onchain_amount.unwrap());

//! ```
use crate::network::Chain;
use bitcoin::hashes::hash160;
use bitcoin::secp256k1::Keypair;
use elements::secp256k1_zkp::Keypair as ZKKeyPair;
use elements::secp256k1_zkp::Secp256k1 as ZKSecp256k1;
use lightning_invoice::Bolt11Invoice;
// use reqwest;
use crate::swaps::bitcoin::BtcSwapScript;
use crate::swaps::liquid::LBtcSwapScript;
use crate::util::error::{ErrorKind, S5Error};
use crate::util::secrets::Preimage;
use serde::Serializer;
use serde::{Deserialize, Serialize};
use serde_json;
use std::str::FromStr;
use ureq::Error;

pub const BOLTZ_TESTNET_URL: &str = "https://api.testnet.boltz.exchange";
pub const BOLTZ_MAINNET_URL: &str = "https://api.boltz.exchange";

#[derive(Debug, Clone)]
pub enum SwapTxKind {
    Claim,
    Refund,
}
/// Reference Documnetation: https://docs.boltz.exchange/v/api/
pub struct BoltzApiClient {
    base_url: String,
}

impl BoltzApiClient {
    pub fn new(base_url: &str) -> Self {
        BoltzApiClient {
            base_url: base_url.to_string(),
        }
    }
    /// In order to create a swap, one first has to know which pairs are supported and what kind of rates, limits and fees are applied when creating a new swap.
    /// The following call returns this information.
    pub fn get_pairs(&self) -> Result<GetPairsResponse, S5Error> {
        let url = format!("{}/getpairs", self.base_url);

        match ureq::get(&url).call() {
            Ok(res) => {
                let body = res.into_string().unwrap();
                let get_pairs_response: GetPairsResponse = serde_json::from_str(&body).unwrap();
                Ok(get_pairs_response)
            }
            Err(Error::Status(_code, res)) => Err(S5Error::new(
                ErrorKind::BoltzApi,
                &res.into_string().unwrap(),
            )),
            Err(_) => Err(S5Error::new(ErrorKind::BoltzApi, "Request failed")),
        }
    }

    pub fn get_fee_estimation(&self) -> Result<GetFeeEstimationResponse, S5Error> {
        let url = format!("{}/getfeeestimation", self.base_url);

        match ureq::get(&url).call() {
            Ok(res) => {
                let body = res.into_string().unwrap();
                let get_fee_estimation_response: GetFeeEstimationResponse =
                    serde_json::from_str(&body).unwrap();
                Ok(get_fee_estimation_response)
            }
            Err(Error::Status(_code, res)) => Err(S5Error::new(
                ErrorKind::BoltzApi,
                &res.into_string().unwrap(),
            )),
            Err(_) => Err(S5Error::new(ErrorKind::BoltzApi, "Request failed")),
        }
    }
    /// Create a swap. This method supports using either a Submarine or Reverse SwapRequest
    /// Check CreateSwapRequest to see how to construct each swap request.
    pub fn create_swap(&self, request: CreateSwapRequest) -> Result<CreateSwapResponse, S5Error> {
        let url = format!("{}/createswap", self.base_url);

        match ureq::post(&url).send_json(serde_json::to_value(request).unwrap()) {
            Ok(res) => {
                let body = res.into_string().unwrap();
                let create_swap_response: CreateSwapResponse = serde_json::from_str(&body).unwrap();
                Ok(create_swap_response)
            }
            Err(Error::Status(_code, res)) => Err(S5Error::new(
                ErrorKind::BoltzApi,
                &res.into_string().unwrap(),
            )),
            Err(_) => Err(S5Error::new(ErrorKind::BoltzApi, "Request failed")),
        }
    }
    /// Checks the status of an ongoing swap with boltz.
    pub fn swap_status(&self, request: SwapStatusRequest) -> Result<SwapStatusResponse, S5Error> {
        let url = format!("{}/swapstatus", self.base_url);
        match ureq::post(&url).send_json(serde_json::to_value(request).unwrap()) {
            Ok(res) => {
                let body = res.into_string().unwrap();
                let swap_status_response: SwapStatusResponse = serde_json::from_str(&body).unwrap();
                Ok(swap_status_response)
            }
            Err(Error::Status(_code, res)) => Err(S5Error::new(
                ErrorKind::BoltzApi,
                &res.into_string().unwrap(),
            )),
            Err(_) => Err(S5Error::new(ErrorKind::BoltzApi, "Request failed")),
        }
    }
}

#[derive(Deserialize, Debug)]
pub enum PairId {
    BtcBtc,
    LBtcBtc,
}

impl Serialize for PairId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match *self {
            PairId::BtcBtc => "BTC/BTC",
            PairId::LBtcBtc => "L-BTC/BTC",
        };
        serializer.serialize_str(s)
    }
}

impl ToString for PairId {
    fn to_string(&self) -> String {
        match self {
            PairId::BtcBtc => "BTC/BTC".to_string(),
            PairId::LBtcBtc => "L-BTC/BTC".to_string(),
        }
    }
}

impl FromStr for PairId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BTC/BTC" => Ok(PairId::BtcBtc),
            "L-BTC/BTC" => Ok(PairId::LBtcBtc),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetPairsResponse {
    pub info: Vec<String>,
    pub warnings: Vec<String>,
    pub pairs: Pairs,
}

impl GetPairsResponse {
    pub fn get_btc_pair(&self) -> Pair {
        self.pairs
            .pairs
            .get(&PairId::BtcBtc.to_string())
            .map(|pair_info| pair_info)
            .unwrap()
            .clone()
    }
    pub fn get_lbtc_pair(&self) -> Pair {
        self.pairs
            .pairs
            .get(&PairId::LBtcBtc.to_string())
            .map(|pair_info| pair_info)
            .unwrap()
            .clone()
    }
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pairs {
    #[serde(flatten)]
    pub pairs: std::collections::HashMap<String, Pair>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Pair {
    /// Required to create swaps.
    /// Represents a hash of rates, fees and limits.
    /// Using a pair hash to create a swap represents accepting these values
    pub hash: String,
    /// The exchange rate of the pair
    pub rate: f64,
    /// The minimum/maximum order size
    pub limits: Limits,
    /// Boltz + Miner fees
    pub fees: Fees,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    pub maximal: i64,
    pub minimal: i64,
    /// The maximal amounts that will be accepted without chain confirmations by Boltz. 0 indicates that Boltz will not accept 0-conf.
    pub maximal_zero_conf: MaximalZeroConf,
}
impl Limits {
    /// Check whether the output amount intended is within the Limits
    pub fn within(&self, output_amount: u64) -> Result<(), S5Error> {
        if output_amount < self.minimal as u64 {
            return Err(S5Error::new(
                ErrorKind::Input,
                &format!("Ouput amount is below minimum {}", self.minimal),
            ));
        }
        if output_amount > self.maximal as u64 {
            return Err(S5Error::new(
                ErrorKind::Input,
                &format!("Ouput amount is above maximum {}", self.maximal),
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MaximalZeroConf {
    pub base_asset: i64,
    pub quote_asset: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MinerFees {
    pub base_asset: AssetMinerFee,
    pub quote_asset: AssetMinerFee,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssetMinerFee {
    pub normal: i64,
    pub reverse: ReverseMinerFee,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReverseMinerFee {
    pub claim: i64,
    pub lockup: i64,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Fees {
    /// The percentage of the "send amount" that is charged by Boltz as "Boltz Fee" for swaps from quote to base asset (e.g. Lightning -> Bitcoin).
    percentage: f64,
    /// The percentage of the "send amount" that is charged by Boltz as "Boltz Fee" for swaps from base to quote asset (e.g. Bitcoin -> Lightning).
    percentage_swap_in: f64,
    /// The network fees charged for locking up and claiming funds onchain. These values are absolute, denominated in 10 ** -8 of the quote asset.
    miner_fees: MinerFees,
}

impl Fees {
    /// Calculate boltz fees for a submarine swap, given an output amount
    pub fn submarine_boltz(&self, output_amount: u64) -> Result<u64, S5Error> {
        let boltz_fee = ((self.percentage_swap_in / 100.0) * output_amount as f64).round() as u64;
        Ok(boltz_fee)
    }
    /// Get claim miner fees for a submarine swap
    pub fn submarine_claim(&self) -> Result<u64, S5Error> {
        let ln_fee = (self.miner_fees.quote_asset.normal) as u64;
        let claim_miner_fees = (self.miner_fees.base_asset.normal) as u64;
        Ok(claim_miner_fees + ln_fee)
    }
    /// Get onchain lockup miner fees for a submarine swap
    pub fn submarine_lockup_estimate(&self) -> u64 {
        self.miner_fees.base_asset.normal as u64
    }
    /// Calculate boltz fees for a reverse swap, given an output amount
    pub fn reverse_boltz(&self, output_amount: u64) -> Result<u64, S5Error> {
        let boltz_fee = ((self.percentage / 100.0) * output_amount as f64).round() as u64;
        Ok(boltz_fee)
    }
    /// Get lockup miner fees for a reverse swap
    pub fn reverse_lockup(&self) -> Result<u64, S5Error> {
        let lockup_fee = (self.miner_fees.base_asset.reverse.lockup) as u64;
        Ok(lockup_fee)
    }
    /// Estimate claim tx miner fee (claim miner fee) for a reverse swap
    pub fn reverse_claim_estimate(&self) -> u64 {
        self.miner_fees.base_asset.reverse.claim as u64
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum SubSwapStates {
    Created,
    TransactionMempool,
    TransactionConfirmed,
    InvoiceSet,
    InvoicePaid,
    InvoiceFailedToPay,
    TransactionClaimed,
    SwapExpired,
}

impl ToString for SubSwapStates {
    fn to_string(&self) -> String {
        match self {
            SubSwapStates::Created => "swap.created".to_string(),
            SubSwapStates::TransactionMempool => "transaction.mempool".to_string(),
            SubSwapStates::TransactionConfirmed => "transaction.confirmed".to_string(),
            SubSwapStates::InvoiceSet => "invoice.set".to_string(),
            SubSwapStates::InvoicePaid => "invoice.paid".to_string(),
            SubSwapStates::InvoiceFailedToPay => "invoice.failedToPay".to_string(),
            SubSwapStates::TransactionClaimed => "transaction.claimed".to_string(),
            SubSwapStates::SwapExpired => "swap.expired".to_string(),
        }
    }
}

impl FromStr for SubSwapStates {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "swap.created" => Ok(SubSwapStates::Created),
            "transaction.mempool" => Ok(SubSwapStates::TransactionMempool),
            "transaction.confirmed" => Ok(SubSwapStates::TransactionConfirmed),
            "invoice.set" => Ok(SubSwapStates::InvoiceSet),
            "invoice.paid" => Ok(SubSwapStates::InvoicePaid),
            "invoice.failedToPay" => Ok(SubSwapStates::InvoiceFailedToPay),
            "transaction.claimed" => Ok(SubSwapStates::TransactionClaimed),
            "swap.expired" => Ok(SubSwapStates::SwapExpired),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum RevSwapStates {
    Created,
    MinerFeePaid,
    TransactionMempool,
    TransactionConfirmed,
    InvoiceSettled,
    InvoiceExpired,
    SwapExpired,
    TransactionFailed,
    TransactionRefunded,
}

impl ToString for RevSwapStates {
    fn to_string(&self) -> String {
        match self {
            RevSwapStates::Created => "swap.created".to_string(),
            RevSwapStates::MinerFeePaid => "minerfee.paid".to_string(),
            RevSwapStates::TransactionMempool => "transaction.mempool".to_string(),
            RevSwapStates::TransactionConfirmed => "transaction.confirmed".to_string(),
            RevSwapStates::InvoiceSettled => "invoice.settled".to_string(),
            RevSwapStates::InvoiceExpired => "invoice.expired".to_string(),
            RevSwapStates::SwapExpired => "swap.expired".to_string(),
            RevSwapStates::TransactionFailed => "transaction.failed".to_string(),
            RevSwapStates::TransactionRefunded => "transaction.refunded".to_string(),
        }
    }
}

impl FromStr for RevSwapStates {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "swap.created" => Ok(RevSwapStates::Created),
            "minerfee.paid" => Ok(RevSwapStates::MinerFeePaid),
            "transaction.mempool" => Ok(RevSwapStates::TransactionMempool),
            "transaction.confirmed" => Ok(RevSwapStates::TransactionConfirmed),
            "invoice.settled" => Ok(RevSwapStates::InvoiceSettled),
            "invoice.expired" => Ok(RevSwapStates::InvoiceExpired),
            "swap.expired" => Ok(RevSwapStates::SwapExpired),
            "transaction.failed" => Ok(RevSwapStates::TransactionFailed),
            "transaction.refunded" => Ok(RevSwapStates::TransactionRefunded),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(rename_all = "lowercase")]
pub enum SwapType {
    Submarine,
    ReverseSubmarine,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum OrderSide {
    Buy,
    Sell,
}

impl ToString for OrderSide {
    fn to_string(&self) -> String {
        match self {
            OrderSide::Buy => "buy".to_string(),
            OrderSide::Sell => "sell".to_string(),
        }
    }
}

impl FromStr for OrderSide {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "buy" => Ok(OrderSide::Buy),
            "sell" => Ok(OrderSide::Sell),
            _ => Err(()),
        }
    }
}

/// Structure to create a swap request with boltz
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateSwapRequest {
    #[serde(rename = "type")]
    swap_type: SwapType,
    pair_id: PairId,
    order_side: OrderSide,
    pair_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    invoice: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    refund_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    preimage_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    claim_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_block_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    onchain_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invoice_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    channel: Option<ChannelDetails>,
}

impl CreateSwapRequest {
    /// Create a BTC->LN Submarine Swap
    pub fn new_btc_submarine(
        pair_hash: String,
        invoice: String,
        refund_pubkey: String,
    ) -> CreateSwapRequest {
        CreateSwapRequest {
            swap_type: SwapType::Submarine,
            pair_id: PairId::BtcBtc,
            order_side: OrderSide::Sell,
            pair_hash,
            invoice: Some(invoice),
            refund_public_key: Some(refund_pubkey),
            preimage_hash: None,
            claim_public_key: None,
            timeout_block_height: None,
            onchain_amount: None,
            invoice_amount: None,
            channel: None,
        }
    }
    /// Creates a LN->BTC Reverse Swap
    /// This method sets the amount of the invoice that will be generated by Boltz
    /// Eg. Swap for amount 50,000 sats will create an invoice for 50,000 sats
    /// Fees will be deducted from the onchain swap script amount
    pub fn new_btc_reverse_invoice_amt(
        pair_hash: String,
        preimage_hash: String,
        claim_public_key: String,
        invoice_amount: u64,
    ) -> CreateSwapRequest {
        CreateSwapRequest {
            swap_type: SwapType::ReverseSubmarine,
            pair_id: PairId::BtcBtc,
            order_side: OrderSide::Buy,
            pair_hash,
            invoice: None,
            refund_public_key: None,
            preimage_hash: Some(preimage_hash),
            claim_public_key: Some(claim_public_key),
            timeout_block_height: None,
            invoice_amount: Some(invoice_amount),
            onchain_amount: None,
            channel: None,
        }
    }
    /// Creates a LN->BTC Reverse Swap
    /// This method sets the amount of the onchain swap script
    /// Eg. Swap for amount 50,000 sats will create an invoice for (50,000 + fees) sats
    /// The onchain amount to sweep will be exactly 50,000
    pub fn new_btc_reverse_onchain_amt(
        pair_hash: String,
        preimage_hash: String,
        claim_public_key: String,
        onchain_amount: u64,
    ) -> CreateSwapRequest {
        CreateSwapRequest {
            swap_type: SwapType::ReverseSubmarine,
            pair_id: PairId::BtcBtc,
            order_side: OrderSide::Buy,
            pair_hash,
            invoice: None,
            refund_public_key: None,
            preimage_hash: Some(preimage_hash),
            claim_public_key: Some(claim_public_key),
            timeout_block_height: None,
            onchain_amount: Some(onchain_amount),
            invoice_amount: None,
            channel: None,
        }
    }

    /// Create a BTC->LN Submarine Swap
    pub fn new_lbtc_submarine(
        pair_hash: String,
        invoice: String,
        refund_public_key: String,
    ) -> CreateSwapRequest {
        CreateSwapRequest {
            swap_type: SwapType::Submarine,
            pair_id: PairId::LBtcBtc,
            order_side: OrderSide::Sell,
            pair_hash,
            invoice: Some(invoice),
            refund_public_key: Some(refund_public_key),
            preimage_hash: None,
            claim_public_key: None,
            timeout_block_height: None,
            onchain_amount: None,
            invoice_amount: None,
            channel: None,
        }
    }

    /// Creates a LN->LBTC Reverse Swap
    /// This method sets the amount of the invoice that will be generated by Boltz
    /// Eg. Swap for amount 50,000 sats will create an invoice for 50,000 sats
    /// Fees will be deducted from the onchain swap script amount
    pub fn new_lbtc_reverse_invoice_amt(
        pair_hash: String,
        preimage_hash: String,
        claim_public_key: String,
        invoice_amount: u64,
    ) -> CreateSwapRequest {
        CreateSwapRequest {
            swap_type: SwapType::ReverseSubmarine,
            pair_id: PairId::LBtcBtc,
            order_side: OrderSide::Buy,
            pair_hash,
            invoice: None,
            refund_public_key: None,
            preimage_hash: Some(preimage_hash),
            claim_public_key: Some(claim_public_key),
            timeout_block_height: None,
            onchain_amount: None,
            invoice_amount: Some(invoice_amount),
            channel: None,
        }
    }

    /// Creates a LN->BTC Reverse Swap
    /// This method sets the amount of the onchain swap script
    /// Eg. Swap for amount 50,000 sats will create an invoice for (50,000 + fees) sats
    /// The onchain amount to sweep will be exactly 50,000
    pub fn new_lbtc_reverse_onchain_amt(
        pair_hash: String,
        preimage_hash: String,
        claim_public_key: String,
        onchain_amount: u64,
    ) -> CreateSwapRequest {
        CreateSwapRequest {
            swap_type: SwapType::ReverseSubmarine,
            pair_id: PairId::LBtcBtc,
            order_side: OrderSide::Buy,
            pair_hash,
            invoice: None,
            refund_public_key: None,
            preimage_hash: Some(preimage_hash),
            claim_public_key: Some(claim_public_key),
            timeout_block_height: None,
            onchain_amount: Some(onchain_amount),
            invoice_amount: None,
            channel: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDetails {
    auto: bool,
    private: bool,
    inbound_liquidity: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct CreateSwapResponse {
    id: String,
    pub invoice: Option<String>,
    pub redeem_script: Option<String>,
    pub timeout_block_height: Option<u64>,
    pub onchain_amount: Option<u64>,
    pub lockup_address: Option<String>,
    pub miner_fee_invoice: Option<String>,
    pub service_fee_percentage: Option<f64>,
    pub preimage: Option<String>,
    pub claim_address: Option<String>,
    pub claim_public_key: Option<String>,
    private_key: Option<String>,
    pub refund_address: Option<String>,
    pub refund_public_key: Option<String>,
    blinding_key: Option<String>,
    pub address: Option<String>,
    pub expected_amount: Option<u64>,
}

impl CreateSwapResponse {
    /// Get a copy of the id of the swap
    pub fn get_id(&self) -> String {
        self.id.clone()
    }
    /// Get a copy of the blinding key
    pub fn get_blinding_key(&self) -> Result<String, S5Error> {
        if self.blinding_key.is_none() {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Boltz response does not contain a blinding key.",
            ));
        }
        Ok(self.blinding_key.clone().unwrap())
    }
    /// Get a copy of the Timelock value
    pub fn get_timeout(&self) -> Result<u64, S5Error> {
        if self.timeout_block_height.is_none() {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Boltz response does not contain timeout",
            ));
        }
        Ok(self.timeout_block_height.clone().unwrap())
    }
    /// Get a copy of the Invoice value
    pub fn get_invoice(&self) -> Result<Bolt11Invoice, S5Error> {
        if self.invoice.is_none() {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Boltz response does not contain an invoice",
            ));
        }
        match Bolt11Invoice::from_str(&self.invoice.clone().unwrap()) {
            Ok(result) => Ok(result),
            Err(e) => Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        }
    }
    /// Get a BtcSwapScript of the a btc submarine swap response
    pub fn into_btc_sub_swap_script(&self, preimage: &Preimage) -> Result<BtcSwapScript, S5Error> {
        match self.validate_submarine(preimage.hash160) {
            Ok(()) => {
                if self.redeem_script.is_none() {
                    return Err(S5Error::new(
                        ErrorKind::Input,
                        "Boltz response does not contain redeem script",
                    ));
                }
                BtcSwapScript::submarine_from_str(&self.redeem_script.clone().unwrap())
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    /// Get a LbtcSwapScript of the a lbtc submarine swap response
    pub fn into_lbtc_sub_swap_script(
        &self,
        preimage: &Preimage,
    ) -> Result<LBtcSwapScript, S5Error> {
        match self.validate_submarine(preimage.hash160) {
            Ok(()) => {
                if self.redeem_script.is_none() {
                    return Err(S5Error::new(
                        ErrorKind::Input,
                        "Boltz response does not contain redeem script",
                    ));
                }
                LBtcSwapScript::submarine_from_str(
                    &self.redeem_script.clone().unwrap(),
                    self.get_blinding_key()?,
                )
            }
            Err(e) => {
                return Err(e);
            }
        }
    }
    /// Get a BtcSwapScript of the a btc reverse swap response
    pub fn into_btc_rev_swap_script(
        &self,
        preimage: &Preimage,
        keypair: Keypair,
        chain: Chain,
    ) -> Result<BtcSwapScript, S5Error> {
        match self.validate_reverse(preimage, keypair.clone(), chain) {
            Ok(()) => {
                if self.redeem_script.is_none() {
                    return Err(S5Error::new(
                        ErrorKind::Input,
                        "Boltz response does not contain redeem script",
                    ));
                }
                BtcSwapScript::reverse_from_str(&self.redeem_script.clone().unwrap())
            }
            Err(e) => return Err(e),
        }
    }
    /// Get a LbtcSwapScript of the a lbtc reverse swap response
    pub fn into_lbtc_rev_swap_script(
        &self,
        preimage: &Preimage,
        keypair: &ZKKeyPair,
        chain: Chain,
    ) -> Result<LBtcSwapScript, S5Error> {
        match self.validate_reverse(preimage, keypair.clone(), chain) {
            Ok(()) => {
                if self.redeem_script.is_none() {
                    return Err(S5Error::new(
                        ErrorKind::Input,
                        "Boltz response does not contain redeem script",
                    ));
                }
                LBtcSwapScript::reverse_from_str(
                    &self.redeem_script.clone().unwrap(),
                    self.get_blinding_key()?,
                )
            }

            Err(e) => return Err(e),
        }
    }
    /// Ensure submarine swap redeem script uses the preimage hash used in the invoice
    fn validate_submarine(&self, preimage_hash160: hash160::Hash) -> Result<(), S5Error> {
        match &self.redeem_script {
            Some(rs) => {
                let script_elements = BtcSwapScript::submarine_from_str(&rs)?;
                if &script_elements.hashlock == &preimage_hash160.to_string() {
                    Ok(())
                } else {
                    Err(S5Error::new(
                        ErrorKind::BoltzApi,
                        &format!(
                            "{},{}",
                            script_elements.hashlock,
                            preimage_hash160.to_string()
                        ),
                    ))
                }
            }
            None => Err(S5Error::new(
                ErrorKind::BoltzApi,
                "No redeem script found in Boltz response.",
            )),
        }
    }

    /// Validate reverse swap response
    /// Ensure reverse swap invoice uses the provided preimage
    /// Ensure reverse swap redeem script matches locally constructured SwapScript
    fn validate_reverse(
        &self,
        preimage: &Preimage,
        keypair: Keypair,
        chain: Chain,
    ) -> Result<(), S5Error> {
        match &self.invoice {
            Some(invoice_str) => {
                let invoice = match Bolt11Invoice::from_str(&invoice_str) {
                    Ok(invoice) => invoice,
                    Err(_) => {
                        return Err(S5Error::new(
                            ErrorKind::BoltzApi,
                            "Error parsing invoice from boltz.",
                        ))
                    }
                };
                if &invoice.payment_hash().to_string() == &preimage.sha256.to_string() {
                    ()
                } else {
                    return Err(S5Error::new(
                        ErrorKind::BoltzApi,
                        &format!(
                            "{},{}",
                            &invoice.payment_hash().to_string(),
                            preimage.sha256.to_string()
                        ),
                    ));
                }
            }
            None => {
                return Err(S5Error::new(
                    ErrorKind::BoltzApi,
                    "No invoice found in Boltz response.",
                ))
            }
        }
        match chain {
            Chain::Bitcoin | Chain::BitcoinTestnet => {
                let boltz_rev_script =
                    BtcSwapScript::reverse_from_str(&self.redeem_script.as_ref().unwrap()).unwrap();

                let constructed_rev_script = BtcSwapScript::new(
                    &SwapType::ReverseSubmarine,
                    &preimage.hash160.to_string(),
                    &keypair.public_key().to_string(),
                    &(self.timeout_block_height.unwrap() as u32),
                    &boltz_rev_script.sender_pubkey,
                );
                let address = constructed_rev_script.to_address(chain).unwrap();
                if constructed_rev_script == boltz_rev_script
                    && address.to_string() == self.lockup_address.as_ref().unwrap().to_string()
                {
                    Ok(())
                } else {
                    Err(S5Error::new(
                        ErrorKind::BoltzApi,
                        "Script/LockupAddress Mismatch",
                    ))
                }
            }
            Chain::Liquid | Chain::LiquidTestnet => {
                let blinding_key = self.blinding_key.as_ref().unwrap().clone().to_string();
                let boltz_rev_script = LBtcSwapScript::reverse_from_str(
                    &self.redeem_script.as_ref().clone().unwrap(),
                    blinding_key.clone(),
                )
                .unwrap();
                let secp = ZKSecp256k1::new();
                let constructed_rev_script = LBtcSwapScript::new(
                    SwapType::ReverseSubmarine,
                    preimage.hash160.to_string(),
                    keypair.public_key().to_string().clone(),
                    self.timeout_block_height.unwrap() as u32,
                    boltz_rev_script.sender_pubkey.clone(),
                    ZKKeyPair::from_seckey_str(&secp, &blinding_key).unwrap(),
                );
                let address = constructed_rev_script.to_address(chain).unwrap();
                if constructed_rev_script == boltz_rev_script
                    && address.to_string() == self.lockup_address.as_ref().unwrap().to_string()
                {
                    Ok(())
                } else {
                    Err(S5Error::new(
                        ErrorKind::BoltzApi,
                        "Script/LockupAddress Mismatch",
                    ))
                }
            }
        }
    }
}

// impl Into<BtcSwapScript> for CreateSwapResponse{
//     fn into(self) -> Result<BtcSwapScript,S5Error> {
//         if self.blinding_key.is_some() {
//             return Err(S5Error::new(ErrorKind::Script, "Response is for a Liquid Swap, not Bitcoin."))
//         }
//         let from_rs = if self.invoice.is_some(){
//             BtcSwapScript::reverse_from_str(self.redeem_script).unwrap()
//         } else {
//             BtcSwapScript::submarine_from_str(self.redeem_script).unwrap()
//         };

//         let from_items = if self.invoice.is_some(){
//             BtcSwapScript::new(SwapType::ReverseSubmarine, self.preimage, self.refund_public_key, self.timeout_block_height, self.claim_public_key);
//         } else {
//             BtcSwapScript::new(SwapType::Submarine, self.preimage, self.refund_public_key, self.timeout_block_height, self.claim_public_key);
//         };

//         if from_rs == from_items {
//             Ok(from_items)
//         } else {
//             Err(S5Error::new(ErrorKind::BoltzApi, "Boltz redeem script does not match provided script items."))
//         }
// }
// }
// impl Into<LBtcSwapScript> for CreateSwapResponse{
//     fn into(self) -> Result<LBtcSwapScript,S5Error> {
//         if self.blinding_key.is_none() {
//             return Err(S5Error::new(ErrorKind::Script, "Response is for a Bitcoin Swap, not Liquid."))
//         }
//         let from_rs = if self.invoice.is_some(){
//             LBtcSwapScript::reverse_from_str(self.redeem_script).unwrap()
//         } else {
//             LBtcSwapScript::submarine_from_str(self.redeem_script).unwrap()
//         };

//         let from_items = if self.invoice.is_some(){
//             LBtcSwapScript::new(SwapType::ReverseSubmarine, self.preimage, self.refund_public_key, self.timeout_block_height, self.claim_public_key);
//         } else {
//             LBtcSwapScript::new(SwapType::Submarine, self.preimage, self.refund_public_key, self.timeout_block_height, self.claim_public_key);
//         };

//         if from_rs == from_items {
//             Ok(from_items)
//         } else {
//             Err(S5Error::new(ErrorKind::BoltzApi, "Boltz redeem script does not match provided script items."))
//         }
// }
// }

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SwapStatusRequest {
    pub id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SwapStatusResponse {
    pub status: String,
    zero_conf_rejected: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GetFeeEstimationResponse {
    #[serde(rename = "BTC")]
    pub btc: f64,
    #[serde(rename = "L-BTC")]
    pub lbtc: f64,
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::{Keypair, Secp256k1};

    use super::*;
    use crate::util::secrets::{Preimage, SwapKey};

    #[test]
    fn test_get_pairs() {
        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let response = client.get_pairs();
        assert!(response.is_ok());
        // println!("{:?}",response.unwrap().pairs);
        let pair_hash = response
            .unwrap()
            .pairs
            .pairs
            .get("BTC/BTC")
            .map(|pair_info| pair_info.hash.clone());

        assert!(pair_hash.is_some());

        let response = client.get_pairs();
        assert!(response.is_ok());
        let pair_hash = response
            .unwrap()
            .pairs
            .pairs
            .get("L-BTC/BTC")
            .map(|pair_info| pair_info.hash.clone());

        assert!(pair_hash.is_some());
    }

    #[test]
    fn test_get_fee_estimation() {
        let client = BoltzApiClient::new(BOLTZ_MAINNET_URL);
        let response = client.get_fee_estimation();
        println!("{:?}", response);
        assert!(response.is_ok());
    }

    #[test]
    #[ignore]
    /// updated invoice before running
    fn test_create_bitcoin_submarine() {
        let secp = Secp256k1::new();
        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let invoice = "lntb501u1pjh67z3pp539hhfy9vk70yde3m0lkp838l2y0xqskmf5cwm8ng25rqp8asncmsdq8w3jhxaqxqyjw5qcqp2sp59dsnqt4ecde2frjn5zrnw6cunryadzv3p386glz8l7uj37pnwnvsrzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkfkdwyqqq4sqqyqqqqqpqqqqqzsqqc9qyyssq4esj2vvneu5y4e8qtheyxmepjgg5turmxccgmuks78l08m9wguvhvw2yvrftfjh6tzaxy57mty3zsvg3jveazfxs60e6acn989pzdlspafd52g".to_string();

        let refund_key_pair = Keypair::from_seckey_str(
            &secp,
            "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0",
        )
        .unwrap();
        let pair_hash =
            "a3a295202ab0b65cc9597b82663dbcdc77076e138f6d97285711ab7df086afd5".to_string();
        let request = CreateSwapRequest::new_btc_submarine(
            pair_hash,
            invoice,
            refund_key_pair.public_key().to_string(),
        );
        println!("{:?}", serde_json::to_string(&request));
        let response = client.create_swap(request);
        println!("RESPONSE: {:?}", response);
        assert!(response.is_ok());
        // assert!(response.as_ref().unwrap().validate_preimage());
        let id = response.unwrap().id;
        let request = SwapStatusRequest { id: id };
        let response = client.swap_status(request);
        assert!(response.is_ok());
    }

    #[test]
    #[ignore]
    fn test_swap_status() {
        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let id = "Nh7Y1J".to_string();
        let request = SwapStatusRequest { id: id };
        let response = client.swap_status(request);
        assert!(response.is_ok());
    }

    #[test]
    fn test_invoice_decode() {
        let invoice_str = "lntb505590n1pj643ausp5tcn7dy6ax4rglfm6zxscla4dcuwte5jxzc5amgg08t6v2v0m2qnspp5xj7e3y722n7sel292wcrnsnfjl5j02jzf2m3r0pvh548su0ruf9sdql2djkuepqw3hjqsj5gvsxzerywfjhxucxqyp2xqcqzyl9qxpqysgqf8ydv0wst50g7yn04lavjfvzku4k693jawzsk563qv55z5752crs763lv2533xlhh0jdhcafaugw46a724cjr6cufnl7da8j3e3nl3cpy7zz8e";
        let invoice = Bolt11Invoice::from_str(invoice_str).unwrap();
        let amount_sats = invoice.amount_milli_satoshis().unwrap() / 1000;
        println!("amount: {} sats", amount_sats);
    }

    #[test]
    fn test_composite() {
        let client = BoltzApiClient::new(BOLTZ_MAINNET_URL);
        let pairs = client.get_pairs().unwrap();
        let btc_pair = pairs.get_btc_pair();
        let output_amount = 75_000;
        let base_fees = btc_pair.fees.reverse_boltz(output_amount).unwrap()
            + btc_pair.fees.reverse_lockup().unwrap();
        let claim_fee = btc_pair.fees.reverse_claim_estimate();
        println!("CALCULATED FEES: {}", base_fees);
        println!("ONCHAIN LOCKUP: {}", output_amount - base_fees);
        println!(
            "ONCHAIN RECIEVABLE: {}",
            output_amount - base_fees - claim_fee
        );
        let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";
        let claim_key_pair = SwapKey::from_reverse_account(mnemonic, "", Chain::Bitcoin, 0)
            .unwrap()
            .keypair;

        let preimage = Preimage::new();
        let request = CreateSwapRequest::new_btc_reverse_invoice_amt(
            btc_pair.hash,
            preimage.sha256.clone().to_string(),
            claim_key_pair.public_key().to_string(),
            output_amount,
        );
        let response = client.create_swap(request).unwrap();
        println!("Onchain Amount: {}", response.onchain_amount.unwrap());
        assert!((output_amount - base_fees) == response.onchain_amount.unwrap());

        let _btc_rss = response.into_btc_rev_swap_script(&preimage, claim_key_pair, Chain::Bitcoin);
        // let timeout = response.get_timeout();
        // let timeout = LockTime::from_height(timeout as u32).unwrap();
    }
}
