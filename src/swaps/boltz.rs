use lightning_invoice::Bolt11Invoice;
use reqwest;
use serde::Serializer;
use serde::{Deserialize, Serialize};
use serde_json;
use std::str::FromStr;
use std::time::Duration;
use ureq::{Agent, AgentBuilder, Error};

use crate::e::{ErrorKind, S5Error};

use crate::network::electrum::{BitcoinNetwork, DEFAULT_MAINNET_NODE, DEFAULT_TESTNET_NODE};
use crate::swaps::bitcoin::BtcSwapScript;

pub const BOLTZ_TESTNET_URL: &str = "https://api.testnet.boltz.exchange";
pub const BOLTZ_MAINNET_URL: &str = "https://api.boltz.exchange";

#[derive(Debug, Clone)]
pub enum SwapTxKind {
    Claim,
    Refund,
}

use reqwest::blocking::Client;

pub struct BoltzApiClient {
    base_url: String,
}

impl BoltzApiClient {
    pub fn new(base_url: &str) -> Self {
        BoltzApiClient {
            base_url: base_url.to_string(),
        }
    }

    pub fn get_pairs(&self) -> Result<GetPairsResponse, S5Error> {
        let url = format!("{}/getpairs", self.base_url);

        let res = Client::new().get(&url).send().unwrap();

        if res.status().is_success() {
            let body = res.text().unwrap();
            let get_pairs_response: GetPairsResponse = serde_json::from_str(&body).unwrap();
            Ok(get_pairs_response)
        } else {
            Err(S5Error::new(ErrorKind::Network, &res.text().unwrap()))
        }
    }

    pub fn get_fee_estimation(&self) -> Result<GetFeeEstimationResponse, S5Error> {
        let url = format!("{}/getfeeestimation", self.base_url);
        let res = Client::new().get(&url).send().unwrap();

        if res.status().is_success() {
            let body = res.text().unwrap();
            let get_fee_estimation_response: GetFeeEstimationResponse =
                serde_json::from_str(&body).unwrap();
            Ok(get_fee_estimation_response)
        } else {
            Err(S5Error::new(ErrorKind::Network, &res.text().unwrap()))
        }
    }

    pub fn create_swap(&self, request: CreateSwapRequest) -> Result<CreateSwapResponse, S5Error> {
        let url = format!("{}/createswap", self.base_url);
        let res = Client::new().post(&url).json(&request).send().unwrap();

        if res.status().is_success() {
            let body = res.text().unwrap();
            let create_swap_response: CreateSwapResponse = serde_json::from_str(&body).unwrap();
            Ok(create_swap_response)
        } else {
            Err(S5Error::new(ErrorKind::Network, &res.text().unwrap()))
        }
    }

    pub fn swap_status(&self, request: SwapStatusRequest) -> Result<SwapStatusResponse, S5Error> {
        let url = format!("{}/swapstatus", self.base_url);

        let res = Client::new().post(&url).json(&request).send().unwrap();

        if res.status().is_success() {
            let body = res.text().unwrap();
            let swap_status_response: SwapStatusResponse = serde_json::from_str(&body).unwrap();
            Ok(swap_status_response)
        } else {
            Err(S5Error::new(ErrorKind::Network, &res.text().unwrap()))
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
    info: Vec<String>,
    warnings: Vec<String>,
    pub pairs: Pairs,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Pairs {
    #[serde(flatten)]
    pub pairs: std::collections::HashMap<String, Pair>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Pair {
    pub hash: String,
    pub rate: f64,
    pub limits: Limits,
    pub fees: Fees,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    maximal: i64,
    minimal: i64,
    maximal_zero_conf: MaximalZeroConf,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MaximalZeroConf {
    base_asset: i64,
    quote_asset: i64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Fees {
    percentage: f64,
    percentage_swap_in: f64,
    miner_fees: MinerFees,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MinerFees {
    base_asset: MinerFee,
    quote_asset: MinerFee,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MinerFee {
    normal: i64,
    reverse: ReverseMinerFee,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ReverseMinerFee {
    claim: i64,
    lockup: i64,
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
    channel: Option<ChannelDetails>,
}

impl CreateSwapRequest {
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
            channel: None,
        }
    }
    pub fn new_btc_reverse(
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
            channel: None,
        }
    }
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
            channel: None,
        }
    }

    pub fn new_lbtc_reverse(
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
    pub id: String,
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
    pub private_key: Option<String>,
    pub refund_address: Option<String>,
    pub refund_public_key: Option<String>,
    pub blinding_key: Option<String>,
    pub address: Option<String>,
    pub expected_amount: Option<u64>,
}

impl CreateSwapResponse {
    pub fn validate_invoice_preimage256(&self, preimage_sha256: String) -> bool {
        match &self.invoice {
            Some(invoice_str) => {
                let invoice = match Bolt11Invoice::from_str(&invoice_str) {
                    Ok(invoice) => invoice,
                    Err(e) => {
                        println!("{:?}", e);
                        return false;
                    }
                };
                if &invoice.payment_hash().to_string() == &preimage_sha256 {
                    true
                } else {
                    println!(
                        "{},{}",
                        invoice.payment_hash().to_string(),
                        preimage_sha256.to_string()
                    );
                    false
                }
            }
            None => false,
        }
    }
    pub fn validate_script_preimage160(&self, preimage_hash160: String) -> bool {
        match &self.redeem_script {
            Some(rs) => {
                let script_elements = match BtcSwapScript::submarine_from_str(
                    BitcoinNetwork::Bitcoin,
                    DEFAULT_MAINNET_NODE.to_string(),
                    &rs,
                ) {
                    // network doesnt matter here, we just want the hashlock extracted
                    Ok(se) => se,
                    Err(e) => {
                        println!("Error parsing sub script elements:{:?}", e);
                        return false;
                    }
                };
                // println!("{}-m----m-{}", script_elements.hashlock, preimage_hash160);
                if &script_elements.hashlock == &preimage_hash160 {
                    true
                } else {
                    println!(
                        "{},{}",
                        script_elements.hashlock,
                        preimage_hash160.to_string()
                    );
                    false
                }
            }
            None => false,
        }
    }
}

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
    btc: f64,
    #[serde(rename = "L-BTC")]
    lbtc: f64,
}

#[cfg(test)]
mod tests {
    use secp256k1::hashes::{sha256, Hash};

    use super::*;
    use crate::{key::ec::KeyPairString, util::rnd_str};

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
            .map(|pair_info| pair_info.hash.clone())
            .unwrap();
        assert_eq!(
            pair_hash,
            "22567ecdd28deb837edadc555b094a2b1acf633f0754f9c5f15a2db3808c6df5".to_string()
        );

        let response = client.get_pairs();
        assert!(response.is_ok());
        let pair_hash = response
            .unwrap()
            .pairs
            .pairs
            .get("L-BTC/BTC")
            .map(|pair_info| pair_info.hash.clone())
            .unwrap();
        assert_eq!(
            pair_hash,
            "9021f628875ca585e804d3cb67cbda8f1ffd8dfad49ce10873698537b9dd8f2d".to_string()
        );
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
        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let invoice = "lntb501u1pjh67z3pp539hhfy9vk70yde3m0lkp838l2y0xqskmf5cwm8ng25rqp8asncmsdq8w3jhxaqxqyjw5qcqp2sp59dsnqt4ecde2frjn5zrnw6cunryadzv3p386glz8l7uj37pnwnvsrzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkfkdwyqqq4sqqyqqqqqpqqqqqzsqqc9qyyssq4esj2vvneu5y4e8qtheyxmepjgg5turmxccgmuks78l08m9wguvhvw2yvrftfjh6tzaxy57mty3zsvg3jveazfxs60e6acn989pzdlspafd52g".to_string();

        let refund_key_pair = KeyPairString {
            seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
            pubkey: "023946267e8f3eeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d".to_string(),
        };
        let pair_hash =
            "a3a295202ab0b65cc9597b82663dbcdc77076e138f6d97285711ab7df086afd5".to_string();
        let request =
            CreateSwapRequest::new_btc_submarine(pair_hash, invoice, refund_key_pair.pubkey);
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

    /**
         *
         * {"id":"FwS1I8","bip21":"bitcoin:2NCzMM3ruqW9PKYBFpunsjaCUELqMU5uAtC?amount=0.00050491&label=Send%20to%20BTC%20lightning","address":"2NCzMM3ruqW9PKYBFpunsjaCUELqMU5uAtC","redeemScript":"a9141b0ec63cfb573d37f7b8ddb342e326d68530719e87632102252ef842406c2abf2d3905d87e9b52ad535eb32eb87306cc1409feea4a55568b67035bce26b17520023946267e8f3eeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf23568ac","acceptZeroConf":false,"expectedAmount":50491,"timeoutBlockHeight":2543195}
    RESPONSE: Ok(CreateSwapResponse { id: "FwS1I8", invoice: None, redeem_script: Some("a9141b0ec63cfb573d37f7b8ddb342e326d68530719e87632102252ef842406c2abf2d3905d87e9b52ad535eb32eb87306cc1409feea4a55568b67035bce26b17520023946267e8f3eeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf23568ac"), timeout_block_height: Some(2543195), onchain_amount: None, lockup_address: None, miner_fee_invoice: None, service_fee_percentage: None, preimage: None, claim_address: None, claim_public_key: None, private_key: None, refund_address: None, refund_public_key: None, blinding_key: None })

         */

    #[test]
    #[ignore]
    /// No changes required to run
    fn test_create_bitcoin_reverse() {
        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let claim_key_pair = KeyPairString {
            seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
            pubkey: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d"
                .to_string(),
        };

        let preimage = rnd_str();
        println!("Preimage: {:?}", preimage);
        let preimage_hash = sha256::Hash::hash(&hex::decode(preimage).unwrap()).to_string();

        let pair_hash =
            "d3479af57b3a55e7a4d8e70e2b7ce1a79196446b4708713061d3f6efe587c601".to_string();

        let request = CreateSwapRequest::new_btc_reverse(
            pair_hash,
            preimage_hash.clone(),
            claim_key_pair.pubkey,
            100_000,
        );
        let response = client.create_swap(request);
        assert!(response.is_ok());
        assert!(response
            .as_ref()
            .unwrap()
            .validate_invoice_preimage256(preimage_hash));
        let id = response.unwrap().id;
        let request = SwapStatusRequest { id: id };
        let response = client.swap_status(request);
        assert!(response.is_ok());
    }

    #[test]
    #[ignore]
    /// No changes required to run
    fn test_liquid_reverse() {
        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let claim_key_pair = KeyPairString {
            seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
            pubkey: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d"
                .to_string(),
        };

        let preimage = rnd_str();
        println!("Preimage: {:?}", preimage);
        let preimage_hash = sha256::Hash::hash(&hex::decode(preimage).unwrap()).to_string();

        let pair_hash =
            "bfe685df32af97d89e4ca9faa0f133003bf7637e719fdef0d665f34cc66d3f76".to_string();

        let request = CreateSwapRequest::new_btc_reverse(
            pair_hash,
            preimage_hash.clone(),
            claim_key_pair.pubkey,
            100_000,
        );
        let response = client.create_swap(request);
        assert!(response.is_ok());
        assert!(response
            .as_ref()
            .unwrap()
            .validate_invoice_preimage256(preimage_hash));
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
}
