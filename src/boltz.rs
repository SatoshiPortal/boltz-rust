use reqwest::{Client, Error};
use serde::{Deserialize, Serialize};
use serde::Serializer;
use std::str::FromStr;


pub struct BoltzApiClient {
    client: Client,
    base_url: String,
}

impl BoltzApiClient {
    pub fn new(base_url: &str) -> Self {
        BoltzApiClient {
            client: Client::new(),
            base_url: base_url.to_string(),
        }
    }

    pub async fn get_pairs(&self) -> Result<GetPairsResponse, Error> {
        let url = format!("{}/getpairs", self.base_url);
        let response = self.client.get(url).send().await?;
        let body = response.text().await?; // Get the response body as a string
        println!("{}",body);
        let get_pairs_response: GetPairsResponse = serde_json::from_str(&body).unwrap(); // Deserialize the string into your Rust struct
        Ok(get_pairs_response)
    }

    pub async fn get_fee_estimation(&self) -> Result<GetFeeEstimationResponse, reqwest::Error> {
        let url = format!("{}/getfeeestimation", self.base_url);
        let response = self.client.get(url).send().await?;
        let body = response.text().await?;
        println!("{}",body);
        let get_fee_estimation_response: GetFeeEstimationResponse = serde_json::from_str(&body).unwrap();
        Ok(get_fee_estimation_response)
    }

    pub async fn create_swap(&self, request: CreateSwapRequest) -> Result<CreateSwapResponse, Error> {
        let url = format!("{}/createswap", self.base_url);
        let response = self.client.post(url)
            .json(&request)
            .send()
            .await?;
        let body = response.text().await?;
        println!("{}",body);

        let create_swap_response: CreateSwapResponse = serde_json::from_str(&body).unwrap();
        Ok(create_swap_response)
    }

    pub async fn swap_status(&self, request: SwapStatusRequest) -> Result<SwapStatusResponse, Error> {
        let url = format!("{}/swapstatus", self.base_url);
        let response = self.client.post(url)
            .json(&request)
            .send()
            .await?;
        let body = response.text().await?;
        println!("{}",body);

        let swap_status_response: SwapStatusResponse = serde_json::from_str(&body).unwrap();
        Ok(swap_status_response)
    }
}

#[derive(Deserialize, Debug)]
pub enum PairId {
    Btc_Btc,
    LBtc_Btc,
}


impl Serialize for PairId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = match *self {
            PairId::Btc_Btc => "BTC/BTC",
            PairId::LBtc_Btc => "L-BTC/BTC",
        };
        serializer.serialize_str(s)
    }
}

impl ToString for PairId {
    fn to_string(&self) -> String {
        match self {
            PairId::Btc_Btc => "BTC/BTC".to_string(),
            PairId::LBtc_Btc => "L-BTC/BTC".to_string(),
        }
    }
}

impl FromStr for PairId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BTC/BTC" => Ok(PairId::Btc_Btc),
            "L-BTC/BTC" => Ok(PairId::LBtc_Btc),
            _ => Err(()),
        }
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct GetPairsResponse {
    info: Vec<String>,
    warnings: Vec<String>,
    pairs: Pairs,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Pairs {
    // Use a HashMap to represent pairs, keys are strings like "BTC/BTC"
    #[serde(flatten)]
    pairs: std::collections::HashMap<String, Pair>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Pair {
    hash: String,
    rate: f64,
    limits: Limits,
    fees: Fees,
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
pub enum SubmarineSwapStates {
    Created,
    TransactionMempool,
    TransactionConfirmed,
    InvoiceSet,
    InvoicePaid,
    InvoiceFailedToPay,
    TransactionClaimed,
    SwapExpired,
}

impl ToString for SubmarineSwapStates {
    fn to_string(&self) -> String {
        match self {
            SubmarineSwapStates::Created => "swap.created".to_string(),
            SubmarineSwapStates::TransactionMempool => "transaction.mempool".to_string(),
            SubmarineSwapStates::TransactionConfirmed => "transaction.confirmed".to_string(),
            SubmarineSwapStates::InvoiceSet => "invoice.set".to_string(),
            SubmarineSwapStates::InvoicePaid => "invoice.paid".to_string(),
            SubmarineSwapStates::InvoiceFailedToPay => "invoice.failedToPay".to_string(),
            SubmarineSwapStates::TransactionClaimed => "transaction.claimed".to_string(),
            SubmarineSwapStates::SwapExpired => "swap.expired".to_string(),
        }
    }
}

impl FromStr for SubmarineSwapStates {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "swap.created" => Ok(SubmarineSwapStates::Created),
            "transaction.mempool" => Ok(SubmarineSwapStates::TransactionMempool),
            "transaction.confirmed" => Ok(SubmarineSwapStates::TransactionConfirmed),
            "invoice.set" => Ok(SubmarineSwapStates::InvoiceSet),
            "invoice.paid" => Ok(SubmarineSwapStates::InvoicePaid),
            "invoice.failedToPay" => Ok(SubmarineSwapStates::InvoiceFailedToPay),
            "transaction.claimed" => Ok(SubmarineSwapStates::TransactionClaimed),
            "swap.expired" => Ok(SubmarineSwapStates::SwapExpired),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ReverseSwapStates {
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

impl ToString for ReverseSwapStates {
    fn to_string(&self) -> String {
        match self {
            ReverseSwapStates::Created => "swap.created".to_string(),
            ReverseSwapStates::MinerFeePaid => "minerfee.paid".to_string(),
            ReverseSwapStates::TransactionMempool => "transaction.mempool".to_string(),
            ReverseSwapStates::TransactionConfirmed => "transaction.confirmed".to_string(),
            ReverseSwapStates::InvoiceSettled => "invoice.settled".to_string(),
            ReverseSwapStates::InvoiceExpired => "invoice.expired".to_string(),
            ReverseSwapStates::SwapExpired => "swap.expired".to_string(),
            ReverseSwapStates::TransactionFailed => "transaction.failed".to_string(),
            ReverseSwapStates::TransactionRefunded => "transaction.refunded".to_string(),
        }
    }
}

impl FromStr for ReverseSwapStates {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "swap.created" => Ok(ReverseSwapStates::Created),
            "minerfee.paid" => Ok(ReverseSwapStates::MinerFeePaid),
            "transaction.mempool" => Ok(ReverseSwapStates::TransactionMempool),
            "transaction.confirmed" => Ok(ReverseSwapStates::TransactionConfirmed),
            "invoice.settled" => Ok(ReverseSwapStates::InvoiceSettled),
            "invoice.expired" => Ok(ReverseSwapStates::InvoiceExpired),
            "swap.expired" => Ok(ReverseSwapStates::SwapExpired),
            "transaction.failed" => Ok(ReverseSwapStates::TransactionFailed),
            "transaction.refunded" => Ok(ReverseSwapStates::TransactionRefunded),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SwapType {
    Submarine,
    ReverseSubmarine,
}

impl ToString for SwapType {
    fn to_string(&self) -> String {
        match self {
            SwapType::Submarine => "submarine".to_string(),
            SwapType::ReverseSubmarine => "reversesubmarine".to_string(),
        }
    }
}

impl FromStr for SwapType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "submarine" => Ok(SwapType::Submarine),
            "reversesubmarine" => Ok(SwapType::ReverseSubmarine),
            _ => Err(()),
        }
    }
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
    invoice: String,
    pair_hash: String,
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
    pub fn new(swap_type: SwapType, 
        pair_id: PairId, 
        order_side: OrderSide,
        invoice: String,
        pair_hash: String,
        refund_public_key: Option<String>,
        preimage_hash: Option<String>,
        claim_public_key: Option<String>,
        timeout_block_height: Option<u64>,
        onchain_amount: Option<u64>,
        channel: Option<ChannelDetails>
    ) -> CreateSwapRequest {
        CreateSwapRequest {
            swap_type,
            pair_id,
            order_side,
            invoice,
            pair_hash,
            refund_public_key,
            preimage_hash,
            claim_public_key,
            timeout_block_height,
            onchain_amount,
            channel,
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

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CreateSwapResponse {
    id: String,
    invoice: Option<String>,
    redeem_script: Option<String>,
    timeout_block_height: Option<u64>,
    onchain_amount: Option<u64>,
    lockup_address: Option<String>,
    miner_fee_invoice: Option<String>,
    service_fee_percentage: Option<f64>,
    preimage_hash: Option<String>,
    claim_address: Option<String>,
    claim_public_key: Option<String>,
    private_key: Option<String>,
    refund_address: Option<String>,
    refund_public_key: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SwapStatusRequest {
    id: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SwapStatusResponse {
    status: String,
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
    use super::*;
    use crate::ec::XOnlyPair;

    #[tokio::test]
    async fn test_get_pairs() {
        let client = BoltzApiClient::new("https://testnet.boltz.exchange/api");
        let response = client.get_pairs().await;
        assert!(response.is_ok());
        // Here you can add more detailed tests, like checking the contents of the response
    }

    #[tokio::test]
    async fn test_get_fee_estimation() {
        let client = BoltzApiClient::new("https://testnet.boltz.exchange/api");
        let response = client.get_fee_estimation().await;
        assert!(response.is_ok());
        // Additional detailed assertions can be added here
    }

    #[tokio::test]
     #[ignore]
    async fn test_normal_swap() {
        let client = BoltzApiClient::new("https://testnet.boltz.exchange/api");
        let refund_key_pair = XOnlyPair {
            seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
            pubkey: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d".to_string(),
        };
        let invoice = "lntb560u1pjka0aypp59wmr35slav63cjnt22c2uu4mqyld483jumjjw4m6dj9sdqv9hy5qdpgxguzq5mrv9kxzgzrdp5hqgzxwfshqur4vd3kjmn0xqrrsscqp79qy9qsqsp5qerwpp78lepyejnmn7vm9jp3899vy34xnfp9vdyh2afvwwguntysz38gzprptss3y5w85z548y4mgjpfaghfqe0uxtqvl9gypv64alrky8wc76hfhm55uk8gdr4rlvct67fgxjzmavgc86aunfsw0xfn3sqpcgctl8".to_string();
        let pair_hash = "d3479af57b3a55e7a4d8e70e2b7ce1a79196446b4708713061d3f6efe587c601".to_string();
        let request = CreateSwapRequest::new(SwapType::Submarine, PairId::Btc_Btc, OrderSide::Sell, invoice, pair_hash, Some(refund_key_pair.pubkey),None, None, None,None,None);
        let response = client.create_swap(request).await;
        assert!(response.is_ok());
        let id = response.unwrap().id;
        // let id = "Nh7Y1J".to_string();
        let request = SwapStatusRequest{id: id};
        let response = client.swap_status(request).await;
        assert!(response.is_ok());

        // Additional detailed assertions can be added here
    }
    #[tokio::test]
    #[ignore]
    async fn test_swap_status() {
        let client = BoltzApiClient::new("https://testnet.boltz.exchange/api");
        let id = "Nh7Y1J".to_string();
        let request = SwapStatusRequest{id: id};
        let response = client.swap_status(request).await;
        assert!(response.is_ok());

        // Additional detailed assertions can be added here
    }
    // #[tokio::test]
    // async fn test_reverse_swap() {
    //     let client = BoltzApiClient::new("https://testnet.boltz.exchange/api");
    //     let response = client.get_fee_estimation().await;
    //     assert!(response.is_ok());
    //     // Additional detailed assertions can be added here
    // }
    
}