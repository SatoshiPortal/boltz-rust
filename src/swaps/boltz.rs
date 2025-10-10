//!
//! ### Boltz v2 API
//! ## Estimate fees
//!
//! ### Example
//! ```
//! let client = BoltzApiClient::new(BOLTZ_MAINNET_URL);
//! let pairs = client.get_pairs()?;
//! let btc_pair = pairs.get_btc_pair();
//! let output_amount = 75_000;
//! let base_fees = btc_pair.fees.reverse_base(output_amount)?;
//! let claim_fee = btc_pair.fees.reverse_claim_estimate();
//! println!("CALCULATED FEES: {}", base_fees);
//! println!("ONCHAIN LOCKUP: {}", output_amount - base_fees);
//! println!(
//!     "ONCHAIN RECIEVABLE: {}",
//!     output_amount - base_fees - claim_fee
//! );

use crate::network::Network;
use crate::{error::Error, network::Chain, util::secrets::Preimage};
use crate::{BtcSwapScript, LBtcSwapScript};
use bitcoin::secp256k1;
use bitcoin::{hashes::sha256, hex::DisplayHex, PublicKey};
use lightning_invoice::Bolt11Invoice;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use std::time::Duration;

pub const BOLTZ_TESTNET_URL_V2: &str = "https://api.testnet.boltz.exchange/v2";
pub const BOLTZ_MAINNET_URL_V2: &str = "https://api.boltz.exchange/v2";
pub const BOLTZ_REGTEST: &str = "http://localhost:9001/v2";

#[cfg(feature = "ws")]
pub use crate::swaps::status_stream::{BoltzWsApi, BoltzWsConfig};
use elements::secp256k1_zkp::{MusigPartialSignature, MusigPubNonce};
use reqwest::RequestBuilder;
#[cfg(feature = "ws")]
pub use tokio_tungstenite_wasm;
#[cfg(feature = "ws")]
use tokio_tungstenite_wasm::{connect, connect_with_protocols, WebSocketStream};

#[derive(Serialize, Deserialize, Debug)]
pub struct HeightResponse {
    #[serde(rename = "BTC")]
    pub btc: u32,
    #[serde(rename = "L-BTC")]
    pub lbtc: u32,
}

fn check_limits_within(maximal: u64, minimal: u64, output_amount: u64) -> Result<(), Error> {
    if output_amount < minimal {
        return Err(Error::Protocol(format!(
            "Output amount is below minimum {minimal}"
        )));
    }
    if output_amount > maximal {
        return Err(Error::Protocol(format!(
            "Output amount is above maximum {maximal}"
        )));
    }
    Ok(())
}

/// Various limits of swap parameters
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PairLimits {
    /// Maximum swap amount
    pub maximal: u64,
    /// Minimum swap amount
    pub minimal: u64,
    /// Maximum amount allowed for zero-conf
    pub maximal_zero_conf: u64,
}

impl PairLimits {
    /// Check whether the output amount intended is within the Limits
    pub fn within(&self, output_amount: u64) -> Result<(), Error> {
        check_limits_within(self.maximal, self.minimal, output_amount)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
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

impl SubmarinePairLimits {
    /// Check whether the output amount intended is within the Limits
    pub fn within(&self, output_amount: u64) -> Result<(), Error> {
        let minimal = self.minimal_batched.unwrap_or(self.minimal);
        check_limits_within(self.maximal, minimal, output_amount)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReverseLimits {
    /// Maximum swap amount
    pub maximal: u64,
    /// Minimum swap amount
    pub minimal: u64,
}

impl ReverseLimits {
    /// Check whether the output amount intended is within the Limits
    pub fn within(&self, output_amount: u64) -> Result<(), Error> {
        check_limits_within(self.maximal, self.minimal, output_amount)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PairMinerFees {
    pub lockup: u64,
    pub claim: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChainMinerFees {
    pub server: u64,
    pub user: PairMinerFees,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ChainFees {
    pub percentage: f64,
    pub miner_fees: ChainMinerFees,
}

impl ChainFees {
    pub fn total(&self, amount_sat: u64) -> u64 {
        self.boltz(amount_sat) + self.claim_estimate() + self.lockup() + self.server()
    }

    pub fn boltz(&self, amount_sat: u64) -> u64 {
        ((self.percentage / 100.0) * amount_sat as f64).ceil() as u64
    }

    pub fn claim_estimate(&self) -> u64 {
        self.miner_fees.user.claim
    }

    pub fn lockup(&self) -> u64 {
        self.miner_fees.user.lockup
    }

    pub fn server(&self) -> u64 {
        self.miner_fees.server
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReverseFees {
    pub percentage: f64,
    pub miner_fees: PairMinerFees,
}

impl ReverseFees {
    pub fn total(&self, invoice_amount_sat: u64) -> u64 {
        self.boltz(invoice_amount_sat) + self.claim_estimate() + self.lockup()
    }

    pub fn boltz(&self, invoice_amount_sat: u64) -> u64 {
        ((self.percentage / 100.0) * invoice_amount_sat as f64).ceil() as u64
    }

    pub fn claim_estimate(&self) -> u64 {
        self.miner_fees.claim
    }

    pub fn lockup(&self) -> u64 {
        self.miner_fees.lockup
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SubmarineFees {
    /// The percentage of the "send amount" that is charged by Boltz as "Boltz Fee".
    pub percentage: f64,
    /// The network fees charged for locking up and claiming funds onchain. These values are absolute, denominated in 10 ** -8 of the quote asset.
    pub miner_fees: u64,
}

impl SubmarineFees {
    pub fn total(&self, invoice_amount_sat: u64) -> u64 {
        self.boltz(invoice_amount_sat) + self.network()
    }

    pub fn boltz(&self, invoice_amount_sat: u64) -> u64 {
        ((self.percentage / 100.0) * invoice_amount_sat as f64).ceil() as u64
    }

    pub fn network(&self) -> u64 {
        self.miner_fees
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetSubmarinePairsResponse {
    #[serde(rename = "BTC")]
    pub btc: HashMap<String, SubmarinePair>,
    #[serde(rename = "L-BTC")]
    pub lbtc: HashMap<String, SubmarinePair>,
}

impl GetSubmarinePairsResponse {
    /// Get the BtcBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_btc_to_btc_pair(&self) -> Option<SubmarinePair> {
        self.btc.get("BTC").cloned()
    }

    /// Get the BtcLBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_btc_to_lbtc_pair(&self) -> Option<SubmarinePair> {
        self.btc.get("L-BTC").cloned()
    }

    /// Get the LBtcBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_lbtc_to_btc_pair(&self) -> Option<SubmarinePair> {
        self.lbtc.get("BTC").cloned()
    }

    /// Get the LBtcLBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_lbtc_to_lbtc_pair(&self) -> Option<SubmarinePair> {
        self.lbtc.get("L-BTC").cloned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetReversePairsResponse {
    #[serde(rename = "BTC")]
    pub btc: HashMap<String, ReversePair>,
}

impl GetReversePairsResponse {
    /// Get the BtcBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_btc_to_btc_pair(&self) -> Option<ReversePair> {
        self.btc.get("BTC").cloned()
    }

    /// Get the BtcLBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_btc_to_lbtc_pair(&self) -> Option<ReversePair> {
        self.btc.get("L-BTC").cloned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetChainPairsResponse {
    #[serde(rename = "BTC")]
    pub btc: HashMap<String, ChainPair>,
    #[serde(rename = "L-BTC")]
    pub lbtc: HashMap<String, ChainPair>,
}

impl GetChainPairsResponse {
    /// Get the BtcLBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_btc_to_lbtc_pair(&self) -> Option<ChainPair> {
        self.btc.get("L-BTC").cloned()
    }

    /// Get the LBtcBtc Pair data from the response.
    /// Returns None if not found.
    pub fn get_lbtc_to_btc_pair(&self) -> Option<ChainPair> {
        self.lbtc.get("BTC").cloned()
    }
}

/// Reference Documnetation: <https://api.boltz.exchange/swagger>
#[derive(Debug, Clone)]
pub struct BoltzApiClientV2 {
    base_url: String,
    http_client: reqwest::Client,
    timeout: Option<Duration>,
}

impl BoltzApiClientV2 {
    pub fn new(base_url: String, timeout: Option<Duration>) -> Self {
        let http_client = reqwest::Client::new();
        Self {
            base_url,
            http_client,
            timeout,
        }
    }

    pub fn default(network: Network) -> Self {
        let base_url = match network {
            Network::Mainnet => BOLTZ_MAINNET_URL_V2.to_string(),
            Network::Testnet => BOLTZ_TESTNET_URL_V2.to_string(),
            Network::Regtest => BOLTZ_REGTEST.to_string(),
        };
        Self::new(base_url, None)
    }

    pub fn with_client(
        base_url: String,
        http_client: reqwest::Client,
        timeout: Option<Duration>,
    ) -> Self {
        Self {
            base_url,
            http_client,
            timeout,
        }
    }

    /// Returns the WebSocket URL for the Boltz server
    fn get_ws_url(&self) -> String {
        self.base_url.clone().replace("http", "ws") + "/ws"
    }

    /// Returns the web socket connection to the boltz server
    #[cfg(feature = "ws")]
    pub async fn connect_ws(&self) -> Result<WebSocketStream, Error> {
        Ok(connect(self.get_ws_url()).await?)
    }

    /// Same as `connect_ws` but with protocols
    #[cfg(feature = "ws")]
    pub async fn connect_ws_with_protocols(
        &self,
        protocols: &[&str],
    ) -> Result<WebSocketStream, Error> {
        Ok(connect_with_protocols(self.get_ws_url(), protocols).await?)
    }

    #[cfg(feature = "ws")]
    pub fn ws(&self, config: BoltzWsConfig) -> BoltzWsApi {
        BoltzWsApi::new(self.get_ws_url(), config)
    }

    /// Make a GET request. Returns the Response
    async fn get_response(&self, end_point: &str) -> Result<reqwest::Response, Error> {
        let url = format!("{}/{}", self.base_url, end_point);
        let req_builder = self.http_client.get(url);
        let req_builder = self.maybe_add_timeout(req_builder);
        Ok(req_builder.send().await?)
    }

    /// Make a GET request. Returns the Response as text
    async fn get(&self, end_point: &str) -> Result<String, Error> {
        Ok(self.get_response(end_point).await?.text().await?)
    }

    /// Make a POST request. Returns the Response
    async fn post(&self, end_point: &str, data: impl Serialize) -> Result<String, Error> {
        let url = format!("{}/{}", self.base_url, end_point);

        self.request(Method::POST, url, data).await
    }

    /// Make a PATCH request. Returns the Response
    async fn patch(&self, end_point: &str, data: impl Serialize) -> Result<String, Error> {
        let url = format!("{}/{}", self.base_url, end_point);

        self.request(Method::PATCH, url, data).await
    }

    async fn request(
        &self,
        method: Method,
        url: String,
        data: impl Serialize,
    ) -> Result<String, Error> {
        let method_str = method.to_string();
        let req_builder = self.http_client.request(method, url).json(&data);
        let req_builder = self.maybe_add_timeout(req_builder);
        match req_builder.send().await {
            Ok(r) => {
                if r.status().is_success() {
                    log::debug!("{method_str} response: {r:#?}");
                    Ok(r.text().await?)
                } else {
                    log::error!("{} error: HTTP {}", method_str, r.status());
                    let err_resp = r.text().await.unwrap_or("Unknown error".to_string());
                    let e_val: Value = serde_json::from_str(&err_resp).unwrap_or(Value::Null);
                    let e_str = e_val.get("error").unwrap_or(&Value::Null).to_string();
                    Err(Error::HTTP(e_str))
                }
            }
            Err(e) => {
                log::error!("{method_str} error: {e:#?}");
                Err(e.into())
            }
        }
    }

    fn maybe_add_timeout(&self, req_builder: RequestBuilder) -> RequestBuilder {
        if let Some(timeout) = self.timeout {
            req_builder.timeout(timeout)
        } else {
            req_builder
        }
    }

    pub async fn get_fee_estimation(&self) -> Result<GetFeeEstimationResponse, Error> {
        Ok(serde_json::from_str(&self.get("chain/fees").await?)?)
    }

    pub async fn get_height(&self) -> Result<HeightResponse, Error> {
        Ok(serde_json::from_str(&self.get("chain/heights").await?)?)
    }

    pub async fn get_submarine_pairs(&self) -> Result<GetSubmarinePairsResponse, Error> {
        Ok(serde_json::from_str(&self.get("swap/submarine").await?)?)
    }

    pub async fn get_reverse_pairs(&self) -> Result<GetReversePairsResponse, Error> {
        Ok(serde_json::from_str(&self.get("swap/reverse").await?)?)
    }

    pub async fn get_chain_pairs(&self) -> Result<GetChainPairsResponse, Error> {
        Ok(serde_json::from_str(&self.get("swap/chain").await?)?)
    }

    pub async fn post_swap_req(
        &self,
        swap_request: &CreateSubmarineRequest,
    ) -> Result<CreateSubmarineResponse, Error> {
        let data = serde_json::to_value(swap_request)?;
        Ok(serde_json::from_str(
            &self.post("swap/submarine", data).await?,
        )?)
    }

    pub async fn post_reverse_req(
        &self,
        req: CreateReverseRequest,
    ) -> Result<CreateReverseResponse, Error> {
        Ok(serde_json::from_str(
            &self.post("swap/reverse", req).await?,
        )?)
    }

    pub async fn post_chain_req(
        &self,
        req: CreateChainRequest,
    ) -> Result<CreateChainResponse, Error> {
        Ok(serde_json::from_str(&self.post("swap/chain", req).await?)?)
    }

    pub async fn get_submarine_claim_tx_details(
        &self,
        id: &String,
    ) -> Result<SubmarineClaimTxResponse, Error> {
        let endpoint = format!("swap/submarine/{id}/claim");
        let response = self.get_response(&endpoint).await?;
        let status = response.status();
        if status.is_success() {
            let body = response.text().await?;
            Ok(serde_json::from_str(&body)?)
        } else {
            let body = serde_json::from_str(&response.text().await?)?;
            Err(Error::HTTPStatusNotSuccess(status, body))
        }
    }

    pub async fn get_chain_claim_tx_details(
        &self,
        id: &String,
    ) -> Result<ChainClaimTxResponse, Error> {
        let endpoint = format!("swap/chain/{id}/claim");
        Ok(serde_json::from_str(&self.get(&endpoint).await?)?)
    }

    pub async fn post_submarine_claim_tx_details(
        &self,
        id: &String,
        pub_nonce: MusigPubNonce,
        partial_sig: MusigPartialSignature,
    ) -> Result<Value, Error> {
        let data = json!(
            {
                "pubNonce": pub_nonce.serialize().to_lower_hex_string(),
                "partialSignature": partial_sig.serialize().to_lower_hex_string()
            }
        );
        let endpoint = format!("swap/submarine/{id}/claim");
        Ok(serde_json::from_str(&self.post(&endpoint, data).await?)?)
    }

    pub async fn post_chain_claim_tx_details(
        &self,
        id: &String,
        preimage: &Preimage,
        signature: Option<(MusigPartialSignature, MusigPubNonce)>,
        to_sign: ToSign,
    ) -> Result<PartialSig, Error> {
        let data = match signature {
            Some((partial_sig, pub_nonce)) => json!(
                {
                "preimage": preimage.bytes.ok_or(Error::Protocol("Preimage bytes not available to post chain claim".to_string()))?.to_lower_hex_string(),
                "signature": PartialSig {
                    pub_nonce: pub_nonce.serialize().to_lower_hex_string(),
                    partial_signature: partial_sig.serialize().to_lower_hex_string(),
                },
                "toSign": to_sign,
            }
            ),
            None => json!(
                {
                    "preimage": preimage.bytes.ok_or(Error::Protocol("Preimage bytes not available to post chain claim".to_string()))?.to_lower_hex_string(),
                    "toSign": to_sign,
                }
            ),
        };
        let endpoint = format!("swap/chain/{id}/claim");
        Ok(serde_json::from_str(&self.post(&endpoint, data).await?)?)
    }

    pub async fn get_reverse_tx(&self, id: &str) -> Result<ReverseSwapTxResp, Error> {
        Ok(serde_json::from_str(
            &self.get(&format!("swap/reverse/{id}/transaction")).await?,
        )?)
    }

    pub async fn get_submarine_tx(&self, id: &str) -> Result<SubmarineSwapTxResp, Error> {
        Ok(serde_json::from_str(
            &self
                .get(&format!("swap/submarine/{id}/transaction"))
                .await?,
        )?)
    }

    pub async fn get_submarine_preimage(
        &self,
        id: &str,
    ) -> Result<SubmarineSwapPreimageResp, Error> {
        Ok(serde_json::from_str(
            &self.get(&format!("swap/submarine/{id}/preimage")).await?,
        )?)
    }

    pub async fn get_chain_txs(&self, id: &str) -> Result<ChainSwapTxResp, Error> {
        Ok(serde_json::from_str(
            &self.get(&format!("swap/chain/{id}/transactions")).await?,
        )?)
    }

    pub async fn get_reverse_partial_sig(
        &self,
        id: &String,
        preimage: &Preimage,
        pub_nonce: &MusigPubNonce,
        claim_tx_hex: &String,
    ) -> Result<PartialSig, Error> {
        let data = json!(
            {
                "preimage": preimage.bytes.ok_or(Error::Protocol("Preimage bytes not available to post chain claim".to_string()))?.to_lower_hex_string(),
                "pubNonce": pub_nonce.serialize().to_lower_hex_string(),
                "transaction": claim_tx_hex,
                "index": 0
            }
        );

        let endpoint = format!("swap/reverse/{id}/claim");
        Ok(serde_json::from_str(&self.post(&endpoint, data).await?)?)
    }

    pub async fn get_submarine_partial_sig(
        &self,
        id: &String,
        input_index: usize,
        pub_nonce: &MusigPubNonce,
        refund_tx_hex: &String,
    ) -> Result<PartialSig, Error> {
        let data = json!(
            {
                "pubNonce": pub_nonce.serialize().to_lower_hex_string(),
                "transaction": refund_tx_hex,
                "index": input_index
            }
        );

        let endpoint = format!("swap/submarine/{id}/refund");
        Ok(serde_json::from_str(&self.post(&endpoint, data).await?)?)
    }

    pub async fn get_chain_partial_sig(
        &self,
        id: &String,
        input_index: usize,
        pub_nonce: &MusigPubNonce,
        refund_tx_hex: &String,
    ) -> Result<PartialSig, Error> {
        let data = json!(
            {
                "pubNonce": pub_nonce.serialize().to_lower_hex_string(),
                "transaction": refund_tx_hex,
                "index": input_index
            }
        );

        let endpoint = format!("swap/chain/{id}/refund");
        Ok(serde_json::from_str(&self.post(&endpoint, data).await?)?)
    }

    pub async fn get_mrh_bip21(&self, invoice: &str) -> Result<MrhResponse, Error> {
        let request = format!("swap/reverse/{invoice}/bip21");
        Ok(serde_json::from_str(&self.get(&request).await?)?)
    }

    pub async fn broadcast_tx(&self, chain: Chain, tx_hex: &String) -> Result<Value, Error> {
        let data = json!(
            {
                "hex": tx_hex
            }
        );

        let chain = match chain {
            Chain::Bitcoin(_) => "BTC",
            Chain::Liquid(_) => "L-BTC",
        };

        let end_point = format!("chain/{chain}/transaction");
        Ok(serde_json::from_str(&self.post(&end_point, data).await?)?)
    }

    /// Creates a BOLT12 offer
    pub async fn post_bolt12_offer(&self, req: CreateBolt12OfferRequest) -> Result<(), Error> {
        let data = serde_json::to_value(req)?;
        let end_point = "lightning/BTC/bolt12".to_string();
        self.post(&end_point, data).await?;
        Ok(())
    }

    /// Updates the webhook URL for a BOLT12 offer
    ///
    /// # Arguments
    ///   * `req` - The request object containing the offer and the new webhook URL
    ///     * `offer` - The BOLT12 offer
    ///     * `url` - The updated webhook URL. Setting to None will remove the webhook URL from the registered offer
    ///     * `signature` - The schnorr signature of the SHA256 hash of the webhook URL or "UPDATE" when not set
    pub async fn patch_bolt12_offer(&self, req: UpdateBolt12OfferRequest) -> Result<(), Error> {
        let data = serde_json::to_value(req)?;
        let end_point = "lightning/BTC/bolt12".to_string();
        self.patch(&end_point, data).await?;
        Ok(())
    }

    /// Deletes a BOLT12 offer
    ///
    /// # Arguments
    ///    * `offer` - The BOLT12 offer
    ///    * `signature` - This schnorr signature of the SHA256 hash of "DELETE"
    pub async fn delete_bolt12_offer(&self, offer: &str, signature: &str) -> Result<(), Error> {
        let data = json!(
            {
                "offer": offer,
                "signature": signature,
            }
        );

        let end_point = "lightning/BTC/bolt12/delete".to_string();
        self.post(&end_point, data).await?;
        Ok(())
    }

    /// Fetch an invoice for the specified BOLT12 offer
    pub async fn get_bolt12_invoice(
        &self,
        req: GetBolt12FetchRequest,
    ) -> Result<GetBolt12FetchResponse, Error> {
        let data = serde_json::to_value(req)?;
        let end_point = "lightning/BTC/bolt12/fetch".to_string();
        Ok(serde_json::from_str(&self.post(&end_point, data).await?)?)
    }

    /// Gets parameters for a BOLT12 offer
    pub async fn get_bolt12_params(&self) -> Result<GetBolt12ParamsResponse, Error> {
        let end_point = "lightning/BTC/bolt12/L-BTC".to_string();
        Ok(serde_json::from_str(&self.get(&end_point).await?)?)
    }

    /// Fetch information about the Lightning nodes the backend is connected to
    pub async fn get_nodes(&self) -> Result<GetNodesResponse, Error> {
        let end_point = "nodes".to_string();
        Ok(serde_json::from_str(&self.get(&end_point).await?)?)
    }

    /// Gets a quote for a Zero-Amount or over- or underpaid Chain Swap.
    ///
    /// If the user locked up a valid amount, it will return the server lockup amount. In all other
    /// cases, it will return an error.
    pub async fn get_quote(&self, swap_id: &str) -> Result<GetQuoteResponse, Error> {
        let end_point = format!("swap/chain/{swap_id}/quote");
        Ok(serde_json::from_str(&self.get(&end_point).await?)?)
    }

    /// Accepts a specific quote for a Zero-Amount or over- or underpaid Chain Swap.
    pub async fn accept_quote(&self, swap_id: &str, amount_sat: u64) -> Result<(), Error> {
        let data = json!(
            {
                "amount": amount_sat
            }
        );

        let end_point = format!("swap/chain/{swap_id}/quote");
        self.post(&end_point, data).await?;
        Ok(())
    }

    /// Gets the latest status of the Swap
    pub async fn get_swap(&self, swap_id: &str) -> Result<GetSwapResponse, Error> {
        let end_point = format!("swap/{swap_id}");
        Ok(serde_json::from_str(&self.get(&end_point).await?)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainClaimTxResponse {
    pub pub_nonce: String,
    pub public_key: PublicKey,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmarineClaimTxResponse {
    pub preimage: String,
    pub pub_nonce: String,
    pub public_key: PublicKey,
    pub transaction_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MrhResponse {
    pub bip21: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Webhook<T> {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_swap_id: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<Vec<T>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSubmarineRequest {
    pub from: String,
    pub to: String,
    pub invoice: String,
    pub refund_public_key: PublicKey,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referral_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<Webhook<SubSwapStates>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSubmarineResponse {
    pub accept_zero_conf: bool,
    pub address: String,
    pub bip21: String,
    pub claim_public_key: PublicKey,
    pub expected_amount: u64,
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referral_id: Option<String>,
    pub swap_tree: SwapTree,
    pub timeout_block_height: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blinding_key: Option<String>,
}
impl CreateSubmarineResponse {
    /// Ensure submarine swap redeem script uses the preimage hash used in the invoice
    pub fn validate(
        &self,
        invoice: &str,
        our_pubkey: &PublicKey,
        chain: Chain,
    ) -> Result<(), Error> {
        let preimage = Preimage::from_invoice_str(invoice)?;

        match chain {
            Chain::Bitcoin(bitcoin_chain) => {
                let boltz_sub_script = BtcSwapScript::submarine_from_swap_resp(self, *our_pubkey)?;
                boltz_sub_script.validate_address(bitcoin_chain, self.address.clone())
            }
            Chain::Liquid(liquid_chain) => {
                let boltz_sub_script = LBtcSwapScript::submarine_from_swap_resp(self, *our_pubkey)?;
                if boltz_sub_script.hashlock != preimage.hash160 {
                    return Err(Error::Protocol(format!(
                        "Hash160 mismatch: {},{}",
                        boltz_sub_script.hashlock, preimage.hash160
                    )));
                }

                boltz_sub_script.validate_address(liquid_chain, self.address.clone())
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapTree {
    pub claim_leaf: Leaf,
    pub refund_leaf: Leaf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Leaf {
    pub output: String,
    pub version: u8,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SubscriptionChannel {
    #[serde(rename = "swap.update")]
    SwapUpdate,
    #[serde(rename = "invoice.request")]
    InvoiceRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct InvoiceRequestParams {
    pub offer: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "channel")]
pub enum SubscribeRequest {
    #[serde(rename = "swap.update")]
    SwapUpdate { args: Vec<String> },
    #[serde(rename = "invoice.request")]
    InvoiceRequest { args: Vec<InvoiceRequestParams> },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct UnsubscribeRequest {
    pub channel: SubscriptionChannel,
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct InvoiceCreated {
    pub id: String,
    pub invoice: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct InvoiceError {
    pub id: String,
    pub error: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum WsRequest {
    #[serde(rename = "subscribe")]
    Subscribe(SubscribeRequest),
    #[serde(rename = "unsubscribe")]
    Unsubscribe(UnsubscribeRequest),
    #[serde(rename = "invoice")]
    Invoice(InvoiceCreated),
    #[serde(rename = "invoice.error")]
    InvoiceError(InvoiceError),
    #[serde(rename = "ping")]
    Ping,
}

impl WsRequest {
    pub fn subscribe_swap_request(swap_id: &str) -> Self {
        Self::subscribe_swaps_request(vec![swap_id.to_string()])
    }

    pub fn subscribe_swaps_request(swap_ids: Vec<String>) -> Self {
        Self::Subscribe(SubscribeRequest::SwapUpdate { args: swap_ids })
    }

    pub fn subscribe_invoice_request(params: InvoiceRequestParams) -> Self {
        Self::subscribe_invoice_requests(vec![params])
    }

    pub fn subscribe_invoice_requests(params: Vec<InvoiceRequestParams>) -> Self {
        Self::Subscribe(SubscribeRequest::InvoiceRequest { args: params })
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct SubscribeResponse {
    pub channel: SubscriptionChannel,
    pub args: Vec<String>,

    pub timestamp: String,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct UnsubscribeResponse {
    pub channel: SubscriptionChannel,
    pub args: Vec<String>,

    pub timestamp: String,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct TransactionInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta: Option<u64>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct FailureReasonIncorrectAmounts {
    pub expected: u64,
    pub actual: u64,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct ChannelInfo {
    #[serde(rename = "fundingTransactionId")]
    pub funding_transaction_id: String,
    #[serde(rename = "fundingTransactionVout")]
    pub funding_transaction_vout: u64,
}

#[derive(Deserialize, Serialize, Default, Debug, Clone, PartialEq)]
pub struct SwapStatus {
    pub id: String,
    pub status: String,

    #[serde(rename = "zeroConfRejected", skip_serializing_if = "Option::is_none")]
    pub zero_conf_rejected: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<TransactionInfo>,

    #[serde(rename = "failureReason", skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    #[serde(rename = "failureDetails", skip_serializing_if = "Option::is_none")]
    pub failure_details: Option<FailureReasonIncorrectAmounts>,

    #[serde(rename = "channel", skip_serializing_if = "Option::is_none")]
    pub channel_info: Option<ChannelInfo>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct InvoiceRequest {
    pub id: String,

    pub offer: String,
    #[serde(rename = "invoiceRequest")]
    pub invoice_request: String,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct UpdateResponse<T> {
    pub channel: SubscriptionChannel,
    pub args: Vec<T>,

    pub timestamp: String,
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
#[serde(tag = "event")]
pub enum WsResponse {
    #[serde(rename = "subscribe")]
    Subscribe(SubscribeResponse),
    #[serde(rename = "unsubscribe")]
    Unsubscribe(UnsubscribeResponse),
    #[serde(rename = "update")]
    Update(UpdateResponse<SwapStatus>),
    #[serde(rename = "request")]
    InvoiceRequest(UpdateResponse<InvoiceRequest>),
    #[serde(rename = "error")]
    Error(ErrorResponse),
    #[serde(rename = "pong")]
    Pong,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReverseRequest {
    pub from: String,
    pub to: String,
    pub claim_public_key: PublicKey,
    /// The BOLT12 invoice
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice: Option<String>,
    /// The invoice amount if the invoice is not provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invoice_amount: Option<u64>,
    /// The preimage hash if the invoice is not provided
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preimage_hash: Option<sha256::Hash>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address_signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referral_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<Webhook<RevSwapStates>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
impl CreateReverseResponse {
    /// Validate reverse swap response
    /// Ensure reverse swap invoice uses the provided preimage
    /// Ensure reverse swap redeem script matches locally constructured SwapScript
    pub fn validate(
        &self,
        preimage: &Preimage,
        our_pubkey: &PublicKey,
        chain: Chain,
    ) -> Result<(), Error> {
        if let Some(invoice) = &self.invoice {
            // Boltz will only return a BOLT11 invoice if the invoice is not provided
            let invoice = Bolt11Invoice::from_str(invoice)?;
            if invoice.payment_hash().to_string() != preimage.sha256.to_string() {
                return Err(Error::Protocol(format!(
                    "Preimage hash mismatch : {},{}",
                    &invoice.payment_hash().to_string(),
                    preimage.sha256
                )));
            }
        }

        match chain {
            Chain::Bitcoin(bitcoin_chain) => {
                let boltz_rev_script = BtcSwapScript::reverse_from_swap_resp(self, *our_pubkey)?;
                boltz_rev_script.validate_address(bitcoin_chain, self.lockup_address.clone())
            }
            Chain::Liquid(liquid_chain) => {
                let boltz_rev_script = LBtcSwapScript::reverse_from_swap_resp(self, *our_pubkey)?;
                boltz_rev_script.validate_address(liquid_chain, self.lockup_address.clone())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Side {
    Lockup,
    Claim,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateChainRequest {
    pub from: String,
    pub to: String,
    pub preimage_hash: sha256::Hash,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refund_public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_lock_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_lock_amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub referral_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook: Option<Webhook<ChainSwapStates>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateChainResponse {
    pub id: String,
    pub claim_details: ChainSwapDetails,
    pub lockup_details: ChainSwapDetails,
}
impl CreateChainResponse {
    /// Validate chain swap response
    pub fn validate(
        &self,
        claim_pubkey: &PublicKey,
        refund_pubkey: &PublicKey,
        from_chain: Chain,
        to_chain: Chain,
    ) -> Result<(), Error> {
        self.validate_side(
            Side::Lockup,
            from_chain,
            &self.lockup_details,
            refund_pubkey,
        )?;
        self.validate_side(Side::Claim, to_chain, &self.claim_details, claim_pubkey)
    }

    fn validate_side(
        &self,
        side: Side,
        chain: Chain,
        details: &ChainSwapDetails,
        our_pubkey: &PublicKey,
    ) -> Result<(), Error> {
        match chain {
            Chain::Bitcoin(bitcoin_chain) => {
                let boltz_chain_script =
                    BtcSwapScript::chain_from_swap_resp(side, details.clone(), *our_pubkey)?;
                boltz_chain_script.validate_address(bitcoin_chain, details.lockup_address.clone())
            }
            Chain::Liquid(liquid_chain) => {
                let boltz_chain_script =
                    LBtcSwapScript::chain_from_swap_resp(side, details.clone(), *our_pubkey)?;
                boltz_chain_script.validate_address(liquid_chain, details.lockup_address.clone())
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapTx {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapTxTimeout {
    pub block_height: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapTxLock {
    pub transaction: ChainSwapTx,
    pub timeout: ChainSwapTxTimeout,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainSwapTxResp {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_lock: Option<ChainSwapTxLock>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_lock: Option<ChainSwapTxLock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseSwapTxResp {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    pub timeout_block_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmarineSwapTxResp {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_block_height: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_eta: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmarineSwapPreimageResp {
    pub preimage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialSig {
    pub pub_nonce: String,
    pub partial_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToSign {
    pub pub_nonce: String,
    pub transaction: String,
    pub index: u32,
}

#[derive(Debug, Clone)]
pub struct Cooperative<'a> {
    pub boltz_api: &'a BoltzApiClientV2,
    pub swap_id: String,
    /// The signature (partial_sig + pub_nonce) is needed to post the claim tx details of the Chain swap
    /// It may be omitted for a chain swap if we've already sent the signature to Boltz
    pub signature: Option<(MusigPartialSignature, MusigPubNonce)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapUpdateTxDetails {
    pub id: String,
    pub hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespError {
    pub id: String,
    pub error: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SwapTxKind {
    Claim,
    Refund,
}

/// States for a submarine swap.
///
/// See <https://docs.boltz.exchange/v/api/lifecycle#normal-submarine-swaps>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubSwapStates {
    /// Initial state of the swap; optionally the initial state can also be `invoice.set` in case
    /// the invoice was already specified in the request that created the swap.
    #[serde(rename = "swap.created")]
    Created,
    /// The lockup transaction was found in the mempool, meaning the user sent funds to the
    /// lockup address.
    #[serde(rename = "transaction.mempool")]
    TransactionMempool,
    /// The lockup transaction was included in a block.
    #[serde(rename = "transaction.confirmed")]
    TransactionConfirmed,
    /// The swap has an invoice that should be paid.
    /// Can be the initial state when the invoice was specified in the request that created the swap
    #[serde(rename = "invoice.set")]
    InvoiceSet,
    /// Boltz successfully paid the invoice.
    #[serde(rename = "invoice.paid")]
    InvoicePaid,
    /// Boltz started paying the invoice.
    #[serde(rename = "invoice.pending")]
    InvoicePending,
    /// Boltz failed to pay the invoice. In this case the user needs to broadcast a refund
    /// transaction to reclaim the locked up onchain coins.
    #[serde(rename = "invoice.failedToPay")]
    InvoiceFailedToPay,
    /// Indicates that after the invoice was successfully paid, the onchain were successfully
    /// claimed by Boltz. This is the final status of a successful Normal Submarine Swap.
    #[serde(rename = "transaction.claimed")]
    TransactionClaimed,
    /// Indicates that Boltz is ready for the creation of a cooperative signature for a key path
    /// spend. Taproot Swaps are not claimed immediately by Boltz after the invoice has been paid,
    /// but instead Boltz waits for the API client to post a signature for a key path spend. If the
    /// API client does not cooperate in a key path spend, Boltz will eventually claim via the script path.
    #[serde(rename = "transaction.claim.pending")]
    TransactionClaimPending,
    /// Indicates the lockup failed, which is usually because the user sent too little.
    #[serde(rename = "transaction.lockupFailed")]
    TransactionLockupFailed,
    /// Indicates the user didn't send onchain (lockup) and the swap expired (approximately 24h).
    /// This means that it was cancelled and chain L-BTC shouldn't be sent anymore.
    #[serde(rename = "swap.expired")]
    SwapExpired,
}

impl Display for SubSwapStates {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            SubSwapStates::Created => "swap.created".to_string(),
            SubSwapStates::TransactionMempool => "transaction.mempool".to_string(),
            SubSwapStates::TransactionConfirmed => "transaction.confirmed".to_string(),
            SubSwapStates::InvoiceSet => "invoice.set".to_string(),
            SubSwapStates::InvoicePaid => "invoice.paid".to_string(),
            SubSwapStates::InvoicePending => "invoice.pending".to_string(),
            SubSwapStates::InvoiceFailedToPay => "invoice.failedToPay".to_string(),
            SubSwapStates::TransactionClaimed => "transaction.claimed".to_string(),
            SubSwapStates::TransactionClaimPending => "transaction.claim.pending".to_string(),
            SubSwapStates::TransactionLockupFailed => "transaction.lockupFailed".to_string(),
            SubSwapStates::SwapExpired => "swap.expired".to_string(),
        };
        write!(f, "{str}")
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
            "invoice.pending" => Ok(SubSwapStates::InvoicePending),
            "invoice.failedToPay" => Ok(SubSwapStates::InvoiceFailedToPay),
            "transaction.claimed" => Ok(SubSwapStates::TransactionClaimed),
            "transaction.claim.pending" => Ok(SubSwapStates::TransactionClaimPending),
            "transaction.lockupFailed" => Ok(SubSwapStates::TransactionLockupFailed),
            "swap.expired" => Ok(SubSwapStates::SwapExpired),
            _ => Err(()),
        }
    }
}

/// States for a reverse swap.
///
/// See <https://docs.boltz.exchange/v/api/lifecycle#reverse-submarine-swaps>
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevSwapStates {
    /// Initial state of a newly created Reverse Submarine Swap.
    #[serde(rename = "swap.created")]
    Created,
    /// Optional and currently not enabled on Boltz. If Boltz requires prepaying miner fees via a
    /// separate Lightning invoice, this state is set when the miner fee invoice was successfully paid.
    #[serde(rename = "minerfee.paid")]
    MinerFeePaid,
    /// Boltz's lockup transaction is found in the mempool which will only happen after the user
    /// paid the Lightning hold invoice.
    #[serde(rename = "transaction.mempool")]
    TransactionMempool,
    /// The lockup transaction was included in a block. This state is skipped, if the client
    /// optionally accepts the transaction without confirmation. Boltz broadcasts chain transactions
    /// non-RBF only.
    #[serde(rename = "transaction.confirmed")]
    TransactionConfirmed,
    /// The transaction claiming onchain was broadcast by the user's client and Boltz used the
    /// preimage of this transaction to settle the Lightning invoice. This is the final status of a
    /// successful Reverse Submarine Swap.
    #[serde(rename = "invoice.settled")]
    InvoiceSettled,
    /// Set when the invoice of Boltz expired and pending HTLCs are cancelled. Boltz invoices
    /// currently expire after 50% of the swap timeout window.
    #[serde(rename = "invoice.expired")]
    InvoiceExpired,
    /// This is the final status of a swap, if the swap expires without the lightning invoice being paid.
    #[serde(rename = "swap.expired")]
    SwapExpired,
    /// Set in the unlikely event that Boltz is unable to send the agreed amount of onchain coins
    /// after the user set up the payment to the provided Lightning invoice. If this happens, the
    /// pending Lightning HTLC will also be cancelled. The Lightning bitcoin automatically bounce
    /// back to the user, no further action or refund is required and the user didn't pay any fees.
    #[serde(rename = "transaction.failed")]
    TransactionFailed,
    /// This is the final status of a swap, if the user successfully set up the Lightning payment
    /// and Boltz successfully locked up coins onchain, but the Boltz API Client did not claim
    /// the locked oncahin coins before swap expiry. In this case, Boltz will also automatically refund
    /// its own locked onchain coins and the Lightning payment is cancelled.
    #[serde(rename = "transaction.refunded")]
    TransactionRefunded,
}

impl Display for RevSwapStates {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            RevSwapStates::Created => "swap.created".to_string(),
            RevSwapStates::MinerFeePaid => "minerfee.paid".to_string(),
            RevSwapStates::TransactionMempool => "transaction.mempool".to_string(),
            RevSwapStates::TransactionConfirmed => "transaction.confirmed".to_string(),
            RevSwapStates::InvoiceSettled => "invoice.settled".to_string(),
            RevSwapStates::InvoiceExpired => "invoice.expired".to_string(),
            RevSwapStates::SwapExpired => "swap.expired".to_string(),
            RevSwapStates::TransactionFailed => "transaction.failed".to_string(),
            RevSwapStates::TransactionRefunded => "transaction.refunded".to_string(),
        };
        write!(f, "{str}")
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainSwapStates {
    /// The initial state of the chain swap.
    #[serde(rename = "swap.created")]
    Created,
    /// The server has rejected a 0-conf transaction for this swap.
    #[serde(rename = "transaction.zeroconf.rejected")]
    TransactionZeroConfRejected,
    /// The lockup transaction of the client was found in the mempool.
    #[serde(rename = "transaction.mempool")]
    TransactionMempool,
    /// The lockup transaction of the client was confirmed in a block. When the server accepts 0-conf,
    /// for the lockup transaction, this state is skipped.
    #[serde(rename = "transaction.confirmed")]
    TransactionConfirmed,
    /// The lockup transaction of the server has been broadcast.
    #[serde(rename = "transaction.server.mempool")]
    TransactionServerMempool,
    /// The lockup transaction of the server has been included in a block.
    #[serde(rename = "transaction.server.confirmed")]
    TransactionServerConfirmed,
    /// The server claimed the coins that the client locked.
    #[serde(rename = "transaction.claimed")]
    TransactionClaimed,
    /// Indicates the lockup failed, which is usually because the user sent too little.
    #[serde(rename = "transaction.lockupFailed")]
    TransactionLockupFailed,
    /// This is the final status of a swap, if the swap expires without a chain bitcoin transaction.
    #[serde(rename = "swap.expired")]
    SwapExpired,
    /// Set in the unlikely event that Boltz is unable to lock the agreed amount of chain bitcoin.
    /// The user needs to submit a refund transaction to reclaim the chain bitcoin if bitcoin were
    /// already sent.
    #[serde(rename = "transaction.failed")]
    TransactionFailed,
    /// If the user and Boltz both successfully locked up bitcoin on the chain, but the user did not
    /// claim the locked chain bitcoin until swap expiry, Boltz will automatically refund its own locked
    /// chain bitcoin.
    #[serde(rename = "transaction.refunded")]
    TransactionRefunded,
}

impl Display for ChainSwapStates {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            ChainSwapStates::Created => "swap.created".to_string(),
            ChainSwapStates::TransactionZeroConfRejected => {
                "transaction.zeroconf.rejected".to_string()
            }
            ChainSwapStates::TransactionMempool => "transaction.mempool".to_string(),
            ChainSwapStates::TransactionConfirmed => "transaction.confirmed".to_string(),
            ChainSwapStates::TransactionServerMempool => "transaction.server.mempool".to_string(),
            ChainSwapStates::TransactionServerConfirmed => {
                "transaction.server.confirmed".to_string()
            }
            ChainSwapStates::TransactionClaimed => "transaction.claimed".to_string(),
            ChainSwapStates::TransactionLockupFailed => "transaction.lockupFailed".to_string(),
            ChainSwapStates::SwapExpired => "swap.expired".to_string(),
            ChainSwapStates::TransactionFailed => "transaction.failed".to_string(),
            ChainSwapStates::TransactionRefunded => "transaction.refunded".to_string(),
        };
        write!(f, "{str}")
    }
}

impl FromStr for ChainSwapStates {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "swap.created" => Ok(ChainSwapStates::Created),
            "transaction.zeroconf.rejected" => Ok(ChainSwapStates::TransactionZeroConfRejected),
            "transaction.mempool" => Ok(ChainSwapStates::TransactionMempool),
            "transaction.confirmed" => Ok(ChainSwapStates::TransactionConfirmed),
            "transaction.server.mempool" => Ok(ChainSwapStates::TransactionServerMempool),
            "transaction.server.confirmed" => Ok(ChainSwapStates::TransactionServerConfirmed),
            "transaction.claimed" => Ok(ChainSwapStates::TransactionClaimed),
            "transaction.lockupFailed" => Ok(ChainSwapStates::TransactionLockupFailed),
            "swap.expired" => Ok(ChainSwapStates::SwapExpired),
            "transaction.failed" => Ok(ChainSwapStates::TransactionFailed),
            "transaction.refunded" => Ok(ChainSwapStates::TransactionRefunded),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum SwapType {
    Submarine,
    ReverseSubmarine,
    Chain,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum OrderSide {
    Buy,
    Sell,
}

impl Display for OrderSide {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            OrderSide::Buy => "buy",
            OrderSide::Sell => "sell",
        };
        f.write_str(str)
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
pub struct GetFeeEstimationResponse {
    #[serde(rename = "BTC")]
    pub btc: f64,
    #[serde(rename = "L-BTC")]
    pub lbtc: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateBolt12OfferRequest {
    pub offer: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBolt12OfferRequest {
    pub offer: String,
    /// The updated webhook URL.
    /// Setting to None will remove the webhook URL from the registered Offer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// The schnorr signature of the SHA256 hash of the webhook URL or "UPDATE" when None
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MagicRoutingHint {
    pub bip21: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBolt12FetchRequest {
    /// The offer to fetch an invoice for
    pub offer: String,
    /// The amount to pay, in satoshi
    pub amount: u64,
    /// The optional payer note
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBolt12FetchResponse {
    /// BOLT12 invoice
    pub invoice: String,
    /// The invoice magic routing hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub magic_routing_hint: Option<MagicRoutingHint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetBolt12ParamsResponse {
    /// Minimum CLTV value
    pub min_cltv: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    /// The public key
    pub public_key: secp256k1::PublicKey,
    /// The public URIs
    pub uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetNodesResponse {
    #[serde(rename = "BTC")]
    pub btc: HashMap<String, Node>,
}

impl GetNodesResponse {
    /// Get the BTC LND node data from the response.
    /// Returns None if not found.
    pub fn get_btc_lnd_node(&self) -> Option<Node> {
        self.btc.get("LND").cloned()
    }

    /// Get the BTC CLN node data from the response.
    /// Returns None if not found.
    pub fn get_btc_cln_node(&self) -> Option<Node> {
        self.btc.get("CLN").cloned()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetQuoteResponse {
    /// Server lockup amount, in sat
    pub amount: u64,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransactionResponse {
    pub id: String,
    pub hex: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct GetSwapResponse {
    pub status: String,
    pub zero_conf_rejected: Option<bool>,
    pub transaction: Option<TransactionResponse>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[macros::async_test_all]
    async fn test_get_fee_estimation() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let result = client.get_fee_estimation().await;
        assert!(result.is_ok(), "Failed to get fee estimation");
    }

    #[macros::async_test_all]
    async fn test_get_height() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let result = client.get_height().await;
        assert!(result.is_ok(), "Failed to get height");
    }

    #[macros::async_test_all]
    async fn test_get_submarine_pairs() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let result = client.get_submarine_pairs().await;
        assert!(result.is_ok(), "Failed to get submarine pairs");
    }

    #[macros::async_test_all]
    async fn test_get_reverse_pairs() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let result = client.get_reverse_pairs().await;
        assert!(result.is_ok(), "Failed to get reverse pairs");
    }

    #[macros::async_test_all]
    async fn test_get_chain_pairs() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let result = client.get_chain_pairs().await;
        assert!(result.is_ok(), "Failed to get chain pairs");
    }

    #[macros::async_test_all]
    #[ignore]
    async fn test_get_submarine_claim_tx_details() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let id = "G6c6GJJY8eXz".to_string();
        let result = client.get_submarine_claim_tx_details(&id).await;
        assert!(
            result.is_ok(),
            "Failed to get submarine claim transaction details"
        );
    }

    #[macros::async_test_all]
    #[ignore]
    async fn test_get_chain_claim_tx_details() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let id = "3BIJf8UqGaSC".to_string();
        let result = client.get_chain_claim_tx_details(&id).await;
        assert!(
            result.is_ok(),
            "Failed to get chain claim transaction details"
        );
    }

    #[macros::async_test_all]
    #[ignore]
    async fn test_get_reverse_tx() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let id = "G6c6GJJY8eXz";
        let result = client.get_reverse_tx(id).await;
        assert!(result.is_ok(), "Failed to get reverse transaction");
    }

    #[macros::async_test_all]
    #[ignore]
    async fn test_get_submarine_tx() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let id = "G6c6GJJY8eXz";
        let result = client.get_submarine_tx(id).await;
        assert!(result.is_ok(), "Failed to get submarine transaction");
    }

    #[macros::async_test_all]
    async fn test_get_chain_txs() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let id = "G6c6GJJY8eXz";
        let result = client.get_chain_txs(id).await;
        assert!(result.is_ok(), "Failed to get chain transactions");
    }

    #[macros::async_test_all]
    async fn test_get_swap() {
        let client = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
        let id = "G6c6GJJY8eXz";
        let result = client.get_swap(id).await;
        assert!(result.is_ok(), "Failed to get swap status");
    }
}
