use std::{collections::HashMap, fmt::format, net::TcpStream};

use bitcoin::{
    hashes::sha256, hex::DisplayHex, taproot::TapLeaf, PublicKey, ScriptBuf, Transaction,
};
use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tungstenite::{connect, stream::MaybeTlsStream, WebSocket};
use ureq::json;

use crate::{error::Error, network::Chain, util::secrets::Preimage};

use super::boltz::GetFeeEstimationResponse;

pub const BOLTZ_TESTNET_URL_V2: &str = "https://api.testnet.boltz.exchange/v2";
pub const BOLTZ_MAINNET_URL_V2: &str = "https://api.boltz.exchange/v2";
pub const BOLTZ_REGTEST: &str = "http://127.0.0.1:9001/v2";

use url::Url;

use elements::secp256k1_zkp::{
    MusigAggNonce, MusigKeyAggCache, MusigPartialSignature, MusigPubNonce, MusigSession,
    MusigSessionId,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct HeightResponse {
    #[serde(rename = "BTC")]
    pub btc: u32,
    #[serde(rename = "L-BTC")]
    pub lbtc: u32,
}

/// Various limits of swap parameters
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Limits {
    /// Maximum swap amount
    pub maximal: u64,
    /// Minimum swap amount
    pub minimal: u64,
    /// Maximum amount allowed for zero-conf
    pub maximal_zero_conf: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Fees {
    /// The percentage of the "send amount" that is charged by Boltz as "Boltz Fee".
    percentage: f64,
    /// The network fees charged for locking up and claiming funds onchain. These values are absolute, denominated in 10 ** -8 of the quote asset.
    miner_fees: u64,
}

/// Various swap parameters associated with different assets.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SwapParams {
    /// Pair hash, representing an id for an asset-pair swap
    pub hash: String,
    /// The exchange rate of the pair
    pub rate: f64,
    /// The swap limits
    pub limits: Limits,
    /// Total fees required for the swap
    pub fees: Fees,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapResponse {
    #[serde(rename = "BTC")]
    btc: HashMap<String, SwapParams>,
    #[serde(rename = "L-BTC")]
    lbtc: HashMap<String, SwapParams>,
}

/// Reference Documnetation: https://docs.boltz.exchange/v/api/
pub struct BoltzApiClientV2 {
    base_url: String,
}

impl BoltzApiClientV2 {
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.to_string(),
        }
    }

    /// Returns the web socket connection to the boltz server
    pub fn connect_ws(&self) -> Result<WebSocket<MaybeTlsStream<TcpStream>>, Error> {
        let ws_string = self.base_url.clone().replace("http", "ws") + "/ws";
        let (socket, response) = connect(Url::parse(&ws_string)?)?;
        log::debug!("websocket response: {:?}", response);
        Ok(socket)
    }

    /// Make a get request. returns the Response
    fn get(&self, end_point: &str) -> Result<String, Error> {
        let url = format!("{}/{}", self.base_url, end_point);
        Ok(ureq::get(&url).call()?.into_string()?)
    }

    /// Make a Post request. Returns the Response
    fn post(&self, end_point: &str, data: impl Serialize) -> Result<String, Error> {
        let url = format!("{}/{}", self.base_url, end_point);
        Ok(ureq::post(&url).send_json(data)?.into_string()?)
    }

    pub fn get_fee_estimation(&self) -> Result<GetFeeEstimationResponse, Error> {
        Ok(serde_json::from_str(&self.get("chain/fees")?)?)
    }

    pub fn get_height(&self) -> Result<HeightResponse, Error> {
        Ok(serde_json::from_str(&self.get("chain/heights")?)?)
    }

    pub fn get_pairs(&self) -> Result<SwapResponse, Error> {
        Ok(serde_json::from_str(&self.get("swap/submarine")?)?)
    }

    pub fn post_swap_req(
        &self,
        swap_request: CreateSwapRequest,
    ) -> Result<CreateSwapResponse, Error> {
        let data = serde_json::to_value(swap_request)?;
        Ok(serde_json::from_str(&self.post("swap/submarine", data)?)?)
    }

    pub fn get_claim_tx_details(&self, id: &String) -> Result<ClaimTxResponse, Error> {
        let endpoint = format!("swap/submarine/{}/claim", id);
        Ok(serde_json::from_str(&self.get(&endpoint)?)?)
    }

    pub fn post_claim_tx_details(
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
        let endpoint = format!("swap/submarine/{}/claim", id);
        Ok(serde_json::from_str(&self.post(&endpoint, data)?)?)
    }

    pub fn post_reverse_req(&self, req: CreateReverseReq) -> Result<ReverseResp, Error> {
        Ok(serde_json::from_str(&self.post("swap/reverse", req)?)?)
    }

    pub fn get_reverse_tx(&self, id: &String) -> Result<ReverseSwapTxResp, Error> {
        Ok(serde_json::from_str(
            &self.get(&format!("swap/reverse/{}/transaction", id))?,
        )?)
    }

    pub fn get_reverse_partial_sig(
        &self,
        id: &String,
        preimage: &Preimage,
        pub_nonce: &MusigPubNonce,
        claim_tx_hex: &String,
    ) -> Result<ReversePartialSig, Error> {
        let data = json!(
            {
                "preimage": preimage.bytes.expect("expected").to_lower_hex_string(),
                "pubNonce": pub_nonce.serialize().to_lower_hex_string(),
                "transaction": claim_tx_hex,
                "index": 0
            }
        );

        let endpoint = format!("swap/reverse/{}/claim", id);
        Ok(serde_json::from_str(&self.post(&endpoint, data)?)?)
    }

    pub fn broadcast_tx(&self, chain: Chain, tx_hex: &String) -> Result<Value, Error> {
        let data = json!(
            {
                "hex": tx_hex
            }
        );

        let chain = match chain {
            Chain::Bitcoin | Chain::BitcoinRegtest | Chain::BitcoinTestnet => "BTC",
            Chain::Liquid | Chain::LiquidTestnet => "L-BTC",
        };

        let end_point = format!("chain/{}/transaction", chain);
        Ok(serde_json::from_str(&self.post(&end_point, data)?)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClaimTxResponse {
    pub preimage: String,
    pub pub_nonce: String,
    pub public_key: PublicKey,
    pub transaction_hash: String,
}

/// Various swap parameters associated with different assets.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ClaimTxData {
    /// Pair hash, representing an id for an asset-pair swap
    pub hash: String,
    /// The exchange rate of the pair
    pub rate: f64,
    /// The swap limits
    pub limits: Limits,
    /// Total fees required for the swap
    pub fees: Fees,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSwapRequest {
    pub from: String,
    pub to: String,
    pub invoice: String,
    pub refund_public_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSwapResponse {
    accept_zero_conf: bool,
    pub address: String,
    bip21: String,
    pub claim_public_key: PublicKey,
    pub expected_amount: u64,
    pub id: String,
    pub swap_tree: SwapTree,
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
    pub output: ScriptBuf,
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    op: String,
    channel: String,
    args: Vec<String>,
}

impl Subscription {
    pub fn new(id: &String) -> Self {
        Self {
            op: "subscribe".to_string(),
            channel: "swap.update".to_string(),
            args: vec![id.clone()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateReverseReq {
    pub invoice_amount: u32,
    pub from: String,
    pub to: String,
    pub preimage_hash: sha256::Hash,
    pub claim_public_key: PublicKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseResp {
    pub id: String,
    pub invoice: String,
    pub swap_tree: SwapTree,
    pub lockup_address: String,
    pub refund_public_key: PublicKey,
    pub timeout_block_height: u32,
    pub onchain_amount: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseSwapTxResp {
    pub id: String,
    pub hex: String,
    pub timeout_block_height: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReversePartialSig {
    pub pub_nonce: String,
    pub partial_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Update {
    pub id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RespError {
    pub id: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SwapUpdate {
    Subscription {
        event: String,
        channel: String,
        args: Vec<String>,
    },
    Update {
        event: String,
        channel: String,
        args: Vec<Update>,
    },
    Error {
        event: String,
        channel: String,
        args: Vec<RespError>,
    },
}
