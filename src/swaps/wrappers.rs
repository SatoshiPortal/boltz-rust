use std::str::FromStr;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::Keypair;
use bitcoin::Transaction as BtcTransaction;
use elements::secp256k1_zkp::{MusigPartialSignature, MusigPubNonce};
use elements::Transaction as LbtcTransaction;
use lightning_invoice::Bolt11Invoice;
use serde_json::Value;

use super::boltz::{
    BoltzApiClientV2, ChainSwapDetails, Cooperative, CreateReverseResponse,
    CreateSubmarineResponse, Side, SwapType,
};
use crate::error::Error;
use crate::network::{BitcoinClient, Chain, LiquidClient};
use crate::swaps::bitcoin::{BtcSwapScript, BtcSwapTx};
use crate::swaps::liquid::{LBtcSwapScript, LBtcSwapTx};
use crate::util::fees::Fee;
use crate::util::secrets::Preimage;

/// Options for signing swap transactions
#[derive(Clone, Debug, Default)]
pub struct TransactionOptions {
    /// Whether to use discount confidential transactions for Liquid swaps
    pub is_discount_ct: bool,
}

impl TransactionOptions {
    pub fn with_discount_ct(mut self) -> Self {
        self.is_discount_ct = true;
        self
    }
}

/// A wrapper for transactions that can be either Bitcoin or Liquid
#[derive(Clone, Debug)]
pub enum BtcLikeTransaction {
    Bitcoin(BtcTransaction),
    Liquid(LbtcTransaction),
}

impl BtcLikeTransaction {
    pub fn bitcoin(tx: BtcTransaction) -> Self {
        Self::Bitcoin(tx)
    }

    pub fn liquid(tx: LbtcTransaction) -> Self {
        Self::Liquid(tx)
    }

    pub fn as_bitcoin(&self) -> Option<&BtcTransaction> {
        match self {
            Self::Bitcoin(tx) => Some(tx),
            Self::Liquid(_) => None,
        }
    }

    pub fn as_liquid(&self) -> Option<&LbtcTransaction> {
        match self {
            Self::Bitcoin(_) => None,
            Self::Liquid(tx) => Some(tx),
        }
    }
}

/// A wrapper for blockchain clients that can be either Bitcoin or Liquid
pub struct Client {
    bitcoin: Option<Box<dyn BitcoinClient>>,
    liquid: Option<Box<dyn LiquidClient>>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            bitcoin: None,
            liquid: None,
        }
    }

    pub fn with_bitcoin(mut self, client: impl BitcoinClient + 'static) -> Self {
        self.bitcoin = Some(Box::new(client));
        self
    }

    pub fn with_liquid(mut self, client: impl LiquidClient + 'static) -> Self {
        self.liquid = Some(Box::new(client));
        self
    }

    pub fn bitcoin_client(&self) -> Option<&(dyn BitcoinClient)> {
        self.bitcoin.as_deref()
    }

    pub fn liquid_client(&self) -> Option<&(dyn LiquidClient)> {
        self.liquid.as_deref()
    }

    fn require_bitcoin_client(&self) -> Result<&(dyn BitcoinClient), Error> {
        self.bitcoin_client()
            .ok_or_else(|| Error::Generic("Expected Bitcoin client".to_string()))
    }

    fn require_liquid_client(&self) -> Result<&(dyn LiquidClient), Error> {
        self.liquid_client()
            .ok_or_else(|| Error::Generic("Expected Liquid client".to_string()))
    }

    pub async fn broadcast_tx(&self, tx: &BtcLikeTransaction) -> Result<String, Error> {
        match tx {
            BtcLikeTransaction::Bitcoin(tx) => {
                let id = self.require_bitcoin_client()?.broadcast_tx(tx).await?;
                Ok(id.to_string())
            }
            BtcLikeTransaction::Liquid(tx) => {
                let id = self.require_liquid_client()?.broadcast_tx(tx).await?;
                Ok(id)
            }
        }
    }
}

/// Trait for common functionality between Bitcoin and Liquid swap transactions
pub trait SwapScriptCommon {
    fn swap_type(&self) -> SwapType;

    fn partial_sign(
        &self,
        keys: &Keypair,
        pub_nonce: &str,
        transaction_hash: &str,
    ) -> Result<(MusigPartialSignature, MusigPubNonce), Error>;
}

/// A wrapper for swap scripts that can be either Bitcoin or Liquid
#[derive(Clone, Debug)]
pub enum SwapScript {
    Bitcoin(Arc<BtcSwapScript>),
    Liquid(Arc<LBtcSwapScript>),
}

impl SwapScript {
    pub fn bitcoin(script: BtcSwapScript) -> Self {
        Self::Bitcoin(Arc::new(script))
    }

    pub fn liquid(script: LBtcSwapScript) -> Self {
        Self::Liquid(Arc::new(script))
    }

    pub fn common(&self) -> &dyn SwapScriptCommon {
        match self {
            Self::Bitcoin(script) => script.as_ref(),
            Self::Liquid(script) => script.as_ref(),
        }
    }

    pub fn submarine_from_swap_resp(
        chain: Chain,
        create_swap_response: &CreateSubmarineResponse,
        our_pubkey: bitcoin::PublicKey,
    ) -> Result<Self, Error> {
        match chain {
            Chain::Bitcoin(_) => {
                let script =
                    BtcSwapScript::submarine_from_swap_resp(create_swap_response, our_pubkey)?;
                Ok(Self::bitcoin(script))
            }
            Chain::Liquid(_) => {
                let script =
                    LBtcSwapScript::submarine_from_swap_resp(create_swap_response, our_pubkey)?;
                Ok(Self::liquid(script))
            }
        }
    }

    pub fn reverse_from_swap_resp(
        chain: Chain,
        reverse_response: &CreateReverseResponse,
        our_pubkey: bitcoin::PublicKey,
    ) -> Result<Self, Error> {
        match chain {
            Chain::Bitcoin(_) => {
                let script = BtcSwapScript::reverse_from_swap_resp(reverse_response, our_pubkey)?;
                Ok(Self::bitcoin(script))
            }
            Chain::Liquid(_) => {
                let script = LBtcSwapScript::reverse_from_swap_resp(reverse_response, our_pubkey)?;
                Ok(Self::liquid(script))
            }
        }
    }

    pub fn chain_from_swap_resp(
        chain: Chain,
        side: Side,
        chain_swap_details: ChainSwapDetails,
        our_pubkey: bitcoin::PublicKey,
    ) -> Result<Self, Error> {
        match chain {
            Chain::Bitcoin(_) => {
                let script =
                    BtcSwapScript::chain_from_swap_resp(side, chain_swap_details, our_pubkey)?;
                Ok(Self::bitcoin(script))
            }
            Chain::Liquid(_) => {
                let script =
                    LBtcSwapScript::chain_from_swap_resp(side, chain_swap_details, our_pubkey)?;
                Ok(Self::liquid(script))
            }
        }
    }

    /// Cooperatively claim a submarine swap with Boltz.
    ///
    /// This function should be called when the swap status is `transaction.claim.pending`, indicating
    /// that Boltz has detected the on-chain funding transaction and has paid the invoice.
    /// The function will verify that boltz indeed has paid the given `invoice` by checking the returned preimage
    /// before sending the partial signature for the claim transaction of boltz.
    pub async fn submarine_cooperative_claim(
        &self,
        swap_id: &String,
        keys: &Keypair,
        invoice: &str,
        boltz_api: &BoltzApiClientV2,
    ) -> Result<Value, Error> {
        if self.common().swap_type() != SwapType::Submarine {
            return Err(Error::Generic(
                "can only be called for submarine swaps".to_string(),
            ));
        }
        // Get claim tx details from Boltz
        let claim_tx_response = boltz_api.get_submarine_claim_tx_details(swap_id).await?;

        log::debug!("Received claim tx details : {claim_tx_response:?}");

        let preimage = Vec::from_hex(&claim_tx_response.preimage)?;

        // Verify preimage matches invoice payment hash
        let preimage_hash = sha256::Hash::hash(&preimage);
        let invoice = Bolt11Invoice::from_str(invoice)?;
        let invoice_payment_hash = invoice.payment_hash();
        if invoice_payment_hash.to_string() != preimage_hash.to_string() {
            return Err(Error::Protocol(
                "Preimage does not match invoice payment hash".to_string(),
            ));
        }

        // Generate partial signature
        let (partial_sig, pub_nonce) = self.common().partial_sign(
            keys,
            &claim_tx_response.pub_nonce.to_string(),
            &claim_tx_response.transaction_hash.to_string(),
        )?;

        boltz_api
            .post_submarine_claim_tx_details(swap_id, pub_nonce, partial_sig)
            .await
    }

    // Initiates a cooperative claim for a chain swap with Boltz.
    //
    // This function should be called when the swap status is `transaction.server.confirmed`,
    // It creates a partial signature for boltz's side of the transaction, and returns a Cooperative struct which
    // can be passed to `sign_claim` where it is used in exchange for the signature for our own claim transaction.
    pub async fn cooperative_chain_claim<'a>(
        &self,
        our_refund_keys: &Keypair,
        swap_id: &String,
        boltz_api: &'a BoltzApiClientV2,
    ) -> Result<Cooperative<'a>, Error> {
        let claim_tx_response = boltz_api.get_chain_claim_tx_details(swap_id).await?;
        let (partial_sig, pub_nonce) = self.common().partial_sign(
            our_refund_keys,
            &claim_tx_response.pub_nonce,
            &claim_tx_response.transaction_hash,
        )?;
        Ok(Cooperative {
            boltz_api,
            swap_id: swap_id.clone(),
            pub_nonce: Some(pub_nonce),
            partial_sig: Some(partial_sig),
        })
    }
}

/// A wrapper for swap transactions that can be either Bitcoin or Liquid
#[derive(Clone, Debug)]
pub enum SwapTx {
    Bitcoin(Arc<BtcSwapTx>),
    Liquid(Arc<LBtcSwapTx>),
}

impl SwapTx {
    pub fn bitcoin(tx: BtcSwapTx) -> Self {
        Self::Bitcoin(Arc::new(tx))
    }

    pub fn liquid(tx: LBtcSwapTx) -> Self {
        Self::Liquid(Arc::new(tx))
    }

    pub async fn sign_refund(
        &self,
        keys: &Keypair,
        fee: Fee,
        is_cooperative: Option<Cooperative<'_>>,
        options: Option<TransactionOptions>,
    ) -> Result<BtcLikeTransaction, Error> {
        match self {
            Self::Bitcoin(tx) => {
                let tx = tx.sign_refund(keys, fee, is_cooperative).await?;
                Ok(BtcLikeTransaction::bitcoin(tx))
            }
            Self::Liquid(tx) => {
                let is_discount_ct = options.map(|o| o.is_discount_ct).unwrap_or_default();
                let tx = tx
                    .sign_refund(keys, fee, is_cooperative, is_discount_ct)
                    .await?;
                Ok(BtcLikeTransaction::liquid(tx))
            }
        }
    }

    pub async fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        fee: Fee,
        is_cooperative: Option<Cooperative<'_>>,
        options: Option<TransactionOptions>,
    ) -> Result<BtcLikeTransaction, Error> {
        match self {
            Self::Bitcoin(tx) => {
                let tx = tx.sign_claim(keys, preimage, fee, is_cooperative).await?;
                Ok(BtcLikeTransaction::bitcoin(tx))
            }
            Self::Liquid(tx) => {
                let is_discount_ct = options.map(|o| o.is_discount_ct).unwrap_or_default();
                let tx = tx
                    .sign_claim(keys, preimage, fee, is_cooperative, is_discount_ct)
                    .await?;
                Ok(BtcLikeTransaction::liquid(tx))
            }
        }
    }

    pub async fn new_claim(
        swap_script: SwapScript,
        output_address: String,
        client: &Client,
        boltz_client: &BoltzApiClientV2,
        swap_id: String,
    ) -> Result<Self, Error> {
        match swap_script {
            SwapScript::Bitcoin(script) => {
                let btc_client = client.require_bitcoin_client()?;
                let tx = BtcSwapTx::new_claim(
                    script.as_ref().clone(),
                    output_address,
                    btc_client,
                    boltz_client,
                    swap_id,
                )
                .await?;
                Ok(Self::bitcoin(tx))
            }
            SwapScript::Liquid(script) => {
                let lbtc_client = client.require_liquid_client()?;
                let tx = LBtcSwapTx::new_claim(
                    script.as_ref().clone(),
                    output_address,
                    lbtc_client,
                    boltz_client,
                    swap_id,
                )
                .await?;
                Ok(Self::liquid(tx))
            }
        }
    }

    pub async fn new_refund(
        swap_script: SwapScript,
        output_address: &str,
        client: &Client,
        boltz_client: &BoltzApiClientV2,
        swap_id: String,
    ) -> Result<Self, Error> {
        match swap_script {
            SwapScript::Bitcoin(script) => {
                let btc_client = client.require_bitcoin_client()?;
                let tx = BtcSwapTx::new_refund(
                    script.as_ref().clone(),
                    output_address,
                    btc_client,
                    boltz_client,
                    swap_id,
                )
                .await?;
                Ok(Self::bitcoin(tx))
            }
            SwapScript::Liquid(script) => {
                let lbtc_client = client.require_liquid_client()?;
                let tx = LBtcSwapTx::new_refund(
                    script.as_ref().clone(),
                    output_address,
                    lbtc_client,
                    boltz_client,
                    swap_id,
                )
                .await?;
                Ok(Self::liquid(tx))
            }
        }
    }
}
