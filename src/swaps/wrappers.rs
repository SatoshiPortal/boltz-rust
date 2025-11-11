use std::str::FromStr;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Keypair;
use bitcoin::{consensus, Amount, Transaction as BtcTransaction};
use elements::{Sequence, Transaction as LbtcTransaction};
use lightning_invoice::Bolt11Invoice;
use secp256k1_musig::musig;
use serde_json::Value;

use super::boltz::{
    BoltzApiClientV2, ChainSwapDetails, Cooperative, CreateReverseResponse,
    CreateSubmarineResponse, Side, SwapTxKind, SwapType,
};
use crate::boltz::{CreateChainResponse, TransactionInfo};
use crate::error::Error;
use crate::network::{BitcoinClient, Chain, LiquidClient};
use crate::swaps::bitcoin::{BtcSwapScript, BtcSwapTx};
use crate::swaps::liquid::{LBtcSwapScript, LBtcSwapTx};
use crate::util::fees::Fee;
use crate::util::secrets::Preimage;

#[derive(Clone, Debug)]
struct ChainClaim {
    refund_keys: Keypair,
    lockup_script: SwapScript,
}

#[derive(Clone, Debug)]
pub struct TransactionOptions {
    cooperative: bool,
    chain_claim: Option<ChainClaim>,
    lockup_tx: Option<BtcLikeTransaction>,
}

impl Default for TransactionOptions {
    fn default() -> Self {
        Self {
            cooperative: true,
            chain_claim: None,
            lockup_tx: None,
        }
    }
}

impl TransactionOptions {
    /// Whether a cooperative claim with boltz should be attempted
    pub fn with_cooperative(mut self, cooperative: bool) -> Self {
        self.cooperative = cooperative;
        self
    }

    /// For a cooperative claim of a chain swap, the refund keys and lockup script of the swap have to be provided
    /// Calling this function will implicitly set cooperative to true
    pub fn with_chain_claim(mut self, refund_keys: Keypair, lockup_script: SwapScript) -> Self {
        self.cooperative = true;
        self.chain_claim = Some(ChainClaim {
            refund_keys,
            lockup_script,
        });
        self
    }

    pub fn with_lockup_tx(mut self, lockup_tx: BtcLikeTransaction) -> Self {
        self.lockup_tx = Some(lockup_tx);
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
    pub fn from_hex(chain: Chain, hex: &str) -> Result<Self, Error> {
        match chain {
            Chain::Bitcoin(_) => Self::from_hex_bitcoin(hex),
            Chain::Liquid(_) => Self::from_hex_liquid(hex),
        }
    }

    pub fn from_hex_bitcoin(hex: &str) -> Result<Self, Error> {
        let decoded = hex::decode(hex)?;
        Ok(Self::bitcoin(consensus::deserialize(&decoded)?))
    }

    pub fn signals_rbf(&self) -> bool {
        match self {
            Self::Bitcoin(_) => true,
            Self::Liquid(tx) => tx.input.iter().any(|input| input.sequence != Sequence::MAX),
        }
    }

    pub fn from_hex_liquid(hex: &str) -> Result<Self, Error> {
        let decoded = hex::decode(hex)?;
        Ok(Self::liquid(elements::encode::deserialize(&decoded)?))
    }

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
pub struct ChainClient {
    bitcoin: Option<Box<dyn BitcoinClient>>,
    liquid: Option<Box<dyn LiquidClient>>,
}

impl Default for ChainClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainClient {
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

    pub fn bitcoin_client(&self) -> Option<&dyn BitcoinClient> {
        self.bitcoin.as_deref()
    }

    pub fn liquid_client(&self) -> Option<&dyn LiquidClient> {
        self.liquid.as_deref()
    }

    fn require_bitcoin_client(&self) -> Result<&dyn BitcoinClient, Error> {
        self.bitcoin_client()
            .ok_or_else(|| Error::Generic("Expected Bitcoin client".to_string()))
    }

    fn require_liquid_client(&self) -> Result<&dyn LiquidClient, Error> {
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

    pub async fn try_broadcast_tx(&self, tx: &BtcLikeTransaction) -> Result<(), Error> {
        match self.broadcast_tx(tx).await {
            Ok(_) => Ok(()),
            Err(e) => {
                if e.message().contains("already in block chain")
                    || e.message().contains("already in utxo set")
                {
                    Ok(())
                } else {
                    Err(e)
                }
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
    ) -> Result<(musig::PartialSignature, musig::PublicNonce), Error>;
}

/// A wrapper for swap scripts that can be either Bitcoin or Liquid
#[derive(Clone, Debug)]
pub enum SwapScriptImpl {
    Bitcoin(Arc<BtcSwapScript>),
    Liquid(Arc<LBtcSwapScript>),
}

#[derive(Clone, Debug)]
pub struct SwapScript {
    pub script: SwapScriptImpl,
    pub boltz_lockup: Option<Amount>,
    pub swap_id: String,
}

#[derive(Clone)]
pub struct SwapTransactionParams<'a> {
    pub keys: Keypair,
    pub output_address: String,
    pub fee: Fee,
    pub chain_client: &'a ChainClient,
    pub boltz_client: &'a BoltzApiClientV2,
    pub options: Option<TransactionOptions>,
}

impl SwapScriptImpl {
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
}

impl SwapScript {
    pub fn new(script: SwapScriptImpl, boltz_lockup: Option<Amount>, swap_id: String) -> Self {
        Self {
            script,
            boltz_lockup,
            swap_id,
        }
    }

    pub fn submarine_from_swap_resp(
        chain: Chain,
        create_swap_response: &CreateSubmarineResponse,
        our_pubkey: bitcoin::PublicKey,
    ) -> Result<Self, Error> {
        let script: Result<SwapScriptImpl, Error> = match chain {
            Chain::Bitcoin(_) => {
                let script =
                    BtcSwapScript::submarine_from_swap_resp(create_swap_response, our_pubkey)?;
                Ok(SwapScriptImpl::bitcoin(script))
            }
            Chain::Liquid(_) => {
                let script =
                    LBtcSwapScript::submarine_from_swap_resp(create_swap_response, our_pubkey)?;
                Ok(SwapScriptImpl::liquid(script))
            }
        };
        // we dont have to validate our own lockup amounts
        Ok(Self::new(script?, None, create_swap_response.id.clone()))
    }

    pub fn reverse_from_swap_resp(
        chain: Chain,
        reverse_response: &CreateReverseResponse,
        our_pubkey: bitcoin::PublicKey,
    ) -> Result<Self, Error> {
        let script: Result<SwapScriptImpl, Error> = match chain {
            Chain::Bitcoin(_) => {
                let script = BtcSwapScript::reverse_from_swap_resp(reverse_response, our_pubkey)?;
                Ok(SwapScriptImpl::bitcoin(script))
            }
            Chain::Liquid(_) => {
                let script = LBtcSwapScript::reverse_from_swap_resp(reverse_response, our_pubkey)?;
                Ok(SwapScriptImpl::liquid(script))
            }
        };
        Ok(Self::new(
            script?,
            Some(Amount::from_sat(reverse_response.onchain_amount)),
            reverse_response.id.clone(),
        ))
    }

    pub fn chain_from_swap_resp(
        swap_id: String,
        chain: Chain,
        side: Side,
        chain_swap_details: ChainSwapDetails,
        our_pubkey: bitcoin::PublicKey,
    ) -> Result<Self, Error> {
        let amount = chain_swap_details.amount;
        let script: Result<SwapScriptImpl, Error> = match chain {
            Chain::Bitcoin(_) => {
                let script =
                    BtcSwapScript::chain_from_swap_resp(side, chain_swap_details, our_pubkey)?;
                Ok(SwapScriptImpl::bitcoin(script))
            }
            Chain::Liquid(_) => {
                let script =
                    LBtcSwapScript::chain_from_swap_resp(side, chain_swap_details, our_pubkey)?;
                Ok(SwapScriptImpl::liquid(script))
            }
        };
        Ok(Self::new(
            script?,
            if amount > 0 {
                Some(Amount::from_sat(amount))
            } else {
                None
            },
            swap_id,
        ))
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
        if self.script.common().swap_type() != SwapType::Submarine {
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
        let (partial_sig, pub_nonce) = self.script.common().partial_sign(
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
        boltz_api: &'a BoltzApiClientV2,
    ) -> Result<Cooperative<'a>, Error> {
        let signature: Option<(musig::PartialSignature, musig::PublicNonce)> = match boltz_api
            .get_chain_claim_tx_details(&self.swap_id)
            .await
        {
            Ok(claim_tx_response) => Some(self.script.common().partial_sign(
                our_refund_keys,
                &claim_tx_response.pub_nonce,
                &claim_tx_response.transaction_hash,
            )?),
            Err(Error::JSON(e)) => {
                log::warn!("Failed to parse chain claim tx details: {e} - continuing without signature as we may have already sent it");
                None
            }
            Err(e) => {
                return Err(e);
            }
        };

        Ok(Cooperative {
            boltz_api,
            swap_id: self.swap_id.clone(),
            signature,
        })
    }

    async fn get_cooperative<'a>(
        &self,
        tx_kind: SwapTxKind,
        options: Option<TransactionOptions>,
        boltz_client: &'a BoltzApiClientV2,
    ) -> Result<Option<Cooperative<'a>>, Error> {
        let o = options.unwrap_or_default();
        match o.cooperative {
            true => match (self.script.common().swap_type(), tx_kind) {
                (SwapType::Chain, SwapTxKind::Claim) => {
                    let claim = o.chain_claim.ok_or(Error::Generic(
                        "Chain claim options are missing".to_string(),
                    ))?;
                    claim
                        .lockup_script
                        .cooperative_chain_claim(&claim.refund_keys, boltz_client)
                        .await
                        .map(Option::Some)
                }
                _ => Ok(Some(Cooperative {
                    boltz_api: boltz_client,
                    swap_id: self.swap_id.clone(),
                    signature: None,
                })),
            },
            false => Ok(None),
        }
    }

    pub async fn check_lockup(
        &self,
        chain_client: &ChainClient,
        lockup_tx: &BtcLikeTransaction,
    ) -> Result<(), Error> {
        chain_client.try_broadcast_tx(lockup_tx).await?;

        Ok(())
    }

    pub async fn parse_lockup_transaction(
        &self,
        lockup_info: &TransactionInfo,
    ) -> Result<BtcLikeTransaction, Error> {
        let hex = lockup_info
            .hex
            .as_ref()
            .ok_or(Error::Generic("Lockup info is missing".to_string()))?;
        match self.script.clone() {
            SwapScriptImpl::Bitcoin(_) => BtcLikeTransaction::from_hex_bitcoin(hex),
            SwapScriptImpl::Liquid(_) => BtcLikeTransaction::from_hex_liquid(hex),
        }
    }

    fn validate_amount(&self, amount: Amount) -> Result<(), Error> {
        if let Some(boltz_lockup) = self.boltz_lockup {
            if amount != boltz_lockup {
                return Err(Error::Protocol(format!(
                    "Lockup amount mismatch: {} != {}",
                    amount, boltz_lockup
                )));
            }
        }
        Ok(())
    }

    pub async fn construct_claim(
        &self,
        preimage: &Preimage,
        params: SwapTransactionParams<'_>,
    ) -> Result<BtcLikeTransaction, Error> {
        let cooperative = self
            .get_cooperative(
                SwapTxKind::Claim,
                params.options.clone(),
                params.boltz_client,
            )
            .await?;
        let lockup_tx = params.options.clone().and_then(|o| o.lockup_tx);
        if let Some(lockup_tx) = lockup_tx.clone() {
            params.chain_client.try_broadcast_tx(&lockup_tx).await?;
        }
        match self.script.clone() {
            SwapScriptImpl::Bitcoin(script) => {
                let chain_client = params.chain_client.require_bitcoin_client()?;

                let utxo = script
                    .fetch_swap_utxo(
                        lockup_tx
                            .as_ref()
                            .map(|tx| {
                                tx.as_bitcoin().ok_or(Error::Generic(
                                    "Lockup transaction is not a Bitcoin transaction".to_string(),
                                ))
                            })
                            .transpose()?,
                        chain_client,
                        params.boltz_client,
                        &self.swap_id,
                        SwapTxKind::Claim,
                    )
                    .await?;

                self.validate_amount(utxo.1.value)?;

                let tx = BtcSwapTx::new_claim_with_utxo(
                    script.as_ref().clone(),
                    params.output_address.clone(),
                    chain_client,
                    utxo,
                )?;

                tx.sign_claim(&params.keys, preimage, params.fee, cooperative)
                    .await
                    .map(BtcLikeTransaction::bitcoin)
            }
            SwapScriptImpl::Liquid(script) => {
                let chain_client = params.chain_client.require_liquid_client()?;

                let utxo = script
                    .fetch_swap_utxo(
                        lockup_tx
                            .as_ref()
                            .map(|tx| {
                                tx.as_liquid().ok_or(Error::Generic(
                                    "Lockup transaction is not a Liquid transaction".to_string(),
                                ))
                            })
                            .transpose()?,
                        chain_client,
                        params.boltz_client,
                        &self.swap_id,
                        SwapTxKind::Claim,
                    )
                    .await?;

                if self.boltz_lockup.is_some() {
                    let secp = Secp256k1::new();
                    let secrets = utxo.1.unblind(&secp, script.blinding_key.secret_key())?;
                    self.validate_amount(Amount::from_sat(secrets.value))?;
                }

                let tx = LBtcSwapTx::new_claim_with_utxo(
                    script.as_ref().clone(),
                    params.output_address.clone(),
                    chain_client,
                    utxo,
                )
                .await?;

                tx.sign_claim(&params.keys, preimage, params.fee, cooperative, true)
                    .await
                    .map(BtcLikeTransaction::liquid)
            }
        }
    }

    pub async fn construct_refund(
        &self,
        params: SwapTransactionParams<'_>,
    ) -> Result<BtcLikeTransaction, Error> {
        let cooperative = self
            .get_cooperative(SwapTxKind::Refund, params.options, params.boltz_client)
            .await?;

        match self.script.clone() {
            SwapScriptImpl::Bitcoin(script) => {
                let tx = BtcSwapTx::new_refund(
                    script.as_ref().clone(),
                    &params.output_address,
                    params.chain_client.require_bitcoin_client()?,
                    params.boltz_client,
                    self.swap_id.clone(),
                )
                .await?;
                tx.sign_refund(&params.keys, params.fee, cooperative)
                    .await
                    .map(BtcLikeTransaction::bitcoin)
            }
            SwapScriptImpl::Liquid(script) => {
                let tx = LBtcSwapTx::new_refund(
                    script.as_ref().clone(),
                    &params.output_address,
                    params.chain_client.require_liquid_client()?,
                    params.boltz_client,
                    self.swap_id.clone(),
                )
                .await?;
                tx.sign_refund(&params.keys, params.fee, cooperative, true)
                    .await
                    .map(BtcLikeTransaction::liquid)
            }
        }
    }
}
