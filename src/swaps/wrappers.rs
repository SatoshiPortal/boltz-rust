use std::str::FromStr;
use std::sync::Arc;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::Keypair;
use bitcoin::{consensus, Amount, Transaction as BtcTransaction};
use elements::{confidential, Transaction as LbtcTransaction};
use secp256k1_musig::musig;
use serde_json::Value;

use super::boltz::{
    BoltzApiClientV2, ChainSwapDetails, Cooperative, CreateReverseResponse,
    CreateSubmarineResponse, Side, SwapTxKind, SwapType,
};
use crate::boltz::TransactionInfo;
use crate::error::Error;
use crate::network::{BitcoinClient, Chain, LiquidChain, LiquidClient, Network};
use crate::swaps::bitcoin::{BtcSwapScript, BtcSwapTx};
use crate::swaps::fees::estimate_claim_fee;
use crate::swaps::liquid::{LBtcSwapScript, LBtcSwapTx};
use crate::util::fees::Fee;
use crate::util::invoice::LightningInvoice;
use crate::util::secrets::Preimage;

#[derive(Clone, Debug)]
struct ChainClaim {
    refund_keys: Keypair,
    lockup_script: SwapScript,
}

#[derive(Clone, Debug, Default)]
pub struct DirectTxOptions {
    blinding_key: Option<bitcoin::secp256k1::SecretKey>,
}

impl DirectTxOptions {
    pub fn new() -> Self {
        Self { blinding_key: None }
    }

    pub fn with_blinding_key(mut self, blinding_key: bitcoin::secp256k1::SecretKey) -> Self {
        self.blinding_key = Some(blinding_key);
        self
    }
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
    script: SwapScriptImpl,
    boltz_lockup: Option<Amount>,
    mrh_amount: Option<Amount>,
}

#[derive(Clone)]
pub struct SwapTransactionParams<'a> {
    pub keys: Keypair,
    pub output_address: String,
    pub fee: Fee,
    pub swap_id: String,
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
    fn new(
        script: SwapScriptImpl,
        boltz_lockup: Option<Amount>,
        mrh_amount: Option<Amount>,
    ) -> Self {
        Self {
            script,
            boltz_lockup,
            mrh_amount,
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
        Ok(Self::new(script?, None, None))
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

        let boltz_lockup = Amount::from_sat(reverse_response.onchain_amount);
        let mrh_amount = match chain {
            Chain::Bitcoin(_) => None,
            Chain::Liquid(_) => Some(boltz_lockup - estimate_claim_fee(chain, 0.1)),
        };
        Ok(Self::new(script?, Some(boltz_lockup), mrh_amount))
    }

    pub fn chain_from_swap_resp(
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
            None,
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
        let invoice = LightningInvoice::from_str(invoice)?;
        if invoice.payment_hash() != preimage_hash.to_string() {
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
        swap_id: &String,
        boltz_api: &'a BoltzApiClientV2,
    ) -> Result<Cooperative<'a>, Error> {
        let signature: Option<(musig::PartialSignature, musig::PublicNonce)> = match boltz_api
            .get_chain_claim_tx_details(swap_id)
            .await
        {
            Ok(claim_tx_response) => {
                if let Some(claim_tx_response) = claim_tx_response {
                    Some(self.script.common().partial_sign(
                        our_refund_keys,
                        &claim_tx_response.pub_nonce,
                        &claim_tx_response.transaction_hash,
                    )?)
                } else {
                    None
                }
            }
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
            swap_id: swap_id.clone(),
            signature,
        })
    }

    async fn get_cooperative<'a>(
        &self,
        tx_kind: SwapTxKind,
        options: Option<TransactionOptions>,
        boltz_client: &'a BoltzApiClientV2,
        swap_id: String,
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
                        .cooperative_chain_claim(&claim.refund_keys, &swap_id, boltz_client)
                        .await
                        .map(Option::Some)
                }
                _ => Ok(Some(Cooperative {
                    boltz_api: boltz_client,
                    swap_id,
                    signature: None,
                })),
            },
            false => Ok(None),
        }
    }

    fn check_direct_transaction_inner(
        mrh_amount: Amount,
        network: Network,
        direct_tx: &BtcLikeTransaction,
        claim_address: &str,
        options: DirectTxOptions,
    ) -> Result<(), Error> {
        let amount = match direct_tx {
            BtcLikeTransaction::Bitcoin(_) => {
                Err(Error::Generic("Not implemented for mainchain".to_string()))
            }
            BtcLikeTransaction::Liquid(tx) => {
                let chain = LiquidChain::from(network);
                let address = elements::Address::parse_with_params(claim_address, chain.into())?;
                let script_pubkey = address.script_pubkey();
                let (_, utxo) = super::liquid::find_utxo(tx, &script_pubkey)
                    .ok_or(Error::Generic("No UTXO found for this script".to_string()))?;
                let secp = Secp256k1::new();
                let (value, asset) = match (utxo.value, utxo.asset) {
                    (
                        confidential::Value::Explicit(value),
                        confidential::Asset::Explicit(asset),
                    ) => (value, asset),
                    (
                        confidential::Value::Confidential(_),
                        confidential::Asset::Confidential(_),
                    ) => {
                        let secrets = utxo.unblind(
                            &secp,
                            options.blinding_key.ok_or(Error::Generic(
                                "Blinding key is required for confidential UTXO".to_string(),
                            ))?,
                        )?;
                        (secrets.value, secrets.asset)
                    }
                    (_, _) => {
                        return Err(Error::Generic("Inconsistent blinding".to_string()));
                    }
                };
                if asset != chain.bitcoin() {
                    return Err(Error::Protocol(format!("Asset is not bitcoin: {asset}")));
                }
                Ok(Amount::from_sat(value))
            }
        }?;

        if amount < mrh_amount {
            return Err(Error::Protocol(format!(
                "Amount received via direct transaction is less than expected: {amount} < {mrh_amount}",
            )));
        }
        Ok(())
    }

    pub async fn check_direct_transaction(
        &self,
        chain_client: &ChainClient,
        network: Network,
        direct_tx: &BtcLikeTransaction,
        claim_address: &str,
        options: DirectTxOptions,
    ) -> Result<(), Error> {
        chain_client.try_broadcast_tx(direct_tx).await?;
        if let Some(mrh_amount) = self.mrh_amount {
            return SwapScript::check_direct_transaction_inner(
                mrh_amount,
                network,
                direct_tx,
                claim_address,
                options,
            );
        }
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

    fn validate_lockup_amount(&self, amount: Amount) -> Result<(), Error> {
        if let Some(boltz_lockup) = self.boltz_lockup {
            if amount != boltz_lockup {
                return Err(Error::Protocol(format!(
                    "Lockup amount mismatch: {amount} != {boltz_lockup}",
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
                params.swap_id.clone(),
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
                        &params.swap_id,
                        SwapTxKind::Claim,
                    )
                    .await?;

                self.validate_lockup_amount(utxo.1.value)?;

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
                        &params.swap_id,
                        SwapTxKind::Claim,
                    )
                    .await?;

                if self.boltz_lockup.is_some() {
                    let secrets = super::liquid::unblind_utxo(
                        chain_client.network(),
                        utxo.1.clone(),
                        script.blinding_key.secret_key(),
                    )?;
                    self.validate_lockup_amount(Amount::from_sat(secrets.value))?;
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
            .get_cooperative(
                SwapTxKind::Refund,
                params.options,
                params.boltz_client,
                params.swap_id.clone(),
            )
            .await?;

        match self.script.clone() {
            SwapScriptImpl::Bitcoin(script) => {
                let tx = BtcSwapTx::new_refund(
                    script.as_ref().clone(),
                    &params.output_address,
                    params.chain_client.require_bitcoin_client()?,
                    params.boltz_client,
                    params.swap_id.clone(),
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
                    params.swap_id.clone(),
                )
                .await?;
                tx.sign_refund(&params.keys, params.fee, cooperative, true)
                    .await
                    .map(BtcLikeTransaction::liquid)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use elements::{
        confidential::Value, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness, TxOut,
        TxOutWitness,
    };

    // Helper function to generate a regtest address
    fn generate_regtest_address() -> String {
        use bitcoin::key::rand::thread_rng;
        let network = Network::Regtest;
        let chain = LiquidChain::from(network);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::new(&secp, &mut thread_rng());

        let addr = elements::Address::p2wpkh(
            &elements::bitcoin::PublicKey::new(keypair.public_key()),
            None,
            chain.into(),
        );

        addr.to_string()
    }

    // Helper function to create a Liquid transaction with explicit value
    fn create_liquid_tx_explicit(address: &str, amount: u64) -> BtcLikeTransaction {
        let network = Network::Regtest;
        let chain = LiquidChain::from(network);
        let addr = elements::Address::parse_with_params(address, chain.into()).unwrap();
        let script_pubkey = addr.script_pubkey();

        // Use the regtest LBTC asset
        let asset = chain.bitcoin();

        let tx = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                asset_issuance: elements::AssetIssuance::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: Value::Explicit(amount),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: script_pubkey.clone(),
                    witness: TxOutWitness::default(),
                },
                // Add a fee output
                TxOut {
                    asset: confidential::Asset::Explicit(asset),
                    value: Value::Explicit(1000),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: TxOutWitness::default(),
                },
            ],
        };

        BtcLikeTransaction::Liquid(tx)
    }

    #[test]
    fn test_check_direct_transaction_bitcoin_not_implemented() {
        let btc_tx = BtcLikeTransaction::Bitcoin(bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        });

        let result = SwapScript::check_direct_transaction_inner(
            Amount::from_sat(100_000),
            Network::Regtest,
            &btc_tx,
            "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
            DirectTxOptions::new(),
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Not implemented for mainchain"));
    }

    #[test]
    fn test_check_direct_transaction_liquid_explicit_success() {
        let address = generate_regtest_address();
        let amount = 100_000;

        let liquid_tx = create_liquid_tx_explicit(&address, amount);

        let result = SwapScript::check_direct_transaction_inner(
            Amount::from_sat(amount),
            Network::Regtest,
            &liquid_tx,
            &address,
            DirectTxOptions::new(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_check_direct_transaction_liquid_wrong_asset() {
        let address = generate_regtest_address();
        let amount = 100_000;

        // Create a transaction with the wrong asset
        let network = Network::Regtest;
        let chain = LiquidChain::from(network);
        let addr = elements::Address::parse_with_params(&address, chain.into()).unwrap();
        let script_pubkey = addr.script_pubkey();

        // Use a wrong asset ID (just some random asset, not the regtest LBTC)
        let wrong_asset = elements::AssetId::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001",
        )
        .unwrap();

        let tx = Transaction {
            version: 2,
            lock_time: elements::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::default(),
                is_pegin: false,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                asset_issuance: elements::AssetIssuance::default(),
                witness: TxInWitness::default(),
            }],
            output: vec![
                TxOut {
                    asset: confidential::Asset::Explicit(wrong_asset),
                    value: Value::Explicit(amount),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: script_pubkey.clone(),
                    witness: TxOutWitness::default(),
                },
                // Add a fee output
                TxOut {
                    asset: confidential::Asset::Explicit(wrong_asset),
                    value: Value::Explicit(1000),
                    nonce: confidential::Nonce::Null,
                    script_pubkey: Script::new(),
                    witness: TxOutWitness::default(),
                },
            ],
        };

        let liquid_tx = BtcLikeTransaction::Liquid(tx);

        let result = SwapScript::check_direct_transaction_inner(
            Amount::from_sat(amount),
            Network::Regtest,
            &liquid_tx,
            &address,
            DirectTxOptions::new(),
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("asset") || err_msg.contains("Asset"));
    }

    #[test]
    fn test_check_direct_transaction_liquid_no_utxo_found() {
        let tx_address = generate_regtest_address();
        let different_address = generate_regtest_address();

        let liquid_tx = create_liquid_tx_explicit(&tx_address, 100_000);

        let result = SwapScript::check_direct_transaction_inner(
            Amount::from_sat(100_000),
            Network::Regtest,
            &liquid_tx,
            &different_address,
            DirectTxOptions::new(),
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No UTXO found for this script"));
    }

    #[test]
    fn test_check_direct_transaction_amount_validation_less_than_expected() {
        let expected_amount = Amount::from_sat(100_000);
        let address = generate_regtest_address();
        let actual_amount = 50_000; // Less than expected

        let liquid_tx = create_liquid_tx_explicit(&address, actual_amount);

        let result = SwapScript::check_direct_transaction_inner(
            expected_amount,
            Network::Regtest,
            &liquid_tx,
            &address,
            DirectTxOptions::new(),
        );

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Amount received via direct transaction is less than expected"));
    }

    #[test]
    fn test_check_direct_transaction_amount_validation_equal() {
        let expected_amount = Amount::from_sat(100_000);
        let address = generate_regtest_address();

        let liquid_tx = create_liquid_tx_explicit(&address, expected_amount.to_sat());

        let result = SwapScript::check_direct_transaction_inner(
            expected_amount,
            Network::Regtest,
            &liquid_tx,
            &address,
            DirectTxOptions::new(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_check_direct_transaction_amount_validation_greater() {
        let expected_amount = Amount::from_sat(100_000);
        let address = generate_regtest_address();
        let actual_amount = 150_000; // Greater than expected

        let liquid_tx = create_liquid_tx_explicit(&address, actual_amount);

        let result = SwapScript::check_direct_transaction_inner(
            expected_amount,
            Network::Regtest,
            &liquid_tx,
            &address,
            DirectTxOptions::new(),
        );

        assert!(result.is_ok());
    }
}
