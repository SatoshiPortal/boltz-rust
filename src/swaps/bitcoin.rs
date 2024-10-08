use bitcoin::consensus::{deserialize, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::key::rand::rngs::OsRng;
use bitcoin::key::rand::{thread_rng, RngCore};
use bitcoin::script::{PushBytes, PushBytesBuf};
use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::Prevouts;
use bitcoin::taproot::{LeafVersion, Signature, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    blockdata::script::{Builder, Instruction, Script, ScriptBuf},
    opcodes::{all::*, OP_0},
    Address, OutPoint, PublicKey,
};
use bitcoin::{sighash::SighashCache, Network, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::{Amount, EcdsaSighashType, TapLeafHash, TapSighashType, Txid, XOnlyPublicKey};
use electrum_client::ElectrumApi;
use elements::encode::serialize;
use elements::pset::serialize::Serialize;
use std::ops::{Add, Index};
use std::str::FromStr;

use crate::{
    error::Error,
    network::{electrum::ElectrumConfig, Chain},
    util::secrets::Preimage,
};
use crate::{LBtcSwapScript, LBtcSwapTx};

use bitcoin::{blockdata::locktime::absolute::LockTime, hashes::hash160};

use super::boltz::{
    BoltzApiClientV2, ChainClaimTxResponse, ChainSwapDetails, Cooperative, CreateChainResponse,
    CreateReverseResponse, CreateSubmarineResponse, PartialSig, Side, SubmarineClaimTxResponse,
    SwapTxKind, SwapType, ToSign,
};

use elements::secp256k1_zkp::{
    musig, MusigAggNonce, MusigKeyAggCache, MusigPartialSignature, MusigPubNonce, MusigSession,
    MusigSessionId,
};

/// Bitcoin v2 swap script helper.
// TODO: This should encode the network at global level.
#[derive(Debug, PartialEq, Clone)]
pub struct BtcSwapScript {
    pub swap_type: SwapType,
    // pub swap_id: String,
    pub side: Option<Side>,
    pub funding_addrs: Option<Address>, // we should not store this as a field, since we have a method
    // if we are using it just to recognize regtest, we should consider another strategy
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
}

impl BtcSwapScript {
    /// Create the struct for a submarine swap from boltz create swap response.
    pub fn submarine_from_swap_resp(
        create_swap_response: &CreateSubmarineResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = ScriptBuf::from_hex(&create_swap_response.swap_tree.claim_leaf.output)?;
        let refund_script =
            ScriptBuf::from_hex(&create_swap_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0;
        let mut hashlock = None;
        let mut timelock = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&create_swap_response.address)?.assume_checked();

        Ok(BtcSwapScript {
            swap_type: SwapType::Submarine,
            // swap_id: create_swap_response.id.clone(),
            side: None,
            funding_addrs: Some(funding_addrs),
            hashlock: hashlock,
            receiver_pubkey: create_swap_response.claim_public_key,
            locktime: timelock,
            sender_pubkey: our_pubkey,
        })
    }

    pub fn musig_keyagg_cache(&self) -> MusigKeyAggCache {
        match (self.swap_type, self.side.clone()) {
            (SwapType::ReverseSubmarine, _) | (SwapType::Chain, Some(Side::Claim)) => {
                let pubkeys = [self.sender_pubkey.inner, self.receiver_pubkey.inner];
                MusigKeyAggCache::new(&Secp256k1::new(), &pubkeys)
            }

            (SwapType::Submarine, _) | (SwapType::Chain, _) => {
                let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];
                MusigKeyAggCache::new(&Secp256k1::new(), &pubkeys)
            }
        }
    }

    /// Create the struct for a reverse swap from a boltz create response.
    pub fn reverse_from_swap_resp(
        reverse_response: &CreateReverseResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = ScriptBuf::from_hex(&reverse_response.swap_tree.claim_leaf.output)?;
        let refund_script = ScriptBuf::from_hex(&reverse_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0;
        let mut hashlock = None;
        let mut timelock = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&reverse_response.lockup_address)?.assume_checked();

        Ok(BtcSwapScript {
            swap_type: SwapType::ReverseSubmarine,
            // swap_id: reverse_response.id.clone(),
            side: None,
            funding_addrs: Some(funding_addrs),
            hashlock: hashlock,
            receiver_pubkey: our_pubkey,
            locktime: timelock,
            sender_pubkey: reverse_response.refund_public_key,
        })
    }

    /// Create the struct for a chain swap from a boltz create response.
    pub fn chain_from_swap_resp(
        side: Side,
        chain_swap_details: ChainSwapDetails,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = ScriptBuf::from_hex(&chain_swap_details.swap_tree.claim_leaf.output)?;
        let refund_script = ScriptBuf::from_hex(&chain_swap_details.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0;
        let mut hashlock = None;
        let mut timelock = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&chain_swap_details.lockup_address)?.assume_checked();

        let (sender_pubkey, receiver_pubkey) = match side {
            Side::Lockup => (our_pubkey, chain_swap_details.server_public_key),
            Side::Claim => (chain_swap_details.server_public_key, our_pubkey),
        };

        Ok(BtcSwapScript {
            swap_type: SwapType::Chain,
            // swap_id: reverse_response.id.clone(),
            side: Some(side),
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey,
            locktime: timelock,
            sender_pubkey,
        })
    }

    fn claim_script(&self) -> ScriptBuf {
        match self.swap_type {
            SwapType::Submarine => Builder::new()
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.to_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_x_only_key(&self.receiver_pubkey.inner.x_only_public_key().0)
                .push_opcode(OP_CHECKSIG)
                .into_script(),

            SwapType::ReverseSubmarine | SwapType::Chain => Builder::new()
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.to_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_x_only_key(&self.receiver_pubkey.inner.x_only_public_key().0)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
        }
    }

    fn refund_script(&self) -> ScriptBuf {
        // Refund scripts are same for all swap types
        Builder::new()
            .push_x_only_key(&self.sender_pubkey.inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_lock_time(self.locktime)
            .push_opcode(OP_CLTV)
            .into_script()
    }

    /// Internally used to convert struct into a bitcoin::Script type
    fn taproot_spendinfo(&self) -> Result<TaprootSpendInfo, Error> {
        let secp = Secp256k1::new();

        // Setup Key Aggregation cache
        // let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];

        let mut key_agg_cache = self.musig_keyagg_cache();

        // Construct the Taproot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.claim_script(), LeafVersion::TapScript)?;
        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.refund_script(), LeafVersion::TapScript)?;

        let taproot_spend_info = match taproot_builder.finalize(&secp, internal_key) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::Taproot(
                    "Could not finalize taproot constructions".to_string(),
                ))
            }
        };

        // Verify taproot construction, only if we have funding address previously known.
        // Which will be None only for regtest integration tests, so verification will be skipped for them.
        if let Some(funding_address) = &self.funding_addrs {
            let claim_key = taproot_spend_info.output_key();

            let lockup_spk = funding_address.script_pubkey();

            let pubkey_instruction = lockup_spk
                .instructions()
                .last()
                .expect("should contain value")
                .expect("should not fail");

            let lockup_xonly_pubkey_bytes = pubkey_instruction
                .push_bytes()
                .expect("pubkey bytes expected");

            let lockup_xonly_pubkey =
                XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes.as_bytes())?;

            if lockup_xonly_pubkey != claim_key.to_inner() {
                return Err(Error::Protocol(format!(
                    "Taproot construction Failed. Lockup Pubkey: {}, Claim Pubkey {}",
                    lockup_xonly_pubkey, claim_key
                )));
            }

            log::info!("Taproot creation and verification success!");
        }

        Ok(taproot_spend_info)
    }

    /// Get taproot address for the swap script.
    pub fn to_address(&self, network: Chain) -> Result<Address, Error> {
        let spend_info = self.taproot_spendinfo()?;
        let output_key = spend_info.output_key();

        let mut network = match network {
            Chain::Bitcoin => Network::Bitcoin,
            Chain::BitcoinRegtest => Network::Regtest,
            Chain::BitcoinTestnet => Network::Testnet,
            _ => {
                return Err(Error::Protocol(
                    "Liquid chain used for Bitcoin operations".to_string(),
                ))
            }
        };

        Ok(Address::p2tr_tweaked(output_key, network))
    }

    pub fn validate_address(&self, chain: Chain, address: String) -> Result<(), Error> {
        let to_address = self.to_address(chain)?;
        if to_address.to_string() == address {
            Ok(())
        } else {
            Err(Error::Protocol("Script/LockupAddress Mismatch".to_string()))
        }
    }

    /// Get the balance of the script
    pub fn get_balance(&self, network_config: &ElectrumConfig) -> Result<(u64, i64), Error> {
        let electrum_client = network_config.build_client()?;
        let spk = self.to_address(network_config.network())?.script_pubkey();
        let script_balance = electrum_client.script_get_balance(spk.as_script())?;
        Ok((script_balance.confirmed, script_balance.unconfirmed))
    }

    /// Fetch (utxo,amount) pairs for all utxos of the script_pubkey of this swap.
    pub fn fetch_utxos(
        &self,
        network_config: &ElectrumConfig,
    ) -> Result<Vec<(OutPoint, TxOut)>, Error> {
        let electrum_client = network_config.build_client()?;
        let spk = self.to_address(network_config.network())?.script_pubkey();
        let utxos = electrum_client.script_list_unspent(spk.as_script())?;
        let utxo_pairs = utxos
            .iter()
            .map(|unspent| {
                let outpoint = OutPoint::new(unspent.tx_hash, unspent.tx_pos as u32);
                let txout = TxOut {
                    script_pubkey: spk.clone(),
                    value: Amount::from_sat(unspent.value),
                };
                (outpoint, txout)
            })
            .collect();
        Ok(utxo_pairs)
    }

    /// Fetch utxo for script from BoltzApi
    pub fn fetch_lockup_utxo_boltz(
        &self,
        network_config: &ElectrumConfig,
        boltz_url: &str,
        swap_id: &str,
        tx_kind: SwapTxKind,
    ) -> Result<Option<(OutPoint, TxOut)>, Error> {
        let boltz_client: BoltzApiClientV2 = BoltzApiClientV2::new(boltz_url);
        let chain_txs = boltz_client.get_chain_txs(swap_id)?;
        let hex = match self.swap_type {
            SwapType::Chain => match tx_kind {
                SwapTxKind::Claim => {
                    chain_txs
                        .server_lock
                        .ok_or(Error::Protocol(
                            "No server_lock transaction for Chain Swap available".to_string(),
                        ))?
                        .transaction
                        .hex
                }
                SwapTxKind::Refund => {
                    chain_txs
                        .user_lock
                        .ok_or(Error::Protocol(
                            "No user_lock transaction for Chain Swap available".to_string(),
                        ))?
                        .transaction
                        .hex
                }
            },
            SwapType::ReverseSubmarine => boltz_client.get_reverse_tx(swap_id)?.hex,
            SwapType::Submarine => boltz_client.get_submarine_tx(swap_id)?.hex,
        };
        if (hex.is_none()) {
            return Err(Error::Hex(
                "No transaction hex found in boltz response".to_string(),
            ));
        }
        let address = self.to_address(network_config.network())?;
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(&hex.unwrap())?)?;
        let mut vout = 0;
        for output in tx.clone().output {
            if output.script_pubkey == address.script_pubkey() {
                let outpoint_0 = OutPoint::new(tx.txid(), vout);
                return Ok(Some((outpoint_0, output)));
            }
            vout += 1;
        }
        return Ok(None);
    }
}

pub fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

/// A structure representing either a Claim or a Refund Tx.
/// This Tx spends from the HTLC.
#[derive(Debug, Clone)]
pub struct BtcSwapTx {
    pub kind: SwapTxKind, // These fields needs to be public to do manual creation in IT.
    pub swap_script: BtcSwapScript,
    pub output_address: Address,
    /// All utxos for the script_pubkey of this swap, at this point in time:
    /// - the initial lockup utxo, if not yet spent (claimed or refunded)
    /// - any further utxos, if not yet spent
    pub utxos: Vec<(OutPoint, TxOut)>,
}

impl BtcSwapTx {
    /// Craft a new ClaimTx. Only works for Reverse and Chain Swaps.
    /// Returns None, if the HTLC utxo doesn't exist for the swap.
    pub fn new_claim(
        swap_script: BtcSwapScript,
        claim_address: String,
        network_config: &ElectrumConfig,
        boltz_url: String,
        swap_id: String,
    ) -> Result<BtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim transactions cannot be constructed for Submarine swaps.".to_string(),
            ));
        }

        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = Address::from_str(&claim_address)?;

        address.is_valid_for_network(network);

        let utxo_info = match swap_script.fetch_utxos(&network_config) {
            Ok(v) => v.first().cloned(),
            Err(_) => swap_script.fetch_lockup_utxo_boltz(
                &network_config,
                &boltz_url,
                &swap_id,
                SwapTxKind::Claim,
            )?,
        };
        if let Some(utxo) = utxo_info {
            Ok(BtcSwapTx {
                kind: SwapTxKind::Claim,
                swap_script,
                output_address: address.assume_checked(),
                utxos: vec![utxo], // When claiming, we only consider the first utxo
            })
        } else {
            Err(Error::Protocol(
                "No Bitcoin UTXO detected for this script".to_string(),
            ))
        }
    }

    /// Construct a RefundTX corresponding to the swap_script. Only works for Submarine and Chain Swaps.
    /// Returns None, if the HTLC UTXO for the swap doesn't exist in blockhcian.
    pub fn new_refund(
        swap_script: BtcSwapScript,
        refund_address: &String,
        network_config: &ElectrumConfig,
        boltz_url: String,
        swap_id: String,
    ) -> Result<BtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Txs cannot be constructed for Reverse Submarine Swaps.".to_string(),
            ));
        }

        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };

        let address = Address::from_str(&refund_address)?;
        if !address.is_valid_for_network(network) {
            return Err(Error::Address("Address validation failed".to_string()));
        };

        let utxos = match swap_script.fetch_utxos(&network_config) {
            Ok(r) => r,
            Err(_) => {
                let lockup_utxo_info = swap_script.fetch_lockup_utxo_boltz(
                    &network_config,
                    &boltz_url,
                    &swap_id,
                    SwapTxKind::Refund,
                )?;

                match lockup_utxo_info {
                    Some(r) => vec![r],
                    None => vec![],
                }
            }
        };

        match utxos.is_empty() {
            true => Err(Error::Protocol(
                "No Bitcoin UTXO detected for this script".to_string(),
            )),
            false => Ok(BtcSwapTx {
                kind: SwapTxKind::Refund,
                swap_script,
                output_address: address.assume_checked(),
                utxos,
            }),
        }
    }

    /// Compute the Musig partial signature.
    /// This is used to cooperatively settle a Submarine or Chain Swap.
    pub fn partial_sign(
        &self,
        keys: &Keypair,
        pub_nonce: &String,
        transaction_hash: &String,
    ) -> Result<(MusigPartialSignature, MusigPubNonce), Error> {
        // Step 1: Start with a Musig KeyAgg Cache
        let secp = Secp256k1::new();

        let pubkeys = [
            self.swap_script.receiver_pubkey.inner,
            self.swap_script.sender_pubkey.inner,
        ];

        let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

        let tweak = SecretKey::from_slice(
            self.swap_script
                .taproot_spendinfo()?
                .tap_tweak()
                .as_byte_array(),
        )?;

        let _ = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak)?;

        let session_id = MusigSessionId::new(&mut thread_rng());

        let msg = Message::from_digest_slice(&Vec::from_hex(transaction_hash)?)?;

        // Step 4: Start the Musig2 Signing session
        let mut extra_rand = [0u8; 32];
        OsRng.fill_bytes(&mut extra_rand);

        let (gen_sec_nonce, gen_pub_nonce) =
            key_agg_cache.nonce_gen(&secp, session_id, keys.public_key(), msg, Some(extra_rand))?;

        let boltz_nonce = MusigPubNonce::from_slice(&Vec::from_hex(pub_nonce)?)?;

        let agg_nonce = MusigAggNonce::new(&secp, &[boltz_nonce, gen_pub_nonce]);

        let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

        let partial_sig =
            musig_session.partial_sign(&secp, gen_sec_nonce, &keys, &key_agg_cache)?;

        Ok((partial_sig, gen_pub_nonce))
    }

    /// Sign a claim transaction.
    /// Errors if called on a Submarine Swap or Refund Tx.
    /// If the claim is cooperative, provide the other party's partial sigs.
    /// If this is None, transaction will be claimed via taproot script path.
    pub fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: u64,
        is_cooperative: Option<Cooperative>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim Tx signing is not applicable for Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Refund {
            return Err(Error::Protocol(
                "Cannot sign claim with refund-type BtcSwapTx".to_string(),
            ));
        }

        let preimage_bytes = if let Some(value) = preimage.bytes {
            value
        } else {
            return Err(Error::Protocol(format!(
                "No preimage provided while signing."
            )));
        };

        // For claim, we only consider 1 utxo
        let utxo = self.utxos.first().ok_or(Error::Protocol(
            "No Bitcoin UTXO detected for this script".to_string(),
        ))?;
        let txin = TxIn {
            previous_output: utxo.0,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let destination_spk = self.output_address.script_pubkey();

        let txout = TxOut {
            script_pubkey: destination_spk,
            value: Amount::from_sat(utxo.1.value.to_sat() - absolute_fees),
        };

        let mut claim_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };

        let secp = Secp256k1::new();

        // If its a cooperative claim, compute the Musig2 Aggregate Signature and use Keypath spending
        if let Some(Cooperative {
            boltz_api,
            swap_id,
            pub_nonce,
            partial_sig,
        }) = is_cooperative
        {
            // Start the Musig session
            // Step 1: Get the sighash
            let claim_tx_taproot_hash = SighashCache::new(claim_tx.clone())
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&utxo.1]),
                    bitcoin::TapSighashType::Default,
                )?;

            let msg = Message::from_digest_slice(claim_tx_taproot_hash.as_byte_array())?;

            // Step 2: Get the Public and Secret nonces
            let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

            let tweak = SecretKey::from_slice(
                self.swap_script
                    .taproot_spendinfo()?
                    .tap_tweak()
                    .as_byte_array(),
            )?;

            let _ = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak)?;

            let session_id = MusigSessionId::new(&mut thread_rng());

            let mut extra_rand = [0u8; 32];
            OsRng.fill_bytes(&mut extra_rand);

            let (claim_sec_nonce, claim_pub_nonce) = key_agg_cache.nonce_gen(
                &secp,
                session_id,
                keys.public_key(),
                msg,
                Some(extra_rand),
            )?;

            // Step 7: Get boltz's partial sig
            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
            let partial_sig_resp = match self.swap_script.swap_type {
                SwapType::Chain => match (pub_nonce, partial_sig) {
                    (Some(pub_nonce), Some(partial_sig)) => boltz_api.post_chain_claim_tx_details(
                        &swap_id,
                        preimage,
                        pub_nonce,
                        partial_sig,
                        ToSign {
                            pub_nonce: claim_pub_nonce.serialize().to_lower_hex_string(),
                            transaction: claim_tx_hex,
                            index: 0,
                        },
                    ),
                    _ => Err(Error::Protocol(
                        "Chain swap claim needs a partial_sig".to_string(),
                    )),
                },
                SwapType::ReverseSubmarine => boltz_api.get_reverse_partial_sig(
                    &swap_id,
                    &preimage,
                    &claim_pub_nonce,
                    &claim_tx_hex,
                ),
                _ => Err(Error::Protocol(format!(
                    "Cannot get partial sig for {:?} Swap",
                    self.swap_script.swap_type
                ))),
            }?;

            let boltz_public_nonce =
                MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce)?)?;

            let boltz_partial_sig = MusigPartialSignature::from_slice(&Vec::from_hex(
                &partial_sig_resp.partial_signature,
            )?)?;

            // Aggregate Our's and Other's Nonce and start the Musig session.
            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, claim_pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the Boltz's sig.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.sender_pubkey.inner,
            );

            if !boltz_partial_sig_verify {
                return Err(Error::Protocol(
                    "Invalid partial-sig received from Boltz".to_string(),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(&secp, claim_sec_nonce, &keys, &key_agg_cache)?;

            let schnorr_sig = musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

            let final_schnorr_sig = Signature {
                sig: schnorr_sig,
                hash_ty: TapSighashType::Default,
            };

            let output_key = self.swap_script.taproot_spendinfo()?.output_key();

            let _ = secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.to_inner())?;

            let mut witness = Witness::new();
            witness.push(final_schnorr_sig.to_vec());

            claim_tx.input[0].witness = witness;
        } else {
            // If Non-Cooperative claim use the Script Path spending
            claim_tx.input[0].sequence = Sequence::ZERO;

            let leaf_hash =
                TapLeafHash::from_script(&self.swap_script.claim_script(), LeafVersion::TapScript);

            let sighash = SighashCache::new(claim_tx.clone()).taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&utxo.1]),
                leaf_hash,
                TapSighashType::Default,
            )?;

            let msg = Message::from_digest_slice(sighash.as_byte_array())?;

            let sig = secp.sign_schnorr(&msg, &keys);

            let final_sig = Signature {
                sig,
                hash_ty: TapSighashType::Default,
            };

            let control_block = self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(self.swap_script.claim_script(), LeafVersion::TapScript))
                .expect("Control block calculation failed");

            let mut witness = Witness::new();

            witness.push(final_sig.to_vec());
            witness.push(&preimage.bytes.unwrap());
            witness.push(self.swap_script.claim_script().as_bytes());
            witness.push(control_block.serialize());

            claim_tx.input[0].witness = witness;
        }

        Ok(claim_tx)
    }

    /// Sign a refund transaction.
    /// Errors if called for a Reverse Swap.
    pub fn sign_refund(
        &self,
        keys: &Keypair,
        absolute_fees: u64,
        is_cooperative: Option<Cooperative>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Tx signing is not applicable for Reverse Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Claim {
            return Err(Error::Protocol(
                "Cannot sign refund with a claim-type BtcSwapTx".to_string(),
            ));
        }

        let utxos_amount = self
            .utxos
            .iter()
            .fold(Amount::ZERO, |acc, (_, txo)| acc + txo.value);
        let absolute_fees_amount = Amount::from_sat(absolute_fees);
        if utxos_amount <= absolute_fees_amount {
            return Err(Error::Generic(
                format!("Cannot sign Refund Tx because utxos_amount ({utxos_amount}) <= absolute_fees ({absolute_fees_amount})")
            ));
        }
        let output_amount: Amount = utxos_amount - absolute_fees_amount;
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: output_amount,
        };

        let unsigned_inputs = self
            .utxos
            .iter()
            .map(|(outpoint, _txo)| TxIn {
                previous_output: outpoint.clone(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect();

        let lock_time = match self
            .swap_script
            .refund_script()
            .instructions()
            .filter_map(|i| {
                let ins = i.unwrap();
                if let Instruction::PushBytes(bytes) = ins {
                    if bytes.len() < 5 as usize {
                        Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next()
        {
            Some(r) => r,
            None => {
                return Err(Error::Protocol(
                    "Error getting timelock from refund script".to_string(),
                ))
            }
        };

        let mut refund_tx = Transaction {
            version: Version::TWO,
            lock_time,
            input: unsigned_inputs,
            output: vec![output],
        };

        let secp = Secp256k1::new();
        let tx_outs: Vec<&TxOut> = self.utxos.iter().map(|(_, out)| out).collect();

        if let Some(Cooperative {
            boltz_api, swap_id, ..
        }) = is_cooperative
        {
            // Start the Musig session
            refund_tx.lock_time = LockTime::ZERO; // No locktime for cooperative spend

            for input_index in 0..refund_tx.input.len() {
                // Step 1: Get the sighash
                let refund_tx_taproot_hash = SighashCache::new(refund_tx.clone())
                    .taproot_key_spend_signature_hash(
                        input_index,
                        &Prevouts::All(&tx_outs),
                        bitcoin::TapSighashType::Default,
                    )?;

                let msg = Message::from_digest_slice(refund_tx_taproot_hash.as_byte_array())?;

                // Step 2: Get the Public and Secret nonces

                let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

                let tweak = SecretKey::from_slice(
                    self.swap_script
                        .taproot_spendinfo()?
                        .tap_tweak()
                        .as_byte_array(),
                )?;

                let _ = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak)?;

                let session_id = MusigSessionId::new(&mut thread_rng());

                let mut extra_rand = [0u8; 32];
                OsRng.fill_bytes(&mut extra_rand);

                let (sec_nonce, pub_nonce) = key_agg_cache.nonce_gen(
                    &secp,
                    session_id,
                    keys.public_key(),
                    msg,
                    Some(extra_rand),
                )?;

                // Step 7: Get boltz's partial sig
                let refund_tx_hex = serialize(&refund_tx).to_lower_hex_string();
                let partial_sig_resp = match self.swap_script.swap_type {
                    SwapType::Chain => boltz_api.get_chain_partial_sig(
                        &swap_id,
                        input_index,
                        &pub_nonce,
                        &refund_tx_hex,
                    ),
                    SwapType::Submarine => boltz_api.get_submarine_partial_sig(
                        &swap_id,
                        input_index,
                        &pub_nonce,
                        &refund_tx_hex,
                    ),
                    _ => Err(Error::Protocol(format!(
                        "Cannot get partial sig for {:?} Swap",
                        self.swap_script.swap_type
                    ))),
                }?;

                let boltz_public_nonce =
                    MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce)?)?;

                let boltz_partial_sig = MusigPartialSignature::from_slice(&Vec::from_hex(
                    &partial_sig_resp.partial_signature,
                )?)?;

                // Aggregate Our's and Other's Nonce and start the Musig session.
                let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, pub_nonce]);

                let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

                // Verify the Boltz's sig.
                let boltz_partial_sig_verify = musig_session.partial_verify(
                    &secp,
                    &key_agg_cache,
                    boltz_partial_sig,
                    boltz_public_nonce,
                    self.swap_script.receiver_pubkey.inner, //boltz key
                );

                if !boltz_partial_sig_verify {
                    return Err(Error::Protocol(
                        "Invalid partial-sig received from Boltz".to_string(),
                    ));
                }

                let our_partial_sig =
                    musig_session.partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)?;

                let schnorr_sig =
                    musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

                let final_schnorr_sig = Signature {
                    sig: schnorr_sig,
                    hash_ty: TapSighashType::Default,
                };

                let output_key = self.swap_script.taproot_spendinfo()?.output_key();

                secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.to_inner())?;

                let mut witness = Witness::new();
                witness.push(final_schnorr_sig.to_vec());
                refund_tx.input[input_index].witness = witness;
            }
        } else {
            let leaf_hash =
                TapLeafHash::from_script(&self.swap_script.refund_script(), LeafVersion::TapScript);

            let control_block = self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(
                    self.swap_script.refund_script().clone(),
                    LeafVersion::TapScript,
                ))
                .ok_or(Error::Protocol(
                    "Control block calculation failed".to_string(),
                ))?;

            for input_index in 0..refund_tx.input.len() {
                refund_tx.input[input_index].sequence = Sequence::ZERO;

                let sighash = SighashCache::new(refund_tx.clone())
                    .taproot_script_spend_signature_hash(
                        input_index,
                        &Prevouts::All(&tx_outs),
                        leaf_hash,
                        TapSighashType::Default,
                    )?;

                let msg = Message::from_digest_slice(sighash.as_byte_array())?;

                let sig = Secp256k1::new().sign_schnorr(&msg, &keys);

                let final_sig = Signature {
                    sig,
                    hash_ty: TapSighashType::Default,
                };

                let mut witness = Witness::new();
                witness.push(final_sig.to_vec());
                witness.push(self.swap_script.refund_script().as_bytes());
                witness.push(control_block.serialize());
                refund_tx.input[input_index].witness = witness;
            }
        };

        Ok(refund_tx)
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(&self, keys: &Keypair, preimage: &Preimage) -> Result<usize, Error> {
        let dummy_abs_fee = 5_000;
        // Can only calculate non-coperative claims
        let tx = match self.kind {
            SwapTxKind::Claim => self.sign_claim(keys, preimage, dummy_abs_fee, None)?,
            SwapTxKind::Refund => self.sign_refund(keys, dummy_abs_fee, None)?,
        };
        Ok(tx.vsize())
    }

    /// Broadcast transaction to the network.
    pub fn broadcast(
        &self,
        signed_tx: &Transaction,
        network_config: &ElectrumConfig,
    ) -> Result<Txid, Error> {
        Ok(network_config
            .build_client()?
            .transaction_broadcast(signed_tx)?)
    }
}
