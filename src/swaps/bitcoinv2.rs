use bitcoin::consensus::{deserialize, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::key::rand::rngs::OsRng;
use bitcoin::key::rand::{thread_rng, RngCore};
use bitcoin::script::{PushBytes, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
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
use std::ops::{Add, Index};
use std::str::FromStr;

use crate::swaps::boltz;
use crate::{
    error::Error,
    network::{electrum::ElectrumConfig, Chain},
    swaps::boltz::SwapTxKind,
    util::secrets::Preimage,
};

use bitcoin::{blockdata::locktime::absolute::LockTime, hashes::hash160};

use super::boltz::SwapType;
use super::boltzv2::{BoltzApiClientV2, ClaimTxResponse, CreateSwapResponse, ReverseResp};

use elements::secp256k1_zkp::{
    MusigAggNonce, MusigKeyAggCache, MusigPartialSignature, MusigPubNonce, MusigSession,
    MusigSessionId,
};

/// Bitcoin swap script helper.
// TODO: This should encode the network at global level.
#[derive(Debug, PartialEq, Clone)]
pub struct BtcSwapScriptV2 {
    pub swap_type: SwapType,
    // pub swap_id: String,
    pub funding_addrs: Option<Address>,
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
}

impl BtcSwapScriptV2 {
    /// Create the struct from a submarine swap from create swap response.
    pub fn submarine_from_swap_resp(
        create_swap_response: &CreateSwapResponse,
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

        Ok(BtcSwapScriptV2 {
            swap_type: SwapType::Submarine,
            // swap_id: create_swap_response.id.clone(),
            funding_addrs: Some(funding_addrs),
            hashlock: hashlock,
            receiver_pubkey: create_swap_response.claim_public_key,
            locktime: timelock,
            sender_pubkey: our_pubkey,
        })
    }

    /// Create the struct from a reverse swap create request.
    pub fn reverse_from_swap_resp(
        reverse_response: &ReverseResp,
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

        Ok(BtcSwapScriptV2 {
            swap_type: SwapType::ReverseSubmarine,
            // swap_id: reverse_response.id.clone(),
            funding_addrs: Some(funding_addrs),
            hashlock: hashlock,
            receiver_pubkey: our_pubkey,
            locktime: timelock,
            sender_pubkey: reverse_response.refund_public_key,
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

            SwapType::ReverseSubmarine => Builder::new()
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
        let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];

        let mut key_agg_cache = MusigKeyAggCache::new(&secp, &pubkeys);

        // Construct the Taproot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let taproot_builder = taproot_builder
            .add_leaf_with_ver(1, self.claim_script(), LeafVersion::TapScript)
            .unwrap();
        let taproot_builder = taproot_builder
            .add_leaf_with_ver(1, self.refund_script(), LeafVersion::TapScript)
            .unwrap();

        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // Verify taproot construction, only if we have funding address previously known.
        // Which will be None only for regtest integration tests, so verification will be skipped for them.
        if let Some(funding_address) = &self.funding_addrs {
            let output_key = taproot_spend_info.output_key();

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

            debug_assert!(lockup_xonly_pubkey == output_key.to_inner());

            log::info!("Taproot creation and verification success!");
        }

        Ok(taproot_spend_info)
    }

    /// Get address for the swap script.
    /// Submarine swaps use p2shwsh. Reverse swaps use p2wsh.
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

    /// Get the balance of the script
    pub fn get_balance(&self, network_config: &ElectrumConfig) -> Result<(u64, i64), Error> {
        let electrum_client = network_config.build_client()?;
        let spk = self.to_address(network_config.network())?.script_pubkey();
        let script_balance = electrum_client.script_get_balance(spk.as_script())?;
        Ok((script_balance.confirmed, script_balance.unconfirmed))
    }

    /// Fetch (utxo,amount) pair for the script_pubkey of this swap.
    /// Returns None if no utxo for the script_pubkey is found.
    pub fn fetch_utxo(
        &self,
        network_config: &ElectrumConfig,
    ) -> Result<Option<(OutPoint, TxOut)>, Error> {
        let electrum_client = network_config.build_client()?;
        let spk = self.to_address(network_config.network())?.script_pubkey();
        let utxos = electrum_client.script_list_unspent(spk.as_script())?;

        if utxos.len() == 0 {
            // No utxo found. Return None.
            return Ok(None);
        } else {
            let outpoint_0 = OutPoint::new(utxos[0].tx_hash, utxos[0].tx_pos as u32);
            let txout = TxOut {
                script_pubkey: spk,
                value: Amount::from_sat(utxos[0].value),
            };
            Ok(Some((outpoint_0, txout)))
        }
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
pub struct BtcSwapTxV2 {
    pub kind: SwapTxKind, // These fields needs to be public to do manual creation in IT.
    pub swap_script: BtcSwapScriptV2,
    pub output_address: Address,
    // The HTLC utxo in (Outpoint, Amount) Pair
    pub utxo: (OutPoint, TxOut),
}
impl BtcSwapTxV2 {
    /// Craft a new ClaimTx. Only works for Reverse Swaps.
    /// Returns None, if the HTLC utxo doesn't exist for the swap.
    pub fn new_claim(
        swap_script: BtcSwapScriptV2,
        claim_address: String,
        network_config: &ElectrumConfig,
    ) -> Result<Option<BtcSwapTxV2>, Error> {
        debug_assert!(
            swap_script.swap_type != SwapType::Submarine,
            "Claim transactions can only be constructed for Reverse swaps."
        );
        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = Address::from_str(&claim_address)?;

        address.is_valid_for_network(network);

        let utxo_info = swap_script.fetch_utxo(network_config)?;
        if let Some(utxo) = utxo_info {
            Ok(Some(BtcSwapTxV2 {
                kind: SwapTxKind::Claim,
                swap_script,
                output_address: address.assume_checked(),
                utxo,
            }))
        } else {
            Ok(None)
        }
    }

    /// Construct a RefundTX corresponding to the swap_script. Only works for Normal Swaps.
    /// Returns None, if the HTLC UTXO for the swap doesn't exist in blockhcian.
    pub fn new_refund(
        swap_script: BtcSwapScriptV2,
        refund_address: &String,
        network_config: &ElectrumConfig,
    ) -> Result<Option<BtcSwapTxV2>, Error> {
        debug_assert!(
            swap_script.swap_type != SwapType::ReverseSubmarine,
            "Refund Txs can only be constructed for Normal Swaps"
        );
        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };

        let address = Address::from_str(&refund_address)?;
        assert!(address.is_valid_for_network(network));

        let utxo_info = swap_script.fetch_utxo(network_config)?;
        if let Some(utxo) = utxo_info {
            Ok(Some(BtcSwapTxV2 {
                kind: SwapTxKind::Refund,
                swap_script,
                output_address: address.assume_checked(),
                utxo,
            }))
        } else {
            Ok(None)
        }
    }

    /// Compute the Musig partial signature for Submarine Swap.
    /// This is used to cooperatively close a submarine swap.
    pub fn submarine_partial_sig(
        &self,
        keys: &Keypair,
        claim_tx_response: &ClaimTxResponse,
    ) -> Result<(MusigPartialSignature, MusigPubNonce), Error> {
        // Step 1: Start with a Musig KeyAgg Cache
        let secp = Secp256k1::new();

        let pubkeys = [
            self.swap_script.receiver_pubkey.inner,
            self.swap_script.sender_pubkey.inner,
        ];

        let mut key_agg_cache = MusigKeyAggCache::new(&secp, &pubkeys);

        let tweak = SecretKey::from_slice(
            self.swap_script
                .taproot_spendinfo()?
                .tap_tweak()
                .as_byte_array(),
        )?;

        let _ = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak)?;

        let session_id = MusigSessionId::new(&mut thread_rng());

        let msg = Message::from_digest_slice(
            &Vec::from_hex(&claim_tx_response.transaction_hash).unwrap(),
        )?;

        // Step 4: Start the Musig2 Signing session
        let mut extra_rand = [0u8; 32];
        OsRng.fill_bytes(&mut extra_rand);

        let (sec_nonce, pub_nonce) =
            key_agg_cache.nonce_gen(&secp, session_id, keys.public_key(), msg, Some(extra_rand))?;

        let boltz_nonce = MusigPubNonce::from_slice(&Vec::from_hex(&claim_tx_response.pub_nonce)?)?;

        let agg_nonce = MusigAggNonce::new(&secp, &[boltz_nonce, pub_nonce]);

        let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

        let partial_sig = musig_session.partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)?;

        let is_partial_sig_valid = musig_session.partial_verify(
            &secp,
            &key_agg_cache,
            partial_sig,
            pub_nonce,
            keys.public_key(),
        );

        assert!(is_partial_sig_valid == true);

        log::info!("Partial Signature creation and verification success.");

        Ok((partial_sig, pub_nonce))
    }

    pub fn create_unsigned_claim_tx(&self, absolute_fees: u64) -> Result<Transaction, Error> {
        debug_assert!(
            self.swap_script.swap_type != SwapType::Submarine,
            "Cannot sign claim tx, for a submarine swap"
        );

        debug_assert!(
            self.kind != SwapTxKind::Refund,
            "Cannot sign claim with Refund type BTCSwapTx"
        );

        let txin = TxIn {
            previous_output: self.utxo.0,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let destination_spk = self.output_address.script_pubkey();

        let txout = TxOut {
            script_pubkey: destination_spk,
            value: Amount::from_sat(self.utxo.1.value.to_sat() - absolute_fees),
        };

        let claim_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };

        Ok(claim_tx)
    }

    /// Sign a reverse swap claim transaction.
    /// Panics if called on a Normal Swap or Refund Tx.
    /// If the claim is cooperative, provide the other party's partial sigs.
    /// If this is None, transaction will be claimed via taproot script path.
    pub fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: u64,
        is_cooperative: Option<(&BoltzApiClientV2, String)>,
    ) -> Result<Transaction, Error> {
        debug_assert!(
            self.swap_script.swap_type != SwapType::Submarine,
            "Cannot sign claim tx, for a submarine swap"
        );

        debug_assert!(
            self.kind != SwapTxKind::Refund,
            "Cannot sign claim with Refund type BTCSwapTx"
        );

        let preimage_bytes = if let Some(value) = preimage.bytes {
            value
        } else {
            return Err(Error::Protocol(format!(
                "No preimage provided while signing."
            )));
        };

        let txin = TxIn {
            previous_output: self.utxo.0,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let destination_spk = self.output_address.script_pubkey();

        let txout = TxOut {
            script_pubkey: destination_spk,
            value: Amount::from_sat(self.utxo.1.value.to_sat() - absolute_fees),
        };

        let mut claim_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };

        let secp = Secp256k1::new();

        // If its a cooperative claim, compute the Musig2 Aggregate Signature and use Keypath spending
        if let Some((boltz_api, swap_id)) = is_cooperative {
            // Start the Musig session

            // Step 1: Get the sighash
            let claim_tx_taproot_hash = SighashCache::new(claim_tx.clone())
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.utxo.1]),
                    bitcoin::TapSighashType::Default,
                )
                .unwrap();

            let msg = Message::from_digest_slice(claim_tx_taproot_hash.as_byte_array()).unwrap();

            // Step 2: Get the Public and Secret nonces

            let mut key_agg_cache = MusigKeyAggCache::new(
                &secp,
                &[
                    self.swap_script.receiver_pubkey.inner,
                    self.swap_script.sender_pubkey.inner,
                ],
            );

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

            let (sec_nonce, pub_nonce) = key_agg_cache
                .nonce_gen(&secp, session_id, keys.public_key(), msg, Some(extra_rand))
                .unwrap();

            // Step 7: Get boltz's partail sig
            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
            let partial_sig_resp = boltz_api
                .get_reverse_partial_sig(&swap_id, &preimage, &pub_nonce, &claim_tx_hex)
                .unwrap();

            let boltz_public_nonce =
                MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce).unwrap())
                    .unwrap();

            let boltz_partial_sig = MusigPartialSignature::from_slice(
                &Vec::from_hex(&partial_sig_resp.partial_signature).unwrap(),
            )
            .unwrap();

            // Aggregate Our's and Other's Nonce and start the Musig session.
            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the Boltz's sig.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.sender_pubkey.inner,
            );

            assert!(boltz_partial_sig_verify == true);

            let our_partial_sig = musig_session
                .partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)
                .unwrap();

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

            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
        } else {
            // If Non-Cooperative claim use the Script Path spending
            let leaf_hash =
                TapLeafHash::from_script(&self.swap_script.claim_script(), LeafVersion::TapScript);

            let sighash = SighashCache::new(claim_tx.clone())
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.utxo.1]),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .unwrap();

            let msg = Message::from_digest_slice(sighash.as_byte_array()).unwrap();

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

    /// Sign a submarine swap refund transaction.
    /// Panics if called on Reverse Swap, Claim type.
    pub fn sign_refund(&self, keys: &Keypair, absolute_fees: u64) -> Result<Transaction, Error> {
        debug_assert!(
            self.swap_script.swap_type != SwapType::ReverseSubmarine,
            "Cannot sign refund tx, for a reverse-swap"
        );

        debug_assert!(
            self.kind != SwapTxKind::Claim,
            "Cannot sign refund with a claim-type BtcSwapTx"
        );

        let unsigned_input: TxIn = TxIn {
            sequence: Sequence::ZERO, // enables absolute locktime
            previous_output: self.utxo.0,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };
        let output_amount: Amount = Amount::from_sat(self.utxo.1.value.to_sat() - absolute_fees);
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: output_amount,
        };

        let input = TxIn {
            previous_output: self.utxo.0,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        };

        let lock_time = self
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
            .unwrap();

        let mut spending_tx = Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![input],
            output: vec![output],
        };

        let leaf_hash =
            TapLeafHash::from_script(&self.swap_script.refund_script(), LeafVersion::TapScript);

        let sighash = SighashCache::new(spending_tx.clone())
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&self.utxo.1]),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();

        let msg = Message::from_digest_slice(sighash.as_byte_array()).unwrap();

        let sig = Secp256k1::new().sign_schnorr(&msg, &keys);

        let final_sig = Signature {
            sig,
            hash_ty: TapSighashType::Default,
        };

        let control_block = self
            .swap_script
            .taproot_spendinfo()?
            .control_block(&(
                self.swap_script.refund_script().clone(),
                LeafVersion::TapScript,
            ))
            .expect("Control block calculation failed");

        let mut witness = Witness::new();

        witness.push(final_sig.to_vec());
        witness.push(self.swap_script.refund_script().as_bytes());
        witness.push(control_block.serialize());

        spending_tx.input[0].witness = witness;

        Ok(spending_tx)
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(&self, keys: &Keypair, preimage: &Preimage) -> Result<usize, Error> {
        let dummy_abs_fee = 5_000;
        let tx = match self.kind {
            SwapTxKind::Claim => self.sign_claim(keys, preimage, dummy_abs_fee, None)?, // Can only calculate non-coperative claims
            SwapTxKind::Refund => self.sign_refund(keys, dummy_abs_fee)?,
        };
        Ok(tx.vsize())
    }
    /// Broadcast transaction to the network
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
