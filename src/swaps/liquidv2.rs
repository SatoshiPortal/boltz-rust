use electrum_client::ElectrumApi;
use std::{hash, str::FromStr};

use bitcoin::{
    hashes::{hash160, Hash},
    hex::DisplayHex,
    key::rand::{rngs::OsRng, thread_rng, RngCore},
    script::Script as BitcoinScript,
    secp256k1::Keypair,
    Witness, XOnlyPublicKey,
};
use elements::{
    confidential::{self, Asset, AssetBlindingFactor, Value, ValueBlindingFactor},
    hex::{FromHex, ToHex},
    secp256k1_zkp::{
        self, MusigAggNonce, MusigKeyAggCache, MusigPartialSignature, MusigPubNonce, MusigSession,
        MusigSessionId, Secp256k1, SecretKey,
    },
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TapLeafHash, TaprootBuilder, TaprootSpendInfo},
    Address, AssetIssuance, BlockHash, LockTime, OutPoint, SchnorrSig, SchnorrSighashType, Script,
    Sequence, Transaction, TxIn, TxInWitness, TxOut, TxOutSecrets, TxOutWitness,
};

use elements::encode::serialize;
use elements::secp256k1_zkp::Message;

use crate::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::boltz::SwapTxKind,
    util::secrets::Preimage,
};

use crate::error::Error;

use elements::bitcoin::PublicKey;
use elements::secp256k1_zkp::Keypair as ZKKeyPair;
use elements::{
    address::Address as EAddress,
    opcodes::all::*,
    script::{Builder as EBuilder, Instruction, Script as EScript},
    AddressParams,
};

use super::{
    boltz::SwapType,
    boltzv2::{ClaimTxResponse, CreateSwapResponse, ReverseResp},
};

/// Liquid swap script helper.
#[derive(Debug, Clone, PartialEq)]
pub struct LBtcSwapScriptV2 {
    pub swap_type: SwapType,
    pub funding_addrs: Address,
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
    pub blinding_key: ZKKeyPair,
}

impl LBtcSwapScriptV2 {
    /// Create the struct from a submarine swap from create swap response.
    pub fn submarine_from_swap_resp(
        create_swap_response: &CreateSwapResponse,
    ) -> Result<Self, Error> {
        let claim_script = Script::from_str(&create_swap_response.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_str(&create_swap_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut reciever_pubkey = None;
        let mut locktime = None;
        let mut sender_pubkey = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
                    } else if bytes.len() == 32 {
                        reciever_pubkey = Some(PublicKey::from_slice(bytes)?);
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
                    if bytes.len() == 32 {
                        sender_pubkey = Some(PublicKey::from_slice(bytes)?);
                    } else if last_op == OP_CHECKSIGVERIFY {
                        locktime =
                            Some(LockTime::from_consensus(bytes_to_u32_little_endian(&bytes)));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let sender_pubkey = sender_pubkey
            .ok_or_else(|| Error::Protocol("No sender_pubkey provided".to_string()))?;

        let locktime =
            locktime.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let receiver_pubkey = reciever_pubkey
            .ok_or_else(|| Error::Protocol("No receiver_pubkey provided".to_string()))?;

        let funding_addrs = Address::from_str(&create_swap_response.address)?;

        let blinding_str = create_swap_response
            .blinding_key
            .as_ref()
            .expect("No blinding key provided in CreateSwapResp");
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::Submarine,
            funding_addrs,
            hashlock,
            receiver_pubkey,
            locktime,
            sender_pubkey,
            blinding_key,
        })
    }

    /// Create the struct from a reverse swap create request.
    pub fn reverse_from_swap_resp(reverse_response: &ReverseResp) -> Result<Self, Error> {
        let claim_script = Script::from_str(&reverse_response.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_str(&reverse_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut reciever_pubkey = None;
        let mut locktime = None;
        let mut sender_pubkey = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
                    } else if bytes.len() == 32 {
                        reciever_pubkey = Some(PublicKey::from_slice(bytes)?);
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
                    if bytes.len() == 32 {
                        sender_pubkey = Some(PublicKey::from_slice(bytes)?);
                    } else if last_op == OP_CHECKSIGVERIFY {
                        locktime =
                            Some(LockTime::from_consensus(bytes_to_u32_little_endian(&bytes)));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let sender_pubkey = sender_pubkey
            .ok_or_else(|| Error::Protocol("No sender_pubkey provided".to_string()))?;

        let locktime =
            locktime.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let receiver_pubkey = reciever_pubkey
            .ok_or_else(|| Error::Protocol("No receiver_pubkey provided".to_string()))?;

        let funding_addrs = Address::from_str(&reverse_response.lockup_address)?;

        let blinding_str = reverse_response
            .blinding_key
            .as_ref()
            .expect("No blinding key provided in CreateSwapResp");
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::Submarine,
            funding_addrs,
            hashlock,
            receiver_pubkey,
            locktime,
            sender_pubkey,
            blinding_key,
        })
    }

    fn claim_script(&self) -> Script {
        match self.swap_type {
            SwapType::Submarine => EBuilder::new()
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.as_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_key(&self.receiver_pubkey)
                .push_opcode(OP_CHECKSIG)
                .into_script(),

            SwapType::ReverseSubmarine => EBuilder::new()
                .push_opcode(OP_SIZE)
                .push_int(20)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.as_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_key(&self.receiver_pubkey)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
        }
    }

    fn refund_script(&self) -> Script {
        match self.swap_type {
            SwapType::Submarine => EBuilder::new()
                .push_key(&self.sender_pubkey)
                .push_opcode(OP_CHECKSIGVERIFY)
                .push_int(self.locktime.to_consensus_u32() as i64)
                .push_opcode(OP_CLTV)
                .into_script(),
            SwapType::ReverseSubmarine => EBuilder::new()
                .push_key(&self.sender_pubkey)
                .push_opcode(OP_CHECKSIGVERIFY)
                .push_int(self.locktime.to_consensus_u32() as i64)
                .push_opcode(OP_CLTV)
                .into_script(),
        }
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
            .add_leaf_with_ver(1, self.claim_script(), LeafVersion::default())
            .unwrap();
        let taproot_builder = taproot_builder
            .add_leaf_with_ver(1, self.refund_script(), LeafVersion::default())
            .unwrap();

        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // Verify taproot construction
        let output_key = taproot_spend_info.output_key();

        let lockup_spk = self.funding_addrs.script_pubkey();

        let pubkey_instruction = lockup_spk
            .instructions()
            .last()
            .expect("should contain value")
            .expect("should not fail");

        let lockup_xonly_pubkey_bytes = pubkey_instruction
            .push_bytes()
            .expect("pubkey bytes expected");

        let lockup_xonly_pubkey = XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes)?;

        assert!(lockup_xonly_pubkey == output_key.into_inner());

        log::info!("Taproot creation and verification success!");

        Ok(taproot_spend_info)
    }

    /// Get address for the swap script.
    /// Submarine swaps use p2shwsh. Reverse swaps use p2wsh.
    /// Always returns a confidential address
    pub fn to_address(&self, network: Chain) -> Result<EAddress, Error> {
        let taproot_spend_info = self.taproot_spendinfo()?;
        let address_params = match network {
            Chain::Liquid => &AddressParams::LIQUID,
            Chain::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
            _ => {
                return Err(Error::Address(
                    "Cannot derive Liquid address for Bitcoin network".to_string(),
                ))
            }
        };

        Ok(EAddress::p2tr(
            &Secp256k1::new(),
            taproot_spend_info.internal_key(),
            taproot_spend_info.merkle_root(),
            Some(self.blinding_key.public_key()),
            address_params,
        ))
    }

    /// Get balance for the swap script
    pub fn get_balance(&self, network_config: &ElectrumConfig) -> Result<(u64, i64), Error> {
        let electrum_client = network_config.clone().build_client()?;

        let _ = electrum_client.script_subscribe(BitcoinScript::from_bytes(
            &self
                .to_address(network_config.network())?
                .script_pubkey()
                .as_bytes(),
        ))?;

        let balance = electrum_client.script_get_balance(BitcoinScript::from_bytes(
            &self
                .to_address(network_config.network())?
                .script_pubkey()
                .as_bytes(),
        ))?;

        let _ = electrum_client.script_unsubscribe(BitcoinScript::from_bytes(
            &self
                .to_address(network_config.network())?
                .script_pubkey()
                .as_bytes(),
        ))?;
        Ok((balance.confirmed, balance.unconfirmed))
    }

    /// Fetch utxo for script
    pub fn fetch_utxo(&self, network_config: &ElectrumConfig) -> Result<(OutPoint, TxOut), Error> {
        let electrum_client = network_config.clone().build_client()?;
        let address = self.to_address(network_config.network())?;
        let history = electrum_client.script_get_history(BitcoinScript::from_bytes(
            self.to_address(network_config.network())?
                .to_unconfidential()
                .script_pubkey()
                .as_bytes(),
        ))?;
        if history.is_empty() {
            return Err(Error::Protocol("No Transaction History".to_string()));
        }
        let bitcoin_txid = history.last().expect("txid expected").tx_hash;
        let raw_tx = electrum_client.transaction_get_raw(&bitcoin_txid)?;
        let tx: Transaction = elements::encode::deserialize(&raw_tx)?;
        let mut vout = 0;
        for output in tx.clone().output {
            if output.script_pubkey == address.script_pubkey() {
                let outpoint_0 = OutPoint::new(tx.txid(), vout);

                return Ok((outpoint_0, output));
            }
            vout += 1;
        }
        return Err(Error::Protocol(
            "Could not find utxos for script".to_string(),
        ));
    }

    // Get the chain genesis hash. Requires for sighash calculation
    pub fn genesis_hash(
        &self,
        electrum_config: &ElectrumConfig,
    ) -> Result<elements::BlockHash, Error> {
        let electrum = electrum_config.build_client()?;
        Ok(elements::BlockHash::from_raw_hash(
            electrum.block_header(0)?.block_hash().into(),
        ))
    }
}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

/// Liquid swap transaction helper.
#[derive(Debug, Clone)]
pub struct LBtcSwapTx {
    kind: SwapTxKind,
    swap_script: LBtcSwapScriptV2,
    output_address: Address,
    funding_outpoint: OutPoint,
    funding_utxo: TxOut,     // there should only ever be one outpoint in a swap
    genesis_hash: BlockHash, // Required to calculate sighash
}

impl LBtcSwapTx {
    /// Required to claim reverse swaps only. This is never used for submarine swaps.WW
    pub fn new_claim(
        swap_script: LBtcSwapScriptV2,
        output_address: String,
        network_config: &ElectrumConfig,
    ) -> Result<LBtcSwapTx, Error> {
        debug_assert!(
            swap_script.swap_type != SwapType::Submarine,
            "Claim transactions can only be constructed for Reverse swaps."
        );

        let (funding_outpoint, funding_utxo) = swap_script.fetch_utxo(network_config)?;

        let electrum = network_config.build_client()?;
        let genesis_hash =
            elements::BlockHash::from_raw_hash(electrum.block_header(0)?.block_hash().into());

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Claim,
            swap_script: swap_script,
            output_address: Address::from_str(&output_address)?,
            funding_outpoint,
            funding_utxo,
            genesis_hash,
        })
    }
    /// Required to claim submarine swaps only. This is never used for reverse swaps.
    pub fn new_refund(
        swap_script: LBtcSwapScriptV2,
        output_address: String,
        network_config: &ElectrumConfig,
    ) -> Result<LBtcSwapTx, Error> {
        debug_assert!(
            swap_script.swap_type != SwapType::ReverseSubmarine,
            "Refund transactions can only be constructed for Submarine swaps."
        );
        let address = Address::from_str(&output_address)?;

        let (funding_outpoint, funding_utxo) = swap_script.fetch_utxo(network_config)?;

        let electrum = network_config.build_client()?;
        let genesis_hash =
            elements::BlockHash::from_raw_hash(electrum.block_header(0)?.block_hash().into());

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Refund,
            swap_script: swap_script,
            output_address: address,
            funding_outpoint,
            funding_utxo,
            genesis_hash,
        })
    }

    /// Compute the Musig partial signature for Submarine Swap.
    /// This is used to cooperatively close a submarine swap.
    fn submarine_partial_sig(
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

    /// Sign a reverse swap claim transaction.
    /// Panics if called on a Normal Swap or Refund Tx.
    /// If the claim is cooperative, provide the other party's partial sigs.
    /// If this is None, transaction will be claimed via taproot script path.
    pub fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: u64,
        is_cooperative: Option<(MusigPartialSignature, MusigPubNonce)>,
    ) -> Result<Transaction, Error> {
        debug_assert!(
            self.swap_script.swap_type != SwapType::Submarine,
            "Claim transactions can only be constructed for Reverse swaps."
        );
        debug_assert!(
            self.kind != SwapTxKind::Refund,
            "Constructed transaction is a refund. Cannot claim."
        );
        let preimage_bytes = preimage
            .bytes
            .ok_or(Error::Protocol("No preimage provided".to_string()))?;

        let claim_txin = TxIn {
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            previous_output: self.funding_outpoint,
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let secp = Secp256k1::new();

        // Unblind the funding utxo
        let unblinded_utxo = self
            .funding_utxo
            .unblind(&secp, self.swap_script.blinding_key.secret_key())?;

        let output_value = unblinded_utxo.value - absolute_fees;
        let exp_asset = Asset::Explicit(unblinded_utxo.asset);
        let exp_value = elements::confidential::Value::Explicit(output_value);

        // Create new Blinding Factors
        let asset_bf = AssetBlindingFactor::new(&mut thread_rng());
        let msg = elements::RangeProofMessage {
            asset: unblinded_utxo.asset,
            bf: asset_bf,
        };
        let value_bf = ValueBlindingFactor::last(
            &secp,
            output_value,
            asset_bf,
            &[(
                unblinded_utxo.value,
                unblinded_utxo.asset_bf,
                unblinded_utxo.value_bf,
            )],
            &[(
                absolute_fees,
                AssetBlindingFactor::zero(),
                ValueBlindingFactor::zero(),
            )],
        );

        // Blind the Value
        let blinding_key = self.output_address.blinding_pubkey.ok_or(Error::Protocol(
            "We can only send to blinded address.".to_string(),
        ))?;

        let (blinded_value, nonce, range_proof) = exp_value.blind(
            &secp,
            value_bf,
            blinding_key,
            SecretKey::new(&mut thread_rng()),
            &self.output_address.script_pubkey(),
            &msg,
        )?;

        // Blind the Asset
        let (blinded_asset, surjection_proof) = exp_asset.blind(
            &mut thread_rng(),
            &secp,
            AssetBlindingFactor::new(&mut thread_rng()),
            &[unblinded_utxo],
        )?;

        // Create the witness and the outputs
        let tx_out_witness = TxOutWitness {
            surjection_proof: Some(Box::new(surjection_proof)), // from asset blinding
            rangeproof: Some(Box::new(range_proof)),            // from value blinding
        };

        let payment_output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: blinded_value,
            asset: blinded_asset,
            nonce: nonce,
            witness: tx_out_witness,
        };
        let fee_output: TxOut = TxOut::new_fee(absolute_fees, unblinded_utxo.asset);

        let mut claim_tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![claim_txin],
            output: vec![payment_output, fee_output],
        };

        // If its a cooperative claim, compute the Musig2 Aggregate Signature and use Keypath spending
        if let Some((boltz_partial_sig, boltz_public_nonce)) = is_cooperative {
            let claim_tx_taproot_hash = SighashCache::new(&claim_tx)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.funding_utxo]),
                    SchnorrSighashType::Default,
                    self.genesis_hash,
                )
                .unwrap();

            let msg = Message::from_digest_slice(claim_tx_taproot_hash.as_byte_array()).unwrap();

            let mut key_agg_cache = MusigKeyAggCache::new(
                &secp,
                &[
                    self.swap_script.receiver_pubkey.inner,
                    self.swap_script.sender_pubkey.inner,
                ],
            );

            let session_id = MusigSessionId::new(&mut thread_rng());

            let mut extra_rand = [0u8; 32];
            OsRng.fill_bytes(&mut extra_rand);

            let (sec_nonce, pub_nonce) = key_agg_cache
                .nonce_gen(&secp, session_id, keys.public_key(), msg, Some(extra_rand))
                .unwrap();

            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            let our_partial_sig = musig_session
                .partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)
                .unwrap();

            let schnorr_sig = musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

            let final_schnorr_sig = SchnorrSig {
                sig: schnorr_sig,
                hash_ty: SchnorrSighashType::Default,
            };

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.sender_pubkey.inner,
            );

            assert!(boltz_partial_sig_verify == true);

            let output_key = self.swap_script.taproot_spendinfo()?.output_key();

            let _ = secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.into_inner())?;

            let mut script_witness = Witness::new();
            script_witness.push(final_schnorr_sig.to_vec());

            let witness = TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: script_witness.to_vec(),
                pegin_witness: vec![],
            };

            claim_tx.input[0].witness = witness;

            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
        } else {
            // If Non-Cooperative claim use the Script Path spending

            let claim_script = self.swap_script.claim_script();
            let leaf_hash = TapLeafHash::from_script(&claim_script, LeafVersion::default());

            let sighash = SighashCache::new(&claim_tx)
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.funding_utxo]),
                    leaf_hash,
                    SchnorrSighashType::Default,
                    self.genesis_hash,
                )
                .unwrap();

            let msg = Message::from_digest_slice(sighash.as_byte_array()).unwrap();

            let sig = secp.sign_schnorr(&msg, &keys);

            let final_sig = SchnorrSig {
                sig,
                hash_ty: SchnorrSighashType::Default,
            };

            let control_block = self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(claim_script.clone(), LeafVersion::default()))
                .unwrap();

            let mut script_witness = Witness::new();
            script_witness.push(final_sig.to_vec());
            script_witness.push(claim_script.as_bytes());
            script_witness.push(control_block.serialize());

            let witness = TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: script_witness.to_vec(),
                pegin_witness: vec![],
            };

            claim_tx.input[0].witness = witness;
        }

        Ok(claim_tx)
    }

    /// Sign a refund transaction for a submarine swap
    pub fn sign_refund(&self, keys: &Keypair, absolute_fees: u64) -> Result<Transaction, Error> {
        debug_assert!(
            self.swap_script.swap_type != SwapType::ReverseSubmarine,
            "Refund transactions can only be constructed for Submarine swaps."
        );
        debug_assert!(
            self.kind != SwapTxKind::Claim,
            "Constructed transaction is a claim. Cannot refund."
        );

        // Create unsigned refund transaction
        let refund_txin = TxIn {
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            previous_output: self.funding_outpoint,
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let secp = Secp256k1::new();

        let unblined_utxo = self
            .funding_utxo
            .unblind(&secp, self.swap_script.blinding_key.secret_key())?;
        let asset_id = unblined_utxo.asset;
        let out_abf = AssetBlindingFactor::new(&mut thread_rng());
        let exp_asset = Asset::Explicit(asset_id);

        let (blinded_asset, asset_surjection_proof) =
            exp_asset.blind(&mut thread_rng(), &secp, out_abf, &[unblined_utxo])?;

        let output_value = unblined_utxo.value - absolute_fees;

        let final_vbf = ValueBlindingFactor::last(
            &secp,
            output_value,
            out_abf,
            &[(
                unblined_utxo.value,
                unblined_utxo.asset_bf,
                unblined_utxo.value_bf,
            )],
            &[(
                absolute_fees,
                AssetBlindingFactor::zero(),
                ValueBlindingFactor::zero(),
            )],
        );
        let explicit_value = elements::confidential::Value::Explicit(output_value);
        let msg = elements::RangeProofMessage {
            asset: asset_id,
            bf: out_abf,
        };
        let ephemeral_sk = SecretKey::new(&mut thread_rng());

        // assuming we always use a blinded address that has an extractable blinding pub
        let blinding_key = self
            .output_address
            .blinding_pubkey
            .ok_or(Error::Protocol("No blinding key in tx.".to_string()))?;
        let (blinded_value, nonce, rangeproof) = explicit_value.blind(
            &secp,
            final_vbf,
            blinding_key,
            ephemeral_sk,
            &self.output_address.script_pubkey(),
            &msg,
        )?;

        let tx_out_witness = TxOutWitness {
            surjection_proof: Some(Box::new(asset_surjection_proof)), // from asset blinding
            rangeproof: Some(Box::new(rangeproof)),                   // from value blinding
        };
        let payment_output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: blinded_value,
            asset: blinded_asset,
            nonce: nonce,
            witness: tx_out_witness,
        };
        let fee_output: TxOut = TxOut::new_fee(absolute_fees, asset_id);

        let refund_script = self.swap_script.refund_script();

        let lock_time = refund_script
            .instructions()
            .filter_map(|i| {
                let ins = i.unwrap();
                if let Instruction::PushBytes(bytes) = ins {
                    if bytes.len() == 3 as usize {
                        Some(LockTime::from_consensus(bytes_to_u32_little_endian(&bytes)))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next()
            .unwrap();

        let mut refund_tx = Transaction {
            version: 2,
            lock_time,
            input: vec![refund_txin],
            output: vec![payment_output, fee_output],
        };

        let leaf_hash = TapLeafHash::from_script(&refund_script, LeafVersion::default());

        let electrum = ElectrumConfig::default_liquid().build_client()?;

        let genesis_blockhash =
            elements::BlockHash::from_raw_hash(electrum.block_header(0)?.block_hash().into());

        let sighash = SighashCache::new(&refund_tx)
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&self.funding_utxo]),
                leaf_hash,
                SchnorrSighashType::Default,
                genesis_blockhash,
            )
            .unwrap();

        let msg = Message::from_digest_slice(sighash.as_byte_array()).unwrap();

        let sig = secp.sign_schnorr(&msg, &keys);

        let final_sig = SchnorrSig {
            sig,
            hash_ty: SchnorrSighashType::Default,
        };

        let control_block = self
            .swap_script
            .taproot_spendinfo()?
            .control_block(&(refund_script.clone(), LeafVersion::default()))
            .unwrap();

        let mut script_witness = Witness::new();
        script_witness.push(final_sig.to_vec());
        script_witness.push(refund_script.as_bytes());
        script_witness.push(control_block.serialize());

        let witness = TxInWitness {
            amount_rangeproof: None,
            inflation_keys_rangeproof: None,
            script_witness: script_witness.to_vec(),
            pegin_witness: vec![],
        };

        refund_tx.input[0].witness = witness;

        Ok(refund_tx)
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        is_cooperative: Option<(MusigPartialSignature, MusigPubNonce)>,
    ) -> Result<usize, Error> {
        let dummy_abs_fee = 5_000;
        let tx = match self.kind {
            SwapTxKind::Claim => self.sign_claim(keys, preimage, dummy_abs_fee, is_cooperative)?,
            SwapTxKind::Refund => self.sign_refund(keys, dummy_abs_fee)?,
        };
        Ok(tx.vsize())
    }

    /// Broadcast transaction to the network
    pub fn broadcast(
        &self,
        signed_tx: Transaction,
        network_config: &ElectrumConfig,
    ) -> Result<String, Error> {
        let electrum_client = network_config.build_client()?;
        let serialized = serialize(&signed_tx);
        Ok(electrum_client
            .transaction_broadcast_raw(&serialized)?
            .to_string())
    }
}
