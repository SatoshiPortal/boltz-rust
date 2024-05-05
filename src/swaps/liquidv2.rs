use electrum_client::ElectrumApi;
use std::{hash, str::FromStr};

use bitcoin::{
    hashes::{hash160, Hash},
    hex::DisplayHex,
    key::rand::{rngs::OsRng, thread_rng, RngCore},
    script::Script as BitcoinScript,
    secp256k1::Keypair,
    Amount, Witness, XOnlyPublicKey,
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
    swaps::boltz::{self, SwapTxKind},
    util::{liquid_genesis_hash, secrets::Preimage},
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
    boltzv2::{BoltzApiClientV2, ClaimTxResponse, CreateReverseResponse, CreateSubmarineResponse},
};

/// Liquid v2 swap script helper.
#[derive(Debug, Clone, PartialEq)]
pub struct LBtcSwapScriptV2 {
    pub swap_type: SwapType,
    pub funding_addrs: Option<Address>,
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
    pub blinding_key: ZKKeyPair,
}

impl LBtcSwapScriptV2 {
    /// Create the struct for a submarine swap from boltz create response.
    pub fn submarine_from_swap_resp(
        create_swap_response: &CreateSubmarineResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = Script::from_hex(&create_swap_response.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_hex(&create_swap_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut locktime = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
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

        let locktime =
            locktime.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&create_swap_response.address)?;

        let blinding_str = create_swap_response
            .blinding_key
            .as_ref()
            .expect("No blinding key provided in CreateSwapResp");
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::Submarine,
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey: create_swap_response.claim_public_key,
            locktime,
            sender_pubkey: our_pubkey,
            blinding_key,
        })
    }

    /// Create the struct for a reverse swap from boltz create response.
    pub fn reverse_from_swap_resp(
        reverse_response: &CreateReverseResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = Script::from_hex(&reverse_response.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_hex(&reverse_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut locktime = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
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

        let locktime =
            locktime.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&reverse_response.lockup_address)?;

        let blinding_str = reverse_response
            .blinding_key
            .as_ref()
            .expect("No blinding key provided in CreateSwapResp");
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::ReverseSubmarine,
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey: our_pubkey,
            locktime,
            sender_pubkey: reverse_response.refund_public_key,
            blinding_key,
        })
    }

    fn claim_script(&self) -> Script {
        match self.swap_type {
            SwapType::Submarine => EBuilder::new()
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.as_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_slice(&self.receiver_pubkey.inner.x_only_public_key().0.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),

            SwapType::ReverseSubmarine => EBuilder::new()
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.as_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_slice(&self.receiver_pubkey.inner.x_only_public_key().0.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),
        }
    }

    fn refund_script(&self) -> Script {
        // Refund scripts are same for all swap types
        EBuilder::new()
            .push_slice(&self.sender_pubkey.inner.x_only_public_key().0.serialize())
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_int(self.locktime.to_consensus_u32().into())
            .push_opcode(OP_CLTV)
            .into_script()
    }

    pub fn musig_keyagg_cache(&self) -> MusigKeyAggCache {
        match self.swap_type {
            SwapType::Submarine => {
                let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];
                MusigKeyAggCache::new(&Secp256k1::new(), &pubkeys)
            }

            SwapType::ReverseSubmarine => {
                let pubkeys = [self.sender_pubkey.inner, self.receiver_pubkey.inner];
                MusigKeyAggCache::new(&Secp256k1::new(), &pubkeys)
            }
        }
    }

    /// Internally used to convert struct into a bitcoin::Script type
    fn taproot_spendinfo(&self) -> Result<TaprootSpendInfo, Error> {
        let secp = Secp256k1::new();

        // Setup Key Aggregation cache
        let mut key_agg_cache = self.musig_keyagg_cache();

        // Construct the Taproot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.claim_script(), LeafVersion::default())?;
        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.refund_script(), LeafVersion::default())?;

        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key)?;

        // Verify taproot construction
        if let Some(funding_addrs) = &self.funding_addrs {
            let claim_key = taproot_spend_info.output_key();

            let lockup_spk = funding_addrs.script_pubkey();

            let pubkey_instruction = lockup_spk
                .instructions()
                .last()
                .expect("should contain value")
                .expect("should not fail");

            let lockup_xonly_pubkey_bytes = pubkey_instruction
                .push_bytes()
                .expect("pubkey bytes expected");

            let lockup_xonly_pubkey = XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes)?;

            if lockup_xonly_pubkey != claim_key.into_inner() {
                return Err(Error::Protocol(format!(
                    "Taproot construction Failed. Lockup Pubkey: {}, Claim Pubkey {:?}",
                    lockup_xonly_pubkey, claim_key
                )));
            }

            log::info!("Taproot creation and verification success!");
        }

        Ok(taproot_spend_info)
    }

    /// Get taproot address for the swap script.
    /// Always returns a confidential address
    pub fn to_address(&self, network: Chain) -> Result<EAddress, Error> {
        let taproot_spend_info = self.taproot_spendinfo()?;
        let address_params = match network {
            Chain::Liquid => &AddressParams::LIQUID,
            Chain::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
            Chain::LiquidRegtest => &AddressParams::ELEMENTS,
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
pub struct LBtcSwapTxV2 {
    pub kind: SwapTxKind,
    pub swap_script: LBtcSwapScriptV2,
    pub output_address: Address,
    pub funding_outpoint: OutPoint,
    pub funding_utxo: TxOut, // there should only ever be one outpoint in a swap
    pub genesis_hash: BlockHash, // Required to calculate sighash
}

impl LBtcSwapTxV2 {
    /// Required to claim reverse swaps only. This is never used for submarine swaps.WW
    pub fn new_claim(
        swap_script: LBtcSwapScriptV2,
        output_address: String,
        network_config: &ElectrumConfig,
    ) -> Result<LBtcSwapTxV2, Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim transactions can only be constructed for Reverse swaps.".to_string(),
            ));
        }

        let (funding_outpoint, funding_utxo) = swap_script.fetch_utxo(network_config)?;

        let electrum = network_config.build_client()?;
        let genesis_hash = liquid_genesis_hash(&network_config)?;

        Ok(LBtcSwapTxV2 {
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
        output_address: &String,
        network_config: &ElectrumConfig,
    ) -> Result<LBtcSwapTxV2, Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Txs can only be constructed for Submarine Swaps.".to_string(),
            ));
        }

        let address = Address::from_str(&output_address)?;

        let (funding_outpoint, funding_utxo) = swap_script.fetch_utxo(network_config)?;

        let electrum = network_config.build_client()?;
        let genesis_hash = liquid_genesis_hash(&network_config)?;

        Ok(LBtcSwapTxV2 {
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

        let msg = Message::from_digest_slice(&Vec::from_hex(&claim_tx_response.transaction_hash)?)?;

        // Step 4: Start the Musig2 Signing session
        let mut extra_rand = [0u8; 32];
        OsRng.fill_bytes(&mut extra_rand);

        let (sec_nonce, pub_nonce) =
            key_agg_cache.nonce_gen(&secp, session_id, keys.public_key(), msg, Some(extra_rand))?;

        let boltz_nonce = MusigPubNonce::from_slice(&Vec::from_hex(&claim_tx_response.pub_nonce)?)?;

        let agg_nonce = MusigAggNonce::new(&secp, &[boltz_nonce, pub_nonce]);

        let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

        let partial_sig = musig_session.partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)?;

        Ok((partial_sig, pub_nonce))
    }

    /// Sign a reverse swap claim transaction.
    /// If the claim is cooperative, provide the other party's partial sigs.
    /// If this is None, transaction will be claimed via taproot script path.
    pub fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: Amount,
        is_cooperative: Option<(&BoltzApiClientV2, String)>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim Tx signing is only applicable for Reverse Swap Type".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Refund {
            return Err(Error::Protocol(
                "Cannot sign claim with Refund type BTCSwapTx".to_string(),
            ));
        }

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

        let unblined_utxo = self
            .funding_utxo
            .unblind(&secp, self.swap_script.blinding_key.secret_key())?;
        let asset_id = unblined_utxo.asset;
        let out_abf = AssetBlindingFactor::new(&mut thread_rng());
        let exp_asset = Asset::Explicit(asset_id);

        let (blinded_asset, asset_surjection_proof) =
            exp_asset.blind(&mut thread_rng(), &secp, out_abf, &[unblined_utxo])?;

        let output_value = Amount::from_sat(unblined_utxo.value) - absolute_fees;

        let final_vbf = ValueBlindingFactor::last(
            &secp,
            output_value.to_sat(),
            out_abf,
            &[(
                unblined_utxo.value,
                unblined_utxo.asset_bf,
                unblined_utxo.value_bf,
            )],
            &[(
                absolute_fees.to_sat(),
                AssetBlindingFactor::zero(),
                ValueBlindingFactor::zero(),
            )],
        );
        let explicit_value = elements::confidential::Value::Explicit(output_value.to_sat());
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
        let fee_output: TxOut = TxOut::new_fee(absolute_fees.to_sat(), asset_id);

        let mut claim_tx = Transaction {
            version: 2,
            lock_time: LockTime::ZERO,
            input: vec![claim_txin],
            output: vec![payment_output, fee_output],
        };

        // If its a cooperative claim, compute the Musig2 Aggregate Signature and use Keypath spending
        if let Some((boltz_api, swap_id)) = is_cooperative {
            let claim_tx_taproot_hash = SighashCache::new(&claim_tx)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.funding_utxo]),
                    SchnorrSighashType::Default,
                    self.genesis_hash,
                )?;

            let msg = Message::from_digest_slice(claim_tx_taproot_hash.as_byte_array())?;

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
            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
            let partial_sig_resp = boltz_api.get_reverse_partial_sig(
                &swap_id,
                &preimage,
                &pub_nonce,
                &claim_tx_hex,
            )?;

            let boltz_public_nonce =
                MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce)?)?;

            let boltz_partial_sig = MusigPartialSignature::from_slice(&Vec::from_hex(
                &partial_sig_resp.partial_signature,
            )?)?;

            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.sender_pubkey.inner,
            );

            if (!boltz_partial_sig_verify) {
                return Err(Error::Taproot(
                    ("Unable to verify Partial Signature".to_string()),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)?;

            let schnorr_sig = musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

            let final_schnorr_sig = SchnorrSig {
                sig: schnorr_sig,
                hash_ty: SchnorrSighashType::Default,
            };

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

            let sighash = SighashCache::new(&claim_tx).taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&self.funding_utxo]),
                leaf_hash,
                SchnorrSighashType::Default,
                self.genesis_hash,
            )?;

            let msg = Message::from_digest_slice(sighash.as_byte_array())?;

            let sig = secp.sign_schnorr(&msg, &keys);

            let final_sig = SchnorrSig {
                sig,
                hash_ty: SchnorrSighashType::Default,
            };

            let control_block = match self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(claim_script.clone(), LeafVersion::default()))
            {
                Some(r) => r,
                None => return Err(Error::Taproot("Could not create control block".to_string())),
            };

            let mut script_witness = Witness::new();
            script_witness.push(final_sig.to_vec());
            script_witness.push(&preimage.bytes.unwrap()); // checked for none
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
    pub fn sign_refund(
        &self,
        keys: &Keypair,
        absolute_fees: Amount,
        is_cooperative: Option<(&BoltzApiClientV2, &String)>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Cannot sign refund tx, for a reverse-swap".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Claim {
            return Err(Error::Protocol(
                "Cannot sign refund with a claim-type BtcSwapTx".to_string(),
            ));
        }

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

        let output_value = Amount::from_sat(unblined_utxo.value) - absolute_fees;

        let final_vbf = ValueBlindingFactor::last(
            &secp,
            output_value.to_sat(),
            out_abf,
            &[(
                unblined_utxo.value,
                unblined_utxo.asset_bf,
                unblined_utxo.value_bf,
            )],
            &[(
                absolute_fees.to_sat(),
                AssetBlindingFactor::zero(),
                ValueBlindingFactor::zero(),
            )],
        );
        let explicit_value = elements::confidential::Value::Explicit(output_value.to_sat());
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
        let fee_output: TxOut = TxOut::new_fee(absolute_fees.to_sat(), asset_id);

        let refund_script = self.swap_script.refund_script();

        let lock_time = match refund_script
            .instructions()
            .filter_map(|i| {
                let ins = i.unwrap();
                if let Instruction::PushBytes(bytes) = ins {
                    if bytes.len() < 5 as usize {
                        Some(LockTime::from_consensus(bytes_to_u32_little_endian(&bytes)))
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
            version: 2,
            lock_time,
            input: vec![refund_txin],
            output: vec![fee_output, payment_output],
        };

        if let Some((boltz_api, swap_id)) = is_cooperative {
            let claim_tx_taproot_hash = SighashCache::new(&refund_tx)
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.funding_utxo]),
                    SchnorrSighashType::Default,
                    self.genesis_hash,
                )?;

            let msg = Message::from_digest_slice(claim_tx_taproot_hash.as_byte_array())?;

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
            let claim_tx_hex = serialize(&refund_tx).to_lower_hex_string();
            let partial_sig_resp =
                boltz_api.get_submarine_partial_sig(&swap_id, &pub_nonce, &claim_tx_hex)?;

            let boltz_public_nonce =
                MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce)?)?;

            let boltz_partial_sig = MusigPartialSignature::from_slice(&Vec::from_hex(
                &partial_sig_resp.partial_signature,
            )?)?;

            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.receiver_pubkey.inner,
            );

            if (!boltz_partial_sig_verify) {
                return Err(Error::Taproot(
                    ("Unable to verify Partial Signature".to_string()),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)?;

            let schnorr_sig = musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

            let final_schnorr_sig = SchnorrSig {
                sig: schnorr_sig,
                hash_ty: SchnorrSighashType::Default,
            };

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

            refund_tx.input[0].witness = witness;

            refund_tx.lock_time = LockTime::ZERO;
        } else {
            let leaf_hash = TapLeafHash::from_script(&refund_script, LeafVersion::default());

            let sighash = SighashCache::new(&refund_tx).taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&self.funding_utxo]),
                leaf_hash,
                SchnorrSighashType::Default,
                self.genesis_hash,
            )?;

            let msg = Message::from_digest_slice(sighash.as_byte_array())?;

            let sig = secp.sign_schnorr(&msg, &keys);

            let final_sig = SchnorrSig {
                sig,
                hash_ty: SchnorrSighashType::Default,
            };

            let control_block = match self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(refund_script.clone(), LeafVersion::default()))
            {
                Some(r) => r,
                None => return Err(Error::Taproot("Could not create control block".to_string())),
            };

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
        }

        Ok(refund_tx)
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(&self, keys: &Keypair, preimage: &Preimage) -> Result<usize, Error> {
        let dummy_abs_fee = Amount::from_sat(5_000);
        let tx = match self.kind {
            SwapTxKind::Claim => self.sign_claim(keys, preimage, dummy_abs_fee, None)?, // TODO: Hardcode cooperative spend size
            SwapTxKind::Refund => self.sign_refund(keys, dummy_abs_fee, None)?,
        };
        Ok(tx.vsize())
    }

    /// Broadcast transaction to the network
    pub fn broadcast(
        &self,
        signed_tx: &Transaction,
        network_config: &ElectrumConfig,
        is_lowball: Option<(&BoltzApiClientV2, Chain)>,
    ) -> Result<String, Error> {
        if let Some((boltz_api, chain)) = is_lowball {
            if chain == Chain::Liquid {
                return Err(Error::Protocol(
                    "Lowball broadcast is not active for main chain".to_string(),
                ));
            }
            log::info!("Attempting lowball braodcast");
            let tx_hex = serialize(signed_tx).to_lower_hex_string();
            let response = boltz_api.broadcast_tx(chain, &tx_hex)?;
            let txid = response
                .as_object()
                .unwrap()
                .get("id")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string();
            log::info!("Broadcasted transaction via Boltz: {}", txid);

            return Ok(txid);
        } else {
            let electrum_client = network_config.build_client()?;
            let serialized = serialize(signed_tx);
            Ok(electrum_client
                .transaction_broadcast_raw(&serialized)?
                .to_string())
        }
    }
}
