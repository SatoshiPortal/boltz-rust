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

use super::boltz::{
    BoltzApiClientV2, ChainClaimTxResponse, ChainSwapDetails, Cooperative, CreateReverseResponse,
    CreateSubmarineResponse, Side, SubmarineClaimTxResponse, SwapTxKind, SwapType, ToSign,
};

/// Liquid v2 swap script helper.
#[derive(Debug, Clone, PartialEq)]
pub struct LBtcSwapScript {
    pub swap_type: SwapType,
    pub side: Option<Side>,
    pub funding_addrs: Option<Address>,
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
    pub blinding_key: ZKKeyPair,
}

impl LBtcSwapScript {
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
            side: None,
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
            side: None,
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey: our_pubkey,
            locktime,
            sender_pubkey: reverse_response.refund_public_key,
            blinding_key,
        })
    }

    /// Create the struct for a chain swap from boltz create response.
    pub fn chain_from_swap_resp(
        side: Side,
        chain_swap_details: ChainSwapDetails,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = Script::from_hex(&chain_swap_details.swap_tree.claim_leaf.output)?;
        let refund_script = Script::from_hex(&chain_swap_details.swap_tree.refund_leaf.output)?;

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

        let funding_addrs = Address::from_str(&chain_swap_details.lockup_address)?;

        let (sender_pubkey, receiver_pubkey) = match side {
            Side::Lockup => (our_pubkey, chain_swap_details.server_public_key),
            Side::Claim => (chain_swap_details.server_public_key, our_pubkey),
        };

        let blinding_str = chain_swap_details
            .blinding_key
            .as_ref()
            .expect("No blinding key provided in ChainSwapDetails");
        let blinding_key = ZKKeyPair::from_seckey_str(&Secp256k1::new(), blinding_str)?;

        Ok(Self {
            swap_type: SwapType::Chain,
            side: Some(side),
            funding_addrs: Some(funding_addrs),
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
                .push_slice(&self.receiver_pubkey.inner.x_only_public_key().0.serialize())
                .push_opcode(OP_CHECKSIG)
                .into_script(),

            SwapType::ReverseSubmarine | SwapType::Chain => EBuilder::new()
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

    pub fn validate_address(&self, chain: Chain, address: String) -> Result<(), Error> {
        let to_address = self.to_address(chain)?;
        if to_address.to_string() == address {
            Ok(())
        } else {
            Err(Error::Protocol("Script/LockupAddress Mismatch".to_string()))
        }
    }

    /// Fetch utxo for script from Electrum
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

    /// Fetch utxo for script from BoltzApi
    pub fn fetch_lockup_utxo_boltz(
        &self,
        network_config: &ElectrumConfig,
        boltz_url: &str,
        swap_id: &str,
    ) -> Result<(OutPoint, TxOut), Error> {
        let boltz_client = BoltzApiClientV2::new(boltz_url);
        let hex = match self.swap_type {
            SwapType::Chain => {
                boltz_client
                    .get_chain_txs(swap_id)?
                    .user_lock
                    .ok_or(Error::Protocol(
                        "No user_lock transaction for Chain Swap available".to_string(),
                    ))?
                    .transaction
                    .hex
            }
            SwapType::ReverseSubmarine => boltz_client.get_reverse_tx(swap_id)?.hex,
            SwapType::Submarine => boltz_client.get_submarine_tx(swap_id)?.hex,
        };

        let address = self.to_address(network_config.network())?;
        let tx: Transaction = elements::encode::deserialize(&hex::decode(&hex)?)?;
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
    pub kind: SwapTxKind,
    pub swap_script: LBtcSwapScript,
    pub output_address: Address,
    pub funding_outpoint: OutPoint,
    pub funding_utxo: TxOut, // there should only ever be one outpoint in a swap
    pub genesis_hash: BlockHash, // Required to calculate sighash
}

impl LBtcSwapTx {
    /// Craft a new ClaimTx. Only works for Reverse and Chain Swaps.
    pub fn new_claim(
        swap_script: LBtcSwapScript,
        output_address: String,
        network_config: &ElectrumConfig,
        boltz_url: String,
        swap_id: String,
    ) -> Result<LBtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim transactions cannot be constructed for Submarine swaps.".to_string(),
            ));
        }

        let (funding_outpoint, funding_utxo) = match swap_script.fetch_utxo(&network_config) {
            Ok(r) => r,
            Err(_) => swap_script.fetch_lockup_utxo_boltz(&network_config, &boltz_url, &swap_id)?,
        };

        let electrum = network_config.build_client()?;
        let genesis_hash = liquid_genesis_hash(&network_config)?;

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Claim,
            swap_script: swap_script,
            output_address: Address::from_str(&output_address)?,
            funding_outpoint,
            funding_utxo,
            genesis_hash,
        })
    }

    /// Construct a RefundTX corresponding to the swap_script. Only works for Submarine and Chain Swaps.
    pub fn new_refund(
        swap_script: LBtcSwapScript,
        output_address: &String,
        network_config: &ElectrumConfig,
        boltz_url: String,
        swap_id: String,
    ) -> Result<LBtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Txs cannot be constructed for Reverse Submarine Swaps.".to_string(),
            ));
        }

        let address = Address::from_str(&output_address)?;
        let (funding_outpoint, funding_utxo) = match swap_script.fetch_utxo(&network_config) {
            Ok(r) => r,
            Err(_) => swap_script.fetch_lockup_utxo_boltz(&network_config, &boltz_url, &swap_id)?,
        };

        let electrum = network_config.build_client()?;
        let genesis_hash = liquid_genesis_hash(&network_config)?;

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Refund,
            swap_script: swap_script,
            output_address: address,
            funding_outpoint,
            funding_utxo,
            genesis_hash,
        })
    }

    /// Compute the Musig partial signature.
    /// This is used to cooperatively close a Submarine or Chain Swap.
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

        let mut key_agg_cache = MusigKeyAggCache::new(&secp, &pubkeys);

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
    /// Panics if called on a Submarine Swap or Refund Tx.
    /// If the claim is cooperative, provide the other party's partial sigs.
    /// If this is None, transaction will be claimed via taproot script path.
    pub fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: Amount,
        is_cooperative: Option<Cooperative>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim Tx signing is not applicable for Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Refund {
            return Err(Error::Protocol(
                "Cannot sign claim with refund-type LBtcSwapTx".to_string(),
            ));
        }

        let preimage_bytes = preimage
            .bytes
            .ok_or(Error::Protocol("No preimage provided".to_string()))?;

        let claim_txin = TxIn {
            sequence: Sequence::MAX,
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
        if let Some(Cooperative {
            boltz_api,
            swap_id,
            pub_nonce,
            partial_sig,
        }) = is_cooperative
        {
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

            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, claim_pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.sender_pubkey.inner, //boltz key
            );

            if (!boltz_partial_sig_verify) {
                return Err(Error::Taproot(
                    ("Unable to verify Partial Signature".to_string()),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(&secp, claim_sec_nonce, &keys, &key_agg_cache)?;

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

    /// Sign a refund transaction.
    /// Panics if called on a Reverse Swap or Claim Tx.
    pub fn sign_refund(
        &self,
        keys: &Keypair,
        absolute_fees: Amount,
        is_cooperative: Option<Cooperative>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Tx signing is not applicable for Reverse Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Claim {
            return Err(Error::Protocol(
                "Cannot sign refund with a claim-type LBtcSwapTx".to_string(),
            ));
        }

        // Create unsigned refund transaction
        let refund_txin = TxIn {
            sequence: Sequence::MAX,
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

        if let Some(Cooperative {
            boltz_api, swap_id, ..
        }) = is_cooperative
        {
            refund_tx.lock_time = LockTime::ZERO;

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
            let refund_tx_hex = serialize(&refund_tx).to_lower_hex_string();
            let partial_sig_resp = match self.swap_script.swap_type {
                SwapType::Chain => {
                    boltz_api.get_chain_partial_sig(&swap_id, &pub_nonce, &refund_tx_hex)
                }
                SwapType::Submarine => {
                    boltz_api.get_submarine_partial_sig(&swap_id, &pub_nonce, &refund_tx_hex)
                }
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

            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.receiver_pubkey.inner, //boltz key
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
        } else {
            refund_tx.input[0].sequence = Sequence::ZERO;

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
            log::info!("Attempting lowball broadcast");
            let tx_hex = serialize(signed_tx).to_lower_hex_string();
            let response = boltz_api.broadcast_tx(chain, &tx_hex)?;

            match response.as_object() {
                None => Err(Error::Protocol("Invalid broadcast reply".to_string())),
                Some(response_map) => match response_map.get("id") {
                    None => Err(Error::Protocol(
                        "No txid found in broadcast reply".to_string(),
                    )),
                    Some(txid_val) => match txid_val.as_str() {
                        None => Err(Error::Protocol("Returned txid is not a string".to_string())),
                        Some(txid_str) => {
                            let txid = txid_str.to_string();
                            log::info!("Broadcasted transaction via Boltz: {txid}");
                            Ok(txid)
                        }
                    },
                },
            }
        } else {
            let electrum_client = network_config.build_client()?;
            let serialized = serialize(signed_tx);
            Ok(electrum_client
                .transaction_broadcast_raw(&serialized)?
                .to_string())
        }
    }
}

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Error> {
    if hex_str.len() % 2 != 0 {
        return Err(Error::Hex(
            "Hex string must have an even length".to_string(),
        ));
    }
    let mut bytes = Vec::new();
    for i in (0..hex_str.len()).step_by(2) {
        let hex_pair = &hex_str[i..i + 2];
        match u8::from_str_radix(hex_pair, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => {
                return Err(Error::Hex(format!(
                    "Invalid hexadecimal pair: {}",
                    hex_pair
                )))
            }
        }
    }

    Ok(bytes)
}
