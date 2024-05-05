use electrum_client::ElectrumApi;
use std::{hash, str::FromStr};

use bitcoin::{
    hashes::{hash160, Hash},
    script::Script as BitcoinScript,
    secp256k1::Keypair,
    Witness,
};
use elements::{
    confidential::{self, AssetBlindingFactor, Value, ValueBlindingFactor},
    hex::ToHex,
    secp256k1_zkp::{self, Secp256k1, SecretKey},
    sighash::SighashCache,
    Address, AssetIssuance, LockTime, OutPoint, Script, Sequence, Transaction, TxIn, TxInWitness,
    TxOut, TxOutSecrets, TxOutWitness,
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

use super::boltz::SwapType;

/// Liquid swap script helper.
#[derive(Debug, Clone, PartialEq)]
pub struct LBtcSwapScript {
    pub swap_type: SwapType,
    pub hashlock: hash160::Hash,
    pub reciever_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
    pub blinding_key: ZKKeyPair,
}

impl LBtcSwapScript {
    /// Create the struct from a submarine swap redeem_script string.
    ///Usually created from the string provided by boltz api response.
    pub fn submarine_from_str(redeem_script_str: &str, blinding_str: &str) -> Result<Self, Error> {
        let script = EScript::from_str(&redeem_script_str)?;

        let instructions = script.instructions();
        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut reciever_pubkey = None;
        let mut timelock = None;
        let mut sender_pubkey = None;

        for instruction in instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => {
                    last_op = opcode;
                }

                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_HASH160 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
                    }
                    if last_op == OP_IF {
                        reciever_pubkey = Some(PublicKey::from_slice(&bytes)?);
                    }
                    if last_op == OP_ELSE {
                        timelock =
                            Some(LockTime::from_consensus(bytes_to_u32_little_endian(&bytes)));
                    }
                    if last_op == OP_DROP {
                        sender_pubkey = Some(PublicKey::from_slice(&bytes)?);
                    }
                }
                _ => (),
            }
        }
        let zksecp = Secp256k1::new();
        if hashlock.is_some()
            && reciever_pubkey.is_some()
            && timelock.is_some()
            && sender_pubkey.is_some()
        {
            Ok(LBtcSwapScript {
                swap_type: SwapType::Submarine,
                hashlock: hashlock.expect("Not none"),
                reciever_pubkey: reciever_pubkey.expect("Not none"),
                locktime: timelock.expect("Not none"),
                sender_pubkey: sender_pubkey.expect("Not none"),
                blinding_key: ZKKeyPair::from_seckey_str(&zksecp, &blinding_str)?,
            })
        } else {
            Err(Error::Protocol(format!(
                "Could not extract all elements: {:?} {:?} {:?} {:?}",
                hashlock, reciever_pubkey, timelock, sender_pubkey
            )))
        }
    }

    /// Create the struct from a reverse swap redeem_script string.
    /// Usually created from the string provided by boltz api response.
    pub fn reverse_from_str(redeem_script_str: &str, blinding_str: &str) -> Result<Self, Error> {
        let script = EScript::from_str(redeem_script_str)?;

        let instructions = script.instructions();
        let mut last_op = OP_0NOTEQUAL;
        let mut hashlock = None;
        let mut reciever_pubkey = None;
        let mut timelock = None;
        let mut sender_pubkey = None;

        for instruction in instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => {
                    last_op = opcode;
                }

                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_HASH160 {
                        hashlock = Some(hash160::Hash::from_slice(bytes)?);
                    }
                    if last_op == OP_EQUALVERIFY {
                        reciever_pubkey = Some(PublicKey::from_slice(bytes)?);
                    }
                    if last_op == OP_DROP {
                        if bytes.len() == 3 as usize {
                            timelock =
                                Some(LockTime::from_consensus(bytes_to_u32_little_endian(&bytes)));
                        } else {
                            sender_pubkey = Some(PublicKey::from_slice(bytes)?);
                        }
                    }
                }
                _ => (),
            }
        }
        let zksecp = Secp256k1::new();
        if hashlock.is_some()
            && reciever_pubkey.is_some()
            && timelock.is_some()
            && sender_pubkey.is_some()
        {
            Ok(LBtcSwapScript {
                swap_type: SwapType::ReverseSubmarine,
                hashlock: hashlock.expect("Not None"),
                reciever_pubkey: reciever_pubkey.expect("Not None"),
                locktime: timelock.expect("Not None"),
                sender_pubkey: sender_pubkey.expect("Not None"),
                blinding_key: ZKKeyPair::from_seckey_str(&zksecp, &blinding_str)?,
            })
        } else {
            Err(Error::Protocol(format!(
                "Could not extract all elements: {:?} {:?} {:?} {:?}",
                hashlock, reciever_pubkey, timelock, sender_pubkey
            )))
        }
    }

    /// Internally used to convert struct into a bitcoin::Script type
    pub fn to_script(&self) -> Result<EScript, Error> {
        /*
            HASH160 <hash of the preimage>
            EQUAL
            IF <reciever public key>
            ELSE <timeout block height>
            CHECKLOCKTIMEVERIFY
            DROP <sender public key>
            ENDIF
            CHECKSIG
        */
        match self.swap_type {
            SwapType::Submarine => {
                let script = EBuilder::new()
                    .push_opcode(OP_HASH160)
                    .push_slice(self.hashlock.as_byte_array())
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_key(&self.reciever_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_int(self.locktime.to_consensus_u32() as i64)
                    .push_opcode(OP_CLTV)
                    .push_opcode(OP_DROP)
                    .push_key(&self.sender_pubkey)
                    .push_opcode(OP_ENDIF)
                    .push_opcode(OP_CHECKSIG)
                    .into_script();

                Ok(script)
            }
            SwapType::ReverseSubmarine => {
                /*
                    OP_SIZE
                    [32]
                    OP_EQUAL
                    OP_IF
                    OP_HASH160 <hash of the preimage>
                    OP_EQUALVERIFY <reciever public key>
                    OP_ELSE
                    OP_DROP <timeout block height>
                    OP_CLTV
                    OP_DROP <sender public key>
                    OP_ENDIF
                    OP_CHECKSIG
                */
                let script = EBuilder::new()
                    .push_opcode(OP_SIZE)
                    .push_slice(&[32])
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_opcode(OP_HASH160)
                    .push_slice(self.hashlock.as_byte_array())
                    .push_opcode(OP_EQUALVERIFY)
                    .push_key(&self.reciever_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_opcode(OP_DROP)
                    .push_int(self.locktime.to_consensus_u32() as i64)
                    .push_opcode(OP_CLTV)
                    .push_opcode(OP_DROP)
                    .push_key(&self.sender_pubkey)
                    .push_opcode(OP_ENDIF)
                    .push_opcode(OP_CHECKSIG)
                    .into_script();

                Ok(script)
            }
        }
    }

    /// Get address for the swap script.
    /// Submarine swaps use p2shwsh. Reverse swaps use p2wsh.
    /// Always returns a confidential address
    pub fn to_address(&self, network: Chain) -> Result<EAddress, Error> {
        let script = self.to_script()?;
        let address_params = match network {
            Chain::Liquid => &AddressParams::LIQUID,
            _ => &AddressParams::LIQUID_TESTNET,
        };

        match self.swap_type {
            SwapType::Submarine => Ok(EAddress::p2wsh(
                &script,
                Some(self.blinding_key.public_key()),
                address_params,
            )),
            SwapType::ReverseSubmarine => Ok(EAddress::p2wsh(
                &script,
                Some(self.blinding_key.public_key()),
                address_params,
            )),
        }
    }

    /// Get balance for the swap script
    pub fn get_balance(&self, network_config: &ElectrumConfig) -> Result<(u64, i64), Error> {
        let electrum_client = network_config.clone().build_client()?;

        // let _ = electrum_client
        //     .script_subscribe(BitcoinScript::from_bytes(
        //         &self
        //             .to_address(network_config.network())?
        //             .script_pubkey()
        //             .as_bytes(),
        //     ))
        //     .unwrap();

        let _ = electrum_client.script_subscribe(BitcoinScript::from_bytes(
            &self
                .to_address(network_config.network())?
                .script_pubkey()
                .as_bytes(),
        ))?;

        // let balance = electrum_client
        //     .script_get_balance(BitcoinScript::from_bytes(
        //         &self
        //             .to_address(network_config.network())?
        //             .script_pubkey()
        //             .as_bytes(),
        //     ))
        //     .unwrap();

        let balance = electrum_client.script_get_balance(BitcoinScript::from_bytes(
            &self
                .to_address(network_config.network())?
                .script_pubkey()
                .as_bytes(),
        ))?;

        // let _ = electrum_client
        //     .script_unsubscribe(BitcoinScript::from_bytes(
        //         &self
        //             .to_address(network_config.network())?
        //             .script_pubkey()
        //             .as_bytes(),
        //     ))
        //     .unwrap();
        // Ok((balance.confirmed, balance.unconfirmed))

        let _ = electrum_client.script_unsubscribe(BitcoinScript::from_bytes(
            &self
                .to_address(network_config.network())?
                .script_pubkey()
                .as_bytes(),
        ))?;
        Ok((balance.confirmed, balance.unconfirmed))
    }

    /// Fetch utxo for script
    pub fn fetch_utxo(
        &self,
        network_config: &ElectrumConfig,
        raw_tx: Option<Vec<u8>>,
    ) -> Result<(OutPoint, u64, Option<Value>, Option<TxOutSecrets>), Error> {
        let electrum_client = network_config.clone().build_client()?;
        let address = self.to_address(network_config.network())?;

        let raw_tx = if let Some(tx) = raw_tx {
            tx
        } else {
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
            raw_tx
        };

        let tx: Transaction = elements::encode::deserialize(&raw_tx)?;
        let mut vout = 0;
        for output in tx.clone().output {
            if output.script_pubkey == address.script_pubkey() {
                let zksecp = Secp256k1::new();
                let is_blinded = output.asset.is_confidential() && output.value.is_confidential();
                if !is_blinded {
                    let el_txid = tx.clone().txid();
                    let outpoint_0 = OutPoint::new(el_txid, vout);
                    let output_explicit = output
                        .value
                        .explicit()
                        .ok_or_else(|| Error::Protocol("No sender_pubkey provided".to_string()))?;
                    return Ok((outpoint_0, output_explicit, None, None));
                } else {
                    let unblinded = output.unblind(&zksecp, self.blinding_key.secret_key())?;
                    let el_txid = tx.clone().txid();
                    let outpoint_0 = OutPoint::new(el_txid, vout);
                    let utxo_value = unblinded.value;

                    return Ok((outpoint_0, utxo_value, Some(output.value), Some(unblinded)));
                }
            }
            vout += 1;
        }
        return Err(Error::Protocol(
            "Could not find utxos for script".to_string(),
        ));
    }
}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}
fn _u32_to_bytes_little_endian(value: u32) -> [u8; 4] {
    let b1: u8 = (value & 0xff) as u8;
    let b2: u8 = ((value >> 8) & 0xff) as u8;
    let b3: u8 = ((value >> 16) & 0xff) as u8;
    let b4: u8 = ((value >> 24) & 0xff) as u8;
    [b1, b2, b3, b4]
}

pub type ElementsSig = (secp256k1_zkp::ecdsa::Signature, elements::EcdsaSighashType);

/// Internal elements signature helper
fn elementssig_to_rawsig(sig: &ElementsSig) -> Vec<u8> {
    let ser_sig = sig.0.serialize_der();
    let mut raw_sig = Vec::from(&ser_sig[..]);
    raw_sig.push(sig.1 as u8);
    raw_sig
}

/// Liquid swap transaction helper.
#[derive(Debug, Clone)]
pub struct LBtcSwapTx {
    kind: SwapTxKind,
    swap_script: LBtcSwapScript,
    output_address: Address,
    utxo: OutPoint,
    utxo_value: u64, // there should only ever be one outpoint in a swap
    utxo_confidential_value: Option<elements::confidential::Value>,
    txout_secrets: Option<TxOutSecrets>,
}

impl LBtcSwapTx {
    /// Required to claim reverse swaps only. This is never used for submarine swaps.
    pub fn new_claim(
        swap_script: LBtcSwapScript,
        output_address: String,
        tx: String,
        network_config: &ElectrumConfig,
    ) -> Result<LBtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim transactions can only be constructed for Reverse swaps.".to_string(),
            ));
        }

        let tx_bytes = hex::decode(&tx).map_err(|e| Error::Protocol(format!("Could not decode tx: {}", e)))?;

        let (utxo, utxo_value, utxo_confidential_value, txout_secrets) =
            swap_script.fetch_utxo(network_config, Some(tx_bytes))?;

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Claim,
            swap_script: swap_script,
            output_address: Address::from_str(&output_address)?,
            utxo,
            utxo_value,
            utxo_confidential_value,
            txout_secrets,
        })
    }
    /// Required to claim submarine swaps only. This is never used for reverse swaps.
    pub fn new_refund(
        swap_script: LBtcSwapScript,
        output_address: String,
        tx: String,
        network_config: &ElectrumConfig,
    ) -> Result<LBtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Txs can only be constructed for Submarine Swaps.".to_string(),
            ));
        }

        let address = Address::from_str(&output_address)?;

        let tx_bytes = hex::decode(&tx).map_err(|e| Error::Protocol(format!("Could not decode tx: {}", e)))?;

        let (utxo, utxo_value, utxo_confidential_value, txout_secrets) =
            swap_script.fetch_utxo(network_config, Some(tx_bytes))?;

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Refund,
            swap_script: swap_script,
            output_address: address,
            utxo,
            utxo_value,
            utxo_confidential_value,
            txout_secrets,
        })
    }

    /// Internally used to check if utxos are present in the struct to build the transaction.
    fn _is_confidential(&self) -> bool {
        self.txout_secrets.is_some() && self.utxo_confidential_value.is_some()
    }

    /// Sign a claim transaction for a reverse swap
    pub fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: u64,
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
        let redeem_script = self.swap_script.to_script()?;

        let sequence = Sequence::MAX;
        let unsigned_input: TxIn = TxIn {
            sequence: sequence,
            previous_output: self.utxo,
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        use bitcoin::secp256k1::rand::rngs::OsRng;
        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        let is_explicit_utxo =
            self.utxo_confidential_value.is_none() && self.txout_secrets.is_none();

        if is_explicit_utxo {
            todo!()
        }
        let txout_secrets = self
            .txout_secrets
            .ok_or(Error::Protocol("No txout_secrets in script".to_string()))?;

        let asset_id = txout_secrets.asset;
        let out_abf = AssetBlindingFactor::new(&mut rng);
        let exp_asset = confidential::Asset::Explicit(asset_id);

        let (blinded_asset, asset_surjection_proof) =
            exp_asset.blind(&mut rng, &secp, out_abf, &[txout_secrets])?;

        let output_value = self.utxo_value - absolute_fees;

        let final_vbf = ValueBlindingFactor::last(
            &secp,
            output_value,
            out_abf,
            &[(
                txout_secrets.value,
                txout_secrets.asset_bf,
                txout_secrets.value_bf,
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
        let ephemeral_sk = SecretKey::new(&mut rng);
        // assuming we always use a blinded address that has an extractable blinding pub
        let blinding_key = self
            .output_address
            .blinding_pubkey
            .ok_or(Error::Protocol("No Blinding key in tx".to_string()))?;
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

        let unsigned_tx = Transaction {
            version: 2,
            lock_time: self.swap_script.locktime,
            input: vec![unsigned_input],
            output: vec![payment_output.clone(), fee_output.clone()],
        };

        let utxo_confidential_value = self.utxo_confidential_value.ok_or(Error::Protocol(
            "No utxo confidential value in tx.".to_string(),
        ))?;

        // SIGN TRANSACTION
        let hash_type = elements::EcdsaSighashType::All;
        let sighash = Message::from_digest_slice(
            &SighashCache::new(&unsigned_tx).segwitv0_sighash(
                0,
                &redeem_script,
                utxo_confidential_value,
                hash_type,
            )[..],
        )?;

        let sig: secp256k1_zkp::ecdsa::Signature =
            secp.sign_ecdsa_low_r(&sighash, &keys.secret_key());
        let sig = elementssig_to_rawsig(&(sig, hash_type));

        let mut script_witness = Witness::new();
        script_witness.push(sig);
        script_witness.push(preimage_bytes);
        script_witness.push(redeem_script.as_bytes());

        let witness = TxInWitness {
            amount_rangeproof: None,
            inflation_keys_rangeproof: None,
            script_witness: script_witness.to_vec(),
            pegin_witness: vec![],
        };

        let signed_txin = TxIn {
            previous_output: self.utxo,
            script_sig: Script::default(),
            sequence: sequence,
            witness: witness,
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let signed_tx = Transaction {
            version: 2,
            lock_time: self.swap_script.locktime,
            input: vec![signed_txin],
            output: vec![payment_output, fee_output],
        };
        Ok(signed_tx)
    }

    /// Sign a refund transaction for a submarine swap
    pub fn sign_refund(&self, keys: &Keypair, absolute_fees: u64) -> Result<Transaction, Error> {
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

        let redeem_script = self.swap_script.to_script()?;
        let sequence = Sequence::ZERO;
        let unsigned_input: TxIn = TxIn {
            sequence: sequence,
            previous_output: self.utxo,
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        use bitcoin::secp256k1::rand::rngs::OsRng;
        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        let is_explicit_utxo =
            self.utxo_confidential_value.is_none() && self.txout_secrets.is_none();

        if is_explicit_utxo {
            todo!()
        }
        let txout_secrets = self
            .txout_secrets
            .ok_or(Error::Protocol("No txout_secrets in script.".to_string()))?;
        let asset_id = txout_secrets.asset;
        let out_abf = AssetBlindingFactor::new(&mut rng);
        let exp_asset = confidential::Asset::Explicit(asset_id);

        let (blinded_asset, asset_surjection_proof) =
            exp_asset.blind(&mut rng, &secp, out_abf, &[txout_secrets])?;

        let output_value = self.utxo_value - absolute_fees;

        let final_vbf = ValueBlindingFactor::last(
            &secp,
            output_value,
            out_abf,
            &[(
                txout_secrets.value,
                txout_secrets.asset_bf,
                txout_secrets.value_bf,
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
        let ephemeral_sk = SecretKey::new(&mut rng);
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

        let unsigned_tx = Transaction {
            version: 2,
            lock_time: self.swap_script.locktime,
            input: vec![unsigned_input],
            output: vec![payment_output.clone(), fee_output.clone()],
        };
        let utxo_confidential_value = self.utxo_confidential_value.ok_or(Error::Protocol(
            "No utxo confidential value in tx".to_string(),
        ))?;

        // SIGN TRANSACTION
        let hash_type = elements::EcdsaSighashType::All;
        let sighash = Message::from_digest_slice(
            &SighashCache::new(&unsigned_tx).segwitv0_sighash(
                0,
                &redeem_script,
                utxo_confidential_value,
                hash_type,
            )[..],
        )?;

        let sig: secp256k1_zkp::ecdsa::Signature =
            secp.sign_ecdsa_low_r(&sighash, &keys.secret_key());
        let sig = elementssig_to_rawsig(&(sig, hash_type));

        let mut script_witness = Witness::new();
        script_witness.push(sig);
        script_witness.push([0]);
        script_witness.push(redeem_script.as_bytes());

        let witness = TxInWitness {
            amount_rangeproof: None,
            inflation_keys_rangeproof: None,
            script_witness: script_witness.to_vec(),
            pegin_witness: vec![],
        };

        let signed_txin = TxIn {
            previous_output: self.utxo,
            script_sig: Script::default(),
            sequence: sequence,
            witness: witness,
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let signed_tx = Transaction {
            version: 2,
            lock_time: self.swap_script.locktime,
            input: vec![signed_txin],
            output: vec![payment_output, fee_output],
        };
        Ok(signed_tx)
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(&self, keys: &Keypair, preimage: &Preimage) -> Result<usize, Error> {
        let dummy_abs_fee = 5_000;
        let tx = match self.kind {
            _ => self.sign_claim(keys, preimage, dummy_abs_fee)?,
        };
        Ok(tx.size())
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore]
    fn test_fetch_utxo_fix() {
        const _RETURN_ADDRESS: &str =
        "tlq1qqtc07z9kljll7dk2jyhz0qj86df9gnrc70t0wuexutzkxjavdpht0d4vwhgs2pq2f09zsvfr5nkglc394766w3hdaqrmay4tw";
        let redeem_script_str = "8201208763a9142bdd03d431251598f46a625f1d3abfcd7f491535882102ccbab5f97c89afb97d814831c5355ef5ba96a18c9dcd1b5c8cfd42c697bfe53c677503715912b1752103fced00385bd14b174a571d88b4b6aced2cb1d532237c29c4ec61338fbb7eff4068ac".to_string();
        let blinding_str = "02702ae71ec11a895f6255e26395983585a0d791ea1eb83d1aa54a66056469da";
        let script =
            LBtcSwapScript::reverse_from_str(&redeem_script_str.clone(), blinding_str).unwrap();
        let network_config = &ElectrumConfig::default_liquid();
        let address = script.to_address(network_config.network()).unwrap();
        println!("{:?}", address.to_string());
        // let balance = script.get_balance(network_config.clone()).unwrap();
        // println!("BALANCE: {:?}", balance);

        let _status = network_config
            .build_client()
            .unwrap()
            .script_subscribe(BitcoinScript::from_bytes(
                &script
                    .to_address(Chain::LiquidTestnet)
                    .unwrap()
                    .script_pubkey()
                    .as_bytes(),
            ))
            .unwrap();
        // println!("Sub status: {:#?}",_status);

        // let utxo_from_raw = network_config
        // .build_client()
        // .unwrap()
        // .raw_call("blockchain.address.listunspent", [Param::String(script
        //         .to_address(Chain::LiquidTestnet)
        //         .unwrap()
        //         .to_string())]
        // )
        // .unwrap();
        // println!("{:#?}",utxo_from_raw);
        let utxo = network_config
            .build_client()
            .unwrap()
            .script_list_unspent(BitcoinScript::from_bytes(
                &script
                    .to_address(Chain::LiquidTestnet)
                    .unwrap()
                    .script_pubkey()
                    .as_bytes(),
            ))
            .unwrap();
        println!("{:#?}", utxo);

        let _ =
            network_config
                .build_client()
                .unwrap()
                .script_unsubscribe(BitcoinScript::from_bytes(
                    &script
                        .to_address(Chain::LiquidTestnet)
                        .unwrap()
                        .script_pubkey()
                        .as_bytes(),
                ));

        // println!("ATTEMPTING TO GET BLOCKHEIGHT FROM ELECTRUM CLIENT");

        // let blockheight = network_config.build_client().unwrap().block_headers_subscribe().unwrap();
        // println!("{:?}", blockheight);

        // let mut liquid_swap_tx =
        //     LBtcSwapTx::new_claim(script, RETURN_ADDRESS.to_string()).unwrap();
        // // let _ = liquid_swap_tx.fetch_utxo(network_config.clone()).unwrap();
        // let _ = liquid_swap_tx.fetch_utxo_raw(network_config.clone()).unwrap();
    }

    #[test]
    fn test_script_address() {
        let rs = "a91430dd7bf6e97514be2ec0d1368790f763184b7f848763210301798770066e9d93803ced62f169d06567683d26a180f87be736e1af00eaba116703fa0113b1752102c530b4583640ab3df5c75c5ce381c4b747af6bdd6c618db7e5248cb0adcf3a1868ac";
        let blinder = "89b7b9e32cb141787ae187f0d7db784eb114ea7e69da7be9bebafee3f3dbb64e";
        let exp_addr =
            "tlq1qqdtkt2czrht3mjy7kwtauq0swtvr5tfxysvcekmrzraayu025wjl8537am2epmhzl40e27mpuxr2cp36emmmtudjquf5lruld437rz0tkqxu72j38yjz";
        let script = LBtcSwapScript::submarine_from_str(rs, blinder).unwrap();
        assert_eq!(
            script.to_address(Chain::LiquidTestnet).unwrap().to_string(),
            exp_addr
        );
    }
    #[test]
    #[ignore]
    fn test_liquid_swap_elements() {
        // let secp = Secp256k1::new();
        let secp = Secp256k1::new();
        const RETURN_ADDRESS: &str =
        "tlq1qqtc07z9kljll7dk2jyhz0qj86df9gnrc70t0wuexutzkxjavdpht0d4vwhgs2pq2f09zsvfr5nkglc394766w3hdaqrmay4tw";
        let redeem_script_str = "8201208763a9142bdd03d431251598f46a625f1d3abfcd7f491535882102ccbab5f97c89afb97d814831c5355ef5ba96a18c9dcd1b5c8cfd42c697bfe53c677503715912b1752103fced00385bd14b174a571d88b4b6aced2cb1d532237c29c4ec61338fbb7eff4068ac".to_string();
        let expected_address = "tlq1qq0gnj2my5tp8r77srvvdmwfrtr8va9mgz9e8ja0rzk75jvsanjvgz5sfvl093l5a7xztrtzhyhfmfyr2exdxtpw7cehfgtzgn62zdzcsgrz8c4pjfvtj";
        let expected_timeout = 1202545;
        let boltz_blinding_str = "02702ae71ec11a895f6255e26395983585a0d791ea1eb83d1aa54a66056469da";
        let boltz_blinding_key = ZKKeyPair::from_seckey_str(&secp, boltz_blinding_str).unwrap();
        let preimage_str = "6ef7d91c721ea06b3b65d824ae1d69777cd3892d41090234aef13a572ff0e64f";
        let preimage = Preimage::from_str(preimage_str).unwrap();
        let _id = "axtHXB";
        let my_key_pair = ZKKeyPair::from_seckey_str(
            &secp,
            "aecbc2bddfcd3fa6953d257a9f369dc20cdc66f2605c73efb4c91b90703506b6",
        )
        .unwrap();
        let network_config = &ElectrumConfig::default_liquid();
        let decoded =
            LBtcSwapScript::reverse_from_str(&redeem_script_str.clone(), boltz_blinding_str)
                .unwrap();
        // println!("{:?}", decoded);
        assert_eq!(decoded.reciever_pubkey.inner, my_key_pair.public_key());
        assert_eq!(decoded.locktime.to_consensus_u32(), expected_timeout);

        let el_script = LBtcSwapScript {
            hashlock: decoded.hashlock,
            reciever_pubkey: decoded.reciever_pubkey,
            sender_pubkey: decoded.sender_pubkey,
            locktime: decoded.locktime,
            swap_type: SwapType::ReverseSubmarine,
            blinding_key: boltz_blinding_key,
        };

        let address = el_script.to_address(network_config.network()).unwrap();
        println!("ADDRESS FROM ENCODED: {:?}", address.to_string());
        println!("Blinding Pub: {:?}", address.blinding_pubkey);

        assert_eq!(address.to_string(), expected_address);

        let liquid_swap_tx =
            LBtcSwapTx::new_claim(el_script, RETURN_ADDRESS.to_string(), "".to_string(), network_config).unwrap();
        //let _ = liquid_swap_tx.fetch_utxo(&network_config).unwrap();
        println!("{:#?}", liquid_swap_tx);
        let final_tx = liquid_swap_tx
            .sign_claim(&my_key_pair, &preimage, 5_000)
            .unwrap();
        println!("FINALIZED TX SIZE: {:?}", final_tx.size());
        // let manifest_dir = env!("CARGO_MANIFEST_DIR");

        // let file_path = Path::new(manifest_dir).join("tx.constructed");
        // let mut file = File::create(file_path).unwrap();
        // use std::io::Write;
        // writeln!(file, "{:#?}", final_tx).unwrap();
        // println!("CHECK FILE tx.hex!");

        let txid = liquid_swap_tx.broadcast(final_tx, &network_config).unwrap();
        println!("TXID: {}", txid);
    }
}
