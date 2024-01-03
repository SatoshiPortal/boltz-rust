use electrum_client::ElectrumApi;
use std::str::FromStr;

use bitcoin::{script::Script as BitcoinScript, secp256k1::KeyPair};
use elements::{
    confidential::{self, AssetBlindingFactor, Nonce, ValueBlindingFactor},
    hashes::hash160,
    secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, Secp256k1, Tag, Tweak},
    sighash::SighashCache,
    Address, AssetId, AssetIssuance, OutPoint, Script, Sequence, SurjectionInput, Transaction,
    TxIn, TxInWitness, TxOut, TxOutSecrets, TxOutWitness, Txid,
};

use elements::encode::{deserialize, serialize};
use elements::secp256k1_zkp::Message;

use crate::{
    network::electrum::{BitcoinNetwork, NetworkConfig},
    swaps::boltz::SwapTxKind,
    util::{
        error::{ErrorKind, S5Error},
        preimage::Preimage,
    },
};

pub const DUST_VALUE: u64 = 546;
// 3-input ASP
pub const DEFAULT_SURJECTIONPROOF_SIZE: u64 = 135;
// 52-bit rangeproof
pub const DEFAULT_RANGEPROOF_SIZE: u64 = 4174;
use bitcoin::PublicKey;
use elements::secp256k1_zkp::{KeyPair as ZKKeyPair, PublicKey as NoncePublicKey};
use elements::{
    address::Address as EAddress,
    opcodes::all::*,
    script::{Builder as EBuilder, Instruction, Script as EScript},
    secp256k1_zkp::PublicKey as ZKPublicKey,
    AddressParams, LockTime,
};

use super::boltz::SwapType;
#[derive(Debug, Clone, PartialEq)]
pub struct LBtcSwapScript {
    network: BitcoinNetwork,
    electrum_url: String,
    swap_type: SwapType,
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
    pub blinding_key: ZKKeyPair,
}

impl LBtcSwapScript {
    pub fn new(
        network: BitcoinNetwork,
        electrum_url: String,
        swap_type: SwapType,
        hashlock: String,
        reciever_pubkey: String,
        timelock: u32,
        sender_pubkey: String,
        blinding_key: ZKKeyPair,
    ) -> Self {
        LBtcSwapScript {
            network,
            electrum_url,
            swap_type,
            hashlock,
            reciever_pubkey,
            timelock,
            sender_pubkey,
            blinding_key,
        }
    }
    pub fn submarine_from_str(
        network: BitcoinNetwork,
        electrum_url: String,
        redeem_script_str: &str,
        blinding_str: String,
    ) -> Result<Self, S5Error> {
        // let script_bytes = hex::decode(redeem_script_str).unwrap().to_owned();
        let script = EScript::from_str(&redeem_script_str).unwrap();
        // let address = Address::p2shwsh(&script, bitcoin::Network::Testnet);

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
                    // println!("{:?}", opcode)
                }

                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_HASH160 {
                        hashlock = Some(hex::encode(bytes));
                    }
                    if last_op == OP_IF {
                        reciever_pubkey = Some(hex::encode(bytes));
                    }
                    if last_op == OP_ELSE {
                        timelock = Some(bytes_to_u32_little_endian(&bytes));
                    }
                    if last_op == OP_DROP {
                        sender_pubkey = Some(hex::encode(bytes));
                    }
                    // println!("{:?}", bytes)
                }
                Err(e) => println!("Error: {:?}", e),
            }
        }

        if hashlock.is_some()
            && sender_pubkey.is_some()
            && timelock.is_some()
            && sender_pubkey.is_some()
        {
            let zksecp = Secp256k1::new();

            Ok(LBtcSwapScript {
                network,
                electrum_url,
                swap_type: SwapType::Submarine,
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
                blinding_key: ZKKeyPair::from_seckey_str(&zksecp, &blinding_str).unwrap(),
            })
        } else {
            Err(S5Error::new(
                ErrorKind::Input,
                &format!(
                    "Could not extract all elements: {:?} {:?} {:?} {:?}",
                    hashlock, reciever_pubkey, timelock, sender_pubkey
                ),
            ))
        }
    }

    pub fn reverse_from_str(
        network: BitcoinNetwork,
        electrum_url: String,
        redeem_script_str: &str,
        blinding_str: String,
    ) -> Result<Self, S5Error> {
        let script = EScript::from_str(&redeem_script_str).unwrap();
        // let address = Address::p2shwsh(&script, bitcoin::Network::Testnet);
        // println!("ADDRESS DECODED: {:?}",address);
        // let script_hash = script.script_hash();
        // let sh_str = hex::encode(script_hash.to_raw_hash().to_string());
        // println!("DECODED SCRIPT HASH: {}",sh_str);
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
                    // println!("{:?}", opcode)
                }

                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_HASH160 {
                        hashlock = Some(hex::encode(bytes));
                    }
                    if last_op == OP_EQUALVERIFY {
                        reciever_pubkey = Some(hex::encode(bytes));
                    }
                    if last_op == OP_DROP {
                        if bytes.len() == 3 as usize {
                            timelock = Some(bytes_to_u32_little_endian(&bytes));
                        } else {
                            sender_pubkey = Some(hex::encode(bytes));
                        }
                    }
                    // println!("{:?}: LENGTH: {}", bytes, bytes.len() )
                }
                Err(e) => println!("Error: {:?}", e),
            }
        }

        if hashlock.is_some()
            && sender_pubkey.is_some()
            && timelock.is_some()
            && sender_pubkey.is_some()
        {
            let zksecp = Secp256k1::new();

            Ok(LBtcSwapScript {
                network,
                electrum_url,
                swap_type: SwapType::ReverseSubmarine,
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
                blinding_key: ZKKeyPair::from_seckey_str(&zksecp, &blinding_str).unwrap(),
            })
        } else {
            Err(S5Error::new(
                ErrorKind::Input,
                &format!(
                    "Could not extract all elements: {:?} {:?} {:?} {:?}",
                    hashlock, reciever_pubkey, timelock, sender_pubkey
                ),
            ))
        }
    }
    pub fn to_script(&self) -> EScript {
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
                let reciever_pubkey = PublicKey::from_str(&self.reciever_pubkey).unwrap();
                let sender_pubkey = PublicKey::from_str(&self.sender_pubkey).unwrap();
                let locktime = LockTime::from_consensus(self.timelock);
                let hashvalue = hash160::Hash::from_str(&self.hashlock).unwrap();
                let hashbytes_slice: &[u8] = hashvalue.as_ref();
                let hashbytes: [u8; 20] =
                    hashbytes_slice.try_into().expect("Hash must be 20 bytes");

                let script = EBuilder::new()
                    .push_opcode(OP_HASH160)
                    .push_slice(&hashbytes)
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_key(&reciever_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_int(locktime.to_consensus_u32() as i64)
                    .push_opcode(OP_CLTV)
                    .push_opcode(OP_DROP)
                    .push_key(&sender_pubkey)
                    .push_opcode(OP_ENDIF)
                    .push_opcode(OP_CHECKSIG)
                    .into_script();

                script
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
                let reciever_pubkey = PublicKey::from_str(&self.reciever_pubkey).unwrap();
                let sender_pubkey = PublicKey::from_str(&self.sender_pubkey).unwrap();
                let locktime = LockTime::from_consensus(self.timelock);
                let hashvalue = hash160::Hash::from_str(&self.hashlock).unwrap();
                let hashbytes_slice: &[u8] = hashvalue.as_ref();
                let hashbytes: [u8; 20] =
                    hashbytes_slice.try_into().expect("Hash must be 20 bytes");

                let script = EBuilder::new()
                    .push_opcode(OP_SIZE)
                    .push_slice(&[32])
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_opcode(OP_HASH160)
                    .push_slice(&hashbytes)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_key(&reciever_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_opcode(OP_DROP)
                    .push_int(locktime.to_consensus_u32() as i64)
                    .push_opcode(OP_CLTV)
                    .push_opcode(OP_DROP)
                    .push_key(&sender_pubkey)
                    .push_opcode(OP_ENDIF)
                    .push_opcode(OP_CHECKSIG)
                    .into_script();

                script
            }
        }
    }

    pub fn to_address(&self) -> EAddress {
        let script = self.to_script();
        let address_params = match self.network {
            BitcoinNetwork::Liquid => &AddressParams::LIQUID,
            _ => &AddressParams::LIQUID_TESTNET,
        };

        match self.swap_type {
            SwapType::Submarine => EAddress::p2shwsh(
                &script,
                Some(self.blinding_key.public_key()),
                address_params,
            )
            .to_confidential(self.blinding_key.public_key()),
            SwapType::ReverseSubmarine => EAddress::p2wsh(
                &script,
                Some(self.blinding_key.public_key()),
                address_params,
            )
            .to_confidential(self.blinding_key.public_key()),
        }
    }
}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}
fn u32_to_bytes_little_endian(value: u32) -> [u8; 4] {
    let b1: u8 = (value & 0xff) as u8;
    let b2: u8 = ((value >> 8) & 0xff) as u8;
    let b3: u8 = ((value >> 16) & 0xff) as u8;
    let b4: u8 = ((value >> 24) & 0xff) as u8;
    [b1, b2, b3, b4]
}

#[derive(Debug, Clone)]
pub struct LBtcSwapTx {
    kind: SwapTxKind,
    swap_script: LBtcSwapScript,
    output_address: Address,
    absolute_fees: u32,
    utxo: Option<OutPoint>,
    utxo_value: Option<u64>, // there should only ever be one outpoint in a swap
    txout_secrets: Option<TxOutSecrets>,
}

impl LBtcSwapTx {
    pub fn manual_utxo_update(&mut self, utxo: OutPoint, value: u64) -> LBtcSwapTx {
        self.utxo = Some(utxo);
        self.utxo_value = Some(value);
        self.clone()
    }
    pub fn new_claim(
        swap_script: LBtcSwapScript,
        output_address: String,
        absolute_fees: u32,
    ) -> Result<LBtcSwapTx, S5Error> {
        let address = match Address::from_str(&output_address) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        Ok(LBtcSwapTx {
            kind: SwapTxKind::Claim,
            swap_script: swap_script,
            output_address: address,
            absolute_fees,
            utxo: None,
            utxo_value: None,
            txout_secrets: None,
        })
    }
    pub fn new_refund(
        swap_script: LBtcSwapScript,
        output_address: String,
        absolute_fees: u32,
    ) -> Result<LBtcSwapTx, S5Error> {
        let address = match Address::from_str(&output_address) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };

        Ok(LBtcSwapTx {
            kind: SwapTxKind::Refund,
            swap_script: swap_script,
            output_address: address,
            absolute_fees,
            utxo: None,
            utxo_value: None,
            txout_secrets: None,
        })
    }

    pub fn drain(&mut self, keys: ZKKeyPair, preimage: Preimage) -> Result<Transaction, S5Error> {
        self.fetch_utxo();
        if !self.has_utxo() {
            return Err(S5Error::new(
                ErrorKind::Transaction,
                "No utxos available yet",
            ));
        }
        match self.kind {
            SwapTxKind::Claim => Ok(self.sign_claim_tx(keys, preimage)),
            SwapTxKind::Refund => {
                self.sign_refund_tx(keys);
                Err(S5Error::new(
                    ErrorKind::Transaction,
                    "Refund transaction signing not supported yet",
                ))
            }
        }
        // let sweep_psbt = Psbt::from_unsigned_tx(sweep_tx);
    }

    fn fetch_utxo(&mut self) -> () {
        let electrum_client = NetworkConfig::default_liquid()
            .electrum_url
            .build_client()
            .unwrap();
        let address = self.swap_script.to_address();
        let history = electrum_client
            .script_get_history(BitcoinScript::from_bytes(
                self.swap_script.to_script().to_v0_p2wsh().as_bytes(),
            ))
            .unwrap();
        let bitcoin_txid = history.first().unwrap().tx_hash;
        let raw_tx = electrum_client.transaction_get_raw(&bitcoin_txid).unwrap();
        let tx: Transaction = elements::encode::deserialize(&raw_tx).unwrap();

        let mut vout = 0;
        for output in tx.output {
            if output.script_pubkey == address.script_pubkey() {
                let zksecp = Secp256k1::new();
                println!("FOUND SPENDABLE OUTPUT!\nvout: {:?}", vout);
                let unblinded = output
                    .unblind(&zksecp, self.swap_script.blinding_key.secret_key())
                    .unwrap();
                // println!("{:?}", unblinded);
                let el_txid = elements::Txid::from_str(&bitcoin_txid.to_string()).unwrap();
                let outpoint_0 = OutPoint::new(el_txid, vout);
                let utxo_value = unblinded.value;
                self.utxo = Some(outpoint_0);
                self.utxo_value = Some(utxo_value);
                self.txout_secrets = Some(unblinded);
                break;
            }
            vout += 1;
        }
        ()
    }
    fn has_utxo(&self) -> bool {
        self.utxo.is_some() && self.utxo_value.is_some()
    }

    pub fn _check_utxo_value(&self, expected_value: u64) -> bool {
        self.has_utxo() && self.utxo_value.unwrap() == expected_value
    }

    fn sign_claim_tx(&self, keys: KeyPair, preimage: Preimage) -> Transaction {
        /*
        *
        * NOTES:
        *
        * decodetransaction additional fields in liquid
           "is_pegin": false,
           "value-minimum": 0.00000001,
           "value-maximum": 687.19476736,
           "ct-exponent": 0,
           "ct-bits": 36,
           "valuecommitment": "0844778d24db8b3454924e3b77d2aa00b4bd57bc20cb852a65238a336b93db7ac6",
           "assetcommitment": "0b96a62e05fcf65a50ad58643a603f21bb033172336c653840accbae54e9fe7dd7",
           "commitmentnonce": "02acc6606bdd8c65bdaeadf1eefec726d0d3b777586922b6255c557bb8e43ac946",
           "commitmentnonce_fully_valid": true,


           In Liquid, the fee is explicitly stated as a vout.
           It is not derived from deducting the vout total from the vin total like in Bitcoin.
        *
        *
        */
        let sequence = Sequence::from_consensus(0xFFFFFFFF);
        let unsigned_input: TxIn = TxIn {
            sequence: sequence,
            previous_output: self.utxo.unwrap(),
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };
        /*
         *
         *
        let surject_inputs = self.surjection_inputs(inp_txout_sec)?;
        let asset_id = self.outputs[last_out_index]
            .asset
            .ok_or(PsetBlindError::MustHaveExplicitTxOut(last_out_index))?;
        let out_abf = AssetBlindingFactor::new(rng);
        let exp_asset = confidential::Asset::Explicit(asset_id);
        let blind_res = exp_asset.blind(rng, secp, out_abf, &surject_inputs);

        let (out_asset_commitment, surjection_proof) =
            blind_res.map_err(|e| PsetBlindError::ConfidentialTxOutError(last_out_index, e))?;

        let value = self.outputs[last_out_index]
            .amount
            .ok_or(PsetBlindError::MustHaveExplicitTxOut(last_out_index))?;
        let exp_value = confidential::Value::Explicit(value);
        // Get all the explicit outputs
        let mut exp_out_secrets = vec![];
        for (i, out) in self.outputs.iter().enumerate() {
            if out.blinding_key.is_none() {
                let amt = out.amount.ok_or(PsetBlindError::MustHaveExplicitTxOut(i))?;
                exp_out_secrets.push((
                    amt,
                    AssetBlindingFactor::zero(),
                    ValueBlindingFactor::zero(),
                ));
            }
        }
        let mut final_vbf =
            ValueBlindingFactor::last(secp, value, out_abf, &inp_secrets, &exp_out_secrets);

        // Add all the scalars
        for value_diff in self.global.scalars.iter() {
            final_vbf += ValueBlindingFactor(*value_diff);
        }

        let receiver_blinding_pk = &self.outputs[last_out_index]
            .blinding_key
            .ok_or(PsetBlindError::MustHaveExplicitTxOut(last_out_index))?;
        let ephemeral_sk = SecretKey::new(rng);
        let spk = &self.outputs[last_out_index].script_pubkey;
        let msg = RangeProofMessage {
            asset: asset_id,
            bf: out_abf,
        };
        let blind_res = exp_value.blind(
            secp,
            final_vbf,
            receiver_blinding_pk.inner,
            ephemeral_sk,
            spk,
            &msg,
        );
        let (value_commitment, nonce, rangeproof) =
            blind_res.map_err(|e| PsetBlindError::ConfidentialTxOutError(last_out_index, e))?;
         *
         */
        use bitcoin::secp256k1::rand::rngs::OsRng;
        let mut rng = OsRng::default();
        let secp = Secp256k1::new();

        let blinding_factor =
            Tweak::from_slice(self.swap_script.blinding_key.secret_bytes().as_ref()).unwrap();
        let nonce = Nonce::Confidential(self.swap_script.blinding_key.public_key());
        let asset_id = AssetId::LIQUID_BTC;
        let out_abf = AssetBlindingFactor::new(&mut rng);
        let exp_asset = confidential::Asset::Explicit(asset_id);
        let inp_txout_secrets = self.txout_secrets.unwrap();

        let (blinded_asset, asset_surjection_proof) = exp_asset
            .blind(&mut rng, &secp, out_abf, &[inp_txout_secrets])
            .unwrap();

        // let tx_out_secrets = TxOutSecrets::new(AssetId::LIQUID_BTC);
        let asset_generator = Generator::new_blinded(
            &secp,
            AssetId::LIQUID_BTC.into_tag(), // as &[u8; 32]
            blinding_factor,
        );
        let output_value = self.utxo_value.unwrap() - self.absolute_fees as u64;
        let out_vbf = ValueBlindingFactor::new(&mut rng);

        let value_generator = Generator::new_blinded(&secp, Tag::default(), blinding_factor);
        let value_pedersen_commitment =
            PedersenCommitment::new(&secp, output_value, blinding_factor, value_generator);
        let explicit_value = elements::confidential::Value::Explicit(output_value);
        let msg = elements::RangeProofMessage {
            asset: asset_id,
            bf: out_abf,
        };
        let (blinded_value, nonce, rangeproof) = explicit_value
            .blind(
                &secp,
                out_vbf,
                self.swap_script.blinding_key.public_key(),
                self.swap_script.blinding_key.secret_key(),
                &self.swap_script.to_script(),
                &msg,
            )
            .unwrap();
        let blinded_asset = elements::confidential::Asset::Confidential(asset_generator);

        let tx_out_witness = TxOutWitness {
            surjection_proof: Some(Box::new(asset_surjection_proof)), // from asset blinding
            rangeproof: None,                                         // from value blinding
        };
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: explicit_value,
            asset: blinded_asset,
            nonce: nonce,
            witness: tx_out_witness,
        };

        let unsigned_tx = Transaction {
            version: 1,
            lock_time: LockTime::from_consensus(self.swap_script.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };

        // SIGN TRANSACTION
        let sighash = Message::from_slice(
            &SighashCache::new(&unsigned_tx).segwitv0_sighash(
                0,
                &&self.swap_script.to_script(),
                explicit_value,
                elements::EcdsaSighashType::All,
            )[..],
        )
        .unwrap();
        let signature = secp.sign_ecdsa(&sighash, &keys.secret_key());

        let mut script_witness: Vec<Vec<u8>> = vec![vec![]];
        script_witness.push(hex::decode(&signature.serialize_der().to_string()).unwrap());
        script_witness.push(preimage.bytes.unwrap().to_vec());
        script_witness.push(self.swap_script.to_script().as_bytes().to_vec());

        let min_value: u64 = DUST_VALUE;
        let exp: i32 = 0;
        let min_bits: u8 = 36;
        let message: &[u8] = &[];
        let additional_commitment: &[u8] = &[];
        let additional_generator = Generator::new_blinded(&secp, Tag::default(), blinding_factor);

        let amount_rangeproof = RangeProof::new(
            &secp,
            min_value,
            value_pedersen_commitment,
            output_value,
            blinding_factor,
            message,
            additional_commitment,
            keys.secret_key(),
            exp,
            min_bits,
            additional_generator,
        )
        .unwrap();
        let inflation_keys_rangeproof = None;

        let witness = TxInWitness {
            amount_rangeproof: Some(Box::new(amount_rangeproof)),
            inflation_keys_rangeproof,
            script_witness: script_witness.clone(),
            pegin_witness: vec![],
        };

        let signed_txin = TxIn {
            previous_output: self.utxo.unwrap(),
            script_sig: Script::default(),
            sequence: sequence,
            witness: witness,
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let signed_tx = Transaction {
            version: 1,
            lock_time: LockTime::from_consensus(self.swap_script.timelock),
            input: vec![signed_txin],
            output: vec![output.clone()],
        };
        signed_tx
    }
    fn sign_refund_tx(&self, _keys: KeyPair) -> () {
        ()
    }
    pub fn broadcast(&mut self, signed_tx: Transaction) -> Result<String, S5Error> {
        let electrum_client = NetworkConfig::new(
            BitcoinNetwork::LiquidTestnet,
            &self.swap_script.electrum_url,
            true,
            true,
            false,
            None,
        )
        .electrum_url
        .build_client()?;
        let serialized = serialize(&signed_tx);
        match electrum_client.transaction_broadcast_raw(&serialized) {
            Ok(txid) => Ok(txid.to_string()),
            Err(e) => Err(S5Error::new(ErrorKind::Network, &e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::network::electrum::DEFAULT_LIQUID_TESTNET_NODE;

    use super::*;

    use elements::pset::serialize::Serialize;

    /// https://liquidtestnet.com/utils
    /// https://blockstream.info/liquidtestnet
    ///
    #[test]
    #[ignore]
    fn test_liquid_rev_tx() {
        let secp = Secp256k1::new();
        const RETURN_ADDRESS: &str =
            "tlq1qqtc07z9kljll7dk2jyhz0qj86df9gnrc70t0wuexutzkxjavdpht0d4vwhgs2pq2f09zsvfr5nkglc394766w3hdaqrmay4tw";

        let redeem_script_str = "8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac".to_string();
        let expected_address = "tlq1qqtvg2v6wv2akxa8dpcdrfemgwnr09ragwlqagr57ezc8nzrvvd6x32rtt4s3e2xylcukuz64fm2zu0l4erdr2h98zjv07w4rearycpxqlz2gstkfw7ln";
        let _expected_timeout = 1179263;
        let blinding_str = "bf99362dff7e8f2ec01e081215cab9047779da4547a6f47d67bb1cbb8c96961d";
        let blinding_key = ZKKeyPair::from_seckey_str(&secp, blinding_str).unwrap();

        let _id = "s9EBbv";
        let _my_key_pair = KeyPair::from_seckey_str(
            &secp,
            "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1",
        )
        .unwrap();
        let preimage =
            Preimage::from_str("a323c8c5abadca53bb4b732d62d0486ba49ecab7e340d2b44aac13ac813fed29")
                .unwrap();

        let script_elements = LBtcSwapScript::reverse_from_str(
            BitcoinNetwork::LiquidTestnet,
            DEFAULT_LIQUID_TESTNET_NODE.to_string(),
            &redeem_script_str.clone(),
            blinding_str.to_string(),
        )
        .unwrap();

        let address = script_elements.to_address();
        println!("ADDRESS FROM ENCODED: {:?}", address.to_string());
        assert!(address.to_string() == expected_address);

        let mut tx_elements =
            LBtcSwapTx::new_claim(script_elements, RETURN_ADDRESS.to_string(), 300).unwrap();

        let outpoint = OutPoint {
            txid: Txid::from_str(
                "6a05897e425229a199abb2d3d5e5bccadafe41597d07c211dc9330e93bf3ac49",
            )
            .unwrap(),
            vout: 0,
        };
        let out_value = 50_000;

        tx_elements = tx_elements.manual_utxo_update(outpoint, out_value);
        println!("{:?}", tx_elements);
        let signed = tx_elements.drain(_my_key_pair, preimage);
        println!("{:?}", hex::encode(signed.clone().unwrap().serialize()));
        // println!("{:?}", signed.unwrap())
    }

    /*
     *
     *
     * KeyPairString { seckey: "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1", pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986" }
    {"info":[],"warnings":[],"pairs":{"BTC/BTC":{"hash":"a3a295202ab0b65cc9597b82663dbcdc77076e138f6d97285711ab7df086afd5","rate":1,"limits":{"maximal":25000000,"minimal":50000,"maximalZeroConf":{"baseAsset":0,"quoteAsset":0}},"fees":{"percentage":0.5,"percentageSwapIn":0.1,"minerFees":{"baseAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}},"L-BTC/BTC":{"hash":"04df6e4b5a91d62a4e1a7ecb88ca462851d835c4bae955a6c5baad8e047b14e9","rate":1,"limits":{"maximal":25000000,"minimal":1000,"maximalZeroConf":{"baseAsset":100000,"quoteAsset":0}},"fees":{"percentage":0.25,"percentageSwapIn":0.1,"minerFees":{"baseAsset":{"normal":147,"reverse":{"claim":152,"lockup":276}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}},"RBTC/BTC":{"hash":"17acb1892ddaaaf60bf44a6e88a86405922d44f29265cc2ebe9f0f137277aa24","rate":1,"limits":{"maximal":4294967,"minimal":10000,"maximalZeroConf":{"baseAsset":0,"quoteAsset":0}},"fees":{"percentage":0.5,"percentageSwapIn":0.5,"minerFees":{"baseAsset":{"normal":162,"reverse":{"claim":162,"lockup":302}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}}}}
    {"id":"s9EBbv","invoice":"lntb504030n1pjhu7w9sp5a2vkmm292fr6mlsjcdpdr3d5zjffttj66nucq9czmkez42pgzdpspp593c9qjvhfu57xzxeer2utmppd4kyxh9w2fmhc57uemha4z6jjgkqdpz2djkuepqw3hjqnpdgf2yxgrpv3j8yetnwvxqyp2xqcqz959qxpqysgqztrywvj30fqhsq6aawf4ew69y6vwea8ykt4qyendmc3vgn6la2534syaqrx296ud04gvaprex9ns687ljnk6s4d5xqrj2v2pfsqtvkqparpzcd","blindingKey":"bf99362dff7e8f2ec01e081215cab9047779da4547a6f47d67bb1cbb8c96961d","redeemScript":"8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac","lockupAddress":"tlq1qqtvg2v6wv2akxa8dpcdrfemgwnr09ragwlqagr57ezc8nzrvvd6x32rtt4s3e2xylcukuz64fm2zu0l4erdr2h98zjv07w4rearycpxqlz2gstkfw7ln","timeoutBlockHeight":1179263}
    Ok(CreateSwapResponse { id: "s9EBbv", invoice: Some("lntb504030n1pjhu7w9sp5a2vkmm292fr6mlsjcdpdr3d5zjffttj66nucq9czmkez42pgzdpspp593c9qjvhfu57xzxeer2utmppd4kyxh9w2fmhc57uemha4z6jjgkqdpz2djkuepqw3hjqnpdgf2yxgrpv3j8yetnwvxqyp2xqcqz959qxpqysgqztrywvj30fqhsq6aawf4ew69y6vwea8ykt4qyendmc3vgn6la2534syaqrx296ud04gvaprex9ns687ljnk6s4d5xqrj2v2pfsqtvkqparpzcd"), redeem_script: Some("8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac"), timeout_block_height: Some(1179263), onchain_amount: None, lockup_address: Some("tlq1qqtvg2v6wv2akxa8dpcdrfemgwnr09ragwlqagr57ezc8nzrvvd6x32rtt4s3e2xylcukuz64fm2zu0l4erdr2h98zjv07w4rearycpxqlz2gstkfw7ln"), miner_fee_invoice: None, service_fee_percentage: None, preimage: None, claim_address: None, claim_public_key: None, private_key: None, refund_address: None, refund_public_key: None, blinding_key: Some("bf99362dff7e8f2ec01e081215cab9047779da4547a6f47d67bb1cbb8c96961d"), address: None, expected_amount: None })
    Preimage { preimage: "a323c8c5abadca53bb4b732d62d0486ba49ecab7e340d2b44aac13ac813fed29", sha256: "2c705049974f29e308d9c8d5c5ec216d6c435cae52777c53dcceefda8b52922c", hash160: "8514cc9235824c914d94fda549e45d6dec629b97", preimage_bytes: [163, 35, 200, 197, 171, 173, 202, 83, 187, 75, 115, 45, 98, 208, 72, 107, 164, 158, 202, 183, 227, 64, 210, 180, 74, 172, 19, 172, 129, 63, 237, 41], sha256_bytes: [44, 112, 80, 73, 151, 79, 41, 227, 8, 217, 200, 213, 197, 236, 33, 109, 108, 67, 92, 174, 82, 119, 124, 83, 220, 206, 239, 218, 139, 82, 146, 44], hash160_bytes: [133, 20, 204, 146, 53, 130, 76, 145, 77, 148, 253, 165, 73, 228, 93, 109, 236, 98, 155, 151] }
    8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac
    LBtcRevScriptElements { hashlock: "8514cc9235824c914d94fda549e45d6dec629b97", reciever_pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986", timelock: 1179263, sender_pubkey: "02869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec3598", preimage: None, signature: None } , LBtcRevScriptElements { hashlock: "8514cc9235824c914d94fda549e45d6dec629b97", reciever_pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986", timelock: 1179263, sender_pubkey: "02869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec3598", preimage: None, signature: None }
     */

    // use std::io::Write;
    // use std::path::Path;
    // use std::{fs::File, str::FromStr};
    #[test]
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
        // println!("{}", blinding_key.public_key().to_string());
        let _id = "axtHXB";
        let my_key_pair = KeyPair::from_seckey_str(
            &secp,
            "aecbc2bddfcd3fa6953d257a9f369dc20cdc66f2605c73efb4c91b90703506b6",
        )
        .unwrap();

        let decoded = LBtcSwapScript::reverse_from_str(
            BitcoinNetwork::LiquidTestnet,
            DEFAULT_LIQUID_TESTNET_NODE.to_string(),
            &redeem_script_str.clone(),
            boltz_blinding_str.to_string(),
        )
        .unwrap();
        // println!("{:?}", decoded);
        assert_eq!(
            decoded.reciever_pubkey,
            my_key_pair.public_key().to_string()
        );
        assert_eq!(decoded.timelock, expected_timeout);

        let el_script = LBtcSwapScript {
            hashlock: decoded.hashlock,
            reciever_pubkey: decoded.reciever_pubkey,
            sender_pubkey: decoded.sender_pubkey,
            timelock: decoded.timelock,
            network: BitcoinNetwork::LiquidTestnet,
            electrum_url: DEFAULT_LIQUID_TESTNET_NODE.to_string(),
            swap_type: SwapType::ReverseSubmarine,
            blinding_key: boltz_blinding_key,
        };

        let address = el_script.to_address();
        println!("ADDRESS FROM ENCODED: {:?}", address.to_string());
        println!("Blinding Pub: {:?}", address.blinding_pubkey);

        assert_eq!(address.to_string(), expected_address);

        let mut liquid_swap_tx =
            LBtcSwapTx::new_claim(el_script, RETURN_ADDRESS.to_string(), 5_000).unwrap();
        let final_tx = liquid_swap_tx.drain(my_key_pair, preimage).unwrap();
        println!("FINALIZED TX SIZE: {:?}", final_tx.size());
        let txid = liquid_swap_tx.broadcast(final_tx).unwrap();
        println!("TXID: {}", txid);
    }
}

/*
Transaction {
    version: 2,
    lock_time: Blocks(
        Height(
            1195427,
        ),
    ),
    input: [
        TxIn {
            previous_output: OutPoint {
                txid: 0x10c31b81b93a69a635ab337bb48adeefe662d40d3e5d50b319a1fed17485104a,
                vout: 1,
            },
            is_pegin: false,
            script_sig: Script(),
            sequence: Sequence(
                4294967293,
            ),
            asset_issuance: AssetIssuance {
                asset_blinding_nonce: Tweak(0000000000000000000000000000000000000000000000000000000000000000),
                asset_entropy: [1,0,0,0,0,0,0,0,0,0,0,0],
                amount: Null,
                inflation_keys: Null,
            },
            witness: TxInWitness {
                amount_rangeproof: None,
                inflation_keys_rangeproof: None,
                script_witness: [...],
                pegin_witness: [],
            },
        },
    ],
    output: [
        TxOut {
            asset: Confidential(
                Generator(
                    8ff79b82771122d74473bd976a4293ab0bf36f53c87134d67f6f028e501bcab7819cd6587a3bc6a070b77e83de6beed2b8df88812cab0739846cca41de390f5f,
                ),
            ),
            value: Confidential(
                PedersenCommitment(
                    08600d4a9eb4ee992ded59b62ecbb6bba602f77ffcd4a2dfe549e76f8937172ba900000000000000000000000000000000000000000000000000000000000000,
                ),
            ),
            nonce: Confidential(
                PublicKey(
                    f145cb239a483a268e17397efd6a2b079f37bd9f872c6e1d2c467de322def7290197d31727b33a7fa6cf099feeff4a8d223f40459a1fdba393ba797a57aa3a14,
                ),
            ),
            script_pubkey: Script(OP_0 OP_PUSHBYTES_32 f233649a711ff2dddef1b5f585f1375ec045099f83a1b3e1fc63d8fe010b1493),
            witness: TxOutWitness {
                surjection_proof: Some(
                    SurjectionProof {
                        inner: SurjectionProof {
                            n_inputs: 1,
                            used_inputs: [...],
                            data: [...],
                        },
                    },
                ),
                rangeproof: Some(
                    RangeProof {
                        inner: RangeProof(
                            [...],
                        ),
                    },
                ),
            },
        },
        TxOut {
            asset: Confidential(
                Generator(
                    56addeefbaeb6543735b3ffefd71beed41cec402379b5aa486b9586757d0358be76dbc5de43796ec109a92866d081c07c87fe35bc228da98521867e58833d202,
                ),
            ),
            value: Confidential(
                PedersenCommitment(
                    09bf4134766c6d659e018a94a6bcc1ef842a85c2b4360dae2daf9217aedfcdc57600000000000000000000000000000000000000000000000000000000000000,
                ),
            ),
            nonce: Confidential(
                PublicKey(
                    125bcca9a718c16ea2f1e0623d4e2dc32008d3f278ddc9a423028d101c37bdac570128f0ba36c97ef7bb4cf034305053d6d3e091dcf0d2e742bebb2e05021bcb,
                ),
            ),
            script_pubkey: Script(OP_0 OP_PUSHBYTES_20 53919f7c33109507ae46caedc81ad064f3bc6298),
            witness: TxOutWitness {
                surjection_proof: Some(
                    SurjectionProof {
                        inner: SurjectionProof {
                            n_inputs: 1,
                            used_inputs: [...],
                            data: [...],
                        },
                    },
                ),
                rangeproof: Some(
                    RangeProof {
                        inner: RangeProof(
                            [...],
                        ),
                    },
                ),
            },
        },
        TxOut {
            asset: Explicit(
                0x144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49,
            ),
            value: Explicit(
                250,
            ),
            nonce: Null,
            script_pubkey: Script(),
            witness: TxOutWitness {
                surjection_proof: None,
                rangeproof: None,
            },
        },
    ],
}
*/

/*

let manifest_dir = env!("CARGO_MANIFEST_DIR");
let file_path = Path::new(manifest_dir).join("tx.hex");
let mut file = File::create(file_path).unwrap();
writeln!(file, "{}", serialized).unwrap();
println!("CHECK FILE tx.hex!");
 */
