use bitcoin::consensus::Decodable;
use bitcoin::ecdsa::Signature;
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::script::{PushBytes, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{
    blockdata::script::{Builder, Instruction, Script, ScriptBuf},
    opcodes::{all::*, OP_0},
    Address, OutPoint, PublicKey,
};
use bitcoin::{sighash::SighashCache, Network, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::{Amount, EcdsaSighashType, Txid};
use electrum_client::ElectrumApi;
use std::ops::{Add, Index};
use std::str::FromStr;

use crate::{
    error::Error,
    network::{electrum::ElectrumConfig, Chain},
    swaps::boltz::SwapTxKind,
    util::secrets::Preimage,
};

use bitcoin::{blockdata::locktime::absolute::LockTime, hashes::hash160};

use super::boltz::SwapType;

/// Bitcoin swap script helper.
// TODO: This should encode the network at global level.
#[derive(Debug, PartialEq, Clone)]
pub struct BtcSwapScript {
    pub swap_type: SwapType,
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
}

impl BtcSwapScript {
    /// Create the struct from a submarine swap redeem_script string.
    /// Usually created from the string provided by boltz api response.
    pub fn submarine_from_str(redeem_script_str: &str) -> Result<Self, Error> {
        let script = ScriptBuf::from_hex(redeem_script_str)?;

        let instructions = script.instructions();
        let mut last_op = OP_0;
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
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    }
                    if last_op == OP_IF {
                        reciever_pubkey = Some(PublicKey::from_slice(bytes.as_bytes())?);
                    }
                    if last_op == OP_ELSE {
                        timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )));
                    }
                    if last_op == OP_DROP {
                        sender_pubkey = Some(PublicKey::from_slice(bytes.as_bytes())?);
                    }
                }
                _ => (),
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let sender_pubkey = sender_pubkey
            .ok_or_else(|| Error::Protocol("No sender_pubkey provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let receiver_pubkey = reciever_pubkey
            .ok_or_else(|| Error::Protocol("No receiver_pubkey provided".to_string()))?;

        Ok(BtcSwapScript {
            swap_type: SwapType::Submarine,
            hashlock: hashlock,
            receiver_pubkey: receiver_pubkey,
            locktime: timelock,
            sender_pubkey: sender_pubkey,
        })
    }

    /// Create the struct from a reverse swap redeem_script string.
    /// Usually created from the string provided by boltz api response.
    pub fn reverse_from_str(redeem_script_str: &str) -> Result<Self, Error> {
        let script_bytes = Vec::from_hex(redeem_script_str)?;
        let script = Script::from_bytes(&script_bytes);

        let instructions = script.instructions();
        let mut last_op = OP_0;
        let mut hashlock = None;
        let mut receiver_pubkey = None;
        let mut timelock = None;
        let mut sender_pubkey = None;

        for instruction in instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => {
                    last_op = opcode;
                }

                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_HASH160 {
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    }
                    if last_op == OP_EQUALVERIFY {
                        receiver_pubkey = Some(PublicKey::from_slice(bytes.as_bytes())?);
                    }
                    if last_op == OP_DROP {
                        if bytes.len() == 3 as usize {
                            timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                                &bytes.as_bytes(),
                            )));
                        } else {
                            sender_pubkey = Some(PublicKey::from_slice(bytes.as_bytes())?);
                        }
                    }
                }
                _ => (),
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let sender_pubkey = sender_pubkey
            .ok_or_else(|| Error::Protocol("No sender_pubkey provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let receiver_pubkey = receiver_pubkey
            .ok_or_else(|| Error::Protocol("No receiver_pubkey provided".to_string()))?;

        Ok(BtcSwapScript {
            swap_type: SwapType::ReverseSubmarine,
            hashlock: hashlock,
            receiver_pubkey: receiver_pubkey,
            locktime: timelock,
            sender_pubkey: sender_pubkey,
        })
    }

    /// Internally used to convert struct into a bitcoin::Script type
    fn to_script(&self) -> Result<ScriptBuf, Error> {
        match self.swap_type {
            SwapType::Submarine => {
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

                let script = Builder::new()
                    .push_opcode(OP_HASH160)
                    .push_slice(self.hashlock.to_byte_array())
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_key(&self.receiver_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_lock_time(self.locktime)
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

                let script = Builder::new()
                    .push_opcode(OP_SIZE)
                    .push_slice([32])
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_opcode(OP_HASH160)
                    .push_slice(self.hashlock.to_byte_array())
                    .push_opcode(OP_EQUALVERIFY)
                    .push_key(&self.receiver_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_opcode(OP_DROP)
                    .push_lock_time(self.locktime)
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
    pub fn to_address(&self, network: Chain) -> Result<Address, Error> {
        let script = self.to_script()?;
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
        match self.swap_type {
            SwapType::Submarine => Ok(Address::p2shwsh(&script, network)),
            SwapType::ReverseSubmarine => Ok(Address::p2wsh(&script, network)),
        }
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
    ) -> Result<Option<(OutPoint, u64)>, Error> {
        let electrum_client = network_config.build_client()?;
        let spk = self.to_address(network_config.network())?.script_pubkey();
        let utxos = electrum_client.script_list_unspent(spk.as_script())?;

        if utxos.len() == 0 {
            // No utxo found. Return None.
            return Ok(None);
        } else {
            let txid = Txid::from_str(&utxos[0].tx_hash.to_string())?;

            let outpoint_0 = OutPoint::new(txid, utxos[0].tx_pos as u32);
            let utxo_value = utxos[0].value;

            Ok(Some((outpoint_0, utxo_value)))
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
pub struct BtcSwapTx {
    pub kind: SwapTxKind, // These fields needs to be public to do manual creation in IT.
    pub swap_script: BtcSwapScript,
    pub output_address: Address,
    // The HTLC utxo in (Outpoint, Amount) Pair
    pub utxo: (OutPoint, u64),
}
impl BtcSwapTx {
    /// Craft a new ClaimTx. Only works for Reverse Swaps.
    /// Returns None, if the HTLC utxo doesn't exist for the swap.
    pub fn new_claim(
        swap_script: BtcSwapScript,
        output_address: String,
        network_config: &ElectrumConfig,
    ) -> Result<BtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim transactions can only be constructed for Reverse swaps.".to_string(),
            ));
        }

        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = Address::from_str(&output_address)?;

        address.is_valid_for_network(network);

        let utxo_info = swap_script.fetch_utxo(network_config)?;
        if let Some(utxo) = utxo_info {
            Ok(BtcSwapTx {
                kind: SwapTxKind::Claim,
                swap_script,
                output_address: address.assume_checked(),
                utxo,
            })
        } else {
            Err(Error::Protocol(
                "No utxos detected for this script".to_string(),
            ))
        }
    }
    /// Construct a RefundTX corresponding to the swap_script. Only works for Normal Swaps.
    /// Returns None, if the HTLC UTXO for the swap doesn't exist in blockhcian.
    pub fn new_refund(
        swap_script: BtcSwapScript,
        output_address: String,
        network_config: &ElectrumConfig,
    ) -> Result<BtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Txs can only be constructed for Submarine Swaps.".to_string(),
            ));
        }

        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };

        let address = Address::from_str(&output_address)?;
        address.is_valid_for_network(network);

        let utxo_info = swap_script.fetch_utxo(network_config)?;
        if let Some(utxo) = utxo_info {
            Ok(BtcSwapTx {
                kind: SwapTxKind::Refund,
                swap_script,
                output_address: address.assume_checked(),
                utxo,
            })
        } else {
            Err(Error::Protocol(
                "No utxos detected for this script".to_string(),
            ))
        }
    }
    /// Fetch utxo for the script

    /// Sign a reverse swap claim transaction.
    /// Panics if called on a Normal Swap or Refund Tx.
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

        let preimage_bytes = if let Some(value) = preimage.bytes {
            value
        } else {
            return Err(Error::Protocol(format!(
                "No preimage provided while signing."
            )));
        };

        let unsigned_input: TxIn = TxIn {
            sequence: Sequence::MAX,
            previous_output: self.utxo.0,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };
        let output_amount: Amount = Amount::from_sat(self.utxo.1 - absolute_fees);
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.payload().script_pubkey(),
            value: output_amount,
        };
        let mut unsigned_tx = Transaction {
            version: Version(1),
            lock_time: self.swap_script.locktime,
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };

        // Compute the signature
        let witness_script = self.swap_script.to_script()?;
        let secp = Secp256k1::new();
        let hash_type = bitcoin::sighash::EcdsaSighashType::All;
        let sighash = SighashCache::new(&unsigned_tx).p2wsh_signature_hash(
            0,
            &witness_script,
            Amount::from_sat(self.utxo.1),
            hash_type,
        )?;
        let sighash_message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&sighash_message, &keys.secret_key());
        signature.verify(&sighash_message, &keys.public_key())?;
        let ecdsa_signature = Signature::sighash_all(signature);

        // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
        let mut witness = Witness::new();
        witness.push_ecdsa_signature(&ecdsa_signature);
        witness.push(preimage_bytes);
        witness.push(witness_script.as_bytes());

        unsigned_tx
            .input
            .get_mut(0)
            .expect("input expected")
            .witness = witness;

        Ok(unsigned_tx)
    }

    /// Sign a submarine swap refund transaction.
    /// Panics if called on Reverse Swap, Claim type.
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

        let unsigned_input: TxIn = TxIn {
            sequence: Sequence::ZERO, // enables absolute locktime
            previous_output: self.utxo.0,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };
        let output_amount: Amount = Amount::from_sat(self.utxo.1 - absolute_fees);
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: output_amount,
        };
        let mut unsigned_tx = Transaction {
            version: Version(2),
            lock_time: self.swap_script.locktime,
            input: vec![unsigned_input],
            output: vec![output],
        };

        // The whole witness script of the swap tx.
        let witness_script = self.swap_script.to_script()?;

        // a p2wsh script pubkey, from the witness_script to set the script_sig field
        let redeem_script = witness_script.to_p2wsh();
        let mut script_sig = ScriptBuf::new();
        let mut push_bytes = PushBytesBuf::new();
        push_bytes.extend_from_slice(redeem_script.as_bytes());
        script_sig.push_slice(push_bytes);

        // The script pubkey of the previous output for sighash calculation
        let script_pubkey = self
            .swap_script
            .to_address(Chain::BitcoinTestnet)
            .unwrap()
            .script_pubkey();

        // Create signature
        let secp = Secp256k1::new();
        let sighash = SighashCache::new(&unsigned_tx).p2wsh_signature_hash(
            0,
            &witness_script,
            Amount::from_sat(self.utxo.1),
            EcdsaSighashType::All,
        )?;
        let sighash_message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&sighash_message, &keys.secret_key());
        let ecdsa_signature = Signature::sighash_all(signature);

        // Assemble the witness data
        // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
        let mut witness = Witness::new();
        witness.push_ecdsa_signature(&ecdsa_signature);
        witness.push(Vec::new()); // empty push to activate the timelock branch of the script
        witness.push(witness_script);

        // set scriptsig and witness field
        unsigned_tx
            .input
            .get_mut(0)
            .expect("input expected")
            .script_sig = script_sig;
        unsigned_tx
            .input
            .get_mut(0)
            .expect("input expected")
            .witness = witness;

        Ok(unsigned_tx)
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(&self, keys: &Keypair, preimage: &Preimage) -> Result<usize, Error> {
        let dummy_abs_fee = 5_000;
        let tx = match self.kind {
            _ => self.sign_claim(keys, preimage, dummy_abs_fee)?,
        };
        Ok(tx.vsize())
    }
    /// Broadcast transaction to the network
    pub fn broadcast(
        &self,
        signed_tx: Transaction,
        network_config: &ElectrumConfig,
    ) -> Result<Txid, Error> {
        Ok(network_config
            .build_client()?
            .transaction_broadcast(&signed_tx)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::electrum::ElectrumConfig;
    use bitcoin::opcodes::all::{OP_EQUAL, OP_HASH160};
    use bitcoin::script::Builder;
    use bitcoin::secp256k1::hashes::{hash160, Hash};
    use bitcoin::{
        absolute::LockTime, Address, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };
    use electrum_client::ElectrumApi;
    use std::io;
    use std::io::Write;
    use std::str::FromStr;
    pub fn pause_and_wait(msg: &str) {
        let stdin = io::stdin();
        let mut stdout = io::stdout();
        write!(stdout, "\n").unwrap();
        write!(stdout, "******{msg}******").unwrap();
        write!(stdout, "\n").unwrap();
        write!(stdout, "Press Enter to continue...").unwrap();
        stdout.flush().unwrap();
        let _ = stdin.read_line(&mut String::new()).unwrap();
    }

    #[test]
    #[ignore]
    fn test_transaction() {
        let preimage = "a45380303a1b87ec9d0de25f5eba4f6bfbf79b0396e15b72df4914fdb1124634";
        let preimage_bytes = Vec::from_hex(preimage).unwrap();
        let preimage_hash = hash160::Hash::hash(&preimage_bytes);
        let hashbytes: [u8; 20] = *preimage_hash.as_ref();

        let script = Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(hashbytes)
            .push_opcode(OP_EQUAL)
            .into_script();

        let address = Address::p2wsh(&script, Network::Testnet);
        println!("PAY THIS ADDRESS: {}", address);
        pause_and_wait("Pay the address and then continue!");

        let electrum_client = ElectrumConfig::default_bitcoin().build_client().unwrap();

        let utxos = electrum_client
            .script_list_unspent(electrum_client::bitcoin::Script::from_bytes(
                &script.to_p2wsh().as_bytes(),
            ))
            .unwrap();
        let outpoint_0 = OutPoint::new(
            bitcoin::Txid::from_str(&utxos[0].tx_hash.to_string()).unwrap(),
            utxos[0].tx_pos as u32,
        );
        let utxo_value = utxos[0].value;

        assert_eq!(utxo_value, 1_000);
        println!("{:?}", utxos[0]);

        let mut witness = Witness::new();

        // witness.push(OP_0);
        witness.push(preimage_bytes);
        witness.push(script.to_bytes());
        // println!("{:?}",script.to_v0_p2wsh());
        let input: TxIn = TxIn {
            previous_output: outpoint_0,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_consensus(0xFFFFFFFF),
            witness: witness,
        };
        const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
        let return_address = Address::from_str(RETURN_ADDRESS).unwrap();
        let output_value = 700;

        let output: TxOut = TxOut {
            script_pubkey: return_address.payload().script_pubkey(),
            value: Amount::from_sat(output_value),
        };

        let tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(0),
            input: vec![input],
            output: vec![output.clone()],
        };

        let txid = electrum_client.transaction_broadcast(&tx).unwrap();
        println!("{}", txid);

        // let mut utxo_map = HashMap::new();
        // utxo_map.insert(outpoint_0, output);

        // let verify_result = tx.verify(|outpoint| {
        //     utxo_map.get(outpoint).cloned()
        // });

        // match verify_result {
        //     Ok(_) => println!("Transaction verified successfully!"),
        //     Err(e) =>{
        //         println!("Verification failed: {:?}", e.to_string())
        //     }
        // }
        // assert!(verify_result.is_ok());
        // let unsigned_tx = Transaction{
        //     version : 1,
        //     lock_time: LockTime::from_consensus(script_elements.timelock),
        //     input: vec![unsigned_input],
        //     output: vec![output.clone()],
        // };
    }

    #[test]
    fn test_decode_encode_swap_redeem_script() {
        let secp = Secp256k1::new();
        let redeem_script = "a91461be1fecdb989e10275a19f893836066230ab208876321039f3dece2229c2e957e43df168bd078bcdad7e66d1690a27c8b0277d7832ced216703e0c926b17521023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d68ac";
        let expected_address = "2MxkD9NtLhU4iRAUw8G6B83SiHxDESGfDac";
        let expected_timeout = LockTime::from_consensus(2542048);
        let sender_key_pair = Keypair::from_seckey_str(
            &secp,
            "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0",
        )
        .unwrap();
        let decoded = BtcSwapScript::submarine_from_str(&redeem_script).unwrap();
        println!("{:?}", decoded);
        assert!(decoded.sender_pubkey.inner == sender_key_pair.public_key());
        assert!(decoded.locktime == expected_timeout);

        let encoded = BtcSwapScript {
            swap_type: SwapType::Submarine,
            hashlock: decoded.hashlock,
            receiver_pubkey: decoded.receiver_pubkey,
            sender_pubkey: decoded.sender_pubkey,
            locktime: decoded.locktime,
        }
        .to_script()
        .unwrap();
        let script_hash = encoded.script_hash();
        let sh_str = script_hash.as_byte_array().to_lower_hex_string();
        println!("ENCODED SCRIPT HASH: {}", sh_str);
        println!("ENCODED HEX: {}", encoded.to_hex_string());
        let address = Address::p2shwsh(&encoded, bitcoin::Network::Testnet);
        println!("ADDRESS FROM ENCODED: {:?}", address.to_string());
        assert!(address.to_string() == expected_address);
    }
}

/*

lightning-cli --lightning-dir=/.lightning

*/
