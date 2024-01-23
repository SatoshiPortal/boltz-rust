use std::str::FromStr;

use bitcoin::secp256k1::{Keypair, Message, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::Amount;
use bitcoin::{
    blockdata::script::{Builder, Instruction, Script, ScriptBuf},
    opcodes::{all::*, OP_0},
    Address, OutPoint, PublicKey,
};
use bitcoin::{sighash::SighashCache, Network, Sequence, Transaction, TxIn, TxOut, Witness};
use electrum_client::ElectrumApi;

use crate::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::boltz::SwapTxKind,
    util::{
        error::{ErrorKind, S5Error},
        secrets::Preimage,
    },
};

use bitcoin::{blockdata::locktime::absolute::LockTime, hashes::hash160::Hash};

use super::boltz::SwapType;

/// Bitcoin swap script helper.
#[derive(Debug, PartialEq, Clone)]
pub struct BtcSwapScript {
    pub swap_type: SwapType,
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
}

impl BtcSwapScript {
    /// Create the struct from raw elements
    pub fn new(
        swap_type: SwapType,
        hashlock: String,
        reciever_pubkey: String,
        timelock: u32,
        sender_pubkey: String,
    ) -> Self {
        BtcSwapScript {
            swap_type,
            hashlock,
            reciever_pubkey,
            timelock,
            sender_pubkey,
        }
    }
    /// Create the struct from a submarine swap redeem_script string.
    /// Usually created from the string provided by boltz api response.
    pub fn submarine_from_str(redeem_script_str: &str) -> Result<Self, S5Error> {
        let script_bytes = match hex::decode(redeem_script_str) {
            Ok(result) => result.to_owned(),
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        let script = Script::from_bytes(&script_bytes);

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
                        hashlock = Some(hex::encode(bytes.as_bytes()));
                    }
                    if last_op == OP_IF {
                        reciever_pubkey = Some(hex::encode(bytes.as_bytes()));
                    }
                    if last_op == OP_ELSE {
                        timelock = Some(bytes_to_u32_little_endian(&bytes.as_bytes()));
                    }
                    if last_op == OP_DROP {
                        sender_pubkey = Some(hex::encode(bytes.as_bytes()));
                    }
                }
                _ => (),
            }
        }

        if hashlock.is_some()
            && sender_pubkey.is_some()
            && timelock.is_some()
            && sender_pubkey.is_some()
        {
            Ok(BtcSwapScript {
                swap_type: SwapType::Submarine,
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
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

    /// Create the struct from a reverse swap redeem_script string.
    /// Usually created from the string provided by boltz api response.
    pub fn reverse_from_str(redeem_script_str: &str) -> Result<Self, S5Error> {
        let script_bytes = match hex::decode(redeem_script_str) {
            Ok(result) => result.to_owned(),
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        let script = Script::from_bytes(&script_bytes);

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
                        hashlock = Some(hex::encode(bytes.as_bytes()));
                    }
                    if last_op == OP_EQUALVERIFY {
                        reciever_pubkey = Some(hex::encode(bytes.as_bytes()));
                    }
                    if last_op == OP_DROP {
                        if bytes.len() == 3 as usize {
                            timelock = Some(bytes_to_u32_little_endian(&bytes.as_bytes()));
                        } else {
                            sender_pubkey = Some(hex::encode(bytes.as_bytes()));
                        }
                    }
                }
                _ => (),
            }
        }

        if hashlock.is_some()
            && sender_pubkey.is_some()
            && timelock.is_some()
            && sender_pubkey.is_some()
        {
            Ok(BtcSwapScript {
                swap_type: SwapType::ReverseSubmarine,
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
            })
        } else {
            Err(S5Error::new(
                ErrorKind::Input,
                &format!(
                    "Could not extract all script elements. Check your redeem script and swap_type."
                ),
            ))
        }
    }

    /// Internally used to convert struct into a bitcoin::Script type
    fn to_script(&self) -> Result<ScriptBuf, S5Error> {
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
                let reciever_pubkey = match PublicKey::from_str(&self.reciever_pubkey) {
                    Ok(result) => result,
                    Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
                };

                let sender_pubkey = match PublicKey::from_str(&self.sender_pubkey) {
                    Ok(result) => result,
                    Err(e) => {
                        // do more stuff
                        return Err(S5Error::new(ErrorKind::Input, &e.to_string()));
                    }
                };
                let locktime = LockTime::from_consensus(self.timelock);
                let hashvalue = match Hash::from_str(&self.hashlock) {
                    Ok(result) => result,
                    Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
                };
                let hashbytes: [u8; 20] = *hashvalue.as_ref();

                let script = Builder::new()
                    .push_opcode(OP_HASH160)
                    .push_slice(hashbytes)
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_key(&reciever_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_lock_time(locktime)
                    .push_opcode(OP_CLTV)
                    .push_opcode(OP_DROP)
                    .push_key(&sender_pubkey)
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
                let reciever_pubkey = match PublicKey::from_str(&self.reciever_pubkey) {
                    Ok(result) => result.to_owned(),
                    Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
                };
                let sender_pubkey = match PublicKey::from_str(&self.sender_pubkey) {
                    Ok(result) => result.to_owned(),
                    Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
                };
                let locktime = LockTime::from_consensus(self.timelock);
                let hashvalue = match Hash::from_str(&self.hashlock) {
                    Ok(result) => result.to_owned(),
                    Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
                };
                let hashbytes: [u8; 20] = *hashvalue.as_ref();

                let script = Builder::new()
                    .push_opcode(OP_SIZE)
                    .push_slice([32])
                    .push_opcode(OP_EQUAL)
                    .push_opcode(OP_IF)
                    .push_opcode(OP_HASH160)
                    .push_slice(hashbytes)
                    .push_opcode(OP_EQUALVERIFY)
                    .push_key(&reciever_pubkey)
                    .push_opcode(OP_ELSE)
                    .push_opcode(OP_DROP)
                    .push_lock_time(locktime)
                    .push_opcode(OP_CLTV)
                    .push_opcode(OP_DROP)
                    .push_key(&sender_pubkey)
                    .push_opcode(OP_ENDIF)
                    .push_opcode(OP_CHECKSIG)
                    .into_script();

                Ok(script)
            }
        }
    }

    /// Get address for the swap script.
    /// Submarine swaps use p2shwsh. Reverse swaps use p2wsh.
    pub fn to_address(&self, network: Chain) -> Result<Address, S5Error> {
        let script = self.to_script()?;
        let network = match network {
            Chain::Bitcoin => Network::Bitcoin,
            _ => Network::Testnet,
        };
        match self.swap_type {
            SwapType::Submarine => Ok(Address::p2shwsh(&script, network)),
            SwapType::ReverseSubmarine => Ok(Address::p2wsh(&script, network)),
        }
    }
    /// Get the balance of the script
    pub fn get_balance(&self, network_config: ElectrumConfig) -> Result<(u64, i64), S5Error> {
        let electrum_client = network_config.build_client()?;

        let script_balance =
            match electrum_client.script_get_balance(electrum_client::bitcoin::Script::from_bytes(
                &self
                    .to_address(network_config.network())
                    .unwrap()
                    .script_pubkey()
                    .as_bytes(),
            )) {
                Ok(result) => result,
                Err(e) => return Err(S5Error::new(ErrorKind::Script, &e.to_string())),
            };
        Ok((script_balance.confirmed, script_balance.unconfirmed))
    }
}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

/// Bitcoin swap transaction helper.
pub struct BtcSwapTx {
    kind: SwapTxKind,
    swap_script: BtcSwapScript,
    output_address: Address,
    utxo: Option<OutPoint>,
    utxo_value: Option<u64>, // there should only ever be one outpoint in a swap
}

impl BtcSwapTx {
    /// Required to claim reverse swaps only. Cannot be used for submarine swaps.
    pub fn new_claim(
        swap_script: BtcSwapScript,
        output_address: String,
        network: Chain,
    ) -> Result<BtcSwapTx, S5Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(S5Error::new(
                ErrorKind::Script,
                "Claim transactions can only be constructed for Reverse swaps.",
            ));
        }
        let network = if network == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = match Address::from_str(&output_address) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };

        address.is_valid_for_network(network);

        Ok(BtcSwapTx {
            kind: SwapTxKind::Claim,
            swap_script,
            output_address: address.assume_checked(),
            utxo: None,
            utxo_value: None,
        })
    }
    /// Required to claim submarine swaps only. Cannot be used for reverse swaps.
    pub fn new_refund(
        swap_script: BtcSwapScript,
        output_address: String,
        network: Chain,
    ) -> Result<BtcSwapTx, S5Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(S5Error::new(
                ErrorKind::Script,
                "Refund transactions can only be constructed for Submarine swaps.",
            ));
        }
        let network = if network == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };

        let address = match Address::from_str(&output_address) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        address.is_valid_for_network(network);

        Ok(BtcSwapTx {
            kind: SwapTxKind::Refund,
            swap_script: swap_script,
            output_address: address.assume_checked(),
            utxo: None,
            utxo_value: None,
        })
    }
    /// Sweep the script utxo.
    pub fn drain(
        &mut self,
        keys: Keypair,
        preimage: Preimage,
        absolute_fees: u64,
    ) -> Result<Transaction, S5Error> {
        if !self.has_utxo() {
            return Err(S5Error::new(ErrorKind::Transaction, "No Utxos Found."));
        }
        match self.kind {
            SwapTxKind::Claim => self.sign_claim_tx(keys, preimage, absolute_fees),
            SwapTxKind::Refund => self.sign_refund_tx(keys, absolute_fees),
        }
    }
    /// Fetch utxo for the script
    pub fn fetch_utxo(
        &mut self,
        expected_value: u64,
        network_config: ElectrumConfig,
    ) -> Result<(), S5Error> {
        let electrum_client = network_config.build_client()?;

        let utxos =
            match electrum_client.script_list_unspent(electrum_client::bitcoin::Script::from_bytes(
                self.swap_script
                    .to_address(network_config.network())?
                    .script_pubkey()
                    .as_bytes(),
            )) {
                Ok(result) => result,
                Err(e) => return Err(S5Error::new(ErrorKind::Network, &e.to_string())),
            };
        if utxos.len() == 0 {
            return Err(S5Error::new(
                ErrorKind::Transaction,
                &format!("0 utxos found for this script",),
            ));
        } else {
            let outpoint_0 = OutPoint::new(
                bitcoin::Txid::from_str(&utxos[0].tx_hash.to_string()).unwrap(),
                utxos[0].tx_pos as u32,
            );
            let utxo_value = utxos[0].value;
            if utxo_value >= expected_value {
                self.utxo = Some(outpoint_0);
                self.utxo_value = Some(utxo_value);
                Ok(())
            } else {
                return Err(S5Error::new(
                    ErrorKind::Input,
                    &format!(
                        "Expected value does not match utxo value. Expected {}, Found {}",
                        expected_value, utxo_value
                    ),
                ));
            }
        }
    }

    /// Internally used to check if utxos are present in the struct to build the transaction.
    fn has_utxo(&self) -> bool {
        self.utxo.is_some() && self.utxo_value.is_some()
    }

    /// Sign a reverse swap claim transaction
    fn sign_claim_tx(
        &self,
        keys: Keypair,
        preimage: Preimage,
        absolute_fees: u64,
    ) -> Result<Transaction, S5Error> {
        if self.swap_script.swap_type == SwapType::Submarine {
            return Err(S5Error::new(
                ErrorKind::Script,
                "Claim transactions can only be constructed for Reverse swaps.",
            ));
        }

        let preimage_bytes = if preimage.bytes.is_some() {
            preimage.bytes.unwrap()
        } else {
            return Err(S5Error::new(ErrorKind::Input, "No preimage provided"));
        };
        let redeem_script = self.swap_script.to_script()?;

        let sequence = Sequence::from_consensus(0xFFFFFFFF);

        let unsigned_input: TxIn = TxIn {
            sequence: sequence,
            previous_output: self.utxo.unwrap(),
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let output_amount: Amount = Amount::from_sat(self.utxo_value.unwrap() - absolute_fees);
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.payload().script_pubkey(),
            value: output_amount,
        };

        let unsigned_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(self.swap_script.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };
        let hash_type = bitcoin::sighash::EcdsaSighashType::All;
        let secp = Secp256k1::new();
        let sighash = match SighashCache::new(unsigned_tx.clone()).p2wpkh_signature_hash(
            0,
            &redeem_script,
            Amount::from_sat(self.utxo_value.unwrap()),
            hash_type,
        ) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Transaction, &e.to_string())),
        };
        let sighash_message = Message::from_digest_slice(&sighash[..]).unwrap();
        let signature = bitcoin::ecdsa::Signature::from_str(
            &secp
                .sign_ecdsa(&sighash_message, &keys.secret_key())
                .to_string(),
        )
        .unwrap();

        // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
        let mut witness = Witness::new();
        witness.push_ecdsa_signature(&signature);
        witness.push(preimage_bytes);
        witness.push(redeem_script.as_bytes());

        let signed_txin = TxIn {
            previous_output: self.utxo.unwrap(),
            script_sig: ScriptBuf::new(),
            sequence: sequence,
            witness: witness,
        };
        let signed_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(self.swap_script.timelock),
            input: vec![signed_txin],
            output: vec![output.clone()],
        };
        Ok(signed_tx)
    }

    /// Sign a submarine swap refund transaction
    fn sign_refund_tx(&self, keys: Keypair, absolute_fees: u64) -> Result<Transaction, S5Error> {
        if self.swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(S5Error::new(
                ErrorKind::Script,
                "Refund transactions can only be constructed for Submarine swaps.",
            ));
        }

        let redeem_script = self.swap_script.to_script()?;

        let sequence = Sequence::from_consensus(0xFFFFFFFF);

        let unsigned_input: TxIn = TxIn {
            sequence: sequence,
            previous_output: self.utxo.unwrap(),
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let output_amount: Amount = Amount::from_sat(self.utxo_value.unwrap() - absolute_fees);
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.payload().script_pubkey(),
            value: output_amount,
        };

        let unsigned_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(self.swap_script.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };
        let hash_type = bitcoin::sighash::EcdsaSighashType::All;
        let secp = Secp256k1::new();
        let sighash = match SighashCache::new(unsigned_tx.clone()).p2wpkh_signature_hash(
            0,
            &redeem_script,
            Amount::from_sat(self.utxo_value.unwrap()),
            hash_type,
        ) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Transaction, &e.to_string())),
        };
        let sighash_message = Message::from_digest_slice(&sighash[..]).unwrap();
        let signature = bitcoin::ecdsa::Signature::from_str(
            &secp
                .sign_ecdsa(&sighash_message, &keys.secret_key())
                .to_string(),
        )
        .unwrap();

        // https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
        let mut witness = Witness::new();
        witness.push_ecdsa_signature(&signature);
        witness.push([0]);
        witness.push(redeem_script.as_bytes());

        let signed_txin = TxIn {
            previous_output: self.utxo.unwrap(),
            script_sig: ScriptBuf::new(),
            sequence: sequence,
            witness: witness,
        };
        let signed_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::from_consensus(self.swap_script.timelock),
            input: vec![signed_txin],
            output: vec![output.clone()],
        };
        Ok(signed_tx)
    }
    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(&self, keys: Keypair, preimage: Preimage) -> Result<usize, S5Error> {
        let dummy_abs_fee = 5_000;
        let tx = match self.kind {
            _ => self.sign_claim_tx(keys, preimage, dummy_abs_fee)?,
        };
        Ok(tx.vsize())
    }
    /// Broadcast transaction to the network
    pub fn broadcast(
        &mut self,
        signed_tx: Transaction,
        network_config: ElectrumConfig,
    ) -> Result<String, S5Error> {
        let electrum_client = network_config.build_client()?;
        match electrum_client.transaction_broadcast(&signed_tx) {
            Ok(txid) => Ok(txid.to_string()),
            Err(e) => Err(S5Error::new(ErrorKind::Network, &e.to_string())),
        }
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
        let preimage_bytes = hex::decode(preimage).unwrap();
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
        let redeem_script_str = "a91461be1fecdb989e10275a19f893836066230ab208876321039f3dece2229c2e957e43df168bd078bcdad7e66d1690a27c8b0277d7832ced216703e0c926b17521023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d68ac".to_string();
        let expected_address = "2MxkD9NtLhU4iRAUw8G6B83SiHxDESGfDac";
        let expected_timeout = 2542048;
        let sender_key_pair = Keypair::from_seckey_str(
            &secp,
            "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0",
        )
        .unwrap();
        let decoded = BtcSwapScript::submarine_from_str(&redeem_script_str.clone()).unwrap();
        println!("{:?}", decoded);
        assert!(decoded.sender_pubkey == sender_key_pair.public_key().to_string());
        assert!(decoded.timelock == expected_timeout);

        let encoded = BtcSwapScript {
            swap_type: SwapType::Submarine,
            hashlock: decoded.hashlock,
            reciever_pubkey: decoded.reciever_pubkey,
            sender_pubkey: decoded.sender_pubkey,
            timelock: decoded.timelock,
        }
        .to_script()
        .unwrap();
        let script_hash = encoded.script_hash();
        let sh_str = hex::encode(script_hash.to_raw_hash().to_string());
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
