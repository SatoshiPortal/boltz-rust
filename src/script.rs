use std::{num::ParseIntError, str::FromStr};

use bitcoin::{
    blockdata::script::{Script,ScriptBuf,Builder, Instruction}, 
    opcodes::{all::{*}, OP_0},
    PublicKey, 
    Address, script::PushBytes
};

use bitcoin::{
    blockdata::locktime::absolute::LockTime,
    hashes::{
        hash160::Hash,
        hex::{FromHex},
    },
    secp256k1,
    secp256k1::{Secp256k1, SecretKey},
            secp256k1::ecdsa::Signature
    };

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey},
    psbt,
    Amount, Network, OutPoint, Transaction, TxIn, TxOut, Txid,
};


#[derive(Debug, PartialEq)]
pub struct SwapRedeemScriptElements {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
}


impl FromStr for SwapRedeemScriptElements {
    type Err = String; // Change this to a more suitable error type as needed

    fn from_str(redeem_script_str: &str) -> Result<Self, Self::Err> {
        let script_bytes = hex::decode(redeem_script_str).unwrap().to_owned();
        let script = Script::from_bytes(&script_bytes);
        // let address = Address::p2shwsh(&script, bitcoin::Network::Testnet);
        // println!("ADDRESS DECODED: {:?}",address);
        // let script_hash = script.script_hash();
        // let sh_str = hex::encode(script_hash.to_raw_hash().to_string());
        // println!("DECODED SCRIPT HASH: {}",sh_str);
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
                    println!("{:?}", opcode)
                },
                
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
                    println!("{:?}", bytes)
                },
                Err(e) => println!("Error: {:?}", e),
            }
        }

        if hashlock.is_some() && sender_pubkey.is_some() && timelock.is_some() && sender_pubkey.is_some() {
            Ok(SwapRedeemScriptElements{
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
            })
        }
        else {
            Err(format!("Could not extract all elements: {:?} {:?} {:?} {:?}",hashlock,reciever_pubkey,timelock,sender_pubkey))
        }
    
    }
}
impl  SwapRedeemScriptElements{
    pub fn to_script(
        &self,
    ) -> ScriptBuf {
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
        let reciever_pubkey = PublicKey::from_str(&self.reciever_pubkey).unwrap();
        let sender_pubkey = PublicKey::from_str(&self.sender_pubkey).unwrap();
        let locktime = LockTime::from_consensus(self.timelock);
        let hashvalue = Hash::from_str(&self.hashlock).unwrap();
        let hashbytes: [u8;20] = *hashvalue.as_ref();

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

        script

    }

    pub fn to_address(&self, network: bitcoin::Network)->Address{
        let script = self.to_script();
        Address::p2shwsh(&script, network)
    }
}

#[derive(Debug, PartialEq)]
pub struct ReverseSwapRedeemScriptElements {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
}


impl FromStr for ReverseSwapRedeemScriptElements {
    type Err = String; // Change this to a more suitable error type as needed

    fn from_str(redeem_script_str: &str) -> Result<Self, Self::Err> {
        let script_bytes = hex::decode(redeem_script_str).unwrap().to_owned();
        let script = Script::from_bytes(&script_bytes);
        // let address = Address::p2shwsh(&script, bitcoin::Network::Testnet);
        // println!("ADDRESS DECODED: {:?}",address);
        // let script_hash = script.script_hash();
        // let sh_str = hex::encode(script_hash.to_raw_hash().to_string());
        // println!("DECODED SCRIPT HASH: {}",sh_str);
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
                    // println!("{:?}", opcode)
                },
                
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
                    // println!("{:?}: LENGTH: {}", bytes, bytes.len() )
                },
                Err(e) => println!("Error: {:?}", e),
            }
        }

        if hashlock.is_some() && sender_pubkey.is_some() && timelock.is_some() && sender_pubkey.is_some() {
            Ok(ReverseSwapRedeemScriptElements{
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
            })
        }
        else {
            Err(format!("Could not extract all elements: {:?} {:?} {:?} {:?}",hashlock,reciever_pubkey,timelock,sender_pubkey))
        }
    
    }
}
impl  ReverseSwapRedeemScriptElements{
    pub fn to_script(
        &self,
    ) -> ScriptBuf {
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
        let hashvalue = Hash::from_str(&self.hashlock).unwrap();
        let hashbytes: [u8;20] = *hashvalue.as_ref();

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

        script

    }
    pub fn to_address(&self, network: bitcoin::Network)->Address{
        let script = self.to_script();
        Address::p2wsh(&script, network)
    }
}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

// fn find_difference(s1: &str, s2: &str) -> Vec<(usize, char, char)> {
//     s1.char_indices()
//         .zip(s2.chars())
//         .filter(|((_, char1), char2)| char1 != char2)
//         .map(|((i, char1), char2)| (i, char1, char2))
//         .collect()
// }

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use crate::ec::KeyPairString;

    use super::*;

    #[test]
    fn test_decode_script() {
        let script_str = "a91461be1fecdb989e10275a19f893836066230ab208876321039f3dece2229c2e957e43df168bd078bcdad7e66d1690a27c8b0277d7832ced216703e0c926b17521023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d68ac".to_string();
        let script_bytes = hex::decode(script_str).unwrap().to_owned();
        let script = Script::from_bytes(&script_bytes);
        println!("is p2pk: {}",script.is_p2pk());
        println!("is p2sh: {}",script.is_p2sh());
        println!("is p2pkh: {}",script.is_p2pkh());
        println!("is v0_p2wpkh: {}",script.is_v0_p2wpkh());
        println!("is v0_p2wsh: {}",script.is_v0_p2wsh());
        println!("is p2tr: {}",script.is_v1_p2tr());
        println!("is opreturn: {}",script.is_op_return());
        println!("is witness_program: {}",script.is_witness_program());
        println!("is provably unspendable: {}",script.is_provably_unspendable());
        let instructions = script.instructions();
        let mut last_op = OP_0;
        for instruction in instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => {
                    last_op = opcode;
                    println!("Opcode: {:?}", opcode)
                },
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_HASH160 {
                        println!("HashLock: {:?}", hex::encode(bytes.as_bytes()));
                    }
                    if last_op == OP_EQUALVERIFY {
                        println!("Reciever PubKey: {:?}", hex::encode(bytes.as_bytes()));
                        
                    }
                    if last_op == OP_ELSE {
                        println!("TimeLock: {:?}", bytes_to_u32_little_endian(bytes.as_bytes()));
                        // println!("TimeLock: {:?}", Height::try_from(bytes.as_bytes()));
                    }
                    if last_op == OP_DROP {
                        println!("Sender Pubkey: {:?}", hex::encode(bytes.as_bytes()));
                    }
                    println!("PushBytes: {:?}", bytes.as_bytes());
                },
                Err(e) => println!("Error: {:?}", e),
            }
        }
    }
    
    #[test]
    fn test_decode_encode_swap_redeem_script(){
        let redeem_script_str = "a91461be1fecdb989e10275a19f893836066230ab208876321039f3dece2229c2e957e43df168bd078bcdad7e66d1690a27c8b0277d7832ced216703e0c926b17521023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d68ac".to_string();
        let expected_address = "2MxkD9NtLhU4iRAUw8G6B83SiHxDESGfDac";
        let expected_timeout = 2542048;
        let sender_key_pair = KeyPairString {
            seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
            pubkey: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d".to_string(),
        };
        let decoded = SwapRedeemScriptElements::from_str(&redeem_script_str.clone()).unwrap();
        println!("{:?}", decoded);
        assert!(decoded.sender_pubkey == sender_key_pair.pubkey);
        assert!(decoded.timelock == expected_timeout);

        let encoded = SwapRedeemScriptElements{
            hashlock: decoded.hashlock,
            reciever_pubkey:  decoded.reciever_pubkey,
            sender_pubkey: decoded.sender_pubkey,
            timelock:  decoded.timelock
        }.to_script();
        let script_hash = encoded.script_hash();
        let sh_str = hex::encode(script_hash.to_raw_hash().to_string());
        println!("ENCODED SCRIPT HASH: {}",sh_str);
        println!("ENCODED HEX: {}",encoded.to_hex_string());
        let address = Address::p2shwsh(&encoded, bitcoin::Network::Testnet);
        println!("ADDRESS FROM ENCODED: {:?}",address.to_string());
        assert!(address.to_string() == expected_address);

    }
}