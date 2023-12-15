
use std::str::FromStr;

use elements::{
    script::{Script as EScript,Builder as EBuilder, Instruction}, 
    address::Address as EAddress,
    opcodes::{all::{*}},
    bitcoin::{LockTime, PublicKey}, 
    secp256k1_zkp::PublicKey as ZKPublicKey,
    hashes::hash160::Hash, AddressParams,

};
#[derive(Debug, PartialEq)]
pub struct LiquidSwapScriptElements {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
}

impl FromStr for LiquidSwapScriptElements {
    type Err = String; // Change this to a more suitable error type as needed

    fn from_str(redeem_script_str: &str) -> Result<Self, Self::Err> {
        // let script_bytes = hex::decode(redeem_script_str).unwrap().to_owned();
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
                    println!("{:?}", opcode)
                },
                
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
                    println!("{:?}", bytes)
                },
                Err(e) => println!("Error: {:?}", e),
            }
        }

        if hashlock.is_some() && sender_pubkey.is_some() && timelock.is_some() && sender_pubkey.is_some() {
            Ok(LiquidSwapScriptElements{
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
impl  LiquidSwapScriptElements{
    pub fn to_script(
        &self,
    ) -> EScript {
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
        let hashbytes: [u8;20] = hashvalue.as_ref().try_into().unwrap();

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

    pub fn to_address(&self, _network: bitcoin::Network)->EAddress{
        let script = self.to_script();
        let pubkey = ZKPublicKey::from_str(&self.reciever_pubkey).unwrap();
        EAddress::p2shwsh(&script, Some(pubkey), &AddressParams::LIQUID_TESTNET)
    }
}

#[derive(Debug, PartialEq)]
pub struct LiquidReverseSwapScriptElements {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
    pub preimage: Option<String>,
    pub signature: Option<String>,
}

impl FromStr for LiquidReverseSwapScriptElements {
    type Err = String; // Change this to a more suitable error type as needed

    fn from_str(redeem_script_str: &str) -> Result<Self, Self::Err> {
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
                },
                
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
                },
                Err(e) => println!("Error: {:?}", e),
            }
        }

        if hashlock.is_some() && sender_pubkey.is_some() && timelock.is_some() && sender_pubkey.is_some() {
            Ok(LiquidReverseSwapScriptElements{
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
                preimage: None,
                signature: None
            })
        }
        else {
            Err(format!("Could not extract all elements: {:?} {:?} {:?} {:?}",hashlock,reciever_pubkey,timelock,sender_pubkey))
        }
    
    }
}
impl  LiquidReverseSwapScriptElements{
    pub fn new(
        hashlock: String, 
        reciever_pubkey: String, 
        timelock: u32, 
        sender_pubkey: String
    )->Self{
        LiquidReverseSwapScriptElements{
            hashlock,
            reciever_pubkey,
            timelock,
            sender_pubkey,
            preimage: None, 
            signature: None,
        }
    }

    pub fn to_script(
        &self,
    ) -> EScript {
        // Script ~= ScriptBufs
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
        let hashbytes: [u8;20] = hashvalue.as_ref().try_into().unwrap();

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
    
    pub fn to_address(&self, _network: bitcoin::Network)->EAddress{
        let script = self.to_script();
        let pubkey = ZKPublicKey::from_str(&self.reciever_pubkey).unwrap();
        EAddress::p2wsh(&script, Some(pubkey), &AddressParams::LIQUID_TESTNET)
    }

}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}
