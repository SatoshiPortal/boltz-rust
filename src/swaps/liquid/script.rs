use std::str::FromStr;

use bitcoin::hashes::hash160::Hash;
use bitcoin::PublicKey;
use elements::{
    address::Address as EAddress,
    opcodes::all::*,
    script::{Builder as EBuilder, Instruction, Script as EScript},
    secp256k1_zkp::PublicKey as ZKPublicKey,
    AddressParams, LockTime,
};

use crate::key::ec::BlindingKeyPair;
#[derive(Debug, PartialEq)]
pub struct LBtcSubSwapScript {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
}

impl FromStr for LBtcSubSwapScript {
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
            Ok(LBtcSubSwapScript {
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
            })
        } else {
            Err(format!(
                "Could not extract all elements: {:?} {:?} {:?} {:?}",
                hashlock, reciever_pubkey, timelock, sender_pubkey
            ))
        }
    }
}
impl LBtcSubSwapScript {
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
        let reciever_pubkey = PublicKey::from_str(&self.reciever_pubkey).unwrap();
        let sender_pubkey = PublicKey::from_str(&self.sender_pubkey).unwrap();
        let locktime = LockTime::from_consensus(self.timelock);
        let hashvalue: Hash = Hash::from_str(&self.hashlock).unwrap();
        let hashbytes_slice: &[u8] = hashvalue.as_ref();
        let hashbytes: [u8; 20] = hashbytes_slice.try_into().expect("Hash must be 20 bytes");

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

    pub fn to_address(&self, _network: elements::bitcoin::Network, blinder: String) -> EAddress {
        let script = self.to_script();
        let blinder = ZKPublicKey::from_str(&blinder).unwrap();
        EAddress::p2shwsh(&script, Some(blinder), &AddressParams::LIQUID_TESTNET)
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct LBtcRevSwapScript {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
    pub preimage: Option<String>,
    pub signature: Option<String>,
}

impl FromStr for LBtcRevSwapScript {
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
            Ok(LBtcRevSwapScript {
                hashlock: hashlock.unwrap(),
                reciever_pubkey: reciever_pubkey.unwrap(),
                timelock: timelock.unwrap(),
                sender_pubkey: sender_pubkey.unwrap(),
                preimage: None,
                signature: None,
            })
        } else {
            Err(format!(
                "Could not extract all elements: {:?} {:?} {:?} {:?}",
                hashlock, reciever_pubkey, timelock, sender_pubkey
            ))
        }
    }
}
impl LBtcRevSwapScript {
    pub fn new(
        hashlock: String,
        reciever_pubkey: String,
        timelock: u32,
        sender_pubkey: String,
    ) -> Self {
        LBtcRevSwapScript {
            hashlock,
            reciever_pubkey,
            timelock,
            sender_pubkey,
            preimage: None,
            signature: None,
        }
    }

    pub fn to_typed(&self) -> EScript {
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
        let hashvalue: Hash = Hash::from_str(&self.hashlock).unwrap();
        let hashbytes_slice: &[u8] = hashvalue.as_ref();
        let hashbytes: [u8; 20] = hashbytes_slice.try_into().expect("Hash must be 20 bytes");

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

    pub fn to_address(&self, blinding_key: BlindingKeyPair) -> EAddress {
        let script = self.to_typed();
        EAddress::p2wsh(
            &script,
            Some(blinding_key.to_typed().public_key()),
            &AddressParams::LIQUID_TESTNET,
        )
    }
}

fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::ec::{BlindingKeyPair, KeyPairString};
    use std::str::FromStr;

    #[test]
    fn test_liquid_swap_elements() {
        let redeem_script_str = "8201208763a914fc9eeab62b946bd3e9681c082ac2b6d0bccea80f88210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c545898667750315f411b1752102285c72dca7aaa31d58334e20be181cfa2cb8eb8092a577ef6f77bba068b8c69868ac".to_string();
        let expected_address = "tlq1qqv7fnca53ad6fnnn05rwtdc8q6gp8h3yd7s3gmw20updn44f8mvwkxqf8psf3e56k2k7393r3tkllznsdpphqa33rdvz00va429jq6j2zzg8f59kqhex";
        let expected_timeout = 1176597;

        let blinding_key = BlindingKeyPair::from_secret_string(
            "852f5fb1a95ea3e16ad0bb1c12ce0eac94234e3c652e9b163accd41582c366ed".to_string(),
        );

        let _id = "axtHXB";
        let my_key_pair = KeyPairString {
            seckey: "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1".to_string(),
            pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986"
                .to_string(),
        };
        let decoded = LBtcRevSwapScript::from_str(&redeem_script_str.clone()).unwrap();
        // println!("{:?}", decoded);
        assert_eq!(decoded.reciever_pubkey, my_key_pair.pubkey);
        assert_eq!(decoded.timelock, expected_timeout);

        let script_elements = LBtcRevSwapScript {
            hashlock: decoded.hashlock,
            reciever_pubkey: decoded.reciever_pubkey,
            sender_pubkey: decoded.sender_pubkey,
            timelock: decoded.timelock,
            preimage: None,
            signature: None,
        };

        // let script = script_elements.to_typed();
        // println!("ENCODED HEX: {}", script.to_string());
        let address = script_elements.to_address(blinding_key);
        // println!("ADDRESS FROM ENCODED: {:?}", address.to_string());
        assert!(address.to_string() == expected_address);
    }
}
