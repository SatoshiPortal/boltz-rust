use bitcoin::{blockdata::script::{Script, Instruction}, opcodes::{all::{OP_HASH160, OP_EQUALVERIFY, OP_DROP, OP_ELSE, OP_IF}, OP_0}, Address};

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for &byte in bytes {
        result = (result << 8) | (byte as u32);
    }
    result
}

#[derive(Debug)]
pub struct DecodedNormalBTCSwapRedeemScript {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
    pub address: String,
}

pub fn decode_normal_btc_swap_script(redeem_script_str: String)->Option<DecodedNormalBTCSwapRedeemScript>{
    let script_bytes = hex::decode(redeem_script_str).unwrap().to_owned();
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
            },
            Ok(Instruction::PushBytes(bytes)) => {
                if last_op == OP_HASH160 {
                    hashlock = Some(hex::encode(bytes.as_bytes()));
                }
                if last_op == OP_IF {
                    reciever_pubkey = Some(hex::encode(bytes.as_bytes()));
                }
                if last_op == OP_ELSE {
                    timelock = Some(bytes_to_u32(&bytes.as_bytes()));
                }
                if last_op == OP_DROP {
                    sender_pubkey = Some(hex::encode(bytes.as_bytes()));
                    
                }

            },
            Err(e) => println!("Error: {:?}", e),
        }
    }

    if hashlock.is_some() && sender_pubkey.is_some() && timelock.is_some() && sender_pubkey.is_some() {
        let address = Address::p2shwsh(&script, bitcoin::Network::Testnet);
        println!("ADDRESS: {:?}",address);
        Some(DecodedNormalBTCSwapRedeemScript{
            hashlock: hashlock.unwrap(),
            reciever_pubkey: reciever_pubkey.unwrap(),
            timelock: timelock.unwrap(),
            sender_pubkey: sender_pubkey.unwrap(),
            address: address.to_string(),
        })
    }
    else {
        None
    }
}

#[cfg(test)]
mod tests {

    use crate::ec::XOnlyPair;

    use super::*;

    #[test]
    fn test_decode_script() {
        let script_str = "a914e1db6d8de42a72420d408695ab393407a28bc341876321036e36d8f4c8ccf8776828fe6962b87024bf786a42b8127a0e7a8b92c2bfc5c8e5670358c926b17521023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d68ac".to_string();
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
                    if last_op == OP_DROP {
                        if bytes.as_bytes().len() == 3 {
                            println!("TimeLock: {:?}", bytes_to_u32(&bytes.as_bytes()));
                        } else {
                            println!("Sender Pubkey: {:?}", hex::encode(bytes.as_bytes()));
                        }
                    }

                    println!("PushBytes: {:?}", bytes.as_bytes());
                },
                Err(e) => println!("Error: {:?}", e),
            }
        }
    }
    
    #[test]
    fn test_decode_swap_redeem_script(){
        let redeem_script_str = "a914e1db6d8de42a72420d408695ab393407a28bc341876321036e36d8f4c8ccf8776828fe6962b87024bf786a42b8127a0e7a8b92c2bfc5c8e5670358c926b17521023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d68ac".to_string();
        let expected_address = "2NBQJYfU4VrTuNb4rcWySMT9tGB8o8rfGAM";
        let sender_key_pair = XOnlyPair {
            seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
            pubkey: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d".to_string(),
        };
        let decoded = decode_normal_btc_swap_script(redeem_script_str).unwrap();
        println!("{:?}", decoded);
        assert!(decoded.address == expected_address);
        assert!(decoded.sender_pubkey == sender_key_pair.pubkey);

    }
}