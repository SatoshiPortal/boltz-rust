use bitcoin::{blockdata::script::{Script, Instruction}, opcodes::{all::{OP_HASH160, OP_EQUALVERIFY, OP_DROP}, OP_0}};

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for &byte in bytes {
        result = (result << 8) | (byte as u32);
    }
    result
}

pub struct DecodedSwapRedeemScript {
    pub hashlock: String,
    pub reciever_pubkey: String,
    pub timelock: u32,
    pub sender_pubkey: String,
}

pub fn decode_swap_redeem_script(script_str: String)->Option<DecodedSwapRedeemScript>{
    let script_bytes = hex::decode(script_str).unwrap().to_owned();
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
                if last_op == OP_EQUALVERIFY {
                    reciever_pubkey = Some(hex::encode(bytes.as_bytes()));
                    
                }
                if last_op == OP_DROP {
                    if bytes.as_bytes().len() == 3 {
                        timelock = Some(bytes_to_u32(&bytes.as_bytes()));
                    } else {
                        sender_pubkey = Some(hex::encode(bytes.as_bytes()));
                    }
                }

            },
            Err(e) => println!("Error: {:?}", e),
        }
    }

    if hashlock.is_some() && sender_pubkey.is_some() && timelock.is_some() && sender_pubkey.is_some() {
        Some(DecodedSwapRedeemScript{
            hashlock: hashlock.unwrap(),
            reciever_pubkey: reciever_pubkey.unwrap(),
            timelock: timelock.unwrap(),
            sender_pubkey: sender_pubkey.unwrap()
        })
    }
    else {
        None
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_decode_script() {
        let script_str = "8201208763a914be1abd8e8d7ef7e64a9c6e1e2f498f3a92e078a2882103b76c1fe14bab50e52a026f35287fda75b9304bcf311ee85b4d32482400a436f5677503dbf40eb175210330fd4cfd53b5c20886415c1b67d2daa87bce2761b9be009e9d1f9eec4419ba5968ac".to_string();
        let script_bytes = hex::decode(script_str).unwrap().to_owned();
        let script = Script::from_bytes(&script_bytes);
        println!("is p2pk: {}",script.is_p2pk());
        println!("is p2sh: {}",script.is_p2sh());
        println!("is p2sh: {}",script.is_p2pkh());
        println!("is p2sh: {}",script.is_v0_p2wpkh());
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
    
}