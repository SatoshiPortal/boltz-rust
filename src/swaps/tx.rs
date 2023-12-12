#[cfg(test)]
mod tests {
    use std::{str::FromStr, collections::HashMap};
    use bitcoin::opcodes::all::{OP_HASH160, OP_EQUAL};
    use bitcoin::psbt::Psbt;
    use bitcoin::script::Builder;
    use bitcoin::{Network, OutPoint, Transaction, TxOut, TxIn, Sequence, Witness, Address, absolute::LockTime, sighash::SighashCache, Script};
    use electrum_client::ElectrumApi;
    use secp256k1::hashes::{sha256, Hash, ripemd160, hash160};
    use secp256k1::{Message, Secp256k1};
    use crate::util::pause_and_wait;
    use crate::{electrum::NetworkConfig};

    
    #[test]
    #[ignore]
    fn test_transaction(){
        let preimage = "a45380303a1b87ec9d0de25f5eba4f6bfbf79b0396e15b72df4914fdb1124634";
        let preimage_bytes = hex::decode(preimage).unwrap();
        let preimage_hash = hash160::Hash::hash(&preimage_bytes);
        // let hashvalue = Hash::from_str(&self.hashlock).unwrap();
        let hashbytes: [u8;20] = *preimage_hash.as_ref();
        // let hashcheck = ripemd160::Hash::from_slice(&hashbytes).unwrap();
        // assert_eq!(hashcheck, preimage_hash);

        let script = Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(hashbytes)
            .push_opcode(OP_EQUAL)
            .into_script();

        let address = Address::p2wsh(&script, Network::Testnet);
        println!("PAY THIS ADDRESS: {}", address);
        pause_and_wait();

        let electrum_client = NetworkConfig::default()
        .unwrap()
        .electrum_url
        .build_client()
        .unwrap();

        let utxos = electrum_client.script_list_unspent(&script.to_v0_p2wsh()).unwrap();
        let outpoint_0 = OutPoint::new(
            utxos[0].tx_hash, 
            utxos[0].tx_pos as u32,
        );
        let utxo_value = utxos[0].value;

        assert_eq!(utxo_value, 1_000);
        println!("{:?}", utxos[0]);

        let mut witness = Witness::new();

        // witness.push(OP_0);
        witness.push(preimage_bytes);
        witness.push((script.to_bytes()));
        // println!("{:?}",script.to_v0_p2wsh());
        let input: TxIn = TxIn { 
            previous_output: outpoint_0, 
            script_sig: Script::empty().into(),
            sequence: Sequence::from_consensus(0xFFFFFFFF), 
            witness: witness
        };
        const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
        let return_address = Address::from_str(RETURN_ADDRESS).unwrap();
        let output_value = 700;

        let output: TxOut = TxOut {
            script_pubkey:return_address.payload.script_pubkey(), 
            value: output_value
        };

        let tx = Transaction{
            version : 1, 
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

}