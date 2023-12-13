use bitcoin::{Script, Address, ScriptBuf, Network, network, Transaction, OutPoint, TxIn, absolute::LockTime, Witness, Sequence, TxOut, sighash::SighashCache};
use electrum_client::ElectrumApi;
use secp256k1::{Secp256k1, Message};
use std::str::FromStr;

use crate::{key::{ec::KeyPairString, preimage::Preimage}, electrum::{NetworkConfig, BitcoinNetwork}};

use super::script::OnchainSwapScriptElements;

struct OnchainSwapTxElements{
    script_elements: OnchainSwapScriptElements,
    output_address: Address,
    absolute_fees: u32,
    network: Network,
    utxo: Option<OutPoint>,
    utxo_value: Option<u64>, // there should only ever be one outpoint in a swap
}

impl OnchainSwapTxElements{
    pub fn new(redeem_script: String, output_address: String, absolute_fees: u32, network: Network)->OnchainSwapTxElements{
        let address = Address::from_str(&output_address).unwrap();
        address.is_valid_for_network(network);
        OnchainSwapTxElements{
            script_elements: OnchainSwapScriptElements::from_str(&redeem_script).unwrap(),
            output_address: address.assume_checked(),
            absolute_fees,
            network: network,
            utxo: None,
            utxo_value: None,
        }
    }
    pub fn fetch_utxo(self, electrum_url: String, expected_value: u64)->OnchainSwapTxElements{
        let network = match self.network {
            Network::Bitcoin=>BitcoinNetwork::Bitcoin,
            _=>BitcoinNetwork::BitcoinTestnet
        };
        let electrum_client = NetworkConfig::new(network, &electrum_url, true, true, false, None).unwrap()
        .electrum_url
        .build_client()
        .unwrap();

        let utxos = electrum_client.script_list_unspent(&self.script_elements.to_script().to_v0_p2wsh()).unwrap();
        if utxos.len() == 0 {
            self
        }
        else{
            let outpoint_0 = OutPoint::new(
                utxos[0].tx_hash, 
                utxos[0].tx_pos as u32,
            );
            let utxo_value = utxos[0].value;
            if utxo_value == expected_value{
                OnchainSwapTxElements{
                    script_elements: self.script_elements,
                    output_address: self.output_address,
                    absolute_fees: self.absolute_fees,
                    network: self.network,
                    utxo: Some(outpoint_0),
                    utxo_value: Some(utxo_value),
                }
            }
            else {
                self 
                // this should appropriately error stating exptected value is not a match
            }

        }        
        
    }
    
    pub fn has_utxo(&self)->bool{
        self.utxo.is_some() && self.utxo_value.is_some()
    }
    pub fn build_tx(&self,keys: KeyPairString, preimage: Preimage)->Transaction{
        let sequence = Sequence::from_consensus(0xFFFFFFFF);

        let unsigned_input: TxIn = TxIn { 
            previous_output: self.utxo.unwrap(), 
            script_sig: Script::empty().into(),
            sequence: sequence, 
            witness: Witness::new() 
        };
        let output: TxOut = TxOut {
            script_pubkey:self.output_address.payload.script_pubkey(), 
            value: self.utxo_value.unwrap() - self.absolute_fees as u64
        };

        let unsigned_tx = Transaction{
            version : 1, 
            lock_time: LockTime::from_consensus(self.script_elements.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };

        // SIGN TRANSACTION
        let secp = Secp256k1::new();
        let sighash_0 = Message::from_slice(
            &SighashCache::new(unsigned_tx.clone())
                .segwit_signature_hash(
                    0,
                    &self.script_elements.to_script(),
                    self.utxo_value.unwrap(),
                    bitcoin::sighash::EcdsaSighashType::All,
                ).unwrap()[..]
        ).unwrap();
        let signature_0 = secp.sign_ecdsa(&sighash_0, &keys.to_typed().secret_key());
        println!("SIG: {}",signature_0.to_string());

        // CREATE WITNESS
        let mut witness = Witness::new();
        witness.push_bitcoin_signature(&signature_0.serialize_der(), bitcoin::sighash::EcdsaSighashType::All);
        witness.push(preimage.preimage_bytes);
        witness.push(self.script_elements.to_script().as_bytes());

        // https://github.com/bitcoin-teleport/teleport-transactions/blob/master/src/wallet_sync.rs#L255
        // println!("{:?}", witness);
        // BUILD SIGNED TX w/ WITNESS
        let signed_txin = TxIn { 
            previous_output: self.utxo.unwrap(), 
            script_sig: Script::empty().into(),
            sequence: sequence, 
            witness: witness
        };
        
        let signed_tx = Transaction{
            version : 1, 
            lock_time: LockTime::from_consensus(self.script_elements.timelock),
            input: vec![signed_txin],
            output: vec![output.clone()],
        };
        signed_tx
        // let sweep_psbt = Psbt::from_unsigned_tx(sweep_tx);


    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use bitcoin::opcodes::all::{OP_HASH160, OP_EQUAL};
    use bitcoin::script::Builder;
    use bitcoin::{Network, OutPoint, Transaction, TxOut, TxIn, Sequence, Witness, Address, absolute::LockTime, Script};
    use electrum_client::ElectrumApi;
    use secp256k1::hashes::{Hash, hash160};
    use crate::util::pause_and_wait;
    use crate::electrum::NetworkConfig;

    
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
        witness.push(script.to_bytes());
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