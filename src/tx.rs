#[cfg(test)]
mod tests {
    use std::{str::FromStr, collections::HashMap};
    use bitcoin::psbt::Psbt;
    use bitcoin::{Network, OutPoint, Transaction, TxOut, TxIn, Sequence, Witness, Address, absolute::LockTime, sighash::SighashCache, Script};
    use electrum_client::ElectrumApi;
    use secp256k1::hashes::{sha256, Hash, ripemd160};
    use secp256k1::{Message, Secp256k1};
    use crate::{script::ReverseSwapRedeemScriptElements, electrum::NetworkConfig, ec::KeyPairString};
    use bitcoin::blockdata::script::Error as ScriptError;
    use bitcoin::bitcoinconsensus::Error as ConsensusError;
    
    #[test]
    #[ignore]
    fn test_transaction(){
        /*
         * a script was created
         * an address was generated
         * it has been paid 
         * retrieve those funds!
         * -------------------------
         * get utxo from electrum 
         * build a transaction
         * solve it 
         * broadcast it 
         */

        // OUTPUT ADDRESS
        const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
        let return_address = Address::from_str(RETURN_ADDRESS).unwrap();
        let output_value = 2_500;

        // SECRETS FOR UNLOCKING SCRIPT
        // let _preimage = "36393139333730383132383738353633303337";
        let preimage = "d8f64d842dba7883989b70e13ae5bfb85f918a2da98c33c8abfa37f414066faa";
        let preimage_bytes = hex::decode(preimage).unwrap();
        let preimage_hash =  sha256::Hash::hash(&preimage_bytes);
        let preimage_ripemd = ripemd160::Hash::hash(preimage_hash.as_byte_array());
        let key_pair_string = KeyPairString { 
            seckey: "f37f95f01f3a28ba2bf4054e56b0cc217dd0b48edfd75a205cc2a96c20876a1b".to_string(), 
            pubkey: "037bdb90d61d1100664c4aaf0ea93fb71c87433f417e93294e08ae9859910efcea".to_string() 
        };

        let key_pair = key_pair_string.to_typed();

        // REDEEM SCRIPT

        let redeem_script_str = "8201208763a91465cb49fff0542478b408a8d8f220ce9e1ab437578821037bdb90d61d1100664c4aaf0ea93fb71c87433f417e93294e08ae9859910efcea677503bbcb26b17521034f26a94daafc342874aa4973a2418585dbfdd579d060643d0d087c002addee6268ac";
        let script_elements = ReverseSwapRedeemScriptElements::from_str(redeem_script_str).unwrap();
        assert_eq!(preimage_ripemd.to_string(),script_elements.hashlock);

        // ADDRESS WITH FUNDS THAT NEEDS TO BE CLAIMED
        let address = script_elements.to_address(Network::Testnet);
        let lockup_address = "tb1qc5hyw0wh2kk2xp2ynk5l0mpeqhvqclv5ypurw65serefg3qu4hesxactxc".to_string();
        // nSEQUENCE
        let sequence = Sequence::ZERO;

        // INIT ELECTRUM
        let electrum_client = NetworkConfig::default()
            .unwrap()
            .electrum_url
            .build_client()
            .unwrap();
 
        assert_eq!(address.to_string() , lockup_address);
        let script_balance = electrum_client.script_get_balance(&script_elements.to_script().to_v0_p2wsh()).unwrap();
        println!("Balance: {:?}", script_balance);

        // UTXO SET FOR GIVEN SCRIPT
        let utxos = electrum_client.script_list_unspent(&script_elements.to_script().to_v0_p2wsh()).unwrap();
        let outpoint_0 = OutPoint::new(
            utxos[0].tx_hash, 
            utxos[0].tx_pos as u32,
        );
        let utxo_value = utxos[0].value;
        // println!("{:?}", utxos[0]);

        // CREATE UNSIGNED TX
        let unsigned_input: TxIn = TxIn { 
            previous_output: outpoint_0, 
            script_sig: Script::empty().into(),
            sequence: sequence, 
            witness: Witness::new() 
        };
        let output: TxOut = TxOut {
            script_pubkey:return_address.payload.script_pubkey(), 
            value: output_value
        };

        let unsigned_tx = Transaction{
            version : 1, 
            lock_time: LockTime::from_consensus(script_elements.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };

        // SIGN TRANSACTION
        let secp = Secp256k1::new();
        let sighash_0 = Message::from_slice(
            &SighashCache::new(unsigned_tx.clone())
                .segwit_signature_hash(
                    0,
                    &script_elements.to_script(),
                    utxo_value,
                    bitcoin::sighash::EcdsaSighashType::All,
                ).unwrap()[..]
        ).unwrap();
        let signature_0 = secp.sign_ecdsa(&sighash_0, &key_pair.secret_key());
        println!("SIG: {}",signature_0.to_string());

        // CREATE WITNESS
        let mut witness = Witness::new();
        witness.push_bitcoin_signature(&signature_0.serialize_der(), bitcoin::sighash::EcdsaSighashType::All);
        // witness.push(bitcoin::sighash::EcdsaSighashType::All);
        witness.push(preimage_bytes);
        witness.push(&hex::encode(script_elements.to_script().as_bytes()));

        assert_eq!(redeem_script_str,&hex::encode(script_elements.to_script().as_bytes()));
        // https://github.com/bitcoin-teleport/teleport-transactions/blob/master/src/wallet_sync.rs#L255
        // println!("{:?}", witness);
        // BUILD SIGNED TX w/ WITNESS
        let signed_txin = TxIn { 
            previous_output: outpoint_0, 
            script_sig: Script::empty().into(),
            sequence: sequence, 
            witness: witness
        };
        
        let signed_tx = Transaction{
            version : 1, 
            lock_time: LockTime::from_consensus(script_elements.timelock),
            input: vec![signed_txin],
            output: vec![output.clone()],
        };
        // let sweep_psbt = Psbt::from_unsigned_tx(sweep_tx);

        
        let txid = electrum_client.transaction_broadcast(&signed_tx).unwrap();
        println!("{}", txid);


        // VERIFY SIGNED TX
        // let mut utxo_map = HashMap::new();
        // utxo_map.insert(outpoint_0, output);
        // let verify_result = signed_tx.verify(|outpoint| {
        //     utxo_map.get(outpoint).cloned()
        // });

        // match verify_result {
        //     Ok(_) => println!("Transaction verified successfully!"),
        //     Err(e) =>{ 
        //         match e{
        //             ScriptError::BitcoinConsensus(e)=>{
        //                 match e {
        //                     _=>println!("Consensus Error: {:?}", e),
        //                 }
                        
        //             }
        //             _=> println!("Verification failed: {:?}", e.to_string()),
        //         }
        //     }
        // }
        // assert!(verify_result.is_ok());





        // VERIFY THE UPDATED TX
        // let verification = solution.as_script().verify(
        //     0,
        //     Amount::from_sat(10_000),
        //     updated_tx.txid().as_byte_array()
        // );
        // println!("{:?}",verification);
        // assert!(verification.is_ok());

        /*
         * REFERENCES
         * https://github.com/BoltzExchange/boltz-core/blob/master/lib/swap/Claim.ts#L63
         * 
         * https://github.com/bitcoin-teleport/teleport-transactions/blob/master/src/contracts.rs#L516C8-L516C24
         */
        
    }
}