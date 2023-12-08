#[cfg(test)]
mod tests {
    use std::{str::FromStr, env};
    use bitcoin::{Network, OutPoint, Txid, Transaction, consensus::{Decodable, deserialize}, TxOut, TxIn, Sequence, ScriptBuf, Witness, Address, absolute::{Height, LockTime}, sighash::SighashCache, script::Builder};
    use electrum_client::ElectrumApi;
    use bitcoin::psbt::Psbt;
    use secp256k1::{hashes::hex::FromHex, Message, Secp256k1};
    use crate::{ec::{KeyPairString, keypair_from_xprv_str}, derivation::{DerivationPurpose, to_hardened_account}, seed::import, script::ReverseSwapRedeemScriptElements, electrum::NetworkConfig};
    use super::*;

    #[test]
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
        let electrum_client = NetworkConfig::default()
            .unwrap()
            .electrum_url
            .build_client()
            .unwrap();
 
        const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
        let return_address = Address::from_str(RETURN_ADDRESS).unwrap();

        
        let preimage = "36393139333730383132383738353633303337";
        let key_pair_string = KeyPairString { 
            seckey: "f37f95f01f3a28ba2bf4054e56b0cc217dd0b48edfd75a205cc2a96c20876a1b".to_string(), 
            pubkey: "037bdb90d61d1100664c4aaf0ea93fb71c87433f417e93294e08ae9859910efcea".to_string() 
        };
        let key_pair = key_pair_string.to_typed();
        let redeem_script_str = "8201208763a9140ba9f02ac085c062d72db3c1ca5a448b75537a1c8821037bdb90d61d1100664c4aaf0ea93fb71c87433f417e93294e08ae9859910efcea677503f8c926b1752102ee2ebf016f67732a95ee6751eede736c433325f29470fde26fb6d8d2d7f0513168ac";

        let script_elements = ReverseSwapRedeemScriptElements::from_str(redeem_script_str).unwrap();
        let address = script_elements.to_address(Network::Testnet);
        let lockup_address = "tb1qdc5mtlxkxntnkujczhqz8rztguz26xc4ppmuxyxzj0cswdnxmq7sx47z90".to_string();
        assert_eq!(address.to_string() , lockup_address);
        let script_balance = electrum_client.script_get_balance(&script_elements.to_script().to_v0_p2wsh()).unwrap();
        println!("Balance: {:?}", script_balance);
        let txs = electrum_client.script_get_history(&script_elements.to_script().to_v0_p2wsh()).unwrap();
        for tx in txs{
            let raw_tx = electrum_client.transaction_get_raw(&tx.tx_hash).unwrap();
            let _transaction = deserialize::<bitcoin::Transaction>(&raw_tx).unwrap();
            // println!("{:?}",transaction);
        }

        let utxos = electrum_client.script_list_unspent(&script_elements.to_script().to_v0_p2wsh()).unwrap();
        let outpoint_10000 = OutPoint::new(
            utxos[0].tx_hash, 
            utxos[0].tx_pos as u32,
        );
        let outpoint_5000 = OutPoint::new(
            utxos[1].tx_hash, 
            utxos[1].tx_pos as u32,
        );
        let tx_in_0: TxIn = TxIn { previous_output: outpoint_10000, script_sig: ScriptBuf::new(),sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, witness: Witness::new() };
        // let tx_in_1: TxIn = TxIn { previous_output: outpoint_5000, script_sig: ScriptBuf::new(),sequence: Sequence::ENABLE_LOCKTIME_NO_RBF, witness: Witness::new() };
        let tx_out_0: TxOut = TxOut {script_pubkey:return_address.payload.script_pubkey(), value: 9_000};
        let secp = Secp256k1::new();

        let sweep_tx = Transaction{
            version : 0, 
            lock_time: LockTime::from_consensus(script_elements.timelock),
            input: vec![tx_in_0],
            output: vec![tx_out_0],
        };
        let sighash_0 = Message::from_slice(
            &SighashCache::new(sweep_tx.clone()).segwit_signature_hash(
                0,
                &script_elements.to_script(),
                10_000,
                bitcoin::sighash::EcdsaSighashType::All,
            ).unwrap()[..],
        ).unwrap();
        let signature_0 = secp.sign_ecdsa(&sighash_0, &key_pair.secret_key());
        // let sighash_1 = Message::from_slice(
        //     &SighashCache::new(sweep_tx.clone()).segwit_signature_hash(
        //         1,
        //         &script_elements.to_script(),
        //         5_000,
        //         bitcoin::sighash::EcdsaSighashType::All,
        //     ).unwrap()[..],
        // ).unwrap();
        // let _signature_1 = secp.sign_ecdsa(&sighash_1, &key_pair.secret_key());
        let solved_script_elements = script_elements.add_secrets(preimage.to_string(), signature_0.to_string());
        let solution = solved_script_elements.solve().unwrap();

       
        // let sweep_psbt = Psbt::from_unsigned_tx(sweep_tx);
        println!("{:?}", solution.to_hex_string());


        /*
         * REFERENCES
         * https://github.com/BoltzExchange/boltz-core/blob/master/lib/swap/Claim.ts#L63
         * 
         * https://github.com/bitcoin-teleport/teleport-transactions/blob/master/src/contracts.rs#L516C8-L516C24
         */
        
    }
}