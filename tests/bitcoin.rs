    // mod bullbitcoin_rnd;
    extern crate bullbitcoin_rnd;
    use std::{env, str::FromStr};
    use bitcoin::{Network, script::Error, sighash::SighashCache, Address, OutPoint, TxIn, Witness, Script, TxOut, Transaction, absolute::LockTime};
    use electrum_client::ElectrumApi;
    use bitcoin::Sequence;
    use secp256k1::{hashes::hash160, Secp256k1, Message};
    use bullbitcoin_rnd::{key::{seed::import, derivation::{to_hardened_account, DerivationPurpose}, ec::{keypair_from_xprv_str, KeyPairString}}, util::{rnd_str, pause_and_wait}, boltz::{BoltzApiClient, CreateSwapRequest, SwapType, PairId, OrderSide, SwapStatusRequest, BOLTZ_TESTNET_URL}, swaps::script::OnchainReverseSwapScriptElements, electrum::{NetworkConfig, BitcoinNetwork, DEFAULT_TESTNET_NODE}};
    use dotenv::dotenv;
    use bitcoin::hashes::{sha256, Hash};

    #[tokio::test]
    #[ignore]
    async fn test_bitcoin_rsi() {

        const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
        let out_amount = 50_000;

        dotenv().ok();
        let mnemonic = match env::var("MNEMONIC") {
            Ok(result) => result,
            Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
        };
        println!("{}", mnemonic);
        let master_key = import(&mnemonic, "" , Network::Testnet).unwrap();
        let child_key = to_hardened_account(&master_key.xprv, DerivationPurpose::Native, 0).unwrap();
        let ec_key = keypair_from_xprv_str(&child_key.xprv).unwrap();
        let string_keypair = KeyPairString::from_keypair(ec_key);
        println!("{:?}",string_keypair);
        let preimage = rnd_str();
        println!("Preimage: {:?}", preimage);
        let preimage_s256 =  sha256::Hash::hash(&hex::decode(preimage.clone()).unwrap());
        let preimage_h160 =  hash160::Hash::hash(&hex::decode(preimage.clone()).unwrap());

        let network_config = NetworkConfig::new(
            BitcoinNetwork::BitcoinTestnet,
            DEFAULT_TESTNET_NODE,
            true,
            true,
            false,
            None,
        ).unwrap();
        let electrum_client = network_config.electrum_url.build_client().unwrap();
        let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
       
        let boltz_pairs = boltz_client.get_pairs().await.unwrap();
        
        let pair_hash = boltz_pairs.pairs.pairs.get("BTC/BTC")
            .map(|pair_info| pair_info.hash.clone())
            .unwrap();
        // let timeout: u32 = 3_989_055;
        /*
         * 
         * 
         * 
         * TIMEOUT NEEDS TO BE CLARIFIED
         * SET BY BOLTZ
         * 
         * 
         * 
         */

        let request = CreateSwapRequest::new_reverse(
            SwapType::ReverseSubmarine, 
            PairId::Btc_Btc, 
            OrderSide::Buy, 
            pair_hash, 
            preimage_s256.to_string(), 
            string_keypair.pubkey.clone(), 
            // timeout as u64,
            out_amount
        );
        let response = boltz_client.create_swap(request).await;
        assert!(response.is_ok());
        println!("{}",preimage.clone().to_string());
        assert!(response.as_ref().unwrap().validate_preimage(preimage_s256.to_string()));
        // assert_eq!(timeout as u64 , response.as_ref().unwrap().timeout_block_height.unwrap().clone());

        let timeout = response.as_ref().unwrap().timeout_block_height.unwrap().clone();
        let id = response.as_ref().unwrap().id.as_str();
        let invoice = response.as_ref().unwrap().invoice.clone().unwrap();
        let lockup_address = response.as_ref().unwrap().lockup_address.clone().unwrap();
        let redeem_script_string = response.as_ref().unwrap().redeem_script.as_ref().unwrap().clone();

        let boltz_script_elements = OnchainReverseSwapScriptElements::from_str(&redeem_script_string).unwrap();
        // assert!(response.as_ref().unwrap().claim_public_key.as_ref().unwrap().clone() == boltz_script_elements.sender_pubkey);

        let constructed_script_elements = OnchainReverseSwapScriptElements::new(
            preimage_h160.to_string(),
            string_keypair.pubkey.clone(),
            timeout as u32,
            boltz_script_elements.sender_pubkey.clone(),
        );
        let boltz_rs = hex::encode(boltz_script_elements.to_script().to_bytes());
        let our_rs = hex::encode(constructed_script_elements.to_script().to_bytes());
        println!("{}", boltz_rs);
        assert_eq!(constructed_script_elements , boltz_script_elements);
        assert_eq!(lockup_address, Address::p2wsh(&constructed_script_elements.to_script(), Network::Testnet).to_string());

        assert_eq!(boltz_rs,our_rs);
        assert!(boltz_rs == redeem_script_string && our_rs == redeem_script_string);
        
        // println!("{:?} , {:?}", constructed_script_elements, boltz_script_elements);

        
        let constructed_address = constructed_script_elements.to_address(Network::Testnet);
        println!("{}", constructed_address.to_string());
        assert_eq!(constructed_address.to_string() , lockup_address);

        
        let script_balance = electrum_client.script_get_balance(&constructed_script_elements.to_script()).unwrap();
        assert_eq!(script_balance.unconfirmed, 0);
        assert_eq!(script_balance.confirmed, 0);
        println!("*******PAY********************");
        println!("*******LN*********************");
        println!("*******INVOICE****************");
        println!("{}",invoice);
        println!("");
        println!("Once you have paid the invoice, press enter to continue the tests.");
        println!("******************************");

        loop{
            pause_and_wait();
            let request = SwapStatusRequest{id: id.to_string()};
            let response = boltz_client.swap_status(request).await;
            assert!(response.is_ok());
            let swap_status = response.unwrap().status;
            
            if swap_status == "swap.created"{
                println!("Your turn: Pay the invoice");

            }
            if swap_status == "transaction.mempool"{
                println!("*******BOLTZ******************");
                println!("*******ONCHAIN-TX*************");
                println!("*******DETECTED***************");
                let script_balance = electrum_client.script_get_balance(&constructed_script_elements.to_script().to_v0_p2wsh()).unwrap();
                println!("{:?}",script_balance);
                break;
            }
        //     if swap_status == "transaction.confirmed"{
        //         println!("*******BOLTZ******************");
        //         println!("*******ONCHAIN-TX*************");
        //         println!("*******CONFIRMED**************");
        //         // claim the transaction
        //         break
        //     }
        }

        // ADDRESS WITH FUNDS THAT NEEDS TO BE CLAIMED
        // nSEQUENCE
        let sequence = Sequence::from_consensus(0xFFFFFFFF);

        // INIT ELECTRUM
        let electrum_client = NetworkConfig::default()
            .unwrap()
            .electrum_url
            .build_client()
            .unwrap();
 
        assert_eq!(constructed_address.to_string() , lockup_address);
        let script_balance = electrum_client.script_get_balance(&constructed_script_elements.to_script().to_v0_p2wsh()).unwrap();
        println!("Balance: {:?}", script_balance);

        // UTXO SET FOR GIVEN SCRIPT
        let utxos = electrum_client.script_list_unspent(&constructed_script_elements.to_script().to_v0_p2wsh()).unwrap();
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
        let return_address = Address::from_str(RETURN_ADDRESS).unwrap();
        let output: TxOut = TxOut {
            script_pubkey:return_address.payload.script_pubkey(), 
            value: out_amount
        };

        let unsigned_tx = Transaction{
            version : 1, 
            lock_time: LockTime::from_consensus(constructed_script_elements.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };

        // SIGN TRANSACTION
        let secp = Secp256k1::new();
        let sighash_0 = Message::from_slice(
            &SighashCache::new(unsigned_tx.clone())
                .segwit_signature_hash(
                    0,
                    &constructed_script_elements.to_script(),
                    utxo_value,
                    bitcoin::sighash::EcdsaSighashType::All,
                ).unwrap()[..]
        ).unwrap();
        let signature_0 = secp.sign_ecdsa(&sighash_0, &ec_key.secret_key());
        println!("SIG: {}",signature_0.to_string());

        // CREATE WITNESS
        let mut witness = Witness::new();
        witness.push_bitcoin_signature(&signature_0.serialize_der(), bitcoin::sighash::EcdsaSighashType::All);
        witness.push(hex::decode(preimage).unwrap());
        witness.push(constructed_script_elements.to_script().as_bytes());

        assert_eq!(redeem_script_string,hex::encode(constructed_script_elements.to_script().as_bytes()));
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
            lock_time: LockTime::from_consensus(constructed_script_elements.timelock),
            input: vec![signed_txin],
            output: vec![output.clone()],
        };
        // let sweep_psbt = Psbt::from_unsigned_tx(sweep_tx);

        
        let txid = electrum_client.transaction_broadcast(&signed_tx).unwrap();
        println!("{}", txid);

    }
