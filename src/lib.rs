pub mod e;
pub mod boltz;
pub mod config;
pub mod seed;
pub mod derivation;
pub mod ec;
pub mod util;
pub mod script;
pub mod address;
pub mod sync;

#[cfg(test)]
mod tests {
    use std::{env, str::FromStr};
    use bitcoin::Network;
    use secp256k1::{rand::{thread_rng, Rng}, hashes::ripemd160};
    use crate::{config::WalletConfig, address, seed::import, derivation::{to_hardened_account, DerivationPurpose}, ec::{keypair_from_xprv_str, KeyPairString}, util::rnd_str, boltz::{BoltzApiClient, CreateSwapRequest, SwapType, PairId, OrderSide, SwapStatusRequest, BOLTZ_TESTNET_URL}, script::{ SwapRedeemScriptElements, self, ReverseSwapRedeemScriptElements, }};
    use dotenv::dotenv;
    use bitcoin::hashes::{sha256, Hash};

    #[tokio::test]
    async fn test_reverse_swap_integration() {
        const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
        dotenv().ok();
        let mnemonic = match env::var("MNEMONIC") {
            Ok(result) => result,
            Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
        };
        println!("{}", mnemonic);

        let master_key = import(&mnemonic, "" , Network::Testnet).unwrap();
        let child_key = to_hardened_account(&master_key.xprv, DerivationPurpose::Compatible, 0).unwrap();
        let ec_key = keypair_from_xprv_str(&child_key.xprv).unwrap();
        let string_keypair = KeyPairString::from_keypair(ec_key);

        let preimage = rnd_str();
        println!("Preimage: {:?}", preimage);
        let preimage_hash =  sha256::Hash::hash(&hex::decode(preimage).unwrap());
        let hash160 = ripemd160::Hash::hash(&hex::decode(preimage_hash.to_string()).unwrap());

        println!("Hash160: {:?}", hash160);
        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let boltz_pairs = client.get_pairs().await.unwrap();
        
        let pair_hash = boltz_pairs.pairs.pairs.get("BTC/BTC")
            .map(|pair_info| pair_info.hash.clone())
            .unwrap();
        let timeout: u32 = 3_989_055;
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
            preimage_hash.to_string(), 
            string_keypair.pubkey.clone(), 
            timeout as u64,
            100_000
        );
        let response = client.create_swap(request).await;
        assert!(response.is_ok());
        println!("{}",preimage_hash.to_string());
        assert!(response.as_ref().unwrap().validate_preimage(preimage_hash.to_string()));
        // assert_eq!(timeout as u64 , response.as_ref().unwrap().timeout_block_height.unwrap().clone());

        let timeout = response.as_ref().unwrap().timeout_block_height.unwrap().clone();
        let id = response.as_ref().unwrap().id.clone();
        let boltz_script_elements = ReverseSwapRedeemScriptElements::from_str(&response.as_ref().unwrap().redeem_script.as_ref().unwrap().clone()).unwrap();
        // assert!(response.as_ref().unwrap().claim_public_key.as_ref().unwrap().clone() == boltz_script_elements.sender_pubkey);

        let constructed_script_elements = ReverseSwapRedeemScriptElements{
            hashlock: hash160.to_string(),
            reciever_pubkey: string_keypair.pubkey.clone(),
            timelock: timeout as u32,
            sender_pubkey: boltz_script_elements.sender_pubkey.clone(),
        };
        println!("{:?} , {:?}", constructed_script_elements, boltz_script_elements);

        assert!(constructed_script_elements == boltz_script_elements);
        // println!("swap id:{}",id);
        let request = SwapStatusRequest{id: id};
        let response = client.swap_status(request).await;
        assert!(response.is_ok());

    }
    
}