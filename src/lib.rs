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
    use std::env;
    use bitcoin::Network;
    use secp256k1::rand::{thread_rng, Rng};
    use crate::{config::WalletConfig, address, seed::import, derivation::{to_hardened_account, DerivationPurpose}, ec::{keypair_from_xprv_str, KeyPairString}, util::rnd_str, boltz::{BoltzApiClient, CreateSwapRequest, SwapType, PairId, OrderSide, SwapStatusRequest, BOLTZ_TESTNET_URL}};
    use dotenv::dotenv;
    use bitcoin::hashes::{sha256, Hash};

    #[tokio::test]
    async fn test_reverse_swap_integration() {
        println!("Creating a script wallet to recieve onchain swapped funds...");
        const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
        dotenv().ok();
        println!("Using predefined keys...");
        let mnemonic = match env::var("MNEMONIC") {
            Ok(result) => result,
            Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
        };
        println!("{}", mnemonic);

        let master_key = import(&mnemonic, "" , Network::Testnet).unwrap();
        let child_key = to_hardened_account(&master_key.xprv, DerivationPurpose::Compatible, 0).unwrap();
        let ec_key = keypair_from_xprv_str(&child_key.xprv).unwrap();
        let string_keypair = KeyPairString::from_keypair(ec_key);

        println!("Creating new preimage...");
        let preimage = rnd_str();
        println!("Preimage: {:?}", preimage);
        let preimage_hash =  sha256::Hash::hash(&hex::decode(preimage).unwrap());

        let client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
        let boltz_pairs = client.get_pairs().await.unwrap();
        
        let pair_hash = boltz_pairs.pairs.pairs.get("BTC/BTC")
            .map(|pair_info| pair_info.hash.clone())
            .unwrap();

        let request = CreateSwapRequest::new_reverse(
            SwapType::ReverseSubmarine, 
            PairId::Btc_Btc, 
            OrderSide::Buy, 
            pair_hash, 
            preimage_hash.to_string(), 
            string_keypair.pubkey, 
            3_999_999,
            100_000
        );
        let response = client.create_swap(request).await;
        assert!(response.is_ok());
        assert!(response.as_ref().unwrap().validate_preimage(preimage_hash.to_string()));
        let id = response.unwrap().id;
        let request = SwapStatusRequest{id: id};
        let response = client.swap_status(request).await;
        assert!(response.is_ok());
        
    }
    
}