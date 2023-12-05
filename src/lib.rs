pub mod e;
pub mod boltz;
pub mod config;
pub mod seed;
pub mod derivation;
pub mod ec;
pub mod hash;
pub mod script;
pub mod address;
pub mod policy;
pub mod sync;

#[cfg(test)]
mod tests {
    use std::env;
    use bitcoin::Network;
    use secp256k1::rand::{thread_rng, Rng};

    use crate::{config::WalletConfig, address};


    #[tokio::test]
    async fn test_integration() {
        println!("Creating a script wallet to recieve onchain swapped funds...");
        println!("Using predefined keys");
        println!("Using predefined preimage");
        let descriptor = "sh(wsh(thresh(1,j:and_v(v:pk(036e36d8f4c8ccf8776828fe6962b87024bf786a42b8127a0e7a8b92c2bfc5c8e5),hash160(e1db6d8de42a72420d408695ab393407a28bc341)),snj:and_v(v:pk(023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d),after(5818662)))))";

        let config = WalletConfig::new_offline(Network::Testnet,&descriptor,&descriptor,None).unwrap();
        let address0 = address::generate(config, 0).unwrap();
        assert_eq!(
            "2NBQJYfU4VrTuNb4rcWySMT9tGB8o8rfGAM".to_string(),
            address0.address
        );
       
        assert!(true);
    }
    
}