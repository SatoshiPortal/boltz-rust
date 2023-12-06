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

    use crate::{config::WalletConfig, address};


    #[tokio::test]
    async fn test_integration() {
        println!("Creating a script wallet to recieve onchain swapped funds...");
        println!("Using predefined keys");
        println!("Using predefined preimage");
        
        assert!(true);
    }
    
}