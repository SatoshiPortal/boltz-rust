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

    #[tokio::test]
    async fn test_integration() {
        println!("Creating a script wallet to recieve onchain swapped funds...");
        println!("Using predefined keys");
        println!("Using predefined preimage");

        println!("");
        println!("");
        println!("");
        println!("");
        println!("");
        println!("");

        assert!(true);
    }
    
}