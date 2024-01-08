use boltz_client::{
    swaps::boltz::SwapType,
    util::{derivation::ChildKeys, error::S5Error},
};

pub struct KeyPair {
    pub secret_key: String,
    pub public_key: String,
}

impl KeyPair {
    pub fn new(mnemonic: String, index: u64, swap_type: SwapType) -> Result<Self, S5Error> {
        match swap_type {
            SwapType::Submarine => {
                let child_keys = ChildKeys::from_submarine_account(&mnemonic, index)?;
                Ok(KeyPair {
                    secret_key: child_keys.keypair.display_secret().to_string(),
                    public_key: child_keys.keypair.public_key().to_string(),
                })
            }
            SwapType::Reverse => {
                let child_keys = ChildKeys::from_reverse_account(&mnemonic, index)?;
                Ok(KeyPair {
                    secret_key: child_keys.keypair.display_secret().to_string(),
                    public_key: child_keys.keypair.public_key().to_string(),
                })
            }
        }
    }
}

mod tests {
    use super::*;
    #[test]
    fn test_secrets() {
        let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon".to_string();
        let kps = KeyPair::new(mnemonic.clone(), 0, SwapType::Submarine).unwrap();
        let expected_seckey = "9b496356fbb59d95656acc879a5d7a9169eb3d77e5b7c511aeb827925e5b49e9";
        assert_eq!(&kps.secret_key, expected_seckey);
        let kps = KeyPair::new(mnemonic.clone(), 1, SwapType::Submarine).unwrap();
        let expected_seckey = "5416f1e024c191605502017d066786e294f841e711d3d437d13e9d27e40e066e";
        assert_eq!(&kps.secret_key, expected_seckey);
        let kps = KeyPair::new(mnemonic.clone(), 0, SwapType::Reverse).unwrap();
        let expected_seckey = "a0a62dd7225288f41a741c293a3220035b4c71686dc34c01ec84cbe6ab11b4e1";
        assert_eq!(&kps.secret_key, expected_seckey);
        let kps = KeyPair::new(mnemonic.clone(), 1, SwapType::Reverse).unwrap();
        let expected_seckey = "aecbc2bddfcd3fa6953d257a9f369dc20cdc66f2605c73efb4c91b90703506b6";
        assert_eq!(&kps.secret_key, expected_seckey);
    }
}
