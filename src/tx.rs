#[cfg(test)]
mod tests {
    use std::{str::FromStr, env};
    use bitcoin::Network;
    use electrum_client::ElectrumApi;
    use crate::{ec::{KeyPairString, keypair_from_xprv_str}, derivation::{DerivationPurpose, to_hardened_account}, seed::import, script::ReverseSwapRedeemScriptElements, electrum::NetworkConfig};
    use super::*;

    #[test]
    fn test_transaction(){
        /*
         * a script was created
         * gn address was generated
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
        let preimage = "36393139333730383132383738353633303337";
        let key_pair_string = KeyPairString { 
            seckey: "f37f95f01f3a28ba2bf4054e56b0cc217dd0b48edfd75a205cc2a96c20876a1b".to_string(), 
            pubkey: "037bdb90d61d1100664c4aaf0ea93fb71c87433f417e93294e08ae9859910efcea".to_string() 
        };
        let redeem_script_str = "8201208763a9140ba9f02ac085c062d72db3c1ca5a448b75537a1c8821037bdb90d61d1100664c4aaf0ea93fb71c87433f417e93294e08ae9859910efcea677503f8c926b1752102ee2ebf016f67732a95ee6751eede736c433325f29470fde26fb6d8d2d7f0513168ac";
        let script_elements = ReverseSwapRedeemScriptElements::from_str(redeem_script_str).unwrap();
        let address = script_elements.to_address(Network::Testnet);
        let lockup_address = "tb1qdc5mtlxkxntnkujczhqz8rztguz26xc4ppmuxyxzj0cswdnxmq7sx47z90".to_string();
        assert_eq!(address.to_string() , lockup_address);
        let script_balance = electrum_client.script_get_balance(&script_elements.to_script().to_v0_p2wsh()).unwrap();
        println!("Balance: {:?}", script_balance);

        
    }
}