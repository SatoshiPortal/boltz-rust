use dotenv::dotenv;
use std::env;

use boltzclient::{
    key::{ec::KeyPairString, preimage::PreimageStates},
    network::electrum::{
        BitcoinNetwork, NetworkConfig, DEFAULT_LIQUID_TESTNET_NODE, DEFAULT_TESTNET_NODE,
    },
    swaps::{
        boltz::{BoltzApiClient, CreateSwapRequest, BOLTZ_TESTNET_URL},
        liquid::LBtcSwapScript,
    },
};
// use elements::Address;

/// submarine swap integration
/// update invoice before running
#[test]
#[ignore]
fn test_liquid_ssi() {
    // https://liquidtestnet.com/faucet
    let invoice_str = "lntb560u1pjcfqampp59kxkg8nywg50a37ks8v6qau9nv0dmkf825pfxwl3mn8mw4u08p9qdpgxguzq5mrv9kxzgzrdp5hqgzxwfshqur4vd3kjmn0xqrrsscqp79qy9qsqsp5g6p5xc5l5qyk98txtescxw3a768rpcjshf5at9n9jkamxzthsr2ssjxc9hw90kqp0e000xq7y0vwec434xu094adnp2zlq4esjkzecryt7net4cv2mjqjx7euxzetyrkl339dygl3cnmr8h2fq43yuvfnqsqhhukdw";

    let preimage = PreimageStates::from_invoice_str(invoice_str).unwrap();

    let _out_amount = 50_000;

    dotenv().ok();
    // SECRETS
    let mnemonic = match env::var("MNEMONIC") {
        Ok(result) => result,
        Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
    };
    let keypair = KeyPairString::from_mnemonic(mnemonic, "".to_string(), 1).unwrap();
    println!("{:?}", keypair);
    // SECRETS
    let network_config = NetworkConfig::default_liquid();
    let _electrum_client = network_config.electrum_url.build_client().unwrap();
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let pair_hash = boltz_pairs
        .pairs
        .pairs
        .get("L-BTC/BTC")
        .map(|pair_info| pair_info.hash.clone())
        .unwrap();

    let request = CreateSwapRequest::new_lbtc_submarine(
        pair_hash,
        invoice_str.to_string(),
        keypair.pubkey.clone(),
    );
    let response = boltz_client.create_swap(request);
    println!("{:?}", response);
    assert!(response.is_ok());
    assert!(response
        .as_ref()
        .unwrap()
        .validate_script_preimage160(preimage.hash160));

    let _id = response.as_ref().unwrap().id.as_str();
    let funding_address = response.as_ref().unwrap().address.clone().unwrap();
    let expected_amount = response.as_ref().unwrap().expected_amount.clone().unwrap();

    let redeem_script_string = response
        .as_ref()
        .unwrap()
        .redeem_script
        .as_ref()
        .unwrap()
        .clone();

    let boltz_script_elements = LBtcSwapScript::submarine_from_str(
        BitcoinNetwork::LiquidTestnet,
        DEFAULT_LIQUID_TESTNET_NODE.to_string(),
        &redeem_script_string,
    )
    .unwrap();

    println!("{:?}", boltz_script_elements);

    println!("*******FUND*********************");
    println!("*******SWAP*********************");
    println!("*******SCRIPT*******************");
    println!("PAY: {} TO: {}", expected_amount, funding_address);
    println!("");
    println!("Once you have paid the address, the invoice will get paid after 1 conf.");
    println!("********************************");
}

/// reverse swap integration
#[test]
#[ignore]
fn test_liquid_rsi() {
    // https://liquidtestnet.com/faucet
    const _RETURN_ADDRESS: &str =
        "tlq1qqtc07z9kljll7dk2jyhz0qj86df9gnrc70t0wuexutzkxjavdpht0d4vwhgs2pq2f09zsvfr5nkglc394766w3hdaqrmay4tw";
    let out_amount = 50_000;

    dotenv().ok();
    // SECRETS
    let mnemonic = match env::var("MNEMONIC") {
        Ok(result) => result,
        Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
    };
    let keypair = KeyPairString::from_mnemonic(mnemonic, "".to_string(), 1).unwrap();
    println!("{:?}", keypair);
    let preimage = PreimageStates::new();
    // SECRETS
    let network_config = NetworkConfig::default_liquid();
    let _electrum_client = network_config.electrum_url.build_client().unwrap();
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let pair_hash = boltz_pairs
        .pairs
        .pairs
        .get("L-BTC/BTC")
        .map(|pair_info| pair_info.hash.clone())
        .unwrap();

    let request = CreateSwapRequest::new_lbtc_reverse(
        pair_hash,
        preimage.clone().sha256,
        keypair.pubkey.clone(),
        out_amount,
    );
    let response = boltz_client.create_swap(request);
    // println!("{:?}", response);

    assert!(response.is_ok());
    println!("{:?}", preimage.clone());
    assert!(response
        .as_ref()
        .unwrap()
        .validate_invoice_preimage256(preimage.clone().sha256));

    let timeout = response
        .as_ref()
        .unwrap()
        .timeout_block_height
        .unwrap()
        .clone();
    let _id = response.as_ref().unwrap().id.as_str();
    let _invoice = response.as_ref().unwrap().invoice.clone().unwrap();
    let _lockup_address = response.as_ref().unwrap().lockup_address.clone().unwrap();
    let redeem_script_string = response
        .as_ref()
        .unwrap()
        .redeem_script
        .as_ref()
        .unwrap()
        .clone();

    let boltz_script_elements = LBtcSwapScript::reverse_from_str(
        BitcoinNetwork::LiquidTestnet,
        DEFAULT_LIQUID_TESTNET_NODE.to_string(),
        &redeem_script_string,
    )
    .unwrap();
    let constructed_script_elements = LBtcSwapScript::new(
        BitcoinNetwork::LiquidTestnet,
        DEFAULT_LIQUID_TESTNET_NODE.to_string(),
        boltzclient::swaps::boltz::SwapType::ReverseSubmarine,
        preimage.hash160.to_string(),
        keypair.pubkey.clone(),
        timeout as u32,
        boltz_script_elements.sender_pubkey.clone(),
    );

    assert_eq!(constructed_script_elements, boltz_script_elements);
    println!("{:?}", constructed_script_elements);
}
