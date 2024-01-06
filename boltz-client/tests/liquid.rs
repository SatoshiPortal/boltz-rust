use boltzclient::{
    network::electrum::{BitcoinNetwork, NetworkConfig, DEFAULT_LIQUID_TESTNET_NODE},
    swaps::{
        boltz::{BoltzApiClient, CreateSwapRequest, BOLTZ_TESTNET_URL},
        liquid::LBtcSwapScript,
    },
    util::{derivation::ChildKeys, preimage::Preimage},
};
use elements::secp256k1_zkp::KeyPair as ZKKeyPair;
use elements::secp256k1_zkp::Secp256k1;

/// submarine swap integration
/// update invoice before running
#[test]
#[ignore]
fn test_liquid_ssi() {
    // https://liquidtestnet.com/faucet
    let invoice_str = "lntb500u1pjchejhpp5lpsl9kglag95sd848esm0e8wghv5t9u8y0stj7aq0kyyfvhl899qdq9w3hhqxqyjw5qcqp2sp50chgw33mdrhrqgax52srptdt0kpwswmngexfhucz30ptmh8pzx0qrzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkfkdwyqqq4sqqyqqqqqpqqqqqzsqqc9qyyssq4k5t7aphnpsemxggwxkd0dj7c6le0l9htr750tpekghh458gunrh0s47qpyg4utzh2qhy6jykk9d055pcw9hv98wpz7ncywf67qk2rcpwmpyyj";

    let preimage = Preimage::from_invoice_str(invoice_str).unwrap();

    let _out_amount = 50_000;

    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon".to_string();
    let keypair = ChildKeys::from_submarine_account(&mnemonic, 1)
        .unwrap()
        .keypair;
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
        keypair.public_key().to_string().clone(),
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
    let blinding_string = response.as_ref().unwrap().blinding_key.clone().unwrap();

    let redeem_script_string = response
        .as_ref()
        .unwrap()
        .redeem_script
        .as_ref()
        .unwrap()
        .clone();

    let boltz_script_elements =
        LBtcSwapScript::submarine_from_str(&redeem_script_string, blinding_string).unwrap();

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

    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon".to_string();
    let keypair = ChildKeys::from_reverse_account(&mnemonic, 1)
        .unwrap()
        .keypair;
    println!("SECRET-KEY: {:?}", keypair.display_secret());
    let preimage = Preimage::new();
    println!("PREIMAGE: {}", hex::encode(preimage.bytes.unwrap()));
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
        preimage.clone().sha256.to_string(),
        keypair.public_key().to_string().clone(),
        out_amount,
    );
    let response = boltz_client.create_swap(request);
    // println!("{:?}", response);

    assert!(response.is_ok());
    // println!("{:?}", preimage.clone());
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
    let blinding_string = response.as_ref().unwrap().blinding_key.clone().unwrap();
    println!("BOLTZ-BLINDING-KEY: {}", blinding_string);

    let redeem_script_string = response
        .as_ref()
        .unwrap()
        .redeem_script
        .as_ref()
        .unwrap()
        .clone();
    println!("REDEEM_SCRIPT: {}", redeem_script_string);

    let boltz_script_elements =
        LBtcSwapScript::reverse_from_str(&redeem_script_string, blinding_string.clone()).unwrap();
    let secp = Secp256k1::new();
    let constructed_script_elements = LBtcSwapScript::new(
        boltzclient::swaps::boltz::SwapType::ReverseSubmarine,
        preimage.hash160.to_string(),
        keypair.public_key().to_string().clone(),
        timeout as u32,
        boltz_script_elements.sender_pubkey.clone(),
        ZKKeyPair::from_seckey_str(&secp, &blinding_string).unwrap(),
    );

    assert_eq!(constructed_script_elements, boltz_script_elements);
    println!("{:?}", constructed_script_elements);
}
