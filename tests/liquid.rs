use dotenv::dotenv;
use std::{env, str::FromStr};

use boltzclient::{
    key::{ec::KeyPairString, preimage::Preimage},
    network::electrum::{BitcoinNetwork, NetworkConfig, DEFAULT_TESTNET_NODE},
    swaps::{
        boltz::{BoltzApiClient, CreateSwapRequest, BOLTZ_TESTNET_URL},
        liquid::script::{LBtcRevScriptElements, LBtcSubScriptElements},
    },
};
// use elements::Address;

/// submarine swap integration
/// update invoice before running
#[test]
#[ignore]
fn test_liquid_ssi() {
    // https://liquidtestnet.com/faucet
    let invoice = "lntb500u1pjhuau2pp5540kmv38f5227y7pvw7gs8jsk3htl66hlazv4qxpakmnq2x87wxsdqdd338gcmnwashqxqyjw5qcqp2sp5mj7q54kusg04fscuq9sgqwzwen0jj3304vsuug9pchj3w9vme7tsrzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkfkdwyqqq4sqqyqqqqqpqqqqqzsqqc9qyyssq8svlp8g70e5ngyzkylqyzdca4wandfdjjk330hu7xynkvmkjqr6j5439k4w40gmzh2t5lywf50yf3jj4j4xz8p5vryezjyrtt2avenqqdwss2n";

    let out_amount = 50_000;

    dotenv().ok();
    // SECRETS
    let mnemonic = match env::var("MNEMONIC") {
        Ok(result) => result,
        Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
    };
    let keypair = KeyPairString::from_mnemonic(mnemonic, "".to_string());
    println!("{:?}", keypair);
    // SECRETS
    let network_config = NetworkConfig::new(
        BitcoinNetwork::BitcoinTestnet,
        DEFAULT_TESTNET_NODE,
        true,
        true,
        false,
        None,
    )
    .unwrap();
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
        invoice.to_string(),
        keypair.pubkey.clone(),
    );
    let response = boltz_client.create_swap(request);
    assert!(response.is_ok());

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

    let boltz_script_elements = LBtcSubScriptElements::from_str(&redeem_script_string).unwrap();

    println!("{:?}", boltz_script_elements);

    println!("*******FUND*********************");
    println!("*******SWAP*********************");
    println!("*******SCRIPT*******************");
    println!("{}", funding_address);
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
        "vjTyPZRBt2WVo8nnFrkQSp4x6xRHt5DVmdtvNaHbMaierD41uz7fk4Jr9V9vgsPHD74WA61Ne67popRQ";
    let out_amount = 50_000;

    dotenv().ok();
    // SECRETS
    let mnemonic = match env::var("MNEMONIC") {
        Ok(result) => result,
        Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
    };
    let keypair = KeyPairString::from_mnemonic(mnemonic, "".to_string());
    println!("{:?}", keypair);
    let preimage = Preimage::new();
    // SECRETS
    let network_config = NetworkConfig::new(
        BitcoinNetwork::BitcoinTestnet,
        DEFAULT_TESTNET_NODE,
        true,
        true,
        false,
        None,
    )
    .unwrap();
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
        // timeout as u64,
        out_amount,
    );
    let response = boltz_client.create_swap(request);
    assert!(response.is_ok());
    println!("{:?}", preimage.clone());
    assert!(response
        .as_ref()
        .unwrap()
        .validate_preimage(preimage.clone().sha256));

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

    let boltz_script_elements = LBtcRevScriptElements::from_str(&redeem_script_string).unwrap();

    let constructed_script_elements = LBtcRevScriptElements::new(
        preimage.hash160.to_string(),
        keypair.pubkey.clone(),
        timeout as u32,
        boltz_script_elements.sender_pubkey.clone(),
    );
    let boltz_rs = hex::encode(boltz_script_elements.to_script().to_bytes());
    let _our_rs = hex::encode(constructed_script_elements.to_script().to_bytes());
    println!("{}", boltz_rs);
    assert_eq!(constructed_script_elements, boltz_script_elements);
    println!(
        "{:?} , {:?}",
        constructed_script_elements, boltz_script_elements
    );
}
