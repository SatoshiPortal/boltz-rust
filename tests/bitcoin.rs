// mod bullbitcoin_rnd;
// extern crate libbullwallet;

use bitcoin::{Address, Network};
use bullwallet::{
    key::{ec::KeyPairString, preimage::Preimage},
    network::electrum::{BitcoinNetwork, NetworkConfig, DEFAULT_TESTNET_NODE},
    swaps::{
        bitcoin::script::OnchainReverseSwapScriptElements,
        bitcoin::tx::OnchainSwapTxElements,
        boltz::{
            BoltzApiClient, CreateSwapRequest, OrderSide, PairId, SwapStatusRequest, SwapType,
            BOLTZ_TESTNET_URL,
        },
    },
    util::pause_and_wait,
};
use dotenv::dotenv;
use electrum_client::ElectrumApi;

use std::{env, str::FromStr};

#[test]
#[ignore]
fn test_bitcoin_rsi() {
    const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
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
    let electrum_client = network_config.electrum_url.build_client().unwrap();
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let pair_hash = boltz_pairs
        .pairs
        .pairs
        .get("BTC/BTC")
        .map(|pair_info| pair_info.hash.clone())
        .unwrap();

    let request = CreateSwapRequest::new_btc_reverse(
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
        .validate_preimage(preimage.clone().preimage));

    let timeout = response
        .as_ref()
        .unwrap()
        .timeout_block_height
        .unwrap()
        .clone();
    let id = response.as_ref().unwrap().id.as_str();
    let invoice = response.as_ref().unwrap().invoice.clone().unwrap();
    let lockup_address = response.as_ref().unwrap().lockup_address.clone().unwrap();
    let redeem_script_string = response
        .as_ref()
        .unwrap()
        .redeem_script
        .as_ref()
        .unwrap()
        .clone();

    let boltz_script_elements =
        OnchainReverseSwapScriptElements::from_str(&redeem_script_string).unwrap();

    let constructed_script_elements = OnchainReverseSwapScriptElements::new(
        preimage.hash160.to_string(),
        keypair.pubkey.clone(),
        timeout as u32,
        boltz_script_elements.sender_pubkey.clone(),
    );
    let boltz_rs = hex::encode(boltz_script_elements.to_script().to_bytes());
    let our_rs = hex::encode(constructed_script_elements.to_script().to_bytes());
    println!("{}", boltz_rs);
    assert_eq!(constructed_script_elements, boltz_script_elements);
    assert_eq!(
        lockup_address,
        Address::p2wsh(&constructed_script_elements.to_script(), Network::Testnet).to_string()
    );
    assert_eq!(boltz_rs, our_rs);
    assert!(boltz_rs == redeem_script_string && our_rs == redeem_script_string);

    // println!("{:?} , {:?}", constructed_script_elements, boltz_script_elements);

    let constructed_address = constructed_script_elements.to_address(Network::Testnet);
    println!("{}", constructed_address.to_string());
    assert_eq!(constructed_address.to_string(), lockup_address);

    let script_balance = electrum_client
        .script_get_balance(&constructed_script_elements.to_script())
        .unwrap();
    assert_eq!(script_balance.unconfirmed, 0);
    assert_eq!(script_balance.confirmed, 0);
    println!("*******PAY********************");
    println!("*******LN*********************");
    println!("*******INVOICE****************");
    println!("{}", invoice);
    println!("");
    println!("Once you have paid the invoice, press enter to continue the tests.");
    println!("******************************");

    loop {
        pause_and_wait();
        let request = SwapStatusRequest { id: id.to_string() };
        let response = boltz_client.swap_status(request);
        assert!(response.is_ok());
        let swap_status = response.unwrap().status;

        if swap_status == "swap.created" {
            println!("Your turn: Pay the invoice");
        }
        if swap_status == "transaction.mempool" {
            println!("*******BOLTZ******************");
            println!("*******ONCHAIN-TX*************");
            println!("*******DETECTED***************");
            let script_balance = electrum_client
                .script_get_balance(&constructed_script_elements.to_script().to_v0_p2wsh())
                .unwrap();
            println!("{:?}", script_balance);
            break;
        }
    }

    let absolute_fees = 300;
    let mut swap_tx_elements = OnchainSwapTxElements::new(
        redeem_script_string,
        RETURN_ADDRESS.to_string(),
        absolute_fees,
        Network::Testnet,
    );
    swap_tx_elements.fetch_utxo(DEFAULT_TESTNET_NODE.to_string(), out_amount);
    let signed_tx = swap_tx_elements.build_tx(keypair, preimage);
    let txid = electrum_client.transaction_broadcast(&signed_tx).unwrap();
    println!("{}", txid);
}
