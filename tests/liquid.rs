use std::os::unix::net;

use boltz_client::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::{
        boltz::{BoltzApiClient, CreateSwapRequest, SwapStatusRequest, BOLTZ_TESTNET_URL},
        liquid::{LBtcSwapTx},
    },
    util::{secrets::{SwapKey, LiquidSwapKey,Preimage}},
};
pub mod test_utils;
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
    let keypair = SwapKey::from_submarine_account(&mnemonic, "", &Chain::LiquidTestnet, 1)
        .unwrap()
        .keypair;
    println!("{:?}", keypair);
    // SECRETS
    let network_config = ElectrumConfig::default_liquid();
    let _electrum_client = network_config.build_client().unwrap();
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_lbtc_pair = boltz_pairs.get_lbtc_pair();
    let fees = boltz_lbtc_pair.fees.submarine_boltz(_out_amount).unwrap() +  boltz_lbtc_pair.fees.submarine_claim().unwrap();
    println!("TOTAL FEES:{}", fees);

    let request = CreateSwapRequest::new_lbtc_submarine(
        &boltz_lbtc_pair.hash,
        invoice_str,
        &keypair.public_key().to_string(),
    );
    let response = boltz_client.create_swap(request).unwrap();
    let _id = response.get_id();

    println!("{:?}", response);

    let expected_amount = response.get_expected_amount().unwrap();
    let boltz_script_elements = response.into_lbtc_sub_swap_script(&preimage).unwrap();
    let funding_address = boltz_script_elements.to_address(network_config.network()).unwrap().to_string();

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
    const RETURN_ADDRESS: &str =
        "tlq1qqtc07z9kljll7dk2jyhz0qj86df9gnrc70t0wuexutzkxjavdpht0d4vwhgs2pq2f09zsvfr5nkglc394766w3hdaqrmay4tw";
    let out_amount = 50_000;
    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon".to_string();
    let swap_key = SwapKey::from_reverse_account(&mnemonic, "", Chain::LiquidTestnet, 1)
        .unwrap();
    let lsk: LiquidSwapKey = swap_key.into();
    let keypair = lsk.keypair;

    println!("SECRET-KEY: {:?}", keypair.display_secret());
    let preimage = Preimage::new();
    println!("PREIMAGE: {}", hex::encode(preimage.bytes.unwrap()));
    // SECRETS
    let network_config = ElectrumConfig::default_liquid();
    let _electrum_client = network_config.build_client().unwrap();
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_lbtc_pair = boltz_pairs.get_lbtc_pair();
    let fees = boltz_lbtc_pair.fees.reverse_boltz(out_amount).unwrap() + boltz_lbtc_pair.fees.reverse_lockup().unwrap();
    println!("TOTAL FEES: {}", fees);

    let request = CreateSwapRequest::new_lbtc_reverse_onchain_amt(
        boltz_lbtc_pair.hash,
        preimage.sha256.to_string(),
        keypair.public_key().to_string(),
        out_amount,
    );
    let response = boltz_client.create_swap(request).unwrap();
    let id = response.get_id();

    let invoice = response.get_invoice().unwrap();
    let boltz_script_elements = response.into_lbtc_rev_swap_script(&preimage, &keypair, Chain::LiquidTestnet).unwrap();

    let absolute_fees = 900;
    let network_config = ElectrumConfig::default_bitcoin();

    println!("*******PAY********************");
    println!("*******LN*********************");
    println!("*******INVOICE****************");
    println!("{}", invoice.to_string());
    println!("");
    println!("Once you have paid the invoice, press enter to continue the tests.");
    println!("******************************");

    loop {
        test_utils::pause_and_wait("Continue will check swap status and act accordingly");
        let request = SwapStatusRequest { id: id.to_string() };
        let response = boltz_client.swap_status(request);
        assert!(response.is_ok());
        let swap_status = response.unwrap().status;
        println!("SwapStatus: {}", swap_status);

        if swap_status == "swap.created" {
            println!("Your turn: Pay the invoice");
        }
        if swap_status == "transaction.mempool" || swap_status == "transaction.confirmed" {
            println!("*******BOLTZ******************");
            println!("*******ONCHAIN-TX*************");
            println!("*******DETECTED***************");
            test_utils::pause_and_wait(
                "WE ARE ABOUT TO BREAK: Give it 20-30 seconds for tx to propogate into the testnet mempool.",
            );
            break;
        }
    }

    let mut rev_swap_tx =
        LBtcSwapTx::new_claim(boltz_script_elements, RETURN_ADDRESS.to_string()).unwrap();
    let _ = rev_swap_tx.fetch_utxo(&network_config).unwrap();
    println!("{:?}", rev_swap_tx);
    test_utils::pause_and_wait("Waiting....");
    let _ = rev_swap_tx.fetch_utxo(&network_config).unwrap();
    println!("{:?}", rev_swap_tx);
    test_utils::pause_and_wait("Waiting....");

    let signed_tx = rev_swap_tx
        .drain(
            keypair,
            preimage,
            absolute_fees,
        )
        .unwrap();
    let txid = rev_swap_tx.broadcast(signed_tx, &network_config).unwrap();
    println!("{}", txid);
}
