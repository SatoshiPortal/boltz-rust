use std::{os::unix::net, str::FromStr};

use boltz_client::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::{
        boltz::{BoltzApiClient, CreateSwapRequest, SwapStatusRequest, BOLTZ_TESTNET_URL},
        liquid::{LBtcSwapScript, LBtcSwapTx},
    },
    util::secrets::{LBtcReverseRecovery, LiquidSwapKey, Preimage, SwapKey},
    Keypair, ZKKeyPair,
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
    let keypair = SwapKey::from_submarine_account(&mnemonic, "", Chain::LiquidTestnet, 1)
        .unwrap()
        .keypair;
    println!("{:?}", keypair);
    // SECRETS
    let network_config = ElectrumConfig::default_liquid();
    let _electrum_client = network_config.build_client().unwrap();
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_lbtc_pair = boltz_pairs.get_lbtc_pair().unwrap();
    let fees = boltz_lbtc_pair.fees.submarine_boltz(_out_amount).unwrap()
        + boltz_lbtc_pair.fees.submarine_claim().unwrap();
    println!("TOTAL FEES:{}", fees);

    let request = CreateSwapRequest::new_lbtc_submarine(
        &boltz_lbtc_pair.hash,
        invoice_str,
        &keypair.public_key().to_string(),
    );
    let response = boltz_client.create_swap(request).unwrap();
    let _id = response.get_id();

    println!("{:?}", response);

    let expected_amount = response.get_funding_amount().unwrap();
    let boltz_script_elements = response
        .into_lbtc_sub_swap_script(&preimage, &keypair, network_config.network())
        .unwrap();
    let funding_address = boltz_script_elements
        .to_address(network_config.network())
        .unwrap()
        .to_string();

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
        "tlq1qqv4z28utgwunvn62s3aw0qjuw3sqgfdq6q8r8fesnawwnuctl70kdyedxw6tmxgqpq83x6ldsyr4n6cj0dm875k8g9k85w2s7";
    let out_amount = 50_000;
    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon".to_string();
    let swap_key = SwapKey::from_reverse_account(&mnemonic, "", Chain::LiquidTestnet, 1).unwrap();
    let lsk: LiquidSwapKey = swap_key.into();
    let keypair = lsk.keypair;

    let preimage = Preimage::new();
    // SECRETS
    let network_config = ElectrumConfig::default_liquid();
    let _electrum_client = network_config.build_client().unwrap();
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_lbtc_pair = boltz_pairs.get_lbtc_pair().unwrap();
    let fees = boltz_lbtc_pair.fees.reverse_boltz(out_amount).unwrap()
        + boltz_lbtc_pair.fees.reverse_lockup().unwrap();
    println!("TOTAL FEES: {}", fees);

    let request = CreateSwapRequest::new_lbtc_reverse_onchain_amt(
        boltz_lbtc_pair.hash,
        preimage.sha256.to_string(),
        keypair.public_key().to_string(),
        out_amount,
    );
    let response = boltz_client.create_swap(request).unwrap();
    let id = response.get_id();
    let blinding_key = ZKKeyPair::from_str(&response.get_blinding_key().unwrap()).unwrap();
    let invoice = response.get_invoice().unwrap();
    let boltz_script_elements = response
        .into_lbtc_rev_swap_script(&preimage, &keypair, Chain::LiquidTestnet)
        .unwrap();

    let absolute_fees = 900;
    let network_config = ElectrumConfig::default_bitcoin();

    let recovery = LBtcReverseRecovery::new(
        &id,
        &preimage,
        &keypair,
        &blinding_key,
        &response.get_redeem_script().unwrap(),
    );
    println!("RECOVERY: {:#?}", recovery);
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
        .sign_claim(&keypair, &preimage, absolute_fees)
        .unwrap();
    let txid = rev_swap_tx.broadcast(signed_tx, &network_config).unwrap();
    println!("{}", txid);
}

#[test]
fn test_recover_liquid_rsi() {
    const RETURN_ADDRESS: &str =
    "tlq1qqv4z28utgwunvn62s3aw0qjuw3sqgfdq6q8r8fesnawwnuctl70kdyedxw6tmxgqpq83x6ldsyr4n6cj0dm875k8g9k85w2s7";
    let recovery = &LBtcReverseRecovery {
        id: "G5GDSN".to_string(),
        preimage: "76878e58c6bfedc5e961b1c09fc5fad03bcbfce3237b586266b8288cdf70391f".to_string(),
        claim_key: "aecbc2bddfcd3fa6953d257a9f369dc20cdc66f2605c73efb4c91b90703506b6".to_string(),
        blinding_key: "b8ec3f5a97af0567a80246d0ed4f4c39106649797ced86a2085eaf2a5fd17d91".to_string(),
        redeem_script: "8201208763a914756ec1797f685b2499638c5afbc69a418795073a882102ccbab5f97c89afb97d814831c5355ef5ba96a18c9dcd1b5c8cfd42c697bfe53c67750351d612b175210264db3a3b1c2a06a2a7ea5ccbb0d8e73d0605e4f9049c4b634ecd31c87880e1b668ac".to_string(),
    };
    let script: LBtcSwapScript = recovery.try_into().unwrap();
    let mut tx = LBtcSwapTx::new_claim(script, RETURN_ADDRESS.to_string()).unwrap();
    let network_config = ElectrumConfig::default_liquid();
    let _ = tx.fetch_utxo(&network_config).unwrap();
    let _keypair: Keypair = recovery.try_into().unwrap();
    let _preimage: Preimage = recovery.try_into().unwrap();

    // let signed_tx = tx
    // .drain(&_keypair, &_preimage, 1_000)
    // .unwrap();
    // let txid = tx.broadcast(signed_tx, &network_config).unwrap();
    // println!("{}", txid);
}
