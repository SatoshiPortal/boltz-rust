use std::{path::PathBuf, str::FromStr};

use rust_elements_wrapper::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::{
        boltz::{BoltzApiClient, CreateSwapRequest, SwapStatusRequest, BOLTZ_TESTNET_URL},
        liquid::{LBtcSwapScript, LBtcSwapTx},
    },
    util::secrets::{
        LBtcReverseRecovery, LBtcSubmarineRecovery, LiquidSwapKey, Preimage, RefundSwapFile,
        SwapKey,
    },
    Keypair, Secp256k1, ZKKeyPair,
};
pub mod test_utils;
/// submarine swap integration
/// update invoice before running
#[test]
#[ignore]
fn test_liquid_ssi() {
    // https://liquidtestnet.com/faucet
    let invoice_str = "lntb650u1pjut6hupp57akjrewzj59g4sm0lp57euzul3dw2ep55um98nh73ruy0w4vcrzqdq8d3skk6qxqyjw5qcqp2sp5ugurque8z76czwqdkxl2ae7ddydka9xymfnhgzdyalfzcslxzjnqrzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkf6vkyqq20gqqqqqqqqpqqqqqzsqqc9qyyssqpl8p6yqhfpc4t03nmczqp9vrc25qf36zzyglqt685ncvqyx8z48rmetst6v8t3vt35z3pxvjfa7pu3kgc0ltqy8jvtql4ap37wtevpsqh7m6en";

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

    let blinding_key = ZKKeyPair::from_str(&response.get_blinding_key().unwrap()).unwrap();

    let recovery = LBtcSubmarineRecovery::new(
        &_id,
        &keypair,
        &blinding_key,
        &response.get_redeem_script().unwrap(),
    );
    let refund_file: RefundSwapFile = recovery.clone().into();
    let cargo_manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let refund_path = PathBuf::from(cargo_manifest_dir);
    println!("path: {:?}", refund_path);
    let _ = refund_file.write_to_file(refund_path);
    println!("RECOVERY: {:#?}", recovery);

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
    println!("timeoutBlockHeight: {}", response.get_timeout().unwrap());
    println!("nLocktime: {}", boltz_script_elements.timelock);
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

    let rev_swap_tx = LBtcSwapTx::new_claim(
        boltz_script_elements,
        RETURN_ADDRESS.to_string(),
        &network_config,
    )
    .unwrap();

    let signed_tx = rev_swap_tx
        .sign_claim(&keypair, &preimage, absolute_fees)
        .unwrap();
    let txid = rev_swap_tx.broadcast(signed_tx, &network_config).unwrap();
    println!("{}", txid);
}

#[test]
#[ignore]
fn test_recover_liquid_rsi() {
    const RETURN_ADDRESS: &str =
    "tlq1qqv4z28utgwunvn62s3aw0qjuw3sqgfdq6q8r8fesnawwnuctl70kdyedxw6tmxgqpq83x6ldsyr4n6cj0dm875k8g9k85w2s7";
    let recovery = &LBtcReverseRecovery {
        id: "aSdpTM".to_string(),
        preimage: "0d8b705906f96911e86962dae9c683bf520beb8d01031d60ee277a21f18b23c4".to_string(),
        claim_key: "aecbc2bddfcd3fa6953d257a9f369dc20cdc66f2605c73efb4c91b90703506b6".to_string(),
        blinding_key: "095272a241171abbf879e99e2b5cc4aa3e2d1c85cd5213a2aff0986b35b04786".to_string(),
        redeem_script: "8201208763a9142c03a91289ea61c1abc8cb98e1ced8cb4481387d882102ccbab5f97c89afb97d814831c5355ef5ba96a18c9dcd1b5c8cfd42c697bfe53c677503922b13b1752103f0f75e9b3d6748b8492a24a0be06b19a0e7629ba8451aae901cca4b0d87b97b768ac".to_string(),
    };
    let script: LBtcSwapScript = recovery.try_into().unwrap();
    let network_config = ElectrumConfig::default_liquid();
    println!("{:?}", script.fetch_utxo(&network_config));

    let tx =
        LBtcSwapTx::new_claim(script.clone(), RETURN_ADDRESS.to_string(), &network_config).unwrap();
    let _keypair: Keypair = recovery.try_into().unwrap();
    let _preimage: Preimage = recovery.try_into().unwrap();

    let signed_tx = tx.sign_claim(&_keypair, &_preimage, 1_000).unwrap();
    let txid = tx.broadcast(signed_tx, &network_config).unwrap();
    println!("{}", txid);
}
