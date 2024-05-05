use boltz_rust::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::{
        bitcoin::{BtcSwapScript, BtcSwapTx},
        boltz::{BoltzApiClient, CreateSwapRequest, SwapStatusRequest, BOLTZ_TESTNET_URL},
    },
    util::secrets::{BtcReverseRecovery, BtcSubmarineRecovery, Preimage, RefundSwapFile, SwapKey},
    Bolt11Invoice, Keypair, Secp256k1,
};

use std::{path::PathBuf, str::FromStr};
pub mod test_utils;

/// submarine swap integration
/// Always run this with --no-capture so you get all the data to recover (if needed)
/// Always update invoice before running

#[test]
#[ignore]
fn test_bitcoin_ssi() {
    let invoice_str = "lntb650u1pjut6cfpp5h7dgn6wghmsm8dfky9cjzrlyf5c2xaszk2lxamfqm2w4eurevpwqdq8d3skk6qxqyjw5qcqp2sp5nyk5mtwjf250uv0uf2l2trhyycefndu868dya04zlrvw5gvaev2srzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkf6vkyqq20gqqqqqqqqpqqqqqzsqqc9qyyssqva5tvj5gxfsdmc84hvreme8djgwj3rqr37kwtsa6qttgwzhe7s0yfy482afyje45ppualmatfwnmlmk2py7wc7l3l849jl7vdpa86aqqxmqmws";

    let invoice = Bolt11Invoice::from_str(invoice_str).unwrap();
    let out_amount = invoice.amount_milli_satoshis().unwrap() / 1000;
    // ensure the payment hash is the one boltz uses in their swap script
    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon".to_string();

    let keypair =
        SwapKey::from_submarine_account(&mnemonic.to_string(), "", Chain::BitcoinTestnet, 1)
            .unwrap()
            .keypair;
    println!(
        "****SECRETS****:\n sec: {:?}, pub: {:?}",
        keypair.display_secret(),
        keypair.public_key()
    );
    // SECRETS
    let network_config = ElectrumConfig::default_bitcoin();
    let _electrum_client = network_config.build_client().unwrap();

    // CHECK FEES AND LIMITS IN BOLTZ AND MAKE SURE USER CONFIRMS THIS FIRST
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_btc_pair = boltz_pairs.get_btc_pair().unwrap();
    let fees =
        boltz_btc_pair.fees.submarine_boltz(out_amount) + boltz_btc_pair.fees.submarine_claim();
    println!("TOTAL FEES: {}", fees);
    let request = CreateSwapRequest::new_btc_submarine(
        &boltz_btc_pair.hash,
        invoice_str,
        &keypair.public_key().to_string(),
    );
    let response = boltz_client.create_swap(request).unwrap();
    let preimage = Preimage::from_invoice_str(invoice_str).unwrap();

    println!("{:?}", response);

    let _id = response.get_id();
    let funding_amount = response.get_funding_amount().unwrap();
    let script = response
        .into_btc_sub_swap_script(&preimage, &keypair, network_config.network())
        .unwrap();
    let funding_address = script.to_address(network_config.network()).unwrap();

    let recovery =
        BtcSubmarineRecovery::new(&_id, &keypair, &response.get_redeem_script().unwrap());
    let refund_file: RefundSwapFile = recovery.clone().try_into().unwrap();
    let cargo_manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let refund_path = PathBuf::from(cargo_manifest_dir);
    println!("path: {:?}", refund_path);
    let _ = refund_file.write_to_file(refund_path);
    println!("RECOVERY: {:#?}", recovery);
    println!("*******FUND*********************");
    println!("*******SWAP*********************");
    println!("*******SCRIPT*******************");
    println!("{}", funding_address);
    println!("{}", funding_amount);

    println!("");
    println!("Once you have paid the address, the invoice will get paid after 1 conf.");
    println!("********************************");
}

/// reverse swap integration
/// Always run this with --no-capture so you get all the data to recover (if needed)
#[test]
#[ignore]
fn test_bitcoin_rsi() {
    const RETURN_ADDRESS: &str = "tb1qq20a7gqewc0un9mxxlqyqwn7ut7zjrj9y3d0mu";
    let out_amount = 50_000;
    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";

    let keypair = SwapKey::from_reverse_account(mnemonic, "", Chain::BitcoinTestnet, 1)
        .unwrap()
        .keypair;
    let preimage = Preimage::new();
    // SECRETS
    let network_config = ElectrumConfig::default_bitcoin();
    // CHECK FEES AND LIMITS IN BOLTZ AND MAKE SURE USER CONFIRMS THIS FIRST
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_btc_pair = boltz_pairs.get_btc_pair();
    let request = CreateSwapRequest::new_btc_reverse_invoice_amt(
        &boltz_btc_pair.unwrap().hash,
        &preimage.sha256.to_string(),
        &keypair.public_key().to_string(),
        out_amount,
    );
    let response = boltz_client.create_swap(request).unwrap();
    println!("{:?}", response);
    let id = response.get_id();
    let invoice = response.get_invoice().unwrap();
    let boltz_rev_script = response
        .into_btc_rev_swap_script(&preimage, &keypair, Chain::BitcoinTestnet)
        .unwrap();

    let script_balance = boltz_rev_script.get_balance(&network_config).unwrap();
    assert_eq!(script_balance.0, 0);
    assert_eq!(script_balance.1, 0);

    let recovery = BtcReverseRecovery::new(
        &id,
        &preimage,
        &keypair,
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
            let script_balance = boltz_rev_script.get_balance(&network_config).unwrap();
            println!(
                "confirmed: {}, unconfirmed: {}",
                script_balance.0, script_balance.1
            );
            test_utils::pause_and_wait(
                "!!!!!WE ARE ABOUT TO BREAK: if tx is not shown above, just hang on a moment!!!!!",
            );
            break;
        }
    }

    let absolute_fees = 300;
    let rv_claim_tx = BtcSwapTx::new_claim(
        boltz_rev_script,
        RETURN_ADDRESS.to_string(),
        &network_config,
    )
    .unwrap()
    .unwrap();
    let signed_tx = rv_claim_tx
        .sign_claim(&keypair, &preimage, absolute_fees)
        .unwrap();
    let txid = rv_claim_tx.broadcast(signed_tx, &network_config).unwrap();
    println!("{}", txid);
}

use boltz_client::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::{
        bitcoin::{BtcSwapScript, BtcSwapTx},
        boltz::{BoltzApiClient, CreateSwapRequest, SwapStatusRequest, BOLTZ_TESTNET_URL},
    },
    util::secrets::{BtcReverseRecovery, BtcSubmarineRecovery, Preimage, RefundSwapFile, SwapKey},
    Bolt11Invoice, Keypair, Secp256k1,
};

use std::{path::PathBuf, str::FromStr};
pub mod test_utils;

/// submarine swap integration
/// Always run this with --no-capture so you get all the data to recover (if needed)
/// Always update invoice before running

#[test]
#[ignore]
fn test_bitcoin_ssi() {
    let invoice_str = "lntb650u1pjut6cfpp5h7dgn6wghmsm8dfky9cjzrlyf5c2xaszk2lxamfqm2w4eurevpwqdq8d3skk6qxqyjw5qcqp2sp5nyk5mtwjf250uv0uf2l2trhyycefndu868dya04zlrvw5gvaev2srzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkf6vkyqq20gqqqqqqqqpqqqqqzsqqc9qyyssqva5tvj5gxfsdmc84hvreme8djgwj3rqr37kwtsa6qttgwzhe7s0yfy482afyje45ppualmatfwnmlmk2py7wc7l3l849jl7vdpa86aqqxmqmws";

    let invoice = Bolt11Invoice::from_str(invoice_str).unwrap();
    let out_amount = invoice.amount_milli_satoshis().unwrap() / 1000;
    // ensure the payment hash is the one boltz uses in their swap script
    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon".to_string();

    let keypair =
        SwapKey::from_submarine_account(&mnemonic.to_string(), "", Chain::BitcoinTestnet, 1)
            .unwrap()
            .keypair;
    println!(
        "****SECRETS****:\n sec: {:?}, pub: {:?}",
        keypair.display_secret(),
        keypair.public_key()
    );
    // SECRETS
    let network_config = ElectrumConfig::default_bitcoin();
    let _electrum_client = network_config.build_client().unwrap();

    // CHECK FEES AND LIMITS IN BOLTZ AND MAKE SURE USER CONFIRMS THIS FIRST
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_btc_pair = boltz_pairs.get_btc_pair().unwrap();
    let fees =
        boltz_btc_pair.fees.submarine_boltz(out_amount) + boltz_btc_pair.fees.submarine_claim();
    println!("TOTAL FEES: {}", fees);
    let request = CreateSwapRequest::new_btc_submarine(
        &boltz_btc_pair.hash,
        invoice_str,
        &keypair.public_key().to_string(),
    );
    let response = boltz_client.create_swap(request).unwrap();
    let preimage = Preimage::from_invoice_str(invoice_str).unwrap();

    println!("{:?}", response);

    let _id = response.get_id();
    let funding_amount = response.get_funding_amount().unwrap();
    let script = response
        .into_btc_sub_swap_script(&preimage, &keypair, network_config.network())
        .unwrap();
    let funding_address = script.to_address(network_config.network()).unwrap();

    let recovery =
        BtcSubmarineRecovery::new(&_id, &keypair, &response.get_redeem_script().unwrap());
    let refund_file: RefundSwapFile = recovery.clone().try_into().unwrap();
    let cargo_manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let refund_path = PathBuf::from(cargo_manifest_dir);
    println!("path: {:?}", refund_path);
    let _ = refund_file.write_to_file(refund_path);
    println!("RECOVERY: {:#?}", recovery);
    println!("*******FUND*********************");
    println!("*******SWAP*********************");
    println!("*******SCRIPT*******************");
    println!("{}", funding_address);
    println!("{}", funding_amount);

    println!("");
    println!("Once you have paid the address, the invoice will get paid after 1 conf.");
    println!("********************************");
}

/// reverse swap integration
/// Always run this with --no-capture so you get all the data to recover (if needed)
#[test]
#[ignore]
fn test_bitcoin_rsi() {
    const RETURN_ADDRESS: &str = "tb1qq20a7gqewc0un9mxxlqyqwn7ut7zjrj9y3d0mu";
    let out_amount = 50_000;
    // SECRETS
    let mnemonic = "bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon bacon";

    let keypair = SwapKey::from_reverse_account(mnemonic, "", Chain::BitcoinTestnet, 1)
        .unwrap()
        .keypair;
    let preimage = Preimage::new();
    // SECRETS
    let network_config = ElectrumConfig::default_bitcoin();
    // CHECK FEES AND LIMITS IN BOLTZ AND MAKE SURE USER CONFIRMS THIS FIRST
    let boltz_client = BoltzApiClient::new(BOLTZ_TESTNET_URL);
    let boltz_pairs = boltz_client.get_pairs().unwrap();
    let boltz_btc_pair = boltz_pairs.get_btc_pair();
    let request = CreateSwapRequest::new_btc_reverse_invoice_amt(
        &boltz_btc_pair.unwrap().hash,
        &preimage.sha256.to_string(),
        &keypair.public_key().to_string(),
        out_amount,
    );
    let response = boltz_client.create_swap(request).unwrap();
    println!("{:?}", response);
    let id = response.get_id();
    let invoice = response.get_invoice().unwrap();
    let boltz_rev_script = response
        .into_btc_rev_swap_script(&preimage, &keypair, Chain::BitcoinTestnet)
        .unwrap();

    let script_balance = boltz_rev_script.get_balance(&network_config).unwrap();
    assert_eq!(script_balance.0, 0);
    assert_eq!(script_balance.1, 0);

    let recovery = BtcReverseRecovery::new(
        &id,
        &preimage,
        &keypair,
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
            let script_balance = boltz_rev_script.get_balance(&network_config).unwrap();
            println!(
                "confirmed: {}, unconfirmed: {}",
                script_balance.0, script_balance.1
            );
            test_utils::pause_and_wait(
                "!!!!!WE ARE ABOUT TO BREAK: if tx is not shown above, just hang on a moment!!!!!",
            );
            break;
        }
    }

    let absolute_fees = 300;
    let rv_claim_tx = BtcSwapTx::new_claim(
        boltz_rev_script,
        RETURN_ADDRESS.to_string(),
        &network_config,
    )
    .unwrap();
    let signed_tx = rv_claim_tx
        .sign_claim(&keypair, &preimage, absolute_fees)
        .unwrap();
    let txid = rv_claim_tx.broadcast(signed_tx, &network_config).unwrap();
    println!("{}", txid);
}

/// Use this test to recover from a failed swap from the main rsi test
/// You will need to update the values of preimage, redeem script and invoice
/// You will get these values in the log of the main rsi function
#[test]
#[ignore]
fn test_recover_bitcoin_rsi() {
    let secp = Secp256k1::new();
    const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
    let _out_amount = 50_000;
    let keypair = Keypair::from_seckey_str(
        &secp,
        "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1",
    )
    .unwrap();

    let preimage =
        Preimage::from_str("898396fe53c58375cf8a5a8cfead2a285dc4b5b84cd149800914fc60c9f3a70b")
            .unwrap();

    let redeem_script = "8201208763a9143b2b7485171679c84f6540a8b907c2c830e9a60b88210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775030bce26b1752103778dc69769e3cbdd9091d05a5e027ebc1919675d0725d2c1f2259f821a3e6a2668ac".to_string();

    let invoice = "lntb505590n1pjhcajmsp5fhmrf08upk8cshg7k3rp3v2hchckh7q9lgx3h94mzeld0v3wh65qpp525c4hyrnc7sztcwedfkmns0x5jacsea66h367mwulufw86yc4waqdql2djkuepqw3hjqsj5gvsxzerywfjhxucxqyp2xqcqzyl9qxpqysgqm4xhsuspj73qr207ppr5ujqtn4g0zdh24p3kynx3kzuc8nwh4qey4m4havn4fh2q5chun7afp75hq7stztjswxz03wxd2wmdp3vxlcspexpdmy";

    let invoice = Bolt11Invoice::from_str(invoice).unwrap();
    assert_eq!(
        invoice.payment_hash().to_string(),
        preimage.sha256.to_string()
    );

    let absolute_fees = 1_200;
    let network_config = ElectrumConfig::default_bitcoin();

    let rev_swap_tx = BtcSwapTx::new_claim(
        BtcSwapScript::reverse_from_str(&redeem_script).unwrap(),
        RETURN_ADDRESS.to_string(),
        &network_config,
    )
    .unwrap();

    let signed_tx = rev_swap_tx.sign_refund(&keypair, absolute_fees).unwrap();
    let txid = rev_swap_tx.broadcast(signed_tx, &network_config).unwrap();
    println!("{}", txid);
}
