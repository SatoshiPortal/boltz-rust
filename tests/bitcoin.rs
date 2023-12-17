// mod bullbitcoin_rnd;
// extern crate libbullwallet;

use bitcoin::{Address, Network};
use boltzclient::{
    key::{ec::KeyPairString, preimage::Preimage},
    network::electrum::{BitcoinNetwork, NetworkConfig, DEFAULT_TESTNET_NODE},
    swaps::{
        bitcoin::script::BtcRevScriptElements,
        bitcoin::{script::BtcSubScriptElements, tx::BtcRevTxElements},
        boltz::{BoltzApiClient, CreateSwapRequest, SwapStatusRequest, BOLTZ_TESTNET_URL},
    },
    util::pause_and_wait,
};
use dotenv::dotenv;
use electrum_client::ElectrumApi;
use lightning_invoice::Bolt11Invoice;

use std::{env, str::FromStr};

/// submarine swap integration
/// Always run this with --no-capture so you get all the data to recover (if needed)

#[test]
#[ignore]
fn test_bitcoin_ssi() {
    let invoice = "lntb500n1pjhevffpp5pkjxerpae05qve5c3azajfguqx36sejefupjzx9hhm287azg0f0sdqydehqxqyjw5qcqp2sp5gqzmltv6t289gghd5a6tp3avndzmta39ynm8za23lkcyzfpuv89srzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkfkdwyqqq4sqqyqqqqqpqqqqqzsqqc9qyyssqjnfmhvgafmjrkct0rmwj9mxj6gsjv9uwqv7853mf3n78vmv0uwh85ahr0et4dkalcsmh4crqsundjv0wqdntlcefeg4cnfj0dtjqz0gqqdh5lm";
    // ensure the payment hash is the one boltz uses in their swap script

    let _out_amount = 50_000;

    dotenv().ok();
    // SECRETS
    let mnemonic = match env::var("MNEMONIC") {
        Ok(result) => result,
        Err(e) => panic!("Couldn't read MNEMONIC ({})", e),
    };
    let keypair = KeyPairString::from_mnemonic(mnemonic, "".to_string());
    println!("****SECRETS****:{:?}", keypair);
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
        .get("BTC/BTC")
        .map(|pair_info| pair_info.hash.clone())
        .unwrap();

    let request = CreateSwapRequest::new_btc_submarine(
        pair_hash,
        invoice.to_string(),
        keypair.pubkey.clone(),
    );
    let response = boltz_client.create_swap(request);
    assert!(response.is_ok());

    let _timeout = response
        .as_ref()
        .unwrap()
        .timeout_block_height
        .unwrap()
        .clone();
    let _id = response.as_ref().unwrap().id.as_str();
    let funding_address = response.as_ref().unwrap().address.clone().unwrap();
    let redeem_script_string = response
        .as_ref()
        .unwrap()
        .redeem_script
        .as_ref()
        .unwrap()
        .clone();

    let boltz_script_elements = BtcSubScriptElements::from_str(&redeem_script_string).unwrap();

    // let constructed_script_elements = OnchainSwapScriptElements::new(
    //     preimage.hash160.to_string(),
    //     keypair.pubkey.clone(),
    //     timeout as u32,
    //     boltz_script_elements.sender_pubkey.clone(),
    // );

    println!("{:?}", boltz_script_elements);

    // assert_eq!(
    //     lockup_address,
    //     Address::p2wsh(&constructed_script_elements.to_script(), Network::Testnet).to_string()
    // );

    println!("*******FUND*********************");
    println!("*******SWAP*********************");
    println!("*******SCRIPT*******************");
    println!("{}", funding_address);
    println!("");
    println!("Once you have paid the address, the invoice will get paid after 1 conf.");
    println!("********************************");
}

/// reverse swap integration
/// Always run this with --no-capture so you get all the data to recover (if needed)
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
    println!("****SECRETS****:{:?}", keypair);
    let preimage = Preimage::new();
    println!("****SECRETS****:{:?}", preimage.clone());
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
    // println!("{:?}", response);
    assert!(response.is_ok());
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

    let boltz_script_elements = BtcRevScriptElements::from_str(&redeem_script_string).unwrap();

    let constructed_script_elements = BtcRevScriptElements::new(
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
        pause_and_wait("Continue will check swap status and act accordingly");
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
            let script_balance = electrum_client
                .script_get_balance(&constructed_script_elements.to_script().to_v0_p2wsh())
                .unwrap();
            println!("{:?}", script_balance);
            pause_and_wait(
                "!!!!!WE ARE ABOUT TO BREAK: if tx is not shown above, just hang on a moment!!!!!",
            );
            break;
        }
    }
    let absolute_fees = 300;
    let mut swap_tx_elements = BtcRevTxElements::new_claim(
        Network::Testnet,
        RETURN_ADDRESS.to_string(),
        absolute_fees,
        redeem_script_string,
    );
    swap_tx_elements.fetch_utxo(DEFAULT_TESTNET_NODE.to_string(), out_amount);
    let signed_tx = swap_tx_elements.drain_tx(keypair, preimage).unwrap();
    let txid = electrum_client.transaction_broadcast(&signed_tx).unwrap();
    println!("{}", txid);
}

/// Use this test to recover from a failed swap from the main rsi test
/// You will need to update the values of preimage, redeem script and invoice
/// You will get these values in the log of the main rsi function
#[test]
#[ignore]
fn test_recover_bitcoin_rsi() {
    const RETURN_ADDRESS: &str = "tb1qw2c3lxufxqe2x9s4rdzh65tpf4d7fssjgh8nv6";
    let out_amount = 50_000;
    let keypair = KeyPairString {
        seckey: "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1".to_string(),
        pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986".to_string(),
    };
    let preimage =
        Preimage::from_str("898396fe53c58375cf8a5a8cfead2a285dc4b5b84cd149800914fc60c9f3a70b");

    let redeem_script = "8201208763a9143b2b7485171679c84f6540a8b907c2c830e9a60b88210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775030bce26b1752103778dc69769e3cbdd9091d05a5e027ebc1919675d0725d2c1f2259f821a3e6a2668ac".to_string();

    let invoice = "lntb505590n1pjhcajmsp5fhmrf08upk8cshg7k3rp3v2hchckh7q9lgx3h94mzeld0v3wh65qpp525c4hyrnc7sztcwedfkmns0x5jacsea66h367mwulufw86yc4waqdql2djkuepqw3hjqsj5gvsxzerywfjhxucxqyp2xqcqzyl9qxpqysgqm4xhsuspj73qr207ppr5ujqtn4g0zdh24p3kynx3kzuc8nwh4qey4m4havn4fh2q5chun7afp75hq7stztjswxz03wxd2wmdp3vxlcspexpdmy";

    let invoice = Bolt11Invoice::from_str(invoice).unwrap();
    assert_eq!(invoice.payment_hash().to_string(), preimage.sha256);

    let absolute_fees = 300;

    let network_config = NetworkConfig::default().unwrap();
    let electrum_client = network_config.electrum_url.build_client().unwrap();
    let mut swap_tx_elements = BtcRevTxElements::new_claim(
        Network::Testnet,
        RETURN_ADDRESS.to_string(),
        absolute_fees,
        redeem_script,
    );

    swap_tx_elements.fetch_utxo(DEFAULT_TESTNET_NODE.to_string(), out_amount);
    let signed_tx = swap_tx_elements.drain_tx(keypair, preimage).unwrap();
    let txid = electrum_client.transaction_broadcast(&signed_tx).unwrap();
    println!("{}", txid);
}
/*

EXAMPLE LOG OF test_bitcoin_rsi

KeyPairString { seckey: "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1", pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986" }
{"info":[],"warnings":[],"pairs":{"BTC/BTC":{"hash":"a3a295202ab0b65cc9597b82663dbcdc77076e138f6d97285711ab7df086afd5","rate":1,"limits":{"maximal":25000000,"minimal":50000,"maximalZeroConf":{"baseAsset":0,"quoteAsset":0}},"fees":{"percentage":0.5,"percentageSwapIn":0.1,"minerFees":{"baseAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}},"L-BTC/BTC":{"hash":"04df6e4b5a91d62a4e1a7ecb88ca462851d835c4bae955a6c5baad8e047b14e9","rate":1,"limits":{"maximal":25000000,"minimal":1000,"maximalZeroConf":{"baseAsset":100000,"quoteAsset":0}},"fees":{"percentage":0.25,"percentageSwapIn":0.1,"minerFees":{"baseAsset":{"normal":147,"reverse":{"claim":152,"lockup":276}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}},"RBTC/BTC":{"hash":"17acb1892ddaaaf60bf44a6e88a86405922d44f29265cc2ebe9f0f137277aa24","rate":1,"limits":{"maximal":4294967,"minimal":10000,"maximalZeroConf":{"baseAsset":0,"quoteAsset":0}},"fees":{"percentage":0.5,"percentageSwapIn":0.5,"minerFees":{"baseAsset":{"normal":162,"reverse":{"claim":162,"lockup":302}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}}}}
{"id":"cUFgeM","invoice":"lntb505590n1pjhce75sp58jvctm5flwssredt3u77u8zsz5qtysz4us9ach02qx8ch3dqhlsqpp5j04mmaqv3p3yp9ptkdf2nhg86vgd85sm3qu7h3y9r9qprldhm8tsdql2djkuepqw3hjqsj5gvsxzerywfjhxucxqyp2xqcqzyl9qxpqysgq5hffhua6y33fnkcqrw2dssedyh0uze2yg0mztft0sd4zymdc36ejs7am9n8rjfa6ucde5vw6ummvncmss0pmlmfseg5pts7pzf0hnusp7pprfz","redeemScript":"8201208763a914721149994da9e510ba44f150434898acfb36ee6888210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c545898667750306ce26b175210355de825f6d2fbe18eb5edab40ea5b85aff847b130a07e3cd7245605ad0cf083f68ac","lockupAddress":"tb1qnvw3a9uzhaa2em84aekrdpurhkjhhaz3lt2r5r9nkg5kv8zhnnpqwqx8tw","timeoutBlockHeight":2543110}
Preimage { preimage: "8f89ae106d56f9d56fcb75a98499c7f8386223ca5d6f0c9f866b08387c2ca624", sha256: "93ebbdf40c886240942bb352a9dd07d310d3d21b8839ebc485194011fdb7d9d7", hash160: "721149994da9e510ba44f150434898acfb36ee68", preimage_bytes: [143, 137, 174, 16, 109, 86, 249, 213, 111, 203, 117, 169, 132, 153, 199, 248, 56, 98, 35, 202, 93, 111, 12, 159, 134, 107, 8, 56, 124, 44, 166, 36], sha256_bytes: [147, 235, 189, 244, 12, 136, 98, 64, 148, 43, 179, 82, 169, 221, 7, 211, 16, 211, 210, 27, 136, 57, 235, 196, 133, 25, 64, 17, 253, 183, 217, 215], hash160_bytes: [114, 17, 73, 153, 77, 169, 229, 16, 186, 68, 241, 80, 67, 72, 152, 172, 251, 54, 238, 104] }
8201208763a914721149994da9e510ba44f150434898acfb36ee6888210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c545898667750306ce26b175210355de825f6d2fbe18eb5edab40ea5b85aff847b130a07e3cd7245605ad0cf083f68ac
tb1qnvw3a9uzhaa2em84aekrdpurhkjhhaz3lt2r5r9nkg5kv8zhnnpqwqx8tw
*******PAY********************
*******LN*********************
*******INVOICE****************
lntb505590n1pjhce75sp58jvctm5flwssredt3u77u8zsz5qtysz4us9ach02qx8ch3dqhlsqpp5j04mmaqv3p3yp9ptkdf2nhg86vgd85sm3qu7h3y9r9qprldhm8tsdql2djkuepqw3hjqsj5gvsxzerywfjhxucxqyp2xqcqzyl9qxpqysgq5hffhua6y33fnkcqrw2dssedyh0uze2yg0mztft0sd4zymdc36ejs7am9n8rjfa6ucde5vw6ummvncmss0pmlmfseg5pts7pzf0hnusp7pprfz



*/