#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[cfg(feature = "electrum")]
use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
#[cfg(feature = "esplora")]
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::{
    network::Chain,
    swaps::{
        boltz::{BoltzApiClientV2, Cooperative, CreateReverseRequest, CreateSubmarineRequest},
        magic_routing::{check_for_mrh, sign_address},
        wrappers::{SwapScript, SwapTx},
    },
    util::{secrets::Preimage, setup_logger},
    BtcSwapScript, BtcSwapTx, Secp256k1,
};
use std::sync::Arc;

use crate::regtest::WAIT_TIME_MS;
use crate::utils;
use bitcoin::{key::rand::thread_rng, secp256k1::Keypair, PublicKey};
use boltz_client::boltz::{BoltzWsConfig, BOLTZ_REGTEST};
use boltz_client::fees::Fee;
use boltz_client::network::esplora::async_sleep;
use boltz_client::network::{BitcoinChain, BitcoinClient, LiquidChain};
use serial_test::serial;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const CHAIN: BitcoinChain = BitcoinChain::BitcoinRegtest;
const LIQUID_CHAIN: LiquidChain = LiquidChain::LiquidRegtest;

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_v2_submarine_electrum() {
    setup_logger();
    let client = Client::new().with_bitcoin(ElectrumBitcoinClient::default(CHAIN, None).unwrap());
    bitcoin_v2_submarine(&client, false, Chain::Bitcoin(CHAIN)).await;
    bitcoin_v2_submarine(&client, true, Chain::Bitcoin(CHAIN)).await;
}
use boltz_client::swaps::wrappers::Client;

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_submarine_esplora() {
    setup_logger();
    let client = Client::new().with_bitcoin(EsploraBitcoinClient::default(CHAIN, None));
    bitcoin_v2_submarine(&client, false, Chain::Bitcoin(CHAIN)).await;
    bitcoin_v2_submarine(&client, true, Chain::Bitcoin(CHAIN)).await;
}

async fn bitcoin_v2_submarine(client: &Client, underpay: bool, chain: Chain) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());

    let refund_public_key = PublicKey {
        inner: our_keys.public_key(),
        compressed: true,
    };

    // Set a new invoice string and refund address for each test.
    let invoice = utils::generate_invoice_lnd(50_000).await.unwrap();
    let refund_address = match chain {
        Chain::Bitcoin(_) => utils::generate_address_bitcoind().await.unwrap(),
        Chain::Liquid(_) => utils::generate_address_elementsd().await.unwrap(),
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST);
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    ws_api.clone().start();

    // If there is MRH send directly to that address
    //    let (bip21_addrs, amount) =
    //         check_for_mrh(&boltz_api_v2, &invoice, chain).unwrap();
    //         log::info!("Found MRH in invoice");
    //         log::info!("Send {} to {}", amount, bip21_addrs);
    //         return;

    // Initiate the swap with Boltz
    let create_swap_req = CreateSubmarineRequest {
        from: match chain {
            Chain::Bitcoin(_) => "BTC".to_string(),
            Chain::Liquid(_) => "L-BTC".to_string(),
        },
        to: "BTC".to_string(),
        invoice: invoice.to_string(),
        refund_public_key,
        pair_hash: None,
        referral_id: None,
        webhook: None,
    };

    let create_swap_response = boltz_api_v2.post_swap_req(&create_swap_req).await.unwrap();

    log::info!("Got Swap Response from Boltz server");

    log::debug!("Swap Response: {:?}", create_swap_response);

    let swap_script =
        SwapScript::submarine_from_swap_resp(chain, &create_swap_response, refund_public_key)
            .unwrap();
    let swap_id = create_swap_response.id.clone();
    log::debug!("Created Swap Script. : {:?}", swap_script);

    ws_api.subscribe(&swap_id).await.unwrap();
    // Event handlers for various swap status.
    let mut rx = ws_api.updates();
    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "invoice.set" => {
                log::info!(
                    "Send {} sats to {} address {}",
                    create_swap_response.expected_amount,
                    match chain {
                        Chain::Bitcoin(_) => "BTC",
                        Chain::Liquid(_) => "L-BTC",
                    },
                    create_swap_response.address
                );

                let amount = match underpay {
                    true => create_swap_response.expected_amount - 1,
                    false => create_swap_response.expected_amount,
                };
                match chain {
                    Chain::Bitcoin(_) => {
                        utils::send_to_address_bitcoind(&create_swap_response.address, amount)
                            .await
                            .unwrap();
                    }
                    Chain::Liquid(_) => {
                        utils::send_to_address_elementsd(&create_swap_response.address, amount)
                            .await
                            .unwrap();
                    }
                }
            }
            "transaction.mempool" => {
                utils::mine_blocks(1).await.unwrap();
            }
            "transaction.claim.pending" => {
                let response = swap_script
                    .submarine_cooperative_claim(
                        &swap_id,
                        &our_keys,
                        &create_swap_req.invoice,
                        &boltz_api_v2,
                    )
                    .await
                    .unwrap();
                log::debug!("Received claim tx details : {:?}", response);
            }

            "transaction.claimed" => {
                log::info!("Successfully completed submarine swap");
                break;
            }

            // This means the funding transaction was rejected by Boltz for whatever reason, and we need to get
            // the funds back via refund.
            "transaction.lockupFailed" | "invoice.failedToPay" => {
                async_sleep(WAIT_TIME_MS).await;
                let swap_tx = SwapTx::new_refund(
                    swap_script.clone(),
                    &refund_address,
                    client,
                    BOLTZ_REGTEST.to_owned(),
                    swap_id.to_owned(),
                )
                .await
                .expect("Funding UTXO not found");

                let tx = swap_tx
                    .sign_refund(
                        &our_keys,
                        Fee::Absolute(1000),
                        Some(Cooperative {
                            boltz_api: &boltz_api_v2,
                            swap_id: swap_id.clone(),
                            pub_nonce: None,
                            partial_sig: None,
                        }),
                        false,
                    )
                    .await
                    .unwrap();

                let txid = swap_tx.broadcast(&tx, client).await.unwrap();
                log::info!("Cooperative Refund Successfully broadcasted: {}", txid);

                // Non cooperative refund requires expired swap
                /*log::info!("Cooperative refund failed. {:?}", e);
                log::info!("Attempting Non-cooperative refund.");

                let tx = swap_tx
                    .sign_refund(&our_keys, Fee::Absolute(1000), None)
                    .await
                    .unwrap();
                let txid = swap_tx
                    .broadcast(&tx, bitcoin_client)
                    .await
                    .unwrap();
                log::info!("Non-cooperative Refund Successfully broadcasted: {}", txid);*/
                break;
            }
            _ => {
                log::info!("Got Update from server: {}", update.status);
            }
        };
    }
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_v2_reverse_electrum() {
    setup_logger();
    let bitcoin_client = ElectrumBitcoinClient::default(CHAIN, None).unwrap();
    bitcoin_v2_reverse(bitcoin_client).await
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_reverse_esplora() {
    setup_logger();
    let bitcoin_client = EsploraBitcoinClient::default(CHAIN, None);
    bitcoin_v2_reverse(bitcoin_client).await
}

async fn bitcoin_v2_reverse<BC: BitcoinClient>(bitcoin_client: BC) {
    let secp = Secp256k1::new();
    let preimage = Preimage::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());
    let invoice_amount = 100000;
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_keys.public_key(),
    };

    // Give a valid claim address or else funds will be lost.
    let claim_address = utils::generate_address_bitcoind().await.unwrap();

    let addrs_sig = sign_address(&claim_address, &our_keys).unwrap();
    let create_reverse_req = CreateReverseRequest {
        invoice_amount,
        from: "BTC".to_string(),
        to: "BTC".to_string(),
        preimage_hash: preimage.sha256,
        description: None,
        description_hash: None,
        address_signature: Some(addrs_sig.to_string()),
        address: Some(claim_address.clone()),
        claim_public_key,
        referral_id: None, // Add address signature here.
        webhook: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST);
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    ws_api.clone().start();

    let reverse_resp = boltz_api_v2
        .post_reverse_req(create_reverse_req)
        .await
        .unwrap();

    let _ = check_for_mrh(&boltz_api_v2, &reverse_resp.invoice, Chain::Bitcoin(CHAIN))
        .await
        .unwrap()
        .unwrap();

    log::debug!("Got Reverse swap response: {:?}", reverse_resp);

    let swap_script =
        BtcSwapScript::reverse_from_swap_resp(&reverse_resp, claim_public_key).unwrap();
    let swap_id = reverse_resp.id.clone();

    ws_api.subscribe(&swap_id).await.unwrap();
    let mut rx = ws_api.updates();

    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "swap.created" => {
                log::info!("Waiting for Invoice to be paid: {}", &reverse_resp.invoice);

                let invoice = reverse_resp.invoice.clone();
                utils::start_pay_invoice_lnd(invoice);

                continue;
            }

            "transaction.mempool" => {
                log::info!("Boltz broadcasted funding tx");

                async_sleep(WAIT_TIME_MS).await;

                let claim_tx = BtcSwapTx::new_claim(
                    swap_script.clone(),
                    claim_address.clone(),
                    &bitcoin_client,
                    BOLTZ_REGTEST.to_owned(),
                    swap_id.clone(),
                )
                .await
                .expect("Funding tx expected");

                let tx = claim_tx
                    .sign_claim(
                        &our_keys,
                        &preimage,
                        Fee::Absolute(1000),
                        Some(Cooperative {
                            boltz_api: &boltz_api_v2,
                            swap_id: swap_id.clone(),
                            pub_nonce: None,
                            partial_sig: None,
                        }),
                    )
                    .await
                    .unwrap();

                claim_tx.broadcast(&tx, &bitcoin_client).await.unwrap();

                log::info!("Successfully broadcasted claim tx!");
                log::debug!("Claim Tx {:?}", tx);
            }

            "invoice.settled" => {
                log::info!("Reverse Swap Successful!");
                break;
            }
            _ => {
                log::info!("Got Update from server: {}", update.status);
            }
        }
    }
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_v2_reverse_script_path_electrum() {
    setup_logger();
    let bitcoin_client = ElectrumBitcoinClient::default(CHAIN, None).unwrap();
    bitcoin_v2_reverse_script_path(bitcoin_client).await
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_reverse_script_path_esplora() {
    setup_logger();
    let bitcoin_client = EsploraBitcoinClient::default(CHAIN, None);
    bitcoin_v2_reverse_script_path(bitcoin_client).await
}

async fn bitcoin_v2_reverse_script_path<BC: BitcoinClient>(bitcoin_client: BC) {
    let secp = Secp256k1::new();
    let preimage = Preimage::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());
    let invoice_amount = 100000;
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_keys.public_key(),
    };

    // Give a valid claim address or else funds will be lost.
    let claim_address = utils::generate_address_bitcoind().await.unwrap();

    let addrs_sig = sign_address(&claim_address, &our_keys).unwrap();
    let create_reverse_req = CreateReverseRequest {
        invoice_amount,
        from: "BTC".to_string(),
        to: "BTC".to_string(),
        preimage_hash: preimage.sha256,
        description: None,
        description_hash: None,
        address_signature: Some(addrs_sig.to_string()),
        address: Some(claim_address.clone()),
        claim_public_key,
        referral_id: None, // Add address signature here.
        webhook: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST);
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    ws_api.clone().start();

    let reverse_resp = boltz_api_v2
        .post_reverse_req(create_reverse_req)
        .await
        .unwrap();
    let swap_id = reverse_resp.id.clone();
    let _ = check_for_mrh(&boltz_api_v2, &reverse_resp.invoice, Chain::Bitcoin(CHAIN))
        .await
        .unwrap()
        .unwrap();

    log::debug!("Got Reverse swap response: {:?}", reverse_resp);

    let swap_script =
        BtcSwapScript::reverse_from_swap_resp(&reverse_resp, claim_public_key).unwrap();

    ws_api.subscribe(&swap_id).await.unwrap();
    let mut rx = ws_api.updates();

    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "swap.created" => {
                log::info!("Waiting for Invoice to be paid: {}", &reverse_resp.invoice);

                let invoice = reverse_resp.invoice.clone();
                utils::start_pay_invoice_lnd(invoice);

                continue;
            }

            "transaction.mempool" => {
                log::info!("Boltz broadcasted funding tx");

                async_sleep(WAIT_TIME_MS).await;

                let claim_tx = BtcSwapTx::new_claim(
                    swap_script.clone(),
                    claim_address.clone(),
                    &bitcoin_client,
                    BOLTZ_REGTEST.to_owned(),
                    swap_id.clone(),
                )
                .await
                .expect("Funding tx expected");

                let tx = claim_tx
                    .sign_claim(&our_keys, &preimage, Fee::Absolute(1000), None)
                    .await
                    .unwrap();

                claim_tx.broadcast(&tx, &bitcoin_client).await.unwrap();

                log::info!("Successfully broadcasted claim tx!");
                log::debug!("Claim Tx {:?}", tx);
            }

            "invoice.settled" => {
                log::info!("Reverse Swap Successful!");
                break;
            }
            _ => {
                log::info!("Got Update from server: {}", update.status);
            }
        }
    }
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_v2_submarine_electrum() {
    setup_logger();
    let client = Client::new().with_liquid(ElectrumLiquidClient::default(LIQUID_CHAIN, None).unwrap());
    bitcoin_v2_submarine(&client, false, Chain::Liquid(LIQUID_CHAIN)).await;
    bitcoin_v2_submarine(&client, true, Chain::Liquid(LIQUID_CHAIN)).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_v2_submarine_esplora() {
    setup_logger();
    let client = Client::new().with_liquid(EsploraLiquidClient::default(LIQUID_CHAIN, None));
    bitcoin_v2_submarine(&client, false, Chain::Liquid(LIQUID_CHAIN)).await;
    bitcoin_v2_submarine(&client, true, Chain::Liquid(LIQUID_CHAIN)).await;
}
