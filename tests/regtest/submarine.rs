#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[cfg(feature = "electrum")]
use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
#[cfg(feature = "esplora")]
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::{
    network::Chain,
    swaps::{
        boltz::{BoltzApiClientV2, CreateSubmarineRequest},
        Client, SwapScript, SwapTransactionParams,
    },
    util::{setup_logger, sleep},
};
use std::sync::Arc;

use crate::regtest::WAIT_TIME;
use crate::utils;
use bitcoin::{key::rand::thread_rng, secp256k1::Keypair, PublicKey};
use boltz_client::boltz::{BoltzWsConfig, BOLTZ_REGTEST};
use boltz_client::fees::Fee;
use boltz_client::network::{BitcoinChain, LiquidChain};
use serial_test::serial;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const BTC_CHAIN: BitcoinChain = BitcoinChain::BitcoinRegtest;
const LIQUID_CHAIN: LiquidChain = LiquidChain::LiquidRegtest;

async fn v2_submarine(client: &Client, underpay: bool, chain: Chain) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());

    let refund_public_key = PublicKey {
        inner: our_keys.public_key(),
        compressed: true,
    };

    // Set a new invoice string and refund address for each test.
    let invoice = utils::generate_invoice_lnd(50_000).await.unwrap();
    let refund_address = utils::generate_address(chain).await.unwrap();

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());

    // If there is MRH send directly to that address
    //    let (bip21_addrs, amount) =
    //         check_for_mrh(&boltz_api_v2, &invoice, chain).unwrap();
    //         log::info!("Found MRH in invoice");
    //         log::info!("Send {} to {}", amount, bip21_addrs);
    //         return;

    // Initiate the swap with Boltz
    let create_swap_req = CreateSubmarineRequest {
        from: chain.symbol().to_string(),
        to: "BTC".to_string(),
        invoice: invoice.to_string(),
        refund_public_key,
        pair_hash: None,
        referral_id: None,
        webhook: None,
    };

    let create_swap_response = boltz_api_v2.post_swap_req(&create_swap_req).await.unwrap();

    log::info!("Got Swap Response from Boltz server");

    create_swap_response
        .validate(&invoice, &refund_public_key, chain)
        .unwrap();
    log::info!("VALIDATED RESPONSE!");

    log::debug!("Swap Response: {create_swap_response:?}");

    let swap_script =
        SwapScript::submarine_from_swap_resp(chain, &create_swap_response, refund_public_key)
            .unwrap();
    let swap_id = create_swap_response.id.clone();
    log::debug!("Created Swap Script. : {swap_script:?}");

    let mut rx = ws_api.updates();
    ws_api.subscribe(&swap_id).await.unwrap();
    // Event handlers for various swap status.
    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "invoice.set" => {
                log::info!(
                    "Send {} sats to {} address {}",
                    create_swap_response.expected_amount,
                    chain.symbol(),
                    create_swap_response.address
                );

                let amount = match underpay {
                    true => create_swap_response.expected_amount - 1,
                    false => create_swap_response.expected_amount,
                };
                utils::send_to_address(chain, &create_swap_response.address, amount)
                    .await
                    .unwrap();
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
                log::debug!("Received claim tx details : {response:?}");
            }

            "transaction.claimed" => {
                log::info!("Successfully completed submarine swap");
                break;
            }

            // This means the funding transaction was rejected by Boltz for whatever reason, and we need to get
            // the funds back via refund.
            "transaction.lockupFailed" | "invoice.failedToPay" => {
                sleep(WAIT_TIME).await;
                let tx = swap_script
                    .construct_refund(SwapTransactionParams {
                        keys: our_keys,
                        output_address: refund_address,
                        fee: Fee::Absolute(1000),
                        swap_id: swap_id.clone(),
                        client,
                        boltz_client: &boltz_api_v2,
                        options: None,
                    })
                    .await
                    .unwrap();

                let txid = client.broadcast_tx(&tx).await.unwrap();
                log::info!("Cooperative Refund Successfully broadcasted: {txid}");

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
async fn bitcoin_v2_submarine_electrum() {
    setup_logger();
    let client =
        Client::new().with_bitcoin(ElectrumBitcoinClient::default(BTC_CHAIN, None).unwrap());
    v2_submarine(&client, false, Chain::Bitcoin(BTC_CHAIN)).await;
    v2_submarine(&client, true, Chain::Bitcoin(BTC_CHAIN)).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_submarine_esplora() {
    setup_logger();
    let client = Client::new().with_bitcoin(EsploraBitcoinClient::default(BTC_CHAIN, None));
    v2_submarine(&client, false, Chain::Bitcoin(BTC_CHAIN)).await;
    v2_submarine(&client, true, Chain::Bitcoin(BTC_CHAIN)).await;
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_v2_submarine_electrum() {
    setup_logger();
    let client =
        Client::new().with_liquid(ElectrumLiquidClient::default(LIQUID_CHAIN, None).unwrap());
    v2_submarine(&client, false, Chain::Liquid(LIQUID_CHAIN)).await;
    v2_submarine(&client, true, Chain::Liquid(LIQUID_CHAIN)).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_v2_submarine_esplora() {
    setup_logger();
    let client = Client::new().with_liquid(EsploraLiquidClient::default(LIQUID_CHAIN, None));
    v2_submarine(&client, false, Chain::Liquid(LIQUID_CHAIN)).await;
    v2_submarine(&client, true, Chain::Liquid(LIQUID_CHAIN)).await;
}
