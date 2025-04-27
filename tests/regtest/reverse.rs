#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[cfg(feature = "electrum")]
use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
#[cfg(feature = "esplora")]
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::swaps::TransactionOptions;
use boltz_client::util::sleep;
use boltz_client::{
    network::Chain,
    swaps::{
        boltz::{BoltzApiClientV2, CreateReverseRequest},
        magic_routing::{check_for_mrh, sign_address},
        {ChainClient, SwapScript, SwapTransactionParams},
    },
    util::{secrets::Preimage, setup_logger},
    Secp256k1,
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

async fn v2_reverse(chain_client: &ChainClient, chain: Chain, cooperative: bool) {
    let secp = Secp256k1::new();
    let preimage = Preimage::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());
    let invoice_amount = 100000;
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_keys.public_key(),
    };

    // Give a valid claim address or else funds will be lost.
    let claim_address = utils::generate_address(chain).await.unwrap();

    let addrs_sig = sign_address(&claim_address, &our_keys).unwrap();
    let create_reverse_req = CreateReverseRequest {
        from: "BTC".to_string(),
        to: chain.to_string(),
        invoice: None,
        invoice_amount: Some(invoice_amount),
        preimage_hash: Some(preimage.sha256),
        description: None,
        description_hash: None,
        address_signature: Some(addrs_sig.to_string()),
        address: Some(claim_address.clone()),
        claim_public_key,
        referral_id: None, // Add address signature here.
        webhook: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());

    let reverse_resp = boltz_api_v2
        .post_reverse_req(create_reverse_req)
        .await
        .unwrap();
    let invoice = reverse_resp.invoice.clone().unwrap();

    let _ = check_for_mrh(&boltz_api_v2, &invoice, chain)
        .await
        .unwrap()
        .unwrap();

    log::debug!("Got Reverse swap response: {reverse_resp:?}");

    let swap_script =
        SwapScript::reverse_from_swap_resp(chain, &reverse_resp, claim_public_key).unwrap();
    let swap_id = reverse_resp.id.clone();

    ws_api.subscribe_swap(&swap_id).await.unwrap();
    let mut rx = ws_api.updates();

    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "swap.created" => {
                log::info!("Waiting for Invoice to be paid: {}", &invoice);

                utils::start_pay_invoice_lnd(invoice.clone());

                continue;
            }

            "transaction.mempool" => {
                log::info!("Boltz broadcasted funding tx");

                sleep(WAIT_TIME).await;

                let tx = swap_script
                    .construct_claim(
                        &preimage,
                        SwapTransactionParams {
                            keys: our_keys,
                            output_address: claim_address.clone(),
                            fee: Fee::Absolute(1000),
                            swap_id: swap_id.clone(),
                            options: Some(
                                TransactionOptions::default().with_cooperative(cooperative),
                            ),
                            chain_client,
                            boltz_client: &boltz_api_v2,
                        },
                    )
                    .await
                    .unwrap();

                chain_client.broadcast_tx(&tx).await.unwrap();

                log::info!("Successfully broadcasted claim tx!");
                log::debug!("Claim Tx {tx:?}");
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
async fn bitcoin_v2_reverse_electrum() {
    setup_logger();
    let chain_client =
        ChainClient::new().with_bitcoin(ElectrumBitcoinClient::default(BTC_CHAIN, None).unwrap());
    v2_reverse(&chain_client, BTC_CHAIN.into(), false).await;
    v2_reverse(&chain_client, BTC_CHAIN.into(), true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_reverse_esplora() {
    setup_logger();
    let chain_client =
        ChainClient::new().with_bitcoin(EsploraBitcoinClient::default(BTC_CHAIN, None));
    v2_reverse(&chain_client, BTC_CHAIN.into(), false).await;
    v2_reverse(&chain_client, BTC_CHAIN.into(), true).await;
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_v2_reverse_electrum() {
    setup_logger();
    let chain_client =
        ChainClient::new().with_liquid(ElectrumLiquidClient::default(LIQUID_CHAIN, None).unwrap());
    v2_reverse(&chain_client, LIQUID_CHAIN.into(), false).await;
    v2_reverse(&chain_client, LIQUID_CHAIN.into(), true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_v2_reverse_esplora() {
    setup_logger();
    let chain_client =
        ChainClient::new().with_liquid(EsploraLiquidClient::default(LIQUID_CHAIN, None));
    v2_reverse(&chain_client, LIQUID_CHAIN.into(), false).await;
    v2_reverse(&chain_client, LIQUID_CHAIN.into(), true).await;
}
