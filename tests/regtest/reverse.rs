use bitcoin::{key::rand::thread_rng, secp256k1::Keypair, PublicKey};
use boltz_client::boltz::BoltzWsConfig;
use boltz_client::fees::Fee;
use boltz_client::swaps::{ChainClient, TransactionOptions};
use boltz_client::{
    network::Chain,
    swaps::{
        boltz::CreateReverseRequest,
        magic_routing::{check_for_mrh, sign_address},
        {SwapScript, SwapTransactionParams},
    },
    util::{secrets::Preimage, setup_logger},
    Secp256k1,
};
use serial_test::serial;
use std::sync::Arc;

use crate::regtest::common::*;
use crate::utils;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

async fn swap(chain: Chain, chain_client: &ChainClient) {
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

    let boltz_api_v2 = create_boltz_api();
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());

    let reverse_resp = boltz_api_v2
        .post_reverse_req(create_reverse_req)
        .await
        .unwrap();
    let invoice = reverse_resp.invoice.clone().unwrap();

    reverse_resp
        .validate(&preimage, &claim_public_key, chain)
        .unwrap();

    let _ = check_for_mrh(&boltz_api_v2, &invoice, chain)
        .await
        .unwrap()
        .unwrap();

    log::debug!("Got Reverse swap response: {reverse_resp:?}");

    let swap_script =
        SwapScript::reverse_from_swap_resp(chain, &reverse_resp, claim_public_key).unwrap();
    let swap_id = reverse_resp.id.clone();

    ws_api.subscribe_swap(&swap_id).await.unwrap();
    let mut updates = ws_api.updates();

    next_status(&mut updates, "swap.created").await.unwrap();

    utils::start_pay_invoice_lnd(reverse_resp.invoice.clone().unwrap());

    let status = next_status(&mut updates, "transaction.mempool")
        .await
        .unwrap();

    let lockup_tx = swap_script
        .parse_lockup_transaction(&status.transaction.unwrap())
        .await
        .unwrap();

    let claim_address = utils::generate_address(chain).await.unwrap();
    let tx = swap_script
        .construct_claim(
            &preimage,
            SwapTransactionParams {
                swap_id: swap_id.clone(),
                keys: our_keys,
                fee: Fee::Absolute(200),
                output_address: claim_address,
                chain_client,
                boltz_client: &boltz_api_v2,
                options: Some(TransactionOptions::default().with_lockup_tx(lockup_tx)),
            },
        )
        .await
        .unwrap();

    chain_client.broadcast_tx(&tx).await.unwrap();

    next_status(&mut updates, "invoice.settled").await.unwrap();
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_v2_reverse_electrum() {
    setup_logger();
    let chain_client = create_chain_client_electrum();
    swap(BTC_CHAIN.into(), &chain_client).await;
    swap(BTC_CHAIN.into(), &chain_client).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_reverse_esplora() {
    setup_logger();
    let chain_client = create_chain_client_esplora();
    swap(BTC_CHAIN.into(), &chain_client).await;
    swap(BTC_CHAIN.into(), &chain_client).await;
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_v2_reverse_electrum() {
    setup_logger();
    let chain_client = create_chain_client_electrum();
    swap(LBTC_CHAIN.into(), &chain_client).await;
    swap(LBTC_CHAIN.into(), &chain_client).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_v2_reverse_esplora() {
    setup_logger();
    let chain_client = create_chain_client_esplora();
    swap(LBTC_CHAIN.into(), &chain_client).await;
    swap(LBTC_CHAIN.into(), &chain_client).await;
}
