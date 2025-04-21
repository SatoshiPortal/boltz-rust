#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[cfg(feature = "electrum")]
use boltz_client::network::electrum::ElectrumBitcoinClient;
#[cfg(feature = "esplora")]
use boltz_client::network::esplora::EsploraBitcoinClient;
use boltz_client::{
    network::Chain,
    swaps::{
        boltz::{BoltzApiClientV2, Cooperative, CreateReverseRequest, CreateSubmarineRequest},
        magic_routing::{check_for_mrh, sign_address},
    },
    util::{secrets::Preimage, setup_logger},
    Bolt11Invoice, BtcSwapScript, BtcSwapTx, Secp256k1,
};
use std::str::FromStr;
use std::sync::Arc;

use crate::regtest::WAIT_TIME;
use crate::utils;
use bitcoin::{
    hashes::{sha256, Hash},
    hex::FromHex,
    key::rand::thread_rng,
    secp256k1::Keypair,
    PublicKey,
};
use boltz_client::boltz::{BoltzWsConfig, BOLTZ_REGTEST};
use boltz_client::fees::Fee;
use boltz_client::network::{BitcoinChain, BitcoinClient};
use boltz_client::util::sleep;
use serial_test::serial;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const CHAIN: BitcoinChain = BitcoinChain::BitcoinRegtest;

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_v2_submarine_electrum() {
    setup_logger();
    let bitcoin_client = ElectrumBitcoinClient::default(CHAIN, None).unwrap();
    bitcoin_v2_submarine(&bitcoin_client, false).await;
    bitcoin_v2_submarine(&bitcoin_client, true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_submarine_esplora() {
    setup_logger();
    let bitcoin_client = EsploraBitcoinClient::default(CHAIN, None);
    bitcoin_v2_submarine(&bitcoin_client, false).await;
    bitcoin_v2_submarine(&bitcoin_client, true).await;
}

async fn bitcoin_v2_submarine<BC: BitcoinClient>(bitcoin_client: &BC, underpay: bool) {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());

    let refund_public_key = PublicKey {
        inner: our_keys.public_key(),
        compressed: true,
    };

    // Set a new invoice string and refund address for each test.
    let invoice = utils::generate_invoice_lnd(50_000).await.unwrap();
    let refund_address = utils::generate_address_bitcoind().await.unwrap();

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());

    // If there is MRH send directly to that address
    //    let (bip21_addrs, amount) =
    //         check_for_mrh(&boltz_api_v2, &invoice, CHAIN).unwrap();
    //         log::info!("Found MRH in invoice");
    //         log::info!("Send {} to {}", amount, bip21_addrs);
    //         return;

    // Initiate the swap with Boltz
    let create_swap_req = CreateSubmarineRequest {
        from: "BTC".to_string(),
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
        BtcSwapScript::submarine_from_swap_resp(&create_swap_response, refund_public_key).unwrap();
    let swap_id = create_swap_response.id.clone();
    log::debug!("Created Swap Script. : {:?}", swap_script);

    let mut rx = ws_api.updates();
    ws_api.subscribe(&swap_id).await.unwrap();
    // Event handlers for various swap status.
    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "invoice.set" => {
                log::info!(
                    "Send {} sats to BTC address {}",
                    create_swap_response.expected_amount,
                    create_swap_response.address
                );

                let amount = match underpay {
                    true => create_swap_response.expected_amount - 1,
                    false => create_swap_response.expected_amount,
                };
                utils::send_to_address_bitcoind(&create_swap_response.address, amount)
                    .await
                    .unwrap();
            }
            "transaction.mempool" => {
                utils::mine_blocks(1).await.unwrap();
            }
            "transaction.claim.pending" => {
                // Create the refund transaction at this stage
                // This will fail if the funding transaction isn't confirmed yet. Which should not happen.
                let swap_tx = BtcSwapTx::new_refund(
                    swap_script.clone(),
                    &refund_address,
                    bitcoin_client,
                    &boltz_api_v2,
                    swap_id.to_owned(),
                )
                .await
                .expect("Funding UTXO not found");

                let claim_tx_response = boltz_api_v2
                    .get_submarine_claim_tx_details(&swap_id)
                    .await
                    .unwrap();

                log::debug!("Received claim tx details : {:?}", claim_tx_response);

                // Check that boltz have the correct preimage.
                // At this stage the client should verify that LN invoice has been paid.
                let preimage = Vec::from_hex(&claim_tx_response.preimage).unwrap();
                let preimage_hash = sha256::Hash::hash(&preimage);
                let invoice = Bolt11Invoice::from_str(&create_swap_req.invoice).unwrap();
                let invoice_payment_hash = invoice.payment_hash();
                assert_eq!(invoice_payment_hash.to_string(), preimage_hash.to_string());
                log::info!("Correct Hash preimage received from Boltz.");

                // Compute and send Musig2 partial sig
                let (partial_sig, pub_nonce) = swap_tx
                    .partial_sign(
                        &our_keys,
                        &claim_tx_response.pub_nonce,
                        &claim_tx_response.transaction_hash,
                    )
                    .unwrap();
                boltz_api_v2
                    .post_submarine_claim_tx_details(&swap_id, pub_nonce, partial_sig)
                    .await
                    .unwrap();
                log::info!("Successfully Sent partial signature");
            }

            "transaction.claimed" => {
                log::info!("Successfully completed submarine swap");
                break;
            }

            // This means the funding transaction was rejected by Boltz for whatever reason, and we need to get
            // the funds back via refund.
            "transaction.lockupFailed" | "invoice.failedToPay" => {
                sleep(WAIT_TIME).await;
                let swap_tx = BtcSwapTx::new_refund(
                    swap_script.clone(),
                    &refund_address,
                    bitcoin_client,
                    &boltz_api_v2,
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
                    )
                    .await
                    .unwrap();

                let txid = swap_tx.broadcast(&tx, bitcoin_client).await.unwrap();
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

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());

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

    let mut rx = ws_api.updates();

    ws_api.subscribe(&swap_id).await.unwrap();

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

                sleep(WAIT_TIME).await;

                let claim_tx = BtcSwapTx::new_claim(
                    swap_script.clone(),
                    claim_address.clone(),
                    &bitcoin_client,
                    &boltz_api_v2,
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

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());

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

    let mut rx = ws_api.updates();
    ws_api.subscribe(&swap_id).await.unwrap();

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

                sleep(WAIT_TIME).await;

                let claim_tx = BtcSwapTx::new_claim(
                    swap_script.clone(),
                    claim_address.clone(),
                    &bitcoin_client,
                    &boltz_api_v2,
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
