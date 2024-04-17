use std::{str::FromStr, time::Duration};

use boltz_client::{
    network::electrum::ElectrumConfig,
    swaps::boltzv2::{
        BoltzApiClientV2, CreateReverseReq, CreateSwapRequest, Subscription, SwapUpdate,
        BOLTZ_TESTNET_URL_V2,
    },
    util::{secrets::Preimage, setup_logger},
    Bolt11Invoice, LBtcSwapScriptV2, LBtcSwapTxV2, Secp256k1,
};

use bitcoin::{
    hashes::{sha256, Hash},
    hex::FromHex,
    key::rand::thread_rng,
    secp256k1::Keypair,
    Amount, PublicKey,
};

pub mod test_utils;

#[test]
#[ignore = "Requires testnet invoice and refund address"]
fn liquid_v2_submarine() {
    setup_logger();

    let secp = Secp256k1::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());

    let refund_public_key = PublicKey {
        inner: our_keys.public_key(),
        compressed: true,
    };

    // Set a new invoice string and refund address for each test.
    let invoice = "lntb650u1pjut6cfpp5h7dgn6wghmsm8dfky9cjzrlyf5c2xaszk2lxamfqm2w4eurevpwqdq8d3skk6qxqyjw5qcqp2sp5nyk5mtwjf250uv0uf2l2trhyycefndu868dya04zlrvw5gvaev2srzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkf6vkyqq20gqqqqqqqqpqqqqqzsqqc9qyyssqva5tvj5gxfsdmc84hvreme8djgwj3rqr37kwtsa6qttgwzhe7s0yfy482afyje45ppualmatfwnmlmk2py7wc7l3l849jl7vdpa86aqqxmqmws".to_string();
    let refund_address = "tlq1qqv4z28utgwunvn62s3aw0qjuw3sqgfdq6q8r8fesnawwnuctl70kdyedxw6tmxgqpq83x6ldsyr4n6cj0dm875k8g9k85w2s7".to_string();

    // Initiate the swap with Boltz
    let create_swap_req = CreateSwapRequest {
        from: "L-BTC".to_string(),
        to: "BTC".to_string(),
        invoice: invoice.to_string(),
        refund_public_key,
        referral_id: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_TESTNET_URL_V2);

    let create_swap_response = boltz_api_v2.post_swap_req(&create_swap_req).unwrap();

    log::info!("Got Swap Response from Boltz server");

    log::debug!("Swap Response: {:?}", create_swap_response);

    let swap_script =
        LBtcSwapScriptV2::submarine_from_swap_resp(&create_swap_response, refund_public_key)
            .unwrap();

    log::debug!("Created Swap Script. : {:?}", swap_script);

    // Subscribe to websocket updates
    let mut socket = boltz_api_v2.connect_ws().unwrap();

    socket
        .send(tungstenite::Message::Text(
            serde_json::to_string(&Subscription::new(&create_swap_response.id)).unwrap(),
        ))
        .unwrap();

    // Event handlers for various swap status.
    loop {
        let response = serde_json::from_str(&socket.read().unwrap().to_string());

        if response.is_err() {
            if response.err().expect("expected").is_eof() {
                continue;
            }
        } else {
            match response.unwrap() {
                SwapUpdate::Subscription {
                    event,
                    channel,
                    args,
                } => {
                    assert!(event == "subscribe");
                    assert!(channel == "swap.update");
                    assert!(args.get(0).expect("expected") == &create_swap_response.id);
                    log::info!(
                        "Successfully subscribed for Swap updates. Swap ID : {}",
                        create_swap_response.id
                    );
                }

                SwapUpdate::Update {
                    event,
                    channel,
                    args,
                } => {
                    assert!(event == "update");
                    assert!(channel == "swap.update");
                    let update = args.get(0).expect("expected");
                    assert!(update.id == create_swap_response.id);
                    log::info!("Got Update from server: {}", update.status);

                    // Invoice is Set. Waiting for us to send onchain tx.
                    if update.status == "invoice.set" {
                        log::info!(
                            "Send {} sats to BTC address {}",
                            create_swap_response.expected_amount,
                            create_swap_response.address
                        );
                    }

                    // Boltz has paid the invoice, and waiting for our partial sig.
                    if update.status == "transaction.claim.pending" {
                        // Create the refund transaction at this stage
                        let swap_tx = LBtcSwapTxV2::new_refund(
                            swap_script.clone(),
                            &refund_address,
                            &ElectrumConfig::default_bitcoin(),
                        )
                        .unwrap();

                        let claim_tx_response = boltz_api_v2
                            .get_claim_tx_details(&create_swap_response.id)
                            .unwrap();

                        log::debug!("Received claim tx details : {:?}", claim_tx_response);

                        // Check that boltz have the correct preimage.
                        // At this stage the client should verify that LN invoice has been paid.
                        let preimage = Vec::from_hex(&claim_tx_response.preimage).unwrap();
                        let preimage_hash = sha256::Hash::hash(&preimage);
                        let invoice = Bolt11Invoice::from_str(&create_swap_req.invoice).unwrap();
                        let invoice_payment_hash = invoice.payment_hash();
                        assert!(invoice_payment_hash.to_string() == preimage_hash.to_string());
                        log::info!("Correct Hash preimage received from Boltz.");

                        // Compute and send Musig2 partial sig
                        let (partial_sig, pub_nonce) = swap_tx
                            .submarine_partial_sig(&our_keys, &claim_tx_response)
                            .unwrap();
                        boltz_api_v2
                            .post_claim_tx_details(&create_swap_response.id, pub_nonce, partial_sig)
                            .unwrap();
                        log::info!("Successfully Sent partial signature");
                    }

                    if update.status == "transaction.claimed" {
                        log::info!("Successfully completed submarine swap");
                        break;
                    }
                }

                SwapUpdate::Error {
                    event,
                    channel,
                    args,
                } => {
                    assert!(event == "update");
                    assert!(channel == "swap.update");
                    let error = args.get(0).expect("expected");
                    log::error!(
                        "Got Boltz response error : {} for swap: {}",
                        error.error,
                        error.id
                    );
                }
            }
        }
    }
}

#[test]
#[ignore = "Requires testnet invoice and refund address"]
fn liquid_v2_reverse() {
    setup_logger();

    let secp = Secp256k1::new();
    let preimage = Preimage::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());
    let invoice_amount = 100000;
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_keys.public_key(),
    };

    // Give a valid claim address or else funds will be lost.
    let claim_address = "tb1qq20a7gqewc0un9mxxlqyqwn7ut7zjrj9y3d0mu".to_string();

    let create_reverse_req = CreateReverseReq {
        invoice_amount,
        from: "BTC".to_string(),
        to: "BTC".to_string(),
        preimage_hash: preimage.sha256,
        claim_public_key,
        referral_id: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_TESTNET_URL_V2);

    let reverse_resp = boltz_api_v2.post_reverse_req(create_reverse_req).unwrap();

    log::debug!("Got Reverse swap response: {:?}", reverse_resp);

    let swap_script =
        LBtcSwapScriptV2::reverse_from_swap_resp(&reverse_resp, claim_public_key).unwrap();

    // Subscribe to wss status updates
    let mut socket = boltz_api_v2.connect_ws().unwrap();

    let subscription = Subscription::new(&reverse_resp.id);

    socket
        .send(tungstenite::Message::Text(
            serde_json::to_string(&subscription).unwrap(),
        ))
        .unwrap();

    // Event handlers for various swap status.
    loop {
        let response = serde_json::from_str(&socket.read().unwrap().to_string());

        if response.is_err() {
            if response.err().expect("expected").is_eof() {
                continue;
            }
        } else {
            match response.as_ref().unwrap() {
                SwapUpdate::Subscription {
                    event,
                    channel,
                    args,
                } => {
                    assert!(event == "subscribe");
                    assert!(channel == "swap.update");
                    assert!(args.get(0).expect("expected") == &reverse_resp.id);
                    log::info!("Subscription successful for swap : {}", &reverse_resp.id);
                }

                SwapUpdate::Update {
                    event,
                    channel,
                    args,
                } => {
                    assert!(event == "update");
                    assert!(channel == "swap.update");
                    let update = args.get(0).expect("expected");
                    assert!(&update.id == &reverse_resp.id);
                    log::info!("Got Update from server: {}", update.status);

                    if update.status == "swap.created" {
                        log::info!("Waiting for Invoice to be paid: {}", &reverse_resp.invoice);
                        continue;
                    }

                    if update.status == "transaction.mempool" {
                        log::info!("Boltz broadcasted funding tx");

                        std::thread::sleep(Duration::from_secs(15));

                        let claim_tx = LBtcSwapTxV2::new_claim(
                            swap_script.clone(),
                            claim_address.clone(),
                            &ElectrumConfig::default_bitcoin(),
                        )
                        .unwrap();

                        let tx = claim_tx
                            .sign_claim(
                                &our_keys,
                                &preimage,
                                Amount::from_sat(1000),
                                Some((&boltz_api_v2, reverse_resp.id.clone())),
                            )
                            .unwrap();

                        claim_tx
                            .broadcast(&tx, &ElectrumConfig::default_bitcoin())
                            .unwrap();

                        log::info!("Succesfully broadcasted claim tx!");
                        log::debug!("Claim Tx {:?}", tx);
                    }

                    if update.status == "invoice.settled" {
                        log::info!("Reverse Swap Successful!");
                        break;
                    }
                }

                SwapUpdate::Error {
                    event,
                    channel,
                    args,
                } => {
                    assert!(event == "update");
                    assert!(channel == "swap.update");
                    let error = args.get(0).expect("expected");
                    println!("Got error : {} for swap: {}", error.error, error.id);
                }
            }
        }
    }
}
