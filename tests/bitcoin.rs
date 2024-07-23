use std::{str::FromStr, time::Duration};

use boltz_client::{
    network::{electrum::ElectrumConfig, Chain},
    swaps::{
        boltz::{
            BoltzApiClientV2, Cooperative, CreateReverseRequest, CreateSubmarineRequest,
            Subscription, SwapUpdate, BOLTZ_TESTNET_URL_V2,
        },
        magic_routing::{check_for_mrh, sign_address},
    },
    util::{secrets::Preimage, setup_logger},
    Bolt11Invoice, BtcSwapScript, BtcSwapTx, Secp256k1,
};

use bitcoin::{
    hashes::{sha256, Hash},
    hex::FromHex,
    key::rand::thread_rng,
    secp256k1::Keypair,
    PublicKey,
};

pub mod test_utils;

#[test]
#[ignore = "Requires testnet invoice and refund address"]
fn bitcoin_v2_submarine() {
    setup_logger();

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let our_keys = Keypair::new(&secp, &mut thread_rng());

    let refund_public_key = PublicKey {
        inner: our_keys.public_key(),
        compressed: true,
    };

    // Set a new invoice string and refund address for each test.
    let invoice = "lntb510u1pnpuwgxpp5arh2aw92wv5vxmndm0704zu2qhj6k8xhg38dlylt2atcc3vcs88qdqgdverzvm2xqyjw5qcqp2sp52vgwm4s6pc2q38hxrma9h4ycgtn4kzaq0we0d4mjtq030fu6zsfqrzjq2gyp9za7vc7vd8m59fvu63pu00u4pak35n4upuv4mhyw5l586dvkf6vkyqq20gqqqqqqqqpqqqqqzsqqc9qyyssq6frgq8gly29thefxg83y57hv564npas5dqc0cslml2q3cj0usrdptqa5p2el3df0c0xc6raxnty06m745l87v4qausuq9xh0wj2x57cpxsxxcz".to_string();
    let refund_address = "tb1qq20a7gqewc0un9mxxlqyqwn7ut7zjrj9y3d0mu".to_string();

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_TESTNET_URL_V2);

    // If there is MRH send directly to that address
    //    let (bip21_addrs, amount) =
    //         check_for_mrh(&boltz_api_v2, &invoice, Chain::BitcoinTestnet).unwrap();
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

    let create_swap_response = boltz_api_v2.post_swap_req(&create_swap_req).unwrap();

    log::info!("Got Swap Response from Boltz server");

    log::debug!("Swap Response: {:?}", create_swap_response);

    let swap_script =
        BtcSwapScript::submarine_from_swap_resp(&create_swap_response, refund_public_key).unwrap();

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

                        // Test Cooperative Refund.
                        // Send 1 sat less to than expected amount to Boltz, and let Boltz fail the swap.
                    }

                    // Boltz has paid the invoice, and waiting for our partial sig.
                    if update.status == "transaction.claim.pending" {
                        // Create the refund transaction at this stage
                        // This will fail if the funding transaction isn't confirmed yet. Which should not happen.
                        let swap_tx = BtcSwapTx::new_refund(
                            swap_script.clone(),
                            &refund_address,
                            &ElectrumConfig::default_bitcoin(),
                        )
                        .expect("Funding UTXO not found");

                        let claim_tx_response = boltz_api_v2
                            .get_submarine_claim_tx_details(&create_swap_response.id)
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
                            .partial_sign(
                                &our_keys,
                                &claim_tx_response.pub_nonce,
                                &claim_tx_response.transaction_hash,
                            )
                            .unwrap();
                        boltz_api_v2
                            .post_submarine_claim_tx_details(
                                &create_swap_response.id,
                                pub_nonce,
                                partial_sig,
                            )
                            .unwrap();
                        log::info!("Successfully Sent partial signature");
                    }

                    if update.status == "transaction.claimed" {
                        log::info!("Successfully completed submarine swap");
                        break;
                    }

                    // This means the funding transaction was rejected by Boltz for whatever reason, and we need to get
                    // fund back via refund.
                    if update.status == "transaction.lockupFailed"
                        || update.status == "invoice.failedToPay"
                    {
                        let swap_tx = BtcSwapTx::new_refund(
                            swap_script.clone(),
                            &refund_address,
                            &ElectrumConfig::default_bitcoin(),
                        )
                        .expect("Funding UTXO not found");

                        match swap_tx.sign_refund(
                            &our_keys,
                            1000,
                            Some(Cooperative {
                                boltz_api: &boltz_api_v2,
                                swap_id: create_swap_response.id.clone(),
                                pub_nonce: None,
                                partial_sig: None,
                            }),
                        ) {
                            Ok(tx) => {
                                let txid = swap_tx
                                    .broadcast(&tx, &ElectrumConfig::default_bitcoin())
                                    .unwrap();
                                log::info!("Cooperative Refund Successfully broadcasted: {}", txid);
                            }
                            Err(e) => {
                                log::info!("Cooperative refund failed. {:?}", e);
                                log::info!("Attempting Non-cooperative refund.");

                                let tx = swap_tx.sign_refund(&our_keys, 1000, None).unwrap();
                                let txid = swap_tx
                                    .broadcast(&tx, &ElectrumConfig::default_bitcoin())
                                    .unwrap();
                                log::info!(
                                    "Non-cooperative Refund Successfully broadcasted: {}",
                                    txid
                                );
                            }
                        }
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
fn bitcoin_v2_reverse() {
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

    let addrs_sig = sign_address(&claim_address, &our_keys).unwrap();
    let create_reverse_req = CreateReverseRequest {
        invoice_amount,
        from: "BTC".to_string(),
        to: "BTC".to_string(),
        preimage_hash: preimage.sha256,
        description: None,
        address_signature: Some(addrs_sig.to_string()),
        address: Some(claim_address.clone()),
        claim_public_key,
        referral_id: None, // Add address signature here.
        webhook: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_TESTNET_URL_V2);

    let reverse_resp = boltz_api_v2.post_reverse_req(create_reverse_req).unwrap();

    let _ = check_for_mrh(&boltz_api_v2, &reverse_resp.invoice, Chain::BitcoinTestnet)
        .unwrap()
        .unwrap();

    log::debug!("Got Reverse swap response: {:?}", reverse_resp);

    let swap_script =
        BtcSwapScript::reverse_from_swap_resp(&reverse_resp, claim_public_key).unwrap();

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

                        let claim_tx = BtcSwapTx::new_claim(
                            swap_script.clone(),
                            claim_address.clone(),
                            &ElectrumConfig::default_bitcoin(),
                        )
                        .expect("Funding tx expected");

                        let tx = claim_tx
                            .sign_claim(
                                &our_keys,
                                &preimage,
                                1000,
                                Some(Cooperative {
                                    boltz_api: &boltz_api_v2,
                                    swap_id: reverse_resp.id.clone(),
                                    pub_nonce: None,
                                    partial_sig: None,
                                }),
                            )
                            .unwrap();

                        claim_tx
                            .broadcast(&tx, &ElectrumConfig::default_bitcoin())
                            .unwrap();

                        log::info!("Successfully broadcasted claim tx!");
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
