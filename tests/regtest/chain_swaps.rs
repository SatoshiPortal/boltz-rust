use crate::regtest::WAIT_TIME;
use crate::utils;
use bitcoin::{key::rand::thread_rng, PublicKey};
use boltz_client::boltz::{
    BoltzApiClientV2, BoltzWsConfig, ChainSwapDetails, Cooperative, CreateChainRequest, Side,
    BOLTZ_REGTEST,
};
use boltz_client::fees::Fee;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[cfg(feature = "electrum")]
use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
#[cfg(feature = "esplora")]
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::network::{BitcoinChain, BitcoinClient, LiquidChain, LiquidClient};
use boltz_client::util::sleep;
use boltz_client::{
    util::{secrets::Preimage, setup_logger},
    BtcSwapScript, BtcSwapTx, Keypair, LBtcSwapScript, LBtcSwapTx, Secp256k1,
};
use elements::Address as EAddress;
use serial_test::serial;
use std::str::FromStr;
use std::sync::Arc;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

const BITCOIN_CHAIN: BitcoinChain = BitcoinChain::BitcoinRegtest;
const LIQUID_CHAIN: LiquidChain = LiquidChain::LiquidRegtest;

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_liquid_v2_chain_electrum() {
    setup_logger();
    let bitcoin_client = ElectrumBitcoinClient::default(BITCOIN_CHAIN, None).unwrap();
    let liquid_client = ElectrumLiquidClient::default(LIQUID_CHAIN, None).unwrap();
    bitcoin_liquid_v2_chain(&bitcoin_client, &liquid_client, false).await;
    bitcoin_liquid_v2_chain(&bitcoin_client, &liquid_client, true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_liquid_v2_chain_esplora() {
    setup_logger();
    let bitcoin_client = EsploraBitcoinClient::default(BITCOIN_CHAIN, None);
    let liquid_client = EsploraLiquidClient::default(LIQUID_CHAIN, None);
    bitcoin_liquid_v2_chain(&bitcoin_client, &liquid_client, false).await;
    bitcoin_liquid_v2_chain(&bitcoin_client, &liquid_client, true).await;
}

async fn bitcoin_liquid_v2_chain<BC: BitcoinClient, LC: LiquidClient>(
    bitcoin_client: &BC,
    liquid_client: &LC,
    underpay: bool,
) {
    let network = BITCOIN_CHAIN;
    let secp = Secp256k1::new();
    let preimage = Preimage::new();
    log::info!("{:#?}", preimage);
    let our_claim_keys = Keypair::new(&secp, &mut thread_rng());
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_claim_keys.public_key(),
    };

    let our_refund_keys = Keypair::new(&secp, &mut thread_rng());
    log::info!("Refund: {:#?}", our_refund_keys.display_secret());

    let refund_public_key = PublicKey {
        inner: our_refund_keys.public_key(),
        compressed: true,
    };

    let create_chain_req = CreateChainRequest {
        from: "BTC".to_string(),
        to: "L-BTC".to_string(),
        preimage_hash: preimage.sha256,
        claim_public_key: Some(claim_public_key),
        refund_public_key: Some(refund_public_key),
        referral_id: None,
        user_lock_amount: Some(50_000),
        server_lock_amount: None,
        pair_hash: None, // Add address signature here.
        webhook: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));

    let create_chain_response = boltz_api_v2.post_chain_req(create_chain_req).await.unwrap();
    let swap_id = create_chain_response.clone().id;
    let lockup_details: ChainSwapDetails = create_chain_response.clone().lockup_details;

    let lockup_script = BtcSwapScript::chain_from_swap_resp(
        Side::Lockup,
        lockup_details.clone(),
        refund_public_key,
    )
    .unwrap();
    log::debug!("Lockup Script: {:#?}", lockup_script);
    log::debug!(
        "Lockup Sender Pubkey: {:#?}",
        lockup_script.sender_pubkey.to_string()
    );
    log::debug!(
        "Lockup Receiver Pubkey: {:#?}",
        lockup_script.receiver_pubkey.to_string()
    );

    let lockup_address = lockup_script.clone().to_address(network).unwrap();
    assert_eq!(
        lockup_address.clone().to_string(),
        lockup_details.clone().lockup_address.to_string()
    );
    let refund_address = utils::generate_address_bitcoind().await.unwrap();

    let claim_details: ChainSwapDetails = create_chain_response.claim_details;

    let claim_script =
        LBtcSwapScript::chain_from_swap_resp(Side::Claim, claim_details.clone(), claim_public_key)
            .unwrap();

    let claim_address = utils::generate_address_elementsd().await.unwrap();
    let lq_address = EAddress::from_str(&claim_address).unwrap();
    log::debug!("{:#?}", lq_address);
    // let claim_address = claim_script.to_address(network).unwrap();
    // assert_eq!(claim_address.to_string(), claim_details.claim_address.unwrap());
    let liquid_genesis_hash = liquid_client.get_genesis_hash().await.unwrap();
    log::debug!("{:#?}", liquid_genesis_hash);

    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());
    let mut rx = ws_api.updates();
    ws_api.subscribe(&swap_id).await.unwrap();

    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "swap.created" => {
                let amount = match underpay {
                    true => create_chain_response.lockup_details.amount / 2,
                    false => create_chain_response.lockup_details.amount,
                };
                let address = create_chain_response.lockup_details.clone().lockup_address;

                log::info!("Sending {} sats to BTC address {}", amount, address);

                utils::send_to_address_bitcoind(&address, amount)
                    .await
                    .unwrap();
            }

            "transaction.mempool" | "transaction.server.mempool" => {
                utils::mine_blocks(1).await.unwrap();
            }

            "transaction.server.confirmed" => {
                log::info!("Server lockup tx is confirmed!");

                sleep(WAIT_TIME).await;
                log::info!("Claiming!");

                let claim_tx = LBtcSwapTx::new_claim(
                    claim_script.clone(),
                    claim_address.clone(),
                    liquid_client,
                    &boltz_api_v2,
                    swap_id.clone(),
                )
                .await
                .unwrap();
                let refund_tx = BtcSwapTx::new_refund(
                    lockup_script.clone(),
                    &refund_address,
                    bitcoin_client,
                    &boltz_api_v2,
                    swap_id.clone(),
                )
                .await
                .unwrap();
                let claim_tx_response = boltz_api_v2
                    .get_chain_claim_tx_details(&swap_id)
                    .await
                    .unwrap();
                let (partial_sig, pub_nonce) = refund_tx
                    .partial_sign(
                        &our_refund_keys,
                        &claim_tx_response.pub_nonce,
                        &claim_tx_response.transaction_hash,
                    )
                    .unwrap();
                let tx = claim_tx
                    .sign_claim(
                        &our_claim_keys,
                        &preimage,
                        Fee::Absolute(1000),
                        Some(Cooperative {
                            boltz_api: &boltz_api_v2,
                            swap_id: swap_id.clone(),
                            pub_nonce: Some(pub_nonce),
                            partial_sig: Some(partial_sig),
                        }),
                        false,
                    )
                    .await
                    .unwrap();

                claim_tx.broadcast(&tx, liquid_client, None).await.unwrap();

                log::info!("Succesfully broadcasted claim tx!");
            }

            "transaction.claimed" => {
                log::info!("Successfully completed chain swap");
                break;
            }

            "transaction.lockupFailed" => {
                sleep(WAIT_TIME).await;
                log::info!("REFUNDING!");
                refund_bitcoin_liquid_v2_chain(
                    lockup_script.clone(),
                    refund_address.clone(),
                    swap_id.clone(),
                    our_refund_keys,
                    boltz_api_v2.clone(),
                    100,
                    bitcoin_client,
                )
                .await;
                log::info!("REFUNDING with higher fee");
                refund_bitcoin_liquid_v2_chain(
                    lockup_script.clone(),
                    refund_address.clone(),
                    swap_id.clone(),
                    our_refund_keys,
                    boltz_api_v2.clone(),
                    1000,
                    bitcoin_client,
                )
                .await;
                break;
            }
            _ => {
                log::info!("Got Update from server: {}", update.status);
            }
        }
    }
}

async fn refund_bitcoin_liquid_v2_chain<BC: BitcoinClient>(
    lockup_script: BtcSwapScript,
    refund_address: String,
    swap_id: String,
    our_refund_keys: Keypair,
    boltz_api_v2: BoltzApiClientV2,
    absolute_fees: u64,
    bitcoin_client: &BC,
) {
    let refund_tx = BtcSwapTx::new_refund(
        lockup_script.clone(),
        &refund_address,
        bitcoin_client,
        &boltz_api_v2,
        swap_id.clone(),
    )
    .await
    .unwrap();
    let tx = refund_tx
        .sign_refund(
            &our_refund_keys,
            Fee::Absolute(absolute_fees),
            Some(Cooperative {
                boltz_api: &boltz_api_v2,
                swap_id: swap_id.clone(),
                pub_nonce: None,
                partial_sig: None,
            }),
        )
        .await
        .unwrap();

    refund_tx.broadcast(&tx, bitcoin_client).await.unwrap();

    log::info!("Successfully broadcasted refund tx!");
    log::debug!("Refund Tx {:?}", tx);
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_bitcoin_v2_chain_electrum() {
    setup_logger();
    let bitcoin_client = ElectrumBitcoinClient::default(BITCOIN_CHAIN, None).unwrap();
    let liquid_client = ElectrumLiquidClient::default(LIQUID_CHAIN, None).unwrap();
    liquid_bitcoin_v2_chain(&bitcoin_client, &liquid_client, false).await;
    liquid_bitcoin_v2_chain(&bitcoin_client, &liquid_client, true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_bitcoin_v2_chain_esplora() {
    setup_logger();
    let bitcoin_client = EsploraBitcoinClient::default(BITCOIN_CHAIN, None);
    let liquid_client = EsploraLiquidClient::default(LIQUID_CHAIN, None);
    liquid_bitcoin_v2_chain(&bitcoin_client, &liquid_client, false).await;
    liquid_bitcoin_v2_chain(&bitcoin_client, &liquid_client, true).await;
}

async fn liquid_bitcoin_v2_chain<BC: BitcoinClient, LC: LiquidClient>(
    bitcoin_client: &BC,
    liquid_client: &LC,
    underpay: bool,
) {
    let network = LIQUID_CHAIN;
    let secp = Secp256k1::new();
    let preimage = Preimage::new();
    log::info!("{:#?}", preimage);
    let our_claim_keys = Keypair::new(&secp, &mut thread_rng());
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_claim_keys.public_key(),
    };

    let our_refund_keys = Keypair::new(&secp, &mut thread_rng());
    log::info!("Refund: {:#?}", our_refund_keys.display_secret());

    let refund_public_key = PublicKey {
        inner: our_refund_keys.public_key(),
        compressed: true,
    };

    let create_chain_req = CreateChainRequest {
        from: "L-BTC".to_string(),
        to: "BTC".to_string(),
        preimage_hash: preimage.sha256,
        claim_public_key: Some(claim_public_key),
        refund_public_key: Some(refund_public_key),
        referral_id: None,
        user_lock_amount: Some(50_000),
        server_lock_amount: None,
        pair_hash: None, // Add address signature here.
        webhook: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));

    let create_chain_response = boltz_api_v2.post_chain_req(create_chain_req).await.unwrap();
    let swap_id = create_chain_response.clone().id;
    let lockup_details: ChainSwapDetails = create_chain_response.clone().lockup_details;

    let lockup_script = LBtcSwapScript::chain_from_swap_resp(
        Side::Lockup,
        lockup_details.clone(),
        refund_public_key,
    )
    .unwrap();
    log::debug!("Lockup Script: {:#?}", lockup_script);
    log::debug!(
        "Lockup Sender Pubkey: {:#?}",
        lockup_script.sender_pubkey.to_string()
    );
    log::debug!(
        "Lockup Receiver Pubkey: {:#?}",
        lockup_script.receiver_pubkey.to_string()
    );
    log::debug!(
        "Lockup Blinding Key: {:#?}",
        lockup_script.blinding_key.display_secret()
    );

    let lockup_address = lockup_script.clone().to_address(network).unwrap();
    assert_eq!(
        lockup_address.clone().to_string(),
        lockup_details.clone().lockup_address.to_string()
    );
    let refund_address = utils::generate_address_elementsd().await.unwrap();

    let claim_details: ChainSwapDetails = create_chain_response.claim_details;

    let claim_script =
        BtcSwapScript::chain_from_swap_resp(Side::Claim, claim_details.clone(), claim_public_key)
            .unwrap();

    let claim_address = utils::generate_address_bitcoind().await.unwrap();

    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());
    let mut rx = ws_api.updates();
    ws_api.subscribe(&swap_id).await.unwrap();

    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "swap.created" => {
                let amount = match underpay {
                    true => create_chain_response.lockup_details.amount / 2,
                    false => create_chain_response.lockup_details.amount,
                };
                let address = create_chain_response.lockup_details.clone().lockup_address;

                log::info!("Sending {} sats to L-BTC address {}", amount, address);

                utils::send_to_address_elementsd(&address, amount)
                    .await
                    .unwrap();
            }

            "transaction.mempool" | "transaction.server.mempool" => {
                utils::mine_blocks(1).await.unwrap();
            }

            "transaction.server.confirmed" => {
                log::info!("Server lockup tx is confirmed!");

                sleep(WAIT_TIME).await;
                log::info!("Claiming!");

                let claim_tx = BtcSwapTx::new_claim(
                    claim_script.clone(),
                    claim_address.clone(),
                    bitcoin_client,
                    &boltz_api_v2,
                    swap_id.clone(),
                )
                .await
                .unwrap();
                let refund_tx = LBtcSwapTx::new_refund(
                    lockup_script.clone(),
                    &refund_address,
                    liquid_client,
                    &boltz_api_v2,
                    swap_id.clone(),
                )
                .await
                .unwrap();
                let claim_tx_response = boltz_api_v2
                    .get_chain_claim_tx_details(&swap_id)
                    .await
                    .unwrap();
                let (partial_sig, pub_nonce) = refund_tx
                    .partial_sign(
                        &our_refund_keys,
                        &claim_tx_response.pub_nonce,
                        &claim_tx_response.transaction_hash,
                    )
                    .unwrap();
                let tx = claim_tx
                    .sign_claim(
                        &our_claim_keys,
                        &preimage,
                        Fee::Absolute(1000),
                        Some(Cooperative {
                            boltz_api: &boltz_api_v2,
                            swap_id: swap_id.clone(),
                            pub_nonce: Some(pub_nonce),
                            partial_sig: Some(partial_sig),
                        }),
                    )
                    .await
                    .unwrap();

                claim_tx.broadcast(&tx, bitcoin_client).await.unwrap();

                log::info!("Successfully broadcasted claim tx!");
            }

            "transaction.claimed" => {
                log::info!("Successfully completed chain swap");
                break;
            }

            "transaction.lockupFailed" => {
                sleep(WAIT_TIME).await;
                log::info!("REFUNDING!");
                let refund_tx = LBtcSwapTx::new_refund(
                    lockup_script.clone(),
                    &refund_address,
                    liquid_client,
                    &boltz_api_v2,
                    swap_id.clone(),
                )
                .await
                .unwrap();
                let tx = refund_tx
                    .sign_refund(
                        &our_refund_keys,
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

                refund_tx.broadcast(&tx, liquid_client, None).await.unwrap();

                log::info!("Successfully broadcasted claim tx!");
                log::debug!("Claim Tx {:?}", tx);
                break;
            }
            _ => {
                log::info!("Got Update from server: {}", update.status);
            }
        }
    }
}
