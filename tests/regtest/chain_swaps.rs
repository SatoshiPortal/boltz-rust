use crate::regtest::WAIT_TIME;
use crate::utils;
use bitcoin::{key::rand::thread_rng, PublicKey};
use boltz_client::boltz::{
    BoltzApiClientV2, BoltzWsConfig, ChainSwapDetails, CreateChainRequest, Side, BOLTZ_REGTEST,
};
use boltz_client::fees::Fee;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
#[cfg(feature = "electrum")]
use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
#[cfg(feature = "esplora")]
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::{ChainClient, SwapScript, SwapTransactionParams, TransactionOptions};
use boltz_client::util::sleep;
use boltz_client::{
    util::{secrets::Preimage, setup_logger},
    Keypair, Secp256k1,
};
use serial_test::serial;
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
    let chain_client = ChainClient::new()
        .with_bitcoin(ElectrumBitcoinClient::default(BITCOIN_CHAIN, None).unwrap())
        .with_liquid(ElectrumLiquidClient::default(LIQUID_CHAIN, None).unwrap());
    v2_chain(
        &chain_client,
        false,
        BITCOIN_CHAIN.into(),
        LIQUID_CHAIN.into(),
    )
    .await;
    v2_chain(
        &chain_client,
        true,
        BITCOIN_CHAIN.into(),
        LIQUID_CHAIN.into(),
    )
    .await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_liquid_v2_chain_esplora() {
    setup_logger();
    let chain_client = ChainClient::new()
        .with_bitcoin(EsploraBitcoinClient::default(BITCOIN_CHAIN, None))
        .with_liquid(EsploraLiquidClient::default(LIQUID_CHAIN, None));
    v2_chain(
        &chain_client,
        false,
        BITCOIN_CHAIN.into(),
        LIQUID_CHAIN.into(),
    )
    .await;
    v2_chain(
        &chain_client,
        true,
        BITCOIN_CHAIN.into(),
        LIQUID_CHAIN.into(),
    )
    .await;
}

async fn v2_chain(chain_client: &ChainClient, underpay: bool, from: Chain, to: Chain) {
    let secp = Secp256k1::new();
    let preimage = Preimage::new();
    log::info!("{preimage:#?}");
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
        from: from.to_string(),
        to: to.to_string(),
        preimage_hash: preimage.sha256,
        claim_public_key: Some(claim_public_key),
        refund_public_key: Some(refund_public_key),
        referral_id: None,
        user_lock_amount: Some(50_000),
        server_lock_amount: None,
        pair_hash: None,
        webhook: None,
    };

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT));

    let create_chain_response = boltz_api_v2.post_chain_req(create_chain_req).await.unwrap();
    create_chain_response
        .validate(&claim_public_key, &refund_public_key, from, to)
        .unwrap();
    let swap_id = create_chain_response.clone().id;
    let lockup_details: ChainSwapDetails = create_chain_response.clone().lockup_details;

    let lockup_script = SwapScript::chain_from_swap_resp(
        from,
        Side::Lockup,
        lockup_details.clone(),
        refund_public_key,
    )
    .unwrap();
    log::debug!("Lockup Script: {lockup_script:#?}");

    let refund_address = utils::generate_address(from).await.unwrap();

    let claim_details: ChainSwapDetails = create_chain_response.claim_details;

    let claim_script =
        SwapScript::chain_from_swap_resp(to, Side::Claim, claim_details.clone(), claim_public_key)
            .unwrap();

    let claim_address = utils::generate_address(to).await.unwrap();
    log::debug!("{claim_address:#?}");

    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());
    let mut rx = ws_api.updates();
    ws_api.subscribe_swap(&swap_id).await.unwrap();

    log::info!("Subscribed to swap {swap_id}");

    loop {
        let update = rx.recv().await.unwrap();
        match update.status.as_str() {
            "swap.created" => {
                let amount = match underpay {
                    true => create_chain_response.lockup_details.amount / 2,
                    false => create_chain_response.lockup_details.amount,
                };
                let address = create_chain_response.lockup_details.clone().lockup_address;

                log::info!("Sending {amount} sats to {from} address {address}");

                utils::send_to_address(from, &address, amount)
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

                let tx = claim_script
                    .construct_claim(
                        &preimage,
                        SwapTransactionParams {
                            keys: our_claim_keys,
                            output_address: claim_address.clone(),
                            fee: Fee::Absolute(1000),
                            swap_id: swap_id.clone(),
                            options: Some(
                                TransactionOptions::default()
                                    .with_chain_claim(our_refund_keys, lockup_script.clone()),
                            ),
                            chain_client,
                            boltz_client: &boltz_api_v2,
                        },
                    )
                    .await
                    .unwrap();

                chain_client.broadcast_tx(&tx).await.unwrap();

                log::info!("Successfully broadcasted claim tx!");
            }

            "transaction.claimed" => {
                log::info!("Successfully completed chain swap");
                break;
            }

            "transaction.lockupFailed" => {
                sleep(WAIT_TIME).await;
                log::info!("REFUNDING!");
                refund_v2_chain(
                    lockup_script.clone(),
                    refund_address.clone(),
                    swap_id.clone(),
                    our_refund_keys,
                    boltz_api_v2.clone(),
                    100,
                    chain_client,
                )
                .await;
                if let Chain::Bitcoin(_) = from {
                    log::info!("REFUNDING with higher fee");
                    refund_v2_chain(
                        lockup_script.clone(),
                        refund_address.clone(),
                        swap_id.clone(),
                        our_refund_keys,
                        boltz_api_v2.clone(),
                        1000,
                        chain_client,
                    )
                    .await;
                }
                break;
            }
            _ => {
                log::info!("Got Update from server: {}", update.status);
            }
        }
    }
}

async fn refund_v2_chain(
    lockup_script: SwapScript,
    refund_address: String,
    swap_id: String,
    our_refund_keys: Keypair,
    boltz_api_v2: BoltzApiClientV2,
    absolute_fees: u64,
    chain_client: &ChainClient,
) {
    let tx = lockup_script
        .construct_refund(SwapTransactionParams {
            keys: our_refund_keys,
            output_address: refund_address,
            fee: Fee::Absolute(absolute_fees),
            swap_id: swap_id.clone(),
            chain_client,
            boltz_client: &boltz_api_v2,
            options: None,
        })
        .await
        .unwrap();

    chain_client.broadcast_tx(&tx).await.unwrap();

    log::info!("Successfully broadcasted refund tx!");
    log::debug!("Refund Tx {tx:#?}");
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_bitcoin_v2_chain_electrum() {
    setup_logger();
    let chain_client = ChainClient::new()
        .with_bitcoin(ElectrumBitcoinClient::default(BITCOIN_CHAIN, None).unwrap())
        .with_liquid(ElectrumLiquidClient::default(LIQUID_CHAIN, None).unwrap());
    v2_chain(
        &chain_client,
        false,
        LIQUID_CHAIN.into(),
        BITCOIN_CHAIN.into(),
    )
    .await;
    v2_chain(
        &chain_client,
        true,
        LIQUID_CHAIN.into(),
        BITCOIN_CHAIN.into(),
    )
    .await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_bitcoin_v2_chain_esplora() {
    setup_logger();
    let chain_client = ChainClient::new()
        .with_bitcoin(EsploraBitcoinClient::default(BITCOIN_CHAIN, None))
        .with_liquid(EsploraLiquidClient::default(LIQUID_CHAIN, None));
    v2_chain(
        &chain_client,
        false,
        LIQUID_CHAIN.into(),
        BITCOIN_CHAIN.into(),
    )
    .await;
    v2_chain(
        &chain_client,
        true,
        LIQUID_CHAIN.into(),
        BITCOIN_CHAIN.into(),
    )
    .await;
}
