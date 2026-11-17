use bitcoin::secp256k1::SecretKey;
use bitcoin::{key::rand::thread_rng, secp256k1::Keypair, PublicKey};
use boltz_client::boltz::BoltzWsConfig;
use boltz_client::fees::Fee;
use boltz_client::network::Network;
use boltz_client::swaps::{ChainClient, DirectTxOptions, TransactionOptions};
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
use std::str::FromStr;
use std::sync::Arc;

use crate::regtest::common::*;
use crate::utils;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

async fn swap(chain: Chain, chain_client: &ChainClient, multi_output: bool) {
    let secp = Secp256k1::new();
    let preimage = Preimage::random();
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

    let mut reverse_resp = boltz_api_v2
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

    // A multi-output claim pays two extra fixed-amount outputs and spends
    // non-cooperatively, so the additional-outputs wrapper path is exercised
    // without Boltz involvement.
    let additional_outputs = if multi_output {
        vec![
            (utils::generate_address(chain).await.unwrap(), 800),
            (utils::generate_address(chain).await.unwrap(), 1_200),
        ]
    } else {
        Vec::new()
    };
    let absolute_fee = if multi_output { 1_000 } else { 200 };
    let mut options = TransactionOptions::default().with_lockup_tx(lockup_tx);
    if multi_output {
        options = options
            .with_cooperative(false)
            .with_additional_outputs(additional_outputs.clone());
    }

    let onchain_amount = reverse_resp.onchain_amount;
    let params = SwapTransactionParams {
        swap_id: swap_id.clone(),
        keys: our_keys,
        fee: Fee::Absolute(absolute_fee),
        output_address: claim_address.clone(),
        chain_client,
        boltz_client: &boltz_api_v2,
        options: Some(options),
    };

    reverse_resp.onchain_amount += 10;
    let underpaid_script =
        SwapScript::reverse_from_swap_resp(chain, &reverse_resp, claim_public_key).unwrap();

    underpaid_script
        .construct_claim(&preimage, params.clone())
        .await
        .expect_err("Underpaid script should throw");

    let tx = swap_script
        .construct_claim(&preimage, params)
        .await
        .unwrap();

    if multi_output {
        assert_multi_output_tx(
            &tx,
            chain,
            true,
            &claim_address,
            &additional_outputs,
            onchain_amount,
            absolute_fee,
        )
        .await;
    }

    chain_client.broadcast_tx(&tx).await.unwrap();

    next_status(&mut updates, "invoice.settled").await.unwrap();
}

async fn swap_mrh(chain: Chain, chain_client: &ChainClient) {
    let secp = Secp256k1::new();
    let preimage = Preimage::random();
    let our_keys = Keypair::new(&secp, &mut thread_rng());
    let invoice_amount = 100000;
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_keys.public_key(),
    };

    // Give a valid claim address or else funds will be lost.
    let claim_address = utils::generate_address(chain).await.unwrap();
    let blinding_key = utils::get_blinding_key(chain, &claim_address)
        .await
        .unwrap();

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

    let (address, amount) = check_for_mrh(&boltz_api_v2, &invoice, chain)
        .await
        .unwrap()
        .unwrap();

    log::debug!("Got MRH in invoice: {address}, {amount}");

    log::debug!("Got Reverse swap response: {reverse_resp:?}");

    let swap_script =
        SwapScript::reverse_from_swap_resp(chain, &reverse_resp, claim_public_key).unwrap();
    let swap_id = reverse_resp.id.clone();

    ws_api.subscribe_swap(&swap_id).await.unwrap();
    let mut updates = ws_api.updates();

    next_status(&mut updates, "swap.created").await.unwrap();

    utils::send_to_address(chain, &address, amount.to_sat())
        .await
        .unwrap();

    let status = next_status(&mut updates, "transaction.direct")
        .await
        .unwrap();

    let lockup_tx = swap_script
        .parse_lockup_transaction(&status.transaction.unwrap())
        .await
        .unwrap();

    log::debug!("Blinding key: {blinding_key}");

    swap_script
        .check_direct_transaction(
            chain_client,
            Network::Regtest,
            &lockup_tx,
            &address,
            DirectTxOptions::new().with_blinding_key(SecretKey::from_str(&blinding_key).unwrap()),
        )
        .await
        .unwrap();
}

/// A chain client that cannot see the swap lockup until `visible` is set:
/// Bitcoin lookups fail (the case that used to fall back to Boltz's copy of
/// the lockup), Liquid lookups find nothing. Everything else is the real
/// Electrum client.
#[cfg(feature = "electrum")]
mod hidden_lockup {
    use boltz_client::error::Error;
    use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
    use boltz_client::network::{BitcoinChain, BitcoinClient, LiquidChain, LiquidClient};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    pub struct HiddenBitcoin {
        pub inner: ElectrumBitcoinClient,
        pub visible: Arc<AtomicBool>,
    }

    #[macros::async_trait]
    impl BitcoinClient for HiddenBitcoin {
        async fn get_address_balance(
            &self,
            address: &bitcoin::Address,
        ) -> Result<(u64, i64), Error> {
            self.inner.get_address_balance(address).await
        }

        async fn get_address_utxos(
            &self,
            address: &bitcoin::Address,
        ) -> Result<Vec<(bitcoin::OutPoint, bitcoin::TxOut)>, Error> {
            if !self.visible.load(Ordering::SeqCst) {
                return Err(Error::Protocol("electrum unavailable".to_string()));
            }
            self.inner.get_address_utxos(address).await
        }

        async fn get_tx(&self, txid: bitcoin::Txid) -> Result<bitcoin::Transaction, Error> {
            self.inner.get_tx(txid).await
        }

        async fn broadcast_tx(
            &self,
            signed_tx: &bitcoin::Transaction,
        ) -> Result<bitcoin::Txid, Error> {
            self.inner.broadcast_tx(signed_tx).await
        }

        fn network(&self) -> BitcoinChain {
            self.inner.network()
        }
    }

    pub struct HiddenLiquid {
        pub inner: ElectrumLiquidClient,
        pub visible: Arc<AtomicBool>,
    }

    #[macros::async_trait]
    impl LiquidClient for HiddenLiquid {
        async fn get_address_utxo(
            &self,
            address: &elements::Address,
        ) -> Result<Option<(elements::OutPoint, elements::TxOut)>, Error> {
            if !self.visible.load(Ordering::SeqCst) {
                return Ok(None);
            }
            self.inner.get_address_utxo(address).await
        }

        async fn get_genesis_hash(&self) -> Result<elements::BlockHash, Error> {
            self.inner.get_genesis_hash().await
        }

        async fn get_tx(&self, txid: elements::Txid) -> Result<elements::Transaction, Error> {
            self.inner.get_tx(txid).await
        }

        async fn broadcast_tx(&self, signed_tx: &elements::Transaction) -> Result<String, Error> {
            self.inner.broadcast_tx(signed_tx).await
        }

        fn network(&self) -> LiquidChain {
            self.inner.network()
        }
    }
}

/// A claim takes Boltz's lockup only from our own chain client: while the
/// client cannot see it, the claim fails even though Boltz has reported the
/// lockup; once the client sees it, the same claim goes through.
#[cfg(feature = "electrum")]
async fn claim_waits_for_own_lockup(chain: Chain) {
    use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
    use hidden_lockup::{HiddenBitcoin, HiddenLiquid};
    use std::sync::atomic::{AtomicBool, Ordering};

    let visible = Arc::new(AtomicBool::new(false));
    let chain_client = ChainClient::new()
        .with_bitcoin(HiddenBitcoin {
            inner: ElectrumBitcoinClient::default(BTC_CHAIN, None).unwrap(),
            visible: visible.clone(),
        })
        .with_liquid(HiddenLiquid {
            inner: ElectrumLiquidClient::default(LBTC_CHAIN, None).unwrap(),
            visible: visible.clone(),
        });

    let secp = Secp256k1::new();
    let preimage = Preimage::random();
    let our_keys = Keypair::new(&secp, &mut thread_rng());
    let claim_public_key = PublicKey {
        compressed: true,
        inner: our_keys.public_key(),
    };
    let claim_address = utils::generate_address(chain).await.unwrap();
    let addrs_sig = sign_address(&claim_address, &our_keys).unwrap();
    let create_reverse_req = CreateReverseRequest {
        from: "BTC".to_string(),
        to: chain.to_string(),
        invoice: None,
        invoice_amount: Some(100000),
        preimage_hash: Some(preimage.sha256),
        description: None,
        description_hash: None,
        address_signature: Some(addrs_sig.to_string()),
        address: Some(claim_address.clone()),
        claim_public_key,
        referral_id: None,
        webhook: None,
    };

    let boltz_api_v2 = create_boltz_api();
    let ws_api = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));
    utils::start_ws(ws_api.clone());

    let reverse_resp = boltz_api_v2
        .post_reverse_req(create_reverse_req)
        .await
        .unwrap();
    reverse_resp
        .validate(&preimage, &claim_public_key, chain)
        .unwrap();

    let swap_script =
        SwapScript::reverse_from_swap_resp(chain, &reverse_resp, claim_public_key).unwrap();
    let swap_id = reverse_resp.id.clone();

    ws_api.subscribe_swap(&swap_id).await.unwrap();
    let mut updates = ws_api.updates();

    next_status(&mut updates, "swap.created").await.unwrap();
    utils::start_pay_invoice_lnd(reverse_resp.invoice.clone().unwrap());
    next_status(&mut updates, "transaction.mempool")
        .await
        .unwrap();

    let claim_address = utils::generate_address(chain).await.unwrap();
    let params = SwapTransactionParams {
        swap_id: swap_id.clone(),
        keys: our_keys,
        fee: Fee::Absolute(200),
        output_address: claim_address,
        chain_client: &chain_client,
        boltz_client: &boltz_api_v2,
        options: None,
    };

    let err = swap_script
        .construct_claim(&preimage, params.clone())
        .await
        .expect_err("a lockup our chain client cannot see must not be claimed");
    let expected = match chain {
        Chain::Bitcoin(_) => "electrum unavailable",
        Chain::Liquid(_) => "Lockup UTXO not yet visible to the chain client",
    };
    assert_eq!(err.message(), expected);

    visible.store(true, Ordering::SeqCst);
    let mut attempts = 0;
    let tx = loop {
        match swap_script.construct_claim(&preimage, params.clone()).await {
            Ok(tx) => break tx,
            Err(e) if attempts < 10 => {
                log::debug!("Lockup not indexed yet: {e:?}");
                attempts += 1;
                boltz_client::util::sleep(super::WAIT_TIME).await;
            }
            Err(e) => panic!("claim failed once the lockup was visible: {e:?}"),
        }
    };

    chain_client.broadcast_tx(&tx).await.unwrap();

    next_status(&mut updates, "invoice.settled").await.unwrap();
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_v2_reverse_claim_waits_for_own_lockup() {
    setup_logger();
    claim_waits_for_own_lockup(BTC_CHAIN.into()).await;
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_v2_reverse_claim_waits_for_own_lockup() {
    setup_logger();
    claim_waits_for_own_lockup(LBTC_CHAIN.into()).await;
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn bitcoin_v2_reverse_electrum() {
    setup_logger();
    let chain_client = create_chain_client_electrum();
    swap(BTC_CHAIN.into(), &chain_client, false).await;
    swap(BTC_CHAIN.into(), &chain_client, true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn bitcoin_v2_reverse_esplora() {
    setup_logger();
    let chain_client = create_chain_client_esplora();
    swap(BTC_CHAIN.into(), &chain_client, false).await;
    swap(BTC_CHAIN.into(), &chain_client, true).await;
}

#[macros::async_test]
#[serial]
#[cfg(feature = "electrum")]
async fn liquid_v2_reverse_electrum() {
    setup_logger();
    let chain_client = create_chain_client_electrum();
    swap(LBTC_CHAIN.into(), &chain_client, false).await;
    swap(LBTC_CHAIN.into(), &chain_client, true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_v2_reverse_esplora() {
    setup_logger();
    let chain_client = create_chain_client_esplora();
    swap(LBTC_CHAIN.into(), &chain_client, false).await;
    swap(LBTC_CHAIN.into(), &chain_client, true).await;
}

#[macros::async_test_all]
#[serial]
#[cfg(feature = "esplora")]
async fn liquid_v2_mrh() {
    setup_logger();
    let chain_client = create_chain_client_esplora();
    swap_mrh(LBTC_CHAIN.into(), &chain_client).await;
}
