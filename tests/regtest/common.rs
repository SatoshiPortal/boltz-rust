use boltz_client::swaps::{BtcLikeTransaction, ChainClient};
use boltz_client::util::sleep;
use boltz_client::{
    boltz::{BoltzApiClientV2, SwapStatus, BOLTZ_REGTEST},
    network::{BitcoinChain, Chain, LiquidChain},
};
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::broadcast::Receiver;

pub const BTC_CHAIN: BitcoinChain = BitcoinChain::BitcoinRegtest;
pub const LBTC_CHAIN: LiquidChain = LiquidChain::LiquidRegtest;

// Create default Boltz API client
pub fn create_boltz_api() -> BoltzApiClientV2 {
    BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), Some(super::BOLTZ_TIMEOUT))
}

#[cfg(feature = "electrum")]
pub fn create_chain_client_electrum() -> ChainClient {
    use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};

    ChainClient::new()
        .with_bitcoin(ElectrumBitcoinClient::default(BTC_CHAIN, None).unwrap())
        .with_liquid(ElectrumLiquidClient::default(LBTC_CHAIN, None).unwrap())
}

#[cfg(feature = "esplora")]
pub fn create_chain_client_esplora() -> ChainClient {
    use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};

    ChainClient::new()
        .with_bitcoin(EsploraBitcoinClient::default(BTC_CHAIN, None))
        .with_liquid(EsploraLiquidClient::default(LBTC_CHAIN, None))
}

/// Assert the multi-output layout of a wrapper-built transaction: the primary
/// output receives the remainder (input - fee - sum of additional outputs) and
/// each additional output pays its fixed amount, in order. On Bitcoin the
/// primary is output 0; on Liquid claims order [primary, additions.., fee] and
/// refunds [fee, primary, additions..]. Liquid outputs are unblinded with the
/// node's blinding keys and checked for value and asset.
pub async fn assert_multi_output_tx(
    tx: &BtcLikeTransaction,
    chain: Chain,
    is_claim: bool,
    primary_address: &str,
    additional: &[(String, u64)],
    input_amount: u64,
    absolute_fee: u64,
) {
    let total_additional: u64 = additional.iter().map(|(_, amount)| amount).sum();
    let expected_primary = input_amount - absolute_fee - total_additional;

    match chain {
        Chain::Bitcoin(_) => {
            let tx = tx.as_bitcoin().unwrap();
            assert_eq!(tx.output.len(), 1 + additional.len());

            let primary_spk = bitcoin::Address::from_str(primary_address)
                .unwrap()
                .assume_checked()
                .script_pubkey();
            assert_eq!(tx.output[0].script_pubkey, primary_spk);
            assert_eq!(tx.output[0].value.to_sat(), expected_primary);

            for (i, (address, amount)) in additional.iter().enumerate() {
                let spk = bitcoin::Address::from_str(address)
                    .unwrap()
                    .assume_checked()
                    .script_pubkey();
                assert_eq!(tx.output[1 + i].script_pubkey, spk);
                assert_eq!(tx.output[1 + i].value.to_sat(), *amount);
            }
        }
        Chain::Liquid(liquid_chain) => {
            let tx = tx.as_liquid().unwrap();
            assert_eq!(tx.output.len(), 2 + additional.len());

            let (fee_index, primary_index, additional_offset) = if is_claim {
                (1 + additional.len(), 0, 1)
            } else {
                (0, 1, 2)
            };
            assert!(tx.output[fee_index].is_fee());
            assert_eq!(tx.output[fee_index].value.explicit().unwrap(), absolute_fee);

            let expected_asset = liquid_chain.bitcoin();
            let primary = unblind_liquid_output(tx, primary_index, chain, primary_address).await;
            assert_eq!(primary.value, expected_primary);
            assert_eq!(primary.asset, expected_asset);

            for (i, (address, amount)) in additional.iter().enumerate() {
                let secrets =
                    unblind_liquid_output(tx, additional_offset + i, chain, address).await;
                assert_eq!(secrets.value, *amount);
                assert_eq!(secrets.asset, expected_asset);
            }
        }
    }
}

/// Check the output at `index` pays `address` and unblind it with the node
/// wallet's blinding key.
async fn unblind_liquid_output(
    tx: &elements::Transaction,
    index: usize,
    chain: Chain,
    address: &str,
) -> elements::TxOutSecrets {
    let addr = elements::Address::from_str(address).unwrap();
    assert_eq!(tx.output[index].script_pubkey, addr.script_pubkey());

    let blinding_key = crate::utils::get_blinding_key(chain, address)
        .await
        .unwrap();
    let blinding_sk = elements::secp256k1_zkp::SecretKey::from_str(&blinding_key).unwrap();
    tx.output[index]
        .unblind(&elements::secp256k1_zkp::Secp256k1::new(), blinding_sk)
        .unwrap()
}

pub async fn next_status(
    updates: &mut Receiver<SwapStatus>,
    expected_status: &str,
) -> Result<boltz_client::boltz::SwapStatus, anyhow::Error> {
    tokio::select! {
        result = async {
            loop {
                let update = updates.recv().await?;
                log::info!("Waiting for status: {}", update.status);
                if update.status == expected_status {
                    return Ok(update);
                }
            }
        } => result,
        _ = sleep(Duration::from_secs(10)) => {
            Err(anyhow::anyhow!("Timeout waiting for status: {expected_status}"))
        }
    }
}
