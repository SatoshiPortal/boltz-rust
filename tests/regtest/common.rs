use boltz_client::swaps::ChainClient;
use boltz_client::util::sleep;
use boltz_client::{
    boltz::{BoltzApiClientV2, SwapStatus, BOLTZ_REGTEST},
    network::{BitcoinChain, LiquidChain},
};
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
            Err(anyhow::anyhow!("Timeout waiting for status: {}", expected_status))
        }
    }
}
