use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::network::{BitcoinChain, Chain, LiquidChain, Network};
use boltz_client::swaps::ChainClient as CoreClient;

use crate::boltz::Error;
use crate::swap::BtcLikeTransaction;

#[uniffi::remote(Enum)]
pub enum Network {
    Regtest,
    Testnet,
    Mainnet,
}

#[uniffi::remote(Enum)]
pub enum LiquidChain {
    Liquid,
    LiquidTestnet,
    LiquidRegtest,
}

#[uniffi::remote(Enum)]
pub enum BitcoinChain {
    Bitcoin,
    BitcoinTestnet,
    BitcoinRegtest,
}

#[uniffi::remote(Enum)]
pub enum Chain {
    Bitcoin(BitcoinChain),
    Liquid(LiquidChain),
}

#[derive(uniffi::Record)]
pub struct EsploraBuilder {
    pub url: String,
    #[uniffi(default = 30)]
    pub timeout: u64,
}

#[derive(uniffi::Record)]
pub struct ElectrumBuilder {
    pub url: String,
    pub tls: bool,
    #[uniffi(default = 10)]
    pub timeout: u8,
    #[uniffi(default = true)]
    pub validate_domain: bool,
}

#[derive(uniffi::Enum)]
pub enum ClientConnection {
    Esplora(EsploraBuilder),
    Electrum(ElectrumBuilder),
}

#[derive(uniffi::Record)]
pub struct ClientConfig {
    pub network: Network,
    pub bitcoin: Option<ClientConnection>,
    pub liquid: Option<ClientConnection>,
}

#[uniffi::export]
pub fn btc_chain_from_network(network: Network) -> Chain {
    let btc_chain: BitcoinChain = network.into();
    btc_chain.into()
}

#[uniffi::export]
pub fn lbtc_chain_from_network(network: Network) -> Chain {
    let lbtc_chain: LiquidChain = network.into();
    lbtc_chain.into()
}

#[derive(uniffi::Object)]
pub struct ChainClient(pub(crate) CoreClient);

#[uniffi::export]
impl ChainClient {
    #[uniffi::constructor]
    pub fn new(config: ClientConfig) -> Result<Self, Error> {
        let mut client = CoreClient::new();
        if let Some(connection) = config.bitcoin {
            client = match connection {
                ClientConnection::Esplora(esplora) => client.with_bitcoin(
                    EsploraBitcoinClient::new(config.network.into(), &esplora.url, esplora.timeout),
                ),
                ClientConnection::Electrum(electrum) => client.with_bitcoin(
                    ElectrumBitcoinClient::new(
                        config.network.into(),
                        &electrum.url,
                        electrum.tls,
                        electrum.validate_domain,
                        electrum.timeout,
                    )
                    .map_err(|e| Error::Generic(e.to_string()))?,
                ),
            };
        };
        if let Some(connection) = config.liquid {
            client = match connection {
                ClientConnection::Esplora(esplora) => client.with_liquid(EsploraLiquidClient::new(
                    config.network.into(),
                    &esplora.url,
                    esplora.timeout,
                )),
                ClientConnection::Electrum(electrum) => client.with_liquid(
                    ElectrumLiquidClient::new(
                        config.network.into(),
                        &electrum.url,
                        electrum.tls,
                        electrum.validate_domain,
                        electrum.timeout,
                    )
                    .map_err(|e| Error::Generic(e.to_string()))?,
                ),
            };
        };
        Ok(ChainClient(client))
    }
}

#[uniffi::export]
impl ChainClient {
    #[uniffi::method]
    pub async fn broadcast_tx(&self, tx: &BtcLikeTransaction) -> Result<String, Error> {
        self.0.broadcast_tx(&tx.0).await.map_err(|e| e.into())
    }
}
