use bitcoin::Network;
use boltz_client::network::electrum::{ElectrumBitcoinClient, ElectrumLiquidClient};
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::network::{self, BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::Client as CoreClient;
use uniffi;

use crate::bitcoin::BtcLikeTransaction;
use crate::boltz::Error;

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
    pub network: Chain,
    pub url: String,
    pub timeout: u64,
}

#[derive(uniffi::Record)]
pub struct ElectrumBuilder {
    pub url: String,
    pub timeout: u8,
    pub tls: bool,
    pub validate_domain: bool,
}

#[derive(uniffi::Enum)]
pub enum ClientConnection {
    Esplora(EsploraBuilder),
    Electrum(ElectrumBuilder),
}

#[derive(uniffi::Record)]
pub struct BtcConnection {
    pub network: BitcoinChain,
    pub connection: ClientConnection,
}

#[derive(uniffi::Record)]
pub struct LiquidConnection {
    pub network: LiquidChain,
    pub connection: ClientConnection,
}

#[derive(uniffi::Record)]
pub struct ClientConfig {
    pub bitcoin: Option<BtcConnection>,
    pub liquid: Option<LiquidConnection>,
}

#[derive(uniffi::Object)]
pub struct Client(pub(crate) CoreClient);

#[uniffi::export]
impl Client {
    #[uniffi::constructor]
    pub fn new(config: ClientConfig) -> Self {
        let mut client = CoreClient::new();
        if let Some(bitcoin) = config.bitcoin {
            client = match bitcoin.connection {
                ClientConnection::Esplora(esplora) => client.with_bitcoin(
                    EsploraBitcoinClient::new(bitcoin.network, &esplora.url, esplora.timeout),
                ),
                ClientConnection::Electrum(electrum) => client.with_bitcoin(
                    ElectrumBitcoinClient::new(
                        bitcoin.network,
                        &electrum.url,
                        electrum.tls,
                        electrum.validate_domain,
                        electrum.timeout,
                    )
                    .unwrap(),
                ),
            };
        };
        if let Some(liquid) = config.liquid {
            client =
                match liquid.connection {
                    ClientConnection::Esplora(esplora) => client.with_liquid(
                        EsploraLiquidClient::new(liquid.network, &esplora.url, esplora.timeout),
                    ),
                    ClientConnection::Electrum(electrum) => client.with_liquid(
                        ElectrumLiquidClient::new(
                            liquid.network,
                            &electrum.url,
                            electrum.tls,
                            electrum.validate_domain,
                            electrum.timeout,
                        )
                        .unwrap(),
                    ),
                };
        };
        Client(client)
    }
}

#[uniffi::export]
impl Client {
    #[uniffi::method]
    pub async fn broadcast_tx(&self, tx: &BtcLikeTransaction) -> Result<String, Error> {
        self.0.broadcast_tx(&tx.0).await.map_err(|e| e.into())
    }
}

// Simplified representation for
#[derive(uniffi::Record, Debug, Clone)]
pub struct BitcoinUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: String,
}

#[derive(uniffi::Record, Debug, Clone)]
pub struct ElementsUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: String,
    pub asset: String,
}

// Helper conversion functions
#[uniffi::export]
fn bitcoin_chain_to_network_name(chain: BitcoinChain) -> String {
    let n: network::BitcoinChain = BitcoinChain::from(chain).into();
    let network: Network = n.into();
    match network {
        Network::Bitcoin => "Bitcoin".to_string(),
        Network::Testnet => "Testnet".to_string(),
        Network::Signet => "Signet".to_string(),
        Network::Regtest => "Regtest".to_string(),
        _ => "Unknown".to_string(),
    }
}

#[uniffi::export]
fn liquid_chain_to_network_name(chain: LiquidChain) -> String {
    let chain = LiquidChain::from(chain);
    match chain {
        LiquidChain::Liquid => "Liquid".to_string(),
        LiquidChain::LiquidTestnet => "Liquid Testnet".to_string(),
        LiquidChain::LiquidRegtest => "Liquid Regtest".to_string(),
    }
}

#[uniffi::export]
fn chain_to_network_name(chain: Chain) -> String {
    match chain {
        Chain::Bitcoin(btc_chain) => bitcoin_chain_to_network_name(btc_chain),
        Chain::Liquid(liquid_chain) => liquid_chain_to_network_name(liquid_chain),
    }
}
