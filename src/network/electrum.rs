// use electrum_client::raw_client::RawClient;

use crate::error::Error;

use super::Chain;

pub const DEFAULT_TESTNET_NODE: &str = "electrum.bullbitcoin.com:60002";
pub const DEFAULT_LIQUID_TESTNET_NODE: &str = "blockstream.info:465";
pub const DEFAULT_MAINNET_NODE: &str = "electrum.blockstream.info:50002";
pub const DEFAULT_LIQUID_MAINNET_NODE: &str = "blockstream.info:995";
pub const DEFAULT_ELECTRUM_TIMEOUT: u8 = 10;

#[derive(Debug, Clone)]
enum ElectrumUrl {
    Tls(String, bool), // the bool value indicates if the domain name should be validated
    Plaintext(String),
}

impl ElectrumUrl {
    pub fn build_client(&self, timeout: u8) -> Result<electrum_client::Client, Error> {
        let builder = electrum_client::ConfigBuilder::new();
        let builder = builder.timeout(Some(timeout));
        let (url, builder) = match self {
            ElectrumUrl::Tls(url, validate) => {
                (format!("ssl://{}", url), builder.validate_domain(*validate))
            }
            ElectrumUrl::Plaintext(url) => (format!("tcp://{}", url), builder),
        };
        Ok(electrum_client::Client::from_config(&url, builder.build())?)
    }
}

/// Electrum client configuration.
#[derive(Debug, Clone)]
pub struct ElectrumConfig {
    network: Chain,
    url: ElectrumUrl,
    timeout: u8,
}

impl ElectrumConfig {
    pub fn default(chain: Chain, regtest_url: Option<String>) -> Result<Self, Error> {
        if (chain == Chain::LiquidRegtest || chain == Chain::BitcoinRegtest)
            && regtest_url.is_none()
        {
            return Err(Error::Electrum(electrum_client::Error::Message(
                "Regtest requires using a custom url".to_string(),
            )));
        }
        match chain {
            Chain::Bitcoin => Ok(ElectrumConfig::new(
                Chain::Bitcoin,
                DEFAULT_MAINNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            )),
            Chain::BitcoinTestnet => Ok(ElectrumConfig::new(
                Chain::BitcoinTestnet,
                DEFAULT_TESTNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            )),
            Chain::BitcoinRegtest => Ok(ElectrumConfig::new(
                Chain::BitcoinTestnet,
                &regtest_url.unwrap(),
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            )),
            Chain::Liquid => Ok(ElectrumConfig::new(
                Chain::Liquid,
                DEFAULT_LIQUID_MAINNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            )),
            Chain::LiquidTestnet => Ok(ElectrumConfig::new(
                Chain::LiquidTestnet,
                DEFAULT_LIQUID_TESTNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            )),
            Chain::LiquidRegtest => Ok(ElectrumConfig::new(
                Chain::BitcoinTestnet,
                &regtest_url.unwrap(),
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            )),
        }
    }

    pub fn default_bitcoin() -> Self {
        ElectrumConfig::new(
            Chain::BitcoinTestnet,
            DEFAULT_TESTNET_NODE,
            true,
            true,
            DEFAULT_ELECTRUM_TIMEOUT,
        )
    }
    pub fn default_liquid() -> Self {
        ElectrumConfig::new(
            Chain::Liquid,
            DEFAULT_MAINNET_NODE,
            true,
            true,
            DEFAULT_ELECTRUM_TIMEOUT,
        )
    }
    pub fn new(
        network: Chain,
        electrum_url: &str,
        tls: bool,
        validate_domain: bool,
        timeout: u8,
    ) -> Self {
        let electrum_url = match tls {
            true => ElectrumUrl::Tls(electrum_url.into(), validate_domain),
            false => ElectrumUrl::Plaintext(electrum_url.into()),
        };
        ElectrumConfig {
            network: network.clone(),
            url: electrum_url,
            timeout: timeout,
        }
    }
    // Get a copy of the network (Chain) field.
    pub fn network(&self) -> Chain {
        self.network.clone()
    }
    /// Builds an electrum_client::Client which can be used to make calls to electrum api
    pub fn build_client(&self) -> Result<electrum_client::Client, Error> {
        self.url.clone().build_client(self.timeout)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use electrum_client::ElectrumApi;

    #[test]
    fn test_electrum_default_clients() {
        let network_config = ElectrumConfig::default_bitcoin();
        let electrum_client = network_config.build_client().unwrap();
        assert!(electrum_client.ping().is_ok());

        let network_config = ElectrumConfig::default_liquid();
        let electrum_client = network_config.build_client().unwrap();
        assert!(electrum_client.ping().is_ok());
    }

    #[test]
    #[ignore]
    fn test_raw_electrum_calls() {
        let network_config = ElectrumConfig::default_bitcoin();
        let electrum_client = network_config.build_client().unwrap();
        let numblocks = "blockchain.numblocks.subscribe";
        let blockheight = electrum_client.raw_call(numblocks, []).unwrap();
        println!("blockheight: {}", blockheight);
    }
}
