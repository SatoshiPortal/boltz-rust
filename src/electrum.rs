use crate::e::{ErrorKind, S5Error};
use elements::bitcoin::hashes::hex::FromHex;

// TODO: policy asset should only be set for ElementsRegtest, fail otherwise
const LIQUID_POLICY_ASSET_STR: &str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
const LIQUID_TESTNET_POLICY_ASSET_STR: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

pub const DEFAULT_TESTNET_NODE: &str = "electrum.bullbitcoin.com:60002";
pub const DEFAULT_MAINNET_NODE: &str = "electrum.bullbitcoin.com:50002";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Bitcoin,
    BitcoinTestnet,
    Liquid,
    LiquidTestnet,
    ElementsRegtest,
}

#[derive(Debug, Clone)]
pub enum ElectrumUrl {
    Tls(String, bool), // the bool value indicates if the domain name should be validated
    Plaintext(String),
}

impl ElectrumUrl {
    pub fn build_client(&self) -> Result<electrum_client::Client, S5Error> {
        let builder = electrum_client::ConfigBuilder::new();
        let (url, builder) = match self {
            ElectrumUrl::Tls(url, validate) => {
                (format!("ssl://{}", url), builder.validate_domain(*validate))
            }
            ElectrumUrl::Plaintext(url) => (format!("tcp://{}", url), builder),
        };
        Ok(electrum_client::Client::new(&url).unwrap())
    }
}

#[derive(Debug, Clone)]
pub struct NetworkConfig {
    pub network: BitcoinNetwork,
    pub electrum_url: ElectrumUrl,
    pub spv_enabled: bool,
    _policy_asset: Option<elements::issuance::AssetId>,
}

impl NetworkConfig {
    pub fn new(
        network: BitcoinNetwork,
        electrum_url: &str,
        tls: bool,
        validate_domain: bool,
        spv_enabled: bool,
        policy_asset: Option<&str>,
    ) -> Result<Self, S5Error> {
        let electrum_url = match tls {
            true => ElectrumUrl::Tls(electrum_url.into(), validate_domain),
            false => ElectrumUrl::Plaintext(electrum_url.into()),
        };
        Ok(NetworkConfig {
            network: network,
            electrum_url,
            spv_enabled,
            _policy_asset: match policy_asset{
                Some(policy_asset)=>Some(elements::issuance::AssetId::from_slice(&hex::decode(policy_asset).unwrap()).unwrap()),
                None=>None,
            }
        })
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    pub fn electrum_url(&self) -> ElectrumUrl {
        self.electrum_url.clone()
    }
}

#[cfg(test)]
mod tests {
    use electrum_client::ElectrumApi;
    use super::*;

    #[test]
    fn test_electrum_client(){
        let network_config = NetworkConfig::new(
            BitcoinNetwork::BitcoinTestnet,
            DEFAULT_TESTNET_NODE,
            true,
            true,
            false,
            None,
        ).unwrap();

        let electrum_client = network_config.electrum_url.build_client().unwrap();
        assert!(electrum_client.ping().is_ok());
        // let res = client.server_features();
        // println!("chain genesis block: {:#?}", res.genesis_block);
    }
}