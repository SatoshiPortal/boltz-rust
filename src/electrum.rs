use crate::error::Error;
use elements::bitcoin::hashes::hex::FromHex;

// TODO: policy asset should only be set for ElementsRegtest, fail otherwise
const LIQUID_POLICY_ASSET_STR: &str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
const LIQUID_TESTNET_POLICY_ASSET_STR: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

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
    pub fn build_client(&self) -> Result<electrum_client::Client, Error> {
        let builder = electrum_client::ConfigBuilder::new();
        let (url, builder) = match self {
            ElectrumUrl::Tls(url, validate) => {
                (format!("ssl://{}", url), builder.validate_domain(*validate))
            }
            ElectrumUrl::Plaintext(url) => (format!("tcp://{}", url), builder),
        };
        Ok(electrum_client::Client::from_config(&url, builder.build())?)
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    network: BitcoinNetwork,
    policy_asset: Option<elements::issuance::AssetId>,
    electrum_url: ElectrumUrl,
    pub spv_enabled: bool,
}

impl Config {
    pub fn new(
        network: BitcoinNetwork,
        tls: bool,
        validate_domain: bool,
        spv_enabled: bool,
        electrum_url: &str,
        policy_asset: Option<&str>,
    ) -> Result<Self, Error> {
        let electrum_url = match tls {
            true => ElectrumUrl::Tls(electrum_url.into(), validate_domain),
            false => ElectrumUrl::Plaintext(electrum_url.into()),
        };
        Ok(Config {
            network: network,
            electrum_url,
            spv_enabled,
            policy_asset: match policy_asset{
                Ok(policy_asset)=>Some(elements::issuance::AssetId::from_hex(policy_asset)?),
                Err(_)=>None,
            }
        })
    }

    pub fn network(&self) -> BitcoinNetwork {
        self.network
    }

    pub fn policy_asset(&self) -> elements::issuance::AssetId {
        self.policy_asset
    }

    pub fn electrum_url(&self) -> ElectrumUrl {
        self.electrum_url.clone()
    }
}