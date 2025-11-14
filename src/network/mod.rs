use core::fmt;
use std::str::FromStr;

use crate::error::Error;
use elements::{AddressParams, AssetId};

#[cfg(feature = "electrum")]
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub mod electrum;

#[cfg(feature = "esplora")]
pub mod esplora;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Bitcoin(BitcoinChain),
    Liquid(LiquidChain),
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chain::Bitcoin(_) => write!(f, "BTC"),
            Chain::Liquid(_) => write!(f, "L-BTC"),
        }
    }
}

impl From<BitcoinChain> for Chain {
    fn from(value: BitcoinChain) -> Self {
        Chain::Bitcoin(value)
    }
}

impl From<LiquidChain> for Chain {
    fn from(value: LiquidChain) -> Self {
        Chain::Liquid(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitcoinChain {
    Bitcoin,
    BitcoinTestnet,
    BitcoinRegtest,
}

impl From<BitcoinChain> for bitcoin::Network {
    fn from(value: BitcoinChain) -> Self {
        match value {
            BitcoinChain::Bitcoin => Self::Bitcoin,
            BitcoinChain::BitcoinTestnet => Self::Testnet,
            BitcoinChain::BitcoinRegtest => Self::Regtest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiquidChain {
    Liquid,
    LiquidTestnet,
    LiquidRegtest,
}

const ASSET_ID_REGTEST: &str = "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
const ASSET_ID_TESTNET: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

impl LiquidChain {
    pub fn bitcoin(self) -> AssetId {
        match self {
            LiquidChain::Liquid => AssetId::LIQUID_BTC,
            LiquidChain::LiquidTestnet => AssetId::from_str(ASSET_ID_TESTNET).unwrap(),
            LiquidChain::LiquidRegtest => AssetId::from_str(ASSET_ID_REGTEST).unwrap(),
        }
    }
}

impl From<LiquidChain> for &'static AddressParams {
    fn from(value: LiquidChain) -> Self {
        match value {
            LiquidChain::Liquid => &AddressParams::LIQUID,
            LiquidChain::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
            LiquidChain::LiquidRegtest => &AddressParams::ELEMENTS,
        }
    }
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl From<Network> for BitcoinChain {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => BitcoinChain::Bitcoin,
            Network::Testnet => BitcoinChain::BitcoinTestnet,
            Network::Regtest => BitcoinChain::BitcoinRegtest,
        }
    }
}

impl From<Network> for LiquidChain {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => LiquidChain::Liquid,
            Network::Testnet => LiquidChain::LiquidTestnet,
            Network::Regtest => LiquidChain::LiquidRegtest,
        }
    }
}

impl From<Network> for bitcoin::Network {
    fn from(value: Network) -> Self {
        match value {
            Network::Mainnet => Self::Bitcoin,
            Network::Testnet => Self::Testnet,
            Network::Regtest => Self::Regtest,
        }
    }
}

impl From<Chain> for Network {
    fn from(value: Chain) -> Self {
        match value {
            Chain::Bitcoin(_) => Network::Mainnet,
            Chain::Liquid(_) => Network::Mainnet,
        }
    }
}

#[macros::async_trait]
pub trait BitcoinClient: Send + Sync {
    async fn get_address_balance(&self, address: &bitcoin::Address) -> Result<(u64, i64), Error>;

    async fn get_address_utxos(
        &self,
        address: &bitcoin::Address,
    ) -> Result<Vec<(bitcoin::OutPoint, bitcoin::TxOut)>, Error>;

    async fn broadcast_tx(&self, signed_tx: &bitcoin::Transaction) -> Result<bitcoin::Txid, Error>;

    fn network(&self) -> BitcoinChain;
}

#[macros::async_trait]
pub trait LiquidClient: Send + Sync {
    async fn get_address_utxo(
        &self,
        address: &elements::Address,
    ) -> Result<Option<(elements::OutPoint, elements::TxOut)>, Error>;

    async fn get_genesis_hash(&self) -> Result<elements::BlockHash, Error>;

    async fn broadcast_tx(&self, signed_tx: &elements::Transaction) -> Result<String, Error>;

    fn network(&self) -> LiquidChain;
}
