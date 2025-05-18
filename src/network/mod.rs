use core::fmt;

use crate::error::Error;
use bitcoin::Network;
use elements::AddressParams;

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

impl From<BitcoinChain> for Network {
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

impl From<LiquidChain> for &'static AddressParams {
    fn from(value: LiquidChain) -> Self {
        match value {
            LiquidChain::Liquid => &AddressParams::LIQUID,
            LiquidChain::LiquidTestnet => &AddressParams::LIQUID_TESTNET,
            LiquidChain::LiquidRegtest => &AddressParams::ELEMENTS,
        }
    }
}

#[macros::async_trait]
pub trait BitcoinClient {
    async fn get_address_balance(&self, address: &bitcoin::Address) -> Result<(u64, i64), Error>;

    async fn get_address_utxos(
        &self,
        address: &bitcoin::Address,
    ) -> Result<Vec<(bitcoin::OutPoint, bitcoin::TxOut)>, Error>;

    async fn broadcast_tx(&self, signed_tx: &bitcoin::Transaction) -> Result<bitcoin::Txid, Error>;

    fn network(&self) -> BitcoinChain;
}

#[macros::async_trait]
pub trait LiquidClient {
    async fn get_address_utxo(
        &self,
        address: &elements::Address,
    ) -> Result<Option<(elements::OutPoint, elements::TxOut)>, Error>;

    async fn get_genesis_hash(&self) -> Result<elements::BlockHash, Error>;

    async fn broadcast_tx(&self, signed_tx: &elements::Transaction) -> Result<String, Error>;

    fn network(&self) -> LiquidChain;
}
