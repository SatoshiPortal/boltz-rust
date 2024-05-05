pub mod electrum;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Bitcoin,
    BitcoinTestnet,
    BitcoinRegtest,
    Liquid,
    LiquidTestnet,
    LiquidRegtest,
}
