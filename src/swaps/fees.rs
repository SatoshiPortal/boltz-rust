use bitcoin::Amount;

use crate::network::Chain;

/// Transaction sizes in virtual bytes for different swap operations
#[derive(Debug, Clone, Copy)]
pub struct TxSizes {
    /// Size of a normal (submarine) swap claim transaction
    pub normal_claim: u64,
    /// Size of a reverse swap lockup transaction
    pub reverse_lockup: u64,
    /// Size of a reverse swap claim transaction
    pub reverse_claim: u64,
}

/// Transaction sizes for Bitcoin
pub const BTC_TX_SIZES: TxSizes = TxSizes {
    normal_claim: 151,
    reverse_lockup: 154,
    reverse_claim: 111,
};

/// Transaction sizes for Liquid
pub const LIQUID_TX_SIZES: TxSizes = TxSizes {
    normal_claim: 181,
    reverse_lockup: 269,
    reverse_claim: 193,
};

/// Get transaction sizes for a given chain
fn get_tx_sizes(chain: Chain) -> TxSizes {
    match chain {
        Chain::Bitcoin(_) => BTC_TX_SIZES,
        Chain::Liquid(_) => LIQUID_TX_SIZES,
    }
}

pub fn estimate_claim_fee(chain: Chain, fee_rate: f64) -> Amount {
    let sizes = get_tx_sizes(chain);
    Amount::from_sat((sizes.reverse_claim as f64 * fee_rate).ceil() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{BitcoinChain, LiquidChain};

    #[test]
    fn test_estimate_claim_fee() {
        let fee = estimate_claim_fee(Chain::Bitcoin(BitcoinChain::Bitcoin), 1.0);
        assert_eq!(fee, Amount::from_sat(111));

        let fee = estimate_claim_fee(Chain::Liquid(LiquidChain::Liquid), 0.1);
        assert_eq!(fee, Amount::from_sat(20));
    }
}
