//! Bounds on the HTLC timeouts Boltz chooses, checked against the current
//! tip of the chain the HTLC lives on.
//!
//! Boltz's own timeouts are one day for a lockup it funds (reverse swaps and
//! the server side of chain swaps) and up to seven days for a lockup the user
//! funds (Taproot submarine swaps). A lockup Boltz funds must leave the user
//! time to claim before Boltz can refund it; a lockup the user funds must not
//! keep the user's coins from a refund for longer than Boltz ever needs.

use crate::error::Error;
use crate::network::Chain;

/// Least time left on a lockup Boltz funds: six hours.
const MIN_CLAIM_WINDOW_MINUTES: u32 = 6 * 60;
/// Most time a user's lockup may wait for its refund: fourteen days.
const MAX_REFUND_WAIT_MINUTES: u32 = 14 * 24 * 60;

fn block_minutes(chain: Chain) -> u32 {
    match chain {
        Chain::Bitcoin(_) => 10,
        Chain::Liquid(_) => 1,
    }
}

/// Checks the timeout of a lockup Boltz funds and the user claims.
pub fn validate_claim_timeout(chain: Chain, timeout: u32, tip: u32) -> Result<(), Error> {
    let min_blocks = MIN_CLAIM_WINDOW_MINUTES / block_minutes(chain);
    if timeout < tip.saturating_add(min_blocks) {
        return Err(Error::Protocol(format!(
            "Timeout too close: {timeout} at tip {tip} leaves less than {min_blocks} blocks to claim"
        )));
    }
    Ok(())
}

/// Checks the timeout of a lockup the user funds and refunds after it.
pub fn validate_refund_timeout(chain: Chain, timeout: u32, tip: u32) -> Result<(), Error> {
    let max_blocks = MAX_REFUND_WAIT_MINUTES / block_minutes(chain);
    if timeout <= tip {
        return Err(Error::Protocol(format!(
            "Timeout already passed: {timeout} at tip {tip}"
        )));
    }
    if timeout > tip.saturating_add(max_blocks) {
        return Err(Error::Protocol(format!(
            "Timeout too far: {timeout} at tip {tip} is more than {max_blocks} blocks away"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{BitcoinChain, LiquidChain};

    const BTC: Chain = Chain::Bitcoin(BitcoinChain::Bitcoin);
    const LBTC: Chain = Chain::Liquid(LiquidChain::Liquid);

    #[test]
    fn claim_timeout_needs_six_hours() {
        assert!(validate_claim_timeout(BTC, 1_000 + 144, 1_000).is_ok());
        assert!(validate_claim_timeout(BTC, 1_000 + 36, 1_000).is_ok());
        assert!(validate_claim_timeout(BTC, 1_000 + 35, 1_000).is_err());
        assert!(validate_claim_timeout(LBTC, 1_000 + 1_440, 1_000).is_ok());
        assert!(validate_claim_timeout(LBTC, 1_000 + 359, 1_000).is_err());
    }

    #[test]
    fn refund_timeout_waits_at_most_fourteen_days() {
        assert!(validate_refund_timeout(BTC, 1_000 + 1_008, 1_000).is_ok());
        assert!(validate_refund_timeout(BTC, 1_000 + 2_016, 1_000).is_ok());
        assert!(validate_refund_timeout(BTC, 1_000 + 2_017, 1_000).is_err());
        assert!(validate_refund_timeout(LBTC, 1_000 + 10_080, 1_000).is_ok());
        assert!(validate_refund_timeout(LBTC, 1_000 + 20_161, 1_000).is_err());
    }

    #[test]
    fn refund_timeout_must_lie_ahead() {
        assert!(validate_refund_timeout(BTC, 1_000, 1_000).is_err());
        assert!(validate_refund_timeout(BTC, 999, 1_000).is_err());
    }
}
