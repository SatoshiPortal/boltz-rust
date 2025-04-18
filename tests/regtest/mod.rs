#![cfg(feature = "regtest")]

use std::time::Duration;

mod bitcoin;
mod chain_swaps;
mod liquid;

const WAIT_TIME: Duration = Duration::from_millis(5_000);
