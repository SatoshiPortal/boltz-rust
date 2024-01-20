//! A boltz client for submarine/reverse swaps between Bitcoin, Lightning & Liquid
//! Refer to tests/ folder for usage
//! THIS LIBRARY IS IN EARLY ALPHA. DO NOT USE ON MAINNET.

pub mod network;
/// core swap logic
pub mod swaps;
/// utilities (key, preimage, error)
pub mod util;

pub use bitcoin::secp256k1::{Keypair, Secp256k1};
pub use elements::secp256k1_zkp::{Keypair as ZKKeyPair, Secp256k1 as ZKSecp256k1};
pub use lightning_invoice::Bolt11Invoice;
