//! A boltz client for submarine/reverse swaps between Bitcoin, Lightning & Liquid
//! Refer to tests/ folder for usage

pub mod network;
pub mod swaps;
pub mod util;

pub use bitcoin::secp256k1::{KeyPair, Secp256k1};
pub use elements::secp256k1_zkp::{Keypair as ZKKeyPair, Secp256k1 as ZKSecp256k1};
pub use lightning_invoice::Bolt11Invoice;
