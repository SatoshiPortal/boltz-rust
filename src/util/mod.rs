use std::{env, str::FromStr, sync::Once};

use bitcoin::amount;
use electrum_client::ElectrumApi;
use elements::{encode::Decodable, hex::ToHex};
use lightning_invoice::{Bolt11Invoice, RouteHintHop};

use crate::{error::Error, network::electrum::ElectrumConfig};

pub mod ec;
pub mod lnurl;
pub mod secrets;

/// Setup function that will only run once, even if called multiple times.

pub fn liquid_genesis_hash(electrum_config: &ElectrumConfig) -> Result<elements::BlockHash, Error> {
    let electrum = electrum_config.build_client()?;
    // println!("ELECTRUM NETWORK: {:?}", electrum_config.network());

    let response = electrum.block_header_raw(0)?;
    // println!("{:#?}", response);
    let block_header = elements::BlockHeader::consensus_decode(&*response)?;
    // println!("{:#?}", block_header);

    Ok(elements::BlockHash::from_raw_hash(
        block_header.block_hash().into(),
    ))
}

pub fn setup_logger() {
    Once::new().call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default()
                .default_filter_or("debug")
                .default_write_style_or("always"),
        )
        // .is_test(true)
        .init();
    });
}
