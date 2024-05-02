use std::{env, str::FromStr, sync::Once};

use electrum_client::ElectrumApi;
use elements::{encode::Decodable, hex::ToHex};
use lightning_invoice::{Bolt11Invoice, RouteHintHop};

use crate::{error::Error, network::electrum::ElectrumConfig};

pub mod ec;
pub mod secrets;

const ENDPOINT: &str = "https://api.testnet.boltz.exchange";
const MAGIC_ROUTING_HINT_CONSTANT: &str = "0846c900051c0000";
const LBTC_ASSET_HASH: &str = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";

/// Setup function that will only run once, even if called multiple times.

pub fn liquid_genesis_hash(electrum_config: &ElectrumConfig) -> Result<elements::BlockHash, Error> {
    let electrum = electrum_config.build_client()?;
    println!("ELECTRUM NETWORK: {:?}", electrum_config.network());

    let response = electrum.block_header_raw(0)?;
    println!("{:#?}", response);
    let block_header = elements::BlockHeader::consensus_decode(&*response)?;
    println!("{:#?}", block_header);

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

/// Decodes the provided invoice to find the magic routing hint.
pub fn find_magic_routing_hint(invoice: &str) -> Result<Option<RouteHintHop>, Error> {
    let invoice = Bolt11Invoice::from_str(&invoice)?;
    Ok(invoice
        .private_routes()
        .iter()
        .map(|route| &route.0)
        .flatten()
        .find(|hint| hint.short_channel_id.to_hex() == MAGIC_ROUTING_HINT_CONSTANT)
        .cloned())
}
