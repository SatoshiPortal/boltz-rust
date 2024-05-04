use std::str::FromStr;

use crate::{error::Error, network::Chain};
use bitcoin::{
    hashes::{sha256, Hash},
    hex::FromHex,
    key::{Keypair, Secp256k1},
    secp256k1::{schnorr::Signature, Message},
    PublicKey,
};
use elements::hex::ToHex;
use lightning_invoice::{Bolt11Invoice, RouteHintHop};

use super::boltzv2::BoltzApiClientV2;

const MAGIC_ROUTING_HINT_CONSTANT: u64 = 596385002596073472;
const LBTC_TESTNET_ASSET_HASH: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
const LBTC_MAINNET_ASSET_HASH: &str = "";

/// Decodes the provided invoice to find the magic routing hint.
pub fn find_magic_routing_hint(invoice: &str) -> Result<Option<RouteHintHop>, Error> {
    let invoice = Bolt11Invoice::from_str(&invoice)?;
    Ok(invoice
        .private_routes()
        .iter()
        .map(|route| &route.0)
        .flatten()
        .find(|hint| hint.short_channel_id == MAGIC_ROUTING_HINT_CONSTANT)
        .cloned())
}

/// Parse a BIP21 String and get the network, address, asset_id if present
pub fn parse_bip21(uri: &str) -> Result<(String, String, f64, Option<String>), Error> {
    let parts: Vec<&str> = uri.split('?').collect();

    let (network_address, params) = (parts[0], parts[1]);

    // Extract network and address
    let mut network_address_parts = network_address.split(':');
    let network = match network_address_parts.next() {
        Some(r) => r.into(),
        None => {
            return Err(Error::Generic(
                "Unable to extract network from bip21 string".to_string(),
            ))
        }
    };
    let address = match network_address_parts.next() {
        Some(r) => r.into(),
        None => {
            return Err(Error::Generic(
                "Unable to extract address from bip21 string".to_string(),
            ))
        }
    };

    // Parse URI parameters
    let params: Vec<&str> = params.split('&').collect();
    let mut amount = 0f64;
    let mut assetid = None::<String>;

    for param in params {
        let pair: Vec<&str> = param.split('=').collect();
        match pair[0] {
            "amount" => {
                amount = match f64::from_str(pair[1]) {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(Error::Generic(
                            "Unable to parse amount from string".to_string(),
                        ))
                    }
                }
            }
            "assetid" => assetid = Some(pair[1].into()),
            _ => {}
        }
    }

    Ok((network, address, amount, assetid))
}

/// Check for magic routing hint in invoice. If present, get the BIP21 from Boltz and verify it.
/// Returns the BIP21 (address, amount) tupple.
pub fn check_for_mrh(
    boltz_api_v2: &BoltzApiClientV2,
    invoice: &str,
    network: Chain,
) -> Result<Option<(String, f64)>, Error> {
    if let Some(route_hint) = find_magic_routing_hint(&invoice)? {
        let mrh_resp = boltz_api_v2.get_mrh_bip21(&invoice)?;

        let (network_found, address, amount, assetid) = parse_bip21(&mrh_resp.bip21)?;
        let address_hash = sha256::Hash::hash(address.as_bytes());
        let msg = Message::from_digest_slice(address_hash.as_byte_array())?;

        let receiver_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&Vec::from_hex(
            &mrh_resp.signature,
        )?)?;

        let receiver_pubkey = PublicKey::from_str(&route_hint.src_node_id.to_string())?.inner;

        let secp = Secp256k1::new();
        secp.verify_schnorr(&receiver_sig, &msg, &receiver_pubkey.x_only_public_key().0)?;

        match network {
            Chain::LiquidTestnet => {
                if assetid != Some(LBTC_TESTNET_ASSET_HASH.to_string()) {
                    return Err(Error::Protocol(
                        "Asset Id missmatch in Magic Routing Hint".to_string(),
                    ));
                }
            }

            Chain::Liquid => {
                if assetid != Some(LBTC_MAINNET_ASSET_HASH.to_string()) {
                    return Err(Error::Protocol(
                        "Asset Id missmatch in Magic Routing Hint".to_string(),
                    ));
                }
            }
            _ => (),
        }

        Ok(Some((address, amount)))
    } else {
        Ok(None)
    }
}

/// Sign the address signature by a priv key.
pub fn sign_address(addr: &str, keys: &Keypair) -> Result<Signature, Error> {
    let address_hash = sha256::Hash::hash(addr.as_bytes());
    let msg = Message::from_digest_slice(address_hash.as_byte_array())?;
    Ok(Secp256k1::new().sign_schnorr(&msg, &keys))
}

#[test]
fn test_bip21_parsing() {
    let uri = "liquidtestnet:tlq1qqt3sgky7zert7237tred5rqmmx0eargp625zkyhr2ldw6yqdvh5fusnm5xk0qfjpejvgm37q7mqtv5epfksv78jweytmqgpd8?amount=0.00005122&assetid=144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a4";
    let (network, address, amount, assetid) = parse_bip21(uri).unwrap();

    assert_eq!(network, "liquidtestnet");
    assert_eq!(address, "tlq1qqt3sgky7zert7237tred5rqmmx0eargp625zkyhr2ldw6yqdvh5fusnm5xk0qfjpejvgm37q7mqtv5epfksv78jweytmqgpd8");
    assert_eq!(amount, 0.00005122);
    assert_eq!(
        assetid,
        Some("144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a4".to_string())
    );
}

#[test]
fn test_mrh() {
    let route_hint = find_magic_routing_hint("lntb1m1pnrv328pp5zymney8y48234em5lakrkuk8rfrftn5dkwfys7zghe2c40hxfmusdpz2djkuepqw3hjqnpdgf2yxgrpv3j8yetnwvcqz95xqyp2xqrzjqwyg6p2yhhqvq5d97kkwuk0mnrp3su6sn5fvtxn63gppms9fkegajzzxeyqq28qqqqqqqqqqqqqqq9gq2ysp5znw62my456pnzq7vyfgje2yjfat8gzgf88q8rl30dt3cgpmpk9eq9qyyssq55qds9y2vrtmqxq00fgrnartdhs0wwlt7u5uflzs5wnx8wad8y3y86y8lgre4qaszhvhesa6ts99g7m088j6dgjfe6hhtkfglqfqwjcp03v2nh").unwrap().expect("route hint expected");
    assert_eq!(route_hint.short_channel_id, MAGIC_ROUTING_HINT_CONSTANT);
}
