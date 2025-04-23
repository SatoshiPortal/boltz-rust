use std::str::FromStr;

use super::boltz::BoltzApiClientV2;
use crate::network::LiquidChain;
use crate::util::bolt12;
use crate::{error::Error, network::Chain};
use bitcoin::{
    hashes::{sha256, Hash},
    hex::FromHex,
    key::{Keypair, Secp256k1},
    secp256k1::{schnorr::Signature, Message},
    PublicKey,
};
use lightning::blinded_path::{Direction, IntroductionNode};
use lightning::bolt11_invoice::Bolt11Invoice;
use lightning::offers::invoice::Bolt12Invoice;

const MAGIC_ROUTING_HINT_CONSTANT: u64 = 596385002596073472;
const LBTC_TESTNET_ASSET_HASH: &str =
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49";
const LBTC_MAINNET_ASSET_HASH: &str =
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";

/// Decodes the provided invoice to find the magic routing hint.
pub fn find_magic_routing_hint(
    invoice: &str,
) -> Result<
    Option<(
        /* short_channel_id */ u64,
        /* public_key */ String,
    )>,
    Error,
> {
    match Bolt11Invoice::from_str(invoice) {
        Ok(invoice) => find_bolt11_magic_routing_hint(&invoice),
        Err(_) => match bolt12::decode_invoice(invoice) {
            Ok(invoice) => find_bolt12_magic_routing_hint(&invoice),
            Err(e) => Err(e),
        },
    }
}

pub fn find_bolt11_magic_routing_hint(
    invoice: &Bolt11Invoice,
) -> Result<
    Option<(
        /* short_channel_id */ u64,
        /* public_key */ String,
    )>,
    Error,
> {
    Ok(invoice
        .private_routes()
        .iter()
        .flat_map(|route| &route.0)
        .find(|hint| hint.short_channel_id == MAGIC_ROUTING_HINT_CONSTANT)
        .cloned()
        .map(|hint| (hint.short_channel_id, hint.src_node_id.to_string())))
}

pub fn find_bolt12_magic_routing_hint(
    invoice: &Bolt12Invoice,
) -> Result<
    Option<(
        /* short_channel_id */ u64,
        /* public_key */ String,
    )>,
    Error,
> {
    Ok(invoice
        .payment_paths()
        .iter()
        .find_map(|path| match path.introduction_node() {
            IntroductionNode::DirectedShortChannelId(
                Direction::NodeOne,
                MAGIC_ROUTING_HINT_CONSTANT,
            ) => Some((
                MAGIC_ROUTING_HINT_CONSTANT,
                invoice.signing_pubkey().to_string(),
            )),
            _ => None,
        }))
}

/// Parse a BIP21 String and get the network, address, asset_id if present
pub fn parse_bip21(uri: &str) -> Result<(String, String, bitcoin::Amount, Option<String>), Error> {
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
    let mut amount = bitcoin::Amount::from_sat(0);
    let mut assetid = None::<String>;

    for param in params {
        let pair: Vec<&str> = param.split('=').collect();
        match pair[0] {
            "amount" => {
                amount = match bitcoin::Amount::from_str_in(pair[1], bitcoin::Denomination::Bitcoin)
                {
                    Ok(r) => r,
                    Err(e) => {
                        return Err(Error::Generic(format!(
                            "Unable to parse amount from string: {e}"
                        )))
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
pub async fn check_for_mrh(
    boltz_api_v2: &BoltzApiClientV2,
    invoice: &str,
    network: Chain,
) -> Result<Option<(String, bitcoin::Amount)>, Error> {
    if let Some((_, public_key)) = find_magic_routing_hint(invoice)? {
        let mrh_resp = boltz_api_v2.get_mrh_bip21(invoice).await?;

        let (_, address, amount, assetid) = parse_bip21(&mrh_resp.bip21)?;
        let address_hash = sha256::Hash::hash(address.as_bytes());
        let msg = Message::from_digest_slice(address_hash.as_byte_array())?;

        let receiver_sig = Signature::from_slice(&Vec::from_hex(&mrh_resp.signature)?)?;
        let receiver_pubkey = PublicKey::from_str(&public_key)?.inner;

        let secp = Secp256k1::new();
        secp.verify_schnorr(&receiver_sig, &msg, &receiver_pubkey.x_only_public_key().0)?;

        match network {
            Chain::Liquid(LiquidChain::LiquidTestnet) => {
                if assetid != Some(LBTC_TESTNET_ASSET_HASH.to_string()) {
                    return Err(Error::Protocol(
                        "Asset Id missmatch in Magic Routing Hint".to_string(),
                    ));
                }
            }

            Chain::Liquid(LiquidChain::Liquid) => {
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
    Ok(Secp256k1::new().sign_schnorr(&msg, keys))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        hashes::{sha256, Hash},
        hex::FromHex,
        key::Secp256k1,
        secp256k1::{schnorr::Signature, Message},
        PublicKey,
    };

    use crate::swaps::magic_routing::{
        find_magic_routing_hint, parse_bip21, MAGIC_ROUTING_HINT_CONSTANT,
    };

    #[macros::test_all]
    fn test_bip21_parsing() {
        let uri = "liquidtestnet:tlq1qqt3sgky7zert7237tred5rqmmx0eargp625zkyhr2ldw6yqdvh5fusnm5xk0qfjpejvgm37q7mqtv5epfksv78jweytmqgpd8?amount=0.00005122&assetid=144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a4";
        let (network, address, amount, assetid) = parse_bip21(uri).unwrap();

        assert_eq!(network, "liquidtestnet");
        assert_eq!(address, "tlq1qqt3sgky7zert7237tred5rqmmx0eargp625zkyhr2ldw6yqdvh5fusnm5xk0qfjpejvgm37q7mqtv5epfksv78jweytmqgpd8");
        assert_eq!(amount.to_btc(), 0.00005122);
        assert_eq!(
            assetid,
            Some("144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a4".to_string())
        );
    }

    /// BIP21 amounts which can lead to rounding errors when converting from BTC amount (f64) to sats (u64).
    /// The format is: (sat amount, BIP21 BTC amount)
    fn get_bip21_rounding_test_vectors() -> Vec<(u64, f64)> {
        vec![
            (999, 0.0000_0999),
            (1_000, 0.0000_1000),
            (59_810, 0.0005_9810),
        ]
    }

    #[macros::test_all]
    fn test_bip21_parsing_with_rounding_edge_cases() {
        let liquid_address = "tlq1qqt3sgky7zert7237tred5rqmmx0eargp625zkyhr2ldw6yqdvh5fusnm5xk0qfjpejvgm37q7mqtv5epfksv78jweytmqgpd8";
        let asset_id = "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a4";

        for (amount_sat, amount_btc) in get_bip21_rounding_test_vectors() {
            let uri =
                format!("liquidtestnet:{liquid_address}?amount={amount_btc}&assetid={asset_id}");
            let (_network, _address, bip21_amount, _assetid) = parse_bip21(&uri).unwrap();

            let parsed_amount_sat = bip21_amount.to_sat();

            assert_eq!(parsed_amount_sat, amount_sat);
        }
    }

    #[macros::test_all]
    fn test_mrh() {
        // Test BOLT11
        let (short_channel_id, _) = find_magic_routing_hint("lntb1m1pnrv328pp5zymney8y48234em5lakrkuk8rfrftn5dkwfys7zghe2c40hxfmusdpz2djkuepqw3hjqnpdgf2yxgrpv3j8yetnwvcqz95xqyp2xqrzjqwyg6p2yhhqvq5d97kkwuk0mnrp3su6sn5fvtxn63gppms9fkegajzzxeyqq28qqqqqqqqqqqqqqq9gq2ysp5znw62my456pnzq7vyfgje2yjfat8gzgf88q8rl30dt3cgpmpk9eq9qyyssq55qds9y2vrtmqxq00fgrnartdhs0wwlt7u5uflzs5wnx8wad8y3y86y8lgre4qaszhvhesa6ts99g7m088j6dgjfe6hhtkfglqfqwjcp03v2nh").unwrap().expect("short_channel_id expected");
        assert_eq!(short_channel_id, MAGIC_ROUTING_HINT_CONSTANT);

        // Test BOLT12
        let mrh_address = "tlq1pq0wqu32e2xacxeyps22x8gjre4qk3u6r70pj4r62hzczxeyz8x3yxucrpn79zy28plc4x37aaf33kwt6dz2nn6gtkya6h02mwpzy4eh69zzexq7cf5y5";
        let mrh_address_signature = "1d0fd70eb190f3054062746be057219324c5252d28cc809f73abbabf31a51f833fa22b29d5099144ceedda3078f63c5a9d21199cc03062042a4e77ac68de9cb0";
        let signing_pubkey = "02b1e2634b2c87d667cb9950efc106faf33d53676820d7394ac43a88a15fe0dafb";

        let (short_channel_id, public_key) = find_magic_routing_hint("lni1qqs8xcehdjudtjdnhwlevxxge30sr7rlf6uthfw4kfvcrkgm8v4667szypp5jl7hlqnf2ugg7j3slkwwcwht57vhyzzwjr4dq84rxzgqqqqqqyyjqtvkat0284uqzpzynt99ey6xrnn8c9tyutsawv39lfna6wue0fspsqhfprklc2w6mvde9xg552ckj6zqh4my0t8zj4pqunxfrchcytfnc5qs9t3hd8wy4wztdxepujztgq3kk7czu43q8gpz8n9gvj72a6hugfwqqqkd2qz0z60ehmgk0ep0xxsjzzlq783x4v8ht3rv8qeyrzg694ef4m3cvf33g38alynznzensgtzzq43uf35kty86enuhx2salqsd7hn84fkw6pq6uu543p63zs4lcx6ldgzqs6f0ltlsf54wyy0fgc0m88v8t460xtjpp8fp6ksr63npyqqqqqq2gps7sjqtqss96jpjwug2jx0sy9vty6nhz9d4gam35r5yekech4dk9tejkzes3qz5r7sywszm9h2m63a0qqsg3y6efwfx3suue7p2e8zu8tnyf06vlwnhxt6vqvqxjlw7wz7lc8zrunpkunxawmung0ugdr4k8w356xehttw7d4lyv2wqypzkudks5nk5x0thr3wvqwzncpvec4r7za5qknu3u2vnuyejvyu8eqqc0q8c7zulhjghpr9s03qnpt46us88uv7uat95gm74jys2tkmtyc2dj4e72aqpur23hn3kgzjmxlg94mz8xntdmfzde42x34r9p497cxt05d8a62t4wr2706ntzscscxccvvm5mmxgseyqjywn3v4dt0gt7mc44nlgk6hdaq5fxgf5xu78q8s9x0r93mfjnwnlgc008qjydpj4jxhmtk2ce95h779zgjw9rp9d6866w3wrktc4t00h6459gh36je4x0e6w8jaqgjj3nswpud3k2wwlpukzfg60le4f83vllzq34ys8jvr48d70cqqs3kfqqz3cqqqqd97auu9alswy8exrdexd6ahexslcs68tvwarf5dnwkkaumt7gc5uqgz9dcmdpf8dgv7hw8zucqu98szen328u9mgpd8erc5e8cfnycfc0jqps7q03u9el0y3wzxtqlzpxzht4eqw0ceae6ktg3hatyfq5hdkkfs5m9tnu46qrcx4r08rvs99kd7sttkywdxkmkjymn25dr2x2r2tasvklg60m55h2ux4ul4xk9p3psd3scehfhkv3pjgpyga8ze26k7shah3tt873d4wm6pgjvsngdeuwq0q2v7xtrkn9xa873s77wpyg6r9tyd0khv43jtf0au2y3yu2xz2m5045azu8vh32k7l04tg230r49n2vln5u096q399r8qurcmrv5ua7revyj35lln2j0zel7ypr2fq0yc82wmul4z8qqqqqqqqqqqqqqqksqqqqqqqqqqqqgayjedltzjqqqqqqqqqqqqqqqqqqqqpdqqqqqqqqqqqqq36f9jm7k9yqqqqqq2gpr8lecce2pqfkjfg9xap6pgprh98p6e7myfva7wc4uw64xcdxh7zh0qq7ahqz665qc0gfqtqggzk83xxjevsltx0jue2rhuzph67v74xemgyrtnjjky82y2zhlqmtalqs8p5e558mzwmfwz9682hmwq4g7z6llvg0t4suj7j20a82hy79jtsk3w8grr3uz6pnta0xxgq9tq9few20rnvrt2clh3lchmejspuxqly").unwrap().expect("short_channel_id expected");
        assert_eq!(short_channel_id, MAGIC_ROUTING_HINT_CONSTANT);
        assert_eq!(public_key, signing_pubkey);

        let mrh_address_hash = sha256::Hash::hash(mrh_address.as_bytes());
        let msg = Message::from_digest_slice(mrh_address_hash.as_byte_array()).unwrap();

        let receiver_sig =
            Signature::from_slice(&Vec::from_hex(mrh_address_signature).unwrap()).unwrap();
        let receiver_pubkey = PublicKey::from_str(&public_key).unwrap().inner;

        let secp = Secp256k1::new();
        secp.verify_schnorr(&receiver_sig, &msg, &receiver_pubkey.x_only_public_key().0)
            .unwrap();
    }
}
