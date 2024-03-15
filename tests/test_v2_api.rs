use std::str::FromStr;

use bitcoin::{Address, Amount};
use boltz_client::{
    network::Chain,
    swaps::{boltzv2::BOLTZ_REGTEST, btc_swapper::BtcSwapper},
};

#[test]
#[ignore = "Run legend-regtest"]
fn test_v2_submarine() {
    let swapper = BtcSwapper::init(BOLTZ_REGTEST, Chain::BitcoinRegtest);

    println!("Enter a BOLT-11 Invoice with minimum 60,000 sats");

    let mut invoice = String::new();

    std::io::stdin().read_line(&mut invoice).unwrap();

    let invoice = invoice.trim();
    swapper.do_submarine(&invoice).unwrap();
}

#[test]
#[ignore = "Run legend-regtest"]
fn test_v2_reverse() {
    let swapper = BtcSwapper::init(BOLTZ_REGTEST, Chain::BitcoinRegtest);

    let mut claim_addrs_str = String::new();

    println!("Enter a claim address");
    std::io::stdin().read_line(&mut claim_addrs_str).unwrap();

    let claim_addrs_str = claim_addrs_str.trim();

    let claim_addrs = Address::from_str(&claim_addrs_str)
        .unwrap()
        .assume_checked();

    swapper
        .do_reverse_swap(100000, claim_addrs, Amount::from_sat(1000))
        .unwrap();
}
