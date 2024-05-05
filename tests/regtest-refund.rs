use bitcoin::absolute::LockTime;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::key::rand::rngs::OsRng;
use bitcoin::key::rand::{thread_rng, RngCore};
use bitcoin::key::{Keypair, PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, OutPoint};
use bitcoind::bitcoincore_rpc::json::ScanTxOutRequest;
use bitcoind::bitcoincore_rpc::RpcApi;
use boltz_client::network::Chain;
use boltz_client::{BtcSwapScript, BtcSwapTx};
use boltz_client::{SwapTxKind, SwapType};
mod test_framework;
use test_framework::BtcTestFramework;

#[test]
fn test_submarine_refund_regtest() {
    // Init test framework and get a test-wallet
    let test_framework = BtcTestFramework::init();

    // Generate a random preimage and hash it.
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);

    let hash160 = hash160::Hash::hash(&bytes);

    // Generate dummy receiver and sender's keypair
    let secp = Secp256k1::new();
    let recvr_keypair = Keypair::new(&secp, &mut thread_rng());
    let sender_keypair = Keypair::new(&secp, &mut thread_rng());

    // create a btc swap script.
    let swap_script = BtcSwapScript {
        swap_type: SwapType::Submarine,
        hashlock: hash160,
        receiver_pubkey: PublicKey {
            compressed: true,
            inner: recvr_keypair.public_key(),
        },
        locktime: LockTime::from_height(200).unwrap(),
        sender_pubkey: PublicKey {
            compressed: true,
            inner: sender_keypair.public_key(),
        },
    };

    // Send coin the swapscript address and confirm tx
    let swap_addrs = swap_script.to_address(Chain::BitcoinRegtest).unwrap();
    test_framework.send_coins(&swap_addrs, Amount::from_sat(10000));
    test_framework.generate_blocks(1);

    let scan_request = ScanTxOutRequest::Single(format!("addr({})", swap_addrs));

    let scan_result = test_framework
        .as_ref()
        .scan_tx_out_set_blocking(&[scan_request.clone()])
        .unwrap();

    assert_eq!(scan_result.unspents.len(), 1);
    assert_eq!(scan_result.total_amount, Amount::from_sat(10000));

    // Create a refund spending transaction from the swap
    let utxo = scan_result
        .unspents
        .iter()
        .map(|utxo| {
            let outpoint = OutPoint::new(utxo.txid, utxo.vout);
            (outpoint, utxo.amount.to_sat())
        })
        .last()
        .expect("value expected");

    let test_wallet = test_framework.get_test_wallet();
    let refund_addrs = test_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    let swap_tx = BtcSwapTx {
        kind: SwapTxKind::Refund,
        swap_script,
        output_address: refund_addrs,
        utxo,
    };

    let refund_tx = swap_tx.sign_refund(&sender_keypair, 1000).unwrap();

    // Make the timelock matured and broadcast the spend
    test_framework.generate_blocks(100);
    test_framework
        .as_ref()
        .send_raw_transaction(&refund_tx)
        .unwrap();
    test_framework.generate_blocks(1);

    let scan_result = test_framework
        .as_ref()
        .scan_tx_out_set_blocking(&[scan_request])
        .unwrap();

    assert_eq!(scan_result.unspents.len(), 0);
    assert_eq!(scan_result.total_amount, Amount::from_sat(0));

    let test_balance = test_wallet.get_balance(None, None).unwrap();

    assert_eq!(test_balance, Amount::from_sat(19000));
}
