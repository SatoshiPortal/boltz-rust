use bitcoin::absolute::LockTime;
use bitcoin::key::rand::thread_rng;
use bitcoin::key::{Keypair, PublicKey};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::{Amount, OutPoint, TxOut};
use bitcoind::bitcoincore_rpc::json::ScanTxOutRequest;
use bitcoind::bitcoincore_rpc::RpcApi;
use boltz_client::boltz::{SwapTxKind, SwapType};
use boltz_client::network::Chain;
use boltz_client::util::secrets::Preimage;
use boltz_client::{BtcSwapScript, BtcSwapTx, LBtcSwapScript, LBtcSwapTx};
mod test_framework;
use test_framework::{BtcTestFramework, LbtcTestFramework};

#[test]
fn btc_reverse_claim() {
    // Init test framework and get a test-wallet
    let test_framework = BtcTestFramework::init();

    // Generate a random preimage and hash it.
    let preimage = Preimage::new();

    // Generate dummy receiver and sender's keypair
    let secp = Secp256k1::new();
    let recvr_keypair = Keypair::new(&secp, &mut thread_rng());
    let sender_keypair = Keypair::new(&secp, &mut thread_rng());

    // create a btc swap script.
    let swap_script = BtcSwapScript {
        swap_type: SwapType::ReverseSubmarine,
        side: None,
        funding_addrs: None,
        hashlock: preimage.hash160,
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
    let spk = swap_addrs.script_pubkey();
    println!("spk: {}", spk);
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
    let utxos: Vec<(OutPoint, TxOut)> = scan_result
        .unspents
        .iter()
        .map(|utxo| {
            let outpoint = OutPoint::new(utxo.txid, utxo.vout);
            let txout = TxOut {
                script_pubkey: utxo.script_pub_key.clone(),
                value: utxo.amount,
            };
            (outpoint, txout)
        })
        .collect();

    let test_wallet = test_framework.get_test_wallet();
    let refund_addrs = test_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    let swap_tx = BtcSwapTx {
        kind: SwapTxKind::Claim,
        swap_script,
        output_address: refund_addrs,
        utxos,
    };

    let claim_tx = swap_tx
        .sign_claim(&recvr_keypair, &preimage, 1000, None)
        .unwrap();

    test_framework
        .as_ref()
        .send_raw_transaction(&claim_tx)
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

#[test]
fn btc_submarine_refund() {
    // Init test framework and get a test-wallet
    let test_framework = BtcTestFramework::init();

    // Generate dummy receiver and sender's keypair
    let preimage = Preimage::new();
    let secp = Secp256k1::new();
    let recvr_keypair = Keypair::new(&secp, &mut thread_rng());
    let sender_keypair = Keypair::new(&secp, &mut thread_rng());

    // create a btc swap script.
    let swap_script = BtcSwapScript {
        swap_type: SwapType::Submarine,
        side: None,
        funding_addrs: None,
        hashlock: preimage.hash160,
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
    let utxos: Vec<(OutPoint, TxOut)> = scan_result
        .unspents
        .iter()
        .map(|utxo| {
            let outpoint = OutPoint::new(utxo.txid, utxo.vout);
            let txout = TxOut {
                script_pubkey: utxo.script_pub_key.clone(),
                value: utxo.amount,
            };
            (outpoint, txout)
        })
        .collect();

    let test_wallet = test_framework.get_test_wallet();
    let refund_addrs = test_wallet
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();

    let swap_tx = BtcSwapTx {
        kind: SwapTxKind::Refund,
        swap_script,
        output_address: refund_addrs,
        utxos,
    };

    let refund_tx = swap_tx.sign_refund(&sender_keypair, 1000, None).unwrap();

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

#[test]
fn lbtc_reverse_claim() {
    // Init test framework and get a test-wallet
    let test_framework = LbtcTestFramework::init();

    // Generate a random preimage and hash it.
    let preimage = Preimage::new();

    // Generate dummy receiver and sender's keypair
    let secp = Secp256k1::new();
    let recvr_keypair = Keypair::new(&secp, &mut thread_rng());
    let sender_keypair = Keypair::new(&secp, &mut thread_rng());
    let blinding_keypair = elements::secp256k1_zkp::Keypair::new(&secp, &mut thread_rng());

    // create a btc swap script.
    let swap_script = LBtcSwapScript {
        swap_type: SwapType::ReverseSubmarine,
        side: None,
        funding_addrs: None,
        hashlock: preimage.hash160,
        receiver_pubkey: PublicKey {
            compressed: true,
            inner: recvr_keypair.public_key(),
        },
        locktime: elements::LockTime::from_height(200).unwrap(),
        sender_pubkey: PublicKey {
            compressed: true,
            inner: sender_keypair.public_key(),
        },
        blinding_key: blinding_keypair,
    };

    // Send coin the swapscript address and confirm tx
    let swap_addrs = swap_script.to_address(Chain::LiquidRegtest).unwrap();

    test_framework.send_coins(&swap_addrs, Amount::from_sat(10000));
    test_framework.generate_blocks(1);

    let utxo = test_framework.fetch_utxo(&swap_addrs).unwrap();

    let refund_addrs = test_framework.get_new_addrs();

    let genesis_hash = test_framework.genesis_hash();

    let swap_tx = LBtcSwapTx {
        kind: SwapTxKind::Claim,
        swap_script,
        output_address: refund_addrs,
        funding_outpoint: utxo.0,
        funding_utxo: utxo.1,
        genesis_hash,
    };

    let claim_tx = swap_tx
        .sign_claim(&recvr_keypair, &preimage, Amount::from_sat(1000), None)
        .unwrap();

    test_framework.send_tx(&claim_tx);

    test_framework.generate_blocks(1);

    assert!(test_framework.fetch_utxo(&swap_addrs).is_none());
}

#[test]
fn lbtc_submarine_refund() {
    // Init test framework and get a test-wallet
    let test_framework = LbtcTestFramework::init();

    // Generate dummy receiver and sender's keypair
    let preimage = Preimage::new();
    let secp = Secp256k1::new();
    let recvr_keypair = Keypair::new(&secp, &mut thread_rng());
    let sender_keypair = Keypair::new(&secp, &mut thread_rng());
    let blinding_keypair = elements::secp256k1_zkp::Keypair::new(&secp, &mut thread_rng());

    // create a btc swap script.
    let swap_script = LBtcSwapScript {
        swap_type: SwapType::Submarine,
        side: None,
        funding_addrs: None,
        hashlock: preimage.hash160,
        receiver_pubkey: PublicKey {
            compressed: true,
            inner: recvr_keypair.public_key(),
        },
        locktime: elements::LockTime::from_height(200).unwrap(),
        sender_pubkey: PublicKey {
            compressed: true,
            inner: sender_keypair.public_key(),
        },
        blinding_key: blinding_keypair,
    };

    // Send coin the swapscript address and confirm tx
    let swap_addrs = swap_script.to_address(Chain::LiquidRegtest).unwrap();
    test_framework.send_coins(&swap_addrs, Amount::from_sat(10000));
    test_framework.generate_blocks(1);

    // Create a refund spending transaction from the swap
    let utxo = test_framework.fetch_utxo(&swap_addrs).unwrap();

    let refund_addrs = test_framework.get_new_addrs();

    let genesis_hash = test_framework.genesis_hash();

    let swap_tx = LBtcSwapTx {
        kind: SwapTxKind::Refund,
        swap_script,
        output_address: refund_addrs,
        funding_outpoint: utxo.0,
        funding_utxo: utxo.1,
        genesis_hash,
    };

    let refund_tx = swap_tx
        .sign_refund(&sender_keypair, Amount::from_sat(1000), None)
        .unwrap();

    // Make the timelock matured and broadcast the spend
    test_framework.generate_blocks(100);
    test_framework.send_tx(&refund_tx);
    test_framework.generate_blocks(1);

    assert!(test_framework.fetch_utxo(&swap_addrs).is_none());
}
