//! Mainnet battle-test for multi-output reverse-swap claims (PR #162).
//!
//! Creates a reverse swap with production Boltz, persists all recovery
//! material to a state file BEFORE printing the bolt11, then waits for the
//! lockup and broadcasts a claim that pays two outputs: the primary address
//! receives the remainder, the extra address a fixed amount.
//!
//! Usage:
//!   create <BTC|L-BTC> <invoice_amount_sat> <primary_addr> <extra_addr> <extra_amount_sat> [claim_fee_sat]
//!   claim  <state_file>
//!
//! `create` runs the whole flow; if it is interrupted after the invoice is
//! paid, resume with `claim` and the state file it wrote.

use std::str::FromStr;
use std::time::Duration;

use bitcoin::key::rand::thread_rng;
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::PublicKey;
use boltz_client::boltz::{
    BoltzApiClientV2, CreateChainRequest, CreateChainResponse, CreateReverseRequest,
    CreateReverseResponse, Side, BOLTZ_MAINNET_URL_V2,
};
use boltz_client::fees::Fee;
use boltz_client::network::esplora::{EsploraBitcoinClient, EsploraLiquidClient};
use boltz_client::network::{BitcoinChain, Chain, LiquidChain};
use boltz_client::swaps::{ChainClient, SwapScript, SwapTransactionParams, TransactionOptions};
use boltz_client::util::secrets::Preimage;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ChainState {
    from_chain: String,
    to_chain: String,
    swap_id: String,
    claim_secret_key: String,
    refund_secret_key: String,
    preimage: String,
    swap_response: CreateChainResponse,
    primary_address: String,
    extra_address: String,
    extra_amount_sat: u64,
    claim_fee_sat: u64,
}

#[derive(Serialize, Deserialize)]
struct State {
    chain: String,
    swap_id: String,
    claim_secret_key: String,
    preimage: String,
    swap_response: CreateReverseResponse,
    primary_address: String,
    extra_address: String,
    extra_amount_sat: u64,
    claim_fee_sat: u64,
}

fn parse_chain(s: &str) -> Chain {
    match s {
        "BTC" => Chain::Bitcoin(BitcoinChain::Bitcoin),
        "L-BTC" => Chain::Liquid(LiquidChain::Liquid),
        other => panic!("unsupported chain {other:?}, use BTC or L-BTC"),
    }
}

fn chain_client(chain: Chain) -> ChainClient {
    match chain {
        Chain::Bitcoin(c) => {
            ChainClient::new().with_bitcoin(EsploraBitcoinClient::default(c, None))
        }
        Chain::Liquid(c) => ChainClient::new().with_liquid(EsploraLiquidClient::default(c, None)),
    }
}

/// Reject bad destination addresses before any money moves.
fn validate_address(chain: Chain, address: &str) {
    match chain {
        Chain::Bitcoin(_) => {
            let addr = bitcoin::Address::from_str(address).expect("invalid bitcoin address");
            assert!(
                addr.is_valid_for_network(bitcoin::Network::Bitcoin),
                "{address} is not a mainnet bitcoin address"
            );
        }
        Chain::Liquid(_) => {
            let addr =
                elements::Address::parse_with_params(address, &elements::AddressParams::LIQUID)
                    .expect("invalid mainnet liquid address");
            assert!(
                addr.blinding_pubkey.is_some(),
                "{address} is not confidential; liquid outputs must be blinded"
            );
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    boltz_client::util::setup_logger();
    let args: Vec<String> = std::env::args().collect();

    match args.get(1).map(String::as_str) {
        Some("create") => {
            let chain_str = args[2].clone();
            let invoice_amount: u64 = args[3].parse().unwrap();
            let primary = args[4].clone();
            let extra = args[5].clone();
            let extra_amount: u64 = args[6].parse().unwrap();
            let claim_fee: u64 = args.get(7).map(|f| f.parse().unwrap()).unwrap_or(1_000);
            let chain = parse_chain(&chain_str);

            validate_address(chain, &primary);
            validate_address(chain, &extra);
            assert!(
                extra_amount + claim_fee < invoice_amount,
                "extra amount + fee must leave a primary remainder"
            );

            let secp = Secp256k1::new();
            let keys = Keypair::new(&secp, &mut thread_rng());
            let preimage = Preimage::random();
            let claim_public_key = PublicKey {
                compressed: true,
                inner: keys.public_key(),
            };

            let api = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
            let resp = api
                .post_reverse_req(CreateReverseRequest {
                    from: "BTC".to_string(),
                    to: chain_str.clone(),
                    invoice: None,
                    invoice_amount: Some(invoice_amount),
                    preimage_hash: Some(preimage.sha256),
                    description: Some("boltz-rust PR162 multi-output battle test".to_string()),
                    description_hash: None,
                    address_signature: None,
                    address: None,
                    claim_public_key,
                    referral_id: None,
                    webhook: None,
                })
                .await
                .unwrap();
            resp.validate(&preimage, &claim_public_key, chain).unwrap();

            let state = State {
                chain: chain_str,
                swap_id: resp.id.clone(),
                claim_secret_key: keys.display_secret().to_string(),
                preimage: hex::encode(preimage.bytes.unwrap()),
                swap_response: resp.clone(),
                primary_address: primary,
                extra_address: extra,
                extra_amount_sat: extra_amount,
                claim_fee_sat: claim_fee,
            };
            let state_file = format!("multiout-swap-{}.json", resp.id);
            std::fs::write(&state_file, serde_json::to_string_pretty(&state).unwrap()).unwrap();

            println!(
                "\n=== swap {} created, recovery state saved to {state_file} ===",
                resp.id
            );
            println!("=== KEEP {state_file} UNTIL THE SWAP SETTLES — it holds the claim keys ===");
            println!("onchain lockup will be {} sat", resp.onchain_amount);
            println!("\nPAY THIS INVOICE:\n\n{}\n", resp.invoice.clone().unwrap());

            wait_and_claim(state).await;
        }
        Some("claim") => {
            let state: State =
                serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
            wait_and_claim(state).await;
        }
        Some("create-chain") => {
            let from_str = args[2].clone();
            let to_str = args[3].clone();
            let user_lock_amount: u64 = args[4].parse().unwrap();
            let primary = args[5].clone();
            let extra = args[6].clone();
            let extra_amount: u64 = args[7].parse().unwrap();
            let claim_fee: u64 = args.get(8).map(|f| f.parse().unwrap()).unwrap_or(500);
            let from = parse_chain(&from_str);
            let to = parse_chain(&to_str);

            validate_address(to, &primary);
            validate_address(to, &extra);

            let secp = Secp256k1::new();
            let claim_keys = Keypair::new(&secp, &mut thread_rng());
            let refund_keys = Keypair::new(&secp, &mut thread_rng());
            let preimage = Preimage::random();
            let claim_public_key = PublicKey {
                compressed: true,
                inner: claim_keys.public_key(),
            };
            let refund_public_key = PublicKey {
                compressed: true,
                inner: refund_keys.public_key(),
            };

            let api = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
            let resp = api
                .post_chain_req(CreateChainRequest {
                    from: from_str.clone(),
                    to: to_str.clone(),
                    preimage_hash: preimage.sha256,
                    claim_public_key: Some(claim_public_key),
                    refund_public_key: Some(refund_public_key),
                    referral_id: None,
                    user_lock_amount: Some(user_lock_amount),
                    server_lock_amount: None,
                    pair_hash: None,
                    webhook: None,
                })
                .await
                .unwrap();
            resp.validate(
                &claim_public_key,
                &refund_public_key,
                from,
                to,
                &preimage.sha256,
            )
            .unwrap();
            assert!(
                extra_amount + claim_fee < resp.claim_details.amount,
                "extra amount + fee must leave a primary remainder from the {} sat server lockup",
                resp.claim_details.amount
            );

            let state = ChainState {
                from_chain: from_str,
                to_chain: to_str,
                swap_id: resp.id.clone(),
                claim_secret_key: claim_keys.display_secret().to_string(),
                refund_secret_key: refund_keys.display_secret().to_string(),
                preimage: hex::encode(preimage.bytes.unwrap()),
                swap_response: resp.clone(),
                primary_address: primary,
                extra_address: extra,
                extra_amount_sat: extra_amount,
                claim_fee_sat: claim_fee,
            };
            let state_file = format!("multiout-chainswap-{}.json", resp.id);
            std::fs::write(&state_file, serde_json::to_string_pretty(&state).unwrap()).unwrap();

            println!(
                "\n=== chain swap {} created, recovery state saved to {state_file} ===",
                resp.id
            );
            println!("=== KEEP {state_file} — it holds claim AND refund keys ===");
            println!(
                "server will lock {} sat, claim splits: primary {} sat + extra {} sat (fee {} sat)",
                resp.claim_details.amount,
                resp.claim_details.amount - claim_fee - extra_amount,
                extra_amount,
                claim_fee,
            );
            println!(
                "\nSEND EXACTLY {} sat ({}) TO:\n\n{}\n",
                resp.lockup_details.amount, state.from_chain, resp.lockup_details.lockup_address,
            );

            wait_and_claim_chain(state).await;
        }
        Some("claim-chain") => {
            let state: ChainState =
                serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
            wait_and_claim_chain(state).await;
        }
        Some("refund-chain") => {
            let state: ChainState =
                serde_json::from_str(&std::fs::read_to_string(&args[2]).unwrap()).unwrap();
            let refund_address = args[3].clone();
            let from = parse_chain(&state.from_chain);
            validate_address(from, &refund_address);

            let secp = Secp256k1::new();
            let refund_keys = Keypair::from_seckey_str(&secp, &state.refund_secret_key).unwrap();
            let refund_public_key = PublicKey {
                compressed: true,
                inner: refund_keys.public_key(),
            };
            let api = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
            let client = chain_client(from);
            let lockup_script = SwapScript::chain_from_swap_resp(
                from,
                Side::Lockup,
                state.swap_response.lockup_details.clone(),
                refund_public_key,
            )
            .unwrap();

            let tx = lockup_script
                .construct_refund(SwapTransactionParams {
                    swap_id: state.swap_id.clone(),
                    keys: refund_keys,
                    fee: Fee::Absolute(state.claim_fee_sat),
                    output_address: refund_address,
                    chain_client: &client,
                    boltz_client: &api,
                    options: None,
                })
                .await
                .unwrap();
            let txid = client.broadcast_tx(&tx).await.unwrap();
            println!("=== refund broadcast: {txid} ===");
        }
        _ => {
            eprintln!("usage: create <BTC|L-BTC> <invoice_amount_sat> <primary_addr> <extra_addr> <extra_amount_sat> [claim_fee_sat]");
            eprintln!("       claim <state_file>");
            eprintln!("       create-chain <from> <to> <user_lock_amount_sat> <primary_addr> <extra_addr> <extra_amount_sat> [claim_fee_sat]");
            eprintln!("       claim-chain <state_file>");
            eprintln!("       refund-chain <state_file> <refund_addr>");
            std::process::exit(1);
        }
    }
}

async fn wait_and_claim_chain(state: ChainState) {
    let from = parse_chain(&state.from_chain);
    let to = parse_chain(&state.to_chain);
    let secp = Secp256k1::new();
    let claim_keys = Keypair::from_seckey_str(&secp, &state.claim_secret_key).unwrap();
    let refund_keys = Keypair::from_seckey_str(&secp, &state.refund_secret_key).unwrap();
    let preimage = Preimage::from_str(&state.preimage).unwrap();
    let claim_public_key = PublicKey {
        compressed: true,
        inner: claim_keys.public_key(),
    };
    let refund_public_key = PublicKey {
        compressed: true,
        inner: refund_keys.public_key(),
    };

    let api = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
    let client = match (from, to) {
        (Chain::Liquid(l), Chain::Bitcoin(b)) | (Chain::Bitcoin(b), Chain::Liquid(l)) => {
            ChainClient::new()
                .with_bitcoin(EsploraBitcoinClient::default(b, None))
                .with_liquid(EsploraLiquidClient::default(l, None))
        }
        _ => panic!("chain swap must be between BTC and L-BTC"),
    };

    let lockup_script = SwapScript::chain_from_swap_resp(
        from,
        Side::Lockup,
        state.swap_response.lockup_details.clone(),
        refund_public_key,
    )
    .unwrap();
    let claim_script = SwapScript::chain_from_swap_resp(
        to,
        Side::Claim,
        state.swap_response.claim_details.clone(),
        claim_public_key,
    )
    .unwrap();

    println!(
        "waiting for the server lockup of chain swap {} ...",
        state.swap_id
    );
    let mut last_status = String::new();
    loop {
        match api.get_swap(&state.swap_id).await.map(|s| s.status) {
            Ok(status) => {
                if status != last_status {
                    println!("swap status: {status}");
                    last_status = status.clone();
                }
                match status.as_str() {
                    "transaction.server.mempool" | "transaction.server.confirmed" => break,
                    "transaction.claimed" => {
                        println!("swap already claimed, nothing to do");
                        return;
                    }
                    "transaction.lockupFailed"
                    | "swap.expired"
                    | "transaction.failed"
                    | "transaction.refunded" => {
                        panic!(
                            "swap ended without a server lockup: {status} — \
                             recover the user lockup with: refund-chain <state_file> <{}_address>",
                            state.from_chain
                        );
                    }
                    _ => {}
                }
            }
            Err(e) => println!("status poll failed (will retry): {e:?}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    println!(
        "server lockup detected, claiming cooperatively to primary {} + {} sat to {} (fee {} sat)",
        state.primary_address, state.extra_amount_sat, state.extra_address, state.claim_fee_sat,
    );

    let mut attempts = 0;
    let tx = loop {
        let params = SwapTransactionParams {
            swap_id: state.swap_id.clone(),
            keys: claim_keys,
            fee: Fee::Absolute(state.claim_fee_sat),
            output_address: state.primary_address.clone(),
            chain_client: &client,
            boltz_client: &api,
            options: Some(
                TransactionOptions::default()
                    .with_chain_claim(refund_keys, lockup_script.clone())
                    .with_additional_outputs(vec![(
                        state.extra_address.clone(),
                        state.extra_amount_sat,
                    )]),
            ),
        };
        match claim_script.construct_claim(&preimage, params).await {
            Ok(tx) => break tx,
            Err(e) => {
                attempts += 1;
                assert!(attempts < 24, "claim construction kept failing: {e:?}");
                println!("claim construction failed (attempt {attempts}, will retry): {e:?}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    let txid = client.broadcast_tx(&tx).await.unwrap();
    println!(
        "\n=== claim broadcast: {txid} ===\nprimary gets {} sat (server lockup {} - fee {} - extra {})",
        state.swap_response.claim_details.amount - state.claim_fee_sat - state.extra_amount_sat,
        state.swap_response.claim_details.amount,
        state.claim_fee_sat,
        state.extra_amount_sat,
    );

    loop {
        if let Ok(s) = api.get_swap(&state.swap_id).await {
            if s.status != last_status {
                println!("swap status: {}", s.status);
                last_status = s.status.clone();
            }
            if s.status == "transaction.claimed" {
                println!("=== chain swap claimed — battle test complete ===");
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

async fn wait_and_claim(state: State) {
    let chain = parse_chain(&state.chain);
    let secp = Secp256k1::new();
    let keys = Keypair::from_seckey_str(&secp, &state.claim_secret_key).unwrap();
    let preimage = Preimage::from_str(&state.preimage).unwrap();
    let claim_public_key = PublicKey {
        compressed: true,
        inner: keys.public_key(),
    };

    let api = BoltzApiClientV2::new(BOLTZ_MAINNET_URL_V2.to_string(), None);
    let client = chain_client(chain);
    let swap_script =
        SwapScript::reverse_from_swap_resp(chain, &state.swap_response, claim_public_key).unwrap();

    println!("waiting for lockup of swap {} ...", state.swap_id);
    let mut last_status = String::new();
    loop {
        let status = api.get_swap(&state.swap_id).await.map(|s| s.status);
        match status {
            Ok(status) => {
                if status != last_status {
                    println!("swap status: {status}");
                    last_status = status.clone();
                }
                match status.as_str() {
                    "transaction.mempool" | "transaction.confirmed" => break,
                    "invoice.settled" => {
                        println!("swap already settled, nothing to claim");
                        return;
                    }
                    "swap.expired"
                    | "invoice.expired"
                    | "transaction.failed"
                    | "transaction.refunded" => {
                        panic!("swap ended without lockup: {status}");
                    }
                    _ => {}
                }
            }
            Err(e) => println!("status poll failed (will retry): {e:?}"),
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    let cooperative = std::env::var("NONCOOP").is_err();
    println!(
        "lockup detected, claiming ({}) to primary {} + {} sat to {} (fee {} sat)",
        if cooperative {
            "cooperative"
        } else {
            "script path"
        },
        state.primary_address,
        state.extra_amount_sat,
        state.extra_address,
        state.claim_fee_sat,
    );

    let mut attempts = 0;
    let tx = loop {
        let params = SwapTransactionParams {
            swap_id: state.swap_id.clone(),
            keys,
            fee: Fee::Absolute(state.claim_fee_sat),
            output_address: state.primary_address.clone(),
            chain_client: &client,
            boltz_client: &api,
            options: Some(
                TransactionOptions::default()
                    .with_cooperative(cooperative)
                    .with_additional_outputs(vec![(
                        state.extra_address.clone(),
                        state.extra_amount_sat,
                    )]),
            ),
        };
        match swap_script.construct_claim(&preimage, params).await {
            Ok(tx) => break tx,
            Err(e) => {
                attempts += 1;
                assert!(attempts < 24, "claim construction kept failing: {e:?}");
                println!("claim construction failed (attempt {attempts}, will retry): {e:?}");
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    };

    let txid = client.broadcast_tx(&tx).await.unwrap();
    println!(
        "\n=== claim broadcast: {txid} ===\nprimary gets {} sat (lockup {} - fee {} - extra {})",
        state.swap_response.onchain_amount - state.claim_fee_sat - state.extra_amount_sat,
        state.swap_response.onchain_amount,
        state.claim_fee_sat,
        state.extra_amount_sat,
    );

    loop {
        if let Ok(s) = api.get_swap(&state.swap_id).await {
            if s.status != last_status {
                println!("swap status: {}", s.status);
                last_status = s.status.clone();
            }
            if s.status == "invoice.settled" {
                println!("=== invoice settled — battle test complete ===");
                return;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
