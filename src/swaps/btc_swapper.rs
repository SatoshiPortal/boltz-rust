use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::{sha256, Hash},
    hex::{DisplayHex, FromHex},
    key::{
        rand::{rngs::OsRng, thread_rng, RngCore},
        Keypair, Secp256k1,
    },
    script::Instruction,
    secp256k1::{Message, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, Signature, TaprootBuilder},
    transaction::Version,
    Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey,
};
use electrum_client::{Client, ElectrumApi};
use elements::secp256k1_zkp::{
    MusigAggNonce, MusigKeyAggCache, MusigPartialSignature, MusigPubNonce, MusigSession,
    MusigSessionId,
};
use lightning_invoice::Bolt11Invoice;

use crate::{
    error::Error,
    network::Chain,
    swaps::{
        bitcoin::bytes_to_u32_little_endian,
        boltzv2::{CreateReverseReq, CreateSwapRequest, Subscription, SwapUpdate, BOLTZ_REGTEST},
    },
    util::{secrets::Preimage, setup_logger},
};

use super::boltzv2::{BoltzApiClientV2, ClaimTxResponse, CreateSwapResponse, ReverseResp};

pub struct BtcSwapper {
    chain: Chain,
    api: BoltzApiClientV2,
    keypair: Keypair,
}

impl BtcSwapper {
    /// Initialize a swapper
    pub fn init(boltz_url: &str, chain: Chain) -> Self {
        let secp = Secp256k1::new();

        let keypair = Keypair::new(&secp, &mut thread_rng());

        Self {
            chain,
            api: BoltzApiClientV2::new(boltz_url),
            keypair,
        }
    }

    /// Compute the Musig partial signature
    fn submarine_partial_sig(
        &self,
        create_swap_response: &CreateSwapResponse,
        claim_tx_response: &ClaimTxResponse,
    ) -> Result<(MusigPartialSignature, MusigPubNonce), Error> {
        // Step 1: Start with a Musig KeyAgg Cache
        let secp = Secp256k1::new();

        let pubkeys = [
            create_swap_response.claim_public_key.inner,
            self.keypair.public_key(),
        ];

        let mut key_agg_cache = MusigKeyAggCache::new(&secp, &pubkeys);

        // Step 2: Build the Taporoot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let (claim_script, claim_version) = (
            ScriptBuf::from_hex(&create_swap_response.swap_tree.claim_leaf.output)?,
            LeafVersion::from_consensus(create_swap_response.swap_tree.claim_leaf.version)?,
        );
        let (refund_script, refund_version) = (
            ScriptBuf::from_hex(&create_swap_response.swap_tree.refund_leaf.output)?,
            LeafVersion::from_consensus(create_swap_response.swap_tree.refund_leaf.version)?,
        );

        let taproot_builder = taproot_builder.add_leaf_with_ver(1, claim_script, claim_version)?;
        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, refund_script, refund_version)?;

        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap(); // Taproot finalizing in unfailable

        // Verify taproot construction
        let output_key = taproot_spend_info.output_key();

        let lockup_spk = Address::from_str(&create_swap_response.address)?
            .assume_checked()
            .script_pubkey();

        let pubkey_instruction = lockup_spk
            .instructions()
            .last()
            .expect("should contain value")
            .expect("should not fail");

        let lockup_xonly_pubkey_bytes = pubkey_instruction
            .push_bytes()
            .expect("pubkey bytes expected");

        let lockup_xonly_pubkey = XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes.as_bytes())?;

        debug_assert!(lockup_xonly_pubkey == output_key.to_inner());

        log::info!("Taproot creation and verification success!");

        // Step 3: Tweak the Key Cache with Taproot tweak
        let tweak = taproot_spend_info.tap_tweak();

        let tweaked_pubkey = key_agg_cache
            .pubkey_xonly_tweak_add(&secp, SecretKey::from_slice(&tweak.to_byte_array())?)?;

        debug_assert!(output_key.to_inner() == tweaked_pubkey.x_only_public_key().0);

        log::info!("Musig2 tweaking success!");

        let session_id = MusigSessionId::new(&mut thread_rng());

        let msg = Message::from_digest_slice(
            &Vec::from_hex(&claim_tx_response.transaction_hash).unwrap(),
        )?;

        // Step 4: Start the Musig2 Signing session
        let mut extra_rand = [0u8; 32];
        OsRng.fill_bytes(&mut extra_rand);

        let (sec_nonce, pub_nonce) = key_agg_cache.nonce_gen(
            &secp,
            session_id,
            self.keypair.public_key(),
            msg,
            Some(extra_rand),
        )?;

        let boltz_nonce = MusigPubNonce::from_slice(&Vec::from_hex(&claim_tx_response.pub_nonce)?)?;

        let agg_nonce = MusigAggNonce::new(&secp, &[boltz_nonce, pub_nonce]);

        let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

        let partial_sig =
            musig_session.partial_sign(&secp, sec_nonce, &self.keypair, &key_agg_cache)?;

        let is_partial_sig_valid = musig_session.partial_verify(
            &secp,
            &key_agg_cache,
            partial_sig,
            pub_nonce,
            self.keypair.public_key(),
        );

        debug_assert!(is_partial_sig_valid == true);

        log::info!("Partial Signature creation and verification success.");

        Ok((partial_sig, pub_nonce))
    }

    /// Creates a refund timelocked transaction for subamrine swap.
    pub fn submarine_refund(
        &self,
        electrum: &Client,
        create_swap_response: &CreateSwapResponse,
        destination: Address,
        fee: Amount,
    ) -> Result<Transaction, Error> {
        // Step 1: Start with a Musig KeyAgg Cache
        let secp = Secp256k1::new();

        let pubkeys = [
            create_swap_response.claim_public_key.inner,
            self.keypair.public_key(),
        ];

        let mut key_agg_cache = MusigKeyAggCache::new(&secp, &pubkeys);

        // Step 2: Build the Taporoot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let (claim_script, claim_version) = (
            ScriptBuf::from_hex(&create_swap_response.swap_tree.claim_leaf.output)?,
            LeafVersion::from_consensus(create_swap_response.swap_tree.claim_leaf.version)?,
        );
        let (refund_script, refund_version) = (
            ScriptBuf::from_hex(&create_swap_response.swap_tree.refund_leaf.output.clone())?,
            LeafVersion::from_consensus(create_swap_response.swap_tree.refund_leaf.version)?,
        );

        let taproot_builder = taproot_builder.add_leaf_with_ver(1, claim_script, claim_version)?;
        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, refund_script.clone(), refund_version)?;

        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap(); // Taproot finalizing in unfailable

        // Verify taproot construction
        let output_key = taproot_spend_info.output_key();

        let lockup_spk = Address::from_str(&create_swap_response.address)?
            .assume_checked()
            .script_pubkey();

        let pubkey_instruction = lockup_spk
            .instructions()
            .last()
            .expect("should contain value")
            .expect("should not fail");

        let lockup_xonly_pubkey_bytes = pubkey_instruction
            .push_bytes()
            .expect("pubkey bytes expected");

        let lockup_xonly_pubkey = XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes.as_bytes())?;

        debug_assert!(lockup_xonly_pubkey == output_key.to_inner());

        log::info!("Taproot creation and verification success!");

        // Assume theres only one funding UTXO.
        let funding_utxo = &electrum
            .batch_script_list_unspent([lockup_spk.as_script()])
            .unwrap()[0][0];

        let funding_txout = TxOut {
            script_pubkey: lockup_spk,
            value: Amount::from_sat(funding_utxo.value),
        };

        let funding_outpoint = OutPoint::new(funding_utxo.tx_hash, 0);

        let spending_txin = TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
            witness: Witness::new(),
        };

        let spending_txout = TxOut {
            value: Amount::from_sat(funding_utxo.value) - fee,
            script_pubkey: destination.script_pubkey(),
        };

        let lock_time = refund_script
            .instructions()
            .filter_map(|i| {
                let ins = i.unwrap();
                if let Instruction::PushBytes(bytes) = ins {
                    if bytes.len() == 3 as usize {
                        Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .next()
            .unwrap();

        let mut spending_tx = Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![spending_txin],
            output: vec![spending_txout],
        };

        let leaf_hash = TapLeafHash::from_script(&refund_script, LeafVersion::TapScript);

        let sighash = SighashCache::new(spending_tx.clone())
            .taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[funding_txout]),
                leaf_hash,
                TapSighashType::Default,
            )
            .unwrap();

        let msg = Message::from_digest_slice(sighash.as_byte_array()).unwrap();

        let sig = secp.sign_schnorr(&msg, &self.keypair);

        let final_sig = Signature {
            sig,
            hash_ty: TapSighashType::Default,
        };

        let control_block = taproot_spend_info
            .control_block(&(refund_script.clone(), LeafVersion::TapScript))
            .unwrap();

        let mut witness = Witness::new();

        witness.push(final_sig.to_vec());
        witness.push(refund_script.as_bytes());
        witness.push(control_block.serialize());

        spending_tx.input[0].witness = witness;

        Ok(spending_tx)
    }

    /// Compute the final signed claim tx for reverse swap
    fn reverse_claim_tx(
        &self,
        reverse_resp: &ReverseResp,
        preimage: &Preimage,
        destination: Address,
        fee: Amount,
        is_cooperative: bool,
    ) -> Result<Transaction, Error> {
        // Get the tx in mempool
        let tx_resp = self.api.get_reverse_tx(&reverse_resp.id).unwrap();

        let lockup_tx: Transaction = deserialize(&Vec::from_hex(&tx_resp.hex).unwrap()).unwrap();

        let secp = Secp256k1::new();
        // Start Musig

        // Step 1: Setup Key Aggregation cache
        let boltz_pubkey = reverse_resp.refund_public_key;
        let pubkeys = [boltz_pubkey.inner, self.keypair.public_key()];

        let mut key_agg_cache = MusigKeyAggCache::new(&secp, &pubkeys);

        //Step 2: Construct the Taproot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let (claim_script, claim_version) = (
            ScriptBuf::from_hex(&reverse_resp.swap_tree.claim_leaf.output)?,
            LeafVersion::from_consensus(reverse_resp.swap_tree.claim_leaf.version)?,
        );
        let (refund_script, refund_version) = (
            ScriptBuf::from_hex(&reverse_resp.swap_tree.refund_leaf.output.clone())?,
            LeafVersion::from_consensus(reverse_resp.swap_tree.refund_leaf.version)?,
        );

        let taproot_builder = taproot_builder
            .add_leaf_with_ver(1, claim_script.clone(), claim_version)
            .unwrap();
        let taproot_builder = taproot_builder
            .add_leaf_with_ver(1, refund_script, refund_version)
            .unwrap();

        let taproot_spend_info = taproot_builder.finalize(&secp, internal_key).unwrap();

        // Verify taproot construction
        let output_key = taproot_spend_info.output_key();

        let lockup_spk = Address::from_str(&reverse_resp.lockup_address)
            .unwrap()
            .assume_checked()
            .script_pubkey();

        let pubkey_instruction = lockup_spk.instructions().last().expect("expected").unwrap();

        let lockup_xonly_pubkey_bytes = pubkey_instruction
            .push_bytes()
            .expect("pubkey bytes expected");

        let lockup_xonly_pubkey =
            XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes.as_bytes()).unwrap();

        assert_eq!(lockup_xonly_pubkey, output_key.to_inner());

        log::info!("Taproot creation and verification success!");

        // Step 3: Tweak the Musig aggregated key with the taproot tweak
        let tweak = taproot_spend_info.tap_tweak();

        let tweaked_pubkey = key_agg_cache
            .pubkey_xonly_tweak_add(
                &secp,
                SecretKey::from_slice(&tweak.to_byte_array()).unwrap(),
            )
            .unwrap();

        debug_assert!(output_key.to_inner() == tweaked_pubkey.x_only_public_key().0);

        log::info!("Musig2 tweaking success!");

        // Step 4: Start the Musig Session
        let session_id = MusigSessionId::new(&mut thread_rng());

        // Step 5: Create the claim Tx
        let (lockup_outpoint, lockup_txout) = {
            let txid = lockup_tx.txid();
            let (vout, txout) = lockup_tx
                .output
                .iter()
                .enumerate()
                .find(|(index, txout)| txout.script_pubkey == lockup_spk)
                .expect("atleast one output expected");
            (OutPoint::new(txid, vout as u32), txout)
        };

        let txin = TxIn {
            previous_output: lockup_outpoint,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let destination_spk = destination.script_pubkey();

        let txout = TxOut {
            script_pubkey: destination_spk,
            value: lockup_txout.value - fee,
        };

        let mut claim_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };

        // If its a cooperative claim, compute the Musig2 Aggregate Signature and use Keypath spending
        if is_cooperative {
            let claim_tx_taproot_hash = SighashCache::new(claim_tx.clone())
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[lockup_txout]),
                    bitcoin::TapSighashType::Default,
                )
                .unwrap();

            // Step 6: Generate secret and public nonces
            let msg = Message::from_digest_slice(claim_tx_taproot_hash.as_byte_array()).unwrap();

            let mut extra_rand = [0u8; 32];
            OsRng.fill_bytes(&mut extra_rand);

            let (sec_nonce, pub_nonce) = key_agg_cache
                .nonce_gen(
                    &secp,
                    session_id,
                    self.keypair.public_key(),
                    msg,
                    Some(extra_rand),
                )
                .unwrap();

            // Step 7: Get boltz's partail sig
            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
            let partial_sig_resp = self
                .api
                .get_reverse_partial_sig(&reverse_resp.id, &preimage, &pub_nonce, &claim_tx_hex)
                .unwrap();

            let boltz_nonce =
                MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce).unwrap())
                    .unwrap();

            let boltz_partial_sig = MusigPartialSignature::from_slice(
                &Vec::from_hex(&partial_sig_resp.partial_signature).unwrap(),
            )
            .unwrap();

            // Step 7: Perform

            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_nonce, pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            let our_partial_sig = musig_session
                .partial_sign(&secp, sec_nonce, &self.keypair, &key_agg_cache)
                .unwrap();

            let schnorr_sig = musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

            let final_schnorr_sig = Signature {
                sig: schnorr_sig,
                hash_ty: TapSighashType::Default,
            };

            // Verify the sigs.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_nonce,
                boltz_pubkey.inner,
            );

            debug_assert!(boltz_partial_sig_verify == true);

            let final_sig_verify =
                secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.to_inner())?;

            debug_assert!(final_sig_verify == ());

            let mut witness = Witness::new();
            witness.push(final_schnorr_sig.to_vec());

            claim_tx.input[0].witness = witness;

            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
        } else {
            // If Non-Cooperative claim use the Script Path spending
            let leaf_hash = TapLeafHash::from_script(&claim_script, LeafVersion::TapScript);

            let sighash = SighashCache::new(claim_tx.clone())
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&[lockup_txout]),
                    leaf_hash,
                    TapSighashType::Default,
                )
                .unwrap();

            let msg = Message::from_digest_slice(sighash.as_byte_array()).unwrap();

            let sig = secp.sign_schnorr(&msg, &self.keypair);

            let final_sig = Signature {
                sig,
                hash_ty: TapSighashType::Default,
            };

            let control_block = taproot_spend_info
                .control_block(&(claim_script.clone(), LeafVersion::TapScript))
                .unwrap();

            let mut witness = Witness::new();

            witness.push(final_sig.to_vec());
            witness.push(&preimage.bytes.unwrap());
            witness.push(claim_script.as_bytes());
            witness.push(control_block.serialize());

            claim_tx.input[0].witness = witness;
        }

        Ok(claim_tx)
    }

    /// Perform a submarine swap with Boltz
    pub fn do_submarine(&self, invoice: &str) -> Result<(), Error> {
        setup_logger();

        let refund_public_key = PublicKey {
            inner: self.keypair.public_key(),
            compressed: true,
        };

        let data = CreateSwapRequest {
            from: "BTC".to_string(),
            to: "BTC".to_string(),
            invoice: invoice.to_string(),
            refund_public_key,
        };

        let invoice = Bolt11Invoice::from_str(&data.invoice).unwrap();

        let create_swap_response = self.api.post_swap_req(&data).unwrap();

        log::info!("Got Swap Response from Boltz server");

        log::debug!("Swap Response: {:?}", create_swap_response);

        let mut socket = self.api.connect_ws()?;

        let subscription = Subscription::new(&create_swap_response.id);

        socket.send(tungstenite::Message::Text(
            serde_json::to_string(&subscription).unwrap(),
        ))?;

        loop {
            let response = serde_json::from_str(&socket.read().unwrap().to_string());

            if response.is_err() {
                if response.err().expect("expected").is_eof() {
                    continue;
                }
            } else {
                match response.unwrap() {
                    SwapUpdate::Subscription {
                        event,
                        channel,
                        args,
                    } => {
                        debug_assert!(event == "subscribe");
                        debug_assert!(channel == "swap.update");
                        debug_assert!(args.get(0).expect("expected") == &create_swap_response.id);
                        log::info!(
                            "Subscription successful for swap : {}",
                            create_swap_response.id
                        );
                    }

                    SwapUpdate::Update {
                        event,
                        channel,
                        args,
                    } => {
                        debug_assert!(event == "update");
                        debug_assert!(channel == "swap.update");
                        let update = args.get(0).expect("expected");
                        assert!(update.id == create_swap_response.id);
                        log::info!("Got Update from server: {}", update.status);

                        if update.status == "invoice.set" {
                            log::info!(
                                "Send {} sats to BTC address {}",
                                create_swap_response.expected_amount,
                                create_swap_response.address
                            );
                        }

                        if update.status == "transaction.claim.pending" {
                            // Step 1: Get the claim tx details and check preimage hash
                            let claim_tx_response =
                                self.api.get_claim_tx_details(&create_swap_response.id)?;

                            log::debug!("Received claim tx details : {:?}", claim_tx_response);

                            let preimage = Vec::from_hex(&claim_tx_response.preimage)?;

                            let preimage_hash = sha256::Hash::hash(&preimage);

                            let invoice_payment_hash = invoice.payment_hash();

                            if invoice_payment_hash.to_string() != preimage_hash.to_string() {
                                return Err(Error::Protocol(
                                    "Preimage Hash missmatch with LN invoice".to_string(),
                                ));
                            }

                            log::info!("Correct Claim TX Response Received from Boltz.");

                            let (partial_sig, pub_nonce) = self
                                .submarine_partial_sig(&create_swap_response, &claim_tx_response)?;

                            self.api.post_claim_tx_details(
                                &create_swap_response.id,
                                pub_nonce,
                                partial_sig,
                            )?;

                            log::info!("Successfully Sent partial signature");
                        }

                        if update.status == "transaction.claimed" {
                            log::info!("Successfully completed sunmarine swap");
                            return Ok(());
                        }
                    }

                    SwapUpdate::Error {
                        event,
                        channel,
                        args,
                    } => {
                        assert!(event == "update");
                        assert!(channel == "swap.update");
                        let error = args.get(0).expect("expected");
                        log::error!(
                            "Got Boltz response error : {} for swap: {}",
                            error.error,
                            error.id
                        );
                    }
                }
            }
        }
    }

    /// Perform a reverse swap with Boltz
    pub fn do_reverse_swap(
        &self,
        invoice_amount: u32,
        claim_addrs: Address,
        claim_tx_fee: Amount,
    ) -> Result<(), Error> {
        setup_logger();
        let preimage = Preimage::new();

        let create_reverse_req = CreateReverseReq {
            invoice_amount,
            from: "BTC".to_string(),
            to: "BTC".to_string(),
            preimage_hash: preimage.sha256,
            claim_public_key: PublicKey {
                compressed: true,
                inner: self.keypair.public_key(),
            },
        };

        let reverse_resp = self.api.post_reverse_req(create_reverse_req).unwrap();

        log::debug!("Got Reverse swap response: {:?}", reverse_resp);

        let mut socket = self.api.connect_ws()?;

        let subscription = Subscription::new(&reverse_resp.id);

        socket.send(tungstenite::Message::Text(
            serde_json::to_string(&subscription).unwrap(),
        ))?;

        loop {
            let response = serde_json::from_str(&socket.read().unwrap().to_string());

            if response.is_err() {
                if response.err().expect("expected").is_eof() {
                    continue;
                }
            } else {
                match response.as_ref().unwrap() {
                    SwapUpdate::Subscription {
                        event,
                        channel,
                        args,
                    } => {
                        debug_assert!(event == "subscribe");
                        debug_assert!(channel == "swap.update");
                        debug_assert!(args.get(0).expect("expected") == &reverse_resp.id);
                        log::info!("Subscription successful for swap : {}", reverse_resp.id);
                    }

                    SwapUpdate::Update {
                        event,
                        channel,
                        args,
                    } => {
                        debug_assert!(event == "update");
                        debug_assert!(channel == "swap.update");
                        let update = args.get(0).expect("expected");
                        debug_assert!(&update.id == &reverse_resp.id);
                        log::info!("Got Update from server: {}", update.status);

                        if update.status == "swap.created" {
                            log::info!("Waiting for Invoice to be paid: {}", reverse_resp.invoice);
                            continue;
                        }

                        if update.status == "transaction.mempool" {
                            let tx = self.reverse_claim_tx(
                                &reverse_resp,
                                &preimage,
                                claim_addrs.clone(),
                                claim_tx_fee,
                                true,
                            )?;

                            let claim_tx_hex = serialize(&tx).to_lower_hex_string();
                            self.api.broadcast_tx(self.chain, &claim_tx_hex)?;

                            log::info!("Succesfully broadcasted claim tx!");
                            log::debug!("Claim Tx Hex: {}", claim_tx_hex);
                        }

                        if update.status == "invoice.settled" {
                            log::info!("Reverse Swap Successful!");
                            return Ok(());
                        }
                    }

                    SwapUpdate::Error {
                        event,
                        channel,
                        args,
                    } => {
                        assert!(event == "update");
                        assert!(channel == "swap.update");
                        let error = args.get(0).expect("expected");
                        println!("Got error : {} for swap: {}", error.error, error.id);
                    }
                }
            }
        }
    }
}
