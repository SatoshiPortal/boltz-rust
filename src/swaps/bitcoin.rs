use bitcoin::consensus::{deserialize, Decodable};
use bitcoin::hashes::Hash;
use bitcoin::hex::{DisplayHex, FromHex};
use bitcoin::key::rand::rngs::OsRng;
use bitcoin::key::rand::{thread_rng, RngCore};
use bitcoin::script::{PushBytes, PushBytesBuf};
use bitcoin::secp256k1::{All, Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::Prevouts;
use bitcoin::taproot::{LeafVersion, Signature, TaprootBuilder, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    blockdata::script::{Builder, Instruction, Script, ScriptBuf},
    opcodes::{all::*, OP_0},
    Address, OutPoint, PublicKey,
};
use bitcoin::{sighash::SighashCache, Network, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin::{
    Amount, EcdsaSighashType, PrivateKey, TapLeafHash, TapSighashType, Txid, XOnlyPublicKey,
};
use electrum_client::ElectrumApi;
use elements::encode::serialize;
use elements::pset::serialize::Serialize;
use std::ops::{Add, Index};
use std::str::FromStr;

use crate::{
    error::Error,
    network::{electrum::ElectrumConfig, Chain},
    util::secrets::Preimage,
};
use crate::{LBtcSwapScript, LBtcSwapTx};

use bitcoin::{blockdata::locktime::absolute::LockTime, hashes::hash160};

use super::boltz::{
    BoltzApiClientV2, ChainClaimTxResponse, ChainSwapDetails, Cooperative, CreateChainResponse,
    CreateReverseResponse, CreateSubmarineResponse, Leaf, PartialSig, Side,
    SubmarineClaimTxResponse, SwapTree, SwapTxKind, SwapType, ToSign,
};

use elements::secp256k1_zkp::{
    musig, MusigAggNonce, MusigKeyAggCache, MusigPartialSignature, MusigPubNonce, MusigSession,
    MusigSessionId,
};

/// Bitcoin v2 swap script helper.
///
/// This struct is used to construct a Bitcoin swap script, which facilitates atomic swaps
/// between two parties with boltz exchange.
///
/// # Fields
///
/// * `swap_type`: [`SwapType`] — Specifies the type of swap being conducted (Submarine, ReverseSubmarine, Chain).
/// * `side`: [`Option<Side>`] — Indicates the side of the swap, "Lockup" or "Claim"
///   This is optional and may not always be provided.
/// * `funding_addrs`: [`Option<Address>`] — The Bitcoin address used to fund the swap. This field is optional.
///   However, consider removing this field if it's only used to identify the network (e.g., regtest).
/// * `hashlock`: [`hash160::Hash`] — The hash of the preimage that will be used to unlock the swap.
///   The hashlock ensures that the funds can only be spent by the party with the correct preimage.
/// * `receiver_pubkey`: [`PublicKey`] — The public key of the receiver in the swap. The receiver will
///   need the corresponding private key to claim the funds.
/// * `locktime`: [`LockTime`] — The locktime specifies the earliest time at which the swap can be completed.
///   It prevents the sender from reclaiming the funds until the specified time has passed.
/// * `sender_pubkey`: [`PublicKey`] — The public key of the sender in the swap. This key is used to return
///   the funds to the sender if the swap is not completed before the locktime expires.
// TODO: This should encode the network at global level.
#[derive(Debug, PartialEq, Clone)]
pub struct BtcSwapScript {
    pub swap_type: SwapType,
    // pub swap_id: String,
    pub side: Option<Side>,
    pub funding_addrs: Option<Address>, // we should not store this as a field, since we have a method
    // if we are using it just to recognize regtest, we should consider another strategy
    pub hashlock: hash160::Hash,
    pub receiver_pubkey: PublicKey,
    pub locktime: LockTime,
    pub sender_pubkey: PublicKey,
}

impl BtcSwapScript {
    /// Creates a `BtcSwapScript` for a submarine swap from a Boltz create swap response.
    ///
    /// This method parses the swap scripts provided in the `CreateSubmarineResponse` and extracts
    /// the necessary components to construct a `BtcSwapScript` for a submarine swap. It identifies
    /// the hashlock and timelock values from the provided scripts and constructs the swap script
    /// with the given public keys and the swap's funding address.
    ///
    /// # Arguments
    ///
    /// * `create_swap_response`: [`CreateSubmarineResponse`] — The response object containing the swap details,
    /// including the claim and refund scripts used to extract the hashlock and timelock.
    /// * `our_pubkey`: [`PublicKey`] — The public key of the sender, which will be used in the swap script.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing either the constructed `BtcSwapScript` or an `Error` if the creation fails.
    ///
    /// # Example
    ///
    ///```rust
    /// use boltz_client::boltz::Leaf;
    /// use boltz_client::boltz::SwapTree;
    /// use boltz_client::Secp256k1;
    /// use boltz_client::boltz::CreateSubmarineResponse;
    /// use boltz_client::BtcSwapScript;
    ///
    ///
    /// let claim_leaf = Leaf {
    ///     output: "placeholder".to_string(),
    ///     version: 0,
    /// };
    /// let refund_leaf = Leaf {
    ///     output: "placeholder".to_string(),
    ///     version: 1,
    /// };
    /// let swap_tree = SwapTree {
    ///     claim_leaf,
    ///     refund_leaf,
    /// };
    /// let secp = Secp256k1::new();
    /// let (secret_key, our_pubkey) = secp.generate_keypair(&mut bitcoin::key::rand::thread_rng());       
    /// let create_swap_response = CreateSubmarineResponse {
    ///     accept_zero_conf: true,
    ///     address: "placeholder".to_string(),
    ///     bip21: "placeholder".to_string(),
    ///     claim_public_key: our_pubkey.clone().into(),
    ///     expected_amount: 2314,
    ///     id: "placeholder".to_string(),
    ///     referral_id: None,
    ///     swap_tree,
    ///     timeout_block_height: 90000,
    ///     blinding_key: None,
    /// };
    /// let btc_swap_script = BtcSwapScript::submarine_from_swap_resp(&create_swap_response, our_pubkey.into())
    ///     .expect("Failed to create BtcSwapScript");
    ///  
    /// // Use the `btc_swap_script` for further processing...
    /// ```
    pub fn submarine_from_swap_resp(
        create_swap_response: &CreateSubmarineResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = ScriptBuf::from_hex(&create_swap_response.swap_tree.claim_leaf.output)?;
        let refund_script =
            ScriptBuf::from_hex(&create_swap_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0;
        let mut hashlock = None;
        let mut timelock = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&create_swap_response.address)?.assume_checked();

        Ok(BtcSwapScript {
            swap_type: SwapType::Submarine,
            // swap_id: create_swap_response.id.clone(),
            side: None,
            funding_addrs: Some(funding_addrs),
            hashlock: hashlock,
            receiver_pubkey: create_swap_response.claim_public_key,
            locktime: timelock,
            sender_pubkey: our_pubkey,
        })
    }
    /// Generates a MuSig2 key aggregation cache for the swap.
    ///
    /// This method creates a `MusigKeyAggCache` using the public keys of the sender and receiver
    /// in the correct order based on the swap type and side. The key aggregation cache is used
    /// in the MuSig2 signing process to ensure that all signers' public keys are correctly aggregated.
    ///
    /// # Returns
    ///
    /// A `MusigKeyAggCache` object that aggregates the public keys in the appropriate order.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use bitcoin::secp256k1::{Secp256k1, PublicKey};
    /// # use submarine_swap::{BtcSwapScript, SwapType, Side};
    /// # use secp256k1_zkp::MusigKeyAggCache;
    ///
    /// let btc_swap_script = /* ... construct a BtcSwapScript ... */;
    ///
    /// let musig_cache = btc_swap_script.musig_keyagg_cache();
    ///
    /// // Use `musig_cache` for further signing operations...
    /// ```
    pub fn musig_keyagg_cache(&self) -> MusigKeyAggCache {
        match (self.swap_type, self.side.clone()) {
            (SwapType::ReverseSubmarine, _) | (SwapType::Chain, Some(Side::Claim)) => {
                let pubkeys = [self.sender_pubkey.inner, self.receiver_pubkey.inner];
                MusigKeyAggCache::new(&Secp256k1::new(), &pubkeys)
            }

            (SwapType::Submarine, _) | (SwapType::Chain, _) => {
                let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];
                MusigKeyAggCache::new(&Secp256k1::new(), &pubkeys)
            }
        }
    }

    /// Creates a `BtcSwapScript` for a reverse submarine swap from a Boltz create swap response.
    ///
    /// This method constructs a `BtcSwapScript` by parsing the provided `CreateReverseResponse`.
    /// It extracts the hashlock and timelock from the claim and refund scripts, respectively.
    /// The resulting `BtcSwapScript` can be used to manage the reverse submarine swap's logic.
    ///
    /// # Arguments
    ///
    /// * `reverse_response` - A reference to a `CreateReverseResponse` which contains the swap details.
    /// * `our_pubkey` - The public key of the current participant, which will be set as the receiver's public key.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the constructed `BtcSwapScript` or an `Error` if something goes wrong during parsing.
    ///
    /// # Errors
    ///
    /// - Returns `Error::Protocol` if the claim script doesn't contain a valid hashlock or if the refund script doesn't contain a valid timelock.
    /// - Returns any errors encountered during hex decoding or address parsing.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use bitcoin::secp256k1::PublicKey;
    /// # use submarine_swap::{BtcSwapScript, SwapType, CreateReverseResponse};
    ///
    /// let reverse_response = /* construct a CreateReverseResponse */;
    /// let our_pubkey = /* obtain our public key */;
    ///
    /// let swap_script = BtcSwapScript::reverse_from_swap_resp(&reverse_response, our_pubkey)?;
    ///
    /// // Use `swap_script` for further processing...
    /// ```
    pub fn reverse_from_swap_resp(
        reverse_response: &CreateReverseResponse,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = ScriptBuf::from_hex(&reverse_response.swap_tree.claim_leaf.output)?;
        let refund_script = ScriptBuf::from_hex(&reverse_response.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0;
        let mut hashlock = None;
        let mut timelock = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&reverse_response.lockup_address)?.assume_checked();

        Ok(BtcSwapScript {
            swap_type: SwapType::ReverseSubmarine,
            // swap_id: reverse_response.id.clone(),
            side: None,
            funding_addrs: Some(funding_addrs),
            hashlock: hashlock,
            receiver_pubkey: our_pubkey,
            locktime: timelock,
            sender_pubkey: reverse_response.refund_public_key,
        })
    }

    /// Creates a `BtcSwapScript` for a chain swap from a Boltz create swap response.
    ///
    /// This method constructs a `BtcSwapScript` by parsing the provided `ChainSwapDetails`.
    /// It extracts the hashlock and timelock from the claim and refund scripts, respectively.
    /// The resulting `BtcSwapScript` can be used to manage the chain swap's logic.
    ///
    /// # Arguments
    ///
    /// * `side` - A `Side` enum indicating whether the current participant is on the `Lockup` or `Claim` side of the swap.
    /// * `chain_swap_details` - A `ChainSwapDetails` struct containing details about the swap.
    /// * `our_pubkey` - The public key of the current participant, used as either the sender or receiver's public key depending on the `side`.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the constructed `BtcSwapScript` or an `Error` if something goes wrong during parsing.
    ///
    /// # Errors
    ///
    /// - Returns `Error::Protocol` if the claim script doesn't contain a valid hashlock or if the refund script doesn't contain a valid timelock.
    /// - Returns any errors encountered during hex decoding or address parsing.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use bitcoin::secp256k1::PublicKey;
    /// # use submarine_swap::{BtcSwapScript, SwapType, ChainSwapDetails, Side};
    ///
    /// let chain_swap_details = /* obtain or construct a ChainSwapDetails */;
    /// let our_pubkey = /* obtain our public key */;
    /// let side = Side::Lockup; // or Side::Claim
    ///
    /// let swap_script = BtcSwapScript::chain_from_swap_resp(side, chain_swap_details, our_pubkey)?;
    ///
    /// // Use `swap_script` for further processing...
    /// ```
    pub fn chain_from_swap_resp(
        side: Side,
        chain_swap_details: ChainSwapDetails,
        our_pubkey: PublicKey,
    ) -> Result<Self, Error> {
        let claim_script = ScriptBuf::from_hex(&chain_swap_details.swap_tree.claim_leaf.output)?;
        let refund_script = ScriptBuf::from_hex(&chain_swap_details.swap_tree.refund_leaf.output)?;

        let claim_instructions = claim_script.instructions();
        let refund_instructions = refund_script.instructions();

        let mut last_op = OP_0;
        let mut hashlock = None;
        let mut timelock = None;

        for instruction in claim_instructions {
            match instruction {
                Ok(Instruction::PushBytes(bytes)) => {
                    if bytes.len() == 20 {
                        hashlock = Some(hash160::Hash::from_slice(bytes.as_bytes())?);
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        for instruction in refund_instructions {
            match instruction {
                Ok(Instruction::Op(opcode)) => last_op = opcode,
                Ok(Instruction::PushBytes(bytes)) => {
                    if last_op == OP_CHECKSIGVERIFY {
                        timelock = Some(LockTime::from_consensus(bytes_to_u32_little_endian(
                            &bytes.as_bytes(),
                        )));
                    } else {
                        continue;
                    }
                }
                _ => continue,
            }
        }

        let hashlock =
            hashlock.ok_or_else(|| Error::Protocol("No hashlock provided".to_string()))?;

        let timelock =
            timelock.ok_or_else(|| Error::Protocol("No timelock provided".to_string()))?;

        let funding_addrs = Address::from_str(&chain_swap_details.lockup_address)?.assume_checked();

        let (sender_pubkey, receiver_pubkey) = match side {
            Side::Lockup => (our_pubkey, chain_swap_details.server_public_key),
            Side::Claim => (chain_swap_details.server_public_key, our_pubkey),
        };

        Ok(BtcSwapScript {
            swap_type: SwapType::Chain,
            // swap_id: reverse_response.id.clone(),
            side: Some(side),
            funding_addrs: Some(funding_addrs),
            hashlock,
            receiver_pubkey,
            locktime: timelock,
            sender_pubkey,
        })
    }
    /// Generates the claim script for the swap.
    ///
    /// The claim script is used to claim the funds in the swap. The exact script structure depends on the type of swap.
    ///
    /// # Returns
    ///
    /// A `ScriptBuf` representing the claim script.
    ///
    /// # Script Structure
    ///
    /// - **Submarine Swap**:
    ///   - `OP_HASH160 <hashlock> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG`
    ///
    /// - **Reverse Submarine Swap or Chain Swap**:
    ///   - `OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <hashlock> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG`
    ///
    /// The script ensures that the correct preimage is provided (`hashlock`) and that the signature from the receiver's public key (`receiver_pubkey`) is valid.
    fn claim_script(&self) -> ScriptBuf {
        match self.swap_type {
            SwapType::Submarine => Builder::new()
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.to_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_x_only_key(&self.receiver_pubkey.inner.x_only_public_key().0)
                .push_opcode(OP_CHECKSIG)
                .into_script(),

            SwapType::ReverseSubmarine | SwapType::Chain => Builder::new()
                .push_opcode(OP_SIZE)
                .push_int(32)
                .push_opcode(OP_EQUALVERIFY)
                .push_opcode(OP_HASH160)
                .push_slice(self.hashlock.to_byte_array())
                .push_opcode(OP_EQUALVERIFY)
                .push_x_only_key(&self.receiver_pubkey.inner.x_only_public_key().0)
                .push_opcode(OP_CHECKSIG)
                .into_script(),
        }
    }
    /// Generates the refund script for the swap.
    ///
    /// The refund script is used to reclaim the funds if the swap fails. This script is the same across all swap types.
    ///
    /// # Returns
    ///
    /// A `ScriptBuf` representing the refund script.
    ///
    /// # Script Structure
    ///
    /// - `OP_CHECKSIGVERIFY <sender_pubkey> OP_CLTV <locktime>`
    ///
    /// The script ensures that the sender's signature is valid and that the locktime has passed before the refund can be claimed.
    fn refund_script(&self) -> ScriptBuf {
        // Refund scripts are same for all swap types
        Builder::new()
            .push_x_only_key(&self.sender_pubkey.inner.x_only_public_key().0)
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_lock_time(self.locktime)
            .push_opcode(OP_CLTV)
            .into_script()
    }

    /// Internally used to convert struct into a bitcoin::Script type
    ///
    /// This function constructs the Taproot structure using the `claim_script` and `refund_script`
    /// as Taproot leaves. It verifies the Taproot construction against the funding address, if provided.
    ///
    /// # Returns
    ///
    /// A `Result<TaprootSpendInfo, Error>` containing the constructed Taproot spend information.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Taproot` if the Taproot construction fails, or an `Error::Protocol` if the
    /// verification of the Taproot construction against the funding address fails.
    ///
    /// # Implementation Details
    ///
    /// - **Key Aggregation**: The `musig_keyagg_cache` method is used to aggregate the sender and
    ///   receiver public keys, forming the internal key of the Taproot.
    ///
    /// - **Taproot Leaves**:
    ///   - The `claim_script` and `refund_script` are added as Taproot leaves.
    ///
    /// - **Taproot Finalization**:
    ///   - The Taproot structure is finalized with the internal key and added leaves.
    ///
    /// - **Verification**:
    ///   - If the `funding_addrs` field is present, the constructed Taproot is verified against the
    ///     known funding address. The verification ensures the constructed Taproot matches the expected
    ///     XOnly public key derived from the funding address.
    ///
    /// - **Logging**:
    ///   - Logs a success message if the Taproot creation and verification succeed.
    ///
    /// # Security Considerations
    ///
    /// - The function performs a critical verification step where it checks if the Taproot construction
    ///   aligns with the funding address, ensuring that the constructed Taproot is valid and matches
    ///   the intended lockup conditions.
    ///
    /// - Skipping verification for certain test conditions (`regtest`) where the funding address is not
    ///   available is a potential point of concern, but it is controlled and intended for testing environments only.
    fn taproot_spendinfo(&self) -> Result<TaprootSpendInfo, Error> {
        let secp = Secp256k1::new();

        // Setup Key Aggregation cache
        // let pubkeys = [self.receiver_pubkey.inner, self.sender_pubkey.inner];

        let mut key_agg_cache = self.musig_keyagg_cache();

        // Construct the Taproot
        let internal_key = key_agg_cache.agg_pk();

        let taproot_builder = TaprootBuilder::new();

        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.claim_script(), LeafVersion::TapScript)?;
        let taproot_builder =
            taproot_builder.add_leaf_with_ver(1, self.refund_script(), LeafVersion::TapScript)?;

        let taproot_spend_info = match taproot_builder.finalize(&secp, internal_key) {
            Ok(r) => r,
            Err(e) => {
                return Err(Error::Taproot(
                    "Could not finalize taproot constructions".to_string(),
                ))
            }
        };

        // Verify taproot construction, only if we have funding address previously known.
        // Which will be None only for regtest integration tests, so verification will be skipped for them.
        if let Some(funding_address) = &self.funding_addrs {
            let claim_key = taproot_spend_info.output_key();

            let lockup_spk = funding_address.script_pubkey();

            let pubkey_instruction = lockup_spk
                .instructions()
                .last()
                .expect("should contain value")
                .expect("should not fail");

            let lockup_xonly_pubkey_bytes = pubkey_instruction
                .push_bytes()
                .expect("pubkey bytes expected");

            let lockup_xonly_pubkey =
                XOnlyPublicKey::from_slice(lockup_xonly_pubkey_bytes.as_bytes())?;

            if lockup_xonly_pubkey != claim_key.to_inner() {
                return Err(Error::Protocol(format!(
                    "Taproot construction Failed. Lockup Pubkey: {}, Claim Pubkey {}",
                    lockup_xonly_pubkey, claim_key
                )));
            }

            log::info!("Taproot creation and verification success!");
        }

        Ok(taproot_spend_info)
    }

    /// Get the Taproot address for the swap script.
    ///
    /// This function derives the Taproot address associated with the swap script,
    /// based on the provided Bitcoin network.
    ///
    /// # Arguments
    ///
    /// * `network` - The Bitcoin network (e.g., Mainnet, Testnet, Regtest) for which
    ///   the address should be generated.
    ///
    /// # Returns
    ///
    /// A `Result<Address, Error>` containing the Taproot address.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Protocol` if the function is used with an unsupported network.
    pub fn to_address(&self, network: Chain) -> Result<Address, Error> {
        let spend_info = self.taproot_spendinfo()?;
        let output_key = spend_info.output_key();

        let mut network = match network {
            Chain::Bitcoin => Network::Bitcoin,
            Chain::BitcoinRegtest => Network::Regtest,
            Chain::BitcoinTestnet => Network::Testnet,
            _ => {
                return Err(Error::Protocol(
                    "Liquid chain used for Bitcoin operations".to_string(),
                ))
            }
        };

        Ok(Address::p2tr_tweaked(output_key, network))
    }
    /// Validate the provided address against the swap script.
    ///
    /// This function compares a given address with the address derived from the swap script.
    /// It verifies whether the provided address matches the expected Taproot address.
    ///
    /// # Arguments
    ///
    /// * `chain` - The Bitcoin network on which the address validation should occur.
    /// * `address` - The address to be validated as a `String`.
    ///
    /// # Returns
    ///
    /// A `Result<(), Error>` indicating whether the validation succeeded.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Protocol` if the provided address does not match the derived address.
    pub fn validate_address(&self, chain: Chain, address: String) -> Result<(), Error> {
        let to_address = self.to_address(chain)?;
        if to_address.to_string() == address {
            Ok(())
        } else {
            Err(Error::Protocol("Script/LockupAddress Mismatch".to_string()))
        }
    }

    /// Get the balance of the swap script.
    ///
    /// This function queries the Electrum server for the balance associated with the swap script.
    /// It returns both confirmed and unconfirmed balances.
    ///
    /// # Arguments
    ///
    /// * `network_config` - The configuration details for the Electrum client.
    ///
    /// # Returns
    ///
    /// A `Result<(u64, i64), Error>` where:
    /// - The first value is the confirmed balance in satoshis.
    /// - The second value is the unconfirmed balance in satoshis.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Protocol` if the balance retrieval fails.
    pub fn get_balance(&self, network_config: &ElectrumConfig) -> Result<(u64, i64), Error> {
        let electrum_client = network_config.build_client()?;
        let spk = self.to_address(network_config.network())?.script_pubkey();
        let script_balance = electrum_client.script_get_balance(spk.as_script())?;
        Ok((script_balance.confirmed, script_balance.unconfirmed))
    }

    /// Fetch the UTXO and its amount for the swap script.
    ///
    /// This function queries the Electrum server to find the unspent transaction output (UTXO)
    /// associated with the swap script's public key. It returns the first found UTXO, if any.
    ///
    /// # Arguments
    ///
    /// * `network_config` - The configuration details for the Electrum client.
    ///
    /// # Returns
    ///
    /// A `Result<Option<(OutPoint, TxOut)>, Error>` containing:
    /// - `Some((OutPoint, TxOut))` if a UTXO is found.
    /// - `None` if no UTXO is found.
    ///
    /// # Errors
    ///
    /// Returns an `Error::Protocol` if the UTXO retrieval fails.
    pub fn fetch_utxo(
        &self,
        network_config: &ElectrumConfig,
    ) -> Result<Option<(OutPoint, TxOut)>, Error> {
        let electrum_client = network_config.build_client()?;
        let spk = self.to_address(network_config.network())?.script_pubkey();
        let utxos = electrum_client.script_list_unspent(spk.as_script())?;

        if utxos.len() == 0 {
            // No utxo found. Return None.
            return Ok(None);
        } else {
            let outpoint_0 = OutPoint::new(utxos[0].tx_hash, utxos[0].tx_pos as u32);
            let txout = TxOut {
                script_pubkey: spk,
                value: Amount::from_sat(utxos[0].value),
            };
            Ok(Some((outpoint_0, txout)))
        }
    }

    /// Fetch utxo for script from BoltzApi
    pub fn fetch_lockup_utxo_boltz(
        &self,
        network_config: &ElectrumConfig,
        boltz_url: &str,
        swap_id: &str,
        tx_kind: SwapTxKind,
    ) -> Result<Option<(OutPoint, TxOut)>, Error> {
        let boltz_client: BoltzApiClientV2 = BoltzApiClientV2::new(boltz_url);
        let chain_txs = boltz_client.get_chain_txs(swap_id)?;
        let hex = match self.swap_type {
            SwapType::Chain => match tx_kind {
                SwapTxKind::Claim => {
                    chain_txs
                        .server_lock
                        .ok_or(Error::Protocol(
                            "No server_lock transaction for Chain Swap available".to_string(),
                        ))?
                        .transaction
                        .hex
                }
                SwapTxKind::Refund => {
                    chain_txs
                        .user_lock
                        .ok_or(Error::Protocol(
                            "No user_lock transaction for Chain Swap available".to_string(),
                        ))?
                        .transaction
                        .hex
                }
            },
            SwapType::ReverseSubmarine => boltz_client.get_reverse_tx(swap_id)?.hex,
            SwapType::Submarine => boltz_client.get_submarine_tx(swap_id)?.hex,
        };
        if (hex.is_none()) {
            return Err(Error::Hex(
                "No transaction hex found in boltz response".to_string(),
            ));
        }
        let address = self.to_address(network_config.network())?;
        let tx: Transaction = bitcoin::consensus::deserialize(&hex::decode(&hex.unwrap())?)?;
        let mut vout = 0;
        for output in tx.clone().output {
            if output.script_pubkey == address.script_pubkey() {
                let outpoint_0 = OutPoint::new(tx.txid(), vout);
                return Ok(Some((outpoint_0, output)));
            }
            vout += 1;
        }
        return Ok(None);
    }
}

pub fn bytes_to_u32_little_endian(bytes: &[u8]) -> u32 {
    let mut result = 0u32;
    for (i, &byte) in bytes.iter().enumerate() {
        result |= (byte as u32) << (8 * i);
    }
    result
}

/// A structure representing either a Claim or a Refund Tx.
/// This Tx spends from the HTLC.
/// Represents a Bitcoin swap transaction that can either be a Claim or a Refund transaction.
/// This transaction spends from an HTLC (Hash Time-Locked Contract).
///
/// # Fields:
///
/// * `kind` - The type of swap transaction, specified by [SwapTxKind]. This indicates whether
///   the transaction is a Claim or a Refund.
///
/// * `swap_script` - The [BtcSwapScript] used in the swap transaction. This script governs
///   the conditions under which the swap can be executed.
///
/// * `output_address` - The [Address] where the output of the swap transaction will be sent.
///
/// * `utxo` - A tuple consisting of:
///   - `OutPoint` - The outpoint of the HTLC UTXO, identifying the specific UTXO to be spent.
///   - `TxOut` - The transaction output associated with the HTLC UTXO, which includes details like
///     the value and script.
///
/// # Example:
///
/// ```rust
/// use some_crate::{BtcSwapTx, SwapTxKind, BtcSwapScript, Address, OutPoint, TxOut};
///
/// // Example instantiation of BtcSwapTx
/// let tx = BtcSwapTx {
///     kind: SwapTxKind::Claim,
///     swap_script: BtcSwapScript::new(...),  // Replace with actual BtcSwapScript creation
///     output_address: Address::new(...),      // Replace with actual Address creation
///     utxo: (
///         OutPoint::new(...),                 // Replace with actual OutPoint creation
///         TxOut::new(...)                     // Replace with actual TxOut creation
///     ),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct BtcSwapTx {
    pub kind: SwapTxKind, // These fields needs to be public to do manual creation in IT.
    pub swap_script: BtcSwapScript,
    pub output_address: Address,
    // The HTLC utxo in (Outpoint, Amount) Pair
    pub utxo: (OutPoint, TxOut),
}

impl BtcSwapTx {
    /// Creates a new Claim transaction for Reverse and Chain swaps.
    ///
    /// This function constructs a `Claim` transaction using the provided `swap_script` and `claim_address`.
    /// It verifies that the swap type is compatible with claim transactions and checks the validity
    /// of the provided address for the appropriate network (Bitcoin or Testnet).
    ///
    /// **Important:** Claim transactions cannot be constructed for Submarine swaps. If the HTLC UTXO
    /// does not exist for the swap, the function returns an error.
    ///
    /// # Arguments:
    ///
    /// * `swap_script` - A [BtcSwapScript] defining the script used for the swap. This should match the
    ///   expected script for the swap type.
    /// * `claim_address` - A string representation of the address to which the output of the Claim
    ///   transaction will be sent. This address must be valid for the network specified in the
    ///   `network_config`.
    /// * `network_config` - A reference to [ElectrumConfig] containing network configuration details.
    ///   This is used to determine the network type and fetch relevant UTXO information.
    ///
    /// # Returns:
    ///
    /// Returns a `Result` containing:
    /// * `Ok(BtcSwapTx)` - A new `BtcSwapTx` instance of type `Claim` if the UTXO is found and address is valid.
    /// * `Err(Error)` - An error if:
    ///   - The swap type is Submarine, which is not supported for claim transactions.
    ///   - The address is invalid for the specified network.
    ///   - No UTXO is detected for the given script.
    ///
    /// # Errors:
    ///
    /// * `Error::Protocol` - If the swap type is Submarine or if no UTXO is found for the script.
    /// * `AddressError` - If the provided `claim_address` is not valid for the specified network.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use some_crate::{BtcSwapTx, BtcSwapScript, Address, ElectrumConfig, Error};
    ///
    /// // Example setup
    /// let swap_script = BtcSwapScript::new(...); // actual script creation
    /// let claim_address = "your_claim_address".to_string();
    /// let network_config = ElectrumConfig::new(...); // actual network configuration
    ///
    /// match BtcSwapTx::new_claim(swap_script, claim_address, &network_config) {
    ///     Ok(tx) => println!("Claim transaction created: {:?}", tx),
    ///     Err(e) => eprintln!("Error creating claim transaction: {:?}", e),
    /// }
    /// ```
    pub fn new_claim(
        swap_script: BtcSwapScript,
        claim_address: String,
        network_config: &ElectrumConfig,
        boltz_url: String,
        swap_id: String,
    ) -> Result<BtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim transactions cannot be constructed for Submarine swaps.".to_string(),
            ));
        }

        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };
        let address = Address::from_str(&claim_address)?;

        address.is_valid_for_network(network);

        let utxo_info = match swap_script.fetch_utxo(&network_config) {
            Ok(r) => r,
            Err(_) => swap_script.fetch_lockup_utxo_boltz(
                &network_config,
                &boltz_url,
                &swap_id,
                SwapTxKind::Claim,
            )?,
        };
        if let Some(utxo) = utxo_info {
            Ok(BtcSwapTx {
                kind: SwapTxKind::Claim,
                swap_script,
                output_address: address.assume_checked(),
                utxo,
            })
        } else {
            Err(Error::Protocol(
                "No Bitcoin UTXO detected for this script".to_string(),
            ))
        }
    }

    /// Constructs a Refund transaction corresponding to the provided `swap_script`.
    ///
    /// This function creates a `Refund` transaction for the specified swap script. It supports
    /// Submarine and Chain swaps, but not Reverse Submarine swaps. The function checks for
    /// the existence of the HTLC UTXO in the blockchain. If the UTXO does not exist, it returns an error.
    ///
    /// **Important:** Refund transactions cannot be constructed for Reverse Submarine swaps.
    ///
    /// # Arguments:
    ///
    /// * `swap_script` - A [BtcSwapScript] that defines the script associated with the swap.
    ///   This script should match the swap type for which the refund is being created.
    /// * `refund_address` - A reference to a string containing the address where the refund
    ///   transaction output will be sent. This address must be valid for the network specified in
    ///   the `network_config`.
    /// * `network_config` - A reference to [ElectrumConfig] providing the network configuration.
    ///   This is used to determine the network type and fetch relevant UTXO information.
    ///
    /// # Returns:
    ///
    /// Returns a `Result` containing:
    /// * `Ok(BtcSwapTx)` - A new `BtcSwapTx` instance of type `Refund` if the UTXO is found and
    ///   the address is valid.
    /// * `Err(Error)` - An error if:
    ///   - The swap type is Reverse Submarine, which is not supported for refund transactions.
    ///   - The provided address is invalid for the specified network.
    ///   - No UTXO is detected for the given script.
    ///
    /// # Errors:
    ///
    /// * `Error::Protocol` - If the swap type is Reverse Submarine or if no UTXO is found for the script.
    /// * `Error::Address` - If the provided `refund_address` is not valid for the specified network.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use some_crate::{BtcSwapTx, BtcSwapScript, Address, ElectrumConfig, Error};
    ///
    /// // Example setup
    /// let swap_script = BtcSwapScript::new(...); // actual script creation
    /// let refund_address = "your_refund_address".to_string();
    /// let network_config = ElectrumConfig::new(...); // actual network configuration
    ///
    /// match BtcSwapTx::new_refund(swap_script, &refund_address, &network_config) {
    ///     Ok(tx) => println!("Refund transaction created: {:?}", tx),
    ///     Err(e) => eprintln!("Error creating refund transaction: {:?}", e),
    /// }
    /// ```
    pub fn new_refund(
        swap_script: BtcSwapScript,
        refund_address: &String,
        network_config: &ElectrumConfig,
        boltz_url: String,
        swap_id: String,
    ) -> Result<BtcSwapTx, Error> {
        if swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Txs cannot be constructed for Reverse Submarine Swaps.".to_string(),
            ));
        }

        let network = if network_config.network() == Chain::Bitcoin {
            Network::Bitcoin
        } else {
            Network::Testnet
        };

        let address = Address::from_str(&refund_address)?;
        if !address.is_valid_for_network(network) {
            return Err(Error::Address("Address validation failed".to_string()));
        };

        let utxo_info = match swap_script.fetch_utxo(&network_config) {
            Ok(r) => r,
            Err(_) => swap_script.fetch_lockup_utxo_boltz(
                &network_config,
                &boltz_url,
                &swap_id,
                SwapTxKind::Refund,
            )?,
        };

        if let Some(utxo) = utxo_info {
            Ok(BtcSwapTx {
                kind: SwapTxKind::Refund,
                swap_script,
                output_address: address.assume_checked(),
                utxo,
            })
        } else {
            Err(Error::Protocol(
                "No Bitcoin UTXO detected for this script".to_string(),
            ))
        }
    }

    /// Computes the MuSig partial signature for a cooperative settlement of a Submarine or Chain swap.
    ///
    /// This function performs the necessary steps to generate a MuSig partial signature as part of a
    /// cooperative swap process. It uses the provided keypair, public nonce, and transaction hash to
    /// compute the partial signature and the corresponding public nonce.
    ///
    /// **Steps:**
    /// 1. Initializes the MuSig KeyAgg cache.
    /// 2. Applies a tweak to the public key aggregation cache.
    /// 3. Generates nonces for the MuSig signing session.
    /// 4. Creates the MuSig signing session and computes the partial signature.
    ///
    /// # Arguments:
    ///
    /// * `keys` - A reference to a [Keypair] containing the private key used for signing and the corresponding
    ///   public key.
    /// * `pub_nonce` - A string representation of the public nonce used in the MuSig signing process.
    /// * `transaction_hash` - A string containing the hash of the transaction to be signed, represented as a hex string.
    ///
    /// # Returns:
    ///
    /// Returns a `Result` containing:
    /// * `Ok((MusigPartialSignature, MusigPubNonce))` - A tuple with the computed partial signature and the
    ///   generated public nonce if successful.
    /// * `Err(Error)` - An error if any issues occur during the signing process. Potential errors include
    ///   problems with nonce generation, key aggregation, or invalid inputs.
    ///
    /// # Errors:
    ///
    /// The function may return errors if:
    /// * Key aggregation or nonce generation fails.
    /// * The public nonce or transaction hash is invalid.
    /// * There are issues with cryptographic operations or key parsing.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use some_crate::{BtcSwapTx, Keypair, MusigPartialSignature, MusigPubNonce, Error};
    ///
    /// // Example setup
    /// let swap_tx = BtcSwapTx::new(...); // actual BtcSwapTx initialization
    /// let keys = Keypair::new(); // actual keypair initialization
    /// let pub_nonce = "your_public_nonce".to_string();
    /// let transaction_hash = "your_transaction_hash".to_string();
    ///
    /// match swap_tx.partial_sign(&keys, &pub_nonce, &transaction_hash) {
    ///     Ok((partial_sig, gen_pub_nonce)) => {
    ///         println!("Partial signature: {:?}", partial_sig);
    ///         println!("Generated public nonce: {:?}", gen_pub_nonce);
    ///     },
    ///     Err(e) => eprintln!("Error computing partial signature: {:?}", e),
    /// }
    /// ```
    pub fn partial_sign(
        &self,
        keys: &Keypair,
        pub_nonce: &String,
        transaction_hash: &String,
    ) -> Result<(MusigPartialSignature, MusigPubNonce), Error> {
        // Step 1: Start with a Musig KeyAgg Cache
        let secp = Secp256k1::new();

        let pubkeys = [
            self.swap_script.receiver_pubkey.inner,
            self.swap_script.sender_pubkey.inner,
        ];

        let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

        let tweak = SecretKey::from_slice(
            self.swap_script
                .taproot_spendinfo()?
                .tap_tweak()
                .as_byte_array(),
        )?;

        let _ = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak)?;

        let session_id = MusigSessionId::new(&mut thread_rng());

        let msg = Message::from_digest_slice(&Vec::from_hex(transaction_hash)?)?;

        // Step 4: Start the Musig2 Signing session
        let mut extra_rand = [0u8; 32];
        OsRng.fill_bytes(&mut extra_rand);

        let (gen_sec_nonce, gen_pub_nonce) =
            key_agg_cache.nonce_gen(&secp, session_id, keys.public_key(), msg, Some(extra_rand))?;

        let boltz_nonce = MusigPubNonce::from_slice(&Vec::from_hex(pub_nonce)?)?;

        let agg_nonce = MusigAggNonce::new(&secp, &[boltz_nonce, gen_pub_nonce]);

        let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

        let partial_sig =
            musig_session.partial_sign(&secp, gen_sec_nonce, &keys, &key_agg_cache)?;

        Ok((partial_sig, gen_pub_nonce))
    }

    /// Signs a claim transaction for a swap, handling both cooperative and non-cooperative claims.
    ///
    /// This function signs a claim transaction based on the type of swap and the provided parameters.
    /// It supports both cooperative claims (where the signature involves multiple parties) and
    /// non-cooperative claims (where only the local party's signature is required).
    /// Errors are returned if the function is called for a Submarine Swap or Refund transaction.
    ///
    /// **Note:** For cooperative claims, you must provide the other party's partial signatures. If this is
    /// not provided, the transaction will be claimed via the taproot script path.
    ///
    /// # Arguments:
    ///
    /// * `keys` - A reference to a [Keypair] containing the private key used for signing and the corresponding
    ///   public key.
    /// * `preimage` - A [Preimage] object containing the preimage required for the claim transaction.
    /// * `absolute_fees` - The absolute fee amount to be deducted from the UTXO value for the claim transaction.
    /// * `is_cooperative` - An optional [Cooperative] struct containing details for a cooperative claim,
    ///   including the API for Boltz, swap ID, public nonce, and partial signatures.
    ///
    /// # Returns:
    ///
    /// Returns a `Result` containing:
    /// * `Ok(Transaction)` - The signed Bitcoin transaction if successful.
    /// * `Err(Error)` - An error if:
    ///   - The swap type is Submarine, which is not supported for claim signing.
    ///   - The transaction kind is Refund, which is not applicable for signing a claim.
    ///   - The preimage is not provided.
    ///   - There are issues with the cooperative claim process, including errors with partial signatures or
    ///     nonce generation.
    ///
    /// # Errors:
    ///
    /// The function may return errors if:
    /// * The swap type is Submarine or Refund.
    /// * The preimage is missing.
    /// * There are issues with nonce generation, signature creation, or signature verification.
    /// * The cooperative claim details are incomplete or invalid.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use some_crate::{BtcSwapTx, Keypair, Preimage, Cooperative, Error};
    ///
    /// // Example setup
    /// let swap_tx = BtcSwapTx::new(...); // actual BtcSwapTx initialization
    /// let keys = Keypair::new(); // actual keypair initialization
    /// let preimage = Preimage::new(...); // actual preimage initialization
    /// let absolute_fees = 1000; // actual fee amount
    /// let cooperative = Some(Cooperative {
    ///     boltz_api: ..., // actual Boltz API instance
    ///     swap_id: "swap_id".to_string(),
    ///     pub_nonce: Some("public_nonce".to_string()),
    ///     partial_sig: Some("partial_signature".to_string()),
    /// });
    ///
    /// match swap_tx.sign_claim(&keys, &preimage, absolute_fees, cooperative) {
    ///     Ok(tx) => println!("Claim transaction signed: {:?}", tx),
    ///     Err(e) => eprintln!("Error signing claim transaction: {:?}", e),
    /// }
    /// ```
    pub fn sign_claim(
        &self,
        keys: &Keypair,
        preimage: &Preimage,
        absolute_fees: u64,
        is_cooperative: Option<Cooperative>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::Submarine {
            return Err(Error::Protocol(
                "Claim Tx signing is not applicable for Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Refund {
            return Err(Error::Protocol(
                "Cannot sign claim with refund-type BtcSwapTx".to_string(),
            ));
        }

        let preimage_bytes = if let Some(value) = preimage.bytes {
            value
        } else {
            return Err(Error::Protocol(format!(
                "No preimage provided while signing."
            )));
        };

        let txin = TxIn {
            previous_output: self.utxo.0,
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::new(),
            witness: Witness::new(),
        };

        let destination_spk = self.output_address.script_pubkey();

        let txout = TxOut {
            script_pubkey: destination_spk,
            value: Amount::from_sat(self.utxo.1.value.to_sat() - absolute_fees),
        };

        let mut claim_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![txin],
            output: vec![txout],
        };

        let secp = Secp256k1::new();

        // If its a cooperative claim, compute the Musig2 Aggregate Signature and use Keypath spending
        if let Some(Cooperative {
            boltz_api,
            swap_id,
            pub_nonce,
            partial_sig,
        }) = is_cooperative
        {
            // Start the Musig session
            // Step 1: Get the sighash
            let claim_tx_taproot_hash = SighashCache::new(claim_tx.clone())
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.utxo.1]),
                    bitcoin::TapSighashType::Default,
                )?;

            let msg = Message::from_digest_slice(claim_tx_taproot_hash.as_byte_array())?;

            // Step 2: Get the Public and Secret nonces
            let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

            let tweak = SecretKey::from_slice(
                self.swap_script
                    .taproot_spendinfo()?
                    .tap_tweak()
                    .as_byte_array(),
            )?;

            let _ = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak)?;

            let session_id = MusigSessionId::new(&mut thread_rng());

            let mut extra_rand = [0u8; 32];
            OsRng.fill_bytes(&mut extra_rand);

            let (claim_sec_nonce, claim_pub_nonce) = key_agg_cache.nonce_gen(
                &secp,
                session_id,
                keys.public_key(),
                msg,
                Some(extra_rand),
            )?;

            // Step 7: Get boltz's partial sig
            let claim_tx_hex = serialize(&claim_tx).to_lower_hex_string();
            let partial_sig_resp = match self.swap_script.swap_type {
                SwapType::Chain => match (pub_nonce, partial_sig) {
                    (Some(pub_nonce), Some(partial_sig)) => boltz_api.post_chain_claim_tx_details(
                        &swap_id,
                        preimage,
                        pub_nonce,
                        partial_sig,
                        ToSign {
                            pub_nonce: claim_pub_nonce.serialize().to_lower_hex_string(),
                            transaction: claim_tx_hex,
                            index: 0,
                        },
                    ),
                    _ => Err(Error::Protocol(
                        "Chain swap claim needs a partial_sig".to_string(),
                    )),
                },
                SwapType::ReverseSubmarine => boltz_api.get_reverse_partial_sig(
                    &swap_id,
                    &preimage,
                    &claim_pub_nonce,
                    &claim_tx_hex,
                ),
                _ => Err(Error::Protocol(format!(
                    "Cannot get partial sig for {:?} Swap",
                    self.swap_script.swap_type
                ))),
            }?;

            let boltz_public_nonce =
                MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce)?)?;

            let boltz_partial_sig = MusigPartialSignature::from_slice(&Vec::from_hex(
                &partial_sig_resp.partial_signature,
            )?)?;

            // Aggregate Our's and Other's Nonce and start the Musig session.
            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, claim_pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the Boltz's sig.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.sender_pubkey.inner,
            );

            if !boltz_partial_sig_verify {
                return Err(Error::Protocol(
                    "Invalid partial-sig received from Boltz".to_string(),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(&secp, claim_sec_nonce, &keys, &key_agg_cache)?;

            let schnorr_sig = musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

            let final_schnorr_sig = Signature {
                sig: schnorr_sig,
                hash_ty: TapSighashType::Default,
            };

            let output_key = self.swap_script.taproot_spendinfo()?.output_key();

            let _ = secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.to_inner())?;

            let mut witness = Witness::new();
            witness.push(final_schnorr_sig.to_vec());

            claim_tx.input[0].witness = witness;
        } else {
            // If Non-Cooperative claim use the Script Path spending
            claim_tx.input[0].sequence = Sequence::ZERO;

            let leaf_hash =
                TapLeafHash::from_script(&self.swap_script.claim_script(), LeafVersion::TapScript);

            let sighash = SighashCache::new(claim_tx.clone()).taproot_script_spend_signature_hash(
                0,
                &Prevouts::All(&[&self.utxo.1]),
                leaf_hash,
                TapSighashType::Default,
            )?;

            let msg = Message::from_digest_slice(sighash.as_byte_array())?;

            let sig = secp.sign_schnorr(&msg, &keys);

            let final_sig = Signature {
                sig,
                hash_ty: TapSighashType::Default,
            };

            let control_block = self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(self.swap_script.claim_script(), LeafVersion::TapScript))
                .expect("Control block calculation failed");

            let mut witness = Witness::new();

            witness.push(final_sig.to_vec());
            witness.push(&preimage.bytes.unwrap());
            witness.push(self.swap_script.claim_script().as_bytes());
            witness.push(control_block.serialize());

            claim_tx.input[0].witness = witness;
        }

        Ok(claim_tx)
    }

    /// Signs a refund transaction for a swap.
    ///
    /// This function signs a refund transaction for a Bitcoin swap. It checks that the swap type is
    /// appropriate for a refund and handles both cooperative and non-cooperative refund claims.
    /// Errors are returned if the function is called for a Reverse Submarine Swap or if the transaction
    /// type is Claim.
    ///
    /// **Note:** For cooperative refunds, the MuSig2 signing process involves multiple parties, and
    /// both public and secret nonces are used to generate the final Schnorr signature. If not cooperative,
    /// the script path spending is used for the refund.
    ///
    /// # Arguments:
    ///
    /// * `keys` - A reference to a [Keypair] containing the private key used for signing and the corresponding
    ///   public key.
    /// * `absolute_fees` - The absolute fee amount to be deducted from the UTXO value for the refund transaction.
    /// * `is_cooperative` - An optional [Cooperative] struct containing details for a cooperative refund,
    ///   including the API for Boltz and swap ID.
    ///
    /// # Returns:
    ///
    /// Returns a `Result` containing:
    /// * `Ok(Transaction)` - The signed Bitcoin transaction if successful.
    /// * `Err(Error)` - An error if:
    ///   - The swap type is Reverse Submarine, which is not supported for refund signing.
    ///   - The transaction type is Claim, which is not applicable for signing a refund.
    ///   - There are issues with nonce generation, signature creation, or signature verification.
    ///   - The cooperative refund details are incomplete or invalid.
    ///
    /// # Errors:
    ///
    /// The function may return errors if:
    /// * The swap type is Reverse Submarine or the transaction type is Claim.
    /// * There are issues extracting the timelock from the refund script or generating signatures.
    /// * There are issues with the cooperative refund process, including errors with partial signatures or
    ///   nonce generation.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use some_crate::{BtcSwapTx, Keypair, Error};
    ///
    /// // Example setup
    /// let swap_tx = BtcSwapTx::new(...); // actual BtcSwapTx initialization
    /// let keys = Keypair::new(); // actual keypair initialization
    /// let absolute_fees = 1000; // actual fee amount
    /// let cooperative = Some(Cooperative {
    ///     boltz_api: ..., // actual Boltz API instance
    ///     swap_id: "swap_id".to_string(),
    /// });
    ///
    /// match swap_tx.sign_refund(&keys, absolute_fees, cooperative) {
    ///     Ok(tx) => println!("Refund transaction signed: {:?}", tx),
    ///     Err(e) => eprintln!("Error signing refund transaction: {:?}", e),
    /// }
    /// ```
    pub fn sign_refund(
        &self,
        keys: &Keypair,
        absolute_fees: u64,
        is_cooperative: Option<Cooperative>,
    ) -> Result<Transaction, Error> {
        if self.swap_script.swap_type == SwapType::ReverseSubmarine {
            return Err(Error::Protocol(
                "Refund Tx signing is not applicable for Reverse Submarine Swaps".to_string(),
            ));
        }

        if self.kind == SwapTxKind::Claim {
            return Err(Error::Protocol(
                "Cannot sign refund with a claim-type BtcSwapTx".to_string(),
            ));
        }

        // let unsigned_input: TxIn = TxIn {
        //     sequence: Sequence::ZERO, // enables absolute locktime
        //     previous_output: self.utxo.0,
        //     script_sig: ScriptBuf::new(),
        //     witness: Witness::new(),
        // };
        let output_amount: Amount = Amount::from_sat(self.utxo.1.value.to_sat() - absolute_fees);
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: output_amount,
        };

        let input = TxIn {
            previous_output: self.utxo.0,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        };

        let lock_time = match self
            .swap_script
            .refund_script()
            .instructions()
            .filter_map(|i| {
                let ins = i.unwrap();
                if let Instruction::PushBytes(bytes) = ins {
                    if bytes.len() < 5 as usize {
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
        {
            Some(r) => r,
            None => {
                return Err(Error::Protocol(
                    "Error getting timelock from refund script".to_string(),
                ))
            }
        };

        let mut refund_tx = Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![input],
            output: vec![output],
        };

        let secp = Secp256k1::new();

        if let Some(Cooperative {
            boltz_api, swap_id, ..
        }) = is_cooperative
        {
            // Start the Musig session
            refund_tx.lock_time = LockTime::ZERO; // No locktime for cooperative spend

            // Step 1: Get the sighash
            let refund_tx_taproot_hash = SighashCache::new(refund_tx.clone())
                .taproot_key_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.utxo.1]),
                    bitcoin::TapSighashType::Default,
                )?;

            let msg = Message::from_digest_slice(refund_tx_taproot_hash.as_byte_array())?;

            // Step 2: Get the Public and Secret nonces

            let mut key_agg_cache = self.swap_script.musig_keyagg_cache();

            let tweak = SecretKey::from_slice(
                self.swap_script
                    .taproot_spendinfo()?
                    .tap_tweak()
                    .as_byte_array(),
            )?;

            let _ = key_agg_cache.pubkey_xonly_tweak_add(&secp, tweak)?;

            let session_id = MusigSessionId::new(&mut thread_rng());

            let mut extra_rand = [0u8; 32];
            OsRng.fill_bytes(&mut extra_rand);

            let (sec_nonce, pub_nonce) = key_agg_cache.nonce_gen(
                &secp,
                session_id,
                keys.public_key(),
                msg,
                Some(extra_rand),
            )?;

            // Step 7: Get boltz's partial sig
            let refund_tx_hex = serialize(&refund_tx).to_lower_hex_string();
            let partial_sig_resp = match self.swap_script.swap_type {
                SwapType::Chain => {
                    boltz_api.get_chain_partial_sig(&swap_id, &pub_nonce, &refund_tx_hex)
                }
                SwapType::Submarine => {
                    boltz_api.get_submarine_partial_sig(&swap_id, &pub_nonce, &refund_tx_hex)
                }
                _ => Err(Error::Protocol(format!(
                    "Cannot get partial sig for {:?} Swap",
                    self.swap_script.swap_type
                ))),
            }?;

            let boltz_public_nonce =
                MusigPubNonce::from_slice(&Vec::from_hex(&partial_sig_resp.pub_nonce)?)?;

            let boltz_partial_sig = MusigPartialSignature::from_slice(&Vec::from_hex(
                &partial_sig_resp.partial_signature,
            )?)?;

            // Aggregate Our's and Other's Nonce and start the Musig session.
            let agg_nonce = MusigAggNonce::new(&secp, &[boltz_public_nonce, pub_nonce]);

            let musig_session = MusigSession::new(&secp, &key_agg_cache, agg_nonce, msg);

            // Verify the Boltz's sig.
            let boltz_partial_sig_verify = musig_session.partial_verify(
                &secp,
                &key_agg_cache,
                boltz_partial_sig,
                boltz_public_nonce,
                self.swap_script.receiver_pubkey.inner, //boltz key
            );

            if !boltz_partial_sig_verify {
                return Err(Error::Protocol(
                    "Invalid partial-sig received from Boltz".to_string(),
                ));
            }

            let our_partial_sig =
                musig_session.partial_sign(&secp, sec_nonce, &keys, &key_agg_cache)?;

            let schnorr_sig = musig_session.partial_sig_agg(&[boltz_partial_sig, our_partial_sig]);

            let final_schnorr_sig = Signature {
                sig: schnorr_sig,
                hash_ty: TapSighashType::Default,
            };

            let output_key = self.swap_script.taproot_spendinfo()?.output_key();

            let _ = secp.verify_schnorr(&final_schnorr_sig.sig, &msg, &output_key.to_inner())?;

            let mut witness = Witness::new();
            witness.push(final_schnorr_sig.to_vec());

            refund_tx.input[0].witness = witness;
        } else {
            refund_tx.input[0].sequence = Sequence::ZERO;

            let leaf_hash =
                TapLeafHash::from_script(&self.swap_script.refund_script(), LeafVersion::TapScript);

            let sighash = SighashCache::new(refund_tx.clone())
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(&[&self.utxo.1]),
                    leaf_hash,
                    TapSighashType::Default,
                )?;

            let msg = Message::from_digest_slice(sighash.as_byte_array())?;

            let sig = Secp256k1::new().sign_schnorr(&msg, &keys);

            let final_sig = Signature {
                sig,
                hash_ty: TapSighashType::Default,
            };

            let control_block = self
                .swap_script
                .taproot_spendinfo()?
                .control_block(&(
                    self.swap_script.refund_script().clone(),
                    LeafVersion::TapScript,
                ))
                .expect("Control block calculation failed");

            let mut witness = Witness::new();

            witness.push(final_sig.to_vec());
            witness.push(self.swap_script.refund_script().as_bytes());
            witness.push(control_block.serialize());

            refund_tx.input[0].witness = witness;
        }

        Ok(refund_tx)
    }

    /// Calculate the size of a transaction.
    /// Use this before calling drain to help calculate the absolute fees.
    /// Multiply the size by the fee_rate to get the absolute fees.
    pub fn size(&self, keys: &Keypair, preimage: &Preimage) -> Result<usize, Error> {
        let dummy_abs_fee = 5_000;
        // Can only calculate non-coperative claims
        let tx = match self.kind {
            SwapTxKind::Claim => self.sign_claim(keys, preimage, dummy_abs_fee, None)?,
            SwapTxKind::Refund => self.sign_refund(keys, dummy_abs_fee, None)?,
        };
        Ok(tx.vsize())
    }

    /// Broadcasts a signed transaction to the Bitcoin network.
    ///
    /// This function sends a transaction to the Bitcoin network using an Electrum client configured
    /// with the provided network configuration. It handles the communication with the Electrum server
    /// and returns the transaction ID (Txid) of the broadcasted transaction.
    ///
    /// **Note:** Ensure that the transaction is fully signed before broadcasting to avoid transaction
    /// rejection or issues with incomplete signatures.
    ///
    /// # Arguments:
    ///
    /// * `signed_tx` - A reference to the [Transaction] object that has been signed and is ready to be
    ///   broadcasted.
    /// * `network_config` - A reference to [ElectrumConfig], which contains the configuration needed to
    ///   create an Electrum client for broadcasting the transaction.
    ///
    /// # Returns:
    ///
    /// Returns a `Result` containing:
    /// * `Ok(Txid)` - The transaction ID of the broadcasted transaction if successful.
    /// * `Err(Error)` - An error if there are issues with:
    ///   - Building the Electrum client.
    ///   - Broadcasting the transaction through the Electrum client.
    ///
    /// # Errors:
    ///
    /// The function may return errors if:
    /// * There are issues creating the Electrum client, such as network problems or configuration errors.
    /// * The transaction broadcast fails due to connectivity issues or invalid transaction data.
    ///
    /// # Example:
    ///
    /// ```rust
    /// use some_crate::{BtcSwapTx, Transaction, ElectrumConfig, Error};
    ///
    /// // Example setup
    /// let swap_tx = BtcSwapTx::new(...); // actual BtcSwapTx initialization
    /// let signed_tx = Transaction::new(...); // actual signed transaction
    /// let network_config = ElectrumConfig::new(...); // actual ElectrumConfig
    ///
    /// match swap_tx.broadcast(&signed_tx, &network_config) {
    ///     Ok(txid) => println!("Transaction broadcasted with Txid: {:?}", txid),
    ///     Err(e) => eprintln!("Error broadcasting transaction: {:?}", e),
    /// }
    /// ```
    pub fn broadcast(
        &self,
        signed_tx: &Transaction,
        network_config: &ElectrumConfig,
    ) -> Result<Txid, Error> {
        Ok(network_config
            .build_client()?
            .transaction_broadcast(signed_tx)?)
    }
}
