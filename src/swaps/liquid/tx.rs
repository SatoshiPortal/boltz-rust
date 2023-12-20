use bitcoin::Network;
use electrum_client::ElectrumApi;

use bitcoin::script::Script as BitcoinScript;
use elements::{
    confidential::{Nonce, Value},
    hex::ToHex,
    secp256k1_zkp::{Generator, PedersenCommitment, RangeProof, Secp256k1, Tag, Tweak},
    sighash::SighashCache,
    Address, AssetId, AssetIssuance, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness, Txid,
};

use secp256k1::{AllPreallocated, Message, PublicKey};
use std::str::FromStr;

use crate::{
    e::S5Error,
    key::{
        ec::{BlindingKeyPair, KeyPairString},
        preimage::Preimage,
    },
    network::electrum::NetworkConfig,
    swaps::boltz::SwapTxKind,
};

use super::script::LBtcRevSwapScript;

pub const DUST_VALUE: u64 = 546;
// 3-input ASP
pub const DEFAULT_SURJECTIONPROOF_SIZE: u64 = 135;
// 52-bit rangeproof
pub const DEFAULT_RANGEPROOF_SIZE: u64 = 4174;

#[derive(Debug, Clone)]
pub struct LBtcRevSwapTx {
    _network: Network,
    kind: SwapTxKind,
    script_elements: LBtcRevSwapScript,
    output_address: Address,
    absolute_fees: u32,
    utxo: Option<OutPoint>,
    utxo_value: Option<u64>, // there should only ever be one outpoint in a swap
}

impl LBtcRevSwapTx {
    pub fn manual_utxo_update(&mut self, utxo: OutPoint, value: u64) -> LBtcRevSwapTx {
        self.utxo = Some(utxo);
        self.utxo_value = Some(value);
        self.clone()
    }
    pub fn new_claim(
        redeem_script: String,
        output_address: String,
        absolute_fees: u32,
        network: Network,
    ) -> LBtcRevSwapTx {
        let address = Address::from_str(&output_address).unwrap();
        LBtcRevSwapTx {
            kind: SwapTxKind::Claim,
            script_elements: LBtcRevSwapScript::from_str(&redeem_script).unwrap(),
            output_address: address,
            absolute_fees,
            _network: network,
            utxo: None,
            utxo_value: None,
        }
    }

    pub fn drain_tx(
        &mut self,
        keys: KeyPairString,
        preimage: Preimage,
        blinding_keys: BlindingKeyPair,
    ) -> Result<Transaction, S5Error> {
        // self.fetch_utxo();
        if !self.has_utxo() {
            return Err(S5Error::new(
                crate::e::ErrorKind::Wallet,
                "No utxos available yet",
            ));
        }
        match self.kind {
            SwapTxKind::Claim => Ok(self.sign_claim_tx(keys, preimage, blinding_keys)),
            SwapTxKind::Refund => {
                self.sign_refund_tx(keys);
                Err(S5Error::new(
                    crate::e::ErrorKind::Wallet,
                    "Refund transaction signing not supported yet",
                ))
            }
        }
        // let sweep_psbt = Psbt::from_unsigned_tx(sweep_tx);
    }

    fn _fetch_utxo(&mut self) -> () {
        let electrum_client = NetworkConfig::default_liquid()
            .unwrap()
            .electrum_url
            .build_client()
            .unwrap();
        let binding = self.script_elements.clone().to_typed().to_v0_p2wsh();
        let script_p2wsh = binding.as_bytes();
        let bitcoin_script = BitcoinScript::from_bytes(script_p2wsh);
        let utxos = electrum_client.script_list_unspent(bitcoin_script).unwrap();
        if utxos.len() == 0 {
            ()
        } else {
            let elements_txid: Txid = Txid::from_str(&utxos[0].tx_hash.to_string()).unwrap();
            let outpoint_0 = OutPoint::new(elements_txid, utxos[0].tx_pos as u32);
            let utxo_value = utxos[0].value;
            self.utxo = Some(outpoint_0);
            self.utxo_value = Some(utxo_value);
            ()
        }
    }
    fn has_utxo(&self) -> bool {
        self.utxo.is_some() && self.utxo_value.is_some()
    }

    pub fn _check_utxo_value(&self, expected_value: u64) -> bool {
        self.has_utxo() && self.utxo_value.unwrap() == expected_value
    }

    fn sign_claim_tx(
        &self,
        keys: KeyPairString,
        preimage: Preimage,
        _blinding_keys: BlindingKeyPair,
    ) -> Transaction {
        let sequence = Sequence::from_consensus(0xFFFFFFFF);

        let unsigned_input: TxIn = TxIn {
            sequence: sequence,
            previous_output: self.utxo.unwrap(),
            script_sig: Script::new(),
            witness: TxInWitness::default(),
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };
        // let txout_witness = TxOutWitness::from(0);
        let secp = Secp256k1::new();
        let blinding_factor =
            Tweak::from_slice(_blinding_keys.to_typed().secret_key().as_ref()).unwrap();
        let generator = Generator::new_blinded(&secp, Tag::default(), blinding_factor);
        let nonce = Nonce::Confidential(PublicKey::from_str(&_blinding_keys.pubkey).unwrap());
        let explicit_asset = elements::confidential::Asset::Explicit(AssetId::LIQUID_BTC);
        let output_value = self.utxo_value.unwrap() - self.absolute_fees as u64;
        let value_pedersen_commitment =
            create_pedersen_commitment(&secp, output_value, blinding_factor, generator);
        let blinded_value = elements::confidential::Value::Confidential(value_pedersen_commitment);

        let output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: blinded_value,
            asset: explicit_asset,
            nonce: nonce,
            witness: TxOutWitness::default(),
        };

        let unsigned_tx = Transaction {
            version: 1,
            lock_time: LockTime::from_consensus(self.script_elements.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };

        // SIGN TRANSACTION
        let sighash = Message::from_slice(
            &SighashCache::new(&unsigned_tx).segwitv0_sighash(
                0,
                &self.script_elements.to_typed(),
                Value::Explicit(self.utxo_value.unwrap()),
                elements::EcdsaSighashType::All,
            )[..],
        )
        .unwrap();
        let signature = secp.sign_ecdsa(&sighash, &keys.to_typed().secret_key());

        let mut script_witness: Vec<Vec<u8>> = vec![vec![]];
        script_witness.push(hex::decode(&signature.serialize_der().to_string()).unwrap());
        script_witness.push(preimage.preimage_bytes);
        script_witness.push(self.script_elements.to_typed().as_bytes().to_vec());

        let min_value: u64 = 1; // Minimum value for the range proof, adjust as needed
        let exp: i32 = 0; // Exponent for the range proof
        let min_bits: u8 = 36; // Minimum number of bits for the range proof

        // Assuming you have these values correctly set up
        let message: &[u8] = &[]; // Optional message for range proof
        let additional_commitment: &[u8] = &[]; // Additional commitment data
        let additional_generator = Generator::new_blinded(&secp, Tag::default(), blinding_factor);

        let amount_rangeproof = RangeProof::new(
            &secp,
            min_value,
            value_pedersen_commitment,
            output_value,
            blinding_factor,
            message,
            additional_commitment,
            keys.to_typed().secret_key(),
            exp,
            min_bits,
            additional_generator,
        )
        .unwrap(); // help me with this chat
        let inflation_keys_rangeproof = None; // help me with this chat

        let witness = TxInWitness {
            amount_rangeproof: Some(Box::new(amount_rangeproof)),
            inflation_keys_rangeproof,
            script_witness: script_witness.clone(),
            pegin_witness: vec![],
        };

        let signed_txin = TxIn {
            previous_output: self.utxo.unwrap(),
            script_sig: Script::default(),
            sequence: sequence,
            witness: witness,
            is_pegin: false,
            asset_issuance: AssetIssuance::default(),
        };

        let signed_tx = Transaction {
            version: 1,
            lock_time: LockTime::from_consensus(self.script_elements.timelock),
            input: vec![signed_txin],
            output: vec![output.clone()],
        };
        signed_tx
    }
    fn sign_refund_tx(&self, _keys: KeyPairString) -> () {
        ()
    }
}

fn mock_generator() -> elements::secp256k1_zkp::Generator {
    let mut a = [2u8; 33];
    a[0] = 10;
    elements::secp256k1_zkp::Generator::from_slice(&a).unwrap()
}

fn create_pedersen_commitment(
    secp: &Secp256k1<secp256k1::All>,
    value: u64,
    blinding_factor: Tweak,
    generator: Generator,
) -> PedersenCommitment {
    PedersenCommitment::new(secp, value, blinding_factor, generator)
}

fn mock_pubkey() -> elements::secp256k1_zkp::PublicKey {
    let a = [2u8; 33];
    elements::secp256k1_zkp::PublicKey::from_slice(&a).unwrap()
}
#[cfg(test)]
mod tests {
    use crate::key::ec::BlindingKeyPair;

    use super::*;
    use elements::pset::serialize::Serialize;

    /// https://liquidtestnet.com/utils
    /// https://blockstream.info/liquidtestnet
    ///
    #[test]
    #[ignore]
    fn test_liquid_rev_tx() {
        const RETURN_ADDRESS: &str =
            "tlq1qqtc07z9kljll7dk2jyhz0qj86df9gnrc70t0wuexutzkxjavdpht0d4vwhgs2pq2f09zsvfr5nkglc394766w3hdaqrmay4tw";

        let redeem_script_str = "8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac".to_string();
        let expected_address = "tlq1qqtvg2v6wv2akxa8dpcdrfemgwnr09ragwlqagr57ezc8nzrvvd6x32rtt4s3e2xylcukuz64fm2zu0l4erdr2h98zjv07w4rearycpxqlz2gstkfw7ln";
        let _expected_timeout = 1179263;

        let blinding_key = BlindingKeyPair::from_secret_string(
            "bf99362dff7e8f2ec01e081215cab9047779da4547a6f47d67bb1cbb8c96961d".to_string(),
        );

        let _id = "s9EBbv";
        let _my_key_pair = KeyPairString {
            seckey: "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1".to_string(),
            pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986"
                .to_string(),
        };
        let preimage = Preimage {
            preimage: "a323c8c5abadca53bb4b732d62d0486ba49ecab7e340d2b44aac13ac813fed29"
                .to_string(),
            sha256: "2c705049974f29e308d9c8d5c5ec216d6c435cae52777c53dcceefda8b52922c".to_string(),
            hash160: "8514cc9235824c914d94fda549e45d6dec629b97".to_string(),
            preimage_bytes: [
                163, 35, 200, 197, 171, 173, 202, 83, 187, 75, 115, 45, 98, 208, 72, 107, 164, 158,
                202, 183, 227, 64, 210, 180, 74, 172, 19, 172, 129, 63, 237, 41,
            ]
            .to_vec(),
            sha256_bytes: [
                44, 112, 80, 73, 151, 79, 41, 227, 8, 217, 200, 213, 197, 236, 33, 109, 108, 67,
                92, 174, 82, 119, 124, 83, 220, 206, 239, 218, 139, 82, 146, 44,
            ],
            hash160_bytes: [
                133, 20, 204, 146, 53, 130, 76, 145, 77, 148, 253, 165, 73, 228, 93, 109, 236, 98,
                155, 151,
            ],
        };

        let script_elements = LBtcRevSwapScript::from_str(&redeem_script_str.clone()).unwrap();

        let address = script_elements.to_address(blinding_key.clone());
        println!("ADDRESS FROM ENCODED: {:?}", address.to_string());
        assert!(address.to_string() == expected_address);

        let mut tx_elements = LBtcRevSwapTx::new_claim(
            redeem_script_str,
            RETURN_ADDRESS.to_string(),
            300,
            Network::Testnet,
        );

        let outpoint = OutPoint {
            txid: Txid::from_str(
                "6a05897e425229a199abb2d3d5e5bccadafe41597d07c211dc9330e93bf3ac49",
            )
            .unwrap(),
            vout: 0,
        };
        let out_value = 50_000;

        tx_elements = tx_elements.manual_utxo_update(outpoint, out_value);
        println!("{:?}", tx_elements);
        let signed = tx_elements.drain_tx(_my_key_pair, preimage, blinding_key);
        println!("{:?}", hex::encode(signed.clone().unwrap().serialize()));
        // println!("{:?}", signed.unwrap())
    }
}

/*
 *
 *
 * KeyPairString { seckey: "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1", pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986" }
{"info":[],"warnings":[],"pairs":{"BTC/BTC":{"hash":"a3a295202ab0b65cc9597b82663dbcdc77076e138f6d97285711ab7df086afd5","rate":1,"limits":{"maximal":25000000,"minimal":50000,"maximalZeroConf":{"baseAsset":0,"quoteAsset":0}},"fees":{"percentage":0.5,"percentageSwapIn":0.1,"minerFees":{"baseAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}},"L-BTC/BTC":{"hash":"04df6e4b5a91d62a4e1a7ecb88ca462851d835c4bae955a6c5baad8e047b14e9","rate":1,"limits":{"maximal":25000000,"minimal":1000,"maximalZeroConf":{"baseAsset":100000,"quoteAsset":0}},"fees":{"percentage":0.25,"percentageSwapIn":0.1,"minerFees":{"baseAsset":{"normal":147,"reverse":{"claim":152,"lockup":276}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}},"RBTC/BTC":{"hash":"17acb1892ddaaaf60bf44a6e88a86405922d44f29265cc2ebe9f0f137277aa24","rate":1,"limits":{"maximal":4294967,"minimal":10000,"maximalZeroConf":{"baseAsset":0,"quoteAsset":0}},"fees":{"percentage":0.5,"percentageSwapIn":0.5,"minerFees":{"baseAsset":{"normal":162,"reverse":{"claim":162,"lockup":302}},"quoteAsset":{"normal":340,"reverse":{"claim":276,"lockup":306}}}}}}}
{"id":"s9EBbv","invoice":"lntb504030n1pjhu7w9sp5a2vkmm292fr6mlsjcdpdr3d5zjffttj66nucq9czmkez42pgzdpspp593c9qjvhfu57xzxeer2utmppd4kyxh9w2fmhc57uemha4z6jjgkqdpz2djkuepqw3hjqnpdgf2yxgrpv3j8yetnwvxqyp2xqcqz959qxpqysgqztrywvj30fqhsq6aawf4ew69y6vwea8ykt4qyendmc3vgn6la2534syaqrx296ud04gvaprex9ns687ljnk6s4d5xqrj2v2pfsqtvkqparpzcd","blindingKey":"bf99362dff7e8f2ec01e081215cab9047779da4547a6f47d67bb1cbb8c96961d","redeemScript":"8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac","lockupAddress":"tlq1qqtvg2v6wv2akxa8dpcdrfemgwnr09ragwlqagr57ezc8nzrvvd6x32rtt4s3e2xylcukuz64fm2zu0l4erdr2h98zjv07w4rearycpxqlz2gstkfw7ln","timeoutBlockHeight":1179263}
Ok(CreateSwapResponse { id: "s9EBbv", invoice: Some("lntb504030n1pjhu7w9sp5a2vkmm292fr6mlsjcdpdr3d5zjffttj66nucq9czmkez42pgzdpspp593c9qjvhfu57xzxeer2utmppd4kyxh9w2fmhc57uemha4z6jjgkqdpz2djkuepqw3hjqnpdgf2yxgrpv3j8yetnwvxqyp2xqcqz959qxpqysgqztrywvj30fqhsq6aawf4ew69y6vwea8ykt4qyendmc3vgn6la2534syaqrx296ud04gvaprex9ns687ljnk6s4d5xqrj2v2pfsqtvkqparpzcd"), redeem_script: Some("8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac"), timeout_block_height: Some(1179263), onchain_amount: None, lockup_address: Some("tlq1qqtvg2v6wv2akxa8dpcdrfemgwnr09ragwlqagr57ezc8nzrvvd6x32rtt4s3e2xylcukuz64fm2zu0l4erdr2h98zjv07w4rearycpxqlz2gstkfw7ln"), miner_fee_invoice: None, service_fee_percentage: None, preimage: None, claim_address: None, claim_public_key: None, private_key: None, refund_address: None, refund_public_key: None, blinding_key: Some("bf99362dff7e8f2ec01e081215cab9047779da4547a6f47d67bb1cbb8c96961d"), address: None, expected_amount: None })
Preimage { preimage: "a323c8c5abadca53bb4b732d62d0486ba49ecab7e340d2b44aac13ac813fed29", sha256: "2c705049974f29e308d9c8d5c5ec216d6c435cae52777c53dcceefda8b52922c", hash160: "8514cc9235824c914d94fda549e45d6dec629b97", preimage_bytes: [163, 35, 200, 197, 171, 173, 202, 83, 187, 75, 115, 45, 98, 208, 72, 107, 164, 158, 202, 183, 227, 64, 210, 180, 74, 172, 19, 172, 129, 63, 237, 41], sha256_bytes: [44, 112, 80, 73, 151, 79, 41, 227, 8, 217, 200, 213, 197, 236, 33, 109, 108, 67, 92, 174, 82, 119, 124, 83, 220, 206, 239, 218, 139, 82, 146, 44], hash160_bytes: [133, 20, 204, 146, 53, 130, 76, 145, 77, 148, 253, 165, 73, 228, 93, 109, 236, 98, 155, 151] }
8201208763a9148514cc9235824c914d94fda549e45d6dec629b9788210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c54589866775037ffe11b1752102869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec359868ac
LBtcRevScriptElements { hashlock: "8514cc9235824c914d94fda549e45d6dec629b97", reciever_pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986", timelock: 1179263, sender_pubkey: "02869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec3598", preimage: None, signature: None } , LBtcRevScriptElements { hashlock: "8514cc9235824c914d94fda549e45d6dec629b97", reciever_pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986", timelock: 1179263, sender_pubkey: "02869bf2e041d122d67b222d7b2fdc1e2466e726bbcacd35feccdfb0101cec3598", preimage: None, signature: None }



 */
