use bitcoin::Network;
use electrum_client::ElectrumApi;

use bitcoin::script::Script as BitcoinScript;
use elements::{
    confidential::{Nonce, Value},
    sighash::SighashCache,
    Address, AssetId, AssetIssuance, LockTime, OutPoint, Script, Sequence, Transaction, TxIn,
    TxInWitness, TxOut, TxOutWitness, Txid,
};

use secp256k1::{Message, Secp256k1};
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

use super::script::LBtcRevScriptElements;

#[derive(Debug, Clone)]
pub struct LBtcRevTxElements {
    kind: SwapTxKind,
    script_elements: LBtcRevScriptElements,
    output_address: Address,
    absolute_fees: u32,
    _network: Network,
    utxo: Option<OutPoint>,
    utxo_value: Option<u64>, // there should only ever be one outpoint in a swap
}

impl LBtcRevTxElements {
    pub fn new_claim(
        redeem_script: String,
        output_address: String,
        absolute_fees: u32,
        network: Network,
    ) -> LBtcRevTxElements {
        let address = Address::from_str(&output_address).unwrap();
        LBtcRevTxElements {
            kind: SwapTxKind::Claim,
            script_elements: LBtcRevScriptElements::from_str(&redeem_script).unwrap(),
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
        self.fetch_utxo();
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

    fn fetch_utxo(&mut self) -> () {
        let electrum_client = NetworkConfig::default_liquid()
            .unwrap()
            .electrum_url
            .build_client()
            .unwrap();
        let binding = self.script_elements.clone().to_script().to_v0_p2wsh();
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
        blinding_keys: BlindingKeyPair,
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
        let output: TxOut = TxOut {
            script_pubkey: self.output_address.script_pubkey(),
            value: elements::confidential::Value::Explicit(
                self.utxo_value.unwrap() - self.absolute_fees as u64,
            ),
            asset: elements::confidential::Asset::Explicit(AssetId::LIQUID_BTC),
            nonce: Nonce::Null,
            witness: TxOutWitness::default(),
        };

        let unsigned_tx = Transaction {
            version: 1,
            lock_time: LockTime::from_consensus(self.script_elements.timelock),
            input: vec![unsigned_input],
            output: vec![output.clone()],
        };

        // SIGN TRANSACTION
        let secp = Secp256k1::new();
        let sighash = Message::from_slice(
            &SighashCache::new(&unsigned_tx).segwitv0_sighash(
                0,
                &self.script_elements.to_script(),
                Value::Explicit(self.utxo_value.unwrap()),
                elements::EcdsaSighashType::All,
            )[..],
        )
        .unwrap();
        let signature = secp.sign_ecdsa(&sighash, &keys.to_typed().secret_key());

        let mut script_witness: Vec<Vec<u8>> = vec![vec![]];
        script_witness.push(hex::decode(&signature.serialize_der().to_string()).unwrap());
        script_witness.push(preimage.preimage_bytes);
        script_witness.push(self.script_elements.to_script().as_bytes().to_vec());

        let amount_rangeproof = None;
        let inflation_keys_rangeproof = None;

        let witness = TxInWitness {
            amount_rangeproof,
            inflation_keys_rangeproof,
            script_witness: script_witness.clone(),
            pegin_witness: script_witness,
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

#[cfg(test)]
mod tests {
    use crate::key::ec::BlindingKeyPair;

    use super::*;

    #[test]
    #[ignore]
    fn test_liquid_rev_tx() {
        const RETURN_ADDRESS: &str =
            "vjTyPZRBt2WVo8nnFrkQSp4x6xRHt5DVmdtvNaHbMaierD41uz7fk4Jr9V9vgsPHD74WA61Ne67popRQ";

        let redeem_script_str = "8201208763a914fc9eeab62b946bd3e9681c082ac2b6d0bccea80f88210223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c545898667750315f411b1752102285c72dca7aaa31d58334e20be181cfa2cb8eb8092a577ef6f77bba068b8c69868ac".to_string();
        let expected_address = "tlq1qqv7fnca53ad6fnnn05rwtdc8q6gp8h3yd7s3gmw20updn44f8mvwkxqf8psf3e56k2k7393r3tkllznsdpphqa33rdvz00va429jq6j2zzg8f59kqhex";
        let expected_timeout = 1176597;

        let blinding_key = BlindingKeyPair::from_secret_string(
            "852f5fb1a95ea3e16ad0bb1c12ce0eac94234e3c652e9b163accd41582c366ed".to_string(),
        );

        let _id = "axtHXB";
        let _my_key_pair = KeyPairString {
            seckey: "5f9f8cb71d8193cb031b1a8b9b1ec08057a130dd8ac9f69cea2e3d8e6675f3a1".to_string(),
            pubkey: "0223a99c57bfbc2a4bfc9353d49d6fd7312afaec8e8eefb82273d26c34c5458986"
                .to_string(),
        };
        let script_elements = LBtcRevScriptElements::from_str(&redeem_script_str.clone()).unwrap();

        let address = script_elements.to_address(Network::Testnet, blinding_key);
        println!("ADDRESS FROM ENCODED: {:?}", address.to_string());
        assert!(address.to_string() == expected_address);

        let tx_elements = LBtcRevTxElements::new_claim(
            redeem_script_str,
            RETURN_ADDRESS.to_string(),
            300,
            Network::Testnet,
        );

        println!("{:?}", tx_elements);
    }
}
