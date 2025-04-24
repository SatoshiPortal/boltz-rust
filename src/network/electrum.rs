// use electrum_client::raw_client::RawClient;

use super::{BitcoinChain, BitcoinClient, LiquidChain, LiquidClient};
use crate::error::Error;
use bitcoin::{Address, ScriptBuf, Transaction, Txid};
use electrum_client::{ElectrumApi, GetHistoryRes};
use elements::encode::{serialize, Decodable};
use std::collections::{HashMap, HashSet};

pub const DEFAULT_MAINNET_NODE: &str = "wes.bullbitcoin.com:50002";
pub const DEFAULT_TESTNET_NODE: &str = "electrum.blockstream.info:60002";
pub const DEFAULT_REGTEST_NODE: &str = "localhost:19001";
pub const DEFAULT_LIQUID_MAINNET_NODE: &str = "blockstream.info:995";
pub const DEFAULT_LIQUID_TESTNET_NODE: &str = "blockstream.info:465";
pub const DEFAULT_LIQUID_REGTEST_NODE: &str = "localhost:19002";

pub const DEFAULT_ELECTRUM_TIMEOUT: u8 = 10;

#[derive(Debug, Clone)]
enum ElectrumUrl {
    Tls(String, bool), // the bool value indicates if the domain name should be validated
    Plaintext(String),
}

impl ElectrumUrl {
    pub fn build_client(&self, timeout: u8) -> Result<electrum_client::Client, Error> {
        let builder = electrum_client::ConfigBuilder::new();
        let builder = builder.timeout(Some(timeout));
        let (url, builder) = match self {
            ElectrumUrl::Tls(url, validate) => {
                (format!("ssl://{url}"), builder.validate_domain(*validate))
            }
            ElectrumUrl::Plaintext(url) => (format!("tcp://{url}"), builder),
        };
        Ok(electrum_client::Client::from_config(&url, builder.build())?)
    }
}

pub struct ElectrumBitcoinClient {
    inner: electrum_client::Client,
    network: BitcoinChain,
}

impl ElectrumBitcoinClient {
    pub fn default(network: BitcoinChain, regtest_url: Option<&str>) -> Result<Self, Error> {
        match network {
            BitcoinChain::Bitcoin => Self::new(
                network,
                DEFAULT_MAINNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            ),
            BitcoinChain::BitcoinTestnet => Self::new(
                network,
                DEFAULT_TESTNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            ),
            BitcoinChain::BitcoinRegtest => Self::new(
                network,
                regtest_url.unwrap_or(DEFAULT_REGTEST_NODE),
                false,
                false,
                DEFAULT_ELECTRUM_TIMEOUT,
            ),
        }
    }

    pub fn new(
        network: BitcoinChain,
        electrum_url: &str,
        tls: bool,
        validate_domain: bool,
        timeout: u8,
    ) -> Result<Self, Error> {
        let electrum_url = match tls {
            true => ElectrumUrl::Tls(electrum_url.into(), validate_domain),
            false => ElectrumUrl::Plaintext(electrum_url.into()),
        };
        Ok(Self {
            inner: electrum_url.build_client(timeout)?,
            network,
        })
    }

    fn extract_address_utxos(
        txs: Vec<Transaction>,
        history: &[GetHistoryRes],
        spk: &ScriptBuf,
    ) -> Vec<(bitcoin::OutPoint, bitcoin::TxOut)> {
        let tx_is_confirmed_map: HashMap<_, _> =
            history.iter().map(|h| (h.tx_hash, h.height > 0)).collect();

        let mut spent_outputs = HashSet::new();
        for tx in &txs {
            for input in &tx.input {
                let outpoint = input.previous_output;
                let spending_tx_hash = tx.compute_txid();

                if tx_is_confirmed_map
                    .get(&spending_tx_hash)
                    .copied()
                    .unwrap_or(false)
                {
                    spent_outputs.insert(outpoint);
                }
            }
        }

        // Convert to the needed output format without cloning
        let mut result = Vec::new();
        for tx in txs.into_iter() {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.into_iter().enumerate() {
                if output.script_pubkey == *spk {
                    let outpoint = bitcoin::OutPoint::new(txid, vout as u32);
                    if !spent_outputs.contains(&outpoint) {
                        result.push((outpoint, output));
                    }
                }
            }
        }

        result
    }
}

#[macros::async_trait]
impl BitcoinClient for ElectrumBitcoinClient {
    async fn get_address_balance(&self, address: &Address) -> Result<(u64, i64), Error> {
        let spk = address.script_pubkey();
        let script_balance = self.inner.script_get_balance(spk.as_script())?;
        Ok((script_balance.confirmed, script_balance.unconfirmed))
    }

    async fn get_address_utxos(
        &self,
        address: &Address,
    ) -> Result<Vec<(bitcoin::OutPoint, bitcoin::TxOut)>, Error> {
        let spk = address.script_pubkey();
        let history: Vec<_> = self.inner.script_get_history(spk.as_script())?;

        let txs = self
            .inner
            .batch_transaction_get(&history.iter().map(|h| h.tx_hash).collect::<Vec<_>>())?;

        Ok(Self::extract_address_utxos(txs, &history, &spk))
    }

    async fn broadcast_tx(&self, signed_tx: &Transaction) -> Result<Txid, Error> {
        Ok(self.inner.transaction_broadcast(signed_tx)?)
    }

    fn network(&self) -> BitcoinChain {
        self.network
    }
}

pub struct ElectrumLiquidClient {
    inner: electrum_client::Client,
    network: LiquidChain,
}

impl ElectrumLiquidClient {
    pub fn default(network: LiquidChain, regtest_url: Option<&str>) -> Result<Self, Error> {
        match network {
            LiquidChain::Liquid => Self::new(
                network,
                DEFAULT_LIQUID_MAINNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            ),
            LiquidChain::LiquidTestnet => Self::new(
                network,
                DEFAULT_LIQUID_TESTNET_NODE,
                true,
                true,
                DEFAULT_ELECTRUM_TIMEOUT,
            ),
            LiquidChain::LiquidRegtest => Self::new(
                network,
                regtest_url.unwrap_or(DEFAULT_LIQUID_REGTEST_NODE),
                false,
                false,
                DEFAULT_ELECTRUM_TIMEOUT,
            ),
        }
    }

    pub fn new(
        network: LiquidChain,
        electrum_url: &str,
        tls: bool,
        validate_domain: bool,
        timeout: u8,
    ) -> Result<Self, Error> {
        let electrum_url = match tls {
            true => ElectrumUrl::Tls(electrum_url.into(), validate_domain),
            false => ElectrumUrl::Plaintext(electrum_url.into()),
        };
        Ok(Self {
            inner: electrum_url.build_client(timeout)?,
            network,
        })
    }
}

#[macros::async_trait]
impl LiquidClient for ElectrumLiquidClient {
    async fn get_address_utxo(
        &self,
        address: &elements::Address,
    ) -> Result<Option<(elements::OutPoint, elements::TxOut)>, Error> {
        let history = self.inner.script_get_history(bitcoin::Script::from_bytes(
            address.to_unconfidential().script_pubkey().as_bytes(),
        ))?;
        if history.is_empty() {
            return Err(Error::Protocol("No Transaction History".to_string()));
        }
        let bitcoin_txid = history.last().expect("txid expected").tx_hash;
        let raw_tx = self.inner.transaction_get_raw(&bitcoin_txid)?;
        let tx: elements::Transaction = elements::encode::deserialize(&raw_tx)?;
        for (vout, output) in tx.clone().output.into_iter().enumerate() {
            if output.script_pubkey == address.script_pubkey() {
                let outpoint_0 = elements::OutPoint::new(tx.txid(), vout as u32);

                return Ok(Some((outpoint_0, output)));
            }
        }
        Ok(None)
    }

    async fn get_genesis_hash(&self) -> Result<elements::BlockHash, Error> {
        let response = self.inner.block_header_raw(0)?;
        let block_header = elements::BlockHeader::consensus_decode(&*response)?;
        Ok(elements::BlockHash::from_raw_hash(
            block_header.block_hash().into(),
        ))
    }

    async fn broadcast_tx(&self, signed_tx: &elements::Transaction) -> Result<String, Error> {
        let serialized = serialize(signed_tx);
        Ok(self
            .inner
            .transaction_broadcast_raw(&serialized)?
            .to_string())
    }

    fn network(&self) -> LiquidChain {
        self.network
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::network::BitcoinChain::BitcoinTestnet;
    use bitcoin::absolute::LockTime;
    use bitcoin::blockdata::transaction::Transaction;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, OutPoint, ScriptBuf, TxIn, TxOut};
    use electrum_client::ElectrumApi;
    use electrum_client::GetHistoryRes;

    #[test]
    fn test_electrum_default_clients() {
        let electrum_client = ElectrumBitcoinClient::default(BitcoinChain::Bitcoin, None).unwrap();
        assert!(electrum_client.inner.ping().is_ok());

        let electrum_client = ElectrumLiquidClient::default(LiquidChain::Liquid, None).unwrap();
        assert!(electrum_client.inner.ping().is_ok());
    }

    #[test]
    #[ignore]
    fn test_blockstream_electrum() {
        let electrum_client = ElectrumBitcoinClient::default(BitcoinTestnet, None).unwrap();
        assert!(electrum_client.inner.ping().is_ok());

        let electrum_client =
            ElectrumLiquidClient::default(LiquidChain::LiquidTestnet, None).unwrap();
        assert!(electrum_client.inner.ping().is_ok());
    }
    #[test]
    #[ignore]
    fn test_raw_electrum_calls() {
        let electrum_client = ElectrumLiquidClient::default(LiquidChain::Liquid, None).unwrap();
        let numblocks = "blockchain.numblocks.subscribe";
        let blockheight = electrum_client.inner.raw_call(numblocks, []).unwrap();
        println!("blockheight: {blockheight}");
    }

    #[test]
    fn test_extract_address_utxos() {
        let our_script = ScriptBuf::from_hex("aaaa").unwrap();
        let other_script = ScriptBuf::from_hex("bbbb").unwrap();

        // Pending tx with unspent output
        let tx1 = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: our_script.clone(),
            }],
        };

        let tx1_id = tx1.compute_txid();

        // Confirmed tx with unspent output
        let tx2 = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(2000),
                script_pubkey: our_script.clone(),
            }],
        };

        let tx2_id = tx2.compute_txid();

        // Confirmed tx with unconfirmed spend
        let tx3 = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(5000),
                script_pubkey: our_script.clone(),
            }],
        };

        let tx3_id = tx3.compute_txid();

        // Confirmed tx with confirmed spend
        let tx4 = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(4500),
                script_pubkey: our_script.clone(),
            }],
        };

        let tx4_id = tx4.compute_txid();

        // Confirmed spending tx for tx4's output
        let spending_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(tx4_id, 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1500),
                script_pubkey: other_script.clone(),
            }],
        };

        let spending_tx_id = spending_tx.compute_txid();

        // Pending spending tx for tx3's output
        let pending_spending_tx = Transaction {
            version: Version(1),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(tx3_id, 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(500),
                script_pubkey: other_script.clone(),
            }],
        };

        let pending_spending_tx_id = pending_spending_tx.compute_txid();

        // Transaction history
        let history = vec![
            GetHistoryRes {
                tx_hash: tx1_id,
                height: 0, // Pending
                fee: None,
            },
            GetHistoryRes {
                tx_hash: tx2_id,
                height: 100, // Confirmed
                fee: None,
            },
            GetHistoryRes {
                tx_hash: tx3_id,
                height: 101, // Confirmed
                fee: None,
            },
            GetHistoryRes {
                tx_hash: tx4_id,
                height: 102, // Confirmed
                fee: None,
            },
            GetHistoryRes {
                tx_hash: spending_tx_id,
                height: 103, // Confirmed
                fee: None,
            },
            GetHistoryRes {
                tx_hash: pending_spending_tx_id,
                height: 0, // Pending
                fee: None,
            },
        ];

        let utxo_pairs = ElectrumBitcoinClient::extract_address_utxos(
            vec![tx1, tx2, tx3, tx4, spending_tx, pending_spending_tx],
            &history,
            &our_script,
        );

        assert_eq!(utxo_pairs.len(), 3);

        // Pending tx with unspent output
        assert!(utxo_pairs
            .iter()
            .any(|(outpoint, _)| outpoint.txid == tx1_id));

        // Confirmed tx with unspent output
        assert!(utxo_pairs
            .iter()
            .any(|(outpoint, _)| outpoint.txid == tx2_id));

        // Confirmed tx with unconfirmed spend
        assert!(utxo_pairs
            .iter()
            .any(|(outpoint, _)| outpoint.txid == tx3_id));
    }
}
