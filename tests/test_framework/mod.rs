use std::str::FromStr;

use bitcoind::{
    bitcoincore_rpc::{json::ScanTxOutRequest, Client, RpcApi},
    BitcoinD, Conf,
};

use elementsd::{downloaded_exe_path, ElementsD};

use elements::{
    hex::{FromHex, ToHex},
    Address as EAddress, BlockHash,
};

use bitcoin::{network::Network, Address, Amount, Txid};
use serde_json::Value;

pub struct BtcTestFramework {
    bitcoind: BitcoinD,
    mining_address: Address,
    test_wallet: Client,
}

impl BtcTestFramework {
    /// Initializes the Bitcoind regtest backend, mines initial blocks,
    /// creates a test-wallet and funds it with 10,000 sats.
    pub fn init() -> Self {
        let mut conf = Conf::default();

        conf.args.push("-txindex=1");
        let bitcoind = BitcoinD::from_downloaded_with_conf(&conf).unwrap();

        // Generate initial 101 blocks
        let mining_address = bitcoind
            .client
            .get_new_address(None, None)
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .unwrap();

        let test_wallet = bitcoind.create_wallet("test-wallet").unwrap();

        let test_addrs = test_wallet
            .get_new_address(None, None)
            .unwrap()
            .require_network(Network::Regtest)
            .unwrap();

        bitcoind
            .client
            .send_to_address(
                &test_addrs,
                Amount::from_sat(10000),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .unwrap();

        let tf = Self {
            bitcoind,
            mining_address,
            test_wallet,
        };

        tf
    }

    pub fn generate_blocks(&self, n: u64) {
        self.bitcoind
            .client
            .generate_to_address(n, &self.mining_address)
            .unwrap();
    }

    pub fn send_coins(&self, addr: &Address, amount: Amount) -> Txid {
        self.bitcoind
            .client
            .send_to_address(&addr, amount, None, None, None, None, None, None)
            .unwrap()
    }

    pub fn get_test_wallet(&self) -> &Client {
        &self.test_wallet
    }
}

impl AsRef<Client> for BtcTestFramework {
    fn as_ref(&self) -> &Client {
        &self.bitcoind.client
    }
}

#[allow(unused)]
pub struct LbtcTestFramework {
    elementsd: ElementsD,
}

#[allow(unused)]
impl LbtcTestFramework {
    pub fn init() -> Self {
        let mut conf = elementsd::Conf::default();
        conf.0.args.push("-txindex=1");

        let elementsd = ElementsD::with_conf(downloaded_exe_path().unwrap(), &conf).unwrap();

        let tf = LbtcTestFramework { elementsd };

        tf.generate_blocks(101);

        tf.rescan();

        tf
    }

    pub fn get_new_addrs(&self) -> EAddress {
        let new_addrs = self
            .elementsd
            .client()
            .call::<Value>("getnewaddress", &[])
            .unwrap();

        let addrs = EAddress::from_str(new_addrs.as_str().unwrap()).unwrap();

        addrs
    }

    pub fn generate_blocks(&self, n: u64) {
        let mining_address = self
            .elementsd
            .client()
            .call::<Value>("getnewaddress", &[])
            .unwrap();

        self.elementsd
            .client()
            .call::<Value>("generatetoaddress", &[n.into(), mining_address])
            .unwrap();

        self.rescan();
    }

    pub fn send_coins(&self, addr: &EAddress, amount: Amount) -> elements::Txid {
        let addrs_value = serde_json::to_value(addr).unwrap();
        let txid = self
            .elementsd
            .client()
            .call::<Value>("sendtoaddress", &[addrs_value, amount.to_btc().into()])
            .unwrap();

        elements::Txid::from_str(txid.as_str().unwrap()).unwrap()
    }

    pub fn rescan(&self) {
        self.elementsd
            .client()
            .call::<Value>("rescanblockchain", &[])
            .unwrap();
    }

    pub fn genesis_hash(&self) -> BlockHash {
        let blockhahs = self
            .elementsd
            .client()
            .call::<Value>("getblockhash", &[0.into()])
            .unwrap();

        BlockHash::from_str(blockhahs.as_str().unwrap()).unwrap()
    }

    pub fn fetch_utxo(&self, addrs: &EAddress) -> Option<(elements::OutPoint, elements::TxOut)> {
        let scan_request = ScanTxOutRequest::Single(format!("addr({})", addrs));

        let scan_reqs = [scan_request];

        let scan_result = self
            .elementsd
            .client()
            .call::<Value>(
                "scantxoutset",
                &["start".into(), serde_json::to_value(&scan_reqs).unwrap()],
            )
            .unwrap();

        let unspents = if let Some(value) = scan_result
            .as_object()
            .unwrap()
            .get("unspents")
            .unwrap()
            .as_array()
            .unwrap()
            .get(0)
        {
            let value = value.as_object().unwrap().clone();
            value
        } else {
            return None;
        };

        let txid = unspents.get("txid").unwrap();

        let get_raw_tx = self
            .elementsd
            .client()
            .call::<Value>("getrawtransaction", &[txid.clone()])
            .unwrap();

        let tx: elements::Transaction =
            elements::encode::deserialize(&Vec::from_hex(get_raw_tx.as_str().unwrap()).unwrap())
                .unwrap();

        tx.output.iter().enumerate().find_map(|(vout, txout)| {
            if txout.script_pubkey == addrs.script_pubkey() {
                let outpoint = elements::OutPoint::new(tx.txid(), vout as u32);
                Some((outpoint, txout.to_owned()))
            } else {
                None
            }
        })
    }

    pub fn send_tx(&self, tx: &elements::Transaction) {
        let tx_hex = elements::encode::serialize(tx).to_hex();
        let _ = self
            .elementsd
            .client()
            .call::<Value>(
                "sendrawtransaction",
                &[serde_json::to_value(tx_hex).unwrap()],
            )
            .unwrap();
    }
}
