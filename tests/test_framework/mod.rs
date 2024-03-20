use bitcoind::{
    bitcoincore_rpc::{Client, RpcApi},
    BitcoinD, Conf,
};

use bitcoin::{network::Network, Address, Amount, Txid};

pub struct TestFramework {
    bitcoind: BitcoinD,
    mining_address: Address,
    test_wallet: Client,
}

impl TestFramework {
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

impl AsRef<Client> for TestFramework {
    fn as_ref(&self) -> &Client {
        &self.bitcoind.client
    }
}
