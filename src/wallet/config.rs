use bewallet::{self, ElectrumWallet};
use elements::BlockHash;

use elements;

use bewallet::*;

use std::thread;
use std::time::Duration;
use tempdir::TempDir;

pub struct TestElectrumWallet {
    mnemonic: String,
    electrum_wallet: ElectrumWallet,
    _tx_status: u64,
    _block_status: (u32, BlockHash),
    _db_root_dir: TempDir,
}

impl TestElectrumWallet {
    pub fn new(electrs_url: &str, mnemonic: String) -> Self {
        let tls = false;
        let validate_domain = false;
        let spv_enabled = true;
        let policy_asset_hex = &"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
        let _db_root_dir = TempDir::new("electrum_integration_tests").unwrap();

        let db_root = format!("{}", _db_root_dir.path().display());

        let electrum_wallet = ElectrumWallet::new_regtest(
            policy_asset_hex,
            electrs_url,
            tls,
            validate_domain,
            spv_enabled,
            &db_root,
            &mnemonic,
        )
        .unwrap();
        electrum_wallet.update_fee_estimates();

        let tx_status = electrum_wallet.tx_status().unwrap();
        assert_eq!(tx_status, 15130871412783076140);
        let mut i = 120;
        let _block_status = loop {
            assert!(i > 0, "1 minute without updates");
            i -= 1;
            let block_status = electrum_wallet.block_status().unwrap();
            if block_status.0 == 101 {
                break block_status;
            } else {
                thread::sleep(Duration::from_millis(500));
            }
        };
        assert_eq!(_block_status.0, 101);

        Self {
            mnemonic,
            electrum_wallet,
            _tx_status: 0,
            _block_status,
            _db_root_dir,
        }
    }

    pub fn policy_asset(&self) -> elements::issuance::AssetId {
        self.electrum_wallet.policy_asset()
    }

    /// asset balance in satoshi
    pub fn balance(&self, asset: &elements::issuance::AssetId) -> u64 {
        let balance = self.electrum_wallet.balance().unwrap();
        *balance.get(asset).unwrap_or(&0u64)
    }

    fn _balance_btc(&self) -> u64 {
        self.balance(&self.policy_asset())
    }

    fn get_tx_from_list(&mut self, txid: &str) -> TransactionDetails {
        self.electrum_wallet.update_spv().unwrap();
        let mut opt = GetTransactionsOpt::default();
        opt.count = 100;
        let list = self.electrum_wallet.transactions(&opt).unwrap();
        let filtered_list: Vec<TransactionDetails> =
            list.iter().filter(|e| e.txid == txid).cloned().collect();
        assert!(
            !filtered_list.is_empty(),
            "just made tx {} is not in tx list",
            txid
        );
        filtered_list.first().unwrap().clone()
    }

    pub fn _get_fee(&mut self, txid: &str) -> u64 {
        self.get_tx_from_list(txid).fee
    }

    /// send a tx from the wallet to the specified address
    pub fn send_tx(
        &mut self,
        address: &elements::Address,
        satoshi: u64,
        asset: Option<elements::issuance::AssetId>,
        utxos: Option<Vec<UnblindedTXO>>,
    ) -> String {
        let asset = asset.unwrap_or(self.policy_asset());
        let _init_satt = self.balance(&asset);
        //let init_node_balance = self.node_balance(asset.clone());
        let mut create_opt = CreateTransactionOpt::default();
        let fee_rate = 100;
        create_opt.fee_rate = Some(fee_rate);
        let net = self.electrum_wallet.network();
        create_opt.addressees.push(
            Destination::new(&address.to_string(), satoshi, &asset.to_string(), net).unwrap(),
        );
        create_opt.utxos = utxos;
        let tx_details = self.electrum_wallet.create_tx(&mut create_opt).unwrap();
        let mut tx = tx_details.transaction.clone();
        let len_before = elements::encode::serialize(&tx).len();
        self.electrum_wallet
            .sign_tx(&mut tx, &self.mnemonic)
            .unwrap();
        let len_after = elements::encode::serialize(&tx).len();
        assert!(len_before < len_after, "sign tx did not increased tx size");
        //self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        let txid = tx.txid().to_string();
        self.electrum_wallet.broadcast_tx(&tx).unwrap();
        // self.wallet_wait_tx_status_change();

        self.tx_checks(&tx);

        // let fee = if asset == self.policy_asset() {
        //     tx_details.fee
        // } else {
        //     0
        // };
        //assert_eq!(
        //    self.node_balance(asset.clone()),
        //    init_node_balance + satoshi,
        //    "node balance does not match"
        //);

        // let expected = init_sat - satoshi - fee;
        // for _ in 0..5 {
        //     if expected != self.balance(&asset) {
        //         // FIXME I should not wait again, but apparently after reconnect it's needed
        //         self.wallet_wait_tx_status_change();
        //     }
        // }
        // assert_eq!(self.balance(&asset), expected, "gdk balance does not match");

        //self.list_tx_contains(&txid, &vec![address.to_string()], true);
        // let wallet_txid = self.get_tx_from_list(&txid).txid;
        // assert_eq!(txid, wallet_txid);

        txid
    }

    pub fn is_verified(&mut self, txid: &str, verified: SPVVerifyResult) {
        let tx = self.get_tx_from_list(txid);
        assert_eq!(tx.spv_verified.to_string(), verified.to_string());
    }

    /// send a tx with multiple recipients with same amount from the wallet to addresses generated
    /// by the node. If `assets` contains values, they are used as asset cyclically

    /// check create_tx failure reasons

    pub fn utxos(&self) -> Vec<UnblindedTXO> {
        self.electrum_wallet.utxos().unwrap()
    }

    pub fn _asset_utxos(&self, asset: &elements::issuance::AssetId) -> Vec<UnblindedTXO> {
        self.electrum_wallet
            .utxos()
            .unwrap()
            .iter()
            .cloned()
            .filter(|u| u.unblinded.asset == *asset)
            .collect()
    }

    /// performs checks on transactions, like checking for address reuse in outputs and on liquid confidential commitments inequality
    pub fn tx_checks(&self, transaction: &elements::Transaction) {
        let output_nofee: Vec<&elements::TxOut> =
            transaction.output.iter().filter(|o| !o.is_fee()).collect();
        for current in output_nofee.iter() {
            assert_eq!(
                1,
                output_nofee
                    .iter()
                    .filter(|o| o.script_pubkey == current.script_pubkey)
                    .count(),
                "address reuse"
            ); // for example using the same change address for lbtc and asset change
            assert_eq!(
                1,
                output_nofee
                    .iter()
                    .filter(|o| o.asset == current.asset)
                    .count(),
                "asset commitment equal"
            );
            assert_eq!(
                1,
                output_nofee
                    .iter()
                    .filter(|o| o.value == current.value)
                    .count(),
                "value commitment equal"
            );
            assert_eq!(
                1,
                output_nofee
                    .iter()
                    .filter(|o| o.nonce == current.nonce)
                    .count(),
                "nonce commitment equal"
            );
        }
        assert!(
            transaction.output.last().unwrap().is_fee(),
            "last output is not a fee"
        );
    }
}
