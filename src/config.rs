use bdk::blockchain::any::{AnyBlockchain, AnyBlockchainConfig};
use bdk::blockchain::electrum::ElectrumBlockchainConfig;
use bdk::blockchain::rpc::{Auth, RpcConfig};
use bdk::wallet::wallet_name_from_descriptor;
use bdk::blockchain::{Blockchain, ConfigurableBlockchain, ElectrumBlockchain, RpcBlockchain};
use bdk::electrum_client::Error as ElectrumError;
use bdk::bitcoin::Network;
use std::fmt::Debug;
use std::fmt::Formatter;
use bdk::bitcoin::secp256k1::Secp256k1;
use crate::e::{ErrorKind, S5Error};

pub const DEFAULT: &str = "default";
pub const DEFAULT_TESTNET_NODE: &str = "ssl://electrum.blockstream.info:60002";
pub const DEFAULT_MAINNET_NODE: &str = "ssl://electrum.blockstream.info:50002";

pub struct WalletConfig {
    pub deposit_desc: String,
    pub change_desc: String,
    pub network: Network,
    pub client: Option<AnyBlockchain>,
    pub db_path: Option<String>
  }
  impl Debug for WalletConfig {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
      match &self.client {
        Some(client)=> {
          match client{
            AnyBlockchain::Electrum(ref _config) => f.debug_struct("WalletConfig")
            .field("deposit_descriptor", &self.deposit_desc)
            .field("network", &self.network)
            .field("backend", &"Electrum: ".to_string())
            .finish(),
            AnyBlockchain::Rpc(ref _config) =>f.debug_struct("WalletConfig")
            .field("deposit_descriptor", &self.deposit_desc)
            .field("network", &self.network)
            .field("backend", &"CoreRpc".to_string())
            .finish(),
            // _=> write!(f, "Unknown"),
          }
        },
        None=> {
          write!(f, "deposit_desc: {}\nchange_desc: {}\nnetwork: {}\nbackend: None",
            self.deposit_desc, self.change_desc, self.network)
        }
      }
    }
  }
  impl WalletConfig {
    pub fn new(
      descriptor: &str,
      node_address: &str,
      socks5: Option<String>,
      db_path: Option<String>
    ) -> Result<Self, S5Error> {
      let deposit_desc: &str = &descriptor.replace("/*", "/0/*");
      let change_desc: &str = &descriptor.replace("/*", "/1/*");
      let network = if <&str>::clone(&descriptor).contains("xpub")
        || <&str>::clone(&descriptor).contains("xprv")
      {
        Network::Bitcoin
      } else {
        Network::Testnet
      };
      
      let node_address = if node_address.contains(DEFAULT) {
        match network {
          Network::Bitcoin => DEFAULT_TESTNET_NODE,
          _ => DEFAULT_TESTNET_NODE,
        }
      } else {
        node_address
      };
  
      if node_address.contains("electrum") || node_address.contains("onion") {
        let config = if socks5.is_none() {
          ElectrumBlockchainConfig {
          url: node_address.to_string(),
          socks5: None,
          retry: 1,
          timeout: Some(5),
          stop_gap: 1000,
          validate_domain: true,
          }
        }else{
          ElectrumBlockchainConfig{
            url: node_address.to_string(),
            socks5,
            retry: 1,
            timeout: None,
            stop_gap: 1000,
            validate_domain: true,
          }
        };
        let client = match create_blockchain_client(AnyBlockchainConfig::Electrum(config)) {
          Ok(client) => client,
          Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.message)),
        };
  
        Ok(WalletConfig {
          deposit_desc: deposit_desc.to_string(),
          change_desc: change_desc.to_string(),
          network:network,
          client: Some(client),
          db_path: db_path
        })
      } else if node_address.contains("?auth=") {
        let parts: Vec<&str> = node_address.split("?auth=").collect();
        let auth = if parts.len() <= 1 {
          return Err(S5Error::new(ErrorKind::Input, "Node address requires an authentication stirng. Add ?auth=uname:pass"))
        } else {
          Auth::UserPass {
            username: parts[1].split(':').collect::<Vec<&str>>()[0].to_string(),
            password: parts[1].split(':').collect::<Vec<&str>>()[1].to_string(),
          }
        };
        let wallet_name = match wallet_name_from_descriptor(
          deposit_desc,
          Some(change_desc),
          network,
          &Secp256k1::new(),
        ) {
          Ok(name) => name,
          Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.to_string())),
        };
        let config = RpcConfig {
          url: parts[0].to_string(),
          auth,
          network,
          wallet_name,
          sync_params: None,
        };
        let client = match create_blockchain_client(AnyBlockchainConfig::Rpc(config)) {
          Ok(client) => client,
          Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.message)),
        };
  
        Ok(WalletConfig {
          deposit_desc: deposit_desc.to_string(),
          change_desc: change_desc.to_string(),
          network,
          client: Some(client),
          db_path: db_path
        })
      } else {
        Err(S5Error::new(ErrorKind::Internal, "Core RPC requires an onion address."))
      }
      // let config = if socks5.is_none() {
      //   ElectrumBlockchainConfig {
      //     url: node_address.to_string(),
      //     socks5: None,
      //     retry: 1,
      //     timeout: Some(5),
      //     stop_gap: 1000,
      //   }
      // } else {
      //   ElectrumBlockchainConfig {
      //     url: node_address.to_string(),
      //     socks5,
      //     retry: 1,
      //     timeout: None,
      //     stop_gap: 1000,
      //   }
      // };
      // let client = match create_blockchain_client(AnyBlockchainConfig::Electrum(config)) {
      //   Ok(client) => client,
      //   Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.message)),
      // };
  
      // Ok(WalletConfig {
      //   deposit_desc: deposit_desc.to_string(),
      //   change_desc: change_desc.to_string(),
      //   network,
      //   client: Some(client),
      // })
    }
  
    pub fn new_offline(network: Network, deposit_desc: &str,change_desc: &str, db_path: Option<String>) -> Result<Self, S5Error> {
  
      Ok(WalletConfig {
        deposit_desc: deposit_desc.to_string(),
        change_desc: change_desc.to_string(),
        network,
        client: None,
        db_path: db_path
      })
    }
  }
  
  pub fn create_blockchain_client(config: AnyBlockchainConfig) -> Result<AnyBlockchain, S5Error> {
    match config {
      AnyBlockchainConfig::Electrum(conf) => {
        let client = match ElectrumBlockchain::from_config(&conf) {
          Ok(result) => result,
          Err(bdk_error) => match bdk_error {
            bdk::Error::Electrum(electrum_error) => match electrum_error {
              ElectrumError::IOError(c_error) => {
                return Err(S5Error::new(ErrorKind::Network, &c_error.to_string()))
              }
              e_error => return Err(S5Error::new(ErrorKind::Internal, &e_error.to_string())),
            },
            e_error => return Err(S5Error::new(ErrorKind::Internal, &e_error.to_string())),
          },
        };
        Ok(AnyBlockchain::Electrum(Box::new(client)))
      }
      AnyBlockchainConfig::Rpc(conf) => {
        let client = match RpcBlockchain::from_config(&conf) {
          Ok(result) => result,
          Err(bdk_error) => match bdk_error {
            bdk::Error::Rpc(rpc_error) => match rpc_error {
              bdk::bitcoincore_rpc::Error::Io(c_error) => {
                return Err(S5Error::new(ErrorKind::Network, &c_error.to_string()))
              }
              r_error => return Err(S5Error::new(ErrorKind::Internal, &r_error.to_string())),
            },
            r_error => return Err(S5Error::new(ErrorKind::Internal, &r_error.to_string())),
          },
        };
        Ok(AnyBlockchain::Rpc(Box::new(client)))
      }
    }
  }
  
  pub fn _check_client(network: Network, node_address: &str) -> Result<bool, S5Error> {
    let client: AnyBlockchain = if node_address.contains("electrum") {
      let config = ElectrumBlockchainConfig {
        url: node_address.to_string(),
        socks5: None,
        retry: 1,
        timeout: Some(5),
        stop_gap: 1000,
        validate_domain: true,
      };
      match create_blockchain_client(AnyBlockchainConfig::Electrum(config)) {
        Ok(client) => client,
        Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.message)),
      }
    } else if node_address.contains("onion") {
      let parts: Vec<&str> = node_address.split("?auth=").collect();
      let auth = if parts[1].is_empty() {
        Auth::None
      } else {
        Auth::UserPass {
          username: parts[1].split(':').collect::<Vec<&str>>()[0].to_string(),
          password: parts[1].split(':').collect::<Vec<&str>>()[1].to_string(),
        }
      };
      let config = RpcConfig {
        url: parts[0].to_string(),
        auth,
        network,
        wallet_name: "ping".to_string(),
        sync_params: None,
      };
  
      match create_blockchain_client(AnyBlockchainConfig::Rpc(config)) {
        Ok(client) => client,
        Err(e) => return Err(S5Error::new(ErrorKind::Internal, &e.message)),
      }
    } else {
      return Err(S5Error::new(ErrorKind::Internal, "Invalid Node Address."));
    };
    match client.estimate_fee(1) {
      Ok(_) => Ok(true),
      Err(e) => Err(S5Error::new(ErrorKind::Network, &e.to_string())),
    }
  }
  
  #[cfg(test)]
  mod tests {
    use super::*;
    use crate::config::WalletConfig;
    use bdk::blockchain::Blockchain;
    #[test]
    fn test_default_electrum_config() {
      let xkey = "[db7d25b5/84'/1'/6']tpubDCCh4SuT3pSAQ1qAN86qKEzsLoBeiugoGGQeibmieRUKv8z6fCTTmEXsb9yeueBkUWjGVzJr91bCzeCNShorbBqjZV4WRGjz3CrJsCboXUe";
      let descriptor = format!("wpkh({}/*)", xkey);
      let config = WalletConfig::new(&descriptor, DEFAULT_TESTNET_NODE, None,None).unwrap();
      match config.client.unwrap() {
        AnyBlockchain::Electrum(client) => {
          let fee = client.estimate_fee(8);
          assert_eq!((fee.unwrap().as_sat_per_vb() > 0.0), true);
        }
        _ => println!("Should not reach."),
      };
  
      let change_desc = format!("wpkh({}/1/*)", xkey);
      let network = Network::Testnet;
      assert_eq!(config.change_desc, change_desc);
      assert_eq!(config.network, network);
    }
  
    
  }