use std::ffi::CString;
use std::os::raw::c_char;
use serde::{Deserialize, Serialize};
use bdk::keys::bip39::{Language, Mnemonic};
use bdk::bitcoin::network::constants::Network;
use bdk::bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::bip32::ExtendedPrivKey;
use crate::e::{ErrorKind, S5Error};
use rand_core::{RngCore};

/// FFI Output
#[derive(Serialize, Deserialize, Debug)]
pub struct MasterKey {
  pub fingerprint: String,
  pub mnemonic: String,
  pub xprv: String,
}

impl MasterKey {
  pub fn c_stringify(&self) -> *mut c_char {
    let stringified = match serde_json::to_string(self) {
      Ok(result) => result,
      Err(e) => {
        eprint!("{:#?}", e.to_string());
        return CString::new("Error:JSON Stringify Failed. BAD NEWS! Contact Support.")
          .unwrap()
          .into_raw();
      }
    };

    CString::new(stringified).unwrap().into_raw()
  }
}

pub fn generate(
  passphrase: &str, 
  network: Network
) -> Result<MasterKey, S5Error> {
  let secp = Secp256k1::new();
  let mut key = [0u8; 16];
  OsRng.fill_bytes(&mut key);

  let mnemonic = match Mnemonic::from_entropy_in(Language::English, &key) {
    Ok(mne) => mne,
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  };
  let mnemonic_struct = match Mnemonic::parse_in(Language::English, &mnemonic.to_string()) {
    Ok(mne) => mne,
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  };
  let seed = mnemonic_struct.to_seed(passphrase);
  let master_xprv = match ExtendedPrivKey::new_master(network, &seed) {
    Ok(xprv) => xprv,
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  };

  Ok(MasterKey {
    fingerprint: master_xprv.fingerprint(&secp).to_string(),
    mnemonic: mnemonic.to_string(),
    xprv: master_xprv.to_string(),
  })
}

pub fn import(
  mnemonic: &str, 
  passphrase: &str, 
  network: Network
) -> Result<MasterKey, S5Error> {
  let secp = Secp256k1::new();
  let mnemonic_struct = match Mnemonic::parse_in(Language::English, mnemonic.to_string()) {
    Ok(mne) => mne,
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  };
  let seed = mnemonic_struct.to_seed(passphrase);
  let master_xprv = match ExtendedPrivKey::new_master(network, &seed) {
    Ok(xprv) => xprv,
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  };

  Ok(MasterKey {
    fingerprint: master_xprv.fingerprint(&secp).to_string(),
    mnemonic: mnemonic.to_string(),
    xprv: master_xprv.to_string(),
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn test_key_ops() {
    let master_key = generate("password", Network::Testnet).unwrap();
    assert_eq!(
      12,
      master_key
        .mnemonic
        .split_whitespace()
        .collect::<Vec<&str>>()
        .len()
    );
    let imported_master_key = import(&master_key.mnemonic, "password", Network::Testnet).unwrap();
    assert_eq!(imported_master_key.xprv, master_key.xprv);
    assert_eq!(imported_master_key.fingerprint, master_key.fingerprint);
  }
}