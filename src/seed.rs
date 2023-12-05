use std::ffi::CString;
use std::os::raw::c_char;
use serde::{Deserialize, Serialize};
use bip39::{Language, Mnemonic};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::ExtendedPrivKey;
use crate::e::{ErrorKind, S5Error};

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
  length: usize, 
  passphrase: &str, 
  network: Network
) -> Result<MasterKey, S5Error> {
  let secp = Secp256k1::new();
  let length: usize = if length == 12 || length == 24 {
    length
  } else {
    24
  };
  let mut rng = match OsRng::new() {
    Ok(r) => r,
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  };
  let mnemonic = match Mnemonic::generate_in_with(&mut rng, Language::English, length) {
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
    let master_key = generate(9, "password", Network::Testnet).unwrap();
    assert_eq!(
      24,
      master_key
        .mnemonic
        .split_whitespace()
        .collect::<Vec<&str>>()
        .len()
    );
    let master_key = generate(12, "password", Network::Testnet).unwrap();
    assert_eq!(
      12,
      master_key
        .mnemonic
        .split_whitespace()
        .collect::<Vec<&str>>()
        .len()
    );
    let master_key = generate(29, "password", Network::Testnet).unwrap();
    assert_eq!(
      24,
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

  #[test]
  fn test_key_errors() {
    let invalid_mnemonic = "sushi dog road bed cliff thirty five four nine";
    let imported_key = import(invalid_mnemonic, "password", Network::Testnet)
      .err()
      .unwrap();
    let expected_emessage = "mnemonic has an invalid word count: 9. Word count must be 12, 15, 18, 21, or 24";
    assert_eq!(expected_emessage, imported_key.message);

    let invalid_mnemonic = "beach dog road bed cliff thirty five four nine ten eleven tweleve";
    let imported_key = import(invalid_mnemonic, "password", Network::Testnet)
      .err()
      .unwrap();
    let expected_emessage = "mnemonic contains an unknown word (word 3)";
    assert_eq!(expected_emessage, imported_key.message);
  }
}