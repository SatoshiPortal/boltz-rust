use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::os::raw::c_char;
use std::str::FromStr;
use secp256k1::hashes::sha256;
use secp256k1::schnorr::Signature;
use secp256k1::Secp256k1;
use secp256k1::{ecdh::SharedSecret, KeyPair, Message, PublicKey, SecretKey, XOnlyPublicKey};
use bitcoin::bip32::ExtendedPrivKey;

use crate::e::{ErrorKind, S5Error};

/// FFI Output
#[derive(Serialize, Deserialize, Debug)]
pub struct XOnlyPair {
  pub seckey: String,
  pub pubkey: String,
}
impl XOnlyPair {
  pub fn c_stringify(&self) -> *mut c_char {
    let stringified = match serde_json::to_string(self) {
      Ok(result) => result,
      Err(_) => {
        return CString::new("Error:JSON Stringify Failed. BAD NEWS! Contact Support.")
          .unwrap()
          .into_raw()
      }
    };

    CString::new(stringified).unwrap().into_raw()
  }
  pub fn from_keypair(keypair: KeyPair) -> XOnlyPair {
    return XOnlyPair {
      seckey: hex::encode(keypair.secret_bytes()).to_string(),
      pubkey: keypair.public_key().to_string(),
    };
  }
}

pub fn keypair_from_xprv_str(xprv: &str) -> Result<KeyPair, S5Error> {
  let secp = Secp256k1::new();
  let xprv = match ExtendedPrivKey::from_str(xprv) {
    Ok(result) => result,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD XPRV STRING")),
  };
  let key_pair = match KeyPair::from_seckey_str(&secp, &hex::encode(xprv.private_key.secret_bytes())) {
    Ok(kp) => kp,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
  };

  Ok(key_pair)
}
pub fn keypair_from_seckey_str(seckey: &str) -> Result<KeyPair, S5Error> {
  let secp = Secp256k1::new();
  let key_pair = match KeyPair::from_seckey_str(&secp, seckey) {
    Ok(kp) => kp,
    Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
  };

  Ok(key_pair)
}

/// Generate a ecdsa shared secret
pub fn compute_shared_secret_str(
  secret_key: &str, 
  public_key: &str
) -> Result<String, S5Error> {
  let seckey = match SecretKey::from_str(secret_key) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
  };
  // let public_key = if public_key.len() == 64 {
  //   "02".to_string() + public_key
  // } else if public_key.len() == 66 {
  //   public_key.to_string()
  // } else {
  //    return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING"));
  // };
  let pubkey = match PublicKey::from_str(&public_key) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING")),
  };

  let shared_secret = SharedSecret::new(&pubkey, &seckey);
  let shared_secret_hex = hex::encode(&(shared_secret.secret_bytes()));
  Ok(shared_secret_hex)
}

pub fn signature_from_str(sig_str: &str) -> Result<Signature, S5Error> {
  match Signature::from_str(sig_str) {
    Ok(sig) => return Ok(sig),
    Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
  }
}

pub fn schnorr_sign(message: &str, key_pair: KeyPair) -> Result<Signature, S5Error> {
  let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());
  let signature = key_pair.sign_schnorr(message);
  Ok(signature)
}

pub fn schnorr_verify(signature: &str,message: &str, pubkey: &str) -> Result<bool, S5Error> {
  let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());

  let signature = match signature_from_str(signature) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD SIGNATURE STRING")),
  };

  let pubkey = match XOnlyPublicKey::from_str(&pubkey[2..]) {
    Ok(result) => result,
    Err(_) =>  return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING")),
  };

  let result = match signature.verify(&message, &pubkey) {
    Ok(()) => true,
    Err(e) => {
      println!("{}", e);
      return Err(S5Error::new(ErrorKind::Key, "BAD SIGNATURE"));
    }
  };
  return Ok(result);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn test_from_xprv_str() {
    let xprv= "xprv9ym1fn2sRJ6Am4z3cJkM4NoxFsaeNdSyFQvE5CqzqqterM5nZdKUStQghQWBupjAgJZEgAWCSQWuFgqbvdGwg22tiUp8rsupd4fTrtYMEWS";
    let key_pair = keypair_from_xprv_str(xprv).unwrap();
    let expected_pubkey = "0286a4b6e8b4c544111a6736d4f4195027d23495d947f87aa448c088da477c1b5f";
    assert_eq!(expected_pubkey, key_pair.public_key().to_string());
  }
  #[test]
  fn test_schnorr_sigs() {
    let message = "stackmate 1646056571433";
    let alice_seckey = "3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7";
    let exptected_pubkey = "02dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882";
    let key_pair = keypair_from_seckey_str(&alice_seckey).unwrap();
    assert_eq!(exptected_pubkey, &key_pair.public_key().to_string());

    let signature = schnorr_sign(message, key_pair).unwrap();
    let signature = signature_from_str(&signature.to_string()).unwrap();
    let check_sig = schnorr_verify(&signature.to_string(),message, &key_pair.public_key().to_string()).unwrap();
    // println!("{:#?}",signature.to_string());
    assert!(check_sig);
  }

  #[test]
  fn test_shared_secret() {
    let alice_pair = XOnlyPair {
      seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
      pubkey: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d".to_string(),
    };
    let bob_pair = XOnlyPair {
      seckey: "3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7".to_string(),
      pubkey: "02dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882".to_string(),
    };
    // let expected_shared_secret = "48c413dc9459a3c154221a524e8fad34267c47fc7b47443246fa8919b19fff93";
    let alice_shared_secret =
      compute_shared_secret_str(&alice_pair.seckey, &bob_pair.pubkey).unwrap();
    let bob_shared_secret =
      compute_shared_secret_str(&bob_pair.seckey, &alice_pair.pubkey).unwrap();
    // let alice_shared_secret = generate_shared_secret(alice_pair.0, bob_pair.1).unwrap();
    // let bob_shared_secret = generate_shared_secret(bob_pair.0, alice_pair.1).unwrap();
    assert_eq!(alice_shared_secret, bob_shared_secret);
    // assert_eq!(alice_shared_secret,expected_shared_secret);
  }
}