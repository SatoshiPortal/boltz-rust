use std::str::FromStr;

use bitcoin::secp256k1::hashes::{hash160, ripemd160, sha256, Hash};
use lightning_invoice::Bolt11Invoice;

use crate::e::{ErrorKind, S5Error};
use bitcoin::secp256k1::rand::rngs::OsRng;
use rand_core::RngCore;

fn rng_32b() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[derive(Debug, Clone)]
pub struct Preimage {
    pub bytes: Option<[u8; 32]>,
    pub sha256: sha256::Hash,
    pub hash160: hash160::Hash,
}

impl Preimage {
    pub fn new() -> Preimage {
        let preimage = rng_32b();
        let sha256 = sha256::Hash::hash(&preimage);
        let hash160 = hash160::Hash::hash(&preimage);

        Preimage {
            bytes: Some(preimage),
            sha256: sha256,
            hash160: hash160,
        }
    }

    pub fn from_str(preimage: &str) -> Result<Preimage, S5Error> {
        // Check if the input string is exactly 64 characters (32 bytes)
        if preimage.len() != 64 {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Preimage input is not 32 bytes",
            ));
        }

        let decoded = match hex::decode(preimage) {
            Ok(decoded) => decoded,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };

        // Ensure the decoded bytes are exactly 32 bytes long
        let preimage_bytes: [u8; 32] = match decoded.try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(S5Error::new(
                    ErrorKind::Input,
                    "Decoded Preimage input is not 32 bytes",
                ))
            }
        };

        let sha256 = sha256::Hash::hash(&preimage_bytes);
        let hash160 = hash160::Hash::hash(&preimage_bytes);

        Ok(Preimage {
            bytes: Some(preimage_bytes),
            sha256: sha256,
            hash160: hash160,
        })
    }

    pub fn from_sha256_str(preimage_sha256: &str) -> Result<Preimage, S5Error> {
        let sha256 = match sha256::Hash::from_str(preimage_sha256) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Input, &e.to_string())),
        };
        let hash160 = hash160::Hash::from_slice(
            ripemd160::Hash::hash(sha256.as_byte_array()).as_byte_array(),
        )
        .unwrap();
        // will never fail as long as sha256 is a valid sha256::Hash
        Ok(Preimage {
            bytes: None,
            sha256: sha256,
            hash160: hash160,
        })
    }
    pub fn from_invoice_str(invoice_str: &str) -> Result<Preimage, S5Error> {
        let invoice = match Bolt11Invoice::from_str(&invoice_str) {
            Ok(invoice) => invoice,
            Err(e) => {
                println!("{:?}", e);
                return Err(S5Error::new(
                    ErrorKind::Input,
                    "Could not parse invoice string.",
                ));
            }
        };
        Ok(Preimage::from_sha256_str(
            &invoice.payment_hash().to_string(),
        )?)
    }
    pub fn to_string(&self) -> Option<String> {
        match &self.bytes {
            Some(result) => Some(hex::encode(result)),
            None => None,
        }
    }
}
