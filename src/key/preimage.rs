use secp256k1::hashes::{hash160, sha256, Hash};

use crate::util::rnd_str;

#[derive(Debug, Clone)]
pub struct Preimage {
    pub preimage: String,
    pub sha256: String,
    pub hash160: String,
    pub preimage_bytes: [u8; 32],
    pub sha256_bytes: [u8; 32],
    pub hash160_bytes: [u8; 20],
}

impl Preimage {
    pub fn new() -> Preimage {
        let preimage = rnd_str();
        let sha256 = sha256::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_string();
        let hash160 = hash160::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_string();
        let preimage_vec: Vec<u8> = hex::decode(preimage.clone()).unwrap();
        let preimage_bytes: [u8; 32] = match preimage_vec.try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Expected a Vec<u8> of length 32"),
        };
        let sha256_bytes =
            sha256::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_byte_array();
        let hash160_bytes =
            hash160::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_byte_array();

        Preimage {
            preimage,
            sha256,
            hash160,
            preimage_bytes,
            sha256_bytes,
            hash160_bytes,
        }
    }

    pub fn from_str(preimage: &str) -> Preimage {
        let preimage = preimage.to_string();
        let sha256 = sha256::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_string();
        let hash160 = hash160::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_string();
        let preimage_vec: Vec<u8> = hex::decode(preimage.clone()).unwrap();
        let preimage_bytes: [u8; 32] = match preimage_vec.try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Expected a Vec<u8> of length 32"),
        };
        let sha256_bytes =
            sha256::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_byte_array();
        let hash160_bytes =
            hash160::Hash::hash(&hex::decode(preimage.clone()).unwrap()).to_byte_array();

        Preimage {
            preimage,
            sha256,
            hash160,
            preimage_bytes,
            sha256_bytes,
            hash160_bytes,
        }
    }
}
