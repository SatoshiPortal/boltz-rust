use bitcoin::bip32::ExtendedPrivKey;
use bitcoin::secp256k1::hashes::sha256;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::{
    ecdh::SharedSecret, KeyPair, Message, PublicKey, SecretKey, XOnlyPublicKey,
};
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::e::{ErrorKind, S5Error};

use super::derivation::{ChildKeys, DerivationPurpose};
use super::seed::MasterKey;

use elements::secp256k1_zkp::{
    KeyPair as ZKKeyPair, PublicKey as ZKPublicKey, SecretKey as ZKSecretKey,
};
use elements::secp256k1_zkp::{PedersenCommitment, Secp256k1 as ZKSecp256k1};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlindingKeyPair {
    seckey: String,
    pub pubkey: String,
}

impl BlindingKeyPair {
    pub fn from_secret_string(blinding_key: String) -> Result<Self, S5Error> {
        let zksecp = ZKSecp256k1::new();
        let blinding_key_bytes = hex::decode(&blinding_key).unwrap();

        let zkseckey: ZKSecretKey = match ZKSecretKey::from_str(&blinding_key) {
            Ok(result) => result,
            Err(e) => return Err(S5Error::new(ErrorKind::Key, &e.to_string())),
        };
        let zkspubkey = zkseckey.public_key(&zksecp);
        Ok(BlindingKeyPair {
            seckey: blinding_key,
            pubkey: zkspubkey.to_string(),
        })
    }
    // pub fn commit_value(&self, value: String) -> PedersenCommitment {}
    pub fn to_typed(&self) -> ZKKeyPair {
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_str(&self.seckey).unwrap();
        ZKKeyPair::from_secret_key(&secp, &seckey)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyPairString {
    pub seckey: String,
    pub pubkey: String,
}
impl KeyPairString {
    pub fn from_keypair(keypair: KeyPair) -> KeyPairString {
        return KeyPairString {
            seckey: hex::encode(keypair.secret_bytes()).to_string(),
            pubkey: keypair.public_key().to_string(),
        };
    }
    pub fn to_typed(&self) -> KeyPair {
        let secp = Secp256k1::new();
        let seckey = SecretKey::from_str(&self.seckey).unwrap();
        KeyPair::from_secret_key(&secp, &seckey)
    }
    pub fn from_mnemonic(
        mnemonic: String,
        passphrase: String,
        account: u64,
    ) -> Result<KeyPairString, S5Error> {
        if account == 0 {
            return Err(S5Error::new(
                ErrorKind::Input,
                "Account 0 is reserved for your main wallet.",
            ));
        }

        let master_key = MasterKey::import(&mnemonic, &passphrase, Network::Testnet)?;

        let child_key =
            ChildKeys::from_hardened_account(&master_key.xprv, DerivationPurpose::Native, account)?;
        let ec_key = keypair_from_xprv_str(&child_key.xprv)?;
        let string_keypair = KeyPairString::from_keypair(ec_key);
        Ok(string_keypair)
    }
}

pub fn keypair_from_xprv_str(xprv: &str) -> Result<KeyPair, S5Error> {
    let secp = Secp256k1::new();
    let xprv = match ExtendedPrivKey::from_str(xprv) {
        Ok(result) => result,
        Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD XPRV STRING")),
    };
    let key_pair =
        match KeyPair::from_seckey_str(&secp, &hex::encode(xprv.private_key.secret_bytes())) {
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
pub fn compute_shared_secret_str(secret_key: &str, public_key: &str) -> Result<String, S5Error> {
    let seckey = match SecretKey::from_str(secret_key) {
        Ok(result) => result,
        Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SECKEY STRING")),
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
        Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING")),
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

pub fn schnorr_verify(signature: &str, message: &str, pubkey: &str) -> Result<bool, S5Error> {
    let message = Message::from_hashed_data::<sha256::Hash>(message.as_bytes());

    let signature = match signature_from_str(signature) {
        Ok(result) => result,
        Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD SIGNATURE STRING")),
    };

    let pubkey = match XOnlyPublicKey::from_str(&pubkey[2..]) {
        Ok(result) => result,
        Err(_) => return Err(S5Error::new(ErrorKind::Key, "BAD PUBKEY STRING")),
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
    use elements::secp256k1_zkp::{Generator, RangeProof, Tag, Tweak};

    use super::*;

    #[test]
    fn test_ct_primitives() {
        // create a blinding key
        // commit some value
        // read the commited value
        let secp = ZKSecp256k1::new();
        let blinding_key_str = BlindingKeyPair::from_secret_string(
            "bf99362dff7e8f2ec01e081215cab9047779da4547a6f47d67bb1cbb8c96961d".to_string(),
        )
        .unwrap();

        let blinding_key = blinding_key_str.to_typed();
        let value = 50_000;

        let blinding_factor = Tweak::from_slice(blinding_key.secret_key().as_ref()).unwrap();
        let generator = Generator::new_blinded(&secp, Tag::default(), blinding_factor);
        let pc = PedersenCommitment::new(&secp, value, blinding_factor, generator);

        let min_value: u64 = 0;
        let exp: i32 = 0;
        let min_bits: u8 = 36;
        let message: &[u8] = &[];
        let additional_commitment: &[u8] = &[];
        let additional_generator = Generator::new_blinded(&secp, Tag::default(), blinding_factor);

        let range_proof = RangeProof::new(
            &secp,
            min_value,
            pc,
            value,
            blinding_factor,
            message,
            additional_commitment,
            blinding_key.secret_key(),
            exp,
            min_bits,
            additional_generator,
        )
        .unwrap();
        let range = range_proof.verify(&secp, pc, additional_commitment, additional_generator);
        println!("{:?}", range);
        /*
         * https://docs.rs/secp256k1-zkp/0.9.2/secp256k1_zkp/struct.RangeProof.html
         * pub fn new<C: Signing>(
            secp: &Secp256k1<C>,
            min_value: u64,
            commitment: PedersenCommitment,
            value: u64,
            commitment_blinding: Tweak,
            message: &[u8],
            additional_commitment: &[u8],
            sk: SecretKey,
            exp: i32,
            min_bits: u8,
            additional_generator: Generator
        ) -> Result<RangeProof, Error>

        Prove that commitment hides a value within a range, with the lower bound set to min_value.
        source
        pub fn verify<C: Verification>(
            &self,
            secp: &Secp256k1<C>,
            commitment: PedersenCommitment,
            additional_commitment: &[u8],
            additional_generator: Generator
        ) -> Result<Range<u64>, Error>

        Verify that the committed value is within a range.

        If the verification is successful, return the actual range of possible values.

        *
        */
    }

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
        let check_sig = schnorr_verify(
            &signature.to_string(),
            message,
            &key_pair.public_key().to_string(),
        )
        .unwrap();
        println!(
            "sig: {}, message: {}, seckey: {}",
            signature.to_string(),
            message,
            alice_seckey
        );
        assert!(check_sig);
    }

    #[test]
    fn test_shared_secret() {
        let alice_pair = KeyPairString {
            seckey: "d5f984d2ab332345dbf7ddff9f47852125721b2025329e6981c4130671e237d0".to_string(),
            pubkey: "023946267e8f3eeeea651b0ea865b52d1f9d1c12e851b0f98a3303c15a26cf235d"
                .to_string(),
        };
        let bob_pair = KeyPairString {
            seckey: "3c842fc0e15f2f1395922d432aafa60c35e09ad97c363a37b637f03e7adcb1a7".to_string(),
            pubkey: "02dfbbf1979269802015da7dba4143ff5935ea502ef3a7276cc650be0d84a9c882"
                .to_string(),
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
