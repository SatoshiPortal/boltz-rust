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
}
