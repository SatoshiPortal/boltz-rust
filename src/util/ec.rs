use bitcoin::secp256k1::Secp256k1;
use bitcoin::secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use crate::util::error::{ErrorKind, S5Error};

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
    use hex::FromHex;

    use super::*;

    #[test]
    fn test_ct_primitives() {
        // 1. Test Pedersen commitment - https://docs.rs/secp256k1-zkp/0.9.2/secp256k1_zkp/struct.PedersenCommitment.html
        let secp = ZKSecp256k1::new();
        let value = 50_000;

        let blinding_factor_n = Tweak::from_inner(<[u8; 32]>::from_hex("dfad9ad4ab3d475c487858cbab210e893a6dfffa814851e4692f91f8a0818a3a").unwrap());
        let additional_generator = Generator::new_blinded(&secp, Tag::default(), blinding_factor_n.unwrap());
        let blinding_factor_r = Tweak::from_inner(<[u8; 32]>::from_hex("aa24825c14e0bf855e9bc3c877eadee934a9e870ea69fe6678650c4ab99e2d25").unwrap());
        // Pedersen commitment of form X = r*G + v*H
        //     where X is the Pedersen commitment
        //     r is the blinding_factor
        //     v is value to commit
        //     H is additional_generator and G is secp256k1's fixed generator point  
        let pc = PedersenCommitment::new(&secp, value, blinding_factor_r.unwrap(), additional_generator);
        let expected_pc = "09c02e309a8ac06d644aab0c8b52dd4318825340d7a33336a0b496a21cbea56229";
        assert_eq!(expected_pc, pc.to_string());

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
