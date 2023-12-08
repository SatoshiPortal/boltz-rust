use secp256k1::rand::{thread_rng,Rng};

// use rand::{Rng, thread_rng};

pub fn rnd_str() -> String {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    hex::encode(bytes)
}
