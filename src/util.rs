use secp256k1::rand::{thread_rng,Rng};

pub fn rnd_str()->String{
    let mut rng = thread_rng();
    let random = rng.gen::<u64>().clone();
    let random_string = random.to_string();
    let random_bytes = random_string.as_bytes();
    hex::encode(random_bytes)
}