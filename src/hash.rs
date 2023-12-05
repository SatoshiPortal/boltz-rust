use secp256k1::rand::{thread_rng,Rng};

pub fn rnd_str()->String{
    let mut rng = thread_rng();
    let random = rng.gen::<u64>().clone();
    let random_string = random.to_string();
    let random_bytes = random_string.as_bytes();
    let key_str = "ishi".to_string() + &base64::encode(random_bytes); 
    println!("KEY: {}", key_str);
    // let key = Key::from_slice(&key_str.as_bytes());
    // let ciphertext = _cc20p1305_encrypt(message.as_bytes(), &key).unwrap();
    // let plaintext = _cc20p1305_decrypt(&ciphertext, key).unwrap();
    // println!("{}\n{}",ciphertext,plaintext);
    // assert_eq!(&plaintext, message);
    key_str.to_string()
}