use bitcoin::secp256k1::rand::{thread_rng, Rng};
use std::io;
use std::io::Write;

pub fn rnd_str() -> String {
    let mut rng = thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes[..]);
    hex::encode(bytes)
}

pub fn pause_and_wait(msg: &str) {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    write!(stdout, "\n").unwrap();
    write!(stdout, "******{msg}******").unwrap();
    write!(stdout, "\n").unwrap();
    write!(stdout, "Press Enter to continue...").unwrap();
    stdout.flush().unwrap();
    let _ = stdin.read_line(&mut String::new()).unwrap();
}
