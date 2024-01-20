use std::io::{self, Write};

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

