use std::{env, sync::Once};

pub mod ec;
pub mod secrets;

/// Setup function that will only run once, even if called multiple times.
pub fn setup_logger() {
    Once::new().call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default()
                .default_filter_or("debug")
                .default_write_style_or("always"),
        )
        // .is_test(true)
        .init();
    });
}
