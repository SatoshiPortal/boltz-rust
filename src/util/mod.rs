use bitcoin::hex::FromHex;
use std::time::Duration;

pub mod bolt12;
pub mod ec;
pub mod fees;
pub mod invoice;
#[cfg(feature = "lnurl")]
pub mod lnurl;
pub mod secrets;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use gloo_timers::future::TimeoutFuture;

use crate::error::Error;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
static INIT: std::sync::Once = std::sync::Once::new();

/// Setup function that will only run once, even if called multiple times.
pub fn setup_logger() {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    INIT.call_once(|| {
        env_logger::Builder::from_env(
            env_logger::Env::default()
                .default_filter_or("debug")
                .default_write_style_or("always"),
        )
        .filter_module("serial_test", log::LevelFilter::Error)
        // .is_test(true)
        .init();
    });
}

#[cfg(all(
    feature = "ws",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
pub(crate) fn ensure_rustls_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[cfg(all(feature = "ws", target_family = "wasm", target_os = "unknown"))]
pub(crate) fn ensure_rustls_crypto_provider() {}

pub async fn sleep(duration: Duration) {
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    {
        tokio::time::sleep(duration).await;
    }
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    {
        let timeout_ms = duration.as_millis() as u32;
        TimeoutFuture::new(timeout_ms).await;
    }
}

pub(crate) fn hex_to_bytes32(hex: &str) -> Result<[u8; 32], Error> {
    let bytes = Vec::from_hex(hex)?;
    if bytes.len() != 32 {
        return Err(Error::Protocol(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut result = [0u8; 32];
    result.copy_from_slice(&bytes);
    Ok(result)
}
