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

pub(crate) fn script_num_to_u32(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() || bytes.len() > 5 {
        return Err(Error::Protocol("Invalid timelock encoding".to_string()));
    }

    let last = *bytes.last().expect("non-empty checked above");
    if last & 0x80 != 0 {
        return Err(Error::Protocol("Negative timelock".to_string()));
    }
    if last & 0x7f == 0 && (bytes.len() == 1 || bytes[bytes.len() - 2] & 0x80 == 0) {
        return Err(Error::Protocol("Non-minimal timelock encoding".to_string()));
    }

    let value = bytes
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            value | (u64::from(*byte) << (8 * index))
        });
    u32::try_from(value).map_err(|_| Error::Protocol("Timelock exceeds u32 range".to_string()))
}

#[cfg(test)]
mod tests {
    use super::script_num_to_u32;

    #[test]
    fn script_num_to_u32_accepts_minimal_positive_values() {
        assert_eq!(script_num_to_u32(&[0x11]).unwrap(), 17);
        assert_eq!(script_num_to_u32(&[0x80, 0x00]).unwrap(), 128);
        assert_eq!(
            script_num_to_u32(&[0xff, 0xff, 0xff, 0xff, 0x00]).unwrap(),
            u32::MAX
        );
    }

    #[test]
    fn script_num_to_u32_rejects_invalid_values() {
        assert!(script_num_to_u32(&[]).is_err());
        assert!(script_num_to_u32(&[0x80]).is_err());
        assert!(script_num_to_u32(&[0x01, 0x00]).is_err());
        assert!(script_num_to_u32(&[0x00, 0x00, 0x00, 0x00, 0x01]).is_err());
        assert!(script_num_to_u32(&[0x01, 0, 0, 0, 0, 0]).is_err());
    }
}
