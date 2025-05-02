use std::time::Duration;

pub mod ec;
pub mod fees;
#[cfg(feature = "lnurl")]
pub mod lnurl;
pub mod secrets;

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
use gloo_timers::future::TimeoutFuture;

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
