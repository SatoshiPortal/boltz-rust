#![cfg(feature = "regtest")]

use boltz_client::boltz::{BoltzApiClientV2, WsRequest, WsResponse, BOLTZ_REGTEST};
use boltz_client::util::setup_logger;
use futures_util::{SinkExt, StreamExt};
use serial_test::serial;
use std::time::Duration;
use tokio_tungstenite_wasm::Message;

mod bitcoin;
mod chain_swaps;
mod liquid;

const WAIT_TIME_MS: i32 = 5_000;

const BOLTZ_TIMEOUT: Duration = Duration::from_secs(30);

#[macros::async_test_all]
#[serial]
async fn ws_ping_pong() {
    setup_logger();

    let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), None);

    let (mut sender, mut receiver) = boltz_api_v2.connect_ws().await.unwrap().split();

    sender
        .send(Message::text(
            serde_json::to_string(&WsRequest::Ping).unwrap(),
        ))
        .await
        .unwrap();

    loop {
        let response = receiver.next().await.unwrap().unwrap().into_text().unwrap();

        if let Ok(WsResponse::Pong) = serde_json::from_str(&response) {
            log::info!("Got Pong from server");
            break;
        }
    }
}
