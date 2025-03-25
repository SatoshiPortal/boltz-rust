use crate::boltz::{SwapStatus, WsRequest, WsResponse};
use crate::error::Error;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, oneshot, Mutex};
use tokio_tungstenite_wasm::{connect, Message, WebSocketStream};

struct BoltzWsConnection {
    ws: WebSocketStream,
}

impl BoltzWsConnection {
    async fn new(url: &str) -> Result<Self, Error> {
        let ws = connect(url).await?;
        Ok(Self { ws })
    }

    async fn subscribe(&mut self, ids: Vec<String>) -> Result<(), Error> {
        if ids.is_empty() {
            return Ok(());
        }
        self.send_json(&WsRequest::subscribe_swaps_request(ids))
            .await
    }

    async fn send_json(&mut self, data: &WsRequest) -> Result<(), Error> {
        let t = serde_json::to_string(data)?;
        self.ws.send(Message::text(t)).await?;
        Ok(())
    }
}

pub struct BoltzWsApi {
    ws_url: String,
    swap_ids: Mutex<Vec<String>>,
    subscription_notifier: broadcast::Sender<String>,
    update_notifier: broadcast::Sender<SwapStatus>,
    shutdown_sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl BoltzWsApi {
    pub fn new(ws_url: String) -> Self {
        let (subscription_notifier, _) = broadcast::channel(16);
        let (update_notifier, _) = broadcast::channel(16);
        Self {
            ws_url,
            swap_ids: Mutex::new(vec![]),
            subscription_notifier,
            update_notifier,
            shutdown_sender: Mutex::new(None),
        }
    }

    pub fn updates(&self) -> broadcast::Receiver<SwapStatus> {
        self.update_notifier.subscribe()
    }

    pub fn subscribe(&self, swap_id: &str) -> Result<(), Error> {
        let _ = self.subscription_notifier.subscribe();
        match self.subscription_notifier.send(swap_id.to_string()) {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::Protocol(format!(
                "Failed to send subscription: {:?}",
                e
            ))),
        }
    }

    pub fn start(self: Arc<Self>) {
        let keep_alive_ping_interval = Duration::from_secs(15);
        let reconnect_delay = Duration::from_secs(2);
        let mut sub_stream = self.subscription_notifier.subscribe();

        tokio::spawn(async move {
            let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();
            let _ = self.shutdown_sender.lock().await.replace(shutdown_sender);

            loop {
                match BoltzWsConnection::new(self.ws_url.as_str()).await {
                    Ok(mut connection) => {
                        {
                            let ids = self.swap_ids.lock().await;
                            match connection.subscribe(ids.to_owned()).await {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("Error subscribing to swaps: {:?}", e);
                                    tokio::time::sleep(reconnect_delay).await;
                                    continue;
                                }
                            }
                        }
                        let mut interval = tokio::time::interval(keep_alive_ping_interval);

                        loop {
                            tokio::select! {
                                _ = &mut shutdown_receiver => {
                                    info!("Received shutdown signal, exiting socket loop");
                                    break;
                                },

                                _ = interval.tick() => {
                                    match connection.send_json(&WsRequest::Ping).await {
                                        Ok(_) => debug!("Sent keep-alive ping"),
                                        Err(e) => warn!("Failed to send keep-alive ping: {e:?}"),
                                    }
                                },

                                swap_res = sub_stream.recv() => match swap_res {
                                    Ok(swap_id) => {
                                        if let Err(e) = connection.subscribe(vec![swap_id.clone()]).await {
                                            let mut ids = self.swap_ids.lock().await;
                                            ids.push(swap_id.clone());
                                            error!("Failed to subscribe to swap {swap_id}: {e:?}");
                                        }
                                    },
                                    Err(e) => error!("Received error on subscription stream: {e:?}"),
                                },

                                maybe_next = connection.ws.next() => match maybe_next {
                                    Some(msg) => match msg {
                                        Ok(Message::Close(_)) => {
                                            warn!("Received close msg, exiting socket loop");
                                            tokio::time::sleep(reconnect_delay).await;
                                            break;
                                        },
                                        Ok(Message::Text(payload)) => {
                                            let payload = payload.as_str();
                                            info!("Received text msg: {payload:?}");
                                            match serde_json::from_str::<WsResponse>(payload) {
                                                // Subscribing/unsubscribing confirmation
                                                Ok(WsResponse::Subscribe { .. }) | Ok(WsResponse::Unsubscribe { .. }) => {}

                                                // Status update(s)
                                                Ok(WsResponse::Update(update)) => {
                                                    for update in update.args {
                                                        let _ = self.update_notifier.send(update);
                                                    }
                                                }

                                                // A response to one of our pings
                                                Ok(WsResponse::Pong) => debug!("Received pong"),

                                                // Either an invalid response, or an error related to subscription
                                                Err(e) => error!("Failed to parse websocket response: {e:?} - response: {payload}"),
                                            }
                                        },
                                        Ok(msg) => warn!("Unhandled msg: {msg:?}"),
                                        Err(e) => {
                                            error!("Received stream error: {e:?}");
                                            let _ = connection.ws.close().await;
                                            break;
                                        }
                                    },
                                    None => {
                                        warn!("Received nothing from the stream");
                                        let _ = connection.ws.close().await;
                                        tokio::time::sleep(reconnect_delay).await;
                                        break;
                                    },
                                }

                            }
                        }
                    }
                    Err(e) => {
                        error!("Error connecting to websocket: {:?}", e);
                        tokio::time::sleep(reconnect_delay).await;
                    }
                }
            }
        });
    }
}

impl Drop for BoltzWsApi {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown_sender.get_mut().take() {
            let _ = sender.send(());
        }
    }
}
