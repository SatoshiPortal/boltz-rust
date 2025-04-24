use crate::boltz::{SwapStatus, WsRequest, WsResponse};
use crate::error::Error;
use crate::util::sleep;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, trace, warn};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio_tungstenite_wasm::{connect, Message, WebSocketStream};

struct BoltzWsConnection {
    ws: WebSocketStream,
}

struct SubscriptionRequest {
    swap_id: String,
    response_sender: oneshot::Sender<Result<(), Error>>,
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

#[derive(Debug, Clone)]
pub struct BoltzWsConfig {
    pub keep_alive_interval: Duration,
    pub reconnect_delay: Duration,
    pub subscription_timeout: Duration,
}

impl Default for BoltzWsConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: Duration::from_secs(15),
            reconnect_delay: Duration::from_secs(2),
            subscription_timeout: Duration::from_secs(5),
        }
    }
}

pub struct BoltzWsApi {
    pub ws_url: String,
    pub config: BoltzWsConfig,

    // broadcasts the swap ids after we got a successful subscription response from boltz
    subscription_notifier: broadcast::Sender<String>,
    subscribed_swaps: Mutex<HashSet<String>>,

    // communication channel for the subscription requests to the websocket task.
    subscription_sender: mpsc::Sender<SubscriptionRequest>,
    subscription_receiver: Mutex<mpsc::Receiver<SubscriptionRequest>>,

    update_notifier: broadcast::Sender<SwapStatus>,
    shutdown_sender: Mutex<Option<oneshot::Sender<()>>>,
    restart_sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl BoltzWsApi {
    pub fn new(ws_url: String, config: BoltzWsConfig) -> Self {
        let (subscription_sender, subscription_receiver) = mpsc::channel(16);
        let (update_notifier, _) = broadcast::channel(16);
        let (subscription_notifier, _) = broadcast::channel(16);
        Self {
            ws_url,
            config,
            subscribed_swaps: Mutex::new(HashSet::new()),
            subscription_sender,
            subscription_receiver: Mutex::new(subscription_receiver),
            subscription_notifier,
            update_notifier,
            shutdown_sender: Mutex::new(None),
            restart_sender: Mutex::new(None),
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.restart_sender.lock().await.is_some()
    }

    pub async fn is_tracking(&self, swap_id: &str) -> bool {
        self.subscribed_swaps.lock().await.contains(swap_id)
    }

    pub async fn reconnect(&self) -> Result<(), Error> {
        if let Some(sender) = self.restart_sender.lock().await.take() {
            sender
                .send(())
                .map_err(|_| Error::Generic("Failed to send restart signal".to_string()))
        } else {
            Err(Error::Generic("Not connected".to_string()))
        }
    }

    pub fn updates(&self) -> broadcast::Receiver<SwapStatus> {
        self.update_notifier.subscribe()
    }

    pub async fn swap_ids(&self) -> HashSet<String> {
        self.subscribed_swaps.lock().await.clone()
    }

    async fn wait_for_subscription(
        response_receiver: oneshot::Receiver<Result<(), Error>>,
        mut subscriptions: broadcast::Receiver<String>,
        swap_id: &str,
    ) -> Result<(), Error> {
        // First, wait for the result from the subscribe call
        response_receiver
            .await
            .map_err(|_| Error::Generic("Failed to receive subscription response".to_string()))??;

        // Then, wait for the successful subscription response from boltz
        loop {
            if subscriptions.recv().await.map_err(|_| {
                Error::Generic("Failed to receive subscription notification".to_string())
            })? == swap_id
            {
                return Ok(());
            }
        }
    }

    pub async fn subscribe(&self, swap_id: &str) -> Result<(), Error> {
        match self.try_subscribe(swap_id).await {
            Ok(_) => Ok(()),
            Err(e) => {
                info!(
                    "Failed to subscribe to swap {}, forcing reconnect and trying again: {:?}",
                    swap_id, e
                );
                self.reconnect().await?;
                self.try_subscribe(swap_id).await
            }
        }
    }

    async fn try_subscribe(&self, swap_id: &str) -> Result<(), Error> {
        let (response_sender, response_receiver) = oneshot::channel();
        let subscriptions = self.subscription_notifier.subscribe();

        self.subscription_sender
            .send(SubscriptionRequest {
                swap_id: swap_id.to_string(),
                response_sender,
            })
            .await
            .map_err(|e| {
                Error::Generic(format!(
                    "Failed to send subscription request to channel: {:?}",
                    e
                ))
            })?;

        tokio::select! {
            _ = BoltzWsApi::wait_for_subscription(response_receiver, subscriptions, swap_id) => Ok(()),
            _ = sleep(self.config.subscription_timeout) => Err(Error::Generic("Subscription timeout".to_string())),
        }
    }

    pub async fn run_ws_loop(self: Arc<Self>) {
        let (shutdown_sender, mut shutdown_receiver) = oneshot::channel();
        let _ = self.shutdown_sender.lock().await.replace(shutdown_sender);

        'outer: loop {
            // Set up restart channel at the start of each connection attempt
            let (restart_sender, mut restart_receiver) = oneshot::channel();
            let _ = self.restart_sender.lock().await.replace(restart_sender);

            let mut interval = Box::pin(futures_util::stream::unfold((), async |_| {
                sleep(self.config.keep_alive_interval).await;
                Some(((), ()))
            }));

            match BoltzWsConnection::new(self.ws_url.as_str()).await {
                Ok(mut connection) => {
                    {
                        let ids = self.subscribed_swaps.lock().await;
                        match connection.subscribe(ids.iter().cloned().collect()).await {
                            Ok(_) => {}
                            Err(e) => {
                                error!("Error subscribing to swaps: {:?}", e);
                                sleep(self.config.reconnect_delay).await;
                                continue;
                            }
                        }
                    }

                    loop {
                        let mut sub_receiver = self.subscription_receiver.lock().await;
                        tokio::select! {
                            _ = &mut shutdown_receiver => {
                                info!("Received shutdown signal, exiting socket loop");
                                break 'outer;
                            },

                            _ = &mut restart_receiver => {
                                info!("Received restart signal, reconnecting");
                                break;
                            },

                            _ = interval.next() => {
                                match connection.send_json(&WsRequest::Ping).await {
                                    Ok(_) => trace!("Sent keep-alive ping"),
                                    Err(e) => warn!("Failed to send keep-alive ping: {e:?}"),
                                }
                            },

                            Some(subscription) = sub_receiver.recv() => {
                                match connection.subscribe(vec![subscription.swap_id.clone()]).await {
                                    Ok(_) => {
                                        let _ = subscription.response_sender.send(Ok(()));
                                    }
                                    Err(e) => {
                                        error!("Failed to subscribe to swap {}: {:?}", subscription.swap_id, e);
                                        let _ = subscription.response_sender.send(Err(e));
                                    }
                                }
                            },

                            maybe_next = connection.ws.next() => match maybe_next {
                                Some(msg) => match msg {
                                    Ok(Message::Close(_)) => {
                                        warn!("Received close msg, exiting socket loop");
                                        break;
                                    },
                                    Ok(Message::Text(payload)) => {
                                        let payload = payload.as_str();
                                        debug!("Received text msg: {payload:?}");
                                        match serde_json::from_str::<WsResponse>(payload) {
                                            // Subscribing/unsubscribing confirmation
                                            Ok(WsResponse::Subscribe(subscribe)) => {
                                                let mut swap_ids = self.subscribed_swaps.lock().await;
                                                for swap_id in subscribe.args {
                                                    self.subscription_notifier.send(swap_id.clone()).unwrap();
                                                    swap_ids.insert(swap_id);
                                                }
                                            }
                                            Ok(WsResponse::Unsubscribe { .. }) => {}

                                            // Status update(s)
                                            Ok(WsResponse::Update(update)) => {
                                                for update in update.args {
                                                    if let Err(e) = self.update_notifier.send(update) {
                                                        warn!("Failed to broadcast update: {}", e);
                                                    }
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
                                    sleep(self.config.reconnect_delay).await;
                                    break;
                                },
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error connecting to websocket: {:?}", e);
                    sleep(self.config.reconnect_delay).await;
                }
            }
        }
    }
}

impl Drop for BoltzWsApi {
    fn drop(&mut self) {
        if let Some(sender) = self.shutdown_sender.get_mut().take() {
            let _ = sender.send(());
        }
    }
}

#[cfg(test)]
#[cfg(feature = "regtest")]
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
mod tests {
    use std::sync::Arc;

    use crate::boltz::{BoltzApiClientV2, BoltzWsConfig, BOLTZ_REGTEST};
    use crate::util::setup_logger;
    use serial_test::serial;

    #[macros::async_test_all]
    #[serial]
    async fn test_subscribe() {
        setup_logger();

        let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), None);
        let ws = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));

        assert!(!ws.is_connected().await);
        tokio::spawn(ws.clone().run_ws_loop());

        let swap_id = "swap_id";
        ws.subscribe(swap_id).await.unwrap();
        assert!(ws.is_connected().await);
        assert!(ws.is_tracking(swap_id).await);
        let swap_ids = ws.swap_ids().await;
        assert!(swap_ids.contains(swap_id));

        ws.reconnect().await.unwrap();
        // we should resubscribe to the swap internally
        let mut subs = ws.subscription_notifier.subscribe();
        assert_eq!(subs.recv().await.unwrap(), swap_id);
    }
}
