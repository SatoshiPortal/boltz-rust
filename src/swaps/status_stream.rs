use crate::boltz::{InvoiceCreated, InvoiceError, SwapStatus, WsRequest, WsResponse};
use crate::error::Error;
use crate::util::sleep;
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, trace, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex};
use tokio_tungstenite_wasm::{connect, connect_with_protocols, Message, WebSocketStream};

use super::boltz::{ErrorResponse, InvoiceRequest, InvoiceRequestParams, SubscribeRequest};

struct BoltzWsConnection {
    ws: WebSocketStream,
}

struct RequestPacket {
    ws_request: WsRequest,
    response_sender: oneshot::Sender<Result<(), Error>>,
}

impl BoltzWsConnection {
    async fn new(url: &str, protocols: Option<&[&str]>) -> Result<Self, Error> {
        let ws = if let Some(protocols) = protocols {
            connect_with_protocols(url, protocols).await?
        } else {
            connect(url).await?
        };
        Ok(Self { ws })
    }

    async fn send_request(&mut self, ws_request: &WsRequest) -> Result<(), Error> {
        let t = serde_json::to_string(ws_request)?;
        self.ws.send(Message::text(t)).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BoltzWsConfig {
    pub keep_alive_interval: Duration,
    pub reconnect_delay: Duration,
    pub subscription_timeout: Duration,
    pub protocols: Option<Vec<String>>,
}

impl Default for BoltzWsConfig {
    fn default() -> Self {
        Self {
            keep_alive_interval: Duration::from_secs(15),
            reconnect_delay: Duration::from_secs(2),
            subscription_timeout: Duration::from_secs(5),
            protocols: None,
        }
    }
}

pub struct BoltzWsApi {
    pub ws_url: String,
    pub config: BoltzWsConfig,

    // broadcasts the ids after we got a successful subscription response from boltz
    subscription_notifier: broadcast::Sender<String>,
    pending_subscriptions: Mutex<HashMap<String, SubscribeRequest>>,
    subscriptions: Mutex<HashMap<String, SubscribeRequest>>,

    // communication channel for the requests to the websocket task.
    request_sender: mpsc::Sender<RequestPacket>,
    request_receiver: Mutex<mpsc::Receiver<RequestPacket>>,

    error_notifier: broadcast::Sender<ErrorResponse>,
    invoice_request_notifier: broadcast::Sender<InvoiceRequest>,
    update_notifier: broadcast::Sender<SwapStatus>,

    shutdown_sender: Mutex<Option<oneshot::Sender<()>>>,
    restart_sender: Mutex<Option<oneshot::Sender<()>>>,
}

impl BoltzWsApi {
    pub fn new(ws_url: String, config: BoltzWsConfig) -> Self {
        let (request_sender, request_receiver) = mpsc::channel(16);
        let (error_notifier, _) = broadcast::channel(16);
        let (invoice_request_notifier, _) = broadcast::channel(16);
        let (update_notifier, _) = broadcast::channel(16);
        let (subscription_notifier, _) = broadcast::channel(16);
        Self {
            ws_url,
            config,
            pending_subscriptions: Mutex::new(HashMap::new()),
            subscriptions: Mutex::new(HashMap::new()),
            request_sender,
            request_receiver: Mutex::new(request_receiver),
            subscription_notifier,
            error_notifier,
            invoice_request_notifier,
            update_notifier,
            shutdown_sender: Mutex::new(None),
            restart_sender: Mutex::new(None),
        }
    }

    pub async fn is_connected(&self) -> bool {
        self.restart_sender.lock().await.is_some()
    }

    pub async fn is_tracking(&self, id: &str) -> bool {
        self.subscriptions.lock().await.contains_key(id)
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

    pub fn errors(&self) -> broadcast::Receiver<ErrorResponse> {
        self.error_notifier.subscribe()
    }

    pub fn updates(&self) -> broadcast::Receiver<SwapStatus> {
        self.update_notifier.subscribe()
    }

    pub fn invoice_requests(&self) -> broadcast::Receiver<InvoiceRequest> {
        self.invoice_request_notifier.subscribe()
    }

    pub async fn swap_ids(&self) -> HashSet<String> {
        self.subscriptions
            .lock()
            .await
            .iter()
            .filter_map(|(id, s)| match s {
                SubscribeRequest::SwapUpdate { .. } => Some(id.clone()),
                _ => None,
            })
            .collect()
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

    pub async fn send_invoice_created(&self, id: &str, invoice: &str) -> Result<(), Error> {
        let (response_sender, response_receiver) = oneshot::channel();

        self.request_sender
            .send(RequestPacket {
                ws_request: WsRequest::Invoice(InvoiceCreated {
                    id: id.to_string(),
                    invoice: invoice.to_string(),
                }),
                response_sender,
            })
            .await
            .map_err(|e| Error::Generic(format!("Failed to send request to channel: {e:?}")))?;

        tokio::select! {
            _ = response_receiver => Ok(()),
            _ = sleep(self.config.subscription_timeout) => Err(Error::Generic("Send invoice created timeout".to_string())),
        }
    }

    pub async fn send_invoice_error(&self, id: &str, error: &str) -> Result<(), Error> {
        let (response_sender, response_receiver) = oneshot::channel();

        self.request_sender
            .send(RequestPacket {
                ws_request: WsRequest::InvoiceError(InvoiceError {
                    id: id.to_string(),
                    error: error.to_string(),
                }),
                response_sender,
            })
            .await
            .map_err(|e| Error::Generic(format!("Failed to send request to channel: {e:?}")))?;

        tokio::select! {
            _ = response_receiver => Ok(()),
            _ = sleep(self.config.subscription_timeout) => Err(Error::Generic("Send invoice error timeout".to_string())),
        }
    }

    pub async fn subscribe_offer(&self, offer: &str, signature: &str) -> Result<(), Error> {
        let ws_request = WsRequest::subscribe_invoice_request(InvoiceRequestParams {
            offer: offer.to_string(),
            signature: signature.to_string(),
        });
        match self.try_subscribe(ws_request.clone(), offer).await {
            Ok(_) => Ok(()),
            Err(e) => {
                info!(
                    "Failed to subscribe to offer {offer}, forcing reconnect and trying again: {e:?}"
                );
                self.reconnect().await?;
                self.try_subscribe(ws_request, offer).await
            }
        }
    }

    pub async fn subscribe_swap(&self, swap_id: &str) -> Result<(), Error> {
        let ws_request = WsRequest::subscribe_swap_request(swap_id);
        match self.try_subscribe(ws_request.clone(), swap_id).await {
            Ok(_) => Ok(()),
            Err(e) => {
                info!(
                    "Failed to subscribe to swap {swap_id}, forcing reconnect and trying again: {e:?}"
                );
                self.reconnect().await?;
                self.try_subscribe(ws_request, swap_id).await
            }
        }
    }

    async fn try_subscribe(&self, ws_request: WsRequest, id: &str) -> Result<(), Error> {
        let (response_sender, response_receiver) = oneshot::channel();
        let subscriptions = self.subscription_notifier.subscribe();

        if let WsRequest::Subscribe(subscribe_request) = &ws_request {
            let mut pending_subscriptions = self.pending_subscriptions.lock().await;
            pending_subscriptions.insert(id.to_string(), subscribe_request.clone());
        }

        self.request_sender
            .send(RequestPacket {
                ws_request,
                response_sender,
            })
            .await
            .map_err(|e| Error::Generic(format!("Failed to send request to channel: {e:?}")))?;

        tokio::select! {
            _ = BoltzWsApi::wait_for_subscription(response_receiver, subscriptions, id) => Ok(()),
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

            let protocols = self
                .config
                .protocols
                .as_ref()
                .map(|p| p.iter().map(|s| s.as_ref()).collect::<Vec<_>>());
            match BoltzWsConnection::new(self.ws_url.as_str(), protocols.as_deref()).await {
                Ok(mut connection) => {
                    {
                        let subscriptions = self.subscriptions.lock().await;
                        for subscribe_request in subscriptions.values() {
                            match connection
                                .send_request(&WsRequest::Subscribe(subscribe_request.clone()))
                                .await
                            {
                                Ok(_) => {}
                                Err(e) => {
                                    error!("Error resubscribing to {subscribe_request:?}: {e:?}");
                                    let _ = connection.ws.close().await;
                                    break 'outer;
                                }
                            }
                        }
                    }

                    loop {
                        let mut request_receiver = self.request_receiver.lock().await;
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
                                match connection.send_request(&WsRequest::Ping).await {
                                    Ok(_) => trace!("Sent keep-alive ping"),
                                    Err(e) => warn!("Failed to send keep-alive ping: {e:?}"),
                                }
                            },

                            Some(request_packet) = request_receiver.recv() => {
                                match connection.send_request(&request_packet.ws_request).await {
                                    Ok(_) => {
                                        let _ = request_packet.response_sender.send(Ok(()));
                                    }
                                    Err(e) => {
                                        error!("Failed to send request {:?}: {:?}", request_packet.ws_request, e);
                                        let _ = request_packet.response_sender.send(Err(e));
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
                                            // Subscribing confirmation
                                            Ok(WsResponse::Subscribe(subscribe)) => {
                                                let mut pending_subscriptions = self.pending_subscriptions.lock().await;
                                                let mut subscriptions = self.subscriptions.lock().await;
                                                for id in subscribe.args {
                                                    if let Some(subscribe_request) = pending_subscriptions.remove(&id) {
                                                        subscriptions.insert(id.clone(), subscribe_request);
                                                    }
                                                    self.subscription_notifier.send(id.clone()).unwrap();
                                                }
                                            }

                                            // Usubscribing confirmation
                                            Ok(WsResponse::Unsubscribe(unsubscribe)) => {
                                                let mut subscriptions = self.subscriptions.lock().await;
                                                for id in unsubscribe.args {
                                                    subscriptions.remove(&id);
                                                }
                                            }

                                            // Status update(s)
                                            Ok(WsResponse::Update(update)) => {
                                                for update in update.args {
                                                    if let Err(e) = self.update_notifier.send(update) {
                                                        warn!("Failed to broadcast update: {e}");
                                                    }
                                                }
                                            }

                                            // Invoice request(s)
                                            Ok(WsResponse::InvoiceRequest(invoice_request)) => {
                                                for invoice_request in invoice_request.args {
                                                    if let Err(e) = self.invoice_request_notifier.send(invoice_request) {
                                                        warn!("Failed to broadcast invoice request: {e}");
                                                    }
                                                }
                                            }

                                            // Error response
                                            Ok(WsResponse::Error(error)) => {
                                                if let Err(e) = self.error_notifier.send(error) {
                                                    warn!("Failed to broadcast error: {e}");
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
                    error!("Error connecting to websocket: {e:?}");
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

    use crate::boltz::{
        BoltzApiClientV2, BoltzWsConfig, CreateBolt12OfferRequest, GetBolt12FetchRequest,
        BOLTZ_REGTEST,
    };
    use crate::util::setup_logger;
    use serial_test::serial;
    use tokio::sync::oneshot;

    #[macros::async_test_all]
    #[serial]
    async fn test_subscribe_swap() {
        setup_logger();

        let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), None);
        let ws = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));

        assert!(!ws.is_connected().await);
        tokio::spawn(ws.clone().run_ws_loop());

        let swap_id = "swap_id";
        ws.subscribe_swap(swap_id).await.unwrap();
        assert!(ws.is_connected().await);
        assert!(ws.is_tracking(swap_id).await);
        let swap_ids = ws.swap_ids().await;
        assert!(swap_ids.contains(swap_id));

        ws.reconnect().await.unwrap();
        // we should resubscribe to the swap internally
        let mut subs = ws.subscription_notifier.subscribe();
        assert_eq!(subs.recv().await.unwrap(), swap_id);
    }

    #[macros::async_test_all]
    #[serial]
    async fn test_subscribe_invoice_request() {
        setup_logger();

        let offer = "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsjgpnk92d4djxzuvgt65hwfn94vm2dfxa5c8pc9zyhgqz6rzfzmk40jsrqwkt9ar7t0q285ag5e3ksng3r0dt32gqm5tuwc4m0ks8pfu6q5nszqm2hw2ruqxzq0hp6r9va4weev8qwm3hq4nmahcshkjaqdzezudyq5qzerxh2gwyna5ge6alhucq80ulhpjkh5aeglz37yekzrc5j0gjfru4e7u9aerf8r6sjwknef73vggr5ye6r8mn2a276g9u48ctjy0p8xm2qnyz6ghmdjux27qkh7t7mres";
        let signature = "0f86a6bc7bc34baeaf6f8a5539af3e20bbd5413e33ee9c214d9cd1821887a810639496bbdbefb2fe7fb1dd094c114ec2d038a9dd925b58683b57b83fa488c2f7";

        let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), None);
        let ws = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));

        assert!(!ws.is_connected().await);
        tokio::spawn(ws.clone().run_ws_loop());

        ws.subscribe_offer(offer, signature).await.unwrap();
        assert!(ws.is_connected().await);
        assert!(ws.is_tracking(offer).await);

        ws.reconnect().await.unwrap();
        // we should resubscribe to the offer internally
        let mut subs = ws.subscription_notifier.subscribe();
        assert_eq!(subs.recv().await.unwrap(), offer);
    }

    #[macros::async_test_all]
    #[serial]
    async fn test_receive_invoice_request_error_response() {
        setup_logger();

        let offer = "lno1qgsqvgnwgcg35z6ee2h3yczraddm72xrfua9uve2rlrm9deu7xyfzrcsjgpnk92d4djxzuvgt65hwfn94vm2dfxa5c8pc9zyhgqz6rzfzmk40jsrqwkt9ar7t0q285ag5e3ksng3r0dt32gqm5tuwc4m0ks8pfu6q5nszqm2hw2ruqxzq0hp6r9va4weev8qwm3hq4nmahcshkjaqdzezudyq5qzerxh2gwyna5ge6alhucq80ulhpjkh5aeglz37yekzrc5j0gjfru4e7u9aerf8r6sjwknef73vggr5ye6r8mn2a276g9u48ctjy0p8xm2qnyz6ghmdjux27qkh7t7mres";
        let signature = "0f86a6bc7bc34baeaf6f8a5539af3e20bbd5413e33ee9c214d9cd1821887a810639496bbdbefb2fe7fb1dd094c114ec2d038a9dd925b58683b57b83fa488c2f7";

        let boltz_api_v2 = BoltzApiClientV2::new(BOLTZ_REGTEST.to_string(), None);
        let ws = Arc::new(boltz_api_v2.ws(BoltzWsConfig::default()));

        // Register the offer with the server
        boltz_api_v2
            .post_bolt12_offer(CreateBolt12OfferRequest {
                offer: offer.to_string(),
                url: None,
            })
            .await
            .unwrap();

        assert!(!ws.is_connected().await);
        tokio::spawn(ws.clone().run_ws_loop());

        ws.subscribe_offer(offer, signature).await.unwrap();
        assert!(ws.is_connected().await);
        assert!(ws.is_tracking(offer).await);

        let mut rx = ws.invoice_requests();

        // Request a BOLT12 invoice in a separate task
        let boltz_api_v2_clone = boltz_api_v2.clone();
        let (complete_sender, complete_receiver) = oneshot::channel();
        tokio::spawn(async move {
            let res = boltz_api_v2_clone
                .get_bolt12_invoice(GetBolt12FetchRequest {
                    offer: offer.to_string(),
                    amount: 1000,
                    note: None,
                })
                .await;
            assert!(res.is_err());

            complete_sender.send(()).unwrap();
        });

        // Handle the WS message
        let req = rx.recv().await.unwrap();
        assert_eq!(req.offer, offer);

        let error = "Failed to create invoice";
        ws.send_invoice_error(&req.id, error).await.unwrap();

        complete_receiver.await.unwrap();
    }
}
