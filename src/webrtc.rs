use std::collections::{HashMap, VecDeque};
use std::io::{Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex as StdMutex, OnceLock, Weak};
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine;
use bytes::{Bytes, BytesMut};
use rtc::ice::mdns::MulticastDnsMode;
use rtc::peer_connection::configuration::setting_engine::SctpMaxMessageSize;
use tokio::sync::{watch, Mutex, Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use url::Url;
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::peer_connection::{
    PeerConnection, PeerConnectionBuilder, PeerConnectionEventHandler, RTCConfigurationBuilder,
    RTCIceGatheringState, RTCIceServer, RTCIceTransportPolicy, RTCPeerConnectionState,
    RTCSessionDescription, SettingEngineBuilder,
};

use crate::config;
use crate::protobuf::Message;
use crate::sodiumoxide::crypto::secretbox::Key;
use crate::ResultType;

const DATA_CHANNEL_BUFFER_SIZE: usize = u16::MAX as usize;
const RECEIVE_QUEUE_CAPACITY: usize = 32;
const MAX_SDP_SIZE: usize = 256 * 1024;
static DEFAULT_ICE_SERVERS: [&str; 3] = [
    "stun:stun.cloudflare.com:3478",
    "stun:stun.nextcloud.com:3478",
    "stun:stun.nextcloud.com:443",
];

lazy_static::lazy_static! {
    static ref SESSIONS: Arc<Mutex<HashMap<String, WebRTCStream>>> = Default::default();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChannelState {
    Connecting,
    Open,
    Closed,
}

struct SessionState {
    channel: StdMutex<Option<Arc<dyn DataChannel>>>,
    status: watch::Sender<ChannelState>,
    gathered: watch::Sender<bool>,
    incoming: StdMutex<VecDeque<(OwnedSemaphorePermit, BytesMut)>>,
    incoming_ready: Notify,
    incoming_slots: Arc<Semaphore>,
    peer: OnceLock<Weak<dyn PeerConnection>>,
    cache_key: StdMutex<Option<String>>,
}

impl SessionState {
    fn new() -> Arc<Self> {
        let (status, _) = watch::channel(ChannelState::Connecting);
        let (gathered, _) = watch::channel(false);
        Arc::new(Self {
            channel: StdMutex::new(None),
            status,
            gathered,
            incoming: StdMutex::new(VecDeque::new()),
            incoming_ready: Notify::new(),
            incoming_slots: Arc::new(Semaphore::new(RECEIVE_QUEUE_CAPACITY)),
            peer: OnceLock::new(),
            cache_key: StdMutex::new(None),
        })
    }

    fn close(self: &Arc<Self>) {
        if self.status.send_replace(ChannelState::Closed) == ChannelState::Closed {
            return;
        }
        self.incoming_slots.close();
        self.incoming_ready.notify_waiters();
        let key = self
            .cache_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let peer = self.peer.get().and_then(Weak::upgrade);
        // Driver callbacks must not wait for an RPC to their own driver.
        tokio::spawn(async move {
            if let Some(peer) = peer {
                if let Some(key) = key {
                    let mut sessions = SESSIONS.lock().await;
                    if sessions
                        .get(&key)
                        .is_some_and(|entry| Arc::ptr_eq(&entry.pc, &peer))
                    {
                        sessions.remove(&key);
                    }
                }
                if let Err(err) = peer.close().await {
                    log::debug!("WebRTC peer cleanup: {err}");
                }
            }
        });
    }

    fn attach(self: &Arc<Self>, channel: Arc<dyn DataChannel>) {
        let accepted = {
            let mut current = self.channel.lock().unwrap_or_else(|e| e.into_inner());
            if current.is_some() || *self.status.borrow() == ChannelState::Closed {
                false
            } else {
                *current = Some(channel.clone());
                true
            }
        };
        let state = self.clone();
        tokio::spawn(async move {
            if !accepted {
                if let Err(err) = channel.close().await {
                    log::debug!("WebRTC extra channel cleanup: {err}");
                }
                return;
            }
            while let Some(event) = channel.poll().await {
                match event {
                    DataChannelEvent::OnOpen => {
                        state.status.send_if_modified(|status| {
                            if *status == ChannelState::Connecting {
                                *status = ChannelState::Open;
                                true
                            } else {
                                false
                            }
                        });
                    }
                    DataChannelEvent::OnMessage(message) => {
                        if message.is_string
                            || message.data.is_empty()
                            || message.data.len() > DATA_CHANNEL_BUFFER_SIZE
                        {
                            state.close();
                            break;
                        }
                        let Ok(permit) = state.incoming_slots.clone().acquire_owned().await else {
                            break;
                        };
                        state
                            .incoming
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .push_back((permit, message.data));
                        state.incoming_ready.notify_one();
                    }
                    DataChannelEvent::OnClose
                    | DataChannelEvent::OnClosing
                    | DataChannelEvent::OnError => {
                        state.close();
                        break;
                    }
                    _ => {}
                }
            }
            state.close();
        });
    }

    async fn wait_connected(&self) -> ResultType<()> {
        let mut state = self.status.subscribe();
        loop {
            match *state.borrow_and_update() {
                ChannelState::Open => return Ok(()),
                ChannelState::Closed => {
                    return Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        "WebRTC connection closed",
                    )
                    .into())
                }
                ChannelState::Connecting => {}
            }
            state.changed().await.map_err(|_| {
                Error::new(ErrorKind::ConnectionAborted, "WebRTC connection closed")
            })?;
        }
    }

    async fn wait_gathered(&self) -> ResultType<()> {
        let mut gathered = self.gathered.subscribe();
        let mut state = self.status.subscribe();
        loop {
            if *state.borrow_and_update() == ChannelState::Closed {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "WebRTC connection closed during ICE gathering",
                )
                .into());
            }
            if *gathered.borrow_and_update() {
                return Ok(());
            }
            tokio::select! {
                result = gathered.changed() => result.map_err(|_| Error::new(ErrorKind::ConnectionAborted, "WebRTC ICE gathering closed"))?,
                result = state.changed() => result.map_err(|_| Error::new(ErrorKind::ConnectionAborted, "WebRTC connection closed"))?,
            }
        }
    }
}

struct SessionEvents(Arc<SessionState>);

#[async_trait::async_trait]
impl PeerConnectionEventHandler for SessionEvents {
    async fn on_data_channel(&self, channel: Arc<dyn DataChannel>) {
        self.0.attach(channel);
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.0.gathered.send_replace(true);
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        if matches!(
            state,
            RTCPeerConnectionState::Disconnected
                | RTCPeerConnectionState::Failed
                | RTCPeerConnectionState::Closed
        ) {
            self.0.close();
        }
    }
}

#[derive(Clone)]
pub struct WebRTCStream {
    pc: Arc<dyn PeerConnection>,
    state: Arc<SessionState>,
    send_timeout: u64,
}

impl WebRTCStream {
    fn get_remote_offer(endpoint: &str) -> ResultType<String> {
        let encoded = endpoint
            .strip_prefix("webrtc://")
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "Invalid WebRTC endpoint format"))?;
        if encoded.len() > MAX_SDP_SIZE * 4 / 3 + 4 {
            return Err(
                Error::new(ErrorKind::InvalidInput, "WebRTC SDP exceeds size limit").into(),
            );
        }
        let decoded = BASE64_STANDARD
            .decode(encoded)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Failed to decode Base64 SDP"))?;
        if decoded.len() > MAX_SDP_SIZE {
            return Err(
                Error::new(ErrorKind::InvalidInput, "WebRTC SDP exceeds size limit").into(),
            );
        }
        Ok(String::from_utf8(decoded)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid SDP UTF-8"))?)
    }

    fn sdp_to_endpoint(sdp: &str) -> String {
        format!("webrtc://{}", BASE64_STANDARD.encode(sdp))
    }

    fn get_key_for_sdp(sdp: &RTCSessionDescription) -> ResultType<String> {
        let description = sdp.unmarshal()?;
        for media in &description.media_descriptions {
            if media.media_name.media == "application" {
                if let Some(fingerprint) = media
                    .attributes
                    .iter()
                    .find(|attribute| attribute.key == "fingerprint")
                    .and_then(|attribute| attribute.value.as_ref())
                {
                    return Ok(fingerprint.to_owned());
                }
            }
        }
        description
            .attribute("fingerprint")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("SDP fingerprint attribute not found"))
    }

    fn get_key_for_sdp_json(sdp_json: &str) -> ResultType<String> {
        if sdp_json.is_empty() {
            return Ok(String::new());
        }
        Self::get_key_for_sdp(&serde_json::from_str(sdp_json)?)
    }

    fn get_ice_server_from_url(url: &str) -> Option<RTCIceServer> {
        let url = Url::parse(url).ok()?;
        if !matches!(url.scheme(), "turn" | "turns" | "stun" | "stuns") {
            return None;
        }
        Some(RTCIceServer {
            urls: vec![format!(
                "{}:{}:{}",
                url.scheme(),
                url.host_str()?,
                url.port().unwrap_or(3478)
            )],
            username: url.username().to_owned(),
            credential: url.password().unwrap_or_default().to_owned(),
            ..Default::default()
        })
    }

    fn get_ice_servers() -> Vec<RTCIceServer> {
        Self::parse_ice_servers(&config::Config::get_option(
            config::keys::OPTION_ICE_SERVERS,
        ))
    }

    fn parse_ice_servers(configuration: &str) -> Vec<RTCIceServer> {
        let mut servers: Vec<_> = configuration
            .split(',')
            .map(str::trim)
            .filter_map(Self::get_ice_server_from_url)
            .collect();
        if !servers.iter().any(|server| {
            server
                .urls
                .iter()
                .any(|url| url.starts_with("stun:") || url.starts_with("stuns:"))
        }) {
            servers.insert(
                0,
                RTCIceServer {
                    urls: DEFAULT_ICE_SERVERS
                        .iter()
                        .map(|url| (*url).to_owned())
                        .collect(),
                    ..Default::default()
                },
            );
        }
        servers
    }

    pub async fn new(
        remote_endpoint: &str,
        force_relay: bool,
        ms_timeout: u64,
    ) -> ResultType<Self> {
        Self::create(
            remote_endpoint,
            force_relay,
            ms_timeout,
            Self::get_ice_servers(),
            false,
            true,
        )
        .await
    }

    async fn create(
        remote_endpoint: &str,
        force_relay: bool,
        ms_timeout: u64,
        ice_servers: Vec<RTCIceServer>,
        loopback: bool,
        cache: bool,
    ) -> ResultType<Self> {
        let offer = if remote_endpoint.is_empty() {
            String::new()
        } else {
            Self::get_remote_offer(remote_endpoint)?
        };
        if !offer.is_empty()
            && serde_json::from_str::<serde_json::Value>(&offer)?
                .get("type")
                .and_then(serde_json::Value::as_str)
                != Some("offer")
        {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "A new WebRTC connection requires an offer",
            )
            .into());
        }
        let mut key = Self::get_key_for_sdp_json(&offer)?;
        if cache && !key.is_empty() {
            if let Some(session) = SESSIONS.lock().await.get(&key) {
                return Ok(session.clone());
            }
        }
        let state = SessionState::new();
        let settings = SettingEngineBuilder::default()
            .with_multicast_dns_mode(MulticastDnsMode::Disabled)
            .with_include_loopback_candidate(loopback)
            .with_sctp_max_message_size(SctpMaxMessageSize::Bounded(
                DATA_CHANNEL_BUFFER_SIZE as u32,
            ))
            .build();
        let configuration = RTCConfigurationBuilder::default()
            .with_ice_servers(ice_servers)
            .with_ice_transport_policy(if force_relay {
                RTCIceTransportPolicy::Relay
            } else {
                RTCIceTransportPolicy::All
            })
            .build();
        let pc: Arc<dyn PeerConnection> = Arc::new(
            PeerConnectionBuilder::new()
                .with_configuration(configuration)
                .with_setting_engine(settings)
                .with_handler(Arc::new(SessionEvents(state.clone())))
                .with_udp_addrs(vec![if loopback { "127.0.0.1:0" } else { "0.0.0.0:0" }])
                .with_data_channel_send_buffer_limit(
                    RECEIVE_QUEUE_CAPACITY * DATA_CHANNEL_BUFFER_SIZE,
                )
                .build()
                .await?,
        );
        if state.peer.set(Arc::downgrade(&pc)).is_err() {
            pc.close().await?;
            return Err(anyhow::anyhow!("WebRTC peer is already initialized"));
        }
        let closed_during_build = *state.status.borrow() == ChannelState::Closed;
        if closed_during_build {
            pc.close().await?;
            return Err(Error::new(
                ErrorKind::ConnectionAborted,
                "WebRTC connection closed during setup",
            )
            .into());
        }
        let setup: ResultType<()> = async {
            if offer.is_empty() {
                state.attach(pc.create_data_channel("bootstrap", None).await?);
                let description = pc.create_offer(None).await?;
                key = Self::get_key_for_sdp(&description)?;
                pc.set_local_description(description).await?;
            } else {
                pc.set_remote_description(serde_json::from_str(&offer)?)
                    .await?;
                let description = pc.create_answer(None).await?;
                pc.set_local_description(description).await?;
            }
            timeout(
                Duration::from_millis(if ms_timeout == 0 { 30_000 } else { ms_timeout }),
                state.wait_gathered(),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "WebRTC ICE gathering timed out"))??;
            Ok(())
        }
        .await;
        if let Err(err) = setup {
            state.close();
            return Err(err);
        }
        let stream = Self {
            pc,
            state,
            send_timeout: ms_timeout,
        };
        if cache {
            *stream
                .state
                .cache_key
                .lock()
                .unwrap_or_else(|e| e.into_inner()) = Some(key.clone());
            let existing = {
                let mut sessions = SESSIONS.lock().await;
                if *stream.state.status.borrow() == ChannelState::Closed {
                    return Err(Error::new(
                        ErrorKind::ConnectionAborted,
                        "WebRTC connection closed during setup",
                    )
                    .into());
                }
                if let Some(existing) = sessions.get(&key) {
                    Some(existing.clone())
                } else {
                    sessions.insert(key, stream.clone());
                    None
                }
            };
            if let Some(existing) = existing {
                stream.state.close();
                return Ok(existing);
            }
        }
        Ok(stream)
    }

    pub async fn get_local_endpoint(&self) -> ResultType<String> {
        let description = self
            .pc
            .local_description()
            .await
            .ok_or_else(|| anyhow::anyhow!("Local desc is not set"))?;
        Ok(Self::sdp_to_endpoint(&serde_json::to_string(&description)?))
    }

    pub async fn set_remote_endpoint(&self, endpoint: &str) -> ResultType<()> {
        self.pc
            .set_remote_description(serde_json::from_str(&Self::get_remote_offer(endpoint)?)?)
            .await?;
        Ok(())
    }

    pub fn set_raw(&mut self) {}

    pub fn local_addr(&self) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }

    pub fn set_send_timeout(&mut self, ms: u64) {
        self.send_timeout = ms;
    }

    pub fn set_key(&mut self, _key: Key) {}

    pub fn is_secured(&self) -> bool {
        true
    }

    pub async fn send(&mut self, message: &impl Message) -> ResultType<()> {
        self.send_raw(message.write_to_bytes()?).await
    }

    pub async fn send_raw(&mut self, message: Vec<u8>) -> ResultType<()> {
        self.send_bytes(Bytes::from(message)).await
    }

    pub async fn send_bytes(&mut self, bytes: Bytes) -> ResultType<()> {
        if bytes.is_empty() || bytes.len() > DATA_CHANNEL_BUFFER_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "WebRTC message exceeds supported size",
            )
            .into());
        }
        let sending = async {
            self.state.wait_connected().await?;
            let channel = self
                .state
                .channel
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotConnected,
                        "WebRTC data channel is not available",
                    )
                })?;
            channel.send(BytesMut::from(bytes.as_ref())).await?;
            Ok(())
        };
        let result = if self.send_timeout == 0 {
            sending.await
        } else {
            match timeout(Duration::from_millis(self.send_timeout), sending).await {
                Ok(result) => result,
                Err(_) => {
                    self.state.close();
                    Err(Error::new(ErrorKind::TimedOut, "WebRTC send timed out").into())
                }
            }
        };
        if result.is_err() {
            self.state.close();
        }
        result
    }

    pub async fn next(&mut self) -> Option<Result<BytesMut, Error>> {
        loop {
            let notified = self.state.incoming_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let message = self
                .state
                .incoming
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pop_front();
            if let Some((_permit, message)) = message {
                return Some(Ok(message));
            }
            if *self.state.status.borrow() == ChannelState::Closed {
                return Some(Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "WebRTC data channel closed",
                )));
            }
            notified.await;
        }
    }

    pub async fn next_timeout(&mut self, ms: u64) -> Option<Result<BytesMut, Error>> {
        timeout(Duration::from_millis(ms), self.next())
            .await
            .ok()
            .flatten()
    }
}

pub fn is_webrtc_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("webrtc://")
}

#[cfg(test)]
mod tests {
    use crate::webrtc::WebRTCStream;
    use crate::webrtc::DEFAULT_ICE_SERVERS;
    use webrtc::peer_connection::RTCSessionDescription;

    #[test]
    fn test_webrtc_ice_url() {
        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://example.com:3478")
                .unwrap_or_default()
                .urls[0],
            "turn:example.com:3478"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://example.com")
                .unwrap_or_default()
                .urls[0],
            "turn:example.com:3478"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://123@example.com")
                .unwrap_or_default()
                .username,
            "123"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://123@example.com")
                .unwrap_or_default()
                .credential,
            ""
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("turn://123:321@example.com")
                .unwrap_or_default()
                .credential,
            "321"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("stun://example.com:3478")
                .unwrap_or_default()
                .urls[0],
            "stun:example.com:3478"
        );

        assert_eq!(
            WebRTCStream::get_ice_server_from_url("http://123:123@example.com:3478"),
            None
        );

        assert_eq!(
            WebRTCStream::parse_ice_servers("")[0].urls[0],
            DEFAULT_ICE_SERVERS[0].to_string()
        );

        let servers = WebRTCStream::parse_ice_servers(",stun://example.com,turn://example.com,sdf");
        assert_eq!(servers[0].urls[0], "stun:example.com:3478");
        assert_eq!(servers[1].urls[0], "turn:example.com:3478");
        assert_eq!(servers.len(), 2);
    }

    #[test]
    fn test_webrtc_session_key() {
        let mut sdp_str = "".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            )
            .unwrap_or_default(),
            ""
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=fingerprint:sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88
a=group:BUNDLE 0
a=extmap-allow-mixed
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            ).unwrap_or_default(),
            "sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88"
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=fingerprint:sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            ).unwrap_or_default(),
            "sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88"
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT"
            .to_owned();
        assert!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            )
            .is_err(),
            "can not find fingerprint attribute"
        );

        sdp_str = "\
v=0
o=- 7400546379179479477 208696200 IN IP4 0.0.0.0
s=-
t=0 0
a=group:BUNDLE 0
a=extmap-allow-mixed
m=audio 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=fingerprint:sha-256 97:52:D6:1F:1E:87:6C:DA:B8:21:95:64:A5:85:89:FA:02:71:C7:4D:B3:FD:25:92:40:FB:6B:65:24:3C:79:88
a=setup:actpass
a=mid:0
a=sendrecv
a=sctp-port:5000
a=ice-ufrag:RMWjjpXfpXbDPdMz
a=ice-pwd:BtIqlWHfwhsJdFiBROeLuEbNmYfHxRfT".to_owned();
        assert!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer(sdp_str).unwrap_or_default()
            )
            .is_err(),
            "can not find datachannel fingerprint attribute"
        );

        assert!(
            WebRTCStream::get_key_for_sdp(
                &RTCSessionDescription::offer("".to_owned()).unwrap_or_default()
            )
            .is_err(),
            "invalid sdp should error"
        );

        assert!(
            WebRTCStream::get_key_for_sdp_json("{}").is_err(),
            "empty sdp json should error"
        );

        assert!(
            WebRTCStream::get_key_for_sdp_json("{ss}").is_err(),
            "invalid sdp json should error"
        );

        let endpoint = "webrtc://eyJ0eXBlIjoiYW5zd2VyIiwic2RwIjoidj0wXHJcbm89LSA0MTA1NDk3NTY2NDgyMTQzODEwIDYwMzk1NzQw\
MCBJTiBJUDQgMC4wLjAuMFxyXG5zPS1cclxudD0wIDBcclxuYT1maW5nZXJwcmludDpzaGEtMjU2IDYxOjYwOjc0OjQwOjI4OkNFOjBCOjBDOjc1OjRCOj\
EwOjlBOkVFOjc3OkY1OjQ0OjU3Ojg0OjUxOkRCOjA0OjkyOjRBOjEwOjFDOjRFOjVGOjdFOkYxOkIzOjcxOjIyXHJcbmE9Z3JvdXA6QlVORExFIDBcclxu\
YT1leHRtYXAtYWxsb3ctbWl4ZWRcclxubT1hcHBsaWNhdGlvbiA5IFVEUC9EVExTL1NDVFAgd2VicnRjLWRhdGFjaGFubmVsXHJcbmM9SU4gSVA0IDAuMC\
4wLjBcclxuYT1zZXR1cDphY3RpdmVcclxuYT1taWQ6MFxyXG5hPXNlbmRyZWN2XHJcbmE9c2N0cC1wb3J0OjUwMDBcclxuYT1pY2UtdWZyYWc6SHlnU1Rr\
V2RsRlpHRG1XWlxyXG5hPWljZS1wd2Q6SkJneFZWaGZveVhHdHZha1VWcnBQeHVOSVpMU3llS1pcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDEgdWRwID\
IxMzA3MDY0MzEgMTkyLjE2OC4xLjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDIgdWRwIDIxMzA3MDY0MzEgMTkyLjE2OC4x\
LjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6MTg2MTA0NTE5MCAxIHVkcCAxNjk0NDk4ODE1IDE0LjIxMi42OC4xMiAyNzAwNCB0eXAgc3JmbH\
ggcmFkZHIgMC4wLjAuMCBycG9ydCA2NDAwOFxyXG5hPWNhbmRpZGF0ZToxODYxMDQ1MTkwIDIgdWRwIDE2OTQ0OTg4MTUgMTQuMjEyLjY4LjEyIDI3MDA0\
IHR5cCBzcmZseCByYWRkciAwLjAuMC4wIHJwb3J0IDY0MDA4XHJcbmE9ZW5kLW9mLWNhbmRpZGF0ZXNcclxuIn0=".to_owned();
        assert_eq!(
            WebRTCStream::get_key_for_sdp_json(
                &WebRTCStream::get_remote_offer(&endpoint).unwrap_or_default()
            ).unwrap_or_default(),
            "sha-256 61:60:74:40:28:CE:0B:0C:75:4B:10:9A:EE:77:F5:44:57:84:51:DB:04:92:4A:10:1C:4E:5F:7E:F1:B3:71:22"
        );
    }

    #[tokio::test]
    async fn test_webrtc_new_stream() {
        let mut endpoint = "webrtc://sdfsdf".to_owned();
        assert!(
            WebRTCStream::create(&endpoint, false, 10000, Vec::new(), true, false)
                .await
                .is_err(),
            "invalid webrtc endpoint should error"
        );

        endpoint = "wss://sdfsdf".to_owned();
        assert!(
            WebRTCStream::new(&endpoint, false, 10000).await.is_err(),
            "invalid webrtc endpoint should error"
        );

        assert!(
            WebRTCStream::create("", false, 10000, Vec::new(), true, false)
                .await
                .is_ok(),
            "local webrtc endpoint should ok"
        );

        endpoint = "webrtc://eyJ0eXBlIjoiYW5zd2VyIiwic2RwIjoidj0wXHJcbm89LSA0MTA1NDk3NTY2NDgyMTQzODEwIDYwMzk1NzQw\
MCBJTiBJUDQgMC4wLjAuMFxyXG5zPS1cclxudD0wIDBcclxuYT1maW5nZXJwcmludDpzaGEtMjU2IDYxOjYwOjc0OjQwOjI4OkNFOjBCOjBDOjc1OjRCOj\
EwOjlBOkVFOjc3OkY1OjQ0OjU3Ojg0OjUxOkRCOjA0OjkyOjRBOjEwOjFDOjRFOjVGOjdFOkYxOkIzOjcxOjIyXHJcbmE9Z3JvdXA6QlVORExFIDBcclxu\
YT1leHRtYXAtYWxsb3ctbWl4ZWRcclxubT1hcHBsaWNhdGlvbiA5IFVEUC9EVExTL1NDVFAgd2VicnRjLWRhdGFjaGFubmVsXHJcbmM9SU4gSVA0IDAuMC\
4wLjBcclxuYT1zZXR1cDphY3RpdmVcclxuYT1taWQ6MFxyXG5hPXNlbmRyZWN2XHJcbmE9c2N0cC1wb3J0OjUwMDBcclxuYT1pY2UtdWZyYWc6SHlnU1Rr\
V2RsRlpHRG1XWlxyXG5hPWljZS1wd2Q6SkJneFZWaGZveVhHdHZha1VWcnBQeHVOSVpMU3llS1pcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDEgdWRwID\
IxMzA3MDY0MzEgMTkyLjE2OC4xLjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6OTYzOTg4MzQ4IDIgdWRwIDIxMzA3MDY0MzEgMTkyLjE2OC4x\
LjIgNjQwMDcgdHlwIGhvc3RcclxuYT1jYW5kaWRhdGU6MTg2MTA0NTE5MCAxIHVkcCAxNjk0NDk4ODE1IDE0LjIxMi42OC4xMiAyNzAwNCB0eXAgc3JmbH\
ggcmFkZHIgMC4wLjAuMCBycG9ydCA2NDAwOFxyXG5hPWNhbmRpZGF0ZToxODYxMDQ1MTkwIDIgdWRwIDE2OTQ0OTg4MTUgMTQuMjEyLjY4LjEyIDI3MDA0\
IHR5cCBzcmZseCByYWRkciAwLjAuMC4wIHJwb3J0IDY0MDA4XHJcbmE9ZW5kLW9mLWNhbmRpZGF0ZXNcclxuIn0=".to_owned();
        assert!(
            WebRTCStream::new(&endpoint, false, 10000).await.is_err(),
            "connect to an 'answer' webrtc endpoint should error"
        );
    }
}

#[cfg(test)]
mod security_regressions {
    use super::*;

    async fn offer(timeout_ms: u64) -> WebRTCStream {
        WebRTCStream::create("", false, timeout_ms, Vec::new(), true, false)
            .await
            .expect("Create an isolated localhost offer")
    }

    async fn pair() -> (WebRTCStream, WebRTCStream) {
        let first = offer(5_000).await;
        let second = WebRTCStream::create(
            &first.get_local_endpoint().await.unwrap(),
            false,
            5_000,
            Vec::new(),
            true,
            false,
        )
        .await
        .expect("Create an isolated localhost answer");
        first
            .set_remote_endpoint(&second.get_local_endpoint().await.unwrap())
            .await
            .unwrap();
        (first, second)
    }

    #[test]
    fn rejects_invalid_and_oversized_endpoints() {
        assert!(WebRTCStream::get_remote_offer("https://example.invalid").is_err());
        assert!(WebRTCStream::get_remote_offer("webrtc://!!!!").is_err());
        assert!(WebRTCStream::get_remote_offer(&format!(
            "webrtc://{}",
            "A".repeat(MAX_SDP_SIZE * 4 / 3 + 5)
        ))
        .is_err());
    }

    #[tokio::test]
    async fn exchanges_binary_messages_and_preserves_order() {
        timeout(Duration::from_secs(30), async {
            let (mut first, mut second) = pair().await;
            let payload: Vec<_> = (0..DATA_CHANNEL_BUFFER_SIZE).map(|n| n as u8).collect();
            first.send_raw(payload.clone()).await.unwrap();
            assert_eq!(second.next_timeout(5_000).await.unwrap().unwrap(), payload);
            second.send_raw(b"reply".to_vec()).await.unwrap();
            assert_eq!(
                &first.next_timeout(5_000).await.unwrap().unwrap()[..],
                b"reply"
            );
            assert!(first.send_raw(Vec::new()).await.is_err());
            assert!(first
                .send_raw(vec![0; DATA_CHANNEL_BUFFER_SIZE + 1])
                .await
                .is_err());
            first.state.close();
            second.state.close();
        })
        .await
        .expect("Local binary exchange must be bounded");
    }

    #[tokio::test]
    async fn receive_queue_is_bounded_and_resumes_without_losing_messages() {
        timeout(Duration::from_secs(30), async {
            let (mut first, mut second) = pair().await;
            for sequence in 0u32..64 {
                first
                    .send_raw(sequence.to_be_bytes().to_vec())
                    .await
                    .unwrap();
            }
            timeout(Duration::from_secs(5), async {
                while second.state.incoming.lock().unwrap().len() != RECEIVE_QUEUE_CAPACITY {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("The queue should apply backpressure");
            assert_eq!(
                second.state.incoming.lock().unwrap().len(),
                RECEIVE_QUEUE_CAPACITY
            );
            for sequence in 0u32..64 {
                let received = second.next_timeout(5_000).await.unwrap().unwrap();
                assert_eq!(&received[..], &sequence.to_be_bytes());
            }
            first.state.close();
            second.state.close();
        })
        .await
        .expect("Bounded receive queue must resume");
    }

    #[tokio::test]
    async fn send_deadline_closes_an_unanswered_connection() {
        let mut stream = offer(5_000).await;
        stream.set_send_timeout(50);
        let error = timeout(Duration::from_secs(2), stream.send_raw(vec![1]))
            .await
            .expect("Sending must respect its deadline")
            .expect_err("No answer means no authenticated data channel");
        assert_eq!(
            error.downcast_ref::<Error>().unwrap().kind(),
            ErrorKind::TimedOut
        );
        assert!(*stream.state.status.borrow() == ChannelState::Closed);
    }

    #[tokio::test]
    async fn closing_a_connection_wakes_a_waiting_reader() {
        let stream = offer(5_000).await;
        let mut reader = stream.clone();
        let waiting = tokio::spawn(async move { reader.next().await });
        tokio::task::yield_now().await;
        stream.state.close();
        let result = timeout(Duration::from_secs(2), waiting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result.unwrap().unwrap_err().kind(),
            ErrorKind::ConnectionAborted
        );
    }

    #[tokio::test]
    async fn tampered_dtls_fingerprint_cannot_deliver_data() {
        timeout(Duration::from_secs(20), async {
            let mut first = offer(5_000).await;
            let endpoint = first.get_local_endpoint().await.unwrap();
            let mut description: serde_json::Value =
                serde_json::from_str(&WebRTCStream::get_remote_offer(&endpoint).unwrap()).unwrap();
            let fingerprint = format!("a=fingerprint:sha-256 {}", vec!["00"; 32].join(":"));
            let sdp = description["sdp"]
                .as_str()
                .unwrap()
                .lines()
                .map(|line| {
                    if line.starts_with("a=fingerprint:") {
                        fingerprint.as_str()
                    } else {
                        line
                    }
                })
                .collect::<Vec<_>>()
                .join("\r\n")
                + "\r\n";
            description["sdp"] = sdp.into();
            let tampered = WebRTCStream::sdp_to_endpoint(&description.to_string());
            let mut second = WebRTCStream::create(&tampered, false, 5_000, Vec::new(), true, false)
                .await
                .unwrap();
            first
                .set_remote_endpoint(&second.get_local_endpoint().await.unwrap())
                .await
                .unwrap();
            first.set_send_timeout(1_000);
            assert!(first.send_raw(b"must not arrive".to_vec()).await.is_err());
            assert!(!matches!(second.next_timeout(200).await, Some(Ok(_))));
            first.state.close();
            second.state.close();
        })
        .await
        .expect("A failed fingerprint check must be bounded");
    }
}
