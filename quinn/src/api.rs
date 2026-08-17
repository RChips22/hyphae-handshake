use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::time::timeout;

use crate::builder::V1_PATTERN;
use crate::customization::HyphaePeerIdentity;

// ── lifecycle stages ──────────────────────────────────────────

/// Non-sensitive stages of the handshake lifecycle.
///
/// Hooks receive these stages for observability and metrics.
/// The enum is `#[non_exhaustive]` — future releases may add new
/// stages without a semver break.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HandshakeStage {
    /// Client connect has been initiated.
    ClientConnecting,
    /// Server has accepted a new incoming connection.
    ServerAccepted,
    /// QUIC connection established, before extracting handshake result.
    ConnectionEstablished,
    /// Handshake result successfully extracted.
    HandshakeComplete,
}

// ── options ───────────────────────────────────────────────────

/// Runtime options for a single handshake.
///
/// Compile-time settings (allowed patterns, RNG factory, crypto
/// backend) belong on `HandshakeBuilder`.
///
/// This struct is `#[non_exhaustive]` — use `HandshakeOptions::new()`
/// or `Default` to construct, then override fields you need.
#[derive(Clone)]
#[non_exhaustive]
pub struct HandshakeOptions {
    /// Maximum time to wait for the handshake.
    /// Default: 10 seconds.
    pub timeout: Duration,

    /// Maximum size (bytes) of the initiator payload carried in
    /// Noise message 1. Payloads exceeding this limit are rejected
    /// with `HandshakeError::Payload`.
    /// Default: 4096.
    pub max_payload_len: usize,

    /// If set, the peer's static key must match this value exactly.
    /// Mismatch returns `HandshakeError::Key("peer key mismatch")`.
    /// Default: `None`.
    pub pinned_peer_key: Option<[u8; 32]>,

    /// Optional callback invoked at each lifecycle stage.
    /// Default: `None`.
    pub handshake_hook: Option<Arc<dyn Fn(HandshakeStage) + Send + Sync>>,

    /// Optional callback invoked after the handshake result is
    /// extracted but before it is returned. Return `Err(...)` to
    /// reject the connection.
    /// Default: `None`.
    pub anti_downgrade_hook:
        Option<Arc<dyn Fn(&HandshakeResult) -> Result<(), HandshakeError> + Send + Sync>>,
}

impl HandshakeOptions {
    /// Create options with all defaults.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for HandshakeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_payload_len: 4096,
            pinned_peer_key: None,
            handshake_hook: None,
            anti_downgrade_hook: None,
        }
    }
}

// ── result ────────────────────────────────────────────────────

/// Normalised result of a completed handshake.
///
/// Every field is either fixed-size or optional so that future
/// protocol versions can add data without breaking the struct
/// layout.
///
/// `#[non_exhaustive]` — construct via `HandshakeResult::new()`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HandshakeResult {
    /// Final Noise handshake hash (always 32 bytes for the
    /// hardened V1 profile).
    pub handshake_hash: [u8; 32],

    /// Peer's long-term static public key, if the Noise pattern
    /// authenticated the peer.
    pub peer_static: Option<[u8; 32]>,

    /// Payload carried in Noise message 1 (the initiator's first
    /// handshake message). `None` if the initiator sent an empty
    /// payload.
    pub msg1_payload: Option<Vec<u8>>,

    /// The Noise protocol string that was negotiated for this
    /// handshake.
    pub negotiated_pattern: String,
}

impl HandshakeResult {
    /// Create a handshake result.
    ///
    /// This constructor exists so the struct can remain
    /// `#[non_exhaustive]` — callers who construct results
    /// (e.g. in tests) should use this instead of struct literals.
    pub fn new(
        handshake_hash: [u8; 32],
        peer_static: Option<[u8; 32]>,
        msg1_payload: Option<Vec<u8>>,
        negotiated_pattern: String,
    ) -> Self {
        Self {
            handshake_hash,
            peer_static,
            msg1_payload,
            negotiated_pattern,
        }
    }
}

// ── errors ────────────────────────────────────────────────────

/// Layered handshake error.
///
/// Each variant carries a human-readable description. Callers can
/// match on the variant to decide recovery strategy.
///
/// `#[non_exhaustive]` — new error categories may be added.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HandshakeError {
    /// The requested or negotiated pattern is not allowed.
    Pattern(String),
    /// Key extraction or validation failed.
    Key(String),
    /// An I/O or transport-level error occurred.
    Io(String),
    /// Payload validation failed (e.g. too large).
    Payload(String),
    /// The handshake timed out.
    Timeout,
    /// A lower-level cryptographic error occurred.
    Crypto(String),
}

impl fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pattern(msg) => write!(f, "pattern: {msg}"),
            Self::Key(msg) => write!(f, "key: {msg}"),
            Self::Io(msg) => write!(f, "io: {msg}"),
            Self::Payload(msg) => write!(f, "payload: {msg}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Crypto(msg) => write!(f, "crypto: {msg}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

// ── public entry points ───────────────────────────────────────

/// Connect to a remote endpoint and complete a Hyphae handshake.
///
/// Returns the QUIC `Connection` and the normalised handshake
/// result. The connection is ready for stream use immediately.
pub async fn client_connect(
    endpoint: &Endpoint,
    remote_addr: SocketAddr,
    server_name: &str,
    options: HandshakeOptions,
) -> Result<(Connection, HandshakeResult), HandshakeError> {
    let connecting = endpoint
        .connect(remote_addr, server_name)
        .map_err(|e| HandshakeError::Io(e.to_string()))?;

    fire_hook(&options, HandshakeStage::ClientConnecting);

    let connection = timeout(options.timeout, connecting)
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .map_err(|e| HandshakeError::Io(e.to_string()))?;

    fire_hook(&options, HandshakeStage::ConnectionEstablished);

    let result = extract_result(&connection, &options)?;

    fire_hook(&options, HandshakeStage::HandshakeComplete);
    Ok((connection, result))
}

/// Accept an incoming connection and complete a Hyphae handshake.
///
/// Returns the QUIC `Connection` and the normalised handshake
/// result. The connection is ready for stream use immediately.
pub async fn server_accept(
    endpoint: &Endpoint,
    options: HandshakeOptions,
) -> Result<(Connection, HandshakeResult), HandshakeError> {
    let connection = timeout(options.timeout, async {
        let incoming = endpoint.accept().await.ok_or_else(|| {
            HandshakeError::Io("endpoint closed before incoming connection".to_owned())
        })?;

        fire_hook(&options, HandshakeStage::ServerAccepted);

        incoming
            .await
            .map_err(|e| HandshakeError::Io(e.to_string()))
    })
    .await
    .map_err(|_| HandshakeError::Timeout)??;

    fire_hook(&options, HandshakeStage::ConnectionEstablished);

    let result = extract_result(&connection, &options)?;

    fire_hook(&options, HandshakeStage::HandshakeComplete);
    Ok((connection, result))
}

// ── internal helpers ──────────────────────────────────────────

fn fire_hook(options: &HandshakeOptions, stage: HandshakeStage) {
    if let Some(hook) = options.handshake_hook.as_ref() {
        hook(stage);
    }
}

fn extract_result(
    connection: &Connection,
    options: &HandshakeOptions,
) -> Result<HandshakeResult, HandshakeError> {
    let peer_identity = connection
        .peer_identity()
        .ok_or_else(|| HandshakeError::Io("missing peer identity".to_owned()))?;

    let identity = peer_identity
        .downcast::<HyphaePeerIdentity>()
        .map_err(|_| HandshakeError::Io("unexpected peer identity type".to_owned()))?;

    let negotiated_pattern = if identity.negotiated_pattern.is_empty() {
        V1_PATTERN.to_owned()
    } else {
        identity.negotiated_pattern.clone()
    };

    let hash = identity
        .final_handshake_hash
        .as_ref()
        .ok_or_else(|| HandshakeError::Key("missing final handshake hash".to_owned()))?;
    if hash.len() != 32 {
        return Err(HandshakeError::Key(format!(
            "expected 32-byte handshake hash, got {} bytes",
            hash.len()
        )));
    }

    let mut handshake_hash = [0u8; 32];
    handshake_hash.copy_from_slice(hash.as_slice());

    let peer_static = match identity.remote_public.as_ref() {
        Some(raw) => {
            if raw.len() != 32 {
                return Err(HandshakeError::Key(format!(
                    "expected 32-byte peer static key, got {} bytes",
                    raw.len()
                )));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(raw.as_slice());
            Some(key)
        }
        None => None,
    };

    if let Some(pinned) = options.pinned_peer_key {
        match peer_static {
            Some(actual) if actual != pinned => {
                return Err(HandshakeError::Key("peer key mismatch".to_owned()));
            }
            None => {
                return Err(HandshakeError::Key(
                    "peer provides no static key for pinning".to_owned(),
                ));
            }
            _ => {}
        }
    }

    if let Some(msg1_payload) = identity.msg1_payload.as_ref() {
        if msg1_payload.len() > options.max_payload_len {
            return Err(HandshakeError::Payload(format!(
                "msg1 payload too large: {} > {}",
                msg1_payload.len(),
                options.max_payload_len
            )));
        }
    }

    let result = HandshakeResult::new(
        handshake_hash,
        peer_static,
        identity.msg1_payload.clone(),
        negotiated_pattern,
    );

    if let Some(anti_downgrade_hook) = options.anti_downgrade_hook.as_ref() {
        anti_downgrade_hook(&result)?;
    }

    Ok(result)
}
