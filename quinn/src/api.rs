use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use quinn::{Connection, Endpoint};
use tokio::time::timeout;

use crate::builder::{DEFAULT_MAX_MSG1_PAYLOAD_LEN, V1_PATTERN};
use crate::customization::HyphaePeerIdentity;

/// Non-sensitive stages of the handshake lifecycle.
#[derive(Debug, Clone)]
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

#[derive(Clone)]
pub struct HandshakeOptions {
    pub timeout: Duration,
    pub max_payload_len: usize,
    pub expected_pattern: &'static str,
    pub allowed_patterns: Vec<&'static str>,
    pub pinned_peer_key: Option<[u8; 32]>,
    pub handshake_hook: Option<Arc<dyn Fn(HandshakeStage) + Send + Sync>>,
    pub anti_downgrade_hook: Option<Arc<dyn Fn(&HandshakeResultV1) -> Result<(), HandshakeApiError> + Send + Sync>>,
}

impl Default for HandshakeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_payload_len: DEFAULT_MAX_MSG1_PAYLOAD_LEN,
            expected_pattern: V1_PATTERN,
            allowed_patterns: vec![V1_PATTERN],
            pinned_peer_key: None,
            handshake_hook: None,
            anti_downgrade_hook: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeResultV1 {
    pub handshake_hash: [u8; 32],
    pub peer_static: Option<[u8; 32]>,
    pub msg1_payload: Option<Vec<u8>>,
    pub negotiated_pattern: String,
}

#[derive(Debug, Clone)]
pub enum HandshakeApiError {
    UnsupportedPattern(String),
    PatternError(String),
    KeyError(String),
    IoError(String),
    PayloadError(String),
    Timeout,
    Crypto(String),
}

impl fmt::Display for HandshakeApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPattern(msg) => write!(f, "unsupported_pattern: {msg}"),
            Self::PatternError(msg) => write!(f, "pattern_error: {msg}"),
            Self::KeyError(msg) => write!(f, "key_error: {msg}"),
            Self::IoError(msg) => write!(f, "io_error: {msg}"),
            Self::PayloadError(msg) => write!(f, "payload_error: {msg}"),
            Self::Timeout => write!(f, "timeout"),
            Self::Crypto(msg) => write!(f, "crypto_error: {msg}"),
        }
    }
}

impl std::error::Error for HandshakeApiError {}

pub async fn client_connect(
    endpoint: &Endpoint,
    remote_addr: SocketAddr,
    server_name: &str,
    options: HandshakeOptions,
) -> Result<(Connection, HandshakeResultV1), HandshakeApiError> {
    validate_options(&options)?;

    fire_hook(&options, HandshakeStage::ClientConnecting);

    let connecting = endpoint
        .connect(remote_addr, server_name)
        .map_err(|e| HandshakeApiError::IoError(e.to_string()))?;

    let connection = timeout(options.timeout, connecting)
        .await
        .map_err(|_| HandshakeApiError::Timeout)?
        .map_err(|e| HandshakeApiError::IoError(e.to_string()))?;

    fire_hook(&options, HandshakeStage::ConnectionEstablished);

    let result = extract_handshake_result(&connection, &options)?;

    fire_hook(&options, HandshakeStage::HandshakeComplete);
    Ok((connection, result))
}

pub async fn server_accept(
    endpoint: &Endpoint,
    options: HandshakeOptions,
) -> Result<(Connection, HandshakeResultV1), HandshakeApiError> {
    validate_options(&options)?;

    let connection = timeout(options.timeout, async {
        let incoming = endpoint.accept().await.ok_or_else(|| {
            HandshakeApiError::IoError("endpoint closed before incoming connection".to_owned())
        })?;

        fire_hook(&options, HandshakeStage::ServerAccepted);

        incoming
            .await
            .map_err(|e| HandshakeApiError::IoError(e.to_string()))
    })
    .await
    .map_err(|_| HandshakeApiError::Timeout)??;

    fire_hook(&options, HandshakeStage::ConnectionEstablished);

    let result = extract_handshake_result(&connection, &options)?;

    fire_hook(&options, HandshakeStage::HandshakeComplete);
    Ok((connection, result))
}

fn fire_hook(options: &HandshakeOptions, stage: HandshakeStage) {
    if let Some(hook) = options.handshake_hook.as_ref() {
        hook(stage);
    }
}

fn validate_options(options: &HandshakeOptions) -> Result<(), HandshakeApiError> {
    if !options.allowed_patterns.contains(&options.expected_pattern) {
        return Err(HandshakeApiError::UnsupportedPattern(options.expected_pattern.to_owned()));
    }
    Ok(())
}

fn extract_handshake_result(
    connection: &Connection,
    options: &HandshakeOptions,
) -> Result<HandshakeResultV1, HandshakeApiError> {
    let peer_identity = connection
        .peer_identity()
        .ok_or_else(|| HandshakeApiError::IoError("missing peer identity".to_owned()))?;

    let identity = peer_identity
        .downcast::<HyphaePeerIdentity>()
        .map_err(|_| HandshakeApiError::IoError("unexpected peer identity type".to_owned()))?;

    let negotiated_pattern = if identity.negotiated_pattern.is_empty() {
        V1_PATTERN.to_owned()
    } else {
        identity.negotiated_pattern.clone()
    };

    if negotiated_pattern != options.expected_pattern {
        return Err(HandshakeApiError::PatternError(format!(
            "expected {}, got {}",
            options.expected_pattern, negotiated_pattern
        )));
    }

    let hash = identity
        .final_handshake_hash
        .as_ref()
        .ok_or_else(|| HandshakeApiError::KeyError("missing final handshake hash".to_owned()))?;
    if hash.len() != 32 {
        return Err(HandshakeApiError::KeyError(format!(
            "expected 32-byte handshake hash, got {} bytes",
            hash.len()
        )));
    }

    let mut handshake_hash = [0u8; 32];
    handshake_hash.copy_from_slice(hash.as_slice());

    let peer_static = match identity.remote_public.as_ref() {
        Some(raw) => {
            if raw.len() != 32 {
                return Err(HandshakeApiError::KeyError(format!(
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
                return Err(HandshakeApiError::KeyError("peer key mismatch".to_owned()));
            }
            None => {
                return Err(HandshakeApiError::KeyError("peer provides no static key for pinning".to_owned()));
            }
            _ => {}
        }
    }

    if let Some(msg1_payload) = identity.msg1_payload.as_ref() {
        if msg1_payload.len() > options.max_payload_len {
            return Err(HandshakeApiError::PayloadError(format!(
                "msg1 payload too large: {} > {}",
                msg1_payload.len(),
                options.max_payload_len
            )));
        }
    }

    let result = HandshakeResultV1 {
        handshake_hash,
        peer_static,
        msg1_payload: identity.msg1_payload.clone(),
        negotiated_pattern,
    };

    if let Some(anti_downgrade_hook) = options.anti_downgrade_hook.as_ref() {
        anti_downgrade_hook(&result)?;
    }

    Ok(result)
}
