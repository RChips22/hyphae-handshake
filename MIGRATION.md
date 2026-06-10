# Migration to V2 Handshake API

This release consolidates the handshake API for extensibility and future-proofing.

Key principle: **all public types are `#[non_exhaustive]`** — future releases can add
fields/variants without semver breaks. Construct them via `::new()` or `::default()`,
never with struct literals.

## V1 → V2 Breaking Changes

| V1 name | V2 name | Notes |
|---------|---------|-------|
| `HandshakeResultV1` | `HandshakeResult` | `#[non_exhaustive]`; use `HandshakeResult::new(...)` |
| `HandshakeApiError` | `HandshakeError` | `#[non_exhaustive]`; variants renamed (`KeyError` → `Key`, etc.) |
| `HandshakeOptions.expected_pattern` | removed | validation is now internal |
| `HandshakeOptions.allowed_patterns` | moved to `HandshakeBuilder::with_allowed_patterns()` | compile-time config |
| `HandshakeBuilder::with_max_msg1_payload_len()` | moved to `HandshakeOptions.max_payload_len` | runtime config |
| `QuinnHandshakeData::PeerIdentity` | removed | return type fixed to `HyphaePeerIdentity`; generic bounds simplified |

## V2 Types

### `HandshakeResult` (was `HandshakeResultV1`)
```rust
#[non_exhaustive]
pub struct HandshakeResult {
    pub handshake_hash: [u8; 32],
    pub peer_static: Option<[u8; 32]>,
    pub msg1_payload: Option<Vec<u8>>,
    pub negotiated_pattern: String,
}
```

### `HandshakeError` (was `HandshakeApiError`)
```rust
#[non_exhaustive]
pub enum HandshakeError {
    Pattern(String),
    Key(String),
    Io(String),
    Payload(String),
    Timeout,
    Crypto(String),
}
```

### `HandshakeOptions`
```rust
#[non_exhaustive]
pub struct HandshakeOptions {
    pub timeout: Duration,
    pub max_payload_len: usize,
    pub pinned_peer_key: Option<[u8; 32]>,
    pub handshake_hook: Option<Arc<dyn Fn(HandshakeStage) + Send + Sync>>,
    pub anti_downgrade_hook: Option<Arc<dyn Fn(&HandshakeResult) -> Result<(), HandshakeError> + Send + Sync>>,
}
```

### `HandshakeStage`
```rust
#[non_exhaustive]
pub enum HandshakeStage {
    ClientConnecting,
    ServerAccepted,
    ConnectionEstablished,
    HandshakeComplete,
}
```

## Entry Points (unchanged signatures, new types)

```rust
pub async fn client_connect(
    endpoint: &Endpoint,
    remote_addr: SocketAddr,
    server_name: &str,
    options: HandshakeOptions,
) -> Result<(Connection, HandshakeResult), HandshakeError>;

pub async fn server_accept(
    endpoint: &Endpoint,
    options: HandshakeOptions,
) -> Result<(Connection, HandshakeResult), HandshakeError>;
```

## Builder Changes

- `HandshakeBuilder::with_max_msg1_payload_len()` removed — use `HandshakeOptions::max_payload_len` instead.
- `HandshakeBuilder::with_allowed_patterns()` sets compile-time pattern whitelist.
- `HandshakeBuilder::with_rng_factory()` injects custom RNG.
- `QuinnHandshakeData` no longer has `PeerIdentity` associated type — `peer_identity()` always returns `Option<HyphaePeerIdentity>`.

## Architected for Replaceability

V2 types are designed so individual components can be upgraded or replaced
without touching the high-level API:

- **RNG**: `RngFactory` / `SecureRng` trait — swap `OsRng` for HSM, deterministic, etc.
- **Crypto**: `CryptoBackend` trait — plug in `ring`, `aws-lc-rs`, or custom backend.
- **Payload**: `PayloadDriver` trait — customize initiator/responder payloads.
- **Lifecycle**: `handshake_hook` callback — add metrics, tracing, without API break.
- **Errors**: `#[non_exhaustive]` enum — add new error categories without breaking `match`.
