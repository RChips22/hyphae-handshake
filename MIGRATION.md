# Migration to V1 Handshake API

This release introduces a V1 constrained handshake surface with a single allowed pattern:

- `Noise_XX_25519_ChaChaPoly_BLAKE2s`

## Old -> New API

- Old client connect flow:
  - build endpoint/config manually
  - call `endpoint.connect(...).await?`
  - call `conn.peer_identity()` and downcast

- New client connect flow:
  - keep endpoint/config setup
  - call `client_connect(&endpoint, addr, server_name, options).await?`
  - receive `(Connection, HandshakeResultV1)`

- Old server accept flow:
  - call `endpoint.accept().await?.await?`
  - call `conn.peer_identity()` and downcast

- New server accept flow:
  - call `server_accept(&endpoint, options).await?`
  - receive `(Connection, HandshakeResultV1)`

## New Result + Options Types

- `HandshakeResultV1`
  - `handshake_hash: [u8; 32]`
  - `peer_static: Option<[u8; 32]>`
  - `msg1_payload: Option<Vec<u8>>`
  - `negotiated_pattern: String`

- `HandshakeOptions`
  - `timeout`
  - `max_payload_len`
  - `expected_pattern`
  - `anti_downgrade_hook`

## Error Mapping

New layered API errors use:

- `UnsupportedPattern`
- `PatternError`
- `KeyError`
- `IoError`
- `PayloadError`
- `Timeout`

## Builder Changes

- `HandshakeBuilder::new_v1()` is provided and recommended.
- `HandshakeBuilder::build(...)` rejects non-V1 patterns with `CryptoError::UnsupportedPattern`.
- `HandshakeBuilder::with_max_msg1_payload_len(...)` sets msg1 payload limits.
