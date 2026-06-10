# Compatibility Matrix

Baseline target: V1 single-pattern mode (`Noise_XX_25519_ChaChaPoly_BLAKE2s`)

| quinn-hyphae | quinn | quinn-proto | snow | rand | status |
| --- | --- | --- | --- | --- | --- |
| local workspace HEAD | 0.11.9 | 0.11.14 | 0.9.6 | 0.9.4 | PASS |

## Verification Commands

- `cargo check --workspace`
- `cargo test --workspace`
- `cargo audit`

## Notes

- This matrix is intentionally constrained to V1 single-pattern behavior to keep handshake hash semantics stable (`[u8; 32]`) and reduce downgrade surface area.
