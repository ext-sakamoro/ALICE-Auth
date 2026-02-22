# Changelog

All notable changes to ALICE-Auth will be documented in this file.

## [0.4.0] - 2026-02-23

### Added
- `Identity` — Ed25519 keypair generation / seed recovery
- `AliceId` (32 B) / `AliceSig` (64 B) — transparent wrapper types
- `verify` / `verify32` / `ok` — signature verification helpers
- Challenge-response protocol: `Hello`, `Challenge`, `Response`, `AuthResult`, `Pending`
- `write_did` — `alice://did:ed25519:<hex>` DID formatting (84 B, no alloc)
- Fully unrolled hex encoder (`hex4` / `hex8` / `hex32`) — no loop, no branch
- C-ABI FFI exports (feature `ffi`): `aa_new`, `aa_id`, `aa_sign`, `aa_verify`, `aa_free`
- Bridge modules: `crypto_bridge`, `db_bridge`, `api_bridge`
- `serde` support for wire types (feature `serde`)
- PyO3 Python bindings (feature `pyo3`)
- `no_std` compatible core (zero alloc, zero panic in release)
- 28 unit tests

### Fixed
- Removed `panic = "abort"` from `[profile.dev]` to allow test harness unwinding
