# Changelog

All notable changes to ALICE-Auth will be documented in this file.

## [0.5.0] - 2026-03-04

### Added — Security Hardening (Round 1)
- `ct_eq()` — constant-time byte comparison for timing-attack resistance
- `RotatingIdentity` — key rotation with current + previous keypair grace period
- `TimedPending` / `make_timed_challenge` / `check_timed` — challenge TTL (default 30s)
- `Endorsement` / `endorse` / `verify_endorsement` / `verify_chain` — trust chain / PKI
- `RevocationList` — constant-time session token blacklist (api feature)
- `Permission` / `Role` / `PolicyEngine` — bitmask RBAC (api feature)
- Distributed rate limit state export/import/merge (api feature)
- `AuthDbStore` — self-contained BTreeMap audit log (removed alice-db dependency)

### Added — Cryptographic Strengthening (Round 2)
- `nizk` module — Schnorr NIZK proof with Fiat-Shamir transform (true ZKP)
  - `prove()` / `verify_proof()` / `SchnorrProof` (64 bytes, wire-compatible with AliceSig)
  - Uses `curve25519-dalek` Edwards point ops + BLAKE3 domain-separated challenge
- `split_seed()` / `recover_identity()` — Shamir SSS seed backup via ALICE-Crypto
- `derive_child()` — HD key derivation (BLAKE3 KDF, parent seed + index)
- `RecoveryConfig` / `approve_recovery` / `validate_recovery` — Social Recovery (guardian threshold)

### Added — 10/10 Hardening (Round 3)
- `nizk`: Security references (Schnorr '89, Fiat-Shamir '86, RFC 8235, Bellare-Neven batch)
- `nizk`: Batch weight wide reduction (consistency with nonce/challenge)
- `nizk`: Dual-KDF HKDF-Expand equivalence documentation
- `ct_eq_n<N>` — compile-time fixed-size constant-time comparison
- `Endorsement::expires_ms` — endorsement expiry field + verify/chain expiry check
- `RotatingIdentity` N-generation: `Vec<(Identity, u64)>` + `max_generations` + `previous_ids()`
- `RevocationList` — timestamped entries, `max_capacity`, `auto_purge(now_ms, ttl_ms)`
- `verify_request(req, now_ms)` — token expiry check in middleware
- `derive_session_key` — BLAKE3 hash normalization (no silent zero-padding)

### Added — FFI/PyO3 Extension (Round 4)
- FFI: `aa_endorse` / `aa_verify_endorsement` — C-ABI endorsement with expiry
- FFI: `aa_rotating_new` / `aa_rotating_rotate` / `aa_rotating_id` / `aa_rotating_verify` / `aa_rotating_free` — N-gen rotation
- FFI: `aa_token_create` / `aa_token_is_expired` — structured auth token
- FFI: `aa_revlist_new` / `aa_revlist_revoke` / `aa_revlist_is_revoked` / `aa_revlist_auto_purge` / `aa_revlist_free`
- FFI: `aa_policy_new` / `aa_policy_assign` / `aa_policy_check` / `aa_policy_free` — RBAC
- FFI: `aa_nizk_prove` / `aa_nizk_verify` — Schnorr NIZK (ffi+nizk)
- FFI: `aa_derive_child` / `aa_derive_session_key` — HD derivation (ffi+crypto)
- PyO3: `nizk_prove()` / `nizk_verify()` / `nizk_verify_batch()` — Schnorr NIZK
- PyO3: `endorse()` / `verify_endorsement()` — trust chain with expiry
- PyO3: `RotatingIdentity` class — N-generation key rotation
- PyO3: `RevocationList` class — constant-time token revocation + auto_purge
- PyO3: `PolicyEngine` class — RBAC role assignment + permission check
- PyO3: `token_create()` / `token_parse()` / `token_is_expired()` — auth token
- PyO3: `derive_child()` — HD key derivation
- Eco-System bridge: `auth_endorsement_to_cache_ttl` — endorsement expiry → Cache TTL
- Eco-System bridge: `auth_rotation_ngen_to_edge` — N-gen rotation → Edge device management
- Eco-System bridge: `auth_revocation_purge_to_analytics` — purge results → Analytics metrics
- Eco-System bridge: `auth_token_to_api_gateway` — token expiry → API Gateway TTL

### Changed
- `db` feature no longer depends on `alice-db` (self-contained BTreeMap store)
- Ed25519-dalek now uses `hazmat` feature for NIZK secret scalar extraction
- ZKP terminology clarified: default auth = Ed25519 challenge-response, `nizk` = formal Schnorr ZKP
- `endorse()` now takes `ttl_ms` parameter; `verify_endorsement()`/`verify_chain()` take `now_ms`
- `RevocationList::revoke()` now takes `now_ms` timestamp
- `verify_request()` now takes `now_ms` for expiry check
- `AuthDbStore::total_entries` synced with actual `store.len()` on insert
- `write_did` unsafe pointer arithmetic replaced with safe slice operations

### Stats
- 145 tests (50 → 101 → 124 → 137 → 145), 0 clippy warnings, 0 fmt diff

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
