# Changelog

All notable changes to ALICE-Auth will be documented in this file.

## [Unreleased]

### Changed
- **Breaking (挙動)** 署名の検証を strict にした: crate の全ての署名の検証が通る `verify` (と `verify32` / `ok`、challenge-response の `check`、JWT の `verify_jwt`、`RotatingIdentity::verify_any`、`verify_recovery_approval`、`verify_endorsement` / `verify_chain`、`AuthMiddleware::verify_request`、C ABI の `aa_verify` / `aa_verify_endorsement`、Python の `verify32`) は ed25519-dalek の `verify_strict` を使う small-order の公開鍵 (plain の Ed25519 の検証はその鍵の下で 1 つの署名を全ての message に対して受ける)、small-order の R、非正準に書いた small-order の鍵を拒む 試験 `tests/verify_strict.rs` (RFC 8032 section 7.1 TEST 1-3 を受ける、上の 3 通りを拒む、各入口から small-order の鍵が拒まれる、鍵を更新した後の以前の鍵の下でも small-order の R が拒まれる) fuzz target `fuzz_verify` は任意の message で small-order の鍵が拒まれることを確かめる 移行: small-order の鍵で作った署名は検証を通らなくなる (正しく生成した鍵の署名には影響しない)
- CI: feature `crypto` / `nizk` を本物の ALICE-Crypto で build して試験する job (`.github/workflows/crypto-features.yml`、`scripts/crypto_features.sh`) を足した 他の job は sibling を空の stub に置き換えるので、この 2 feature の code と `alice-crypto` の要求は以前はどの job でも compile されなかった `.github/alice-crypto-pin` の revision を取り、commit 済みの tree をその横に置いて `--locked` で試験し、`pyo3` を check する 要求が解決できない時・`nizk::` か `crypto_bridge::` の試験が 1 本も走らなかった時・pin が読めない時は失敗する 試験 `scripts/test_crypto_features.py` (偽の `cargo` で引数と出力を差し替え、件数の検査・`cargo test` の失敗が script の失敗になること・全 feature と `--locked` での呼び出し・`pyo3` の check・pin の形式を確かめる、検査を外す・`--locked` を外す・feature を外す・`pyo3` の行を消す・pipefail を外す・`tee` の失敗を無視する変異は失敗する) `src/**` / `Cargo.*` などが変わった push だけで走る `scripts/preflight.sh` でも走る
- **Breaking** `RevocationList` は容量に達しても取消を捨てない 以前は容量 (既定 10,000) に達すると最古の取消を消して新しい token を入れていたので、取消済の token が再び通っていた `revoke` は `Result<(), RevokeError>` を返し、満杯なら `RevokeError::Full { capacity }` で拒否して何も記録しない (既に取消済の token は満杯でも `Ok`) 取消が消えるのは明示の `purge` (値で) と `auto_purge` (経過時間で、token の最長寿命を渡す) だけ 試験 `tests/revocation_fail_closed.rs` (既定容量 + 1 件で 1 件目が取消のまま、満杯の拒否で list が変わらない、`auto_purge` は経過時間の境界どおり、C ABI の満杯と null) 変異 6 件 (最古を消す、満杯を黙って捨てる、`auto_purge` が経過時間を見ない 2 通り、C ABI が満杯と null を成功と返す) は失敗する
- **Breaking** C ABI: `aa_revlist_revoke` は `int32_t` を返す (`AA_REVLIST_OK` 0 / `AA_REVLIST_ERR_NULL` -1 / `AA_REVLIST_ERR_FULL` -2、失敗時は `aa_last_error` に理由) `aa_revlist_new_with_capacity` を追加 UE5 の `FAliceRevocationList::Revoke` は `[[nodiscard]] bool` を返し、Unity の `AliceRevocationList.Revoke` は満杯で `InvalidOperationException` を投げる (どちらも容量を取る constructor を追加) Python の `RevocationList.revoke` は満杯で `RuntimeError` を投げ、`RevocationList(capacity=...)` を受ける
- 移行: `revoke` の戻り値を確かめる (`Err` の時その token は取消されていない) 容量が足りない運用は `with_capacity` で広げるか、token の寿命で `auto_purge` を定期的に呼ぶ
- CI: 公開する text の検査 (`.github/workflows/public-text.yml`、`scripts/public_text.sh`) を足した ALICE-Law の `scripts/public_text_check.py` を `.github/public-text-pin` の revision で取り、SHA-256 を照らしてから、HEAD の全 file (path と本文) と push した commit (message・追加行・path) を検査する 比較 0 件と読めない pin / base は失敗 試験 `scripts/test_public_text.py` (読めない pin と base、置いた note link が tree でも commit message でも検出されること、置かない tree と commit が 0 件で通ること、新しい commit が無い時は commit を読まないこと、SHA-256 が pin と違えば exit 2、pin の revision を取ること) `scripts/preflight.sh` でも走る
- **License: `AGPL-3.0-or-later` → `AGPL-3.0-or-later OR LicenseRef-Commercial` (dual-licensed、2026-09-27)** AGPL 側の条件は変更なし (既存 AGPL 利用者への影響ゼロ)、商用という選択肢が追加されただけ SPDX が AGPL 単独だと cargo-deny / FOSSA / SBOM に「商用オプションなし」と見えるため宣言を dual に 変更点: SPDX / `LICENSE` → `LICENSE-AGPL` / `LICENSE-COMMERCIAL.md` (商用トリガー 6 条件 = クローズド製品・商用 SaaS・エッジ / ファームウェア配布・plugin 再配布・プラットフォーム NDA・保証、社内利用は AGPL 側で無償と明記) / README の選択肢表 商用窓口は法人 `contact@extoria.co.jp`
- 依存: optional の `alice-crypto` (feature `crypto` / `nizk`) の要求を `0.1` から `0.4` に上げた 以前の要求は公開中の 0.4.1 を受け取れなかった 0.4.1 で `crypto` / `nizk` / `pyo3` を build し、`crypto` / `nizk` を含む feature で試験が通ることを確かめた
- CI: `ci/**` の branch への push でも `ci.yml` を走らせる (main を進める前に同じ commit で CI の結果を得る)

### Fixed
- **FFI 28 関数の panic 隔離** (`ffi.rs` / `ffi_nizk.rs` / `ffi_crypto.rs`): 全 `extern "C"` の本体を `ffi_guard(sentinel, || ..)` で包み、panic は host を落とさず sentinel + `aa_last_error()` (新規、`aa_clear_last_error` / `aa_free_error_string` も) で通知 認可系 (`aa_verify*` / `aa_policy_check` = 0、`aa_token_is_expired` = 1、`aa_revlist_is_revoked` = **1 = revoked**) は panic 時 fail-closed `[profile.release] panic = "abort"` を撤去 (abort では `catch_unwind` が機能しない) release profile で guard test 通過

## [0.5.1] - 2026-09-17

### Fixed
- **release build が compile 不能だった** (0.5.0 は crates.io に release 不能のまま公開): `hex::hex4` / `hex8` が `#[cfg(debug_assertions)]` gate なのに `types.rs` が無条件 import (E0432) gate を撤去
- `Debug for AliceId / AliceSig` と `Display for AuthError` の release 側 silent no-op impl (何も出力しない) を撤去し、build profile に依らず同じ出力にする (release だけ `Debug` が空になる API 不整合の解消)
- CI に `cargo test --release` を追加 (debug しか build しない CI では上記が見えなかった)

## [Unreleased]

### Fixed
- **`ffi` feature 単独 (`--features std,ffi`) が compile 不能だった** — `src/ffi.rs` が `api_bridge::AuthToken` を無条件使用するのに `ffi = ["std"]` に `api` が無かった → `ffi = ["std", "api"]` (feature-powerset で検出)
- **library が `#[panic_handler]` を定義していた** (`cfg(not(std), not(test))`) — no_std consumer が自前の handler を持つと `duplicate lang item: panic_impl` で link 不能、削除 (最終 binary が提供、README no_std 節に明記)
- no_std build の unused import (`key_rotation` は全て `std` gate なので module / re-export ごと `std` gate)、pedantic 1 件

### Added
- `custom-rng` feature (`getrandom/custom`) — `getrandom` が非対応の bare-metal target 向け (README)
- `rust-version = "1.88"` (`slice::as_chunks`、`cargo +1.88 check` green / 1.87 red を実測) + `rust-toolchain.toml` に thumbv7em target
- `ci.yml`: fmt + actionlint のみ → test (default + `std,serde,ffi,db,api`) / clippy `--all-targets` pedantic `-D warnings` 2 variant / `no_std` job (host no-alloc / alloc / thumbv7em `custom-rng` + clippy) / `msrv` 1.88 / `feature-powerset` (std 固定 depth 2) / doc `-D warnings`、rust-cache

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
