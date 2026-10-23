# Changelog

All notable changes to ALICE-Auth will be documented in this file.

## [Unreleased]

### Added
- module `player`: game をまたいで使う player の id と鍵の更新の鎖 `PlayerId` は最初の鍵に tag (`alice-auth/player-id/v1/`) を付けた SHA-256 で、鍵を変えても変わらない 鍵の更新は離れる鍵が署名する `RotationLink` (173 byte、版の byte 1、little-endian、署名の対象は tag `alice-auth/rotate/v1////` と先頭 109 byte) で表し、`resolve_chain(最初の鍵, links)` が鎖を最初から確かめて今の鍵とそれが有効になった時刻を返す 署名は鎖が今いる鍵で strict に確かめ (link が名乗る鍵ではなく)、次に link が鎖を続けるか (同じ player、0 からの連番、前の link より後の時刻、前と違う鍵、small-order でない鍵、最初の鍵も同じ) を見る 鍵の重なる期間は無い (更新の後は以前の鍵は player の鍵ではない) 拒否の理由は `GrantError` (C ABI の code を固定、-1 から -14) 依存に `sha2 0.10` を足した (ed25519-dalek 経由で既に lock にあった版、lock に新しい crate は増えない) 試験 `tests/player_chain.rs` (期待値は crate の外の program で計算: Python の hashlib と RFC 8032 の参照 Ed25519)
- module `player`: game が player に与える `Grant` (201 byte、game の鍵が tag `alice-auth/grant/v1/////` と先頭 137 byte に署名、scope は game が意味を決める u64、`issued <= now < expires` で有効) と、その取消 `Revocation` (129 byte、grant の nonce と期限を持ち、grant を出した game だけが署名できる) と、検証側が持つ失効の集合 `RevocationSet` (容量は固定、満杯なら新しい取消を拒否して持っている取消は捨てない、取消が消えるのは `purge(now)` で grant の期限を過ぎた分だけ) 満杯で拒否された取消は効いていないので、その grant は呼び手が対処するまで有効 (`Full` は再試行でなく、より大きな集合へ移すか、その game の grant の受け付けを止める合図) 同じ game が nonce を使い回すと 1 つの取消が同じ nonce の grant 全てを止め、集合は渡された grant の期限のうち遅い方を持つ (使い回しは取消を長くするだけで短くしない) nonce を grant ごとに一意にする (16 byte の乱数) のは発行する game の務め `Grant::verify(期待する game, 鎖の終わり, now, 失効の集合)` は失効の集合を必ず取り、決まった順に確かめて最初に外れた理由を返す (署名 → game → 期間 (期限ちょうどは期限切れ) → player と今の鍵 (鍵が今のものになった時刻より前に出た grant も拒否) → 失効) 試験 `tests/player_grant.rs`

- C ABI: player の関数 13 本 (`aa_from_seed`、`aa_player_id_from_genesis`、`aa_rotation_link_issue`、`aa_player_chain_resolve`、`aa_grant_issue`、`aa_grant_verify`、`aa_revocation_issue`、`aa_revset_new` / `_add` / `_contains` / `_purge` / `_len` / `_free`) 戻り値は 0 か `GrantError::code` の負値、拒否の時は `aa_last_error` が関数を名指し、出力は成功の時だけ書く null の引数は -1 (`aa_revset_contains` は取消済みと読む) `aa_from_seed` は保存した 32 byte の seed から鍵を読み戻す (game の発行鍵を再起動の後も使うため、seed は秘密鍵そのもの) UE5 (`FAlicePlayer` / `FAliceRevocationSet` / `IdentityFromSeed`)、Unity (`AlicePlayer` / `AliceRevocationSet` / `AliceIdentity.FromSeed` / `AliceGrantResult`)、Python (`grant_issue` / `grant_verify` / `RevocationSet` / `GrantError` ほか) の包装を足した 試験 `tests/player_ffi.rs` (参照の byte 列と Rust の判定が C ABI でも同じ、拒否の code と出力の不変、null)
- README: FFI の関数の数 (28 → 45、変更の前から 32 あった)、Python・Unity・UE5 の数、試験の数を実数に直した

### Changed
- 依存: `alice-crypto` (feature `crypto`) を "0.4" から "0.5" に上げた (0.5.0 は `CipherError` を `#[non_exhaustive]` にし `InvalidKeyLength` を足した、この crate は `CipherError` を match しないので code は変わらない) CI の stub の版を 0.5.0、実物で試験する `.github/alice-crypto-pin` を 0.5.0 の revision にし、`Cargo.lock` を更新した (argon2 ほか 5 crate が lock に入る)
- **Breaking (挙動)** 期限の境界を crate 全体で 1 つにした: 期限 `exp` を持つものは `now < exp` の間だけ有効で、`now == exp` から期限切れ (排他) 判定は新しい `is_expired(now_ms, expires_ms)` (const fn) 1 つで、`AuthToken::is_expired`、`AuthMiddleware::verify_request` (構造化 token と旧形式の 8 byte)、`verify_endorsement` / `verify_chain`、`JwtClaims::is_expired`、`check_timed` (経過時間が ttl に達したら期限切れ)、rate limit の同期の報告、player の grant と失効の集合がすべてこれを呼ぶ C ABI の `aa_token_is_expired` / `aa_verify_endorsement`、UE5 / Unity / Python も同じ 以前は token・endorsement・timed challenge が `now == exp` を有効として受け (包含)、JWT と grant は拒んでいた (排他) 変わるのは境界の 1 ms だけで、型・C ABI・wire 形式は変わらない `ttl_ms = 0` の endorsement は一度も有効にならない 試験 `tests/expiry_convention.rs` (各経路で exp - 1 を受け exp と exp + 1 を拒む) 移行: 期限ちょうどの時刻に有効と見なしていた呼び出し側は 1 ms 早く切れる
- **Breaking** 公開の署名経路は予約接頭辞 `alice-auth/` (`RESERVED_PREFIX`、11 byte の ASCII) で始まる message に署名しない `Identity::sign` / `sign32`、`RotatingIdentity::sign`、challenge-response の `respond` は `Result<_, SignError>` を返し、message の先頭 (offset 0) の bytes が接頭辞と一致する時は `SignError::ReservedPrefix` で何も署名しない (大文字小文字の区別あり、正規化なし) この接頭辞は crate が自分で署名する形式の tag の先頭で、ホストに任意の bytes を署名させる鍵や、相手が選んだ challenge に答える鍵が、それらの形式に署名させられることを防ぐ C ABI の `aa_sign` は `int32_t` を返す (`AA_SIGN_OK` 0 / `AA_SIGN_ERR_NULL` -1 / `AA_SIGN_ERR_RESERVED` -2、失敗時は出力に書かず `aa_last_error` に理由) UE5 の `FAliceIdentity::Sign` は `[[nodiscard]] bool`、Unity の `Sign` は例外、Python の `sign` / `sign32` は `ValueError` endorsement・recovery の承認・JWT・player の tag 付きの形式 (id / 鍵の更新の鎖) の署名は crate 内部の経路で作る endorsement の署名対象は呼び出し側が選ぶ target で始まるので、`endorse` は接頭辞で始まる target を新しい `AuthError::E7` で拒み (C ABI は `AA_ENDORSE_ERR_RESERVED` -3、UE5 は false、Unity と Python は例外)、`verify_endorsement` は endorsed id が接頭辞で始まる endorsement を拒む (実在の鍵は当たらない) 試験 `tests/endorse_reserved_target.rs` 新しい `SignError` (`#[non_exhaustive]`) 試験 `tests/sign_reserved_prefix.rs` 移行: `sign` / `sign32` / `respond` の結果を `?` か `match` で受ける
- **Breaking** 分散した rate limit の同期を、合成した時刻でなく node ごとの件数で持つ `RateLimitState` は `expires_ms` (数えた request が影響しなくなる時刻) を持つ `import_rate_state(node, state, now_ms)` は `Result` を返し、その node の以前の報告を置き換える (同じ報告を 2 回入れても 2 倍にならない) 報告は自分の `expires_ms` まで数え、それより早くも遅くも外さない 件数が `max_remote_count` を超える報告と、`max_remote_nodes` を超える node からの報告は、何も保存せず拒み、その identity を報告の `expires_ms` まで上限超過として扱う (fail-closed、既存の報告は追い出さない) 上限は新しい `RateSyncConfig` (`AuthMiddleware::with_rate_sync`、0 と上限を超える値は作る時に拒む、既定は 10,000 件 / 64 node / 10 分) 報告の `expires_ms` は受け手が `now_ms + max_report_ttl_ms` までに抑えるので (保存する報告にも上限超過の保留にも同じ)、1 つの報告で identity を無期限に止めることはできない `merge_rate_states` は `Result` を返し、別の identity の混在・件数の桁あふれ・空を拒む `export_rate_state` は自分の request だけを数え、件数と期限は桁あふれせず飽和する 以前は合算が release で wrap して制限を数え落とし (debug は panic)、`import` は件数 (最大 u32::MAX) だけ時刻を確保していた 新しい `RateSyncError` 試験 `tests/rate_limit_sync.rs` 移行: `import_rate_state` に送り手の node id と現在時刻を渡し、結果を受ける `RateLimitState` に `expires_ms` を入れる
- **Breaking** `AuthToken::new` (const fn のまま)、`AuthMiddleware::create_auth_token`、`JwtClaims::with_iat` は `Result` を返す 期限 (`now_ms + ttl_ms` / `iat + ttl`) が `u64::MAX` を超える時は `AuthError::E6` 以前は release で wrap して期限が過去になっていた (debug は panic) C ABI の `aa_token_create` は `int32_t` を返す (`AA_TOKEN_OK` 0 / `AA_TOKEN_ERR_NULL` -1 / `AA_TOKEN_ERR_OVERFLOW` -2、失敗時は出力に書かず `aa_last_error` に理由) UE5 は `[[nodiscard]] bool`、Unity は例外、Python の `token_create` は `ValueError` 期限の境界は別の項目 (上) で統一した 試験 `tests/token_overflow.rs` 移行: `AuthToken::new(..)` / `.with_iat(..)` の結果を `?` か `match` で受ける
- **Breaking** `endorse` は `Result<Endorsement>` を返す `now_ms + ttl_ms` が `u64::MAX` を超える時は `AuthError::E6` (新しい code、桁あふれ) で何も署名しない 以前は release で wrap して期限が過去になり、発行した endorsement が即座に期限切れだった (debug は panic) C ABI の `aa_endorse` は `int32_t` を返す (`AA_ENDORSE_OK` 0 / `AA_ENDORSE_ERR_NULL` -1 / `AA_ENDORSE_ERR_OVERFLOW` -2、失敗時は出力に書かず `aa_last_error` に理由) UE5 の `FAliceEndorsement::Endorse` は `[[nodiscard]] bool`、Unity は例外、Python は `ValueError` `ttl_ms = 0` は `expires_ms == now_ms` で、期限の境界の統一 (上) により一度も通らない
- **Breaking** `AuthError` に `E6` を足し `#[non_exhaustive]` にした (以後の code の追加は破壊的にならない) 既存の E1-E5 の番号は変えていない (試験で固定) 試験 `tests/endorse_overflow.rs`
- 移行: `endorse(..)` の結果を `?` か `match` で受ける `AuthError` を網羅する `match` には `_` の腕を足す
- **Breaking (挙動)** `RotatingIdentity::verify_any(id, m, s)` (と C ABI の `aa_rotating_verify`、UE5 / Unity の `VerifyAny`、Python の `verify_any`) は `id` がこの identity の今の鍵か残している以前の鍵の時だけ、その鍵で strict に検証する 以前は渡された `id` で先に検証したので、別の鍵で正しく署名した (id, m, s) も通っていた 署名を作った世代と違う世代の `id` で検証した時の通り抜け (以前の世代へ順に試す) も無くした 試験 `tests/rotation_membership.rs` (別の鍵・追い出した世代・`clear_previous` 後の鍵・世代の取り違えを拒む、今の鍵と残っている以前の鍵は受ける、C ABI も同じ) 移行: 署名を作った世代の公開鍵を `id` に渡す
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
- `pyo3` feature 単独で compile できなかった (`src/python.rs` が `api_bridge` / `crypto_bridge` / `nizk` を使うのに、`pyo3` はそれらを有効にしていなかった) Python の wheel は `pyproject.toml` の `features = ["pyo3"]` で build するので、wheel の build も失敗していた `pyo3 = ["dep:pyo3", "std", "api", "nizk"]` にした (`nizk` は `crypto` を含む) CI: `scripts/crypto_features.sh` は `crypto` / `nizk` / `pyo3` を 1 つずつ単独で check し、`pyproject.toml` の `[tool.maturin] features` (wheel の feature) も check する (以前は `pyo3,api,nizk` を併せて check していたので欠けを隠していた) wheel の feature が無ければ何も build せず exit 2 試験 `scripts/test_crypto_features.py` (各 feature の単独 check、wheel の feature が別の時の追加の check、1 つの feature の失敗で script が失敗、wheel の feature が無い時の exit 2) `crypto-features.yml` は `pyproject.toml` の変更でも走る
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
