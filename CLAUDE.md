# ALICE-Auth — Claude Code 設定

## プロジェクト概要

Ed25519 認証 + Schnorr NIZK (真ZKP) for ALICE

| 項目 | 値 |
|------|-----|
| クレート名 | `alice-auth` |
| バージョン | 0.5.0 |
| ライセンス | AGPL-3.0 |
| リポジトリ | `ext-sakamoro/ALICE-Auth` |
| デフォルト features | `["std"]` (no_std: `default-features = false`) |
| crate-type | `["lib"]` (cdylib: `cargo rustc --crate-type cdylib`) |
| テスト数 | 90 (default/std), 171 (all-features) |
| Eco-Systemブリッジ | `bridge_auth.rs` (8), `bridge_auth_ext.rs` (9) |
| Unity C# | `bindings/unity/AliceAuth.cs` (28 DllImport, 8クラス) |
| UE5 C++ | `bindings/ue5/AliceAuth.h` (28 extern C, 8クラス RAII) |

## Feature Flags

| Feature | 依存 | 内容 |
|---------|------|------|
| `std` | `alloc`, `getrandom/std` | 標準ライブラリ |
| `crypto` | `alice-crypto`, `std` | BLAKE3ハッシュ, XChaCha20暗号化, Shamir SSS, HD鍵導出 |
| `nizk` | `curve25519-dalek`, `crypto`, `std` | Schnorr NIZK証明（真ZKP） |
| `db` | `std` | 自己完結型BTreeMap監査ログ |
| `api` | `std` | APIミドルウェア, RBAC, セッション失効, 分散レート制限 |
| `ffi` | `std` | C-ABI FFI 28関数 (基本+NIZK+Endorsement+Rotation+Token+Revocation+RBAC+HD) |
| `pyo3` | `std` | Python 15関数+5クラス (基本+NIZK+Endorsement+Rotation+Token+Revocation+RBAC+HD) |
| `serde` | — | シリアライゼーション |

## コーディングルール

メインCLAUDE.md「Git Commit設定」参照。日本語コミット・コメント、署名禁止、作成者 `Moroya Sakamoto`。

## ALICE 品質基準

ALICE-KARIKARI.md「100/100品質基準」参照。clippy基準: `pedantic+nursery`

| 指標 | 値 |
|------|-----|
| clippy (pedantic+nursery) | 0 warnings |
| テスト数 | 171 (all-features lib) |
| fmt | clean |

## Eco-System パイプライン

本クレートはALICE-Eco-Systemの以下のパスで使用:
- Path J (DNS/API→Auth)
- Path T (Container→Auth→API→CDN)

## 情報更新ルール

- バージョンアップ時: このCLAUDE.mdのバージョンを更新
- APIの破壊的変更時: ALICE-Eco-Systemブリッジへの影響をメモ
- テスト数/品質の変化時: テスト数を更新
- 新feature追加時: Feature Flagsテーブルを更新
