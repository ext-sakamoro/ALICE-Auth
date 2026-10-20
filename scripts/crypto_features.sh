#!/usr/bin/env bash
# scripts/crypto_features.sh — build and test the `crypto` / `nizk` features (and check
# `pyo3`) against the real ALICE-Crypto, at the revision .github/alice-crypto-pin names.
#
# These features depend on the sibling path dependency `../ALICE-Crypto`. The other CI
# jobs replace it with an empty stub, so only this script compiles the code behind them
# and notices a requirement the sibling's real version no longer satisfies.
#
# It builds in a temporary layout: the committed tree (HEAD) as ALICE-Auth beside
# ALICE-Crypto fetched at the pinned revision, so the result does not depend on what
# sits next to this checkout. `--locked` keeps Cargo.lock as committed.
#
# It fails when a test fails, when the requirement cannot be resolved, and when the run
# compared nothing: no test passed, or no test of `nizk::` or `crypto_bridge::` ran
# (a feature dropped from the list would otherwise pass with fewer tests). It exits 2
# when it cannot know what to build (a malformed pin).
#
# usage: scripts/crypto_features.sh
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD

pin=.github/alice-crypto-pin
rev=$(awk '$1 == "rev" { print $2 }' "$pin")
if [[ ! "$rev" =~ ^[0-9a-f]{40}$ ]]; then
  echo "$pin: needs 'rev <40 hex>'" >&2
  exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/ALICE-Auth"
git archive HEAD | tar -x -C "$tmp/ALICE-Auth"
git init -q "$tmp/ALICE-Crypto"
git -C "$tmp/ALICE-Crypto" fetch -q --depth 1 https://github.com/ext-sakamoro/ALICE-Crypto "$rev"
git -C "$tmp/ALICE-Crypto" checkout -q FETCH_HEAD
echo "ALICE-Crypto at $rev: $(awk -F'"' '/^version/ { print $2; exit }' "$tmp/ALICE-Crypto/Cargo.toml")"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$root/target/crypto-features}"
cd "$tmp/ALICE-Auth"

features="std,api,ffi,crypto,nizk"
log="$tmp/test.log"
cargo test --locked --features "$features" 2>&1 | tee "$log"

passed=$(awk '/^test result: ok\./ { s += $4 } END { print s + 0 }' "$log")
nizk=$(grep -c '^test nizk::.* \.\.\. ok$' "$log" || true)
bridge=$(grep -c '^test crypto_bridge::.* \.\.\. ok$' "$log" || true)
echo "crypto features: $passed passed ($nizk nizk::, $bridge crypto_bridge::) with --features $features"
if [[ "$passed" -eq 0 || "$nizk" -eq 0 || "$bridge" -eq 0 ]]; then
  echo "crypto features: compared nothing for a feature (passed $passed, nizk $nizk, crypto_bridge $bridge)" >&2
  exit 1
fi

cargo check --locked --lib --features pyo3,api,nizk
