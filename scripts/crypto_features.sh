#!/usr/bin/env bash
# scripts/crypto_features.sh — build and test the `crypto` / `nizk` features (and check
# each of `crypto`, `nizk`, `pyo3` on its own, and the Python wheel's feature set) against
# the real ALICE-Crypto, at the commit Cargo.toml takes it from.
#
# ALICE-Crypto is a git dependency: `git = "https://github.com/ext-sakamoro/ALICE-Crypto"` at a
# 40-hex `rev` (the rev is the pin; Cargo.lock records the same commit and `--locked` refuses a
# lock that differs). Anything else (a path, a branch, a tag, a short rev, another URL) exits 2
# before cargo runs, so the features are always built against the one commit the manifest names.
#
# It builds the committed tree (HEAD) in a temporary directory, so the result does not depend
# on uncommitted changes. `--locked` keeps Cargo.lock as committed.
#
# It fails when a test fails, when the requirement cannot be resolved, and when the run
# compared nothing: no test passed, or no test of `nizk::` or `crypto_bridge::` ran
# (a feature dropped from the list would otherwise pass with fewer tests). It then checks
# each of these features alone (a feature must enable what its code uses; the tests above
# enable them together, which would hide a missing one) and the feature set the Python
# wheel is built with (`[tool.maturin] features` in pyproject.toml). It exits 2 when it
# cannot know what to build (alice-crypto not taken by git at a 40-hex rev, no wheel feature set).
#
# usage: scripts/crypto_features.sh
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD

# the commit alice-crypto is taken at: git on the public repository's https URL, a 40-hex rev
rev=$(python3 - <<'PY'
import re
import tomllib
try:
    d = tomllib.load(open("Cargo.toml", "rb"))["dependencies"]["alice-crypto"]
except (OSError, KeyError, tomllib.TOMLDecodeError):
    d = None
ok = (isinstance(d, dict) and "path" not in d and not ({"branch", "tag"} & set(d))
      and d.get("git") == "https://github.com/ext-sakamoro/ALICE-Crypto"
      and isinstance(d.get("rev"), str) and re.fullmatch(r"[0-9a-f]{40}", d["rev"]))
print(d["rev"] if ok else "")
PY
)
if [[ -z "$rev" ]]; then
  echo "Cargo.toml: alice-crypto needs git = \"https://github.com/ext-sakamoro/ALICE-Crypto\" and a 40-hex rev" >&2
  exit 2
fi
# the feature set `maturin build` uses for the Python wheel
wheel=$(python3 - <<'PY'
import tomllib
try:
    f = tomllib.load(open("pyproject.toml", "rb"))["tool"]["maturin"]["features"]
except (OSError, KeyError, tomllib.TOMLDecodeError):
    f = []
print(",".join(x for x in f if isinstance(x, str)))
PY
)
if [[ -z "$wheel" ]]; then
  echo "pyproject.toml: needs [tool.maturin] features (the Python wheel's feature set)" >&2
  exit 2
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/ALICE-Auth"
git archive HEAD | tar -x -C "$tmp/ALICE-Auth"
echo "ALICE-Crypto at $rev (git)"

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

# each feature alone, then the wheel's set (once if it is one of them)
sets=(crypto nizk pyo3)
case " ${sets[*]} " in *" $wheel "*) ;; *) sets+=("$wheel") ;; esac
checked=0
for f in "${sets[@]}"; do
  cargo check --locked --lib --features "$f"
  checked=$((checked + 1))
done
echo "crypto features: checked $checked feature set(s) on their own (crypto, nizk, pyo3, wheel: $wheel)"
if [[ "$checked" -lt 3 ]]; then
  echo "crypto features: checked fewer than 3 feature sets ($checked)" >&2
  exit 1
fi
