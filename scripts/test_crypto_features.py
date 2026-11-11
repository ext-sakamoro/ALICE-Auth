#!/usr/bin/env python3
"""Tests of scripts/crypto_features.sh: its own guards.

A fake `cargo` first on PATH records each call's arguments and prints a canned test log,
so these tests check what the script asks cargo to do and how it reads the result, not
the build (cargo would fetch ALICE-Crypto; the fake does not, so these tests are offline).

- a log with no `nizk::` test, or no `crypto_bridge::` test, or no passed test at all,
  exits 1 naming what is missing;
- a good log exits 0, and cargo was asked for `test --locked` with every feature, then for
  `check --locked` of `crypto`, `nizk` and `pyo3` each on its own (a feature that does not
  enable what its code uses fails there), and of the wheel's feature set when it differs;
- a failing check of one feature fails the script;
- no `[tool.maturin] features` in pyproject.toml exits 2 before anything is built;
- a failing `cargo test` fails the script even when the log still has enough passed tests,
  and the `pyo3` check is not run;
- the commit comes from the committed Cargo.lock: alice-crypto by git on the public repository's https
  URL with `branch = "main"` in Cargo.toml, and exactly one alice-crypto from that branch in the lock;
  the old `.github/alice-crypto-pin` and `.github/alice-siblings` are gone and not read;
- alice-crypto by path, by rev or tag, on another branch or none, from another URL, without a version,
  or missing, and a lock without it, with it from a rev or with two of it, exit 2 before cargo runs.

usage: python3 scripts/test_crypto_features.py
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "crypto_features.sh"
URL = "https://github.com/ext-sakamoro/ALICE-Crypto"
# the ALICE-Crypto commit the repository's lock resolves, read here without the script under test
SIBLING_SHA = next(re.fullmatch(r".*#([0-9a-f]{40})", p["source"]).group(1)
                   for p in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"] if p["name"] == "alice-crypto")
assert re.fullmatch(r"[0-9a-f]{40}", SIBLING_SHA), SIBLING_SHA


def manifest(dep: str | None) -> str:
    """a Cargo.toml whose alice-crypto dependency is the inline table `dep` (none when None)"""
    body = '[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies]\n'
    if dep is not None:
        body += f"alice-crypto = {{ {dep} }}\n"
    return body


GOOD = f'git = "{URL}", branch = "main", version = "0.7", optional = true'


def lock(*sources: str) -> str:
    """a Cargo.lock with one alice-crypto package per source"""
    return "version = 4\n\n" + "".join(
        f'[[package]]\nname = "alice-crypto"\nversion = "0.7.0"\nsource = "{src}"\n\n' for src in sources)


MAIN = f"git+{URL}?branch=main#{SIBLING_SHA}"

FAKE_CARGO = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_CARGO_ARGV"
if [[ "$1" == "test" ]]; then cat "$FAKE_CARGO_LOG"; exit "${FAKE_CARGO_RC:-0}"; fi
if [[ "$1" == "check" && "${@: -1}" == "${FAKE_CHECK_FAIL:-}" ]]; then exit 101; fi
exit 0
"""

NIZK = "test nizk::tests::proof_round_trips ... ok\n"
BRIDGE = "test crypto_bridge::tests::seal_round_trips ... ok\n"
OTHER = "test api_bridge::tests::revoke_basic ... ok\n"


def result(n: int) -> str:
    return f"test result: ok. {n} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"


def git(*args: str, cwd: Path) -> None:
    subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                   check=True, capture_output=True)


class CryptoFeatures(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="crypto-features-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.r = self.tmp / "r"
        (self.r / "scripts").mkdir(parents=True)
        (self.r / ".github").mkdir()
        shutil.copy(SCRIPT, self.r / "scripts" / "crypto_features.sh")
        (self.r / "Cargo.toml").write_text(manifest(GOOD))
        (self.r / "Cargo.lock").write_text(lock(MAIN))
        self.write_wheel_features('["pyo3"]')
        git("init", "-q", "-b", "main", cwd=self.r)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "cargo").write_text(FAKE_CARGO)
        (bin_dir / "cargo").chmod(0o755)
        self.argv = self.tmp / "argv"
        self.log = self.tmp / "log"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env["PATH"] = f"{bin_dir}{os.pathsep}{self.env['PATH']}"
        self.env["FAKE_CARGO_ARGV"] = str(self.argv)
        self.env["FAKE_CARGO_LOG"] = str(self.log)
        self.env["CARGO_TARGET_DIR"] = str(self.tmp / "target")

    def write_wheel_features(self, features: str | None) -> None:
        body = '[build-system]\nrequires = ["maturin>=1.0,<2.0"]\n'
        if features is not None:
            body += f"\n[tool.maturin]\nfeatures = {features}\n"
        (self.r / "pyproject.toml").write_text(body)

    def run_script(self, log: str) -> subprocess.CompletedProcess:
        self.log.write_text(log)
        git("add", "-A", cwd=self.r)
        git("commit", "-q", "--allow-empty", "-m", "c", cwd=self.r)
        return subprocess.run(["bash", "scripts/crypto_features.sh"], cwd=self.r, capture_output=True, text=True,
                              env=self.env, timeout=300)

    def calls(self) -> list[str]:
        return self.argv.read_text().splitlines() if self.argv.exists() else []

    def test_no_nizk_test_fails_naming_nizk(self) -> None:
        p = self.run_script(BRIDGE + OTHER + result(2))
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("nizk 0", p.stderr)

    def test_no_crypto_bridge_test_fails_naming_it(self) -> None:
        p = self.run_script(NIZK + OTHER + result(2))
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("crypto_bridge 0", p.stderr)

    def test_no_passed_test_fails(self) -> None:
        p = self.run_script(NIZK + BRIDGE)
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("passed 0", p.stderr)

    def test_a_good_log_passes_and_cargo_was_asked_for_every_feature_locked(self) -> None:
        p = self.run_script(NIZK + BRIDGE + OTHER + result(3))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn(f"ALICE-Crypto at {SIBLING_SHA} (git)", p.stdout)
        self.assertIn("3 passed (1 nizk::, 1 crypto_bridge::)", p.stdout)
        self.assertEqual(self.calls(), [
            "test --locked --features std,api,ffi,crypto,nizk",
            "check --locked --lib --features crypto",
            "check --locked --lib --features nizk",
            "check --locked --lib --features pyo3",
        ])
        self.assertIn("checked 3 feature set(s)", p.stdout)

    def test_a_wheel_feature_set_of_its_own_is_checked_too(self) -> None:
        self.write_wheel_features('["pyo3", "serde"]')
        p = self.run_script(NIZK + BRIDGE + OTHER + result(3))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.calls()[1:], [
            "check --locked --lib --features crypto",
            "check --locked --lib --features nizk",
            "check --locked --lib --features pyo3",
            "check --locked --lib --features pyo3,serde",
        ])

    def test_a_feature_that_fails_alone_fails_the_script(self) -> None:
        for feature in ("crypto", "nizk", "pyo3"):
            with self.subTest(feature=feature):
                self.env["FAKE_CHECK_FAIL"] = feature
                p = self.run_script(NIZK + BRIDGE + OTHER + result(3))
                self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
                self.assertNotIn("checked 3", p.stdout)
                self.argv.unlink()

    def test_no_wheel_feature_set_exits_2_before_building(self) -> None:
        for features in (None, "[]"):
            with self.subTest(features=features):
                self.write_wheel_features(features)
                p = self.run_script(NIZK + BRIDGE + OTHER + result(3))
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("needs [tool.maturin] features", p.stderr)
                self.assertEqual(self.calls(), [])

    def test_a_failing_cargo_test_fails_the_script(self) -> None:
        self.env["FAKE_CARGO_RC"] = "101"
        log = (NIZK + BRIDGE + OTHER + result(3)
               + "test api_bridge::tests::broken ... FAILED\n"
               + "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n")
        p = self.run_script(log)
        self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertEqual(self.calls(), ["test --locked --features std,api,ffi,crypto,nizk"])
        self.assertNotIn("crypto features:", p.stdout)

    def test_alice_crypto_not_from_its_main_branch_exits_2(self) -> None:
        bad = {
            "path": 'path = "../ALICE-Crypto", version = "0.7"',
            "path and git": f'path = "../ALICE-Crypto", git = "{URL}", branch = "main", version = "0.7"',
            "rev": f'git = "{URL}", rev = "{SIBLING_SHA}", version = "0.7"',
            "branch and rev": f'git = "{URL}", branch = "main", rev = "{SIBLING_SHA}", version = "0.7"',
            "tag": f'git = "{URL}", tag = "v0.7.0", version = "0.7"',
            "other branch": f'git = "{URL}", branch = "dev", version = "0.7"',
            "no branch": f'git = "{URL}", version = "0.7"',
            "no version": f'git = "{URL}", branch = "main"',
            "other URL": f'git = "https://github.com/someone/ALICE-Crypto", branch = "main", version = "0.7"',
            "ssh URL": f'git = "ssh://git@github.com/ext-sakamoro/ALICE-Crypto", branch = "main", version = "0.7"',
            "missing": None,
        }
        for name, dep in bad.items():
            with self.subTest(name=name):
                (self.r / "Cargo.toml").write_text(manifest(dep))
                p = self.run_script(NIZK + BRIDGE + result(2))
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn('Cargo.toml: alice-crypto needs git = "https://github.com/ext-sakamoro/ALICE-Crypto" '
                              'and branch = "main"', p.stderr)
                self.assertEqual(self.calls(), [])

    def test_a_lock_without_one_alice_crypto_from_main_exits_2(self) -> None:
        bad = {
            "none": lock(),
            "from a rev": lock(f"git+{URL}?rev={SIBLING_SHA}#{SIBLING_SHA}"),
            "from crates.io": lock("registry+https://github.com/rust-lang/crates.io-index"),
            "two": lock(MAIN, f"git+{URL}?rev={SIBLING_SHA}#{SIBLING_SHA}"),
            "short commit": lock(f"git+{URL}?branch=main#{SIBLING_SHA[:12]}"),
        }
        for name, text in bad.items():
            with self.subTest(name=name):
                (self.r / "Cargo.lock").write_text(text)
                p = self.run_script(NIZK + BRIDGE + result(2))
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertEqual(self.calls(), [])

    def test_the_old_pin_files_are_gone_and_not_read(self) -> None:
        self.assertFalse((ROOT / ".github" / "alice-crypto-pin").exists())
        self.assertFalse((ROOT / ".github" / "alice-siblings").exists())
        # well-formed old pins beside a path dependency: reading either old file would build
        (self.r / ".github" / "alice-crypto-pin").write_text("rev " + SIBLING_SHA + "\n")
        (self.r / ".github" / "alice-siblings").write_text("ALICE-Crypto " + SIBLING_SHA + "\n")
        (self.r / "Cargo.toml").write_text(manifest('path = "../ALICE-Crypto", version = "0.6"'))
        p = self.run_script(NIZK + BRIDGE + result(2))
        self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
        self.assertEqual(self.calls(), [])

    def test_the_commit_is_the_one_the_committed_lock_names(self) -> None:
        other = "0123456789abcdef0123456789abcdef01234567"
        (self.r / "Cargo.toml").write_text(
            '[package]\nname = "x"\nversion = "0.1.0"\n\n[dependencies.alice-crypto]\n'
            f'git = "{URL}"\nbranch = \'main\'\nversion = "0.7"\n')
        (self.r / "Cargo.lock").write_text(lock(f"git+{URL}?branch=main#{other}"))
        p = self.run_script(NIZK + BRIDGE + OTHER + result(3))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn(f"ALICE-Crypto at {other} (git)", p.stdout)

if __name__ == "__main__":
    unittest.main()
