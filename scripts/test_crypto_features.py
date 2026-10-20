#!/usr/bin/env python3
"""Tests of scripts/crypto_features.sh: its own guards.

A fake `cargo` first on PATH records each call's arguments and prints a canned test log,
so these tests check what the script asks cargo to do and how it reads the result, not
the build. The script still fetches ALICE-Crypto at this repository's pin (network).

- a log with no `nizk::` test, or no `crypto_bridge::` test, or no passed test at all,
  exits 1 naming what is missing;
- a good log exits 0, and cargo was asked for `test --locked` with every feature and for
  the `pyo3` check with `--locked`;
- a malformed pin exits 2 before anything is fetched.

usage: python3 scripts/test_crypto_features.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "crypto_features.sh"

FAKE_CARGO = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$FAKE_CARGO_ARGV"
if [[ "$1" == "test" ]]; then cat "$FAKE_CARGO_LOG"; fi
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
        shutil.copy(ROOT / ".github" / "alice-crypto-pin", self.r / ".github" / "alice-crypto-pin")
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

    def run_script(self, log: str) -> subprocess.CompletedProcess:
        self.log.write_text(log)
        git("add", "-A", cwd=self.r)
        git("commit", "-qm", "c", cwd=self.r)
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
        self.assertIn("3 passed (1 nizk::, 1 crypto_bridge::)", p.stdout)
        self.assertEqual(self.calls(), [
            "test --locked --features std,api,ffi,crypto,nizk",
            "check --locked --lib --features pyo3,api,nizk",
        ])

    def test_a_malformed_pin_exits_2(self) -> None:
        for pin in ("", "rev abc\n", "rev " + "A" * 40 + "\n"):
            with self.subTest(pin=pin):
                (self.r / ".github" / "alice-crypto-pin").write_text(pin)
                p = self.run_script(NIZK + BRIDGE + result(2))
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("needs 'rev <40 hex>'", p.stderr)
                self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
