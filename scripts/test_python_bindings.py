#!/usr/bin/env python3
"""Python-side tests for the `pyo3` feature (src/python.rs).

Builds the crate as a Python extension for the interpreter running this script
(`cargo rustc --lib --crate-type cdylib --features pyo3`, PYO3_PYTHON = this
interpreter), imports it as `alice_auth`, checks that every name the module
registers is exported, and checks signing against the RFC 8032 section 7.1
Ed25519 test vectors (values written out below, not computed by the crate).

The extension is built in the debug profile on purpose: debug assertions make
pyo3 abort on a misaligned pyclass (contents aligned above CPython's 16 bytes),
which a release build would run as silent undefined behaviour (src/python.rs
also asserts the alignment of every pyclass at compile time).

Usage: python3 scripts/test_python_bindings.py
Exit 1 when the build fails, when a test fails or when no test ran.
"""

from __future__ import annotations

import importlib.util
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE = None  # set by load_module()


def build_extension() -> pathlib.Path:
    env = dict(os.environ)
    env["PYO3_PYTHON"] = sys.executable
    target_dir = pathlib.Path(env.get("CARGO_TARGET_DIR", ROOT / "target"))
    cmd = ["cargo", "rustc", "--lib", "--crate-type", "cdylib", "--features", "pyo3"]
    profile = "debug"
    if sys.platform == "darwin":
        # the interpreter provides the Python symbols at import time; maturin passes the same
        # two arguments (a dependency's build script cannot add link arguments to this cdylib)
        cmd += ["--", "-C", "link-arg=-undefined", "-C", "link-arg=dynamic_lookup"]
    print("+", " ".join(cmd), f"(PYO3_PYTHON={sys.executable})", flush=True)
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)
    out = target_dir / profile
    for name in ("libalice_auth.so", "libalice_auth.dylib", "alice_auth.dll"):
        if (out / name).is_file():
            return out / name
    raise SystemExit(f"no extension library found in {out}")


def load_module(lib: pathlib.Path, workdir: pathlib.Path):
    suffix = ".pyd" if sys.platform == "win32" else ".so"
    dest = workdir / f"alice_auth{suffix}"
    shutil.copyfile(lib, dest)
    spec = importlib.util.spec_from_file_location("alice_auth", dest)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {dest}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


EXPORTED = [
    "Identity", "AliceId", "RotatingIdentity", "RevocationList", "PolicyEngine", "RevocationSet",
    "GrantError", "verify", "verify32", "challenge", "make_challenge", "check", "verify_batch",
    "nizk_prove", "nizk_verify", "nizk_verify_batch", "endorse", "verify_endorsement",
    "token_create", "token_parse", "token_is_expired", "derive_child", "player_id_from_genesis",
    "rotation_link_issue", "player_chain_resolve", "grant_issue", "grant_verify", "revocation_issue",
]

# RFC 8032 section 7.1, TEST 1 (empty message) and TEST 2 (one byte 0x72)
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]


class ExportTests(unittest.TestCase):
    def test_every_registered_name_is_exported(self):
        missing = [n for n in EXPORTED if not hasattr(MODULE, n)]
        self.assertEqual(missing, [])


class Ed25519Tests(unittest.TestCase):
    def test_rfc8032_public_key_and_signature(self):
        for seed, public, msg, sig in RFC8032:
            with self.subTest(public=public[:8]):
                ident = MODULE.Identity.from_seed(bytes.fromhex(seed))
                self.assertEqual(bytes(ident.seed()), bytes.fromhex(seed))
                self.assertEqual(bytes(ident.id().as_bytes()), bytes.fromhex(public))
                self.assertEqual(bytes(ident.sign(bytes.fromhex(msg))), bytes.fromhex(sig))

    def test_verify_accepts_the_vector_and_rejects_a_flipped_bit(self):
        for _seed, public, msg, sig in RFC8032:
            with self.subTest(public=public[:8]):
                pid = MODULE.AliceId(bytes.fromhex(public))
                good = bytes.fromhex(sig)
                self.assertTrue(MODULE.verify(pid, bytes.fromhex(msg), good))
                bad = bytes([good[0] ^ 1]) + good[1:]
                self.assertFalse(MODULE.verify(pid, bytes.fromhex(msg), bad))

    def test_seed_and_id_lengths_are_checked(self):
        for n in (0, 31, 33):
            with self.subTest(n=n):
                with self.assertRaises(ValueError):
                    MODULE.Identity.from_seed(bytes(n))
                with self.assertRaises(ValueError):
                    MODULE.AliceId(bytes(n))

    def test_reserved_prefix_is_refused(self):
        ident = MODULE.Identity.from_seed(bytes.fromhex(RFC8032[0][0]))
        with self.assertRaises(ValueError):
            ident.sign(b"alice-auth/anything")

    def test_alice_id_equality_and_hash(self):
        a = MODULE.AliceId(bytes.fromhex(RFC8032[0][1]))
        b = MODULE.AliceId(bytes.fromhex(RFC8032[0][1]))
        c = MODULE.AliceId(bytes.fromhex(RFC8032[1][1]))
        self.assertEqual(a, b)
        self.assertEqual(hash(a), hash(b))
        self.assertNotEqual(a, c)


def main() -> int:
    global MODULE
    print(f"python {sys.version.split()[0]} ({sys.executable})", flush=True)
    lib = build_extension()
    with tempfile.TemporaryDirectory() as tmp:
        MODULE = load_module(lib, pathlib.Path(tmp))
        suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun == 0:
        print("no test ran", file=sys.stderr)
        return 1
    print(f"python bindings: {result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
