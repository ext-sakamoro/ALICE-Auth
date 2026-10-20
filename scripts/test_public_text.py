#!/usr/bin/env python3
"""Tests of scripts/public_text.sh.

`PublicText` needs no network: what it cannot know to compare exits 2 (a malformed
pin, a base that is not a commit), before anything is fetched. `Planted` fetches the
checker at this repository's pin and shows it has teeth: a planted note link is a
finding, and the same tree without it is clean with a non-zero file count.

The check itself (the checker at the pin on the tree and the commits) runs in the
Public text workflow and in scripts/preflight.sh.

usage: python3 scripts/test_public_text.py
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "public_text.sh"
GOOD_PIN = "rev " + "a" * 40 + "\nsha256 " + "b" * 64 + "\n"


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", "-c", "user.name=T", "-c", "user.email=t@example.invalid", *args], cwd=cwd,
                          check=True, capture_output=True, text=True).stdout.strip()


class PublicText(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="public-text-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.r = self.tmp / "r"
        (self.r / "scripts").mkdir(parents=True)
        (self.r / ".github").mkdir()
        shutil.copy(SCRIPT, self.r / "scripts" / "public_text.sh")
        git("init", "-q", "-b", "main", cwd=self.r)
        (self.r / ".github" / "public-text-pin").write_text(GOOD_PIN)
        git("add", "-A", cwd=self.r)
        git("commit", "-qm", "c", cwd=self.r)
        # (no network: a fetch would fail with a git error, never exit 2 with these messages)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env["GIT_CONFIG_NOSYSTEM"] = "1"
        self.env["HOME"] = str(self.tmp)

    def run_script(self, *args: str, base: str | None = None) -> subprocess.CompletedProcess:
        env = dict(self.env)
        if base is not None:
            env["PUBLIC_TEXT_BASE"] = base
        return subprocess.run(["bash", "scripts/public_text.sh", *args], cwd=self.r, capture_output=True, text=True,
                              env=env, timeout=60)

    def test_a_base_that_is_not_a_commit_exits_2(self) -> None:
        for args, base in ((("nosuchref",), None), (("deadbeef" * 5,), None), ((), "nosuchref"),
                           ((), "0" * 40)):
            with self.subTest(args=args, base=base):
                p = self.run_script(*args, base=base)
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("is not a commit in this repository", p.stderr)
                self.assertNotIn("no new commit", p.stdout)

    def test_a_malformed_pin_exits_2(self) -> None:
        for pin in ("", "rev abc\nsha256 " + "b" * 64 + "\n", "rev " + "a" * 40 + "\n", "sha256 " + "b" * 64 + "\n",
                    "rev " + "A" * 40 + "\nsha256 " + "b" * 64 + "\n"):
            with self.subTest(pin=pin):
                (self.r / ".github" / "public-text-pin").write_text(pin)
                p = self.run_script(base="HEAD")
                self.assertEqual(p.returncode, 2, p.stdout + p.stderr)
                self.assertIn("needs 'rev <40 hex>' and 'sha256 <64 hex>'", p.stderr)



class Planted(unittest.TestCase):
    """The checker at this repository's pin, on a repository with and without a planted
    note link (fetches ALICE-Law)."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="public-text-planted-"))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.r = self.tmp / "r"
        (self.r / "scripts").mkdir(parents=True)
        (self.r / ".github").mkdir()
        shutil.copy(SCRIPT, self.r / "scripts" / "public_text.sh")
        shutil.copy(ROOT / ".github" / "public-text-pin", self.r / ".github" / "public-text-pin")
        (self.r / "README.md").write_text("A clean file.\n")
        git("init", "-q", "-b", "main", cwd=self.r)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}

    def check(self) -> subprocess.CompletedProcess:
        git("add", "-A", cwd=self.r)
        git("commit", "-qm", "c", cwd=self.r)
        return subprocess.run(["bash", "scripts/public_text.sh", "HEAD"], cwd=self.r, capture_output=True,
                              text=True, env=self.env, timeout=300)

    def test_a_planted_note_link_is_a_finding(self) -> None:
        # built at run time so this file itself carries no note link
        link = "[" * 2 + "x_y" + "]" * 2
        (self.r / "notes.md").write_text(f"see {link} for the reason\n")
        p = self.check()
        self.assertEqual(p.returncode, 1, p.stdout + p.stderr)
        self.assertIn("notes.md:1:", p.stdout)

    def test_the_same_tree_without_it_is_clean(self) -> None:
        p = self.check()
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertRegex(p.stdout, r"public text: 0 findings in [1-9][0-9]* files at HEAD")


if __name__ == "__main__":
    unittest.main()
