#!/usr/bin/env python3
"""Linux integration tests; a missing Landlock implementation is a failure."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


LAUNCHER = Path(__file__).with_name("aishield-proto")
SYSTEM_ROOTS = [
    Path(path) for path in ("/usr", "/bin", "/lib", "/lib64", "/etc", "/usr/local")
    if Path(path).exists()
]


class LandlockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="aishield-test-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.allowed = base / "allowed"
        self.secret = base / "secret"
        self.allowed.mkdir()
        self.secret.mkdir()
        (self.allowed / "ok.txt").write_text("allowed")
        (self.secret / "no.txt").write_text("secret")

    def run_agent(self, program, *, writable=False, pass_fds=()):
        args = [str(LAUNCHER)]
        for root in SYSTEM_ROOTS:
            args += ["--read", str(root)]
        args += ["--write" if writable else "--read", str(self.allowed)]
        args += ["--lock", str(self.secret), "--", *program]
        return subprocess.run(args, text=True, capture_output=True, pass_fds=pass_fds)

    def test_allowed_read_and_denied_read(self):
        ok = self.run_agent(["/bin/cat", str(self.allowed / "ok.txt")])
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(ok.stdout, "allowed")
        no = self.run_agent(["/bin/cat", str(self.secret / "no.txt")])
        self.assertNotEqual(no.returncode, 0)
        self.assertNotIn("secret", no.stdout)

    def test_descendant_denied(self):
        result = self.run_agent([
            "/bin/sh", "-c", 'exec /bin/cat "$1"', "sh", str(self.secret / "no.txt")
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("secret", result.stdout)

    def test_symlink_into_secret_denied(self):
        link = self.allowed / "link"
        link.symlink_to(self.secret / "no.txt")
        result = self.run_agent(["/bin/cat", str(link)])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("secret", result.stdout)

    def test_write_requires_write_grant(self):
        target = self.allowed / "new.txt"
        command = [sys.executable, "-c", "import pathlib,sys; pathlib.Path(sys.argv[1]).write_text('ok')", str(target)]
        denied = self.run_agent(command)
        self.assertNotEqual(denied.returncode, 0)
        self.assertFalse(target.exists())
        allowed = self.run_agent(command, writable=True)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertEqual(target.read_text(), "ok")

    def test_inherited_descriptor_closed(self):
        fd = os.open(self.secret / "no.txt", os.O_RDONLY)
        self.addCleanup(os.close, fd)
        code = "import os,sys; fd=int(sys.argv[1]); os.read(fd,1)"
        result = self.run_agent([sys.executable, "-c", code, str(fd)], pass_fds=(fd,))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Bad file descriptor", result.stderr)

    def test_preopened_stdin_rejected(self):
        args = [str(LAUNCHER), "--read", str(self.allowed), "--", "/bin/cat"]
        with (self.secret / "no.txt").open("rb") as secret_input:
            result = subprocess.run(args, stdin=secret_input, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("pre-opened file", result.stderr)

    def test_nested_lock_rejected(self):
        args = [str(LAUNCHER), "--read", self.temp.name, "--lock", str(self.secret),
                "--", "/bin/true"]
        result = subprocess.run(args, text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("grant narrower roots", result.stderr)


if __name__ == "__main__":
    unittest.main()
