#!/usr/bin/env python3
"""Root-run integration check for the privileged local control service."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest


HERE = Path(__file__).parent
SOCKET = Path("/run/aishield/control.sock")


class ControlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise RuntimeError("run this test as root on a disposable Linux host")
        cls.temp = tempfile.TemporaryDirectory(prefix="aishield-control-")
        cls.base = Path(cls.temp.name)
        cls.base.chmod(0o755)
        cls.secret = cls.base / "secret"
        cls.secret.mkdir(mode=0o755)
        cls.public_client = cls.base / "aishieldctl"
        cls.public_launcher = cls.base / "aishield-proto"
        shutil.copy2(HERE / "aishieldctl", cls.public_client)
        shutil.copy2(HERE / "aishield-proto", cls.public_launcher)
        cls.public_client.chmod(0o755)
        cls.public_launcher.chmod(0o755)
        cls.service = subprocess.Popen(
            [str(HERE / "aishieldd")], stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, text=True,
        )
        for _ in range(50):
            if SOCKET.exists():
                break
            if cls.service.poll() is not None:
                raise RuntimeError(f"service exited: {cls.service.stderr.read()}")
            time.sleep(0.1)
        else:
            raise RuntimeError("service socket did not appear")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "service"):
            cls.service.terminate()
            cls.service.wait(timeout=5)
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def ctl(self, *args):
        return subprocess.run(
            [str(HERE / "aishieldctl"), *args], text=True, capture_output=True,
        )

    def test_lock_unlock_and_agent_denial(self):
        try:
            added = self.ctl("lock", str(self.secret))
            self.assertEqual(added.returncode, 0, added.stderr)
            self.assertIn("restart affected agents", added.stdout)

            status = self.ctl("status")
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertIn(str(self.secret), status.stdout)

            denied = subprocess.run(
                ["runuser", "-u", "nobody", "--", str(self.public_client),
                 "unlock", str(self.secret)], text=True, capture_output=True,
            )
            self.assertNotEqual(denied.returncode, 0)

            launched = subprocess.run(
                ["runuser", "-u", "nobody", "--", str(self.public_launcher),
                 "--read", str(self.base), "--", "/bin/true"],
                text=True, capture_output=True,
            )
            self.assertNotEqual(launched.returncode, 0, launched.stderr)
            self.assertIn(str(self.secret), launched.stderr, launched.stderr)
            self.assertIn("grant narrower roots", launched.stderr, launched.stderr)
        finally:
            removed = self.ctl("unlock", str(self.secret))
            self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertNotIn(str(self.secret), self.ctl("status").stdout)


if __name__ == "__main__":
    unittest.main()
