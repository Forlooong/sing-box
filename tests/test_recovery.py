"""Recovery is tested from an installed entry after a real updater process dies."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from sbmanager import bootstrap, recovery, state, upgrade
from sbmanager.transaction import atomic


SOURCE = Path(__file__).resolve().parent.parent


@unittest.skipUnless(os.name == "posix", "installed shell entry requires POSIX")
class InstalledRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sb-recovery-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "root"
        self.runtime = self.root / "opt/sb/current"
        self.source = self.base / "candidate"
        for name, body in bootstrap.runtime_files(SOURCE).items():
            atomic(state.logical_path(self.root, name), body, 0o755 if name.endswith("/sb") else 0o644)
            if name.startswith("/opt/sb/current/"):
                atomic(self.source / name.removeprefix("/opt/sb/current/"), body, 0o644)
        # This is the installed legacy entry, relocated only to the fixture root.
        self.entry = self.root / "usr/local/bin/sb"
        self.entry.write_text("#!/bin/sh\n# Managed Forlooong stack\nset -eu\ncd " + str(self.runtime)
                              + '\nexport PYTHONDONTWRITEBYTECODE=1\nexec /usr/bin/python3 -m sbmanager.cli "$@"\n')
        self.old_cli = (self.runtime / "sbmanager/cli.py").read_bytes()
        candidate = self.source / "sbmanager/cli.py"
        candidate.write_bytes(self.old_cli.replace(b"import argparse\n", b"from .zz_new_dependency import READY\nimport argparse\n"))
        (self.source / "sbmanager/zz_new_dependency.py").write_text("READY = True\n")
        self.public, self.private = state.create("site.example.com", "sub.example.com", "admin@example.com")
        self.public["rules"]["enabled"] = False
        atomic(state.logical_path(self.root, state.STATE), state.encode(self.public))
        atomic(state.logical_path(self.root, state.SECRETS), state.encode(self.private))

    def interrupt_update(self, revoke=False, interrupt_recovery=False):
        output = self.base / "output"
        next_private = dict(self.private, subscription_token="n" * 43)
        files = {state.STATE: state.encode(self.public), state.SECRETS: state.encode(next_private)}
        if interrupt_recovery:
            marker = self.base / "interrupt-recovery-once"
            marker.touch()
            path = self.source / "sbmanager/transaction.py"
            original = path.read_text()
            injected = original.replace("        os.replace(name, path)\n", "        os.replace(name, path)\n"
                + "        if path == Path(" + repr(str(self.runtime / "sbmanager/cli.py")) + ") and Path(" + repr(str(marker)) + ").exists():\n"
                + "            Path(" + repr(str(marker)) + ").unlink()\n            os._exit(97)\n")
            self.assertNotEqual(injected, original)
            path.write_text(injected)
        with patch.object(upgrade.cli, "snapshot_for", return_value=None), \
             patch.object(upgrade.cli, "compile_files", return_value=files), \
             patch.object(upgrade.updates, "binary", return_value=b"fixture-core"):
            upgrade.prepare(self.root, output, self.source)
        # No exception handler can catch this forced process death. The child
        # runs the installed updater, not the candidate or the test's imports.
        code = r'''
import json, os, sys
from pathlib import Path
from sbmanager import transaction
root, output = map(Path, sys.argv[1:])
files = {name: (output / name.lstrip("/")).read_bytes()
         for name in json.loads((output / "files.json").read_bytes())}
original = transaction.atomic
def die_after_cli(path, body, mode=0o600):
    original(path, body, mode)
    if path == root / "opt/sb/current/sbmanager/cli.py":
        os._exit(99)
transaction.atomic = die_after_cli
transaction.Transaction(root).apply(files, label="update fixture")
'''
        env = dict(os.environ, PYTHONPATH=str(self.runtime), PYTHONDONTWRITEBYTECODE="1")
        child = subprocess.run([sys.executable, "-c", code, str(self.root), str(output)],
                               cwd=self.runtime, env=env, capture_output=True, timeout=15)
        self.assertEqual(child.returncode, 99, child.stderr.decode())
        self.assertFalse((self.runtime / "sbmanager/zz_new_dependency.py").exists())
        self.assertIn(b"zz_new_dependency", (self.runtime / "sbmanager/cli.py").read_bytes())
        self.journal = next((self.root / "var/backups/sb/transactions").glob("*/journal.json"))
        self.assertEqual(json.loads(self.journal.read_bytes())["status"], "applying")
        if revoke:
            digest = hashlib.sha256(self.private["subscription_token"].encode()).hexdigest()
            atomic(state.logical_path(self.root, state.REVOKED), state.encode([digest]))
        # Execute the installed command, with no project import path available.
        env.pop("PYTHONPATH", None)
        command = ["/bin/sh", str(self.entry), "--root", str(self.root), "--offline", "transaction", "recover"]
        if interrupt_recovery:
            interrupted = subprocess.run(command, cwd=self.base, env=env, capture_output=True, timeout=15)
            self.assertEqual(interrupted.returncode, 97, interrupted.stderr.decode())
            self.assertEqual(json.loads(self.journal.read_bytes())["status"], "rolling-back")
        result = subprocess.run(command,
                                cwd=self.base, env=env, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(self.journal.read_bytes())["status"], "rolled-back")
        self.assertEqual((self.runtime / "sbmanager/cli.py").read_bytes(), self.old_cli)
        self.assertTrue(self.runtime.is_dir())
        self.assertFalse(self.runtime.is_symlink())
        self.assertTrue((self.root / recovery.ENTRY.lstrip("/")).is_file())
        check = subprocess.run([sys.executable, "-m", "sbmanager.cli", "--root", str(self.root), "--offline", "status"],
                               cwd=self.runtime, env=env, capture_output=True, timeout=15)
        self.assertEqual(check.returncode, 0, check.stderr.decode())

    def test_killed_update_recovers_from_installed_entry(self):
        self.interrupt_update()

    def test_killed_update_recovery_does_not_revive_revoked_token(self):
        self.interrupt_update(revoke=True)
        self.assertEqual(state.load(self.root)[1]["subscription_token"], "n" * 43)

    def test_recovery_killed_during_restore_can_be_restarted(self):
        self.interrupt_update(revoke=True, interrupt_recovery=True)
        self.assertEqual(state.load(self.root)[1]["subscription_token"], "n" * 43)

    def test_new_install_preserves_foreign_launcher_until_transaction(self):
        previous = b"#!/bin/sh\n# upstream entry\n"
        self.entry.write_bytes(previous)
        with patch.object(bootstrap, "ROOT", self.root), \
             patch.object(bootstrap.system, "os_check", return_value={"ID": "debian", "VERSION_ID": "12"}), \
             patch.object(bootstrap.system, "network_preflight"), \
             patch.object(bootstrap.system, "service_state", return_value={}), \
             patch.object(bootstrap, "_install_packages"), patch.object(bootstrap, "_service_accounts"), \
             patch.object(bootstrap.updates, "binary", return_value=b"fixture-core"):
            files = bootstrap.prepare_host(self.source, self.public)
        self.assertEqual(self.entry.read_bytes(), previous)
        self.assertIn(b"sb-recover", files["/usr/local/bin/sb"])
        self.assertTrue((self.root / recovery.ENTRY.lstrip("/")).is_file())
        self.assertNotIn(recovery.ENTRY, files)

    def test_unrelated_recovery_command_is_preserved(self):
        target = self.root / recovery.ENTRY.lstrip("/")
        target.write_bytes(b"unrelated command")
        previous = self.entry.read_bytes()
        with self.assertRaisesRegex(ValueError, "not owned"):
            recovery.install(self.root, bootstrap.runtime_files(self.source), update_launcher=True)
        self.assertEqual(target.read_bytes(), b"unrelated command")
        self.assertEqual(self.entry.read_bytes(), previous)


if __name__ == "__main__":
    unittest.main()
