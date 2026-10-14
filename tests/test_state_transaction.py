import json
import hashlib
import errno
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest import mock

from sbmanager import state, system
from sbmanager.transaction import Transaction, lock, atomic
from sbmanager.system import patch_nginx


class StateTests(unittest.TestCase):
    def test_domain_and_path_injection_rejected(self):
        for name in ("x;return 200", "*.example.com", "127.0.0.1", "example..com", "-x.example.com"):
            with self.assertRaises(ValueError):
                state.domain(name)
        for path in ("../../etc", "private?x=1", "sub/%2e%2e", "", "x\ny"):
            with self.assertRaises(ValueError):
                state.prefix(path)

    def test_state_does_not_allow_credential_fields(self):
        s, p = state.create("site.example.com", "sub.example.com", "admin@example.com")
        self.assertEqual(state.validate(s, p), s)
        s["nodes"] = [{"id": "a", "name": "A", "source": "local", "password": "secret"}]
        with self.assertRaises(ValueError):
            state.validate(s, p)

    def test_nginx_include_idempotent_and_conflicting_stream(self):
        sample = 'events {}\nhttp { # pretend stream {\n include mime.types;\n}\n'
        changed = patch_nginx(sample)
        self.assertEqual(patch_nginx(changed), changed)
        with self.assertRaises(ValueError):
            patch_nginx("events {} http {} stream {}")


class TransactionTests(unittest.TestCase):
    def test_lock_io_failure_is_not_classified_as_contention(self):
        with tempfile.TemporaryDirectory() as temp:
            backend = "msvcrt.locking" if os.name == "nt" else "fcntl.flock"
            with mock.patch(backend, side_effect=OSError(errno.EIO, "Storage failure")):
                with self.assertRaises(OSError) as raised:
                    with lock(Path(temp)):
                        self.fail("A failed lock must never enter the operation")
            self.assertEqual(raised.exception.errno, errno.EIO)

    def test_interrupted_manual_rollback_remains_recoverable(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            atomic(root / "etc/sb/fixture", b"before")
            tx = Transaction(root)
            identifier = tx.apply({"/etc/sb/fixture": b"after"})
            def interrupted(_):
                raise RuntimeError("crash during service restoration")
            with self.assertRaises(RuntimeError):
                tx.rollback(identifier, restore_services=interrupted)
            journal = tx.base / identifier / "journal.json"
            self.assertEqual(json.loads(journal.read_bytes())["status"], "rolling-back")
            tx.recover()
            self.assertEqual((root / "etc/sb/fixture").read_bytes(), b"before")
            self.assertEqual(json.loads(journal.read_bytes())["status"], "rolled-back")

    def test_migration_rollback_cannot_restart_revoked_standalone_service(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            saved, private = state.create("site.example.com", "sub.example.com", "admin@example.com")
            saved["rules"]["enabled"] = False
            tx = Transaction(root)
            identifier = tx.apply({state.STATE: state.encode(saved), state.SECRETS: state.encode(private)},
                label="migrate", service_state={"subscription-generator.service": {"is-active": True, "is-enabled": True}})
            atomic(root / "etc/sb/revoked-tokens.json", state.encode([hashlib.sha256(private["subscription_token"].encode()).hexdigest()]))
            private["subscription_token"] = "n" * 43
            atomic(root / "etc/sb/secrets.json", state.encode(private))
            restored = []
            with self.assertRaisesRegex(RuntimeError, "original token was revoked"):
                tx.rollback(identifier, restore_services=restored.append)
            self.assertEqual(restored, [])
            self.assertEqual(state.load(root)[1]["subscription_token"], "n" * 43)

    def test_failure_restores_old_files_and_removes_new(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            first = root / "etc/sb/fixture"
            atomic(first, b"old")
            tx = Transaction(root)
            with lock(root):
                with self.assertRaises(RuntimeError):
                    tx.apply({"/etc/sb/fixture": b"new", "/etc/sb/second": b"created"},
                             health=lambda: (_ for _ in ()).throw(RuntimeError("failure")))
            self.assertEqual(first.read_bytes(), b"old")
            self.assertFalse((root / "etc/sb/second").exists())

    def test_validation_failure_never_changes_live_data(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            atomic(root / "etc/sb/fixture", b"old")
            with self.assertRaises(ValueError):
                Transaction(root).apply({"/etc/sb/fixture": b"new"},
                    validate=lambda _: (_ for _ in ()).throw(ValueError("invalid candidate")))
            self.assertEqual((root / "etc/sb/fixture").read_bytes(), b"old")

    def test_committed_rollback_and_path_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            tx = Transaction(Path(temp))
            identifier = tx.apply({"/etc/sb/fixture": b"one"})
            tx.rollback(identifier)
            self.assertFalse((Path(temp) / "etc/sb/fixture").exists())
            with self.assertRaises(ValueError):
                tx.apply({"/../../escape": b"no"})

    def test_recovery_from_interrupted_apply(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            atomic(root / "etc/sb/fixture", b"before")
            tx = Transaction(root)
            identifier = tx.apply({"/etc/sb/fixture": b"after"})
            journal = tx.base / identifier / "journal.json"
            record = json.loads(journal.read_bytes())
            record["status"] = "applying"
            atomic(journal, state.encode(record))
            tx.recover()
            self.assertEqual((root / "etc/sb/fixture").read_bytes(), b"before")


class CertificateCopyTransactionTests(unittest.TestCase):
    certificate = "/etc/sb/certificates/site.example.com/fullchain.pem"
    pending = "/var/lib/sb/certificate-sync/pending.json"

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.tx = Transaction(self.root)
        self.old_queue = state.encode({"nginx": ["old.example.com"]})
        atomic(state.logical_path(self.root, self.certificate), b"old certificate")
        atomic(state.logical_path(self.root, self.pending), self.old_queue)

    def copy(self):
        return self.tx.apply({self.certificate: b"renewed certificate", self.pending: state.encode({
            "nginx": ["site.example.com"]})}, label="certificate copies")

    def test_manual_certificate_copy_rollback_is_rejected_without_mutation(self):
        identifier = self.copy()
        before = {path: state.logical_path(self.root, path).read_bytes() for path in (self.certificate, self.pending)}
        restored = mock.Mock()
        with self.assertRaisesRegex(ValueError, "cert sync"):
            self.tx.rollback(identifier, restore_services=restored)
        restored.assert_not_called()
        for path, value in before.items():
            self.assertEqual(state.logical_path(self.root, path).read_bytes(), value)
        self.assertEqual(json.loads((self.tx.base / identifier / "journal.json").read_bytes())["status"], "committed")

    def test_interrupted_copy_recovery_restores_old_files_and_queue_without_restarting_services(self):
        script = """
import os, sys
from pathlib import Path
from sbmanager import state
from sbmanager.transaction import Transaction
Transaction(Path(sys.argv[1])).apply({sys.argv[2]: b"renewed certificate", sys.argv[3]: state.encode({"nginx": ["site.example.com"]})},
    label="certificate copies", activate=lambda record: os._exit(92))
"""
        process = subprocess.run([sys.executable, "-B", "-c", script, str(self.root), self.certificate, self.pending],
                                 capture_output=True, timeout=20)
        self.assertEqual(process.returncode, 92, process.stderr.decode())
        journal = next(self.tx.base.glob("*/journal.json"))
        self.assertEqual(json.loads(journal.read_bytes())["status"], "applying")
        self.assertEqual(state.logical_path(self.root, self.certificate).read_bytes(), b"renewed certificate")
        with mock.patch.object(system, "run") as run:
            self.tx.recover(restore_services=system.restore_services)
        self.assertEqual(run.call_args_list, [mock.call(["systemctl", "daemon-reload"])])
        self.assertEqual(state.logical_path(self.root, self.certificate).read_bytes(), b"old certificate")
        self.assertEqual(state.logical_path(self.root, self.pending).read_bytes(), self.old_queue)
        self.assertEqual(json.loads(journal.read_bytes())["status"], "rolled-back")

    def test_newer_certificate_copies_do_not_block_disjoint_configuration_rollback(self):
        path = "/etc/sb/ordinary-setting"
        atomic(state.logical_path(self.root, path), b"before")
        identifier = self.tx.apply({path: b"after"})
        self.copy()
        self.tx.rollback(identifier)
        self.assertEqual(state.logical_path(self.root, path).read_bytes(), b"before")
        self.assertEqual(state.logical_path(self.root, self.certificate).read_bytes(), b"renewed certificate")
        self.assertEqual(json.loads(state.logical_path(self.root, self.pending).read_bytes()), {"nginx": ["site.example.com"]})

    def test_newer_certificate_copies_block_overlapping_configuration_rollback(self):
        identifier = self.tx.apply({self.certificate: b"intermediate certificate"}, label="domain change")
        self.copy()
        with self.assertRaisesRegex(ValueError, "overlaps.*certificate"):
            self.tx.rollback(identifier)
        self.assertEqual(state.logical_path(self.root, self.certificate).read_bytes(), b"renewed certificate")
        self.assertEqual(json.loads((self.tx.base / identifier / "journal.json").read_bytes())["status"], "committed")

    def test_ordinary_newer_transactions_still_block_out_of_order_rollback(self):
        identifier = self.tx.apply({"/etc/sb/earlier": b"first"})
        self.copy()
        self.tx.apply({"/etc/sb/later": b"second"})
        with self.assertRaisesRegex(ValueError, "newer transactions first"):
            self.tx.rollback(identifier)
        self.assertEqual(state.logical_path(self.root, "/etc/sb/earlier").read_bytes(), b"first")


if __name__ == "__main__":
    unittest.main()
