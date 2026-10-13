import json
import hashlib
from pathlib import Path
import tempfile
import unittest

from sbmanager import state
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


if __name__ == "__main__":
    unittest.main()
