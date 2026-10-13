"""Durable file transactions. A caller holds the global lock across read/modify/apply."""
from __future__ import annotations

from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time
import uuid
import secrets

from .state import logical_path, encode, REVOKED, SECRETS


class ManagementBusy(RuntimeError):
    """Another manager already owns the nonblocking global lock."""


def atomic(path: Path, data: bytes, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".sb-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        if os.name == "posix":
            descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def lock(root=Path("/")):
    path = logical_path(root, "/run/lock/sb-manager.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        try:
            if os.name == "nt":
                import msvcrt
                stream.seek(0)
                if not stream.read(1):
                    stream.write(b"0")
                    stream.flush()
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EWOULDBLOCK}:
                raise ManagementBusy("Another sb operation holds the management lock") from None
            raise
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def file_mode(path):
    if path.startswith("/opt/sb/bin/") or (path.startswith("/opt/sb/legacy/") and path.endswith("/sing-box")):
        return 0o755
    if path.startswith("/opt/sb/current/"):
        return 0o644
    if path.startswith("/etc/systemd/") or path.startswith("/etc/nginx/"):
        return 0o644
    if path.startswith("/var/www/"):
        return 0o644
    if path.startswith("/usr/local/bin/") or "/renewal-hooks/" in path:
        return 0o755
    if path.startswith("/var/lib/sb/subscription/") or path.startswith("/etc/sb/certificates/"):
        return 0o640
    return 0o600


class Transaction:
    def __init__(self, root=Path("/")):
        self.root = Path(root).resolve()
        self.base = logical_path(self.root, "/var/backups/sb/transactions")
        self.base.mkdir(parents=True, exist_ok=True)
        os.chmod(self.base, 0o700)

    def apply(self, files, *, validate=lambda _: None, activate=lambda _: None,
              health=lambda: None, restore_services=lambda _: None, service_state=None,
              label="change", remove_symlinks=None, commit=lambda: None):
        self.recover(restore_services=restore_services)
        identifier = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + str(time.time_ns()) + "-" + uuid.uuid4().hex[:6]
        folder = self.base / identifier
        folder.mkdir(mode=0o700)
        stage = folder / "stage"
        record = {"id": identifier, "label": label, "status": "preparing", "files": {},
                  "services": service_state or {}, "created": int(time.time()), "symlinks": {}, "changed": [], "directories": {}}
        journal = folder / "journal.json"
        for name, content in files.items():
            if name == REVOKED:
                raise ValueError("Revocations are monotonic and cannot be transactional")
            target = logical_path(self.root, name)
            parent = target.parent
            while parent != self.root:
                logical = "/" + parent.relative_to(self.root).as_posix()
                if logical not in record["directories"]:
                    info = {"existed": parent.exists()}
                    if parent.exists():
                        details = parent.stat()
                        info.update(mode=stat.S_IMODE(details.st_mode), uid=details.st_uid, gid=details.st_gid)
                    record["directories"][logical] = info
                parent = parent.parent
            if target.exists() and not target.is_file():
                raise ValueError("Managed target is not a regular file")
            if content is not None:
                candidate = logical_path(stage, name)
                atomic(candidate, content, file_mode(name))
            entry = {"existed": target.exists(), "mode": stat.S_IMODE(target.stat().st_mode) if target.exists() else file_mode(name)}
            if target.exists():
                entry.update(uid=target.stat().st_uid, gid=target.stat().st_gid)
                atomic(logical_path(folder / "before", name), target.read_bytes(), 0o600)
            if (content is None and target.exists()) or (content is not None and (not target.exists() or target.read_bytes() != content)):
                record["changed"].append(name)
            record["files"][name] = entry
        for name, expected in (remove_symlinks or {}).items():
            target = self._link_path(name)
            if not target.exists() and not target.is_symlink():
                continue  # already removed by the original migration
            if not target.is_symlink() or os.readlink(target) != expected:
                raise ValueError("Migration symlink changed since inspection")
            record["symlinks"][name] = expected
        atomic(journal, encode(record))
        validate(stage)
        record["status"] = "applying"
        atomic(journal, encode(record))
        try:
            for name in record["symlinks"]:
                self._link_path(name).unlink()
            for name, content in files.items():
                target = logical_path(self.root, name)
                if content is None:
                    target.unlink(missing_ok=True)
                else:
                    atomic(target, content, file_mode(name))
            activate(record)
            health()
            commit()
            record["status"] = "committed"
            atomic(journal, encode(record))
            return identifier
        except BaseException:
            self._restore(folder, record, restore_services)
            raise

    def _restore(self, folder, record, restore_services):
        # Revocation survives rollback. Restore old configuration with a valid current
        # token and rewrite its routes; never bring a revoked URL back to life.
        revoked_path = logical_path(self.root, REVOKED)
        revoked = set(json.loads(revoked_path.read_bytes())) if revoked_path.exists() else set()
        previous_secret = logical_path(folder / "before", SECRETS)
        # Initial migration may restore a different subscription application whose
        # config is outside /etc/sb. Never re-enable its revoked original token.
        original_service = record.get("services", {}).get("subscription-generator.service", {})
        staged_secret = logical_path(folder / "stage", SECRETS)
        if (record.get("label") == "migrate" and not previous_secret.exists()
                and (original_service.get("is-active") or original_service.get("is-enabled"))
                and staged_secret.exists()):
            original = json.loads(staged_secret.read_bytes()).get("subscription_token", "")
            if hashlib.sha256(original.encode()).hexdigest() in revoked:
                raise RuntimeError("Cannot restore the standalone subscription service: its original token was revoked; retain the managed service")
        replacement = None
        old_token = None
        if previous_secret.exists():
            value = json.loads(previous_secret.read_bytes())
            if hashlib.sha256(value["subscription_token"].encode()).hexdigest() in revoked:
                old_token = value["subscription_token"]
                current = logical_path(self.root, SECRETS)
                replacement = json.loads(current.read_bytes()).get("subscription_token") if current.exists() else None
                if not replacement or hashlib.sha256(replacement.encode()).hexdigest() in revoked:
                    replacement = secrets.token_urlsafe(32)
        record["status"] = "rolling-back"
        atomic(folder / "journal.json", encode(record))
        for name, info in reversed(list(record["files"].items())):
            target = logical_path(self.root, name)
            if info["existed"]:
                content = logical_path(folder / "before", name).read_bytes()
                if replacement and name == SECRETS:
                    value = json.loads(content)
                    value["subscription_token"] = replacement
                    content = encode(value)
                elif replacement and name == "/var/lib/sb/subscription/runtime.json":
                    value = json.loads(content)
                    for route in value["routes"]:
                        route["path"] = "/".join(replacement if p == old_token else p for p in route["path"].split("/"))
                    value.pop("generation", None)
                    value["generation"] = hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()
                    content = encode(value)
                atomic(target, content, info["mode"])
                if os.name == "posix" and "uid" in info:
                    os.chown(target, info["uid"], info["gid"])
            else:
                target.unlink(missing_ok=True)
        for name, expected in record.get("symlinks", {}).items():
            target = self._link_path(name)
            if target.is_symlink() and os.readlink(target) == expected:
                continue
            if target.exists() or target.is_symlink():
                raise RuntimeError("Cannot restore migration symlink over an unexpected file")
            target.symlink_to(expected)
        for name, info in record.get("directories", {}).items():
            target = logical_path(self.root, name)
            if info["existed"] and target.is_dir():
                os.chmod(target, info["mode"])
                if os.name == "posix":
                    os.chown(target, info["uid"], info["gid"])
        restore_services(record.get("services", {}))
        record["status"] = "rolled-back"
        atomic(folder / "journal.json", encode(record))

    def _link_path(self, name):
        # Only the final component may be a symlink, and never a traversal segment.
        from pathlib import PurePosixPath
        p = PurePosixPath(name)
        if not p.is_absolute() or p.name in ("", ".", "..") or ".." in p.parts or "\\" in name or "\0" in name:
            raise ValueError("Unsafe symlink path")
        return logical_path(self.root, str(p.parent)) / p.name

    def recover(self, restore_services=lambda _: None):
        for path in sorted(self.base.glob("*/journal.json")):
            record = json.loads(path.read_bytes())
            if record["status"] in {"applying", "rolling-back", "blocked-revoked-token"}:
                self._restore(path.parent, record, restore_services)

    def rollback(self, identifier, restore_services=lambda _: None):
        if "/" in identifier or "\\" in identifier or identifier in {".", ".."}:
            raise ValueError("Invalid transaction ID")
        folder = self.base / identifier
        record = json.loads((folder / "journal.json").read_bytes())
        if record["status"] != "committed":
            raise ValueError("Only a committed transaction can be rolled back")
        newer = [p for p in self.base.glob("*/journal.json") if p.parent.name > identifier
                 and json.loads(p.read_bytes())["status"] == "committed"]
        if newer:
            raise ValueError("Roll back newer transactions first")
        previous_state = logical_path(folder / "before", "/etc/sb/state.json")
        if previous_state.exists():
            rules_state = json.loads(previous_state.read_bytes()).get("rules", {})
            if rules_state.get("enabled"):
                from . import rules
                rules.load(logical_path(self.root, "/var/lib/sb/rules"), rules_state.get("active_build"))
        self._restore(folder, record, restore_services)
