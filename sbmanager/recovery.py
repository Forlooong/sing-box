"""Self-contained recovery entry, installed before an updater touches its runtime.

The executable zip contains a complete, verified candidate package. It lives
outside /opt/sb/current and is deliberately retained across transaction rollback:
recovering an interrupted rollback must not depend on the code being restored.
"""
from __future__ import annotations

import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from .state import logical_path
from .transaction import ManagementBusy, Transaction, atomic, lock


ENTRY = "/usr/local/bin/sb-recover"
PREFIX = b"#!/usr/bin/python3 -I\n# sb-manager recovery v1\n"


def archive(files):
    """Package only already-filtered runtime inputs; use fixed ZIP metadata."""
    members = {name.removeprefix("/opt/sb/current/"): body for name, body in files.items()
               if name.startswith("/opt/sb/current/")}
    required = {"sbmanager/" + name + ".py" for name in
                ("__init__", "recovery", "transaction", "state", "system", "bootstrap", "certificates", "updates")}
    if not required <= members.keys():
        raise ValueError("Recovery runtime is incomplete")
    members["__main__.py"] = b"from sbmanager.recovery import main\nraise SystemExit(main())\n"
    stream = io.BytesIO(PREFIX)
    stream.seek(0, io.SEEK_END)
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, body in sorted(members.items()):
            if name.endswith(".py"):
                compile(body, name, "exec")
            entry = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(entry, body)
    return stream.getvalue()


def install(root, files, *, update_launcher=False):
    """Install safety tooling, which intentionally outlives failed changes.

For a first upgrade from the old per-file updater, this runs in the candidate
preparer before handing artifacts to the old process. New installations only
install the rescue executable here: their sb entry is published transactionally
so an existing upstream/legacy entry can still be restored after install fails.
    """
    target = logical_path(root, ENTRY)
    launcher = logical_path(root, "/usr/local/bin/sb")
    if target.exists() and (not target.is_file() or not target.read_bytes().startswith(PREFIX)):
        raise ValueError("Existing sb-recover is not owned by this manager")
    if update_launcher:
        if not launcher.is_file() or not any(line.startswith(b"# Managed Forlooong stack")
                                            for line in launcher.read_bytes().splitlines()[:3]):
            raise ValueError("Existing sb entry is not owned by this manager")
        if "/usr/local/bin/sb" not in files or b"sb-recover" not in files["/usr/local/bin/sb"]:
            raise ValueError("Recovery-aware launcher is missing")
    body = archive(files)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Check the actual isolated ZIP import path before replacing the installed
    # rescue command. -I ignores cwd, PYTHONPATH and user site packages.
    with tempfile.TemporaryDirectory(prefix=".sb-recovery-", dir=target.parent) as directory:
        check = Path(directory) / "check.pyz"
        atomic(check, body, 0o700)
        result = subprocess.run([sys.executable, "-I", str(check), "--help"], capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError("Candidate recovery entry cannot start independently")
    atomic(target, body, 0o755)
    # The ZIP is durable before any entry can dispatch to it. This compatible
    # launcher must remain usable even if an older runtime is restored.
    if update_launcher:
        atomic(launcher, files["/usr/local/bin/sb"], 0o755)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="sb-recover", description="Recover interrupted sb transactions without importing the installed runtime")
    parser.add_argument("--root", type=Path, default=Path("/"), help=argparse.SUPPRESS)
    parser.add_argument("--offline", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("command", nargs="?", choices=("transaction",))
    parser.add_argument("action", nargs="?", choices=("recover",))
    args = parser.parse_args(argv)
    args.root = args.root.resolve()
    if (args.command, args.action) not in ((None, None), ("transaction", "recover")):
        parser.error("Use sb transaction recover or sb-recover")
    if args.offline and args.root == Path("/").resolve():
        parser.error("--offline requires a separate --root fixture directory")
    try:
        from . import bootstrap, system
        if not args.offline:
            if args.root != Path("/").resolve():
                raise ValueError("A separate --root requires --offline")
            system.require_linux_root()
            os.umask(0o077)
        with lock(args.root):
            if not args.offline:
                bootstrap.recover_acme()
            Transaction(args.root).recover(restore_services=(lambda _: None) if args.offline else system.restore_services)
            if not args.offline:
                bootstrap.rollback_preparation()
        print(json.dumps({"recovered": True}))
        return 0
    except (ManagementBusy, ValueError, RuntimeError, OSError, KeyError) as exc:
        print("sb-recover: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
