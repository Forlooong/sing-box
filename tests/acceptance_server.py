#!/usr/bin/env python3
"""Explicit, mutating acceptance checks for an installed Linux server.

Run only on a designated test installation:
  python3 tests/acceptance_server.py --run-mutating-checks --output /root/protected.json

This rotates and permanently revokes the original subscription token, even when
the rotation transaction is rolled back. Existing clients must obtain the new
URL with `sb subscription url` afterward. No credentials or URLs enter reports,
stdout, subprocess arguments, or exception messages emitted by this script.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


SB = "/usr/local/bin/sb"
STATE = Path("/etc/sb/state.json")
SECRETS = Path("/etc/sb/secrets.json")


class AcceptanceError(Exception):
    """Contains only a fixed, nonsecret error code."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def require(condition, code):
    if not condition:
        raise AcceptanceError(code)


def command(argv, *, as_json=False, timeout=300):
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise AcceptanceError("command_timeout") from None
    except OSError:
        raise AcceptanceError("command_unavailable") from None
    require(result.returncode == 0, "command_failed")
    if not as_json:
        return None
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise AcceptanceError("command_response_invalid") from None


def sb(*args, as_json=False):
    return command([SB, *args], as_json=as_json)


def read_state():
    try:
        public = json.loads(STATE.read_bytes())
        private = json.loads(SECRETS.read_bytes())
        for value in (public["domains"]["subscription"], public["subscription"]["prefix"],
                      private["subscription_token"], public["installation_id"]):
            require(isinstance(value, str) and bool(value), "managed_state_invalid")
        return public, private
    except (OSError, ValueError, KeyError, TypeError):
        raise AcceptanceError("managed_state_unavailable") from None


def transactions():
    rows = sb("transaction", "list", as_json=True)
    require(isinstance(rows, list), "transaction_list_invalid")
    require(all(isinstance(row, dict) and isinstance(row.get("id"), str)
                and isinstance(row.get("status"), str) for row in rows), "transaction_list_invalid")
    return rows


def pids():
    values = {}
    for name in ("sb-sing-box", "sb-subscription"):
        value = command(["systemctl", "show", "--property=MainPID", "--value", name], as_json=True, timeout=30)
        require(isinstance(value, int) and value > 0, "service_pid_unavailable")
        values[name] = value
    return values


def url(public, token, prefix=None):
    return "https://" + public["domains"]["subscription"] + "/" + (prefix or public["subscription"]["prefix"]) + "/" + token


def http_status(address):
    # Ignore proxy environment variables; TLS verifies the public domain using
    # the operating system trust store. Private paths stay in memory only.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
                                        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(address, method="GET"), timeout=20) as response:
            return response.status
    except urllib.error.HTTPError as error:
        try:
            return error.code
        finally:
            error.close()
    except (OSError, urllib.error.URLError, ValueError):
        raise AcceptanceError("https_request_failed") from None


def expect_https(address, expected, code):
    # Rollback restores services with systemctl restart. Type=simple can return
    # before the restored Python listener is ready, so tolerate startup failures.
    deadline = time.monotonic() + 20
    while True:
        try:
            status = http_status(address)
        except AcceptanceError:
            if time.monotonic() >= deadline:
                raise AcceptanceError(code) from None
        else:
            if status == expected:
                return
            if status not in {502, 503, 504} or time.monotonic() >= deadline:
                raise AcceptanceError(code)
        time.sleep(0.25)


def output_path(value):
    path = Path(value)
    require(path.is_absolute() and path.name not in {"", ".", ".."}, "output_path_invalid")
    require(".." not in path.parts, "output_path_invalid")
    require(not any(item.is_symlink() for item in [path, *path.parents]), "output_path_symlink")
    require(path.parent.is_dir(), "output_directory_missing")
    info = path.parent.stat()
    require(info.st_uid == 0 and info.st_mode & 0o077 == 0, "output_directory_must_be_root_private")
    require(not path.exists(), "output_already_exists")
    return path


def write_report(path, report):
    descriptor, temporary = tempfile.mkstemp(prefix=".sb-acceptance-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Acceptance:
    def __init__(self):
        self.created = []
        self.step = "preflight"
        self.original_prefix = None
        self.installation_id = None
        self.original_token_digest = None
        self.report = {"schema_version": 1, "started_at": datetime.now(timezone.utc).isoformat(),
                       "status": "running", "checks": [], "created_transactions": self.created,
                       "original_subscription_token_permanently_revoked": False}

    def passed(self, name, **details):
        self.report["checks"].append({"name": name, "status": "passed", **details})

    def mutate(self, action, *args):
        before = {row["id"] for row in transactions()}
        result = None
        try:
            result = sb("subscription", action, *args, as_json=True)
        finally:
            # Also discover a committed operation if sb exited after committing
            # but before producing its JSON response. Never claim another label.
            candidates = [row for row in transactions() if row["id"] not in before
                          and row.get("label") == "subscription " + action]
            if isinstance(result, dict) and isinstance(result.get("transaction"), str):
                selected = [row for row in candidates if row["id"] == result["transaction"]]
            else:
                selected = candidates if len(candidates) == 1 else []
            for row in selected:
                if row["id"] not in self.created:
                    self.created.append(row["id"])
        require(isinstance(result, dict) and result.get("transaction") in self.created,
                "mutation_transaction_unidentified")
        return result["transaction"]

    def rollback(self, identifier):
        committed = [row["id"] for row in transactions() if row["status"] == "committed"]
        require(identifier in self.created and committed and identifier == max(committed),
                "rollback_blocked_by_newer_transaction")
        sb("transaction", "rollback", identifier)

    def run(self):
        public, private = read_state()
        self.original_prefix = public["subscription"]["prefix"]
        self.installation_id = public["installation_id"]
        old_token = private["subscription_token"]
        self.original_token_digest = hashlib.sha256(old_token.encode()).hexdigest()
        old_url = url(public, old_token)

        self.step = "initial_check"
        sb("check")
        initial_pids = pids()
        expect_https(old_url, 200, "initial_subscription_not_available")
        self.passed(self.step)

        self.step = "path_alias_and_reload"
        test_prefix = "sb-test-" + secrets.token_hex(12) + "/private"
        identifier = self.mutate("path", test_prefix)
        expect_https(url(public, old_token, test_prefix), 200, "new_subscription_path_failed")
        expect_https(old_url, 200, "historical_subscription_path_failed")
        require(pids() == initial_pids, "subscription_change_restarted_service")
        self.passed(self.step, transaction=identifier)

        self.step = "path_rollback"
        self.rollback(identifier)
        restored, _ = read_state()
        require(restored["subscription"]["prefix"] == self.original_prefix, "subscription_prefix_not_restored")
        expect_https(old_url, 200, "subscription_unavailable_after_path_rollback")
        self.passed(self.step, transaction=identifier)

        self.step = "unchanged_certificate_sync"
        count = len(transactions())
        core_pid = pids()["sb-sing-box"]
        for _ in range(2):
            sb("cert", "sync")
            require(len(transactions()) == count, "unchanged_certificate_sync_created_transaction")
            require(pids()["sb-sing-box"] == core_pid, "unchanged_certificate_sync_restarted_core")
        self.passed(self.step, attempts=2)

        self.step = "token_rotation"
        identifier = self.mutate("rotate")
        rotated, rotated_private = read_state()
        require(rotated_private["subscription_token"] != old_token, "subscription_token_not_rotated")
        self.report["original_subscription_token_permanently_revoked"] = True
        expect_https(old_url, 404, "revoked_subscription_token_still_accepted")
        expect_https(url(rotated, rotated_private["subscription_token"]), 200, "rotated_subscription_failed")
        self.passed(self.step, transaction=identifier)

        self.step = "rotation_rollback_preserves_revocation"
        self.rollback(identifier)
        restored, restored_private = read_state()
        require(restored_private["subscription_token"] != old_token, "rollback_restored_revoked_token")
        expect_https(old_url, 404, "rollback_reactivated_revoked_url")
        expect_https(url(restored, restored_private["subscription_token"]), 200,
                     "subscription_unavailable_after_rotation_rollback")
        require(restored["subscription"]["prefix"] == self.original_prefix, "subscription_prefix_not_restored")
        self.passed(self.step, transaction=identifier)

        self.step = "final_check"
        sb("check")
        self.passed(self.step)
        self.report["status"] = "passed"

    def cleanup(self):
        cleanup = {"rolled_back": [], "status": "attempted"}
        # All failures are classified without including subprocess/HTTP text.
        try:
            while True:
                active = [row["id"] for row in transactions() if row["status"] == "committed"]
                own = [identifier for identifier in active if identifier in self.created]
                if not own:
                    break
                latest = max(own)
                require(latest == max(active), "cleanup_blocked_by_newer_transaction")
                self.rollback(latest)
                cleanup["rolled_back"].append(latest)
            public, _ = read_state()
            require(public["installation_id"] == self.installation_id, "installation_changed_during_test")
            require(public["subscription"]["prefix"] == self.original_prefix, "test_prefix_requires_manual_recovery")
            cleanup["status"] = "restored"
        except BaseException as error:
            cleanup["status"] = "incomplete"
            cleanup["error"] = str(error) if isinstance(error, AcceptanceError) else "cleanup_failed"
        try:
            sb("check")
            cleanup["final_check"] = "passed"
        except BaseException:
            cleanup["final_check"] = "failed"
        # A command can commit its revocation and then fail before JSON output.
        # Report that irreversible result even if the main sequence stopped early.
        try:
            revoked = Path("/etc/sb/revoked-tokens.json")
            if revoked.is_file() and self.original_token_digest in json.loads(revoked.read_bytes()):
                self.report["original_subscription_token_permanently_revoked"] = True
        except (OSError, ValueError, TypeError):
            cleanup["revocation_status"] = "unknown"
        self.report["cleanup"] = cleanup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-mutating-checks", action="store_true",
                        help="Explicitly authorize path changes and irreversible subscription-token revocation")
    parser.add_argument("--output", required=True, help="New JSON file in an existing root-only directory")
    args = parser.parse_args()
    acceptance = Acceptance()
    destination = None
    lock_stream = None
    try:
        require(args.run_mutating_checks, "explicit_mutation_flag_required")
        require(platform.system() == "Linux" and os.geteuid() == 0, "linux_root_required")
        os.umask(0o077)
        destination = output_path(args.output)
        require(Path(SB).is_file() and STATE.is_file() and SECRETS.is_file(), "managed_installation_required")
        import fcntl
        lock_stream = open("/run/lock/sb-acceptance.lock", "a+b")
        try:
            fcntl.flock(lock_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise AcceptanceError("another_acceptance_test_is_running") from None
        def interrupted(*_):
            raise AcceptanceError("interrupted")
        signal.signal(signal.SIGTERM, interrupted)
        acceptance.run()
    except BaseException as error:
        acceptance.report.update(status="failed", failed_step=acceptance.step,
                                 error=str(error) if isinstance(error, AcceptanceError) else
                                 "interrupted" if isinstance(error, KeyboardInterrupt) else "unexpected_failure")
        if acceptance.installation_id is not None:
            acceptance.cleanup()
    finally:
        if lock_stream is not None:
            lock_stream.close()
    acceptance.report["finished_at"] = datetime.now(timezone.utc).isoformat()
    if destination is not None:
        try:
            write_report(destination, acceptance.report)
        except BaseException:
            acceptance.report.update(status="failed", report_error="protected_report_write_failed")
    print(json.dumps(acceptance.report, ensure_ascii=False))
    return 0 if acceptance.report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
