"""CLI regressions: a broken old lineage must not starve healthy renewals."""
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from sbmanager import bootstrap, certificates, certsync, cli, migration, probe, state


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable is required")
class CertSyncIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory(prefix="sb-sync-ca-")
        cls.ca_root = Path(cls.fixtures.name)
        cls.openssl = shutil.which("openssl")
        cls.ca = cls.ca_root / "ca.pem"
        (cls.ca_root / "openssl.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n")
        cls.openssl_run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "7",
                        "-subj", "/CN=Sync test root", "-addext", "basicConstraints=critical,CA:TRUE",
                        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-config", "openssl.cnf")
        cls.material = {name: cls.issue(name) for name in ("old.example.com", "site.example.com", "sub.example.com")}

    @classmethod
    def openssl_run(cls, *args):
        subprocess.run([cls.openssl, *args], cwd=cls.ca_root, check=True, capture_output=True, timeout=20)

    @classmethod
    def issue(cls, domain, days="3"):
        cls.openssl_run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                        "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=" + domain,
                        "-config", "openssl.cnf")
        (cls.ca_root / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                            "extendedKeyUsage=serverAuth\nsubjectAltName=DNS:" + domain + "\n")
        cls.openssl_run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                        "-CAcreateserial", "-out", "leaf.pem", "-days", days, "-extfile", "leaf.ext")
        return (cls.ca_root / "leaf.pem").read_bytes(), (cls.ca_root / "leaf.key").read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="sb-sync-root-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        code, out, err = self.invoke("install", "--site", "site.example.com", "--subscription-domain", "sub.example.com",
                                     "--email", "admin@example.com", "--without-rules")
        self.assertEqual(code, 0, err)
        saved, secret = state.load(self.root)
        saved["domains"]["site_aliases"].append("old.example.com")
        for path, content in cli.compile_files(self.root, saved, secret).items():
            self.write(path, content)
        for name, material in self.material.items():
            self.write_pair("/etc/sb/certificates/" + name, material)
            self.write_pair("/etc/letsencrypt/live/" + name, self.issue(name))
        self.write("/etc/letsencrypt/live/old.example.com/fullchain.pem", b"broken old lineage")
        self.real_validate = certificates.validate_pair
        patch = mock.patch.object(certificates, "validate_pair", side_effect=self.validate_with_test_ca)
        patch.start()
        self.addCleanup(patch.stop)

    def validate_with_test_ca(self, *args, **kwargs):
        return self.real_validate(*args, **dict(kwargs, openssl=self.openssl, ca_file=self.ca))

    def write(self, path, content):
        target = state.logical_path(self.root, path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    def write_pair(self, directory, material):
        for name, body in zip(("fullchain.pem", "privkey.pem"), material):
            self.write(directory + "/" + name, body)

    def invoke(self, *words):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--root", str(self.root), "--offline", *words])
        return code, out.getvalue(), err.getvalue()

    def invoke_live(self):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(cli.system, "require_linux_root"), mock.patch.object(cli.os, "umask"), \
             mock.patch.object(bootstrap, "recover_acme"), mock.patch.object(certsync, "_permissions"), \
             mock.patch.object(cli.system, "run") as run, \
             mock.patch.object(certsync, "_check_served_certificate") as served, \
             mock.patch.object(probe, "local_nodes") as probes, \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--root", str(self.root), "cert", "sync"])
        return code, json.loads(out.getvalue()), err.getvalue(), run, served, probes

    def move_hy2_to_old_domain(self):
        saved, secret = state.load(self.root)
        next(node for node in saved["nodes"] if node["protocol"] == "hysteria2")["sni"] = "old.example.com"
        cli.add_local(saved, secret, protocol="hysteria2", name="Healthy HY2", port=4443, offline=True)
        for path, content in cli.compile_files(self.root, saved, secret).items():
            self.write(path, content)

    def test_cli_sync_copies_healthy_renewals_despite_invalid_old_lineage(self):
        old = state.logical_path(self.root, "/etc/sb/certificates/old.example.com/fullchain.pem").read_bytes()
        code, out, err = self.invoke("cert", "sync", "--scheduled")
        for name in ("site.example.com", "sub.example.com"):
            self.assertEqual(state.logical_path(self.root, "/etc/sb/certificates/" + name + "/fullchain.pem").read_bytes(),
                             state.logical_path(self.root, "/etc/letsencrypt/live/" + name + "/fullchain.pem").read_bytes(),
                             "healthy renewed certificate was starved by the old lineage")
        self.assertEqual(state.logical_path(self.root, "/etc/sb/certificates/old.example.com/fullchain.pem").read_bytes(), old)
        self.assertEqual(code, 1, "a skipped broken lineage must not report complete success")
        result = json.loads(out)
        self.assertEqual(result["failed"][0]["domain"], "old.example.com")
        self.assertTrue(result["failed"][0]["copy_valid"])
        self.assertIn("old.example.com", err)

    def test_valid_old_copy_allows_healthy_service_activation_without_state_changes(self):
        before = {path: state.logical_path(self.root, path).read_bytes()
                  for path in (state.STATE, state.SECRETS, "/var/lib/sb/subscription/runtime.json")}
        code, result, _, run, served, probes = self.invoke_live()
        self.assertEqual(code, 1)
        self.assertEqual(set(result["activated"]), {"nginx", "sb-sing-box"})
        self.assertFalse(result["deferred"])
        run.assert_any_call(["systemctl", "reload", "nginx"])
        run.assert_any_call(["systemctl", "restart", "sb-sing-box"])
        self.assertEqual({call.args[0] for call in served.call_args_list}, {"site.example.com", "sub.example.com"})
        self.assertEqual(len(probes.call_args.args[0]["nodes"]), 1)
        for path, content in before.items():
            self.assertEqual(state.logical_path(self.root, path).read_bytes(), content)

    def test_missing_or_damaged_old_copy_defers_nginx_but_healthy_hy2_is_reloaded(self):
        for damaged in (None, b"damaged"):
            with self.subTest(damaged=damaged):
                path = state.logical_path(self.root, "/etc/sb/certificates/old.example.com/fullchain.pem")
                if damaged is None:
                    path.unlink()
                else:
                    path.write_bytes(damaged)
                # Restore distinct healthy copies so both iterations renew.
                for name in ("site.example.com", "sub.example.com"):
                    self.write_pair("/etc/sb/certificates/" + name, self.material[name])
                code, result, _, run, _, _ = self.invoke_live()
                self.assertEqual(code, 1)
                self.assertEqual(set(result["applied"]), {"site.example.com", "sub.example.com"})
                self.assertEqual(set(result["activated"]), {"sb-sing-box"})
                self.assertEqual(result["deferred"]["nginx"]["blocked_by"], ["old.example.com"])
                self.assertFalse(result["failed"][0]["copy_loadable"])
                self.assertNotIn(mock.call(["systemctl", "reload", "nginx"]), run.call_args_list)
                self.assertNotIn(mock.call(["systemctl", "restart", "nginx"]), run.call_args_list)

    def test_expired_old_copy_allows_nginx_reload_but_does_not_restart_dependent_hy2(self):
        self.move_hy2_to_old_domain()
        self.write_pair("/etc/sb/certificates/old.example.com", self.issue("old.example.com", days="0"))
        code, result, _, run, served, _ = self.invoke_live()
        self.assertEqual(code, 1)
        self.assertEqual(set(result["activated"]), {"nginx"})
        self.assertEqual(result["deferred"]["sb-sing-box"]["blocked_by"], ["old.example.com"])
        self.assertFalse(result["failed"][0]["copy_valid"])
        self.assertTrue(result["failed"][0]["copy_loadable"])
        self.assertNotIn(mock.call(["systemctl", "restart", "sb-sing-box"]), run.call_args_list)
        self.assertNotIn("old.example.com", {call.args[0] for call in served.call_args_list})

    def test_repaired_dependency_retries_unchanged_certificates_from_persistent_queue(self):
        self.move_hy2_to_old_domain()
        self.write("/etc/sb/certificates/old.example.com/fullchain.pem", b"broken copy")
        _, first, _, first_run, _, _ = self.invoke_live()
        self.assertEqual(set(first["deferred"]), {"nginx", "sb-sing-box"})
        self.assertFalse(first["activated"])
        self.assertFalse(first_run.called)
        self.write_pair("/etc/sb/certificates/old.example.com", self.material["old.example.com"])
        code, second, _, run, _, _ = self.invoke_live()
        self.assertEqual(code, 1)  # The broken ACME lineage remains visible.
        self.assertEqual(second["applied"], [])
        self.assertEqual(set(second["activated"]), {"nginx", "sb-sing-box"})
        self.assertFalse(second["deferred"])
        run.assert_any_call(["systemctl", "restart", "sb-sing-box"])
        self.assertEqual(json.loads(state.logical_path(self.root, certsync.PENDING).read_bytes()), {})

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "POSIX root is required to verify real service group ownership")
    def test_deferred_services_keep_healthy_copies_readable_by_service_group(self):
        import grp
        self.move_hy2_to_old_domain()
        self.write("/etc/sb/certificates/old.example.com/fullchain.pem", b"broken copy")
        saved, secret = state.load(self.root)
        # Use a distinct numeric group in the isolated tree, without creating
        # or changing any real service account.
        gid = 65534 if os.getgid() != 65534 else 65533
        group = mock.Mock(gr_gid=gid)
        with mock.patch.object(grp, "getgrnam", return_value=group), \
             mock.patch.object(certsync, "_activate_service") as activate:
            result = certsync.synchronize(saved, secret, self.root)
        self.assertEqual(set(result["deferred"]), {"nginx", "sb-sing-box"})
        activate.assert_not_called()
        for name in ("site.example.com", "sub.example.com"):
            for path in certificates.cert_paths(name):
                target = state.logical_path(self.root, path)
                self.assertEqual(target.stat().st_gid, gid, "committed healthy certificate lost its service-readable group")
                self.assertEqual(target.stat().st_mode & 0o777, 0o640)
                self.assertEqual(target.parent.stat().st_gid, gid)
                self.assertEqual(target.parent.stat().st_mode & 0o777, 0o750)
        journal = state.logical_path(self.root, "/var/backups/sb/transactions/" + result["transaction"] + "/journal.json")
        self.assertEqual(json.loads(journal.read_bytes())["status"], "committed")

    def test_reload_failure_keeps_retry_queue_and_does_not_roll_back_healthy_files(self):
        saved, secret = state.load(self.root)
        with mock.patch.object(certsync, "_permissions"), \
             mock.patch.object(certsync, "_activate_service", side_effect=RuntimeError("reload failed")):
            result = certsync.synchronize(saved, secret, self.root)
        self.assertEqual(set(result["deferred"]), {"nginx", "sb-sing-box"})
        self.assertFalse(result["activated"])
        for name in ("site.example.com", "sub.example.com"):
            self.assertEqual(state.logical_path(self.root, "/etc/sb/certificates/" + name + "/fullchain.pem").read_bytes(),
                             state.logical_path(self.root, "/etc/letsencrypt/live/" + name + "/fullchain.pem").read_bytes())
        self.assertEqual(set(json.loads(state.logical_path(self.root, certsync.PENDING).read_bytes())), {"nginx", "sb-sing-box"})

    def test_permission_failure_rolls_back_copy_and_queue_before_service_activation(self):
        saved, secret = state.load(self.root)
        before = {path: state.logical_path(self.root, path).read_bytes()
                  for domain in ("site.example.com", "sub.example.com") for path in certificates.cert_paths(domain)}
        with mock.patch.object(certsync, "_permissions", side_effect=PermissionError("service group unavailable")), \
             mock.patch.object(certsync, "_activate_service") as activate, \
             self.assertRaisesRegex(PermissionError, "service group unavailable"):
            certsync.synchronize(saved, secret, self.root)
        activate.assert_not_called()
        for path, body in before.items():
            self.assertEqual(state.logical_path(self.root, path).read_bytes(), body)
        self.assertFalse(state.logical_path(self.root, certsync.PENDING).exists())
        records = [json.loads(path.read_bytes()) for path in (self.root / "var/backups/sb/transactions").glob("*/journal.json")]
        self.assertEqual(next(record for record in records if record["label"] == "certificate copies")["status"], "rolled-back")

    def test_process_death_after_copy_commit_retries_activation_with_unchanged_lineages(self):
        script = """
import os, sys
from pathlib import Path
from sbmanager import certificates, certsync, state
root = Path(sys.argv[1])
validate = certificates.validate_pair
certificates.validate_pair = lambda *a, **kw: validate(*a, **dict(kw, ca_file=Path(sys.argv[2])))
certsync._permissions = lambda *a: None
certsync._activate_service = lambda *a: os._exit(91)
saved, secret = state.load(root)
certsync.synchronize(saved, secret, root)
"""
        process = subprocess.run([sys.executable, "-c", script, str(self.root), str(self.ca)],
                                 capture_output=True, timeout=30)
        self.assertEqual(process.returncode, 91, process.stderr.decode())
        queue = json.loads(state.logical_path(self.root, certsync.PENDING).read_bytes())
        self.assertEqual(set(queue), {"nginx", "sb-sing-box"})
        code, result, _, _, _, _ = self.invoke_live()
        self.assertEqual(code, 1)  # Broken historical lineage still reported.
        self.assertEqual(result["applied"], [])
        self.assertEqual(set(result["activated"]), {"nginx", "sb-sing-box"})
        self.assertEqual(json.loads(state.logical_path(self.root, certsync.PENDING).read_bytes()), {})

    def test_real_tls_endpoint_must_serve_the_exact_managed_certificate(self):
        domain = "site.example.com"
        expected = self.material[domain]
        different = self.issue(domain)
        client_context = ssl.create_default_context(cafile=str(self.ca))
        connect = socket.create_connection
        for served, matches in ((expected, True), (different, False)):
            with self.subTest(matches=matches):
                self.write_pair("/tls-endpoint", served)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(self.root / "tls-endpoint/fullchain.pem", self.root / "tls-endpoint/privkey.pem")
                errors = []
                with socket.socket() as listener:
                    listener.bind(("127.0.0.1", 0))
                    listener.listen()
                    listener.settimeout(5)
                    port = listener.getsockname()[1]
                    def serve():
                        try:
                            connection, _ = listener.accept()
                            with connection, context.wrap_socket(connection, server_side=True):
                                pass
                        except Exception as exc:
                            errors.append(exc)
                    worker = threading.Thread(target=serve)
                    worker.start()
                    with mock.patch.object(certsync.ssl, "create_default_context", return_value=client_context), \
                         mock.patch.object(certsync.socket, "create_connection",
                                           side_effect=lambda addr, timeout: connect(("127.0.0.1", port), timeout)):
                        if matches:
                            certsync._check_served_certificate(domain, self.root)
                        else:
                            with self.assertRaisesRegex(RuntimeError, "previous certificate"):
                                certsync._check_served_certificate(domain, self.root)
                    worker.join(timeout=5)
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors)

    def test_legacy_core_dependencies_use_the_registered_systemd_service_name(self):
        saved, secret = state.load(self.root)
        saved["legacy"]["services"] = ["sb-sing-box-legacy.service"]
        self.write(state.STATE, state.encode(saved))
        self.write("/etc/sing-box/sb-legacy/config.json", json.dumps({"inbounds": [{"tls": {
            "certificate_path": "/etc/sb/certificates/site.example.com/fullchain.pem",
            "key_path": "/etc/sb/certificates/site.example.com/privkey.pem"}}]}).encode())
        self.write("/etc/systemd/system/sb-sing-box-legacy.service",
                   b"[Service]\nExecStart=/opt/sb/legacy/fixture/sing-box run -c /etc/sing-box/sb-legacy/config.json\n")
        code, result, _, run, _, _ = self.invoke_live()
        self.assertEqual(code, 1)
        self.assertIn("sb-sing-box-legacy.service", result["activated"])
        run.assert_any_call(["/opt/sb/legacy/fixture/sing-box", "check", "-c", "/etc/sing-box/sb-legacy/config.json"])
        run.assert_any_call(["systemctl", "restart", "sb-sing-box-legacy.service"])

    def test_domain_retirement_removes_only_obsolete_queue_dependencies(self):
        self.write(certsync.PENDING, state.encode({"nginx": ["old.example.com", "sub.example.com"],
                                                 "sb-sing-box": ["site.example.com"]}))
        code, _, err = self.invoke("domain", "retire", "old.example.com")
        self.assertEqual(code, 0, err)
        saved, secret = state.load(self.root)
        with mock.patch.object(certificates, "stage_sync", return_value=({}, [])):
            result = certsync.synchronize(saved, secret, self.root, offline=True)
        self.assertEqual(result["deferred"]["nginx"]["domains"], ["sub.example.com"])
        self.assertEqual(json.loads(state.logical_path(self.root, certsync.PENDING).read_bytes()),
                         {"nginx": ["sub.example.com"], "sb-sing-box": ["site.example.com"]})

    def test_known_service_spellings_merge_but_unknown_services_reject_before_copy(self):
        saved, secret = state.load(self.root)
        self.write(certsync.PENDING, state.encode({"nginx.service": ["site.example.com"],
                                                 "nginx": ["sub.example.com"],
                                                 "sb-sing-box.service": ["site.example.com"],
                                                 "sb-sing-box-legacy": ["old.example.com"]}))
        with mock.patch.object(certificates, "stage_sync", return_value=({}, [])):
            result = certsync.synchronize(saved, secret, self.root, offline=True)
        expected = {"nginx": ["site.example.com", "sub.example.com"], "sb-sing-box": ["site.example.com"]}
        self.assertEqual(json.loads(state.logical_path(self.root, certsync.PENDING).read_bytes()), expected)
        self.assertEqual({service: item["domains"] for service, item in result["deferred"].items()}, expected)
        healthy = "/etc/sb/certificates/site.example.com/fullchain.pem"
        before = state.logical_path(self.root, healthy).read_bytes()
        for name in ("unknown.service", "nginx;false", "sb-sing-box-legacy-unowned.service"):
            with self.subTest(service=name):
                self.write(certsync.PENDING, state.encode({name: ["site.example.com"]}))
                with mock.patch.object(certificates, "stage_sync", return_value=({healthy: b"validated renewal"}, [])), \
                     self.assertRaisesRegex(ValueError, "Invalid certificate activation queue"):
                    certsync.synchronize(saved, secret, self.root, offline=True)
                self.assertEqual(state.logical_path(self.root, healthy).read_bytes(), before)

    def test_short_legacy_service_name_has_the_same_dependency_identity(self):
        saved, _ = state.load(self.root)
        self.write("/etc/sing-box/sb-legacy/config.json", json.dumps({"inbounds": [{"tls": {
            "certificate_path": "/etc/sb/certificates/old.example.com/fullchain.pem"}}]}).encode())
        for spelling in ("sb-sing-box-legacy", "sb-sing-box-legacy.service"):
            with self.subTest(service=spelling):
                saved["legacy"]["services"] = [spelling]
                self.assertEqual(certsync.dependencies(saved, self.root)["sb-sing-box-legacy.service"], {"old.example.com"})


class CertSyncRetirementTests(unittest.TestCase):
    def test_real_last_legacy_retirement_cannot_starve_a_healthy_renewal(self):
        # Exercise actual inspect/prepare/retire control flow. Only stage_sync's
        # already-validated byte boundary is replaced; the queue and file
        # transaction remain real throughout.
        from test_migration import MigrationTests
        fixture = MigrationTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.core({"type": "vmess", "listen": "127.0.0.1", "listen_port": 14443,
                      "users": [{"uuid": "12345678-1234-4234-9234-123456789012"}],
                      "transport": {"type": "http", "path": "/node", "headers": {"host": "old.example.com"}},
                      "tls": {"enabled": True}})
        fixture.caddy(True)
        current, private, files = migration.prepare(migration.inspect(fixture.root), fixture.current, fixture.private)
        fixture.apply_files(files)
        fixture.put("/etc/sing-box/sb/config.json", '{"inbounds": []}')
        with mock.patch.object(certificates, "stage_sync", return_value=({
                "/etc/sb/certificates/old.example.com/fullchain.pem": b"validated old-domain renewal"}, [])):
            initial = certsync.synchronize(current, private, fixture.root, offline=True)
        self.assertIn(migration.LEGACY_SERVICE, initial["deferred"])
        current, private, files = migration.retire(fixture.root, current, private, current["nodes"][0]["id"])
        fixture.apply_files(files)
        self.assertEqual(current["legacy"]["services"], [])
        healthy = "/etc/sb/certificates/sub.example.com/fullchain.pem"
        with mock.patch.object(certificates, "stage_sync", return_value=({healthy: b"validated healthy renewal"}, [])):
            result = certsync.synchronize(current, private, fixture.root, offline=True)
        self.assertEqual(state.logical_path(fixture.root, healthy).read_bytes(), b"validated healthy renewal")
        self.assertNotIn(migration.LEGACY_SERVICE, result["deferred"])
        queue = json.loads(state.logical_path(fixture.root, certsync.PENDING).read_bytes())
        self.assertNotIn(migration.LEGACY_SERVICE, queue)
        self.assertEqual(queue["nginx"], ["old.example.com", "sub.example.com"])


if __name__ == "__main__":
    unittest.main()
