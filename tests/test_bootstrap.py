from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from sbmanager import bootstrap as b
from sbmanager import state


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="sb-bootstrap-")
        self.root = Path(self.directory.name)
        self.root_patch = patch.object(b, "ROOT", self.root)
        self.root_patch.start()
        self.state, _ = state.create("site.example.com", "sub.example.com", "admin@example.com", "private")

    def tearDown(self):
        self.root_patch.stop()
        self.directory.cleanup()

    def write(self, name, body):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return path

    def test_exact_packages_reject_unreviewed_distro(self):
        for values, expected in (({"ID": "debian", "VERSION_ID": "12"}, "1.30.5-1~bookworm"),
                                 ({"ID": "debian", "VERSION_ID": "13"}, "1.30.5-1~trixie"),
                                 ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "1.30.5-1~noble")):
            self.assertEqual(b.nginx_package_version(values, "1.30.5")[1], expected)
        with self.assertRaises(ValueError):
            b.nginx_package_version({"ID": "ubuntu", "VERSION_ID": "22.04"}, "1.30.5")

    def test_package_guard_failure_removes_own_policy(self):
        with self.assertRaisesRegex(RuntimeError, "package failure"):
            with b.package_service_guard():
                self.assertEqual(b._path(b.POLICY).read_bytes(), b.POLICY_BODY)
                raise RuntimeError("package failure")
        self.assertFalse(b._path(b.POLICY).exists())

    def test_existing_unknown_policy_is_untouched(self):
        content = b"#!/bin/sh\n# site custom policy\nexit 0\n"
        path = self.write(b.POLICY, content)
        with self.assertRaises(RuntimeError):
            with b.package_service_guard():
                self.fail("Unknown policy must not be bypassed")
        self.assertEqual(path.read_bytes(), content)
        path.write_bytes(b"#!/bin/sh\nexit 101\n")
        with b.package_service_guard():
            pass
        self.assertEqual(path.read_bytes(), b"#!/bin/sh\nexit 101\n")

    def test_rollback_restores_replaced_and_removes_new_preparation_files(self):
        original = self.write("/opt/sb/existing", b"before")
        record = {"files": {}, "services": {"nginx": {"is-active": False, "is-enabled": False}}}
        b._remember_write(record, "/opt/sb/existing", b"after")
        b._remember_write(record, "/opt/sb/new", b"new")
        with patch.object(b.system, "restore_services") as restore:
            b.rollback_preparation()
        self.assertEqual(original.read_bytes(), b"before")
        self.assertFalse(b._path("/opt/sb/new").exists())
        self.assertFalse(b._path(b.PREPARATION).exists())
        restore.assert_called_once_with(record["services"])

    def test_interrupted_package_guard_recovered_but_foreign_replacement_preserved(self):
        record = {"files": {}, "services": {}, "owned_guard_created": True}
        b._remember_write(record, b.POLICY, b.POLICY_BODY, 0o755)
        with patch.object(b.system, "restore_services"):
            b.rollback_preparation()
        self.assertFalse(b._path(b.POLICY).exists())
        record["files"] = {}
        b._remember_write(record, b.POLICY, b.POLICY_BODY, 0o755)
        b._path(b.POLICY).write_bytes(b"custom policy")
        with patch.object(b.system, "restore_services") as restore:
            with self.assertRaisesRegex(RuntimeError, "replaced"):
                b.rollback_preparation()
        restore.assert_not_called()
        self.assertEqual(b._path(b.POLICY).read_bytes(), b"custom policy")
        self.assertTrue(b._path(b.PREPARATION).exists())

    def test_interruption_after_install_commit_keeps_active_core(self):
        record = {"files": {}, "services": {}, "installation_id": self.state["installation_id"]}
        b._remember_write(record, "/opt/sb/bin/sing-box", b"active core", 0o755)
        self.write("/etc/sb/state.json", json.dumps(self.state).encode())
        self.write("/var/backups/sb/transactions/installation/stage/etc/sb/state.json", json.dumps(self.state).encode())
        self.write("/var/backups/sb/transactions/installation/journal.json", json.dumps({
            "status": "committed", "label": "install", "files": {"/etc/sb/state.json": {"existed": False}}}).encode())
        with patch.object(b.system, "restore_services") as restore:
            b.rollback_preparation()
        restore.assert_not_called()
        self.assertEqual(b._path("/opt/sb/bin/sing-box").read_bytes(), b"active core")
        self.assertFalse(b._path(b.PREPARATION).exists())

    def test_matching_state_without_committed_install_does_not_skip_rollback(self):
        record = {"files": {}, "services": {}, "installation_id": self.state["installation_id"]}
        b._remember_write(record, "/opt/sb/bin/sing-box", b"uncommitted core", 0o755)
        self.write("/etc/sb/state.json", json.dumps(self.state).encode())
        self.write("/var/backups/sb/transactions/installation/stage/etc/sb/state.json", json.dumps(self.state).encode())
        self.write("/var/backups/sb/transactions/installation/journal.json", json.dumps({
            "status": "applying", "label": "install", "files": {"/etc/sb/state.json": {"existed": False}}}).encode())
        with patch.object(b.system, "restore_services") as restore:
            b.rollback_preparation()
        restore.assert_called_once()
        self.assertFalse(b._path("/opt/sb/bin/sing-box").exists())

    def test_existing_nginx_never_enters_package_install_request(self):
        record = {"files": {}, "services": {}}
        with patch.object(b.shutil, "which", return_value="/usr/sbin/nginx"), \
             patch.object(b, "_nginx_capabilities", return_value={"dynamic_stream": False}), patch.object(b, "_apt") as apt:
            b._install_packages({"ID": "debian", "VERSION_ID": "12"}, {"nginx": "1.30.5"}, record, True)
        self.assertFalse(any(any(str(a).startswith("nginx=") for a in call.args) for call in apt.call_args_list))
        self.assertIn("--no-upgrade", apt.call_args_list[1].args)
        self.assertEqual(set(record["files"]), {b.POLICY})

    def test_distribution_nginx_122_and_124_supported_without_h2_upstream(self):
        for version in ("1.22.1", "1.24.0", "1.30.5"):
            response = SimpleNamespace(returncode=0, stdout=b"", stderr=(
                "nginx version: nginx/" + version + "\nconfigure arguments: --with-http_ssl_module --with-http_v2_module --with-stream=dynamic --with-stream_ssl_preread_module --modules-path=/usr/lib/nginx/modules").encode())
            with patch.object(b, "_probe", return_value=response):
                info = b._nginx_capabilities(self.state)
                self.assertEqual(info["version"], version)
                self.assertEqual(info["legacy_http2_directive"], version != "1.30.5")
                self.state["legacy"]["http_config"] = "proxy_http_version 2;"
                if version != "1.30.5":
                    with self.assertRaisesRegex(RuntimeError, "HTTP/2 upstream"):
                        b._nginx_capabilities(self.state)
                else:
                    b._nginx_capabilities(self.state)
                self.state["legacy"].pop("http_config")

    def test_stream_module_install_uses_exact_existing_nginx_version(self):
        info = {"dynamic_stream": True, "stream_module": "/usr/lib/nginx/modules/ngx_stream_module.so"}
        version = "1.22.1-9+deb12u3"
        def command(argv, **kwargs):
            if argv[0] == "dpkg-query":
                return version
            if argv[0] == "apt-cache":
                return "Package: libnginx-mod-stream\nVersion: " + version + "\nDepends: nginx-abi-1.22.1-7\n"
            if argv == ["nginx", "-T"]:
                return "load_module /usr/lib/nginx/modules/ngx_stream_module.so;\n"
            return ""
        def apt(*args):
            if "--simulate" not in args:
                self.write(info["stream_module"], b"installed module")
            return "Inst libnginx-mod-stream (" + version + " Debian)\n"
        with patch.object(b.system, "run", side_effect=command), patch.object(b, "_apt", side_effect=apt) as execute:
            b._ensure_stream_module(info, {"files": {}, "services": {}})
        self.assertEqual(execute.call_count, 2)
        self.assertIn("libnginx-mod-stream=" + version, execute.call_args.args)
        self.assertIn("nginx=" + version, execute.call_args.args)
        self.assertIn("--no-upgrade", execute.call_args.args)

    def test_stream_module_rejects_package_resolution_that_upgrades_nginx(self):
        info = {"dynamic_stream": True, "stream_module": "/usr/lib/nginx/modules/ngx_stream_module.so"}
        with patch.object(b.system, "run", side_effect=["1.22.1-9", "Package: libnginx-mod-stream\nVersion: 1.22.1-9\n"]), \
             patch.object(b, "_apt", return_value="Inst nginx [1.22.1-9] (1.24.0 Ubuntu)\n") as apt:
            with self.assertRaisesRegex(RuntimeError, "replace existing Nginx"):
                b._ensure_stream_module(info, {"files": {}, "services": {}})
        self.assertEqual(apt.call_count, 1)

    def test_runtime_copy_excludes_credentials_and_test_artifacts(self):
        source = self.root / "source"
        for name in ("versions.json", "LICENSE", "sing-box.sh", "sbmanager/cli.py", "sbmanager/template.yaml", "sbmanager/assets/index.html",
                     "sbmanager/vendor/NOTICE.md",
                     "sbmanager/secret.json", "sbmanager/server.key", "sbmanager/__pycache__/server.pyc"):
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("data")
        files = b.runtime_files(source)
        self.assertIn("/usr/local/bin/sb", files)
        self.assertIn("/opt/sb/current/sbmanager/assets/index.html", files)
        self.assertIn("/opt/sb/current/sbmanager/vendor/NOTICE.md", files)
        self.assertFalse(any("secret" in key or ".key" in key or "__pycache__" in key for key in files))

    def test_failed_second_binary_restores_first_and_services(self):
        source = self.root / "source"
        source.mkdir()
        (source / "versions.json").write_text(json.dumps({"assets": {"sing-box-amd64": {}, "mihomo-amd64": {}}}))
        flags = {"nginx": {"is-active": False, "is-enabled": False}}
        with patch.object(b.system, "os_check", return_value={"ID": "debian", "VERSION_ID": "12"}), \
             patch.object(b.system, "network_preflight"), patch.object(b.system, "service_state", return_value=flags), \
             patch.object(b.system, "restore_services") as restore, patch.object(b, "runtime_files", return_value={}), \
             patch.object(b, "_install_packages"), patch.object(b, "_service_accounts"), \
             patch.object(b.platform, "machine", return_value="x86_64"), \
             patch.object(b.updates, "binary", side_effect=[b"\x7fELFfirst", RuntimeError("checksum")]):
            with self.assertRaisesRegex(RuntimeError, "checksum"):
                b.prepare_host(source, self.state)
        self.assertFalse(b._path("/opt/sb/bin/sing-box").exists())
        self.assertFalse(b._path(b.PREPARATION).exists())
        restore.assert_called_once_with(flags)

    def test_gpg_bundle_must_contain_every_pinned_official_key(self):
        with patch.object(b, "_key_bytes", return_value=b"fake bundle"), \
             patch.object(b.system, "run", return_value="fpr:::::::::0000000000000000000000000000000000000000:") as run:
            with self.assertRaisesRegex(ValueError, "fingerprint"):
                b._nginx_keyring()
        self.assertEqual(run.call_count, 1)  # Failed identity check precedes import/export.

    def test_certificate_renewal_requires_known_authenticator_and_webroot(self):
        path = self.write("/etc/letsencrypt/renewal/site.example.com.conf", b"[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/lib/sb/acme,\n[[webroot_map]]\nsite.example.com = /var/www/subscription-acme\n")
        self.assertEqual(b.renewal_webroot("site.example.com"), "/var/www/subscription-acme")
        for content in (b"[renewalparams]\nauthenticator = standalone\nwebroot_path = /var/lib/sb/acme,\n",
                        b"[renewalparams]\nauthenticator = webroot\nwebroot_path = /srv/another-website,\n"):
            path.write_bytes(content)
            with self.assertRaisesRegex(RuntimeError, "recognized webroot"):
                b.renewal_webroot("site.example.com")

    def test_existing_valid_lineages_preserve_their_enrolled_renewal_roots(self):
        for domain in ("site.example.com", "sub.example.com"):
            self.write("/etc/letsencrypt/renewal/" + domain + ".conf", b"[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/www/subscription-acme,\n")
        with patch.object(b.system, "require_linux_root"), patch.object(b.certificates, "stage_lineage", return_value={"certificate": b"valid"}), \
             patch.object(b, "challenge_listener") as listener:
            b.ensure_certificates(self.state)
        listener.assert_not_called()
        self.assertEqual(self.state["certificates"]["webroots"], {
            "site.example.com": "/var/www/subscription-acme", "sub.example.com": "/var/www/subscription-acme"})

    def test_online_acme_failure_only_reloads_and_removes_temporary_conf(self):
        path = self.write("/etc/nginx/nginx.conf", b"events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n")
        original = path.read_bytes()
        flags = {"nginx": {"is-active": True}, "caddy": {"is-active": False}}
        with patch.object(b.system, "service_state", return_value=flags), patch.object(b.system, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "ACME refused"):
                with b.challenge_listener(self.state, ["sub.example.com"]):
                    self.assertTrue(b._path("/etc/nginx/conf.d/sb-acme-challenge.conf").exists())
                    raise RuntimeError("ACME refused")
        self.assertEqual(path.read_bytes(), original)
        self.assertFalse(b._path("/etc/nginx/conf.d/sb-acme-challenge.conf").exists())
        self.assertEqual([call.args[0] for call in run.call_args_list].count(["systemctl", "reload", "nginx"]), 2)
        self.assertFalse(any("stop" in call.args[0] for call in run.call_args_list))

    def test_caddy_restored_after_acme_failure(self):
        flags = {"nginx": {"is-active": False}, "caddy": {"is-active": True}}
        self.state["legacy"]["switch"] = {"stop_services": ["caddy.service"]}
        def command(argv, **kwargs):
            if argv[-2:] == ["-s", "quit"]:
                (Path(argv[argv.index("-c") + 1]).parent / "nginx.pid").unlink()
            return ""
        with patch.object(b.system, "service_state", return_value=flags), patch.object(b.system, "run", side_effect=command) as run:
            with self.assertRaisesRegex(RuntimeError, "ACME refused"):
                with b.challenge_listener(self.state, ["sub.example.com"]):
                    journal = json.loads(b._path(b.ACME_SESSION).read_bytes())
                    directory = b._path(journal["directory"])
                    (directory / "nginx.pid").write_text("1234")
                    self.write("/proc/1234/cmdline", ("nginx -c " + str(directory / "nginx.conf")).encode())
                    raise RuntimeError("ACME refused")
        calls = [call.args[0] for call in run.call_args_list]
        self.assertIn(["systemctl", "stop", "caddy"], calls)
        self.assertEqual(calls[-1], ["systemctl", "start", "caddy"])
        self.assertTrue(any(call[-2:] == ["-s", "quit"] for call in calls))
        self.assertFalse(b._path(b.ACME_SESSION).exists())

    def test_interrupted_online_acme_recovers_on_next_invocation(self):
        import hashlib
        body = b"owned HTTP challenge config"
        temporary = self.write("/etc/nginx/conf.d/sb-acme-challenge.conf", body)
        self.write(b.ACME_SESSION, json.dumps({"kind": "live-nginx", "sha256": hashlib.sha256(body).hexdigest()}).encode())
        with patch.object(b.system, "run") as run:
            b.recover_acme()
        self.assertFalse(temporary.exists())
        self.assertFalse(b._path(b.ACME_SESSION).exists())
        self.assertEqual(run.call_args.args[0], ["systemctl", "reload", "nginx"])

    def test_acme_recovery_never_signals_reused_process_id(self):
        directory = "/run/sb-acme-" + "a" * 24
        self.write(directory + "/nginx.conf", b"events {}")
        self.write(directory + "/nginx.pid", b"4567")
        self.write("/proc/4567/cmdline", b"unrelated application")
        self.write(b.ACME_SESSION, json.dumps({"kind": "temporary-nginx", "directory": directory, "restore_caddy": True}).encode())
        with patch.object(b.system, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "reused"):
                b.recover_acme()
        run.assert_not_called()
        self.assertTrue(b._path(b.ACME_SESSION).exists())

    def test_unknown_caddy_never_stopped(self):
        flags = {"nginx": {"is-active": False}, "caddy": {"is-active": True}}
        with patch.object(b.system, "service_state", return_value=flags), patch.object(b.system, "run") as run:
            with self.assertRaisesRegex(RuntimeError, "reviewed migration"):
                with b.challenge_listener(self.state, ["sub.example.com"]):
                    self.fail("must refuse")
        run.assert_not_called()

    def test_certbot_no_directory_hooks_and_checked_results(self):
        @contextmanager
        def listener(*args, **kwargs):
            yield
        def stage(lineage, state, root):
            if not issued:
                raise FileNotFoundError()
            return {"/etc/sb/certificates/" + Path(lineage).name + "/fullchain.pem": b"trusted"}
        issued = []
        def run(command, **kwargs):
            issued.append(command)
            domain = command[command.index("--domain") + 1]
            self.write("/etc/letsencrypt/renewal/" + domain + ".conf", b"[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/lib/sb/acme,\n")
        with patch.object(b.system, "require_linux_root"), patch.object(b.certificates, "stage_lineage", side_effect=stage), \
             patch.object(b, "challenge_listener", listener), patch.object(b, "_challenge_webroot", return_value="/var/lib/sb/acme"), \
             patch.object(b.system, "run", side_effect=run):
            files = b.ensure_certificates(self.state, new_install=True)
        self.assertEqual(len(files), 2)
        self.assertEqual(len(issued), 2)
        for command in issued:
            self.assertIn("--no-directory-hooks", command)
            self.assertNotIn("--standalone", command)


if __name__ == "__main__":
    unittest.main()
