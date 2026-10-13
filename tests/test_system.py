from pathlib import Path
from types import SimpleNamespace
from unittest import mock
import tempfile
import unittest

from sbmanager import state, system


class SystemTests(unittest.TestCase):
    def test_candidate_keeps_distro_module_prefix_and_uses_staged_includes(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name) / "live"
            stage = Path(name) / "stage"
            for folder in (root / "etc/nginx", stage / "etc/nginx/sb"):
                folder.mkdir(parents=True)
            (root / "etc/nginx/nginx.conf").write_text("events {} http {}")
            (stage / "etc/nginx/nginx.conf").write_text(
                "load_module modules/ngx_stream_module.so;\nevents {}\n"
                "http { include /etc/nginx/sb/http.conf; }\n")
            (stage / "etc/nginx/sb/http.conf").write_text("server { listen 127.0.0.1:8444; }")
            with mock.patch.object(system, "require_linux_root"), mock.patch.object(system, "run") as run:
                system.validate_candidate(stage, root=root)
            candidate = stage / "nginx-validation/nginx.conf"
            run.assert_called_once_with(["nginx", "-t", "-c", candidate])
            self.assertIn("load_module modules/ngx_stream_module.so;", candidate.read_text())
            self.assertIn(str(stage / "nginx-validation/sb/http.conf"), candidate.read_text())
            self.assertIn("include /etc/nginx/sb/http.conf;", (stage / "etc/nginx/nginx.conf").read_text())

    def test_modified_managed_stream_include_is_rejected(self):
        managed = system.patch_nginx("events {}\nhttp {}\n")
        self.assertEqual(system.patch_nginx(managed), managed)
        for changed in (managed.replace("include /etc/nginx/sb/stream.conf;", ""),
                        managed + "include /etc/nginx/sb/stream.conf;\n"):
            with self.assertRaisesRegex(ValueError, "includes were modified"):
                system.patch_nginx(changed)

    def test_each_service_must_be_active_not_just_one(self):
        saved, secret = state.create("site.example.com", "sub.example.com", "admin@example.com")
        saved["legacy"]["services"] = ["sb-sing-box-legacy.service"]
        calls = []
        def run(argv, **_):
            calls.append(argv)
            if argv[-1] == "sb-sing-box-legacy.service":
                raise RuntimeError("legacy inactive")
        with mock.patch.object(system, "run", side_effect=run):
            with self.assertRaisesRegex(RuntimeError, "legacy inactive"):
                system.health(saved, secret)
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(len(call) == 4 for call in calls))

    def test_install_opens_new_website_parent_and_subscription_change_only_reloads(self):
        saved, _ = state.create("site.example.com", "sub.example.com", "admin@example.com")
        record = {"directories": {"/var/www": {"existed": False}},
                  "changed": ["/var/lib/sb/subscription/runtime.json"],
                  "services": {"sb-sing-box": {"is-active": True}, "sb-subscription": {"is-active": True}}}
        with tempfile.TemporaryDirectory() as name:
            site = Path(name) / "site"
            site.mkdir()
            with mock.patch.object(system, "require_linux_root"), mock.patch.object(system, "permissions"), \
                 mock.patch.object(system, "logical_path", return_value=site), \
                 mock.patch.object(system.os, "chmod") as chmod, mock.patch.object(system, "run") as run, \
                 mock.patch.object(system.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
                system.activate(saved, record)
                chmod.assert_any_call("/var/www", 0o755)
                self.assertIn(mock.call(["systemctl", "reload", "sb-subscription"]), run.call_args_list)
                self.assertNotIn(mock.call(["systemctl", "restart", "sb-sing-box"]), run.call_args_list)
                self.assertIn(mock.call(["systemctl", "start", "certbot.timer", "sb-cert-sync.timer"]), run.call_args_list)
                chmod.reset_mock()
                record["directories"]["/var/www"]["existed"] = True
                system.activate(saved, record)
                self.assertNotIn(mock.call("/var/www", 0o755), chmod.call_args_list)


if __name__ == "__main__":
    unittest.main()
