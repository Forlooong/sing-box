import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from tests import soak_client as soak


def fixture():
    proxies = [
        {"name": "REALITY", "type": "vless", "server": "127.0.0.1", "port": 443,
         "uuid": "sensitive-uuid", "tls": True, "reality-opts": {"public-key": "sensitive-public"}},
        {"name": "HY2", "type": "hysteria2", "server": "127.0.0.1", "port": 443,
         "password": "sensitive-password", "sni": "site.example.com"}]
    config = {"proxies": proxies, "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": [p["name"] for p in proxies]}],
              "rules": ["RULE-SET,fixture,DIRECT", "MATCH,节点选择"],
              "rule-providers": {"fixture": {"type": "http", "behavior": "domain", "format": "text",
                                            "url": "https://rules.example.com/rules.txt", "path": "./rules/fixture.txt"}},
              "dns": {"enable": True, "listen": "0.0.0.0:53", "enhanced-mode": "fake-ip", "nameserver": ["1.1.1.1"]}}
    bundle = {"proxies": copy.deepcopy(proxies), "site_url": "https://site.example.com/",
              "subscription_url": "https://sub.example.com/private-sensitive-token", "expected_site_sha256": "a" * 64}
    return config, bundle


class SoakConfigTests(unittest.TestCase):
    def test_initial_http_provider_timeout_is_retried_before_readiness_passes(self):
        config, _ = fixture()
        clock, ready, updates = FakeClock(), [False], []
        def api(path, method="GET", payload=None, **kwargs):
            if path == "/providers/rules/fixture" and method == "PUT":
                updates.append(path)
                ready[0] = True
            if path == "/providers/rules":
                return {"providers": {"fixture": {"ruleCount": 10 if ready[0] else 0}}}
            return None
        with tempfile.TemporaryDirectory() as raw:
            client = soak.Client(Path(raw) / "client", Path("unused"), "reality")
            self.addCleanup(client.log.close)
            client.process = SimpleNamespace(poll=lambda: None)
            with patch.object(client, "api", side_effect=api), patch.object(client, "verify_selection"), \
                 patch.object(soak.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
                 patch.object(soak.time, "sleep", side_effect=clock.sleep), \
                 patch.object(soak.time, "monotonic", side_effect=clock.time):
                client.configure(config, {"reality": "REALITY"})
        self.assertEqual(len(updates), 1)
        self.assertTrue(ready[0])

    def test_provider_retry_never_accepts_missing_data_or_runs_unbounded(self):
        clock, updates = FakeClock(), []
        def api(path, method="GET", payload=None, **kwargs):
            if method == "PUT":
                updates.append(path)
                raise TimeoutError()
            return {"providers": {"fixture": {"ruleCount": 0}}}
        with tempfile.TemporaryDirectory() as raw:
            client = soak.Client(Path(raw) / "client", Path("unused"), "reality")
            self.addCleanup(client.log.close)
            client.process = SimpleNamespace(poll=lambda: None)
            client.expected_providers = {"fixture"}
            client.provider_types = {"fixture": "http"}
            with patch.object(client, "api", side_effect=api), \
                 patch.object(soak.time, "sleep", side_effect=clock.sleep), \
                 patch.object(soak.time, "monotonic", side_effect=clock.time):
                with self.assertRaisesRegex(soak.Error, "rule_providers_not_ready"):
                    client.wait_providers()
        self.assertEqual(len(updates), 2)
        self.assertEqual(client.provider_retry_failures, 2)
        self.assertLess(clock.now, 121)

    def test_complete_subscription_matches_credentials_and_renamed_nodes(self):
        config, bundle = fixture()
        config["proxies"][0]["name"] = "重命名"
        config["proxy-groups"][0]["proxies"][0] = "重命名"
        with patch.object(soak.acceptance, "get_https", return_value=(yaml.safe_dump(config).encode(), {"Profile-Update-Interval": "12"})):
            loaded, selected = soak.fetch_subscription(bundle)
        self.assertEqual(loaded, config)
        self.assertEqual(selected, {"reality": "重命名", "hy2": "HY2"})
        config["proxies"][1]["password"] = "wrong"
        with patch.object(soak.acceptance, "get_https", return_value=(yaml.safe_dump(config).encode(), {"Profile-Update-Interval": "12"})):
            with self.assertRaisesRegex(soak.Error, "node_mismatch"):
                soak.fetch_subscription(bundle)

    def test_isolation_preserves_nodes_groups_rules_and_dns_except_listener(self):
        config, _ = fixture()
        original = copy.deepcopy(config)
        config.update({"tun": {"enable": True, "auto-route": True, "auto-redirect": True},
            "external-controller-unix": "/tmp/controller", "external-controller-tls": "0.0.0.0:4443",
            "listeners": [{"type": "tun"}], "tunnels": ["dangerous"], "authentication": ["a:b"],
            "external-ui-url": "https://example.com/ui", "ntp": {"enable": True, "write-to-system": True}})
        value = soak.isolated_config(config, 11111, 11112, 11113, "random-secret")
        for name in ("proxies", "proxy-groups", "rules", "rule-providers"):
            self.assertEqual(value[name], original[name])
        dns = copy.deepcopy(original["dns"])
        dns["listen"] = "127.0.0.1:11113"
        self.assertEqual(value["dns"], dns)
        self.assertFalse(value["tun"]["enable"])
        self.assertFalse(value["tun"]["auto-route"])
        self.assertFalse(value["ntp"]["write-to-system"])
        self.assertFalse(value["allow-lan"])
        self.assertEqual(value["listeners"], [])
        self.assertNotIn("external-controller-unix", value)
        self.assertEqual(value["external-controller"], "127.0.0.1:11112")
        self.assertEqual(config["dns"]["listen"], "0.0.0.0:53")

    def test_provider_paths_cannot_escape_private_directory(self):
        config, bundle = fixture()
        for value in ("/etc/fixture", "../escape", "rules/../../escape", "C:\\escape"):
            config["rule-providers"]["fixture"]["path"] = value
            with patch.object(soak.acceptance, "get_https", return_value=(yaml.safe_dump(config).encode(), {"Profile-Update-Interval": "12"})):
                with self.assertRaisesRegex(soak.Error, "provider_path"):
                    soak.fetch_subscription(bundle)

    def test_timing_boundaries(self):
        for value in ("nan", "inf", "-1", "0", "86401", "word"):
            with self.assertRaises(Exception):
                soak.bounded_seconds(value)
        args = soak.parser().parse_args(["--bundle", "/private/bundle"])
        self.assertEqual((args.duration, args.interval, args.refresh_interval), (3600, 30, 300))


class FakeClock:
    def __init__(self):
        self.now = 0
    def time(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class FakeClient:
    def __init__(self, protocol, fail_once=False, exit_code=None):
        self.protocol, self.fail_once, self.exit_code = protocol, fail_once, exit_code
        self.requests, self.refreshes = 0, 0
    def request(self, bundle):
        self.requests += 1
        if self.fail_once and self.requests == 1:
            raise soak.Error("proxied_https_failed")
        self.alive()
    def alive(self):
        if self.exit_code is not None:
            raise soak.Error("client_process_exited")
    def status(self):
        return {"exit_code": self.exit_code, "rss_kib": 12000}
    def configure(self, config, selected):
        self.refreshes += 1
    def verify_selection(self):
        self.alive()


class SoakLoopTests(unittest.TestCase):
    def test_process_exit_in_final_sleep_cannot_report_passed(self):
        clock, events = FakeClock(), []
        clients = [FakeClient("reality"), FakeClient("hy2")]
        def fail_during_last_sleep(seconds):
            clock.sleep(seconds)
            clients[0].exit_code = 7
        summary = soak.cycle(clients, {}, 3, 3, 30, events.append,
                             clock=clock.time, sleep=fail_during_last_sleep)
        self.assertEqual(summary["status"], "failed")
        final = [event for event in events if event["event"] == "client_final" and event["protocol"] == "reality"]
        self.assertEqual(len(final), 1)
        self.assertEqual(final[0]["exit_code"], 7)
        self.assertEqual(final[0]["category"], "client_process_exited")

    def test_full_window_continues_after_request_failure_and_refreshes(self):
        clock, events = FakeClock(), []
        clients = [FakeClient("reality", True), FakeClient("hy2")]
        with patch.object(soak, "fetch_subscription", return_value=({}, {})):
            summary = soak.cycle(clients, {}, 5, 1, 2, events.append, clock=clock.time, sleep=clock.sleep)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["traffic"]["reality"], {"passed": 4, "failed": 1})
        self.assertEqual(summary["traffic"]["hy2"], {"passed": 5, "failed": 0})
        self.assertEqual(summary["refreshes_passed"], 2)
        self.assertEqual([c.refreshes for c in clients], [2, 2])
        self.assertEqual(len([e for e in events if e["event"] == "traffic"]), 10)
        self.assertTrue(all(e["rss_kib"] == 12000 for e in events if e["event"] == "traffic"))

    def test_process_exit_is_recorded_before_failure(self):
        clock, events = FakeClock(), []
        with self.assertRaisesRegex(soak.Error, "process_exited"):
            soak.cycle([FakeClient("reality", exit_code=7)], {}, 5, 1, 2, events.append,
                       clock=clock.time, sleep=clock.sleep)
        self.assertEqual(events[0]["exit_code"], 7)
        self.assertEqual(events[0]["status"], "failed")

    def test_failed_refresh_is_not_counted_as_success(self):
        clock, events = FakeClock(), []
        with patch.object(soak, "fetch_subscription", side_effect=soak.Error("subscription_bundle_node_mismatch")):
            summary = soak.cycle([FakeClient("reality"), FakeClient("hy2")], {}, 3, 1, 1, events.append,
                                 clock=clock.time, sleep=clock.sleep)
        self.assertEqual(summary["status"], "failed")
        self.assertEqual(summary["refreshes_failed"], 2)
        self.assertEqual(summary["refreshes_passed"], 0)

    def test_failure_report_never_prints_exception_or_bundle_secrets(self):
        config, bundle = fixture()
        stream = io.StringIO()
        with patch.object(soak.acceptance, "load_bundle", return_value=bundle), \
             patch.object(soak, "fetch_subscription", side_effect=ValueError(bundle["subscription_url"])), \
             patch.object(soak.sys, "platform", "linux"), patch.object(soak.shutil, "which", return_value="curl"), \
             contextlib.redirect_stdout(stream):
            result = soak.main(["--bundle", "ignored", "--duration", "1", "--interval", "1"])
        self.assertEqual(result, 1)
        report = stream.getvalue()
        self.assertNotIn("private-sensitive-token", report)
        self.assertNotIn("sensitive-password", report)
        final = json.loads(report.splitlines()[-1])
        self.assertEqual(final["category"], "invalid_input_or_response")

    def test_startup_failure_closes_client_and_removes_private_directory(self):
        config, bundle = fixture()
        opened, closed = [], []
        class FailingClient:
            def __init__(self, directory, binary, protocol):
                self.protocol, self.directory = protocol, directory
                directory.mkdir()
                (directory / "private-config").write_text("sensitive-password")
                opened.append(directory)
            def configure(self, *args):
                raise ValueError("sensitive-password")
            def status(self):
                return {"pid": None, "exit_code": None, "rss_kib": None}
            def close(self):
                closed.append(self.directory)
        stream = io.StringIO()
        with patch.object(soak.acceptance, "load_bundle", return_value=bundle), \
             patch.object(soak, "fetch_subscription", return_value=(config, {})), \
             patch.object(soak, "download_cores", return_value={"mihomo": "fixture"}), \
             patch.object(soak, "Client", FailingClient), patch.object(soak.sys, "platform", "linux"), \
             patch.object(soak.shutil, "which", return_value="curl"), contextlib.redirect_stdout(stream):
            self.assertEqual(soak.main(["--bundle", "ignored", "--duration", "1", "--interval", "1"]), 1)
        self.assertEqual(opened, closed)
        self.assertFalse(any(path.exists() for path in opened))
        self.assertNotIn("sensitive-password", stream.getvalue())

    def test_report_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "report.jsonl"
            path.write_text("existing report")
            with patch.object(soak.sys, "platform", "linux"), patch.object(soak.shutil, "which", return_value="curl"), \
                 contextlib.redirect_stdout(io.StringIO()), patch.object(soak.acceptance, "load_bundle") as load:
                result = soak.main(["--bundle", "ignored", "--output", str(path), "--duration", "1", "--interval", "1"])
            self.assertEqual(result, 1)
            load.assert_not_called()
            self.assertEqual(path.read_text(), "existing report")


if __name__ == "__main__":
    unittest.main()
