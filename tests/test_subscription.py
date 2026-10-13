import base64
import copy
import http.client
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

import yaml

from sbmanager import protocols, server, state, subscription


def fixture():
    public, secrets = state.create("site.example.com", "sub.example.com", "admin@example.com")
    node, credentials = protocols.parse_uri("hy2://password@site.example.com:443?sni=site.example.com#HY2")
    public["nodes"] = [node]
    public["rules"]["enabled"] = False
    secrets["nodes"][node["id"]] = credentials
    return public, secrets


class SubscriptionTests(unittest.TestCase):
    def test_single_group_bundle_and_raw(self):
        public, secrets = fixture()
        files = subscription.render(public, secrets)
        config = yaml.safe_load(files[subscription.DIRECTORY + "/clash.yaml"])
        self.assertEqual(config["proxy-groups"], [{"name": "节点选择", "type": "select", "proxies": ["HY2"]}])
        raw = base64.b64decode(files[subscription.DIRECTORY + "/raw.txt"]).decode()
        self.assertTrue(raw.startswith("hysteria2://"))
        self.assertNotIn("private_key", raw)

    def test_aliases_rotate_together_and_metadata_is_manual(self):
        public, secrets = fixture()
        public["subscription"]["aliases"] = [{"domain": "old.example.com", "prefix": "old/sub", "suffix": "/clash.yaml"}]
        old = secrets["subscription_token"]
        before = subscription.routes(public, old)
        secrets["subscription_token"] = "B" * 43
        after = subscription.routes(public, secrets["subscription_token"])
        self.assertTrue(all(old not in row["path"] for row in after))
        self.assertEqual(len(before), len(after))
        self.assertTrue(any(row["path"].endswith("/clash.yaml") for row in after))
        self.assertEqual(subscription.metadata_headers({"reset_day": 12}), {})
        self.assertEqual(subscription.metadata_headers({"upload": 1, "download": 2, "total": 10, "expire": 200}),
                         {"Subscription-Userinfo": "upload=1; download=2; total=10; expire=200"})
        with self.assertRaises(ValueError):
            subscription.metadata_headers({"total": 10})

    def test_name_collision_and_missing_rules_fail_before_publish(self):
        public, secrets = fixture()
        another = copy.deepcopy(public["nodes"][0])
        another["id"] = "different"
        public["nodes"].append(another)
        with self.assertRaises(ValueError):
            subscription.render(public, secrets)
        public["nodes"].pop()
        public["rules"]["enabled"] = True
        with self.assertRaises(ValueError):
            subscription.render(public, secrets)

    def test_no_template_override_of_groups_or_rules(self):
        for key in ("proxies", "proxy-groups", "rules", "sub-rules", "proxy-providers"):
            with self.assertRaises(ValueError):
                subscription.template_config({key: []})
        self.assertTrue(subscription.template_config({"tun": {"enable": True}})["tun"]["enable"])

    def test_recursive_yaml_and_runtime_oversize_are_rejected(self):
        recursive = yaml.safe_load("dns: &dns\n  fallback: *dns\n")
        with self.assertRaisesRegex(ValueError, "Recursive"):
            subscription.template_config(recursive)
        public, secrets = fixture()
        with patch.object(subscription, "MAX_BUNDLE", 100), self.assertRaisesRegex(ValueError, "resource limit"):
            subscription.render(public, secrets)

    def test_unsupported_legacy_export_is_explicit_and_raw_retained(self):
        public, secrets = fixture()
        public["nodes"].append({"id": "old-quic", "name": "旧 QUIC", "protocol": "vmess", "source": "legacy",
                                "enabled": True, "exportable": False})
        secrets["legacy_uris"] = {"old-quic": "vmess://preserved-legacy-link"}
        files = subscription.render(public, secrets)
        diagnostics = json.loads(files[subscription.DIRECTORY + "/diagnostics.json"])
        self.assertEqual(diagnostics["omitted_nodes"][0]["id"], "old-quic")
        self.assertTrue(diagnostics["omitted_nodes"][0]["raw_preserved"])
        self.assertIn(b"vmess://preserved-legacy-link", base64.b64decode(files[subscription.DIRECTORY + "/raw.txt"]))

    def test_http_routes_host_head_reload_and_token_revocation(self):
        public, secrets = fixture()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            path.write_bytes(subscription.render(public, secrets)[subscription.DIRECTORY + "/runtime.json"])
            service = server.create_server(path, port=0)
            thread = threading.Thread(target=service.serve_forever, daemon=True)
            thread.start()

            def request(route, host="sub.example.com", method="GET"):
                client = http.client.HTTPConnection("127.0.0.1", service.server_port, timeout=3)
                client.request(method, route, headers={"Host": host})
                result = client.getresponse()
                answer = result.status, dict(result.getheaders()), result.read()
                client.close()
                return answer

            try:
                route = subscription.routes(public, secrets["subscription_token"])[0]["path"]
                status, headers, body = request(route)
                self.assertEqual(status, 200)
                self.assertEqual(headers["Profile-Update-Interval"], "12")
                self.assertIn(b"hysteria2", body)
                self.assertEqual(request(route, method="HEAD")[2], b"")
                self.assertEqual(request(route, "other.example.com")[0], 404)
                self.assertEqual(request(route + "?ignored=1")[0], 404)
                self.assertEqual(request("/" + route)[0], 400)
                self.assertEqual(request(route, method="POST")[0], 404)
                self.assertEqual(request("/healthz", "localhost")[0], 200)
                self.assertEqual(request("/healthz")[0], 404)
                for field, values in (("Host", ["sub.example.com", "sub.example.com"]),
                                      ("Content-Length", ["0", "0"]), ("Transfer-Encoding", [""])):
                    client = http.client.HTTPConnection("127.0.0.1", service.server_port, timeout=3)
                    client.putrequest("GET", route, skip_host=True)
                    if field != "Host":
                        client.putheader("Host", "sub.example.com")
                    for value in values:
                        client.putheader(field, value)
                    client.endheaders()
                    response = client.getresponse()
                    self.assertEqual(response.status, 400)
                    response.read()
                    client.close()
                path.write_bytes(b"not-json")
                with self.assertRaises(ValueError):
                    service.reload()
                self.assertEqual(request(route)[0], 200)
                secrets["subscription_token"] = "C" * 43
                path.write_bytes(subscription.render(public, secrets)[subscription.DIRECTORY + "/runtime.json"])
                service.reload()
                self.assertEqual(request(route)[0], 404)
                current = subscription.routes(public, secrets["subscription_token"])[0]["path"]
                self.assertEqual(request(current)[0], 200)
            finally:
                service.shutdown()
                service.server_close()
                thread.join(3)

    def test_bundle_checksum_rejects_torn_generation(self):
        public, secrets = fixture()
        bundle = json.loads(subscription.render(public, secrets)[subscription.DIRECTORY + "/runtime.json"])
        bundle["headers"]["Subscription-Userinfo"] = "total=999"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "runtime.json"
            path.write_text(json.dumps(bundle), encoding="utf-8")
            with self.assertRaises(ValueError):
                server.load_bundle(path)


if __name__ == "__main__":
    unittest.main()
