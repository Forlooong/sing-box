import copy
import hashlib
import json
import os
from pathlib import Path
import ssl
import tempfile
import unittest

from sbmanager import migration, state, subscription


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.current, self.private = state.create("new.example.com", "sub.example.com", "admin@example.com")
        self.current["migration"] = {"public_server": "198.51.100.7"}

    def put(self, name, value):
        path = self.root / name.lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value if isinstance(value, bytes) else value.encode())
        return path

    def core(self, inbound=None):
        self.put("/etc/sing-box/sh/src/init.sh", "author=233boy\nis_core=sing-box\n")
        self.put("/etc/sing-box/bin/sing-box", b"\x7fELFlegacy-fixture-do-not-execute")
        self.put("/etc/systemd/system/sing-box.service", "[Service]\nExecStart=/etc/sing-box/bin/sing-box run -c /etc/sing-box/config.json -C /etc/sing-box/conf\n")
        self.put("/etc/sing-box/config.json", json.dumps({"outbounds": [{"type": "direct", "tag": "direct"}], "dns": {}, "log": {"output": "/var/log/sing-box/access.log"}}))
        if inbound is None:
            inbound = {"type": "vless", "listen": "::", "listen_port": 443,
                       "users": [{"uuid": "12345678-1234-4234-9234-123456789012", "flow": "xtls-rprx-vision"}],
                       "tls": {"enabled": True, "server_name": "old.example.com", "reality": {"enabled": True,
                               "private_key": "B" * 43, "short_id": [""], "handshake": {"server": "old.example.com", "server_port": 443}}}}
        self.put("/etc/sing-box/conf/old.json", json.dumps({"inbounds": [inbound], "outbounds": [{"type": "direct"}, {"type": "direct", "tag": "public_key_" + "A" * 43}]}))
        return inbound

    def test_inspection_is_read_only_redacted_and_reality_is_preserved(self):
        original = self.core()
        report = migration.inspect(self.root)
        self.assertTrue(report["eligible"], report)
        text = json.dumps(report)
        self.assertNotIn("B" * 43, text)
        self.assertNotIn(original["users"][0]["uuid"], text)
        new, private, files = migration.prepare(report, self.current, self.private)
        config = json.loads(files["/etc/sing-box/sb-legacy/config.json"])
        migrated = config["inbounds"][0]
        self.assertEqual(migrated["tls"], original["tls"])
        self.assertEqual(migrated["users"], original["users"])
        self.assertEqual(migrated["listen"], "127.0.0.1")
        self.assertNotEqual(migrated["listen_port"], 443)
        self.assertEqual(new["nodes"][0]["port"], 443)
        self.assertEqual(new["nodes"][0]["sni"], "old.example.com")
        self.assertEqual(private["nodes"][new["nodes"][0]["id"]]["private_key"], "B" * 43)
        self.assertEqual(files[f"/opt/sb/legacy/{report['inventory_id']}/sing-box"], b"\x7fELFlegacy-fixture-do-not-execute")
        self.assertFalse((self.root / "etc/sb").exists())

    def test_prepare_rejects_toctou_changes_and_missing_old_public_address(self):
        self.core()
        report = migration.inspect(self.root)
        missing = copy.deepcopy(self.current)
        missing.pop("migration")
        with self.assertRaisesRegex(migration.MigrationError, "public-server"):
            migration.prepare(report, missing, self.private)
        self.put("/etc/sing-box/conf/new.json", "{}")
        with self.assertRaisesRegex(migration.MigrationError, "changed"):
            migration.prepare(report, self.current, self.private)

    def test_unknown_global_routing_and_custom_caddy_block_entire_migration(self):
        self.core()
        self.put("/etc/sing-box/config.json", json.dumps({"route": {"rules": [{"source_ip_cidr": ["192.0.2.0/24"], "outbound": "direct"}]}}))
        self.assertFalse(migration.inspect(self.root)["eligible"])
        self.put("/etc/sing-box/config.json", "{}")
        self.put("/etc/caddy/Caddyfile", "custom.example.com { reverse_proxy 127.0.0.1:1234 }\n")
        report = migration.inspect(self.root)
        self.assertFalse(report["eligible"])
        self.assertIn("Caddy", report["blockers"][0])

    def test_hy2_pin_bytes_password_port_and_new_udp_coexistence(self):
        certificate = ssl.DER_cert_to_PEM_cert(b"fixture-certificate-bytes").encode()
        self.put("/etc/sing-box/bin/tls.cer", certificate)
        self.put("/etc/sing-box/bin/tls.key", "private-fixture-key")
        self.core({"type": "hysteria2", "listen": "::", "listen_port": 443,
                   "users": [{"password": "original-hy-password"}],
                   "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": "/etc/sing-box/bin/tls.cer", "key_path": "/etc/sing-box/bin/tls.key"}})
        self.current["nodes"] = [{"id": "new-hy", "name": "New HY2", "source": "local", "protocol": "hysteria2", "transport": "quic", "port": 443}]
        self.private["nodes"]["new-hy"] = {"password": "new-password"}
        new, private, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        legacy = next(node for node in new["nodes"] if node["source"] == "legacy")
        self.assertEqual(legacy["port"], 443)
        self.assertEqual(legacy["certificate_pin"], hashlib.sha256(b"fixture-certificate-bytes").hexdigest())
        self.assertNotEqual(new["nodes"][0]["port"], 443)
        self.assertEqual(new["ports"]["hy2"], new["nodes"][0]["port"])
        self.assertEqual(private["nodes"][legacy["id"]]["password"], "original-hy-password")
        self.assertEqual(files["/etc/sing-box/sb-legacy/certificates/0/certificate.pem"], certificate)

    def caddy(self, h2=False):
        self.put("/etc/caddy/Caddyfile", "# generated\n{\n admin off\n http_port 80\n https_port 443\n}\nimport /etc/caddy/233boy/*.conf\nimport /etc/caddy/sites/*.conf\n")
        self.put("/etc/systemd/system/caddy.service", "[Service]\nExecStart=/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile\n")
        transport = "h2c://" if h2 else ""
        opts = " { transport http { tls_insecure_skip_verify } }" if h2 else ""
        self.put("/etc/caddy/233boy/old.example.com.conf", f"old.example.com:443 {{\n reverse_proxy /node {transport}127.0.0.1:14443{opts}\n import /etc/caddy/233boy/old.example.com.conf.add\n}}\n")
        self.put("/etc/caddy/233boy/old.example.com.conf.add", "# original empty fallback\n")

    def test_known_ws_caddy_route_maps_without_exposing_credential(self):
        self.core({"type": "vmess", "listen": "127.0.0.1", "listen_port": 14443,
                   "users": [{"uuid": "12345678-1234-4234-9234-123456789012"}],
                   "transport": {"type": "ws", "path": "/node", "headers": {"host": "old.example.com"}}})
        self.caddy()
        report = migration.inspect(self.root)
        self.assertTrue(report["eligible"], report)
        new, _, _ = migration.prepare(report, self.current, self.private)
        self.assertEqual(new["nodes"][0]["server"], "old.example.com")
        self.assertEqual(new["nodes"][0]["port"], 443)
        self.assertIn("proxy_pass http://127.0.0.1:14443", new["legacy"]["http_config"])
        self.assertIn("caddy.service", new["legacy"]["switch"]["stop_services"])

    def test_h2_keeps_tls_backend_with_verified_http2(self):
        self.core({"type": "vmess", "listen": "127.0.0.1", "listen_port": 14443,
                   "users": [{"uuid": "12345678-1234-4234-9234-123456789012"}],
                   "transport": {"type": "http", "path": "/node", "headers": {"host": "old.example.com"}},
                   "tls": {"enabled": True}})
        self.caddy(True)
        new, _, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        self.assertIn("proxy_http_version 2", new["legacy"]["http_config"])
        self.assertIn("proxy_ssl_verify on", new["legacy"]["http_config"])
        self.assertNotIn("h2c://", new["legacy"]["http_config"])
        tls = json.loads(files["/etc/sing-box/sb-legacy/config.json"])["inbounds"][0]["tls"]
        self.assertEqual(tls["alpn"], ["h2"])
        self.assertEqual(tls["certificate_path"], "/etc/sb/certificates/old.example.com/fullchain.pem")

    def test_hand_built_xray_nginx_and_service_hooks_are_blocked(self):
        self.core()
        self.put("/etc/nginx/nginx.conf", "events {} http { server { listen 443 ssl; } }\n")
        self.assertFalse(migration.inspect(self.root)["eligible"])
        self.put("/etc/nginx/nginx.conf", "events {} http {}\n")
        self.put("/etc/systemd/system/sing-box.service.d/custom.conf", "[Service]\nExecStartPost=/custom\n")
        self.assertFalse(migration.inspect(self.root)["eligible"])

    def test_same_sni_different_core_blocks_and_custom_files_are_retained_in_backup(self):
        self.core()
        self.current["nodes"] = [{"id": "new", "name": "new", "source": "local", "protocol": "vless", "transport": "tcp", "sni": "old.example.com", "port": 443}]
        self.private["nodes"]["new"] = {}
        with self.assertRaisesRegex(migration.MigrationError, "same SNI"):
            migration.prepare(migration.inspect(self.root), self.current, self.private)

    def apply_files(self, files):
        for name, value in files.items():
            if value is None:
                (self.root / name.lstrip('/')).unlink(missing_ok=True)
            else:
                self.put(name, value)

    def test_retire_one_user_preserves_other_users_then_stops_last_listener(self):
        inbound = self.core()
        inbound["users"].append({"uuid": "87654321-4321-4321-8321-210987654321", "flow": "xtls-rprx-vision"})
        self.core(inbound)
        current, private, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        self.apply_files(files)
        first, second = [node["id"] for node in current["nodes"]]
        current, private, files = migration.retire(self.root, current, private, first)
        self.assertEqual([n["id"] for n in current["nodes"]], [second])
        retained = json.loads(files[migration.LEGACY_CONFIG])["inbounds"][0]
        self.assertEqual(retained["users"], inbound["users"][1:])
        self.assertEqual(current["nodes"][0]["legacy_user_index"], 0)
        self.assertTrue(current["legacy"]["entries"])
        self.apply_files(files)
        current, private, files = migration.retire(self.root, current, private, second)
        self.assertEqual(current["nodes"], [])
        self.assertEqual(current["legacy"]["entries"], [])
        self.assertEqual(json.loads(files[migration.LEGACY_CONFIG])["inbounds"], [])
        self.assertNotIn("/etc/systemd/system/" + migration.LEGACY_SERVICE, files)
        self.assertEqual(current["legacy"]["switch"]["stop_services"], [migration.LEGACY_SERVICE])
        self.assertEqual(current["legacy"]["services"], [])
        self.assertNotIn(second, private["nodes"])
        self.assertTrue(any((self.root / "var/lib/sb/migration").rglob("inventory.json")))

    def test_retire_refuses_modified_runtime_and_leaves_inputs_unchanged(self):
        self.core()
        current, private, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        self.apply_files(files)
        before = copy.deepcopy(current)
        self.put(migration.LEGACY_CONFIG, files[migration.LEGACY_CONFIG] + b" ")
        with self.assertRaisesRegex(migration.MigrationError, "outside sb"):
            migration.retire(self.root, current, private, current["nodes"][0]["id"])
        self.assertEqual(current, before)

    def test_retire_caddy_listener_removes_only_its_route(self):
        self.core({"type": "vmess", "listen": "127.0.0.1", "listen_port": 14443,
                   "users": [{"uuid": "12345678-1234-4234-9234-123456789012"}],
                   "transport": {"type": "ws", "path": "/node", "headers": {"host": "old.example.com"}}})
        self.caddy()
        current, private, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        self.apply_files(files)
        current, _, _ = migration.retire(self.root, current, private, current["nodes"][0]["id"])
        self.assertEqual(current["legacy"]["http_config"], "")
        self.assertEqual(current["legacy"]["entries"], [])
        # Website aliases require their own explicit retirement.
        self.assertIn("old.example.com", current["domains"]["site_aliases"])

    def test_udp443_is_reserved_before_new_nodes_exist(self):
        certificate = ssl.DER_cert_to_PEM_cert(b"fixture-certificate-bytes").encode()
        self.put("/etc/sing-box/bin/tls.cer", certificate)
        self.put("/etc/sing-box/bin/tls.key", "private-fixture-key")
        self.core({"type": "hysteria2", "listen": "::", "listen_port": 443,
                   "users": [{"password": "original-hy-password"}],
                   "tls": {"enabled": True, "certificate_path": "/etc/sing-box/bin/tls.cer", "key_path": "/etc/sing-box/bin/tls.key"}})
        current, _, _ = migration.prepare(migration.inspect(self.root), self.current, self.private)
        self.assertNotEqual(current["ports"]["hy2"], 443)
        self.assertEqual(current["nodes"][0]["port"], 443)

    def test_old_dedicated_tcp_port_wins_over_new_internal_default(self):
        inbound = self.core()
        inbound["listen_port"] = 2443
        self.core(inbound)
        current, _, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        self.assertNotEqual(current["ports"]["reality"], 2443)
        retained = json.loads(files[migration.LEGACY_CONFIG])["inbounds"][0]
        self.assertEqual(retained["listen_port"], 2443)
        self.assertEqual(next(iter(current["legacy"]["listeners"].values()))["listen_port"], 2443)

    def test_observed_other_listener_ports_are_never_allocated(self):
        self.core()
        self.current["migration"]["occupied_ports"] = [20000, 20001, 20002]
        current, _, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        retained = json.loads(files[migration.LEGACY_CONFIG])["inbounds"][0]
        self.assertEqual(retained["listen_port"], 20003)
        self.current["migration"]["occupied_ports"] = [True]
        with self.assertRaisesRegex(migration.MigrationError, "Observed listener ports"):
            migration.prepare(migration.inspect(self.root), self.current, self.private)

    def test_certificate_pin_is_leaf_not_full_chain(self):
        leaf = ssl.DER_cert_to_PEM_cert(b"leaf").encode()
        chain = leaf + ssl.DER_cert_to_PEM_cert(b"issuer").encode()
        self.assertEqual(migration._fingerprint(chain), hashlib.sha256(b"leaf").hexdigest())

    def test_unknown_exec_commands_and_source_ip_settings_are_blocked(self):
        self.core()
        self.put("/etc/systemd/system/sing-box.service", "[Service]\nExecStart=/etc/sing-box/bin/sing-box run -c /etc/sing-box/config.json -C /etc/sing-box/conf\nExecCondition=/custom/check\n")
        self.assertFalse(migration.inspect(self.root)["eligible"])
        self.core()
        self.put("/etc/nginx/nginx.conf", "events {} http { real_ip_header X-Forwarded-For; }\n")
        self.assertFalse(migration.inspect(self.root)["eligible"])

    def standalone(self):
        self.put("/opt/subscription-generator/.managed-install", "")
        self.put("/opt/subscription-generator/config.json", json.dumps({"domain": "old-sub.example.com", "token": "C" * 43}))
        self.put("/opt/subscription-generator/nodes.txt", "vless://12345678-1234-4234-9234-123456789012@198.51.100.7:443?security=reality&type=tcp&sni=old.example.com&pbk=" + "A" * 43 + "&flow=xtls-rprx-vision#Original%20name\n")
        self.put("/opt/subscription-generator/template.yaml", "mixed-port: 7897\nproxy-groups: [{name: 节点选择, type: select, proxies: []}]\ndns: {proxy-server-nameserver: [https://1.1.1.1/dns-query]}\n")
        self.put("/etc/systemd/system/subscription-generator.service", "[Service]\nExecStart=/usr/bin/python3 /opt/subscription-generator/generator.py serve\n")
        self.renewal()
        template = Path(__file__).with_name("fixtures") / "standalone-nginx.conf"
        target = self.put("/etc/nginx/sites-available/subscription-generator", template.read_bytes())
        enabled = self.root / "etc/nginx/sites-enabled/subscription-generator"
        enabled.parent.mkdir(parents=True, exist_ok=True)
        try:
            enabled.symlink_to("../sites-available/subscription-generator")
        except OSError as exc:
            self.skipTest("Symlinks unavailable on this test host: " + str(exc))
        return target

    def renewal(self):
        return self.put(migration.OLD_RENEWAL, """version = 2.1.0
archive_dir = /etc/letsencrypt/archive/subscription-generator
cert = /etc/letsencrypt/live/subscription-generator/cert.pem
privkey = /etc/letsencrypt/live/subscription-generator/privkey.pem
chain = /etc/letsencrypt/live/subscription-generator/chain.pem
fullchain = /etc/letsencrypt/live/subscription-generator/fullchain.pem
[renewalparams]
account = 0123456789abcdef
server = https://acme-v02.api.letsencrypt.org/directory
authenticator = webroot
webroot_path = /var/www/subscription-acme,
key_type = ecdsa
[[webroot_map]]
old-sub.example.com = /var/www/subscription-acme
""")

    def test_owned_renewal_is_recognized_but_custom_hooks_are_blocked(self):
        path = self.renewal()
        self.assertTrue(migration._standalone_renewal(self.root, "old-sub.example.com"))
        path.write_text(path.read_text().replace("authenticator = webroot", "authenticator = webroot\npre_hook = /custom/mutation"), encoding="utf-8")
        with self.assertRaises(migration.MigrationError):
            migration._standalone_renewal(self.root, "old-sub.example.com")

    def test_standalone_preserves_token_alias_template_and_node_name(self):
        self.standalone()
        report = migration.inspect(self.root)
        self.assertTrue(report["eligible"], report)
        current, private, files = migration.prepare(report, self.current, self.private)
        self.assertEqual(private["subscription_token"], "C" * 43)
        self.assertEqual(current["nodes"][0]["name"], "Original name")
        self.assertEqual(current["subscription"]["template"]["mixed-port"], 7897)
        routes = subscription.routes(current, private["subscription_token"])
        self.assertIn({"host": "old-sub.example.com", "path": "/sub/" + "C" * 43 + "/clash.yaml", "artifact": "clash"}, routes)
        self.assertIn({"host": "old-sub.example.com", "path": "/sub/" + "C" * 43 + "/raw", "artifact": "raw"}, routes)
        self.assertEqual(current["legacy"]["switch"]["remove_symlinks"], {"/etc/nginx/sites-enabled/subscription-generator": "../sites-available/subscription-generator"})
        self.assertTrue(any(name.endswith("/opt/subscription-generator/config.json") for name in files))
        self.assertIsNone(files[migration.OLD_RENEWAL])
        self.assertIn(f"/var/lib/sb/migration/{report['inventory_id']}/backup" + migration.OLD_RENEWAL, files)

    def test_standalone_rearranged_known_directives_are_not_accepted(self):
        target = self.standalone()
        target.write_text(target.read_text().replace("listen 443 ssl;", "listen 80;"), encoding="utf-8")
        self.assertFalse(migration.inspect(self.root)["eligible"])

    def test_standalone_and_same_legacy_connection_are_deduplicated(self):
        self.standalone()
        self.core()
        current, private, files = migration.prepare(migration.inspect(self.root), self.current, self.private)
        self.assertEqual(len(current["nodes"]), 1)
        self.assertEqual(current["nodes"][0]["name"], "Original name")
        self.assertEqual(current["nodes"][0]["source"], "legacy")
        self.apply_files(files)
        current, _, _ = migration.retire(self.root, current, private, current["nodes"][0]["id"])
        self.assertEqual(current["nodes"], [])


if __name__ == "__main__":
    unittest.main()
