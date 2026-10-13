import copy
import json
import unittest

from sbmanager import render


def fixture():
    state = {"domains": {"site": "site.example.com", "subscription": "sub.example.com", "site_aliases": [], "subscription_aliases": []},
             "ports": dict(render.DEFAULT_PORTS), "site": {"root": render.DEFAULT_SITE_ROOT},
             "subscription": {"aliases": []}, "legacy": {"entries": []}, "nodes": [
                 {"id": "reality", "name": "Reality", "source": "local", "enabled": True, "protocol": "vless", "port": 443,
                  "transport": "tcp", "security": "reality", "sni": "site.example.com", "flow": "xtls-rprx-vision", "short_id": "12345678"},
                 {"id": "hy2", "name": "Hysteria", "source": "local", "enabled": True, "protocol": "hysteria2", "port": 443,
                  "transport": "quic", "security": "tls", "sni": "site.example.com"}]}
    secrets = {"subscription_token": "token-should-never-appear-in-nginx", "nodes": {
        "reality": {"uuid": "68c2c127-1302-440b-8727-833b914f374b", "private_key": "a" * 43},
        "hy2": {"password": "private-hy2-password"}}}
    return state, secrets


class RenderTests(unittest.TestCase):
    def test_vmess_http1_and_h2_are_distinct_transports(self):
        state, secret = fixture()
        node = state["nodes"][0]
        node.update(protocol="vmess", security="none", transport="http", port=21001, path="/legacy-http")
        state["nodes"] = [node]
        inbounds, _ = render.render_inbounds(state, secret)
        self.assertNotIn("tls", inbounds[0])
        self.assertEqual(inbounds[0]["transport"], {"type": "http", "path": "/legacy-http"})
        node["security"] = "tls"
        with self.assertRaisesRegex(render.RenderError, "HTTP/1"):
            render.render_inbounds(state, secret)
        node.update(transport="h2", security="none")
        with self.assertRaisesRegex(render.RenderError, "HTTP/2"):
            render.render_inbounds(state, secret)

    def test_browser_reality_hy2_and_subscription_share_443_without_loop(self):
        state, secret = fixture()
        files = render.render(state, secret)
        core = json.loads(files["/etc/sing-box/sb/config.json"])
        reality, hy2 = core["inbounds"]
        self.assertEqual((reality["listen"], reality["listen_port"]), ("127.0.0.1", 2443))
        self.assertEqual(reality["tls"]["reality"]["handshake"], {"server": "127.0.0.1", "server_port": 8443})
        self.assertEqual((hy2["listen_port"], hy2["type"]), (443, "hysteria2"))
        self.assertEqual(hy2["tls"]["min_version"], "1.3")
        self.assertNotIn("insecure", hy2["tls"])
        self.assertEqual(hy2["tls"]["certificate_path"], "/etc/sb/certificates/site.example.com/fullchain.pem")
        stream = files["/etc/nginx/sb/stream.conf"].decode()
        self.assertIn("site.example.com 127.0.0.1:2443;", stream)
        self.assertIn("sub.example.com 127.0.0.1:8444;", stream)
        self.assertNotIn("proxy_protocol", stream)
        http = files["/etc/nginx/sb/http.conf"].decode()
        self.assertIn("ssl_reject_handshake on", http)
        self.assertIn("ssl_ecdh_curve X25519", http)
        self.assertIn("http2 on", http)
        self.assertNotIn("quic", http)
        self.assertIn("location = /healthz { return 404; }", http)
        self.assertNotIn(secret["subscription_token"], http)
        self.assertNotIn(secret["nodes"]["hy2"]["password"], stream)

    def test_imported_and_legacy_nodes_do_not_create_new_listeners(self):
        state, secret = fixture()
        for source in ("uri", "legacy"):
            node = copy.deepcopy(state["nodes"][0])
            node.update(id=source, source=source)
            state["nodes"].append(node)
        state["nodes"][1]["enabled"] = False
        inbounds, _ = render.render_inbounds(state, secret)
        self.assertEqual(len(inbounds), 1)

    def test_alias_domains_get_certificates_and_continue_routing(self):
        state, secret = fixture()
        state["domains"]["site_aliases"] = ["old.example.com"]
        state["subscription"]["aliases"] = [{"domain": "oldsub.example.com", "prefix": "old", "suffix": "/clash.yaml"}]
        state["nodes"][0]["sni"] = "old.example.com"
        files = render.render(state, secret)
        http = files["/etc/nginx/sb/http.conf"].decode()
        self.assertIn("/certificates/old.example.com/", http)
        self.assertIn("/certificates/oldsub.example.com/", http)
        stream = files["/etc/nginx/sb/stream.conf"].decode()
        self.assertIn("old.example.com 127.0.0.1:2443", stream)
        self.assertIn("site.example.com 127.0.0.1:8443", stream)

    def test_migrated_certificate_renewal_keeps_its_enrolled_webroot(self):
        state, secret = fixture()
        state["certificates"] = {"webroots": {"sub.example.com": "/var/www/subscription-acme"}}
        http = render.render(state, secret)["/etc/nginx/sb/http.conf"].decode()
        self.assertIn("root /var/www/subscription-acme;", http)
        self.assertIn("root /var/lib/sb/acme;", http)
        state["certificates"]["webroots"]["sub.example.com"] = "/etc/sb"
        with self.assertRaises(ValueError):
            render.render(state, secret)

    def test_distribution_nginx_uses_compatible_frontend_http2_syntax(self):
        state, secret = fixture()
        state["nginx"] = {"version": "1.22.1", "legacy_http2_directive": True}
        state["legacy"]["http_config"] = "server { listen 127.0.0.1:20001 ssl; server_name old.example.com; http2 on; location /ws { proxy_http_version 1.1; } }"
        files = render.render(state, secret)
        http = files["/etc/nginx/sb/http.conf"].decode()
        self.assertNotIn("http2 on;", http)
        self.assertIn("listen 127.0.0.1:8443 ssl http2;", http)
        self.assertIn("ssl http2 default_server;", http)
        self.assertIn("listen 127.0.0.1:20001 ssl http2;", files["/etc/nginx/sb/legacy-http.conf"].decode())
        self.assertNotIn("http2 on;", files["/etc/nginx/sb/legacy-http.conf"].decode())
        state["legacy"]["http_config"] = "proxy_http_version 2;"
        with self.assertRaisesRegex(ValueError, "HTTP/2 upstream"):
            render.render(state, secret)

    def test_certificate_sync_timer_retries_missed_hooks(self):
        state, secret = fixture()
        files = render.render(state, secret)
        unit = files["/etc/systemd/system/sb-cert-sync.service"].decode()
        timer = files["/etc/systemd/system/sb-cert-sync.timer"].decode()
        self.assertIn("ExecStart=/usr/local/bin/sb cert sync --scheduled", unit)
        for value in ("OnBootSec=2min", "OnUnitActiveSec=15min", "RandomizedDelaySec=30s", "Persistent=true"):
            self.assertIn(value, timer)

    def test_port_sni_and_protocol_conflicts_fail_before_writes(self):
        for change in (
            lambda s: s["ports"].update(site_tls=443),
            lambda s: s["ports"].update(sub_http=8443),
            lambda s: s["nodes"][0].update(listen="0.0.0.0"),
            lambda s: s["nodes"][0].update(listen="::1"),
            lambda s: s["nodes"][0].update(listen_port=8444),
            lambda s: s["nodes"][0].update(sni="unowned.example.com"),
            lambda s: s["nodes"][0].update(transport="quic"),
            lambda s: s["domains"].update(subscription="site.example.com"),
            lambda s: s["nodes"][1].update(insecure=True),
        ):
            with self.subTest(change=change):
                state, secret = fixture()
                change(state)
                with self.assertRaises(ValueError):
                    render.render(state, secret)

    def test_compatible_users_share_listener_but_different_keys_fail(self):
        state, secret = fixture()
        node = copy.deepcopy(state["nodes"][0])
        node.update(id="reality2", name="Second")
        state["nodes"].append(node)
        secret["nodes"]["reality2"] = dict(secret["nodes"]["reality"], uuid="12345678-1234-1234-1234-123456789012")
        inbounds, _ = render.render_inbounds(state, secret)
        self.assertEqual(len(inbounds), 2)
        self.assertEqual(len(inbounds[0]["users"]), 2)
        secret["nodes"]["reality2"]["private_key"] = "b" * 43
        with self.assertRaises(render.RenderError):
            render.render(state, secret)

    def test_legacy_h2_preserves_verified_tls_upstream_and_detects_sni_collisions(self):
        state, secret = fixture()
        state["legacy"]["entries"] = [{"kind": "sni", "sni": "old.example.com", "upstream": "127.0.0.1:28001"}]
        state["legacy"]["http_config"] = "server { listen 127.0.0.1:28001 ssl; location /h2 { proxy_pass https://127.0.0.1:28002; proxy_http_version 2; proxy_ssl_server_name on; proxy_ssl_name old.example.com; proxy_ssl_verify on; proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt; } }\n"
        files = render.render(state, secret)
        self.assertEqual(files["/etc/nginx/sb/legacy-http.conf"].decode(), state["legacy"]["http_config"])
        state["legacy"]["entries"][0]["sni"] = "site.example.com"
        with self.assertRaises(render.RenderError):
            render.render(state, secret)

    def test_legacy_duplicate_sni_and_public_loop_are_rejected(self):
        state, secret = fixture()
        state["legacy"]["entries"] = [{"kind": "sni", "sni": "old.example.com", "upstream": "127.0.0.1:443"}]
        with self.assertRaises(render.RenderError):
            render.render(state, secret)
        state["legacy"]["entries"][0]["upstream"] = "127.0.0.1:29000"
        state["legacy"]["entries"].append({"kind": "sni", "sni": "old.example.com", "upstream": "127.0.0.1:29001"})
        with self.assertRaises(render.RenderError):
            render.render(state, secret)

    def test_http2_requires_tls_and_vision_cannot_use_h2(self):
        state, secret = fixture()
        node = state["nodes"][0]
        node.update(transport="h2", flow="", security="tls", port=10443)
        core, _ = render.render_inbounds(state, secret)
        self.assertEqual(core[0]["transport"]["type"], "http")
        self.assertEqual(core[0]["tls"]["alpn"], ["h2"])
        node["flow"] = "xtls-rprx-vision"
        with self.assertRaises(render.RenderError):
            render.render(state, secret)
        node.update(flow="", security="none")
        with self.assertRaises(render.RenderError):
            render.render(state, secret)

    def test_expanded_protocols_use_dedicated_listeners(self):
        for protocol in ("shadowsocks", "trojan", "tuic", "anytls", "vmess", "socks"):
            with self.subTest(protocol=protocol):
                state, secret = fixture()
                state["nodes"] = [{"id": "test", "name": "Test", "source": "local", "protocol": protocol,
                    "port": 10443, "transport": "quic" if protocol == "tuic" else "tcp",
                    "security": "none" if protocol in ("shadowsocks", "socks", "vmess") else "tls", "method": "aes-128-gcm"}]
                secret["nodes"]["test"] = {"uuid": "12345678-1234-1234-1234-123456789012", "password": "p", "username": "u"}
                inbounds, routes = render.render_inbounds(state, secret)
                self.assertEqual(inbounds[0]["type"], protocol)
                self.assertEqual(inbounds[0]["listen_port"], 10443)
                self.assertEqual(routes, {})

    def test_custom_site_is_not_overwritten_and_paths_are_validated(self):
        state, secret = fixture()
        state["site"]["root"] = "/srv/my-site"
        self.assertFalse(any(path.endswith("index.html") for path in render.render(state, secret)))
        for path in ("/srv/x;include /etc/shadow", "/srv/../etc", "relative"):
            state["site"]["root"] = path
            with self.assertRaises(render.RenderError):
                render.render(state, secret)

    def test_bootstrap_requires_no_certificates_and_never_exposes_subscription(self):
        state, _ = fixture()
        files = render.render_bootstrap(state)
        self.assertNotIn(b"ssl_certificate", files["/etc/nginx/sb/http.conf"])
        self.assertIn(b".well-known/acme-challenge", files["/etc/nginx/sb/http.conf"])
        self.assertNotIn(b"https://sub.example.com", files["/etc/nginx/sb/http.conf"])
        self.assertNotIn(b"listen 443", files["/etc/nginx/sb/stream.conf"])

    def test_services_separate_credentials_and_use_bounded_privileges(self):
        state, secret = fixture()
        files = render.render(state, secret)
        core = files["/etc/systemd/system/sb-sing-box.service"].decode()
        sub = files["/etc/systemd/system/sb-subscription.service"].decode()
        self.assertIn("User=sb-core", core)
        self.assertIn("CapabilityBoundingSet=CAP_NET_BIND_SERVICE", core)
        self.assertIn("InaccessiblePaths=/etc/sb/secrets.json", core)
        self.assertIn("User=sb-subscription", sub)
        self.assertIn("ProtectSystem=strict", sub)
        self.assertIn("/etc/sb/certificates", sub)
        self.assertIn("OnUnitActiveSec=15min", files["/etc/systemd/system/sb-rules.timer"].decode())


if __name__ == "__main__":
    unittest.main()
