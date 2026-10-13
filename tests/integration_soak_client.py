#!/usr/bin/env python3
"""Short, local real-core check of the full-subscription soak harness.

All listeners use loopback ephemeral ports and temporary fixture credentials.
No public server, installed services, routes, firewall, or system CA is changed.
This is not the one-hour public-client soak.
"""
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import threading
from unittest.mock import patch

import yaml

if __package__:
    from . import integration_core as integration, soak_client as soak
else:
    import integration_core as integration
    import soak_client as soak

from sbmanager import cli, render, state, subscription


def run():
    with tempfile.TemporaryDirectory(prefix="sb-soak-integration-") as raw:
        directory = Path(raw)
        cores = soak.download_cores(directory)
        cert, key = directory / "cert.pem", directory / "key.pem"
        integration.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                         "-subj", "/CN=site.example.com", "-addext", "subjectAltName=DNS:site.example.com,IP:127.0.0.1",
                         "-keyout", key, "-out", cert])
        body = b"sb-soak-loopback"
        current_config = {}
        counters = {"subscription": 0, "site": 0}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                if self.path == "/subscription":
                    data = yaml.safe_dump(current_config, allow_unicode=True).encode()
                    counters["subscription"] += 1
                else:
                    data = body
                    counters["site"] += 1
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Profile-Update-Interval", "12")
                self.end_headers()
                self.wfile.write(data)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        ports = set()
        while len(ports) < 5:
            ports.add(integration.free_port())
        reality_port, hy2_port, sub_tls, sub_http, extra = sorted(ports)
        public, secret = state.create("site.example.com", "sub.example.com", "admin@example.com")
        public["rules"]["enabled"] = False
        public["ports"] = {"reality": extra, "site_tls": server.server_port,
                           "sub_tls": sub_tls, "sub_http": sub_http, "hy2": hy2_port}
        cli.add_local(public, secret, name="Fixture REALITY", port=reality_port, offline=True)
        cli.add_local(public, secret, name="Fixture HY2", protocol="hysteria2", port=hy2_port, offline=True)
        for node in public["nodes"]:
            node.update(server="127.0.0.1", listen="127.0.0.1")
        files = render.render(public, secret)
        config_path = directory / "server.json"
        config_path.write_text(json.dumps(integration.remap(json.loads(files["/etc/sing-box/sb/config.json"]), cert, key, directory)))
        config, _, _ = subscription.compile_config(public, secret)
        der = integration.run(["openssl", "x509", "-in", cert, "-outform", "DER"], text=False)
        for proxy in config["proxies"]:
            if proxy["type"] == "hysteria2":
                proxy["fingerprint"] = hashlib.sha256(der).hexdigest()
        config["rule-providers"] = {"fixture": {"type": "inline", "behavior": "domain", "payload": ["+.fixture.invalid"]}}
        config["rules"].insert(0, "RULE-SET,fixture,DIRECT")
        current_config.update(config)
        bundle = {"site_url": "https://127.0.0.1:" + str(server.server_port) + "/",
                  "subscription_url": "https://127.0.0.1:" + str(server.server_port) + "/subscription",
                  "proxies": copy.deepcopy(config["proxies"]), "expected_site_sha256": hashlib.sha256(body).hexdigest()}
        clients, events, process = [], [], None
        try:
            with (directory / "server.log").open("wb") as log, \
                 patch.dict(os.environ, {"SSL_CERT_FILE": str(cert), "CURL_CA_BUNDLE": str(cert)}):
                process = subprocess.Popen([str(cores["sing-box"]), "run", "-c", str(config_path)], stdout=log, stderr=subprocess.STDOUT)
                integration.wait_port(reality_port, [process])
                downloaded, selected = soak.fetch_subscription(bundle)
                for protocol in ("reality", "hy2"):
                    client = soak.Client(directory / protocol, cores["mihomo"], protocol)
                    clients.append(client)
                    client.configure(downloaded, selected)
                original_pids = [client.process.pid for client in clients]
                result = soak.cycle(clients, bundle, 5, 1, 2, events.append)
                if result["status"] != "passed" or result["refreshes_passed"] < 1:
                    raise soak.Error("local_soak_traffic_or_refresh_failed")
                if original_pids != [client.process.pid for client in clients]:
                    raise soak.Error("refresh_restarted_core")
                clients[0].process.kill()
                clients[0].process.wait(timeout=5)
                try:
                    soak.cycle(clients, bundle, 1, 1, 1, events.append)
                except soak.Error as exc:
                    if str(exc) != "client_process_exited":
                        raise
                else:
                    raise soak.Error("process_death_was_not_reported")
                if events[-1].get("exit_code") != -9:
                    raise soak.Error("process_exit_report_incorrect")
                return {"status": "passed", "scope": "local_real_core_five_second_fixture",
                        "traffic": result["traffic"], "refreshes_passed": result["refreshes_passed"],
                        "full_subscription_https_requests": counters["subscription"],
                        "persistent_pids": True, "process_death_detected": True,
                        "rss_observed": all(event.get("rss_kib", 0) for event in events
                                            if event.get("event") == "traffic" and event.get("status") == "passed")}
        finally:
            for client in clients:
                client.close()
            if process:
                soak.acceptance.stop(process)
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    try:
        print(json.dumps(run()))
    except Exception as exc:
        print(json.dumps({"status": "failed", "category": soak.acceptance.category(exc)}))
        raise SystemExit(1)
