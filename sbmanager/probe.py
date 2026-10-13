"""Exercise local REALITY/HY2 with Mihomo against a short-lived loopback origin."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time

import yaml

from . import protocols


def local_nodes(state, credentials, mihomo=Path("/opt/sb/bin/mihomo")):
    nodes = [n for n in state["nodes"] if n.get("source") == "local" and n.get("enabled", True)
             and (n.get("security") == "reality" or n["protocol"] == "hysteria2")]
    if not nodes:
        return
    marker = secrets.token_urlsafe(32).encode()
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(marker)))
            self.end_headers()
            self.wfile.write(marker)
        def log_message(self, *_):
            pass
    origin = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=origin.serve_forever, daemon=True)
    worker.start()
    try:
        for node in nodes:
            proxy = protocols.to_mihomo(node, credentials["nodes"][node["id"]])
            listen = node.get("listen", "::")
            proxy["server"] = "127.0.0.1" if listen in {"::", "0.0.0.0", "127.0.0.1"} or node["port"] == 443 else listen
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                port = reserve.getsockname()[1]
            document = {"mixed-port": port, "bind-address": "127.0.0.1", "allow-lan": False,
                        "mode": "rule", "log-level": "silent", "ipv6": True,
                        "dns": {"enable": False}, "tun": {"enable": False},
                        "proxies": [proxy], "proxy-groups": [], "rules": ["MATCH," + proxy["name"]]}
            with tempfile.TemporaryDirectory(prefix="sb-probe-") as name:
                folder = Path(name)
                os.chmod(folder, 0o700)
                config = folder / "config.yaml"
                config.write_text(yaml.safe_dump(document, allow_unicode=True), encoding="utf-8")
                os.chmod(config, 0o600)
                with (folder / "core.log").open("wb") as log:
                    process = subprocess.Popen([str(mihomo), "-d", str(folder), "-f", str(config)], stdout=log, stderr=log)
                    try:
                        deadline = time.monotonic() + 10
                        while True:
                            if process.poll() is not None:
                                raise RuntimeError("Local proxy probe core exited before readiness")
                            try:
                                with socket.create_connection(("127.0.0.1", port), timeout=.2):
                                    break
                            except OSError:
                                if time.monotonic() >= deadline:
                                    raise RuntimeError("Local proxy probe did not become ready") from None
                                time.sleep(.1)
                        # Mihomo opens its listeners before the tunnel enters
                        # Running. A TCP connection can succeed during that gap
                        # while a SOCKS request is closed without a response.
                        # Retry only empty connection failures within the same
                        # startup deadline; success still requires the marker.
                        while True:
                            result = subprocess.run(["curl", "--silent", "--fail", "--max-time", "15", "--noproxy", "",
                                  "--socks5-hostname", f"127.0.0.1:{port}", f"http://127.0.0.1:{origin.server_port}/"],
                                  capture_output=True, timeout=20)
                            core_exit = process.poll()
                            if core_exit is None and result.returncode == 0 and result.stdout == marker:
                                break
                            transient = core_exit is None and result.returncode in {7, 52, 56, 97} and not result.stdout
                            if not transient or time.monotonic() >= deadline:
                                core_status = "running" if core_exit is None else "exit " + str(core_exit)
                                response_status = "empty" if not result.stdout else "unexpected"
                                raise RuntimeError("Local " + node["protocol"] + " data-path probe failed "
                                                   f"(curl exit {result.returncode}; core {core_status}; response {response_status})")
                            time.sleep(.1)
                    finally:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
    finally:
        origin.shutdown()
        origin.server_close()
        worker.join(timeout=5)
