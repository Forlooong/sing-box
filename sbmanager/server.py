"""Read-only loopback HTTP service for an atomically published subscription bundle.

No rule fetching, URI parsing, management commands, or access logging occurs here.
Nginx is responsible for public TLS, request limits and connection timeouts.
"""
import argparse
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading

from .protocols import hostname

MAX_BUNDLE = 8 * 1024 * 1024
PATH = re.compile(r"/(?:[A-Za-z0-9_-]{1,64}/){1,8}[A-Za-z0-9_-]{43}(?:/raw|/clash\.yaml)?$")


def load_bundle(path):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Runtime bundle must be a regular file")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BUNDLE + 1)
    if len(raw) > MAX_BUNDLE:
        raise ValueError("Runtime bundle too large")
    bundle = json.loads(raw)
    if not isinstance(bundle, dict) or bundle.get("schema_version") != 1:
        raise ValueError("Unsupported runtime schema")
    generation = bundle.pop("generation", None)
    digest = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest()
    if generation != digest:
        raise ValueError("Runtime generation checksum mismatch")
    if bundle.get("listen_host") != "127.0.0.1" or not isinstance(bundle.get("listen_port"), int) or not 1024 <= bundle["listen_port"] <= 65535:
        raise ValueError("Runtime must listen on an unprivileged loopback port")
    headers = bundle.get("headers")
    if not isinstance(headers, dict) or set(headers) - {
            "Profile-Update-Interval", "Subscription-Userinfo", "Content-Disposition", "Profile-Title"}:
        raise ValueError("Unsupported runtime response header")
    for name, value in headers.items():
        limit = 1024 if name in {"Content-Disposition", "Profile-Title"} else 500
        if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) > 126 for c in value):
            raise ValueError("Invalid runtime response header")
    if headers.get("Profile-Update-Interval") != "12":
        raise ValueError("Invalid profile update interval")
    artifacts = bundle.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {"clash", "raw"}:
        raise ValueError("Invalid runtime artifacts")
    decoded = {}
    for name, content_type in (("clash", "text/yaml; charset=utf-8"), ("raw", "text/plain; charset=utf-8")):
        artifact = artifacts[name]
        if not isinstance(artifact, dict) or artifact.get("content_type") != content_type:
            raise ValueError("Invalid artifact content type")
        body = base64.b64decode(artifact["body"], validate=True)
        if not body or len(body) > MAX_BUNDLE // 2:
            raise ValueError("Invalid artifact size")
        decoded[name] = (body, content_type)
    routes = bundle.get("routes")
    if not isinstance(routes, list) or not 2 <= len(routes) <= 200:
        raise ValueError("Invalid runtime routes")
    lookup = {}
    for route in routes:
        if not isinstance(route, dict) or set(route) != {"host", "path", "artifact"}:
            raise ValueError("Invalid runtime route")
        host, path, name = route["host"], route["path"], route["artifact"]
        if hostname(host) != host or not isinstance(path, str) or not PATH.fullmatch(path) or name not in decoded:
            raise ValueError("Unsafe runtime route")
        if (host, path) in lookup:
            raise ValueError("Duplicate runtime route")
        lookup[host, path] = decoded[name]
    return {"port": bundle["listen_port"], "generation": generation, "headers": headers, "routes": lookup}


class SubscriptionServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, runtime_path, port=None):
        self.runtime_path = Path(runtime_path)
        self.bundle = load_bundle(self.runtime_path)
        self._slots = threading.BoundedSemaphore(32)
        super().__init__(("127.0.0.1", self.bundle["port"] if port is None else port), Handler)

    def reload(self):
        """Publish the whole new in-memory generation or retain the old one."""
        candidate = load_bundle(self.runtime_path)
        if candidate["port"] != self.bundle["port"]:
            raise ValueError("Changing the listen port requires a service restart")
        self.bundle = candidate

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        return connection, address

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request, client_address):
        # HTTP paths and exception tracebacks can contain the bearer token.
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = ""
    sys_version = ""

    def log_message(self, format, *args):
        pass

    def parse_request(self):
        # BaseHTTPRequestHandler rewrites a leading // to / for redirects.
        # Bearer routes must instead match exactly what the caller sent.
        request_parts = self.raw_requestline.decode("iso-8859-1").split()
        if not super().parse_request():
            return False
        if len(request_parts) < 2 or request_parts[1] != self.path:
            self.send_error(400)
            return False
        return True

    def send_error(self, code, message=None, explain=None):
        self._response(code, b"Not found\n", "text/plain; charset=utf-8", {})

    def _response(self, status, body, content_type, headers):
        self.send_response_only(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, private")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Connection", "close")
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(body)

    def _get(self):
        bundle = self.server.bundle
        # Reject normalization/query tricks: routes are exact bearer capabilities.
        host_values = self.headers.get_all("Host", [])
        lengths = self.headers.get_all("Content-Length", [])
        if len(host_values) != 1 or self.headers.get_all("Transfer-Encoding", []) or len(lengths) > 1 or lengths not in ([], ["0"]):
            return self.send_error(400)
        host = host_values[0].lower()
        if host.endswith(":443"):
            host = host[:-4]
        if self.path == "/healthz" and host in {"localhost", "127.0.0.1", "127.0.0.1:" + str(self.server.server_port)}:
            return self._response(200, (json.dumps({"ok": True, "generation": bundle["generation"]}) + "\n").encode(), "application/json", {})
        artifact = bundle["routes"].get((host, self.path))
        if artifact is None:
            return self.send_error(404)
        self._response(200, artifact[0], artifact[1], bundle["headers"])

    do_GET = _get
    do_HEAD = _get

    def do_POST(self):
        self.send_error(404)

    do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_POST


def create_server(runtime_path, port=None):
    return SubscriptionServer(runtime_path, port)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", default="/var/lib/sb/subscription/runtime.json")
    parser.add_argument("--port", type=int)
    args = parser.parse_args()
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        parser.error("Run this HTTP service as sb-subscription, never as root")
    server = create_server(args.runtime, args.port)

    def reload_bundle(signum, frame):
        try:
            server.reload()
        except (OSError, ValueError, KeyError, TypeError):
            print("Subscription reload rejected; previous generation retained", file=sys.stderr)

    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, reload_bundle)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
