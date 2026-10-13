#!/usr/bin/env python3
"""Isolated real-core checks; no apt, systemd, firewall or system CA changes.

Run on Linux: python3 tests/integration_core.py [--remote-rules]
Verified release archives are cached under .test-runtime; all generated credentials,
certificates and runtime files live in a private TemporaryDirectory and are removed.
"""
from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sbmanager import cli, probe, protocols, render, rules, server, state, subscription, updates
from sbmanager.vendor import snapshot


def run(argv, **kwargs):
    kwargs.setdefault("text", True)
    result = subprocess.run([str(v) for v in argv], capture_output=True, timeout=90, **kwargs)
    if result.returncode:
        # Test fixtures only; never pass real state or production credentials here.
        raise RuntimeError("Command failed: " + str(argv[0]) + "\n" + result.stdout[-4000:] + result.stderr[-4000:])
    return result.stdout


def binaries(directory):
    versions = json.loads((ROOT / "versions.json").read_bytes())
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if arch is None:
        raise RuntimeError("Only amd64/arm64 real-core checks are supported")
    cache = ROOT / ".test-runtime/core-archives"
    cache.mkdir(parents=True, exist_ok=True)
    found = {}
    for name in ("sing-box", "mihomo"):
        asset = versions["assets"][name + "-" + arch]
        cached = cache / (asset["sha256"] + ".archive")

        def fetcher(url):
            if cached.exists():
                raw = cached.read_bytes()
                updates.verify(raw, asset["sha256"])
                return raw
            raw = updates.fetch(url)
            updates.verify(raw, asset["sha256"])
            cached.write_bytes(raw)
            return raw

        print("Verifying pinned " + name + " " + versions[name], flush=True)
        executable = directory / name
        executable.write_bytes(updates.binary(asset, fetcher=fetcher))
        executable.chmod(0o700)
        found[name] = executable
    return found


def certificates(directory):
    cert, key = directory / "fullchain.pem", directory / "privkey.pem"
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
         "-subj", "/CN=site.example.com", "-addext", "subjectAltName=DNS:site.example.com,DNS:sub.example.com",
         "-keyout", key, "-out", cert])
    key.chmod(0o600)
    return cert, key


def nginx_binary(directory):
    """Verify nginx.org's signed APT metadata, then extract without installing."""
    versions = json.loads((ROOT / "versions.json").read_bytes())
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    base = "https://nginx.org/packages/ubuntu/"
    cache = ROOT / ".test-runtime/core-archives"

    def fetch(url, limit=64 * 1024 * 1024):
        if not url.startswith("https://nginx.org/"):
            raise ValueError("Unexpected Nginx test source")
        with urllib.request.urlopen(url, timeout=30) as response:
            if not response.geturl().startswith("https://nginx.org/"):
                raise ValueError("Unexpected Nginx redirect")
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Oversized Nginx artifact")
        return data

    home = directory / "gnupg"
    home.mkdir(mode=0o700)
    keyfile = directory / "nginx-signing.asc"
    keyfile.write_bytes(fetch("https://nginx.org/keys/nginx_signing.key", 65536))
    fingerprints = ("573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62", "8540A6F18833A80E9C1653A42FD21310B49F6B46",
                    "9E9BE90EACBCDE69FE9B204CBCDCD8A38D88A2B3")
    run(["gpg", "--batch", "--homedir", home, "--import", keyfile])
    listing = run(["gpg", "--batch", "--homedir", home, "--with-colons", "--fingerprint"])
    if not all(fingerprint in listing for fingerprint in fingerprints):
        raise ValueError("Official Nginx signing fingerprint not found")
    # Only export the independently pinned key, not arbitrary keys in downloaded file.
    keyring = directory / "nginx.gpg"
    run(["gpg", "--batch", "--homedir", home, "--output", keyring, "--export", *fingerprints])
    release, signature = directory / "Release", directory / "Release.gpg"
    release.write_bytes(fetch(base + "dists/jammy/Release", 1024 * 1024))
    signature.write_bytes(fetch(base + "dists/jammy/Release.gpg", 65536))
    run(["gpgv", "--keyring", keyring, signature, release])
    relative = "nginx/binary-" + arch + "/Packages"
    lines = release.read_text().split("SHA256:\n", 1)[1].splitlines()
    matches = [line.split() for line in lines if len(line.split()) == 3 and line.split()[2] == relative]
    if len(matches) != 1:
        raise ValueError("Signed package index absent")
    digest, size, _ = matches[0]
    packages = fetch(base + "dists/jammy/" + relative, int(size))
    updates.verify(packages, digest)
    entries = [dict(line.split(": ", 1) for line in block.splitlines() if ": " in line and not line.startswith(" "))
               for block in packages.decode().split("\n\n")]
    entries = [entry for entry in entries if entry.get("Package") == "nginx" and
               entry.get("Version", "").split("-", 1)[0] == versions["nginx"] and entry.get("Architecture") == arch]
    if len(entries) != 1:
        raise ValueError("Pinned Nginx version absent from signed Jammy repository")
    entry = entries[0]
    if not re.fullmatch(r"pool/[A-Za-z0-9_./+~\-]+\.deb", entry["Filename"]) or ".." in entry["Filename"]:
        raise ValueError("Unsafe Nginx package filename")
    package = cache / (entry["SHA256"] + ".deb")
    if not package.exists():
        package.write_bytes(fetch(base + entry["Filename"], int(entry["Size"])))
    updates.verify(package.read_bytes(), entry["SHA256"])
    unpacked = directory / "nginx-package"
    run(["dpkg-deb", "-x", package, unpacked])
    return unpacked / "usr/sbin/nginx", unpacked


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port, processes):
    for _ in range(100):
        if any(proc.poll() is not None for proc in processes):
            raise RuntimeError("An isolated test service exited early")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                return
        except OSError:
            time.sleep(.1)
    raise RuntimeError("Isolated listener did not become ready")


def traffic(directory, cores):
    print("Verifying signed Nginx package for isolated traffic tests", flush=True)
    nginx, unpacked = nginx_binary(directory)
    cert, key = certificates(directory)
    public, secret = state.create("site.example.com", "sub.example.com", "test@example.com")
    public["rules"]["enabled"] = False
    edge, http_port = free_port(), free_port()
    public["ports"] = {name: free_port() for name in ("reality", "site_tls", "sub_tls", "sub_http")}
    public["ports"]["hy2"] = edge
    cli.add_local(public, secret, name="Reality", offline=True)
    cli.add_local(public, secret, name="HY2", protocol="hysteria2", port=edge, offline=True)
    cli.add_local(public, secret, name="VMess HTTP", protocol="vmess", port=free_port(),
                  transport="http", security="none", path="/vmess-test", offline=True)
    for node in public["nodes"]:
        node["listen"] = "127.0.0.1"
    files = render.render(public, secret)
    site = directory / "www"
    site.mkdir()
    (site / "index.html").write_text("sb-integration-site")
    legacy = directory / "legacy-http.conf"
    legacy.write_text("")
    http = files["/etc/nginx/sb/http.conf"].decode()
    http = re.sub(r"listen 80([ ;])", rf"listen 127.0.0.1:{http_port}\1", http)
    http = re.sub(r"listen \[::\]:80(?: default_server)?;", "", http)
    http = http.replace("/var/www/sb-site", str(site)).replace("/var/www/sb-acme", str(site))
    http = http.replace("/etc/nginx/sb/legacy-http.conf", str(legacy))
    for domain in ("site.example.com", "sub.example.com"):
        http = http.replace("/etc/sb/certificates/" + domain + "/fullchain.pem", str(cert))
        http = http.replace("/etc/sb/certificates/" + domain + "/privkey.pem", str(key))
    stream = files["/etc/nginx/sb/stream.conf"].decode()
    stream = stream.replace("listen 443;", f"listen 127.0.0.1:{edge};").replace("listen [::]:443;", "")
    modules = "".join("load_module " + str(path) + ";\n" for path in unpacked.glob("usr/lib/nginx/modules/*stream*.so"))
    config = directory / "nginx.conf"
    config.write_text(modules + "daemon off; master_process off;\npid " + str(directory / "nginx.pid") +
                      ";\nerror_log stderr warn;\nevents {}\n" + stream + "\nhttp { access_log off;\n" +
                      "".join(name + "_temp_path " + str(directory / name) + ";\n" for name in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi")) + http + "\n}\n")
    run([nginx, "-t", "-e", "stderr", "-p", directory, "-c", config])
    core_config = directory / "server.json"
    core_config.write_text(json.dumps(remap(json.loads(files["/etc/sing-box/sb/config.json"]), cert, key, site)))
    runtime = directory / "runtime.json"
    runtime.write_bytes(subscription.render(public, secret)[subscription.DIRECTORY + "/runtime.json"])
    subscription_server = server.create_server(runtime)
    subscription_thread = threading.Thread(target=subscription_server.serve_forever, daemon=True)
    subscription_thread.start()

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "25")
            self.end_headers()
            self.wfile.write(b"sb-integration-proxy-data")

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)
    target_thread = threading.Thread(target=target.serve_forever, daemon=True)
    target_thread.start()
    processes, logs = [], []
    verified = []
    try:
        for name, argv in (("nginx", [nginx, "-e", "stderr", "-p", directory, "-c", config]),
                           ("sing-box", [cores["sing-box"], "run", "-c", core_config])):
            log = (directory / (name + ".log")).open("w+")
            logs.append(log)
            processes.append(subprocess.Popen([str(v) for v in argv], stdout=log, stderr=subprocess.STDOUT))
        wait_port(edge, processes)
        wait_port(public["ports"]["reality"], processes)
        curl = ["curl", "--silent", "--show-error", "--fail", "--noproxy", "*", "--max-time", "12", "--cacert", cert]
        # Ordinary TLS to the REALITY SNI must reach its loopback website target.
        body = run(curl + ["--http2", "--resolve", f"site.example.com:{edge}:127.0.0.1", "-w", "\n%{http_version}", f"https://site.example.com:{edge}/"])
        if body != "sb-integration-site\n2":
            raise AssertionError("REALITY browser fallback did not negotiate and serve HTTP/2")
        verified.append("REALITY HTTPS fallback with HTTP/2")
        path = subscription.routes(public, secret["subscription_token"])[0]["path"]
        body = run(curl + ["--resolve", f"sub.example.com:{edge}:127.0.0.1", f"https://sub.example.com:{edge}" + path])
        if len(yaml.safe_load(body)["proxies"]) != len(public["nodes"]):
            raise AssertionError("SNI subscription path did not return the generated bundle")
        verified.append("HTTPS subscription via separate SNI")
        for node in public["nodes"]:
            candidate = dict(node, server="127.0.0.1", port=node["port"] if node["protocol"] == "vmess" else edge)
            proxy = protocols.to_mihomo(candidate, secret["nodes"][node["id"]])
            # Trust the temporary self-signed fixture by its exact leaf pin. This
            # exercises certificate verification without editing the system CA.
            if node["protocol"] == "hysteria2":
                der = run(["openssl", "x509", "-in", cert, "-outform", "DER"], text=False)
                proxy["fingerprint"] = hashlib.sha256(der).hexdigest()
            mixed = free_port()
            client = {"mixed-port": mixed, "allow-lan": False, "bind-address": "127.0.0.1", "mode": "rule",
                      "log-level": "warning", "dns": {"enable": False}, "proxies": [proxy],
                      "rules": ["MATCH," + node["name"]]}
            client_file = directory / (node["protocol"] + "-client.yaml")
            client_file.write_text(yaml.safe_dump(client, allow_unicode=True))
            log = (directory / (node["protocol"] + "-client.log")).open("w+")
            logs.append(log)
            process = subprocess.Popen([str(cores["mihomo"]), "-d", str(directory), "-f", str(client_file)], stdout=log, stderr=subprocess.STDOUT)
            processes.append(process)
            wait_port(mixed, processes)
            body = run(["curl", "--silent", "--show-error", "--fail", "--noproxy", "", "--max-time", "15",
                        "--proxy", f"socks5h://127.0.0.1:{mixed}", f"http://127.0.0.1:{target.server_port}/"])
            if body != "sb-integration-proxy-data":
                raise AssertionError("Proxy traffic content mismatch")
            verified.append(node["protocol"] + " Mihomo to sing-box proxied TCP traffic")
            process.terminate()
            process.wait(timeout=10)
            processes.remove(process)
            # A negative control proves the successful request depended on proxy
            # authentication/certificate verification, rather than a direct path.
            if node["protocol"] in ("vless", "vmess"):
                proxy["uuid"] = "00000000-0000-0000-0000-000000000001"
            else:
                proxy["fingerprint"] = "00" * 32
            client_file.write_text(yaml.safe_dump(client, allow_unicode=True))
            failed = subprocess.Popen([str(cores["mihomo"]), "-d", str(directory), "-f", str(client_file)], stdout=log, stderr=subprocess.STDOUT)
            processes.append(failed)
            wait_port(mixed, processes)
            negative = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--noproxy", "", "--max-time", "5",
                                       "--proxy", f"socks5h://127.0.0.1:{mixed}", f"http://127.0.0.1:{target.server_port}/"],
                                      capture_output=True, timeout=8)
            if negative.returncode == 0:
                raise AssertionError("Invalid authentication or certificate pin unexpectedly succeeded")
            verified.append(node["protocol"] + " invalid " + ("UUID" if node["protocol"] in ("vless", "vmess") else "certificate pin") + " refused")
            failed.terminate()
            failed.wait(timeout=10)
            processes.remove(failed)
        probe_state = copy.deepcopy(public)
        for node in probe_state["nodes"]:
            if node["protocol"] != "vmess":
                node["port"] = edge
        with patch.dict(os.environ, {"SSL_CERT_FILE": str(cert)}):
            probe.local_nodes(probe_state, secret, cores["mihomo"])
        verified.append("production transaction local_nodes probe with temporary trust")
        return verified
    except Exception:
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read()[-3000:], file=sys.stderr)
        raise
    finally:
        for process in reversed(processes):
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for log in logs:
            log.close()
        subscription_server.shutdown()
        subscription_server.server_close()
        subscription_thread.join(3)
        target.shutdown()
        target.server_close()
        target_thread.join(3)


def cases():
    yield "vmess", "http", "none"
    yield "vless", "tcp", "reality"
    yield "vless", "h2", "reality"
    for protocol in ("vless", "vmess", "trojan"):
        for transport in ("tcp", "ws", "h2", "httpupgrade"):
            yield protocol, transport, "tls"
    for protocol, security in (("hysteria2", "tls"), ("tuic", "tls"), ("anytls", "tls"),
                               ("shadowsocks", "none"), ("socks", "none")):
        yield protocol, "quic" if protocol in ("hysteria2", "tuic") else "tcp", security


def remap(value, cert, key, site):
    if isinstance(value, dict):
        return {k: str(cert) if k == "certificate_path" else str(key) if k == "key_path" else
                str(site) if k == "directory" else remap(v, cert, key, site) for k, v in value.items()}
    if isinstance(value, list):
        return [remap(v, cert, key, site) for v in value]
    return value


def synthetic_snapshot(cache, mihomo):
    """Build deterministic valid MRS fixtures for all four source sections.

    This proves assembly/core compatibility; it does not claim upstream releases
    or production domain coverage. --remote-rules additionally validates live data.
    """
    tag = "rules-integration-fixture"
    directory = cache / tag
    directory.mkdir(parents=True)
    providers, files = {}, {}
    for name, (rel, behavior) in snapshot.PROVIDERS.items():
        source = directory / "input.txt"
        source.write_text("192.0.2.0/24\n" if behavior == "ipcidr" else "fixture.example\n")
        target = directory / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        run([mihomo, "convert-ruleset", behavior, "text", source, target])
        body = target.read_bytes()
        providers[name] = {"path": rel, "behavior": behavior, "format": "mrs"}
        files[rel] = {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    inline = {"schema_version": 1, "build_id": tag, "sections": {name: [] for name in snapshot.SECTIONS}}
    inline["sections"]["services"] = ["DOMAIN-KEYWORD,integration-fixture"]
    raw = json.dumps(inline).encode()
    (directory / "inline-rules.json").write_bytes(raw)
    files["inline-rules.json"] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    manifest = {"schema_version": 1, "build_id": tag, "tag": tag, "created_at": int(time.time()),
                "fake_ip_pool": "198.18.0.0/16", "providers": providers, "files": files,
                "sources": {name: {"fixture": True} for name in ("loyal", "acl", "meta", "personal")}}
    (directory / "build-manifest.json").write_text(json.dumps(manifest))
    return tag, rules.load(cache, tag)


def check(directory, cores, remote=False):
    cert, key = certificates(directory)
    public, secret = state.create("site.example.com", "sub.example.com", "test@example.com")
    public["rules"]["enabled"] = False
    checked = []
    for index, (protocol, transport, security) in enumerate(cases()):
        name = "-".join((protocol, transport, security))
        identity = cli.add_local(public, secret, protocol=protocol, name=name, server="127.0.0.1",
                                 port=31000 + index, transport=transport, security=security, offline=True)
        node = public["nodes"][-1]
        node["listen"] = "127.0.0.1"
        # Check each inbound independently so diagnostics identify the failing case.
        candidate = dict(public, nodes=[node])
        inbound = json.loads(render.render(candidate, secret)["/etc/sing-box/sb/config.json"])
        config = directory / "server-check.json"
        config.write_text(json.dumps(remap(inbound, cert, key, directory)))
        try:
            run([cores["sing-box"], "check", "-c", config])
        except RuntimeError as exc:
            raise RuntimeError(name + ": " + str(exc)) from None
        node_again, creds_again = protocols.parse_uri(protocols.to_uri(node, secret["nodes"][identity]))
        if protocols.to_mihomo(node, secret["nodes"][identity]) != protocols.to_mihomo(node_again, creds_again):
            raise AssertionError("Share link roundtrip changed " + name)
        checked.append(name)
        print("sing-box check: " + name, flush=True)
    cache = directory / "rules"
    tag, rule_snapshot = synthetic_snapshot(cache, cores["mihomo"])
    public["rules"].update(enabled=True, active_build=tag)
    config = subscription.render(public, secret, rule_snapshot)[subscription.DIRECTORY + "/clash.yaml"]
    diagnostic = directory / "client-check.yaml"
    diagnostic.write_text(yaml.safe_dump(rules.assemble(yaml.safe_load(config), *rule_snapshot, local_dir=cache / tag), allow_unicode=True))
    run([cores["mihomo"], "-t", "-d", directory, "-f", diagnostic])
    receipt = rules.validate(cache, tag, config, cores["mihomo"])
    rules.activation_artifacts(cache, tag, receipt, config)
    # A self-consistent manifest cannot make malformed MRS acceptable.
    broken_provider = next(iter(rule_snapshot[0]["providers"].values()))["path"]
    broken_path = cache / tag / broken_provider
    original = broken_path.read_bytes()
    manifest_path = cache / tag / "build-manifest.json"
    original_manifest = manifest_path.read_bytes()
    malformed = b"not-a-valid-mrs-payload"
    broken_path.write_bytes(malformed)
    changed = json.loads(original_manifest)
    changed["files"][broken_provider] = {"size": len(malformed), "sha256": hashlib.sha256(malformed).hexdigest()}
    manifest_path.write_text(json.dumps(changed))
    try:
        rules.validate(cache, tag, config, cores["mihomo"])
    except ValueError:
        pass
    else:
        raise AssertionError("A malformed MRS payload passed full validation")
    finally:
        broken_path.write_bytes(original)
        manifest_path.write_bytes(original_manifest)
    result = {"server_configuration_checks": checked, "mihomo_complete_four_source_fixture": True,
              "malformed_mrs_refused": True, "live_upstream_rules": None, "end_to_end_traffic": False}
    if remote:
        tag = rules.stage(cache)
        actual = rules.load(cache, tag)
        public["rules"]["active_build"] = tag
        config = subscription.render(public, secret, actual)[subscription.DIRECTORY + "/clash.yaml"]
        rules.validate(cache, tag, config, cores["mihomo"])
        result["live_upstream_rules"] = tag
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-rules", action="store_true", help="Also download and validate the current upstream candidate")
    parser.add_argument("--traffic", action="store_true", help="Verify signed Nginx package and run loopback REALITY/HY2 traffic")
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("This harness requires Linux; it does not install a runtime")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="sb-core-integration-") as temporary:
        directory = Path(temporary)
        cores = binaries(directory)
        result = check(directory, cores, args.remote_rules)
        if args.traffic:
            result["end_to_end_traffic"] = traffic(directory, cores)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
