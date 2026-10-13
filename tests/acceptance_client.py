#!/usr/bin/env python3
"""External Linux acceptance checks for an already deployed test server.

Usage: python3 tests/acceptance_client.py --bundle /private/acceptance.json

The caller supplies a regular JSON file owned by the current user with mode 0600
(or stricter), containing site_url, subscription_url, expected_site_sha256, and
proxies: the deployed default REALITY and HY2 Mihomo proxy dictionaries. Keep the
bundle outside Git and delete it after use; this script never modifies it.

Run from a different machine to test public reachability, with Python, PyYAML,
curl, and access to the pinned core releases. integration_core.binaries verifies
release SHA-256 and caches only public archives under .test-runtime. No package
installation, systemd, firewall, or system CA changes occur. HTTPS validation is
enabled throughout. URL/credential arguments never enter subprocess argv.

Only a result JSON is printed. Runtime configurations, response bodies and logs
stay in a private temporary directory and are removed, including after failures.
A passing negative control is bracketed by successful requests to distinguish
authentication rejection from a server that simply went offline. These tests do
not establish performance, long-term reliability, renewal, or China reachability.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_BODY = 8 * 1024 * 1024


class AcceptanceError(Exception):
    """Its message is a fixed, non-sensitive result category."""


def load_bundle(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o177 or info.st_size > 1024 * 1024):
            raise AcceptanceError("bundle_permissions_or_size")
        bundle = json.load(source)
    if not isinstance(bundle, dict):
        raise AcceptanceError("bundle_schema")
    for field in ("site_url", "subscription_url"):
        value = bundle.get(field)
        if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 33 for c in value):
            raise AcceptanceError("bundle_https_url")
        parsed = urllib.parse.urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.fragment or "\\" in value):
            raise AcceptanceError("bundle_https_url")
        if parsed.port not in (None, 443):
            raise AcceptanceError("bundle_https_port")
    digest = bundle.get("expected_site_sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        raise AcceptanceError("bundle_site_digest")
    bundle["expected_site_sha256"] = digest.lower()
    proxies = bundle.get("proxies")
    if (not isinstance(proxies, list) or len(proxies) != 2
            or any(not isinstance(p, dict) for p in proxies)
            or sorted(p.get("type", "") for p in proxies) != ["hysteria2", "vless"]):
        raise AcceptanceError("bundle_default_protocols")
    for proxy in proxies:
        if proxy.get("skip-cert-verify", False) is not False:
            raise AcceptanceError("bundle_verification_disabled")
        if proxy["type"] == "vless" and (proxy.get("tls") is not True or not proxy.get("reality-opts")):
            raise AcceptanceError("bundle_reality_required")
        if proxy.get("dialer-proxy"):
            raise AcceptanceError("bundle_proxy_chaining")
    return bundle


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_https(url):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with opener.open(request, timeout=20) as response:
        if response.status != 200:
            raise AcceptanceError("https_status")
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise AcceptanceError("https_body_limit")
        return body, response.headers


def check_site(bundle):
    body, _ = get_https(bundle["site_url"])
    if hashlib.sha256(body).hexdigest() != bundle["expected_site_sha256"]:
        raise AcceptanceError("site_digest_mismatch")


def check_subscription(bundle):
    import yaml

    body, headers = get_https(bundle["subscription_url"])
    if headers.get("Profile-Update-Interval") != "12":
        raise AcceptanceError("subscription_update_header")
    config = yaml.safe_load(body)
    if not isinstance(config, dict):
        raise AcceptanceError("subscription_yaml")
    proxies, groups = config.get("proxies"), config.get("proxy-groups")
    if (not isinstance(proxies, list) or len(proxies) < 2
            or any(not isinstance(p, dict) or not isinstance(p.get("name"), str) for p in proxies)
            or not isinstance(groups, list) or len(groups) != 1 or not isinstance(groups[0], dict)):
        raise AcceptanceError("subscription_single_group")
    names = [p["name"] for p in proxies]
    group = groups[0]
    if (len(set(names)) != len(names) or group.get("name") != "节点选择"
            or group.get("type") != "select" or group.get("proxies") != names):
        raise AcceptanceError("subscription_group_members")
    if not {"vless", "hysteria2"}.issubset({p.get("type") for p in proxies}):
        raise AcceptanceError("subscription_default_protocols")


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def curl_quote(value):
    # Bundle URLs were checked for control characters before reaching curl.
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def proxy_request(directory, mihomo, original, bundle, negative=False):
    import yaml

    proxy = copy.deepcopy(original)
    proxy["name"] = "acceptance-proxy"
    if negative:
        if proxy["type"] == "vless":
            replacement = str(uuid.uuid4())
            while replacement == proxy.get("uuid"):
                replacement = str(uuid.uuid4())
            proxy["uuid"] = replacement
        else:
            existing = str(proxy.get("fingerprint", "")).replace(":", "").lower()
            proxy["fingerprint"] = "11" * 32 if existing == "00" * 32 else "00" * 32
    port = free_port()
    config = {"socks-port": port, "allow-lan": False, "bind-address": "127.0.0.1",
              "mode": "rule", "log-level": "warning", "dns": {"enable": False},
              "proxies": [proxy], "rules": ["MATCH,acceptance-proxy"]}
    with tempfile.TemporaryDirectory(prefix="client-", dir=directory) as raw:
        private = Path(raw)
        config_path = private / "client.yaml"
        config_path.write_text(yaml.safe_dump(config, allow_unicode=True), encoding="utf-8")
        config_path.chmod(0o600)
        with (private / "client.log").open("wb") as log:
            checked = subprocess.run([str(mihomo), "-t", "-d", str(private), "-f", str(config_path)],
                                     stdout=log, stderr=subprocess.STDOUT, timeout=20)
            if checked.returncode:
                raise AcceptanceError("client_configuration_rejected")
            process = subprocess.Popen([str(mihomo), "-d", str(private), "-f", str(config_path)],
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise AcceptanceError("client_startup_failed")
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise AcceptanceError("client_startup_timeout")
                body = private / "response.bin"
                seconds = 8 if negative else 20
                curl_config = "\n".join((
                    "url = " + curl_quote(bundle["site_url"]),
                    "proxy = " + curl_quote("socks5h://127.0.0.1:" + str(port)),
                    'noproxy = ""', 'proto = "=https"', "silent", "show-error", "fail",
                    "connect-timeout = 6", "max-time = " + str(seconds),
                    "max-filesize = " + str(MAX_BODY), 'header = "Accept-Encoding: identity"', ""))
                result = subprocess.run(["curl", "-q", "--config", "-", "--output", str(body)],
                                        input=curl_config.encode(), stdout=subprocess.DEVNULL,
                                        stderr=log, timeout=seconds + 5)
                if process.poll() is not None:
                    raise AcceptanceError("client_exited_during_request")
                if negative:
                    if result.returncode == 0:
                        raise AcceptanceError("invalid_credentials_accepted")
                    # Unsupported flags, local file errors, and setup failures
                    # cannot count as evidence of remote credential rejection.
                    if result.returncode not in {7, 28, 35, 52, 55, 56, 60, 97}:
                        raise AcceptanceError("negative_control_inconclusive")
                elif result.returncode:
                    raise AcceptanceError("proxied_https_failed")
                elif body.stat().st_size > MAX_BODY or hashlib.sha256(body.read_bytes()).hexdigest() != bundle["expected_site_sha256"]:
                    raise AcceptanceError("proxied_site_digest_mismatch")
            finally:
                stop(process)


def category(exc):
    if isinstance(exc, AcceptanceError):
        return str(exc)
    if isinstance(exc, urllib.error.HTTPError):
        return "https_http_status"
    if isinstance(exc, urllib.error.URLError):
        return category(exc.reason)
    if isinstance(exc, ssl.SSLError):
        return "https_certificate_or_tls"
    if isinstance(exc, socket.gaierror):
        return "dns_resolution"
    if isinstance(exc, (TimeoutError, subprocess.TimeoutExpired)):
        return "operation_timeout"
    if isinstance(exc, KeyboardInterrupt):
        return "interrupted"
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return "invalid_input_or_response"
    if isinstance(exc, ImportError):
        return "missing_python_dependency"
    if isinstance(exc, OSError):
        return "local_io_or_network"
    return "acceptance_check_failed"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    checks, current = [], "environment"
    previous_umask = os.umask(0o077)
    try:
        if sys.platform != "linux" or shutil.which("curl") is None:
            raise AcceptanceError("linux_and_curl_required")
        current = "protected_bundle"
        bundle = load_bundle(args.bundle)
        checks.append({"check": current, "status": "passed"})
        for current, operation in (("public_https_site", check_site), ("public_https_subscription", check_subscription)):
            operation(bundle)
            checks.append({"check": current, "status": "passed"})
        with tempfile.TemporaryDirectory(prefix="sb-external-acceptance-") as raw:
            directory = Path(raw)
            current = "pinned_core_hashes"
            from integration_core import binaries
            with (directory / "download.log").open("w", encoding="utf-8") as log:
                with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
                    cores = binaries(directory)
            checks.append({"check": current, "status": "passed"})
            for proxy in sorted(bundle["proxies"], key=lambda item: item["type"], reverse=True):
                protocol = "reality" if proxy["type"] == "vless" else "hy2"
                for suffix, negative in (("public_traffic", False), ("invalid_credential_rejected", True),
                                         ("traffic_after_negative_control", False)):
                    current = protocol + "_" + suffix
                    proxy_request(directory, cores["mihomo"], proxy, bundle, negative)
                    checks.append({"check": current, "status": "passed"})
    except (Exception, KeyboardInterrupt) as exc:
        checks.append({"check": current, "status": "failed", "category": category(exc)})
        print(json.dumps({"status": "failed", "checks": checks}, ensure_ascii=False))
        return 1
    finally:
        os.umask(previous_umask)
    print(json.dumps({"status": "passed", "checks": checks}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
