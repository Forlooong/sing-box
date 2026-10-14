#!/usr/bin/env python3
"""Finite real-Mihomo soak using a complete downloaded private subscription.

python3 tests/soak_client.py --bundle /private/acceptance.json --output /private/soak.jsonl

The bundle uses acceptance_client's protected 0600 schema. Two persistent cores
retain the subscription's nodes, groups, rules and DNS, with isolated loopback
listeners, no TUN/LAN, and global mode to force each measured protocol. This
tests full configuration loading, refresh and traffic; it does not measure rule
routing decisions, GUI behavior, or unlimited uptime. Reports contain no URLs,
node names, credentials, controller secrets, or raw core diagnostics.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

if __package__:
    from . import acceptance_client as acceptance
else:
    import acceptance_client as acceptance

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sbmanager.subscription import _bounded_template
from sbmanager.transaction import atomic

Error = acceptance.AcceptanceError


def require(value, code):
    if not value:
        raise Error(code)


def fetch_subscription(bundle):
    """One verified HTTPS response supplies the actual configuration we run."""
    import yaml
    body, headers = acceptance.get_https(bundle["subscription_url"])
    require(headers.get("Profile-Update-Interval") == "12", "subscription_update_header")
    config = yaml.safe_load(body)
    require(isinstance(config, dict), "subscription_yaml")
    _bounded_template(config)
    proxies, groups = config.get("proxies"), config.get("proxy-groups")
    require(isinstance(proxies, list) and 2 <= len(proxies) <= 200
            and all(isinstance(p, dict) and isinstance(p.get("name"), str) for p in proxies), "subscription_proxies")
    names = [p["name"] for p in proxies]
    require(len(set(names)) == len(names) and not set(names) & {"DIRECT", "REJECT", "GLOBAL"}, "subscription_proxy_names")
    require(isinstance(groups, list) and len(groups) == 1 and isinstance(groups[0], dict)
            and groups[0].get("name") == "节点选择" and groups[0].get("type") == "select"
            and groups[0].get("proxies") == names, "subscription_group_members")
    require(isinstance(config.get("rules"), list) and config["rules"]
            and isinstance(config.get("dns"), dict), "subscription_rules_and_dns")
    selected = {}
    for expected in bundle["proxies"]:
        identity = {key: value for key, value in expected.items() if key != "name"}
        matches = [p for p in proxies if {k: v for k, v in p.items() if k != "name"} == identity]
        require(len(matches) == 1, "subscription_bundle_node_mismatch")
        selected["reality" if expected["type"] == "vless" else "hy2"] = matches[0]["name"]
    # Provider caches must stay under the private core directory. URL/contents
    # remain those of the downloaded subscription and are never copied to logs.
    for field in ("rule-providers", "proxy-providers"):
        providers = config.get(field, {})
        require(isinstance(providers, dict), "subscription_provider_schema")
        for provider in providers.values():
            require(isinstance(provider, dict), "subscription_provider_schema")
            if "path" in provider:
                path = provider["path"]
                require(isinstance(path, str) and path and not PurePosixPath(path).is_absolute()
                        and ".." not in PurePosixPath(path).parts and "\\" not in path
                        and ":" not in path, "subscription_provider_path")
    return config, selected


def isolated_config(config, socks_port, controller_port, dns_port, secret):
    value = copy.deepcopy(config)
    value.update({"port": 0, "mixed-port": 0, "socks-port": socks_port, "redir-port": 0,
                  "tproxy-port": 0, "allow-lan": False, "bind-address": "127.0.0.1",
                  "external-controller": "127.0.0.1:" + str(controller_port), "secret": secret,
                  "mode": "global", "log-level": "warning", "listeners": [], "tunnels": [],
                  "authentication": [], "skip-auth-prefixes": [], "routing-mark": 0})
    for key in ("external-controller-unix", "external-controller-pipe", "external-controller-tls",
                "external-ui", "external-ui-name", "external-ui-url", "external-doh-server", "interface-name"):
        value.pop(key, None)
    value.setdefault("tun", {}).update(enable=False, **{"auto-route": False, "auto-redirect": False})
    value.setdefault("iptables", {})["enable"] = False
    value["dns"]["listen"] = "127.0.0.1:" + str(dns_port)
    # Prevent unrelated NTP system clock adjustment from a custom template.
    if isinstance(value.get("ntp"), dict):
        value["ntp"]["write-to-system"] = False
    return value


class Client:
    def __init__(self, directory, binary, protocol):
        self.directory, self.binary, self.protocol = directory, binary, protocol
        directory.mkdir(mode=0o700)
        ports = set()
        while len(ports) < 3:
            ports.add(acceptance.free_port())
        self.socks, self.controller, self.dns = sorted(ports)
        self.secret = secrets.token_urlsafe(32)
        self.path = directory / "client.yaml"
        self.log = (directory / "client.log").open("wb")
        self.process = None
        self.selected = None
        self.expected_providers = set()
        self.provider_types = {}
        self.provider_retry_attempts = 0
        self.provider_retry_failures = 0

    def api(self, path, method="GET", payload=None, *, timeout=30):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request("http://127.0.0.1:" + str(self.controller) + path,
            data=body, method=method, headers={"Authorization": "Bearer " + self.secret,
                                              "Content-Type": "application/json"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), acceptance.NoRedirect())
        with opener.open(request, timeout=timeout) as response:
            require(response.status in (200, 204), "controller_status")
            raw = response.read(acceptance.MAX_BODY + 1)
            require(len(raw) <= acceptance.MAX_BODY, "controller_body_limit")
            return json.loads(raw) if raw else None

    def status(self):
        result = {"pid": self.process.pid if self.process else None,
                  "exit_code": self.process.poll() if self.process else None, "rss_kib": None,
                  "provider_retry_attempts": self.provider_retry_attempts,
                  "provider_retry_failures": self.provider_retry_failures}
        if self.process and result["exit_code"] is None:
            try:
                for line in Path("/proc", str(self.process.pid), "status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        result["rss_kib"] = int(line.split()[1])
                        break
            except (OSError, ValueError):
                pass
        return result

    def alive(self):
        require(self.process is not None and self.process.poll() is None, "client_process_exited")

    def configure(self, config, selected):
        import yaml
        candidate = isolated_config(config, self.socks, self.controller, self.dns, self.secret)
        atomic(self.path, yaml.safe_dump(candidate, allow_unicode=True, sort_keys=False).encode(), 0o600)
        checked = subprocess.run([str(self.binary), "-t", "-d", str(self.directory), "-f", str(self.path)],
                                 stdout=self.log, stderr=subprocess.STDOUT, timeout=90)
        require(checked.returncode == 0, "client_configuration_rejected")
        if self.process is None:
            self.process = subprocess.Popen([str(self.binary), "-d", str(self.directory), "-f", str(self.path)],
                                            stdout=self.log, stderr=subprocess.STDOUT)
            for _ in range(150):
                self.alive()
                try:
                    self.api("/version")
                    break
                except (OSError, ValueError):
                    time.sleep(.1)
            else:
                raise Error("client_startup_timeout")
        else:
            self.alive()
            self.api("/configs?force=true", "PUT", {"path": str(self.path)})
        self.selected = selected[self.protocol]
        self.expected_providers = set(config.get("rule-providers", {}))
        self.provider_types = {name: value.get("type") for name, value in config.get("rule-providers", {}).items()}
        self.api("/proxies/" + urllib.parse.quote("节点选择", safe=""), "PUT", {"name": self.selected})
        self.api("/proxies/GLOBAL", "PUT", {"name": "节点选择"})
        self.verify_selection()
        self.wait_providers()

    def wait_providers(self):
        # Controller inspection proves provider loading, not just valid YAML.
        # A failed initial HTTP fetch may otherwise wait for its 12-hour refresh
        # interval. Retry via the core's own configured proxy, without supplying
        # local substitutes or accepting missing/empty rule data.
        deadline = time.monotonic() + 120
        next_retry = time.monotonic() + 15
        attempts = {name: 0 for name in self.expected_providers}
        while time.monotonic() < deadline:
            self.alive()
            remaining = max(.1, deadline - time.monotonic())
            providers = self.api("/providers/rules", timeout=min(10, remaining)).get("providers", {})
            pending = [name for name in self.expected_providers
                       if name not in providers or providers[name].get("ruleCount", 0) <= 0]
            if not pending:
                return
            if time.monotonic() >= next_retry:
                for name in pending:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    if self.provider_types.get(name) != "http" or attempts[name] >= 2:
                        continue
                    attempts[name] += 1
                    self.provider_retry_attempts += 1
                    try:
                        self.api("/providers/rules/" + urllib.parse.quote(name, safe=""), "PUT",
                                 timeout=min(20, remaining))
                    except (OSError, ValueError, Error):
                        self.provider_retry_failures += 1
                next_retry = time.monotonic() + 15
            time.sleep(.2)
        raise Error("rule_providers_not_ready")

    def verify_selection(self):
        self.alive()
        runtime = self.api("/configs")
        require(runtime.get("mode") == "global" and runtime.get("allow-lan") is False
                and not runtime.get("tun", {}).get("enable")
                and runtime.get("socks-port") == self.socks, "client_isolation_or_mode")
        group = self.api("/proxies/" + urllib.parse.quote("节点选择", safe=""))
        global_group = self.api("/proxies/GLOBAL")
        require(group.get("now") == self.selected and global_group.get("now") == "节点选择", "client_selection_mismatch")

    def request(self, bundle):
        self.verify_selection()
        body = self.directory / "response.bin"
        settings = "\n".join(("url = " + acceptance.curl_quote(bundle["site_url"]),
            "proxy = " + acceptance.curl_quote("socks5h://127.0.0.1:" + str(self.socks)),
            'noproxy = ""', 'proto = "=https"', "silent", "show-error", "fail",
            "connect-timeout = 6", "max-time = 20", "max-filesize = " + str(acceptance.MAX_BODY),
            'header = "Accept-Encoding: identity"', ""))
        try:
            result = subprocess.run(["curl", "-q", "--config", "-", "--output", str(body)],
                input=settings.encode(), stdout=subprocess.DEVNULL, stderr=self.log, timeout=25)
            self.alive()
            require(result.returncode == 0, "proxied_https_failed")
            require(body.stat().st_size <= acceptance.MAX_BODY
                    and hashlib.sha256(body.read_bytes()).hexdigest() == bundle["expected_site_sha256"],
                    "proxied_site_digest_mismatch")
            self.verify_selection()
        finally:
            body.unlink(missing_ok=True)

    def close(self):
        if self.process:
            acceptance.stop(self.process)
        self.log.close()


def cycle(clients, bundle, duration, interval, refresh_interval, emit, *, clock=time.monotonic, sleep=time.sleep):
    start = clock()
    next_refresh, next_sample = start + refresh_interval, start
    counts = {name: {"passed": 0, "failed": 0} for name in ("reality", "hy2")}
    refreshes, refresh_failures = 0, 0
    while clock() - start < duration:
        now = clock()
        if now >= next_refresh:
            event = {"event": "subscription_refresh", "elapsed_seconds": round(now - start, 3)}
            try:
                config, selected = fetch_subscription(bundle)
                for client in clients:
                    client.configure(config, selected)
                event["status"] = "passed"
                refreshes += 1
            except Exception as exc:
                event.update(status="failed", category=acceptance.category(exc))
                refresh_failures += 1
            emit(event)
            next_refresh = clock() + refresh_interval
        for client in clients:
            began = clock()
            event = {"event": "traffic", "protocol": client.protocol, "elapsed_seconds": round(began - start, 3)}
            try:
                client.request(bundle)
                event["status"] = "passed"
            except Exception as exc:
                event.update(status="failed", category=acceptance.category(exc))
            event.update(latency_ms=round((clock() - began) * 1000, 1), **client.status())
            counts[client.protocol][event["status"]] += 1
            emit(event)
            client.alive()  # Process death ends the run, after its sample was recorded.
        next_sample += interval
        if next_sample <= clock():
            next_sample = clock() + interval
        sleep(max(0, min(next_sample, start + duration) - clock()))
    # The last sleep is part of the observation window. A core can die after
    # the final successful request; never report success without a final probe.
    final_failures = 0
    for client in clients:
        event = {"event": "client_final", "protocol": client.protocol,
                 "elapsed_seconds": round(clock() - start, 3)}
        try:
            client.verify_selection()
            event["status"] = "passed"
        except Exception as exc:
            event.update(status="failed", category=acceptance.category(exc))
        event.update(client.status())
        if event.get("exit_code") is not None:
            event.update(status="failed", category="client_process_exited")
        if event["status"] == "failed":
            final_failures += 1
        emit(event)
    return {"elapsed_seconds": round(clock() - start, 3), "traffic": counts,
            "refreshes_passed": refreshes, "refreshes_failed": refresh_failures,
            "final_checks_failed": final_failures,
            "status": "passed" if not refresh_failures and not final_failures
                      and all(v["passed"] and not v["failed"] for v in counts.values()) else "failed"}


def bounded_seconds(value):
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("seconds must be numeric") from None
    if not math.isfinite(number) or not 1 <= number <= 86400:
        raise argparse.ArgumentTypeError("seconds must be between 1 and 86400")
    return number


def parser():
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--output", type=Path, help="New protected JSONL report; existing files are never overwritten")
    result.add_argument("--duration", type=bounded_seconds, default=3600)
    result.add_argument("--interval", type=bounded_seconds, default=30)
    result.add_argument("--refresh-interval", type=bounded_seconds, default=300)
    return result


def download_cores(directory):
    if __package__:
        from .integration_core import binaries
    else:
        from integration_core import binaries
    with (directory / "download.log").open("w", encoding="utf-8") as log:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            return binaries(directory)


def main(argv=None):
    options = parser()
    args = options.parse_args(argv)
    if args.interval > args.duration:
        options.error("--interval cannot exceed --duration")
    old_umask = os.umask(0o077)
    output, clients, failure_snapshot = None, [], []
    old_signal = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    def emit(value):
        line = json.dumps(value, ensure_ascii=False)
        if output:
            output.write(line + "\n")
            output.flush()
            os.fsync(output.fileno())
        print(line, flush=True)
    try:
        require(sys.platform == "linux" and shutil.which("curl"), "linux_and_curl_required")
        if args.output:
            descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            output = os.fdopen(descriptor, "w", encoding="utf-8")
        bundle = acceptance.load_bundle(args.bundle)
        emit({"event": "started", "started_at": datetime.now(timezone.utc).isoformat(),
              "duration_seconds": args.duration, "interval_seconds": args.interval,
              "refresh_interval_seconds": args.refresh_interval, "client": "mihomo",
              "configuration": "complete_subscription", "traffic_mode": "global_forced_protocol"})
        with tempfile.TemporaryDirectory(prefix="sb-client-soak-") as raw:
            directory = Path(raw)
            try:
                config, selected = fetch_subscription(bundle)
                cores = download_cores(directory)
                versions = json.loads((ROOT / "versions.json").read_bytes())
                emit({"event": "pinned_core_verified", "version": versions["mihomo"]})
                for protocol in ("reality", "hy2"):
                    client = Client(directory / protocol, cores["mihomo"], protocol)
                    clients.append(client)
                    client.configure(config, selected)
                    emit({"event": "client_started", "protocol": protocol, **client.status()})
                summary = cycle(clients, bundle, args.duration, args.interval, args.refresh_interval, emit)
                emit(dict(summary, event="summary"))
                return 0 if summary["status"] == "passed" else 1
            finally:
                failure_snapshot = [{"protocol": c.protocol, **c.status()} for c in clients]
                for client in clients:
                    client.close()
    except (Exception, KeyboardInterrupt) as exc:
        emit({"event": "summary", "status": "failed", "category": acceptance.category(exc),
              "clients": failure_snapshot})
        return 1
    finally:
        signal.signal(signal.SIGTERM, old_signal)
        if output:
            output.close()
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
