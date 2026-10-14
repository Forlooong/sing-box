"""Consume a real unpublished v2 snapshot through the production compiler.

Only the download transport is replaced with local file reads. All staging,
hash checks, complete-subscription compilation, DNS validation and core calls
are real. Fixtures contain one loopback dummy node and no production secrets.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.request
from unittest.mock import patch

import yaml

from sbmanager import cli, protocols, rules, state, subscription
from sbmanager.vendor import snapshot


def _port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _refused(label, function, reason):
    try:
        function()
    except ValueError as exc:
        if reason.lower() not in str(exc).lower():
            raise AssertionError(label + " failed for an unexpected reason: " + str(exc)) from exc
    else:
        raise AssertionError(label + " was accepted")


def _policy_checks(document, manifest, inline):
    """Check policy invariants independently of the production assembler."""
    names = manifest["providers"]
    route = document["rules"]
    if route[-1] != "MATCH,节点选择" or any(",REJECT" in row for row in route):
        raise AssertionError("Default must proxy unmatched traffic without an advertising reject layer")
    ordered = ["personal-direct-domain", "personal-direct-ipcidr", "personal-proxy-domain",
               "personal-proxy-ipcidr", "private-domain", "private-ipcidr", "services-proxy",
               "telegram-ipcidr", "cn-domain", "cn-ipcidr"]
    actual = [row.split(",")[1] for row in route if row.startswith("RULE-SET,")]
    if actual != [name for name in ordered if name in names]:
        raise AssertionError("Personal/private/services/CN route priority differs from balanced-v2")
    if "RULE-SET,cn-ipcidr,DIRECT" not in route or "RULE-SET,cn-ipcidr,DIRECT,no-resolve" in route:
        raise AssertionError("CN IP fallback must resolve through the managed DNS policy")
    for section in ("private", "services", "direct"):
        if any(rule.startswith("PROCESS-") for rule in inline["sections"][section]):
            raise AssertionError("Automatic sections must not bypass routing by process")
    for direction, action in (("direct", "DIRECT"), ("proxy", "节点选择")):
        for behavior in ("domain", "ipcidr"):
            name = "personal-" + direction + "-" + behavior
            if name in names and "RULE-SET," + name + "," + action not in route:
                raise AssertionError("Personal route does not retain its explicit action")

    dns = document["dns"]
    remote = ["https://1.1.1.1/dns-query#节点选择", "https://8.8.8.8/dns-query#节点选择"]
    domestic = ["https://223.5.5.5/dns-query#DIRECT", "https://120.53.53.53/dns-query#DIRECT"]
    for field in ("nameserver", "direct-nameserver"):
        if dns.get(field) != remote:
            raise AssertionError(field + " must use proxy-bound encrypted DNS")
    for field in ("default-nameserver", "proxy-server-nameserver"):
        if dns.get(field) != domestic:
            raise AssertionError(field + " must retain independent encrypted bootstrap")
    if dns.get("respect-rules") is not False or dns.get("direct-nameserver-follow-policy") is not True:
        raise AssertionError("DNS recursion/follow-policy configuration drifted")
    if any(key in dns for key in ("fallback", "fallback-filter", "fallback-lazy-query", "proxy-server-nameserver-policy")):
        raise AssertionError("Managed DNS must not gain a hidden fallback")
    providers = document["rule-providers"]
    policy = {"localhost": "system", "+.localhost": "system"}
    for name in ("personal-direct-domain", "personal-proxy-domain", "dns-only-personal"):
        if name in providers:
            policy["rule-set:" + name] = remote
    policy.update({name: "system" for name in ("+.lan", "+.local", "+.home.arpa")})
    for name, resolver in (("private-domain", ["system"]), ("dns-only-private", ["system"]),
                           ("services-proxy", remote), ("dns-only-services", remote),
                           ("cn-domain", domestic), ("dns-only-direct", domestic)):
        if name in providers:
            policy["rule-set:" + name] = resolver
    if list(dns.get("nameserver-policy", {}).items()) != list(policy.items()):
        raise AssertionError("Personal/private/services/CN DNS priority or resolver differs from policy")
    return {"route_provider_order": actual, "dns_policy_order": list(policy),
            "personal_actions_preserved": True, "unknown_and_direct_dns_via_proxy": True}


def _loaded_core(directory, core, config, local_snapshot, api_port):
    """Load every file provider and inspect runtime rule order without traffic."""
    path = directory / "local-snapshot-core.yaml"
    path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    environment = dict(os.environ, SAFE_PATHS=str(local_snapshot), SKIP_SAFE_PATH_CHECK="false")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    api = "http://127.0.0.1:" + str(api_port)
    with (directory / "local-snapshot-core.log").open("w+") as log:
        process = subprocess.Popen([str(core), "-d", str(directory), "-f", str(path)],
                                   stdout=log, stderr=subprocess.STDOUT, env=environment)
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise AssertionError("Local snapshot core exited during startup")
                try:
                    with opener.open(api + "/providers/rules", timeout=.3) as response:
                        loaded = json.load(response)["providers"]
                    # The REST listener may accept requests before provider
                    # initialization finishes; its initial payload can be null.
                    if isinstance(loaded, dict) and set(config["rule-providers"]) <= set(loaded):
                        break
                except (OSError, KeyError):
                    pass
                time.sleep(.05)
            else:
                raise AssertionError("Local snapshot provider API did not become ready")
            for name, provider in config["rule-providers"].items():
                if provider["type"] == "file":
                    request = urllib.request.Request(api + "/providers/rules/" + name, method="PUT")
                    with opener.open(request, timeout=15) as response:
                        if response.status != 204:
                            raise AssertionError("Core did not load provider " + name)
            with opener.open(api + "/providers/rules", timeout=2) as response:
                loaded = json.load(response)["providers"]
            counts = {}
            for name, provider in config["rule-providers"].items():
                actual = loaded[name]
                if actual.get("behavior", "").lower() != provider["behavior"]:
                    raise AssertionError("Core loaded the wrong behavior for " + name)
                count = actual.get("ruleCount")
                if type(count) is not int or count <= 0:
                    raise AssertionError("Final selected provider must contain real rules: " + name)
                counts[name] = count
            with opener.open(api + "/rules", timeout=2) as response:
                core_rules = json.load(response)["rules"]
            expected = [row.split(",")[1] for row in config["rules"] if row.startswith("RULE-SET,")]
            actual = [row["payload"] for row in core_rules if row["type"] == "RuleSet"]
            if actual != expected or len(core_rules) != len(config["rules"]):
                raise AssertionError("Core runtime route sequence differs from compiled subscription")
            return {"loaded_provider_counts": counts, "runtime_rule_count": len(core_rules),
                    "runtime_route_priority_verified": True}
        except Exception:
            log.flush()
            log.seek(0)
            # This process only received synthetic credentials and public rules.
            print("Isolated snapshot fixture log:\n" + log.read()[-5000:])
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def check_local_snapshot(directory, core, source):
    core_version = subprocess.check_output([str(core), "-v"], text=True, timeout=10).strip().splitlines()[0]
    source = Path(source).resolve(strict=True)
    raw = (source / "build-manifest.json").read_bytes()
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("Local manifest exceeds the production size limit")
    manifest = snapshot.validate_manifest(json.loads(raw))
    if manifest.get("schema_version") != 2 or manifest.get("policy_version") != "balanced-v2":
        raise ValueError("Local snapshot acceptance requires balanced-v2")
    tag = manifest["build_id"]
    candidate = {"schema_version": 2, "policy_version": "balanced-v2", "build_id": tag,
                 "manifest_sha256": hashlib.sha256(raw).hexdigest()}
    prefix = rules.REPO + tag + "/"
    artifact = next(iter(manifest["providers"].values()))["path"]

    def local_download(url, maximum, deadline):
        if url == rules.CANDIDATE_V2:
            data = json.dumps(candidate).encode()
        elif url == prefix + "build-manifest.json":
            data = raw
        elif url.startswith(prefix) and url[len(prefix):] in manifest["files"]:
            target = source / url[len(prefix):]
            if target.is_symlink() or any(p.is_symlink() for p in target.parents if p != source.parent):
                raise ValueError("Local snapshot artifact cannot be a symlink")
            with target.open("rb") as stream:
                data = stream.read(maximum + 1)
        else:
            raise AssertionError("Unexpected network dependency during local acceptance")
        if len(data) > maximum:
            raise ValueError("Local source exceeds declared size")
        return data

    cache = directory / "local-rules"
    with patch.object(rules, "download", side_effect=local_download):
        if rules.stage(cache, channel="v2") != tag:
            raise AssertionError("Local staging returned another snapshot")
    actual = rules.load(cache, tag, channel="v2")
    for label, url in (("manifest", prefix + "build-manifest.json"), ("artifact", prefix + artifact)):
        def corrupt(url_requested, maximum, deadline):
            body = local_download(url_requested, maximum, deadline)
            return bytes([body[0] ^ 1]) + body[1:] if url_requested == url else body
        broken_cache = directory / ("rejected-" + label)
        with patch.object(rules, "download", side_effect=corrupt):
            _refused(label + " hash corruption", lambda: rules.stage(broken_cache, channel="v2"), "checksum")
        if (broken_cache / tag).exists() or (broken_cache / "active.json").exists():
            raise AssertionError("A corrupt snapshot left an activated or completed cache")

    public, private = state.create("site.example.com", "sub.example.com", "test@example.com")
    cli.add_local(public, private, name="LOCAL-DUMMY", protocol="socks", server="127.0.0.1",
                  port=_port(), security="none", offline=True)
    public["rules"].update(enabled=True, channel="v2", active_build=tag)
    ports = set()
    while len(ports) < 3:
        ports.add(_port())
    mixed_port, api_port, dns_port = sorted(ports)
    override = {"mixed-port": mixed_port, "external-controller": "127.0.0.1:" + str(api_port),
                "secret": "", "find-process-mode": "off", "dns": {"listen": "127.0.0.1:" + str(dns_port)}}
    public["subscription"]["template"] = override
    before = copy.deepcopy((public["nodes"], private["nodes"]))
    bundle = subscription.render(public, private, actual)
    config_bytes = bundle[subscription.DIRECTORY + "/clash.yaml"]
    document = yaml.safe_load(config_bytes)
    node = public["nodes"][0]
    expected_node = protocols.to_mihomo(node, private["nodes"][node["id"]])
    if document["proxies"] != [expected_node] or document["proxy-groups"] != [
            {"name": "节点选择", "type": "select", "proxies": ["LOCAL-DUMMY"]}]:
        raise AssertionError("Snapshot compilation changed nodes or single-group selection")
    if before != (public["nodes"], private["nodes"]):
        raise AssertionError("Compilation mutated the node registry")
    policy = _policy_checks(document, *actual)
    receipt = rules.validate(cache, tag, config_bytes, core, override=override)
    rules.activation_artifacts(cache, tag, receipt, config_bytes)
    _refused("post-validation config mutation", lambda: rules.activation_artifacts(
        cache, tag, receipt, config_bytes + b"\n"), "changed")
    for label in ("dns-resolver", "dns-order", "route-order"):
        broken = copy.deepcopy(document)
        if label == "dns-resolver":
            broken["dns"]["direct-nameserver"] = ["system"]
        elif label == "dns-order":
            broken["dns"]["nameserver-policy"] = dict(reversed(list(broken["dns"]["nameserver-policy"].items())))
        else:
            broken["rules"] = list(reversed(broken["rules"]))
        _refused(label + " tampering", lambda: rules.validate_assembly(broken, *actual, override=override),
                 "DNS" if label.startswith("dns-") else "configuration")
    local = rules.assemble(document, *actual, local_dir=cache / tag, override=override)
    runtime = _loaded_core(directory, core, local, cache / tag, api_port)
    # No write or repair of the provided build is allowed, including on failure.
    if (source / "build-manifest.json").read_bytes() != raw:
        raise AssertionError("Input manifest changed while testing")
    return {"build_id": tag, "core_version": core_version, "manifest_sha256": candidate["manifest_sha256"],
            "audit_manifest_sha256": manifest["audit"]["manifest_sha256"],
            "policy_version": manifest["policy_version"], "runtime_bytes": sum(v["size"] for v in manifest["files"].values()),
            "complete_single_group_subscription": True, "nodes_preserved": True,
            "staging_transport": "local files, candidate digest derived from input manifest",
            "negative_controls": ["manifest hash", "artifact hash", "config receipt hash", "DNS resolver", "DNS order", "route order"],
            "dns_upstream_traffic_tested": False, "external_proxy_traffic_tested": False, **policy, **runtime}
