"""Pure compilation of an immutable, private subscription runtime bundle."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import re

import yaml

from . import protocols

DIRECTORY = "/var/lib/sb/subscription"
MANAGED_FIELDS = {"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules", "sub-rules"}
MAX_NODES = 200
MAX_BUNDLE = 8 * 1024 * 1024


def _bounded_template(value, active=None, budget=None, depth=0):
    """Reject recursive YAML aliases and resource-heavy client overrides."""
    active = set() if active is None else active
    budget = [10000] if budget is None else budget
    budget[0] -= 1
    if budget[0] < 0 or depth > 32:
        raise ValueError("Client template is too complex")
    if isinstance(value, (dict, list)):
        if id(value) in active:
            raise ValueError("Recursive YAML aliases are not valid client settings")
        active.add(id(value))
        if isinstance(value, dict) and any(not isinstance(k, str) for k in value):
            raise ValueError("Client template keys must be strings")
        for item in value.values() if isinstance(value, dict) else value:
            _bounded_template(item, active, budget, depth + 1)
        active.remove(id(value))
    elif not isinstance(value, (str, int, float, bool, type(None))):
        raise ValueError("Unsupported client template value")


def default_template():
    return yaml.safe_load(Path(__file__).with_name("template.yaml").read_text(encoding="utf-8"))


def _merge(base, override):
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def template_config(override=None):
    override = {} if override is None else override
    if not isinstance(override, dict) or MANAGED_FIELDS.intersection(override):
        raise ValueError("Nodes, groups and rules are managed; edit only the client template fields")
    _bounded_template(override)
    result = _merge(default_template(), override)
    dns = result.get("dns")
    if not isinstance(dns, dict) or not dns.get("proxy-server-nameserver"):
        raise ValueError("Template requires independent bootstrap DNS for proxy servers")
    for group in MANAGED_FIELDS:
        if group in result:
            raise ValueError("Managed field in default template")
    return result


def _prefix(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}(?:/[A-Za-z0-9_-]{1,64}){0,7}", value):
        raise ValueError("Subscription prefix must contain safe nonempty path segments")
    return value


def metadata_headers(metadata):
    if not isinstance(metadata, dict) or set(metadata) - {"upload", "download", "total", "expire", "reset_day", "reset_at", "note"}:
        raise ValueError("Unknown subscription metadata field")
    traffic = {"upload", "download", "total"}
    if traffic.intersection(metadata) and not traffic <= metadata.keys():
        raise ValueError("Upload, download and total must be supplied together")
    for key in traffic | {"expire", "reset_at"}:
        if key in metadata and (not isinstance(metadata[key], int) or isinstance(metadata[key], bool) or not 0 <= metadata[key] <= 2**63 - 1):
            raise ValueError("Metadata counters and timestamps must be nonnegative integers")
    if "reset_day" in metadata and (not isinstance(metadata["reset_day"], int) or isinstance(metadata["reset_day"], bool) or not 1 <= metadata["reset_day"] <= 31):
        raise ValueError("Reset day must be between 1 and 31")
    if "note" in metadata and (not isinstance(metadata["note"], str) or len(metadata["note"]) > 500 or any(ord(c) < 32 for c in metadata["note"])):
        raise ValueError("Invalid metadata note")
    # Expiry is a timestamp, never inferred from billing/reset day.
    fields = [f"{key}={metadata[key]}" for key in ("upload", "download", "total", "expire") if key in metadata]
    return {"Subscription-Userinfo": "; ".join(fields)} if fields else {}


def routes(state, token):
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        raise ValueError("Subscription token must contain 256 bits of URL-safe random data")
    sub = state["subscription"]
    endpoints = [{"domain": state["domains"]["subscription"], "prefix": sub["prefix"], "suffix": ""}]
    endpoints += sub.get("aliases", [])
    # Domain aliases keep TLS/SNI ownership only. Routes are explicit historical
    # (domain, prefix) pairs, so retiring a path cannot recreate it implicitly.
    if len(endpoints) > 100:
        raise ValueError("Too many subscription aliases")
    result, seen = [], set()
    for endpoint in endpoints:
        domain = protocols.hostname(endpoint["domain"])
        prefix = _prefix(endpoint["prefix"])
        suffix = endpoint.get("suffix", "")
        if suffix not in ("", "/clash.yaml"):
            raise ValueError("Unsupported legacy subscription suffix")
        base = "/" + prefix + "/" + token
        for path, artifact in ((base + suffix, "clash"), (base + "/raw", "raw")):
            key = (domain, path)
            if key not in seen:
                seen.add(key)
                result.append({"host": domain, "path": path, "artifact": artifact})
    return result


def urls(state, secrets):
    token = secrets["subscription_token"]
    current = routes(state, token)[:2]
    return {row["artifact"]: "https://" + row["host"] + row["path"] for row in current}


def compile_config(state, secrets, snapshot=None, *, local_rules=None):
    """Return (document, raw_bytes, omitted_nodes), without writing or networking."""
    template = template_config(state["subscription"].get("template", {}))
    nodes = state.get("nodes", [])
    if not isinstance(nodes, list) or len(nodes) > MAX_NODES:
        raise ValueError("A subscription supports at most 200 nodes")
    proxies, uris, omitted, names, ids = [], [], [], set(), set()
    for node in nodes:
        if not node.get("enabled", True):
            continue
        if node["id"] in ids:
            raise ValueError("Duplicate registry node ID")
        ids.add(node["id"])
        name = protocols.node_name(node["name"])
        if name in names:
            raise ValueError("Node names must be unique; rename the conflicting node")
        names.add(name)
        if node.get("exportable") is False:
            if node.get("source") != "legacy":
                raise ValueError("Only explicitly marked legacy nodes can bypass Mihomo export")
            raw = secrets.get("legacy_uris", {}).get(node.get("raw_uri_ref", node["id"]))
            if raw is not None:
                if not isinstance(raw, str) or len(raw) > 16384 or any(c.isspace() or ord(c) < 32 for c in raw):
                    raise ValueError("Malformed preserved legacy share link")
                uris.append(raw)
            omitted.append({"id": node["id"], "name": name, "protocol": node["protocol"],
                            "reason": "Legacy protocol cannot be represented in Mihomo", "raw_preserved": raw is not None})
            continue
        credentials = secrets.get("nodes", {}).get(node["id"], {})
        compatible = copy.deepcopy(node)
        if compatible.get("source") == "legacy" and compatible.get("legacy_insecure"):
            compatible["insecure"] = True
        proxies.append(protocols.to_mihomo(compatible, credentials))
        uris.append(protocols.to_uri(compatible, credentials))
    if not proxies:
        raise ValueError("At least one enabled, Mihomo-compatible node is required")
    template["proxies"] = proxies
    template["proxy-groups"] = [{"name": protocols.GROUP, "type": "select", "proxies": [p["name"] for p in proxies]}]
    if state.get("rules", {}).get("enabled", True):
        if snapshot is None:
            raise ValueError("No verified rule snapshot is available; subscription was not published")
        from .rules import assemble
        template = assemble(template, *snapshot, local_dir=local_rules)
    else:
        template["rule-providers"] = {}
        template["rules"] = ["MATCH," + protocols.GROUP]
    return template, base64.b64encode(("\n".join(uris) + "\n").encode()), omitted


def render(state, secrets, snapshot=None):
    document, raw, omitted = compile_config(state, secrets, snapshot)
    clash = yaml.safe_dump(document, allow_unicode=True, sort_keys=False).encode("utf-8")
    headers = {"Profile-Update-Interval": "12", **metadata_headers(state["subscription"].get("metadata", {}))}
    port = state["ports"]["sub_http"]
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("Subscription HTTP port must be an unprivileged TCP port")
    artifacts = {"clash": {"body": base64.b64encode(clash).decode(), "content_type": "text/yaml; charset=utf-8"},
                 "raw": {"body": base64.b64encode(raw).decode(), "content_type": "text/plain; charset=utf-8"}}
    bundle = {"schema_version": 1, "listen_host": "127.0.0.1", "listen_port": port,
              "routes": routes(state, secrets["subscription_token"]), "artifacts": artifacts, "headers": headers}
    bundle["generation"] = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest()
    runtime = (json.dumps(bundle, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    if len(runtime) > MAX_BUNDLE or len(clash) > MAX_BUNDLE // 2 or len(raw) > MAX_BUNDLE // 2:
        raise ValueError("Subscription exceeds the HTTP runtime resource limit")
    diagnostics = {"exported_nodes": len(document["proxies"]), "omitted_nodes": omitted,
                   "rules_build": snapshot[0]["build_id"] if snapshot else None}
    return {DIRECTORY + "/runtime.json": runtime,
            DIRECTORY + "/clash.yaml": clash, DIRECTORY + "/raw.txt": raw,
            DIRECTORY + "/template.yaml": yaml.safe_dump(template_config(state["subscription"].get("template", {})), allow_unicode=True, sort_keys=False).encode(),
            DIRECTORY + "/diagnostics.json": (json.dumps(diagnostics, ensure_ascii=False, indent=2) + "\n").encode()}
