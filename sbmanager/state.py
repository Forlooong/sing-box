"""Versioned, credential-separated management state and strict input boundaries."""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import re
import secrets
import uuid
from pathlib import Path, PurePosixPath

STATE = "/etc/sb/state.json"
SECRETS = "/etc/sb/secrets.json"
REVOKED = "/etc/sb/revoked-tokens.json"
TOKEN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
DEFAULT_SUBSCRIPTION_NAME = "我的订阅"


def domain(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Domain must be text")
    value = value.lower().rstrip(".")
    if len(value) > 253 or "." not in value:
        raise ValueError("Provide a fully qualified DNS domain")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("A DNS domain, not an IP address, is required")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in value.split(".")):
        raise ValueError("Invalid domain; use ASCII/Punycode DNS labels")
    return value


def prefix(value: str) -> str:
    value = value.strip("/")
    if len(value) > 160 or not value or any(
        not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", part) for part in value.split("/")
    ):
        raise ValueError("Prefix must contain safe URL path segments")
    if value.split("/")[0] in {"healthz", ".well-known"}:
        raise ValueError("Reserved subscription prefix")
    return value


def node_name(value: str) -> str:
    if (not isinstance(value, str) or not value or len(value) > 200
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or value in {"节点选择", "DIRECT", "REJECT"}):
        raise ValueError("Invalid/reserved node name")
    return value


def subscription_name(value: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 80 or value != value.strip()
            or any(ord(c) < 32 or 127 <= ord(c) < 160 or 0xD800 <= ord(c) <= 0xDFFF
                   or c in "/\\\u2028\u2029" for c in value)):
        raise ValueError("订阅名称须为 1–80 个字符，不能含首尾空白、换行、控制字符或斜杠")
    # Clash Verge Rev decodes filename* before splitting its RFC 5987 delimiter.
    if "''" in value:
        raise ValueError("为兼容客户端，订阅名称不能含连续两个英文单引号")
    return value


def logical_path(root: Path, name: str) -> Path:
    p = PurePosixPath(name)
    if not p.is_absolute() or ".." in p.parts or "\\" in name or "\0" in name:
        raise ValueError("Unsafe managed path")
    root = root.resolve()
    result = root.joinpath(*p.parts[1:])
    # No managed file may escape via an existing symlink, even under /.
    cursor = result
    while cursor != root:
        if cursor.is_symlink():
            raise ValueError("Managed path crosses a symlink: " + name)
        cursor = cursor.parent
    if not result.resolve().is_relative_to(root):
        raise ValueError("Managed path escapes filesystem root")
    return result


def encode(value) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def create(site: str, subscription: str, email: str, path="private"):
    site, subscription = domain(site), domain(subscription)
    if site == subscription:
        raise ValueError("Website and subscription domains must differ")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise ValueError("A certificate contact email is required")
    state = {
        "schema_version": 1, "installation_id": str(uuid.uuid4()),
        "domains": {"site": site, "subscription": subscription,
                    "site_aliases": [], "subscription_aliases": []},
        "email": email,
        "ports": {"reality": 2443, "site_tls": 8443, "sub_tls": 8444,
                  "sub_http": 8767, "hy2": 443},
        "site": {"root": "/var/www/sb-site"},
        "subscription": {"name": DEFAULT_SUBSCRIPTION_NAME, "prefix": prefix(path), "aliases": [], "metadata": {}, "template": {}},
        "nodes": [], "rules": {"enabled": True, "active_build": None, "channel": "v1"},
        "legacy": {"entries": [], "files": {}, "services": []},
    }
    return state, {"subscription_token": secrets.token_urlsafe(32), "nodes": {}}


def validate(state, secret):
    if state.get("schema_version") != 1:
        raise ValueError("Unsupported state schema; use a compatible release")
    channel = state.get("rules", {}).get("channel", "v1")
    if not isinstance(channel, str) or channel not in {"v1", "v2"}:
        raise ValueError("Unsupported rule channel; choose v1 or v2")
    uuid.UUID(state["installation_id"])
    d = state["domains"]
    sites = [domain(d["site"])] + [domain(x) for x in d["site_aliases"]]
    subs = [domain(d["subscription"])] + [domain(x) for x in d["subscription_aliases"]]
    if set(sites) & set(subs) or len(sites) != len(set(sites)) or len(subs) != len(set(subs)):
        raise ValueError("Domain roles or aliases conflict")
    prefix(state["subscription"]["prefix"])
    subscription_name(state["subscription"].get("name", DEFAULT_SUBSCRIPTION_NAME))
    if not TOKEN.fullmatch(secret.get("subscription_token", "")):
        raise ValueError("Invalid subscription token")
    ports = state["ports"]
    for k in ("reality", "site_tls", "sub_tls", "sub_http", "hy2"):
        if type(ports[k]) is not int or not 1 <= ports[k] <= 65535:
            raise ValueError("Invalid reserved port")
    tcp = [ports[k] for k in ("reality", "site_tls", "sub_tls", "sub_http")]
    if len(set(tcp)) != len(tcp) or set(tcp) & {80, 443}:
        raise ValueError("Internal TCP listeners overlap")
    root = state["site"]["root"]
    if not re.fullmatch(r"/var/www/[A-Za-z0-9_/-]+", root) or ".." in root.split("/"):
        raise ValueError("Website root must be a safe directory under /var/www")
    ids, names = set(), set()
    for node in state["nodes"]:
        identity = node["id"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", identity) or identity in ids:
            raise ValueError("Invalid/duplicate node ID")
        name = node_name(node["name"])
        if name in names:
            raise ValueError("Node names must be unique")
        if node.get("source") not in {"local", "uri", "legacy"}:
            raise ValueError("Invalid node source")
        if any(k in node for k in ("uuid", "password", "private_key", "obfs_password")):
            raise ValueError("Credentials cannot be stored in public node state")
        if identity not in secret["nodes"]:
            raise ValueError("Node credential reference is missing")
        ids.add(identity)
        names.add(name)
    for alias in state["subscription"]["aliases"]:
        domain(alias["domain"])
        prefix(alias["prefix"])
        if alias.get("suffix", "") not in {"", "/clash.yaml"}:
            raise ValueError("Invalid legacy route suffix")
    return state


def load(root=Path("/")):
    state = json.loads(logical_path(root, STATE).read_bytes())
    secret = json.loads(logical_path(root, SECRETS).read_bytes())
    validate(state, secret)
    digest = hashlib.sha256(secret["subscription_token"].encode()).hexdigest()
    revocations = logical_path(root, REVOKED)
    if revocations.exists() and digest in json.loads(revocations.read_bytes()):
        raise ValueError("Saved subscription token has been revoked; recovery required")
    return state, secret


def public_view(state):
    result = copy.deepcopy(state)
    # Never leak imported URIs or migration private artifacts added by an adapter.
    result.get("legacy", {}).pop("files", None)
    result.get("legacy", {}).pop("private", None)
    return result


def remember_alias(state):
    item = {"domain": state["domains"]["subscription"],
            "prefix": state["subscription"]["prefix"], "suffix": ""}
    if item not in state["subscription"]["aliases"]:
        state["subscription"]["aliases"].append(item)
