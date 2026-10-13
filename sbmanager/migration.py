"""Conservative, read-only inventory and transactional legacy migration adapters.

No legacy shell code is sourced or run. Reports contain fingerprints and topology,
never node credentials, private keys, subscription tokens or configuration bodies.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import stat

import yaml

from . import protocols
from .state import domain, encode, validate
from .certificates import cert_paths


class MigrationError(ValueError):
    pass


BASE = "/etc/sing-box"
SUB = "/opt/subscription-generator"
KNOWN_TYPES = {"vless", "vmess", "hysteria2", "tuic", "trojan", "anytls", "shadowsocks", "socks", "direct"}
UNIT_DIRS = ("/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system")
LEGACY_CONFIG = "/etc/sing-box/sb-legacy/config.json"
LEGACY_SERVICE = "sb-sing-box-legacy.service"
OLD_RENEWAL = "/etc/letsencrypt/renewal/subscription-generator.conf"


def _path(root, name):
    value = PurePosixPath(name)
    if not value.is_absolute() or ".." in value.parts or "\\" in name or "\0" in name:
        raise MigrationError("Unsafe legacy file reference")
    root = Path(root).resolve()
    target = root.joinpath(*value.parts[1:])
    # Imported paths may have symlinks, but a mapped root must never be escaped.
    if not target.resolve().is_relative_to(root):
        raise MigrationError("Legacy symlink escapes inspected root")
    return target


def _read(root, name, limit=128 * 1024 * 1024):
    path = _path(root, name)
    if not path.is_file() or path.stat().st_size > limit:
        raise MigrationError("Missing, nonregular or oversized legacy file: " + name)
    return path.read_bytes()


def _json(root, name):
    try:
        value = json.loads(_read(root, name, 4 * 1024 * 1024))
    except (ValueError, UnicodeError):
        raise MigrationError("Invalid legacy JSON: " + name) from None
    if not isinstance(value, dict):
        raise MigrationError("Legacy JSON must be an object: " + name)
    return value


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip())


def _unit(root, name, expected):
    found = []
    for directory in UNIT_DIRS:
        path = _path(root, directory + "/" + name + ".service")
        if path.exists():
            found.append(directory + "/" + name + ".service")
    if not found:
        raise MigrationError("Recognized systemd unit is missing: " + name)
    text = _strip_comments(_read(root, found[0], 128 * 1024).decode())
    commands = re.findall(r"^(Exec\w+)=(.*)$", text, re.M)
    allowed = {("ExecStart", expected)}
    if name == "caddy":
        allowed.add(("ExecReload", "/usr/local/bin/caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile"))
    if commands.count(("ExecStart", expected)) != 1 or any(command not in allowed for command in commands):
        raise MigrationError("Customized service commands require manual migration: " + name)
    if re.search(r"^(?:Environment|EnvironmentFile|RootDirectory|RootImage|BindPaths|BindReadOnlyPaths|LoadCredential|SetCredential|NetworkNamespacePath|IPAddressAllow|IPAddressDeny)=", text, re.M):
        raise MigrationError("Custom service environment or namespace requires manual migration: " + name)
    for directory in UNIT_DIRS:
        overrides = _path(root, directory + "/" + name + ".service.d")
        if overrides.exists() and list(overrides.iterdir()):
            raise MigrationError("Service drop-ins require manual migration: " + name)
    return found


def _caddy(root):
    """Recognize only the literal 233boy grammar, never approximate custom rules."""
    if not _path(root, "/etc/caddy/Caddyfile").exists():
        return []
    text = _strip_comments(_read(root, "/etc/caddy/Caddyfile").decode())
    expected = r"\{\s*admin off\s+http_port 80\s+https_port 443\s*\}\s*import /etc/caddy/233boy/\*\.conf\s+import /etc/caddy/sites/\*\.conf"
    if not re.fullmatch(expected, text):
        raise MigrationError("Custom Caddyfile/global ports are outside automatic migration")
    custom = _path(root, "/etc/caddy/sites")
    if custom.exists() and any(custom.iterdir()):
        raise MigrationError("Custom Caddy sites must be migrated manually")
    _unit(root, "caddy", "/usr/local/bin/caddy run --environ --config /etc/caddy/Caddyfile --adapter caddyfile")
    entries = []
    directory = _path(root, "/etc/caddy/233boy")
    if not directory.exists():
        raise MigrationError("Caddy import directory is missing")
    for file in sorted(directory.iterdir()):
        if file.name.endswith(".conf.add"):
            continue
        if file.suffix != ".conf" or not file.is_file():
            raise MigrationError("Unknown Caddy import file")
        text = _strip_comments(file.read_text(encoding="utf-8"))
        pattern = (r"([a-zA-Z0-9.-]+):443\s*\{\s*reverse_proxy\s+(/[A-Za-z0-9_/-]+)\s+"
                   r"(h2c://)?127\.0\.0\.1:([0-9]{1,5})(\s*\{\s*transport http\s*\{\s*tls_insecure_skip_verify\s*\}\s*\})?"
                   r"\s+import (/etc/caddy/233boy/[A-Za-z0-9.-]+\.conf\.add)\s*\}")
        match = re.fullmatch(pattern, text)
        if not match:
            raise MigrationError("Unknown Caddy route; automatic migration is blocked")
        host, route, h2c, port, options, add = match.groups()
        host = domain(host)
        if file.name != host + ".conf" or add != "/etc/caddy/233boy/" + host + ".conf.add":
            raise MigrationError("Caddy import ownership is ambiguous")
        if bool(h2c) != bool(options):
            raise MigrationError("Unsupported Caddy transport options")
        fallback = _strip_comments(_read(root, add).decode())
        proxy = None
        if fallback:
            extra = re.fullmatch(r"reverse_proxy https://([a-zA-Z0-9.-]+)\s*\{\s*header_up Host \{upstream_hostport\}\s*\}", fallback)
            if not extra:
                raise MigrationError("Custom Caddy fallback must be migrated manually")
            proxy = domain(extra[1])
        entries.append({"domain": host, "path": route, "port": int(port), "transport": "h2" if h2c else "http1", "fallback": proxy})
    if len({item["domain"] for item in entries}) != len(entries) or len({item["port"] for item in entries}) != len(entries):
        raise MigrationError("Ambiguous Caddy domain/backend ownership")
    return entries


def _core(root):
    marker = _path(root, BASE + "/sh/src/init.sh")
    if not marker.exists() or "author=233boy" not in marker.read_text(encoding="utf-8"):
        raise MigrationError("sing-box installation is not the recognized 233boy layout")
    _unit(root, "sing-box", "/etc/sing-box/bin/sing-box run -c /etc/sing-box/config.json -C /etc/sing-box/conf")
    binary = _read(root, BASE + "/bin/sing-box")
    if not binary.startswith(b"\x7fELF"):
        raise MigrationError("Legacy sing-box binary is not ELF")
    config = _json(root, BASE + "/config.json")
    if set(config) - {"log", "dns", "ntp", "outbounds", "route"} or config.get("route"):
        raise MigrationError("Global/custom routing requires manual migration")
    configs = []
    directory = _path(root, BASE + "/conf")
    if not directory.exists():
        raise MigrationError("Legacy inbound directory is missing")
    for file in sorted(directory.iterdir()):
        if file.suffix != ".json":
            raise MigrationError("Unknown legacy inbound file requires manual inspection")
        name = BASE + "/conf/" + file.name
        data = _json(root, name)
        if set(data) - {"inbounds", "outbounds"} or len(data.get("inbounds", [])) != 1:
            raise MigrationError("Custom inbound container requires manual migration")
        inbound = data["inbounds"][0]
        if inbound.get("type") not in KNOWN_TYPES:
            raise MigrationError("Unsupported legacy inbound type")
        allowed = {"type", "tag", "listen", "listen_port", "users", "method", "password", "tls", "transport", "congestion_control", "override_address", "override_port", "obfs"}
        if set(inbound) - allowed:
            raise MigrationError("Custom listener or source-IP dependent options require manual migration")
        port = inbound.get("listen_port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise MigrationError("Invalid legacy listener port")
        ipaddress.ip_address(inbound.get("listen", "::"))
        tls = inbound.get("tls", {})
        if tls.get("acme") or tls.get("certificate_provider"):
            raise MigrationError("Embedded core ACME must be explicitly transferred before migration")
        if set(tls) - {"enabled", "server_name", "alpn", "certificate_path", "key_path", "reality"}:
            raise MigrationError("Custom legacy TLS options require manual migration")
        if set(inbound.get("transport", {})) - {"type", "path", "headers", "host", "early_data_header_name"}:
            raise MigrationError("Custom transport options require manual migration")
        if any(set(user) - {"name", "uuid", "password", "username", "flow"} for user in inbound.get("users", [])):
            raise MigrationError("Custom user options require manual migration")
        if tls.get("reality") and set(tls["reality"]) - {"enabled", "handshake", "private_key", "short_id", "max_time_difference"}:
            raise MigrationError("Custom REALITY options require manual migration")
        if tls.get("reality", {}).get("enabled"):
            reality = tls["reality"]
            if set(reality.get("handshake", {})) != {"server", "server_port"}:
                raise MigrationError("REALITY handshake dialer/source-IP dependencies require manual migration")
            if not isinstance(reality.get("short_id"), list) or not reality["short_id"]:
                raise MigrationError("Legacy REALITY short IDs require explicit inspection")
        if config.get("ntp", {}).get("write_to_system"):
            raise MigrationError("Legacy system-clock privileges require manual migration")
        configs.append((name, data))
    for data in [config, *(data for _, data in configs)]:
        for outbound in data.get("outbounds", []):
            if outbound.get("type") != "direct" or set(outbound) - {"type", "tag"}:
                raise MigrationError("Custom outbounds/source-IP dependencies require manual migration")
    routes = _caddy(root)
    ports = [data["inbounds"][0]["listen_port"] for _, data in configs]
    if any(ports.count(route["port"]) != 1 for route in routes):
        raise MigrationError("Caddy backend does not match a recognized inbound")
    return config, configs, routes


def _standalone_renewal(root, host):
    """Recognize only Certbot's owned webroot lineage before retiring its timer entry."""
    if not _path(root, OLD_RENEWAL).exists():
        return False
    values, section = {}, "main"
    for line in _strip_comments(_read(root, OLD_RENEWAL, 128 * 1024).decode()).splitlines():
        if line in ("[renewalparams]", "[[webroot_map]]"):
            section = line.strip("[]")
            continue
        if "=" not in line:
            raise MigrationError("Custom standalone Certbot renewal config requires manual migration")
        key, value = (part.strip() for part in line.split("=", 1))
        pair = (section, key)
        if pair in values:
            raise MigrationError("Duplicate standalone Certbot renewal setting")
        values[pair] = value
    expected = {
        ("main", "archive_dir"): "/etc/letsencrypt/archive/subscription-generator",
        ("main", "cert"): "/etc/letsencrypt/live/subscription-generator/cert.pem",
        ("main", "privkey"): "/etc/letsencrypt/live/subscription-generator/privkey.pem",
        ("main", "chain"): "/etc/letsencrypt/live/subscription-generator/chain.pem",
        ("main", "fullchain"): "/etc/letsencrypt/live/subscription-generator/fullchain.pem",
        ("renewalparams", "authenticator"): "webroot",
        ("renewalparams", "server"): "https://acme-v02.api.letsencrypt.org/directory",
        ("webroot_map", host): "/var/www/subscription-acme",
    }
    optional = {("main", "version"), ("main", "renew_before_expiry"),
                *( ("renewalparams", key) for key in ("account", "key_type", "elliptic_curve", "rsa_key_size", "webroot_path") )}
    if any(values.get(key) != value for key, value in expected.items()) or set(values) - expected.keys() - optional:
        raise MigrationError("Custom standalone Certbot lineage must be migrated manually")
    if values.get(("renewalparams", "webroot_path"), "/var/www/subscription-acme").rstrip(",") != "/var/www/subscription-acme":
        raise MigrationError("Standalone Certbot webroot differs from the owned installation")
    return True


def _standalone(root):
    if not _path(root, SUB + "/.managed-install").is_file():
        raise MigrationError("Standalone subscription installation has no ownership marker")
    config = _json(root, SUB + "/config.json")
    domain(config.get("domain", ""))
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", config.get("token", "")) or set(config) != {"domain", "token"}:
        raise MigrationError("Unrecognized standalone subscription config")
    _standalone_renewal(root, config["domain"])
    _unit(root, "subscription-generator", "/usr/bin/python3 /opt/subscription-generator/generator.py serve")
    text = _read(root, "/etc/nginx/sites-available/subscription-generator").decode()
    # Compare the complete known grammar, including nesting and listener counts.
    # A directive whitelist would also admit rearranged/duplicated directives.
    expected = f"""server {{
 listen 80;
 listen [::]:80;
 server_name {config['domain']};
 access_log off;
 error_log /dev/null;
 location /.well-known/acme-challenge/ {{ root /var/www/subscription-acme; }}
 location / {{ return 404; }}
}}
server {{
 listen 443 ssl;
 listen [::]:443 ssl;
 server_name {config['domain']};
 ssl_certificate /etc/letsencrypt/live/subscription-generator/fullchain.pem;
 ssl_certificate_key /etc/letsencrypt/live/subscription-generator/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 access_log off;
 error_log /dev/null;
 location ^~ /sub/ {{
  limit_except GET HEAD {{ deny all; }}
  proxy_pass http://127.0.0.1:8767;
  proxy_connect_timeout 3s;
  proxy_read_timeout 10s;
  proxy_set_header Host $host;
 }}
 location / {{ return 404; }}
}}
"""
    normalize = lambda value: re.sub(r"\s+", " ", _strip_comments(value)).strip()
    if normalize(text) != normalize(expected):
        raise MigrationError("Custom standalone Nginx config requires manual migration")
    enabled = _path(root, "/etc/nginx/sites-enabled/subscription-generator")
    if not enabled.is_symlink() or os.readlink(enabled) != "/etc/nginx/sites-available/subscription-generator":
        # Tests may use a relative symlink, exactly resolving to the owned file.
        if not enabled.is_symlink() or enabled.resolve() != _path(root, "/etc/nginx/sites-available/subscription-generator").resolve():
            raise MigrationError("Standalone Nginx activation is not an owned symlink")
    nodes = []
    for line in _read(root, SUB + "/nodes.txt").decode("utf-8-sig").splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            try:
                nodes.append(protocols.parse_uri(line.strip()))
            except ValueError:
                raise MigrationError("Standalone node cannot be imported without loss") from None
    if not 1 <= len(nodes) <= 200 or len({node['name'] for node, _ in nodes}) != len(nodes):
        raise MigrationError("Standalone subscription nodes are empty, duplicated or oversized")
    template = yaml.safe_load(_read(root, SUB + "/template.yaml"))
    if not isinstance(template, dict) or not isinstance(template.get("dns"), dict):
        raise MigrationError("Invalid standalone client template")
    return config, nodes, template


def _inventory(root):
    paths = set()
    for name in (BASE, "/etc/caddy", SUB, "/etc/nginx", "/etc/xray", "/usr/local/etc/xray"):
        directory = _path(root, name)
        if directory.exists():
            for file in directory.rglob("*"):
                if file.is_file() or file.is_symlink():
                    paths.add("/" + file.relative_to(root).as_posix())
    for name in ("sing-box", "caddy", "subscription-generator", "xray"):
        for directory in UNIT_DIRS:
            path = directory + "/" + name + ".service"
            if _path(root, path).exists():
                paths.add(path)
            dropins = _path(root, directory + "/" + name + ".service.d")
            if dropins.exists():
                paths.update("/" + p.relative_to(root).as_posix() for p in dropins.rglob("*") if p.is_file())
    if _path(root, SUB).exists() and _path(root, OLD_RENEWAL).exists():
        paths.add(OLD_RENEWAL)
    # Certificate paths referenced by the legacy core are also inventoried.
    conf = _path(root, BASE + "/conf")
    if conf.exists():
        for file in conf.glob("*.json"):
            try:
                data = json.loads(file.read_bytes())
                for inbound in data.get("inbounds", []):
                    for key in ("certificate_path", "key_path"):
                        value = inbound.get("tls", {}).get(key)
                        if value:
                            paths.add(value)
            except (ValueError, AttributeError):
                pass
    result = {}
    for name in sorted(paths):
        path = _path(root, name)
        meta = path.lstat()
        item = {"mode": stat.S_IMODE(meta.st_mode), "size": path.stat().st_size,
                "sha256": hashlib.sha256(_read(root, name)).hexdigest()}
        if path.is_symlink():
            item["symlink"] = os.readlink(path)
        result[name] = item
    return result


def inspect(root=Path("/")):
    root = Path(root).resolve()
    report = {"schema_version": 1, "root": str(root), "deployments": [], "blockers": [], "warnings": [], "inventory": {}, "nodes": []}
    try:
        report["inventory"] = _inventory(root)
        if _path(root, BASE).exists():
            _, configs, routes = _core(root)
            report["deployments"].append("233boy-sing-box")
            for name, data in configs:
                node = data["inbounds"][0]
                report["nodes"].append({"config": name, "protocol": node["type"], "port": node["listen_port"],
                                        "transport": node.get("transport", {}).get("type", "tcp"),
                                        "users": len(node.get("users", [])), "reality": bool(node.get("tls", {}).get("reality", {}).get("enabled"))})
            if routes:
                report["warnings"].append("Caddy domains require active DNS and replacement ACME certificates before switch")
        if _path(root, SUB).exists():
            _standalone(root)
            report["deployments"].append("standalone-subscription")
        if (_path(root, "/etc/xray").exists() or _path(root, "/usr/local/etc/xray").exists()
                or any(_path(root, directory + "/xray.service").exists() for directory in UNIT_DIRS)):
            raise MigrationError("Hand-built Xray installations are inspection-only")
        nginx = _path(root, "/etc/nginx/nginx.conf")
        if nginx.exists():
            text = _strip_comments(nginx.read_text(encoding="utf-8"))
            if re.search(r"\b(?:stream|server)\s*\{", text):
                raise MigrationError("Custom global Nginx listeners require manual migration")
            if re.search(r"\b(?:geo|map|real_ip_header|set_real_ip_from|proxy_protocol|allow|deny)\b", text):
                raise MigrationError("Nginx source-IP or custom mapping dependencies require manual migration")
            allowed = {"mime.types", "/etc/nginx/mime.types", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*", "/etc/nginx/modules-enabled/*.conf"}
            if any(path not in allowed for path in re.findall(r"\binclude\s+([^;]+);", text)):
                raise MigrationError("Custom Nginx imports require manual migration")
        # A standalone-owned config is the only accepted active Nginx site.
        for directory in ("/etc/nginx/sites-enabled", "/etc/nginx/conf.d"):
            path = _path(root, directory)
            if path.exists():
                for entry in path.iterdir():
                    if entry.name == "subscription-generator" and "standalone-subscription" in report["deployments"]:
                        continue
                    if entry.is_file() and _strip_comments(entry.read_text(encoding="utf-8")):
                        raise MigrationError("Existing custom/default Nginx sites require explicit manual migration")
        if not report["deployments"]:
            raise MigrationError("No supported legacy deployment was found")
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as exc:
        report["blockers"].append(str(exc) if isinstance(exc, MigrationError) else "Malformed or unreadable legacy deployment; inspect files locally")
    report["inventory_id"] = hashlib.sha256(encode(report["inventory"])).hexdigest()[:24]
    report["eligible"] = bool(report["deployments"]) and not report["blockers"]
    return report


def _fingerprint(pem):
    try:
        first = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem.decode(), re.S)
        if not first:
            raise ValueError("No PEM certificate")
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(first[0])).hexdigest()
    except (ValueError, UnicodeError):
        raise MigrationError("Legacy certificate cannot be fingerprinted") from None


def _legacy_unit(binary):
    return f"""[Unit]
Description=Preserved legacy sing-box core (do not upgrade implicitly)
After=network.target nginx.service
[Service]
Type=simple
User=sb-core
Group=sb-core
ExecStartPre={binary} check -c /etc/sing-box/sb-legacy/config.json
ExecStart={binary} run -c /etc/sing-box/sb-legacy/config.json
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
""".encode()


def prepare(report, state, secrets):
    """Return candidate state/secrets/files after re-inventory; no writes or processes."""
    if report.get("schema_version") != 1 or not report.get("eligible") or report.get("blockers"):
        raise MigrationError("Migration inventory contains blockers")
    current = inspect(Path(report["root"]))
    if current != report:
        raise MigrationError("Legacy deployment changed after inspection; inspect again")
    if state.get("legacy", {}).get("migration_id"):
        raise MigrationError("A legacy migration has already been recorded")
    root = Path(report["root"])
    new, private = copy.deepcopy(state), copy.deepcopy(secrets)
    identifier = report["inventory_id"]
    files = {}
    backup = f"/var/lib/sb/migration/{identifier}/backup"
    for name, item in report["inventory"].items():
        # Back up resolved bytes and record original symlink target/mode separately.
        files[backup + name] = _read(root, name)
    files[backup + "/inventory.json"] = encode(report)
    legacy = new.setdefault("legacy", {})
    legacy.update(migration_id=identifier, entries=[], certificates=[], services=[], listeners={},
                  switch={"stop_services": [], "start_services": [], "remove_symlinks": {}}, http_config="")
    occupied = {new["ports"][key] for key in ("reality", "site_tls", "sub_tls", "sub_http")}
    occupied.update(node["port"] for node in new["nodes"])
    observed_ports = new.get("migration", {}).get("occupied_ports", [])
    if not isinstance(observed_ports, list) or any(type(port) is not int or not 1 <= port <= 65535 for port in observed_ports):
        raise MigrationError("Observed listener ports must be integers between 1 and 65535")
    occupied.update(observed_ports)

    def free_port():
        for port in range(20000, 60000):
            if port not in occupied:
                occupied.add(port)
                return port
        raise MigrationError("No migration loopback port is available")

    def add_node(node, credentials):
        def identity(item, credential):
            try:
                compatible = dict(item)
                if compatible.get("legacy_insecure"):
                    compatible["insecure"] = True
                return protocols.connection_id(compatible, credential)
            except ValueError:
                return None
        connection = identity(node, credentials)
        for existing in new["nodes"]:
            if connection and connection == identity(existing, private["nodes"][existing["id"]]):
                if node["source"] == "legacy" and existing["source"] != "uri":
                    raise MigrationError("Multiple local listeners publish the same connection; resolve ambiguous ownership before migration")
                if node["source"] == "legacy" and existing["source"] == "uri":
                    # Preserve the administrator's existing display name and stable
                    # registry ID while attaching the retained local runtime.
                    node.update(id=existing["id"], name=existing["name"])
                    new["nodes"][new["nodes"].index(existing)] = node
                    private["nodes"][node["id"]] = credentials
                return existing["id"]
        if any(existing["name"] == node["name"] for existing in new["nodes"]):
            raise MigrationError("Legacy node name conflicts; rename new node before migration")
        if any(existing["id"] == node["id"] for existing in new["nodes"]):
            return node["id"]
        new["nodes"].append(node)
        private["nodes"][node["id"]] = credentials
        return node["id"]

    if "standalone-subscription" in report["deployments"]:
        config, nodes, template = _standalone(root)
        if config["domain"] in [new["domains"]["site"], *new["domains"]["site_aliases"]]:
            raise MigrationError("Legacy subscription domain conflicts with site role")
        private["subscription_token"] = config["token"]
        alias = {"domain": config["domain"], "prefix": "sub", "suffix": "/clash.yaml"}
        if alias not in new["subscription"]["aliases"]:
            new["subscription"]["aliases"].append(alias)
        if config["domain"] != new["domains"]["subscription"] and config["domain"] not in new["domains"]["subscription_aliases"]:
            new["domains"]["subscription_aliases"].append(config["domain"])
        for node, credential in nodes:
            node.update(source="uri", enabled=True)
            # The URI parser deliberately excludes registry ownership/identity.
            node.setdefault("id", protocols.connection_id(node, credential)[:32])
            add_node(node, credential)
        managed = {"proxies", "proxy-groups", "proxy-providers", "rule-providers", "rules", "sub-rules"}
        new["subscription"]["template"] = {key: value for key, value in template.items() if key not in managed}
        new["subscription"]["template"].get("dns", {}).pop("proxy-server-nameserver-policy", None)
        legacy["switch"]["stop_services"].append("subscription-generator.service")
        link = "/etc/nginx/sites-enabled/subscription-generator"
        legacy["switch"]["remove_symlinks"][link] = report["inventory"][link]["symlink"]
        if _standalone_renewal(root, config["domain"]):
            # Only the renewal entry is retired, after replacement certificates
            # are ready in the caller's final transaction. Keep certificate/key
            # archives untouched for old-service rollback and forensic recovery.
            files[OLD_RENEWAL] = None

    if "233boy-sing-box" in report["deployments"]:
        public_server = new.get("migration", {}).get("public_server")
        if not public_server:
            raise MigrationError("Specify the old published IP/domain with --public-server; do not infer it from the new site")
        protocols.hostname(public_server)
        config, configs, routes = _core(root)
        occupied.update(data["inbounds"][0]["listen_port"] for _, data in configs)
        udp_ports = {data["inbounds"][0]["listen_port"] for _, data in configs if data["inbounds"][0]["type"] in {"hysteria2", "tuic"} or data["inbounds"][0].get("transport", {}).get("type") == "quic"}
        tcp_ports = {data["inbounds"][0]["listen_port"] for _, data in configs
                     if data["inbounds"][0]["type"] not in {"hysteria2", "tuic"}
                     and data["inbounds"][0].get("transport", {}).get("type") != "quic"}
        for key in ("reality", "site_tls", "sub_tls", "sub_http"):
            if new["ports"][key] in tcp_ports:
                new["ports"][key] = free_port()
        if new["ports"]["hy2"] in udp_ports:
            new["ports"]["hy2"] = free_port()
        for node in new["nodes"]:
            if node.get("source") == "local" and node.get("transport") == "quic" and node["port"] in udp_ports:
                node["port"] = new["ports"]["hy2"] if node["protocol"] == "hysteria2" else free_port()
                if node["protocol"] == "hysteria2":
                    new["ports"]["hy2"] = node["port"]
        routed = {route["port"]: route for route in routes}
        inbounds = []
        for index, (name, data) in enumerate(configs):
            listener_id = hashlib.sha256(name.encode()).hexdigest()[:24]
            listener = {"index": index, "nodes": [], "certificate_files": [], "http_config": ""}
            legacy["listeners"][listener_id] = listener
            inbound = copy.deepcopy(data["inbounds"][0])
            original_port = inbound["listen_port"]
            protocol = inbound["type"]
            transport = inbound.get("transport", {}).get("type", "tcp")
            tls = inbound.get("tls", {})
            reality = tls.get("reality", {}).get("enabled", False)
            udp = protocol in {"hysteria2", "tuic"} or transport == "quic"
            route = routed.get(original_port)
            if not udp and original_port == 80:
                raise MigrationError("Legacy TCP80 listener conflicts with ACME; explicit migration required")
            if not udp and original_port != 443 and any(
                    node.get("source") == "local" and node.get("transport") != "quic"
                    and node["port"] == original_port for node in new["nodes"]):
                raise MigrationError("New local TCP node collides with a preserved legacy port")
            if not udp and original_port in {new["ports"][k] for k in ("reality", "site_tls", "sub_tls", "sub_http")}:
                inbound.update(listen="127.0.0.1", listen_port=free_port())
                if not route:
                    raise MigrationError("Legacy dedicated port conflicts with managed internal listener")
            if not udp and original_port == 443:
                sni = tls.get("server_name")
                if not tls.get("enabled") or not sni:
                    raise MigrationError("Legacy TCP443 requires a distinct explicit TLS SNI")
                sni = domain(sni)
                if sni in [new["domains"]["site"], new["domains"]["subscription"], *new["domains"]["subscription_aliases"]] or any(n.get("source") == "local" and n.get("sni") == sni and n["port"] == 443 for n in new["nodes"]):
                    raise MigrationError("New and old TCP443 use the same SNI with different credentials")
                inbound.update(listen="127.0.0.1", listen_port=free_port())
                upstream = "127.0.0.1:" + str(inbound["listen_port"])
                legacy["entries"].extend([{"kind": "sni", "sni": sni, "upstream": upstream, "listener": listener_id}, {"kind": "default", "upstream": upstream, "listener": listener_id}])
            if route:
                if not ipaddress.ip_address(inbound.get("listen", "::")).is_loopback:
                    raise MigrationError("Caddy-managed inbound is not restricted to loopback")
                host = route["domain"]
                if host in [new["domains"]["subscription"], *new["domains"]["subscription_aliases"]]:
                    raise MigrationError("Legacy Caddy domain conflicts with subscription")
                if host == new["domains"]["site"]:
                    raise MigrationError("Choose a separate new site domain; legacy Caddy TCP443 already owns this SNI")
                if host != new["domains"]["site"] and host not in new["domains"]["site_aliases"]:
                    new["domains"]["site_aliases"].append(host)
                tls_port = free_port()
                legacy["entries"].append({"kind": "sni", "sni": host, "upstream": "127.0.0.1:" + str(tls_port), "listener": listener_id})
                chain, key = cert_paths(host)
                h2 = route["transport"] == "h2"
                if h2:
                    if transport != "http" or not tls.get("enabled"):
                        raise MigrationError("H2 migration requires the existing TLS HTTP/2 backend")
                    tls.update(server_name=host, certificate_path=chain, key_path=key, alpn=["h2"])
                elif transport not in {"ws", "httpupgrade"} or tls.get("enabled"):
                    raise MigrationError("Caddy route transport does not match the old backend")
                scheme = "https" if h2 else "http"
                upgrade = "" if h2 else 'proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection "upgrade";'
                verify = f"proxy_ssl_server_name on; proxy_ssl_name {host}; proxy_ssl_verify on; proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;" if h2 else ""
                fallback = "return 404;"
                if route["fallback"]:
                    target = route["fallback"]
                    fallback = f"proxy_pass https://{target}; proxy_set_header Host {target}; proxy_ssl_server_name on; proxy_ssl_name {target}; proxy_ssl_verify on; proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;"
                listener["http_config"] = f"""
server {{
 listen 127.0.0.1:{tls_port} ssl;
 server_name {host}; http2 on; ssl_protocols TLSv1.2 TLSv1.3;
 ssl_certificate {chain}; ssl_certificate_key {key}; access_log off; error_log /dev/null crit;
 location = {route['path']} {{
  proxy_pass {scheme}://127.0.0.1:{inbound['listen_port']}; proxy_http_version {'2' if h2 else '1.1'};
  proxy_set_header Host {host}; {upgrade} {verify}
 }}
 location / {{ {fallback} }}
}}
"""
                legacy["http_config"] += listener["http_config"]
            # Copy certificate/key bytes unchanged for every dedicated/pinned legacy listener.
            pin = None
            if not route and tls.get("certificate_path"):
                certificate = _read(root, tls["certificate_path"])
                pin = _fingerprint(certificate)
                for field, filename in (("certificate_path", "certificate.pem"), ("key_path", "private.key")):
                    if not tls.get(field):
                        raise MigrationError("Legacy TLS certificate/key pair is incomplete")
                    copied = f"/etc/sing-box/sb-legacy/certificates/{index}/{filename}"
                    files[copied] = _read(root, tls[field])
                    listener["certificate_files"].append(copied)
                    tls[field] = copied
            listener["listen_port"] = inbound["listen_port"]
            inbounds.append(inbound)
            users = inbound.get("users", [{}])
            for user_index, user in enumerate(users):
                node_id = hashlib.sha256((name + ":" + str(user_index)).encode()).hexdigest()[:32]
                node = {"id": node_id, "name": "legacy-" + PurePosixPath(name).stem + ("-" + str(user_index + 1) if len(users) > 1 else ""),
                        "protocol": protocol, "source": "legacy", "enabled": True, "server": route["domain"] if route else public_server,
                        "port": 443 if route else original_port, "transport": "h2" if transport == "http" else ("quic" if udp else transport),
                        "security": "reality" if reality else ("tls" if tls.get("enabled") or route else "none"),
                        "legacy_config": LEGACY_CONFIG, "legacy_listener": listener_id,
                        "legacy_user_index": user_index, "legacy": True}
                credentials = {field: user[field] for field in ("uuid", "password", "username") if field in user}
                if protocol == "shadowsocks":
                    node["method"] = inbound["method"]
                    credentials["password"] = inbound["password"]
                if protocol == "tuic":
                    node["congestion_control"] = inbound.get("congestion_control", "cubic")
                if user.get("flow"):
                    node["flow"] = user["flow"]
                if tls.get("server_name") or route:
                    node["sni"] = route["domain"] if route else tls["server_name"]
                if tls.get("alpn"):
                    node["alpn"] = tls["alpn"]
                if reality:
                    public_keys = [out["tag"][11:] for out in data.get("outbounds", []) if out.get("tag", "").startswith("public_key_")]
                    if len(public_keys) != 1:
                        raise MigrationError("Legacy REALITY public key is missing; do not regenerate keys")
                    node.update(public_key=public_keys[0], short_id=tls["reality"].get("short_id", [""])[0], fingerprint="chrome")
                    credentials["private_key"] = tls["reality"]["private_key"]
                elif pin:
                    node.update(certificate_pin=pin, legacy_insecure=True)
                options = inbound.get("transport", {})
                if options.get("path"):
                    node["path"] = options["path"]
                # In sing-box HTTP without TLS means HTTP/1 transport, not H2.
                if transport == "http" and not tls.get("enabled") and not route:
                    node["transport"] = "http"
                host = options.get("headers", {}).get("host") or options.get("headers", {}).get("Host") or options.get("host")
                if host:
                    node["host"] = host[0] if isinstance(host, list) else host
                if inbound.get("obfs"):
                    node["obfs"] = inbound["obfs"]["type"]
                    credentials["obfs_password"] = inbound["obfs"]["password"]
                try:
                    compatible = dict(node)
                    if compatible.get("legacy_insecure"):
                        compatible["insecure"] = True
                    protocols.to_mihomo(compatible, credentials)
                    protocols.to_uri(compatible, credentials)
                except ValueError:
                    node.update(exportable=False, export_reason="Preserved listener cannot be represented without loss in Mihomo/share links")
                    if protocol == "vmess" and transport == "quic":
                        raw = {"v": "2", "ps": node["name"], "add": public_server, "port": str(original_port), "id": credentials["uuid"], "aid": "0", "net": "quic", "type": "none", "tls": "tls", "alpn": ",".join(tls.get("alpn", ["h3"]))}
                        private.setdefault("legacy_uris", {})[node_id] = "vmess://" + base64.b64encode(json.dumps(raw).encode()).decode()
                actual_id = add_node(node, credentials)
                listener["nodes"].append(actual_id)
        config["inbounds"] = inbounds
        # Retain DNS/NTP settings, direct semantics and core binary, but use journald.
        config.setdefault("log", {}).pop("output", None)
        config["outbounds"] = [{"type": "direct", "tag": "direct"}]
        binary = f"/opt/sb/legacy/{identifier}/sing-box"
        files[binary] = _read(root, BASE + "/bin/sing-box")
        files[LEGACY_CONFIG] = encode(config)
        legacy["config_sha256"] = hashlib.sha256(files[LEGACY_CONFIG]).hexdigest()
        files["/etc/systemd/system/sb-sing-box-legacy.service"] = _legacy_unit(binary)
        legacy["services"].append("sb-sing-box-legacy.service")
        legacy["switch"]["stop_services"].append("sing-box.service")
        legacy["switch"]["start_services"].append("sb-sing-box-legacy.service")
        if _path(root, "/etc/caddy/Caddyfile").exists():
            legacy["switch"]["stop_services"].append("caddy.service")
    if inspect(root) != report:
        raise MigrationError("Legacy deployment changed while preparing; inspect again")
    validate(new, private)
    return new, private, files


def retire(root, state, secrets, node_id):
    """Explicitly retire one legacy user/listener; caller publishes transactionally.

    Disabling a legacy node only hides its subscription entry. This operation is
    the separate, deliberate network retirement and never edits the old backup.
    """
    new, private = copy.deepcopy(state), copy.deepcopy(secrets)
    matches = [node for node in new.get("nodes", []) if node.get("id") == node_id]
    if len(matches) != 1 or matches[0].get("source") != "legacy":
        raise MigrationError("Retirement requires an existing migrated legacy node ID")
    node = matches[0]
    legacy = new.get("legacy", {})
    listener_id = node.get("legacy_listener")
    listener = legacy.get("listeners", {}).get(listener_id)
    if not listener or node_id not in listener.get("nodes", []):
        raise MigrationError("Legacy listener ownership is missing; inspect the migration backup")
    content = _read(root, LEGACY_CONFIG)
    if hashlib.sha256(content).hexdigest() != legacy.get("config_sha256"):
        raise MigrationError("Legacy runtime changed outside sb; retirement was refused")
    config = json.loads(content)
    index = listener["index"]
    if type(index) is not int or not 0 <= index < len(config.get("inbounds", [])):
        raise MigrationError("Legacy listener index is invalid")
    inbound = config["inbounds"][index]
    members = listener["nodes"]
    siblings = [n for n in new["nodes"] if n.get("legacy_listener") == listener_id]
    if {n["id"] for n in siblings} != set(members) or len(members) != len(set(members)):
        raise MigrationError("Legacy user ownership is inconsistent")
    files = {}
    # A new transition replaces any consumed initial migration switch actions.
    legacy["switch"] = {"stop_services": [], "start_services": [LEGACY_SERVICE], "remove_symlinks": {}}
    if len(members) > 1:
        users = inbound.get("users", [])
        user_index = node.get("legacy_user_index")
        if type(user_index) is not int or len(users) != len(members) or not 0 <= user_index < len(users):
            raise MigrationError("Legacy user mapping is inconsistent")
        users.pop(user_index)
        members.remove(node_id)
        for sibling in siblings:
            if sibling["legacy_user_index"] > user_index:
                sibling["legacy_user_index"] -= 1
    else:
        config["inbounds"].pop(index)
        legacy["listeners"].pop(listener_id)
        for remaining in legacy["listeners"].values():
            if remaining["index"] > index:
                remaining["index"] -= 1
        legacy["entries"] = [entry for entry in legacy["entries"] if entry.get("listener") != listener_id]
        legacy["http_config"] = "".join(item["http_config"] for item in sorted(
            legacy["listeners"].values(), key=lambda item: item["index"]))
        for name in listener.get("certificate_files", []):
            if not re.fullmatch(r"/etc/sing-box/sb-legacy/certificates/[0-9]+/(?:certificate\.pem|private\.key)", name):
                raise MigrationError("Invalid owned legacy certificate path")
            files[name] = None
    new["nodes"].remove(node)
    private["nodes"].pop(node_id)
    private.get("legacy_uris", {}).pop(node_id, None)
    if config["inbounds"]:
        files[LEGACY_CONFIG] = encode(config)
        legacy["config_sha256"] = hashlib.sha256(files[LEGACY_CONFIG]).hexdigest()
    else:
        # Keep an inert configuration and the known unit until after systemctl
        # can stop/disable it. Removing the unit first breaks disable on some
        # systemd versions and unnecessarily prevents safe transaction rollback.
        files[LEGACY_CONFIG] = encode(config)
        legacy["config_sha256"] = hashlib.sha256(files[LEGACY_CONFIG]).hexdigest()
        legacy["services"] = [name for name in legacy.get("services", []) if name != LEGACY_SERVICE]
        legacy["switch"] = {"stop_services": [LEGACY_SERVICE], "start_services": [], "remove_symlinks": {}}
    validate(new, private)
    return new, private, files
