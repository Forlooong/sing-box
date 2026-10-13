"""Pure, deterministic Nginx/sing-box/systemd configuration rendering."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path, PurePosixPath

from .certificates import cert_paths, deploy_hook, managed_domains, validate_domain, webroot_for, WEBROOT, HOOK

DEFAULT_SITE_ROOT = "/var/www/sb-site"
DEFAULT_PORTS = {"reality": 2443, "site_tls": 8443, "sub_tls": 8444, "sub_http": 8767, "hy2": 443}


class RenderError(ValueError):
    pass


def _port(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise RenderError("port must be an integer between 1 and 65535")
    return value


def _path(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value) or ".." in PurePosixPath(value).parts:
        raise RenderError("path must be an absolute path without traversal or Nginx metacharacters")
    return value


def _ports(state: dict) -> dict:
    result = {key: _port(state.get("ports", {}).get(key, default)) for key, default in DEFAULT_PORTS.items()}
    internal = [result[name] for name in ("reality", "site_tls", "sub_tls", "sub_http")]
    if len(set(internal)) != len(internal) or any(p in (80, 443) for p in internal):
        raise RenderError("internal TCP ports must be distinct and must not loop into public 80/443")
    return result


def _domains(state: dict) -> tuple[list[str], list[str]]:
    config = state["domains"]
    site = list(dict.fromkeys(validate_domain(d) for d in [config["site"], *config.get("site_aliases", [])]))
    subscription = list(dict.fromkeys(validate_domain(d) for d in [config["subscription"], *config.get("subscription_aliases", []),
                           *[alias["domain"] for alias in state.get("subscription", {}).get("aliases", [])]]))
    if set(site) & set(subscription):
        raise RenderError("site and subscription domains must be separate, including aliases")
    return site, subscription


def _credential(credentials: dict, field: str) -> str:
    value = credentials.get(field)
    if not isinstance(value, str) or not value or len(value) > 4096 or any(ord(c) < 32 for c in value):
        raise RenderError(f"a valid {field} credential is required")
    return value


def _transport(node: dict) -> dict | None:
    kind = node.get("transport", "tcp")
    if kind in ("udp", "quic") and node["protocol"] in ("hysteria2", "tuic"):
        return None
    if kind in ("tcp", "", None):
        return None
    if kind not in ("ws", "httpupgrade", "h2", "http"):
        raise RenderError(f"unsupported local transport: {kind}")
    if node["protocol"] not in ("vless", "vmess", "trojan"):
        raise RenderError("this protocol cannot use a V2Ray transport")
    if kind == "h2" and node.get("security", "none") not in ("tls", "reality"):
        raise RenderError("HTTP/2 inbound requires TLS; h2c is not a supported deployment")
    if kind == "http" and (node["protocol"] != "vmess" or node.get("security", "none") != "none"):
        raise RenderError("HTTP/1 inbound is supported only for plain VMess")
    path = node.get("path", "/")
    if not isinstance(path, str) or not path.startswith("/") or any(ord(c) < 32 for c in path):
        raise RenderError("transport path must start with / and contain no control characters")
    value = {"type": "http" if kind in ("h2", "http") else kind, "path": path}
    if node.get("host"):
        host = validate_domain(node["host"])
        if kind in ("h2", "http"):
            value["host"] = [host]
        elif kind == "httpupgrade":
            value["host"] = host
        else:
            value["headers"] = {"Host": host}
    return value


def _tls(node: dict, credentials: dict, site_domains: list[str], ports: dict) -> dict | None:
    security = node.get("security", "none")
    if security not in ("none", "", "tls", "reality"):
        raise RenderError("unsupported local TLS security")
    if security in ("none", ""):
        if node["protocol"] in ("hysteria2", "tuic", "anytls", "trojan"):
            raise RenderError("this protocol requires TLS")
        return None
    sni = validate_domain(node.get("sni") or site_domains[0])
    if sni not in site_domains:
        raise RenderError("local TLS SNI must be a managed site domain or retained alias")
    result = {"enabled": True, "server_name": sni,
              "min_version": "1.3" if security == "reality" or node["protocol"] in ("hysteria2", "tuic") else "1.2"}
    if security == "reality":
        if node["protocol"] != "vless":
            raise RenderError("REALITY is supported only for local VLESS")
        short_id = node.get("short_id", "")
        if not isinstance(short_id, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", short_id):
            raise RenderError("REALITY short_id must contain 0 to 8 hexadecimal bytes")
        private_key = _credential(credentials, "private_key")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", private_key):
            raise RenderError("invalid REALITY private key")
        result["reality"] = {"enabled": True, "handshake": {"server": "127.0.0.1", "server_port": ports["site_tls"]},
                             "private_key": private_key, "short_id": [short_id], "max_time_difference": "1m"}
    else:
        chain, key = cert_paths(sni)
        result.update(certificate_path=chain, key_path=key)
    if node.get("alpn"):
        alpn = node["alpn"]
        if not isinstance(alpn, list) or not all(isinstance(a, str) and a in ("h2", "http/1.1", "h3") for a in alpn):
            raise RenderError("invalid ALPN list")
        result["alpn"] = alpn
    elif node["protocol"] in ("hysteria2", "tuic"):
        result["alpn"] = ["h3"]
    elif node.get("transport") in ("h2", "http"):
        result["alpn"] = ["h2"]
    return result


def plan_reality_listener(state: dict, node: dict, occupied=()) -> tuple[dict | None, int]:
    """Keep an SNI's listener identity; reserve disabled nodes for later enable.

    The caller supplies observed host ports when creating a new listener. Imported
    remote nodes own no local ports; retained migration listeners still do.
    """
    ports = _ports(state)
    local = [item for item in state.get("nodes", []) if item.get("source") == "local"]
    matches = [item for item in local if item.get("protocol") == "vless"
               and item.get("security") == "reality" and item["port"] == 443
               and item.get("sni", state["domains"]["site"]) == node["sni"]]
    if matches:
        # Older deployments may retain a disabled user with a superseded key.
        prior = next((item for item in matches if item.get("enabled", True)), matches[0])
        if _transport(prior) != _transport(node):
            raise RenderError("This SNI already uses a different transport/path; choose a dedicated external port or another managed SNI")
        return prior, _port(prior.get("listen_port", ports["reality"]))

    reserved = {80, 443, ports["site_tls"], ports["sub_tls"], ports["sub_http"], *occupied}
    for item in local:
        if item["protocol"] not in ("hysteria2", "tuic"):
            reserved.add(_port(item.get("listen_port", ports["reality"] if item["port"] == 443 else item["port"])))
    legacy = state.get("legacy", {})
    for listener in legacy.get("listeners", {}).values():
        if listener.get("listen_port") is not None:
            reserved.add(_port(listener["listen_port"]))
    for entry in legacy.get("entries", []):
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", entry.get("upstream", ""))
        if match:
            reserved.add(_port(int(match[1])))
    port = ports["reality"] if ports["reality"] not in reserved else next(
        (port for port in range(20000, 60000) if port not in reserved), None)
    if port is None:
        raise RenderError("No available internal TCP port for the new REALITY SNI")
    return None, port


def render_inbounds(state: dict, secrets: dict) -> tuple[list[dict], dict[str, str]]:
    ports = _ports(state)
    site_domains, _ = _domains(state)
    inbounds: list[dict] = []
    routes: dict[str, str] = {}
    listeners: dict[tuple[str, int], dict] = {}
    for node in state.get("nodes", []):
        if node.get("source") != "local" or not node.get("enabled", True):
            continue
        protocol = node["protocol"]
        if protocol not in ("vless", "hysteria2", "shadowsocks", "trojan", "tuic", "anytls", "vmess", "socks"):
            raise RenderError(f"unsupported local protocol: {protocol}")
        node_id = str(node["id"])
        credentials = secrets.get("nodes", {}).get(node_id, {})
        udp = protocol in ("hysteria2", "tuic")
        external_port = _port(node["port"])
        security = node.get("security", "none")
        shared = external_port == 443 and not udp
        if shared and security != "reality":
            raise RenderError("TCP 443 is reserved for REALITY and the managed HTTPS sites; choose a separate port")
        listen_port = _port(node.get("listen_port", ports["reality"] if shared else external_port))
        listen = node.get("listen", "127.0.0.1" if shared else "::")
        try:
            address = ipaddress.ip_address(listen)
        except ValueError as exc:
            raise RenderError("listen must be an IP address") from exc
        if shared and (str(address) != "127.0.0.1" or listen_port in (80, 443)):
            raise RenderError("SNI-routed inbounds must use a private 127.0.0.1 port")
        if not shared and listen_port != external_port:
            raise RenderError("dedicated local listener must match the published port")
        if not udp and listen_port in (80, ports["site_tls"], ports["sub_tls"], ports["sub_http"]):
            raise RenderError("local inbound collides with a managed HTTP listener")
        inbound = {"type": protocol, "tag": f"sb-{node_id}", "listen": listen, "listen_port": listen_port}
        user = {"name": str(node.get("name", node_id))}
        if protocol in ("vless", "vmess", "tuic"):
            import uuid
            try:
                user["uuid"] = str(uuid.UUID(_credential(credentials, "uuid")))
            except ValueError as exc:
                raise RenderError("invalid node UUID") from exc
        if protocol == "vless":
            flow = node.get("flow", "")
            if flow not in ("", "xtls-rprx-vision") or (flow and node.get("transport", "tcp") != "tcp"):
                raise RenderError("Vision requires TCP and a supported flow value")
            if flow and security not in ("tls", "reality"):
                raise RenderError("Vision requires TLS or REALITY")
            if flow:
                user["flow"] = flow
        elif protocol == "vmess":
            user["alterId"] = 0
        if protocol in ("hysteria2", "trojan", "tuic", "anytls", "socks", "shadowsocks"):
            user["password"] = _credential(credentials, "password")
        if protocol == "socks":
            user = {"username": _credential(credentials, "username"), "password": user["password"]}
        if protocol == "shadowsocks":
            method = node.get("method")
            if method not in ("aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
                               "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"):
                raise RenderError("unsupported Shadowsocks method")
            inbound.update(method=method, password=user["password"])
        else:
            inbound["users"] = [user]
        tls = _tls(node, credentials, site_domains, ports)
        if tls:
            if protocol in ("shadowsocks", "socks"):
                raise RenderError("TLS wrapping is unsupported for this local protocol")
            inbound["tls"] = tls
        transport = _transport(node)
        if transport:
            inbound["transport"] = transport
        if protocol == "hysteria2":
            if node.get("insecure") or node.get("skip_cert_verify"):
                raise RenderError("new Hysteria2 nodes must verify a trusted certificate")
            inbound["masquerade"] = {"type": "file", "directory": _path(state.get("site", {}).get("root", DEFAULT_SITE_ROOT))}
            if node.get("obfs"):
                if node["obfs"] != "salamander":
                    raise RenderError("unsupported Hysteria2 obfuscation")
                inbound["obfs"] = {"type": "salamander", "password": _credential(credentials, "obfs_password")}
        if protocol == "tuic":
            inbound["congestion_control"] = node.get("congestion_control", "bbr")
            if inbound["congestion_control"] not in ("bbr", "cubic", "new_reno"):
                raise RenderError("unsupported TUIC congestion controller")
        protocols = ("udp",) if udp else (("tcp", "udp") if protocol in ("shadowsocks", "socks") else ("tcp",))
        prior = next((listeners[(p, listen_port)] for p in protocols if (p, listen_port) in listeners), None)
        if prior:
            comparison = {k: v for k, v in inbound.items() if k not in ("tag", "users")}
            old = {k: v for k, v in prior.items() if k not in ("tag", "users")}
            if comparison != old or protocol == "shadowsocks":
                raise RenderError("incompatible local nodes share a listener")
            for candidate in inbound["users"]:
                if candidate not in prior["users"]:
                    prior["users"].append(candidate)
        else:
            inbounds.append(inbound)
            for p in protocols:
                listeners[(p, listen_port)] = inbound
        if shared:
            sni = tls["server_name"]
            upstream = f"127.0.0.1:{listen_port}"
            if sni in routes and routes[sni] != upstream:
                raise RenderError("SNI maps to more than one local listener")
            routes[sni] = upstream
    return inbounds, routes


def _http80(state: dict) -> str:
    sites, subscriptions = _domains(state)
    servers = ["server {\n    listen 80 default_server;\n    listen [::]:80 default_server;\n    server_name _;\n    access_log off;\n    return 404;\n}\n"]
    for domain in managed_domains(state):
        webroot = webroot_for(state, domain)
        # The ACME location always wins; HTTP subscription paths are never redirected.
        response = f"return 308 https://{domain}$request_uri;" if domain in sites else "return 404;"
        servers.append(f"""server {{
    listen 80;
    listen [::]:80;
    server_name {domain};
    access_log off;
    error_log /dev/null crit;
    location ^~ /.well-known/acme-challenge/ {{ root {webroot}; default_type text/plain; try_files $uri =404; }}
    location / {{ {response} }}
}}
""")
    return "\n".join(servers)


def render_bootstrap(state: dict) -> dict[str, bytes]:
    """HTTP-only servers used before the very first certificate has been issued."""
    return {"/etc/nginx/sb/http.conf": _http80(state).encode(), "/etc/nginx/sb/stream.conf": b"# ACME bootstrap; no TCP 443 listener yet.\n"}


def _tls_server(domain: str, port: int, body: str, *, subscription: bool = False, legacy_http2: bool = False) -> str:
    chain, key = cert_paths(domain)
    listen_options = "ssl http2" if legacy_http2 else "ssl"
    http2 = "" if legacy_http2 else "    http2 on;\n"
    return f"""server {{
    listen 127.0.0.1:{port} {listen_options};
    server_name {domain};
{http2}    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1;
    ssl_certificate {chain};
    ssl_certificate_key {key};
    ssl_session_tickets off;
    server_tokens off;
    access_log off;
    error_log /dev/null crit;
{body}
}}
"""


def _units() -> dict[str, bytes]:
    core = """[Unit]
Description=SB managed sing-box core
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=sb-core
Group=sb-core
WorkingDirectory=/var/lib/sb/core
ExecStartPre=/opt/sb/bin/sing-box check -c /etc/sing-box/sb/config.json
ExecStart=/opt/sb/bin/sing-box run -c /etc/sing-box/sb/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
InaccessiblePaths=/etc/sb/secrets.json /etc/sb/state.json /var/lib/sb/subscription -/etc/letsencrypt
ReadWritePaths=/var/lib/sb/core
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0027

[Install]
WantedBy=multi-user.target
"""
    subscription = """[Unit]
Description=SB private subscription service
After=network.target

[Service]
Type=simple
User=sb-subscription
Group=sb-subscription
WorkingDirectory=/opt/sb/current
ExecStart=/usr/bin/python3 -m sbmanager.server --runtime /var/lib/sb/subscription/runtime.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
Environment=PYTHONDONTWRITEBYTECODE=1
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
InaccessiblePaths=/etc/sb/secrets.json /etc/sb/state.json /etc/sb/certificates /etc/sing-box -/etc/letsencrypt
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
"""
    rules = """[Unit]
Description=Validate and activate a complete SB rule snapshot
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=/opt/sb/current
ExecStart=/usr/local/bin/sb rules update --scheduled
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
"""
    timer = """[Unit]
Description=Check for published SB rule snapshots every 15 minutes

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
RandomizedDelaySec=30s
Persistent=true
Unit=sb-rules.service

[Install]
WantedBy=timers.target
"""
    certificate_sync = """[Unit]
Description=Reconcile issued SB certificates after missed deploy hooks
After=network.target

[Service]
Type=oneshot
WorkingDirectory=/opt/sb/current
ExecStart=/usr/local/bin/sb cert sync --scheduled
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
"""
    certificate_timer = """[Unit]
Description=Retry SB certificate deployment every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
RandomizedDelaySec=30s
Persistent=true
Unit=sb-cert-sync.service

[Install]
WantedBy=timers.target
"""
    return {f"/etc/systemd/system/{name}": content.encode() for name, content in {
        "sb-sing-box.service": core, "sb-subscription.service": subscription, "sb-rules.service": rules, "sb-rules.timer": timer,
        "sb-cert-sync.service": certificate_sync, "sb-cert-sync.timer": certificate_timer}.items()}


def render(state: dict, secrets: dict) -> dict[str, bytes]:
    ports = _ports(state)
    legacy_http2 = state.get("nginx", {}).get("legacy_http2_directive", False)
    if not isinstance(legacy_http2, bool):
        raise RenderError("Nginx HTTP/2 syntax selection must be a boolean capability")
    sites, subscriptions = _domains(state)
    inbounds, node_routes = render_inbounds(state, secrets)
    routes = {domain: f"127.0.0.1:{ports['site_tls']}" for domain in sites}
    routes.update(node_routes)
    routes.update({domain: f"127.0.0.1:{ports['sub_tls']}" for domain in subscriptions})
    default = f"127.0.0.1:{ports['site_tls']}"
    legacy_routes = {}
    for entry in state.get("legacy", {}).get("entries", []):
        kind = entry.get("kind")
        if kind not in ("sni", "default"):
            continue
        upstream = entry.get("upstream", "")
        match = re.fullmatch(r"127\.0\.0\.1:([0-9]{1,5})", upstream)
        if not match or _port(int(match[1])) in (80, 443):
            raise RenderError("legacy upstream must be a non-public loopback port")
        if kind == "default":
            if "default" in legacy_routes and legacy_routes["default"] != upstream:
                raise RenderError("legacy contains conflicting default routes")
            legacy_routes["default"] = upstream
            default = upstream
        else:
            domain = validate_domain(entry["sni"])
            if domain in legacy_routes and legacy_routes[domain] != upstream:
                raise RenderError("legacy contains conflicting SNI routes")
            legacy_routes[domain] = upstream
            if domain in subscriptions or domain in node_routes:
                if routes[domain] != upstream:
                    raise RenderError("legacy SNI conflicts with a new subscription or node route")
            routes[domain] = upstream
    mapping = "\n".join(f"        {domain} {upstream};" for domain, upstream in sorted(routes.items()))
    stream = f"""# Included at the top level of nginx.conf, outside http {{}}.
stream {{
    map $ssl_preread_server_name $sb_upstream {{
        default {default};
{mapping}
    }}
    server {{
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;
        proxy_pass $sb_upstream;
    }}
}}
"""
    http = _http80(state)
    for port in (ports["site_tls"], ports["sub_tls"]):
        listener = "ssl http2 default_server;" if legacy_http2 else "ssl default_server; http2 on;"
        http += f"\nserver {{ listen 127.0.0.1:{port} {listener} ssl_protocols TLSv1.2 TLSv1.3; ssl_reject_handshake on; access_log off; error_log /dev/null crit; return 404; }}\n"
    site_root = _path(state.get("site", {}).get("root", DEFAULT_SITE_ROOT))
    for domain in sites:
        body = f"    root {site_root};\n    index index.html;\n    location / {{ try_files $uri $uri/ =404; }}\n    location ~ /\\. {{ deny all; }}"
        http += _tls_server(domain, ports["site_tls"], body, legacy_http2=legacy_http2)
    for domain in subscriptions:
        body = f"""    client_max_body_size 1k;
    location = /healthz {{ return 404; }}
    location / {{
        limit_except GET HEAD {{ deny all; }}
        proxy_pass http://127.0.0.1:{ports['sub_http']};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Connection "";
        proxy_hide_header X-Powered-By;
        proxy_cache off;
        proxy_buffering off;
        proxy_connect_timeout 3s;
        proxy_read_timeout 30s;
        add_header Cache-Control "no-store, private" always;
        add_header X-Content-Type-Options nosniff always;
    }}"""
        http += _tls_server(domain, ports["sub_tls"], body, subscription=True, legacy_http2=legacy_http2)
    legacy_http = state.get("legacy", {}).get("http_config", "")
    if not isinstance(legacy_http, str):
        raise RenderError("legacy HTTP configuration must be a string from migration inspection")
    if legacy_http2:
        if re.search(r"\bproxy_http_version\s+2(?:\.0)?\s*;", legacy_http):
            raise RenderError("This Nginx cannot proxy a preserved HTTP/2 upstream")
        # This snippet comes only from the bounded legacy migration renderer.
        # Preserve TLS frontend HTTP/2 on pre-1.25.1 distribution Nginx.
        legacy_http = re.sub(r"\blisten\s+(127\.0\.0\.1:[0-9]+)\s+ssl\s*;", r"listen \1 ssl http2;", legacy_http)
        legacy_http = re.sub(r"\bhttp2\s+on\s*;", "", legacy_http)
    http += "\ninclude /etc/nginx/sb/legacy-http.conf;\n"
    config = {"log": {"level": "warn", "timestamp": True}, "inbounds": inbounds,
              "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct"}}
    files = {"/etc/nginx/sb/stream.conf": stream.encode(), "/etc/nginx/sb/http.conf": http.encode(),
             "/etc/nginx/sb/legacy-http.conf": legacy_http.encode(),
             "/etc/sing-box/sb/config.json": (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode(), HOOK: deploy_hook()}
    files.update(_units())
    # The transaction owner skips this file if it already exists (custom content).
    if site_root == DEFAULT_SITE_ROOT:
        files[f"{site_root}/index.html"] = (Path(__file__).parent / "assets/index.html").read_bytes()
    return files
