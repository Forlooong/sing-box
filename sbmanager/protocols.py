"""Lossless supported share-link adapters. No server private keys leave this module.

Supported transports are explicit: an unknown value must never become TCP.
Errors deliberately contain no URI, credential, or third-party parser exception.
"""
import base64
import binascii
import hashlib
import ipaddress
import json
import re
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit
import uuid

GROUP = "节点选择"
FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "iOS", "android", "edge", "360", "qq", "random", "randomized"}
SS_METHODS = {"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
              "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
              "2022-blake3-chacha20-poly1305"}
TRANSPORTS = {"tcp", "http", "ws", "h2", "httpupgrade", "grpc"}


class ProtocolError(ValueError):
    """A safe-to-display validation error."""


def _text(value, label="text", maximum=4096, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not value and not empty) or any(
            ord(c) < 32 or ord(c) == 127 for c in value):
        raise ProtocolError("Invalid " + label)
    return value


def hostname(value):
    _text(value, "server hostname", 253)
    if "%" in value:
        raise ProtocolError("IPv6 zone IDs are not supported")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        try:
            value = value.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ProtocolError("Invalid server hostname") from None
        if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                                     for p in value.split(".")):
            raise ProtocolError("Invalid server hostname")
        return value


def node_name(value):
    value = _text(value, "node name", 200)
    if value.strip() != value or value.upper() in {GROUP, "DIRECT", "REJECT", "PASS", "GLOBAL", "COMPATIBLE", "REJECT-DROP"}:
        raise ProtocolError("Invalid or reserved node name")
    return value


def _port(value):
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise ProtocolError("Invalid node port")
    return value


def _uuid(value):
    try:
        return str(uuid.UUID(value))
    except (ValueError, TypeError, AttributeError):
        raise ProtocolError("Invalid node UUID") from None


def _b64decode(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_+/=-]+", value):
        raise ProtocolError("Invalid share-link encoding")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ProtocolError("Invalid share-link encoding") from None


def _b64(value):
    return base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")


def _flag(value):
    if value not in ("0", "1", "false", "true"):
        raise ProtocolError("Invalid boolean URI parameter")
    return value in ("1", "true")


def _query(value, allowed):
    if not value:
        return {}  # Python 3.10 strict parsing rejects an otherwise valid empty query.
    pairs = parse_qsl(value, keep_blank_values=True, strict_parsing=True, max_num_fields=40, errors="strict")
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ProtocolError("Duplicate URI parameter")
    if set(result) - allowed:
        raise ProtocolError("Unsupported URI parameter; import refused to prevent data loss")
    for item in result.values():
        _text(item, "URI parameter", empty=True)
    return result


def _tls_query(node, q):
    if q.get("sni") or q.get("peer"):
        if q.get("sni") and q.get("peer") and q["sni"] != q["peer"]:
            raise ProtocolError("Conflicting SNI parameters")
        node["sni"] = hostname(q.get("sni") or q["peer"])
    if "fp" in q:
        node["fingerprint"] = q["fp"]
    insecure = [q[k] for k in ("insecure", "allowInsecure", "skip-cert-verify") if k in q]
    if len({_flag(value) for value in insecure}) > 1:
        raise ProtocolError("Conflicting certificate-verification setting")
    if insecure:
        node["insecure"] = _flag(insecure[0])
    if q.get("alpn"):
        node["alpn"] = q["alpn"].split(",")
    if "pinSHA256" in q:
        node["certificate_pin"] = q["pinSHA256"].replace(":", "").lower()


TLS_QUERY = {"sni", "peer", "fp", "alpn", "insecure", "allowInsecure", "skip-cert-verify", "pinSHA256"}
STREAM_QUERY = TLS_QUERY | {"type", "security", "path", "host", "serviceName"}


def _base(protocol, server, port, name):
    return {"protocol": protocol, "server": hostname(server), "port": _port(port),
            "name": node_name(name or hostname(server)), "source": "uri", "enabled": True,
            "transport": "tcp", "security": "none"}


def _unique_json(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ProtocolError("Duplicate VMess JSON field")
    return result


def _parse_vmess(uri):
    if "?" in uri or "#" in uri:
        raise ProtocolError("VMess JSON link must not contain query or fragment")
    d = json.loads(_b64decode(uri[8:]).decode("utf-8"), object_pairs_hook=_unique_json)
    if not isinstance(d, dict) or set(d) - {"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp", "allowInsecure"}:
        raise ProtocolError("Unsupported VMess link field")
    if str(d.get("v", "2")) != "2" or str(d.get("aid", "0")) != "0" or d.get("type", "none") not in ("", "none", "http"):
        raise ProtocolError("Only AEAD VMess links with supported header types are supported")
    if d.get("tls", "") not in ("", "none", "tls"):
        raise ProtocolError("Unsupported VMess TLS mode")
    n = _base("vmess", d["add"], int(d["port"]), d.get("ps"))
    n.update(transport=d.get("net", "tcp"), security="tls" if d.get("tls") == "tls" else "none",
             cipher=d.get("scy", "auto"), alter_id=0)
    if d.get("type") == "http":
        if n["transport"] != "tcp":
            raise ProtocolError("VMess HTTP header type requires TCP")
        n["transport"] = "http"
    for k in ("host", "path"):
        if d.get(k):
            n[k] = d[k]
    _tls_query(n, {k: str(d[k]) for k in TLS_QUERY if k in d and d[k] != ""})
    return n, {"uuid": _uuid(d["id"])}


def _parse_uri(uri):
    if not isinstance(uri, str) or len(uri) > 16384 or any(c.isspace() or ord(c) < 32 for c in uri) or re.search(r"%(?![0-9a-fA-F]{2})", uri):
        raise ProtocolError("Malformed share link; percent-encode special characters")
    if uri.startswith("vmess://"):
        return _parse_vmess(uri)
    if uri.startswith("ss://") and "@" not in uri[5:].split("#", 1)[0].split("?", 1)[0]:
        # Old whole-link Base64 can contain '/' and must be decoded before URL
        # parsing treats that character as a path delimiter.
        encoded, _, fragment = uri[5:].partition("#")
        if "?" in encoded:
            raise ProtocolError("Legacy Shadowsocks links cannot discard plugin parameters")
        decoded = _b64decode(encoded).decode("utf-8")
        if not decoded or "@" not in decoded:
            raise ProtocolError("Invalid legacy Shadowsocks endpoint")
        credentials, endpoint = decoded.rsplit("@", 1)
        return _parse_uri("ss://" + _b64(credentials) + "@" + endpoint + ("#" + fragment if fragment else ""))
    u = urlsplit(uri)
    scheme = {"hy2": "hysteria2", "ss": "shadowsocks", "socks5": "socks"}.get(u.scheme, u.scheme)
    if scheme == "shadowsocks" and "@" not in u.netloc:
        # The legacy SIP002 form encodes both userinfo and endpoint.
        if u.query or u.path:
            raise ProtocolError("Legacy Shadowsocks links cannot discard path or plugin parameters")
        decoded = _b64decode(u.netloc).decode()
        return _parse_uri("ss://" + decoded + ("#" + u.fragment if u.fragment else ""))
    if scheme not in {"vless", "hysteria2", "shadowsocks", "trojan", "tuic", "anytls", "socks"}:
        raise ProtocolError("Unsupported share-link protocol")
    if not u.hostname or u.path not in ("", "/"):
        raise ProtocolError("Expected share link with hostname and port")
    port = u.port if u.port is not None else (443 if scheme == "hysteria2" else None)
    n = _base(scheme, u.hostname, port, unquote(u.fragment, errors="strict"))
    credentials = {}
    auth = unquote(u.netloc.rsplit("@", 1)[0], errors="strict") if "@" in u.netloc else ""
    if scheme == "shadowsocks":
        q = _query(u.query, set())
        if ":" not in auth:
            auth = _b64decode(auth).decode()
        method, separator, password = auth.partition(":")
        if not separator:
            raise ProtocolError("Invalid Shadowsocks credentials")
        n["method"] = method
        credentials["password"] = password
    elif scheme == "socks":
        q = _query(u.query, {"udp"})
        if auth:
            raw_auth = u.netloc.rsplit("@", 1)[0]
            if ":" in raw_auth:
                username, separator, password = raw_auth.partition(":")
                username, password = unquote(username, errors="strict"), unquote(password, errors="strict")
            else:
                username, separator, password = _b64decode(auth).decode().partition(":")
            if not separator:
                raise ProtocolError("SOCKS credentials require username and password")
            credentials.update(username=username, password=password)
        n["udp"] = _flag(q.get("udp", "1"))
    elif scheme == "hysteria2":
        q = _query(u.query, TLS_QUERY | {"obfs", "obfs-password"})
        n.update(transport="quic", security="tls")
        credentials["password"] = auth
        if q.get("obfs"):
            n["obfs"] = q["obfs"]
            credentials["obfs_password"] = q.get("obfs-password", "")
        elif q.get("obfs-password"):
            raise ProtocolError("Obfuscation password requires an obfuscation method")
        _tls_query(n, q)
    elif scheme == "tuic":
        q = _query(u.query, TLS_QUERY | {"congestion_control", "udp_relay_mode", "disable_sni"})
        identity, separator, password = auth.partition(":")
        if not separator:
            raise ProtocolError("TUIC v5 requires UUID and password")
        credentials.update(uuid=_uuid(identity), password=password)
        n.update(transport="quic", security="tls", congestion_control=q.get("congestion_control", "cubic"),
                 udp_relay_mode=q.get("udp_relay_mode", "native"))
        if "disable_sni" in q:
            n["disable_sni"] = _flag(q["disable_sni"])
        _tls_query(n, q)
    else:
        q = _query(u.query, STREAM_QUERY | {"encryption"} | ({"flow", "pbk", "sid", "spx"} if scheme == "vless" else set()))
        if q.get("encryption", "none") != "none":
            raise ProtocolError("Unsupported stream protocol encryption")
        if scheme == "vless":
            credentials["uuid"] = _uuid(auth)
            if q.get("encryption", "none") != "none":
                raise ProtocolError("Unsupported VLESS encryption")
            for src, dest in (("flow", "flow"), ("pbk", "public_key"), ("sid", "short_id"), ("spx", "spider_x")):
                if src in q:
                    n[dest] = q[src]
        else:
            credentials["password"] = auth
        n.update(transport=q.get("type", "tcp"), security=q.get("security", "none" if scheme == "vless" else "tls"))
        for src, dest in (("host", "host"), ("path", "path"), ("serviceName", "service_name")):
            if src in q:
                n[dest] = q[src]
        _tls_query(n, q)
    return n, credentials


def parse_uri(uri):
    """Return public node and secret credentials; reject unrepresentable input."""
    try:
        node, credentials = _parse_uri(uri)
        to_mihomo(node, credentials)
        node["id"] = connection_id(node, credentials)
        return node, credentials
    except ProtocolError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, OverflowError):
        raise ProtocolError("Invalid share link; check the supported format and parameters") from None


def _tls(node, result, sni_key):
    if node.get("sni"):
        result[sni_key] = hostname(node["sni"])
    insecure = node.get("insecure", node.get("legacy_insecure", False) if node.get("source") == "legacy" else False)
    if not isinstance(insecure, bool):
        raise ProtocolError("Invalid certificate-verification setting")
    result["skip-cert-verify"] = insecure
    if node.get("certificate_pin"):
        pin = node["certificate_pin"].replace(":", "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", pin):
            raise ProtocolError("Invalid certificate SHA-256 fingerprint")
        result["fingerprint"] = pin
    if node.get("fingerprint"):
        if node["fingerprint"] not in FINGERPRINTS:
            raise ProtocolError("Unsupported TLS client fingerprint")
        result["client-fingerprint"] = node["fingerprint"]
    if "alpn" in node:
        alpn = node["alpn"]
        if not isinstance(alpn, list) or not 1 <= len(alpn) <= 8 or any(
                not isinstance(a, str) or not re.fullmatch(r"[A-Za-z0-9./_-]{1,32}", a) for a in alpn):
            raise ProtocolError("Invalid ALPN list")
        result["alpn"] = list(alpn)


def _transport(node, result):
    transport = node.get("transport", "tcp")
    if transport not in TRANSPORTS:
        raise ProtocolError("Unsupported transport; automatic TCP fallback is forbidden")
    if transport != "grpc" and node.get("service_name"):
        raise ProtocolError("gRPC service name on another transport would be ignored")
    if transport == "grpc" and (node.get("path") or node.get("host")):
        raise ProtocolError("HTTP path or host on gRPC would be ignored")
    if node["protocol"] == "vmess" and transport == "grpc":
        raise ProtocolError("VMess gRPC has no lossless supported JSON share-link representation")
    result["network"] = "ws" if transport == "httpupgrade" else transport
    if transport == "http":
        if node["protocol"] != "vmess" or node.get("security", "none") != "none":
            raise ProtocolError("HTTP/1 transport is supported only for plain VMess")
        path = _text(node.get("path", "/"), "transport path")
        if not path.startswith("/"):
            raise ProtocolError("Transport path must start with a slash")
        opts = {"method": "GET", "path": [path]}
        if node.get("host"):
            opts["headers"] = {"Host": [hostname(node["host"])]}
        result["http-opts"] = opts
    elif transport in {"ws", "h2", "httpupgrade"}:
        path = _text(node.get("path", "/"), "transport path")
        if not path.startswith("/"):
            raise ProtocolError("Transport path must start with a slash")
        opts = {"path": path}
        if node.get("host"):
            host = hostname(node["host"])
            opts["host" if transport == "h2" else "headers"] = [host] if transport == "h2" else {"Host": host}
        if transport == "httpupgrade":
            opts["v2ray-http-upgrade"] = True
        result["h2-opts" if transport == "h2" else "ws-opts"] = opts
    elif transport == "grpc":
        result["grpc-opts"] = {"grpc-service-name": _text(node.get("service_name", ""), "gRPC service name", empty=True)}
    elif node.get("path") or node.get("host") or node.get("service_name"):
        raise ProtocolError("Transport options on TCP would be ignored")


def to_mihomo(node, credentials):
    """Convert one supported connection without exposing server-side key material."""
    try:
        p = node["protocol"]
        result = {"name": node_name(node["name"]), "type": {"shadowsocks": "ss", "socks": "socks5"}.get(p, p),
                  "server": hostname(node["server"]), "port": _port(node["port"]), "udp": True}
        transport, security = node.get("transport", "tcp"), node.get("security", "none")
        if security not in {"none", "tls", "reality"}:
            raise ProtocolError("Unsupported security mode")
        if p in {"vless", "vmess", "trojan"}:
            _transport(node, result)
            if p in {"vless", "vmess"}:
                result["uuid"] = _uuid(credentials.get("uuid"))
            else:
                result["password"] = _text(credentials.get("password"), "node password")
                if security != "tls":
                    raise ProtocolError("Trojan adapter requires TLS")
            result["tls"] = security != "none"
            if security != "none":
                _tls(node, result, "servername" if p != "trojan" else "sni")
            elif any(node.get(k) for k in ("sni", "insecure", "certificate_pin", "fingerprint", "alpn")):
                raise ProtocolError("TLS options without TLS would be ignored")
            if p == "vmess":
                if security == "reality" or node.get("alter_id", 0) != 0 or node.get("cipher", "auto") not in {"auto", "none", "aes-128-gcm", "chacha20-poly1305", "zero"}:
                    raise ProtocolError("Unsupported VMess encryption or authentication mode")
                result.update(alterId=0, cipher=node.get("cipher", "auto"))
            if p == "vless":
                flow = node.get("flow", "")
                if flow not in ("", "xtls-rprx-vision") or flow and (transport != "tcp" or security == "none"):
                    raise ProtocolError("Vision requires VLESS with TCP and TLS or REALITY")
                if flow:
                    result["flow"] = flow
                if security == "reality":
                    key, sid = node.get("public_key", ""), node.get("short_id", "")
                    if transport not in {"tcp", "h2", "grpc"} or not re.fullmatch(r"[A-Za-z0-9_-]{43}", key) or len(_b64decode(key)) != 32:
                        raise ProtocolError("Invalid REALITY transport or public key")
                    if not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", sid):
                        raise ProtocolError("Invalid REALITY short ID")
                    if not node.get("sni") or node.get("insecure") or node.get("certificate_pin"):
                        raise ProtocolError("REALITY requires SNI and its own public-key verification")
                    result["client-fingerprint"] = node.get("fingerprint", "chrome")
                    result["reality-opts"] = {"public-key": key, "short-id": sid.lower()}
                    # spx is an Xray crawler hint; Mihomo does not implement it.
                    if node.get("spider_x") not in (None, "", "/"):
                        raise ProtocolError("Mihomo cannot preserve this REALITY spider path")
                elif any(node.get(k) for k in ("public_key", "short_id", "spider_x")):
                    raise ProtocolError("REALITY options without REALITY would be ignored")
        elif p in {"hysteria2", "tuic", "anytls"}:
            if security != "tls" or transport != ("tcp" if p == "anytls" else "quic"):
                raise ProtocolError("Unsupported TLS or transport combination")
            if any(node.get(k) for k in ("path", "host", "service_name")):
                raise ProtocolError("HTTP transport options on this protocol would be ignored")
            result["password"] = _text(credentials.get("password"), "node password")
            _tls(node, result, "sni")
            if p in {"hysteria2", "tuic"} and node.get("fingerprint"):
                raise ProtocolError("QUIC protocols do not use a browser TLS fingerprint")
            if p == "hysteria2" and node.get("obfs"):
                if node["obfs"] != "salamander":
                    raise ProtocolError("Only salamander obfuscation is supported by the pinned adapter")
                result.update(obfs="salamander", **{"obfs-password": _text(credentials.get("obfs_password"), "obfuscation password")})
            if p == "tuic":
                result["uuid"] = _uuid(credentials.get("uuid"))
                cc, relay = node.get("congestion_control", "cubic"), node.get("udp_relay_mode", "native")
                if cc not in {"cubic", "new_reno", "bbr"} or relay not in {"native", "quic"}:
                    raise ProtocolError("Unsupported TUIC congestion or UDP relay mode")
                result.update(**{"congestion-controller": cc, "udp-relay-mode": relay})
                if "disable_sni" in node:
                    if not isinstance(node["disable_sni"], bool):
                        raise ProtocolError("Invalid TUIC SNI setting")
                    if node["disable_sni"] and not node.get("insecure") and not node.get("certificate_pin"):
                        raise ProtocolError("TUIC disable_sni disables normal certificate verification; supply a pin or explicitly allow insecure TLS")
                    result["disable-sni"] = node["disable_sni"]
        elif p == "shadowsocks":
            if security != "none" or transport != "tcp" or node.get("method") not in SS_METHODS:
                raise ProtocolError("Unsupported Shadowsocks cipher, security, or transport")
            result.update(cipher=node["method"], password=_text(credentials.get("password"), "node password"))
            if node["method"].startswith("2022-"):
                expected = 16 if "aes-128" in node["method"] else 32
                if any(len(_b64decode(key)) != expected for key in result["password"].split(":")):
                    raise ProtocolError("Invalid Shadowsocks 2022 key length")
        elif p == "socks":
            if security != "none" or transport != "tcp":
                raise ProtocolError("Only plain SOCKS5 share links are supported")
            if credentials.get("username") or credentials.get("password"):
                result.update(username=_text(credentials.get("username"), "SOCKS username", 255),
                              password=_text(credentials.get("password"), "SOCKS password", 255))
            if not isinstance(node.get("udp", True), bool):
                raise ProtocolError("Invalid SOCKS UDP setting")
            result["udp"] = node.get("udp", True)
        else:
            raise ProtocolError("Protocol has no Mihomo adapter; it cannot be exported")
        return result
    except ProtocolError:
        raise
    except (KeyError, TypeError, ValueError, AttributeError):
        raise ProtocolError("Invalid node configuration") from None


def connection_id(node, credentials):
    connection = to_mihomo(node, credentials)
    connection.pop("name")
    raw = json.dumps(connection, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def to_uri(node, credentials):
    """Generate escaped canonical links. First validate the export capability."""
    proxy = to_mihomo(node, credentials)
    p = node["protocol"]
    host = proxy["server"]
    endpoint = ("[" + host + "]" if ":" in host else host) + ":" + str(proxy["port"])
    name = quote(node["name"], safe="")
    if p == "vmess":
        d = {"v": "2", "ps": node["name"], "add": host, "port": str(node["port"]), "id": proxy["uuid"],
             "aid": "0", "scy": proxy["cipher"], "net": node.get("transport", "tcp"), "type": "none",
             "tls": "tls" if proxy["tls"] else ""}
        if node.get("transport") == "http":
            d.update(net="tcp", type="http")
        for key in ("host", "path", "sni", "alpn"):
            if node.get(key):
                d[key] = ",".join(node[key]) if key == "alpn" else node[key]
        if node.get("fingerprint"):
            d["fp"] = node["fingerprint"]
        if proxy.get("skip-cert-verify"):
            d["allowInsecure"] = "1"
        if node.get("certificate_pin") or node.get("service_name"):
            raise ProtocolError("VMess JSON share link cannot represent this certificate pin or gRPC service")
        return "vmess://" + _b64(json.dumps(d, ensure_ascii=False, separators=(",", ":")))
    if p == "shadowsocks":
        return "ss://" + _b64(node["method"] + ":" + credentials["password"]) + "@" + endpoint + "#" + name
    q = {}
    if p in {"vless", "trojan", "anytls"}:
        q.update(type=node.get("transport", "tcp"), security=node.get("security", "none"))
        for src, dest in (("host", "host"), ("path", "path"), ("service_name", "serviceName")):
            if node.get(src):
                q[dest] = node[src]
    if p == "vless":
        auth = proxy["uuid"]
        q["encryption"] = "none"
        for src, dest in (("flow", "flow"), ("public_key", "pbk"), ("short_id", "sid"), ("spider_x", "spx")):
            if src in node:
                q[dest] = node[src]
    elif p == "tuic":
        auth = proxy["uuid"] + ":" + quote(credentials["password"], safe="")
        q.update(congestion_control=proxy["congestion-controller"], udp_relay_mode=proxy["udp-relay-mode"])
        if "disable_sni" in node:
            q["disable_sni"] = "1" if node["disable_sni"] else "0"
    elif p == "socks":
        auth = quote(credentials["username"], safe="") + ":" + quote(credentials["password"], safe="") if credentials.get("username") else ""
        q["udp"] = "1" if node.get("udp", True) else "0"
    else:
        auth = quote(credentials["password"], safe="")
    for src, dest in (("sni", "sni"), ("fingerprint", "fp"), ("certificate_pin", "pinSHA256")):
        if node.get(src):
            q[dest] = node[src]
    if node.get("alpn"):
        q["alpn"] = ",".join(node["alpn"])
    if proxy.get("skip-cert-verify"):
        q["insecure"] = "1"
    if p == "hysteria2" and node.get("obfs"):
        q.update(obfs=node["obfs"], **{"obfs-password": credentials["obfs_password"]})
    return p + "://" + (auth + "@" if auth else "") + endpoint + ("?" + urlencode(q, quote_via=quote) if q else "") + "#" + name


def capabilities():
    """Keep endpoint support and evidence separate from renderer capability."""
    return [
        {"protocol": p, "transports": transports, "uri_import": supported, "mihomo_export": supported,
         "end_to_end_verified": False, "note": note}
        for p, transports, supported, note in (
            ("vless", ["tcp", "ws", "h2", "httpupgrade", "grpc"], True, "REALITY: TCP/H2/gRPC; Vision: TCP only"),
            ("hysteria2", ["quic"], True, "Trusted TLS by default; salamander supported"),
            ("shadowsocks", ["tcp"], True, "AEAD and 2022 ciphers; no plugins"),
            ("trojan", ["tcp", "ws", "h2", "httpupgrade", "grpc"], True, "TLS only"),
            ("tuic", ["quic"], True, "TUIC v5 UUID/password"),
            ("anytls", ["tcp"], True, "TLS only; REALITY is unsupported by Mihomo"),
            ("vmess", ["tcp", "http", "ws", "h2", "httpupgrade"], True, "AEAD; plain HTTP/1 header mode; QUIC refused; no lossy downgrade"),
            ("socks", ["tcp"], True, "SOCKS5 only"),
            ("direct", [], False, "Forwarding is a server feature, not a client proxy node"),
            ("vmess-quic", ["quic"], False, "Keep legacy service; Mihomo cannot represent this transport"),
        )]
