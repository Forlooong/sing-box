"""Deterministic DNS policy for balanced-v2; no network or template side effects.

Business DIRECT and DNS DIRECT are separate decisions. Unknown destinations and
personal exceptions use proxy DNS even when their business connection is direct.
Call after route assembly, and serialize the result with sort_keys=False.
"""
import copy
import re
from urllib.parse import urlsplit


POLICY_VERSION = "balanced-v2"
REMOTE = ["https://1.1.1.1/dns-query#节点选择", "https://8.8.8.8/dns-query#节点选择"]
DOMESTIC = ["https://223.5.5.5/dns-query#DIRECT", "https://120.53.53.53/dns-query#DIRECT"]
LOCAL = ("+.lan", "+.local", "+.home.arpa")
DOMAIN_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "DOMAIN-REGEX"}
MANAGED_FIELDS = {"enable", "use-system-hosts", "respect-rules", "prefer-h3",
                  "default-nameserver", "proxy-server-nameserver", "direct-nameserver",
                  "direct-nameserver-follow-policy", "nameserver", "nameserver-policy",
                  "proxy-server-nameserver-policy", "fallback", "fallback-filter", "fallback-lazy-query"}
INLINE_PROVIDERS = {"dns-only-personal": ("personal_direct", "personal_proxy"),
                    "dns-only-private": ("private",), "dns-only-services": ("services",),
                    "dns-only-direct": ("direct",)}
GENERATED_POLICIES = {**{"rule-set:" + name: REMOTE for name in
                         ("personal-direct-domain", "personal-proxy-domain", "dns-only-personal",
                          "services-proxy", "dns-only-services")},
                      **{"rule-set:" + name: DOMESTIC for name in ("cn-domain", "dns-only-direct")},
                      **{"rule-set:" + name: ["system"] for name in ("private-domain", "dns-only-private")}}
DOMAIN = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$")


def dns_limitations(inline):
    """DNS has no process, port or destination-IP context; report, never project."""
    return [{"section": section, "rule": rule,
             "reason": "Routing only: DNS queries have no process/port/IP connection context"}
            for section in ("personal_direct", "personal_proxy")
            for rule in inline.get("sections", {}).get(section, [])
            if rule.partition(",")[0] not in DOMAIN_KINDS]


def _servers(value):
    if isinstance(value, str) and value:
        return [value]
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return value
    raise ValueError("DNS policy requires a nonempty resolver string or list")


def _domestic(value):
    # Historical templates used both explicit DIRECT and implicit direct DNS.
    return set(_servers(value)) in (set(DOMESTIC), {v.split("#")[0] for v in DOMESTIC})


def _remote(value):
    for server in _servers(value):
        parsed = urlsplit(server)
        if (parsed.scheme not in {"https", "tls"} or not parsed.hostname or
                parsed.username or parsed.password or parsed.fragment != "节点选择" or
                parsed.query or any(c.isspace() for c in server)):
            return False
    return True


def _domain_range(value):
    """Only canonical exact names and inclusive suffixes have proved semantics."""
    if not isinstance(value, str):
        raise ValueError("DNS domain index contains a non-string predicate")
    suffix = value.startswith("+.")
    host = (value[2:] if suffix else value).lower()
    if not DOMAIN.fullmatch(host):
        raise ValueError("Cannot prove DNS policy overlap for domain syntax: " + value)
    return suffix, host


def _inside(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def _intersects(left, right):
    ls, lh = left
    rs, rh = right
    return lh == rh or (ls and _inside(rh, lh)) or (rs and _inside(lh, rh))


def _regex_matches(pattern, host):
    # Mihomo 1.19.32 uses regexp2 with IgnoreCase. DNS names are ASCII here;
    # accept only shared Python/regexp2 syntax, rejecting character-class
    # subtraction and extensions which Python can silently interpret differently.
    if (not pattern.isascii() or "[[:" in pattern or "[[." in pattern or "[[=" in pattern
            or "-[" in pattern
            or re.search(r"\(\?(?!:|[ims]+(?:\)|:))", pattern)
            or re.search(r"\\(?![AbBdDsSwW\\.*+?{}\[\]()|^$-])", pattern)):
        raise ValueError("Cannot prove custom DNS policy disjoint from unsupported DOMAIN-REGEX: " + pattern)
    try:
        return re.search(pattern, host, flags=re.ASCII | re.IGNORECASE) is not None
    except re.error as error:
        raise ValueError("Cannot evaluate managed DNS DOMAIN-REGEX: " + pattern) from error


def _check_disjoint(custom, providers, inline):
    """Reject overlap or unknown overlap; encryption alone is not compatibility."""
    if not custom:
        return
    index = inline.get("domain_index")
    names = {name for name, provider in providers.items() if provider.get("behavior") == "domain"}
    if not isinstance(index, dict) or not names <= set(index):
        raise ValueError("Custom DNS policies require a complete snapshot domain_index")
    managed = [_domain_range(value) for value in ("+.localhost", *LOCAL)]
    for name in names:
        values = index[name]
        if not isinstance(values, list):
            raise ValueError("Invalid DNS domain_index provider: " + name)
        managed.extend(_domain_range(value) for value in values)
    predicates = []
    for section in inline.get("sections", {}).values():
        for rule in section:
            kind, _, value = rule.partition(",")
            if kind == "DOMAIN":
                managed.append(_domain_range(value))
            elif kind == "DOMAIN-SUFFIX":
                managed.append(_domain_range("+." + value))
            elif kind in {"DOMAIN-KEYWORD", "DOMAIN-REGEX"}:
                predicates.append((kind, value))
    for key in custom:
        candidate = _domain_range(key)
        if any(_intersects(candidate, entry) for entry in managed):
            raise ValueError("Custom DNS policy overlaps managed domains: " + key)
        suffix, host = candidate
        for kind, value in predicates:
            # A suffix admits arbitrary labels; a keyword may occur in one of
            # them, and testing one host cannot prove regex-language disjointness.
            if suffix:
                raise ValueError("Cannot prove custom DNS suffix disjoint from " + kind + ": " + key)
            matches = value.lower() in host if kind == "DOMAIN-KEYWORD" else _regex_matches(value, host)
            if matches:
                raise ValueError("Custom DNS policy overlaps managed " + kind + ": " + key)


def _custom_policies(source, generated, providers, inline):
    policy = source.get("nameserver-policy", {})
    if not isinstance(policy, dict):
        raise ValueError("nameserver-policy must be a mapping")
    custom = {}
    for key, value in policy.items():
        if not isinstance(key, str) or not key or any(c in key for c in "\r\n"):
            raise ValueError("Invalid DNS policy key")
        # Optional providers can disappear on the next snapshot. Recognize their
        # old generated policy by value even when no longer generated this time.
        if key in GENERATED_POLICIES and _servers(value) == _servers(GENERATED_POLICIES[key]):
            continue
        if key in {"localhost", "+.localhost", *LOCAL, "rule-set:private"} and _servers(value) == ["system"]:
            continue
        if key in {"rule-set:direct", "rule-set:icloud", "rule-set:apple"} and _domestic(value):
            continue
        # A modified reserved policy is not silently overwritten. Encryption and
        # proxy binding are necessary, but managed-domain disjointness is checked
        # separately against the exact inputs compiled into this MRS snapshot.
        normalized = key.lstrip("+.*").lower().rstrip(".")
        if (key in GENERATED_POLICIES or key in generated or key in {"localhost", "+.localhost", *LOCAL}
                or normalized == "localhost" or normalized.endswith(".localhost") or not _remote(value)):
            raise ValueError("Custom DNS policy cannot be proved compatible with balanced-v2: " + key)
        # Additional rule sets, geosite data and wildcard syntaxes are not part of
        # the immutable exact/suffix index and therefore cannot be proved disjoint.
        _domain_range(key)
        custom[key] = copy.deepcopy(value)
    node_policy = source.get("proxy-server-nameserver-policy", {})
    if not isinstance(node_policy, dict) or any(not _domestic(v) for v in node_policy.values()):
        raise ValueError("Custom proxy-server DNS policy conflicts with independent bootstrap")
    _check_disjoint(custom, providers, inline)
    return custom


def assemble_dns(document, manifest, inline, override=None):
    """Return a new v2 document, leaving v1 and all input objects untouched.

    override may be the full persisted client template or its DNS mapping. It is
    used to distinguish intentional custom policies from generated policies.
    Conflicting policies raise before any caller-owned object can be changed.
    """
    if manifest.get("policy_version") != POLICY_VERSION:
        return document
    if manifest.get("schema_version") != 2 or inline.get("schema_version") != 2:
        raise ValueError("balanced-v2 DNS requires schema 2")
    result = copy.deepcopy(document)
    dns = result.setdefault("dns", {})
    if not isinstance(dns, dict):
        raise ValueError("Client DNS configuration must be a mapping")
    providers = result.setdefault("rule-providers", {})
    sections = inline.get("sections", {})
    for name, section_names in INLINE_PROVIDERS.items():
        payload = list(dict.fromkeys(rule for section in section_names
                                    for rule in sections.get(section, [])
                                    if rule.partition(",")[0] in DOMAIN_KINDS))
        providers.pop(name, None)
        if payload:
            providers[name] = {"type": "inline", "behavior": "classical", "format": "yaml", "payload": payload}
    policy = {"localhost": "system", "+.localhost": "system"}

    def add(name, resolvers):
        if name in providers:
            policy["rule-set:" + name] = copy.deepcopy(resolvers)

    for name in ("personal-direct-domain", "personal-proxy-domain", "dns-only-personal"):
        add(name, REMOTE)
    # Generic local suffixes must come after personal exceptions. An explicit
    # ruleset matcher separates domain-trie segments in Mihomo 1.19.32.
    for name in LOCAL:
        policy[name] = "system"
    add("private-domain", ["system"])
    add("dns-only-private", ["system"])
    add("services-proxy", REMOTE)
    add("dns-only-services", REMOTE)
    add("cn-domain", DOMESTIC)
    add("dns-only-direct", DOMESTIC)

    source = document.get("dns", {}) if override is None else override
    if isinstance(source, dict) and "dns" in source:
        source = source["dns"]
    if not isinstance(source, dict):
        raise ValueError("DNS override must be a mapping")
    custom = _custom_policies(source, policy, providers, inline)
    # Rebuild after JSON state round-trips; dictionary sorting must never move
    # CN DNS above a personal or overseas exception. Custom DNS is retained only
    # when its domains are proved disjoint from every managed DNS predicate.
    ordered = {"localhost": "system", "+.localhost": "system", **dict(sorted(custom.items()))}
    ordered.update({k: v for k, v in policy.items() if k not in ordered})
    for key in ("fallback", "fallback-filter", "fallback-lazy-query", "proxy-server-nameserver-policy"):
        dns.pop(key, None)
    dns.update({"enable": True, "use-system-hosts": False, "respect-rules": False, "prefer-h3": False,
                "default-nameserver": list(DOMESTIC), "proxy-server-nameserver": list(DOMESTIC),
                "nameserver": list(REMOTE), "direct-nameserver": list(REMOTE),
                "direct-nameserver-follow-policy": True, "nameserver-policy": ordered})
    return result
