"""Reconcile certificate files without making unrelated services a commit gate.

Validated files and an activation queue commit together. Reloads are retried
from that queue, including after a crash or an unchanged-lineage timer run.
An activation failure never reports a live deployment or discards another
domain's valid renewal. No state, subscription, or credentials are rewritten.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time

from . import certificates, system
from .state import encode, logical_path
from .transaction import Transaction, atomic

PENDING = "/var/lib/sb/certificate-sync/pending.json"
# Only these managed consumers may ever enter the retry queue. Canonicalize
# systemd's equivalent short/full spellings before reconciling current owners.
SERVICE_NAMES = {"nginx": "nginx", "nginx.service": "nginx",
                 "sb-sing-box": "sb-sing-box", "sb-sing-box.service": "sb-sing-box",
                 "sb-sing-box-legacy": "sb-sing-box-legacy.service",
                 "sb-sing-box-legacy.service": "sb-sing-box-legacy.service"}


def dependencies(state, root):
    domains = state["domains"]
    nginx = {domains["site"], domains["subscription"], *domains.get("site_aliases", []),
             *domains.get("subscription_aliases", []),
             *[a["domain"] for a in state.get("subscription", {}).get("aliases", [])]}
    # Preserved migration frontends can reference independently enrolled names.
    nginx.update(re.findall(r"ssl_certificate\s+/etc/sb/certificates/([^/\s]+)/fullchain\.pem",
                            state.get("legacy", {}).get("http_config", "")))
    result = {"nginx": nginx}
    configs = {"sb-sing-box": "/etc/sing-box/sb/config.json"}
    registered = {SERVICE_NAMES.get(name, name) for name in state.get("legacy", {}).get("services", [])}
    if "sb-sing-box-legacy.service" in registered:
        configs["sb-sing-box-legacy.service"] = "/etc/sing-box/sb-legacy/config.json"
    for service, config in configs.items():
        # Read the installed config, including retained legacy TLS listeners.
        text = logical_path(root, config).read_text(encoding="utf-8")
        value = json.loads(text)
        names = set()
        def visit(item):
            if isinstance(item, dict):
                path = item.get("certificate_path", "")
                match = re.fullmatch(r"/etc/sb/certificates/([^/]+)/fullchain\.pem", path)
                if match:
                    names.add(certificates.validate_domain(match[1]))
                for nested in item.values():
                    visit(nested)
            elif isinstance(item, list):
                for nested in item:
                    visit(nested)
        visit(value)
        result[service] = names
    return result


def _reconcile_pending(pending, deps):
    """Validate the queue, then discard only consumers no longer configured.

    Last-user and domain retirement intentionally remove dependencies. Their
    old queue entries are obsolete work, not permission to restart retired
    services. Unknown service names remain a hard validation error.
    """
    if not isinstance(pending, dict):
        raise ValueError("Invalid certificate activation queue")
    current = {}
    for service, values in pending.items():
        if service not in SERVICE_NAMES or not isinstance(values, list):
            raise ValueError("Invalid certificate activation queue")
        service = SERVICE_NAMES[service]
        names = {certificates.validate_domain(name) for name in values}
        retained = names & deps.get(service, set())
        if retained:
            current[service] = sorted(set(current.get(service, [])) | retained)
    return current


def _permissions(root, domains):
    # Atomic replacement creates root-owned files; restore only certificate
    # access, without traversing unrelated service directories.
    import grp
    gid = grp.getgrnam("sb-core").gr_gid
    os.chmod(logical_path(root, "/etc/sb"), 0o711)
    base = logical_path(root, certificates.CERT_ROOT)
    os.chown(base, 0, gid)
    os.chmod(base, 0o750)
    for domain in domains:
        for path in certificates.cert_paths(domain):
            target = logical_path(root, path)
            os.chown(target.parent, 0, gid)
            os.chmod(target.parent, 0o750)
            os.chown(target, 0, gid)
            os.chmod(target, 0o640)


def _check_served_certificate(domain, root):
    """Verify the public TLS endpoint actually loaded the managed leaf."""
    chain = logical_path(root, certificates.cert_paths(domain)[0]).read_text(encoding="ascii")
    first = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", chain, re.DOTALL)
    expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(first[0])).digest()
    context = ssl.create_default_context()
    with socket.create_connection(("127.0.0.1", 443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as stream:
            actual = hashlib.sha256(stream.getpeercert(binary_form=True)).digest()
    if actual != expected:
        raise RuntimeError("TLS endpoint still serves the previous certificate for " + domain)


def _activate_service(service, domains, state, secret, root):
    system.run(["systemctl", "is-active", "--quiet", service])
    if service == "nginx":
        system.run(["nginx", "-t"])
        system.run(["systemctl", "reload", "nginx"])
        for domain in sorted(domains):
            deadline = time.monotonic() + 10
            while True:
                try:
                    _check_served_certificate(domain, root)
                    break
                except (OSError, RuntimeError):
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.2)
    else:
        if service == "sb-sing-box":
            binary, config = "/opt/sb/bin/sing-box", "/etc/sing-box/sb/config.json"
        elif service == "sb-sing-box-legacy.service":
            unit = logical_path(root, "/etc/systemd/system/sb-sing-box-legacy.service").read_text()
            match = re.search(r"^ExecStart=(/opt/sb/legacy/[A-Za-z0-9_-]+/sing-box) ", unit, re.M)
            if not match:
                raise ValueError("Unexpected legacy core service entrypoint")
            binary, config = match[1], "/etc/sing-box/sb-legacy/config.json"
        else:
            raise ValueError("Unexpected certificate service")
        system.run([binary, "check", "-c", config])
        system.run(["systemctl", "restart", service])
        # Exercise only nodes owned by the restarted service. The certificate
        # dependency check has already excluded invalid TLS identities.
        from .probe import local_nodes
        selected = copy.deepcopy(state)
        source = "local" if service == "sb-sing-box" else "legacy"
        selected["nodes"] = [dict(node, source="local") for node in state["nodes"]
                             if node.get("source") == source and node.get("enabled", True)
                             and node.get("security") == "tls" and node.get("sni") in domains]
        local_nodes(selected, secret)
    system.run(["systemctl", "is-active", "--quiet", service])


def synchronize(state, secret, root=Path("/"), *, offline=False, names=None):
    files, failed = certificates.stage_sync(state, root, names=names)
    deps = dependencies(state, root)
    changed = sorted({Path(path).parent.name for path in files})
    queue_file = logical_path(root, PENDING)
    previous = json.loads(queue_file.read_bytes()) if queue_file.exists() else {}
    pending = _reconcile_pending(previous, deps)
    queue_changed = pending != previous
    for service, domains in deps.items():
        updated = set(changed) & domains
        if updated:
            pending[service] = sorted(set(pending.get(service, [])) | updated)
    result = {"applied": changed, "activated": {}, "deferred": {}, "failed": failed}
    if files:
        # Only public validated candidates and the retry record participate in
        # this transaction. Recovery never restarts an already-broken service.
        files[PENDING] = encode(pending)
        result["transaction"] = Transaction(root).apply(files, label="certificate copies",
            activate=(lambda _: None) if offline else lambda _: _permissions(root, changed))
    elif queue_changed:
        # Persist retirement even when no lineage bytes changed. This is only
        # retry metadata; certificates and services remain untouched.
        atomic(queue_file, encode(pending), 0o600)
    if not pending:
        if not files:
            result["unchanged"] = True
        return result
    if offline:
        result["deferred"] = {service: {"domains": domains, "reason": "offline fixture; activation not attempted"}
                              for service, domains in pending.items()}
        return result
    statuses = {name: certificates.managed_copy_status(name, root)
                for name in set().union(*deps.values())}
    for service, domains in list(pending.items()):
        # Nginx can reload an expired but parseable certificate to renew other
        # virtual hosts. A core restart requires all its TLS identities valid.
        required = "loadable" if service == "nginx" else "valid"
        blocked = sorted(name for name in deps[service] if not statuses[name][required])
        if blocked:
            result["deferred"][service] = {"domains": domains, "blocked_by": blocked,
                                            "reason": "invalid managed certificate dependency"}
            continue
        try:
            _permissions(root, deps[service])
            _activate_service(service, set(domains) & deps[service], state, secret, root)
        except (OSError, ValueError, RuntimeError) as exc:
            result["deferred"][service] = {"domains": domains, "reason": str(exc)}
        else:
            result["activated"][service] = domains
            del pending[service]
            atomic(queue_file, encode(pending), 0o600)
    return result
