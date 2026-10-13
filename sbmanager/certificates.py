"""Certbot commands and checked certificate candidates, with no deployment writes.

The caller must commit stage_lineage() through the normal configuration transaction.
Certbot's own archive is never used by a restricted service directly.
"""
from __future__ import annotations

import ipaddress
import re
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

CERT_ROOT = "/etc/sb/certificates"
WEBROOT = "/var/lib/sb/acme"
LEGACY_WEBROOT = "/var/www/subscription-acme"
HOOK = "/etc/letsencrypt/renewal-hooks/deploy/50-sb"


class CertificateError(ValueError):
    pass


def validate_domain(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise CertificateError("a DNS domain is required")
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise CertificateError("invalid domain") from exc
    if len(value) > 253 or "." not in value or value.endswith("."):
        raise CertificateError("a fully qualified DNS domain is required")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        raise CertificateError("invalid domain label")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise CertificateError("use a DNS domain rather than an IP address")


def managed_domains(state: dict) -> list[str]:
    domains = state["domains"]
    values = [domains["site"], domains["subscription"]]
    values += domains.get("site_aliases", []) + domains.get("subscription_aliases", [])
    values += [a["domain"] for a in state.get("subscription", {}).get("aliases", [])]
    # Only public CA lineages are enrolled by migration; pinned/self-signed
    # certificates deliberately stay outside this list.
    values += [item["domain"] for item in state.get("legacy", {}).get("certificates", [])]
    return sorted({validate_domain(value) for value in values})


def cert_paths(domain: str) -> tuple[str, str]:
    directory = f"{CERT_ROOT}/{validate_domain(domain)}"
    return f"{directory}/fullchain.pem", f"{directory}/privkey.pem"


def webroot_for(state: dict, domain: str) -> str:
    """Retain enrolled renewal paths; accept no arbitrary Nginx root injection."""
    domain = validate_domain(domain)
    value = state.get("certificates", {}).get("webroots", {}).get(domain, WEBROOT)
    if value not in (WEBROOT, LEGACY_WEBROOT):
        raise CertificateError("certificate webroot must be a recognized managed ACME directory")
    return value


def certbot_issue_command(domains: list[str], email: str) -> list[str]:
    """Use one independently renewable lineage per managed DNS name."""
    names = list(dict.fromkeys(validate_domain(d) for d in domains))
    if len(names) != 1:
        raise CertificateError("issue one certificate lineage per domain")
    if not isinstance(email, str) or not re.fullmatch(r"[^\s@\x00-\x1f]+@[^\s@\x00-\x1f]+\.[^\s@\x00-\x1f]+", email):
        raise CertificateError("a valid ACME contact email is required")
    command = ["certbot", "certonly", "--non-interactive", "--agree-tos", "--email", email,
               "--webroot", "--webroot-path", WEBROOT, "--cert-name", names[0],
               "--key-type", "ecdsa", "--elliptic-curve", "secp256r1", "--keep-until-expiring"]
    for name in names:
        command.extend(["--domain", name])
    return command


def certbot_renew_command() -> list[str]:
    return ["certbot", "renew", "--non-interactive", "--quiet"]


def deploy_hook() -> bytes:
    return b'#!/bin/sh\nset -eu\n: "${RENEWED_LINEAGE:?missing Certbot lineage}"\nexec /usr/local/bin/sb cert deploy --lineage "$RENEWED_LINEAGE"\n'


def _run(command: list[str], *, data: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(command, input=data, capture_output=True, check=False, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CertificateError("OpenSSL certificate validation could not run") from exc
    if completed.returncode:
        # Do not propagate arbitrary subprocess output containing private material.
        raise CertificateError("certificate or private-key validation failed")
    return completed.stdout


def validate_pair(chain: bytes, private_key: bytes, domains: list[str], *, openssl: str = "openssl",
                  ca_file: str | Path | None = None) -> None:
    """Validate chain trust, server purpose, hostname, expiry, and matching keys.

    Only the public chain goes into a temporary file; private keys are supplied
    to OpenSSL on stdin. ca_file is intended for an isolated test trust anchor.
    Production callers omit it and use the operating system's trust store.
    """
    if not chain or not private_key or len(chain) > 1024 * 1024 or len(private_key) > 65536:
        raise CertificateError("certificate material is empty or too large")
    if b"-----BEGIN CERTIFICATE-----" not in chain or b"PRIVATE KEY-----" not in private_key:
        raise CertificateError("expected PEM certificate and private key")
    _run([openssl, "x509", "-noout", "-checkend", "86400"], data=chain)
    certificates = re.findall(rb"-----BEGIN CERTIFICATE-----\s+.+?-----END CERTIFICATE-----", chain, re.DOTALL)
    if not certificates:
        raise CertificateError("certificate chain is malformed")
    # -untrusted supplies intermediates, never a new trust anchor.
    with tempfile.TemporaryDirectory(prefix="sb-cert-check-") as directory:
        intermediate = Path(directory) / "chain.pem"
        intermediate.write_bytes(chain)
        for domain in domains:
            argv = [openssl, "verify", "-purpose", "sslserver", "-verify_hostname", validate_domain(domain),
                    "-untrusted", str(intermediate)]
            if ca_file is not None:
                argv.extend(["-CAfile", str(ca_file), "-no-CApath", "-no-CAstore"])
            _run(argv, data=certificates[0])
    certificate_public = _run([openssl, "x509", "-pubkey", "-noout"], data=chain)
    certificate_der = _run([openssl, "pkey", "-pubin", "-outform", "DER"], data=certificate_public)
    key_der = _run([openssl, "pkey", "-pubout", "-outform", "DER", "-passin", "pass:"], data=private_key)
    if not certificate_der or certificate_der != key_der:
        raise CertificateError("certificate and private key do not match")


def stage_lineage(lineage: str | Path, state: dict, root: Path = Path("/"), *, openssl: str = "openssl",
                  ca_file: str | Path | None = None) -> dict[str, bytes]:
    """Read an authorized Certbot lineage; return copies for a transaction to apply.

    root maps logical Linux paths in tests. Certbot's live/archive symlinks are
    accepted only inside that same domain's managed lineage.
    """
    logical = PurePosixPath(str(lineage))
    if not logical.is_absolute() or logical.parent != PurePosixPath("/etc/letsencrypt/live"):
        raise CertificateError("lineage must be a managed /etc/letsencrypt/live/domain path")
    domain = validate_domain(logical.name)
    if domain not in managed_domains(state):
        raise CertificateError("lineage is not owned by this installation")
    root = Path(root).resolve()
    live = root / "etc/letsencrypt/live" / domain
    archive = root / "etc/letsencrypt/archive" / domain
    allowed = [live.absolute(), archive.absolute()]
    material = []
    for name in ("fullchain.pem", "privkey.pem"):
        path = live / name
        resolved = path.resolve(strict=True)
        if not any(resolved.is_relative_to(base) for base in allowed) or not resolved.is_file():
            raise CertificateError("certificate symlink escapes its managed lineage")
        if resolved.stat().st_size > 1024 * 1024:
            raise CertificateError("certificate file is too large")
        material.append(resolved.read_bytes())
    chain, key = material
    validate_pair(chain, key, [domain], openssl=openssl, ca_file=ca_file)
    certificate, private_key = cert_paths(domain)
    return {certificate: chain, private_key: key}


def certificate_status(state: dict, root: Path = Path("/"), *, openssl: str = "openssl",
                       ca_file: str | Path | None = None) -> list[dict]:
    results = []
    for domain in managed_domains(state):
        chain, key = cert_paths(domain)
        entry = {"domain": domain, "valid": False}
        try:
            chain_bytes = (root / chain.lstrip("/")).read_bytes()
            validate_pair(chain_bytes, (root / key.lstrip("/")).read_bytes(), [domain], openssl=openssl, ca_file=ca_file)
            entry["valid"] = True
            entry["dates"] = _run([openssl, "x509", "-noout", "-dates"], data=chain_bytes).decode().strip()
        except (OSError, CertificateError) as exc:
            entry["error"] = str(exc)
        results.append(entry)
    return results
