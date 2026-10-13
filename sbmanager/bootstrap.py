"""Bounded host preparation and reversible ACME listener setup.

Package dependencies may remain after a failed installation. Managed files,
temporary HTTP listeners, APT policy, and pre-existing service states are
restored. No existing Nginx/core package is upgraded during migration.
"""
from __future__ import annotations

from contextlib import contextmanager
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.request

from . import certificates, system, updates
from .state import encode, logical_path
from .transaction import atomic

ROOT = Path("/")
PREPARATION = "/var/lib/sb/preparation.json"
ACME_SESSION = "/var/lib/sb/acme-session.json"
POLICY = "/usr/sbin/policy-rc.d"
POLICY_BODY = b"#!/bin/sh\n# sb-manager temporary package service guard\nexit 101\n"
KEYRING = "/usr/share/keyrings/sb-nginx-archive-keyring.gpg"
NGINX_SOURCE = "/etc/apt/sources.list.d/sb-nginx.list"
NGINX_PIN = "/etc/apt/preferences.d/sb-nginx"
OFFICIAL_KEY = "573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62"
# Official HTTPS key bundle + signed bookworm InRelease verified 2026-10-13.
# All three fingerprints are also recorded in nginx.org tracker #2654, whose
# maintainer confirmed publishing the updated keys.
OFFICIAL_KEYS = (OFFICIAL_KEY, "8540A6F18833A80E9C1653A42FD21310B49F6B46",
                 "9E9BE90EACBCDE69FE9B204CBCDCD8A38D88A2B3")


def _path(name):
    return logical_path(ROOT, name)


def _probe(argv):
    return subprocess.run(list(map(str, argv)), capture_output=True, timeout=30)


def _save(record):
    atomic(_path(PREPARATION), encode(record), 0o600)


def _remember_write(record, name, body, mode=0o600):
    path = _path(name)
    if name not in record["files"]:
        old = {"exists": path.exists()}
        if path.exists():
            if not path.is_file():
                raise ValueError("Host preparation target is not a regular file")
            info = path.stat()
            old.update(body=base64.b64encode(path.read_bytes()).decode(), mode=stat.S_IMODE(info.st_mode),
                       uid=info.st_uid, gid=info.st_gid)
        record["files"][name] = old
    record["files"][name]["written_sha256"] = hashlib.sha256(body).hexdigest()
    _save(record)  # Durable before mutation, including a crash between write and return.
    atomic(path, body, mode)


def finish_preparation():
    """Call only after the complete install transaction committed successfully."""
    path = _path(PREPARATION)
    if path.exists():
        path.unlink()


def _installation_committed(record):
    """Identify the narrow crash window after commit but before prep cleanup."""
    identifier = record.get("installation_id")
    current = _path("/etc/sb/state.json")
    if not identifier or not current.exists() or json.loads(current.read_bytes()).get("installation_id") != identifier:
        return False
    base = _path("/var/backups/sb/transactions")
    for journal in base.glob("*/journal.json"):
        value = json.loads(journal.read_bytes())
        if value.get("status") != "committed" or value.get("label") not in ("install", "migrate"):
            continue
        entry = value.get("files", {}).get("/etc/sb/state.json")
        candidate = journal.parent / "stage/etc/sb/state.json"
        if entry and not entry.get("existed", True) and candidate.is_file():
            if json.loads(candidate.read_bytes()).get("installation_id") == identifier:
                return True
    return False


def rollback_preparation():
    """Restore preparatory files/services; safe when no preparation was started."""
    recover_acme()
    path = _path(PREPARATION)
    if not path.exists():
        return
    record = json.loads(path.read_bytes())
    if _installation_committed(record):
        # A broken output pipe or SIGINT after transaction commit must never
        # erase the core that the now-active installation is using.
        finish_preparation()
        return
    policy = _path(POLICY)
    if record.get("owned_guard_created") and policy.exists() and policy.read_bytes() != POLICY_BODY:
        raise RuntimeError("Preparation's policy-rc.d was replaced; preserving it and recovery journal for review")
    for name, before in reversed(list(record["files"].items())):
        target = _path(name)
        if before["exists"]:
            atomic(target, base64.b64decode(before["body"]), before["mode"])
            if os.name == "posix":
                os.chown(target, before["uid"], before["gid"])
        else:
            target.unlink(missing_ok=True)
    system.restore_services(record["services"])
    # Accounts are intentionally not deleted: a later administrator may already
    # have assigned files to them. They are locked system users without shells.
    path.unlink()


@contextmanager
def package_service_guard(record=None):
    """Prevent package maintainer scripts from starting listeners.

An existing policy is retained only if it is the exact known deny-all policy;
arbitrary existing scripts are never executed/replaced by this installer.
"""
    path = _path(POLICY)
    existed = path.exists()
    if existed:
        if not path.is_file() or path.read_bytes() not in (POLICY_BODY, b"#!/bin/sh\nexit 101\n"):
            raise RuntimeError("Existing policy-rc.d requires administrator review; it was preserved")
        yield
        return
    if record is not None:
        record["owned_guard_created"] = True
        _remember_write(record, POLICY, POLICY_BODY, 0o755)
    else:
        atomic(path, POLICY_BODY, 0o755)
    try:
        yield
    finally:
        if path.read_bytes() != POLICY_BODY:
            raise RuntimeError("policy-rc.d changed concurrently; preserving it for administrator review")
        path.unlink()


def _apt(*args):
    # No package removal/downgrade, no incidental upgrade of installed packages.
    return system.run(["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "apt-get",
                       "-o", "Dpkg::Options::=--force-confold", *args], timeout=600)


def _key_bytes():
    request = urllib.request.Request("https://nginx.org/keys/nginx_signing.key", headers={"User-Agent": "sb-manager"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.geturl() != request.full_url:
            raise ValueError("Unexpected Nginx signing key redirect")
        value = response.read(65537)
    if len(value) > 65536:
        raise ValueError("Nginx signing key is oversized")
    return value


def _nginx_keyring():
    """Anchor the bundle to the fingerprint published by nginx.org."""
    key = _key_bytes()
    with tempfile.TemporaryDirectory(prefix="sb-nginx-gpg-") as directory:
        home = Path(directory)
        os.chmod(home, 0o700)
        source = home / "nginx.asc"
        source.write_bytes(key)
        listing = system.run(["gpg", "--batch", "--homedir", home, "--with-colons", "--show-keys", source])
        fingerprints = {line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")}
        if not set(OFFICIAL_KEYS) <= fingerprints:
            raise ValueError("Nginx signing key fingerprint mismatch")
        # Trust only explicitly pinned official keys. Do not export
        # unrelated keys merely because they accompany the official bundle.
        system.run(["gpg", "--batch", "--homedir", home, "--import", source])
        output = home / "nginx.gpg"
        system.run(["gpg", "--batch", "--homedir", home, "--output", output, "--export", *OFFICIAL_KEYS])
        return output.read_bytes()


def nginx_package_version(values, version):
    code = {("debian", "12"): "bookworm", ("debian", "13"): "trixie", ("ubuntu", "24.04"): "noble"}.get(
        (values.get("ID"), values.get("VERSION_ID")))
    if code is None or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Unsupported Nginx package target")
    return code, f"{version}-1~{code}"


def _nginx_capabilities(state=None):
    result = _probe(["nginx", "-V"])
    value = (result.stdout + result.stderr).decode(errors="replace")
    match = re.search(r"nginx/([0-9]+)\.([0-9]+)\.([0-9]+)", value)
    if result.returncode or not match or tuple(map(int, match.groups())) < (1, 22, 0):
        raise RuntimeError("Nginx >= 1.22 is required; migration never upgrades it implicitly")
    version = tuple(map(int, match.groups()))
    needs_upstream_h2 = re.search(r"\bproxy_http_version\s+2(?:\.0)?\s*;", (state or {}).get("legacy", {}).get("http_config", ""))
    if needs_upstream_h2 and version < (1, 29, 4):
        raise RuntimeError("Migrated HTTP/2 upstream requires Nginx >= 1.29.4; explicitly upgrade Nginx before this migration")
    for option in ("--with-http_ssl_module", "--with-http_v2_module", "--with-stream_ssl_preread_module"):
        if option not in value:
            raise RuntimeError("Nginx lacks required TLS, HTTP/2 or stream SNI support")
    if not re.search(r"(?:^|\s)--with-stream(?:=dynamic)?(?:\s|$)", value):
        raise RuntimeError("Nginx stream support is required")
    dynamic = "--with-stream=dynamic" in value
    module_path = re.search(r"--modules-path=([^\s]+)", value)
    directory = module_path[1] if module_path else "/usr/lib/nginx/modules"
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", directory) or ".." in Path(directory).parts:
        raise RuntimeError("Unsupported Nginx dynamic module directory")
    return {"version": ".".join(match.groups()), "legacy_http2_directive": version < (1, 25, 1),
            "dynamic_stream": dynamic, "stream_module": directory + "/ngx_stream_module.so"}


def _ensure_stream_module(info, record):
    if not info["dynamic_stream"]:
        return
    module = _path(info["stream_module"])
    if not module.exists():
        package_version = system.run(["dpkg-query", "-W", "-f", "${Version}", "nginx"]).strip()
        if not re.fullmatch(r"[0-9A-Za-z.+:~_-]+", package_version):
            raise RuntimeError("Cannot identify the installed distribution Nginx package version")
        package = "libnginx-mod-stream=" + package_version
        try:
            metadata = system.run(["apt-cache", "show", package])
        except RuntimeError as exc:
            raise RuntimeError("No stream module matching installed Nginx " + package_version + "; explicitly update the distribution packages together first") from exc
        if not re.search(r"^Package: libnginx-mod-stream$", metadata, re.M) or not re.search(
                r"^Version: " + re.escape(package_version) + r"$", metadata, re.M):
            raise RuntimeError("No exact compatible distribution stream module is available")
        request = ("install", "-y", "--no-remove", "--no-upgrade", "--no-install-recommends",
                   package, "nginx=" + package_version)
        simulation = _apt("--simulate", *request)
        # A missing module is allowed; replacing the existing web server is not.
        if re.search(r"^(?:Remv |Inst nginx(?:\s|:|-(?:core|common|full|light|extras)\b))", simulation, re.M):
            raise RuntimeError("Installing the stream module would replace existing Nginx; migration stopped")
        _apt(*request)
        if system.run(["dpkg-query", "-W", "-f", "${Version}", "nginx"]).strip() != package_version:
            raise RuntimeError("Nginx package version changed unexpectedly during module installation")
        if not module.is_file():
            raise RuntimeError("The matching stream module package did not provide the expected module")
    # A load test verifies binary compatibility, independently of package names.
    with tempfile.TemporaryDirectory(prefix="sb-stream-check-") as directory:
        directory = Path(directory)
        config = directory / "nginx.conf"
        config.write_text(f"load_module {module};\nerror_log /dev/null crit;\npid {directory / 'nginx.pid'};\n"
                          "events {}\nstream { server { listen 127.0.0.1:65534; ssl_preread on; proxy_pass 127.0.0.1:65533; } }\n")
        system.run(["nginx", "-t", "-p", str(directory) + "/", "-c", config])
    active_config = system.run(["nginx", "-T"])
    clean = re.sub(r"#[^\n]*", "", active_config)
    if not re.search(r"\bload_module\s+[^;\n]*ngx_stream_module\.so\s*;", clean):
        path = _path("/etc/nginx/nginx.conf")
        _remember_write(record, "/etc/nginx/nginx.conf",
                        (f"load_module {info['stream_module']}; # sb-manager required stream module\n" + path.read_text()).encode(), 0o644)
        system.run(["nginx", "-t"])


def _install_packages(values, pinned, record, migration, state=None):
    existing_nginx = shutil.which("nginx") is not None
    if existing_nginx:
        existing_info = _nginx_capabilities(state)  # Reject before invoking apt on incompatible migrations.
        if not migration and existing_info["version"] != pinned["nginx"]:
            raise RuntimeError("Existing Nginx differs from the pinned new-install version; inspect an explicit migration instead of upgrading or downgrading it")
    with package_service_guard(record):
        _apt("update")
        _apt("install", "-y", "--no-remove", "--no-upgrade", "--no-install-recommends",
             "ca-certificates", "curl", "gnupg", "certbot", "python3-yaml", "iproute2", "openssl")
        if not existing_nginx:
            code, package = nginx_package_version(values, pinned["nginx"])
            _remember_write(record, KEYRING, _nginx_keyring(), 0o644)
            repo = f"deb [signed-by={KEYRING}] https://nginx.org/packages/{values['ID']} {code} nginx\n"
            _remember_write(record, NGINX_SOURCE, repo.encode(), 0o644)
            pin = f"Package: nginx\nPin: version {package}\nPin-Priority: 990\n"
            _remember_write(record, NGINX_PIN, pin.encode(), 0o644)
            _apt("update")
            _apt("install", "-y", "--no-remove", "--no-install-recommends", "nginx=" + package)
        info = _nginx_capabilities(state)
        _ensure_stream_module(info, record)
    if state is not None:
        state["nginx"] = {key: info[key] for key in ("version", "legacy_http2_directive")}


def _service_accounts():
    import pwd
    import grp
    # The private management journal can create this parent under umask 077;
    # ACME workers need traversal before the final transaction sets permissions.
    _path("/var/lib/sb").mkdir(parents=True, exist_ok=True)
    os.chmod(_path("/var/lib/sb"), 0o711)
    for name in ("sb-core", "sb-subscription"):
        try:
            row = pwd.getpwnam(name)
        except KeyError:
            system.run(["useradd", "--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
                        "--shell", "/usr/sbin/nologin", name])
            row = pwd.getpwnam(name)
        group = grp.getgrnam(name)
        if row.pw_uid == 0 or group.gr_gid == 0 or row.pw_gid != group.gr_gid or row.pw_shell not in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
            raise RuntimeError("Existing service account has unsafe privileges or an interactive shell")
        if any(name in entry.gr_mem and entry.gr_gid != group.gr_gid for entry in grp.getgrall()):
            raise RuntimeError("Existing service account has supplementary groups; review its privileges first")
    for name, mode in (("/var/lib/sb/core", 0o750), (certificates.WEBROOT, 0o755), ("/var/lib/sb/rules", 0o700)):
        path = _path(name)
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
    row = pwd.getpwnam("sb-core")
    os.chown(_path("/var/lib/sb/core"), row.pw_uid, row.pw_gid)


def runtime_files(source):
    """Copy only distributable runtime inputs, never working-tree credentials."""
    source = Path(source)
    files = {}
    for relative in ("versions.json", "LICENSE", "sing-box.sh"):
        path = source / relative
        if path.is_symlink() or not path.is_file():
            raise ValueError("Runtime source is incomplete")
        files["/opt/sb/current/" + relative] = path.read_bytes()
    for folder in (source / "sbmanager",):
        for path in folder.rglob("*"):
            if path.is_symlink():
                raise ValueError("Runtime source must not contain symlinks")
            if path.is_file() and (path.suffix in {".py", ".yaml", ".html"}
                                   or path.relative_to(folder).as_posix() == "vendor/NOTICE.md"):
                files["/opt/sb/current/" + path.relative_to(source).as_posix()] = path.read_bytes()
    files["/usr/local/bin/sb"] = (source / "sing-box.sh").read_bytes()
    return files


def prepare_host(source, state, public_addresses=(), migration=False):
    """Prepare dependencies; caller must finish/rollback after its full transaction."""
    values = system.os_check()
    system.network_preflight(state, public_addresses=public_addresses, new_install=not migration)
    if _path(PREPARATION).exists():
        raise RuntimeError("Interrupted host preparation exists; recover it before retrying")
    pinned = json.loads((Path(source) / "versions.json").read_bytes())
    files = runtime_files(source)
    record = {"installation_id": state["installation_id"], "files": {},
              "services": system.service_state(["nginx", "caddy", "certbot.timer"])}
    _save(record)
    try:
        _install_packages(values, pinned, record, migration, state)
        _service_accounts()
        arch = "arm64" if platform.machine() in {"arm64", "aarch64"} else "amd64"
        for name in ("sing-box", "mihomo"):
            target = "/opt/sb/bin/" + name
            if _path(target).exists():
                # Never overwrite an unrelated executable before a transaction.
                raise RuntimeError("Managed binary path already exists without managed state; review it explicitly")
            value = updates.binary(pinned["assets"][name + "-" + arch])
            _remember_write(record, target, value, 0o755)
            files[target] = value
        return files
    except BaseException:
        rollback_preparation()
        raise


def _challenge_config(domains):
    names = " ".join(certificates.validate_domain(name) for name in domains)
    return f"""server {{
    listen 80;
    listen [::]:80;
    server_name {names};
    access_log off;
    error_log /dev/null crit;
    location ^~ /.well-known/acme-challenge/ {{ root {certificates.WEBROOT}; default_type text/plain; try_files $uri =404; }}
    location / {{ return 404; }}
}}
"""


def renewal_webroot(domain):
    """Read Certbot's restricted renewal fields without executing configuration."""
    domain = certificates.validate_domain(domain)
    path = _path("/etc/letsencrypt/renewal/" + domain + ".conf")
    if path.stat().st_size > 131072:
        raise ValueError("Certificate renewal configuration is oversized")
    section, authenticator, default, roots = "", None, None, {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            section = line
            continue
        if "=" not in line:
            continue
        key, value = [x.strip() for x in line.split("=", 1)]
        value = value.rstrip(",").strip().strip("\"'")
        if section == "[renewalparams]":
            if key == "authenticator":
                authenticator = value
            elif key == "webroot_path":
                default = value
        elif section == "[[webroot_map]]":
            roots[key] = value
    selected = roots.get(domain, default)
    if authenticator != "webroot" or selected not in (certificates.WEBROOT, certificates.LEGACY_WEBROOT):
        raise RuntimeError("Existing certificate renewal requires a recognized webroot authenticator for " + domain)
    return selected


def _challenge_webroot(domain, roots):
    """Prove the existing HTTP vhost serves one of our known challenge roots."""
    for name in roots:
        root = _path(name)
        folder = _path(name + "/.well-known/acme-challenge")
        folder.mkdir(parents=True, exist_ok=True)
        for public in (root, root / ".well-known", folder):
            os.chmod(public, 0o755)
        token = secrets.token_urlsafe(24)
        path = folder / token
        atomic(path, token.encode(), 0o644)
        try:
            connection = http.client.HTTPConnection("127.0.0.1", 80, timeout=5)
            try:
                connection.request("GET", "/.well-known/acme-challenge/" + token, headers={"Host": domain})
                response = connection.getresponse()
                if response.status == 200 and response.read(1024) == token.encode():
                    return name
            finally:
                connection.close()
        except OSError:
            pass
        finally:
            path.unlink(missing_ok=True)
    raise RuntimeError("HTTP challenge route is not reachable for " + domain + "; original services will be restored")


def recover_acme():
    """Recover an interrupted HTTP challenge while holding the manager lock."""
    journal = _path(ACME_SESSION)
    if not journal.exists():
        return
    session = json.loads(journal.read_bytes())
    if session.get("kind") == "live-nginx":
        path = _path("/etc/nginx/conf.d/sb-acme-challenge.conf")
        if path.exists():
            if hashlib.sha256(path.read_bytes()).hexdigest() != session["sha256"]:
                raise RuntimeError("ACME configuration changed after interruption; preserved for manual review")
            path.unlink()
        system.run(["nginx", "-t"])
        system.run(["systemctl", "reload", "nginx"])
    elif session.get("kind") == "temporary-nginx":
        name = session["directory"]
        if not re.fullmatch(r"/run/sb-acme-[a-f0-9]{24}", name):
            raise ValueError("Invalid ACME recovery directory")
        directory = _path(name)
        conf, pid = directory / "nginx.conf", directory / "nginx.pid"
        if pid.exists():
            number = pid.read_text().strip()
            if not number.isdigit():
                raise RuntimeError("ACME recovery has an invalid process ID")
            cmdline = _path("/proc/" + number + "/cmdline")
            if cmdline.exists():
                command = cmdline.read_bytes()
                if b"nginx" not in command or str(conf).encode() not in command:
                    raise RuntimeError("ACME process ID was reused; refusing to signal another process")
                system.run(["nginx", "-p", str(directory) + "/", "-c", str(conf), "-s", "quit"])
                deadline = time.monotonic() + 10
                while pid.exists() and time.monotonic() < deadline:
                    time.sleep(.1)
                if pid.exists():
                    raise RuntimeError("Temporary ACME Nginx did not stop; retry sb transaction recover")
            else:
                pid.unlink()
        if session.get("restore_caddy"):
            system.run(["systemctl", "start", "caddy"])
        conf.unlink(missing_ok=True)
        if directory.exists():
            directory.rmdir()  # Never recursively remove an unrecognized file.
    else:
        raise ValueError("Unknown ACME recovery record")
    journal.unlink()


@contextmanager
def challenge_listener(state, domains, new_install=False):
    """Keep live Nginx HTTPS intact; briefly suspend only recognized old Caddy."""
    services = system.service_state(["nginx", "caddy"])
    active_nginx = services["nginx"]["is-active"]
    active_caddy = services["caddy"]["is-active"]
    if new_install and (active_nginx or active_caddy):
        raise RuntimeError("A web service started since initial preflight; retry after inspecting it")
    if active_nginx and active_caddy:
        raise RuntimeError("Both Nginx and Caddy are active; HTTP ownership requires manual review")
    if active_nginx:
        main = _path("/etc/nginx/nginx.conf").read_text()
        if not re.search(r"\binclude\s+/etc/nginx/conf\.d/\*\.conf\s*;", re.sub(r"#[^\n]*", "", main)):
            raise RuntimeError("Live Nginx must include /etc/nginx/conf.d/*.conf for isolated ACME provisioning")
        path = _path("/etc/nginx/conf.d/sb-acme-challenge.conf")
        if path.exists():
            raise RuntimeError("An existing ACME bootstrap file requires recovery")
        body = _challenge_config(domains).encode()
        atomic(_path(ACME_SESSION), encode({"kind": "live-nginx", "sha256": hashlib.sha256(body).hexdigest()}))
        try:
            atomic(path, body, 0o644)
            system.run(["nginx", "-t"])
            system.run(["systemctl", "reload", "nginx"])
            yield
        finally:
            recover_acme()
        return
    if active_caddy and "caddy.service" not in state.get("legacy", {}).get("switch", {}).get("stop_services", []):
        raise RuntimeError("Caddy is not part of the reviewed migration; no listener was changed")
    name = "/run/sb-acme-" + secrets.token_hex(12)
    directory = _path(name)
    directory.mkdir(parents=True, mode=0o700)
    conf, pid = directory / "nginx.conf", directory / "nginx.pid"
    atomic(_path(ACME_SESSION), encode({"kind": "temporary-nginx", "directory": name, "restore_caddy": active_caddy}))
    try:
        # Explicit cache paths prevent prefix-relative temporary directories
        # from obstructing recovery of the isolated configuration directory.
        cache = certificates.WEBROOT + "/.nginx-temp"
        _path(cache).mkdir(parents=True, exist_ok=True)
        for public in (_path(certificates.WEBROOT), _path(cache)):
            os.chmod(public, 0o755)
        temporary_paths = "\n".join(f"{name}_temp_path {cache}/{name};" for name in
                                    ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
        conf.write_text(f"pid {pid};\nerror_log /dev/null crit;\nevents {{}}\nhttp {{\n{temporary_paths}\n{_challenge_config(domains)}\n}}\n")
        command = ["nginx", "-p", str(directory) + "/", "-c", str(conf)]
        system.run(command + ["-t"])
        if active_caddy:
            system.run(["systemctl", "stop", "caddy"])
        if system.run(["ss", "-H", "-ltn", "sport = :80"]).strip():
            raise RuntimeError("TCP80 is occupied by an unrecognized listener")
        system.run(command)
        yield
    finally:
        recover_acme()


def ensure_certificates(state, new_install=False):
    """Issue missing certificates, restore listeners, return checked candidates."""
    system.require_linux_root()
    recover_acme()
    pending, files = [], {}
    webroots = state.setdefault("certificates", {}).setdefault("webroots", {})
    for domain in certificates.managed_domains(state):
        try:
            candidate = certificates.stage_lineage("/etc/letsencrypt/live/" + domain, state, ROOT)
        except (OSError, certificates.CertificateError):
            pending.append(domain)
        else:
            # A valid certificate alone is insufficient: its saved renewal
            # authenticator/path must continue to work after the final cutover.
            webroots[domain] = renewal_webroot(domain)
            files.update(candidate)
    if not pending:
        return files
    roots = [certificates.WEBROOT]
    if "/etc/nginx/sites-enabled/subscription-generator" in state.get("legacy", {}).get("switch", {}).get("remove_symlinks", {}):
        roots.append(certificates.LEGACY_WEBROOT)
    with challenge_listener(state, pending, new_install=new_install):
        for domain in pending:
            root = _challenge_webroot(domain, roots)
            command = certificates.certbot_issue_command([domain], state["email"])
            command[command.index("--webroot-path") + 1] = root
            # Global management lock is already held; no nested deploy-hook CLI.
            system.run(command + ["--no-directory-hooks"], timeout=600)
            files.update(certificates.stage_lineage("/etc/letsencrypt/live/" + domain, state, ROOT))
            webroots[domain] = renewal_webroot(domain)
            if webroots[domain] != root:
                raise RuntimeError("Certbot did not enroll the validated HTTP challenge webroot")
    return files
