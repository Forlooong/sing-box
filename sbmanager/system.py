"""Linux boundary: explicit argv, bounded probes and validated candidate activation."""
from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import time
import urllib.request

from .state import logical_path
from .transaction import atomic

SERVICES = ("nginx", "sb-sing-box", "sb-subscription", "sb-rules.timer", "sb-cert-sync.timer", "certbot.timer")


def run(argv, *, timeout=60, input=None, env=None):
    try:
        result = subprocess.run([str(x) for x in argv], input=input, capture_output=True,
                                timeout=timeout, check=False, env=env)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out: {Path(str(argv[0])).name}") from None
    if result.returncode:
        # Core diagnostics may print complete configurations/passwords.
        detail = ""
        if os.name == "posix" and os.geteuid() == 0:
            folder = logical_path(Path("/"), "/var/log/sb")
            folder.mkdir(parents=True, exist_ok=True)
            os.chmod(folder, 0o700)
            atomic(folder / "last-command.log", (result.stdout + result.stderr)[-1024 * 1024:], 0o600)
            detail = "; protected diagnostics: /var/log/sb/last-command.log"
        raise RuntimeError(f"Command failed: {Path(str(argv[0])).name} (exit {result.returncode})" + detail)
    return result.stdout.decode("utf-8", errors="replace")


def require_linux_root():
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("Live system operations require Linux root; use --root DIR --offline for fixtures")
    if not Path("/run/systemd/system").is_dir():
        raise RuntimeError("This release requires systemd")


def os_check():
    require_linux_root()
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, val = line.split("=", 1)
            values[key] = val.strip('"')
    if (values.get("ID"), values.get("VERSION_ID")) not in {
        ("debian", "12"), ("debian", "13"), ("ubuntu", "24.04")
    }:
        raise RuntimeError("Supported: Debian 12/13, Ubuntu 24.04")
    if platform.machine() not in {"x86_64", "aarch64", "amd64", "arm64"}:
        raise RuntimeError("Supported architectures: amd64/arm64")
    return values


def service_state(names=SERVICES):
    data = {}
    for name in names:
        if not re.fullmatch(r"[A-Za-z0-9_.@-]+", name):
            raise ValueError("Invalid service name")
        item = {}
        for action in ("is-active", "is-enabled"):
            p = subprocess.run(["systemctl", action, name], capture_output=True, timeout=10)
            item[action] = p.returncode == 0
        data[name] = item
    return data


def restore_services(values):
    run(["systemctl", "daemon-reload"])
    # Stop new owners before old listeners resume.
    for name, flags in values.items():
        if not flags["is-active"]:
            subprocess.run(["systemctl", "stop", name], capture_output=True, timeout=30)
    for name, flags in values.items():
        if flags["is-active"]:
            run(["systemctl", "restart", name])
        subprocess.run(["systemctl", "enable" if flags["is-enabled"] else "disable", name],
                       capture_output=True, timeout=30)


def patch_nginx(text):
    marker = "# sb-manager managed includes v1"
    if marker in text:
        if (text.count(marker) != 1 or text.count("include /etc/nginx/sb/http.conf;") != 1
                or text.count("include /etc/nginx/sb/stream.conf;") != 1):
            raise ValueError("Owned Nginx includes were modified")
        return text
    # Locate top-level blocks without treating comments/quoted values as syntax.
    clean = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|#[^\n]*',
                   lambda m: " " * len(m.group()), text)
    if re.search(r"\bstream\s*\{", clean):
        raise ValueError("Unmanaged Nginx stream block requires explicit migration")
    hits = list(re.finditer(r"\bhttp\s*\{", clean))
    if len(hits) != 1:
        raise ValueError("Expected exactly one Nginx http block")
    index = hits[0].end()
    return (text[:index] + "\n    include /etc/nginx/sb/http.conf;\n" + text[index:]
            + "\n" + marker + "\ninclude /etc/nginx/sb/stream.conf;\n")


def validate_candidate(stage, *, root=Path("/"), snapshot_dir=None, remove_symlinks=None):
    """Check the complete staged stack without changing live listeners."""
    require_linux_root()
    stage = Path(stage)
    nginx = logical_path(stage, "/etc/nginx/nginx.conf")
    if nginx.exists():
        # Copy all included files into a validation-only tree. Follow distro
        # sites-enabled links for reads, but never alter the live tree or publish
        # rewritten staging paths. Omit exactly the links the transaction removes.
        tree = stage / "nginx-validation"
        source = logical_path(root, "/etc/nginx")
        excluded = set(remove_symlinks or {})
        if source.exists():
            def ignore(folder, names):
                relative = Path(folder).relative_to(source)
                return [name for name in names if "/etc/nginx/" + (relative / name).as_posix() in excluded]
            shutil.copytree(source, tree, ignore=ignore)
        else:
            tree.mkdir()
        for file in (stage / "etc/nginx").rglob("*"):
            if file.is_file():
                target = tree / file.relative_to(stage / "etc/nginx")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(file, target)
        for conf in tree.rglob("*"):
            if not conf.is_file() or conf.suffix == ".so":
                continue
            content = conf.read_text()
            content = content.replace("/etc/nginx/", str(tree) + "/")
            for path in re.findall(r"/(?:etc|var|opt)/[^\s;]+", content):
                candidate = stage / path.lstrip("/")
                if candidate.is_file():
                    content = content.replace(path, str(candidate))
            atomic(conf, content.encode(), 0o600)
        # Keep the compiled prefix: distro module loaders commonly use a
        # relative modules/*.so path. Candidate includes are already absolute.
        run(["nginx", "-t", "-c", tree / "nginx.conf"])
    cores = [("/etc/sing-box/sb/config.json", "/opt/sb/bin/sing-box")]
    legacy = logical_path(stage, "/etc/systemd/system/sb-sing-box-legacy.service")
    if not legacy.exists():
        legacy = logical_path(root, "/etc/systemd/system/sb-sing-box-legacy.service")
    if legacy.exists():
        match = re.search(r"^ExecStart=(/opt/sb/legacy/[A-Za-z0-9_-]+/sing-box) ", legacy.read_text(), re.M)
        if not match:
            raise ValueError("Unexpected legacy core service entrypoint")
        cores.append(("/etc/sing-box/sb-legacy/config.json", match[1]))
    for config_path, binary_path in cores:
        core = logical_path(stage, config_path)
        if not core.exists():
            core = logical_path(root, config_path)
        if not core.exists():
            continue
        config = json.loads(core.read_bytes())
        def remap(obj):
            if isinstance(obj, dict):
                return {k: remap(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [remap(v) for v in obj]
            if isinstance(obj, str) and obj.startswith("/") and (stage / obj.lstrip("/")).is_file():
                return str(stage / obj.lstrip("/"))
            return obj
        check = stage / ("sing-box-check-" + str(len(config_path)) + ".json")
        atomic(check, json.dumps(remap(config)).encode())
        binary = logical_path(stage, binary_path)
        if not binary.exists():
            binary = logical_path(root, binary_path)
        run([binary, "check", "-c", check])
    validate_subscription_candidate(stage, root=root, snapshot_dir=snapshot_dir)


def validate_subscription_candidate(stage, *, root=Path("/"), snapshot_dir=None):
    """Validate the client artifact without requiring unrelated proxy services."""
    require_linux_root()
    stage = Path(stage)
    from .server import load_bundle
    runtime = logical_path(stage, "/var/lib/sb/subscription/runtime.json")
    if runtime.exists():
        load_bundle(runtime)
    client = logical_path(stage, "/var/lib/sb/subscription/clash.yaml")
    if client.exists():
        import yaml
        value = yaml.safe_load(client.read_bytes())
        if value.get("rule-providers"):
            if snapshot_dir is None:
                raise ValueError("Offline rule snapshot is required for candidate validation")
            from . import rules
            directory = Path(snapshot_dir)
            manifest, inline = rules.load(directory.parent, directory.name)
            state_file = logical_path(stage, "/etc/sb/state.json")
            override = json.loads(state_file.read_bytes()).get("subscription", {}).get("template", {}) if state_file.exists() else None
            rules.validate_assembly(value, manifest, inline, override=override)
            value = rules.assemble(value, manifest, inline, local_dir=directory, override=override)
        check = stage / "mihomo-check.yaml"
        atomic(check, yaml.safe_dump(value, allow_unicode=True, sort_keys=False).encode())
        mihomo = logical_path(stage, "/opt/sb/bin/mihomo")
        if not mihomo.exists():
            mihomo = logical_path(root, "/opt/sb/bin/mihomo")
        environment = dict(os.environ, SKIP_SAFE_PATH_CHECK="false")
        environment["SAFE_PATHS"] = str(Path(snapshot_dir).resolve()) if snapshot_dir else ""
        run([mihomo, "-t", "-d", stage / "mihomo", "-f", check], timeout=90, env=environment)


def permissions():
    require_linux_root()
    import grp
    for name, mode in (("/var/lib/sb", 0o711), ("/opt/sb", 0o755), ("/opt/sb/bin", 0o755),
                       ("/opt/sb/legacy", 0o755)):
        path = Path(name)
        if path.exists():
            if path.is_symlink():
                raise ValueError("Unexpected symlink in a managed parent directory")
            os.chmod(path, mode)
    core_parent = Path("/etc/sing-box")
    if core_parent.exists():
        if core_parent.is_symlink():
            raise ValueError("Core parent cannot be a symlink")
        os.chown(core_parent, 0, grp.getgrnam("sb-core").gr_gid)
        os.chmod(core_parent, 0o710)
    runtime = Path("/opt/sb/current")
    if runtime.exists():
        for child in [runtime, *runtime.rglob("*")]:
            if child.is_symlink():
                raise ValueError("Runtime files cannot be symlinks")
            os.chown(child, 0, 0)
            os.chmod(child, 0o755 if child.is_dir() else 0o644)
    legacy = Path("/opt/sb/legacy")
    if legacy.exists():
        for child in legacy.iterdir():
            if child.is_symlink() or not child.is_dir():
                raise ValueError("Unexpected legacy binary directory")
            os.chmod(child, 0o755)
    for group, roots in (("sb-core", ("/etc/sb/certificates", "/etc/sing-box/sb", "/etc/sing-box/sb-legacy")),
                         ("sb-subscription", ("/var/lib/sb/subscription",))):
        gid = grp.getgrnam(group).gr_gid
        for folder in roots:
            path = Path(folder)
            if path.exists():
                os.chown(path, 0, gid)
                os.chmod(path, 0o750)
                for child in path.rglob("*"):
                    if child.is_symlink():
                        raise ValueError("Unexpected symlink in protected service directory")
                    os.chown(child, 0, gid)
                    os.chmod(child, 0o750 if child.is_dir() else 0o640)
    # Each service needs traversal but not enumeration of /etc/sb.
    os.chmod("/etc/sb", 0o711)


def activate(state, record=None):
    require_linux_root()
    permissions()
    site = logical_path(Path("/"), state["site"]["root"])
    if not (record or {}).get("directories", {}).get("/var/www", {}).get("existed", True):
        os.chmod("/var/www", 0o755)
    for directory in [site, *[p for p in site.parents if p != Path("/var/www") and p.is_relative_to("/var/www")]]:
        if directory.exists():
            os.chmod(directory, 0o755)
    switches = state.get("legacy", {}).get("switch", {})
    for name in switches.get("stop_services", []):
        run(["systemctl", "stop", name])
        run(["systemctl", "disable", name])
    run(["systemctl", "daemon-reload"])
    changed = (record or {}).get("changed", [])
    def needs_restart(name):
        if record is None or not record.get("services", {}).get(name, {}).get("is-active"):
            return True
        if name == "sb-subscription":
            return any(p.startswith("/opt/sb/current/") or p.endswith("/sb-subscription.service") for p in changed)
        if name == "sb-sing-box":
            return any(p.startswith(("/etc/sing-box/sb/", "/etc/sb/certificates/", "/opt/sb/bin/")) or p.endswith("/sb-sing-box.service") for p in changed)
        return any(p.startswith(("/etc/sing-box/sb-legacy/", "/etc/sb/certificates/")) for p in changed)
    starts = list(dict.fromkeys(switches.get("start_services", []) + state.get("legacy", {}).get("services", []) + ["sb-sing-box", "sb-subscription"]))
    for name in starts:
        run(["systemctl", "enable", name])
        if needs_restart(name):
            run(["systemctl", "restart", name])
        elif name == "sb-subscription" and "/var/lib/sb/subscription/runtime.json" in changed:
            run(["systemctl", "reload", name])
    run(["nginx", "-t"])
    active = subprocess.run(["systemctl", "is-active", "--quiet", "nginx"], capture_output=True).returncode == 0
    run(["systemctl", "reload" if active else "start", "nginx"])
    run(["systemctl", "enable", "nginx", "certbot.timer", "sb-cert-sync.timer"])
    run(["systemctl", "start", "certbot.timer", "sb-cert-sync.timer"])
    run(["systemctl", "enable" if state["rules"].get("enabled") else "disable", "sb-rules.timer"])
    run(["systemctl", "start" if state["rules"].get("enabled") else "stop", "sb-rules.timer"])


def activate_subscription(state, record):
    """Publish content without restarting, repairing or probing proxy services."""
    require_linux_root()
    import grp
    directory = logical_path(Path('/'), '/var/lib/sb/subscription')
    gid = grp.getgrnam('sb-subscription').gr_gid
    for path in [directory, *directory.rglob('*')]:
        if path.is_symlink():
            raise ValueError('Unexpected symlink in subscription directory')
        os.chown(path, 0, gid)
        os.chmod(path, 0o750 if path.is_dir() else 0o640)
    active = record.get('services', {}).get('sb-subscription', {}).get('is-active')
    if not active:
        run(['systemctl', 'start', 'sb-subscription'])
    elif '/var/lib/sb/subscription/runtime.json' in record.get('changed', []):
        run(['systemctl', 'reload', 'sb-subscription'])


def subscription_health(state, secret, *, expected_generation=None, root=Path("/")):
    if expected_generation is None:
        from .server import load_bundle
        expected_generation = load_bundle(logical_path(root, "/var/lib/sb/subscription/runtime.json"))["generation"]
    if not isinstance(expected_generation, str) or not re.fullmatch(r"[a-f0-9]{64}", expected_generation):
        raise ValueError("Invalid expected subscription generation")
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f'http://127.0.0.1:{state["ports"]["sub_http"]}/healthz', timeout=2) as r:
                body = r.read(4097)
                status = json.loads(body) if len(body) <= 4096 else None
                if (r.status == 200 and isinstance(status, dict) and status.get("ok") is True
                        and status.get("generation") == expected_generation):
                    break
        except (OSError, ValueError):
            pass
        time.sleep(.25)
    else:
        raise RuntimeError("Subscription readiness generation does not match the candidate")
    domain = state["domains"]["subscription"]
    url = f'https://{domain}/{state["subscription"]["prefix"]}/{secret["subscription_token"]}'
    # URL in stdin, not process listing; curl output discarded and errors redacted.
    config = f'url = "{url}"\nresolve = "{domain}:443:127.0.0.1"\n'
    run(["curl", "--fail", "--silent", "--show-error", "--max-time", "10", "--config", "-", "--output", "/dev/null"],
        input=config.encode())


def health(state, secret, *, expected_generation=None, subscription_only=False, root=Path("/")):
    services = (["nginx", "sb-subscription"] if subscription_only else
                ["nginx", "sb-sing-box", "sb-subscription", *state.get("legacy", {}).get("services", [])])
    for name in services:
        run(["systemctl", "is-active", "--quiet", name])
    subscription_health(state, secret, expected_generation=expected_generation, root=root)
    if subscription_only:
        return
    site = state["domains"]["site"]
    run(["curl", "--fail", "--silent", "--http2", "--max-time", "10", "--resolve", f"{site}:443:127.0.0.1",
         f"https://{site}/", "--output", "/dev/null"])
    from .probe import local_nodes
    local_nodes(state, secret)


def network_preflight(state, *, public_addresses=(), new_install=True):
    import ipaddress
    local = set(public_addresses)
    for link in json.loads(run(["ip", "-json", "addr", "show"])):
        for item in link.get("addr_info", []):
            if item.get("scope") == "global":
                local.add(item["local"])
    if not local:
        raise RuntimeError("No public interface address found; supply --public-address for NAT hosts")
    for name in (state["domains"]["site"], state["domains"]["subscription"]):
        addresses = {a[4][0] for a in socket.getaddrinfo(name, 443, type=socket.SOCK_STREAM)}
        if not addresses or not addresses <= local:
            raise RuntimeError(f"DNS for {name} does not exclusively point to this host; check A/AAAA and disable CDN proxying")
        if any(not ipaddress.ip_address(a).is_global for a in addresses):
            raise RuntimeError("Public certificates require a publicly reachable origin")
    if new_install:
        if run(["ss", "-H", "-ltn", "( sport = :80 or sport = :443 )"]).strip():
            raise RuntimeError("TCP 80/443 already occupied; run sb migrate inspect")
        if run(["ss", "-H", "-lun", "sport = :443"]).strip():
            raise RuntimeError("UDP 443 already occupied; run sb migrate inspect")


def occupied_ports():
    used = set()
    for line in (run(["ss", "-H", "-ltn"]) + "\n" + run(["ss", "-H", "-lun"])).splitlines():
        fields = line.split()
        if len(fields) >= 4:
            try:
                used.add(int(fields[3].rsplit(":", 1)[1]))
            except ValueError:
                pass
    return used


def allocate_ports(state):
    used = occupied_ports()
    reserved = set(state["ports"].values())
    for entry in state.get("legacy", {}).get("entries", []):
        if entry.get("upstream", "").startswith("127.0.0.1:"):
            reserved.add(int(entry["upstream"].rsplit(":", 1)[1]))
    for listener in state.get("legacy", {}).get("listeners", {}).values():
        if listener.get("listen_port"):
            reserved.add(listener["listen_port"])
    for key in ("reality", "site_tls", "sub_tls", "sub_http"):
        if state["ports"][key] in used:
            state["ports"][key] = next((p for p in range(20000, 30000) if p not in used | reserved), None)
            if state["ports"][key] is None:
                raise RuntimeError("No available internal TCP port")
            reserved.add(state["ports"][key])
