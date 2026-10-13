"""Pinned release downloads with transport verification and safe extraction."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import subprocess
import tempfile
import os
import urllib.request

REPOSITORY = "Forlooong/sing-box"
RELEASE = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?\Z")


def fetch(url, maximum=100 * 1024 * 1024):
    if not url.startswith("https://github.com/"):
        raise ValueError("Release download must originate from GitHub HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": "Forlooong-sb-manager"})
    with urllib.request.urlopen(request, timeout=60) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("Release redirect downgraded TLS")
        data = response.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("Release exceeds download limit")
        return data


def verify(data, expected):
    if not re.fullmatch(r"[a-f0-9]{64}", expected) or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError("Release checksum mismatch")


def binary(asset, fetcher=fetch):
    data = fetcher(asset["url"])
    verify(data, asset["sha256"])
    if asset["format"] == "gz":
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as source:
            value = source.read(200 * 1024 * 1024 + 1)
    else:
        value = None
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
            total = 0
            for count, entry in enumerate(archive):
                total += entry.size
                if count > 1000 or total > 300 * 1024 * 1024:
                    raise ValueError("Oversized binary archive")
                if PurePosixPath(entry.name).name == asset["binary"]:
                    if value is not None or not entry.isfile() or entry.size > 200 * 1024 * 1024:
                        raise ValueError("Invalid binary archive")
                    value = archive.extractfile(entry).read()
        if value is None:
            raise ValueError("Binary missing from archive")
    if len(value) > 200 * 1024 * 1024 or not value.startswith(b"\x7fELF"):
        raise ValueError("Expected bounded Linux ELF executable")
    return value


def release(version, fetcher=fetch):
    if not RELEASE.fullmatch(version):
        raise ValueError("Specify an explicit published version, e.g. v2.0.0")
    base = f"https://github.com/{REPOSITORY}/releases/download/{version}/"
    sums = fetcher(base + "SHA256SUMS", 8192).decode("ascii")
    pairs = dict((name.lstrip("*"), digest) for digest, name in
                 (line.split(None, 1) for line in sums.splitlines() if line.strip()))
    if "code.tar.gz" not in pairs:
        raise ValueError("Release checksum file is incomplete")
    data = fetcher(base + "code.tar.gz")
    verify(data, pairs["code.tar.gz"])
    files = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
        total = 0
        for count, item in enumerate(archive):
            if count > 10000:
                raise ValueError("Too many release archive entries")
            path = PurePosixPath(item.name.removeprefix("./"))
            if path.is_absolute() or ".." in path.parts or "\\" in item.name:
                raise ValueError("Unsafe release archive path")
            if item.isdir():
                continue
            if not item.isfile() or item.size > 20 * 1024 * 1024:
                raise ValueError("Unsupported release entry")
            total += item.size
            if total > 100 * 1024 * 1024 or str(path) in files:
                raise ValueError("Oversized or duplicate release entries")
            files[str(path)] = archive.extractfile(item).read()
    required = {"sbmanager/cli.py", "sbmanager/upgrade.py", "versions.json", "sing-box.sh", "LICENSE"}
    if not required <= files.keys():
        raise ValueError("Not a managed Forlooong release")
    if json.loads(files["versions.json"])["repository"] != REPOSITORY:
        raise ValueError("Release repository identity mismatch")
    return files


def prepare(version, root=Path("/")):
    """Render with the reviewed candidate package before swapping any live code."""
    package = release(version)
    from .state import logical_path
    from .transaction import atomic
    base = logical_path(root, "/var/lib/sb/update-staging")
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    with tempfile.TemporaryDirectory(prefix="candidate-", dir=base) as name:
        directory = Path(name)
        source, output = directory / "package", directory / "output"
        for relative, content in package.items():
            target = logical_path(source, "/" + relative)
            atomic(target, content, 0o644)
        env = dict(os.environ, PYTHONPATH=str(source), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run(["/usr/bin/python3", "-m", "sbmanager.upgrade", "--root", str(root),
                                 "--output", str(output)], cwd=source, env=env, capture_output=True, timeout=600)
        if result.returncode:
            raise ValueError("Candidate release could not prepare this installation; existing version retained")
        names = json.loads((output / "files.json").read_bytes())
        if not isinstance(names, list) or len(names) > 1000 or len(set(names)) != len(names):
            raise ValueError("Invalid upgrade artifact inventory")
        allowed = ("/etc/sb/", "/etc/sing-box/sb/", "/etc/nginx/sb/", "/etc/systemd/system/sb-",
                   "/opt/sb/current/", "/opt/sb/bin/", "/var/lib/sb/subscription/", "/var/www/")
        exact = {"/etc/nginx/nginx.conf", "/usr/local/bin/sb", "/etc/letsencrypt/renewal-hooks/deploy/50-sb",
                 "/var/lib/sb/rules/active.json", "/var/lib/sb/rules/validation.json"}
        files = {}
        for path in names:
            if path == "/etc/sb/revoked-tokens.json" or not (path in exact or path.startswith(allowed)):
                raise ValueError("Upgrade attempted an unrelated filesystem mutation")
            target = logical_path(output, path)
            if target.stat().st_size > 200 * 1024 * 1024:
                raise ValueError("Upgrade artifact exceeds size limit")
            files[path] = target.read_bytes()
        return files
