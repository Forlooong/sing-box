"""Stage and validate immutable four-source rule releases without activation.

Only the root manager's transaction may write the returned active pointer. The
HTTP daemon does not import this module or download anything. Candidate hashes
provide integrity, not an independent signature: GitHub/repository trust remains.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import urllib.request

import yaml

from .vendor import snapshot

REPO = snapshot.REPO
CANDIDATE = REPO + "release/candidate.json"
CANDIDATE_V2 = REPO + "release/candidate-v2.json"
LOGICAL_CACHE = "/var/lib/sb/rules"


def _channel(value):
    if not isinstance(value, str) or value not in {"v1", "v2"}:
        raise ValueError("Unsupported rule channel; choose v1 or v2")
    return value


def _check_channel(manifest, channel):
    expected = 1 if _channel(channel) == "v1" else 2
    if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != expected:
        raise ValueError("Rule snapshot does not match the selected channel")
    if channel == "v2" and manifest.get("policy_version") != "balanced-v2":
        raise ValueError("Unsupported v2 rule policy")


def _manifest(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid rule manifest")
    try:
        snapshot.validate_manifest(value)
    except (AttributeError, TypeError, KeyError):
        raise ValueError("Invalid rule manifest structure") from None
    if not isinstance(value.get("sources"), dict) or set(value["sources"]) != {"loyal", "acl", "meta", "personal"}:
        raise ValueError("Rule manifest must account for all four sources")
    if not isinstance(value.get("created_at"), int) or isinstance(value["created_at"], bool) or value["created_at"] <= 0:
        raise ValueError("Rule manifest requires its build timestamp")
    return value


def _tag(value):
    if not isinstance(value, str) or not snapshot.TAG.fullmatch(value):
        raise ValueError("Unsafe rule build ID")
    return value


def _directory(cache_dir, tag):
    cache = Path(cache_dir).resolve()
    directory = cache / _tag(tag)
    if directory.is_symlink() or directory.resolve().parent != cache:
        raise ValueError("Rule snapshot cannot be a symlink")
    return directory


def _json(path, maximum=2 * 1024 * 1024):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Rule state cannot be a symlink")
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Rule metadata too large")
    return json.loads(data)


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith(REPO):
            raise ValueError("Unexpected rule download redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, maximum, deadline):
    if not url.startswith(REPO):
        raise ValueError("Unapproved rule source")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Rule download batch timed out")
    opener = urllib.request.build_opener(_Redirect())
    with opener.open(urllib.request.Request(url, headers={"User-Agent": "Forlooong-sb-manager"}), timeout=min(10, remaining)) as response:
        if not response.geturl().startswith(REPO):
            raise ValueError("Unexpected rule source")
        data = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Rule download batch timed out")
            chunk = response.read(min(65536, maximum + 1 - len(data)))
            if not chunk:
                return bytes(data)
            data.extend(chunk)
            if len(data) > maximum:
                raise ValueError("Rule download exceeds declared size")


def verify(cache_dir, build_id):
    directory = _directory(cache_dir, build_id)
    manifest = _manifest(_json(directory / "build-manifest.json"))
    if manifest["build_id"] != build_id:
        raise ValueError("Rule snapshot identity mismatch")
    for rel in manifest["files"]:
        target = directory / rel
        if target.is_symlink() or any(parent.is_symlink() for parent in target.parents if parent != directory.parent):
            raise ValueError("Rule snapshot contains a symlink")
    for rel, expected in manifest["files"].items():
        with (directory / rel).open("rb") as stream:
            data = stream.read(expected["size"] + 1)
        if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("Rule artifact checksum or size mismatch")
    snapshot.validate_inline(manifest, _json(directory / "inline-rules.json", 16 * 1024 * 1024))
    return manifest


def load(cache_dir, build_id=None, *, channel=None):
    if build_id is None:
        build_id = _json(Path(cache_dir) / "active.json", 4096)["build_id"]
    manifest = verify(cache_dir, _tag(build_id))
    if channel is not None:
        _check_channel(manifest, channel)
    inline = _json(_directory(cache_dir, build_id) / "inline-rules.json", 16 * 1024 * 1024)
    return manifest, snapshot.validate_inline(manifest, inline)


def stage(cache_dir, channel="v1"):
    """Fetch only a changed candidate; never modify active.json, even on failure."""
    channel = _channel(channel)
    cache = Path(cache_dir)
    cache.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 120
    candidate = json.loads(download(CANDIDATE if channel == "v1" else CANDIDATE_V2, 4096, deadline))
    if not isinstance(candidate, dict):
        raise ValueError("Invalid rule candidate schema")
    _check_channel(candidate, channel)
    tag = _tag(candidate.get("build_id"))
    checksum = candidate.get("manifest_sha256")
    if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
        raise ValueError("Invalid rule candidate checksum")
    final = _directory(cache, tag)
    if final.exists():
        raw = (final / "build-manifest.json").read_bytes()
        if hashlib.sha256(raw).hexdigest() != checksum:
            raise ValueError("Immutable rule tag has changed; refusing replacement")
        _check_channel(verify(cache, tag), channel)
    else:
        raw = download(REPO + tag + "/build-manifest.json", 2 * 1024 * 1024, deadline)
        if hashlib.sha256(raw).hexdigest() != checksum:
            raise ValueError("Rule manifest checksum mismatch")
        manifest = _manifest(json.loads(raw))
        _check_channel(manifest, channel)
        if manifest["build_id"] != tag:
            raise ValueError("Rule candidate identity mismatch")
        previous = load(cache)[0] if (cache / "active.json").exists() else None
        temporary = Path(tempfile.mkdtemp(prefix=".stage-", dir=cache))
        try:
            (temporary / "build-manifest.json").write_bytes(raw)
            for rel, expected in manifest["files"].items():
                # The v2 inline file includes the DNS domain index. Comparing it
                # to the v1 layout would reject a legitimate first migration.
                old = previous["files"].get(rel) if previous and previous["schema_version"] == manifest["schema_version"] else None
                if old and expected["size"] > old["size"] * 2:
                    raise ValueError("Rule artifact size more than doubled; review upstream build")
                data = download(REPO + tag + "/" + rel, expected["size"], deadline)
                if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
                    raise ValueError("Rule artifact checksum mismatch")
                target = temporary / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
            snapshot.verify(temporary, manifest)
            os.replace(temporary, final)
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)
    snapshot.atomic(cache / "staged.json", {"build_id": tag, "manifest_sha256": checksum, "channel": channel})
    prune(cache)
    return tag


def assemble(document, manifest, inline, local_dir=None, *, override=None):
    """Compile routing and the v2 DNS policy, preserving unrelated client settings."""
    assembled = snapshot.assemble(copy.deepcopy(document), manifest, inline, local_dir)
    result = copy.deepcopy(document)
    result["rule-providers"] = assembled["rule-providers"]
    result["rules"] = assembled["rules"]
    if manifest.get("schema_version") == 2:
        from .vendor.dns import assemble_dns
        result = assemble_dns(result, manifest, inline, override=override)
    return result


def validate_assembly(document, manifest, inline, *, override=None):
    """Reject drift, including DNS policy order which plain dict equality ignores."""
    expected = assemble(document, manifest, inline, override=override)
    if document.get("rule-providers") != expected["rule-providers"] or document.get("rules") != expected["rules"]:
        raise ValueError("Generated configuration does not match the staged rule snapshot")
    if manifest.get("schema_version") == 2:
        actual_dns, expected_dns = document.get("dns", {}), expected.get("dns", {})
        actual_policy, expected_policy = actual_dns.get("nameserver-policy", {}), expected_dns.get("nameserver-policy", {})
        if actual_dns != expected_dns or list(actual_policy.items()) != list(expected_policy.items()):
            raise ValueError("Generated DNS configuration does not match the staged v2 policy")
    return expected


def validate(cache_dir, build_id, config_bytes, mihomo_path, *, override=None):
    """Validate the exact generated full client config using local verified MRS."""
    manifest, inline = load(cache_dir, build_id)
    document = yaml.safe_load(config_bytes)
    if not isinstance(document, dict) or len(document.get("proxy-groups", [])) != 1 or document["proxy-groups"][0].get("name") != "节点选择":
        raise ValueError("Validation requires the complete single-group subscription")
    validate_assembly(document, manifest, inline, override=override)
    local = assemble(document, manifest, inline, local_dir=_directory(cache_dir, build_id), override=override)
    with tempfile.TemporaryDirectory(prefix=".validate-", dir=cache_dir) as temporary:
        directory = Path(temporary)
        config = directory / "config.yaml"
        config.write_text(yaml.safe_dump(local, allow_unicode=True, sort_keys=False), encoding="utf-8")
        os.chmod(config, 0o600)
        environment = dict(os.environ, SAFE_PATHS=str(_directory(cache_dir, build_id)), SKIP_SAFE_PATH_CHECK="false")
        try:
            # -t parses configuration, but is not a substitute for decoding each
            # MRS payload. The core's MRS reader verifies behavior/header/data;
            # discard its text output, never rebuild or replace the snapshot.
            for provider in manifest["providers"].values():
                decoded = subprocess.run([str(mihomo_path), "convert-ruleset", provider["behavior"], "mrs",
                                          str(_directory(cache_dir, build_id) / provider["path"]), os.devnull],
                                         capture_output=True, timeout=30, check=False, env=environment)
                if decoded.returncode:
                    raise ValueError("Mihomo rejected a candidate MRS payload; active rules retained")
            result = subprocess.run([str(mihomo_path), "-t", "-d", str(directory), "-f", str(config)], capture_output=True, timeout=60, check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError("Mihomo validation could not complete; active rules retained") from None
        if result.returncode:
            # Core diagnostics may contain credentials. Never echo them.
            raise ValueError("Mihomo rejected the full candidate subscription; active rules retained")
    raw = (_directory(cache_dir, build_id) / "build-manifest.json").read_bytes()
    return {"schema_version": 1, "build_id": build_id, "manifest_sha256": hashlib.sha256(raw).hexdigest(),
            "config_sha256": hashlib.sha256(config_bytes).hexdigest(), "validated_at": int(time.time()),
            "rules_schema_version": manifest["schema_version"], "policy_version": manifest.get("policy_version")}


def activation_artifacts(cache_dir, build_id, validation, config_bytes=None):
    manifest = verify(cache_dir, build_id)
    checksum = hashlib.sha256((_directory(cache_dir, build_id) / "build-manifest.json").read_bytes()).hexdigest()
    if not isinstance(validation, dict) or validation.get("schema_version") != 1 or validation.get("build_id") != build_id or validation.get("manifest_sha256") != checksum or not re.fullmatch(r"[0-9a-f]{64}", validation.get("config_sha256", "")):
        raise ValueError("Rule activation requires a matching successful validation receipt")
    if config_bytes is not None and validation["config_sha256"] != hashlib.sha256(config_bytes).hexdigest():
        raise ValueError("Subscription changed after rule validation")
    if manifest.get("schema_version") == 2 and (
            validation.get("rules_schema_version") != 2 or validation.get("policy_version") != manifest.get("policy_version")):
        raise ValueError("Rule activation requires a matching v2 policy validation receipt")
    data = (json.dumps(validation, sort_keys=True) + "\n").encode()
    return {LOGICAL_CACHE + "/active.json": data, LOGICAL_CACHE + "/validation.json": data}


def prune(cache_dir):
    """Keep active/staged, rollback references, newest five, and snapshots under 30 days."""
    cache = Path(cache_dir).resolve()
    protected = {_tag(_json(path, 4096)["build_id"]) for path in (cache / "active.json", cache / "staged.json") if path.exists()}
    # A policy migration must remain reversible even when the previous v1 build
    # is old. Retain snapshots referenced by transactions that can still restore
    # configuration; never infer a management root from an arbitrary cache path.
    if cache.parts[-4:] == ("var", "lib", "sb", "rules"):
        transactions = cache.parents[3] / "var/backups/sb/transactions"
        for journal in transactions.glob("*/journal.json"):
            try:
                if _json(journal).get("status") not in {"committed", "applying", "rolling-back"}:
                    continue
                saved = _json(journal.parent / "before/etc/sb/state.json")
                tag = saved.get("rules", {}).get("active_build")
                if tag:
                    protected.add(_tag(tag))
            except (OSError, ValueError, TypeError, KeyError):
                continue
    snapshots = []
    for path in cache.iterdir():
        if path.is_symlink() or not path.is_dir() or not snapshot.TAG.fullmatch(path.name):
            continue
        try:
            manifest = _json(path / "build-manifest.json")
            created = manifest.get("created_at")
            if manifest["build_id"] == path.name and isinstance(created, int) and not isinstance(created, bool):
                snapshots.append((created, path))
        except (OSError, ValueError, KeyError, TypeError):
            continue
    snapshots.sort(key=lambda row: row[0], reverse=True)
    protected.update(path.name for _, path in snapshots[:5])
    for created, path in snapshots:
        if path.name not in protected and created < time.time() - 30 * 86400 and path.resolve().parent == cache:
            shutil.rmtree(path)
