"""Prepare candidate artifacts and publish the independent recovery entry.

Invoked by the existing manager with a protected output directory. Runtime
schema changes must be explicitly implemented here by their release author.
Proxy configuration and runtime changes remain inside the later transaction.
"""
import argparse
import json
from pathlib import Path
import platform

from . import cli, state, updates
from .bootstrap import runtime_files
from .transaction import atomic


def prepare(root, destination, source):
    saved, secret = state.load(root)
    snapshot = cli.snapshot_for(root, saved)
    files = cli.compile_files(root, saved, secret, snapshot)
    files.update(runtime_files(source))
    versions = json.loads((source / "versions.json").read_bytes())
    arch = "arm64" if platform.machine() in {"arm64", "aarch64"} else "amd64"
    for name in ("sing-box", "mihomo"):
        files["/opt/sb/bin/" + name] = updates.binary(versions["assets"][name + "-" + arch])
    if snapshot:
        from . import rules
        binary = destination / "candidate-mihomo"
        atomic(binary, files["/opt/sb/bin/mihomo"], 0o700)
        cache = state.logical_path(root, "/var/lib/sb/rules")
        build = snapshot[0]["build_id"]
        config = files["/var/lib/sb/subscription/clash.yaml"]
        receipt = rules.validate(cache, build, config, binary,
                                 override=saved["subscription"].get("template", {}))
        files.update(rules.activation_artifacts(cache, build, receipt, config))
        binary.unlink()
    for name, data in files.items():
        atomic(state.logical_path(destination, name), data)
    # This also protects the first update initiated by a legacy manager whose
    # Transaction still replaces runtime modules one by one. Publish the safe
    # entry only after candidate compilation/download/validation has succeeded.
    from . import recovery
    recovery.install(root, files, update_launcher=True)
    atomic(destination / "files.json", state.encode(sorted(files)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.root, args.output, Path(__file__).resolve().parent.parent)
