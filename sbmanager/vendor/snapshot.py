"""Public, credential-free rule snapshot reader and subscription assembler."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
import urllib.request

REPO = "https://raw.githubusercontent.com/Forlooong/clash-rules-mrs/"
BASE = "reject icloud apple google proxy direct private gfw greatfire tld-not-cn telegramcidr cncidr lancidr".split()
SECTIONS = ("personal_direct", "personal_proxy", "private", "reject", "applications",
            "services", "proxy", "direct")
PROVIDERS = {n: ("loyalsoldier/" + n + ".mrs", "ipcidr" if n.endswith("cidr") else "domain") for n in BASE}
PROVIDERS.update({"acl-unban-domain": ("acl4ssr/unban-domain.mrs", "domain"),
                  "acl-direct-ipcidr": ("acl4ssr/direct-ipcidr.mrs", "ipcidr"),
                  "services-proxy": ("services/services-proxy.mrs", "domain")})
for direction in ("direct", "proxy"):
    for behavior in ("domain", "ipcidr"):
        n = "personal-" + direction + "-" + behavior
        PROVIDERS[n] = ("personal/" + n + ".mrs", behavior)
META_FILES = {"inline-rules.json", "build-report.json", "cidr-report.json",
              "conflict-report.json", "sources.json", "licenses/NOTICE.md", "licenses/acl-LICENSE",
              "licenses/acl-README.md", "licenses/loyal-README.md", "licenses/meta-README.md",
              "licenses/loyal-LICENSE", "licenses/meta-LICENSE", "source-archive.tar.gz"}
TAG = re.compile(r"rules-[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")
ALLOWED = {"DOMAIN-KEYWORD", "DOMAIN-REGEX", "PROCESS-NAME", "PROCESS-PATH",
           "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX", "DST-PORT", "SRC-PORT",
           "NETWORK", "SRC-IP-CIDR", "SRC-IP-CIDR6", "UID", "IP-ASN", "IP-CIDR", "IP-CIDR6"}

def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))

def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".atomic-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(value, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def validate_manifest(m):
    if m.get("schema_version") != 1 or not TAG.fullmatch(m.get("build_id", "")) or m.get("tag") != m["build_id"]:
        raise ValueError("Invalid snapshot identity")
    if m.get("fake_ip_pool") != "198.18.0.0/16":
        raise ValueError("Incompatible Fake-IP pool")
    providers = m.get("providers", {})
    required = set(BASE) | {"acl-unban-domain", "services-proxy"}
    if not required <= set(providers) <= set(PROVIDERS):
        raise ValueError("Incomplete/unexpected MRS providers")
    for name, provider in providers.items():
        rel, behavior = PROVIDERS[name]
        if provider != {"path": rel, "behavior": behavior, "format": "mrs"}:
            raise ValueError("Invalid provider schema: " + name)
    allowed = {p[0] for p in PROVIDERS.values()} | META_FILES
    files = m.get("files", {})
    if not {p["path"] for p in providers.values()} | {"inline-rules.json"} <= set(files):
        raise ValueError("Missing registered file")
    if not set(files) <= allowed:
        raise ValueError("Unsafe/unexpected artifact path")
    for rel, data in files.items():
        if not isinstance(data.get("size"), int) or isinstance(data["size"], bool) or not 0 < data["size"] <= 64 * 1024 * 1024:
            raise ValueError("Bad file size: " + rel)
        if not re.fullmatch("[a-f0-9]{64}", data.get("sha256", "")):
            raise ValueError("Bad checksum")
    if sum(x["size"] for x in files.values()) > 256 * 1024 * 1024:
        raise ValueError("Snapshot too large")
    return m

def validate_inline(m, inline):
    if inline.get("schema_version") != 1 or inline.get("build_id") != m["build_id"]:
        raise ValueError("Inline rules from another build")
    sections = inline.get("sections", {})
    if set(sections) != set(SECTIONS):
        raise ValueError("Unknown/missing inline section")
    for name, rules in sections.items():
        if not isinstance(rules, list) or len(rules) > 10000:
            raise ValueError("Invalid inline list")
        for rule in rules:
            if not isinstance(rule, str) or len(rule) > 8192 or "\n" in rule or "\r" in rule:
                raise ValueError("Invalid inline rule")
            kind, sep, value = rule.partition(",")
            if not sep or kind not in ALLOWED or not value:
                raise ValueError("Invalid inline predicate")
            if kind in ("IP-CIDR", "IP-CIDR6"):
                fields = value.split(",")
                if len(fields) != 2 or fields[1] != "no-resolve":
                    raise ValueError("Inline IP must retain no-resolve")
                net = ipaddress.ip_network(fields[0], strict=True)
                pool = ipaddress.ip_network(m["fake_ip_pool"])
                if net.version == pool.version and net.overlaps(pool):
                    raise ValueError("Inline IP overlaps Fake-IP")
            # Policy is supplied only by assembler, not by upstream entries.
            if kind != "DOMAIN-REGEX" and kind not in ("PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX") and \
                    kind not in ("IP-CIDR", "IP-CIDR6") and "," in value:
                raise ValueError("Unexpected rule fields")
    return inline

def assemble(doc, m, inline, local_dir=None):
    validate_manifest(m)
    validate_inline(m, inline)
    dns = doc.get("dns", {})
    if dns and ipaddress.ip_network(dns.get("fake-ip-range", ""), strict=False) != ipaddress.ip_network(m["fake_ip_pool"]):
        raise ValueError("Template Fake-IP differs from snapshot")
    group = "节点选择"
    providers = {}
    for name, p in m["providers"].items():
        common = {"behavior": p["behavior"], "format": "mrs"}
        if local_dir:
            providers[name] = dict(common, type="file", path=str((Path(local_dir) / p["path"]).resolve()))
        else:
            providers[name] = dict(common, type="http", url=REPO + m["tag"] + "/" + p["path"],
                                   path="./ruleset/forlooong/" + m["build_id"] + "/" + p["path"],
                                   interval=43200, proxy=group)
    rules = ["DOMAIN,localhost,DIRECT", "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
             "IP-CIDR6,::1/128,DIRECT,no-resolve"]
    def provider(name, action):
        if name in providers:
            suffix = ",no-resolve" if m["providers"][name]["behavior"] == "ipcidr" and not name.startswith("personal-") else ""
            rules.append("RULE-SET," + name + "," + action + suffix)
    def section(name, action):
        for rule in inline["sections"][name]:
            if rule.partition(",")[0] in ("IP-CIDR", "IP-CIDR6") and rule.endswith(",no-resolve"):
                rules.append(rule[:-11] + "," + action + ",no-resolve")
            else:
                rules.append(rule + "," + action)
    for direction, action in (("direct", "DIRECT"), ("proxy", group)):
        for behavior in ("domain", "ipcidr"):
            provider("personal-" + direction + "-" + behavior, action)
        section("personal_" + direction, action)
    provider("private", "DIRECT")
    provider("lancidr", "DIRECT")
    section("private", "DIRECT")
    provider("acl-unban-domain", "DIRECT")
    provider("reject", "REJECT")
    section("reject", "REJECT")
    section("applications", "DIRECT")
    provider("icloud", "DIRECT")
    provider("apple", "DIRECT")
    provider("google", group)
    provider("services-proxy", group)
    section("services", group)
    provider("telegramcidr", group)
    provider("proxy", group)
    section("proxy", group)
    provider("direct", "DIRECT")
    section("direct", "DIRECT")
    provider("acl-direct-ipcidr", "DIRECT")
    for name in ("gfw", "greatfire", "tld-not-cn"):
        provider(name, group)
    provider("cncidr", "DIRECT")
    rules.append("MATCH," + group)
    doc["rule-providers"], doc["rules"] = providers, rules
    doc["tun"] = {"enable": False}
    skip = doc.get("sniffer", {}).get("skip-dst-address")
    if skip is not None and "100.64.0.0/10" not in skip:
        skip.append("100.64.0.0/10")
    if dns.get("proxy-server-nameserver-policy") and all(
            v == dns.get("proxy-server-nameserver") for v in dns["proxy-server-nameserver-policy"].values()):
        dns.pop("proxy-server-nameserver-policy")
    return doc

def download(url, maximum, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("Snapshot batch timeout")
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Forlooong-snapshot"}),
                                timeout=min(8, remaining)) as r:
        data = bytearray()
        while True:
            if time.monotonic() >= deadline:
                raise TimeoutError("Snapshot batch timeout")
            chunk = r.read(min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > maximum:
                raise ValueError("Download exceeds size limit")
        return bytes(data)

def verify(directory, m):
    validate_manifest(m)
    for rel, expected in m["files"].items():
        p = Path(directory) / rel
        data = p.read_bytes()
        if len(data) != expected["size"] or hashlib.sha256(data).hexdigest() != expected["sha256"]:
            raise ValueError("Artifact hash/size mismatch: " + rel)
    validate_inline(m, read_json(Path(directory) / "inline-rules.json"))

def load_active(state):
    state = Path(state)
    active = read_json(state / "active.json")
    tag = active["build_id"]
    if not TAG.fullmatch(tag):
        raise ValueError("Unsafe active path")
    directory = state / tag
    m = read_json(directory / "build-manifest.json")
    if m["build_id"] != tag:
        raise ValueError("Active build mismatch")
    # HTTP requests only read two small files. Full verification occurs at refresh.
    inline = read_json(directory / "inline-rules.json")
    validate_manifest(m)
    validate_inline(m, inline)
    return m, inline

def refresh(state, candidate_url=REPO + "release/candidate.json"):
    state = Path(state)
    state.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + 120
    candidate = json.loads(download(candidate_url, 4096, deadline))
    tag = candidate["build_id"]
    if not TAG.fullmatch(tag):
        raise ValueError("Unsafe candidate tag")
    raw = download(REPO + tag + "/build-manifest.json", 2 * 1024 * 1024, deadline)
    if hashlib.sha256(raw).hexdigest() != candidate["manifest_sha256"]:
        raise ValueError("Candidate manifest checksum mismatch")
    m = validate_manifest(json.loads(raw))
    if m["build_id"] != tag:
        raise ValueError("Candidate identity mismatch")
    previous = None
    if (state / "active.json").exists():
        previous, _ = load_active(state)
        if previous["build_id"] == tag:
            return tag
    final = state / tag
    if final.exists():
        if (final / "build-manifest.json").read_bytes() != raw:
            raise ValueError("Cached manifest differs from candidate")
        verify(final, m)
    else:
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=state))
        try:
            (stage / "build-manifest.json").write_bytes(raw)
            for rel, expected in m["files"].items():
                old = previous["files"].get(rel) if previous else None
                if old and expected["size"] > old["size"] * 2:
                    raise ValueError("Artifact size more than doubled")
                target = stage / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(download(REPO + tag + "/" + rel, expected["size"], deadline))
            verify(stage, m)
            os.replace(stage, final)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
    atomic(state / "staged.json", {"build_id": tag})
    if (state / "activation.enabled").exists():
        atomic(state / "active.json", {"build_id": tag})
    prune(state)
    return tag

def prune(state):
    state = Path(state).resolve()
    protected = {read_json(p)["build_id"] for p in (state / "active.json", state / "staged.json") if p.exists()}
    snapshots = []
    for p in state.iterdir():
        if p.is_dir() and TAG.fullmatch(p.name) and p.resolve().parent == state:
            try:
                m = read_json(p / "build-manifest.json")
                if m["build_id"] != p.name or not isinstance(m.get("created_at"), int): continue
                snapshots.append((m["created_at"], p))
            except (OSError, ValueError, KeyError):
                continue
    snapshots.sort(key=lambda x: x[0], reverse=True)
    protected.update(p.name for _, p in snapshots[:5])
    for created, p in snapshots:
        if p.name not in protected and created < time.time() - 30 * 86400:
            shutil.rmtree(p)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("refresh", "activate", "verify", "disable"))
    parser.add_argument("--state", required=True)
    parser.add_argument("--build-id")
    parser.add_argument("--candidate-url", default=REPO + "release/candidate.json")
    args = parser.parse_args()
    state = Path(args.state)
    if args.command == "refresh":
        if args.candidate_url not in {REPO + "release/candidate.json", REPO + "candidates/candidate.json"}:
            raise ValueError("Unapproved candidate source")
        print(refresh(state, args.candidate_url))
    elif args.command == "disable":
        (state / "activation.enabled").unlink(missing_ok=True)
    else:
        tag = args.build_id or read_json(state / "staged.json")["build_id"]
        if not TAG.fullmatch(tag):
            raise ValueError("Unsafe tag")
        m = read_json(state / tag / "build-manifest.json")
        verify(state / tag, m)
        if args.command == "activate":
            atomic(state / "active.json", {"build_id": tag})
            (state / "activation.enabled").touch()
        print(tag)

if __name__ == "__main__":
    main()
