import copy
import hashlib
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from sbmanager import rules
from sbmanager.vendor import snapshot


def fixture(tag="rules-test", created=None):
    inline = {"schema_version": 1, "build_id": tag, "sections": {name: [] for name in snapshot.SECTIONS}}
    providers = {name: {"path": snapshot.PROVIDERS[name][0], "behavior": snapshot.PROVIDERS[name][1], "format": "mrs"}
                 for name in snapshot.BASE + ["acl-unban-domain", "services-proxy"]}
    files = {entry["path"]: b"test-mrs" for entry in providers.values()}
    files["inline-rules.json"] = json.dumps(inline).encode()
    manifest = {"schema_version": 1, "build_id": tag, "tag": tag, "created_at": int(time.time()) if created is None else created,
                "fake_ip_pool": "198.18.0.0/16", "sources": {name: {} for name in ("loyal", "acl", "meta", "personal")},
                "providers": providers, "files": {name: {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()} for name, raw in files.items()}}
    raw = json.dumps(manifest).encode()
    candidate = json.dumps({"schema_version": 1, "build_id": tag, "manifest_sha256": hashlib.sha256(raw).hexdigest()}).encode()

    def download(url, maximum, deadline):
        if url == rules.CANDIDATE:
            return candidate
        if url.endswith("/build-manifest.json"):
            return raw
        return files[url.split(tag + "/", 1)[1]]

    return manifest, inline, download


class RuleTests(unittest.TestCase):
    def test_stage_does_not_activate_and_unchanged_only_fetches_pointer(self):
        manifest, _, download = fixture()
        with tempfile.TemporaryDirectory() as temporary, patch.object(rules, "download", side_effect=download) as network:
            path = Path(temporary)
            (path / "activation.enabled").touch()  # Old runtime flag must be ignored.
            self.assertEqual(rules.stage(path), manifest["build_id"])
            self.assertFalse((path / "active.json").exists())
            network.reset_mock()
            rules.stage(path)
            self.assertEqual(network.call_count, 1)
            self.assertEqual(rules.load(path, manifest["build_id"])[0], manifest)

    def test_bad_download_and_network_failure_keep_last_good(self):
        manifest, _, good = fixture("rules-old")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            with patch.object(rules, "download", side_effect=good):
                rules.stage(path)
            old = b'{"build_id":"rules-old"}'
            (path / "active.json").write_bytes(old)
            _, _, new = fixture("rules-new")

            def corrupt(url, maximum, deadline):
                return new(url, maximum, deadline) if url.endswith(".json") else b"corrupt!"

            with patch.object(rules, "download", side_effect=corrupt), self.assertRaises(ValueError):
                rules.stage(path)
            self.assertEqual((path / "active.json").read_bytes(), old)
            self.assertFalse((path / "rules-new").exists())
            with patch.object(rules, "download", side_effect=TimeoutError), self.assertRaises(TimeoutError):
                rules.stage(path)
            self.assertEqual((path / "active.json").read_bytes(), old)

    def test_same_tag_rewrite_and_cache_tamper_are_refused(self):
        _, _, download = fixture()
        with tempfile.TemporaryDirectory() as temporary, patch.object(rules, "download", side_effect=download):
            path = Path(temporary)
            rules.stage(path)
            (path / "rules-test/loyalsoldier/reject.mrs").write_bytes(b"tampered")
            with self.assertRaises(ValueError):
                rules.stage(path)
            with self.assertRaises(ValueError):
                rules.load(path, "../outside")

    def test_full_validation_uses_files_and_activation_requires_same_config(self):
        manifest, inline, download = fixture()
        document = {"dns": {"fake-ip-range": "198.18.0.1/16"}, "tun": {"enable": True, "stack": "mixed"},
                    "sniffer": {"skip-dst-address": ["127.0.0.0/8"]}, "proxies": [{"name": "x", "type": "direct"}],
                    "proxy-groups": [{"name": "节点选择", "type": "select", "proxies": ["x"]}]}
        expected_tun = copy.deepcopy(document["tun"])
        result = rules.assemble(document, manifest, inline)
        self.assertEqual(result["tun"], expected_tun)
        self.assertEqual(result["sniffer"], document["sniffer"])
        self.assertTrue(all("/rules-test/" in value["url"] for value in result["rule-providers"].values()))
        config = yaml.safe_dump(result, allow_unicode=True).encode()
        with tempfile.TemporaryDirectory() as temporary, patch.object(rules, "download", side_effect=download):
            path = Path(temporary)
            rules.stage(path)

            def check(argv, **kwargs):
                if argv[1] == "convert-ruleset":
                    self.assertEqual(argv[3], "mrs")
                    self.assertTrue(Path(argv[4]).exists())
                    return SimpleNamespace(returncode=0)
                local = yaml.safe_load(Path(argv[-1]).read_bytes())
                self.assertTrue(all(value["type"] == "file" and "url" not in value for value in local["rule-providers"].values()))
                self.assertEqual(kwargs["env"]["SAFE_PATHS"], str((path / "rules-test").resolve()))
                self.assertEqual(kwargs["env"]["SKIP_SAFE_PATH_CHECK"], "false")
                return SimpleNamespace(returncode=0)

            with patch.object(rules.subprocess, "run", side_effect=check):
                receipt = rules.validate(path, "rules-test", config, "mihomo")
            artifacts = rules.activation_artifacts(path, "rules-test", receipt, config)
            self.assertIn(rules.LOGICAL_CACHE + "/active.json", artifacts)
            self.assertFalse((path / "active.json").exists())
            with self.assertRaises(ValueError):
                rules.activation_artifacts(path, "rules-test", receipt, config + b"\n")
            with patch.object(rules.subprocess, "run", return_value=SimpleNamespace(returncode=1)), self.assertRaises(ValueError):
                rules.validate(path, "rules-test", config, "mihomo")

    def test_prune_keeps_five_recent_and_active(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            for index in range(8):
                tag = "rules-" + str(index)
                directory = path / tag
                directory.mkdir()
                (directory / "build-manifest.json").write_text(json.dumps({"build_id": tag, "created_at": 100 + index}), encoding="utf-8")
            (path / "active.json").write_text('{"build_id":"rules-0"}', encoding="utf-8")
            rules.prune(path)
            self.assertTrue((path / "rules-0").exists())
            self.assertFalse((path / "rules-1").exists())
            self.assertFalse((path / "rules-2").exists())
            self.assertEqual(len(list(path.glob("rules-*"))), 6)


if __name__ == "__main__":
    unittest.main()
