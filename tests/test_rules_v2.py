"""Channel isolation, final DNS validation and transactional policy migration.

The subprocess boundary is mocked in these unit tests. Real MRS decoding and
Mihomo execution belong to integration_core.py, not these synthetic payloads.
"""
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml

from sbmanager import cli, protocols, rules, state, subscription, system
from sbmanager.transaction import Transaction, atomic
from sbmanager.vendor import snapshot


def fixture(version=2, tag="rules-balanced-v2"):
    registry = snapshot.V2_PROVIDERS if version == 2 else snapshot.PROVIDERS
    sections = snapshot.V2_SECTIONS if version == 2 else snapshot.SECTIONS
    providers = {name: {"path": rel, "behavior": behavior, "format": "mrs"}
                 for name, (rel, behavior) in registry.items()}
    inline = {"schema_version": version, "build_id": tag, "sections": {name: [] for name in sections}}
    if version == 2:
        inline["sections"]["personal_direct"] = ["DOMAIN-KEYWORD,personal-direct-test"]
        # Real v2 ships a DNS intersection index, substantially larger than v1
        # metadata. Migration must not apply the same-schema doubling guard.
        inline["domain_index"] = {name: [f"fixture-{i}.{name}.example" for i in range(40)]
                                  for name, entry in providers.items() if entry["behavior"] == "domain"}
    files = {entry["path"]: b"synthetic-unit-test-mrs" for entry in providers.values()}
    files["inline-rules.json"] = json.dumps(inline).encode()
    manifest = {"schema_version": version, "build_id": tag, "tag": tag, "created_at": int(time.time()),
                "fake_ip_pool": "198.18.0.0/16", "sources": {key: {} for key in ("loyal", "acl", "meta", "personal")},
                "providers": providers, "files": {name: {"size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                                                  for name, body in files.items()}}
    candidate = {"schema_version": version, "build_id": tag}
    if version == 2:
        manifest.update(policy_version="balanced-v2", audit={"status": "passed", "manifest_sha256": "a" * 64})
        candidate["policy_version"] = "balanced-v2"
    manifest_bytes = json.dumps(manifest).encode()
    candidate["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    pointer = rules.CANDIDATE_V2 if version == 2 else rules.CANDIDATE

    def download(url, maximum, deadline):
        if url == pointer:
            return json.dumps(candidate).encode()
        if url.endswith("/build-manifest.json"):
            return manifest_bytes
        return files[url.split(tag + "/", 1)[1]]

    return manifest, inline, download


def client():
    public, private = state.create("site.example.com", "sub.example.com", "admin@example.com")
    node, credential = protocols.parse_uri("hy2://fixture@site.example.com:443?sni=site.example.com#HY2")
    public["nodes"] = [node]
    private["nodes"][node["id"]] = credential
    public["subscription"]["template"] = {"tun": {"enable": True}, "log-level": "debug",
                                           "dns": {"listen": "127.0.0.1:5544"}}
    return public, private


class ChannelTests(unittest.TestCase):
    def test_v2_pointer_is_separate_and_wrong_channel_is_refused(self):
        manifest, _, network = fixture()
        with tempfile.TemporaryDirectory() as folder, patch.object(rules, "download", side_effect=network) as fetch:
            cache = Path(folder)
            self.assertEqual(rules.stage(cache, channel="v2"), manifest["build_id"])
            self.assertEqual(fetch.call_args_list[0].args[0], rules.CANDIDATE_V2)
            self.assertFalse((cache / "active.json").exists())
            self.assertEqual(rules.load(cache, manifest["build_id"], channel="v2")[0], manifest)
            with self.assertRaisesRegex(ValueError, "channel"):
                rules.load(cache, manifest["build_id"], channel="v1")
            pointer = network(rules.CANDIDATE_V2, 4096, 0)
            with patch.object(rules, "download", return_value=pointer), self.assertRaisesRegex(ValueError, "channel"):
                rules.stage(cache)
            with self.assertRaises(ValueError):
                rules.stage(cache, channel="latest")

    def test_legacy_state_defaults_to_v1_and_rejects_unknown_channels(self):
        public, private = client()
        public["rules"].pop("channel")
        state.validate(public, private)
        self.assertNotIn("channel", public["rules"])
        for invalid in ("latest", "", None, 2):
            public["rules"]["channel"] = invalid
            with self.assertRaises(ValueError):
                state.validate(public, private)

    def test_final_dns_is_managed_only_on_v2_and_order_is_verified(self):
        public, private = client()
        old, old_inline, _ = fixture(1, "rules-old")
        legacy = subscription.compile_config(public, private, (old, old_inline))[0]
        self.assertEqual(legacy["dns"], subscription.template_config(public["subscription"]["template"])["dns"])
        manifest, inline, _ = fixture()
        public["rules"]["channel"] = "v2"
        original_override = copy.deepcopy(public["subscription"]["template"])
        config = subscription.compile_config(public, private, (manifest, inline))[0]
        self.assertTrue(config["tun"]["enable"])
        self.assertEqual(config["log-level"], "debug")
        self.assertEqual(config["dns"]["listen"], "127.0.0.1:5544")
        self.assertEqual(public["subscription"]["template"], original_override)
        self.assertNotEqual(config["dns"]["direct-nameserver"], legacy["dns"]["direct-nameserver"])
        self.assertTrue(all("#节点选择" in item for item in config["dns"]["direct-nameserver"]))
        self.assertIn("rule-set:cn-domain", config["dns"]["nameserver-policy"])
        self.assertTrue(set(config["rule-providers"]) - set(manifest["providers"]))
        self.assertEqual(rules.validate_assembly(config, manifest, inline, override=original_override), config)
        broken = copy.deepcopy(config)
        broken["dns"]["direct-nameserver"] = ["https://223.5.5.5/dns-query#DIRECT"]
        with self.assertRaisesRegex(ValueError, "DNS"):
            rules.validate_assembly(broken, manifest, inline, override=original_override)
        broken = copy.deepcopy(config)
        broken["dns"]["nameserver-policy"] = dict(reversed(list(broken["dns"]["nameserver-policy"].items())))
        with self.assertRaisesRegex(ValueError, "DNS"):
            rules.validate_assembly(broken, manifest, inline, override=original_override)

    def test_dns_tamper_fails_before_core_and_receipt_binds_policy_and_config(self):
        manifest, inline, network = fixture()
        public, private = client()
        public["rules"]["channel"] = "v2"
        override = public["subscription"]["template"]
        config = subscription.compile_config(public, private, (manifest, inline))[0]
        body = yaml.safe_dump(config, allow_unicode=True, sort_keys=False).encode()
        with tempfile.TemporaryDirectory() as folder, patch.object(rules, "download", side_effect=network):
            cache = Path(folder)
            rules.stage(cache, channel="v2")
            with patch.object(rules.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as core:
                receipt = rules.validate(cache, manifest["build_id"], body, "fixture-mihomo", override=override)
                self.assertEqual(receipt["rules_schema_version"], 2)
                self.assertEqual(receipt["policy_version"], "balanced-v2")
                rules.activation_artifacts(cache, manifest["build_id"], receipt, body)
                with self.assertRaisesRegex(ValueError, "changed"):
                    rules.activation_artifacts(cache, manifest["build_id"], receipt, body + b"\n")
                legacy_receipt = dict(receipt, rules_schema_version=1)
                with self.assertRaisesRegex(ValueError, "v2"):
                    rules.activation_artifacts(cache, manifest["build_id"], legacy_receipt, body)
                core.reset_mock()
                config["dns"]["direct-nameserver"] = ["system"]
                with self.assertRaisesRegex(ValueError, "DNS"):
                    rules.validate(cache, manifest["build_id"], yaml.safe_dump(config).encode(), "fixture-mihomo", override=override)
                core.assert_not_called()

    def test_pruning_keeps_old_build_referenced_by_rollback_transaction(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cache = root / "var/lib/sb/rules"
            for index in range(8):
                tag = "rules-" + str(index)
                atomic(cache / tag / "build-manifest.json", json.dumps({"build_id": tag, "created_at": 100 + index}).encode())
            tx = root / "var/backups/sb/transactions/fixture"
            atomic(tx / "journal.json", b'{"status":"committed"}')
            atomic(tx / "before/etc/sb/state.json", b'{"rules":{"active_build":"rules-0"}}')
            rules.prune(cache)
            self.assertTrue((cache / "rules-0").exists())
            self.assertFalse((cache / "rules-1").exists())
            self.assertFalse((cache / "rules-2").exists())

    def test_second_core_validation_keeps_dns_only_providers_and_template_override(self):
        manifest, inline, network = fixture()
        public, private = client()
        public["rules"].update(channel="v2", active_build=manifest["build_id"])
        with tempfile.TemporaryDirectory() as folder, patch.object(rules, "download", side_effect=network):
            root = Path(folder)
            cache = root / "rules"
            rules.stage(cache, channel="v2")
            stage = root / "candidate"
            config = subscription.compile_config(public, private, (manifest, inline))[0]
            atomic(state.logical_path(stage, state.STATE), state.encode(public))
            atomic(state.logical_path(stage, subscription.DIRECTORY + "/clash.yaml"),
                   yaml.safe_dump(config, allow_unicode=True, sort_keys=False).encode())

            def core(argv, **kwargs):
                local = yaml.safe_load(Path(argv[-1]).read_bytes())
                self.assertEqual(local["dns"], config["dns"])
                self.assertEqual(list(local["dns"]["nameserver-policy"]), list(config["dns"]["nameserver-policy"]))
                self.assertTrue(all(local["rule-providers"][name]["type"] == "file" for name in manifest["providers"]))
                self.assertTrue(any(value["type"] == "inline" for value in local["rule-providers"].values()))

            with patch.object(system, "require_linux_root"), patch.object(system, "run", side_effect=core) as check:
                system.validate_subscription_candidate(stage, root=root, snapshot_dir=cache / manifest["build_id"])
            check.assert_called_once()


class MigrationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = state.logical_path(self.root, rules.LOGICAL_CACHE)
        self.old, self.old_inline, network = fixture(1, "rules-old")
        self.new, self.new_inline, self.network = fixture()
        public, private = client()
        public["rules"].pop("channel")  # A pre-channel installation.
        public["rules"]["active_build"] = self.old["build_id"]
        with patch.object(rules, "download", side_effect=network):
            rules.stage(self.cache)
        files = subscription.render(public, private, (self.old, self.old_inline))
        files[state.STATE], files[state.SECRETS] = state.encode(public), state.encode(private)
        with patch.object(rules.subprocess, "run", return_value=SimpleNamespace(returncode=0)):
            body = files[subscription.DIRECTORY + "/clash.yaml"]
            receipt = rules.validate(self.cache, self.old["build_id"], body, "fixture-mihomo")
        files.update(rules.activation_artifacts(self.cache, self.old["build_id"], receipt, body))
        Transaction(self.root).apply(files)
        self.before = {name: state.logical_path(self.root, name).read_bytes() for name in files}

    def update(self, *, fail_health=False):
        args = cli.parser().parse_args(["--root", str(self.root), "rules", "update", "--channel", "v2"])
        stream = io.StringIO()
        with patch.object(rules, "download", side_effect=self.network), \
             patch.object(rules.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
             patch.object(system, "validate_subscription_candidate"), \
             patch.object(system, "validate_candidate") as full_validation, \
             patch.object(system, "activate_subscription"), patch.object(system, "activate") as full_activation, \
             patch.object(system, "health", side_effect=RuntimeError("injected reload failure") if fail_health else None), \
             patch.object(system, "restore_services"), \
             patch.object(system, "service_state", return_value={"sb-subscription": {"is-active": True}}), \
             contextlib.redirect_stdout(stream):
            cli.execute(args)
        full_validation.assert_not_called()
        full_activation.assert_not_called()
        return json.loads(stream.getvalue())

    def assert_original(self):
        for name, body in self.before.items():
            self.assertEqual(state.logical_path(self.root, name).read_bytes(), body, name)

    def test_migrate_persists_channel_timer_follows_and_rollback_restores_all_bytes(self):
        result = self.update()
        saved, _ = state.load(self.root)
        self.assertEqual(saved["rules"]["channel"], "v2")
        self.assertEqual(saved["rules"]["active_build"], self.new["build_id"])
        config = yaml.safe_load(state.logical_path(self.root, subscription.DIRECTORY + "/clash.yaml").read_bytes())
        self.assertTrue(all("#节点选择" in item for item in config["dns"]["direct-nameserver"]))
        args = cli.parser().parse_args(["--root", str(self.root), "rules", "update", "--scheduled"])
        with patch.object(rules, "stage", return_value=self.new["build_id"]) as stage, \
             patch.object(cli, "publish") as publish, contextlib.redirect_stdout(io.StringIO()):
            cli.execute(args)
        stage.assert_called_once_with(self.cache, channel="v2")
        publish.assert_not_called()
        Transaction(self.root).rollback(result["transaction"])
        self.assert_original()

    def test_failed_reload_restores_state_dns_subscription_and_active_pointer(self):
        with self.assertRaisesRegex(RuntimeError, "reload failure"):
            self.update(fail_health=True)
        self.assert_original()


if __name__ == "__main__":
    unittest.main()
