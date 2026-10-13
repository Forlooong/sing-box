import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from sbmanager import cli, state
from sbmanager.server import load_bundle


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.invoke("install", "--site", "site.example.com", "--subscription-domain", "sub.example.com",
                    "--email", "admin@example.com", "--without-rules")

    def invoke(self, *words, ok=True):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            code = cli.main(["--root", str(self.root), "--offline", *words])
        self.assertEqual(code, 0 if ok else 1, stream.getvalue())
        return stream.getvalue()

    def test_install_has_both_real_nodes_and_private_bundle(self):
        saved, secret = state.load(self.root)
        self.assertEqual([n["protocol"] for n in saved["nodes"]], ["vless", "hysteria2"])
        self.assertEqual(saved["nodes"][1]["transport"], "quic")
        bundle = load_bundle(self.root / "var/lib/sb/subscription/runtime.json")
        self.assertEqual(len(bundle["routes"]), 2)
        self.assertNotIn(secret["subscription_token"], self.invoke("status"))
        for credential in secret["nodes"].values():
            for value in credential.values():
                self.assertNotIn(value, self.invoke("node", "list"))

    def test_domain_and_path_changes_keep_urls_then_retire(self):
        self.invoke("subscription", "path", "new/path")
        self.invoke("domain", "subscription", "new-sub.example.com")
        self.invoke("domain", "site", "new-site.example.com")
        saved, secret = state.load(self.root)
        self.assertIn("site.example.com", saved["domains"]["site_aliases"])
        self.assertEqual(saved["nodes"][0]["sni"], "site.example.com")
        self.assertEqual(len(saved["subscription"]["aliases"]), 2)
        self.invoke("domain", "retire", "site.example.com", ok=False)
        self.invoke("subscription", "retire", "sub.example.com", "private")
        bundle = load_bundle(self.root / "var/lib/sb/subscription/runtime.json")
        self.assertNotIn(("sub.example.com", "/private/" + secret["subscription_token"]), bundle["routes"])
        self.invoke("subscription", "retire", "sub.example.com", "new/path")
        bundle = load_bundle(self.root / "var/lib/sb/subscription/runtime.json")
        self.assertFalse(any(host == "sub.example.com" for host, _ in bundle["routes"]))

    def test_rotating_then_rolling_back_never_revives_token(self):
        old_token = state.load(self.root)[1]["subscription_token"]
        result = json.loads(self.invoke("subscription", "rotate"))
        new = state.load(self.root)[1]["subscription_token"]
        self.assertNotEqual(new, old_token)
        self.invoke("transaction", "rollback", result["transaction"])
        saved, restored = state.load(self.root)
        self.assertEqual(restored["subscription_token"], new)
        bundle = load_bundle(self.root / "var/lib/sb/subscription/runtime.json")
        self.assertFalse(any(old_token in path for _, path in bundle["routes"]))
        self.assertTrue(any(new in path for _, path in bundle["routes"]))
        self.assertIn(hashlib.sha256(old_token.encode()).hexdigest(),
                      json.loads((self.root / "etc/sb/revoked-tokens.json").read_bytes()))

    def test_import_deduplicates_credentials_not_labels(self):
        saved, secret = state.load(self.root)
        node = saved["nodes"][0]
        from sbmanager.protocols import to_uri
        file = self.root / "nodes.txt"
        file.write_text(to_uri(node, secret["nodes"][node["id"]]), encoding="utf-8")
        result = json.loads(self.invoke("node", "import", "--file", str(file), "--name", "other name"))
        self.assertEqual(result["duplicates"], [node["id"]])
        self.assertEqual(len(state.load(self.root)[0]["nodes"]), 2)

    def test_failed_mutation_does_not_publish_partial_state(self):
        before = (self.root / "etc/sb/state.json").read_bytes()
        self.invoke("node", "add", "--name", "本机 REALITY", ok=False)
        self.assertEqual(before, (self.root / "etc/sb/state.json").read_bytes())
        self.invoke("node", "add", "--name", "Bad TCP443", "--protocol", "trojan", ok=False)
        self.assertEqual(before, (self.root / "etc/sb/state.json").read_bytes())

    def test_certificate_sync_repairs_missed_hook_and_skips_unchanged_copies(self):
        cert_path = "/etc/sb/certificates/site.example.com/fullchain.pem"
        with mock.patch.object(cli.certificates, "stage_lineage", return_value={cert_path: b"new"}), \
             mock.patch.object(cli, "publish", return_value="fixture-transaction") as publish:
            self.invoke("cert", "sync", "--scheduled")
            self.assertEqual(publish.call_args.kwargs["extra"], {cert_path: b"new"})
            target = state.logical_path(self.root, cert_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"new")
            publish.reset_mock()
            self.invoke("cert", "sync", "--scheduled")
            publish.assert_not_called()
            self.invoke("cert", "deploy", "--lineage", "/etc/letsencrypt/live/unrelated.example.com")
            publish.assert_not_called()

    def test_certificate_renew_only_touches_managed_lineages_under_lock(self):
        from sbmanager import bootstrap
        from sbmanager.transaction import lock
        unrelated = self.root / "etc/letsencrypt/renewal/unrelated.example.com.conf"
        unrelated.parent.mkdir(parents=True)
        unrelated.write_text("# another application's certificate\n")
        calls = []

        def renew(argv, **kwargs):
            # main() must retain its management lock while Certbot runs.
            with self.assertRaisesRegex(RuntimeError, "management lock"):
                with lock(self.root):
                    self.fail("Certificate renewal released the management lock")
            calls.append((argv, kwargs))

        def stage(lineage, saved, root):
            name = Path(lineage).name
            return {"/etc/sb/certificates/" + name + "/fullchain.pem": name.encode()}

        with mock.patch.object(cli.system, "require_linux_root"), mock.patch.object(cli.os, "umask"), \
             mock.patch.object(bootstrap, "recover_acme"), mock.patch.object(cli.system, "run", side_effect=renew), \
             mock.patch.object(cli.certificates, "stage_lineage", side_effect=stage) as stages, \
             mock.patch.object(cli, "publish", return_value="renewal-transaction") as publish, \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--root", str(self.root), "cert", "renew"]), 0)
        names = ["site.example.com", "sub.example.com"]
        self.assertEqual(calls, [(["certbot", "renew", "--non-interactive", "--quiet", "--cert-name", name,
                                  "--no-directory-hooks"], {"timeout": 600}) for name in names])
        self.assertEqual([call.args[0] for call in stages.call_args_list],
                         ["/etc/letsencrypt/live/" + name for name in names])
        self.assertEqual(publish.call_args.kwargs["extra"],
                         {"/etc/sb/certificates/" + name + "/fullchain.pem": name.encode() for name in names})
        self.assertEqual(unrelated.read_text(), "# another application's certificate\n")


if __name__ == "__main__":
    unittest.main()
