"""Regression tests at the local-node creation -> rendered listener boundary."""
import base64
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sbmanager import cli, protocols, render, state


class RealityListenerTests(unittest.TestCase):
    def setUp(self):
        self.state, self.secret = state.create("site.example.com", "sub.example.com", "admin@example.com")
        self.first = self.add("FIRST")

    def add(self, name, **kwargs):
        identity = cli.add_local(self.state, self.secret, name=name, offline=True, **kwargs)
        return next(node for node in self.state["nodes"] if node["id"] == identity)

    def test_default_second_user_reuses_listener_without_replacing_first(self):
        original = copy.deepcopy(self.first)
        with mock.patch.object(cli, "reality_keys", side_effect=AssertionError("A shared listener must keep its key")):
            second = self.add("SECOND")
        inbounds, routes = render.render_inbounds(self.state, self.secret)
        self.assertEqual(len(inbounds), 1)
        self.assertEqual(len(inbounds[0]["users"]), 2)
        self.assertEqual(routes, {"site.example.com": "127.0.0.1:2443"})
        self.assertEqual(self.first, original)
        self.assertNotEqual(self.secret["nodes"][self.first["id"]]["uuid"], self.secret["nodes"][second["id"]]["uuid"])
        self.assertEqual(self.secret["nodes"][self.first["id"]]["private_key"], self.secret["nodes"][second["id"]]["private_key"])
        self.assertEqual(self.first["public_key"], second["public_key"])
        for node in (self.first, second):
            self.assert_export_matches_listener(node, inbounds[0])

    def assert_export_matches_listener(self, node, inbound):
        credentials = self.secret["nodes"][node["id"]]
        exported = protocols.to_mihomo(node, credentials)
        reality = inbound["tls"]["reality"]
        key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(reality["private_key"] + "="))
        public_key = base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode().rstrip("=")
        self.assertEqual(exported["reality-opts"]["public-key"], public_key)
        self.assertIn(exported["reality-opts"]["short-id"], reality["short_id"])
        self.assertEqual(exported["servername"], inbound["tls"]["server_name"])
        self.assertIn(exported["uuid"], [user["uuid"] for user in inbound["users"]])
        uri = protocols.to_uri(node, credentials)
        self.assertNotIn(credentials["private_key"], uri)
        parsed_node, parsed_credentials = protocols.parse_uri(uri)
        self.assertEqual(protocols.to_mihomo(parsed_node, parsed_credentials), exported)

    def test_add_after_site_change_keeps_both_sni_routes(self):
        original = copy.deepcopy(self.first)
        self.state["domains"]["site_aliases"].append("site.example.com")
        self.state["domains"]["site"] = "new.example.com"
        second = self.add("SECOND")
        inbounds, routes = render.render_inbounds(self.state, self.secret)
        self.assertEqual(len(inbounds), 2)
        self.assertEqual(routes["site.example.com"], "127.0.0.1:2443")
        self.assertNotEqual(routes["new.example.com"], routes["site.example.com"])
        self.assertEqual(second["port"], 443)
        self.assertTrue(all(inbound["listen"] == "127.0.0.1" for inbound in inbounds))
        self.assertEqual(self.first, original)
        self.assertNotEqual(self.first["public_key"], second["public_key"])
        for node, inbound in zip(self.state["nodes"], inbounds):
            self.assert_export_matches_listener(node, inbound)

    def test_preexisting_node_without_explicit_listener_remains_compatible(self):
        self.first.pop("listen", None)
        self.first.pop("listen_port", None)
        original = copy.deepcopy(self.first)
        self.add("SECOND")
        inbounds, _ = render.render_inbounds(self.state, self.secret)
        self.assertEqual(len(inbounds), 1)
        self.assertEqual(len(inbounds[0]["users"]), 2)
        self.assertEqual(inbounds[0]["listen_port"], self.state["ports"]["reality"])
        self.assertEqual(self.first, original)

    def test_dedicated_external_port_keeps_independent_listener_and_key(self):
        second = self.add("DEDICATED", port=10443)
        inbounds, routes = render.render_inbounds(self.state, self.secret)
        self.assertEqual(len(inbounds), 2)
        self.assertEqual(inbounds[1]["listen_port"], 10443)
        self.assertEqual(inbounds[1]["listen"], "::")
        self.assertNotEqual(self.first["public_key"], second["public_key"])
        self.assertEqual(routes, {"site.example.com": "127.0.0.1:2443"})
        self.assert_export_matches_listener(second, inbounds[1])

    def test_new_sni_avoids_local_legacy_and_observed_port_conflicts(self):
        self.add("DEDICATED", port=20000)
        self.state["legacy"]["listeners"] = {"kept": {"listen_port": 20001}}
        self.state["legacy"]["entries"] = [{"kind": "sni", "sni": "legacy.example.com", "upstream": "127.0.0.1:20002"}]
        self.state["domains"]["site_aliases"].append("new.example.com")
        with mock.patch.object(cli.system, "occupied_ports", return_value={20003}), \
             mock.patch.object(cli, "reality_keys", return_value=cli.reality_keys(True)):
            identity = cli.add_local(self.state, self.secret, name="NEW", sni="new.example.com")
        node = cli.find_node(self.state, identity)
        self.assertEqual(node["listen_port"], 20004)
        files = render.render(self.state, self.secret)
        self.assertIn(b"new.example.com 127.0.0.1:20004;", files["/etc/nginx/sb/stream.conf"])
        self.assertIn(b"legacy.example.com 127.0.0.1:20002;", files["/etc/nginx/sb/stream.conf"])

    def test_new_sni_skips_managed_http_ports_and_disabled_nodes(self):
        self.state["ports"].update(site_tls=20000, sub_tls=20001, sub_http=20002)
        disabled = self.add("DISABLED", port=20003)
        disabled["enabled"] = False
        self.state["domains"]["site_aliases"].append("new.example.com")
        new = self.add("NEW", sni="new.example.com")
        self.assertEqual(new["listen_port"], 20004)
        disabled["enabled"] = True
        self.assertEqual(len(render.render_inbounds(self.state, self.secret)[0]), 3)

    def test_disabled_same_sni_preserves_identity_for_later_enable(self):
        self.first["enabled"] = False
        second = self.add("SECOND")
        self.assertEqual(self.first["public_key"], second["public_key"])
        inbounds, _ = render.render_inbounds(self.state, self.secret)
        self.assertEqual([user["name"] for user in inbounds[0]["users"]], ["SECOND"])
        self.first["enabled"] = True
        self.assertEqual(len(render.render_inbounds(self.state, self.secret)[0][0]["users"]), 2)

    def test_active_identity_wins_over_disabled_older_keys_for_same_sni(self):
        self.first["enabled"] = False
        # Older releases could create a fresh identity after disabling the only
        # user. Preserve that valid deployed state and prefer its active key.
        active = self.add("ACTIVE", port=10443)
        active["port"] = 443
        render.render_inbounds(self.state, self.secret)
        third = self.add("THIRD")
        inbounds, _ = render.render_inbounds(self.state, self.secret)
        self.assertEqual(len(inbounds), 1)
        self.assertEqual(len(inbounds[0]["users"]), 2)
        self.assertEqual(active["public_key"], third["public_key"])
        self.assertNotEqual(self.first["public_key"], third["public_key"])

    def test_removing_first_user_does_not_change_second_users_route_or_keys(self):
        second = self.add("SECOND")
        original, routes = render.render_inbounds(self.state, self.secret)
        old_uuid = self.secret["nodes"][self.first["id"]]["uuid"]
        self.state["nodes"].remove(self.first)
        self.secret["nodes"].pop(self.first["id"])
        inbounds, new_routes = render.render_inbounds(self.state, self.secret)
        self.assertEqual(new_routes, routes)
        self.assertEqual(inbounds[0]["tls"], original[0]["tls"])
        self.assertEqual(len(inbounds[0]["users"]), 1)
        self.assertNotIn(old_uuid, [user["uuid"] for user in inbounds[0]["users"]])
        self.assert_export_matches_listener(second, inbounds[0])

    def test_incompatible_transport_requires_a_distinct_sni_or_external_port(self):
        before = copy.deepcopy((self.state, self.secret))
        with self.assertRaisesRegex(render.RenderError, "different transport/path"):
            self.add("H2", transport="h2", path="/h2")
        self.assertEqual((self.state, self.secret), before)
        self.add("H2 dedicated", transport="h2", path="/h2", port=10443)
        self.assertEqual(len(render.render_inbounds(self.state, self.secret)[0]), 2)

    def test_compatible_h2_users_keep_listener_transport(self):
        self.state["domains"]["site_aliases"].append("h2.example.com")
        first = self.add("H2 FIRST", sni="h2.example.com", transport="h2", path="/h2")
        second = self.add("H2 SECOND", sni="h2.example.com", transport="h2", path="/h2")
        inbounds, _ = render.render_inbounds(self.state, self.secret)
        self.assertEqual(len(inbounds), 2)
        self.assertEqual(len(inbounds[1]["users"]), 2)
        self.assertEqual(first["public_key"], second["public_key"])
        with self.assertRaisesRegex(render.RenderError, "different transport/path"):
            self.add("H2 different path", sni="h2.example.com", transport="h2", path="/other")

    def test_exhausted_internal_port_pool_fails_before_state_mutation(self):
        self.state["domains"]["site_aliases"].append("new.example.com")
        before = copy.deepcopy((self.state, self.secret))
        with mock.patch.object(cli.system, "occupied_ports", return_value=set(range(20000, 60000))), \
             self.assertRaisesRegex(render.RenderError, "No available internal TCP port"):
            cli.add_local(self.state, self.secret, name="NEW", sni="new.example.com")
        self.assertEqual((self.state, self.secret), before)


class RealityCLIRegressionTests(unittest.TestCase):
    def test_install_add_change_site_add_and_remove_publish_compatible_runtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def invoke(*args):
                output = io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                    code = cli.main(["--root", str(root), "--offline", *args])
                self.assertEqual(code, 0, output.getvalue())
                return json.loads(output.getvalue())

            invoke("install", "--site", "site.example.com", "--subscription-domain", "sub.example.com",
                   "--email", "admin@example.com", "--without-rules")
            installed, credentials = state.load(root)
            old_id = installed["nodes"][0]["id"]
            old_uuid = credentials["nodes"][old_id]["uuid"]
            second_id = invoke("node", "add", "--name", "SECOND")["node_id"]
            invoke("domain", "site", "new.example.com")
            invoke("node", "add", "--name", "NEW SNI")
            invoke("node", "remove", old_id)
            saved, secrets = state.load(root)
            inbounds, routes = render.render_inbounds(saved, secrets)
            published = json.loads((root / "etc/sing-box/sb/config.json").read_bytes())
            self.assertEqual(published["inbounds"], inbounds)
            self.assertEqual(len([item for item in inbounds if item["type"] == "vless"]), 2)
            self.assertEqual(routes["site.example.com"], "127.0.0.1:2443")
            self.assertNotEqual(routes["new.example.com"], routes["site.example.com"])
            self.assertNotIn(old_uuid, json.dumps(published))
            self.assertIn(secrets["nodes"][second_id]["uuid"], json.dumps(published))


if __name__ == "__main__":
    unittest.main()
