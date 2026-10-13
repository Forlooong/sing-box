import base64
import copy
import json
import unittest

from sbmanager import protocols as p

UUID = "b01f4712-1919-4612-bbe8-eb6bd83c310a"
KEY = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")


def reality(name="Reality"):
    return p.parse_uri(f"vless://{UUID}@node.example.com:443?security=reality&type=tcp&sni=site.example.com&pbk={KEY}&sid=abcd&flow=xtls-rprx-vision#{name}")


class ProtocolTests(unittest.TestCase):
    def test_reality_roundtrip_identity_ignores_label_and_private_key(self):
        node, secret = reality()
        other = copy.deepcopy(node)
        other["name"] = "New name"
        secret["private_key"] = "server-only-private-key"
        self.assertEqual(p.connection_id(node, secret), p.connection_id(other, secret))
        link = p.to_uri(other, secret)
        again, again_secret = p.parse_uri(link)
        self.assertEqual(p.to_mihomo(other, secret), p.to_mihomo(again, again_secret))
        self.assertNotIn("server-only", link)
        self.assertNotIn("server-only", json.dumps(p.to_mihomo(node, secret)))

    def test_every_supported_upstream_protocol_roundtrips(self):
        links = [
            "hy2://p%40ss%3Aword@[2001:db8::1]:443?sni=site.example.com&obfs=salamander&obfs-password=obfs#HY2",
            "ss://" + base64.b64encode(b"chacha20-ietf-poly1305:password").decode() + "@node.example.com:1988#SS",
            "trojan://p%40ss@node.example.com:443?encryption=none&security=tls&type=ws&host=site.example.com&path=%2Fws#Trojan",
            f"tuic://{UUID}:p%40ss%3Aword@node.example.com:443?congestion_control=bbr&alpn=h3#TUIC",
            "anytls://password@node.example.com:443?sni=site.example.com#AnyTLS",
            "socks://user:password@node.example.com:1080?udp=0#SOCKS",
            "socks://node.example.com:1080#SOCKS-no-auth",
        ]
        for transport in ("tcp", "http", "ws", "h2", "httpupgrade"):
            data = {"v": "2", "ps": "VMess-" + transport, "add": "node.example.com", "port": 443, "id": UUID,
                    "aid": 0, "net": "tcp" if transport == "http" else transport, "type": "http" if transport == "http" else "none"}
            if transport in ("h2", "httpupgrade"):
                data["tls"] = "tls"
            links.append("vmess://" + base64.b64encode(json.dumps(data).encode()).decode())
        for link in links:
            with self.subTest(scheme=link.split(":", 1)[0]):
                node, credentials = p.parse_uri(link)
                again, again_secret = p.parse_uri(p.to_uri(node, credentials))
                self.assertEqual(p.to_mihomo(node, credentials), p.to_mihomo(again, again_secret))

    def test_httpupgrade_is_not_downgraded_to_websocket(self):
        node, secret = p.parse_uri(f"vless://{UUID}@node.example.com:443?type=httpupgrade&security=tls&path=%2Fup#Upgrade")
        proxy = p.to_mihomo(node, secret)
        self.assertTrue(proxy["ws-opts"]["v2ray-http-upgrade"])

    def test_fail_closed_on_unknown_or_lossy_transport(self):
        for tail in ("type=quic", "type=unknown", "type=tcp&path=%2Flost", "type=tcp&mux=true", "type=tcp&type=ws"):
            with self.subTest(tail=tail), self.assertRaises(p.ProtocolError):
                p.parse_uri(f"vless://{UUID}@node.example.com:443?{tail}#Bad")
        node, secret = reality()
        node["transport"] = "h2"
        with self.assertRaises(p.ProtocolError):
            p.to_mihomo(node, secret)  # Vision cannot be carried over H2.
        with self.assertRaises(p.ProtocolError):
            p.parse_uri("https://example.com/subscription")

    def test_legacy_duplicate_insecure_flags_must_agree(self):
        node, _ = p.parse_uri("trojan://password@node.example.com:8443?insecure=1&allowInsecure=1#Old")
        self.assertTrue(node["insecure"])
        with self.assertRaises(p.ProtocolError):
            p.parse_uri("trojan://secret@node.example.com:8443?insecure=1&allowInsecure=0#Bad")

    def test_options_are_never_silently_lost(self):
        legacy_ss = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:password@node.example.com:1988").decode()
        for link in (
            "ss://" + legacy_ss + "?plugin=obfs-local#SS",
            "anytls://password@node.example.com:443?path=%2Fdiscarded#AnyTLS",
            f"vless://{UUID}@node.example.com:443?type=ws&serviceName=discarded#WS",
            f"vless://{UUID}@node.example.com:443?type=grpc&path=%2Fdiscarded#GRPC",
            "hy2://password@node.example.com:0#ZeroPort",
        ):
            with self.subTest(scheme=link.split(":", 1)[0]), self.assertRaises(p.ProtocolError):
                p.parse_uri(link)
        data = {"v": "2", "ps": "grpc", "add": "node.example.com", "port": "443", "id": UUID, "net": "grpc"}
        with self.assertRaises(p.ProtocolError):
            p.parse_uri("vmess://" + base64.b64encode(json.dumps(data).encode()).decode())

    def test_socks_percent_encoded_username_roundtrips(self):
        node, secret = p.parse_uri("socks://user%3Aname:p%40ss%3Aword@node.example.com:1080#SOCKS")
        self.assertEqual(secret, {"username": "user:name", "password": "p@ss:word"})
        again, again_secret = p.parse_uri(p.to_uri(node, secret))
        self.assertEqual(secret, again_secret)

    def test_legacy_whole_base64_retains_password_delimiters(self):
        password = "literal?query#fragment/@percent%+"
        value = "chacha20-ietf-poly1305:" + password + "@node.example.com:1988"
        uri = "ss://" + base64.b64encode(value.encode()).decode() + "#Legacy"
        node, secret = p.parse_uri(uri)
        self.assertEqual(secret["password"], password)
        _, again_secret = p.parse_uri(p.to_uri(node, secret))
        self.assertEqual(secret, again_secret)

    def test_hy2_certificate_pin_survives_both_outputs(self):
        pin = "ab" * 32
        node, secret = p.parse_uri("hy2://password@node.example.com:443?insecure=1&pinSHA256=" + pin + "#Pinned")
        proxy = p.to_mihomo(node, secret)
        self.assertEqual(proxy["fingerprint"], pin)
        again, again_secret = p.parse_uri(p.to_uri(node, secret))
        self.assertEqual(p.to_mihomo(again, again_secret), proxy)

    def test_tuic_disabling_sni_cannot_silently_disable_verification(self):
        uri = f"tuic://{UUID}:password@node.example.com:443?disable_sni=1"
        with self.assertRaises(p.ProtocolError):
            p.parse_uri(uri)
        node, secret = p.parse_uri(uri + "&pinSHA256=" + "ab" * 32)
        self.assertEqual(p.to_mihomo(node, secret)["fingerprint"], "ab" * 32)

    def test_invalid_utf8_and_duplicate_json_do_not_change_credentials(self):
        for link in ("hy2://%ff@node.example.com:443#Bad", "hy2://password@node.example.com:443?obfs-password=%ff",
                     "hy2://password@node.example.com:443#%ff"):
            with self.assertRaises(p.ProtocolError):
                p.parse_uri(link)
        data = '{"v":"2","ps":"one","ps":"two","add":"node.example.com","port":443,"id":"' + UUID + '"}'
        with self.assertRaisesRegex(p.ProtocolError, "Duplicate"):
            p.parse_uri("vmess://" + base64.b64encode(data.encode()).decode())

    def test_malformed_errors_do_not_include_secrets(self):
        secret = "SECRET_CREDENTIAL_123"
        for link in ("trojan://" + secret + "@node.example.com:99999", "hy2://" + secret + "@node.example.com?obfs=bad", "bad://" + secret):
            with self.assertRaises(p.ProtocolError) as error:
                p.parse_uri(link)
            self.assertNotIn(secret, str(error.exception))


if __name__ == "__main__":
    unittest.main()
