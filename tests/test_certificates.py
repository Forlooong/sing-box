from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

from sbmanager import certificates as cert


def state():
    return {"domains": {"site": "site.example.com", "subscription": "sub.example.com", "site_aliases": ["old.example.com"]},
            "subscription": {"aliases": [{"domain": "oldsub.example.com"}]},
            "legacy": {"certificates": [{"domain": "legacy.example.com"}]}}


class CommandTests(unittest.TestCase):
    def test_untrusted_inputs_never_enter_shell(self):
        for domain in ("x;rm -rf /", "example.com\n", "*.example.com", "../example.com", "127.0.0.1", "-x.example.com"):
            with self.assertRaises(cert.CertificateError):
                cert.certbot_issue_command([domain], "admin@example.com")
        command = cert.certbot_issue_command(["EXAMPLE.com"], "admin@example.com")
        self.assertIsInstance(command, list)
        self.assertIn("--webroot", command)
        self.assertEqual(command[-2:], ["--domain", "example.com"])
        self.assertNotIn("--standalone", command)
        with self.assertRaises(cert.CertificateError):
            cert.certbot_issue_command(["a.example.com", "b.example.com"], "admin@example.com")

    def test_retained_and_migrated_public_certificates_remain_managed(self):
        self.assertEqual(cert.managed_domains(state()), ["legacy.example.com", "old.example.com", "oldsub.example.com", "site.example.com", "sub.example.com"])

    def test_hook_is_quoted_and_uses_transaction_entrypoint(self):
        self.assertIn(b'cert deploy --lineage "$RENEWED_LINEAGE"', cert.deploy_hook())
        self.assertNotIn(b"systemctl", cert.deploy_hook())


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL executable is required")
class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="sb-cert-fixture-")
        cls.root = Path(cls.directory.name)
        cls.openssl = shutil.which("openssl")
        (cls.root / "openssl.cnf").write_text("[req]\ndistinguished_name=dn\n[dn]\n")
        def run(*args):
            if args[0] == "req":
                args = (*args, "-config", "openssl.cnf")
            subprocess.run([cls.openssl, *map(str, args)], cwd=cls.root, check=True, capture_output=True, timeout=30)
        run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "7",
            "-subj", "/CN=SB test root", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "intermediate.key", "-out", "intermediate.csr", "-subj", "/CN=SB test intermediate")
        (cls.root / "intermediate.ext").write_text("basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n")
        run("x509", "-req", "-in", "intermediate.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", "intermediate.pem", "-days", "5", "-extfile", "intermediate.ext")
        run("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=site.example.com")
        (cls.root / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:site.example.com\n")
        run("x509", "-req", "-in", "leaf.csr", "-CA", "intermediate.pem", "-CAkey", "intermediate.key", "-CAcreateserial", "-out", "leaf.pem", "-days", "3", "-extfile", "leaf.ext")
        cls.chain = (cls.root / "leaf.pem").read_bytes() + (cls.root / "intermediate.pem").read_bytes()
        cls.key = (cls.root / "leaf.key").read_bytes()
        cls.ca = cls.root / "ca.pem"

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_valid_chain_hostname_key_and_server_purpose(self):
        cert.validate_pair(self.chain, self.key, ["site.example.com"], openssl=self.openssl, ca_file=self.ca)

    def test_wrong_hostname_missing_intermediate_and_mismatched_key_rejected(self):
        for chain, key, domain in ((self.chain, self.key, "other.example.com"),
                                   ((self.root / "leaf.pem").read_bytes(), self.key, "site.example.com"),
                                   (self.chain, (self.root / "ca.key").read_bytes(), "site.example.com")):
            with self.subTest(domain=domain, chain_size=len(chain)):
                with self.assertRaises(cert.CertificateError):
                    cert.validate_pair(chain, key, [domain], openssl=self.openssl, ca_file=self.ca)

    def test_untrusted_root_is_not_trusted_merely_because_chain_contains_it(self):
        with self.assertRaises(cert.CertificateError):
            cert.validate_pair(self.chain + self.ca.read_bytes(), self.key, ["site.example.com"], openssl=self.openssl)

    def test_near_expiry_rejected(self):
        subprocess.run([self.openssl, "x509", "-req", "-in", str(self.root / "leaf.csr"), "-CA", str(self.ca),
            "-CAkey", str(self.root / "ca.key"), "-CAcreateserial", "-days", "0", "-extfile", str(self.root / "leaf.ext"),
            "-out", str(self.root / "expired.pem")], check=True, capture_output=True, timeout=30)
        with self.assertRaises(cert.CertificateError):
            cert.validate_pair((self.root / "expired.pem").read_bytes(), self.key, ["site.example.com"], openssl=self.openssl, ca_file=self.ca)

    def test_stage_only_returns_candidates_and_does_not_deploy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            live = root / "etc/letsencrypt/live/site.example.com"
            live.mkdir(parents=True)
            (live / "fullchain.pem").write_bytes(self.chain)
            (live / "privkey.pem").write_bytes(self.key)
            try:
                files = cert.stage_lineage("/etc/letsencrypt/live/site.example.com", state(), root, openssl=self.openssl, ca_file=self.ca)
            except PermissionError:
                if os.name == "nt":
                    self.skipTest("Windows sandbox denies canonical path inspection; covered on Linux")
                raise
            self.assertEqual(files["/etc/sb/certificates/site.example.com/privkey.pem"], self.key)
            self.assertFalse((root / "etc/sb").exists())
            for path in ("/tmp/site.example.com", "/etc/letsencrypt/live/unknown.example.com", "/etc/letsencrypt/live/../site.example.com"):
                with self.assertRaises(cert.CertificateError):
                    cert.stage_lineage(path, state(), root, openssl=self.openssl, ca_file=self.ca)

    def test_lineage_symlink_cannot_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            live = root / "etc/letsencrypt/live/site.example.com"
            live.mkdir(parents=True)
            external = root / "unexpected.pem"
            external.write_bytes(self.chain)
            try:
                (live / "fullchain.pem").symlink_to(external)
            except OSError:
                self.skipTest("Windows user cannot create symlinks")
            (live / "privkey.pem").write_bytes(self.key)
            with self.assertRaises(cert.CertificateError):
                cert.stage_lineage("/etc/letsencrypt/live/site.example.com", state(), root, openssl=self.openssl, ca_file=self.ca)

    def test_status_reports_missing_domains_without_returning_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            results = cert.certificate_status(state(), Path(temp), openssl=self.openssl, ca_file=self.ca)
            self.assertTrue(all(not row["valid"] for row in results))
            self.assertNotIn("PRIVATE KEY", str(results))


if __name__ == "__main__":
    unittest.main()
