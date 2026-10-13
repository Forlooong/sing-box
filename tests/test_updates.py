import hashlib
import io
import json
import tarfile
import unittest

from sbmanager import updates


def archive(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as tar:
        for name, body, kind in entries:
            row = tarfile.TarInfo(name)
            row.type = kind
            if kind == tarfile.REGTYPE:
                row.size = len(body)
                tar.addfile(row, io.BytesIO(body))
            else:
                row.linkname = "/etc/passwd"
                tar.addfile(row)
    return output.getvalue()


class UpdateTests(unittest.TestCase):
    def test_untrusted_archive_types_paths_and_hash_are_rejected(self):
        base = [(name, body, tarfile.REGTYPE) for name, body in {
            "sbmanager/cli.py": b"", "sbmanager/upgrade.py": b"", "versions.json": json.dumps({"repository": updates.REPOSITORY}).encode(),
            "sing-box.sh": b"", "LICENSE": b"GPL"}.items()]
        for name, kind in (("../../escape", tarfile.REGTYPE), ("/etc/passwd", tarfile.REGTYPE),
                           ("sbmanager/linked.py", tarfile.SYMTYPE), ("sbmanager/cli.py", tarfile.REGTYPE)):
            data = archive([*base, (name, b"x", kind)])
            digest = hashlib.sha256(data).hexdigest()
            def fetch(url, maximum=None):
                return (digest + "  code.tar.gz\n").encode() if url.endswith("SHA256SUMS") else data
            with self.assertRaises(ValueError):
                updates.release("v2.0.0", fetch)
        with self.assertRaises(ValueError):
            updates.verify(b"wrong", "0" * 64)
        with self.assertRaises(ValueError):
            updates.release("latest")

    def test_verified_explicit_release_and_elf_extraction(self):
        data = archive([(name, body, tarfile.REGTYPE) for name, body in {
            "sbmanager/cli.py": b"", "sbmanager/upgrade.py": b"", "versions.json": json.dumps({"repository": updates.REPOSITORY}).encode(),
            "sing-box.sh": b"", "LICENSE": b"GPL"}.items()])
        digest = hashlib.sha256(data).hexdigest()
        requested = []
        def fetch(url, maximum=None):
            requested.append(url)
            return (digest + "  code.tar.gz\n").encode() if url.endswith("SHA256SUMS") else data
        self.assertIn("versions.json", updates.release("v2.0.0-rc1", fetch))
        self.assertTrue(all("Forlooong/sing-box/releases/download/v2.0.0-rc1/" in url for url in requested))
        elf = b"\x7fELFtest"
        binary = archive([("folder/sing-box", elf, tarfile.REGTYPE)])
        asset = {"binary": "sing-box", "url": "fixture", "format": "tar.gz", "sha256": hashlib.sha256(binary).hexdigest()}
        self.assertEqual(updates.binary(asset, lambda _: binary), elf)


if __name__ == "__main__":
    unittest.main()
