from pathlib import Path
import socket
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.request

import yaml

from sbmanager import cli, probe, state


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class ListeningCore:
    """A listening socket does not imply Mihomo's tunnel is Running yet."""
    def __init__(self, argv, **_):
        config = yaml.safe_load(Path(argv[argv.index("-f") + 1]).read_text(encoding="utf-8"))
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", config["mixed-port"]))
        self.listener.listen()
        self.alive = True
        self.terminated = False

    def poll(self):
        return None if self.alive else 1

    def terminate(self):
        self.terminated = True
        self.alive = False
        self.listener.close()

    def kill(self):
        self.terminate()

    def wait(self, timeout=None):
        return 0


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.public, self.secret = state.create("site.example.com", "sub.example.com", "test@example.com")
        cli.add_local(self.public, self.secret, name="HY2 fixture", protocol="hysteria2", offline=True)
        self.clock = FakeClock()
        self.cores = []
        self.requests = 0

    def launch_core(self, argv, **kwargs):
        core = ListeningCore(argv, **kwargs)
        self.cores.append(core)
        self.addCleanup(core.terminate)
        return core

    def curl_result(self, argv, *, code=0, body=None, stderr=b""):
        self.assertEqual(argv[0], "curl")
        self.assertIn("--socks5-hostname", argv)
        self.requests += 1
        # Advance virtual time so persistent errors exercise the real deadline
        # without making the unit test wait for network timeouts.
        self.clock.sleep(1)
        if body is None and code == 0:
            # Fetch the production function's random marker from its actual
            # loopback HTTP origin; never replace it with a fixture constant.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(argv[-1], timeout=2) as response:
                body = response.read()
        return SimpleNamespace(returncode=code, stdout=body or b"", stderr=stderr)

    def run_probe(self, curl):
        with mock.patch.object(probe.subprocess, "Popen", side_effect=self.launch_core), \
             mock.patch.object(probe.subprocess, "run", side_effect=curl), \
             mock.patch.object(probe, "time", self.clock):
            probe.local_nodes(self.public, self.secret, Path("unused-mihomo"))

    def test_listener_ready_before_tunnel_retries_empty_response_then_checks_real_marker(self):
        for code in (7, 52, 56, 97):
            with self.subTest(curl_code=code):
                self.requests = 0
                def curl(argv, **_):
                    if not self.requests:
                        return self.curl_result(argv, code=code)
                    return self.curl_result(argv)

                self.run_probe(curl)
                self.assertEqual(self.requests, 2)
                self.assertTrue(self.cores[-1].terminated)

    def test_permanent_tls_or_authentication_failure_does_not_pass(self):
        for message in (b"certificate signed by unknown authority", b"authentication failed"):
            with self.subTest(message=message):
                self.requests = 0
                def curl(argv, **_):
                    return self.curl_result(argv, code=52, stderr=message)

                with self.assertRaisesRegex(RuntimeError, "data-path probe failed"):
                    self.run_probe(curl)
                self.assertGreater(self.requests, 1)
                self.assertLess(self.requests, 100)
                self.assertTrue(self.cores[-1].terminated)

    def test_successful_http_with_wrong_marker_does_not_pass(self):
        def curl(argv, **_):
            return self.curl_result(argv, body=b"unrelated HTTP response")

        with self.assertRaisesRegex(RuntimeError, "data-path probe failed"):
            self.run_probe(curl)
        self.assertEqual(self.requests, 1)
        self.assertTrue(self.cores[0].terminated)

    def test_other_curl_failures_or_partial_responses_are_not_startup_retries(self):
        for code, body in ((35, b""), (52, b"partial response")):
            with self.subTest(curl_code=code, body=body):
                self.requests = 0
                def curl(argv, **_):
                    return self.curl_result(argv, code=code, body=body)

                with self.assertRaises(RuntimeError):
                    self.run_probe(curl)
                self.assertEqual(self.requests, 1)
                self.assertTrue(self.cores[-1].terminated)

    def test_core_exit_after_request_does_not_pass_even_with_real_marker(self):
        def curl(argv, **_):
            result = self.curl_result(argv)
            self.cores[0].alive = False
            return result

        with self.assertRaises(RuntimeError):
            self.run_probe(curl)
        self.assertEqual(self.requests, 1)
        self.assertTrue(self.cores[0].terminated)


if __name__ == "__main__":
    unittest.main()
