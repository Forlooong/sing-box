"""The help entry points must be usable before installation, without privileges."""
import contextlib
import io
import shlex
import unittest
from unittest import mock

from sbmanager import cli


class HelpTests(unittest.TestCase):
    def invoke(self, *words):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream), \
                mock.patch.object(cli.system, "require_linux_root", side_effect=AssertionError("help requires root")), \
                mock.patch.object(cli.registry, "load", side_effect=AssertionError("help reads server state")), \
                mock.patch.object(cli, "lock", side_effect=AssertionError("help acquires the management lock")):
            try:
                code = cli.main(list(words))
            except SystemExit as exc:
                code = exc.code
        return code, stream.getvalue()

    def test_overview_is_available_before_installation(self):
        outputs = []
        for words in ((), ("help",), ("--help",), ("-h",)):
            with self.subTest(words=words):
                code, text = self.invoke(*words)
                self.assertEqual(code, 0, text)
                self.assertIn('sb sub name "最伟大的派送员"', text)
                self.assertIn("sb help sub", text)
                outputs.append(text)
        self.assertTrue(all(text == outputs[0] for text in outputs))

    def test_topic_help_and_unknown_topic_never_touch_the_installation(self):
        code, short = self.invoke("help", "sub")
        self.assertEqual(code, 0, short)
        code, long = self.invoke("help", "subscription")
        self.assertEqual(code, 0, long)
        self.assertEqual(short, long)
        self.assertIn("旧链接", short)
        code, message = self.invoke("help", "not-a-topic")
        self.assertNotEqual(code, 0)
        self.assertIn("未知帮助主题", message)
        self.assertIn("sb help", message)

    def test_nested_argparse_help_is_still_available(self):
        code, text = self.invoke("node", "add", "-h")
        self.assertEqual(code, 0, text)
        self.assertIn("--protocol", text)
        self.assertIn("--metadata-file", text)

    def test_documented_commands_are_accepted_by_the_actual_parser(self):
        from sbmanager import helptext

        for topic in (None, *helptext.TOPICS):
            for line in helptext.render(topic).splitlines():
                if not line.startswith("  sb "):
                    continue
                words = shlex.split(line.strip(), comments=True)[1:]
                with self.subTest(topic=topic, command=words):
                    # Parse only: examples must never run or read the referenced files.
                    cli.parser().parse_args(words)


if __name__ == "__main__":
    unittest.main()
