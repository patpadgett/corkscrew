#!/usr/bin/env python3
"""Command-line option regressions; no network or generated build required."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="corkscrew-cli-")
        directory = Path(cls.build.name)
        cls.binary = os.environ.get("CORKSCREW_BINARY")
        if not cls.binary:
            shutil.copyfile(ROOT / "corkscrew.c", directory / "corkscrew.c")
            (directory / "config.h").write_text('#define VERSION "cli-test"\n')
            cls.binary = str(directory / "corkscrew")
            subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-Wall",
                            "-Wextra", "-Werror", "-O2", "-o", cls.binary,
                            str(directory / "corkscrew.c")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def run_cli(self, *args, input_data=b""):
        return subprocess.run([self.binary, *args], input=input_data,
                              capture_output=True, timeout=3)

    def test_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"usage: corkscrew [options]", result.stdout)
        self.assertIn(b"--auth-fd=FD", result.stdout)
        self.assertIn(b"--http11", result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_short_help(self):
        result = self.run_cli("-h")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"usage: corkscrew", result.stdout)

    def test_version(self):
        result = self.run_cli("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout, rb"^corkscrew [^\s]+\n$")
        self.assertEqual(result.stderr, b"")

    def test_unknown_option(self):
        result = self.run_cli("--not-an-option")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"unknown option", result.stderr)
        self.assertIn(b"usage: corkscrew", result.stderr)

    def test_missing_option_value(self):
        for option in ("--connect-timeout", "--handshake-timeout",
                       "--auth-file", "--auth-fd"):
            with self.subTest(option=option):
                result = self.run_cli(option)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"missing value", result.stderr)

    def test_invalid_timeouts(self):
        for option in ("--connect-timeout", "--handshake-timeout"):
            for value in ("", "0", "-1", "abc", "1x", "999999999999999999999"):
                with self.subTest(option=option, value=value):
                    result = self.run_cli("{}={}".format(option, value))
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(b"invalid", result.stderr)

    def test_invalid_auth_descriptor(self):
        for value in ("0", "1", "2", "-1", "abc", "999999999999999999999"):
            with self.subTest(value=value):
                result = self.run_cli("--auth-fd={}".format(value))
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"invalid --auth-fd", result.stderr)

    def test_auth_sources_are_mutually_exclusive(self):
        positional = ["127.0.0.1", "9", "example.org", "443"]
        result = self.run_cli("--auth-fd=3", *positional, "/tmp/auth")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"cannot be combined", result.stderr)
        result = self.run_cli("--auth-file=/tmp/auth", "--auth-fd=3", *positional)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"cannot be combined", result.stderr)
        result = self.run_cli("--auth-file=/tmp/auth", *positional, "/tmp/auth")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"specified twice", result.stderr)

    def test_positional_argument_count(self):
        result = self.run_cli("127.0.0.1", "9", "example.org")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"expected 4 or 5", result.stderr)
        result = self.run_cli("127.0.0.1", "9", "example.org", "443",
                              "/tmp/auth", "extra")
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"too many", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
