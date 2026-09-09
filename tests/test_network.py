#!/usr/bin/env python3
"""Network/authority regression tests; build in a temporary directory.

Run: python3 -m unittest discover -s tests -p test_network.py -v
CORKSCREW_BINARY may select an already-built (including sanitized) binary.
"""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class NetworkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="corkscrew-network-")
        directory = Path(cls.build.name)
        cls.sanitize_flags = (['-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                               '-fno-pie', '-no-pie'] if os.environ.get('SANITIZE') else [])
        cls.binary = os.environ.get("CORKSCREW_BINARY")
        if not cls.binary:
            shutil.copyfile(ROOT / "corkscrew.c", directory / "corkscrew.c")
            (directory / "config.h").write_text('#define VERSION "network-test"\n#define ANSI_FUNC 1\n#define HAVE_SYS_FILIO_H 0\n')
            cls.binary = str(directory / "corkscrew")
            subprocess.run(["gcc", "-std=c99", "-Wall", "-Wextra", "-O2", *cls.sanitize_flags, "-o", cls.binary, str(directory / "corkscrew.c")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def rejected(self, args, message=None):
        result = subprocess.run([self.binary, *args], input=b"", capture_output=True, timeout=3)
        self.assertNotEqual(result.returncode, 0, result)
        if message:
            self.assertIn(message, result.stderr)
        return result

    def request(self, family=socket.AF_INET, proxy=None, destination="example.com", port="443"):
        address = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        with socket.socket(family) as listener:
            try:
                listener.bind((address, 0))
            except OSError as exc:
                if family == socket.AF_INET6:
                    self.skipTest(f"IPv6 loopback unavailable: {exc}")
                raise
            listener.listen()
            listener.settimeout(3)
            process = subprocess.Popen([self.binary, proxy or address, str(listener.getsockname()[1]), destination, port], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(3)
                    data = b""
                    while not data.endswith(b"\r\n\r\n"):
                        chunk = connection.recv(8192)
                        self.assertTrue(chunk)
                        data += chunk
                    # Closing without a response deliberately avoids testing the
                    # handshake/relay, which are owned by separate changes.
                process.communicate(timeout=3)
                return data
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_connection_deadline_and_fd_cleanup(self):
        directory = Path(self.build.name)
        # Build the focused harness even when the CLI binary is supplied.
        shutil.copyfile(ROOT / "corkscrew.c", directory / "corkscrew.c")
        (directory / "config.h").write_text('#define VERSION "network-test"\n#define ANSI_FUNC 1\n#define HAVE_SYS_FILIO_H 0\n')
        harness = directory / "network-harness"
        subprocess.run(["gcc", "-std=c99", "-O1", *self.sanitize_flags, "-DCONNECT_TIMEOUT_MS=100", "-I", str(directory), "-o", str(harness), str(ROOT / "tests/network_harness.c")], check=True)
        result = subprocess.run([str(harness)], capture_output=True, timeout=3)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"no fd leak", result.stdout)
        print(result.stdout.decode().strip())

    def test_ipv4_connect(self):
        self.assertEqual(self.request(), b"CONNECT example.com:443 HTTP/1.0\r\n\r\n")

    def test_localhost_address_fallback(self):
        self.assertEqual(self.request(proxy="localhost"), b"CONNECT example.com:443 HTTP/1.0\r\n\r\n")

    def test_ipv6_proxy(self):
        self.assertEqual(self.request(socket.AF_INET6), b"CONNECT example.com:443 HTTP/1.0\r\n\r\n")

    def test_bracketed_ipv6_proxy(self):
        self.assertEqual(self.request(socket.AF_INET6, proxy="[::1]"), b"CONNECT example.com:443 HTTP/1.0\r\n\r\n")

    def test_ipv6_destination(self):
        for destination in ("2001:db8::1", "[2001:db8::1]"):
            with self.subTest(destination=destination):
                self.assertEqual(self.request(destination=destination), b"CONNECT [2001:db8::1]:443 HTTP/1.0\r\n\r\n")

    def test_port_boundaries(self):
        for port in ("1", "65535"):
            with self.subTest(port=port):
                self.assertEqual(self.request(port=port), f"CONNECT example.com:{port} HTTP/1.0\r\n\r\n".encode())

    def test_invalid_ports(self):
        for index in (1, 3):
            for port in ("", "0", "-1", "+1", "65536", "9999999999999999999999999999999", "80x", "0x50", " 80", "80 ", "80\r\nX-Injected: yes", "8\t0"):
                with self.subTest(index=index, port=port):
                    args = ["127.0.0.1", "9", "example.com", "443"]
                    args[index] = port
                    self.rejected(args, b"Invalid")

    def test_invalid_hosts(self):
        for index in (0, 2):
            for host in ("", "example.com\r\nX-Injected: yes", "a b", "a\tb", "a\x01b", "a\x7fb", "[::1", "::1]", "[example.com]", "example.com:443", "user@example.com", "example.com/path", "example.com?x", "example.com#x"):
                with self.subTest(index=index, host=host):
                    args = ["127.0.0.1", "9", "example.com", "443"]
                    args[index] = host
                    self.rejected(args, b"Invalid")

    def test_long_request_rejected_before_auth_or_connect(self):
        result = self.rejected(["127.0.0.1", "9", "a" * 10000, "443", "/nonexistent-corkscrew-auth"], b"too long")
        self.assertNotIn(b"Error opening", result.stderr)

    def test_proxy_port_does_not_wrap(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            self.rejected(["127.0.0.1", str(listener.getsockname()[1] + 65536), "example.com", "443"], b"Invalid")

    def test_connect_failure(self):
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            self.rejected(["127.0.0.1", str(reserved.getsockname()[1]), "example.com", "443"], b"Couldn't establish connection")


if __name__ == "__main__":
    unittest.main()
