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
import time
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
            (directory / "config.h").write_text('#define VERSION "network-test"\n')
            cls.binary = str(directory / "corkscrew")
            subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-Wall",
                            "-Wextra", "-Werror", "-O2", *cls.sanitize_flags,
                            "-o", cls.binary,
                            str(directory / "corkscrew.c")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def assert_clean_stderr(self, stderr):
        self.assertNotIn(b"AddressSanitizer", stderr)
        self.assertNotIn(b"LeakSanitizer", stderr)
        self.assertNotIn(b"runtime error:", stderr)

    def rejected(self, args, message=None, timeout=3):
        result = subprocess.run([self.binary, *args], input=b"", capture_output=True,
                                timeout=timeout)
        self.assert_clean_stderr(result.stderr)
        self.assertNotEqual(result.returncode, 0, result)
        if message:
            self.assertIn(message, result.stderr)
        return result

    def request(self, family=socket.AF_INET, proxy=None, destination="example.com",
                port="443", extra_args=None):
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
            process = subprocess.Popen([self.binary, *(extra_args or []),
                                        proxy or address,
                                        str(listener.getsockname()[1]),
                                        destination, port],
                                       stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
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
                _, stderr = process.communicate(timeout=3)
                self.assert_clean_stderr(stderr)
                return data
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_verbose_reports_progress(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(3)
            process = subprocess.Popen(
                [self.binary, "--verbose", "127.0.0.1",
                 str(listener.getsockname()[1]), "example.com", "443"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(3)
                    request = b""
                    while b"\r\n\r\n" not in request:
                        part = connection.recv(4096)
                        self.assertTrue(part)
                        request += part
                    connection.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
                    connection.shutdown(socket.SHUT_WR)
                process.stdin.close()
                stdout = process.stdout.read()
                stderr = process.stderr.read()
                self.assert_clean_stderr(stderr)
                self.assertEqual(process.wait(timeout=3), 0)
                self.assertEqual(stdout, b"")
                self.assertIn(b"connecting to proxy", stderr)
                self.assertIn(b"proxy tunnel established", stderr)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream:
                        stream.close()

    def test_connection_deadline_and_fd_cleanup(self):
        directory = Path(self.build.name)
        # Build the focused harness even when the CLI binary is supplied.
        shutil.copyfile(ROOT / "corkscrew.c", directory / "corkscrew.c")
        (directory / "config.h").write_text('#define VERSION "network-test"\n')
        harness = directory / "network-harness"
        subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-O1",
                        "-Wall", "-Wextra", "-Werror", *self.sanitize_flags,
                        "-DCONNECT_TIMEOUT_MS=100", "-I", str(directory),
                        "-o", str(harness),
                        str(ROOT / "tests/network_harness.c")], check=True)
        result = subprocess.run([str(harness)], capture_output=True, timeout=3)
        self.assert_clean_stderr(result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"no fd leak", result.stdout)
        print(result.stdout.decode().strip())

    def test_ipv4_connect(self):
        self.assertEqual(self.request(), b"CONNECT example.com:443 HTTP/1.0\r\n\r\n")

    def test_http11_headers(self):
        version = subprocess.check_output(
            [self.binary, "--version"], timeout=3).decode().split()[1]
        self.assertEqual(
            self.request(extra_args=["--http11"]),
            ("CONNECT example.com:443 HTTP/1.1\r\n"
             "Host: example.com:443\r\n"
             "User-Agent: corkscrew/{}\r\n\r\n".format(version)).encode())
        self.assertEqual(
            self.request(destination="2001:db8::1", extra_args=["--http11"]),
            ("CONNECT [2001:db8::1]:443 HTTP/1.1\r\n"
             "Host: [2001:db8::1]:443\r\n"
             "User-Agent: corkscrew/{}\r\n\r\n".format(version)).encode())

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
            self.rejected(["--connect-timeout=1", "127.0.0.1",
                           str(reserved.getsockname()[1]), "example.com", "443"],
                          b"Couldn't establish connection", timeout=5)

    def closed_stdio_rejected(self, fd, message):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.3)
            process = subprocess.Popen(
                [self.binary, "127.0.0.1", str(listener.getsockname()[1]),
                 "example.com", "443"],
                stdin=subprocess.PIPE if fd != 0 else subprocess.DEVNULL,
                stdout=subprocess.PIPE if fd != 1 else subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                preexec_fn=lambda: os.close(fd))
            try:
                _, stderr = process.communicate(timeout=3)
                self.assert_clean_stderr(stderr)
                self.assertNotEqual(process.returncode, 0)
                self.assertIn(message, stderr)
                with self.assertRaises(socket.timeout):
                    listener.accept()
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_closed_stdin_rejected_before_connect(self):
        self.closed_stdio_rejected(0, b"standard input")

    def test_closed_stdout_rejected_before_connect(self):
        self.closed_stdio_rejected(1, b"standard output")

    @unittest.skipUnless(Path("/proc").is_dir(), "requires /proc")
    def test_socket_moved_above_closed_stderr(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
            process = subprocess.Popen(
                [self.binary, "127.0.0.1", str(listener.getsockname()[1]),
                 "example.com", "443"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                preexec_fn=lambda: os.close(2))
            try:
                with listener.accept()[0] as conn:
                    conn.settimeout(3)
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        part = conn.recv(4096)
                        self.assertTrue(part)
                        request.extend(part)
                    conn.sendall(b"HTTP/1.0 200 Connection established\r\n\r\n")
                    deadline = time.monotonic() + 2
                    fds = set()
                    socket_fds = []
                    while time.monotonic() < deadline:
                        try:
                            fds = set(os.listdir(f"/proc/{process.pid}/fd"))
                        except FileNotFoundError:
                            break
                        socket_fds = []
                        for name in fds:
                            try:
                                target = os.readlink(
                                    f"/proc/{process.pid}/fd/{name}")
                            except OSError:
                                continue
                            if target.startswith("socket:"):
                                socket_fds.append(int(name))
                        if "2" not in fds and any(fd > 2 for fd in socket_fds):
                            break
                        time.sleep(.005)
                    self.assertNotIn("2", fds)
                    self.assertTrue(any(fd > 2 for fd in socket_fds),
                                    f"proxy socket stayed on a standard descriptor: {socket_fds}")
                    conn.shutdown(socket.SHUT_WR)
                process.stdin.close()
                self.assertEqual(process.wait(timeout=2), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                process.wait()
                process.stdin.close()
                process.stdout.close()


if __name__ == "__main__":
    unittest.main()
