#!/usr/bin/env python3
"""Loopback-only authentication regressions; stdlib and GCC are sufficient.

Run: python3 tests/test_auth.py
Sanitizers: AUTH_SANITIZE=1 python3 tests/test_auth.py
Original source: AUTH_SOURCE=/path/to/corkscrew.c AUTH_BASELINE=1 ...
"""
import base64
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AuthenticationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="corkscrew-auth-")
        cls.directory = Path(cls.build.name)
        source = Path(os.environ.get("AUTH_SOURCE", ROOT / "corkscrew.c"))
        shutil.copyfile(source, cls.directory / "corkscrew.c")
        (cls.directory / "tests").mkdir()
        shutil.copyfile(ROOT / "tests/base64_harness.c",
                        cls.directory / "tests/base64_harness.c")
        (cls.directory / "config.h").write_text('#define VERSION "auth-test"\n')
        flags = ["-std=c99", "-g", "-O1", "-Wall", "-Wextra", "-Werror"]
        if os.environ.get("AUTH_SANITIZE"):
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                      "-fno-pie", "-no-pie"]
        cls.program = cls.directory / "corkscrew"
        cls.harness = cls.directory / "base64-test"
        cc = os.environ.get("CC", "cc")
        subprocess.run([cc, *flags, "-o", str(cls.program),
                        str(cls.directory / "corkscrew.c")], check=True)
        if not os.environ.get("AUTH_BASELINE"):
            flags += ["-DTEST_BASE64_SIZE"]
        subprocess.run([cc, *flags, "-o", str(cls.harness),
                        str(cls.directory / "tests/base64_harness.c")], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def clean_result(self, result):
        self.assertNotIn(b"AddressSanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        self.assertNotIn(b"LeakSanitizer", result.stderr)

    def request(self, credentials, host="example.org", directory=False,
                mode=0o600, auth_fd=False, pipe=False, auth_option=False,
                extra_args=None):
        auth = self.directory / "credentials"
        auth.write_bytes(credentials)
        auth.chmod(mode)
        pass_fds = ()
        read_fd = None
        command = [str(self.program), *(extra_args or [])]
        auth_argument = []
        if auth_fd:
            if pipe:
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, credentials)
                finally:
                    os.close(write_fd)
            else:
                read_fd = os.open(auth, os.O_RDONLY)
            command.append("--auth-fd={}".format(read_fd))
            pass_fds = (read_fd,)
        elif auth_option:
            command.append("--auth-file={}".format(auth))
        else:
            auth_argument = [str(self.directory if directory else auth)]
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(0.4)
            command += ["127.0.0.1", str(listener.getsockname()[1]),
                        host, "443", *auth_argument]
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, pass_fds=pass_fds)
            if read_fd is not None:
                os.close(read_fd)
            request = b""
            try:
                try:
                    connection, _ = listener.accept()
                except socket.timeout:
                    connection = None
                if connection is not None:
                    with connection:
                        connection.settimeout(2)
                        while b"\r\n\r\n" not in request:
                            part = connection.recv(8192)
                            if not part:
                                break
                            request += part
                        # Close without exercising the independently owned HTTP parser.
                stdout, stderr = process.communicate(timeout=3)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            result = subprocess.CompletedProcess(process.args, process.returncode,
                                                 stdout, stderr)
            self.clean_result(result)
            return request, result

    def test_base64_vectors(self):
        for value in [b"", b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar",
                      b"u:\xff", b"\xff\xfe\xfd\xfc", bytes(range(1, 256))]:
            with self.subTest(value=value):
                result = subprocess.run([os.fsencode(self.harness), value],
                                        capture_output=True, timeout=3)
                self.clean_result(result)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.rstrip(b"\n"), base64.b64encode(value))

    def test_base64_null(self):
        result = subprocess.run([self.harness, "null"], capture_output=True, timeout=3)
        self.clean_result(result)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipIf(bool(os.environ.get("AUTH_BASELINE")), "new internal size helper")
    def test_base64_overflow(self):
        result = subprocess.run([self.harness, "overflow"], capture_output=True, timeout=3)
        self.clean_result(result)
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipIf(bool(os.environ.get("AUTH_BASELINE")), "new bounded reader")
    def test_credential_reader_boundaries(self):
        result = subprocess.run([self.harness, "reader"], capture_output=True, timeout=3)
        self.clean_result(result)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_auth_header_and_password_spaces(self):
        for ending in [b"", b"\n", b"\r\n"]:
            for value in [b"user:password", b"user: pass word  ", b"u:\xff"]:
                with self.subTest(value=value, ending=ending):
                    request, _ = self.request(value + ending)
                    self.assertEqual(request, b"CONNECT example.org:443 HTTP/1.0\r\n"
                                     b"Proxy-Authorization: Basic " +
                                     base64.b64encode(value) + b"\r\n\r\n")

    def test_auth_fd_accepts_inherited_descriptor(self):
        request, _ = self.request(b"user:password", mode=0o644, auth_fd=True)
        self.assertEqual(request, b"CONNECT example.org:443 HTTP/1.0\r\n"
                         b"Proxy-Authorization: Basic " +
                         base64.b64encode(b"user:password") + b"\r\n\r\n")

    def test_auth_fd_accepts_pipe(self):
        request, _ = self.request(b"user:password\n", auth_fd=True, pipe=True)
        self.assertEqual(request, b"CONNECT example.org:443 HTTP/1.0\r\n"
                         b"Proxy-Authorization: Basic " +
                         base64.b64encode(b"user:password") + b"\r\n\r\n")

    def test_auth_fd_rejects_invalid_data(self):
        for value in (b"", b"\n", b"x" * 5000, b"user:pass\x00hidden\n"):
            with self.subTest(length=len(value)):
                request, result = self.request(value, auth_fd=True)
                self.assertEqual(request, b"")
                self.assertNotEqual(result.returncode, 0)

    def test_auth_file_option(self):
        request, _ = self.request(b"user:password", auth_option=True)
        self.assertEqual(request, b"CONNECT example.org:443 HTTP/1.0\r\n"
                         b"Proxy-Authorization: Basic " +
                         base64.b64encode(b"user:password") + b"\r\n\r\n")

    def test_http11_with_auth(self):
        version = subprocess.check_output(
            [str(self.program), "--version"], timeout=3).decode().split()[1]
        request, _ = self.request(b"user:password", extra_args=["--http11"])
        self.assertEqual(request,
                         ("CONNECT example.org:443 HTTP/1.1\r\n"
                          "Host: example.org:443\r\n"
                          "User-Agent: corkscrew/{}\r\n"
                          "Proxy-Authorization: Basic ").format(version).encode() +
                         base64.b64encode(b"user:password") + b"\r\n\r\n")

    def test_invalid_credentials(self):
        for value in [b"", b"\n", b"\r\n", b"x" * 5000,
                      b"x" * 4096 + b"\n", b"user:pass\x00hidden\n"]:
            with self.subTest(length=len(value)):
                request, result = self.request(value)
                self.assertEqual(request, b"")
                self.assertNotEqual(result.returncode, 0)

    def test_file_read_error(self):
        request, result = self.request(b"unused", directory=True)
        self.assertEqual(request, b"")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"regular file", result.stderr)

    def test_insecure_auth_file_rejected(self):
        for mode in (0o644, 0o640, 0o604):
            with self.subTest(mode=oct(mode)):
                request, result = self.request(b"user:password", mode=mode)
                self.assertEqual(request, b"")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"group or others", result.stderr)

    def test_fifo_auth_file_rejected_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("requires mkfifo")
        auth = self.directory / "fifo"
        if auth.exists():
            auth.unlink()
        os.mkfifo(auth)
        result = subprocess.run(
            [str(self.program), "127.0.0.1", "8080", "example.org", "22",
             str(auth)],
            capture_output=True, timeout=2)
        self.clean_result(result)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"regular file", result.stderr)

    def test_complete_request_size_boundary(self):
        value = b"user:password"
        fixed = (b"CONNECT :443 HTTP/1.0\r\nProxy-Authorization: Basic " +
                 base64.b64encode(value) + b"\r\n\r\n")
        host = "x" * (4095 - len(fixed))
        request, _ = self.request(value, host=host)
        self.assertEqual(len(request), 4095)
        request, result = self.request(value, host=host + "x")
        self.assertEqual(request, b"")
        self.assertNotEqual(result.returncode, 0)

    def test_encoded_credentials_exceed_request_limit(self):
        request, result = self.request(b"u:" + b"x" * 4093)
        self.assertEqual(request, b"")
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
