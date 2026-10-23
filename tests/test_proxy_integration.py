#!/usr/bin/env python3
"""Exercise the CONNECT client against a real tinyproxy process.

The test skips when tinyproxy is not installed. CI installs it on Linux; the
test never requires network access beyond loopback.
"""
import os
from pathlib import Path
import select
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class _EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            while True:
                data = self.request.recv(65536)
                if not data:
                    return
                self.request.sendall(data)
        except (BrokenPipeError, ConnectionResetError):
            return


class _EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@unittest.skipUnless(shutil.which("tinyproxy") or os.environ.get("TINYPROXY"),
                     "tinyproxy is not installed")
class RealProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="corkscrew-proxy-")
        directory = Path(cls.tmp.name)
        cls.tinyproxy = os.environ.get("TINYPROXY") or shutil.which("tinyproxy")
        if not cls.tinyproxy:
            raise unittest.SkipTest("tinyproxy is not installed")

        cls.echo = _EchoServer(("127.0.0.1", 0), _EchoHandler)
        cls.echo_thread = threading.Thread(target=cls.echo.serve_forever,
                                           daemon=True)
        cls.echo_thread.start()
        echo_port = cls.echo.server_address[1]

        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            proxy_port = probe.getsockname()[1]
        config = directory / "tinyproxy.conf"
        log = directory / "tinyproxy.log"
        config.write_text(
            "Port {}\n"
            "Listen 127.0.0.1\n"
            "Timeout 10\n"
            "Allow 127.0.0.1\n"
            "LogLevel Info\n"
            'LogFile "{}"\n'
            'PidFile "{}"\n'.format(proxy_port, log, directory / "tinyproxy.pid"))
        cls.log = log
        cls.proxy = subprocess.Popen(
            [cls.tinyproxy, "-d", "-c", str(config)],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, start_new_session=True)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if cls.proxy.poll() is not None:
                break
            try:
                with socket.create_connection(("127.0.0.1", proxy_port),
                                              timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            cls._stop_proxy()
            raise AssertionError("tinyproxy did not start")
        if cls.proxy.poll() is not None:
            cls._stop_proxy()
            raise AssertionError("tinyproxy exited: {}".format(
                cls._proxy_output()))
        cls.proxy_port = proxy_port
        cls.echo_port = echo_port

        cls.binary = os.environ.get("CORKSCREW_BINARY")
        if not cls.binary:
            shutil.copyfile(ROOT / "corkscrew.c", directory / "corkscrew.c")
            (directory / "config.h").write_text('#define VERSION "proxy-test"\n')
            cls.binary = str(directory / "corkscrew")
            subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-Wall",
                            "-Wextra", "-Werror", "-O2", "-o", cls.binary,
                            str(directory / "corkscrew.c")], check=True)

    @classmethod
    def _proxy_output(cls):
        pieces = []
        if cls.log.exists():
            pieces.append(cls.log.read_text(errors="replace"))
        if cls.proxy.stderr is not None and not cls.proxy.stderr.closed:
            pieces.append(cls.proxy.stderr.read().decode(errors="replace"))
        return "\n".join(pieces)

    @classmethod
    def _stop_proxy(cls):
        if cls.proxy.poll() is None:
            cls.proxy.terminate()
            try:
                cls.proxy.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.proxy.kill()
                cls.proxy.wait()
        if cls.proxy.stderr is not None:
            cls.proxy.stderr.close()
        if hasattr(cls, "echo"):
            cls.echo.shutdown()
            cls.echo.server_close()
            cls.echo_thread.join(timeout=3)

    @classmethod
    def tearDownClass(cls):
        cls._stop_proxy()
        cls.tmp.cleanup()

    @staticmethod
    def _read_exact(stream, length, timeout=10):
        data = bytearray()
        deadline = time.monotonic() + timeout
        while len(data) < length:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("timed out waiting for tunnel data")
            ready, _, _ = select.select([stream], [], [], remaining)
            if not ready:
                raise AssertionError("timed out waiting for tunnel data")
            part = os.read(stream.fileno(), length - len(data))
            if not part:
                break
            data.extend(part)
        return bytes(data)

    def test_echo_through_real_proxy(self):
        payload = b"hello through tinyproxy"
        for extra_args in ([], ["--http11"]):
            with self.subTest(extra_args=extra_args):
                process = subprocess.Popen(
                    [self.binary, *extra_args, "127.0.0.1",
                     str(self.proxy_port), "127.0.0.1", str(self.echo_port)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE)
                try:
                    process.stdin.write(payload)
                    process.stdin.flush()
                    # Keep stdin open while the echo response traverses the
                    # real proxy, then close it to finish the tunnel.
                    self.assertEqual(self._read_exact(process.stdout,
                                                      len(payload)), payload)
                    process.stdin.close()
                    self.assertEqual(process.wait(timeout=10), 0)
                    self.assertEqual(process.stdout.read(), b"")
                    self.assertEqual(process.stderr.read(), b"")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.wait()
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream:
                            stream.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
