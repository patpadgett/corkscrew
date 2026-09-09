"""Loopback-only CONNECT regressions; direct build needs no generated config.h.
Run: python3 tests/test_handshake.py [-v]
Set SANITIZE=1 for ASan/UBSan. No authentication or relay semantics are tested.
"""
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HandshakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        build = Path(cls.tmp.name)
        (build / 'config.h').write_text('#define VERSION "handshake-test"\n#define HAVE_SYS_FILIO_H 0\n')
        cls.binary = str(build / 'corkscrew')
        flags = ['-g', '-O1', '-Wall', '-Wextra', '-DANSI_FUNC',
                 '-DHANDSHAKE_TIMEOUT_MS=300', '-DCONNECT_TIMEOUT_MS=300', '-I' + str(build)]
        if os.environ.get('SANITIZE'):
            flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                      '-fno-pie', '-no-pie']
        subprocess.run([os.environ.get('CC', 'cc'), *flags, str(ROOT / 'corkscrew.c'),
                        str(ROOT / 'tests/handshake_faults.c'),
                        '-Wl,--wrap=write,--wrap=read,--wrap=poll',
                        '-o', cls.binary], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def proxy(self, fragments, delay=0.012, stall=False, stdin_ready=False, faults=False):
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        request = bytearray()
        errors = []

        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(3)
                    while b'\r\n\r\n' not in request:
                        data = conn.recv(4096)
                        if not data:
                            return
                        request.extend(data)
                    for part in fragments:
                        conn.sendall(part)
                        time.sleep(delay)
                    if stall:
                        time.sleep(0.6)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as exc:
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve)
        thread.start()
        start = time.monotonic()
        env = dict(os.environ)
        if faults:
            env['HANDSHAKE_FAULTS'] = '1'
        p = subprocess.Popen([self.binary, '127.0.0.1', str(listener.getsockname()[1]),
                              'example.test', '22'], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        assert p.stdin is not None and p.stdout is not None and p.stderr is not None
        if stdin_ready:
            p.stdin.write(b'queued input')
            p.stdin.flush()
        try:
            # Keep stdin open: the unrelated legacy relay exits on stdin EOF.
            p.wait(timeout=2)
            elapsed = time.monotonic() - start
            out = p.stdout.read()
            err = p.stderr.read()
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            p.stdin.close()
            p.stdout.close()
            p.stderr.close()
            thread.join(timeout=3)
        self.assertFalse(errors, errors)
        self.assertEqual(bytes(request), b'CONNECT example.test:22 HTTP/1.0\r\n\r\n')
        self.assertNotIn(b'AddressSanitizer', err)
        self.assertNotIn(b'runtime error:', err)
        return p.returncode, out, err, elapsed

    def test_all_response_split_points(self):
        response = b'HTTP/1.1 200 OK\r\nX-Test: yes\r\n\r\n\x00SSH\xff'
        for split in range(1, len(response)):
            with self.subTest(split=split):
                rc, out, _, _ = self.proxy([response[:split], response[split:]], delay=0.001)
                self.assertEqual((rc, out), (0, b'\x00SSH\xff'))

    def test_partial_writes_and_interrupted_syscalls(self):
        payload = b'\x00SSH-2.0-partial-write\xff\r\n'
        rc, out, _, _ = self.proxy([b'HTTP/1.1 200 OK\r\n\r\n' + payload], faults=True)
        self.assertEqual((rc, out), (0, payload))

    def test_header_limit_boundary(self):
        prefix = b'HTTP/1.1 200 OK\r\nX: '
        for size in [16383, 16384, 16385]:
            with self.subTest(size=size):
                header = prefix + b'a' * (size - len(prefix) - 4) + b'\r\n\r\n'
                rc, out, _, _ = self.proxy([header + b'BOUNDARY'])
                if size <= 16384:
                    self.assertEqual((rc, out), (0, b'BOUNDARY'))
                else:
                    self.assertNotEqual(rc, 0)
                    self.assertEqual(out, b'')

    def test_status_line_limit(self):
        rc, out, _, _ = self.proxy([b'HTTP/1.1 200 ' + b'a' * 4096 + b'\r\n\r\n'])
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, b'')

    def test_repeated_poll_eintr_obeys_deadline(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            started = time.monotonic()
            p = subprocess.run([self.binary, '127.0.0.1', str(listener.getsockname()[1]),
                                'example.test', '22'], input=b'', capture_output=True,
                               env={**os.environ, 'HANDSHAKE_POLL_EINTR': '1'}, timeout=2)
            self.assertNotEqual(p.returncode, 0)
            self.assertIn(b'timed out', p.stderr)
            self.assertEqual(p.stdout, b'')
            self.assertLess(time.monotonic() - started, 1.2)
            self.assertNotIn(b'AddressSanitizer', p.stderr)
            self.assertNotIn(b'runtime error:', p.stderr)

    def test_fragmented_status(self):
        rc, out, _, _ = self.proxy([b'HTTP/1.', b'1 200 OK\r\n\r\n', b'SSH-2.0-test\r\n'])
        self.assertEqual((rc, out), (0, b'SSH-2.0-test\r\n'))

    def test_coalesced_binary_payload(self):
        payload = bytes(range(256)) * 5
        rc, out, _, _ = self.proxy([b'HTTP/1.0 200 OK\r\nX-Test: yes\r\n\r\n' + payload])
        self.assertEqual((rc, out), (0, payload))

    def test_split_headers_and_terminator(self):
        rc, out, _, _ = self.proxy([b'HTTP/1.1 200 OK\r\n', b'X-Test: yes\r', b'\n\r', b'\nPAYLOAD'])
        self.assertEqual((rc, out), (0, b'PAYLOAD'))

    def test_each_byte_fragmented(self):
        response = b'HTTP/1.1 204 \r\nX: y\r\n\r\nhello'
        rc, out, _, _ = self.proxy([bytes([x]) for x in response], delay=0.001)
        self.assertEqual((rc, out), (0, b'hello'))

    def test_oversized_headers(self):
        for response in [b'A' * 4096, b'HTTP/1.1 200 OK\r\nX: ' + b'A' * 17000 + b'\r\n\r\n']:
            with self.subTest(size=len(response)):
                rc, out, _, _ = self.proxy([response])
                self.assertNotEqual(rc, 0)
                self.assertEqual(out, b'')

    def test_malformed_status_and_headers(self):
        cases = [b'HTTP/ 200 OK', b'HTTP/2.0 200 OK', b'HTTP/1.2 200 OK',
                 b'HTTP/1.1 20 OK', b'HTTP/1.1 2000 OK', b'HTTP/1.1 +200 OK',
                 b'HTTP/1.1 200', b'HTTP/1.1\t200 OK', b'HTTP/1.1 200 O\x00K',
                 b'HTTP/1.1 099 bad', b'HTTP/1.1 600 bad', b'HTTP/1.1 407 denied',
                 b'HTTP/1.1 200 OK\nX: y', b'HTTP/1.1 200 OK\r\nBad header',
                 b'HTTP/1.1 200 OK\r\nX: bad\x00value',
                 b'HTTP/1.1 200 OK\r\n X: folded']
        for line in cases:
            with self.subTest(line=line):
                rc, out, _, _ = self.proxy([line + b'\r\n\r\nPAYLOAD'], delay=0)
                self.assertNotEqual(rc, 0)
                self.assertEqual(out, b'')

    def test_early_closure(self):
        for fragments in [[], [b'HTTP/1.1 200 OK\r\nX: unfinished']]:
            with self.subTest(fragments=fragments):
                rc, out, _, _ = self.proxy(fragments)
                self.assertNotEqual(rc, 0)
                self.assertEqual(out, b'')

    def test_setup_deadline_with_ready_stdin(self):
        rc, out, err, elapsed = self.proxy([b'HTTP/1.1 200'], stall=True, stdin_ready=True)
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, b'')
        self.assertIn(b'timed out', err)
        self.assertLess(elapsed, 1.2)

    def test_absolute_deadline_not_reset_by_fragments(self):
        rc, out, err, elapsed = self.proxy([b'H'] * 12, delay=0.05)
        self.assertNotEqual(rc, 0)
        self.assertEqual(out, b'')
        self.assertIn(b'timed out', err)
        self.assertLess(elapsed, 1.2)


if __name__ == '__main__':
    unittest.main()
