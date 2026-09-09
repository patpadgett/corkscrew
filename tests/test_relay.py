"""Compile the relay in isolation; no proxy handshake/authentication is exercised."""
import concurrent.futures
import fcntl
import os
from pathlib import Path
import resource
import shlex
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        source = (ROOT / "corkscrew.c").read_text()
        start = source.index("/* Buffered duplex relay.")
        end = source.index("/* End buffered duplex relay. */", start)
        harness = '''#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
'''
        harness += source[start:end]
        harness += '''
static void interrupt_poll(int sig) { (void)sig; }
int main(int argc, char **argv) {
    int rc;
    struct sigaction sa;
    struct itimerval timer;
    (void)argc;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = interrupt_poll;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGALRM, &sa, NULL);
    memset(&timer, 0, sizeof(timer));
    timer.it_value.tv_usec = timer.it_interval.tv_usec = 1000;
    setitimer(ITIMER_REAL, &timer, NULL);
    rc = relay(atoi(argv[1]));
    return rc;
}
'''
        (tmp / "relay.c").write_text(harness)
        cls.binary = str(tmp / "relay")
        subprocess.run([os.environ.get("CC", "cc"), "-std=c99", "-D_POSIX_C_SOURCE=200809L", "-Wall", "-Wextra", "-Werror", "-O2", *shlex.split(os.environ.get("RELAY_TEST_CFLAGS", "")), str(tmp / "relay.c"), "-o", cls.binary], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def spawn(self, high=False, stdout=None):
        child, peer = socket.socketpair()
        child.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        peer.settimeout(10)
        fd = child.fileno()
        highfd = None
        if high:
            if resource.getrlimit(resource.RLIMIT_NOFILE)[0] <= 2048:
                child.close()
                peer.close()
                self.skipTest("descriptor limit too low")
            highfd = fcntl.fcntl(fd, fcntl.F_DUPFD, 2048)
            fd = highfd
        proc = subprocess.Popen([self.binary, str(fd)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE if stdout is None else stdout,
                                stderr=subprocess.PIPE, pass_fds=(fd,))
        child.close()
        if highfd is not None:
            os.close(highfd)
        self.addCleanup(peer.close)
        def cleanup():
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            for stream in (proc.stdin, proc.stdout, proc.stderr):
                if stream:
                    stream.close()
        self.addCleanup(cleanup)
        return proc, peer

    @staticmethod
    def receive(sock):
        chunks = []
        while True:
            part = sock.recv(8192)
            if not part:
                return b"".join(chunks)
            chunks.append(part)

    def test_stdin_half_close_drains_late_response(self):
        proc, peer = self.spawn()
        proc.stdin.write(b"request")
        proc.stdin.close()
        self.assertEqual(self.receive(peer), b"request")
        time.sleep(0.03)
        peer.sendall(b"response after request EOF")
        peer.shutdown(socket.SHUT_WR)
        self.assertEqual(proc.stdout.read(), b"response after request EOF")
        self.assertEqual(proc.wait(timeout=5), 0)

    def test_socket_eof_drains_output_with_stdin_open(self):
        proc, peer = self.spawn()
        payload = os.urandom(1024 * 1024)
        with concurrent.futures.ThreadPoolExecutor() as pool:
            sender = pool.submit(lambda: (peer.sendall(payload), peer.shutdown(socket.SHUT_WR)))
            time.sleep(0.05)
            self.assertEqual(proc.stdout.read(), payload)
            sender.result(timeout=10)
        self.assertEqual(proc.wait(timeout=5), 0)

    def duplex(self, high=False):
        proc, peer = self.spawn(high=high)
        upload, download = os.urandom(2 * 1024 * 1024), os.urandom(2 * 1024 * 1024)
        def upload_data():
            proc.stdin.write(upload)
            proc.stdin.close()
        def download_data():
            peer.sendall(download)
            # Keep response direction open until all request data has arrived.
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            up = pool.submit(upload_data)
            down = pool.submit(download_data)
            # Both sinks initially blocked: relay must bound buffering and not deadlock.
            time.sleep(0.1)
            output = pool.submit(proc.stdout.read)
            received = pool.submit(self.receive, peer)
            self.assertEqual(received.result(timeout=15), upload)
            down.result(timeout=15)
            peer.shutdown(socket.SHUT_WR)
            self.assertEqual(output.result(timeout=15), download)
            up.result(timeout=15)
        self.assertEqual(proc.wait(timeout=5), 0)

    def test_large_duplex_backpressure_and_eintr(self):
        self.duplex()

    def test_high_socket_descriptor(self):
        self.duplex(high=True)

    def test_closed_stdout_is_failure_not_sigpipe(self):
        reader, writer = os.pipe()
        os.close(reader)
        try:
            proc, peer = self.spawn(stdout=writer)
        finally:
            os.close(writer)
        peer.sendall(b"cannot write this")
        rc = proc.wait(timeout=5)
        self.assertGreater(rc, 0)
        self.assertIn(b"relay", proc.stderr.read())

    def test_closed_peer_write_is_failure(self):
        proc, peer = self.spawn()
        peer.shutdown(socket.SHUT_RD)
        proc.stdin.write(b"cannot send this")
        proc.stdin.flush()
        self.assertGreater(proc.wait(timeout=5), 0)

    def test_termination_restores_shared_flags(self):
        import signal
        for signo in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            with self.subTest(signal=signo):
                child, peer = socket.socketpair()
                stdio, caller = socket.socketpair()
                original = fcntl.fcntl(stdio, fcntl.F_GETFL)
                proc = subprocess.Popen([self.binary, str(child.fileno())],
                    stdin=stdio.fileno(), stdout=stdio.fileno(), stderr=subprocess.PIPE,
                    pass_fds=(child.fileno(),))
                try:
                    deadline = time.monotonic() + 2
                    while not fcntl.fcntl(stdio, fcntl.F_GETFL) & os.O_NONBLOCK:
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(.005)
                    proc.send_signal(signo)
                    self.assertEqual(proc.wait(timeout=2), 128 + signo)
                    self.assertEqual(fcntl.fcntl(stdio, fcntl.F_GETFL), original)
                finally:
                    if proc.poll() is None:
                        proc.kill(); proc.wait()
                    proc.stderr.close()
                    for sock in (child, peer, stdio, caller): sock.close()

    def test_shared_stdio_open_file_description_restored(self):
        for nonblocking in (False, True):
            with self.subTest(nonblocking=nonblocking):
                stdio, caller = socket.socketpair()
                child, peer = socket.socketpair()
                if nonblocking:
                    stdio.setblocking(False)
                original = fcntl.fcntl(stdio, fcntl.F_GETFL)
                proc = subprocess.Popen([self.binary, str(child.fileno())],
                                        stdin=stdio.fileno(), stdout=stdio.fileno(), stderr=subprocess.PIPE,
                                        pass_fds=(child.fileno(),))
                try:
                    child.close()
                    caller.shutdown(socket.SHUT_WR)
                    peer.settimeout(5)
                    self.assertEqual(peer.recv(1), b"")
                    peer.sendall(b"shared flags")
                    peer.shutdown(socket.SHUT_WR)
                    caller.settimeout(5)
                    self.assertEqual(caller.recv(128), b"shared flags")
                    self.assertEqual(proc.wait(timeout=5), 0)
                    self.assertEqual(fcntl.fcntl(stdio, fcntl.F_GETFL), original)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                    proc.wait()
                    proc.stderr.close()
                    for sock in (stdio, caller, child, peer):
                        sock.close()

    def test_stdio_flags_restored_success_and_failure(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                incoming, input_writer = os.pipe()
                output_reader, outgoing = os.pipe()
                input_flags = fcntl.fcntl(incoming, fcntl.F_GETFL)
                output_flags = fcntl.fcntl(outgoing, fcntl.F_GETFL)
                child, peer = socket.socketpair()
                try:
                    proc = subprocess.Popen([self.binary, str(child.fileno())], stdin=incoming,
                                            stdout=outgoing, stderr=subprocess.PIPE,
                                            pass_fds=(child.fileno(),))
                    child.close()
                    if fail:
                        os.close(output_reader)
                        output_reader = -1
                    os.close(input_writer)
                    input_writer = -1
                    peer.sendall(b"reply")
                    peer.shutdown(socket.SHUT_WR)
                    rc = proc.wait(timeout=5)
                    proc.stderr.close()
                    self.assertEqual(rc, 1 if fail else 0)
                    self.assertEqual(fcntl.fcntl(incoming, fcntl.F_GETFL), input_flags)
                    self.assertEqual(fcntl.fcntl(outgoing, fcntl.F_GETFL), output_flags)
                finally:
                    child.close()
                    peer.close()
                    for fd in (incoming, input_writer, output_reader, outgoing):
                        if fd >= 0:
                            os.close(fd)


if __name__ == "__main__":
    unittest.main(verbosity=2)
