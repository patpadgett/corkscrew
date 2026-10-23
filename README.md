# Corkscrew 3.0

[![Build and regression tests](https://github.com/patpadgett/corkscrew/actions/workflows/ci.yml/badge.svg)](https://github.com/patpadgett/corkscrew/actions/workflows/ci.yml)

Corkscrew tunnels SSH through an HTTP proxy that permits the HTTP CONNECT
method. It can also be used for other protocols that need a TCP tunnel.

This release targets POSIX environments with sockets and `poll(2)`. Linux is
covered by GCC and Clang CI, including sanitizer, real-proxy, and parser-fuzz
jobs. macOS has a separate portability build and test job. Historical platform
lists are not compatibility guarantees.

Project and issue tracker:

    https://github.com/patpadgett/corkscrew

## Building

From a Git checkout, generate the build system first (requires Autoconf and
Automake):

    autoreconf -fi
    ./configure
    make

The Python 3 standard library is required for the regression suite, but not
for building or running the program. Install with:

    sudo make install

That installs the `corkscrew` binary and the `corkscrew(1)` manual page.

To run the regression suite:

    make check

`make check` runs the Python tests with `CORKSCREW_BINARY` pointing at the
built program. The tests cover authentication, command-line parsing, network
deadlines, fault injection, handshake/relay behavior, and, when `tinyproxy` is
installed, a loopback integration test against a real proxy. `make distcheck`
verifies that a source distribution builds, tests, installs, and uninstalls
cleanly.

The tests can also be run directly:

    python3 -m unittest discover -s tests -p 'test_*.py' -v

See [SECURITY.md](SECURITY.md) for the security model and validation scope.

## Usage

The original positional syntax remains supported:

    corkscrew [options] <proxyhost> <proxyport> <desthost> <destport> [authfile]

Ports must be decimal integers in the range 1 through 65535. IPv6 destination
addresses may be written with or without brackets; the CONNECT request uses
the bracketed form.

Options:

| Option | Meaning |
| --- | --- |
| `-h`, `--help` | Print usage information and exit. |
| `-V`, `--version` | Print the version and exit. |
| `-v`, `--verbose` | Report connection progress on standard error. Credentials are never printed. |
| `--connect-timeout=SECONDS` | TCP connect deadline; the default is 10 seconds. |
| `--handshake-timeout=SECONDS` | CONNECT write/read deadline; the default is 10 seconds. |
| `--auth-file=FILE` | Read proxy credentials from `FILE` instead of a positional argument. |
| `--auth-fd=FD` | Read proxy credentials from an inherited descriptor (3 or greater). |
| `--http11` | Send an HTTP/1.1 CONNECT request with `Host` and `User-Agent` headers. |

The default request remains HTTP/1.0 for compatibility with older proxies.
`--http11` is opt-in; it adds standard headers that some proxies require.

### Using Corkscrew with SSH

Add a `ProxyCommand` to `~/.ssh/config`:

    Host ssh.example.com
        ProxyCommand /usr/local/bin/corkscrew proxy.example.com 8080 %h %p

To use the HTTP/1.1 request form:

    Host ssh.example.com
        ProxyCommand /usr/local/bin/corkscrew --http11 proxy.example.com 8080 %h %p

## HTTP authentication

Create an authentication file containing the proxy username and password on
the first line:

    username:password

Protect it and pass it as the last argument:

    chmod 600 ~/.ssh/corkscrew-auth
    ProxyCommand /usr/local/bin/corkscrew proxy.example.com 8080 %h %p ~/.ssh/corkscrew-auth

Alternatively, use `--auth-file=FILE`.

Corkscrew requires a positional or `--auth-file` credential file to be a
regular file and rejects files whose group or other permission bits are set.
It reads the first line with LF or CRLF line endings and preserves spaces,
including trailing spaces before the line ending. Credentials and the
generated CONNECT request are cleared from memory before the tunnel begins and
on normal exit paths.

`--auth-fd=FD` is intended for secret managers and supervisors that pass an
already-open descriptor. The descriptor must be 3 or greater and is closed
after the first line is read. Because it may be a pipe or another
non-regular stream, corkscrew deliberately does not apply the regular-file
and permission checks in this mode; the caller is responsible for protecting
the descriptor and its contents.

The proxy connection is plaintext HTTP unless an external transport protects
it. Proxy Basic authentication is Base64 encoding, not encryption; the SSH
session that follows does not protect the preceding proxy login. Use a
trusted, protected proxy connection, and do not reuse valuable passwords.
Never submit real passwords in issues, logs, fixtures, or bug reports.

## Signals and exit status

During the relay, SIGTERM, SIGINT, SIGHUP, and SIGQUIT request an orderly
shutdown. Inherited descriptor flags are restored before termination. SIGTSTP
restores shared terminal flags before the process stops and reapplies
nonblocking mode after it resumes.

Exit status is 0 for a clean tunnel close, 1 for an operational error, 2 for
an invalid command line, and 128 plus the signal number for a termination
signal received during the relay.

## Changes

See [CHANGELOG.md](CHANGELOG.md) for the 3.0 changes and the 2.0 baseline
note. The `2.0` and `3.0` Git tags identify the baseline and this release;
the older historical `v2.0` tag is retained unchanged.

## License

Corkscrew is released under the [MIT License](LICENSE).

Previously published releases were distributed under the GNU General Public
License, version 2 or later; those releases remain available under their
original terms.

Corkscrew was originally written by Pat Padgett. See the Git history for
contributors.
