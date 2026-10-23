# Changelog

All notable changes to Corkscrew are documented here.

## 3.1 - 2026-10-23

This release relicenses the project under MIT, removes generated build
artifacts from version control, and consolidates the changelog. The CONNECT
protocol and authentication behavior are unchanged.

### Licensing and repository cleanup

- Relicense the project under the MIT License. Previously published releases
  remain available under the GNU General Public License, version 2 or later.
- Replace `COPYING` with `LICENSE`, document the license in `README.md` and
  `corkscrew(1)`, and include the license in source distributions.
- Remove the redundant `AUTHORS` file, the generic Autotools `INSTALL` file,
  and tracked Autotools-generated files. Build from a Git checkout with
  `autoreconf -fi` as documented.
- Replace the stale maintainer email in the help banner with the project URL,
  and update historical changelog entries to `pat@patpadgett.com`.
- Merge the legacy `ChangeLog` into this file and remove the separate file.
- Replace the Base64 encoder with an independent implementation. The
  `Proxy-Authorization` wire format is unchanged.

## 3.0 - 2026-10-23

This release hardens the CONNECT client and relay, adds command-line
compatibility options, and expands continuous integration.

### Proxy and relay correctness

- Relay bytes that arrive coalesced with the proxy's CONNECT response instead
  of writing them to standard output during handshake setup.
- Preserve half-close semantics in both directions: a remote write shutdown
  no longer discards input that the caller has not finished sending.
- Apply bounded buffering and backpressure without resetting setup deadlines
  or deadlocking when either standard streams or the proxy socket stall.
- Parse bounded CONNECT responses incrementally, including fragmented status
  lines, split headers, repeated short reads, and interrupted system calls.
- Reject malformed, oversized, prematurely closed, and unsupported proxy
  responses before entering the relay.
- Validate proxy and destination host/port arguments, including bracketed
  IPv6 destinations, and bound TCP connect and handshake deadlines.

### Descriptor and signal handling

- Never let the proxy socket alias standard input, standard output, or
  standard error. Reject closed stdin/stdout early and relocate low-numbered
  proxy sockets above the standard error descriptor.
- Handle SIGQUIT like SIGTERM, SIGINT, and SIGHUP. Handle SIGTSTP by restoring
  shared descriptor flags before stopping and reapplying nonblocking mode on
  resume.
- Centralize teardown so credentials, CONNECT request data, and open
  descriptors are cleared or closed on every normal exit path.

### Authentication and credentials

- Require positional and `--auth-file` credential files to be regular files
  with no group or other permission bits.
- Read credentials without an uncleared stdio buffer and clear both the
  plaintext credentials and generated Base64 authorization material before
  the tunnel starts or the process exits.
- Preserve spaces and support LF or CRLF line endings in credential files.
- Add `--auth-fd=FD` for secret managers and supervisors that pass an
  inherited descriptor. Descriptor mode reads one line, closes the descriptor,
  and deliberately bypasses regular-file and permission checks because pipes
  and other secure descriptors are valid sources.

### Command-line interface

- Add `-h`/`--help`, `-V`/`--version`, and `-v`/`--verbose`.
- Add `--connect-timeout=SECONDS` and `--handshake-timeout=SECONDS`; both
  default to 10 seconds while the old positional syntax remains unchanged.
- Add `--auth-file=FILE` as an alternative to the positional auth file.
- Add opt-in `--http11` mode, which sends an HTTP/1.1 CONNECT request with
  `Host` and `User-Agent: corkscrew/3.0` headers. The default remains
  HTTP/1.0 for older proxies.
- Reject unknown options, invalid values, duplicate authentication sources,
  and incorrect positional argument counts with exit status 2.

### Build, portability, and testing

- Add a real-proxy integration test that uses tinyproxy on loopback when it is
  installed; Linux CI installs tinyproxy and runs the test.
- Add a Clang/libFuzzer harness for the CONNECT response parser, with seed
  inputs and sanitizer coverage in CI.
- Add macOS build and regression jobs; GNU linker fault-injection tests skip
  on platforms without `ld --wrap`, while portable suites still run.
- Keep GCC and Clang strict-warning builds, AddressSanitizer and
  UndefinedBehaviorSanitizer runs, `make check`, and `make distcheck`.
- Add regression coverage for CLI parsing, HTTP/1.1 request headers,
  inherited-descriptor authentication, auth-file options, real proxies,
  descriptor cleanup, handshake deadlines, backpressure, half-close, and
  signal cleanup.
- Install the `corkscrew(1)` manual page and include the tests, changelog, and
  documentation in source distributions.

### Documentation

- Make `README.md` the canonical README and remove the duplicate legacy
  `README`.
- Document the complete CLI, authentication modes, timeout behavior,
  HTTP/1.1 compatibility mode, security model, portability status, and
  release tags.
- Add this changelog and update `NEWS` for the 3.0 release.

## 2.0 - baseline

The `2.0` tag records the pre-hardening release baseline. The 3.0 and 3.1
sections above describe later releases. The historical `v2.0` tag is retained
unchanged for older release references.

## Historical changes

The following entries are preserved from the original plain-text changelog
and reformatted for this Markdown file. They predate the 2.0 baseline.

### 2001-08-24 13:21:23 - Pat Padgett

- Merged proxy authentication patches from Karel Dudasek.
- Cleaned up `configure.in` and `Makefile.am`.
- Added support for non-ANSI/K&R C compilers.

### 2001-06-14 12:05:24 - Pat Padgett

- Added timer for `select` (thanks Robert Loomans).
- Removed `xmit()` function.
- Win32 support now stable.

### 2001-04-17 14:30:23 - Pat Padgett

- Fixed glaring bug with `getopt`.
- Command-line syntax has changed. (View `README`.)
- Corkscrew was compiled on Win32.
- Added error reporting if proxy-to-destination connection unsuccessful.

### 2001-04-11 10:27:32 - Pat Padgett

- Added support for function prototypes (for HPUX compatibility).
- Changed buffer size declaration (now `#define`d).

### 2001-04-10 23:20:21 - Pat Padgett

- Changed `strncat` to `strncpy` during URI setup.

### 2001-04-10 16:26:43 - Pat Padgett

- Added GPL license to distribution.
- Added support for GNU autoconf and automake.
- Corkscrew now compiles on Solaris with GNU tools.
