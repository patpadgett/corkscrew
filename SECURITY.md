# Security and supported behavior

Corkscrew opens an HTTP CONNECT tunnel through a proxy. It does **not** establish TLS to the proxy. Proxy Basic authentication is Base64 encoding, not encryption: anyone who can observe the client-to-proxy connection can recover those credentials. The subsequent SSH session does not encrypt the preceding proxy authentication exchange. Use a trusted, protected proxy connection; do not reuse valuable account passwords.

Keep authentication files readable only by their owner (`chmod 600`). Corkscrew rejects a positional or `--auth-file` credential file unless it is a regular file and all group and other permission bits are clear. Credentials are read without a stdio buffer and are cleared from memory before the tunnel starts and on normal exit paths. `--auth-fd` accepts an inherited descriptor (3 or greater) for supervisors and secret managers; it deliberately skips regular-file and permission checks because the descriptor may be a pipe or another protected stream, so the caller must protect that descriptor. Never submit real passwords in issues, logs, fixtures, or bug reports.

Corkscrew validates the CONNECT destination and bounds proxy response headers and connection/handshake timeouts. The `--connect-timeout` and `--handshake-timeout` options select these deadlines in seconds. The default request is HTTP/1.0; `--http11` opts into an HTTP/1.1 request with `Host` and `User-Agent` headers for proxies that require them. Corkscrew does not authenticate the proxy, inspect proxy response bodies, or protect traffic from a malicious proxy. SSH host-key verification remains necessary.

## Reporting vulnerabilities

Use the repository's private security reporting feature if enabled, or contact the maintainer privately before publishing exploit details. Do not assume a historical release includes fixes visible on a development branch.

## Development checks

The supported baseline is a POSIX environment with a C compiler, sockets, and `poll(2)`. Linux is covered by GCC and Clang CI, sanitizer runs, a loopback tinyproxy integration test, and a libFuzzer parser job. macOS has a portability build and regression job. Other platforms still require their own build and interoperability validation. Historical operating-system lists in old releases are not current compatibility guarantees.

From a Git checkout:

```sh
autoreconf -fi
./configure
make check
make distcheck
```

`make check` runs the standard-library Python regression tests against the built binary, plus focused harnesses for authentication, network deadlines, handshake fault injection, and relay behavior. The tests require Python 3 but the program does not. Tests use loopback endpoints and synthetic credentials only.

Continuous integration builds with strict warnings as errors, runs the suite under AddressSanitizer and UndefinedBehaviorSanitizer, exercises a real tinyproxy instance on Linux, and fuzzes the CONNECT response parser with Clang/libFuzzer. Sanitizers, integration tests, and fuzzing complement each other; none is proof that the software is vulnerability-free.
