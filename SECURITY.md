# Security and supported behavior

Corkscrew opens an HTTP CONNECT tunnel through a proxy. It does **not** establish TLS to the proxy. Proxy Basic authentication is Base64 encoding, not encryption: anyone who can observe the client-to-proxy connection can recover those credentials. The subsequent SSH session does not encrypt the preceding proxy authentication exchange. Use a trusted, protected proxy connection; do not reuse valuable account passwords.

Keep authentication files readable only by their owner (`chmod 600`). Never submit real passwords in issues, logs, fixtures or bug reports.

## Reporting vulnerabilities
Use the repository's private security reporting feature if enabled, or contact the maintainer privately before publishing exploit details. Do not assume a historical release includes fixes visible on a development branch.

## Development checks

The supported baseline is a POSIX environment with a C compiler, sockets and poll. Linux is covered by continuous integration; other platforms require their own build and interoperability validation. Historical operating-system lists in old releases are not current compatibility guarantees.

Build from a checkout with `autoreconf -fi`, `./configure`, and `make`. Run the local standard-library Python regression tests with `python3 -m unittest discover -s tests -p 'test_*.py'`. Tests must use loopback endpoints and synthetic credentials. Sanitizer jobs complement tests; neither is proof that the software is vulnerability-free.
