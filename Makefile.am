AUTOMAKE_OPTIONS = no-dependencies
AM_CPPFLAGS = -I$(srcdir)
bin_PROGRAMS = corkscrew
corkscrew_SOURCES = corkscrew.c
man_MANS = corkscrew.1

EXTRA_DIST = README.md CHANGELOG.md SECURITY.md TODO bootstrap corkscrew.1 \
	tests/base64_harness.c tests/handshake_faults.c tests/fuzz_handshake.c \
	tests/network_harness.c tests/test_auth.py tests/test_cli.py \
	tests/test_handshake.py tests/test_network.py \
	tests/test_proxy_integration.py tests/test_relay.py \
	tests/fuzz_corpus/ok tests/fuzz_corpus/ok-headers \
	tests/fuzz_corpus/auth-required tests/fuzz_corpus/server-error \
	tests/fuzz_corpus/partial tests/fuzz_corpus/garbage

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)
AM_TESTS_ENVIRONMENT = CORKSCREW_BINARY='$(abs_top_builddir)/corkscrew'; \
	export CORKSCREW_BINARY;
if HAVE_PYTHON
TESTS = tests/test_auth.py tests/test_cli.py tests/test_handshake.py \
	tests/test_network.py tests/test_proxy_integration.py \
	tests/test_relay.py
else
check-local:
	@echo "python3 not found; skipping regression tests"
endif
