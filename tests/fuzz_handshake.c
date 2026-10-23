/* libFuzzer harness for the bounded CONNECT response parser.
 *
 * Build from the project root after configure:
 *   clang -std=c99 -g -O1 -fsanitize=fuzzer,address,undefined \
 *       -I. tests/fuzz_handshake.c -o fuzz_handshake
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdint.h>

#define main corkscrew_program_main
#include "../corkscrew.c"
#undef main

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t end = 0;

	(void)end;
	if (size > HANDSHAKE_HEADER_LIMIT)
		return 0;
	(void)handshake_status((const unsigned char *)data, size);
	return 0;
}
