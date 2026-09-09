/* Include the implementation to exercise its internal sizing helper too. */
#define main corkscrew_program_main
#include "../corkscrew.c"
#undef main
#include <assert.h>

#ifdef TEST_BASE64_SIZE
static void check_reader(const char *value, size_t length, int valid, size_t expected)
{
    FILE *fp = tmpfile();
    char *line;
    assert(fp != NULL);
    assert(fwrite(value, 1, length, fp) == length);
    rewind(fp);
    line = read_credentials(fp);
    assert((line != NULL) == valid);
    if (line != NULL) {
        assert(strlen(line) == expected);
        assert(memcmp(line, value, expected) == 0);
        clear_secret(line, AUTH_MAX_LENGTH + 2);
        free(line);
    }
    assert(fclose(fp) == 0);
}
#endif

int main(int argc, char **argv)
{
    char *encoded;
    if (argc == 2 && strcmp(argv[1], "null") == 0) {
        assert(base64_encode(NULL) == NULL);
        return 0;
    }
#ifdef TEST_BASE64_SIZE
    if (argc == 2 && strcmp(argv[1], "reader") == 0) {
        char value[AUTH_MAX_LENGTH + 3];
        memset(value, 'x', sizeof(value));
        check_reader(value, AUTH_MAX_LENGTH, 1, AUTH_MAX_LENGTH);
        check_reader(value, AUTH_MAX_LENGTH + 1, 0, 0);
        value[AUTH_MAX_LENGTH] = '\n';
        check_reader(value, AUTH_MAX_LENGTH + 1, 1, AUTH_MAX_LENGTH);
        value[AUTH_MAX_LENGTH] = '\r';
        value[AUTH_MAX_LENGTH + 1] = '\n';
        check_reader(value, AUTH_MAX_LENGTH + 2, 1, AUTH_MAX_LENGTH);
        value[AUTH_MAX_LENGTH] = 'x';
        check_reader(value, AUTH_MAX_LENGTH + 2, 0, 0);
        check_reader("user: pass  \nignored", sizeof("user: pass  \nignored") - 1,
                     1, sizeof("user: pass  ") - 1);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "overflow") == 0) {
        size_t size;
        assert(base64_output_size((size_t)-1, &size) == 0);
        assert(base64_output_size((size_t)-2, &size) == 0);
        assert(base64_output_size(0, &size) == 1 && size == 1);
        assert(base64_output_size(3, &size) == 1 && size == 5);
        return 0;
    }
#endif
    encoded = base64_encode(argc == 2 ? argv[1] : "u:\xff");
    assert(encoded != NULL);
    puts(encoded);
    free(encoded);
    return 0;
}
