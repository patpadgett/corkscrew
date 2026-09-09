/* Link-time syscall fault injection; the original relay is not exercised. */
#include <errno.h>
#include <poll.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

ssize_t __real_write(int, const void *, size_t);
ssize_t __real_read(int, void *, size_t);
int __real_poll(struct pollfd *, nfds_t, int);

ssize_t __wrap_write(int fd, const void *buf, size_t len)
{
    static unsigned calls;
    if (getenv("HANDSHAKE_FAULTS") && fd != 2) {
        calls++;
        if (calls == 1) { errno = EINTR; return -1; }
        if (calls == 2) { errno = EAGAIN; return -1; }
        if (len > 3) len = 3;
    }
    return __real_write(fd, buf, len);
}

ssize_t __wrap_read(int fd, void *buf, size_t len)
{
    static unsigned calls;
    if (getenv("HANDSHAKE_FAULTS") && fd > 2) {
        calls++;
        if (calls == 1) { errno = EINTR; return -1; }
        if (calls == 2) { errno = EAGAIN; return -1; }
    }
    return __real_read(fd, buf, len);
}

int __wrap_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    static unsigned calls;
    if (getenv("HANDSHAKE_POLL_EINTR")) {
        usleep(1000);
        errno = EINTR;
        return -1;
    }
    if (getenv("HANDSHAKE_FAULTS") && ++calls <= 2) {
        errno = EINTR;
        return -1;
    }
    return __real_poll(fds, nfds, timeout);
}
