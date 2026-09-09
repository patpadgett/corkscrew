/* Exercise only sock_connect, with real sockets and a deliberately stalled
 * connect seam. poll remains real, so repeated EINTR must not reset deadline. */
#define _POSIX_C_SOURCE 200809L
#include <sys/socket.h>
#include <errno.h>
static int stalled_connect(int fd, const struct sockaddr *address, socklen_t length);
#define connect stalled_connect
#define main corkscrew_program_main
#include "corkscrew.c"
#undef main
#undef connect
#include <assert.h>
#include <signal.h>

static int stall;
static int stalled_connect(int fd, const struct sockaddr *address, socklen_t length)
{
    if (!stall)
        return connect(fd, address, length);
    /* A filled pipe write end remains non-writable until the deadline. */
    static int read_end = -1;
    int pipes[2];
    char bytes[4096] = {0};
    assert(pipe(pipes) == 0);
    assert(fcntl(pipes[1], F_SETFL, O_NONBLOCK) == 0);
    while (write(pipes[1], bytes, sizeof(bytes)) > 0) {}
    assert(errno == EAGAIN);
    assert(dup2(pipes[1], fd) == fd);
    close(pipes[1]);
    if (read_end >= 0) close(read_end);
    read_end = pipes[0];
    errno = EINPROGRESS;
    return -1;
}
static void interrupted(int signal_number) { (void)signal_number; }
int main(void)
{
    struct sockaddr_in address;
    socklen_t length = sizeof(address);
    int reserved = socket(AF_INET, SOCK_STREAM, 0);
    int first, after, i;
    assert(reserved >= 0);
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(reserved, (struct sockaddr *)&address, sizeof(address)) == 0);
    assert(getsockname(reserved, (struct sockaddr *)&address, &length) == 0);
    first = open("/dev/null", O_RDONLY);
    assert(first >= 0);
    close(first);
    for (i = 0; i < 100; ++i) {
        assert(sock_connect("127.0.0.1", ntohs(address.sin_port)) == -1);
        assert(errno == ECONNREFUSED);
    }
    after = open("/dev/null", O_RDONLY);
    assert(after == first);
    close(after);
    assert(sock_connect("127.0.0.1", 0) == -1 && errno == EINVAL);
    assert(sock_connect("127.0.0.1", 65536) == -1 && errno == EINVAL);
    assert(sock_connect("127.0.0.1", 1) == -1);
    {
        struct sigaction action;
        struct itimerval timer = {{0, 5000}, {0, 5000}};
        struct timespec start, end;
        double elapsed;
        memset(&action, 0, sizeof(action));
        action.sa_handler = interrupted;
        sigemptyset(&action.sa_mask);
        assert(sigaction(SIGALRM, &action, NULL) == 0);
        assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
        stall = 1;
        assert(clock_gettime(CLOCK_MONOTONIC, &start) == 0);
        assert(sock_connect("127.0.0.1", 9) == -1);
        assert(errno == ETIMEDOUT);
        assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
        elapsed = end.tv_sec - start.tv_sec + (end.tv_nsec - start.tv_nsec) / 1e9;
        assert(elapsed >= 0.075 && elapsed < 1.0);
        memset(&timer, 0, sizeof(timer));
        assert(setitimer(ITIMER_REAL, &timer, NULL) == 0);
        printf("100 refused connections: errno preserved, no fd leak; EINTR timeout %.3fs\n", elapsed);
    }
    close(reserved);
    return 0;
}
