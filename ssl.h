#ifndef _SSL_H
#define _SSL_H

#include <openssl/ssl.h>

typedef union conn_un *CONN;

#define conn_init(fd) ssl_initialize((fd))
#define FD(conn) ssl_get_fd((conn))
#define peer_read(conn, buf, count)  ssl_read((conn), (buf), (count))
#define peer_write(conn, buf, count) ssl_write((conn), (buf), (count))
#define conn_free(conn) ssl_free((conn))

CONN ssl_initialize PARAMS((int sock));
extern int (*ssl_read) PARAMS((CONN conn, void *buf, size_t count));
extern int (*ssl_write) PARAMS((CONN conn, void *buf, size_t count));
int ssl_get_fd PARAMS((CONN conn));
void ssl_free PARAMS((CONN conn));

#endif /* _SSL_H */
