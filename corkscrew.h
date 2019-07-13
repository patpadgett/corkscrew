#ifndef _CORKSCREW_H
#define _CORKSCREW_H

#include "config.h"

#define BUFSIZE 4096

/* h_addr macro is not available when gcc compiles with strict ansi enabled. */
#ifndef HAVE_H_ADDR
#define h_addr h_addr_list[0]
#endif

#if __STDC__
#  ifndef NOPROTOS
#    define PARAMS(args)      args
#  endif
#  ifndef ANSI_FUNC
#    define ANSI_FUNC
#  endif
#endif
#ifndef PARAMS
#  define PARAMS(args)        ()
#endif

int sock_connect PARAMS((const char *hname, const char *port));

#endif /* _CORKSCREW_H */
