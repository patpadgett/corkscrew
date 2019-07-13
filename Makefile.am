AUTOMAKE_OPTIONS = no-dependencies
AM_CPPFLAGS = -I$(srcdir)
bin_PROGRAMS = corkscrew
corkscrew_SOURCES = corkscrew.c corkscrew.h

if IPV6
corkscrew_SOURCES += sock_ipv6.c
else
corkscrew_SOURCES += sock_ipv4.c
endif
