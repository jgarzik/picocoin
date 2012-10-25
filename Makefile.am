##
## Toplevel Makefile.am
##

INCLUDES	= @GLIB_CFLAGS@

bin_PROGRAMS	= picocoin

picocoin_SOURCES= picocoin.h dns.c main.c

picocoin_LDADD	= @GLIB_LIBS@ @EVENT_LIBS@

EXTRA_DIST	= autogen.sh

