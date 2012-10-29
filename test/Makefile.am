
INCLUDES	= @GLIB_CFLAGS@ -DTEST_SRCDIR=\"$(top_srcdir)/test\" \
		  -I$(top_srcdir)/include

EXTRA_DIST	= random.data

noinst_PROGRAMS	= fileio hex

TESTS		= fileio hex

fileio_LDADD	= ../lib/libccoin.a @GLIB_LIBS@ @CRYPTO_LIBS@
hex_LDADD	= ../lib/libccoin.a @GLIB_LIBS@ @CRYPTO_LIBS@

